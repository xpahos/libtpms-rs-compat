use crate::library::constants::{
    TPM_RC_FAILURE, TPM_RC_INSUFFICIENT, TPM_RC_LOCALITY, TPM_RC_NV_UNAVAILABLE,
    TPM_RC_NV_UNINITIALIZED, TPM_RC_SIZE, TPM_RC_VALUE,
};
use crate::library::tpm2::TPM_SU_STATE_MASK;
use crate::library::tpm2::command::core::dispatcher::CommandFrame;
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::crypto::DRBG_MAGIC;
use crate::library::tpm2::live::{unoccupied_objects, unoccupied_sessions};
use crate::library::tpm2::nv::{
    MAX_ORDERLY_COUNT, TPMA_NV_ORDERLY, build_nv_image, is_counter_index, startup_attributes,
};
use crate::library::tpm2::orderly::{SU_DA_USED_VALUE, SU_NONE_VALUE, is_orderly};
use crate::library::tpm2::pcr::{
    HCRTM_PCR, PCR_SLOT_BANKS, allocation_selects, pcr_in_tcb_group, pcr_resets_to_ones,
};
use crate::library::tpm2::persistent::{
    OwnedDrbgState, OwnedIndexOrderlyRam, OwnedPcrAllocation, OwnedSecret, OwnedStateClearData,
    OwnedStateResetData, OwnedUserNvramEntry,
};
use crate::library::tpm2::random::{startup_live_drbg, startup_secret};
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::state::{COMMIT_ARRAY_SIZE, MAX_ACTIVE_SESSIONS};
use crate::library::tpm2::volatile::{IMPLEMENTATION_PCR, MAX_LOADED_SESSIONS, OwnedPcr};
use crate::types::TpmResult;
pub(in crate::library::tpm2) const TPM_SU_CLEAR: u16 = 0x0000;
pub(in crate::library::tpm2) const TPM_SU_STATE: u16 = 0x0001;

pub(super) const PRE_STARTUP_FLAG: u16 = 0x8000;
pub(super) const STARTUP_LOCALITY_3: u16 = 0x4000;

const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;
const RC_STARTUP_STARTUP_TYPE: TpmResult = TPM_RC_P + TPM_RC_1;

const TPM_ALG_NULL: u16 = 0x0010;

const PROOF_SIZE: usize = 64;
const PRIMARY_SEED_SIZE: usize = 64;
const COMMIT_NONCE_SIZE: usize = 64;

const SEED_COMPAT_LEVEL_LAST: u8 = 1;

fn nv_startup_attributes(attributes: u32, mode: StartupMode) -> u32 {
    startup_attributes(attributes, mode == StartupMode::Reset)
}

fn pcr_state_saved(pcr: usize) -> bool {
    pcr < 16
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartupMode {
    Reset,
    Restart,
    Resume,
}

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let startup_type = parse_startup_type(frame.parameters)?;
    perform_startup(runtime, startup_type)?;
    Ok(CommandOutput::empty())
}

fn parse_startup_type(parameters: &[u8]) -> Result<u16, TpmResult> {
    let Some((su_bytes, rest)) = parameters.split_first_chunk::<2>() else {
        return Err(TPM_RC_INSUFFICIENT + RC_STARTUP_STARTUP_TYPE);
    };
    let startup_type = u16::from_be_bytes(*su_bytes);
    if startup_type != TPM_SU_CLEAR && startup_type != TPM_SU_STATE {
        return Err(TPM_RC_VALUE + RC_STARTUP_STARTUP_TYPE);
    }
    if !rest.is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(startup_type)
}

struct PreparedStartup {
    prev_orderly: u16,
    startup_locality3: bool,
    new_reset: OwnedStateResetData,
    new_clear: OwnedStateClearData,
    new_drbg: OwnedDrbgState,
    clock_safe: u8,
    reset_count: u32,
    total_reset_count: u64,
    failed_tries: u32,
    lockout_auth_enabled: bool,
    time_epoch: Option<u32>,
    live_pcrs: Vec<OwnedPcr>,
    oldest_saved_session: u32,
    live_orderly_ram: OwnedIndexOrderlyRam,
    max_nv_counter: u64,
    user_nvram_attributes: Vec<(usize, u32)>,
}

fn perform_startup(runtime: &mut Tpm2Runtime, startup_type: u16) -> Result<(), TpmResult> {
    let prepared = prepare_startup(runtime, startup_type)?;
    commit_startup(runtime, prepared)
}

struct StartupChecks {
    locality: u8,
    drtm_pre_startup: bool,
    startup_locality3: bool,
    prev_orderly: u16,
    da_used: bool,
    mode: StartupMode,
}

fn startup_checks(runtime: &Tpm2Runtime, startup_type: u16) -> Result<StartupChecks, TpmResult> {
    // TODO: Support runtimes without decoded state after the NVChip fallback
    // is implemented.
    let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;

    let mut locality = runtime.locality;
    if !runtime.nv_available {
        return Err(TPM_RC_NV_UNAVAILABLE);
    }
    if locality != 0 && locality != 3 {
        return Err(TPM_RC_LOCALITY);
    }
    let drtm_pre_startup = runtime.live.drtm_pre_startup;
    if drtm_pre_startup {
        locality = 0;
    }
    let startup_locality3 = locality == 3;

    let raw_orderly = state.persistent.orderly_state;
    let da_used = raw_orderly == SU_DA_USED_VALUE;
    let orderly = if da_used { SU_NONE_VALUE } else { raw_orderly };
    let prev_orderly = if is_orderly(orderly) {
        orderly & TPM_SU_STATE_MASK
    } else {
        orderly
    };

    if startup_type == TPM_SU_STATE {
        if prev_orderly != TPM_SU_STATE {
            return Err(TPM_RC_VALUE + RC_STARTUP_STARTUP_TYPE);
        }
        if !runtime.live.nv_ok {
            return Err(TPM_RC_NV_UNINITIALIZED);
        }
        if drtm_pre_startup != (orderly & PRE_STARTUP_FLAG != 0) {
            return Err(TPM_RC_VALUE + RC_STARTUP_STARTUP_TYPE);
        }
        if startup_locality3 != (orderly & STARTUP_LOCALITY_3 != 0) {
            return Err(TPM_RC_LOCALITY);
        }
    }

    let mode = if prev_orderly == TPM_SU_STATE && runtime.live.nv_ok {
        if startup_type == TPM_SU_STATE {
            StartupMode::Resume
        } else {
            StartupMode::Restart
        }
    } else {
        StartupMode::Reset
    };

    Ok(StartupChecks {
        locality,
        drtm_pre_startup,
        startup_locality3,
        prev_orderly,
        da_used,
        mode,
    })
}

fn prepare_startup(
    runtime: &mut Tpm2Runtime,
    startup_type: u16,
) -> Result<PreparedStartup, TpmResult> {
    let checks = startup_checks(runtime, startup_type)?;
    let StartupChecks {
        locality,
        drtm_pre_startup,
        startup_locality3,
        prev_orderly,
        da_used,
        mode,
    } = checks;

    let mut drbg = startup_live_drbg(runtime)?;
    let reset_secrets = if mode == StartupMode::Reset {
        let commit_nonce = startup_secret(runtime, &mut drbg, COMMIT_NONCE_SIZE)?;
        let null_proof = startup_secret(runtime, &mut drbg, PROOF_SIZE)?;
        let null_seed = startup_secret(runtime, &mut drbg, PRIMARY_SEED_SIZE)?;
        Some((commit_nonce, null_proof, null_seed))
    } else {
        None
    };

    let runtime = &*runtime;
    let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;

    let mut new_reset = match reset_secrets {
        Some((commit_nonce, null_proof, null_seed)) => OwnedStateResetData {
            null_proof,
            null_seed,
            clear_count: 0,
            object_context_id: 0,
            context_array: Box::new([0; MAX_ACTIVE_SESSIONS]),
            context_slot_mask: 0xffff,
            context_counter: MAX_LOADED_SESSIONS as u64 + 1,
            command_audit_digest: Vec::new(),
            restart_count: 0,
            pcr_counter: 0,
            commit_counter: 0,
            commit_nonce,
            commit_array: [0; COMMIT_ARRAY_SIZE],
            null_seed_compat_level: SEED_COMPAT_LEVEL_LAST,
        },
        None => {
            let old = state.state_reset.as_ref().ok_or(TPM_RC_FAILURE)?;
            carried_state_reset(old)
        }
    };
    match mode {
        StartupMode::Reset => {}
        StartupMode::Restart => {
            new_reset.clear_count = new_reset.clear_count.wrapping_add(1);
            new_reset.restart_count = new_reset.restart_count.wrapping_add(1);
        }
        StartupMode::Resume => {
            new_reset.restart_count = new_reset.restart_count.wrapping_add(1);
        }
    }
    new_reset.pcr_counter = new_reset
        .pcr_counter
        .checked_add(pcr_changed_increments(mode))
        .ok_or(TPM_RC_FAILURE)?;

    let new_clear = match mode {
        StartupMode::Reset | StartupMode::Restart => fresh_state_clear(),
        StartupMode::Resume => state.state_clear.as_ref().ok_or(TPM_RC_FAILURE)?.clone(),
    };

    let allocation = runtime.effective_pcr_allocated().ok_or(TPM_RC_FAILURE)?;
    let live_pcrs =
        build_startup_pcrs(runtime, state, allocation, mode, locality, drtm_pre_startup)?;

    let mut live_orderly_ram = state.index_orderly_ram.clone();
    let mut user_nvram_attributes = Vec::new();
    if mode != StartupMode::Resume {
        for entry in &mut live_orderly_ram.entries {
            entry.attributes = nv_startup_attributes(entry.attributes, mode);
            if is_counter_index(entry.attributes) && prev_orderly == SU_NONE_VALUE {
                let counter_bytes: &mut [u8] = entry.data.get_mut(..8).ok_or(TPM_RC_FAILURE)?;
                let counter =
                    u64::from_be_bytes(counter_bytes.try_into().map_err(|_| TPM_RC_FAILURE)?)
                        | MAX_ORDERLY_COUNT;
                counter_bytes.copy_from_slice(&counter.to_be_bytes());
            }
        }
        for (index, entry) in state.user_nvram.entries.iter().enumerate() {
            let OwnedUserNvramEntry::NvIndex {
                index: nv_index, ..
            } = entry
            else {
                continue;
            };
            if nv_index.attributes & TPMA_NV_ORDERLY != 0 {
                continue;
            }
            let updated = nv_startup_attributes(nv_index.attributes, mode);
            if updated != nv_index.attributes {
                user_nvram_attributes.push((index, updated));
            }
        }
    }
    let max_nv_counter = state.user_nvram.max_count;

    let mut failed_tries = state.persistent.failed_tries;
    let mut lockout_auth_enabled = state.persistent.lockout_auth_enabled;
    if state.persistent.lockout_recovery == 0 {
        lockout_auth_enabled = true;
    }
    if state.persistent.recovery_time != 0
        && failed_tries < state.persistent.max_tries
        && !is_orderly(prev_orderly)
    {
        failed_tries += u32::from(da_used);
    }

    let time_epoch = runtime
        .timer
        .timer_stopped
        .then(|| state.persistent.time_epoch.wrapping_add(1));

    let clock_safe = if is_orderly(prev_orderly) {
        runtime.live.orderly.clock_safe
    } else {
        0
    };

    let (mut reset_count, mut total_reset_count) = (
        state.persistent.reset_count,
        state.persistent.total_reset_count,
    );
    if mode == StartupMode::Reset {
        reset_count = reset_count.wrapping_add(1);
        total_reset_count = total_reset_count.wrapping_add(1);
    }

    let oldest_saved_session = if mode == StartupMode::Reset {
        MAX_ACTIVE_SESSIONS as u32 + 1
    } else {
        context_id_oldest(
            &new_reset.context_array,
            new_reset.context_counter,
            new_reset.context_slot_mask,
        )
    };

    Ok(PreparedStartup {
        prev_orderly,
        startup_locality3,
        new_reset,
        new_clear,
        new_drbg: OwnedDrbgState {
            reseed_counter: drbg.reseed_counter(),
            drbg_magic: DRBG_MAGIC,
            seed: OwnedSecret::from_vec(drbg.seed().to_vec()),
            last_value: drbg.last_value(),
        },
        clock_safe,
        reset_count,
        total_reset_count,
        failed_tries,
        lockout_auth_enabled,
        time_epoch,
        live_pcrs,
        oldest_saved_session,
        live_orderly_ram,
        max_nv_counter,
        user_nvram_attributes,
    })
}

fn commit_startup(runtime: &mut Tpm2Runtime, prepared: PreparedStartup) -> Result<(), TpmResult> {
    let state = runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?;

    let backup_orderly_state = state.persistent.orderly_state;
    let backup_reset_count = state.persistent.reset_count;
    let backup_total_reset_count = state.persistent.total_reset_count;
    let backup_failed_tries = state.persistent.failed_tries;
    let backup_lockout_auth_enabled = state.persistent.lockout_auth_enabled;
    let backup_time_epoch = state.persistent.time_epoch;

    state.persistent.orderly_state = SU_NONE_VALUE;
    state.persistent.reset_count = prepared.reset_count;
    state.persistent.total_reset_count = prepared.total_reset_count;
    state.persistent.failed_tries = prepared.failed_tries;
    state.persistent.lockout_auth_enabled = prepared.lockout_auth_enabled;
    if let Some(time_epoch) = prepared.time_epoch {
        state.persistent.time_epoch = time_epoch;
    }
    let mut backup_nv_attributes = Vec::with_capacity(prepared.user_nvram_attributes.len());
    for &(index, attributes) in &prepared.user_nvram_attributes {
        let OwnedUserNvramEntry::NvIndex {
            index: nv_index, ..
        } = &mut state.user_nvram.entries[index]
        else {
            continue;
        };
        backup_nv_attributes.push((index, nv_index.attributes));
        nv_index.attributes = attributes;
    }

    let nv_memory = match build_nv_image(state) {
        Ok(image) => image,
        Err(_) => {
            state.persistent.orderly_state = backup_orderly_state;
            state.persistent.reset_count = backup_reset_count;
            state.persistent.total_reset_count = backup_total_reset_count;
            state.persistent.failed_tries = backup_failed_tries;
            state.persistent.lockout_auth_enabled = backup_lockout_auth_enabled;
            state.persistent.time_epoch = backup_time_epoch;
            for (index, attributes) in backup_nv_attributes {
                if let OwnedUserNvramEntry::NvIndex {
                    index: nv_index, ..
                } = &mut state.user_nvram.entries[index]
                {
                    nv_index.attributes = attributes;
                }
            }
            return Err(TPM_RC_FAILURE);
        }
    };

    let context_slot_mask = prepared.new_reset.context_slot_mask;
    let null_seed_compat_level = prepared.new_reset.null_seed_compat_level;
    runtime.nv_memory = nv_memory;

    if prepared.time_epoch.is_some() {
        runtime.timer.timer_stopped = false;
    }
    let timer_was_reset = runtime.timer.consume_reset();
    let live = &mut runtime.live;
    if timer_was_reset {
        if is_orderly(prepared.prev_orderly) {
            live.orderly.self_heal_timer =
                live.orderly.self_heal_timer.wrapping_sub(live.orderly.time);
            live.orderly.lockout_timer = live.orderly.lockout_timer.wrapping_sub(live.orderly.time);
        } else {
            live.orderly.self_heal_timer = 0;
            live.orderly.lockout_timer = 0;
        }
    }
    live.orderly.drbg_state = prepared.new_drbg;
    live.orderly.clock_safe = prepared.clock_safe;
    live.state_reset = Some(prepared.new_reset);
    live.state_clear = Some(prepared.new_clear);
    live.ph_enable = true;
    live.pcr_reconfig = false;
    live.power_was_lost = false;
    live.da_used = false;
    live.prev_orderly_state = prepared.prev_orderly;
    live.startup_locality3 = prepared.startup_locality3;
    live.pcrs = prepared.live_pcrs;
    live.sessions = unoccupied_sessions();
    live.free_session_slots = MAX_LOADED_SESSIONS as u32;
    live.oldest_saved_session = prepared.oldest_saved_session;
    live.objects = unoccupied_objects();
    live.context_slot_mask = context_slot_mask;
    live.null_seed_compat_level = null_seed_compat_level;
    live.index_orderly_ram = prepared.live_orderly_ram;
    live.max_nv_counter = prepared.max_nv_counter;

    runtime.startup_received = true;
    runtime.nv_update_pending = true;
    Ok(())
}

fn carried_state_reset(old: &OwnedStateResetData) -> OwnedStateResetData {
    let mut context_array = *old.context_array;
    for slot in context_array.iter_mut() {
        if *slot <= MAX_LOADED_SESSIONS as u16 {
            *slot = 0;
        }
    }
    OwnedStateResetData {
        null_proof: OwnedSecret::copy_of(old.null_proof.as_bytes()),
        null_seed: OwnedSecret::copy_of(old.null_seed.as_bytes()),
        clear_count: old.clear_count,
        object_context_id: old.object_context_id,
        context_array: Box::new(context_array),
        context_slot_mask: old.context_slot_mask,
        context_counter: old.context_counter,
        command_audit_digest: old.command_audit_digest.clone(),
        restart_count: old.restart_count,
        pcr_counter: old.pcr_counter,
        commit_counter: old.commit_counter,
        commit_nonce: OwnedSecret::copy_of(old.commit_nonce.as_bytes()),
        commit_array: old.commit_array,
        null_seed_compat_level: old.null_seed_compat_level,
    }
}

fn fresh_state_clear() -> OwnedStateClearData {
    OwnedStateClearData {
        sh_enable: true,
        eh_enable: true,
        ph_enable_nv: true,
        platform_alg: TPM_ALG_NULL,
        platform_policy: Vec::new(),
        platform_auth: OwnedSecret::from_vec(Vec::new()),
        pcr_save: core::array::from_fn(|_| None),
        pcr_auth_values: core::array::from_fn(|_| OwnedSecret::from_vec(Vec::new())),
    }
}

fn pcr_changed_increments(mode: StartupMode) -> u32 {
    (0..IMPLEMENTATION_PCR)
        .filter(|&pcr| {
            let state_saved = mode == StartupMode::Resume && pcr_state_saved(pcr);
            !state_saved && (pcr == HCRTM_PCR || !pcr_in_tcb_group(pcr))
        })
        .count() as u32
}

fn build_startup_pcrs(
    runtime: &Tpm2Runtime,
    state: &crate::library::tpm2::persistent::OwnedPersistentState,
    allocation: &OwnedPcrAllocation,
    mode: StartupMode,
    locality: u8,
    drtm_pre_startup: bool,
) -> Result<Vec<OwnedPcr>, TpmResult> {
    let mut out = Vec::with_capacity(IMPLEMENTATION_PCR);
    for pcr in 0..IMPLEMENTATION_PCR {
        let restored = mode == StartupMode::Resume && pcr_state_saved(pcr);
        let keep_hcrtm = pcr == HCRTM_PCR && mode != StartupMode::Resume && drtm_pre_startup;
        let mut banks: [Option<Vec<u8>>; PCR_SLOT_BANKS.len()] = core::array::from_fn(|_| None);
        for (slot, &(hash_alg, digest_size)) in PCR_SLOT_BANKS.iter().enumerate() {
            if !allocation_selects(allocation, hash_alg, pcr) {
                continue;
            }
            let value = if restored {
                let clear = state.state_clear.as_ref().ok_or(TPM_RC_FAILURE)?;
                let bank = clear.pcr_save[slot].as_ref().ok_or(TPM_RC_FAILURE)?;
                bank.pcrs
                    .get(pcr * digest_size..(pcr + 1) * digest_size)
                    .ok_or(TPM_RC_FAILURE)?
                    .to_vec()
            } else if keep_hcrtm {
                previous_pcr_bank(runtime, pcr, slot).unwrap_or_else(|| vec![0u8; digest_size])
            } else {
                let fill = if pcr_resets_to_ones(pcr) { 0xff } else { 0x00 };
                let mut value = vec![fill; digest_size];
                if pcr == HCRTM_PCR {
                    value[digest_size - 1] = locality;
                }
                value
            };
            banks[slot] = Some(value);
        }
        out.push(OwnedPcr { banks });
    }
    Ok(out)
}

fn previous_pcr_bank(runtime: &Tpm2Runtime, pcr: usize, slot: usize) -> Option<Vec<u8>> {
    runtime.live.pcrs.get(pcr)?.banks[slot].clone()
}

fn context_id_oldest(
    context_array: &[u16; MAX_ACTIVE_SESSIONS],
    context_counter: u64,
    slot_mask: u16,
) -> u32 {
    let masked = |value: u16| value & slot_mask;
    let low_bits = masked(context_counter as u16);
    let mut smallest = masked(0xffff);
    let mut oldest = MAX_ACTIVE_SESSIONS as u32 + 1;
    for (index, &entry) in context_array.iter().enumerate() {
        if entry > MAX_LOADED_SESSIONS as u16 {
            let age = masked(entry.wrapping_sub(low_bits));
            if age <= smallest {
                smallest = age;
                oldest = index as u32;
            }
        }
    }
    oldest
}

#[cfg(test)]
mod tests {
    fn process(
        runtime: &mut crate::library::tpm2::runtime::Tpm2Runtime,
        locality: u8,
        command: &crate::library::CommandInput,
        commit_nv: impl FnOnce(
            &crate::library::tpm2::runtime::Tpm2Runtime,
        ) -> Result<(), crate::types::TpmResult>,
    ) -> Result<Vec<u8>, crate::types::TpmResult> {
        crate::library::tpm2::process(
            runtime,
            crate::library::tpm2::PlatformInputs::at_locality(locality),
            command,
            &crate::library::tpm2::clock::RecordingClock::new(1_600_000_000_000, 5_000_000),
            commit_nv,
        )
    }
    use super::*;
    use crate::library::CommandInput;
    use crate::library::constants::TPM_FAIL;
    use crate::library::tpm2::command::core::dispatcher::dispatch;
    use crate::library::tpm2::command::core::header::{parse_command, serialize_response};
    use crate::library::tpm2::command::core::registry::TPM_CC_STARTUP;
    use crate::library::tpm2::crypto::Drbg;
    use crate::library::tpm2::manufacture::manufacture_state;
    use crate::library::tpm2::nv::{IndexOrderlyRamFixture, UserNvramFixture};
    use crate::library::tpm2::nv::{
        TPM_NT_COUNTER, TPMA_NV_CLEAR_STCLEAR, TPMA_NV_READLOCKED, TPMA_NV_TPM_NT_SHIFT,
        TPMA_NV_WRITEDEFINE, TPMA_NV_WRITELOCKED, TPMA_NV_WRITTEN,
    };
    use crate::library::tpm2::pcr::{PcrAllocationFixture, PcrPoliciesFixture};
    use crate::library::tpm2::persistent::{
        CompatTailFixture, OrderlyFixture, PersistentAllEnvelope, PrefixFixture,
        materialize_persistent_state,
    };
    use crate::library::tpm2::profile::validate_user_profile;
    use crate::library::tpm2::runtime::{commit_manufactured_state, commit_restored_state};
    use crate::library::tpm2::state::{PcrSaveFixture, StateClearFixture, StateResetFixture};
    use crate::library::tpm2::{
        audit, compile_constants, lockout, parse_persistent_all_payload, pp_list,
    };
    use crate::types::TpmResult;

    const SUCCESS_RESPONSE: [u8; 10] = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00];
    const INITIALIZE_RESPONSE: [u8; 10] =
        [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x00];
    const LOCALITY_RESPONSE: [u8; 10] =
        [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x09, 0x07];
    const NV_UNAVAILABLE_RESPONSE: [u8; 10] =
        [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x09, 0x23];
    const VALUE_PARAM1_RESPONSE: [u8; 10] =
        [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0xc4];
    const INSUFFICIENT_PARAM1_RESPONSE: [u8; 10] =
        [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0xda];
    const SIZE_RESPONSE: [u8; 10] = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x95];
    const AUTH_CONTEXT_RESPONSE: [u8; 10] =
        [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x45];
    const INSUFFICIENT_RESPONSE: [u8; 10] =
        [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x9a];
    const FAILURE_RESPONSE: [u8; 10] = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x01];

    fn deterministic_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
        let len = buffer.len() as u8;
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_add(len) ^ 0x71;
        }
        Ok(())
    }

    fn failing_entropy(_buffer: &mut [u8]) -> Result<(), TpmResult> {
        Err(TPM_FAIL)
    }

    fn manufactured_runtime() -> Box<Tpm2Runtime> {
        let profile = validate_user_profile(None).expect("the null profile validates");
        let state = manufacture_state(profile, deterministic_entropy).expect("manufactures");
        let mut runtime = commit_manufactured_state(state).expect("commits");
        runtime.entropy = deterministic_entropy;
        runtime
    }

    struct RestoredFixture {
        orderly_state: u16,
        allocation: PcrAllocationFixture,
        lockout: lockout::LockoutFixture,
        state_reset: StateResetFixture,
        state_clear: StateClearFixture,
        index_orderly_ram: IndexOrderlyRamFixture,
        user_nvram: UserNvramFixture,
    }

    impl Default for RestoredFixture {
        fn default() -> Self {
            Self {
                orderly_state: TPM_SU_STATE,
                allocation: PcrAllocationFixture::default(),
                lockout: lockout::LockoutFixture::default(),
                state_reset: StateResetFixture::default(),
                state_clear: StateClearFixture::default(),
                index_orderly_ram: IndexOrderlyRamFixture::default(),
                user_nvram: UserNvramFixture::default(),
            }
        }
    }

    impl RestoredFixture {
        fn runtime(self) -> Box<Tpm2Runtime> {
            let with_su_state = (self.orderly_state & TPM_SU_STATE_MASK) == TPM_SU_STATE;
            let mut sections = OrderlyFixture::default().bytes();
            if with_su_state {
                sections.extend_from_slice(&self.state_reset.bytes());
                sections.extend_from_slice(&self.state_clear.bytes());
            }
            sections.extend_from_slice(&self.index_orderly_ram.bytes());
            sections.extend_from_slice(&self.user_nvram.bytes());
            sections.extend_from_slice(&[0x01, 0x00, 0x00]);

            let mut payload = compile_constants::marshalled_section(3);
            payload.extend_from_slice(
                &PrefixFixture {
                    tail: PcrPoliciesFixture {
                        tail: PcrAllocationFixture {
                            tail: pp_list::PpListFixture {
                                tail: lockout::LockoutFixture {
                                    orderly_state: self.orderly_state,
                                    tail: audit::AuditFixture {
                                        tail: CompatTailFixture {
                                            tail: sections,
                                            ..CompatTailFixture::default()
                                        }
                                        .bytes(),
                                        ..audit::AuditFixture::default()
                                    }
                                    .bytes(),
                                    ..self.lockout
                                }
                                .bytes(),
                                ..pp_list::PpListFixture::default()
                            }
                            .bytes(),
                            ..self.allocation
                        }
                        .bytes(),
                        ..PcrPoliciesFixture::default()
                    }
                    .bytes(),
                    ..PrefixFixture::default()
                }
                .bytes(),
            );

            let mut blob = vec![0x00, 0x03, 0xab, 0x36, 0x47, 0x23, 0x00, 0x01];
            blob.extend_from_slice(&payload);
            blob.extend_from_slice(&[0xab, 0x36, 0x47, 0x23]);

            let envelope = PersistentAllEnvelope::parse(&blob).expect("envelope parses");
            let decoded = parse_persistent_all_payload(&envelope).expect("payload parses");
            let candidate = materialize_persistent_state(decoded).expect("materializes");
            let mut runtime = commit_restored_state(candidate).expect("commits");
            runtime.entropy = deterministic_entropy;
            runtime
        }
    }

    fn startup_command(startup_type: u16) -> Vec<u8> {
        let mut out = vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0c];
        out.extend_from_slice(&TPM_CC_STARTUP.to_be_bytes());
        out.extend_from_slice(&startup_type.to_be_bytes());
        out
    }

    #[track_caller]
    fn dispatch_bytes(runtime: &mut Tpm2Runtime, bytes: &[u8]) -> Vec<u8> {
        let input = CommandInput::new(bytes.len() as u32, bytes.to_vec());
        let parsed = parse_command(&input).expect("the header parses");
        serialize_response(&dispatch(runtime, &parsed)).expect("the response serializes")
    }

    struct Snapshot {
        startup_received: bool,
        orderly_state: u16,
        reset_count: u32,
        total_reset_count: u64,
        failed_tries: u32,
        clock_safe: u8,
        drbg_counter: u64,
        drbg_seed: Vec<u8>,
        reset_summary: Option<(u32, u32, u32, u64)>,
        clear_present: bool,
        nv_memory: Box<[u8]>,
        live_pcrs_present: bool,
        nv_index_attributes: Vec<u32>,
        live_orderly_entries: Vec<(u32, Vec<u8>)>,
        live_drbg_counter: u64,
        live_drbg_seed: Vec<u8>,
        live_clock_safe: u8,
        live_reset_summary: Option<(u32, u32, u32, u64)>,
        live_clear_present: bool,
        nv_update_pending: bool,
    }

    fn snapshot(runtime: &Tpm2Runtime) -> Snapshot {
        let state = runtime.state.as_ref().expect("state present");
        Snapshot {
            startup_received: runtime.startup_received,
            orderly_state: state.persistent.orderly_state,
            reset_count: state.persistent.reset_count,
            total_reset_count: state.persistent.total_reset_count,
            failed_tries: state.persistent.failed_tries,
            clock_safe: state.orderly.clock_safe,
            drbg_counter: state.orderly.drbg_state.reseed_counter,
            drbg_seed: state.orderly.drbg_state.seed.expose().to_vec(),
            reset_summary: state.state_reset.as_ref().map(|reset| {
                (
                    reset.clear_count,
                    reset.restart_count,
                    reset.pcr_counter,
                    reset.context_counter,
                )
            }),
            clear_present: state.state_clear.is_some(),
            nv_memory: runtime.nv_memory.clone(),
            live_pcrs_present: !runtime
                .live
                .pcrs
                .iter()
                .all(|pcr| pcr.banks.iter().all(Option::is_none)),
            nv_index_attributes: nv_index_attributes(state),
            live_orderly_entries: runtime
                .live
                .index_orderly_ram
                .entries
                .iter()
                .map(|entry| (entry.attributes, entry.data.clone()))
                .collect(),
            live_drbg_counter: runtime.live.orderly.drbg_state.reseed_counter,
            live_drbg_seed: runtime.live.orderly.drbg_state.seed.expose().to_vec(),
            live_clock_safe: runtime.live.orderly.clock_safe,
            live_reset_summary: runtime.live.state_reset.as_ref().map(|reset| {
                (
                    reset.clear_count,
                    reset.restart_count,
                    reset.pcr_counter,
                    reset.context_counter,
                )
            }),
            live_clear_present: runtime.live.state_clear.is_some(),
            nv_update_pending: runtime.nv_update_pending,
        }
    }

    fn nv_index_attributes(
        state: &crate::library::tpm2::persistent::OwnedPersistentState,
    ) -> Vec<u32> {
        state
            .user_nvram
            .entries
            .iter()
            .filter_map(|entry| match entry {
                OwnedUserNvramEntry::NvIndex { index, .. } => Some(index.attributes),
                OwnedUserNvramEntry::Persistent { .. } => None,
            })
            .collect()
    }

    #[track_caller]
    fn assert_unchanged(runtime: &Tpm2Runtime, snapshot: &Snapshot) {
        let state = runtime.state.as_ref().expect("state present");
        assert_eq!(runtime.startup_received, snapshot.startup_received);
        assert_eq!(state.persistent.orderly_state, snapshot.orderly_state);
        assert_eq!(state.persistent.reset_count, snapshot.reset_count);
        assert_eq!(
            state.persistent.total_reset_count,
            snapshot.total_reset_count
        );
        assert_eq!(state.persistent.failed_tries, snapshot.failed_tries);
        assert_eq!(state.orderly.clock_safe, snapshot.clock_safe);
        assert_eq!(
            state.orderly.drbg_state.reseed_counter,
            snapshot.drbg_counter
        );
        assert_eq!(
            state.orderly.drbg_state.seed.expose(),
            &snapshot.drbg_seed[..]
        );
        assert_eq!(
            state.state_reset.as_ref().map(|reset| (
                reset.clear_count,
                reset.restart_count,
                reset.pcr_counter,
                reset.context_counter,
            )),
            snapshot.reset_summary
        );
        assert_eq!(state.state_clear.is_some(), snapshot.clear_present);
        assert_eq!(runtime.nv_memory, snapshot.nv_memory);
        assert_eq!(nv_index_attributes(state), snapshot.nv_index_attributes);
        assert_eq!(
            runtime
                .live
                .index_orderly_ram
                .entries
                .iter()
                .map(|entry| (entry.attributes, entry.data.clone()))
                .collect::<Vec<_>>(),
            snapshot.live_orderly_entries
        );
        assert_eq!(
            !runtime
                .live
                .pcrs
                .iter()
                .all(|pcr| pcr.banks.iter().all(Option::is_none)),
            snapshot.live_pcrs_present
        );
        assert_eq!(
            runtime.live.orderly.drbg_state.reseed_counter,
            snapshot.live_drbg_counter
        );
        assert_eq!(
            runtime.live.orderly.drbg_state.seed.expose(),
            &snapshot.live_drbg_seed[..]
        );
        assert_eq!(runtime.live.orderly.clock_safe, snapshot.live_clock_safe);
        assert_eq!(
            runtime.live.state_reset.as_ref().map(|reset| (
                reset.clear_count,
                reset.restart_count,
                reset.pcr_counter,
                reset.context_counter,
            )),
            snapshot.live_reset_summary
        );
        assert_eq!(
            runtime.live.state_clear.is_some(),
            snapshot.live_clear_present
        );
        assert_eq!(runtime.nv_update_pending, snapshot.nv_update_pending);
    }

    #[test]
    fn clear_startup_succeeds_on_a_manufactured_runtime() {
        let mut runtime = manufactured_runtime();
        let response = dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR));
        assert_eq!(response, SUCCESS_RESPONSE);
        assert!(runtime.startup_received);
    }

    #[test]
    fn startup_type_decodes_big_endian() {
        let mut runtime = RestoredFixture::default().runtime();
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(0x0100)),
            VALUE_PARAM1_RESPONSE
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_STATE)),
            SUCCESS_RESPONSE
        );
    }

    #[test]
    fn startup_succeeds_at_locality_0_and_3() {
        for locality in [0u8, 3] {
            let mut runtime = manufactured_runtime();
            runtime.locality = locality;
            assert_eq!(
                dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
                SUCCESS_RESPONSE,
                "locality {locality}"
            );
        }
    }

    #[test]
    fn a_second_startup_returns_initialize_without_mutation() {
        let mut runtime = manufactured_runtime();
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
            SUCCESS_RESPONSE
        );
        let after_first = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
            INITIALIZE_RESPONSE
        );
        assert_unchanged(&runtime, &after_first);
    }

    #[test]
    fn a_second_startup_with_malformed_parameters_still_returns_initialize() {
        let mut runtime = manufactured_runtime();
        dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR));
        let after_first = snapshot(&runtime);
        let mut truncated = vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0a];
        truncated.extend_from_slice(&TPM_CC_STARTUP.to_be_bytes());
        assert_eq!(
            dispatch_bytes(&mut runtime, &truncated),
            INITIALIZE_RESPONSE
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(0x0002)),
            INITIALIZE_RESPONSE
        );
        assert_unchanged(&runtime, &after_first);
    }

    #[test]
    fn unknown_commands_still_answer_command_code_after_startup() {
        let mut runtime = manufactured_runtime();
        dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR));
        let mut unknown = vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0c];
        unknown.extend_from_slice(&0x2000_0000u32.to_be_bytes());
        unknown.extend_from_slice(&[0x00, 0x00]);
        assert_eq!(
            dispatch_bytes(&mut runtime, &unknown),
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x43]
        );
    }

    #[test]
    fn a_failed_startup_leaves_the_tpm_eligible_for_a_later_startup() {
        let mut runtime = manufactured_runtime();
        runtime.locality = 2;
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
            LOCALITY_RESPONSE
        );
        assert!(!runtime.startup_received);
        runtime.locality = 0;
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
            SUCCESS_RESPONSE
        );
    }

    #[test]
    fn localities_follow_the_oracle() {
        for (locality, expected) in [
            (1u8, LOCALITY_RESPONSE),
            (2, LOCALITY_RESPONSE),
            (4, LOCALITY_RESPONSE),
            (5, SUCCESS_RESPONSE),
            (31, SUCCESS_RESPONSE),
            (32, LOCALITY_RESPONSE),
            (255, LOCALITY_RESPONSE),
        ] {
            let mut runtime = manufactured_runtime();
            let command = startup_command(TPM_SU_CLEAR);
            let input = CommandInput::new(command.len() as u32, command);
            let response = process(&mut runtime, locality, &input, |_| Ok(())).unwrap();
            assert_eq!(response, expected, "locality {locality}");
            assert_eq!(
                runtime.startup_received,
                expected == SUCCESS_RESPONSE,
                "locality {locality}"
            );
        }
    }

    #[test]
    fn locality_failure_is_transactional() {
        let mut runtime = manufactured_runtime();
        runtime.locality = 2;
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
            LOCALITY_RESPONSE
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn unavailable_nv_returns_nv_unavailable_and_wins_over_locality() {
        let mut runtime = manufactured_runtime();
        runtime.nv_available = false;
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
            NV_UNAVAILABLE_RESPONSE
        );
        assert_unchanged(&runtime, &before);

        runtime.locality = 2;
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
            NV_UNAVAILABLE_RESPONSE
        );
        assert_unchanged(&runtime, &before);

        runtime.locality = 0;
        runtime.nv_available = true;
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
            SUCCESS_RESPONSE
        );
    }

    #[test]
    fn malformed_parameters_match_the_oracle() {
        let mut missing = vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0a];
        missing.extend_from_slice(&TPM_CC_STARTUP.to_be_bytes());
        let mut one_byte = vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0b];
        one_byte.extend_from_slice(&TPM_CC_STARTUP.to_be_bytes());
        one_byte.push(0x00);
        let mut trailing = vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0d];
        trailing.extend_from_slice(&TPM_CC_STARTUP.to_be_bytes());
        trailing.extend_from_slice(&[0x00, 0x00, 0x00]);

        for (label, command, expected) in [
            ("missing", missing, INSUFFICIENT_PARAM1_RESPONSE),
            ("one_byte", one_byte, INSUFFICIENT_PARAM1_RESPONSE),
            ("trailing", trailing, SIZE_RESPONSE),
            ("invalid", startup_command(0x0002), VALUE_PARAM1_RESPONSE),
            (
                "invalid_max",
                startup_command(0xffff),
                VALUE_PARAM1_RESPONSE,
            ),
        ] {
            let mut runtime = manufactured_runtime();
            let before = snapshot(&runtime);
            assert_eq!(dispatch_bytes(&mut runtime, &command), expected, "{label}");
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn session_tagged_requests_match_the_oracle() {
        let mut no_authsize = vec![0x80, 0x02, 0x00, 0x00, 0x00, 0x0a];
        no_authsize.extend_from_slice(&TPM_CC_STARTUP.to_be_bytes());
        let mut authsize_zero = vec![0x80, 0x02, 0x00, 0x00, 0x00, 0x10];
        authsize_zero.extend_from_slice(&TPM_CC_STARTUP.to_be_bytes());
        authsize_zero.extend_from_slice(&[0x00; 4]);
        authsize_zero.extend_from_slice(&[0x00, 0x00]);
        let mut authsize_too_big = vec![0x80, 0x02, 0x00, 0x00, 0x00, 0x12];
        authsize_too_big.extend_from_slice(&TPM_CC_STARTUP.to_be_bytes());
        authsize_too_big.extend_from_slice(&0x20u32.to_be_bytes());
        authsize_too_big.extend_from_slice(&[0x00; 4]);
        let mut pw_auth = vec![0x80, 0x02, 0x00, 0x00, 0x00, 0x19];
        pw_auth.extend_from_slice(&TPM_CC_STARTUP.to_be_bytes());
        pw_auth.extend_from_slice(&0x09u32.to_be_bytes());
        pw_auth.extend_from_slice(&[0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00]);
        pw_auth.extend_from_slice(&[0x00, 0x00]);

        for (label, command, expected) in [
            ("no_authsize", no_authsize, INSUFFICIENT_RESPONSE),
            ("authsize_zero", authsize_zero, SIZE_RESPONSE),
            ("authsize_too_big", authsize_too_big, SIZE_RESPONSE),
            ("pw_auth", pw_auth, AUTH_CONTEXT_RESPONSE),
        ] {
            let mut runtime = manufactured_runtime();
            let before = snapshot(&runtime);
            assert_eq!(dispatch_bytes(&mut runtime, &command), expected, "{label}");
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn su_reset_transition_matches_the_vendored_semantics() {
        let mut runtime = manufactured_runtime();
        let before = snapshot(&runtime);
        assert!(before.reset_summary.is_none(), "manufacture carries no gr");
        assert!(!before.clear_present);
        let seed_before = before.drbg_seed.clone();

        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
            SUCCESS_RESPONSE
        );

        let state = runtime.state.as_ref().unwrap();
        assert_eq!(state.persistent.reset_count, 1);
        assert_eq!(state.persistent.total_reset_count, 1);
        assert_eq!(state.persistent.orderly_state, 0xffff, "SU_NONE_VALUE");
        assert_eq!(
            runtime.live.orderly.clock_safe, 1,
            "orderly shutdown keeps the safe flag"
        );
        assert!(
            state.state_reset.is_none() && state.state_clear.is_none(),
            "the fresh gr/gc are live-only; NV keeps none"
        );

        let reset = runtime.live.state_reset.as_ref().expect("fresh live gr");
        assert_eq!(reset.clear_count, 0);
        assert_eq!(reset.restart_count, 0);
        assert_eq!(reset.object_context_id, 0);
        assert_eq!(reset.context_counter, 4, "MAX_LOADED_SESSIONS + 1");
        assert_eq!(reset.context_slot_mask, 0xffff);
        assert_eq!(*reset.context_array, [0u16; MAX_ACTIVE_SESSIONS]);
        assert!(reset.command_audit_digest.is_empty());
        assert_eq!(reset.pcr_counter, 20, "24 PCRs minus the 4 TCB-group PCRs");
        assert_eq!(reset.commit_counter, 0);
        assert_eq!(reset.commit_array, [0u8; COMMIT_ARRAY_SIZE]);
        assert_eq!(reset.null_seed_compat_level, SEED_COMPAT_LEVEL_LAST);
        assert_eq!(reset.null_proof.expose().len(), PROOF_SIZE);
        assert_eq!(reset.null_seed.expose().len(), PRIMARY_SEED_SIZE);
        assert_eq!(reset.commit_nonce.expose().len(), COMMIT_NONCE_SIZE);
        assert!(reset.null_proof.expose().iter().any(|&byte| byte != 0));
        assert_ne!(reset.null_proof.expose(), reset.null_seed.expose());
        assert_ne!(reset.null_proof.expose(), reset.commit_nonce.expose());

        let clear = runtime.live.state_clear.as_ref().expect("fresh live gc");
        assert!(clear.sh_enable && clear.eh_enable && clear.ph_enable_nv);
        assert_eq!(clear.platform_alg, 0x0010);
        assert!(clear.platform_policy.is_empty());
        assert!(clear.platform_auth.expose().is_empty());
        assert!(clear.pcr_save.iter().all(Option::is_none));
        assert!(
            clear
                .pcr_auth_values
                .iter()
                .all(|auth| auth.expose().is_empty())
        );

        let live_drbg = &runtime.live.orderly.drbg_state;
        assert_eq!(live_drbg.reseed_counter, 4);
        assert_eq!(live_drbg.drbg_magic, 0x4742_5244);
        assert_ne!(live_drbg.seed.expose(), &seed_before[..]);
        assert_eq!(live_drbg.last_value, [0; 4]);
        assert_eq!(
            state.orderly.drbg_state.seed.expose(),
            &seed_before[..],
            "NV-backed go is untouched by Startup"
        );

        assert_eq!(runtime.live.context_slot_mask, 0xffff);
        assert_eq!(runtime.live.null_seed_compat_level, SEED_COMPAT_LEVEL_LAST);

        assert_ne!(runtime.nv_memory, before.nv_memory);
        let rebuilt = build_nv_image(state).expect("the committed state serializes");
        assert_eq!(runtime.nv_memory, rebuilt);
    }

    #[test]
    fn su_reset_initializes_the_pcr_state_from_the_active_allocation() {
        for locality in [0u8, 3] {
            let mut runtime = manufactured_runtime();
            runtime.locality = locality;
            assert_eq!(
                dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
                SUCCESS_RESPONSE
            );
            let pcrs = &runtime.live.pcrs;
            assert_eq!(pcrs.len(), IMPLEMENTATION_PCR);
            for (slot, &(_, digest_size)) in PCR_SLOT_BANKS.iter().enumerate() {
                let pcr0 = pcrs[0].banks[slot].as_ref().expect("HCRTM PCR bank");
                assert_eq!(pcr0.len(), digest_size);
                assert!(pcr0[..digest_size - 1].iter().all(|&byte| byte == 0));
                assert_eq!(pcr0[digest_size - 1], locality, "HCRTM locality byte");

                let pcr16 = pcrs[16].banks[slot].as_ref().unwrap();
                assert!(pcr16.iter().all(|&byte| byte == 0), "debug PCR resets to 0");
                let pcr23 = pcrs[23].banks[slot].as_ref().unwrap();
                assert!(pcr23.iter().all(|&byte| byte == 0));
                for (drtm_pcr, pcr) in pcrs.iter().enumerate() {
                    if !(17..=22).contains(&drtm_pcr) {
                        continue;
                    }
                    let value = pcr.banks[slot].as_ref().unwrap();
                    assert!(
                        value.iter().all(|&byte| byte == 0xff),
                        "locality-4 resettable PCR {drtm_pcr} resets to ones"
                    );
                }
            }
        }
    }

    fn all_pcrs_allocation() -> PcrAllocationFixture {
        PcrAllocationFixture {
            selections: vec![(0x000b, 3, vec![0xff, 0xff, 0xff])],
            ..PcrAllocationFixture::default()
        }
    }

    const SHA256_SLOT: usize = 1;

    #[test]
    fn su_restart_preserves_reset_scoped_state_and_reinitializes_clear_state() {
        let mut context_array = vec![0u16; MAX_ACTIVE_SESSIONS];
        context_array[2] = 2; // references a loaded session slot -> reclaimed
        context_array[7] = 9; // saved context -> preserved
        let mut runtime = RestoredFixture {
            allocation: all_pcrs_allocation(),
            state_reset: StateResetFixture {
                clear_count: 5,
                restart_count: 11,
                pcr_counter: 100,
                object_context_id: 77,
                context_counter: 21,
                context_array,
                null_proof: vec![0x0f; 8],
                null_seed: vec![0x5e; 8],
                command_audit_digest: vec![0x2a; 32],
                ..StateResetFixture::default()
            },
            state_clear: StateClearFixture {
                sh_enable: 0,
                eh_enable: 0,
                platform_alg: 0x000b,
                platform_auth: vec![0x44; 20],
                ..StateClearFixture::default()
            },
            ..RestoredFixture::default()
        }
        .runtime();

        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
            SUCCESS_RESPONSE
        );

        let state = runtime.state.as_ref().unwrap();
        assert_eq!(state.persistent.reset_count, 0, "a Restart is not a Reset");
        assert_eq!(state.persistent.total_reset_count, 0);
        assert_eq!(state.persistent.orderly_state, 0xffff);
        assert_eq!(
            state.state_reset.as_ref().unwrap().clear_count,
            5,
            "the NV-saved gr keeps its pre-Startup value"
        );
        assert_eq!(
            state.state_clear.as_ref().unwrap().platform_alg,
            0x000b,
            "the NV-saved gc keeps its pre-Startup value"
        );

        let reset = runtime.live.state_reset.as_ref().unwrap();
        assert_eq!(reset.clear_count, 6, "clearCount++");
        assert_eq!(reset.restart_count, 12, "restartCount++");
        assert_eq!(reset.pcr_counter, 120, "20 PCRChanged increments");
        assert_eq!(reset.object_context_id, 77, "preserved");
        assert_eq!(reset.context_counter, 21, "preserved");
        assert_eq!(reset.null_proof.expose(), &[0x0f; 8][..], "preserved");
        assert_eq!(reset.null_seed.expose(), &[0x5e; 8][..], "preserved");
        assert_eq!(reset.command_audit_digest, vec![0x2a; 32], "preserved");
        assert_eq!(reset.context_array[2], 0, "loaded-session slot reclaimed");
        assert_eq!(reset.context_array[7], 9, "saved context preserved");

        let clear = runtime.live.state_clear.as_ref().unwrap();
        assert!(clear.sh_enable && clear.eh_enable, "hierarchies re-enabled");
        assert_eq!(
            clear.platform_alg, 0x0010,
            "platformAlg reset to TPM_ALG_NULL"
        );
        assert!(
            clear.platform_auth.expose().is_empty(),
            "platformAuth cleared"
        );
        assert!(clear.pcr_save.iter().all(Option::is_none));

        let pcrs = &runtime.live.pcrs;
        let pcr5 = pcrs[5].banks[SHA256_SLOT].as_ref().unwrap();
        assert!(pcr5.iter().all(|&byte| byte == 0));

        assert_eq!(runtime.live.orderly.drbg_state.reseed_counter, 1);
        assert_eq!(state.orderly.drbg_state.reseed_counter, 0);

        assert_eq!(
            runtime.nv_memory,
            build_nv_image(state).unwrap(),
            "the NV image tracks the owned state"
        );
    }

    #[test]
    fn su_resume_restores_saved_state() {
        let mut sha256_save = vec![0u8; 16 * 32];
        sha256_save[5 * 32..6 * 32].fill(0xaa);
        let pcr_save = PcrSaveFixture {
            banks: vec![
                (0x0004, 320, vec![0u8; 320]),
                (0x000b, 512, sha256_save),
                (0x000c, 768, vec![0u8; 768]),
                (0x000d, 1024, vec![0u8; 1024]),
            ],
            ..PcrSaveFixture::default()
        };
        let mut runtime = RestoredFixture {
            allocation: all_pcrs_allocation(),
            state_reset: StateResetFixture {
                clear_count: 5,
                restart_count: 11,
                pcr_counter: 100,
                ..StateResetFixture::default()
            },
            state_clear: StateClearFixture {
                sh_enable: 0,
                platform_alg: 0x000b,
                platform_auth: vec![0x44; 20],
                pcr_save: pcr_save.bytes(),
                ..StateClearFixture::default()
            },
            ..RestoredFixture::default()
        }
        .runtime();

        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_STATE)),
            SUCCESS_RESPONSE
        );

        let state = runtime.state.as_ref().unwrap();
        assert_eq!(state.persistent.reset_count, 0);
        assert_eq!(state.persistent.total_reset_count, 0);
        assert_eq!(state.persistent.orderly_state, 0xffff);
        assert_eq!(
            state.state_reset.as_ref().unwrap().restart_count,
            11,
            "the NV-saved gr keeps its pre-Startup value"
        );

        let reset = runtime.live.state_reset.as_ref().unwrap();
        assert_eq!(reset.clear_count, 5, "clearCount preserved on Resume");
        assert_eq!(reset.restart_count, 12, "restartCount++");
        assert_eq!(
            reset.pcr_counter, 104,
            "only the 4 unsaved non-TCB PCRs report PCRChanged"
        );

        let clear = runtime.live.state_clear.as_ref().unwrap();
        assert!(!clear.sh_enable, "clear-scoped state restored, not reset");
        assert_eq!(clear.platform_alg, 0x000b);
        assert_eq!(clear.platform_auth.expose(), &[0x44; 20][..]);

        let pcrs = &runtime.live.pcrs;
        let pcr5 = pcrs[5].banks[SHA256_SLOT].as_ref().unwrap();
        assert_eq!(pcr5, &vec![0xaa; 32], "saved PCR restored");
        let pcr17 = pcrs[17].banks[SHA256_SLOT].as_ref().unwrap();
        assert!(
            pcr17.iter().all(|&byte| byte == 0xff),
            "unsaved PCR reinitialized"
        );
        let pcr16 = pcrs[16].banks[SHA256_SLOT].as_ref().unwrap();
        assert!(pcr16.iter().all(|&byte| byte == 0));

        assert_eq!(
            runtime.live.orderly.drbg_state.reseed_counter, 1,
            "reseed only"
        );
        assert_eq!(state.orderly.drbg_state.reseed_counter, 0, "NV untouched");
        assert_eq!(runtime.nv_memory, build_nv_image(state).unwrap());
    }

    #[test]
    fn resume_at_locality_3_requires_the_saved_locality_flag() {
        let mut runtime = RestoredFixture::default().runtime();
        runtime.locality = 3;
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_STATE)),
            LOCALITY_RESPONSE
        );
        assert_unchanged(&runtime, &before);

        let mut runtime = RestoredFixture {
            orderly_state: 0x4001,
            ..RestoredFixture::default()
        }
        .runtime();
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_STATE)),
            LOCALITY_RESPONSE
        );
        assert_unchanged(&runtime, &before);
        runtime.locality = 3;
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_STATE)),
            SUCCESS_RESPONSE
        );
    }

    #[test]
    fn resume_with_a_pre_startup_flag_mismatch_is_rejected() {
        let mut runtime = RestoredFixture {
            orderly_state: 0x8001,
            ..RestoredFixture::default()
        }
        .runtime();
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_STATE)),
            VALUE_PARAM1_RESPONSE
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn resume_without_a_prior_state_shutdown_is_rejected() {
        let mut runtime = manufactured_runtime();
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_STATE)),
            VALUE_PARAM1_RESPONSE
        );
        assert_unchanged(&runtime, &before);

        let mut runtime = RestoredFixture {
            orderly_state: TPM_SU_CLEAR,
            ..RestoredFixture::default()
        }
        .runtime();
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_STATE)),
            VALUE_PARAM1_RESPONSE
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn resume_with_missing_su_sections_fails_transactionally() {
        for drop_reset in [true, false] {
            let mut runtime = RestoredFixture::default().runtime();
            let state = runtime.state.as_mut().unwrap();
            if drop_reset {
                state.state_reset = None;
            } else {
                state.state_clear = None;
            }
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(&mut runtime, &startup_command(TPM_SU_STATE)),
                FAILURE_RESPONSE,
                "drop_reset {drop_reset}"
            );
            assert_unchanged(&runtime, &before);
            assert!(!runtime.startup_received);
        }
    }

    #[test]
    fn resume_with_unavailable_nv_fails_transactionally() {
        let mut runtime = RestoredFixture::default().runtime();
        runtime.nv_available = false;
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_STATE)),
            NV_UNAVAILABLE_RESPONSE
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn non_orderly_reset_clears_the_clock_safe_flag_and_counts_da() {
        let mut runtime = RestoredFixture {
            orderly_state: 0xfffe,
            lockout: lockout::LockoutFixture {
                failed_tries: 1,
                max_tries: 5,
                recovery_time: 1000,
                lockout_recovery: 1000,
                lockout_auth_enabled: 1,
                ..lockout::LockoutFixture::default()
            },
            ..RestoredFixture::default()
        }
        .runtime();
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
            SUCCESS_RESPONSE
        );
        let state = runtime.state.as_ref().unwrap();
        assert_eq!(
            state.persistent.reset_count, 1,
            "non-orderly boot is a Reset"
        );
        assert_eq!(runtime.live.orderly.clock_safe, 0, "clockSafe cleared");
        assert_eq!(state.orderly.clock_safe, 1, "NV copy untouched");
        assert_eq!(state.persistent.failed_tries, 2, "g_daUsed counted");

        let mut runtime = RestoredFixture {
            orderly_state: 0xffff,
            lockout: lockout::LockoutFixture {
                failed_tries: 1,
                max_tries: 5,
                recovery_time: 1000,
                lockout_recovery: 1000,
                lockout_auth_enabled: 1,
                ..lockout::LockoutFixture::default()
            },
            ..RestoredFixture::default()
        }
        .runtime();
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
            SUCCESS_RESPONSE
        );
        let state = runtime.state.as_ref().unwrap();
        assert_eq!(state.persistent.failed_tries, 1);
        assert_eq!(runtime.live.orderly.clock_safe, 0);
    }

    #[test]
    fn zero_lockout_recovery_enables_lockout_auth_on_startup() {
        let mut runtime = RestoredFixture::default().runtime();
        assert!(
            !runtime
                .state
                .as_ref()
                .unwrap()
                .persistent
                .lockout_auth_enabled
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_STATE)),
            SUCCESS_RESPONSE
        );
        assert!(
            runtime
                .state
                .as_ref()
                .unwrap()
                .persistent
                .lockout_auth_enabled
        );
    }

    #[test]
    fn startup_publishes_the_live_state_after_a_fresh_manufacture() {
        let mut runtime = manufactured_runtime();
        assert!(!runtime.live.ph_enable, "pre-startup power-on default");
        assert!(
            runtime.live.power_was_lost,
            "power-on implies power was lost"
        );

        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
            SUCCESS_RESPONSE
        );

        let live = &runtime.live;
        assert!(live.ph_enable, "HierarchyStartup sets g_phEnable");
        assert!(!live.power_was_lost);
        assert!(!live.da_used);
        assert!(!live.pcr_reconfig);
        assert!(!live.startup_locality3);
        assert_eq!(live.prev_orderly_state, TPM_SU_CLEAR);
        assert!(live.sessions.iter().all(|slot| !slot.occupied));
        assert_eq!(live.free_session_slots, MAX_LOADED_SESSIONS as u32);
        assert_eq!(live.oldest_saved_session, MAX_ACTIVE_SESSIONS as u32 + 1);
        assert!(live.objects.iter().all(|object| matches!(
            object.body,
            crate::library::tpm2::persistent::OwnedAnyObjectBody::Unoccupied
        )));
        assert_eq!(live.context_slot_mask, 0xffff);
        assert_eq!(live.null_seed_compat_level, SEED_COMPAT_LEVEL_LAST);
        assert_eq!(live.pcrs.len(), IMPLEMENTATION_PCR);
        assert!(live.index_orderly_ram.entries.is_empty());
        assert_eq!(live.max_nv_counter, 0);
    }

    fn pre_startup_volatile_runtime() -> Box<Tpm2Runtime> {
        pre_startup_volatile_runtime_with(
            RestoredFixture::default(),
            OrderlyFixture::default().bytes(),
        )
    }

    fn pre_startup_volatile_runtime_with(
        fixture: RestoredFixture,
        orderly: Vec<u8>,
    ) -> Box<Tpm2Runtime> {
        pre_startup_volatile_runtime_sections(
            fixture,
            orderly,
            StateResetFixture::default().bytes(),
            StateClearFixture::default().bytes(),
        )
    }

    fn pre_startup_volatile_runtime_sections(
        fixture: RestoredFixture,
        orderly: Vec<u8>,
        state_reset: Vec<u8>,
        state_clear: Vec<u8>,
    ) -> Box<Tpm2Runtime> {
        use crate::library::tpm2::clock::RecordingClock;
        use crate::library::tpm2::public::StateFormatLimit;
        use crate::library::tpm2::volatile::{SeedTie, VolatileFixture, parse_volatile_state_blob};

        let mut runtime = fixture.runtime();
        let blob = VolatileFixture {
            initialized: 0,
            ep_seed: Vec::new(),
            sp_seed: Vec::new(),
            pp_seed: Vec::new(),
            orderly,
            state_reset,
            state_clear,
            ..VolatileFixture::default()
        }
        .bytes();
        let clock = RecordingClock::new(1_600_000_500_000, 7_000_000);
        let decoded = parse_volatile_state_blob(
            &blob,
            &[],
            SeedTie::EMPTY,
            &clock,
            StateFormatLimit::CURRENT,
        )
        .expect("the pre-startup volatile blob decodes");
        let owned = crate::library::tpm2::volatile::materialize_volatile_state(
            &decoded,
            SeedTie::EMPTY,
            crate::library::tpm2::volatile::CURRENT_OBJECT_VERSION,
        )
        .expect("materializes");
        crate::library::tpm2::runtime::merge_volatile_state(&mut runtime, owned);
        crate::library::tpm2::runtime::nv_shadow_restore(&mut runtime);
        runtime.entropy = deterministic_entropy;
        runtime
    }

    #[test]
    fn startup_applies_identical_cleanup_after_a_pre_startup_volatile_restore() {
        let mut with_volatile = pre_startup_volatile_runtime();
        assert!(
            !with_volatile.startup_received,
            "the snapshot predates Startup"
        );
        assert!(
            with_volatile.live.sessions[0].occupied,
            "the restored blob carries a loaded session"
        );
        let carry_time = with_volatile
            .restored_volatile
            .as_ref()
            .expect("carry present")
            .time;

        let mut without_volatile = RestoredFixture::default().runtime();

        for runtime in [&mut with_volatile, &mut without_volatile] {
            assert_eq!(
                dispatch_bytes(runtime, &startup_command(TPM_SU_STATE)),
                SUCCESS_RESPONSE
            );
        }

        for runtime in [&with_volatile, &without_volatile] {
            let live = &runtime.live;
            assert!(live.sessions.iter().all(|slot| !slot.occupied));
            assert!(live.sessions.iter().all(|slot| slot.session.is_none()));
            assert_eq!(live.free_session_slots, MAX_LOADED_SESSIONS as u32);
            assert!(live.objects.iter().all(|object| matches!(
                object.body,
                crate::library::tpm2::persistent::OwnedAnyObjectBody::Unoccupied
            )));
            assert!(live.ph_enable && !live.power_was_lost && !live.da_used);
            assert_eq!(live.prev_orderly_state, TPM_SU_STATE);
            assert_eq!(live.oldest_saved_session, MAX_ACTIVE_SESSIONS as u32 + 1);
        }

        let carry = with_volatile.restored_volatile.as_ref().unwrap();
        assert_eq!(carry.time, carry_time);
        assert!(
            carry.index_orderly_ram_bytes.len() == 512,
            "the raw RAM snapshot survives as restore-time data"
        );
    }

    fn volatile_orderly_bytes(seed: [u8; 48], clock_safe: u8) -> Vec<u8> {
        use crate::library::tpm2::persistent::{DrbgFixture, OrderlyFixture};
        OrderlyFixture {
            clock_safe,
            drbg: DrbgFixture {
                seed: seed.to_vec(),
                ..DrbgFixture::default()
            }
            .bytes(),
            ..OrderlyFixture::default()
        }
        .bytes()
    }

    fn expected_reseeded_seed(seed: [u8; 48]) -> Vec<u8> {
        let mut drbg = Drbg::restore(&seed, 0, [0; 4], false).unwrap();
        drbg.reseed_from_entropy(deterministic_entropy).unwrap();
        drbg.seed().to_vec()
    }

    const VOLATILE_DRBG_SEED: [u8; 48] = [0x77; 48];

    #[test]
    fn startup_reseeds_the_volatile_restored_drbg_state() {
        let mut runtime = pre_startup_volatile_runtime_with(
            RestoredFixture::default(),
            volatile_orderly_bytes(VOLATILE_DRBG_SEED, 1),
        );
        assert_eq!(
            runtime.live.orderly.drbg_state.seed.expose(),
            &VOLATILE_DRBG_SEED[..],
            "the volatile blob's go.drbgState is authoritative"
        );
        assert_eq!(
            runtime
                .state
                .as_ref()
                .unwrap()
                .orderly
                .drbg_state
                .seed
                .expose(),
            &[0x5a; 48][..],
            "the permanent NV copy still holds the fixture seed"
        );

        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_STATE)),
            SUCCESS_RESPONSE
        );

        let expected = expected_reseeded_seed(VOLATILE_DRBG_SEED);
        let state = runtime.state.as_ref().unwrap();
        assert_eq!(
            runtime.live.orderly.drbg_state.seed.expose(),
            &expected[..],
            "Startup reseeded the volatile DRBG state"
        );
        assert_eq!(
            state.orderly.drbg_state.seed.expose(),
            &[0x5a; 48][..],
            "the NV-backed copy keeps the last persisted go"
        );
        assert_eq!(runtime.live.orderly.drbg_state.reseed_counter, 1);
        assert_ne!(expected, expected_reseeded_seed([0x5a; 48]));
    }

    #[test]
    fn permanent_drbg_changes_do_not_affect_startup_after_volatile_restore() {
        let mut runtime = pre_startup_volatile_runtime_with(
            RestoredFixture::default(),
            volatile_orderly_bytes(VOLATILE_DRBG_SEED, 1),
        );
        runtime.state.as_mut().unwrap().orderly.drbg_state.seed =
            OwnedSecret::from_vec(vec![0x11; 48]);

        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_STATE)),
            SUCCESS_RESPONSE
        );
        assert_eq!(
            runtime.live.orderly.drbg_state.seed.expose(),
            &expected_reseeded_seed(VOLATILE_DRBG_SEED)[..]
        );
    }

    #[test]
    fn restored_clock_safe_is_authoritative_for_startup() {
        let mut runtime = pre_startup_volatile_runtime_with(
            RestoredFixture::default(),
            volatile_orderly_bytes(VOLATILE_DRBG_SEED, 0),
        );
        assert_eq!(runtime.state.as_ref().unwrap().orderly.clock_safe, 1);
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_STATE)),
            SUCCESS_RESPONSE
        );
        assert_eq!(runtime.live.orderly.clock_safe, 0);
        assert_eq!(
            runtime.state.as_ref().unwrap().orderly.clock_safe,
            1,
            "the NV copy keeps the last persisted value"
        );

        let mut runtime = pre_startup_volatile_runtime_with(
            RestoredFixture {
                orderly_state: 0xffff,
                ..RestoredFixture::default()
            },
            volatile_orderly_bytes(VOLATILE_DRBG_SEED, 1),
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
            SUCCESS_RESPONSE
        );
        assert_eq!(runtime.live.orderly.clock_safe, 0);
        assert_eq!(runtime.state.as_ref().unwrap().orderly.clock_safe, 1);
    }

    #[test]
    fn entropy_failure_leaves_live_and_nv_orderly_state_unchanged() {
        let mut runtime = pre_startup_volatile_runtime_with(
            RestoredFixture::default(),
            volatile_orderly_bytes(VOLATILE_DRBG_SEED, 1),
        );
        runtime.entropy = failing_entropy;
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_STATE)),
            FAILURE_RESPONSE
        );
        assert_unchanged(&runtime, &before);
        assert_eq!(
            runtime.live.orderly.drbg_state.seed.expose(),
            &VOLATILE_DRBG_SEED[..]
        );
        assert_eq!(
            runtime
                .state
                .as_ref()
                .unwrap()
                .orderly
                .drbg_state
                .seed
                .expose(),
            &[0x5a; 48][..]
        );
    }

    const NV_UNINITIALIZED_RESPONSE: [u8; 10] =
        [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x4a];

    #[test]
    fn resume_with_bad_nv_ok_returns_nv_uninitialized_transactionally() {
        let mut runtime = RestoredFixture::default().runtime();
        runtime.live.nv_ok = false;
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_STATE)),
            NV_UNINITIALIZED_RESPONSE
        );
        assert_unchanged(&runtime, &before);
        assert!(!runtime.startup_received);
        assert!(!runtime.nv_update_pending, "no host commit is scheduled");

        runtime.live.nv_ok = true;
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_STATE)),
            SUCCESS_RESPONSE
        );
    }

    #[test]
    fn nv_ok_validation_order_matches_upstream() {
        let mut runtime = RestoredFixture::default().runtime();
        runtime.live.nv_ok = false;
        runtime.nv_available = false;
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_STATE)),
            NV_UNAVAILABLE_RESPONSE
        );

        let mut runtime = RestoredFixture::default().runtime();
        runtime.live.nv_ok = false;
        runtime.locality = 2;
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_STATE)),
            LOCALITY_RESPONSE
        );

        let mut runtime = manufactured_runtime();
        runtime.live.nv_ok = false;
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_STATE)),
            VALUE_PARAM1_RESPONSE
        );

        let mut runtime = RestoredFixture {
            orderly_state: 0x4001,
            ..RestoredFixture::default()
        }
        .runtime();
        runtime.live.nv_ok = false;
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_STATE)),
            NV_UNINITIALIZED_RESPONSE
        );
    }

    #[test]
    fn clear_startup_with_bad_nv_ok_falls_back_to_reset() {
        let mut runtime = RestoredFixture {
            state_reset: StateResetFixture {
                clear_count: 5,
                restart_count: 11,
                ..StateResetFixture::default()
            },
            ..RestoredFixture::default()
        }
        .runtime();
        runtime.live.nv_ok = false;
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
            SUCCESS_RESPONSE
        );
        let state = runtime.state.as_ref().unwrap();
        assert_eq!(state.persistent.reset_count, 1, "SU_RESET, not SU_RESTART");
        let reset = runtime.live.state_reset.as_ref().unwrap();
        assert_eq!(
            reset.clear_count, 0,
            "a fresh live gr replaces the saved one"
        );
        assert_eq!(reset.restart_count, 0);
        assert_eq!(
            state.state_reset.as_ref().unwrap().clear_count,
            5,
            "the NV-saved gr stays as last persisted"
        );
    }

    mod live_nv_separation {
        use super::*;
        use crate::library::tpm2::parse_persistent_all_payload;
        use crate::library::tpm2::persistent::{
            PersistentAllEnvelope, materialize_persistent_state, persistent_all_store,
        };

        #[test]
        fn startup_updates_live_go_gr_gc_but_never_their_nv_copies() {
            let fixture = RestoredFixture {
                state_reset: StateResetFixture {
                    clear_count: 5,
                    restart_count: 11,
                    null_proof: vec![0x0f; 8],
                    ..StateResetFixture::default()
                },
                state_clear: StateClearFixture {
                    sh_enable: 0,
                    platform_alg: 0x000b,
                    ..StateClearFixture::default()
                },
                ..RestoredFixture::default()
            };
            let mut runtime = pre_startup_volatile_runtime_sections(
                fixture,
                volatile_orderly_bytes(VOLATILE_DRBG_SEED, 1),
                StateResetFixture {
                    clear_count: 40,
                    restart_count: 50,
                    null_proof: vec![0x0d; 8],
                    ..StateResetFixture::default()
                }
                .bytes(),
                StateClearFixture {
                    platform_alg: 0x000c,
                    ..StateClearFixture::default()
                }
                .bytes(),
            );
            assert_eq!(
                runtime.live.state_reset.as_ref().unwrap().clear_count,
                40,
                "VolatileLoad() restored the blob's gr"
            );

            let response = dispatch_bytes(&mut runtime, &startup_command(TPM_SU_STATE));
            assert_eq!(response, SUCCESS_RESPONSE);
            assert!(runtime.nv_update_pending, "Startup schedules one NV commit");
            runtime.nv_update_pending = false;
            let stored = vec![persistent_all_store(runtime.state.as_ref().unwrap()).unwrap()];

            assert_eq!(
                runtime.live.orderly.drbg_state.seed.expose(),
                &expected_reseeded_seed(VOLATILE_DRBG_SEED)[..]
            );
            let live_reset = runtime.live.state_reset.as_ref().unwrap();
            assert_eq!(live_reset.clear_count, 5, "NvRead gr, volatile gr dropped");
            assert_eq!(live_reset.restart_count, 12, "restartCount++ on Resume");
            assert_eq!(live_reset.null_proof.expose(), &[0x0f; 8][..]);
            let live_clear = runtime.live.state_clear.as_ref().unwrap();
            assert_eq!(live_clear.platform_alg, 0x000b, "NvRead gc");
            assert!(!live_clear.sh_enable);

            let state = runtime.state.as_ref().unwrap();
            assert_eq!(state.state_reset.as_ref().unwrap().clear_count, 5);
            assert_eq!(state.state_reset.as_ref().unwrap().restart_count, 11);
            assert_eq!(state.state_clear.as_ref().unwrap().platform_alg, 0x000b);
            assert_eq!(state.orderly.drbg_state.seed.expose(), &[0x5a; 48][..]);
            assert_eq!(state.orderly.drbg_state.reseed_counter, 0);

            assert_eq!(stored.len(), 1);
            assert_eq!(stored[0], persistent_all_store(state).unwrap());
            let envelope = PersistentAllEnvelope::parse(&stored[0]).unwrap();
            let decoded = parse_persistent_all_payload(&envelope).unwrap();
            let reparsed = materialize_persistent_state(decoded).unwrap();
            assert_eq!(reparsed.persistent.orderly_state, 0xffff);
            assert_eq!(reparsed.persistent.reset_count, 0, "a Resume is no Reset");
            assert!(
                reparsed.state_reset.is_none() && reparsed.state_clear.is_none(),
                "a non-orderly blob stores no SU sections"
            );
            assert_eq!(
                reparsed.orderly.drbg_state.seed.expose(),
                &[0x5a; 48][..],
                "the stored ORDERLY_DATA is the previously persisted one"
            );
        }
    }

    const ORDINARY_LOCKED: u32 = TPMA_NV_READLOCKED | TPMA_NV_WRITELOCKED | TPMA_NV_WRITTEN;
    const STCLEAR_DEFINED: u32 = TPMA_NV_CLEAR_STCLEAR
        | TPMA_NV_WRITTEN
        | (1 << 31) // TPMA_NV_READ_STCLEAR
        | (1 << 14); // TPMA_NV_WRITE_STCLEAR
    const WRITEDEFINE_LOCKED: u32 =
        TPMA_NV_WRITEDEFINE | TPMA_NV_WRITTEN | TPMA_NV_WRITELOCKED | TPMA_NV_READLOCKED;
    const COUNTER_STCLEAR: u32 =
        (TPM_NT_COUNTER << TPMA_NV_TPM_NT_SHIFT) | TPMA_NV_CLEAR_STCLEAR | TPMA_NV_WRITTEN;
    const ORDERLY_NV_INDEX: u32 = TPMA_NV_ORDERLY | TPMA_NV_WRITTEN | TPMA_NV_READLOCKED;
    const ORDERLY_RAM_WRITTEN: u32 = TPMA_NV_ORDERLY | TPMA_NV_WRITTEN;
    const ORDERLY_RAM_COUNTER: u32 =
        TPMA_NV_ORDERLY | TPMA_NV_WRITTEN | (TPM_NT_COUNTER << TPMA_NV_TPM_NT_SHIFT);

    fn nv_entity_fixture(orderly_state: u16) -> RestoredFixture {
        let index_bytes = |attributes: u32| {
            crate::library::tpm2::nv::NvIndexFixture {
                attributes,
                ..crate::library::tpm2::nv::NvIndexFixture::default()
            }
            .bytes()
        };
        let bulk = vec![0x5au8; 8];
        RestoredFixture {
            orderly_state,
            user_nvram: UserNvramFixture {
                entries: vec![
                    UserNvramFixture::nv_index_entry(
                        0x0100_0001,
                        &index_bytes(ORDINARY_LOCKED),
                        &bulk,
                    ),
                    UserNvramFixture::nv_index_entry(
                        0x0100_0002,
                        &index_bytes(STCLEAR_DEFINED),
                        &bulk,
                    ),
                    UserNvramFixture::nv_index_entry(
                        0x0100_0003,
                        &index_bytes(WRITEDEFINE_LOCKED),
                        &bulk,
                    ),
                    UserNvramFixture::nv_index_entry(
                        0x0100_0004,
                        &index_bytes(COUNTER_STCLEAR),
                        &bulk,
                    ),
                    UserNvramFixture::nv_index_entry(
                        0x0100_0005,
                        &index_bytes(ORDERLY_NV_INDEX),
                        &bulk,
                    ),
                ],
                max_count: Some(7),
                ..UserNvramFixture::default()
            },
            index_orderly_ram: IndexOrderlyRamFixture {
                entries: vec![
                    IndexOrderlyRamFixture::entry(0x0100_0005, ORDERLY_RAM_WRITTEN, &[0xaa; 8]),
                    IndexOrderlyRamFixture::entry(
                        0x0100_0006,
                        ORDERLY_RAM_COUNTER,
                        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00],
                    ),
                ],
                ..IndexOrderlyRamFixture::default()
            },
            ..RestoredFixture::default()
        }
    }

    #[track_caller]
    fn nv_attrs(runtime: &Tpm2Runtime) -> Vec<u32> {
        nv_index_attributes(runtime.state.as_ref().unwrap())
    }

    #[test]
    fn reset_applies_the_nv_startup_attribute_rules() {
        let mut runtime = nv_entity_fixture(0xffff).runtime();
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
            SUCCESS_RESPONSE
        );

        assert_eq!(
            nv_attrs(&runtime),
            vec![
                TPMA_NV_WRITTEN,
                STCLEAR_DEFINED & !TPMA_NV_WRITTEN,
                WRITEDEFINE_LOCKED & !TPMA_NV_READLOCKED,
                COUNTER_STCLEAR,
                ORDERLY_NV_INDEX,
            ]
        );

        let live_ram = &runtime.live.index_orderly_ram;
        assert_eq!(live_ram.entries[0].attributes, TPMA_NV_ORDERLY);
        assert_eq!(live_ram.entries[0].data, vec![0xaa; 8], "data preserved");
        assert_eq!(live_ram.entries[1].attributes, ORDERLY_RAM_COUNTER);
        assert_eq!(
            live_ram.entries[1].data,
            0x0000_0000_0034_00ffu64.to_be_bytes().to_vec(),
            "counter low bits forced to ones after a non-orderly startup"
        );

        let state = runtime.state.as_ref().unwrap();
        assert_eq!(
            state.index_orderly_ram.entries[1].data,
            vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00]
        );
        assert_eq!(
            state.index_orderly_ram.entries[0].attributes,
            ORDERLY_RAM_WRITTEN
        );
        assert_eq!(runtime.live.max_nv_counter, 7, "NvSetMaxCount from NV");
        assert_eq!(runtime.nv_memory, build_nv_image(state).unwrap());
    }

    #[test]
    fn restart_keeps_orderly_written_and_skips_the_counter_fixup() {
        let mut runtime = nv_entity_fixture(TPM_SU_STATE).runtime();
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
            SUCCESS_RESPONSE
        );

        let live_ram = &runtime.live.index_orderly_ram;
        assert_eq!(live_ram.entries[0].attributes, ORDERLY_RAM_WRITTEN);
        assert_eq!(
            live_ram.entries[1].data,
            vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00]
        );
        assert_eq!(nv_attrs(&runtime)[1], STCLEAR_DEFINED & !TPMA_NV_WRITTEN);
    }

    #[test]
    fn resume_restores_the_ram_view_without_attribute_clearing() {
        let mut runtime = nv_entity_fixture(TPM_SU_STATE).runtime();
        let attrs_before = nv_attrs(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_STATE)),
            SUCCESS_RESPONSE
        );

        assert_eq!(nv_attrs(&runtime), attrs_before, "NV attributes untouched");
        let live_ram = &runtime.live.index_orderly_ram;
        assert_eq!(live_ram.entries.len(), 2, "RAM view restored from NV");
        assert_eq!(live_ram.entries[0].attributes, ORDERLY_RAM_WRITTEN);
        assert_eq!(live_ram.entries[1].attributes, ORDERLY_RAM_COUNTER);
        assert_eq!(
            live_ram.entries[1].data,
            vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00],
            "no counter adjustment on Resume"
        );
        assert_eq!(runtime.live.max_nv_counter, 7);
    }

    #[test]
    fn late_serialization_failure_rolls_back_the_nv_startup_effects() {
        let object_bytes = crate::library::tpm2::object::fixtures::any_rsa_object(3);
        let mut fixture = nv_entity_fixture(0xffff);
        fixture
            .user_nvram
            .entries
            .push(UserNvramFixture::persistent_entry(
                0x8100_0001,
                &object_bytes,
            ));
        let mut runtime = fixture.runtime();

        {
            let state = runtime.state.as_mut().unwrap();
            for entry in &mut state.user_nvram.entries {
                if let OwnedUserNvramEntry::Persistent {
                    object_destination_size,
                    ..
                } = entry
                {
                    *object_destination_size += 1;
                }
            }
        }

        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
            FAILURE_RESPONSE
        );
        assert_unchanged(&runtime, &before);
        assert!(!runtime.startup_received);
        assert!(!runtime.live.ph_enable, "live state was not published");
        assert!(!runtime.nv_update_pending);

        {
            let state = runtime.state.as_mut().unwrap();
            for entry in &mut state.user_nvram.entries {
                if let OwnedUserNvramEntry::Persistent {
                    object_destination_size,
                    ..
                } = entry
                {
                    *object_destination_size -= 1;
                }
            }
        }
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
            SUCCESS_RESPONSE
        );
    }

    fn unreachable_entropy(_buffer: &mut [u8]) -> Result<(), TpmResult> {
        panic!("the entropy-bad latch must short-circuit the platform callback");
    }

    #[test]
    fn a_startup_entropy_failure_latches_g_entropy_bad_and_never_retries() {
        let mut runtime = manufactured_runtime();
        runtime.entropy = failing_entropy;
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
            FAILURE_RESPONSE
        );
        assert_unchanged(&runtime, &before);
        assert!(runtime.entropy_bad, "the failed fetch latches g_entropyBad");
        assert!(!runtime.failure_mode, "no FAIL() site is reached");
        assert_eq!(runtime.failure_diagnostics, Default::default());
        assert!(!runtime.startup_received);

        runtime.entropy = unreachable_entropy;
        for _ in 0..2 {
            assert_eq!(
                dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
                FAILURE_RESPONSE
            );
            assert_unchanged(&runtime, &before);
            assert!(runtime.entropy_bad);
            assert!(!runtime.failure_mode);
        }
    }

    #[test]
    fn an_instantiating_startup_entropy_failure_latches_the_same_way() {
        let mut runtime = manufactured_runtime();
        runtime.live.orderly.drbg_state.drbg_magic = 0;
        runtime.entropy = failing_entropy;
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
            FAILURE_RESPONSE
        );
        assert!(runtime.entropy_bad);
        assert!(!runtime.failure_mode);
        assert_eq!(
            runtime.live.orderly.drbg_state.drbg_magic, 0,
            "no partially instantiated state is stored"
        );

        runtime.entropy = unreachable_entropy;
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
            FAILURE_RESPONSE
        );
        assert!(!runtime.failure_mode);
    }

    #[test]
    fn a_new_tpm_init_lifecycle_starts_with_the_latch_clear() {
        use crate::library::tpm2::persistent::persistent_all_store;

        let mut runtime = manufactured_runtime();
        runtime.entropy = failing_entropy;
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
            FAILURE_RESPONSE
        );
        assert!(runtime.entropy_bad);

        let blob =
            persistent_all_store(runtime.state.as_ref().unwrap()).expect("the state serializes");
        let envelope = PersistentAllEnvelope::parse(&blob).expect("the envelope parses");
        let decoded = parse_persistent_all_payload(&envelope).expect("the payload parses");
        let restored = materialize_persistent_state(decoded).expect("materializes");
        let mut runtime = commit_restored_state(restored).expect("commits");
        assert!(!runtime.entropy_bad, "the latch is not part of any state");
        runtime.entropy = deterministic_entropy;
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
            SUCCESS_RESPONSE
        );
    }

    const CONTINUOUS_TEST_PROFILE: &[u8] =
        br#"{"Name":"custom","Attributes":"drbg-continous-test"}"#;

    fn continuous_test_runtime() -> Box<Tpm2Runtime> {
        let profile =
            validate_user_profile(Some(CONTINUOUS_TEST_PROFILE)).expect("the profile validates");
        let state = manufacture_state(profile, deterministic_entropy).expect("manufactures");
        let mut runtime = commit_manufactured_state(state).expect("commits");
        runtime.entropy = deterministic_entropy;
        runtime
    }

    fn colliding_last_value(seed: &[u8]) -> [u32; 4] {
        let mut probe = Drbg::restore(seed, 1, [0; 4], false).expect("the probe restores");
        let mut block = [0u8; 16];
        probe.generate(&mut block).expect("the probe generates");
        core::array::from_fn(|word| {
            u32::from_le_bytes(block[word * 4..word * 4 + 4].try_into().unwrap())
        })
    }

    #[test]
    fn a_continuous_test_failure_during_the_startup_reseed_is_the_encrypt_drbg_fatal() {
        use crate::library::tpm2::failure_mode::FailureLocation;

        let mut runtime = continuous_test_runtime();
        let seed = runtime.live.orderly.drbg_state.seed.expose().to_vec();
        runtime.live.orderly.drbg_state.last_value = colliding_last_value(&seed);

        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
            FAILURE_RESPONSE
        );
        assert!(runtime.failure_mode, "the repeated block stops the TPM");
        assert_eq!(
            runtime.failure_diagnostics,
            FailureLocation::DrbgEntropy.diagnostics(),
            "the diagnostics name EncryptDRBG's FATAL_ERROR_ENTROPY site"
        );
        assert!(
            !runtime.entropy_bad,
            "a continuous-test hit is not an entropy-callback failure"
        );
        assert!(!runtime.startup_received);
        assert_eq!(
            runtime.live.orderly.drbg_state.seed.expose(),
            &seed[..],
            "the failed reseed is not stored"
        );
    }
}
