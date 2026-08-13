use crate::ffi_types::TpmResult;
use crate::library::constants::{
    TPM_RC_FAILURE, TPM_RC_INSUFFICIENT, TPM_RC_NV_UNAVAILABLE, TPM_RC_SIZE, TPM_RC_TYPE,
    TPM_RC_VALUE,
};

use super::super::live::LiveState;
use super::super::nv::build_nv_image;
use super::super::pcr::PCR_SLOT_BANKS;
use super::super::persistent::{OwnedPcrBank, OwnedStateClearData};
use super::super::runtime::Tpm2Runtime;
use super::super::state::NUM_STATIC_PCR;
use super::dispatcher::CommandFrame;
use super::startup::{PRE_STARTUP_FLAG, STARTUP_LOCALITY_3, TPM_SU_CLEAR, TPM_SU_STATE};

const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;
const RC_SHUTDOWN_SHUTDOWN_TYPE: TpmResult = TPM_RC_P + TPM_RC_1;

pub(super) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<Vec<u8>, TpmResult> {
    let shutdown_type = parse_shutdown_type(frame.parameters)?;
    perform_shutdown(runtime, shutdown_type)?;
    Ok(Vec::new())
}

fn parse_shutdown_type(parameters: &[u8]) -> Result<u16, TpmResult> {
    let Some((su_bytes, rest)) = parameters.split_first_chunk::<2>() else {
        return Err(TPM_RC_INSUFFICIENT + RC_SHUTDOWN_SHUTDOWN_TYPE);
    };
    let shutdown_type = u16::from_be_bytes(*su_bytes);
    if shutdown_type != TPM_SU_CLEAR && shutdown_type != TPM_SU_STATE {
        return Err(TPM_RC_VALUE + RC_SHUTDOWN_SHUTDOWN_TYPE);
    }
    if !rest.is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(shutdown_type)
}

fn pcr_state_save(live: &LiveState) -> Result<OwnedStateClearData, TpmResult> {
    let mut clear = live.state_clear.as_ref().ok_or(TPM_RC_FAILURE)?.clone();
    for (slot, &(hash_alg, digest_size)) in PCR_SLOT_BANKS.iter().enumerate() {
        for pcr in 0..NUM_STATIC_PCR {
            let Some(value) = live
                .pcrs
                .get(pcr)
                .and_then(|entry| entry.banks[slot].as_ref())
            else {
                continue;
            };
            if value.len() != digest_size {
                return Err(TPM_RC_FAILURE);
            }
            let bank = clear.pcr_save[slot].get_or_insert_with(|| OwnedPcrBank {
                hash_alg,
                pcrs: vec![0u8; NUM_STATIC_PCR * digest_size],
            });
            bank.pcrs
                .get_mut(pcr * digest_size..(pcr + 1) * digest_size)
                .ok_or(TPM_RC_FAILURE)?
                .copy_from_slice(value);
        }
    }
    Ok(clear)
}

fn perform_shutdown(runtime: &mut Tpm2Runtime, shutdown_type: u16) -> Result<(), TpmResult> {
    if !runtime.nv_available {
        return Err(TPM_RC_NV_UNAVAILABLE);
    }
    if runtime.live.pcr_reconfig && shutdown_type == TPM_SU_STATE {
        return Err(TPM_RC_TYPE + RC_SHUTDOWN_SHUTDOWN_TYPE);
    }

    let su_state = if shutdown_type == TPM_SU_STATE {
        let reset = runtime
            .live
            .state_reset
            .as_ref()
            .ok_or(TPM_RC_FAILURE)?
            .clone();
        let clear = pcr_state_save(&runtime.live)?;
        Some((reset, clear))
    } else {
        None
    };
    let orderly_state = if shutdown_type == TPM_SU_STATE {
        if runtime.live.drtm_pre_startup {
            TPM_SU_STATE | PRE_STARTUP_FLAG
        } else if runtime.live.startup_locality3 {
            TPM_SU_STATE | STARTUP_LOCALITY_3
        } else {
            TPM_SU_STATE
        }
    } else {
        TPM_SU_CLEAR
    };

    // TODO: Support runtimes without decoded state after the NVChip fallback
    // is implemented.
    let state = runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?;

    let backup_orderly_state = state.persistent.orderly_state;
    state.persistent.orderly_state = orderly_state;
    let backup_orderly = core::mem::replace(&mut state.orderly, runtime.live.orderly.clone());
    let backup_index_orderly_ram = core::mem::replace(
        &mut state.index_orderly_ram,
        runtime.live.index_orderly_ram.clone(),
    );
    let (new_reset, new_clear) = match &su_state {
        Some((reset, clear)) => (Some(reset.clone()), Some(clear.clone())),
        None => (None, None),
    };
    let backup_state_reset = core::mem::replace(&mut state.state_reset, new_reset);
    let backup_state_clear = core::mem::replace(&mut state.state_clear, new_clear);

    let nv_memory = match build_nv_image(state) {
        Ok(image) => image,
        Err(_) => {
            state.persistent.orderly_state = backup_orderly_state;
            state.orderly = backup_orderly;
            state.index_orderly_ram = backup_index_orderly_ram;
            state.state_reset = backup_state_reset;
            state.state_clear = backup_state_clear;
            return Err(TPM_RC_FAILURE);
        }
    };

    runtime.nv_memory = nv_memory;
    if let Some((_, clear)) = su_state {
        runtime.live.state_clear = Some(clear);
    }
    runtime.live.da_used = false;
    runtime.nv_update_pending = true;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::dispatcher::dispatch;
    use super::super::header::{parse_command, serialize_response};
    use super::super::registry::{TPM_CC_SHUTDOWN, TPM_CC_STARTUP};
    use super::super::session::{HMAC_SESSION_FIRST, POLICY_SESSION_FIRST, TPM_RS_PW};
    use super::*;
    use crate::library::CommandInput;
    use crate::library::tpm2::manufacture::manufacture_state;
    use crate::library::tpm2::parse_persistent_all_payload;
    use crate::library::tpm2::persistent::{
        OwnedIndexOrderlyRam, OwnedOrderlyRamEntry, OwnedPersistentState, PersistentAllEnvelope,
        materialize_persistent_state, persistent_all_store,
    };
    use crate::library::tpm2::profile::validate_user_profile;
    use crate::library::tpm2::runtime::{commit_manufactured_state, commit_restored_state};

    const SUCCESS: u32 = 0x000;
    const INITIALIZE: u32 = 0x100;
    const FAILURE: u32 = 0x101;
    const SIZE: u32 = 0x095;
    const INSUFFICIENT: u32 = 0x09a;
    const INSUFFICIENT_PARAM1: u32 = 0x1da;
    const VALUE_PARAM1: u32 = 0x1c4;
    const TYPE_PARAM1: u32 = 0x1ca;
    const NV_UNAVAILABLE: u32 = 0x923;
    const SESSION1_HANDLE: u32 = 0x98b;
    const SESSION1_NONCE: u32 = 0x98f;
    const SESSION1_ATTRIBUTES: u32 = 0x982;
    const SESSION1_VALUE: u32 = 0x984;
    const SESSION1_INSUFFICIENT: u32 = 0x99a;
    const SESSION2_INSUFFICIENT: u32 = 0xa9a;
    const REFERENCE_S0: u32 = 0x918;

    const SHA256_SLOT: usize = 1;
    const TPMA_NV_ORDERLY: u32 = 1 << 26;
    const TPMA_NV_WRITTEN: u32 = 1 << 29;

    fn response_bytes(code: u32) -> [u8; 10] {
        let mut out = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0, 0, 0, 0];
        out[6..].copy_from_slice(&code.to_be_bytes());
        out
    }

    fn deterministic_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
        let len = buffer.len() as u8;
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_add(len) ^ 0x53;
        }
        Ok(())
    }

    fn manufactured_runtime() -> Box<Tpm2Runtime> {
        let profile = validate_user_profile(None).expect("the null profile validates");
        let state = manufacture_state(profile, deterministic_entropy).expect("manufactures");
        let mut runtime = commit_manufactured_state(state).expect("commits");
        runtime.entropy = deterministic_entropy;
        runtime
    }

    fn command_with_params(code: u32, params: &[u8]) -> Vec<u8> {
        let mut out = vec![0x80, 0x01];
        out.extend_from_slice(&(10 + params.len() as u32).to_be_bytes());
        out.extend_from_slice(&code.to_be_bytes());
        out.extend_from_slice(params);
        out
    }

    fn startup_command(startup_type: u16) -> Vec<u8> {
        command_with_params(TPM_CC_STARTUP, &startup_type.to_be_bytes())
    }

    fn shutdown_command(shutdown_type: u16) -> Vec<u8> {
        command_with_params(TPM_CC_SHUTDOWN, &shutdown_type.to_be_bytes())
    }

    fn session_shutdown(auth_area: &[u8], declared_auth: Option<u32>, params: &[u8]) -> Vec<u8> {
        let mut out = vec![0x80, 0x02];
        let total = 10 + 4 + auth_area.len() + params.len();
        out.extend_from_slice(&(total as u32).to_be_bytes());
        out.extend_from_slice(&TPM_CC_SHUTDOWN.to_be_bytes());
        let auth_size = declared_auth.unwrap_or(auth_area.len() as u32);
        out.extend_from_slice(&auth_size.to_be_bytes());
        out.extend_from_slice(auth_area);
        out.extend_from_slice(params);
        out
    }

    fn session_bytes(handle: u32, nonce: &[u8], attributes: u8, hmac: &[u8]) -> Vec<u8> {
        let mut out = handle.to_be_bytes().to_vec();
        out.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
        out.extend_from_slice(nonce);
        out.push(attributes);
        out.extend_from_slice(&(hmac.len() as u16).to_be_bytes());
        out.extend_from_slice(hmac);
        out
    }

    #[track_caller]
    fn dispatch_bytes(runtime: &mut Tpm2Runtime, bytes: &[u8]) -> Vec<u8> {
        let input = CommandInput::new(bytes.len() as u32, bytes.to_vec());
        let parsed = parse_command(&input).expect("the header parses");
        serialize_response(&dispatch(runtime, &parsed)).expect("the response serializes")
    }

    #[track_caller]
    fn started_runtime() -> Box<Tpm2Runtime> {
        let mut runtime = manufactured_runtime();
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
            response_bytes(SUCCESS)
        );
        runtime.nv_update_pending = false;
        runtime
    }

    fn state(runtime: &Tpm2Runtime) -> &OwnedPersistentState {
        runtime.state.as_ref().expect("state present")
    }

    struct Snapshot {
        startup_received: bool,
        nv_update_pending: bool,
        orderly_state: u16,
        nv_orderly_seed: Vec<u8>,
        nv_orderly_counter: u64,
        nv_reset_summary: Option<(u32, u32)>,
        nv_clear_present: bool,
        nv_ram_entries: Vec<(u32, u32, Vec<u8>)>,
        nv_memory: Box<[u8]>,
        live_da_used: bool,
        live_reset_present: bool,
        live_clear_pcr_save: Vec<bool>,
    }

    fn snapshot(runtime: &Tpm2Runtime) -> Snapshot {
        let state = state(runtime);
        Snapshot {
            startup_received: runtime.startup_received,
            nv_update_pending: runtime.nv_update_pending,
            orderly_state: state.persistent.orderly_state,
            nv_orderly_seed: state.orderly.drbg_state.seed.expose().to_vec(),
            nv_orderly_counter: state.orderly.drbg_state.reseed_counter,
            nv_reset_summary: state
                .state_reset
                .as_ref()
                .map(|reset| (reset.clear_count, reset.restart_count)),
            nv_clear_present: state.state_clear.is_some(),
            nv_ram_entries: state
                .index_orderly_ram
                .entries
                .iter()
                .map(|entry| (entry.handle, entry.attributes, entry.data.clone()))
                .collect(),
            nv_memory: runtime.nv_memory.clone(),
            live_da_used: runtime.live.da_used,
            live_reset_present: runtime.live.state_reset.is_some(),
            live_clear_pcr_save: runtime
                .live
                .state_clear
                .as_ref()
                .map(|clear| clear.pcr_save.iter().map(Option::is_some).collect())
                .unwrap_or_default(),
        }
    }

    #[track_caller]
    fn assert_unchanged(runtime: &Tpm2Runtime, before: &Snapshot) {
        let state = state(runtime);
        assert_eq!(runtime.startup_received, before.startup_received);
        assert_eq!(runtime.nv_update_pending, before.nv_update_pending);
        assert_eq!(state.persistent.orderly_state, before.orderly_state);
        assert_eq!(
            state.orderly.drbg_state.seed.expose(),
            &before.nv_orderly_seed[..]
        );
        assert_eq!(
            state.orderly.drbg_state.reseed_counter,
            before.nv_orderly_counter
        );
        assert_eq!(
            state
                .state_reset
                .as_ref()
                .map(|reset| (reset.clear_count, reset.restart_count)),
            before.nv_reset_summary
        );
        assert_eq!(state.state_clear.is_some(), before.nv_clear_present);
        assert_eq!(
            state
                .index_orderly_ram
                .entries
                .iter()
                .map(|entry| (entry.handle, entry.attributes, entry.data.clone()))
                .collect::<Vec<_>>(),
            before.nv_ram_entries
        );
        assert_eq!(runtime.nv_memory, before.nv_memory);
        assert_eq!(runtime.live.da_used, before.live_da_used);
        assert_eq!(
            runtime.live.state_reset.is_some(),
            before.live_reset_present
        );
        assert_eq!(
            runtime
                .live
                .state_clear
                .as_ref()
                .map(|clear| clear
                    .pcr_save
                    .iter()
                    .map(Option::is_some)
                    .collect::<Vec<_>>())
                .unwrap_or_default(),
            before.live_clear_pcr_save
        );
    }

    #[track_caller]
    fn reload(state: &OwnedPersistentState) -> OwnedPersistentState {
        let blob = persistent_all_store(state).expect("the state serializes");
        let envelope = PersistentAllEnvelope::parse(&blob).expect("envelope parses");
        let decoded = parse_persistent_all_payload(&envelope).expect("payload parses");
        materialize_persistent_state(decoded).expect("materializes")
    }

    #[track_caller]
    fn rebooted_runtime(runtime: &Tpm2Runtime) -> Box<Tpm2Runtime> {
        let restored = reload(state(runtime));
        let mut rebooted = commit_restored_state(restored).expect("the persisted state restores");
        rebooted.entropy = deterministic_entropy;
        rebooted
    }

    #[test]
    fn shutdown_before_startup_returns_initialize_without_mutation() {
        let mut runtime = manufactured_runtime();
        let before = snapshot(&runtime);
        for shutdown_type in [TPM_SU_CLEAR, TPM_SU_STATE] {
            assert_eq!(
                dispatch_bytes(&mut runtime, &shutdown_command(shutdown_type)),
                response_bytes(INITIALIZE)
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn malformed_shutdown_before_startup_still_returns_initialize() {
        let mut runtime = manufactured_runtime();
        let before = snapshot(&runtime);
        let truncated = command_with_params(TPM_CC_SHUTDOWN, &[]);
        assert_eq!(
            dispatch_bytes(&mut runtime, &truncated),
            response_bytes(INITIALIZE)
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(0x0002)),
            response_bytes(INITIALIZE)
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn repeated_shutdown_is_dispatched_normally() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(TPM_SU_CLEAR)),
            response_bytes(SUCCESS)
        );
        assert!(runtime.startup_received, "Shutdown keeps g_initialized set");
        assert_eq!(state(&runtime).persistent.orderly_state, TPM_SU_CLEAR);

        runtime.nv_update_pending = false;
        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(TPM_SU_STATE)),
            response_bytes(SUCCESS)
        );
        assert!(runtime.startup_received);
        assert!(runtime.nv_update_pending);
        let state_after_second = state(&runtime);
        assert_eq!(state_after_second.persistent.orderly_state, TPM_SU_STATE);
        assert!(
            state_after_second.state_reset.is_some() && state_after_second.state_clear.is_some()
        );

        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(TPM_SU_CLEAR)),
            response_bytes(SUCCESS)
        );
        let state_after_third = state(&runtime);
        assert_eq!(state_after_third.persistent.orderly_state, TPM_SU_CLEAR);
        assert!(state_after_third.state_reset.is_none() && state_after_third.state_clear.is_none());
    }

    #[test]
    fn startup_after_shutdown_without_a_reset_returns_initialize() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(TPM_SU_STATE)),
            response_bytes(SUCCESS)
        );
        let after_shutdown = snapshot(&runtime);
        for startup_type in [TPM_SU_CLEAR, TPM_SU_STATE] {
            assert_eq!(
                dispatch_bytes(&mut runtime, &startup_command(startup_type)),
                response_bytes(INITIALIZE)
            );
            assert_unchanged(&runtime, &after_shutdown);
        }
    }

    #[test]
    fn shutdown_type_decodes_big_endian() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(0x0100)),
            response_bytes(VALUE_PARAM1)
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(TPM_SU_STATE)),
            response_bytes(SUCCESS)
        );

        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(TPM_SU_CLEAR)),
            response_bytes(SUCCESS)
        );
    }

    #[test]
    fn malformed_parameters_match_the_oracle() {
        for (label, params, expected) in [
            ("missing", &[][..], INSUFFICIENT_PARAM1),
            ("one_byte", &[0x00][..], INSUFFICIENT_PARAM1),
            ("trailing", &[0x00, 0x00, 0x00][..], SIZE),
            ("invalid", &[0x00, 0x02][..], VALUE_PARAM1),
            ("invalid_max", &[0xff, 0xff][..], VALUE_PARAM1),
        ] {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            let command = command_with_params(TPM_CC_SHUTDOWN, params);
            assert_eq!(
                dispatch_bytes(&mut runtime, &command),
                response_bytes(expected),
                "{label}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn every_strict_parameter_prefix_fails_safely() {
        let full = shutdown_command(TPM_SU_STATE);
        for len in 10..full.len() {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            let mut prefix = full[..len].to_vec();
            prefix[2..6].copy_from_slice(&(len as u32).to_be_bytes());
            assert_eq!(
                dispatch_bytes(&mut runtime, &prefix),
                response_bytes(INSUFFICIENT_PARAM1),
                "prefix length {len}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn session_tagged_requests_match_the_oracle() {
        let pw = session_bytes(TPM_RS_PW, &[], 0x00, &[]);
        let mut no_authsize = vec![0x80, 0x02, 0x00, 0x00, 0x00, 0x0a];
        no_authsize.extend_from_slice(&TPM_CC_SHUTDOWN.to_be_bytes());
        let mut pw_trunc_hmac = pw.clone();
        pw_trunc_hmac[8] = 0x04;
        let mut two_pw = pw.clone();
        two_pw.extend_from_slice(&pw);
        let mut pw_leftover = pw.clone();
        pw_leftover.push(0xcc);

        for (label, command, expected) in [
            ("no_authsize", no_authsize.clone(), INSUFFICIENT),
            (
                "authsize_zero",
                session_shutdown(&[], Some(0), &[0, 0]),
                SIZE,
            ),
            (
                "authsize_too_big",
                session_shutdown(&[0, 0, 0, 0], Some(0x20), &[]),
                SIZE,
            ),
            (
                "pw_auth",
                session_shutdown(&pw, None, &[0, 0]),
                SESSION1_HANDLE,
            ),
            (
                "pw_nonce",
                session_shutdown(
                    &session_bytes(TPM_RS_PW, &[0xaa, 0xbb], 0x00, &[]),
                    None,
                    &[0, 0],
                ),
                SESSION1_NONCE,
            ),
            (
                "pw_audit_attribute",
                session_shutdown(&session_bytes(TPM_RS_PW, &[], 0x80, &[]), None, &[0, 0]),
                SESSION1_ATTRIBUTES,
            ),
            (
                "unloaded_policy_session",
                session_shutdown(
                    &session_bytes(POLICY_SESSION_FIRST, &[], 0x00, &[]),
                    None,
                    &[0, 0],
                ),
                REFERENCE_S0,
            ),
            (
                "unloaded_hmac_session",
                session_shutdown(
                    &session_bytes(HMAC_SESSION_FIRST, &[], 0x00, &[]),
                    None,
                    &[0, 0],
                ),
                REFERENCE_S0,
            ),
            (
                "invalid_handle",
                session_shutdown(&session_bytes(0x1234_5678, &[], 0x00, &[]), None, &[0, 0]),
                SESSION1_VALUE,
            ),
            (
                "pw_truncated_hmac",
                session_shutdown(&pw_trunc_hmac, None, &[0, 0]),
                SESSION1_INSUFFICIENT,
            ),
            (
                "two_pw",
                session_shutdown(&two_pw, None, &[0, 0]),
                SESSION1_HANDLE,
            ),
            (
                "pw_leftover_byte",
                session_shutdown(&pw_leftover, None, &[0, 0]),
                SESSION2_INSUFFICIENT,
            ),
        ] {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(&mut runtime, &command),
                response_bytes(expected),
                "{label}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn shutdown_clear_persists_live_go_and_omits_gr_gc() {
        let mut runtime = started_runtime();
        let live_seed = runtime.live.orderly.drbg_state.seed.expose().to_vec();
        let live_counter = runtime.live.orderly.drbg_state.reseed_counter;
        assert_ne!(
            state(&runtime).orderly.drbg_state.seed.expose(),
            &live_seed[..],
            "startup reseeded only the live go"
        );
        let nv_before = runtime.nv_memory.clone();

        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(TPM_SU_CLEAR)),
            response_bytes(SUCCESS)
        );

        let state = state(&runtime);
        assert_eq!(state.persistent.orderly_state, TPM_SU_CLEAR);
        assert_eq!(state.orderly.drbg_state.seed.expose(), &live_seed[..]);
        assert_eq!(state.orderly.drbg_state.reseed_counter, live_counter);
        assert_eq!(state.orderly.clock_safe, runtime.live.orderly.clock_safe);
        assert!(
            state.state_reset.is_none() && state.state_clear.is_none(),
            "SU_CLEAR persists no gr/gc"
        );
        assert!(
            runtime.live.state_reset.is_some() && runtime.live.state_clear.is_some(),
            "the live gr/gc survive Shutdown"
        );
        assert!(runtime.startup_received, "Shutdown keeps g_initialized set");
        assert!(runtime.nv_update_pending);
        assert_ne!(runtime.nv_memory, nv_before);
        assert_eq!(runtime.nv_memory, build_nv_image(state).unwrap());

        let reloaded = reload(state);
        assert_eq!(reloaded.persistent.orderly_state, TPM_SU_CLEAR);
        assert!(reloaded.state_reset.is_none() && reloaded.state_clear.is_none());
        assert_eq!(reloaded.orderly.drbg_state.seed.expose(), &live_seed[..]);
    }

    #[test]
    fn shutdown_state_persists_live_go_gr_and_gc() {
        let mut runtime = started_runtime();
        let live_seed = runtime.live.orderly.drbg_state.seed.expose().to_vec();
        let null_proof = runtime
            .live
            .state_reset
            .as_ref()
            .unwrap()
            .null_proof
            .expose()
            .to_vec();

        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(TPM_SU_STATE)),
            response_bytes(SUCCESS)
        );

        let state = state(&runtime);
        assert_eq!(state.persistent.orderly_state, TPM_SU_STATE);
        assert_eq!(state.orderly.drbg_state.seed.expose(), &live_seed[..]);
        let reset = state.state_reset.as_ref().expect("gr persisted");
        assert_eq!(reset.clear_count, 0);
        assert_eq!(reset.restart_count, 0);
        assert_eq!(reset.null_proof.expose(), &null_proof[..]);
        assert!(state.state_clear.is_some(), "gc persisted");
        assert!(runtime.startup_received, "Shutdown keeps g_initialized set");
        assert!(runtime.nv_update_pending);
        assert_eq!(runtime.nv_memory, build_nv_image(state).unwrap());

        let reloaded = reload(state);
        assert_eq!(reloaded.persistent.orderly_state, TPM_SU_STATE);
        let reloaded_reset = reloaded.state_reset.as_ref().expect("gr round-trips");
        assert_eq!(reloaded_reset.null_proof.expose(), &null_proof[..]);
        assert!(reloaded.state_clear.is_some());
    }

    #[test]
    fn shutdown_state_records_the_locality_3_modifier() {
        let mut runtime = manufactured_runtime();
        runtime.locality = 3;
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
            response_bytes(SUCCESS)
        );
        assert!(runtime.live.startup_locality3);
        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(TPM_SU_STATE)),
            response_bytes(SUCCESS)
        );
        assert_eq!(
            state(&runtime).persistent.orderly_state,
            TPM_SU_STATE | STARTUP_LOCALITY_3
        );
    }

    #[test]
    fn shutdown_state_records_the_drtm_modifier_with_upstream_precedence() {
        let mut runtime = started_runtime();
        runtime.live.drtm_pre_startup = true;
        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(TPM_SU_STATE)),
            response_bytes(SUCCESS)
        );
        assert_eq!(
            state(&runtime).persistent.orderly_state,
            TPM_SU_STATE | PRE_STARTUP_FLAG
        );

        let mut runtime = started_runtime();
        runtime.live.drtm_pre_startup = true;
        runtime.live.startup_locality3 = true;
        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(TPM_SU_STATE)),
            response_bytes(SUCCESS)
        );
        assert_eq!(
            state(&runtime).persistent.orderly_state,
            TPM_SU_STATE | PRE_STARTUP_FLAG,
            "PRE_STARTUP_FLAG wins over STARTUP_LOCALITY_3"
        );
    }

    #[test]
    fn shutdown_clear_keeps_su_clear_without_modifiers() {
        let mut runtime = started_runtime();
        runtime.live.drtm_pre_startup = true;
        runtime.live.startup_locality3 = true;
        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(TPM_SU_CLEAR)),
            response_bytes(SUCCESS)
        );
        assert_eq!(state(&runtime).persistent.orderly_state, TPM_SU_CLEAR);
    }

    #[test]
    fn orderly_nv_ram_is_copied_into_the_nv_backed_state() {
        let mut runtime = started_runtime();
        let entry = OwnedOrderlyRamEntry {
            declared_size: 20,
            handle: 0x0100_0005,
            attributes: TPMA_NV_ORDERLY | TPMA_NV_WRITTEN,
            data: vec![0xaa; 8],
        };
        runtime.live.index_orderly_ram = OwnedIndexOrderlyRam {
            sourceside_size: 512,
            entries: vec![entry.clone()],
            terminated: true,
            used_bytes: 20,
        };
        assert!(state(&runtime).index_orderly_ram.entries.is_empty());

        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(TPM_SU_CLEAR)),
            response_bytes(SUCCESS)
        );

        let state = state(&runtime);
        assert_eq!(state.index_orderly_ram.entries, vec![entry.clone()]);
        assert_eq!(runtime.nv_memory, build_nv_image(state).unwrap());

        let reloaded = reload(state);
        assert_eq!(reloaded.index_orderly_ram.entries.len(), 1);
        assert_eq!(reloaded.index_orderly_ram.entries[0].handle, entry.handle);
        assert_eq!(
            reloaded.index_orderly_ram.entries[0].attributes,
            entry.attributes
        );
        assert_eq!(reloaded.index_orderly_ram.entries[0].data, entry.data);
    }

    #[test]
    fn shutdown_clears_da_used() {
        let mut runtime = started_runtime();
        runtime.live.da_used = true;
        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(TPM_SU_CLEAR)),
            response_bytes(SUCCESS)
        );
        assert!(!runtime.live.da_used);
    }

    #[test]
    fn shutdown_state_saves_the_live_pcrs_into_gc() {
        let mut runtime = started_runtime();
        runtime.live.pcrs[5].banks[SHA256_SLOT] = Some(vec![0xaa; 32]);
        runtime.live.pcrs[17].banks[SHA256_SLOT] = Some(vec![0xbb; 32]);

        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(TPM_SU_STATE)),
            response_bytes(SUCCESS)
        );

        for clear in [
            state(&runtime).state_clear.as_ref().expect("NV gc"),
            runtime.live.state_clear.as_ref().expect("live gc"),
        ] {
            let bank = clear.pcr_save[SHA256_SLOT].as_ref().expect("SHA-256 bank");
            assert_eq!(bank.hash_alg, 0x000b);
            assert_eq!(bank.pcrs.len(), NUM_STATIC_PCR * 32);
            assert_eq!(&bank.pcrs[5 * 32..6 * 32], &[0xaa; 32][..]);
            assert!(
                bank.pcrs[6 * 32..].iter().all(|&byte| byte == 0),
                "PCR 17 is not state-saved"
            );
            assert!(clear.pcr_save[0].is_some(), "allocated SHA-1 bank saved");
        }
    }

    #[test]
    fn shutdown_clear_does_not_save_pcr_state() {
        let mut runtime = started_runtime();
        runtime.live.pcrs[5].banks[SHA256_SLOT] = Some(vec![0xaa; 32]);
        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(TPM_SU_CLEAR)),
            response_bytes(SUCCESS)
        );
        assert!(
            runtime
                .live
                .state_clear
                .as_ref()
                .unwrap()
                .pcr_save
                .iter()
                .all(Option::is_none)
        );
    }

    #[test]
    fn pcr_reconfiguration_rejects_only_state_shutdown() {
        let mut runtime = started_runtime();
        runtime.live.pcr_reconfig = true;
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(TPM_SU_STATE)),
            response_bytes(TYPE_PARAM1)
        );
        assert_unchanged(&runtime, &before);
        assert!(runtime.startup_received);
        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(TPM_SU_CLEAR)),
            response_bytes(SUCCESS)
        );
    }

    #[test]
    fn unavailable_nv_causes_no_mutation() {
        let mut runtime = started_runtime();
        runtime.nv_available = false;
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(TPM_SU_CLEAR)),
            response_bytes(NV_UNAVAILABLE)
        );
        assert_unchanged(&runtime, &before);
        assert!(runtime.startup_received);

        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(0x0002)),
            response_bytes(VALUE_PARAM1),
            "parameter parsing precedes the NV availability check"
        );
        assert_unchanged(&runtime, &before);

        runtime.nv_available = true;
        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(TPM_SU_CLEAR)),
            response_bytes(SUCCESS)
        );
    }

    #[test]
    fn missing_live_gr_or_gc_rejects_state_shutdown_transactionally() {
        for drop_reset in [true, false] {
            let mut runtime = started_runtime();
            if drop_reset {
                runtime.live.state_reset = None;
            } else {
                runtime.live.state_clear = None;
            }
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(&mut runtime, &shutdown_command(TPM_SU_STATE)),
                response_bytes(FAILURE),
                "drop_reset {drop_reset}"
            );
            assert_unchanged(&runtime, &before);
            assert!(runtime.startup_received);
            assert_eq!(
                dispatch_bytes(&mut runtime, &shutdown_command(TPM_SU_CLEAR)),
                response_bytes(SUCCESS),
                "SU_CLEAR does not need the live gr/gc"
            );
        }
    }

    #[test]
    fn nv_serialization_failure_rolls_back_all_state_changes() {
        let mut runtime = started_runtime();
        runtime.live.state_clear.as_mut().unwrap().platform_policy = vec![0x11; 100];
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(TPM_SU_STATE)),
            response_bytes(FAILURE)
        );
        assert_unchanged(&runtime, &before);
        assert!(runtime.startup_received);
        assert!(!runtime.nv_update_pending);

        runtime.live.state_clear.as_mut().unwrap().platform_policy = Vec::new();
        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(TPM_SU_STATE)),
            response_bytes(SUCCESS)
        );
    }

    #[test]
    fn shutdown_clear_then_startup_clear_after_reset_is_a_reset() {
        let mut runtime = started_runtime();
        assert_eq!(state(&runtime).persistent.reset_count, 1);
        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(TPM_SU_CLEAR)),
            response_bytes(SUCCESS)
        );
        let shutdown_seed = runtime.live.orderly.drbg_state.seed.expose().to_vec();

        let mut runtime = rebooted_runtime(&runtime);
        assert!(!runtime.startup_received, "_TPM_Init clears g_initialized");
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
            response_bytes(SUCCESS)
        );

        let state = state(&runtime);
        assert_eq!(state.persistent.reset_count, 2, "SU_RESET");
        assert_eq!(state.persistent.total_reset_count, 2);
        assert_eq!(state.persistent.orderly_state, 0xffff);
        let reset = runtime.live.state_reset.as_ref().unwrap();
        assert_eq!(reset.clear_count, 0, "a Reset builds a fresh gr");
        assert_eq!(reset.restart_count, 0);
        assert_eq!(runtime.live.prev_orderly_state, TPM_SU_CLEAR);
        assert_eq!(
            runtime.live.orderly.clock_safe, 1,
            "an orderly shutdown keeps clockSafe"
        );
        assert_eq!(
            state.orderly.drbg_state.seed.expose(),
            &shutdown_seed[..],
            "the NV go is the shutdown-time live go"
        );
        assert_ne!(
            runtime.live.orderly.drbg_state.seed.expose(),
            &shutdown_seed[..],
            "Startup reseeded the restored go"
        );
    }

    #[test]
    fn shutdown_state_then_startup_state_after_reset_is_a_resume() {
        let mut runtime = started_runtime();
        runtime.live.pcrs[5].banks[SHA256_SLOT] = Some(vec![0xaa; 32]);
        let null_proof = runtime
            .live
            .state_reset
            .as_ref()
            .unwrap()
            .null_proof
            .expose()
            .to_vec();
        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(TPM_SU_STATE)),
            response_bytes(SUCCESS)
        );

        let mut runtime = rebooted_runtime(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_STATE)),
            response_bytes(SUCCESS)
        );

        let state = state(&runtime);
        assert_eq!(state.persistent.reset_count, 1, "a Resume is not a Reset");
        assert_eq!(state.persistent.orderly_state, 0xffff);
        let reset = runtime.live.state_reset.as_ref().unwrap();
        assert_eq!(reset.clear_count, 0, "preserved on Resume");
        assert_eq!(reset.restart_count, 1, "restartCount++");
        assert_eq!(reset.null_proof.expose(), &null_proof[..]);
        assert_eq!(runtime.live.prev_orderly_state, TPM_SU_STATE);
        assert_eq!(
            runtime.live.pcrs[5].banks[SHA256_SLOT].as_deref(),
            Some(&[0xaa; 32][..]),
            "the state-saved PCR came back through gc.pcrSave"
        );
        assert_eq!(
            state.orderly.drbg_state.reseed_counter, 4,
            "the NV go keeps the shutdown-time value"
        );
        assert_eq!(
            runtime.live.orderly.drbg_state.reseed_counter, 1,
            "Resume reseeds without generating fresh secrets"
        );
    }

    #[test]
    fn shutdown_state_then_startup_clear_after_reset_is_a_restart() {
        let mut runtime = started_runtime();
        runtime.live.pcrs[5].banks[SHA256_SLOT] = Some(vec![0xaa; 32]);
        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(TPM_SU_STATE)),
            response_bytes(SUCCESS)
        );

        let mut runtime = rebooted_runtime(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
            response_bytes(SUCCESS)
        );

        let state = state(&runtime);
        assert_eq!(state.persistent.reset_count, 1, "a Restart is not a Reset");
        let reset = runtime.live.state_reset.as_ref().unwrap();
        assert_eq!(reset.clear_count, 1, "clearCount++");
        assert_eq!(reset.restart_count, 1, "restartCount++");
        let clear = runtime.live.state_clear.as_ref().unwrap();
        assert_eq!(clear.platform_alg, 0x0010, "gc reinitialized");
        assert!(clear.pcr_save.iter().all(Option::is_none));
        assert!(
            runtime.live.pcrs[5].banks[SHA256_SLOT]
                .as_ref()
                .unwrap()
                .iter()
                .all(|&byte| byte == 0),
            "PCRs reinitialize on Restart"
        );
    }

    #[test]
    fn locality_3_resume_round_trip_requires_locality_3() {
        let mut runtime = manufactured_runtime();
        runtime.locality = 3;
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_CLEAR)),
            response_bytes(SUCCESS)
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(TPM_SU_STATE)),
            response_bytes(SUCCESS)
        );

        let mut runtime = rebooted_runtime(&runtime);
        runtime.locality = 0;
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_STATE)),
            response_bytes(0x907)
        );
        assert!(!runtime.startup_received);

        runtime.locality = 3;
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_STATE)),
            response_bytes(SUCCESS)
        );
        assert!(runtime.startup_received);
    }

    #[test]
    fn drtm_resume_round_trip_requires_the_pre_startup_flag() {
        let mut runtime = started_runtime();
        runtime.live.drtm_pre_startup = true;
        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(TPM_SU_STATE)),
            response_bytes(SUCCESS)
        );

        let mut runtime = rebooted_runtime(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_STATE)),
            response_bytes(VALUE_PARAM1),
            "a resume without the DRTM sequence mismatches the saved flag"
        );
        assert!(!runtime.startup_received);

        runtime.live.drtm_pre_startup = true;
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command(TPM_SU_STATE)),
            response_bytes(SUCCESS)
        );
        assert!(runtime.startup_received);
    }
}
