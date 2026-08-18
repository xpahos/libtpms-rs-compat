use sha1::{Digest, Sha1};

use crate::ffi_types::TpmResult;
use crate::library::constants::TPM_FAIL;

use super::attach::{
    OwnedPcr, OwnedSession, OwnedSessionProcess, OwnedSessionSlot, OwnedVolatileState,
};
use super::{
    IMPLEMENTATION_PCR, MAX_LOADED_OBJECTS, MAX_LOADED_SESSIONS, MAX_SESSION_NUM,
    PRIMARY_SEED_SIZE, RAM_INDEX_SPACE, VOLATILE_STATE_MAGIC, VOLATILE_STATE_VERSION,
};
use crate::library::tpm2::clock::HostClock;
use crate::library::tpm2::live::{RestoredVolatile, power_on_state_clear, power_on_state_reset};
use crate::library::tpm2::nv::{
    NV_INDEX_RAM_DATA, WireWriter, any_object_image, marshal_sym_def_object,
};
use crate::library::tpm2::pcr::{PCR_MAGIC, PCR_SLOT_BANKS, PCR_VERSION};
use crate::library::tpm2::persistent::{
    OwnedSecret, marshal_orderly_data, marshal_state_clear, marshal_state_reset,
};
use crate::library::tpm2::public::{DIGEST_SIZE, NAME_SIZE, TPM_ALG_NULL};
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::session::{
    EPOCH_CLOCK_SIZE, SESSION_MAGIC, SESSION_SLOT_MAGIC, SESSION_SLOT_VERSION, SESSION_VERSION,
};

const MIN_SUPPORTED_VERSION: u16 = 1;

const SECTION_MIN_VERSION: u16 = 1;

const LEGACY_OBJECT_VERSION: u16 = 3;
pub(in crate::library::tpm2) const CURRENT_OBJECT_VERSION: u16 = 4;

const LAST_LEGACY_OBJECT_FORMAT_LEVEL: u32 = 5;

pub(in crate::library::tpm2) fn volatile_object_version(
    state_format_level: u32,
) -> Result<u16, TpmResult> {
    match state_format_level {
        0 => Err(TPM_FAIL),
        level if level <= LAST_LEGACY_OBJECT_FORMAT_LEVEL => Ok(LEGACY_OBJECT_VERSION),
        _ => Ok(CURRENT_OBJECT_VERSION),
    }
}

fn bounded_tpm2b(w: &mut WireWriter, data: &[u8], maximum: usize) -> Result<(), TpmResult> {
    if data.len() > maximum {
        return Err(TPM_FAIL);
    }
    w.tpm2b(data)
}

fn marshal_pcr(w: &mut WireWriter, pcr: &OwnedPcr) -> Result<(), TpmResult> {
    w.nv_header(PCR_VERSION, PCR_MAGIC, SECTION_MIN_VERSION);
    for (index, &(algorithm, digest_size)) in PCR_SLOT_BANKS.iter().enumerate() {
        w.u16(algorithm);
        w.u16(u16::try_from(digest_size).map_err(|_| TPM_FAIL)?);
        match &pcr.banks[index] {
            Some(digest) => {
                if digest.len() != digest_size {
                    return Err(TPM_FAIL);
                }
                w.bytes(digest);
            }
            None => w.bytes(&vec![0u8; digest_size]),
        }
    }
    w.u16(TPM_ALG_NULL);
    w.block(true, |_| Ok(()))
}

fn marshal_session(w: &mut WireWriter, session: &OwnedSession) -> Result<(), TpmResult> {
    w.nv_header(SESSION_VERSION, SESSION_MAGIC, SECTION_MIN_VERSION);
    w.u32(session.attributes);
    w.u32(session.pcr_counter);
    w.u64(session.start_time);
    w.u64(session.timeout);
    w.u8(EPOCH_CLOCK_SIZE);
    w.u32(session.epoch);
    w.u32(session.command_code);
    w.u16(session.auth_hash_alg);
    w.u8(session.command_locality);
    marshal_sym_def_object(w, &session.symmetric);
    bounded_tpm2b(w, session.session_key.as_bytes(), DIGEST_SIZE)?;
    bounded_tpm2b(w, session.nonce_tpm.as_bytes(), DIGEST_SIZE)?;
    bounded_tpm2b(w, &session.bound_entity, NAME_SIZE)?;
    bounded_tpm2b(w, &session.audit_digest, DIGEST_SIZE)?;
    w.block(true, |_| Ok(()))
}

fn marshal_session_slot(w: &mut WireWriter, slot: &OwnedSessionSlot) -> Result<(), TpmResult> {
    w.nv_header(
        SESSION_SLOT_VERSION,
        SESSION_SLOT_MAGIC,
        SECTION_MIN_VERSION,
    );
    w.u8(u8::from(slot.occupied));
    match (slot.occupied, &slot.session) {
        (false, None) => Ok(()),
        (true, Some(session)) => {
            marshal_session(w, session)?;
            w.block(true, |_| Ok(()))
        }
        _ => Err(TPM_FAIL),
    }
}

fn marshal_session_process(
    w: &mut WireWriter,
    process: &OwnedSessionProcess,
) -> Result<(), TpmResult> {
    w.u16(u16::try_from(MAX_SESSION_NUM).map_err(|_| TPM_FAIL)?);
    for index in 0..MAX_SESSION_NUM {
        w.u32(process.session_handles[index]);
        w.u8(process.attributes[index]);
        w.u32(process.associated_handles[index]);
        bounded_tpm2b(w, process.nonce_callers[index].as_bytes(), DIGEST_SIZE)?;
        bounded_tpm2b(w, process.input_auth_values[index].as_bytes(), DIGEST_SIZE)?;
    }
    w.u32(process.encrypt_session_index);
    w.u32(process.decrypt_session_index);
    w.u32(process.audit_session_index);
    w.block(true, |w| {
        bounded_tpm2b(w, &process.cp_hash_for_command_audit, DIGEST_SIZE)
    })?;
    w.u8(u8::from(process.da_pending_on_nv));
    Ok(())
}

pub(in crate::library::tpm2) fn marshal_volatile_state(
    state: &OwnedVolatileState,
) -> Result<Vec<u8>, TpmResult> {
    if state.objects.len() != MAX_LOADED_OBJECTS
        || state.pcrs.len() != IMPLEMENTATION_PCR
        || state.sessions.len() != MAX_LOADED_SESSIONS
        || state.index_orderly_ram.len() != RAM_INDEX_SPACE
    {
        return Err(TPM_FAIL);
    }
    let Some(tail) = state.tail_v4 else {
        return Err(TPM_FAIL);
    };

    let mut w = WireWriter::new();
    w.nv_header(
        VOLATILE_STATE_VERSION,
        VOLATILE_STATE_MAGIC,
        MIN_SUPPORTED_VERSION,
    );

    w.u32(state.exclusive_audit_session);
    w.u64(state.time);
    w.u8(u8::from(state.ph_enable));
    w.u8(u8::from(state.pcr_reconfig));
    w.u32(state.drtm_handle);
    w.u8(u8::from(state.drtm_pre_startup));
    w.u8(u8::from(state.startup_locality3));

    w.block(true, |w| {
        w.u8(u8::from(state.da_used));
        Ok(())
    })?;

    w.u8(u8::from(state.power_was_lost));
    w.u16(state.prev_orderly_state);
    w.u8(u8::from(state.nv_ok));
    w.tpm2b(&[])?;

    marshal_orderly_data(&mut w, &state.orderly)?;
    marshal_state_clear(&mut w, &state.state_clear)?;
    marshal_state_reset(
        &mut w,
        &state.state_reset,
        state.state_reset.null_seed_compat_level,
    )?;

    w.u8(u8::from(state.manufactured));
    w.u8(u8::from(state.initialized));

    w.block(true, |w| marshal_session_process(w, &state.session_process))?;

    w.block(false, |_| Ok(()))?;

    w.block(true, |w| {
        w.u32(state.evict_nv_end);
        w.u16(u16::try_from(RAM_INDEX_SPACE).map_err(|_| TPM_FAIL)?);
        w.bytes(&state.index_orderly_ram);
        w.u64(state.max_counter);
        Ok(())
    })?;

    w.block(true, |w| {
        w.u16(u16::try_from(MAX_LOADED_OBJECTS).map_err(|_| TPM_FAIL)?);
        for object in &state.objects {
            let image = any_object_image(object, state.object_version)?;
            w.bytes(&image);
        }
        Ok(())
    })?;

    w.block(true, |w| {
        w.u16(u16::try_from(IMPLEMENTATION_PCR).map_err(|_| TPM_FAIL)?);
        for pcr in &state.pcrs {
            marshal_pcr(w, pcr)?;
        }
        Ok(())
    })?;

    w.block(true, |w| {
        w.u16(u16::try_from(MAX_LOADED_SESSIONS).map_err(|_| TPM_FAIL)?);
        for slot in &state.sessions {
            marshal_session_slot(w, slot)?;
        }
        w.u32(state.oldest_saved_session);
        w.u32(state.free_session_slots);
        Ok(())
    })?;

    w.u8(u8::from(state.in_failure_mode));
    w.u8(u8::from(state.tpm_established));

    w.block(true, |w| {
        w.u32(state.fail_function);
        w.u32(state.fail_line);
        w.u32(state.fail_code);
        Ok(())
    })?;

    w.block(true, |w| {
        w.u64(state.real_time_previous);
        w.u64(state.tpm_time);
        Ok(())
    })?;

    w.u8(u8::from(state.timer_reset));
    w.u8(u8::from(state.timer_stopped));
    w.u32(state.adjust_rate);
    w.u64(state.backthen);

    w.block(true, |w| {
        bounded_tpm2b(w, state.ep_seed.as_bytes(), PRIMARY_SEED_SIZE)?;
        bounded_tpm2b(w, state.sp_seed.as_bytes(), PRIMARY_SEED_SIZE)?;
        bounded_tpm2b(w, state.pp_seed.as_bytes(), PRIMARY_SEED_SIZE)?;
        w.block(true, |w| {
            w.u64(tail.host_monotonic_sample);
            w.u64(tail.suspended_elapsed_time);
            w.u64(tail.last_system_time);
            w.u64(tail.last_reported_time);
            w.block(true, |_| Ok(()))
        })
    })?;

    w.u32(VOLATILE_STATE_MAGIC);

    let mut blob = w.out;
    blob.extend_from_slice(&Sha1::digest(&blob));
    Ok(blob)
}

pub(in crate::library::tpm2) fn capture_volatile_state(
    runtime: &Tpm2Runtime,
    clock: &dyn HostClock,
) -> Result<OwnedVolatileState, TpmResult> {
    let persistent = runtime.state.as_ref().ok_or(TPM_FAIL)?;
    let object_version = volatile_object_version(persistent.profile.state_format_level)?;

    let power_on_compat;
    let compat = match runtime.restored_volatile.as_ref() {
        Some(restored) => restored,
        None => {
            power_on_compat = RestoredVolatile::power_on();
            &power_on_compat
        }
    };

    let live = &runtime.live;

    let index_orderly_ram = runtime
        .nv_memory
        .get(NV_INDEX_RAM_DATA..NV_INDEX_RAM_DATA + RAM_INDEX_SPACE)
        .ok_or(TPM_FAIL)?
        .to_vec();

    let mut state_reset = live
        .state_reset
        .clone()
        .unwrap_or_else(power_on_state_reset);
    state_reset.context_slot_mask = live.context_slot_mask;
    state_reset.null_seed_compat_level = live.null_seed_compat_level;

    let backthen = clock.realtime_ms();
    let host_monotonic_sample = clock
        .monotonic_ms()
        .wrapping_add(runtime.clock.host_monotonic_adjust_ms as u64);

    let mut session_process = compat.session_process.clone();
    session_process.da_pending_on_nv = live.da_pending_on_nv;

    Ok(OwnedVolatileState {
        header_version: VOLATILE_STATE_VERSION,
        exclusive_audit_session: compat.exclusive_audit_session,
        time: runtime.timer.time_ms,
        ph_enable: live.ph_enable,
        pcr_reconfig: live.pcr_reconfig,
        drtm_handle: compat.drtm_handle,
        drtm_pre_startup: live.drtm_pre_startup,
        startup_locality3: live.startup_locality3,
        da_used: live.da_used,
        power_was_lost: live.power_was_lost,
        prev_orderly_state: live.prev_orderly_state,
        nv_ok: live.nv_ok,
        orderly: live.orderly.clone(),
        state_clear: live
            .state_clear
            .clone()
            .unwrap_or_else(power_on_state_clear),
        state_reset,
        manufactured: runtime.was_manufactured,
        initialized: runtime.startup_received,
        session_process,
        evict_nv_end: compat.evict_nv_end,
        index_orderly_ram,
        max_counter: live.max_nv_counter,
        objects: live.objects.clone(),
        pcrs: live.pcrs.clone(),
        sessions: live.sessions.clone(),
        oldest_saved_session: live.oldest_saved_session,
        free_session_slots: live.free_session_slots,
        in_failure_mode: runtime.failure_mode,
        tpm_established: runtime.tpm_established,
        fail_function: compat.fail_function,
        fail_line: compat.fail_line,
        fail_code: compat.fail_code,
        real_time_previous: runtime.timer.real_time_previous,
        tpm_time: runtime.timer.tpm_time,
        timer_reset: runtime.timer.timer_reset,
        timer_stopped: runtime.timer.timer_stopped,
        adjust_rate: runtime.timer.adjust_rate,
        backthen,
        times_are_realtime: false,
        tail_v4: Some(super::TailV4 {
            host_monotonic_sample,
            suspended_elapsed_time: runtime.clock.suspended_elapsed_ms,
            last_system_time: runtime.clock.last_system_time_ms,
            last_reported_time: runtime.clock.last_reported_time_ms,
        }),
        resume_clock: runtime.clock,
        ep_seed: OwnedSecret::copy_of(persistent.persistent.ep_seed.as_bytes()),
        sp_seed: OwnedSecret::copy_of(persistent.persistent.sp_seed.as_bytes()),
        pp_seed: OwnedSecret::copy_of(persistent.persistent.pp_seed.as_bytes()),
        object_version,
    })
}

pub(in crate::library::tpm2) fn volatile_all_store(
    runtime: &Tpm2Runtime,
    clock: &dyn HostClock,
) -> Result<Vec<u8>, TpmResult> {
    marshal_volatile_state(&capture_volatile_state(runtime, clock)?)
}

#[cfg(test)]
mod tests {
    use super::super::{
        SHA1_DIGEST_SIZE, SeedTie, VolatileFixture, materialize_volatile_state,
        parse_volatile_state_blob,
    };
    use super::*;
    use crate::library::tpm2::clock::{ClockCall, RecordingClock, RuntimeClock};
    use crate::library::tpm2::hierarchy::TPM_RH_UNASSIGNED;
    use crate::library::tpm2::manufacture::manufacture_state;
    use crate::library::tpm2::object::ATTR_OCCUPIED;
    use crate::library::tpm2::persistent::ProfileField;
    use crate::library::tpm2::persistent::{OwnedAnyObjectBody, OwnedPcrBank};
    use crate::library::tpm2::profile::{validate_profile, validate_user_profile};
    use crate::library::tpm2::public::StateFormatLimit;
    use crate::library::tpm2::runtime::{commit_manufactured_state, merge_volatile_state};
    use crate::library::tpm2::volatile::DecodedVolatileState;

    const C_FIXTURE_V4: &[u8] = include_bytes!("../testdata/volatile_state_v4.bin");
    const C_FIXTURE_V4_FUTURE: &[u8] = include_bytes!("../testdata/volatile_state_v4_future.bin");

    const HOST_REALTIME: u64 = 1_600_000_500_000;
    const HOST_MONOTONIC: u64 = 7_000_000;

    fn host_clock() -> RecordingClock {
        RecordingClock::new(HOST_REALTIME, HOST_MONOTONIC)
    }

    fn own_c_fixture(blob: &[u8]) -> OwnedVolatileState {
        let decoded = parse_volatile_state_blob(
            blob,
            &[],
            SeedTie::EMPTY,
            &host_clock(),
            StateFormatLimit::CURRENT,
        )
        .expect("the C fixture decodes");
        materialize_volatile_state(&decoded, SeedTie::EMPTY, CURRENT_OBJECT_VERSION)
            .expect("the C fixture materializes")
    }

    fn own_synthetic_fixture(fixture: &VolatileFixture) -> OwnedVolatileState {
        let blob = fixture.bytes();
        let decoded = parse_volatile_state_blob(
            &blob,
            &[],
            VolatileFixture::seed_tie(),
            &host_clock(),
            StateFormatLimit::CURRENT,
        )
        .expect("the synthetic fixture decodes");
        materialize_volatile_state(
            &decoded,
            VolatileFixture::seed_tie(),
            CURRENT_OBJECT_VERSION,
        )
        .expect("the synthetic fixture materializes")
    }

    fn deterministic_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
        let len = buffer.len() as u8;
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_add(len) ^ 0x71;
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

    fn runtime_seed_tie(runtime: &Tpm2Runtime) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let persistent = &runtime.state().persistent;
        (
            persistent.ep_seed.expose().to_vec(),
            persistent.sp_seed.expose().to_vec(),
            persistent.pp_seed.expose().to_vec(),
        )
    }

    fn decode_produced<'a>(
        blob: &'a [u8],
        seeds: &'a (Vec<u8>, Vec<u8>, Vec<u8>),
    ) -> DecodedVolatileState<'a> {
        parse_volatile_state_blob(
            blob,
            &[],
            SeedTie {
                ep_seed: &seeds.0,
                sp_seed: &seeds.1,
                pp_seed: &seeds.2,
            },
            &host_clock(),
            StateFormatLimit::CURRENT,
        )
        .expect("the produced blob decodes")
    }

    fn store(runtime: &Tpm2Runtime) -> Vec<u8> {
        volatile_all_store(runtime, &host_clock()).expect("the runtime serializes")
    }

    fn restored_from_c_fixture() -> Box<Tpm2Runtime> {
        let mut runtime = manufactured_runtime();
        merge_volatile_state(&mut runtime, own_c_fixture(C_FIXTURE_V4));
        runtime
    }

    #[test]
    fn c_v4_fixture_reencodes_byte_for_byte() {
        let owned = own_c_fixture(C_FIXTURE_V4);
        assert_eq!(marshal_volatile_state(&owned).unwrap(), C_FIXTURE_V4);
    }

    #[test]
    fn c_v4_future_fixture_reencodes_to_the_current_writer_bytes() {
        assert_eq!(C_FIXTURE_V4_FUTURE.len(), C_FIXTURE_V4.len() + 6);
        let owned = own_c_fixture(C_FIXTURE_V4_FUTURE);
        assert_eq!(
            marshal_volatile_state(&owned).unwrap(),
            C_FIXTURE_V4,
            "the forward-compatible bytes are not part of the current writer's output"
        );
    }

    #[test]
    fn synthetic_v4_fixture_reencodes_byte_for_byte() {
        let fixture = VolatileFixture::default();
        let owned = own_synthetic_fixture(&fixture);
        assert_eq!(marshal_volatile_state(&owned).unwrap(), fixture.bytes());
    }

    #[test]
    fn occupied_objects_and_sessions_reencode_byte_for_byte() {
        let mut fixture = VolatileFixture::default();
        fixture.objects[0] = crate::library::tpm2::object::fixtures::any_rsa_object(4);
        let owned = own_synthetic_fixture(&fixture);
        assert!(owned.objects[0].attributes & ATTR_OCCUPIED != 0);
        assert!(owned.sessions[0].occupied);
        assert_eq!(marshal_volatile_state(&owned).unwrap(), fixture.bytes());
    }

    #[test]
    fn reencoded_blob_decodes_back_to_an_equal_snapshot() {
        let owned = own_c_fixture(C_FIXTURE_V4);
        let encoded = marshal_volatile_state(&owned).unwrap();
        let round_tripped = own_c_fixture(&encoded);

        assert_eq!(round_tripped.header_version, VOLATILE_STATE_VERSION);
        assert_eq!(
            round_tripped.exclusive_audit_session,
            owned.exclusive_audit_session
        );
        assert_eq!(round_tripped.time, owned.time);
        assert_eq!(round_tripped.prev_orderly_state, owned.prev_orderly_state);
        assert_eq!(round_tripped.index_orderly_ram, owned.index_orderly_ram);
        assert_eq!(round_tripped.max_counter, owned.max_counter);
        assert_eq!(round_tripped.backthen, owned.backthen);
        assert_eq!(round_tripped.tail_v4, owned.tail_v4);
        assert_eq!(round_tripped.pcrs[5].banks, owned.pcrs[5].banks);
        assert_eq!(
            marshal_volatile_state(&round_tripped).unwrap(),
            encoded,
            "the decoder and the writer agree on every field"
        );
    }

    #[test]
    fn freshly_manufactured_runtime_serializes_without_restored_volatile() {
        let runtime = manufactured_runtime();
        assert!(runtime.restored_volatile.is_none());
        let blob = store(&runtime);
        let seeds = runtime_seed_tie(&runtime);
        let decoded = decode_produced(&blob, &seeds);

        assert_eq!(decoded.header_version, VOLATILE_STATE_VERSION);
        assert!(decoded.manufactured);
        assert!(!decoded.initialized);
        assert_eq!(
            decoded.evict_nv_end,
            crate::library::tpm2::runtime::NV_MEMORY_SIZE as u32,
            "NvInitStatic sets s_evictNvEnd to NV_MEMORY_SIZE"
        );
        assert_eq!(decoded.adjust_rate, 30_000, "CLOCK_NOMINAL");
        assert!(decoded.timer_reset, "_plat__TimerReset sets s_timerReset");
        assert!(decoded.timer_stopped);
        assert_eq!(decoded.exclusive_audit_session, 0);
        assert_eq!(
            decoded.drtm_handle, TPM_RH_UNASSIGNED,
            "_TPM_Init sets g_DRTMHandle to TPM_RH_UNASSIGNED"
        );
        assert_eq!(decoded.time, 0);
        assert_eq!(decoded.fail_function, 0);
        assert_eq!(decoded.fail_line, 0);
        assert_eq!(decoded.fail_code, 0);
        assert_eq!(decoded.real_time_previous, 0);
        assert_eq!(decoded.tpm_time, 0);
        assert_eq!(decoded.index_orderly_ram.len(), RAM_INDEX_SPACE);
        assert_eq!(decoded.objects.len(), MAX_LOADED_OBJECTS);
        assert_eq!(decoded.pcrs.len(), IMPLEMENTATION_PCR);
        assert_eq!(decoded.sessions.len(), MAX_LOADED_SESSIONS);
    }

    #[test]
    fn runtime_restored_from_the_c_fixture_serializes_again() {
        let runtime = restored_from_c_fixture();
        assert!(runtime.restored_volatile.is_some());
        let blob = store(&runtime);
        let seeds = runtime_seed_tie(&runtime);
        let decoded = decode_produced(&blob, &seeds);

        assert_eq!(
            decoded.exclusive_audit_session, 0x0300_0abc,
            "the compatibility carry supplies g_exclusiveAuditSession"
        );
        assert_eq!(decoded.time, 0x123456);
        assert_eq!(decoded.drtm_handle, 0x4000_0007);
        assert_eq!(decoded.evict_nv_end, 0x0002_4000);
        assert_eq!(decoded.fail_function, 0xa1);
        assert_eq!(decoded.fail_line, 0xa2);
        assert_eq!(decoded.fail_code, 0xa3);
        assert_eq!(decoded.real_time_previous, 111_222);
        assert_eq!(decoded.tpm_time, 111_000);
        assert!(decoded.timer_reset);
        assert!(!decoded.timer_stopped);
        assert_eq!(decoded.adjust_rate, 30_000);
        assert_eq!(decoded.session_process.session_handles[0], 0x0200_0000);
        assert_eq!(decoded.session_process.encrypt_session_index, 7);
        assert_eq!(
            decoded.session_process.cp_hash_for_command_audit,
            &[0x23; 32][..]
        );
        assert!(decoded.pcrs[5].banks[0].is_some());
        assert!(decoded.sessions[0].occupied);
    }

    #[test]
    fn live_pcr_mutations_reach_the_new_blob() {
        let mut runtime = manufactured_runtime();
        runtime.live.pcrs[7].banks[0] = Some(vec![0xa7; 20]);
        runtime.live.pcrs[7].banks[1] = Some(vec![0xb7; 32]);

        let blob = store(&runtime);
        let seeds = runtime_seed_tie(&runtime);
        let decoded = decode_produced(&blob, &seeds);
        assert_eq!(decoded.pcrs[7].banks[0], Some(&[0xa7u8; 20][..]));
        assert_eq!(decoded.pcrs[7].banks[1], Some(&[0xb7u8; 32][..]));
        assert_eq!(
            decoded.pcrs[6].banks[0],
            Some(&[0u8; 20][..]),
            "an unset bank is the upstream all-zero PCR array"
        );
    }

    #[test]
    fn live_session_and_object_slots_reach_the_new_blob() {
        let mut runtime = manufactured_runtime();
        let donor = own_synthetic_fixture(&{
            let mut fixture = VolatileFixture::default();
            fixture.objects[1] = crate::library::tpm2::object::fixtures::any_rsa_object(4);
            fixture
        });
        runtime.live.sessions = donor.sessions;
        runtime.live.objects = donor.objects;
        runtime.live.free_session_slots = 1;
        runtime.live.oldest_saved_session = 5;

        let blob = store(&runtime);
        let seeds = runtime_seed_tie(&runtime);
        let decoded = decode_produced(&blob, &seeds);
        assert!(decoded.sessions[0].occupied);
        let session = decoded.sessions[0].session.as_ref().expect("session body");
        assert_eq!(session.session_key, &[0x33; 32][..]);
        assert!(!decoded.sessions[1].occupied);
        assert_eq!(decoded.free_session_slots, 1);
        assert_eq!(decoded.oldest_saved_session, 5);
        assert!(!decoded.objects[0].occupied());
        assert!(decoded.objects[1].occupied());
    }

    #[test]
    fn failure_mode_and_tpm_established_come_from_the_runtime() {
        for (failure_mode, established) in [(false, false), (true, true), (true, false)] {
            let mut runtime = manufactured_runtime();
            runtime.failure_mode = failure_mode;
            runtime.tpm_established = established;
            let blob = store(&runtime);
            let seeds = runtime_seed_tie(&runtime);
            let decoded = decode_produced(&blob, &seeds);
            assert_eq!(decoded.in_failure_mode, failure_mode);
            assert_eq!(decoded.tpm_established, established);
        }
    }

    #[test]
    fn orderly_and_drbg_state_come_from_the_live_globals() {
        let mut runtime = manufactured_runtime();
        runtime.live.orderly.clock = 0x1234_5678;
        runtime.live.orderly.clock_safe = 0;
        runtime.live.orderly.self_heal_timer = 4242;
        runtime.live.orderly.lockout_timer = 2424;
        runtime.live.orderly.time = 999;
        runtime.live.orderly.drbg_state.reseed_counter = 77;
        runtime.live.orderly.drbg_state.last_value = [9, 8, 7, 6];
        let magic = runtime.live.orderly.drbg_state.drbg_magic;
        let seed = runtime.live.orderly.drbg_state.seed.expose().to_vec();

        let blob = store(&runtime);
        let seeds = runtime_seed_tie(&runtime);
        let decoded = decode_produced(&blob, &seeds);
        assert_eq!(decoded.orderly.clock, 0x1234_5678);
        assert_eq!(decoded.orderly.clock_safe, 0);
        assert_eq!(decoded.orderly.self_heal_timer, 4242);
        assert_eq!(decoded.orderly.lockout_timer, 2424);
        assert_eq!(decoded.orderly.time, 999);
        assert_eq!(decoded.orderly.drbg_state.reseed_counter, 77);
        assert_eq!(decoded.orderly.drbg_state.drbg_magic, magic);
        assert_eq!(decoded.orderly.drbg_state.seed, &seed[..]);
        assert_eq!(decoded.orderly.drbg_state.last_value, [9, 8, 7, 6]);
    }

    #[test]
    fn persistent_seeds_are_written_into_the_seed_tie_block() {
        let runtime = manufactured_runtime();
        let seeds = runtime_seed_tie(&runtime);
        assert!(!seeds.0.is_empty(), "a manufactured TPM has an EPS");
        let blob = store(&runtime);

        let _ = decode_produced(&blob, &seeds);
        let wrong = (vec![0xaa; 32], seeds.1.clone(), seeds.2.clone());
        assert!(
            parse_volatile_state_blob(
                &blob,
                &[],
                SeedTie {
                    ep_seed: &wrong.0,
                    sp_seed: &wrong.1,
                    pp_seed: &wrong.2,
                },
                &host_clock(),
                StateFormatLimit::CURRENT,
            )
            .is_err()
        );
    }

    #[test]
    fn a_runtime_without_persistent_state_cannot_be_serialized() {
        let mut runtime = manufactured_runtime();
        runtime.state = None;
        assert_eq!(volatile_all_store(&runtime, &host_clock()), Err(TPM_FAIL));
    }

    #[test]
    fn object_encoding_follows_the_active_profile() {
        assert_eq!(volatile_object_version(0), Err(TPM_FAIL));
        for level in 1..=5u32 {
            assert_eq!(volatile_object_version(level), Ok(LEGACY_OBJECT_VERSION));
        }
        for level in 6..=9u32 {
            assert_eq!(volatile_object_version(level), Ok(CURRENT_OBJECT_VERSION));
        }

        let runtime = manufactured_runtime();
        let level = runtime.state().profile.state_format_level;
        let snapshot = capture_volatile_state(&runtime, &host_clock()).unwrap();
        assert_eq!(
            snapshot.object_version,
            volatile_object_version(level).unwrap()
        );

        let profile = validate_profile(ProfileField::Bytes(
            br#"{"Name":"default-v1","StateFormatLevel":7}"#,
        ))
        .expect("the level-7 profile validates");
        let state = manufacture_state(profile, deterministic_entropy).expect("manufactures");
        let runtime = commit_manufactured_state(state).expect("commits");
        let snapshot = capture_volatile_state(&runtime, &host_clock()).unwrap();
        assert_eq!(snapshot.object_version, CURRENT_OBJECT_VERSION);
    }

    #[test]
    fn the_snapshot_object_version_changes_the_emitted_object_bytes() {
        let mut fixture = VolatileFixture::default();
        fixture.objects[0] = crate::library::tpm2::object::fixtures::any_rsa_object(4);
        let mut owned = own_synthetic_fixture(&fixture);

        owned.object_version = CURRENT_OBJECT_VERSION;
        let current = marshal_volatile_state(&owned).unwrap();
        owned.object_version = LEGACY_OBJECT_VERSION;
        let legacy = marshal_volatile_state(&owned).unwrap();
        assert_ne!(current, legacy);
        assert_eq!(
            current.len(),
            legacy.len() + 4,
            "the v4 object format appends the hierarchy handle"
        );
    }

    #[test]
    fn stale_restored_values_never_override_the_live_globals() {
        let mut runtime = restored_from_c_fixture();
        runtime.live.max_nv_counter = 0x5a5a;
        runtime.live.da_pending_on_nv = false;
        runtime.live.nv_ok = false;
        runtime.live.prev_orderly_state = 0x0001;
        runtime.live.power_was_lost = false;

        let restored = runtime.restored_volatile.as_ref().unwrap();
        assert_eq!(restored.max_counter, 0x2a, "the stale carry disagrees");
        assert!(restored.session_process.da_pending_on_nv);

        let blob = store(&runtime);
        let seeds = runtime_seed_tie(&runtime);
        let decoded = decode_produced(&blob, &seeds);
        assert_eq!(decoded.max_counter, 0x5a5a);
        assert!(!decoded.session_process.da_pending_on_nv);
        assert!(!decoded.nv_ok);
        assert_eq!(decoded.prev_orderly_state, 0x0001);
        assert!(!decoded.power_was_lost);
        assert_eq!(
            decoded.index_orderly_ram,
            &runtime.nv_memory[NV_INDEX_RAM_DATA..NV_INDEX_RAM_DATA + RAM_INDEX_SPACE],
            "s_indexOrderlyRam is the live NV image region, not the stale carry"
        );
    }

    #[test]
    fn every_upstream_field_has_a_pinned_runtime_source() {
        let mut runtime = manufactured_runtime();
        runtime.live.ph_enable = true;
        runtime.live.pcr_reconfig = true;
        runtime.live.drtm_pre_startup = true;
        runtime.live.startup_locality3 = true;
        runtime.live.da_used = true;
        runtime.live.power_was_lost = true;
        runtime.live.prev_orderly_state = 0x8001;
        runtime.live.nv_ok = true;
        runtime.live.da_pending_on_nv = true;
        runtime.live.max_nv_counter = 0x1234;
        runtime.live.context_slot_mask = 0x00ff;
        runtime.live.null_seed_compat_level = 1;
        runtime.live.free_session_slots = 2;
        runtime.live.oldest_saved_session = 9;
        runtime.startup_received = true;
        runtime.failure_mode = true;
        runtime.tpm_established = true;

        let blob = store(&runtime);
        let seeds = runtime_seed_tie(&runtime);
        let decoded = decode_produced(&blob, &seeds);

        assert!(decoded.ph_enable);
        assert!(decoded.pcr_reconfig);
        assert!(decoded.drtm_pre_startup);
        assert!(decoded.startup_locality3);
        assert!(decoded.da_used);
        assert!(decoded.power_was_lost);
        assert_eq!(decoded.prev_orderly_state, 0x8001);
        assert!(decoded.nv_ok);
        assert!(decoded.session_process.da_pending_on_nv);
        assert_eq!(decoded.max_counter, 0x1234);
        assert_eq!(decoded.state_reset.context_slot_mask, 0x00ff);
        assert_eq!(decoded.state_reset.null_seed_compat_level, 1);
        assert_eq!(decoded.free_session_slots, 2);
        assert_eq!(decoded.oldest_saved_session, 9);
        assert!(decoded.manufactured);
        assert!(decoded.initialized);
        assert!(decoded.in_failure_mode);
        assert!(decoded.tpm_established);
        assert_eq!(
            decoded.index_orderly_ram,
            &runtime.nv_memory[NV_INDEX_RAM_DATA..NV_INDEX_RAM_DATA + RAM_INDEX_SPACE]
        );
    }

    #[test]
    fn clock_reads_follow_the_upstream_order_and_wrap_like_c() {
        let mut runtime = manufactured_runtime();
        runtime.clock = RuntimeClock {
            host_monotonic_adjust_ms: -8_000_000,
            suspended_elapsed_ms: 60_000,
            last_system_time_ms: 1_600_000_000_500,
            last_reported_time_ms: 1_600_000_000_400,
        };

        let host = host_clock();
        let blob = volatile_all_store(&runtime, &host).expect("serializes");
        assert_eq!(host.calls(), [ClockCall::Realtime, ClockCall::Monotonic]);

        let seeds = runtime_seed_tie(&runtime);
        let decoded = decode_produced(&blob, &seeds);
        assert_eq!(decoded.backthen, HOST_REALTIME);
        let tail = decoded.tail_v4.expect("the v4 tail is always written");
        assert_eq!(
            tail.host_monotonic_sample,
            HOST_MONOTONIC.wrapping_add((-8_000_000i64) as u64),
            "ClockGetTime(CLOCK_MONOTONIC) + s_hostMonotonicAdjustTime wraps"
        );
        assert_eq!(tail.suspended_elapsed_time, 60_000);
        assert_eq!(tail.last_system_time, 1_600_000_000_500);
        assert_eq!(tail.last_reported_time, 1_600_000_000_400);
    }

    #[test]
    fn two_serializations_of_the_same_runtime_are_identical() {
        let runtime = restored_from_c_fixture();
        assert_eq!(store(&runtime), store(&runtime));
    }

    #[test]
    fn wrong_slot_counts_are_rejected() {
        for mutate in [
            (|state: &mut OwnedVolatileState| {
                state.objects.pop();
            }) as fn(&mut OwnedVolatileState),
            |state| {
                state.pcrs.pop();
            },
            |state| {
                state.sessions.pop();
            },
            |state| state.index_orderly_ram.truncate(511),
        ] {
            let mut owned = own_c_fixture(C_FIXTURE_V4);
            mutate(&mut owned);
            assert_eq!(marshal_volatile_state(&owned), Err(TPM_FAIL));
        }
    }

    #[test]
    fn session_slot_occupancy_must_match_the_session_body() {
        let mut owned = own_synthetic_fixture(&VolatileFixture::default());
        owned.sessions[0].occupied = false;
        assert_eq!(marshal_volatile_state(&owned), Err(TPM_FAIL));

        let mut owned = own_synthetic_fixture(&VolatileFixture::default());
        owned.sessions[1].occupied = true;
        assert_eq!(marshal_volatile_state(&owned), Err(TPM_FAIL));
    }

    #[test]
    fn pcr_bank_digests_of_the_wrong_size_are_rejected() {
        for (slot, wrong) in [(0usize, 19usize), (1, 33), (2, 0), (3, 65)] {
            let mut owned = own_c_fixture(C_FIXTURE_V4);
            owned.pcrs[3].banks[slot] = Some(vec![0u8; wrong]);
            assert_eq!(marshal_volatile_state(&owned), Err(TPM_FAIL));
        }
    }

    #[test]
    fn oversized_tpm2b_values_are_rejected() {
        let oversized = vec![0u8; DIGEST_SIZE + 1];
        let mut owned = own_c_fixture(C_FIXTURE_V4);
        owned.session_process.cp_hash_for_command_audit = oversized.clone();
        assert_eq!(marshal_volatile_state(&owned), Err(TPM_FAIL));

        let mut owned = own_c_fixture(C_FIXTURE_V4);
        owned.session_process.nonce_callers[1] = OwnedSecret::from_vec(oversized.clone());
        assert_eq!(marshal_volatile_state(&owned), Err(TPM_FAIL));

        let mut owned = own_c_fixture(C_FIXTURE_V4);
        owned.ep_seed = OwnedSecret::from_vec(vec![0u8; PRIMARY_SEED_SIZE + 1]);
        assert_eq!(marshal_volatile_state(&owned), Err(TPM_FAIL));

        let mut owned = own_synthetic_fixture(&VolatileFixture::default());
        let session = owned.sessions[0].session.as_mut().unwrap();
        session.bound_entity = vec![0u8; NAME_SIZE + 1];
        assert_eq!(marshal_volatile_state(&owned), Err(TPM_FAIL));
    }

    #[test]
    fn a_block_payload_wider_than_its_length_field_is_rejected() {
        let mut fixture = VolatileFixture::default();
        fixture.objects[0] = crate::library::tpm2::object::fixtures::any_rsa_object(4);
        let mut owned = own_synthetic_fixture(&fixture);
        let OwnedAnyObjectBody::Object(body) = &mut owned.objects[0].body else {
            panic!("the fixture slot holds a key object");
        };
        body.name = vec![0u8; 40_000];
        body.qualified_name = vec![0u8; 40_000];
        assert_eq!(marshal_volatile_state(&owned), Err(TPM_FAIL));
    }

    #[test]
    fn a_snapshot_without_a_version_4_tail_is_rejected() {
        let mut owned = own_c_fixture(C_FIXTURE_V4);
        owned.tail_v4 = None;
        assert_eq!(marshal_volatile_state(&owned), Err(TPM_FAIL));
    }

    #[test]
    fn an_unoccupied_object_slot_with_the_occupied_bit_is_rejected() {
        let mut owned = own_c_fixture(C_FIXTURE_V4);
        owned.objects[0].attributes |= ATTR_OCCUPIED;
        assert_eq!(marshal_volatile_state(&owned), Err(TPM_FAIL));
    }

    #[test]
    fn an_oversized_pcr_bank_from_state_clear_is_rejected() {
        let mut owned = own_c_fixture(C_FIXTURE_V4);
        owned.state_clear.pcr_save[0] = Some(OwnedPcrBank {
            hash_alg: 0x0004,
            pcrs: vec![0u8; 1],
        });
        assert_eq!(marshal_volatile_state(&owned), Err(TPM_FAIL));
    }

    #[test]
    fn strict_prefixes_of_a_produced_blob_are_handled_safely() {
        let runtime = restored_from_c_fixture();
        let blob = store(&runtime);
        let seeds = runtime_seed_tie(&runtime);
        let payload = &blob[..blob.len() - SHA1_DIGEST_SIZE];
        for len in (0..payload.len()).step_by(37) {
            let mut prefix = payload[..len].to_vec();
            prefix.extend_from_slice(&Sha1::digest(&prefix));
            assert!(
                parse_volatile_state_blob(
                    &prefix,
                    &[],
                    SeedTie {
                        ep_seed: &seeds.0,
                        sp_seed: &seeds.1,
                        pp_seed: &seeds.2,
                    },
                    &host_clock(),
                    StateFormatLimit::CURRENT,
                )
                .is_err(),
                "prefix length {len} decoded"
            );
        }
    }

    #[test]
    fn single_byte_corruptions_of_a_produced_blob_never_panic() {
        let runtime = restored_from_c_fixture();
        let blob = store(&runtime);
        let seeds = runtime_seed_tie(&runtime);
        for index in (0..blob.len()).step_by(11) {
            for byte in [0x00u8, 0x01, 0xff] {
                let mut corrupted = blob.clone();
                corrupted[index] = byte;
                let _ = parse_volatile_state_blob(
                    &corrupted,
                    &[],
                    SeedTie {
                        ep_seed: &seeds.0,
                        sp_seed: &seeds.1,
                        pp_seed: &seeds.2,
                    },
                    &host_clock(),
                    StateFormatLimit::CURRENT,
                );
            }
        }
    }
}
