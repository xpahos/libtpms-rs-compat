use crate::ffi::types::TpmResult;
use crate::library::constants::{TPM_RC_HANDLE, TPM_RC_INSUFFICIENT, TPM_RC_SIZE, TPM_RC_VALUE};
use crate::library::tpm2::command::core::dispatcher::CommandFrame;
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::hierarchy::TPM_RH_UNASSIGNED;
use crate::library::tpm2::marshal::BlobReader;
use crate::library::tpm2::object_create::{is_transient_object_handle, occupied_object_slot};
use crate::library::tpm2::persistent::{OwnedAnyObject, OwnedAnyObjectBody};
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::session::{
    flush_session, is_session_handle, session_is_loaded, session_is_saved,
};

const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;

const RC_FLUSH_HANDLE: TpmResult = TPM_RC_P + TPM_RC_1;

enum Target {
    Object(usize),
    Session(u32),
}

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let flush_handle = parse_parameters(frame.parameters)?;
    match resolve(runtime, flush_handle)? {
        Target::Object(slot) => flush_object(runtime, slot),
        Target::Session(handle) => flush_loaded_or_saved_session(runtime, handle),
    }
    Ok(CommandOutput::empty())
}

fn parse_parameters(parameters: &[u8]) -> Result<u32, TpmResult> {
    let mut reader = BlobReader::new(parameters);
    let flush_handle = reader
        .read_u32()
        .map_err(|_| TPM_RC_INSUFFICIENT + RC_FLUSH_HANDLE)?;
    if !is_transient_object_handle(flush_handle) && !is_session_handle(flush_handle) {
        return Err(TPM_RC_VALUE + RC_FLUSH_HANDLE);
    }
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(flush_handle)
}

fn resolve(runtime: &Tpm2Runtime, flush_handle: u32) -> Result<Target, TpmResult> {
    if is_transient_object_handle(flush_handle) {
        return occupied_object_slot(runtime, flush_handle)
            .map(Target::Object)
            .ok_or(TPM_RC_HANDLE + RC_FLUSH_HANDLE);
    }
    if session_is_loaded(&runtime.live, flush_handle)
        || session_is_saved(&runtime.live, flush_handle)
    {
        return Ok(Target::Session(flush_handle));
    }
    Err(TPM_RC_HANDLE + RC_FLUSH_HANDLE)
}

fn flush_object(runtime: &mut Tpm2Runtime, slot: usize) {
    if let Some(object) = runtime.live.objects.get_mut(slot) {
        *object = OwnedAnyObject {
            attributes: 0,
            body: OwnedAnyObjectBody::Unoccupied,
        };
    }
}

fn flush_loaded_or_saved_session(runtime: &mut Tpm2Runtime, handle: u32) {
    if let Some(restored) = runtime.restored_volatile.as_mut()
        && restored.exclusive_audit_session == handle
    {
        restored.exclusive_audit_session = TPM_RH_UNASSIGNED;
    }
    flush_session(&mut runtime.live, handle);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::CommandInput;
    use crate::library::tpm2::capability::handles::test_state::{load_session, save_session};
    use crate::library::tpm2::clock::RecordingClock;
    use crate::library::tpm2::command::core::dispatcher::dispatch;
    use crate::library::tpm2::command::core::header::{parse_command, serialize_response};
    use crate::library::tpm2::command::core::registry::TPM_CC_FLUSH_CONTEXT;
    use crate::library::tpm2::command::session::processing::TPM_RS_PW;
    use crate::library::tpm2::golden_responses::flush_context::vector;
    use crate::library::tpm2::live::RestoredVolatile;
    use crate::library::tpm2::manufacture::manufacture_state;
    use crate::library::tpm2::object::ATTR_OCCUPIED;
    use crate::library::tpm2::persistent::{OwnedUserNvramEntry, persistent_all_store};
    use crate::library::tpm2::profile::validate_user_profile;
    use crate::library::tpm2::restore_permanent_blob_for_test;
    use crate::library::tpm2::runtime::commit_manufactured_state;
    use crate::library::tpm2::session::NO_OLDEST_SAVED_SESSION;
    use crate::library::tpm2::state::MAX_ACTIVE_SESSIONS;
    use crate::library::tpm2::volatile::volatile_all_store;
    use crate::library::tpm2::volatile::{MAX_LOADED_OBJECTS, MAX_LOADED_SESSIONS};

    const TPM_CC_CREATE_PRIMARY: u32 = 0x0000_0131;
    const TPM_CC_EVICT_CONTROL: u32 = 0x0000_0120;
    const TPM_CC_GET_CAPABILITY: u32 = 0x0000_017a;

    const RC_SUCCESS: u32 = 0x000;

    const STORAGE_ATTRIBUTES: u32 = 0x0003_0072;
    const OWNER_HANDLE: u32 = 0x4000_0001;
    const PLATFORM_HANDLE: u32 = 0x4000_000c;
    const SPK_PERSISTENT_HANDLE: u32 = 0x8100_0000;

    const HMAC_SESSION_0: u32 = 0x0200_0000;
    const POLICY_SESSION_1: u32 = 0x0300_0001;
    const HMAC_SESSION_2: u32 = 0x0200_0002;

    const SAVED_CONTEXT_ID: u16 = MAX_LOADED_SESSIONS as u16 + 1;

    fn hex(value: &str) -> Vec<u8> {
        let digits: String = value.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(digits.len().is_multiple_of(2));
        (0..digits.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&digits[at..at + 2], 16).expect("hex digits"))
            .collect()
    }

    fn deterministic_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
        let len = buffer.len() as u8;
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_add(len) ^ 0x55;
        }
        Ok(())
    }

    #[track_caller]
    fn dispatch_bytes(runtime: &mut Tpm2Runtime, bytes: &[u8]) -> Vec<u8> {
        let input = CommandInput::new(bytes.len() as u32, bytes.to_vec());
        let parsed = parse_command(&input).expect("the header parses");
        serialize_response(&dispatch(runtime, &parsed)).expect("the response serializes")
    }

    #[track_caller]
    fn start(runtime: &mut Tpm2Runtime) {
        assert_eq!(
            dispatch_bytes(runtime, &hex("80010000000c0000014400 00")),
            hex("80010000000a00000000")
        );
        runtime.nv_update_pending = false;
    }

    fn manufactured_runtime() -> Box<Tpm2Runtime> {
        let profile = validate_user_profile(None).expect("the null profile validates");
        let state = manufacture_state(profile, deterministic_entropy).expect("manufactures");
        let mut runtime = commit_manufactured_state(state).expect("commits");
        runtime.entropy = deterministic_entropy;
        runtime
    }

    #[track_caller]
    fn started_runtime() -> Box<Tpm2Runtime> {
        let mut runtime = manufactured_runtime();
        start(&mut runtime);
        runtime
    }

    #[track_caller]
    fn oracle_runtime() -> Box<Tpm2Runtime> {
        let mut runtime = restore_permanent_blob_for_test(vector("PERMALL"))
            .expect("the oracle permanent state restores");
        start(&mut runtime);
        runtime
    }

    fn pw_session(password: &[u8]) -> Vec<u8> {
        let mut out = TPM_RS_PW.to_be_bytes().to_vec();
        out.extend_from_slice(&0u16.to_be_bytes());
        out.push(0x00);
        out.extend_from_slice(&(password.len() as u16).to_be_bytes());
        out.extend_from_slice(password);
        out
    }

    fn framed(code: u32, payload: &[u8], sessions: bool) -> Vec<u8> {
        let tag: u16 = if sessions { 0x8002 } else { 0x8001 };
        let mut out = tag.to_be_bytes().to_vec();
        out.extend_from_slice(&(10 + payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&code.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn flush_command(parameters: &[u8]) -> Vec<u8> {
        framed(TPM_CC_FLUSH_CONTEXT, parameters, false)
    }

    #[track_caller]
    fn flush(runtime: &mut Tpm2Runtime, handle: u32) -> Vec<u8> {
        dispatch_bytes(runtime, &flush_command(&handle.to_be_bytes()))
    }

    fn capability_command(capability: u32, property: u32, count: u32) -> Vec<u8> {
        let mut payload = capability.to_be_bytes().to_vec();
        payload.extend_from_slice(&property.to_be_bytes());
        payload.extend_from_slice(&count.to_be_bytes());
        framed(TPM_CC_GET_CAPABILITY, &payload, false)
    }

    #[track_caller]
    fn capability(
        runtime: &mut Tpm2Runtime,
        capability: u32,
        property: u32,
        count: u32,
    ) -> Vec<u8> {
        dispatch_bytes(runtime, &capability_command(capability, property, count))
    }

    fn symcipher_template(attributes: u32) -> Vec<u8> {
        let mut out = 0x0025u16.to_be_bytes().to_vec();
        out.extend_from_slice(&0x000bu16.to_be_bytes());
        out.extend_from_slice(&attributes.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0x0006u16.to_be_bytes());
        out.extend_from_slice(&0x0080u16.to_be_bytes());
        out.extend_from_slice(&0x0043u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out
    }

    fn create_primary_command(hierarchy: u32) -> Vec<u8> {
        let template = symcipher_template(STORAGE_ATTRIBUTES);
        let mut parameters = Vec::new();
        parameters.extend_from_slice(&4u16.to_be_bytes());
        parameters.extend_from_slice(&0u16.to_be_bytes());
        parameters.extend_from_slice(&0u16.to_be_bytes());
        parameters.extend_from_slice(&(template.len() as u16).to_be_bytes());
        parameters.extend_from_slice(&template);
        parameters.extend_from_slice(&0u16.to_be_bytes());
        parameters.extend_from_slice(&0u32.to_be_bytes());

        let session = pw_session(&[]);
        let mut payload = hierarchy.to_be_bytes().to_vec();
        payload.extend_from_slice(&(session.len() as u32).to_be_bytes());
        payload.extend_from_slice(&session);
        payload.extend_from_slice(&parameters);
        framed(TPM_CC_CREATE_PRIMARY, &payload, true)
    }

    #[track_caller]
    fn create_primary(runtime: &mut Tpm2Runtime, hierarchy: u32) -> (u32, Vec<u8>) {
        let response = dispatch_bytes(runtime, &create_primary_command(hierarchy));
        assert_eq!(
            response_code(&response),
            RC_SUCCESS,
            "the primary is created"
        );
        let handle = u32::from_be_bytes(response[10..14].try_into().expect("a response handle"));
        (handle, response)
    }

    #[track_caller]
    fn evict(runtime: &mut Tpm2Runtime, object: u32, persistent: u32) -> Vec<u8> {
        let session = pw_session(&[]);
        let mut payload = OWNER_HANDLE.to_be_bytes().to_vec();
        payload.extend_from_slice(&object.to_be_bytes());
        payload.extend_from_slice(&(session.len() as u32).to_be_bytes());
        payload.extend_from_slice(&session);
        payload.extend_from_slice(&persistent.to_be_bytes());
        dispatch_bytes(runtime, &framed(TPM_CC_EVICT_CONTROL, &payload, true))
    }

    fn response_code(response: &[u8]) -> u32 {
        u32::from_be_bytes(response[6..10].try_into().expect("a response code"))
    }

    #[track_caller]
    fn assert_matches_oracle(runtime: &Tpm2Runtime, expected: &str, label: &str) {
        let actual = persistent_all_store(runtime.state()).expect("the state serializes");
        let oracle = vector(expected);
        assert_eq!(actual.len(), oracle.len(), "{label} blob length");
        let divergence: Vec<usize> = (0..actual.len())
            .filter(|&index| actual[index] != oracle[index])
            .collect();
        assert_eq!(
            divergence,
            Vec::<usize>::new(),
            "{label} diverges from the oracle"
        );
    }

    fn test_clock() -> RecordingClock {
        RecordingClock::new(1_700_000_100_000, 4_000_000)
    }

    #[derive(Debug, Eq, PartialEq)]
    struct Snapshot {
        permanent: Vec<u8>,
        volatile: Vec<u8>,
        nv_memory: Box<[u8]>,
        nv_update_pending: bool,
    }

    fn snapshot(runtime: &Tpm2Runtime) -> Snapshot {
        Snapshot {
            permanent: persistent_all_store(runtime.state()).expect("the state serializes"),
            volatile: volatile_all_store(runtime, &test_clock()).expect("the volatile serializes"),
            nv_memory: runtime.nv_memory.clone(),
            nv_update_pending: runtime.nv_update_pending,
        }
    }

    #[track_caller]
    fn assert_unchanged(runtime: &Tpm2Runtime, before: &Snapshot) {
        assert_eq!(snapshot(runtime), *before);
    }

    fn occupied_slots(runtime: &Tpm2Runtime) -> Vec<usize> {
        runtime
            .live
            .objects
            .iter()
            .enumerate()
            .filter(|(_, object)| object.attributes & ATTR_OCCUPIED != 0)
            .map(|(slot, _)| slot)
            .collect()
    }

    fn nvram_handles(runtime: &Tpm2Runtime) -> Vec<u32> {
        runtime
            .state()
            .user_nvram
            .entries
            .iter()
            .map(|entry| match entry {
                OwnedUserNvramEntry::NvIndex { handle, .. }
                | OwnedUserNvramEntry::Persistent { handle, .. } => *handle,
            })
            .collect()
    }

    fn context_array(runtime: &Tpm2Runtime) -> Vec<u16> {
        runtime
            .live
            .state_reset
            .as_ref()
            .expect("state reset present")
            .context_array
            .to_vec()
    }

    fn drbg_state(runtime: &Tpm2Runtime) -> (u64, u32, Vec<u8>, Vec<u32>) {
        let drbg = &runtime.live.orderly.drbg_state;
        (
            drbg.reseed_counter,
            drbg.drbg_magic,
            drbg.seed.expose().to_vec(),
            drbg.last_value.to_vec(),
        )
    }

    fn pcr_banks(runtime: &Tpm2Runtime) -> Vec<Vec<Option<Vec<u8>>>> {
        runtime
            .live
            .pcrs
            .iter()
            .map(|pcr| pcr.banks.to_vec())
            .collect()
    }

    fn context_save(runtime: &mut Tpm2Runtime, context_slot: usize, ram_slot: usize) {
        save_session(runtime, context_slot, SAVED_CONTEXT_ID);
        runtime.live.sessions[ram_slot].occupied = false;
        runtime.live.sessions[ram_slot].session = None;
        runtime.live.free_session_slots += 1;
        runtime.live.oldest_saved_session = context_slot as u32;
    }

    fn three_loaded_sessions(runtime: &mut Tpm2Runtime) {
        load_session(runtime, 0, 0, false);
        load_session(runtime, 1, 1, true);
        load_session(runtime, 2, 2, false);
        runtime.live.free_session_slots = 0;
    }

    fn set_exclusive_audit(runtime: &mut Tpm2Runtime, handle: u32) {
        let restored = runtime
            .restored_volatile
            .get_or_insert_with(RestoredVolatile::power_on);
        restored.exclusive_audit_session = handle;
    }

    fn exclusive_audit(runtime: &Tpm2Runtime) -> Vec<u8> {
        runtime
            .restored_volatile
            .as_ref()
            .expect("a restored volatile carry")
            .exclusive_audit_session
            .to_be_bytes()
            .to_vec()
    }

    #[test]
    fn the_command_is_advertised_with_the_oracle_attributes() {
        let mut runtime = started_runtime();
        assert_eq!(
            capability(&mut runtime, 2, TPM_CC_FLUSH_CONTEXT, 1),
            vector("CAP_COMMANDS_RESPONSE")
        );
    }

    #[test]
    fn the_command_is_rejected_before_startup() {
        let mut runtime = manufactured_runtime();
        assert_eq!(
            flush(&mut runtime, 0x8000_0000),
            vector("BEFORE_STARTUP_RESPONSE")
        );
    }

    #[test]
    fn a_session_tagged_request_is_rejected() {
        let mut runtime = started_runtime();
        let session = pw_session(&[]);
        let mut payload = (session.len() as u32).to_be_bytes().to_vec();
        payload.extend_from_slice(&session);
        payload.extend_from_slice(&0x8000_0000u32.to_be_bytes());
        assert_eq!(
            dispatch_bytes(&mut runtime, &framed(TPM_CC_FLUSH_CONTEXT, &payload, true)),
            vector("SESSION_TAGGED_RESPONSE")
        );
    }

    #[test]
    fn a_truncated_flush_handle_is_an_indexed_parameter_error() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(&mut runtime, &flush_command(&[])),
            vector("NO_PARAMETERS_RESPONSE")
        );
        for length in 1..4usize {
            assert_eq!(
                dispatch_bytes(&mut runtime, &flush_command(&[0x80, 0x00, 0x00][..length])),
                vector("TRUNCATED_RESPONSE"),
                "{length} of four bytes"
            );
        }
    }

    #[test]
    fn trailing_parameter_bytes_are_a_size_error() {
        let mut runtime = started_runtime();
        for extra in 1..5usize {
            let mut parameters = 0x8000_0000u32.to_be_bytes().to_vec();
            parameters.extend_from_slice(&vec![0u8; extra]);
            assert_eq!(
                dispatch_bytes(&mut runtime, &flush_command(&parameters)),
                vector("TRAILING_RESPONSE"),
                "{extra} trailing bytes"
            );
        }
    }

    #[test]
    fn handles_of_unsupported_types_are_rejected_by_the_unmarshaller() {
        let mut runtime = started_runtime();
        for handle in [
            0x0000_0000u32,
            0x0000_0017,
            0x0100_0000,
            0x01ff_ffff,
            0x0200_0000 + MAX_ACTIVE_SESSIONS as u32,
            0x02ff_ffff,
            0x0300_0000 + MAX_ACTIVE_SESSIONS as u32,
            0x03ff_ffff,
            OWNER_HANDLE,
            0x4000_0007,
            PLATFORM_HANDLE,
            0x8000_0000 + MAX_LOADED_OBJECTS as u32,
            0x8000_ffff,
            0x8100_0000,
            0x8180_0000,
            0x81ff_ffff,
            u32::MAX,
        ] {
            assert_eq!(
                flush(&mut runtime, handle),
                vector("BAD_HANDLE_RESPONSE"),
                "handle {handle:#010x}"
            );
        }
    }

    #[test]
    fn an_unloaded_transient_handle_is_a_decorated_handle_error() {
        let mut runtime = started_runtime();
        for slot in 0..MAX_LOADED_OBJECTS as u32 {
            assert_eq!(
                flush(&mut runtime, 0x8000_0000 + slot),
                vector("ABSENT_TRANSIENT_RESPONSE"),
                "slot {slot}"
            );
        }
    }

    #[test]
    fn an_unknown_session_is_a_decorated_handle_error() {
        let mut runtime = started_runtime();
        for slot in [0u32, 21, 42, 63] {
            assert_eq!(
                flush(&mut runtime, 0x0200_0000 + slot),
                vector("ABSENT_HMAC_RESPONSE"),
                "hmac slot {slot}"
            );
            assert_eq!(
                flush(&mut runtime, 0x0300_0000 + slot),
                vector("ABSENT_POLICY_RESPONSE"),
                "policy slot {slot}"
            );
        }
    }

    #[test]
    fn a_loaded_transient_object_is_flushed_and_its_slot_is_reused() {
        let mut runtime = oracle_runtime();
        let (owner, owner_response) = create_primary(&mut runtime, OWNER_HANDLE);
        let (platform, platform_response) = create_primary(&mut runtime, PLATFORM_HANDLE);
        assert_eq!(owner_response, vector("OWNER_PRIMARY_RESPONSE"));
        assert_eq!(platform_response, vector("PLATFORM_PRIMARY_RESPONSE"));
        assert_eq!(owner, 0x8000_0000);
        assert_eq!(platform, 0x8000_0001);
        assert_eq!(
            capability(&mut runtime, 1, 0x8000_0000, 8),
            vector("CAP_TRANSIENT_TWO")
        );

        assert_eq!(flush(&mut runtime, owner), vector("SUCCESS_RESPONSE"));
        assert_eq!(occupied_slots(&runtime), [1]);
        assert!(matches!(
            runtime.live.objects[0].body,
            OwnedAnyObjectBody::Unoccupied
        ));
        assert_eq!(runtime.live.objects[0].attributes, 0);
        assert_eq!(
            capability(&mut runtime, 1, 0x8000_0000, 8),
            vector("CAP_TRANSIENT_ONE")
        );
        assert_eq!(
            flush(&mut runtime, owner),
            vector("ABSENT_TRANSIENT_RESPONSE"),
            "the slot is empty again"
        );

        let (reused, reused_response) = create_primary(&mut runtime, OWNER_HANDLE);
        assert_eq!(reused, owner, "the freed slot is handed out again");
        assert_eq!(reused_response, vector("REUSED_PRIMARY_RESPONSE"));

        assert_eq!(flush(&mut runtime, reused), vector("SUCCESS_RESPONSE"));
        assert_eq!(flush(&mut runtime, platform), vector("SUCCESS_RESPONSE"));
        assert_eq!(
            capability(&mut runtime, 1, 0x8000_0000, 8),
            vector("CAP_TRANSIENT_NONE")
        );
        assert!(occupied_slots(&runtime).is_empty());
    }

    #[test]
    fn flushing_a_transient_object_never_touches_nv_state() {
        let mut runtime = oracle_runtime();
        assert_matches_oracle(&runtime, "PERMALL_STARTED", "startup");
        let (owner, _) = create_primary(&mut runtime, OWNER_HANDLE);
        let before = snapshot(&runtime);
        assert_eq!(flush(&mut runtime, owner), vector("SUCCESS_RESPONSE"));
        assert_matches_oracle(&runtime, "PERMALL_STARTED", "after the flush");
        assert_eq!(runtime.nv_memory, before.nv_memory);
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn the_create_spk_flow_flushes_the_transient_copy_and_keeps_the_evict_object() {
        let mut runtime = oracle_runtime();
        let (spk, spk_response) = create_primary(&mut runtime, OWNER_HANDLE);
        assert_eq!(spk_response, vector("SPK_PRIMARY_RESPONSE"));
        assert_eq!(
            evict(&mut runtime, spk, SPK_PERSISTENT_HANDLE),
            vector("EVICT_SPK_RESPONSE")
        );
        assert_matches_oracle(&runtime, "PERMALL_SPK_PERSISTED", "the persisted SPK");
        assert_eq!(
            capability(&mut runtime, 1, 0x8100_0000, 8),
            vector("CAP_PERSISTENT_SPK")
        );

        runtime.nv_update_pending = false;
        assert_eq!(flush(&mut runtime, spk), vector("SUCCESS_RESPONSE"));
        assert_matches_oracle(&runtime, "PERMALL_AFTER_SPK_FLUSH", "the flushed SPK");
        assert!(!runtime.nv_update_pending);
        assert_eq!(
            capability(&mut runtime, 1, 0x8000_0000, 8),
            vector("CAP_TRANSIENT_NONE")
        );
        assert_eq!(
            capability(&mut runtime, 1, 0x8100_0000, 8),
            vector("CAP_PERSISTENT_AFTER_FLUSH")
        );
        assert_eq!(nvram_handles(&runtime), [SPK_PERSISTENT_HANDLE]);
    }

    #[test]
    fn loaded_sessions_are_flushed_and_disappear_from_capability_reporting() {
        let mut runtime = started_runtime();
        three_loaded_sessions(&mut runtime);
        assert_eq!(
            capability(&mut runtime, 1, 0x0200_0000, 8),
            vector("CAP_LOADED_THREE")
        );

        assert_eq!(
            flush(&mut runtime, HMAC_SESSION_0),
            vector("SUCCESS_RESPONSE")
        );
        assert_eq!(runtime.live.free_session_slots, 1);
        assert!(!runtime.live.sessions[0].occupied);
        assert!(runtime.live.sessions[0].session.is_none());
        assert_eq!(context_array(&runtime)[0], 0);
        assert_eq!(
            capability(&mut runtime, 1, 0x0200_0000, 8),
            vector("CAP_LOADED_TWO")
        );
        assert_eq!(
            flush(&mut runtime, HMAC_SESSION_0),
            vector("ABSENT_HMAC_RESPONSE")
        );

        assert_eq!(
            flush(&mut runtime, POLICY_SESSION_1),
            vector("SUCCESS_RESPONSE")
        );
        assert_eq!(runtime.live.free_session_slots, 2);
        assert_eq!(
            capability(&mut runtime, 1, 0x0200_0000, 8),
            vector("CAP_LOADED_ONE")
        );
        assert!(runtime.live.sessions[2].occupied, "the third is untouched");
    }

    #[test]
    fn saved_sessions_are_flushed_through_the_context_slot() {
        let mut runtime = started_runtime();
        three_loaded_sessions(&mut runtime);
        context_save(&mut runtime, 2, 2);
        assert_eq!(
            capability(&mut runtime, 1, 0x0300_0000, 8),
            vector("CAP_SAVED_ONE")
        );

        assert_eq!(
            flush(&mut runtime, HMAC_SESSION_2),
            vector("SUCCESS_RESPONSE")
        );
        assert_eq!(context_array(&runtime)[2], 0);
        assert_eq!(runtime.live.oldest_saved_session, NO_OLDEST_SAVED_SESSION);
        assert_eq!(
            runtime.live.free_session_slots, 1,
            "a saved session owns no RAM slot"
        );
        assert_eq!(
            capability(&mut runtime, 1, 0x0300_0000, 8),
            vector("CAP_SAVED_NONE")
        );
        assert_eq!(
            flush(&mut runtime, HMAC_SESSION_2),
            vector("ABSENT_HMAC_RESPONSE")
        );
        assert!(runtime.live.sessions[0].occupied, "the first is untouched");
        assert!(runtime.live.sessions[1].occupied, "the second is untouched");
    }

    #[test]
    fn a_saved_policy_session_is_flushed_through_the_same_path() {
        let mut runtime = started_runtime();
        load_session(&mut runtime, 0, 0, true);
        runtime.live.free_session_slots = MAX_LOADED_SESSIONS as u32 - 1;
        context_save(&mut runtime, 0, 0);
        assert_eq!(
            flush(&mut runtime, POLICY_SESSION_1 - 1),
            vector("SUCCESS_RESPONSE")
        );
        assert_eq!(context_array(&runtime)[0], 0);
        assert_eq!(runtime.live.oldest_saved_session, NO_OLDEST_SAVED_SESSION);
    }

    #[test]
    fn flushing_the_oldest_saved_session_rescans_the_context_array() {
        let mut runtime = started_runtime();
        {
            let reset = runtime
                .live
                .state_reset
                .as_mut()
                .expect("state reset present");
            reset.context_counter = 0x37;
            reset.context_array[4] = 0x0b + 0x37;
            reset.context_array[6] = 0x02 + 0x37;
            reset.context_array[7] = 0x08 + 0x37;
        }
        runtime.live.oldest_saved_session = 6;
        assert_eq!(flush(&mut runtime, 0x0200_0006), vector("SUCCESS_RESPONSE"));
        assert_eq!(
            runtime.live.oldest_saved_session, 7,
            "the smallest remaining age wins"
        );
        assert_eq!(flush(&mut runtime, 0x0200_0007), vector("SUCCESS_RESPONSE"));
        assert_eq!(runtime.live.oldest_saved_session, 4);
        assert_eq!(flush(&mut runtime, 0x0200_0004), vector("SUCCESS_RESPONSE"));
        assert_eq!(runtime.live.oldest_saved_session, NO_OLDEST_SAVED_SESSION);
    }

    #[test]
    fn flushing_a_younger_saved_session_leaves_the_oldest_alone() {
        let mut runtime = started_runtime();
        {
            let reset = runtime
                .live
                .state_reset
                .as_mut()
                .expect("state reset present");
            reset.context_counter = 0x37;
            reset.context_array[4] = 0x0b + 0x37;
            reset.context_array[6] = 0x02 + 0x37;
        }
        runtime.live.oldest_saved_session = 4;
        assert_eq!(flush(&mut runtime, 0x0200_0006), vector("SUCCESS_RESPONSE"));
        assert_eq!(runtime.live.oldest_saved_session, 4);
    }

    #[test]
    fn the_exclusive_audit_session_is_reset_only_when_it_is_itself_flushed() {
        let mut runtime = started_runtime();
        three_loaded_sessions(&mut runtime);
        set_exclusive_audit(
            &mut runtime,
            u32::from_be_bytes(
                vector("EXCLUSIVE_AUDIT_SET")
                    .try_into()
                    .expect("a four-byte handle"),
            ),
        );

        assert_eq!(
            flush(&mut runtime, POLICY_SESSION_1),
            vector("SUCCESS_RESPONSE")
        );
        assert_eq!(exclusive_audit(&runtime), vector("EXCLUSIVE_AUDIT_KEPT"));

        assert_eq!(
            flush(&mut runtime, HMAC_SESSION_0),
            vector("SUCCESS_RESPONSE")
        );
        assert_eq!(exclusive_audit(&runtime), vector("EXCLUSIVE_AUDIT_CLEARED"));
    }

    #[test]
    fn a_flush_without_an_exclusive_audit_session_leaves_the_field_unassigned() {
        let mut runtime = started_runtime();
        three_loaded_sessions(&mut runtime);
        set_exclusive_audit(
            &mut runtime,
            u32::from_be_bytes(
                vector("EXCLUSIVE_AUDIT_UNSET")
                    .try_into()
                    .expect("a four-byte handle"),
            ),
        );
        assert_eq!(
            flush(&mut runtime, HMAC_SESSION_0),
            vector("SUCCESS_RESPONSE")
        );
        assert_eq!(exclusive_audit(&runtime), vector("EXCLUSIVE_AUDIT_UNSET"));
    }

    #[test]
    fn every_rejected_request_leaves_the_whole_tpm_untouched() {
        let mut runtime = oracle_runtime();
        let (owner, _) = create_primary(&mut runtime, OWNER_HANDLE);
        evict(&mut runtime, owner, SPK_PERSISTENT_HANDLE);
        create_primary(&mut runtime, PLATFORM_HANDLE);
        three_loaded_sessions(&mut runtime);
        context_save(&mut runtime, 2, 2);
        set_exclusive_audit(&mut runtime, HMAC_SESSION_0);

        let before = snapshot(&runtime);
        let audit_before = exclusive_audit(&runtime);
        for parameters in [
            Vec::new(),
            vec![0x80],
            vec![0x80, 0x00, 0x00],
            hex("80000000 00"),
            hex("40000001"),
            hex("81000000"),
            hex("00000000"),
            hex("80000002"),
            hex("02000005"),
            hex("03000005"),
        ] {
            let response = dispatch_bytes(&mut runtime, &flush_command(&parameters));
            assert_ne!(
                response_code(&response),
                RC_SUCCESS,
                "parameters {parameters:02x?}"
            );
            assert_unchanged(&runtime, &before);
            assert_eq!(exclusive_audit(&runtime), audit_before);
        }
    }

    #[test]
    fn a_successful_flush_leaves_the_rest_of_the_tpm_alone() {
        let mut runtime = oracle_runtime();
        let (persisted, _) = create_primary(&mut runtime, OWNER_HANDLE);
        evict(&mut runtime, persisted, SPK_PERSISTENT_HANDLE);
        let (survivor, survivor_response) = create_primary(&mut runtime, PLATFORM_HANDLE);
        three_loaded_sessions(&mut runtime);
        runtime.nv_update_pending = true;

        let permanent_before = persistent_all_store(runtime.state()).expect("serializes");
        let nv_before = runtime.nv_memory.clone();
        let pcrs_before = pcr_banks(&runtime);
        let drbg_before = drbg_state(&runtime);
        let orderly_before = runtime.state().persistent.orderly_state;
        let handles_before = nvram_handles(&runtime);
        let survivor_object = runtime.live.objects[1].clone();

        assert_eq!(flush(&mut runtime, persisted), vector("SUCCESS_RESPONSE"));
        assert_eq!(
            flush(&mut runtime, HMAC_SESSION_0),
            vector("SUCCESS_RESPONSE")
        );

        assert_eq!(
            persistent_all_store(runtime.state()).expect("serializes"),
            permanent_before,
            "the permanent state is untouched"
        );
        assert_eq!(runtime.nv_memory, nv_before, "NV memory is untouched");
        assert!(
            runtime.nv_update_pending,
            "a pending NV write is neither dropped nor completed"
        );
        assert_eq!(pcr_banks(&runtime), pcrs_before, "PCR state is untouched");
        assert_eq!(drbg_state(&runtime), drbg_before, "the DRBG is untouched");
        assert_eq!(
            runtime.state().persistent.orderly_state,
            orderly_before,
            "the orderly state is untouched"
        );
        assert_eq!(nvram_handles(&runtime), handles_before);
        assert_eq!(handles_before, [SPK_PERSISTENT_HANDLE]);

        assert_eq!(occupied_slots(&runtime), [1], "only the survivor is loaded");
        assert_eq!(
            runtime.live.objects[1].attributes,
            survivor_object.attributes
        );
        assert_eq!(
            capability(&mut runtime, 1, 0x8000_0000, 8),
            vector("CAP_TRANSIENT_ONE")
        );
        assert_eq!(survivor, 0x8000_0001);
        assert!(!survivor_response.is_empty());

        assert!(!runtime.live.sessions[0].occupied);
        assert!(runtime.live.sessions[1].occupied);
        assert!(runtime.live.sessions[2].occupied);
        assert_eq!(context_array(&runtime)[1], 2);
        assert_eq!(context_array(&runtime)[2], 3);
    }
}
