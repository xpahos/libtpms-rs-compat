use crate::ffi::types::TpmResult;
use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_SEQUENCE, TPM_RC_SIZE};
use crate::library::tpm2::command::core::dispatcher::{CommandFrame, handle_at};
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::marshal::BlobWriter;
use crate::library::tpm2::object_create::resolve_any_object;
use crate::library::tpm2::persistent::OwnedAnyObjectBody;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::sequence::sequence_kind;
use crate::library::tpm2::template::marshal_public_area;
pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let object_handle = handle_at(frame, 0)?;
    if !frame.parameters.is_empty() {
        return Err(TPM_RC_SIZE);
    }
    let object = resolve_any_object(runtime, object_handle).ok_or(TPM_RC_FAILURE)?;
    if sequence_kind(object.attributes).is_some() {
        return Err(TPM_RC_SEQUENCE);
    }
    let OwnedAnyObjectBody::Object(body) = &object.body else {
        return Err(TPM_RC_FAILURE);
    };
    let public = marshal_public_area(&body.public)?;
    let mut writer = BlobWriter::new();
    writer.write_tpm2b(&public).map_err(|_| TPM_RC_SIZE)?;
    writer.write_tpm2b(&body.name).map_err(|_| TPM_RC_SIZE)?;
    writer
        .write_tpm2b(&body.qualified_name)
        .map_err(|_| TPM_RC_SIZE)?;
    Ok(CommandOutput::from_parameters(writer.into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::command::core::registry::{
        CommandLifecycle, HandleKind, NvAccess, TPM_CC_READ_PUBLIC, find,
    };
    use crate::library::tpm2::command::core::test_support::{
        RC_SUCCESS, command, dispatch_bytes, framed, response_code,
    };
    use crate::library::tpm2::golden_responses::read_public_verify_signature::vector;
    use crate::library::tpm2::object::{ATTR_EVICT, ATTR_OCCUPIED};
    use crate::library::tpm2::{attach_volatile_blob_for_test, restore_permanent_blob_for_test};

    const TPM_CC: u32 = 0x0000_0173;

    #[track_caller]
    fn restored(snapshot: &str) -> Box<Tpm2Runtime> {
        let mut runtime = restore_permanent_blob_for_test(vector(&format!("PERMALL_{snapshot}")))
            .expect("the oracle permanent state restores");
        attach_volatile_blob_for_test(&mut runtime, vector(&format!("VOLATILE_{snapshot}")))
            .expect("the oracle volatile state attaches");
        assert!(
            runtime.startup_received,
            "the snapshot is past TPM2_Startup"
        );
        runtime
    }

    #[track_caller]
    fn read_public(runtime: &mut Tpm2Runtime, handle: u32) -> Vec<u8> {
        dispatch_bytes(runtime, &command(TPM_CC, &[handle], &[], &[]))
    }

    #[track_caller]
    fn assert_matches_oracle(snapshot: &str, record: &str, handle: u32) {
        let mut runtime = restored(snapshot);
        assert_eq!(
            read_public(&mut runtime, handle),
            vector(record),
            "{record} from {snapshot}"
        );
    }

    #[test]
    fn the_command_attributes_match_the_oracle() {
        let expected = vector("CCATTR_0173");
        let attributes = u32::from_be_bytes(expected[19..23].try_into().unwrap());
        assert_eq!(TPM_CC_READ_PUBLIC, TPM_CC);
        let descriptor = find(TPM_CC_READ_PUBLIC).expect("a registered command");
        assert_eq!(descriptor.attributes, attributes);
        assert_eq!(descriptor.attributes, 0x0200_0173);
        assert_eq!(
            descriptor.attributes & (1 << 22),
            0,
            "TPM2_ReadPublic does not use NV"
        );
        assert_eq!(descriptor.attributes & (1 << 28), 0, "no response handle");
        assert_eq!((descriptor.attributes >> 25) & 0x7, 1, "one command handle");
        assert!(!descriptor.physical_presence);
        assert!(descriptor.sessions_allowed);
        assert!(matches!(descriptor.nv_access, NvAccess::Neither));
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
    }

    #[test]
    fn the_object_handle_needs_no_authorization() {
        let descriptor = find(TPM_CC_READ_PUBLIC).expect("a registered command");
        assert_eq!(descriptor.handles.len(), 1);
        assert!(
            !descriptor.handles[0].user_auth,
            "upstream declares no HANDLE_1_USER for TPM2_ReadPublic"
        );
        assert!(!descriptor.handles[0].admin_role());
        assert!(matches!(descriptor.handles[0].kind, HandleKind::Object));
    }

    #[test]
    fn every_public_area_matches_the_oracle() {
        for (snapshot, record, handle) in [
            ("KEYS", "READPUBLIC_RSASSA", 0x8000_0000),
            ("KEYS", "READPUBLIC_ECDSA", 0x8000_0001),
            ("HMAC_KEYS", "READPUBLIC_HMAC_SHA256", 0x8000_0000),
            ("HMAC_KEYS", "READPUBLIC_HMAC_SHA384", 0x8000_0002),
            ("HMAC_SHA512", "READPUBLIC_HMAC_SHA512", 0x8000_0000),
            ("ALT_KEYS", "READPUBLIC_ECSCHNORR", 0x8000_0000),
            ("ALT_KEYS", "READPUBLIC_ECC_NULL_SCHEME", 0x8000_0001),
            ("ALT_KEYS", "READPUBLIC_RSAPSS", 0x8000_0002),
            ("MISC_KEYS", "READPUBLIC_STORAGE", 0x8000_0000),
            ("MISC_KEYS", "READPUBLIC_SYMCIPHER", 0x8000_0001),
            ("MISC_KEYS", "READPUBLIC_POLICY", 0x8000_0002),
            ("NO_SHA1_HMAC", "READPUBLIC_NO_SHA1_HMAC", 0x8000_0000),
        ] {
            assert_matches_oracle(snapshot, record, handle);
        }
    }

    #[test]
    fn every_hierarchy_reports_its_own_qualified_name() {
        for (record, handle) in [
            ("READPUBLIC_ENDORSEMENT", 0x8000_0000),
            ("READPUBLIC_PLATFORM", 0x8000_0001),
            ("READPUBLIC_NULL", 0x8000_0002),
        ] {
            assert_matches_oracle("HIERARCHY_KEYS", record, handle);
        }
    }

    #[test]
    fn a_persistent_copy_reports_the_same_public_area_name_and_qualified_name() {
        assert_matches_oracle("PERSISTENT", "READPUBLIC_PERSISTENT", 0x8100_0001);
        let transient = vector("READPUBLIC_RSASSA");
        let persistent = vector("READPUBLIC_PERSISTENT");
        assert_eq!(
            transient, persistent,
            "evicting a key does not change what TPM2_ReadPublic reports"
        );
    }

    #[test]
    fn the_reported_name_and_qualified_name_are_the_stored_ones() {
        let runtime = restored("KEYS");
        let response = vector("READPUBLIC_RSASSA");
        let parameters = &response[10..];
        let public_size = usize::from(u16::from_be_bytes([parameters[0], parameters[1]]));
        let rest = &parameters[2 + public_size..];
        let name_size = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
        let name = &rest[2..2 + name_size];
        let tail = &rest[2 + name_size..];
        let qualified_size = usize::from(u16::from_be_bytes([tail[0], tail[1]]));
        let qualified = &tail[2..2 + qualified_size];

        let object = resolve_any_object(&runtime, 0x8000_0000).expect("the key is loaded");
        let OwnedAnyObjectBody::Object(body) = &object.body else {
            panic!("a key object");
        };
        assert_eq!(body.name, name, "the stored Name is reported verbatim");
        assert_eq!(
            body.qualified_name, qualified,
            "the stored Qualified Name is reported verbatim"
        );
        assert_eq!(
            marshal_public_area(&body.public).expect("the public area marshals"),
            parameters[2..2 + public_size],
            "the stored public area is reported verbatim"
        );
    }

    #[test]
    fn no_sensitive_material_reaches_the_response() {
        let runtime = restored("KEYS");
        let object = resolve_any_object(&runtime, 0x8000_0000).expect("the key is loaded");
        let OwnedAnyObjectBody::Object(body) = &object.body else {
            panic!("a key object");
        };
        let secret = body
            .sensitive
            .sensitive
            .as_ref()
            .expect("a private key")
            .as_bytes()
            .to_vec();
        let response = vector("READPUBLIC_RSASSA");
        assert!(!secret.is_empty());
        assert!(
            !response
                .windows(secret.len())
                .any(|window| window == secret),
            "the private prime never appears in the response"
        );
    }

    #[test]
    fn every_sequence_object_is_rejected_with_the_upstream_sequence_error() {
        for (snapshot, record, handle) in [
            ("SEQUENCE_OBJECT", "READPUBLIC_SEQUENCE", 0x8000_0002),
            (
                "EVENT_SEQUENCE_OBJECT",
                "READPUBLIC_EVENT_SEQUENCE",
                0x8000_0002,
            ),
            (
                "HMAC_SEQUENCE_OBJECT",
                "READPUBLIC_HMAC_SEQUENCE",
                0x8000_0001,
            ),
        ] {
            let mut runtime = restored(snapshot);
            let response = read_public(&mut runtime, handle);
            assert_eq!(response, vector(record), "{record}");
            assert_eq!(response_code(&response), TPM_RC_SEQUENCE, "{record}");
        }
    }

    #[test]
    fn every_rejected_handle_matches_the_oracle() {
        for (record, handle) in [
            ("READPUBLIC_EMPTY_TRANSIENT", 0x8000_0000),
            ("READPUBLIC_UNKNOWN_TRANSIENT", 0x8000_0005),
            ("READPUBLIC_UNKNOWN_PERSISTENT", 0x8100_0009),
            ("READPUBLIC_SESSION_HANDLE", 0x0200_0000),
            ("READPUBLIC_NV_HANDLE", 0x0100_0000),
            ("READPUBLIC_PCR_HANDLE", 0x0000_0000),
            ("READPUBLIC_PERMANENT_HANDLE", 0x4000_0001),
            ("READPUBLIC_NULL_HANDLE", 0x4000_0007),
        ] {
            let mut runtime = restored("READY");
            assert_eq!(
                read_public(&mut runtime, handle),
                vector(record),
                "{record}"
            );
        }
    }

    #[test]
    fn a_malformed_handle_matches_the_oracle() {
        for (record, payload) in [
            ("READPUBLIC_NO_HANDLE", &[][..]),
            ("READPUBLIC_SHORT_HANDLE", &[0x80, 0x00, 0x00][..]),
        ] {
            let mut runtime = restored("READY");
            assert_eq!(
                dispatch_bytes(&mut runtime, &framed(TPM_CC, payload, false)),
                vector(record),
                "{record}"
            );
        }
    }

    #[test]
    fn trailing_bytes_are_rejected_with_the_upstream_size_error() {
        let mut runtime = restored("KEYS");
        let mut payload = 0x8000_0000u32.to_be_bytes().to_vec();
        payload.push(0x00);
        let response = dispatch_bytes(&mut runtime, &framed(TPM_CC, &payload, false));
        assert_eq!(response, vector("READPUBLIC_TRAILING"));
        assert_eq!(response_code(&response), 0x095);
    }

    #[test]
    fn reading_a_public_area_leaves_the_runtime_untouched() {
        let mut runtime = restored("KEYS");
        let before = snapshot_of(&runtime);
        assert_eq!(
            response_code(&read_public(&mut runtime, 0x8000_0000)),
            RC_SUCCESS
        );
        assert_eq!(snapshot_of(&runtime), before, "a successful read");

        for handle in [0x8000_0005u32, 0x8100_0009, 0x0200_0000] {
            let _ = read_public(&mut runtime, handle);
            assert_eq!(snapshot_of(&runtime), before, "handle {handle:#010x}");
        }
    }

    #[test]
    fn a_persistent_read_leaves_no_object_slot_occupied() {
        let mut runtime = restored("PERSISTENT");
        let occupied: Vec<bool> = runtime
            .live
            .objects
            .iter()
            .map(|object| object.attributes & ATTR_OCCUPIED != 0)
            .collect();
        assert!(
            occupied.iter().all(|used| !used),
            "the snapshot holds no transient objects"
        );
        assert_eq!(
            response_code(&read_public(&mut runtime, 0x8100_0001)),
            RC_SUCCESS
        );
        for object in runtime.live.objects.iter() {
            assert_eq!(
                object.attributes & ATTR_OCCUPIED,
                0,
                "the slot borrowed for the persistent object is released"
            );
            assert_eq!(object.attributes & ATTR_EVICT, 0);
        }
    }

    #[test]
    fn object_memory_exhaustion_is_reported_before_the_persistent_object_is_found() {
        let mut runtime = restored("PERSISTENT");
        for object in runtime.live.objects.iter_mut() {
            object.attributes |= ATTR_OCCUPIED;
        }
        let before = snapshot_of(&runtime);
        assert_eq!(
            response_code(&read_public(&mut runtime, 0x8100_0001)),
            0x902,
            "TPM_RC_OBJECT_MEMORY"
        );
        assert_eq!(snapshot_of(&runtime), before, "no slot changes");
    }

    fn snapshot_of(runtime: &Tpm2Runtime) -> RuntimeSnapshot {
        RuntimeSnapshot {
            nv_memory: runtime.nv_memory.to_vec(),
            nv_update_pending: runtime.nv_update_pending,
            objects: runtime
                .live
                .objects
                .iter()
                .map(|object| object.attributes)
                .collect(),
            failed_tries: runtime
                .state
                .as_ref()
                .map(|state| state.persistent.failed_tries),
            commit_counter: runtime
                .live
                .state_reset
                .as_ref()
                .map(|reset| reset.commit_counter),
            reseed_counter: runtime.live.orderly.drbg_state.reseed_counter,
            drbg_seed: runtime.live.orderly.drbg_state.seed.as_bytes().to_vec(),
            drbg_last_value: runtime.live.orderly.drbg_state.last_value,
            pcrs: runtime
                .live
                .pcrs
                .iter()
                .map(|pcr| pcr.banks.clone())
                .collect(),
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    struct RuntimeSnapshot {
        nv_memory: Vec<u8>,
        nv_update_pending: bool,
        objects: Vec<u32>,
        failed_tries: Option<u32>,
        commit_counter: Option<u64>,
        reseed_counter: u64,
        drbg_seed: Vec<u8>,
        drbg_last_value: [u32; 4],
        pcrs: Vec<[Option<Vec<u8>>; 4]>,
    }
}
