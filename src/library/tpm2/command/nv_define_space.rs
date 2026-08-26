use crate::ffi_types::TpmResult;
use crate::library::constants::{
    TPM_RC_ATTRIBUTES, TPM_RC_FAILURE, TPM_RC_HASH, TPM_RC_HIERARCHY, TPM_RC_NV_DEFINED,
    TPM_RC_SIZE,
};

use super::super::algorithm::{algorithm_enabled, hash_profile_name};
use super::super::hierarchy::{TPM_RH_OWNER, TPM_RH_PLATFORM};
use super::super::nv::{
    MAX_NV_INDEX_SIZE, NvPublic, TPM_NT_BITS, TPM_NT_COUNTER, TPM_NT_EXTEND, TPM_NT_ORDINARY,
    TPM_NT_PIN_FAIL, TPM_NT_PIN_PASS, TPMA_NV_AUTHREAD, TPMA_NV_AUTHWRITE, TPMA_NV_CLEAR_STCLEAR,
    TPMA_NV_GLOBALLOCK, TPMA_NV_NO_DA, TPMA_NV_OWNERREAD, TPMA_NV_OWNERWRITE,
    TPMA_NV_PLATFORMCREATE, TPMA_NV_POLICY_DELETE, TPMA_NV_POLICYREAD, TPMA_NV_POLICYWRITE,
    TPMA_NV_PPREAD, TPMA_NV_PPWRITE, TPMA_NV_READLOCKED, TPMA_NV_WRITEALL, TPMA_NV_WRITEDEFINE,
    TPMA_NV_WRITELOCKED, TPMA_NV_WRITTEN, add_index, checked_auth_value, handle_is_defined,
    nv_index_type, parse_sized_nv_public, strip_trailing_zeros, transact,
};
use super::super::runtime::Tpm2Runtime;
use super::super::template::{TemplateReader, digest_size};
use super::dispatcher::CommandFrame;
use super::nv_common::{MAX_NV_BUFFER_SIZE, TPM_RC_1, TPM_RC_2, TPM_RC_H, TPM_RC_P, handle_at};
use super::output::CommandOutput;

const RC_AUTH_HANDLE: TpmResult = TPM_RC_H + TPM_RC_1;
const RC_AUTH: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_PUBLIC_INFO: TpmResult = TPM_RC_P + TPM_RC_2;

const AUTH_TPM2B_MAX: usize = 64;

const READ_WAYS: u32 = TPMA_NV_OWNERREAD | TPMA_NV_PPREAD | TPMA_NV_AUTHREAD | TPMA_NV_POLICYREAD;
const WRITE_WAYS: u32 =
    TPMA_NV_OWNERWRITE | TPMA_NV_PPWRITE | TPMA_NV_AUTHWRITE | TPMA_NV_POLICYWRITE;
const DEFINITION_LOCKS: u32 = TPMA_NV_WRITTEN | TPMA_NV_WRITELOCKED | TPMA_NV_READLOCKED;

pub(super) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let auth_handle = handle_at(frame, 0)?;
    let (auth, public) = parse_parameters(frame.parameters)?;

    validate(runtime, auth_handle, &auth, &public)?;

    let auth_value = strip_trailing_zeros(&auth).to_vec();
    transact(runtime, |runtime| {
        add_index(runtime, &public, auth_value.clone())
    })?;
    Ok(CommandOutput::empty())
}

fn parse_parameters(parameters: &[u8]) -> Result<(Vec<u8>, NvPublic), TpmResult> {
    let mut reader = TemplateReader::new(parameters);
    let auth = reader
        .tpm2b(AUTH_TPM2B_MAX)
        .map_err(|code| code + RC_AUTH)?
        .to_vec();
    let public = parse_sized_nv_public(&mut reader).map_err(|code| code + RC_PUBLIC_INFO)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok((auth, public))
}

fn validate(
    runtime: &Tpm2Runtime,
    auth_handle: u32,
    auth: &[u8],
    public: &NvPublic,
) -> Result<(), TpmResult> {
    let attributes = public.attributes;
    let name_size = digest_size(public.name_alg).ok_or(TPM_RC_FAILURE)?;
    if !name_alg_is_enabled(runtime, public.name_alg)? {
        return Err(TPM_RC_HASH + RC_PUBLIC_INFO);
    }

    if !public.auth_policy.is_empty() && public.auth_policy.len() != name_size {
        return Err(TPM_RC_SIZE + RC_PUBLIC_INFO);
    }
    if checked_auth_value(auth, public.name_alg).is_err() {
        return Err(TPM_RC_SIZE + RC_AUTH);
    }
    if auth_handle == TPM_RH_PLATFORM && !platform_nv_is_enabled(runtime)? {
        return Err(TPM_RC_HIERARCHY + RC_AUTH_HANDLE);
    }

    let index_type = nv_index_type(attributes);
    if !matches!(
        index_type,
        TPM_NT_ORDINARY
            | TPM_NT_COUNTER
            | TPM_NT_BITS
            | TPM_NT_EXTEND
            | TPM_NT_PIN_FAIL
            | TPM_NT_PIN_PASS
    ) {
        return Err(TPM_RC_ATTRIBUTES + RC_PUBLIC_INFO);
    }

    match index_type {
        TPM_NT_ORDINARY => {
            if u32::from(public.data_size) > MAX_NV_INDEX_SIZE {
                return Err(TPM_RC_SIZE + RC_PUBLIC_INFO);
            }
        }
        TPM_NT_EXTEND => {
            if usize::from(public.data_size) != name_size {
                return Err(TPM_RC_SIZE + RC_PUBLIC_INFO);
            }
        }
        _ => {
            if public.data_size != 8 {
                return Err(TPM_RC_SIZE + RC_PUBLIC_INFO);
            }
        }
    }

    if index_type == TPM_NT_COUNTER && attributes & TPMA_NV_CLEAR_STCLEAR != 0 {
        return Err(TPM_RC_ATTRIBUTES + RC_PUBLIC_INFO);
    }
    if index_type == TPM_NT_PIN_FAIL && attributes & TPMA_NV_NO_DA == 0 {
        return Err(TPM_RC_ATTRIBUTES + RC_PUBLIC_INFO);
    }
    if matches!(index_type, TPM_NT_PIN_FAIL | TPM_NT_PIN_PASS)
        && attributes & (TPMA_NV_AUTHWRITE | TPMA_NV_GLOBALLOCK | TPMA_NV_WRITEDEFINE) != 0
    {
        return Err(TPM_RC_ATTRIBUTES + RC_PUBLIC_INFO);
    }

    if attributes & DEFINITION_LOCKS != 0
        || attributes & READ_WAYS == 0
        || attributes & WRITE_WAYS == 0
        || attributes & (TPMA_NV_CLEAR_STCLEAR | TPMA_NV_WRITEDEFINE)
            == (TPMA_NV_CLEAR_STCLEAR | TPMA_NV_WRITEDEFINE)
    {
        return Err(TPM_RC_ATTRIBUTES + RC_PUBLIC_INFO);
    }

    let platform_create = attributes & TPMA_NV_PLATFORMCREATE != 0;
    if (platform_create && auth_handle == TPM_RH_OWNER)
        || (!platform_create && auth_handle == TPM_RH_PLATFORM)
    {
        return Err(TPM_RC_ATTRIBUTES + RC_AUTH_HANDLE);
    }
    if attributes & TPMA_NV_POLICY_DELETE != 0 && auth_handle != TPM_RH_PLATFORM {
        return Err(TPM_RC_ATTRIBUTES + RC_PUBLIC_INFO);
    }
    if usize::from(public.data_size) > MAX_NV_BUFFER_SIZE && attributes & TPMA_NV_WRITEALL != 0 {
        return Err(TPM_RC_SIZE + RC_PUBLIC_INFO);
    }
    if handle_is_defined(runtime, public.nv_index) {
        return Err(TPM_RC_NV_DEFINED);
    }
    Ok(())
}

fn name_alg_is_enabled(runtime: &Tpm2Runtime, name_alg: u16) -> Result<bool, TpmResult> {
    let profile = &runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?.profile;
    Ok(
        hash_profile_name(name_alg)
            .is_some_and(|name| algorithm_enabled(&profile.algorithms, name)),
    )
}

fn platform_nv_is_enabled(runtime: &Tpm2Runtime) -> Result<bool, TpmResult> {
    runtime
        .live
        .state_clear
        .as_ref()
        .map(|clear| clear.ph_enable_nv)
        .ok_or(TPM_RC_FAILURE)
}

#[cfg(test)]
mod tests {
    use super::super::nv_common::harness::*;
    use super::super::registry::{
        CommandLifecycle, HandleKind, NvAccess, TPM_CC_NV_DEFINE_SPACE, find,
    };
    use super::*;
    use crate::library::constants::TPM_RC_INITIALIZE;
    use crate::library::tpm2::golden_responses::nv::nv_vector;
    use crate::library::tpm2::hierarchy::{TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT, TPM_RH_NULL};
    use crate::library::tpm2::nv::{
        NV_INDEX_FIRST, NV_INDEX_LAST, TPMA_NV_ORDERLY, TPMA_NV_READ_STCLEAR,
        TPMA_NV_WRITE_STCLEAR, marshal_sized_nv_public, resolve_index,
    };
    use crate::library::tpm2::persistent::OwnedUserNvramEntry;

    const RC_SIZE: u32 = 0x095;
    const RC_AUTH_MISSING: u32 = 0x125;
    const RC_NV_DEFINED: u32 = 0x14c;
    const RC_NV_SPACE: u32 = 0x14b;
    const RC_HANDLE1_VALUE: u32 = 0x184;
    const RC_HANDLE1_ATTRIBUTES: u32 = 0x182;
    const RC_HANDLE1_HIERARCHY: u32 = 0x185;
    const RC_HANDLE1_INSUFFICIENT: u32 = 0x19a;
    const RC_PARAM1_SIZE: u32 = 0x1d5;
    const RC_PARAM1_INSUFFICIENT: u32 = 0x1da;
    const RC_PARAM2_ATTRIBUTES: u32 = 0x2c2;
    const RC_PARAM2_HASH: u32 = 0x2c3;
    const RC_PARAM2_VALUE: u32 = 0x2c4;
    const RC_PARAM2_SIZE: u32 = 0x2d5;
    const RC_PARAM2_RESERVED_BITS: u32 = 0x2e1;
    const RC_PARAM2_INSUFFICIENT: u32 = 0x2da;
    const RC_SESSION1_BAD_AUTH: u32 = 0x9a2;
    const RC_NV_UNAVAILABLE: u32 = 0x923;

    const OWNER_INDEX: u32 = 0x0100_0001;
    const READ_WRITE: u32 = TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD;

    fn define_parameters(auth: &[u8], public: &NvPublic) -> Vec<u8> {
        let mut out = (auth.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(auth);
        out.extend_from_slice(&marshal_sized_nv_public(public));
        out
    }

    fn define_command(
        auth_handle: u32,
        password: &[u8],
        auth: &[u8],
        public: &NvPublic,
    ) -> Vec<u8> {
        command(
            TPM_CC_NV_DEFINE_SPACE,
            &[auth_handle],
            &[password],
            &define_parameters(auth, public),
        )
    }

    #[track_caller]
    fn define(runtime: &mut Tpm2Runtime, auth_handle: u32, public: &NvPublic) -> u32 {
        response_code(&dispatch_bytes(
            runtime,
            &define_command(auth_handle, &[], &[], public),
        ))
    }

    #[track_caller]
    fn define_with_auth(
        runtime: &mut Tpm2Runtime,
        auth_handle: u32,
        auth: &[u8],
        public: &NvPublic,
    ) -> u32 {
        response_code(&dispatch_bytes(
            runtime,
            &define_command(auth_handle, &[], auth, public),
        ))
    }

    fn owner_ordinary() -> NvPublic {
        nv_public(OWNER_INDEX, READ_WRITE, 32)
    }

    fn platform_ordinary() -> NvPublic {
        nv_public(
            0x0180_0001,
            READ_WRITE | TPMA_NV_PLATFORMCREATE | TPMA_NV_PPREAD | TPMA_NV_PPWRITE,
            32,
        )
    }

    #[test]
    fn the_command_code_and_attributes_match_the_vendored_table() {
        assert_eq!(TPM_CC_NV_DEFINE_SPACE, 0x0000_012a);
        let expected = nv_vector("CCATTR_012A");
        let descriptor = find(TPM_CC_NV_DEFINE_SPACE).expect("a registered command");
        assert_eq!(
            descriptor.attributes,
            u32::from_be_bytes(expected[19..23].try_into().unwrap())
        );
        assert_eq!(descriptor.attributes, 0x0240_012a);
        assert_ne!(
            descriptor.attributes & (1 << 22),
            0,
            "DefineSpace writes NV"
        );
        assert_eq!(descriptor.attributes & (1 << 28), 0, "no response handle");
        assert_eq!((descriptor.attributes >> 25) & 0x7, 1, "one command handle");
        assert!(descriptor.physical_presence);
        assert!(descriptor.sessions_allowed);
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
        assert!(matches!(descriptor.nv_access, NvAccess::Neither));
    }

    #[test]
    fn the_only_handle_is_a_provision_handle_needing_user_authorization() {
        let descriptor = find(TPM_CC_NV_DEFINE_SPACE).expect("a registered command");
        assert_eq!(descriptor.handles.len(), 1);
        assert!(descriptor.handles[0].user_auth);
        assert!(!descriptor.handles[0].admin_role());
        assert!(matches!(descriptor.handles[0].kind, HandleKind::Provision));

        let kind = descriptor.handles[0].kind;
        assert!(kind.accepts(TPM_RH_OWNER));
        assert!(kind.accepts(TPM_RH_PLATFORM));
        for handle in [
            TPM_RH_ENDORSEMENT,
            TPM_RH_LOCKOUT,
            TPM_RH_NULL,
            NV_INDEX_FIRST,
            0x8100_0000,
        ] {
            assert!(!kind.accepts(handle), "handle {handle:#010x}");
        }
    }

    #[test]
    fn define_space_is_rejected_before_startup() {
        let mut runtime = manufactured_runtime();
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &define_command(TPM_RH_OWNER, &[], &[], &owner_ordinary())
            ),
            error_response(TPM_RC_INITIALIZE)
        );
    }

    #[test]
    fn an_owner_created_ordinary_index_is_defined_and_survives_serialization() {
        let mut runtime = started_runtime();
        assert_eq!(
            define(&mut runtime, TPM_RH_OWNER, &owner_ordinary()),
            RC_SUCCESS
        );
        assert!(runtime.nv_update_pending);

        let stored = resolved(&runtime, OWNER_INDEX);
        assert_eq!(stored.public, owner_ordinary());
        assert_eq!(stored.ram, None);

        let OwnedUserNvramEntry::NvIndex { data, index, .. } =
            &runtime.state().user_nvram.entries[stored.entry]
        else {
            panic!("expected an NV index entry");
        };
        assert_eq!(data, &vec![0u8; 32], "the data area is zeroed");
        assert!(index.auth_value.expose().is_empty());
    }

    #[test]
    fn the_defined_index_survives_a_permanent_state_round_trip() {
        use crate::library::tpm2::persistent::persistent_all_store;
        use crate::library::tpm2::restore_permanent_blob_for_test;

        let mut runtime = started_runtime();
        assert_eq!(
            define_with_auth(&mut runtime, TPM_RH_OWNER, b"secret", &owner_ordinary()),
            RC_SUCCESS
        );
        let blob = persistent_all_store(runtime.state()).expect("the state serializes");
        let reloaded = restore_permanent_blob_for_test(&blob).expect("the blob restores");

        let entry = reloaded
            .state()
            .user_nvram
            .entries
            .iter()
            .find(|entry| matches!(entry, OwnedUserNvramEntry::NvIndex { handle, .. } if *handle == OWNER_INDEX))
            .expect("the index survives");
        let OwnedUserNvramEntry::NvIndex { index, data, .. } = entry else {
            panic!("expected an NV index entry");
        };
        assert_eq!(index.nv_index, OWNER_INDEX);
        assert_eq!(index.attributes, READ_WRITE);
        assert_eq!(index.data_size, 32);
        assert_eq!(index.auth_value.expose(), b"secret");
        assert_eq!(data, &vec![0u8; 32]);
    }

    #[test]
    fn a_platform_created_index_needs_platform_authorization() {
        let mut runtime = started_runtime();
        assert_eq!(
            define(&mut runtime, TPM_RH_PLATFORM, &platform_ordinary()),
            RC_SUCCESS
        );
        assert!(
            resolve_index(&runtime, 0x0180_0001)
                .unwrap()
                .is_platform_created()
        );
    }

    #[test]
    fn the_creating_hierarchy_must_match_the_platform_create_attribute() {
        let mut runtime = started_runtime();
        assert_eq!(
            define(&mut runtime, TPM_RH_OWNER, &platform_ordinary()),
            RC_HANDLE1_ATTRIBUTES,
            "the owner cannot set PLATFORMCREATE"
        );
        assert_eq!(
            define(&mut runtime, TPM_RH_PLATFORM, &owner_ordinary()),
            RC_HANDLE1_ATTRIBUTES,
            "the platform must set PLATFORMCREATE"
        );
    }

    #[test]
    fn a_duplicate_handle_is_nv_defined() {
        let mut runtime = started_runtime();
        assert_eq!(
            define(&mut runtime, TPM_RH_OWNER, &owner_ordinary()),
            RC_SUCCESS
        );
        let before = snapshot(&runtime);
        assert_eq!(
            define(&mut runtime, TPM_RH_OWNER, &owner_ordinary()),
            RC_NV_DEFINED
        );
        assert_unchanged(&runtime, &before);
        assert_eq!(
            define(
                &mut runtime,
                TPM_RH_OWNER,
                &nv_public(OWNER_INDEX, READ_WRITE | TPMA_NV_AUTHREAD, 8)
            ),
            RC_NV_DEFINED,
            "only the handle matters"
        );
    }

    #[test]
    fn a_persistent_object_handle_blocks_nothing_because_the_ranges_are_disjoint() {
        let mut runtime = started_runtime();
        assert_eq!(
            define(&mut runtime, TPM_RH_OWNER, &owner_ordinary()),
            RC_SUCCESS
        );
        assert_eq!(
            define(
                &mut runtime,
                TPM_RH_OWNER,
                &nv_public(0x0100_0002, READ_WRITE, 8)
            ),
            RC_SUCCESS
        );
        assert_eq!(index_handles(&runtime), [OWNER_INDEX, 0x0100_0002]);
    }

    #[test]
    fn every_supported_index_type_is_accepted_with_its_required_data_size() {
        let mut runtime = started_runtime();
        for (index_type, data_size, extra) in [
            (TPM_NT_ORDINARY, 32u16, 0u32),
            (TPM_NT_COUNTER, 8, 0),
            (TPM_NT_BITS, 8, 0),
            (TPM_NT_EXTEND, 32, 0),
            (TPM_NT_PIN_PASS, 8, 0),
            (TPM_NT_PIN_FAIL, 8, TPMA_NV_NO_DA),
        ] {
            let handle = 0x0100_0010 + index_type;
            let public = nv_public(handle, READ_WRITE | nt(index_type) | extra, data_size);
            assert_eq!(
                define(&mut runtime, TPM_RH_OWNER, &public),
                RC_SUCCESS,
                "index type {index_type}"
            );
            assert_eq!(resolved(&runtime, handle).public, public);
        }
    }

    #[test]
    fn an_unsupported_index_type_is_an_attribute_error() {
        let mut runtime = started_runtime();
        for index_type in [0x3u32, 0x5, 0x6, 0x7, 0xa, 0xf] {
            assert_eq!(
                define(
                    &mut runtime,
                    TPM_RH_OWNER,
                    &nv_public(OWNER_INDEX, READ_WRITE | nt(index_type), 8)
                ),
                RC_PARAM2_ATTRIBUTES,
                "index type {index_type}"
            );
        }
    }

    #[test]
    fn each_index_type_enforces_its_own_data_size() {
        let mut runtime = started_runtime();
        for index_type in [TPM_NT_COUNTER, TPM_NT_BITS, TPM_NT_PIN_PASS] {
            for data_size in [0u16, 4, 7, 9, 32] {
                assert_eq!(
                    define(
                        &mut runtime,
                        TPM_RH_OWNER,
                        &nv_public(OWNER_INDEX, READ_WRITE | nt(index_type), data_size)
                    ),
                    RC_PARAM2_SIZE,
                    "index type {index_type} size {data_size}"
                );
            }
        }
        for data_size in [0u16, 20, 31, 33, 48] {
            assert_eq!(
                define(
                    &mut runtime,
                    TPM_RH_OWNER,
                    &nv_public(OWNER_INDEX, READ_WRITE | nt(TPM_NT_EXTEND), data_size)
                ),
                RC_PARAM2_SIZE,
                "an extend index must equal the nameAlg digest, size {data_size}"
            );
        }
        let mut sha1 = nv_public(OWNER_INDEX, READ_WRITE | nt(TPM_NT_EXTEND), 20);
        sha1.name_alg = TPM_ALG_SHA1;
        assert_eq!(define(&mut runtime, TPM_RH_OWNER, &sha1), RC_SUCCESS);
    }

    #[test]
    fn an_ordinary_index_may_be_empty_or_the_maximum_size() {
        let mut runtime = started_runtime();
        assert_eq!(
            define(
                &mut runtime,
                TPM_RH_OWNER,
                &nv_public(OWNER_INDEX, READ_WRITE, 0)
            ),
            RC_SUCCESS
        );
        assert_eq!(
            define(
                &mut runtime,
                TPM_RH_OWNER,
                &nv_public(0x0100_0002, READ_WRITE, 2048)
            ),
            RC_SUCCESS
        );
    }

    #[test]
    fn an_ordinary_index_above_the_implementation_limit_is_rejected_at_unmarshalling() {
        let mut runtime = started_runtime();
        assert_eq!(
            define(
                &mut runtime,
                TPM_RH_OWNER,
                &nv_public(OWNER_INDEX, READ_WRITE, 2049)
            ),
            RC_PARAM2_SIZE
        );
    }

    #[test]
    fn a_counter_may_not_be_cleared_on_startup() {
        let mut runtime = started_runtime();
        assert_eq!(
            define(
                &mut runtime,
                TPM_RH_OWNER,
                &nv_public(
                    OWNER_INDEX,
                    READ_WRITE | nt(TPM_NT_COUNTER) | TPMA_NV_CLEAR_STCLEAR,
                    8
                )
            ),
            RC_PARAM2_ATTRIBUTES
        );
    }

    #[test]
    fn a_pin_fail_index_must_be_dictionary_attack_exempt() {
        let mut runtime = started_runtime();
        assert_eq!(
            define(
                &mut runtime,
                TPM_RH_OWNER,
                &nv_public(OWNER_INDEX, READ_WRITE | nt(TPM_NT_PIN_FAIL), 8)
            ),
            RC_PARAM2_ATTRIBUTES
        );
        assert_eq!(
            define(
                &mut runtime,
                TPM_RH_OWNER,
                &nv_public(
                    OWNER_INDEX,
                    READ_WRITE | nt(TPM_NT_PIN_FAIL) | TPMA_NV_NO_DA,
                    8
                )
            ),
            RC_SUCCESS
        );
    }

    #[test]
    fn a_pin_index_forbids_auth_write_global_lock_and_write_define() {
        let mut runtime = started_runtime();
        for forbidden in [TPMA_NV_AUTHWRITE, TPMA_NV_GLOBALLOCK, TPMA_NV_WRITEDEFINE] {
            for index_type in [TPM_NT_PIN_PASS, TPM_NT_PIN_FAIL] {
                assert_eq!(
                    define(
                        &mut runtime,
                        TPM_RH_OWNER,
                        &nv_public(
                            OWNER_INDEX,
                            READ_WRITE | nt(index_type) | TPMA_NV_NO_DA | forbidden,
                            8
                        )
                    ),
                    RC_PARAM2_ATTRIBUTES,
                    "type {index_type} attribute {forbidden:#x}"
                );
            }
        }
    }

    #[test]
    fn definition_time_locks_and_the_written_bit_are_rejected() {
        let mut runtime = started_runtime();
        for attribute in [TPMA_NV_WRITTEN, TPMA_NV_WRITELOCKED, TPMA_NV_READLOCKED] {
            assert_eq!(
                define(
                    &mut runtime,
                    TPM_RH_OWNER,
                    &nv_public(OWNER_INDEX, READ_WRITE | attribute, 32)
                ),
                RC_PARAM2_ATTRIBUTES,
                "attribute {attribute:#x}"
            );
        }
    }

    #[test]
    fn an_index_must_offer_a_way_to_read_and_a_way_to_write() {
        let mut runtime = started_runtime();
        assert_eq!(
            define(
                &mut runtime,
                TPM_RH_OWNER,
                &nv_public(OWNER_INDEX, TPMA_NV_OWNERWRITE, 32)
            ),
            RC_PARAM2_ATTRIBUTES,
            "no read attribute"
        );
        assert_eq!(
            define(
                &mut runtime,
                TPM_RH_OWNER,
                &nv_public(OWNER_INDEX, TPMA_NV_OWNERREAD, 32)
            ),
            RC_PARAM2_ATTRIBUTES,
            "no write attribute"
        );
        for read in [
            TPMA_NV_OWNERREAD,
            TPMA_NV_PPREAD,
            TPMA_NV_AUTHREAD,
            TPMA_NV_POLICYREAD,
        ] {
            for write in [
                TPMA_NV_OWNERWRITE,
                TPMA_NV_PPWRITE,
                TPMA_NV_AUTHWRITE,
                TPMA_NV_POLICYWRITE,
            ] {
                let mut fresh = started_runtime();
                assert_eq!(
                    define(
                        &mut fresh,
                        TPM_RH_OWNER,
                        &nv_public(OWNER_INDEX, read | write, 32)
                    ),
                    RC_SUCCESS,
                    "read {read:#x} write {write:#x}"
                );
            }
        }
    }

    #[test]
    fn clear_stclear_and_write_define_are_mutually_exclusive() {
        let mut runtime = started_runtime();
        assert_eq!(
            define(
                &mut runtime,
                TPM_RH_OWNER,
                &nv_public(
                    OWNER_INDEX,
                    READ_WRITE | TPMA_NV_CLEAR_STCLEAR | TPMA_NV_WRITEDEFINE,
                    32
                )
            ),
            RC_PARAM2_ATTRIBUTES
        );
    }

    #[test]
    fn a_policy_delete_index_may_only_be_created_by_the_platform() {
        let mut runtime = started_runtime();
        assert_eq!(
            define(
                &mut runtime,
                TPM_RH_OWNER,
                &nv_public(OWNER_INDEX, READ_WRITE | TPMA_NV_POLICY_DELETE, 32)
            ),
            RC_PARAM2_ATTRIBUTES,
            "the PLATFORMCREATE check fires first for the owner"
        );
        let mut public = platform_ordinary();
        public.attributes |= TPMA_NV_POLICY_DELETE;
        assert_eq!(define(&mut runtime, TPM_RH_PLATFORM, &public), RC_SUCCESS);
    }

    #[test]
    fn write_all_is_refused_above_the_nv_buffer_size() {
        let mut runtime = started_runtime();
        assert_eq!(
            define(
                &mut runtime,
                TPM_RH_OWNER,
                &nv_public(OWNER_INDEX, READ_WRITE | TPMA_NV_WRITEALL, 1025)
            ),
            RC_PARAM2_SIZE
        );
        assert_eq!(
            define(
                &mut runtime,
                TPM_RH_OWNER,
                &nv_public(OWNER_INDEX, READ_WRITE | TPMA_NV_WRITEALL, 1024)
            ),
            RC_SUCCESS
        );
        assert_eq!(
            define(
                &mut runtime,
                TPM_RH_OWNER,
                &nv_public(0x0100_0002, READ_WRITE, 2048)
            ),
            RC_SUCCESS,
            "without WRITEALL a large index is fine"
        );
    }

    #[test]
    fn an_auth_policy_must_match_the_name_algorithm_digest_size() {
        let mut runtime = started_runtime();
        for size in [1usize, 20, 31, 33, 48, 64] {
            let mut public = owner_ordinary();
            public.auth_policy = vec![0x5a; size];
            assert_eq!(
                define(&mut runtime, TPM_RH_OWNER, &public),
                RC_PARAM2_SIZE,
                "policy size {size}"
            );
        }
        let mut public = owner_ordinary();
        public.auth_policy = vec![0x5a; 32];
        assert_eq!(define(&mut runtime, TPM_RH_OWNER, &public), RC_SUCCESS);
    }

    #[test]
    fn an_auth_value_longer_than_the_name_algorithm_digest_is_a_size_error() {
        let mut runtime = started_runtime();
        assert_eq!(
            define_with_auth(&mut runtime, TPM_RH_OWNER, &[0xaa; 33], &owner_ordinary()),
            RC_PARAM1_SIZE
        );
        assert_eq!(
            define_with_auth(&mut runtime, TPM_RH_OWNER, &[0xaa; 32], &owner_ordinary()),
            RC_SUCCESS
        );
    }

    #[test]
    fn an_auth_value_is_stored_without_its_trailing_zeros() {
        let mut runtime = started_runtime();
        let mut padded = vec![0x41u8, 0x42];
        padded.extend_from_slice(&[0x00; 40]);
        assert_eq!(
            define_with_auth(&mut runtime, TPM_RH_OWNER, &padded, &owner_ordinary()),
            RC_SUCCESS,
            "the size is measured after stripping trailing zeros"
        );
        let stored = resolved(&runtime, OWNER_INDEX);
        let OwnedUserNvramEntry::NvIndex { index, .. } =
            &runtime.state().user_nvram.entries[stored.entry]
        else {
            panic!("expected an NV index entry");
        };
        assert_eq!(index.auth_value.expose(), &[0x41, 0x42]);
    }

    #[test]
    fn a_platform_index_needs_ph_enable_nv() {
        let mut runtime = started_runtime();
        runtime.live.state_clear.as_mut().unwrap().ph_enable_nv = false;
        assert_eq!(
            define(&mut runtime, TPM_RH_PLATFORM, &platform_ordinary()),
            RC_HANDLE1_HIERARCHY
        );
        assert_eq!(
            define(&mut runtime, TPM_RH_OWNER, &owner_ordinary()),
            RC_SUCCESS,
            "the owner hierarchy is unaffected"
        );
    }

    #[test]
    fn an_orderly_index_is_backed_by_ram() {
        let mut runtime = started_runtime();
        let public = nv_public(OWNER_INDEX, READ_WRITE | TPMA_NV_ORDERLY, 8);
        assert_eq!(define(&mut runtime, TPM_RH_OWNER, &public), RC_SUCCESS);

        let stored = resolved(&runtime, OWNER_INDEX);
        assert_eq!(stored.ram, Some(0));
        assert_eq!(
            runtime.live.index_orderly_ram.entries[0].handle,
            OWNER_INDEX
        );
        assert_eq!(runtime.live.index_orderly_ram.entries[0].data, vec![0u8; 8]);
        let OwnedUserNvramEntry::NvIndex { data, .. } =
            &runtime.state().user_nvram.entries[stored.entry]
        else {
            panic!("expected an NV index entry");
        };
        assert!(data.is_empty(), "orderly indexes allocate no NV data area");
    }

    #[test]
    fn a_failed_definition_leaves_no_trace() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        for public in [
            nv_public(OWNER_INDEX, READ_WRITE | TPMA_NV_WRITTEN, 32),
            nv_public(OWNER_INDEX, TPMA_NV_OWNERREAD, 32),
            nv_public(OWNER_INDEX, READ_WRITE | nt(0x3), 8),
        ] {
            assert_ne!(define(&mut runtime, TPM_RH_OWNER, &public), RC_SUCCESS);
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn definition_without_nv_is_unavailable_and_changes_nothing() {
        let mut runtime = started_runtime();
        runtime.nv_available = false;
        let before = snapshot(&runtime);
        assert_eq!(
            define(&mut runtime, TPM_RH_OWNER, &owner_ordinary()),
            RC_NV_UNAVAILABLE
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn the_dynamic_region_runs_out_of_space_before_the_handle_space_does() {
        let mut runtime = started_runtime();
        let mut defined = 0u32;
        loop {
            let handle = NV_INDEX_FIRST + defined;
            let code = define(
                &mut runtime,
                TPM_RH_OWNER,
                &nv_public(handle, READ_WRITE, 2048),
            );
            if code == RC_NV_SPACE {
                break;
            }
            assert_eq!(code, RC_SUCCESS, "index {defined}");
            defined += 1;
            assert!(defined < 200, "the dynamic region must run out");
        }
        assert!(defined > 0, "at least one index fits");
        let before = snapshot(&runtime);
        assert_eq!(
            define(
                &mut runtime,
                TPM_RH_OWNER,
                &nv_public(NV_INDEX_LAST, READ_WRITE, 2048)
            ),
            RC_NV_SPACE
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn the_orderly_ram_runs_out_of_space_independently() {
        let mut runtime = started_runtime();
        let mut defined = 0u32;
        loop {
            let handle = NV_INDEX_FIRST + defined;
            let code = define(
                &mut runtime,
                TPM_RH_OWNER,
                &nv_public(handle, READ_WRITE | TPMA_NV_ORDERLY, 64),
            );
            if code == RC_NV_SPACE {
                break;
            }
            assert_eq!(code, RC_SUCCESS, "index {defined}");
            defined += 1;
            assert!(defined < 20, "512 bytes of orderly RAM must run out");
        }
        assert_eq!(defined, 6, "76 bytes per index fits six times in 512 bytes");
        assert_eq!(
            define(
                &mut runtime,
                TPM_RH_OWNER,
                &nv_public(0x0101_0000, READ_WRITE, 64)
            ),
            RC_SUCCESS,
            "a non-orderly index still fits"
        );
    }

    #[test]
    fn a_missing_authorization_area_is_auth_missing() {
        let mut runtime = started_runtime();
        let payload = {
            let mut out = TPM_RH_OWNER.to_be_bytes().to_vec();
            out.extend_from_slice(&define_parameters(&[], &owner_ordinary()));
            out
        };
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &framed(TPM_CC_NV_DEFINE_SPACE, &payload, false)
            )),
            RC_AUTH_MISSING
        );
    }

    #[test]
    fn a_wrong_owner_password_is_reported_against_the_first_session() {
        let mut runtime = started_runtime();
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &define_command(TPM_RH_OWNER, b"wrong", &[], &owner_ordinary())
            )),
            RC_SESSION1_BAD_AUTH
        );
    }

    #[test]
    fn an_invalid_or_truncated_handle_is_reported_with_its_own_index() {
        let mut runtime = started_runtime();
        for (payload, expected) in [
            (&[][..], RC_HANDLE1_INSUFFICIENT),
            (&[0x40][..], RC_HANDLE1_INSUFFICIENT),
            (&[0x40, 0x00, 0x00][..], RC_HANDLE1_INSUFFICIENT),
            (&[0x40, 0x00, 0x00, 0x0b][..], RC_HANDLE1_VALUE),
            (&[0x01, 0x00, 0x00, 0x01][..], RC_HANDLE1_VALUE),
        ] {
            assert_eq!(
                response_code(&dispatch_bytes(
                    &mut runtime,
                    &framed(TPM_CC_NV_DEFINE_SPACE, payload, true)
                )),
                expected,
                "payload {payload:02x?}"
            );
        }
    }

    #[test]
    fn truncated_parameters_are_reported_against_their_own_parameter_number() {
        let mut runtime = started_runtime();
        let full = define_parameters(b"pw", &owner_ordinary());
        for length in 0..full.len() {
            let code = response_code(&dispatch_bytes(
                &mut runtime,
                &command(
                    TPM_CC_NV_DEFINE_SPACE,
                    &[TPM_RH_OWNER],
                    &[&[]],
                    &full[..length],
                ),
            ));
            let expected = if length < 4 {
                RC_PARAM1_INSUFFICIENT
            } else {
                RC_PARAM2_INSUFFICIENT
            };
            assert!(
                code == expected || code == RC_PARAM2_SIZE,
                "prefix {length} of {} gave {code:#05x}",
                full.len()
            );
        }
    }

    #[test]
    fn trailing_parameter_bytes_are_a_size_error() {
        let mut runtime = started_runtime();
        let mut parameters = define_parameters(&[], &owner_ordinary());
        parameters.push(0x00);
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &command(TPM_CC_NV_DEFINE_SPACE, &[TPM_RH_OWNER], &[&[]], &parameters),
            )),
            RC_SIZE
        );
    }

    #[test]
    fn an_out_of_range_index_handle_in_the_public_area_is_a_value_error() {
        let mut runtime = started_runtime();
        for handle in [0x0000_0001u32, 0x00ff_ffff, 0x0200_0000, 0x8100_0000] {
            let mut public = owner_ordinary();
            public.nv_index = handle;
            assert_eq!(
                define(&mut runtime, TPM_RH_OWNER, &public),
                RC_PARAM2_VALUE,
                "handle {handle:#010x}"
            );
        }
    }

    #[test]
    fn an_unsupported_name_algorithm_is_a_hash_error() {
        let mut runtime = started_runtime();
        for alg in [0x0000u16, 0x0010, 0x0012, 0xffff] {
            let mut public = owner_ordinary();
            public.name_alg = alg;
            assert_eq!(
                define(&mut runtime, TPM_RH_OWNER, &public),
                RC_PARAM2_HASH,
                "alg {alg:#06x}"
            );
        }
    }

    #[track_caller]
    fn profile_runtime(algorithms: &str) -> Box<Tpm2Runtime> {
        use crate::library::tpm2::manufacture::manufacture_state;
        use crate::library::tpm2::profile::validate_user_profile;
        use crate::library::tpm2::runtime::commit_manufactured_state;

        let json = format!(r#"{{"Name":"custom","Algorithms":"{algorithms}"}}"#);
        let profile =
            validate_user_profile(Some(json.as_bytes())).expect("the custom profile validates");
        let state = manufacture_state(profile, |buffer| {
            let len = buffer.len() as u8;
            for (index, byte) in buffer.iter_mut().enumerate() {
                *byte = (index as u8).wrapping_add(len) ^ 0x55;
            }
            Ok(())
        })
        .expect("manufactures");
        let mut runtime = commit_manufactured_state(state).expect("commits");
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &framed(0x0000_0144, &[0x00, 0x00], false)
            )),
            RC_SUCCESS
        );
        runtime.nv_update_pending = false;
        runtime
    }

    const ALL_HASHES: &str = "rsa,sha1,hmac,aes,mgf1,keyedhash,xor,sha256,sha384,sha512,null,\
                              rsassa,rsaes,rsapss,oaep,ecdsa,ecdh,ecdaa,ecschnorr,kdf1-sp800-56a,\
                              kdf2,kdf1-sp800-108,ecc,ecc-nist,symcipher,cfb";

    #[test]
    fn a_name_algorithm_disabled_by_the_profile_is_a_hash_error() {
        for (disabled, name_alg) in [("sha1", TPM_ALG_SHA1), ("sha512", 0x000du16)] {
            let algorithms: String = ALL_HASHES
                .split(',')
                .map(str::trim)
                .filter(|token| *token != disabled)
                .collect::<Vec<_>>()
                .join(",");
            let mut runtime = profile_runtime(&algorithms);
            let mut public = owner_ordinary();
            public.name_alg = name_alg;
            assert_eq!(
                define(&mut runtime, TPM_RH_OWNER, &public),
                RC_PARAM2_HASH,
                "{disabled} is implemented but disabled by the active profile"
            );
            assert!(
                resolve_index(&runtime, OWNER_INDEX).is_none(),
                "a rejected definition creates no index"
            );
            assert!(!runtime.nv_update_pending);
        }
    }

    #[test]
    fn a_name_algorithm_enabled_by_the_profile_is_accepted() {
        for (kept, name_alg, data_size) in
            [("sha1", TPM_ALG_SHA1, 20u16), ("sha512", 0x000du16, 64)]
        {
            let mut runtime = profile_runtime(ALL_HASHES);
            let mut public = owner_ordinary();
            public.name_alg = name_alg;
            public.data_size = data_size;
            assert_eq!(
                define(&mut runtime, TPM_RH_OWNER, &public),
                RC_SUCCESS,
                "{kept} is enabled by the active profile"
            );
            assert_eq!(resolved(&runtime, OWNER_INDEX).public.name_alg, name_alg);
        }
    }

    #[test]
    fn a_disabled_name_algorithm_is_rejected_before_the_attribute_checks() {
        let algorithms: String = ALL_HASHES
            .split(',')
            .map(str::trim)
            .filter(|token| *token != "sha1")
            .collect::<Vec<_>>()
            .join(",");
        let mut runtime = profile_runtime(&algorithms);
        let before = snapshot(&runtime);
        let mut public = nv_public(OWNER_INDEX, TPMA_NV_OWNERREAD, 32);
        public.name_alg = TPM_ALG_SHA1;
        assert_eq!(
            define(&mut runtime, TPM_RH_OWNER, &public),
            RC_PARAM2_HASH,
            "the profile check precedes the missing-write-attribute check"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn reserved_attribute_bits_are_rejected_at_unmarshalling() {
        let mut runtime = started_runtime();
        for bit in [8u32, 9, 20, 21, 22, 23, 24] {
            let mut public = owner_ordinary();
            public.attributes |= 1 << bit;
            assert_eq!(
                define(&mut runtime, TPM_RH_OWNER, &public),
                RC_PARAM2_RESERVED_BITS,
                "bit {bit}"
            );
        }
    }

    #[test]
    fn the_stclear_attributes_are_accepted_at_definition_time() {
        let mut runtime = started_runtime();
        assert_eq!(
            define(
                &mut runtime,
                TPM_RH_OWNER,
                &nv_public(
                    OWNER_INDEX,
                    READ_WRITE | TPMA_NV_READ_STCLEAR | TPMA_NV_WRITE_STCLEAR,
                    32
                )
            ),
            RC_SUCCESS
        );
    }

    #[track_caller]
    fn oracle_runtime(base: &[u8]) -> Box<Tpm2Runtime> {
        use crate::library::tpm2::restore_permanent_blob_for_test;
        let mut runtime =
            restore_permanent_blob_for_test(base).expect("the oracle permanent state restores");
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &framed(0x0000_0144, &[0x00, 0x00], false)
            )),
            RC_SUCCESS,
            "the oracle state starts up"
        );
        runtime.nv_update_pending = false;
        runtime
    }

    #[test]
    fn the_oracle_define_and_write_sequence_reproduces_the_permanent_state() {
        let mut runtime = oracle_runtime(nv_vector("PERMALL_BASE"));
        assert_matches_oracle(&runtime, nv_vector("PERMALL_STARTED"), "startup");

        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &define_command(TPM_RH_OWNER, &[], &[], &owner_ordinary())
            ),
            nv_vector("DEFINE_OWNER_ORDINARY"),
            "the define response matches the oracle byte for byte"
        );
        assert_matches_oracle(&runtime, nv_vector("PERMALL_AFTER_DEFINE"), "after define");

        let mut parameters = 8u16.to_be_bytes().to_vec();
        parameters.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        parameters.extend_from_slice(&4u16.to_be_bytes());
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &command(
                    0x0000_0137,
                    &[TPM_RH_OWNER, OWNER_INDEX],
                    &[&[]],
                    &parameters
                ),
            ),
            nv_vector("WRITE_OWNER_PARTIAL")
        );
        assert_matches_oracle(&runtime, nv_vector("PERMALL_AFTER_WRITE"), "after write");
    }

    #[test]
    fn the_oracle_orderly_sequence_reproduces_the_permanent_state() {
        let mut runtime = oracle_runtime(nv_vector("PERMALL_ORDERLY_BASE"));
        let orderly = nv_public(0x0100_0020, READ_WRITE | TPMA_NV_ORDERLY, 8);
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &define_command(TPM_RH_OWNER, &[], &[], &orderly)
            )),
            RC_SUCCESS
        );
        assert_matches_oracle(
            &runtime,
            nv_vector("PERMALL_ORDERLY_DEFINED"),
            "orderly defined",
        );

        let mut parameters = 8u16.to_be_bytes().to_vec();
        parameters.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        parameters.extend_from_slice(&0u16.to_be_bytes());
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &command(
                    0x0000_0137,
                    &[TPM_RH_OWNER, 0x0100_0020],
                    &[&[]],
                    &parameters
                ),
            )),
            RC_SUCCESS
        );
        assert_matches_oracle(
            &runtime,
            nv_vector("PERMALL_ORDERLY_WRITTEN"),
            "orderly written",
        );

        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &command(0x0000_0122, &[TPM_RH_OWNER, 0x0100_0020], &[&[]], &[]),
            )),
            RC_SUCCESS
        );
        assert_matches_oracle(
            &runtime,
            nv_vector("PERMALL_ORDERLY_UNDEFINED"),
            "orderly undefined",
        );
    }

    #[test]
    fn parameter_mutations_do_not_panic() {
        let full = define_parameters(b"pw", &owner_ordinary());
        for index in 0..full.len() {
            for byte in [0x00u8, 0x01, 0x7f, 0xff] {
                let mut parameters = full.clone();
                parameters[index] = byte;
                let mut runtime = started_runtime();
                let _ = dispatch_bytes(
                    &mut runtime,
                    &command(TPM_CC_NV_DEFINE_SPACE, &[TPM_RH_OWNER], &[&[]], &parameters),
                );
            }
        }
    }
}
