use super::access::resolve;
use crate::ffi_types::TpmResult;
use crate::library::constants::{TPM_RC_ATTRIBUTES, TPM_RC_NV_AUTHORIZATION, TPM_RC_SIZE};
use crate::library::tpm2::command::core::dispatcher::{CommandFrame, handle_at};
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::command::core::response_code::{TPM_RC_1, TPM_RC_2, TPM_RC_H};
use crate::library::tpm2::command::session::processing::remove_session_association;
use crate::library::tpm2::hierarchy::TPM_RH_OWNER;
use crate::library::tpm2::nv::{TPMA_NV_POLICY_DELETE, delete_index, transact};
use crate::library::tpm2::runtime::Tpm2Runtime;

const RC_UNDEFINE_NV_INDEX: TpmResult = TPM_RC_H + TPM_RC_2;
const RC_SPECIAL_NV_INDEX: TpmResult = TPM_RC_H + TPM_RC_1;

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let auth_handle = handle_at(frame, 0)?;
    let nv_handle = handle_at(frame, 1)?;
    if !frame.parameters.is_empty() {
        return Err(TPM_RC_SIZE);
    }

    let resolved = resolve(runtime, nv_handle)?;
    if resolved.attributes() & TPMA_NV_POLICY_DELETE != 0 {
        return Err(TPM_RC_ATTRIBUTES + RC_UNDEFINE_NV_INDEX);
    }
    if auth_handle == TPM_RH_OWNER && resolved.is_platform_created() {
        return Err(TPM_RC_NV_AUTHORIZATION);
    }

    transact(runtime, |runtime| delete_index(runtime, &resolved))?;
    Ok(CommandOutput::empty())
}

pub(in crate::library::tpm2::command) fn execute_special(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let nv_handle = handle_at(frame, 0)?;
    handle_at(frame, 1)?;
    if !frame.parameters.is_empty() {
        return Err(TPM_RC_SIZE);
    }

    let resolved = resolve(runtime, nv_handle)?;
    if resolved.attributes() & TPMA_NV_POLICY_DELETE == 0 {
        return Err(TPM_RC_ATTRIBUTES + RC_SPECIAL_NV_INDEX);
    }

    transact(runtime, |runtime| delete_index(runtime, &resolved))?;
    remove_session_association(runtime, nv_handle);
    Ok(CommandOutput::empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::command::core::registry::{
        CommandLifecycle, HandleKind, NvAccess, TPM_CC_NV_UNDEFINE_SPACE,
        TPM_CC_NV_UNDEFINE_SPACE_SPECIAL, find,
    };
    use crate::library::tpm2::command::core::test_support::{
        RC_SUCCESS, command, dispatch_bytes, response_code, started_runtime,
    };
    use crate::library::tpm2::command::nv::test_support::{
        assert_unchanged, index_handles, nv_public, snapshot,
    };
    use crate::library::tpm2::golden_responses::nv::nv_vector;
    use crate::library::tpm2::hierarchy::TPM_RH_PLATFORM;
    use crate::library::tpm2::nv::{
        NvPublic, TPM_NT_COUNTER, TPMA_NV_ORDERLY, TPMA_NV_OWNERREAD, TPMA_NV_OWNERWRITE,
        TPMA_NV_PLATFORMCREATE, TPMA_NV_PPREAD, TPMA_NV_PPWRITE, TPMA_NV_TPM_NT_SHIFT,
        marshal_sized_nv_public, resolve_index,
    };

    const RC_SIZE: u32 = 0x095;
    const RC_AUTH_TYPE: u32 = 0x124;
    const RC_HANDLE1_ATTRIBUTES: u32 = 0x182;
    const RC_HANDLE2_ATTRIBUTES: u32 = 0x282;
    const RC_HANDLE2_HANDLE: u32 = 0x28b;
    const RC_NV_AUTHORIZATION: u32 = 0x149;
    const RC_NV_UNAVAILABLE: u32 = 0x923;

    const INDEX: u32 = 0x0100_0001;
    const READ_WRITE: u32 = TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD;
    const PLATFORM_INDEX: u32 = 0x0180_0001;

    #[track_caller]
    fn define(runtime: &mut Tpm2Runtime, auth: u32, public: &NvPublic) {
        let mut parameters = 0u16.to_be_bytes().to_vec();
        parameters.extend_from_slice(&marshal_sized_nv_public(public));
        assert_eq!(
            response_code(&dispatch_bytes(
                runtime,
                &command(0x0000_012a, &[auth], &[&[]], &parameters),
            )),
            RC_SUCCESS,
            "the index is defined"
        );
    }

    fn platform_public(attributes: u32) -> NvPublic {
        nv_public(
            PLATFORM_INDEX,
            attributes | TPMA_NV_PLATFORMCREATE | TPMA_NV_PPREAD | TPMA_NV_PPWRITE,
            8,
        )
    }

    #[track_caller]
    fn undefine(runtime: &mut Tpm2Runtime, auth: u32, index: u32) -> Vec<u8> {
        dispatch_bytes(
            runtime,
            &command(TPM_CC_NV_UNDEFINE_SPACE, &[auth, index], &[&[]], &[]),
        )
    }

    #[test]
    fn the_undefine_command_attributes_match_the_oracle() {
        for (code, oracle, pp) in [
            (TPM_CC_NV_UNDEFINE_SPACE, nv_vector("CCATTR_0122"), true),
            (
                TPM_CC_NV_UNDEFINE_SPACE_SPECIAL,
                nv_vector("CCATTR_011F"),
                true,
            ),
        ] {
            let expected = oracle;
            let attributes = u32::from_be_bytes(expected[19..23].try_into().unwrap());
            let descriptor = find(code).expect("a registered command");
            assert_eq!(descriptor.attributes, attributes, "code {code:#x}");
            assert_ne!(descriptor.attributes & (1 << 22), 0, "code {code:#x}");
            assert_eq!((descriptor.attributes >> 25) & 0x7, 2, "code {code:#x}");
            assert_eq!(descriptor.physical_presence, pp);
            assert!(descriptor.sessions_allowed);
            assert!(matches!(descriptor.nv_access, NvAccess::Neither));
            assert!(matches!(
                descriptor.lifecycle,
                CommandLifecycle::RequiresStarted
            ));
        }
    }

    #[test]
    fn the_undefine_handles_carry_the_upstream_roles() {
        let descriptor = find(TPM_CC_NV_UNDEFINE_SPACE).unwrap();
        assert_eq!(descriptor.handles.len(), 2);
        assert!(descriptor.handles[0].user_auth);
        assert!(!descriptor.handles[0].admin_role());
        assert!(!descriptor.handles[1].user_auth);
        assert!(matches!(descriptor.handles[0].kind, HandleKind::Provision));
        assert!(matches!(descriptor.handles[1].kind, HandleKind::NvIndex));

        let special = find(TPM_CC_NV_UNDEFINE_SPACE_SPECIAL).unwrap();
        assert_eq!(special.handles.len(), 2);
        assert!(special.handles[0].user_auth);
        assert!(
            special.handles[0].admin_role(),
            "the index is authorized with the ADMIN role"
        );
        assert!(special.handles[1].user_auth);
        assert!(matches!(special.handles[0].kind, HandleKind::NvIndex));
        assert!(matches!(special.handles[1].kind, HandleKind::Platform));
    }

    #[test]
    fn an_owner_index_is_deleted_and_the_others_survive() {
        let mut runtime = started_runtime();
        define(
            &mut runtime,
            TPM_RH_OWNER,
            &nv_public(INDEX, READ_WRITE, 32),
        );
        define(
            &mut runtime,
            TPM_RH_OWNER,
            &nv_public(0x0100_0002, READ_WRITE, 8),
        );
        assert_eq!(
            undefine(&mut runtime, TPM_RH_OWNER, INDEX),
            nv_vector("UNDEFINE_OWNER")
        );
        assert!(resolve_index(&runtime, INDEX).is_none());
        assert_eq!(index_handles(&runtime), [0x0100_0002]);
        assert!(runtime.nv_update_pending);
    }

    #[test]
    fn an_undefined_index_is_reported_against_its_own_handle() {
        let mut runtime = started_runtime();
        assert_eq!(
            undefine(&mut runtime, TPM_RH_OWNER, INDEX),
            nv_vector("UNDEFINE_MISSING")
        );
        assert_eq!(
            response_code(&undefine(&mut runtime, TPM_RH_OWNER, INDEX)),
            RC_HANDLE2_HANDLE
        );
    }

    #[test]
    fn the_owner_may_not_delete_a_platform_created_index() {
        let mut runtime = started_runtime();
        define(&mut runtime, TPM_RH_PLATFORM, &platform_public(0));
        assert_eq!(
            undefine(&mut runtime, TPM_RH_OWNER, PLATFORM_INDEX),
            nv_vector("PLATFORM_UNDEFINE_BY_OWNER")
        );
        assert_eq!(
            response_code(&undefine(&mut runtime, TPM_RH_OWNER, PLATFORM_INDEX)),
            RC_NV_AUTHORIZATION
        );
        assert_eq!(
            undefine(&mut runtime, TPM_RH_PLATFORM, PLATFORM_INDEX),
            nv_vector("PLATFORM_UNDEFINE_BY_PLATFORM"),
            "the platform may delete its own index"
        );
    }

    #[test]
    fn the_platform_may_delete_an_owner_created_index() {
        let mut runtime = started_runtime();
        define(&mut runtime, TPM_RH_OWNER, &nv_public(INDEX, READ_WRITE, 8));
        assert_eq!(
            response_code(&undefine(&mut runtime, TPM_RH_PLATFORM, INDEX)),
            RC_SUCCESS
        );
    }

    #[test]
    fn a_policy_delete_index_refuses_the_ordinary_undefine() {
        let mut runtime = started_runtime();
        define(
            &mut runtime,
            TPM_RH_PLATFORM,
            &platform_public(TPMA_NV_POLICY_DELETE),
        );
        assert_eq!(
            undefine(&mut runtime, TPM_RH_PLATFORM, PLATFORM_INDEX),
            nv_vector("POLICY_DELETE_UNDEFINE_IS_ATTRIBUTES")
        );
        assert_eq!(
            response_code(&undefine(&mut runtime, TPM_RH_PLATFORM, PLATFORM_INDEX)),
            RC_HANDLE2_ATTRIBUTES
        );
        assert!(resolve_index(&runtime, PLATFORM_INDEX).is_some());
    }

    #[test]
    fn undefine_special_needs_a_policy_session_for_the_index() {
        let mut runtime = started_runtime();
        runtime.live.da_used = true;
        define(
            &mut runtime,
            TPM_RH_PLATFORM,
            &platform_public(TPMA_NV_POLICY_DELETE),
        );
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &command(
                    TPM_CC_NV_UNDEFINE_SPACE_SPECIAL,
                    &[PLATFORM_INDEX, TPM_RH_PLATFORM],
                    &[&[], &[]],
                    &[],
                ),
            ),
            nv_vector("UNDEFINE_SPECIAL_PASSWORD_SESSIONS")
        );
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &command(
                    TPM_CC_NV_UNDEFINE_SPACE_SPECIAL,
                    &[PLATFORM_INDEX, TPM_RH_PLATFORM],
                    &[&[], &[]],
                    &[],
                ),
            )),
            RC_AUTH_TYPE
        );
        assert!(
            resolve_index(&runtime, PLATFORM_INDEX).is_some(),
            "the index survives an unauthorized deletion"
        );
    }

    #[test]
    fn undefine_special_rejects_an_index_without_policy_delete() {
        let mut runtime = started_runtime();
        define(&mut runtime, TPM_RH_PLATFORM, &platform_public(0));
        let frame = CommandFrame {
            handles: vec![PLATFORM_INDEX, TPM_RH_PLATFORM],
            parameters: &[],
        };
        assert_eq!(
            execute_special(&mut runtime, &frame).err(),
            Some(RC_HANDLE1_ATTRIBUTES)
        );
    }

    #[test]
    fn undefine_special_deletes_a_policy_delete_index() {
        let mut runtime = started_runtime();
        define(
            &mut runtime,
            TPM_RH_PLATFORM,
            &platform_public(TPMA_NV_POLICY_DELETE),
        );
        let frame = CommandFrame {
            handles: vec![PLATFORM_INDEX, TPM_RH_PLATFORM],
            parameters: &[],
        };
        assert!(execute_special(&mut runtime, &frame).is_ok());
        assert!(resolve_index(&runtime, PLATFORM_INDEX).is_none());
        assert!(runtime.nv_update_pending);
    }

    #[test]
    fn undefine_special_rejects_trailing_parameters() {
        let mut runtime = started_runtime();
        define(
            &mut runtime,
            TPM_RH_PLATFORM,
            &platform_public(TPMA_NV_POLICY_DELETE),
        );
        let frame = CommandFrame {
            handles: vec![PLATFORM_INDEX, TPM_RH_PLATFORM],
            parameters: &[0x00],
        };
        assert_eq!(execute_special(&mut runtime, &frame).err(), Some(RC_SIZE));
    }

    #[test]
    fn deleting_an_orderly_index_frees_its_ram_slot() {
        let mut runtime = started_runtime();
        define(
            &mut runtime,
            TPM_RH_OWNER,
            &nv_public(INDEX, READ_WRITE | TPMA_NV_ORDERLY, 8),
        );
        define(
            &mut runtime,
            TPM_RH_OWNER,
            &nv_public(0x0100_0002, READ_WRITE | TPMA_NV_ORDERLY, 8),
        );
        assert_eq!(runtime.live.index_orderly_ram.entries.len(), 2);
        assert_eq!(
            response_code(&undefine(&mut runtime, TPM_RH_OWNER, INDEX)),
            RC_SUCCESS
        );
        assert_eq!(runtime.live.index_orderly_ram.entries.len(), 1);
        assert_eq!(
            runtime.live.index_orderly_ram.entries[0].handle,
            0x0100_0002
        );
        assert_eq!(
            runtime.state().index_orderly_ram.entries.len(),
            1,
            "the RAM image is written back to NV"
        );
    }

    #[test]
    fn deleting_a_written_counter_raises_the_max_counter() {
        let mut runtime = started_runtime();
        define(
            &mut runtime,
            TPM_RH_OWNER,
            &nv_public(
                INDEX,
                READ_WRITE | (TPM_NT_COUNTER << TPMA_NV_TPM_NT_SHIFT),
                8,
            ),
        );
        for _ in 0..3 {
            assert_eq!(
                response_code(&dispatch_bytes(
                    &mut runtime,
                    &command(0x0000_0134, &[TPM_RH_OWNER, INDEX], &[&[]], &[]),
                )),
                RC_SUCCESS
            );
        }
        assert_eq!(
            response_code(&undefine(&mut runtime, TPM_RH_OWNER, INDEX)),
            RC_SUCCESS
        );
        assert_eq!(runtime.live.max_nv_counter, 3);
        assert_eq!(runtime.state().user_nvram.max_count, 3);
    }

    #[test]
    fn trailing_parameter_bytes_are_a_size_error() {
        let mut runtime = started_runtime();
        define(&mut runtime, TPM_RH_OWNER, &nv_public(INDEX, READ_WRITE, 8));
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &command(
                    TPM_CC_NV_UNDEFINE_SPACE,
                    &[TPM_RH_OWNER, INDEX],
                    &[&[]],
                    &[0x00],
                ),
            )),
            RC_SIZE
        );
    }

    #[test]
    fn a_failed_deletion_leaves_no_trace() {
        let mut runtime = started_runtime();
        define(
            &mut runtime,
            TPM_RH_OWNER,
            &nv_public(INDEX, READ_WRITE, 32),
        );
        runtime.nv_update_pending = false;
        runtime.nv_available = false;
        let before = snapshot(&runtime);
        assert_eq!(
            response_code(&undefine(&mut runtime, TPM_RH_OWNER, INDEX)),
            RC_NV_UNAVAILABLE
        );
        assert_unchanged(&runtime, &before);
        assert!(resolve_index(&runtime, INDEX).is_some());
    }

    #[test]
    fn a_deleted_index_stays_deleted_across_a_state_round_trip() {
        use crate::library::tpm2::persistent::persistent_all_store;
        use crate::library::tpm2::restore_permanent_blob_for_test;

        let mut runtime = started_runtime();
        define(
            &mut runtime,
            TPM_RH_OWNER,
            &nv_public(INDEX, READ_WRITE, 32),
        );
        define(
            &mut runtime,
            TPM_RH_OWNER,
            &nv_public(0x0100_0002, READ_WRITE, 8),
        );
        assert_eq!(
            response_code(&undefine(&mut runtime, TPM_RH_OWNER, INDEX)),
            RC_SUCCESS
        );
        let blob = persistent_all_store(runtime.state()).expect("the state serializes");
        let reloaded = restore_permanent_blob_for_test(&blob).expect("the blob restores");
        assert_eq!(index_handles(&reloaded), [0x0100_0002]);
    }
}
