use crate::ffi_types::TpmResult;
use crate::library::constants::{
    TPM_RC_FAILURE, TPM_RC_HASH, TPM_RC_NV_UNAVAILABLE, TPM_RC_SIZE, TPM_RC_VALUE,
};

use super::super::algorithm::{algorithm_enabled, hash_profile_name};
use super::super::capability::commands::MAX_CAP_CC;
use super::super::profile::ValidatedProfile;
use super::super::public::TPM_ALG_NULL;
use super::super::runtime::Tpm2Runtime;
use super::super::template::{TemplateReader, digest_size};
use super::command_audit::{audit_hash_alg, clear_command, mark_algorithm_change, set_command};
use super::dispatcher::CommandFrame;
use super::nv_common::{TPM_RC_1, TPM_RC_2, TPM_RC_3, TPM_RC_P};
use super::output::CommandOutput;

const RC_AUDIT_ALG: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_SET_LIST: TpmResult = TPM_RC_P + TPM_RC_2;
const RC_CLEAR_LIST: TpmResult = TPM_RC_P + TPM_RC_3;

struct Parameters {
    audit_alg: u16,
    set_list: Vec<u32>,
    clear_list: Vec<u32>,
}

pub(super) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let parameters = parse_parameters(
        frame.parameters,
        &runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?.profile,
    )?;
    if !runtime.nv_available {
        return Err(TPM_RC_NV_UNAVAILABLE);
    }

    let current = audit_hash_alg(runtime)?;
    if parameters.audit_alg != TPM_ALG_NULL && parameters.audit_alg != current {
        if !parameters.set_list.is_empty() || !parameters.clear_list.is_empty() {
            return Err(TPM_RC_VALUE + RC_AUDIT_ALG);
        }
        return change_algorithm(runtime, parameters.audit_alg);
    }

    let mut bitmap = super::command_audit::audit_bitmap(runtime)?;
    let profile_commands = runtime
        .state
        .as_ref()
        .ok_or(TPM_RC_FAILURE)?
        .profile
        .commands
        .clone();
    let mut changed = false;
    for &code in &parameters.set_list {
        changed |= set_command(&mut bitmap, &profile_commands, code);
    }
    for &code in &parameters.clear_list {
        changed |= clear_command(&mut bitmap, &profile_commands, code);
    }
    if changed {
        super::command_audit::store_bitmap(runtime, bitmap)?;
    }
    Ok(CommandOutput::empty())
}

fn change_algorithm(runtime: &mut Tpm2Runtime, audit_alg: u16) -> Result<CommandOutput, TpmResult> {
    let state = runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?;
    let backup = state.persistent.audit_hash_alg;
    state.persistent.audit_hash_alg = audit_alg;
    match super::super::nv::build_nv_image(state) {
        Ok(image) => runtime.nv_memory = image,
        Err(_) => {
            state.persistent.audit_hash_alg = backup;
            return Err(TPM_RC_FAILURE);
        }
    }
    runtime.nv_update_pending = true;
    mark_algorithm_change(runtime)?;
    Ok(CommandOutput::empty())
}

fn parse_parameters(
    parameters: &[u8],
    profile: &ValidatedProfile,
) -> Result<Parameters, TpmResult> {
    let mut reader = TemplateReader::new(parameters);
    let audit_alg = parse_audit_alg(&mut reader, profile)?;
    let set_list = parse_command_list(&mut reader, RC_SET_LIST)?;
    let clear_list = parse_command_list(&mut reader, RC_CLEAR_LIST)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(Parameters {
        audit_alg,
        set_list,
        clear_list,
    })
}

fn parse_audit_alg(
    reader: &mut TemplateReader<'_>,
    profile: &ValidatedProfile,
) -> Result<u16, TpmResult> {
    let audit_alg = reader.u16().map_err(|code| code + RC_AUDIT_ALG)?;
    if audit_alg == TPM_ALG_NULL {
        return Ok(audit_alg);
    }
    let enabled = digest_size(audit_alg).is_some()
        && hash_profile_name(audit_alg)
            .is_some_and(|name| algorithm_enabled(&profile.algorithms, name));
    if !enabled {
        return Err(TPM_RC_HASH + RC_AUDIT_ALG);
    }
    Ok(audit_alg)
}

fn parse_command_list(
    reader: &mut TemplateReader<'_>,
    error_index: TpmResult,
) -> Result<Vec<u32>, TpmResult> {
    let count = reader.u32().map_err(|code| code + error_index)?;
    if count > MAX_CAP_CC as u32 {
        return Err(TPM_RC_SIZE + error_index);
    }
    let mut codes = Vec::with_capacity(count as usize);
    for _ in 0..count {
        codes.push(reader.u32().map_err(|code| code + error_index)?);
    }
    Ok(codes)
}

#[cfg(test)]
mod tests {
    use super::super::attest::harness::*;
    use super::super::command_audit::{audit_bitmap, command_index, is_required};
    use super::super::nv_common::harness::{RC_SUCCESS, assert_matches_oracle, response_code};
    use super::super::registry::{
        CommandLifecycle, HandleKind, NvAccess, TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS,
        TPM_CC_SHUTDOWN, find,
    };
    use crate::library::tpm2::golden_responses::attestation::vector;
    use crate::library::tpm2::runtime::Tpm2Runtime;

    const RC_HANDLE1_VALUE: u32 = 0x184;
    const RC_PARAM1_HASH: u32 = 0x1c3;
    const RC_PARAM1_VALUE: u32 = 0x1c4;
    const RC_PARAM2_SIZE: u32 = 0x2d5;
    const RC_PARAM2_INSUFFICIENT: u32 = 0x2da;
    const RC_SIZE: u32 = 0x095;
    const RC_NV_UNAVAILABLE: u32 = 0x923;

    fn audit_status(auth: u32, audit_alg: u16, set_list: &[u32], clear_list: &[u32]) -> Vec<u8> {
        let mut parameters = audit_alg.to_be_bytes().to_vec();
        parameters.extend_from_slice(&(set_list.len() as u32).to_be_bytes());
        for code in set_list {
            parameters.extend_from_slice(&code.to_be_bytes());
        }
        parameters.extend_from_slice(&(clear_list.len() as u32).to_be_bytes());
        for code in clear_list {
            parameters.extend_from_slice(&code.to_be_bytes());
        }
        command(
            TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS,
            &[auth],
            Some(&[pw()]),
            &parameters,
        )
    }

    #[track_caller]
    fn audit_runtime() -> Box<Tpm2Runtime> {
        let mut runtime = ready_runtime();
        run_ok(
            &mut runtime,
            &create_primary(
                TPM_RH_ENDORSEMENT,
                &rsa_template(ALG_RSASSA, ALG_SHA256, SIGN_ATTRS),
            ),
            "the attestation key is created",
        );
        assert_matches_oracle(&runtime, vector("PERMALL_AUDIT_BASE"), "before auditing");
        runtime
    }

    #[test]
    fn the_command_attributes_match_the_oracle() {
        let expected = vector("CCATTR_0140");
        let attributes = u32::from_be_bytes(expected[19..23].try_into().expect("four bytes"));
        assert_eq!(TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS, 0x0000_0140);
        let descriptor = find(TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS).expect("a registered command");
        assert_eq!(descriptor.attributes, attributes);
        assert_eq!(descriptor.attributes, 0x0240_0140);
        assert_eq!(
            descriptor.attributes & (1 << 22),
            1 << 22,
            "TPM2_SetCommandCodeAuditStatus writes NV"
        );
        assert_eq!(descriptor.decrypt_size, 0);
        assert_eq!(descriptor.encrypt_size, 0);
        assert!(descriptor.physical_presence);
        assert!(matches!(descriptor.nv_access, NvAccess::Neither));
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
        assert_eq!(descriptor.handles.len(), 1);
        assert!(descriptor.handles[0].user_auth && !descriptor.handles[0].admin_role());
        assert!(matches!(descriptor.handles[0].kind, HandleKind::Provision));
    }

    #[test]
    fn adding_a_command_records_the_reference_state() {
        let mut runtime = audit_runtime();
        assert!(!is_required(&runtime, CC_GET_RANDOM));
        assert_eq!(
            run(
                &mut runtime,
                &audit_status(TPM_RH_OWNER, ALG_NULL, &[CC_GET_RANDOM], &[])
            ),
            vector("AUDIT_STATUS_ADD_GETRANDOM")
        );
        assert!(is_required(&runtime, CC_GET_RANDOM));
        assert_matches_oracle(
            &runtime,
            vector("PERMALL_AUDIT_AFTER_SET"),
            "after adding TPM2_GetRandom",
        );
        assert!(runtime.nv_update_pending, "the NV image was queued");
    }

    #[test]
    fn clearing_a_command_records_the_reference_state() {
        let mut runtime = audit_runtime();
        run_ok(
            &mut runtime,
            &audit_status(TPM_RH_OWNER, ALG_NULL, &[CC_GET_RANDOM], &[]),
            "the command is audited",
        );
        assert_eq!(
            run(
                &mut runtime,
                &audit_status(TPM_RH_OWNER, ALG_NULL, &[], &[CC_GET_RANDOM])
            ),
            vector("AUDIT_STATUS_CLEAR_GETRANDOM")
        );
        assert!(!is_required(&runtime, CC_GET_RANDOM));
        assert_matches_oracle(
            &runtime,
            vector("PERMALL_AUDIT_AFTER_CLEAR"),
            "after clearing TPM2_GetRandom",
        );
    }

    #[test]
    fn the_audit_algorithm_may_be_changed_on_its_own() {
        let mut runtime = audit_runtime();
        assert_eq!(
            run(
                &mut runtime,
                &audit_status(TPM_RH_OWNER, ALG_SHA256, &[], &[])
            ),
            vector("AUDIT_STATUS_ALG_SHA256")
        );
        assert_eq!(runtime.state().persistent.audit_hash_alg, ALG_SHA256);
        assert_matches_oracle(
            &runtime,
            vector("PERMALL_AUDIT_ALG_SHA256"),
            "after changing the audit algorithm",
        );
        assert_eq!(
            run(
                &mut runtime,
                &audit_status(TPM_RH_OWNER, ALG_SHA256, &[], &[])
            ),
            vector("AUDIT_STATUS_ALG_AGAIN"),
            "repeating the current algorithm takes the list branch"
        );
    }

    #[test]
    fn an_algorithm_change_may_not_carry_a_command_list() {
        let mut runtime = audit_runtime();
        assert_eq!(
            run(
                &mut runtime,
                &audit_status(TPM_RH_OWNER, ALG_SHA256, &[CC_GET_RANDOM], &[])
            ),
            vector("AUDIT_STATUS_ALG_AND_LIST")
        );
        assert_eq!(
            response_code(vector("AUDIT_STATUS_ALG_AND_LIST")),
            RC_PARAM1_VALUE
        );
        assert_matches_oracle(&runtime, vector("PERMALL_AUDIT_BASE"), "after the refusal");
    }

    #[test]
    fn an_unsupported_audit_algorithm_is_a_hash_error() {
        let mut runtime = audit_runtime();
        assert_eq!(
            run(
                &mut runtime,
                &audit_status(TPM_RH_OWNER, ALG_HMAC, &[], &[])
            ),
            vector("AUDIT_STATUS_BAD_ALG")
        );
        assert_eq!(
            response_code(vector("AUDIT_STATUS_BAD_ALG")),
            RC_PARAM1_HASH
        );
    }

    #[test]
    fn the_lists_that_change_nothing_leave_the_state_alone() {
        for (record, permall, set_list, clear_list) in [
            (
                "AUDIT_STATUS_UNREMOVABLE",
                "PERMALL_AUDIT_UNREMOVABLE",
                &[][..],
                &[TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS][..],
            ),
            (
                "AUDIT_STATUS_SHUTDOWN",
                "PERMALL_AUDIT_SHUTDOWN",
                &[TPM_CC_SHUTDOWN][..],
                &[][..],
            ),
            (
                "AUDIT_STATUS_UNIMPLEMENTED",
                "PERMALL_AUDIT_UNIMPLEMENTED",
                &[0x0000_0123, 0x2000_ffff][..],
                &[][..],
            ),
            (
                "AUDIT_STATUS_BOTH_LISTS",
                "PERMALL_AUDIT_BOTH_LISTS",
                &[CC_GET_RANDOM][..],
                &[CC_GET_RANDOM][..],
            ),
        ] {
            let mut runtime = audit_runtime();
            assert_eq!(
                run(
                    &mut runtime,
                    &audit_status(TPM_RH_OWNER, ALG_NULL, set_list, clear_list)
                ),
                vector(record),
                "{record}"
            );
            assert_matches_oracle(&runtime, vector(permall), record);
        }
    }

    #[test]
    fn empty_lists_change_no_command_bit() {
        let mut runtime = audit_runtime();
        let before = audit_bitmap(&runtime).expect("the bitmap reads");
        assert_eq!(
            run(
                &mut runtime,
                &audit_status(TPM_RH_OWNER, ALG_NULL, &[], &[])
            ),
            vector("AUDIT_STATUS_EMPTY_LISTS")
        );
        assert_eq!(
            audit_bitmap(&runtime).expect("the bitmap reads"),
            before,
            "no command bit moved"
        );
    }

    #[test]
    fn a_duplicated_command_is_set_once() {
        let mut runtime = audit_runtime();
        assert_eq!(
            run(
                &mut runtime,
                &audit_status(TPM_RH_OWNER, ALG_NULL, &[CC_GET_RANDOM, CC_GET_RANDOM], &[])
            ),
            vector("AUDIT_STATUS_DUPLICATES")
        );
        assert_matches_oracle(
            &runtime,
            vector("PERMALL_AUDIT_DUPLICATES"),
            "after the duplicated set list",
        );
        assert!(is_required(&runtime, CC_GET_RANDOM));
    }

    #[test]
    fn the_x509_certification_command_joins_the_audit_bitmap() {
        let mut runtime = audit_runtime();
        assert_eq!(
            run(
                &mut runtime,
                &audit_status(TPM_RH_OWNER, ALG_NULL, &[0x0000_0197], &[])
            ),
            vector("AUDIT_STATUS_UNREGISTERED_UPSTREAM")
        );
        assert_matches_oracle(
            &runtime,
            vector("PERMALL_AUDIT_UNREGISTERED"),
            "TPM2_CertifyX509 is enabled by the profile",
        );
        assert!(
            find(0x0000_0197).is_some(),
            "the registry implements TPM2_CertifyX509"
        );
        let bitmap = audit_bitmap(&runtime).expect("the bitmap reads");
        let index = command_index(0x0000_0197).expect("an upstream command index");
        assert_ne!(bitmap[index / 8] & (1 << (index % 8)), 0);
    }

    #[test]
    fn both_provision_hierarchies_may_authorize_the_change() {
        let mut runtime = audit_runtime();
        assert_eq!(
            run(
                &mut runtime,
                &audit_status(TPM_RH_PLATFORM, ALG_NULL, &[CC_GET_RANDOM], &[])
            ),
            vector("AUDIT_STATUS_PLATFORM")
        );
        let mut runtime = audit_runtime();
        assert_eq!(
            run(
                &mut runtime,
                &audit_status(TPM_RH_ENDORSEMENT, ALG_NULL, &[CC_GET_RANDOM], &[])
            ),
            vector("AUDIT_STATUS_ENDORSEMENT")
        );
        assert_eq!(
            response_code(vector("AUDIT_STATUS_ENDORSEMENT")),
            RC_HANDLE1_VALUE
        );
    }

    #[test]
    fn the_parameter_limits_match_the_oracle() {
        let mut runtime = audit_runtime();
        let mut trailing = audit_status(TPM_RH_OWNER, ALG_NULL, &[], &[]);
        trailing.push(0x00);
        let size = (trailing.len() as u32).to_be_bytes();
        trailing[2..6].copy_from_slice(&size);
        assert_eq!(
            run(&mut runtime, &trailing),
            vector("AUDIT_STATUS_TRAILING")
        );

        let mut truncated = ALG_NULL.to_be_bytes().to_vec();
        truncated.extend_from_slice(&1u32.to_be_bytes());
        assert_eq!(
            run(
                &mut runtime,
                &command(
                    TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS,
                    &[TPM_RH_OWNER],
                    Some(&[pw()]),
                    &truncated
                )
            ),
            vector("AUDIT_STATUS_TRUNCATED")
        );

        let mut huge = ALG_NULL.to_be_bytes().to_vec();
        huge.extend_from_slice(&255u32.to_be_bytes());
        huge.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(
            run(
                &mut runtime,
                &command(
                    TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS,
                    &[TPM_RH_OWNER],
                    Some(&[pw()]),
                    &huge
                )
            ),
            vector("AUDIT_STATUS_HUGE_LIST")
        );

        assert_eq!(response_code(vector("AUDIT_STATUS_TRAILING")), RC_SIZE);
        assert_eq!(
            response_code(vector("AUDIT_STATUS_TRUNCATED")),
            RC_PARAM2_INSUFFICIENT
        );
        assert_eq!(
            response_code(vector("AUDIT_STATUS_HUGE_LIST")),
            RC_PARAM2_SIZE
        );
    }

    #[test]
    fn an_unavailable_nv_refuses_the_change() {
        let mut runtime = audit_runtime();
        runtime.nv_available = false;
        let before = crate::library::tpm2::persistent::persistent_all_store(runtime.state())
            .expect("the state serializes");
        assert_eq!(
            response_code(&run(
                &mut runtime,
                &audit_status(TPM_RH_OWNER, ALG_NULL, &[CC_GET_RANDOM], &[])
            )),
            RC_NV_UNAVAILABLE
        );
        assert_eq!(
            crate::library::tpm2::persistent::persistent_all_store(runtime.state())
                .expect("the state serializes"),
            before
        );
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn a_failed_host_commit_rolls_the_change_back() {
        use crate::library::tpm2::nv::build_nv_image;
        let mut runtime = audit_runtime();
        runtime
            .state
            .as_mut()
            .expect("state")
            .persistent
            .owner_policy = vec![0x5a; 4096];
        assert!(build_nv_image(runtime.state()).is_err());
        let before = runtime.state().persistent.audit_hash_alg;
        let nv_memory_before = runtime.nv_memory.clone();
        assert_eq!(
            response_code(&run(
                &mut runtime,
                &audit_status(TPM_RH_OWNER, ALG_SHA256, &[], &[])
            )),
            0x101,
            "the host commit failure is a TPM failure"
        );
        assert_eq!(runtime.state().persistent.audit_hash_alg, before);
        assert_eq!(runtime.nv_memory, nv_memory_before);
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn parameter_mutations_do_not_panic() {
        let mut full = ALG_SHA256.to_be_bytes().to_vec();
        full.extend_from_slice(&1u32.to_be_bytes());
        full.extend_from_slice(&CC_GET_RANDOM.to_be_bytes());
        full.extend_from_slice(&1u32.to_be_bytes());
        full.extend_from_slice(&CC_GET_RANDOM.to_be_bytes());
        for index in 0..full.len() {
            for byte in [0x00u8, 0x01, 0x7f, 0xff] {
                let mut parameters = full.clone();
                parameters[index] = byte;
                let mut runtime = ready_runtime();
                let response = run(
                    &mut runtime,
                    &command(
                        TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS,
                        &[TPM_RH_OWNER],
                        Some(&[pw()]),
                        &parameters,
                    ),
                );
                assert!(response.len() >= 10);
                let _ = response_code(&response) == RC_SUCCESS;
            }
        }
    }
}
