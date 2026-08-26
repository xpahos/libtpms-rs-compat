use crate::ffi_types::TpmResult;
use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_SCHEME, TPM_RC_SIZE};

use super::super::hierarchy::TPM_RH_NULL;
use super::super::profile::ValidatedProfile;
use super::super::runtime::Tpm2Runtime;
use super::super::signature::{SigScheme, select_sign_scheme};
use super::super::template::TemplateReader;
use super::attest::{
    Attested, attestation_response, check_signing_object, fill_in_attest_info,
    parse_qualifying_data, parse_scheme, sign_attest_info,
};
use super::command_audit::{
    audit_counter, audit_digest, audit_hash_alg, command_list_digest, reset_digest,
};
use super::dispatcher::CommandFrame;
use super::nv_common::{TPM_RC_1, TPM_RC_2, TPM_RC_H, TPM_RC_P, handle_at};
use super::output::CommandOutput;
use super::signing::signing_object;

const RC_SIGN_HANDLE: TpmResult = TPM_RC_H + TPM_RC_2;
const RC_QUALIFYING_DATA: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_IN_SCHEME: TpmResult = TPM_RC_P + TPM_RC_2;

struct Parameters {
    qualifying_data: Vec<u8>,
    scheme: SigScheme,
}

pub(super) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let sign_handle = handle_at(frame, 1)?;
    let parameters = parse_parameters(
        frame.parameters,
        &runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?.profile,
    )?;

    let sign_object = signing_object(runtime, sign_handle)?;
    check_signing_object(sign_object.as_deref(), RC_SIGN_HANDLE)?;
    let scheme = select_sign_scheme(sign_object.as_deref(), parameters.scheme)
        .ok_or(TPM_RC_SCHEME + RC_IN_SCHEME)?;

    let attested = Attested::CommandAudit {
        audit_counter: audit_counter(runtime)?,
        digest_alg: audit_hash_alg(runtime)?,
        audit_digest: audit_digest(runtime)?,
        command_digest: command_list_digest(runtime)?,
    };
    let attest = fill_in_attest_info(
        runtime,
        sign_object.as_deref(),
        &scheme,
        &parameters.qualifying_data,
        attested,
    )?;
    let (attestation_data, signature) =
        sign_attest_info(runtime, sign_object.as_deref(), &scheme, &attest)?;
    if sign_handle != TPM_RH_NULL {
        reset_digest(runtime)?;
    }
    attestation_response(&attestation_data, &signature)
}

fn parse_parameters(
    parameters: &[u8],
    profile: &ValidatedProfile,
) -> Result<Parameters, TpmResult> {
    let mut reader = TemplateReader::new(parameters);
    let qualifying_data = parse_qualifying_data(&mut reader, RC_QUALIFYING_DATA)?;
    let scheme = parse_scheme(&mut reader, profile, RC_IN_SCHEME)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(Parameters {
        qualifying_data,
        scheme,
    })
}

#[cfg(test)]
mod tests {
    use super::super::attest::harness::*;
    use super::super::command_audit::{audit_digest, command_list_digest};
    use super::super::nv_common::harness::{RC_SUCCESS, assert_matches_oracle, response_code};
    use super::super::registry::{
        CommandLifecycle, HandleKind, NvAccess, TPM_CC_GET_COMMAND_AUDIT_DIGEST,
        TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS, find,
    };
    use crate::library::tpm2::golden_responses::attestation::vector;
    use crate::library::tpm2::runtime::Tpm2Runtime;

    const RC_HANDLE1_VALUE: u32 = 0x184;
    const RC_SIZE: u32 = 0x095;

    fn digest_command(privacy: u32, sign: u32, scheme: u16) -> Vec<u8> {
        let mut parameters = tpm2b(&QUALIFY);
        parameters.extend_from_slice(&sig_scheme(scheme, ALG_SHA256));
        command(
            TPM_CC_GET_COMMAND_AUDIT_DIGEST,
            &[privacy, sign],
            Some(&[pw(), pw()]),
            &parameters,
        )
    }

    fn audit_status(audit_alg: u16, set_list: &[u32], clear_list: &[u32]) -> Vec<u8> {
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
            &[TPM_RH_OWNER],
            Some(&[pw()]),
            &parameters,
        )
    }

    fn get_random() -> Vec<u8> {
        command(CC_GET_RANDOM, &[], None, &4u16.to_be_bytes())
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
        runtime
    }

    #[track_caller]
    fn getrandom_audited() -> Box<Tpm2Runtime> {
        let mut runtime = audit_runtime();
        assert_eq!(
            run(&mut runtime, &audit_status(ALG_NULL, &[CC_GET_RANDOM], &[])),
            vector("AUDIT_STATUS_ADD_GETRANDOM")
        );
        runtime
    }

    #[test]
    fn the_command_attributes_match_the_oracle() {
        let expected = vector("CCATTR_0133");
        let attributes = u32::from_be_bytes(expected[19..23].try_into().expect("four bytes"));
        assert_eq!(TPM_CC_GET_COMMAND_AUDIT_DIGEST, 0x0000_0133);
        let descriptor = find(TPM_CC_GET_COMMAND_AUDIT_DIGEST).expect("a registered command");
        assert_eq!(descriptor.attributes, attributes);
        assert_eq!(descriptor.attributes, 0x0440_0133);
        assert_eq!(descriptor.decrypt_size, 2);
        assert_eq!(descriptor.encrypt_size, 2);
        assert!(!descriptor.physical_presence);
        assert!(matches!(descriptor.nv_access, NvAccess::Neither));
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
        assert_eq!(descriptor.handles.len(), 2);
        assert!(descriptor.handles.iter().all(|spec| spec.user_auth));
        assert!(descriptor.handles.iter().all(|spec| !spec.admin_role()));
        assert!(matches!(
            descriptor.handles[0].kind,
            HandleKind::Endorsement
        ));
        assert!(matches!(
            descriptor.handles[1].kind,
            HandleKind::ObjectAllowNull
        ));
    }

    #[test]
    fn an_untouched_log_attests_an_empty_digest() {
        let mut runtime = audit_runtime();
        let expected = vector("CMD_AUDIT_DIGEST_EMPTY");
        replay_clock(&mut runtime, expected);
        assert_eq!(
            run(
                &mut runtime,
                &digest_command(TPM_RH_ENDORSEMENT, KEY0, ALG_NULL)
            ),
            expected
        );
        let body = attested_body(&attested_bytes(expected));
        assert_eq!(&body[..8], &0u64.to_be_bytes(), "the audit counter is zero");
        assert_eq!(&body[8..10], &0x000du16.to_be_bytes(), "SHA-512 by default");
        assert_eq!(&body[10..12], &[0x00, 0x00], "the audit digest is empty");
    }

    #[test]
    fn the_command_list_digest_covers_the_audited_commands() {
        use crate::library::tpm2::crypto::Hasher;
        let mut runtime = audit_runtime();
        let expected = vector("CMD_AUDIT_DIGEST_EMPTY");
        let body = attested_body(&attested_bytes(expected));
        let list_len = u16::from_be_bytes([body[12], body[13]]) as usize;
        let list_digest = &body[14..14 + list_len];
        assert_eq!(body.len(), 14 + list_len);

        let mut hasher = Hasher::new(0x000d).expect("a compiled hash");
        hasher.update(&TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS.to_be_bytes());
        assert_eq!(
            list_digest,
            &hasher.finalize()[..],
            "only TPM2_SetCommandCodeAuditStatus is audited after manufacture"
        );
        assert_eq!(
            command_list_digest(&mut runtime).expect("the list digest computes"),
            list_digest
        );
    }

    #[test]
    fn an_audited_command_starts_a_digest_and_bumps_the_counter() {
        let mut runtime = getrandom_audited();
        assert_matches_oracle(
            &runtime,
            vector("PERMALL_AUDIT_AFTER_SET"),
            "after enabling the audit",
        );
        assert_eq!(runtime.state().persistent.audit_counter, 1);
        assert_eq!(
            run(
                &mut runtime,
                &digest_command(TPM_RH_ENDORSEMENT, KEY0, ALG_NULL)
            ),
            vector("CMD_AUDIT_DIGEST_AFTER_SET")
        );
    }

    #[test]
    fn every_audited_command_extends_the_same_digest() {
        let mut runtime = getrandom_audited();
        assert_eq!(
            run(&mut runtime, &get_random()),
            vector("AUDIT_TRIGGER_GETRANDOM")
        );
        assert_matches_oracle(
            &runtime,
            vector("PERMALL_AUDIT_AFTER_ONE"),
            "after one audited TPM2_GetRandom",
        );
        let first = vector("CMD_AUDIT_DIGEST_ONE");
        replay_clock(&mut runtime, first);
        assert_eq!(
            run(
                &mut runtime,
                &digest_command(TPM_RH_ENDORSEMENT, KEY0, ALG_NULL)
            ),
            first
        );
        assert!(
            audit_digest(&runtime).expect("the digest reads").is_empty(),
            "a signed report resets the log"
        );
        assert_matches_oracle(
            &runtime,
            vector("PERMALL_AUDIT_AFTER_DIGEST"),
            "after the signed report",
        );
        assert_eq!(
            run(&mut runtime, &get_random()),
            vector("AUDIT_TRIGGER_GETRANDOM_2")
        );
        let second = vector("CMD_AUDIT_DIGEST_TWO");
        replay_clock(&mut runtime, second);
        assert_eq!(
            run(
                &mut runtime,
                &digest_command(TPM_RH_ENDORSEMENT, KEY0, ALG_NULL)
            ),
            second
        );
        let first_body = attested_body(&attested_bytes(first));
        let second_body = attested_body(&attested_bytes(second));
        assert_ne!(
            &first_body[..8],
            &second_body[..8],
            "the audit counter advanced with the new log"
        );
    }

    #[test]
    fn a_null_signer_leaves_the_log_in_place() {
        let mut runtime = getrandom_audited();
        let expected = vector("CMD_AUDIT_DIGEST_NULL_SIGNER");
        replay_clock(&mut runtime, expected);
        let before = audit_digest(&runtime).expect("the digest reads");
        assert_eq!(
            run(
                &mut runtime,
                &digest_command(TPM_RH_ENDORSEMENT, TPM_RH_NULL, ALG_NULL)
            ),
            expected
        );
        assert_eq!(
            audit_digest(&runtime).expect("the digest reads"),
            before,
            "an unsigned report keeps the log"
        );
        let after = vector("CMD_AUDIT_DIGEST_AFTER_NULL");
        replay_clock(&mut runtime, after);
        assert_eq!(
            run(
                &mut runtime,
                &digest_command(TPM_RH_ENDORSEMENT, KEY0, ALG_NULL)
            ),
            after
        );
    }

    #[test]
    fn clearing_the_last_audited_command_still_reports_the_log() {
        let mut runtime = getrandom_audited();
        assert_eq!(
            run(&mut runtime, &audit_status(ALG_NULL, &[], &[CC_GET_RANDOM])),
            vector("AUDIT_STATUS_CLEAR_GETRANDOM")
        );
        let expected = vector("CMD_AUDIT_DIGEST_AFTER_CLEAR");
        replay_clock(&mut runtime, expected);
        assert_eq!(
            run(
                &mut runtime,
                &digest_command(TPM_RH_ENDORSEMENT, KEY0, ALG_NULL)
            ),
            expected
        );
    }

    #[test]
    fn an_algorithm_change_resets_the_digest_without_bumping_the_counter() {
        let mut runtime = audit_runtime();
        run_ok(
            &mut runtime,
            &audit_status(ALG_SHA256, &[], &[]),
            "the audit algorithm changes",
        );
        assert!(
            audit_digest(&runtime).expect("the digest reads").is_empty(),
            "the change marker is consumed by the same command"
        );
        assert_eq!(
            runtime.state().persistent.audit_counter,
            0,
            "the algorithm change does not start a log"
        );
        let expected = vector("CMD_AUDIT_DIGEST_SHA256");
        replay_clock(&mut runtime, expected);
        assert_eq!(
            run(
                &mut runtime,
                &digest_command(TPM_RH_ENDORSEMENT, KEY0, ALG_NULL)
            ),
            expected
        );
        let body = attested_body(&attested_bytes(expected));
        assert_eq!(&body[8..10], &ALG_SHA256.to_be_bytes(), "the new algorithm");
        assert_eq!(&body[..8], &0u64.to_be_bytes(), "the counter did not move");

        run_ok(
            &mut runtime,
            &audit_status(ALG_SHA256, &[], &[]),
            "repeating the algorithm takes the list branch",
        );
        assert_eq!(runtime.state().persistent.audit_counter, 1);
        let again = vector("CMD_AUDIT_DIGEST_SHA256_AGAIN");
        replay_clock(&mut runtime, again);
        assert_eq!(
            run(
                &mut runtime,
                &digest_command(TPM_RH_ENDORSEMENT, KEY0, ALG_NULL)
            ),
            again
        );
    }

    #[test]
    fn the_x509_certification_command_appears_in_the_command_list_digest() {
        let mut runtime = audit_runtime();
        run_ok(
            &mut runtime,
            &audit_status(ALG_NULL, &[0x0000_0197], &[]),
            "TPM2_CertifyX509 is audited",
        );
        let expected = vector("CMD_AUDIT_DIGEST_UNREGISTERED");
        replay_clock(&mut runtime, expected);
        assert_eq!(
            run(
                &mut runtime,
                &digest_command(TPM_RH_ENDORSEMENT, KEY0, ALG_NULL)
            ),
            expected
        );
    }

    #[test]
    fn the_scheme_and_privacy_handle_rules_match_the_oracle() {
        let mut runtime = audit_runtime();
        let expected = vector("CMD_AUDIT_DIGEST_EXPLICIT");
        replay_clock(&mut runtime, expected);
        assert_eq!(
            run(
                &mut runtime,
                &digest_command(TPM_RH_ENDORSEMENT, KEY0, ALG_RSASSA)
            ),
            expected
        );
        let mut runtime = audit_runtime();
        assert_eq!(
            run(&mut runtime, &digest_command(TPM_RH_OWNER, KEY0, ALG_NULL)),
            vector("CMD_AUDIT_DIGEST_OWNER_PRIVACY")
        );
        assert_eq!(
            response_code(vector("CMD_AUDIT_DIGEST_OWNER_PRIVACY")),
            RC_HANDLE1_VALUE
        );
    }

    #[test]
    fn trailing_parameter_bytes_are_a_size_error() {
        let mut runtime = audit_runtime();
        let mut parameters = tpm2b(&QUALIFY);
        parameters.extend_from_slice(&sig_scheme(ALG_NULL, 0));
        parameters.push(0x00);
        assert_eq!(
            run(
                &mut runtime,
                &command(
                    TPM_CC_GET_COMMAND_AUDIT_DIGEST,
                    &[TPM_RH_ENDORSEMENT, KEY0],
                    Some(&[pw(), pw()]),
                    &parameters
                )
            ),
            vector("CMD_AUDIT_DIGEST_TRAILING")
        );
        assert_eq!(response_code(vector("CMD_AUDIT_DIGEST_TRAILING")), RC_SIZE);
    }

    #[test]
    fn a_failed_report_keeps_the_log() {
        let mut runtime = getrandom_audited();
        run_ok(&mut runtime, &get_random(), "the audited command runs");
        let before = audit_digest(&runtime).expect("the digest reads");
        assert_ne!(
            response_code(&run(
                &mut runtime,
                &digest_command(TPM_RH_OWNER, KEY0, ALG_NULL)
            )),
            RC_SUCCESS
        );
        assert_eq!(audit_digest(&runtime).expect("the digest reads"), before);
    }

    #[test]
    fn parameter_mutations_do_not_panic() {
        let mut full = tpm2b(&QUALIFY);
        full.extend_from_slice(&sig_scheme(ALG_RSASSA, ALG_SHA256));
        let mut runtime = audit_runtime();
        for index in 0..full.len() {
            for byte in [0x00u8, 0x01, 0x7f, 0xff] {
                let mut parameters = full.clone();
                parameters[index] = byte;
                let _ = run(
                    &mut runtime,
                    &command(
                        TPM_CC_GET_COMMAND_AUDIT_DIGEST,
                        &[TPM_RH_ENDORSEMENT, KEY0],
                        Some(&[pw(), pw()]),
                        &parameters,
                    ),
                );
            }
        }
    }
}
