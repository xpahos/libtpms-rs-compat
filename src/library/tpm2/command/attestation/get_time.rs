use super::builder::{
    Attested, check_signing_object, fill_in_attest_info, firmware_version, parse_qualifying_data,
    parse_scheme, sign_and_respond, time_clock_info,
};
use crate::ffi_types::TpmResult;
use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_SCHEME, TPM_RC_SIZE};
use crate::library::tpm2::command::core::dispatcher::{CommandFrame, handle_at};
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::command::core::response_code::{TPM_RC_1, TPM_RC_2, TPM_RC_H, TPM_RC_P};
use crate::library::tpm2::command::crypto::signing_state::signing_object;
use crate::library::tpm2::profile::ValidatedProfile;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::signature::{SigScheme, select_sign_scheme};
use crate::library::tpm2::template::TemplateReader;

const RC_SIGN_HANDLE: TpmResult = TPM_RC_H + TPM_RC_2;
const RC_QUALIFYING_DATA: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_IN_SCHEME: TpmResult = TPM_RC_P + TPM_RC_2;

struct Parameters {
    qualifying_data: Vec<u8>,
    scheme: SigScheme,
}

pub(in crate::library::tpm2::command) fn execute(
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

    let attested = Attested::Time {
        time: runtime.timer.time_ms,
        clock_info: time_clock_info(runtime)?,
        firmware_version: firmware_version(runtime)?,
    };
    let attest = fill_in_attest_info(
        runtime,
        sign_object.as_deref(),
        &scheme,
        &parameters.qualifying_data,
        attested,
    )?;
    sign_and_respond(runtime, sign_object.as_deref(), &scheme, &attest)
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
    use crate::library::tpm2::command::attestation::builder::test_support::{
        ALG_NULL, ALG_RSASSA, ALG_SHA256, KEY0, QUALIFY, SIGN_ATTRS, TPM_RH_ENDORSEMENT,
        TPM_RH_NULL, TPM_RH_OWNER, TPM_RH_PLATFORM, attest_prefix, attested_body, attested_bytes,
        command, create_primary, pw, ready_runtime, replay_clock, rsa_template, run, run_ok,
        sig_scheme, signature_bytes, tpm2b,
    };
    use crate::library::tpm2::command::core::registry::{
        CommandLifecycle, HandleKind, NvAccess, TPM_CC_GET_TIME, find,
    };
    use crate::library::tpm2::command::core::test_support::{RC_SUCCESS, response_code};
    use crate::library::tpm2::golden_responses::attestation::vector;
    use crate::library::tpm2::runtime::Tpm2Runtime;

    const RC_HANDLE1_VALUE: u32 = 0x184;
    const RC_SIZE: u32 = 0x095;

    fn get_time_command(privacy: u32, sign: u32, qualifying: &[u8], scheme: u16) -> Vec<u8> {
        let mut parameters = tpm2b(qualifying);
        parameters.extend_from_slice(&sig_scheme(scheme, ALG_SHA256));
        command(
            TPM_CC_GET_TIME,
            &[privacy, sign],
            Some(&[pw(), pw()]),
            &parameters,
        )
    }

    #[track_caller]
    fn time_runtime() -> Box<Tpm2Runtime> {
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
    fn replay_time(runtime: &mut Tpm2Runtime, expected: &[u8]) {
        replay_clock(runtime, expected);
        if response_code(expected) != 0 {
            return;
        }
        let attest = attested_bytes(expected);
        let body = attested_body(&attest);
        runtime.timer.time_ms = u64::from_be_bytes(body[..8].try_into().expect("eight bytes"));
    }

    #[track_caller]
    fn assert_get_time(record: &str, privacy: u32, sign: u32, qualifying: &[u8], scheme: u16) {
        let mut runtime = time_runtime();
        let expected = vector(record);
        replay_time(&mut runtime, expected);
        assert_eq!(
            run(
                &mut runtime,
                &get_time_command(privacy, sign, qualifying, scheme)
            ),
            expected,
            "{record}"
        );
    }

    #[test]
    fn the_command_attributes_match_the_oracle() {
        let expected = vector("CCATTR_014C");
        let attributes = u32::from_be_bytes(expected[19..23].try_into().expect("four bytes"));
        assert_eq!(TPM_CC_GET_TIME, 0x0000_014c);
        let descriptor = find(TPM_CC_GET_TIME).expect("a registered command");
        assert_eq!(descriptor.attributes, attributes);
        assert_eq!(descriptor.attributes, 0x0400_014c);
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
        assert!(descriptor.handles[0].kind.accepts(TPM_RH_ENDORSEMENT));
        for handle in [TPM_RH_OWNER, TPM_RH_PLATFORM, TPM_RH_NULL, 0x8000_0000] {
            assert!(
                !descriptor.handles[0].kind.accepts(handle),
                "{handle:#010x}"
            );
        }
    }

    #[test]
    fn a_signed_time_attestation_matches_the_oracle() {
        assert_get_time(
            "GETTIME_SIGNED",
            TPM_RH_ENDORSEMENT,
            KEY0,
            &QUALIFY,
            ALG_NULL,
        );
        assert_get_time(
            "GETTIME_EXPLICIT_SCHEME",
            TPM_RH_ENDORSEMENT,
            KEY0,
            &QUALIFY,
            ALG_RSASSA,
        );
        assert_get_time(
            "GETTIME_NO_QUALIFYING",
            TPM_RH_ENDORSEMENT,
            KEY0,
            &[],
            ALG_NULL,
        );
    }

    #[test]
    fn a_null_signer_answers_a_null_signature() {
        assert_get_time(
            "GETTIME_NULL_SIGNER",
            TPM_RH_ENDORSEMENT,
            TPM_RH_NULL,
            &QUALIFY,
            ALG_NULL,
        );
        assert_eq!(signature_bytes(vector("GETTIME_NULL_SIGNER")), [0x00, 0x10]);
    }

    #[test]
    fn the_attested_time_carries_the_unmasked_clock_and_firmware_version() {
        let signed = attested_bytes(vector("GETTIME_SIGNED"));
        let (attest_type, _, _, at) = attest_prefix(&signed);
        assert_eq!(attest_type, 0x8019, "TPM_ST_ATTEST_TIME");
        let outer_reset =
            u32::from_be_bytes(signed[at + 8..at + 12].try_into().expect("four bytes"));
        let outer_firmware =
            u64::from_be_bytes(signed[at + 17..at + 25].try_into().expect("eight bytes"));

        let body = attested_body(&signed);
        assert_eq!(
            body.len(),
            8 + 17 + 8,
            "TPMS_TIME_ATTEST_INFO is fixed size"
        );
        let inner_reset = u32::from_be_bytes(body[16..20].try_into().expect("four bytes"));
        let inner_firmware = u64::from_be_bytes(body[25..33].try_into().expect("eight bytes"));
        assert_eq!(inner_reset, 1, "the inner reset count is not obfuscated");
        assert_eq!(
            inner_firmware, 0x2024_0125_0012_0000,
            "the inner firmware version is plain text"
        );
        assert_eq!(
            outer_reset, inner_reset,
            "an endorsement-hierarchy signer leaves the outer clock info unmasked"
        );
        assert_eq!(outer_firmware, inner_firmware);
        assert_eq!(body[24], 1, "the safe flag is set while NV is available");
    }

    #[test]
    fn only_the_endorsement_hierarchy_may_authorize_the_attestation() {
        let mut runtime = time_runtime();
        for (record, privacy) in [
            ("GETTIME_OWNER_PRIVACY", TPM_RH_OWNER),
            ("GETTIME_NULL_PRIVACY", TPM_RH_NULL),
        ] {
            assert_eq!(
                run(
                    &mut runtime,
                    &get_time_command(privacy, KEY0, &QUALIFY, ALG_NULL)
                ),
                vector(record),
                "{record}"
            );
            assert_eq!(response_code(vector(record)), RC_HANDLE1_VALUE);
        }
    }

    #[test]
    fn trailing_parameter_bytes_are_a_size_error() {
        let mut runtime = time_runtime();
        let mut parameters = tpm2b(&QUALIFY);
        parameters.extend_from_slice(&sig_scheme(ALG_NULL, 0));
        parameters.push(0x00);
        assert_eq!(
            run(
                &mut runtime,
                &command(
                    TPM_CC_GET_TIME,
                    &[TPM_RH_ENDORSEMENT, KEY0],
                    Some(&[pw(), pw()]),
                    &parameters
                )
            ),
            vector("GETTIME_TRAILING")
        );
        assert_eq!(response_code(vector("GETTIME_TRAILING")), RC_SIZE);
    }

    #[test]
    fn an_advanced_clock_is_reported_by_the_attestation() {
        let advanced = attested_bytes(vector("GETTIME_AFTER_ADVANCE"));
        let base = attested_bytes(vector("GETTIME_SIGNED"));
        let advanced_body = attested_body(&advanced);
        let base_body = attested_body(&base);
        let advanced_time = u64::from_be_bytes(advanced_body[..8].try_into().expect("eight bytes"));
        let base_time = u64::from_be_bytes(base_body[..8].try_into().expect("eight bytes"));
        assert!(
            advanced_time > base_time,
            "the reference clock advanced: {advanced_time} > {base_time}"
        );

        let mut runtime = time_runtime();
        replay_time(&mut runtime, vector("GETTIME_AFTER_ADVANCE"));
        assert_eq!(
            run(
                &mut runtime,
                &get_time_command(TPM_RH_ENDORSEMENT, KEY0, &QUALIFY, ALG_NULL)
            ),
            vector("GETTIME_AFTER_ADVANCE")
        );
    }

    #[test]
    fn a_failed_attestation_leaves_no_trace() {
        let mut runtime = time_runtime();
        run_ok(
            &mut runtime,
            &get_time_command(TPM_RH_ENDORSEMENT, KEY0, &QUALIFY, ALG_NULL),
            "the first authorization performs the DA-used transition",
        );
        runtime.nv_update_pending = false;
        let before = crate::library::tpm2::persistent::persistent_all_store(runtime.state())
            .expect("the state serializes");
        assert_ne!(
            response_code(&run(
                &mut runtime,
                &get_time_command(TPM_RH_OWNER, KEY0, &QUALIFY, ALG_NULL)
            )),
            RC_SUCCESS
        );
        assert_eq!(
            crate::library::tpm2::persistent::persistent_all_store(runtime.state())
                .expect("the state serializes"),
            before
        );
    }

    #[test]
    fn parameter_mutations_do_not_panic() {
        let mut full = tpm2b(&QUALIFY);
        full.extend_from_slice(&sig_scheme(ALG_RSASSA, ALG_SHA256));
        let mut runtime = time_runtime();
        for index in 0..full.len() {
            for byte in [0x00u8, 0x01, 0x7f, 0xff] {
                let mut parameters = full.clone();
                parameters[index] = byte;
                let _ = run(
                    &mut runtime,
                    &command(
                        TPM_CC_GET_TIME,
                        &[TPM_RH_ENDORSEMENT, KEY0],
                        Some(&[pw(), pw()]),
                        &parameters,
                    ),
                );
            }
        }
    }
}
