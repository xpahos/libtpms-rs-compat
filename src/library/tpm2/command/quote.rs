use crate::ffi_types::TpmResult;
use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_SCHEME, TPM_RC_SIZE};

use super::super::pcr::{compute_current_digest, parse_selection_list};
use super::super::persistent::OwnedPcrSelection;
use super::super::profile::ValidatedProfile;
use super::super::public::TPM_ALG_NULL;
use super::super::runtime::Tpm2Runtime;
use super::super::signature::{SigScheme, select_sign_scheme};
use super::super::template::TemplateReader;
use super::attest::{
    Attested, check_signing_object, fill_in_attest_info, parse_qualifying_data, parse_scheme,
    sign_and_respond,
};
use super::dispatcher::CommandFrame;
use super::nv_common::{TPM_RC_1, TPM_RC_2, TPM_RC_3, TPM_RC_P, handle_at};
use super::output::CommandOutput;
use super::signing::{RC_SIGN_HANDLE, signing_object};

const RC_QUALIFYING_DATA: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_IN_SCHEME: TpmResult = TPM_RC_P + TPM_RC_2;
const RC_PCR_SELECT: TpmResult = TPM_RC_P + TPM_RC_3;

struct Parameters {
    qualifying_data: Vec<u8>,
    scheme: SigScheme,
    selections: Vec<OwnedPcrSelection>,
}

pub(super) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let sign_handle = handle_at(frame, 0)?;
    let mut parameters = parse_parameters(
        frame.parameters,
        &runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?.profile,
    )?;

    let sign_object = signing_object(runtime, sign_handle)?;
    check_signing_object(sign_object.as_deref(), RC_SIGN_HANDLE)?;
    let scheme = select_sign_scheme(sign_object.as_deref(), parameters.scheme)
        .ok_or(TPM_RC_SCHEME + RC_IN_SCHEME)?;
    if scheme.hash_alg == TPM_ALG_NULL {
        return Err(TPM_RC_SCHEME + RC_IN_SCHEME);
    }

    let pcr_digest = compute_current_digest(runtime, scheme.hash_alg, &mut parameters.selections)?;
    let attested = Attested::Quote {
        selections: parameters.selections,
        pcr_digest,
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
    let selections = parse_selection_list(&mut reader, &profile.algorithms, RC_PCR_SELECT)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(Parameters {
        qualifying_data,
        scheme,
        selections,
    })
}

#[cfg(test)]
mod tests {
    use super::super::attest::harness::*;
    use super::super::nv_common::harness::{RC_SUCCESS, response_code};
    use super::super::registry::{CommandLifecycle, HandleKind, NvAccess, TPM_CC_QUOTE, find};
    use crate::library::tpm2::golden_responses::attestation::vector;
    use crate::library::tpm2::runtime::Tpm2Runtime;

    const RC_PARAM2_SCHEME: u32 = 0x2d2;
    const RC_PARAM3_HASH: u32 = 0x3c3;
    const RC_PARAM3_VALUE: u32 = 0x3c4;
    const RC_PARAM3_SIZE: u32 = 0x3d5;
    const RC_PARAM3_INSUFFICIENT: u32 = 0x3da;
    const RC_SIZE: u32 = 0x095;

    const PCR0_SHA256: [(u16, &[u8]); 1] = [(ALG_SHA256, &[0x01, 0x00, 0x00])];
    const ALL_BANKS: [(u16, &[u8]); 4] = [
        (ALG_SHA1, &[0xff, 0xff, 0xff]),
        (ALG_SHA256, &[0xff, 0xff, 0xff]),
        (ALG_SHA384, &[0xff, 0xff, 0xff]),
        (0x000d, &[0xff, 0xff, 0xff]),
    ];

    fn quote_command(sign: u32, selections: &[u8], scheme: u16, hash_alg: u16) -> Vec<u8> {
        let mut parameters = tpm2b(&QUALIFY);
        parameters.extend_from_slice(&sig_scheme(scheme, hash_alg));
        parameters.extend_from_slice(selections);
        command(TPM_CC_QUOTE, &[sign], Some(&[pw()]), &parameters)
    }

    #[track_caller]
    fn quote_runtime() -> Box<Tpm2Runtime> {
        let mut runtime = ready_runtime();
        run_ok(
            &mut runtime,
            &create_primary(
                TPM_RH_OWNER,
                &rsa_template(ALG_RSASSA, ALG_SHA256, SIGN_ATTRS),
            ),
            "the quoting key is created",
        );
        runtime
    }

    #[track_caller]
    fn assert_quote(record: &str, sign: u32, selections: &[u8], scheme: u16, hash_alg: u16) {
        let mut runtime = quote_runtime();
        let expected = vector(record);
        replay_clock(&mut runtime, expected);
        assert_eq!(
            run(
                &mut runtime,
                &quote_command(sign, selections, scheme, hash_alg)
            ),
            expected,
            "{record}"
        );
    }

    fn pcr_extend_command(pcr: u32, digest: &[u8]) -> Vec<u8> {
        let mut parameters = 1u32.to_be_bytes().to_vec();
        parameters.extend_from_slice(&ALG_SHA256.to_be_bytes());
        parameters.extend_from_slice(digest);
        command(CC_PCR_EXTEND, &[pcr], Some(&[pw()]), &parameters)
    }

    #[test]
    fn the_command_attributes_match_the_oracle() {
        let expected = vector("CCATTR_0158");
        let attributes = u32::from_be_bytes(expected[19..23].try_into().expect("four bytes"));
        assert_eq!(TPM_CC_QUOTE, 0x0000_0158);
        let descriptor = find(TPM_CC_QUOTE).expect("a registered command");
        assert_eq!(descriptor.attributes, attributes);
        assert_eq!(descriptor.attributes, 0x0200_0158);
        assert_eq!(descriptor.decrypt_size, 2);
        assert_eq!(descriptor.encrypt_size, 2);
        assert!(!descriptor.physical_presence);
        assert!(matches!(descriptor.nv_access, NvAccess::Neither));
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
        assert_eq!(descriptor.handles.len(), 1);
        assert!(descriptor.handles[0].user_auth && !descriptor.handles[0].admin_role());
        assert!(matches!(
            descriptor.handles[0].kind,
            HandleKind::ObjectAllowNull
        ));
    }

    #[test]
    fn an_empty_selection_quotes_the_empty_digest_like_the_oracle() {
        assert_quote(
            "QUOTE_EMPTY_SELECTION",
            KEY0,
            &pcr_selection(&[]),
            ALG_NULL,
            0,
        );
        let body = attested_body(&attested_bytes(vector("QUOTE_EMPTY_SELECTION")));
        assert_eq!(
            &body[..4],
            &[0x00, 0x00, 0x00, 0x00],
            "no banks are selected"
        );
    }

    #[test]
    fn a_single_bank_selection_quotes_like_the_oracle() {
        assert_quote(
            "QUOTE_PCR0_SHA256",
            KEY0,
            &pcr_selection(&PCR0_SHA256),
            ALG_NULL,
            0,
        );
        assert_quote(
            "QUOTE_EXPLICIT_SCHEME",
            KEY0,
            &pcr_selection(&PCR0_SHA256),
            ALG_RSASSA,
            ALG_SHA256,
        );
    }

    #[test]
    fn every_allocated_bank_may_be_quoted_at_once() {
        assert_quote(
            "QUOTE_ALL_BANKS",
            KEY0,
            &pcr_selection(&ALL_BANKS),
            ALG_NULL,
            0,
        );
        let body = attested_body(&attested_bytes(vector("QUOTE_ALL_BANKS")));
        assert_eq!(&body[..4], &[0x00, 0x00, 0x00, 0x04], "four banks survive");
    }

    #[test]
    fn a_high_selection_bit_is_preserved_when_the_pcr_is_implemented() {
        assert_quote(
            "QUOTE_UNSELECTED_HIGH_PCR",
            KEY0,
            &pcr_selection(&[(ALG_SHA256, &[0x00, 0x00, 0x80])]),
            ALG_NULL,
            0,
        );
    }

    #[test]
    fn extending_a_pcr_changes_the_quoted_digest() {
        let mut runtime = quote_runtime();
        let before = vector("QUOTE_BEFORE_EXTEND");
        replay_clock(&mut runtime, before);
        assert_eq!(
            run(
                &mut runtime,
                &quote_command(KEY0, &pcr_selection(&PCR0_SHA256), ALG_NULL, 0)
            ),
            before
        );
        let digest: Vec<u8> = (1..=32).collect();
        run_ok(
            &mut runtime,
            &pcr_extend_command(0, &digest),
            "the PCR extends",
        );
        let after = vector("QUOTE_AFTER_EXTEND");
        replay_clock(&mut runtime, after);
        assert_eq!(
            run(
                &mut runtime,
                &quote_command(KEY0, &pcr_selection(&PCR0_SHA256), ALG_NULL, 0)
            ),
            after
        );
        run_ok(
            &mut runtime,
            &pcr_extend_command(0, &digest),
            "the PCR extends again",
        );
        let again = vector("QUOTE_AFTER_SECOND_EXTEND");
        replay_clock(&mut runtime, again);
        assert_eq!(
            run(
                &mut runtime,
                &quote_command(KEY0, &pcr_selection(&PCR0_SHA256), ALG_NULL, 0)
            ),
            again
        );
        assert_ne!(
            attested_body(&attested_bytes(before)),
            attested_body(&attested_bytes(after)),
            "the quoted digest tracks the PCR"
        );
        assert_ne!(
            attested_body(&attested_bytes(after)),
            attested_body(&attested_bytes(again))
        );
    }

    #[test]
    fn a_null_signer_has_no_hash_to_quote_with() {
        assert_quote(
            "QUOTE_NULL_SIGNER",
            TPM_RH_NULL,
            &pcr_selection(&PCR0_SHA256),
            ALG_NULL,
            0,
        );
        assert_eq!(response_code(vector("QUOTE_NULL_SIGNER")), RC_PARAM2_SCHEME);
    }

    #[test]
    fn a_scheme_hash_that_disagrees_with_the_key_is_rejected() {
        assert_quote(
            "QUOTE_SHA384_SCHEME",
            KEY0,
            &pcr_selection(&PCR0_SHA256),
            ALG_RSASSA,
            ALG_SHA384,
        );
        assert_eq!(
            response_code(vector("QUOTE_SHA384_SCHEME")),
            RC_PARAM2_SCHEME
        );
    }

    #[test]
    fn the_selection_errors_match_the_oracle() {
        let mut runtime = quote_runtime();
        for (record, selections, code) in [
            (
                "QUOTE_UNSUPPORTED_BANK",
                pcr_selection(&[(ALG_HMAC, &[0x01, 0x00, 0x00])]),
                RC_PARAM3_HASH,
            ),
            (
                "QUOTE_SHORT_SELECT",
                pcr_selection(&[(ALG_SHA256, &[0x01])]),
                RC_PARAM3_VALUE,
            ),
            (
                "QUOTE_LONG_SELECT",
                pcr_selection(&[(ALG_SHA256, &[0x01, 0x00, 0x00, 0x00])]),
                RC_PARAM3_VALUE,
            ),
        ] {
            assert_eq!(
                run(&mut runtime, &quote_command(KEY0, &selections, ALG_NULL, 0)),
                vector(record),
                "{record}"
            );
            assert_eq!(response_code(vector(record)), code, "{record}");
        }

        let mut too_many = 5u32.to_be_bytes().to_vec();
        for _ in 0..5 {
            too_many.extend_from_slice(&ALG_SHA256.to_be_bytes());
            too_many.push(3);
            too_many.extend_from_slice(&[0x00, 0x00, 0x00]);
        }
        assert_eq!(
            run(&mut runtime, &quote_command(KEY0, &too_many, ALG_NULL, 0)),
            vector("QUOTE_TOO_MANY_BANKS")
        );
        assert_eq!(
            response_code(vector("QUOTE_TOO_MANY_BANKS")),
            RC_PARAM3_SIZE
        );

        let mut truncated = 1u32.to_be_bytes().to_vec();
        truncated.extend_from_slice(&ALG_SHA256.to_be_bytes());
        assert_eq!(
            run(&mut runtime, &quote_command(KEY0, &truncated, ALG_NULL, 0)),
            vector("QUOTE_TRUNCATED_SELECTION")
        );
        assert_eq!(
            response_code(vector("QUOTE_TRUNCATED_SELECTION")),
            RC_PARAM3_INSUFFICIENT
        );
    }

    #[test]
    fn trailing_parameter_bytes_are_a_size_error() {
        let mut runtime = quote_runtime();
        let mut parameters = tpm2b(&QUALIFY);
        parameters.extend_from_slice(&sig_scheme(ALG_NULL, 0));
        parameters.extend_from_slice(&pcr_selection(&PCR0_SHA256));
        parameters.push(0x00);
        assert_eq!(
            run(
                &mut runtime,
                &command(TPM_CC_QUOTE, &[KEY0], Some(&[pw()]), &parameters)
            ),
            vector("QUOTE_TRAILING")
        );
        assert_eq!(response_code(vector("QUOTE_TRAILING")), RC_SIZE);
    }

    #[test]
    fn the_quoted_digest_is_the_hash_of_the_selected_pcr_values() {
        use crate::library::tpm2::crypto::Hasher;
        let mut runtime = quote_runtime();
        let expected = vector("QUOTE_PCR0_SHA256");
        replay_clock(&mut runtime, expected);
        let response = run(
            &mut runtime,
            &quote_command(KEY0, &pcr_selection(&PCR0_SHA256), ALG_NULL, 0),
        );
        let attest = attested_bytes(&response);
        assert_eq!(attest_prefix(&attest).0, 0x8018, "TPM_ST_ATTEST_QUOTE");
        let body = attested_body(&attest);
        assert_eq!(
            &body[..10],
            &[0x00, 0x00, 0x00, 0x01, 0x00, 0x0b, 0x03, 0x01, 0x00, 0x00]
        );
        let digest_len = u16::from_be_bytes([body[10], body[11]]) as usize;
        let quoted = &body[12..12 + digest_len];
        let mut hasher = Hasher::new(ALG_SHA256).expect("a compiled hash");
        hasher.update(
            runtime.live.pcrs[0].banks[1]
                .as_ref()
                .expect("the SHA-256 bank is allocated"),
        );
        assert_eq!(quoted, &hasher.finalize()[..]);
    }

    #[test]
    fn a_failed_quote_leaves_no_trace() {
        let mut runtime = quote_runtime();
        run_ok(
            &mut runtime,
            &quote_command(KEY0, &pcr_selection(&PCR0_SHA256), ALG_NULL, 0),
            "the first authorization performs the DA-used transition",
        );
        runtime.nv_update_pending = false;
        let before = crate::library::tpm2::persistent::persistent_all_store(runtime.state())
            .expect("the state serializes");
        for selections in [
            pcr_selection(&[(ALG_HMAC, &[0x01, 0x00, 0x00])]),
            pcr_selection(&[(ALG_SHA256, &[0x01])]),
        ] {
            assert_ne!(
                response_code(&run(
                    &mut runtime,
                    &quote_command(KEY0, &selections, ALG_NULL, 0)
                )),
                RC_SUCCESS
            );
            assert_eq!(
                crate::library::tpm2::persistent::persistent_all_store(runtime.state())
                    .expect("the state serializes"),
                before
            );
        }
    }

    #[test]
    fn malformed_quote_parameters_never_panic() {
        let mut full = tpm2b(&QUALIFY);
        full.extend_from_slice(&sig_scheme(ALG_RSASSA, ALG_SHA256));
        full.extend_from_slice(&pcr_selection(&ALL_BANKS));
        let mut runtime = quote_runtime();
        for index in 0..full.len() {
            for byte in [0x00u8, 0x01, 0x7f, 0xff] {
                let mut parameters = full.clone();
                parameters[index] = byte;
                let _ = run(
                    &mut runtime,
                    &command(TPM_CC_QUOTE, &[KEY0], Some(&[pw()]), &parameters),
                );
            }
        }
    }
}
