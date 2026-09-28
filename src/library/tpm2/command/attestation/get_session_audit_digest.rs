// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/AttestationCommands.c
// - libtpms/src/tpm2/SessionProcess.c
//
// Original upstream authors and copyright notices:
// Written by Ken Goldman
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corp. and others, 2016 - 2021
// (c) Copyright IBM Corp. and others, 2016 - 2023
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use super::builder::{
    Attested, check_signing_object, fill_in_attest_info, parse_qualifying_data, parse_scheme,
    sign_and_respond,
};
use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_SCHEME, TPM_RC_SIZE, TPM_RC_TYPE};
use crate::library::tpm2::command::core::dispatcher::{CommandFrame, handle_at};
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::command::core::response_code::{
    TPM_RC_1, TPM_RC_2, TPM_RC_3, TPM_RC_H, TPM_RC_P,
};
use crate::library::tpm2::command::crypto::signing_state::signing_object;
use crate::library::tpm2::command::session::processing::exclusive_audit_session;
use crate::library::tpm2::profile::ValidatedProfile;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::session::{SESSION_ATTR_IS_AUDIT, loaded_session};
use crate::library::tpm2::signature::{SigScheme, select_sign_scheme};
use crate::library::tpm2::template::TemplateReader;
use crate::types::TpmResult;

const RC_SIGN_HANDLE: TpmResult = TPM_RC_H + TPM_RC_2;
const RC_SESSION_HANDLE: TpmResult = TPM_RC_H + TPM_RC_3;
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
    let session_handle = handle_at(frame, 2)?;
    let parameters = parse_parameters(
        frame.parameters,
        &runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?.profile,
    )?;

    let sign_object = signing_object(runtime, sign_handle)?;
    check_signing_object(sign_object.as_deref(), RC_SIGN_HANDLE)?;
    let scheme = select_sign_scheme(sign_object.as_deref(), parameters.scheme)
        .ok_or(TPM_RC_SCHEME + RC_IN_SCHEME)?;

    let session = loaded_session(&runtime.live, session_handle).ok_or(TPM_RC_FAILURE)?;
    if session.attributes & SESSION_ATTR_IS_AUDIT == 0 {
        return Err(TPM_RC_TYPE + RC_SESSION_HANDLE);
    }
    let attested = Attested::SessionAudit {
        exclusive_session: exclusive_audit_session(runtime) == session_handle,
        session_digest: session.audit_digest.clone(),
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
        ALG_NULL, ALG_RSASSA, ALG_SHA256, CC_FLUSH_CONTEXT, CC_GET_RANDOM, CC_START_AUTH_SESSION,
        HMAC_SESSION, KEY0, NONCE_CALLER, QUALIFY, SIGN_ATTRS, TPM_RH_ENDORSEMENT, TPM_RH_NULL,
        TPM_RH_OWNER, TPM_RS_PW, assert_trailing_byte_oracle, attest_prefix, attested_body,
        attested_bytes, audited_get_random, command, create_primary, pw, ready_runtime,
        replay_clock, rsa_template, run, run_ok, sig_scheme, tpm2b,
    };
    use crate::library::tpm2::command::core::registry::TPM_CC_GET_SESSION_AUDIT_DIGEST;
    use crate::library::tpm2::command::core::test_support::{
        RC_SUCCESS, REPLACEMENT_BYTES, byte_replacements, for_each_mutation, response_code,
    };
    use crate::library::tpm2::golden_responses::attestation::vector;
    use crate::library::tpm2::runtime::Tpm2Runtime;

    const RC_HANDLE1_VALUE: u32 = 0x184;
    const RC_HANDLE3_VALUE: u32 = 0x384;
    const RC_HANDLE3_TYPE: u32 = 0x38a;
    const RC_REFERENCE_H2: u32 = 0x912;

    fn audit_digest_command(privacy: u32, sign: u32, audit: u32, scheme: u16) -> Vec<u8> {
        let mut parameters = tpm2b(&QUALIFY);
        parameters.extend_from_slice(&sig_scheme(scheme, ALG_SHA256));
        command(
            TPM_CC_GET_SESSION_AUDIT_DIGEST,
            &[privacy, sign, audit],
            Some(&[pw(), pw()]),
            &parameters,
        )
    }

    fn start_hmac_session() -> Vec<u8> {
        let mut parameters = tpm2b(&NONCE_CALLER);
        parameters.extend_from_slice(&tpm2b(&[]));
        parameters.push(0x00);
        parameters.extend_from_slice(&ALG_NULL.to_be_bytes());
        parameters.extend_from_slice(&ALG_SHA256.to_be_bytes());
        command(
            CC_START_AUTH_SESSION,
            &[TPM_RH_NULL, TPM_RH_NULL],
            None,
            &parameters,
        )
    }

    #[track_caller]
    fn session_runtime() -> (Tpm2Runtime, Vec<u8>) {
        let mut runtime = ready_runtime();
        run_ok(
            &mut runtime,
            &create_primary(
                TPM_RH_ENDORSEMENT,
                &rsa_template(ALG_RSASSA, ALG_SHA256, SIGN_ATTRS),
            ),
            "the attestation key is created",
        );
        let session = run(&mut runtime, &start_hmac_session());
        assert_eq!(
            session,
            vector("AUDIT_SESSION_START"),
            "the audit session matches the oracle"
        );
        (runtime, session)
    }

    #[track_caller]
    fn audited_runtime() -> Tpm2Runtime {
        let (mut runtime, session) = session_runtime();
        assert_eq!(
            run(&mut runtime, &audited_get_random(&session)),
            vector("AUDIT_GETRANDOM_1"),
            "the audited command matches the oracle"
        );
        runtime
    }

    #[test]
    fn unaudited_session_type_error() {
        let (mut runtime, _) = session_runtime();
        assert_eq!(
            run(
                &mut runtime,
                &audit_digest_command(TPM_RH_ENDORSEMENT, KEY0, HMAC_SESSION, ALG_NULL)
            ),
            vector("SESSION_AUDIT_UNUSED")
        );
        assert_eq!(
            response_code(vector("SESSION_AUDIT_UNUSED")),
            RC_HANDLE3_TYPE
        );
    }

    #[test]
    fn audited_session_digest_oracle_match() {
        for (record, sign, scheme) in [
            ("SESSION_AUDIT_ONE", KEY0, ALG_NULL),
            ("SESSION_AUDIT_EXPLICIT", KEY0, ALG_RSASSA),
            ("SESSION_AUDIT_NULL_SIGNER", TPM_RH_NULL, ALG_NULL),
        ] {
            let mut runtime = audited_runtime();
            let expected = vector(record);
            replay_clock(&mut runtime, expected);
            assert_eq!(
                run(
                    &mut runtime,
                    &audit_digest_command(TPM_RH_ENDORSEMENT, sign, HMAC_SESSION, scheme)
                ),
                expected,
                "{record}"
            );
        }
    }

    #[test]
    fn attested_digest_command_response_hash_extension() {
        use crate::library::tpm2::crypto::Hasher;

        let (mut runtime, session) = session_runtime();
        let response = run(&mut runtime, &audited_get_random(&session));
        assert_eq!(response, vector("AUDIT_GETRANDOM_1"));

        let mut hasher = Hasher::new(ALG_SHA256).expect("a compiled hash");
        hasher.update(&CC_GET_RANDOM.to_be_bytes());
        hasher.update(&4u16.to_be_bytes());
        let cp_hash = hasher.finalize();

        let size = u32::from_be_bytes(response[10..14].try_into().expect("four bytes")) as usize;
        let parameters = &response[14..14 + size];
        let mut hasher = Hasher::new(ALG_SHA256).expect("a compiled hash");
        hasher.update(&0u32.to_be_bytes());
        hasher.update(&CC_GET_RANDOM.to_be_bytes());
        hasher.update(parameters);
        let rp_hash = hasher.finalize();

        let mut hasher = Hasher::new(ALG_SHA256).expect("a compiled hash");
        hasher.update(&[0u8; 32]);
        hasher.update(&cp_hash);
        hasher.update(&rp_hash);
        let expected_digest = hasher.finalize();

        let attest = attested_bytes(vector("SESSION_AUDIT_ONE"));
        assert_eq!(
            attest_prefix(&attest).0,
            0x8016,
            "TPM_ST_ATTEST_SESSION_AUDIT"
        );
        let body = attested_body(&attest);
        assert_eq!(body[0], 0x01, "the session is still the exclusive one");
        let digest_len = u16::from_be_bytes([body[1], body[2]]) as usize;
        assert_eq!(&body[3..3 + digest_len], &expected_digest[..]);
        assert_eq!(body.len(), 3 + digest_len);
        assert_eq!(
            vector("EXCLUSIVE_AFTER_ONE"),
            HMAC_SESSION.to_be_bytes(),
            "the reference records the exclusive audit session"
        );
    }

    #[test]
    fn attestation_audited_session_unchanged() {
        use crate::library::tpm2::session::loaded_session;
        let mut runtime = audited_runtime();
        let before = loaded_session(&runtime.live, HMAC_SESSION)
            .expect("the session is loaded")
            .audit_digest
            .clone();
        run_ok(
            &mut runtime,
            &audit_digest_command(TPM_RH_ENDORSEMENT, KEY0, HMAC_SESSION, ALG_NULL),
            "the digest is attested",
        );
        let after = loaded_session(&runtime.live, HMAC_SESSION)
            .expect("the session is still loaded")
            .audit_digest
            .clone();
        assert_eq!(before, after, "the audited session keeps its digest");
    }

    #[test]
    fn session_handle_error_oracle_match() {
        let mut runtime = audited_runtime();
        for (record, handle, code) in [
            ("SESSION_AUDIT_PASSWORD_HANDLE", TPM_RS_PW, RC_HANDLE3_VALUE),
            ("SESSION_AUDIT_POLICY_HANDLE", 0x0300_0000, RC_HANDLE3_VALUE),
            (
                "SESSION_AUDIT_UNLOADED_HANDLE",
                0x0200_0005,
                RC_REFERENCE_H2,
            ),
        ] {
            assert_eq!(
                run(
                    &mut runtime,
                    &audit_digest_command(TPM_RH_ENDORSEMENT, KEY0, handle, ALG_NULL)
                ),
                vector(record),
                "{record}"
            );
            assert_eq!(response_code(vector(record)), code, "{record}");
        }
    }

    #[test]
    fn flushed_session_reference_removal() {
        let mut runtime = audited_runtime();
        run_ok(
            &mut runtime,
            &command(CC_FLUSH_CONTEXT, &[], None, &HMAC_SESSION.to_be_bytes()),
            "the session flushes",
        );
        assert_eq!(
            run(
                &mut runtime,
                &audit_digest_command(TPM_RH_ENDORSEMENT, KEY0, HMAC_SESSION, ALG_NULL)
            ),
            vector("SESSION_AUDIT_FLUSHED")
        );
        assert_eq!(
            response_code(vector("SESSION_AUDIT_FLUSHED")),
            RC_REFERENCE_H2
        );
    }

    #[test]
    fn attestation_authorization_endorsement_hierarchy_only() {
        let mut runtime = audited_runtime();
        assert_eq!(
            run(
                &mut runtime,
                &audit_digest_command(TPM_RH_OWNER, KEY0, HMAC_SESSION, ALG_NULL)
            ),
            vector("SESSION_AUDIT_OWNER_PRIVACY")
        );
        assert_eq!(
            response_code(vector("SESSION_AUDIT_OWNER_PRIVACY")),
            RC_HANDLE1_VALUE
        );
    }

    #[test]
    fn trailing_parameter_bytes_size_error() {
        let mut runtime = audited_runtime();
        let mut parameters = tpm2b(&QUALIFY);
        parameters.extend_from_slice(&sig_scheme(ALG_NULL, 0));
        assert_trailing_byte_oracle(
            &mut runtime,
            TPM_CC_GET_SESSION_AUDIT_DIGEST,
            &[TPM_RH_ENDORSEMENT, KEY0, HMAC_SESSION],
            &[pw(), pw()],
            &parameters,
            "SESSION_AUDIT_TRAILING",
        );
    }

    #[test]
    fn failed_attestation_no_state_change() {
        let mut runtime = audited_runtime();
        run_ok(
            &mut runtime,
            &audit_digest_command(TPM_RH_ENDORSEMENT, KEY0, HMAC_SESSION, ALG_NULL),
            "the first authorization performs the DA-used transition",
        );
        runtime.nv_update_pending = false;
        let before = crate::library::tpm2::persistent::persistent_all_store(runtime.state())
            .expect("the state serializes");
        assert_ne!(
            response_code(&run(
                &mut runtime,
                &audit_digest_command(TPM_RH_ENDORSEMENT, KEY0, 0x0200_0005, ALG_NULL)
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
    fn parameter_mutation_panic_safety() {
        let mut full = tpm2b(&QUALIFY);
        full.extend_from_slice(&sig_scheme(ALG_RSASSA, ALG_SHA256));
        let mut runtime = audited_runtime();
        for_each_mutation(
            "TPM2_GetSessionAuditDigest",
            byte_replacements(&full, &REPLACEMENT_BYTES),
            |parameters| {
                let _ = run(
                    &mut runtime,
                    &command(
                        TPM_CC_GET_SESSION_AUDIT_DIGEST,
                        &[TPM_RH_ENDORSEMENT, KEY0, HMAC_SESSION],
                        Some(&[pw(), pw()]),
                        &parameters,
                    ),
                );
            },
        );
    }
}
