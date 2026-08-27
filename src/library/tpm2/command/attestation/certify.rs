use super::builder::{
    Attested, check_signing_object, fill_in_attest_info, parse_qualifying_data, parse_scheme,
    sign_and_respond,
};
use crate::ffi::types::TpmResult;
use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_SCHEME, TPM_RC_SIZE};
use crate::library::tpm2::command::core::dispatcher::{CommandFrame, handle_at};
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::command::core::response_code::{TPM_RC_1, TPM_RC_2, TPM_RC_H, TPM_RC_P};
use crate::library::tpm2::command::crypto::signing_state::signing_object;
use crate::library::tpm2::object_create::resolve_any_object;
use crate::library::tpm2::persistent::{OwnedAnyObjectBody, OwnedObjectBody};
use crate::library::tpm2::profile::ValidatedProfile;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::signature::{SigScheme, is_anonymous_scheme, select_sign_scheme};
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
    let object_handle = handle_at(frame, 0)?;
    let sign_handle = handle_at(frame, 1)?;
    let parameters = parse_parameters(
        frame.parameters,
        &runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?.profile,
    )?;

    let sign_object = signing_object(runtime, sign_handle)?;
    check_signing_object(sign_object.as_deref(), RC_SIGN_HANDLE)?;
    let scheme = select_sign_scheme(sign_object.as_deref(), parameters.scheme)
        .ok_or(TPM_RC_SCHEME + RC_IN_SCHEME)?;

    let certified = certified_object(runtime, object_handle)?;
    let attested = Attested::Certify {
        name: certified.name.clone(),
        qualified_name: if is_anonymous_scheme(scheme.scheme) {
            Vec::new()
        } else {
            certified.qualified_name.clone()
        },
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

pub(super) fn certified_object(
    runtime: &Tpm2Runtime,
    handle: u32,
) -> Result<Box<OwnedObjectBody>, TpmResult> {
    let object = resolve_any_object(runtime, handle).ok_or(TPM_RC_FAILURE)?;
    match &object.body {
        OwnedAnyObjectBody::Object(body) => Ok(body.clone()),
        _ => Err(TPM_RC_FAILURE),
    }
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
        ALG_ECDSA, ALG_HMAC, ALG_NULL, ALG_RSAPSS, ALG_RSASSA, ALG_SHA1, ALG_SHA256, DECRYPT_ATTRS,
        KEY0, KEY1, QUALIFY, SIGN_ATTRS, TPM_RH_ENDORSEMENT, TPM_RH_NULL, TPM_RH_OWNER,
        attest_prefix, attested_body, attested_bytes, command, create_primary, ecc_template,
        keyedhash_template, pw, ready_runtime, replay_clock, rsa_template, run, run_ok, sig_scheme,
        signature_bytes, tpm2b,
    };
    use crate::library::tpm2::command::core::registry::{
        CommandLifecycle, HandleKind, NvAccess, TPM_CC_CERTIFY, find,
    };
    use crate::library::tpm2::command::core::test_support::{RC_SUCCESS, response_code};
    use crate::library::tpm2::golden_responses::attestation::vector;
    use crate::library::tpm2::runtime::Tpm2Runtime;

    const RC_HANDLE1_VALUE: u32 = 0x184;
    const RC_HANDLE2_VALUE: u32 = 0x284;
    const RC_HANDLE2_KEY: u32 = 0x29c;
    const RC_PARAM1_SIZE: u32 = 0x1d5;
    const RC_PARAM2_SCHEME: u32 = 0x2d2;
    const RC_AUTH_MISSING: u32 = 0x125;
    const RC_SIZE: u32 = 0x095;

    fn certify_command(
        object: u32,
        sign: u32,
        qualifying: &[u8],
        scheme: u16,
        hash_alg: u16,
    ) -> Vec<u8> {
        let mut parameters = tpm2b(qualifying);
        parameters.extend_from_slice(&sig_scheme(scheme, hash_alg));
        command(
            TPM_CC_CERTIFY,
            &[object, sign],
            Some(&[pw(), pw()]),
            &parameters,
        )
    }

    #[track_caller]
    fn two_signers() -> Box<Tpm2Runtime> {
        let mut runtime = ready_runtime();
        assert_eq!(
            run(
                &mut runtime,
                &create_primary(
                    TPM_RH_ENDORSEMENT,
                    &rsa_template(ALG_RSASSA, ALG_SHA256, SIGN_ATTRS)
                )
            ),
            vector("CREATE_EK_RSA_SIGNER"),
            "the endorsement signer matches the oracle"
        );
        assert_eq!(
            run(
                &mut runtime,
                &create_primary(TPM_RH_OWNER, &ecc_template(ALG_ECDSA, ALG_SHA256))
            ),
            vector("CREATE_SK_ECC_SIGNER"),
            "the owner signer matches the oracle"
        );
        runtime
    }

    #[track_caller]
    fn assert_certify(
        record: &str,
        object: u32,
        sign: u32,
        qualifying: &[u8],
        scheme: u16,
        hash_alg: u16,
    ) {
        let mut runtime = two_signers();
        let expected = vector(record);
        replay_clock(&mut runtime, expected);
        assert_eq!(
            run(
                &mut runtime,
                &certify_command(object, sign, qualifying, scheme, hash_alg)
            ),
            expected,
            "{record}"
        );
    }

    #[test]
    fn the_command_attributes_match_the_oracle() {
        let expected = vector("CCATTR_0148");
        let attributes = u32::from_be_bytes(expected[19..23].try_into().expect("four bytes"));
        assert_eq!(TPM_CC_CERTIFY, 0x0000_0148);
        let descriptor = find(TPM_CC_CERTIFY).expect("a registered command");
        assert_eq!(descriptor.attributes, attributes);
        assert_eq!(descriptor.attributes, 0x0400_0148);
        assert_eq!(descriptor.decrypt_size, 2);
        assert_eq!(descriptor.encrypt_size, 2);
        assert!(!descriptor.physical_presence);
        assert!(descriptor.sessions_allowed);
        assert!(matches!(descriptor.nv_access, NvAccess::Neither));
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
        assert_eq!(descriptor.handles.len(), 2);
        assert!(descriptor.handles[0].user_auth && descriptor.handles[0].admin_role());
        assert!(descriptor.handles[1].user_auth && !descriptor.handles[1].admin_role());
        assert!(matches!(descriptor.handles[0].kind, HandleKind::Object));
        assert!(matches!(
            descriptor.handles[1].kind,
            HandleKind::ObjectAllowNull
        ));
        assert!(!descriptor.handles[0].kind.accepts(TPM_RH_NULL));
        assert!(descriptor.handles[1].kind.accepts(TPM_RH_NULL));
    }

    #[test]
    fn an_rsa_signer_certifies_an_ecc_object_like_the_oracle() {
        assert_certify("CERTIFY_RSA", KEY1, KEY0, &QUALIFY, ALG_NULL, 0);
    }

    #[test]
    fn an_ecc_signer_certifies_an_rsa_object_like_the_oracle() {
        for (record, scheme) in [
            ("CERTIFY_ECC", ALG_NULL),
            ("CERTIFY_ECC_EXPLICIT", ALG_ECDSA),
        ] {
            let mut runtime = two_signers();
            let expected = vector(record);
            replay_clock(&mut runtime, expected);
            let response = run(
                &mut runtime,
                &certify_command(KEY0, KEY1, &QUALIFY, scheme, ALG_SHA256),
            );
            assert_eq!(response_code(&response), RC_SUCCESS, "{record}");
            assert_eq!(
                attested_bytes(&response),
                attested_bytes(expected),
                "{record} attests the reference bytes"
            );
            let signature = signature_bytes(&response);
            assert_eq!(&signature[..4], &[0x00, 0x18, 0x00, 0x0b], "{record}");
            assert_eq!(
                signature.len(),
                signature_bytes(expected).len(),
                "{record} signature layout"
            );
            assert_ecdsa_verifies(&runtime, &response);
        }
    }

    #[track_caller]
    fn assert_ecdsa_verifies(runtime: &Tpm2Runtime, response: &[u8]) {
        use crate::library::tpm2::crypto::{BigUint, Hasher, curve_parameters};
        use crate::library::tpm2::object_create::resolve_any_object;
        use crate::library::tpm2::persistent::{OwnedAnyObjectBody, OwnedPublicId};

        let signature = signature_bytes(response);
        let r_size = u16::from_be_bytes([signature[4], signature[5]]) as usize;
        let r = BigUint::from_be_bytes(&signature[6..6 + r_size]);
        let s_at = 6 + r_size;
        let s_size = u16::from_be_bytes([signature[s_at], signature[s_at + 1]]) as usize;
        let s = BigUint::from_be_bytes(&signature[s_at + 2..s_at + 2 + s_size]);

        let object = resolve_any_object(runtime, KEY1).expect("the signer is loaded");
        let OwnedAnyObjectBody::Object(body) = &object.body else {
            panic!("the handle names a key");
        };
        let OwnedPublicId::Ecc { x, y } = &body.public.unique else {
            panic!("an ECC key");
        };
        let curve = curve_parameters(0x0003).expect("a compiled curve");
        let order = &curve.order;

        let mut hasher = Hasher::new(ALG_SHA256).expect("a compiled hash");
        hasher.update(&attested_bytes(response));
        let digest = BigUint::from_be_bytes(&hasher.finalize())
            .rem(order)
            .expect("a reduced digest");

        let s_inverse = s.mod_inverse(order).expect("s is invertible");
        let u1 = digest.mod_mul(&s_inverse, order).expect("u1");
        let u2 = r.mod_mul(&s_inverse, order).expect("u2");
        let (x_coordinate, _) = curve
            .multiply_sum(
                &u1,
                (&BigUint::from_be_bytes(x), &BigUint::from_be_bytes(y)),
                &u2,
            )
            .expect("the verification point");
        assert_eq!(
            x_coordinate.rem(order).expect("a reduced x"),
            r.rem(order).expect("a reduced r"),
            "the ECDSA signature verifies against the public key"
        );
    }

    #[test]
    fn a_key_may_certify_itself() {
        assert_certify("CERTIFY_SELF_RSA", KEY0, KEY0, &QUALIFY, ALG_NULL, 0);
    }

    #[test]
    fn a_null_signer_answers_a_null_signature() {
        assert_certify(
            "CERTIFY_NULL_SIGNER",
            KEY0,
            TPM_RH_NULL,
            &QUALIFY,
            ALG_NULL,
            0,
        );
        let attest = attested_bytes(vector("CERTIFY_NULL_SIGNER"));
        let (attest_type, signer, extra, _) = attest_prefix(&attest);
        assert_eq!(attest_type, 0x8017);
        assert_eq!(signer, TPM_RH_NULL.to_be_bytes());
        assert_eq!(extra, QUALIFY);
        assert_eq!(signature_bytes(vector("CERTIFY_NULL_SIGNER")), [0x00, 0x10]);
    }

    #[test]
    fn the_qualifying_data_may_be_empty() {
        assert_certify("CERTIFY_NO_QUALIFYING", KEY1, KEY0, &[], ALG_NULL, 0);
    }

    #[test]
    fn an_explicit_scheme_that_matches_the_key_is_accepted() {
        assert_certify(
            "CERTIFY_EXPLICIT_SCHEME",
            KEY1,
            KEY0,
            &QUALIFY,
            ALG_RSASSA,
            ALG_SHA256,
        );
    }

    #[test]
    fn a_scheme_that_disagrees_with_the_key_is_a_scheme_error() {
        assert_certify(
            "CERTIFY_WRONG_SCHEME",
            KEY1,
            KEY0,
            &QUALIFY,
            ALG_RSAPSS,
            ALG_SHA256,
        );
        assert_certify(
            "CERTIFY_WRONG_HASH",
            KEY1,
            KEY0,
            &QUALIFY,
            ALG_RSASSA,
            ALG_SHA1,
        );
        assert_eq!(
            response_code(vector("CERTIFY_WRONG_SCHEME")),
            RC_PARAM2_SCHEME
        );
        assert_eq!(
            response_code(vector("CERTIFY_WRONG_HASH")),
            RC_PARAM2_SCHEME
        );
    }

    #[test]
    fn the_attested_data_carries_the_object_name_and_qualified_name() {
        let mut runtime = two_signers();
        let expected = vector("CERTIFY_RSA");
        replay_clock(&mut runtime, expected);
        let response = run(
            &mut runtime,
            &certify_command(KEY1, KEY0, &QUALIFY, ALG_NULL, 0),
        );
        let attest = attested_bytes(&response);
        let body = attested_body(&attest);
        let name_len = u16::from_be_bytes([body[0], body[1]]) as usize;
        let name = &body[2..2 + name_len];
        let qualified_len = u16::from_be_bytes([body[2 + name_len], body[3 + name_len]]) as usize;
        let qualified = &body[4 + name_len..4 + name_len + qualified_len];
        assert_eq!(
            body.len(),
            4 + name_len + qualified_len,
            "the body is exact"
        );

        let created = vector("CREATE_SK_ECC_SIGNER");
        let size = u32::from_be_bytes(created[14..18].try_into().expect("four bytes")) as usize;
        let parameters = &created[18..18 + size];
        let created_name = &parameters[parameters.len() - 2 - 34..];
        assert_eq!(
            &created_name[2..],
            name,
            "the certified name is the object name"
        );
        assert_ne!(name, qualified);
        assert_eq!(qualified.len(), name.len());
    }

    #[test]
    fn the_signature_verifies_against_the_signing_key() {
        use crate::library::tpm2::crypto::{BigUint, Hasher};
        let mut runtime = two_signers();
        let expected = vector("CERTIFY_RSA");
        replay_clock(&mut runtime, expected);
        let response = run(
            &mut runtime,
            &certify_command(KEY1, KEY0, &QUALIFY, ALG_NULL, 0),
        );
        let attest = attested_bytes(&response);
        let signature = signature_bytes(&response);
        assert_eq!(&signature[..4], &[0x00, 0x14, 0x00, 0x0b]);
        let blob = &signature[6..];
        assert_eq!(blob.len(), 256);

        let create = vector("CREATE_EK_RSA_SIGNER");
        let size = u32::from_be_bytes(create[14..18].try_into().expect("four bytes")) as usize;
        let parameters = &create[18..18 + size];
        let public_size = u16::from_be_bytes([parameters[0], parameters[1]]) as usize;
        let public_area = &parameters[2..2 + public_size];
        let modulus = &public_area[public_area.len() - 256..];

        let recovered = BigUint::from_be_bytes(blob)
            .mod_exp(&BigUint::from_u64(65537), &BigUint::from_be_bytes(modulus))
            .expect("the public operation succeeds")
            .to_be_bytes(256)
            .expect("the block fits the modulus");
        let mut hasher = Hasher::new(ALG_SHA256).expect("a compiled hash");
        hasher.update(&attest);
        assert_eq!(&recovered[256 - 32..], &hasher.finalize()[..]);
        assert_eq!(&recovered[..2], &[0x00, 0x01]);
    }

    #[test]
    fn a_decrypt_only_key_cannot_sign() {
        let mut runtime = ready_runtime();
        run_ok(
            &mut runtime,
            &create_primary(TPM_RH_OWNER, &rsa_template(ALG_NULL, 0, DECRYPT_ATTRS)),
            "the decrypt key is created",
        );
        assert_eq!(
            run(
                &mut runtime,
                &certify_command(KEY0, KEY0, &QUALIFY, ALG_RSASSA, ALG_SHA256)
            ),
            vector("CERTIFY_DECRYPT_ONLY_SIGNER")
        );
        assert_eq!(
            response_code(vector("CERTIFY_DECRYPT_ONLY_SIGNER")),
            RC_HANDLE2_KEY
        );
    }

    #[test]
    fn a_key_without_a_default_scheme_needs_an_explicit_one() {
        let mut runtime = ready_runtime();
        run_ok(
            &mut runtime,
            &create_primary(TPM_RH_OWNER, &rsa_template(ALG_NULL, 0, SIGN_ATTRS)),
            "the schemeless signer is created",
        );
        assert_eq!(
            run(
                &mut runtime,
                &certify_command(KEY0, KEY0, &QUALIFY, ALG_NULL, 0)
            ),
            vector("CERTIFY_KEY_WITHOUT_SCHEME")
        );
        let expected = vector("CERTIFY_KEY_WITH_EXPLICIT_PSS");
        replay_clock(&mut runtime, expected);
        let response = run(
            &mut runtime,
            &certify_command(KEY0, KEY0, &QUALIFY, ALG_RSAPSS, ALG_SHA256),
        );
        assert_eq!(response_code(&response), RC_SUCCESS);
        assert_eq!(
            attested_bytes(&response),
            attested_bytes(expected),
            "the PSS attestation matches the reference bytes"
        );
        let signature = signature_bytes(&response);
        assert_eq!(&signature[..4], &[0x00, 0x16, 0x00, 0x0b]);
        assert_eq!(signature.len(), signature_bytes(expected).len());
        assert_pss_verifies(&runtime, &response);
    }

    #[track_caller]
    fn assert_pss_verifies(runtime: &Tpm2Runtime, response: &[u8]) {
        use crate::library::tpm2::crypto::{BigUint, Hasher, mgf1};
        use crate::library::tpm2::object_create::resolve_any_object;
        use crate::library::tpm2::persistent::{OwnedAnyObjectBody, OwnedPublicId};

        let object = resolve_any_object(runtime, KEY0).expect("the signer is loaded");
        let OwnedAnyObjectBody::Object(body) = &object.body else {
            panic!("the handle names a key");
        };
        let OwnedPublicId::Rsa(modulus) = &body.public.unique else {
            panic!("an RSA key");
        };
        let blob = &signature_bytes(response)[6..];
        let recovered = BigUint::from_be_bytes(blob)
            .mod_exp(&BigUint::from_u64(65537), &BigUint::from_be_bytes(modulus))
            .expect("the public operation succeeds")
            .to_be_bytes(256)
            .expect("the block fits the modulus");
        assert_eq!(recovered[255], 0xbc, "the PSS trailer is present");
        let mask_len = 256 - 32 - 1;
        let h = &recovered[mask_len..mask_len + 32];
        let mask = mgf1(ALG_SHA256, h, mask_len).expect("a mask");
        let mut db: Vec<u8> = recovered[..mask_len]
            .iter()
            .zip(&mask)
            .map(|(left, right)| left ^ right)
            .collect();
        db[0] &= 0x7f;
        assert_eq!(db[mask_len - 33], 0x01, "the salt separator is recovered");
        let salt = &db[mask_len - 32..];
        let mut hasher = Hasher::new(ALG_SHA256).expect("a compiled hash");
        hasher.update(&attested_bytes(response));
        let digest = hasher.finalize();
        let mut hasher = Hasher::new(ALG_SHA256).expect("a compiled hash");
        hasher.update(&[0u8; 8]);
        hasher.update(&digest);
        hasher.update(salt);
        assert_eq!(
            h,
            &hasher.finalize()[..],
            "the PSS hash commits to the attestation digest and the recovered salt"
        );
    }

    #[test]
    fn a_keyed_hash_signer_answers_an_hmac_signature() {
        let mut runtime = ready_runtime();
        run_ok(
            &mut runtime,
            &create_primary(TPM_RH_OWNER, &keyedhash_template(ALG_HMAC, ALG_SHA256)),
            "the keyed-hash signer is created",
        );
        let expected = vector("CERTIFY_HMAC_SIGNER");
        replay_clock(&mut runtime, expected);
        let response = run(
            &mut runtime,
            &certify_command(KEY0, KEY0, &QUALIFY, ALG_NULL, 0),
        );
        assert_eq!(response, expected);
        let signature = signature_bytes(&response);
        assert_eq!(&signature[..4], &[0x00, 0x05, 0x00, 0x0b]);
        assert_eq!(signature.len(), 4 + 32, "TPMT_HA carries a bare digest");
    }

    #[test]
    fn the_handle_errors_match_the_oracle() {
        let mut runtime = two_signers();
        assert_eq!(
            run(
                &mut runtime,
                &certify_command(TPM_RH_NULL, KEY0, &QUALIFY, ALG_NULL, 0)
            ),
            vector("CERTIFY_BAD_OBJECT_HANDLE")
        );
        assert_eq!(
            run(
                &mut runtime,
                &certify_command(0x8000_0005, KEY0, &QUALIFY, ALG_NULL, 0)
            ),
            vector("CERTIFY_UNLOADED_OBJECT")
        );
        assert_eq!(
            run(
                &mut runtime,
                &certify_command(KEY0, TPM_RH_OWNER, &QUALIFY, ALG_NULL, 0)
            ),
            vector("CERTIFY_HIERARCHY_SIGNER")
        );
        assert_eq!(
            response_code(vector("CERTIFY_BAD_OBJECT_HANDLE")),
            RC_HANDLE1_VALUE
        );
        assert_eq!(
            response_code(vector("CERTIFY_UNLOADED_OBJECT")),
            RC_HANDLE1_VALUE
        );
        assert_eq!(
            response_code(vector("CERTIFY_HIERARCHY_SIGNER")),
            RC_HANDLE2_VALUE
        );
    }

    #[test]
    fn every_authorization_session_is_required() {
        let mut runtime = two_signers();
        let mut parameters = tpm2b(&QUALIFY);
        parameters.extend_from_slice(&sig_scheme(ALG_NULL, 0));
        assert_eq!(
            run(
                &mut runtime,
                &command(TPM_CC_CERTIFY, &[KEY1, KEY0], Some(&[pw()]), &parameters)
            ),
            vector("CERTIFY_MISSING_SESSION")
        );
        assert_eq!(
            run(
                &mut runtime,
                &command(TPM_CC_CERTIFY, &[KEY1, KEY0], None, &parameters)
            ),
            vector("CERTIFY_NO_SESSIONS")
        );
        assert_eq!(
            response_code(vector("CERTIFY_MISSING_SESSION")),
            RC_AUTH_MISSING
        );
        assert_eq!(
            response_code(vector("CERTIFY_NO_SESSIONS")),
            RC_AUTH_MISSING
        );
    }

    #[test]
    fn the_parameter_limits_match_the_oracle() {
        let mut runtime = two_signers();
        let oversized: Vec<u8> = (0..67).collect();
        assert_eq!(
            run(
                &mut runtime,
                &certify_command(KEY1, KEY0, &oversized, ALG_NULL, 0)
            ),
            vector("CERTIFY_OVERSIZED_QUALIFYING")
        );
        let mut parameters = tpm2b(&QUALIFY);
        parameters.extend_from_slice(&sig_scheme(ALG_NULL, 0));
        parameters.push(0x00);
        assert_eq!(
            run(
                &mut runtime,
                &command(
                    TPM_CC_CERTIFY,
                    &[KEY1, KEY0],
                    Some(&[pw(), pw()]),
                    &parameters
                )
            ),
            vector("CERTIFY_TRAILING")
        );
        assert_eq!(
            response_code(vector("CERTIFY_OVERSIZED_QUALIFYING")),
            RC_PARAM1_SIZE
        );
        assert_eq!(response_code(vector("CERTIFY_TRAILING")), RC_SIZE);
    }

    #[test]
    fn a_failed_certification_leaves_no_trace() {
        let mut runtime = two_signers();
        run_ok(
            &mut runtime,
            &certify_command(KEY1, KEY0, &QUALIFY, ALG_NULL, 0),
            "the first authorization performs the DA-used transition",
        );
        runtime.nv_update_pending = false;
        let before = crate::library::tpm2::persistent::persistent_all_store(runtime.state())
            .expect("the state serializes");
        let drbg_before = runtime.live.orderly.drbg_state.clone();
        for (object, sign, scheme) in [
            (KEY1, KEY0, ALG_RSAPSS),
            (TPM_RH_NULL, KEY0, ALG_NULL),
            (KEY0, TPM_RH_OWNER, ALG_NULL),
        ] {
            assert_ne!(
                response_code(&run(
                    &mut runtime,
                    &certify_command(object, sign, &QUALIFY, scheme, ALG_SHA256)
                )),
                RC_SUCCESS
            );
            assert_eq!(
                crate::library::tpm2::persistent::persistent_all_store(runtime.state())
                    .expect("the state serializes"),
                before
            );
            assert_eq!(
                runtime.live.orderly.drbg_state.reseed_counter, drbg_before.reseed_counter,
                "a rejected certification draws no randomness"
            );
        }
    }

    #[test]
    fn certify_parameter_mutations_do_not_panic() {
        let mut full = tpm2b(&QUALIFY);
        full.extend_from_slice(&sig_scheme(ALG_RSASSA, ALG_SHA256));
        let mut runtime = two_signers();
        for index in 0..full.len() {
            for byte in [0x00u8, 0x01, 0x7f, 0xff] {
                let mut parameters = full.clone();
                parameters[index] = byte;
                let response = run(
                    &mut runtime,
                    &command(
                        TPM_CC_CERTIFY,
                        &[KEY1, KEY0],
                        Some(&[pw(), pw()]),
                        &parameters,
                    ),
                );
                assert!(response.len() >= 10, "index {index} byte {byte:#04x}");
            }
        }
    }
}
