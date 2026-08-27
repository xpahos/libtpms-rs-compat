use super::key::{RC_KEY_HANDLE, ecc_key};
use crate::library::constants::{TPM_RC_ATTRIBUTES, TPM_RC_FAILURE, TPM_RC_SCHEME, TPM_RC_SIZE};
use crate::library::tpm2::algorithm::TPM_ALG_ECDH;
use crate::library::tpm2::command::core::dispatcher::{CommandFrame, handle_at};
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::command::core::response_code::{
    TPM_RC_1, TPM_RC_2, TPM_RC_3, TPM_RC_4, TPM_RC_P,
};
use crate::library::tpm2::command::object::load::algorithm_policy;
use crate::library::tpm2::ecc::{
    EccPoint, EccSelfTest, MAX_ECC_MESSAGE, crypt_ecc_decrypt, crypt_ecc_encrypt, ecc_curve_id,
    ecc_key_kdf, ecc_private_scalar, ecc_public_point, parse_ecc_point, select_kdf_scheme,
    write_ecc_point,
};
use crate::library::tpm2::marshal::BlobWriter;
use crate::library::tpm2::public::{DIGEST_SIZE, Scheme};
use crate::library::tpm2::random::{finish_live_rand, take_live_rand};
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::self_test::self_test_algorithm;
use crate::library::tpm2::template::{TPMA_OBJECT_DECRYPT, TPMA_OBJECT_RESTRICTED, TemplateReader};
use crate::types::TpmResult;

const RC_PLAIN_TEXT: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_ENCRYPT_SCHEME: TpmResult = TPM_RC_P + TPM_RC_2;
const RC_C1: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_C2: TpmResult = TPM_RC_P + TPM_RC_2;
const RC_C3: TpmResult = TPM_RC_P + TPM_RC_3;
const RC_DECRYPT_SCHEME: TpmResult = TPM_RC_P + TPM_RC_4;

fn run_self_test(runtime: &mut Tpm2Runtime, gate: EccSelfTest) -> Result<(), TpmResult> {
    match gate {
        EccSelfTest::Ecdh => self_test_algorithm(runtime, TPM_ALG_ECDH),
        EccSelfTest::Hash(hash_alg) => self_test_algorithm(runtime, hash_alg),
    }
}

fn parse_scheme(
    runtime: &Tpm2Runtime,
    reader: &mut TemplateReader<'_>,
    marker: TpmResult,
) -> Result<Scheme, TpmResult> {
    let policy = algorithm_policy(runtime)?;
    policy.kdf_scheme(reader).map_err(|code| code + marker)
}

pub(in crate::library::tpm2::command) fn execute_encrypt(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let key_handle = handle_at(frame, 0)?;
    let mut reader = TemplateReader::new(frame.parameters);
    let plain_text = reader
        .tpm2b(MAX_ECC_MESSAGE)
        .map_err(|code| code + RC_PLAIN_TEXT)?
        .to_vec();
    let requested = parse_scheme(runtime, &mut reader, RC_ENCRYPT_SCHEME)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }

    let key = ecc_key(runtime, key_handle)?;
    let key_kdf = ecc_key_kdf(&key).ok_or(TPM_RC_FAILURE)?;
    let scheme = select_kdf_scheme(key_kdf, requested).ok_or(TPM_RC_SCHEME + RC_ENCRYPT_SCHEME)?;
    let curve_id = ecc_curve_id(&key).ok_or(TPM_RC_FAILURE)?;
    let public = ecc_public_point(&key).ok_or(TPM_RC_FAILURE)?;

    let mut rand = take_live_rand(runtime)?;
    let outcome = crypt_ecc_encrypt(
        curve_id,
        &public,
        scheme,
        &plain_text,
        &mut rand,
        &mut |gate| run_self_test(runtime, gate),
    );
    finish_live_rand(runtime, rand)?;
    let cipher = outcome?;

    let mut writer = BlobWriter::new();
    write_ecc_point(&mut writer, &cipher.c1)?;
    writer.write_tpm2b(&cipher.c2).map_err(|_| TPM_RC_SIZE)?;
    writer.write_tpm2b(&cipher.c3).map_err(|_| TPM_RC_SIZE)?;
    Ok(CommandOutput::from_parameters(writer.into_bytes()))
}

struct DecryptRequest {
    c1: EccPoint,
    c2: Vec<u8>,
    c3: Vec<u8>,
    scheme: Scheme,
}

fn parse_decrypt(runtime: &Tpm2Runtime, parameters: &[u8]) -> Result<DecryptRequest, TpmResult> {
    let mut reader = TemplateReader::new(parameters);
    let c1 = parse_ecc_point(&mut reader).map_err(|code| code + RC_C1)?;
    let c2 = reader
        .tpm2b(MAX_ECC_MESSAGE)
        .map_err(|code| code + RC_C2)?
        .to_vec();
    let c3 = reader
        .tpm2b(DIGEST_SIZE)
        .map_err(|code| code + RC_C3)?
        .to_vec();
    let scheme = parse_scheme(runtime, &mut reader, RC_DECRYPT_SCHEME)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(DecryptRequest { c1, c2, c3, scheme })
}

pub(in crate::library::tpm2::command) fn execute_decrypt(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let key_handle = handle_at(frame, 0)?;
    let request = parse_decrypt(runtime, frame.parameters)?;

    let key = ecc_key(runtime, key_handle)?;
    let attributes = key.public.object_attributes;
    if attributes & TPMA_OBJECT_RESTRICTED != 0 || attributes & TPMA_OBJECT_DECRYPT == 0 {
        return Err(TPM_RC_ATTRIBUTES + RC_KEY_HANDLE);
    }
    let key_kdf = ecc_key_kdf(&key).ok_or(TPM_RC_FAILURE)?;
    let scheme =
        select_kdf_scheme(key_kdf, request.scheme).ok_or(TPM_RC_SCHEME + RC_DECRYPT_SCHEME)?;
    let curve_id = ecc_curve_id(&key).ok_or(TPM_RC_FAILURE)?;
    let private = ecc_private_scalar(&key).unwrap_or_default();

    let plain_text = crypt_ecc_decrypt(
        curve_id,
        private,
        scheme,
        &request.c1,
        &request.c2,
        &request.c3,
        &mut |gate| run_self_test(runtime, gate),
    )?;
    let mut writer = BlobWriter::new();
    writer.write_tpm2b(&plain_text).map_err(|_| TPM_RC_SIZE)?;
    Ok(CommandOutput::from_parameters(writer.into_bytes()))
}

#[cfg(test)]
mod tests {
    use crate::library::tpm2::command::core::registry::{
        AuthRole, CommandLifecycle, HandleKind, NvAccess, TPM_CC_ECC_DECRYPT, TPM_CC_ECC_ENCRYPT,
        find,
    };
    use crate::library::tpm2::command::core::test_support::{
        dispatch_bytes, response_code, response_parameters,
    };
    use crate::library::tpm2::command::crypto::ecc::key::test_support::{
        ATTR_DECRYPT, ATTR_SIGN, CC_ECC_DECRYPT, CC_ECC_ENCRYPT, CURVE_P256, Ciphertext, H0,
        KDF_NULL, KDF1_SHA256, KDF2_SHA256, KDF2_SHA384, KEY_AUTH, KEYED_AUTH, MGF1_SHA256,
        PRIVATE_SCALAR, SCHEME_NULL, SHA256, SHA384, ciphertext, cmd, decrypt_parameters,
        ecc_private, ecc_public, expect, framed, generator_multiple, keyed_object, load_external,
        max_message, message, off_curve_point, point2b, public_point, pw, ready_with, restored,
        tpm2b,
    };

    const EPHEMERAL_ONE: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    const EPHEMERAL_EMPTY: [u8; 32] = [
        0x2f, 0x2e, 0x2d, 0x2c, 0x2b, 0x2a, 0x29, 0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21,
        0x20, 0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12,
        0x11, 0x10,
    ];
    const EPHEMERAL_MAX: [u8; 32] = [
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f, 0x50,
    ];
    const EPHEMERAL_SHA384: [u8; 31] = [
        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28,
    ];

    fn decrypt_key(auth: &[u8]) -> Vec<u8> {
        let point = public_point();
        load_external(
            &ecc_private(&PRIVATE_SCALAR, auth),
            &ecc_public(
                ATTR_DECRYPT,
                &SCHEME_NULL,
                CURVE_P256,
                &KDF_NULL,
                &point.x,
                &point.y,
            ),
        )
    }

    fn sign_key() -> Vec<u8> {
        let point = public_point();
        load_external(
            &ecc_private(&PRIVATE_SCALAR, &[]),
            &ecc_public(
                ATTR_SIGN,
                &SCHEME_NULL,
                CURVE_P256,
                &KDF_NULL,
                &point.x,
                &point.y,
            ),
        )
    }

    fn public_only_key() -> Vec<u8> {
        let point = public_point();
        load_external(
            &tpm2b(&[]),
            &ecc_public(
                ATTR_DECRYPT,
                &SCHEME_NULL,
                CURVE_P256,
                &KDF_NULL,
                &point.x,
                &point.y,
            ),
        )
    }

    fn encrypt(plain_text: &[u8], scheme: &[u8]) -> Vec<u8> {
        let mut parameters = tpm2b(plain_text);
        parameters.extend_from_slice(scheme);
        cmd(CC_ECC_ENCRYPT, &[H0], None, &parameters)
    }

    fn decrypt(auth: &[u8], cipher: &Ciphertext, scheme: &[u8]) -> Vec<u8> {
        cmd(
            CC_ECC_DECRYPT,
            &[H0],
            Some(&pw(auth)),
            &decrypt_parameters(cipher, scheme),
        )
    }

    #[test]
    fn the_commands_are_registered_with_the_upstream_attributes() {
        let encrypt = find(TPM_CC_ECC_ENCRYPT).expect("TPM2_ECC_Encrypt is registered");
        assert_eq!(encrypt.attributes, 0x0200_0199);
        assert_eq!((encrypt.decrypt_size, encrypt.encrypt_size), (2, 2));
        assert_eq!(encrypt.handles.len(), 1);
        assert!(
            !encrypt.handles[0].user_auth,
            "the reference does not set HANDLE_1_USER for encryption"
        );
        assert!(matches!(encrypt.handles[0].kind, HandleKind::Object));
        assert!(matches!(encrypt.nv_access, NvAccess::Neither));
        assert!(matches!(
            encrypt.lifecycle,
            CommandLifecycle::RequiresStarted
        ));

        let decrypt = find(TPM_CC_ECC_DECRYPT).expect("TPM2_ECC_Decrypt is registered");
        assert_eq!(decrypt.attributes, 0x0200_019a);
        assert_eq!((decrypt.decrypt_size, decrypt.encrypt_size), (2, 2));
        assert!(decrypt.handles[0].user_auth);
        assert!(decrypt.handles[0].role == AuthRole::User);
    }

    #[test]
    fn the_ciphertexts_match_the_reference_for_every_message_size() {
        let mut runtime = ready_with(&[decrypt_key(KEY_AUTH)]);
        expect(
            &mut runtime,
            "ENC_EXPLICIT",
            &encrypt(&message(32), &KDF2_SHA256),
        );
        expect(&mut runtime, "ENC_EMPTY", &encrypt(&[], &KDF2_SHA256));
        expect(
            &mut runtime,
            "ENC_MAX",
            &encrypt(&max_message(), &KDF2_SHA256),
        );
        expect(
            &mut runtime,
            "ENC_SHA384",
            &encrypt(&message(32), &KDF2_SHA384),
        );
    }

    #[test]
    fn an_encryption_round_trips_through_the_decrypt_command() {
        let mut runtime = ready_with(&[decrypt_key(KEY_AUTH)]);
        let response = expect(
            &mut runtime,
            "ENC_EXPLICIT",
            &encrypt(&message(32), &KDF2_SHA256),
        );
        let parameters = response_parameters(&response);
        let cipher = Ciphertext {
            c1: crate::library::tpm2::ecc::EccPoint {
                x: parameters[4..36].to_vec(),
                y: parameters[38..70].to_vec(),
            },
            c2: parameters[72..72 + 32].to_vec(),
            c3: parameters[72 + 32 + 2..72 + 32 + 2 + 32].to_vec(),
        };
        let recovered = dispatch_bytes(&mut runtime, &decrypt(KEY_AUTH, &cipher, &KDF2_SHA256));
        assert_eq!(response_code(&recovered), 0, "the round trip decrypts");
        assert_eq!(
            response_parameters(&recovered),
            tpm2b(&message(32)),
            "the recovered plain text is the original message"
        );
    }

    #[test]
    fn the_recovered_plain_text_matches_the_reference() {
        let mut runtime = restored("ENC_AFTER");
        for (record, ephemeral, plain_text, scheme, hash) in [
            (
                "DEC_EXPLICIT",
                &EPHEMERAL_ONE[..],
                message(32),
                &KDF2_SHA256[..],
                SHA256,
            ),
            (
                "DEC_EMPTY",
                &EPHEMERAL_EMPTY[..],
                Vec::new(),
                &KDF2_SHA256[..],
                SHA256,
            ),
            (
                "DEC_MAX",
                &EPHEMERAL_MAX[..],
                max_message(),
                &KDF2_SHA256[..],
                SHA256,
            ),
            (
                "DEC_SHA384",
                &EPHEMERAL_SHA384[..],
                message(32),
                &KDF2_SHA384[..],
                SHA384,
            ),
        ] {
            let cipher = ciphertext(ephemeral, &plain_text, hash);
            let response = expect(&mut runtime, record, &decrypt(KEY_AUTH, &cipher, scheme));
            assert_eq!(
                response_parameters(&response),
                tpm2b(&plain_text),
                "{record}"
            );
        }
    }

    #[test]
    fn an_out_of_field_ciphertext_point_matches_the_reference() {
        use crate::library::tpm2::crypto::{BigUint, curve_parameters};
        let curve = curve_parameters(CURVE_P256).expect("NIST P256");
        let mut runtime = restored("ENC_AFTER");
        let mut cipher = ciphertext(&EPHEMERAL_ONE, &message(32), SHA256);
        cipher.c1.x = BigUint::from_be_bytes(&cipher.c1.x)
            .add(&curve.prime)
            .to_be_bytes(33)
            .expect("a 33-byte alias");
        let response = expect(
            &mut runtime,
            "DEC_C1_PLUS_PRIME",
            &decrypt(KEY_AUTH, &cipher, &KDF2_SHA256),
        );
        assert_eq!(
            response_parameters(&response),
            tpm2b(&message(32)),
            "the aliased C1 still recovers the plain text"
        );
    }

    #[test]
    fn a_modified_ciphertext_never_returns_plain_text() {
        let mut runtime = restored("ENC_AFTER");
        let cipher = ciphertext(&EPHEMERAL_ONE, &message(32), SHA256);
        let mut broken_c1 = ciphertext(&EPHEMERAL_ONE, &message(32), SHA256);
        broken_c1.c1.x[31] ^= 0x01;
        let mut broken_c2 = ciphertext(&EPHEMERAL_ONE, &message(32), SHA256);
        broken_c2.c2[0] ^= 0x01;
        let mut broken_c3 = ciphertext(&EPHEMERAL_ONE, &message(32), SHA256);
        broken_c3.c3[0] ^= 0x01;
        for (record, broken) in [
            ("DEC_BAD_C1", &broken_c1),
            ("DEC_BAD_C2", &broken_c2),
            ("DEC_BAD_C3", &broken_c3),
        ] {
            let response = expect(
                &mut runtime,
                record,
                &decrypt(KEY_AUTH, broken, &KDF2_SHA256),
            );
            assert_eq!(response.len(), 10, "{record} carries no plain text");
        }
        let mut off_curve = ciphertext(&EPHEMERAL_ONE, &message(32), SHA256);
        off_curve.c1 = off_curve_point();
        expect(
            &mut runtime,
            "DEC_OFF_CURVE_C1",
            &decrypt(KEY_AUTH, &off_curve, &KDF2_SHA256),
        );
        let mut empty_coordinates = ciphertext(&EPHEMERAL_ONE, &message(32), SHA256);
        empty_coordinates.c1 = crate::library::tpm2::ecc::EccPoint::empty();
        expect(
            &mut runtime,
            "DEC_EMPTY_COORDS_C1",
            &decrypt(KEY_AUTH, &empty_coordinates, &KDF2_SHA256),
        );
        expect(
            &mut runtime,
            "DEC_HASH_MISMATCH",
            &decrypt(KEY_AUTH, &cipher, &KDF2_SHA384),
        );
    }

    #[test]
    fn the_scheme_selection_matches_the_reference() {
        let mut runtime = restored("ENC_AFTER");
        expect(
            &mut runtime,
            "ENC_NO_SCHEME",
            &encrypt(&message(32), &KDF_NULL),
        );
        expect(
            &mut runtime,
            "ENC_MGF1",
            &encrypt(&message(32), &MGF1_SHA256),
        );
        expect(
            &mut runtime,
            "ENC_KDF1",
            &encrypt(&message(32), &KDF1_SHA256),
        );
        expect(
            &mut runtime,
            "ENC_BAD_KDF",
            &encrypt(&message(32), &[0x00, 0x33]),
        );
        expect(
            &mut runtime,
            "ENC_BAD_HASH",
            &encrypt(&message(32), &[0x00, 0x21, 0x00, 0x12]),
        );
        let cipher = ciphertext(&EPHEMERAL_ONE, &message(32), SHA256);
        expect(
            &mut runtime,
            "DEC_NO_SCHEME",
            &decrypt(KEY_AUTH, &cipher, &KDF_NULL),
        );
        expect(
            &mut runtime,
            "DEC_MGF1",
            &decrypt(KEY_AUTH, &cipher, &MGF1_SHA256),
        );
    }

    #[test]
    fn the_framing_failures_match_the_reference() {
        let mut runtime = restored("ENC_AFTER");
        let mut oversize = max_message();
        oversize.push(0x00);
        expect(
            &mut runtime,
            "ENC_TOO_LARGE",
            &encrypt(&oversize, &KDF2_SHA256),
        );
        let mut trailing = tpm2b(&message(32));
        trailing.extend_from_slice(&KDF2_SHA256);
        trailing.push(0x00);
        expect(
            &mut runtime,
            "ENC_TRAILING",
            &cmd(CC_ECC_ENCRYPT, &[H0], None, &trailing),
        );
        expect(
            &mut runtime,
            "ENC_TRUNCATED",
            &cmd(CC_ECC_ENCRYPT, &[H0], None, &tpm2b(&message(32))),
        );
        expect(
            &mut runtime,
            "ENC_MISSING_SCHEME_HASH",
            &encrypt(&message(32), &[0x00, 0x21]),
        );
        expect(
            &mut runtime,
            "ENC_WITH_SESSION",
            &cmd(
                CC_ECC_ENCRYPT,
                &[H0],
                Some(&pw(KEY_AUTH)),
                &[&tpm2b(&message(32))[..], &KDF2_SHA256].concat(),
            ),
        );
        expect(
            &mut runtime,
            "ENC_TRUNCATED_HANDLE",
            &framed(0x8001, CC_ECC_ENCRYPT, &[0x80, 0x00, 0x00]),
        );

        let cipher = ciphertext(&EPHEMERAL_ONE, &message(32), SHA256);
        let mut short_c1 = decrypt_parameters(&cipher, &KDF2_SHA256);
        short_c1.splice(0..2, [0x00, 0x00]);
        expect(
            &mut runtime,
            "DEC_EMPTY_C1",
            &cmd(
                CC_ECC_DECRYPT,
                &[H0],
                Some(&pw(KEY_AUTH)),
                &short_c1[..2]
                    .iter()
                    .copied()
                    .chain(short_c1[70..].iter().copied())
                    .collect::<Vec<u8>>(),
            ),
        );
        let mut oversize_c3 = point2b(&cipher.c1);
        oversize_c3.extend_from_slice(&tpm2b(&cipher.c2));
        oversize_c3.extend_from_slice(&tpm2b(&[0x00; 65]));
        oversize_c3.extend_from_slice(&KDF2_SHA256);
        expect(
            &mut runtime,
            "DEC_OVERSIZE_C3",
            &cmd(CC_ECC_DECRYPT, &[H0], Some(&pw(KEY_AUTH)), &oversize_c3),
        );
        let mut decrypt_trailing = decrypt_parameters(&cipher, &KDF2_SHA256);
        decrypt_trailing.push(0x00);
        expect(
            &mut runtime,
            "DEC_TRAILING",
            &cmd(
                CC_ECC_DECRYPT,
                &[H0],
                Some(&pw(KEY_AUTH)),
                &decrypt_trailing,
            ),
        );
        let mut decrypt_truncated = point2b(&cipher.c1);
        decrypt_truncated.extend_from_slice(&tpm2b(&cipher.c2));
        expect(
            &mut runtime,
            "DEC_TRUNCATED",
            &cmd(
                CC_ECC_DECRYPT,
                &[H0],
                Some(&pw(KEY_AUTH)),
                &decrypt_truncated,
            ),
        );
        expect(
            &mut runtime,
            "DEC_NO_SESSION",
            &cmd(
                CC_ECC_DECRYPT,
                &[H0],
                None,
                &decrypt_parameters(&cipher, &KDF2_SHA256),
            ),
        );
        expect(
            &mut runtime,
            "DEC_BAD_AUTH",
            &decrypt(b"bad", &cipher, &KDF2_SHA256),
        );
    }

    #[test]
    fn the_key_checks_match_the_reference() {
        let cipher = ciphertext(&EPHEMERAL_ONE, &message(32), SHA256);
        let mut runtime = ready_with(&[sign_key()]);
        expect(
            &mut runtime,
            "ENC_SIGN_ONLY_KEY",
            &encrypt(&message(32), &KDF2_SHA256),
        );
        expect(
            &mut runtime,
            "DEC_SIGN_ONLY_KEY",
            &decrypt(&[], &cipher, &KDF2_SHA256),
        );

        let mut runtime = ready_with(&[public_only_key()]);
        expect(
            &mut runtime,
            "ENC_PUBLIC_ONLY",
            &encrypt(&message(32), &KDF2_SHA256),
        );

        let (private, public) = keyed_object();
        let mut runtime = ready_with(&[load_external(&private, &public)]);
        let mut parameters = tpm2b(b"x");
        parameters.extend_from_slice(&KDF2_SHA256);
        expect(
            &mut runtime,
            "ENC_WRONG_TYPE",
            &cmd(CC_ECC_ENCRYPT, &[H0], None, &parameters),
        );
        let mut wrong = point2b(&generator_multiple(2));
        wrong.extend_from_slice(&tpm2b(b"x"));
        wrong.extend_from_slice(&tpm2b(b"y"));
        wrong.extend_from_slice(&KDF2_SHA256);
        expect(
            &mut runtime,
            "DEC_WRONG_TYPE",
            &cmd(CC_ECC_DECRYPT, &[H0], Some(&pw(KEYED_AUTH)), &wrong),
        );
    }

    #[test]
    fn a_rejected_encryption_leaves_the_generator_alone() {
        let mut runtime = restored("ENC_AFTER");
        let before = runtime.live.orderly.drbg_state.seed.expose().to_vec();
        for packet in [
            encrypt(&message(32), &KDF_NULL),
            encrypt(&message(32), &[0x00, 0x33]),
            encrypt(&[0x00; 1025], &KDF2_SHA256),
        ] {
            dispatch_bytes(&mut runtime, &packet);
            assert_eq!(
                runtime.live.orderly.drbg_state.seed.expose(),
                &before[..],
                "a request rejected before the ephemeral key never draws"
            );
        }
    }

    #[test]
    fn an_encryption_advances_the_generator_exactly_once() {
        let mut runtime = ready_with(&[decrypt_key(KEY_AUTH)]);
        let before = runtime.live.orderly.drbg_state.reseed_counter;
        dispatch_bytes(&mut runtime, &encrypt(&message(32), &KDF2_SHA256));
        assert_eq!(
            runtime.live.orderly.drbg_state.reseed_counter,
            before + 1,
            "one private-scalar draw"
        );
    }

    #[test]
    fn a_failed_decryption_leaves_the_state_untouched() {
        let mut runtime = restored("ENC_AFTER");
        let mut broken = ciphertext(&EPHEMERAL_ONE, &message(32), SHA256);
        broken.c3[0] ^= 0x01;
        let packet = decrypt(KEY_AUTH, &broken, &KDF2_SHA256);

        dispatch_bytes(&mut runtime, &packet);
        let before = crate::library::tpm2::persistent::persistent_all_store(runtime.state())
            .expect("the state serializes");
        let nv_before = runtime.nv_memory.clone();
        let drbg_before = runtime.live.orderly.drbg_state.seed.expose().to_vec();
        let objects_before = runtime.live.objects.len();

        for _ in 0..2 {
            let response = dispatch_bytes(&mut runtime, &packet);
            assert_eq!(response.len(), 10, "no plain text escapes");
            assert_eq!(
                crate::library::tpm2::persistent::persistent_all_store(runtime.state())
                    .expect("the state serializes"),
                before
            );
            assert_eq!(runtime.nv_memory, nv_before);
            assert_eq!(
                runtime.live.orderly.drbg_state.seed.expose(),
                &drbg_before[..],
                "decryption never draws"
            );
            assert_eq!(runtime.live.objects.len(), objects_before);
        }
    }
}
