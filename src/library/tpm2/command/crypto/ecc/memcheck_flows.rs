use crate::library::cancel::CancellationToken;
use crate::library::tpm2::command::core::registry::{
    TPM_CC_CONTEXT_LOAD, TPM_CC_CONTEXT_SAVE, TPM_CC_ECC_DECRYPT, TPM_CC_FLUSH_CONTEXT,
    TPM_CC_READ_PUBLIC, TPM_CC_RSA_DECRYPT, TPM_CC_RSA_ENCRYPT, TPM_CC_SIGN,
};
use crate::library::tpm2::command::core::test_support::{
    auth_session, command, create_primary, framed, pw_session, response_parameters,
    restored_snapshot,
};
use crate::library::tpm2::command::crypto::ecc::key::test_support::{
    CC_ECDH_KEYGEN, H0, KDF2_SHA256, SHA256, ciphertext, decrypt_key, decrypt_parameters,
    dispatch_bytes, load_external, ready, response_code, sign_key, tpm2b,
};
use crate::library::tpm2::command::session::processing::{ResponseFault, inject_response_fault};
use crate::library::tpm2::crypto::{SeededRand, generate_rsa_key};
use crate::library::tpm2::golden_responses::rsa_encryption::vector as rsa_vector;
use crate::library::tpm2::memcheck::{Publication, Shadow, Trace, error_count, shadow, traced};
use crate::library::tpm2::persistent::{OwnedAnyObjectBody, OwnedPublicId};
use crate::library::tpm2::runtime::Tpm2Runtime;

const TPM_RH_OWNER: u32 = 0x4000_0001;
const TPM_RH_NULL: u32 = 0x4000_0007;
const ATTR_DECRYPT_KEY: u32 = 0x0002_0072;
const ATTR_SIGN_KEY: u32 = 0x0004_0072;
const ATTR_EXTERNAL_DECRYPT_KEY: u32 = 0x0002_0040;
const ALG_NULL: [u8; 2] = [0x00, 0x10];
const ECDSA_SHA256: [u8; 4] = [0x00, 0x18, 0x00, 0x0b];
const RSAES: [u8; 2] = [0x00, 0x15];
const RESTORED_RSA_KEY: u32 = 0x8000_0000;
const RESTORED_RSA_AUTH: &[u8] = b"dec";

fn phase<T: Send>(name: &str, run: impl FnOnce() -> T + Send) -> T {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name(name.to_string())
            .spawn_scoped(scope, run)
            .expect("a phase thread")
            .join()
            .expect("the phase completes")
    })
}

fn ecc_template(attributes: u32) -> Vec<u8> {
    let mut out = 0x0023u16.to_be_bytes().to_vec();
    out.extend_from_slice(&SHA256.to_be_bytes());
    out.extend_from_slice(&attributes.to_be_bytes());
    out.extend_from_slice(&tpm2b(&[]));
    out.extend_from_slice(&ALG_NULL);
    out.extend_from_slice(&ALG_NULL);
    out.extend_from_slice(&0x0003u16.to_be_bytes());
    out.extend_from_slice(&ALG_NULL);
    out.extend_from_slice(&tpm2b(&[]));
    out.extend_from_slice(&tpm2b(&[]));
    out
}

fn rsa_template(attributes: u32, modulus: &[u8]) -> Vec<u8> {
    let mut out = 0x0001u16.to_be_bytes().to_vec();
    out.extend_from_slice(&SHA256.to_be_bytes());
    out.extend_from_slice(&attributes.to_be_bytes());
    out.extend_from_slice(&tpm2b(&[]));
    out.extend_from_slice(&ALG_NULL);
    out.extend_from_slice(&ALG_NULL);
    out.extend_from_slice(&1024u16.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&tpm2b(modulus));
    out
}

fn rsa_private(prime: &[u8], auth: &[u8]) -> Vec<u8> {
    let mut body = 0x0001u16.to_be_bytes().to_vec();
    body.extend_from_slice(&tpm2b(auth));
    body.extend_from_slice(&tpm2b(&[]));
    body.extend_from_slice(&tpm2b(prime));
    tpm2b(&body)
}

fn sign_command(handle: u32, digest: &[u8]) -> Vec<u8> {
    let mut parameters = tpm2b(digest);
    parameters.extend_from_slice(&ECDSA_SHA256);
    parameters.extend_from_slice(&0x8024u16.to_be_bytes());
    parameters.extend_from_slice(&TPM_RH_NULL.to_be_bytes());
    parameters.extend_from_slice(&tpm2b(&[]));
    command(TPM_CC_SIGN, &[handle], &[&[]], &parameters)
}

fn rsa_encrypt_command(handle: u32, message: &[u8]) -> Vec<u8> {
    let mut parameters = tpm2b(message);
    parameters.extend_from_slice(&RSAES);
    parameters.extend_from_slice(&tpm2b(&[]));
    command(TPM_CC_RSA_ENCRYPT, &[handle], &[], &parameters)
}

fn rsa_decrypt_parameters(ciphertext: &[u8]) -> Vec<u8> {
    let mut parameters = tpm2b(ciphertext);
    parameters.extend_from_slice(&RSAES);
    parameters.extend_from_slice(&tpm2b(&[]));
    parameters
}

fn rsa_decrypt_command(handle: u32, ciphertext: &[u8], password: &[u8]) -> Vec<u8> {
    command(
        TPM_CC_RSA_DECRYPT,
        &[handle],
        &[password],
        &rsa_decrypt_parameters(ciphertext),
    )
}

fn read_public(handle: u32) -> Vec<u8> {
    command(TPM_CC_READ_PUBLIC, &[handle], &[], &[])
}

fn first_tpm2b(parameters: &[u8]) -> Vec<u8> {
    let length = usize::from(u16::from_be_bytes([parameters[0], parameters[1]]));
    parameters[2..2 + length].to_vec()
}

fn response_handle(response: &[u8]) -> u32 {
    u32::from_be_bytes(response[10..14].try_into().expect("a response handle"))
}

fn object_body(
    runtime: &Tpm2Runtime,
    handle: u32,
) -> &crate::library::tpm2::persistent::OwnedObjectBody {
    let slot = usize::try_from(handle - 0x8000_0000).expect("a transient slot");
    match &runtime.live.objects[slot].body {
        OwnedAnyObjectBody::Object(body) => body,
        _ => panic!("{handle:#x} is a loaded object"),
    }
}

fn public_copies(runtime: &Tpm2Runtime, handle: u32) -> Vec<Vec<u8>> {
    let body = object_body(runtime, handle);
    let mut copies = match &body.public.unique {
        OwnedPublicId::Rsa(modulus) => vec![modulus.clone()],
        OwnedPublicId::Ecc { x, y } => vec![x.clone(), y.clone()],
        _ => panic!("an asymmetric key"),
    };
    copies.push(body.name.clone());
    copies.push(body.qualified_name.clone());
    copies
}

fn private_copies(runtime: &Tpm2Runtime, handle: u32) -> Vec<Vec<u8>> {
    let body = object_body(runtime, handle);
    let mut copies = vec![
        body.sensitive
            .sensitive
            .as_ref()
            .expect("a private key")
            .as_bytes()
            .to_vec(),
    ];
    if let Some(exponent) = &body.private_exponent {
        for prime in &exponent.primes {
            copies.push(
                prime
                    .words
                    .iter()
                    .flat_map(|word| word.to_ne_bytes())
                    .collect(),
            );
        }
    }
    copies
}

#[track_caller]
fn single_response(label: &str, trace: &Trace, conceal_secret: bool) -> Publication {
    let responses = trace.published("command-response");
    assert_eq!(responses.len(), 1, "{label}: {:?}", trace.publications());
    let response = responses[0].clone();
    if conceal_secret {
        assert!(
            matches!(response.before, Shadow::Mixed | Shadow::Undefined),
            "{label}: a secret-derived response stays secret until its release: {response:?}"
        );
    } else {
        assert_eq!(
            response.before,
            Shadow::Defined,
            "{label}: the response carries no secret-derived bytes"
        );
    }
    response
}

#[track_caller]
fn nothing_published(label: &str, trace: &Trace) {
    assert!(
        trace.publications().is_empty(),
        "{label}: a failed command publishes nothing: {:?}",
        trace.publications()
    );
}

fn imported_rsa_key() -> (Vec<u8>, Vec<u8>) {
    let mut rand =
        SeededRand::instantiate(&[0x6e; 64], b"FLOWS", b"imported rsa", &[], 1, false).unwrap();
    let key = generate_rsa_key(1024, 0, false, &mut rand, CancellationToken::disabled()).unwrap();
    (
        crate::library::tpm2::memcheck::verification_copy(&key.modulus),
        crate::library::tpm2::memcheck::verification_copy(&key.prime),
    )
}

fn created_keys_are_reused(conceal: bool) {
    let mut runtime = ready();
    let created = phase("create", || {
        let mut handles = Vec::new();
        for (label, template, copies) in [
            ("ecc-sign", ecc_template(ATTR_SIGN_KEY), 4),
            ("ecc-decrypt", ecc_template(ATTR_DECRYPT_KEY), 4),
            ("rsa-decrypt", rsa_template(ATTR_DECRYPT_KEY, &[]), 3),
        ] {
            let ((handle, response), trace) = traced(conceal, || {
                create_primary(&mut runtime, TPM_RH_OWNER, &template)
            });
            single_response(label, &trace, conceal);
            assert_eq!(
                trace.published("released-public-copy").len(),
                copies,
                "{label}: the stored public copies are released with the response"
            );
            assert_eq!(shadow(&response), Shadow::Defined, "{label}");
            for copy in public_copies(&runtime, handle) {
                assert_eq!(
                    shadow(&copy),
                    Shadow::Defined,
                    "{label}: released public copy"
                );
            }
            for copy in private_copies(&runtime, handle) {
                let state = shadow(&copy);
                if conceal {
                    assert!(
                        matches!(state, Shadow::Undefined | Shadow::Mixed),
                        "{label}: the private part stays secret: {state:?}"
                    );
                } else {
                    assert_eq!(state, Shadow::Defined, "{label}");
                }
            }
            handles.push(handle);
        }
        handles
    });
    let [sign_handle, decrypt_handle, rsa_handle] = created[..] else {
        panic!("three keys")
    };
    let ciphertext = phase("public-use", || {
        let errors_before = error_count();
        let (responses, trace) = traced(conceal, || {
            let mut responses = Vec::new();
            for handle in [sign_handle, decrypt_handle, rsa_handle] {
                responses.push(dispatch_bytes(&mut runtime, &read_public(handle)));
            }
            let message = b"public use of a created key".to_vec();
            responses.push(dispatch_bytes(
                &mut runtime,
                &rsa_encrypt_command(rsa_handle, &message),
            ));
            responses
        });
        assert_eq!(
            error_count() - errors_before,
            0,
            "public use of released keys reports no Memcheck error"
        );
        for response in &responses {
            assert_eq!(response_code(response), 0, "the public command succeeds");
        }
        let published = trace.published("command-response");
        assert_eq!(published.len(), responses.len());
        for publication in published {
            assert_eq!(
                publication.before,
                Shadow::Defined,
                "public results of released keys carry no secret: {publication:?}"
            );
        }
        first_tpm2b(&response_parameters(responses.last().expect("RSA_Encrypt")))
    });
    phase("secret-use", || {
        let errors_before = error_count();
        let digest = [0x5au8; 32];
        for (label, packet) in [
            ("TPM2_Sign", sign_command(sign_handle, &digest)),
            (
                "TPM2_ECDH_KeyGen",
                crate::library::tpm2::command::crypto::ecc::key::test_support::cmd(
                    CC_ECDH_KEYGEN,
                    &[decrypt_handle],
                    None,
                    &[],
                ),
            ),
            (
                "TPM2_RSA_Decrypt",
                rsa_decrypt_command(rsa_handle, &ciphertext, &[]),
            ),
        ] {
            let (response, trace) = traced(conceal, || dispatch_bytes(&mut runtime, &packet));
            assert_eq!(response_code(&response), 0, "{label} succeeds");
            single_response(label, &trace, conceal);
            if label == "TPM2_RSA_Decrypt" {
                assert_eq!(
                    first_tpm2b(&response_parameters(&response)),
                    b"public use of a created key",
                    "the created key decrypts what the public phase encrypted"
                );
            }
        }
        let secret_use_errors = error_count() - errors_before;
        if conceal {
            assert!(
                secret_use_errors > 0,
                "the open findings stay visible when created keys are used"
            );
        } else {
            assert_eq!(secret_use_errors, 0, "the control phase reports nothing");
        }
    });
}

#[test]
#[ignore = "flow diagnostic: run under valgrind --tool=memcheck; the public-use thread must stay clean"]
fn memcheck_flow_created_keys_are_reused_by_later_commands() {
    created_keys_are_reused(true);
}

#[test]
#[ignore = "flow control: run under valgrind --tool=memcheck"]
fn memcheck_flow_created_keys_are_reused_by_later_commands_control() {
    created_keys_are_reused(false);
}

fn imported_and_restored_keys(conceal: bool) {
    let (modulus, prime) = imported_rsa_key();
    let mut runtime = ready();
    phase("imported", || {
        let (responses, trace) = traced(conceal, || {
            let ecc = dispatch_bytes(&mut runtime, &sign_key());
            let rsa = dispatch_bytes(
                &mut runtime,
                &load_external(
                    &rsa_private(&prime, &[]),
                    &tpm2b(&rsa_template(ATTR_EXTERNAL_DECRYPT_KEY, &modulus)),
                ),
            );
            (ecc, rsa)
        });
        assert_eq!(response_code(&responses.0), 0, "the ECC key loads");
        assert_eq!(response_code(&responses.1), 0, "the RSA key loads");
        let ecc_handle = response_handle(&responses.0);
        let rsa_handle = response_handle(&responses.1);
        if conceal {
            assert!(
                matches!(
                    trace.states("imported-prime-validation")[..],
                    [Shadow::Undefined]
                ),
                "{:?}",
                trace.observations()
            );
        }
        let (signed, trace) = traced(conceal, || {
            dispatch_bytes(&mut runtime, &sign_command(ecc_handle, &[0x3cu8; 32]))
        });
        assert_eq!(response_code(&signed), 0, "the imported ECC key signs");
        single_response("imported TPM2_Sign", &trace, conceal);
        let encrypted = dispatch_bytes(&mut runtime, &rsa_encrypt_command(rsa_handle, b"import"));
        assert_eq!(response_code(&encrypted), 0);
        let ciphertext = first_tpm2b(&response_parameters(&encrypted));
        let (decrypted, trace) = traced(conceal, || {
            dispatch_bytes(
                &mut runtime,
                &rsa_decrypt_command(rsa_handle, &ciphertext, &[]),
            )
        });
        assert_eq!(
            response_code(&decrypted),
            0,
            "the imported RSA key decrypts"
        );
        assert_eq!(first_tpm2b(&response_parameters(&decrypted)), b"import");
        single_response("imported TPM2_RSA_Decrypt", &trace, conceal);

        let saved = dispatch_bytes(
            &mut runtime,
            &command(TPM_CC_CONTEXT_SAVE, &[ecc_handle], &[], &[]),
        );
        assert_eq!(response_code(&saved), 0, "the imported key is saved");
        let flushed = dispatch_bytes(
            &mut runtime,
            &framed(TPM_CC_FLUSH_CONTEXT, &ecc_handle.to_be_bytes(), false),
        );
        assert_eq!(response_code(&flushed), 0);
        let context = saved[10..].to_vec();
        let (restored_signature, trace) = traced(conceal, || {
            let loaded =
                dispatch_bytes(&mut runtime, &framed(TPM_CC_CONTEXT_LOAD, &context, false));
            assert_eq!(response_code(&loaded), 0, "the saved context loads");
            dispatch_bytes(
                &mut runtime,
                &sign_command(response_handle(&loaded), &[0x3cu8; 32]),
            )
        });
        assert_eq!(response_code(&restored_signature), 0);
        assert_eq!(
            trace.published("command-response").len(),
            2,
            "ContextLoad and Sign each publish their response"
        );
        let signature = trace.published("command-response")[1].clone();
        if conceal {
            assert!(matches!(
                signature.before,
                Shadow::Mixed | Shadow::Undefined
            ));
        }
    });
    let mut restored = restored_snapshot(rsa_vector, "KEYS");
    phase("restored", || {
        let encrypted = dispatch_bytes(
            &mut restored,
            &rsa_encrypt_command(RESTORED_RSA_KEY, b"restored"),
        );
        assert_eq!(response_code(&encrypted), 0);
        let ciphertext = first_tpm2b(&response_parameters(&encrypted));
        let (decrypted, trace) = traced(conceal, || {
            dispatch_bytes(
                &mut restored,
                &rsa_decrypt_command(RESTORED_RSA_KEY, &ciphertext, RESTORED_RSA_AUTH),
            )
        });
        assert_eq!(
            response_code(&decrypted),
            0,
            "the restored RSA key decrypts"
        );
        assert_eq!(first_tpm2b(&response_parameters(&decrypted)), b"restored");
        single_response("restored TPM2_RSA_Decrypt", &trace, conceal);
    });
}

#[test]
#[ignore = "flow diagnostic: run under valgrind --tool=memcheck"]
fn memcheck_flow_imported_and_restored_keys_through_commands() {
    imported_and_restored_keys(true);
}

#[test]
#[ignore = "flow control: run under valgrind --tool=memcheck"]
fn memcheck_flow_imported_and_restored_keys_through_commands_control() {
    imported_and_restored_keys(false);
}

struct ResponseFaultGuard;

impl ResponseFaultGuard {
    fn arm(fault: ResponseFault) -> Self {
        inject_response_fault(Some(fault));
        Self
    }
}

impl Drop for ResponseFaultGuard {
    fn drop(&mut self) {
        inject_response_fault(None);
    }
}

fn late_failures(conceal: bool) {
    let mut keys = restored_snapshot(rsa_vector, "KEYS");
    let mut session = restored_snapshot(rsa_vector, "SESSION");
    let mut ecc = ready();
    let loaded = dispatch_bytes(&mut ecc, &decrypt_key(&[]));
    assert_eq!(response_code(&loaded), 0);
    let ecc_key = response_handle(&loaded);
    assert_eq!(ecc_key, H0);
    phase("late-failure", || {
        let encrypted = dispatch_bytes(&mut keys, &rsa_encrypt_command(RESTORED_RSA_KEY, b"late"));
        let ciphertext = first_tpm2b(&response_parameters(&encrypted));
        let mut not_padded = ciphertext.clone();
        not_padded[0] = 0;
        let last = not_padded.len() - 1;
        not_padded[last] ^= 0x5a;
        let (response, trace) = traced(conceal, || {
            dispatch_bytes(
                &mut keys,
                &rsa_decrypt_command(RESTORED_RSA_KEY, &not_padded, RESTORED_RSA_AUTH),
            )
        });
        assert_ne!(
            response_code(&response),
            0,
            "the padding check fails after the private operation"
        );
        nothing_published("RSA_Decrypt padding failure", &trace);

        let encrypted = dispatch_bytes(
            &mut session,
            &rsa_encrypt_command(RESTORED_RSA_KEY, b"late"),
        );
        assert_eq!(response_code(&encrypted), 0);
        let ciphertext = first_tpm2b(&response_parameters(&encrypted));
        let mut area = pw_session(RESTORED_RSA_AUTH);
        area.extend_from_slice(&auth_session(0x0200_0000, &[0x11; 32], 0x41, &[]));
        let mut payload = RESTORED_RSA_KEY.to_be_bytes().to_vec();
        payload.extend_from_slice(&(area.len() as u32).to_be_bytes());
        payload.extend_from_slice(&area);
        payload.extend_from_slice(&rsa_decrypt_parameters(&ciphertext));
        let packet = framed(TPM_CC_RSA_DECRYPT, &payload, true);
        let (response, trace) = traced(conceal, || {
            let _fault = ResponseFaultGuard::arm(ResponseFault::BeforeFlush);
            dispatch_bytes(&mut session, &packet)
        });
        assert_eq!(
            response_code(&response),
            0x0000_0101,
            "the response session fails after the private operation"
        );
        nothing_published("RSA_Decrypt response-session failure", &trace);
        let (response, trace) = traced(conceal, || dispatch_bytes(&mut session, &packet));
        assert_eq!(
            response_code(&response),
            0,
            "the same command succeeds without the fault"
        );
        single_response("RSA_Decrypt with a response session", &trace, conceal);

        let mut cipher = ciphertext_for_ecc();
        cipher.c3[0] ^= 0x01;
        let (response, trace) = traced(conceal, || {
            dispatch_bytes(
                &mut ecc,
                &command(
                    TPM_CC_ECC_DECRYPT,
                    &[ecc_key],
                    &[&[]],
                    &decrypt_parameters(&cipher, &KDF2_SHA256),
                ),
            )
        });
        assert_ne!(
            response_code(&response),
            0,
            "the integrity check fails after the shared point"
        );
        nothing_published("ECC_Decrypt integrity failure", &trace);
    });
}

fn ciphertext_for_ecc() -> crate::library::tpm2::command::crypto::ecc::key::test_support::Ciphertext
{
    ciphertext(&[0x42; 32], b"late failure", SHA256)
}

#[test]
#[ignore = "flow diagnostic: run under valgrind --tool=memcheck"]
fn memcheck_flow_late_failures_publish_nothing() {
    late_failures(true);
}

#[test]
#[ignore = "flow control: run under valgrind --tool=memcheck"]
fn memcheck_flow_late_failures_publish_nothing_control() {
    late_failures(false);
}
