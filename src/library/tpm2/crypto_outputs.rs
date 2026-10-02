use super::algorithm::{
    TPM_ALG_ECC, TPM_ALG_ECDAA, TPM_ALG_ECDH, TPM_ALG_ECDSA, TPM_ALG_ECSCHNORR, TPM_ALG_NULL,
    TPM_ALG_OAEP, TPM_ALG_RSA, TPM_ALG_RSAES, TPM_ALG_RSAPSS, TPM_ALG_RSASSA, TPM_ALG_SHA256,
    TPM_ALG_SM2,
};
use super::commit::CommitState;
use super::crypto::{Hasher, SeededRand, curve_detail};
use super::ecc::{
    EccPoint, TwoPhaseOutcome, commit_compute, crypt_ecc_decrypt, crypt_ecc_encrypt,
    point_multiply, two_phase_key_exchange,
};
use super::persistent::{
    OwnedObjectBody, OwnedPrivateExponent, OwnedPublicId, OwnedSecret, OwnedTpmtPublic,
    OwnedTpmtSensitive,
};
use super::public::{PublicParms, Scheme, SymDefObject};
use super::rsa_encryption::{RsaDecryptScheme, crypt_rsa_decrypt, crypt_rsa_encrypt};
use super::secret::secret_decrypt;
use super::self_test::LazySelfTest;
use super::signature::{
    SigScheme, Signature, SigningState, marshal_signature, sign_digest, validate_signature,
};
use super::state::COMMIT_ARRAY_SIZE;
use crate::library::cancel::CancellationToken;
use crate::types::TpmResult;

use super::crypto::{CrtWords, EccCurve, EccScalar, crt_words_be};
use super::persistent::OwnedBnPrime;

const MATRIX_INPUT: &str = "matrix-input/";

fn secret_input(case: impl FnOnce() -> String, bytes: &[u8]) {
    super::memcheck::secret(bytes);
    super::memcheck::observe_case(|| format!("{MATRIX_INPUT}{}", case()), bytes);
}

fn released(bytes: &[u8]) {
    super::memcheck::publish("caller-result", bytes);
}

fn release_signature(signature: &Signature) {
    match signature {
        Signature::Ecc { r, s, .. } => {
            released(r);
            released(s);
        }
        Signature::Rsa { signature, .. } => released(signature),
        _ => {}
    }
}

fn stored(case: &str, bytes: &[u8]) -> OwnedSecret {
    let secret = OwnedSecret::copy_of(bytes);
    secret_input(|| format!("{case}/stored"), secret.as_bytes());
    secret
}

fn words_of(value: CrtWords) -> (u16, Vec<u8>) {
    let words = OwnedBnPrime::computed(value).serialized_words().to_vec();
    (
        (words.len() * 8) as u16,
        words.iter().flat_map(|word| word.to_be_bytes()).collect(),
    )
}

macro_rules! key_parts {
    ($key:expr) => {{
        let key = $key;
        (
            key.modulus,
            key.prime,
            vec![
                words_of(key.q),
                words_of(key.d_p),
                words_of(key.d_q),
                words_of(key.q_inv),
            ],
        )
    }};
}
fn recover_words(modulus: &[u8], prime: &[u8], exponent: u32) -> Option<Vec<Vec<u8>>> {
    let imported = prime.to_vec();
    secret_input(|| "recover".into(), &imported);
    let recovered = super::crypto::recover_rsa_private_exponent(modulus, &imported, exponent)?;
    Some(
        [recovered.q, recovered.d_p, recovered.d_q, recovered.q_inv]
            .into_iter()
            .map(|value| {
                let (n, d) = words_of(value);
                let mut v = n.to_be_bytes().to_vec();
                v.extend(d);
                v
            })
            .collect(),
    )
}

fn swapped_words(_prime: &[u8], images: Vec<Vec<u8>>) -> Vec<(u16, Vec<u8>)> {
    images
        .into_iter()
        .map(|image| {
            (
                u16::from_be_bytes([image[0], image[1]]),
                image[2..].to_vec(),
            )
        })
        .collect()
}

fn prime_from_words(data: &[u8], length: usize) -> Vec<u8> {
    let words = OwnedBnPrime::from_image(data.len() as u16, data).words;
    let bytes = crt_words_be(&words);
    bytes[bytes.len() - length..].to_vec()
}

fn exponent_from(words: &[(u16, Vec<u8>)]) -> OwnedPrivateExponent {
    let prime = |index: usize| OwnedBnPrime::from_image(words[index].0, &words[index].1);
    OwnedPrivateExponent {
        primes: [prime(0), prime(1), prime(2), prime(3)],
        runtime: crate::library::tpm2::crypto::RsaRuntimeCache::default(),
    }
}

fn ephemeral(case: &str, curve_id: u16, value: u64) -> EccScalar {
    let bytes = value.to_be_bytes();
    secret_input(|| format!("{case}/ephemeral"), &bytes);
    EccCurve::lookup(curve_id)
        .unwrap()
        .secret_scalar(&bytes)
        .unwrap()
}

fn commit_r(curve_id: u16) -> Option<Vec<u8>> {
    let curve = EccCurve::lookup(curve_id)?;
    let r = commit_state().generate_r(&curve, b"name", None).ok()??;
    r.to_bytes(curve.order_bytes())
}

const TPM_ALG_KDF2: u16 = 0x0021;
const CURVES: [u16; 8] = [
    0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0010, 0x0011, 0x0020,
];

fn fingerprint(bytes: &[u8]) -> String {
    let mut hasher = Hasher::new(TPM_ALG_SHA256).unwrap();
    hasher.update(&(bytes.len() as u32).to_be_bytes());
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn record(out: &mut Vec<String>, label: &str, result: Result<Vec<u8>, TpmResult>) {
    match result {
        Ok(bytes) => {
            let verified = super::memcheck::verification_copy(&bytes);
            out.push(format!("{label} {}", fingerprint(&verified)));
        }
        Err(code) => out.push(format!("{label} err:{code:#x}")),
    }
}

fn rand(label: &[u8], level: u8) -> SeededRand {
    SeededRand::instantiate(&[0x5d; 64], b"PROBE", label, &[], level, false).unwrap()
}

fn null_scheme() -> Scheme {
    Scheme {
        scheme: TPM_ALG_NULL,
        hash_alg: None,
        count: None,
        kdf: None,
    }
}

fn sym_null() -> SymDefObject {
    SymDefObject {
        algorithm: TPM_ALG_NULL,
        key_bits: None,
        mode: None,
    }
}

fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Hasher::new(TPM_ALG_SHA256).unwrap();
    hasher.update(data);
    hasher.finalize()
}

fn body(
    public: OwnedTpmtPublic,
    private: Vec<u8>,
    exponent: Option<OwnedPrivateExponent>,
) -> OwnedObjectBody {
    OwnedObjectBody {
        section_version: 1,
        sensitive: OwnedTpmtSensitive {
            sensitive_type: public.object_type,
            auth_value: OwnedSecret::from_vec(Vec::new()),
            seed_value: OwnedSecret::from_vec(Vec::new()),
            sensitive: Some({
                let secret = OwnedSecret::from_vec(private);
                secret_input(|| "body".into(), secret.as_bytes());
                secret
            }),
        },
        public,
        private_exponent: exponent,
        qualified_name: Vec::new(),
        evict_handle: 0,
        name: vec![0x00, 0x0b, 0x11, 0x22],
        seed_compat_level: 1,
        hierarchy: None,
    }
}

fn rsa_public(modulus: Vec<u8>, exponent: u32) -> OwnedTpmtPublic {
    OwnedTpmtPublic {
        object_type: TPM_ALG_RSA,
        name_alg: TPM_ALG_SHA256,
        object_attributes: (1 << 17) | (1 << 18),
        auth_policy: Vec::new(),
        parameters: PublicParms::Rsa {
            symmetric: sym_null(),
            scheme: null_scheme(),
            key_bits: (modulus.len() * 8) as u16,
            exponent,
        },
        unique: OwnedPublicId::Rsa(modulus),
    }
}

fn ecc_public(curve_id: u16, x: Vec<u8>, y: Vec<u8>, scheme: Scheme) -> OwnedTpmtPublic {
    OwnedTpmtPublic {
        object_type: TPM_ALG_ECC,
        name_alg: TPM_ALG_SHA256,
        object_attributes: (1 << 17) | (1 << 18),
        auth_policy: Vec::new(),
        parameters: PublicParms::Ecc {
            symmetric: sym_null(),
            scheme,
            curve_id,
            kdf: null_scheme(),
        },
        unique: OwnedPublicId::Ecc { x, y },
    }
}

fn profile() -> super::profile::ValidatedProfile {
    super::profile::validate_user_profile(None).unwrap()
}

fn commit_state() -> CommitState {
    CommitState {
        counter: 0x10,
        nonce: OwnedSecret::from_vec(vec![0x6b; 64]),
        array: [0u8; COMMIT_ARRAY_SIZE],
    }
}

fn point_bytes(point: &EccPoint) -> Vec<u8> {
    let mut out = point.x.clone();
    out.push(0xee);
    out.extend_from_slice(&point.y);
    out
}

fn hook(_: super::ecc::EccSelfTest) -> Result<(), TpmResult> {
    Ok(())
}

fn be_add(left: &[u8], right: &[u8]) -> Vec<u8> {
    let width = left.len().max(right.len()) + 1;
    let mut out = vec![0u8; width];
    let mut carry = 0u16;
    for index in 0..width {
        let a = if index < left.len() {
            u16::from(left[left.len() - 1 - index])
        } else {
            0
        };
        let b = if index < right.len() {
            u16::from(right[right.len() - 1 - index])
        } else {
            0
        };
        let sum = a + b + carry;
        out[width - 1 - index] = sum as u8;
        carry = sum >> 8;
    }
    out
}

fn be_sub_small(value: &[u8], small: u8) -> Vec<u8> {
    let mut out = value.to_vec();
    let mut borrow = u16::from(small);
    for byte in out.iter_mut().rev() {
        let current = u16::from(*byte);
        if current >= borrow {
            *byte = (current - borrow) as u8;
            break;
        }
        *byte = (current + 256 - borrow) as u8;
        borrow = 1;
    }
    out
}

fn rsa_matrix(out: &mut Vec<String>) {
    let cases: [(u16, u32, bool, &[u8], u8); 6] = [
        (1024, 0, false, b"r1", 1),
        (1024, 0, true, b"r2", 1),
        (1024, 65539, false, b"r3", 1),
        (1024, 0, false, b"r4", 0),
        (2048, 0, true, b"r5", 1),
        (3072, 0, false, b"r6", 1),
    ];
    for (bits, exponent, signing, label, level) in cases {
        let name = format!(
            "rsa{bits}/{}/{exponent}/{signing}/{level}",
            core::str::from_utf8(label).unwrap()
        );
        let mut generator = rand(label, level);
        let key = super::crypto::generate_rsa_key(
            bits,
            exponent,
            signing,
            &mut generator,
            CancellationToken::disabled(),
        )
        .unwrap();
        released(&key.modulus);
        let (modulus, prime, words) = key_parts!(key);
        record(out, &format!("{name}/modulus"), Ok(modulus.clone()));
        record(out, &format!("{name}/prime"), Ok(prime.clone()));
        for (index, (numbytes, data)) in words.iter().enumerate() {
            let mut image = numbytes.to_be_bytes().to_vec();
            image.extend_from_slice(data);
            record(out, &format!("{name}/word{index}"), Ok(image));
        }
        record(
            out,
            &format!("{name}/drbg"),
            Ok(generator.random_bytes(32).unwrap()),
        );

        let recovered = recover_words(&modulus, &prime, exponent);
        record(
            out,
            &format!("{name}/recover"),
            recovered.map(|words| words.concat()).ok_or(0xdead),
        );
        let q_bytes = prime_from_words(&words[0].1, prime.len());
        let swapped = recover_words(&modulus, &q_bytes, exponent);
        record(
            out,
            &format!("{name}/recover-swapped"),
            swapped.clone().map(|words| words.concat()).ok_or(0xdead),
        );

        let key_body = body(
            rsa_public(modulus.clone(), exponent),
            prime.clone(),
            Some(exponent_from(&words)),
        );
        let digest = sha256(name.as_bytes());
        let profile = profile();
        for (scheme_alg, tag) in [(TPM_ALG_RSASSA, "rsassa"), (TPM_ALG_RSAPSS, "rsapss")] {
            let scheme = SigScheme {
                scheme: scheme_alg,
                hash_alg: TPM_ALG_SHA256,
                count: 0,
            };
            let mut state = SigningState {
                rand: rand(b"sign", 1),
                commit: commit_state(),
            };
            let signature = sign_digest(Some(&key_body), &scheme, &digest, &profile, &mut state);
            if let Ok(signature) = &signature {
                release_signature(signature);
            }
            record(
                out,
                &format!("{name}/{tag}"),
                signature
                    .as_ref()
                    .map(marshal_signature)
                    .map_err(|code| *code),
            );
            if let Ok(signature) = signature {
                let verified = validate_signature(&key_body, false, &digest, &signature, &profile)
                    .map(|_| vec![1u8]);
                record(out, &format!("{name}/{tag}-verify"), verified);
            }
        }
        let length = modulus.len();
        let mut inputs: Vec<(String, Vec<u8>)> = Vec::new();
        let mut one = vec![0u8; length];
        one[length - 1] = 1;
        inputs.push(("one".into(), one));
        let mut two = vec![0u8; length];
        two[length - 1] = 2;
        inputs.push(("two".into(), two));
        inputs.push(("n-1".into(), be_sub_small(&modulus, 1)));
        let mut sparse = vec![0u8; length];
        sparse[length / 2] = 0x80;
        sparse[length - 1] = 0x03;
        inputs.push(("sparse".into(), sparse));
        inputs.push(("random".into(), {
            let mut v = rand(b"ct", 1).random_bytes(length).unwrap();
            v[0] &= 0x3f;
            v
        }));
        inputs.push(("n".into(), modulus.clone()));
        for (tag, input) in &inputs {
            let decrypted = crypt_rsa_decrypt(
                &key_body,
                &RsaDecryptScheme {
                    scheme: TPM_ALG_NULL,
                    hash_alg: 0x0000,
                },
                input,
                &[],
                false,
                &mut LazySelfTest::untested(),
            );
            record(out, &format!("{name}/raw-{tag}"), decrypted);
        }
        if let Some(swapped) = swapped {
            let swapped_body = body(
                rsa_public(modulus.clone(), exponent),
                q_bytes.clone(),
                Some(exponent_from(&swapped_words(&prime, swapped))),
            );
            let decrypted = crypt_rsa_decrypt(
                &swapped_body,
                &RsaDecryptScheme {
                    scheme: TPM_ALG_NULL,
                    hash_alg: 0x0000,
                },
                &inputs[4].1,
                &[],
                false,
                &mut LazySelfTest::untested(),
            );
            record(out, &format!("{name}/raw-swapped"), decrypted);
        }
        for (scheme_alg, hash_alg, tag) in [
            (TPM_ALG_OAEP, TPM_ALG_SHA256, "oaep"),
            (TPM_ALG_RSAES, 0x0000u16, "rsaes"),
        ] {
            let scheme = RsaDecryptScheme {
                scheme: scheme_alg,
                hash_alg,
            };
            let mut encrypt_rand = rand(b"enc", 1);
            let encrypted = crypt_rsa_encrypt(
                &key_body.public,
                &scheme,
                b"message bytes",
                b"LABEL\0",
                false,
                &mut LazySelfTest::untested(),
                &mut encrypt_rand,
            );
            record(out, &format!("{name}/{tag}-encrypt"), encrypted.clone());
            if let Ok(ciphertext) = encrypted {
                let decrypted = crypt_rsa_decrypt(
                    &key_body,
                    &scheme,
                    &ciphertext,
                    b"LABEL\0",
                    false,
                    &mut LazySelfTest::untested(),
                );
                record(out, &format!("{name}/{tag}-decrypt"), decrypted);
                let secret = secret_decrypt(
                    &key_body,
                    b"LABEL\0",
                    &ciphertext,
                    &mut LazySelfTest::untested(),
                );
                record(out, &format!("{name}/{tag}-secret"), secret);
            }
        }
    }
}

fn ecc_matrix(out: &mut Vec<String>) {
    let profile = profile();
    for curve_id in CURVES {
        let name = format!("ecc{curve_id:04x}");
        let detail = curve_detail(curve_id).unwrap();
        let mut generator = rand(name.as_bytes(), 1);
        let key = super::crypto::generate_ecc_key(curve_id, &mut generator).unwrap();
        released(&key.x);
        released(&key.y);
        record(out, &format!("{name}/key-x"), Ok(key.x.clone()));
        record(out, &format!("{name}/key-y"), Ok(key.y.clone()));
        record(out, &format!("{name}/key-d"), Ok(key.private.clone()));
        record(
            out,
            &format!("{name}/drbg"),
            Ok(generator.random_bytes(32).unwrap()),
        );
        let other = super::crypto::generate_ecc_key(curve_id, &mut rand(b"other", 1)).unwrap();
        released(&other.x);
        released(&other.y);

        let order = detail.order.clone();
        let width = key.private.len();
        let mut scalars: Vec<(String, Vec<u8>)> = vec![
            ("zero".into(), vec![0u8; width]),
            ("one".into(), vec![1u8]),
            ("two".into(), vec![0, 2]),
            ("three".into(), vec![3u8]),
            ("n-1".into(), be_sub_small(&order, 1)),
            ("n".into(), order.clone()),
            ("n+1".into(), be_add(&order, &[1])),
            ("2n+5".into(), be_add(&be_add(&order, &order), &[5])),
            ("wide".into(), rand(b"wide", 1).random_bytes(72).unwrap()),
            ("padded".into(), {
                let mut v = vec![0u8; 3];
                v.extend_from_slice(&other.private);
                v
            }),
            ("sparse".into(), {
                let mut v = vec![0u8; width];
                v[1] = 0x40;
                v[width - 1] = 1;
                v
            }),
            ("dense".into(), {
                let mut v = vec![0xffu8; width];
                v[0] = 0x0f;
                v
            }),
        ];
        scalars.push(("private".into(), other.private.clone()));
        let generator_point = EccPoint {
            x: detail.generator_x.clone(),
            y: detail.generator_y.clone(),
        };
        let public = EccPoint {
            x: key.x.clone(),
            y: key.y.clone(),
        };
        let aliased = EccPoint {
            x: be_add(&key.x, &detail.prime),
            y: key.y.clone(),
        };
        let mut off_curve = public.clone();
        off_curve.y[0] ^= 0x01;
        for (tag, scalar) in &scalars {
            secret_input(|| format!("{name}/mulg-{tag}"), scalar);
            record(
                out,
                &format!("{name}/mulg-{tag}"),
                point_multiply(curve_id, None, scalar).map(|p| point_bytes(&p)),
            );
            secret_input(|| format!("{name}/mulq-{tag}"), scalar);
            record(
                out,
                &format!("{name}/mulq-{tag}"),
                point_multiply(curve_id, Some(&public), scalar).map(|p| point_bytes(&p)),
            );
        }
        for (tag, base) in [
            ("aliased", &aliased),
            ("generator-point", &generator_point),
            ("off-curve", &off_curve),
        ] {
            secret_input(|| format!("{name}/mul-{tag}"), &other.private);
            record(
                out,
                &format!("{name}/mul-{tag}"),
                point_multiply(curve_id, Some(base), &other.private).map(|p| point_bytes(&p)),
            );
        }

        let digest = sha256(name.as_bytes());
        for (scheme_alg, tag) in [
            (TPM_ALG_ECDSA, "ecdsa"),
            (TPM_ALG_ECSCHNORR, "ecschnorr"),
            (TPM_ALG_SM2, "sm2"),
            (TPM_ALG_ECDAA, "ecdaa"),
        ] {
            let key_scheme = if scheme_alg == TPM_ALG_ECDAA {
                Scheme {
                    scheme: TPM_ALG_ECDAA,
                    hash_alg: Some(TPM_ALG_SHA256),
                    count: Some(0),
                    kdf: None,
                }
            } else {
                null_scheme()
            };
            let key_body = body(
                ecc_public(curve_id, key.x.clone(), key.y.clone(), key_scheme),
                key.private.clone(),
                None,
            );
            let scheme = SigScheme {
                scheme: scheme_alg,
                hash_alg: TPM_ALG_SHA256,
                count: 0x10,
            };
            let mut state = SigningState {
                rand: rand(b"sign", 1),
                commit: commit_state(),
            };
            state.commit.commit();
            let signature = sign_digest(Some(&key_body), &scheme, &digest, &profile, &mut state);
            if let Ok(signature) = &signature {
                release_signature(signature);
            }
            record(
                out,
                &format!("{name}/{tag}"),
                signature
                    .as_ref()
                    .map(marshal_signature)
                    .map_err(|code| *code),
            );
            record(
                out,
                &format!("{name}/{tag}-drbg"),
                state.rand.random_bytes(16),
            );
            if let Ok(signature) = &signature
                && scheme_alg != TPM_ALG_ECDAA
            {
                let verified = validate_signature(&key_body, false, &digest, signature, &profile)
                    .map(|_| vec![1u8]);
                record(out, &format!("{name}/{tag}-verify"), verified);
                if let Signature::Ecc {
                    scheme,
                    hash_alg,
                    r,
                    s,
                } = signature
                {
                    let mut tampered = s.clone();
                    let last = tampered.len() - 1;
                    tampered[last] ^= 0x01;
                    let tampered = Signature::Ecc {
                        scheme: *scheme,
                        hash_alg: *hash_alg,
                        r: r.clone(),
                        s: tampered,
                    };
                    let rejected =
                        validate_signature(&key_body, false, &digest, &tampered, &profile)
                            .map(|_| vec![1u8]);
                    record(out, &format!("{name}/{tag}-tampered"), rejected);
                    let high = Signature::Ecc {
                        scheme: *scheme,
                        hash_alg: *hash_alg,
                        r: r.clone(),
                        s: order.clone(),
                    };
                    let rejected = validate_signature(&key_body, false, &digest, &high, &profile)
                        .map(|_| vec![1u8]);
                    record(out, &format!("{name}/{tag}-order-s"), rejected);
                }
            }
        }

        let kdf2 = Scheme {
            scheme: TPM_ALG_KDF2,
            hash_alg: Some(TPM_ALG_SHA256),
            count: None,
            kdf: None,
        };
        let encrypted = crypt_ecc_encrypt(
            curve_id,
            &public,
            kdf2,
            b"ecc message",
            &mut rand(b"ecenc", 1),
            &mut hook,
        );
        match encrypted {
            Ok(cipher) => {
                for part in [&cipher.c1.x, &cipher.c1.y, &cipher.c2, &cipher.c3] {
                    released(part);
                }
                let mut image = point_bytes(&cipher.c1);
                image.extend_from_slice(&cipher.c2);
                image.extend_from_slice(&cipher.c3);
                record(out, &format!("{name}/ecc-encrypt"), Ok(image));
                record(
                    out,
                    &format!("{name}/ecc-decrypt"),
                    crypt_ecc_decrypt(
                        curve_id,
                        Some(&stored(&format!("{name}/ecc-decrypt"), &key.private)),
                        kdf2,
                        &cipher.c1,
                        &cipher.c2,
                        &cipher.c3,
                        &mut hook,
                    ),
                );
                let aliased_c1 = EccPoint {
                    x: be_add(&cipher.c1.x, &detail.prime),
                    y: cipher.c1.y.clone(),
                };
                record(
                    out,
                    &format!("{name}/ecc-decrypt-aliased"),
                    crypt_ecc_decrypt(
                        curve_id,
                        Some(&stored(
                            &format!("{name}/ecc-decrypt-aliased"),
                            &key.private,
                        )),
                        kdf2,
                        &aliased_c1,
                        &cipher.c2,
                        &cipher.c3,
                        &mut hook,
                    ),
                );
                let mut secret = (cipher.c1.x.len() as u16).to_be_bytes().to_vec();
                secret.extend_from_slice(&cipher.c1.x);
                secret.extend_from_slice(&(cipher.c1.y.len() as u16).to_be_bytes());
                secret.extend_from_slice(&cipher.c1.y);
                let key_body = body(
                    ecc_public(curve_id, key.x.clone(), key.y.clone(), null_scheme()),
                    key.private.clone(),
                    None,
                );
                record(
                    out,
                    &format!("{name}/ecc-secret"),
                    secret_decrypt(
                        &key_body,
                        b"SECRET\0",
                        &secret,
                        &mut LazySelfTest::untested(),
                    ),
                );
            }
            Err(code) => record(out, &format!("{name}/ecc-encrypt"), Err(code)),
        }

        let other_public = EccPoint {
            x: other.x.clone(),
            y: other.y.clone(),
        };
        for (scheme_alg, tag) in [(TPM_ALG_ECDH, "ecdh"), (TPM_ALG_SM2, "sm2x")] {
            let exchanged = two_phase_key_exchange(
                curve_id,
                scheme_alg,
                Some(&stored(&format!("{name}/{tag}"), &key.private)),
                &ephemeral(&format!("{name}/{tag}"), curve_id, 0x0123_4567_89ab),
                &other_public,
                &public,
            );
            record(
                out,
                &format!("{name}/{tag}"),
                exchanged.map(|result| {
                    let mut image = point_bytes(&result.z1);
                    image.extend_from_slice(&point_bytes(&result.z2));
                    image.push(u8::from(result.outcome == TwoPhaseOutcome::Points));
                    image
                }),
            );
        }
        let never = || false;
        let committed = commit_compute(
            curve_id,
            Some(&other_public),
            Some(&public),
            Some(&stored(&format!("{name}/commit"), &key.private)),
            &ephemeral(&format!("{name}/commit"), curve_id, 0x0bad_cafe),
            &never,
        );
        record(
            out,
            &format!("{name}/commit"),
            committed.map(|(k, l, e)| {
                let mut image = point_bytes(&k);
                image.extend_from_slice(&point_bytes(&l));
                image.extend_from_slice(&point_bytes(&e));
                image
            }),
        );
        record(
            out,
            &format!("{name}/commit-r"),
            commit_r(curve_id).ok_or(0xdead),
        );
    }
}

fn assert_listing(actual: &[String], pinned: &str) {
    assert_listing_with_parity(actual, pinned, "");
}

fn assert_listing_with_parity(actual: &[String], pinned: &str, parity: &str) {
    let replacements: Vec<(&str, &str)> = parity
        .lines()
        .map(|line| line.split_once(' ').expect("a name and a digest"))
        .collect();
    let expected: Vec<String> = pinned
        .lines()
        .map(|line| {
            let name = line.split_once(' ').map_or(line, |(name, _)| name);
            match replacements.iter().find(|(entry, _)| *entry == name) {
                Some((entry, digest)) => {
                    assert_ne!(line, format!("{entry} {digest}"), "{entry} is unchanged");
                    format!("{entry} {digest}")
                }
                None => line.to_string(),
            }
        })
        .collect();
    for (name, _) in &replacements {
        assert!(
            pinned
                .lines()
                .any(|line| line.starts_with(&format!("{name} "))),
            "{name} is not a pinned entry"
        );
    }
    let mismatches: Vec<String> = actual
        .iter()
        .zip(&expected)
        .enumerate()
        .filter(|(_, (line, pinned))| line != pinned)
        .map(|(index, (line, pinned))| format!("line {index}: {line} (pinned {pinned})"))
        .collect();
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    assert_eq!(actual.len(), expected.len(), "listing length");
}

#[test]
fn rsa_outputs_match_commit_16260bd() {
    let mut out = Vec::new();
    rsa_matrix(&mut out);
    assert_listing(
        &out,
        include_str!("testdata/crypto_outputs_rsa_16260bd.txt"),
    );
}

#[test]
fn ecc_outputs_match_commit_16260bd() {
    let mut out = Vec::new();
    ecc_matrix(&mut out);
    assert_listing_with_parity(
        &out,
        include_str!("testdata/crypto_outputs_ecc_16260bd.txt"),
        include_str!("testdata/crypto_outputs_ecc_c_parity.txt"),
    );
}

#[derive(Clone, Copy)]
struct Matrix {
    run: fn(&mut Vec<String>),
    secret_inputs: usize,
}

const ECC_MATRIX: Matrix = Matrix {
    run: ecc_matrix,
    secret_inputs: 42 * CURVES.len(),
};

const RSA_MATRIX: Matrix = Matrix {
    run: rsa_matrix,
    secret_inputs: 4 * 6,
};

fn memcheck_matrix(conceal: bool, matrix: Matrix) -> Vec<String> {
    use super::memcheck::{Shadow, concealing, traced};
    let mut out = Vec::new();
    let (held, trace) = traced(conceal, || {
        (matrix.run)(&mut out);
        concealing()
    });
    assert_eq!(held, conceal, "the marking mode held for the whole run");
    let expected = if conceal {
        Shadow::Undefined
    } else {
        Shadow::Defined
    };
    let inputs: Vec<&(String, Shadow)> = trace
        .observations()
        .iter()
        .filter(|(label, _)| label.starts_with(MATRIX_INPUT))
        .collect();
    let wrong: Vec<String> = inputs
        .iter()
        .filter(|(_, state)| *state != expected)
        .map(|(label, state)| format!("{label}: {state:?}"))
        .collect();
    assert!(
        wrong.is_empty(),
        "secret matrix inputs were not {expected:?} before use:\n{}",
        wrong.join("\n")
    );
    assert_eq!(
        inputs.len(),
        matrix.secret_inputs,
        "every secret matrix input was checked"
    );
    out
}

fn rsa_concealed_diagnostic() -> Vec<String> {
    memcheck_matrix(true, RSA_MATRIX)
}

fn check_ecc_listing(out: &[String]) {
    assert_listing_with_parity(
        out,
        include_str!("testdata/crypto_outputs_ecc_16260bd.txt"),
        include_str!("testdata/crypto_outputs_ecc_c_parity.txt"),
    );
}

fn check_rsa_listing(out: &[String]) {
    assert_listing(out, include_str!("testdata/crypto_outputs_rsa_16260bd.txt"));
}

#[test]
#[ignore = "secret-flow check: run under valgrind --tool=memcheck"]
fn memcheck_ecc_matrix_with_concealed_secrets() {
    check_ecc_listing(&memcheck_matrix(true, ECC_MATRIX));
}

#[test]
#[ignore = "secret-flow control: run under valgrind --tool=memcheck"]
fn memcheck_ecc_matrix_control() {
    check_ecc_listing(&memcheck_matrix(false, ECC_MATRIX));
}

#[test]
#[ignore = "secret-flow check: run alone in a fresh process under valgrind --tool=memcheck"]
fn memcheck_rsa_matrix_cold_process() {
    assert_eq!(
        super::crypto::validated_factor_sets(),
        0,
        "a cold run is the first RSA work in a fresh process"
    );
    check_rsa_listing(&rsa_concealed_diagnostic());
}

#[test]
#[ignore = "secret-flow check: run under valgrind --tool=memcheck"]
fn memcheck_rsa_matrix_with_concealed_secrets() {
    check_rsa_listing(&rsa_concealed_diagnostic());
}

#[test]
#[ignore = "secret-flow check: run under valgrind --tool=memcheck"]
fn memcheck_rsa_matrix_with_validated_factor_sets() {
    let mut warm = Vec::new();
    rsa_matrix(&mut warm);
    assert!(
        super::crypto::validated_factor_sets() > 0,
        "the untainted pass validated the factor sets"
    );
    check_rsa_listing(&rsa_concealed_diagnostic());
}

#[test]
#[ignore = "secret-flow control: run under valgrind --tool=memcheck"]
fn memcheck_rsa_matrix_control() {
    check_rsa_listing(&memcheck_matrix(false, RSA_MATRIX));
}

#[test]
#[ignore = "guard: passes only under Valgrind's Memcheck tool"]
fn memcheck_guard_accepts_only_memcheck() {
    assert!(
        super::memcheck::running_on_valgrind(),
        "not running under Valgrind"
    );
    super::memcheck::require_memcheck();
}

#[test]
#[ignore = "Memcheck canary: must report one finding under valgrind"]
fn memcheck_canary_reports_a_secret_index() {
    super::memcheck::require_memcheck();
    assert_eq!(super::memcheck::canary(true), 3);
}

#[test]
#[ignore = "Memcheck canary: the scoped marking helper must produce one finding under valgrind"]
fn memcheck_scoped_canary_reports_a_marked_branch() {
    use super::memcheck::{MarkingScope, require_memcheck, scoped_canary};
    require_memcheck();
    let _scope = MarkingScope::concealed();
    assert_eq!(scoped_canary(3), 3);
}

#[test]
#[ignore = "Memcheck canary control: the scoped helper in a control scope must stay clean"]
fn memcheck_scoped_canary_control() {
    use super::memcheck::{MarkingScope, require_memcheck, scoped_canary};
    require_memcheck();
    let _scope = MarkingScope::control();
    assert_eq!(scoped_canary(3), 3);
}

#[test]
#[ignore = "Memcheck canary control: must stay clean under valgrind"]
fn memcheck_canary_control() {
    super::memcheck::require_memcheck();
    assert_eq!(super::memcheck::canary(false), 3);
}

#[test]
#[ignore = "performance profile; run with --ignored --nocapture on the target"]
fn ecc_performance_profile() {
    use std::time::Instant;
    fn median(mut samples: Vec<f64>) -> f64 {
        samples.sort_by(f64::total_cmp);
        samples[samples.len() / 2]
    }
    fn time(rounds: usize, mut body: impl FnMut()) -> f64 {
        body();
        median(
            (0..rounds)
                .map(|_| {
                    let start = Instant::now();
                    body();
                    start.elapsed().as_secs_f64() * 1e6
                })
                .collect(),
        )
    }
    let profile = profile();
    let kdf2 = Scheme {
        scheme: TPM_ALG_KDF2,
        hash_alg: Some(TPM_ALG_SHA256),
        count: None,
        kdf: None,
    };
    for curve_id in CURVES {
        let rounds = 64;
        let mut generator = rand(b"profile", 1);
        let key = super::crypto::generate_ecc_key(curve_id, &mut generator).unwrap();
        let keygen = time(rounds, || {
            super::crypto::generate_ecc_key(curve_id, &mut generator).unwrap();
        });
        let public = EccPoint {
            x: key.x.clone(),
            y: key.y.clone(),
        };
        let mulg = time(rounds, || {
            point_multiply(curve_id, None, &key.private).unwrap();
        });
        let mulq = time(rounds, || {
            point_multiply(curve_id, Some(&public), &key.private).unwrap();
        });
        let digest = sha256(b"profile");
        let mut signing = Vec::new();
        for scheme_alg in [TPM_ALG_ECDSA, TPM_ALG_ECSCHNORR, TPM_ALG_SM2, TPM_ALG_ECDAA] {
            let key_scheme = if scheme_alg == TPM_ALG_ECDAA {
                Scheme {
                    scheme: TPM_ALG_ECDAA,
                    hash_alg: Some(TPM_ALG_SHA256),
                    count: Some(0),
                    kdf: None,
                }
            } else {
                null_scheme()
            };
            let key_body = body(
                ecc_public(curve_id, key.x.clone(), key.y.clone(), key_scheme),
                key.private.clone(),
                None,
            );
            let mut state = SigningState {
                rand: rand(b"sign", 1),
                commit: commit_state(),
            };
            signing.push(time(rounds, || {
                let scheme = SigScheme {
                    scheme: scheme_alg,
                    hash_alg: TPM_ALG_SHA256,
                    count: state.commit.commit(),
                };
                sign_digest(Some(&key_body), &scheme, &digest, &profile, &mut state).unwrap();
            }));
        }
        let mut encrypt_rand = rand(b"encrypt", 1);
        let ciphertext = crypt_ecc_encrypt(
            curve_id,
            &public,
            kdf2,
            b"message",
            &mut encrypt_rand,
            &mut hook,
        )
        .unwrap();
        let encrypt = time(rounds, || {
            crypt_ecc_encrypt(
                curve_id,
                &public,
                kdf2,
                b"message",
                &mut encrypt_rand,
                &mut hook,
            )
            .unwrap();
        });
        let private = stored("profile", &key.private);
        let decrypt = time(rounds, || {
            crypt_ecc_decrypt(
                curve_id,
                Some(&private),
                kdf2,
                &ciphertext.c1,
                &ciphertext.c2,
                &ciphertext.c3,
                &mut hook,
            )
            .unwrap();
        });
        eprintln!(
            "ECC {curve_id:#06x} median us: keygen {keygen:.1} mulG {mulg:.1} mulQ {mulq:.1} ecdsa {:.1} ecschnorr {:.1} sm2 {:.1} ecdaa {:.1} encrypt {encrypt:.1} decrypt {decrypt:.1}",
            signing[0], signing[1], signing[2], signing[3]
        );
    }
}

mod boundaries {
    use super::super::memcheck::{Shadow, Trace, shadow, traced, verification_copy};
    use super::*;

    const P256: u16 = 0x0003;
    const P521: u16 = 0x0005;
    const SM2_CURVE: u16 = 0x0020;

    fn states(trace: &Trace, label: &str) -> Vec<Shadow> {
        trace.states(label)
    }

    #[track_caller]
    fn all(trace: &Trace, label: &str, expected: Shadow) -> usize {
        trace.all(label, expected)
    }

    fn ecc_key_body(curve_id: u16, scheme: Scheme) -> (OwnedObjectBody, Vec<u8>, Vec<u8>) {
        let mut generator = rand(b"boundary key", 1);
        let key = super::super::crypto::generate_ecc_key(curve_id, &mut generator).unwrap();
        let x = verification_copy(&key.x);
        let y = verification_copy(&key.y);
        (
            body(
                ecc_public(curve_id, x.clone(), y.clone(), scheme),
                key.private,
                None,
            ),
            x,
            y,
        )
    }

    fn sign(
        body: &OwnedObjectBody,
        scheme_alg: u16,
        rand: SeededRand,
    ) -> (Result<Signature, TpmResult>, SigningState) {
        let mut state = SigningState {
            rand,
            commit: commit_state(),
        };
        let count = state.commit.commit();
        let scheme = SigScheme {
            scheme: scheme_alg,
            hash_alg: TPM_ALG_SHA256,
            count,
        };
        let signature = sign_digest(
            Some(body),
            &scheme,
            &sha256(b"boundary"),
            &profile(),
            &mut state,
        );
        (signature, state)
    }

    #[test]
    #[ignore = "boundary diagnostic: run under valgrind --tool=memcheck"]
    fn memcheck_boundary_nonce_candidates_are_marked_before_their_predicates() {
        let (key, _, _) = ecc_key_body(P256, null_scheme());
        let order = curve_detail(P256).unwrap().order;
        let mut short = vec![0x5au8; 32];
        short[0] = 0;
        let mut script = vec![0u8; 32];
        script.extend_from_slice(&[0xffu8; 32]);
        assert!(
            [0xffu8; 32].as_slice() > order.as_slice(),
            "an out-of-range candidate"
        );
        script.extend_from_slice(&short);
        script.extend_from_slice(&[0x5au8; 32]);
        let ((signature, state), entries) = traced(true, || {
            sign(&key, TPM_ALG_SM2, SeededRand::scripted(&script, 1))
        });
        let signature = signature.expect("the fourth candidate signs");
        assert_eq!(state.rand.script_remaining(), Some(0), "exactly four draws");
        assert_eq!(
            all(&entries, "nonce-candidate", Shadow::Undefined),
            4,
            "zero, out-of-range, short and accepted candidates are all marked before their predicates"
        );
        all(&entries, "sm2-commitment", Shadow::Undefined);
        entries.tainted("signature-output");
        assert!(
            entries.publications().is_empty(),
            "the signature is published by the enclosing command, not the library"
        );
        release_signature(&signature);
        assert!(
            validate_signature(&key, false, &sha256(b"boundary"), &signature, &profile()).is_ok()
        );
    }

    #[test]
    #[ignore = "boundary diagnostic: run under valgrind --tool=memcheck"]
    fn memcheck_boundary_signing_commitments_stay_secret_until_the_signature() {
        for (curve_id, scheme_alg, label) in [
            (P256, TPM_ALG_ECDSA, "ecdsa-commitment"),
            (P521, TPM_ALG_ECDSA, "ecdsa-commitment"),
            (P256, TPM_ALG_ECSCHNORR, "schnorr-commitment"),
            (P521, TPM_ALG_ECSCHNORR, "schnorr-commitment"),
            (SM2_CURVE, TPM_ALG_SM2, "sm2-commitment"),
            (P521, TPM_ALG_SM2, "sm2-commitment"),
        ] {
            let (key, _, _) = ecc_key_body(curve_id, null_scheme());
            let ((signature, _), entries) =
                traced(true, || sign(&key, scheme_alg, rand(b"boundary sign", 1)));
            let signature = signature.expect("a signature");
            all(&entries, label, Shadow::Undefined);
            entries.tainted("signature-output");
            assert!(entries.publications().is_empty());
            release_signature(&signature);
            if scheme_alg != TPM_ALG_SM2 {
                all(&entries, "nonce-draw", Shadow::Undefined);
            }
            assert!(
                validate_signature(&key, false, &sha256(b"boundary"), &signature, &profile())
                    .is_ok()
            );
        }
    }

    #[test]
    #[ignore = "boundary diagnostic: run under valgrind --tool=memcheck"]
    fn memcheck_boundary_retries_and_backend_failures_publish_nothing() {
        use super::super::crypto::{FaultBoundary, arm_fault, disarm_fault};
        let (key, _, _) = ecc_key_body(P256, null_scheme());
        arm_fault(FaultBoundary::Signature, 0);
        let ((failed, _), entries) = traced(true, || {
            sign(&key, TPM_ALG_ECDSA, rand(b"boundary fault", 1))
        });
        assert!(disarm_fault() || failed.is_err());
        assert!(failed.is_err(), "the injected failure fails the signature");
        all(&entries, "ecdsa-commitment", Shadow::Undefined);
        assert!(
            states(&entries, "signature-output").is_empty(),
            "a failed attempt produces no signature"
        );
        assert!(
            entries.publications().is_empty(),
            "a failed attempt publishes nothing"
        );
        let curve = EccCurve::lookup(P256).unwrap();
        let (attempt, entries) = traced(true, || {
            let private = curve.secret_scalar(&[0x42; 32]).unwrap();
            curve
                .ecdsa_sign(&private, &curve.zero_scalar().unwrap(), &[0x11; 32])
                .map(|attempt| matches!(attempt, super::super::crypto::EcdsaAttempt::Retry))
        });
        assert_eq!(attempt, Some(true), "a zero nonce is a genuine retry");
        assert!(states(&entries, "signature-output").is_empty());
        assert!(
            entries.publications().is_empty(),
            "a retry publishes nothing"
        );
        let mut short = vec![0x5au8; 32];
        short[0] = 0;
        let mut script = short.clone();
        script.extend_from_slice(&[0x6bu8; 32]);
        let ((signature, _), entries) = traced(true, || {
            sign(&key, TPM_ALG_SM2, SeededRand::scripted(&script, 1))
        });
        assert!(signature.is_ok());
        assert_eq!(all(&entries, "nonce-candidate", Shadow::Undefined), 2);
        assert_eq!(
            all(&entries, "sm2-commitment", Shadow::Undefined),
            1,
            "the redrawn short nonce never reaches a commitment"
        );
    }

    #[test]
    #[ignore = "boundary diagnostic: run under valgrind --tool=memcheck"]
    fn memcheck_boundary_imported_and_restored_material_is_marked_before_use() {
        let mut generator = rand(b"boundary rsa", 1);
        let key = super::super::crypto::generate_rsa_key(
            1024,
            0,
            false,
            &mut generator,
            CancellationToken::disabled(),
        )
        .unwrap();
        let modulus = verification_copy(&key.modulus);
        let prime = verification_copy(&key.prime);
        let sensitive = OwnedTpmtSensitive {
            sensitive_type: TPM_ALG_RSA,
            auth_value: OwnedSecret::from_vec(Vec::new()),
            seed_value: OwnedSecret::from_vec(Vec::new()),
            sensitive: Some(OwnedSecret::from_vec(prime.clone())),
        };
        let (loaded, entries) = traced(true, || {
            super::super::object_load::object_load(
                None,
                rsa_public(modulus.clone(), 0),
                Some(sensitive),
                0,
                0,
                vec![0x00, 0x0b],
            )
        });
        let loaded = loaded.expect("the imported RSA key loads");
        assert!(
            shadow(&prime) == Shadow::Defined,
            "the fixture copy stays public"
        );
        all(&entries, "imported-prime-validation", Shadow::Undefined);
        all(&entries, "recovery-prime", Shadow::Undefined);
        let restored = body(
            rsa_public(modulus.clone(), 0),
            prime.clone(),
            loaded.private_exponent,
        );
        let message = verification_copy(&be_sub_small(&modulus, 7));
        let (decrypted, entries) = traced(true, || {
            crypt_rsa_decrypt(
                &restored,
                &RsaDecryptScheme {
                    scheme: TPM_ALG_NULL,
                    hash_alg: 0,
                },
                &message,
                &[],
                false,
                &mut LazySelfTest::untested(),
            )
        });
        assert!(decrypted.is_ok());
        all(&entries, "private-key-prime", Shadow::Undefined);
        all(&entries, "rsa-private-exponent", Shadow::Undefined);

        let (ecc, x, y) = ecc_key_body(P256, null_scheme());
        let stored = ecc.sensitive.sensitive.clone();
        let sensitive = OwnedTpmtSensitive {
            sensitive_type: TPM_ALG_ECC,
            auth_value: OwnedSecret::from_vec(Vec::new()),
            seed_value: OwnedSecret::from_vec(Vec::new()),
            sensitive: stored,
        };
        let (loaded, entries) = traced(true, || {
            super::super::object_load::object_load(
                None,
                ecc_public(P256, x.clone(), y.clone(), null_scheme()),
                Some(sensitive),
                0,
                0,
                vec![0x00, 0x0b],
            )
        });
        assert!(loaded.is_ok(), "the imported ECC key validates");
        all(&entries, "stored-scalar", Shadow::Undefined);
    }

    #[test]
    #[ignore = "needs Valgrind Memcheck"]
    fn memcheck_boundary_context_save_marks_the_restored_prime_before_recovery() {
        use super::super::object::ATTR_PRIVATE_EXP;
        use super::super::object_load::replay::{clock, context_save, exec_raw, runtime_at};
        use super::super::persistent::OwnedAnyObjectBody;

        let clock = clock();
        let mut runtime = runtime_at("AFTER_CREATE", &clock);
        let slot = runtime
            .live
            .objects
            .iter()
            .position(|entry| {
                entry.attributes & ATTR_PRIVATE_EXP != 0
                    && matches!(&entry.body, OwnedAnyObjectBody::Object(body)
                        if body.public.object_type == TPM_ALG_RSA)
            })
            .expect("the snapshot holds an RSA object with a cached private exponent");
        let entry = &mut runtime.live.objects[slot];
        entry.attributes &= !ATTR_PRIVATE_EXP;
        if let OwnedAnyObjectBody::Object(body) = &mut entry.body {
            body.private_exponent = None;
        }
        let handle = 0x8000_0000 + u32::try_from(slot).unwrap();
        let (saved, entries) = traced(true, || {
            exec_raw(&mut runtime, &clock, context_save(handle))
        });
        assert_eq!(saved[6..10], [0, 0, 0, 0], "the save succeeds");
        assert!(
            runtime.live.objects[slot].attributes & ATTR_PRIVATE_EXP != 0,
            "the save recovered the private exponent"
        );
        all(&entries, "recovery-prime", Shadow::Undefined);
    }

    #[test]
    #[ignore = "boundary diagnostic: run under valgrind --tool=memcheck"]
    fn memcheck_boundary_internal_secrets_and_public_results() {
        let (key, x, y) = ecc_key_body(P256, null_scheme());
        let public = EccPoint { x, y };
        let kdf2 = Scheme {
            scheme: TPM_ALG_KDF2,
            hash_alg: Some(TPM_ALG_SHA256),
            count: None,
            kdf: None,
        };
        let (ciphertext, entries) = traced(true, || {
            crypt_ecc_encrypt(
                P256,
                &public,
                kdf2,
                b"boundary",
                &mut rand(b"enc", 1),
                &mut hook,
            )
        });
        let ciphertext = ciphertext.unwrap();
        all(&entries, "ephemeral-draw", Shadow::Undefined);
        all(&entries, "shared-point", Shadow::Undefined);
        all(&entries, "offset-point", Shadow::Undefined);
        all(&entries, "ciphertext", Shadow::Undefined);
        assert!(entries.publications().is_empty());
        for part in [
            &ciphertext.c1.x,
            &ciphertext.c1.y,
            &ciphertext.c2,
            &ciphertext.c3,
        ] {
            released(part);
        }
        let private = key.sensitive.sensitive.as_ref().unwrap();
        let (plain, entries) = traced(true, || {
            crypt_ecc_decrypt(
                P256,
                Some(private),
                kdf2,
                &ciphertext.c1,
                &ciphertext.c2,
                &ciphertext.c3,
                &mut hook,
            )
        });
        assert_eq!(verification_copy(&plain.unwrap()), b"boundary");
        all(&entries, "stored-scalar", Shadow::Undefined);
        all(&entries, "shared-point", Shadow::Undefined);
        let (zgen, entries) = traced(true, || {
            super::super::ecc::private_point_multiply(P256, Some(&ciphertext.c1), Some(private))
        });
        assert!(zgen.is_ok());
        assert!(
            entries.publications().is_empty(),
            "a point-multiplication helper never publishes its product"
        );
        let (generated, entries) = traced(true, || {
            super::super::crypto::generate_ecc_key(P521, &mut rand(b"boundary keygen", 1))
        });
        assert!(generated.is_ok());
        all(&entries, "ephemeral-draw", Shadow::Undefined);
        all(&entries, "public-key", Shadow::Undefined);
        assert!(entries.publications().is_empty());
        all(&entries, "exported-private", Shadow::Undefined);
        let (commit_r, entries) = traced(true, || {
            commit_state().generate_r(&EccCurve::lookup(P256).unwrap(), b"name", None)
        });
        assert!(matches!(commit_r, Ok(Some(_))));
        all(&entries, "commit-stream", Shadow::Undefined);
        let (rsa, entries) = traced(true, || {
            super::super::crypto::generate_rsa_key(
                1024,
                0,
                true,
                &mut rand(b"boundary rsa keygen", 1),
                CancellationToken::disabled(),
            )
        });
        assert!(rsa.is_ok());
        all(&entries, "prime-candidate", Shadow::Undefined);
        all(&entries, "public-modulus", Shadow::Undefined);
        assert!(entries.publications().is_empty());
    }

    #[test]
    #[ignore = "boundary diagnostic: run under valgrind --tool=memcheck"]
    fn memcheck_boundary_stored_secrets_keep_public_padding_defined() {
        use super::super::memcheck::undefined_bytes;
        use super::super::persistent::SECRET_STORAGE_BYTES;
        let mut leading_zeros = vec![0x6du8; 32];
        leading_zeros[..3].fill(0);
        let cases: [(&str, Vec<u8>); 4] = [
            ("short", vec![0x35u8; 20]),
            ("p256", rand(b"padding p256", 1).random_bytes(32).unwrap()),
            (
                "full-width",
                rand(b"padding full", 1)
                    .random_bytes(SECRET_STORAGE_BYTES)
                    .unwrap(),
            ),
            ("leading-zeros", leading_zeros),
        ];
        for (tag, payload) in cases {
            let padding = SECRET_STORAGE_BYTES - payload.len();
            for conceal in [true, false] {
                let secret = OwnedSecret::copy_of(&payload);
                let ((combined, undefined), entries) = traced(conceal, || {
                    let fixed = secret.fixed_width().expect("a fixed-width secret");
                    (shadow(fixed), undefined_bytes(fixed))
                });
                let (payload_state, combined_state, undefined_count) = if conceal {
                    let combined_state = if padding == 0 {
                        Shadow::Undefined
                    } else {
                        Shadow::Mixed
                    };
                    (Shadow::Undefined, combined_state, payload.len())
                } else {
                    (Shadow::Defined, Shadow::Defined, 0)
                };
                assert_eq!(
                    all(&entries, "stored-scalar", payload_state),
                    1,
                    "{tag}: the whole payload, including its own zero bytes"
                );
                if padding == 0 {
                    assert!(states(&entries, "stored-padding").is_empty(), "{tag}");
                } else {
                    all(&entries, "stored-padding", Shadow::Defined);
                }
                assert_eq!(combined, combined_state, "{tag} conceal={conceal}");
                assert_eq!(
                    undefined,
                    Some(undefined_count),
                    "{tag} conceal={conceal}: only the payload bytes are secret"
                );
            }
        }
    }

    fn scalar_input(curve: &EccCurve, value: u8) -> EccScalar {
        let bytes = [value; 32];
        super::super::memcheck::secret(&bytes);
        curve.secret_scalar(&bytes).unwrap()
    }

    #[test]
    #[ignore = "boundary diagnostic: run under valgrind --tool=memcheck"]
    fn memcheck_boundary_failed_compound_operations_publish_no_points() {
        use crate::library::constants::{TPM_RC_CANCELED, TPM_RC_ECC_POINT, TPM_RC_VALUE};
        use core::cell::Cell;
        let curve = EccCurve::lookup(P256).unwrap();
        let (key, x, y) = ecc_key_body(P256, null_scheme());
        let private = key.sensitive.sensitive.as_ref().unwrap();
        let public = EccPoint { x, y };
        let p2 = super::super::ecc::point_multiply(P256, None, &[0x07]).unwrap();
        let mut off_curve = p2.clone();
        off_curve.y[0] ^= 0x01;

        let checks = Cell::new(0);
        let (canceled, entries) = traced(true, || {
            let canceled = || {
                checks.set(checks.get() + 1);
                true
            };
            commit_compute(
                P256,
                None,
                Some(&p2),
                Some(private),
                &scalar_input(&curve, 0x21),
                &canceled,
            )
        });
        assert_eq!(canceled.err(), Some(TPM_RC_CANCELED));
        assert_eq!(checks.get(), 1, "canceled immediately after K");
        assert!(
            entries.publications().is_empty(),
            "a canceled Commit published {:?}",
            entries.publications()
        );
        assert_eq!(all(&entries, "commit-product", Shadow::Undefined), 2, "K");

        let (rejected, entries) = traced(true, || {
            commit_compute(
                P256,
                None,
                Some(&p2),
                Some(private),
                &curve.zero_scalar().unwrap(),
                &|| false,
            )
        });
        assert_eq!(rejected.err(), Some(TPM_RC_VALUE), "r is rejected after K");
        assert!(
            entries.publications().is_empty(),
            "a rejected Commit published {:?}",
            entries.publications()
        );
        assert_eq!(all(&entries, "commit-product", Shadow::Undefined), 2, "K");

        let (failed, entries) = traced(true, || {
            commit_compute(
                P256,
                Some(&off_curve),
                Some(&p2),
                Some(private),
                &scalar_input(&curve, 0x22),
                &|| false,
            )
        });
        assert_eq!(
            failed.err(),
            Some(TPM_RC_ECC_POINT),
            "E fails after K and L"
        );
        assert_eq!(
            all(&entries, "commit-product", Shadow::Undefined),
            4,
            "K, L"
        );
        assert!(
            entries.publications().is_empty(),
            "a failed Commit published {:?}",
            entries.publications()
        );

        let (exchanged, entries) = traced(true, || {
            two_phase_key_exchange(
                P256,
                TPM_ALG_ECDH,
                Some(private),
                &scalar_input(&curve, 0x23),
                &public,
                &off_curve,
            )
        });
        assert_eq!(
            exchanged.err(),
            Some(TPM_RC_ECC_POINT),
            "z2 fails after z1 succeeded"
        );
        assert!(
            entries.publications().is_empty(),
            "a failed two-phase exchange published {:?}",
            entries.publications()
        );
        assert_eq!(
            all(&entries, "two-phase-product", Shadow::Undefined),
            2,
            "z1"
        );

        let (committed, entries) = traced(true, || {
            commit_compute(
                P256,
                Some(&public),
                Some(&p2),
                Some(private),
                &scalar_input(&curve, 0x24),
                &|| false,
            )
        });
        assert!(committed.is_ok());
        assert_eq!(
            all(&entries, "commit-product", Shadow::Undefined),
            6,
            "K, L and E stay secret inside the operation"
        );
        let (exchanged, entries) = traced(true, || {
            two_phase_key_exchange(
                P256,
                TPM_ALG_ECDH,
                Some(private),
                &scalar_input(&curve, 0x25),
                &public,
                &p2,
            )
        });
        assert!(exchanged.is_ok());
        assert_eq!(
            all(&entries, "two-phase-product", Shadow::Undefined),
            4,
            "z1 and z2 stay secret inside the operation"
        );
        let (product, entries) = traced(true, || {
            super::super::ecc::point_multiply_by(&curve, Some(&public), &scalar_input(&curve, 0x26))
        });
        assert!(product.is_ok());
        assert!(
            entries.publications().is_empty(),
            "the returned product is published by the enclosing operation, not the helper"
        );
    }

    #[test]
    #[ignore = "boundary diagnostic: run under valgrind --tool=memcheck"]
    fn memcheck_boundary_public_constants_stay_defined() {
        use super::super::crypto::{BigUint, rsa_public_key_op};
        let ((), entries) = traced(true, || {
            let constant = BigUint::from_u64(65537)
                .unwrap()
                .add_u64(2)
                .unwrap()
                .to_be_bytes(4)
                .unwrap();
            super::super::memcheck::observe("public-constant", &constant);
            let curve = EccCurve::lookup(P256).unwrap();
            let scalar = curve
                .public_scalar_from_u64(5)
                .unwrap()
                .to_bytes(32)
                .unwrap();
            super::super::memcheck::observe("public-constant", &scalar);
            let detail = curve_detail(P521).unwrap();
            super::super::memcheck::observe("public-constant", &detail.order);
            super::super::memcheck::observe("public-constant", &detail.generator_x);
            let modulus = be_sub_small(&[0xffu8; 128], 0);
            let mut odd = modulus.clone();
            odd[127] = 0xfb;
            let message = vec![0x02u8; 128];
            let mut message = message;
            message[0] = 0;
            let encrypted = rsa_public_key_op(&odd, 65537, &message).unwrap();
            super::super::memcheck::observe("public-constant", &encrypted);
        });
        assert_eq!(all(&entries, "public-constant", Shadow::Defined), 5);
    }

    #[test]
    #[ignore = "boundary diagnostic control: run under valgrind --tool=memcheck"]
    fn memcheck_boundary_control_scope_marks_nothing() {
        let (key, _, _) = ecc_key_body(P256, null_scheme());
        let mut script = vec![0u8; 32];
        script.extend_from_slice(&[0x5au8; 32]);
        let ((signature, _), entries) = traced(false, || {
            sign(&key, TPM_ALG_SM2, SeededRand::scripted(&script, 1))
        });
        assert!(signature.is_ok());
        assert_eq!(all(&entries, "nonce-candidate", Shadow::Defined), 2);
        all(&entries, "sm2-commitment", Shadow::Defined);
        all(&entries, "stored-scalar", Shadow::Defined);
    }
}

fn concealed_phase(diagnostic: fn() -> Vec<String>) -> Vec<String> {
    std::thread::Builder::new()
        .name("concealed".into())
        .spawn(move || {
            let listing = diagnostic();
            assert!(
                !listing.is_empty(),
                "the concealed phase produced a listing"
            );
            listing
        })
        .unwrap()
        .join()
        .unwrap()
}

fn control_phase(diagnostic: fn() -> Vec<String>) -> Vec<String> {
    std::thread::Builder::new()
        .name("control".into())
        .spawn(move || {
            let listing = diagnostic();
            assert!(!listing.is_empty(), "the control phase produced a listing");
            listing
        })
        .unwrap()
        .join()
        .unwrap()
}

#[test]
#[ignore = "secret-flow sequence: a control run after a concealed run in one process"]
fn memcheck_ecc_concealed_then_control() {
    check_ecc_listing(&concealed_phase(|| memcheck_matrix(true, ECC_MATRIX)));
    check_ecc_listing(&control_phase(|| memcheck_matrix(false, ECC_MATRIX)));
}

#[test]
#[ignore = "secret-flow sequence: a control run after a concealed run in one process"]
fn memcheck_rsa_concealed_then_control() {
    check_rsa_listing(&concealed_phase(rsa_concealed_diagnostic));
    check_rsa_listing(&control_phase(|| memcheck_matrix(false, RSA_MATRIX)));
}

#[test]
#[ignore = "secret-flow sequence: the general RSA diagnostic after a control run warmed the cache"]
fn memcheck_rsa_control_then_concealed() {
    check_rsa_listing(&control_phase(|| memcheck_matrix(false, RSA_MATRIX)));
    assert!(
        super::crypto::validated_factor_sets() > 0,
        "the completed control run validated the factor sets first"
    );
    check_rsa_listing(&concealed_phase(rsa_concealed_diagnostic));
}
