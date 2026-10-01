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

fn stored(bytes: &[u8]) -> OwnedSecret {
    OwnedSecret::copy_of(bytes)
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
    let recovered = super::crypto::recover_rsa_private_exponent(modulus, prime, exponent)?;
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

fn ephemeral(curve_id: u16, value: u64) -> EccScalar {
    EccCurve::lookup(curve_id)
        .unwrap()
        .scalar_from_u64(value)
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
        Ok(bytes) => out.push(format!("{label} {}", fingerprint(&bytes))),
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
            sensitive: Some(OwnedSecret::from_vec(private)),
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
        record(out, &format!("{name}/key-x"), Ok(key.x.clone()));
        record(out, &format!("{name}/key-y"), Ok(key.y.clone()));
        record(out, &format!("{name}/key-d"), Ok(key.private.clone()));
        record(
            out,
            &format!("{name}/drbg"),
            Ok(generator.random_bytes(32).unwrap()),
        );
        let other = super::crypto::generate_ecc_key(curve_id, &mut rand(b"other", 1)).unwrap();

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
            record(
                out,
                &format!("{name}/mulg-{tag}"),
                point_multiply(curve_id, None, scalar).map(|p| point_bytes(&p)),
            );
            record(
                out,
                &format!("{name}/mulq-{tag}"),
                point_multiply(curve_id, Some(&public), scalar).map(|p| point_bytes(&p)),
            );
        }
        record(
            out,
            &format!("{name}/mul-aliased"),
            point_multiply(curve_id, Some(&aliased), &other.private).map(|p| point_bytes(&p)),
        );
        record(
            out,
            &format!("{name}/mul-generator-point"),
            point_multiply(curve_id, Some(&generator_point), &other.private)
                .map(|p| point_bytes(&p)),
        );
        record(
            out,
            &format!("{name}/mul-off-curve"),
            point_multiply(curve_id, Some(&off_curve), &other.private).map(|p| point_bytes(&p)),
        );

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
                let mut image = point_bytes(&cipher.c1);
                image.extend_from_slice(&cipher.c2);
                image.extend_from_slice(&cipher.c3);
                record(out, &format!("{name}/ecc-encrypt"), Ok(image));
                record(
                    out,
                    &format!("{name}/ecc-decrypt"),
                    crypt_ecc_decrypt(
                        curve_id,
                        Some(&stored(&key.private)),
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
                        Some(&stored(&key.private)),
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
                Some(&stored(&key.private)),
                &ephemeral(curve_id, 0x0123_4567_89ab),
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
            Some(&stored(&key.private)),
            &ephemeral(curve_id, 0x0bad_cafe),
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
