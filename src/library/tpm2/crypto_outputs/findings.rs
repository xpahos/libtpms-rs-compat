use super::super::crypto::{
    BigUint, forget_validated_factor_sets, rsa_public_key_op, validated_factor_sets,
};
use super::super::ecc::private_point_multiply;
use super::super::memcheck::{Shadow, Trace, traced, verification_copy};
use super::super::object_load::object_load;
use super::*;
use crate::library::cancel::CommandCancellation;

const FINDING_INPUT: &str = "finding-input/";
const RSA_SIZES: [(u16, &[u8]); 3] = [
    (1024, b"f14-1024"),
    (2048, b"f14-2048"),
    (3072, b"f14-3072"),
];

fn finding_input(case: impl FnOnce() -> String, bytes: &[u8]) {
    super::super::memcheck::secret(bytes);
    super::super::memcheck::observe_case(|| format!("{FINDING_INPUT}{}", case()), bytes);
}

fn stored_input(case: &str, bytes: &[u8]) -> OwnedSecret {
    let secret = OwnedSecret::copy_of(bytes);
    finding_input(|| format!("{case}/stored"), secret.as_bytes());
    secret
}

#[track_caller]
fn check_inputs(conceal: bool, trace: &Trace, expected_count: usize) {
    let expected = if conceal {
        Shadow::Undefined
    } else {
        Shadow::Defined
    };
    let inputs: Vec<&(String, Shadow)> = trace
        .observations()
        .iter()
        .filter(|(label, _)| label.starts_with(FINDING_INPUT))
        .collect();
    let wrong: Vec<String> = inputs
        .iter()
        .filter(|(_, state)| *state != expected)
        .map(|(label, state)| format!("{label}: {state:?}"))
        .collect();
    assert!(
        wrong.is_empty(),
        "finding inputs were not {expected:?} before use:\n{}",
        wrong.join("\n")
    );
    assert_eq!(
        inputs.len(),
        expected_count,
        "every finding input was checked"
    );
}

#[track_caller]
fn check_source(conceal: bool, trace: &Trace, label: &str) -> usize {
    let states = trace.states(label);
    assert!(!states.is_empty(), "`{label}` was never observed");
    let wrong: Vec<&Shadow> = states
        .iter()
        .filter(|state| {
            if conceal {
                !matches!(state, Shadow::Undefined | Shadow::Mixed)
            } else {
                **state != Shadow::Defined
            }
        })
        .collect();
    assert!(wrong.is_empty(), "`{label}` conceal={conceal}: {states:?}");
    states.len()
}

struct RsaFixture {
    modulus: Vec<u8>,
    prime: Vec<u8>,
    other: Vec<u8>,
    words: Vec<(u16, Vec<u8>)>,
    swapped: Vec<(u16, Vec<u8>)>,
}

fn rsa_fixture(bits: u16, label: &[u8]) -> RsaFixture {
    let key = super::super::crypto::generate_rsa_key(
        bits,
        0,
        false,
        &mut rand(label, 1),
        CancellationToken::disabled(),
    )
    .unwrap();
    let (modulus, prime, words) = key_parts!(key);
    let other = prime_from_words(&words[0].1, prime.len());
    let swapped = swapped_words(
        &prime,
        recover_words(&modulus, &other, 0).expect("the other prime recovers"),
    );
    RsaFixture {
        modulus: verification_copy(&modulus),
        prime: verification_copy(&prime),
        other: verification_copy(&other),
        words,
        swapped,
    }
}

fn be_value(bytes: &[u8]) -> BigUint {
    BigUint::from_be_bytes(bytes).unwrap()
}

fn be_width(value: &BigUint, width: usize) -> Vec<u8> {
    value.to_be_bytes(width).unwrap()
}

fn prime_words(prime: &[u8]) -> (u16, Vec<u8>) {
    let mut padded = vec![0u8; prime.len().next_multiple_of(8)];
    let start = padded.len() - prime.len();
    padded[start..].copy_from_slice(prime);
    (padded.len() as u16, padded)
}

fn malformed_words(other: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let zero = (8u16, vec![0u8; 8]);
    vec![prime_words(other), zero.clone(), zero.clone(), zero]
}

fn decrypt_raw(body: &OwnedObjectBody, ciphertext: &[u8]) -> Result<Vec<u8>, TpmResult> {
    crypt_rsa_decrypt(
        body,
        &RsaDecryptScheme {
            scheme: TPM_ALG_NULL,
            hash_alg: 0,
        },
        ciphertext,
        &[],
        false,
        &mut LazySelfTest::untested(),
    )
}

fn restored_rsa(modulus: &[u8], prime: &[u8], words: &[(u16, Vec<u8>)]) -> OwnedObjectBody {
    body(
        rsa_public(modulus.to_vec(), 0),
        prime.to_vec(),
        Some(exponent_from(words)),
    )
}

fn message_for(modulus: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut message = vec![0u8; modulus.len()];
    message[1..9].copy_from_slice(b"F14plain");
    let last = message.len() - 1;
    message[last] = 0x2b;
    let ciphertext = rsa_public_key_op(modulus, 0, &message).expect("a public operation");
    (message, ciphertext)
}

struct ColdOutcome {
    label: String,
    validated_before: usize,
    validated_after: usize,
    result: Result<Vec<u8>, TpmResult>,
}

fn cold(label: String, run: impl FnOnce() -> Result<Vec<u8>, TpmResult>) -> ColdOutcome {
    forget_validated_factor_sets();
    let validated_before = validated_factor_sets();
    let result = run();
    ColdOutcome {
        label,
        validated_before,
        validated_after: validated_factor_sets(),
        result,
    }
}

fn factor_validation_on_first_use(conceal: bool) {
    let fixtures: Vec<(u16, RsaFixture)> = RSA_SIZES
        .iter()
        .map(|(bits, label)| (*bits, rsa_fixture(*bits, label)))
        .collect();
    let other = rsa_fixture(1024, b"f14-other");
    let composite = verification_copy(&be_width(
        &be_value(&fixtures[0].1.prime)
            .mul(&be_value(&fixtures[0].1.other))
            .unwrap(),
        fixtures[0].1.modulus.len(),
    ));
    let composite_modulus = verification_copy(&be_width(
        &be_value(&composite).mul(&be_value(&other.prime)).unwrap(),
        composite.len() + other.prime.len(),
    ));
    let repeated_modulus = verification_copy(&be_width(
        &be_value(&other.prime).mul(&be_value(&other.prime)).unwrap(),
        other.modulus.len(),
    ));
    let mut two = vec![0u8; other.modulus.len()];
    let last = two.len() - 1;
    two[last] = 2;
    let mut two_wide = vec![0u8; composite_modulus.len()];
    let last = two_wide.len() - 1;
    two_wide[last] = 2;

    let (outcomes, trace) = traced(conceal, || {
        let mut outcomes = Vec::new();
        for (bits, fixture) in &fixtures {
            let (message, ciphertext) = message_for(&fixture.modulus);
            let stored_p = restored_rsa(&fixture.modulus, &fixture.prime, &fixture.words);
            outcomes.push((
                message.clone(),
                cold(format!("rsa{bits}/restored-p"), || {
                    decrypt_raw(&stored_p, &ciphertext)
                }),
            ));
            let stored_q = restored_rsa(&fixture.modulus, &fixture.other, &fixture.swapped);
            outcomes.push((
                message.clone(),
                cold(format!("rsa{bits}/restored-q"), || {
                    decrypt_raw(&stored_q, &ciphertext)
                }),
            ));
            for (order, prime) in [("p", &fixture.prime), ("q", &fixture.other)] {
                let imported = prime.clone();
                let sensitive = OwnedTpmtSensitive {
                    sensitive_type: TPM_ALG_RSA,
                    auth_value: OwnedSecret::from_vec(Vec::new()),
                    seed_value: OwnedSecret::from_vec(Vec::new()),
                    sensitive: Some(OwnedSecret::from_vec(imported)),
                };
                outcomes.push((
                    message.clone(),
                    cold(format!("rsa{bits}/imported-{order}"), || {
                        let loaded = object_load(
                            None,
                            rsa_public(fixture.modulus.clone(), 0),
                            Some(sensitive),
                            0,
                            0,
                            vec![0x00, 0x0b],
                        )?;
                        let restored = body(loaded.public, prime.clone(), loaded.private_exponent);
                        decrypt_raw(&restored, &ciphertext)
                    }),
                ));
            }
            outcomes.push((
                message.clone(),
                ColdOutcome {
                    label: format!("rsa{bits}/warm-restored-p"),
                    validated_before: validated_factor_sets(),
                    result: decrypt_raw(
                        &restored_rsa(&fixture.modulus, &fixture.prime, &fixture.words),
                        &ciphertext,
                    ),
                    validated_after: validated_factor_sets(),
                },
            ));
        }
        let composite_body = restored_rsa(
            &composite_modulus,
            &composite,
            &malformed_words(&other.prime),
        );
        outcomes.push((
            Vec::new(),
            cold("composite".into(), || {
                decrypt_raw(&composite_body, &two_wide)
            }),
        ));
        let repeated_body = restored_rsa(
            &repeated_modulus,
            &other.prime,
            &malformed_words(&other.prime),
        );
        outcomes.push((
            Vec::new(),
            cold("repeated".into(), || decrypt_raw(&repeated_body, &two)),
        ));
        let mismatched_body = restored_rsa(
            &other.modulus,
            &other.prime,
            &malformed_words(&fixtures[0].1.other),
        );
        outcomes.push((
            Vec::new(),
            cold("mismatched".into(), || decrypt_raw(&mismatched_body, &two)),
        ));
        outcomes
    });
    let mut cold_valid = 0;
    for (message, outcome) in &outcomes {
        let label = &outcome.label;
        let malformed = message.is_empty();
        if malformed {
            assert!(outcome.result.is_err(), "{label} must stay rejected");
            assert_eq!(
                outcome.validated_after, 0,
                "{label} never becomes a validated factor set"
            );
            continue;
        }
        let plain = outcome
            .result
            .as_ref()
            .unwrap_or_else(|code| panic!("{label} decrypts: {code:#x}"));
        assert_eq!(&verification_copy(plain), message, "{label}");
        if label.contains("warm") {
            assert_eq!(
                outcome.validated_after, outcome.validated_before,
                "{label} hits the factor-set memo"
            );
        } else {
            assert_eq!(outcome.validated_before, 0, "{label} starts cold");
            assert_eq!(outcome.validated_after, 1, "{label} validated on first use");
            cold_valid += 1;
        }
    }
    assert_eq!(cold_valid, 4 * RSA_SIZES.len());
    assert!(check_source(conceal, &trace, "private-key-prime") >= 4 * RSA_SIZES.len());
    assert_eq!(
        check_source(conceal, &trace, "imported-prime-validation"),
        2 * RSA_SIZES.len()
    );
    forget_validated_factor_sets();
}

#[test]
#[ignore = "open finding F14: secret factor validation on first use; run under valgrind --tool=memcheck"]
fn memcheck_finding_f14_factor_validation_on_first_use() {
    factor_validation_on_first_use(true);
}

#[test]
#[ignore = "open finding F14 control: run under valgrind --tool=memcheck"]
fn memcheck_finding_f14_factor_validation_control() {
    factor_validation_on_first_use(false);
}

fn warm_factor_sets(conceal: bool) {
    let fixture = rsa_fixture(1024, b"f14-warm");
    let (message, ciphertext) = message_for(&fixture.modulus);
    let warm_body = restored_rsa(&fixture.modulus, &fixture.prime, &fixture.words);
    forget_validated_factor_sets();
    assert_eq!(
        verification_copy(&decrypt_raw(&warm_body, &ciphertext).unwrap()),
        message
    );
    assert_eq!(validated_factor_sets(), 1, "the untainted pass validated");
    let (decrypted, trace) = traced(conceal, || {
        let fresh = restored_rsa(&fixture.modulus, &fixture.other, &fixture.swapped);
        decrypt_raw(&fresh, &ciphertext)
    });
    assert_eq!(verification_copy(&decrypted.unwrap()), message);
    assert_eq!(
        validated_factor_sets(),
        1,
        "the concealed pass hit the memo"
    );
    check_source(conceal, &trace, "private-key-prime");
    forget_validated_factor_sets();
}

#[test]
#[ignore = "F14 cache evidence: a memo hit skips validation; run under valgrind --tool=memcheck"]
fn memcheck_finding_f14_warm_memo_skips_validation() {
    warm_factor_sets(true);
}

fn top_limb_zero(order: &[u8]) -> Vec<u8> {
    let bits = order.len() * 8 - order[0].leading_zeros() as usize;
    let kept_bits = ((bits - 1) / 64) * 64;
    let kept_bytes = kept_bits / 8;
    let mut value = vec![0u8; order.len()];
    for (index, byte) in value[order.len() - kept_bytes..].iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(37).wrapping_add(0x5b);
    }
    value
}

fn leading_zero(order: &[u8]) -> Vec<u8> {
    let mut value: Vec<u8> = (0..order.len())
        .map(|index| (index as u8).wrapping_mul(29).wrapping_add(0x11))
        .collect();
    value[0] = 0;
    value
}

fn nonce_inputs(order: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let width = order.len() + 8;
    let order_minus_one = be_sub_small(order, 1);
    let mut aligned = vec![0u8; width - order.len()];
    aligned.extend_from_slice(&be_sub_small(&order_minus_one, 1));
    let mut wraps = vec![0u8; width - order.len()];
    wraps.extend_from_slice(&order_minus_one);
    let mut top_limb = vec![0u8; width - order.len()];
    top_limb.extend_from_slice(&top_limb_zero(order));
    vec![
        ("zero", vec![0u8; width]),
        ("all-ones", vec![0xffu8; width]),
        ("n-2", aligned),
        ("n-1-wraps", wraps),
        ("top-limb-zero", top_limb),
    ]
}

fn scalar_paths(conceal: bool) {
    let mut expected_inputs = 0;
    let fixtures: Vec<_> = CURVES
        .iter()
        .map(|&curve_id| {
            let label = format!("ecc{curve_id:04x}");
            let key =
                super::super::crypto::generate_ecc_key(curve_id, &mut rand(label.as_bytes(), 1))
                    .unwrap();
            (
                curve_id,
                verification_copy(&key.x),
                verification_copy(&key.y),
                verification_copy(&key.private),
            )
        })
        .collect();
    let rsa = rsa_fixture(1024, b"f16-rsa");
    let (rsa_message, rsa_ciphertext) = message_for(&rsa.modulus);
    forget_validated_factor_sets();
    assert!(
        decrypt_raw(
            &restored_rsa(&rsa.modulus, &rsa.prime, &rsa.words),
            &rsa_ciphertext
        )
        .is_ok()
    );
    let (listing, trace) = traced(conceal, || {
        let mut out = Vec::new();
        for (curve_id, x, y, private) in &fixtures {
            let curve_id = *curve_id;
            let name = format!("f16/{curve_id:04x}");
            let detail = curve_detail(curve_id).unwrap();
            let order = detail.order.clone();
            let public = EccPoint {
                x: x.clone(),
                y: y.clone(),
            };
            let mut oversized = vec![0u8; super::super::crypto::PRIVATE_SCALAR_BYTES - order.len()];
            oversized.extend_from_slice(&be_sub_small(&order, 3));
            oversized[0] = 0x01;
            let shapes: Vec<(&str, Vec<u8>)> = vec![
                ("zero", vec![0u8; order.len()]),
                ("one", vec![1u8]),
                ("n-1", be_sub_small(&order, 1)),
                ("n", order.clone()),
                ("n+1", be_add(&order, &[1])),
                ("leading-zero", leading_zero(&order)),
                ("top-limb-zero", top_limb_zero(&order)),
                ("sparse", {
                    let mut v = vec![0u8; order.len()];
                    v[1] = 0x80;
                    v[order.len() - 1] = 1;
                    v
                }),
                ("dense", {
                    let mut v = vec![0xffu8; order.len()];
                    v[0] = 0x0f;
                    v
                }),
                ("oversized", oversized),
            ];
            for (tag, scalar) in &shapes {
                let stored = stored_input(&format!("{name}/mulg-{tag}"), scalar);
                record(
                    &mut out,
                    &format!("{name}/mulg-{tag}"),
                    private_point_multiply(curve_id, None, Some(&stored)).map(|point| {
                        released(&point.x);
                        released(&point.y);
                        point_bytes(&point)
                    }),
                );
                let stored = stored_input(&format!("{name}/mulq-{tag}"), scalar);
                let product = private_point_multiply(curve_id, Some(&public), Some(&stored));
                record(
                    &mut out,
                    &format!("{name}/mulq-{tag}"),
                    product.map(|point| {
                        released(&point.x);
                        released(&point.y);
                        point_bytes(&point)
                    }),
                );
                expected_inputs += 2;
            }
            let curve = EccCurve::lookup(curve_id).unwrap();
            for (tag, draw) in nonce_inputs(&order) {
                finding_input(|| format!("{name}/nonce-{tag}"), &draw);
                let nonce = curve.scalar_from_extra_bits(&draw).expect("a nonce");
                let commitment = curve.mul_generator(&nonce).expect("a commitment");
                released(&commitment.x);
                released(&commitment.y);
                record(
                    &mut out,
                    &format!("{name}/nonce-{tag}"),
                    Ok([commitment.x, commitment.y].concat()),
                );
                expected_inputs += 1;
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
                    ecc_public(curve_id, x.clone(), y.clone(), key_scheme),
                    private.clone(),
                    None,
                );
                let mut state = SigningState {
                    rand: rand(b"f16-sign", 1),
                    commit: commit_state(),
                };
                let count = state.commit.commit();
                let scheme = SigScheme {
                    scheme: scheme_alg,
                    hash_alg: TPM_ALG_SHA256,
                    count,
                };
                let signature =
                    sign_digest(Some(&key_body), &scheme, &digest, &profile(), &mut state);
                if let Ok(signature) = &signature {
                    release_signature(signature);
                }
                record(
                    &mut out,
                    &format!("{name}/{tag}"),
                    signature
                        .as_ref()
                        .map(marshal_signature)
                        .map_err(|code| *code),
                );
            }
            let generated =
                super::super::crypto::generate_ecc_key(curve_id, &mut rand(b"f16-keygen", 1))
                    .unwrap();
            released(&generated.x);
            released(&generated.y);
            record(
                &mut out,
                &format!("{name}/keygen"),
                Ok([generated.x.clone(), generated.y.clone()].concat()),
            );
            let exported = verification_copy(&generated.private);
            out.push(format!("{name}/keygen-d {}", fingerprint(&exported)));
        }
        let fresh = restored_rsa(&rsa.modulus, &rsa.other, &rsa.swapped);
        record(
            &mut out,
            "f16/rsa/prepare",
            decrypt_raw(&fresh, &rsa_ciphertext),
        );
        for (order, prime) in [("p", &rsa.prime), ("q", &rsa.other)] {
            let recovered = recover_words(&rsa.modulus, prime, 0).map(|words| words.concat());
            record(
                &mut out,
                &format!("f16/rsa/recover-{order}"),
                recovered.ok_or(0xdead),
            );
        }
        out
    });
    let rsa_plain = listing
        .iter()
        .find(|line| line.starts_with("f16/rsa/prepare "))
        .expect("the RSA preparation ran");
    assert!(!rsa_plain.contains("err:"), "{rsa_plain}");
    assert_eq!(
        rsa_plain,
        &format!("f16/rsa/prepare {}", fingerprint(&rsa_message))
    );
    for line in &listing {
        if line.contains("/mulg-n ") || line.contains("/mulg-zero ") {
            assert!(line.contains("err:"), "{line}: a zero product is rejected");
        }
    }
    let pinned = include_str!("../testdata/crypto_outputs_ecc_16260bd.txt");
    let mut compared = 0;
    for line in &listing {
        let Some((name, _)) = line.split_once(' ') else {
            continue;
        };
        let Some(matrix_name) = name
            .strip_prefix("f16/")
            .and_then(|rest| rest.split_once('/'))
            .filter(|(_, case)| {
                [
                    "mulg-one", "mulg-n-1", "mulg-n+1", "mulq-one", "mulq-n-1", "mulq-n+1",
                ]
                .contains(case)
            })
            .map(|(curve, case)| format!("ecc{curve}/{case}"))
        else {
            continue;
        };
        let expected = pinned
            .lines()
            .find(|pinned| {
                pinned
                    .split_once(' ')
                    .is_some_and(|(n, _)| n == matrix_name)
            })
            .unwrap_or_else(|| panic!("{matrix_name} is pinned"));
        assert_eq!(
            line.split_once(' ').unwrap().1,
            expected.split_once(' ').unwrap().1,
            "{name} matches the unchanged {matrix_name} fixture"
        );
        compared += 1;
    }
    assert_eq!(compared, 6 * CURVES.len());
    check_inputs(conceal, &trace, expected_inputs);
    check_source(conceal, &trace, "stored-scalar");
    check_source(conceal, &trace, "private-key-prime");
    forget_validated_factor_sets();
}

#[test]
#[ignore = "open finding F16: secret scalar and integer paths; run under valgrind --tool=memcheck"]
fn memcheck_finding_f16_secret_scalar_and_integer_paths() {
    scalar_paths(true);
}

#[test]
#[ignore = "open finding F16 control: run under valgrind --tool=memcheck"]
fn memcheck_finding_f16_secret_scalar_and_integer_paths_control() {
    scalar_paths(false);
}

const PRIME_SEARCHES: [(u16, u32, bool, &[u8], u8); 4] = [
    (1024, 0, false, b"r1", 1),
    (1024, 0, false, b"r4", 0),
    (2048, 0, true, b"r5", 1),
    (3072, 0, false, b"r6", 1),
];

fn prime_search(conceal: bool) {
    let (listing, trace) = traced(conceal, || {
        let mut out = Vec::new();
        for (bits, exponent, signing, label, level) in PRIME_SEARCHES {
            let name = format!(
                "rsa{bits}/{}/{exponent}/{signing}/{level}",
                core::str::from_utf8(label).unwrap()
            );
            let mut generator = rand(label, level);
            let key = super::super::crypto::generate_rsa_key(
                bits,
                exponent,
                signing,
                &mut generator,
                CancellationToken::disabled(),
            )
            .unwrap();
            released(&key.modulus);
            let stored = verification_copy(&key.prime);
            let other = verification_copy(&prime_from_words(&words_of(key.q).1, key.prime.len()));
            record(
                &mut out,
                &format!("{name}/modulus"),
                Ok(key.modulus.clone()),
            );
            record(&mut out, &format!("{name}/prime"), Ok(key.prime.clone()));
            record(
                &mut out,
                &format!("{name}/drbg"),
                Ok(generator.random_bytes(32).unwrap()),
            );
            out.push(format!(
                "order {name} {}",
                if stored > other {
                    "stored-larger"
                } else {
                    "stored-smaller"
                }
            ));
        }
        let cancellation = std::sync::Arc::new(CommandCancellation::new());
        let canceled = cancellation.run(|token| {
            let trigger = std::sync::Arc::clone(&cancellation);
            let mut attempts = 0u32;
            let _hook = super::super::crypto::work::GenerationAttemptHook::install(move || {
                attempts += 1;
                if attempts == 2 {
                    trigger.cancel();
                }
            });
            super::super::crypto::generate_rsa_key(
                1024,
                0,
                false,
                &mut rand(b"f17-cancel", 1),
                token,
            )
        });
        out.push(format!(
            "canceled {}",
            matches!(canceled, Err(super::super::crypto::RsaKeyError::Canceled))
        ));
        out
    });
    let pinned = include_str!("../testdata/crypto_outputs_rsa_16260bd.txt");
    let mut compared = 0;
    for line in &listing {
        if line.starts_with("order ") || line.starts_with("canceled ") {
            continue;
        }
        assert!(
            pinned.lines().any(|pinned| pinned == line),
            "{line} matches the unchanged reference listing"
        );
        compared += 1;
    }
    assert_eq!(compared, 3 * PRIME_SEARCHES.len());
    assert!(
        listing.contains(&"canceled true".to_string()),
        "{listing:?}"
    );
    let orders: Vec<&String> = listing
        .iter()
        .filter(|line| line.starts_with("order "))
        .collect();
    assert_eq!(orders.len(), PRIME_SEARCHES.len());
    assert!(
        orders.iter().any(|line| line.ends_with("stored-larger"))
            && orders.iter().any(|line| line.ends_with("stored-smaller")),
        "both stored-prime orders occur: {orders:?}"
    );
    check_source(conceal, &trace, "prime-candidate");
    check_source(conceal, &trace, "drbg-integer");
    let releases = trace.published("caller-result");
    assert_eq!(
        releases.len(),
        PRIME_SEARCHES.len(),
        "only the completed searches release their modulus; the canceled one releases nothing"
    );
}

#[test]
#[ignore = "open finding F17: deterministic prime search; run under valgrind --tool=memcheck"]
fn memcheck_finding_f17_deterministic_prime_search() {
    prime_search(true);
}

#[test]
#[ignore = "open finding F17 control: run under valgrind --tool=memcheck"]
fn memcheck_finding_f17_deterministic_prime_search_control() {
    prime_search(false);
}

fn shared_points(conceal: bool) {
    let fixtures: Vec<_> = CURVES
        .iter()
        .map(|&curve_id| {
            let key =
                super::super::crypto::generate_ecc_key(curve_id, &mut rand(b"f18", 1)).unwrap();
            (
                curve_id,
                verification_copy(&key.x),
                verification_copy(&key.y),
                verification_copy(&key.private),
            )
        })
        .collect();
    let kdf2 = Scheme {
        scheme: TPM_ALG_KDF2,
        hash_alg: Some(TPM_ALG_SHA256),
        count: None,
        kdf: None,
    };
    let (listing, trace) = traced(conceal, || {
        let mut out = Vec::new();
        for (curve_id, x, y, private) in &fixtures {
            let curve_id = *curve_id;
            let name = format!("f18/{curve_id:04x}");
            let detail = curve_detail(curve_id).unwrap();
            let public = EccPoint {
                x: x.clone(),
                y: y.clone(),
            };
            let cipher = crypt_ecc_encrypt(
                curve_id,
                &public,
                kdf2,
                b"shared point message",
                &mut rand(b"f18-encrypt", 1),
                &mut hook,
            )
            .expect("ECC encryption");
            for part in [&cipher.c1.x, &cipher.c1.y, &cipher.c2, &cipher.c3] {
                released(part);
            }
            let mut image = point_bytes(&cipher.c1);
            image.extend_from_slice(&cipher.c2);
            image.extend_from_slice(&cipher.c3);
            record(&mut out, &format!("{name}/encrypt"), Ok(image));
            let generator = EccPoint {
                x: detail.generator_x.clone(),
                y: detail.generator_y.clone(),
            };
            let aliased = EccPoint {
                x: be_add(&cipher.c1.x, &detail.prime),
                y: cipher.c1.y.clone(),
            };
            let mut off_curve = cipher.c1.clone();
            off_curve.y[0] ^= 0x01;
            for (tag, c1) in [
                ("c1", &cipher.c1),
                ("generator", &generator),
                ("public", &public),
                ("aliased", &aliased),
                ("off-curve", &off_curve),
            ] {
                let stored = stored_input(&format!("{name}/{tag}"), private);
                let decrypted = crypt_ecc_decrypt(
                    curve_id,
                    Some(&stored),
                    kdf2,
                    c1,
                    &cipher.c2,
                    &cipher.c3,
                    &mut hook,
                );
                if let Ok(plain) = &decrypted {
                    released(plain);
                }
                record(&mut out, &format!("{name}/decrypt-{tag}"), decrypted);
            }
            let mut secret = (cipher.c1.x.len() as u16).to_be_bytes().to_vec();
            secret.extend_from_slice(&cipher.c1.x);
            secret.extend_from_slice(&(cipher.c1.y.len() as u16).to_be_bytes());
            secret.extend_from_slice(&cipher.c1.y);
            let key_body = body(
                ecc_public(curve_id, x.clone(), y.clone(), null_scheme()),
                private.clone(),
                None,
            );
            let published = super::super::memcheck::publications_recorded();
            let seed = secret_decrypt(
                &key_body,
                b"SECRET\0",
                &secret,
                &mut LazySelfTest::untested(),
            );
            assert_eq!(
                super::super::memcheck::publications_recorded(),
                published,
                "{name}: returning the internal seed publishes nothing"
            );
            if let Ok(seed) = &seed {
                super::super::memcheck::observe_case(|| format!("{name}/secret-seed"), seed);
            }
            record(&mut out, &format!("{name}/secret"), seed);
        }
        out
    });
    for line in &listing {
        let (name, value) = line.split_once(' ').unwrap();
        if name.ends_with("/decrypt-c1") || name.ends_with("/decrypt-aliased") {
            assert_eq!(
                value,
                fingerprint(b"shared point message"),
                "{name} recovers the message"
            );
        }
        if name.ends_with("/decrypt-generator") || name.ends_with("/decrypt-public") {
            assert!(
                value.starts_with("err:"),
                "{name}: the integrity check rejects it"
            );
        }
        if name.ends_with("/secret") {
            assert!(!value.starts_with("err:"), "{line}");
        }
    }
    check_inputs(conceal, &trace, 5 * CURVES.len());
    let seeds: Vec<&(String, Shadow)> = trace
        .observations()
        .iter()
        .filter(|(label, _)| label.ends_with("/secret-seed"))
        .collect();
    assert_eq!(seeds.len(), CURVES.len(), "every curve returned a seed");
    for (label, state) in seeds {
        if conceal {
            assert!(
                matches!(state, Shadow::Undefined | Shadow::Mixed),
                "{label}: the decrypted seed stays secret, observed {state:?}"
            );
        } else {
            assert_eq!(*state, Shadow::Defined, "{label}");
        }
    }
    check_source(conceal, &trace, "stored-scalar");
    check_source(conceal, &trace, "ephemeral-draw");
}

#[test]
#[ignore = "open finding F18: shared points through the project formula; run under valgrind --tool=memcheck"]
fn memcheck_finding_f18_shared_points() {
    shared_points(true);
}

#[test]
#[ignore = "open finding F18 control: run under valgrind --tool=memcheck"]
fn memcheck_finding_f18_shared_points_control() {
    shared_points(false);
}

#[test]
#[ignore = "F17 conflict evidence: run with --ignored --nocapture"]
fn prime_search_work_and_drbg_consumption_follow_the_secret_seed() {
    use super::super::crypto::work::measure;
    let mut profiles = Vec::new();
    for label in 0u8..12 {
        let run = || {
            let mut generator = rand(&[b'w', label], 1);
            let key = super::super::crypto::generate_rsa_key(
                1024,
                0,
                false,
                &mut generator,
                CancellationToken::disabled(),
            )
            .unwrap();
            (key.modulus, generator.random_bytes(16).unwrap())
        };
        let ((modulus, next), work) = measure(run);
        let ((again, next_again), repeated) = measure(run);
        assert_eq!(
            (&modulus, &next),
            (&again, &next_again),
            "seed {label} is deterministic"
        );
        assert_eq!(work, repeated, "seed {label} repeats the same work");
        eprintln!(
            "seed {label:2}: primality tests {:3} sieved candidates {:4} sieve passes {:2} attempts {:2} drbg bytes {:6} next {}",
            work.primality_tests,
            work.sieved_candidates,
            work.sieve_passes,
            work.generation_attempts,
            work.generator_bytes,
            fingerprint(&next)
        );
        profiles.push(work);
    }
    let distinct = |field: fn(&super::super::crypto::work::Counters) -> u64| {
        let mut values: Vec<u64> = profiles.iter().map(field).collect();
        values.sort_unstable();
        values.dedup();
        values.len()
    };
    assert!(distinct(|work| work.primality_tests) > 1);
    assert!(distinct(|work| work.sieved_candidates) > 1);
    assert!(distinct(|work| work.generator_bytes) > 1);
}
