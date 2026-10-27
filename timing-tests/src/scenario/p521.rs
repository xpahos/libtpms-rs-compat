use super::family::{Built, COMMAND_LEVEL, ClassSpec, PER_CLASS_KEYS, PairModel, ScenarioDoc};
use super::layout::{Creates, HandleRef, Step};
use super::{InputPair, Scenario, Seed, SeedKind, SplitMix};
use crate::scalar::{
    Point, SCALAR_BYTES, Scalar521, ScalarPair, offset, order_minus, peer_scalar, power_of_two,
};
use crate::tpm;

pub const CONTROL_BASE_ITERATIONS: u64 = 20_000;
pub const CONTROL_ITERATIONS_PER_BIT: u64 = 1000;
pub const CONTROL_COUNTED_BYTES: usize = 8;
pub const CONTROL_MASK: [u8; CONTROL_COUNTED_BYTES] =
    [0xa5, 0x3c, 0x96, 0x0f, 0xe1, 0x78, 0x2d, 0xb4];

pub fn peer_point() -> Point {
    peer_scalar().public_point()
}

pub fn control_output(scenario: Scenario, input: &[u8; SCALAR_BYTES]) -> [u8; 16] {
    let (seed, iterations) = match scenario {
        Scenario::ControlPositive => {
            let bits = masked_tail_bits(input);
            (
                fnv1a(input),
                CONTROL_BASE_ITERATIONS + CONTROL_ITERATIONS_PER_BIT * bits,
            )
        }
        Scenario::ControlNegative => (
            0x5eed_5eed_5eed_5eed,
            CONTROL_BASE_ITERATIONS + CONTROL_ITERATIONS_PER_BIT * 32,
        ),
        _ => unreachable!("not a control scenario"),
    };
    let mut x = seed;
    for _ in 0..iterations {
        x = x
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
    }
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&x.to_be_bytes());
    out[8..].copy_from_slice(&iterations.to_be_bytes());
    out
}

pub fn masked_tail_bits(input: &[u8; SCALAR_BYTES]) -> u64 {
    input[SCALAR_BYTES - CONTROL_COUNTED_BYTES..]
        .iter()
        .zip(CONTROL_MASK)
        .map(|(byte, mask)| (byte ^ mask).count_ones() as u64)
        .sum()
}

fn fnv1a(input: &[u8]) -> u64 {
    input.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, byte| {
        (h ^ *byte as u64).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

fn scalar(bytes: [u8; SCALAR_BYTES]) -> Scalar521 {
    Scalar521::new(bytes).expect("seed scalar is valid by construction")
}

fn with_leading_zero_bytes(mut base: [u8; SCALAR_BYTES], zeros: usize) -> [u8; SCALAR_BYTES] {
    base[..zeros].fill(0);
    if base[zeros] == 0 {
        base[zeros] = 0x80;
    }
    base
}

pub fn boundary_seeds(campaign_seed: u64) -> Vec<Seed> {
    let mut rng = SplitMix::new(campaign_seed ^ 0xb0b0_b0b0_b0b0_b0b0);
    let mut pairs: Vec<(String, Scalar521, Scalar521)> = Vec::new();
    let small = |v: u128| Scalar521::from_u128(v).expect("small scalar");
    pairs.push((
        "small-1-vs-random".into(),
        small(1),
        rng.full_width_scalar(),
    ));
    pairs.push(("small-2-vs-small-3".into(), small(2), small(3)));
    pairs.push((
        "small-255-vs-random".into(),
        small(255),
        rng.full_width_scalar(),
    ));
    for zeros in [1usize, 2, 8, 9, 33] {
        let base = *rng.full_width_scalar().bytes();
        pairs.push((
            format!("leading-zero-{zeros}-bytes-vs-full-width"),
            scalar(with_leading_zero_bytes(base, zeros)),
            rng.full_width_scalar(),
        ));
    }
    for exponent in [64usize, 128, 256, 512] {
        pairs.push((
            format!("limb-2^{exponent}-minus-1-vs-2^{exponent}"),
            scalar(offset(power_of_two(exponent), -1)),
            scalar(power_of_two(exponent)),
        ));
    }
    pairs.push((
        "top-bit-2^520-vs-random".into(),
        scalar(power_of_two(520)),
        rng.full_width_scalar(),
    ));
    pairs.push((
        "order-minus-1-vs-random".into(),
        scalar(order_minus(1)),
        rng.full_width_scalar(),
    ));
    pairs.push((
        "order-minus-1-vs-small-1".into(),
        scalar(order_minus(1)),
        small(1),
    ));
    pairs.push((
        "order-minus-2-vs-order-minus-1".into(),
        scalar(order_minus(2)),
        scalar(order_minus(1)),
    ));
    pairs.push((
        "order-minus-2^64-vs-random".into(),
        scalar(order_minus(1u128 << 64)),
        rng.full_width_scalar(),
    ));
    pairs
        .into_iter()
        .map(|(name, a, b)| Seed {
            name,
            kind: SeedKind::Boundary,
            pair: ScalarPair { a, b }.into(),
        })
        .collect()
}

pub fn seeds(campaign_seed: u64, random_pairs: usize) -> Vec<Seed> {
    let mut rng = SplitMix::new(campaign_seed);
    let mut out: Vec<Seed> = (0..random_pairs)
        .map(|i| Seed {
            name: format!("random-pair-{i}"),
            kind: SeedKind::Random,
            pair: ScalarPair {
                a: rng.scalar(),
                b: rng.scalar(),
            }
            .into(),
        })
        .collect();
    out.extend(boundary_seeds(campaign_seed));
    out
}

pub fn random_scalar(rng: &mut SplitMix) -> Scalar521 {
    loop {
        let mut bytes = [0u8; SCALAR_BYTES];
        for chunk in bytes.chunks_mut(8) {
            let word = rng.next_u64().to_be_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        bytes[0] &= 0x01;
        if let Ok(scalar) = Scalar521::new(bytes) {
            return scalar;
        }
    }
}

pub const DIAGNOSTIC_SEED_ORDER: &[&str] = &[
    "order-minus-1-vs-small-1",
    "small-1-vs-random",
    "leading-zero-9-bytes-vs-full-width",
    "order-minus-1-vs-random",
    "limb-2^64-minus-1-vs-2^64",
    "top-bit-2^520-vs-random",
    "leading-zero-1-bytes-vs-full-width",
    "small-2-vs-small-3",
    "order-minus-2-vs-order-minus-1",
];

pub const LIMB_EXPONENTS: [usize; 9] = [64, 128, 192, 256, 320, 384, 448, 512, 520];

pub fn valid_scalar(bytes: &[u8]) -> bool {
    Scalar521::from_slice(bytes).is_ok()
}

pub fn boundary_scalar(
    op: usize,
    r: u64,
    current: &[u8; SCALAR_BYTES],
    other: &[u8; SCALAR_BYTES],
) -> [u8; SCALAR_BYTES] {
    match op {
        0 => {
            let mut out = [0u8; SCALAR_BYTES];
            out[SCALAR_BYTES - 2..].copy_from_slice(&((r % 0xffff) as u16 + 1).to_be_bytes());
            out
        }
        1 => order_minus((r % 0xffff) as u128 + 1),
        2 => {
            let zeros = 1 + (r % 16) as usize;
            let mut out = *current;
            out[..zeros].fill(0);
            out
        }
        3 => {
            let exponent = LIMB_EXPONENTS[(r % LIMB_EXPONENTS.len() as u64) as usize];
            let delta = ((r >> 8) % 3) as i64 - 1;
            offset(power_of_two(exponent), delta)
        }
        4 => {
            let mut out = *other;
            let bit = (r % 521) as usize;
            out[SCALAR_BYTES - 1 - bit / 8] ^= 1 << (bit % 8);
            out
        }
        _ => {
            let mut out = *current;
            out[0] ^= 0x01;
            out
        }
    }
}

pub fn build(scenario: Scenario, pair: &InputPair) -> Result<Built, String> {
    let scalar_pair = pair
        .as_scalar_pair()
        .ok_or("inputs are not valid P-521 scalars")?;
    let class = |index: usize| -> ClassSpec {
        let scalar = scalar_pair.class(index);
        match scenario {
            Scenario::EcdhP521 => {
                let shared = scalar.shared_point(&peer_scalar());
                let public = scalar.public_point();
                let mut spec = ClassSpec::new(
                    Step::new("ECDH_ZGen", tpm::ecdh_zgen(0, &peer_point()))
                        .handle_at(10, HandleRef::Class(0)),
                    tpm::expected_zgen_response(&shared),
                );
                spec.setup = vec![
                    Step::new("LoadExternal", tpm::load_external(scalar, &public))
                        .creates(Creates::Object),
                ];
                spec.public = Some(public);
                spec.shared = Some(shared);
                spec
            }
            _ => ClassSpec::new(
                Step::new("control", scalar.bytes().to_vec()),
                control_output(scenario, scalar.bytes()).to_vec(),
            ),
        }
    };
    Ok(Built {
        shared: Vec::new(),
        classes: [class(0), class(1)],
        model: {
            let differs = pair.a != pair.b;
            match scenario {
                Scenario::EcdhP521 => PairModel::secret(differs)
                    .confounder(differs, PER_CLASS_KEYS)
                    .confounder(
                        differs,
                        "the shared points returned for the two keys differ",
                    ),
                Scenario::ControlPositive => PairModel::secret(differs),
                _ => PairModel::secret(false),
            }
        },
        varying_public_values: match scenario {
            Scenario::EcdhP521 => vec![
                "public key point loaded with each class (LoadExternal inPublic)".into(),
                "object name derived from that public area".into(),
                "shared point returned by ECDH_ZGen".into(),
                "transient handle and object slot assigned to each class".into(),
            ],
            _ => vec!["control output digest".into()],
        },
    })
}

pub fn doc(scenario: Scenario) -> ScenarioDoc {
    match scenario {
        Scenario::EcdhP521 => ScenarioDoc {
            harness: COMMAND_LEVEL.into(),
            entry_point: "TPM2_ECDH_ZGen (0x154) with one password session on a P-521 key loaded by TPM2_LoadExternal".into(),
            secret: "the P-521 private scalar d of the loaded key".into(),
            attacker_inputs: "the private scalars chosen for the two classes (search domain: valid scalars 1 <= d < n)".into(),
            observable_outputs: "response code and the shared point d*Q_peer".into(),
            classes: "two scalars loaded as two transient objects in one TPM; each class sends ECDH_ZGen on its own handle".into(),
            fixed: "the peer point (SHA-512 derived), curve, object template, session encoding, command length".into(),
            timed_region: "one TPMLIB_Process call of ECDH_ZGen; key loading, Startup and warm-up are outside".into(),
            correctness: "shared point computed independently with the p521 crate; exact response match on every execution".into(),
            interpretation: "a signal shows ECDH time depends on the private scalar (or the derived public values that vary with it); it is not attributed to the scalar alone".into(),
            randomized: false,
        },
        _ => ScenarioDoc {
            harness: "synthetic: worker-internal LCG loop, no libtpms code".into(),
            entry_point: "worker control backend".into(),
            secret: "the masked popcount of the last 8 input bytes (positive) or nothing (negative)".into(),
            attacker_inputs: "66-byte inputs".into(),
            observable_outputs: "16-byte digest of the loop state and iteration count".into(),
            classes: "two inputs".into(),
            fixed: "loop body".into(),
            timed_region: "one control call".into(),
            correctness: "digest recomputed in Rust".into(),
            interpretation: "positive: must be found; negative: must not be confirmed".into(),
            randomized: false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::PreparedPair;

    #[test]
    fn seeds_are_valid_and_deterministic() {
        let first = seeds(7, 4);
        let second = seeds(7, 4);
        assert_eq!(first.len(), second.len());
        for (a, b) in first.iter().zip(&second) {
            assert_eq!(a.pair, b.pair);
            assert_eq!(a.pair.to_bytes().len(), 132);
            assert!(ScalarPair::from_bytes(&a.pair.to_bytes()).is_ok());
        }
        let names: Vec<_> = first.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"order-minus-1-vs-random"));
        assert!(names.contains(&"leading-zero-9-bytes-vs-full-width"));
        assert!(names.contains(&"limb-2^64-minus-1-vs-2^64"));
        assert!(names.contains(&"small-1-vs-random"));
        let leading = first
            .iter()
            .find(|s| s.name == "leading-zero-9-bytes-vs-full-width")
            .unwrap()
            .pair
            .as_scalar_pair()
            .unwrap();
        assert_eq!(leading.a.leading_zero_bytes(), 9);
        assert_eq!(leading.b.bit_length(), 521);
    }

    #[test]
    fn negative_control_output_ignores_the_secret() {
        let a = [1u8; SCALAR_BYTES];
        let mut b = [0u8; SCALAR_BYTES];
        b[65] = 9;
        assert_eq!(
            control_output(Scenario::ControlNegative, &a),
            control_output(Scenario::ControlNegative, &b)
        );
        assert_ne!(
            control_output(Scenario::ControlPositive, &a),
            control_output(Scenario::ControlPositive, &b)
        );
    }

    #[test]
    fn ecdh_preparation_produces_matching_expected_responses() {
        let pair = seeds(1, 1)[0].pair.clone();
        let prepared = PreparedPair::prepare(Scenario::EcdhP521, pair);
        for class in 0..2 {
            let expected = &prepared.classes[class].expected_response;
            assert_eq!(expected.len(), 157);
            assert_eq!(crate::tpm::response_code(expected), Ok(0));
            assert_eq!(
                prepared.measured_command(class, 0x8000_0000).len(),
                crate::tpm::zgen_command_len()
            );
        }
        assert_ne!(
            prepared.classes[0].expected_response,
            prepared.classes[1].expected_response
        );
    }
}
