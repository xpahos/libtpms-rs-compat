use std::fmt;

use serde::{Deserialize, Serialize};

use crate::scalar::{
    Point, SCALAR_BYTES, Scalar521, ScalarPair, offset, order_minus, peer_scalar, power_of_two,
};
use crate::tpm;

pub const CONTROL_BASE_ITERATIONS: u64 = 20_000;
pub const CONTROL_ITERATIONS_PER_BIT: u64 = 1000;
pub const CONTROL_COUNTED_BYTES: usize = 8;
pub const CONTROL_MASK: [u8; CONTROL_COUNTED_BYTES] =
    [0xa5, 0x3c, 0x96, 0x0f, 0xe1, 0x78, 0x2d, 0xb4];

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    clap::ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
pub enum Scenario {
    EcdhP521,
    ControlPositive,
    ControlNegative,
}

impl Scenario {
    pub fn name(self) -> &'static str {
        match self {
            Self::EcdhP521 => "ecdh-p521",
            Self::ControlPositive => "control-positive",
            Self::ControlNegative => "control-negative",
        }
    }

    pub fn is_control(self) -> bool {
        !matches!(self, Self::EcdhP521)
    }
}

impl fmt::Display for Scenario {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassPrep {
    #[serde(with = "crate::scalar::hex_bytes")]
    pub scalar: Vec<u8>,
    pub public: Option<Point>,
    pub shared: Option<Point>,
    #[serde(with = "crate::scalar::hex_bytes")]
    pub expected_response: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicMetadata {
    pub varying_public_values: Vec<String>,
    pub bit_length: [usize; 2],
    pub leading_zero_bytes: [usize; 2],
    pub hamming_weight: [u32; 2],
    pub shared_x_leading_zero_bytes: [usize; 2],
    pub public_x_leading_zero_bytes: [usize; 2],
}

#[derive(Debug, Clone)]
pub struct PreparedPair {
    pub scenario: Scenario,
    pub pair: ScalarPair,
    pub classes: [ClassPrep; 2],
    pub metadata: PublicMetadata,
}

impl PreparedPair {
    pub fn prepare(scenario: Scenario, pair: ScalarPair) -> Self {
        let class = |scalar: &Scalar521| match scenario {
            Scenario::EcdhP521 => {
                let shared = scalar.shared_point(&peer_scalar());
                ClassPrep {
                    scalar: scalar.bytes().to_vec(),
                    public: Some(scalar.public_point()),
                    expected_response: tpm::expected_zgen_response(&shared),
                    shared: Some(shared),
                }
            }
            Scenario::ControlPositive | Scenario::ControlNegative => ClassPrep {
                scalar: scalar.bytes().to_vec(),
                public: None,
                shared: None,
                expected_response: control_output(scenario, scalar.bytes()).to_vec(),
            },
        };
        let classes = [class(&pair.a), class(&pair.b)];
        let leading = |bytes: &[u8]| bytes.iter().take_while(|byte| **byte == 0).count();
        let metadata = PublicMetadata {
            varying_public_values: match scenario {
                Scenario::EcdhP521 => vec![
                    "public key point loaded with each class (LoadExternal inPublic)".into(),
                    "object name derived from that public area".into(),
                    "shared point returned by ECDH_ZGen".into(),
                    "transient handle and object slot assigned to each class".into(),
                ],
                _ => vec!["control output digest".into()],
            },
            bit_length: [pair.a.bit_length(), pair.b.bit_length()],
            leading_zero_bytes: [pair.a.leading_zero_bytes(), pair.b.leading_zero_bytes()],
            hamming_weight: [pair.a.hamming_weight(), pair.b.hamming_weight()],
            shared_x_leading_zero_bytes: [0, 1].map(|i| {
                classes[i]
                    .shared
                    .as_ref()
                    .map(|p| leading(&p.x))
                    .unwrap_or(0)
            }),
            public_x_leading_zero_bytes: [0, 1].map(|i| {
                classes[i]
                    .public
                    .as_ref()
                    .map(|p| leading(&p.x))
                    .unwrap_or(0)
            }),
        };
        Self {
            scenario,
            pair,
            classes,
            metadata,
        }
    }

    pub fn load_command(&self, class: usize) -> Option<Vec<u8>> {
        match self.scenario {
            Scenario::EcdhP521 => Some(tpm::load_external(
                self.pair.class(class),
                self.classes[class]
                    .public
                    .as_ref()
                    .expect("ecdh class has a public point"),
            )),
            _ => None,
        }
    }

    pub fn measured_command(&self, class: usize, handle: u32) -> Vec<u8> {
        match self.scenario {
            Scenario::EcdhP521 => tpm::ecdh_zgen(handle, &peer_point()),
            _ => self.pair.class(class).bytes().to_vec(),
        }
    }
}

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
        Scenario::EcdhP521 => unreachable!("not a control scenario"),
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SeedKind {
    Random,
    Boundary,
}

#[derive(Debug, Clone)]
pub struct Seed {
    pub name: String,
    pub kind: SeedKind,
    pub pair: ScalarPair,
}

pub struct SplitMix(u64);

impl SplitMix {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn scalar(&mut self) -> Scalar521 {
        loop {
            let mut bytes = [0u8; SCALAR_BYTES];
            for chunk in bytes.chunks_mut(8) {
                let word = self.next_u64().to_be_bytes();
                chunk.copy_from_slice(&word[..chunk.len()]);
            }
            bytes[0] &= 0x01;
            if let Ok(scalar) = Scalar521::new(bytes) {
                return scalar;
            }
        }
    }

    pub fn full_width_scalar(&mut self) -> Scalar521 {
        loop {
            let scalar = self.scalar();
            if scalar.bit_length() == 521 {
                return scalar;
            }
        }
    }
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
            pair: ScalarPair { a, b },
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
            },
        })
        .collect();
    out.extend(boundary_seeds(campaign_seed));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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
            .unwrap();
        assert_eq!(leading.pair.a.leading_zero_bytes(), 9);
        assert_eq!(leading.pair.b.bit_length(), 521);
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
        let pair = seeds(1, 1)[0].pair;
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
