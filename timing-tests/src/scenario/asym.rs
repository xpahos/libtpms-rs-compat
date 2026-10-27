use num_bigint::BigUint;

use super::catalog::{AsymKind, EccScheme, RsaPadding, RsaSigScheme, Scenario};
use super::family::{
    Built, COMMAND_LEVEL, Check, ClassSpec, PER_CLASS_KEYS, PairModel, ScenarioDoc, mask_range,
    random_seeds, seed,
};
use super::layout::{Creates, HandleRef, Post, Step};
use super::{InputPair, Seed, SplitMix};
use crate::oracle::bytes::{from_be, to_fixed};
use crate::oracle::ec::{Affine, CurveId};
use crate::oracle::hash::HashAlg;
use crate::oracle::rsa::{
    RsaBits, oaep_encode, oaep_unmask, pkcs1_sign_encode, pkcs1_type2_decode, pkcs1_type2_encode,
};
use crate::scalar::Point;
use crate::tpm::{
    self, ATTR_DECRYPT, ATTR_NO_DA, ATTR_SIGN, ATTR_USER_WITH_AUTH, Public, PublicDetail, Scheme,
    SymDef, TPM_ALG_ECC, TPM_ALG_NULL, TPM_ALG_OAEP, TPM_ALG_RSA, TPM_ALG_RSAES, TPM_ALG_RSAPSS,
    TPM_ALG_RSASSA, TPM_ALG_SHA256, TPM_RH_NULL, TPM_ST_HASHCHECK,
};

pub const PADDED_KINDS: u8 = 5;
/// RSAES encodings have two extra boundary kinds: a separator byte placed at PS length 7
/// (one before the minimum valid padding of 8) and at PS length 8 (the minimum that a
/// conforming decoder still accepts). Existing kinds 0..=4 keep their meaning.
pub const RSAES_KINDS: u8 = 7;
pub const PADDED_MATERIAL: usize = 48;
pub const MESSAGE_BYTES: usize = 32;
pub const NONCE_CALLER: [u8; 32] = [0x6e; 32];
pub const SALT_LABEL: &[u8] = b"SECRET\0";

pub fn ecc_public(curve: CurveId, attributes: u32, scheme: Scheme, point: &Affine) -> Public {
    let c = curve.curve();
    let (x, y) = c.encode(point);
    Public {
        name_alg: TPM_ALG_SHA256,
        attributes,
        detail: PublicDetail::Ecc {
            symmetric: SymDef::Null,
            scheme,
            curve: curve.tpm_id(),
            x,
            y,
        },
    }
}

pub fn ecc_load(curve: CurveId, attributes: u32, scheme: Scheme, d: &[u8]) -> (Vec<u8>, Affine) {
    let c = curve.curve();
    let q = c
        .mul_g(&from_be(d))
        .expect("valid scalar has a public point");
    let public = ecc_public(curve, attributes, scheme, &q);
    let sensitive = tpm::sensitive(TPM_ALG_ECC, &[], &[], &to_fixed(&from_be(d), c.bytes));
    (
        tpm::load_external_command(Some(&sensitive), &public, TPM_RH_NULL),
        q,
    )
}

pub fn rsa_public(bits: RsaBits, attributes: u32, scheme: Scheme) -> Public {
    Public {
        name_alg: TPM_ALG_SHA256,
        attributes,
        detail: PublicDetail::Rsa {
            symmetric: SymDef::Null,
            scheme,
            bits: bits.bits() as u16,
            modulus: bits.key().modulus(),
        },
    }
}

pub fn rsa_load(bits: RsaBits, attributes: u32, scheme: Scheme) -> Vec<u8> {
    let public = rsa_public(bits, attributes, scheme);
    let sensitive = tpm::sensitive(TPM_ALG_RSA, &[], &[], &bits.key().prime());
    tpm::load_external_command(Some(&sensitive), &public, TPM_RH_NULL)
}

fn point_of(curve: CurveId, point: &Affine) -> Point {
    let (x, y) = curve.curve().encode(point);
    Point { x, y }
}

pub fn ecc_point_bytes(curve: CurveId, point: &Affine) -> Vec<u8> {
    let (x, y) = curve.curve().encode(point);
    let mut out = Vec::new();
    tpm::put_2b(&mut out, &x);
    tpm::put_2b(&mut out, &y);
    out
}

fn derived_scalar(curve: CurveId, label: &str) -> BigUint {
    let c = curve.curve();
    let digest = HashAlg::Sha512.digest(&[label.as_bytes(), curve.name().as_bytes()]);
    let mut wide = digest.clone();
    wide.extend(HashAlg::Sha512.digest(&[&digest]));
    from_be(&wide) % (&c.n - 1u32) + 1u32
}

pub fn peer_point(curve: CurveId) -> Affine {
    curve
        .curve()
        .mul_g(&derived_scalar(curve, "tpms-timing-tests ecdh peer v1"))
        .unwrap()
}

pub fn sign_digest() -> Vec<u8> {
    HashAlg::Sha256.digest(&[b"tpms-timing-tests sign message v1"])
}

pub fn null_ticket() -> Vec<u8> {
    let mut out = Vec::new();
    tpm::put_u16(&mut out, TPM_ST_HASHCHECK);
    tpm::put_u32(&mut out, TPM_RH_NULL);
    tpm::put_2b(&mut out, &[]);
    out
}

fn curve_of(scenario: Scenario) -> Option<CurveId> {
    match scenario {
        Scenario::Ecdh(curve)
        | Scenario::EccSign(_, curve)
        | Scenario::SaltedSession(AsymKind::Ecc(curve)) => Some(curve),
        _ => None,
    }
}

pub fn input_width(scenario: Scenario) -> usize {
    match scenario {
        Scenario::Ecdh(curve) | Scenario::EccSign(_, curve) => curve.key_bytes(),
        Scenario::SaltedSession(AsymKind::Ecc(curve)) => 1 + curve.key_bytes(),
        Scenario::SaltedSession(AsymKind::Rsa(_)) => 1 + PADDED_MATERIAL,
        Scenario::RsaDecrypt(bits, RsaPadding::Raw) => bits.bytes(),
        Scenario::RsaDecrypt(..) => 1 + PADDED_MATERIAL,
        Scenario::RsaSign(..) => 32,
        _ => unreachable!("not an asymmetric scenario"),
    }
}

pub fn validate(scenario: Scenario, bytes: &[u8]) -> Result<(), String> {
    match scenario {
        Scenario::EccSign(EccScheme::Sm2, curve) => {
            let c = curve.curve();
            (c.valid_scalar(bytes) && from_be(bytes) < &c.n - 1u32)
                .then_some(())
                .ok_or_else(|| format!("not an SM2 private key 1 <= d <= n-2 for {}", curve.name()))
        }
        Scenario::Ecdh(curve) | Scenario::EccSign(_, curve) => curve
            .curve()
            .valid_scalar(bytes)
            .then_some(())
            .ok_or_else(|| format!("not a scalar 1 <= d < n for {}", curve.name())),
        Scenario::SaltedSession(AsymKind::Ecc(curve)) => curve
            .curve()
            .valid_scalar(&bytes[1..])
            .then_some(())
            .ok_or_else(|| "ephemeral scalar out of range".into()),
        Scenario::RsaDecrypt(bits, RsaPadding::Raw) => (from_be(bytes) < bits.key().n)
            .then_some(())
            .ok_or_else(|| "ciphertext is not below the modulus".into()),
        _ => Ok(()),
    }
}

fn scalar_seeds(curve: CurveId, top: u32) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let c = curve.curve();
    let w = c.bytes;
    let fix = |v: &BigUint| to_fixed(v, w);
    let n = &c.n;
    let below = |k: u32| {
        (
            format!("order-minus-{}", k + top - 1),
            fix(&(n - (k + top - 1))),
        )
    };
    let mut rng = SplitMix::new(0x5ca1_ab1e ^ curve.tpm_id() as u64);
    let mut random = || rng.below(n, w);
    let small = |v: u64| fix(&BigUint::from(v));
    let (top_name, top_value) = below(1);
    let (next_name, next_value) = below(2);
    let mut out = vec![
        ("small-1-vs-random".into(), small(1), random()),
        ("small-2-vs-small-3".into(), small(2), small(3)),
        (format!("{top_name}-vs-random"), top_value.clone(), random()),
        (
            format!("{top_name}-vs-small-1"),
            top_value.clone(),
            small(1),
        ),
        (format!("{next_name}-vs-{top_name}"), next_value, top_value),
    ];
    for zeros in [1usize, 2, 8] {
        let mut a = random();
        a[..zeros].fill(0);
        if a[zeros] == 0 {
            a[zeros] = 0x80;
        }
        out.push((format!("leading-zero-{zeros}-bytes-vs-random"), a, random()));
    }
    for exponent in [64usize, 128] {
        let p = BigUint::from(1u32) << exponent;
        out.push((
            format!("limb-2^{exponent}-minus-1-vs-2^{exponent}"),
            fix(&(&p - 1u32)),
            fix(&p),
        ));
    }
    let top = BigUint::from(1u32) << (n.bits() - 1);
    out.push(("top-bit-vs-random".into(), fix(&top), random()));
    out
}

fn padded_seed_names(padding_kinds: &[&str]) -> Vec<(String, u8, u8)> {
    let mut out = vec![("valid-vs-valid".to_string(), 0u8, 0u8)];
    for (i, a) in padding_kinds.iter().enumerate() {
        for (j, b) in padding_kinds.iter().enumerate().skip(i + 1) {
            out.push((format!("{a}-vs-{b}"), i as u8 + 1, j as u8 + 1));
        }
    }
    out.push((format!("valid-vs-{}", padding_kinds[0]), 0, 1));
    out
}

pub fn oaep_kind_names() -> [&'static str; 4] {
    [
        "bad-leading-byte",
        "bad-label-hash",
        "bad-separator",
        "missing-separator",
    ]
}

pub fn pkcs1_kind_names() -> [&'static str; 6] {
    [
        "bad-block-type",
        "bad-leading-byte",
        "missing-separator",
        "short-padding",
        "separator-before-minimum",
        "separator-at-minimum",
    ]
}

pub fn seeds(scenario: Scenario, campaign_seed: u64, random_pairs: usize) -> Vec<Seed> {
    let width = input_width(scenario);
    let mut out = Vec::new();
    match scenario {
        Scenario::Ecdh(curve) | Scenario::EccSign(_, curve) => {
            let top = if matches!(scenario, Scenario::EccSign(EccScheme::Sm2, _)) {
                2
            } else {
                1
            };
            for (name, a, b) in scalar_seeds(curve, top) {
                out.push(seed(name, a, b));
            }
            let c = curve.curve();
            out.extend(random_seeds(scenario, campaign_seed, random_pairs, |rng| {
                rng.below(&c.n, c.bytes)
            }));
        }
        Scenario::SaltedSession(AsymKind::Ecc(curve)) => {
            for (name, a, b) in scalar_seeds(curve, 1) {
                out.push(seed(name, [vec![0], a].concat(), [vec![0], b].concat()));
            }
            let (_, a, _) = scalar_seeds(curve, 1).remove(0);
            out.push(seed(
                "valid-vs-off-curve",
                [vec![0], a.clone()].concat(),
                [vec![1], a].concat(),
            ));
            let c = curve.curve();
            out.extend(random_seeds(scenario, campaign_seed, random_pairs, |rng| {
                [vec![0], rng.below(&c.n, c.bytes)].concat()
            }));
        }
        Scenario::RsaDecrypt(bits, RsaPadding::Raw) => {
            let key = bits.key();
            let k = bits.bytes();
            let mut rng = SplitMix::new(0x0007_7a11 ^ k as u64);
            let mut random = || rng.below(&key.n, k);
            let small = |v: u64| to_fixed(&BigUint::from(v), k);
            out.push(seed("small-1-vs-random", small(1), random()));
            out.push(seed("small-2-vs-small-3", small(2), small(3)));
            out.push(seed(
                "modulus-minus-1-vs-random",
                to_fixed(&(&key.n - 1u32), k),
                random(),
            ));
            let mut short = random();
            short[..k / 2].fill(0);
            out.push(seed("half-width-vs-random", short, random()));
            out.extend(random_seeds(scenario, campaign_seed, random_pairs, |rng| {
                rng.below(&key.n, k)
            }));
        }
        Scenario::RsaDecrypt(_, RsaPadding::Rsaes) => {
            let names = pkcs1_kind_names();
            let mut rng = SplitMix::new(0x0bad_5eed ^ width as u64);
            let mut pairs = padded_seed_names(&names);
            // Keep the validated valid-vs-valid pairs of the previous coverage.
            pairs.splice(
                1..1,
                [
                    ("valid-vs-valid-second-pair".to_string(), 0u8, 0u8),
                    ("valid-vs-valid-third-pair".to_string(), 0, 0),
                ],
            );
            for (name, ka, kb) in pairs {
                out.push(seed(
                    name,
                    [
                        vec![rsaes_kind_byte(ka as usize)],
                        rng.bytes(PADDED_MATERIAL),
                    ]
                    .concat(),
                    [
                        vec![rsaes_kind_byte(kb as usize)],
                        rng.bytes(PADDED_MATERIAL),
                    ]
                    .concat(),
                ));
            }
            // An invalid/invalid pair whose independently predicted implicit-rejection
            // plaintexts have equal length, so equal-length synthetic responses are not
            // mistaken for identical outcomes.
            out.push(equal_length_malformed_pair(scenario, width));
            out.extend(random_seeds(scenario, campaign_seed, random_pairs, |rng| {
                [vec![0], rng.bytes(PADDED_MATERIAL)].concat()
            }));
        }
        Scenario::RsaDecrypt(..) | Scenario::SaltedSession(AsymKind::Rsa(_)) => {
            let names = oaep_kind_names();
            let mut rng = SplitMix::new(0x0bad_5eed ^ width as u64);
            let pairs = padded_seed_names(&names);
            for (name, ka, kb) in pairs {
                out.push(seed(
                    name,
                    [vec![ka], rng.bytes(PADDED_MATERIAL)].concat(),
                    [vec![kb], rng.bytes(PADDED_MATERIAL)].concat(),
                ));
            }
            out.extend(random_seeds(scenario, campaign_seed, random_pairs, |rng| {
                [vec![0], rng.bytes(PADDED_MATERIAL)].concat()
            }));
        }
        Scenario::RsaSign(..) => {
            out.push(seed(
                "zero-digest-vs-ones-digest",
                vec![0; 32],
                vec![0xff; 32],
            ));
            out.push(seed("digest-vs-digest-bitflip", sign_digest(), {
                let mut d = sign_digest();
                d[31] ^= 1;
                d
            }));
            out.extend(random_seeds(scenario, campaign_seed, random_pairs, |rng| {
                rng.bytes(32)
            }));
        }
        _ => unreachable!(),
    }
    out
}

fn padding_is_pkcs1(scenario: Scenario) -> bool {
    matches!(scenario, Scenario::RsaDecrypt(_, RsaPadding::Rsaes))
}

/// Deterministically derived invalid/invalid input pair whose independently predicted
/// OpenSSL implicit-rejection synthetic plaintexts have equal lengths, so genuinely
/// equal-length synthetic responses cannot be mistaken for extra structure. The bytes
/// of the two plaintexts still differ with overwhelming probability because the PRF is
/// keyed by different ciphertexts.
fn equal_length_malformed_pair(scenario: Scenario, width: usize) -> Seed {
    let Scenario::RsaDecrypt(bits, RsaPadding::Rsaes) = scenario else {
        unreachable!("RSAES scenario required");
    };
    type EqualLengthPairs = std::collections::BTreeMap<RsaBits, (Vec<u8>, Vec<u8>)>;
    static PAIRS: std::sync::OnceLock<EqualLengthPairs> = std::sync::OnceLock::new();
    let (a, b) = PAIRS
        .get_or_init(|| {
            let mut found = std::collections::BTreeMap::new();
            for bits in RsaBits::ALL {
                let key = bits.key();
                let input_width = 1 + PADDED_MATERIAL;
                let synthetic_len = |material: &[u8]| -> Option<usize> {
                    let mut input = vec![0u8; input_width];
                    input[0] = 3; // missing-separator: invalid for every well-formed decoder
                    input[1..].copy_from_slice(material);
                    let (em, outcome) =
                        encode_pkcs1_case(bits.bytes(), &input, RsaesSelectorSpace::LegacyMod5);
                    match outcome {
                        Encoded::Invalid => {}
                        Encoded::Valid(_) => return None,
                    }
                    let ciphertext = key.public(&em)?;
                    Some(crate::oracle::rsa::implicit_rejection(key, &ciphertext).len())
                };
                let mut rng = SplitMix::new(0x1e55_1e55 ^ bits.bits() as u64);
                let left = rng.bytes(PADDED_MATERIAL);
                let target = synthetic_len(&left).expect("kind 3 fixture decodes as invalid");
                let right = (0..200_000u32)
                    .map(|_| rng.bytes(PADDED_MATERIAL))
                    .find(|m| synthetic_len(m) == Some(target))
                    .unwrap_or_else(|| left.clone());
                found.insert(bits, (left, right));
            }
            found
        })
        .get(&bits)
        .expect("pair computed for every RSA key size")
        .clone();
    debug_assert_eq!(width, 1 + PADDED_MATERIAL);
    seed(
        "invalid-invalid-equal-implicit-length",
        [vec![3], a].concat(),
        [vec![3], b].concat(),
    )
}

pub fn boundary(scenario: Scenario, op: usize, r: u64, current: &[u8], other: &[u8]) -> Vec<u8> {
    let scalar_mutation = |curve: CurveId, current: &[u8], other: &[u8]| -> Vec<u8> {
        let c = curve.curve();
        let w = c.bytes;
        match op % 6 {
            0 => to_fixed(&BigUint::from(r % 0xffff + 1), w),
            1 => to_fixed(&(&c.n - (r % 0xffff + 1)), w),
            2 => {
                let mut out = current.to_vec();
                let zeros = 1 + (r as usize) % (w / 2);
                out[..zeros].fill(0);
                out
            }
            3 => {
                let exponent = 32 + (r as usize) % (c.n.bits() as usize - 33);
                let p = BigUint::from(1u32) << exponent;
                let delta = (r >> 8) % 3;
                let value = if delta == 0 {
                    p - 1u32
                } else {
                    p + (delta - 1)
                };
                to_fixed(&value, w)
            }
            4 => {
                let mut out = other.to_vec();
                let bit = (r as usize) % (8 * w);
                out[w - 1 - bit / 8] ^= 1 << (bit % 8);
                out
            }
            _ => {
                let mut out = current.to_vec();
                out[0] ^= 0x80 >> (r % 8);
                out
            }
        }
    };
    match scenario {
        Scenario::Ecdh(curve) | Scenario::EccSign(_, curve) => {
            scalar_mutation(curve, current, other)
        }
        Scenario::SaltedSession(AsymKind::Ecc(curve)) => {
            if op % 7 == 6 {
                let mut out = current.to_vec();
                out[0] ^= 1;
                return out;
            }
            [
                vec![current[0]],
                scalar_mutation(curve, &current[1..], &other[1..]),
            ]
            .concat()
        }
        Scenario::RsaDecrypt(bits, RsaPadding::Raw) => {
            let key = bits.key();
            let k = bits.bytes();
            match op % 4 {
                0 => to_fixed(&BigUint::from(r % 0xffff + 1), k),
                1 => to_fixed(&(&key.n - (r % 0xffff + 1)), k),
                2 => {
                    let mut out = current.to_vec();
                    out[..1 + (r as usize) % (k / 2)].fill(0);
                    out
                }
                _ => {
                    let mut out = other.to_vec();
                    let bit = (r as usize) % (8 * k - 8);
                    out[k - 1 - bit / 8] ^= 1 << (bit % 8);
                    out
                }
            }
        }
        Scenario::RsaDecrypt(..) | Scenario::SaltedSession(AsymKind::Rsa(_)) => {
            let mut out = current.to_vec();
            if padding_is_pkcs1(scenario) {
                match op % 4 {
                    // Explore the encoding kinds: the legacy alias space
                    // (selector bytes below 0x80) and the versioned
                    // separator-boundary selectors 0x85 / 0x86.
                    0 => {
                        out[0] = match r % RSAES_KINDS as u64 {
                            5 => RSAES_SEPARATOR_BEFORE_MINIMUM_SELECTOR as u64,
                            6 => RSAES_SEPARATOR_AT_MINIMUM_SELECTOR as u64,
                            k => k,
                        } as u8
                    }
                    1 => out[1..].copy_from_slice(&other[1..]),
                    2 => {
                        let at = 1 + (r as usize) % PADDED_MATERIAL;
                        out[at] ^= 1 << ((r >> 16) % 8);
                    }
                    _ => {
                        let fill = if r & 1 == 0 { 0x00 } else { 0xff };
                        out[1..].iter_mut().for_each(|b| *b = fill);
                    }
                }
            } else if op.is_multiple_of(2) {
                out[0] = (r % PADDED_KINDS as u64) as u8;
            } else {
                out[1..].copy_from_slice(&other[1..]);
            }
            out
        }
        _ => super::family::generic_byte_boundary(op, r, current, other),
    }
}

fn material(input: &[u8], label: &str, len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut counter = 0u32;
    while out.len() < len {
        out.extend(HashAlg::Sha256.digest(&[label.as_bytes(), &counter.to_be_bytes(), input]));
        counter += 1;
    }
    out.truncate(len);
    out
}

pub enum Encoded {
    Valid(Vec<u8>),
    Invalid,
}

pub fn encode_oaep_case(hash: HashAlg, label: &[u8], k: usize, input: &[u8]) -> (Vec<u8>, Encoded) {
    let kind = input[0] % PADDED_KINDS;
    let maximum = k
        .checked_sub(2 * hash.size() + 2)
        .expect("OAEP configuration must fit its hash");
    let message = input[1..1 + MESSAGE_BYTES.min(maximum)].to_vec();
    let seed = material(input, "oaep-seed", hash.size());
    let h = hash.size();
    let mut em = oaep_encode(hash, label, &message, &seed, k);
    if kind == 0 {
        return (em, Encoded::Valid(message));
    }
    let (_, mut db) = oaep_unmask(hash, &em);
    let mut first = 0u8;
    match kind {
        1 => first = 0x01,
        2 => db[0] ^= 0x01,
        3 => {
            let at = db.len() - message.len() - 1;
            db[at] = 0x02;
        }
        _ => {
            let len = db.len();
            db[h..len].fill(0);
        }
    }
    let mut masked_db = db.clone();
    let db_mask = crate::oracle::kdf::mgf1(hash, &seed, k - h - 1);
    masked_db
        .iter_mut()
        .zip(&db_mask)
        .for_each(|(a, b)| *a ^= b);
    let mut masked_seed = seed.clone();
    let seed_mask = crate::oracle::kdf::mgf1(hash, &masked_db, h);
    masked_seed
        .iter_mut()
        .zip(&seed_mask)
        .for_each(|(a, b)| *a ^= b);
    em = vec![first];
    em.extend(masked_seed);
    em.extend(masked_db);
    let decoded = crate::oracle::rsa::oaep_decode(hash, label, &em);
    (
        em,
        match decoded {
            Some(m) => Encoded::Valid(m),
            None => Encoded::Invalid,
        },
    )
}

/// The RSAES selector-encoding version recorded explicitly with every saved
/// input. The version is never inferred from the selector byte: candidates
/// written before the versioned encoding keep their original semantics, and
/// program-generated inputs state the current version explicitly.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    Default,
    Hash,
    PartialOrd,
    Ord,
)]
#[serde(rename_all = "kebab-case")]
pub enum RsaesSelectorSpace {
    /// Original selector semantics: `kind = selector % 5` for every one of the
    /// 256 possible selector bytes, including bytes with the high bit set.
    /// Candidates saved before the versioned encoding decode with this space;
    /// a missing `selector-encoding` field therefore means legacy-mod5.
    #[default]
    LegacyMod5,
    /// Versioned selector encoding: bytes below 0x80 keep `kind = selector % 5`
    /// (identical to the legacy space, so alias selectors 0, 5, 10, 15… keep
    /// their original meaning); bytes with the high bit set select the explicit
    /// separator-boundary kinds: 0x85 a separator one byte before the conforming
    /// PS minimum (PS length 7, rejected) and 0x86 the minimum a conforming
    /// decoder accepts (PS length 8, message k - 11).
    V2Tagged,
}

pub const RSAES_V2_TAG: u8 = 0x80;
pub const RSAES_SEPARATOR_BEFORE_MINIMUM_SELECTOR: u8 = 0x85;
pub const RSAES_SEPARATOR_AT_MINIMUM_SELECTOR: u8 = 0x86;

pub fn rsaes_selector_kind(selector: u8, space: RsaesSelectorSpace) -> usize {
    match space {
        RsaesSelectorSpace::LegacyMod5 => usize::from(selector % 5),
        RsaesSelectorSpace::V2Tagged => {
            if selector & RSAES_V2_TAG != 0 {
                // 0x85 (odd) selects the separator one byte before the conforming
                // minimum (kind 5); 0x86 (even) selects the minimum itself (kind 6).
                5 + usize::from(selector & 0x01 == 0)
            } else {
                usize::from(selector % 5)
            }
        }
    }
}

/// Seed/boundary byte encoding of a kind: legacy kinds 0..=4 keep their
/// historical bytes, the separator-boundary kinds use the v2 tagged selectors.
pub fn rsaes_kind_byte(kind: usize) -> u8 {
    match kind {
        0..=4 => kind as u8,
        5 => RSAES_SEPARATOR_BEFORE_MINIMUM_SELECTOR,
        _ => RSAES_SEPARATOR_AT_MINIMUM_SELECTOR,
    }
}

pub fn encode_pkcs1_case(k: usize, input: &[u8], space: RsaesSelectorSpace) -> (Vec<u8>, Encoded) {
    let kind = rsaes_selector_kind(input[0], space);
    let message = input[1..1 + MESSAGE_BYTES].to_vec();
    if matches!(kind, 5 | 6) {
        // The 0x00 separator sits at PS length 7 (one before the conforming minimum
        // of 8, rejected) or at PS length 8 (the minimum a conforming decoder accepts,
        // yielding the longest decodable message, k - 11 bytes).
        let ps_len = 7 + usize::from(kind == 6);
        // EM = 0x00 0x02 || PS || 0x00 || message, exactly k bytes, so the
        // message is k - 2 - ps_len - 1 bytes (k - 11 for the minimum PS of 8).
        let ps: Vec<u8> = material(input, "pkcs1-boundary-ps", ps_len)
            .into_iter()
            .map(|b| if b == 0 { 0x5a } else { b })
            .collect();
        let bag = material(input, "pkcs1-boundary-message", k - 3 - ps_len);
        let mut em = vec![0u8, 2];
        em.extend_from_slice(&ps);
        em.push(0);
        em.extend_from_slice(&bag);
        assert_eq!(em.len(), k);
        return (
            em.clone(),
            match pkcs1_type2_decode(&em) {
                Some(m) => Encoded::Valid(m),
                None => Encoded::Invalid,
            },
        );
    }
    let padding: Vec<u8> = material(input, "pkcs1-padding", k - 3 - MESSAGE_BYTES)
        .into_iter()
        .map(|b| if b == 0 { 0x5a } else { b })
        .collect();
    let mut em = pkcs1_type2_encode(&message, &padding, k);
    match kind {
        0 => {}
        1 => em[1] = 0x01,
        2 => em[0] = 0x01,
        3 => {
            let at = 2 + padding.len();
            em[at] = 0xa5;
        }
        _ => em[6] = 0,
    }
    let decoded = pkcs1_type2_decode(&em);
    (
        em,
        match decoded {
            Some(m) => Encoded::Valid(m),
            None => Encoded::Invalid,
        },
    )
}

fn sign_command(digest: &[u8], scheme: Scheme) -> Step {
    let mut parameters = Vec::new();
    tpm::put_2b(&mut parameters, digest);
    scheme.marshal(&mut parameters);
    parameters.extend(null_ticket());
    let built = tpm::build_command(tpm::TPM_CC_SIGN, &[0], &[&[]], &parameters);
    Step::new("Sign", built.bytes).handle_at(10, HandleRef::Class(0))
}

pub fn build(scenario: Scenario, pair: &InputPair) -> Result<Built, String> {
    let classes = [0, 1].map(|class| build_class(scenario, pair.class(class), pair.selector_space));
    let [a, b] = classes;
    let varying = match scenario {
        Scenario::Ecdh(_) => vec![
            "public key and object name loaded with each class".into(),
            "shared point returned by ECDH_ZGen".into(),
            "transient handle of each class".into(),
        ],
        Scenario::EccSign(..) => vec![
            "public key and object name loaded with each class".into(),
            "random signing nonce drawn from the TPM DRBG on every call".into(),
            "signature value (masked in the per-call comparison, verified independently)".into(),
        ],
        Scenario::RsaDecrypt(..) => vec![
            "ciphertext sent by each class (public, attacker-chosen)".into(),
            "decrypted message or error code".into(),
        ],
        Scenario::RsaSign(..) => vec![
            "digest sent by each class (public, attacker-chosen)".into(),
            "signature value".into(),
        ],
        _ => vec![
            "encrypted salt sent by each class (public ciphertext of a secret salt)".into(),
            "random nonceTPM in the response (masked)".into(),
        ],
    };
    Ok(Built {
        shared: match scenario {
            Scenario::RsaDecrypt(bits, _) => vec![
                Step::new(
                    "LoadExternal RSA decrypt key",
                    rsa_load(
                        bits,
                        ATTR_USER_WITH_AUTH | ATTR_NO_DA | ATTR_DECRYPT,
                        Scheme::Null,
                    ),
                )
                .creates(Creates::Object),
            ],
            Scenario::RsaSign(bits, _) => vec![
                Step::new(
                    "LoadExternal RSA signing key",
                    rsa_load(
                        bits,
                        ATTR_USER_WITH_AUTH | ATTR_NO_DA | ATTR_SIGN,
                        Scheme::Null,
                    ),
                )
                .creates(Creates::Object),
            ],
            Scenario::SaltedSession(AsymKind::Rsa(bits)) => vec![
                Step::new(
                    "LoadExternal RSA salt key",
                    rsa_load(
                        bits,
                        ATTR_USER_WITH_AUTH | ATTR_NO_DA | ATTR_DECRYPT,
                        Scheme::Null,
                    ),
                )
                .creates(Creates::Object),
            ],
            Scenario::SaltedSession(AsymKind::Ecc(curve)) => {
                let d = salt_key_scalar(curve);
                vec![
                    Step::new(
                        "LoadExternal ECC salt key",
                        ecc_load(
                            curve,
                            ATTR_USER_WITH_AUTH | ATTR_NO_DA | ATTR_DECRYPT,
                            Scheme::Null,
                            &d,
                        )
                        .0,
                    )
                    .creates(Creates::Object),
                ]
            }
            _ => Vec::new(),
        },
        classes: [a?, b?],
        model: pair_model(scenario, pair),
        varying_public_values: varying,
    })
}

fn salted_session_validation(
    kind: AsymKind,
    salt: &[u8],
) -> Result<super::family::Validation, String> {
    use super::family::{SaltedSessionValidation, Validation};
    let attributes = ATTR_USER_WITH_AUTH | ATTR_NO_DA | ATTR_DECRYPT;
    let (key_name, command_code, parameters, expected_parameters, label) = match kind {
        AsymKind::Rsa(bits) => {
            let key = bits.key();
            let message = vec![0x5au8; 32];
            let seed = HashAlg::Sha256.digest(&[b"tpms-timing-tests salted session probe"]);
            let em = oaep_encode(HashAlg::Sha256, &[], &message, &seed, bits.bytes());
            let ciphertext = key.public(&em).ok_or("probe ciphertext out of range")?;
            let mut parameters = Vec::new();
            tpm::put_2b(&mut parameters, &ciphertext);
            Scheme::WithHash(TPM_ALG_OAEP, TPM_ALG_SHA256).marshal(&mut parameters);
            tpm::put_2b(&mut parameters, &[]);
            let mut expected = Vec::new();
            tpm::put_2b(&mut expected, &message);
            (
                rsa_public(bits, attributes, Scheme::Null).name(),
                tpm::TPM_CC_RSA_DECRYPT,
                parameters,
                expected,
                "TPM2_RSA_Decrypt".to_string(),
            )
        }
        AsymKind::Ecc(curve) => {
            let c = curve.curve();
            let d = from_be(&salt_key_scalar(curve));
            let q = c.mul_g(&d).ok_or("salt key is infinity")?;
            let peer = peer_point(curve);
            let shared = c.mul(&d, &peer).ok_or("shared point is infinity")?;
            let mut parameters = Vec::new();
            tpm::put_2b(&mut parameters, &ecc_point_bytes(curve, &peer));
            let mut expected = Vec::new();
            tpm::put_2b(&mut expected, &ecc_point_bytes(curve, &shared));
            (
                ecc_public(curve, attributes, Scheme::Null, &q).name(),
                tpm::TPM_CC_ECDH_ZGEN,
                parameters,
                expected,
                "TPM2_ECDH_ZGen".to_string(),
            )
        }
    };
    Ok(Validation::SaltedSession(SaltedSessionValidation {
        hash: HashAlg::Sha256,
        nonce_caller: NONCE_CALLER.to_vec(),
        salt: salt.to_vec(),
        key_handle: tpm::FIRST_TRANSIENT_HANDLE,
        key_name,
        command_code,
        parameters,
        expected_parameters,
        label,
    }))
}

fn pair_model(scenario: Scenario, pair: &InputPair) -> PairModel {
    let differs = pair.a != pair.b;
    match scenario {
        Scenario::Ecdh(_) | Scenario::EccSign(..) => PairModel::secret(differs)
            .confounder(differs, PER_CLASS_KEYS)
            .confounder(differs, "the outputs computed with the different keys differ (shared point or signature values)"),
        Scenario::RsaDecrypt(..) => PairModel::secret(differs).public("ciphertext", differs),
        Scenario::RsaSign(..) => PairModel::secret(false).public("digest", differs),
        _ => PairModel::secret(differs).public("encrypted salt", differs),
    }
}

fn salt_key_scalar(curve: CurveId) -> Vec<u8> {
    to_fixed(
        &derived_scalar(curve, "tpms-timing-tests salt key v1"),
        curve.key_bytes(),
    )
}

fn build_class(
    scenario: Scenario,
    input: &[u8],
    space: RsaesSelectorSpace,
) -> Result<ClassSpec, String> {
    match scenario {
        Scenario::Ecdh(curve) => {
            let c = curve.curve();
            let (load, q) = ecc_load(
                curve,
                ATTR_USER_WITH_AUTH | ATTR_NO_DA | ATTR_DECRYPT,
                Scheme::Null,
                input,
            );
            let peer = peer_point(curve);
            let shared = c
                .mul(&from_be(input), &peer)
                .ok_or("shared point is infinity")?;
            let mut parameters = Vec::new();
            tpm::put_2b(&mut parameters, &ecc_point_bytes(curve, &peer));
            let command = tpm::build_command(tpm::TPM_CC_ECDH_ZGEN, &[0], &[&[]], &parameters);
            let mut out = Vec::new();
            tpm::put_2b(&mut out, &ecc_point_bytes(curve, &shared));
            let mut spec = ClassSpec::new(
                Step::new("ECDH_ZGen", command.bytes).handle_at(10, HandleRef::Class(0)),
                tpm::success_response(&[], &out, 1),
            );
            spec.setup = vec![Step::new("LoadExternal", load).creates(Creates::Object)];
            spec.public = Some(point_of(curve, &q));
            spec.shared = Some(point_of(curve, &shared));
            Ok(spec)
        }
        Scenario::EccSign(scheme, curve) => {
            let c = curve.curve();
            let key_scheme = Scheme::WithHash(scheme.alg_id(), TPM_ALG_SHA256);
            let (load, q) = ecc_load(
                curve,
                ATTR_USER_WITH_AUTH | ATTR_NO_DA | ATTR_SIGN,
                key_scheme,
                input,
            );
            let digest = sign_digest();
            let ob = c.order_bytes();
            let mut params = Vec::new();
            tpm::put_u16(&mut params, scheme.alg_id());
            tpm::put_u16(&mut params, TPM_ALG_SHA256);
            tpm::put_2b(&mut params, &vec![0; ob]);
            tpm::put_2b(&mut params, &vec![0; ob]);
            let expected = tpm::success_response(&[], &params, 1);
            let base = tpm::success_parameters_at(0, 1);
            let mut mask = mask_range(expected.len(), base + 6, base + 6 + ob);
            for byte in mask.iter_mut().skip(base + 8 + ob).take(ob) {
                *byte = 0;
            }
            let mut spec = ClassSpec::new(sign_command(&digest, Scheme::Null), expected);
            spec.mask = mask;
            let (x, y) = c.encode(&q);
            spec.check = Some(Check::EccSignature {
                scheme: scheme.name().into(),
                curve,
                hash: HashAlg::Sha256,
                public_x: x,
                public_y: y,
                digest,
            });
            spec.setup = vec![Step::new("LoadExternal", load).creates(Creates::Object)];
            spec.public = Some(point_of(curve, &q));
            Ok(spec)
        }
        Scenario::RsaDecrypt(bits, padding) => {
            let key = bits.key();
            let k = bits.bytes();
            let (ciphertext, outcome) = match padding {
                RsaPadding::Raw => {
                    let m = key.private(input).ok_or("ciphertext out of range")?;
                    (input.to_vec(), Encoded::Valid(m))
                }
                RsaPadding::Rsaes => {
                    let (em, outcome) = encode_pkcs1_case(k, input, space);
                    (
                        key.public(&em).ok_or("encoded message out of range")?,
                        outcome,
                    )
                }
                RsaPadding::OaepSha1
                | RsaPadding::OaepSha256
                | RsaPadding::OaepSha384
                | RsaPadding::OaepSha512 => {
                    let hash = padding.oaep_hash().unwrap();
                    let (em, outcome) = encode_oaep_case(hash, &[], k, input);
                    (
                        key.public(&em).ok_or("encoded message out of range")?,
                        outcome,
                    )
                }
            };
            let scheme = match padding {
                RsaPadding::Raw => Scheme::Null,
                RsaPadding::Rsaes => Scheme::NoHash(TPM_ALG_RSAES),
                _ => Scheme::WithHash(TPM_ALG_OAEP, padding.oaep_hash().unwrap().alg_id()),
            };
            let mut parameters = Vec::new();
            tpm::put_2b(&mut parameters, &ciphertext);
            scheme.marshal(&mut parameters);
            tpm::put_2b(&mut parameters, &[]);
            let command = tpm::build_command(tpm::TPM_CC_RSA_DECRYPT, &[0], &[&[]], &parameters);
            let expected = match outcome {
                Encoded::Valid(message) => {
                    let mut out = Vec::new();
                    tpm::put_2b(&mut out, &message);
                    tpm::success_response(&[], &out, 1)
                }
                Encoded::Invalid => tpm::error_response(tpm::TPM_RC_VALUE),
            };
            Ok(ClassSpec::new(
                Step::new("RSA_Decrypt", command.bytes).handle_at(10, HandleRef::Shared(0)),
                expected,
            ))
        }
        Scenario::RsaSign(bits, scheme) => {
            let key = bits.key();
            let k = bits.bytes();
            let tpm_scheme = match scheme {
                RsaSigScheme::Rsassa => TPM_ALG_RSASSA,
                RsaSigScheme::Rsapss => TPM_ALG_RSAPSS,
            };
            let mut step = sign_command(input, Scheme::WithHash(tpm_scheme, TPM_ALG_SHA256));
            step.handles = vec![(10, HandleRef::Shared(0))];
            let signature = match scheme {
                RsaSigScheme::Rsassa => key
                    .private(&pkcs1_sign_encode(HashAlg::Sha256, input, k))
                    .ok_or("encoding out of range")?,
                RsaSigScheme::Rsapss => vec![0; k],
            };
            let mut params = Vec::new();
            tpm::put_u16(&mut params, tpm_scheme);
            tpm::put_u16(&mut params, TPM_ALG_SHA256);
            tpm::put_2b(&mut params, &signature);
            let expected = tpm::success_response(&[], &params, 1);
            let base = tpm::success_parameters_at(0, 1);
            let mut spec = ClassSpec::new(step, expected.clone());
            if scheme == RsaSigScheme::Rsapss {
                spec.mask = mask_range(expected.len(), base + 6, base + 6 + k);
                spec.check = Some(Check::RsaPss {
                    bits,
                    hash: HashAlg::Sha256,
                    digest: input.to_vec(),
                });
            }
            Ok(spec)
        }
        Scenario::SaltedSession(kind) => {
            let (secret, valid, salt_material) = match kind {
                AsymKind::Rsa(bits) => {
                    let key = bits.key();
                    let (em, outcome) =
                        encode_oaep_case(HashAlg::Sha256, SALT_LABEL, bits.bytes(), input);
                    let salt = match &outcome {
                        Encoded::Valid(message) => message.clone(),
                        Encoded::Invalid => Vec::new(),
                    };
                    (
                        key.public(&em).ok_or("encoded salt out of range")?,
                        matches!(outcome, Encoded::Valid(_)),
                        salt,
                    )
                }
                AsymKind::Ecc(curve) => {
                    let c = curve.curve();
                    let ephemeral = from_be(&input[1..]);
                    let mut point = c.mul_g(&ephemeral).ok_or("ephemeral is infinity")?;
                    let off_curve = input[0] % 2 == 1;
                    if off_curve {
                        point.y = (&point.y + 1u32) % &c.p;
                    }
                    let salt = if off_curve {
                        Vec::new()
                    } else {
                        let d = from_be(&salt_key_scalar(curve));
                        let key_point = c.mul_g(&d).ok_or("salt key is infinity")?;
                        let z = c
                            .mul(&ephemeral, &key_point)
                            .ok_or("ECDH secret is infinity")?;
                        crate::oracle::kdf::kdfe(
                            HashAlg::Sha256,
                            &c.encode(&z).0,
                            SALT_LABEL,
                            &c.encode(&point).0,
                            &c.encode(&key_point).0,
                            HashAlg::Sha256.size() * 8,
                        )
                    };
                    (ecc_point_bytes(curve, &point), !off_curve, salt)
                }
            };
            let mut parameters = Vec::new();
            tpm::put_2b(&mut parameters, &NONCE_CALLER);
            tpm::put_2b(&mut parameters, &secret);
            parameters.push(tpm::TPM_SE_HMAC);
            tpm::put_u16(&mut parameters, TPM_ALG_NULL);
            tpm::put_u16(&mut parameters, TPM_ALG_SHA256);
            let command = tpm::build_command(
                tpm::TPM_CC_START_AUTH_SESSION,
                &[0, TPM_RH_NULL],
                &[],
                &parameters,
            );
            let step = Step::new("StartAuthSession", command.bytes)
                .handle_at(10, HandleRef::Shared(0))
                .creates(Creates::Session);
            if valid {
                let mut params = Vec::new();
                tpm::put_2b(&mut params, &[0; 32]);
                let expected = tpm::success_response(&[tpm::HMAC_SESSION_FIRST], &params, 0);
                let mask = mask_range(expected.len(), 16, 16 + 32);
                let mut spec = ClassSpec::new(step, expected);
                spec.mask = mask;
                spec.check = Some(Check::SessionNonce { size: 32 });
                spec.validation = Some(salted_session_validation(kind, &salt_material)?);
                spec.post = Some(Post {
                    step: Step::new("FlushContext session", tpm::flush_context(0))
                        .handle_at(10, HandleRef::NextSession),
                    expected: tpm::flush_response(),
                });
                Ok(spec)
            } else {
                Ok(ClassSpec::new(
                    step,
                    tpm::error_response(tpm::parameter_error(tpm::TPM_RC_VALUE, 2)),
                ))
            }
        }
        _ => unreachable!(),
    }
}

pub fn doc(scenario: Scenario) -> ScenarioDoc {
    let curve = curve_of(scenario);
    match scenario {
        Scenario::Ecdh(curve) => ScenarioDoc {
            harness: COMMAND_LEVEL.into(),
            entry_point: format!("TPM2_ECDH_ZGen (0x154) with one password session on a {} key loaded by TPM2_LoadExternal (userWithAuth|noDA|decrypt)", curve.name()),
            secret: "the private scalar d of the loaded key".into(),
            attacker_inputs: format!("private scalars of the two classes ({} bytes, 1 <= d < n)", curve.key_bytes()),
            observable_outputs: "response code and shared point d*Q_peer (fixed-width coordinates)".into(),
            classes: "two scalars loaded as two transient objects; each class sends ECDH_ZGen on its own handle".into(),
            fixed: "peer point (SHA-512 derived scalar times G), curve, template, session encoding, command length".into(),
            timed_region: "one TPMLIB_Process call of ECDH_ZGen; Startup, loading and warm-up are outside".into(),
            correctness: "shared point computed by the harness's own Jacobian arithmetic (cross-checked against the p521 crate and a published P-256 vector); exact response match on every execution".into(),
            interpretation: "a signal shows the ECDH point multiplication time depends on the private scalar or on public values derived from it (public key, shared point, handle)".into(),
            randomized: false,
        },
        Scenario::EccSign(scheme, curve) => ScenarioDoc {
            harness: COMMAND_LEVEL.into(),
            entry_point: format!("TPM2_Sign (0x15D) with a {} {} key (scheme {}+SHA-256) loaded by TPM2_LoadExternal, NULL hashcheck ticket", curve.name(), scheme.name(), scheme.name()),
            secret: "the private scalar d of the signing key; the per-signature nonce is secret and random".into(),
            attacker_inputs: "private scalars of the two classes; the digest is fixed".into(),
            observable_outputs: "response code, signature (r, s) padded to the order width".into(),
            classes: "two keys loaded in one TPM; both sign the same digest with fresh random nonces".into(),
            fixed: "digest SHA-256(\"tpms-timing-tests sign message v1\"), curve, scheme, response length".into(),
            timed_region: "one TPMLIB_Process call of Sign, including nonce generation from the TPM DRBG".into(),
            correctness: "response code, header and lengths compared on every execution with r and s masked; every functional check verifies the signature independently (ECDSA/EC-Schnorr/SM2 verifier written from the TCG and GM/T definitions)".into(),
            interpretation: "nonces are drawn independently for both classes, so nonce-dependent timing averages out between classes; a reproducible signal points to a dependence on the long-term key".into(),
            randomized: true,
        },
        Scenario::RsaDecrypt(bits, padding) => ScenarioDoc {
            harness: COMMAND_LEVEL.into(),
            entry_point: format!("TPM2_RSA_Decrypt (0x159) with a fixed {}-bit key loaded by TPM2_LoadExternal, inScheme {}", bits.bits(), padding.name()),
            secret: "the RSA private key and the plaintext/padding structure hidden in each ciphertext".into(),
            attacker_inputs: if padding == RsaPadding::Raw { "the ciphertext integer c < n".into() } else if padding == RsaPadding::Rsaes { "a kind byte (legacy alias space: valid or one of four malformed encodings; versioned high-bit selectors 0x85/0x86 select separator-boundary encodings) and 48 bytes of material from which the encoded message is built and encrypted with the public key".into() } else { "a kind byte (valid or one of four malformed encodings) and 48 bytes of material from which the encoded message is built and encrypted with the public key".into() },
            observable_outputs: "plaintext (32-byte message, or k bytes for raw) or the bare TPM_RC_VALUE error".into(),
            classes: "two ciphertexts decrypted with the same key".into(),
            fixed: "key, scheme, empty label, ciphertext length k".into(),
            timed_region: "one TPMLIB_Process call of RSA_Decrypt".into(),
            correctness: "expected plaintext or error derived from the harness's own OAEP / PKCS#1 v1.5 decoder applied to the encoded message it built; exact response match".into(),
            interpretation: "pairs with the same response code isolate hidden padding-validation paths; valid-versus-invalid pairs have visibly different outcomes and are labelled as such".into(),
            randomized: false,
        },
        Scenario::RsaSign(bits, scheme) => ScenarioDoc {
            harness: COMMAND_LEVEL.into(),
            entry_point: format!("TPM2_Sign (0x15D) with a fixed {}-bit RSA key, inScheme {}+SHA-256", bits.bits(), scheme.name()),
            secret: "the RSA private key".into(),
            attacker_inputs: "the 32-byte digest of each class".into(),
            observable_outputs: "signature".into(),
            classes: "two digests signed with the same key".into(),
            fixed: "key, scheme, signature length".into(),
            timed_region: "one TPMLIB_Process call of Sign (PSS: including salt generation)".into(),
            correctness: if scheme == RsaSigScheme::Rsassa { "exact PKCS#1 v1.5 signature computed by the harness".into() } else { "signature masked per call; every functional check verifies PSS independently".into() },
            interpretation: "the digest is a public input, so a signal means the private-key operation time depends on the (public) message representative combined with the secret key".into(),
            randomized: scheme == RsaSigScheme::Rsapss,
        },
        _ => ScenarioDoc {
            harness: COMMAND_LEVEL.into(),
            entry_point: format!("TPM2_StartAuthSession (0x176), HMAC session salted to a {} key loaded by TPM2_LoadExternal (unrestricted decrypt), then FlushContext of the new session", match scenario { Scenario::SaltedSession(kind) => kind.name(), _ => "" }),
            secret: if curve.is_some() { "the salt key's private scalar and the ECDH secret Z it shares with the ephemeral point; the derived salt (KDFe) and session key (KDFa)".into() } else { "the RSA private key, the OAEP-encoded salt (MGF1) and the session key derived with KDFa".into() },
            attacker_inputs: if curve.is_some() { "a kind byte (valid or off-curve point) and the ephemeral scalar defining the encrypted salt point".into() } else { "a kind byte (valid or one of four malformed OAEP encodings) and 48 bytes of material defining the salt and OAEP seed".into() },
            observable_outputs: "session handle and random nonceTPM, or TPM_RC_VALUE on encryptedSalt".into(),
            classes: "two encrypted salts presented to the same key".into(),
            fixed: "key, nonceCaller, session type, authHash SHA-256".into(),
            timed_region: "StartAuthSession plus, for successful classes, FlushContext of the created session (needed to keep the TPM state repeatable; identical for both classes)".into(),
            correctness: "success or error decided by the harness's own OAEP decoder / point construction; nonceTPM masked, session handle and lengths exact".into(),
            interpretation: "covers secret decryption (OAEP with MGF1, or ECDH+KDFe) followed by KDFa; valid-versus-invalid pairs are visibly different outcomes".into(),
            randomized: true,
        },
    }
}

pub(crate) fn apply_rsaes_profile(
    scenario: Scenario,
    pair: &InputPair,
    built: &mut Built,
    profile: crate::expectation::RsaesProfile,
) -> Result<(), String> {
    let Scenario::RsaDecrypt(bits, RsaPadding::Rsaes) = scenario else {
        return Ok(());
    };
    if profile != crate::expectation::RsaesProfile::OpenSslImplicitV1 {
        return Ok(());
    }
    for (class, spec) in built.classes.iter_mut().enumerate() {
        let (em, outcome) = encode_pkcs1_case(bits.bytes(), pair.class(class), pair.selector_space);
        if matches!(outcome, Encoded::Invalid) {
            let ciphertext = bits
                .key()
                .public(&em)
                .ok_or("encoded message out of range")?;
            let message = crate::oracle::rsa::implicit_rejection(bits.key(), &ciphertext);
            spec.expected = tpm::success_response(&[], &tpm::sized(&message), 1);
        }
    }
    Ok(())
}
