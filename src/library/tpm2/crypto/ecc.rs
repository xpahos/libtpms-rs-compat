// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/BnEccConstants.c
// - libtpms/src/tpm2/crypto/openssl/CryptEccKeyExchange.c
// - libtpms/src/tpm2/crypto/openssl/CryptEccMain.c
// - libtpms/src/tpm2/crypto/openssl/CryptEccSignature.c
//
// Original upstream authors and copyright notices:
// Written by Ken Goldman
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corp. and others, 2023
// (c) Copyright IBM Corp. and others, 2016 - 2023
// (c) Copyright IBM Corp. and others, 2016 - 2024
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use super::ossl::{EccAffine, EccCurve, EccScalar};
use super::rand_state::SeededRand;

pub(in crate::library::tpm2) const TPM_ECC_NIST_P192: u16 = 0x0001;
pub(in crate::library::tpm2) const TPM_ECC_NIST_P224: u16 = 0x0002;
pub(in crate::library::tpm2) const TPM_ECC_NIST_P256: u16 = 0x0003;
pub(in crate::library::tpm2) const TPM_ECC_NIST_P384: u16 = 0x0004;
pub(in crate::library::tpm2) const TPM_ECC_NIST_P521: u16 = 0x0005;
pub(in crate::library::tpm2) const TPM_ECC_BN_P256: u16 = 0x0010;
pub(in crate::library::tpm2) const TPM_ECC_BN_P638: u16 = 0x0011;
pub(in crate::library::tpm2) const TPM_ECC_SM2_P256: u16 = 0x0020;

const TPM_ALG_NULL: u16 = 0x0010;
const TPM_ALG_SHA256: u16 = 0x000b;
const TPM_ALG_SHA384: u16 = 0x000c;
const TPM_ALG_SHA512: u16 = 0x000d;
const TPM_ALG_SM3_256: u16 = 0x0012;
const TPM_ALG_KDF1_SP800_56A: u16 = 0x0020;

pub(super) struct CurveSpec {
    pub(super) curve_id: u16,
    pub(super) key_size_bits: u16,
    kdf_scheme: u16,
    kdf_hash: u16,
    pub(super) prime: &'static str,
    pub(super) a: &'static str,
    pub(super) b: &'static str,
    pub(super) generator_x: &'static str,
    pub(super) generator_y: &'static str,
    pub(super) order: &'static str,
}

pub(super) const NIST_P192: CurveSpec = CurveSpec {
    curve_id: TPM_ECC_NIST_P192,
    key_size_bits: 192,
    kdf_scheme: TPM_ALG_KDF1_SP800_56A,
    kdf_hash: TPM_ALG_SHA256,
    prime: "fffffffffffffffffffffffffffffffeffffffffffffffff",
    a: "fffffffffffffffffffffffffffffffefffffffffffffffc",
    b: "64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",
    generator_x: "188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
    generator_y: "07192b95ffc8da78631011ed6b24cdd573f977a11e794811",
    order: "ffffffffffffffffffffffff99def836146bc9b1b4d22831",
};

pub(super) const NIST_P224: CurveSpec = CurveSpec {
    curve_id: TPM_ECC_NIST_P224,
    key_size_bits: 224,
    kdf_scheme: TPM_ALG_KDF1_SP800_56A,
    kdf_hash: TPM_ALG_SHA256,
    prime: "ffffffffffffffffffffffffffffffff000000000000000000000001",
    a: "fffffffffffffffffffffffffffffffefffffffffffffffffffffffe",
    b: "b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
    generator_x: "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
    generator_y: "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34",
    order: "ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d",
};

pub(super) const NIST_P256: CurveSpec = CurveSpec {
    curve_id: TPM_ECC_NIST_P256,
    key_size_bits: 256,
    kdf_scheme: TPM_ALG_KDF1_SP800_56A,
    kdf_hash: TPM_ALG_SHA256,
    prime: "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    a: "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
    b: "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    generator_x: "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    generator_y: "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    order: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
};

pub(super) const NIST_P384: CurveSpec = CurveSpec {
    curve_id: TPM_ECC_NIST_P384,
    key_size_bits: 384,
    kdf_scheme: TPM_ALG_KDF1_SP800_56A,
    kdf_hash: TPM_ALG_SHA384,
    prime: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
            ffffffff0000000000000000ffffffff",
    a: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
        ffffffff0000000000000000fffffffc",
    b: "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a\
        c656398d8a2ed19d2a85c8edd3ec2aef",
    generator_x: "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38\
                  5502f25dbf55296c3a545e3872760ab7",
    generator_y: "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0\
                  0a60b1ce1d7e819d7a431d7c90ea0e5f",
    order: "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf\
            581a0db248b0a77aecec196accc52973",
};

pub(super) const NIST_P521: CurveSpec = CurveSpec {
    curve_id: TPM_ECC_NIST_P521,
    key_size_bits: 521,
    kdf_scheme: TPM_ALG_KDF1_SP800_56A,
    kdf_hash: TPM_ALG_SHA512,
    prime: "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
            ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
            ffff",
    a: "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
        ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
        fffc",
    b: "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef1\
        09e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b50\
        3f00",
    generator_x: "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d\
                  3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5\
                  bd66",
    generator_y: "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e\
                  662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd1\
                  6650",
    order: "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
            fffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138\
            6409",
};

pub(super) const BN_P256: CurveSpec = CurveSpec {
    curve_id: TPM_ECC_BN_P256,
    key_size_bits: 256,
    kdf_scheme: TPM_ALG_NULL,
    kdf_hash: TPM_ALG_NULL,
    prime: "fffffffffffcf0cd46e5f25eee71a49f0cdc65fb12980a82d3292ddbaed33013",
    a: "00",
    b: "03",
    generator_x: "01",
    generator_y: "02",
    order: "fffffffffffcf0cd46e5f25eee71a49e0cdc65fb1299921af62d536cd10b500d",
};

pub(super) const BN_P638: CurveSpec = CurveSpec {
    curve_id: TPM_ECC_BN_P638,
    key_size_bits: 638,
    kdf_scheme: TPM_ALG_NULL,
    kdf_hash: TPM_ALG_NULL,
    prime: "23fffffdc000000d7fffffb8000001d3fffff942d000165e3fff94870000d52f\
            fffdd0e00008de55c00086520021e55bfffff51ffff4eb800000004c80015acd\
            ffffffffffffece00000000000000067",
    a: "00",
    b: "0101",
    generator_x: "23fffffdc000000d7fffffb8000001d3fffff942d000165e3fff94870000d52f\
                  fffdd0e00008de55c00086520021e55bfffff51ffff4eb800000004c80015acd\
                  ffffffffffffece00000000000000066",
    generator_y: "10",
    order: "23fffffdc000000d7fffffb8000001d3fffff942d000165e3fff94870000d52f\
            fffdd0e00008de55600086550021e555fffff54ffff4eac000000049800154d9\
            ffffffffffffeda00000000000000061",
};

pub(super) const SM2_P256: CurveSpec = CurveSpec {
    curve_id: TPM_ECC_SM2_P256,
    key_size_bits: 256,
    kdf_scheme: TPM_ALG_KDF1_SP800_56A,
    kdf_hash: TPM_ALG_SM3_256,
    prime: "fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff",
    a: "fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc",
    b: "28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93",
    generator_x: "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
    generator_y: "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
    order: "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123",
};

const ECC_CURVES: [&CurveSpec; 8] = [
    &NIST_P192, &NIST_P224, &NIST_P256, &NIST_P384, &NIST_P521, &BN_P256, &BN_P638, &SM2_P256,
];

fn spec(curve_id: u16) -> Option<&'static CurveSpec> {
    ECC_CURVES
        .iter()
        .copied()
        .find(|entry| entry.curve_id == curve_id)
}

pub(in crate::library::tpm2) fn is_compiled_curve(curve_id: u16) -> bool {
    spec(curve_id).is_some()
}

pub(in crate::library::tpm2) fn compiled_curves() -> impl Iterator<Item = u16> {
    ECC_CURVES.iter().map(|entry| entry.curve_id)
}

pub(in crate::library::tpm2) fn curve_key_size_bits(curve_id: u16) -> Option<u16> {
    spec(curve_id).map(|entry| entry.key_size_bits)
}

pub(in crate::library::tpm2) struct CurveDetail {
    pub(in crate::library::tpm2) curve_id: u16,
    pub(in crate::library::tpm2) key_size_bits: u16,
    pub(in crate::library::tpm2) kdf_scheme: u16,
    pub(in crate::library::tpm2) kdf_hash: u16,
    pub(in crate::library::tpm2) sign_scheme: u16,
    pub(in crate::library::tpm2) prime: Vec<u8>,
    pub(in crate::library::tpm2) a: Vec<u8>,
    pub(in crate::library::tpm2) b: Vec<u8>,
    pub(in crate::library::tpm2) generator_x: Vec<u8>,
    pub(in crate::library::tpm2) generator_y: Vec<u8>,
    pub(in crate::library::tpm2) order: Vec<u8>,
    pub(in crate::library::tpm2) cofactor: Vec<u8>,
}

fn hex_digit(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

fn minimal_bytes(text: &str) -> Vec<u8> {
    let digits = text.as_bytes();
    let mut bytes = Vec::with_capacity(digits.len() / 2 + 1);
    let mut index = digits.len() % 2;
    if index == 1 {
        bytes.push(hex_digit(digits[0]));
    }
    while index < digits.len() {
        bytes.push((hex_digit(digits[index]) << 4) | hex_digit(digits[index + 1]));
        index += 2;
    }
    let significant = bytes
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(bytes.len());
    if significant == bytes.len() {
        return vec![0u8];
    }
    bytes.split_off(significant)
}

fn padded_bytes(text: &str, width: usize) -> Vec<u8> {
    let value = minimal_bytes(text);
    if value == [0u8] || value.len() >= width {
        return value;
    }
    let mut padded = vec![0u8; width - value.len()];
    padded.extend_from_slice(&value);
    padded
}

pub(in crate::library::tpm2) fn curve_detail(curve_id: u16) -> Option<CurveDetail> {
    let entry = spec(curve_id)?;
    let prime = minimal_bytes(entry.prime);
    let width = prime.len();
    Some(CurveDetail {
        curve_id,
        key_size_bits: entry.key_size_bits,
        kdf_scheme: entry.kdf_scheme,
        kdf_hash: entry.kdf_hash,
        sign_scheme: TPM_ALG_NULL,
        a: padded_bytes(entry.a, width),
        b: padded_bytes(entry.b, width),
        generator_x: padded_bytes(entry.generator_x, width),
        generator_y: padded_bytes(entry.generator_y, width),
        order: minimal_bytes(entry.order),
        cofactor: vec![0x01],
        prime,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) enum EccKeyError {
    Curve,
    NoResult,
    Failure,
}

pub(in crate::library::tpm2) struct EccKeyMaterial {
    pub(in crate::library::tpm2) x: Vec<u8>,
    pub(in crate::library::tpm2) y: Vec<u8>,
    pub(in crate::library::tpm2) private: Vec<u8>,
}

#[cfg(test)]
pub(in crate::library::tpm2) fn generate_private_scalar(
    curve: &EccCurve,
    rand: &mut SeededRand,
) -> Result<EccScalar, crate::types::TpmResult> {
    let draw = super::SecretBytes(rand.random_bytes(curve.order_bytes() + 8)?);
    crate::library::tpm2::memcheck::secret(&draw.0);
    curve
        .scalar_from_extra_bits(&draw.0)
        .ok_or(crate::library::constants::TPM_RC_FAILURE)
}

pub(in crate::library::tpm2) struct EccEphemeral {
    pub(in crate::library::tpm2) x: Vec<u8>,
    pub(in crate::library::tpm2) y: Vec<u8>,
    pub(in crate::library::tpm2) scalar: EccScalar,
}

pub(in crate::library::tpm2) fn generate_ecc_ephemeral(
    curve_id: u16,
    rand: &mut SeededRand,
) -> Result<EccEphemeral, EccKeyError> {
    let curve = EccCurve::lookup(curve_id).ok_or(EccKeyError::Curve)?;
    let draw = super::SecretBytes(
        rand.random_bytes(curve.order_bytes() + 8)
            .map_err(|_| EccKeyError::NoResult)?,
    );
    #[cfg(test)]
    {
        crate::library::tpm2::memcheck::secret(&draw.0);
        crate::library::tpm2::memcheck::observe("ephemeral-draw", &draw.0);
    }
    let scalar = curve
        .scalar_from_extra_bits(&draw.0)
        .ok_or(EccKeyError::Failure)?;
    drop(draw);
    let EccAffine { x, y } = curve
        .mul_generator_checked(&scalar)
        .map_err(|error| match error {
            super::SharedPointError::Infinity => EccKeyError::NoResult,
            super::SharedPointError::OffCurve | super::SharedPointError::Backend => {
                EccKeyError::Failure
            }
        })?;
    Ok(EccEphemeral { x, y, scalar })
}

pub(in crate::library::tpm2) fn generate_ecc_key(
    curve_id: u16,
    rand: &mut SeededRand,
) -> Result<EccKeyMaterial, EccKeyError> {
    let curve = EccCurve::lookup(curve_id).ok_or(EccKeyError::Curve)?;
    let EccEphemeral { x, y, scalar } = generate_ecc_ephemeral(curve_id, rand)?;
    let private = scalar
        .export_bytes(curve.field_bytes())
        .ok_or(EccKeyError::Failure)?;
    #[cfg(test)]
    {
        for coordinate in [&x, &y] {
            crate::library::tpm2::memcheck::observe("public-key", coordinate);
        }
        crate::library::tpm2::memcheck::observe("exported-private", &private);
    }
    Ok(EccKeyMaterial { x, y, private })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::crypto::ossl::BigUint;

    const ALL_CURVES: [u16; 8] = [
        TPM_ECC_NIST_P192,
        TPM_ECC_NIST_P224,
        TPM_ECC_NIST_P256,
        TPM_ECC_NIST_P384,
        TPM_ECC_NIST_P521,
        TPM_ECC_BN_P256,
        TPM_ECC_BN_P638,
        TPM_ECC_SM2_P256,
    ];

    fn rand(label: &[u8]) -> SeededRand {
        SeededRand::instantiate(&[0x91; 64], b"ECC", label, &[], 1, false)
            .expect("a non-empty derivation input")
    }

    fn curve(curve_id: u16) -> EccCurve {
        EccCurve::lookup(curve_id).expect("a compiled curve")
    }

    #[test]
    fn compiled_curve_identifier_recognition() {
        for curve_id in ALL_CURVES {
            assert!(is_compiled_curve(curve_id), "curve {curve_id:#06x}");
            assert_eq!(curve(curve_id).curve_id(), curve_id);
        }
        assert_eq!(compiled_curves().collect::<Vec<_>>(), ALL_CURVES);
    }

    #[test]
    fn uncompiled_curve_no_parameters() {
        for curve_id in [0x0000u16, 0x0006, 0x000f, 0x0012, 0x0021, 0xffff] {
            assert!(!is_compiled_curve(curve_id), "curve {curve_id:#06x}");
            assert!(EccCurve::lookup(curve_id).is_none());
            assert!(curve_key_size_bits(curve_id).is_none());
            assert!(curve_detail(curve_id).is_none());
        }
    }

    #[test]
    fn key_size_vendored_metadata_match() {
        for (curve_id, bits, field_bytes) in [
            (TPM_ECC_NIST_P192, 192u16, 24usize),
            (TPM_ECC_NIST_P224, 224, 28),
            (TPM_ECC_NIST_P256, 256, 32),
            (TPM_ECC_NIST_P384, 384, 48),
            (TPM_ECC_NIST_P521, 521, 66),
            (TPM_ECC_BN_P256, 256, 32),
            (TPM_ECC_BN_P638, 638, 80),
            (TPM_ECC_SM2_P256, 256, 32),
        ] {
            assert_eq!(curve_key_size_bits(curve_id), Some(bits));
            assert_eq!(curve(curve_id).field_bytes(), field_bytes);
            assert_eq!(curve(curve_id).order_bytes(), field_bytes);
        }
    }

    #[test]
    fn hex_parser_odd_length_minimal_encoding() {
        assert_eq!(minimal_bytes("03"), [0x03]);
        assert_eq!(minimal_bytes("101"), [0x01, 0x01]);
        assert_eq!(minimal_bytes("00"), [0x00]);
        assert_eq!(minimal_bytes("000102"), [0x01, 0x02]);
        assert_eq!(padded_bytes("0102", 4), [0x00, 0x00, 0x01, 0x02]);
        assert_eq!(padded_bytes("00", 4), [0x00]);
    }

    fn big(bytes: &[u8]) -> BigUint {
        BigUint::from_be_bytes(bytes).unwrap()
    }

    #[test]
    fn backend_group_matches_the_tpm_parameters() {
        for curve_id in ALL_CURVES {
            let curve = curve(curve_id);
            let detail = curve_detail(curve_id).expect("a detail");
            assert_eq!(
                big(&curve.order()),
                big(&detail.order),
                "curve {curve_id:#06x}"
            );
            assert_eq!(big(&curve.field_prime()), big(&detail.prime));
            assert_eq!(curve.order_bits(), big(&detail.order).bit_len());
            assert_eq!(big(&detail.prime).byte_len(), curve.field_bytes());
            assert!(curve.on_curve(&detail.generator_x, &detail.generator_y));
            let one = curve.scalar_from_u64(1).unwrap();
            let generator = curve.mul_generator(&one).expect("the generator");
            assert_eq!(big(&generator.x), big(&detail.generator_x));
            assert_eq!(big(&generator.y), big(&detail.generator_y));
            let mut off_curve = detail.generator_y.clone();
            let last = off_curve.len() - 1;
            off_curve[last] ^= 1;
            assert!(!curve.on_curve(&detail.generator_x, &off_curve));
        }
    }

    #[test]
    fn curve_prime_and_order_bit_length() {
        for curve_id in ALL_CURVES {
            let detail = curve_detail(curve_id).expect("a detail");
            let bits = usize::from(curve_key_size_bits(curve_id).expect("a curve"));
            assert_eq!(big(&detail.prime).bit_len(), bits, "curve {curve_id:#06x}");
            assert!(big(&detail.order).bit_len() <= bits + 1);
        }
    }

    #[test]
    fn generated_key_on_curve_scalar_match() {
        for curve_id in ALL_CURVES {
            let key = generate_ecc_key(curve_id, &mut rand(b"key")).expect("a key");
            let curve = curve(curve_id);
            assert_eq!(key.x.len(), curve.field_bytes());
            assert_eq!(key.y.len(), curve.field_bytes());
            assert_eq!(key.private.len(), curve.field_bytes());
            assert!(curve.on_curve(&key.x, &key.y), "curve {curve_id:#06x}");
            assert!(curve.scalar_in_range(&key.private));
            let doubled = curve
                .mul_generator(
                    &curve
                        .scalar(&key.private)
                        .unwrap()
                        .add(&curve.scalar(&key.private).unwrap())
                        .unwrap(),
                )
                .unwrap();
            let added = curve
                .mul_add(
                    &curve.public_scalar_from_u64(1).unwrap(),
                    Some((&key.x, &key.y)),
                    &curve.public_scalar_from_u64(1).unwrap(),
                    (&key.x, &key.y),
                )
                .unwrap();
            assert_eq!(doubled, added, "curve {curve_id:#06x}: [2d]G = Q + Q");
        }
    }

    #[test]
    fn generated_key_determinism() {
        let first = generate_ecc_key(TPM_ECC_NIST_P384, &mut rand(b"same")).expect("a key");
        let second = generate_ecc_key(TPM_ECC_NIST_P384, &mut rand(b"same")).expect("a key");
        assert_eq!(first.x, second.x);
        assert_eq!(first.y, second.y);
        assert_eq!(first.private, second.private);
    }

    #[test]
    fn generator_state_key_distinction() {
        let first = generate_ecc_key(TPM_ECC_NIST_P384, &mut rand(b"one")).expect("a key");
        let second = generate_ecc_key(TPM_ECC_NIST_P384, &mut rand(b"two")).expect("a key");
        assert_ne!(first.private, second.private);
        assert_ne!(first.x, second.x);
    }

    #[test]
    fn unsupported_curve_no_key() {
        assert_eq!(
            generate_ecc_key(0x0007, &mut rand(b"bad")).err(),
            Some(EccKeyError::Curve)
        );
    }

    #[test]
    fn private_scalar_sixty_four_extra_bits_draw() {
        for curve_id in ALL_CURVES {
            let curve = curve(curve_id);
            let order = big(&curve.order());
            let mut scalar_state = rand(b"extra");
            let scalar = generate_private_scalar(&curve, &mut scalar_state).unwrap();
            let mut byte_state = rand(b"extra");
            let raw = byte_state
                .random_integer(curve.order_bytes() * 8 + 64)
                .unwrap();
            let expected = raw
                .rem(&order.sub_u64(1).unwrap())
                .unwrap()
                .add_u64(1)
                .unwrap();
            assert_eq!(
                big(&scalar.to_bytes(curve.order_bytes()).unwrap()),
                expected,
                "curve {curve_id:#06x}"
            );
            assert_eq!(
                scalar_state.random_bytes(16).unwrap(),
                byte_state.random_bytes(16).unwrap(),
                "curve {curve_id:#06x} draws exactly the reference byte count"
            );
        }
    }
}
