use crate::types::TpmResult;

use super::bignum::BigUint;
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

pub(in crate::library::tpm2) struct EccCurve {
    pub(in crate::library::tpm2) curve_id: u16,
    pub(in crate::library::tpm2) key_size_bits: u16,
    kdf_scheme: u16,
    kdf_hash: u16,
    prime: &'static str,
    a: &'static str,
    b: &'static str,
    generator_x: &'static str,
    generator_y: &'static str,
    order: &'static str,
}

static ECC_CURVES: &[EccCurve] = &[
    EccCurve {
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
    },
    EccCurve {
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
    },
    EccCurve {
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
    },
    EccCurve {
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
    },
    EccCurve {
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
    },
    EccCurve {
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
    },
    EccCurve {
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
    },
    EccCurve {
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
    },
];

fn parse_hex(text: &str) -> BigUint {
    let mut bytes = Vec::with_capacity(text.len() / 2 + 1);
    let digits: Vec<u8> = text
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    let odd = digits.len() % 2;
    let mut index = 0;
    if odd == 1 {
        bytes.push(hex_digit(digits[0]));
        index = 1;
    }
    while index < digits.len() {
        bytes.push((hex_digit(digits[index]) << 4) | hex_digit(digits[index + 1]));
        index += 2;
    }
    BigUint::from_be_bytes(&bytes)
}

fn hex_digit(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

pub(in crate::library::tpm2) struct CurveParameters {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(in crate::library::tpm2) curve_id: u16,
    pub(in crate::library::tpm2) key_size_bytes: usize,
    pub(in crate::library::tpm2) prime: BigUint,
    pub(in crate::library::tpm2) a: BigUint,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(in crate::library::tpm2) b: BigUint,
    pub(in crate::library::tpm2) generator_x: BigUint,
    pub(in crate::library::tpm2) generator_y: BigUint,
    pub(in crate::library::tpm2) order: BigUint,
}

pub(in crate::library::tpm2) fn curve_parameters(curve_id: u16) -> Option<CurveParameters> {
    let curve = ECC_CURVES.iter().find(|entry| entry.curve_id == curve_id)?;
    Some(CurveParameters {
        curve_id,
        key_size_bytes: usize::from(curve.key_size_bits).div_ceil(8),
        prime: parse_hex(curve.prime),
        a: parse_hex(curve.a),
        b: parse_hex(curve.b),
        generator_x: parse_hex(curve.generator_x),
        generator_y: parse_hex(curve.generator_y),
        order: parse_hex(curve.order),
    })
}

pub(in crate::library::tpm2) fn is_compiled_curve(curve_id: u16) -> bool {
    ECC_CURVES.iter().any(|entry| entry.curve_id == curve_id)
}

pub(in crate::library::tpm2) fn compiled_curves() -> impl Iterator<Item = u16> {
    ECC_CURVES.iter().map(|entry| entry.curve_id)
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

fn minimal_bytes(value: &BigUint) -> Vec<u8> {
    if value.is_zero() {
        return vec![0u8];
    }
    value
        .to_be_bytes(value.byte_len())
        .expect("a value fits its own byte length")
}

fn padded_bytes(value: &BigUint, width: usize) -> Vec<u8> {
    if value.is_zero() {
        return vec![0u8];
    }
    value
        .to_be_bytes(width.max(value.byte_len()))
        .expect("a value fits the requested width")
}

pub(in crate::library::tpm2) fn curve_detail(curve_id: u16) -> Option<CurveDetail> {
    let entry = ECC_CURVES.iter().find(|entry| entry.curve_id == curve_id)?;
    let curve = curve_parameters(curve_id)?;
    let prime = minimal_bytes(&curve.prime);
    let width = prime.len();
    Some(CurveDetail {
        curve_id,
        key_size_bits: entry.key_size_bits,
        kdf_scheme: entry.kdf_scheme,
        kdf_hash: entry.kdf_hash,
        sign_scheme: TPM_ALG_NULL,
        a: padded_bytes(&curve.a, width),
        b: padded_bytes(&curve.b, width),
        generator_x: padded_bytes(&curve.generator_x, width),
        generator_y: padded_bytes(&curve.generator_y, width),
        order: minimal_bytes(&curve.order),
        cofactor: vec![0x01],
        prime,
    })
}

pub(in crate::library::tpm2) fn curve_key_size_bits(curve_id: u16) -> Option<u16> {
    ECC_CURVES
        .iter()
        .find(|entry| entry.curve_id == curve_id)
        .map(|entry| entry.key_size_bits)
}

#[derive(Clone)]
struct JacobianPoint {
    x: BigUint,
    y: BigUint,
    z: BigUint,
}

impl CurveParameters {
    fn mul(&self, left: &BigUint, right: &BigUint) -> BigUint {
        left.mod_mul(right, &self.prime).expect("a non-zero prime")
    }

    fn sub(&self, left: &BigUint, right: &BigUint) -> BigUint {
        left.mod_sub(right, &self.prime).expect("a non-zero prime")
    }

    fn add(&self, left: &BigUint, right: &BigUint) -> BigUint {
        left.mod_add(right, &self.prime).expect("a non-zero prime")
    }

    fn double(&self, point: &JacobianPoint) -> JacobianPoint {
        if point.z.is_zero() || point.y.is_zero() {
            return JacobianPoint {
                x: BigUint::from_u64(1),
                y: BigUint::from_u64(1),
                z: BigUint::zero(),
            };
        }
        let y_squared = self.mul(&point.y, &point.y);
        let s = {
            let four = self.mul(&point.x, &y_squared);
            self.add(&self.add(&four, &four), &self.add(&four, &four))
        };
        let y_fourth = self.mul(&y_squared, &y_squared);
        let b = {
            let eight = self.add(&y_fourth, &y_fourth);
            let eight = self.add(&eight, &eight);
            self.add(&eight, &eight)
        };
        let z_squared = self.mul(&point.z, &point.z);
        let z_fourth = self.mul(&z_squared, &z_squared);
        let x_squared = self.mul(&point.x, &point.x);
        let m = {
            let three = self.add(&self.add(&x_squared, &x_squared), &x_squared);
            self.add(&three, &self.mul(&self.a, &z_fourth))
        };
        let x = self.sub(&self.mul(&m, &m), &self.add(&s, &s));
        let y = self.sub(&self.mul(&m, &self.sub(&s, &x)), &b);
        let z = {
            let product = self.mul(&point.y, &point.z);
            self.add(&product, &product)
        };
        JacobianPoint { x, y, z }
    }

    fn add_affine(&self, point: &JacobianPoint, x2: &BigUint, y2: &BigUint) -> JacobianPoint {
        if point.z.is_zero() {
            return JacobianPoint {
                x: x2.clone(),
                y: y2.clone(),
                z: BigUint::from_u64(1),
            };
        }
        let z_squared = self.mul(&point.z, &point.z);
        let z_cubed = self.mul(&z_squared, &point.z);
        let u2 = self.mul(x2, &z_squared);
        let s2 = self.mul(y2, &z_cubed);
        let h = self.sub(&u2, &point.x);
        let r = self.sub(&s2, &point.y);
        if h.is_zero() {
            if r.is_zero() {
                return self.double(point);
            }
            return JacobianPoint {
                x: BigUint::from_u64(1),
                y: BigUint::from_u64(1),
                z: BigUint::zero(),
            };
        }
        let h_squared = self.mul(&h, &h);
        let h_cubed = self.mul(&h_squared, &h);
        let v = self.mul(&point.x, &h_squared);
        let x = self.sub(&self.sub(&self.mul(&r, &r), &h_cubed), &self.add(&v, &v));
        let y = self.sub(
            &self.mul(&r, &self.sub(&v, &x)),
            &self.mul(&point.y, &h_cubed),
        );
        let z = self.mul(&point.z, &h);
        JacobianPoint { x, y, z }
    }

    fn infinity() -> JacobianPoint {
        JacobianPoint {
            x: BigUint::from_u64(1),
            y: BigUint::from_u64(1),
            z: BigUint::zero(),
        }
    }

    fn multiply_affine(&self, x: &BigUint, y: &BigUint, scalar: &BigUint) -> JacobianPoint {
        let mut accumulator = Self::infinity();
        for bit in (0..scalar.bit_len()).rev() {
            accumulator = self.double(&accumulator);
            if scalar.test_bit(bit) {
                accumulator = self.add_affine(&accumulator, x, y);
            }
        }
        accumulator
    }

    fn to_affine(&self, point: &JacobianPoint) -> Option<(BigUint, BigUint)> {
        if point.z.is_zero() {
            return None;
        }
        let z_inverse = point.z.mod_inverse(&self.prime)?;
        let z_inverse_squared = self.mul(&z_inverse, &z_inverse);
        let z_inverse_cubed = self.mul(&z_inverse_squared, &z_inverse);
        Some((
            self.mul(&point.x, &z_inverse_squared),
            self.mul(&point.y, &z_inverse_cubed),
        ))
    }

    pub(in crate::library::tpm2) fn multiply_generator(
        &self,
        scalar: &BigUint,
    ) -> Option<(BigUint, BigUint)> {
        if scalar.is_zero() {
            return None;
        }
        self.to_affine(&self.multiply_affine(&self.generator_x, &self.generator_y, scalar))
    }

    pub(in crate::library::tpm2) fn multiply_sum(
        &self,
        generator_scalar: &BigUint,
        point: (&BigUint, &BigUint),
        point_scalar: &BigUint,
    ) -> Option<(BigUint, BigUint)> {
        self.multiply_and_add(
            (&self.generator_x, &self.generator_y),
            generator_scalar,
            point,
            point_scalar,
        )
    }

    pub(in crate::library::tpm2) fn multiply_and_add(
        &self,
        first: (&BigUint, &BigUint),
        first_scalar: &BigUint,
        second: (&BigUint, &BigUint),
        second_scalar: &BigUint,
    ) -> Option<(BigUint, BigUint)> {
        let mut accumulator = self.multiply_affine(first.0, first.1, first_scalar);
        let addend = self.multiply_affine(second.0, second.1, second_scalar);
        if let Some((x, y)) = self.to_affine(&addend) {
            accumulator = self.add_affine(&accumulator, &x, &y);
        }
        self.to_affine(&accumulator)
    }

    pub(in crate::library::tpm2) fn multiply_point(
        &self,
        point: (&BigUint, &BigUint),
        scalar: &BigUint,
    ) -> Option<(BigUint, BigUint)> {
        if scalar.is_zero() {
            return None;
        }
        self.to_affine(&self.multiply_affine(point.0, point.1, scalar))
    }

    pub(in crate::library::tpm2) fn is_point_on_curve(&self, x: &BigUint, y: &BigUint) -> bool {
        let left = self.mul(y, y);
        let x_cubed = self.mul(&self.mul(x, x), x);
        let right = self.add(&self.add(&x_cubed, &self.mul(&self.a, x)), &self.b);
        left == right
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) enum EccKeyError {
    Curve,
    NoResult,
}

pub(in crate::library::tpm2) struct EccKeyMaterial {
    pub(in crate::library::tpm2) x: Vec<u8>,
    pub(in crate::library::tpm2) y: Vec<u8>,
    pub(in crate::library::tpm2) private: Vec<u8>,
}

pub(in crate::library::tpm2) fn generate_private_scalar(
    curve: &CurveParameters,
    rand: &mut SeededRand,
) -> Result<BigUint, TpmResult> {
    let order_bytes = curve.order.bit_len().div_ceil(8);
    let extra = rand.random_integer(order_bytes * 8 + 64)?;
    let order_minus_one = curve
        .order
        .sub_u64(1)
        .ok_or(crate::library::constants::TPM_RC_FAILURE)?;
    let reduced = extra
        .rem(&order_minus_one)
        .ok_or(crate::library::constants::TPM_RC_FAILURE)?;
    Ok(reduced.add_u64(1))
}

pub(in crate::library::tpm2) fn generate_ecc_key(
    curve_id: u16,
    rand: &mut SeededRand,
) -> Result<EccKeyMaterial, EccKeyError> {
    let curve = curve_parameters(curve_id).ok_or(EccKeyError::Curve)?;
    let scalar = generate_private_scalar(&curve, rand).map_err(|_| EccKeyError::NoResult)?;
    let (x, y) = curve
        .multiply_generator(&scalar)
        .ok_or(EccKeyError::NoResult)?;
    let size = curve.key_size_bytes;
    Ok(EccKeyMaterial {
        x: x.to_be_bytes(size).ok_or(EccKeyError::NoResult)?,
        y: y.to_be_bytes(size).ok_or(EccKeyError::NoResult)?,
        private: scalar.to_be_bytes(size).ok_or(EccKeyError::NoResult)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rand(label: &[u8]) -> SeededRand {
        SeededRand::instantiate(&[0x91; 64], b"ECC", label, &[], 1, false)
            .expect("a non-empty derivation input")
    }

    #[test]
    fn compiled_curve_identifier_recognition() {
        for curve_id in [
            TPM_ECC_NIST_P192,
            TPM_ECC_NIST_P224,
            TPM_ECC_NIST_P256,
            TPM_ECC_NIST_P384,
            TPM_ECC_NIST_P521,
            TPM_ECC_BN_P256,
            TPM_ECC_BN_P638,
            TPM_ECC_SM2_P256,
        ] {
            assert!(is_compiled_curve(curve_id), "curve {curve_id:#06x}");
            assert!(curve_parameters(curve_id).is_some());
        }
        assert_eq!(ECC_CURVES.len(), 8);
    }

    #[test]
    fn uncompiled_curve_no_parameters() {
        for curve_id in [0x0000u16, 0x0006, 0x000f, 0x0012, 0x0021, 0xffff] {
            assert!(!is_compiled_curve(curve_id), "curve {curve_id:#06x}");
            assert!(curve_parameters(curve_id).is_none());
            assert!(curve_key_size_bits(curve_id).is_none());
        }
    }

    #[test]
    fn parameter_curve_identifier_round_trip() {
        for entry in ECC_CURVES {
            let curve = curve_parameters(entry.curve_id).expect("a compiled curve");
            assert_eq!(curve.curve_id, entry.curve_id);
        }
    }

    #[test]
    fn key_size_vendored_metadata_match() {
        assert_eq!(curve_key_size_bits(TPM_ECC_NIST_P192), Some(192));
        assert_eq!(curve_key_size_bits(TPM_ECC_NIST_P224), Some(224));
        assert_eq!(curve_key_size_bits(TPM_ECC_NIST_P256), Some(256));
        assert_eq!(curve_key_size_bits(TPM_ECC_NIST_P384), Some(384));
        assert_eq!(curve_key_size_bits(TPM_ECC_NIST_P521), Some(521));
        assert_eq!(curve_key_size_bits(TPM_ECC_BN_P256), Some(256));
        assert_eq!(curve_key_size_bits(TPM_ECC_BN_P638), Some(638));
        assert_eq!(curve_key_size_bits(TPM_ECC_SM2_P256), Some(256));
        assert_eq!(
            curve_parameters(TPM_ECC_NIST_P521).unwrap().key_size_bytes,
            66
        );
        assert_eq!(
            curve_parameters(TPM_ECC_BN_P638).unwrap().key_size_bytes,
            80
        );
    }

    #[test]
    fn hex_parser_odd_length_whitespace_tolerance() {
        assert_eq!(parse_hex("03"), BigUint::from_u64(3));
        assert_eq!(parse_hex("101"), BigUint::from_u64(0x101));
        assert_eq!(parse_hex("00"), BigUint::zero());
        assert_eq!(parse_hex("ff ff\n ff"), BigUint::from_u64(0xffffff));
    }

    #[test]
    fn generator_own_curve_membership() {
        for entry in ECC_CURVES {
            let curve = curve_parameters(entry.curve_id).expect("a compiled curve");
            assert!(
                curve.is_point_on_curve(&curve.generator_x, &curve.generator_y),
                "curve {:#06x}",
                entry.curve_id
            );
        }
    }

    #[test]
    fn curve_prime_and_order_bit_length() {
        for entry in ECC_CURVES {
            let curve = curve_parameters(entry.curve_id).expect("a compiled curve");
            assert_eq!(
                curve.prime.bit_len(),
                usize::from(entry.key_size_bits),
                "curve {:#06x}",
                entry.curve_id
            );
            assert!(curve.order.bit_len() <= usize::from(entry.key_size_bits) + 1);
        }
    }

    #[test]
    fn generator_order_multiplication_infinity() {
        for curve_id in [TPM_ECC_NIST_P256, TPM_ECC_NIST_P384] {
            let curve = curve_parameters(curve_id).expect("a compiled curve");
            assert_eq!(
                curve.multiply_generator(&curve.order),
                None,
                "curve {curve_id:#06x}"
            );
        }
    }

    #[test]
    fn generator_times_one_identity() {
        for entry in ECC_CURVES {
            let curve = curve_parameters(entry.curve_id).expect("a compiled curve");
            let (x, y) = curve
                .multiply_generator(&BigUint::from_u64(1))
                .expect("a finite point");
            assert_eq!(x, curve.generator_x, "curve {:#06x}", entry.curve_id);
            assert_eq!(y, curve.generator_y, "curve {:#06x}", entry.curve_id);
        }
    }

    #[test]
    fn zero_multiplication_no_point() {
        let curve = curve_parameters(TPM_ECC_NIST_P256).unwrap();
        assert_eq!(curve.multiply_generator(&BigUint::zero()), None);
    }

    #[test]
    fn small_generator_multiple_curve_membership() {
        let curve = curve_parameters(TPM_ECC_NIST_P384).unwrap();
        for scalar in 1..12u64 {
            let (x, y) = curve
                .multiply_generator(&BigUint::from_u64(scalar))
                .expect("a finite point");
            assert!(curve.is_point_on_curve(&x, &y), "scalar {scalar}");
        }
    }

    #[test]
    fn multiplication_sum_repeated_addition_match() {
        let curve = curve_parameters(TPM_ECC_NIST_P256).expect("a compiled curve");
        let (qx, qy) = curve
            .multiply_generator(&BigUint::from_u64(7))
            .expect("a point");
        for (left, right, total) in [(1u64, 1u64, 8u64), (3, 2, 17), (5, 4, 33)] {
            let sum = curve
                .multiply_sum(
                    &BigUint::from_u64(left),
                    (&qx, &qy),
                    &BigUint::from_u64(right),
                )
                .expect("a point");
            assert_eq!(
                sum,
                curve
                    .multiply_generator(&BigUint::from_u64(total))
                    .expect("a point"),
                "[{left}]G + [{right}]([7]G) == [{total}]G"
            );
        }
    }

    #[test]
    fn zero_scalar_term_drop() {
        let curve = curve_parameters(TPM_ECC_NIST_P256).expect("a compiled curve");
        let (qx, qy) = curve
            .multiply_generator(&BigUint::from_u64(9))
            .expect("a point");
        assert_eq!(
            curve
                .multiply_sum(&BigUint::zero(), (&qx, &qy), &BigUint::from_u64(1))
                .expect("a point"),
            (qx.clone(), qy.clone()),
            "the generator term vanishes"
        );
        assert_eq!(
            curve
                .multiply_sum(&BigUint::from_u64(9), (&qx, &qy), &BigUint::zero())
                .expect("a point"),
            (qx, qy),
            "the point term vanishes"
        );
    }

    #[test]
    fn infinity_sum_no_affine_point() {
        let curve = curve_parameters(TPM_ECC_NIST_P256).expect("a compiled curve");
        let (qx, qy) = curve
            .multiply_generator(&BigUint::from_u64(1))
            .expect("the generator");
        let negated = curve.order.sub_u64(1).expect("order - 1");
        assert!(
            curve
                .multiply_sum(&BigUint::from_u64(1), (&qx, &qy), &negated)
                .is_none(),
            "[1]G + [n-1]G is the point at infinity"
        );
    }

    #[test]
    fn p256_generator_double_published_value_match() {
        let curve = curve_parameters(TPM_ECC_NIST_P256).unwrap();
        let (x, y) = curve
            .multiply_generator(&BigUint::from_u64(2))
            .expect("a finite point");
        assert_eq!(
            x,
            parse_hex("7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978")
        );
        assert_eq!(
            y,
            parse_hex("07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1")
        );
    }

    #[test]
    fn p384_generator_double_published_value_match() {
        let curve = curve_parameters(TPM_ECC_NIST_P384).unwrap();
        let (x, y) = curve
            .multiply_generator(&BigUint::from_u64(2))
            .expect("a finite point");
        assert_eq!(
            x,
            parse_hex(
                "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e\
                 4fe0e86ebe0e64f85b96a9c75295df61"
            )
        );
        assert_eq!(
            y,
            parse_hex(
                "8e80f1fa5b1b3cedb7bfe8dffd6dba74b275d875bc6cc43e904e505f256ab425\
                 5ffd43e94d39e22d61501e700a940e80"
            )
        );
    }

    #[test]
    fn generated_key_on_curve_scalar_match() {
        for curve_id in [TPM_ECC_NIST_P256, TPM_ECC_NIST_P384, TPM_ECC_NIST_P521] {
            let key = generate_ecc_key(curve_id, &mut rand(b"key")).expect("a key");
            let curve = curve_parameters(curve_id).unwrap();
            assert_eq!(key.x.len(), curve.key_size_bytes);
            assert_eq!(key.y.len(), curve.key_size_bytes);
            assert_eq!(key.private.len(), curve.key_size_bytes);
            let x = BigUint::from_be_bytes(&key.x);
            let y = BigUint::from_be_bytes(&key.y);
            assert!(curve.is_point_on_curve(&x, &y), "curve {curve_id:#06x}");
            let scalar = BigUint::from_be_bytes(&key.private);
            assert!(!scalar.is_zero());
            assert!(scalar < curve.order);
            assert_eq!(curve.multiply_generator(&scalar), Some((x, y)));
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
        let curve = curve_parameters(TPM_ECC_NIST_P384).unwrap();
        let mut scalar_state = rand(b"extra");
        let scalar = generate_private_scalar(&curve, &mut scalar_state).unwrap();
        let mut byte_state = rand(b"extra");
        let raw = byte_state.random_integer(48 * 8 + 64).unwrap();
        let expected = raw
            .rem(&curve.order.sub_u64(1).unwrap())
            .unwrap()
            .add_u64(1);
        assert_eq!(scalar, expected);
        assert!(!scalar.is_zero());
        assert!(scalar < curve.order);
    }
}
