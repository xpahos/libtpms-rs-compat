use std::fmt;

use p521::elliptic_curve::PrimeField;
use p521::elliptic_curve::sec1::ToEncodedPoint;
use p521::{FieldBytes, ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

pub const SCALAR_BYTES: usize = 66;
pub const PAIR_BYTES: usize = 2 * SCALAR_BYTES;

pub const ORDER: [u8; SCALAR_BYTES] = [
    0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xfa, 0x51, 0x86, 0x87, 0x83, 0xbf, 0x2f, 0x96, 0x6b, 0x7f, 0xcc, 0x01, 0x48, 0xf7, 0x09,
    0xa5, 0xd0, 0x3b, 0xb5, 0xc9, 0xb8, 0x89, 0x9c, 0x47, 0xae, 0xbb, 0x6f, 0xb7, 0x1e, 0x91, 0x38,
    0x64, 0x09,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScalarError {
    Width { expected: usize, actual: usize },
    Zero,
    NotBelowOrder,
}

impl fmt::Display for ScalarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Width { expected, actual } => {
                write!(f, "expected {expected} bytes, got {actual}")
            }
            Self::Zero => write!(f, "scalar is zero"),
            Self::NotBelowOrder => write!(f, "scalar is not below the P-521 group order"),
        }
    }
}

impl std::error::Error for ScalarError {}

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Scalar521([u8; SCALAR_BYTES]);

impl fmt::Debug for Scalar521 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Scalar521({})", hex::encode(self.0))
    }
}

impl Scalar521 {
    pub fn new(bytes: [u8; SCALAR_BYTES]) -> Result<Self, ScalarError> {
        check_range(&bytes)?;
        Ok(Self(bytes))
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, ScalarError> {
        let array: [u8; SCALAR_BYTES] = bytes.try_into().map_err(|_| ScalarError::Width {
            expected: SCALAR_BYTES,
            actual: bytes.len(),
        })?;
        Self::new(array)
    }

    pub fn from_u128(value: u128) -> Result<Self, ScalarError> {
        let mut bytes = [0u8; SCALAR_BYTES];
        bytes[SCALAR_BYTES - 16..].copy_from_slice(&value.to_be_bytes());
        Self::new(bytes)
    }

    pub fn bytes(&self) -> &[u8; SCALAR_BYTES] {
        &self.0
    }

    pub fn leading_zero_bytes(&self) -> usize {
        self.0.iter().take_while(|byte| **byte == 0).count()
    }

    pub fn bit_length(&self) -> usize {
        let zeros = self.leading_zero_bytes();
        if zeros == SCALAR_BYTES {
            return 0;
        }
        (SCALAR_BYTES - zeros) * 8 - self.0[zeros].leading_zeros() as usize
    }

    pub fn hamming_weight(&self) -> u32 {
        self.0.iter().map(|byte| byte.count_ones()).sum()
    }

    fn field_scalar(&self) -> Scalar {
        Option::from(Scalar::from_repr(field_bytes(&self.0)))
            .expect("validated scalar is canonical")
    }

    pub fn public_point(&self) -> Point {
        Point::from_projective(ProjectivePoint::GENERATOR * self.field_scalar())
    }

    pub fn shared_point(&self, peer: &Scalar521) -> Point {
        Point::from_projective(
            ProjectivePoint::GENERATOR * peer.field_scalar() * self.field_scalar(),
        )
    }
}

fn field_bytes(bytes: &[u8]) -> FieldBytes {
    let mut out = FieldBytes::default();
    out.copy_from_slice(bytes);
    out
}

pub fn check_range(bytes: &[u8; SCALAR_BYTES]) -> Result<(), ScalarError> {
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(ScalarError::Zero);
    }
    if bytes.as_slice() >= ORDER.as_slice() {
        return Err(ScalarError::NotBelowOrder);
    }
    Ok(())
}

pub fn order_minus(k: u128) -> [u8; SCALAR_BYTES] {
    let mut out = ORDER;
    let mut borrow = k;
    for byte in out.iter_mut().rev() {
        if borrow == 0 {
            break;
        }
        let low = (borrow & 0xff) as u8;
        borrow >>= 8;
        let (value, under) = byte.overflowing_sub(low);
        *byte = value;
        if under {
            borrow += 1;
        }
    }
    out
}

pub fn power_of_two(exponent: usize) -> [u8; SCALAR_BYTES] {
    let mut out = [0u8; SCALAR_BYTES];
    let byte = SCALAR_BYTES - 1 - exponent / 8;
    out[byte] = 1 << (exponent % 8);
    out
}

pub fn offset(base: [u8; SCALAR_BYTES], delta: i64) -> [u8; SCALAR_BYTES] {
    let mut out = base;
    if delta >= 0 {
        let mut carry = delta as u128;
        for byte in out.iter_mut().rev() {
            if carry == 0 {
                break;
            }
            let sum = *byte as u128 + (carry & 0xff);
            *byte = sum as u8;
            carry = (carry >> 8) + (sum >> 8);
        }
    } else {
        let mut borrow = delta.unsigned_abs() as u128;
        for byte in out.iter_mut().rev() {
            if borrow == 0 {
                break;
            }
            let low = (borrow & 0xff) as u8;
            borrow >>= 8;
            let (value, under) = byte.overflowing_sub(low);
            *byte = value;
            if under {
                borrow += 1;
            }
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Point {
    #[serde(with = "hex_bytes")]
    pub x: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub y: Vec<u8>,
}

impl Point {
    fn from_projective(point: ProjectivePoint) -> Self {
        let encoded = point.to_affine().to_encoded_point(false);
        Self {
            x: encoded.x().expect("finite point").to_vec(),
            y: encoded.y().expect("uncompressed point").to_vec(),
        }
    }
}

pub fn peer_scalar() -> Scalar521 {
    let digest = Sha512::digest(b"tpms-timing-tests ecdh-p521 fixed peer v1");
    let mut bytes = [0u8; SCALAR_BYTES];
    bytes[SCALAR_BYTES - 64..].copy_from_slice(&digest);
    Scalar521::new(bytes).expect("fixed peer scalar is valid")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScalarPair {
    pub a: Scalar521,
    pub b: Scalar521,
}

impl ScalarPair {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ScalarError> {
        if bytes.len() != PAIR_BYTES {
            return Err(ScalarError::Width {
                expected: PAIR_BYTES,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            a: Scalar521::from_slice(&bytes[..SCALAR_BYTES])?,
            b: Scalar521::from_slice(&bytes[SCALAR_BYTES..])?,
        })
    }

    pub fn to_bytes(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PAIR_BYTES);
        out.extend_from_slice(self.a.bytes());
        out.extend_from_slice(self.b.bytes());
        out
    }

    pub fn class(&self, index: usize) -> &Scalar521 {
        if index == 0 { &self.a } else { &self.b }
    }

    pub fn unordered_key(&self) -> (Scalar521, Scalar521) {
        if self.a <= self.b {
            (self.a, self.b)
        } else {
            (self.b, self.a)
        }
    }
}

pub mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        hex::decode(text).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_matches_the_p521_crate() {
        assert!(bool::from(Scalar::from_repr(field_bytes(&ORDER)).is_none()));
        let below = order_minus(1);
        assert!(bool::from(Scalar::from_repr(field_bytes(&below)).is_some()));
        assert_eq!(Scalar521::new(ORDER), Err(ScalarError::NotBelowOrder));
        assert!(Scalar521::new(below).is_ok());
        assert_eq!(Scalar521::new([0; SCALAR_BYTES]), Err(ScalarError::Zero));
    }

    #[test]
    fn shared_point_is_symmetric() {
        let a = Scalar521::from_u128(7).unwrap();
        let peer = peer_scalar();
        let left = a.shared_point(&peer);
        let right = peer.shared_point(&a);
        assert_eq!(left, right);
        assert_eq!(left.x.len(), SCALAR_BYTES);
        assert_eq!(left.y.len(), SCALAR_BYTES);
    }

    #[test]
    fn helpers_build_boundaries() {
        assert_eq!(Scalar521::new(power_of_two(64)).unwrap().bit_length(), 65);
        assert_eq!(Scalar521::new(power_of_two(520)).unwrap().bit_length(), 521);
        assert_eq!(offset(power_of_two(64), -1)[SCALAR_BYTES - 8..], [0xff; 8]);
        assert_eq!(offset(order_minus(5), 4), order_minus(1));
    }
}
