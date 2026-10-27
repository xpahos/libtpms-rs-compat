use std::sync::OnceLock;

use num_bigint::BigUint;
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};

use super::bytes::{from_be, from_hex, to_fixed};
use super::hash::HashAlg;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CurveId {
    NistP192,
    NistP224,
    NistP256,
    NistP384,
    NistP521,
    BnP256,
    BnP638,
    Sm2P256,
}

impl CurveId {
    pub const ALL: [CurveId; 8] = [
        Self::NistP192,
        Self::NistP224,
        Self::NistP256,
        Self::NistP384,
        Self::NistP521,
        Self::BnP256,
        Self::BnP638,
        Self::Sm2P256,
    ];

    pub fn tpm_id(self) -> u16 {
        match self {
            Self::NistP192 => 0x0001,
            Self::NistP224 => 0x0002,
            Self::NistP256 => 0x0003,
            Self::NistP384 => 0x0004,
            Self::NistP521 => 0x0005,
            Self::BnP256 => 0x0010,
            Self::BnP638 => 0x0011,
            Self::Sm2P256 => 0x0020,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::NistP192 => "p192",
            Self::NistP224 => "p224",
            Self::NistP256 => "p256",
            Self::NistP384 => "p384",
            Self::NistP521 => "p521",
            Self::BnP256 => "bnp256",
            Self::BnP638 => "bnp638",
            Self::Sm2P256 => "sm2p256",
        }
    }

    pub fn key_bytes(self) -> usize {
        match self {
            Self::NistP192 => 24,
            Self::NistP224 => 28,
            Self::NistP256 | Self::BnP256 | Self::Sm2P256 => 32,
            Self::NistP384 => 48,
            Self::NistP521 => 66,
            Self::BnP638 => 80,
        }
    }

    pub fn curve(self) -> &'static Curve {
        curve(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Affine {
    pub x: BigUint,
    pub y: BigUint,
}

#[derive(Debug, Clone)]
struct Jacobian {
    x: BigUint,
    y: BigUint,
    z: BigUint,
}

#[derive(Debug)]
pub struct Curve {
    pub id: CurveId,
    pub p: BigUint,
    pub a: BigUint,
    pub b: BigUint,
    pub n: BigUint,
    pub g: Affine,
    pub bytes: usize,
}

struct Constants {
    id: CurveId,
    p: &'static str,
    a: &'static str,
    b: &'static str,
    gx: &'static str,
    gy: &'static str,
    n: &'static str,
}

const CONSTANTS: [Constants; 8] = [
    Constants {
        id: CurveId::NistP192,
        p: "fffffffffffffffffffffffffffffffeffffffffffffffff",
        a: "fffffffffffffffffffffffffffffffefffffffffffffffc",
        b: "64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",
        gx: "188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
        gy: "07192b95ffc8da78631011ed6b24cdd573f977a11e794811",
        n: "ffffffffffffffffffffffff99def836146bc9b1b4d22831",
    },
    Constants {
        id: CurveId::NistP224,
        p: "ffffffffffffffffffffffffffffffff000000000000000000000001",
        a: "fffffffffffffffffffffffffffffffefffffffffffffffffffffffe",
        b: "b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
        gx: "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
        gy: "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34",
        n: "ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d",
    },
    Constants {
        id: CurveId::NistP256,
        p: "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        a: "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
        b: "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
        gx: "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        gy: "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        n: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    },
    Constants {
        id: CurveId::NistP384,
        p: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
            ffffffff0000000000000000ffffffff",
        a: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
            ffffffff0000000000000000fffffffc",
        b: "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a\
            c656398d8a2ed19d2a85c8edd3ec2aef",
        gx: "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38\
             5502f25dbf55296c3a545e3872760ab7",
        gy: "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0\
             0a60b1ce1d7e819d7a431d7c90ea0e5f",
        n: "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf\
            581a0db248b0a77aecec196accc52973",
    },
    Constants {
        id: CurveId::NistP521,
        p: "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
            ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
            ffff",
        a: "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
            ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
            fffc",
        b: "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef1\
            09e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b50\
            3f00",
        gx: "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d\
             3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5\
             bd66",
        gy: "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e\
             662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd1\
             6650",
        n: "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
            fffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138\
            6409",
    },
    Constants {
        id: CurveId::BnP256,
        p: "fffffffffffcf0cd46e5f25eee71a49f0cdc65fb12980a82d3292ddbaed33013",
        a: "00",
        b: "03",
        gx: "01",
        gy: "02",
        n: "fffffffffffcf0cd46e5f25eee71a49e0cdc65fb1299921af62d536cd10b500d",
    },
    Constants {
        id: CurveId::BnP638,
        p: "23fffffdc000000d7fffffb8000001d3fffff942d000165e3fff94870000d52f\
            fffdd0e00008de55c00086520021e55bfffff51ffff4eb800000004c80015acd\
            ffffffffffffece00000000000000067",
        a: "00",
        b: "0101",
        gx: "23fffffdc000000d7fffffb8000001d3fffff942d000165e3fff94870000d52f\
             fffdd0e00008de55c00086520021e55bfffff51ffff4eb800000004c80015acd\
             ffffffffffffece00000000000000066",
        gy: "10",
        n: "23fffffdc000000d7fffffb8000001d3fffff942d000165e3fff94870000d52f\
            fffdd0e00008de55600086550021e555fffff54ffff4eac000000049800154d9\
            ffffffffffffeda00000000000000061",
    },
    Constants {
        id: CurveId::Sm2P256,
        p: "fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff",
        a: "fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc",
        b: "28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93",
        gx: "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
        gy: "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
        n: "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123",
    },
];

pub fn curve(id: CurveId) -> &'static Curve {
    static CURVES: OnceLock<Vec<Curve>> = OnceLock::new();
    let curves = CURVES.get_or_init(|| {
        CONSTANTS
            .iter()
            .map(|c| Curve {
                id: c.id,
                p: from_hex(c.p),
                a: from_hex(c.a),
                b: from_hex(c.b),
                n: from_hex(c.n),
                g: Affine {
                    x: from_hex(c.gx),
                    y: from_hex(c.gy),
                },
                bytes: c.id.key_bytes(),
            })
            .collect()
    });
    curves
        .iter()
        .find(|c| c.id == id)
        .expect("every curve id has constants")
}

pub fn mod_inverse(value: &BigUint, prime: &BigUint) -> BigUint {
    value.modpow(&(prime - 2u32), prime)
}

impl Curve {
    fn add_m(&self, a: &BigUint, b: &BigUint) -> BigUint {
        (a + b) % &self.p
    }

    fn sub_m(&self, a: &BigUint, b: &BigUint) -> BigUint {
        ((a + &self.p) - (b % &self.p)) % &self.p
    }

    fn mul_m(&self, a: &BigUint, b: &BigUint) -> BigUint {
        (a * b) % &self.p
    }

    fn infinity() -> Jacobian {
        Jacobian {
            x: BigUint::one(),
            y: BigUint::one(),
            z: BigUint::zero(),
        }
    }

    fn lift(point: &Affine) -> Jacobian {
        Jacobian {
            x: point.x.clone(),
            y: point.y.clone(),
            z: BigUint::one(),
        }
    }

    fn double(&self, p: &Jacobian) -> Jacobian {
        if p.z.is_zero() || p.y.is_zero() {
            return Self::infinity();
        }
        let xx = self.mul_m(&p.x, &p.x);
        let yy = self.mul_m(&p.y, &p.y);
        let yyyy = self.mul_m(&yy, &yy);
        let zz = self.mul_m(&p.z, &p.z);
        let s = self.mul_m(&(BigUint::from(4u32) * &p.x), &yy);
        let m = self.add_m(
            &(BigUint::from(3u32) * &xx),
            &self.mul_m(&self.a, &self.mul_m(&zz, &zz)),
        );
        let x3 = self.sub_m(&self.mul_m(&m, &m), &(BigUint::from(2u32) * &s));
        let y3 = self.sub_m(
            &self.mul_m(&m, &self.sub_m(&s, &x3)),
            &(BigUint::from(8u32) * &yyyy),
        );
        let z3 = self.mul_m(&(BigUint::from(2u32) * &p.y), &p.z);
        Jacobian {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    fn add(&self, p: &Jacobian, q: &Jacobian) -> Jacobian {
        if p.z.is_zero() {
            return q.clone();
        }
        if q.z.is_zero() {
            return p.clone();
        }
        let z1z1 = self.mul_m(&p.z, &p.z);
        let z2z2 = self.mul_m(&q.z, &q.z);
        let u1 = self.mul_m(&p.x, &z2z2);
        let u2 = self.mul_m(&q.x, &z1z1);
        let s1 = self.mul_m(&p.y, &self.mul_m(&q.z, &z2z2));
        let s2 = self.mul_m(&q.y, &self.mul_m(&p.z, &z1z1));
        if u1 == u2 {
            return if s1 == s2 {
                self.double(p)
            } else {
                Self::infinity()
            };
        }
        let h = self.sub_m(&u2, &u1);
        let r = self.sub_m(&s2, &s1);
        let h2 = self.mul_m(&h, &h);
        let h3 = self.mul_m(&h, &h2);
        let u1h2 = self.mul_m(&u1, &h2);
        let x3 = self.sub_m(
            &self.sub_m(&self.mul_m(&r, &r), &h3),
            &(BigUint::from(2u32) * &u1h2),
        );
        let y3 = self.sub_m(
            &self.mul_m(&r, &self.sub_m(&u1h2, &x3)),
            &self.mul_m(&s1, &h3),
        );
        let z3 = self.mul_m(&h, &self.mul_m(&p.z, &q.z));
        Jacobian {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    fn affine(&self, p: &Jacobian) -> Option<Affine> {
        if p.z.is_zero() {
            return None;
        }
        let zinv = mod_inverse(&p.z, &self.p);
        let zinv2 = self.mul_m(&zinv, &zinv);
        Some(Affine {
            x: self.mul_m(&p.x, &zinv2),
            y: self.mul_m(&p.y, &self.mul_m(&zinv2, &zinv)),
        })
    }

    fn mul_jacobian(&self, k: &BigUint, point: &Jacobian) -> Jacobian {
        let mut acc = Self::infinity();
        for bit in (0..k.bits()).rev() {
            acc = self.double(&acc);
            if k.bit(bit) {
                acc = self.add(&acc, point);
            }
        }
        acc
    }

    pub fn mul(&self, k: &BigUint, point: &Affine) -> Option<Affine> {
        self.affine(&self.mul_jacobian(k, &Self::lift(point)))
    }

    pub fn mul_g(&self, k: &BigUint) -> Option<Affine> {
        self.mul(k, &self.g)
    }

    pub fn mul_add(&self, a: &BigUint, p: &Affine, b: &BigUint, q: &Affine) -> Option<Affine> {
        let left = self.mul_jacobian(a, &Self::lift(p));
        let right = self.mul_jacobian(b, &Self::lift(q));
        self.affine(&self.add(&left, &right))
    }

    pub fn on_curve(&self, point: &Affine) -> bool {
        if point.x >= self.p || point.y >= self.p {
            return false;
        }
        let lhs = self.mul_m(&point.y, &point.y);
        let x3 = self.mul_m(&point.x, &self.mul_m(&point.x, &point.x));
        let rhs = self.add_m(&self.add_m(&x3, &self.mul_m(&self.a, &point.x)), &self.b);
        lhs == rhs
    }

    pub fn encode(&self, point: &Affine) -> (Vec<u8>, Vec<u8>) {
        (
            to_fixed(&point.x, self.bytes),
            to_fixed(&point.y, self.bytes),
        )
    }

    pub fn decode(&self, x: &[u8], y: &[u8]) -> Affine {
        Affine {
            x: from_be(x),
            y: from_be(y),
        }
    }

    pub fn order_bytes(&self) -> usize {
        (self.n.bits() as usize).div_ceil(8)
    }

    pub fn valid_scalar(&self, bytes: &[u8]) -> bool {
        let k = from_be(bytes);
        !k.is_zero() && k < self.n
    }

    fn in_range(&self, value: &BigUint) -> bool {
        !value.is_zero() && value < &self.n
    }

    pub fn ecdsa_verify(&self, q: &Affine, digest: &[u8], r: &[u8], s: &[u8]) -> bool {
        let (r, s) = (from_be(r), from_be(s));
        if !self.in_range(&r) || !self.in_range(&s) {
            return false;
        }
        let nbits = self.n.bits() as usize;
        let mut e = from_be(digest);
        if digest.len() * 8 > nbits {
            e >>= digest.len() * 8 - nbits;
        }
        let w = mod_inverse(&s, &self.n);
        let u1 = (&e * &w) % &self.n;
        let u2 = (&r * &w) % &self.n;
        match self.mul_add(&u1, &self.g, &u2, q) {
            Some(point) => point.x % &self.n == r,
            None => false,
        }
    }

    pub fn schnorr_challenge(&self, hash: HashAlg, x: &BigUint, digest: &[u8]) -> BigUint {
        let width = self.order_bytes();
        let mut e = hash.digest(&[&to_fixed(x, width), digest]);
        e.truncate(width);
        from_be(&e)
    }

    pub fn schnorr_verify(
        &self,
        hash: HashAlg,
        q: &Affine,
        digest: &[u8],
        r: &[u8],
        s: &[u8],
    ) -> bool {
        let r = from_be(r) % &self.n;
        let s = from_be(s);
        if r.is_zero() || s >= self.n {
            return false;
        }
        let minus_r = &self.n - &r;
        match self.mul_add(&s, &self.g, &minus_r, q) {
            Some(point) => self.schnorr_challenge(hash, &point.x, digest) == r,
            None => false,
        }
    }

    pub fn sm2_verify(&self, q: &Affine, digest: &[u8], r: &[u8], s: &[u8]) -> bool {
        let (r, s) = (from_be(r), from_be(s));
        if !self.in_range(&r) || !self.in_range(&s) {
            return false;
        }
        let t = (&r + &s) % &self.n;
        if t.is_zero() {
            return false;
        }
        let e = from_be(digest);
        match self.mul_add(&s, &self.g, &t, q) {
            Some(point) => (e + point.x) % &self.n == r,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generators_have_the_stated_order() {
        for id in CurveId::ALL {
            let c = curve(id);
            assert!(c.on_curve(&c.g), "{id:?} generator off curve");
            assert!(c.mul_g(&c.n).is_none(), "{id:?} n*G is not infinity");
            let minus_one = c.mul_g(&(&c.n - 1u32)).unwrap();
            assert_eq!(minus_one.x, c.g.x);
            assert_eq!(minus_one.y, &c.p - &c.g.y);
            assert_eq!(c.p.bits().div_ceil(8) as usize, c.bytes, "{id:?} width");
        }
    }

    #[test]
    fn scalar_multiplication_agrees_with_the_p521_crate() {
        use crate::scalar::Scalar521;
        let k = Scalar521::from_u128(0x1234_5678_9abc_def0_1122_3344).unwrap();
        let reference = k.public_point();
        let c = curve(CurveId::NistP521);
        let ours = c.mul_g(&from_be(k.bytes())).unwrap();
        let (x, y) = c.encode(&ours);
        assert_eq!(x, reference.x);
        assert_eq!(y, reference.y);
    }

    #[test]
    fn nist_p256_matches_a_published_vector() {
        let c = curve(CurveId::NistP256);
        let point = c.mul_g(&BigUint::from(2u32)).unwrap();
        assert_eq!(
            hex::encode(to_fixed(&point.x, 32)),
            "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"
        );
        assert_eq!(
            hex::encode(to_fixed(&point.y, 32)),
            "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"
        );
    }

    fn sign_ecdsa(c: &Curve, d: &BigUint, k: &BigUint, digest: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let nbits = c.n.bits() as usize;
        let mut e = from_be(digest);
        if digest.len() * 8 > nbits {
            e >>= digest.len() * 8 - nbits;
        }
        let r = c.mul_g(k).unwrap().x % &c.n;
        let s = (mod_inverse(k, &c.n) * (e + &r * d)) % &c.n;
        (to_fixed(&r, c.order_bytes()), to_fixed(&s, c.order_bytes()))
    }

    #[test]
    fn signature_verifiers_accept_valid_and_reject_tampered_signatures() {
        for id in CurveId::ALL {
            let c = curve(id);
            let d = BigUint::from(0x1357_9bdf_u64);
            let q = c.mul_g(&d).unwrap();
            let k = BigUint::from(0x2468_ace0_u64);
            let digest = HashAlg::Sha256.digest(&[id.name().as_bytes()]);
            let (r, s) = sign_ecdsa(c, &d, &k, &digest);
            assert!(c.ecdsa_verify(&q, &digest, &r, &s), "{id:?} ecdsa");
            let mut bad = s.clone();
            *bad.last_mut().unwrap() ^= 1;
            assert!(!c.ecdsa_verify(&q, &digest, &r, &bad));

            let rx = c.mul_g(&k).unwrap().x;
            let r = c.schnorr_challenge(HashAlg::Sha256, &rx, &digest);
            let s = (&k + (&r % &c.n) * &d) % &c.n;
            let (rb, sb) = (r.to_bytes_be(), s.to_bytes_be());
            assert!(
                c.schnorr_verify(HashAlg::Sha256, &q, &digest, &rb, &sb),
                "{id:?} schnorr"
            );
            assert!(!c.schnorr_verify(HashAlg::Sha256, &q, &digest[1..], &rb, &sb));

            let e = from_be(&digest);
            let r = (e + c.mul_g(&k).unwrap().x) % &c.n;
            let dinv = mod_inverse(&(&d + 1u32), &c.n);
            let s = (dinv * ((&k + &c.n) - (&r * &d) % &c.n)) % &c.n;
            let (rb, sb) = (r.to_bytes_be(), s.to_bytes_be());
            assert!(c.sm2_verify(&q, &digest, &rb, &sb), "{id:?} sm2");
            assert!(!c.sm2_verify(&q, &digest, &sb, &rb));
        }
    }
}
