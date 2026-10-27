//! Independent equations for the ECC command transcripts; never calls a TPM backend.
use super::{
    bytes::from_be,
    ec::{Affine, Curve, CurveId},
    hash::HashAlg,
};
use crate::{
    program::{Program, frame_parameters},
    scenario::catalog::ExchangeScheme,
    tpm,
};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

pub struct Ciphertext {
    pub c1: Affine,
    pub c2: Vec<u8>,
    pub c3: Vec<u8>,
}

pub fn encrypt(
    curve: CurveId,
    hash: HashAlg,
    d: &BigUint,
    k: &BigUint,
    message: &[u8],
) -> Ciphertext {
    let c = curve.curve();
    let q = c.mul_g(d).expect("valid fixture scalar");
    let shared = c.mul(k, &q).expect("valid fixture ephemeral");
    let (x, y) = c.encode(&shared);
    let mut mask = Vec::new();
    for counter in 1..=message.len().div_ceil(hash.size()) {
        mask.extend(hash.digest(&[&x, &y, &(counter as u32).to_be_bytes()]));
    }
    Ciphertext {
        c1: c.mul_g(k).expect("valid fixture ephemeral"),
        c2: message.iter().zip(mask).map(|(m, k)| m ^ k).collect(),
        c3: hash.digest(&[&x, message, &y]),
    }
}

// Tonelli-Shanks also handles P224 (p = 1 mod 4). Every result is checked on curve.
fn square_root(value: &BigUint, p: &BigUint) -> Option<BigUint> {
    if value.is_zero() {
        return Some(BigUint::zero());
    }
    if value.modpow(&((p - 1u32) >> 1), p) != BigUint::one() {
        return None;
    }
    let mut q = p - 1u32;
    let mut s = 0usize;
    while !q.bit(0) {
        q >>= 1;
        s += 1;
    }
    if s == 1 {
        return Some(value.modpow(&((p + 1u32) >> 2), p));
    }
    let mut z = BigUint::from(2u32);
    while z.modpow(&((p - 1u32) >> 1), p) == BigUint::one() {
        z += 1u32;
    }
    let mut c = z.modpow(&q, p);
    let mut x = value.modpow(&((&q + 1u32) >> 1), p);
    let mut t = value.modpow(&q, p);
    let mut m = s;
    while t != BigUint::one() {
        let mut i = 1usize;
        let mut tt = (&t * &t) % p;
        while tt != BigUint::one() && i < m {
            tt = (&tt * &tt) % p;
            i += 1;
        }
        if i >= m {
            return None;
        }
        let b = c.modpow(&(BigUint::one() << (m - i - 1)), p);
        x = (&x * &b) % p;
        c = (&b * &b) % p;
        t = (&t * &c) % p;
        m = i;
    }
    Some(x)
}

pub fn commit_point(curve: CurveId) -> &'static (Vec<u8>, Affine) {
    static POINTS: OnceLock<Vec<(Vec<u8>, Affine)>> = OnceLock::new();
    let all = POINTS.get_or_init(|| {
        CurveId::ALL
            .into_iter()
            .map(|id| {
                let c = id.curve();
                for attempt in 0u32.. {
                    let s2 = [
                        b"timing independent Commit P2 v1".as_slice(),
                        &id.tpm_id().to_be_bytes(),
                        &attempt.to_be_bytes(),
                    ]
                    .concat();
                    let x = from_be(&HashAlg::Sha256.digest(&[&s2])) % &c.p;
                    let rhs = ((&x * &x % &c.p) * &x + &c.a * &x + &c.b) % &c.p;
                    if let Some(y) = square_root(&rhs, &c.p) {
                        let point = Affine { x, y };
                        assert!(c.on_curve(&point));
                        return (s2, point);
                    }
                }
                unreachable!("finite fixture search")
            })
            .collect()
    });
    let index = CurveId::ALL
        .iter()
        .position(|id| *id == curve)
        .expect("all curves");
    &all[index]
}

pub fn point_bytes(curve: CurveId, p: &Affine) -> Vec<u8> {
    let (x, y) = curve.curve().encode(p);
    tpm::sized(&[tpm::sized(&x), tpm::sized(&y)].concat())
}
fn read_point(
    c: &Curve,
    bytes: &[u8],
    at: &mut usize,
    empty: bool,
) -> Result<Option<Affine>, String> {
    let (p, end) = tpm::read_2b(bytes, *at).ok_or("malformed outer point")?;
    *at = end;
    let (x, next) = tpm::read_2b(p, 0).ok_or("malformed point x")?;
    let (y, end) = tpm::read_2b(p, next).ok_or("malformed point y")?;
    if end != p.len() {
        return Err("trailing point bytes".into());
    }
    if empty && x.is_empty() && y.is_empty() {
        return Ok(None);
    }
    if x.len() != c.bytes || y.len() != c.bytes {
        return Err("wrong coordinate width".into());
    }
    let point = c.decode(x, y);
    if !c.on_curve(&point) {
        return Err("point is off curve".into());
    }
    Ok(Some(point))
}
fn password_parameters(response: &[u8]) -> Result<&[u8], String> {
    let p = frame_parameters(response, 0)?;
    if response[..2] != [0x80, 2] || response.get(14 + p.len()..) != Some(&[0, 0, 1, 0, 0][..]) {
        return Err("password response auth differs".into());
    }
    Ok(p)
}

/// The pinned 64-bit implementation masks by the remainder, rather than its complement.
/// This deliberately differs from the standard SM2 associated-value formula below.
pub fn sm2_associated_compat(c: &Curve, x: &BigUint) -> BigUint {
    let w = ((c.n.bits() - 1) / 2 - 1) as usize;
    let words = w.div_ceil(64);
    let rem = w % 64;
    let kept = if words == 0 {
        0
    } else if rem == 0 {
        64 * words
    } else {
        64 * (words - 1) + 64 - rem
    };
    (x & ((BigUint::one() << kept) - 1u32)) | (BigUint::one() << w)
}
pub fn sm2_associated_standard(c: &Curve, x: &BigUint) -> BigUint {
    let w = c.n.bits().div_ceil(2) as usize - 1;
    (x & ((BigUint::one() << w) - 1u32)) | (BigUint::one() << w)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Oracle {
    Ecdaa {
        curve: CurveId,
        private: Vec<u8>,
        hash: HashAlg,
        digest: Vec<u8>,
    },
    Zgen {
        curve: CurveId,
        private: Vec<u8>,
        scheme: ExchangeScheme,
    },
}
impl Oracle {
    pub fn check(&self, response: &[u8], program: &Program) -> Result<(), String> {
        let frames = program.transcript(response)?;
        if frames.len() != 2 {
            return Err("ECC envelope must contain two calls".into());
        }
        match self {
            Self::Ecdaa {
                curve,
                private,
                hash,
                digest,
            } => {
                let c = curve.curve();
                let cp = password_parameters(frames[0])?;
                let mut at = 0;
                let k = read_point(c, cp, &mut at, false)?.ok_or("missing K")?;
                let l = read_point(c, cp, &mut at, false)?.ok_or("missing L")?;
                let e = read_point(c, cp, &mut at, false)?.ok_or("missing E")?;
                if at + 2 != cp.len() {
                    return Err("Commit counter/trailing parameters".into());
                }
                let sig = password_parameters(frames[1])?;
                if sig.get(..4) != Some(&[0, 0x1a, (hash.alg_id() >> 8) as u8, hash.alg_id() as u8])
                {
                    return Err("ECDAA signature algorithm/hash".into());
                }
                let (nonce, next) = tpm::read_2b(sig, 4).ok_or("malformed nonceK")?;
                let (s, end) = tpm::read_2b(sig, next).ok_or("malformed s")?;
                if end != sig.len()
                    || nonce.first() == Some(&0)
                    || nonce.len() > c.order_bytes()
                    || s.len() != c.order_bytes()
                    || !c.valid_scalar(nonce)
                    || !c.valid_scalar(s)
                {
                    return Err("ECDAA scalar encoding/range".into());
                }
                let d = from_be(private);
                let t = from_be(&hash.digest(&[nonce, digest])) % &c.n;
                let r = (from_be(s) + &c.n - ((&t * &d) % &c.n)) % &c.n;
                if r.is_zero() {
                    return Err("zero Commit scalar".into());
                }
                let p2 = &commit_point(*curve).1;
                if c.mul(&d, p2).as_ref() != Some(&k)
                    || c.mul(&r, p2).as_ref() != Some(&l)
                    || c.mul_g(&r).as_ref() != Some(&e)
                {
                    return Err("Commit K/L/E equations differ".into());
                }
                let q = c.mul_g(&d).ok_or("invalid private scalar")?;
                if c.mul_g(&from_be(s)) != c.mul_add(&BigUint::one(), &e, &t, &q) {
                    return Err("ECDAA public equation differs".into());
                }
                Ok(())
            }
            Self::Zgen {
                curve,
                private,
                scheme,
            } => {
                let c = curve.curve();
                let ep = frame_parameters(frames[0], 0)?;
                let mut at = 0;
                let qe = read_point(c, ep, &mut at, false)?.ok_or("missing QeA")?;
                if at + 2 != ep.len() {
                    return Err("EC_Ephemeral counter/trailing parameters".into());
                }
                let z = password_parameters(frames[1])?;
                at = 0;
                let z1 = read_point(c, z, &mut at, false)?.ok_or("missing Z1")?;
                let z2 = read_point(c, z, &mut at, true)?;
                if at != z.len() {
                    return Err("ZGen trailing parameters".into());
                }
                let qs = c.mul_g(&from_be(private)).ok_or("invalid private scalar")?;
                let ds_b = BigUint::from(5u32);
                let de_b = BigUint::from(11u32);
                match scheme {
                    ExchangeScheme::Ecdh => {
                        if c.mul(&ds_b, &qs).as_ref() != Some(&z1) || c.mul(&de_b, &qe) != z2 {
                            return Err("ECDH two-phase equations differ".into());
                        }
                    }
                    ExchangeScheme::Sm2 => {
                        let qe_b = c.mul_g(&de_b).ok_or("peer point")?;
                        let t_b = (ds_b + de_b * sm2_associated_compat(c, &qe_b.x)) % &c.n;
                        let combined = c
                            .mul_add(&BigUint::one(), &qs, &sm2_associated_compat(c, &qe.x), &qe)
                            .ok_or("infinite SM2 intermediate")?;
                        if c.mul(&t_b, &combined).as_ref() != Some(&z1) || z2.is_some() {
                            return Err("SM2 vendored compatibility equation differs".into());
                        }
                    }
                    ExchangeScheme::Ecmqv => {
                        return Err("ECMQV known functional failure has no passing oracle".into());
                    }
                }
                Ok(())
            }
        }
    }
}
