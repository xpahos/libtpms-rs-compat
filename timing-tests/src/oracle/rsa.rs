use std::sync::OnceLock;

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::One;
use serde::{Deserialize, Serialize};

use super::bytes::{from_be, from_hex, to_fixed};
use super::hash::HashAlg;
use super::kdf::mgf1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RsaBits {
    B1024,
    B2048,
    B3072,
}

impl RsaBits {
    pub const ALL: [RsaBits; 3] = [Self::B1024, Self::B2048, Self::B3072];

    pub fn bits(self) -> usize {
        match self {
            Self::B1024 => 1024,
            Self::B2048 => 2048,
            Self::B3072 => 3072,
        }
    }

    pub fn bytes(self) -> usize {
        self.bits() / 8
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::B1024 => "rsa1024",
            Self::B2048 => "rsa2048",
            Self::B3072 => "rsa3072",
        }
    }

    pub fn key(self) -> &'static RsaKey {
        key(self)
    }
}

pub const PUBLIC_EXPONENT: u32 = 65537;

const PRIMES: [(RsaBits, &str, &str); 3] = [
    (
        RsaBits::B1024,
        "d1a495b417a8c58b54aad6211a58ccbef988f80fca0b20d8be788861fedca3e9802ab9178228d77d46ff19b9d729ab8e643da97224cb655ed0ef052ed4830e8d",
        "c8afa7d0a9cd830e40b478c9fa1ac3bdc87ce640dbdbfc4ef4b7dd7ffbab41eb415f95f5cf0befa94a0bf819bf94c920ad266c1418e3600e7d9d6e28bc70b089",
    ),
    (
        RsaBits::B2048,
        "eb804e2f45e63ca1d7757997e2eb1f14a040b800392abc44cce15a6214aa1a9bd8700ec79abde8a7be60a934310e5565088231ba7f9a9a7db84667f49352502fc5b2c6e710560d3a00182e0f5c103450780bbb45941f5176814d14b1b01f9ecf7d7b9234cf3360aaa6a688f9ea14b96c405a317b110f474d468be8a2e4e891cf",
        "d8f1587496f46b60db4b8cefdd40ee5988dff0004729e1a5eaf39fd3824e2ae406efd5d5f856cf91d16a9136691598e141aa7150d8740b086ca344a211dbfc58499527ec9fbb7dcf70b67328c5d43253b3d3e5628c8060031a372317ea6f6b6a060727947e677a22c09b6b1d006111a77b03fed4ae406092c043d0be6e44b2bd",
    ),
    (
        RsaBits::B3072,
        "f16032685aeee97977e982915a2f2b6b15b029dc61b2e1426843ee719e9227736d148e849325feb2959c9027f5e0841808d8aa3578a0ab2432e43ab7e8aa79040fefb5959df2e744b4b385818802a7c4cb27cb4095668a27aa5bb51a0604eac44d0a309199f13b8cd053586717d70d7b3406a926ee53f6832c1206b17f7acab31fb4cbb6c060a6165de5237d17eb6e9cee884ea36608c2154954bd15993606089ebb15074e45ccf93fef50b173fd1269fb9ed252373a05fa72f02308ebf92783",
        "d62596edbb3779dfc31b9961a5b4940fd3894c983087ee0bc3cc2213eab266c5d4c772812f6d674d85fb53ee08aea11a5b2273ab6f3b41595f6b0351c97f97bd0a58684225beabf185e3d5baf3f440aa0e12cc812aa2338905c64325c2486c9437def62a09f0006ec4ea192ba7f4a220cc89fcd27293f955945d2e69efa3bf10ed044cdb435fcc7b292f2ef04550aa850cd614837e5550dcba5ed19bae80e05e98cf51ce77f88664163ec2b46f4f3dfe1a07bd326bf4c0ab89a2ff1dbe07a89b",
    ),
];

#[derive(Debug)]
pub struct RsaKey {
    pub bits: RsaBits,
    pub n: BigUint,
    pub e: BigUint,
    pub d: BigUint,
    pub p: BigUint,
    pub q: BigUint,
}

pub fn key(bits: RsaBits) -> &'static RsaKey {
    static KEYS: OnceLock<Vec<RsaKey>> = OnceLock::new();
    KEYS.get_or_init(|| {
        PRIMES
            .iter()
            .map(|(bits, p, q)| {
                let p = from_hex(p);
                let q = from_hex(q);
                let n = &p * &q;
                let e = BigUint::from(PUBLIC_EXPONENT);
                let lambda = (&p - 1u32).lcm(&(&q - 1u32));
                let d = mod_inverse(&e, &lambda).expect("e is invertible");
                RsaKey {
                    bits: *bits,
                    n,
                    e,
                    d,
                    p,
                    q,
                }
            })
            .collect()
    })
    .iter()
    .find(|k| k.bits == bits)
    .expect("every size has a key")
}

fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    use num_bigint::BigInt;
    let (a, m) = (BigInt::from(a.clone()), BigInt::from(m.clone()));
    let gcd = a.extended_gcd(&m);
    if !gcd.gcd.is_one() {
        return None;
    }
    let mut x = gcd.x % &m;
    if x < BigInt::from(0) {
        x += &m;
    }
    x.to_biguint()
}

impl RsaKey {
    pub fn k(&self) -> usize {
        self.bits.bytes()
    }

    pub fn modulus(&self) -> Vec<u8> {
        to_fixed(&self.n, self.k())
    }

    pub fn prime(&self) -> Vec<u8> {
        to_fixed(&self.p, self.k() / 2)
    }

    pub fn private(&self, input: &[u8]) -> Option<Vec<u8>> {
        let c = from_be(input);
        (c < self.n).then(|| to_fixed(&c.modpow(&self.d, &self.n), self.k()))
    }

    pub fn public(&self, input: &[u8]) -> Option<Vec<u8>> {
        let m = from_be(input);
        (m < self.n).then(|| to_fixed(&m.modpow(&self.e, &self.n), self.k()))
    }
}

fn xor_into(target: &mut [u8], mask: &[u8]) {
    for (t, m) in target.iter_mut().zip(mask) {
        *t ^= m;
    }
}

pub fn oaep_encode(hash: HashAlg, label: &[u8], message: &[u8], seed: &[u8], k: usize) -> Vec<u8> {
    let h = hash.size();
    assert!(message.len() + 2 * h + 2 <= k, "message too long for OAEP");
    assert_eq!(seed.len(), h);
    let mut db = hash.digest(&[label]);
    db.resize(k - h - 1 - message.len() - 1, 0);
    db.push(1);
    db.extend_from_slice(message);
    let mut masked_seed = seed.to_vec();
    xor_into(&mut db, &mgf1(hash, seed, k - h - 1));
    xor_into(&mut masked_seed, &mgf1(hash, &db, h));
    let mut em = vec![0u8];
    em.extend(masked_seed);
    em.extend(db);
    em
}

pub fn oaep_unmask(hash: HashAlg, em: &[u8]) -> (u8, Vec<u8>) {
    let h = hash.size();
    let mut seed = em[1..1 + h].to_vec();
    let mut db = em[1 + h..].to_vec();
    xor_into(&mut seed, &mgf1(hash, &db, h));
    xor_into(&mut db, &mgf1(hash, &seed, em.len() - h - 1));
    (em[0], db)
}

pub fn oaep_decode(hash: HashAlg, label: &[u8], em: &[u8]) -> Option<Vec<u8>> {
    let h = hash.size();
    if em.len() < 2 * h + 2 {
        return None;
    }
    let (first, db) = oaep_unmask(hash, em);
    if first != 0 || db[..h] != hash.digest(&[label])[..] {
        return None;
    }
    let rest = &db[h..];
    let separator = rest.iter().position(|b| *b != 0)?;
    (rest[separator] == 1).then(|| rest[separator + 1..].to_vec())
}

pub fn pkcs1_type2_encode(message: &[u8], padding: &[u8], k: usize) -> Vec<u8> {
    assert_eq!(padding.len(), k - 3 - message.len());
    assert!(padding.iter().all(|b| *b != 0) && padding.len() >= 8);
    let mut em = vec![0u8, 2];
    em.extend_from_slice(padding);
    em.push(0);
    em.extend_from_slice(message);
    em
}

pub fn pkcs1_type2_decode(em: &[u8]) -> Option<Vec<u8>> {
    if em.len() < 11 || em[0] != 0 || em[1] != 2 {
        return None;
    }
    let separator = em[2..].iter().position(|b| *b == 0)? + 2;
    (separator >= 10).then(|| em[separator + 1..].to_vec())
}

pub fn digest_info_prefix(hash: HashAlg) -> &'static [u8] {
    match hash {
        HashAlg::Sha1 => &[
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
            0x14,
        ],
        HashAlg::Sha256 => &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ],
        HashAlg::Sha384 => &[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x02, 0x05, 0x00, 0x04, 0x30,
        ],
        HashAlg::Sha512 => &[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00, 0x04, 0x40,
        ],
    }
}

pub fn pkcs1_sign_encode(hash: HashAlg, digest: &[u8], k: usize) -> Vec<u8> {
    let prefix = digest_info_prefix(hash);
    let t_len = prefix.len() + digest.len();
    let mut em = vec![0u8, 1];
    em.resize(k - t_len - 1, 0xff);
    em.push(0);
    em.extend_from_slice(prefix);
    em.extend_from_slice(digest);
    em
}

pub fn pss_verify(hash: HashAlg, em: &[u8], digest: &[u8], mod_bits: usize) -> Option<usize> {
    let h = hash.size();
    let em_bits = mod_bits - 1;
    let em_len = em_bits.div_ceil(8);
    let em = &em[em.len() - em_len..];
    if em_len < h + 2 || *em.last()? != 0xbc {
        return None;
    }
    let top_mask = 0xffu8 >> (8 * em_len - em_bits);
    let (masked, rest) = em.split_at(em_len - h - 1);
    let h_value = &rest[..h];
    if masked[0] & !top_mask != 0 {
        return None;
    }
    let mut db = masked.to_vec();
    let mask = mgf1(hash, h_value, db.len());
    xor_into(&mut db, &mask);
    db[0] &= top_mask;
    let one = db.iter().position(|b| *b != 0)?;
    if db[one] != 1 {
        return None;
    }
    let salt = &db[one + 1..];
    let expected = hash.digest(&[&[0u8; 8], digest, salt]);
    (expected == h_value).then_some(salt.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_consistent() {
        for bits in RsaBits::ALL {
            let key = bits.key();
            assert_eq!(key.n.bits() as usize, bits.bits());
            assert_eq!(key.prime()[0] & 0x80, 0x80);
            assert_eq!(key.modulus()[0] & 0x80, 0x80);
            let m = vec![0x42u8; bits.bytes() - 1];
            let c = key.public(&m).unwrap();
            assert_eq!(key.private(&c).unwrap()[1..], m[..]);
            assert!(key.private(&key.modulus()).is_none());
            let _ = BigUint::one();
        }
    }

    #[test]
    fn oaep_round_trips_and_rejects_corruption() {
        let k = 128;
        let seed = vec![7u8; 32];
        let em = oaep_encode(HashAlg::Sha256, b"SECRET\0", b"hello", &seed, k);
        assert_eq!(em.len(), k);
        assert_eq!(
            oaep_decode(HashAlg::Sha256, b"SECRET\0", &em).unwrap(),
            b"hello"
        );
        assert!(oaep_decode(HashAlg::Sha256, b"SECRET", &em).is_none());
        let mut bad = em.clone();
        bad[0] = 1;
        assert!(oaep_decode(HashAlg::Sha256, b"SECRET\0", &bad).is_none());
    }

    #[test]
    fn pkcs1_round_trips() {
        let em = pkcs1_type2_encode(b"abc", &[0x5a; 125 - 3], 128);
        assert_eq!(pkcs1_type2_decode(&em).unwrap(), b"abc");
        let mut short = em.clone();
        short[4] = 0;
        assert!(pkcs1_type2_decode(&short).is_none());
    }

    #[test]
    fn pss_verification_matches_its_encoding() {
        let hash = HashAlg::Sha256;
        let digest = hash.digest(&[b"m"]);
        let salt = [3u8; 32];
        let k = 256;
        let h_value = hash.digest(&[&[0u8; 8], &digest, &salt]);
        let mut db = vec![0u8; k - 32 - 1 - 32 - 1];
        db.push(1);
        db.extend_from_slice(&salt);
        xor_into(&mut db, &mgf1(hash, &h_value, k - 32 - 1));
        db[0] &= 0x7f;
        let mut em = db;
        em.extend_from_slice(&h_value);
        em.push(0xbc);
        assert_eq!(pss_verify(hash, &em, &digest, 2048), Some(32));
        em[10] ^= 1;
        assert_eq!(pss_verify(hash, &em, &digest, 2048), None);
    }
}

/// Independent OpenSSL implicit-rejection v1 oracle using libtpms's imported d rule.
pub fn implicit_rejection(key: &RsaKey, ciphertext: &[u8]) -> Vec<u8> {
    let k = key.k();
    assert_eq!(
        ciphertext.len(),
        k,
        "implicit oracle requires full-width ciphertext"
    );
    let d = if key.bits.bits() < 2048
        || key.e.bits() <= 16
        || key.d.bits() <= (key.bits.bits() / 2) as u64
    {
        mod_inverse(&key.e, &((&key.p - 1u32) * (&key.q - 1u32)))
            .expect("fixture exponent invertible")
    } else {
        key.d.clone()
    };
    let dh = HashAlg::Sha256.digest(&[&to_fixed(&d, k)]);
    let kdk = HashAlg::Sha256.hmac(&dh, &[ciphertext]);
    implicit_from_kdk(k, &kdk)
}

fn implicit_from_kdk(k: usize, kdk: &[u8]) -> Vec<u8> {
    let prf = |label: &[u8], len: usize| {
        let mut output = Vec::new();
        for i in 0..len.div_ceil(32) {
            output.extend(HashAlg::Sha256.hmac(
                kdk,
                &[
                    &(i as u16).to_be_bytes(),
                    label,
                    &((len * 8) as u16).to_be_bytes(),
                ],
            ));
        }
        output.truncate(len);
        output
    };
    let message = prf(b"message", k);
    let lengths = prf(b"length", 256);
    let bound = k - 10;
    let mut mask = bound;
    for shift in [1, 2, 4, 8] {
        mask |= mask >> shift;
    }
    let mut length = 0;
    for word in lengths.chunks_exact(2) {
        let candidate = u16::from_be_bytes([word[0], word[1]]) as usize & mask;
        if candidate < bound {
            length = candidate;
        }
    }
    message[k - length..].to_vec()
}

#[cfg(test)]
mod implicit_tests {
    use super::*;
    #[test]
    fn synthetic_plaintext_matches_independent_python_vectors_all_key_sizes() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/rsaes-implicit-v1.json"))
                .unwrap();
        for vector in fixture["vectors"].as_array().unwrap() {
            if vector["padding_valid"] == true {
                continue;
            }
            let bits = match vector["bits"].as_u64().unwrap() {
                1024 => RsaBits::B1024,
                2048 => RsaBits::B2048,
                _ => RsaBits::B3072,
            };
            let ciphertext = hex::decode(vector["ciphertext_hex"].as_str().unwrap()).unwrap();
            assert_eq!(
                hex::encode(implicit_rejection(bits.key(), &ciphertext)),
                vector["expected_plaintext_hex"].as_str().unwrap(),
                "{bits:?}/{}",
                vector["selector"]
            );
        }
    }
}
