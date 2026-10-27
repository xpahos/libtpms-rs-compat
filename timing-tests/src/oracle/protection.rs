//! Independent TPM duplication/private wrapping using test-side primitives.
use super::{
    bytes::{from_be, to_fixed},
    hash::HashAlg,
    kdf::{kdfa, kdfe},
    rsa::{oaep_decode, oaep_encode},
    sym::{self, SymKey, SymMode},
};
use crate::{scenario::catalog::AsymKind, tpm};

pub const HASH: HashAlg = HashAlg::Sha256;
pub const PARENT_SEED: [u8; 32] = [0x73; 32];
const PARENT_SCALAR: u32 = 7;

pub fn parent_material(kind: AsymKind) -> (tpm::Public, Vec<u8>) {
    let (detail, secret) = match kind {
        AsymKind::Rsa(bits) => (
            tpm::PublicDetail::Rsa {
                symmetric: tpm::SymDef::aes128_cfb(),
                scheme: tpm::Scheme::Null,
                bits: bits.bits() as u16,
                modulus: bits.key().modulus(),
            },
            bits.key().prime(),
        ),
        AsymKind::Ecc(id) => {
            let c = id.curve();
            let (x, y) = c.encode(&c.mul_g(&PARENT_SCALAR.into()).unwrap());
            (
                tpm::PublicDetail::Ecc {
                    symmetric: tpm::SymDef::aes128_cfb(),
                    scheme: tpm::Scheme::Null,
                    curve: id.tpm_id(),
                    x,
                    y,
                },
                to_fixed(&PARENT_SCALAR.into(), id.key_bytes()),
            )
        }
    };
    let public = tpm::Public {
        name_alg: HASH.alg_id(),
        attributes: tpm::ATTR_RESTRICTED
            | tpm::ATTR_DECRYPT
            | tpm::ATTR_USER_WITH_AUTH
            | tpm::ATTR_NO_DA,
        detail,
    };
    let sensitive = tpm::sensitive(public.object_type(), &[], &PARENT_SEED, &secret);
    (public, sensitive)
}

pub fn encrypt_seed(kind: AsymKind) -> (Vec<u8>, Vec<u8>) {
    match kind {
        AsymKind::Rsa(bits) => {
            let seed = vec![0x5a; 32];
            let em = oaep_encode(HASH, b"DUPLICATE\0", &seed, &[0x4b; 32], bits.bytes());
            (seed, bits.key().public(&em).unwrap())
        }
        AsymKind::Ecc(id) => {
            let c = id.curve();
            let ephemeral = c.mul_g(&11u32.into()).unwrap();
            let (x, y) = c.encode(&ephemeral);
            let (parent_x, _) = c.encode(&c.mul_g(&PARENT_SCALAR.into()).unwrap());
            let (z, _) = c.encode(&c.mul(&PARENT_SCALAR.into(), &ephemeral).unwrap());
            let seed = kdfe(HASH, &z, b"DUPLICATE", &x, &parent_x, 256);
            let mut encoded = tpm::sized(&x);
            tpm::put_2b(&mut encoded, &y);
            (seed, encoded)
        }
    }
}

pub fn decrypt_seed(kind: AsymKind, encoded: &[u8]) -> Result<Vec<u8>, String> {
    let seed = match kind {
        AsymKind::Rsa(bits) => {
            if encoded.len() != bits.bytes() {
                return Err("RSA seed width".into());
            }
            let em = bits.key().private(encoded).ok_or("RSA seed range")?;
            oaep_decode(HASH, b"DUPLICATE\0", &em).ok_or("RSA seed OAEP")?
        }
        AsymKind::Ecc(id) => {
            let (x, next) = tpm::read_2b(encoded, 0).ok_or("seed x")?;
            let (y, end) = tpm::read_2b(encoded, next).ok_or("seed y")?;
            if end != encoded.len() || x.len() != id.key_bytes() || y.len() != id.key_bytes() {
                return Err("ECC seed widths".into());
            }
            let c = id.curve();
            let q = c.decode(x, y);
            if !c.on_curve(&q) {
                return Err("ECC seed point".into());
            }
            let shared = c
                .mul(&from_be(&PARENT_SCALAR.to_be_bytes()), &q)
                .ok_or("ECC seed infinity")?;
            let (z, _) = c.encode(&shared);
            let (parent_x, _) = c.encode(&c.mul_g(&PARENT_SCALAR.into()).unwrap());
            kdfe(HASH, &z, b"DUPLICATE", x, &parent_x, 256)
        }
    };
    if seed.len() != 32 {
        return Err("seed digest width".into());
    }
    Ok(seed)
}

pub fn cfb(key: &[u8], iv: &[u8], data: &[u8], encrypt: bool) -> Vec<u8> {
    sym::crypt(SymKey::Aes128, SymMode::Cfb, key, iv, data, encrypt).0
}

pub fn inner_wrap(sensitive: &[u8], name: &[u8], key: &[u8], delta: &[u8]) -> Vec<u8> {
    let mut integrity = HASH.digest(&[sensitive, name]);
    for (byte, xor) in integrity.iter_mut().zip(delta) {
        *byte ^= xor;
    }
    let mut plain = tpm::sized(&integrity);
    plain.extend_from_slice(sensitive);
    cfb(key, &[0; 16], &plain, true)
}

pub fn inner_unwrap(blob: &[u8], name: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 16 {
        return Err("inner key width".into());
    }
    let plain = cfb(key, &[0; 16], blob, false);
    let (digest, at) = tpm::read_2b(&plain, 0).ok_or("inner digest framing")?;
    let sensitive = &plain[at..];
    if digest != HASH.digest(&[sensitive, name]) {
        return Err("inner integrity".into());
    }
    Ok(sensitive.to_vec())
}

pub fn outer_wrap(payload: &[u8], name: &[u8], seed: &[u8]) -> Vec<u8> {
    let key = kdfa(HASH, seed, b"STORAGE", name, &[], 128);
    let integrity_key = kdfa(HASH, seed, b"INTEGRITY", &[], &[], 256);
    let cipher = cfb(&key, &[0; 16], payload, true);
    let mut blob = tpm::sized(&HASH.hmac(&integrity_key, &[&cipher, name]));
    blob.extend(cipher);
    blob
}

pub fn outer_unwrap(
    blob: &[u8],
    name: &[u8],
    seed: &[u8],
    private: bool,
) -> Result<Vec<u8>, String> {
    let (integrity, at) = tpm::read_2b(blob, 0).ok_or("outer HMAC framing")?;
    let protected = &blob[at..];
    let integrity_key = kdfa(HASH, seed, b"INTEGRITY", &[], &[], 256);
    if integrity != HASH.hmac(&integrity_key, &[protected, name]) {
        return Err("outer HMAC".into());
    }
    let zero = [0; 16];
    let (iv, cipher) = if private {
        let (iv, at) = tpm::read_2b(protected, 0).ok_or("private IV framing")?;
        if iv.len() != 16 {
            return Err("private IV width".into());
        }
        (iv, &protected[at..])
    } else {
        (&zero[..], protected)
    };
    let key = kdfa(HASH, seed, b"STORAGE", name, &[], 128);
    Ok(cfb(&key, iv, cipher, false))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wrapping_oracle_rejects_wrong_name_digest_ciphertext_and_trailing_bytes() {
        let sensitive = tpm::sized(&tpm::sensitive(
            tpm::TPM_ALG_KEYEDHASH,
            &[1; 32],
            &[2; 32],
            &[3; 32],
        ));
        let name = [4; 34];
        let key = [5; 16];
        let seed = [6; 32];
        let inner = inner_wrap(&sensitive, &name, &key, &[0; 32]);
        assert_eq!(inner.len(), 140);
        assert_eq!(inner_unwrap(&inner, &name, &key).unwrap(), sensitive);
        for index in [0, 2, 33, 34, 139] {
            let mut bad = inner.clone();
            bad[index] ^= 1;
            assert!(inner_unwrap(&bad, &name, &key).is_err());
        }
        let outer = outer_wrap(&inner, &name, &seed);
        assert_eq!(outer.len(), 174);
        assert_eq!(outer_unwrap(&outer, &name, &seed, false).unwrap(), inner);
        for index in [0, 2, 33, 34, 173] {
            let mut bad = outer.clone();
            bad[index] ^= 1;
            assert!(outer_unwrap(&bad, &name, &seed, false).is_err());
        }
        assert!(outer_unwrap(&outer, &[8; 34], &seed, false).is_err());
        let mut trailing = outer;
        trailing.push(0);
        assert!(outer_unwrap(&trailing, &name, &seed, false).is_err());
    }
    #[test]
    fn seed_oracle_round_trip_rejects_wrong_labels_and_points() {
        for kind in crate::scenario::catalog::storage_kinds() {
            let (seed, encoded) = encrypt_seed(kind);
            assert_eq!(decrypt_seed(kind, &encoded).unwrap(), seed, "{kind:?}");
            let mut short = encoded.clone();
            short.pop();
            assert!(decrypt_seed(kind, &short).is_err());
            if let AsymKind::Rsa(bits) = kind {
                let wrong = oaep_encode(HASH, b"SECRET\0", &seed, &[0x4b; 32], bits.bytes());
                assert!(decrypt_seed(kind, &bits.key().public(&wrong).unwrap()).is_err());
            }
        }
    }
}
