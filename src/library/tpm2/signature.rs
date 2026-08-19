use crate::ffi_types::TpmResult;
use crate::library::constants::{
    TPM_RC_FAILURE, TPM_RC_HASH, TPM_RC_NO_RESULT, TPM_RC_SCHEME, TPM_RC_SIZE, TPM_RC_VALUE,
};

use super::algorithm::{
    TPM_ALG_ECC, TPM_ALG_ECDAA, TPM_ALG_ECDSA, TPM_ALG_ECSCHNORR, TPM_ALG_HMAC, TPM_ALG_KEYEDHASH,
    TPM_ALG_NULL, TPM_ALG_RSA, TPM_ALG_RSAPSS, TPM_ALG_RSASSA, TPM_ALG_SHA1, TPM_ALG_SHA256,
    TPM_ALG_SHA384, TPM_ALG_SHA512, TPM_ALG_SM2, algorithm_enabled, algorithm_profile_name,
};
use super::crypto::{
    BigUint, CurveParameters, HmacState, SeededRand, curve_parameters, kdfa, kdfa_from, mgf1,
    rsa_private_key_op,
};
use super::marshal::BlobWriter;
use super::persistent::{OwnedObjectBody, OwnedPublicId, OwnedSecret};
use super::profile::ValidatedProfile;
use super::public::{PublicParms, Scheme};
use super::state::COMMIT_ARRAY_SIZE;
use super::template::{TemplateReader, digest_size};
use super::ticket::CONTEXT_INTEGRITY_HASH_ALG;

const COMMIT_STRING: &[u8] = b"ECDAA Commit\0";
const COMMIT_INDEX_MASK: u16 = (COMMIT_ARRAY_SIZE as u16 * 8) - 1;
const SIGN_ATTEMPTS: u32 = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SigScheme {
    pub(super) scheme: u16,
    pub(super) hash_alg: u16,
    pub(super) count: u16,
}

impl SigScheme {
    pub(super) const NULL: Self = Self {
        scheme: TPM_ALG_NULL,
        hash_alg: TPM_ALG_NULL,
        count: 0,
    };
}

pub(super) fn parse_sig_scheme(
    reader: &mut TemplateReader<'_>,
    profile: &ValidatedProfile,
) -> Result<SigScheme, TpmResult> {
    let scheme = reader.u16()?;
    if scheme == TPM_ALG_NULL {
        return Ok(SigScheme::NULL);
    }
    if !is_signature_scheme(scheme) {
        return Err(TPM_RC_SCHEME);
    }
    if !profile_enables(profile, scheme) {
        return Err(TPM_RC_SCHEME);
    }
    let hash_alg = reader.u16()?;
    if digest_size(hash_alg).is_none() {
        return Err(TPM_RC_HASH);
    }
    if !profile_enables(profile, hash_alg) {
        return Err(TPM_RC_HASH);
    }
    let count = if scheme == TPM_ALG_ECDAA {
        reader.u16()?
    } else {
        0
    };
    Ok(SigScheme {
        scheme,
        hash_alg,
        count,
    })
}

fn profile_enables(profile: &ValidatedProfile, algorithm: u16) -> bool {
    algorithm_profile_name(algorithm)
        .is_some_and(|name| algorithm_enabled(&profile.algorithms, name))
}

const fn is_signature_scheme(scheme: u16) -> bool {
    matches!(
        scheme,
        TPM_ALG_RSASSA
            | TPM_ALG_RSAPSS
            | TPM_ALG_ECDSA
            | TPM_ALG_ECDAA
            | TPM_ALG_ECSCHNORR
            | TPM_ALG_SM2
            | TPM_ALG_HMAC
    )
}

const fn is_split_sign(scheme: u16) -> bool {
    matches!(scheme, TPM_ALG_ECDAA)
}

pub(super) const fn is_anonymous_scheme(scheme: u16) -> bool {
    matches!(scheme, TPM_ALG_ECDAA)
}

pub(super) fn is_signing_object(body: &OwnedObjectBody) -> bool {
    const TPMA_OBJECT_SIGN: u32 = 1 << 18;
    body.public.object_attributes & TPMA_OBJECT_SIGN != 0
        && body.public.object_type != super::public::TPM_ALG_SYMCIPHER
}

fn object_scheme(body: &OwnedObjectBody) -> Option<Scheme> {
    match &body.public.parameters {
        PublicParms::Rsa { scheme, .. } | PublicParms::Ecc { scheme, .. } => Some(*scheme),
        PublicParms::KeyedHash(scheme) => Some(*scheme),
        PublicParms::SymCipher(_) => None,
    }
}

fn scheme_is_valid_for(object_type: u16, scheme: &SigScheme) -> bool {
    if digest_size(scheme.hash_alg).is_none() {
        return false;
    }
    match object_type {
        TPM_ALG_RSA => matches!(scheme.scheme, TPM_ALG_RSASSA | TPM_ALG_RSAPSS),
        TPM_ALG_ECC => matches!(
            scheme.scheme,
            TPM_ALG_ECDSA | TPM_ALG_ECDAA | TPM_ALG_ECSCHNORR | TPM_ALG_SM2
        ),
        TPM_ALG_KEYEDHASH => scheme.scheme == TPM_ALG_HMAC,
        _ => false,
    }
}

pub(super) fn select_sign_scheme(
    body: Option<&OwnedObjectBody>,
    requested: SigScheme,
) -> Option<SigScheme> {
    let Some(body) = body else {
        return Some(SigScheme::NULL);
    };
    let stored = object_scheme(body)?;
    let object_type = body.public.object_type;

    let selected = if stored.scheme == TPM_ALG_NULL {
        if requested.scheme == TPM_ALG_NULL {
            return None;
        }
        requested
    } else if requested.scheme == TPM_ALG_NULL {
        if is_split_sign(stored.scheme) {
            return None;
        }
        SigScheme {
            scheme: stored.scheme,
            hash_alg: stored.hash_alg.unwrap_or(TPM_ALG_NULL),
            count: 0,
        }
    } else {
        if stored.scheme != requested.scheme
            || stored.hash_alg.unwrap_or(TPM_ALG_NULL) != requested.hash_alg
        {
            return None;
        }
        requested
    };

    if scheme_is_valid_for(object_type, &selected) {
        Some(selected)
    } else {
        None
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Signature {
    Null,
    Rsa {
        scheme: u16,
        hash_alg: u16,
        signature: Vec<u8>,
    },
    Ecc {
        scheme: u16,
        hash_alg: u16,
        r: Vec<u8>,
        s: Vec<u8>,
    },
    Hmac {
        hash_alg: u16,
        digest: Vec<u8>,
    },
}

pub(super) fn marshal_signature(signature: &Signature) -> Vec<u8> {
    let mut writer = BlobWriter::new();
    match signature {
        Signature::Null => writer.write_u16(TPM_ALG_NULL),
        Signature::Rsa {
            scheme,
            hash_alg,
            signature,
        } => {
            writer.write_u16(*scheme);
            writer.write_u16(*hash_alg);
            writer.write_u16(signature.len() as u16);
            writer.write_bytes(signature);
        }
        Signature::Ecc {
            scheme,
            hash_alg,
            r,
            s,
        } => {
            writer.write_u16(*scheme);
            writer.write_u16(*hash_alg);
            writer.write_u16(r.len() as u16);
            writer.write_bytes(r);
            writer.write_u16(s.len() as u16);
            writer.write_bytes(s);
        }
        Signature::Hmac { hash_alg, digest } => {
            writer.write_u16(TPM_ALG_HMAC);
            writer.write_u16(*hash_alg);
            writer.write_bytes(digest);
        }
    }
    writer.into_bytes()
}

const fn der_oid(hash_alg: u16) -> Option<&'static [u8]> {
    Some(match hash_alg {
        TPM_ALG_SHA1 => &[0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a],
        TPM_ALG_SHA256 => &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ],
        TPM_ALG_SHA384 => &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        ],
        TPM_ALG_SHA512 => &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
        ],
        _ => return None,
    })
}

fn der_tag(hash_alg: u16) -> Option<Vec<u8>> {
    let oid = der_oid(hash_alg)?;
    let digest = digest_size(hash_alg)?;
    let mut out = Vec::with_capacity(oid.len() + 8);
    out.push(0x30);
    out.push((6 + oid.len() + digest) as u8);
    out.push(0x30);
    out.push((2 + oid.len()) as u8);
    out.extend_from_slice(oid);
    out.push(0x05);
    out.push(0x00);
    out.push(0x04);
    out.push(digest as u8);
    Some(out)
}

fn rsassa_encode(modulus_size: usize, hash_alg: u16, digest: &[u8]) -> Result<Vec<u8>, TpmResult> {
    let der = der_tag(hash_alg).ok_or(TPM_RC_SCHEME)?;
    if digest_size(hash_alg) != Some(digest.len()) {
        return Err(TPM_RC_VALUE);
    }
    let fill = modulus_size
        .checked_sub(der.len() + digest.len() + 3)
        .ok_or(TPM_RC_SIZE)?;
    if fill < 8 {
        return Err(TPM_RC_SIZE);
    }
    let mut out = Vec::with_capacity(modulus_size);
    out.push(0x00);
    out.push(0x01);
    out.extend(core::iter::repeat_n(0xff, fill));
    out.push(0x00);
    out.extend_from_slice(&der);
    out.extend_from_slice(digest);
    Ok(out)
}

pub(super) fn pss_salt_size(hash_size: usize, out_size: usize) -> usize {
    let salt = (out_size as isize) - (hash_size as isize) - 2;
    if salt < 0 {
        0
    } else if salt as usize > hash_size {
        hash_size
    } else {
        salt as usize
    }
}

fn pss_encode(
    modulus_size: usize,
    hash_alg: u16,
    digest: &[u8],
    salt: &[u8],
) -> Result<Vec<u8>, TpmResult> {
    let hash_len = digest_size(hash_alg).ok_or(TPM_RC_SCHEME)?;
    let mask_len = modulus_size.checked_sub(hash_len + 1).ok_or(TPM_RC_SIZE)?;

    let mut hasher = super::crypto::Hasher::new(hash_alg).ok_or(TPM_RC_SCHEME)?;
    hasher.update(&[0u8; 8]);
    hasher.update(digest);
    hasher.update(salt);
    let h = hasher.finalize();

    let mut out = vec![0u8; modulus_size];
    out[modulus_size - hash_len - 1..modulus_size - 1].copy_from_slice(&h);

    let mask = mgf1(hash_alg, &h, mask_len).ok_or(TPM_RC_SCHEME)?;
    out[..mask_len].copy_from_slice(&mask);
    out[0] &= 0x7f;
    out[modulus_size - 1] = 0xbc;

    let db_start = mask_len - salt.len() - 1;
    out[db_start] ^= 0x01;
    for (index, byte) in salt.iter().enumerate() {
        out[db_start + 1 + index] ^= byte;
    }
    Ok(out)
}

fn rsa_key_parts(body: &OwnedObjectBody) -> Option<(BigUint, BigUint, BigUint, BigUint, BigUint)> {
    let prime = body.sensitive.sensitive.as_ref()?;
    let exponent = body.private_exponent.as_ref()?;
    let p = BigUint::from_be_bytes(prime.as_bytes());
    let q = limbs_to_big(exponent.primes[0].data.as_bytes());
    let d_p = limbs_to_big(exponent.primes[1].data.as_bytes());
    let d_q = limbs_to_big(exponent.primes[2].data.as_bytes());
    let q_inv = limbs_to_big(exponent.primes[3].data.as_bytes());
    Some((p, q, d_p, d_q, q_inv))
}

fn limbs_to_big(data: &[u8]) -> BigUint {
    let mut value = BigUint::zero();
    for (index, chunk) in data.chunks_exact(8).enumerate() {
        let limb = u64::from_be_bytes(chunk.try_into().expect("eight bytes"));
        value = value.add(&BigUint::from_u64(limb).shl(index * 64));
    }
    value
}

fn rsa_modulus(body: &OwnedObjectBody) -> Option<&[u8]> {
    match &body.public.unique {
        OwnedPublicId::Rsa(modulus) => Some(modulus),
        _ => None,
    }
}

fn rsa_sign(
    body: &OwnedObjectBody,
    scheme: &SigScheme,
    digest: &[u8],
    rand: &mut SeededRand,
) -> Result<Signature, TpmResult> {
    let modulus_bytes = rsa_modulus(body).ok_or(TPM_RC_FAILURE)?.to_vec();
    let modulus_size = modulus_bytes.len();
    let encoded = match scheme.scheme {
        TPM_ALG_RSASSA => rsassa_encode(modulus_size, scheme.hash_alg, digest)?,
        TPM_ALG_RSAPSS => {
            let hash_len = digest_size(scheme.hash_alg).ok_or(TPM_RC_SCHEME)?;
            let mut salt = vec![0u8; pss_salt_size(hash_len, modulus_size)];
            match rand.generate(&mut salt) {
                Ok(()) => {}
                Err(_) if rand.live_entropy_starved() => {}
                Err(code) => return Err(code),
            }
            pss_encode(modulus_size, scheme.hash_alg, digest, &salt)?
        }
        _ => return Err(TPM_RC_SCHEME),
    };

    let (p, q, d_p, d_q, q_inv) = rsa_key_parts(body).ok_or(TPM_RC_FAILURE)?;
    let value = BigUint::from_be_bytes(&encoded);
    let signed = rsa_private_key_op(&p, &q, &d_p, &d_q, &q_inv, &value).ok_or(TPM_RC_FAILURE)?;
    let signature = signed.to_be_bytes(modulus_size).ok_or(TPM_RC_FAILURE)?;

    Ok(Signature::Rsa {
        scheme: scheme.scheme,
        hash_alg: scheme.hash_alg,
        signature,
    })
}

pub(super) struct SigningState {
    pub(super) rand: SeededRand,
    pub(super) commit_counter: u64,
    pub(super) commit_nonce: OwnedSecret,
    pub(super) commit_array: [u8; COMMIT_ARRAY_SIZE],
}

fn ecc_sign(
    body: &OwnedObjectBody,
    scheme: &SigScheme,
    digest: &[u8],
    state: &mut SigningState,
) -> Result<Signature, TpmResult> {
    let PublicParms::Ecc { curve_id, .. } = body.public.parameters else {
        return Err(TPM_RC_FAILURE);
    };
    let curve = curve_parameters(curve_id).ok_or(TPM_RC_VALUE)?;
    let d = BigUint::from_be_bytes(
        body.sensitive
            .sensitive
            .as_ref()
            .ok_or(TPM_RC_FAILURE)?
            .as_bytes(),
    );
    let order_bytes = curve.order.bit_len().div_ceil(8);

    if scheme.scheme == TPM_ALG_ECDAA {
        return ecdaa_sign(body, &curve, &d, digest, scheme, state);
    }
    let (r, s) = match scheme.scheme {
        TPM_ALG_ECDSA => ecdsa_sign(&curve, &d, digest, &mut state.rand)?,
        TPM_ALG_ECSCHNORR => ecschnorr_sign(&curve, &d, digest, scheme.hash_alg, &mut state.rand)?,
        TPM_ALG_SM2 => sm2_sign(&curve, &d, digest, &mut state.rand)?,
        _ => return Err(TPM_RC_SCHEME),
    };
    Ok(Signature::Ecc {
        scheme: scheme.scheme,
        hash_alg: scheme.hash_alg,
        r: r.to_be_bytes(order_bytes).ok_or(TPM_RC_FAILURE)?,
        s: s.to_be_bytes(order_bytes).ok_or(TPM_RC_FAILURE)?,
    })
}

fn ecdsa_sign(
    curve: &CurveParameters,
    d: &BigUint,
    digest: &[u8],
    rand: &mut SeededRand,
) -> Result<(BigUint, BigUint), TpmResult> {
    let z = ecdsa_digest(digest, curve.order.bit_len());
    for _ in 0..SIGN_ATTEMPTS {
        let k = random_in_order(rand, &curve.order)?;
        let Some((x, _)) = curve.multiply_generator(&k) else {
            continue;
        };
        let Some(r) = x.rem(&curve.order) else {
            continue;
        };
        if r.is_zero() {
            continue;
        }
        let Some(k_inv) = k.mod_inverse(&curve.order) else {
            continue;
        };
        let Some(s) = r
            .mod_mul(d, &curve.order)
            .and_then(|rd| z.mod_add(&rd, &curve.order))
            .and_then(|sum| k_inv.mod_mul(&sum, &curve.order))
        else {
            continue;
        };
        if s.is_zero() {
            continue;
        }
        return Ok((r, s));
    }
    Err(TPM_RC_NO_RESULT)
}

fn ecschnorr_sign(
    curve: &CurveParameters,
    d: &BigUint,
    digest: &[u8],
    hash_alg: u16,
    rand: &mut SeededRand,
) -> Result<(BigUint, BigUint), TpmResult> {
    let digest_len = digest_size(hash_alg).ok_or(TPM_RC_SCHEME)?;
    let order_bytes = curve.order.bit_len().div_ceil(8);
    for _ in 0..SIGN_ATTEMPTS {
        let k = random_in_order(rand, &curve.order)?;
        let Some((x, _)) = curve.multiply_generator(&k) else {
            continue;
        };
        let Some(e) = x.to_be_bytes(order_bytes) else {
            continue;
        };
        let mut hasher = super::crypto::Hasher::new(hash_alg).ok_or(TPM_RC_SCHEME)?;
        hasher.update(&e);
        hasher.update(digest);
        let mut hash = hasher.finalize();
        hash.truncate(digest_len.min(order_bytes));
        let r = BigUint::from_be_bytes(&hash);
        if let Some(s) = schnorr_s(&r, &k, d, &curve.order) {
            return Ok((r, s));
        }
    }
    Err(TPM_RC_NO_RESULT)
}

fn sm2_sign(
    curve: &CurveParameters,
    d: &BigUint,
    digest: &[u8],
    rand: &mut SeededRand,
) -> Result<(BigUint, BigUint), TpmResult> {
    let e = BigUint::from_be_bytes(digest);
    let inverse = d
        .add_u64(1)
        .mod_inverse(&curve.order)
        .ok_or(TPM_RC_NO_RESULT)?;
    for _ in 0..SIGN_ATTEMPTS {
        let k = random_below(rand, &curve.order)?;
        let Some((x, _)) = curve.multiply_generator(&k) else {
            continue;
        };
        let Some(r) = e.mod_add(&x, &curve.order) else {
            continue;
        };
        if r.is_zero() {
            continue;
        }
        let Some(s) = r
            .mod_mul(d, &curve.order)
            .and_then(|rd| curve.order.mod_sub(&rd, &curve.order))
            .and_then(|negated| k.mod_add(&negated, &curve.order))
            .and_then(|sum| sum.mod_mul(&inverse, &curve.order))
        else {
            continue;
        };
        if s.is_zero() {
            continue;
        }
        return Ok((r, s));
    }
    Err(TPM_RC_NO_RESULT)
}

fn ecdaa_sign(
    body: &OwnedObjectBody,
    curve: &CurveParameters,
    d: &BigUint,
    digest: &[u8],
    scheme: &SigScheme,
    state: &mut SigningState,
) -> Result<Signature, TpmResult> {
    let order_bytes = curve.order.byte_len();
    let commit = generate_r(state, curve, &body.name, scheme.count).ok_or(TPM_RC_VALUE)?;
    for _ in 0..SIGN_ATTEMPTS {
        let nonce = random_in_order(&mut state.rand, &curve.order)?;
        let nonce_bytes = nonce.to_be_bytes(nonce.byte_len()).ok_or(TPM_RC_FAILURE)?;
        let mut hasher = super::crypto::Hasher::new(scheme.hash_alg).ok_or(TPM_RC_SCHEME)?;
        hasher.update(&nonce_bytes);
        hasher.update(digest);
        let t = BigUint::from_be_bytes(&hasher.finalize());
        if let Some(s) = schnorr_s(&t, &commit, d, &curve.order) {
            end_commit(state, scheme.count);
            return Ok(Signature::Ecc {
                scheme: TPM_ALG_ECDAA,
                hash_alg: scheme.hash_alg,
                r: nonce_bytes,
                s: s.to_be_bytes(order_bytes).ok_or(TPM_RC_FAILURE)?,
            });
        }
    }
    Err(TPM_RC_NO_RESULT)
}

fn schnorr_s(value: &BigUint, k: &BigUint, d: &BigUint, order: &BigUint) -> Option<BigUint> {
    let reduced = value.rem(order)?;
    if reduced.is_zero() {
        return None;
    }
    let s = reduced.mul(d).add(k).rem(order)?;
    if s.is_zero() { None } else { Some(s) }
}

fn commit_slot(count: u16) -> (usize, u8) {
    let bit = count & COMMIT_INDEX_MASK;
    (usize::from(bit >> 3), 1u8 << (bit & 7))
}

fn commit_counter_for(state: &SigningState, count: u16) -> Option<u64> {
    let (byte, mask) = commit_slot(count);
    if state.commit_array[byte] & mask == 0 {
        return None;
    }
    let mut current = state.commit_counter;
    if (count & COMMIT_INDEX_MASK) >= (current as u16 & COMMIT_INDEX_MASK) {
        current = current.wrapping_sub(u64::from(COMMIT_INDEX_MASK) + 1);
    }
    if (current as u16) & !COMMIT_INDEX_MASK != count & !COMMIT_INDEX_MASK {
        return None;
    }
    Some((current & 0xffff_ffff_ffff_0000) | u64::from(count))
}

fn end_commit(state: &mut SigningState, count: u16) {
    let (byte, mask) = commit_slot(count);
    state.commit_array[byte] &= !mask;
}

fn generate_r(
    state: &SigningState,
    curve: &CurveParameters,
    name: &[u8],
    count: u16,
) -> Option<BigUint> {
    let order_bytes = curve.order.byte_len();
    let context_v = commit_counter_for(state, count)?.to_be_bytes();
    let bits = u32::try_from(order_bytes.checked_mul(8)?).ok()?;
    let mut counter: u32 = 1;
    for _ in 0..SIGN_ATTEMPTS {
        let stream = kdfa_from(
            CONTEXT_INTEGRITY_HASH_ALG,
            state.commit_nonce.as_bytes(),
            COMMIT_STRING,
            name,
            &context_v,
            bits,
            &mut counter,
        )?;
        if BigUint::from_be_bytes(&stream) >= curve.order {
            continue;
        }
        if stream[..=order_bytes / 2].iter().any(|&byte| byte != 0) {
            return Some(BigUint::from_be_bytes(&stream));
        }
    }
    None
}

fn ecdsa_digest(digest: &[u8], order_bits: usize) -> BigUint {
    let bytes = truncate_digest(digest, order_bits);
    let mut value = BigUint::from_be_bytes(&bytes);
    if bytes.len() * 8 > order_bits {
        value = value.shr(8 - (order_bits & 7));
    }
    value
}

fn truncate_digest(digest: &[u8], order_bits: usize) -> Vec<u8> {
    let order_bytes = order_bits.div_ceil(8);
    if digest.len() <= order_bytes {
        digest.to_vec()
    } else {
        digest[..order_bytes].to_vec()
    }
}

fn random_in_order(rand: &mut SeededRand, order: &BigUint) -> Result<BigUint, TpmResult> {
    let order_bytes = order.bit_len().div_ceil(8);
    let mut bytes = vec![0u8; order_bytes + 8];
    rand.generate(&mut bytes)?;
    let extra = BigUint::from_be_bytes(&bytes);
    let order_minus_one = order.sub_u64(1).ok_or(TPM_RC_FAILURE)?;
    let reduced = extra.rem(&order_minus_one).ok_or(TPM_RC_FAILURE)?;
    Ok(reduced.add_u64(1))
}

fn random_below(rand: &mut SeededRand, limit: &BigUint) -> Result<BigUint, TpmResult> {
    let bits = limit.bit_len();
    if bits < 2 {
        return Err(TPM_RC_NO_RESULT);
    }
    for _ in 0..SIGN_ATTEMPTS {
        let mut bytes = vec![0u8; bits.div_ceil(8)];
        rand.generate(&mut bytes)?;
        let mut value = BigUint::from_be_bytes(&bytes);
        value.mask_bits(bits);
        if !value.is_zero() && value < *limit {
            return Ok(value);
        }
    }
    Err(TPM_RC_NO_RESULT)
}

fn hmac_sign(
    body: &OwnedObjectBody,
    scheme: &SigScheme,
    digest: &[u8],
) -> Result<Signature, TpmResult> {
    let key = body
        .sensitive
        .sensitive
        .as_ref()
        .ok_or(TPM_RC_FAILURE)?
        .as_bytes();
    let mut hmac = HmacState::new(scheme.hash_alg, key).ok_or(TPM_RC_SCHEME)?;
    hmac.update(digest);
    Ok(Signature::Hmac {
        hash_alg: scheme.hash_alg,
        digest: hmac.finalize(),
    })
}

pub(super) fn sign_digest(
    body: Option<&OwnedObjectBody>,
    scheme: &SigScheme,
    digest: &[u8],
    profile: &ValidatedProfile,
    state: &mut SigningState,
) -> Result<Signature, TpmResult> {
    let Some(body) = body else {
        return Ok(Signature::Null);
    };
    if scheme.scheme == TPM_ALG_NULL {
        return Ok(Signature::Null);
    }
    if sha1_is_forbidden(profile, body.public.object_type, scheme.hash_alg) {
        return Err(TPM_RC_HASH);
    }
    match body.public.object_type {
        TPM_ALG_RSA => rsa_sign(body, scheme, digest, &mut state.rand),
        TPM_ALG_ECC => ecc_sign(body, scheme, digest, state),
        TPM_ALG_KEYEDHASH => hmac_sign(body, scheme, digest),
        _ => Err(TPM_RC_SCHEME),
    }
}

fn sha1_is_forbidden(profile: &ValidatedProfile, object_type: u16, hash_alg: u16) -> bool {
    if hash_alg != TPM_ALG_SHA1 {
        return false;
    }
    match object_type {
        TPM_ALG_RSA | TPM_ALG_ECC => profile.forbids_sha1_signing(),
        TPM_ALG_KEYEDHASH => profile.forbids_sha1_hmac_creation(),
        _ => false,
    }
}

pub(super) fn obfuscation_mask(
    hash_alg: u16,
    proof: &[u8],
    qualified_signer: &[u8],
) -> Option<[u64; 2]> {
    let stream = kdfa(hash_alg, proof, b"OBFUSCATE", qualified_signer, &[], 128)?;
    let first = u64::from_le_bytes(stream[..8].try_into().ok()?);
    let second = u64::from_le_bytes(stream[8..16].try_into().ok()?);
    Some([first, second])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::crypto::Hasher;

    fn scheme(scheme: u16, hash_alg: u16) -> SigScheme {
        SigScheme {
            scheme,
            hash_alg,
            count: 0,
        }
    }

    fn all_algorithms() -> String {
        String::from_utf8(super::super::profile::DEFAULT_ALGORITHMS_PROFILE.to_vec())
            .expect("an ascii algorithm list")
    }

    fn without(algorithm: &str) -> String {
        all_algorithms()
            .split(',')
            .filter(|token| *token != algorithm)
            .collect::<Vec<_>>()
            .join(",")
    }

    fn custom_profile(algorithms: &str, attributes: &str) -> ValidatedProfile {
        let json = format!(
            r#"{{"Name":"custom","Algorithms":"{algorithms}","Attributes":"{attributes}"}}"#
        );
        super::super::profile::validate_user_profile(Some(json.as_bytes()))
            .expect("the custom profile validates")
    }

    fn default_profile() -> ValidatedProfile {
        super::super::profile::validate_user_profile(None).expect("the null profile validates")
    }

    fn parse(bytes: &[u8]) -> Result<SigScheme, TpmResult> {
        parse_with(bytes, &default_profile())
    }

    fn parse_with(bytes: &[u8], profile: &ValidatedProfile) -> Result<SigScheme, TpmResult> {
        let mut reader = TemplateReader::new(bytes);
        let parsed = parse_sig_scheme(&mut reader, profile)?;
        assert!(reader.remaining().is_empty(), "exact consumption");
        Ok(parsed)
    }

    fn scheme_bytes(scheme: u16, hash_alg: u16) -> Vec<u8> {
        let mut bytes = scheme.to_be_bytes().to_vec();
        bytes.extend_from_slice(&hash_alg.to_be_bytes());
        if scheme == TPM_ALG_ECDAA {
            bytes.extend_from_slice(&0u16.to_be_bytes());
        }
        bytes
    }

    #[test]
    fn a_null_scheme_carries_no_details() {
        assert_eq!(parse(&[0x00, 0x10]), Ok(SigScheme::NULL));
    }

    #[test]
    fn every_signature_scheme_parses_with_its_hash() {
        for algorithm in [
            TPM_ALG_RSASSA,
            TPM_ALG_RSAPSS,
            TPM_ALG_ECDSA,
            TPM_ALG_ECSCHNORR,
            TPM_ALG_SM2,
            TPM_ALG_HMAC,
        ] {
            let mut bytes = algorithm.to_be_bytes().to_vec();
            bytes.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
            assert_eq!(
                parse(&bytes),
                Ok(scheme(algorithm, TPM_ALG_SHA256)),
                "scheme {algorithm:#06x}"
            );
        }
    }

    #[test]
    fn ecdaa_carries_a_count() {
        let mut bytes = TPM_ALG_ECDAA.to_be_bytes().to_vec();
        bytes.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        bytes.extend_from_slice(&7u16.to_be_bytes());
        assert_eq!(
            parse(&bytes),
            Ok(SigScheme {
                scheme: TPM_ALG_ECDAA,
                hash_alg: TPM_ALG_SHA256,
                count: 7,
            })
        );
    }

    #[test]
    fn a_non_signature_scheme_is_a_scheme_error() {
        for algorithm in [0x0015u16, 0x0017, 0x0019, 0x0023, 0xffff] {
            let mut bytes = algorithm.to_be_bytes().to_vec();
            bytes.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
            assert_eq!(parse(&bytes), Err(TPM_RC_SCHEME), "{algorithm:#06x}");
        }
    }

    #[test]
    fn an_unsupported_hash_is_a_hash_error() {
        for algorithm in [0x0010u16, 0x0012, 0xffff] {
            let mut bytes = TPM_ALG_RSASSA.to_be_bytes().to_vec();
            bytes.extend_from_slice(&algorithm.to_be_bytes());
            assert_eq!(parse(&bytes), Err(TPM_RC_HASH), "{algorithm:#06x}");
        }
    }

    #[test]
    fn the_null_signature_marshals_to_its_selector_only() {
        assert_eq!(marshal_signature(&Signature::Null), [0x00, 0x10]);
    }

    #[test]
    fn an_rsa_signature_marshals_as_a_sized_buffer() {
        let signature = Signature::Rsa {
            scheme: TPM_ALG_RSASSA,
            hash_alg: TPM_ALG_SHA256,
            signature: vec![0xab; 256],
        };
        let bytes = marshal_signature(&signature);
        assert_eq!(&bytes[..6], &[0x00, 0x14, 0x00, 0x0b, 0x01, 0x00]);
        assert_eq!(bytes.len(), 6 + 256);
    }

    #[test]
    fn an_ecc_signature_marshals_both_coordinates() {
        let signature = Signature::Ecc {
            scheme: TPM_ALG_ECDSA,
            hash_alg: TPM_ALG_SHA256,
            r: vec![0x11; 32],
            s: vec![0x22; 32],
        };
        let bytes = marshal_signature(&signature);
        assert_eq!(&bytes[..6], &[0x00, 0x18, 0x00, 0x0b, 0x00, 0x20]);
        assert_eq!(&bytes[38..40], &[0x00, 0x20]);
        assert_eq!(bytes.len(), 4 + 2 + 32 + 2 + 32);
    }

    #[test]
    fn an_hmac_signature_marshals_as_a_bare_digest() {
        let signature = Signature::Hmac {
            hash_alg: TPM_ALG_SHA256,
            digest: vec![0x33; 32],
        };
        let bytes = marshal_signature(&signature);
        assert_eq!(&bytes[..4], &[0x00, 0x05, 0x00, 0x0b]);
        assert_eq!(bytes.len(), 4 + 32, "TPMT_HA has no length prefix");
    }

    #[test]
    fn the_der_tags_match_the_vendored_oid_table() {
        assert_eq!(
            der_tag(TPM_ALG_SHA256).unwrap(),
            [
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20
            ]
        );
        assert_eq!(
            der_tag(TPM_ALG_SHA1).unwrap(),
            [
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
                0x14
            ]
        );
        assert_eq!(der_tag(TPM_ALG_SHA384).unwrap().len(), 19);
        assert_eq!(der_tag(TPM_ALG_SHA512).unwrap().len(), 19);
        assert!(der_tag(TPM_ALG_NULL).is_none());
    }

    #[test]
    fn the_pkcs1_encoding_is_the_upstream_layout() {
        let digest = vec![0x5a; 32];
        let encoded = rsassa_encode(256, TPM_ALG_SHA256, &digest).unwrap();
        assert_eq!(encoded.len(), 256);
        assert_eq!(&encoded[..2], &[0x00, 0x01]);
        let der = der_tag(TPM_ALG_SHA256).unwrap();
        let fill = 256 - der.len() - 32 - 3;
        assert!(encoded[2..2 + fill].iter().all(|&byte| byte == 0xff));
        assert_eq!(encoded[2 + fill], 0x00);
        assert_eq!(&encoded[3 + fill..3 + fill + der.len()], &der[..]);
        assert_eq!(&encoded[256 - 32..], &digest[..]);
    }

    #[test]
    fn a_digest_that_disagrees_with_the_scheme_hash_is_a_value_error() {
        assert_eq!(
            rsassa_encode(256, TPM_ALG_SHA256, &[0x5a; 20]),
            Err(TPM_RC_VALUE)
        );
    }

    #[test]
    fn a_modulus_too_small_for_the_padding_is_a_size_error() {
        assert_eq!(
            rsassa_encode(48, TPM_ALG_SHA512, &[0x5a; 64]),
            Err(TPM_RC_SIZE)
        );
    }

    #[test]
    fn the_pss_salt_size_matches_the_vendored_formula() {
        assert_eq!(pss_salt_size(32, 256), 32);
        assert_eq!(pss_salt_size(64, 256), 64);
        assert_eq!(pss_salt_size(64, 128), 62);
        assert_eq!(pss_salt_size(64, 66), 0);
        assert_eq!(pss_salt_size(64, 65), 0);
    }

    #[test]
    fn the_pss_encoding_ends_with_the_trailer_and_has_a_clear_top_bit() {
        let digest = vec![0x5a; 32];
        let salt = vec![0x77; 32];
        let encoded = pss_encode(256, TPM_ALG_SHA256, &digest, &salt).unwrap();
        assert_eq!(encoded.len(), 256);
        assert_eq!(encoded[255], 0xbc);
        assert_eq!(encoded[0] & 0x80, 0);

        let mask_len = 256 - 32 - 1;
        let h = &encoded[mask_len..mask_len + 32];
        let mask = mgf1(TPM_ALG_SHA256, h, mask_len).unwrap();
        let mut db: Vec<u8> = encoded[..mask_len]
            .iter()
            .zip(&mask)
            .map(|(a, b)| a ^ b)
            .collect();
        db[0] &= 0x7f;
        assert_eq!(db[mask_len - 33], 0x01, "the 0x01 separator is recovered");
        assert_eq!(&db[mask_len - 32..], &salt[..], "the salt is recovered");

        let mut hasher = Hasher::new(TPM_ALG_SHA256).unwrap();
        hasher.update(&[0u8; 8]);
        hasher.update(&digest);
        hasher.update(&salt);
        assert_eq!(h, &hasher.finalize()[..]);
    }

    #[test]
    fn limbs_are_read_least_significant_first() {
        let mut data = 1u64.to_be_bytes().to_vec();
        data.extend_from_slice(&2u64.to_be_bytes());
        let value = limbs_to_big(&data);
        assert_eq!(
            value,
            BigUint::from_u64(1).add(&BigUint::from_u64(2).shl(64))
        );
        assert!(limbs_to_big(&[]).is_zero());
    }

    #[test]
    fn a_short_digest_is_not_truncated() {
        assert_eq!(truncate_digest(&[0xaa; 20], 256), vec![0xaa; 20]);
        assert_eq!(truncate_digest(&[0xaa; 32], 256), vec![0xaa; 32]);
        assert_eq!(truncate_digest(&[0xaa; 64], 256), vec![0xaa; 32]);
        assert_eq!(truncate_digest(&[0xaa; 64], 521), vec![0xaa; 64]);
    }

    #[test]
    fn the_ecdsa_digest_is_truncated_and_shifted_to_the_order() {
        assert_eq!(
            ecdsa_digest(&[0xaa; 64], 256),
            BigUint::from_be_bytes(&[0xaa; 32]),
            "a byte-aligned order truncates without shifting"
        );
        assert_eq!(
            ecdsa_digest(&[0xaa; 20], 256),
            BigUint::from_be_bytes(&[0xaa; 20]),
            "a digest shorter than the order is used whole"
        );
        assert_eq!(
            ecdsa_digest(&[0xaa; 64], 521),
            BigUint::from_be_bytes(&[0xaa; 64]),
            "a 512-bit digest still fits a 521-bit order"
        );
        assert_eq!(
            ecdsa_digest(&[0xff; 4], 20),
            BigUint::from_u64(0x000f_ffff),
            "a digest wider than a non-aligned order loses its low bits"
        );
    }

    #[test]
    fn the_schnorr_s_value_rejects_a_zero_result() {
        let order = BigUint::from_u64(23);
        let d = BigUint::from_u64(5);
        assert_eq!(
            schnorr_s(&BigUint::from_u64(3), &BigUint::from_u64(7), &d, &order),
            Some(BigUint::from_u64(22)),
            "s is k + r * d reduced by the order"
        );
        assert_eq!(
            schnorr_s(&BigUint::from_u64(23), &BigUint::from_u64(7), &d, &order),
            None,
            "a value that reduces to zero has no signature"
        );
        assert_eq!(
            schnorr_s(&BigUint::from_u64(1), &BigUint::from_u64(18), &d, &order),
            None,
            "a zero s has no signature"
        );
    }

    #[test]
    fn a_commit_slot_is_a_little_endian_bit_in_the_array() {
        assert_eq!(COMMIT_INDEX_MASK, 127);
        assert_eq!(commit_slot(0), (0, 0x01));
        assert_eq!(commit_slot(7), (0, 0x80));
        assert_eq!(commit_slot(8), (1, 0x01));
        assert_eq!(commit_slot(127), (15, 0x80));
        assert_eq!(
            commit_slot(128),
            commit_slot(0),
            "the count wraps within the array"
        );
    }

    #[test]
    fn every_signature_scheme_needs_its_profile_token() {
        for algorithm in [
            TPM_ALG_RSASSA,
            TPM_ALG_RSAPSS,
            TPM_ALG_ECDAA,
            TPM_ALG_SM2,
            TPM_ALG_ECSCHNORR,
        ] {
            let name = String::from_utf8(
                algorithm_profile_name(algorithm)
                    .expect("a profile token")
                    .to_vec(),
            )
            .expect("ascii");
            let profile = custom_profile(&without(&name), "");
            assert_eq!(
                parse_with(&scheme_bytes(algorithm, TPM_ALG_SHA256), &profile),
                Err(TPM_RC_SCHEME),
                "scheme {algorithm:#06x} is disabled"
            );
            assert_eq!(
                parse_with(
                    &scheme_bytes(algorithm, TPM_ALG_SHA256),
                    &custom_profile(&all_algorithms(), "")
                ),
                Ok(scheme(algorithm, TPM_ALG_SHA256)),
                "scheme {algorithm:#06x} is enabled"
            );
        }
    }

    #[test]
    fn a_disabled_hash_is_a_hash_error() {
        assert_eq!(
            parse_with(
                &scheme_bytes(TPM_ALG_RSASSA, TPM_ALG_SHA512),
                &custom_profile(&without("sha512"), "")
            ),
            Err(TPM_RC_HASH)
        );
        assert_eq!(
            parse_with(
                &scheme_bytes(TPM_ALG_RSASSA, TPM_ALG_SHA512),
                &custom_profile(&all_algorithms(), "")
            ),
            Ok(scheme(TPM_ALG_RSASSA, TPM_ALG_SHA512))
        );
    }

    #[test]
    fn the_sha1_restrictions_follow_the_key_type() {
        for (attributes, rsa, ecc, keyed_hash) in [
            ("", false, false, false),
            ("no-sha1-signing", true, true, false),
            ("fips-host", true, true, false),
            ("no-sha1-hmac-creation", false, false, true),
            ("no-sha1-hmac", false, false, true),
            ("no-sha1-verification", false, false, false),
        ] {
            let profile = custom_profile(&all_algorithms(), attributes);
            for (object_type, expected) in [
                (TPM_ALG_RSA, rsa),
                (TPM_ALG_ECC, ecc),
                (TPM_ALG_KEYEDHASH, keyed_hash),
            ] {
                assert_eq!(
                    sha1_is_forbidden(&profile, object_type, TPM_ALG_SHA1),
                    expected,
                    "{attributes:?} type {object_type:#06x}"
                );
                assert!(
                    !sha1_is_forbidden(&profile, object_type, TPM_ALG_SHA256),
                    "only SHA-1 is restricted"
                );
            }
        }
    }

    #[test]
    fn the_anonymous_and_split_schemes_are_ecdaa_only() {
        for algorithm in [
            TPM_ALG_RSASSA,
            TPM_ALG_RSAPSS,
            TPM_ALG_ECDSA,
            TPM_ALG_ECSCHNORR,
            TPM_ALG_SM2,
            TPM_ALG_HMAC,
            TPM_ALG_NULL,
        ] {
            assert!(!is_anonymous_scheme(algorithm), "{algorithm:#06x}");
            assert!(!is_split_sign(algorithm), "{algorithm:#06x}");
        }
        assert!(is_anonymous_scheme(TPM_ALG_ECDAA));
        assert!(is_split_sign(TPM_ALG_ECDAA));
    }

    #[test]
    fn a_scheme_is_only_valid_for_its_own_key_type() {
        for (object_type, valid) in [
            (TPM_ALG_RSA, vec![TPM_ALG_RSASSA, TPM_ALG_RSAPSS]),
            (
                TPM_ALG_ECC,
                vec![TPM_ALG_ECDSA, TPM_ALG_ECDAA, TPM_ALG_ECSCHNORR, TPM_ALG_SM2],
            ),
            (TPM_ALG_KEYEDHASH, vec![TPM_ALG_HMAC]),
        ] {
            for algorithm in [
                TPM_ALG_RSASSA,
                TPM_ALG_RSAPSS,
                TPM_ALG_ECDSA,
                TPM_ALG_ECDAA,
                TPM_ALG_ECSCHNORR,
                TPM_ALG_SM2,
                TPM_ALG_HMAC,
            ] {
                assert_eq!(
                    scheme_is_valid_for(object_type, &scheme(algorithm, TPM_ALG_SHA256)),
                    valid.contains(&algorithm),
                    "type {object_type:#06x} scheme {algorithm:#06x}"
                );
            }
        }
        assert!(!scheme_is_valid_for(
            super::super::public::TPM_ALG_SYMCIPHER,
            &scheme(TPM_ALG_RSASSA, TPM_ALG_SHA256)
        ));
        assert!(!scheme_is_valid_for(
            TPM_ALG_RSA,
            &scheme(TPM_ALG_RSASSA, TPM_ALG_NULL)
        ));
    }

    #[test]
    fn a_null_signing_key_selects_the_null_scheme() {
        assert_eq!(
            select_sign_scheme(None, scheme(TPM_ALG_RSASSA, TPM_ALG_SHA256)),
            Some(SigScheme::NULL)
        );
        assert_eq!(
            select_sign_scheme(None, SigScheme::NULL),
            Some(SigScheme::NULL)
        );
    }

    #[test]
    fn the_obfuscation_mask_is_two_native_words_of_the_key_stream() {
        let stream = kdfa(TPM_ALG_SHA256, b"proof", b"OBFUSCATE", b"name", &[], 128).unwrap();
        let mask = obfuscation_mask(TPM_ALG_SHA256, b"proof", b"name").unwrap();
        assert_eq!(
            mask[0],
            u64::from_le_bytes(stream[..8].try_into().unwrap()),
            "upstream reinterprets the key stream as native UINT64 words"
        );
        assert_eq!(
            mask[1],
            u64::from_le_bytes(stream[8..16].try_into().unwrap())
        );
        assert!(obfuscation_mask(TPM_ALG_NULL, b"proof", b"name").is_none());
    }
}
