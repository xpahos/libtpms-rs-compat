// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/SigningCommands.c
// - libtpms/src/tpm2/crypto/openssl/CryptEccSignature.c
// - libtpms/src/tpm2/crypto/openssl/CryptRsa.c
//
// Original upstream authors and copyright notices:
// Written by Ken Goldman
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corp. and others, 2016 - 2023
// (c) Copyright IBM Corp. and others, 2016 - 2024
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use subtle::ConstantTimeEq;

use crate::library::constants::{
    TPM_RC_FAILURE, TPM_RC_HANDLE, TPM_RC_HASH, TPM_RC_KEY_SIZE, TPM_RC_NO_RESULT, TPM_RC_SCHEME,
    TPM_RC_SIGNATURE, TPM_RC_SIZE, TPM_RC_VALUE,
};
use crate::types::TpmResult;

use super::algorithm::{
    TPM_ALG_ECC, TPM_ALG_ECDAA, TPM_ALG_ECDSA, TPM_ALG_ECSCHNORR, TPM_ALG_HMAC, TPM_ALG_KEYEDHASH,
    TPM_ALG_NULL, TPM_ALG_RSA, TPM_ALG_RSAPSS, TPM_ALG_RSASSA, TPM_ALG_SHA1, TPM_ALG_SHA256,
    TPM_ALG_SHA384, TPM_ALG_SHA512, TPM_ALG_SM2, algorithm_enabled, algorithm_profile_name,
};
use super::commit::CommitState;
use super::crypto::{
    EccBackendError, EccCurve, EccPublicScalar, EccScalar, EcdsaAttempt, HmacState, PublicCheck,
    RsaCrtKey, RsaSignaturePadding, SecretBytes, SeededRand, SharedPointError, kdfa, mgf1,
    rsa_private_key_op, rsa_public_key_op, rsa_verify_signature, rsassa_sign, wipe,
};
use super::ecc::{PrivateScalar, ecc_stored_private, fit_be, upstream_mask_kept_bits};
use super::marshal::BlobWriter;
use super::persistent::{OwnedObjectBody, OwnedPublicId, OwnedSecret};
use super::profile::ValidatedProfile;
use super::public::{MAX_ECC_KEY_BYTES, MAX_RSA_KEY_BYTES, PublicParms, Scheme, StateFormatLimit};
use super::template::{AlgorithmPolicy, TemplateReader, digest_size};

const SIGN_ATTEMPTS: u32 = 64;
const RANGE_ATTEMPTS: u32 = 1 << 16;
const SM2_NONCE_REDRAWS: usize = 8;

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
    let scheme = parse_sig_selector(scheme, profile)?;
    let hash_alg = parse_hash_selector(reader, profile)?;
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

fn parse_sig_selector(scheme: u16, profile: &ValidatedProfile) -> Result<u16, TpmResult> {
    if !is_signature_scheme(scheme) || !profile_enables(profile, scheme) {
        return Err(TPM_RC_SCHEME);
    }
    Ok(scheme)
}

fn parse_hash_selector(
    reader: &mut TemplateReader<'_>,
    profile: &ValidatedProfile,
) -> Result<u16, TpmResult> {
    let hash_alg = reader.u16()?;
    if digest_size(hash_alg).is_none() || !profile_enables(profile, hash_alg) {
        return Err(TPM_RC_HASH);
    }
    Ok(hash_alg)
}

pub(super) fn parse_signature(
    reader: &mut TemplateReader<'_>,
    profile: &ValidatedProfile,
) -> Result<Signature, TpmResult> {
    let selector = reader.u16()?;
    let scheme = parse_sig_selector(selector, profile)?;
    let hash_alg = parse_hash_selector(reader, profile)?;
    Ok(match scheme {
        TPM_ALG_RSASSA | TPM_ALG_RSAPSS => Signature::Rsa {
            scheme,
            hash_alg,
            signature: reader.tpm2b(MAX_RSA_KEY_BYTES)?.to_vec(),
        },
        TPM_ALG_HMAC => Signature::Hmac {
            hash_alg,
            digest: reader
                .bytes(digest_size(hash_alg).ok_or(TPM_RC_HASH)?)?
                .to_vec(),
        },
        _ => Signature::Ecc {
            scheme,
            hash_alg,
            r: reader.tpm2b(MAX_ECC_KEY_BYTES)?.to_vec(),
            s: reader.tpm2b(MAX_ECC_KEY_BYTES)?.to_vec(),
        },
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
        PublicParms::SymCipher(_) | PublicParms::Unselected => None,
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

fn rsassa_check(modulus_size: usize, hash_alg: u16, digest: &[u8]) -> Result<usize, TpmResult> {
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
    Ok(fill)
}

fn rsassa_encode(modulus_size: usize, hash_alg: u16, digest: &[u8]) -> Result<Vec<u8>, TpmResult> {
    let fill = rsassa_check(modulus_size, hash_alg, digest)?;
    let der = der_tag(hash_alg).ok_or(TPM_RC_SCHEME)?;
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

pub(super) fn rsa_crt_key(body: &OwnedObjectBody) -> Option<RsaCrtKey<'_>> {
    let prime = body.sensitive.sensitive.as_ref()?;
    let exponent = body.private_exponent.as_ref()?;
    #[cfg(test)]
    {
        super::memcheck::secret(prime.as_bytes());
        for words in &exponent.primes {
            super::memcheck::secret_words(&words.words);
        }
    }
    Some(RsaCrtKey {
        cache: Some(&exponent.runtime),
        modulus: rsa_modulus(body)?,
        exponent: rsa_exponent(body)?,
        prime: prime.as_bytes(),
        q: &exponent.primes[0].words,
        d_p: &exponent.primes[1].words,
        d_q: &exponent.primes[2].words,
        q_inv: &exponent.primes[3].words,
    })
}

pub(super) fn public_value_below(value: &[u8], bound: &[u8]) -> bool {
    let trim = |bytes: &[u8]| -> usize {
        bytes
            .iter()
            .position(|&byte| byte != 0)
            .unwrap_or(bytes.len())
    };
    let value = &value[trim(value)..];
    let bound = &bound[trim(bound)..];
    value.len() < bound.len() || (value.len() == bound.len() && value < bound)
}

pub(super) fn rsa_modulus(body: &OwnedObjectBody) -> Option<&[u8]> {
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
        TPM_ALG_RSASSA => {
            rsassa_check(modulus_size, scheme.hash_alg, digest)?;
            let key = rsa_crt_key(body).ok_or(TPM_RC_FAILURE)?;
            let signature = rsassa_sign(&key, scheme.hash_alg, digest).ok_or(TPM_RC_FAILURE)?;
            #[cfg(test)]
            {
                super::memcheck::observe("signature-output", &signature);
            }
            return Ok(Signature::Rsa {
                scheme: scheme.scheme,
                hash_alg: scheme.hash_alg,
                signature,
            });
        }
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

    let key = rsa_crt_key(body).ok_or(TPM_RC_FAILURE)?;
    let signature = rsa_private_key_op(&key, &encoded).ok_or(TPM_RC_FAILURE)?;
    #[cfg(test)]
    {
        super::memcheck::observe("signature-output", &signature);
    }

    Ok(Signature::Rsa {
        scheme: scheme.scheme,
        hash_alg: scheme.hash_alg,
        signature,
    })
}

pub(super) struct SigningState {
    pub(super) rand: SeededRand,
    pub(super) commit: CommitState,
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
    let curve = EccCurve::lookup(curve_id).ok_or(TPM_RC_VALUE)?;
    let PrivateScalar::Ready(d) = PrivateScalar::of(&curve, ecc_stored_private(body)) else {
        return Err(TPM_RC_FAILURE);
    };
    let order_bytes = curve.order_bytes();

    if scheme.scheme == TPM_ALG_ECDAA {
        return ecdaa_sign(body, &curve, &d, digest, scheme, state);
    }
    let (r, s) = match scheme.scheme {
        TPM_ALG_ECDSA => ecdsa_sign(&curve, &d, digest, &mut state.rand)?,
        TPM_ALG_ECSCHNORR => {
            let (r, s) = ecschnorr_sign(&curve, &d, digest, scheme.hash_alg, &mut state.rand)?;
            (r, s.to_bytes(order_bytes).ok_or(TPM_RC_FAILURE)?)
        }
        TPM_ALG_SM2 => {
            let (r, s): (EccPublicScalar, EccPublicScalar) =
                sm2_sign(&curve, &d, digest, &mut state.rand)?;
            (
                r.to_bytes(order_bytes).ok_or(TPM_RC_FAILURE)?,
                s.to_bytes(order_bytes).ok_or(TPM_RC_FAILURE)?,
            )
        }
        _ => return Err(TPM_RC_SCHEME),
    };
    #[cfg(test)]
    for half in [&r, &s] {
        super::memcheck::observe("signature-output", half);
    }
    Ok(Signature::Ecc {
        scheme: scheme.scheme,
        hash_alg: scheme.hash_alg,
        r,
        s,
    })
}

fn ecdsa_sign(
    curve: &EccCurve,
    d: &EccScalar,
    digest: &[u8],
    rand: &mut SeededRand,
) -> Result<(Vec<u8>, Vec<u8>), TpmResult> {
    for _ in 0..SIGN_ATTEMPTS {
        let k = random_in_order(rand, curve)?;
        match curve.ecdsa_sign(d, &k, digest).ok_or(TPM_RC_FAILURE)? {
            EcdsaAttempt::Retry => continue,
            EcdsaAttempt::Signed { r, s } => return Ok((r, s)),
        }
    }
    Err(TPM_RC_NO_RESULT)
}

fn ecschnorr_sign(
    curve: &EccCurve,
    d: &EccScalar,
    digest: &[u8],
    hash_alg: u16,
    rand: &mut SeededRand,
) -> Result<(Vec<u8>, EccPublicScalar), TpmResult> {
    let digest_len = digest_size(hash_alg).ok_or(TPM_RC_SCHEME)?;
    let order_bytes = curve.order_bytes();
    for _ in 0..SIGN_ATTEMPTS {
        let k = random_in_order(rand, curve)?;
        let point = match curve.mul_generator_checked(&k) {
            Ok(point) => point,
            Err(SharedPointError::Infinity) => continue,
            Err(SharedPointError::OffCurve | SharedPointError::Backend) => {
                return Err(TPM_RC_FAILURE);
            }
        };
        #[cfg(test)]
        super::memcheck::observe("schnorr-commitment", &point.x);
        let Some(e) = fit_be(&point.x, order_bytes) else {
            continue;
        };
        let mut hasher = super::crypto::Hasher::new(hash_alg).ok_or(TPM_RC_SCHEME)?;
        hasher.update(&e);
        hasher.update(digest);
        let mut hash = hasher.finalize();
        hash.truncate(digest_len.min(order_bytes));
        if let Some(s) = schnorr_s(curve, &hash, &k, d)? {
            let r = fit_be(&hash, order_bytes).ok_or(TPM_RC_FAILURE)?;
            return Ok((r, s));
        }
    }
    Err(TPM_RC_NO_RESULT)
}

fn sm2_sign(
    curve: &EccCurve,
    d: &EccScalar,
    digest: &[u8],
    rand: &mut SeededRand,
) -> Result<(EccPublicScalar, EccPublicScalar), TpmResult> {
    let public = |bytes: &[u8]| {
        curve
            .public_scalar_checked(bytes)
            .map_err(|EccBackendError| TPM_RC_FAILURE)
    };
    let e = public(digest)?.ok_or(TPM_RC_NO_RESULT)?;
    let one = public(&[1])?.ok_or(TPM_RC_FAILURE)?;
    let successor = d.add_public(&one).ok_or(TPM_RC_FAILURE)?;
    if successor
        .checked_is_zero()
        .map_err(|EccBackendError| TPM_RC_FAILURE)?
    {
        return Err(TPM_RC_NO_RESULT);
    }
    let inverse = successor.invert().ok_or(TPM_RC_FAILURE)?;
    for _ in 0..SIGN_ATTEMPTS {
        let k = sm2_nonce(rand, curve)?;
        let point = match curve.mul_generator_checked(&k) {
            Ok(point) => point,
            Err(SharedPointError::Infinity) => continue,
            Err(SharedPointError::OffCurve | SharedPointError::Backend) => {
                return Err(TPM_RC_FAILURE);
            }
        };
        #[cfg(test)]
        super::memcheck::observe("sm2-commitment", &point.x);
        let x = public(&point.x)?.ok_or(TPM_RC_FAILURE)?;
        let r = e.add(&x).ok_or(TPM_RC_FAILURE)?;
        if r.is_zero() {
            continue;
        }
        let s = d
            .mul_public(&r)
            .and_then(|product| k.sub(&product))
            .and_then(|difference| difference.mul(&inverse))
            .and_then(|s| s.reveal())
            .ok_or(TPM_RC_FAILURE)?;
        if s.is_zero() {
            continue;
        }
        return Ok((r, s));
    }
    Err(TPM_RC_NO_RESULT)
}

fn ecdaa_sign(
    body: &OwnedObjectBody,
    curve: &EccCurve,
    d: &EccScalar,
    digest: &[u8],
    scheme: &SigScheme,
    state: &mut SigningState,
) -> Result<Signature, TpmResult> {
    let order_bytes = curve.order_bytes();
    let commit = state
        .commit
        .generate_r(curve, &body.name, Some(scheme.count))
        .map_err(|EccBackendError| TPM_RC_FAILURE)?
        .ok_or(TPM_RC_VALUE)?;
    for _ in 0..SIGN_ATTEMPTS {
        let nonce = random_in_order(&mut state.rand, curve)?;
        let nonce_bytes = nonce.reveal().ok_or(TPM_RC_FAILURE)?.to_minimal_bytes();
        let mut hasher = super::crypto::Hasher::new(scheme.hash_alg).ok_or(TPM_RC_SCHEME)?;
        hasher.update(&nonce_bytes);
        hasher.update(digest);
        let t = hasher.finalize();
        if let Some(s) = schnorr_s(curve, &t, &commit, d)? {
            state.commit.end_commit(scheme.count);
            let s = s.to_bytes(order_bytes).ok_or(TPM_RC_FAILURE)?;
            #[cfg(test)]
            for half in [&nonce_bytes, &s] {
                super::memcheck::observe("signature-output", half);
            }
            return Ok(Signature::Ecc {
                scheme: TPM_ALG_ECDAA,
                hash_alg: scheme.hash_alg,
                r: nonce_bytes,
                s,
            });
        }
    }
    Err(TPM_RC_NO_RESULT)
}

fn schnorr_s(
    curve: &EccCurve,
    value: &[u8],
    k: &EccScalar,
    d: &EccScalar,
) -> Result<Option<EccPublicScalar>, TpmResult> {
    let reduced = curve.public_scalar(value).ok_or(TPM_RC_FAILURE)?;
    if reduced.is_zero() {
        return Ok(None);
    }
    let s = d
        .mul_public(&reduced)
        .and_then(|product| product.add(k))
        .and_then(|s| s.reveal())
        .ok_or(TPM_RC_FAILURE)?;
    Ok((!s.is_zero()).then_some(s))
}

#[cfg(test)]
fn ecdsa_digest(digest: &[u8], order_bits: usize) -> Vec<u8> {
    let bytes = truncate_digest(digest, order_bits);
    if bytes.len() * 8 <= order_bits {
        return bytes;
    }
    let shift = 8 - (order_bits & 7);
    let mut shifted = vec![0u8; bytes.len()];
    for index in 0..bytes.len() {
        let high = if index == 0 { 0 } else { bytes[index - 1] };
        shifted[index] = (bytes[index] >> shift) | (high << (8 - shift));
    }
    shifted
}

#[cfg(test)]
fn truncate_digest(digest: &[u8], order_bits: usize) -> Vec<u8> {
    let order_bytes = order_bits.div_ceil(8);
    if digest.len() <= order_bytes {
        digest.to_vec()
    } else {
        digest[..order_bytes].to_vec()
    }
}

fn random_in_order(rand: &mut SeededRand, curve: &EccCurve) -> Result<EccScalar, TpmResult> {
    let mut bytes = SecretBytes(vec![0u8; curve.order_bytes() + 8]);
    rand.generate(&mut bytes.0)?;
    #[cfg(test)]
    {
        super::memcheck::secret(&bytes.0);
        super::memcheck::observe("nonce-draw", &bytes.0);
    }
    curve.scalar_from_extra_bits(&bytes.0).ok_or(TPM_RC_FAILURE)
}

struct NonceDraw {
    scalar: EccScalar,
    short: subtle::Choice,
}

fn random_below(rand: &mut SeededRand, curve: &EccCurve) -> Result<NonceDraw, TpmResult> {
    let bits = curve.order_bits();
    if bits < 2 {
        return Err(TPM_RC_NO_RESULT);
    }
    let length = bits.div_ceil(8);
    let kept = upstream_mask_kept_bits(bits).max(bits);
    for _ in 0..RANGE_ATTEMPTS {
        let mut bytes = vec![0u8; length];
        rand.generate(&mut bytes)?;
        #[cfg(test)]
        super::memcheck::secret(&bytes);
        if kept < 8 * length {
            bytes[0] &= (1u8 << (kept % 8)) - 1;
        }
        #[cfg(test)]
        super::memcheck::observe("nonce-candidate", &bytes);
        let zero = bytes.iter().fold(0u8, |acc, &byte| acc | byte).ct_eq(&0);
        let short = bytes[0].ct_eq(&0) | bytes[length.saturating_sub(8)].ct_eq(&0);
        let draw = curve
            .scalar_below_order(&bytes)
            .map_err(|EccBackendError| TPM_RC_FAILURE);
        wipe(&mut bytes);
        let draw = draw?;
        if let Some(scalar) = draw
            && !bool::from(zero)
        {
            return Ok(NonceDraw { scalar, short });
        }
    }
    Err(TPM_RC_NO_RESULT)
}

fn sm2_nonce(rand: &mut SeededRand, curve: &EccCurve) -> Result<EccScalar, TpmResult> {
    if !curve.order_bits().is_multiple_of(8) {
        return random_below(rand, curve).map(|draw| draw.scalar);
    }
    let mut redraws = 0;
    loop {
        let draw = random_below(rand, curve)?;
        if redraws == SM2_NONCE_REDRAWS || !bool::from(draw.short) {
            return Ok(draw.scalar);
        }
        redraws += 1;
    }
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

pub(super) struct HmacVerification {
    hash_alg: u16,
    key: OwnedSecret,
    mac: Vec<u8>,
}

impl HmacVerification {
    pub(super) fn hash_alg(&self) -> u16 {
        self.hash_alg
    }

    pub(super) fn finish(self, digest: &[u8]) -> Result<(), TpmResult> {
        let mut hmac = HmacState::new(self.hash_alg, self.key.as_bytes()).ok_or(TPM_RC_SCHEME)?;
        hmac.update(digest);
        if bool::from(hmac.finalize().ct_eq(&self.mac)) {
            Ok(())
        } else {
            Err(TPM_RC_SIGNATURE)
        }
    }
}

pub(super) enum Verification {
    Complete,
    Hmac(HmacVerification),
}

pub(super) fn validate_signature(
    body: &OwnedObjectBody,
    public_only: bool,
    digest: &[u8],
    signature: &Signature,
    profile: &ValidatedProfile,
) -> Result<Verification, TpmResult> {
    if matches!(signature, Signature::Null) {
        return Err(TPM_RC_SIGNATURE);
    }
    match body.public.object_type {
        TPM_ALG_RSA => rsa_verify(body, digest, signature).map(|()| Verification::Complete),
        TPM_ALG_ECC => {
            ecc_verify(body, digest, signature, profile).map(|()| Verification::Complete)
        }
        TPM_ALG_KEYEDHASH => {
            if public_only {
                Err(TPM_RC_HANDLE)
            } else {
                hmac_validate(body, signature, profile).map(Verification::Hmac)
            }
        }
        _ => Err(TPM_RC_SCHEME),
    }
}

fn rsa_exponent(body: &OwnedObjectBody) -> Option<u32> {
    match body.public.parameters {
        PublicParms::Rsa { exponent, .. } => Some(exponent),
        _ => None,
    }
}

fn rsa_verify(
    body: &OwnedObjectBody,
    digest: &[u8],
    signature: &Signature,
) -> Result<(), TpmResult> {
    let Signature::Rsa {
        scheme,
        hash_alg,
        signature,
    } = signature
    else {
        return Err(TPM_RC_SCHEME);
    };
    if !matches!(*scheme, TPM_ALG_RSASSA | TPM_ALG_RSAPSS) {
        return Err(TPM_RC_SCHEME);
    }
    rsa_decode_signature(body, *scheme, *hash_alg, signature, digest).map_err(|_| TPM_RC_SIGNATURE)
}

fn rsa_decode_signature(
    body: &OwnedObjectBody,
    scheme: u16,
    hash_alg: u16,
    signature: &[u8],
    digest: &[u8],
) -> Result<(), TpmResult> {
    let modulus_bytes = rsa_modulus(body).ok_or(TPM_RC_FAILURE)?;
    if signature.len() != modulus_bytes.len() {
        return Err(TPM_RC_SIGNATURE);
    }
    let exponent = rsa_exponent(body).ok_or(TPM_RC_FAILURE)?;
    let padding = match scheme {
        TPM_ALG_RSASSA => {
            if digest_size(hash_alg) != Some(digest.len()) {
                return Err(TPM_RC_SCHEME);
            }
            RsaSignaturePadding::Pkcs1
        }
        TPM_ALG_RSAPSS => RsaSignaturePadding::Pss,
        _ => return Err(TPM_RC_SCHEME),
    };
    match rsa_verify_signature(
        modulus_bytes,
        exponent,
        padding,
        hash_alg,
        digest,
        signature,
    ) {
        PublicCheck::Verified => Ok(()),
        PublicCheck::Rejected => Err(TPM_RC_VALUE),
        PublicCheck::Unsupported => {
            let encoded =
                rsa_public_key_op(modulus_bytes, exponent, signature).ok_or(TPM_RC_VALUE)?;
            match padding {
                RsaSignaturePadding::Pkcs1 => rsassa_decode(hash_alg, digest, &encoded),
                RsaSignaturePadding::Pss => pss_decode(hash_alg, digest, &encoded),
            }
        }
    }
}

fn rsassa_decode(hash_alg: u16, digest: &[u8], encoded: &[u8]) -> Result<(), TpmResult> {
    if digest_size(hash_alg) != Some(digest.len()) {
        return Err(TPM_RC_SCHEME);
    }
    if rsassa_encode(encoded.len(), hash_alg, digest)? == encoded {
        Ok(())
    } else {
        Err(TPM_RC_VALUE)
    }
}

fn pss_decode(hash_alg: u16, digest: &[u8], encoded: &[u8]) -> Result<(), TpmResult> {
    let hash_len = digest_size(hash_alg).ok_or(TPM_RC_SCHEME)?;
    let mask_len = encoded
        .len()
        .checked_sub(hash_len + 1)
        .filter(|length| *length > 0)
        .ok_or(TPM_RC_VALUE)?;
    let mut fail = encoded[0] & 0x80 != 0;
    fail |= encoded[encoded.len() - 1] != 0xbc;

    let seed = &encoded[mask_len..mask_len + hash_len];
    let mut recovered = mgf1(hash_alg, seed, mask_len).ok_or(TPM_RC_SCHEME)?;
    recovered[0] &= 0x7f;
    for (index, byte) in recovered.iter_mut().enumerate() {
        *byte ^= encoded[index];
    }

    let mut separator = None;
    for (index, &byte) in recovered.iter().enumerate() {
        if byte == 0x01 {
            separator = Some(index);
            break;
        }
        fail |= byte != 0;
    }
    let salt = match separator {
        Some(index) if !fail => &recovered[index + 1..],
        _ => return Err(TPM_RC_VALUE),
    };

    let mut hasher = super::crypto::Hasher::new(hash_alg).ok_or(TPM_RC_SCHEME)?;
    hasher.update(&[0u8; 8]);
    hasher.update(digest);
    hasher.update(salt);
    if hasher.finalize() == seed {
        Ok(())
    } else {
        Err(TPM_RC_VALUE)
    }
}

fn ecc_public_point(body: &OwnedObjectBody) -> Option<(&[u8], &[u8])> {
    match &body.public.unique {
        OwnedPublicId::Ecc { x, y } => Some((x, y)),
        _ => None,
    }
}

fn ecc_verify(
    body: &OwnedObjectBody,
    digest: &[u8],
    signature: &Signature,
    profile: &ValidatedProfile,
) -> Result<(), TpmResult> {
    let PublicParms::Ecc { curve_id, .. } = body.public.parameters else {
        return Err(TPM_RC_FAILURE);
    };
    let curve = EccCurve::lookup(curve_id).ok_or(TPM_RC_VALUE)?;
    let Signature::Ecc {
        scheme,
        hash_alg,
        r,
        s,
    } = signature
    else {
        return Err(TPM_RC_SCHEME);
    };
    if !matches!(*scheme, TPM_ALG_ECDSA | TPM_ALG_ECSCHNORR | TPM_ALG_SM2) {
        return Err(TPM_RC_SCHEME);
    }
    if !curve.scalar_in_range(r) || !curve.scalar_in_range(s) {
        return Err(TPM_RC_SIGNATURE);
    }
    let point = ecc_public_point(body).ok_or(TPM_RC_FAILURE)?;
    if *scheme == TPM_ALG_ECDSA {
        return ecdsa_verify(&curve, point, r, s, digest, profile);
    }
    let r = curve.public_scalar(r).ok_or(TPM_RC_SIGNATURE)?;
    let s = curve.public_scalar(s).ok_or(TPM_RC_SIGNATURE)?;
    match *scheme {
        TPM_ALG_ECSCHNORR => ecschnorr_verify(&curve, point, &r, &s, *hash_alg, digest, profile),
        _ => sm2_verify(&curve, point, &r, &s, digest, profile),
    }
}

fn sha1_sized(digest: &[u8]) -> bool {
    digest_size(TPM_ALG_SHA1) == Some(digest.len())
}

fn ecdsa_verify(
    curve: &EccCurve,
    point: (&[u8], &[u8]),
    r: &[u8],
    s: &[u8],
    digest: &[u8],
    profile: &ValidatedProfile,
) -> Result<(), TpmResult> {
    if sha1_sized(digest) && profile.forbids_sha1_verification() {
        return Err(TPM_RC_HASH);
    }
    if curve.ecdsa_verify(point, r, s, digest) {
        Ok(())
    } else {
        Err(TPM_RC_SIGNATURE)
    }
}

fn ecschnorr_verify(
    curve: &EccCurve,
    point: (&[u8], &[u8]),
    r: &EccPublicScalar,
    s: &EccPublicScalar,
    hash_alg: u16,
    digest: &[u8],
    profile: &ValidatedProfile,
) -> Result<(), TpmResult> {
    if hash_alg == TPM_ALG_SHA1 && profile.forbids_sha1_verification() {
        return Err(TPM_RC_HASH);
    }
    let digest_len = digest_size(hash_alg).ok_or(TPM_RC_SCHEME)?;
    let order_bytes = curve.order_bytes();
    let negated = r.neg().ok_or(TPM_RC_SIGNATURE)?;
    let sum = curve
        .mul_add(s, None, &negated, point)
        .ok_or(TPM_RC_SIGNATURE)?;
    let e = fit_be(&sum.x, order_bytes).ok_or(TPM_RC_SIGNATURE)?;
    let mut hasher = super::crypto::Hasher::new(hash_alg).ok_or(TPM_RC_SCHEME)?;
    hasher.update(&e);
    hasher.update(digest);
    let mut hash = hasher.finalize();
    hash.truncate(digest_len.min(order_bytes));
    if r.equals_integer(&hash) {
        Ok(())
    } else {
        Err(TPM_RC_SIGNATURE)
    }
}

fn sm2_verify(
    curve: &EccCurve,
    point: (&[u8], &[u8]),
    r: &EccPublicScalar,
    s: &EccPublicScalar,
    digest: &[u8],
    profile: &ValidatedProfile,
) -> Result<(), TpmResult> {
    if sha1_sized(digest) && profile.forbids_sha1_verification() {
        return Err(TPM_RC_HASH);
    }
    let order_bytes = curve.order_bytes();
    let (Some(r_bytes), Some(s_bytes)) = (r.to_bytes(order_bytes), s.to_bytes(order_bytes)) else {
        return Err(TPM_RC_SIGNATURE);
    };
    match curve.sm2_verify(point, &r_bytes, &s_bytes, digest) {
        PublicCheck::Verified => return Ok(()),
        PublicCheck::Rejected => return Err(TPM_RC_SIGNATURE),
        PublicCheck::Unsupported => {}
    }
    let t = r.add(s).ok_or(TPM_RC_SIGNATURE)?;
    if t.is_zero() {
        return Err(TPM_RC_SIGNATURE);
    }
    let sum = curve.mul_add(s, None, &t, point).ok_or(TPM_RC_SIGNATURE)?;
    let recovered = curve
        .public_scalar(digest)
        .ok_or(TPM_RC_SIGNATURE)?
        .add(&curve.public_scalar(&sum.x).ok_or(TPM_RC_SIGNATURE)?)
        .ok_or(TPM_RC_SIGNATURE)?;
    if recovered.sub(r).ok_or(TPM_RC_SIGNATURE)?.is_zero() {
        Ok(())
    } else {
        Err(TPM_RC_SIGNATURE)
    }
}

fn hmac_validate(
    body: &OwnedObjectBody,
    signature: &Signature,
    profile: &ValidatedProfile,
) -> Result<HmacVerification, TpmResult> {
    let key = body
        .sensitive
        .sensitive
        .as_ref()
        .ok_or(TPM_RC_FAILURE)?
        .as_bytes();
    let policy = AlgorithmPolicy {
        profile_algorithms: &profile.algorithms,
        state_format: StateFormatLimit::new(profile.state_format_level),
    };
    let key_bits = u16::try_from(key.len().saturating_mul(8)).unwrap_or(u16::MAX);
    if !policy.key_size_allowed(TPM_ALG_HMAC, key_bits) {
        return Err(TPM_RC_KEY_SIZE);
    }
    let Signature::Hmac {
        hash_alg,
        digest: mac,
    } = signature
    else {
        return Err(TPM_RC_SCHEME);
    };
    let PublicParms::KeyedHash(stored) = body.public.parameters else {
        return Err(TPM_RC_FAILURE);
    };
    if stored.scheme != TPM_ALG_NULL
        && (stored.scheme != TPM_ALG_HMAC || stored.hash_alg != Some(*hash_alg))
    {
        return Err(TPM_RC_SIGNATURE);
    }
    if *hash_alg == TPM_ALG_SHA1 && profile.forbids_sha1_hmac_verification() {
        return Err(TPM_RC_HASH);
    }
    Ok(HmacVerification {
        hash_alg: *hash_alg,
        key: OwnedSecret::copy_of(key),
        mac: mac.clone(),
    })
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
    use crate::library::constants::TPM_RC_INSUFFICIENT;
    use crate::library::tpm2::crypto::{COMPILED_HASHES, Hasher};
    use crate::library::tpm2::test_support::tpm2b;

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
    fn null_scheme_no_details() {
        assert_eq!(parse(&[0x00, 0x10]), Ok(SigScheme::NULL));
    }

    #[test]
    fn signature_scheme_hash_parsing_coverage() {
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
    fn ecdaa_count_field() {
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
    fn non_signature_scheme_scheme_error() {
        for algorithm in [0x0015u16, 0x0017, 0x0019, 0x0023, 0xffff] {
            let mut bytes = algorithm.to_be_bytes().to_vec();
            bytes.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
            assert_eq!(parse(&bytes), Err(TPM_RC_SCHEME), "{algorithm:#06x}");
        }
    }

    #[test]
    fn unsupported_hash_hash_error() {
        for algorithm in [0x0010u16, 0x0012, 0xffff] {
            let mut bytes = TPM_ALG_RSASSA.to_be_bytes().to_vec();
            bytes.extend_from_slice(&algorithm.to_be_bytes());
            assert_eq!(parse(&bytes), Err(TPM_RC_HASH), "{algorithm:#06x}");
        }
    }

    #[test]
    fn null_signature_selector_only_marshal() {
        assert_eq!(marshal_signature(&Signature::Null), [0x00, 0x10]);
    }

    #[test]
    fn rsa_signature_sized_buffer_marshal() {
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
    fn ecc_signature_coordinate_marshal() {
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
    fn hmac_signature_bare_digest_marshal() {
        let signature = Signature::Hmac {
            hash_alg: TPM_ALG_SHA256,
            digest: vec![0x33; 32],
        };
        let bytes = marshal_signature(&signature);
        assert_eq!(&bytes[..4], &[0x00, 0x05, 0x00, 0x0b]);
        assert_eq!(bytes.len(), 4 + 32, "TPMT_HA has no length prefix");
    }

    #[test]
    fn der_tag_oid_table_match() {
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
    fn pkcs1_encoding_upstream_layout() {
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
    fn digest_scheme_hash_mismatch_value_error() {
        assert_eq!(
            rsassa_encode(256, TPM_ALG_SHA256, &[0x5a; 20]),
            Err(TPM_RC_VALUE)
        );
    }

    #[test]
    fn undersized_modulus_size_error() {
        assert_eq!(
            rsassa_encode(48, TPM_ALG_SHA512, &[0x5a; 64]),
            Err(TPM_RC_SIZE)
        );
    }

    #[test]
    fn pss_salt_size_vendored_formula_match() {
        assert_eq!(pss_salt_size(32, 256), 32);
        assert_eq!(pss_salt_size(64, 256), 64);
        assert_eq!(pss_salt_size(64, 128), 62);
        assert_eq!(pss_salt_size(64, 66), 0);
        assert_eq!(pss_salt_size(64, 65), 0);
    }

    #[test]
    fn pss_encoding_trailer_clear_top_bit() {
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
    fn crt_key_word_order_least_significant_first() {
        use crate::library::tpm2::crypto::{BigUint, crt_words_be};
        use crate::library::tpm2::persistent::OwnedBnPrime;
        let mut data = 1u64.to_be_bytes().to_vec();
        data.extend_from_slice(&2u64.to_be_bytes());
        let prime = OwnedBnPrime::from_image(16, &data);
        assert_eq!(
            BigUint::from_be_bytes(&crt_words_be(&prime.words)).unwrap(),
            BigUint::from_u64(1)
                .unwrap()
                .add(&BigUint::from_u64(2).unwrap().shl(64).unwrap())
                .unwrap()
        );
        assert_eq!(prime.serialized_words(), &[1, 2]);
        let empty = OwnedBnPrime::from_image(0, &[]);
        assert!(empty.serialized_words().is_empty());
        assert!(
            BigUint::from_be_bytes(&crt_words_be(&empty.words))
                .unwrap()
                .is_zero()
        );
    }

    #[test]
    fn public_value_below_numeric_order() {
        assert!(public_value_below(&[0x00, 0x05], &[0x06]));
        assert!(!public_value_below(&[0x06], &[0x00, 0x06]));
        assert!(!public_value_below(&[0x07], &[0x06]));
        assert!(public_value_below(&[], &[0x01]));
        assert!(!public_value_below(&[0x01], &[]));
        assert!(public_value_below(&[0x01, 0x00], &[0x01, 0x01]));
        assert!(!public_value_below(&[0x01, 0x00, 0x00], &[0xff, 0xff]));
    }

    #[test]
    fn short_digest_no_truncation() {
        assert_eq!(truncate_digest(&[0xaa; 20], 256), vec![0xaa; 20]);
        assert_eq!(truncate_digest(&[0xaa; 32], 256), vec![0xaa; 32]);
        assert_eq!(truncate_digest(&[0xaa; 64], 256), vec![0xaa; 32]);
        assert_eq!(truncate_digest(&[0xaa; 64], 521), vec![0xaa; 64]);
    }

    #[test]
    fn ecdsa_digest_truncation_order_shift() {
        use crate::library::tpm2::crypto::BigUint;
        let value = |digest: &[u8], bits: usize| {
            BigUint::from_be_bytes(&ecdsa_digest(digest, bits)).unwrap()
        };
        assert_eq!(
            value(&[0xaa; 64], 256),
            BigUint::from_be_bytes(&[0xaa; 32]).unwrap(),
            "a byte-aligned order truncates without shifting"
        );
        assert_eq!(
            value(&[0xaa; 20], 256),
            BigUint::from_be_bytes(&[0xaa; 20]).unwrap(),
            "a digest shorter than the order is used whole"
        );
        assert_eq!(
            value(&[0xaa; 64], 521),
            BigUint::from_be_bytes(&[0xaa; 64]).unwrap(),
            "a 512-bit digest still fits a 521-bit order"
        );
        assert_eq!(
            value(&[0xff; 4], 20),
            BigUint::from_u64(0x000f_ffff).unwrap(),
            "a digest wider than a non-aligned order loses its low bits"
        );
        assert_eq!(
            value(&[0x12, 0x34, 0x56], 20),
            BigUint::from_u64(0x0012_3456 >> 4).unwrap(),
            "the shift carries bits across byte boundaries"
        );
    }

    #[test]
    fn schnorr_s_zero_result_rejection() {
        let curve = nist_p256();
        let order = curve.order();
        let d = curve.scalar_from_u64(5).unwrap();
        assert_eq!(
            schnorr_s(&curve, &[3], &curve.scalar_from_u64(7).unwrap(), &d),
            Ok(Some(curve.public_scalar_from_u64(22).unwrap())),
            "s is k + r * d reduced by the order"
        );
        assert_eq!(
            schnorr_s(&curve, &order, &curve.scalar_from_u64(7).unwrap(), &d),
            Ok(None),
            "a value that reduces to zero has no signature"
        );
        let k = curve.scalar_from_u64(5).unwrap().neg().unwrap();
        assert_eq!(
            schnorr_s(&curve, &[1], &k, &d),
            Ok(None),
            "a zero s has no signature"
        );
    }

    #[test]
    fn signature_scheme_profile_token_requirement() {
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
    fn disabled_hash_hash_error() {
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
    fn sha1_restriction_key_type_dependence() {
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
    fn anonymous_split_schemes_ecdaa_only() {
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
    fn scheme_key_type_exclusivity() {
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
    fn null_signing_key_null_scheme_selection() {
        assert_eq!(
            select_sign_scheme(None, scheme(TPM_ALG_RSASSA, TPM_ALG_SHA256)),
            Some(SigScheme::NULL)
        );
        assert_eq!(
            select_sign_scheme(None, SigScheme::NULL),
            Some(SigScheme::NULL)
        );
    }

    fn parse_sig(bytes: &[u8]) -> Result<Signature, TpmResult> {
        parse_sig_with(bytes, &default_profile())
    }

    fn parse_sig_with(bytes: &[u8], profile: &ValidatedProfile) -> Result<Signature, TpmResult> {
        let mut reader = TemplateReader::new(bytes);
        let parsed = parse_signature(&mut reader, profile)?;
        assert!(reader.remaining().is_empty(), "exact consumption");
        Ok(parsed)
    }

    #[test]
    fn rsa_signature_parse_layout() {
        for algorithm in [TPM_ALG_RSASSA, TPM_ALG_RSAPSS] {
            let mut bytes = algorithm.to_be_bytes().to_vec();
            bytes.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
            bytes.extend_from_slice(&tpm2b(&[0xab; 256]));
            assert_eq!(
                parse_sig(&bytes),
                Ok(Signature::Rsa {
                    scheme: algorithm,
                    hash_alg: TPM_ALG_SHA256,
                    signature: vec![0xab; 256],
                })
            );
        }
    }

    #[test]
    fn ecc_signature_sized_coordinate_pair_parsing() {
        for algorithm in [TPM_ALG_ECDSA, TPM_ALG_ECDAA, TPM_ALG_ECSCHNORR, TPM_ALG_SM2] {
            let mut bytes = algorithm.to_be_bytes().to_vec();
            bytes.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
            bytes.extend_from_slice(&tpm2b(&[0x11; 32]));
            bytes.extend_from_slice(&tpm2b(&[0x22; 32]));
            assert_eq!(
                parse_sig(&bytes),
                Ok(Signature::Ecc {
                    scheme: algorithm,
                    hash_alg: TPM_ALG_SHA256,
                    r: vec![0x11; 32],
                    s: vec![0x22; 32],
                }),
                "an ECDAA signature carries no count, only r and s"
            );
        }
    }

    #[test]
    fn hmac_signature_bare_digest_parse() {
        for (hash_alg, size) in COMPILED_HASHES {
            let mut bytes = TPM_ALG_HMAC.to_be_bytes().to_vec();
            bytes.extend_from_slice(&hash_alg.to_be_bytes());
            bytes.extend_from_slice(&vec![0x33; size]);
            assert_eq!(
                parse_sig(&bytes),
                Ok(Signature::Hmac {
                    hash_alg,
                    digest: vec![0x33; size],
                })
            );
        }
    }

    #[test]
    fn parsed_signature_marshal_round_trip() {
        for signature in [
            Signature::Rsa {
                scheme: TPM_ALG_RSASSA,
                hash_alg: TPM_ALG_SHA256,
                signature: vec![0xab; 256],
            },
            Signature::Ecc {
                scheme: TPM_ALG_ECDSA,
                hash_alg: TPM_ALG_SHA384,
                r: vec![0x11; 48],
                s: vec![0x22; 48],
            },
            Signature::Hmac {
                hash_alg: TPM_ALG_SHA512,
                digest: vec![0x33; 64],
            },
        ] {
            let bytes = marshal_signature(&signature);
            assert_eq!(parse_sig(&bytes), Ok(signature));
        }
    }

    #[test]
    fn null_signature_selector_rejection() {
        assert_eq!(parse_sig(&[0x00, 0x10]), Err(TPM_RC_SCHEME));
    }

    #[test]
    fn non_signature_selector_scheme_error() {
        for algorithm in [0x0015u16, 0x0017, 0x0023, 0xffff] {
            let mut bytes = algorithm.to_be_bytes().to_vec();
            bytes.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
            assert_eq!(parse_sig(&bytes), Err(TPM_RC_SCHEME), "{algorithm:#06x}");
        }
    }

    #[test]
    fn disabled_scheme_scheme_error() {
        let profile = custom_profile(&without("ecschnorr"), "");
        let mut bytes = TPM_ALG_ECSCHNORR.to_be_bytes().to_vec();
        bytes.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        bytes.extend_from_slice(&tpm2b(&[0x11; 32]));
        bytes.extend_from_slice(&tpm2b(&[0x22; 32]));
        assert_eq!(parse_sig_with(&bytes, &profile), Err(TPM_RC_SCHEME));
    }

    #[test]
    fn null_or_disabled_hash_hash_error() {
        for algorithm in [TPM_ALG_NULL, 0x0012, 0xffff] {
            let mut bytes = TPM_ALG_RSASSA.to_be_bytes().to_vec();
            bytes.extend_from_slice(&algorithm.to_be_bytes());
            assert_eq!(parse_sig(&bytes), Err(TPM_RC_HASH), "{algorithm:#06x}");
        }
        let mut bytes = TPM_ALG_RSASSA.to_be_bytes().to_vec();
        bytes.extend_from_slice(&TPM_ALG_SHA512.to_be_bytes());
        bytes.extend_from_slice(&tpm2b(&[0xab; 256]));
        assert_eq!(
            parse_sig_with(&bytes, &custom_profile(&without("sha512"), "")),
            Err(TPM_RC_HASH)
        );
    }

    #[test]
    fn oversized_signature_field_size_error() {
        let mut bytes = TPM_ALG_RSASSA.to_be_bytes().to_vec();
        bytes.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        bytes.extend_from_slice(&((MAX_RSA_KEY_BYTES + 1) as u16).to_be_bytes());
        assert_eq!(
            parse_sig(&bytes),
            Err(TPM_RC_SIZE),
            "the declared length is checked before any allocation"
        );

        let mut bytes = TPM_ALG_ECDSA.to_be_bytes().to_vec();
        bytes.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        bytes.extend_from_slice(&((MAX_ECC_KEY_BYTES + 1) as u16).to_be_bytes());
        assert_eq!(parse_sig(&bytes), Err(TPM_RC_SIZE));
    }

    #[test]
    fn truncated_signature_insufficient_error() {
        let mut prefix = TPM_ALG_RSASSA.to_be_bytes().to_vec();
        prefix.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        prefix.extend_from_slice(&256u16.to_be_bytes());
        prefix.extend_from_slice(&[0u8; 8]);
        assert_eq!(parse_sig(&prefix), Err(TPM_RC_INSUFFICIENT));

        let mut hmac = TPM_ALG_HMAC.to_be_bytes().to_vec();
        hmac.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        hmac.extend_from_slice(&[0u8; 31]);
        assert_eq!(parse_sig(&hmac), Err(TPM_RC_INSUFFICIENT));

        assert_eq!(parse_sig(&[0x00]), Err(TPM_RC_INSUFFICIENT));
        assert_eq!(
            parse_sig(&TPM_ALG_RSASSA.to_be_bytes()),
            Err(TPM_RC_INSUFFICIENT)
        );
    }

    #[test]
    fn signature_parse_declared_boundary() {
        let mut bytes = TPM_ALG_ECDSA.to_be_bytes().to_vec();
        bytes.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        bytes.extend_from_slice(&tpm2b(&[0x11; 32]));
        bytes.extend_from_slice(&tpm2b(&[0x22; 32]));
        bytes.push(0xff);
        let mut reader = TemplateReader::new(&bytes);
        assert!(parse_signature(&mut reader, &default_profile()).is_ok());
        assert_eq!(reader.remaining(), [0xff], "the trailing byte is left");
    }

    #[test]
    fn pss_with_a_nonstandard_digest_length_uses_the_tpm_decoder() {
        use crate::library::tpm2::crypto::{
            PublicCheck, RsaSignaturePadding, rsa_verify_signature,
        };
        let digest = [0x42u8; 20];
        let salt = [0x17u8; 32];
        let encoded = pss_encode(256, TPM_ALG_SHA256, &digest, &salt).expect("encodes");
        assert_eq!(pss_decode(TPM_ALG_SHA256, &digest, &encoded), Ok(()));
        assert_eq!(
            pss_decode(TPM_ALG_SHA256, &[0x43u8; 20], &encoded),
            Err(TPM_RC_VALUE)
        );
        let modulus = vec![0xc5u8; 256];
        assert_eq!(
            rsa_verify_signature(
                &modulus,
                0,
                RsaSignaturePadding::Pss,
                TPM_ALG_SHA256,
                &digest,
                &encoded
            ),
            PublicCheck::Unsupported,
            "libtpms PssDecode hashes a digest of any length; EVP verification requires the hash length"
        );
    }

    #[test]
    fn pss_for_a_1023_bit_modulus_in_128_bytes_uses_the_tpm_decoder() {
        use crate::library::tpm2::crypto::{
            BigUint, PublicCheck, RsaSignaturePadding, rsa_verify_signature,
        };
        use crate::library::tpm2::object_load::replay::{
            RH_NULL, clock, exec_raw, load_external, plain, runtime_at, runtime_from, vector,
        };
        let p = BigUint::from_hex(
            "fbff03c08ba7063d47bad8a135e6ba5d9a60fb595ba1daea9594265e2d256dbbd99b852b5c1d96a1bb21da522d9d90d8fc6fc5bdd4d2786048a29b2bd224d221",
        )
        .unwrap();
        let q = BigUint::from_hex(
            "7eee92ea2ef9e36cf0a1022746a4fd1fbde45b3efccccf99f0c54b07b37463edd576bd760a68fce89fa1119fcac87eae67e15d22651a487d4ede425cec1b0719",
        )
        .unwrap();
        let n = p.mul(&q).unwrap();
        assert_eq!(n.bit_len(), 1023, "a genuine 1023-bit modulus");
        let modulus = n.to_be_bytes(128).unwrap();
        assert!(modulus[0] & 0x40 != 0 && modulus[0] & 0x80 == 0);
        let phi = p.sub_u64(1).unwrap().mul(&q.sub_u64(1).unwrap()).unwrap();
        let d = BigUint::from_u64(65537).unwrap().mod_inverse(&phi).unwrap();

        let digest = {
            let mut hasher = Hasher::new(TPM_ALG_SHA256).unwrap();
            hasher.update(b"1023-bit PSS");
            hasher.finalize()
        };
        let (encoded, salt) = (0u8..=255)
            .map(|byte| {
                let salt = [byte; 32];
                (
                    pss_encode(128, TPM_ALG_SHA256, &digest, &salt).unwrap(),
                    salt,
                )
            })
            .find(|(encoded, _)| {
                encoded[0] & 0x40 != 0 && BigUint::from_be_bytes(encoded).unwrap() < n
            })
            .expect("a block with the extra bit set below the modulus");
        assert_eq!(encoded.len(), 128);
        assert_eq!(salt.len(), 32);
        let signature = BigUint::from_be_bytes(&encoded)
            .unwrap()
            .mod_exp(&d, &n)
            .unwrap()
            .to_be_bytes(128)
            .unwrap();

        let recovered = rsa_public_key_op(&modulus, 0, &signature).unwrap();
        assert_eq!(recovered, encoded);
        assert_eq!(pss_decode(TPM_ALG_SHA256, &digest, &recovered), Ok(()));
        assert_eq!(
            rsa_verify_signature(
                &modulus,
                0,
                RsaSignaturePadding::Pss,
                TPM_ALG_SHA256,
                &digest,
                &signature
            ),
            PublicCheck::Unsupported,
            "OpenSSL checks the block against bits(n) - 1 = 1022 bits and would reject it"
        );
        let native = openssl::pkey::PKey::from_rsa(
            openssl::rsa::Rsa::from_public_components(
                openssl::bn::BigNum::from_slice(&modulus).unwrap(),
                openssl::bn::BigNum::from_u32(65537).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let mut ctx = openssl::pkey_ctx::PkeyCtx::new(&native).unwrap();
        ctx.verify_init().unwrap();
        ctx.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)
            .unwrap();
        ctx.set_signature_md(openssl::md::Md::sha256()).unwrap();
        ctx.set_rsa_mgf1_md(openssl::md::Md::sha256()).unwrap();
        ctx.set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::custom(-2))
            .unwrap();
        assert!(
            !ctx.verify(&digest, &signature).unwrap_or(false),
            "the native checker disagrees with the TPM rules for this block"
        );
        let _ = openssl::error::ErrorStack::get();

        let mut placeholder = modulus.clone();
        placeholder[0] |= 0x80;
        let mut public = 0x0001u16.to_be_bytes().to_vec();
        public.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        public.extend_from_slice(&0x0004_0472u32.to_be_bytes());
        public.extend_from_slice(&tpm2b(&[]));
        public.extend_from_slice(&0x0010u16.to_be_bytes());
        public.extend_from_slice(&0x0010u16.to_be_bytes());
        public.extend_from_slice(&1024u16.to_be_bytes());
        public.extend_from_slice(&0u32.to_be_bytes());
        public.extend_from_slice(&tpm2b(&placeholder));
        let clock = clock();
        let mut loading = runtime_at("READY", &clock);
        let loaded = exec_raw(&mut loading, &clock, load_external(&[], &public, RH_NULL));
        assert_eq!(&loaded[6..10], &[0, 0, 0, 0], "LoadExternal {loaded:02x?}");
        let mut state = crate::library::tpm2::volatile_all_store(&loading).unwrap();
        let offsets: Vec<usize> = state
            .windows(128)
            .enumerate()
            .filter(|(_, window)| *window == placeholder.as_slice())
            .map(|(offset, _)| offset)
            .collect();
        assert_eq!(offsets.len(), 1, "the stored modulus appears once");
        state[offsets[0]..offsets[0] + 128].copy_from_slice(&modulus);
        let payload = state.len() - 20;
        let digest_of_state = openssl::sha::sha1(&state[..payload]);
        state[payload..].copy_from_slice(&digest_of_state);
        let mut runtime = runtime_from(vector("PERMALL_READY"), &state, &clock);
        let handle = 0x8000_0000u32;
        let restored_modulus = runtime
            .live
            .objects
            .iter()
            .find_map(|slot| match &slot.body {
                crate::library::tpm2::persistent::OwnedAnyObjectBody::Object(body) => {
                    rsa_modulus(body).map(|modulus| modulus.to_vec())
                }
                _ => None,
            });
        assert_eq!(restored_modulus.as_deref(), Some(modulus.as_slice()));
        let mut verify = |signature: &[u8]| {
            let mut parameters = handle.to_be_bytes().to_vec();
            parameters.extend_from_slice(&tpm2b(&digest));
            parameters.extend_from_slice(&TPM_ALG_RSAPSS.to_be_bytes());
            parameters.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
            parameters.extend_from_slice(&tpm2b(signature));
            let response = exec_raw(&mut runtime, &clock, plain(0x0000_0177, &parameters));
            u32::from_be_bytes(response[6..10].try_into().unwrap())
        };
        assert_eq!(verify(&signature), 0, "VerifySignature on the restored key");
        let mut altered = signature.clone();
        altered[127] ^= 1;
        assert_ne!(
            verify(&altered),
            0,
            "a malformed signature is still rejected"
        );
        let mut other_digest_signature =
            BigUint::from_be_bytes(&pss_encode(128, TPM_ALG_SHA256, &[0x11; 32], &salt).unwrap())
                .unwrap();
        other_digest_signature = other_digest_signature
            .rem(&n)
            .unwrap()
            .mod_exp(&d, &n)
            .unwrap();
        assert_ne!(
            verify(&other_digest_signature.to_be_bytes(128).unwrap()),
            0,
            "a signature over another digest is rejected"
        );
    }

    #[test]
    fn pss_encode_decode_round_trip() {
        let digest = vec![0x5a; 32];
        let salt = vec![0x77; 32];
        let encoded = pss_encode(256, TPM_ALG_SHA256, &digest, &salt).unwrap();
        assert_eq!(pss_decode(TPM_ALG_SHA256, &digest, &encoded), Ok(()));
        assert_eq!(
            pss_decode(TPM_ALG_SHA256, &[0x5b; 32], &encoded),
            Err(TPM_RC_VALUE),
            "a different digest does not decode"
        );

        let mut corrupted = encoded.clone();
        corrupted[255] = 0x00;
        assert_eq!(
            pss_decode(TPM_ALG_SHA256, &digest, &corrupted),
            Err(TPM_RC_VALUE),
            "the 0xbc trailer is required"
        );

        let mut high_bit = encoded.clone();
        high_bit[0] |= 0x80;
        assert_eq!(
            pss_decode(TPM_ALG_SHA256, &digest, &high_bit),
            Err(TPM_RC_VALUE),
            "the most significant bit must be clear"
        );
    }

    #[test]
    fn pss_decode_short_salt_acceptance() {
        let digest = vec![0x5a; 32];
        for salt_len in [0usize, 1, 16, 32] {
            let salt = vec![0x77; salt_len];
            let encoded = pss_encode(256, TPM_ALG_SHA256, &digest, &salt).unwrap();
            assert_eq!(
                pss_decode(TPM_ALG_SHA256, &digest, &encoded),
                Ok(()),
                "salt of {salt_len} bytes"
            );
        }
    }

    #[test]
    fn rsassa_encode_decode_round_trip() {
        let digest = vec![0x5a; 32];
        let encoded = rsassa_encode(256, TPM_ALG_SHA256, &digest).unwrap();
        assert_eq!(rsassa_decode(TPM_ALG_SHA256, &digest, &encoded), Ok(()));
        assert_eq!(
            rsassa_decode(TPM_ALG_SHA256, &[0x5b; 32], &encoded),
            Err(TPM_RC_VALUE)
        );
        assert_eq!(
            rsassa_decode(TPM_ALG_SHA384, &[0x5a; 48], &encoded),
            Err(TPM_RC_VALUE),
            "another hash reconstructs another block"
        );
        assert_eq!(
            rsassa_decode(TPM_ALG_SHA256, &[0x5a; 20], &encoded),
            Err(TPM_RC_SCHEME),
            "the digest must match the selected hash"
        );
    }

    fn nist_p256() -> EccCurve {
        EccCurve::lookup(0x0003).expect("a compiled curve")
    }

    fn signing_rand(label: &[u8]) -> SeededRand {
        SeededRand::instantiate(&[0x31; 64], b"SIG", label, &[], 1, false)
            .expect("a non-empty derivation input")
    }

    #[test]
    fn ecdsa_backend_failure_is_a_failure_not_a_fresh_nonce() {
        use crate::library::tpm2::crypto::{FaultBoundary, arm_fault, disarm_fault};
        let curve = nist_p256();
        let private = curve.scalar_from_u64(0x1234).unwrap();
        for boundary in [FaultBoundary::Signature, FaultBoundary::Exponentiation] {
            let mut used = signing_rand(b"ecdsa failure");
            let mut reference = signing_rand(b"ecdsa failure");
            let recorder = crate::library::tpm2::memcheck::Recorder::start();
            arm_fault(boundary, 0);
            let result = ecdsa_sign(&curve, &private, &[0x42; 32], &mut used);
            assert!(disarm_fault(), "{boundary:?} fired");
            assert_eq!(result, Err(TPM_RC_FAILURE), "{boundary:?}");
            assert!(
                recorder.trace().publications().is_empty(),
                "{boundary:?}: a failed signature publishes nothing"
            );
            drop(recorder);
            random_in_order(&mut reference, &curve).unwrap();
            assert_eq!(
                used.random_bytes(32).unwrap(),
                reference.random_bytes(32).unwrap(),
                "{boundary:?}: exactly one nonce was drawn"
            );
        }
        let mut used = signing_rand(b"ecdsa failure");
        assert!(ecdsa_sign(&curve, &private, &[0x42; 32], &mut used).is_ok());
    }

    #[test]
    fn schnorr_and_sm2_backend_failures_do_not_redraw_nonces() {
        use crate::library::tpm2::crypto::{FaultBoundary, arm_fault, disarm_fault, faults_fired};
        let curve = nist_p256();
        let private = curve.scalar_from_u64(0x2468).unwrap();
        for (boundary, precomputation) in [
            (FaultBoundary::PointOperation, FaultBoundary::PointOperation),
            (
                FaultBoundary::ImportReduction,
                FaultBoundary::Exponentiation,
            ),
        ] {
            let mut used = signing_rand(b"schnorr failure");
            let mut reference = signing_rand(b"schnorr failure");
            let before = faults_fired();
            arm_fault(boundary, 0);
            let result = ecschnorr_sign(&curve, &private, &[0x24; 32], TPM_ALG_SHA256, &mut used);
            disarm_fault();
            assert_eq!(faults_fired() - before, 1, "{boundary:?}");
            assert_eq!(result.err(), Some(TPM_RC_FAILURE), "ECSCHNORR {boundary:?}");
            random_in_order(&mut reference, &curve).unwrap();
            assert_eq!(
                used.random_bytes(32).unwrap(),
                reference.random_bytes(32).unwrap()
            );

            let mut used = signing_rand(b"sm2 failure");
            let mut reference = signing_rand(b"sm2 failure");
            let before = faults_fired();
            arm_fault(precomputation, 0);
            let result = sm2_sign(&curve, &private, &[0x24; 32], &mut used);
            disarm_fault();
            assert!(faults_fired() > before, "{precomputation:?}");
            assert_eq!(result.err(), Some(TPM_RC_FAILURE), "SM2 {precomputation:?}");
            if precomputation == FaultBoundary::PointOperation {
                sm2_nonce(&mut reference, &curve).unwrap();
            }
            assert_eq!(
                used.random_bytes(32).unwrap(),
                reference.random_bytes(32).unwrap(),
                "SM2 {precomputation:?}: one nonce for a multiply failure, none for a precomputation failure"
            );
        }
    }

    #[test]
    fn p521_ecdsa_with_drbg_nonces_on_both_sides_of_two_to_the_512() {
        use crate::library::tpm2::crypto::BigUint;
        let curve = EccCurve::lookup(0x0005).expect("P-521");
        let order = BigUint::from_be_bytes(&curve.order()).unwrap();
        let minus_one = order.sub_u64(1).unwrap();
        let draw_len = curve.order_bytes() + 8;
        let nonce_of = |label: &[u8]| {
            let bytes = signing_rand(label).random_bytes(draw_len).unwrap();
            BigUint::from_be_bytes(&bytes)
                .unwrap()
                .rem(&minus_one)
                .unwrap()
                .add_u64(1)
                .unwrap()
        };
        let mut short_label = None;
        let mut long_label = None;
        for index in 0u32..20_000 {
            let label = index.to_be_bytes();
            let bits = nonce_of(&label).bit_len();
            if bits <= 512 && short_label.is_none() {
                short_label = Some(label);
            }
            if bits > 512 && long_label.is_none() {
                long_label = Some(label);
            }
            if short_label.is_some() && long_label.is_some() {
                break;
            }
        }
        let d_bytes = [0x17u8; 66];
        let d = curve.secret_scalar(&d_bytes).unwrap();
        let d_value = BigUint::from_be_bytes(&d_bytes)
            .unwrap()
            .rem(&order)
            .unwrap();
        let digest = [0x5au8; 64];
        for label in [
            short_label.expect("a short nonce"),
            long_label.expect("a long nonce"),
        ] {
            let k = nonce_of(&label);
            let mut signer = signing_rand(&label);
            let (r, s) = ecdsa_sign(&curve, &d, &digest, &mut signer).expect("a signature");
            let x = BigUint::from_be_bytes(
                &curve
                    .mul_generator(&curve.secret_scalar(&k.to_be_bytes(66).unwrap()).unwrap())
                    .unwrap()
                    .x,
            )
            .unwrap()
            .rem(&order)
            .unwrap();
            let z = BigUint::from_be_bytes(&digest).unwrap();
            let expected_s = k
                .mod_inverse(&order)
                .unwrap()
                .mod_mul(
                    &z.mod_add(&x.mod_mul(&d_value, &order).unwrap(), &order)
                        .unwrap(),
                    &order,
                )
                .unwrap();
            assert_eq!(BigUint::from_be_bytes(&r).unwrap(), x);
            assert_eq!(
                BigUint::from_be_bytes(&s).unwrap(),
                expected_s,
                "nonce bits {}",
                k.bit_len()
            );
            let mut reference = signing_rand(&label);
            reference.random_bytes(draw_len).unwrap();
            assert_eq!(
                signer.random_bytes(32).unwrap(),
                reference.random_bytes(32).unwrap(),
                "the signature consumes exactly the TPM nonce draw"
            );
        }
    }

    #[test]
    fn sm2_nonce_coordinate_reduction_failure_is_a_failure_not_a_new_nonce() {
        use crate::library::tpm2::crypto::{FaultBoundary, arm_fault, disarm_fault, faults_fired};
        let curve = nist_p256();
        let private = curve.scalar_from_u64(0x5a5a).unwrap();
        let digest = [0x3c; 32];
        let first_nonce_x = 2;
        let mut used = signing_rand(b"sm2 x reduction");
        let before = faults_fired();
        arm_fault(FaultBoundary::PublicReduction, first_nonce_x);
        let result = sm2_sign(&curve, &private, &digest, &mut used);
        disarm_fault();
        assert_eq!(
            faults_fired() - before,
            1,
            "the reduction of the first nonce's x is reached"
        );
        assert_eq!(
            result,
            Err(TPM_RC_FAILURE),
            "no signature after a backend failure"
        );
        let mut reference = signing_rand(b"sm2 x reduction");
        sm2_nonce(&mut reference, &curve).unwrap();
        assert_eq!(
            used.random_bytes(32).unwrap(),
            reference.random_bytes(32).unwrap(),
            "exactly one sm2_nonce call, with its normal redraw rule, before the failure"
        );

        let mut clean = signing_rand(b"sm2 x reduction");
        let (r, s) = sm2_sign(&curve, &private, &digest, &mut clean)
            .expect("signing succeeds without the fault");
        let mut repeat = signing_rand(b"sm2 x reduction");
        assert_eq!(
            sm2_sign(&curve, &private, &digest, &mut repeat).unwrap(),
            (r, s),
            "the normal signature is deterministic for the same DRBG state"
        );
    }

    #[test]
    fn sm2_nonce_redraws_like_upstream_all_bytes_draw() {
        let curve = nist_p256();
        let order_bytes = curve.order_bytes();
        let draws = |label: &[u8], count: usize| {
            let mut rand = signing_rand(label);
            (0..count)
                .map(|_| {
                    random_below(&mut rand, &curve)
                        .expect("a draw")
                        .scalar
                        .to_bytes(order_bytes)
                        .expect("encodes")
                })
                .collect::<Vec<_>>()
        };
        let short = |bytes: &[u8]| bytes[0] == 0 || bytes[order_bytes - 8] == 0;
        let label = (0u32..)
            .map(u32::to_be_bytes)
            .find(|label| short(&draws(label, 1)[0]))
            .expect("a short first draw");
        let sequence = draws(&label, 9);
        let accepted = sequence
            .iter()
            .find(|bytes| !short(bytes))
            .expect("a full-width draw");
        let mut rand = signing_rand(&label);
        let nonce = sm2_nonce(&mut rand, &curve).expect("a nonce");
        assert_eq!(&nonce.to_bytes(order_bytes).expect("encodes"), accepted);
        assert_ne!(accepted, &sequence[0], "the short first draw is discarded");
        let label = (0u32..)
            .map(u32::to_be_bytes)
            .find(|label| !short(&draws(label, 1)[0]))
            .expect("a full-width first draw");
        let mut rand = signing_rand(&label);
        let nonce = sm2_nonce(&mut rand, &curve).expect("a nonce");
        assert_eq!(
            nonce.to_bytes(order_bytes).expect("encodes"),
            draws(&label, 1)[0]
        );
        let p521 = EccCurve::lookup(0x0005).expect("a compiled curve");
        let mut rand = signing_rand(b"p521");
        let mut unmasked = vec![0u8; 66];
        let mut draws_taken = 0;
        loop {
            rand.generate(&mut unmasked).expect("random bytes");
            draws_taken += 1;
            if let Some(value) = p521.scalar_below_order(&unmasked).unwrap()
                && !value.is_zero()
            {
                let mut replay = signing_rand(b"p521");
                let nonce = sm2_nonce(&mut replay, &p521).expect("a nonce");
                assert_eq!(
                    nonce, value,
                    "P-521 rejects unmasked 66-byte draws like BnMaskBits"
                );
                break;
            }
        }
        assert!(
            draws_taken > 1,
            "the unmasked P-521 draw usually needs several attempts"
        );
    }

    fn sha256_of(data: &[u8]) -> Vec<u8> {
        let mut hasher = Hasher::new(TPM_ALG_SHA256).expect("a compiled hash");
        hasher.update(data);
        hasher.finalize()
    }

    #[test]
    fn ecc_scheme_sign_verify_round_trip() {
        let curve = nist_p256();
        let profile = default_profile();
        let private = curve.scalar_from_u64(0x0123_4567_89ab_cdef).unwrap();
        let public = curve.mul_generator(&private).expect("a public point");
        let point = (public.x.as_slice(), public.y.as_slice());
        let digest = sha256_of(b"abc");
        let other = sha256_of(b"xyz");

        let (r, s) = ecdsa_sign(&curve, &private, &digest, &mut signing_rand(b"ecdsa"))
            .expect("an ECDSA signature");
        assert_eq!(
            ecdsa_verify(&curve, point, &r, &s, &digest, &profile),
            Ok(())
        );
        assert_eq!(
            ecdsa_verify(&curve, point, &r, &s, &other, &profile),
            Err(TPM_RC_SIGNATURE)
        );

        let (r, s) = ecschnorr_sign(
            &curve,
            &private,
            &digest,
            TPM_ALG_SHA256,
            &mut signing_rand(b"ecschnorr"),
        )
        .expect("an EC Schnorr signature");
        let r = curve.public_scalar(&r).expect("a scalar");
        assert_eq!(
            ecschnorr_verify(&curve, point, &r, &s, TPM_ALG_SHA256, &digest, &profile),
            Ok(())
        );
        assert_eq!(
            ecschnorr_verify(&curve, point, &r, &s, TPM_ALG_SHA256, &other, &profile),
            Err(TPM_RC_SIGNATURE)
        );

        let (r, s) = sm2_sign(&curve, &private, &digest, &mut signing_rand(b"sm2"))
            .expect("an SM2 signature");
        assert_eq!(sm2_verify(&curve, point, &r, &s, &digest, &profile), Ok(()));
        assert_eq!(
            sm2_verify(&curve, point, &r, &s, &other, &profile),
            Err(TPM_RC_SIGNATURE)
        );
    }

    #[test]
    fn ecc_verify_sha1_restriction() {
        let curve = nist_p256();
        let profile = custom_profile(&all_algorithms(), "no-sha1-verification");
        let private = curve.scalar_from_u64(0x0123_4567_89ab_cdef).unwrap();
        let public = curve.mul_generator(&private).expect("a public point");
        let point = (public.x.as_slice(), public.y.as_slice());
        let short = vec![0x5a; 20];
        let r = curve.public_scalar_from_u64(1).unwrap();
        let s = curve.public_scalar_from_u64(2).unwrap();
        assert_eq!(
            ecdsa_verify(&curve, point, &[1], &[2], &short, &profile),
            Err(TPM_RC_HASH),
            "ECDSA keys on the digest size"
        );
        assert_eq!(
            sm2_verify(&curve, point, &r, &s, &short, &profile),
            Err(TPM_RC_HASH),
            "SM2 keys on the digest size"
        );
        assert_eq!(
            ecschnorr_verify(&curve, point, &r, &s, TPM_ALG_SHA1, &short, &profile),
            Err(TPM_RC_HASH),
            "EC Schnorr keys on the scheme hash"
        );
        assert_eq!(
            ecschnorr_verify(
                &curve,
                point,
                &r,
                &s,
                TPM_ALG_SHA256,
                &sha256_of(b"abc"),
                &profile
            ),
            Err(TPM_RC_SIGNATURE),
            "another hash still runs the verification"
        );
    }

    #[test]
    fn hmac_verification_matching_mac_only() {
        let key = b"a keyed-hash secret";
        let digest = sha256_of(b"abc");
        let mut hmac = HmacState::new(TPM_ALG_SHA256, key).expect("a compiled hash");
        hmac.update(&digest);
        let mac = hmac.finalize();

        let verification = |mac: Vec<u8>| HmacVerification {
            hash_alg: TPM_ALG_SHA256,
            key: OwnedSecret::copy_of(key),
            mac,
        };
        assert_eq!(verification(mac.clone()).finish(&digest), Ok(()));
        assert_eq!(
            verification(mac.clone()).finish(&sha256_of(b"xyz")),
            Err(TPM_RC_SIGNATURE),
            "another digest produces another MAC"
        );

        let mut altered = mac.clone();
        altered[0] ^= 0x01;
        assert_eq!(
            verification(altered).finish(&digest),
            Err(TPM_RC_SIGNATURE),
            "a flipped leading bit is still compared to the end"
        );

        let mut altered = mac.clone();
        let last = altered.len() - 1;
        altered[last] ^= 0x01;
        assert_eq!(verification(altered).finish(&digest), Err(TPM_RC_SIGNATURE));

        assert_eq!(
            verification(mac[..mac.len() - 1].to_vec()).finish(&digest),
            Err(TPM_RC_SIGNATURE),
            "a short MAC never matches"
        );
        assert_eq!(
            verification(Vec::new()).finish(&digest),
            Err(TPM_RC_SIGNATURE)
        );
    }

    #[test]
    fn sha1_verification_restriction_upstream_split() {
        for (attributes, verification, hmac_verification) in [
            ("", false, false),
            ("no-sha1-signing", false, false),
            ("no-sha1-verification", true, false),
            ("fips-host", true, false),
            ("no-sha1-hmac-creation", false, false),
            ("no-sha1-hmac-verification", false, true),
            ("no-sha1-hmac", false, true),
        ] {
            let profile = custom_profile(&all_algorithms(), attributes);
            assert_eq!(
                profile.forbids_sha1_verification(),
                verification,
                "{attributes:?} asymmetric verification"
            );
            assert_eq!(
                profile.forbids_sha1_hmac_verification(),
                hmac_verification,
                "{attributes:?} HMAC verification"
            );
        }
    }

    #[test]
    fn obfuscation_mask_two_native_words() {
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
