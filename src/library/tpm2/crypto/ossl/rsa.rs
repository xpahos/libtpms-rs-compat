// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/crypto/openssl/CryptRsa.c
// - libtpms/src/tpm2/crypto/openssl/CryptPrime.c
// - libtpms/src/tpm2/crypto/openssl/Helpers.c
//
// Original upstream authors and copyright notices:
// Written by Ken Goldman
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corp. and others, 2016 - 2024
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use openssl::bn::{BigNum, BigNumContext, BigNumContextRef, BigNumRef};
use openssl::error::ErrorStack;
use openssl::md::{Md, MdRef};
use openssl::pkey::{PKey, Private};
use openssl::pkey_ctx::PkeyCtx;
use openssl::rsa::{Padding, Rsa, RsaPrivateKeyBuilder};
use openssl::sha::Sha256;
use openssl::sign::RsaPssSaltlen;
use subtle::{ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater};

use super::super::rsa::RSA_DEFAULT_PUBLIC_EXPONENT;
use super::fault::{Boundary, checkpoint};
use super::ffi::{check_prime, cleanse, mod_exp_consttime, oaep_check, pkcs1_type2_check};
use super::secret::SecretBn;

pub(in crate::library::tpm2) const CRT_WORDS: usize = 25;

pub(in crate::library::tpm2) type CrtWords = [u64; CRT_WORDS];

const WORD_BYTES: usize = 8;
const CRT_BYTES: usize = CRT_WORDS * WORD_BYTES;
const MAX_PUBLIC_OPERATION_BITS: i32 = 16384;

pub(in crate::library::tpm2) struct RsaCrtKey<'a> {
    pub(in crate::library::tpm2) cache: Option<&'a RsaRuntimeCache>,
    pub(in crate::library::tpm2) modulus: &'a [u8],
    pub(in crate::library::tpm2) exponent: u32,
    pub(in crate::library::tpm2) prime: &'a [u8],
    pub(in crate::library::tpm2) q: &'a CrtWords,
    pub(in crate::library::tpm2) d_p: &'a CrtWords,
    pub(in crate::library::tpm2) d_q: &'a CrtWords,
    pub(in crate::library::tpm2) q_inv: &'a CrtWords,
}

pub(in crate::library::tpm2) struct RecoveredExponent {
    pub(in crate::library::tpm2) q: CrtWords,
    pub(in crate::library::tpm2) d_p: CrtWords,
    pub(in crate::library::tpm2) d_q: CrtWords,
    pub(in crate::library::tpm2) q_inv: CrtWords,
}

#[derive(Debug)]
enum Outcome<T> {
    Value(T),
    Invalid,
    Backend,
}

fn effective_exponent(exponent: u32) -> u32 {
    if exponent == 0 {
        RSA_DEFAULT_PUBLIC_EXPONENT
    } else {
        exponent
    }
}

fn crt_limbs(modulus_len: usize, prime_len: usize) -> Option<usize> {
    let limbs = (prime_len.max(modulus_len.div_ceil(2)) + 1).div_ceil(WORD_BYTES);
    (limbs <= CRT_WORDS).then_some(limbs)
}

fn words_be(words: &CrtWords) -> [u8; CRT_BYTES] {
    let mut bytes = [0u8; CRT_BYTES];
    for (index, word) in words.iter().enumerate() {
        let end = CRT_BYTES - index * WORD_BYTES;
        bytes[end - WORD_BYTES..end].copy_from_slice(&word.to_be_bytes());
    }
    bytes
}

#[cfg(test)]
pub(in crate::library::tpm2) fn crt_words_be(words: &CrtWords) -> Vec<u8> {
    words_be(words).to_vec()
}

fn secret_words(words: &CrtWords) -> Option<SecretBn> {
    let mut bytes = words_be(words);
    let value = SecretBn::from_be(&bytes).ok();
    cleanse(&mut bytes);
    value
}

fn crt_words(value: &BigNumRef) -> Option<CrtWords> {
    let mut bytes = value.to_vec_padded(i32::try_from(CRT_BYTES).ok()?).ok()?;
    let mut words = [0u64; CRT_WORDS];
    for (index, word) in words.iter_mut().enumerate() {
        let end = CRT_BYTES - index * WORD_BYTES;
        let mut chunk = [0u8; WORD_BYTES];
        chunk.copy_from_slice(&bytes[end - WORD_BYTES..end]);
        *word = u64::from_be_bytes(chunk);
    }
    cleanse(&mut bytes);
    Some(words)
}

pub(in crate::library::tpm2) fn normalized_word_count(value: &CrtWords) -> usize {
    let mut significant = 0u64;
    for (index, &word) in value.iter().enumerate() {
        let occupied = !word.ct_eq(&0);
        significant.conditional_assign(&(index as u64 + 1), occupied);
    }
    significant as usize
}

fn fixed_width(value: &BigNumRef, length: usize) -> Option<Vec<u8>> {
    value.to_vec_padded(i32::try_from(length).ok()?).ok()
}

fn zero_is_one_byte(mut output: Vec<u8>) -> Vec<u8> {
    let occupied = output.iter().fold(0u8, |acc, &byte| acc | byte);
    if bool::from(occupied.ct_eq(&0)) {
        cleanse(&mut output);
        return vec![0u8];
    }
    output
}

struct PrimeBytes(Vec<u8>);

impl Drop for PrimeBytes {
    fn drop(&mut self) {
        cleanse(&mut self.0);
    }
}

fn ordered_prime_bytes(
    first: &SecretBn,
    second: &SecretBn,
    width: usize,
) -> Option<(PrimeBytes, PrimeBytes)> {
    let mut first_bytes = PrimeBytes(first.to_be(width).ok()?);
    let mut second_bytes = PrimeBytes(second.to_be(width).ok()?);
    let mut second_greater = subtle::Choice::from(0u8);
    let mut decided = subtle::Choice::from(0u8);
    for (left, right) in first_bytes.0.iter().zip(second_bytes.0.iter()) {
        let greater = right.ct_gt(left);
        let differs = !left.ct_eq(right);
        second_greater.conditional_assign(&greater, !decided & differs);
        decided |= differs;
    }
    for (left, right) in first_bytes.0.iter_mut().zip(second_bytes.0.iter_mut()) {
        u8::conditional_swap(left, right, second_greater);
    }
    Some((first_bytes, second_bytes))
}

fn at_most_one(bytes: &[u8]) -> bool {
    let Some((last, high)) = bytes.split_last() else {
        return true;
    };
    let high = high.iter().fold(0u8, |acc, &byte| acc | byte);
    bool::from((high | (last >> 1)).ct_eq(&0))
}

fn at_most_two(bytes: &[u8]) -> bool {
    let Some((last, high)) = bytes.split_last() else {
        return true;
    };
    let high = high.iter().fold(0u8, |acc, &byte| acc | byte);
    let above_two = (*last).ct_gt(&2);
    bool::from(high.ct_eq(&0) & !above_two)
}

macro_rules! backend {
    ($value:expr) => {
        match $value {
            Some(value) => value,
            None => return Outcome::Backend,
        }
    };
}

macro_rules! outcome {
    ($value:expr) => {
        match $value {
            Outcome::Value(value) => value,
            Outcome::Invalid => return Outcome::Invalid,
            Outcome::Backend => return Outcome::Backend,
        }
    };
}

fn no_inverse(error: &ErrorStack) -> bool {
    const ERR_LIB_BN: i32 = 3;
    const BN_R_NO_INVERSE: i32 = 108;
    error
        .errors()
        .iter()
        .any(|entry| entry.library_code() == ERR_LIB_BN && entry.reason_code() == BN_R_NO_INVERSE)
}

fn checked_inverse(
    value: &BigNumRef,
    modulus: &BigNumRef,
    ctx: &mut BigNumContextRef,
) -> Outcome<SecretBn> {
    backend!(checkpoint(Boundary::Inverse));
    let mut inverse = backend!(SecretBn::new().ok());
    drop(ErrorStack::get());
    match inverse.mod_inverse(value, modulus, ctx) {
        Ok(()) => Outcome::Value(inverse),
        Err(error) if no_inverse(&error) => Outcome::Invalid,
        Err(_) => Outcome::Backend,
    }
}

fn predecessor(value: &BigNumRef) -> Option<SecretBn> {
    let mut result = SecretBn::copy_of(value).ok()?;
    result.sub_word(1).ok()?;
    Some(result)
}

fn crt_exponent_of(
    prime: &SecretBn,
    exponent: u32,
    ctx: &mut BigNumContextRef,
) -> Outcome<SecretBn> {
    let e = backend!(BigNum::from_u32(exponent).ok());
    let modulus = backend!(predecessor(prime));
    checked_inverse(&e, &modulus, ctx)
}

fn crt_exponent(prime: &[u8], exponent: u32) -> Outcome<CrtWords> {
    if at_most_two(prime) {
        return Outcome::Invalid;
    }
    let mut ctx = backend!(BigNumContext::new().ok());
    let prime = backend!(SecretBn::from_be(prime).ok());
    let exponent = outcome!(crt_exponent_of(&prime, exponent, &mut ctx));
    Outcome::Value(backend!(crt_words(&exponent)))
}

fn crt_coefficient(
    smaller: &SecretBn,
    larger: &SecretBn,
    ctx: &mut BigNumContextRef,
) -> Outcome<CrtWords> {
    if larger.num_bits() == 0 {
        return Outcome::Invalid;
    }
    let inverse = outcome!(checked_inverse(smaller, larger, ctx));
    Outcome::Value(backend!(crt_words(&inverse)))
}

fn factors_multiply_to(larger: &[u8], smaller: &[u8], modulus: &BigNumRef) -> Option<bool> {
    let mut ctx = BigNumContext::new().ok()?;
    let left = SecretBn::from_be(larger).ok()?;
    let right = SecretBn::from_be(smaller).ok()?;
    let mut product = SecretBn::new().ok()?;
    checkpoint(Boundary::Product)?;
    product.checked_mul(&left, &right, &mut ctx).ok()?;
    Some(product.ucmp(modulus).is_eq())
}

struct NativeRsaKey {
    rsa: Rsa<Private>,
    pkey: PKey<Private>,
}

pub(in crate::library::tpm2) struct PreparedRsaKey {
    fingerprint: [u8; 32],
    key: Option<NativeRsaKey>,
}

#[derive(Clone, Default)]
pub(in crate::library::tpm2) struct RsaRuntimeCache(Arc<Mutex<Option<Arc<PreparedRsaKey>>>>);

#[cfg(test)]
thread_local! {
    static PREPARATIONS: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

#[cfg(test)]
pub(in crate::library::tpm2) fn prepared_key_count() -> u64 {
    PREPARATIONS.with(core::cell::Cell::get)
}

fn fingerprint(key: &RsaCrtKey<'_>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in [key.modulus, key.prime] {
        hasher.update(&(part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.update(&effective_exponent(key.exponent).to_be_bytes());
    for words in [key.q, key.d_p, key.d_q, key.q_inv] {
        let mut bytes = words_be(words);
        hasher.update(&bytes);
        cleanse(&mut bytes);
    }
    hasher.finish()
}

struct Transient;

impl<T> Outcome<T> {
    fn half(self) -> Option<Option<T>> {
        match self {
            Outcome::Value(value) => Some(Some(value)),
            Outcome::Invalid => Some(None),
            Outcome::Backend => None,
        }
    }
}

fn transient<T, E>(result: Result<T, E>) -> Result<T, Transient> {
    result.map_err(|_| Transient)
}

fn present<T>(value: Option<T>) -> Result<T, Transient> {
    value.ok_or(Transient)
}

fn prepare(key: &RsaCrtKey<'_>, fingerprint: [u8; 32]) -> Result<PreparedRsaKey, Transient> {
    #[cfg(test)]
    if key.cache.is_some() {
        PREPARATIONS.with(|count| count.set(count.get() + 1));
    }
    let unusable = PreparedRsaKey {
        fingerprint,
        key: None,
    };
    if crt_limbs(key.modulus.len(), key.prime.len()).is_none() {
        return Ok(unusable);
    }
    let n = transient(BigNum::from_slice(key.modulus))?;
    if !n.is_odd() || n.num_bits() < 2 {
        return Ok(unusable);
    }
    #[cfg(test)]
    crate::library::tpm2::memcheck::observe("private-key-prime", key.prime);
    let width = CRT_BYTES.max(key.prime.len());
    let stored = transient(SecretBn::from_be(key.prime))?;
    let other = present(secret_words(key.q))?;
    let (larger_bytes, smaller_bytes) = present(ordered_prime_bytes(&stored, &other, width))?;
    drop((stored, other));
    if at_most_one(&smaller_bytes.0) {
        return Ok(unusable);
    }
    if !present(factors_multiply_to(&larger_bytes.0, &smaller_bytes.0, &n))? {
        return Ok(unusable);
    }
    let exponent = effective_exponent(key.exponent);
    if exponent.is_multiple_of(2) {
        return Ok(unusable);
    }
    if !factors_are_prime(&n, &larger_bytes.0, &smaller_bytes.0)? {
        return Ok(unusable);
    }
    let p = transient(SecretBn::from_be(&larger_bytes.0))?;
    let q = transient(SecretBn::from_be(&smaller_bytes.0))?;
    drop((larger_bytes, smaller_bytes));
    let components = match private_components(&p, &q, exponent) {
        Outcome::Value(components) => components,
        Outcome::Invalid => return Ok(unusable),
        Outcome::Backend => return Err(Transient),
    };
    present(checkpoint(Boundary::NativeKey))?;
    let [d, d_p, d_q, q_inv] = components;
    let native = transient(
        transient(RsaPrivateKeyBuilder::new(
            transient(n.to_owned())?,
            transient(BigNum::from_u32(exponent))?,
            transient(d.export())?,
        ))?
        .set_factors(transient(p.export())?, transient(q.export())?),
    )?;
    let native = transient(native.set_crt_params(
        transient(d_p.export())?,
        transient(d_q.export())?,
        transient(q_inv.export())?,
    ))?
    .build();
    let pkey = transient(PKey::from_rsa(native.clone()))?;
    Ok(PreparedRsaKey {
        fingerprint,
        key: Some(NativeRsaKey { rsa: native, pkey }),
    })
}

fn private_components(p: &SecretBn, q: &SecretBn, exponent: u32) -> Outcome<[SecretBn; 4]> {
    let mut ctx = backend!(BigNumContext::new().ok());
    let e = backend!(BigNum::from_u32(exponent).ok());
    let p_minus_one = backend!(predecessor(p));
    let q_minus_one = backend!(predecessor(q));
    let mut totient = backend!(SecretBn::new().ok());
    backend!(checkpoint(Boundary::Product));
    backend!(
        totient
            .checked_mul(&p_minus_one, &q_minus_one, &mut ctx)
            .ok()
    );
    let d = outcome!(checked_inverse(&e, &totient, &mut ctx));
    let d_p = outcome!(checked_inverse(&e, &p_minus_one, &mut ctx));
    let d_q = outcome!(checked_inverse(&e, &q_minus_one, &mut ctx));
    let q_inv = outcome!(checked_inverse(q, p, &mut ctx));
    Outcome::Value([d, d_p, d_q, q_inv])
}

const VALIDATED_FACTOR_SETS: usize = 64;

static VALIDATED_FACTORS: Mutex<VecDeque<[u8; 32]>> = Mutex::new(VecDeque::new());

#[cfg(test)]
pub(in crate::library::tpm2) fn validated_factor_sets() -> usize {
    VALIDATED_FACTORS
        .lock()
        .map_or(0, |validated| validated.len())
}

#[cfg(test)]
thread_local! {
    static PRIMALITY_TESTS: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

#[cfg(test)]
fn primality_test_count() -> u64 {
    PRIMALITY_TESTS.with(core::cell::Cell::get)
}

fn factor_identity(n: &BigNumRef) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"rsa modulus of two distinct primes");
    let modulus = n.to_vec();
    hasher.update(&(modulus.len() as u64).to_be_bytes());
    hasher.update(&modulus);
    hasher.finish()
}

#[cfg(test)]
fn forget_factor_set(key: &RsaCrtKey<'_>) {
    let n = BigNum::from_slice(key.modulus).unwrap();
    let identity = factor_identity(&n);
    VALIDATED_FACTORS
        .lock()
        .unwrap()
        .retain(|known| *known != identity);
}

fn factors_are_prime(n: &BigNumRef, larger: &[u8], smaller: &[u8]) -> Result<bool, Transient> {
    let identity = factor_identity(n);
    {
        let validated = transient(VALIDATED_FACTORS.lock())?;
        if validated
            .iter()
            .any(|known| bool::from(known.ct_eq(&identity)))
        {
            return Ok(true);
        }
    }
    if bool::from(larger.ct_eq(smaller)) {
        return Ok(false);
    }
    #[cfg(test)]
    PRIMALITY_TESTS.with(|count| count.set(count.get() + 1));
    let mut ctx = transient(BigNumContext::new())?;
    for factor in [larger, smaller] {
        let value = transient(SecretBn::from_be(factor))?;
        present(checkpoint(Boundary::Primality))?;
        if !transient(check_prime(&value, &mut ctx))? {
            return Ok(false);
        }
    }
    let mut validated = transient(VALIDATED_FACTORS.lock())?;
    if validated.len() == VALIDATED_FACTOR_SETS {
        validated.pop_front();
    }
    validated.push_back(identity);
    Ok(true)
}

fn prepared(key: &RsaCrtKey<'_>) -> Option<Arc<PreparedRsaKey>> {
    let fingerprint = fingerprint(key);
    let Some(cache) = key.cache else {
        return prepare(key, fingerprint).ok().map(Arc::new);
    };
    let mut slot = cache.0.lock().ok()?;
    if let Some(current) = slot.as_ref()
        && bool::from(current.fingerprint.ct_eq(&fingerprint))
    {
        return Some(Arc::clone(current));
    }
    *slot = None;
    let fresh = Arc::new(prepare(key, fingerprint).ok()?);
    *slot = Some(Arc::clone(&fresh));
    Some(fresh)
}

fn private_operation(native: &Rsa<Private>, modulus: &[u8], input: &[u8]) -> Option<Vec<u8>> {
    let mut ctx = BigNumContext::new().ok()?;
    let n = BigNum::from_slice(modulus).ok()?;
    let mut ciphertext = BigNum::from_slice(input).ok()?;
    if ciphertext.ucmp(&n).is_ge() {
        let mut reduced = BigNum::new().ok()?;
        reduced.nnmod(&ciphertext, &n, &mut ctx).ok()?;
        ciphertext = reduced;
    }
    let width = usize::try_from(n.num_bytes()).ok()?;
    let block = fixed_width(&ciphertext, width)?;
    let mut decrypted = vec![0u8; width];
    let written = native.private_decrypt(&block, &mut decrypted, Padding::NONE);
    if written.ok() != Some(width) {
        cleanse(&mut decrypted);
        return None;
    }
    let mut output = vec![0u8; modulus.len().max(width)];
    let offset = output.len() - width;
    output[offset..].copy_from_slice(&decrypted);
    cleanse(&mut decrypted);
    Some(zero_is_one_byte(output))
}

fn even_modulus_result(value: &[u8], length: usize) -> Vec<u8> {
    let significant = value
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(value.len());
    let value = &value[significant..];
    let mut unchanged = vec![0u8; length];
    unchanged[length - value.len()..].copy_from_slice(value);
    unchanged[0] = 0;
    unchanged
}

pub(in crate::library::tpm2) fn rsa_public_key_op(
    modulus: &[u8],
    exponent: u32,
    value: &[u8],
) -> Option<Vec<u8>> {
    let n = BigNum::from_slice(modulus).ok()?;
    let input = BigNum::from_slice(value).ok()?;
    if n.num_bits() == 0 || input.ucmp(&n).is_ge() {
        return None;
    }
    if !n.is_odd() {
        return Some(even_modulus_result(value, modulus.len()));
    }
    if n.num_bits() == 1 {
        return Some(vec![0u8; modulus.len()]);
    }
    let e = BigNum::from_u32(exponent).ok()?;
    let width = usize::try_from(n.num_bytes()).ok()?;
    let mut output = vec![0u8; modulus.len()];
    let offset = modulus.len() - width;
    if n.ucmp(&e).is_gt() && n.num_bits() <= MAX_PUBLIC_OPERATION_BITS {
        let key = Rsa::from_public_components(n, e).ok()?;
        let block = fixed_width(&input, width)?;
        let written = key
            .public_encrypt(&block, &mut output[offset..], Padding::NONE)
            .ok()?;
        return (written == width).then_some(output);
    }
    let mut ctx = BigNumContext::new().ok()?;
    let mut power = BigNum::new().ok()?;
    mod_exp_consttime(&mut power, &input, &e, &n, &mut ctx).ok()?;
    output[offset..].copy_from_slice(&fixed_width(&power, width)?);
    Some(output)
}

pub(in crate::library::tpm2) fn rsa_private_key_op(
    key: &RsaCrtKey<'_>,
    input: &[u8],
) -> Option<Vec<u8>> {
    let prepared = prepared(key)?;
    private_operation(&prepared.key.as_ref()?.rsa, key.modulus, input)
}

const TPM_ALG_SHA1: u16 = 0x0004;
const TPM_ALG_SHA256: u16 = 0x000b;
const TPM_ALG_SHA384: u16 = 0x000c;
const TPM_ALG_SHA512: u16 = 0x000d;

fn message_digest(hash_alg: u16) -> Option<&'static MdRef> {
    Some(match hash_alg {
        TPM_ALG_SHA1 => Md::sha1(),
        TPM_ALG_SHA256 => Md::sha256(),
        TPM_ALG_SHA384 => Md::sha384(),
        TPM_ALG_SHA512 => Md::sha512(),
        _ => return None,
    })
}

pub(in crate::library::tpm2) fn oaep_unpad(
    hash_alg: u16,
    label: &[u8],
    block: &[u8],
) -> Option<Vec<u8>> {
    oaep_check(block, label, message_digest(hash_alg)?)
}

pub(in crate::library::tpm2) fn pkcs1_type2_unpad(block: &[u8]) -> Option<Vec<u8>> {
    pkcs1_type2_check(block)
}

pub(in crate::library::tpm2) fn rsassa_sign(
    key: &RsaCrtKey<'_>,
    hash_alg: u16,
    digest: &[u8],
) -> Option<Vec<u8>> {
    let prepared = prepared(key)?;
    let pkey = &prepared.key.as_ref()?.pkey;
    let mut ctx = PkeyCtx::new(pkey).ok()?;
    ctx.sign_init().ok()?;
    ctx.set_rsa_padding(Padding::PKCS1).ok()?;
    ctx.set_signature_md(message_digest(hash_alg)?).ok()?;
    let mut signature = vec![0u8; pkey.size()];
    let written = ctx.sign(digest, Some(&mut signature)).ok()?;
    signature.truncate(written);
    let width = key.modulus.len().max(signature.len());
    let mut output = vec![0u8; width];
    output[width - signature.len()..].copy_from_slice(&signature);
    Some(output)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) enum RsaSignaturePadding {
    Pkcs1,
    Pss,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) enum PublicCheck {
    Verified,
    Rejected,
    Unsupported,
}

fn native_public_key(modulus: &[u8], exponent: u32) -> Option<PKey<openssl::pkey::Public>> {
    let n = BigNum::from_slice(modulus).ok()?;
    let e = BigNum::from_u32(effective_exponent(exponent)).ok()?;
    let operable = n.is_odd()
        && n.num_bits() > 1
        && n.ucmp(&e).is_gt()
        && n.num_bits() <= MAX_PUBLIC_OPERATION_BITS
        && usize::try_from(n.num_bytes()).ok()? == modulus.len();
    if !operable {
        return None;
    }
    PKey::from_rsa(Rsa::from_public_components(n, e).ok()?).ok()
}

fn full_width(modulus: &[u8]) -> bool {
    BigNum::from_slice(modulus)
        .ok()
        .and_then(|n| usize::try_from(n.num_bits()).ok())
        == Some(8 * modulus.len())
}

pub(in crate::library::tpm2) fn rsa_verify_signature(
    modulus: &[u8],
    exponent: u32,
    padding: RsaSignaturePadding,
    hash_alg: u16,
    digest: &[u8],
    signature: &[u8],
) -> PublicCheck {
    let Some(md) = message_digest(hash_alg) else {
        return PublicCheck::Unsupported;
    };
    if padding == RsaSignaturePadding::Pss && (digest.len() != md.size() || !full_width(modulus)) {
        return PublicCheck::Unsupported;
    }
    let Some(key) = native_public_key(modulus, exponent) else {
        return PublicCheck::Unsupported;
    };
    let verified = || -> Option<bool> {
        let mut ctx = PkeyCtx::new(&key).ok()?;
        ctx.verify_init().ok()?;
        match padding {
            RsaSignaturePadding::Pkcs1 => ctx.set_rsa_padding(Padding::PKCS1).ok()?,
            RsaSignaturePadding::Pss => {
                ctx.set_rsa_padding(Padding::PKCS1_PSS).ok()?;
                ctx.set_signature_md(md).ok()?;
                ctx.set_rsa_mgf1_md(md).ok()?;
                ctx.set_rsa_pss_saltlen(RsaPssSaltlen::custom(-2)).ok()?;
                return ctx.verify(digest, signature).ok();
            }
        }
        ctx.set_signature_md(md).ok()?;
        ctx.verify(digest, signature).ok()
    };
    let outcome = verified();
    let _ = openssl::error::ErrorStack::get();
    match outcome {
        Some(true) => PublicCheck::Verified,
        _ => PublicCheck::Rejected,
    }
}

pub(in crate::library::tpm2) struct CrtCandidate {
    prime_bytes: usize,
    p: SecretBn,
    q: SecretBn,
    d_p: CrtWords,
    d_q: CrtWords,
    q_inv: CrtWords,
    modulus: Option<BigNum>,
}

impl CrtCandidate {
    pub(in crate::library::tpm2) fn new(prime_bytes: usize) -> Option<Self> {
        Some(Self {
            prime_bytes,
            p: SecretBn::new().ok()?,
            q: SecretBn::new().ok()?,
            d_p: [0; CRT_WORDS],
            d_q: [0; CRT_WORDS],
            q_inv: [0; CRT_WORDS],
            modulus: None,
        })
    }

    pub(in crate::library::tpm2) fn set_p(&mut self, prime: &[u8]) -> Option<()> {
        self.p = SecretBn::from_be(prime).ok()?;
        self.modulus = None;
        Some(())
    }

    pub(in crate::library::tpm2) fn q_is_zero(&self) -> bool {
        self.q.num_bits() == 0
    }

    pub(in crate::library::tpm2) fn copy_p_into_q(&mut self) -> Option<()> {
        self.q = self.p.duplicate().ok()?;
        self.modulus = None;
        Some(())
    }

    pub(in crate::library::tpm2) fn clear_q(&mut self) -> Option<()> {
        self.q = SecretBn::new().ok()?;
        self.modulus = None;
        Some(())
    }

    pub(in crate::library::tpm2) fn primes_differ_by_at_least(&self, bits: u32) -> Option<bool> {
        if bits == 0 {
            return Some(true);
        }
        let (larger, smaller) = self.factor_bytes()?;
        let larger = SecretBn::from_be(&larger.0).ok()?;
        let smaller = SecretBn::from_be(&smaller.0).ok()?;
        let mut difference = SecretBn::new().ok()?;
        difference.checked_sub(&larger, &smaller).ok()?;
        Some(u32::try_from(difference.num_bits()).ok()? >= bits)
    }

    fn factor_bytes(&self) -> Option<(PrimeBytes, PrimeBytes)> {
        let width = CRT_BYTES.max(self.prime_bytes.next_multiple_of(WORD_BYTES));
        ordered_prime_bytes(&self.p, &self.q, width)
    }

    pub(in crate::library::tpm2) fn modulus(&mut self) -> Option<Vec<u8>> {
        let mut ctx = BigNumContext::new().ok()?;
        let mut product = BigNum::new().ok()?;
        checkpoint(Boundary::Product)?;
        product.checked_mul(&self.p, &self.q, &mut ctx).ok()?;
        let minimal = product.to_vec();
        self.modulus = Some(BigNum::from_slice(&minimal).ok()?);
        Some(minimal)
    }

    pub(in crate::library::tpm2) fn p_bytes(&self) -> Option<Vec<u8>> {
        self.p
            .to_be(self.prime_bytes.next_multiple_of(WORD_BYTES))
            .ok()
    }

    pub(in crate::library::tpm2) fn q_words(&self) -> Option<CrtWords> {
        crt_words(&self.q)
    }

    pub(in crate::library::tpm2) fn compute(&mut self, exponent: u32) -> Option<bool> {
        let width = CRT_BYTES.max(self.prime_bytes.next_multiple_of(WORD_BYTES));
        let (larger, smaller) = ordered_prime_bytes(&self.p, &self.q, width)?;
        self.p = SecretBn::from_be(&larger.0).ok()?;
        self.q = SecretBn::from_be(&smaller.0).ok()?;
        let mut ctx = BigNumContext::new().ok()?;
        let d_p = crt_exponent(&larger.0, exponent).half()?;
        let d_q = crt_exponent(&smaller.0, exponent).half()?;
        drop((larger, smaller));
        self.modulus.as_ref()?;
        let q_inv = crt_coefficient(&self.q, &self.p, &mut ctx).half()?;
        let q_inv_exists = q_inv.is_some();
        let p_ok = d_p.is_some();
        let q_ok = d_q.is_some();
        let p_kept = p_ok && (!q_ok || q_inv_exists);
        let q_kept = q_ok && (!p_ok || q_inv_exists);
        if let Some(d_p) = d_p {
            self.d_p = d_p;
        }
        if let Some(d_q) = d_q {
            self.d_q = d_q;
        }
        if let Some(q_inv) = q_inv
            && p_ok
            && q_ok
        {
            self.q_inv = q_inv;
        }
        if !p_kept {
            self.p = SecretBn::new().ok()?;
        }
        if !q_kept {
            self.q = SecretBn::new().ok()?;
        }
        Some(p_kept && q_kept)
    }

    pub(in crate::library::tpm2) fn trial(
        &self,
        modulus: &[u8],
        exponent: u32,
        input: &[u8],
    ) -> Option<Option<Vec<u8>>> {
        let words = [crt_words(&self.q)?, self.d_p, self.d_q, self.q_inv];
        let prime = self.p_bytes()?;
        let key = RsaCrtKey {
            cache: None,
            modulus,
            exponent,
            prime: &prime,
            q: &words[0],
            d_p: &words[1],
            d_q: &words[2],
            q_inv: &words[3],
        };
        let prepared = prepare(&key, fingerprint(&key)).ok()?;
        let mut prime = prime;
        cleanse(&mut prime);
        Some(match prepared.key.as_ref() {
            Some(native) => Some(private_operation(&native.rsa, modulus, input)?),
            None => None,
        })
    }

    pub(in crate::library::tpm2) fn exponent_words(
        &self,
    ) -> Option<(CrtWords, CrtWords, CrtWords)> {
        Some((self.d_p, self.d_q, self.q_inv))
    }
}

fn quotient(n: &BigNumRef, prime: &[u8], limbs: usize) -> Outcome<SecretBn> {
    #[cfg(test)]
    crate::library::tpm2::memcheck::observe("recovery-prime", prime);
    let divisor = backend!(SecretBn::from_be(prime).ok());
    if divisor.num_bits() == 0 {
        return Outcome::Invalid;
    }
    let mut ctx = backend!(BigNumContext::new().ok());
    let mut quotient = backend!(SecretBn::new().ok());
    let mut remainder = backend!(SecretBn::new().ok());
    backend!(checkpoint(Boundary::Division));
    backend!(quotient.div_rem(&mut remainder, n, &divisor, &mut ctx).ok());
    let quotient_fits = backend!(usize::try_from(quotient.num_bits()).ok()) <= limbs * 64;
    if remainder.num_bits() == 0 && quotient_fits {
        Outcome::Value(quotient)
    } else {
        Outcome::Invalid
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) enum RecoveryError {
    Invalid,
    Backend,
}

pub(in crate::library::tpm2) fn recover_rsa_private_exponent(
    modulus: &[u8],
    prime: &[u8],
    exponent: u32,
) -> Option<RecoveredExponent> {
    recover_rsa_components(modulus, prime, exponent).ok()
}

pub(in crate::library::tpm2) fn recover_rsa_components(
    modulus: &[u8],
    prime: &[u8],
    exponent: u32,
) -> Result<RecoveredExponent, RecoveryError> {
    fn backend<T>(value: Option<T>) -> Result<T, RecoveryError> {
        value.ok_or(RecoveryError::Backend)
    }
    let exponent = effective_exponent(exponent);
    let limbs = crt_limbs(modulus.len(), prime.len()).ok_or(RecoveryError::Invalid)?;
    let n = backend(BigNum::from_slice(modulus).ok())?;
    let quotient = match quotient(&n, prime, limbs) {
        Outcome::Value(quotient) => quotient,
        Outcome::Invalid => return Err(RecoveryError::Invalid),
        Outcome::Backend => return Err(RecoveryError::Backend),
    };
    let mut candidate = backend(CrtCandidate::new(prime.len()))?;
    candidate.p = backend(SecretBn::from_be(prime).ok())?;
    candidate.q = quotient;
    candidate.modulus = Some(n);
    let q = backend(candidate.q_words())?;
    if !backend(candidate.compute(exponent))? {
        return Err(RecoveryError::Invalid);
    }
    let (d_p, d_q, q_inv) = backend(candidate.exponent_words())?;
    Ok(RecoveredExponent { q, d_p, d_q, q_inv })
}

pub(in crate::library::tpm2) fn miller_rabin_witness(
    candidate: &[u8],
    base: &[u8],
    odd_part: &[u8],
    power: u32,
) -> Option<bool> {
    let modulus = SecretBn::from_be(candidate).ok()?;
    if modulus.num_bits() < 2 || !modulus.is_odd() {
        return None;
    }
    let mut ctx = BigNumContext::new().ok()?;
    let mut reduced = SecretBn::new().ok()?;
    let base = SecretBn::from_be(base).ok()?;
    reduced.nnmod(&base, &modulus, &mut ctx).ok()?;
    let exponent = SecretBn::from_be(odd_part).ok()?;
    let mut value = SecretBn::new().ok()?;
    mod_exp_consttime(&mut value, &reduced, &exponent, &modulus, &mut ctx).ok()?;
    let one = SecretBn::from_u32(1).ok()?;
    let mut minus_one = modulus.duplicate().ok()?;
    minus_one.sub_word(1).ok()?;
    if value.ucmp(&one).is_eq() || value.ucmp(&minus_one).is_eq() {
        return Some(true);
    }
    for _ in 1..power {
        let mut squared = SecretBn::new().ok()?;
        squared.mod_sqr(&value, &modulus, &mut ctx).ok()?;
        value = squared;
        if value.ucmp(&minus_one).is_eq() {
            return Some(true);
        }
        if value.ucmp(&one).is_eq() {
            return Some(false);
        }
    }
    Some(false)
}

#[cfg(test)]
pub(in crate::library::tpm2) mod review_keys {
    use super::super::bignum::BigUint;

    pub(in crate::library::tpm2) const SHORT_Q_INV: u64 = 0x0003_8e51;
    pub(in crate::library::tpm2) const FULL_Q_INV: u64 = 0x0003_9273;

    fn power_of_two(bits: usize) -> BigUint {
        BigUint::from_u64(1).unwrap().shl(bits).unwrap()
    }

    fn be(value: &BigUint, width: usize) -> Vec<u8> {
        value.to_be_bytes(width).expect("the value fits")
    }

    pub(in crate::library::tpm2) fn component_length_key(q_low: u64) -> (Vec<u8>, Vec<u8>) {
        let p = BigUint::from_u64(0xf0)
            .unwrap()
            .shl(504)
            .unwrap()
            .add_u64(0x0005_5579)
            .unwrap();
        let q = BigUint::from_u64(0xa0)
            .unwrap()
            .shl(504)
            .unwrap()
            .add_u64(q_low)
            .unwrap();
        (be(&p.mul(&q).unwrap(), 128), be(&p, 64))
    }

    pub(in crate::library::tpm2) fn uneven_key(prime_bits: usize) -> (Vec<u8>, Vec<u8>, BigUint) {
        let (p_low, q_low) = match prime_bits {
            512 => (0x6f, 0x123),
            1024 => (0x483, 0xb1),
            1536 => (0x2bb, 0xe85),
            _ => panic!("no uneven key with {prime_bits}-bit primes"),
        };
        let p = power_of_two(prime_bits - 1).add_u64(p_low).unwrap();
        let q = power_of_two(prime_bits)
            .add(&power_of_two(prime_bits - 12))
            .unwrap()
            .add_u64(q_low)
            .unwrap();
        (
            be(&p.mul(&q).unwrap(), prime_bits / 4),
            be(&p, prime_bits / 8),
            q,
        )
    }
}

#[cfg(test)]
pub(in crate::library::tpm2) fn forget_validated_factor_sets() {
    VALIDATED_FACTORS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
}

#[cfg(test)]
mod tests {
    use super::super::bignum::BigUint;
    use super::review_keys::{FULL_Q_INV, SHORT_Q_INV, component_length_key, uneven_key};
    use super::*;
    use crate::library::cancel::CancellationToken;
    use crate::library::tpm2::crypto::rand_state::SeededRand;
    use crate::library::tpm2::crypto::rsa::generate_rsa_key;

    fn rand(label: &[u8]) -> SeededRand {
        SeededRand::instantiate(&[0x4e; 64], b"CTRSA", label, &[], 1, false)
            .expect("a non-empty derivation input")
    }

    fn int(value: u64) -> BigUint {
        BigUint::from_u64(value).unwrap()
    }

    fn big(bytes: &[u8]) -> BigUint {
        BigUint::from_be_bytes(bytes).unwrap()
    }

    fn be(value: &BigUint, width: usize) -> Vec<u8> {
        value.to_be_bytes(width).expect("the value fits")
    }

    fn value_of(words: &CrtWords) -> BigUint {
        big(&words_be(words))
    }

    fn words_of(value: &BigUint) -> CrtWords {
        let bytes = be(value, CRT_BYTES);
        let mut words = [0u64; CRT_WORDS];
        for (index, word) in words.iter_mut().enumerate() {
            let end = CRT_BYTES - index * WORD_BYTES;
            *word = u64::from_be_bytes(bytes[end - WORD_BYTES..end].try_into().unwrap());
        }
        words
    }

    struct Key {
        modulus: Vec<u8>,
        prime: Vec<u8>,
        words: [CrtWords; 4],
    }

    impl Key {
        fn crt(&self) -> RsaCrtKey<'_> {
            RsaCrtKey {
                cache: None,
                modulus: &self.modulus,
                exponent: 0,
                prime: &self.prime,
                q: &self.words[0],
                d_p: &self.words[1],
                d_q: &self.words[2],
                q_inv: &self.words[3],
            }
        }
    }

    fn generated(bits: u16, label: &[u8]) -> Key {
        let key = generate_rsa_key(
            bits,
            0,
            false,
            &mut rand(label),
            CancellationToken::disabled(),
        )
        .expect("a key");
        Key {
            modulus: key.modulus,
            prime: key.prime,
            words: [key.q, key.d_p, key.d_q, key.q_inv],
        }
    }

    fn recovered(modulus: Vec<u8>, prime: Vec<u8>) -> Key {
        let recovered = recover_rsa_private_exponent(&modulus, &prime, 0).expect("recovers");
        Key {
            modulus,
            prime,
            words: [recovered.q, recovered.d_p, recovered.d_q, recovered.q_inv],
        }
    }

    fn reference_recover(modulus: &[u8], prime: &[u8], exponent: u32) -> Option<[BigUint; 4]> {
        let e = int(u64::from(effective_exponent(exponent)));
        let p = big(prime);
        if p.is_zero() {
            return None;
        }
        let (q, remainder) = big(modulus).div_rem(&p)?;
        if !remainder.is_zero() {
            return None;
        }
        let (larger, smaller) = if p < q {
            (q.clone(), p)
        } else {
            (p, q.clone())
        };
        let d_p = e.mod_inverse(&larger.sub_u64(1)?)?;
        let d_q = e.mod_inverse(&smaller.sub_u64(1)?)?;
        let q_inv = smaller.mod_inverse(&larger)?;
        Some([q, d_p, d_q, q_inv])
    }

    fn textbook_private(key: &Key, input: &BigUint) -> BigUint {
        let n = big(&key.modulus);
        let p = big(&key.prime);
        let q = value_of(&key.words[0]);
        let phi = p.sub_u64(1).unwrap().mul(&q.sub_u64(1).unwrap()).unwrap();
        let d = int(65537).mod_inverse(&phi).unwrap();
        input.mod_exp(&d, &n).unwrap()
    }

    #[test]
    fn private_operation_matches_the_textbook_exponentiation() {
        for (bits, label) in [
            (1024u16, b"op1024".as_slice()),
            (2048, b"op2048"),
            (3072, b"op3072"),
        ] {
            let key = generated(bits, label);
            let length = key.modulus.len();
            let n = big(&key.modulus);
            let mut generator = rand(label);
            let mut inputs = vec![
                be(&int(1), length),
                be(&n.sub_u64(1).unwrap(), length),
                be(&big(&key.prime), length),
            ];
            for _ in 0..3 {
                let mut draw = generator.random_bytes(length).unwrap();
                draw[0] &= 0x7f;
                inputs.push(draw);
            }
            for input in &inputs {
                let expected = be(&textbook_private(&key, &big(input)), length);
                assert_eq!(
                    rsa_private_key_op(&key.crt(), input),
                    Some(expected),
                    "keyBits {bits}"
                );
            }
            let swapped = recovered(
                key.modulus.clone(),
                be(&value_of(&key.words[0]), key.prime.len()),
            );
            assert_eq!(
                rsa_private_key_op(&swapped.crt(), &inputs[3]),
                rsa_private_key_op(&key.crt(), &inputs[3]),
                "keyBits {bits}: either stored prime yields the same result"
            );
        }
    }

    #[test]
    fn prepared_key_is_reused_until_the_components_change() {
        let key = generated(2048, b"cache");
        let cache = RsaRuntimeCache::default();
        let message = be(&int(0x0bad_cafe), key.modulus.len());
        let ciphertext = rsa_public_key_op(&key.modulus, 65537, &message).unwrap();
        let cached = RsaCrtKey {
            cache: Some(&cache),
            ..key.crt()
        };
        let before = prepared_key_count();
        for _ in 0..4 {
            assert_eq!(
                rsa_private_key_op(&cached, &ciphertext),
                Some(message.clone())
            );
        }
        assert_eq!(
            prepared_key_count() - before,
            1,
            "four operations, one preparation"
        );
        let shared = cache.clone();
        let through_clone = RsaCrtKey {
            cache: Some(&shared),
            ..key.crt()
        };
        assert_eq!(
            rsa_private_key_op(&through_clone, &ciphertext),
            Some(message.clone())
        );
        assert_eq!(
            prepared_key_count() - before,
            1,
            "a cloned object reuses the prepared key"
        );

        let mut changed = key.words[3];
        changed[0] ^= 4;
        let restored = RsaCrtKey {
            cache: Some(&cache),
            q_inv: &changed,
            ..key.crt()
        };
        assert_eq!(
            rsa_private_key_op(&restored, &ciphertext),
            Some(message.clone()),
            "the stored qInv is not used by the native key, so the result is correct"
        );
        assert_eq!(
            prepared_key_count() - before,
            2,
            "a changed component rebuilds the key"
        );
        assert_eq!(
            rsa_private_key_op(&cached, &ciphertext),
            Some(message.clone())
        );
        assert_eq!(
            prepared_key_count() - before,
            3,
            "the original components rebuild again"
        );

        let fresh = RsaRuntimeCache::default();
        let reloaded = RsaCrtKey {
            cache: Some(&fresh),
            ..key.crt()
        };
        assert_eq!(rsa_private_key_op(&reloaded, &ciphertext), Some(message));
        assert_eq!(
            prepared_key_count() - before,
            4,
            "a new object instance prepares its own key"
        );
    }

    #[test]
    fn prepared_key_binds_modulus_exponent_and_prime() {
        let key = generated(1024, b"binding");
        let cache = RsaRuntimeCache::default();
        let message = be(&int(0x77), key.modulus.len());
        let ciphertext = rsa_public_key_op(&key.modulus, 65537, &message).unwrap();
        let cached = RsaCrtKey {
            cache: Some(&cache),
            ..key.crt()
        };
        assert_eq!(
            rsa_private_key_op(&cached, &ciphertext),
            Some(message.clone())
        );
        let mut other_modulus = key.modulus.clone();
        let last = other_modulus.len() - 1;
        other_modulus[last] ^= 2;
        let other = RsaCrtKey {
            cache: Some(&cache),
            modulus: &other_modulus,
            ..key.crt()
        };
        assert_eq!(
            rsa_private_key_op(&other, &ciphertext),
            None,
            "a cache entry is never reused for another modulus"
        );
        let wrong_exponent = RsaCrtKey {
            cache: Some(&cache),
            exponent: 3,
            ..key.crt()
        };
        assert_eq!(rsa_private_key_op(&wrong_exponent, &ciphertext), None);
        assert_eq!(rsa_private_key_op(&cached, &ciphertext), Some(message));
    }

    fn digest_info(hash_alg: u16, digest: &[u8]) -> Vec<u8> {
        let prefix: &[u8] = match hash_alg {
            TPM_ALG_SHA1 => &[
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
                0x14,
            ],
            TPM_ALG_SHA256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            TPM_ALG_SHA384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            TPM_ALG_SHA512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
            _ => panic!("no DigestInfo"),
        };
        let mut out = prefix.to_vec();
        out.extend_from_slice(digest);
        out
    }

    const HASHES: [(u16, usize); 4] = [
        (TPM_ALG_SHA1, 20),
        (TPM_ALG_SHA256, 32),
        (TPM_ALG_SHA384, 48),
        (TPM_ALG_SHA512, 64),
    ];

    #[test]
    fn rsassa_signatures_match_the_pkcs1_v1_5_encoding_for_every_size_and_hash() {
        for (bits, label) in [
            (1024u16, b"sig1024".as_slice()),
            (2048, b"sig2048"),
            (3072, b"sig3072"),
        ] {
            let key = generated(bits, label);
            let mut generator = rand(label);
            for (hash_alg, hash_len) in HASHES {
                let digest = generator.random_bytes(hash_len).unwrap();
                let signature = rsassa_sign(&key.crt(), hash_alg, &digest).expect("a signature");
                assert_eq!(signature.len(), key.modulus.len());
                let block = rsa_public_key_op(&key.modulus, 65537, &signature).unwrap();
                let info = digest_info(hash_alg, &digest);
                let mut expected = vec![0x00, 0x01];
                expected.resize(key.modulus.len() - info.len() - 1, 0xff);
                expected.push(0x00);
                expected.extend_from_slice(&info);
                assert_eq!(block, expected, "keyBits {bits} hash {hash_alg:#06x}");
                assert_eq!(
                    rsa_verify_signature(
                        &key.modulus,
                        0,
                        RsaSignaturePadding::Pkcs1,
                        hash_alg,
                        &digest,
                        &signature
                    ),
                    PublicCheck::Verified
                );
                let mut tampered = signature.clone();
                tampered[10] ^= 1;
                assert_eq!(
                    rsa_verify_signature(
                        &key.modulus,
                        0,
                        RsaSignaturePadding::Pkcs1,
                        hash_alg,
                        &digest,
                        &tampered
                    ),
                    PublicCheck::Rejected
                );
                let other = if hash_alg == TPM_ALG_SHA256 {
                    TPM_ALG_SHA384
                } else {
                    TPM_ALG_SHA256
                };
                assert_eq!(
                    rsa_verify_signature(
                        &key.modulus,
                        0,
                        RsaSignaturePadding::Pkcs1,
                        other,
                        &digest,
                        &signature
                    ),
                    PublicCheck::Rejected,
                    "the DigestInfo names the hash"
                );
            }
        }
    }

    fn pss_signature(key: &Key, hash_alg: u16, digest: &[u8], salt: i32) -> Vec<u8> {
        let prepared = prepared(&key.crt()).unwrap();
        let pkey = &prepared.key.as_ref().unwrap().pkey;
        let md = message_digest(hash_alg).unwrap();
        let mut ctx = PkeyCtx::new(pkey).unwrap();
        ctx.sign_init().unwrap();
        ctx.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
        ctx.set_signature_md(md).unwrap();
        ctx.set_rsa_mgf1_md(md).unwrap();
        ctx.set_rsa_pss_saltlen(RsaPssSaltlen::custom(salt))
            .unwrap();
        let mut signature = vec![0u8; key.modulus.len()];
        let written = ctx.sign(digest, Some(&mut signature)).unwrap();
        assert_eq!(written, key.modulus.len());
        signature
    }

    #[test]
    fn pss_verification_accepts_every_salt_length() {
        for (bits, label) in [
            (1024u16, b"pss1024".as_slice()),
            (2048, b"pss2048"),
            (3072, b"pss3072"),
        ] {
            let key = generated(bits, label);
            let mut generator = rand(label);
            for (hash_alg, hash_len) in HASHES {
                let digest = generator.random_bytes(hash_len).unwrap();
                let maximum = (key.modulus.len() - hash_len - 2) as i32;
                for salt in [0, 1, (hash_len as i32).min(maximum), maximum] {
                    let signature = pss_signature(&key, hash_alg, &digest, salt);
                    assert_eq!(
                        rsa_verify_signature(
                            &key.modulus,
                            0,
                            RsaSignaturePadding::Pss,
                            hash_alg,
                            &digest,
                            &signature
                        ),
                        PublicCheck::Verified,
                        "keyBits {bits} hash {hash_alg:#06x} salt {salt}"
                    );
                    let mut other = digest.clone();
                    other[0] ^= 1;
                    assert_eq!(
                        rsa_verify_signature(
                            &key.modulus,
                            0,
                            RsaSignaturePadding::Pss,
                            hash_alg,
                            &other,
                            &signature
                        ),
                        PublicCheck::Rejected
                    );
                }
                assert_eq!(
                    rsa_verify_signature(
                        &key.modulus,
                        0,
                        RsaSignaturePadding::Pss,
                        hash_alg,
                        &digest[1..],
                        &[0u8; 1]
                    ),
                    PublicCheck::Unsupported,
                    "a digest of another length stays with the TPM decoder"
                );
            }
        }
    }

    #[test]
    fn keys_openssl_cannot_operate_on_are_left_to_the_tpm_decoder() {
        let mut even = vec![0xc0u8; 256];
        even[255] = 0x02;
        assert_eq!(
            rsa_verify_signature(
                &even,
                0,
                RsaSignaturePadding::Pkcs1,
                TPM_ALG_SHA256,
                &[0; 32],
                &[1; 256]
            ),
            PublicCheck::Unsupported
        );
        assert_eq!(
            rsa_verify_signature(
                &[0x0c, 0xa1],
                65537,
                RsaSignaturePadding::Pkcs1,
                TPM_ALG_SHA256,
                &[0; 32],
                &[1; 2]
            ),
            PublicCheck::Unsupported,
            "an exponent above the modulus"
        );
        let key = generated(1024, b"unsupported-hash");
        assert_eq!(
            rsa_verify_signature(
                &key.modulus,
                0,
                RsaSignaturePadding::Pkcs1,
                0x0012,
                &[0; 32],
                &[1; 128]
            ),
            PublicCheck::Unsupported,
            "a hash without an OpenSSL digest here"
        );
    }

    #[test]
    fn padding_checkers_reject_explicitly() {
        let key = generated(1024, b"explicit");
        let mut generator = rand(b"explicit");
        for _ in 0..32 {
            let block = generator.random_bytes(128).unwrap();
            assert_eq!(
                pkcs1_type2_unpad(&block),
                None,
                "no implicit-rejection plaintext"
            );
            assert_eq!(oaep_unpad(TPM_ALG_SHA256, b"", &block), None);
        }
        let mut empty = vec![0x00, 0x02];
        empty.resize(127, 0x55);
        empty.push(0x00);
        assert_eq!(
            pkcs1_type2_unpad(&empty),
            Some(Vec::new()),
            "an empty message decodes"
        );
        let _ = key;
    }

    #[test]
    fn zero_private_result_single_byte() {
        let key = generated(1024, b"zero-result");
        let length = key.modulus.len();
        assert_eq!(
            rsa_private_key_op(&key.crt(), &vec![0u8; length]),
            Some(vec![0u8]),
            "TpmMath_IntTo2B of a zero result is one zero byte"
        );
        assert_eq!(rsa_private_key_op(&key.crt(), &[0u8]), Some(vec![0u8]));
        let one = be(&int(1), length);
        assert_eq!(rsa_private_key_op(&key.crt(), &one), Some(one.clone()));
    }

    #[test]
    fn oversized_input_reduces_like_the_reference() {
        let key = generated(1024, b"wide");
        let wide = [0x11u8; 257];
        let reduced = big(&wide).rem(&big(&key.modulus)).unwrap();
        assert_eq!(
            rsa_private_key_op(&key.crt(), &wide),
            rsa_private_key_op(&key.crt(), &be(&reduced, 128)),
            "callers reject inputs above the modulus; the operation itself reduces them"
        );
    }

    #[test]
    fn unusable_prime_explicit_failure() {
        let key = generated(1024, b"even");
        let input = vec![0x11u8; 128];
        let mut even = key.prime.clone();
        let last = even.len() - 1;
        even[last] &= 0xfe;
        let mut broken = RsaCrtKey {
            prime: &even,
            ..key.crt()
        };
        assert_eq!(rsa_private_key_op(&broken, &input), None, "an even prime");
        let zero = [0u8; 64];
        broken.prime = &zero;
        assert_eq!(rsa_private_key_op(&broken, &input), None, "a zero prime");
        assert!(rsa_private_key_op(&key.crt(), &input).is_some());
    }

    #[test]
    fn inconsistent_restored_components_fail_instead_of_returning_a_faulty_result() {
        let key = generated(1024, b"faulty");
        let message = be(&int(0x1234_5678), 128);
        let ciphertext = rsa_public_key_op(&key.modulus, 65537, &message).unwrap();
        let mut wrong_d_p = key.words[1];
        wrong_d_p[0] ^= 2;
        let faulty = RsaCrtKey {
            d_p: &wrong_d_p,
            ..key.crt()
        };
        assert_eq!(
            rsa_private_key_op(&faulty, &ciphertext),
            Some(message.clone()),
            "the native key ignores the stored CRT values, so a faulty dP cannot change the result"
        );
        for index in [2usize, 3] {
            let mut wrong = key.words;
            wrong[index][0] ^= 2;
            let faulty = RsaCrtKey {
                d_q: &wrong[2],
                q_inv: &wrong[3],
                ..key.crt()
            };
            for _ in 0..2 {
                assert_eq!(
                    rsa_private_key_op(&faulty, &ciphertext),
                    Some(message.clone()),
                    "a faulty dQ or qInv with consistent factors keeps the fault recovery"
                );
            }
        }
        let mut wrong_q = key.words[0];
        wrong_q[0] ^= 2;
        let mismatched = RsaCrtKey {
            q: &wrong_q,
            ..key.crt()
        };
        assert_eq!(
            rsa_private_key_op(&mismatched, &ciphertext),
            None,
            "a stored q that does not divide the modulus is rejected"
        );
    }

    #[test]
    fn factors_with_the_sum_of_the_key_never_become_usable() {
        for bits in [1024u16, 2048] {
            let key = generated(bits, b"same sum");
            let n = big(&key.modulus);
            let p = big(&key.prime);
            let q = value_of(&key.words[0]);
            let shifted_p = p.add_u64(2).unwrap();
            let shifted_q = q.sub_u64(2).unwrap();
            assert_eq!(shifted_p.add(&shifted_q).unwrap(), p.add(&q).unwrap());
            assert!(shifted_p.mul(&shifted_q).unwrap() != n);
            let message = be(&int(0x5a5a_0001), key.modulus.len());
            let ciphertext = rsa_public_key_op(&key.modulus, 65537, &message).unwrap();

            let phi = p.sub_u64(1).unwrap().mul(&q.sub_u64(1).unwrap()).unwrap();
            let d = int(65537).mod_inverse(&phi).unwrap();
            let bn = |value: &BigUint| {
                BigNum::from_slice(&value.to_be_bytes(value.byte_len()).unwrap()).unwrap()
            };
            let unchecked = Rsa::from_private_components(
                bn(&n),
                BigNum::from_u32(65537).unwrap(),
                bn(&d),
                bn(&shifted_p),
                bn(&shifted_q),
                bn(&value_of(&key.words[1])),
                bn(&value_of(&key.words[2])),
                bn(&value_of(&key.words[3])),
            )
            .unwrap();
            let mut decrypted = vec![0u8; key.modulus.len()];
            assert_eq!(
                unchecked
                    .private_decrypt(&ciphertext, &mut decrypted, Padding::NONE)
                    .ok(),
                Some(key.modulus.len())
            );
            assert_eq!(
                decrypted, message,
                "OpenSSL's fallback hides the wrong factors, so a round trip trial accepts them"
            );

            let shifted_prime = be(&shifted_p, key.prime.len());
            let shifted_words = words_of(&shifted_q);
            let inconsistent = RsaCrtKey {
                prime: &shifted_prime,
                q: &shifted_words,
                ..key.crt()
            };
            for _ in 0..3 {
                let prepared = prepare(&inconsistent, fingerprint(&inconsistent));
                assert!(matches!(prepared, Ok(PreparedRsaKey { key: None, .. })));
                assert_eq!(rsa_private_key_op(&inconsistent, &ciphertext), None);
            }

            let cache = RsaRuntimeCache::default();
            let cached = RsaCrtKey {
                cache: Some(&cache),
                ..inconsistent
            };
            let before = prepared_key_count();
            for _ in 0..3 {
                assert_eq!(rsa_private_key_op(&cached, &ciphertext), None);
            }
            assert_eq!(
                prepared_key_count() - before,
                1,
                "the rejection is cached and never turns into a usable key"
            );
            let valid = RsaCrtKey {
                cache: Some(&cache),
                ..key.crt()
            };
            assert_eq!(
                rsa_private_key_op(&valid, &ciphertext),
                Some(message.clone())
            );

            let mut candidate = CrtCandidate::new(key.prime.len()).unwrap();
            candidate.p = SecretBn::from_be(&shifted_prime).unwrap();
            candidate.q = secret_words(&shifted_words).unwrap();
            candidate.d_p = key.words[1];
            candidate.d_q = key.words[2];
            candidate.q_inv = key.words[3];
            assert_eq!(
                candidate.trial(&key.modulus, 65537, &ciphertext),
                Some(None),
                "key generation's trial goes through the same rejection"
            );

            let mixed_words = words_of(&q);
            let mixed = RsaCrtKey {
                prime: &shifted_prime,
                q: &mixed_words,
                ..key.crt()
            };
            assert_eq!(rsa_private_key_op(&mixed, &ciphertext), None);
        }
    }

    fn toy_key(larger: u64, smaller: u64) -> Key {
        Key {
            modulus: be(&int(larger).mul(&int(smaller)).unwrap(), 8),
            prime: be(&int(larger), 8),
            words: [
                words_of(&int(smaller)),
                [0; CRT_WORDS],
                [0; CRT_WORDS],
                [0; CRT_WORDS],
            ],
        }
    }

    #[test]
    fn prime_factors_of_another_modulus_never_become_usable() {
        for (larger, smaller, wrong_larger, wrong_smaller) in [
            (61u64, 53u64, 71u64, 67u64),
            (1_000_003, 999_983, 1_000_033, 999_979),
        ] {
            let key = toy_key(larger, smaller);
            let mut other = toy_key(wrong_larger, wrong_smaller);
            other.modulus = key.modulus.clone();
            let n = int(larger).mul(&int(smaller)).unwrap();
            let message = int(0x2a);
            let ciphertext = be(&message.mod_exp(&int(65537), &n).unwrap(), 8);
            assert_eq!(
                rsa_private_key_op(&key.crt(), &ciphertext).map(|plain| big(&plain)),
                Some(message),
                "{larger} x {smaller}: the genuine factors decrypt"
            );
            for _ in 0..2 {
                assert!(matches!(
                    prepare(&other.crt(), fingerprint(&other.crt())),
                    Ok(PreparedRsaKey { key: None, .. })
                ));
                assert_eq!(
                    rsa_private_key_op(&other.crt(), &ciphertext),
                    None,
                    "{wrong_larger} x {wrong_smaller} are primes of another modulus"
                );
            }
        }
    }

    #[test]
    #[ignore = "F14 memo regression: run under valgrind --tool=memcheck"]
    fn memcheck_memo_lookup_never_branches_on_another_keys_factors() {
        use crate::library::tpm2::memcheck::{error_count, traced};
        let concealed = generated(1024, b"memo concealed");
        let control = generated(1024, b"memo control");
        let ordered = |key: &Key| {
            let n = BigNum::from_slice(&key.modulus).unwrap();
            let stored = SecretBn::from_be(&key.prime).unwrap();
            let other = secret_words(&key.words[0]).unwrap();
            let (larger, smaller) = ordered_prime_bytes(&stored, &other, CRT_BYTES).unwrap();
            (n, larger, smaller)
        };
        forget_validated_factor_sets();
        let (n, larger, smaller) = ordered(&concealed);
        let (valid, _) = traced(true, || {
            crate::library::tpm2::memcheck::secret(&larger.0);
            crate::library::tpm2::memcheck::secret(&smaller.0);
            factors_are_prime(&n, &larger.0, &smaller.0).ok()
        });
        assert_eq!(valid, Some(true), "the concealed key validates");
        let (n, larger, smaller) = ordered(&control);
        let (valid, _) = traced(false, || factors_are_prime(&n, &larger.0, &smaller.0).ok());
        assert_eq!(valid, Some(true), "the control key validates");
        assert_eq!(validated_factor_sets(), 2);
        let before = error_count();
        let (hit, _) = traced(false, || factors_are_prime(&n, &larger.0, &smaller.0).ok());
        let during = error_count() - before;
        assert_eq!(hit, Some(true), "the control key hits the memo");
        assert_eq!(
            during, 0,
            "the memo lookup never branches on the secret factors of another validated key"
        );
        forget_validated_factor_sets();
    }

    #[test]
    fn a_validated_modulus_never_admits_another_factorization() {
        let (larger, smaller) = (1_000_003u64, 999_983u64);
        let key = toy_key(larger, smaller);
        let n = int(larger).mul(&int(smaller)).unwrap();
        let ciphertext = be(&int(0x2a).mod_exp(&int(65537), &n).unwrap(), 8);
        assert!(rsa_private_key_op(&key.crt(), &ciphertext).is_some());
        let identity = factor_identity(&BigNum::from_slice(&key.modulus).unwrap());
        assert!(
            VALIDATED_FACTORS.lock().unwrap().contains(&identity),
            "the memo holds the public modulus identity"
        );
        let trivial = |stored: &BigUint, other: &BigUint| Key {
            modulus: key.modulus.clone(),
            prime: be(stored, 8),
            words: [
                words_of(other),
                [0; CRT_WORDS],
                [0; CRT_WORDS],
                [0; CRT_WORDS],
            ],
        };
        for candidate in [
            trivial(&int(1), &n),
            trivial(&n, &int(1)),
            trivial(&int(larger), &int(smaller + 2)),
            trivial(&int(larger + 2), &int(smaller)),
        ] {
            assert!(
                matches!(
                    prepare(&candidate.crt(), fingerprint(&candidate.crt())),
                    Ok(PreparedRsaKey { key: None, .. })
                ),
                "only the validated factorization of a memoised modulus is usable"
            );
        }
        forget_factor_set(&key.crt());
    }

    #[test]
    fn invalid_factor_sets_never_become_usable() {
        for (first, second, wrong_message) in [(1093u64, 1093u64, 3u64), (9, 763, 5), (3, 341, 5)] {
            let n = int(first).mul(&int(second)).unwrap();
            let phi = int(first - 1).mul(&int(second - 1)).unwrap();
            let d = int(65537).mod_inverse(&phi).unwrap();
            let two = int(2);
            assert_eq!(
                two.mod_exp(&d, &n)
                    .unwrap()
                    .mod_exp(&int(65537), &n)
                    .unwrap(),
                two,
                "{first} x {second} passes the removed base-2 check"
            );
            let ciphertext = int(wrong_message).mod_exp(&int(65537), &n).unwrap();
            assert_ne!(
                ciphertext.mod_exp(&d, &n).unwrap(),
                int(wrong_message),
                "{first} x {second}: the exponent derived from these factors is faulty"
            );
            let ciphertext = be(&ciphertext, 8);
            for (stored, other) in [(first, second), (second, first)] {
                let key = toy_key(stored, other);
                let cache = RsaRuntimeCache::default();
                let cached = RsaCrtKey {
                    cache: Some(&cache),
                    ..key.crt()
                };
                let before = prepared_key_count();
                for _ in 0..3 {
                    let prepared = prepare(&key.crt(), fingerprint(&key.crt()));
                    assert!(matches!(prepared, Ok(PreparedRsaKey { key: None, .. })));
                    assert_eq!(rsa_private_key_op(&key.crt(), &ciphertext), None);
                    assert_eq!(rsa_private_key_op(&cached, &ciphertext), None);
                }
                assert_eq!(
                    prepared_key_count() - before,
                    1,
                    "the rejection stays cached"
                );
                let mut candidate = CrtCandidate::new(8).unwrap();
                candidate.p = SecretBn::from_be(&key.prime).unwrap();
                candidate.q = secret_words(&key.words[0]).unwrap();
                assert_eq!(
                    candidate.trial(&key.modulus, 65537, &ciphertext),
                    Some(None),
                    "{stored} x {other}"
                );
            }
        }
    }

    fn small_primes(from: u64, count: usize) -> Vec<u64> {
        (from..)
            .filter(|candidate| {
                candidate % 2 == 1
                    && (3..)
                        .take_while(|d| d * d <= *candidate)
                        .all(|d| candidate % d != 0)
            })
            .take(count)
            .collect()
    }

    fn prepares_with_tests(key: &Key) -> u64 {
        let message = be(&int(5), key.modulus.len());
        let ciphertext = rsa_public_key_op(&key.modulus, 65537, &message).unwrap();
        let before = primality_test_count();
        let cache = RsaRuntimeCache::default();
        let cached = RsaCrtKey {
            cache: Some(&cache),
            ..key.crt()
        };
        assert_eq!(rsa_private_key_op(&cached, &ciphertext), Some(message));
        primality_test_count() - before
    }

    #[test]
    fn primality_memo_is_only_an_optimisation_across_cold_warm_restart_and_eviction() {
        let primes = small_primes(20_011, 140);
        let key = toy_key(primes[1], primes[0]);
        assert_eq!(
            prepares_with_tests(&key),
            1,
            "cold: the factor set is tested"
        );
        assert_eq!(
            prepares_with_tests(&key),
            0,
            "warm: the memo skips the test"
        );
        forget_factor_set(&key.crt());
        assert_eq!(
            prepares_with_tests(&key),
            1,
            "a restarted process tests again"
        );
        for pair in primes[2..].chunks(2).take(VALIDATED_FACTOR_SETS) {
            prepares_with_tests(&toy_key(pair[1], pair[0]));
        }
        assert_eq!(
            prepares_with_tests(&key),
            1,
            "after 64 other valid factor sets the first one is tested again"
        );
        let invalid = toy_key(primes[1], primes[1]);
        let ciphertext = be(
            &int(3).mod_exp(&int(65537), &big(&invalid.modulus)).unwrap(),
            8,
        );
        for _ in 0..2 {
            assert_eq!(
                rsa_private_key_op(&invalid.crt(), &ciphertext),
                None,
                "invalid sets are never memoised"
            );
        }
    }

    #[test]
    fn primality_memo_tolerates_concurrent_first_use() {
        let primes = small_primes(40_009, 2);
        let key = std::sync::Arc::new(toy_key(primes[1], primes[0]));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
        let tests: u64 = (0..4)
            .map(|_| {
                let key = std::sync::Arc::clone(&key);
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    prepares_with_tests(&key)
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .sum();
        assert!(
            (1..=4).contains(&tests),
            "{tests} concurrent first uses tested the set"
        );
        assert_eq!(
            prepares_with_tests(&key),
            0,
            "afterwards the set is memoised"
        );
    }

    #[test]
    fn prime_validation_runs_once_per_factor_set_and_valid_keys_keep_working() {
        let key = generated(1024, b"validated once");
        let message = be(&int(0x0102_0304), key.modulus.len());
        let ciphertext = rsa_public_key_op(&key.modulus, 65537, &message).unwrap();
        let tests = primality_test_count();
        let preparations = prepared_key_count();
        for _ in 0..4 {
            let cache = RsaRuntimeCache::default();
            let reloaded = RsaCrtKey {
                cache: Some(&cache),
                ..key.crt()
            };
            assert_eq!(
                rsa_private_key_op(&reloaded, &ciphertext),
                Some(message.clone())
            );
            assert_eq!(
                rsa_private_key_op(&reloaded, &ciphertext),
                Some(message.clone())
            );
        }
        assert_eq!(
            prepared_key_count() - preparations,
            4,
            "every instance prepares"
        );
        let prepared = prepared(&key.crt()).unwrap();
        let native = &prepared.key.as_ref().unwrap().rsa;
        assert!(
            native.p().is_some()
                && native.q().is_some()
                && native.dmp1().is_some()
                && native.dmq1().is_some()
                && native.iqmp().is_some(),
            "the native key is a complete CRT key"
        );
        assert_eq!(
            native.check_key().ok(),
            Some(true),
            "OpenSSL accepts the CRT key"
        );
        assert!(
            primality_test_count() - tests <= 1,
            "the primality test of one factor set runs at most once per process"
        );
        let mut swapped_words = key.words;
        let q = value_of(&key.words[0]);
        swapped_words[0] = words_of(&big(&key.prime));
        let other_order = Key {
            modulus: key.modulus.clone(),
            prime: be(&q, key.prime.len()),
            words: swapped_words,
        };
        assert_eq!(
            rsa_private_key_op(&other_order.crt(), &ciphertext),
            Some(message),
            "either stored prime order works"
        );
    }

    fn injected_failures(
        boundary: super::super::fault::Boundary,
        mut attempt: impl FnMut() -> bool,
    ) -> usize {
        use super::super::fault::{arm, disarm, fired};
        for skipped in 0..512 {
            let before = fired();
            arm(boundary, skipped);
            let succeeded = attempt();
            let hit = fired() != before;
            disarm();
            if !hit {
                assert!(succeeded, "{boundary:?}: an undisturbed attempt succeeds");
                return skipped;
            }
            assert!(
                !succeeded,
                "{boundary:?} #{skipped}: a backend failure is reported"
            );
        }
        panic!("{boundary:?} is hit more than 512 times");
    }

    #[test]
    fn recovery_backend_failures_are_reported_as_failures() {
        use super::super::fault::Boundary;
        let key = generated(1024, b"recovery faults");
        for boundary in [Boundary::Division, Boundary::Inverse] {
            let injected = injected_failures(boundary, || {
                match recover_rsa_private_exponent(&key.modulus, &key.prime, 0) {
                    Some(recovered) => {
                        assert_eq!(
                            [recovered.q, recovered.d_p, recovered.d_q, recovered.q_inv],
                            key.words
                        );
                        true
                    }
                    None => false,
                }
            });
            eprintln!("recovery: {boundary:?} failed at {injected} points");
            assert!(injected > 0, "{boundary:?} is on the recovery path");
            let retried = recovered(key.modulus.clone(), key.prime.clone());
            assert_eq!(
                retried.words, key.words,
                "the same key recovers after the failures"
            );
        }
    }

    #[test]
    fn compatibility_inverse_paths_report_backend_failures_as_failures() {
        use super::super::fault::Boundary;
        for (modulus, prime, exponent, label) in [
            (
                28u64,
                7u64,
                5u32,
                "even n: divided quotient, Euclidean qInv",
            ),
            (77, 11, 1, "unit e: blinded legacy dP/dQ"),
        ] {
            let modulus = modulus.to_be_bytes().to_vec();
            let prime = prime.to_be_bytes().to_vec();
            let reference = recover_rsa_private_exponent(&modulus, &prime, exponent).expect(label);
            let injected = injected_failures(Boundary::Inverse, || {
                match recover_rsa_private_exponent(&modulus, &prime, exponent) {
                    Some(recovered) => {
                        assert_eq!(
                            [recovered.q, recovered.d_p, recovered.d_q, recovered.q_inv],
                            [reference.q, reference.d_p, reference.d_q, reference.q_inv]
                        );
                        true
                    }
                    None => false,
                }
            });
            assert!(injected > 0, "{label}: the inverse boundary is reached");
        }
    }

    #[test]
    fn candidate_computation_keeps_backend_failures_apart_from_invalid_factors() {
        use super::super::fault::{Boundary, arm, disarm};
        let candidate = |p: u64, q: u64| {
            let mut candidate = CrtCandidate::new(8).unwrap();
            candidate.set_p(&p.to_be_bytes()).unwrap();
            candidate.q = SecretBn::from_be(&q.to_be_bytes()).unwrap();
            candidate.modulus().unwrap();
            candidate
        };
        assert_eq!(candidate(13, 17).compute(5), Some(true));
        assert_eq!(
            candidate(7, 11).compute(3),
            Some(false),
            "no inverse is invalid material"
        );
        for (boundary, skipped) in [
            (Boundary::Inverse, 0),
            (Boundary::Inverse, 1),
            (Boundary::Inverse, 2),
        ] {
            let mut subject = candidate(13, 17);
            arm(boundary, skipped);
            assert_eq!(
                subject.compute(5),
                None,
                "{boundary:?} #{skipped} is a backend failure, not Some(false)"
            );
            disarm();
        }
        let mut stale = candidate(13, 17);
        stale.set_p(&19u64.to_be_bytes()).unwrap();
        assert_eq!(
            stale.compute(5),
            None,
            "a changed factor needs a fresh modulus"
        );
    }

    #[test]
    fn recovery_reports_backend_failures_apart_from_invalid_primes() {
        use super::super::fault::{Boundary, arm, disarm};
        let key = generated(1024, b"recovery errors");
        arm(Boundary::Division, 0);
        let failed = recover_rsa_components(&key.modulus, &key.prime, 0);
        disarm();
        assert_eq!(failed.err(), Some(RecoveryError::Backend));
        let mut wrong = key.prime.clone();
        let last = wrong.len() - 1;
        wrong[last] ^= 2;
        assert_eq!(
            recover_rsa_components(&key.modulus, &wrong, 0).err(),
            Some(RecoveryError::Invalid)
        );
        assert!(recover_rsa_components(&key.modulus, &key.prime, 0).is_ok());
    }

    #[test]
    fn preparation_backend_failures_are_retried_and_never_published() {
        use super::super::fault::Boundary;
        let key = generated(1024, b"preparation faults");
        let message = be(&int(0x0a0b_0c0d), key.modulus.len());
        let ciphertext = rsa_public_key_op(&key.modulus, 65537, &message).unwrap();
        for boundary in [
            Boundary::Primality,
            Boundary::Product,
            Boundary::Inverse,
            Boundary::NativeKey,
        ] {
            let injected = injected_failures(boundary, || {
                forget_factor_set(&key.crt());
                let cache = RsaRuntimeCache::default();
                let cached = RsaCrtKey {
                    cache: Some(&cache),
                    ..key.crt()
                };
                match rsa_private_key_op(&cached, &ciphertext) {
                    Some(plain) => {
                        assert_eq!(plain, message);
                        true
                    }
                    None => {
                        assert!(
                            cache.0.lock().unwrap().is_none(),
                            "{boundary:?}: nothing is published after a backend failure"
                        );
                        assert_eq!(
                            rsa_private_key_op(&cached, &ciphertext),
                            Some(message.clone()),
                            "{boundary:?}: the same instance succeeds on retry"
                        );
                        false
                    }
                }
            });
            eprintln!("preparation: {boundary:?} failed at {injected} points");
            assert!(injected > 0, "{boundary:?} is on the preparation path");
            if boundary == Boundary::Primality {
                assert_eq!(injected, 2, "both factors are tested");
            }
        }
        let invalid = toy_key(1093, 1093);
        let ciphertext = be(&int(3).mod_exp(&int(65537), &int(1093 * 1093)).unwrap(), 8);
        assert_eq!(rsa_private_key_op(&invalid.crt(), &ciphertext), None);
    }

    #[test]
    #[ignore = "performance profile; run with --ignored --nocapture on the target"]
    fn rsa_performance_profile() {
        use std::time::Instant;
        let per =
            |start: Instant, count: u32| start.elapsed().as_secs_f64() * 1000.0 / f64::from(count);
        for bits in [1024u16, 2048, 3072] {
            let start = Instant::now();
            let key = generated(bits, format!("profile {bits}").as_bytes());
            let generation = per(start, 1);
            let message = be(&int(0x1234_5678), key.modulus.len());
            let ciphertext = rsa_public_key_op(&key.modulus, 65537, &message).unwrap();
            let rounds = 8u32;
            let start = Instant::now();
            for _ in 0..rounds {
                recover_rsa_private_exponent(&key.modulus, &key.prime, 0).unwrap();
            }
            let recovery = per(start, rounds);
            let start = Instant::now();
            for _ in 0..rounds {
                forget_factor_set(&key.crt());
                let cache = RsaRuntimeCache::default();
                let cold = RsaCrtKey {
                    cache: Some(&cache),
                    ..key.crt()
                };
                assert_eq!(
                    rsa_private_key_op(&cold, &ciphertext),
                    Some(message.clone())
                );
            }
            let cold = per(start, rounds);
            let start = Instant::now();
            for _ in 0..rounds {
                let cache = RsaRuntimeCache::default();
                let warm = RsaCrtKey {
                    cache: Some(&cache),
                    ..key.crt()
                };
                assert_eq!(
                    rsa_private_key_op(&warm, &ciphertext),
                    Some(message.clone())
                );
            }
            let memoised = per(start, rounds);
            let cache = RsaRuntimeCache::default();
            let cached = RsaCrtKey {
                cache: Some(&cache),
                ..key.crt()
            };
            rsa_private_key_op(&cached, &ciphertext).unwrap();
            let operations = 64u32;
            let start = Instant::now();
            for _ in 0..operations {
                rsa_private_key_op(&cached, &ciphertext).unwrap();
            }
            let non_crt = per(start, operations);
            let (p, q) = {
                let stored = big(&key.prime);
                let other = value_of(&key.words[0]);
                if stored < other {
                    (other, stored)
                } else {
                    (stored, other)
                }
            };
            let phi = p.sub_u64(1).unwrap().mul(&q.sub_u64(1).unwrap()).unwrap();
            let d = int(65537).mod_inverse(&phi).unwrap();
            let bn = |value: &BigUint| BigNum::from_slice(&be(value, value.byte_len())).unwrap();
            let crt = Rsa::from_private_components(
                bn(&big(&key.modulus)),
                BigNum::from_u32(65537).unwrap(),
                bn(&d),
                bn(&p),
                bn(&q),
                bn(&value_of(&key.words[1])),
                bn(&value_of(&key.words[2])),
                bn(&value_of(&key.words[3])),
            )
            .unwrap();
            let start = Instant::now();
            for _ in 0..operations {
                assert_eq!(
                    private_operation(&crt, &key.modulus, &ciphertext),
                    Some(message.clone())
                );
            }
            let with_crt = per(start, operations);
            eprintln!(
                "RSA-{bits}: generation {generation:.1} ms; recovery {recovery:.2} ms; cold preparation + first operation {cold:.2} ms; preparation with a validated factor set {memoised:.2} ms; private operation non-CRT {non_crt:.3} ms vs CRT {with_crt:.3} ms ({:.2}x)",
                non_crt / with_crt
            );
        }
    }

    #[test]
    fn crt_coefficient_matches_the_euclidean_inverse() {
        let mut ctx = BigNumContext::new().unwrap();
        let secret =
            |value: u64| SecretBn::adopt(BigNum::from_slice(&value.to_be_bytes()).unwrap());
        for (smaller, larger, expected) in [
            (2u64, 15u64, Some(8u64)),
            (3, 9, None),
            (2, 341, Some(171)),
            (3, 341, Some(114)),
            (3, 16, Some(11)),
            (4, 16, None),
            (5, 1, None),
            (5, 0, None),
            (7, 11, Some(8)),
        ] {
            for _ in 0..16 {
                let inverse = crt_coefficient(&secret(smaller), &secret(larger), &mut ctx)
                    .half()
                    .unwrap();
                assert_eq!(
                    inverse.map(|words| words[0]),
                    expected,
                    "{smaller}^-1 mod {larger}"
                );
            }
        }
        for bits in [1024u16, 2048, 3072] {
            let key = generated(bits, b"coefficient");
            let p = big(&key.prime);
            let q = value_of(&key.words[0]);
            let (larger, smaller) = if p < q { (q, p) } else { (p, q) };
            let reference = smaller.mod_inverse(&larger).unwrap();
            assert_eq!(
                value_of(&key.words[3]),
                reference,
                "{bits}-bit key generation"
            );
            for _ in 0..4 {
                let computed = crt_coefficient(
                    &SecretBn::from_be(&be(&smaller, CRT_BYTES)).unwrap(),
                    &SecretBn::from_be(&be(&larger, CRT_BYTES)).unwrap(),
                    &mut ctx,
                )
                .half()
                .unwrap()
                .unwrap();
                assert_eq!(value_of(&computed), reference);
            }
            let reloaded = recovered(key.modulus.clone(), key.prime.clone());
            assert_eq!(
                reloaded.words, key.words,
                "{bits}-bit reload recomputes the same words"
            );
        }
    }

    #[test]
    fn private_operation_accepts_either_prime_order_on_a_toy_key() {
        let word = |value: u64| {
            let mut words = [0u64; CRT_WORDS];
            words[0] = value;
            words
        };
        let (d_p, d_q, q_inv) = (word(53), word(49), word(38));
        for (p, q) in [(61u8, 53u64), (53, 61)] {
            let q = word(q);
            let key = RsaCrtKey {
                cache: None,
                modulus: &[0x0c, 0xa1],
                exponent: 17,
                prime: &[p],
                q: &q,
                d_p: &d_p,
                d_q: &d_q,
                q_inv: &q_inv,
            };
            assert_eq!(
                rsa_private_key_op(&key, &[0x0a, 0xe6]),
                Some(vec![0x00, 0x41]),
                "stored p {p}"
            );
        }
    }

    #[test]
    fn uneven_prime_keys_every_supported_size() {
        for prime_bits in [512usize, 1024, 1536] {
            let (modulus, prime, q) = uneven_key(prime_bits);
            assert_eq!(q.bit_len(), prime_bits + 1);
            let expected = reference_recover(&modulus, &prime, 0).expect("the reference recovers");
            let key = recovered(modulus.clone(), prime.clone());
            for _ in 0..3 {
                let again = recovered(modulus.clone(), prime.clone());
                assert_eq!(again.words, key.words, "repeated recovery is identical");
            }
            assert_eq!(key.words.map(|words| value_of(&words)), expected);
            assert_eq!(
                normalized_word_count(&key.words[0]),
                prime_bits / 64 + 1,
                "{prime_bits}-bit prime: the quotient takes one more word"
            );
            let message = be(
                &int(0x5a5a_5a5a)
                    .shl(prime_bits)
                    .unwrap()
                    .add_u64(42)
                    .unwrap(),
                modulus.len(),
            );
            let ciphertext = rsa_public_key_op(&modulus, 65537, &message).unwrap();
            assert_eq!(
                rsa_private_key_op(&key.crt(), &ciphertext),
                Some(message),
                "{prime_bits}-bit prime"
            );
        }
        assert_eq!(crt_limbs(384, 192), Some(CRT_WORDS));
        assert_eq!(
            crt_limbs(512, 256),
            None,
            "no capacity beyond the supported sizes"
        );
    }

    #[test]
    fn component_lengths_keep_their_state_format() {
        let short = recovered(
            component_length_key(SHORT_Q_INV).0,
            component_length_key(SHORT_Q_INV).1,
        );
        let full = recovered(
            component_length_key(FULL_Q_INV).0,
            component_length_key(FULL_Q_INV).1,
        );
        assert_eq!(value_of(&short.words[3]), int(3), "q = (2p + 1) / 3");
        assert_eq!(
            short.words.map(|words| normalized_word_count(&words)),
            [8, 8, 8, 1]
        );
        assert_eq!(
            full.words.map(|words| normalized_word_count(&words)),
            [8, 8, 8, 8]
        );
        for key in [&short, &full] {
            let message = be(&int(0x0123_4567_89ab_cdef), 128);
            let ciphertext = rsa_public_key_op(&key.modulus, 65537, &message).unwrap();
            assert_eq!(rsa_private_key_op(&key.crt(), &ciphertext), Some(message));
        }
    }

    #[test]
    fn recovery_matches_the_reference_formulas() {
        for (bits, label) in [(1024u16, b"rec1024".as_slice()), (2048, b"rec2048")] {
            let key = generated(bits, label);
            let q_bytes = be(&value_of(&key.words[0]), key.prime.len());
            for (stored, exponent) in [
                (&key.prime, 0u32),
                (&q_bytes, 0),
                (&key.prime, 65537),
                (&q_bytes, 65539),
                (&key.prime, 7),
                (&key.prime, 9),
                (&key.prime, 65535),
            ] {
                let expected = reference_recover(&key.modulus, stored, exponent);
                let actual =
                    recover_rsa_private_exponent(&key.modulus, stored, exponent).map(|recovered| {
                        [recovered.q, recovered.d_p, recovered.d_q, recovered.q_inv]
                            .map(|words| value_of(&words))
                    });
                assert_eq!(actual, expected, "keyBits {bits} exponent {exponent}");
            }
            let mut other = key.prime.clone();
            let last = other.len() - 1;
            other[last] ^= 0x02;
            assert!(recover_rsa_private_exponent(&key.modulus, &other, 0).is_none());
            assert!(
                recover_rsa_private_exponent(&key.modulus, &vec![0u8; key.prime.len()], 0)
                    .is_none()
            );
            assert!(recover_rsa_private_exponent(&key.modulus, &[], 0).is_none());
            assert!(
                recover_rsa_private_exponent(&key.modulus, &key.modulus, 0).is_none(),
                "a quotient of one has no inverse modulo zero"
            );
        }
    }

    #[test]
    fn small_semiprime_recovery_matches_the_reference_formulas() {
        let primes = [
            3u64, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
        ];
        for &p in &primes {
            for &q in &primes {
                for exponent in [3u32, 5, 7, 9, 17, 65537] {
                    let modulus = be(&int(p * q), 2);
                    let prime = [p as u8];
                    let actual =
                        recover_rsa_private_exponent(&modulus, &prime, exponent).map(|recovered| {
                            [recovered.q, recovered.d_p, recovered.d_q, recovered.q_inv]
                                .map(|words| value_of(&words))
                        });
                    assert_eq!(
                        actual,
                        reference_recover(&modulus, &prime, exponent),
                        "p {p} q {q} e {exponent}"
                    );
                }
            }
        }
    }

    #[test]
    fn candidate_failure_zeroes_like_the_reference() {
        for (p, q, exponent, kept) in [
            (7u64, 11u64, 3u32, false),
            (11, 7, 5, false),
            (5, 7, 7, true),
            (13, 17, 5, true),
            (17, 13, 3, false),
        ] {
            let mut candidate = CrtCandidate::new(8).unwrap();
            candidate.set_p(&p.to_be_bytes()).unwrap();
            candidate.q = SecretBn::from_be(&q.to_be_bytes()).unwrap();
            assert_eq!(candidate.modulus(), Some(vec![(p * q) as u8]));
            assert_eq!(
                candidate.compute(exponent),
                Some(kept),
                "p {p} q {q} e {exponent}"
            );
            let larger = p.max(q);
            let smaller = p.min(q);
            let e = int(u64::from(exponent));
            let larger_ok = e.mod_inverse(&int(larger - 1)).is_some();
            let smaller_ok = e.mod_inverse(&int(smaller - 1)).is_some();
            let stored_p = big(&candidate.p_bytes().unwrap());
            let stored_q = big(&be(&value_of(&candidate.q_words().unwrap()), 8));
            assert_eq!(stored_p, if larger_ok { int(larger) } else { int(0) });
            assert_eq!(stored_q, if smaller_ok { int(smaller) } else { int(0) });
        }
    }

    fn reference_miller_rabin_round(witness: &BigUint, base: &BigUint) -> bool {
        let minus_one = witness.sub_u64(1).unwrap();
        let mut power = 1usize;
        while power < minus_one.bit_len() && !minus_one.test_bit(power) {
            power += 1;
        }
        let odd_part = minus_one.shr(power).unwrap();
        let mut value = base.mod_exp(&odd_part, witness).unwrap();
        if value == int(1) || value == minus_one {
            return true;
        }
        for _ in 1..power {
            value = value.mod_mul(&value, witness).unwrap();
            if value == minus_one {
                return true;
            }
            if value == int(1) {
                return false;
            }
        }
        false
    }

    #[test]
    fn miller_rabin_witness_matches_the_reference_round() {
        let mut generator = rand(b"mr");
        let mersenne = int(1).shl(127).unwrap().sub_u64(1).unwrap();
        let witnesses = [
            int(561),
            int(1105),
            int(2047),
            int(3215031751),
            int(41041),
            int(65537),
            int(0xffff_ffff_ffff_ffc5),
            mersenne.clone(),
            mersenne.mul(&int(3)).unwrap(),
        ];
        for witness in &witnesses {
            let width = witness.byte_len();
            let minus_one = witness.sub_u64(1).unwrap();
            let mut power = 1usize;
            while power < minus_one.bit_len() && !minus_one.test_bit(power) {
                power += 1;
            }
            let odd_part = be(&minus_one.shr(power).unwrap(), width);
            let mut bases = vec![int(2), int(3), minus_one.clone()];
            for _ in 0..12 {
                let draw = big(&generator.random_bytes(width).unwrap());
                bases.push(draw.rem(&minus_one).unwrap().add_u64(1).unwrap());
            }
            for base in &bases {
                assert_eq!(
                    miller_rabin_witness(
                        &be(witness, width),
                        &be(base, width),
                        &odd_part,
                        power as u32
                    ),
                    Some(reference_miller_rabin_round(witness, base)),
                    "witness {witness:?}"
                );
            }
        }
        assert_eq!(
            miller_rabin_witness(&[0x10], &[3], &[1], 4),
            None,
            "an even candidate"
        );
    }

    #[test]
    fn public_operation_matches_the_reference_exponentiation() {
        let mut generator = rand(b"public");
        for modulus_bytes in [16usize, 128, 256, 384] {
            let mut modulus = generator.random_bytes(modulus_bytes).unwrap();
            modulus[0] |= 0x80;
            modulus[modulus_bytes - 1] |= 0x01;
            for exponent in [3u32, 17, 65537, 65539, 0xffff_ffff] {
                let mut value = generator.random_bytes(modulus_bytes).unwrap();
                value[0] &= 0x7f;
                let expected = big(&value)
                    .mod_exp(&int(u64::from(exponent)), &big(&modulus))
                    .unwrap();
                assert_eq!(
                    rsa_public_key_op(&modulus, exponent, &value),
                    Some(be(&expected, modulus_bytes)),
                    "modulus {modulus_bytes} exponent {exponent}"
                );
            }
            assert_eq!(rsa_public_key_op(&modulus, 65537, &modulus), None);
        }
        assert_eq!(rsa_public_key_op(&[0u8; 16], 65537, &[1]), None);
    }

    #[test]
    fn public_operation_keeps_degenerate_public_keys() {
        let modulus = [0x00, 0x00, 0x0c, 0xa1];
        assert_eq!(
            rsa_public_key_op(&modulus, 17, &[0x00, 0x00, 0x00, 0x41]),
            Some(be(&int(65).mod_exp(&int(17), &int(3233)).unwrap(), 4)),
            "a modulus with leading zero bytes keeps its declared width"
        );
        assert_eq!(
            rsa_public_key_op(&modulus, 65537, &[0x41]),
            Some(be(&int(65).mod_exp(&int(65537), &int(3233)).unwrap(), 4)),
            "an exponent above the modulus uses the plain exponentiation, as BnModExp does"
        );
        assert_eq!(rsa_public_key_op(&[0x01], 3, &[0x00]), Some(vec![0x00]));
    }

    #[test]
    fn even_modulus_public_operation_reference_in_place_buffer() {
        let mut modulus = vec![0u8; 256];
        modulus[0] = 0xc0;
        modulus[255] = 0x02;
        let short: Vec<u8> = (1..=20u8).collect();
        let mut expected = vec![0u8; 236];
        expected.extend_from_slice(&short);
        assert_eq!(rsa_public_key_op(&modulus, 65537, &short), Some(expected));
        let full = vec![0x5au8; 256];
        let mut expected = full.clone();
        expected[0] = 0;
        assert_eq!(rsa_public_key_op(&modulus, 65537, &full), Some(expected));
    }

    #[test]
    fn crt_words_round_trip_through_the_backend() {
        for value in [
            int(0),
            int(7),
            int(1).shl(1599).unwrap(),
            int(1).shl(64).unwrap().sub_u64(1).unwrap(),
        ] {
            let words = words_of(&value);
            let secret = secret_words(&words).unwrap();
            assert_eq!(crt_words(&secret), Some(words));
        }
    }

    #[test]
    fn normalized_word_count_upstream_size() {
        let mut words = [0u64; CRT_WORDS];
        assert_eq!(
            normalized_word_count(&words),
            0,
            "zero marshals as an empty prime"
        );
        words[0] = 7;
        assert_eq!(normalized_word_count(&words), 1);
        words[CRT_WORDS - 1] = 1;
        assert_eq!(normalized_word_count(&words), CRT_WORDS);
        words[CRT_WORDS - 1] = 0;
        words[11] = u64::MAX;
        assert_eq!(
            normalized_word_count(&words),
            12,
            "high zero words are normalised away"
        );
    }
}
