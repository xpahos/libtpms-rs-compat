// Part of the Rust port of libtpms.
//
// Project licensing and upstream notices: LICENSE and LICENSES/README.md.
//
// Rust implementation:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use core::ffi::{c_int, c_void};

use super::fault::{Boundary, checkpoint};
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::bn::{BigNum, BigNumContextRef, BigNumRef};
use openssl::ec::{EcGroupRef, EcKey, EcPoint};
use openssl::ecdsa::EcdsaSig;
use openssl::error::ErrorStack;
use openssl::pkey::Private;
use openssl_sys::{BIGNUM, BN_CTX, BN_ULONG, EC_KEY, EC_POINT, ECDSA_SIG};

unsafe extern "C" {
    fn BN_mod_exp_mont_consttime(
        result: *mut BIGNUM,
        base: *const BIGNUM,
        exponent: *const BIGNUM,
        modulus: *const BIGNUM,
        ctx: *mut BN_CTX,
        montgomery: *mut c_void,
    ) -> c_int;
    fn ECDSA_do_sign_ex(
        digest: *const u8,
        digest_len: c_int,
        k_inv: *const BIGNUM,
        r: *const BIGNUM,
        key: *mut EC_KEY,
    ) -> *mut ECDSA_SIG;
    fn EC_POINT_clear_free(point: *mut EC_POINT);
    fn BN_priv_rand_range(result: *mut BIGNUM, range: *const BIGNUM) -> c_int;
    fn BN_priv_rand(result: *mut BIGNUM, bits: c_int, top: c_int, bottom: c_int) -> c_int;
    fn BN_check_prime(value: *const BIGNUM, ctx: *mut BN_CTX, callback: *mut c_void) -> c_int;
    fn BN_consttime_swap(condition: BN_ULONG, a: *mut BIGNUM, b: *mut BIGNUM, words: c_int);
    fn OPENSSL_cleanse(buffer: *mut c_void, length: usize);
    fn OSSL_PARAM_construct_utf8_string(
        key: *const core::ffi::c_char,
        buffer: *mut core::ffi::c_char,
        length: usize,
    ) -> openssl_sys::OSSL_PARAM;
    fn RSA_padding_check_PKCS1_OAEP_mgf1(
        to: *mut u8,
        to_len: c_int,
        from: *const u8,
        from_len: c_int,
        modulus_len: c_int,
        label: *const u8,
        label_len: c_int,
        md: *const openssl_sys::EVP_MD,
        mgf1_md: *const openssl_sys::EVP_MD,
    ) -> c_int;
}

#[cfg(test)]
pub(super) fn raise_error(library: c_int, reason: c_int) {
    // SAFETY: ERR_new starts a new entry on this thread's error queue,
    // ERR_set_debug records static NUL-terminated strings, and ERR_set_error
    // with a null format only stores the library and reason codes.
    unsafe {
        openssl_sys::ERR_new();
        openssl_sys::ERR_set_debug(c"fault.rs".as_ptr(), 0, c"injected".as_ptr());
        openssl_sys::ERR_set_error(library, reason, core::ptr::null());
    }
}

pub(in crate::library::tpm2::crypto::ossl) fn cleanse(buffer: &mut [u8]) {
    // SAFETY: the pointer and length describe the caller's exclusively borrowed
    // slice; OPENSSL_cleanse only overwrites those bytes.
    unsafe { OPENSSL_cleanse(buffer.as_mut_ptr().cast(), buffer.len()) }
}

pub(super) fn mod_exp_consttime(
    result: &mut BigNumRef,
    base: &BigNumRef,
    exponent: &BigNumRef,
    modulus: &BigNumRef,
    ctx: &mut BigNumContextRef,
) -> Result<(), ErrorStack> {
    // SAFETY: every pointer comes from a live reference that outlives the call,
    // `result` is the only mutable one and is distinct from the inputs because
    // the borrow checker forbids aliasing a `&mut` with a `&`, and a null
    // Montgomery context asks OpenSSL to build and free its own. The function
    // only reads the inputs and writes `result`; on failure it pushes onto the
    // thread's error queue, which `ErrorStack::get` drains.
    let status = unsafe {
        BN_mod_exp_mont_consttime(
            result.as_ptr(),
            base.as_ptr(),
            exponent.as_ptr(),
            modulus.as_ptr(),
            ctx.as_ptr(),
            core::ptr::null_mut(),
        )
    };
    if status == 1 {
        Ok(())
    } else {
        Err(ErrorStack::get())
    }
}

pub(super) fn ecdsa_sign_with_nonce(
    group: &EcGroupRef,
    private: &BigNumRef,
    digest: &[u8],
    k_inv: &BigNumRef,
    r: &BigNumRef,
) -> Result<(BigNum, BigNum), ErrorStack> {
    let digest_len = c_int::try_from(digest.len()).map_err(|_| ErrorStack::get())?;
    // SAFETY: EC_KEY_new returns either null or a fresh key that nothing else
    // references; `EcKey::from_ptr` takes sole ownership and frees it with
    // EC_KEY_free, which releases the private scalar with BN_clear_free.
    let key = unsafe {
        let raw = openssl_sys::EC_KEY_new();
        if raw.is_null() {
            return Err(ErrorStack::get());
        }
        EcKey::<Private>::from_ptr(raw)
    };
    // SAFETY: `key` is a valid EC_KEY owned above; EC_KEY_set_group and
    // EC_KEY_set_private_key copy the group and the scalar, so the borrowed
    // `group` and `private` only need to live for the duration of the calls.
    let configured = unsafe {
        openssl_sys::EC_KEY_set_group(key.as_ptr(), group.as_ptr()) == 1
            && openssl_sys::EC_KEY_set_private_key(key.as_ptr(), private.as_ptr()) == 1
    };
    if !configured {
        return Err(ErrorStack::get());
    }
    // SAFETY: `digest` is valid for `digest_len` bytes, `k_inv` and `r` are
    // live BIGNUMs that ECDSA_do_sign_ex only reads (it copies `r` into the
    // signature), and `key` holds the group and private scalar set above. The
    // returned ECDSA_SIG is newly allocated and owned by `EcdsaSig`.
    let signature = unsafe {
        let raw = ECDSA_do_sign_ex(
            digest.as_ptr(),
            digest_len,
            k_inv.as_ptr(),
            r.as_ptr(),
            key.as_ptr(),
        );
        if raw.is_null() {
            return Err(ErrorStack::get());
        }
        EcdsaSig::from_ptr(raw)
    };
    Ok((signature.r().to_owned()?, signature.s().to_owned()?))
}

pub(super) fn private_random_below(
    result: &mut BigNumRef,
    range: &BigNumRef,
) -> Result<(), ErrorStack> {
    checkpoint(Boundary::Random).ok_or_else(ErrorStack::get)?;
    // SAFETY: both pointers come from live references; `result` is exclusively
    // borrowed and distinct from `range`. BN_priv_rand_range only writes
    // `result` and draws from OpenSSL's private DRBG, not from the TPM DRBG.
    let status = unsafe { BN_priv_rand_range(result.as_ptr(), range.as_ptr()) };
    if status == 1 {
        Ok(())
    } else {
        Err(ErrorStack::get())
    }
}

pub(super) fn private_random_bits(result: &mut BigNumRef, bits: i32) -> Result<(), ErrorStack> {
    checkpoint(Boundary::Random).ok_or_else(ErrorStack::get)?;
    // SAFETY: `result` is a live, exclusively borrowed BIGNUM; top = -1 and
    // bottom = 0 request a value uniform in [0, 2^bits) from OpenSSL's private
    // DRBG.
    let status = unsafe { BN_priv_rand(result.as_ptr(), bits, -1, 0) };
    if status == 1 {
        Ok(())
    } else {
        Err(ErrorStack::get())
    }
}

pub(super) fn consttime_swap(
    condition: bool,
    a: &mut BigNumRef,
    b: &mut BigNumRef,
    words: i32,
) -> Result<(), ErrorStack> {
    let bits = words.checked_mul(64).ok_or_else(ErrorStack::get)?;
    for value in [&mut *a, &mut *b] {
        value.set_bit(bits - 1)?;
        value.clear_bit(bits - 1)?;
    }
    // SAFETY: `a` and `b` are distinct live BIGNUMs (two exclusive borrows) whose
    // word arrays were just expanded to at least `words` words by setting the
    // top bit of word `words - 1`; BN_consttime_swap reads and writes exactly
    // `words` words of each and swaps `top`, `neg` and the constant-time flags.
    unsafe { BN_consttime_swap(BN_ULONG::from(condition), a.as_ptr(), b.as_ptr(), words) };
    Ok(())
}

pub(super) fn oaep_check(block: &[u8], label: &[u8], md: &openssl::md::MdRef) -> Option<Vec<u8>> {
    let length = c_int::try_from(block.len()).ok()?;
    let label_len = c_int::try_from(label.len()).ok()?;
    let mut message = vec![0u8; block.len()];
    // SAFETY: `message` and `block` are valid for `length` bytes, `label` for
    // `label_len` bytes, and `md` is a live EVP_MD; the checker writes at most
    // `length` bytes into `message` and returns the message length or -1.
    let written = unsafe {
        RSA_padding_check_PKCS1_OAEP_mgf1(
            message.as_mut_ptr(),
            length,
            block.as_ptr(),
            length,
            length,
            label.as_ptr(),
            label_len,
            md.as_ptr(),
            md.as_ptr(),
        )
    };
    finish_check(message, written)
}

pub(super) fn pkcs1_type2_check(block: &[u8]) -> Option<Vec<u8>> {
    let length = c_int::try_from(block.len()).ok()?;
    let mut message = vec![0u8; block.len()];
    // SAFETY: `message` and `block` are valid for `length` bytes; the
    // explicit-rejection checker writes at most `length` bytes into `message`
    // and returns the message length or -1.
    let written = unsafe {
        openssl_sys::RSA_padding_check_PKCS1_type_2(
            message.as_mut_ptr(),
            length,
            block.as_ptr(),
            length,
            length,
        )
    };
    finish_check(message, written)
}

fn finish_check(mut message: Vec<u8>, written: c_int) -> Option<Vec<u8>> {
    let _ = ErrorStack::get();
    match usize::try_from(written) {
        Ok(length) if length <= message.len() => {
            let kept = message[..length].to_vec();
            cleanse(&mut message);
            Some(kept)
        }
        _ => {
            cleanse(&mut message);
            None
        }
    }
}

pub(super) fn sm2_public_key(
    uncompressed_point: &[u8],
) -> Result<openssl::pkey::PKey<openssl::pkey::Public>, ErrorStack> {
    let mut group = *b"SM2\0";
    let mut point = uncompressed_point.to_vec();
    // SAFETY: the parameter keys and the name are NUL-terminated static
    // strings; `group` and `point` outlive the OSSL_PARAM array, which only
    // borrows them; the context is created and freed here; on success
    // EVP_PKEY_fromdata stores a new EVP_PKEY whose ownership moves into the
    // returned PKey.
    unsafe {
        let ctx = openssl_sys::EVP_PKEY_CTX_new_from_name(
            core::ptr::null_mut(),
            c"SM2".as_ptr(),
            core::ptr::null(),
        );
        if ctx.is_null() {
            return Err(ErrorStack::get());
        }
        let mut params = [
            OSSL_PARAM_construct_utf8_string(c"group".as_ptr(), group.as_mut_ptr().cast(), 3),
            openssl_sys::OSSL_PARAM_construct_octet_string(
                c"pub".as_ptr(),
                point.as_mut_ptr().cast(),
                point.len(),
            ),
            openssl_sys::OSSL_PARAM_construct_end(),
        ];
        let mut key = core::ptr::null_mut();
        let created = openssl_sys::EVP_PKEY_fromdata_init(ctx) == 1
            && openssl_sys::EVP_PKEY_fromdata(
                ctx,
                &mut key,
                openssl_sys::EVP_PKEY_PUBLIC_KEY,
                params.as_mut_ptr(),
            ) == 1;
        openssl_sys::EVP_PKEY_CTX_free(ctx);
        if created && !key.is_null() {
            Ok(openssl::pkey::PKey::from_ptr(key))
        } else {
            Err(ErrorStack::get())
        }
    }
}

pub(super) fn clear_free_point(point: EcPoint) {
    let raw = point.as_ptr();
    core::mem::forget(point);
    // SAFETY: `raw` came from an owned EcPoint whose destructor was suppressed
    // by `forget`, so this is the only release of the allocation.
    unsafe { EC_POINT_clear_free(raw) }
}

pub(super) fn check_prime(
    value: &BigNumRef,
    ctx: &mut BigNumContextRef,
) -> Result<bool, ErrorStack> {
    // SAFETY: `value` and `ctx` are live borrows for the duration of the call;
    // BN_check_prime only reads `value`, uses `ctx` for temporaries and accepts
    // a null callback. It draws its witnesses from OpenSSL's private DRBG.
    let status = unsafe { BN_check_prime(value.as_ptr(), ctx.as_ptr(), core::ptr::null_mut()) };
    match status {
        1 => Ok(true),
        0 => Ok(false),
        _ => Err(ErrorStack::get()),
    }
}
