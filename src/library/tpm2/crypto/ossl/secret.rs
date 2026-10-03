// Part of the Rust port of libtpms.
//
// Project licensing and upstream notices: LICENSE and LICENSES/README.md.
//
// Rust implementation:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use core::ops::{Deref, DerefMut};

use openssl::bn::{BigNum, BigNumRef};
use openssl::ec::{EcGroupRef, EcPoint, EcPointRef};
use openssl::error::ErrorStack;

use super::ffi::{cleanse, clear_free_point};

pub(super) struct SecretBn {
    value: BigNum,
    #[cfg(test)]
    origin: &'static core::panic::Location<'static>,
}

#[cfg(test)]
thread_local! {
    static CLEARING_LEDGER: core::cell::RefCell<Option<Vec<(&'static str, u32)>>> =
        const { core::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(in crate::library::tpm2) fn cleared_secrets<T>(
    run: impl FnOnce() -> T,
) -> (T, Vec<(&'static str, u32)>) {
    let previous = CLEARING_LEDGER.with(|ledger| ledger.borrow_mut().replace(Vec::new()));
    let value = run();
    let cleared = CLEARING_LEDGER.with(|ledger| {
        let mut ledger = ledger.borrow_mut();
        let cleared = ledger.take().unwrap_or_default();
        *ledger = previous;
        cleared
    });
    (value, cleared)
}

impl SecretBn {
    #[track_caller]
    fn wrap(mut value: BigNum) -> Self {
        value.set_const_time();
        Self {
            value,
            #[cfg(test)]
            origin: core::panic::Location::caller(),
        }
    }

    #[track_caller]
    pub(super) fn new() -> Result<Self, ErrorStack> {
        Ok(Self::wrap(BigNum::new()?))
    }

    #[track_caller]
    pub(super) fn from_u32(value: u32) -> Result<Self, ErrorStack> {
        Ok(Self::wrap(BigNum::from_u32(value)?))
    }

    #[cfg(test)]
    #[track_caller]
    pub(super) fn adopt(value: BigNum) -> Self {
        Self::wrap(value)
    }

    #[track_caller]
    pub(super) fn copy_of(value: &BigNumRef) -> Result<Self, ErrorStack> {
        Ok(Self::wrap(value.to_owned()?))
    }

    #[track_caller]
    pub(super) fn from_be(bytes: &[u8]) -> Result<Self, ErrorStack> {
        let width = i32::try_from(bytes.len() * 8).map_err(|_| ErrorStack::get())?;
        let mut marked = Vec::with_capacity(bytes.len() + 1);
        marked.push(1u8);
        marked.extend_from_slice(bytes);
        let parsed = BigNum::from_slice(&marked);
        cleanse(&mut marked);
        let mut value = Self::wrap(parsed?);
        value.value.mask_bits(width)?;
        Ok(value)
    }

    pub(super) fn to_be(&self, length: usize) -> Result<Vec<u8>, ErrorStack> {
        let length = i32::try_from(length).map_err(|_| ErrorStack::get())?;
        self.value.to_vec_padded(length)
    }

    pub(super) fn export(&self) -> Result<BigNum, ErrorStack> {
        self.value.to_owned()
    }

    #[track_caller]
    pub(super) fn duplicate(&self) -> Result<Self, ErrorStack> {
        Self::copy_of(&self.value)
    }
}

impl Deref for SecretBn {
    type Target = BigNumRef;

    fn deref(&self) -> &BigNumRef {
        &self.value
    }
}

impl DerefMut for SecretBn {
    fn deref_mut(&mut self) -> &mut BigNumRef {
        &mut self.value
    }
}

impl Drop for SecretBn {
    fn drop(&mut self) {
        self.value.clear();
        #[cfg(test)]
        CLEARING_LEDGER.with(|ledger| {
            if let Some(ledger) = ledger.borrow_mut().as_mut() {
                ledger.push((self.origin.file(), self.origin.line()));
            }
        });
    }
}

pub(super) struct SecretPoint(Option<EcPoint>);

impl SecretPoint {
    pub(super) fn new(group: &EcGroupRef) -> Result<Self, ErrorStack> {
        Ok(Self(Some(EcPoint::new(group)?)))
    }

    pub(super) fn point(&self) -> &EcPointRef {
        self.0.as_deref().expect("a live point until drop")
    }

    pub(super) fn point_mut(&mut self) -> &mut EcPointRef {
        self.0.as_deref_mut().expect("a live point until drop")
    }
}

impl Drop for SecretPoint {
    fn drop(&mut self) {
        if let Some(point) = self.0.take() {
            clear_free_point(point);
        }
    }
}

pub(in crate::library::tpm2) fn wipe(buffer: &mut [u8]) {
    super::ffi::cleanse(buffer);
}

pub(in crate::library::tpm2) struct SecretBytes(pub(in crate::library::tpm2) Vec<u8>);

impl Drop for SecretBytes {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}
