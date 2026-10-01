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

pub(super) struct SecretBn(BigNum);

impl SecretBn {
    pub(super) fn new() -> Result<Self, ErrorStack> {
        let mut value = BigNum::new()?;
        value.set_const_time();
        Ok(Self(value))
    }

    pub(super) fn from_u32(value: u32) -> Result<Self, ErrorStack> {
        let mut value = BigNum::from_u32(value)?;
        value.set_const_time();
        Ok(Self(value))
    }

    pub(super) fn adopt(mut value: BigNum) -> Self {
        value.set_const_time();
        Self(value)
    }

    pub(super) fn copy_of(value: &BigNumRef) -> Result<Self, ErrorStack> {
        let mut value = value.to_owned()?;
        value.set_const_time();
        Ok(Self(value))
    }

    pub(super) fn from_be(bytes: &[u8]) -> Result<Self, ErrorStack> {
        let width = i32::try_from(bytes.len() * 8).map_err(|_| ErrorStack::get())?;
        let mut marked = Vec::with_capacity(bytes.len() + 1);
        marked.push(1u8);
        marked.extend_from_slice(bytes);
        let parsed = BigNum::from_slice(&marked);
        cleanse(&mut marked);
        let mut value = Self(parsed?);
        value.0.set_const_time();
        value.0.mask_bits(width)?;
        Ok(value)
    }

    pub(super) fn to_be(&self, length: usize) -> Result<Vec<u8>, ErrorStack> {
        let length = i32::try_from(length).map_err(|_| ErrorStack::get())?;
        self.0.to_vec_padded(length)
    }

    pub(super) fn export(&self) -> Result<BigNum, ErrorStack> {
        self.0.to_owned()
    }

    pub(super) fn duplicate(&self) -> Result<Self, ErrorStack> {
        Self::copy_of(&self.0)
    }
}

impl Deref for SecretBn {
    type Target = BigNumRef;

    fn deref(&self) -> &BigNumRef {
        &self.0
    }
}

impl DerefMut for SecretBn {
    fn deref_mut(&mut self) -> &mut BigNumRef {
        &mut self.0
    }
}

impl Drop for SecretBn {
    fn drop(&mut self) {
        self.0.clear();
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
