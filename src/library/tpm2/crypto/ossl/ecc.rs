// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/crypto/openssl/BnToOsslMath.c
// - libtpms/src/tpm2/crypto/openssl/CryptEccMain.c
// - libtpms/src/tpm2/crypto/openssl/CryptEccSignature.c
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

use std::sync::OnceLock;

use openssl::bn::{BigNum, BigNumContext, BigNumContextRef, BigNumRef};
use openssl::ec::{EcGroup, EcGroupRef, EcKey, EcPoint, EcPointRef};
use openssl::ecdsa::EcdsaSig;
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater};

use super::super::ecc::{
    BN_P256, BN_P638, CurveSpec, NIST_P192, NIST_P224, NIST_P256, NIST_P384, NIST_P521, SM2_P256,
};
use super::fault::{Boundary, checkpoint};
use super::ffi::{cleanse, ecdsa_sign_with_nonce, mod_exp_consttime, sm2_public_key};
use super::rsa::PublicCheck;
use super::secret::{SecretBn, SecretPoint};

pub(in crate::library::tpm2) const MAX_INTEGER_BYTES: usize = 96;
pub(in crate::library::tpm2) const PRIVATE_SCALAR_BYTES: usize = MAX_INTEGER_BYTES;

const CURVES: [&CurveSpec; 8] = [
    &NIST_P192, &NIST_P224, &NIST_P256, &NIST_P384, &NIST_P521, &BN_P256, &BN_P638, &SM2_P256,
];

struct CurveData {
    group: EcGroup,
    field: BigNum,
    order: BigNum,
    order_minus_one: BigNum,
    order_minus_two: BigNum,
    order_be: [u8; MAX_INTEGER_BYTES],
    order_bits: usize,
    field_bytes: usize,
    order_bytes: usize,
}

static CURVE_DATA: [OnceLock<CurveData>; 8] = [
    OnceLock::new(),
    OnceLock::new(),
    OnceLock::new(),
    OnceLock::new(),
    OnceLock::new(),
    OnceLock::new(),
    OnceLock::new(),
    OnceLock::new(),
];

fn named_group(curve_id: u16) -> Option<Nid> {
    match curve_id {
        id if id == NIST_P192.curve_id => Some(Nid::X9_62_PRIME192V1),
        id if id == NIST_P224.curve_id => Some(Nid::SECP224R1),
        id if id == NIST_P256.curve_id => Some(Nid::X9_62_PRIME256V1),
        id if id == NIST_P384.curve_id => Some(Nid::SECP384R1),
        id if id == NIST_P521.curve_id => Some(Nid::SECP521R1),
        _ => None,
    }
}

fn hex(value: &str) -> Option<BigNum> {
    BigNum::from_hex_str(value).ok()
}

fn explicit_group(spec: &CurveSpec, ctx: &mut BigNumContextRef) -> Option<EcGroup> {
    let mut group =
        EcGroup::from_components(hex(spec.prime)?, hex(spec.a)?, hex(spec.b)?, ctx).ok()?;
    let mut generator = EcPoint::new(&group).ok()?;
    let x = hex(spec.generator_x)?;
    let y = hex(spec.generator_y)?;
    generator
        .set_affine_coordinates_gfp(&group, &x, &y, ctx)
        .ok()?;
    group
        .set_generator(generator, hex(spec.order)?, BigNum::from_u32(1).ok()?)
        .ok()?;
    Some(group)
}

fn matches_spec(group: &EcGroup, spec: &CurveSpec, ctx: &mut BigNumContextRef) -> Option<bool> {
    let mut p = BigNum::new().ok()?;
    let mut a = BigNum::new().ok()?;
    let mut b = BigNum::new().ok()?;
    group.components_gfp(&mut p, &mut a, &mut b, ctx).ok()?;
    let mut order = BigNum::new().ok()?;
    group.order(&mut order, ctx).ok()?;
    let mut cofactor = BigNum::new().ok()?;
    group.cofactor(&mut cofactor, ctx).ok()?;
    let generator = group.generator_opt()?;
    let mut x = BigNum::new().ok()?;
    let mut y = BigNum::new().ok()?;
    generator
        .affine_coordinates_gfp(group, &mut x, &mut y, ctx)
        .ok()?;
    Some(
        [
            (&p, spec.prime),
            (&a, spec.a),
            (&b, spec.b),
            (&x, spec.generator_x),
            (&y, spec.generator_y),
            (&order, spec.order),
        ]
        .iter()
        .all(|(value, expected)| {
            hex(expected).is_some_and(|expected| value.ucmp(&expected).is_eq())
        }) && cofactor.num_bits() == 1,
    )
}

fn build(spec: &CurveSpec) -> Option<CurveData> {
    let mut ctx = BigNumContext::new().ok()?;
    let group = match named_group(spec.curve_id) {
        Some(nid) => EcGroup::from_curve_name(nid).ok()?,
        None => explicit_group(spec, &mut ctx)?,
    };
    if !matches_spec(&group, spec, &mut ctx)? {
        return None;
    }
    let field = hex(spec.prime)?;
    let order = hex(spec.order)?;
    let mut order_minus_one = order.to_owned().ok()?;
    order_minus_one.sub_word(1).ok()?;
    let mut order_minus_two = order.to_owned().ok()?;
    order_minus_two.sub_word(2).ok()?;
    let order_bits = usize::try_from(order.num_bits()).ok()?;
    let mut order_be = [0u8; MAX_INTEGER_BYTES];
    order_be.copy_from_slice(&order.to_vec_padded(MAX_INTEGER_BYTES as i32).ok()?);
    Some(CurveData {
        group,
        field,
        order,
        order_minus_one,
        order_minus_two,
        order_be,
        order_bits,
        field_bytes: usize::from(spec.key_size_bits).div_ceil(8),
        order_bytes: order_bits.div_ceil(8),
    })
}

fn padded(bytes: &[u8]) -> Option<[u8; MAX_INTEGER_BYTES]> {
    if bytes.len() > MAX_INTEGER_BYTES {
        return None;
    }
    let mut out = [0u8; MAX_INTEGER_BYTES];
    out[MAX_INTEGER_BYTES - bytes.len()..].copy_from_slice(bytes);
    Some(out)
}

fn ct_less(left: &[u8], right: &[u8]) -> Choice {
    let mut less = Choice::from(0u8);
    let mut decided = Choice::from(0u8);
    for (left, right) in left.iter().zip(right.iter()) {
        let differs = !left.ct_eq(right);
        less.conditional_assign(&right.ct_gt(left), !decided & differs);
        decided |= differs;
    }
    less
}

fn ct_is_zero(bytes: &[u8]) -> Choice {
    bytes.iter().fold(0u8, |acc, &byte| acc | byte).ct_eq(&0)
}

fn reason_is(error: &ErrorStack, library: i32, reason: i32) -> bool {
    error
        .errors()
        .iter()
        .any(|entry| entry.library_code() == library && entry.reason_code() == reason)
}

fn only_reason(error: &ErrorStack, library: i32, reason: i32) -> bool {
    !error.errors().is_empty()
        && error
            .errors()
            .iter()
            .all(|entry| entry.library_code() == library && entry.reason_code() == reason)
}

const ERR_LIB_EC: i32 = 16;
const EC_R_POINT_IS_NOT_ON_CURVE: i32 = 107;
const EC_R_NEED_NEW_SETUP_VALUES: i32 = 157;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) struct EccAffine {
    pub(in crate::library::tpm2) x: Vec<u8>,
    pub(in crate::library::tpm2) y: Vec<u8>,
}

#[derive(Clone, Copy)]
pub(in crate::library::tpm2) struct EccCurve {
    index: usize,
    data: &'static CurveData,
}

pub(in crate::library::tpm2) struct EccScalar {
    curve: EccCurve,
    value: SecretBn,
}

pub(in crate::library::tpm2) struct EccPublicScalar {
    curve: EccCurve,
    value: BigNum,
}

impl core::fmt::Debug for EccScalar {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "EccScalar {{ curve: {:#06x} }}", self.curve.curve_id())
    }
}

impl core::fmt::Debug for EccPublicScalar {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "EccPublicScalar {{ curve: {:#06x}, value: {:02x?} }}",
            self.curve.curve_id(),
            self.value.to_vec()
        )
    }
}

#[cfg(test)]
impl PartialEq for EccScalar {
    fn eq(&self, other: &Self) -> bool {
        self.curve.index == other.curve.index
            && match (self.reveal(), other.reveal()) {
                (Some(left), Some(right)) => left == right,
                _ => false,
            }
    }
}

impl PartialEq for EccPublicScalar {
    fn eq(&self, other: &Self) -> bool {
        self.curve.index == other.curve.index && self.value.ucmp(&other.value).is_eq()
    }
}

#[cfg(test)]
fn validation_result(result: Result<(), ErrorStack>) -> Result<(), ErrorStack> {
    if checkpoint(Boundary::PointValidation).is_some() {
        return result;
    }
    drop(result);
    drop(ErrorStack::get());
    const ERR_LIB_BN: i32 = 3;
    const ERR_R_MALLOC_FAILURE: i32 = 256;
    super::ffi::raise_error(ERR_LIB_BN, ERR_R_MALLOC_FAILURE);
    super::ffi::raise_error(ERR_LIB_EC, EC_R_POINT_IS_NOT_ON_CURVE);
    Err(ErrorStack::get())
}

#[cfg(not(test))]
#[inline(always)]
fn validation_result(result: Result<(), ErrorStack>) -> Result<(), ErrorStack> {
    result
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) enum SharedPointError {
    OffCurve,
    Infinity,
    Backend,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) struct EccBackendError;

pub(in crate::library::tpm2) enum EcdsaAttempt {
    Retry,
    Signed { r: Vec<u8>, s: Vec<u8> },
}

impl EccCurve {
    pub(in crate::library::tpm2) fn lookup(curve_id: u16) -> Option<Self> {
        let index = CURVES.iter().position(|spec| spec.curve_id == curve_id)?;
        let cell = &CURVE_DATA[index];
        let data = match cell.get() {
            Some(data) => data,
            None => {
                let built = build(CURVES[index])?;
                cell.get_or_init(|| built)
            }
        };
        Some(Self { index, data })
    }

    pub(in crate::library::tpm2) fn curve_id(&self) -> u16 {
        CURVES[self.index].curve_id
    }

    pub(in crate::library::tpm2) fn field_bytes(&self) -> usize {
        self.data.field_bytes
    }

    pub(in crate::library::tpm2) fn order_bytes(&self) -> usize {
        self.data.order_bytes
    }

    pub(in crate::library::tpm2) fn order_bits(&self) -> usize {
        self.data.order_bits
    }

    #[cfg(test)]
    pub(in crate::library::tpm2) fn order(&self) -> Vec<u8> {
        self.data.order.to_vec()
    }

    #[cfg(test)]
    pub(in crate::library::tpm2) fn field_prime(&self) -> Vec<u8> {
        self.data.field.to_vec()
    }

    fn group(&self) -> &EcGroupRef {
        &self.data.group
    }

    fn order_ref(&self) -> &BigNumRef {
        &self.data.order
    }

    fn secret(&self, value: SecretBn) -> EccScalar {
        EccScalar {
            curve: *self,
            value,
        }
    }

    fn public(&self, value: BigNum) -> EccPublicScalar {
        EccPublicScalar {
            curve: *self,
            value,
        }
    }

    fn point(&self, x: &[u8], y: &[u8], ctx: &mut BigNumContextRef) -> Option<EcPoint> {
        self.checked_point(x, y, ctx).ok().flatten()
    }

    fn checked_point(
        &self,
        x: &[u8],
        y: &[u8],
        ctx: &mut BigNumContextRef,
    ) -> Result<Option<EcPoint>, EccBackendError> {
        if x.len() > MAX_INTEGER_BYTES || y.len() > MAX_INTEGER_BYTES {
            return Ok(None);
        }
        let backend = |_| EccBackendError;
        let (x, y) = (
            BigNum::from_slice(x).map_err(backend)?,
            BigNum::from_slice(y).map_err(backend)?,
        );
        let mut x_reduced = BigNum::new().map_err(backend)?;
        x_reduced
            .nnmod(&x, &self.data.field, ctx)
            .map_err(backend)?;
        let mut y_reduced = BigNum::new().map_err(backend)?;
        y_reduced
            .nnmod(&y, &self.data.field, ctx)
            .map_err(backend)?;
        let mut point = EcPoint::new(self.group()).map_err(backend)?;
        drop(ErrorStack::get());
        let set = point.set_affine_coordinates_gfp(self.group(), &x_reduced, &y_reduced, ctx);
        match validation_result(set) {
            Ok(()) => Ok(Some(point)),
            Err(error) if only_reason(&error, ERR_LIB_EC, EC_R_POINT_IS_NOT_ON_CURVE) => Ok(None),
            Err(_) => Err(EccBackendError),
        }
    }

    fn affine(&self, point: &EcPointRef, ctx: &mut BigNumContextRef) -> Option<EccAffine> {
        if point.is_infinity(self.group()) {
            return None;
        }
        self.coordinates(point, ctx)
    }

    fn shared_affine(&self, point: &EcPointRef, ctx: &mut BigNumContextRef) -> Option<EccAffine> {
        self.coordinates(point, ctx)
    }

    fn coordinates(&self, point: &EcPointRef, ctx: &mut BigNumContextRef) -> Option<EccAffine> {
        let mut x = SecretBn::new().ok()?;
        checkpoint(Boundary::Coordinates)?;
        let mut y = SecretBn::new().ok()?;
        point
            .affine_coordinates_gfp(self.group(), &mut x, &mut y, ctx)
            .ok()?;
        checkpoint(Boundary::Coordinates)?;
        let mut x = x.to_be(self.data.field_bytes).ok()?;
        match checkpoint(Boundary::Coordinates).and_then(|()| y.to_be(self.data.field_bytes).ok()) {
            Some(y) => Some(EccAffine { x, y }),
            None => {
                cleanse(&mut x);
                None
            }
        }
    }

    #[cfg(test)]
    pub(in crate::library::tpm2) fn on_curve(&self, x: &[u8], y: &[u8]) -> bool {
        self.is_on_curve(x, y).expect("no backend failure")
    }

    pub(in crate::library::tpm2) fn is_on_curve(
        &self,
        x: &[u8],
        y: &[u8],
    ) -> Result<bool, EccBackendError> {
        let mut ctx = BigNumContext::new().map_err(|_| EccBackendError)?;
        Ok(self.checked_point(x, y, &mut ctx)?.is_some())
    }

    pub(in crate::library::tpm2) fn reduce_field(&self, bytes: &[u8]) -> Option<Vec<u8>> {
        if bytes.len() > MAX_INTEGER_BYTES {
            return None;
        }
        let mut ctx = BigNumContext::new().ok()?;
        let value = BigNum::from_slice(bytes).ok()?;
        let mut reduced = BigNum::new().ok()?;
        reduced.nnmod(&value, &self.data.field, &mut ctx).ok()?;
        reduced
            .to_vec_padded(i32::try_from(self.data.field_bytes).ok()?)
            .ok()
    }

    pub(in crate::library::tpm2) fn public_scalar(&self, bytes: &[u8]) -> Option<EccPublicScalar> {
        self.public_scalar_checked(bytes).ok().flatten()
    }

    pub(in crate::library::tpm2) fn public_scalar_checked(
        &self,
        bytes: &[u8],
    ) -> Result<Option<EccPublicScalar>, EccBackendError> {
        if bytes.len() > MAX_INTEGER_BYTES {
            return Ok(None);
        }
        let backend = |_| EccBackendError;
        let mut ctx = BigNumContext::new().map_err(backend)?;
        let value = BigNum::from_slice(bytes).map_err(backend)?;
        let mut reduced = BigNum::new().map_err(backend)?;
        checkpoint(Boundary::PublicReduction).ok_or(EccBackendError)?;
        reduced
            .nnmod(&value, self.order_ref(), &mut ctx)
            .map_err(backend)?;
        Ok(Some(self.public(reduced)))
    }

    pub(in crate::library::tpm2) fn public_scalar_from_u64(
        &self,
        value: u64,
    ) -> Option<EccPublicScalar> {
        self.public_scalar(&value.to_be_bytes())
    }

    pub(in crate::library::tpm2) fn scalar_in_range(&self, bytes: &[u8]) -> bool {
        padded(bytes).is_some_and(|value| {
            bool::from(ct_less(&value, &self.data.order_be) & !ct_is_zero(&value))
        })
    }

    fn reduced(&self, bytes: &[u8], modulus: &BigNumRef) -> Option<SecretBn> {
        if bytes.len() > MAX_INTEGER_BYTES {
            return None;
        }
        let mut ctx = BigNumContext::new().ok()?;
        let raw = SecretBn::from_be(bytes).ok()?;
        let mut value = SecretBn::new().ok()?;
        checkpoint(Boundary::ImportReduction)?;
        value.nnmod(&raw, modulus, &mut ctx).ok()?;
        Some(value)
    }

    pub(in crate::library::tpm2) fn secret_scalar(&self, bytes: &[u8]) -> Option<EccScalar> {
        Some(self.secret(self.reduced(bytes, self.order_ref())?))
    }

    #[cfg(test)]
    pub(in crate::library::tpm2) fn scalar(&self, bytes: &[u8]) -> Option<EccScalar> {
        self.secret_scalar(bytes)
    }

    #[cfg(test)]
    pub(in crate::library::tpm2) fn scalar_from_u64(&self, value: u64) -> Option<EccScalar> {
        self.secret_scalar(&value.to_be_bytes())
    }

    pub(in crate::library::tpm2) fn zero_scalar(&self) -> Option<EccScalar> {
        Some(self.secret(SecretBn::new().ok()?))
    }

    pub(in crate::library::tpm2) fn scalar_from_extra_bits(
        &self,
        bytes: &[u8],
    ) -> Option<EccScalar> {
        let mut value = self.reduced(bytes, &self.data.order_minus_one)?;
        value.add_word(1).ok()?;
        Some(self.secret(value))
    }

    pub(in crate::library::tpm2) fn scalar_below_order(
        &self,
        bytes: &[u8],
    ) -> Result<Option<EccScalar>, EccBackendError> {
        let Some(mut value) = padded(bytes) else {
            return Ok(None);
        };
        let below = bool::from(ct_less(&value, &self.data.order_be));
        cleanse(&mut value);
        if below {
            self.secret_scalar(bytes).map(Some).ok_or(EccBackendError)
        } else {
            Ok(None)
        }
    }

    pub(in crate::library::tpm2) fn private_scalar(
        &self,
        stored: &[u8; PRIVATE_SCALAR_BYTES],
    ) -> Option<EccScalar> {
        self.secret_scalar(stored)
    }

    pub(in crate::library::tpm2) fn private_scalar_in_range(
        &self,
        stored: &[u8; PRIVATE_SCALAR_BYTES],
    ) -> bool {
        bool::from(ct_less(stored, &self.data.order_be) & !ct_is_zero(stored))
    }

    fn product(
        &self,
        base: Option<&EcPointRef>,
        scalar: &EccScalar,
        ctx: &mut BigNumContextRef,
    ) -> Option<SecretPoint> {
        checkpoint(Boundary::PointOperation)?;
        let mut product = SecretPoint::new(self.group()).ok()?;
        match base {
            None => product
                .point_mut()
                .mul_generator2(self.group(), &scalar.value, ctx)
                .ok()?,
            Some(base) => product
                .point_mut()
                .mul2(self.group(), base, &scalar.value, ctx)
                .ok()?,
        }
        Some(product)
    }

    pub(in crate::library::tpm2) fn mul_generator(&self, scalar: &EccScalar) -> Option<EccAffine> {
        self.mul_generator_checked(scalar).ok()
    }

    #[cfg(test)]
    pub(in crate::library::tpm2) fn mul_point(
        &self,
        x: &[u8],
        y: &[u8],
        scalar: &EccScalar,
    ) -> Option<EccAffine> {
        self.mul_point_checked(x, y, scalar).ok()
    }

    fn returned_point(
        &self,
        base: Option<&EcPointRef>,
        scalar: &EccScalar,
        ctx: &mut BigNumContextRef,
    ) -> Result<EccAffine, SharedPointError> {
        let product = self
            .product(base, scalar, ctx)
            .ok_or(SharedPointError::Backend)?;
        if product.point().is_infinity(self.group()) {
            return Err(SharedPointError::Infinity);
        }
        self.affine(product.point(), ctx)
            .ok_or(SharedPointError::Backend)
    }

    pub(in crate::library::tpm2) fn mul_generator_checked(
        &self,
        scalar: &EccScalar,
    ) -> Result<EccAffine, SharedPointError> {
        let mut ctx = BigNumContext::new().map_err(|_| SharedPointError::Backend)?;
        self.returned_point(None, scalar, &mut ctx)
    }

    pub(in crate::library::tpm2) fn mul_point_checked(
        &self,
        x: &[u8],
        y: &[u8],
        scalar: &EccScalar,
    ) -> Result<EccAffine, SharedPointError> {
        let mut ctx = BigNumContext::new().map_err(|_| SharedPointError::Backend)?;
        let base = self
            .checked_point(x, y, &mut ctx)
            .map_err(|_| SharedPointError::Backend)?
            .ok_or(SharedPointError::OffCurve)?;
        self.returned_point(Some(&base), scalar, &mut ctx)
    }

    pub(in crate::library::tpm2) fn mul_point_shared(
        &self,
        x: &[u8],
        y: &[u8],
        scalar: &EccScalar,
    ) -> Result<EccAffine, SharedPointError> {
        let mut ctx = BigNumContext::new().map_err(|_| SharedPointError::Backend)?;
        let base = self
            .checked_point(x, y, &mut ctx)
            .map_err(|_| SharedPointError::Backend)?
            .ok_or(SharedPointError::OffCurve)?;
        let product = self
            .product(Some(&base), scalar, &mut ctx)
            .ok_or(SharedPointError::Backend)?;
        if product.point().is_infinity(self.group()) {
            return Err(SharedPointError::Infinity);
        }
        let shared = self
            .shared_affine(product.point(), &mut ctx)
            .ok_or(SharedPointError::Backend)?;
        #[cfg(test)]
        {
            crate::library::tpm2::memcheck::observe("shared-point", &shared.x);
            crate::library::tpm2::memcheck::observe("shared-point", &shared.y);
        }
        Ok(shared)
    }

    #[cfg(test)]
    pub(in crate::library::tpm2) fn mul_generator_public(
        &self,
        scalar: &EccPublicScalar,
    ) -> Option<EccAffine> {
        let mut ctx = BigNumContext::new().ok()?;
        let mut product = EcPoint::new(self.group()).ok()?;
        product
            .mul_generator2(self.group(), &scalar.value, &mut ctx)
            .ok()?;
        self.affine(&product, &mut ctx)
    }

    pub(in crate::library::tpm2) fn mul_add(
        &self,
        first_scalar: &EccPublicScalar,
        first: Option<(&[u8], &[u8])>,
        second_scalar: &EccPublicScalar,
        second: (&[u8], &[u8]),
    ) -> Option<EccAffine> {
        let mut ctx = BigNumContext::new().ok()?;
        let second = self.point(second.0, second.1, &mut ctx)?;
        let mut sum = EcPoint::new(self.group()).ok()?;
        match first {
            None => sum
                .mul_full(
                    self.group(),
                    &first_scalar.value,
                    &second,
                    &second_scalar.value,
                    &mut ctx,
                )
                .ok()?,
            Some((x, y)) => {
                let first = self.point(x, y, &mut ctx)?;
                let mut left = EcPoint::new(self.group()).ok()?;
                left.mul2(self.group(), &first, &first_scalar.value, &mut ctx)
                    .ok()?;
                let mut right = EcPoint::new(self.group()).ok()?;
                right
                    .mul2(self.group(), &second, &second_scalar.value, &mut ctx)
                    .ok()?;
                sum.add(self.group(), &left, &right, &mut ctx).ok()?;
            }
        }
        self.affine(&sum, &mut ctx)
    }

    pub(in crate::library::tpm2) fn ecdsa_sign(
        &self,
        private: &EccScalar,
        nonce: &EccScalar,
        digest: &[u8],
    ) -> Option<EcdsaAttempt> {
        let mut ctx = BigNumContext::new().ok()?;
        let order = self.order_ref();
        let point = self.product(None, nonce, &mut ctx)?;
        if point.point().is_infinity(self.group()) {
            return Some(EcdsaAttempt::Retry);
        }
        let mut commitment = self.affine(point.point(), &mut ctx)?;
        #[cfg(test)]
        crate::library::tpm2::memcheck::observe("ecdsa-commitment", &commitment.x);
        drop(point);
        let x = SecretBn::from_be(&commitment.x).ok();
        cleanse(&mut commitment.x);
        cleanse(&mut commitment.y);
        let x = x?;
        let mut r = SecretBn::new().ok()?;
        r.nnmod(&x, order, &mut ctx).ok()?;
        if r.num_bits() == 0 {
            return Some(EcdsaAttempt::Retry);
        }
        let mut nonce_inverse = SecretBn::new().ok()?;
        checkpoint(Boundary::Exponentiation)?;
        mod_exp_consttime(
            &mut nonce_inverse,
            &nonce.value,
            &self.data.order_minus_two,
            order,
            &mut ctx,
        )
        .ok()?;
        checkpoint(Boundary::Signature)?;
        drop(ErrorStack::get());
        let s =
            match ecdsa_sign_with_nonce(self.group(), &private.value, digest, &nonce_inverse, &r) {
                Ok((_, s)) => s,
                Err(error) if reason_is(&error, ERR_LIB_EC, EC_R_NEED_NEW_SETUP_VALUES) => {
                    return Some(EcdsaAttempt::Retry);
                }
                Err(_) => return None,
            };
        let length = i32::try_from(self.data.order_bytes).ok()?;
        let (r, s) = (r.to_vec_padded(length).ok()?, s.to_vec_padded(length).ok()?);
        Some(EcdsaAttempt::Signed { r, s })
    }

    pub(in crate::library::tpm2) fn sm2_verify(
        &self,
        public: (&[u8], &[u8]),
        r: &[u8],
        s: &[u8],
        digest: &[u8],
    ) -> PublicCheck {
        const SM3_DIGEST_BYTES: usize = 32;
        if CURVES[self.index].curve_id != SM2_P256.curve_id || digest.len() != SM3_DIGEST_BYTES {
            return PublicCheck::Unsupported;
        }
        let verify = || -> Option<bool> {
            let mut ctx = BigNumContext::new().ok()?;
            self.point(public.0, public.1, &mut ctx)?;
            let mut point = vec![0x04u8];
            for coordinate in [public.0, public.1] {
                let value = BigNum::from_slice(coordinate).ok()?;
                let mut reduced = BigNum::new().ok()?;
                reduced.nnmod(&value, &self.data.field, &mut ctx).ok()?;
                point.extend_from_slice(
                    &reduced
                        .to_vec_padded(i32::try_from(self.data.field_bytes).ok()?)
                        .ok()?,
                );
            }
            let key = sm2_public_key(&point).ok()?;
            let signature = EcdsaSig::from_private_components(
                BigNum::from_slice(r).ok()?,
                BigNum::from_slice(s).ok()?,
            )
            .ok()?
            .to_der()
            .ok()?;
            let mut verifier = openssl::pkey_ctx::PkeyCtx::new(&key).ok()?;
            verifier.verify_init().ok()?;
            verifier.verify(digest, &signature).ok()
        };
        let outcome = verify();
        let _ = ErrorStack::get();
        match outcome {
            Some(true) => PublicCheck::Verified,
            _ => PublicCheck::Rejected,
        }
    }

    pub(in crate::library::tpm2) fn ecdsa_verify(
        &self,
        public: (&[u8], &[u8]),
        r: &[u8],
        s: &[u8],
        digest: &[u8],
    ) -> bool {
        let verify = || -> Option<bool> {
            let mut ctx = BigNumContext::new().ok()?;
            let point = self.point(public.0, public.1, &mut ctx)?;
            let key = EcKey::from_public_key(self.group(), &point).ok()?;
            let signature = EcdsaSig::from_private_components(
                BigNum::from_slice(r).ok()?,
                BigNum::from_slice(s).ok()?,
            )
            .ok()?;
            signature.verify(digest, &key).ok()
        };
        verify().unwrap_or(false)
    }
}

type ModularOperation = fn(
    &mut BigNumRef,
    &BigNumRef,
    &BigNumRef,
    &BigNumRef,
    &mut BigNumContextRef,
) -> Result<(), ErrorStack>;

fn modular_add(
    result: &mut BigNumRef,
    left: &BigNumRef,
    right: &BigNumRef,
    modulus: &BigNumRef,
    ctx: &mut BigNumContextRef,
) -> Result<(), ErrorStack> {
    result.mod_add(left, right, modulus, ctx)
}

fn modular_sub(
    result: &mut BigNumRef,
    left: &BigNumRef,
    right: &BigNumRef,
    modulus: &BigNumRef,
    ctx: &mut BigNumContextRef,
) -> Result<(), ErrorStack> {
    result.mod_sub(left, right, modulus, ctx)
}

fn modular_mul(
    result: &mut BigNumRef,
    left: &BigNumRef,
    right: &BigNumRef,
    modulus: &BigNumRef,
    ctx: &mut BigNumContextRef,
) -> Result<(), ErrorStack> {
    result.mod_mul(left, right, modulus, ctx)
}

impl EccScalar {
    fn order(&self) -> &BigNumRef {
        self.curve.order_ref()
    }

    fn combined(&self, other: &BigNumRef, operation: ModularOperation) -> Option<Self> {
        let mut ctx = BigNumContext::new().ok()?;
        let mut value = SecretBn::new().ok()?;
        checkpoint(Boundary::ScalarArithmetic)?;
        operation(&mut value, &self.value, other, self.order(), &mut ctx).ok()?;
        Some(self.curve.secret(value))
    }

    pub(in crate::library::tpm2) fn add(&self, other: &Self) -> Option<Self> {
        (self.curve.index == other.curve.index).then_some(())?;
        self.combined(&other.value, modular_add)
    }

    #[cfg(test)]
    pub(in crate::library::tpm2) fn neg(&self) -> Option<Self> {
        let zero = SecretBn::new().ok()?;
        self.curve.secret(zero).combined(&self.value, modular_sub)
    }

    pub(in crate::library::tpm2) fn sub(&self, other: &Self) -> Option<Self> {
        (self.curve.index == other.curve.index).then_some(())?;
        self.combined(&other.value, modular_sub)
    }

    pub(in crate::library::tpm2) fn mul(&self, other: &Self) -> Option<Self> {
        (self.curve.index == other.curve.index).then_some(())?;
        self.combined(&other.value, modular_mul)
    }

    pub(in crate::library::tpm2) fn mul_public(&self, factor: &EccPublicScalar) -> Option<Self> {
        (self.curve.index == factor.curve.index).then_some(())?;
        self.combined(&factor.value, modular_mul)
    }

    pub(in crate::library::tpm2) fn add_public(&self, term: &EccPublicScalar) -> Option<Self> {
        (self.curve.index == term.curve.index).then_some(())?;
        self.combined(&term.value, modular_add)
    }

    pub(in crate::library::tpm2) fn invert(&self) -> Option<Self> {
        if self.value.num_bits() == 0 {
            return None;
        }
        let mut ctx = BigNumContext::new().ok()?;
        let mut inverse = SecretBn::new().ok()?;
        checkpoint(Boundary::Exponentiation)?;
        mod_exp_consttime(
            &mut inverse,
            &self.value,
            &self.curve.data.order_minus_two,
            self.order(),
            &mut ctx,
        )
        .ok()?;
        Some(self.curve.secret(inverse))
    }

    #[cfg(test)]
    pub(in crate::library::tpm2) fn is_zero(&self) -> bool {
        self.checked_is_zero().expect("no backend failure")
    }

    pub(in crate::library::tpm2) fn checked_is_zero(&self) -> Result<bool, EccBackendError> {
        Ok(self.value.num_bits() == 0)
    }

    pub(in crate::library::tpm2) fn reveal(&self) -> Option<EccPublicScalar> {
        let mut bytes = self.value.to_be(self.curve.data.order_bytes).ok()?;
        let value = BigNum::from_slice(&bytes).ok();
        cleanse(&mut bytes);
        Some(self.curve.public(value?))
    }

    #[cfg(test)]
    pub(in crate::library::tpm2) fn to_bytes(&self, length: usize) -> Option<Vec<u8>> {
        self.export_bytes(length)
    }

    pub(in crate::library::tpm2) fn export_bytes(&self, length: usize) -> Option<Vec<u8>> {
        if length < self.curve.data.order_bytes {
            return None;
        }
        self.value.to_be(length).ok()
    }
}

impl EccPublicScalar {
    fn combine(&self, other: &Self, operation: ModularOperation) -> Option<Self> {
        (self.curve.index == other.curve.index).then_some(())?;
        let mut ctx = BigNumContext::new().ok()?;
        let mut value = BigNum::new().ok()?;
        operation(
            &mut value,
            &self.value,
            &other.value,
            self.curve.order_ref(),
            &mut ctx,
        )
        .ok()?;
        Some(self.curve.public(value))
    }

    pub(in crate::library::tpm2) fn add(&self, other: &Self) -> Option<Self> {
        self.combine(other, modular_add)
    }

    pub(in crate::library::tpm2) fn sub(&self, other: &Self) -> Option<Self> {
        self.combine(other, modular_sub)
    }

    pub(in crate::library::tpm2) fn neg(&self) -> Option<Self> {
        self.curve.public(BigNum::new().ok()?).sub(self)
    }

    pub(in crate::library::tpm2) fn is_zero(&self) -> bool {
        self.value.num_bits() == 0
    }

    pub(in crate::library::tpm2) fn equals_integer(&self, bytes: &[u8]) -> bool {
        BigNum::from_slice(bytes).is_ok_and(|value| value.ucmp(&self.value).is_eq())
    }

    pub(in crate::library::tpm2) fn to_bytes(&self, length: usize) -> Option<Vec<u8>> {
        if length < self.curve.data.order_bytes {
            return None;
        }
        self.value.to_vec_padded(i32::try_from(length).ok()?).ok()
    }

    pub(in crate::library::tpm2) fn to_minimal_bytes(&self) -> Vec<u8> {
        self.value.to_vec()
    }
}

#[cfg(test)]
pub(in crate::library::tpm2) mod reference {
    use super::super::bignum::BigUint;
    use super::{EccAffine, EccCurve, MAX_INTEGER_BYTES};

    pub(in crate::library::tpm2) struct CurveParameters {
        curve: EccCurve,
        pub(in crate::library::tpm2) order: BigUint,
        pub(in crate::library::tpm2) prime: BigUint,
        pub(in crate::library::tpm2) a: BigUint,
        pub(in crate::library::tpm2) b: BigUint,
    }

    pub(in crate::library::tpm2) fn curve_parameters(curve_id: u16) -> Option<CurveParameters> {
        let curve = EccCurve::lookup(curve_id)?;
        Some(CurveParameters {
            curve,
            order: BigUint::from_be_bytes(&curve.order())?,
            prime: BigUint::from_be_bytes(&curve.field_prime())?,
            a: BigUint::from_hex(super::CURVES[curve.index].a)?,
            b: BigUint::from_hex(super::CURVES[curve.index].b)?,
        })
    }

    fn bytes(value: &BigUint) -> Vec<u8> {
        value
            .to_be_bytes(MAX_INTEGER_BYTES)
            .expect("a reference value fits")
    }

    fn pair(point: EccAffine) -> Option<(BigUint, BigUint)> {
        Some((
            BigUint::from_be_bytes(&point.x)?,
            BigUint::from_be_bytes(&point.y)?,
        ))
    }

    impl CurveParameters {
        pub(in crate::library::tpm2) fn multiply_generator(
            &self,
            scalar: &BigUint,
        ) -> Option<(BigUint, BigUint)> {
            pair(
                self.curve
                    .mul_generator_public(&self.curve.public_scalar(&bytes(scalar))?)?,
            )
        }

        pub(in crate::library::tpm2) fn multiply_sum(
            &self,
            first: &BigUint,
            point: (&BigUint, &BigUint),
            second: &BigUint,
        ) -> Option<(BigUint, BigUint)> {
            let x = point.0.to_be_bytes(self.curve.field_bytes())?;
            let y = point.1.to_be_bytes(self.curve.field_bytes())?;
            pair(self.curve.mul_add(
                &self.curve.public_scalar(&bytes(first))?,
                None,
                &self.curve.public_scalar(&bytes(second))?,
                (&x, &y),
            )?)
        }
    }
}

#[cfg(test)]
#[cfg(test)]
mod tests {
    use super::super::bignum::BigUint;
    use super::*;
    use crate::library::tpm2::crypto::rand_state::SeededRand;

    const ALL_CURVES: [u16; 8] = [
        0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0010, 0x0011, 0x0020,
    ];

    fn curve(curve_id: u16) -> EccCurve {
        EccCurve::lookup(curve_id).expect("a compiled curve")
    }

    fn function_lines(signature: &str) -> core::ops::RangeInclusive<u32> {
        let source = include_str!("ecc.rs");
        let start = source
            .find(signature)
            .unwrap_or_else(|| panic!("{signature} is present"));
        let mut depth = 0usize;
        let mut end = source.len();
        for (index, character) in source[start..].char_indices() {
            match character {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = start + index;
                        break;
                    }
                }
                _ => {}
            }
        }
        let line =
            |offset: usize| u32::try_from(source[..offset].matches('\n').count() + 1).unwrap();
        line(start)..=line(end)
    }

    fn cleared_in(cleared: &[(&'static str, u32)], signature: &str) -> usize {
        let lines = function_lines(signature);
        cleared
            .iter()
            .filter(|(file, line)| file.ends_with("crypto/ossl/ecc.rs") && lines.contains(line))
            .count()
    }

    const COORDINATES: &str = "    fn coordinates(&self, point: &EcPointRef";
    const ECDSA_SIGN: &str = "    pub(in crate::library::tpm2) fn ecdsa_sign(";

    #[test]
    fn intermediate_coordinates_are_cleared_on_success_and_every_failure() {
        use super::super::fault::{arm, disarm};
        use super::super::secret::cleared_secrets;
        for curve_id in ALL_CURVES {
            let curve = curve(curve_id);
            let mut ctx = BigNumContext::new().unwrap();
            let scalar = curve.scalar_from_u64(0x1234_5678).unwrap();
            let product = curve.product(None, &scalar, &mut ctx).unwrap();
            let expected = curve.mul_generator(&scalar).unwrap();
            let context = format!("curve {curve_id:#06x}");
            let (affine, cleared) = cleared_secrets(|| curve.affine(product.point(), &mut ctx));
            assert_eq!(affine.as_ref(), Some(&expected), "{context}");
            assert_eq!(cleared_in(&cleared, COORDINATES), 2, "{context}: success");
            let (shared, cleared) =
                cleared_secrets(|| curve.shared_affine(product.point(), &mut ctx));
            assert_eq!(shared.as_ref(), Some(&expected), "{context}");
            assert_eq!(
                cleared_in(&cleared, COORDINATES),
                2,
                "{context}: shared success"
            );
            for (skipped, created, stage) in [
                (0, 1, "after the first coordinate allocation"),
                (1, 2, "after the coordinate conversion"),
                (2, 2, "after exporting x"),
            ] {
                for shared in [false, true] {
                    arm(Boundary::Coordinates, skipped);
                    let (result, cleared) = cleared_secrets(|| {
                        if shared {
                            curve.shared_affine(product.point(), &mut ctx)
                        } else {
                            curve.affine(product.point(), &mut ctx)
                        }
                    });
                    assert!(disarm(), "{context}: the fault {stage} fired");
                    assert_eq!(result, None, "{context}: {stage}");
                    assert_eq!(
                        cleared_in(&cleared, COORDINATES),
                        created,
                        "{context}: every coordinate temporary {stage} is cleared (shared={shared})"
                    );
                }
            }
        }
    }

    #[test]
    fn ecdsa_failures_after_the_commitment_clear_its_coordinates() {
        use super::super::fault::{arm, disarm};
        use super::super::secret::cleared_secrets;
        for curve_id in ALL_CURVES {
            let curve = curve(curve_id);
            let private = curve.scalar_from_u64(0x77).unwrap();
            let nonce = curve.scalar_from_u64(0x99).unwrap();
            let digest = [0x5au8; 32];
            let context = format!("curve {curve_id:#06x}");
            let (reference, cleared) =
                cleared_secrets(|| curve.ecdsa_sign(&private, &nonce, &digest));
            let Some(EcdsaAttempt::Signed { r, s }) = reference else {
                panic!("{context}: a signature")
            };
            assert_eq!(cleared_in(&cleared, COORDINATES), 2, "{context}: success");
            assert!(
                cleared_in(&cleared, ECDSA_SIGN) >= 3,
                "{context}: commitment x, r and the nonce inverse are cleared"
            );
            for boundary in [Boundary::Exponentiation, Boundary::Signature] {
                arm(boundary, 0);
                let (attempt, cleared) =
                    cleared_secrets(|| curve.ecdsa_sign(&private, &nonce, &digest));
                assert!(disarm(), "{context}: {boundary:?} fired");
                assert!(
                    attempt.is_none(),
                    "{context}: {boundary:?} is a backend failure"
                );
                assert_eq!(
                    cleared_in(&cleared, COORDINATES),
                    2,
                    "{context}: the commitment coordinates are cleared after {boundary:?}"
                );
                assert!(
                    cleared_in(&cleared, ECDSA_SIGN) >= 2,
                    "{context}: commitment x and r are cleared after {boundary:?}"
                );
            }
            let Some(EcdsaAttempt::Signed {
                r: again_r,
                s: again_s,
            }) = curve.ecdsa_sign(&private, &nonce, &digest)
            else {
                panic!("{context}: a signature after the failures")
            };
            assert_eq!(
                (again_r, again_s),
                (r, s),
                "{context}: deterministic output"
            );
        }
    }

    fn rand(label: &[u8]) -> SeededRand {
        SeededRand::instantiate(&[0x3c; 64], b"CTECC", label, &[], 1, false)
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

    fn order(curve: &EccCurve) -> BigUint {
        big(&curve.order())
    }

    fn value(scalar: &EccScalar) -> BigUint {
        big(&scalar.reveal().expect("reveals").to_minimal_bytes())
    }

    fn secret(curve: &EccCurve, value: &BigUint) -> EccScalar {
        curve
            .secret_scalar(&be(value, value.byte_len().max(1)))
            .expect("a reducible scalar")
    }

    fn public(curve: &EccCurve, value: &BigUint) -> EccPublicScalar {
        curve
            .public_scalar(&be(value, value.byte_len().max(1)))
            .expect("a reducible scalar")
    }

    fn classes(curve: &EccCurve, generator: &mut SeededRand) -> Vec<(String, BigUint)> {
        let n = order(curve);
        let width = n.byte_len();
        let mut sparse = vec![0u8; width];
        sparse[width - 1] = 1;
        sparse[1] = 0x80;
        let top_word = (n.bit_len() - 1) / 64 * 64;
        let mut values = vec![
            ("zero".to_string(), int(0)),
            ("one".to_string(), int(1)),
            ("two".to_string(), int(2)),
            ("sparse".to_string(), big(&sparse)),
            ("dense".to_string(), big(&vec![0xff; width])),
            ("n-1".to_string(), n.sub_u64(1).unwrap()),
            ("n-2".to_string(), n.sub_u64(2).unwrap()),
            ("n".to_string(), n.clone()),
            ("n+1".to_string(), n.add_u64(1).unwrap()),
            ("half".to_string(), n.shr(1).unwrap()),
            (
                "top word zero".to_string(),
                int(1).shl(top_word).unwrap().sub_u64(1).unwrap(),
            ),
            ("top word one".to_string(), int(1).shl(top_word).unwrap()),
        ];
        for index in 0..3 {
            values.push((
                format!("random{index}"),
                big(&generator.random_bytes(width + 8).unwrap()),
            ));
        }
        values
    }

    #[test]
    fn every_curve_group_matches_its_tpm_parameters() {
        for (index, spec) in CURVES.iter().enumerate() {
            let curve = curve(spec.curve_id);
            assert_eq!(curve.index, index);
            let mut ctx = BigNumContext::new().unwrap();
            assert_eq!(matches_spec(&curve.data.group, spec, &mut ctx), Some(true));
            assert_eq!(
                curve.data.group.curve_name().is_some(),
                named_group(spec.curve_id).is_some(),
                "curve {:#06x}",
                spec.curve_id
            );
        }
    }

    #[test]
    fn scalar_import_reduces_every_input_length() {
        for curve_id in ALL_CURVES {
            let curve = curve(curve_id);
            let n = order(&curve);
            let mut generator = rand(b"import");
            for length in [
                0usize,
                1,
                20,
                curve.order_bytes(),
                curve.order_bytes() + 8,
                80,
                MAX_INTEGER_BYTES,
            ] {
                let draw = generator.random_bytes(length).unwrap();
                assert_eq!(
                    value(&curve.secret_scalar(&draw).unwrap()),
                    big(&draw).rem(&n).unwrap(),
                    "curve {curve_id:#06x} length {length}"
                );
            }
            for (label, raw) in classes(&curve, &mut generator) {
                let stored: [u8; PRIVATE_SCALAR_BYTES] =
                    be(&raw, PRIVATE_SCALAR_BYTES).try_into().unwrap();
                assert_eq!(
                    value(&curve.private_scalar(&stored).unwrap()),
                    raw.rem(&n).unwrap(),
                    "curve {curve_id:#06x} {label}"
                );
                assert_eq!(
                    curve.private_scalar_in_range(&stored),
                    !raw.is_zero() && raw < n,
                    "curve {curve_id:#06x} {label}"
                );
            }
            assert!(curve.secret_scalar(&[0u8; MAX_INTEGER_BYTES + 1]).is_none());
        }
    }

    #[test]
    fn secret_scalars_keep_the_constant_time_flag() {
        for curve_id in ALL_CURVES {
            let curve = curve(curve_id);
            let raw = int(0x1234_5678);
            let first = secret(&curve, &raw);
            let second = secret(&curve, &raw);
            assert_eq!(value(&first), value(&second));
            let derived = [
                first.add(&second).unwrap(),
                first.sub(&second).unwrap(),
                first.mul(&second).unwrap(),
                first.invert().unwrap(),
                curve.scalar_from_extra_bits(&[0x5a; 40]).unwrap(),
                curve.zero_scalar().unwrap(),
            ];
            for scalar in [&first, &second].into_iter().chain(derived.iter()) {
                assert!(scalar.value.is_const_time(), "curve {curve_id:#06x}");
            }
        }
    }

    #[test]
    fn scalar_arithmetic_matches_the_reference_formulas() {
        for curve_id in ALL_CURVES {
            let curve = curve(curve_id);
            let n = order(&curve);
            let mut generator = rand(b"arithmetic");
            let values = classes(&curve, &mut generator);
            for (left_label, left) in &values {
                let a = secret(&curve, left);
                let left = left.rem(&n).unwrap();
                assert_eq!(value(&a), left, "{left_label}");
                assert_eq!(a.is_zero(), left.is_zero(), "{left_label}");
                assert_eq!(value(&a.neg().unwrap()), int(0).mod_sub(&left, &n).unwrap());
                match left.mod_inverse(&n) {
                    Some(inverse) => assert_eq!(value(&a.invert().unwrap()), inverse),
                    None => assert!(a.invert().is_none(), "{left_label}"),
                }
                assert_eq!(
                    a.export_bytes(curve.order_bytes()).map(|bytes| big(&bytes)),
                    Some(left.clone()),
                    "curve {curve_id:#06x} {left_label}: key export"
                );
                for (right_label, right) in values.iter().step_by(2) {
                    let b = secret(&curve, right);
                    let p = public(&curve, right);
                    let right = right.rem(&n).unwrap();
                    let context = format!("curve {curve_id:#06x} {left_label} {right_label}");
                    assert_eq!(
                        value(&a.add(&b).unwrap()),
                        left.mod_add(&right, &n).unwrap(),
                        "{context}"
                    );
                    assert_eq!(
                        value(&a.sub(&b).unwrap()),
                        left.mod_sub(&right, &n).unwrap(),
                        "{context}"
                    );
                    assert_eq!(
                        value(&b.sub(&a).unwrap()),
                        right.mod_sub(&left, &n).unwrap(),
                        "{context}"
                    );
                    assert_eq!(
                        value(&a.mul(&b).unwrap()),
                        left.mod_mul(&right, &n).unwrap(),
                        "{context}"
                    );
                    assert_eq!(
                        value(&a.mul_public(&p).unwrap()),
                        left.mod_mul(&right, &n).unwrap(),
                        "{context}"
                    );
                    assert_eq!(
                        value(&a.add_public(&p).unwrap()),
                        left.mod_add(&right, &n).unwrap(),
                        "{context}"
                    );
                }
                assert_eq!(value(&a.mul(&a).unwrap()), left.mod_mul(&left, &n).unwrap());
                assert_eq!(value(&a.sub(&a).unwrap()), int(0));
            }
        }
    }

    #[test]
    fn carries_and_borrows_on_both_sides_of_the_order() {
        for curve_id in ALL_CURVES {
            let curve = curve(curve_id);
            let n = order(&curve);
            let small = secret(&curve, &int(3));
            let large = secret(&curve, &n.sub_u64(2).unwrap());
            assert_eq!(value(&small.add(&large).unwrap()), int(1), "wrapping sum");
            assert_eq!(value(&small.add(&small).unwrap()), int(6), "plain sum");
            assert_eq!(
                value(&small.sub(&large).unwrap()),
                int(5),
                "borrowing difference"
            );
            assert_eq!(
                value(&large.sub(&small).unwrap()),
                n.sub_u64(5).unwrap(),
                "plain difference"
            );
            for _ in 0..16 {
                assert_eq!(
                    value(&large.sub(&small).unwrap().add(&small).unwrap()),
                    n.sub_u64(2).unwrap()
                );
            }
        }
    }

    #[test]
    fn extra_bit_reduction_matches_the_reference_for_every_mask() {
        for curve_id in ALL_CURVES {
            let curve = curve(curve_id);
            let minus_one = order(&curve).sub_u64(1).unwrap();
            let mut generator = rand(b"extra");
            for _ in 0..24 {
                let draw = generator.random_bytes(curve.order_bytes() + 8).unwrap();
                let expected = big(&draw).rem(&minus_one).unwrap().add_u64(1).unwrap();
                for _ in 0..4 {
                    assert_eq!(
                        value(&curve.scalar_from_extra_bits(&draw).unwrap()),
                        expected,
                        "curve {curve_id:#06x}"
                    );
                }
            }
            let top = be(&minus_one, curve.order_bytes() + 8);
            assert_eq!(value(&curve.scalar_from_extra_bits(&top).unwrap()), int(1));
            let below = be(&minus_one.sub_u64(1).unwrap(), curve.order_bytes() + 8);
            assert_eq!(
                value(&curve.scalar_from_extra_bits(&below).unwrap()),
                minus_one,
                "the largest result is n - 1"
            );
        }
    }

    #[test]
    fn scalar_decoding_boundaries() {
        for curve_id in ALL_CURVES {
            let curve = curve(curve_id);
            let n = order(&curve);
            let width = curve.order_bytes();
            let encode = |value: &BigUint| be(value, width.max(value.byte_len()));
            let below = n.sub_u64(1).unwrap();
            assert!(curve.scalar_in_range(&encode(&below)));
            assert!(curve.scalar_in_range(&[1]));
            assert!(!curve.scalar_in_range(&[0]));
            assert!(!curve.scalar_in_range(&[]));
            assert!(!curve.scalar_in_range(&encode(&n)));
            assert!(!curve.scalar_in_range(&[0u8; MAX_INTEGER_BYTES + 1]));
            assert_eq!(
                curve
                    .scalar_below_order(&encode(&below))
                    .unwrap()
                    .map(|s| value(&s)),
                Some(below.clone())
            );
            assert!(curve.scalar_below_order(&encode(&n)).unwrap().is_none());
            assert!(curve.scalar_below_order(&[0u8]).unwrap().unwrap().is_zero());
            assert!(curve.zero_scalar().unwrap().is_zero());
            let p = public(&curve, &below);
            assert!(p.equals_integer(&encode(&below)));
            assert_eq!(p.to_bytes(width - 1), None);
            assert_eq!(p.to_bytes(width), Some(encode(&below)));
            assert_eq!(
                curve
                    .public_scalar_from_u64(0x0102)
                    .unwrap()
                    .to_minimal_bytes(),
                [1, 2]
            );
            assert!(
                curve
                    .public_scalar_from_u64(0)
                    .unwrap()
                    .to_minimal_bytes()
                    .is_empty()
            );
        }
    }

    #[test]
    fn point_multiplication_matches_the_public_multiplication() {
        for curve_id in ALL_CURVES {
            let curve = curve(curve_id);
            let n = order(&curve);
            let mut generator = rand(&curve_id.to_be_bytes());
            let base = curve
                .mul_generator_public(
                    &curve
                        .public_scalar(&generator.random_bytes(curve.field_bytes()).unwrap())
                        .unwrap(),
                )
                .unwrap();
            for (label, raw) in classes(&curve, &mut generator) {
                let k = secret(&curve, &raw);
                let reduced = raw.rem(&n).unwrap();
                let expected_generator = curve.mul_generator_public(&public(&curve, &raw));
                let expected_point = curve.mul_add(
                    &curve.public_scalar_from_u64(0).unwrap(),
                    None,
                    &public(&curve, &raw),
                    (&base.x, &base.y),
                );
                assert_eq!(
                    curve.mul_generator(&k),
                    expected_generator,
                    "curve {curve_id:#06x} {label}"
                );
                assert_eq!(
                    curve.mul_point(&base.x, &base.y, &k),
                    expected_point,
                    "curve {curve_id:#06x} {label}"
                );
                assert_eq!(
                    curve.mul_point_shared(&base.x, &base.y, &k).ok(),
                    expected_point,
                    "curve {curve_id:#06x} {label} shared conversion"
                );
                if reduced.is_zero() {
                    assert_eq!(expected_generator, None);
                }
            }
        }
    }

    #[test]
    fn a_shared_point_at_infinity_is_reported() {
        for curve_id in ALL_CURVES {
            let curve = curve(curve_id);
            let base = curve
                .mul_generator_public(&public(&curve, &int(0x1357)))
                .unwrap();
            for zero in [curve.zero_scalar().unwrap(), secret(&curve, &order(&curve))] {
                assert_eq!(
                    curve.mul_point_shared(&base.x, &base.y, &zero),
                    Err(SharedPointError::Infinity),
                    "curve {curve_id:#06x}"
                );
            }
            let n_minus_one = secret(&curve, &order(&curve).sub_u64(1).unwrap());
            let negated = curve
                .mul_point_shared(&base.x, &base.y, &n_minus_one)
                .unwrap();
            assert_eq!(negated.x, base.x, "[n-1]P = -P");
            assert_ne!(negated.y, base.y);
        }
    }

    #[test]
    fn shared_point_backend_failures_fail_the_operation_and_retry_succeeds() {
        use super::super::fault::{Boundary, arm, disarm, fired};
        for curve_id in ALL_CURVES {
            let curve = curve(curve_id);
            let base = curve
                .mul_generator_public(&curve.public_scalar_from_u64(0x55).unwrap())
                .unwrap();
            let scalar = secret(&curve, &int(0x0bad_f00d));
            let expected = curve
                .mul_generator_public(&curve.public_scalar_from_u64(0x55 * 0x0bad_f00d).unwrap())
                .unwrap();
            for boundary in [Boundary::PointValidation, Boundary::PointOperation] {
                let before = fired();
                arm(boundary, 0);
                let failed = curve.mul_point_shared(&base.x, &base.y, &scalar);
                assert_eq!(failed.as_ref().err(), Some(&SharedPointError::Backend));
                let failed = failed.ok();
                disarm();
                assert_eq!(
                    fired() - before,
                    1,
                    "{curve_id:#06x} {boundary:?} is on the path"
                );
                assert_eq!(
                    failed, None,
                    "{curve_id:#06x} {boundary:?} fails the conversion"
                );
                assert_eq!(
                    curve.mul_point_shared(&base.x, &base.y, &scalar),
                    Ok(expected.clone()),
                    "{curve_id:#06x} {boundary:?}: retry"
                );
            }
        }
    }

    #[test]
    fn shared_points_with_a_zero_x_coordinate_keep_their_full_width() {
        for curve_id in [0x0003u16, 0x0005] {
            let curve = curve(curve_id);
            let width = curve.field_bytes();
            let mut ctx = BigNumContext::new().unwrap();
            let mut prime = BigNum::new().unwrap();
            let mut a = BigNum::new().unwrap();
            let mut b = BigNum::new().unwrap();
            curve
                .group()
                .components_gfp(&mut prime, &mut a, &mut b, &mut ctx)
                .unwrap();
            let mut root = BigNum::new().unwrap();
            root.mod_sqrt(&b, &prime, &mut ctx).unwrap();
            let zero_point = EccAffine {
                x: vec![0u8; width],
                y: root.to_vec_padded(width as i32).unwrap(),
            };
            assert!(
                curve.on_curve(&zero_point.x, &zero_point.y),
                "(0, sqrt(b)) is a point"
            );
            let key = int(0x1234_5678_9abc);
            let inverse = key.mod_inverse(&order(&curve)).unwrap();
            let zero = curve.public_scalar_from_u64(0).unwrap();
            let zero_base = curve
                .mul_add(
                    &zero,
                    None,
                    &public(&curve, &inverse),
                    (&zero_point.x, &zero_point.y),
                )
                .unwrap();
            for _ in 0..8 {
                let scalar = secret(&curve, &key);
                assert_eq!(
                    curve.mul_point_shared(&zero_base.x, &zero_base.y, &scalar),
                    Ok(zero_point.clone()),
                    "curve {curve_id:#06x}"
                );
            }
        }
    }

    #[test]
    fn curve_membership_and_out_of_field_aliases() {
        for curve_id in ALL_CURVES {
            let curve = curve(curve_id);
            let width = curve.field_bytes();
            let prime = big(&curve.field_prime());
            let mut generator = rand(b"membership");
            let point = curve
                .mul_generator(
                    &curve
                        .secret_scalar(&generator.random_bytes(width).unwrap())
                        .unwrap(),
                )
                .unwrap();
            assert!(curve.on_curve(&point.x, &point.y));
            let mut broken = point.clone();
            broken.y[width - 1] ^= 0x01;
            assert!(!curve.on_curve(&broken.x, &broken.y));
            let aliased = big(&point.x).add(&prime).unwrap();
            let aliased = be(&aliased, aliased.byte_len());
            assert!(curve.on_curve(&aliased, &point.y), "curve {curve_id:#06x}");
            let three = secret(&curve, &int(3));
            assert_eq!(
                curve.mul_point(&aliased, &point.y, &three),
                curve.mul_point(&point.x, &point.y, &three)
            );
            assert!(!curve.on_curve(&[], &[]));
            assert_eq!(curve.mul_point(&[], &[], &three), None);
            assert_eq!(
                curve.reduce_field(&be(&prime.add_u64(5).unwrap(), width + 1)),
                Some(be(&int(5), width))
            );
        }
    }

    fn reference_digest(curve: &EccCurve, digest: &[u8]) -> BigUint {
        let order_bits = curve.order_bits();
        let truncated = &digest[..digest.len().min(order_bits.div_ceil(8))];
        let value = big(truncated);
        if truncated.len() * 8 > order_bits {
            value.shr(8 - (order_bits & 7)).unwrap()
        } else {
            value
        }
    }

    fn check_ecdsa(curve: &EccCurve, d: &BigUint, k: &BigUint, digest: &[u8]) {
        let n = order(curve);
        let private = secret(curve, d);
        let nonce = secret(curve, k);
        let public_key = curve.mul_generator(&private).unwrap();
        let Some(EcdsaAttempt::Signed { r, s }) = curve.ecdsa_sign(&private, &nonce, digest) else {
            panic!("curve {:#06x}: a signature", curve.curve_id());
        };
        let x = big(&curve.mul_generator(&nonce).unwrap().x)
            .rem(&n)
            .unwrap();
        let z = reference_digest(curve, digest).rem(&n).unwrap();
        let expected = k
            .mod_inverse(&n)
            .unwrap()
            .mod_mul(&z.mod_add(&x.mod_mul(d, &n).unwrap(), &n).unwrap(), &n)
            .unwrap();
        assert_eq!(big(&r), x);
        assert_eq!(big(&s), expected, "curve {:#06x}", curve.curve_id());
        assert_eq!(
            (r.len(), s.len()),
            (curve.order_bytes(), curve.order_bytes())
        );
        assert!(curve.ecdsa_verify((&public_key.x, &public_key.y), &r, &s, digest));
        let Some(EcdsaAttempt::Signed {
            r: again_r,
            s: again_s,
        }) = curve.ecdsa_sign(&private, &nonce, digest)
        else {
            panic!("a second signature");
        };
        assert_eq!(
            (again_r, again_s),
            (r, s),
            "signing is deterministic in the nonce"
        );
    }

    #[test]
    fn ecdsa_matches_the_tpm_formula() {
        for curve_id in ALL_CURVES {
            let curve = curve(curve_id);
            let mut generator = rand(b"ecdsa");
            let n = order(&curve);
            let d = big(&generator.random_bytes(curve.order_bytes() + 8).unwrap())
                .rem(&n)
                .unwrap();
            for digest_len in [20usize, 32, 48, 64] {
                let digest = generator.random_bytes(digest_len).unwrap();
                let k = big(&generator.random_bytes(curve.order_bytes() + 8).unwrap())
                    .rem(&n)
                    .unwrap();
                check_ecdsa(&curve, &d, &k, &digest);
            }
            let zero_nonce = curve.zero_scalar().unwrap();
            let private = secret(&curve, &d);
            assert!(matches!(
                curve.ecdsa_sign(&private, &zero_nonce, &[1; 32]),
                Some(EcdsaAttempt::Retry)
            ));
        }
    }

    #[test]
    fn p521_nonces_on_both_sides_of_two_to_the_512() {
        let curve = curve(0x0005);
        let d = int(0x0123_4567_89ab_cdef)
            .shl(300)
            .unwrap()
            .add_u64(17)
            .unwrap();
        let boundary = int(1).shl(512).unwrap();
        for k in [
            boundary.sub_u64(1).unwrap(),
            boundary.sub_u64(0x1_0000).unwrap(),
            int(0xdead_beef),
            boundary.clone(),
            boundary.add_u64(0x55).unwrap(),
            order(&curve).sub_u64(1).unwrap(),
        ] {
            check_ecdsa(&curve, &d, &k, &[0x42; 64]);
        }
    }

    fn sm2_reference_signature(
        curve: &EccCurve,
        d: &BigUint,
        k: &BigUint,
        digest: &[u8],
    ) -> (Vec<u8>, Vec<u8>, EccAffine) {
        let n = order(curve);
        let public_key = curve.mul_generator(&secret(curve, d)).unwrap();
        let x = big(&curve.mul_generator(&secret(curve, k)).unwrap().x);
        let r = big(digest).add(&x).unwrap().rem(&n).unwrap();
        let s = d
            .add_u64(1)
            .unwrap()
            .mod_inverse(&n)
            .unwrap()
            .mod_mul(&k.mod_sub(&r.mod_mul(d, &n).unwrap(), &n).unwrap(), &n)
            .unwrap();
        let width = curve.order_bytes();
        (be(&r, width), be(&s, width), public_key)
    }

    #[test]
    fn sm2_verification_uses_openssl_on_the_sm2_curve_with_32_byte_digests() {
        let sm2 = curve(0x0020);
        let d = int(0x1234_5678_9abc).shl(100).unwrap().add_u64(3).unwrap();
        let k = int(0x0fed_cba9).shl(180).unwrap().add_u64(11).unwrap();
        let digest = [0x5cu8; 32];
        let (r, s, public_key) = sm2_reference_signature(&sm2, &d, &k, &digest);
        let point = (public_key.x.as_slice(), public_key.y.as_slice());
        assert_eq!(
            sm2.sm2_verify(point, &r, &s, &digest),
            PublicCheck::Verified
        );
        let mut tampered = s.clone();
        tampered[5] ^= 1;
        assert_eq!(
            sm2.sm2_verify(point, &r, &tampered, &digest),
            PublicCheck::Rejected
        );
        assert_eq!(
            sm2.sm2_verify(point, &r, &s, &[0x5c; 33]),
            PublicCheck::Unsupported
        );
        assert_eq!(
            sm2.sm2_verify(point, &r, &s, &[0x5c; 48]),
            PublicCheck::Unsupported
        );
        for curve_id in [0x0001u16, 0x0003, 0x0005, 0x0010, 0x0011] {
            let other = curve(curve_id);
            let (r, s, public_key) = sm2_reference_signature(&other, &d, &k, &digest);
            assert_eq!(
                other.sm2_verify((&public_key.x, &public_key.y), &r, &s, &digest),
                PublicCheck::Unsupported,
                "curve {curve_id:#06x}: OpenSSL's SM2 key manager only accepts the SM2 curve"
            );
        }
    }

    #[test]
    fn public_double_multiplication_handles_identity_equal_and_opposite_points() {
        for curve_id in ALL_CURVES {
            let curve = curve(curve_id);
            let n = order(&curve);
            let p = curve
                .mul_generator_public(&public(&curve, &int(0x1234)))
                .unwrap();
            let doubled = curve
                .mul_generator_public(&public(&curve, &int(0x2468)))
                .unwrap();
            let one = curve.public_scalar_from_u64(1).unwrap();
            let zero = curve.public_scalar_from_u64(0).unwrap();
            let minus_one = public(&curve, &n.sub_u64(1).unwrap());
            let point = (p.x.as_slice(), p.y.as_slice());
            let context = format!("curve {curve_id:#06x}");
            assert_eq!(
                curve.mul_add(&one, Some(point), &one, point),
                Some(doubled),
                "{context}: equal points double"
            );
            assert_eq!(
                curve.mul_add(&one, Some(point), &minus_one, point),
                None,
                "{context}: opposite points sum to infinity"
            );
            assert_eq!(
                curve.mul_add(&zero, None, &one, point),
                Some(p.clone()),
                "{context}: the identity on the generator side"
            );
            assert_eq!(
                curve.mul_add(&one, Some(point), &zero, point),
                Some(p.clone()),
                "{context}: the identity on the second point"
            );
            assert_eq!(
                curve.mul_add(&zero, None, &zero, point),
                None,
                "{context}: both products at infinity"
            );
        }
    }

    #[test]
    fn verification_rejects_tampered_signatures() {
        let curve = curve(0x0003);
        let private = secret(&curve, &int(0x1234));
        let nonce = secret(&curve, &int(0x5678));
        let public_key = curve.mul_generator(&private).unwrap();
        let Some(EcdsaAttempt::Signed { r, mut s }) = curve.ecdsa_sign(&private, &nonce, &[7; 32])
        else {
            panic!("a signature");
        };
        s[0] ^= 1;
        assert!(!curve.ecdsa_verify((&public_key.x, &public_key.y), &r, &s, &[7; 32]));
    }
}
