// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/CryptEccData.c
// - libtpms/src/tpm2/crypto/openssl/CryptEccKeyExchange.c
// - libtpms/src/tpm2/crypto/openssl/CryptEccMain.c
//
// Original upstream authors and copyright notices:
// Written by Ken Goldman
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corp. and others, 2018 - 2023
// (c) Copyright IBM Corp. and others, 2016 - 2023
// (c) Copyright IBM Corp. and others, 2016 - 2024
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use crate::library::constants::{
    TPM_RC_CANCELED, TPM_RC_CURVE, TPM_RC_ECC_POINT, TPM_RC_FAILURE, TPM_RC_HASH, TPM_RC_NO_RESULT,
    TPM_RC_SCHEME, TPM_RC_SIZE, TPM_RC_VALUE,
};
use crate::types::TpmResult;

use super::algorithm::{TPM_ALG_ECC, TPM_ALG_ECDH, TPM_ALG_ECMQV, TPM_ALG_KDF2, TPM_ALG_SM2};
use super::commit::CommitState;
use super::crypto::{
    EccAffine, EccBackendError, EccCurve, EccEphemeral, EccKeyError, EccScalar, Hasher,
    PRIVATE_SCALAR_BYTES, SeededRand, SharedPointError, curve_detail, generate_ecc_ephemeral, wipe,
};
use super::marshal::BlobWriter;
use super::persistent::{OwnedObjectBody, OwnedPublicId, OwnedSecret};
use super::public::{MAX_ECC_KEY_BYTES, PublicParms, Scheme};
use super::template::TemplateReader;

pub(super) const MAX_ECC_MESSAGE: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct EccPoint {
    pub(super) x: Vec<u8>,
    pub(super) y: Vec<u8>,
}

impl EccPoint {
    pub(super) fn empty() -> Self {
        Self {
            x: Vec::new(),
            y: Vec::new(),
        }
    }

    fn returned(point: EccAffine) -> Self {
        Self {
            x: returned_coordinate(point.x),
            y: returned_coordinate(point.y),
        }
    }
}

fn returned_coordinate(coordinate: Vec<u8>) -> Vec<u8> {
    let occupied = coordinate.iter().fold(0u8, |acc, &byte| acc | byte);
    if bool::from(occupied.ct_eq(&0)) {
        vec![0u8]
    } else {
        coordinate
    }
}

pub(super) struct SharedCoordinate {
    full: Vec<u8>,
    zero: Choice,
}

impl Drop for SharedCoordinate {
    fn drop(&mut self) {
        wipe(&mut self.full);
    }
}

impl SharedCoordinate {
    pub(super) fn new(full: Vec<u8>) -> Self {
        let occupied = full.iter().fold(0u8, |acc, &byte| acc | byte);
        Self {
            zero: occupied.ct_eq(&0),
            full,
        }
    }

    fn public(bytes: &[u8], width: usize) -> Self {
        let value = significant_bytes(bytes);
        let mut full = vec![0u8; width.saturating_sub(value.len())];
        full.extend_from_slice(value);
        Self::new(full)
    }
}

pub(super) struct SharedPoint {
    x: SharedCoordinate,
    y: SharedCoordinate,
}

impl SharedPoint {
    fn new(point: EccAffine) -> Self {
        Self {
            x: SharedCoordinate::new(point.x),
            y: SharedCoordinate::new(point.y),
        }
    }
}

enum HashPart<'a> {
    Public(&'a [u8]),
    Shared(&'a SharedCoordinate),
}

fn shared_digest(hash_alg: u16, parts: &[HashPart<'_>]) -> Option<Vec<u8>> {
    let shared = parts
        .iter()
        .filter(|part| matches!(part, HashPart::Shared(_)))
        .count();
    let mut selected = vec![0u8; super::template::digest_size(hash_alg)?];
    for variant in 0..1usize << shared {
        let mut hasher = Hasher::new(hash_alg)?;
        let mut chosen = Choice::from(1u8);
        let mut index = 0;
        for part in parts {
            match part {
                HashPart::Public(bytes) => hasher.update(bytes),
                HashPart::Shared(coordinate) => {
                    if (variant >> index) & 1 == 1 {
                        hasher.update(&[0u8]);
                        chosen &= coordinate.zero;
                    } else {
                        hasher.update(&coordinate.full);
                        chosen &= !coordinate.zero;
                    }
                    index += 1;
                }
            }
        }
        for (target, byte) in selected.iter_mut().zip(hasher.finalize()) {
            target.conditional_assign(&byte, chosen);
        }
    }
    Some(selected)
}

pub(super) fn kdfe_shared(
    hash_alg: u16,
    z: &SharedCoordinate,
    label: &[u8],
    party_u_info: &[u8],
    party_v_info: &[u8],
    size_in_bits: u32,
) -> Option<Vec<u8>> {
    let digest_size = super::template::digest_size(hash_alg)?;
    let wanted = usize::try_from(size_in_bits.div_ceil(8)).ok()?;
    let mut out = Vec::with_capacity(wanted.next_multiple_of(digest_size));
    let mut counter: u32 = 0;
    while out.len() < wanted {
        counter = counter.checked_add(1)?;
        out.extend_from_slice(&shared_digest(
            hash_alg,
            &[
                HashPart::Public(&counter.to_be_bytes()),
                HashPart::Shared(z),
                HashPart::Public(label),
                HashPart::Public(party_u_info),
                HashPart::Public(party_v_info),
            ],
        )?);
    }
    out.truncate(wanted);
    if !size_in_bits.is_multiple_of(8) {
        out[0] &= (1u8 << (size_in_bits % 8)) - 1;
    }
    Some(out)
}

fn significant_bytes(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(bytes.len());
    &bytes[start..]
}

pub(super) fn fit_be(bytes: &[u8], length: usize) -> Option<Vec<u8>> {
    let value = significant_bytes(bytes);
    if value.len() > length {
        return None;
    }
    let mut out = vec![0u8; length];
    out[length - value.len()..].copy_from_slice(value);
    Some(out)
}

pub(super) fn parse_ecc_point(reader: &mut TemplateReader<'_>) -> Result<EccPoint, TpmResult> {
    let declared = usize::from(reader.u16()?);
    if declared == 0 {
        return Err(TPM_RC_SIZE);
    }
    let start = reader.consumed();
    let x = reader.tpm2b(MAX_ECC_KEY_BYTES)?.to_vec();
    let y = reader.tpm2b(MAX_ECC_KEY_BYTES)?.to_vec();
    if reader.consumed() - start != declared {
        return Err(TPM_RC_SIZE);
    }
    Ok(EccPoint { x, y })
}

pub(super) fn write_ecc_point(writer: &mut BlobWriter, point: &EccPoint) -> Result<(), TpmResult> {
    let mut inner = BlobWriter::new();
    inner.write_tpm2b(&point.x).map_err(|_| TPM_RC_SIZE)?;
    inner.write_tpm2b(&point.y).map_err(|_| TPM_RC_SIZE)?;
    writer
        .write_tpm2b(inner.as_slice())
        .map_err(|_| TPM_RC_SIZE)?;
    Ok(())
}

pub(super) fn ecc_curve_id(body: &OwnedObjectBody) -> Option<u16> {
    match body.public.parameters {
        PublicParms::Ecc { curve_id, .. } => Some(curve_id),
        _ => None,
    }
}

pub(super) fn ecc_key_scheme(body: &OwnedObjectBody) -> Option<Scheme> {
    match body.public.parameters {
        PublicParms::Ecc { scheme, .. } => Some(scheme),
        _ => None,
    }
}

pub(super) fn ecc_key_kdf(body: &OwnedObjectBody) -> Option<Scheme> {
    match body.public.parameters {
        PublicParms::Ecc { kdf, .. } => Some(kdf),
        _ => None,
    }
}

pub(super) fn ecc_public_point(body: &OwnedObjectBody) -> Option<EccPoint> {
    match &body.public.unique {
        OwnedPublicId::Ecc { x, y } => Some(EccPoint {
            x: x.clone(),
            y: y.clone(),
        }),
        _ => None,
    }
}

pub(super) fn ecc_stored_private(body: &OwnedObjectBody) -> Option<&OwnedSecret> {
    body.sensitive.sensitive.as_ref()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ScalarFailure {
    Unusable,
    Backend,
}

impl ScalarFailure {
    pub(super) fn code(self, unusable: TpmResult) -> TpmResult {
        match self {
            Self::Unusable => unusable,
            Self::Backend => TPM_RC_FAILURE,
        }
    }
}

pub(super) enum PrivateScalar {
    Missing,
    Unusable,
    Backend,
    Ready(EccScalar),
}

impl PrivateScalar {
    pub(super) fn of(curve: &EccCurve, stored: Option<&OwnedSecret>) -> Self {
        let Some(stored) = stored else {
            return Self::Missing;
        };
        let Some(stored) = stored.fixed_width() else {
            return Self::Unusable;
        };
        match curve.private_scalar(stored) {
            Some(scalar) => Self::Ready(scalar),
            None => Self::Backend,
        }
    }

    pub(super) fn or_zero(self, curve: &EccCurve) -> Result<EccScalar, ScalarFailure> {
        match self {
            Self::Missing => curve.zero_scalar().ok_or(ScalarFailure::Backend),
            Self::Unusable => Err(ScalarFailure::Unusable),
            Self::Backend => Err(ScalarFailure::Backend),
            Self::Ready(scalar) => Ok(scalar),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SharedFailure {
    Unusable,
    OffCurve,
    Infinity,
    Backend,
}

fn point_code(error: SharedPointError) -> TpmResult {
    match error {
        SharedPointError::OffCurve => TPM_RC_ECC_POINT,
        SharedPointError::Infinity => TPM_RC_NO_RESULT,
        SharedPointError::Backend => TPM_RC_FAILURE,
    }
}

pub(super) fn point_is_on_curve(curve_id: u16, point: &EccPoint) -> Result<bool, TpmResult> {
    let Some(curve) = EccCurve::lookup(curve_id) else {
        return Ok(false);
    };
    curve
        .is_on_curve(&point.x, &point.y)
        .map_err(|EccBackendError| TPM_RC_FAILURE)
}

pub(super) fn point_multiply(
    curve_id: u16,
    base: Option<&EccPoint>,
    scalar: &[u8],
) -> Result<EccPoint, TpmResult> {
    let curve = EccCurve::lookup(curve_id).ok_or(TPM_RC_VALUE)?;
    if scalar.len() > PRIVATE_SCALAR_BYTES {
        return Err(TPM_RC_NO_RESULT);
    }
    let scalar = curve.secret_scalar(scalar).ok_or(TPM_RC_FAILURE)?;
    point_multiply_by(&curve, base, &scalar)
}

pub(super) fn private_point_multiply(
    curve_id: u16,
    base: Option<&EccPoint>,
    stored: Option<&OwnedSecret>,
) -> Result<EccPoint, TpmResult> {
    let curve = EccCurve::lookup(curve_id).ok_or(TPM_RC_VALUE)?;
    let scalar = PrivateScalar::of(&curve, stored)
        .or_zero(&curve)
        .map_err(|failure| failure.code(TPM_RC_NO_RESULT))?;
    point_multiply_by(&curve, base, &scalar)
}

pub(super) fn point_multiply_by(
    curve: &EccCurve,
    base: Option<&EccPoint>,
    scalar: &EccScalar,
) -> Result<EccPoint, TpmResult> {
    let product = match base {
        Some(base) => {
            if !curve
                .is_on_curve(&base.x, &base.y)
                .map_err(|EccBackendError| TPM_RC_FAILURE)?
            {
                return Err(TPM_RC_ECC_POINT);
            }
            curve.mul_point_checked(&base.x, &base.y, scalar)
        }
        None => curve.mul_generator_checked(scalar),
    };
    product.map(EccPoint::returned).map_err(point_code)
}

fn shared_point_multiply(
    curve: &EccCurve,
    base: &EccPoint,
    scalar: Result<EccScalar, ScalarFailure>,
) -> Result<SharedPoint, SharedFailure> {
    let scalar = scalar.map_err(|failure| match failure {
        ScalarFailure::Unusable => SharedFailure::Unusable,
        ScalarFailure::Backend => SharedFailure::Backend,
    })?;
    curve
        .mul_point_shared(&base.x, &base.y, &scalar)
        .map(SharedPoint::new)
        .map_err(|error| match error {
            SharedPointError::OffCurve => SharedFailure::OffCurve,
            SharedPointError::Infinity => SharedFailure::Infinity,
            SharedPointError::Backend => SharedFailure::Backend,
        })
}

pub(super) fn algorithm_detail(curve_id: u16) -> Option<Vec<u8>> {
    let detail = curve_detail(curve_id)?;
    let mut writer = BlobWriter::new();
    writer.write_u16(detail.curve_id);
    writer.write_u16(detail.key_size_bits);
    writer.write_u16(detail.kdf_scheme);
    if detail.kdf_scheme != super::algorithm::TPM_ALG_NULL {
        writer.write_u16(detail.kdf_hash);
    }
    writer.write_u16(detail.sign_scheme);
    for parameter in [
        &detail.prime,
        &detail.a,
        &detail.b,
        &detail.generator_x,
        &detail.generator_y,
        &detail.order,
        &detail.cofactor,
    ] {
        writer.write_tpm2b(parameter).ok()?;
    }
    Some(writer.into_bytes())
}

pub(super) fn select_kdf_scheme(key_kdf: Scheme, requested: Scheme) -> Option<Scheme> {
    let selected = if requested.scheme == super::algorithm::TPM_ALG_NULL {
        key_kdf
    } else {
        requested
    };
    if selected.scheme == super::algorithm::TPM_ALG_NULL {
        return None;
    }
    if key_kdf.scheme != super::algorithm::TPM_ALG_NULL
        && (key_kdf.scheme != selected.scheme || key_kdf.hash_alg != selected.hash_alg)
    {
        return None;
    }
    Some(selected)
}

pub(super) struct EccCiphertext {
    pub(super) c1: EccPoint,
    pub(super) c2: Vec<u8>,
    pub(super) c3: Vec<u8>,
}

fn kdf2_mask(hash_alg: u16, shared: &SharedPoint, length: usize) -> Option<Vec<u8>> {
    if length == 0 {
        return Some(Vec::new());
    }
    let digest_size = super::template::digest_size(hash_alg)?;
    let mut out = Vec::with_capacity(length.next_multiple_of(digest_size));
    let mut counter: u32 = 1;
    while out.len() < length {
        out.extend_from_slice(&shared_digest(
            hash_alg,
            &[
                HashPart::Shared(&shared.x),
                HashPart::Shared(&shared.y),
                HashPart::Public(&counter.to_be_bytes()),
            ],
        )?);
        counter += 1;
    }
    out.truncate(length);
    Some(out)
}

fn integrity_digest(hash_alg: u16, shared: &SharedPoint, message: &[u8]) -> Option<Vec<u8>> {
    shared_digest(
        hash_alg,
        &[
            HashPart::Shared(&shared.x),
            HashPart::Public(message),
            HashPart::Shared(&shared.y),
        ],
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum EccSelfTest {
    Ecdh,
    Hash(u16),
}

pub(super) type EccSelfTestHook<'a> = &'a mut dyn FnMut(EccSelfTest) -> Result<(), TpmResult>;

pub(super) fn crypt_ecc_encrypt(
    curve_id: u16,
    public: &EccPoint,
    scheme: Scheme,
    plain_text: &[u8],
    rand: &mut SeededRand,
    self_test: EccSelfTestHook<'_>,
) -> Result<EccCiphertext, TpmResult> {
    let curve = EccCurve::lookup(curve_id).ok_or(TPM_RC_CURVE)?;
    if scheme.scheme != TPM_ALG_KDF2 {
        return Err(TPM_RC_SCHEME);
    }
    let ephemeral: EccEphemeral =
        generate_ecc_ephemeral(curve_id, rand).map_err(|error| match error {
            EccKeyError::Curve => TPM_RC_CURVE,
            EccKeyError::NoResult => TPM_RC_NO_RESULT,
            EccKeyError::Failure => TPM_RC_FAILURE,
        })?;
    let c1 = EccPoint {
        x: ephemeral.x,
        y: ephemeral.y,
    };
    self_test(EccSelfTest::Ecdh)?;
    let p2 = shared_point_multiply(&curve, public, Ok(ephemeral.scalar)).map_err(|failure| {
        if failure == SharedFailure::Backend {
            TPM_RC_FAILURE
        } else {
            TPM_RC_NO_RESULT
        }
    })?;
    let hash_alg = scheme.hash_alg.ok_or(TPM_RC_HASH)?;
    self_test(EccSelfTest::Hash(hash_alg))?;

    let c3 = integrity_digest(hash_alg, &p2, plain_text).ok_or(TPM_RC_HASH)?;
    let mut c2 = kdf2_mask(hash_alg, &p2, plain_text.len()).ok_or(TPM_RC_HASH)?;
    for (masked, clear) in c2.iter_mut().zip(plain_text) {
        *masked ^= clear;
    }
    Ok(EccCiphertext { c1, c2, c3 })
}

pub(super) fn crypt_ecc_decrypt(
    curve_id: u16,
    private: Option<&OwnedSecret>,
    scheme: Scheme,
    c1: &EccPoint,
    c2: &[u8],
    c3: &[u8],
    self_test: EccSelfTestHook<'_>,
) -> Result<Vec<u8>, TpmResult> {
    let curve = EccCurve::lookup(curve_id).ok_or(TPM_RC_CURVE)?;
    if scheme.scheme != TPM_ALG_KDF2 {
        return Err(TPM_RC_SCHEME);
    }
    self_test(EccSelfTest::Ecdh)?;
    let scalar = PrivateScalar::of(&curve, private).or_zero(&curve);
    let p2 = match shared_point_multiply(&curve, c1, scalar) {
        Ok(point) => point,
        Err(SharedFailure::Backend) => return Err(TPM_RC_FAILURE),
        Err(SharedFailure::Unusable | SharedFailure::OffCurve | SharedFailure::Infinity) => {
            SharedPoint {
                x: SharedCoordinate::public(&c1.x, curve.field_bytes()),
                y: SharedCoordinate::public(&c1.y, curve.field_bytes()),
            }
        }
    };
    let hash_alg = scheme.hash_alg.ok_or(TPM_RC_HASH)?;
    self_test(EccSelfTest::Hash(hash_alg))?;
    Hasher::new(hash_alg).ok_or(TPM_RC_HASH)?;

    let mut plain_text = kdf2_mask(hash_alg, &p2, c2.len()).ok_or(TPM_RC_HASH)?;
    for (clear, masked) in plain_text.iter_mut().zip(c2) {
        *clear ^= masked;
    }

    let check = integrity_digest(hash_alg, &p2, &plain_text).ok_or(TPM_RC_HASH)?;
    if check.len() != c3.len() || !bool::from(check.ct_eq(c3)) {
        return Err(TPM_RC_VALUE);
    }
    Ok(plain_text)
}

pub(super) fn commit_point_from_s2(
    curve_id: u16,
    name_alg: u16,
    s2: &[u8],
    y2: &[u8],
) -> Result<EccPoint, TpmResult> {
    let curve = EccCurve::lookup(curve_id).ok_or(TPM_RC_FAILURE)?;
    let mut hasher = Hasher::new(name_alg).ok_or(TPM_RC_HASH)?;
    hasher.update(s2);
    let digest = hasher.finalize();
    let x = curve.reduce_field(&digest).ok_or(TPM_RC_NO_RESULT)?;
    Ok(EccPoint { x, y: y2.to_vec() })
}

pub(super) fn commit_compute(
    curve_id: u16,
    p1: Option<&EccPoint>,
    p2: Option<&EccPoint>,
    private: Option<&OwnedSecret>,
    r: &EccScalar,
    canceled: &dyn Fn() -> bool,
) -> Result<(EccPoint, EccPoint, EccPoint), TpmResult> {
    let curve = EccCurve::lookup(curve_id).ok_or(TPM_RC_NO_RESULT)?;
    let mut k = EccPoint::empty();
    let mut l = EccPoint::empty();
    let mut e = EccPoint::empty();
    if let Some(p2) = p2 {
        if !point_is_on_curve(curve_id, p2)? {
            return Err(TPM_RC_VALUE);
        }
        k = private_point_multiply(curve_id, Some(p2), private)?;
        if canceled() {
            return Err(TPM_RC_CANCELED);
        }
        if r.checked_is_zero()
            .map_err(|EccBackendError| TPM_RC_FAILURE)?
        {
            return Err(TPM_RC_VALUE);
        }
        l = point_multiply_by(&curve, Some(p2), r)?;
    }
    if p1.is_some() || p2.is_none() {
        if p2.is_some() && canceled() {
            return Err(TPM_RC_CANCELED);
        }
        e = point_multiply_by(&curve, p1, r)?;
    }
    Ok((k, l, e))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TwoPhaseOutcome {
    Points,
    DivideByZero,
}

pub(super) struct TwoPhaseResult {
    pub(super) z1: EccPoint,
    pub(super) z2: EccPoint,
    pub(super) outcome: TwoPhaseOutcome,
}

pub(super) fn two_phase_key_exchange(
    curve_id: u16,
    scheme: u16,
    static_private: Option<&OwnedSecret>,
    ephemeral_private: &EccScalar,
    qs_b: &EccPoint,
    qe_b: &EccPoint,
) -> Result<TwoPhaseResult, TpmResult> {
    let curve = EccCurve::lookup(curve_id).ok_or(TPM_RC_CURVE)?;
    match scheme {
        TPM_ALG_ECDH => {
            let z1 = private_point_multiply(curve_id, Some(qs_b), static_private)?;
            let z2 = point_multiply_by(&curve, Some(qe_b), ephemeral_private)?;
            Ok(TwoPhaseResult {
                z1,
                z2,
                outcome: TwoPhaseOutcome::Points,
            })
        }
        TPM_ALG_ECMQV => Ok(TwoPhaseResult {
            z1: EccPoint::empty(),
            z2: EccPoint::empty(),
            outcome: TwoPhaseOutcome::DivideByZero,
        }),
        TPM_ALG_SM2 => {
            let z1 = sm2_key_exchange(&curve, static_private, ephemeral_private, qs_b, qe_b)?;
            Ok(TwoPhaseResult {
                z1,
                z2: EccPoint::empty(),
                outcome: TwoPhaseOutcome::Points,
            })
        }
        _ => Err(TPM_RC_SCHEME),
    }
}

const UPSTREAM_RADIX_BITS: usize = 64;

pub(super) fn upstream_mask_kept_bits(mask_bit: usize) -> usize {
    let words = mask_bit.div_ceil(UPSTREAM_RADIX_BITS);
    let remainder = mask_bit % UPSTREAM_RADIX_BITS;
    match (words, remainder) {
        (0, _) => 0,
        (_, 0) => words * UPSTREAM_RADIX_BITS,
        _ => (words - 1) * UPSTREAM_RADIX_BITS + (UPSTREAM_RADIX_BITS - remainder),
    }
}

fn associated_value(coordinate: &[u8], bits: usize) -> Vec<u8> {
    let kept = upstream_mask_kept_bits(bits);
    let width = kept.max(bits + 1).div_ceil(8) + 1;
    let mut value = vec![0u8; width];
    for (offset, &byte) in coordinate.iter().rev().enumerate().take(width) {
        let bit = offset * 8;
        value[width - 1 - offset] = if bit >= kept {
            0
        } else if bit + 8 > kept {
            byte & ((1u8 << (kept - bit)) - 1)
        } else {
            byte
        };
    }
    value[width - 1 - bits / 8] |= 1u8 << (bits % 8);
    value
}

fn sm2_key_exchange(
    curve: &EccCurve,
    static_private: Option<&OwnedSecret>,
    ephemeral_private: &EccScalar,
    qs_b: &EccPoint,
    qe_b: &EccPoint,
) -> Result<EccPoint, TpmResult> {
    let w = (curve.order_bits() - 1) / 2 - 1;
    let qe_a = curve
        .mul_generator_checked(ephemeral_private)
        .map_err(point_code)?;
    let x_a = curve
        .public_scalar(&associated_value(&qe_a.x, w))
        .ok_or(TPM_RC_NO_RESULT)?;
    let ds_a = PrivateScalar::of(curve, static_private)
        .or_zero(curve)
        .map_err(|failure| failure.code(TPM_RC_NO_RESULT))?;
    let ta = ephemeral_private
        .mul_public(&x_a)
        .and_then(|product| product.add(&ds_a))
        .ok_or(TPM_RC_NO_RESULT)?;
    let x_b = curve
        .public_scalar(&associated_value(&qe_b.x, w))
        .ok_or(TPM_RC_NO_RESULT)?;
    let z = curve
        .mul_add(
            &curve.public_scalar_from_u64(1).ok_or(TPM_RC_NO_RESULT)?,
            Some((&qs_b.x, &qs_b.y)),
            &x_b,
            (&qe_b.x, &qe_b.y),
        )
        .ok_or(TPM_RC_NO_RESULT)?;
    let shared = curve
        .mul_point_checked(&z.x, &z.y, &ta)
        .map_err(|error| match error {
            SharedPointError::Backend => TPM_RC_FAILURE,
            SharedPointError::OffCurve | SharedPointError::Infinity => TPM_RC_NO_RESULT,
        })?;
    Ok(EccPoint::returned(shared))
}

pub(super) fn commit_value(
    commit: &CommitState,
    curve_id: u16,
    name: &[u8],
    count: Option<u16>,
) -> Result<Option<EccScalar>, TpmResult> {
    let Some(curve) = EccCurve::lookup(curve_id) else {
        return Ok(None);
    };
    commit
        .generate_r(&curve, name, count)
        .map_err(|EccBackendError| TPM_RC_FAILURE)
}

pub(super) fn is_ecc_object(body: &OwnedObjectBody) -> bool {
    body.public.object_type == TPM_ALG_ECC
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::algorithm::{
        TPM_ALG_KDF1_SP800_56A, TPM_ALG_NULL, TPM_ALG_SHA256, TPM_ALG_SHA384,
    };
    use crate::library::tpm2::crypto::{BigUint, curve_key_size_bits, is_compiled_curve};
    use crate::library::tpm2::test_support::tpm2b;

    const P256: u16 = 0x0003;
    const P384: u16 = 0x0004;
    const P521: u16 = 0x0005;
    const BN256: u16 = 0x0010;
    const BN638: u16 = 0x0011;
    const SM2P256: u16 = 0x0020;
    const ALL_CURVES: [u16; 8] = [0x0001, 0x0002, P256, P384, P521, BN256, BN638, SM2P256];

    fn point_bytes(x: &[u8], y: &[u8]) -> Vec<u8> {
        let mut inner = tpm2b(x);
        inner.extend_from_slice(&tpm2b(y));
        let mut out = (inner.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(&inner);
        out
    }

    fn parse(bytes: &[u8]) -> Result<EccPoint, TpmResult> {
        let mut reader = TemplateReader::new(bytes);
        parse_ecc_point(&mut reader)
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex"))
            .collect()
    }

    fn p256_zero_x_point() -> EccPoint {
        EccPoint {
            x: vec![0u8; 32],
            y: hex("66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4"),
        }
    }

    fn kdf2_sha256() -> Scheme {
        Scheme {
            scheme: TPM_ALG_KDF2,
            hash_alg: Some(TPM_ALG_SHA256),
            count: None,
            kdf: None,
        }
    }

    fn stored(bytes: &[u8]) -> OwnedSecret {
        OwnedSecret::copy_of(bytes)
    }

    fn small_scalar(value: u8, width: usize) -> Vec<u8> {
        let mut private = vec![0u8; width];
        private[width - 1] = value;
        private
    }

    #[test]
    fn zero_shared_coordinate_leaves_decrypt_work_unchanged() {
        use crate::library::tpm2::crypto::work;
        let point = p256_zero_x_point();
        assert_eq!(point_is_on_curve(P256, &point), Ok(true));
        let mut measured = Vec::new();
        for d in [1u8, 2] {
            let (result, counters) = work::measure(|| {
                crypt_ecc_decrypt(
                    P256,
                    Some(&stored(&small_scalar(d, 32))),
                    kdf2_sha256(),
                    &point,
                    &[0x42; 32],
                    &[0; 32],
                    &mut |_| Ok(()),
                )
            });
            assert_eq!(result, Err(TPM_RC_VALUE), "d = {d}");
            measured.push(counters);
        }
        assert_eq!(
            measured[0], measured[1],
            "[1]C1 has a zero x coordinate and [2]C1 does not; the work must not show it"
        );
    }

    fn byte_encoded(coordinate: &[u8]) -> Vec<u8> {
        if coordinate.iter().all(|&byte| byte == 0) {
            vec![0u8]
        } else {
            coordinate.to_vec()
        }
    }

    fn reference_digest(parts: &[&[u8]]) -> Vec<u8> {
        let mut hasher = Hasher::new(TPM_ALG_SHA256).expect("SHA-256");
        for part in parts {
            hasher.update(part);
        }
        hasher.finalize()
    }

    fn reference_kdf2(x: &[u8], y: &[u8], length: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut counter = 1u32;
        while out.len() < length {
            out.extend(reference_digest(&[x, y, &counter.to_be_bytes()]));
            counter += 1;
        }
        out.truncate(length);
        out
    }

    fn shared_coordinates() -> Vec<Vec<u8>> {
        let mut leading = vec![0u8; 32];
        leading[31] = 0x07;
        vec![vec![0u8; 32], leading, vec![0xa5; 32]]
    }

    #[test]
    fn shared_kdfe_byte_encoding_of_zero() {
        use crate::library::tpm2::crypto::kdfe;
        for coordinate in shared_coordinates() {
            let shared = SharedCoordinate::new(coordinate.clone());
            for bits in [256u32, 129, 8, 0] {
                assert_eq!(
                    kdfe_shared(
                        TPM_ALG_SHA256,
                        &shared,
                        b"SECRET\0",
                        b"party u",
                        b"party v",
                        bits
                    ),
                    kdfe(
                        TPM_ALG_SHA256,
                        &byte_encoded(&coordinate),
                        b"SECRET\0",
                        b"party u",
                        b"party v",
                        bits
                    ),
                    "coordinate {coordinate:02x?} bits {bits}"
                );
            }
        }
    }

    #[test]
    fn shared_kdf2_and_integrity_byte_encoding_of_zero() {
        for x in shared_coordinates() {
            for y in shared_coordinates() {
                let shared = SharedPoint {
                    x: SharedCoordinate::new(x.clone()),
                    y: SharedCoordinate::new(y.clone()),
                };
                let (ex, ey) = (byte_encoded(&x), byte_encoded(&y));
                for length in [0usize, 1, 32, 33, 100] {
                    assert_eq!(
                        kdf2_mask(TPM_ALG_SHA256, &shared, length),
                        Some(reference_kdf2(&ex, &ey, length))
                    );
                }
                assert_eq!(
                    integrity_digest(TPM_ALG_SHA256, &shared, b"message"),
                    Some(reference_digest(&[&ex, b"message", &ey]))
                );
            }
        }
    }

    #[test]
    fn zero_shared_coordinate_decrypt_upstream_encoding() {
        let point = p256_zero_x_point();
        let message = b"zero shared coordinate".to_vec();
        for (d, shared) in [
            (1u8, point.clone()),
            (
                2,
                point_multiply(P256, Some(&point), &small_scalar(2, 32)).unwrap(),
            ),
        ] {
            let (x, y) = (byte_encoded(&shared.x), byte_encoded(&shared.y));
            let mut c2 = reference_kdf2(&x, &y, message.len());
            for (masked, clear) in c2.iter_mut().zip(&message) {
                *masked ^= clear;
            }
            let c3 = reference_digest(&[&x, &message, &y]);
            assert_eq!(
                crypt_ecc_decrypt(
                    P256,
                    Some(&stored(&small_scalar(d, 32))),
                    kdf2_sha256(),
                    &point,
                    &c2,
                    &c3,
                    &mut |_| Ok(())
                ),
                Ok(message.clone()),
                "d = {d}"
            );
            let mut tampered = c3.clone();
            tampered[0] ^= 1;
            assert_eq!(
                crypt_ecc_decrypt(
                    P256,
                    Some(&stored(&small_scalar(d, 32))),
                    kdf2_sha256(),
                    &point,
                    &c2,
                    &tampered,
                    &mut |_| Ok(())
                ),
                Err(TPM_RC_VALUE),
                "d = {d}"
            );
        }
    }

    #[test]
    fn zero_shared_coordinate_decrypts_repeatedly_on_p256_and_p521() {
        let p521_zero_x = EccPoint {
            x: vec![0u8; 66],
            y: hex(
                "012df13601594a883ef2d935e44bb90bf4d6619b74e52af7552f97769011c0719eb439cfab2a88d40fe59a2bed1f43557169a2d0a2ccd280c607b92bbf51ffe0b078",
            ),
        };
        let message = b"decrypts through a zero shared x".to_vec();
        for (curve_id, zero_point) in [(P256, p256_zero_x_point()), (P521, p521_zero_x)] {
            let curve = curve(curve_id);
            let width = curve.order_bytes();
            let order = BigUint::from_be_bytes(&curve.order()).unwrap();
            let private = BigUint::from_u64(0x0123_4567_89ab_cdef).unwrap();
            let inverse = private.mod_inverse(&order).unwrap();
            let c1 = point_multiply(
                curve_id,
                Some(&zero_point),
                &inverse.to_be_bytes(width).unwrap(),
            )
            .unwrap();
            assert!(
                c1.x.iter().any(|&byte| byte != 0),
                "C1 itself is not the zero point"
            );
            let control_shared = point_multiply(
                curve_id,
                Some(&c1),
                &BigUint::from_u64(0x0123_4567_89ab_cdee)
                    .unwrap()
                    .to_be_bytes(width)
                    .unwrap(),
            )
            .unwrap();
            for (label, key, shared) in [
                ("zero x", 0x0123_4567_89ab_cdefu64, zero_point.clone()),
                ("control", 0x0123_4567_89ab_cdee, control_shared),
            ] {
                let key = stored(&BigUint::from_u64(key).unwrap().to_be_bytes(width).unwrap());
                let (x, y) = (byte_encoded(&shared.x), byte_encoded(&shared.y));
                let mut c2 = reference_kdf2(&x, &y, message.len());
                for (masked, clear) in c2.iter_mut().zip(&message) {
                    *masked ^= clear;
                }
                let c3 = reference_digest(&[&x, &message, &y]);
                for _ in 0..16 {
                    assert_eq!(
                        crypt_ecc_decrypt(
                            curve_id,
                            Some(&key),
                            kdf2_sha256(),
                            &c1,
                            &c2,
                            &c3,
                            &mut |_| Ok(())
                        ),
                        Ok(message.clone()),
                        "curve {curve_id:#06x} {label}"
                    );
                }
                let mut tampered_c3 = c3.clone();
                tampered_c3[31] ^= 0x80;
                let mut tampered_c2 = c2.clone();
                tampered_c2[0] ^= 1;
                for _ in 0..4 {
                    assert_eq!(
                        crypt_ecc_decrypt(
                            curve_id,
                            Some(&key),
                            kdf2_sha256(),
                            &c1,
                            &c2,
                            &tampered_c3,
                            &mut |_| Ok(())
                        ),
                        Err(TPM_RC_VALUE),
                        "curve {curve_id:#06x} {label}: a wrong C3 is rejected after the shared point"
                    );
                    assert_eq!(
                        crypt_ecc_decrypt(
                            curve_id,
                            Some(&key),
                            kdf2_sha256(),
                            &c1,
                            &tampered_c2,
                            &c3,
                            &mut |_| Ok(())
                        ),
                        Err(TPM_RC_VALUE),
                        "curve {curve_id:#06x} {label}: a changed C2 fails the C3 check"
                    );
                }
            }
        }
    }

    #[test]
    fn shared_point_offsets_never_consume_the_tpm_drbg() {
        let message = message_of(48);
        for curve_id in [P256, P521, 0x0010, 0x0011] {
            if !is_compiled_curve(curve_id) {
                continue;
            }
            let public = multiple_of(curve_id, 0x1234);
            for round in 0..4u8 {
                let label = [b'd', b'r', b'b', b'g', round];
                let mut used = rand(&label);
                let mut reference = rand(&label);
                let ciphertext = crypt_ecc_encrypt(
                    curve_id,
                    &public,
                    kdf2(TPM_ALG_SHA256),
                    &message,
                    &mut used,
                    &mut no_self_test,
                )
                .unwrap();
                let ephemeral = generate_ecc_ephemeral(curve_id, &mut reference).unwrap();
                assert_eq!(
                    (ciphertext.c1.x, ciphertext.c1.y),
                    (ephemeral.x, ephemeral.y)
                );
                assert_eq!(
                    used.random_bytes(64).unwrap(),
                    reference.random_bytes(64).unwrap(),
                    "curve {curve_id:#06x}: the following DRBG output is unchanged"
                );
            }
        }
    }

    fn multiple_of(curve_id: u16, value: u64) -> EccPoint {
        point_multiply(curve_id, None, &scalar(curve_id, value)).expect("a generator multiple")
    }

    #[test]
    fn decryption_backend_failure_is_a_failure_not_the_raw_c1_path() {
        use crate::library::tpm2::crypto::{FaultBoundary, arm_fault, disarm_fault};
        let point = p256_zero_x_point();
        let key = stored(&small_scalar(1, 32));
        arm_fault(FaultBoundary::PointOperation, 0);
        let result = crypt_ecc_decrypt(
            P256,
            Some(&key),
            kdf2_sha256(),
            &point,
            &[1, 2, 3],
            &[0; 32],
            &mut |_| Ok(()),
        );
        disarm_fault();
        assert_eq!(result, Err(TPM_RC_FAILURE));
        let public = multiple_of(P256, 0x77);
        let mut generator = rand(b"encrypt failure");
        arm_fault(FaultBoundary::PointOperation, 0);
        let result = crypt_ecc_encrypt(
            P256,
            &public,
            kdf2(TPM_ALG_SHA256),
            b"m",
            &mut generator,
            &mut no_self_test,
        );
        disarm_fault();
        assert_eq!(result.err(), Some(TPM_RC_FAILURE));
    }

    fn public_c1_ciphertext(c1: &EccPoint, message: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let (x, y) = (byte_encoded(&c1.x), byte_encoded(&c1.y));
        let mut c2 = reference_kdf2(&x, &y, message.len());
        for (masked, clear) in c2.iter_mut().zip(message) {
            *masked ^= clear;
        }
        (c2, reference_digest(&[&x, message, &y]))
    }

    #[test]
    fn public_c1_ciphertexts_are_never_accepted_after_a_backend_failure() {
        use crate::library::tpm2::crypto::{FaultBoundary, arm_fault, disarm_fault, faults_fired};
        let chosen = b"attacker-chosen plaintext".to_vec();
        let message = b"genuine plaintext".to_vec();
        for curve_id in [P256, P521] {
            let width = curve(curve_id).order_bytes();
            let private = 0x0123_4567_89ab_cdefu64;
            let key = stored(
                &BigUint::from_u64(private)
                    .unwrap()
                    .to_be_bytes(width)
                    .unwrap(),
            );
            let c1 = multiple_of(curve_id, 0x99);
            let (forged_c2, forged_c3) = public_c1_ciphertext(&c1, &chosen);
            let shared = point_multiply(
                curve_id,
                Some(&c1),
                &BigUint::from_u64(private)
                    .unwrap()
                    .to_be_bytes(width)
                    .unwrap(),
            )
            .unwrap();
            let (valid_c2, valid_c3) = public_c1_ciphertext(&shared, &message);
            let decrypt = |c2: &[u8], c3: &[u8]| {
                crypt_ecc_decrypt(
                    curve_id,
                    Some(&key),
                    kdf2_sha256(),
                    &c1,
                    c2,
                    c3,
                    &mut |_| Ok(()),
                )
            };
            assert_eq!(
                decrypt(&forged_c2, &forged_c3),
                Err(TPM_RC_VALUE),
                "{curve_id:#06x}: normal rejection"
            );
            assert_eq!(decrypt(&valid_c2, &valid_c3), Ok(message.clone()));
            for (boundary, label) in [
                (
                    FaultBoundary::Random,
                    "RNG failure while importing the private scalar",
                ),
                (
                    FaultBoundary::ImportReduction,
                    "arithmetic failure while importing the private scalar",
                ),
                (
                    FaultBoundary::Remask,
                    "failure while refreshing the scalar masks",
                ),
                (
                    FaultBoundary::PointValidation,
                    "backend failure while validating C1",
                ),
                (
                    FaultBoundary::PointOperation,
                    "backend failure in the shared-point computation",
                ),
                (
                    FaultBoundary::MaskedProduct,
                    "backend failure in the coordinate arithmetic",
                ),
                (
                    FaultBoundary::Unmask,
                    "backend failure while unmasking the shared point",
                ),
            ] {
                for (c2, c3) in [(&forged_c2, &forged_c3), (&valid_c2, &valid_c3)] {
                    let mut hits = 0;
                    loop {
                        let before = faults_fired();
                        arm_fault(boundary, hits);
                        let result = decrypt(c2, c3);
                        disarm_fault();
                        if faults_fired() == before {
                            assert!(hits > 0, "{curve_id:#06x} {label}: the fault is reached");
                            break;
                        }
                        assert_eq!(
                            result,
                            Err(TPM_RC_FAILURE),
                            "{curve_id:#06x} {label}, hit {hits}"
                        );
                        hits += 1;
                    }
                }
                assert_eq!(
                    decrypt(&forged_c2, &forged_c3),
                    Err(TPM_RC_VALUE),
                    "{label}: no lasting state"
                );
                assert_eq!(
                    decrypt(&valid_c2, &valid_c3),
                    Ok(message.clone()),
                    "{label}: recovery"
                );
            }
        }
    }

    #[test]
    fn point_validation_failures_are_classified_by_the_curve_equation() {
        use crate::library::tpm2::crypto::{FaultBoundary, arm_fault, disarm_fault};
        let curve = curve(P256);
        let valid = multiple_of(P256, 0x42);
        let off_curve = EccPoint {
            x: valid.x.clone(),
            y: vec![3; 32],
        };
        arm_fault(FaultBoundary::PointValidation, 0);
        assert_eq!(
            curve.is_on_curve(&valid.x, &valid.y),
            Err(EccBackendError),
            "a valid point the backend failed to set"
        );
        disarm_fault();
        arm_fault(FaultBoundary::PointValidation, 0);
        assert_eq!(
            curve.is_on_curve(&off_curve.x, &off_curve.y),
            Ok(false),
            "an off-curve point stays off-curve"
        );
        disarm_fault();
        assert_eq!(curve.is_on_curve(&valid.x, &valid.y), Ok(true));
        assert_eq!(curve.is_on_curve(&off_curve.x, &off_curve.y), Ok(false));
        let message = b"raw".to_vec();
        let (c2, c3) = public_c1_ciphertext(&off_curve, &message);
        let key = stored(&small_scalar(7, 32));
        arm_fault(FaultBoundary::PointValidation, 0);
        let result = crypt_ecc_decrypt(
            P256,
            Some(&key),
            kdf2_sha256(),
            &off_curve,
            &c2,
            &c3,
            &mut |_| Ok(()),
        );
        disarm_fault();
        assert_eq!(
            result,
            Ok(message),
            "a genuinely off-curve C1 keeps the reference's raw-C1 result"
        );
    }

    #[test]
    fn verified_raw_c1_compatibility_cases_are_kept() {
        let message = b"raw".to_vec();
        let off_curve = EccPoint {
            x: vec![1; 32],
            y: vec![2; 32],
        };
        let key = stored(&small_scalar(7, 32));
        for (label, private, c1) in [
            ("off-curve C1", Some(&key), off_curve.clone()),
            ("empty C1", Some(&key), EccPoint::empty()),
            (
                "missing private scalar: product at infinity",
                None,
                multiple_of(P256, 5),
            ),
        ] {
            let (c2, c3) = public_c1_ciphertext(
                &EccPoint {
                    x: SharedCoordinate::public(&c1.x, 32).full.clone(),
                    y: SharedCoordinate::public(&c1.y, 32).full.clone(),
                },
                &message,
            );
            assert_eq!(
                crypt_ecc_decrypt(P256, private, kdf2_sha256(), &c1, &c2, &c3, &mut |_| Ok(())),
                Ok(message.clone()),
                "{label}: the reference keeps the raw C1 coordinates"
            );
        }
    }

    #[test]
    fn ephemeral_backend_failures_are_failures_without_extra_drbg_draws() {
        use crate::library::tpm2::crypto::{FaultBoundary, arm_fault, disarm_fault, faults_fired};
        let public = multiple_of(P256, 0x31);
        for boundary in [
            FaultBoundary::Random,
            FaultBoundary::Remask,
            FaultBoundary::PointOperation,
        ] {
            let mut used = rand(b"ephemeral failure");
            let mut reference = rand(b"ephemeral failure");
            let before = faults_fired();
            arm_fault(boundary, 0);
            let result = crypt_ecc_encrypt(
                P256,
                &public,
                kdf2(TPM_ALG_SHA256),
                b"m",
                &mut used,
                &mut no_self_test,
            );
            disarm_fault();
            assert_eq!(faults_fired() - before, 1, "{boundary:?} is reached");
            assert_eq!(result.err(), Some(TPM_RC_FAILURE), "{boundary:?}");
            reference
                .random_bytes(curve(P256).order_bytes() + 8)
                .unwrap();
            assert_eq!(
                used.random_bytes(32).unwrap(),
                reference.random_bytes(32).unwrap(),
                "{boundary:?}: one ephemeral draw, as on success"
            );
            assert!(
                crypt_ecc_encrypt(
                    P256,
                    &public,
                    kdf2(TPM_ALG_SHA256),
                    b"m",
                    &mut used,
                    &mut no_self_test
                )
                .is_ok()
            );
        }
    }

    fn on_curve(curve_id: u16, point: &EccPoint) -> bool {
        point_is_on_curve(curve_id, point).expect("no backend failure")
    }

    fn curve(curve_id: u16) -> EccCurve {
        EccCurve::lookup(curve_id).expect("a compiled curve")
    }

    fn generator(curve_id: u16) -> EccPoint {
        let detail = curve_detail(curve_id).expect("a compiled curve");
        EccPoint {
            x: detail.generator_x,
            y: detail.generator_y,
        }
    }

    fn secret(curve_id: u16, value: u64) -> EccScalar {
        curve(curve_id).scalar_from_u64(value).unwrap()
    }

    fn scalar(curve_id: u16, value: u64) -> Vec<u8> {
        let curve = curve(curve_id);
        curve
            .scalar_from_u64(value)
            .unwrap()
            .to_bytes(curve.order_bytes())
            .expect("a scalar encodes")
    }

    fn rand(label: &[u8]) -> SeededRand {
        SeededRand::instantiate(&[0x77; 64], b"ECCTEST", label, &[], 1, false)
            .expect("a non-empty derivation input")
    }

    fn no_self_test(_gate: EccSelfTest) -> Result<(), TpmResult> {
        Ok(())
    }

    fn never_canceled() -> bool {
        false
    }

    fn multiple_of_generator(value: u64) -> EccPoint {
        point_multiply(P256, None, &scalar(P256, value)).expect("a generator multiple")
    }

    fn message_of(length: usize) -> Vec<u8> {
        (0..length)
            .map(|index| ((index * 7 + 5) & 0xff) as u8)
            .collect()
    }

    fn kdf2(hash_alg: u16) -> Scheme {
        Scheme {
            scheme: TPM_ALG_KDF2,
            hash_alg: Some(hash_alg),
            count: None,
            kdf: None,
        }
    }

    fn null_scheme() -> Scheme {
        Scheme {
            scheme: TPM_ALG_NULL,
            hash_alg: None,
            count: None,
            kdf: None,
        }
    }

    #[test]
    fn point_marshal_round_trip() {
        let encoded = point_bytes(&[0x11; 32], &[0x22; 32]);
        let point = parse(&encoded).expect("a well-formed point parses");
        assert_eq!(point.x, [0x11; 32]);
        assert_eq!(point.y, [0x22; 32]);
        let mut writer = BlobWriter::new();
        write_ecc_point(&mut writer, &point).expect("the point marshals");
        assert_eq!(writer.into_bytes(), encoded);
    }

    #[test]
    fn empty_point_two_empty_parameters() {
        let mut writer = BlobWriter::new();
        write_ecc_point(&mut writer, &EccPoint::empty()).expect("an empty point marshals");
        assert_eq!(writer.into_bytes(), [0x00, 0x04, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn zero_sized_point_size_error() {
        assert_eq!(parse(&[0x00, 0x00]), Err(TPM_RC_SIZE));
    }

    #[test]
    fn truncated_point_insufficient_or_size_error() {
        let encoded = point_bytes(&[0x11; 32], &[0x22; 32]);
        for length in 0..encoded.len() {
            let error = parse(&encoded[..length]).expect_err("a truncated point is refused");
            assert!(
                error == crate::library::constants::TPM_RC_INSUFFICIENT || error == TPM_RC_SIZE,
                "length {length} reported {error:#x}"
            );
        }
    }

    #[test]
    fn declared_size_coordinate_mismatch_rejection() {
        let mut encoded = point_bytes(&[0x11; 8], &[0x22; 8]);
        encoded[0..2].copy_from_slice(&23u16.to_be_bytes());
        encoded.push(0x00);
        assert_eq!(parse(&encoded), Err(TPM_RC_SIZE));
        let mut short = point_bytes(&[0x11; 8], &[0x22; 8]);
        short[0..2].copy_from_slice(&19u16.to_be_bytes());
        assert_eq!(parse(&short), Err(TPM_RC_SIZE));
    }

    #[test]
    fn oversized_coordinate_size_error() {
        let encoded = point_bytes(&[0x11; MAX_ECC_KEY_BYTES + 1], &[0x22; 4]);
        assert_eq!(parse(&encoded), Err(TPM_RC_SIZE));
    }

    #[test]
    fn trailing_byte_caller_availability() {
        let mut encoded = point_bytes(&[0x11; 4], &[0x22; 4]);
        encoded.extend_from_slice(&[0xaa, 0xbb]);
        let mut reader = TemplateReader::new(&encoded);
        parse_ecc_point(&mut reader).expect("the point parses");
        assert_eq!(reader.remaining(), [0xaa, 0xbb]);
    }

    #[test]
    fn generator_on_curve_all_curves() {
        for curve_id in ALL_CURVES {
            assert!(is_compiled_curve(curve_id));
            assert_eq!(point_is_on_curve(curve_id, &generator(curve_id)), Ok(true));
        }
    }

    #[test]
    fn off_curve_point_rejection() {
        let mut point = generator(P256);
        point.y[31] ^= 0x01;
        assert_eq!(point_is_on_curve(P256, &point), Ok(false));
        assert_eq!(point_is_on_curve(0x0007, &generator(P256)), Ok(false));
    }

    #[test]
    fn generated_point_fixed_curve_width() {
        for curve_id in ALL_CURVES {
            let width = usize::from(curve_key_size_bits(curve_id).expect("a curve")).div_ceil(8);
            let point = point_multiply(curve_id, None, &scalar(curve_id, 5)).expect("a point");
            assert_eq!(point.x.len(), width, "curve {curve_id:#06x}");
            assert_eq!(point.y.len(), width, "curve {curve_id:#06x}");
        }
    }

    #[test]
    fn off_curve_multiply_point_error() {
        let mut point = generator(P256);
        point.x[0] ^= 0xff;
        assert_eq!(
            point_multiply(P256, Some(&point), &scalar(P256, 3)),
            Err(TPM_RC_ECC_POINT)
        );
    }

    #[test]
    fn zero_scalar_no_result() {
        assert_eq!(
            point_multiply(P256, None, &scalar(P256, 0)),
            Err(TPM_RC_NO_RESULT)
        );
        assert_eq!(
            point_multiply(P256, Some(&generator(P256)), &scalar(P256, 0)),
            Err(TPM_RC_NO_RESULT)
        );
    }

    #[test]
    fn unsupported_curve_no_multiply() {
        assert_eq!(point_multiply(0x0007, None, &[0x01]), Err(TPM_RC_VALUE));
    }

    #[test]
    fn diffie_hellman_bidirectional_agreement() {
        for curve_id in ALL_CURVES {
            let a = scalar(curve_id, 0x1234_5678);
            let b = scalar(curve_id, 0x0fed_cba9);
            let public_a = point_multiply(curve_id, None, &a).expect("a public point");
            let public_b = point_multiply(curve_id, None, &b).expect("a public point");
            let left = point_multiply(curve_id, Some(&public_b), &a).expect("a shared point");
            let right = point_multiply(curve_id, Some(&public_a), &b).expect("a shared point");
            assert_eq!(left, right, "curve {curve_id:#06x}");
        }
    }

    #[test]
    fn curve_detail_vendored_metadata_match() {
        let detail = algorithm_detail(P256).expect("NIST P256 has parameters");
        assert_eq!(&detail[..2], &0x0003u16.to_be_bytes());
        assert_eq!(&detail[2..4], &256u16.to_be_bytes());
        assert_eq!(&detail[4..6], &TPM_ALG_KDF1_SP800_56A.to_be_bytes());
        assert_eq!(&detail[6..8], &TPM_ALG_SHA256.to_be_bytes());
        assert_eq!(&detail[8..10], &TPM_ALG_NULL.to_be_bytes());
        assert_eq!(&detail[10..12], &32u16.to_be_bytes());
        assert_eq!(detail.len(), 12 + 32 + 6 * 2 + 32 * 5 + 1);
        assert_eq!(detail[detail.len() - 3..], [0x00, 0x01, 0x01]);
    }

    #[test]
    fn p384_detail_sha384_kdf() {
        let detail = algorithm_detail(P384).expect("NIST P384 has parameters");
        assert_eq!(&detail[4..6], &TPM_ALG_KDF1_SP800_56A.to_be_bytes());
        assert_eq!(&detail[6..8], &TPM_ALG_SHA384.to_be_bytes());
    }

    #[test]
    fn bn_detail_no_kdf_single_zero_a() {
        let detail = algorithm_detail(BN256).expect("BN P256 has parameters");
        assert_eq!(&detail[4..6], &TPM_ALG_NULL.to_be_bytes());
        assert_eq!(&detail[6..8], &TPM_ALG_NULL.to_be_bytes());
        let prime_length = usize::from(u16::from_be_bytes([detail[8], detail[9]]));
        assert_eq!(prime_length, 32);
        let a_at = 10 + prime_length;
        assert_eq!(&detail[a_at..a_at + 3], [0x00, 0x01, 0x00], "a is one zero");
    }

    #[test]
    fn p521_parameter_prime_width_padding() {
        let detail = algorithm_detail(P521).expect("NIST P521 has parameters");
        let prime_length = usize::from(u16::from_be_bytes([detail[10], detail[11]]));
        assert_eq!(prime_length, 66);
        let mut at = 12 + prime_length;
        for _ in 0..4 {
            let length = usize::from(u16::from_be_bytes([detail[at], detail[at + 1]]));
            assert_eq!(length, 66, "a, b, gX and gY are padded to the prime width");
            at += 2 + length;
        }
    }

    #[test]
    fn curve_detail_compiled_only_presence() {
        for curve_id in ALL_CURVES {
            assert!(algorithm_detail(curve_id).is_some(), "{curve_id:#06x}");
        }
        for curve_id in [0x0000u16, 0x0006, 0x0012, 0x0021, 0xffff] {
            assert!(algorithm_detail(curve_id).is_none(), "{curve_id:#06x}");
        }
    }

    #[test]
    fn null_request_key_scheme_selection() {
        let key = kdf2(TPM_ALG_SHA256);
        assert_eq!(select_kdf_scheme(key, null_scheme()), Some(key));
        assert_eq!(select_kdf_scheme(key, key), Some(key));
        assert_eq!(select_kdf_scheme(null_scheme(), key), Some(key));
        assert_eq!(select_kdf_scheme(null_scheme(), null_scheme()), None);
    }

    #[test]
    fn conflicting_scheme_rejection() {
        let key = kdf2(TPM_ALG_SHA256);
        assert_eq!(select_kdf_scheme(key, kdf2(TPM_ALG_SHA384)), None);
        let other = Scheme {
            scheme: TPM_ALG_KDF1_SP800_56A,
            hash_alg: Some(TPM_ALG_SHA256),
            count: None,
            kdf: None,
        };
        assert_eq!(select_kdf_scheme(key, other), None);
        assert_eq!(select_kdf_scheme(other, other), Some(other));
    }

    #[test]
    fn encryption_round_trip() {
        for length in [0usize, 1, 32, 255, MAX_ECC_MESSAGE] {
            let private = scalar(P256, 0x5eed_1234);
            let public = point_multiply(P256, None, &private).expect("a public point");
            let message: Vec<u8> = (0..length).map(|index| (index * 5 + 1) as u8).collect();
            let cipher = crypt_ecc_encrypt(
                P256,
                &public,
                kdf2(TPM_ALG_SHA256),
                &message,
                &mut rand(b"enc"),
                &mut no_self_test,
            )
            .expect("encryption succeeds");
            assert_eq!(cipher.c2.len(), length);
            assert_eq!(cipher.c3.len(), 32);
            let recovered = crypt_ecc_decrypt(
                P256,
                Some(&stored(&private)),
                kdf2(TPM_ALG_SHA256),
                &cipher.c1,
                &cipher.c2,
                &cipher.c3,
                &mut no_self_test,
            )
            .expect("decryption succeeds");
            assert_eq!(recovered, message, "length {length}");
        }
    }

    #[test]
    fn encryption_round_trip_curve_coverage() {
        for curve_id in ALL_CURVES {
            let private = scalar(curve_id, 0x99);
            let public = point_multiply(curve_id, None, &private).expect("a public point");
            let cipher = crypt_ecc_encrypt(
                curve_id,
                &public,
                kdf2(TPM_ALG_SHA256),
                b"round trip",
                &mut rand(b"curve"),
                &mut no_self_test,
            )
            .expect("encryption succeeds");
            assert_eq!(
                crypt_ecc_decrypt(
                    curve_id,
                    Some(&stored(&private)),
                    kdf2(TPM_ALG_SHA256),
                    &cipher.c1,
                    &cipher.c2,
                    &cipher.c3,
                    &mut no_self_test
                )
                .expect("decryption succeeds"),
                b"round trip",
                "curve {curve_id:#06x}"
            );
        }
    }

    #[test]
    fn modified_ciphertext_no_plaintext() {
        let private = scalar(P256, 0x5eed_1234);
        let public = point_multiply(P256, None, &private).expect("a public point");
        let message = b"authenticated".to_vec();
        let cipher = crypt_ecc_encrypt(
            P256,
            &public,
            kdf2(TPM_ALG_SHA256),
            &message,
            &mut rand(b"tamper"),
            &mut no_self_test,
        )
        .expect("encryption succeeds");

        let mut broken_c1 = cipher.c1.clone();
        broken_c1.x[0] ^= 0x01;
        assert_eq!(
            crypt_ecc_decrypt(
                P256,
                Some(&stored(&private)),
                kdf2(TPM_ALG_SHA256),
                &broken_c1,
                &cipher.c2,
                &cipher.c3,
                &mut no_self_test
            ),
            Err(TPM_RC_VALUE)
        );

        let mut broken_c2 = cipher.c2.clone();
        broken_c2[0] ^= 0x01;
        assert_eq!(
            crypt_ecc_decrypt(
                P256,
                Some(&stored(&private)),
                kdf2(TPM_ALG_SHA256),
                &cipher.c1,
                &broken_c2,
                &cipher.c3,
                &mut no_self_test
            ),
            Err(TPM_RC_VALUE)
        );

        let mut broken_c3 = cipher.c3.clone();
        broken_c3[0] ^= 0x01;
        assert_eq!(
            crypt_ecc_decrypt(
                P256,
                Some(&stored(&private)),
                kdf2(TPM_ALG_SHA256),
                &cipher.c1,
                &cipher.c2,
                &broken_c3,
                &mut no_self_test
            ),
            Err(TPM_RC_VALUE)
        );
    }

    #[test]
    fn non_kdf2_scheme_rejection_both_directions() {
        let private = scalar(P256, 0x11);
        let public = point_multiply(P256, None, &private).expect("a public point");
        let scheme = Scheme {
            scheme: TPM_ALG_KDF1_SP800_56A,
            hash_alg: Some(TPM_ALG_SHA256),
            count: None,
            kdf: None,
        };
        assert_eq!(
            crypt_ecc_encrypt(
                P256,
                &public,
                scheme,
                b"x",
                &mut rand(b"scheme"),
                &mut no_self_test
            )
            .err(),
            Some(TPM_RC_SCHEME)
        );
        assert_eq!(
            crypt_ecc_decrypt(
                P256,
                Some(&stored(&private)),
                scheme,
                &public,
                b"x",
                b"y",
                &mut no_self_test
            )
            .err(),
            Some(TPM_RC_SCHEME)
        );
    }

    #[test]
    fn encryption_generator_state_determinism() {
        let private = scalar(P256, 0x77);
        let public = point_multiply(P256, None, &private).expect("a public point");
        let first = crypt_ecc_encrypt(
            P256,
            &public,
            kdf2(TPM_ALG_SHA256),
            b"same",
            &mut rand(b"a"),
            &mut no_self_test,
        )
        .expect("encryption succeeds");
        let second = crypt_ecc_encrypt(
            P256,
            &public,
            kdf2(TPM_ALG_SHA256),
            b"same",
            &mut rand(b"a"),
            &mut no_self_test,
        )
        .expect("encryption succeeds");
        assert_eq!(first.c1, second.c1);
        assert_eq!(first.c2, second.c2);
        assert_eq!(first.c3, second.c3);
        let third = crypt_ecc_encrypt(
            P256,
            &public,
            kdf2(TPM_ALG_SHA256),
            b"same",
            &mut rand(b"b"),
            &mut no_self_test,
        )
        .expect("encryption succeeds");
        assert_ne!(first.c1, third.c1);
    }

    #[test]
    fn commit_output_point_selection() {
        let private = scalar(P256, 0x2222);
        let r = secret(P256, 0x3333);
        let point = generator(P256);

        let (k, l, e) = commit_compute(
            P256,
            None,
            None,
            Some(&stored(&private)),
            &r,
            &never_canceled,
        )
        .expect("K, L and E");
        assert_eq!(k, EccPoint::empty());
        assert_eq!(l, EccPoint::empty());
        assert_eq!(
            e,
            point_multiply(P256, None, &scalar(P256, 0x3333)).expect("[r]G")
        );

        let (k, l, e) = commit_compute(
            P256,
            Some(&point),
            None,
            Some(&stored(&private)),
            &r,
            &never_canceled,
        )
        .expect("K, L and E");
        assert_eq!(k, EccPoint::empty());
        assert_eq!(l, EccPoint::empty());
        assert_eq!(
            e,
            point_multiply(P256, Some(&point), &scalar(P256, 0x3333)).expect("[r]P1")
        );

        let (k, l, e) = commit_compute(
            P256,
            None,
            Some(&point),
            Some(&stored(&private)),
            &r,
            &never_canceled,
        )
        .expect("K, L and E");
        assert_eq!(
            k,
            point_multiply(P256, Some(&point), &private).expect("[d]P2")
        );
        assert_eq!(
            l,
            point_multiply(P256, Some(&point), &scalar(P256, 0x3333)).expect("[r]P2")
        );
        assert_eq!(e, EccPoint::empty());

        let (k, l, e) = commit_compute(
            P256,
            Some(&point),
            Some(&point),
            Some(&stored(&private)),
            &r,
            &never_canceled,
        )
        .expect("K, L and E");
        assert_ne!(k, EccPoint::empty());
        assert_ne!(l, EccPoint::empty());
        assert_ne!(e, EccPoint::empty());
    }

    #[test]
    fn commit_off_curve_operand_value_error() {
        let mut point = generator(P256);
        point.x[0] ^= 0xff;
        assert_eq!(
            commit_compute(
                P256,
                None,
                Some(&point),
                Some(&stored(&scalar(P256, 1))),
                &secret(P256, 2),
                &never_canceled
            ),
            Err(TPM_RC_VALUE)
        );
    }

    #[test]
    fn commit_value_equal_to_order_value_error() {
        let curve = curve(P256);
        let reduced = curve.scalar(&curve.order()).expect("the order reduces");
        assert!(
            reduced.is_zero(),
            "an order-valued commitment reduces to zero"
        );
        assert_eq!(
            commit_compute(
                P256,
                None,
                Some(&generator(P256)),
                Some(&stored(&scalar(P256, 1))),
                &reduced,
                &never_canceled
            ),
            Err(TPM_RC_VALUE)
        );
    }

    #[test]
    fn two_phase_ecdh_dual_shared_point_output() {
        let ds_a = scalar(P256, 0x0a0a);
        let de_a = secret(P256, 0x0b0b);
        let qs_b = point_multiply(P256, None, &scalar(P256, 0x0c0c)).expect("a point");
        let qe_b = point_multiply(P256, None, &scalar(P256, 0x0d0d)).expect("a point");
        let result = two_phase_key_exchange(
            P256,
            TPM_ALG_ECDH,
            Some(&stored(&ds_a)),
            &de_a,
            &qs_b,
            &qe_b,
        )
        .expect("the exchange succeeds");
        assert_eq!(result.outcome, TwoPhaseOutcome::Points);
        assert_eq!(
            result.z1,
            point_multiply(P256, Some(&qs_b), &ds_a).expect("[dsA]QsB")
        );
        assert_eq!(
            result.z2,
            point_multiply(P256, Some(&qe_b), &scalar(P256, 0x0b0b)).expect("[deA]QeB")
        );
    }

    #[test]
    fn two_phase_sm2_single_point_output() {
        let ds_a = scalar(SM2P256, 0x1111);
        let de_a = secret(SM2P256, 0x2222);
        let qs_b = point_multiply(SM2P256, None, &scalar(SM2P256, 0x3333)).expect("a point");
        let qe_b = point_multiply(SM2P256, None, &scalar(SM2P256, 0x4444)).expect("a point");
        let result = two_phase_key_exchange(
            SM2P256,
            TPM_ALG_SM2,
            Some(&stored(&ds_a)),
            &de_a,
            &qs_b,
            &qe_b,
        )
        .expect("the exchange succeeds");
        assert_eq!(result.outcome, TwoPhaseOutcome::Points);
        assert_ne!(result.z1, EccPoint::empty());
        assert_eq!(result.z2, EccPoint::empty());
        assert_eq!(point_is_on_curve(SM2P256, &result.z1), Ok(true));
    }

    #[test]
    fn two_phase_ecmqv_vendored_divide_by_zero() {
        let ds_a = scalar(P256, 0x1111);
        let de_a = secret(P256, 0x2222);
        let point = generator(P256);
        let result = two_phase_key_exchange(
            P256,
            TPM_ALG_ECMQV,
            Some(&stored(&ds_a)),
            &de_a,
            &point,
            &point,
        )
        .expect("the vendored path reports its failure through the outcome");
        assert_eq!(result.outcome, TwoPhaseOutcome::DivideByZero);
    }

    #[test]
    fn two_phase_unsupported_scheme_error() {
        let point = generator(P256);
        assert_eq!(
            two_phase_key_exchange(
                P256,
                TPM_ALG_SHA256,
                Some(&stored(&scalar(P256, 1))),
                &secret(P256, 1),
                &point,
                &point
            )
            .err(),
            Some(TPM_RC_SCHEME)
        );
    }

    fn plus_prime(coordinate: &[u8]) -> Vec<u8> {
        let prime = curve_detail(P256).expect("NIST P256").prime;
        BigUint::from_be_bytes(coordinate)
            .unwrap()
            .add(&BigUint::from_be_bytes(&prime).unwrap())
            .unwrap()
            .to_be_bytes(33)
            .expect("a 33-byte alias")
    }

    #[test]
    fn above_prime_coordinate_vendored_reduction() {
        let peer = multiple_of_generator(2);
        let scalar = scalar(P256, 0x1234);
        let expected = point_multiply(P256, Some(&peer), &scalar).expect("the shared point");
        for aliased in [
            EccPoint {
                x: plus_prime(&peer.x),
                y: peer.y.clone(),
            },
            EccPoint {
                x: peer.x.clone(),
                y: plus_prime(&peer.y),
            },
            EccPoint {
                x: plus_prime(&peer.x),
                y: plus_prime(&peer.y),
            },
        ] {
            assert!(
                on_curve(P256, &aliased),
                "the curve equation is evaluated modulo p"
            );
            assert_eq!(
                point_multiply(P256, Some(&aliased), &scalar).expect("the shared point"),
                expected,
                "an out-of-field alias answers the canonical product"
            );
        }
    }

    #[test]
    fn prime_coordinate_zero_reduction_off_curve() {
        let peer = multiple_of_generator(2);
        let point = EccPoint {
            x: curve_detail(P256).expect("NIST P256").prime,
            y: peer.y.clone(),
        };
        assert!(!on_curve(P256, &point), "(0, y) is off the curve");
        assert_eq!(
            point_multiply(P256, Some(&point), &scalar(P256, 3)),
            Err(TPM_RC_ECC_POINT)
        );
    }

    #[test]
    fn out_of_field_ciphertext_point_decryption_success() {
        let private = scalar(P256, 0x5eed_1234);
        let public = point_multiply(P256, None, &private).expect("a public point");
        let message = b"aliased".to_vec();
        let cipher = crypt_ecc_encrypt(
            P256,
            &public,
            kdf2(TPM_ALG_SHA256),
            &message,
            &mut rand(b"alias"),
            &mut no_self_test,
        )
        .expect("encryption succeeds");
        let aliased = EccPoint {
            x: plus_prime(&cipher.c1.x),
            y: cipher.c1.y.clone(),
        };
        assert_eq!(
            crypt_ecc_decrypt(
                P256,
                Some(&stored(&private)),
                kdf2(TPM_ALG_SHA256),
                &aliased,
                &cipher.c2,
                &cipher.c3,
                &mut no_self_test
            )
            .expect("decryption succeeds"),
            message
        );
    }

    #[test]
    fn integrity_mismatch_rejection_any_position() {
        let private = scalar(P256, 0x0f0f);
        let public = point_multiply(P256, None, &private).expect("a public point");
        let message = message_of(48);
        let cipher = crypt_ecc_encrypt(
            P256,
            &public,
            kdf2(TPM_ALG_SHA256),
            &message,
            &mut rand(b"integrity"),
            &mut no_self_test,
        )
        .expect("encryption succeeds");
        for position in [0usize, 15, 31] {
            let mut broken = cipher.c3.clone();
            broken[position] ^= 0x80;
            assert_eq!(
                crypt_ecc_decrypt(
                    P256,
                    Some(&stored(&private)),
                    kdf2(TPM_ALG_SHA256),
                    &cipher.c1,
                    &cipher.c2,
                    &broken,
                    &mut no_self_test
                ),
                Err(TPM_RC_VALUE),
                "a mismatch at byte {position} is refused"
            );
        }
        for length in [0usize, 31, 33, 64] {
            assert_eq!(
                crypt_ecc_decrypt(
                    P256,
                    Some(&stored(&private)),
                    kdf2(TPM_ALG_SHA256),
                    &cipher.c1,
                    &cipher.c2,
                    &vec![0u8; length],
                    &mut no_self_test
                ),
                Err(TPM_RC_VALUE),
                "a {length}-byte digest is refused"
            );
        }
        assert_eq!(
            crypt_ecc_decrypt(
                P256,
                Some(&stored(&private)),
                kdf2(TPM_ALG_SHA256),
                &cipher.c1,
                &cipher.c2,
                &cipher.c3,
                &mut no_self_test
            )
            .expect("the matching digest is accepted"),
            message
        );
    }

    #[test]
    fn self_test_gate_vendored_call_order() {
        let private = scalar(P256, 0x2222);
        let public = point_multiply(P256, None, &private).expect("a public point");
        let mut gates = Vec::new();
        let cipher = crypt_ecc_encrypt(
            P256,
            &public,
            kdf2(TPM_ALG_SHA256),
            b"gates",
            &mut rand(b"gates"),
            &mut |gate| {
                gates.push(gate);
                Ok(())
            },
        )
        .expect("encryption succeeds");
        assert_eq!(
            gates,
            [EccSelfTest::Ecdh, EccSelfTest::Hash(TPM_ALG_SHA256)],
            "TpmEcc_PointMult runs before CryptHashStart"
        );

        gates.clear();
        crypt_ecc_decrypt(
            P256,
            Some(&stored(&private)),
            kdf2(TPM_ALG_SHA256),
            &cipher.c1,
            &cipher.c2,
            &cipher.c3,
            &mut |gate| {
                gates.push(gate);
                Ok(())
            },
        )
        .expect("decryption succeeds");
        assert_eq!(
            gates,
            [EccSelfTest::Ecdh, EccSelfTest::Hash(TPM_ALG_SHA256)]
        );
    }

    #[test]
    fn failing_self_test_gate_pre_operation_stop() {
        let private = scalar(P256, 0x3333);
        let public = point_multiply(P256, None, &private).expect("a public point");
        const INJECTED: TpmResult = 0x0101;
        for stop in [EccSelfTest::Ecdh, EccSelfTest::Hash(TPM_ALG_SHA256)] {
            assert_eq!(
                crypt_ecc_encrypt(
                    P256,
                    &public,
                    kdf2(TPM_ALG_SHA256),
                    b"gates",
                    &mut rand(b"gates"),
                    &mut |gate| if gate == stop { Err(INJECTED) } else { Ok(()) },
                )
                .err(),
                Some(INJECTED),
                "{stop:?} aborts the encryption"
            );
        }
    }

    #[test]
    fn commit_cancel_poll_vendored_boundaries() {
        let private = scalar(P256, 0x4444);
        let r = secret(P256, 0x5555);
        let point = multiple_of_generator(2);
        let polls = core::cell::Cell::new(0usize);
        let count = || {
            polls.set(polls.get() + 1);
            false
        };

        polls.set(0);
        commit_compute(P256, None, None, Some(&stored(&private)), &r, &count).expect("K, L and E");
        assert_eq!(polls.get(), 0, "the [r]G path has no checkpoint");

        polls.set(0);
        commit_compute(
            P256,
            Some(&point),
            None,
            Some(&stored(&private)),
            &r,
            &count,
        )
        .expect("K, L and E");
        assert_eq!(polls.get(), 0, "the [r]P1 path has no checkpoint");

        polls.set(0);
        commit_compute(
            P256,
            None,
            Some(&point),
            Some(&stored(&private)),
            &r,
            &count,
        )
        .expect("K, L and E");
        assert_eq!(polls.get(), 1, "one checkpoint between K and L");

        polls.set(0);
        commit_compute(
            P256,
            Some(&point),
            Some(&point),
            Some(&stored(&private)),
            &r,
            &count,
        )
        .expect("K, L and E");
        assert_eq!(polls.get(), 2, "a second checkpoint before E");
    }

    #[test]
    fn signaled_cancel_commit_stop() {
        let private = scalar(P256, 0x6666);
        let r = secret(P256, 0x7777);
        let point = multiple_of_generator(2);
        let always = || true;
        assert_eq!(
            commit_compute(
                P256,
                None,
                Some(&point),
                Some(&stored(&private)),
                &r,
                &always
            ),
            Err(crate::library::constants::TPM_RC_CANCELED)
        );
        assert_eq!(
            commit_compute(
                P256,
                Some(&point),
                Some(&point),
                Some(&stored(&private)),
                &r,
                &always
            ),
            Err(crate::library::constants::TPM_RC_CANCELED)
        );
        assert!(
            commit_compute(
                P256,
                Some(&point),
                None,
                Some(&stored(&private)),
                &r,
                &always
            )
            .is_ok(),
            "a path without P2 never reaches a checkpoint"
        );
        assert!(commit_compute(P256, None, None, Some(&stored(&private)), &r, &always).is_ok());
    }

    #[test]
    fn second_checkpoint_after_first_pass_only() {
        let private = scalar(P256, 0x8888);
        let r = secret(P256, 0x9999);
        let point = multiple_of_generator(2);
        let polls = core::cell::Cell::new(0usize);
        let second_only = || {
            polls.set(polls.get() + 1);
            polls.get() == 2
        };
        assert_eq!(
            commit_compute(
                P256,
                Some(&point),
                Some(&point),
                Some(&stored(&private)),
                &r,
                &second_only
            ),
            Err(crate::library::constants::TPM_RC_CANCELED)
        );
        assert_eq!(polls.get(), 2);
    }

    fn reference_associated_value(value: &BigUint, bits: usize) -> BigUint {
        let mut masked = value.clone();
        masked.mask_bits(upstream_mask_kept_bits(bits)).unwrap();
        if masked.test_bit(bits) {
            masked
        } else {
            masked
                .add(&BigUint::from_u64(1).unwrap().shl(bits).unwrap())
                .unwrap()
        }
    }

    #[test]
    fn upstream_mask_word_granularity() {
        assert_eq!(upstream_mask_kept_bits(0), 0);
        assert_eq!(
            upstream_mask_kept_bits(64),
            64,
            "a whole-word mask keeps exactly that word"
        );
        assert_eq!(
            upstream_mask_kept_bits(126),
            66,
            "the vendored shift keeps sixty-six bits, not one hundred twenty-six"
        );
        assert_eq!(
            upstream_mask_kept_bits(8),
            56,
            "a sub-word mask keeps the complement of the requested bits"
        );
    }

    #[test]
    fn associated_value_bit_above_mask() {
        let value = BigUint::from_be_bytes(&[0xff; 32]).unwrap();
        let mut masked = value.clone();
        masked.mask_bits(56).unwrap();
        assert_eq!(
            BigUint::from_be_bytes(&associated_value(&[0xff; 32], 8)).unwrap(),
            masked,
            "avfSm2 sets bit w; a bit the upstream mask kept stays as it is"
        );
        let mut cleared = [0xff; 32];
        cleared[30] = 0xfe;
        let mut masked = BigUint::from_be_bytes(&cleared).unwrap();
        masked.mask_bits(56).unwrap();
        assert_eq!(
            BigUint::from_be_bytes(&associated_value(&cleared, 8)).unwrap(),
            masked.add(&BigUint::from_u64(0x100).unwrap()).unwrap()
        );
        assert_eq!(
            BigUint::from_be_bytes(&associated_value(&[], 4)).unwrap(),
            BigUint::from_u64(0x10).unwrap()
        );
    }

    #[test]
    fn associated_value_reference_agreement_per_curve() {
        for curve_id in ALL_CURVES {
            let curve = curve(curve_id);
            let w = (curve.order_bits() - 1) / 2 - 1;
            for fill in [0x00u8, 0x01, 0x5a, 0x80, 0xff] {
                let mut coordinate = vec![fill; curve.field_bytes()];
                coordinate[0] ^= 0x33;
                assert_eq!(
                    BigUint::from_be_bytes(&associated_value(&coordinate, w)).unwrap(),
                    reference_associated_value(&BigUint::from_be_bytes(&coordinate).unwrap(), w),
                    "curve {curve_id:#06x} fill {fill:#04x}"
                );
            }
        }
    }
}
