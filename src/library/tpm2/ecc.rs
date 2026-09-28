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

use crate::library::constants::{
    TPM_RC_CANCELED, TPM_RC_CURVE, TPM_RC_ECC_POINT, TPM_RC_FAILURE, TPM_RC_HASH, TPM_RC_NO_RESULT,
    TPM_RC_SCHEME, TPM_RC_SIZE, TPM_RC_VALUE,
};
use crate::types::TpmResult;

use super::algorithm::{TPM_ALG_ECC, TPM_ALG_ECDH, TPM_ALG_ECMQV, TPM_ALG_KDF2, TPM_ALG_SM2};
use super::commit::CommitState;
use super::crypto::{
    BigUint, CurveParameters, EccKeyError, EccKeyMaterial, Hasher, SeededRand, curve_detail,
    curve_parameters, generate_ecc_key,
};
use super::marshal::BlobWriter;
use super::persistent::{OwnedObjectBody, OwnedPublicId};
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

    fn from_coordinates(curve: &CurveParameters, x: &BigUint, y: &BigUint) -> Option<Self> {
        let width = curve.key_size_bytes;
        Some(Self {
            x: fixed_width(x, width)?,
            y: fixed_width(y, width)?,
        })
    }

    fn numbers(&self) -> (BigUint, BigUint) {
        (
            BigUint::from_be_bytes(&self.x),
            BigUint::from_be_bytes(&self.y),
        )
    }
}

fn fixed_width(value: &BigUint, width: usize) -> Option<Vec<u8>> {
    if value.is_zero() {
        return Some(vec![0u8]);
    }
    value.to_be_bytes(width.max(value.byte_len()))
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

pub(super) fn ecc_private_scalar(body: &OwnedObjectBody) -> Option<&[u8]> {
    body.sensitive
        .sensitive
        .as_ref()
        .map(super::persistent::OwnedSecret::as_bytes)
}

pub(super) fn point_is_on_curve(curve_id: u16, point: &EccPoint) -> bool {
    let Some(curve) = curve_parameters(curve_id) else {
        return false;
    };
    let (x, y) = point.numbers();
    curve.is_point_on_curve(&x, &y)
}

fn reduced_coordinates(curve: &CurveParameters, point: &EccPoint) -> Option<(BigUint, BigUint)> {
    let (x, y) = point.numbers();
    Some((x.rem(&curve.prime)?, y.rem(&curve.prime)?))
}

pub(super) fn point_multiply(
    curve_id: u16,
    base: Option<&EccPoint>,
    scalar: &[u8],
) -> Result<EccPoint, TpmResult> {
    let curve = curve_parameters(curve_id).ok_or(TPM_RC_VALUE)?;
    let value = BigUint::from_be_bytes(scalar);
    let product = match base {
        Some(base) => {
            let (x, y) = base.numbers();
            if !curve.is_point_on_curve(&x, &y) {
                return Err(TPM_RC_ECC_POINT);
            }
            let (x, y) = reduced_coordinates(&curve, base).ok_or(TPM_RC_NO_RESULT)?;
            curve.multiply_point((&x, &y), &value)
        }
        None => curve.multiply_generator(&value),
    };
    let (x, y) = product.ok_or(TPM_RC_NO_RESULT)?;
    EccPoint::from_coordinates(&curve, &x, &y).ok_or(TPM_RC_FAILURE)
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

fn kdf2_mask(hash_alg: u16, seed: &[u8], length: usize) -> Option<Vec<u8>> {
    if length == 0 {
        return Some(Vec::new());
    }
    let digest_size = super::template::digest_size(hash_alg)?;
    let mut out = Vec::with_capacity(length.next_multiple_of(digest_size));
    let mut counter: u32 = 1;
    while out.len() < length {
        let mut hasher = Hasher::new(hash_alg)?;
        hasher.update(seed);
        hasher.update(&counter.to_be_bytes());
        out.extend_from_slice(&hasher.finalize());
        counter += 1;
    }
    out.truncate(length);
    Some(out)
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
    curve_parameters(curve_id).ok_or(TPM_RC_CURVE)?;
    if scheme.scheme != TPM_ALG_KDF2 {
        return Err(TPM_RC_SCHEME);
    }
    let ephemeral: EccKeyMaterial =
        generate_ecc_key(curve_id, rand).map_err(|error| match error {
            EccKeyError::Curve => TPM_RC_CURVE,
            EccKeyError::NoResult => TPM_RC_NO_RESULT,
        })?;
    let c1 = EccPoint {
        x: ephemeral.x,
        y: ephemeral.y,
    };
    self_test(EccSelfTest::Ecdh)?;
    let p2 =
        point_multiply(curve_id, Some(public), &ephemeral.private).map_err(|_| TPM_RC_NO_RESULT)?;
    let hash_alg = scheme.hash_alg.ok_or(TPM_RC_HASH)?;
    self_test(EccSelfTest::Hash(hash_alg))?;

    let mut hasher = Hasher::new(hash_alg).ok_or(TPM_RC_HASH)?;
    hasher.update(&p2.x);
    hasher.update(plain_text);
    hasher.update(&p2.y);
    let c3 = hasher.finalize();

    let mut seed = p2.x.clone();
    seed.extend_from_slice(&p2.y);
    let mut c2 = kdf2_mask(hash_alg, &seed, plain_text.len()).ok_or(TPM_RC_HASH)?;
    for (masked, clear) in c2.iter_mut().zip(plain_text) {
        *masked ^= clear;
    }
    Ok(EccCiphertext { c1, c2, c3 })
}

pub(super) fn crypt_ecc_decrypt(
    curve_id: u16,
    private: &[u8],
    scheme: Scheme,
    c1: &EccPoint,
    c2: &[u8],
    c3: &[u8],
    self_test: EccSelfTestHook<'_>,
) -> Result<Vec<u8>, TpmResult> {
    let curve = curve_parameters(curve_id).ok_or(TPM_RC_CURVE)?;
    if scheme.scheme != TPM_ALG_KDF2 {
        return Err(TPM_RC_SCHEME);
    }
    self_test(EccSelfTest::Ecdh)?;
    let p2 = match point_multiply(curve_id, Some(c1), private) {
        Ok(point) => point,
        Err(_) => {
            let (x, y) = c1.numbers();
            EccPoint::from_coordinates(&curve, &x, &y).ok_or(TPM_RC_FAILURE)?
        }
    };
    let hash_alg = scheme.hash_alg.ok_or(TPM_RC_HASH)?;
    self_test(EccSelfTest::Hash(hash_alg))?;
    let mut hasher = Hasher::new(hash_alg).ok_or(TPM_RC_HASH)?;
    hasher.update(&p2.x);

    let mut seed = p2.x.clone();
    seed.extend_from_slice(&p2.y);
    let mut plain_text = kdf2_mask(hash_alg, &seed, c2.len()).ok_or(TPM_RC_HASH)?;
    for (clear, masked) in plain_text.iter_mut().zip(c2) {
        *clear ^= masked;
    }

    hasher.update(&plain_text);
    hasher.update(&p2.y);
    if !super::session::digests_equal(&hasher.finalize(), c3) {
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
    let curve = curve_parameters(curve_id).ok_or(TPM_RC_FAILURE)?;
    let mut hasher = Hasher::new(name_alg).ok_or(TPM_RC_HASH)?;
    hasher.update(s2);
    let digest = hasher.finalize();
    let width = curve.prime.byte_len();
    let reduced = BigUint::from_be_bytes(&digest)
        .rem(&curve.prime)
        .ok_or(TPM_RC_NO_RESULT)?;
    let x = reduced.to_be_bytes(width).ok_or(TPM_RC_NO_RESULT)?;
    Ok(EccPoint { x, y: y2.to_vec() })
}

pub(super) fn commit_compute(
    curve_id: u16,
    p1: Option<&EccPoint>,
    p2: Option<&EccPoint>,
    private: &[u8],
    r: &BigUint,
    canceled: &dyn Fn() -> bool,
) -> Result<(EccPoint, EccPoint, EccPoint), TpmResult> {
    let curve = curve_parameters(curve_id).ok_or(TPM_RC_NO_RESULT)?;
    let r_bytes = r
        .to_be_bytes(curve.order.byte_len())
        .ok_or(TPM_RC_NO_RESULT)?;
    let mut k = EccPoint::empty();
    let mut l = EccPoint::empty();
    let mut e = EccPoint::empty();
    if let Some(p2) = p2 {
        if !point_is_on_curve(curve_id, p2) {
            return Err(TPM_RC_VALUE);
        }
        k = point_multiply(curve_id, Some(p2), private)?;
        if canceled() {
            return Err(TPM_RC_CANCELED);
        }
        if r.is_zero() || *r >= curve.order {
            return Err(TPM_RC_VALUE);
        }
        l = point_multiply(curve_id, Some(p2), &r_bytes)?;
    }
    if p1.is_some() || p2.is_none() {
        if p2.is_some() && canceled() {
            return Err(TPM_RC_CANCELED);
        }
        e = point_multiply(curve_id, p1, &r_bytes)?;
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
    static_private: &[u8],
    ephemeral_private: &BigUint,
    qs_b: &EccPoint,
    qe_b: &EccPoint,
) -> Result<TwoPhaseResult, TpmResult> {
    let curve = curve_parameters(curve_id).ok_or(TPM_RC_CURVE)?;
    match scheme {
        TPM_ALG_ECDH => {
            let ephemeral = ephemeral_private
                .to_be_bytes(curve.order.byte_len())
                .ok_or(TPM_RC_NO_RESULT)?;
            let z1 = point_multiply(curve_id, Some(qs_b), static_private)?;
            let z2 = point_multiply(curve_id, Some(qe_b), &ephemeral)?;
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

fn upstream_mask_bits(value: &BigUint, mask_bit: usize) -> BigUint {
    const RADIX_BITS: usize = 64;
    let words = mask_bit.div_ceil(RADIX_BITS);
    if words == 0 {
        return BigUint::zero();
    }
    let remainder = mask_bit % RADIX_BITS;
    let kept = if remainder == 0 {
        words * RADIX_BITS
    } else {
        (words - 1) * RADIX_BITS + (RADIX_BITS - remainder)
    };
    let mut masked = value.clone();
    masked.mask_bits(kept);
    masked
}

fn associated_value(value: &BigUint, bits: usize) -> BigUint {
    upstream_mask_bits(value, bits).add(&BigUint::from_u64(1).shl(bits))
}

fn sm2_key_exchange(
    curve: &CurveParameters,
    static_private: &[u8],
    ephemeral_private: &BigUint,
    qs_b: &EccPoint,
    qe_b: &EccPoint,
) -> Result<EccPoint, TpmResult> {
    let w = (curve.order.bit_len() - 1) / 2 - 1;
    let (qe_a_x, _) = curve
        .multiply_generator(ephemeral_private)
        .ok_or(TPM_RC_NO_RESULT)?;
    let ds_a = BigUint::from_be_bytes(static_private);
    let ta = ephemeral_private
        .mul(&associated_value(&qe_a_x, w))
        .add(&ds_a)
        .rem(&curve.order)
        .ok_or(TPM_RC_NO_RESULT)?;

    let (qs_b_x, qs_b_y) = qs_b.numbers();
    let (qe_b_x, qe_b_y) = qe_b.numbers();
    let (zx, zy) = curve
        .multiply_and_add(
            (&qs_b_x, &qs_b_y),
            &BigUint::from_u64(1),
            (&qe_b_x, &qe_b_y),
            &associated_value(&qe_b_x, w),
        )
        .ok_or(TPM_RC_NO_RESULT)?;
    let (zx, zy) = curve
        .multiply_point((&zx, &zy), &ta)
        .ok_or(TPM_RC_NO_RESULT)?;
    EccPoint::from_coordinates(curve, &zx, &zy).ok_or(TPM_RC_FAILURE)
}

pub(super) fn commit_value(
    commit: &CommitState,
    curve_id: u16,
    name: &[u8],
    count: Option<u16>,
) -> Option<BigUint> {
    let curve = curve_parameters(curve_id)?;
    commit.generate_r(&curve, name, count)
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
    use crate::library::tpm2::crypto::{curve_key_size_bits, is_compiled_curve};
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

    fn generator(curve_id: u16) -> EccPoint {
        let curve = curve_parameters(curve_id).expect("a compiled curve");
        EccPoint::from_coordinates(&curve, &curve.generator_x, &curve.generator_y)
            .expect("the generator encodes")
    }

    fn scalar(curve_id: u16, value: u64) -> Vec<u8> {
        let curve = curve_parameters(curve_id).expect("a compiled curve");
        BigUint::from_u64(value)
            .to_be_bytes(curve.order.byte_len())
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
            assert!(point_is_on_curve(curve_id, &generator(curve_id)));
        }
    }

    #[test]
    fn off_curve_point_rejection() {
        let mut point = generator(P256);
        point.y[31] ^= 0x01;
        assert!(!point_is_on_curve(P256, &point));
        assert!(!point_is_on_curve(0x0007, &generator(P256)));
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
                &private,
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
                    &private,
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
                &private,
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
                &private,
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
                &private,
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
                &private,
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
        let r = BigUint::from_u64(0x3333);
        let point = generator(P256);

        let (k, l, e) =
            commit_compute(P256, None, None, &private, &r, &never_canceled).expect("K, L and E");
        assert_eq!(k, EccPoint::empty());
        assert_eq!(l, EccPoint::empty());
        assert_eq!(
            e,
            point_multiply(P256, None, &scalar(P256, 0x3333)).expect("[r]G")
        );

        let (k, l, e) = commit_compute(P256, Some(&point), None, &private, &r, &never_canceled)
            .expect("K, L and E");
        assert_eq!(k, EccPoint::empty());
        assert_eq!(l, EccPoint::empty());
        assert_eq!(
            e,
            point_multiply(P256, Some(&point), &scalar(P256, 0x3333)).expect("[r]P1")
        );

        let (k, l, e) = commit_compute(P256, None, Some(&point), &private, &r, &never_canceled)
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
            &private,
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
                &scalar(P256, 1),
                &BigUint::from_u64(2),
                &never_canceled
            ),
            Err(TPM_RC_VALUE)
        );
    }

    #[test]
    fn commit_value_above_order_value_error() {
        let curve = curve_parameters(P256).expect("a compiled curve");
        assert_eq!(
            commit_compute(
                P256,
                None,
                Some(&generator(P256)),
                &scalar(P256, 1),
                &curve.order,
                &never_canceled
            ),
            Err(TPM_RC_VALUE)
        );
    }

    #[test]
    fn two_phase_ecdh_dual_shared_point_output() {
        let ds_a = scalar(P256, 0x0a0a);
        let de_a = BigUint::from_u64(0x0b0b);
        let qs_b = point_multiply(P256, None, &scalar(P256, 0x0c0c)).expect("a point");
        let qe_b = point_multiply(P256, None, &scalar(P256, 0x0d0d)).expect("a point");
        let result = two_phase_key_exchange(P256, TPM_ALG_ECDH, &ds_a, &de_a, &qs_b, &qe_b)
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
        let de_a = BigUint::from_u64(0x2222);
        let qs_b = point_multiply(SM2P256, None, &scalar(SM2P256, 0x3333)).expect("a point");
        let qe_b = point_multiply(SM2P256, None, &scalar(SM2P256, 0x4444)).expect("a point");
        let result = two_phase_key_exchange(SM2P256, TPM_ALG_SM2, &ds_a, &de_a, &qs_b, &qe_b)
            .expect("the exchange succeeds");
        assert_eq!(result.outcome, TwoPhaseOutcome::Points);
        assert_ne!(result.z1, EccPoint::empty());
        assert_eq!(result.z2, EccPoint::empty());
        assert!(point_is_on_curve(SM2P256, &result.z1));
    }

    #[test]
    fn two_phase_ecmqv_vendored_divide_by_zero() {
        let ds_a = scalar(P256, 0x1111);
        let de_a = BigUint::from_u64(0x2222);
        let point = generator(P256);
        let result = two_phase_key_exchange(P256, TPM_ALG_ECMQV, &ds_a, &de_a, &point, &point)
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
                &scalar(P256, 1),
                &BigUint::from_u64(1),
                &point,
                &point
            )
            .err(),
            Some(TPM_RC_SCHEME)
        );
    }

    fn plus_prime(coordinate: &[u8]) -> Vec<u8> {
        let curve = curve_parameters(P256).expect("NIST P256");
        BigUint::from_be_bytes(coordinate)
            .add(&curve.prime)
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
                point_is_on_curve(P256, &aliased),
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
        let curve = curve_parameters(P256).expect("NIST P256");
        let peer = multiple_of_generator(2);
        let point = EccPoint {
            x: curve.prime.to_be_bytes(32).expect("the prime"),
            y: peer.y.clone(),
        };
        assert!(!point_is_on_curve(P256, &point), "(0, y) is off the curve");
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
                &private,
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
                    &private,
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
                    &private,
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
                &private,
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
            &private,
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
        let r = BigUint::from_u64(0x5555);
        let point = multiple_of_generator(2);
        let polls = core::cell::Cell::new(0usize);
        let count = || {
            polls.set(polls.get() + 1);
            false
        };

        polls.set(0);
        commit_compute(P256, None, None, &private, &r, &count).expect("K, L and E");
        assert_eq!(polls.get(), 0, "the [r]G path has no checkpoint");

        polls.set(0);
        commit_compute(P256, Some(&point), None, &private, &r, &count).expect("K, L and E");
        assert_eq!(polls.get(), 0, "the [r]P1 path has no checkpoint");

        polls.set(0);
        commit_compute(P256, None, Some(&point), &private, &r, &count).expect("K, L and E");
        assert_eq!(polls.get(), 1, "one checkpoint between K and L");

        polls.set(0);
        commit_compute(P256, Some(&point), Some(&point), &private, &r, &count).expect("K, L and E");
        assert_eq!(polls.get(), 2, "a second checkpoint before E");
    }

    #[test]
    fn signaled_cancel_commit_stop() {
        let private = scalar(P256, 0x6666);
        let r = BigUint::from_u64(0x7777);
        let point = multiple_of_generator(2);
        let always = || true;
        assert_eq!(
            commit_compute(P256, None, Some(&point), &private, &r, &always),
            Err(crate::library::constants::TPM_RC_CANCELED)
        );
        assert_eq!(
            commit_compute(P256, Some(&point), Some(&point), &private, &r, &always),
            Err(crate::library::constants::TPM_RC_CANCELED)
        );
        assert!(
            commit_compute(P256, Some(&point), None, &private, &r, &always).is_ok(),
            "a path without P2 never reaches a checkpoint"
        );
        assert!(commit_compute(P256, None, None, &private, &r, &always).is_ok());
    }

    #[test]
    fn second_checkpoint_after_first_pass_only() {
        let private = scalar(P256, 0x8888);
        let r = BigUint::from_u64(0x9999);
        let point = multiple_of_generator(2);
        let polls = core::cell::Cell::new(0usize);
        let second_only = || {
            polls.set(polls.get() + 1);
            polls.get() == 2
        };
        assert_eq!(
            commit_compute(P256, Some(&point), Some(&point), &private, &r, &second_only),
            Err(crate::library::constants::TPM_RC_CANCELED)
        );
        assert_eq!(polls.get(), 2);
    }

    #[test]
    fn upstream_mask_word_granularity() {
        let value = BigUint::from_be_bytes(&[0xff; 32]);
        assert_eq!(upstream_mask_bits(&value, 0), BigUint::zero());
        assert_eq!(
            upstream_mask_bits(&value, 64),
            BigUint::from_be_bytes(&[0xff; 8]),
            "a whole-word mask keeps exactly that word"
        );
        assert_eq!(
            upstream_mask_bits(&value, 126).bit_len(),
            66,
            "the vendored shift keeps sixty-six bits, not one hundred twenty-six"
        );
        assert_eq!(
            upstream_mask_bits(&value, 8).bit_len(),
            56,
            "a sub-word mask keeps the complement of the requested bits"
        );
    }

    #[test]
    fn associated_value_bit_above_mask() {
        let value = BigUint::from_be_bytes(&[0xff; 32]);
        assert_eq!(
            associated_value(&value, 8),
            upstream_mask_bits(&value, 8).add(&BigUint::from_u64(0x100))
        );
        assert_eq!(
            associated_value(&BigUint::zero(), 4),
            BigUint::from_u64(0x10)
        );
    }
}
