// Part of the Rust port of libtpms.
//
// Project licensing and upstream notices: LICENSE and LICENSES/README.md.
//
// Rust implementation:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use openssl::bn::{BigNum, BigNumContextRef, BigNumRef};
use openssl::error::ErrorStack;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater};

use super::fault::{Boundary, checkpoint};
use super::ffi::{
    cleanse, consttime_swap, mod_exp_consttime, private_random_below, private_random_bits,
};
use super::secret::SecretBn;

const MASK_EXTRA_BITS: usize = 64;

pub(super) type Operation = fn(
    &mut BigNumRef,
    &BigNumRef,
    &BigNumRef,
    &BigNumRef,
    &mut BigNumContextRef,
) -> Result<(), ErrorStack>;

#[derive(Debug)]
pub(super) enum Outcome<T> {
    Value(T),
    Invalid,
    Backend,
}

pub(super) struct Shares {
    pub(super) masked: SecretBn,
    pub(super) mask: SecretBn,
}

pub(super) fn ct_less(left: &[u8], right: &[u8]) -> Choice {
    let mut less = Choice::from(0u8);
    let mut decided = Choice::from(0u8);
    for (left, right) in left.iter().zip(right.iter()) {
        let differs = !left.ct_eq(right);
        less.conditional_assign(&right.ct_gt(left), !decided & differs);
        decided |= differs;
    }
    less
}

pub(super) fn ct_is_zero(bytes: &[u8]) -> Choice {
    bytes.iter().fold(0u8, |acc, &byte| acc | byte).ct_eq(&0)
}

pub(super) fn words_for(modulus: &BigNumRef) -> i32 {
    (modulus.num_bits() + 63) / 64 + 1
}

fn modulus_bytes(modulus: &BigNumRef) -> usize {
    usize::try_from(modulus.num_bytes()).unwrap_or(0)
}

pub(super) fn random_mask(modulus: &BigNumRef) -> Option<SecretBn> {
    let mut mask = SecretBn::new().ok()?;
    private_random_below(&mut mask, modulus).ok()?;
    Some(mask)
}

pub(super) fn nonzero_mask(modulus: &BigNumRef) -> Option<SecretBn> {
    let mut mask = SecretBn::new().ok()?;
    loop {
        private_random_below(&mut mask, modulus).ok()?;
        if mask.num_bits() != 0 {
            return Some(mask);
        }
    }
}

fn apply(
    left: &BigNumRef,
    right: &BigNumRef,
    modulus: &BigNumRef,
    ctx: &mut BigNumContextRef,
    operation: Operation,
) -> Option<SecretBn> {
    let mut result = SecretBn::new().ok()?;
    operation(&mut result, left, right, modulus, ctx).ok()?;
    Some(result)
}

pub(super) fn add_mod(
    left: &BigNumRef,
    right: &BigNumRef,
    modulus: &BigNumRef,
    ctx: &mut BigNumContextRef,
) -> Option<SecretBn> {
    apply(left, right, modulus, ctx, |r, a, b, m, ctx| {
        r.mod_add(a, b, m, ctx)
    })
}

pub(super) fn sub_mod(
    left: &BigNumRef,
    right: &BigNumRef,
    modulus: &BigNumRef,
    ctx: &mut BigNumContextRef,
) -> Option<SecretBn> {
    apply(left, right, modulus, ctx, |r, a, b, m, ctx| {
        r.mod_sub(a, b, m, ctx)
    })
}

pub(super) fn mul_mod(
    left: &BigNumRef,
    right: &BigNumRef,
    modulus: &BigNumRef,
    ctx: &mut BigNumContextRef,
) -> Option<SecretBn> {
    apply(left, right, modulus, ctx, |r, a, b, m, ctx| {
        r.mod_mul(a, b, m, ctx)
    })
}

pub(super) fn invert_public_width(
    value: &BigNumRef,
    modulus_minus_two: &BigNumRef,
    modulus: &BigNumRef,
    ctx: &mut BigNumContextRef,
) -> Option<SecretBn> {
    let mut inverse = SecretBn::new().ok()?;
    mod_exp_consttime(&mut inverse, value, modulus_minus_two, modulus, ctx).ok()?;
    Some(inverse)
}

pub(super) fn exported_bytes(value: &SecretBn, length: usize) -> Option<Vec<u8>> {
    value.to_be(length).ok()
}

pub(super) fn masked_import(
    bytes: &[u8],
    modulus: &BigNumRef,
    ctx: &mut BigNumContextRef,
) -> Option<Shares> {
    let width = bytes.len() * 8;
    let mut marked = Vec::with_capacity(bytes.len() + 1);
    marked.push(1u8);
    marked.extend_from_slice(bytes);
    let parsed = BigNum::from_slice(&marked);
    cleanse(&mut marked);
    let numerator = SecretBn::adopt(parsed.ok()?);
    let mut marker = BigNum::new().ok()?;
    marker.set_bit(i32::try_from(width).ok()?).ok()?;
    let mut marker_residue = BigNum::new().ok()?;
    marker_residue.nnmod(&marker, modulus, ctx).ok()?;
    let mut compensation = BigNum::new().ok()?;
    if marker_residue.num_bits() != 0 {
        compensation.checked_sub(modulus, &marker_residue).ok()?;
    }
    let mask_bits = width.max(usize::try_from(modulus.num_bits()).ok()?) + MASK_EXTRA_BITS;
    let mut wide_mask = SecretBn::new().ok()?;
    private_random_bits(&mut wide_mask, i32::try_from(mask_bits).ok()?).ok()?;
    let mut blinded = SecretBn::new().ok()?;
    blinded.checked_add(&numerator, &wide_mask).ok()?;
    drop(numerator);
    let mut shifted = SecretBn::new().ok()?;
    shifted.checked_add(&blinded, &compensation).ok()?;
    drop(blinded);
    let mut masked = SecretBn::new().ok()?;
    checkpoint(Boundary::ImportReduction)?;
    masked.nnmod(&shifted, modulus, ctx).ok()?;
    let mut mask = SecretBn::new().ok()?;
    mask.nnmod(&wide_mask, modulus, ctx).ok()?;
    Some(Shares { masked, mask })
}

pub(super) fn remask(
    shares: &Shares,
    modulus: &BigNumRef,
    ctx: &mut BigNumContextRef,
) -> Option<Shares> {
    checkpoint(Boundary::Remask)?;
    let fresh = random_mask(modulus)?;
    Some(Shares {
        masked: add_mod(&shares.masked, &fresh, modulus, ctx)?,
        mask: add_mod(&shares.mask, &fresh, modulus, ctx)?,
    })
}

pub(super) fn masked_mul(
    left: &Shares,
    right: &Shares,
    modulus: &BigNumRef,
    ctx: &mut BigNumContextRef,
) -> Option<Shares> {
    checkpoint(Boundary::MaskedProduct)?;
    let right = remask(right, modulus, ctx)?;
    for operand in [&left.masked, &left.mask, &right.masked, &right.mask] {
        record_operand("product operand", operand);
    }
    let output_mask = random_mask(modulus)?;
    let masked_masked = mul_mod(&left.masked, &right.masked, modulus, ctx)?;
    let masked_mask = mul_mod(&left.masked, &right.mask, modulus, ctx)?;
    let mask_masked = mul_mod(&left.mask, &right.masked, modulus, ctx)?;
    let mask_mask = mul_mod(&left.mask, &right.mask, modulus, ctx)?;
    let mut sum = add_mod(&output_mask, &masked_masked, modulus, ctx)?;
    sum = sub_mod(&sum, &masked_mask, modulus, ctx)?;
    sum = sub_mod(&sum, &mask_masked, modulus, ctx)?;
    sum = add_mod(&sum, &mask_mask, modulus, ctx)?;
    Some(Shares {
        masked: sum,
        mask: output_mask,
    })
}

pub(super) fn masked_scale(
    shares: &Shares,
    factor: &BigNumRef,
    modulus: &BigNumRef,
    ctx: &mut BigNumContextRef,
) -> Option<Shares> {
    let scaled = Shares {
        masked: mul_mod(&shares.masked, factor, modulus, ctx)?,
        mask: mul_mod(&shares.mask, factor, modulus, ctx)?,
    };
    remask(&scaled, modulus, ctx)
}

pub(super) fn equals_public(
    shares: &Shares,
    value: &BigNumRef,
    modulus: &BigNumRef,
    ctx: &mut BigNumContextRef,
) -> Option<bool> {
    let width = modulus_bytes(modulus);
    let shifted = add_mod(value, &shares.mask, modulus, ctx)?;
    let mut expected = exported_bytes(&shifted, width)?;
    let mut actual = exported_bytes(&shares.masked, width)?;
    let equal = bool::from(expected.ct_eq(&actual));
    cleanse(&mut expected);
    cleanse(&mut actual);
    Some(equal)
}

pub(super) fn power_of_two(bits: usize) -> Option<BigNum> {
    let mut value = BigNum::new().ok()?;
    value.set_bit(i32::try_from(bits).ok()?).ok()?;
    Some(value)
}

pub(super) fn add_shares(
    left: &Shares,
    right: &Shares,
    modulus: &BigNumRef,
    ctx: &mut BigNumContextRef,
) -> Option<Shares> {
    let right = remask(right, modulus, ctx)?;
    Some(Shares {
        masked: add_mod(&left.masked, &right.masked, modulus, ctx)?,
        mask: add_mod(&left.mask, &right.mask, modulus, ctx)?,
    })
}

pub(super) fn negate(
    shares: &Shares,
    modulus: &BigNumRef,
    ctx: &mut BigNumContextRef,
) -> Option<Shares> {
    let zero = BigNum::new().ok()?;
    Some(Shares {
        masked: sub_mod(&zero, &shares.masked, modulus, ctx)?,
        mask: sub_mod(&zero, &shares.mask, modulus, ctx)?,
    })
}

pub(super) fn sub_shares(
    left: &Shares,
    right: &Shares,
    modulus: &BigNumRef,
    ctx: &mut BigNumContextRef,
) -> Option<Shares> {
    add_shares(left, &negate(right, modulus, ctx)?, modulus, ctx)
}

pub(super) fn add_public(
    shares: &Shares,
    value: &BigNumRef,
    modulus: &BigNumRef,
    ctx: &mut BigNumContextRef,
) -> Option<Shares> {
    let fresh = remask(shares, modulus, ctx)?;
    Some(Shares {
        masked: add_mod(&fresh.masked, value, modulus, ctx)?,
        mask: fresh.mask,
    })
}

pub(super) fn residue_shares(
    bytes: &[u8],
    minus: u32,
    modulus: &BigNumRef,
    ctx: &mut BigNumContextRef,
) -> Option<Shares> {
    let width = bytes.len() * 8;
    let mut marked = Vec::with_capacity(bytes.len() + 1);
    marked.push(1u8);
    marked.extend_from_slice(bytes);
    let parsed = BigNum::from_slice(&marked);
    cleanse(&mut marked);
    let numerator = SecretBn::adopt(parsed.ok()?);
    let mut offset = SecretBn::new().ok()?;
    private_random_bits(&mut offset, i32::try_from(width + MASK_EXTRA_BITS).ok()?).ok()?;
    let mut blinded = SecretBn::new().ok()?;
    blinded.checked_add(&numerator, &offset).ok()?;
    drop(numerator);
    blinded.sub_word(minus).ok()?;
    let mut masked = SecretBn::new().ok()?;
    masked.nnmod(&blinded, modulus, ctx).ok()?;
    let marker = power_of_two(width)?;
    let mut mask_integer = SecretBn::new().ok()?;
    mask_integer.checked_add(&offset, &marker).ok()?;
    let mut mask = SecretBn::new().ok()?;
    mask.nnmod(&mask_integer, modulus, ctx).ok()?;
    Some(Shares { masked, mask })
}

pub(super) fn masked_invert(
    shares: &Shares,
    modulus: &BigNumRef,
    ctx: &mut BigNumContextRef,
) -> Outcome<Shares> {
    match masked_invert_inner(shares, modulus, ctx) {
        Some(Some(value)) => Outcome::Value(value),
        Some(None) => Outcome::Invalid,
        None => Outcome::Backend,
    }
}

fn masked_invert_inner(
    shares: &Shares,
    modulus: &BigNumRef,
    ctx: &mut BigNumContextRef,
) -> Option<Option<Shares>> {
    checkpoint(Boundary::MaskedInverse)?;
    let blind = loop {
        let candidate = nonzero_mask(modulus)?;
        let mut divisor = BigNum::new().ok()?;
        divisor.gcd(&candidate, modulus, ctx).ok()?;
        if divisor.num_bits() == 1 {
            break candidate;
        }
    };
    let masked_product = mul_mod(&shares.masked, &blind, modulus, ctx)?;
    let mask_product = mul_mod(&shares.mask, &blind, modulus, ctx)?;
    let blinded = sub_mod(&masked_product, &mask_product, modulus, ctx)?;
    drop((masked_product, mask_product));
    let mut divisor = BigNum::new().ok()?;
    divisor.gcd(&blinded, modulus, ctx).ok()?;
    if divisor.num_bits() != 1 {
        return Some(None);
    }
    let mut blinded_inverse = SecretBn::new().ok()?;
    blinded_inverse.mod_inverse(&blinded, modulus, ctx).ok()?;
    drop(blinded);
    let split = random_mask(modulus)?;
    let shifted_blind = add_mod(&blind, &split, modulus, ctx)?;
    drop(blind);
    let first = mul_mod(&blinded_inverse, &shifted_blind, modulus, ctx)?;
    let second = mul_mod(&blinded_inverse, &split, modulus, ctx)?;
    let output_mask = random_mask(modulus)?;
    let partial = add_mod(&output_mask, &first, modulus, ctx)?;
    let masked = sub_mod(&partial, &second, modulus, ctx)?;
    Some(Some(Shares {
        masked,
        mask: output_mask,
    }))
}

pub(super) fn hensel_inverse(
    odd: &Shares,
    bits: usize,
    modulus: &BigNumRef,
    ctx: &mut BigNumContextRef,
) -> Option<Shares> {
    checkpoint(Boundary::HenselInverse)?;
    let two = BigNum::from_u32(2).ok()?;
    let mut inverse = remask(odd, modulus, ctx)?;
    let mut precision = 3usize;
    while precision < bits {
        let product = masked_mul(odd, &inverse, modulus, ctx)?;
        let correction = add_public(&negate(&product, modulus, ctx)?, &two, modulus, ctx)?;
        inverse = masked_mul(&inverse, &correction, modulus, ctx)?;
        precision *= 2;
    }
    Some(inverse)
}

#[cfg(test)]
thread_local! {
    static OPERANDS: core::cell::RefCell<Vec<(&'static str, i32)>> =
        const { core::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
pub(super) fn record_operand(label: &'static str, value: &BigNumRef) {
    OPERANDS.with(|operands| operands.borrow_mut().push((label, value.num_bits())));
}

#[cfg(not(test))]
#[inline(always)]
fn record_operand(_label: &'static str, _value: &BigNumRef) {}

#[cfg(test)]
pub(super) fn take_operands() -> Vec<(&'static str, i32)> {
    OPERANDS.with(|operands| core::mem::take(&mut *operands.borrow_mut()))
}

pub(super) fn widen(
    shares: &Shares,
    small: &BigNumRef,
    wide: &BigNumRef,
    ctx: &mut BigNumContextRef,
) -> Option<Shares> {
    let mut fresh = SecretBn::new().ok()?;
    private_random_below(&mut fresh, wide).ok()?;
    widen_with(shares, small, wide, &fresh, ctx)
}

fn widen_with(
    shares: &Shares,
    small: &BigNumRef,
    wide: &BigNumRef,
    fresh: &BigNumRef,
    ctx: &mut BigNumContextRef,
) -> Option<Shares> {
    let width = modulus_bytes(small);
    let mut masked_bytes = exported_bytes(&shares.masked, width)?;
    let mut mask_bytes = exported_bytes(&shares.mask, width)?;
    let wrapped = bool::from(ct_less(&masked_bytes, &mask_bytes));
    cleanse(&mut masked_bytes);
    cleanse(&mut mask_bytes);
    record_operand("masked share", &shares.masked);
    record_operand("fresh mask", fresh);
    let mut chosen = add_mod(&shares.masked, fresh, wide, ctx)?;
    let mut shifted = SecretBn::new().ok()?;
    record_operand("public modulus", small);
    shifted.checked_add(&shares.masked, small).ok()?;
    record_operand("shifted share", &shifted);
    let mut other = add_mod(&shifted, fresh, wide, ctx)?;
    drop(shifted);
    record_operand("unshifted candidate", &chosen);
    record_operand("shifted candidate", &other);
    consttime_swap(wrapped, &mut chosen, &mut other, words_for(wide)).ok()?;
    drop(other);
    Some(Shares {
        masked: chosen,
        mask: add_mod(&shares.mask, fresh, wide, ctx)?,
    })
}

pub(super) fn high_bytes_zero(bytes: &[u8], kept: usize) -> bool {
    let high = bytes.len().saturating_sub(kept);
    bool::from(ct_is_zero(&bytes[..high]))
}

struct Unmasking {
    sum: SecretBn,
    reduced: SecretBn,
    width: usize,
}

fn unmasking_candidates(shares: &Shares, modulus: &BigNumRef) -> Option<(Unmasking, bool)> {
    let word_bits = usize::try_from(modulus.num_bits()).ok()?.div_ceil(64) * 64;
    let mut marker = BigNum::new().ok()?;
    marker.set_bit(i32::try_from(word_bits + 64).ok()?).ok()?;
    marker.set_bit(i32::try_from(word_bits).ok()?).ok()?;
    let mut offset = BigNum::new().ok()?;
    offset.checked_add(&marker, modulus).ok()?;
    let mut complement = SecretBn::new().ok()?;
    complement.checked_sub(&offset, &shares.mask).ok()?;
    let mut sum = SecretBn::new().ok()?;
    sum.checked_add(&complement, &shares.masked).ok()?;
    drop(complement);
    let mut reduced = SecretBn::new().ok()?;
    reduced.checked_sub(&sum, modulus).ok()?;
    let width = word_bits / 8;
    let mut masked = exported_bytes(&shares.masked, width)?;
    let mut mask = exported_bytes(&shares.mask, width)?;
    let wrapped = bool::from(ct_less(&masked, &mask));
    cleanse(&mut masked);
    cleanse(&mut mask);
    Some((
        Unmasking {
            sum,
            reduced,
            width,
        },
        wrapped,
    ))
}

pub(super) fn unmask_to_bytes(
    shares: &Shares,
    modulus: &BigNumRef,
    length: usize,
) -> Option<Vec<u8>> {
    checkpoint(Boundary::Unmask)?;
    if length < modulus_bytes(modulus) {
        return None;
    }
    let (mut candidates, wrapped) = unmasking_candidates(shares, modulus)?;
    let words = i32::try_from(candidates.width / 8 + 2).ok()?;
    consttime_swap(
        !wrapped,
        &mut candidates.sum,
        &mut candidates.reduced,
        words,
    )
    .ok()?;
    let total = candidates.width + 9;
    let mut encoded = exported_bytes(&candidates.sum, total)?;
    let kept = length.min(candidates.width);
    let mut value = vec![0u8; length - kept];
    value.extend_from_slice(&encoded[total - kept..]);
    cleanse(&mut encoded);
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::bn::BigNumContext;

    fn modulus(hex: &str) -> BigNum {
        BigNum::from_hex_str(hex).unwrap()
    }

    fn shares_of(value: &[u8], modulus: &BigNumRef) -> Shares {
        let mut ctx = BigNumContext::new().unwrap();
        masked_import(value, modulus, &mut ctx).unwrap()
    }

    const P521_ORDER: &str = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";

    #[test]
    fn unmasking_never_builds_a_value_of_secret_width() {
        let n = modulus(P521_ORDER);
        let widths = |value: &[u8]| {
            let shares = shares_of(value, &n);
            let (candidates, _) = unmasking_candidates(&shares, &n).unwrap();
            (candidates.sum.num_bits(), candidates.reduced.num_bits())
        };
        let expected = widths(&[0u8]);
        assert_eq!(
            expected.0, expected.1,
            "both candidates share the marker width"
        );
        let mut top = n.to_vec();
        let last = top.len() - 1;
        top[last] -= 1;
        for value in [vec![0u8], vec![1u8], vec![0xffu8; 63], top] {
            for _ in 0..64 {
                assert_eq!(widths(&value), expected, "value {value:02x?}");
            }
        }
    }

    #[test]
    fn unmasking_recovers_every_value_and_wrap() {
        let n = modulus(P521_ORDER);
        let mut top = n.to_vec();
        let last = top.len() - 1;
        top[last] -= 1;
        for value in [vec![0u8], vec![1u8], vec![0x80u8; 40], top.clone()] {
            for length in [66usize, 72, 96] {
                let mut expected = vec![0u8; length - value.len()];
                expected.extend_from_slice(&value);
                for _ in 0..32 {
                    let shares = shares_of(&value, &n);
                    assert_eq!(unmask_to_bytes(&shares, &n, length), Some(expected.clone()));
                }
            }
            assert_eq!(unmask_to_bytes(&shares_of(&value, &n), &n, 65), None);
        }
    }

    fn previous_widen(
        shares: &Shares,
        small: &BigNumRef,
        wide: &BigNumRef,
        ctx: &mut BigNumContextRef,
    ) -> Option<Shares> {
        let width = modulus_bytes(small);
        let masked_bytes = exported_bytes(&shares.masked, width)?;
        let mask_bytes = exported_bytes(&shares.mask, width)?;
        let wrapped = bool::from(ct_less(&masked_bytes, &mask_bytes));
        let words = words_for(small) + 1;
        let mut correction = SecretBn::copy_of(small).ok()?;
        let mut nothing = SecretBn::new().ok()?;
        consttime_swap(!wrapped, &mut correction, &mut nothing, words).ok()?;
        let mut fresh = SecretBn::new().ok()?;
        private_random_below(&mut fresh, wide).ok()?;
        record_operand("correction", &correction);
        let mut lifted = SecretBn::new().ok()?;
        lifted.checked_add(&shares.masked, &correction).ok()?;
        Some(Shares {
            masked: add_mod(&lifted, &fresh, wide, ctx)?,
            mask: add_mod(&shares.mask, &fresh, wide, ctx)?,
        })
    }

    fn controlled_shares(residue: &BigNum, mask: &BigNum, modulus: &BigNumRef) -> Shares {
        let mut ctx = BigNumContext::new().unwrap();
        let mut masked = SecretBn::new().unwrap();
        masked.mod_add(residue, mask, modulus, &mut ctx).unwrap();
        Shares {
            masked,
            mask: SecretBn::copy_of(mask).unwrap(),
        }
    }

    #[test]
    fn widening_selects_the_right_candidate_for_controlled_masks() {
        let mut ctx = BigNumContext::new().unwrap();
        let wide = power_of_two(1728).unwrap();
        let below = |offset: u32| {
            let mut value = wide.to_owned().unwrap();
            value.sub_word(offset).unwrap();
            value
        };
        let word = |bits: i32| {
            let mut value = BigNum::new().unwrap();
            value.set_bit(bits).unwrap();
            value
        };
        let fresh_values = [
            BigNum::new().unwrap(),
            BigNum::from_u32(1).unwrap(),
            &word(64) - &BigNum::from_u32(1).unwrap(),
            word(64),
            &word(128) - &BigNum::from_u32(1).unwrap(),
            word(1727),
            below(65537),
            below(1),
        ];
        let mut outcomes = [0u32; 2];
        for small_value in [3u32, 65537] {
            let small = BigNum::from_u32(small_value).unwrap();
            let residues = [0, 1, small_value / 2, small_value - 1];
            for residue_value in residues {
                let residue = BigNum::from_u32(residue_value).unwrap();
                let masks = [
                    0,
                    1,
                    small_value / 2,
                    small_value - 1,
                    small_value - residue_value.max(1),
                ];
                for mask_value in masks {
                    let mask = BigNum::from_u32(mask_value % small_value).unwrap();
                    let shares = controlled_shares(&residue, &mask, &small);
                    let wrapped = shares.masked.ucmp(&shares.mask).is_lt();
                    assert_eq!(
                        wrapped,
                        residue_value + mask_value % small_value >= small_value
                    );
                    outcomes[usize::from(wrapped)] += 1;
                    for fresh in &fresh_values {
                        take_operands();
                        let lifted = widen_with(&shares, &small, &wide, fresh, &mut ctx).unwrap();
                        let operands = take_operands();
                        let mut expected_masked = BigNum::new().unwrap();
                        let lift = if wrapped {
                            &shares.masked as &BigNumRef
                        } else {
                            &shares.masked
                        };
                        let mut shifted = lift.to_owned().unwrap();
                        if wrapped {
                            shifted.add_word(small_value).unwrap();
                        }
                        expected_masked
                            .mod_add(&shifted, fresh, &wide, &mut ctx)
                            .unwrap();
                        assert_eq!(
                            *lifted.masked, *expected_masked,
                            "candidate for wrap {wrapped}"
                        );
                        let value = unmask_to_bytes(&lifted, &wide, modulus_bytes(&wide)).unwrap();
                        assert_eq!(
                            BigNum::from_slice(&value).unwrap(),
                            residue,
                            "r {residue_value} m {mask_value} e {small_value}"
                        );
                        let widths: Vec<(&str, i32)> = operands.clone();
                        let shifted_share = &*shares.masked + &*small;
                        assert_eq!(
                            widths,
                            vec![
                                ("masked share", shares.masked.num_bits()),
                                ("fresh mask", fresh.num_bits()),
                                ("public modulus", small.num_bits()),
                                ("shifted share", shifted_share.num_bits()),
                                ("unshifted candidate", {
                                    let mut value = BigNum::new().unwrap();
                                    value
                                        .mod_add(&shares.masked, fresh, &wide, &mut ctx)
                                        .unwrap();
                                    value.num_bits()
                                }),
                                ("shifted candidate", {
                                    let mut value = BigNum::new().unwrap();
                                    value
                                        .mod_add(&shifted_share, fresh, &wide, &mut ctx)
                                        .unwrap();
                                    value.num_bits()
                                }),
                            ],
                            "every operand is a share, a fresh mask, the public modulus, or both candidates, computed whatever the wrap"
                        );
                    }
                    take_operands();
                    previous_widen(&shares, &small, &wide, &mut ctx).unwrap();
                    assert_eq!(
                        take_operands(),
                        vec![("correction", if wrapped { small.num_bits() } else { 0 })],
                        "positive control: the previous correction is the wrap bit"
                    );
                }
            }
        }
        assert!(
            outcomes[0] > 0 && outcomes[1] > 0,
            "both wrap outcomes: {outcomes:?}"
        );
    }

    #[test]
    #[ignore = "diagnostic only: random sampling, not a pass/fail regression"]
    fn widening_operand_widths_by_residue_diagnostic() {
        let mut ctx = BigNumContext::new().unwrap();
        let e = BigNum::from_u32(65537).unwrap();
        let wide = power_of_two(1728).unwrap();
        for residue in [1u32, 16384, 32768, 49152, 65535] {
            let mut totals: std::collections::BTreeMap<&str, f64> = Default::default();
            for _ in 0..256 {
                let shares = masked_import(&residue.to_be_bytes(), &e, &mut ctx).unwrap();
                take_operands();
                widen(&shares, &e, &wide, &mut ctx).unwrap();
                for (label, bits) in take_operands() {
                    *totals.entry(label).or_default() += f64::from(bits) / 256.0;
                }
            }
            eprintln!("residue {residue}: mean operand widths {totals:?}");
        }
    }

    #[test]
    fn masked_product_equality_is_exact() {
        let modulus = {
            let mut value = BigNum::new().unwrap();
            value.set_bit(256).unwrap();
            value
        };
        let mut ctx = BigNumContext::new().unwrap();
        let left = shares_of(&[0x12, 0x34, 0x56], &modulus);
        let right = shares_of(&[0x07, 0x89], &modulus);
        let product = masked_mul(&left, &right, &modulus, &mut ctx).unwrap();
        let expected = BigNum::from_u32(0x0012_3456 * 0x0789).unwrap();
        assert_eq!(
            equals_public(&product, &expected, &modulus, &mut ctx),
            Some(true)
        );
        let other = BigNum::from_u32(0x0012_3456 * 0x0789 + 1).unwrap();
        assert_eq!(
            equals_public(&product, &other, &modulus, &mut ctx),
            Some(false)
        );
    }
}
