// Part of the Rust port of libtpms.
//
// Project licensing and upstream notices: LICENSE and LICENSES/README.md.
//
// Rust implementation:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use core::cmp::Ordering;

#[cfg(test)]
use openssl::bn::{BigNum, BigNumContext};

use super::secret::SecretBn;

const WORD_BITS: usize = 64;

pub(in crate::library::tpm2) struct BigUint(SecretBn);

impl core::fmt::Debug for BigUint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BigUint({} bits)", self.bit_len())
    }
}

impl BigUint {
    pub(in crate::library::tpm2) fn zero() -> Option<Self> {
        SecretBn::new().ok().map(Self)
    }

    pub(in crate::library::tpm2) fn from_u64(value: u64) -> Option<Self> {
        Self::from_be_bytes(&value.to_be_bytes())
    }

    pub(in crate::library::tpm2) fn from_be_bytes(bytes: &[u8]) -> Option<Self> {
        SecretBn::from_be(bytes).ok().map(Self)
    }

    #[cfg(test)]
    #[cfg(test)]
    pub(in crate::library::tpm2) fn from_hex(hex: &str) -> Option<Self> {
        Some(Self(SecretBn::adopt(BigNum::from_hex_str(hex).ok()?)))
    }

    #[cfg(test)]
    pub(in crate::library::tpm2) fn duplicate(&self) -> Option<Self> {
        self.0.duplicate().ok().map(Self)
    }

    pub(in crate::library::tpm2) fn to_be_bytes(&self, length: usize) -> Option<Vec<u8>> {
        self.0.to_be(length).ok()
    }

    pub(in crate::library::tpm2) fn is_zero(&self) -> bool {
        self.0.num_bits() == 0
    }

    pub(in crate::library::tpm2) fn is_odd(&self) -> bool {
        self.0.is_odd()
    }

    pub(in crate::library::tpm2) fn bit_len(&self) -> usize {
        usize::try_from(self.0.num_bits()).unwrap_or(0)
    }

    pub(in crate::library::tpm2) fn byte_len(&self) -> usize {
        self.bit_len().div_ceil(8)
    }

    pub(in crate::library::tpm2) fn test_bit(&self, bit: usize) -> bool {
        i32::try_from(bit).is_ok_and(|bit| self.0.is_bit_set(bit))
    }

    fn word(&self, index: usize) -> u64 {
        let bytes = self.0.to_vec();
        let mut word = [0u8; 8];
        for (offset, byte) in word.iter_mut().rev().enumerate() {
            let position = index * 8 + offset;
            if position < bytes.len() {
                *byte = bytes[bytes.len() - 1 - position];
            }
        }
        u64::from_be_bytes(word)
    }

    fn top_word_index(&self) -> Option<usize> {
        self.bit_len().checked_sub(1).map(|bit| bit / WORD_BITS)
    }

    pub(in crate::library::tpm2) fn low_u64(&self) -> u64 {
        self.word(0)
    }

    pub(in crate::library::tpm2) fn low_u32(&self) -> u32 {
        self.low_u64() as u32
    }

    pub(in crate::library::tpm2) fn high_u32(&self) -> u32 {
        self.top_word_index()
            .map_or(0, |index| (self.word(index) >> 32) as u32)
    }

    pub(in crate::library::tpm2) fn replace_high_u32(&mut self, value: u32) -> Option<()> {
        let index = self.top_word_index().unwrap_or(0);
        let old = self.word(index);
        let new = (old & 0xffff_ffff) | (u64::from(value) << 32);
        let old_word = Self::from_u64(old)?.shl(index * WORD_BITS)?;
        let new_word = Self::from_u64(new)?.shl(index * WORD_BITS)?;
        *self = self.sub(&old_word)?.add(&new_word)?;
        Some(())
    }

    pub(in crate::library::tpm2) fn set_low_bit(&mut self) -> Option<()> {
        self.0.set_bit(0).ok()
    }

    pub(in crate::library::tpm2) fn mask_bits(&mut self, bits: usize) -> Option<()> {
        if bits >= self.bit_len() {
            return Some(());
        }
        self.0.mask_bits(i32::try_from(bits).ok()?).ok()
    }

    pub(in crate::library::tpm2) fn add(&self, other: &Self) -> Option<Self> {
        let mut sum = SecretBn::new().ok()?;
        sum.checked_add(&self.0, &other.0).ok()?;
        Some(Self(sum))
    }

    pub(in crate::library::tpm2) fn add_u64(&self, value: u64) -> Option<Self> {
        self.add(&Self::from_u64(value)?)
    }

    pub(in crate::library::tpm2) fn sub(&self, other: &Self) -> Option<Self> {
        if *self < *other {
            return None;
        }
        let mut difference = SecretBn::new().ok()?;
        difference.checked_sub(&self.0, &other.0).ok()?;
        Some(Self(difference))
    }

    pub(in crate::library::tpm2) fn sub_u64(&self, value: u64) -> Option<Self> {
        self.sub(&Self::from_u64(value)?)
    }

    pub(in crate::library::tpm2) fn shr(&self, bits: usize) -> Option<Self> {
        let mut shifted = SecretBn::new().ok()?;
        shifted.rshift(&self.0, i32::try_from(bits).ok()?).ok()?;
        Some(Self(shifted))
    }

    pub(in crate::library::tpm2) fn shl(&self, bits: usize) -> Option<Self> {
        let mut shifted = SecretBn::new().ok()?;
        shifted.lshift(&self.0, i32::try_from(bits).ok()?).ok()?;
        Some(Self(shifted))
    }

    #[cfg(test)]
    pub(in crate::library::tpm2) fn mul(&self, other: &Self) -> Option<Self> {
        let mut ctx = BigNumContext::new().ok()?;
        let mut product = SecretBn::new().ok()?;
        product.checked_mul(&self.0, &other.0, &mut ctx).ok()?;
        Some(Self(product))
    }

    pub(in crate::library::tpm2) fn mod_u32(&self, modulus: u32) -> Option<u32> {
        if modulus == 0 {
            return None;
        }
        u32::try_from(self.0.mod_word(modulus).ok()?).ok()
    }

    #[cfg(test)]
    pub(in crate::library::tpm2) fn div_rem(&self, divisor: &Self) -> Option<(Self, Self)> {
        if divisor.is_zero() {
            return None;
        }
        let mut ctx = BigNumContext::new().ok()?;
        let mut quotient = SecretBn::new().ok()?;
        let mut remainder = SecretBn::new().ok()?;
        quotient
            .div_rem(&mut remainder, &self.0, &divisor.0, &mut ctx)
            .ok()?;
        Some((Self(quotient), Self(remainder)))
    }

    #[cfg(test)]
    pub(in crate::library::tpm2) fn rem(&self, modulus: &Self) -> Option<Self> {
        self.div_rem(modulus).map(|(_, remainder)| remainder)
    }

    #[cfg(test)]
    pub(in crate::library::tpm2) fn mod_mul(&self, other: &Self, modulus: &Self) -> Option<Self> {
        if modulus.is_zero() {
            return None;
        }
        let mut ctx = BigNumContext::new().ok()?;
        let mut product = SecretBn::new().ok()?;
        product
            .mod_mul(&self.0, &other.0, &modulus.0, &mut ctx)
            .ok()?;
        Some(Self(product))
    }

    #[cfg(test)]
    pub(in crate::library::tpm2) fn mod_add(&self, other: &Self, modulus: &Self) -> Option<Self> {
        if modulus.is_zero() {
            return None;
        }
        let mut ctx = BigNumContext::new().ok()?;
        let mut sum = SecretBn::new().ok()?;
        sum.mod_add(&self.0, &other.0, &modulus.0, &mut ctx).ok()?;
        Some(Self(sum))
    }

    #[cfg(test)]
    pub(in crate::library::tpm2) fn mod_sub(&self, other: &Self, modulus: &Self) -> Option<Self> {
        if modulus.is_zero() {
            return None;
        }
        let mut ctx = BigNumContext::new().ok()?;
        let mut difference = SecretBn::new().ok()?;
        difference
            .mod_sub(&self.0, &other.0, &modulus.0, &mut ctx)
            .ok()?;
        Some(Self(difference))
    }

    #[cfg(test)]
    pub(in crate::library::tpm2) fn mod_exp(
        &self,
        exponent: &Self,
        modulus: &Self,
    ) -> Option<Self> {
        if modulus.is_zero() {
            return None;
        }
        let mut ctx = BigNumContext::new().ok()?;
        let mut power = SecretBn::new().ok()?;
        let public_exponent: BigNum = exponent.0.to_owned().ok()?;
        power
            .mod_exp(&self.0, &public_exponent, &modulus.0, &mut ctx)
            .ok()?;
        Some(Self(power))
    }

    #[cfg(test)]
    pub(in crate::library::tpm2) fn mod_inverse(&self, modulus: &Self) -> Option<Self> {
        if modulus.is_zero() {
            return None;
        }
        let mut ctx = BigNumContext::new().ok()?;
        let mut inverse = SecretBn::new().ok()?;
        inverse.mod_inverse(&self.0, &modulus.0, &mut ctx).ok()?;
        Some(Self(inverse))
    }
}

impl PartialEq for BigUint {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for BigUint {}

impl Ord for BigUint {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.ucmp(&other.0)
    }
}

impl PartialOrd for BigUint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
impl Clone for BigUint {
    fn clone(&self) -> Self {
        self.duplicate().expect("a test value duplicates")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn big(value: u128) -> BigUint {
        BigUint::from_be_bytes(&value.to_be_bytes()).unwrap()
    }

    #[test]
    fn leading_zero_encodings_parse_to_one_value() {
        assert!(BigUint::from_be_bytes(&[]).unwrap().is_zero());
        assert_eq!(
            BigUint::from_be_bytes(&[0, 0, 0, 1, 2]).unwrap(),
            BigUint::from_be_bytes(&[1, 2]).unwrap()
        );
        assert_eq!(
            BigUint::from_be_bytes(&[0x80, 0, 0, 0, 0, 0, 0, 0, 0])
                .unwrap()
                .bit_len(),
            72
        );
        assert_eq!(
            big(0x0102).to_be_bytes(4).unwrap(),
            [0, 0, 1, 2],
            "the fixed-width encoding pads on the left"
        );
        assert!(big(0x010203).to_be_bytes(2).is_none());
    }

    #[test]
    fn top_word_quirks_match_the_normalised_limb_view() {
        let mut value = big((0x1234_5678_9abc_def0u128 << 64) | 0x0fed_cba9_8765_4321);
        assert_eq!(value.high_u32(), 0x1234_5678);
        assert_eq!(value.low_u32(), 0x8765_4321);
        value.replace_high_u32(0xb505_0000).unwrap();
        assert_eq!(
            value,
            big((0xb505_0000_9abc_def0u128 << 64) | 0x0fed_cba9_8765_4321)
        );
        let mut short = big(0x0000_0001_0000_0002);
        assert_eq!(
            short.high_u32(),
            1,
            "the top word is the highest nonzero word"
        );
        short.replace_high_u32(0).unwrap();
        assert_eq!(short, big(2));
        let mut empty = BigUint::zero().unwrap();
        assert_eq!(empty.high_u32(), 0);
        empty.replace_high_u32(7).unwrap();
        assert_eq!(empty, big(7u128 << 32));
    }

    #[test]
    fn mask_bits_keeps_the_low_bits_only() {
        let mut value = big(0xffff_ffff_ffff_ffff_ffff);
        value.mask_bits(68).unwrap();
        assert_eq!(value, big(0xf_ffff_ffff_ffff_ffff));
        value.mask_bits(200).unwrap();
        assert_eq!(value, big(0xf_ffff_ffff_ffff_ffff));
        value.mask_bits(0).unwrap();
        assert!(value.is_zero());
    }

    #[test]
    fn word_arithmetic_matches_native_integers() {
        let value = big(0x1_0000_0000_0000_0000_0000_0069);
        assert_eq!(
            value.mod_u32(105),
            Some((0x1_0000_0000_0000_0000_0000_0069u128 % 105) as u32)
        );
        assert_eq!(value.mod_u32(0), None);
        assert_eq!(
            value.sub_u64(0x6a),
            Some(big(0xffff_ffff_ffff_ffff_ffff_ffff))
        );
        assert_eq!(big(5).sub_u64(6), None);
        assert_eq!(
            value.add_u64(1),
            Some(big(0x1_0000_0000_0000_0000_0000_006a))
        );
        assert_eq!(value.shr(64), Some(big(0x1_0000_0000)));
        assert!(value.test_bit(96) && !value.test_bit(95));
        assert!(big(3) < big(0x1_0000_0000_0000_0000));
    }
}
