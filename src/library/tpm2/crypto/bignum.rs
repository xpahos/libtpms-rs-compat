const LIMB_BITS: usize = 64;
const LIMB_BYTES: usize = LIMB_BITS / 8;

#[derive(Clone, Default, Eq, PartialEq)]
pub(in crate::library::tpm2) struct BigUint {
    limbs: Vec<u64>,
}

impl core::fmt::Debug for BigUint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BigUint(bits={}", self.bit_len())?;
        if self.bit_len() <= 64 {
            write!(f, ", {}", self.low_u64())?;
        }
        write!(f, ")")
    }
}

impl BigUint {
    pub(in crate::library::tpm2) fn zero() -> Self {
        Self { limbs: Vec::new() }
    }

    pub(in crate::library::tpm2) fn from_u64(value: u64) -> Self {
        let mut result = Self { limbs: vec![value] };
        result.normalize();
        result
    }

    pub(in crate::library::tpm2) fn from_be_bytes(bytes: &[u8]) -> Self {
        let mut limbs = Vec::with_capacity(bytes.len().div_ceil(LIMB_BYTES));
        let mut remaining = bytes.len();
        while remaining > 0 {
            let take = remaining.min(LIMB_BYTES);
            let mut chunk = [0u8; LIMB_BYTES];
            chunk[LIMB_BYTES - take..].copy_from_slice(&bytes[remaining - take..remaining]);
            limbs.push(u64::from_be_bytes(chunk));
            remaining -= take;
        }
        let mut result = Self { limbs };
        result.normalize();
        result
    }

    pub(in crate::library::tpm2) fn to_be_bytes(&self, length: usize) -> Option<Vec<u8>> {
        if self.byte_len() > length {
            return None;
        }
        let mut out = vec![0u8; length];
        for (index, limb) in self.limbs.iter().enumerate() {
            let bytes = limb.to_be_bytes();
            for (offset, byte) in bytes.iter().rev().enumerate() {
                let position = index * LIMB_BYTES + offset;
                if position < length {
                    out[length - 1 - position] = *byte;
                }
            }
        }
        Some(out)
    }

    pub(in crate::library::tpm2) fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    pub(in crate::library::tpm2) fn is_odd(&self) -> bool {
        self.limbs.first().is_some_and(|limb| limb & 1 == 1)
    }

    pub(in crate::library::tpm2) fn low_u64(&self) -> u64 {
        self.limbs.first().copied().unwrap_or(0)
    }

    pub(in crate::library::tpm2) fn low_u32(&self) -> u32 {
        self.low_u64() as u32
    }

    pub(in crate::library::tpm2) fn bit_len(&self) -> usize {
        match self.limbs.last() {
            None => 0,
            Some(top) => self.limbs.len() * LIMB_BITS - top.leading_zeros() as usize,
        }
    }

    pub(in crate::library::tpm2) fn byte_len(&self) -> usize {
        self.bit_len().div_ceil(8)
    }

    pub(in crate::library::tpm2) fn test_bit(&self, bit: usize) -> bool {
        let limb = bit / LIMB_BITS;
        self.limbs
            .get(limb)
            .is_some_and(|value| (value >> (bit % LIMB_BITS)) & 1 == 1)
    }

    pub(in crate::library::tpm2) fn set_low_bit(&mut self) {
        if self.limbs.is_empty() {
            self.limbs.push(1);
        } else {
            self.limbs[0] |= 1;
        }
    }

    pub(in crate::library::tpm2) fn mask_bits(&mut self, bits: usize) {
        let limbs = bits.div_ceil(LIMB_BITS);
        if self.limbs.len() > limbs {
            self.limbs.truncate(limbs);
        }
        let extra = limbs * LIMB_BITS - bits;
        if extra != 0
            && let Some(top) = self.limbs.last_mut()
        {
            *top &= u64::MAX >> extra;
        }
        self.normalize();
    }

    pub(in crate::library::tpm2) fn replace_high_u32(&mut self, value: u32) {
        if self.limbs.is_empty() {
            self.limbs.push(u64::from(value) << 32);
            self.normalize();
            return;
        }
        let last = self.limbs.len() - 1;
        self.limbs[last] = (self.limbs[last] & 0xffff_ffff) | (u64::from(value) << 32);
        self.normalize();
    }

    pub(in crate::library::tpm2) fn high_u32(&self) -> u32 {
        match self.limbs.last() {
            None => 0,
            Some(top) => (*top >> 32) as u32,
        }
    }

    pub(in crate::library::tpm2) fn limb_count(&self) -> usize {
        self.limbs.len()
    }

    fn normalize(&mut self) {
        while self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
    }

    pub(in crate::library::tpm2) fn add(&self, other: &Self) -> Self {
        let mut limbs = Vec::with_capacity(self.limbs.len().max(other.limbs.len()) + 1);
        let mut carry = 0u64;
        for index in 0..self.limbs.len().max(other.limbs.len()) {
            let left = self.limbs.get(index).copied().unwrap_or(0);
            let right = other.limbs.get(index).copied().unwrap_or(0);
            let (sum, first) = left.overflowing_add(right);
            let (sum, second) = sum.overflowing_add(carry);
            carry = u64::from(first) + u64::from(second);
            limbs.push(sum);
        }
        if carry != 0 {
            limbs.push(carry);
        }
        let mut result = Self { limbs };
        result.normalize();
        result
    }

    pub(in crate::library::tpm2) fn add_u64(&self, value: u64) -> Self {
        self.add(&Self::from_u64(value))
    }

    pub(in crate::library::tpm2) fn sub(&self, other: &Self) -> Option<Self> {
        if self < other {
            return None;
        }
        let mut limbs = Vec::with_capacity(self.limbs.len());
        let mut borrow = 0u64;
        for index in 0..self.limbs.len() {
            let left = self.limbs[index];
            let right = other.limbs.get(index).copied().unwrap_or(0);
            let (difference, first) = left.overflowing_sub(right);
            let (difference, second) = difference.overflowing_sub(borrow);
            borrow = u64::from(first) + u64::from(second);
            limbs.push(difference);
        }
        let mut result = Self { limbs };
        result.normalize();
        Some(result)
    }

    pub(in crate::library::tpm2) fn sub_u64(&self, value: u64) -> Option<Self> {
        self.sub(&Self::from_u64(value))
    }

    pub(in crate::library::tpm2) fn mul(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }
        let mut limbs = vec![0u64; self.limbs.len() + other.limbs.len()];
        for (i, &left) in self.limbs.iter().enumerate() {
            let mut carry = 0u128;
            for (j, &right) in other.limbs.iter().enumerate() {
                let value = u128::from(left) * u128::from(right) + u128::from(limbs[i + j]) + carry;
                limbs[i + j] = value as u64;
                carry = value >> LIMB_BITS;
            }
            let mut index = i + other.limbs.len();
            while carry != 0 {
                let value = u128::from(limbs[index]) + carry;
                limbs[index] = value as u64;
                carry = value >> LIMB_BITS;
                index += 1;
            }
        }
        let mut result = Self { limbs };
        result.normalize();
        result
    }

    pub(in crate::library::tpm2) fn shl(&self, bits: usize) -> Self {
        if self.is_zero() {
            return Self::zero();
        }
        let whole = bits / LIMB_BITS;
        let part = bits % LIMB_BITS;
        let mut limbs = vec![0u64; whole];
        if part == 0 {
            limbs.extend_from_slice(&self.limbs);
        } else {
            let mut carry = 0u64;
            for &limb in &self.limbs {
                limbs.push((limb << part) | carry);
                carry = limb >> (LIMB_BITS - part);
            }
            if carry != 0 {
                limbs.push(carry);
            }
        }
        let mut result = Self { limbs };
        result.normalize();
        result
    }

    pub(in crate::library::tpm2) fn shr(&self, bits: usize) -> Self {
        let whole = bits / LIMB_BITS;
        if whole >= self.limbs.len() {
            return Self::zero();
        }
        let part = bits % LIMB_BITS;
        let mut limbs = self.limbs[whole..].to_vec();
        if part != 0 {
            for index in 0..limbs.len() {
                let high = limbs.get(index + 1).copied().unwrap_or(0);
                limbs[index] = (limbs[index] >> part) | (high << (LIMB_BITS - part));
            }
        }
        let mut result = Self { limbs };
        result.normalize();
        result
    }

    pub(in crate::library::tpm2) fn mod_u64(&self, modulus: u64) -> u64 {
        debug_assert!(modulus != 0);
        let mut remainder = 0u128;
        for &limb in self.limbs.iter().rev() {
            remainder = ((remainder << LIMB_BITS) | u128::from(limb)) % u128::from(modulus);
        }
        remainder as u64
    }

    pub(in crate::library::tpm2) fn div_rem(&self, divisor: &Self) -> Option<(Self, Self)> {
        if divisor.is_zero() {
            return None;
        }
        if self < divisor {
            return Some((Self::zero(), self.clone()));
        }
        if divisor.limbs.len() == 1 {
            let (quotient, remainder) = self.div_rem_u64(divisor.limbs[0]);
            return Some((quotient, Self::from_u64(remainder)));
        }
        Some(self.div_rem_knuth(divisor))
    }

    fn div_rem_u64(&self, divisor: u64) -> (Self, u64) {
        let mut quotient = vec![0u64; self.limbs.len()];
        let mut remainder = 0u128;
        for index in (0..self.limbs.len()).rev() {
            let value = (remainder << LIMB_BITS) | u128::from(self.limbs[index]);
            quotient[index] = (value / u128::from(divisor)) as u64;
            remainder = value % u128::from(divisor);
        }
        let mut result = Self { limbs: quotient };
        result.normalize();
        (result, remainder as u64)
    }

    fn div_rem_knuth(&self, divisor: &Self) -> (Self, Self) {
        let shift = divisor
            .limbs
            .last()
            .expect("a non-zero divisor")
            .leading_zeros() as usize;
        let dividend = self.shl(shift);
        let divisor_shifted = divisor.shl(shift);
        let n = divisor_shifted.limbs.len();
        let mut u = dividend.limbs.clone();
        u.resize(self.limbs.len() + 1, 0);
        let m = u.len() - n - 1;
        let v = &divisor_shifted.limbs;
        let mut quotient = vec![0u64; m + 1];

        for j in (0..=m).rev() {
            let numerator = (u128::from(u[j + n]) << LIMB_BITS) | u128::from(u[j + n - 1]);
            let mut candidate = numerator / u128::from(v[n - 1]);
            let mut rhat = numerator % u128::from(v[n - 1]);
            while candidate >> LIMB_BITS != 0
                || (candidate * u128::from(v[n - 2])
                    > ((rhat << LIMB_BITS) | u128::from(u[j + n - 2])))
            {
                candidate -= 1;
                rhat += u128::from(v[n - 1]);
                if rhat >> LIMB_BITS != 0 {
                    break;
                }
            }

            let mut borrow = 0i128;
            let mut carry = 0u128;
            for index in 0..n {
                let product = candidate * u128::from(v[index]) + carry;
                carry = product >> LIMB_BITS;
                let difference = i128::from(u[j + index]) - i128::from(product as u64) - borrow;
                u[j + index] = difference as u64;
                borrow = i128::from(difference < 0);
            }
            let difference = i128::from(u[j + n]) - carry as i128 - borrow;
            u[j + n] = difference as u64;

            if difference < 0 {
                candidate -= 1;
                let mut carry = 0u64;
                for index in 0..n {
                    let (sum, first) = u[j + index].overflowing_add(v[index]);
                    let (sum, second) = sum.overflowing_add(carry);
                    u[j + index] = sum;
                    carry = u64::from(first) + u64::from(second);
                }
                u[j + n] = u[j + n].wrapping_add(carry);
            }
            quotient[j] = candidate as u64;
        }

        let mut quotient = Self { limbs: quotient };
        quotient.normalize();
        let mut remainder = Self {
            limbs: u[..n].to_vec(),
        };
        remainder.normalize();
        (quotient, remainder.shr(shift))
    }

    pub(in crate::library::tpm2) fn rem(&self, modulus: &Self) -> Option<Self> {
        self.div_rem(modulus).map(|(_, remainder)| remainder)
    }

    pub(in crate::library::tpm2) fn mod_mul(&self, other: &Self, modulus: &Self) -> Option<Self> {
        self.mul(other).rem(modulus)
    }

    pub(in crate::library::tpm2) fn mod_add(&self, other: &Self, modulus: &Self) -> Option<Self> {
        self.add(other).rem(modulus)
    }

    pub(in crate::library::tpm2) fn mod_sub(&self, other: &Self, modulus: &Self) -> Option<Self> {
        let left = self.rem(modulus)?;
        let right = other.rem(modulus)?;
        match left.sub(&right) {
            Some(difference) => Some(difference),
            None => left.add(modulus).sub(&right),
        }
    }

    pub(in crate::library::tpm2) fn mod_exp(
        &self,
        exponent: &Self,
        modulus: &Self,
    ) -> Option<Self> {
        if modulus.is_zero() {
            return None;
        }
        if modulus.limbs.len() == 1 && modulus.limbs[0] == 1 {
            return Some(Self::zero());
        }
        if exponent.is_zero() {
            return Some(Self::from_u64(1));
        }
        if modulus.is_odd() {
            Montgomery::new(modulus)?.exp(&self.rem(modulus)?, exponent)
        } else {
            let mut result = Self::from_u64(1);
            let base = self.rem(modulus)?;
            for bit in (0..exponent.bit_len()).rev() {
                result = result.mod_mul(&result, modulus)?;
                if exponent.test_bit(bit) {
                    result = result.mod_mul(&base, modulus)?;
                }
            }
            Some(result)
        }
    }

    pub(in crate::library::tpm2) fn mod_inverse(&self, modulus: &Self) -> Option<Self> {
        if modulus.is_zero() || modulus == &Self::from_u64(1) {
            return None;
        }
        let mut old_r = self.rem(modulus)?;
        let mut r = modulus.clone();
        if old_r.is_zero() {
            return None;
        }
        let mut old_s = Self::from_u64(1);
        let mut s = Self::zero();
        let mut old_s_negative = false;
        let mut s_negative = false;

        while !r.is_zero() {
            let (quotient, remainder) = old_r.div_rem(&r)?;
            old_r = core::mem::replace(&mut r, remainder);

            let product = quotient.mul(&s);
            let (next, next_negative) = if old_s_negative == s_negative {
                match old_s.sub(&product) {
                    Some(value) => (value, old_s_negative),
                    None => (product.sub(&old_s)?, !old_s_negative),
                }
            } else {
                (old_s.add(&product), old_s_negative)
            };
            old_s = core::mem::replace(&mut s, next);
            old_s_negative = core::mem::replace(&mut s_negative, next_negative);
        }

        if old_r != Self::from_u64(1) {
            return None;
        }
        let reduced = old_s.rem(modulus)?;
        if old_s_negative && !reduced.is_zero() {
            modulus.sub(&reduced)
        } else {
            Some(reduced)
        }
    }
}

impl Ord for BigUint {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.limbs
            .len()
            .cmp(&other.limbs.len())
            .then_with(|| self.limbs.iter().rev().cmp(other.limbs.iter().rev()))
    }
}

impl PartialOrd for BigUint {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

struct Montgomery {
    modulus_limbs: Vec<u64>,
    n0inv: u64,
    limbs: usize,
    r_squared: Vec<u64>,
}

fn inverse_mod_2_64(value: u64) -> u64 {
    let mut inverse = 1u64;
    for _ in 0..6 {
        inverse = inverse.wrapping_mul(2u64.wrapping_sub(value.wrapping_mul(inverse)));
    }
    inverse
}

fn padded_limbs(value: &BigUint, count: usize) -> Option<Vec<u64>> {
    if value.limbs.len() > count {
        return None;
    }
    let mut limbs = value.limbs.clone();
    limbs.resize(count, 0);
    Some(limbs)
}

fn limbs_are_below(value: &[u64], bound: &[u64]) -> bool {
    value.iter().rev().cmp(bound.iter().rev()) == core::cmp::Ordering::Less
}

fn subtract_limbs_in_place(target: &mut [u64], value: &[u64]) {
    let mut borrow = 0u64;
    for index in 0..target.len() {
        let right = value.get(index).copied().unwrap_or(0);
        let (difference, first) = target[index].overflowing_sub(right);
        let (difference, second) = difference.overflowing_sub(borrow);
        borrow = u64::from(first) + u64::from(second);
        target[index] = difference;
    }
}

fn window_width(exponent_bits: usize) -> usize {
    match exponent_bits {
        0..64 => 1,
        64..256 => 3,
        256..1024 => 4,
        _ => 5,
    }
}

impl Montgomery {
    fn new(modulus: &BigUint) -> Option<Self> {
        if !modulus.is_odd() {
            return None;
        }
        let limbs = modulus.limb_count();
        let n0inv = inverse_mod_2_64(modulus.low_u64()).wrapping_neg();
        let r_squared = BigUint::from_u64(1)
            .shl(2 * limbs * LIMB_BITS)
            .rem(modulus)?;
        Some(Self {
            modulus_limbs: padded_limbs(modulus, limbs)?,
            n0inv,
            limbs,
            r_squared: padded_limbs(&r_squared, limbs)?,
        })
    }

    fn multiply(&self, left: &[u64], right: &[u64], product: &mut [u64], accumulator: &mut [u64]) {
        #[cfg(test)]
        super::work::count_modular_multiplication();
        let n = self.limbs;
        let modulus = &self.modulus_limbs;
        accumulator[..=n].fill(0);
        for index in 0..n {
            let multiplier = right[index];
            let opening = u128::from(accumulator[0]) + u128::from(left[0]) * u128::from(multiplier);
            let mut carry = opening >> LIMB_BITS;
            let low = opening as u64;
            let factor = low.wrapping_mul(self.n0inv);
            let mut reduction =
                (u128::from(low) + u128::from(factor) * u128::from(modulus[0])) >> LIMB_BITS;
            for position in 1..n {
                let value = u128::from(accumulator[position])
                    + u128::from(left[position]) * u128::from(multiplier)
                    + carry;
                carry = value >> LIMB_BITS;
                let reduced = u128::from(value as u64)
                    + u128::from(factor) * u128::from(modulus[position])
                    + reduction;
                reduction = reduced >> LIMB_BITS;
                accumulator[position - 1] = reduced as u64;
            }
            let tail = u128::from(accumulator[n]) + carry + reduction;
            accumulator[n - 1] = tail as u64;
            accumulator[n] = (tail >> LIMB_BITS) as u64;
        }
        if accumulator[n] != 0 || !limbs_are_below(&accumulator[..n], modulus) {
            subtract_limbs_in_place(&mut accumulator[..=n], modulus);
        }
        product.copy_from_slice(&accumulator[..n]);
    }

    fn exp(&self, base: &BigUint, exponent: &BigUint) -> Option<BigUint> {
        let n = self.limbs;
        let mut accumulator = vec![0u64; n + 1];
        let mut unit = vec![0u64; n];
        unit[0] = 1;

        let width = window_width(exponent.bit_len());
        let mut table: Vec<Vec<u64>> = Vec::with_capacity(1usize << width);
        let mut residue = vec![0u64; n];
        self.multiply(&unit, &self.r_squared, &mut residue, &mut accumulator);
        table.push(residue);
        let mut montgomery_base = vec![0u64; n];
        self.multiply(
            &padded_limbs(base, n)?,
            &self.r_squared,
            &mut montgomery_base,
            &mut accumulator,
        );
        table.push(montgomery_base.clone());
        for index in 2..(1usize << width) {
            let mut entry = vec![0u64; n];
            self.multiply(
                &table[index - 1],
                &montgomery_base,
                &mut entry,
                &mut accumulator,
            );
            table.push(entry);
        }

        let mut result = table[0].clone();
        let mut scratch = vec![0u64; n];
        let mut remaining = exponent.bit_len();
        let mut started = false;
        while remaining > 0 {
            let take = width.min(remaining);
            let mut digit = 0usize;
            for offset in 0..take {
                digit = (digit << 1) | usize::from(exponent.test_bit(remaining - 1 - offset));
            }
            if started {
                for _ in 0..take {
                    self.multiply(&result, &result, &mut scratch, &mut accumulator);
                    result.copy_from_slice(&scratch);
                }
                if digit != 0 {
                    self.multiply(&result, &table[digit], &mut scratch, &mut accumulator);
                    result.copy_from_slice(&scratch);
                }
            } else {
                result.copy_from_slice(&table[digit]);
                started = true;
            }
            remaining -= take;
        }

        self.multiply(&result, &unit, &mut scratch, &mut accumulator);
        let mut value = BigUint { limbs: scratch };
        value.normalize();
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn big(value: u128) -> BigUint {
        let mut bytes = value.to_be_bytes().to_vec();
        while bytes.first() == Some(&0) && bytes.len() > 1 {
            bytes.remove(0);
        }
        BigUint::from_be_bytes(&bytes)
    }

    fn to_u128(value: &BigUint) -> u128 {
        let bytes = value.to_be_bytes(16).expect("a value below 2^128");
        u128::from_be_bytes(bytes.try_into().expect("sixteen bytes"))
    }

    #[test]
    fn empty_encoding_zero_bytes_equivalence() {
        assert!(BigUint::from_be_bytes(&[]).is_zero());
        assert!(BigUint::from_be_bytes(&[0; 32]).is_zero());
        assert_eq!(BigUint::zero().bit_len(), 0);
        assert_eq!(BigUint::zero().byte_len(), 0);
        assert_eq!(BigUint::zero().low_u64(), 0);
        assert!(!BigUint::zero().is_odd());
    }

    #[test]
    fn big_endian_round_trip_leading_zero_preservation() {
        let value = BigUint::from_be_bytes(&[0x01, 0x23, 0x45, 0x67, 0x89]);
        assert_eq!(
            value.to_be_bytes(5).unwrap(),
            [0x01, 0x23, 0x45, 0x67, 0x89]
        );
        assert_eq!(
            value.to_be_bytes(8).unwrap(),
            [0x00, 0x00, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89]
        );
        assert_eq!(value.to_be_bytes(4), None, "the value does not fit");
    }

    #[test]
    fn multi_limb_big_endian_round_trip() {
        let bytes: Vec<u8> = (1..=48u8).collect();
        let value = BigUint::from_be_bytes(&bytes);
        assert_eq!(value.bit_len(), 8 * 48 - 7);
        assert_eq!(value.to_be_bytes(48).unwrap(), bytes);
    }

    #[test]
    fn bit_length_highest_set_bit_position() {
        for bits in 1..200usize {
            let value = BigUint::from_u64(1).shl(bits - 1);
            assert_eq!(value.bit_len(), bits, "bit {bits}");
            assert!(value.test_bit(bits - 1));
            assert!(!value.test_bit(bits));
        }
    }

    #[test]
    fn add_sub_native_arithmetic_match() {
        let cases = [
            (0u128, 0u128),
            (1, 0),
            (0, 1),
            (u64::MAX as u128, 1),
            (u64::MAX as u128, u64::MAX as u128),
            (0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210),
            (u128::MAX >> 1, u128::MAX >> 2),
        ];
        for (left, right) in cases {
            assert_eq!(to_u128(&big(left).add(&big(right))), left + right);
            if left >= right {
                assert_eq!(to_u128(&big(left).sub(&big(right)).unwrap()), left - right);
            } else {
                assert_eq!(big(left).sub(&big(right)), None);
            }
        }
    }

    #[test]
    fn underflow_subtraction_no_result() {
        assert_eq!(BigUint::zero().sub(&BigUint::from_u64(1)), None);
        assert_eq!(BigUint::from_u64(5).sub_u64(6), None);
        assert_eq!(BigUint::from_u64(5).sub_u64(5).unwrap(), BigUint::zero());
    }

    #[test]
    fn multiplication_native_arithmetic_match() {
        for (left, right) in [
            (0u128, 12345u128),
            (1, 1),
            (u64::MAX as u128, u64::MAX as u128),
            (0xdead_beef, 0xfeed_face),
            (u32::MAX as u128, u32::MAX as u128),
        ] {
            assert_eq!(to_u128(&big(left).mul(&big(right))), left * right);
        }
    }

    #[test]
    fn shift_left_right_identity() {
        let value = BigUint::from_be_bytes(&(1..=40u8).collect::<Vec<u8>>());
        for bits in [0usize, 1, 7, 63, 64, 65, 130, 320] {
            assert_eq!(value.shl(bits).shr(bits), value, "shift {bits}");
        }
    }

    #[test]
    fn right_shift_overshoot_zero_result() {
        let value = BigUint::from_u64(0xffff_ffff_ffff_ffff);
        assert!(value.shr(64).is_zero());
        assert!(value.shr(1000).is_zero());
        assert!(BigUint::zero().shl(1000).is_zero());
    }

    #[test]
    fn division_single_limb_divisor_native_match() {
        for divisor in [1u64, 2, 3, 105, u32::MAX as u64, u64::MAX] {
            let dividend = big(0x1234_5678_9abc_def0_1234_5678_9abc_def0);
            let (quotient, remainder) = dividend.div_rem(&BigUint::from_u64(divisor)).unwrap();
            let native = 0x1234_5678_9abc_def0_1234_5678_9abc_def0u128;
            assert_eq!(to_u128(&quotient), native / u128::from(divisor));
            assert_eq!(to_u128(&remainder), native % u128::from(divisor));
        }
    }

    #[test]
    fn multi_limb_divisor_dividend_reconstruction() {
        let dividend = BigUint::from_be_bytes(&(1..=64u8).collect::<Vec<u8>>());
        for length in [9usize, 16, 17, 31, 32, 33, 63] {
            let divisor = BigUint::from_be_bytes(
                &(0..length)
                    .map(|index| 200u8.wrapping_add(index as u8))
                    .collect::<Vec<u8>>(),
            );
            let (quotient, remainder) = dividend.div_rem(&divisor).unwrap();
            assert!(remainder < divisor, "length {length}");
            assert_eq!(
                quotient.mul(&divisor).add(&remainder),
                dividend,
                "length {length}"
            );
        }
    }

    #[test]
    fn larger_divisor_dividend_preservation() {
        let dividend = BigUint::from_u64(7);
        let divisor = BigUint::from_be_bytes(&[1; 32]);
        let (quotient, remainder) = dividend.div_rem(&divisor).unwrap();
        assert!(quotient.is_zero());
        assert_eq!(remainder, dividend);
    }

    #[test]
    fn zero_divisor_no_result() {
        assert_eq!(BigUint::from_u64(5).div_rem(&BigUint::zero()), None);
        assert_eq!(BigUint::from_u64(5).rem(&BigUint::zero()), None);
    }

    #[test]
    fn word_remainder_full_division_match() {
        let value = BigUint::from_be_bytes(&(7..=70u8).collect::<Vec<u8>>());
        for modulus in [1u64, 2, 3, 5, 7, 105, 65537, u32::MAX as u64] {
            let expected = value.rem(&BigUint::from_u64(modulus)).unwrap().low_u64();
            assert_eq!(value.mod_u64(modulus), expected, "modulus {modulus}");
        }
    }

    #[test]
    fn mask_low_bits_selection() {
        let value = BigUint::from_be_bytes(&[0xff; 32]);
        for bits in [1usize, 7, 8, 63, 64, 65, 127, 128, 255, 256] {
            let mut masked = value.clone();
            masked.mask_bits(bits);
            assert_eq!(masked.bit_len(), bits, "bits {bits}");
            for bit in 0..bits {
                assert!(masked.test_bit(bit));
            }
            assert!(!masked.test_bit(bits));
        }
        let mut zeroed = value.clone();
        zeroed.mask_bits(0);
        assert!(zeroed.is_zero());
    }

    #[test]
    fn oversized_mask_value_unchanged() {
        let value = BigUint::from_u64(0x1234);
        let mut masked = value.clone();
        masked.mask_bits(4096);
        assert_eq!(masked, value);
    }

    #[test]
    fn modular_exponentiation_odd_modulus_reference_match() {
        let modulus = BigUint::from_u64(0xffff_fffb);
        for (base, exponent) in [(2u64, 10u64), (3, 65537), (0xdead_beef, 0x1234_5678)] {
            let expected = {
                let mut accumulator = 1u128;
                let mut factor = u128::from(base) % 0xffff_fffb;
                let mut remaining = exponent;
                while remaining != 0 {
                    if remaining & 1 == 1 {
                        accumulator = accumulator * factor % 0xffff_fffb;
                    }
                    factor = factor * factor % 0xffff_fffb;
                    remaining >>= 1;
                }
                accumulator
            };
            let actual = BigUint::from_u64(base)
                .mod_exp(&BigUint::from_u64(exponent), &modulus)
                .unwrap();
            assert_eq!(to_u128(&actual), expected, "base {base} exp {exponent}");
        }
    }

    #[test]
    fn modular_exponentiation_even_modulus_support() {
        let modulus = BigUint::from_u64(1024);
        let actual = BigUint::from_u64(3)
            .mod_exp(&BigUint::from_u64(100), &modulus)
            .unwrap();
        let mut expected = 1u128;
        for _ in 0..100 {
            expected = expected * 3 % 1024;
        }
        assert_eq!(to_u128(&actual), expected);
    }

    fn mersenne_521() -> BigUint {
        BigUint::from_u64(1).shl(521).sub_u64(1).unwrap()
    }

    #[test]
    fn fermat_little_theorem_large_prime() {
        let prime = mersenne_521();
        assert_eq!(prime.bit_len(), 521);
        let exponent = prime.sub_u64(1).unwrap();
        for base in [2u64, 3, 5, 0x0123_4567_89ab_cdef] {
            let result = BigUint::from_u64(base).mod_exp(&exponent, &prime).unwrap();
            assert_eq!(result, BigUint::from_u64(1), "base {base}");
        }
    }

    fn montgomery_product(montgomery: &Montgomery, left: &BigUint, right: &BigUint) -> BigUint {
        let limbs = montgomery.limbs;
        let mut accumulator = vec![0u64; limbs + 1];
        let mut product = vec![0u64; limbs];
        montgomery.multiply(
            &padded_limbs(left, limbs).expect("a reduced factor"),
            &padded_limbs(right, limbs).expect("a reduced factor"),
            &mut product,
            &mut accumulator,
        );
        let mut value = BigUint { limbs: product };
        value.normalize();
        value
    }

    #[test]
    fn montgomery_multiplication_division_product_match() {
        let modulus = mersenne_521();
        let montgomery = Montgomery::new(&modulus).expect("an odd modulus");
        let left = BigUint::from_be_bytes(&(1..=65u8).collect::<Vec<u8>>())
            .rem(&modulus)
            .unwrap();
        let right = BigUint::from_be_bytes(&(60..=124u8).collect::<Vec<u8>>())
            .rem(&modulus)
            .unwrap();
        let radix = BigUint::from_u64(1).shl(montgomery.limbs * LIMB_BITS);
        let radix_inverse = radix.mod_inverse(&modulus).expect("a coprime radix");
        let expected = left
            .mod_mul(&right, &modulus)
            .unwrap()
            .mod_mul(&radix_inverse, &modulus)
            .unwrap();
        assert_eq!(montgomery_product(&montgomery, &left, &right), expected);
    }

    #[test]
    fn montgomery_kernel_product_reduction() {
        for length in [1usize, 2, 3, 8, 17, 24] {
            let modulus = BigUint::from_be_bytes(
                &(0..length * 8)
                    .map(|index| (index as u8).wrapping_mul(53) | 0x81)
                    .collect::<Vec<u8>>(),
            );
            let montgomery = Montgomery::new(&modulus).expect("an odd modulus");
            assert_eq!(montgomery.limbs, length);
            let radix = BigUint::from_u64(1).shl(length * LIMB_BITS);
            let radix_inverse = radix.mod_inverse(&modulus).expect("a coprime radix");
            for seed in 0..8u8 {
                let left = BigUint::from_be_bytes(
                    &(0..length * 8)
                        .map(|index| (index as u8).wrapping_mul(29).wrapping_add(seed))
                        .collect::<Vec<u8>>(),
                )
                .rem(&modulus)
                .unwrap();
                let right = BigUint::from_be_bytes(
                    &(0..length * 8)
                        .map(|index| (index as u8).wrapping_mul(97).wrapping_sub(seed))
                        .collect::<Vec<u8>>(),
                )
                .rem(&modulus)
                .unwrap();
                let expected = left
                    .mod_mul(&right, &modulus)
                    .unwrap()
                    .mod_mul(&radix_inverse, &modulus)
                    .unwrap();
                let product = montgomery_product(&montgomery, &left, &right);
                assert!(product < modulus, "length {length} seed {seed}");
                assert_eq!(product, expected, "length {length} seed {seed}");
                assert_eq!(
                    montgomery_product(&montgomery, &left, &left),
                    left.mod_mul(&left, &modulus)
                        .unwrap()
                        .mod_mul(&radix_inverse, &modulus)
                        .unwrap(),
                    "squaring, length {length} seed {seed}"
                );
            }
        }
    }

    #[test]
    fn prime_sized_exponentiation_sub_ladder_cost() {
        use crate::library::tpm2::crypto::work;
        let modulus = BigUint::from_be_bytes(
            &(0..192u16)
                .map(|index| (index as u8) | 0x81)
                .collect::<Vec<u8>>(),
        );
        assert_eq!(modulus.bit_len(), 1536);
        let exponent = modulus.sub_u64(4).unwrap();
        let set_bits: usize = (0..exponent.bit_len())
            .filter(|bit| exponent.test_bit(*bit))
            .count();
        let binary_ladder = 3 + (exponent.bit_len() - 1) + (set_bits - 1);
        let (result, counters) =
            work::measure(|| BigUint::from_u64(3).mod_exp(&exponent, &modulus).unwrap());
        assert!(!result.is_zero());
        assert_eq!(counters.modular_multiplications, 1868);
        assert!(
            counters.modular_multiplications + 400 < binary_ladder as u64,
            "{} multiplications against a {binary_ladder}-multiplication binary ladder",
            counters.modular_multiplications
        );
    }

    #[test]
    fn short_exponent_binary_ladder_cost() {
        use crate::library::tpm2::crypto::work;
        let modulus = BigUint::from_be_bytes(
            &(0..192u16)
                .map(|index| (index as u8) | 0x81)
                .collect::<Vec<u8>>(),
        );
        let (result, counters) = work::measure(|| {
            BigUint::from_u64(3)
                .mod_exp(&BigUint::from_u64(65537), &modulus)
                .unwrap()
        });
        assert!(!result.is_zero());
        assert_eq!(
            counters.modular_multiplications, 20,
            "a seventeen-bit public exponent builds no window table"
        );
    }

    #[test]
    fn window_width_exponent_length_growth() {
        assert_eq!(window_width(0), 1);
        assert_eq!(window_width(63), 1);
        assert_eq!(window_width(64), 3);
        assert_eq!(window_width(255), 3);
        assert_eq!(window_width(256), 4);
        assert_eq!(window_width(1023), 4);
        assert_eq!(window_width(1024), 5);
        assert_eq!(window_width(1536), 5);
    }

    #[test]
    fn exponent_length_binary_ladder_match() {
        let modulus = BigUint::from_be_bytes(
            &(0..40u8)
                .map(|index| index.wrapping_mul(61) | 0x81)
                .collect::<Vec<u8>>(),
        );
        let base = BigUint::from_be_bytes(&(1..=40u8).collect::<Vec<u8>>())
            .rem(&modulus)
            .unwrap();
        let binary = |exponent: &BigUint| {
            let mut result = BigUint::from_u64(1);
            for bit in (0..exponent.bit_len()).rev() {
                result = result.mod_mul(&result, &modulus).unwrap();
                if exponent.test_bit(bit) {
                    result = result.mod_mul(&base, &modulus).unwrap();
                }
            }
            result
        };
        for bits in [1usize, 2, 3, 7, 17, 63, 64, 65, 127, 255, 256, 257, 319] {
            for offset in [0u64, 1, 3] {
                let exponent = BigUint::from_u64(1)
                    .shl(bits - 1)
                    .add_u64(offset)
                    .rem(&modulus)
                    .unwrap();
                assert_eq!(
                    base.mod_exp(&exponent, &modulus).unwrap(),
                    binary(&exponent),
                    "bits {bits} offset {offset}"
                );
            }
        }
    }

    #[test]
    fn even_modulus_no_montgomery_form() {
        assert!(Montgomery::new(&BigUint::from_u64(1024)).is_none());
        assert!(Montgomery::new(&BigUint::zero()).is_none());
        assert!(Montgomery::new(&BigUint::from_u64(1025)).is_some());
    }

    #[test]
    fn modular_inverse_product_one() {
        let modulus = BigUint::from_be_bytes(&[
            0xd5, 0x51, 0x33, 0x9d, 0x1a, 0x3b, 0x5e, 0x9f, 0x7a, 0xc1, 0x4b, 0x2d, 0x0e, 0x77,
            0x91, 0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f,
        ]);
        for value in [3u64, 5, 65537, 0x0100_0001] {
            let candidate = BigUint::from_u64(value);
            let Some(inverse) = candidate.mod_inverse(&modulus) else {
                continue;
            };
            assert_eq!(
                candidate.mod_mul(&inverse, &modulus).unwrap(),
                BigUint::from_u64(1),
                "value {value}"
            );
        }
    }

    #[test]
    fn shared_factor_no_inverse() {
        let modulus = BigUint::from_u64(105);
        assert_eq!(BigUint::from_u64(15).mod_inverse(&modulus), None);
        assert_eq!(BigUint::from_u64(0).mod_inverse(&modulus), None);
        assert!(BigUint::from_u64(16).mod_inverse(&modulus).is_some());
    }

    #[test]
    fn inverse_one_and_unit_modulus_boundary() {
        let modulus = BigUint::from_u64(97);
        assert_eq!(
            BigUint::from_u64(1).mod_inverse(&modulus),
            Some(BigUint::from_u64(1))
        );
        assert_eq!(
            BigUint::from_u64(5).mod_inverse(&BigUint::from_u64(1)),
            None
        );
    }

    #[test]
    fn modular_add_sub_modulus_wrap() {
        let modulus = BigUint::from_u64(97);
        assert_eq!(
            BigUint::from_u64(90)
                .mod_add(&BigUint::from_u64(20), &modulus)
                .unwrap(),
            BigUint::from_u64(13)
        );
        assert_eq!(
            BigUint::from_u64(5)
                .mod_sub(&BigUint::from_u64(20), &modulus)
                .unwrap(),
            BigUint::from_u64(82)
        );
        assert_eq!(
            BigUint::from_u64(20)
                .mod_sub(&BigUint::from_u64(5), &modulus)
                .unwrap(),
            BigUint::from_u64(15)
        );
    }

    #[test]
    fn high_word_top32_read_replace() {
        let mut value = BigUint::from_be_bytes(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert_eq!(value.high_u32(), 0x1122_3344);
        value.replace_high_u32(0xdead_beef);
        assert_eq!(
            value.to_be_bytes(8).unwrap(),
            [0xde, 0xad, 0xbe, 0xef, 0x55, 0x66, 0x77, 0x88]
        );
    }

    #[test]
    fn limb_count_normalized_magnitude() {
        assert_eq!(BigUint::zero().limb_count(), 0);
        assert_eq!(BigUint::from_u64(1).limb_count(), 1);
        assert_eq!(BigUint::from_u64(u64::MAX).limb_count(), 1);
        assert_eq!(BigUint::from_be_bytes(&[0x01; 9]).limb_count(), 2);
        assert_eq!(BigUint::from_be_bytes(&[0x00; 9]).limb_count(), 0);
    }

    #[test]
    fn low_bit_set_odd_result() {
        let mut value = BigUint::zero();
        value.set_low_bit();
        assert_eq!(value, BigUint::from_u64(1));
        let mut value = BigUint::from_u64(0x10);
        value.set_low_bit();
        assert_eq!(value, BigUint::from_u64(0x11));
        assert!(value.is_odd());
    }

    #[test]
    fn comparison_magnitude_order_encoding_independence() {
        let padded = BigUint::from_be_bytes(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 5]);
        assert_eq!(
            padded.cmp(&BigUint::from_u64(5)),
            core::cmp::Ordering::Equal
        );
        assert!(BigUint::from_u64(6) > padded);
        assert!(BigUint::from_be_bytes(&[1, 0, 0, 0, 0, 0, 0, 0, 0]) > BigUint::from_u64(u64::MAX));
    }

    #[test]
    fn montgomery_constant_low_limb_inverse() {
        for value in [1u64, 3, 5, 0xffff_ffff_ffff_ffff, 0x0123_4567_89ab_cdef] {
            assert_eq!(inverse_mod_2_64(value).wrapping_mul(value), 1, "{value}");
        }
    }
}
