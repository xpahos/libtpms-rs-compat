use crate::ffi_types::TpmResult;

use super::bignum::BigUint;
use super::drbg::Drbg;

pub(in crate::library::tpm2) const SEED_COMPAT_LEVEL_ORIGINAL: u8 = 0;
pub(in crate::library::tpm2) const SEED_COMPAT_LEVEL_RSA_PRIME_ADJUST_FIX: u8 = 1;
#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::library::tpm2) const SEED_COMPAT_LEVEL_LAST: u8 =
    SEED_COMPAT_LEVEL_RSA_PRIME_ADJUST_FIX;

const CTR_DRBG_MAX_BYTES_PER_REQUEST: usize = 1 << 16;

pub(in crate::library::tpm2) struct SeededRand {
    drbg: Drbg,
    seed_compat_level: u8,
}

impl SeededRand {
    pub(in crate::library::tpm2) fn instantiate(
        seed: &[u8],
        purpose: &[u8],
        name: &[u8],
        additional: &[u8],
        seed_compat_level: u8,
        continuous_test: bool,
    ) -> Result<Self, TpmResult> {
        let drbg = Drbg::instantiate_seeded(&[seed, purpose, name, additional], continuous_test)?;
        Ok(Self {
            drbg,
            seed_compat_level,
        })
    }

    pub(in crate::library::tpm2) fn seed_compat_level(&self) -> u8 {
        self.seed_compat_level
    }

    pub(in crate::library::tpm2) fn additional_data(
        &mut self,
        data: &[u8],
    ) -> Result<(), TpmResult> {
        self.drbg.additional_data(data)
    }

    pub(in crate::library::tpm2) fn generate(&mut self, out: &mut [u8]) -> Result<(), TpmResult> {
        debug_assert!(out.len() <= CTR_DRBG_MAX_BYTES_PER_REQUEST);
        #[cfg(test)]
        super::work::count_generator_bytes(out.len());
        self.drbg.generate(out)
    }

    pub(in crate::library::tpm2) fn random_bytes(
        &mut self,
        length: usize,
    ) -> Result<Vec<u8>, TpmResult> {
        let mut out = vec![0u8; length];
        self.generate(&mut out)?;
        Ok(out)
    }

    pub(in crate::library::tpm2) fn random_integer(
        &mut self,
        bits: usize,
    ) -> Result<BigUint, TpmResult> {
        let bytes = self.random_bytes(bits.div_ceil(8))?;
        let mut value = BigUint::from_be_bytes(&bytes);
        value.mask_bits(bits);
        Ok(value)
    }

    pub(in crate::library::tpm2) fn random_in_range(
        &mut self,
        limit: &BigUint,
    ) -> Result<Option<BigUint>, TpmResult> {
        let bits = limit.bit_len();
        if bits < 2 {
            return Ok(None);
        }
        loop {
            let candidate = self.random_integer(bits)?;
            if !candidate.is_zero() && &candidate < limit {
                return Ok(Some(candidate));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rand() -> SeededRand {
        SeededRand::instantiate(&[0x5a; 64], b"PURPOSE", &[0x11; 34], &[], 1, false)
            .expect("a non-empty derivation input")
    }

    #[test]
    fn the_compat_level_constants_match_upstream() {
        assert_eq!(SEED_COMPAT_LEVEL_ORIGINAL, 0);
        assert_eq!(SEED_COMPAT_LEVEL_RSA_PRIME_ADJUST_FIX, 1);
        assert_eq!(SEED_COMPAT_LEVEL_LAST, 1);
    }

    #[test]
    fn instantiation_is_deterministic_in_all_four_inputs() {
        let baseline = rand().random_bytes(32).unwrap();
        assert_eq!(rand().random_bytes(32).unwrap(), baseline);
        for changed in [
            SeededRand::instantiate(&[0x5b; 64], b"PURPOSE", &[0x11; 34], &[], 1, false),
            SeededRand::instantiate(&[0x5a; 64], b"purpose", &[0x11; 34], &[], 1, false),
            SeededRand::instantiate(&[0x5a; 64], b"PURPOSE", &[0x12; 34], &[], 1, false),
            SeededRand::instantiate(&[0x5a; 64], b"PURPOSE", &[0x11; 34], &[0x01], 1, false),
        ] {
            assert_ne!(changed.unwrap().random_bytes(32).unwrap(), baseline);
        }
    }

    #[test]
    fn the_seed_compat_level_travels_with_the_state_without_changing_the_output() {
        let original =
            SeededRand::instantiate(&[0x5a; 64], b"PURPOSE", &[0x11; 34], &[], 0, false).unwrap();
        assert_eq!(original.seed_compat_level(), 0);
        assert_eq!(rand().seed_compat_level(), 1);
        let mut original =
            SeededRand::instantiate(&[0x5a; 64], b"PURPOSE", &[0x11; 34], &[], 0, false).unwrap();
        assert_eq!(
            original.random_bytes(32).unwrap(),
            rand().random_bytes(32).unwrap()
        );
    }

    #[test]
    fn an_empty_derivation_input_has_no_instantiation() {
        assert!(SeededRand::instantiate(&[], &[], &[], &[], 1, false).is_err());
    }

    #[test]
    fn successive_draws_advance_the_generator() {
        let mut generator = rand();
        let first = generator.random_bytes(48).unwrap();
        let second = generator.random_bytes(48).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn a_random_integer_is_masked_to_the_requested_bit_count() {
        let mut generator = rand();
        for bits in [1usize, 7, 8, 63, 64, 65, 128, 521, 1024] {
            let value = generator.random_integer(bits).unwrap();
            assert!(value.bit_len() <= bits, "bits {bits}");
        }
    }

    #[test]
    fn a_random_integer_draws_exactly_the_rounded_up_byte_count() {
        let mut counted = rand();
        let mut byte_wise = rand();
        let value = counted.random_integer(521).unwrap();
        let bytes = byte_wise.random_bytes(66).unwrap();
        let mut expected = BigUint::from_be_bytes(&bytes);
        expected.mask_bits(521);
        assert_eq!(value, expected);
    }

    #[test]
    fn a_value_in_range_is_never_zero_and_always_below_the_limit() {
        let mut generator = rand();
        let limit = BigUint::from_u64(0x1_0000_0001);
        for _ in 0..32 {
            let value = generator.random_in_range(&limit).unwrap().unwrap();
            assert!(!value.is_zero());
            assert!(value < limit);
        }
    }

    #[test]
    fn a_limit_below_two_has_no_value_in_range() {
        let mut generator = rand();
        assert!(
            generator
                .random_in_range(&BigUint::zero())
                .unwrap()
                .is_none()
        );
        assert!(
            generator
                .random_in_range(&BigUint::from_u64(1))
                .unwrap()
                .is_none()
        );
        assert!(
            generator
                .random_in_range(&BigUint::from_u64(2))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn additional_data_diverges_the_sequence() {
        let mut plain = rand();
        let mut stirred = rand();
        stirred.additional_data(&[0x77; 64]).unwrap();
        assert_ne!(
            plain.random_bytes(32).unwrap(),
            stirred.random_bytes(32).unwrap()
        );
    }

    #[test]
    fn empty_additional_data_is_rejected_rather_than_drawing_entropy() {
        let mut generator = rand();
        assert!(generator.additional_data(&[]).is_err());
    }
}
