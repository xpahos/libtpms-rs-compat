use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_NO_RESULT};
use crate::types::TpmResult;

use super::bignum::BigUint;
use super::drbg::{Drbg, ReseedError};
use super::entropy::EntropySource;
use super::hmac::HmacState;

pub(in crate::library::tpm2) const SEED_COMPAT_LEVEL_ORIGINAL: u8 = 0;
pub(in crate::library::tpm2) const SEED_COMPAT_LEVEL_RSA_PRIME_ADJUST_FIX: u8 = 1;
pub(in crate::library::tpm2) const SEED_COMPAT_LEVEL_LAST: u8 =
    SEED_COMPAT_LEVEL_RSA_PRIME_ADJUST_FIX;

const CTR_DRBG_MAX_BYTES_PER_REQUEST: usize = 1 << 16;

pub(in crate::library::tpm2) struct KdfState {
    hash_alg: u16,
    key: Vec<u8>,
    label: Vec<u8>,
    context: Vec<u8>,
    limit: u32,
    digest_size: usize,
    counter: u32,
    residual: Vec<u8>,
}

impl KdfState {
    fn new(
        hash_alg: u16,
        key: &[u8],
        label: &[u8],
        context: &[u8],
        limit: u32,
    ) -> Result<Self, TpmResult> {
        let digest_size = super::hash::COMPILED_HASHES
            .iter()
            .find(|(algorithm, _)| *algorithm == hash_alg)
            .map(|(_, size)| *size)
            .ok_or(TPM_RC_FAILURE)?;
        Ok(Self {
            hash_alg,
            key: key.to_vec(),
            label: label.to_vec(),
            context: context.to_vec(),
            limit,
            digest_size,
            counter: 0,
            residual: Vec::new(),
        })
    }

    fn next_block(&mut self) -> Result<Vec<u8>, TpmResult> {
        self.counter = self.counter.checked_add(1).ok_or(TPM_RC_NO_RESULT)?;
        let mut hmac = HmacState::new(self.hash_alg, &self.key).ok_or(TPM_RC_FAILURE)?;
        hmac.update(&self.counter.to_be_bytes());
        hmac.update(&self.label);
        if self.label.last() != Some(&0) {
            hmac.update(&[0]);
        }
        hmac.update(&self.context);
        hmac.update(&self.limit.to_be_bytes());
        Ok(hmac.finalize())
    }

    fn generate(&mut self, out: &mut [u8]) -> Result<(), TpmResult> {
        let produced = u64::from(self.counter) * self.digest_size as u64;
        if (produced + out.len() as u64) * 8 > u64::from(self.limit) {
            return Err(TPM_RC_NO_RESULT);
        }
        let mut position = 0;
        while position < out.len() {
            if !self.residual.is_empty() {
                let take = self.residual.len().min(out.len() - position);
                out[position..position + take].copy_from_slice(&self.residual[..take]);
                self.residual.drain(..take);
                position += take;
            } else if out.len() - position >= self.digest_size {
                let block = self.next_block()?;
                out[position..position + self.digest_size].copy_from_slice(&block);
                position += self.digest_size;
            } else {
                self.residual = self.next_block()?;
            }
        }
        Ok(())
    }
}

pub(in crate::library::tpm2) struct LiveDrbg {
    drbg: Drbg,
    entropy: EntropySource,
    entropy_bad: bool,
    fatal: bool,
}

impl LiveDrbg {
    pub(in crate::library::tpm2) fn new(
        drbg: Drbg,
        entropy: EntropySource,
        entropy_bad: bool,
    ) -> Self {
        Self {
            drbg,
            entropy,
            entropy_bad,
            fatal: false,
        }
    }

    fn generate(&mut self, out: &mut [u8]) -> Result<(), TpmResult> {
        if self.drbg.needs_reseed() {
            let outcome = if self.entropy_bad {
                Err(ReseedError::Entropy)
            } else {
                self.drbg.reseed_from_entropy(self.entropy)
            };
            match outcome {
                Ok(()) => {}
                Err(ReseedError::Entropy) => {
                    self.entropy_bad = true;
                    return Err(TPM_RC_NO_RESULT);
                }
                Err(ReseedError::ContinuousTest) => {
                    self.fatal = true;
                    return Err(TPM_RC_FAILURE);
                }
            }
        }
        if self.drbg.generate(out).is_err() {
            self.fatal = true;
            return Err(TPM_RC_FAILURE);
        }
        Ok(())
    }

    fn additional_data(&mut self, data: &[u8]) -> Result<(), TpmResult> {
        self.drbg.additional_data(data).inspect_err(|_| {
            self.fatal = true;
        })
    }

    pub(in crate::library::tpm2) fn entropy_bad(&self) -> bool {
        self.entropy_bad
    }

    pub(in crate::library::tpm2) fn fatal(&self) -> bool {
        self.fatal
    }

    pub(in crate::library::tpm2) fn into_drbg(self) -> Drbg {
        self.drbg
    }
}

enum RandSource {
    Drbg(Drbg),
    Kdf(KdfState),
    Live(LiveDrbg),
}

pub(in crate::library::tpm2) struct SeededRand {
    source: RandSource,
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
            source: RandSource::Drbg(drbg),
            seed_compat_level,
        })
    }

    pub(in crate::library::tpm2) fn instantiate_seeded_kdf(
        hash_alg: u16,
        key: &[u8],
        label: &[u8],
        context: &[u8],
        limit: u32,
        seed_compat_level: u8,
    ) -> Result<Self, TpmResult> {
        Ok(Self {
            source: RandSource::Kdf(KdfState::new(hash_alg, key, label, context, limit)?),
            seed_compat_level,
        })
    }

    pub(in crate::library::tpm2) fn from_live(live: LiveDrbg) -> Self {
        Self {
            source: RandSource::Live(live),
            seed_compat_level: SEED_COMPAT_LEVEL_LAST,
        }
    }

    pub(in crate::library::tpm2) fn into_live(self) -> Option<LiveDrbg> {
        match self.source {
            RandSource::Live(live) => Some(live),
            _ => None,
        }
    }

    pub(in crate::library::tpm2) fn live_entropy_starved(&self) -> bool {
        matches!(&self.source, RandSource::Live(live) if live.entropy_bad)
    }

    pub(in crate::library::tpm2) fn seed_compat_level(&self) -> u8 {
        self.seed_compat_level
    }

    pub(in crate::library::tpm2) fn additional_data(
        &mut self,
        data: &[u8],
    ) -> Result<(), TpmResult> {
        match &mut self.source {
            RandSource::Drbg(drbg) => drbg.additional_data(data),
            RandSource::Live(live) => live.additional_data(data),
            RandSource::Kdf(_) => Ok(()),
        }
    }

    pub(in crate::library::tpm2) fn generate(&mut self, out: &mut [u8]) -> Result<(), TpmResult> {
        debug_assert!(out.len() <= CTR_DRBG_MAX_BYTES_PER_REQUEST);
        #[cfg(test)]
        super::work::count_generator_bytes(out.len());
        match &mut self.source {
            RandSource::Drbg(drbg) => drbg.generate(out),
            RandSource::Kdf(kdf) => kdf.generate(out),
            RandSource::Live(live) => live.generate(out),
        }
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

    #[test]
    fn a_seeded_generator_reports_no_live_outcome_and_no_starvation() {
        assert!(!rand().live_entropy_starved());
        assert!(
            rand().into_live().is_none(),
            "a seeded generator has no runtime-global outcome to publish"
        );
    }

    #[test]
    fn a_seeded_continuous_test_hit_stays_a_local_error() {
        use crate::library::constants::TPM_FAIL;

        let base = Drbg::instantiate_seeded(&[&[0x5a; 64]], true).expect("instantiates");
        let mut probe = Drbg::restore(base.seed(), 1, [0; 4], false).expect("the probe restores");
        let mut block = [0u8; 16];
        probe.generate(&mut block).expect("the probe generates");
        let collision: [u32; 4] = core::array::from_fn(|word| {
            u32::from_le_bytes(block[word * 4..word * 4 + 4].try_into().unwrap())
        });
        let crafted = Drbg::restore(base.seed(), 1, collision, true).expect("restores");

        let mut generator = SeededRand {
            source: RandSource::Drbg(crafted),
            seed_compat_level: SEED_COMPAT_LEVEL_LAST,
        };
        assert_eq!(generator.random_bytes(16).map(|_| ()), Err(TPM_FAIL));
        assert!(
            generator.into_live().is_none(),
            "the local fatal never masquerades as a live-DRBG outcome"
        );
    }
}
