use crate::ffi_types::TpmResult;

use super::bignum::BigUint;
use super::prime::{PrimeSelection, is_prime_int, prime_select_with_sieve};
use super::rand_state::{SEED_COMPAT_LEVEL_ORIGINAL, SeededRand};

pub(in crate::library::tpm2) const RSA_DEFAULT_PUBLIC_EXPONENT: u32 = 0x0001_0001;
pub(in crate::library::tpm2) const MAX_RSA_KEY_BITS: u32 = 3072;

const MAX_GENERATION_ATTEMPTS: u32 = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) enum RsaKeyError {
    Range,
    Value,
    NoResult,
    Failure,
}

pub(in crate::library::tpm2) struct RsaKeyMaterial {
    pub(in crate::library::tpm2) modulus: Vec<u8>,
    pub(in crate::library::tpm2) prime: Vec<u8>,
    pub(in crate::library::tpm2) q: BigUint,
    pub(in crate::library::tpm2) d_p: BigUint,
    pub(in crate::library::tpm2) d_q: BigUint,
    pub(in crate::library::tpm2) q_inv: BigUint,
}

fn adjust_prime_candidate_pre_rev155(prime: &mut BigUint) {
    let top = prime.high_u32();
    let mut high = (top >> 16) as u16;
    high = ((u32::from(high) * 0x4afb) >> 16) as u16;
    high = high.wrapping_add(0xb505);
    prime.replace_high_u32((u32::from(high) << 16) | (top & 0xffff));
    prime.set_low_bit();
}

fn adjust_prime_candidate_new(prime: &mut BigUint) {
    let top = prime.high_u32();
    let mut adjusted = (top >> 16).wrapping_mul(0x4afb);
    adjusted = adjusted.wrapping_add(((top & 0xffff).wrapping_mul(0x4afb)) >> 16);
    adjusted = adjusted.wrapping_add(0xb505_0000);
    prime.replace_high_u32(adjusted);
    prime.set_low_bit();
}

fn random_prime_candidate(bits: usize, rand: &mut SeededRand) -> Result<BigUint, TpmResult> {
    if rand.seed_compat_level() == SEED_COMPAT_LEVEL_ORIGINAL {
        let bytes = rand.random_bytes(bits / 8)?;
        let mut limbs = Vec::with_capacity(bytes.len() / 8);
        for chunk in bytes.chunks(8) {
            let mut word = [0u8; 8];
            word[..chunk.len()].copy_from_slice(chunk);
            limbs.push(u64::from_le_bytes(word));
        }
        let mut value = BigUint::zero();
        for (index, limb) in limbs.into_iter().enumerate() {
            value = value.add(&BigUint::from_u64(limb).shl(index * 64));
        }
        let mut value = value;
        adjust_prime_candidate_pre_rev155(&mut value);
        Ok(value)
    } else {
        let mut value = rand.random_integer(bits)?;
        adjust_prime_candidate_new(&mut value);
        Ok(value)
    }
}

fn generate_prime_for_rsa(
    bits: usize,
    exponent: u32,
    rand: &mut SeededRand,
) -> Result<BigUint, TpmResult> {
    loop {
        let mut candidate = random_prime_candidate(bits, rand)?;
        if prime_select_with_sieve(&mut candidate, exponent, rand)? == PrimeSelection::Found {
            return Ok(candidate);
        }
    }
}

struct PrivateExponent {
    p: BigUint,
    q: BigUint,
    d_p: BigUint,
    d_q: BigUint,
    q_inv: BigUint,
}

impl PrivateExponent {
    fn make_p_greater_than_q(&mut self) {
        if self.p < self.q {
            core::mem::swap(&mut self.p, &mut self.q);
        }
    }

    fn compute(&mut self, exponent: &BigUint) -> bool {
        self.make_p_greater_than_q();

        let mut p_ok = false;
        if let Some(p_minus_one) = self.p.sub_u64(1)
            && let Some(d_p) = exponent.mod_inverse(&p_minus_one)
        {
            self.d_p = d_p;
            p_ok = true;
        }
        let mut q_ok = false;
        if let Some(q_minus_one) = self.q.sub_u64(1)
            && let Some(d_q) = exponent.mod_inverse(&q_minus_one)
        {
            self.d_q = d_q;
            q_ok = true;
        }
        if p_ok && q_ok {
            match self.q.mod_inverse(&self.p) {
                Some(q_inv) => self.q_inv = q_inv,
                None => {
                    p_ok = false;
                    q_ok = false;
                }
            }
        }
        if !p_ok {
            self.p = BigUint::zero();
        }
        if !q_ok {
            self.q = BigUint::zero();
        }
        p_ok && q_ok
    }

    fn private_key_op(&mut self, value: &BigUint) -> Option<BigUint> {
        self.make_p_greater_than_q();
        let m1 = value.mod_exp(&self.d_p, &self.p)?;
        let m2 = value.mod_exp(&self.d_q, &self.q)?;
        let h = self.p.sub(&m2)?.add(&m1).mod_mul(&self.q_inv, &self.p)?;
        Some(m2.add(&h.mul(&self.q)))
    }
}

pub(in crate::library::tpm2) fn rsa_private_key_op(
    p: &BigUint,
    q: &BigUint,
    d_p: &BigUint,
    d_q: &BigUint,
    q_inv: &BigUint,
    value: &BigUint,
) -> Option<BigUint> {
    let mut exponent = PrivateExponent {
        p: p.clone(),
        q: q.clone(),
        d_p: d_p.clone(),
        d_q: d_q.clone(),
        q_inv: q_inv.clone(),
    };
    exponent.private_key_op(value)
}

pub(in crate::library::tpm2) fn rsa_public_key_op(
    modulus: &BigUint,
    exponent: u32,
    value: &BigUint,
) -> Option<BigUint> {
    if modulus.is_zero() || value >= modulus {
        return None;
    }
    let exponent = if exponent == 0 {
        RSA_DEFAULT_PUBLIC_EXPONENT
    } else {
        exponent
    };
    value.mod_exp(&BigUint::from_u64(u64::from(exponent)), modulus)
}

pub(in crate::library::tpm2) fn generate_rsa_key(
    key_bits: u16,
    exponent: u32,
    is_signing_key: bool,
    rand: &mut SeededRand,
) -> Result<RsaKeyMaterial, RsaKeyError> {
    let mut effective_exponent = exponent;
    if effective_exponent == 0 {
        effective_exponent = RSA_DEFAULT_PUBLIC_EXPONENT;
    } else {
        if effective_exponent < RSA_DEFAULT_PUBLIC_EXPONENT {
            return Err(RsaKeyError::Range);
        }
        if !is_prime_int(effective_exponent) {
            return Err(RsaKeyError::Range);
        }
    }
    let public_exponent = BigUint::from_u64(u64::from(effective_exponent));

    let key_size_in_bits = u32::from(key_bits);
    if key_size_in_bits == 0 || key_size_in_bits % 1024 != 0 || key_size_in_bits > MAX_RSA_KEY_BITS
    {
        return Err(RsaKeyError::Value);
    }
    let modulus_bytes = (key_size_in_bits / 8) as usize;
    let prime_bits = (key_size_in_bits / 2) as usize;

    let mut z = PrivateExponent {
        p: BigUint::zero(),
        q: BigUint::zero(),
        d_p: BigUint::zero(),
        d_q: BigUint::zero(),
        q_inv: BigUint::zero(),
    };

    for _ in 1..MAX_GENERATION_ATTEMPTS {
        #[cfg(test)]
        super::work::count_generation_attempt();
        z.p = generate_prime_for_rsa(prime_bits, effective_exponent, rand)
            .map_err(|_| RsaKeyError::Failure)?;

        if z.q.is_zero() {
            z.q = z.p.clone();
            continue;
        }

        let difference = if z.p < z.q {
            z.q.sub(&z.p).ok_or(RsaKeyError::Failure)?
        } else {
            z.p.sub(&z.q).ok_or(RsaKeyError::Failure)?
        };
        if difference.bit_len() < 101 {
            continue;
        }

        let modulus = z.p.mul(&z.q);
        let modulus_bytes_out = modulus
            .to_be_bytes(modulus_bytes)
            .ok_or(RsaKeyError::Failure)?;
        if modulus_bytes_out[0] & 0x80 == 0 {
            return Err(RsaKeyError::Failure);
        }
        let prime_bytes_out =
            z.p.to_be_bytes(modulus_bytes / 2)
                .ok_or(RsaKeyError::Failure)?;
        let stored_q = z.q.clone();

        if !z.compute(&public_exponent) {
            if z.q.is_zero() {
                z.q = z.p.clone();
            }
            continue;
        }
        if prime_bytes_out[0] & 0x80 == 0 {
            return Err(RsaKeyError::Failure);
        }

        if is_signing_key {
            let plain = rand
                .random_in_range(&modulus)
                .map_err(|_| RsaKeyError::Failure)?
                .ok_or(RsaKeyError::Failure)?;
            let encrypted = plain
                .mod_exp(&public_exponent, &modulus)
                .ok_or(RsaKeyError::Failure)?;
            let decrypted = z.private_key_op(&encrypted).ok_or(RsaKeyError::Failure)?;
            if decrypted != plain {
                z.q = BigUint::zero();
                continue;
            }
        }

        return Ok(RsaKeyMaterial {
            modulus: modulus_bytes_out,
            prime: prime_bytes_out,
            q: stored_q,
            d_p: z.d_p,
            d_q: z.d_q,
            q_inv: z.q_inv,
        });
    }
    Err(RsaKeyError::NoResult)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::crypto::work;

    fn rand(label: &[u8]) -> SeededRand {
        SeededRand::instantiate(&[0x21; 64], b"RSA", label, &[], 1, false)
            .expect("a non-empty derivation input")
    }

    fn original_rand(label: &[u8]) -> SeededRand {
        SeededRand::instantiate(&[0x21; 64], b"RSA", label, &[], 0, false)
            .expect("a non-empty derivation input")
    }

    #[test]
    fn the_exponent_defaults_match_upstream() {
        assert_eq!(RSA_DEFAULT_PUBLIC_EXPONENT, 65537);
        assert_eq!(MAX_RSA_KEY_BITS, 3072);
    }

    #[test]
    fn the_public_operation_undoes_the_private_one() {
        let key = generate_rsa_key(1024, 0, true, &mut rand(b"public-op")).expect("a key");
        let modulus = BigUint::from_be_bytes(&key.modulus);
        let prime = BigUint::from_be_bytes(&key.prime);
        let message = BigUint::from_u64(0x0123_4567_89ab_cdef);
        let signed = rsa_private_key_op(&prime, &key.q, &key.d_p, &key.d_q, &key.q_inv, &message)
            .expect("a private operation");
        assert_eq!(
            rsa_public_key_op(&modulus, 0, &signed),
            Some(message),
            "a zero exponent selects the default public exponent"
        );
    }

    #[test]
    fn the_public_operation_uses_the_declared_exponent() {
        let modulus = BigUint::from_u64(3233);
        let message = BigUint::from_u64(65);
        assert_eq!(
            rsa_public_key_op(&modulus, 17, &message),
            message.mod_exp(&BigUint::from_u64(17), &modulus)
        );
        assert_eq!(
            rsa_public_key_op(&modulus, 0, &message),
            message.mod_exp(&BigUint::from_u64(65537), &modulus)
        );
    }

    #[test]
    fn a_value_outside_the_modulus_has_no_public_operation() {
        let modulus = BigUint::from_u64(3233);
        assert!(rsa_public_key_op(&modulus, 17, &modulus).is_none());
        assert!(rsa_public_key_op(&modulus, 17, &BigUint::from_u64(3234)).is_none());
        assert!(rsa_public_key_op(&BigUint::zero(), 17, &BigUint::from_u64(1)).is_none());
    }

    #[test]
    fn the_new_adjustment_sets_the_top_bits_to_at_least_the_root_of_two_over_two() {
        for top in [0u32, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff] {
            let mut value = BigUint::from_u64(u64::from(top) << 32).add_u64(0x1234_5678);
            adjust_prime_candidate_new(&mut value);
            assert!(value.high_u32() >= 0xb505_0000, "top {top:#010x}");
            assert!(value.is_odd(), "top {top:#010x}");
            assert_eq!(value.low_u32(), 0x1234_5679, "the low words are kept");
        }
    }

    #[test]
    fn the_new_adjustment_saturates_just_below_the_top_of_the_range() {
        let mut value = BigUint::from_u64(0xffff_ffff_0000_0000);
        adjust_prime_candidate_new(&mut value);
        assert_eq!(value.high_u32(), 0xffff_ffff);
    }

    #[test]
    fn the_pre_rev155_adjustment_only_rewrites_the_top_sixteen_bits() {
        let mut value = BigUint::from_u64(0x1234_5678_9abc_def0);
        adjust_prime_candidate_pre_rev155(&mut value);
        assert_eq!(value.high_u32() & 0xffff, 0x5678, "the next word is kept");
        assert_eq!(value.low_u32(), 0x9abc_def1);
    }

    #[test]
    fn the_two_adjustments_differ_on_the_same_candidate() {
        let base = BigUint::from_u64(0x1234_5678_9abc_def0);
        let mut old = base.clone();
        let mut new = base;
        adjust_prime_candidate_pre_rev155(&mut old);
        adjust_prime_candidate_new(&mut new);
        assert_ne!(old.high_u32(), new.high_u32());
    }

    #[test]
    fn an_exponent_below_the_default_is_out_of_range() {
        for exponent in [1u32, 3, 17, 65536] {
            assert_eq!(
                generate_rsa_key(1024, exponent, false, &mut rand(b"e")).err(),
                Some(RsaKeyError::Range),
                "exponent {exponent}"
            );
        }
    }

    #[test]
    fn a_composite_exponent_is_out_of_range() {
        for exponent in [65538u32, 65539 * 3, 0xffff_ffff] {
            assert_eq!(
                generate_rsa_key(1024, exponent, false, &mut rand(b"e")).err(),
                Some(RsaKeyError::Range),
                "exponent {exponent}"
            );
        }
    }

    #[test]
    fn an_unsupported_key_size_is_a_value_error() {
        for key_bits in [0u16, 512, 1023, 2047, 4096] {
            assert_eq!(
                generate_rsa_key(key_bits, 0, false, &mut rand(b"size")).err(),
                Some(RsaKeyError::Value),
                "keyBits {key_bits}"
            );
        }
    }

    fn assert_key_is_consistent(key: &RsaKeyMaterial, key_bits: usize, exponent: u32) {
        assert_eq!(key.modulus.len(), key_bits / 8);
        assert_eq!(key.prime.len(), key_bits / 16);
        assert_ne!(key.modulus[0] & 0x80, 0, "the modulus is full length");
        assert_ne!(key.prime[0] & 0x80, 0, "the prime is full length");

        let modulus = BigUint::from_be_bytes(&key.modulus);
        let p = BigUint::from_be_bytes(&key.prime);
        let product = p.mul(&key.q);
        assert_eq!(product, modulus, "the modulus is the product of the primes");

        let public = BigUint::from_u64(u64::from(exponent));
        let (larger, smaller) = if p > key.q {
            (p.clone(), key.q.clone())
        } else {
            (key.q.clone(), p.clone())
        };
        assert_eq!(
            public
                .mod_mul(&key.d_p, &larger.sub_u64(1).unwrap())
                .unwrap(),
            BigUint::from_u64(1)
        );
        assert_eq!(
            public
                .mod_mul(&key.d_q, &smaller.sub_u64(1).unwrap())
                .unwrap(),
            BigUint::from_u64(1)
        );
        assert_eq!(
            smaller.mod_mul(&key.q_inv, &larger).unwrap(),
            BigUint::from_u64(1)
        );

        let message = BigUint::from_u64(0x0123_4567_89ab_cdef);
        let encrypted = message.mod_exp(&public, &modulus).unwrap();
        let phi = larger.sub_u64(1).unwrap().mul(&smaller.sub_u64(1).unwrap());
        let d = public.mod_inverse(&phi).unwrap();
        assert_eq!(encrypted.mod_exp(&d, &modulus).unwrap(), message);
    }

    #[test]
    fn a_two_thousand_forty_eight_bit_key_is_internally_consistent() {
        let key = generate_rsa_key(2048, 0, false, &mut rand(b"rsa2048")).expect("a key");
        assert_key_is_consistent(&key, 2048, RSA_DEFAULT_PUBLIC_EXPONENT);
    }

    #[test]
    fn a_signing_key_passes_its_own_trial_decryption() {
        let key = generate_rsa_key(1024, 0, true, &mut rand(b"sign")).expect("a key");
        assert_key_is_consistent(&key, 1024, RSA_DEFAULT_PUBLIC_EXPONENT);
    }

    #[test]
    fn a_key_is_deterministic_in_the_generator_state() {
        let first = generate_rsa_key(1024, 0, false, &mut rand(b"same")).expect("a key");
        let second = generate_rsa_key(1024, 0, false, &mut rand(b"same")).expect("a key");
        assert_eq!(first.modulus, second.modulus);
        assert_eq!(first.prime, second.prime);
        assert_eq!(first.q, second.q);
        assert_eq!(first.d_p, second.d_p);
        assert_eq!(first.d_q, second.d_q);
        assert_eq!(first.q_inv, second.q_inv);
    }

    #[test]
    fn a_different_generator_state_produces_a_different_key() {
        let first = generate_rsa_key(1024, 0, false, &mut rand(b"one")).expect("a key");
        let second = generate_rsa_key(1024, 0, false, &mut rand(b"two")).expect("a key");
        assert_ne!(first.modulus, second.modulus);
    }

    #[test]
    fn the_seed_compatibility_level_changes_the_key() {
        let new = generate_rsa_key(1024, 0, false, &mut rand(b"level")).expect("a key");
        let old = generate_rsa_key(1024, 0, false, &mut original_rand(b"level")).expect("a key");
        assert_ne!(new.modulus, old.modulus);
        assert_key_is_consistent(&old, 1024, RSA_DEFAULT_PUBLIC_EXPONENT);
    }

    #[test]
    fn a_signing_key_consumes_more_generator_output_than_a_decryption_key() {
        let signing = generate_rsa_key(1024, 0, true, &mut rand(b"drain")).expect("a key");
        let decryption = generate_rsa_key(1024, 0, false, &mut rand(b"drain")).expect("a key");
        assert_eq!(
            signing.modulus, decryption.modulus,
            "the trial decryption happens after both primes are chosen"
        );
        let mut signing_state = rand(b"drain");
        let mut decryption_state = rand(b"drain");
        generate_rsa_key(1024, 0, true, &mut signing_state).expect("a key");
        generate_rsa_key(1024, 0, false, &mut decryption_state).expect("a key");
        assert_ne!(
            signing_state.random_bytes(32).unwrap(),
            decryption_state.random_bytes(32).unwrap(),
            "the trial decryption draws from the same generator"
        );
    }

    #[test]
    fn an_explicit_default_exponent_matches_the_implicit_one() {
        let implicit = generate_rsa_key(1024, 0, false, &mut rand(b"exp")).expect("a key");
        let explicit = generate_rsa_key(1024, 65537, false, &mut rand(b"exp")).expect("a key");
        assert_eq!(implicit.modulus, explicit.modulus);
    }

    #[test]
    fn a_larger_prime_exponent_produces_a_usable_key() {
        let key = generate_rsa_key(1024, 65539, false, &mut rand(b"bigexp")).expect("a key");
        assert_key_is_consistent(&key, 1024, 65539);
    }

    const THREE_THOUSAND_SEVENTY_TWO_BIT_SEEDS: [&[u8]; 5] =
        [b"ek3072", b"spk3072", b"sign3072", b"seed-a", b"seed-b"];

    #[test]
    fn a_three_thousand_seventy_two_bit_key_is_internally_consistent() {
        let key = generate_rsa_key(3072, 0, false, &mut rand(b"ek3072")).expect("a key");
        assert_key_is_consistent(&key, 3072, RSA_DEFAULT_PUBLIC_EXPONENT);
    }

    #[test]
    fn a_three_thousand_seventy_two_bit_signing_key_passes_its_own_trial_decryption() {
        let key = generate_rsa_key(3072, 0, true, &mut rand(b"sign3072")).expect("a key");
        assert_key_is_consistent(&key, 3072, RSA_DEFAULT_PUBLIC_EXPONENT);
    }

    #[test]
    fn every_three_thousand_seventy_two_bit_seed_yields_a_consistent_key() {
        for label in THREE_THOUSAND_SEVENTY_TWO_BIT_SEEDS {
            let key = generate_rsa_key(3072, 0, false, &mut rand(label)).expect("a key");
            assert_key_is_consistent(&key, 3072, RSA_DEFAULT_PUBLIC_EXPONENT);
            let p = BigUint::from_be_bytes(&key.prime);
            let difference = if p > key.q {
                p.sub(&key.q).unwrap()
            } else {
                key.q.sub(&p).unwrap()
            };
            assert!(
                difference.bit_len() >= 101,
                "{} keeps the minimum prime distance",
                core::str::from_utf8(label).unwrap()
            );
        }
    }

    #[test]
    fn the_chosen_seeds_exercise_different_prime_search_paths() {
        let mut lengths = Vec::new();
        for label in THREE_THOUSAND_SEVENTY_TWO_BIT_SEEDS {
            let (key, counters) =
                work::measure(|| generate_rsa_key(3072, 0, false, &mut rand(label)));
            key.expect("a key");
            lengths.push(counters.sieved_candidates);
        }
        lengths.sort_unstable();
        lengths.dedup();
        assert_eq!(
            lengths.len(),
            THREE_THOUSAND_SEVENTY_TWO_BIT_SEEDS.len(),
            "each seed walks a different number of sieved candidates"
        );
        assert!(
            lengths[0] >= 3,
            "the shortest search still tests candidates"
        );
    }

    #[test]
    fn a_three_thousand_seventy_two_bit_key_is_deterministic_in_the_generator_state() {
        for label in THREE_THOUSAND_SEVENTY_TWO_BIT_SEEDS {
            let (first, left) = work::measure(|| {
                generate_rsa_key(3072, 0, false, &mut rand(label)).expect("a key")
            });
            let (second, right) = work::measure(|| {
                generate_rsa_key(3072, 0, false, &mut rand(label)).expect("a key")
            });
            let name = core::str::from_utf8(label).unwrap();
            assert_eq!(first.modulus, second.modulus, "{name} modulus");
            assert_eq!(first.prime, second.prime, "{name} prime");
            assert_eq!(first.q, second.q, "{name} q");
            assert_eq!(first.d_p, second.d_p, "{name} dP");
            assert_eq!(first.d_q, second.d_q, "{name} dQ");
            assert_eq!(first.q_inv, second.q_inv, "{name} qInv");
            assert_eq!(left, right, "{name} work");
        }
    }

    #[test]
    fn different_seeds_produce_different_three_thousand_seventy_two_bit_keys() {
        let mut moduli = Vec::new();
        for label in THREE_THOUSAND_SEVENTY_TWO_BIT_SEEDS {
            moduli.push(
                generate_rsa_key(3072, 0, false, &mut rand(label))
                    .expect("a key")
                    .modulus,
            );
        }
        moduli.sort_unstable();
        moduli.dedup();
        assert_eq!(moduli.len(), THREE_THOUSAND_SEVENTY_TWO_BIT_SEEDS.len());
    }

    #[test]
    fn the_three_thousand_seventy_two_bit_search_does_the_pinned_amount_of_work() {
        let expected = [
            (b"ek3072".as_slice(), 46433u64, 19u64, 5184u64),
            (b"spk3072", 210178, 107, 25152),
            (b"sign3072", 42775, 17, 5952),
            (b"seed-a", 152548, 76, 16704),
            (b"seed-b", 295526, 153, 32640),
        ];
        for (label, multiplications, candidates, generator_bytes) in expected {
            let (key, counters) =
                work::measure(|| generate_rsa_key(3072, 0, false, &mut rand(label)));
            key.expect("a key");
            let name = core::str::from_utf8(label).unwrap();
            assert_eq!(counters.sieved_candidates, candidates, "{name} candidates");
            assert_eq!(counters.primality_tests, candidates, "{name} rounds");
            assert_eq!(counters.sieve_passes, 2, "{name} sieve passes");
            assert_eq!(counters.generation_attempts, 2, "{name} attempts");
            assert_eq!(counters.generator_bytes, generator_bytes, "{name} entropy");
            assert_eq!(
                counters.modular_multiplications, multiplications,
                "{name} modular multiplications"
            );
        }
    }

    #[test]
    fn the_two_thousand_forty_eight_bit_search_does_the_pinned_amount_of_work() {
        let (key, counters) =
            work::measure(|| generate_rsa_key(2048, 0, false, &mut rand(b"rsa2048")));
        let key = key.expect("a key");
        assert_key_is_consistent(&key, 2048, RSA_DEFAULT_PUBLIC_EXPONENT);
        assert_eq!(counters.sieved_candidates, 61);
        assert_eq!(counters.primality_tests, 61);
        assert_eq!(counters.sieve_passes, 2);
        assert_eq!(counters.generation_attempts, 2);
        assert_eq!(counters.generator_bytes, 10368);
        assert_eq!(counters.modular_multiplications, 88014);
    }

    #[test]
    fn the_generation_attempt_budget_bounds_every_supported_key_size() {
        assert_eq!(MAX_GENERATION_ATTEMPTS, 100);
        for key_bits in [1024u16, 2048, 3072] {
            let (key, counters) =
                work::measure(|| generate_rsa_key(key_bits, 0, false, &mut rand(b"budget")));
            key.expect("a key");
            assert!(
                counters.generation_attempts < u64::from(MAX_GENERATION_ATTEMPTS),
                "keyBits {key_bits}"
            );
        }
    }

    #[test]
    fn a_rejected_request_costs_no_arithmetic_at_all() {
        for (key_bits, exponent, error) in [
            (3072u16, 3u32, RsaKeyError::Range),
            (3072, 65538, RsaKeyError::Range),
            (4096, 0, RsaKeyError::Value),
            (1536, 0, RsaKeyError::Value),
        ] {
            let (result, counters) =
                work::measure(|| generate_rsa_key(key_bits, exponent, false, &mut rand(b"bad")));
            assert_eq!(result.err(), Some(error), "keyBits {key_bits}");
            assert_eq!(counters, work::Counters::default(), "keyBits {key_bits}");
        }
    }

    #[test]
    fn the_private_key_operation_inverts_the_public_one() {
        let key = generate_rsa_key(1024, 0, false, &mut rand(b"crt")).expect("a key");
        let modulus = BigUint::from_be_bytes(&key.modulus);
        let mut z = PrivateExponent {
            p: BigUint::from_be_bytes(&key.prime),
            q: key.q.clone(),
            d_p: key.d_p.clone(),
            d_q: key.d_q.clone(),
            q_inv: key.q_inv.clone(),
        };
        let message = BigUint::from_u64(0xdead_beef_cafe_babe);
        let encrypted = message
            .mod_exp(&BigUint::from_u64(65537), &modulus)
            .unwrap();
        assert_eq!(z.private_key_op(&encrypted).unwrap(), message);
    }
}
