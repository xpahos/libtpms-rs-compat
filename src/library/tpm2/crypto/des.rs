use crate::library::constants::{TPM_RC_NO_RESULT, TPM_RC_SYMMETRIC};
use crate::types::TpmResult;

use super::rand_state::SeededRand;

const DES_KEY_BYTES: usize = 8;
const PARITY_MASK: u64 = 0x0101_0101_0101_0101;

const DES_WEAK_KEYS: [u64; 64] = [
    0x01010101_01010101,
    0xfefefefe_fefefefe,
    0xe0e0e0e0_f1f1f1f1,
    0x1f1f1f1f_0e0e0e0e,
    0x011f011f_010e010e,
    0x1f011f01_0e010e01,
    0x01e001e0_01f101f1,
    0xe001e001_f101f101,
    0x01fe01fe_01fe01fe,
    0xfe01fe01_fe01fe01,
    0x1fe01fe0_0ef10ef1,
    0xe01fe01f_f10ef10e,
    0x1ffe1ffe_0efe0efe,
    0xfe1ffe1f_fe0efe0e,
    0xe0fee0fe_f1fef1fe,
    0xfee0fee0_fef1fef1,
    0x01011f1f_01010e0e,
    0x1f1f0101_0e0e0101,
    0xe0e01f1f_f1f10e0e,
    0x0101e0e0_0101f1f1,
    0x1f1fe0e0_0e0ef1f1,
    0xe0e0fefe_f1f1fefe,
    0x0101fefe_0101fefe,
    0x1f1ffefe_0e0efefe,
    0xe0fe011f_f1fe010e,
    0x011f1f01_010e0e01,
    0x1fe001fe_0ef101fe,
    0xe0fe1f01_f1fe0e01,
    0x011fe0fe_010ef1fe,
    0x1fe0e01f_0ef1f10e,
    0xe0fefee0_f1fefef1,
    0x011ffee0_010efef1,
    0x1fe0fe01_0ef1fe01,
    0xfe0101fe_fe0101fe,
    0x01e01ffe_01f10efe,
    0x1ffe01e0_0efe01f1,
    0xfe011fe0_fe010ef1,
    0xfe01e01f_fe01f10e,
    0x1ffee001_0efef101,
    0xfe1f01e0_fe0e01f1,
    0x01e0e001_01f1f101,
    0x1ffefe1f_0efefe0e,
    0xfe1fe001_fe0ef101,
    0x01e0fe1f_01f1fe0e,
    0xe00101e0_f10101f1,
    0xfe1f1ffe_fe0e0efe,
    0x01fe1fe0_01fe0ef1,
    0xe0011ffe_f1010efe,
    0xfee0011f_fef1010e,
    0x01fee01f_01fef10e,
    0xe001fe1f_f101fe0e,
    0xfee01f01_fef10e01,
    0x01fefe01_01fefe01,
    0xe01f01fe_f10e01fe,
    0xfee0e0fe_fef1f1fe,
    0x1f01011f_0e01010e,
    0xe01f1fe0_f10e0ef1,
    0xfefe0101_fefe0101,
    0x1f01e0fe_0e01f1fe,
    0xe01ffe01_f10efe01,
    0xfefe1f1f_fefe0e0e,
    0x1f01fee0_0e01fef1,
    0xe0e00101_f1f10101,
    0xfefee0e0_fefef1f1,
];

pub(in crate::library::tpm2) fn set_odd_byte_parity(key: u64) -> u64 {
    let mut value = key | PARITY_MASK;
    let out = value;
    value ^= value >> 4;
    value ^= value >> 2;
    value ^= value >> 1;
    value &= PARITY_MASK;
    out ^ value ^ PARITY_MASK
}

pub(in crate::library::tpm2) fn is_weak_key(key: u64) -> bool {
    DES_WEAK_KEYS.contains(&key)
}

pub(in crate::library::tpm2) fn validate_tdes_key(key: &[u8]) -> bool {
    let keys = key.len().div_ceil(DES_KEY_BYTES);
    if !matches!(keys, 2 | 3) || !key.len().is_multiple_of(DES_KEY_BYTES) {
        return false;
    }
    let mut components = [0u64; 3];
    for (index, component) in components.iter_mut().take(keys).enumerate() {
        let block: [u8; DES_KEY_BYTES] = key[index * DES_KEY_BYTES..(index + 1) * DES_KEY_BYTES]
            .try_into()
            .expect("a full eight byte component");
        *component = set_odd_byte_parity(u64::from_be_bytes(block));
        if is_weak_key(*component) {
            return false;
        }
    }
    if components[0] == components[1] {
        return false;
    }
    keys != 3 || components[1] != components[2]
}

const MAX_GENERATION_ATTEMPTS: u32 = 100;

pub(in crate::library::tpm2) fn generate_tdes_key(
    key_bits: u16,
    rand: &mut SeededRand,
) -> Result<Vec<u8>, TpmResult> {
    let size = usize::from(key_bits) / 8;
    if !size.is_multiple_of(DES_KEY_BYTES) || !matches!(size / DES_KEY_BYTES, 2 | 3) {
        return Err(TPM_RC_SYMMETRIC);
    }
    for _ in 0..MAX_GENERATION_ATTEMPTS {
        let mut key = rand.random_bytes(size)?;
        if key.is_empty() {
            return Err(TPM_RC_NO_RESULT);
        }
        for block in key.chunks_mut(DES_KEY_BYTES) {
            let value: [u8; DES_KEY_BYTES] = block.try_into().expect("a full component");
            block.copy_from_slice(&set_odd_byte_parity(u64::from_be_bytes(value)).to_be_bytes());
        }
        if validate_tdes_key(&key) {
            return Ok(key);
        }
    }
    Err(TPM_RC_NO_RESULT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rand(label: &[u8]) -> SeededRand {
        SeededRand::instantiate(&[0x4d; 64], b"TDES", label, &[], 1, false)
            .expect("a non-empty derivation input")
    }

    fn odd_parity(byte: u8) -> bool {
        byte.count_ones() % 2 == 1
    }

    const TWO_KEY: [u8; 16] = [
        0x01, 0x02, 0x04, 0x07, 0x08, 0x0b, 0x0d, 0x0e, 0x10, 0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c,
        0x1f,
    ];
    const THREE_KEY: [u8; 24] = [
        0x01, 0x02, 0x04, 0x07, 0x08, 0x0b, 0x0d, 0x0e, 0x10, 0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c,
        0x1f, 0x20, 0x23, 0x25, 0x26, 0x29, 0x2a, 0x2c, 0x2f,
    ];

    #[test]
    fn the_weak_key_table_matches_the_vendored_size_and_bounds() {
        assert_eq!(DES_WEAK_KEYS.len(), 64);
        assert_eq!(DES_WEAK_KEYS[0], 0x0101_0101_0101_0101);
        assert_eq!(DES_WEAK_KEYS[1], 0xfefe_fefe_fefe_fefe);
        assert_eq!(DES_WEAK_KEYS[63], 0xfefe_e0e0_fefe_f1f1);
    }

    #[test]
    fn every_weak_key_already_carries_odd_parity() {
        for key in DES_WEAK_KEYS {
            assert_eq!(set_odd_byte_parity(key), key, "key {key:#018x}");
            assert!(is_weak_key(key));
        }
    }

    #[test]
    fn setting_parity_makes_every_byte_odd_and_never_zero() {
        for seed in [0u64, u64::MAX, 0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210] {
            let adjusted = set_odd_byte_parity(seed);
            for byte in adjusted.to_be_bytes() {
                assert!(odd_parity(byte), "seed {seed:#018x} byte {byte:#04x}");
                assert_ne!(byte, 0);
            }
        }
    }

    #[test]
    fn setting_parity_only_touches_the_least_significant_bit_of_each_byte() {
        for seed in [0u64, 0x5555_5555_5555_5555, 0xaaaa_aaaa_aaaa_aaaa] {
            let adjusted = set_odd_byte_parity(seed);
            assert_eq!(adjusted & !PARITY_MASK, seed & !PARITY_MASK, "{seed:#018x}");
        }
    }

    #[test]
    fn setting_parity_is_idempotent() {
        for seed in [0u64, 1, 0x0f0f_0f0f_0f0f_0f0f, u64::MAX] {
            let once = set_odd_byte_parity(seed);
            assert_eq!(set_odd_byte_parity(once), once);
        }
    }

    #[test]
    fn a_well_formed_two_key_and_three_key_value_validates() {
        assert!(validate_tdes_key(&TWO_KEY));
        assert!(validate_tdes_key(&THREE_KEY));
    }

    #[test]
    fn only_sixteen_and_twenty_four_byte_keys_validate() {
        for length in [0usize, 8, 9, 15, 17, 23, 25, 32] {
            let key = vec![0x01u8; length];
            assert!(!validate_tdes_key(&key), "length {length}");
        }
    }

    #[test]
    fn a_weak_component_in_any_position_is_rejected() {
        for position in 0..3 {
            let mut key = THREE_KEY;
            key[position * 8..(position + 1) * 8].copy_from_slice(&DES_WEAK_KEYS[0].to_be_bytes());
            assert!(!validate_tdes_key(&key), "component {position}");
        }
        for weak in DES_WEAK_KEYS {
            let mut key = TWO_KEY;
            key[..8].copy_from_slice(&weak.to_be_bytes());
            assert!(!validate_tdes_key(&key), "weak {weak:#018x}");
        }
    }

    #[test]
    fn repeated_adjacent_components_are_rejected() {
        let mut key = TWO_KEY;
        key.copy_within(0..8, 8);
        assert!(!validate_tdes_key(&key), "K1 == K2");

        let mut key = THREE_KEY;
        key.copy_within(8..16, 16);
        assert!(!validate_tdes_key(&key), "K2 == K3");
    }

    #[test]
    fn a_repeated_first_and_third_component_is_accepted_like_upstream() {
        let mut key = THREE_KEY;
        key.copy_within(0..8, 16);
        assert!(
            validate_tdes_key(&key),
            "only K1!=K2 and K2!=K3 are checked"
        );
    }

    #[test]
    fn components_are_compared_after_parity_normalization() {
        let mut key = TWO_KEY;
        key[..8].copy_from_slice(&[0x00; 8]);
        assert!(
            !validate_tdes_key(&key),
            "an all-zero component normalizes onto the first weak key"
        );

        let mut key = TWO_KEY;
        for byte in &mut key[8..] {
            *byte &= 0xfe;
        }
        let second = key[8..].to_vec();
        key[..8].copy_from_slice(&second);
        assert!(
            !validate_tdes_key(&key),
            "components that differ only in parity bits are equal after normalization"
        );
    }

    #[test]
    fn a_key_without_odd_parity_validates_on_its_normalized_components() {
        let mut key = TWO_KEY;
        for byte in &mut key {
            *byte &= 0xfe;
        }
        assert!(
            validate_tdes_key(&key),
            "upstream normalizes parity before checking"
        );
    }

    #[test]
    fn a_generated_key_has_the_requested_length_and_odd_parity() {
        for key_bits in [128u16, 192] {
            let key = generate_tdes_key(key_bits, &mut rand(b"gen")).expect("a key");
            assert_eq!(key.len(), usize::from(key_bits) / 8);
            for byte in &key {
                assert!(odd_parity(*byte), "bits {key_bits} byte {byte:#04x}");
            }
            assert!(validate_tdes_key(&key));
        }
    }

    #[test]
    fn a_generated_key_is_deterministic_in_the_generator_state() {
        let first = generate_tdes_key(192, &mut rand(b"same")).expect("a key");
        let second = generate_tdes_key(192, &mut rand(b"same")).expect("a key");
        assert_eq!(first, second);
        let other = generate_tdes_key(192, &mut rand(b"other")).expect("a key");
        assert_ne!(first, other);
    }

    #[test]
    fn only_two_and_three_component_key_sizes_can_be_generated() {
        for key_bits in [8u16, 64, 72, 256, 320] {
            assert_eq!(
                generate_tdes_key(key_bits, &mut rand(b"size")).err(),
                Some(TPM_RC_SYMMETRIC),
                "bits {key_bits}"
            );
        }
        assert!(generate_tdes_key(128, &mut rand(b"size")).is_ok());
        assert!(generate_tdes_key(192, &mut rand(b"size")).is_ok());
    }

    #[test]
    fn the_generation_retry_budget_matches_the_rsa_prime_search() {
        assert_eq!(MAX_GENERATION_ATTEMPTS, 100);
    }

    #[test]
    fn generation_draws_a_fresh_block_until_the_key_validates() {
        let mut counting = rand(b"retry");
        let key = generate_tdes_key(128, &mut counting).expect("a key");
        let mut replay = rand(b"retry");
        let raw = replay.random_bytes(16).unwrap();
        let mut expected = raw.clone();
        for block in expected.chunks_mut(8) {
            let value: [u8; 8] = block.try_into().unwrap();
            block.copy_from_slice(&set_odd_byte_parity(u64::from_be_bytes(value)).to_be_bytes());
        }
        assert_eq!(
            key, expected,
            "the first draw already yields a valid key here"
        );
    }
}
