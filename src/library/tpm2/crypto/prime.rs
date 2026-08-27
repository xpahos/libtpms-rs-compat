use crate::ffi::types::TpmResult;

use super::bignum::BigUint;
use super::rand_state::{SEED_COMPAT_LEVEL_RSA_PRIME_ADJUST_FIX, SeededRand};

pub(in crate::library::tpm2) const LAST_PRIME_IN_TABLE: u32 = 65537;
pub(in crate::library::tpm2) const PRIME_TABLE_SIZE: usize = 4097;
pub(in crate::library::tpm2) const PRIMES_IN_TABLE: u32 = 6542;

const HIGHEST_TABLE_VALUE: u32 = (PRIME_TABLE_SIZE as u32 * 8 - 1) * 2 + 1;

const PRIME_TABLE: [u8; PRIME_TABLE_SIZE] = build_prime_table();

const fn build_prime_table() -> [u8; PRIME_TABLE_SIZE] {
    let mut table = [0xffu8; PRIME_TABLE_SIZE];
    table[0] &= !1;
    let mut index = 1u32;
    while (2 * index + 1) * (2 * index + 1) <= HIGHEST_TABLE_VALUE {
        if table[(index >> 3) as usize] & (1 << (index & 7)) != 0 {
            let prime = 2 * index + 1;
            let mut multiple = prime * prime;
            while multiple <= HIGHEST_TABLE_VALUE {
                let bit = (multiple - 1) / 2;
                table[(bit >> 3) as usize] &= !(1 << (bit & 7));
                multiple += 2 * prime;
            }
        }
        index += 1;
    }
    table
}

const SEED_VALUES_SIZE: usize = 105;

const SEED_VALUES: [u8; SEED_VALUES_SIZE] = build_seed_values();

const fn build_seed_values() -> [u8; SEED_VALUES_SIZE] {
    let mut values = [0u8; SEED_VALUES_SIZE];
    let mut bit = 0usize;
    while bit < SEED_VALUES_SIZE * 8 {
        if bit % 3 != 0 && bit % 5 != 0 && bit % 7 != 0 {
            values[bit / 8] |= 1 << (bit % 8);
        }
        bit += 1;
    }
    values
}

const PRIME_MARKERS: [u32; 6] = [8167, 17881, 28183, 38891, 49871, 60961];

struct SieveMark {
    prime: u32,
    count: u32,
}

const SIEVE_MARKS: [SieveMark; 6] = [
    SieveMark {
        prime: 31,
        count: 7,
    },
    SieveMark {
        prime: 73,
        count: 5,
    },
    SieveMark {
        prime: 241,
        count: 4,
    },
    SieveMark {
        prime: 1621,
        count: 3,
    },
    SieveMark {
        prime: u16::MAX as u32,
        count: 2,
    },
    SieveMark {
        prime: u32::MAX,
        count: 1,
    },
];

pub(in crate::library::tpm2) const MAX_FIELD_SIZE: usize = 2048;

fn table_bit(index: u32) -> bool {
    let byte = (index >> 3) as usize;
    byte < PRIME_TABLE_SIZE && PRIME_TABLE[byte] & (1 << (index & 7)) != 0
}

fn clear_bit(field: &mut [u8], bit: usize) {
    field[bit >> 3] &= !(1 << (bit & 7));
}

fn bits_in_byte(value: u8) -> u32 {
    value.count_ones()
}

fn bits_in_array(field: &[u8]) -> u32 {
    field.iter().map(|byte| bits_in_byte(*byte)).sum()
}

fn root2(n: u32) -> u32 {
    let mut last = (n >> 2) as i64;
    let mut next = (n >> 1) as i64;
    while next != 0 {
        last >>= 1;
        next >>= 2;
    }
    last += 1;
    loop {
        let candidate = (last + (i64::from(n) / last)) >> 1;
        let difference = candidate - last;
        last = candidate;
        if (-1..=1).contains(&difference) {
            break;
        }
    }
    if i64::from(n) / last > last {
        last += 1;
    }
    last as u32
}

pub(in crate::library::tpm2) fn is_prime_int(n: u32) -> bool {
    if n < 3 || n & 1 == 0 {
        return n == 2;
    }
    if n <= LAST_PRIME_IN_TABLE {
        return table_bit(n >> 1);
    }
    let stop = root2(n) >> 1;
    let mut index = 1u32;
    while index < stop {
        if table_bit(index) && n % ((index << 1) + 1) == 0 {
            return false;
        }
        index += 1;
    }
    true
}

pub(in crate::library::tpm2) fn adjust_prime_limit(
    requested_primes: u32,
    seed_compat_level: u8,
) -> u32 {
    let mut requested = requested_primes;
    if requested == 0 || requested > PRIMES_IN_TABLE {
        requested = PRIMES_IN_TABLE;
    }
    requested = (requested - 1) / 1024;
    let limit = match PRIME_MARKERS.get(requested as usize) {
        Some(marker) => *marker,
        None if seed_compat_level <= SEED_COMPAT_LEVEL_RSA_PRIME_ADJUST_FIX => {
            LAST_PRIME_IN_TABLE - 2
        }
        None => LAST_PRIME_IN_TABLE,
    };
    limit >> 1
}

pub(in crate::library::tpm2) fn next_prime(last_prime: u32, prime_limit: u32) -> u32 {
    if last_prime == 0 {
        return 0;
    }
    let mut index = last_prime >> 1;
    index += 1;
    while index <= prime_limit {
        if table_bit(index) {
            return (index << 1) + 1;
        }
        index += 1;
    }
    0
}

pub(in crate::library::tpm2) fn find_nth_set_bit(field: &[u8], n: u32) -> i32 {
    if n < 1 || field.is_empty() {
        return -1;
    }
    let mut sum = 0u32;
    let mut index = 0usize;
    while index < field.len() && sum < n {
        sum += bits_in_byte(field[index]);
        index += 1;
    }
    index -= 1;
    let mut result = index as i32 * 8 - 1;
    let mut selection = field[index];
    sum -= bits_in_byte(selection);
    while selection != 0 && sum != n {
        sum += u32::from(selection & 1 != 0);
        result += 1;
        selection >>= 1;
    }
    if sum == n { result } else { -1 }
}

pub(in crate::library::tpm2) fn prime_sieve(
    candidate: &mut BigUint,
    field: &mut [u8],
    prime_limit: u32,
) -> u32 {
    let field_size = field.len();
    let field_bits = field_size * 8;

    let mut adjust = candidate.mod_u64(105) as u32;
    if adjust & 1 != 0 {
        adjust += 105;
    }
    *candidate = candidate
        .sub_u64(u64::from(adjust))
        .unwrap_or_else(BigUint::zero);

    for (offset, chunk) in field.chunks_mut(SEED_VALUES_SIZE).enumerate() {
        let _ = offset;
        let length = chunk.len();
        chunk.copy_from_slice(&SEED_VALUES[..length]);
    }

    let mut iter = 7u32;
    let mut mark = 0usize;
    let mut count = SIEVE_MARKS[0].count;
    let mut stop = SIEVE_MARKS[0].prime;
    let mut list = [0u32; 8];

    loop {
        let mut composite = next_prime(iter, prime_limit);
        iter = composite;
        if composite == 0 {
            break;
        }
        let mut next = 0u32;
        let mut index = count as usize;
        list[index] = composite;
        index -= 1;
        while index > 0 {
            next = next_prime(iter, prime_limit);
            iter = next;
            list[index] = next;
            if next != 0 {
                composite = composite.wrapping_mul(next);
            }
            index -= 1;
        }

        let residue = candidate.mod_u64(u64::from(composite)) as u32;

        let mut index = count as usize;
        let mut exhausted = false;
        while index > 0 {
            next = list[index];
            if next == 0 {
                exhausted = true;
                break;
            }
            let remainder = residue % next;
            let mut position = if remainder & 1 != 0 {
                (next - remainder) / 2
            } else if remainder == 0 {
                0
            } else {
                next - (remainder / 2)
            } as usize;
            while position < field_bits {
                clear_bit(field, position);
                position += next as usize;
            }
            index -= 1;
        }
        if exhausted {
            break;
        }

        if next >= stop {
            mark += 1;
            if mark >= SIEVE_MARKS.len() {
                break;
            }
            count = SIEVE_MARKS[mark].count;
            stop = SIEVE_MARKS[mark].prime;
        }
    }

    bits_in_array(field)
}

pub(in crate::library::tpm2) fn miller_rabin_rounds(bits: usize) -> u32 {
    if bits < 511 {
        return 8;
    }
    if bits < 1536 {
        return 5;
    }
    4
}

pub(in crate::library::tpm2) fn miller_rabin(
    witness: &BigUint,
    rand: &mut SeededRand,
) -> Result<bool, TpmResult> {
    #[cfg(test)]
    super::work::count_primality_test();
    let iterations = miller_rabin_rounds(witness.bit_len());
    let Some(minus_one) = witness.sub_u64(1) else {
        return Ok(false);
    };
    if minus_one.is_zero() {
        return Ok(false);
    }
    let mut power = 1usize;
    while power < minus_one.bit_len() && !minus_one.test_bit(power) {
        power += 1;
    }
    let odd_part = minus_one.shr(power);
    let witness_bits = witness.bit_len();

    for _ in 0..iterations {
        let base = loop {
            let candidate = rand.random_integer(witness_bits)?;
            if candidate > BigUint::from_u64(1) && candidate < minus_one {
                break candidate;
            }
        };
        let mut value = base
            .mod_exp(&odd_part, witness)
            .ok_or(crate::library::constants::TPM_RC_FAILURE)?;
        if value == BigUint::from_u64(1) || value == minus_one {
            continue;
        }
        let mut composite = true;
        for _ in 1..power {
            value = value
                .mod_mul(&value, witness)
                .ok_or(crate::library::constants::TPM_RC_FAILURE)?;
            if value == minus_one {
                composite = false;
                break;
            }
            if value == BigUint::from_u64(1) {
                return Ok(false);
            }
        }
        if composite {
            return Ok(false);
        }
    }
    Ok(true)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) enum PrimeSelection {
    Found,
    NoResult,
}

pub(in crate::library::tpm2) fn prime_select_with_sieve(
    candidate: &mut BigUint,
    exponent: u32,
    rand: &mut SeededRand,
) -> Result<PrimeSelection, TpmResult> {
    let prime_size = candidate.bit_len();
    let prime_limit = if prime_size <= 512 {
        adjust_prime_limit(1024, rand.seed_compat_level())
    } else if prime_size <= 1024 {
        adjust_prime_limit(4096, rand.seed_compat_level())
    } else {
        adjust_prime_limit(0, rand.seed_compat_level())
    };

    let first = candidate.low_u32() | 0x8000_0000;

    let mut field = [0u8; MAX_FIELD_SIZE];
    #[cfg(test)]
    super::work::count_sieve_pass();
    let mut ones = prime_sieve(candidate, &mut field, prime_limit);

    while ones > 0 {
        #[cfg(test)]
        super::work::count_sieved_candidate();
        let chosen = find_nth_set_bit(&field, (first % ones) + 1);
        if chosen < 0 || chosen >= (MAX_FIELD_SIZE * 8) as i32 {
            return Err(crate::library::constants::TPM_RC_FAILURE);
        }
        let test = candidate.add_u64(chosen as u64 * 2);
        let residue = test.mod_u64(u64::from(exponent)) as u32;
        if residue != 0 && residue != 1 && miller_rabin(&test, rand)? {
            *candidate = test;
            return Ok(PrimeSelection::Found);
        }
        clear_bit(&mut field, chosen as usize);
        ones -= 1;
    }
    Ok(PrimeSelection::NoResult)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_is_prime(n: u32) -> bool {
        if n < 2 {
            return false;
        }
        let mut divisor = 2u64;
        while divisor * divisor <= u64::from(n) {
            if u64::from(n) % divisor == 0 {
                return false;
            }
            divisor += 1;
        }
        true
    }

    fn rand() -> SeededRand {
        SeededRand::instantiate(&[0x33; 64], b"PRIME", &[0x44; 34], &[], 1, false)
            .expect("a non-empty derivation input")
    }

    #[test]
    fn the_table_constants_match_upstream() {
        assert_eq!(LAST_PRIME_IN_TABLE, 65537);
        assert_eq!(PRIME_TABLE_SIZE, 4097);
        assert_eq!(PRIMES_IN_TABLE, 6542);
        assert_eq!(PRIME_MARKERS, [8167, 17881, 28183, 38891, 49871, 60961]);
    }

    #[test]
    fn the_first_prime_table_bytes_match_the_vendored_table() {
        assert_eq!(
            &PRIME_TABLE[..13],
            &[
                0x6e, 0xcb, 0xb4, 0x64, 0x9a, 0x12, 0x6d, 0x81, 0x32, 0x4c, 0x4a, 0x86, 0x0d
            ]
        );
    }

    #[test]
    fn the_prime_table_marks_exactly_the_odd_primes_below_the_last_entry() {
        let mut count = 1;
        for value in (3..=LAST_PRIME_IN_TABLE).step_by(2) {
            assert_eq!(
                table_bit(value >> 1),
                reference_is_prime(value),
                "value {value}"
            );
            if reference_is_prime(value) && value < LAST_PRIME_IN_TABLE {
                count += 1;
            }
        }
        assert_eq!(count, PRIMES_IN_TABLE, "including the even prime two");
        assert!(table_bit(LAST_PRIME_IN_TABLE >> 1), "65537 is prime");
        assert!(!table_bit(0), "one is not prime");
    }

    #[test]
    fn the_integer_primality_test_agrees_with_trial_division() {
        for n in 0..20_000u32 {
            assert_eq!(is_prime_int(n), reference_is_prime(n), "n {n}");
        }
        for n in [
            65_537u32,
            65_539,
            100_003,
            100_005,
            1_000_003,
            1_000_005,
            4_294_967_291,
            4_294_967_293,
        ] {
            assert_eq!(is_prime_int(n), reference_is_prime(n), "n {n}");
        }
    }

    #[test]
    fn the_default_public_exponent_and_its_neighbours_classify_correctly() {
        assert!(is_prime_int(65537));
        assert!(!is_prime_int(65536));
        assert!(!is_prime_int(65538));
        assert!(is_prime_int(2));
        assert!(!is_prime_int(1));
        assert!(!is_prime_int(0));
    }

    #[test]
    fn the_integer_square_root_bounds_the_trial_division_loop() {
        for n in (3..5_000u32).chain([65_539, 1_000_003, 4_294_967_291]) {
            let root = root2(n);
            assert!(root != 0, "n {n}");
            assert!(n / root <= root, "n {n} root {root}");
            assert!(n / (root + 1) < root, "n {n} root {root}");
        }
        assert_eq!(root2(9), 3);
        assert_eq!(root2(16), 4);
        assert_eq!(root2(17), 4, "the bound stays at the floor when it divides");
        assert_eq!(root2(20), 5, "the bound rises when the floor divides short");
    }

    #[test]
    fn the_first_seed_value_bytes_match_the_vendored_table() {
        assert_eq!(
            &SEED_VALUES[..12],
            &[
                0x16, 0x29, 0xcb, 0xa4, 0x65, 0xda, 0x30, 0x6c, 0x99, 0x96, 0x4c, 0x53
            ]
        );
        assert_eq!(SEED_VALUES[SEED_VALUES_SIZE - 1], 0xd1);
    }

    #[test]
    fn the_seed_values_clear_every_multiple_of_three_five_and_seven() {
        for bit in 0..SEED_VALUES_SIZE * 8 {
            let set = SEED_VALUES[bit / 8] & (1 << (bit % 8)) != 0;
            let coprime = bit % 3 != 0 && bit % 5 != 0 && bit % 7 != 0;
            assert_eq!(set, coprime, "bit {bit}");
        }
    }

    #[test]
    fn the_prime_limit_follows_the_marker_table() {
        assert_eq!(adjust_prime_limit(1024, 1), 8167 >> 1);
        assert_eq!(adjust_prime_limit(1025, 1), 17881 >> 1);
        assert_eq!(adjust_prime_limit(4096, 1), 38891 >> 1);
        assert_eq!(adjust_prime_limit(6144, 1), 60961 >> 1);
        assert_eq!(adjust_prime_limit(0, 1), (LAST_PRIME_IN_TABLE - 2) >> 1);
        assert_eq!(
            adjust_prime_limit(PRIMES_IN_TABLE, 1),
            (LAST_PRIME_IN_TABLE - 2) >> 1
        );
        assert_eq!(
            adjust_prime_limit(u32::MAX, 1),
            (LAST_PRIME_IN_TABLE - 2) >> 1
        );
    }

    #[test]
    fn the_prime_limit_keeps_the_pre_fix_reduction_for_every_supported_seed_level() {
        for level in 0..=SEED_COMPAT_LEVEL_RSA_PRIME_ADJUST_FIX {
            assert_eq!(
                adjust_prime_limit(0, level),
                (LAST_PRIME_IN_TABLE - 2) >> 1,
                "level {level}"
            );
        }
    }

    #[test]
    fn the_prime_iterator_walks_the_table_in_order() {
        let limit = adjust_prime_limit(0, 1);
        let mut prime = 7;
        let expected = [11u32, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47];
        for value in expected {
            prime = next_prime(prime, limit);
            assert_eq!(prime, value);
        }
    }

    #[test]
    fn the_prime_iterator_stops_at_the_limit() {
        let limit = adjust_prime_limit(1024, 1);
        let mut prime = 8161u32;
        prime = next_prime(prime, limit);
        assert_eq!(prime, 8167, "the marker itself is still returned");
        assert_eq!(next_prime(prime, limit), 0);
        assert_eq!(next_prime(0, limit), 0, "a zero seed terminates");
    }

    #[test]
    fn the_prime_iterator_reaches_the_last_table_entry_under_the_full_limit() {
        let limit = adjust_prime_limit(0, 1);
        let mut prime = 65_500u32;
        prime = next_prime(prime, limit);
        assert_eq!(prime, 65_519);
        prime = next_prime(prime, limit);
        assert_eq!(prime, 65_521);
        assert_eq!(next_prime(prime, limit), 0, "65537 is above the limit");
    }

    #[test]
    fn the_nth_set_bit_is_found_by_counting_from_the_first_byte() {
        let field = [0b0000_0001u8, 0b0000_0000, 0b1000_0001];
        assert_eq!(find_nth_set_bit(&field, 1), 0);
        assert_eq!(find_nth_set_bit(&field, 2), 16);
        assert_eq!(find_nth_set_bit(&field, 3), 23);
        assert_eq!(find_nth_set_bit(&field, 4), -1);
        assert_eq!(find_nth_set_bit(&field, 0), -1);
        assert_eq!(find_nth_set_bit(&[], 1), -1);
    }

    #[test]
    fn every_set_bit_is_reachable_by_its_own_index() {
        let field: Vec<u8> = (0..64u8).map(|index| index.wrapping_mul(37)).collect();
        let mut expected = Vec::new();
        for bit in 0..field.len() * 8 {
            if field[bit / 8] & (1 << (bit % 8)) != 0 {
                expected.push(bit as i32);
            }
        }
        for (order, bit) in expected.iter().enumerate() {
            assert_eq!(find_nth_set_bit(&field, order as u32 + 1), *bit);
        }
        assert_eq!(find_nth_set_bit(&field, expected.len() as u32 + 1), -1);
    }

    #[test]
    fn the_sieve_aligns_the_candidate_to_an_odd_multiple_of_one_hundred_five() {
        for start in [1_000_001u64, 1_000_003, 1_000_005, 105, 211] {
            let mut candidate = BigUint::from_u64(start);
            let mut field = [0u8; 512];
            prime_sieve(&mut candidate, &mut field, adjust_prime_limit(1024, 1));
            assert_eq!(candidate.mod_u64(105), 0, "start {start}");
            assert!(candidate.is_odd(), "start {start}");
            assert!(candidate.low_u64() <= start, "start {start}");
            assert!(start - candidate.low_u64() < 210, "start {start}");
        }
    }

    #[test]
    fn every_surviving_sieve_bit_is_coprime_to_the_sieved_primes() {
        let mut candidate = BigUint::from_u64(1_000_003);
        let mut field = [0u8; 128];
        let limit = adjust_prime_limit(1024, 1);
        let ones = prime_sieve(&mut candidate, &mut field, limit);
        assert!(ones > 0);
        let base = candidate.low_u64();
        let mut counted = 0;
        for bit in 0..field.len() * 8 {
            if field[bit / 8] & (1 << (bit % 8)) == 0 {
                continue;
            }
            counted += 1;
            let value = base + 2 * bit as u64;
            let mut prime = 3u32;
            while prime <= 8167 {
                if is_prime_int(prime) {
                    assert!(value % u64::from(prime) != 0, "value {value} prime {prime}");
                }
                prime += 2;
            }
        }
        assert_eq!(counted, ones);
    }

    #[test]
    fn the_sieve_clears_every_value_divisible_by_a_sieved_prime() {
        let mut candidate = BigUint::from_u64(500_009);
        let mut field = [0u8; 64];
        let limit = adjust_prime_limit(1024, 1);
        prime_sieve(&mut candidate, &mut field, limit);
        let base = candidate.low_u64();
        for bit in 0..field.len() * 8 {
            let value = base + 2 * bit as u64;
            let survivor = field[bit / 8] & (1 << (bit % 8)) != 0;
            let divisible = (3..=8167u32)
                .step_by(2)
                .any(|prime| is_prime_int(prime) && value % u64::from(prime) == 0);
            assert_eq!(survivor, !divisible, "bit {bit} value {value}");
        }
    }

    #[test]
    fn miller_rabin_accepts_the_nist_curve_primes() {
        let mut generator = rand();
        let power = |bits: usize| BigUint::from_u64(1).shl(bits);
        let p256 = power(256)
            .sub(&power(224))
            .unwrap()
            .add(&power(192))
            .add(&power(96))
            .sub_u64(1)
            .unwrap();
        let p384 = power(384)
            .sub(&power(128))
            .unwrap()
            .sub(&power(96))
            .unwrap()
            .add(&power(32))
            .sub_u64(1)
            .unwrap();
        assert_eq!(p256.bit_len(), 256);
        assert_eq!(p384.bit_len(), 384);
        assert!(miller_rabin(&p256, &mut generator).unwrap());
        assert!(miller_rabin(&p384, &mut generator).unwrap());
    }

    #[test]
    fn miller_rabin_rejects_composites() {
        let mut generator = rand();
        for composite in [
            BigUint::from_u64(0xffff_ffff_ffff_fffd),
            BigUint::from_u64(3).mul(&BigUint::from_u64(1).shl(256).sub_u64(189).unwrap()),
            BigUint::from_u64(1).shl(521).sub_u64(3).unwrap(),
        ] {
            assert!(!miller_rabin(&composite, &mut generator).unwrap());
        }
    }

    #[test]
    fn miller_rabin_accepts_the_mersenne_prime() {
        let mut generator = rand();
        let prime = BigUint::from_u64(1).shl(521).sub_u64(1).unwrap();
        assert!(miller_rabin(&prime, &mut generator).unwrap());
    }

    #[test]
    fn the_round_count_follows_the_published_table() {
        assert_eq!(miller_rabin_rounds(0), 8);
        assert_eq!(miller_rabin_rounds(510), 8);
        assert_eq!(miller_rabin_rounds(511), 5);
        assert_eq!(miller_rabin_rounds(512), 5);
        assert_eq!(miller_rabin_rounds(1024), 5);
        assert_eq!(miller_rabin_rounds(1535), 5);
        assert_eq!(miller_rabin_rounds(1536), 4);
        assert_eq!(miller_rabin_rounds(3072), 4);
    }

    #[test]
    fn the_sieve_selection_returns_a_prime_congruent_to_the_exponent_rules() {
        let mut generator = rand();
        let mut candidate = generator.random_integer(512).unwrap();
        candidate.set_low_bit();
        let start = candidate.clone();
        assert_eq!(
            prime_select_with_sieve(&mut candidate, 65537, &mut generator).unwrap(),
            PrimeSelection::Found
        );
        assert!(miller_rabin(&candidate, &mut generator).unwrap());
        let residue = candidate.mod_u64(65537);
        assert_ne!(residue, 0);
        assert_ne!(residue, 1);
        assert!(candidate.bit_len() <= start.bit_len() + 1);
    }

    #[test]
    fn the_sieve_selection_is_deterministic_for_a_fixed_generator_state() {
        let run = || {
            let mut generator = rand();
            let mut candidate = generator.random_integer(512).unwrap();
            candidate.set_low_bit();
            prime_select_with_sieve(&mut candidate, 65537, &mut generator).unwrap();
            candidate
        };
        assert_eq!(run(), run());
    }
}
