// Part of the Rust port of libtpms.
//
// Project licensing and upstream notices: LICENSE and LICENSES/README.md.
//
// Rust implementation:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use core::cell::Cell;

thread_local! {
    static PRIMALITY_TESTS: Cell<u64> = const { Cell::new(0) };
    static SIEVED_CANDIDATES: Cell<u64> = const { Cell::new(0) };
    static SIEVE_PASSES: Cell<u64> = const { Cell::new(0) };
    static GENERATION_ATTEMPTS: Cell<u64> = const { Cell::new(0) };
    static GENERATOR_BYTES: Cell<u64> = const { Cell::new(0) };
    static HASH_UPDATES: Cell<u64> = const { Cell::new(0) };
    static HASHED_BYTES: Cell<u64> = const { Cell::new(0) };
    static HASH_FINALIZATIONS: Cell<u64> = const { Cell::new(0) };
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::library::tpm2) struct Counters {
    pub(in crate::library::tpm2) primality_tests: u64,
    pub(in crate::library::tpm2) sieved_candidates: u64,
    pub(in crate::library::tpm2) sieve_passes: u64,
    pub(in crate::library::tpm2) generation_attempts: u64,
    pub(in crate::library::tpm2) generator_bytes: u64,
    pub(in crate::library::tpm2) hash_updates: u64,
    pub(in crate::library::tpm2) hashed_bytes: u64,
    pub(in crate::library::tpm2) hash_finalizations: u64,
}

fn bump(counter: &'static std::thread::LocalKey<Cell<u64>>, amount: u64) {
    counter.with(|cell| cell.set(cell.get().saturating_add(amount)));
}

pub(in crate::library::tpm2) fn count_primality_test() {
    bump(&PRIMALITY_TESTS, 1);
}

pub(in crate::library::tpm2) fn count_sieved_candidate() {
    bump(&SIEVED_CANDIDATES, 1);
}

pub(in crate::library::tpm2) fn count_sieve_pass() {
    bump(&SIEVE_PASSES, 1);
}

pub(in crate::library::tpm2) fn count_generation_attempt() {
    bump(&GENERATION_ATTEMPTS, 1);
}

pub(in crate::library::tpm2) fn count_generator_bytes(length: usize) {
    bump(&GENERATOR_BYTES, length as u64);
}

pub(in crate::library::tpm2) fn count_hash_update(length: usize) {
    bump(&HASH_UPDATES, 1);
    bump(&HASHED_BYTES, length as u64);
}

pub(in crate::library::tpm2) fn count_hash_finalization() {
    bump(&HASH_FINALIZATIONS, 1);
}

const ALL: [&std::thread::LocalKey<Cell<u64>>; 8] = [
    &PRIMALITY_TESTS,
    &SIEVED_CANDIDATES,
    &SIEVE_PASSES,
    &GENERATION_ATTEMPTS,
    &GENERATOR_BYTES,
    &HASH_UPDATES,
    &HASHED_BYTES,
    &HASH_FINALIZATIONS,
];

pub(in crate::library::tpm2) fn reset() {
    for counter in ALL {
        counter.with(|cell| cell.set(0));
    }
}

pub(in crate::library::tpm2) fn snapshot() -> Counters {
    let read = |counter: &'static std::thread::LocalKey<Cell<u64>>| counter.with(Cell::get);
    Counters {
        primality_tests: read(&PRIMALITY_TESTS),
        sieved_candidates: read(&SIEVED_CANDIDATES),
        sieve_passes: read(&SIEVE_PASSES),
        generation_attempts: read(&GENERATION_ATTEMPTS),
        generator_bytes: read(&GENERATOR_BYTES),
        hash_updates: read(&HASH_UPDATES),
        hashed_bytes: read(&HASHED_BYTES),
        hash_finalizations: read(&HASH_FINALIZATIONS),
    }
}

pub(in crate::library::tpm2) fn measure<T>(body: impl FnOnce() -> T) -> (T, Counters) {
    reset();
    let result = body();
    (result, snapshot())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_zero_start_and_reset() {
        reset();
        assert_eq!(snapshot(), Counters::default());
        count_primality_test();
        count_sieved_candidate();
        count_sieve_pass();
        count_generation_attempt();
        count_generator_bytes(7);
        count_hash_update(5);
        count_hash_finalization();
        assert_eq!(
            snapshot(),
            Counters {
                primality_tests: 1,
                sieved_candidates: 1,
                sieve_passes: 1,
                generation_attempts: 1,
                generator_bytes: 7,
                hash_updates: 1,
                hashed_bytes: 5,
                hash_finalizations: 1,
            }
        );
        reset();
        assert_eq!(snapshot(), Counters::default());
    }

    #[test]
    fn measurement_body_work_accounting() {
        let (value, counters) = measure(|| {
            count_hash_update(3);
            count_hash_update(4);
            42
        });
        assert_eq!(value, 42);
        assert_eq!(counters.hash_updates, 2);
        assert_eq!(counters.hashed_bytes, 7);
        assert_eq!(snapshot(), counters);
    }
}
