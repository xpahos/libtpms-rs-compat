// Part of the Rust port of libtpms.
//
// Project licensing and upstream notices: LICENSE and LICENSES/README.md.
//
// Rust implementation:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use core::cell::Cell;

thread_local! {
    static MODULAR_MULTIPLICATIONS: Cell<u64> = const { Cell::new(0) };
    static PRIMALITY_TESTS: Cell<u64> = const { Cell::new(0) };
    static SIEVED_CANDIDATES: Cell<u64> = const { Cell::new(0) };
    static SIEVE_PASSES: Cell<u64> = const { Cell::new(0) };
    static GENERATION_ATTEMPTS: Cell<u64> = const { Cell::new(0) };
    static GENERATOR_BYTES: Cell<u64> = const { Cell::new(0) };
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::library::tpm2) struct Counters {
    pub(in crate::library::tpm2) modular_multiplications: u64,
    pub(in crate::library::tpm2) primality_tests: u64,
    pub(in crate::library::tpm2) sieved_candidates: u64,
    pub(in crate::library::tpm2) sieve_passes: u64,
    pub(in crate::library::tpm2) generation_attempts: u64,
    pub(in crate::library::tpm2) generator_bytes: u64,
}

pub(in crate::library::tpm2) fn count_modular_multiplication() {
    MODULAR_MULTIPLICATIONS.with(|counter| counter.set(counter.get() + 1));
}

pub(in crate::library::tpm2) fn count_primality_test() {
    PRIMALITY_TESTS.with(|counter| counter.set(counter.get() + 1));
}

pub(in crate::library::tpm2) fn count_sieved_candidate() {
    SIEVED_CANDIDATES.with(|counter| counter.set(counter.get() + 1));
}

pub(in crate::library::tpm2) fn count_sieve_pass() {
    SIEVE_PASSES.with(|counter| counter.set(counter.get() + 1));
}

pub(in crate::library::tpm2) fn count_generation_attempt() {
    GENERATION_ATTEMPTS.with(|counter| counter.set(counter.get() + 1));
}

pub(in crate::library::tpm2) fn count_generator_bytes(length: usize) {
    GENERATOR_BYTES.with(|counter| counter.set(counter.get() + length as u64));
}

pub(in crate::library::tpm2) fn reset() {
    MODULAR_MULTIPLICATIONS.with(|counter| counter.set(0));
    PRIMALITY_TESTS.with(|counter| counter.set(0));
    SIEVED_CANDIDATES.with(|counter| counter.set(0));
    SIEVE_PASSES.with(|counter| counter.set(0));
    GENERATION_ATTEMPTS.with(|counter| counter.set(0));
    GENERATOR_BYTES.with(|counter| counter.set(0));
}

pub(in crate::library::tpm2) fn snapshot() -> Counters {
    Counters {
        modular_multiplications: MODULAR_MULTIPLICATIONS.with(Cell::get),
        primality_tests: PRIMALITY_TESTS.with(Cell::get),
        sieved_candidates: SIEVED_CANDIDATES.with(Cell::get),
        sieve_passes: SIEVE_PASSES.with(Cell::get),
        generation_attempts: GENERATION_ATTEMPTS.with(Cell::get),
        generator_bytes: GENERATOR_BYTES.with(Cell::get),
    }
}

pub(in crate::library::tpm2) fn measure<T>(body: impl FnOnce() -> T) -> (T, Counters) {
    reset();
    let value = body();
    (value, snapshot())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_zero_start_and_reset() {
        reset();
        assert_eq!(snapshot(), Counters::default());
        count_modular_multiplication();
        count_primality_test();
        count_sieved_candidate();
        count_sieve_pass();
        count_generation_attempt();
        count_generator_bytes(7);
        assert_eq!(
            snapshot(),
            Counters {
                modular_multiplications: 1,
                primality_tests: 1,
                sieved_candidates: 1,
                sieve_passes: 1,
                generation_attempts: 1,
                generator_bytes: 7,
            }
        );
        reset();
        assert_eq!(snapshot(), Counters::default());
    }

    #[test]
    fn measurement_body_work_accounting() {
        let (value, counters) = measure(|| {
            for _ in 0..5 {
                count_modular_multiplication();
            }
            count_generator_bytes(192);
            "done"
        });
        assert_eq!(value, "done");
        assert_eq!(counters.modular_multiplications, 5);
        assert_eq!(counters.generator_bytes, 192);
        assert_eq!(counters.primality_tests, 0);
    }
}
