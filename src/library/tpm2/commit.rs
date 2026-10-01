// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/BnEccConstants.c
// - libtpms/src/tpm2/crypto/openssl/CryptEccMain.c
//
// Original upstream authors and copyright notices:
// Written by Ken Goldman
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corp. and others, 2023
// (c) Copyright IBM Corp. and others, 2016 - 2024
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use subtle::ConstantTimeEq;

use crate::library::constants::TPM_RC_FAILURE;
use crate::types::TpmResult;

use super::crypto::{EccBackendError, EccCurve, EccScalar, kdfa_from};
use super::persistent::OwnedSecret;
use super::runtime::Tpm2Runtime;
use super::state::COMMIT_ARRAY_SIZE;
use super::ticket::CONTEXT_INTEGRITY_HASH_ALG;

const COMMIT_STRING: &[u8] = b"ECDAA Commit\0";
pub(super) const COMMIT_INDEX_MASK: u16 = (COMMIT_ARRAY_SIZE as u16 * 8) - 1;
const GENERATE_ITERATION_LIMIT: u32 = 1_000_000;

pub(super) struct CommitState {
    pub(super) counter: u64,
    pub(super) nonce: OwnedSecret,
    pub(super) array: [u8; COMMIT_ARRAY_SIZE],
}

fn commit_slot(count: u16) -> (usize, u8) {
    let bit = count & COMMIT_INDEX_MASK;
    (usize::from(bit >> 3), 1u8 << (bit & 7))
}

impl CommitState {
    pub(super) fn load(runtime: &Tpm2Runtime) -> Result<Self, TpmResult> {
        let reset = runtime.live.state_reset.as_ref().ok_or(TPM_RC_FAILURE)?;
        Ok(Self {
            counter: reset.commit_counter,
            nonce: reset.commit_nonce.clone(),
            array: reset.commit_array,
        })
    }

    pub(super) fn publish(&self, runtime: &mut Tpm2Runtime) -> Result<(), TpmResult> {
        let reset = runtime.live.state_reset.as_mut().ok_or(TPM_RC_FAILURE)?;
        reset.commit_counter = self.counter;
        reset.commit_array = self.array;
        Ok(())
    }

    pub(super) fn is_set(&self, count: u16) -> bool {
        let (byte, mask) = commit_slot(count);
        self.array[byte] & mask != 0
    }

    pub(super) fn counter_for(&self, count: u16) -> Option<u64> {
        if !self.is_set(count) {
            return None;
        }
        let mut current = self.counter;
        if (count & COMMIT_INDEX_MASK) >= (current as u16 & COMMIT_INDEX_MASK) {
            current = current.wrapping_sub(u64::from(COMMIT_INDEX_MASK) + 1);
        }
        if (current as u16) & !COMMIT_INDEX_MASK != count & !COMMIT_INDEX_MASK {
            return None;
        }
        Some((current & 0xffff_ffff_ffff_0000) | u64::from(count))
    }

    pub(super) fn commit(&mut self) -> u16 {
        let old = self.counter as u16;
        self.counter = self.counter.wrapping_add(1);
        let (byte, mask) = commit_slot(old);
        self.array[byte] |= mask;
        old
    }

    pub(super) fn end_commit(&mut self, count: u16) {
        let (byte, mask) = commit_slot(count);
        self.array[byte] &= !mask;
    }

    pub(super) fn generate_r(
        &self,
        curve: &EccCurve,
        name: &[u8],
        count: Option<u16>,
    ) -> Result<Option<EccScalar>, EccBackendError> {
        let context_v = match count {
            Some(count) => match self.counter_for(count) {
                Some(counter) => counter,
                None => return Ok(None),
            },
            None => self.counter,
        }
        .to_be_bytes();
        let order_bytes = curve.order_bytes();
        let Some(bits) = order_bytes
            .checked_mul(8)
            .and_then(|bits| u32::try_from(bits).ok())
        else {
            return Ok(None);
        };
        let mut counter: u32 = 1;
        while counter < GENERATE_ITERATION_LIMIT {
            let Some(stream) = kdfa_from(
                CONTEXT_INTEGRITY_HASH_ALG,
                self.nonce.as_bytes(),
                COMMIT_STRING,
                name,
                &context_v,
                bits,
                &mut counter,
            ) else {
                return Ok(None);
            };
            let stream = super::crypto::SecretBytes(stream);
            let stream = &stream.0;
            let upper_half = stream[..=order_bytes / 2]
                .iter()
                .fold(0u8, |acc, &byte| acc | byte);
            if let Some(r) = curve.scalar_below_order(stream)?
                && !bool::from(upper_half.ct_eq(&0))
            {
                return Ok(Some(r));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::crypto::is_compiled_curve;

    fn below_order(value: &EccScalar, curve: &EccCurve) -> bool {
        let order = curve.order();
        value
            .to_bytes(order.len())
            .expect("a scalar fits the order width")
            < order
    }

    fn state() -> CommitState {
        CommitState {
            counter: 0,
            nonce: OwnedSecret::from_vec(vec![0x5c; 64]),
            array: [0u8; COMMIT_ARRAY_SIZE],
        }
    }

    #[test]
    fn index_mask_full_array_coverage() {
        assert_eq!(COMMIT_ARRAY_SIZE, 16);
        assert_eq!(COMMIT_INDEX_MASK, 127);
        for count in [0u16, 1, 127] {
            let (byte, mask) = commit_slot(count);
            assert!(byte < COMMIT_ARRAY_SIZE);
            assert_eq!(mask.count_ones(), 1);
        }
        assert_eq!(commit_slot(128), commit_slot(0), "the index wraps");
    }

    #[test]
    fn commit_old_counter_return_and_bit_set() {
        let mut state = state();
        for expected in 0..4u16 {
            assert!(!state.is_set(expected));
            assert_eq!(state.commit(), expected);
            assert!(state.is_set(expected));
            assert_eq!(state.counter, u64::from(expected) + 1);
        }
    }

    #[test]
    fn consumed_commitment_resolution_rejection() {
        let mut state = state();
        let count = state.commit();
        assert_eq!(state.counter_for(count), Some(0));
        state.end_commit(count);
        assert_eq!(state.counter_for(count), None);
    }

    #[test]
    fn unallocated_counter_no_resolution() {
        let mut state = state();
        state.commit();
        for count in [1u16, 2, 64, 127, 128, 0xffff] {
            assert_eq!(state.counter_for(count), None, "count {count}");
        }
    }

    #[test]
    fn counter_upper_bits_request_check() {
        let mut state = state();
        state.counter = 0x0001_0000;
        let count = state.commit();
        assert_eq!(count, 0);
        assert_eq!(state.counter_for(0), Some(0x0001_0000));
        state.array = [0xff; COMMIT_ARRAY_SIZE];
        assert_eq!(
            state.counter_for(0x0001),
            None,
            "a count from the previous epoch is refused"
        );
    }

    #[test]
    fn bitmap_128_live_commitment_capacity() {
        let mut state = state();
        let mut counts = Vec::new();
        for _ in 0..128 {
            counts.push(state.commit());
        }
        assert_eq!(state.counter, 128);
        assert_eq!(state.array, [0xff; COMMIT_ARRAY_SIZE]);
        for (index, &count) in counts.iter().enumerate() {
            assert_eq!(
                state.counter_for(count),
                Some(index as u64),
                "count {count}"
            );
        }
        state.commit();
        assert_eq!(
            state.counter_for(counts[0]),
            None,
            "the reused slot now belongs to the newer commitment"
        );
    }

    #[test]
    fn counter_wrap_panic_safety() {
        let mut state = state();
        state.counter = u64::MAX;
        assert_eq!(state.commit(), 0xffff);
        assert_eq!(state.counter, 0);
    }

    #[test]
    fn generated_value_determinism_and_order_bound() {
        let curve = EccCurve::lookup(0x0003).expect("NIST P256");
        let state = state();
        let first = state
            .generate_r(&curve, b"", None)
            .unwrap()
            .expect("a commit value is produced");
        let second = state
            .generate_r(&curve, b"", None)
            .unwrap()
            .expect("a commit value is produced");
        assert_eq!(first, second);
        assert!(below_order(&first, &curve));
        assert!(!first.is_zero());
    }

    #[test]
    fn name_and_counter_generated_value_dependence() {
        let curve = EccCurve::lookup(0x0003).expect("NIST P256");
        let mut state = state();
        let base = state
            .generate_r(&curve, b"", None)
            .unwrap()
            .expect("a value");
        assert_ne!(
            state
                .generate_r(&curve, b"name", None)
                .unwrap()
                .expect("a value"),
            base
        );
        state.counter = 7;
        assert_ne!(
            state
                .generate_r(&curve, b"", None)
                .unwrap()
                .expect("a value"),
            base
        );
    }

    #[test]
    fn counted_generation_live_commitment_requirement() {
        let curve = EccCurve::lookup(0x0003).expect("NIST P256");
        let mut state = state();
        assert!(state.generate_r(&curve, b"", Some(0)).unwrap().is_none());
        let count = state.commit();
        let bound = state
            .generate_r(&curve, b"", Some(count))
            .unwrap()
            .expect("a value");
        state.counter = 0;
        assert_eq!(
            state
                .generate_r(&curve, b"", None)
                .unwrap()
                .expect("a value"),
            bound,
            "the counter that was current at commit time is replayed"
        );
    }

    #[test]
    fn compiled_curve_commit_value_coverage() {
        let state = state();
        for curve_id in [
            0x0001u16, 0x0002, 0x0003, 0x0004, 0x0005, 0x0010, 0x0011, 0x0020,
        ] {
            assert!(is_compiled_curve(curve_id));
            let curve = EccCurve::lookup(curve_id).expect("a compiled curve");
            let value = state
                .generate_r(&curve, b"", None)
                .unwrap()
                .unwrap_or_else(|| panic!("curve {curve_id:#06x} produces a value"));
            assert!(below_order(&value, &curve), "curve {curve_id:#06x}");
        }
    }

    #[test]
    fn commit_r_backend_failure_is_reported_not_skipped() {
        use crate::library::tpm2::crypto::{FaultBoundary, arm_fault, disarm_fault, faults_fired};
        let curve = EccCurve::lookup(0x0003).unwrap();
        let reference = state().generate_r(&curve, b"name", None).unwrap().unwrap();
        let before = faults_fired();
        arm_fault(FaultBoundary::Random, 0);
        let failed = state().generate_r(&curve, b"name", None);
        disarm_fault();
        assert_eq!(faults_fired() - before, 1);
        assert!(
            failed.is_err(),
            "a backend failure does not advance to another candidate"
        );
        let retried = state().generate_r(&curve, b"name", None).unwrap().unwrap();
        assert_eq!(
            retried.to_bytes(32),
            reference.to_bytes(32),
            "the same r after the failure"
        );
    }
}
