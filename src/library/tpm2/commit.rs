use crate::ffi_types::TpmResult;
use crate::library::constants::TPM_RC_FAILURE;

use super::crypto::{BigUint, CurveParameters, kdfa_from};
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
        curve: &CurveParameters,
        name: &[u8],
        count: Option<u16>,
    ) -> Option<BigUint> {
        let context_v = match count {
            Some(count) => self.counter_for(count)?,
            None => self.counter,
        }
        .to_be_bytes();
        let order_bytes = curve.order.byte_len();
        let bits = u32::try_from(order_bytes.checked_mul(8)?).ok()?;
        let mut counter: u32 = 1;
        while counter < GENERATE_ITERATION_LIMIT {
            let stream = kdfa_from(
                CONTEXT_INTEGRITY_HASH_ALG,
                self.nonce.as_bytes(),
                COMMIT_STRING,
                name,
                &context_v,
                bits,
                &mut counter,
            )?;
            if BigUint::from_be_bytes(&stream) >= curve.order {
                continue;
            }
            if stream[..=order_bytes / 2].iter().any(|&byte| byte != 0) {
                return Some(BigUint::from_be_bytes(&stream));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::crypto::{curve_parameters, is_compiled_curve};

    fn state() -> CommitState {
        CommitState {
            counter: 0,
            nonce: OwnedSecret::from_vec(vec![0x5c; 64]),
            array: [0u8; COMMIT_ARRAY_SIZE],
        }
    }

    #[test]
    fn the_index_mask_covers_every_bit_of_the_committed_array() {
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
    fn committing_returns_the_old_counter_and_sets_its_bit() {
        let mut state = state();
        for expected in 0..4u16 {
            assert!(!state.is_set(expected));
            assert_eq!(state.commit(), expected);
            assert!(state.is_set(expected));
            assert_eq!(state.counter, u64::from(expected) + 1);
        }
    }

    #[test]
    fn a_consumed_commitment_can_not_be_resolved_again() {
        let mut state = state();
        let count = state.commit();
        assert_eq!(state.counter_for(count), Some(0));
        state.end_commit(count);
        assert_eq!(state.counter_for(count), None);
    }

    #[test]
    fn an_unallocated_counter_never_resolves() {
        let mut state = state();
        state.commit();
        for count in [1u16, 2, 64, 127, 128, 0xffff] {
            assert_eq!(state.counter_for(count), None, "count {count}");
        }
    }

    #[test]
    fn the_upper_bits_of_the_counter_are_checked_against_the_request() {
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
    fn the_bitmap_holds_one_hundred_twenty_eight_live_commitments() {
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
    fn the_counter_wraps_without_panicking() {
        let mut state = state();
        state.counter = u64::MAX;
        assert_eq!(state.commit(), 0xffff);
        assert_eq!(state.counter, 0);
    }

    #[test]
    fn a_generated_value_is_deterministic_and_below_the_order() {
        let curve = curve_parameters(0x0003).expect("NIST P256");
        let state = state();
        let first = state
            .generate_r(&curve, b"", None)
            .expect("a commit value is produced");
        let second = state
            .generate_r(&curve, b"", None)
            .expect("a commit value is produced");
        assert_eq!(first, second);
        assert!(first < curve.order);
        assert!(!first.is_zero());
    }

    #[test]
    fn the_name_and_the_counter_both_change_the_generated_value() {
        let curve = curve_parameters(0x0003).expect("NIST P256");
        let mut state = state();
        let base = state.generate_r(&curve, b"", None).expect("a value");
        assert_ne!(
            state.generate_r(&curve, b"name", None).expect("a value"),
            base
        );
        state.counter = 7;
        assert_ne!(state.generate_r(&curve, b"", None).expect("a value"), base);
    }

    #[test]
    fn a_counted_generation_needs_a_live_commitment() {
        let curve = curve_parameters(0x0003).expect("NIST P256");
        let mut state = state();
        assert!(state.generate_r(&curve, b"", Some(0)).is_none());
        let count = state.commit();
        let bound = state.generate_r(&curve, b"", Some(count)).expect("a value");
        state.counter = 0;
        assert_eq!(
            state.generate_r(&curve, b"", None).expect("a value"),
            bound,
            "the counter that was current at commit time is replayed"
        );
    }

    #[test]
    fn every_compiled_curve_produces_a_commit_value() {
        let state = state();
        for curve_id in [
            0x0001u16, 0x0002, 0x0003, 0x0004, 0x0005, 0x0010, 0x0011, 0x0020,
        ] {
            assert!(is_compiled_curve(curve_id));
            let curve = curve_parameters(curve_id).expect("a compiled curve");
            let value = state
                .generate_r(&curve, b"", None)
                .unwrap_or_else(|| panic!("curve {curve_id:#06x} produces a value"));
            assert!(value < curve.order, "curve {curve_id:#06x}");
        }
    }
}
