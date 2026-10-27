// Test-only adapter for controlled-state DRBG timing measurements.
// The timed call includes fixed-size state restore, real LiveDrbg generation,
// and response serialization. It is not a primitive-only AES measurement.

use std::cell::Cell;

use super::{Drbg, LiveDrbg, SeededRand};
use crate::library::constants::TPM_FAIL;
use crate::types::TpmResult;

const INPUT_SIZE: usize = 123;
const MAX_RESPONSE: usize = 152;

#[derive(Clone, Copy)]
struct Entropy {
    bytes: [u8; 48],
    draws: u32,
}

thread_local! {
    static ENTROPY: Cell<Option<Entropy>> = const { Cell::new(None) };
}

struct EntropyScope(Option<Entropy>);

impl Drop for EntropyScope {
    fn drop(&mut self) {
        ENTROPY.set(self.0);
    }
}

fn hook_entropy(output: &mut [u8]) -> Result<(), TpmResult> {
    let Some(mut entropy) = ENTROPY.get() else {
        return Err(TPM_FAIL);
    };
    if output.len() != entropy.bytes.len() || entropy.draws != 0 {
        return Err(TPM_FAIL);
    }
    output.copy_from_slice(&entropy.bytes);
    entropy.draws += 1;
    ENTROPY.set(Some(entropy));
    Ok(())
}

fn execute(input: &[u8], output: &mut [u8]) -> Result<usize, u32> {
    let input: &[u8; INPUT_SIZE] = input.try_into().map_err(|_| TPM_FAIL)?;
    let counter = u64::from_be_bytes(input[48..56].try_into().unwrap());
    let requested = usize::from(u16::from_be_bytes(input[121..123].try_into().unwrap()));
    let response_len = 88 + requested;
    if input[120] > 1
        || !(1..=(1 << 20) + 7).contains(&counter)
        || requested > 64
        || output.len() < response_len
    {
        return Err(TPM_FAIL);
    }
    let last_value = core::array::from_fn(|i| {
        u32::from_le_bytes(input[56 + i * 4..60 + i * 4].try_into().unwrap())
    });
    let drbg = Drbg::restore(&input[..48], counter, last_value, input[120] != 0)?;
    let entropy = Entropy {
        bytes: input[72..120].try_into().unwrap(),
        draws: 0,
    };
    let _scope = EntropyScope(ENTROPY.replace(Some(entropy)));
    let mut random = SeededRand::from_live(LiveDrbg::new(drbg, hook_entropy, false));
    let mut generated = [0; 64];
    random.generate(&mut generated[..requested])?;
    let drbg = random.into_live().ok_or(TPM_FAIL)?.into_drbg();
    output[..2].copy_from_slice(&[0x80, 1]);
    output[2..6].copy_from_slice(&(response_len as u32).to_be_bytes());
    output[6..10].fill(0);
    output[10..12].copy_from_slice(&(requested as u16).to_be_bytes());
    output[12..12 + requested].copy_from_slice(&generated[..requested]);
    let state = 12 + requested;
    output[state..state + 48].copy_from_slice(drbg.seed());
    output[state + 48..state + 56].copy_from_slice(&drbg.reseed_counter().to_be_bytes());
    for (chunk, word) in output[state + 56..state + 72]
        .chunks_exact_mut(4)
        .zip(drbg.last_value())
    {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    output[state + 72..state + 76]
        .copy_from_slice(&ENTROPY.get().ok_or(TPM_FAIL)?.draws.to_be_bytes());
    Ok(response_len)
}

/// Restore controlled state and execute the production live DRBG path.
///
/// # Safety
/// `input` must reference `input_len` readable bytes, `output` must reference
/// `output_capacity` writable bytes, and `output_len` must be a valid aligned
/// writable u32 pointer disjoint from both buffers. Buffers remain owned by the
/// caller for the duration of the call. Null pointers are rejected.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn TPMS_TIMING_DRBG_v1(
    input: *const u8,
    input_len: u32,
    output: *mut u8,
    output_capacity: u32,
    output_len: *mut u32,
) -> u32 {
    if output_len.is_null() {
        return TPM_FAIL;
    }
    // SAFETY: The caller guarantees an aligned writable output length pointer.
    unsafe { output_len.write(0) };
    if input.is_null() || output.is_null() || input_len as usize != INPUT_SIZE {
        return TPM_FAIL;
    }
    let mut payload = [0; INPUT_SIZE];
    // SAFETY: The input is readable for INPUT_SIZE bytes by the caller contract;
    // this local copy is disjoint, and avoids retaining references across output writes.
    unsafe { std::ptr::copy_nonoverlapping(input, payload.as_mut_ptr(), INPUT_SIZE) };
    let mut response = [0; MAX_RESPONSE];
    let capacity = (output_capacity as usize).min(MAX_RESPONSE);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        execute(&payload, &mut response[..capacity])
    }));
    let len = match result {
        Ok(Ok(len)) => len,
        Ok(Err(code)) => return code,
        Err(_) => return TPM_FAIL,
    };
    // SAFETY: execute validated capacity; the local response is disjoint from
    // the caller-owned output, and output_len is disjoint by the caller contract.
    unsafe {
        std::ptr::copy_nonoverlapping(response.as_ptr(), output, len);
        output_len.write(len as u32);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(counter: u64, continuous: bool, length: u16) -> [u8; 123] {
        let mut bytes = [0; 123];
        bytes[48..56].copy_from_slice(&counter.to_be_bytes());
        bytes[72..120].fill(0xa5);
        bytes[120] = u8::from(continuous);
        bytes[121..].copy_from_slice(&length.to_be_bytes());
        bytes
    }

    #[test]
    fn timing_drbg_restores_state_and_reseeds_at_threshold() {
        for continuous in [false, true] {
            for length in [0, 1, 16, 17, 64] {
                for (counter, want_counter, draws) in [
                    (1, 2u64, 0u32),
                    ((1 << 20) - 1, 1 << 20, 0),
                    (1 << 20, 2, 1),
                    ((1 << 20) + 7, 2, 1),
                ] {
                    let payload = input(counter, continuous, length);
                    let mut response = [0; 152];
                    let len = execute(&payload, &mut response).expect("valid hook request");
                    assert_eq!(len, 88 + usize::from(length));
                    assert_eq!(&response[..2], &[0x80, 1]);
                    assert_eq!(&response[2..6], &(len as u32).to_be_bytes());
                    assert_eq!(&response[6..10], &[0; 4]);
                    let state = 12 + usize::from(length);
                    assert_eq!(
                        &response[state + 48..state + 56],
                        &want_counter.to_be_bytes()
                    );
                    assert_eq!(&response[len - 4..len], &draws.to_be_bytes());
                    let mut repeated = [0; 152];
                    assert_eq!(execute(&payload, &mut repeated), Ok(len));
                    assert_eq!(response, repeated, "each call restores the supplied state");
                }
            }
        }
    }

    #[test]
    fn timing_drbg_rejects_invalid_wire_without_response() {
        let mut output = [0x5a; 152];
        let valid = input(1, false, 16);
        for counter in [0, (1 << 20) + 8, u64::MAX] {
            assert!(execute(&input(counter, false, 16), &mut output).is_err());
        }
        let mut bad_flag = valid;
        bad_flag[120] = 2;
        assert!(execute(&bad_flag, &mut output).is_err());
        assert!(execute(&input(1, false, 65), &mut output).is_err());
        assert!(execute(&valid[..122], &mut output).is_err());
        assert!(execute(&valid, &mut output[..103]).is_err());
        assert_eq!(output, [0x5a; 152]);
    }
    #[test]
    fn timing_drbg_ffi_matches_vendored_boundary_vectors() {
        for continuous in [false, true] {
            let record = super::super::drbg_vectors::boundary_record(continuous);
            for case in &record.cases {
                let mut payload = input(case.initial_reseed_counter, continuous, case.requested);
                payload[..48].copy_from_slice(&record.initial_seed);
                for (chunk, word) in payload[56..72]
                    .chunks_exact_mut(4)
                    .zip(record.initial_last_value)
                {
                    chunk.copy_from_slice(&word.to_le_bytes());
                }
                for (i, byte) in payload[72..120].iter_mut().enumerate() {
                    *byte = (i as u8 + 48) ^ 0x63;
                }
                let mut expected = vec![0x80, 1];
                expected.extend_from_slice(&(88 + u32::from(case.requested)).to_be_bytes());
                expected.extend_from_slice(&[0; 4]);
                expected.extend_from_slice(&case.requested.to_be_bytes());
                expected.extend_from_slice(case.output());
                expected.extend_from_slice(&case.seed_after);
                expected.extend_from_slice(&case.reseed_counter_after.to_be_bytes());
                for word in case.last_value_after {
                    expected.extend_from_slice(&word.to_le_bytes());
                }
                expected.extend_from_slice(&u32::from(case.entropy_draws).to_be_bytes());
                let mut response = [0; 152];
                let mut len = 999;
                // SAFETY: All pointers refer to live, disjoint buffers of the
                // advertised sizes, and len is an aligned writable u32.
                let rc = unsafe {
                    TPMS_TIMING_DRBG_v1(payload.as_ptr(), 123, response.as_mut_ptr(), 152, &mut len)
                };
                assert_eq!(rc, 0);
                assert_eq!(response[..len as usize], expected);
                assert!(
                    ENTROPY.get().is_none(),
                    "entropy injection must end with the call"
                );
            }
        }
    }

    #[test]
    fn timing_drbg_continuous_collision_returns_error_and_cleans_scope() {
        let mut payload = input(1 << 20, true, 16);
        // AES-256 with zero key encrypting counter 1. Reseed's first block
        // collides before the supplied entropy is mixed into the new seed.
        payload[56..72].copy_from_slice(&[
            0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb,
            0x73, 0x8b,
        ]);
        let mut response = [0x5a; 152];
        let mut len = 999;
        // SAFETY: Live, disjoint buffers meet the hook's pointer contract.
        let rc = unsafe {
            TPMS_TIMING_DRBG_v1(payload.as_ptr(), 123, response.as_mut_ptr(), 152, &mut len)
        };
        assert_ne!(rc, 0);
        assert_eq!(len, 0);
        assert_eq!(response, [0x5a; 152]);
        assert!(ENTROPY.get().is_none());
        payload[120] = 0;
        assert!(execute(&payload, &mut response).is_ok());
        assert!(ENTROPY.get().is_none());
    }

    #[test]
    fn timing_drbg_ffi_rejects_null_and_short_buffers() {
        let payload = input(1, false, 16);
        let mut response = [0x5a; 152];
        let mut len = 999;
        for (pointer, input_len, capacity) in [
            (std::ptr::null(), 123, 152),
            (payload.as_ptr(), 122, 152),
            (payload.as_ptr(), 123, 103),
        ] {
            // SAFETY: Non-null pointers reference live buffers of the stated
            // sizes. The hook explicitly accepts and rejects null input.
            let rc = unsafe {
                TPMS_TIMING_DRBG_v1(
                    pointer,
                    input_len,
                    response.as_mut_ptr(),
                    capacity,
                    &mut len,
                )
            };
            assert_ne!(rc, 0);
            assert_eq!(len, 0);
            assert_eq!(response, [0x5a; 152]);
        }
    }
}
