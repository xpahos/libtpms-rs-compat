use crate::ffi_types::TpmResult;
use crate::library::constants::TPM_RC_FAILURE;

use super::crypto::{DRBG_MAGIC, Drbg};
use super::persistent::{OwnedDrbgState, OwnedSecret};
use super::profile::ATTRIBUTE_DRBG_CONTINUOUS_TEST;
use super::runtime::Tpm2Runtime;

pub(super) fn generate_random(
    runtime: &mut Tpm2Runtime,
    length: usize,
) -> Result<Vec<u8>, TpmResult> {
    // TODO: Support runtimes without decoded state after the NVChip fallback
    // is implemented.
    let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
    let continuous_test = state
        .profile
        .attribute_enabled(ATTRIBUTE_DRBG_CONTINUOUS_TEST);

    let stored = &runtime.live.orderly.drbg_state;
    let magic = stored.drbg_magic;
    if magic != DRBG_MAGIC {
        return Err(fatal_drbg_failure(runtime));
    }
    let restored = Drbg::restore(
        stored.seed.as_bytes(),
        stored.reseed_counter,
        stored.last_value,
        continuous_test,
    );
    let mut drbg = match restored {
        Ok(drbg) => drbg,
        Err(_) => return Err(fatal_drbg_failure(runtime)),
    };

    let mut bytes = vec![0u8; length];
    if drbg.generate(&mut bytes).is_err() {
        return Err(fatal_drbg_failure(runtime));
    }

    let updated = OwnedDrbgState {
        reseed_counter: drbg.reseed_counter(),
        drbg_magic: magic,
        seed: OwnedSecret::copy_of(drbg.seed()),
        last_value: drbg.last_value(),
    };
    runtime.live.orderly.drbg_state = updated;
    Ok(bytes)
}

fn fatal_drbg_failure(runtime: &mut Tpm2Runtime) -> TpmResult {
    runtime.failure_mode = true;
    TPM_RC_FAILURE
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::constants::TPM_FAIL;
    use crate::library::tpm2::crypto::{DrbgGenerateRecord, generate_record};
    use crate::library::tpm2::manufacture::manufacture_state;
    use crate::library::tpm2::profile::validate_user_profile;
    use crate::library::tpm2::runtime::{commit_manufactured_state, empty_state_runtime};

    const CONTINUOUS_TEST_PROFILE: &[u8] =
        br#"{"Name":"custom","Attributes":"drbg-continous-test"}"#;

    fn deterministic_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
        let len = buffer.len() as u8;
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_add(len) ^ 0x63;
        }
        Ok(())
    }

    fn unreachable_entropy(_buffer: &mut [u8]) -> Result<(), TpmResult> {
        panic!("generating random bytes must not draw host entropy");
    }

    fn failing_entropy(_buffer: &mut [u8]) -> Result<(), TpmResult> {
        Err(TPM_FAIL)
    }

    fn runtime_for(continuous_test: bool) -> Box<Tpm2Runtime> {
        let profile = if continuous_test {
            validate_user_profile(Some(CONTINUOUS_TEST_PROFILE)).expect("the profile validates")
        } else {
            validate_user_profile(None).expect("the null profile validates")
        };
        let state = manufacture_state(profile, deterministic_entropy).expect("manufactures");
        let mut runtime = commit_manufactured_state(state).expect("commits");
        runtime.entropy = unreachable_entropy;
        runtime
    }

    fn install(runtime: &mut Tpm2Runtime, seed: &[u8], reseed_counter: u64, last_value: [u32; 4]) {
        runtime.live.orderly.drbg_state = OwnedDrbgState {
            reseed_counter,
            drbg_magic: DRBG_MAGIC,
            seed: OwnedSecret::copy_of(seed),
            last_value,
        };
    }

    fn install_initial(runtime: &mut Tpm2Runtime, record: &DrbgGenerateRecord) {
        install(
            runtime,
            &record.initial_seed,
            record.initial_reseed_counter,
            record.initial_last_value,
        );
    }

    struct LiveDrbg {
        reseed_counter: u64,
        drbg_magic: u32,
        seed: Vec<u8>,
        last_value: [u32; 4],
    }

    fn live_drbg(runtime: &Tpm2Runtime) -> LiveDrbg {
        let state = &runtime.live.orderly.drbg_state;
        LiveDrbg {
            reseed_counter: state.reseed_counter,
            drbg_magic: state.drbg_magic,
            seed: state.seed.expose().to_vec(),
            last_value: state.last_value,
        }
    }

    #[track_caller]
    fn assert_live_drbg_unchanged(runtime: &Tpm2Runtime, before: &LiveDrbg) {
        let now = live_drbg(runtime);
        assert_eq!(now.reseed_counter, before.reseed_counter);
        assert_eq!(now.drbg_magic, before.drbg_magic);
        assert_eq!(now.seed, before.seed);
        assert_eq!(now.last_value, before.last_value);
    }

    struct PersistentSnapshot {
        drbg_seed: Vec<u8>,
        drbg_counter: u64,
        drbg_last_value: [u32; 4],
        nv_update_pending: bool,
        nv_memory: Box<[u8]>,
    }

    fn persistent_snapshot(runtime: &Tpm2Runtime) -> PersistentSnapshot {
        let stored = &runtime
            .state
            .as_ref()
            .expect("state present")
            .orderly
            .drbg_state;
        PersistentSnapshot {
            drbg_seed: stored.seed.expose().to_vec(),
            drbg_counter: stored.reseed_counter,
            drbg_last_value: stored.last_value,
            nv_update_pending: runtime.nv_update_pending,
            nv_memory: runtime.nv_memory.clone(),
        }
    }

    #[track_caller]
    fn assert_persistent_unchanged(runtime: &Tpm2Runtime, before: &PersistentSnapshot) {
        let stored = &runtime
            .state
            .as_ref()
            .expect("state present")
            .orderly
            .drbg_state;
        assert_eq!(stored.seed.expose(), &before.drbg_seed[..]);
        assert_eq!(stored.reseed_counter, before.drbg_counter);
        assert_eq!(stored.last_value, before.drbg_last_value);
        assert_eq!(runtime.nv_update_pending, before.nv_update_pending);
        assert_eq!(runtime.nv_memory, before.nv_memory);
    }

    #[track_caller]
    fn assert_fatal_failure(
        result: Result<Vec<u8>, TpmResult>,
        runtime: &Tpm2Runtime,
        live: &LiveDrbg,
        persistent: &PersistentSnapshot,
    ) {
        assert_eq!(result, Err(TPM_RC_FAILURE));
        assert!(runtime.failure_mode, "a fatal DRBG error stops the TPM");
        assert_live_drbg_unchanged(runtime, live);
        assert_persistent_unchanged(runtime, persistent);
    }

    fn block_words(block: &[u8]) -> [u32; 4] {
        core::array::from_fn(|word| {
            u32::from_le_bytes(block[word * 4..word * 4 + 4].try_into().unwrap())
        })
    }

    #[test]
    fn the_request_sequence_matches_the_vendored_oracle() {
        for continuous_test in [false, true] {
            let record = generate_record(continuous_test);
            let mut runtime = runtime_for(continuous_test);
            install_initial(&mut runtime, &record);

            for (index, step) in record.steps.iter().enumerate() {
                let produced = generate_random(&mut runtime, usize::from(step.requested))
                    .expect("the live DRBG generates");
                assert_eq!(
                    produced,
                    step.output(),
                    "continuous {continuous_test}, step {index}"
                );
                let live = live_drbg(&runtime);
                assert_eq!(
                    live.seed, step.seed_after,
                    "seed after continuous {continuous_test}, step {index}"
                );
                assert_eq!(
                    live.reseed_counter, step.reseed_counter_after,
                    "counter after continuous {continuous_test}, step {index}"
                );
                assert_eq!(
                    live.last_value, step.last_value_after,
                    "lastValue after continuous {continuous_test}, step {index}"
                );
                assert_eq!(live.drbg_magic, DRBG_MAGIC, "the magic is preserved");
            }
        }
    }

    #[test]
    fn repeated_requests_return_the_next_output_instead_of_repeating() {
        let record = generate_record(false);
        let mut runtime = runtime_for(false);
        install_initial(&mut runtime, &record);
        for step in &record.steps {
            generate_random(&mut runtime, usize::from(step.requested)).expect("generates");
        }

        install_initial(&mut runtime, &record);
        let first = generate_random(&mut runtime, 64).expect("generates");
        let second = generate_random(&mut runtime, 64).expect("generates");
        assert_ne!(first, second);
        assert_eq!(
            first.len() + second.len(),
            128,
            "both requests are fully served"
        );
    }

    #[test]
    fn a_zero_length_request_still_advances_the_state_like_upstream() {
        for continuous_test in [false, true] {
            let record = generate_record(continuous_test);
            let zero_step = &record.steps[0];
            assert_eq!(
                zero_step.requested, 0,
                "the fixture leads with a zero request"
            );

            let mut runtime = runtime_for(continuous_test);
            install_initial(&mut runtime, &record);
            let produced = generate_random(&mut runtime, 0).expect("generates");
            assert!(produced.is_empty());

            let live = live_drbg(&runtime);
            assert_eq!(live.seed, zero_step.seed_after);
            assert_eq!(live.reseed_counter, zero_step.reseed_counter_after);
            assert_eq!(live.reseed_counter, record.initial_reseed_counter + 1);
            assert_ne!(
                live.seed,
                record.initial_seed.to_vec(),
                "the update runs even without output"
            );
            assert_eq!(live.last_value, zero_step.last_value_after);
        }
    }

    #[test]
    fn the_continuous_test_attribute_reaches_the_generator() {
        let record = generate_record(true);
        let repeated = block_words(&record.steps[4].output()[..16]);

        let mut runtime = runtime_for(true);
        install(
            &mut runtime,
            &record.steps[3].seed_after,
            record.steps[3].reseed_counter_after,
            repeated,
        );
        let before = live_drbg(&runtime);
        let persistent = persistent_snapshot(&runtime);
        assert!(!runtime.failure_mode, "the TPM starts healthy");
        assert_fatal_failure(
            generate_random(&mut runtime, 64),
            &runtime,
            &before,
            &persistent,
        );

        let mut runtime = runtime_for(false);
        install(
            &mut runtime,
            &record.steps[3].seed_after,
            record.steps[3].reseed_counter_after,
            repeated,
        );
        let produced = generate_random(&mut runtime, 64).expect("the plain profile has no test");
        assert_eq!(produced, record.steps[4].output());
        assert_eq!(
            live_drbg(&runtime).last_value,
            repeated,
            "lastValue is left alone without the attribute"
        );
    }

    #[test]
    fn a_malformed_seed_length_fails_transactionally() {
        for length in [0usize, 1, 47, 49, 64] {
            let mut runtime = runtime_for(false);
            install(&mut runtime, &vec![0x5a; length], 3, [1, 2, 3, 4]);
            let before = live_drbg(&runtime);
            let persistent = persistent_snapshot(&runtime);
            assert_fatal_failure(
                generate_random(&mut runtime, 16),
                &runtime,
                &before,
                &persistent,
            );
        }
    }

    #[test]
    fn a_foreign_magic_fails_instead_of_instantiating_a_new_generator() {
        let record = generate_record(false);
        for magic in [0u32, DRBG_MAGIC ^ 1, 0xffff_ffff] {
            let mut runtime = runtime_for(false);
            install_initial(&mut runtime, &record);
            runtime.live.orderly.drbg_state.drbg_magic = magic;
            let before = live_drbg(&runtime);
            let persistent = persistent_snapshot(&runtime);
            assert_fatal_failure(
                generate_random(&mut runtime, 16),
                &runtime,
                &before,
                &persistent,
            );
        }
    }

    #[test]
    fn a_runtime_without_decoded_state_fails_transactionally() {
        let record = generate_record(false);
        let mut runtime = empty_state_runtime();
        runtime.entropy = unreachable_entropy;
        install_initial(&mut runtime, &record);
        let before = live_drbg(&runtime);
        assert_eq!(generate_random(&mut runtime, 16), Err(TPM_RC_FAILURE));
        assert_live_drbg_unchanged(&runtime, &before);
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn a_successful_request_leaves_the_persistent_state_and_nv_alone() {
        let record = generate_record(false);
        let mut runtime = runtime_for(false);
        install_initial(&mut runtime, &record);
        let persistent = persistent_snapshot(&runtime);
        for length in [0usize, 1, 16, 64] {
            generate_random(&mut runtime, length).expect("generates");
            assert_persistent_unchanged(&runtime, &persistent);
            assert!(!runtime.failure_mode, "a served request is not fatal");
        }
    }

    #[test]
    fn generation_never_draws_host_entropy() {
        let record = generate_record(false);
        let mut runtime = runtime_for(false);
        runtime.entropy = failing_entropy;
        install_initial(&mut runtime, &record);
        for step in &record.steps {
            let produced = generate_random(&mut runtime, usize::from(step.requested))
                .expect("a failing entropy source is never consulted");
            assert_eq!(produced, step.output());
        }
    }
}
