use crate::ffi_types::TpmResult;
use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_NO_RESULT};

use super::crypto::{DRBG_MAGIC, Drbg, StirError, df_buffer};
use super::persistent::{OwnedDrbgState, OwnedSecret};
use super::profile::ATTRIBUTE_DRBG_CONTINUOUS_TEST;
use super::runtime::Tpm2Runtime;

pub(super) fn stir_random(runtime: &mut Tpm2Runtime, in_data: &[u8]) -> Result<(), TpmResult> {
    let (mut drbg, magic) = restore_live_drbg(runtime)?;
    let additional = df_buffer(in_data);
    match drbg.stir(runtime.entropy, additional.as_ref()) {
        Ok(()) => {}
        Err(StirError::Entropy) => return Err(TPM_RC_NO_RESULT),
        Err(StirError::Fatal(_)) => return Err(fatal_drbg_failure(runtime)),
    }
    runtime.live.orderly.drbg_state = OwnedDrbgState {
        reseed_counter: drbg.reseed_counter(),
        drbg_magic: magic,
        seed: OwnedSecret::copy_of(drbg.seed()),
        last_value: drbg.last_value(),
    };
    Ok(())
}

fn restore_live_drbg(runtime: &mut Tpm2Runtime) -> Result<(Drbg, u32), TpmResult> {
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
    match restored {
        Ok(drbg) => Ok((drbg, magic)),
        Err(_) => Err(fatal_drbg_failure(runtime)),
    }
}

pub(super) fn take_live_drbg(runtime: &mut Tpm2Runtime) -> Result<Drbg, TpmResult> {
    restore_live_drbg(runtime).map(|(drbg, _)| drbg)
}

pub(super) fn store_live_drbg(runtime: &mut Tpm2Runtime, drbg: &Drbg) {
    runtime.live.orderly.drbg_state = OwnedDrbgState {
        reseed_counter: drbg.reseed_counter(),
        drbg_magic: DRBG_MAGIC,
        seed: OwnedSecret::copy_of(drbg.seed()),
        last_value: drbg.last_value(),
    };
}

pub(super) fn generate_random(
    runtime: &mut Tpm2Runtime,
    length: usize,
) -> Result<Vec<u8>, TpmResult> {
    let (mut drbg, magic) = restore_live_drbg(runtime)?;

    if drbg.needs_reseed() && drbg.reseed_from_entropy(runtime.entropy).is_err() {
        return Err(fatal_drbg_failure(runtime));
    }

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
    use crate::library::tpm2::crypto::{
        CTR_DRBG_MAX_REQUESTS_PER_RESEED, DRBG_SEED_SIZE, DrbgBoundaryCase, DrbgBoundaryRecord,
        DrbgGenerateRecord, DrbgStirCase, boundary_record, generate_record, stir_record,
    };
    use crate::library::tpm2::manufacture::manufacture_state;
    use crate::library::tpm2::profile::validate_user_profile;
    use crate::library::tpm2::runtime::{commit_manufactured_state, empty_state_runtime};
    use std::cell::RefCell;

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

    thread_local! {
        static ENTROPY_REQUESTS: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
    }

    fn recording_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
        ENTROPY_REQUESTS.with(|requests| requests.borrow_mut().push(buffer.len()));
        deterministic_entropy(buffer)
    }

    fn take_entropy_requests() -> Vec<usize> {
        ENTROPY_REQUESTS.with(|requests| core::mem::take(&mut *requests.borrow_mut()))
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

    fn install_boundary(
        runtime: &mut Tpm2Runtime,
        record: &DrbgBoundaryRecord,
        case: &DrbgBoundaryCase,
    ) {
        install(
            runtime,
            &record.initial_seed,
            case.initial_reseed_counter,
            record.initial_last_value,
        );
    }

    #[track_caller]
    fn assert_matches_case(runtime: &Tpm2Runtime, produced: &[u8], case: &DrbgBoundaryCase) {
        assert_eq!(produced, case.output());
        let live = live_drbg(runtime);
        assert_eq!(live.seed, case.seed_after);
        assert_eq!(live.reseed_counter, case.reseed_counter_after);
        assert_eq!(live.last_value, case.last_value_after);
        assert_eq!(live.drbg_magic, DRBG_MAGIC);
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

    #[test]
    fn a_request_below_the_reseed_threshold_never_draws_entropy() {
        for continuous_test in [false, true] {
            let record = boundary_record(continuous_test);
            let case = &record.cases[0];
            assert_eq!(
                case.initial_reseed_counter,
                CTR_DRBG_MAX_REQUESTS_PER_RESEED - 1
            );
            assert_eq!(case.entropy_draws, 0, "the oracle drew no entropy either");

            let mut runtime = runtime_for(continuous_test);
            install_boundary(&mut runtime, &record, case);
            let produced = generate_random(&mut runtime, usize::from(case.requested))
                .expect("the request below the threshold is served");
            assert_matches_case(&runtime, &produced, case);
            assert_eq!(
                live_drbg(&runtime).reseed_counter,
                CTR_DRBG_MAX_REQUESTS_PER_RESEED,
                "the request leaves the generator exactly at the threshold"
            );
        }
    }

    #[test]
    fn a_request_at_the_reseed_threshold_draws_exactly_one_seed_block() {
        for continuous_test in [false, true] {
            let record = boundary_record(continuous_test);
            let case = &record.cases[1];
            assert_eq!(
                case.initial_reseed_counter,
                CTR_DRBG_MAX_REQUESTS_PER_RESEED
            );
            assert_eq!(case.entropy_draws, 1);

            let mut runtime = runtime_for(continuous_test);
            runtime.entropy = recording_entropy;
            install_boundary(&mut runtime, &record, case);
            take_entropy_requests();
            let produced = generate_random(&mut runtime, usize::from(case.requested))
                .expect("the automatic reseed serves the request");
            assert_eq!(
                take_entropy_requests(),
                [DRBG_SEED_SIZE],
                "DRBG_Reseed collects one full seed"
            );
            assert_matches_case(&runtime, &produced, case);
            assert_eq!(
                live_drbg(&runtime).reseed_counter,
                2,
                "DRBG_Reseed sets 1 and the generation that follows advances to 2"
            );
        }
    }

    #[test]
    fn a_request_above_the_reseed_threshold_also_reseeds() {
        for continuous_test in [false, true] {
            let record = boundary_record(continuous_test);
            let case = &record.cases[3];
            assert!(case.initial_reseed_counter > CTR_DRBG_MAX_REQUESTS_PER_RESEED);
            assert_eq!(case.entropy_draws, 1);

            let mut runtime = runtime_for(continuous_test);
            runtime.entropy = recording_entropy;
            install_boundary(&mut runtime, &record, case);
            take_entropy_requests();
            let produced = generate_random(&mut runtime, usize::from(case.requested))
                .expect("the automatic reseed serves the request");
            assert_eq!(take_entropy_requests(), [DRBG_SEED_SIZE]);
            assert_matches_case(&runtime, &produced, case);
            assert_eq!(live_drbg(&runtime).reseed_counter, 2);
        }
    }

    #[test]
    fn a_zero_length_request_at_the_threshold_still_reseeds() {
        for continuous_test in [false, true] {
            let record = boundary_record(continuous_test);
            let case = &record.cases[2];
            assert_eq!(
                case.initial_reseed_counter,
                CTR_DRBG_MAX_REQUESTS_PER_RESEED
            );
            assert_eq!(case.requested, 0);
            assert_eq!(case.entropy_draws, 1);

            let mut runtime = runtime_for(continuous_test);
            runtime.entropy = recording_entropy;
            install_boundary(&mut runtime, &record, case);
            take_entropy_requests();
            let produced = generate_random(&mut runtime, 0).expect("a zero-byte request is served");
            assert!(produced.is_empty());
            assert_eq!(take_entropy_requests(), [DRBG_SEED_SIZE]);
            assert_matches_case(&runtime, &produced, case);
            assert_eq!(live_drbg(&runtime).reseed_counter, 2);
            assert_ne!(
                live_drbg(&runtime).seed,
                record.initial_seed.to_vec(),
                "the reseed and the update both ran"
            );
        }
    }

    #[test]
    fn an_entropy_failure_at_the_threshold_fails_transactionally() {
        for continuous_test in [false, true] {
            let record = boundary_record(continuous_test);
            for case in [&record.cases[1], &record.cases[2], &record.cases[3]] {
                let mut runtime = runtime_for(continuous_test);
                runtime.entropy = failing_entropy;
                install_boundary(&mut runtime, &record, case);
                let before = live_drbg(&runtime);
                let persistent = persistent_snapshot(&runtime);
                assert!(!runtime.failure_mode, "the TPM starts healthy");
                assert_fatal_failure(
                    generate_random(&mut runtime, usize::from(case.requested)),
                    &runtime,
                    &before,
                    &persistent,
                );
            }
        }
    }

    fn install_stir(runtime: &mut Tpm2Runtime, case: &DrbgStirCase) {
        install(
            runtime,
            &case.initial_seed,
            case.initial_reseed_counter,
            case.initial_last_value,
        );
    }

    fn stir_runtime(continuous_test: bool) -> Box<Tpm2Runtime> {
        let mut runtime = runtime_for(continuous_test);
        runtime.entropy = recording_entropy;
        take_entropy_requests();
        runtime
    }

    #[test]
    fn the_test_entropy_pattern_is_the_block_the_oracle_injected() {
        let mut block = [0u8; DRBG_SEED_SIZE];
        deterministic_entropy(&mut block).expect("fills");
        for continuous_test in [false, true] {
            for (index, case) in stir_record(continuous_test).cases.iter().enumerate() {
                assert_eq!(case.entropy, block, "continuous {continuous_test}, {index}");
            }
        }
    }

    #[test]
    fn every_stir_matches_the_vendored_oracle() {
        for continuous_test in [false, true] {
            let record = stir_record(continuous_test);
            for (index, case) in record.cases.iter().enumerate() {
                let mut runtime = stir_runtime(continuous_test);
                install_stir(&mut runtime, case);

                stir_random(&mut runtime, case.additional()).expect("the live DRBG stirs");

                let live = live_drbg(&runtime);
                assert_eq!(
                    live.seed, case.seed_after,
                    "seed after continuous {continuous_test}, case {index}"
                );
                assert_eq!(
                    live.reseed_counter, case.reseed_counter_after,
                    "counter after continuous {continuous_test}, case {index}"
                );
                assert_eq!(
                    live.last_value, case.last_value_after,
                    "lastValue after continuous {continuous_test}, case {index}"
                );
                assert_eq!(live.drbg_magic, DRBG_MAGIC, "the magic is preserved");
                assert!(!runtime.failure_mode);
            }
        }
    }

    #[test]
    fn the_stream_after_a_stir_matches_the_vendored_oracle() {
        for continuous_test in [false, true] {
            let record = stir_record(continuous_test);
            for (index, case) in record.cases.iter().enumerate() {
                let mut runtime = stir_runtime(continuous_test);
                install_stir(&mut runtime, case);
                stir_random(&mut runtime, case.additional()).expect("stirs");

                let produced = generate_random(&mut runtime, 64).expect("generates");
                assert_eq!(
                    produced, case.next_output,
                    "continuous {continuous_test}, case {index}"
                );
            }
        }
    }

    #[test]
    fn a_stir_forces_the_counter_to_one_and_the_next_request_advances_to_two() {
        for continuous_test in [false, true] {
            let record = stir_record(continuous_test);
            for (index, case) in record.cases.iter().enumerate() {
                let mut runtime = stir_runtime(continuous_test);
                install_stir(&mut runtime, case);
                stir_random(&mut runtime, case.additional()).expect("stirs");
                assert_eq!(case.reseed_counter_after, 1, "the oracle forced 1 too");
                assert_eq!(live_drbg(&runtime).reseed_counter, 1, "case {index}");

                generate_random(&mut runtime, 16).expect("generates");
                assert_eq!(live_drbg(&runtime).reseed_counter, 2, "case {index}");
                assert_eq!(
                    take_entropy_requests(),
                    [DRBG_SEED_SIZE],
                    "the request after a stir does not reseed again, case {index}"
                );
            }
        }
    }

    #[test]
    fn a_stir_draws_exactly_one_full_seed_block() {
        for continuous_test in [false, true] {
            let record = stir_record(continuous_test);
            for (index, case) in record.cases.iter().enumerate() {
                let mut runtime = stir_runtime(continuous_test);
                install_stir(&mut runtime, case);
                stir_random(&mut runtime, case.additional()).expect("stirs");
                assert_eq!(
                    take_entropy_requests(),
                    [DRBG_SEED_SIZE],
                    "continuous {continuous_test}, case {index}"
                );
            }
        }
    }

    #[test]
    fn an_empty_input_reseeds_from_entropy_alone() {
        let record = stir_record(false);
        let case = &record.cases[0];
        assert!(
            case.additional().is_empty(),
            "the fixture leads with 0 bytes"
        );
        assert_eq!(case.derived, [0; DRBG_SEED_SIZE], "DfBuffer returned NULL");

        let mut runtime = stir_runtime(false);
        install_stir(&mut runtime, case);
        stir_random(&mut runtime, &[]).expect("stirs");
        let entropy_only = live_drbg(&runtime);
        assert_eq!(entropy_only.seed, case.seed_after);

        let mut runtime = stir_runtime(false);
        install_stir(&mut runtime, case);
        stir_random(&mut runtime, &[0x00]).expect("stirs");
        assert_ne!(
            live_drbg(&runtime).seed,
            entropy_only.seed,
            "a one-byte input is not the same as no input"
        );
    }

    #[test]
    fn a_non_empty_input_changes_the_resulting_state() {
        let record = stir_record(false);
        let mut runtime = stir_runtime(false);
        install_stir(&mut runtime, &record.cases[0]);
        stir_random(&mut runtime, &[]).expect("stirs");
        let entropy_only = live_drbg(&runtime).seed;

        for length in [1usize, 16, 48, 128] {
            let input: Vec<u8> = (0..length).map(|index| index as u8).collect();
            let mut runtime = stir_runtime(false);
            install_stir(&mut runtime, &record.cases[0]);
            stir_random(&mut runtime, &input).expect("stirs");
            assert_ne!(live_drbg(&runtime).seed, entropy_only, "length {length}");
        }
    }

    #[test]
    fn different_inputs_of_the_same_length_produce_different_states() {
        let record = stir_record(false);
        let (left, right) = (&record.cases[2], &record.cases[3]);
        assert_eq!(
            left.additional().len(),
            right.additional().len(),
            "16 bytes"
        );
        assert_ne!(left.additional(), right.additional());

        let mut states = Vec::new();
        for case in [left, right] {
            let mut runtime = stir_runtime(false);
            install_stir(&mut runtime, &record.cases[0]);
            stir_random(&mut runtime, case.additional()).expect("stirs");
            states.push(live_drbg(&runtime).seed);
        }
        assert_ne!(states[0], states[1]);
    }

    #[test]
    fn a_successful_stir_leaves_the_persistent_state_and_nv_alone() {
        for continuous_test in [false, true] {
            let record = stir_record(continuous_test);
            for case in &record.cases {
                let mut runtime = stir_runtime(continuous_test);
                install_stir(&mut runtime, case);
                let persistent = persistent_snapshot(&runtime);
                stir_random(&mut runtime, case.additional()).expect("stirs");
                assert_persistent_unchanged(&runtime, &persistent);
                assert!(!runtime.failure_mode, "a served stir is not fatal");
            }
        }
    }

    #[test]
    fn an_entropy_failure_reports_no_result_and_changes_nothing() {
        for continuous_test in [false, true] {
            let record = stir_record(continuous_test);
            for case in &record.cases {
                let mut runtime = runtime_for(continuous_test);
                runtime.entropy = failing_entropy;
                install_stir(&mut runtime, case);
                let before = live_drbg(&runtime);
                let persistent = persistent_snapshot(&runtime);

                assert_eq!(
                    stir_random(&mut runtime, case.additional()),
                    Err(TPM_RC_NO_RESULT)
                );
                assert!(
                    !runtime.failure_mode,
                    "upstream CryptRandomStir does not fail the TPM"
                );
                assert_live_drbg_unchanged(&runtime, &before);
                assert_persistent_unchanged(&runtime, &persistent);
            }
        }
    }

    #[test]
    fn a_malformed_seed_length_fails_the_stir_transactionally() {
        for length in [0usize, 1, 47, 49, 64] {
            let mut runtime = stir_runtime(false);
            install(&mut runtime, &vec![0x5a; length], 3, [1, 2, 3, 4]);
            let before = live_drbg(&runtime);
            let persistent = persistent_snapshot(&runtime);
            assert_eq!(stir_random(&mut runtime, &[0x11; 16]), Err(TPM_RC_FAILURE));
            assert!(runtime.failure_mode, "a fatal DRBG error stops the TPM");
            assert_live_drbg_unchanged(&runtime, &before);
            assert_persistent_unchanged(&runtime, &persistent);
            assert_eq!(
                take_entropy_requests(),
                [] as [usize; 0],
                "the state check precedes entropy collection"
            );
        }
    }

    #[test]
    fn a_foreign_magic_fails_the_stir_instead_of_reseeding() {
        let record = stir_record(false);
        for magic in [0u32, DRBG_MAGIC ^ 1, 0xffff_ffff] {
            let mut runtime = stir_runtime(false);
            install_stir(&mut runtime, &record.cases[0]);
            runtime.live.orderly.drbg_state.drbg_magic = magic;
            let before = live_drbg(&runtime);
            let persistent = persistent_snapshot(&runtime);
            assert_eq!(stir_random(&mut runtime, &[0x11; 16]), Err(TPM_RC_FAILURE));
            assert!(runtime.failure_mode);
            assert_live_drbg_unchanged(&runtime, &before);
            assert_persistent_unchanged(&runtime, &persistent);
        }
    }

    #[test]
    fn a_stir_on_a_runtime_without_decoded_state_fails_transactionally() {
        let record = stir_record(false);
        let mut runtime = empty_state_runtime();
        runtime.entropy = unreachable_entropy;
        install_stir(&mut runtime, &record.cases[0]);
        let before = live_drbg(&runtime);
        assert_eq!(stir_random(&mut runtime, &[0x11; 16]), Err(TPM_RC_FAILURE));
        assert!(!runtime.failure_mode);
        assert_live_drbg_unchanged(&runtime, &before);
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn the_continuous_test_attribute_reaches_the_stir() {
        let plain = stir_record(false);
        let continuous = stir_record(true);
        for (index, (left, right)) in plain.cases.iter().zip(&continuous.cases).enumerate() {
            assert_eq!(left.seed_after, right.seed_after, "case {index}");
            assert_eq!(left.last_value_after, [0; 4], "plain mode never writes");
            assert_ne!(right.last_value_after, [0; 4], "case {index}");
        }

        let case = &continuous.cases[0];
        let mut runtime = stir_runtime(true);
        install_stir(&mut runtime, case);
        stir_random(&mut runtime, case.additional()).expect("stirs");
        assert_eq!(live_drbg(&runtime).last_value, case.last_value_after);

        let mut runtime = stir_runtime(false);
        install_stir(&mut runtime, case);
        stir_random(&mut runtime, case.additional()).expect("stirs");
        assert_eq!(
            live_drbg(&runtime).last_value,
            case.initial_last_value,
            "lastValue is left alone without the attribute"
        );
    }

    #[test]
    fn an_automatic_reseed_leaves_the_persistent_state_and_nv_alone() {
        for continuous_test in [false, true] {
            let record = boundary_record(continuous_test);
            let mut runtime = runtime_for(continuous_test);
            runtime.entropy = recording_entropy;
            install_boundary(&mut runtime, &record, &record.cases[1]);
            let persistent = persistent_snapshot(&runtime);
            take_entropy_requests();

            generate_random(&mut runtime, usize::from(record.cases[1].requested))
                .expect("the automatic reseed serves the request");

            assert_eq!(take_entropy_requests(), [DRBG_SEED_SIZE]);
            assert_persistent_unchanged(&runtime, &persistent);
            assert!(!runtime.failure_mode, "a served request is not fatal");
        }
    }
}
