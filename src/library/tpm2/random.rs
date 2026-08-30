use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_NO_RESULT};
use crate::types::TpmResult;

use super::crypto::{DRBG_MAGIC, Drbg, LiveDrbg, ReseedError, SeededRand, StirError, df_buffer};
use super::failure_mode::{FailureLocation, enter_failure_mode};
use super::persistent::{OwnedDrbgState, OwnedSecret};
use super::profile::ATTRIBUTE_DRBG_CONTINUOUS_TEST;
use super::runtime::Tpm2Runtime;

pub(super) fn stir_random(runtime: &mut Tpm2Runtime, in_data: &[u8]) -> Result<(), TpmResult> {
    let (mut drbg, magic) = restore_live_drbg(runtime)?;
    let additional = df_buffer(in_data);
    let outcome = if runtime.entropy_bad {
        Err(StirError::Entropy)
    } else {
        drbg.stir(runtime.entropy, additional.as_ref())
    };
    match outcome {
        Ok(()) => {}
        Err(StirError::Entropy) => {
            runtime.entropy_bad = true;
            return Err(TPM_RC_NO_RESULT);
        }
        Err(StirError::ContinuousTest) => {
            return Err(fatal_drbg_failure(runtime, FailureLocation::DrbgEntropy));
        }
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
        return Err(fatal_drbg_failure(
            runtime,
            FailureLocation::DrbgInvalidState,
        ));
    }
    let restored = Drbg::restore(
        stored.seed.as_bytes(),
        stored.reseed_counter,
        stored.last_value,
        continuous_test,
    );
    match restored {
        Ok(drbg) => Ok((drbg, magic)),
        Err(_) => Err(fatal_drbg_failure(
            runtime,
            FailureLocation::DrbgInvalidState,
        )),
    }
}

fn store_live_drbg(runtime: &mut Tpm2Runtime, drbg: &Drbg) {
    runtime.live.orderly.drbg_state = OwnedDrbgState {
        reseed_counter: drbg.reseed_counter(),
        drbg_magic: DRBG_MAGIC,
        seed: OwnedSecret::copy_of(drbg.seed()),
        last_value: drbg.last_value(),
    };
}

pub(super) fn take_live_rand(runtime: &mut Tpm2Runtime) -> Result<SeededRand, TpmResult> {
    let (drbg, _) = restore_live_drbg(runtime)?;
    Ok(SeededRand::from_live(LiveDrbg::new(
        drbg,
        runtime.entropy,
        runtime.entropy_bad,
    )))
}

pub(super) fn finish_live_rand(
    runtime: &mut Tpm2Runtime,
    rand: SeededRand,
) -> Result<(), TpmResult> {
    let Some(live) = rand.into_live() else {
        return Ok(());
    };
    if live.entropy_bad() {
        runtime.entropy_bad = true;
    }
    if live.fatal() {
        return Err(fatal_drbg_failure(runtime, FailureLocation::DrbgEntropy));
    }
    store_live_drbg(runtime, &live.into_drbg());
    Ok(())
}

pub(super) fn startup_live_drbg(runtime: &mut Tpm2Runtime) -> Result<Drbg, TpmResult> {
    let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
    let continuous_test = state
        .profile
        .attribute_enabled(ATTRIBUTE_DRBG_CONTINUOUS_TEST);

    let stored = &runtime.live.orderly.drbg_state;
    if stored.drbg_magic == DRBG_MAGIC {
        let restored = Drbg::restore(
            stored.seed.as_bytes(),
            stored.reseed_counter,
            stored.last_value,
            continuous_test,
        );
        let Ok(mut drbg) = restored else {
            return Err(fatal_drbg_failure(
                runtime,
                FailureLocation::DrbgInvalidState,
            ));
        };
        let outcome = if runtime.entropy_bad {
            Err(ReseedError::Entropy)
        } else {
            drbg.reseed_from_entropy(runtime.entropy)
        };
        match outcome {
            Ok(()) => Ok(drbg),
            Err(ReseedError::Entropy) => {
                runtime.entropy_bad = true;
                Err(TPM_RC_FAILURE)
            }
            Err(ReseedError::ContinuousTest) => {
                Err(fatal_drbg_failure(runtime, FailureLocation::DrbgEntropy))
            }
        }
    } else {
        let outcome = if runtime.entropy_bad {
            Err(ReseedError::Entropy)
        } else {
            Drbg::instantiate(runtime.entropy, continuous_test)
        };
        match outcome {
            Ok(drbg) => Ok(drbg),
            Err(ReseedError::Entropy) => {
                runtime.entropy_bad = true;
                Err(TPM_RC_FAILURE)
            }
            Err(ReseedError::ContinuousTest) => {
                Err(fatal_drbg_failure(runtime, FailureLocation::DrbgEntropy))
            }
        }
    }
}

pub(super) fn startup_secret(
    runtime: &mut Tpm2Runtime,
    drbg: &mut Drbg,
    len: usize,
) -> Result<OwnedSecret, TpmResult> {
    let mut bytes = vec![0u8; len];
    if drbg.generate(&mut bytes).is_err() {
        return Err(fatal_drbg_failure(runtime, FailureLocation::DrbgEntropy));
    }
    Ok(OwnedSecret::from_vec(bytes))
}

pub(super) fn generate_random(
    runtime: &mut Tpm2Runtime,
    length: usize,
) -> Result<Vec<u8>, TpmResult> {
    Ok(generate_fresh(runtime, length)?.unwrap_or_else(|| vec![0u8; length]))
}

pub(super) fn regenerate_secret(
    runtime: &mut Tpm2Runtime,
    length: usize,
) -> Result<Option<Vec<u8>>, TpmResult> {
    generate_fresh(runtime, length)
}

fn generate_fresh(runtime: &mut Tpm2Runtime, length: usize) -> Result<Option<Vec<u8>>, TpmResult> {
    let (mut drbg, magic) = restore_live_drbg(runtime)?;

    if drbg.needs_reseed() {
        let outcome = if runtime.entropy_bad {
            Err(ReseedError::Entropy)
        } else {
            drbg.reseed_from_entropy(runtime.entropy)
        };
        match outcome {
            Ok(()) => {}
            Err(ReseedError::Entropy) => {
                runtime.entropy_bad = true;
                return Ok(None);
            }
            Err(ReseedError::ContinuousTest) => {
                return Err(fatal_drbg_failure(runtime, FailureLocation::DrbgEntropy));
            }
        }
    }

    let mut bytes = vec![0u8; length];
    if drbg.generate(&mut bytes).is_err() {
        return Err(fatal_drbg_failure(runtime, FailureLocation::DrbgEntropy));
    }

    let updated = OwnedDrbgState {
        reseed_counter: drbg.reseed_counter(),
        drbg_magic: magic,
        seed: OwnedSecret::copy_of(drbg.seed()),
        last_value: drbg.last_value(),
    };
    runtime.live.orderly.drbg_state = updated;
    Ok(Some(bytes))
}

fn fatal_drbg_failure(runtime: &mut Tpm2Runtime, location: FailureLocation) -> TpmResult {
    enter_failure_mode(runtime, location);
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

    fn runtime_for(continuous_test: bool) -> Tpm2Runtime {
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
    fn request_sequence_vendored_oracle_match() {
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
    fn repeated_request_output_advance() {
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
    fn zero_length_request_state_advance() {
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
    fn continuous_test_attribute_generator_propagation() {
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
        assert_eq!(
            runtime.failure_diagnostics,
            FailureLocation::DrbgEntropy.diagnostics(),
            "the diagnostics name EncryptDRBG's continuous-test site"
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
    fn malformed_seed_length_transactional_failure() {
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
    fn foreign_magic_failure_no_reinstantiation() {
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
    fn undecoded_state_transactional_failure() {
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
    fn request_success_persistent_nv_unchanged() {
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
    fn generation_no_host_entropy_draw() {
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
    fn below_reseed_threshold_no_entropy_draw() {
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
    fn reseed_threshold_single_seed_block_draw() {
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
    fn above_reseed_threshold_reseed() {
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
    fn zero_length_request_threshold_reseed() {
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
    fn threshold_entropy_failure_no_bytes_no_failure_mode() {
        for continuous_test in [false, true] {
            let record = boundary_record(continuous_test);
            for case in [&record.cases[1], &record.cases[2], &record.cases[3]] {
                let mut runtime = runtime_for(continuous_test);
                runtime.entropy = failing_entropy;
                install_boundary(&mut runtime, &record, case);
                let before = live_drbg(&runtime);
                let persistent = persistent_snapshot(&runtime);
                assert!(!runtime.failure_mode, "the TPM starts healthy");
                let produced = generate_random(&mut runtime, usize::from(case.requested))
                    .expect("the vendored path answers success");
                assert_eq!(
                    produced,
                    vec![0u8; usize::from(case.requested)],
                    "no generated bytes; the unwritten reference buffer maps to zeros"
                );
                assert!(
                    !runtime.failure_mode,
                    "an entropy-source failure is not a FAIL() site"
                );
                assert_eq!(
                    runtime.failure_diagnostics,
                    Default::default(),
                    "no diagnostics are fabricated"
                );
                assert!(runtime.entropy_bad, "the failed fetch latches g_entropyBad");
                assert_live_drbg_unchanged(&runtime, &before);
                assert_persistent_unchanged(&runtime, &persistent);
            }
        }
    }

    fn first_encrypted_block(seed: &[u8; 48]) -> [u32; 4] {
        use aes::cipher::{BlockEncrypt, KeyInit};
        let key: [u8; 32] = seed[..32].try_into().unwrap();
        let mut iv: [u8; 16] = seed[32..].try_into().unwrap();
        for byte in iv.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        let cipher = aes::Aes256::new(&key.into());
        let mut block = aes::Block::from(iv);
        cipher.encrypt_block(&mut block);
        block_words(block.as_slice())
    }

    #[test]
    fn auto_reseed_continuous_test_hit_tpm_stop() {
        let record = boundary_record(true);
        let case = &record.cases[1];
        let mut runtime = runtime_for(true);
        runtime.entropy = deterministic_entropy;
        install(
            &mut runtime,
            &record.initial_seed,
            case.initial_reseed_counter,
            first_encrypted_block(&record.initial_seed),
        );
        let before = live_drbg(&runtime);
        let persistent = persistent_snapshot(&runtime);
        assert_fatal_failure(
            generate_random(&mut runtime, usize::from(case.requested)),
            &runtime,
            &before,
            &persistent,
        );
        assert_eq!(
            runtime.failure_diagnostics,
            FailureLocation::DrbgEntropy.diagnostics(),
            "the diagnostics name EncryptDRBG's continuous-test site"
        );
    }

    #[test]
    fn failed_fetch_entropy_bad_latch_no_retry() {
        let record = boundary_record(false);
        let case = &record.cases[1];
        let mut runtime = runtime_for(false);
        runtime.entropy = failing_entropy;
        install_boundary(&mut runtime, &record, case);
        let before = live_drbg(&runtime);
        assert!(!runtime.entropy_bad);
        assert_eq!(
            generate_random(&mut runtime, usize::from(case.requested)).expect("succeeds"),
            vec![0u8; usize::from(case.requested)]
        );
        assert!(
            runtime.entropy_bad,
            "the failed fetch latches the condition"
        );
        assert_live_drbg_unchanged(&runtime, &before);

        runtime.entropy = unreachable_entropy;
        for attempt in 0..2 {
            assert_eq!(
                generate_random(&mut runtime, usize::from(case.requested)).expect("still succeeds"),
                vec![0u8; usize::from(case.requested)],
                "attempt {attempt}: a recovered source is never consulted"
            );
            assert!(runtime.entropy_bad);
            assert_live_drbg_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn entropy_bad_latch_stir_generate_propagation() {
        let stir_case = stir_record(false);
        let case = &stir_case.cases[0];
        let mut runtime = runtime_for(false);
        runtime.entropy = failing_entropy;
        install_stir(&mut runtime, case);
        assert_eq!(
            stir_random(&mut runtime, case.additional()),
            Err(TPM_RC_NO_RESULT)
        );
        assert!(runtime.entropy_bad);

        runtime.entropy = unreachable_entropy;
        runtime.live.orderly.drbg_state.reseed_counter = CTR_DRBG_MAX_REQUESTS_PER_RESEED;
        assert_eq!(
            generate_random(&mut runtime, 16).expect("succeeds"),
            vec![0u8; 16],
            "the latched condition starves the automatic reseed"
        );
        assert_eq!(
            stir_random(&mut runtime, case.additional()),
            Err(TPM_RC_NO_RESULT),
            "a later stir answers without retrying the source"
        );
        assert!(!runtime.failure_mode);
        assert_eq!(runtime.failure_diagnostics, Default::default());
    }

    fn install_stir(runtime: &mut Tpm2Runtime, case: &DrbgStirCase) {
        install(
            runtime,
            &case.initial_seed,
            case.initial_reseed_counter,
            case.initial_last_value,
        );
    }

    fn stir_runtime(continuous_test: bool) -> Tpm2Runtime {
        let mut runtime = runtime_for(continuous_test);
        runtime.entropy = recording_entropy;
        take_entropy_requests();
        runtime
    }

    #[test]
    fn test_entropy_pattern_oracle_block_match() {
        let mut block = [0u8; DRBG_SEED_SIZE];
        deterministic_entropy(&mut block).expect("fills");
        for continuous_test in [false, true] {
            for (index, case) in stir_record(continuous_test).cases.iter().enumerate() {
                assert_eq!(case.entropy, block, "continuous {continuous_test}, {index}");
            }
        }
    }

    #[test]
    fn stir_vendored_oracle_parity() {
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
    fn post_stir_stream_vendored_oracle_match() {
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
    fn stir_counter_reset_next_request_advance() {
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
    fn stir_single_seed_block_draw() {
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
    fn empty_stir_input_entropy_only_reseed() {
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
    fn nonempty_stir_input_state_change() {
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
    fn equal_length_input_state_divergence() {
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
    fn stir_success_persistent_nv_unchanged() {
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
    fn stir_entropy_failure_no_result_unchanged() {
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
                assert!(runtime.entropy_bad, "the failed fetch latches g_entropyBad");
                assert_live_drbg_unchanged(&runtime, &before);
                assert_persistent_unchanged(&runtime, &persistent);
            }
        }
    }

    #[test]
    fn stir_malformed_seed_length_transactional_failure() {
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
    fn stir_continuous_test_hit_tpm_stop() {
        let continuous = stir_record(true);
        let case = &continuous.cases[0];
        let mut runtime = stir_runtime(true);
        install(
            &mut runtime,
            &case.initial_seed,
            case.initial_reseed_counter,
            first_encrypted_block(&case.initial_seed),
        );
        let before = live_drbg(&runtime);
        let persistent = persistent_snapshot(&runtime);
        assert_eq!(
            stir_random(&mut runtime, case.additional()),
            Err(TPM_RC_FAILURE)
        );
        assert!(runtime.failure_mode);
        assert_eq!(
            runtime.failure_diagnostics,
            FailureLocation::DrbgEntropy.diagnostics(),
            "the reseed's DRBG_Update() runs the same EncryptDRBG() site"
        );
        assert_live_drbg_unchanged(&runtime, &before);
        assert_persistent_unchanged(&runtime, &persistent);
    }

    #[test]
    fn stir_foreign_magic_failure_no_reseed() {
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
    fn stir_undecoded_state_transactional_failure() {
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
    fn stir_continuous_test_attribute_propagation() {
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
    fn auto_reseed_persistent_nv_unchanged() {
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

    #[test]
    fn production_caller_live_drbg_layer_coverage() {
        use std::path::Path;

        let rules: &[(&str, &[&str])] = &[
            (
                "reseed_from_entropy",
                &["crypto/drbg.rs", "crypto/rand_state.rs", "random.rs"],
            ),
            (".stir(", &["random.rs"]),
            ("Drbg::instantiate(", &["random.rs", "manufacture.rs"]),
            ("Drbg::restore(", &["random.rs"]),
            ("LiveDrbg::new(", &["random.rs"]),
            ("from_live(", &["crypto/rand_state.rs", "random.rs"]),
            (".entropy_bad = ", &["crypto/rand_state.rs", "random.rs"]),
            (".failure_mode = ", &["failure_mode.rs", "runtime.rs"]),
        ];

        const TEST_ONLY_MODULES: &[&str] = &[
            "command/core/test_support.rs",
            "command/hierarchy/test_support.rs",
            "command/nv/test_support.rs",
            "command/platform/test_support.rs",
        ];

        fn production_slice(source: &str) -> &str {
            let mut cut = source.len();
            let mut search_from = 0;
            while let Some(found) = source[search_from..].find("#[cfg(test)]") {
                let attribute = search_from + found;
                let rest = source[attribute + "#[cfg(test)]".len()..].trim_start();
                if rest.starts_with("mod ") || rest.starts_with("pub(") && rest.contains("mod ") {
                    cut = attribute;
                    break;
                }
                search_from = attribute + "#[cfg(test)]".len();
            }
            &source[..cut]
        }

        fn visit(root: &Path, dir: &Path, rules: &[(&str, &[&str])], violations: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).expect("the source tree is readable") {
                let path = entry.expect("a directory entry").path();
                if path.is_dir() {
                    visit(root, &path, rules, violations);
                    continue;
                }
                if path.extension().is_none_or(|extension| extension != "rs") {
                    continue;
                }
                let relative = path
                    .strip_prefix(root)
                    .expect("inside the tree")
                    .to_string_lossy()
                    .replace('\\', "/");
                let source = std::fs::read_to_string(&path).expect("the source file reads");
                if TEST_ONLY_MODULES.contains(&relative.as_str()) {
                    continue;
                }
                let production = production_slice(&source);
                for (needle, allowed) in rules {
                    if production.contains(needle) && !allowed.contains(&relative.as_str()) {
                        violations.push(format!("{relative}: `{needle}`"));
                    }
                }
                if relative != "random.rs" {
                    let mut search_from = 0;
                    while let Some(found) = production[search_from..].find("runtime.entropy") {
                        let after = search_from + found + "runtime.entropy".len();
                        if !production[after..].starts_with("_bad") {
                            violations.push(format!("{relative}: `runtime.entropy`"));
                            break;
                        }
                        search_from = after;
                    }
                }
            }
        }

        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/library/tpm2");
        let mut violations = Vec::new();
        visit(&root, &root, rules, &mut violations);
        assert!(
            violations.is_empty(),
            "production code must reach the live DRBG through random.rs:\n{}",
            violations.join("\n")
        );
    }

    fn colliding_last_value(seed: &[u8]) -> [u32; 4] {
        let mut probe = Drbg::restore(seed, 1, [0; 4], false).expect("the probe restores");
        let mut block = [0u8; 16];
        probe.generate(&mut block).expect("the probe generates");
        block_words(&block)
    }

    mod startup_boundary {
        use super::*;

        #[test]
        fn reseed_success_single_seed_counter_reset() {
            let mut runtime = runtime_for(false);
            runtime.entropy = recording_entropy;
            take_entropy_requests();
            let drbg = startup_live_drbg(&mut runtime).expect("the startup reseed succeeds");
            assert_eq!(take_entropy_requests(), [DRBG_SEED_SIZE]);
            assert_eq!(drbg.reseed_counter(), 1, "DRBG_Reseed's final assignment");
        }

        #[test]
        fn instantiate_invalid_stored_state_seed_draw() {
            let mut runtime = runtime_for(false);
            runtime.live.orderly.drbg_state.drbg_magic = 0;
            runtime.entropy = recording_entropy;
            take_entropy_requests();
            let drbg = startup_live_drbg(&mut runtime).expect("the instantiation succeeds");
            assert_eq!(take_entropy_requests(), [DRBG_SEED_SIZE]);
            assert_eq!(drbg.reseed_counter(), 1);
        }

        #[test]
        fn entropy_failure_latch_no_callback_retry() {
            for wipe_magic in [false, true] {
                let mut runtime = runtime_for(false);
                if wipe_magic {
                    runtime.live.orderly.drbg_state.drbg_magic = 0;
                }
                runtime.entropy = failing_entropy;
                let before = live_drbg(&runtime);
                assert_eq!(
                    startup_live_drbg(&mut runtime).map(|_| ()),
                    Err(TPM_RC_FAILURE),
                    "wipe_magic {wipe_magic}"
                );
                assert!(runtime.entropy_bad, "the failed fetch latches g_entropyBad");
                assert!(!runtime.failure_mode, "no FAIL() site is reached");
                assert_live_drbg_unchanged(&runtime, &before);

                runtime.entropy = unreachable_entropy;
                assert_eq!(
                    startup_live_drbg(&mut runtime).map(|_| ()),
                    Err(TPM_RC_FAILURE)
                );
                assert_live_drbg_unchanged(&runtime, &before);
            }
        }

        #[test]
        fn reseed_collision_encrypt_drbg_fatal() {
            let mut runtime = runtime_for(true);
            runtime.entropy = deterministic_entropy;
            let seed = runtime.live.orderly.drbg_state.seed.expose().to_vec();
            runtime.live.orderly.drbg_state.last_value = colliding_last_value(&seed);
            let before = live_drbg(&runtime);
            assert_eq!(
                startup_live_drbg(&mut runtime).map(|_| ()),
                Err(TPM_RC_FAILURE)
            );
            assert!(runtime.failure_mode, "the repeated block stops the TPM");
            assert_eq!(
                runtime.failure_diagnostics,
                FailureLocation::DrbgEntropy.diagnostics()
            );
            assert!(
                !runtime.entropy_bad,
                "a continuous-test hit is not an entropy failure"
            );
            assert_live_drbg_unchanged(&runtime, &before);
        }

        #[test]
        fn startup_draw_collision_encrypt_drbg_fatal() {
            let mut runtime = runtime_for(true);
            let seed = runtime.live.orderly.drbg_state.seed.expose().to_vec();
            let mut drbg = Drbg::restore(&seed, 1, colliding_last_value(&seed), true)
                .expect("the crafted state restores");
            assert_eq!(
                startup_secret(&mut runtime, &mut drbg, 64).map(|_| ()),
                Err(TPM_RC_FAILURE)
            );
            assert!(runtime.failure_mode);
            assert_eq!(
                runtime.failure_diagnostics,
                FailureLocation::DrbgEntropy.diagnostics()
            );
        }

        #[test]
        fn healthy_startup_draw_secret_no_entropy() {
            let mut runtime = runtime_for(true);
            let seed = runtime.live.orderly.drbg_state.seed.expose().to_vec();
            let mut drbg = Drbg::restore(&seed, 1, [0; 4], true).expect("restores");
            let secret = startup_secret(&mut runtime, &mut drbg, 64).expect("draws");
            assert_eq!(secret.as_bytes().len(), 64);
            assert!(!runtime.failure_mode);
            assert_eq!(drbg.reseed_counter(), 2);
        }
    }

    mod live_rand_boundary {
        use super::*;

        #[test]
        fn take_generate_finish_direct_path_parity() {
            let record = generate_record(false);
            let step = &record.steps[1];

            let mut direct = runtime_for(false);
            install_initial(&mut direct, &record);
            let expected =
                generate_random(&mut direct, usize::from(step.requested)).expect("generates");

            let mut staged = runtime_for(false);
            install_initial(&mut staged, &record);
            let mut rand = take_live_rand(&mut staged).expect("the live DRBG restores");
            let produced = rand
                .random_bytes(usize::from(step.requested))
                .expect("draws");
            finish_live_rand(&mut staged, rand).expect("completes");

            assert_eq!(produced, expected, "one live draw, same stream");
            assert_eq!(live_drbg(&staged).seed, live_drbg(&direct).seed);
            assert_eq!(
                live_drbg(&staged).reseed_counter,
                live_drbg(&direct).reseed_counter
            );
        }

        #[test]
        fn reseed_due_entropy_failure_finish_latch() {
            let record = boundary_record(false);
            let mut runtime = runtime_for(false);
            runtime.entropy = failing_entropy;
            install_boundary(&mut runtime, &record, &record.cases[1]);
            let before = live_drbg(&runtime);

            let mut rand = take_live_rand(&mut runtime).expect("restores");
            assert_eq!(rand.random_bytes(16), Err(TPM_RC_NO_RESULT));
            assert!(
                !runtime.entropy_bad,
                "the latch is published at completion, not mid-draw"
            );
            assert_eq!(rand.random_bytes(16), Err(TPM_RC_NO_RESULT));

            finish_live_rand(&mut runtime, rand).expect("an entropy failure is not fatal");
            assert!(runtime.entropy_bad, "the completion latches g_entropyBad");
            assert!(!runtime.failure_mode);
            assert_live_drbg_unchanged(&runtime, &before);
        }

        #[test]
        fn pre_latched_runtime_no_callback() {
            let record = boundary_record(false);
            let mut runtime = runtime_for(false);
            runtime.entropy_bad = true;
            runtime.entropy = unreachable_entropy;
            install_boundary(&mut runtime, &record, &record.cases[1]);
            let before = live_drbg(&runtime);

            let mut rand = take_live_rand(&mut runtime).expect("restores");
            assert_eq!(rand.random_bytes(16), Err(TPM_RC_NO_RESULT));
            finish_live_rand(&mut runtime, rand).expect("not fatal");
            assert!(runtime.entropy_bad);
            assert_live_drbg_unchanged(&runtime, &before);
        }

        #[test]
        fn generate_collision_finish_fatal_no_store() {
            let mut runtime = runtime_for(true);
            let seed = runtime.live.orderly.drbg_state.seed.expose().to_vec();
            runtime.live.orderly.drbg_state.last_value = colliding_last_value(&seed);
            runtime.live.orderly.drbg_state.reseed_counter = 1;
            let before = live_drbg(&runtime);
            let persistent = persistent_snapshot(&runtime);

            let mut rand = take_live_rand(&mut runtime).expect("restores");
            assert_eq!(rand.random_bytes(16), Err(TPM_RC_FAILURE));
            assert!(!runtime.failure_mode, "failure mode enters at completion");

            assert_fatal_failure(
                finish_live_rand(&mut runtime, rand).map(|_| Vec::new()),
                &runtime,
                &before,
                &persistent,
            );
            assert_eq!(
                runtime.failure_diagnostics,
                FailureLocation::DrbgEntropy.diagnostics()
            );
            assert!(!runtime.entropy_bad);
        }

        #[test]
        fn invalid_stored_state_take_fatal() {
            let mut runtime = runtime_for(false);
            runtime.live.orderly.drbg_state.drbg_magic = 0;
            assert_eq!(
                take_live_rand(&mut runtime).map(|_| ()),
                Err(TPM_RC_FAILURE)
            );
            assert!(runtime.failure_mode);
            assert_eq!(
                runtime.failure_diagnostics,
                FailureLocation::DrbgInvalidState.diagnostics()
            );
        }

        #[test]
        fn non_live_generator_completion_noop() {
            let mut runtime = runtime_for(false);
            let before = live_drbg(&runtime);
            let rand = crate::library::tpm2::crypto::SeededRand::instantiate(
                &[0x5a; 64],
                b"PURPOSE",
                &[0x11; 34],
                &[],
                1,
                false,
            )
            .expect("instantiates");
            finish_live_rand(&mut runtime, rand).expect("nothing to publish");
            assert_live_drbg_unchanged(&runtime, &before);
            assert!(!runtime.entropy_bad && !runtime.failure_mode);
        }
    }
}
