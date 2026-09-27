use crate::library::constants::{TPM_RC_INSUFFICIENT, TPM_RC_SIZE, TPM_RC_VALUE};
use crate::library::tpm2::command::core::dispatcher::CommandFrame;
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::self_test::run_self_test;
use crate::types::TpmResult;

const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;
const RC_SELF_TEST_FULL_TEST: TpmResult = TPM_RC_P + TPM_RC_1;

const NO: u8 = 0x00;
const YES: u8 = 0x01;

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let full_test = parse_full_test(frame.parameters)?;
    run_self_test(runtime, full_test)?;
    Ok(CommandOutput::empty())
}

fn parse_full_test(parameters: &[u8]) -> Result<bool, TpmResult> {
    let Some((&full_test, rest)) = parameters.split_first() else {
        return Err(TPM_RC_INSUFFICIENT + RC_SELF_TEST_FULL_TEST);
    };
    if full_test != NO && full_test != YES {
        return Err(TPM_RC_VALUE + RC_SELF_TEST_FULL_TEST);
    }
    if !rest.is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(full_test == YES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::CommandInput;
    use crate::library::cancel::CancellationToken;
    use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_INITIALIZE};
    use crate::library::tpm2::command::core::dispatcher::dispatch;
    use crate::library::tpm2::command::core::header::{parse_command, serialize_response};
    use crate::library::tpm2::command::core::registry::TPM_CC_SELF_TEST;
    use crate::library::tpm2::command::core::test_support::{
        dispatch_bytes as run, dispatch_bytes_with as run_with,
    };
    use crate::library::tpm2::command::lifecycle::test_support::{snapshot, started_runtime};

    use crate::library::tpm2::runtime::{Tpm2Runtime, empty_state_runtime};
    use crate::library::tpm2::self_test::{
        PaddedRsaRunner, PaddedRsaSelfTestStage, PrimitiveTest, always_fails, fails_on_sha384,
        fails_on_sha512,
    };

    fn oaep_failure_table() -> [(
        PaddedRsaRunner,
        crate::library::tpm2::failure_mode::FailureLocation,
    ); 5] {
        use crate::library::tpm2::failure_mode::FailureLocation;
        [
            (
                |_: &[u8]| Err(PaddedRsaSelfTestStage::Encrypt),
                FailureLocation::RsaOaepEncrypt,
            ),
            (
                |_: &[u8]| Err(PaddedRsaSelfTestStage::RoundTripDecrypt),
                FailureLocation::RsaOaepRoundTripDecrypt,
            ),
            (
                |_: &[u8]| Err(PaddedRsaSelfTestStage::RoundTripCompare),
                FailureLocation::RsaOaepRoundTripCompare,
            ),
            (
                |_: &[u8]| Err(PaddedRsaSelfTestStage::KnownAnswerDecrypt),
                FailureLocation::RsaOaepKnownAnswerDecrypt,
            ),
            (
                |_: &[u8]| Err(PaddedRsaSelfTestStage::KnownAnswerCompare),
                FailureLocation::RsaOaepKnownAnswerCompare,
            ),
        ]
    }

    const SUCCESS_RESPONSE: [u8; 10] = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00];
    const FULL_TEST_COMMAND: [u8; 11] = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x01, 0x43, 0x01,
    ];
    const PARTIAL_TEST_COMMAND: [u8; 11] = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x01, 0x43, 0x00,
    ];

    const INSUFFICIENT_PARAMETER_1: u32 = 0x1da;
    const VALUE_PARAMETER_1: u32 = 0x1c4;
    const SIZE: u32 = 0x095;
    const SESSION1_HANDLE: u32 = 0x98b;
    const INSUFFICIENT: u32 = 0x09a;

    fn framed(tag: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = tag.to_be_bytes().to_vec();
        out.extend_from_slice(&(10 + payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&TPM_CC_SELF_TEST.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[track_caller]
    fn response_code_of(response: &[u8]) -> u32 {
        u32::from_be_bytes(response[6..10].try_into().expect("a complete header"))
    }

    #[track_caller]
    fn run_code(runtime: &mut Tpm2Runtime, bytes: &[u8]) -> u32 {
        let input = CommandInput::new(bytes.len() as u32, bytes.to_vec());
        let parsed = parse_command(&input).expect("the header parses");
        dispatch(runtime, &parsed, CancellationToken::disabled()).code()
    }

    #[test]
    fn raised_pin_no_cancellation() {
        for command in [FULL_TEST_COMMAND, PARTIAL_TEST_COMMAND] {
            let mut runtime = started_runtime();
            let snapshot_before = snapshot(&runtime);
            assert_eq!(
                run_with(&mut runtime, &command, CancellationToken::requested()),
                SUCCESS_RESPONSE,
                "TPM2_SelfTest runs against g_toTest and is never cancelable"
            );
            assert!(runtime.self_test.pending.is_empty());
            assert!(!runtime.failure_mode);
            assert_eq!(snapshot(&runtime), snapshot_before);
        }
    }

    #[test]
    fn raised_pin_failing_test_unchanged() {
        let mut runtime = started_runtime();
        runtime.self_test.set_runner(always_fails);
        let response = run_with(
            &mut runtime,
            &FULL_TEST_COMMAND,
            CancellationToken::requested(),
        );
        assert_eq!(response_code_of(&response), TPM_RC_FAILURE);
        assert!(runtime.failure_mode);
    }

    #[test]
    fn pre_startup_rejection() {
        let mut runtime = empty_state_runtime();
        assert_eq!(
            run_code(&mut runtime, &FULL_TEST_COMMAND),
            TPM_RC_INITIALIZE
        );
        assert_eq!(
            run_code(&mut runtime, &PARTIAL_TEST_COMMAND),
            TPM_RC_INITIALIZE
        );
        assert!(!runtime.failure_mode);
        for test in PrimitiveTest::ALL {
            assert!(runtime.self_test.pending.contains(test), "{test:?}");
        }
    }

    #[test]
    fn full_test_upstream_success_bytes() {
        let mut runtime = started_runtime();
        assert_eq!(run(&mut runtime, &FULL_TEST_COMMAND), SUCCESS_RESPONSE);
        assert!(runtime.self_test.pending.is_empty());
        assert!(!runtime.failure_mode);
    }

    #[test]
    fn partial_test_upstream_success_bytes() {
        let mut runtime = started_runtime();
        assert_eq!(run(&mut runtime, &PARTIAL_TEST_COMMAND), SUCCESS_RESPONSE);
        assert!(runtime.self_test.pending.is_empty());
        assert!(!runtime.failure_mode);
    }

    #[test]
    fn partial_after_full_no_rerun() {
        let mut runtime = started_runtime();
        assert_eq!(run(&mut runtime, &FULL_TEST_COMMAND), SUCCESS_RESPONSE);
        runtime.self_test.set_runner(always_fails);
        assert_eq!(
            run(&mut runtime, &PARTIAL_TEST_COMMAND),
            SUCCESS_RESPONSE,
            "the completed tests are not run again"
        );
        assert!(!runtime.failure_mode);
    }

    #[test]
    fn full_after_partial_complete_rerun() {
        let mut runtime = started_runtime();
        assert_eq!(run(&mut runtime, &PARTIAL_TEST_COMMAND), SUCCESS_RESPONSE);
        runtime.self_test.set_runner(always_fails);
        assert_eq!(run_code(&mut runtime, &FULL_TEST_COMMAND), TPM_RC_FAILURE);
        for test in PrimitiveTest::ALL {
            assert!(runtime.self_test.pending.contains(test), "{test:?}");
        }
    }

    #[test]
    fn missing_full_test_byte_parameter_one_insufficiency() {
        let mut runtime = started_runtime();
        assert_eq!(
            run_code(&mut runtime, &framed(0x8001, &[])),
            INSUFFICIENT_PARAMETER_1
        );
    }

    #[test]
    fn invalid_yes_no_parameter_one_value_error() {
        let mut runtime = started_runtime();
        for value in [0x02u8, 0x03, 0x7f, 0x80, 0xfe, 0xff] {
            assert_eq!(
                run_code(&mut runtime, &framed(0x8001, &[value])),
                VALUE_PARAMETER_1,
                "fullTest {value:#04x}"
            );
        }
    }

    #[test]
    fn trailing_parameter_size_error() {
        let mut runtime = started_runtime();
        for value in [0x00u8, 0x01] {
            assert_eq!(
                run_code(&mut runtime, &framed(0x8001, &[value, 0x00])),
                SIZE,
                "fullTest {value:#04x}"
            );
            assert_eq!(
                run_code(&mut runtime, &framed(0x8001, &[value, 0xee, 0xee])),
                SIZE,
                "fullTest {value:#04x}"
            );
        }
    }

    #[test]
    fn invalid_value_error_precedence_over_trailing_bytes() {
        let mut runtime = started_runtime();
        assert_eq!(
            run_code(&mut runtime, &framed(0x8001, &[0x02, 0xee])),
            VALUE_PARAMETER_1
        );
    }

    #[test]
    fn rejected_request_tests_pending() {
        let mut runtime = started_runtime();
        for payload in [&[][..], &[0x02][..], &[0x00, 0x00][..]] {
            assert_ne!(run_code(&mut runtime, &framed(0x8001, payload)), 0);
        }
        for test in PrimitiveTest::ALL {
            assert!(runtime.self_test.pending.contains(test), "{test:?}");
        }
        assert!(runtime.self_test.failure.is_none());
        assert!(!runtime.failure_mode);
    }

    #[test]
    fn rejected_parameter_recorded_failure_preservation() {
        let mut runtime = started_runtime();
        runtime.self_test.set_runner(fails_on_sha384);
        assert_eq!(run_code(&mut runtime, &FULL_TEST_COMMAND), TPM_RC_FAILURE);
        let recorded = runtime.self_test.failure;
        let pending = runtime.self_test.pending;
        assert!(recorded.is_some());

        for payload in [&[][..], &[0x02][..], &[0x00, 0x00][..]] {
            assert_ne!(run_code(&mut runtime, &framed(0x8001, payload)), 0);
            assert_eq!(runtime.self_test.failure, recorded);
            assert_eq!(runtime.self_test.pending, pending);
        }
    }

    #[test]
    fn primitive_test_failure_mode() {
        let mut runtime = started_runtime();
        runtime.self_test.set_runner(fails_on_sha384);
        assert_eq!(run_code(&mut runtime, &FULL_TEST_COMMAND), TPM_RC_FAILURE);
        assert!(runtime.failure_mode);
    }

    #[test]
    fn failure_mode_response_bytes() {
        let mut runtime = started_runtime();
        runtime.self_test.set_runner(always_fails);
        assert_eq!(
            run(&mut runtime, &FULL_TEST_COMMAND),
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x01]
        );
    }

    #[test]
    fn failure_progress_preservation() {
        let mut runtime = started_runtime();
        runtime.self_test.set_runner(fails_on_sha384);
        assert_eq!(run_code(&mut runtime, &FULL_TEST_COMMAND), TPM_RC_FAILURE);
        assert!(!runtime.self_test.pending.contains(PrimitiveTest::Sha1));
        assert!(!runtime.self_test.pending.contains(PrimitiveTest::Aes256));
        assert!(!runtime.self_test.pending.contains(PrimitiveTest::Sha256));
        assert!(runtime.self_test.pending.contains(PrimitiveTest::Sha384));
        assert!(runtime.self_test.pending.contains(PrimitiveTest::Sha512));
    }

    #[test]
    fn failure_unrelated_state_unchanged() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        runtime.self_test.set_runner(always_fails);
        assert_eq!(run_code(&mut runtime, &FULL_TEST_COMMAND), TPM_RC_FAILURE);
        assert_eq!(snapshot(&runtime), before);
    }

    #[test]
    fn success_unrelated_state_unchanged() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        assert_eq!(run(&mut runtime, &FULL_TEST_COMMAND), SUCCESS_RESPONSE);
        assert_eq!(run(&mut runtime, &PARTIAL_TEST_COMMAND), SUCCESS_RESPONSE);
        assert_eq!(snapshot(&runtime), before);
    }

    mod rsa_ordering {
        use super::*;
        use crate::library::tpm2::failure_mode::FailureLocation;
        use crate::library::tpm2::rsa_vectors::RawRsaSelfTestStage;
        use core::cell::Cell;

        thread_local! {
            static ORDER: std::cell::RefCell<Vec<&'static str>> =
                const { std::cell::RefCell::new(Vec::new()) };
            static PRIMITIVES: Cell<usize> = const { Cell::new(0) };
        }

        fn note(step: &'static str) {
            ORDER.with(|order| order.borrow_mut().push(step));
        }

        fn taken() -> Vec<&'static str> {
            ORDER.with(|order| core::mem::take(&mut *order.borrow_mut()))
        }

        fn recording_primitive(_test: PrimitiveTest) -> bool {
            if PRIMITIVES.with(Cell::get) == 0 {
                note("primitive");
            }
            PRIMITIVES.with(|count| count.set(count.get() + 1));
            true
        }

        fn recording_raw() -> Result<(), RawRsaSelfTestStage> {
            note("raw");
            crate::library::tpm2::rsa_vectors::run_rsaep_known_answer()
        }

        fn failing_raw() -> Result<(), RawRsaSelfTestStage> {
            note("raw");
            Err(RawRsaSelfTestStage::Decrypt)
        }

        fn recording_rsaes(padding: &[u8]) -> Result<(), PaddedRsaSelfTestStage> {
            note("rsaes");
            crate::library::tpm2::rsa_vectors::run_rsaes_known_answer(padding)
        }

        fn recording_oaep(seed: &[u8]) -> Result<(), PaddedRsaSelfTestStage> {
            note("oaep");
            crate::library::tpm2::rsa_vectors::run_oaep_known_answer(seed)
        }

        fn recording_runtime() -> Tpm2Runtime {
            taken();
            PRIMITIVES.with(|count| count.set(0));
            let mut runtime = started_runtime();
            runtime.self_test.set_runner(recording_primitive);
            runtime.self_test.set_raw_rsa_runner(recording_raw);
            runtime.self_test.set_rsaes_runner(recording_rsaes);
            runtime.self_test.set_oaep_runner(recording_oaep);
            runtime
        }

        #[test]
        fn full_test_raw_before_primitives() {
            let mut runtime = recording_runtime();
            assert_eq!(run(&mut runtime, &FULL_TEST_COMMAND), SUCCESS_RESPONSE);
            assert_eq!(taken(), ["raw", "primitive", "rsaes", "oaep"]);
            assert!(!runtime.self_test.raw_rsa_pending);
            assert!(!runtime.self_test.rsaes_pending);
            assert!(!runtime.self_test.oaep_pending);
        }

        #[test]
        fn partial_test_raw_after_primitives() {
            let mut runtime = recording_runtime();
            assert_eq!(run(&mut runtime, &PARTIAL_TEST_COMMAND), SUCCESS_RESPONSE);
            assert_eq!(taken(), ["primitive", "raw", "rsaes", "oaep"]);
        }

        #[test]
        fn partial_test_raw_after_padded_completion() {
            let mut runtime = recording_runtime();
            runtime.self_test.raw_rsa_pending = true;
            runtime.self_test.rsaes_pending = false;
            runtime.self_test.oaep_pending = false;
            assert_eq!(run(&mut runtime, &PARTIAL_TEST_COMMAND), SUCCESS_RESPONSE);
            assert_eq!(taken(), ["primitive", "raw"]);
            assert!(!runtime.self_test.raw_rsa_pending);
        }

        #[test]
        fn padded_test_raw_pending_clear() {
            for (pending, expected) in [("rsaes", "rsaes"), ("oaep", "oaep")] {
                let mut runtime = recording_runtime();
                runtime.self_test.raw_rsa_pending = false;
                runtime.self_test.rsaes_pending = pending == "rsaes";
                runtime.self_test.oaep_pending = pending == "oaep";
                assert_eq!(run(&mut runtime, &PARTIAL_TEST_COMMAND), SUCCESS_RESPONSE);
                assert_eq!(taken(), ["primitive", expected]);
                assert!(!runtime.self_test.raw_rsa_pending);
                assert!(!runtime.self_test.rsaes_pending);
                assert!(!runtime.self_test.oaep_pending);
            }
        }

        #[test]
        fn repeated_partial_no_rsa_rerun() {
            let mut runtime = recording_runtime();
            assert_eq!(run(&mut runtime, &PARTIAL_TEST_COMMAND), SUCCESS_RESPONSE);
            assert_eq!(taken(), ["primitive", "raw", "rsaes", "oaep"]);
            let requests = runtime.live.orderly.drbg_state.reseed_counter;
            assert_eq!(run(&mut runtime, &PARTIAL_TEST_COMMAND), SUCCESS_RESPONSE);
            assert_eq!(taken(), [] as [&str; 0]);
            assert_eq!(runtime.live.orderly.drbg_state.reseed_counter, requests);
        }

        #[test]
        fn raw_failure_abort_before_padded() {
            let mut runtime = recording_runtime();
            runtime.self_test.set_raw_rsa_runner(failing_raw);
            assert_eq!(
                run_code(&mut runtime, &PARTIAL_TEST_COMMAND),
                TPM_RC_FAILURE
            );
            assert_eq!(taken(), ["primitive", "raw"]);
            assert!(runtime.failure_mode);
            assert_eq!(
                runtime.failure_diagnostics,
                FailureLocation::RsaRawDecrypt.diagnostics()
            );
            assert!(runtime.self_test.raw_rsa_pending);
            assert!(runtime.self_test.rsaes_pending);
            assert!(runtime.self_test.oaep_pending);
        }

        #[test]
        fn padded_failure_pending_at_reference_site() {
            for scheme in ["rsaes", "oaep"] {
                let mut runtime = recording_runtime();
                runtime.self_test.raw_rsa_pending = false;
                runtime.self_test.rsaes_pending = scheme == "rsaes";
                runtime.self_test.oaep_pending = scheme == "oaep";
                if scheme == "rsaes" {
                    runtime
                        .self_test
                        .set_rsaes_runner(|_| Err(PaddedRsaSelfTestStage::KnownAnswerCompare));
                } else {
                    runtime
                        .self_test
                        .set_oaep_runner(|_| Err(PaddedRsaSelfTestStage::KnownAnswerCompare));
                }
                assert_eq!(
                    run_code(&mut runtime, &PARTIAL_TEST_COMMAND),
                    TPM_RC_FAILURE
                );
                assert!(runtime.failure_mode);
                assert_eq!(
                    runtime.failure_diagnostics,
                    FailureLocation::RsaOaepKnownAnswerCompare.diagnostics()
                );
                assert_eq!(runtime.self_test.rsaes_pending, scheme == "rsaes");
                assert_eq!(runtime.self_test.oaep_pending, scheme == "oaep");
                assert!(!runtime.self_test.raw_rsa_pending, "{scheme}");
            }
        }
    }

    mod oaep {
        use super::*;
        use crate::library::tpm2::failure_mode::FailureLocation;
        use crate::library::tpm2::self_test::self_test_rsa_oaep;
        use core::cell::Cell;

        thread_local! {
            static CALLS: Cell<usize> = const { Cell::new(0) };
        }

        fn counting_runner(seed: &[u8]) -> Result<(), PaddedRsaSelfTestStage> {
            CALLS.with(|calls| calls.set(calls.get() + 1));
            assert_eq!(seed.len(), 64, "the reference draws a SHA-512 sized seed");
            crate::library::tpm2::rsa_vectors::run_oaep_known_answer(seed)
        }

        fn counting_runtime() -> Tpm2Runtime {
            CALLS.with(|calls| calls.set(0));
            let mut runtime = started_runtime();
            runtime.self_test.set_oaep_runner(counting_runner);
            runtime
        }

        fn calls() -> usize {
            CALLS.with(Cell::get)
        }

        fn drbg_requests(runtime: &Tpm2Runtime) -> u64 {
            runtime.live.orderly.drbg_state.reseed_counter
        }

        #[test]
        fn full_test_single_kat_run() {
            let mut runtime = counting_runtime();
            let requests = drbg_requests(&runtime);
            assert_eq!(run(&mut runtime, &FULL_TEST_COMMAND), SUCCESS_RESPONSE);
            assert_eq!(calls(), 1);
            assert!(!runtime.self_test.oaep_pending);
            assert!(!runtime.failure_mode);
            assert_eq!(
                drbg_requests(&runtime),
                requests + 2,
                "the reference draws one RSAES pad and one OAEP seed per full test"
            );
        }

        #[test]
        fn partial_test_pending_kat_run() {
            let mut runtime = counting_runtime();
            assert!(runtime.self_test.oaep_pending);
            assert_eq!(run(&mut runtime, &PARTIAL_TEST_COMMAND), SUCCESS_RESPONSE);
            assert_eq!(calls(), 1);
            assert!(!runtime.self_test.oaep_pending);
        }

        #[test]
        fn partial_after_passed_kat_no_rerun() {
            let mut runtime = counting_runtime();
            assert_eq!(run(&mut runtime, &PARTIAL_TEST_COMMAND), SUCCESS_RESPONSE);
            let requests = drbg_requests(&runtime);
            assert_eq!(run(&mut runtime, &PARTIAL_TEST_COMMAND), SUCCESS_RESPONSE);
            assert_eq!(calls(), 1, "the cleared test is not run again");
            assert_eq!(drbg_requests(&runtime), requests, "and draws no seed");
        }

        #[test]
        fn lazy_kat_partial_test_skip() {
            let mut runtime = counting_runtime();
            assert_eq!(self_test_rsa_oaep(&mut runtime), Ok(()));
            assert_eq!(calls(), 1);
            assert!(!runtime.self_test.oaep_pending);
            assert_eq!(run(&mut runtime, &PARTIAL_TEST_COMMAND), SUCCESS_RESPONSE);
            assert_eq!(calls(), 1, "the lazy path already cleared it");
        }

        #[test]
        fn full_test_passed_kat_rerun() {
            let mut runtime = counting_runtime();
            assert_eq!(self_test_rsa_oaep(&mut runtime), Ok(()));
            assert_eq!(calls(), 1);
            assert_eq!(run(&mut runtime, &FULL_TEST_COMMAND), SUCCESS_RESPONSE);
            assert_eq!(calls(), 2, "fullTest rearms every test");
            assert!(!runtime.self_test.oaep_pending);
        }

        #[test]
        fn kat_failure_vendored_site() {
            for (runner, location) in oaep_failure_table() {
                for command in [FULL_TEST_COMMAND, PARTIAL_TEST_COMMAND] {
                    let mut runtime = started_runtime();
                    runtime.self_test.set_oaep_runner(runner);
                    assert_eq!(
                        run_code(&mut runtime, &command),
                        TPM_RC_FAILURE,
                        "{location:?}"
                    );
                    assert!(runtime.failure_mode, "{location:?}");
                    assert_eq!(runtime.failure_diagnostics, location.diagnostics());
                    assert!(
                        runtime.self_test.oaep_pending,
                        "{location:?} leaves OAEP untested"
                    );
                    assert!(
                        runtime.self_test.failure.is_none(),
                        "no primitive is blamed for an OAEP failure"
                    );
                }
            }
        }

        #[test]
        fn sha512_dependency_failure_before_kat() {
            let mut runtime = counting_runtime();
            runtime.self_test.set_runner(fails_on_sha512);
            assert_eq!(run_code(&mut runtime, &FULL_TEST_COMMAND), TPM_RC_FAILURE);
            assert_eq!(calls(), 0, "the OAEP test never starts");
            assert!(runtime.self_test.oaep_pending);
            assert_eq!(
                runtime.failure_diagnostics,
                FailureLocation::HashSelfTest.diagnostics()
            );
        }

        #[test]
        fn unusable_drbg_kat_prestart_failure() {
            let mut runtime = counting_runtime();
            runtime.self_test.set_runner(|_| true);
            runtime.live.orderly.drbg_state.drbg_magic ^= 0xffff_ffff;
            assert_eq!(run_code(&mut runtime, &FULL_TEST_COMMAND), TPM_RC_FAILURE);
            assert_eq!(calls(), 0);
            assert!(runtime.self_test.oaep_pending);
            assert_eq!(
                runtime.failure_diagnostics,
                FailureLocation::DrbgInvalidState.diagnostics()
            );
        }

        #[test]
        fn latched_entropy_failure_kat_continuation() {
            let mut runtime = counting_runtime();
            runtime.entropy_bad = true;
            assert_eq!(run(&mut runtime, &FULL_TEST_COMMAND), SUCCESS_RESPONSE);
            assert_eq!(calls(), 1);
            assert!(
                runtime.entropy_bad,
                "the latch survives a successful self test"
            );
        }
    }

    #[test]
    fn password_session_nonexistent_handle_rejection() {
        let mut runtime = started_runtime();
        let mut payload = 0x09u32.to_be_bytes().to_vec();
        payload.extend_from_slice(&[0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00]);
        payload.push(0x00);
        assert_eq!(
            run_code(&mut runtime, &framed(0x8002, &payload)),
            SESSION1_HANDLE
        );
        for test in PrimitiveTest::ALL {
            assert!(runtime.self_test.pending.contains(test), "{test:?}");
        }
    }

    #[test]
    fn session_tag_missing_auth_size_insufficiency() {
        let mut runtime = started_runtime();
        assert_eq!(run_code(&mut runtime, &framed(0x8002, &[])), INSUFFICIENT);
    }

    #[test]
    fn session_tag_short_auth_area_size_error() {
        let mut runtime = started_runtime();
        let mut payload = 0u32.to_be_bytes().to_vec();
        payload.push(0x00);
        assert_eq!(run_code(&mut runtime, &framed(0x8002, &payload)), SIZE);
    }

    #[test]
    fn yes_no_parsing_defined_values_only() {
        assert_eq!(parse_full_test(&[0x00]), Ok(false));
        assert_eq!(parse_full_test(&[0x01]), Ok(true));
        assert_eq!(
            parse_full_test(&[]),
            Err(TPM_RC_INSUFFICIENT + RC_SELF_TEST_FULL_TEST)
        );
        for value in 2..=u8::MAX {
            assert_eq!(
                parse_full_test(&[value]),
                Err(TPM_RC_VALUE + RC_SELF_TEST_FULL_TEST),
                "fullTest {value:#04x}"
            );
        }
    }

    #[test]
    fn short_command_body_panic_safety() {
        for length in 0..=4usize {
            for byte in 0..=u8::MAX {
                let payload: Vec<u8> = (0..length).map(|_| byte).collect();
                for tag in [0x8001u16, 0x8002] {
                    let mut runtime = started_runtime();
                    let bytes = framed(tag, &payload);
                    let input = CommandInput::new(bytes.len() as u32, bytes);
                    let parsed = parse_command(&input).expect("the header parses");
                    let _ = serialize_response(&dispatch(
                        &mut runtime,
                        &parsed,
                        CancellationToken::disabled(),
                    ));
                }
            }
        }
    }
}
