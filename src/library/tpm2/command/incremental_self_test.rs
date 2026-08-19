use crate::ffi_types::TpmResult;
use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_INSUFFICIENT, TPM_RC_SIZE, TPM_RC_VALUE};

use super::super::failure_mode::{FailureLocation, enter_failure_mode};
use super::super::marshal::BlobReader;
use super::super::runtime::Tpm2Runtime;
use super::super::self_test::SelectedTestError;
use super::dispatcher::CommandFrame;
use super::output::CommandOutput;

const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;
const RC_INCREMENTAL_SELF_TEST_TO_TEST: TpmResult = TPM_RC_P + TPM_RC_1;

const MAX_ALG_LIST_SIZE: u32 = 64;

pub(super) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let to_test = parse_to_test(frame.parameters)?;
    match runtime.self_test.run_selected(&to_test) {
        Ok(()) => Ok(CommandOutput::from_parameters(marshal_to_do_list(
            &runtime.self_test.pending_algorithms(),
        ))),
        Err(SelectedTestError::UnsupportedAlgorithm(_)) => {
            Err(TPM_RC_VALUE + RC_INCREMENTAL_SELF_TEST_TO_TEST)
        }
        Err(SelectedTestError::TestFailed) => {
            let location = FailureLocation::for_self_test(&runtime.self_test);
            enter_failure_mode(runtime, location);
            Err(TPM_RC_FAILURE)
        }
    }
}

fn parse_to_test(parameters: &[u8]) -> Result<Vec<u16>, TpmResult> {
    let mut reader = BlobReader::new(parameters);
    let count = reader
        .read_u32()
        .map_err(|_| TPM_RC_INSUFFICIENT + RC_INCREMENTAL_SELF_TEST_TO_TEST)?;
    if count > MAX_ALG_LIST_SIZE {
        return Err(TPM_RC_SIZE + RC_INCREMENTAL_SELF_TEST_TO_TEST);
    }
    let mut algorithms = Vec::with_capacity(count as usize);
    for _ in 0..count {
        algorithms.push(
            reader
                .read_u16()
                .map_err(|_| TPM_RC_INSUFFICIENT + RC_INCREMENTAL_SELF_TEST_TO_TEST)?,
        );
    }
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(algorithms)
}

fn marshal_to_do_list(algorithms: &[u16]) -> Vec<u8> {
    let mut out = (algorithms.len() as u32).to_be_bytes().to_vec();
    for &algorithm in algorithms {
        out.extend_from_slice(&algorithm.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::dispatcher::dispatch;
    use super::super::header::{parse_command, serialize_response};
    use super::super::registry::TPM_CC_INCREMENTAL_SELF_TEST;
    use super::*;
    use crate::library::CommandInput;
    use crate::library::cancel::CancelSignal;
    use crate::library::constants::TPM_RC_INITIALIZE;
    use crate::library::tpm2::algorithm::{
        TPM_ALG_AES, TPM_ALG_ECC, TPM_ALG_ERROR, TPM_ALG_RSA, TPM_ALG_SHA1, TPM_ALG_SHA256,
        TPM_ALG_SHA384, TPM_ALG_SHA512,
    };
    use crate::library::tpm2::profile::{DEFAULT_ALGORITHMS_PROFILE, validate_user_profile};
    use crate::library::tpm2::runtime::{Tpm2Runtime, empty_state_runtime};
    use crate::library::tpm2::self_test::{
        PrimitiveTest, SelfTestFailure, SelfTestState, always_fails, fails_on_sha384,
    };
    use core::cell::Cell;

    const SWTPM_BIOS_COMMAND: [u8; 16] = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x01, 0x42, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x0b,
    ];
    const SWTPM_BIOS_RESPONSE: [u8; 22] = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
        0x04, 0x00, 0x06, 0x00, 0x0c, 0x00, 0x0d,
    ];

    const INSUFFICIENT_PARAMETER_1: u32 = 0x1da;
    const SIZE_PARAMETER_1: u32 = 0x1d5;
    const VALUE_PARAMETER_1: u32 = 0x1c4;
    const SIZE: u32 = 0x095;
    const FAILURE: u32 = 0x101;
    const SESSION1_HANDLE: u32 = 0x98b;
    const INSUFFICIENT: u32 = 0x09a;

    thread_local! {
        static EXECUTED: Cell<u8> = const { Cell::new(0) };
        static RUN_COUNT: Cell<usize> = const { Cell::new(0) };
    }

    fn recording_runner(test: PrimitiveTest) -> bool {
        EXECUTED.with(|executed| executed.set(executed.get() | 1 << test as u8));
        RUN_COUNT.with(|count| count.set(count.get() + 1));
        true
    }

    fn executed() -> Vec<PrimitiveTest> {
        let bits = EXECUTED.with(Cell::get);
        PrimitiveTest::ALL
            .into_iter()
            .filter(|test| bits & 1 << *test as u8 != 0)
            .collect()
    }

    fn recording_runtime() -> Box<Tpm2Runtime> {
        EXECUTED.with(|executed| executed.set(0));
        RUN_COUNT.with(|count| count.set(0));
        let mut runtime = started_runtime();
        runtime.self_test.set_runner(recording_runner);
        runtime
    }

    fn to_test(algorithms: &[u16]) -> Vec<u8> {
        let mut payload = (algorithms.len() as u32).to_be_bytes().to_vec();
        for &algorithm in algorithms {
            payload.extend_from_slice(&algorithm.to_be_bytes());
        }
        payload
    }

    fn framed(tag: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = tag.to_be_bytes().to_vec();
        out.extend_from_slice(&(10 + payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&TPM_CC_INCREMENTAL_SELF_TEST.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn started_runtime() -> Box<Tpm2Runtime> {
        let mut runtime = empty_state_runtime();
        runtime.startup_received = true;
        runtime
    }

    #[track_caller]
    fn run(runtime: &mut Tpm2Runtime, bytes: &[u8]) -> Vec<u8> {
        let input = CommandInput::new(bytes.len() as u32, bytes.to_vec());
        let parsed = parse_command(&input).expect("the header parses");
        serialize_response(&dispatch(runtime, &parsed)).expect("the response fits")
    }

    #[track_caller]
    fn run_code(runtime: &mut Tpm2Runtime, bytes: &[u8]) -> u32 {
        let input = CommandInput::new(bytes.len() as u32, bytes.to_vec());
        let parsed = parse_command(&input).expect("the header parses");
        dispatch(runtime, &parsed).code()
    }

    #[track_caller]
    fn to_do_list(runtime: &mut Tpm2Runtime, algorithms: &[u16]) -> Vec<u16> {
        let response = run(runtime, &framed(0x8001, &to_test(algorithms)));
        assert_eq!(
            &response[6..10],
            &[0x00, 0x00, 0x00, 0x00],
            "{response:02x?}"
        );
        let count = u32::from_be_bytes(response[10..14].try_into().unwrap()) as usize;
        let reported: Vec<u16> = response[14..]
            .chunks_exact(2)
            .map(|pair| u16::from_be_bytes(pair.try_into().unwrap()))
            .collect();
        assert_eq!(reported.len(), count);
        reported
    }

    #[derive(Debug, Eq, PartialEq)]
    struct RuntimeSnapshot {
        nv_memory: Vec<u8>,
        nv_update_pending: bool,
        manufactured: bool,
        startup_received: bool,
        tpm_established: bool,
        locality: u8,
        power_on: bool,
        nv_available: bool,
    }

    fn snapshot(runtime: &Tpm2Runtime) -> RuntimeSnapshot {
        RuntimeSnapshot {
            nv_memory: runtime.nv_memory.to_vec(),
            nv_update_pending: runtime.nv_update_pending,
            manufactured: runtime.manufactured,
            startup_received: runtime.startup_received,
            tpm_established: runtime.tpm_established,
            locality: runtime.locality,
            power_on: runtime.power_on,
            nv_available: runtime.nv_available,
        }
    }

    #[track_caller]
    fn stays_uncancelable(algorithm: u16, primitive: PrimitiveTest) {
        let mut runtime = recording_runtime();
        runtime.cancel = CancelSignal::signaled();
        let snapshot_before = snapshot(&runtime);

        let response = run(&mut runtime, &framed(0x8001, &to_test(&[algorithm])));
        assert_eq!(
            &response[6..10],
            &[0x00, 0x00, 0x00, 0x00],
            "no Rust primitive reaches an upstream cancellation checkpoint: {response:02x?}"
        );
        assert_eq!(executed(), [primitive], "the selected primitive still ran");
        assert!(!runtime.failure_mode);
        assert!(runtime.self_test.failure.is_none());
        assert!(!runtime.self_test.pending.contains(primitive));
        assert_eq!(
            snapshot(&runtime),
            snapshot_before,
            "no NVRAM write is scheduled"
        );
        assert!(
            runtime.cancel.is_signaled(),
            "dispatch neither consults nor clears the pin"
        );
    }

    #[test]
    fn a_raised_pin_does_not_cancel_an_incremental_sha1_test() {
        stays_uncancelable(TPM_ALG_SHA1, PrimitiveTest::Sha1);
    }

    #[test]
    fn a_raised_pin_does_not_cancel_an_incremental_sha256_test() {
        stays_uncancelable(TPM_ALG_SHA256, PrimitiveTest::Sha256);
    }

    #[test]
    fn a_raised_pin_does_not_cancel_an_incremental_aes_test() {
        stays_uncancelable(TPM_ALG_AES, PrimitiveTest::Aes256);
    }

    #[test]
    fn a_raised_pin_does_not_cancel_an_incremental_sha384_or_sha512_test() {
        stays_uncancelable(TPM_ALG_SHA384, PrimitiveTest::Sha384);
        stays_uncancelable(TPM_ALG_SHA512, PrimitiveTest::Sha512);
    }

    #[test]
    fn a_raised_pin_leaves_a_whole_incremental_list_running_to_completion() {
        let mut runtime = recording_runtime();
        runtime.cancel = CancelSignal::signaled();
        assert_eq!(
            to_do_list(&mut runtime, &[TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_AES]),
            [TPM_ALG_SHA384, TPM_ALG_SHA512]
        );
        assert_eq!(RUN_COUNT.with(Cell::get), 3, "every selected test ran");
        assert!(!runtime.failure_mode);
    }

    #[test]
    fn a_raised_pin_does_not_change_a_rejected_list_or_a_failing_test() {
        let mut runtime = recording_runtime();
        runtime.cancel = CancelSignal::signaled();
        assert_eq!(
            run_code(&mut runtime, &framed(0x8001, &to_test(&[TPM_ALG_ERROR]))),
            VALUE_PARAMETER_1
        );
        assert!(!runtime.failure_mode);

        let mut runtime = started_runtime();
        runtime.cancel = CancelSignal::signaled();
        runtime.self_test.set_runner(always_fails);
        assert_eq!(
            run_code(&mut runtime, &framed(0x8001, &to_test(&[TPM_ALG_SHA256]))),
            FAILURE,
            "a genuine self-test failure is unaffected by the pin"
        );
        assert!(runtime.failure_mode);
        assert_eq!(
            runtime.self_test.failure,
            Some(SelfTestFailure {
                primitive: PrimitiveTest::Sha256
            })
        );
    }

    #[test]
    fn the_swtpm_bios_request_answers_the_remaining_rust_self_tests() {
        let mut runtime = started_runtime();
        assert_eq!(run(&mut runtime, &SWTPM_BIOS_COMMAND), SWTPM_BIOS_RESPONSE);
        assert!(!runtime.failure_mode);
        assert!(!runtime.self_test.pending.contains(PrimitiveTest::Sha256));
    }

    #[test]
    fn the_swtpm_bios_request_carries_one_sha256_entry() {
        assert_eq!(
            &SWTPM_BIOS_COMMAND[10..],
            to_test(&[TPM_ALG_SHA256]).as_slice()
        );
    }

    #[test]
    fn an_incremental_test_before_startup_is_rejected() {
        let mut runtime = empty_state_runtime();
        assert_eq!(
            run_code(&mut runtime, &SWTPM_BIOS_COMMAND),
            TPM_RC_INITIALIZE
        );
        assert!(!runtime.failure_mode);
        for test in PrimitiveTest::ALL {
            assert!(runtime.self_test.pending.contains(test), "{test:?}");
        }
    }

    #[test]
    fn an_empty_list_runs_nothing_and_reports_the_current_pending_tests() {
        let mut runtime = recording_runtime();
        assert_eq!(
            to_do_list(&mut runtime, &[]),
            [
                TPM_ALG_SHA1,
                TPM_ALG_AES,
                TPM_ALG_SHA256,
                TPM_ALG_SHA384,
                TPM_ALG_SHA512
            ]
        );
        assert!(executed().is_empty());
    }

    #[test]
    fn a_single_algorithm_runs_only_its_mapped_primitive() {
        for (algorithm, expected) in [
            (TPM_ALG_SHA1, PrimitiveTest::Sha1),
            (TPM_ALG_SHA256, PrimitiveTest::Sha256),
            (TPM_ALG_SHA384, PrimitiveTest::Sha384),
            (TPM_ALG_SHA512, PrimitiveTest::Sha512),
            (TPM_ALG_AES, PrimitiveTest::Aes256),
        ] {
            let mut runtime = recording_runtime();
            let remaining = to_do_list(&mut runtime, &[algorithm]);
            assert_eq!(executed(), [expected], "algorithm {algorithm:#06x}");
            assert!(!remaining.contains(&algorithm));
            assert_eq!(remaining.len(), 4);
        }
    }

    #[test]
    fn several_algorithms_run_exactly_the_selected_primitives() {
        let mut runtime = recording_runtime();
        assert_eq!(
            to_do_list(&mut runtime, &[TPM_ALG_SHA512, TPM_ALG_AES]),
            [TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384]
        );
        assert_eq!(executed(), [PrimitiveTest::Aes256, PrimitiveTest::Sha512]);
    }

    #[test]
    fn duplicate_algorithm_ids_run_the_primitive_once() {
        let mut runtime = recording_runtime();
        assert_eq!(
            to_do_list(
                &mut runtime,
                &[
                    TPM_ALG_SHA256,
                    TPM_ALG_SHA256,
                    TPM_ALG_SHA256,
                    TPM_ALG_SHA256
                ]
            ),
            [TPM_ALG_SHA1, TPM_ALG_AES, TPM_ALG_SHA384, TPM_ALG_SHA512]
        );
        assert_eq!(executed(), [PrimitiveTest::Sha256]);
        assert_eq!(RUN_COUNT.with(Cell::get), 1);

        let mut runtime = recording_runtime();
        assert_eq!(
            to_do_list(
                &mut runtime,
                &[TPM_ALG_SHA256, TPM_ALG_AES, TPM_ALG_SHA256, TPM_ALG_AES]
            ),
            [TPM_ALG_SHA1, TPM_ALG_SHA384, TPM_ALG_SHA512]
        );
        assert_eq!(RUN_COUNT.with(Cell::get), 2);
    }

    #[test]
    fn an_explicitly_requested_completed_primitive_is_tested_again() {
        let mut runtime = started_runtime();
        assert_eq!(to_do_list(&mut runtime, &[TPM_ALG_SHA256]).len(), 4);
        assert!(!runtime.self_test.pending.contains(PrimitiveTest::Sha256));

        EXECUTED.with(|executed| executed.set(0));
        RUN_COUNT.with(|count| count.set(0));
        runtime.self_test.set_runner(recording_runner);
        assert_eq!(to_do_list(&mut runtime, &[TPM_ALG_SHA256]).len(), 4);
        assert_eq!(executed(), [PrimitiveTest::Sha256]);
        assert_eq!(RUN_COUNT.with(Cell::get), 1);
    }

    #[test]
    fn the_pending_list_is_reported_in_ascending_algorithm_order() {
        let mut runtime = started_runtime();
        let reported = to_do_list(&mut runtime, &[]);
        assert!(
            reported.windows(2).all(|pair| pair[0] < pair[1]),
            "{reported:#06x?}"
        );
        assert_eq!(
            reported,
            [
                TPM_ALG_SHA1,
                TPM_ALG_AES,
                TPM_ALG_SHA256,
                TPM_ALG_SHA384,
                TPM_ALG_SHA512
            ]
        );
    }

    #[test]
    fn a_completed_test_run_reports_an_empty_list() {
        let mut runtime = started_runtime();
        assert_eq!(
            to_do_list(
                &mut runtime,
                &[
                    TPM_ALG_SHA1,
                    TPM_ALG_SHA256,
                    TPM_ALG_SHA384,
                    TPM_ALG_SHA512,
                    TPM_ALG_AES
                ]
            ),
            Vec::new()
        );
        assert!(runtime.self_test.pending.is_empty());
        assert_eq!(
            run(&mut runtime, &framed(0x8001, &to_test(&[]))),
            [
                0x80, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );
    }

    #[test]
    fn an_unknown_algorithm_is_a_parameter_one_value_error() {
        let mut runtime = recording_runtime();
        for algorithm in [TPM_ALG_ERROR, 0x0002, 0x0027, 0x00ff, 0x7fff, 0xffff] {
            assert_eq!(
                run_code(&mut runtime, &framed(0x8001, &to_test(&[algorithm]))),
                VALUE_PARAMETER_1,
                "algorithm {algorithm:#06x}"
            );
        }
        assert!(executed().is_empty());
        assert!(!runtime.failure_mode);
    }

    #[test]
    fn a_profile_disabled_algorithm_is_a_parameter_one_value_error() {
        const MINIMAL_ALGORITHMS: &str = "rsa,hmac,aes,mgf1,keyedhash,xor,sha256,sha384,null,oaep,\
ecdsa,ecdh,kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,symcipher,cfb,ecc-nist-p256,ecc-nist-p384";

        let profile = format!(r#"{{"Name":"custom","Algorithms":"{MINIMAL_ALGORITHMS}"}}"#);
        let profile =
            validate_user_profile(Some(profile.as_bytes())).expect("the profile validates");
        let mut runtime = started_runtime();
        runtime.self_test = SelfTestState::for_profile(&profile);
        for algorithm in [TPM_ALG_SHA1, TPM_ALG_SHA512] {
            assert_eq!(
                run_code(&mut runtime, &framed(0x8001, &to_test(&[algorithm]))),
                VALUE_PARAMETER_1,
                "algorithm {algorithm:#06x}"
            );
        }
        assert_eq!(
            to_do_list(&mut runtime, &[TPM_ALG_SHA256]),
            [TPM_ALG_AES, TPM_ALG_SHA384],
            "only the profile-enabled primitives with a Rust test remain"
        );
    }

    #[test]
    fn an_enabled_algorithm_without_a_rust_test_succeeds_without_being_reported() {
        let mut runtime = recording_runtime();
        let reported = to_do_list(&mut runtime, &[TPM_ALG_RSA, TPM_ALG_ECC]);
        assert!(executed().is_empty());
        assert_eq!(
            reported,
            [
                TPM_ALG_SHA1,
                TPM_ALG_AES,
                TPM_ALG_SHA256,
                TPM_ALG_SHA384,
                TPM_ALG_SHA512
            ]
        );
        assert!(!reported.contains(&TPM_ALG_RSA));
        assert!(!reported.contains(&TPM_ALG_ECC));
    }

    #[test]
    fn the_whole_list_is_validated_before_any_test_runs() {
        let mut runtime = recording_runtime();
        assert_eq!(
            run_code(
                &mut runtime,
                &framed(0x8001, &to_test(&[TPM_ALG_SHA256, 0xffff]))
            ),
            VALUE_PARAMETER_1
        );
        assert!(executed().is_empty(), "no primitive ran");
        for test in PrimitiveTest::ALL {
            assert!(runtime.self_test.pending.contains(test), "{test:?}");
        }
        assert!(runtime.self_test.failure.is_none());
        assert!(!runtime.failure_mode);
    }

    #[test]
    fn a_missing_count_is_an_insufficient_parameter_one() {
        let mut runtime = started_runtime();
        for length in 0..4usize {
            assert_eq!(
                run_code(&mut runtime, &framed(0x8001, &vec![0u8; length])),
                INSUFFICIENT_PARAMETER_1,
                "{length} of 4 count bytes"
            );
        }
    }

    #[test]
    fn a_truncated_algorithm_entry_is_an_insufficient_parameter_one() {
        let mut runtime = started_runtime();
        for payload in [
            &[0x00, 0x00, 0x00, 0x01][..],
            &[0x00, 0x00, 0x00, 0x01, 0x00][..],
            &[0x00, 0x00, 0x00, 0x02, 0x00, 0x0b][..],
            &[0x00, 0x00, 0x00, 0x02, 0x00, 0x0b, 0x00][..],
        ] {
            assert_eq!(
                run_code(&mut runtime, &framed(0x8001, payload)),
                INSUFFICIENT_PARAMETER_1,
                "payload {payload:02x?}"
            );
        }
    }

    #[test]
    fn a_count_above_the_upstream_maximum_is_a_size_parameter_one() {
        let mut runtime = started_runtime();
        for count in [65u32, 100, 0xffff, u32::MAX] {
            let mut payload = count.to_be_bytes().to_vec();
            payload.extend_from_slice(&[0x00, 0x0b]);
            assert_eq!(
                run_code(&mut runtime, &framed(0x8001, &payload)),
                SIZE_PARAMETER_1,
                "count {count}"
            );
        }
    }

    #[test]
    fn the_upstream_maximum_count_is_accepted_and_validated() {
        let mut runtime = started_runtime();
        let algorithms = [TPM_ALG_SHA256; 64];
        assert_eq!(to_do_list(&mut runtime, &algorithms).len(), 4);
        assert_eq!(
            run_code(&mut runtime, &framed(0x8001, &to_test(&[0xffff; 64]))),
            VALUE_PARAMETER_1
        );
    }

    #[test]
    fn trailing_parameter_bytes_are_a_size_error() {
        let mut runtime = started_runtime();
        for extra in [&[0x00][..], &[0x00, 0x0b][..], &[0xee, 0xee, 0xee][..]] {
            let mut payload = to_test(&[TPM_ALG_SHA256]);
            payload.extend_from_slice(extra);
            assert_eq!(
                run_code(&mut runtime, &framed(0x8001, &payload)),
                SIZE,
                "trailing {extra:02x?}"
            );
            let mut payload = to_test(&[]);
            payload.extend_from_slice(extra);
            assert_eq!(run_code(&mut runtime, &framed(0x8001, &payload)), SIZE);
        }
        for test in PrimitiveTest::ALL {
            assert!(runtime.self_test.pending.contains(test), "{test:?}");
        }
    }

    #[test]
    fn a_rejected_request_never_enters_failure_mode() {
        let mut runtime = started_runtime();
        runtime.self_test.set_runner(always_fails);
        for payload in [
            &[][..],
            &[0x00, 0x00, 0x00][..],
            &[0x00, 0x00, 0x00, 0x41, 0x00, 0x0b][..],
            &[0x00, 0x00, 0x00, 0x01, 0xff, 0xff][..],
            &[0x00, 0x00, 0x00, 0x00, 0x00][..],
        ] {
            assert_ne!(run_code(&mut runtime, &framed(0x8001, payload)), 0);
            assert!(!runtime.failure_mode, "payload {payload:02x?}");
            assert!(runtime.self_test.failure.is_none());
        }
    }

    #[test]
    fn a_failing_known_answer_test_records_the_primitive_and_fails_the_tpm() {
        let mut runtime = started_runtime();
        runtime.self_test.set_runner(fails_on_sha384);
        assert_eq!(
            run(
                &mut runtime,
                &framed(0x8001, &to_test(&[TPM_ALG_SHA256, TPM_ALG_SHA384]))
            ),
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x01]
        );
        assert!(runtime.failure_mode);
        assert_eq!(
            runtime.self_test.failure,
            Some(SelfTestFailure {
                primitive: PrimitiveTest::Sha384
            })
        );
        assert!(!runtime.self_test.pending.contains(PrimitiveTest::Sha256));
        assert!(runtime.self_test.pending.contains(PrimitiveTest::Sha384));
        assert!(runtime.self_test.pending.contains(PrimitiveTest::Sha512));
        assert!(runtime.self_test.pending.contains(PrimitiveTest::Aes256));
    }

    #[test]
    fn a_failure_answers_the_bare_failure_response() {
        let mut runtime = started_runtime();
        runtime.self_test.set_runner(always_fails);
        assert_eq!(run_code(&mut runtime, &SWTPM_BIOS_COMMAND), FAILURE);
    }

    #[test]
    fn a_failure_does_not_touch_unrelated_runtime_state() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        runtime.self_test.set_runner(always_fails);
        assert_eq!(run_code(&mut runtime, &SWTPM_BIOS_COMMAND), FAILURE);
        assert_eq!(snapshot(&runtime), before);
    }

    #[test]
    fn a_successful_test_does_not_touch_unrelated_runtime_state() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        assert_eq!(run(&mut runtime, &SWTPM_BIOS_COMMAND), SWTPM_BIOS_RESPONSE);
        assert_eq!(to_do_list(&mut runtime, &[TPM_ALG_SHA1]).len(), 3);
        assert_eq!(snapshot(&runtime), before);
    }

    #[test]
    fn a_session_tagged_request_answers_through_the_session_response_path() {
        let mut runtime = started_runtime();
        let mut payload = 0x09u32.to_be_bytes().to_vec();
        payload.extend_from_slice(&[0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00]);
        payload.extend_from_slice(&to_test(&[TPM_ALG_SHA256]));
        assert_eq!(
            run_code(&mut runtime, &framed(0x8002, &payload)),
            SESSION1_HANDLE,
            "a password session is not associated with a nonexistent handle"
        );
        assert_eq!(run_code(&mut runtime, &framed(0x8002, &[])), INSUFFICIENT);
    }

    #[test]
    fn the_default_profile_enables_every_mapped_algorithm() {
        let state = SelfTestState::for_algorithms(DEFAULT_ALGORITHMS_PROFILE);
        assert_eq!(
            state.pending_algorithms(),
            [
                TPM_ALG_SHA1,
                TPM_ALG_AES,
                TPM_ALG_SHA256,
                TPM_ALG_SHA384,
                TPM_ALG_SHA512
            ]
        );
    }

    #[test]
    fn parsing_decodes_big_endian_lists() {
        assert_eq!(parse_to_test(&[0x00, 0x00, 0x00, 0x00]), Ok(Vec::new()));
        assert_eq!(
            parse_to_test(&[0x00, 0x00, 0x00, 0x02, 0x00, 0x0b, 0x01, 0x02]),
            Ok(vec![0x000b, 0x0102])
        );
        assert_eq!(
            parse_to_test(&[0x00, 0x00, 0x00, 0x41]),
            Err(SIZE_PARAMETER_1)
        );
        assert_eq!(
            parse_to_test(&[0x00, 0x00, 0x00]),
            Err(INSUFFICIENT_PARAMETER_1)
        );
    }

    #[test]
    fn malformed_command_bodies_never_panic() {
        for length in 0..=6usize {
            for byte in 0..=u8::MAX {
                let payload: Vec<u8> = (0..length).map(|_| byte).collect();
                for tag in [0x8001u16, 0x8002] {
                    let mut runtime = started_runtime();
                    let bytes = framed(tag, &payload);
                    let input = CommandInput::new(bytes.len() as u32, bytes);
                    let parsed = parse_command(&input).expect("the header parses");
                    let _ = serialize_response(&dispatch(&mut runtime, &parsed));
                }
            }
        }
    }

    #[test]
    fn an_oversized_count_never_allocates_ahead_of_the_payload() {
        for count in [0x0000_0041u32, 0x00ff_ffff, u32::MAX] {
            assert_eq!(parse_to_test(&count.to_be_bytes()), Err(SIZE_PARAMETER_1));
        }
    }
}
