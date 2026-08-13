use crate::ffi_types::TpmResult;
use crate::library::constants::{TPM_RC_INSUFFICIENT, TPM_RC_SIZE, TPM_RC_VALUE};

use super::super::runtime::Tpm2Runtime;
use super::dispatcher::CommandFrame;

const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;
const RC_SELF_TEST_FULL_TEST: TpmResult = TPM_RC_P + TPM_RC_1;

const NO: u8 = 0x00;
const YES: u8 = 0x01;

pub(super) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<Vec<u8>, TpmResult> {
    let full_test = parse_full_test(frame.parameters)?;
    match runtime.self_test.run(full_test) {
        Ok(()) => Ok(Vec::new()),
        Err(code) => {
            runtime.failure_mode = true;
            Err(code)
        }
    }
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
    use super::super::dispatcher::dispatch;
    use super::super::header::{parse_command, serialize_response};
    use super::super::registry::TPM_CC_SELF_TEST;
    use super::*;
    use crate::library::CommandInput;
    use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_INITIALIZE};
    use crate::library::tpm2::runtime::{Tpm2Runtime, empty_state_runtime};
    use crate::library::tpm2::self_test::{PrimitiveTest, always_fails, fails_on_sha384};

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

    #[test]
    fn self_test_before_startup_is_rejected() {
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
    fn a_full_test_answers_the_upstream_success_bytes() {
        let mut runtime = started_runtime();
        assert_eq!(run(&mut runtime, &FULL_TEST_COMMAND), SUCCESS_RESPONSE);
        assert!(runtime.self_test.pending.is_empty());
        assert!(!runtime.failure_mode);
    }

    #[test]
    fn a_partial_test_answers_the_upstream_success_bytes() {
        let mut runtime = started_runtime();
        assert_eq!(run(&mut runtime, &PARTIAL_TEST_COMMAND), SUCCESS_RESPONSE);
        assert!(runtime.self_test.pending.is_empty());
        assert!(!runtime.failure_mode);
    }

    #[test]
    fn a_partial_test_after_a_full_test_reruns_nothing() {
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
    fn a_full_test_after_a_partial_test_reruns_everything() {
        let mut runtime = started_runtime();
        assert_eq!(run(&mut runtime, &PARTIAL_TEST_COMMAND), SUCCESS_RESPONSE);
        runtime.self_test.set_runner(always_fails);
        assert_eq!(run_code(&mut runtime, &FULL_TEST_COMMAND), TPM_RC_FAILURE);
        for test in PrimitiveTest::ALL {
            assert!(runtime.self_test.pending.contains(test), "{test:?}");
        }
    }

    #[test]
    fn a_missing_full_test_byte_is_an_insufficient_parameter_one() {
        let mut runtime = started_runtime();
        assert_eq!(
            run_code(&mut runtime, &framed(0x8001, &[])),
            INSUFFICIENT_PARAMETER_1
        );
    }

    #[test]
    fn an_invalid_yes_no_value_is_a_parameter_one_value_error() {
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
    fn trailing_parameter_bytes_are_a_size_error() {
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
    fn an_invalid_value_is_reported_before_the_trailing_bytes() {
        let mut runtime = started_runtime();
        assert_eq!(
            run_code(&mut runtime, &framed(0x8001, &[0x02, 0xee])),
            VALUE_PARAMETER_1
        );
    }

    #[test]
    fn a_rejected_request_leaves_every_test_pending() {
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
    fn rejected_parameters_leave_a_recorded_failure_untouched() {
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
    fn a_failing_primitive_test_enters_failure_mode() {
        let mut runtime = started_runtime();
        runtime.self_test.set_runner(fails_on_sha384);
        assert_eq!(run_code(&mut runtime, &FULL_TEST_COMMAND), TPM_RC_FAILURE);
        assert!(runtime.failure_mode);
    }

    #[test]
    fn a_failure_answers_the_failure_mode_response_bytes() {
        let mut runtime = started_runtime();
        runtime.self_test.set_runner(always_fails);
        assert_eq!(
            run(&mut runtime, &FULL_TEST_COMMAND),
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x01]
        );
    }

    #[test]
    fn a_failure_keeps_the_progress_a_later_get_test_result_needs() {
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
    fn a_failure_does_not_touch_unrelated_runtime_state() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        runtime.self_test.set_runner(always_fails);
        assert_eq!(run_code(&mut runtime, &FULL_TEST_COMMAND), TPM_RC_FAILURE);
        assert_eq!(snapshot(&runtime), before);
    }

    #[test]
    fn a_successful_test_does_not_touch_unrelated_runtime_state() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        assert_eq!(run(&mut runtime, &FULL_TEST_COMMAND), SUCCESS_RESPONSE);
        assert_eq!(run(&mut runtime, &PARTIAL_TEST_COMMAND), SUCCESS_RESPONSE);
        assert_eq!(snapshot(&runtime), before);
    }

    #[test]
    fn a_password_session_is_not_associated_with_a_nonexistent_handle() {
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
    fn a_session_tagged_request_without_an_authorization_size_is_insufficient() {
        let mut runtime = started_runtime();
        assert_eq!(run_code(&mut runtime, &framed(0x8002, &[])), INSUFFICIENT);
    }

    #[test]
    fn a_session_tagged_request_with_a_short_authorization_area_is_a_size_error() {
        let mut runtime = started_runtime();
        let mut payload = 0u32.to_be_bytes().to_vec();
        payload.push(0x00);
        assert_eq!(run_code(&mut runtime, &framed(0x8002, &payload)), SIZE);
    }

    #[test]
    fn parsing_accepts_only_the_two_defined_yes_no_values() {
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
    fn malformed_command_bodies_never_panic() {
        for length in 0..=4usize {
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
}
