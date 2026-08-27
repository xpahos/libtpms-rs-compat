use crate::ffi::types::TpmResult;
use crate::library::constants::{TPM_RC_INSUFFICIENT, TPM_RC_NO_RESULT, TPM_RC_SIZE};
use crate::library::tpm2::command::core::dispatcher::CommandFrame;
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::marshal::{BlobReader, Tpm2bError};
use crate::library::tpm2::random::stir_random;
use crate::library::tpm2::runtime::Tpm2Runtime;

const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;
const RC_STIR_RANDOM_IN_DATA: TpmResult = TPM_RC_P + TPM_RC_1;

const MAX_SYM_DATA: usize = 128;

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let in_data = parse_in_data(frame.parameters)?;
    match stir_random(runtime, in_data) {
        // Upstream CryptRandomStir() answers TPM_RC_NO_RESULT when the
        // entropy generator fails and TPM2_StirRandom() discards it.
        Ok(()) | Err(TPM_RC_NO_RESULT) => Ok(CommandOutput::empty()),
        Err(code) => Err(code),
    }
}

fn parse_in_data(parameters: &[u8]) -> Result<&[u8], TpmResult> {
    let mut reader = BlobReader::new(parameters);
    let in_data = reader
        .read_tpm2b(MAX_SYM_DATA)
        .map_err(|error| match error {
            Tpm2bError::Truncated => TPM_RC_INSUFFICIENT + RC_STIR_RANDOM_IN_DATA,
            Tpm2bError::SizeExceeded { .. } => TPM_RC_SIZE + RC_STIR_RANDOM_IN_DATA,
        })?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(in_data)
}

#[cfg(test)]
mod tests {
    fn process(
        runtime: &mut crate::library::tpm2::runtime::Tpm2Runtime,
        locality: u8,
        command: &crate::library::CommandInput,
        commit_nv: impl FnOnce(
            &crate::library::tpm2::runtime::Tpm2Runtime,
        ) -> Result<(), crate::ffi::types::TpmResult>,
    ) -> Result<Vec<u8>, crate::ffi::types::TpmResult> {
        crate::library::tpm2::process(
            runtime,
            crate::library::tpm2::PlatformInputs::at_locality(locality),
            command,
            &crate::library::tpm2::clock::RecordingClock::new(1_600_000_000_000, 5_000_000),
            commit_nv,
        )
    }
    use super::*;
    use crate::library::CommandInput;
    use crate::library::constants::{TPM_FAIL, TPM_RC_FAILURE, TPM_RC_INITIALIZE};
    use crate::library::tpm2::command::core::dispatcher::dispatch;
    use crate::library::tpm2::command::core::header::{parse_command, serialize_response};
    use crate::library::tpm2::command::core::registry::{TPM_CC_GET_RANDOM, TPM_CC_STIR_RANDOM};
    use crate::library::tpm2::crypto::{DRBG_MAGIC, DRBG_SEED_SIZE, DrbgStirCase, stir_record};
    use crate::library::tpm2::manufacture::manufacture_state;
    use crate::library::tpm2::persistent::{OwnedDrbgState, OwnedSecret};
    use crate::library::tpm2::profile::validate_user_profile;
    use crate::library::tpm2::runtime::commit_manufactured_state;
    use std::cell::RefCell;

    const RC_INSUFFICIENT_IN_DATA: u32 = 0x1da;
    const RC_SIZE_IN_DATA: u32 = 0x1d5;
    const RC_SIZE: u32 = 0x095;
    const RC_INSUFFICIENT: u32 = 0x09a;
    const RC_SESSION1_HANDLE: u32 = 0x98b;

    const CONTINUOUS_TEST_PROFILE: &[u8] =
        br#"{"Name":"custom","Attributes":"drbg-continous-test"}"#;

    fn hex(s: &str) -> Vec<u8> {
        let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(cleaned.len().is_multiple_of(2));
        (0..cleaned.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).unwrap())
            .collect()
    }

    fn deterministic_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
        let len = buffer.len() as u8;
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_add(len) ^ 0x63;
        }
        Ok(())
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

    fn manufactured_runtime(continuous_test: bool) -> Box<Tpm2Runtime> {
        let profile = if continuous_test {
            validate_user_profile(Some(CONTINUOUS_TEST_PROFILE)).expect("the profile validates")
        } else {
            validate_user_profile(None).expect("the null profile validates")
        };
        let state = manufacture_state(profile, deterministic_entropy).expect("manufactures");
        let mut runtime = commit_manufactured_state(state).expect("commits");
        runtime.entropy = deterministic_entropy;
        runtime
    }

    #[track_caller]
    fn dispatch_bytes(runtime: &mut Tpm2Runtime, bytes: &[u8]) -> Vec<u8> {
        let input = CommandInput::new(bytes.len() as u32, bytes.to_vec());
        let parsed = parse_command(&input).expect("the header parses");
        serialize_response(&dispatch(runtime, &parsed)).expect("the response serializes")
    }

    #[track_caller]
    fn started_runtime(continuous_test: bool) -> Box<Tpm2Runtime> {
        let mut runtime = manufactured_runtime(continuous_test);
        let startup = hex("80010000000c0000014400 00");
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup),
            hex("80010000000a00000000")
        );
        runtime.nv_update_pending = false;
        runtime
    }

    fn command_with(parameters: &[u8]) -> Vec<u8> {
        let mut out = vec![0x80, 0x01];
        out.extend_from_slice(&(10 + parameters.len() as u32).to_be_bytes());
        out.extend_from_slice(&TPM_CC_STIR_RANDOM.to_be_bytes());
        out.extend_from_slice(parameters);
        out
    }

    fn stir_command(in_data: &[u8]) -> Vec<u8> {
        let mut parameters = (in_data.len() as u16).to_be_bytes().to_vec();
        parameters.extend_from_slice(in_data);
        command_with(&parameters)
    }

    fn get_random_command(bytes_requested: u16) -> Vec<u8> {
        let mut out = hex("8001000000 0c");
        out.extend_from_slice(&TPM_CC_GET_RANDOM.to_be_bytes());
        out.extend_from_slice(&bytes_requested.to_be_bytes());
        out
    }

    fn error_response(code: u32) -> Vec<u8> {
        let mut out = hex("80010000000a");
        out.extend_from_slice(&code.to_be_bytes());
        out
    }

    fn success_response() -> Vec<u8> {
        hex("80010000000a00000000")
    }

    #[track_caller]
    fn random_bytes_of(response: &[u8]) -> Vec<u8> {
        assert_eq!(&response[6..10], &[0, 0, 0, 0], "TPM_RC_SUCCESS");
        response[12..].to_vec()
    }

    fn install(runtime: &mut Tpm2Runtime, case: &DrbgStirCase) {
        runtime.live.orderly.drbg_state = OwnedDrbgState {
            reseed_counter: case.initial_reseed_counter,
            drbg_magic: DRBG_MAGIC,
            seed: OwnedSecret::copy_of(&case.initial_seed),
            last_value: case.initial_last_value,
        };
    }

    struct Snapshot {
        startup_received: bool,
        nv_update_pending: bool,
        persistent_drbg_seed: Vec<u8>,
        persistent_drbg_counter: u64,
        persistent_drbg_last_value: [u32; 4],
        orderly_state: u16,
        nv_memory: Box<[u8]>,
    }

    fn snapshot(runtime: &Tpm2Runtime) -> Snapshot {
        let state = runtime.state.as_ref().expect("state present");
        Snapshot {
            startup_received: runtime.startup_received,
            nv_update_pending: runtime.nv_update_pending,
            persistent_drbg_seed: state.orderly.drbg_state.seed.expose().to_vec(),
            persistent_drbg_counter: state.orderly.drbg_state.reseed_counter,
            persistent_drbg_last_value: state.orderly.drbg_state.last_value,
            orderly_state: state.persistent.orderly_state,
            nv_memory: runtime.nv_memory.clone(),
        }
    }

    #[track_caller]
    fn assert_persistent_unchanged(runtime: &Tpm2Runtime, before: &Snapshot) {
        let state = runtime.state.as_ref().expect("state present");
        assert_eq!(runtime.startup_received, before.startup_received);
        assert_eq!(runtime.nv_update_pending, before.nv_update_pending);
        assert_eq!(
            state.orderly.drbg_state.seed.expose(),
            &before.persistent_drbg_seed[..]
        );
        assert_eq!(
            state.orderly.drbg_state.reseed_counter,
            before.persistent_drbg_counter
        );
        assert_eq!(
            state.orderly.drbg_state.last_value,
            before.persistent_drbg_last_value
        );
        assert_eq!(state.persistent.orderly_state, before.orderly_state);
        assert_eq!(runtime.nv_memory, before.nv_memory);
    }

    #[track_caller]
    fn assert_live_drbg_unchanged(runtime: &Tpm2Runtime, before: &OwnedDrbgState) {
        let now = &runtime.live.orderly.drbg_state;
        assert_eq!(now.seed.expose(), before.seed.expose());
        assert_eq!(now.reseed_counter, before.reseed_counter);
        assert_eq!(now.drbg_magic, before.drbg_magic);
        assert_eq!(now.last_value, before.last_value);
    }

    #[test]
    fn stir_random_is_rejected_before_startup() {
        let mut runtime = manufactured_runtime(false);
        runtime.entropy = failing_entropy;
        let before = snapshot(&runtime);
        let live_before = runtime.live.orderly.drbg_state.clone();
        for parameters in [&[][..], &[0x00, 0x10][..], &[0xff, 0xff, 0x00][..]] {
            assert_eq!(
                dispatch_bytes(&mut runtime, &command_with(parameters)),
                error_response(TPM_RC_INITIALIZE),
                "the lifecycle check precedes parameter parsing, {parameters:02x?}"
            );
        }
        assert_live_drbg_unchanged(&runtime, &live_before);
        assert_persistent_unchanged(&runtime, &before);
        assert!(
            !runtime.failure_mode,
            "the lifecycle check is not a fatal error"
        );
    }

    #[test]
    fn every_input_size_up_to_the_maximum_is_accepted() {
        let mut runtime = started_runtime(false);
        for length in 0..=MAX_SYM_DATA {
            let in_data: Vec<u8> = (0..length).map(|index| index as u8).collect();
            assert_eq!(
                dispatch_bytes(&mut runtime, &stir_command(&in_data)),
                success_response(),
                "length {length}"
            );
            assert!(!runtime.failure_mode, "length {length}");
        }
    }

    #[test]
    fn an_input_above_the_maximum_returns_the_indexed_size_error() {
        for length in [129usize, 130, 255, 1024] {
            let mut runtime = started_runtime(false);
            let before = snapshot(&runtime);
            let live_before = runtime.live.orderly.drbg_state.clone();
            let in_data = vec![0xa5u8; length];
            assert_eq!(
                dispatch_bytes(&mut runtime, &stir_command(&in_data)),
                error_response(RC_SIZE_IN_DATA),
                "length {length}"
            );
            assert_live_drbg_unchanged(&runtime, &live_before);
            assert_persistent_unchanged(&runtime, &before);
            assert!(!runtime.failure_mode);
        }
    }

    #[test]
    fn the_size_check_precedes_the_payload_length_check() {
        let mut runtime = started_runtime(false);
        assert_eq!(
            dispatch_bytes(&mut runtime, &command_with(&hex("ffff"))),
            error_response(RC_SIZE_IN_DATA),
            "an oversized declared size is reported before the missing payload"
        );
    }

    #[test]
    fn a_truncated_in_data_returns_its_indexed_error() {
        let mut truncated: Vec<Vec<u8>> = vec![vec![], vec![0x00], vec![0x00, 0x10]];
        for present in [1usize, 15, 127] {
            let mut parameters = 128u16.to_be_bytes().to_vec();
            parameters.extend_from_slice(&vec![0x5a; present]);
            truncated.push(parameters);
        }
        for parameters in truncated {
            let mut runtime = started_runtime(false);
            let before = snapshot(&runtime);
            let live_before = runtime.live.orderly.drbg_state.clone();
            assert_eq!(
                dispatch_bytes(&mut runtime, &command_with(&parameters)),
                error_response(RC_INSUFFICIENT_IN_DATA),
                "parameters {parameters:02x?}"
            );
            assert_live_drbg_unchanged(&runtime, &live_before);
            assert_persistent_unchanged(&runtime, &before);
            assert!(!runtime.failure_mode);
        }
    }

    #[test]
    fn trailing_parameter_bytes_return_size() {
        for parameters in [hex("0000 00"), hex("0001 11 22"), hex("0002 1122 00000000")] {
            let mut runtime = started_runtime(false);
            let before = snapshot(&runtime);
            let live_before = runtime.live.orderly.drbg_state.clone();
            assert_eq!(
                dispatch_bytes(&mut runtime, &command_with(&parameters)),
                error_response(RC_SIZE),
                "parameters {parameters:02x?}"
            );
            assert_live_drbg_unchanged(&runtime, &live_before);
            assert_persistent_unchanged(&runtime, &before);
            assert!(!runtime.failure_mode);
        }
    }

    #[test]
    fn the_resulting_state_and_the_next_random_bytes_match_the_oracle() {
        for continuous_test in [false, true] {
            let record = stir_record(continuous_test);
            for (index, case) in record.cases.iter().enumerate() {
                let mut runtime = started_runtime(continuous_test);
                runtime.entropy = recording_entropy;
                install(&mut runtime, case);
                take_entropy_requests();

                assert_eq!(
                    dispatch_bytes(&mut runtime, &stir_command(case.additional())),
                    success_response(),
                    "continuous {continuous_test}, case {index}"
                );
                assert_eq!(
                    take_entropy_requests(),
                    [DRBG_SEED_SIZE],
                    "one full seed block, case {index}"
                );

                let live = &runtime.live.orderly.drbg_state;
                assert_eq!(live.seed.expose(), case.seed_after, "case {index}");
                assert_eq!(live.reseed_counter, 1, "case {index}");
                assert_eq!(live.last_value, case.last_value_after, "case {index}");

                let response = dispatch_bytes(&mut runtime, &get_random_command(64));
                assert_eq!(
                    random_bytes_of(&response),
                    case.next_output,
                    "continuous {continuous_test}, case {index}"
                );
                assert_eq!(
                    runtime.live.orderly.drbg_state.reseed_counter, 2,
                    "case {index}"
                );
                assert_eq!(take_entropy_requests(), [] as [usize; 0], "case {index}");
            }
        }
    }

    #[test]
    fn a_successful_stir_leaves_the_persistent_state_and_nv_alone() {
        let record = stir_record(false);
        for case in &record.cases {
            let mut runtime = started_runtime(false);
            install(&mut runtime, case);
            let before = snapshot(&runtime);
            let command = stir_command(case.additional());
            let input = CommandInput::new(command.len() as u32, command);
            let response = process(&mut runtime, 0, &input, |_| {
                panic!("StirRandom must not schedule an NV commit")
            })
            .expect("the command processes");
            assert_eq!(response, success_response());
            assert_persistent_unchanged(&runtime, &before);
            assert!(!runtime.failure_mode);
        }
    }

    #[test]
    fn an_entropy_failure_answers_success_and_changes_nothing() {
        let record = stir_record(false);
        for (index, case) in record.cases.iter().enumerate() {
            let mut runtime = started_runtime(false);
            runtime.entropy = failing_entropy;
            install(&mut runtime, case);
            let before = snapshot(&runtime);
            let live_before = runtime.live.orderly.drbg_state.clone();

            let command = stir_command(case.additional());
            let input = CommandInput::new(command.len() as u32, command);
            let response = process(&mut runtime, 0, &input, |_| {
                panic!("a failed stir must not schedule an NV commit")
            })
            .expect("the command processes");

            assert_eq!(
                response,
                success_response(),
                "upstream TPM2_StirRandom discards TPM_RC_NO_RESULT, case {index}"
            );
            assert!(!runtime.failure_mode, "case {index}");
            assert_live_drbg_unchanged(&runtime, &live_before);
            assert_persistent_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn a_drbg_failure_answers_a_bare_error_response_and_stops_the_tpm() {
        for in_data in [&[][..], &[0x11][..], &[0x22; 128][..]] {
            let mut runtime = started_runtime(false);
            runtime.live.orderly.drbg_state.seed = OwnedSecret::copy_of(&[0x11; 47]);
            let before = snapshot(&runtime);
            let live_before = runtime.live.orderly.drbg_state.clone();
            assert_eq!(
                dispatch_bytes(&mut runtime, &stir_command(in_data)),
                error_response(TPM_RC_FAILURE),
                "an error response carries no parameters and no sessions"
            );
            assert!(runtime.failure_mode, "a fatal DRBG error stops the TPM");
            assert_live_drbg_unchanged(&runtime, &live_before);
            assert_persistent_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn a_foreign_drbg_magic_stops_the_tpm() {
        let mut runtime = started_runtime(false);
        runtime.live.orderly.drbg_state.drbg_magic = DRBG_MAGIC ^ 1;
        let before = snapshot(&runtime);
        let live_before = runtime.live.orderly.drbg_state.clone();
        assert_eq!(
            dispatch_bytes(&mut runtime, &stir_command(&[0x33; 16])),
            error_response(TPM_RC_FAILURE)
        );
        assert!(runtime.failure_mode);
        assert_live_drbg_unchanged(&runtime, &live_before);
        assert_persistent_unchanged(&runtime, &before);
    }

    #[test]
    fn the_next_command_after_a_drbg_failure_takes_the_failure_mode_path() {
        let mut runtime = started_runtime(false);
        runtime.live.orderly.drbg_state.seed = OwnedSecret::copy_of(&[0x11; 47]);
        let command = stir_command(&[0x44; 8]);
        let input = CommandInput::new(command.len() as u32, command);
        let response = process(&mut runtime, 0, &input, |_| {
            panic!("a failed StirRandom must not schedule an NV commit")
        })
        .expect("the command processes");
        assert_eq!(response, error_response(TPM_RC_FAILURE));
        assert!(runtime.failure_mode);

        let follow_up = stir_command(&[0x44; 8]);
        let input = CommandInput::new(follow_up.len() as u32, follow_up);
        let response = process(&mut runtime, 0, &input, |_| {
            panic!("failure mode must not schedule an NV commit")
        })
        .expect("the command processes");
        assert_eq!(response, error_response(TPM_RC_FAILURE));
    }

    #[test]
    fn session_tagged_requests_match_the_oracle() {
        let pw_auth = hex("8002000000190000014600000009 40000009 0000 00 0000 0000");
        let no_authsize = hex("8002000000 0c 00000146 0000");
        let authsize_zero = hex("8002000000 10 00000146 00000000 0000");

        for (label, command, expected) in [
            ("pw_auth", pw_auth, RC_SESSION1_HANDLE),
            ("no_authsize", no_authsize, RC_INSUFFICIENT),
            ("authsize_zero", authsize_zero, RC_SIZE),
        ] {
            let mut runtime = started_runtime(false);
            let before = snapshot(&runtime);
            let live_before = runtime.live.orderly.drbg_state.clone();
            assert_eq!(
                dispatch_bytes(&mut runtime, &command),
                error_response(expected),
                "{label}"
            );
            assert_live_drbg_unchanged(&runtime, &live_before);
            assert_persistent_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn a_successful_stir_answers_without_parameters_or_an_authorization_area() {
        let mut runtime = started_runtime(false);
        let response = dispatch_bytes(&mut runtime, &stir_command(&[0x55; 32]));
        assert_eq!(response, success_response());
        assert_eq!(response.len(), 10, "no parameters, no sessions");
    }

    #[test]
    fn short_parameters_return_upstream_error() {
        let filler = [0x00u8, 0xff, 0x80, 0x7f, 0x01];
        for length in 0..=6usize {
            for &byte in &filler {
                let mut runtime = started_runtime(false);
                runtime.entropy = failing_entropy;
                let before = snapshot(&runtime);
                let response = dispatch_bytes(&mut runtime, &command_with(&vec![byte; length]));
                assert_eq!(&response[..2], &[0x80, 0x01], "length {length}");
                assert_eq!(
                    u32::from_be_bytes(response[2..6].try_into().unwrap()) as usize,
                    response.len(),
                    "length {length}"
                );
                let code = u32::from_be_bytes(response[6..10].try_into().unwrap());
                let declared = if length >= 2 {
                    usize::from(u16::from_be_bytes([byte, byte]))
                } else {
                    0
                };
                let expected = match length {
                    0 | 1 => RC_INSUFFICIENT_IN_DATA,
                    _ if declared > MAX_SYM_DATA => RC_SIZE_IN_DATA,
                    _ if declared > length - 2 => RC_INSUFFICIENT_IN_DATA,
                    _ if declared < length - 2 => RC_SIZE,
                    _ => 0,
                };
                assert_eq!(code, expected, "length {length}, byte {byte:#04x}");
                assert_eq!(response.len(), 10, "length {length}");
                if code != 0 {
                    assert_persistent_unchanged(&runtime, &before);
                }
                assert!(!runtime.failure_mode, "length {length}");
            }
        }
    }
}
