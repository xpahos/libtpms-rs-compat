use crate::ffi_types::TpmResult;
use crate::library::CommandInput;
use crate::library::constants::{TPM_FAIL, TPM_RC_FAILURE};

use super::command::{self, Response};
use super::runtime::Tpm2Runtime;

pub(in crate::library) fn process(
    runtime: &mut Tpm2Runtime,
    locality: u8,
    command: &CommandInput,
) -> Result<Vec<u8>, TpmResult> {
    if !runtime.power_on {
        return Ok(Vec::new());
    }

    runtime.locality = if (5..32).contains(&locality) {
        0
    } else {
        locality
    };

    if runtime.failure_mode {
        return serialize(Response::error(TPM_RC_FAILURE));
    }

    let response = match command::parse_command(command) {
        Ok(parsed) => command::dispatch(runtime, &parsed),
        Err(error) => Response::error(error.response_code()),
    };
    serialize(response)
}

fn serialize(response: Response) -> Result<Vec<u8>, TpmResult> {
    command::serialize_response(&response).map_err(|_| TPM_FAIL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::constants::TPM_SUCCESS;
    use crate::library::library_state::{Library, ProcessPreparation, Tpm2ProcessContext};
    use crate::library::tpm2::runtime::empty_state_runtime;

    const UNSUPPORTED_RESPONSE: [u8; 10] =
        [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x43];
    const INSUFFICIENT_RESPONSE: [u8; 10] =
        [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x9a];
    const COMMAND_SIZE_RESPONSE: [u8; 10] =
        [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x42];

    fn input(buffer: &[u8]) -> CommandInput {
        let received_size = buffer.len() as u32;
        let prefix_len = CommandInput::required_prefix_len(received_size);
        CommandInput::new(received_size, buffer[..prefix_len].to_vec())
    }

    fn startup_command() -> CommandInput {
        input(&[
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
        ])
    }

    fn assert_runtime_is_pristine(runtime: &Tpm2Runtime) {
        assert!(!runtime.manufactured);
        assert!(!runtime.was_manufactured);
        assert!(!runtime.startup_received);
        assert!(!runtime.failure_mode);
        assert!(runtime.power_on && runtime.nv_available);
    }

    #[test]
    fn unsupported_command_is_a_valid_tpm_error_response() {
        let mut runtime = empty_state_runtime();
        let response = process(&mut runtime, 0, &startup_command()).expect(
            "a TPM error is encoded in the response, not in the outer TPMLIB_Process result",
        );
        assert_eq!(response, UNSUPPORTED_RESPONSE);
        assert_runtime_is_pristine(&runtime);
    }

    #[test]
    fn malformed_command_is_a_valid_tpm_error_response() {
        let mut runtime = empty_state_runtime();
        assert_eq!(
            process(&mut runtime, 0, &input(&[0x80, 0x01, 0x00])).unwrap(),
            INSUFFICIENT_RESPONSE
        );
        assert_eq!(
            process(
                &mut runtime,
                0,
                &input(&[0x12, 0x34, 0, 0, 0, 10, 0, 0, 1, 0x44])
            )
            .unwrap(),
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x1e],
            "an invalid tag answers TPM_RC_BAD_TAG"
        );
        assert_runtime_is_pristine(&runtime);
    }

    #[test]
    fn runtime_stays_usable_and_deterministic_across_bad_commands() {
        let mut runtime = empty_state_runtime();
        for round in 0..3 {
            assert_eq!(
                process(&mut runtime, 0, &input(&[])).unwrap(),
                INSUFFICIENT_RESPONSE,
                "round {round}: empty command"
            );
            assert_eq!(
                process(&mut runtime, 0, &startup_command()).unwrap(),
                UNSUPPORTED_RESPONSE,
                "round {round}: unsupported command"
            );
            assert_runtime_is_pristine(&runtime);
        }
    }

    #[test]
    fn powered_off_runtime_answers_an_empty_response() {
        let mut runtime = empty_state_runtime();
        runtime.power_on = false;
        assert_eq!(process(&mut runtime, 0, &startup_command()).unwrap(), []);
        assert_eq!(process(&mut runtime, 0, &input(&[])).unwrap(), []);
    }

    #[test]
    fn failure_mode_answers_the_bare_failure_response() {
        let mut runtime = empty_state_runtime();
        runtime.failure_mode = true;
        assert_eq!(
            process(&mut runtime, 0, &startup_command()).unwrap(),
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x01]
        );
        assert_eq!(
            process(&mut runtime, 0, &input(&[])).unwrap(),
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x01],
            "failure mode wins over header validation, like C"
        );
    }

    #[test]
    fn oversized_received_size_is_a_command_size_error_response() {
        let mut runtime = empty_state_runtime();
        for received_size in [4097u32, i32::MAX as u32 + 1, u32::MAX] {
            let mut prefix = vec![0x80, 0x01];
            prefix.extend_from_slice(&received_size.to_be_bytes());
            let oversized = CommandInput::new(received_size, prefix);
            assert_eq!(
                process(&mut runtime, 0, &oversized).unwrap(),
                COMMAND_SIZE_RESPONSE,
                "received size {received_size}"
            );
        }
        assert_runtime_is_pristine(&runtime);
    }

    #[test]
    fn locality_is_recorded_in_locality_value_form() {
        let mut runtime = empty_state_runtime();
        for (given, recorded) in [(0, 0), (4, 4), (5, 0), (31, 0), (32, 32), (255, 255)] {
            process(&mut runtime, given, &startup_command()).unwrap();
            assert_eq!(
                runtime.locality, recorded,
                "locality {given} records as {recorded}, like _plat__LocalitySet"
            );
        }
    }

    #[test]
    fn locality_reaches_the_runtime_even_in_failure_mode_but_not_powered_off() {
        let mut runtime = empty_state_runtime();
        runtime.failure_mode = true;
        process(&mut runtime, 2, &startup_command()).unwrap();
        assert_eq!(
            runtime.locality, 2,
            "C sets the locality before ExecuteCommand checks failure mode"
        );

        runtime.power_on = false;
        process(&mut runtime, 4, &startup_command()).unwrap();
        assert_eq!(
            runtime.locality, 2,
            "a powered-off TPM rejects the command before the locality is set"
        );
    }

    #[track_caller]
    fn prepared_tpm2(library: &Library) -> Tpm2ProcessContext<'_> {
        match library.prepare_process() {
            ProcessPreparation::Tpm2(context) => context,
            ProcessPreparation::Disabled => panic!("TPM 2 must be selected"),
        }
    }

    #[test]
    fn execute_before_main_init_returns_an_empty_success() {
        let library = Library::new();
        assert_eq!(library.choose_tpm_version(1), TPM_SUCCESS);
        let response = prepared_tpm2(&library)
            .execute(&startup_command())
            .expect("C answers TPM_SUCCESS with an empty response before MainInit");
        assert!(response.is_empty());
    }

    #[test]
    fn preparation_without_tpm2_selection_is_disabled() {
        let library = Library::new();
        assert!(
            matches!(library.prepare_process(), ProcessPreparation::Disabled),
            "the default TPM 1.2 selection routes to the disabled interface"
        );
    }

    #[test]
    fn dropped_preparation_executes_nothing_and_releases_the_library() {
        use crate::ffi_types::TpmModifierIndicator;
        use crate::library::state_blob::StateBlobKind;

        unsafe extern "C" fn getlocality_four(
            locality: *mut TpmModifierIndicator,
            _tpm_number: u32,
        ) -> TpmResult {
            // SAFETY: the library supplies a live locality out-pointer.
            unsafe { *locality = 4 };
            TPM_SUCCESS
        }

        let library = Library::new();
        library.register_callbacks(crate::ffi_types::LibtpmsCallbacks {
            tpm_io_getlocality: Some(getlocality_four),
            ..crate::ffi_types::LibtpmsCallbacks::empty()
        });
        assert_eq!(library.choose_tpm_version(1), TPM_SUCCESS);
        library.stage_empty_state(StateBlobKind::Permanent);
        assert_eq!(library.main_init(), TPM_SUCCESS);
        {
            let _dropped_without_execute = prepared_tpm2(&library);
        }
        assert_eq!(
            library.tpm2_runtime_locality(),
            Some(0),
            "the dropped context never touched the runtime"
        );
        let response = prepared_tpm2(&library).execute(&startup_command()).unwrap();
        assert_eq!(response, UNSUPPORTED_RESPONSE);
        assert_eq!(library.tpm2_runtime_locality(), Some(4));
        library.terminate();
    }

    mod locality {
        use super::*;
        use crate::ffi_types::{LibtpmsCallbacks, TpmModifierIndicator};
        use crate::library::state_blob::StateBlobKind;
        use std::sync::Mutex;

        static EVENTS: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());

        unsafe extern "C" fn getlocality_three(
            locality: *mut TpmModifierIndicator,
            tpm_number: u32,
        ) -> TpmResult {
            assert_eq!(tpm_number, 0, "C passes TPM number 0");
            EVENTS.lock().unwrap().push("locality");
            // SAFETY: the library supplies a live locality out-pointer.
            unsafe { *locality = 3 };
            0x0bad_c0de
        }

        fn locality_library() -> Library {
            let library = Library::new();
            library.register_callbacks(LibtpmsCallbacks {
                tpm_io_getlocality: Some(getlocality_three),
                ..LibtpmsCallbacks::empty()
            });
            library
        }

        #[test]
        fn callback_is_queried_once_per_preparation_and_reaches_the_runtime() {
            EVENTS.lock().unwrap().clear();
            let library = locality_library();
            assert_eq!(library.choose_tpm_version(1), TPM_SUCCESS);

            let context = prepared_tpm2(&library);
            assert_eq!(*EVENTS.lock().unwrap(), ["locality"]);
            let response = context.execute(&startup_command()).unwrap();
            assert!(response.is_empty());
            assert_eq!(*EVENTS.lock().unwrap(), ["locality"]);

            library.stage_empty_state(StateBlobKind::Permanent);
            assert_eq!(library.main_init(), TPM_SUCCESS);
            assert_eq!(
                library.tpm2_runtime_locality(),
                Some(0),
                "MainInit itself never queries the locality callback"
            );

            EVENTS.lock().unwrap().clear();
            let context = prepared_tpm2(&library);
            assert_eq!(
                *EVENTS.lock().unwrap(),
                ["locality"],
                "exactly one callback query per preparation"
            );
            let response = context
                .execute(&startup_command())
                .expect("the callback's weird return code is not the outer result");
            assert_eq!(response, UNSUPPORTED_RESPONSE);
            assert_eq!(*EVENTS.lock().unwrap(), ["locality"]);
            assert_eq!(library.tpm2_runtime_locality(), Some(3));
            library.terminate();
        }

        #[test]
        fn locality_defaults_to_zero_without_a_callback() {
            let library = Library::new();
            assert_eq!(library.choose_tpm_version(1), TPM_SUCCESS);
            library.stage_empty_state(StateBlobKind::Permanent);
            assert_eq!(library.main_init(), TPM_SUCCESS);
            prepared_tpm2(&library).execute(&startup_command()).unwrap();
            assert_eq!(library.tpm2_runtime_locality(), Some(0));
            library.terminate();
        }

        static DISABLED_CALLS: Mutex<u32> = Mutex::new(0);

        unsafe extern "C" fn getlocality_counting(
            _locality: *mut TpmModifierIndicator,
            _tpm_number: u32,
        ) -> TpmResult {
            *DISABLED_CALLS.lock().unwrap() += 1;
            TPM_SUCCESS
        }

        #[test]
        fn disabled_interface_never_queries_the_locality_callback() {
            let library = Library::new();
            library.register_callbacks(LibtpmsCallbacks {
                tpm_io_getlocality: Some(getlocality_counting),
                ..LibtpmsCallbacks::empty()
            });
            assert!(matches!(
                library.prepare_process(),
                ProcessPreparation::Disabled
            ));
            assert_eq!(*DISABLED_CALLS.lock().unwrap(), 0);
        }
    }

    #[test]
    fn each_prepared_context_dispatches_exactly_one_command() {
        use crate::library::state_blob::StateBlobKind;

        let library = Library::new();
        assert_eq!(library.choose_tpm_version(1), TPM_SUCCESS);
        library.stage_empty_state(StateBlobKind::Permanent);
        assert_eq!(library.main_init(), TPM_SUCCESS);
        for round in 0..3 {
            let response = prepared_tpm2(&library)
                .execute(&startup_command())
                .expect("an unsupported command is still an outer success");
            assert_eq!(response, UNSUPPORTED_RESPONSE, "round {round}");
            let malformed = prepared_tpm2(&library).execute(&input(&[0xff])).unwrap();
            assert_eq!(
                malformed, INSUFFICIENT_RESPONSE,
                "round {round}: malformed input"
            );
        }
        assert!(
            !library.was_manufactured(),
            "processing mutated no lifecycle state"
        );
        library.terminate();
    }
}
