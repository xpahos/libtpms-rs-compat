use crate::library::CommandInput;
use crate::library::cancel::CancellationToken;
use crate::library::constants::{TPM_FAIL, TPM_RC_FAILURE};
use crate::types::TpmResult;

use super::clock::{HostClock, time_update};
use super::command::{self, Response};
use super::failure_mode::{self, FailureLocation, enter_failure_mode};
use super::runtime::Tpm2Runtime;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::library) struct PlatformInputs {
    pub(in crate::library) locality: u8,
    pub(in crate::library) physical_presence: bool,
}

impl PlatformInputs {
    #[cfg(test)]
    pub(in crate::library) fn at_locality(locality: u8) -> Self {
        Self {
            locality,
            physical_presence: false,
        }
    }

    #[cfg(test)]
    pub(in crate::library) fn with_physical_presence(
        locality: u8,
        physical_presence: bool,
    ) -> Self {
        Self {
            locality,
            physical_presence,
        }
    }
}

pub(in crate::library) fn process(
    runtime: &mut Tpm2Runtime,
    platform: PlatformInputs,
    command: &CommandInput,
    clock: &dyn HostClock,
    commit_nv: impl FnOnce(&Tpm2Runtime) -> Result<(), TpmResult>,
    cancellation: CancellationToken<'_>,
) -> Result<Vec<u8>, TpmResult> {
    if !runtime.power_on {
        return Ok(Vec::new());
    }

    runtime.locality = if (5..32).contains(&platform.locality) {
        0
    } else {
        platform.locality
    };
    runtime.physical_presence = platform.physical_presence;

    if runtime.failure_mode {
        return failure_mode::process(runtime, command);
    }

    let buffer_size = runtime.buffer_size;

    if runtime.startup_received && runtime.nv_available && time_update(runtime, clock).is_err() {
        enter_failure_mode(runtime, FailureLocation::NvCommit);
        return serialize(Response::error(TPM_RC_FAILURE), buffer_size);
    }

    super::tis::abort_sequence(runtime);

    let was_started = runtime.startup_received;
    let response = match command::parse_command_within(command, buffer_size) {
        Ok(parsed) => command::dispatch(runtime, &parsed, cancellation),
        Err(error) => Response::error(error.response_code()),
    };

    if !was_started && runtime.startup_received && time_update(runtime, clock).is_err() {
        enter_failure_mode(runtime, FailureLocation::NvCommit);
        return serialize(Response::error(TPM_RC_FAILURE), buffer_size);
    }

    if runtime.nv_update_pending {
        runtime.nv_update_pending = false;
        if commit_nv(runtime).is_err() {
            enter_failure_mode(runtime, FailureLocation::NvCommit);
            return serialize(Response::error(TPM_RC_FAILURE), buffer_size);
        }
    }
    serialize(response, buffer_size)
}

fn serialize(response: Response, buffer_size: u32) -> Result<Vec<u8>, TpmResult> {
    command::serialize_response_within(&response, buffer_size).map_err(|_| TPM_FAIL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::constants::TPM_SUCCESS;
    use crate::library::library_state::Tpm;
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

    fn fixed_clock() -> crate::library::tpm2::clock::RecordingClock {
        crate::library::tpm2::clock::RecordingClock::new(1_600_000_000_000, 5_000_000)
    }

    fn process(
        runtime: &mut Tpm2Runtime,
        locality: u8,
        command: &CommandInput,
        commit_nv: impl FnOnce(&Tpm2Runtime) -> Result<(), TpmResult>,
    ) -> Result<Vec<u8>, TpmResult> {
        super::process(
            runtime,
            crate::library::tpm2::PlatformInputs::at_locality(locality),
            command,
            &fixed_clock(),
            commit_nv,
            CancellationToken::disabled(),
        )
    }

    fn run_process(
        runtime: &mut Tpm2Runtime,
        locality: u8,
        command: &CommandInput,
    ) -> Result<Vec<u8>, TpmResult> {
        process(runtime, locality, command, |_| Ok(()))
    }

    fn startup_command() -> CommandInput {
        input(&[
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
        ])
    }

    fn unknown_command() -> CommandInput {
        input(&[0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x20, 0x00, 0x00, 0x00])
    }

    fn assert_runtime_is_pristine(runtime: &Tpm2Runtime) {
        assert!(!runtime.manufactured);
        assert!(!runtime.was_manufactured);
        assert!(!runtime.startup_received);
        assert!(!runtime.failure_mode);
        assert!(runtime.power_on && runtime.nv_available);
    }

    #[test]
    fn unsupported_command_valid_error_response() {
        let mut runtime = empty_state_runtime();
        let response = run_process(&mut runtime, 0, &unknown_command()).expect(
            "a TPM error is encoded in the response, not in the outer TPMLIB_Process result",
        );
        assert_eq!(response, UNSUPPORTED_RESPONSE);
        assert_runtime_is_pristine(&runtime);
    }

    #[test]
    fn startup_undecoded_state_failure_no_mutation() {
        let mut runtime = empty_state_runtime();
        let nv_before = runtime.nv_memory.clone();
        let response = run_process(&mut runtime, 0, &startup_command()).unwrap();
        assert_eq!(
            response,
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x01],
            "a runtime without decoded state cannot perform the transition"
        );
        assert_runtime_is_pristine(&runtime);
        assert_eq!(runtime.nv_memory, nv_before);
    }

    #[test]
    fn malformed_command_valid_error_response() {
        let mut runtime = empty_state_runtime();
        assert_eq!(
            run_process(&mut runtime, 0, &input(&[0x80, 0x01, 0x00])).unwrap(),
            INSUFFICIENT_RESPONSE
        );
        assert_eq!(
            run_process(
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
    fn bad_commands_runtime_determinism() {
        let mut runtime = empty_state_runtime();
        for round in 0..3 {
            assert_eq!(
                run_process(&mut runtime, 0, &input(&[])).unwrap(),
                INSUFFICIENT_RESPONSE,
                "round {round}: empty command"
            );
            assert_eq!(
                run_process(&mut runtime, 0, &unknown_command()).unwrap(),
                UNSUPPORTED_RESPONSE,
                "round {round}: unsupported command"
            );
            assert_runtime_is_pristine(&runtime);
        }
    }

    const INCREMENTAL_SHA256_COMMAND: [u8; 16] = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x01, 0x42, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x0b,
    ];
    const INCREMENTAL_SHA256_RESPONSE: [u8; 26] = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00,
        0x04, 0x00, 0x06, 0x00, 0x0c, 0x00, 0x0d, 0x00, 0x17, 0x00, 0x19,
    ];

    #[test]
    fn checkpoint_free_command_cancellation_immunity() {
        let mut runtime = empty_state_runtime();
        runtime.startup_received = true;

        let response = super::process(
            &mut runtime,
            crate::library::tpm2::PlatformInputs::at_locality(0),
            &input(&INCREMENTAL_SHA256_COMMAND),
            &fixed_clock(),
            |_| Ok(()),
            CancellationToken::requested(),
        )
        .unwrap();
        assert_eq!(response, INCREMENTAL_SHA256_RESPONSE);
        assert!(!runtime.failure_mode);
    }

    #[test]
    fn powered_off_empty_response() {
        let mut runtime = empty_state_runtime();
        runtime.power_on = false;
        assert_eq!(
            run_process(&mut runtime, 0, &startup_command()).unwrap(),
            []
        );
        assert_eq!(run_process(&mut runtime, 0, &input(&[])).unwrap(), []);
    }

    #[test]
    fn failure_mode_bare_failure_response() {
        let mut runtime = empty_state_runtime();
        runtime.failure_mode = true;
        assert_eq!(
            run_process(&mut runtime, 0, &startup_command()).unwrap(),
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x01]
        );
        assert_eq!(
            run_process(&mut runtime, 0, &input(&[])).unwrap(),
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x01],
            "failure mode wins over header validation, like C"
        );
    }

    #[test]
    fn self_test_failure_boundary_routing() {
        use crate::library::tpm2::self_test::{PrimitiveTest, SelfTestFailure, fails_on_sha384};

        const BARE_FAILURE: [u8; 10] = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x01];
        const FULL_SELF_TEST: [u8; 11] = [
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x01, 0x43, 0x01,
        ];

        let mut runtime = empty_state_runtime();
        runtime.startup_received = true;
        runtime.self_test.set_runner(fails_on_sha384);
        let nv_before = runtime.nv_memory.clone();

        assert_eq!(
            run_process(&mut runtime, 0, &input(&FULL_SELF_TEST)).unwrap(),
            BARE_FAILURE
        );
        assert!(runtime.failure_mode);
        let recorded = Some(SelfTestFailure {
            primitive: PrimitiveTest::Sha384,
        });
        assert_eq!(runtime.self_test.failure, recorded);

        assert_eq!(
            run_process(&mut runtime, 0, &unknown_command()).unwrap(),
            BARE_FAILURE,
            "an ordinary command now takes the failure-mode boundary"
        );
        assert_eq!(
            run_process(&mut runtime, 0, &input(&FULL_SELF_TEST)).unwrap(),
            BARE_FAILURE
        );
        assert_eq!(runtime.self_test.failure, recorded);
        assert!(runtime.self_test.pending.contains(PrimitiveTest::Sha384));
        assert!(runtime.self_test.pending.contains(PrimitiveTest::Sha512));
        assert!(!runtime.self_test.pending.contains(PrimitiveTest::Sha1));
        assert_eq!(runtime.nv_memory, nv_before);
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn incremental_self_test_failure_boundary_routing() {
        use crate::library::tpm2::self_test::{PrimitiveTest, SelfTestFailure, always_fails};

        const BARE_FAILURE: [u8; 10] = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x01];
        const INCREMENTAL_SHA256: [u8; 16] = [
            0x80, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x01, 0x42, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x0b,
        ];

        let mut runtime = empty_state_runtime();
        runtime.startup_received = true;
        runtime.self_test.set_runner(always_fails);
        let nv_before = runtime.nv_memory.clone();

        assert_eq!(
            run_process(&mut runtime, 0, &input(&INCREMENTAL_SHA256)).unwrap(),
            BARE_FAILURE
        );
        assert!(runtime.failure_mode);
        let recorded = Some(SelfTestFailure {
            primitive: PrimitiveTest::Sha256,
        });
        assert_eq!(runtime.self_test.failure, recorded);

        assert_eq!(
            run_process(&mut runtime, 0, &unknown_command()).unwrap(),
            BARE_FAILURE,
            "an ordinary command now takes the failure-mode boundary"
        );
        assert_eq!(
            run_process(&mut runtime, 0, &input(&INCREMENTAL_SHA256)).unwrap(),
            BARE_FAILURE
        );
        assert_eq!(runtime.self_test.failure, recorded);
        assert!(runtime.self_test.pending.contains(PrimitiveTest::Sha256));
        assert_eq!(runtime.nv_memory, nv_before);
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn successful_incremental_self_test_dispatch_unchanged() {
        const INCREMENTAL_SHA256: [u8; 16] = [
            0x80, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x01, 0x42, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x0b,
        ];

        let mut runtime = empty_state_runtime();
        runtime.startup_received = true;
        assert_eq!(
            run_process(&mut runtime, 0, &input(&INCREMENTAL_SHA256)).unwrap(),
            [
                0x80, 0x01, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
                0x00, 0x04, 0x00, 0x06, 0x00, 0x0c, 0x00, 0x0d, 0x00, 0x17, 0x00, 0x19
            ]
        );
        assert!(!runtime.failure_mode);
        assert_eq!(
            run_process(&mut runtime, 0, &unknown_command()).unwrap(),
            UNSUPPORTED_RESPONSE,
            "the normal dispatcher still answers"
        );
    }

    fn self_test_capable_runtime() -> Tpm2Runtime {
        use crate::library::tpm2::manufacture::manufacture_state;
        use crate::library::tpm2::profile::validate_user_profile;
        use crate::library::tpm2::runtime::commit_manufactured_state;

        let profile = validate_user_profile(None).expect("the default profile validates");
        let state = manufacture_state(profile, self_test_entropy).expect("the state is built");
        let mut runtime = commit_manufactured_state(state).expect("the state is committed");
        runtime.entropy = self_test_entropy;
        runtime.startup_received = true;
        runtime
    }

    fn self_test_entropy(buffer: &mut [u8]) -> Result<(), u32> {
        let len = buffer.len() as u8;
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_add(len) ^ 0x27;
        }
        Ok(())
    }

    #[test]
    fn successful_self_test_dispatch_unchanged() {
        const SUCCESS: [u8; 10] = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00];
        const FULL_SELF_TEST: [u8; 11] = [
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x01, 0x43, 0x01,
        ];

        let mut runtime = self_test_capable_runtime();
        assert_eq!(
            run_process(&mut runtime, 0, &input(&FULL_SELF_TEST)).unwrap(),
            SUCCESS
        );
        assert!(!runtime.failure_mode);
        assert!(runtime.self_test.failure.is_none());
        assert_eq!(
            run_process(&mut runtime, 0, &unknown_command()).unwrap(),
            UNSUPPORTED_RESPONSE,
            "the normal dispatcher still answers"
        );
    }

    #[test]
    fn oversized_received_size_command_size_error() {
        let mut runtime = empty_state_runtime();
        for received_size in [4097u32, i32::MAX as u32 + 1, u32::MAX] {
            let mut prefix = vec![0x80, 0x01];
            prefix.extend_from_slice(&received_size.to_be_bytes());
            let oversized = CommandInput::new(received_size, prefix);
            assert_eq!(
                run_process(&mut runtime, 0, &oversized).unwrap(),
                COMMAND_SIZE_RESPONSE,
                "received size {received_size}"
            );
        }
        assert_runtime_is_pristine(&runtime);
    }

    #[test]
    fn runtime_buffer_command_size_limit() {
        use crate::library::tpm2::buffer_size::{DEFAULT_BUFFER_SIZE, MIN_BUFFER_SIZE};

        fn unsupported_command(size: u32) -> CommandInput {
            let mut bytes = vec![0u8; size as usize];
            bytes[..2].copy_from_slice(&[0x80, 0x01]);
            bytes[2..6].copy_from_slice(&size.to_be_bytes());
            bytes[6..10].copy_from_slice(&[0x20, 0x00, 0x00, 0x00]);
            CommandInput::new(size, bytes)
        }

        let mut runtime = empty_state_runtime();
        assert_eq!(runtime.buffer_size, DEFAULT_BUFFER_SIZE);
        assert_eq!(
            run_process(&mut runtime, 0, &unsupported_command(DEFAULT_BUFFER_SIZE)).unwrap(),
            UNSUPPORTED_RESPONSE
        );

        runtime.buffer_size = MIN_BUFFER_SIZE;
        assert_eq!(
            run_process(&mut runtime, 0, &unsupported_command(MIN_BUFFER_SIZE)).unwrap(),
            UNSUPPORTED_RESPONSE,
            "a command of exactly the configured size is accepted"
        );
        assert_eq!(
            run_process(&mut runtime, 0, &unsupported_command(MIN_BUFFER_SIZE + 1)).unwrap(),
            COMMAND_SIZE_RESPONSE,
            "one byte more is rejected"
        );
        assert_eq!(
            run_process(&mut runtime, 0, &unsupported_command(DEFAULT_BUFFER_SIZE)).unwrap(),
            COMMAND_SIZE_RESPONSE
        );

        runtime.failure_mode = true;
        assert_eq!(
            run_process(&mut runtime, 0, &startup_command()).unwrap(),
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x01],
            "the failure-mode response still fits the configured buffer"
        );
        runtime.failure_mode = false;

        runtime.buffer_size = DEFAULT_BUFFER_SIZE;
        assert_eq!(
            run_process(&mut runtime, 0, &unsupported_command(DEFAULT_BUFFER_SIZE)).unwrap(),
            UNSUPPORTED_RESPONSE,
            "restoring the maximum restores the original behavior"
        );
    }

    #[test]
    fn locality_value_form_recording() {
        let mut runtime = empty_state_runtime();
        for (given, recorded) in [(0, 0), (4, 4), (5, 0), (31, 0), (32, 32), (255, 255)] {
            run_process(&mut runtime, given, &startup_command()).unwrap();
            assert_eq!(
                runtime.locality, recorded,
                "locality {given} records as {recorded}, like _plat__LocalitySet"
            );
        }
    }

    #[test]
    fn locality_propagation_failure_mode_not_powered_off() {
        let mut runtime = empty_state_runtime();
        runtime.failure_mode = true;
        run_process(&mut runtime, 2, &startup_command()).unwrap();
        assert_eq!(
            runtime.locality, 2,
            "C sets the locality before ExecuteCommand checks failure mode"
        );

        runtime.power_on = false;
        run_process(&mut runtime, 4, &startup_command()).unwrap();
        assert_eq!(
            runtime.locality, 2,
            "a powered-off TPM rejects the command before the locality is set"
        );
    }

    #[test]
    fn process_before_init_empty_response() {
        let library = Tpm::default();
        assert_eq!(
            library.set_version(crate::library::TpmVersion::V2_0),
            TPM_SUCCESS
        );
        let response = library
            .process_input(&startup_command())
            .expect("C answers TPM_SUCCESS with an empty response before MainInit");
        assert!(response.is_empty());
    }

    #[test]
    fn process_after_terminate_empty_response() {
        use crate::library::state_blob::StateBlobKind;

        let library = Tpm::default();
        assert_eq!(
            library.set_version(crate::library::TpmVersion::V2_0),
            TPM_SUCCESS
        );
        library.stage_empty_state(StateBlobKind::Permanent);
        assert_eq!(library.initialize(), TPM_SUCCESS);
        library.terminate();

        let response = library
            .process_input(&startup_command())
            .expect("a terminated library answers like a stopped TPM");
        assert!(response.is_empty());
        assert_eq!(library.tpm2_runtime_locality(), None);
    }

    #[test]
    fn missing_tpm2_selection_process_failure() {
        let library = Tpm::default();
        assert_eq!(
            library.process_input(&startup_command()),
            Err(crate::library::constants::TPM_FAIL),
            "the default TPM 1.2 selection routes to the disabled interface"
        );
    }

    mod physical_presence {
        use super::*;
        use crate::library::platform::test_support::TestPlatform;
        use crate::library::state_blob::StateBlobKind;
        use std::sync::{Arc, Mutex};

        static CALLS: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());

        fn asserted() -> Arc<dyn crate::library::platform::Platform> {
            TestPlatform::new().on_physical_presence(|| true).arc()
        }

        fn counted() -> Arc<dyn crate::library::platform::Platform> {
            TestPlatform::new()
                .on_physical_presence(|| {
                    CALLS.lock().unwrap().push("asserted");
                    true
                })
                .arc()
        }

        fn not_asserted() -> Arc<dyn crate::library::platform::Platform> {
            TestPlatform::new().on_physical_presence(|| false).arc()
        }

        fn absent() -> Arc<dyn crate::library::platform::Platform> {
            TestPlatform::new().arc()
        }

        fn started_library(platform: Arc<dyn crate::library::platform::Platform>) -> Tpm {
            let library = Tpm::default();
            library.register_platform(platform);
            assert_eq!(
                library.set_version(crate::library::TpmVersion::V2_0),
                TPM_SUCCESS
            );
            library.stage_empty_state(StateBlobKind::Permanent);
            assert_eq!(library.initialize(), TPM_SUCCESS);
            library
        }

        #[track_caller]
        fn observed(platform: Arc<dyn crate::library::platform::Platform>) -> Option<bool> {
            let library = started_library(platform);
            library.process_input(&unknown_command()).unwrap();
            let observed = library.tpm2_runtime_physical_presence();
            library.terminate();
            observed
        }

        #[test]
        fn asserting_callback_propagation() {
            assert_eq!(observed(asserted()), Some(true));
        }

        #[test]
        fn denied_presence_callback_propagation() {
            assert_eq!(observed(not_asserted()), Some(false));
        }

        #[test]
        fn absent_callback_platform_default_fallback() {
            assert_eq!(observed(absent()), Some(false));
        }

        #[test]
        fn queried_once_per_command() {
            let mut calls = CALLS.lock().unwrap();
            calls.clear();
            drop(calls);
            let library = started_library(counted());
            library.process_input(&unknown_command()).unwrap();
            assert_eq!(*CALLS.lock().unwrap(), ["asserted"]);
            assert_eq!(library.tpm2_runtime_physical_presence(), Some(true));
            library.terminate();
        }

        #[test]
        fn locality_presence_input_isolation() {
            let library = Tpm::default();
            library.register_platform(asserted());
            assert_eq!(
                library.set_version(crate::library::TpmVersion::V2_0),
                TPM_SUCCESS
            );
            library.stage_empty_state(StateBlobKind::Permanent);
            assert_eq!(library.initialize(), TPM_SUCCESS);
            library.process_input(&unknown_command()).unwrap();
            assert_eq!(library.tpm2_runtime_locality(), Some(0));
            assert_eq!(library.tpm2_runtime_physical_presence(), Some(true));
            library.terminate();
        }
    }

    mod platform_physical_presence {
        use super::*;
        use crate::library::platform::test_support::TestPlatform;
        use crate::library::state_blob::StateBlobKind;
        use crate::library::tpm2::golden_responses::policy_sessions::vector;

        const TPM_CC_CLEAR_CONTROL: u32 = 0x0000_0127;
        const TPM_CC_HIERARCHY_CHANGE_AUTH: u32 = 0x0000_0129;
        const TPM_RC_PP: u32 = 0x0000_0990;
        const TPM_RC_BAD_AUTH: u32 = 0x0000_09a2;
        const PLATFORM: u32 = 0x4000_000c;
        const LOCKOUT: u32 = 0x4000_000a;
        const OWNER: u32 = 0x4000_0001;

        fn asserted() -> std::sync::Arc<dyn crate::library::platform::Platform> {
            TestPlatform::new().on_physical_presence(|| true).arc()
        }

        fn absent() -> std::sync::Arc<dyn crate::library::platform::Platform> {
            TestPlatform::new().arc()
        }

        fn not_asserted() -> std::sync::Arc<dyn crate::library::platform::Platform> {
            TestPlatform::new().on_physical_presence(|| false).arc()
        }

        fn restored_library(
            snapshot: &str,
            platform: std::sync::Arc<dyn crate::library::platform::Platform>,
        ) -> Tpm {
            let library = Tpm::default();
            library.register_platform(platform);
            assert_eq!(
                library.set_version(crate::library::TpmVersion::V2_0),
                TPM_SUCCESS
            );
            library.stage_state_data(
                StateBlobKind::Permanent,
                vector(&format!("PERMALL_{snapshot}")).to_vec(),
            );
            library.stage_state_data(
                StateBlobKind::Volatile,
                vector(&format!("VOLATILE_{snapshot}")).to_vec(),
            );
            assert_eq!(library.initialize(), TPM_SUCCESS);
            library
        }

        #[track_caller]
        fn code_of(response: &[u8]) -> u32 {
            u32::from_be_bytes(response[6..10].try_into().expect("a response code"))
        }

        fn password_area() -> Vec<u8> {
            vec![0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00]
        }

        fn clear_control(handle: u32, area: &[u8], disable: u8) -> Vec<u8> {
            let mut payload = handle.to_be_bytes().to_vec();
            payload.extend_from_slice(&(area.len() as u32).to_be_bytes());
            payload.extend_from_slice(area);
            payload.push(disable);
            framed(TPM_CC_CLEAR_CONTROL, &payload)
        }

        fn hierarchy_change_auth(handle: u32) -> Vec<u8> {
            let area = password_area();
            let mut payload = handle.to_be_bytes().to_vec();
            payload.extend_from_slice(&(area.len() as u32).to_be_bytes());
            payload.extend_from_slice(&area);
            payload.extend_from_slice(&0u16.to_be_bytes());
            framed(TPM_CC_HIERARCHY_CHANGE_AUTH, &payload)
        }

        fn framed(code: u32, payload: &[u8]) -> Vec<u8> {
            let mut out = 0x8002u16.to_be_bytes().to_vec();
            out.extend_from_slice(&(10 + payload.len() as u32).to_be_bytes());
            out.extend_from_slice(&code.to_be_bytes());
            out.extend_from_slice(payload);
            out
        }

        #[track_caller]
        fn send(library: &Tpm, bytes: &[u8]) -> Vec<u8> {
            library
                .process_input(&input(bytes))
                .expect("the command executes")
        }

        #[test]
        fn listed_command_presence_requirement() {
            let library = restored_library("READY", not_asserted());
            library.tpm2_require_physical_presence(TPM_CC_CLEAR_CONTROL);
            assert_eq!(
                code_of(&send(
                    &library,
                    &clear_control(PLATFORM, &password_area(), 0x00)
                )),
                TPM_RC_PP
            );
            library.terminate();
        }

        #[test]
        fn listed_command_asserted_presence_success() {
            let library = restored_library("READY", asserted());
            library.tpm2_require_physical_presence(TPM_CC_CLEAR_CONTROL);
            assert_eq!(
                code_of(&send(
                    &library,
                    &clear_control(PLATFORM, &password_area(), 0x00)
                )),
                0
            );
            library.terminate();
        }

        #[test]
        fn absent_or_failing_callback_unasserted() {
            for platform in [absent(), not_asserted()] {
                let library = restored_library("READY", platform);
                library.tpm2_require_physical_presence(TPM_CC_CLEAR_CONTROL);
                assert_eq!(
                    code_of(&send(
                        &library,
                        &clear_control(PLATFORM, &password_area(), 0x00)
                    )),
                    TPM_RC_PP
                );
                library.terminate();
            }
        }

        #[test]
        fn unlisted_command_ungated() {
            let library = restored_library("READY", not_asserted());
            assert_eq!(
                code_of(&send(
                    &library,
                    &clear_control(PLATFORM, &password_area(), 0x00)
                )),
                0
            );
            library.terminate();
        }

        #[test]
        fn platform_authorization_only_gating() {
            let library = restored_library("READY", not_asserted());
            library.tpm2_require_physical_presence(TPM_CC_CLEAR_CONTROL);
            library.tpm2_require_physical_presence(TPM_CC_HIERARCHY_CHANGE_AUTH);
            assert_eq!(
                code_of(&send(
                    &library,
                    &clear_control(LOCKOUT, &password_area(), 0x01)
                )),
                0,
                "lockout authorization is not platform authorization"
            );
            for handle in [OWNER, 0x4000_000b, LOCKOUT] {
                assert_eq!(
                    code_of(&send(&library, &hierarchy_change_auth(handle))),
                    0,
                    "handle {handle:#x} is not platform authorization"
                );
            }
            library.terminate();
        }

        #[test]
        fn nv_index_authorization_distinction() {
            let library = restored_library("FLOW_NV_WRITTEN", not_asserted());
            library.tpm2_require_physical_presence(0x0000_014e);
            let mut payload = 0x0100_0000u32.to_be_bytes().to_vec();
            payload.extend_from_slice(&0x0100_0000u32.to_be_bytes());
            let area = password_area();
            payload.extend_from_slice(&(area.len() as u32).to_be_bytes());
            payload.extend_from_slice(&area);
            payload.extend_from_slice(&8u16.to_be_bytes());
            payload.extend_from_slice(&0u16.to_be_bytes());
            let response = send(&library, &framed(0x0000_014e, &payload));
            assert_ne!(
                code_of(&response),
                TPM_RC_PP,
                "an NV index authorization never consults the pp-list"
            );
            library.terminate();
        }

        #[test]
        fn gate_order_before_password_and_hmac() {
            let library = restored_library("READY", not_asserted());
            library.tpm2_require_physical_presence(TPM_CC_CLEAR_CONTROL);
            let mut wrong_password = password_area();
            wrong_password[8] = 0x03;
            wrong_password.extend_from_slice(b"bad");
            assert_eq!(
                code_of(&send(
                    &library,
                    &clear_control(PLATFORM, &wrong_password, 0x00)
                )),
                TPM_RC_PP,
                "physical presence is checked before the password"
            );

            let session = {
                let mut start = 0x8001u16.to_be_bytes().to_vec();
                let payload = {
                    let mut out = 0x4000_0007u32.to_be_bytes().to_vec();
                    out.extend_from_slice(&0x4000_0007u32.to_be_bytes());
                    out.extend_from_slice(&16u16.to_be_bytes());
                    out.extend_from_slice(&[0x5a; 16]);
                    out.extend_from_slice(&0u16.to_be_bytes());
                    out.push(0x00);
                    out.extend_from_slice(&[0x00, 0x10]);
                    out.extend_from_slice(&0x000bu16.to_be_bytes());
                    out
                };
                start.extend_from_slice(&(10 + payload.len() as u32).to_be_bytes());
                start.extend_from_slice(&0x0000_0176u32.to_be_bytes());
                start.extend_from_slice(&payload);
                start
            };
            assert_eq!(code_of(&send(&library, &session)), 0, "the session starts");

            let mut hmac_area = 0x0200_0000u32.to_be_bytes().to_vec();
            hmac_area.extend_from_slice(&16u16.to_be_bytes());
            hmac_area.extend_from_slice(&[0x5a; 16]);
            hmac_area.push(0x01);
            hmac_area.extend_from_slice(&32u16.to_be_bytes());
            hmac_area.extend_from_slice(&[0x00; 32]);
            assert_eq!(
                code_of(&send(&library, &clear_control(PLATFORM, &hmac_area, 0x00))),
                TPM_RC_PP,
                "physical presence is checked before the session HMAC"
            );
            library.terminate();
        }

        #[test]
        fn asserted_presence_authorization_failure_propagation() {
            let library = restored_library("READY", asserted());
            library.tpm2_require_physical_presence(TPM_CC_CLEAR_CONTROL);
            let mut wrong_password = password_area();
            wrong_password[8] = 0x03;
            wrong_password.extend_from_slice(b"bad");
            assert_eq!(
                code_of(&send(
                    &library,
                    &clear_control(PLATFORM, &wrong_password, 0x00)
                )),
                TPM_RC_BAD_AUTH,
                "the gate no longer masks the password check"
            );
            library.terminate();
        }

        #[test]
        fn presence_free_policy_build_gated_use() {
            const POLICY_PHYSICAL_PRESENCE: u32 = 0x0000_0187;
            const POLICY_COMMAND_CODE: u32 = 0x0000_016c;

            fn assertions() -> Vec<Vec<u8>> {
                let mut presence = 0x8001u16.to_be_bytes().to_vec();
                presence.extend_from_slice(&14u32.to_be_bytes());
                presence.extend_from_slice(&POLICY_PHYSICAL_PRESENCE.to_be_bytes());
                presence.extend_from_slice(&0x0300_0000u32.to_be_bytes());
                let mut code = 0x8001u16.to_be_bytes().to_vec();
                code.extend_from_slice(&18u32.to_be_bytes());
                code.extend_from_slice(&POLICY_COMMAND_CODE.to_be_bytes());
                code.extend_from_slice(&0x0300_0000u32.to_be_bytes());
                code.extend_from_slice(&0x0000_014eu32.to_be_bytes());
                vec![presence, code]
            }

            fn policy_read() -> Vec<u8> {
                let mut area = 0x0300_0000u32.to_be_bytes().to_vec();
                area.extend_from_slice(&16u16.to_be_bytes());
                area.extend_from_slice(&[0x5a; 16]);
                area.push(0x01);
                area.extend_from_slice(&0u16.to_be_bytes());
                let mut payload = 0x0100_0000u32.to_be_bytes().to_vec();
                payload.extend_from_slice(&0x0100_0000u32.to_be_bytes());
                payload.extend_from_slice(&(area.len() as u32).to_be_bytes());
                payload.extend_from_slice(&area);
                payload.extend_from_slice(&8u16.to_be_bytes());
                payload.extend_from_slice(&0u16.to_be_bytes());
                framed(0x0000_014e, &payload)
            }

            let refused = restored_library("FLOW_PHYSICAL_PRESENCE", not_asserted());
            for assertion in assertions() {
                assert_eq!(
                    code_of(&send(&refused, &assertion)),
                    0,
                    "the policy is built without asserted physical presence"
                );
            }
            assert_eq!(
                send(&refused, &policy_read()),
                vector("FLOW_NV_READ_PHYSICAL_PRESENCE")
            );
            refused.terminate();

            let allowed = restored_library("FLOW_PHYSICAL_PRESENCE", asserted());
            for assertion in assertions() {
                assert_eq!(code_of(&send(&allowed, &assertion)), 0);
            }
            assert_eq!(
                code_of(&send(&allowed, &policy_read())),
                0,
                "the public callback satisfies the policy"
            );
            allowed.terminate();
        }
    }

    mod locality {
        use super::*;
        use crate::library::platform::test_support::TestPlatform;
        use crate::library::state_blob::StateBlobKind;
        use std::sync::Mutex;

        static EVENTS: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());

        fn locality_library() -> Tpm {
            let library = Tpm::default();
            library.register_platform(
                TestPlatform::new()
                    .on_locality(|| {
                        EVENTS.lock().unwrap().push("locality");
                        3
                    })
                    .arc(),
            );
            library
        }

        #[test]
        fn queried_once_per_command() {
            EVENTS.lock().unwrap().clear();
            let library = locality_library();
            assert_eq!(
                library.set_version(crate::library::TpmVersion::V2_0),
                TPM_SUCCESS
            );

            let response = library.process_input(&startup_command()).unwrap();
            assert!(response.is_empty());
            assert!(
                EVENTS.lock().unwrap().is_empty(),
                "an uninitialized TPM never queries the locality callback"
            );

            library.stage_empty_state(StateBlobKind::Permanent);
            assert_eq!(library.initialize(), TPM_SUCCESS);
            assert_eq!(
                library.tpm2_runtime_locality(),
                Some(0),
                "MainInit itself never queries the locality callback"
            );

            EVENTS.lock().unwrap().clear();
            let response = library
                .process_input(&unknown_command())
                .expect("the callback's weird return code is not the outer result");
            assert_eq!(response, UNSUPPORTED_RESPONSE);
            assert_eq!(
                *EVENTS.lock().unwrap(),
                ["locality"],
                "exactly one callback query per command"
            );
            assert_eq!(library.tpm2_runtime_locality(), Some(3));
            library.terminate();
        }

        #[test]
        fn missing_callback_locality_zero_default() {
            let library = Tpm::default();
            assert_eq!(
                library.set_version(crate::library::TpmVersion::V2_0),
                TPM_SUCCESS
            );
            library.stage_empty_state(StateBlobKind::Permanent);
            assert_eq!(library.initialize(), TPM_SUCCESS);
            library.process_input(&startup_command()).unwrap();
            assert_eq!(library.tpm2_runtime_locality(), Some(0));
            library.terminate();
        }

        static DISABLED_CALLS: Mutex<u32> = Mutex::new(0);

        #[test]
        fn disabled_interface_no_locality_callback_query() {
            let library = Tpm::default();
            library.register_platform(
                TestPlatform::new()
                    .on_locality(|| {
                        *DISABLED_CALLS.lock().unwrap() += 1;
                        0
                    })
                    .arc(),
            );
            assert!(library.process_input(&startup_command()).is_err());
            assert_eq!(*DISABLED_CALLS.lock().unwrap(), 0);
        }
    }

    #[test]
    fn single_command_per_process_call() {
        use crate::library::state_blob::StateBlobKind;

        let library = Tpm::default();
        assert_eq!(
            library.set_version(crate::library::TpmVersion::V2_0),
            TPM_SUCCESS
        );
        library.stage_empty_state(StateBlobKind::Permanent);
        assert_eq!(library.initialize(), TPM_SUCCESS);
        for round in 0..3 {
            let response = library
                .process_input(&unknown_command())
                .expect("an unsupported command is still an outer success");
            assert_eq!(response, UNSUPPORTED_RESPONSE, "round {round}");
            let malformed = library.process_input(&input(&[0xff])).unwrap();
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
    mod persistence {
        use super::*;
        use crate::library::constants::TPM_FAIL;
        use crate::library::tpm2::manufacture::manufacture_state;
        use crate::library::tpm2::persistent::{
            PersistentAllEnvelope, materialize_persistent_state, persistent_all_store,
        };
        use crate::library::tpm2::profile::validate_user_profile;
        use crate::library::tpm2::runtime::commit_manufactured_state;

        fn deterministic_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
            let len = buffer.len() as u8;
            for (index, byte) in buffer.iter_mut().enumerate() {
                *byte = (index as u8).wrapping_add(len) ^ 0x27;
            }
            Ok(())
        }

        fn manufactured_runtime() -> Tpm2Runtime {
            let profile = validate_user_profile(None).unwrap();
            let state = manufacture_state(profile, deterministic_entropy).unwrap();
            let mut runtime = commit_manufactured_state(state).unwrap();
            runtime.entropy = deterministic_entropy;
            runtime
        }

        const SUCCESS_RESPONSE: [u8; 10] =
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00];
        const FAILURE_RESPONSE: [u8; 10] =
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x01];

        #[test]
        fn successful_startup_single_permanent_state_commit() {
            let mut runtime = manufactured_runtime();
            let mut stored: Vec<Vec<u8>> = Vec::new();
            let response = process(&mut runtime, 0, &startup_command(), |runtime| {
                stored.push(persistent_all_store(runtime.state.as_ref().unwrap()).unwrap());
                Ok(())
            })
            .unwrap();
            assert_eq!(response, SUCCESS_RESPONSE);
            assert!(!runtime.nv_update_pending, "the pending flag is consumed");

            assert_eq!(stored.len(), 1, "exactly one commit per startup");
            assert_eq!(
                stored[0],
                persistent_all_store(runtime.state.as_ref().unwrap()).unwrap(),
                "the committed blob is the current permanent state"
            );

            let envelope = PersistentAllEnvelope::parse(&stored[0]).unwrap();
            let decoded = crate::library::tpm2::parse_persistent_all_payload(&envelope).unwrap();
            let state = materialize_persistent_state(decoded).unwrap();
            assert_eq!(state.persistent.reset_count, 1);
            assert_eq!(state.persistent.total_reset_count, 1);
            assert_eq!(state.persistent.orderly_state, 0xffff);
            assert!(
                state.state_reset.is_none() && state.state_clear.is_none(),
                "a non-orderly blob carries no SU sections"
            );
            let runtime_state = runtime.state.as_ref().unwrap();
            assert_eq!(
                state.orderly.drbg_state.seed.expose(),
                runtime_state.orderly.drbg_state.seed.expose()
            );
            assert_eq!(
                state.orderly.drbg_state.reseed_counter, 8,
                "the manufacture-time DRBG state is still the persisted one"
            );
            assert_ne!(
                state.orderly.drbg_state.seed.expose(),
                runtime.live.orderly.drbg_state.seed.expose(),
                "the live reseeded go is not persisted by Startup"
            );
            assert_eq!(runtime.live.orderly.drbg_state.reseed_counter, 4);
        }

        #[test]
        fn rejected_and_malformed_command_no_commit() {
            let commits = core::cell::Cell::new(0u32);
            let count = |_: &Tpm2Runtime| -> Result<(), TpmResult> {
                commits.set(commits.get() + 1);
                Ok(())
            };

            let mut runtime = manufactured_runtime();
            let response = process(&mut runtime, 2, &startup_command(), count).unwrap();
            assert_eq!(response[6..], [0x00, 0x00, 0x09, 0x07]);

            let mut runtime = manufactured_runtime();
            let truncated = input(&[0x80, 0x01, 0, 0, 0, 0x0a, 0, 0, 0x01, 0x44]);
            let response = process(&mut runtime, 0, &truncated, count).unwrap();
            assert_eq!(response[6..], [0x00, 0x00, 0x01, 0xda]);

            let mut runtime = manufactured_runtime();
            let invalid = input(&[0x80, 0x01, 0, 0, 0, 0x0c, 0, 0, 0x01, 0x44, 0, 2]);
            let response = process(&mut runtime, 0, &invalid, count).unwrap();
            assert_eq!(response[6..], [0x00, 0x00, 0x01, 0xc4]);

            let mut runtime = manufactured_runtime();
            runtime.nv_available = false;
            let response = process(&mut runtime, 0, &startup_command(), count).unwrap();
            assert_eq!(response[6..], [0x00, 0x00, 0x09, 0x23]);

            let mut runtime = manufactured_runtime();
            let response = process(&mut runtime, 0, &unknown_command(), count).unwrap();
            assert_eq!(response, UNSUPPORTED_RESPONSE);

            assert_eq!(commits.get(), 0, "no commit for non-mutating commands");
        }

        #[test]
        fn repeated_startup_no_recommit() {
            let commits = core::cell::Cell::new(0u32);
            let count = |_: &Tpm2Runtime| -> Result<(), TpmResult> {
                commits.set(commits.get() + 1);
                Ok(())
            };
            let mut runtime = manufactured_runtime();
            assert_eq!(
                process(&mut runtime, 0, &startup_command(), count).unwrap(),
                SUCCESS_RESPONSE
            );
            assert_eq!(commits.get(), 1);
            let response = process(&mut runtime, 0, &startup_command(), count).unwrap();
            assert_eq!(response[6..], [0x00, 0x00, 0x01, 0x00]);
            assert_eq!(commits.get(), 1, "TPM_RC_INITIALIZE performs no commit");
        }

        #[test]
        fn nv_uninitialized_resume_no_commit() {
            use crate::library::tpm2::persistent::{
                OwnedSecret, OwnedStateClearData, OwnedStateResetData,
            };
            use crate::library::tpm2::state::{COMMIT_ARRAY_SIZE, MAX_ACTIVE_SESSIONS};

            let mut runtime = manufactured_runtime();
            {
                let state = runtime.state.as_mut().unwrap();
                state.persistent.orderly_state = 0x0001;
                state.state_reset = Some(OwnedStateResetData {
                    null_proof: OwnedSecret::from_vec(vec![0x0f; 8]),
                    null_seed: OwnedSecret::from_vec(vec![0x5e; 8]),
                    clear_count: 0,
                    object_context_id: 0,
                    context_array: Box::new([0; MAX_ACTIVE_SESSIONS]),
                    context_slot_mask: 0xffff,
                    context_counter: 4,
                    command_audit_digest: Vec::new(),
                    restart_count: 0,
                    pcr_counter: 0,
                    commit_counter: 0,
                    commit_nonce: OwnedSecret::from_vec(vec![0; 64]),
                    commit_array: [0; COMMIT_ARRAY_SIZE],
                    null_seed_compat_level: 1,
                });
                state.state_clear = Some(OwnedStateClearData {
                    sh_enable: true,
                    eh_enable: true,
                    ph_enable_nv: true,
                    platform_alg: 0x0010,
                    platform_policy: Vec::new(),
                    platform_auth: OwnedSecret::from_vec(Vec::new()),
                    pcr_save: core::array::from_fn(|_| None),
                    pcr_auth_values: core::array::from_fn(|_| OwnedSecret::from_vec(Vec::new())),
                });
            }
            runtime.live.nv_ok = false;

            let mut commits = 0u32;
            let resume = input(&[0x80, 0x01, 0, 0, 0, 0x0c, 0, 0, 0x01, 0x44, 0, 1]);
            let response = process(&mut runtime, 0, &resume, |_: &Tpm2Runtime| {
                commits += 1;
                Ok(())
            })
            .unwrap();
            assert_eq!(response[6..], [0x00, 0x00, 0x01, 0x4a]);
            assert!(!runtime.startup_received);
            assert!(!runtime.nv_update_pending);
            assert_eq!(commits, 0, "TPM_RC_NV_UNINITIALIZED performs no commit");
        }

        #[test]
        fn missing_storage_backend_fallthrough_success() {
            use crate::library::storage::NoStorage;
            use crate::library::tpm2::host_nv_commit;

            let storage = NoStorage;
            let mut runtime = manufactured_runtime();
            let response = process(&mut runtime, 0, &startup_command(), |runtime| {
                host_nv_commit(&storage, runtime)
            })
            .unwrap();
            assert_eq!(response, SUCCESS_RESPONSE);
            assert!(runtime.startup_received);
            assert!(!runtime.nv_update_pending);
        }

        fn shutdown_command(shutdown_type: u16) -> CommandInput {
            let mut out = vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x45];
            out.extend_from_slice(&shutdown_type.to_be_bytes());
            input(&out)
        }

        #[test]
        fn successful_shutdown_single_permanent_state_commit() {
            let mut runtime = manufactured_runtime();
            let mut stored: Vec<Vec<u8>> = Vec::new();
            let mut store = |runtime: &Tpm2Runtime| {
                stored.push(persistent_all_store(runtime.state.as_ref().unwrap()).unwrap());
                Ok(())
            };
            let response = process(&mut runtime, 0, &startup_command(), &mut store).unwrap();
            assert_eq!(response, SUCCESS_RESPONSE);
            let response = process(&mut runtime, 0, &shutdown_command(0x0001), &mut store).unwrap();
            assert_eq!(response, SUCCESS_RESPONSE);
            assert!(
                runtime.startup_received,
                "consuming the commit leaves g_initialized set"
            );
            assert!(!runtime.nv_update_pending, "the pending flag is consumed");

            let response = process(&mut runtime, 0, &startup_command(), &mut store).unwrap();
            assert_eq!(
                response[6..],
                [0x00, 0x00, 0x01, 0x00],
                "Startup after Shutdown needs _TPM_Init first"
            );
            assert!(runtime.startup_received);

            assert_eq!(stored.len(), 2, "one commit per state-changing command");
            assert_eq!(
                stored[1],
                persistent_all_store(runtime.state.as_ref().unwrap()).unwrap()
            );

            let envelope = PersistentAllEnvelope::parse(&stored[1]).unwrap();
            let decoded = crate::library::tpm2::parse_persistent_all_payload(&envelope).unwrap();
            let state = materialize_persistent_state(decoded).unwrap();
            assert_eq!(state.persistent.orderly_state, 0x0001);
            assert!(
                state.state_reset.is_some() && state.state_clear.is_some(),
                "an SU_STATE blob carries the SU sections"
            );
            assert_eq!(
                state.orderly.drbg_state.seed.expose(),
                runtime.live.orderly.drbg_state.seed.expose(),
                "Shutdown persisted the live go"
            );
        }

        #[test]
        fn failed_shutdown_command_no_commit() {
            let commits = core::cell::Cell::new(0u32);
            let count = |_: &Tpm2Runtime| -> Result<(), TpmResult> {
                commits.set(commits.get() + 1);
                Ok(())
            };

            let mut runtime = manufactured_runtime();
            let response = process(&mut runtime, 0, &shutdown_command(0x0000), count).unwrap();
            assert_eq!(response[6..], [0x00, 0x00, 0x01, 0x00]);
            assert_eq!(commits.get(), 0);

            let mut runtime = manufactured_runtime();
            assert_eq!(
                process(&mut runtime, 0, &startup_command(), count).unwrap(),
                SUCCESS_RESPONSE
            );
            assert_eq!(commits.get(), 1);

            let response = process(&mut runtime, 0, &shutdown_command(0x0002), count).unwrap();
            assert_eq!(response[6..], [0x00, 0x00, 0x01, 0xc4]);

            runtime.nv_available = false;
            let response = process(&mut runtime, 0, &shutdown_command(0x0000), count).unwrap();
            assert_eq!(response[6..], [0x00, 0x00, 0x09, 0x23]);
            runtime.nv_available = true;

            runtime.live.pcr_reconfig = true;
            let response = process(&mut runtime, 0, &shutdown_command(0x0001), count).unwrap();
            assert_eq!(response[6..], [0x00, 0x00, 0x01, 0xca]);
            runtime.live.pcr_reconfig = false;

            assert_eq!(commits.get(), 1, "failed Shutdowns never reach the commit");
            assert!(runtime.startup_received);
        }

        #[test]
        fn successful_shutdown_storage_backend_propagation() {
            use crate::library::StateBlobKind;
            use crate::library::storage::test_support::TestStorage;
            use crate::library::tpm2::host_nv_commit;
            use std::sync::{Arc, Mutex};

            let stored_blobs = Arc::new(Mutex::new(Vec::new()));
            let recorder = Arc::clone(&stored_blobs);
            let storage = TestStorage::new().on_store(move |kind, data| {
                recorder.lock().unwrap().push((kind, data.to_vec()));
                Ok(())
            });
            let mut runtime = manufactured_runtime();
            let commit = |runtime: &Tpm2Runtime| host_nv_commit(&storage, runtime);
            assert_eq!(
                process(&mut runtime, 0, &startup_command(), commit).unwrap(),
                SUCCESS_RESPONSE
            );
            assert_eq!(
                process(&mut runtime, 0, &shutdown_command(0x0001), commit).unwrap(),
                SUCCESS_RESPONSE
            );

            let stored = stored_blobs.lock().unwrap();
            assert_eq!(stored.len(), 2);
            assert!(
                stored
                    .iter()
                    .all(|(kind, _)| *kind == StateBlobKind::Permanent)
            );
            assert_eq!(
                stored[1].1,
                persistent_all_store(runtime.state.as_ref().unwrap()).unwrap(),
                "the Shutdown commit stored the post-Shutdown permanent state"
            );
        }

        #[test]
        fn shutdown_commit_failure_mutation_preservation() {
            let mut runtime = manufactured_runtime();
            assert_eq!(
                process(&mut runtime, 0, &startup_command(), |_| Ok(())).unwrap(),
                SUCCESS_RESPONSE
            );
            let response = process(&mut runtime, 0, &shutdown_command(0x0000), |_| {
                Err(TPM_FAIL)
            })
            .unwrap();
            assert_eq!(response, FAILURE_RESPONSE);
            assert!(runtime.failure_mode);
            assert!(
                runtime.startup_received,
                "Shutdown never clears g_initialized, even on a commit failure"
            );
            assert_eq!(
                runtime.state.as_ref().unwrap().persistent.orderly_state,
                0x0000,
                "the applied NV-image mutation stays"
            );
        }

        #[test]
        fn commit_failure_mode() {
            let mut runtime = manufactured_runtime();
            let response = process(&mut runtime, 0, &startup_command(), |_| Err(TPM_FAIL)).unwrap();
            assert_eq!(
                response, FAILURE_RESPONSE,
                "NvCommit failure is FAIL(FATAL_ERROR_INTERNAL): the reply \
                 becomes the failure-mode response"
            );
            assert!(runtime.failure_mode);
            assert!(
                runtime.startup_received,
                "like the C g_initialized, the RAM transition stays applied"
            );

            let mut commits = 0u32;
            let response = process(&mut runtime, 0, &unknown_command(), |_: &Tpm2Runtime| {
                commits += 1;
                Ok(())
            })
            .unwrap();
            assert_eq!(response, FAILURE_RESPONSE);
            assert_eq!(commits, 0, "failure mode never reaches the commit");
        }
    }
}
