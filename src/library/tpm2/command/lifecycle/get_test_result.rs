// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/CryptSelfTest.c
// - libtpms/src/tpm2/TestingCommands.c
//
// Original upstream authors and copyright notices:
// Written by Ken Goldman
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corp. and others, 2016 - 2024
// (c) Copyright IBM Corp. and others, 2016 - 2021
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use crate::library::constants::{TPM_RC_SIZE, TPM_SUCCESS};
use crate::library::tpm2::command::core::dispatcher::CommandFrame;
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::types::TpmResult;
pub(in crate::library::tpm2::command) fn execute(
    _runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    if !frame.parameters.is_empty() {
        return Err(TPM_RC_SIZE);
    }
    let mut parameters = Vec::with_capacity(2 + 4);
    parameters.extend_from_slice(&0u16.to_be_bytes());
    parameters.extend_from_slice(&TPM_SUCCESS.to_be_bytes());
    Ok(CommandOutput::from_parameters(parameters))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::CommandInput;
    use crate::library::cancel::CancellationToken;
    use crate::library::tpm2::command::core::dispatcher::dispatch;
    use crate::library::tpm2::command::core::header::parse_command;

    use crate::library::tpm2::command::core::test_support::{
        assert_scenario_response, dispatch_bytes, dispatch_if_header_parses, for_each_mutation,
        prefix_bit_flips,
    };
    use crate::library::tpm2::golden_responses::get_test_result::vector;
    use crate::library::tpm2::runtime::empty_state_runtime;

    fn started_runtime() -> Tpm2Runtime {
        let mut runtime = empty_state_runtime();
        runtime.startup_received = true;
        runtime
    }

    fn command() -> Vec<u8> {
        vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x7c]
    }

    #[test]
    fn success_response_oracle_match() {
        let mut runtime = started_runtime();
        assert_eq!(dispatch_bytes(&mut runtime, &command()), vector("GTR_OK"));
        assert_eq!(
            dispatch_bytes(&mut runtime, &command()),
            vector("GTR_OK_REPEAT"),
            "a repeated query answers identically"
        );
    }

    #[test]
    fn success_response_no_rerun_no_pending_report() {
        let mut runtime = started_runtime();
        runtime
            .self_test
            .set_runner(|test| panic!("TPM2_GetTestResult must not run a self test, got {test:?}"));
        let pending = runtime.self_test.pending;
        assert_eq!(dispatch_bytes(&mut runtime, &command()), vector("GTR_OK"));
        assert_eq!(runtime.self_test.pending, pending);
        assert!(runtime.self_test.failure.is_none());
        assert!(!runtime.failure_mode);
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn pre_startup_query_oracle_match() {
        let mut runtime = empty_state_runtime();
        assert_scenario_response(
            "TPM2_GetTestResult before TPM2_Startup: get-test-result GTR_BEFORE_STARTUP",
            vector("GTR_BEFORE_STARTUP"),
            || dispatch_bytes(&mut runtime, &command()),
        );
    }

    #[test]
    fn declared_trailing_parameter_oracle_parity() {
        let mut runtime = started_runtime();
        let mut bytes = command();
        bytes[5] = 0x0b;
        bytes.push(0x00);
        assert_eq!(
            dispatch_bytes(&mut runtime, &bytes),
            vector("GTR_TRAILING_DECLARED"),
            "TPM_RC_SIZE"
        );
    }

    #[test]
    fn session_tagged_request_oracle_parity() {
        let pw_auth: &[u8] = &[
            0x80, 0x02, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x01, 0x7c, 0x00, 0x00, 0x00, 0x09,
            0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let no_authsize: &[u8] = &[0x80, 0x02, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x7c];
        let authsize_zero: &[u8] = &[
            0x80, 0x02, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x01, 0x7c, 0x00, 0x00, 0x00, 0x00,
        ];
        for (bytes, expected) in [
            (pw_auth, "GTR_SESSIONS_PW"),
            (no_authsize, "GTR_SESSIONS_NO_AUTHSIZE"),
            (authsize_zero, "GTR_SESSIONS_AUTHSIZE_ZERO"),
        ] {
            let mut runtime = started_runtime();
            assert_eq!(
                dispatch_bytes(&mut runtime, bytes),
                vector(expected),
                "{expected}"
            );
        }
    }

    #[test]
    fn response_buffer_size_limit() {
        use crate::library::tpm2::buffer_size::MIN_BUFFER_SIZE;
        use crate::library::tpm2::command::core::header::serialize_response_within;
        let mut runtime = started_runtime();
        runtime.buffer_size = MIN_BUFFER_SIZE;
        let input = CommandInput::new(10, command());
        let parsed = parse_command(&input).expect("the header parses");
        let response = dispatch(&mut runtime, &parsed, CancellationToken::disabled());
        assert_eq!(
            serialize_response_within(&response, MIN_BUFFER_SIZE).expect("fits"),
            vector("GTR_OK"),
            "the sixteen-byte response fits every configurable buffer size"
        );
    }

    #[test]
    fn prefix_and_bit_flip_panic_safety() {
        let valid = command();
        for_each_mutation(
            "TPM2_GetTestResult",
            prefix_bit_flips(&valid, 0, 0, false),
            |bytes| {
                dispatch_if_header_parses(bytes, started_runtime);
            },
        );
    }
}
