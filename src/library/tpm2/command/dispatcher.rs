use crate::library::constants::{TPM_RC_COMMAND_CODE, TPM_RC_INITIALIZE};

use super::super::runtime::Tpm2Runtime;
use super::header::{Command, Response};
use super::shutdown;
use super::startup;

pub(in crate::library::tpm2) const TPM_CC_STARTUP: u32 = 0x0000_0144;
pub(in crate::library::tpm2) const TPM_CC_SHUTDOWN: u32 = 0x0000_0145;

pub(in crate::library::tpm2) fn dispatch(
    runtime: &mut Tpm2Runtime,
    command: &Command<'_>,
) -> Response {
    match command.command_code {
        TPM_CC_STARTUP => {
            if runtime.startup_received {
                return Response::error(TPM_RC_INITIALIZE);
            }
            startup::execute(runtime, command)
        }
        TPM_CC_SHUTDOWN => {
            if !runtime.startup_received {
                return Response::error(TPM_RC_INITIALIZE);
            }
            shutdown::execute(runtime, command)
        }
        _ => Response::error(TPM_RC_COMMAND_CODE),
    }
}

#[cfg(test)]
mod tests {
    use super::super::header::{TPM_ST_NO_SESSIONS, parse_command, serialize_response};
    use super::*;
    use crate::library::CommandInput;
    use crate::library::tpm2::runtime::empty_state_runtime;

    fn command(code: u32) -> CommandInput {
        let mut out = vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0a];
        out.extend_from_slice(&code.to_be_bytes());
        CommandInput::new(out.len() as u32, out)
    }

    #[track_caller]
    fn dispatch_code(code: u32) -> Response {
        let mut runtime = empty_state_runtime();
        let input = command(code);
        let parsed = parse_command(&input).expect("a valid header");
        dispatch(&mut runtime, &parsed)
    }

    #[test]
    fn unknown_command_code_answers_command_code() {
        assert_eq!(dispatch_code(0x2000_0000).code(), TPM_RC_COMMAND_CODE);
    }

    #[test]
    fn known_but_unimplemented_command_answers_command_code() {
        assert_eq!(dispatch_code(0x0000_017b).code(), TPM_RC_COMMAND_CODE);
    }

    #[test]
    fn startup_routes_to_the_startup_handler() {
        use crate::library::constants::TPM_RC_FAILURE;
        let mut out = vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0c];
        out.extend_from_slice(&TPM_CC_STARTUP.to_be_bytes());
        out.extend_from_slice(&[0x00, 0x00]);
        let input = CommandInput::new(out.len() as u32, out);
        let parsed = parse_command(&input).unwrap();
        let mut runtime = empty_state_runtime();
        assert_eq!(dispatch(&mut runtime, &parsed).code(), TPM_RC_FAILURE);
    }

    #[test]
    fn started_tpm_rejects_startup_before_parsing_its_payload() {
        use crate::library::constants::TPM_RC_INITIALIZE;
        let mut runtime = empty_state_runtime();
        runtime.startup_received = true;
        let input = command(TPM_CC_STARTUP);
        let parsed = parse_command(&input).unwrap();
        assert_eq!(dispatch(&mut runtime, &parsed).code(), TPM_RC_INITIALIZE);
    }

    #[test]
    fn unstarted_tpm_rejects_shutdown_before_parsing_its_payload() {
        let mut runtime = empty_state_runtime();
        let input = command(TPM_CC_SHUTDOWN);
        let parsed = parse_command(&input).unwrap();
        assert_eq!(dispatch(&mut runtime, &parsed).code(), TPM_RC_INITIALIZE);
    }

    #[test]
    fn shutdown_routes_to_the_shutdown_handler() {
        use crate::library::constants::TPM_RC_FAILURE;
        let mut out = vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0c];
        out.extend_from_slice(&TPM_CC_SHUTDOWN.to_be_bytes());
        out.extend_from_slice(&[0x00, 0x00]);
        let input = CommandInput::new(out.len() as u32, out);
        let parsed = parse_command(&input).unwrap();
        let mut runtime = empty_state_runtime();
        runtime.startup_received = true;
        assert_eq!(dispatch(&mut runtime, &parsed).code(), TPM_RC_FAILURE);
    }

    #[test]
    fn unsupported_response_serializes_like_c() {
        let response = dispatch_code(0x2000_0000);
        assert_eq!(
            serialize_response(&response).unwrap(),
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x43]
        );
    }

    #[test]
    fn unsupported_commands_do_not_mutate_the_runtime() {
        let mut runtime = empty_state_runtime();
        let nv_before = runtime.nv_memory.clone();
        for code in [0x2000_0000, 0x0000_017b, 0xffff_ffff, 0x0000_0000] {
            let input = command(code);
            let parsed = parse_command(&input).unwrap();
            let response = dispatch(&mut runtime, &parsed);
            assert_eq!(response.code(), TPM_RC_COMMAND_CODE, "code {code:#x}");
            assert!(!runtime.manufactured);
            assert!(!runtime.was_manufactured);
            assert!(!runtime.startup_received);
            assert!(!runtime.failure_mode);
            assert!(runtime.power_on && runtime.nv_available);
            assert_eq!(runtime.nv_memory, nv_before);
        }
    }

    #[test]
    fn session_tagged_commands_take_the_same_path() {
        let mut buffer = vec![0x80, 0x02, 0x00, 0x00, 0x00, 0x0e];
        buffer.extend_from_slice(&0x0000_017bu32.to_be_bytes());
        buffer.extend_from_slice(&[0x00; 4]);
        let input = CommandInput::new(buffer.len() as u32, buffer);
        let parsed = parse_command(&input).unwrap();
        let mut runtime = empty_state_runtime();
        let response = dispatch(&mut runtime, &parsed);
        assert_eq!(response.code(), TPM_RC_COMMAND_CODE);
        let bytes = serialize_response(&response).unwrap();
        assert_eq!(&bytes[..2], &TPM_ST_NO_SESSIONS.to_be_bytes());
    }
}
