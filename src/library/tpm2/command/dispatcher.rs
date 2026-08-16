use crate::ffi_types::TpmResult;
use crate::library::constants::{
    TPM_RC_AUTH_CONTEXT, TPM_RC_AUTH_MISSING, TPM_RC_COMMAND_CODE, TPM_RC_HIERARCHY,
    TPM_RC_INITIALIZE, TPM_RC_INSUFFICIENT, TPM_RC_SIZE, TPM_RC_VALUE,
};

use super::super::marshal::BlobReader;
use super::super::object_create::hierarchy_is_enabled;
use super::super::runtime::Tpm2Runtime;
use super::header::{Command, Response, TPM_ST_NO_SESSIONS, TPM_ST_SESSIONS};
use super::registry::{self, CommandDescriptor, HandleKind};
use super::session::{authorize_sessions, parse_session_area, password_auth_response};

const TPM_RC_H: TpmResult = 0x000;
const TPM_RC_1: TpmResult = 0x100;

const MIN_AUTH_AREA_SIZE: usize = 9;

pub(super) struct CommandFrame<'a> {
    pub(super) handles: Vec<u32>,
    pub(super) parameters: &'a [u8],
}

pub(in crate::library::tpm2) fn dispatch(
    runtime: &mut Tpm2Runtime,
    command: &Command<'_>,
) -> Response {
    let Some(descriptor) = registry::find(command.command_code) else {
        return Response::error(TPM_RC_COMMAND_CODE);
    };
    if !descriptor.lifecycle.allows(runtime) {
        return Response::error(TPM_RC_INITIALIZE);
    }
    match run(runtime, descriptor, command) {
        Ok(response) => response,
        Err(code) => Response::error(code),
    }
}

fn run(
    runtime: &mut Tpm2Runtime,
    descriptor: &CommandDescriptor,
    command: &Command<'_>,
) -> Result<Response, TpmResult> {
    let (handles, rest) = parse_handles(descriptor, command.payload)?;
    check_load_status(runtime, descriptor, &handles)?;
    let (session_count, parameters) =
        check_authorization(runtime, descriptor, command, &handles, rest)?;
    let frame = CommandFrame {
        handles,
        parameters,
    };
    let (handles, parameters) = (descriptor.handler)(runtime, &frame)?.into_parts();
    Ok(if command.tag == TPM_ST_SESSIONS {
        Response::success_with_sessions(handles, parameters, password_auth_response(session_count))
    } else {
        Response::success_with_handles(TPM_ST_NO_SESSIONS, handles, parameters)
    })
}

fn parse_handles<'a>(
    descriptor: &CommandDescriptor,
    payload: &'a [u8],
) -> Result<(Vec<u32>, &'a [u8]), TpmResult> {
    let mut reader = BlobReader::new(payload);
    let mut handles = Vec::with_capacity(descriptor.handles.len());
    for (index, spec) in descriptor.handles.iter().enumerate() {
        let error_index = TPM_RC_H + TPM_RC_1 * (index as u32 + 1);
        let handle = reader
            .read_u32()
            .map_err(|_| TPM_RC_INSUFFICIENT + error_index)?;
        if !spec.kind.accepts(handle) {
            return Err(TPM_RC_VALUE + error_index);
        }
        handles.push(handle);
    }
    Ok((handles, reader.remaining()))
}

fn check_load_status(
    runtime: &Tpm2Runtime,
    descriptor: &CommandDescriptor,
    handles: &[u32],
) -> Result<(), TpmResult> {
    for (index, spec) in descriptor.handles.iter().enumerate() {
        if !matches!(spec.kind, HandleKind::Hierarchy) {
            continue;
        }
        let Some(&handle) = handles.get(index) else {
            continue;
        };
        if !hierarchy_is_enabled(runtime, handle) {
            return Err(TPM_RC_HIERARCHY + TPM_RC_H + TPM_RC_1 * (index as u32 + 1));
        }
    }
    Ok(())
}

fn check_authorization<'a>(
    runtime: &mut Tpm2Runtime,
    descriptor: &CommandDescriptor,
    command: &Command<'_>,
    handles: &[u32],
    rest: &'a [u8],
) -> Result<(usize, &'a [u8]), TpmResult> {
    if command.tag != TPM_ST_SESSIONS {
        if descriptor.handles.iter().any(|spec| spec.user_auth) {
            return Err(TPM_RC_AUTH_MISSING);
        }
        return Ok((0, rest));
    }
    let (size_bytes, after_size) = rest.split_first_chunk::<4>().ok_or(TPM_RC_INSUFFICIENT)?;
    let auth_size = u32::from_be_bytes(*size_bytes) as usize;
    if auth_size < MIN_AUTH_AREA_SIZE || auth_size > after_size.len() {
        return Err(TPM_RC_SIZE);
    }
    if !descriptor.sessions_allowed {
        return Err(TPM_RC_AUTH_CONTEXT);
    }
    let sessions = parse_session_area(&after_size[..auth_size])?;
    authorize_sessions(runtime, descriptor, handles, &sessions)?;
    Ok((sessions.len(), &after_size[auth_size..]))
}

#[cfg(test)]
mod tests {
    use super::super::header::{parse_command, serialize_response};
    use super::super::registry::{TPM_CC_PCR_EXTEND, TPM_CC_SHUTDOWN, TPM_CC_STARTUP};
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

    #[track_caller]
    fn started_dispatch(bytes: &[u8]) -> u32 {
        let mut runtime = empty_state_runtime();
        runtime.startup_received = true;
        let input = CommandInput::new(bytes.len() as u32, bytes.to_vec());
        let parsed = parse_command(&input).expect("the header parses");
        dispatch(&mut runtime, &parsed).code()
    }

    fn framed(tag: u16, code: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = tag.to_be_bytes().to_vec();
        out.extend_from_slice(&(10 + payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&code.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    const HANDLE1_INSUFFICIENT: u32 = 0x19a;
    const HANDLE1_VALUE: u32 = 0x184;
    const SESSION1_HANDLE: u32 = 0x98b;
    const AUTH_MISSING: u32 = 0x125;
    const INSUFFICIENT: u32 = 0x09a;
    const SIZE: u32 = 0x095;

    #[test]
    fn unknown_command_code_answers_command_code() {
        assert_eq!(dispatch_code(0x2000_0000).code(), TPM_RC_COMMAND_CODE);
    }

    #[test]
    fn known_but_unimplemented_command_answers_command_code() {
        assert_eq!(dispatch_code(0x0000_017c).code(), TPM_RC_COMMAND_CODE);
    }

    #[test]
    fn startup_routes_to_the_startup_handler() {
        use crate::library::constants::TPM_RC_FAILURE;
        let mut runtime = empty_state_runtime();
        let bytes = framed(0x8001, TPM_CC_STARTUP, &[0x00, 0x00]);
        let input = CommandInput::new(bytes.len() as u32, bytes);
        let parsed = parse_command(&input).unwrap();
        assert_eq!(dispatch(&mut runtime, &parsed).code(), TPM_RC_FAILURE);
    }

    #[test]
    fn started_tpm_rejects_startup_before_parsing_its_payload() {
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
        let bytes = framed(0x8001, TPM_CC_SHUTDOWN, &[0x00, 0x00]);
        assert_eq!(started_dispatch(&bytes), TPM_RC_FAILURE);
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
        for code in [0x2000_0000, 0x0000_017c, 0xffff_ffff, 0x0000_0000] {
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
        let bytes = framed(0x8002, 0x0000_017c, &[0x00; 4]);
        let input = CommandInput::new(bytes.len() as u32, bytes);
        let parsed = parse_command(&input).unwrap();
        let mut runtime = empty_state_runtime();
        let response = dispatch(&mut runtime, &parsed);
        assert_eq!(response.code(), TPM_RC_COMMAND_CODE);
        let bytes = serialize_response(&response).unwrap();
        assert_eq!(&bytes[..2], &TPM_ST_NO_SESSIONS.to_be_bytes());
    }

    #[test]
    fn handles_are_extracted_before_the_authorization_size() {
        for payload in [&[][..], &[0x00][..], &[0x00, 0x00, 0x00][..]] {
            assert_eq!(
                started_dispatch(&framed(0x8002, TPM_CC_PCR_EXTEND, payload)),
                HANDLE1_INSUFFICIENT,
                "the handle is unmarshaled before authorizationSize, payload {payload:02x?}"
            );
        }
    }

    #[test]
    fn an_invalid_first_handle_is_reported_before_the_authorization_area() {
        let mut payload = 0x0000_0018u32.to_be_bytes().to_vec();
        payload.extend_from_slice(&0x20u32.to_be_bytes());
        assert_eq!(
            started_dispatch(&framed(0x8002, TPM_CC_PCR_EXTEND, &payload)),
            HANDLE1_VALUE,
            "an oversized authorizationSize never masks the handle error"
        );
    }

    #[test]
    fn commands_without_handles_keep_their_authorization_layout() {
        let mut payload = 0x09u32.to_be_bytes().to_vec();
        payload.extend_from_slice(&[0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00]);
        payload.extend_from_slice(&[0x00; 12]);
        assert_eq!(
            started_dispatch(&framed(0x8002, 0x0000_017a, &payload)),
            SESSION1_HANDLE,
            "GetCapability's payload still starts at authorizationSize, and its \
             session has no handle to authorize"
        );
    }

    #[test]
    fn a_missing_authorization_size_is_insufficient() {
        let payload = 0x0000_000au32.to_be_bytes().to_vec();
        assert_eq!(
            started_dispatch(&framed(0x8002, TPM_CC_PCR_EXTEND, &payload)),
            INSUFFICIENT
        );
        for extra in 1..4usize {
            let mut short = payload.clone();
            short.extend_from_slice(&vec![0u8; extra]);
            assert_eq!(
                started_dispatch(&framed(0x8002, TPM_CC_PCR_EXTEND, &short)),
                INSUFFICIENT,
                "{extra} of 4 authorizationSize bytes"
            );
        }
    }

    #[test]
    fn an_authorization_size_below_the_minimum_is_a_size_error() {
        for auth_size in 0..9u32 {
            let mut payload = 0x0000_000au32.to_be_bytes().to_vec();
            payload.extend_from_slice(&auth_size.to_be_bytes());
            payload.extend_from_slice(&[0x00; 16]);
            assert_eq!(
                started_dispatch(&framed(0x8002, TPM_CC_PCR_EXTEND, &payload)),
                SIZE,
                "authorizationSize {auth_size}"
            );
        }
    }

    #[test]
    fn an_authorization_size_beyond_the_command_is_a_size_error() {
        for auth_size in [10u32, 0x20, 0x1000, u32::MAX] {
            let mut payload = 0x0000_000au32.to_be_bytes().to_vec();
            payload.extend_from_slice(&auth_size.to_be_bytes());
            payload.extend_from_slice(&[0x00; 9]);
            assert_eq!(
                started_dispatch(&framed(0x8002, TPM_CC_PCR_EXTEND, &payload)),
                SIZE,
                "authorizationSize {auth_size}"
            );
        }
    }

    #[test]
    fn a_command_without_sessions_that_needs_authorization_is_auth_missing() {
        let mut payload = 0x0000_000au32.to_be_bytes().to_vec();
        payload.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(
            started_dispatch(&framed(0x8001, TPM_CC_PCR_EXTEND, &payload)),
            AUTH_MISSING
        );
    }

    #[test]
    fn malformed_framing_never_panics() {
        let mut valid = 0x0000_000au32.to_be_bytes().to_vec();
        valid.extend_from_slice(&0x09u32.to_be_bytes());
        valid.extend_from_slice(&[0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00]);
        valid.extend_from_slice(&0u32.to_be_bytes());
        for len in 0..=valid.len() {
            for index in 0..len {
                for flip in [0x01u8, 0x80, 0xff] {
                    let mut mutated = valid[..len].to_vec();
                    mutated[index] ^= flip;
                    for tag in [0x8001u16, 0x8002] {
                        let bytes = framed(tag, TPM_CC_PCR_EXTEND, &mutated);
                        let input = CommandInput::new(bytes.len() as u32, bytes);
                        let parsed = parse_command(&input).expect("the header parses");
                        let mut runtime = empty_state_runtime();
                        runtime.startup_received = true;
                        let _ = serialize_response(&dispatch(&mut runtime, &parsed));
                    }
                }
            }
        }
    }
}
