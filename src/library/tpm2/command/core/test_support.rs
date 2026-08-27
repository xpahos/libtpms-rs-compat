use super::dispatcher::dispatch;
use super::header::{parse_command, serialize_response};
use crate::ffi_types::TpmResult;
use crate::library::CommandInput;
use crate::library::tpm2::command::session::processing::TPM_RS_PW;
use crate::library::tpm2::manufacture::manufacture_state;
use crate::library::tpm2::profile::validate_user_profile;
use crate::library::tpm2::runtime::{Tpm2Runtime, commit_manufactured_state};

pub(in crate::library::tpm2::command) const TPM_ALG_SHA1: u16 = 0x0004;
pub(in crate::library::tpm2::command) const TPM_ALG_SHA256: u16 = 0x000b;

pub(in crate::library::tpm2::command) const RC_SUCCESS: u32 = 0x000;

fn deterministic_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
    let len = buffer.len() as u8;
    for (index, byte) in buffer.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_add(len) ^ 0x55;
    }
    Ok(())
}

pub(in crate::library::tpm2::command) fn manufactured_runtime() -> Box<Tpm2Runtime> {
    let profile = validate_user_profile(None).expect("the null profile validates");
    let state = manufacture_state(profile, deterministic_entropy).expect("manufactures");
    let mut runtime = commit_manufactured_state(state).expect("commits");
    runtime.entropy = deterministic_entropy;
    runtime
}

#[track_caller]
pub(in crate::library::tpm2::command) fn started_runtime() -> Box<Tpm2Runtime> {
    let mut runtime = manufactured_runtime();
    let startup = framed(0x0000_0144, &[0x00, 0x00], false);
    assert_eq!(
        response_code(&dispatch_bytes(&mut runtime, &startup)),
        RC_SUCCESS,
        "the TPM starts up"
    );
    runtime.nv_update_pending = false;
    runtime
}

#[track_caller]
pub(in crate::library::tpm2::command) fn dispatch_bytes(
    runtime: &mut Tpm2Runtime,
    bytes: &[u8],
) -> Vec<u8> {
    let input = CommandInput::new(bytes.len() as u32, bytes.to_vec());
    let parsed = parse_command(&input).expect("the header parses");
    serialize_response(&dispatch(runtime, &parsed)).expect("the response serializes")
}

pub(in crate::library::tpm2::command) fn framed(
    code: u32,
    payload: &[u8],
    sessions: bool,
) -> Vec<u8> {
    let tag: u16 = if sessions { 0x8002 } else { 0x8001 };
    let mut out = tag.to_be_bytes().to_vec();
    out.extend_from_slice(&(10 + payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

pub(in crate::library::tpm2::command) fn pw_session(password: &[u8]) -> Vec<u8> {
    let mut out = TPM_RS_PW.to_be_bytes().to_vec();
    out.extend_from_slice(&0u16.to_be_bytes());
    out.push(0x00);
    out.extend_from_slice(&(password.len() as u16).to_be_bytes());
    out.extend_from_slice(password);
    out
}

pub(in crate::library::tpm2::command) fn command(
    code: u32,
    handles: &[u32],
    passwords: &[&[u8]],
    parameters: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::new();
    for handle in handles {
        payload.extend_from_slice(&handle.to_be_bytes());
    }
    if !passwords.is_empty() {
        let mut area = Vec::new();
        for password in passwords {
            area.extend_from_slice(&pw_session(password));
        }
        payload.extend_from_slice(&(area.len() as u32).to_be_bytes());
        payload.extend_from_slice(&area);
    }
    payload.extend_from_slice(parameters);
    framed(code, &payload, !passwords.is_empty())
}

pub(in crate::library::tpm2::command) fn response_code(response: &[u8]) -> u32 {
    u32::from_be_bytes(response[6..10].try_into().expect("a response code"))
}

pub(in crate::library::tpm2::command) fn response_parameters(response: &[u8]) -> Vec<u8> {
    if response[..2] != [0x80, 0x02] {
        return response[10..].to_vec();
    }
    let size = u32::from_be_bytes(response[10..14].try_into().expect("a parameter size"));
    response[14..14 + size as usize].to_vec()
}

pub(in crate::library::tpm2::command) fn error_response(code: u32) -> Vec<u8> {
    let mut out = vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0a];
    out.extend_from_slice(&code.to_be_bytes());
    out
}
