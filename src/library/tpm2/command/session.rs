use crate::ffi_types::TpmResult;
use crate::library::constants::{
    TPM_RC_ATTRIBUTES, TPM_RC_HANDLE, TPM_RC_INSUFFICIENT, TPM_RC_NONCE, TPM_RC_REFERENCE_S0,
    TPM_RC_RESERVED_BITS, TPM_RC_SIZE, TPM_RC_VALUE,
};

use super::super::marshal::{BlobReader, Tpm2bError};
use super::super::state::MAX_ACTIVE_SESSIONS;
use super::header::{Command, TPM_ST_SESSIONS};

const TPM_RC_S: TpmResult = 0x800;
const TPM_RC_1: TpmResult = 0x100;

const MAX_SESSION_NUM: u32 = 3;
pub(super) const TPM_RS_PW: u32 = 0x4000_0009;
pub(super) const HMAC_SESSION_FIRST: u32 = 0x0200_0000;
pub(super) const POLICY_SESSION_FIRST: u32 = 0x0300_0000;
const SESSION_TPM2B_MAX: usize = 64;
const TPMA_SESSION_RESERVED: u8 = 0x18;
const TPMA_SESSION_PW_FORBIDDEN: u8 = 0xe6;

pub(super) fn check_session_area<'a>(command: &Command<'a>) -> Result<&'a [u8], TpmResult> {
    if command.tag != TPM_ST_SESSIONS {
        return Ok(command.payload);
    }
    let (size_bytes, rest) = command
        .payload
        .split_first_chunk::<4>()
        .ok_or(TPM_RC_INSUFFICIENT)?;
    let auth_size = u32::from_be_bytes(*size_bytes) as usize;
    if auth_size < 9 || auth_size > rest.len() {
        return Err(TPM_RC_SIZE);
    }
    parse_session_area(&rest[..auth_size])?;
    Err(TPM_RC_HANDLE + TPM_RC_S + TPM_RC_1)
}

fn session_handle_in_range(handle: u32) -> bool {
    let sessions = MAX_ACTIVE_SESSIONS as u32;
    (HMAC_SESSION_FIRST..HMAC_SESSION_FIRST + sessions).contains(&handle)
        || (POLICY_SESSION_FIRST..POLICY_SESSION_FIRST + sessions).contains(&handle)
}

fn read_session_tpm2b(
    reader: &mut BlobReader<'_>,
    error_index: TpmResult,
) -> Result<usize, TpmResult> {
    match reader.read_tpm2b(SESSION_TPM2B_MAX) {
        Ok(bytes) => Ok(bytes.len()),
        Err(Tpm2bError::Truncated) => Err(TPM_RC_INSUFFICIENT + error_index),
        Err(Tpm2bError::SizeExceeded { .. }) => Err(TPM_RC_SIZE + error_index),
    }
}

fn parse_session_area(auth_area: &[u8]) -> Result<(), TpmResult> {
    let mut reader = BlobReader::new(auth_area);
    let mut index: u32 = 0;
    while !reader.remaining().is_empty() {
        let error_index = TPM_RC_S + TPM_RC_1 * (index + 1);
        if index == MAX_SESSION_NUM {
            return Err(TPM_RC_SIZE + error_index);
        }
        let handle = reader
            .read_u32()
            .map_err(|_| TPM_RC_INSUFFICIENT + error_index)?;
        if handle != TPM_RS_PW && !session_handle_in_range(handle) {
            return Err(TPM_RC_VALUE + error_index);
        }
        let nonce_len = read_session_tpm2b(&mut reader, error_index)?;
        let attributes = reader
            .read_u8()
            .map_err(|_| TPM_RC_INSUFFICIENT + error_index)?;
        if attributes & TPMA_SESSION_RESERVED != 0 {
            return Err(TPM_RC_RESERVED_BITS + error_index);
        }
        read_session_tpm2b(&mut reader, error_index)?;
        if handle != TPM_RS_PW {
            return Err(TPM_RC_REFERENCE_S0 + index);
        }
        if attributes & TPMA_SESSION_PW_FORBIDDEN != 0 {
            return Err(TPM_RC_ATTRIBUTES + error_index);
        }
        if nonce_len != 0 {
            return Err(TPM_RC_NONCE + error_index);
        }
        index += 1;
    }
    Ok(())
}
