// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/ExecCommand.c
// - libtpms/src/tpm2/IoBuffers.c
// - libtpms/src/tpm2/Response.c
// - libtpms/src/tpm2/TpmTypes.h
//
// Original upstream authors and copyright notices:
// Written by Ken Goldman
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corp. and others, 2016 - 2023
// (c) Copyright IBM Corp. and others, 2016 - 2018
// (c) Copyright IBM Corp. and others, 2016 - 2024
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use crate::library::CommandInput;
use crate::library::constants::{
    TPM_RC_BAD_TAG, TPM_RC_COMMAND_SIZE, TPM_RC_INSUFFICIENT, TPM_SUCCESS,
};
use crate::library::tpm2::marshal::BlobWriter;
use crate::types::TpmResult;
pub(in crate::library::tpm2) const TPM_ST_NO_SESSIONS: u16 = 0x8001;
pub(in crate::library::tpm2) const TPM_ST_SESSIONS: u16 = 0x8002;

pub(in crate::library::tpm2) const HEADER_SIZE: usize = 10;

#[derive(Debug)]
pub(in crate::library::tpm2) struct Command<'a> {
    pub(in crate::library::tpm2) tag: u16,
    pub(in crate::library::tpm2) command_code: u32,
    pub(in crate::library::tpm2) payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) enum CommandParseError {
    Insufficient,
    BadTag,
    CommandSize,
}

impl CommandParseError {
    pub(in crate::library::tpm2) fn response_code(self) -> TpmResult {
        match self {
            Self::Insufficient => TPM_RC_INSUFFICIENT,
            Self::BadTag => TPM_RC_BAD_TAG,
            Self::CommandSize => TPM_RC_COMMAND_SIZE,
        }
    }
}

#[cfg(test)]
pub(in crate::library::tpm2) fn parse_command(
    input: &CommandInput,
) -> Result<Command<'_>, CommandParseError> {
    parse_command_within(
        input,
        crate::library::tpm2::buffer_size::DEFAULT_BUFFER_SIZE,
    )
}

pub(in crate::library::tpm2) fn parse_command_within(
    input: &CommandInput,
    buffer_size: u32,
) -> Result<Command<'_>, CommandParseError> {
    let (tag_bytes, rest) = input
        .bytes()
        .split_first_chunk::<2>()
        .ok_or(CommandParseError::Insufficient)?;
    let tag = u16::from_be_bytes(*tag_bytes);
    if tag != TPM_ST_NO_SESSIONS && tag != TPM_ST_SESSIONS {
        return Err(CommandParseError::BadTag);
    }

    let (size_bytes, rest) = rest
        .split_first_chunk::<4>()
        .ok_or(CommandParseError::Insufficient)?;
    let declared_size = u32::from_be_bytes(*size_bytes);
    if declared_size != input.received_size() || declared_size > buffer_size {
        return Err(CommandParseError::CommandSize);
    }

    let (code_bytes, payload) = rest
        .split_first_chunk::<4>()
        .ok_or(CommandParseError::Insufficient)?;
    let command_code = u32::from_be_bytes(*code_bytes);

    Ok(Command {
        tag,
        command_code,
        payload,
    })
}

const PARAMETER_SIZE_FIELD: usize = 4;

pub(in crate::library::tpm2) struct Response {
    tag: u16,
    code: TpmResult,
    handles: Vec<u8>,
    parameters: Vec<u8>,
    auth_sessions: Vec<u8>,
}

impl Response {
    pub(in crate::library::tpm2) fn error(code: TpmResult) -> Self {
        debug_assert_ne!(code, TPM_SUCCESS, "error responses carry an error code");
        Self {
            tag: TPM_ST_NO_SESSIONS,
            code,
            handles: Vec::new(),
            parameters: Vec::new(),
            auth_sessions: Vec::new(),
        }
    }

    #[cfg(test)]
    pub(in crate::library::tpm2) fn success(tag: u16, parameters: Vec<u8>) -> Self {
        Self {
            tag,
            code: TPM_SUCCESS,
            handles: Vec::new(),
            parameters,
            auth_sessions: Vec::new(),
        }
    }

    pub(in crate::library::tpm2) fn success_with_handles(
        tag: u16,
        handles: Vec<u8>,
        parameters: Vec<u8>,
    ) -> Self {
        Self {
            tag,
            code: TPM_SUCCESS,
            handles,
            parameters,
            auth_sessions: Vec::new(),
        }
    }

    pub(in crate::library::tpm2) fn success_with_sessions(
        handles: Vec<u8>,
        parameters: Vec<u8>,
        auth_sessions: Vec<u8>,
    ) -> Self {
        Self {
            tag: TPM_ST_SESSIONS,
            code: TPM_SUCCESS,
            handles,
            parameters,
            auth_sessions,
        }
    }

    #[cfg(test)]
    pub(in crate::library::tpm2) fn code(&self) -> TpmResult {
        self.code
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) struct ResponseTooLarge;

fn checked_response_size(
    handles: usize,
    parameter_size_field: usize,
    parameters: usize,
    auth_sessions: usize,
    buffer_size: u32,
) -> Result<u32, ResponseTooLarge> {
    HEADER_SIZE
        .checked_add(handles)
        .and_then(|total| total.checked_add(parameter_size_field))
        .and_then(|total| total.checked_add(parameters))
        .and_then(|total| total.checked_add(auth_sessions))
        .and_then(|total| u32::try_from(total).ok())
        .filter(|total| *total <= buffer_size)
        .ok_or(ResponseTooLarge)
}

#[cfg(test)]
pub(in crate::library::tpm2) fn serialize_response(
    response: &Response,
) -> Result<Vec<u8>, ResponseTooLarge> {
    serialize_response_within(
        response,
        crate::library::tpm2::buffer_size::DEFAULT_BUFFER_SIZE,
    )
}

pub(in crate::library::tpm2) fn serialize_response_within(
    response: &Response,
    buffer_size: u32,
) -> Result<Vec<u8>, ResponseTooLarge> {
    let (tag, handles, parameters, auth_sessions) = if response.code == TPM_SUCCESS {
        (
            response.tag,
            response.handles.as_slice(),
            response.parameters.as_slice(),
            response.auth_sessions.as_slice(),
        )
    } else {
        (TPM_ST_NO_SESSIONS, &[][..], &[][..], &[][..])
    };
    debug_assert!(
        tag == TPM_ST_SESSIONS || auth_sessions.is_empty(),
        "only a TPM_ST_SESSIONS response carries an authorization area"
    );
    let parameter_size_field = if tag == TPM_ST_SESSIONS {
        PARAMETER_SIZE_FIELD
    } else {
        0
    };
    let size = checked_response_size(
        handles.len(),
        parameter_size_field,
        parameters.len(),
        auth_sessions.len(),
        buffer_size,
    )?;
    let mut writer = BlobWriter::with_capacity(size as usize);
    writer.write_u16(tag);
    writer.write_u32(size);
    writer.write_u32(response.code);
    writer.write_bytes(handles);
    if parameter_size_field != 0 {
        writer.write_u32(u32::try_from(parameters.len()).map_err(|_| ResponseTooLarge)?);
    }
    writer.write_bytes(parameters);
    writer.write_bytes(auth_sessions);
    Ok(writer.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::constants::TPM_RC_COMMAND_CODE;
    use crate::library::tpm2::buffer_size::{DEFAULT_BUFFER_SIZE, MIN_BUFFER_SIZE};
    use crate::library::tpm2::command::core::test_support::{for_each_mutation, prefix_bit_flips};

    const MAX_RESPONSE_SIZE: usize = DEFAULT_BUFFER_SIZE as usize;

    fn command_bytes(tag: u16, size: u32, code: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&tag.to_be_bytes());
        out.extend_from_slice(&size.to_be_bytes());
        out.extend_from_slice(&code.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn received(buffer: &[u8]) -> CommandInput {
        let received_size = buffer.len() as u32;
        let prefix_len = CommandInput::required_prefix_len(received_size);
        CommandInput::new(received_size, buffer[..prefix_len].to_vec())
    }

    fn oversized_received(received_size: u32, prefix: &[u8; 6]) -> CommandInput {
        assert!(CommandInput::required_prefix_len(received_size) == 6);
        CommandInput::new(received_size, prefix.to_vec())
    }

    fn tag_and_size_prefix(tag: u16, size: u32) -> [u8; 6] {
        let mut out = [0u8; 6];
        out[..2].copy_from_slice(&tag.to_be_bytes());
        out[2..].copy_from_slice(&size.to_be_bytes());
        out
    }

    #[test]
    fn valid_header_only_command_parse_success() {
        let input = received(&command_bytes(TPM_ST_NO_SESSIONS, 10, 0x0000_0144, &[]));
        let command = parse_command(&input).expect("a bare header is a valid command");
        assert_eq!(command.tag, 0x8001);
        assert_eq!(command.command_code, 0x144);
        assert!(command.payload.is_empty());
    }

    #[test]
    fn valid_payload_command_parse_and_borrow() {
        let input = received(&command_bytes(
            TPM_ST_SESSIONS,
            14,
            0x0000_017b,
            &[0xde, 0xad, 0xbe, 0xef],
        ));
        let command = parse_command(&input).unwrap();
        assert_eq!(command.tag, 0x8002);
        assert_eq!(command.command_code, 0x17b);
        assert_eq!(command.payload, &[0xde, 0xad, 0xbe, 0xef]);
        assert!(
            core::ptr::eq(command.payload.as_ptr(), input.bytes()[10..].as_ptr()),
            "the payload borrows from the owned command input without copying"
        );
    }

    #[test]
    fn integer_big_endian_decoding() {
        let input = received(&[0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x12, 0x34, 0x56, 0x78]);
        let command = parse_command(&input).unwrap();
        assert_eq!(command.tag, 0x8001);
        assert_eq!(command.command_code, 0x1234_5678);
    }

    #[test]
    fn valid_header_strict_prefix_rejection() {
        let buffer = command_bytes(TPM_ST_NO_SESSIONS, 10, 0x0000_0144, &[]);
        for len in 0..buffer.len() {
            let error = parse_command(&received(&buffer[..len])).unwrap_err();
            let expected = if len < 6 {
                CommandParseError::Insufficient
            } else {
                CommandParseError::CommandSize
            };
            assert_eq!(error, expected, "prefix of {len} bytes");
        }
    }

    #[test]
    fn declared_size_below_header_rejection() {
        for size in 6..10u32 {
            let mut buffer = command_bytes(TPM_ST_NO_SESSIONS, size, 0, &[]);
            buffer.truncate(size as usize);
            assert_eq!(
                parse_command(&received(&buffer)).unwrap_err(),
                CommandParseError::Insufficient,
                "declared size {size} with matching length"
            );
        }
        for size in 0..6u32 {
            let buffer = &command_bytes(TPM_ST_NO_SESSIONS, size, 0, &[])[..6];
            assert_eq!(
                parse_command(&received(buffer)).unwrap_err(),
                CommandParseError::CommandSize,
                "declared size {size} with 6 received bytes"
            );
        }
    }

    #[test]
    fn declared_size_above_input_rejection() {
        let input = received(&command_bytes(TPM_ST_NO_SESSIONS, 11, 0x144, &[]));
        assert_eq!(
            parse_command(&input).unwrap_err(),
            CommandParseError::CommandSize
        );
    }

    #[test]
    fn trailing_bytes_rejection_c_match() {
        let input = received(&command_bytes(TPM_ST_NO_SESSIONS, 10, 0x144, &[0x00, 0x00]));
        assert_eq!(
            parse_command(&input).unwrap_err(),
            CommandParseError::CommandSize
        );
    }

    #[test]
    fn invalid_tag_rejection() {
        for tag in [0x0000, 0x0001, 0x8000, 0x8003, 0xffff] {
            let input = received(&command_bytes(tag, 10, 0x144, &[]));
            assert_eq!(
                parse_command(&input).unwrap_err(),
                CommandParseError::BadTag,
                "tag {tag:#06x}"
            );
        }
    }

    #[test]
    fn invalid_tag_oversized_size_precedence() {
        for received_size in [4097u32, 100_000, u32::MAX] {
            let input = oversized_received(received_size, &tag_and_size_prefix(0x1234, 10));
            assert_eq!(
                parse_command(&input).unwrap_err(),
                CommandParseError::BadTag,
                "received size {received_size}"
            );
        }
    }

    #[test]
    fn oversized_received_size_valid_tag_command_size_error() {
        for received_size in [4097u32, 100_000, i32::MAX as u32 + 1, u32::MAX] {
            for declared in [received_size, 10] {
                let input = oversized_received(
                    received_size,
                    &tag_and_size_prefix(TPM_ST_NO_SESSIONS, declared),
                );
                assert_eq!(
                    parse_command(&input).unwrap_err(),
                    CommandParseError::CommandSize,
                    "received {received_size}, declared {declared}"
                );
            }
        }
    }

    #[test]
    fn extreme_declared_size_rejection() {
        for size in [u32::MAX, i32::MAX as u32 + 1, 0x0001_0000] {
            let input = received(&command_bytes(TPM_ST_NO_SESSIONS, size, 0x144, &[]));
            assert_eq!(
                parse_command(&input).unwrap_err(),
                CommandParseError::CommandSize,
                "declared size {size:#x}"
            );
        }
    }

    #[test]
    fn command_buffer_limit_exactness() {
        let max = command_bytes(TPM_ST_NO_SESSIONS, 4096, 0x144, &[0u8; 4086]);
        let input = received(&max);
        let command = parse_command(&input).expect("TPM_BUFFER_MAX bytes are accepted");
        assert_eq!(command.payload.len(), 4086);

        let over = command_bytes(TPM_ST_NO_SESSIONS, 4097, 0x144, &[0u8; 4087]);
        assert_eq!(
            parse_command(&received(&over)).unwrap_err(),
            CommandParseError::CommandSize
        );
    }

    #[test]
    fn header_prefix_and_bit_flip_panic_safety() {
        let valid = command_bytes(TPM_ST_SESSIONS, 14, 0x144, &[1, 2, 3, 4]);
        for_each_mutation(
            "command header",
            prefix_bit_flips(&valid, 0, 0, false),
            |bytes| {
                let _ = parse_command(&received(&bytes));
            },
        );
    }

    #[test]
    fn error_code_c_response_code_mapping() {
        assert_eq!(CommandParseError::Insufficient.response_code(), 0x9a);
        assert_eq!(CommandParseError::BadTag.response_code(), 0x1e);
        assert_eq!(CommandParseError::CommandSize.response_code(), 0x142);
    }

    #[test]
    fn empty_success_response_ten_bytes() {
        let bytes = serialize_response(&Response::success(TPM_ST_NO_SESSIONS, Vec::new())).unwrap();
        assert_eq!(
            bytes,
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn unsupported_command_response_c_parity() {
        let bytes = serialize_response(&Response::error(TPM_RC_COMMAND_CODE)).unwrap();
        assert_eq!(
            bytes,
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x43]
        );
    }

    #[test]
    fn response_field_big_endian_encoding() {
        let bytes = serialize_response(&Response::error(0x0102_0304)).unwrap();
        assert_eq!(&bytes[..2], &[0x80, 0x01]);
        assert_eq!(&bytes[2..6], &[0x00, 0x00, 0x00, 0x0a]);
        assert_eq!(&bytes[6..], &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn sessionless_success_response_parameter_size_omission() {
        let bytes = serialize_response(&Response::success(
            TPM_ST_NO_SESSIONS,
            vec![0xaa, 0xbb, 0xcc],
        ))
        .unwrap();
        assert_eq!(bytes.len(), 13);
        assert_eq!(&bytes[..2], &[0x80, 0x01]);
        assert_eq!(&bytes[2..6], &[0x00, 0x00, 0x00, 0x0d]);
        assert_eq!(&bytes[6..10], &[0x00, 0x00, 0x00, 0x00]);
        assert_eq!(&bytes[10..], &[0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn empty_parameter_sessions_response_well_formed() {
        let bytes = serialize_response(&Response::success(TPM_ST_SESSIONS, Vec::new())).unwrap();
        assert_eq!(
            bytes,
            [
                0x80, 0x02, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ],
            "tag | size(14) | code | parameterSize(0), empty auth area"
        );
    }

    #[test]
    fn sessions_response_parameter_size_count_and_placement() {
        let bytes = serialize_response(&Response::success(TPM_ST_SESSIONS, vec![0xaa, 0xbb, 0xcc]))
            .unwrap();
        assert_eq!(bytes.len(), 17);
        assert_eq!(&bytes[..2], &[0x80, 0x02], "the command tag is echoed");
        assert_eq!(
            &bytes[2..6],
            &[0x00, 0x00, 0x00, 0x11],
            "responseSize covers header, parameterSize and parameters"
        );
        assert_eq!(&bytes[6..10], &[0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            &bytes[10..14],
            &[0x00, 0x00, 0x00, 0x03],
            "big-endian parameterSize between the code and the parameters"
        );
        assert_eq!(&bytes[14..], &[0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn response_buffer_limit_boundary() {
        let max = MAX_RESPONSE_SIZE - HEADER_SIZE;
        let bytes =
            serialize_response(&Response::success(TPM_ST_NO_SESSIONS, vec![0u8; max])).unwrap();
        assert_eq!(bytes.len(), MAX_RESPONSE_SIZE);
        assert_eq!(
            serialize_response(&Response::success(TPM_ST_NO_SESSIONS, vec![0u8; max + 1])),
            Err(ResponseTooLarge)
        );

        let max = MAX_RESPONSE_SIZE - HEADER_SIZE - PARAMETER_SIZE_FIELD;
        let bytes =
            serialize_response(&Response::success(TPM_ST_SESSIONS, vec![0u8; max])).unwrap();
        assert_eq!(bytes.len(), MAX_RESPONSE_SIZE);
        assert_eq!(
            serialize_response(&Response::success(TPM_ST_SESSIONS, vec![0u8; max + 1])),
            Err(ResponseTooLarge)
        );
    }

    #[test]
    fn oversized_response_computation_overflow_safety() {
        assert_eq!(
            checked_response_size(0, 0, usize::MAX, 0, DEFAULT_BUFFER_SIZE),
            Err(ResponseTooLarge)
        );
        assert_eq!(
            checked_response_size(
                0,
                PARAMETER_SIZE_FIELD,
                usize::MAX - 4,
                usize::MAX,
                DEFAULT_BUFFER_SIZE
            ),
            Err(ResponseTooLarge)
        );
        assert_eq!(
            checked_response_size(
                0,
                0,
                MAX_RESPONSE_SIZE - HEADER_SIZE,
                0,
                DEFAULT_BUFFER_SIZE
            ),
            Ok(MAX_RESPONSE_SIZE as u32)
        );
    }

    #[test]
    fn configured_buffer_size_command_limit() {
        let at_limit = command_bytes(
            TPM_ST_NO_SESSIONS,
            MIN_BUFFER_SIZE,
            0x144,
            &vec![0u8; MIN_BUFFER_SIZE as usize - HEADER_SIZE],
        );
        let input = received(&at_limit);
        let command = parse_command_within(&input, MIN_BUFFER_SIZE)
            .expect("a command of exactly the configured size is accepted");
        assert_eq!(
            command.payload.len(),
            MIN_BUFFER_SIZE as usize - HEADER_SIZE
        );

        let over = command_bytes(
            TPM_ST_NO_SESSIONS,
            MIN_BUFFER_SIZE + 1,
            0x144,
            &vec![0u8; MIN_BUFFER_SIZE as usize + 1 - HEADER_SIZE],
        );
        assert_eq!(
            parse_command_within(&received(&over), MIN_BUFFER_SIZE).unwrap_err(),
            CommandParseError::CommandSize
        );
        assert!(
            parse_command_within(&received(&over), DEFAULT_BUFFER_SIZE).is_ok(),
            "the same command fits the default buffer size"
        );
    }

    #[test]
    fn configured_buffer_size_response_limit() {
        let max = MIN_BUFFER_SIZE as usize - HEADER_SIZE;
        let bytes = serialize_response_within(
            &Response::success(TPM_ST_NO_SESSIONS, vec![0u8; max]),
            MIN_BUFFER_SIZE,
        )
        .unwrap();
        assert_eq!(bytes.len(), MIN_BUFFER_SIZE as usize);
        assert_eq!(&bytes[2..6], &MIN_BUFFER_SIZE.to_be_bytes());

        let over = Response::success(TPM_ST_NO_SESSIONS, vec![0u8; max + 1]);
        assert_eq!(
            serialize_response_within(&over, MIN_BUFFER_SIZE),
            Err(ResponseTooLarge)
        );
        assert_eq!(
            serialize_response_within(&over, DEFAULT_BUFFER_SIZE)
                .unwrap()
                .len(),
            MIN_BUFFER_SIZE as usize + 1,
            "the same response fits the default buffer size"
        );

        let max = MIN_BUFFER_SIZE as usize - HEADER_SIZE - PARAMETER_SIZE_FIELD;
        assert_eq!(
            serialize_response_within(
                &Response::success(TPM_ST_SESSIONS, vec![0u8; max]),
                MIN_BUFFER_SIZE
            )
            .unwrap()
            .len(),
            MIN_BUFFER_SIZE as usize,
            "the session-tagged parameterSize field counts against the limit"
        );
        assert_eq!(
            serialize_response_within(
                &Response::success(TPM_ST_SESSIONS, vec![0u8; max + 1]),
                MIN_BUFFER_SIZE
            ),
            Err(ResponseTooLarge)
        );
    }

    #[test]
    fn error_response_no_sessions_tag_enforcement() {
        let smuggled = Response {
            tag: TPM_ST_SESSIONS,
            code: TPM_RC_COMMAND_CODE,
            handles: vec![0x80, 0x00, 0x00, 0x00],
            parameters: vec![0xff; 4],
            auth_sessions: Vec::new(),
        };
        let bytes = serialize_response(&smuggled).unwrap();
        assert_eq!(
            bytes,
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x43]
        );
    }
}
