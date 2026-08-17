use crate::ffi_types::TpmResult;
use crate::library::constants::{TPM_RC_NV_RANGE, TPM_RC_SIZE, TPM_RC_VALUE};

use super::super::marshal::BlobWriter;
use super::super::nv::{marshal_sized_nv_public, nv_index_name, read_index_data};
use super::super::runtime::Tpm2Runtime;
use super::super::template::TemplateReader;
use super::dispatcher::CommandFrame;
use super::nv_common::{
    MAX_NV_BUFFER_SIZE, TPM_RC_1, TPM_RC_2, TPM_RC_P, handle_at, read_access_checks, resolve,
};
use super::output::CommandOutput;

const RC_SIZE_PARAM: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_OFFSET_PARAM: TpmResult = TPM_RC_P + TPM_RC_2;

pub(super) fn execute_read(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let auth_handle = handle_at(frame, 0)?;
    let nv_handle = handle_at(frame, 1)?;
    let (size, offset) = parse_read_parameters(frame.parameters)?;

    let resolved = resolve(runtime, nv_handle)?;
    read_access_checks(auth_handle, nv_handle, resolved.attributes())?;

    if usize::from(size) > MAX_NV_BUFFER_SIZE {
        return Err(TPM_RC_VALUE + RC_SIZE_PARAM);
    }
    let data_size = resolved.public.data_size;
    if offset > data_size {
        return Err(TPM_RC_VALUE + RC_OFFSET_PARAM);
    }
    if size > data_size - offset {
        return Err(TPM_RC_NV_RANGE);
    }

    let data = read_index_data(runtime, &resolved, usize::from(offset), usize::from(size))?;
    let mut writer = BlobWriter::with_capacity(2 + data.len());
    writer.write_u16(size);
    writer.write_bytes(&data);
    Ok(CommandOutput::from_parameters(writer.into_bytes()))
}

pub(super) fn execute_read_public(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let nv_handle = handle_at(frame, 0)?;
    if !frame.parameters.is_empty() {
        return Err(TPM_RC_SIZE);
    }

    let resolved = resolve(runtime, nv_handle)?;
    let name = nv_index_name(&resolved.public)?;

    let mut out = marshal_sized_nv_public(&resolved.public);
    out.extend_from_slice(&(name.len() as u16).to_be_bytes());
    out.extend_from_slice(&name);
    Ok(CommandOutput::from_parameters(out))
}

fn parse_read_parameters(parameters: &[u8]) -> Result<(u16, u16), TpmResult> {
    let mut reader = TemplateReader::new(parameters);
    let size = reader.u16().map_err(|code| code + RC_SIZE_PARAM)?;
    let offset = reader.u16().map_err(|code| code + RC_OFFSET_PARAM)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok((size, offset))
}

#[cfg(test)]
mod tests {
    use super::super::nv_common::harness::*;
    use super::super::registry::{
        CommandLifecycle, HandleKind, NvAccess, TPM_CC_NV_READ, TPM_CC_NV_READ_PUBLIC, find,
    };
    use super::*;
    use crate::library::tpm2::hierarchy::{TPM_RH_OWNER, TPM_RH_PLATFORM};
    use crate::library::tpm2::nv::{
        NvPublic, TPMA_NV_AUTHREAD, TPMA_NV_ORDERLY, TPMA_NV_OWNERREAD, TPMA_NV_OWNERWRITE,
        TPMA_NV_POLICYREAD, TPMA_NV_POLICYWRITE, TPMA_NV_PPREAD, TPMA_NV_READ_STCLEAR,
        TPMA_NV_WRITTEN, marshal_sized_nv_public, nv_index_name,
    };
    use crate::library::tpm2::oracles::nv::nv_vector;

    const RC_SIZE: u32 = 0x095;
    const RC_NV_RANGE: u32 = 0x146;
    const RC_NV_LOCKED: u32 = 0x148;
    const RC_NV_AUTHORIZATION: u32 = 0x149;
    const RC_NV_UNINITIALIZED: u32 = 0x14a;
    const RC_AUTH_MISSING: u32 = 0x125;
    const RC_AUTH_UNAVAILABLE: u32 = 0x12f;
    const RC_HANDLE1_HANDLE: u32 = 0x18b;
    const RC_SESSION1_HANDLE: u32 = 0x98b;
    const RC_HANDLE2_HANDLE: u32 = 0x28b;
    const RC_PARAM1_VALUE: u32 = 0x1c4;
    const RC_PARAM1_INSUFFICIENT: u32 = 0x1da;
    const RC_PARAM2_VALUE: u32 = 0x2c4;
    const RC_PARAM2_INSUFFICIENT: u32 = 0x2da;

    const INDEX: u32 = 0x0100_0001;
    const READ_WRITE: u32 = TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD;

    #[track_caller]
    fn define(runtime: &mut Tpm2Runtime, public: &NvPublic) {
        let mut parameters = 0u16.to_be_bytes().to_vec();
        parameters.extend_from_slice(&marshal_sized_nv_public(public));
        assert_eq!(
            response_code(&dispatch_bytes(
                runtime,
                &command(0x0000_012a, &[TPM_RH_OWNER], &[&[]], &parameters),
            )),
            RC_SUCCESS,
            "the index is defined"
        );
    }

    #[track_caller]
    fn write(runtime: &mut Tpm2Runtime, index: u32, data: &[u8]) {
        let mut parameters = (data.len() as u16).to_be_bytes().to_vec();
        parameters.extend_from_slice(data);
        parameters.extend_from_slice(&0u16.to_be_bytes());
        assert_eq!(
            response_code(&dispatch_bytes(
                runtime,
                &command(0x0000_0137, &[TPM_RH_OWNER, index], &[&[]], &parameters),
            )),
            RC_SUCCESS,
            "the index is written"
        );
    }

    #[track_caller]
    fn read(runtime: &mut Tpm2Runtime, auth: u32, index: u32, size: u16, offset: u16) -> Vec<u8> {
        let mut parameters = size.to_be_bytes().to_vec();
        parameters.extend_from_slice(&offset.to_be_bytes());
        dispatch_bytes(
            runtime,
            &command(TPM_CC_NV_READ, &[auth, index], &[&[]], &parameters),
        )
    }

    #[track_caller]
    fn read_public(runtime: &mut Tpm2Runtime, index: u32) -> Vec<u8> {
        dispatch_bytes(
            runtime,
            &framed(TPM_CC_NV_READ_PUBLIC, &index.to_be_bytes(), false),
        )
    }

    const DATA8: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    #[test]
    fn the_read_command_attributes_match_the_oracle() {
        let expected = nv_vector("CCATTR_014E");
        let attributes = u32::from_be_bytes(expected[19..23].try_into().unwrap());
        let descriptor = find(TPM_CC_NV_READ).expect("a registered command");
        assert_eq!(descriptor.attributes, attributes);
        assert_eq!(
            descriptor.attributes & (1 << 22),
            0,
            "TPM2_NV_Read does not write NV"
        );
        assert_eq!((descriptor.attributes >> 25) & 0x7, 2);
        assert!(!descriptor.physical_presence);
        assert!(matches!(descriptor.nv_access, NvAccess::Read));
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
        assert_eq!(descriptor.handles.len(), 2);
        assert!(descriptor.handles[0].user_auth);
        assert!(!descriptor.handles[1].user_auth);
        assert!(matches!(descriptor.handles[0].kind, HandleKind::NvAuth));
        assert!(matches!(descriptor.handles[1].kind, HandleKind::NvIndex));
    }

    #[test]
    fn the_read_public_command_attributes_match_the_oracle() {
        let expected = nv_vector("CCATTR_0169");
        let attributes = u32::from_be_bytes(expected[19..23].try_into().unwrap());
        let descriptor = find(TPM_CC_NV_READ_PUBLIC).expect("a registered command");
        assert_eq!(descriptor.attributes, attributes);
        assert_eq!(descriptor.attributes & (1 << 22), 0);
        assert_eq!((descriptor.attributes >> 25) & 0x7, 1);
        assert_eq!(descriptor.handles.len(), 1);
        assert!(
            !descriptor.handles[0].user_auth,
            "TPM2_NV_ReadPublic needs no authorization"
        );
        assert!(matches!(descriptor.handles[0].kind, HandleKind::NvIndex));
        assert!(matches!(descriptor.nv_access, NvAccess::Neither));
    }

    #[test]
    fn reads_and_windows_match_the_oracle() {
        let mut runtime = started_runtime();
        define(&mut runtime, &nv_public(INDEX, READ_WRITE, 32));
        let mut parameters = 8u16.to_be_bytes().to_vec();
        parameters.extend_from_slice(&DATA8);
        parameters.extend_from_slice(&4u16.to_be_bytes());
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &command(0x0000_0137, &[TPM_RH_OWNER, INDEX], &[&[]], &parameters),
            )),
            RC_SUCCESS
        );
        assert_eq!(
            read(&mut runtime, TPM_RH_OWNER, INDEX, 32, 0),
            nv_vector("READ_OWNER_FULL")
        );
        assert_eq!(
            read(&mut runtime, TPM_RH_OWNER, INDEX, 8, 4),
            nv_vector("READ_OWNER_WINDOW")
        );
    }

    #[test]
    fn a_zero_length_read_returns_an_empty_buffer() {
        let mut runtime = started_runtime();
        define(&mut runtime, &nv_public(INDEX, READ_WRITE, 32));
        write(&mut runtime, INDEX, &[0xaa; 32]);
        let response = read(&mut runtime, TPM_RH_OWNER, INDEX, 0, 0);
        assert_eq!(response_code(&response), RC_SUCCESS);
        assert_eq!(response_parameters(&response), [0x00, 0x00]);
        let response = read(&mut runtime, TPM_RH_OWNER, INDEX, 0, 32);
        assert_eq!(
            response_code(&response),
            RC_SUCCESS,
            "an offset at the end of the index is in range"
        );
    }

    #[test]
    fn the_read_range_errors_match_the_oracle() {
        let mut runtime = started_runtime();
        define(&mut runtime, &nv_public(INDEX, READ_WRITE, 32));
        write(&mut runtime, INDEX, &[0xaa; 32]);
        assert_eq!(
            read(&mut runtime, TPM_RH_OWNER, INDEX, 0, 33),
            nv_vector("READ_OWNER_OFFSET_PAST_END")
        );
        assert_eq!(
            response_code(&read(&mut runtime, TPM_RH_OWNER, INDEX, 0, 33)),
            RC_PARAM2_VALUE
        );
        assert_eq!(
            read(&mut runtime, TPM_RH_OWNER, INDEX, 8, 28),
            nv_vector("READ_OWNER_RANGE")
        );
        assert_eq!(
            response_code(&read(&mut runtime, TPM_RH_OWNER, INDEX, 8, 28)),
            RC_NV_RANGE
        );
        assert_eq!(
            read(&mut runtime, TPM_RH_OWNER, INDEX, 1025, 0),
            nv_vector("READ_OWNER_OVERSIZED"),
            "the response buffer limit is checked before the index bounds"
        );
        assert_eq!(
            response_code(&read(&mut runtime, TPM_RH_OWNER, INDEX, 1025, 0)),
            RC_PARAM1_VALUE
        );
    }

    #[test]
    fn a_full_max_nv_buffer_read_is_accepted() {
        let mut runtime = started_runtime();
        define(&mut runtime, &nv_public(INDEX, READ_WRITE, 2048));
        write(&mut runtime, INDEX, &[0xaa; 1024]);
        let response = read(&mut runtime, TPM_RH_OWNER, INDEX, 1024, 0);
        assert_eq!(response_code(&response), RC_SUCCESS);
        assert_eq!(response_parameters(&response).len(), 2 + 1024);
    }

    #[test]
    fn the_read_authorization_attributes_are_enforced() {
        let mut runtime = started_runtime();
        define(
            &mut runtime,
            &nv_public(INDEX, TPMA_NV_OWNERWRITE | TPMA_NV_PPREAD, 8),
        );
        write(&mut runtime, INDEX, &DATA8);
        assert_eq!(
            response_code(&read(&mut runtime, TPM_RH_OWNER, INDEX, 8, 0)),
            RC_NV_AUTHORIZATION,
            "the owner may not read a PPREAD-only index"
        );
        assert_eq!(
            response_code(&read(&mut runtime, TPM_RH_PLATFORM, INDEX, 8, 0)),
            RC_SUCCESS
        );
        define(
            &mut runtime,
            &nv_public(0x0100_0002, TPMA_NV_OWNERWRITE | TPMA_NV_POLICYREAD, 8),
        );
        write(&mut runtime, 0x0100_0002, &DATA8);
        assert_eq!(
            response_code(&read(&mut runtime, TPM_RH_PLATFORM, 0x0100_0002, 8, 0)),
            RC_NV_AUTHORIZATION
        );
    }

    #[test]
    fn an_unwritten_index_cannot_be_read() {
        let mut runtime = started_runtime();
        define(&mut runtime, &nv_public(INDEX, READ_WRITE, 8));
        assert_eq!(
            response_code(&read(&mut runtime, TPM_RH_OWNER, INDEX, 0, 0)),
            RC_NV_UNINITIALIZED
        );
        write(&mut runtime, INDEX, &DATA8);
        assert_eq!(
            response_code(&read(&mut runtime, TPM_RH_OWNER, INDEX, 8, 0)),
            RC_SUCCESS
        );
    }

    #[test]
    fn a_read_locked_index_cannot_be_read() {
        let mut runtime = started_runtime();
        define(
            &mut runtime,
            &nv_public(INDEX, READ_WRITE | TPMA_NV_READ_STCLEAR, 8),
        );
        write(&mut runtime, INDEX, &DATA8);
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &command(0x0000_014f, &[TPM_RH_OWNER, INDEX], &[&[]], &[]),
            )),
            RC_SUCCESS
        );
        assert_eq!(
            response_code(&read(&mut runtime, TPM_RH_OWNER, INDEX, 8, 0)),
            RC_NV_LOCKED
        );
    }

    #[test]
    fn an_index_may_authorize_its_own_read_when_auth_read_is_set() {
        let mut runtime = started_runtime();
        define(
            &mut runtime,
            &nv_public(INDEX, TPMA_NV_OWNERWRITE | TPMA_NV_AUTHREAD, 8),
        );
        write(&mut runtime, INDEX, &DATA8);
        assert_eq!(
            response_code(&read(&mut runtime, INDEX, INDEX, 8, 0)),
            RC_SUCCESS
        );
        define(
            &mut runtime,
            &nv_public(0x0100_0002, TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD, 8),
        );
        write(&mut runtime, 0x0100_0002, &DATA8);
        assert_eq!(
            response_code(&read(&mut runtime, 0x0100_0002, 0x0100_0002, 8, 0)),
            RC_AUTH_UNAVAILABLE,
            "without AUTHREAD the index authValue is not usable"
        );
    }

    #[test]
    fn the_read_authorization_gates_match_the_oracle() {
        let mut runtime = started_runtime();
        define(&mut runtime, &nv_public(0x0100_0010, READ_WRITE, 8));
        write(&mut runtime, 0x0100_0010, &[]);
        assert_eq!(
            read(&mut runtime, 0x0100_0010, 0x0100_0010, 0, 0),
            nv_vector("GATE_READ_INDEX_AUTH"),
            "without AUTHREAD the index authValue is unavailable"
        );
        define(
            &mut runtime,
            &nv_public(0x0100_0011, TPMA_NV_POLICYWRITE | TPMA_NV_OWNERREAD, 8),
        );
        assert_eq!(
            read(&mut runtime, TPM_RH_PLATFORM, 0x0100_0011, 0, 0),
            nv_vector("GATE_READ_PLATFORM_WITHOUT_PPREAD")
        );
        assert_eq!(
            read(&mut runtime, TPM_RH_OWNER, 0x0100_0011, 0, 0),
            nv_vector("GATE_READ_UNWRITTEN"),
            "the owner may read the index, so the unwritten state is reported instead"
        );
    }

    #[test]
    fn the_read_public_response_matches_the_oracle_before_and_after_a_write() {
        let mut runtime = started_runtime();
        define(&mut runtime, &nv_public(INDEX, READ_WRITE, 32));
        assert_eq!(
            read_public(&mut runtime, INDEX),
            nv_vector("READPUBLIC_OWNER_ORDINARY")
        );
        let mut parameters = 8u16.to_be_bytes().to_vec();
        parameters.extend_from_slice(&DATA8);
        parameters.extend_from_slice(&4u16.to_be_bytes());
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &command(0x0000_0137, &[TPM_RH_OWNER, INDEX], &[&[]], &parameters),
            )),
            RC_SUCCESS
        );
        assert_eq!(
            read_public(&mut runtime, INDEX),
            nv_vector("READPUBLIC_AFTER_WRITE"),
            "the response carries the current dynamic attribute bits"
        );
    }

    #[test]
    fn the_read_public_name_is_the_computed_index_name() {
        let mut runtime = started_runtime();
        let public = nv_public(INDEX, READ_WRITE, 32);
        define(&mut runtime, &public);
        let parameters = response_parameters(&read_public(&mut runtime, INDEX));
        let public_size = u16::from_be_bytes([parameters[0], parameters[1]]) as usize;
        let name_offset = 2 + public_size;
        let name_size =
            u16::from_be_bytes([parameters[name_offset], parameters[name_offset + 1]]) as usize;
        let name = &parameters[name_offset + 2..name_offset + 2 + name_size];
        assert_eq!(name, nv_index_name(&public).unwrap());
        assert_eq!(
            &parameters[..2 + public_size],
            marshal_sized_nv_public(&public)
        );
    }

    #[test]
    fn the_read_public_response_of_an_orderly_index_matches_the_oracle() {
        let mut runtime = started_runtime();
        define(
            &mut runtime,
            &nv_public(0x0100_0020, READ_WRITE | TPMA_NV_ORDERLY, 8),
        );
        write(&mut runtime, 0x0100_0020, &DATA8);
        assert_eq!(
            read_public(&mut runtime, 0x0100_0020),
            nv_vector("ORDERLY_READPUBLIC"),
            "the orderly attributes come from the RAM copy"
        );
        assert_eq!(
            read(&mut runtime, TPM_RH_OWNER, 0x0100_0020, 8, 0),
            nv_vector("ORDERLY_READ")
        );
    }

    #[test]
    fn read_public_needs_no_session_and_no_parameters() {
        let mut runtime = started_runtime();
        define(&mut runtime, &nv_public(INDEX, READ_WRITE, 32));
        assert_eq!(
            response_code(&read_public(&mut runtime, INDEX)),
            RC_SUCCESS,
            "a plain-tagged command is accepted"
        );
        let mut payload = INDEX.to_be_bytes().to_vec();
        payload.push(0x00);
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &framed(TPM_CC_NV_READ_PUBLIC, &payload, false)
            )),
            RC_SIZE
        );
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &command(TPM_CC_NV_READ_PUBLIC, &[INDEX], &[&[]], &[]),
            )),
            RC_SESSION1_HANDLE,
            "the index handle takes no authorization, so a password session has nothing to \
             associate with"
        );
    }

    #[test]
    fn read_public_reports_an_undefined_index_against_its_own_handle() {
        let mut runtime = started_runtime();
        assert_eq!(
            response_code(&read_public(&mut runtime, INDEX)),
            RC_HANDLE1_HANDLE
        );
        assert_eq!(
            response_code(&read(&mut runtime, TPM_RH_OWNER, INDEX, 0, 0)),
            RC_HANDLE2_HANDLE
        );
    }

    #[test]
    fn a_read_without_an_authorization_area_is_auth_missing() {
        let mut runtime = started_runtime();
        define(&mut runtime, &nv_public(INDEX, READ_WRITE, 8));
        write(&mut runtime, INDEX, &DATA8);
        let mut payload = TPM_RH_OWNER.to_be_bytes().to_vec();
        payload.extend_from_slice(&INDEX.to_be_bytes());
        payload.extend_from_slice(&[0x00, 0x08, 0x00, 0x00]);
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &framed(TPM_CC_NV_READ, &payload, false)
            )),
            RC_AUTH_MISSING
        );
    }

    #[test]
    fn truncated_read_parameters_carry_their_own_parameter_number() {
        let mut runtime = started_runtime();
        define(&mut runtime, &nv_public(INDEX, READ_WRITE, 8));
        write(&mut runtime, INDEX, &DATA8);
        for (parameters, expected) in [
            (&[][..], RC_PARAM1_INSUFFICIENT),
            (&[0x00][..], RC_PARAM1_INSUFFICIENT),
            (&[0x00, 0x08][..], RC_PARAM2_INSUFFICIENT),
            (&[0x00, 0x08, 0x00][..], RC_PARAM2_INSUFFICIENT),
        ] {
            assert_eq!(
                response_code(&dispatch_bytes(
                    &mut runtime,
                    &command(TPM_CC_NV_READ, &[TPM_RH_OWNER, INDEX], &[&[]], parameters),
                )),
                expected,
                "parameters {parameters:02x?}"
            );
        }
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &command(
                    TPM_CC_NV_READ,
                    &[TPM_RH_OWNER, INDEX],
                    &[&[]],
                    &[0x00, 0x08, 0x00, 0x00, 0x00],
                ),
            )),
            RC_SIZE
        );
    }

    #[test]
    fn reading_never_touches_nv() {
        let mut runtime = started_runtime();
        define(&mut runtime, &nv_public(INDEX, READ_WRITE, 8));
        write(&mut runtime, INDEX, &DATA8);
        runtime.nv_update_pending = false;
        let before = snapshot(&runtime);
        assert_eq!(
            response_code(&read(&mut runtime, TPM_RH_OWNER, INDEX, 8, 0)),
            RC_SUCCESS
        );
        assert_eq!(response_code(&read_public(&mut runtime, INDEX)), RC_SUCCESS);
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn every_written_index_type_reads_back_its_stored_bytes() {
        let mut runtime = started_runtime();
        for (index_type, data_size, handle) in [
            (0u32, 32u16, 0x0100_0021u32),
            (1, 8, 0x0100_0022),
            (2, 8, 0x0100_0023),
            (4, 32, 0x0100_0024),
        ] {
            define(
                &mut runtime,
                &nv_public(handle, READ_WRITE | nt(index_type), data_size),
            );
            let code = match index_type {
                0 => 0x0000_0137u32,
                1 => 0x0000_0134,
                2 => 0x0000_0135,
                _ => 0x0000_0136,
            };
            let parameters: Vec<u8> = match index_type {
                0 => {
                    let mut out = 32u16.to_be_bytes().to_vec();
                    out.extend_from_slice(&[0xcc; 32]);
                    out.extend_from_slice(&0u16.to_be_bytes());
                    out
                }
                1 => Vec::new(),
                2 => 0xffu64.to_be_bytes().to_vec(),
                _ => {
                    let mut out = 8u16.to_be_bytes().to_vec();
                    out.extend_from_slice(&DATA8);
                    out
                }
            };
            assert_eq!(
                response_code(&dispatch_bytes(
                    &mut runtime,
                    &command(code, &[TPM_RH_OWNER, handle], &[&[]], &parameters),
                )),
                RC_SUCCESS,
                "index type {index_type} is written"
            );
            let response = read(&mut runtime, TPM_RH_OWNER, handle, data_size, 0);
            assert_eq!(
                response_code(&response),
                RC_SUCCESS,
                "index type {index_type} is readable"
            );
            assert_eq!(
                response_parameters(&response).len(),
                2 + usize::from(data_size)
            );
            assert_ne!(resolved(&runtime, handle).attributes() & TPMA_NV_WRITTEN, 0);
        }
    }

    #[test]
    fn malformed_read_parameters_never_panic() {
        let full = [0x00u8, 0x08, 0x00, 0x00];
        for index in 0..full.len() {
            for byte in [0x00u8, 0x01, 0x7f, 0xff] {
                let mut parameters = full;
                parameters[index] = byte;
                let mut runtime = started_runtime();
                define(&mut runtime, &nv_public(INDEX, READ_WRITE, 8));
                write(&mut runtime, INDEX, &DATA8);
                let _ = dispatch_bytes(
                    &mut runtime,
                    &command(TPM_CC_NV_READ, &[TPM_RH_OWNER, INDEX], &[&[]], &parameters),
                );
            }
        }
    }
}
