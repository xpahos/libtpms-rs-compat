use super::access::{MAX_NV_BUFFER_SIZE, resolve, write_access_checks};
use crate::library::constants::{
    TPM_RC_ATTRIBUTES, TPM_RC_HASH, TPM_RC_NV_RANGE, TPM_RC_SIZE, TPM_RC_VALUE,
};
use crate::library::tpm2::command::core::dispatcher::{CommandFrame, handle_at};
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::command::core::response_code::{TPM_RC_1, TPM_RC_2, TPM_RC_H, TPM_RC_P};
use crate::library::tpm2::crypto::Hasher;
use crate::library::tpm2::nv::{
    IndexWrite, MAX_ORDERLY_COUNT, ResolvedIndex, TPMA_NV_ORDERLY, TPMA_NV_WRITEALL,
    TPMA_NV_WRITTEN, is_bits_index, is_counter_index, is_extend_index, read_uint64_data,
    sync_orderly_ram, transact, write_index_data,
};
use crate::library::tpm2::orderly::{commit_clear_orderly, prepare_clear_orderly};
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::template::{TemplateReader, digest_size};
use crate::types::TpmResult;

const RC_NV_INDEX: TpmResult = TPM_RC_H + TPM_RC_2;
const RC_PARAM_1: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_PARAM_2: TpmResult = TPM_RC_P + TPM_RC_2;

pub(in crate::library::tpm2::command) fn execute_write(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let auth_handle = handle_at(frame, 0)?;
    let nv_handle = handle_at(frame, 1)?;
    let (data, offset) = parse_write_parameters(frame.parameters)?;

    let resolved = resolve(runtime, nv_handle)?;
    let attributes = resolved.attributes();
    write_access_checks(auth_handle, nv_handle, attributes)?;

    if is_counter_index(attributes) || is_bits_index(attributes) || is_extend_index(attributes) {
        return Err(TPM_RC_ATTRIBUTES);
    }
    let data_size = resolved.public.data_size;
    if offset > data_size {
        return Err(TPM_RC_VALUE + RC_PARAM_2);
    }
    if data.len() > usize::from(data_size - offset) {
        return Err(TPM_RC_NV_RANGE);
    }
    if attributes & TPMA_NV_WRITEALL != 0 && data.len() < usize::from(data_size) {
        return Err(TPM_RC_NV_RANGE);
    }

    apply_write(
        runtime,
        &resolved,
        IndexWrite {
            offset: usize::from(offset),
            data,
        },
        false,
    )?;
    Ok(CommandOutput::empty())
}

pub(in crate::library::tpm2::command) fn execute_increment(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let auth_handle = handle_at(frame, 0)?;
    let nv_handle = handle_at(frame, 1)?;
    if !frame.parameters.is_empty() {
        return Err(TPM_RC_SIZE);
    }

    let resolved = resolve(runtime, nv_handle)?;
    let attributes = resolved.attributes();
    write_access_checks(auth_handle, nv_handle, attributes)?;
    if !is_counter_index(attributes) {
        return Err(TPM_RC_ATTRIBUTES + RC_NV_INDEX);
    }

    let current = if attributes & TPMA_NV_WRITTEN == 0 {
        runtime.live.max_nv_counter
    } else {
        read_uint64_data(runtime, &resolved)?
    };
    let next = current.wrapping_add(1);

    let force_orderly_sync = attributes & TPMA_NV_ORDERLY != 0 && next & MAX_ORDERLY_COUNT == 0;
    apply_write(
        runtime,
        &resolved,
        IndexWrite {
            offset: 0,
            data: next.to_be_bytes().to_vec(),
        },
        force_orderly_sync,
    )?;
    Ok(CommandOutput::empty())
}

pub(in crate::library::tpm2::command) fn execute_set_bits(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let auth_handle = handle_at(frame, 0)?;
    let nv_handle = handle_at(frame, 1)?;
    let bits = parse_bits(frame.parameters)?;

    let resolved = resolve(runtime, nv_handle)?;
    let attributes = resolved.attributes();
    write_access_checks(auth_handle, nv_handle, attributes)?;
    if !is_bits_index(attributes) {
        return Err(TPM_RC_ATTRIBUTES + RC_NV_INDEX);
    }

    let current = if attributes & TPMA_NV_WRITTEN == 0 {
        0
    } else {
        read_uint64_data(runtime, &resolved)?
    };
    apply_write(
        runtime,
        &resolved,
        IndexWrite {
            offset: 0,
            data: (current | bits).to_be_bytes().to_vec(),
        },
        false,
    )?;
    Ok(CommandOutput::empty())
}

pub(in crate::library::tpm2::command) fn execute_extend(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let auth_handle = handle_at(frame, 0)?;
    let nv_handle = handle_at(frame, 1)?;
    let data = parse_max_nv_buffer(frame.parameters, RC_PARAM_1)?;

    let resolved = resolve(runtime, nv_handle)?;
    let attributes = resolved.attributes();
    write_access_checks(auth_handle, nv_handle, attributes)?;
    if !is_extend_index(attributes) {
        return Err(TPM_RC_ATTRIBUTES + RC_NV_INDEX);
    }

    let digest_len = digest_size(resolved.public.name_alg).ok_or(TPM_RC_HASH)?;
    let old = if attributes & TPMA_NV_WRITTEN != 0 {
        crate::library::tpm2::nv::read_index_data(runtime, &resolved, 0, digest_len)?
    } else {
        vec![0u8; digest_len]
    };

    let mut hasher = Hasher::new(resolved.public.name_alg).ok_or(TPM_RC_HASH)?;
    hasher.update(&old);
    hasher.update(&data);
    let extended = hasher.finalize();

    apply_write(
        runtime,
        &resolved,
        IndexWrite {
            offset: 0,
            data: extended,
        },
        false,
    )?;
    Ok(CommandOutput::empty())
}

pub(in crate::library::tpm2::command) fn apply_write(
    runtime: &mut Tpm2Runtime,
    resolved: &ResolvedIndex,
    write: IndexWrite,
    force_orderly_sync: bool,
) -> Result<(), TpmResult> {
    let mut clear_orderly = false;
    transact(runtime, |runtime| {
        clear_orderly = write_index_data(runtime, resolved, write)?;
        if force_orderly_sync {
            sync_orderly_ram(runtime)?;
        }
        Ok(())
    })?;
    if clear_orderly {
        let orderly_state = prepare_clear_orderly(runtime)?;
        commit_clear_orderly(runtime, orderly_state)?;
    }
    Ok(())
}

fn parse_write_parameters(parameters: &[u8]) -> Result<(Vec<u8>, u16), TpmResult> {
    let mut reader = TemplateReader::new(parameters);
    let data = reader
        .tpm2b(MAX_NV_BUFFER_SIZE)
        .map_err(|code| code + RC_PARAM_1)?
        .to_vec();
    let offset = reader.u16().map_err(|code| code + RC_PARAM_2)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok((data, offset))
}

fn parse_bits(parameters: &[u8]) -> Result<u64, TpmResult> {
    let mut reader = TemplateReader::new(parameters);
    let high = reader.u32().map_err(|code| code + RC_PARAM_1)?;
    let low = reader.u32().map_err(|code| code + RC_PARAM_1)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok((u64::from(high) << 32) | u64::from(low))
}

fn parse_max_nv_buffer(parameters: &[u8], error_index: TpmResult) -> Result<Vec<u8>, TpmResult> {
    let mut reader = TemplateReader::new(parameters);
    let data = reader
        .tpm2b(MAX_NV_BUFFER_SIZE)
        .map_err(|code| code + error_index)?
        .to_vec();
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::command::core::registry::{
        CommandLifecycle, HandleKind, NvAccess, TPM_CC_NV_EXTEND, TPM_CC_NV_INCREMENT,
        TPM_CC_NV_SET_BITS, TPM_CC_NV_WRITE, find,
    };
    use crate::library::tpm2::command::core::test_support::{
        RC_SUCCESS, TPM_ALG_SHA1, command, dispatch_bytes, response_code, started_runtime,
    };
    use crate::library::tpm2::command::nv::test_support::{
        assert_unchanged, nt, nv_public, resolved, snapshot,
    };
    use crate::library::tpm2::golden_responses::nv::nv_vector;
    use crate::library::tpm2::hierarchy::{TPM_RH_OWNER, TPM_RH_PLATFORM};
    use crate::library::tpm2::nv::{
        NV_INDEX_FIRST, NvPublic, TPM_NT_BITS, TPM_NT_COUNTER, TPM_NT_EXTEND, TPMA_NV_AUTHREAD,
        TPMA_NV_AUTHWRITE, TPMA_NV_GLOBALLOCK, TPMA_NV_OWNERREAD, TPMA_NV_OWNERWRITE,
        TPMA_NV_POLICYWRITE, TPMA_NV_PPREAD, TPMA_NV_PPWRITE, TPMA_NV_WRITE_STCLEAR,
        marshal_sized_nv_public, resolve_index,
    };

    const RC_SIZE: u32 = 0x095;
    const RC_ATTRIBUTES: u32 = 0x082;
    const RC_NV_RANGE: u32 = 0x146;
    const RC_NV_LOCKED: u32 = 0x148;
    const RC_NV_AUTHORIZATION: u32 = 0x149;
    const RC_HANDLE2_ATTRIBUTES: u32 = 0x282;
    const RC_HANDLE2_HANDLE: u32 = 0x28b;
    const RC_PARAM1_SIZE: u32 = 0x1d5;
    const RC_PARAM2_VALUE: u32 = 0x2c4;
    const RC_SESSION1_AUTH_FAIL: u32 = 0x98e;
    const RC_NV_UNAVAILABLE: u32 = 0x923;

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

    fn write_parameters(data: &[u8], offset: u16) -> Vec<u8> {
        let mut out = (data.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(data);
        out.extend_from_slice(&offset.to_be_bytes());
        out
    }

    #[track_caller]
    fn write(
        runtime: &mut Tpm2Runtime,
        auth: u32,
        index: u32,
        data: &[u8],
        offset: u16,
    ) -> Vec<u8> {
        dispatch_bytes(
            runtime,
            &command(
                TPM_CC_NV_WRITE,
                &[auth, index],
                &[&[]],
                &write_parameters(data, offset),
            ),
        )
    }

    #[track_caller]
    fn read(runtime: &mut Tpm2Runtime, auth: u32, index: u32, size: u16, offset: u16) -> Vec<u8> {
        let mut parameters = size.to_be_bytes().to_vec();
        parameters.extend_from_slice(&offset.to_be_bytes());
        dispatch_bytes(
            runtime,
            &command(0x0000_014e, &[auth, index], &[&[]], &parameters),
        )
    }

    #[track_caller]
    fn increment(runtime: &mut Tpm2Runtime, auth: u32, index: u32) -> Vec<u8> {
        dispatch_bytes(
            runtime,
            &command(TPM_CC_NV_INCREMENT, &[auth, index], &[&[]], &[]),
        )
    }

    #[track_caller]
    fn set_bits(runtime: &mut Tpm2Runtime, auth: u32, index: u32, bits: u64) -> Vec<u8> {
        dispatch_bytes(
            runtime,
            &command(
                TPM_CC_NV_SET_BITS,
                &[auth, index],
                &[&[]],
                &bits.to_be_bytes(),
            ),
        )
    }

    #[track_caller]
    fn extend(runtime: &mut Tpm2Runtime, auth: u32, index: u32, data: &[u8]) -> Vec<u8> {
        let mut parameters = (data.len() as u16).to_be_bytes().to_vec();
        parameters.extend_from_slice(data);
        dispatch_bytes(
            runtime,
            &command(TPM_CC_NV_EXTEND, &[auth, index], &[&[]], &parameters),
        )
    }

    const DATA8: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    #[test]
    fn command_codes_attributes_oracle_match() {
        for (code, oracle) in [
            (TPM_CC_NV_INCREMENT, nv_vector("CCATTR_0134")),
            (TPM_CC_NV_SET_BITS, nv_vector("CCATTR_0135")),
            (TPM_CC_NV_EXTEND, nv_vector("CCATTR_0136")),
            (TPM_CC_NV_WRITE, nv_vector("CCATTR_0137")),
        ] {
            let expected = oracle;
            let attributes = u32::from_be_bytes(expected[19..23].try_into().expect("a TPMA_CC"));
            let descriptor = find(code).expect("a registered command");
            assert_eq!(descriptor.attributes, attributes, "code {code:#x}");
            assert_ne!(
                descriptor.attributes & (1 << 22),
                0,
                "code {code:#x} writes NV"
            );
            assert_eq!((descriptor.attributes >> 25) & 0x7, 2, "code {code:#x}");
            assert!(!descriptor.physical_presence);
            assert!(descriptor.sessions_allowed);
            assert!(matches!(descriptor.nv_access, NvAccess::Write));
            assert!(matches!(
                descriptor.lifecycle,
                CommandLifecycle::RequiresStarted
            ));
            assert_eq!(descriptor.handles.len(), 2);
            assert!(descriptor.handles[0].user_auth);
            assert!(!descriptor.handles[0].admin_role());
            assert!(!descriptor.handles[1].user_auth);
            assert!(matches!(descriptor.handles[0].kind, HandleKind::NvAuth));
            assert!(matches!(descriptor.handles[1].kind, HandleKind::NvIndex));
        }
    }

    #[test]
    fn auth_handle_owner_platform_index_acceptance() {
        let kind = find(TPM_CC_NV_WRITE).unwrap().handles[0].kind;
        assert!(kind.accepts(TPM_RH_OWNER));
        assert!(kind.accepts(TPM_RH_PLATFORM));
        assert!(kind.accepts(NV_INDEX_FIRST));
        assert!(kind.accepts(0x01ff_ffff));
        for handle in [0x4000_0000u32, 0x4000_000b, 0x0200_0000, 0x8100_0000, 0] {
            assert!(!kind.accepts(handle), "handle {handle:#010x}");
        }
    }

    #[test]
    fn partial_write_read_oracle_match() {
        let mut runtime = started_runtime();
        define(&mut runtime, &nv_public(INDEX, READ_WRITE, 32));
        assert_eq!(
            write(&mut runtime, TPM_RH_OWNER, INDEX, &DATA8, 4),
            nv_vector("WRITE_OWNER_PARTIAL")
        );
        assert_eq!(
            read(&mut runtime, TPM_RH_OWNER, INDEX, 32, 0),
            nv_vector("READ_OWNER_FULL"),
            "the untouched bytes carry the platform erase value"
        );
        assert_eq!(
            read(&mut runtime, TPM_RH_OWNER, INDEX, 8, 4),
            nv_vector("READ_OWNER_WINDOW")
        );
    }

    #[test]
    fn write_range_error_oracle_match() {
        let mut runtime = started_runtime();
        define(&mut runtime, &nv_public(INDEX, READ_WRITE, 32));
        assert_eq!(
            write(&mut runtime, TPM_RH_OWNER, INDEX, &DATA8, 33),
            nv_vector("WRITE_OWNER_OFFSET_PAST_END")
        );
        assert_eq!(
            response_code(&write(&mut runtime, TPM_RH_OWNER, INDEX, &DATA8, 33)),
            RC_PARAM2_VALUE
        );
        assert_eq!(
            write(&mut runtime, TPM_RH_OWNER, INDEX, &DATA8, 28),
            nv_vector("WRITE_OWNER_RANGE")
        );
        assert_eq!(
            response_code(&write(&mut runtime, TPM_RH_OWNER, INDEX, &DATA8, 28)),
            RC_NV_RANGE
        );
        assert_eq!(
            response_code(&write(&mut runtime, TPM_RH_OWNER, INDEX, &DATA8, 24)),
            RC_SUCCESS,
            "the last byte of the index is writable"
        );
    }

    #[test]
    fn oversized_write_buffer_size_error() {
        let mut runtime = started_runtime();
        define(&mut runtime, &nv_public(INDEX, READ_WRITE, 2048));
        assert_eq!(
            response_code(&write(&mut runtime, TPM_RH_OWNER, INDEX, &[0xaa; 1025], 0)),
            RC_PARAM1_SIZE
        );
        assert_eq!(
            response_code(&write(&mut runtime, TPM_RH_OWNER, INDEX, &[0xaa; 1024], 0)),
            RC_SUCCESS
        );
    }

    #[test]
    fn write_all_whole_index_requirement() {
        let mut runtime = started_runtime();
        define(
            &mut runtime,
            &nv_public(INDEX, READ_WRITE | TPMA_NV_WRITEALL, 32),
        );
        assert_eq!(
            response_code(&write(&mut runtime, TPM_RH_OWNER, INDEX, &[0xaa; 31], 0)),
            RC_NV_RANGE
        );
        assert_eq!(
            response_code(&write(&mut runtime, TPM_RH_OWNER, INDEX, &[0xaa; 32], 0)),
            RC_SUCCESS
        );
    }

    #[test]
    fn zero_length_write_written_flag() {
        let mut runtime = started_runtime();
        define(&mut runtime, &nv_public(INDEX, READ_WRITE, 32));
        assert!(!resolved(&runtime, INDEX).is_written());
        assert_eq!(
            response_code(&write(&mut runtime, TPM_RH_OWNER, INDEX, &[], 0)),
            RC_SUCCESS
        );
        assert!(resolved(&runtime, INDEX).is_written());
    }

    #[test]
    fn typed_index_plain_write_rejection() {
        let mut runtime = started_runtime();
        for (index_type, data_size, handle) in [
            (TPM_NT_COUNTER, 8u16, 0x0100_0011u32),
            (TPM_NT_BITS, 8, 0x0100_0012),
            (TPM_NT_EXTEND, 32, 0x0100_0013),
        ] {
            define(
                &mut runtime,
                &nv_public(handle, READ_WRITE | nt(index_type), data_size),
            );
            assert_eq!(
                response_code(&write(&mut runtime, TPM_RH_OWNER, handle, &DATA8, 0)),
                RC_ATTRIBUTES,
                "index type {index_type} rejects TPM2_NV_Write"
            );
        }
        assert_eq!(
            write(&mut runtime, TPM_RH_OWNER, 0x0100_0011, &DATA8, 0),
            nv_vector("WRITE_COUNTER_IS_ATTRIBUTES")
        );
    }

    #[test]
    fn counter_max_counter_seed_increment() {
        let mut runtime = started_runtime();
        define(
            &mut runtime,
            &nv_public(INDEX, READ_WRITE | nt(TPM_NT_COUNTER), 8),
        );
        assert_eq!(
            increment(&mut runtime, TPM_RH_OWNER, INDEX),
            nv_vector("INCREMENT_COUNTER_FIRST")
        );
        assert_eq!(
            read(&mut runtime, TPM_RH_OWNER, INDEX, 8, 0),
            nv_vector("READ_COUNTER")
        );
        assert_eq!(
            increment(&mut runtime, TPM_RH_OWNER, INDEX),
            nv_vector("INCREMENT_COUNTER_AGAIN")
        );
        assert_eq!(
            read(&mut runtime, TPM_RH_OWNER, INDEX, 8, 0),
            nv_vector("READ_COUNTER_AGAIN")
        );
    }

    #[test]
    fn new_counter_no_rollback_below_deleted() {
        let mut runtime = started_runtime();
        define(
            &mut runtime,
            &nv_public(INDEX, READ_WRITE | nt(TPM_NT_COUNTER), 8),
        );
        for _ in 0..5 {
            assert_eq!(
                response_code(&increment(&mut runtime, TPM_RH_OWNER, INDEX)),
                RC_SUCCESS
            );
        }
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &command(0x0000_0122, &[TPM_RH_OWNER, INDEX], &[&[]], &[]),
            )),
            RC_SUCCESS
        );
        assert_eq!(runtime.live.max_nv_counter, 5);

        define(
            &mut runtime,
            &nv_public(0x0100_0009, READ_WRITE | nt(TPM_NT_COUNTER), 8),
        );
        assert_eq!(
            response_code(&increment(&mut runtime, TPM_RH_OWNER, 0x0100_0009)),
            RC_SUCCESS
        );
        let resolved = resolved(&runtime, 0x0100_0009);
        assert_eq!(
            crate::library::tpm2::nv::read_uint64_data(&runtime, &resolved).unwrap(),
            6,
            "the fresh counter starts above the deleted one"
        );
    }

    #[test]
    fn non_counter_increment_indexed_attribute_error() {
        let mut runtime = started_runtime();
        define(&mut runtime, &nv_public(INDEX, READ_WRITE, 32));
        assert_eq!(
            increment(&mut runtime, TPM_RH_OWNER, INDEX),
            nv_vector("INCREMENT_ORDINARY_IS_ATTRIBUTES")
        );
        assert_eq!(
            response_code(&increment(&mut runtime, TPM_RH_OWNER, INDEX)),
            RC_HANDLE2_ATTRIBUTES
        );
    }

    #[test]
    fn set_bits_zero_start_or_accumulation() {
        let mut runtime = started_runtime();
        define(
            &mut runtime,
            &nv_public(INDEX, READ_WRITE | nt(TPM_NT_BITS), 8),
        );
        assert_eq!(
            set_bits(&mut runtime, TPM_RH_OWNER, INDEX, 0x0000_0001_0000_0002),
            nv_vector("SETBITS_FIRST")
        );
        assert_eq!(
            read(&mut runtime, TPM_RH_OWNER, INDEX, 8, 0),
            nv_vector("READ_BITS")
        );
        assert_eq!(
            set_bits(&mut runtime, TPM_RH_OWNER, INDEX, 0x8000_0000_0000_0001),
            nv_vector("SETBITS_OR")
        );
        assert_eq!(
            read(&mut runtime, TPM_RH_OWNER, INDEX, 8, 0),
            nv_vector("READ_BITS_AFTER_OR"),
            "the new bits are OR-ed into the old value"
        );
    }

    #[test]
    fn non_bit_field_set_bits_indexed_attribute_error() {
        let mut runtime = started_runtime();
        define(&mut runtime, &nv_public(INDEX, READ_WRITE, 32));
        assert_eq!(
            set_bits(&mut runtime, TPM_RH_OWNER, INDEX, 1),
            nv_vector("SETBITS_ON_ORDINARY")
        );
    }

    #[test]
    fn extend_old_value_new_data_hashing() {
        let mut runtime = started_runtime();
        define(
            &mut runtime,
            &nv_public(INDEX, READ_WRITE | nt(TPM_NT_EXTEND), 32),
        );
        assert_eq!(
            extend(&mut runtime, TPM_RH_OWNER, INDEX, &DATA8),
            nv_vector("EXTEND_FIRST")
        );
        assert_eq!(
            read(&mut runtime, TPM_RH_OWNER, INDEX, 32, 0),
            nv_vector("READ_EXTEND"),
            "the first extension starts from an all-zero digest"
        );
        assert_eq!(
            extend(&mut runtime, TPM_RH_OWNER, INDEX, &DATA8),
            nv_vector("EXTEND_AGAIN")
        );
        assert_eq!(
            read(&mut runtime, TPM_RH_OWNER, INDEX, 32, 0),
            nv_vector("READ_EXTEND_AGAIN")
        );
    }

    #[test]
    fn non_extend_index_extend_indexed_attribute_error() {
        let mut runtime = started_runtime();
        define(&mut runtime, &nv_public(INDEX, READ_WRITE, 32));
        assert_eq!(
            response_code(&extend(&mut runtime, TPM_RH_OWNER, INDEX, &DATA8)),
            RC_HANDLE2_ATTRIBUTES
        );
    }

    #[test]
    fn write_authorization_attribute_enforcement() {
        let mut runtime = started_runtime();
        define(
            &mut runtime,
            &nv_public(INDEX, TPMA_NV_PPWRITE | TPMA_NV_OWNERREAD, 8),
        );
        assert_eq!(
            response_code(&write(&mut runtime, TPM_RH_OWNER, INDEX, &[], 0)),
            RC_NV_AUTHORIZATION,
            "the owner may not write a PPWRITE-only index"
        );
        define(
            &mut runtime,
            &nv_public(0x0100_0002, TPMA_NV_OWNERWRITE | TPMA_NV_PPREAD, 8),
        );
        assert_eq!(
            response_code(&write(&mut runtime, TPM_RH_PLATFORM, 0x0100_0002, &[], 0)),
            RC_NV_AUTHORIZATION,
            "the platform may not write an OWNERWRITE-only index"
        );
    }

    fn wrong_password_response() -> Vec<u8> {
        vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x09, 0x8e]
    }

    #[test]
    fn index_self_write_authorization_only() {
        let mut runtime = started_runtime();
        runtime.live.da_used = true;
        define(
            &mut runtime,
            &nv_public(INDEX, TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD, 8),
        );
        define(
            &mut runtime,
            &nv_public(0x0100_0002, TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD, 8),
        );
        assert_eq!(
            response_code(&write(&mut runtime, INDEX, INDEX, &[], 0)),
            RC_SUCCESS
        );
        assert_eq!(
            response_code(&write(&mut runtime, 0x0100_0002, INDEX, &[], 0)),
            RC_NV_AUTHORIZATION
        );
    }

    #[test]
    fn wrong_password_first_session_report() {
        let mut runtime = started_runtime();
        let mut parameters = 4u16.to_be_bytes().to_vec();
        parameters.extend_from_slice(b"pass");
        parameters.extend_from_slice(&marshal_sized_nv_public(&nv_public(
            INDEX,
            TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD,
            8,
        )));
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &command(0x0000_012a, &[TPM_RH_OWNER], &[&[]], &parameters),
            )),
            RC_SUCCESS
        );
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &command(
                    TPM_CC_NV_WRITE,
                    &[INDEX, INDEX],
                    &[b"wrong"],
                    &write_parameters(&[], 0),
                ),
            ),
            wrong_password_response(),
            "the first DA-protected authorization performs the transition and \
             reports the wrong password"
        );
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &command(
                    TPM_CC_NV_WRITE,
                    &[INDEX, INDEX],
                    &[b"wrong"],
                    &write_parameters(&[], 0),
                ),
            )),
            RC_SESSION1_AUTH_FAIL,
            "a DA-protected index reports an authorization failure, not a bad password"
        );
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &command(
                    TPM_CC_NV_WRITE,
                    &[INDEX, INDEX],
                    &[b"pass"],
                    &write_parameters(&[], 0),
                ),
            )),
            RC_SUCCESS
        );
    }

    #[test]
    fn da_protected_index_oracle_failure_code() {
        let mut runtime = started_runtime();
        let mut parameters = 4u16.to_be_bytes().to_vec();
        parameters.extend_from_slice(b"test");
        let mut public = nv_public(0x0100_0000, TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD, 1);
        public.name_alg = TPM_ALG_SHA1;
        parameters.extend_from_slice(&marshal_sized_nv_public(&public));
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &command(0x0000_012a, &[TPM_RH_OWNER], &[&[]], &parameters),
            )),
            RC_SUCCESS
        );
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &command(
                    TPM_CC_NV_WRITE,
                    &[0x0100_0000, 0x0100_0000],
                    &[&[][..]],
                    &write_parameters(b"A", 0),
                ),
            ),
            nv_vector("DA_WRITE_NO_PASSWORD"),
            "the first DA-protected authorization performs the DA-used \
             transition and reports the missing password"
        );
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &command(
                    TPM_CC_NV_WRITE,
                    &[0x0100_0000, 0x0100_0000],
                    &[&b"nope"[..]],
                    &write_parameters(b"A", 0),
                ),
            ),
            nv_vector("DA_WRITE_WRONG_PASSWORD")
        );
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &command(
                    TPM_CC_NV_WRITE,
                    &[0x0100_0000, 0x0100_0000],
                    &[b"test"],
                    &write_parameters(b"A", 0),
                ),
            ),
            nv_vector("DA_WRITE_RIGHT_PASSWORD")
        );
    }

    #[test]
    fn index_authorization_gate_oracle_match() {
        let mut runtime = started_runtime();
        runtime.live.da_used = true;
        define(&mut runtime, &nv_public(0x0100_0010, READ_WRITE, 8));
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &command(
                    TPM_CC_NV_WRITE,
                    &[0x0100_0010, 0x0100_0010],
                    &[&[]],
                    &write_parameters(&[], 0),
                ),
            ),
            nv_vector("GATE_INDEX_AUTH_WITHOUT_AUTHWRITE"),
            "without AUTHWRITE the index authValue is unavailable"
        );
        assert_eq!(
            write(&mut runtime, 0x0100_0010, 0x0100_0010, &[], 0),
            nv_vector("GATE_WRITE_INDEX_AUTH")
        );
        define(
            &mut runtime,
            &nv_public(0x0100_0011, TPMA_NV_POLICYWRITE | TPMA_NV_OWNERREAD, 8),
        );
        assert_eq!(
            write(&mut runtime, TPM_RH_OWNER, 0x0100_0011, &[], 0),
            nv_vector("GATE_WRITE_OWNER_WITHOUT_OWNERWRITE")
        );
    }

    #[test]
    fn da_index_wrong_password_oracle_match() {
        let mut runtime = started_runtime();
        runtime.live.da_used = true;
        let mut parameters = 4u16.to_be_bytes().to_vec();
        parameters.extend_from_slice(b"test");
        let mut public = nv_public(0x0100_0000, TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD, 1);
        public.name_alg = TPM_ALG_SHA1;
        parameters.extend_from_slice(&marshal_sized_nv_public(&public));
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &command(0x0000_012a, &[TPM_RH_OWNER], &[&[]], &parameters),
            )),
            RC_SUCCESS
        );
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &command(
                    TPM_CC_NV_WRITE,
                    &[0x0100_0000, 0x0100_0000],
                    &[b"nope"],
                    &write_parameters(b"A", 0),
                ),
            ),
            nv_vector("DA_WRITE_WRONG_PASSWORD")
        );
    }

    #[test]
    fn orderly_write_response_oracle_match() {
        let mut runtime = started_runtime();
        define(
            &mut runtime,
            &nv_public(0x0100_0020, READ_WRITE | TPMA_NV_ORDERLY, 8),
        );
        assert_eq!(
            write(&mut runtime, TPM_RH_OWNER, 0x0100_0020, &DATA8, 0),
            nv_vector("ORDERLY_WRITE")
        );
    }

    #[test]
    fn global_lock_unmarked_index_writability() {
        let mut runtime = started_runtime();
        define(
            &mut runtime,
            &nv_public(0x0100_0007, READ_WRITE | TPMA_NV_GLOBALLOCK, 8),
        );
        define(&mut runtime, &nv_public(INDEX, READ_WRITE, 32));
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &command(0x0000_0132, &[TPM_RH_OWNER], &[&[]], &[]),
            )),
            RC_SUCCESS
        );
        assert_eq!(
            write(&mut runtime, TPM_RH_OWNER, INDEX, &DATA8, 0),
            nv_vector("WRITE_UNLOCKED_AFTER_GLOBALLOCK")
        );
    }

    #[test]
    fn undefined_index_handle_decorated_error() {
        let mut runtime = started_runtime();
        assert_eq!(
            response_code(&write(&mut runtime, TPM_RH_OWNER, INDEX, &[], 0)),
            RC_HANDLE2_HANDLE
        );
    }

    #[test]
    fn trailing_parameter_bytes_size_error() {
        let mut runtime = started_runtime();
        define(&mut runtime, &nv_public(INDEX, READ_WRITE, 8));
        let mut parameters = write_parameters(&[], 0);
        parameters.push(0x00);
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &command(TPM_CC_NV_WRITE, &[TPM_RH_OWNER, INDEX], &[&[]], &parameters),
            )),
            RC_SIZE
        );
        for code in [TPM_CC_NV_INCREMENT, TPM_CC_NV_SET_BITS] {
            let extra: &[u8] = if code == TPM_CC_NV_INCREMENT {
                &[0x00]
            } else {
                &[0x00; 9]
            };
            assert_eq!(
                response_code(&dispatch_bytes(
                    &mut runtime,
                    &command(code, &[TPM_RH_OWNER, INDEX], &[&[]], extra),
                )),
                RC_SIZE,
                "code {code:#x}"
            );
        }
    }

    #[test]
    fn write_lock_modification_command_rejection() {
        let mut runtime = started_runtime();
        define(
            &mut runtime,
            &nv_public(INDEX, READ_WRITE | TPMA_NV_WRITE_STCLEAR, 8),
        );
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &command(0x0000_0138, &[TPM_RH_OWNER, INDEX], &[&[]], &[]),
            )),
            RC_SUCCESS
        );
        assert_eq!(
            response_code(&write(&mut runtime, TPM_RH_OWNER, INDEX, &[], 0)),
            RC_NV_LOCKED
        );
        assert_eq!(
            response_code(&increment(&mut runtime, TPM_RH_OWNER, INDEX)),
            RC_NV_LOCKED
        );
        assert_eq!(
            response_code(&set_bits(&mut runtime, TPM_RH_OWNER, INDEX, 1)),
            RC_NV_LOCKED
        );
        assert_eq!(
            response_code(&extend(&mut runtime, TPM_RH_OWNER, INDEX, &DATA8)),
            RC_NV_LOCKED
        );
    }

    #[test]
    fn orderly_index_write_orderly_state_clearing() {
        let mut runtime = started_runtime();
        define(
            &mut runtime,
            &nv_public(INDEX, READ_WRITE | TPMA_NV_ORDERLY, 8),
        );
        runtime.state.as_mut().unwrap().persistent.orderly_state = 0;
        assert_eq!(
            response_code(&write(&mut runtime, TPM_RH_OWNER, INDEX, &DATA8, 0)),
            RC_SUCCESS
        );
        assert_eq!(
            runtime.state().persistent.orderly_state,
            0xffff,
            "the TPM is no longer orderly"
        );
        assert_eq!(
            read(&mut runtime, TPM_RH_OWNER, INDEX, 8, 0),
            nv_vector("ORDERLY_READ")
        );
    }

    #[test]
    fn non_orderly_index_write_orderly_state_unchanged() {
        let mut runtime = started_runtime();
        define(&mut runtime, &nv_public(INDEX, READ_WRITE, 8));
        runtime.state.as_mut().unwrap().persistent.orderly_state = 0;
        assert_eq!(
            response_code(&write(&mut runtime, TPM_RH_OWNER, INDEX, &DATA8, 0)),
            RC_SUCCESS
        );
        assert_eq!(runtime.state().persistent.orderly_state, 0);
    }

    #[test]
    fn failed_write_rollback() {
        let mut runtime = started_runtime();
        define(&mut runtime, &nv_public(INDEX, READ_WRITE, 32));
        runtime.nv_update_pending = false;
        let before = snapshot(&runtime);
        assert_ne!(
            response_code(&write(&mut runtime, TPM_RH_OWNER, INDEX, &DATA8, 33)),
            RC_SUCCESS
        );
        assert_unchanged(&runtime, &before);

        runtime.nv_available = false;
        assert_eq!(
            response_code(&write(&mut runtime, TPM_RH_OWNER, INDEX, &DATA8, 0)),
            RC_NV_UNAVAILABLE
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn identical_byte_rewrite_no_nv_access() {
        let mut runtime = started_runtime();
        define(&mut runtime, &nv_public(INDEX, READ_WRITE, 8));
        assert_eq!(
            response_code(&write(&mut runtime, TPM_RH_OWNER, INDEX, &DATA8, 0)),
            RC_SUCCESS
        );
        runtime.nv_update_pending = false;
        runtime.nv_available = false;
        assert_eq!(
            response_code(&write(&mut runtime, TPM_RH_OWNER, INDEX, &DATA8, 0)),
            RC_SUCCESS,
            "an unchanged write never touches NV"
        );
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn parameter_mutation_panic_safety() {
        let full = write_parameters(&DATA8, 4);
        for index in 0..full.len() {
            for byte in [0x00u8, 0x01, 0x7f, 0xff] {
                let mut parameters = full.clone();
                parameters[index] = byte;
                let mut runtime = started_runtime();
                define(&mut runtime, &nv_public(INDEX, READ_WRITE, 32));
                for code in [
                    TPM_CC_NV_WRITE,
                    TPM_CC_NV_INCREMENT,
                    TPM_CC_NV_SET_BITS,
                    TPM_CC_NV_EXTEND,
                ] {
                    let _ = dispatch_bytes(
                        &mut runtime,
                        &command(code, &[TPM_RH_OWNER, INDEX], &[&[]], &parameters),
                    );
                }
            }
        }
    }

    #[test]
    fn orderly_index_type_ram_copy_round_trip() {
        let mut runtime = started_runtime();
        define(
            &mut runtime,
            &nv_public(INDEX, READ_WRITE | TPMA_NV_ORDERLY | nt(TPM_NT_COUNTER), 8),
        );
        assert_eq!(
            response_code(&increment(&mut runtime, TPM_RH_OWNER, INDEX)),
            RC_SUCCESS
        );
        let resolved = resolve_index(&runtime, INDEX).expect("resolves");
        assert!(resolved.ram.is_some());
        assert!(resolved.is_written());
        assert_eq!(
            crate::library::tpm2::nv::read_uint64_data(&runtime, &resolved).unwrap(),
            1
        );
        assert_eq!(
            runtime.state().index_orderly_ram.entries[0].data,
            runtime.live.index_orderly_ram.entries[0].data,
            "the first write of an orderly counter is written back to NV"
        );
    }
}
