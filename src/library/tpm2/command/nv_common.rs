use crate::ffi_types::TpmResult;
use crate::library::constants::{
    TPM_RC_FAILURE, TPM_RC_NV_AUTHORIZATION, TPM_RC_NV_LOCKED, TPM_RC_NV_UNINITIALIZED,
};

use super::super::hierarchy::{TPM_RH_OWNER, TPM_RH_PLATFORM};
use super::super::nv::{
    ResolvedIndex, TPMA_NV_OWNERREAD, TPMA_NV_OWNERWRITE, TPMA_NV_PPREAD, TPMA_NV_PPWRITE,
    TPMA_NV_READLOCKED, TPMA_NV_WRITELOCKED, TPMA_NV_WRITTEN, resolve_index,
};
use super::super::runtime::Tpm2Runtime;
use super::dispatcher::CommandFrame;

pub(super) const TPM_RC_H: TpmResult = 0x000;
pub(super) const TPM_RC_P: TpmResult = 0x040;
pub(super) const TPM_RC_1: TpmResult = 0x100;
pub(super) const TPM_RC_2: TpmResult = 0x200;
pub(super) const TPM_RC_3: TpmResult = 0x300;
pub(super) const TPM_RC_4: TpmResult = 0x400;

pub(super) const MAX_NV_BUFFER_SIZE: usize = 1024;

pub(super) fn handle_at(frame: &CommandFrame<'_>, position: usize) -> Result<u32, TpmResult> {
    frame.handles.get(position).copied().ok_or(TPM_RC_FAILURE)
}

pub(super) fn resolve(runtime: &Tpm2Runtime, handle: u32) -> Result<ResolvedIndex, TpmResult> {
    resolve_index(runtime, handle).ok_or(TPM_RC_FAILURE)
}

pub(super) fn read_access_checks(
    auth_handle: u32,
    nv_handle: u32,
    attributes: u32,
) -> Result<(), TpmResult> {
    if attributes & TPMA_NV_READLOCKED != 0 {
        return Err(TPM_RC_NV_LOCKED);
    }
    if auth_handle == TPM_RH_OWNER {
        if attributes & TPMA_NV_OWNERREAD == 0 {
            return Err(TPM_RC_NV_AUTHORIZATION);
        }
    } else if auth_handle == TPM_RH_PLATFORM {
        if attributes & TPMA_NV_PPREAD == 0 {
            return Err(TPM_RC_NV_AUTHORIZATION);
        }
    } else if auth_handle != nv_handle {
        return Err(TPM_RC_NV_AUTHORIZATION);
    }
    if attributes & TPMA_NV_WRITTEN == 0 {
        return Err(TPM_RC_NV_UNINITIALIZED);
    }
    Ok(())
}

pub(super) fn write_access_checks(
    auth_handle: u32,
    nv_handle: u32,
    attributes: u32,
) -> Result<(), TpmResult> {
    if attributes & TPMA_NV_WRITELOCKED != 0 {
        return Err(TPM_RC_NV_LOCKED);
    }
    if auth_handle == TPM_RH_OWNER {
        if attributes & TPMA_NV_OWNERWRITE == 0 {
            return Err(TPM_RC_NV_AUTHORIZATION);
        }
    } else if auth_handle == TPM_RH_PLATFORM {
        if attributes & TPMA_NV_PPWRITE == 0 {
            return Err(TPM_RC_NV_AUTHORIZATION);
        }
    } else if auth_handle != nv_handle {
        return Err(TPM_RC_NV_AUTHORIZATION);
    }
    Ok(())
}

#[cfg(test)]
pub(super) mod harness {
    use crate::ffi_types::TpmResult;
    use crate::library::CommandInput;
    use crate::library::tpm2::command::dispatcher::dispatch;
    use crate::library::tpm2::command::header::{parse_command, serialize_response};
    use crate::library::tpm2::command::session::TPM_RS_PW;
    use crate::library::tpm2::manufacture::manufacture_state;
    use crate::library::tpm2::nv::{NvPublic, ResolvedIndex, TPMA_NV_TPM_NT_SHIFT, resolve_index};
    use crate::library::tpm2::persistent::{OwnedUserNvramEntry, persistent_all_store};
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

    pub(in crate::library::tpm2::command) fn nv_public(
        handle: u32,
        attributes: u32,
        data_size: u16,
    ) -> NvPublic {
        NvPublic {
            nv_index: handle,
            name_alg: TPM_ALG_SHA256,
            attributes,
            auth_policy: Vec::new(),
            data_size,
        }
    }

    pub(in crate::library::tpm2::command) fn nt(index_type: u32) -> u32 {
        index_type << TPMA_NV_TPM_NT_SHIFT
    }

    pub(in crate::library::tpm2::command) fn resolved(
        runtime: &Tpm2Runtime,
        handle: u32,
    ) -> ResolvedIndex {
        resolve_index(runtime, handle).expect("the index is defined")
    }

    pub(in crate::library::tpm2::command) fn index_handles(runtime: &Tpm2Runtime) -> Vec<u32> {
        runtime
            .state()
            .user_nvram
            .entries
            .iter()
            .filter_map(|entry| match entry {
                OwnedUserNvramEntry::NvIndex { handle, .. } => Some(*handle),
                OwnedUserNvramEntry::Persistent { .. } => None,
            })
            .collect()
    }

    #[derive(Debug, Eq, PartialEq)]
    pub(in crate::library::tpm2::command) struct Snapshot {
        nv_update_pending: bool,
        index_handles: Vec<u32>,
        required_capacity: u64,
        max_count: u64,
        max_nv_counter: u64,
        orderly_state: u16,
        orderly_ram: Vec<(u32, u32, Vec<u8>)>,
        nv_memory: Box<[u8]>,
        permanent: Vec<u8>,
    }

    pub(in crate::library::tpm2::command) fn snapshot(runtime: &Tpm2Runtime) -> Snapshot {
        Snapshot {
            nv_update_pending: runtime.nv_update_pending,
            index_handles: index_handles(runtime),
            required_capacity: runtime.state().user_nvram.required_capacity,
            max_count: runtime.state().user_nvram.max_count,
            max_nv_counter: runtime.live.max_nv_counter,
            orderly_state: runtime.state().persistent.orderly_state,
            orderly_ram: runtime
                .live
                .index_orderly_ram
                .entries
                .iter()
                .map(|entry| (entry.handle, entry.attributes, entry.data.clone()))
                .collect(),
            nv_memory: runtime.nv_memory.clone(),
            permanent: persistent_all_store(runtime.state()).expect("the state serializes"),
        }
    }

    fn divergence(actual: &[u8], expected: &[u8]) -> Vec<usize> {
        assert_eq!(actual.len(), expected.len(), "blob length");
        (0..actual.len())
            .filter(|&index| actual[index] != expected[index])
            .collect()
    }

    #[track_caller]
    pub(in crate::library::tpm2::command) fn assert_matches_oracle(
        runtime: &Tpm2Runtime,
        expected: &[u8],
        label: &str,
    ) {
        assert_matches_oracle_except(runtime, expected, label, &[]);
    }

    #[track_caller]
    pub(in crate::library::tpm2::command) fn assert_matches_oracle_except(
        runtime: &Tpm2Runtime,
        expected: &[u8],
        label: &str,
        host_supplied: &[usize],
    ) {
        let actual = persistent_all_store(runtime.state()).expect("the state serializes");
        let mut allowed = host_supplied.to_vec();
        allowed.sort_unstable();
        assert_eq!(
            divergence(&actual, expected),
            allowed,
            "{label} diverges from the oracle beyond the known host-supplied bytes"
        );
    }

    #[track_caller]
    pub(in crate::library::tpm2::command) fn assert_unchanged(
        runtime: &Tpm2Runtime,
        before: &Snapshot,
    ) {
        assert_eq!(&snapshot(runtime), before);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::nv::{TPMA_NV_AUTHREAD, TPMA_NV_AUTHWRITE};

    const INDEX: u32 = 0x0100_0001;
    const OTHER_INDEX: u32 = 0x0100_0002;

    #[test]
    fn the_error_index_constants_match_the_vendored_response_code_layout() {
        assert_eq!(TPM_RC_H, 0x000);
        assert_eq!(TPM_RC_P, 0x040);
        assert_eq!(TPM_RC_1, 0x100);
        assert_eq!(TPM_RC_2, 0x200);
        assert_eq!(TPM_RC_3, 0x300);
        assert_eq!(TPM_RC_4, 0x400);
    }

    #[test]
    fn a_read_lock_beats_every_other_read_check() {
        for attributes in [
            TPMA_NV_READLOCKED,
            TPMA_NV_READLOCKED | TPMA_NV_OWNERREAD | TPMA_NV_WRITTEN,
            TPMA_NV_READLOCKED | TPMA_NV_WRITTEN,
        ] {
            assert_eq!(
                read_access_checks(TPM_RH_OWNER, INDEX, attributes),
                Err(TPM_RC_NV_LOCKED),
                "attributes {attributes:#x}"
            );
        }
    }

    #[test]
    fn owner_and_platform_reads_need_their_own_attribute() {
        assert_eq!(
            read_access_checks(TPM_RH_OWNER, INDEX, TPMA_NV_WRITTEN),
            Err(TPM_RC_NV_AUTHORIZATION)
        );
        assert_eq!(
            read_access_checks(TPM_RH_OWNER, INDEX, TPMA_NV_OWNERREAD | TPMA_NV_WRITTEN),
            Ok(())
        );
        assert_eq!(
            read_access_checks(TPM_RH_PLATFORM, INDEX, TPMA_NV_OWNERREAD | TPMA_NV_WRITTEN),
            Err(TPM_RC_NV_AUTHORIZATION)
        );
        assert_eq!(
            read_access_checks(TPM_RH_PLATFORM, INDEX, TPMA_NV_PPREAD | TPMA_NV_WRITTEN),
            Ok(())
        );
    }

    #[test]
    fn an_index_authorizes_only_itself_for_reading() {
        assert_eq!(
            read_access_checks(INDEX, INDEX, TPMA_NV_AUTHREAD | TPMA_NV_WRITTEN),
            Ok(())
        );
        assert_eq!(
            read_access_checks(INDEX, INDEX, TPMA_NV_WRITTEN),
            Ok(()),
            "the attribute gate for index authorization is applied by the session layer"
        );
        assert_eq!(
            read_access_checks(OTHER_INDEX, INDEX, TPMA_NV_AUTHREAD | TPMA_NV_WRITTEN),
            Err(TPM_RC_NV_AUTHORIZATION)
        );
    }

    #[test]
    fn an_unwritten_index_is_uninitialized_after_the_authorization_checks() {
        assert_eq!(
            read_access_checks(TPM_RH_OWNER, INDEX, TPMA_NV_OWNERREAD),
            Err(TPM_RC_NV_UNINITIALIZED)
        );
        assert_eq!(
            read_access_checks(TPM_RH_OWNER, INDEX, 0),
            Err(TPM_RC_NV_AUTHORIZATION),
            "the authorization failure is reported before the uninitialized state"
        );
    }

    #[test]
    fn a_write_lock_beats_every_other_write_check() {
        for attributes in [
            TPMA_NV_WRITELOCKED,
            TPMA_NV_WRITELOCKED | TPMA_NV_OWNERWRITE,
        ] {
            assert_eq!(
                write_access_checks(TPM_RH_OWNER, INDEX, attributes),
                Err(TPM_RC_NV_LOCKED),
                "attributes {attributes:#x}"
            );
        }
    }

    #[test]
    fn owner_and_platform_writes_need_their_own_attribute() {
        assert_eq!(
            write_access_checks(TPM_RH_OWNER, INDEX, 0),
            Err(TPM_RC_NV_AUTHORIZATION)
        );
        assert_eq!(
            write_access_checks(TPM_RH_OWNER, INDEX, TPMA_NV_OWNERWRITE),
            Ok(())
        );
        assert_eq!(
            write_access_checks(TPM_RH_PLATFORM, INDEX, TPMA_NV_OWNERWRITE),
            Err(TPM_RC_NV_AUTHORIZATION)
        );
        assert_eq!(
            write_access_checks(TPM_RH_PLATFORM, INDEX, TPMA_NV_PPWRITE),
            Ok(())
        );
    }

    #[test]
    fn an_index_authorizes_only_itself_for_writing() {
        assert_eq!(write_access_checks(INDEX, INDEX, TPMA_NV_AUTHWRITE), Ok(()));
        assert_eq!(
            write_access_checks(OTHER_INDEX, INDEX, TPMA_NV_AUTHWRITE),
            Err(TPM_RC_NV_AUTHORIZATION)
        );
    }

    #[test]
    fn writing_never_requires_the_written_attribute() {
        assert_eq!(
            write_access_checks(TPM_RH_OWNER, INDEX, TPMA_NV_OWNERWRITE),
            Ok(()),
            "an unwritten index is still writable"
        );
    }
}
