use subtle::ConstantTimeEq;

use crate::ffi_types::TpmResult;
use crate::library::constants::{
    TPM_RC_ATTRIBUTES, TPM_RC_AUTH_FAIL, TPM_RC_AUTH_MISSING, TPM_RC_AUTH_TYPE,
    TPM_RC_AUTH_UNAVAILABLE, TPM_RC_BAD_AUTH, TPM_RC_FAILURE, TPM_RC_HANDLE, TPM_RC_INSUFFICIENT,
    TPM_RC_NONCE, TPM_RC_REFERENCE_S0, TPM_RC_RESERVED_BITS, TPM_RC_SIZE, TPM_RC_VALUE,
};

use super::super::dictionary_attack::{
    check_locked_out, is_da_protected_handle, register_lockout_failure,
};
pub(super) use super::super::hierarchy::TPM_RS_PW;
use super::super::hierarchy::{
    TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT, TPM_RH_NULL, TPM_RH_OWNER, TPM_RH_PLATFORM,
    is_hierarchy_auth_handle,
};
use super::super::marshal::{BlobReader, Tpm2bError};
use super::super::nv::{
    TPMA_NV_AUTHREAD, TPMA_NV_AUTHWRITE, TPMA_NV_WRITTEN, index_auth_value, is_nv_index_handle,
    is_pin_index, read_uint64_data, resolve_index,
};
use super::super::pcr::pcr_auth_value_group;
use super::super::runtime::Tpm2Runtime;
use super::super::state::MAX_ACTIVE_SESSIONS;
use super::registry::{CommandDescriptor, NvAccess};

const TPM_RC_S: TpmResult = 0x800;
const TPM_RC_1: TpmResult = 0x100;

const MAX_SESSION_NUM: u32 = 3;
pub(super) const HMAC_SESSION_FIRST: u32 = 0x0200_0000;
pub(super) const POLICY_SESSION_FIRST: u32 = 0x0300_0000;
const SESSION_TPM2B_MAX: usize = 64;
const TPMA_SESSION_RESERVED: u8 = 0x18;
const TPMA_SESSION_PW_FORBIDDEN: u8 = 0xe6;
const TPMA_SESSION_CONTINUE_SESSION: u8 = 0x01;

pub(super) struct PasswordSession<'a> {
    password: &'a [u8],
}

impl core::fmt::Debug for PasswordSession<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PasswordSession").finish_non_exhaustive()
    }
}

fn session_handle_in_range(handle: u32) -> bool {
    let sessions = MAX_ACTIVE_SESSIONS as u32;
    (HMAC_SESSION_FIRST..HMAC_SESSION_FIRST + sessions).contains(&handle)
        || (POLICY_SESSION_FIRST..POLICY_SESSION_FIRST + sessions).contains(&handle)
}

fn read_session_tpm2b<'a>(
    reader: &mut BlobReader<'a>,
    error_index: TpmResult,
) -> Result<&'a [u8], TpmResult> {
    match reader.read_tpm2b(SESSION_TPM2B_MAX) {
        Ok(bytes) => Ok(bytes),
        Err(Tpm2bError::Truncated) => Err(TPM_RC_INSUFFICIENT + error_index),
        Err(Tpm2bError::SizeExceeded { .. }) => Err(TPM_RC_SIZE + error_index),
    }
}

pub(super) fn parse_session_area<'a>(
    auth_area: &'a [u8],
) -> Result<Vec<PasswordSession<'a>>, TpmResult> {
    let mut reader = BlobReader::new(auth_area);
    let mut sessions = Vec::new();
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
        let nonce = read_session_tpm2b(&mut reader, error_index)?;
        let attributes = reader
            .read_u8()
            .map_err(|_| TPM_RC_INSUFFICIENT + error_index)?;
        if attributes & TPMA_SESSION_RESERVED != 0 {
            return Err(TPM_RC_RESERVED_BITS + error_index);
        }
        let password = read_session_tpm2b(&mut reader, error_index)?;
        if handle != TPM_RS_PW {
            return Err(TPM_RC_REFERENCE_S0 + index);
        }
        if attributes & TPMA_SESSION_PW_FORBIDDEN != 0 {
            return Err(TPM_RC_ATTRIBUTES + error_index);
        }
        if !nonce.is_empty() {
            return Err(TPM_RC_NONCE + error_index);
        }
        sessions.push(PasswordSession { password });
        index += 1;
    }
    Ok(sessions)
}

pub(super) fn strip_trailing_zeros(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .rposition(|&byte| byte != 0)
        .map_or(0, |position| position + 1);
    &bytes[..end]
}

fn auth_value_group(runtime: &Tpm2Runtime, group: usize) -> Result<&[u8], TpmResult> {
    runtime
        .live
        .state_clear
        .as_ref()
        .and_then(|clear| clear.pcr_auth_values.get(group))
        .map(|secret| secret.as_bytes())
        .ok_or(TPM_RC_FAILURE)
}

fn hierarchy_auth_value(runtime: &Tpm2Runtime, handle: u32) -> Result<&[u8], TpmResult> {
    match handle {
        TPM_RH_PLATFORM => runtime
            .live
            .state_clear
            .as_ref()
            .map(|clear| clear.platform_auth.as_bytes())
            .ok_or(TPM_RC_FAILURE),
        _ => {
            let persistent = &runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?.persistent;
            match handle {
                TPM_RH_OWNER => Ok(persistent.owner_auth.as_bytes()),
                TPM_RH_ENDORSEMENT => Ok(persistent.endorsement_auth.as_bytes()),
                TPM_RH_LOCKOUT => Ok(persistent.lockout_auth.as_bytes()),
                _ => Err(TPM_RC_FAILURE),
            }
        }
    }
}

fn effective_auth_value(runtime: &Tpm2Runtime, handle: u32) -> Result<&[u8], TpmResult> {
    if handle == TPM_RH_NULL {
        return Ok(&[]);
    }
    if is_hierarchy_auth_handle(handle) {
        return hierarchy_auth_value(runtime, handle);
    }
    if is_nv_index_handle(handle) {
        return index_auth_value(runtime, handle).ok_or(TPM_RC_FAILURE);
    }
    match pcr_auth_value_group(handle as usize) {
        Some(group) => auth_value_group(runtime, group),
        None => Ok(&[]),
    }
}

fn nv_auth_value_is_available(
    runtime: &Tpm2Runtime,
    handle: u32,
    access: NvAccess,
) -> Result<bool, TpmResult> {
    let resolved = resolve_index(runtime, handle).ok_or(TPM_RC_FAILURE)?;
    let attributes = resolved.attributes();
    if access == NvAccess::Write {
        return Ok(attributes & TPMA_NV_AUTHWRITE != 0);
    }
    if is_pin_index(attributes) {
        if attributes & TPMA_NV_WRITTEN == 0 {
            return Ok(false);
        }
        let value = read_uint64_data(runtime, &resolved)?;
        let pin_count = (value >> 32) as u32;
        let pin_limit = value as u32;
        return Ok(pin_count < pin_limit);
    }
    Ok(attributes & TPMA_NV_AUTHREAD != 0)
}

fn policy_session_is_required(descriptor: &CommandDescriptor, index: usize, handle: u32) -> bool {
    descriptor
        .handles
        .get(index)
        .is_some_and(|spec| spec.admin_role)
        && is_nv_index_handle(handle)
}

fn auth_value_is_available(
    runtime: &Tpm2Runtime,
    handle: u32,
    access: NvAccess,
) -> Result<bool, TpmResult> {
    if is_nv_index_handle(handle) {
        return nv_auth_value_is_available(runtime, handle, access);
    }
    Ok(true)
}

fn password_matches(expected: &[u8], given: &[u8]) -> bool {
    let expected = strip_trailing_zeros(expected);
    let given = strip_trailing_zeros(given);
    if expected.len() != given.len() {
        return false;
    }
    bool::from(expected.ct_eq(given))
}

fn failed_password_code(runtime: &mut Tpm2Runtime, handle: u32) -> Result<TpmResult, TpmResult> {
    if !is_da_protected_handle(runtime, handle) {
        return Ok(TPM_RC_BAD_AUTH);
    }
    register_lockout_failure(runtime, handle)?;
    Ok(TPM_RC_AUTH_FAIL)
}

pub(super) fn authorize_sessions(
    runtime: &mut Tpm2Runtime,
    descriptor: &CommandDescriptor,
    handles: &[u32],
    sessions: &[PasswordSession<'_>],
) -> Result<(), TpmResult> {
    for (index, spec) in descriptor.handles.iter().enumerate() {
        if spec.user_auth && index >= sessions.len() {
            return Err(TPM_RC_AUTH_MISSING);
        }
    }
    for (index, session) in sessions.iter().enumerate() {
        let error_index = TPM_RC_S + TPM_RC_1 * (index as u32 + 1);
        let associated = descriptor
            .handles
            .get(index)
            .is_some_and(|spec| spec.user_auth)
            .then(|| handles.get(index).copied())
            .flatten();
        let Some(handle) = associated else {
            return Err(TPM_RC_HANDLE + error_index);
        };
        if is_da_protected_handle(runtime, handle) {
            check_locked_out(runtime, handle)?;
        }
        if policy_session_is_required(descriptor, index, handle) {
            return Err(TPM_RC_AUTH_TYPE);
        }
        if !auth_value_is_available(runtime, handle, descriptor.nv_access)? {
            return Err(TPM_RC_AUTH_UNAVAILABLE);
        }
        let matched = password_matches(effective_auth_value(runtime, handle)?, session.password);
        if !matched {
            return Err(failed_password_code(runtime, handle)? + error_index);
        }
    }
    Ok(())
}

pub(super) fn password_auth_response(session_count: usize) -> Vec<u8> {
    const PASSWORD_ACK: [u8; 5] = [0x00, 0x00, TPMA_SESSION_CONTINUE_SESSION, 0x00, 0x00];
    let mut out = Vec::with_capacity(session_count * PASSWORD_ACK.len());
    for _ in 0..session_count {
        out.extend_from_slice(&PASSWORD_ACK);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::dispatcher::CommandFrame;
    use super::super::output::CommandOutput;
    use super::super::registry::{CommandLifecycle, HandleKind, HandleSpec};
    use super::*;
    use crate::library::tpm2::persistent::{OwnedSecret, OwnedStateClearData};
    use crate::library::tpm2::runtime::{Tpm2Runtime, empty_state_runtime};
    use crate::library::tpm2::state::NUM_AUTHVALUE_PCR_GROUP;
    use crate::library::tpm2::volatile::IMPLEMENTATION_PCR;

    const SESSION1: TpmResult = TPM_RC_S + TPM_RC_1;
    const SESSION2: TpmResult = TPM_RC_S + TPM_RC_1 * 2;

    fn stub_handler(
        _runtime: &mut Tpm2Runtime,
        _frame: &CommandFrame<'_>,
    ) -> Result<CommandOutput, TpmResult> {
        Ok(CommandOutput::empty())
    }

    fn descriptor(handles: &'static [HandleSpec]) -> CommandDescriptor {
        CommandDescriptor {
            code: 0x0000_0182,
            attributes: 0,
            physical_presence: false,
            lifecycle: CommandLifecycle::RequiresStarted,
            handles,
            sessions_allowed: true,
            nv_access: NvAccess::Neither,
            handler: stub_handler,
        }
    }

    static ONE_AUTH_HANDLE: [HandleSpec; 1] = [HandleSpec {
        kind: HandleKind::PcrAllowNull,
        user_auth: true,
        admin_role: false,
    }];

    static TWO_AUTH_HANDLES: [HandleSpec; 2] = [
        HandleSpec {
            kind: HandleKind::PcrAllowNull,
            user_auth: true,
            admin_role: false,
        },
        HandleSpec {
            kind: HandleKind::PcrAllowNull,
            user_auth: true,
            admin_role: false,
        },
    ];

    fn session(password: &[u8]) -> PasswordSession<'_> {
        PasswordSession { password }
    }

    fn runtime_with_auth_values(values: [&[u8]; NUM_AUTHVALUE_PCR_GROUP]) -> Box<Tpm2Runtime> {
        let mut runtime = empty_state_runtime();
        runtime.live.state_clear = Some(OwnedStateClearData {
            sh_enable: true,
            eh_enable: true,
            ph_enable_nv: true,
            platform_alg: 0x0010,
            platform_policy: Vec::new(),
            platform_auth: OwnedSecret::from_vec(Vec::new()),
            pcr_save: core::array::from_fn(|_| None),
            pcr_auth_values: core::array::from_fn(|index| OwnedSecret::copy_of(values[index])),
        });
        runtime
    }

    #[test]
    fn a_wrong_password_is_decorated_with_the_first_session_number() {
        let mut runtime = empty_state_runtime();
        let descriptor = descriptor(&ONE_AUTH_HANDLE);
        assert_eq!(
            authorize_sessions(&mut runtime, &descriptor, &[10], &[session(b"wrong")]),
            Err(TPM_RC_BAD_AUTH + SESSION1)
        );
    }

    #[test]
    fn a_wrong_password_in_the_second_session_is_decorated_with_its_own_number() {
        let mut runtime = empty_state_runtime();
        let descriptor = descriptor(&TWO_AUTH_HANDLES);
        assert_eq!(
            authorize_sessions(
                &mut runtime,
                &descriptor,
                &[10, 11],
                &[session(&[]), session(b"wrong")]
            ),
            Err(TPM_RC_BAD_AUTH + SESSION2),
            "the second session's failure carries the second session's decoration"
        );
        assert_eq!(
            authorize_sessions(
                &mut runtime,
                &descriptor,
                &[10, 11],
                &[session(b"wrong"), session(&[])]
            ),
            Err(TPM_RC_BAD_AUTH + SESSION1),
            "the first failing session wins"
        );
    }

    #[test]
    fn correct_empty_passwords_authorize_every_session() {
        let mut runtime = empty_state_runtime();
        assert_eq!(
            authorize_sessions(
                &mut runtime,
                &descriptor(&ONE_AUTH_HANDLE),
                &[10],
                &[session(&[])]
            ),
            Ok(())
        );
        assert_eq!(
            authorize_sessions(
                &mut runtime,
                &descriptor(&TWO_AUTH_HANDLES),
                &[10, 11],
                &[session(&[]), session(&[0x00, 0x00])]
            ),
            Ok(()),
            "trailing zeros still compare equal to an empty authValue"
        );
    }

    #[test]
    fn a_missing_state_clear_is_an_undecorated_internal_failure() {
        let runtime = empty_state_runtime();
        assert!(runtime.live.state_clear.is_none());
        assert_eq!(auth_value_group(&runtime, 0), Err(TPM_RC_FAILURE));
    }

    #[test]
    fn an_out_of_range_auth_group_is_an_undecorated_internal_failure() {
        let runtime = runtime_with_auth_values([b"secret"]);
        assert_eq!(
            auth_value_group(&runtime, NUM_AUTHVALUE_PCR_GROUP),
            Err(TPM_RC_FAILURE)
        );
        assert_eq!(auth_value_group(&runtime, usize::MAX), Err(TPM_RC_FAILURE));
    }

    #[test]
    fn an_internal_failure_never_carries_a_session_decoration() {
        let runtime = empty_state_runtime();
        let error = auth_value_group(&runtime, 0).unwrap_err();
        assert_eq!(error, TPM_RC_FAILURE);
        for index in 1..=MAX_SESSION_NUM {
            assert_ne!(
                error,
                TPM_RC_FAILURE + TPM_RC_S + TPM_RC_1 * index,
                "a format-zero code must not be decorated for session {index}"
            );
        }
    }

    #[test]
    fn a_populated_auth_group_is_returned_verbatim() {
        let runtime = runtime_with_auth_values([b"secret"]);
        assert_eq!(auth_value_group(&runtime, 0), Ok(&b"secret"[..]));
    }

    #[test]
    fn every_pcr_handle_and_the_null_handle_have_an_empty_effective_auth_value() {
        let runtime = empty_state_runtime();
        for pcr in 0..IMPLEMENTATION_PCR as u32 {
            assert_eq!(
                effective_auth_value(&runtime, pcr),
                Ok(&[][..]),
                "PCR {pcr} is in no auth-value group in this configuration"
            );
        }
        assert_eq!(effective_auth_value(&runtime, TPM_RH_NULL), Ok(&[][..]));
    }

    #[test]
    fn password_comparison_ignores_only_trailing_zeros() {
        assert!(password_matches(&[], &[]));
        assert!(password_matches(&[], &[0x00, 0x00]));
        assert!(password_matches(&[0x00], &[]));
        assert!(password_matches(b"pw", &[b'p', b'w', 0x00]));
        assert!(!password_matches(b"pw", b"pW"));
        assert!(!password_matches(&[], b"pw"));
        assert!(!password_matches(&[0x00, 0x01], &[0x01, 0x00]));
    }

    #[test]
    fn equal_values_compare_equal_whatever_their_length() {
        assert!(password_matches(&[], &[]), "both empty");
        assert!(password_matches(&[0x7f], &[0x7f]), "equal single byte");
        assert!(
            password_matches(&[0xa5; 20], &[0xa5; 20]),
            "equal non-empty"
        );
        assert!(password_matches(&[0xaa; 64], &[0xaa; 64]), "equal maximum");
        assert!(
            password_matches(&[0x41, 0x42, 0x00], &[0x41, 0x42, 0x00, 0x00, 0x00]),
            "equal after trailing-zero normalization"
        );
    }

    #[test]
    fn all_zero_values_normalize_to_empty() {
        assert!(password_matches(&[0x00; 8], &[]));
        assert!(password_matches(&[], &[0x00; 64]));
        assert!(password_matches(&[0x00; 3], &[0x00; 20]));
    }

    #[test]
    fn a_mismatch_at_any_position_compares_unequal() {
        let expected = [0x10u8, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
        for position in 0..expected.len() {
            let mut given = expected;
            given[position] ^= 0x80;
            assert!(
                !password_matches(&expected, &given),
                "mismatch at byte {position}"
            );
        }
    }

    #[test]
    fn different_normalized_lengths_compare_unequal() {
        assert!(!password_matches(&[0x01], &[0x01, 0x02]));
        assert!(!password_matches(&[], &[0x01]));
        assert!(!password_matches(b"pw", b"pwd"));
        assert!(
            !password_matches(&[0x01, 0x00, 0x01], &[0x01]),
            "an interior zero is not stripped, so the lengths still differ"
        );
    }

    #[test]
    fn only_the_lockout_hierarchy_takes_the_dictionary_attack_path() {
        let mut runtime = empty_state_runtime();
        for handle in [
            TPM_RH_OWNER,
            TPM_RH_ENDORSEMENT,
            TPM_RH_PLATFORM,
            TPM_RH_NULL,
            0,
            23,
        ] {
            assert_eq!(
                failed_password_code(&mut runtime, handle),
                Ok(TPM_RC_BAD_AUTH),
                "handle {handle:#x} is DA exempt"
            );
        }
        assert_eq!(
            failed_password_code(&mut runtime, TPM_RH_LOCKOUT),
            Err(TPM_RC_FAILURE),
            "the lockout path records the failure first, and this runtime has no state"
        );
    }

    #[test]
    fn the_password_failure_codes_carry_the_session_decoration() {
        assert_eq!(TPM_RC_BAD_AUTH + SESSION1, 0x9a2);
        assert_eq!(TPM_RC_BAD_AUTH + SESSION2, 0xaa2);
        assert_eq!(TPM_RC_AUTH_FAIL + SESSION1, 0x98e);
        assert_eq!(TPM_RC_AUTH_FAIL + SESSION2, 0xa8e);
    }

    #[test]
    fn trailing_zeros_are_stripped_like_upstream() {
        assert_eq!(strip_trailing_zeros(&[]), &[] as &[u8]);
        assert_eq!(strip_trailing_zeros(&[0, 0, 0]), &[] as &[u8]);
        assert_eq!(strip_trailing_zeros(&[1, 2, 0, 0]), &[1, 2]);
        assert_eq!(strip_trailing_zeros(&[0, 1]), &[0, 1]);
        assert_eq!(strip_trailing_zeros(&[7]), &[7]);
    }

    #[test]
    fn password_session_debug_output_redacts_the_password() {
        let secret = [0x53, 0x65, 0x63, 0x72, 0x65, 0x74];
        let session = PasswordSession { password: &secret };
        let formatted = format!("{session:?}");
        assert_eq!(formatted, "PasswordSession { .. }");
    }

    #[test]
    fn parsed_password_borrows_the_command_bytes_without_copying() {
        let mut area = vec![0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x04];
        area.extend_from_slice(b"abcd");
        let sessions = parse_session_area(&area).expect("a valid password session");
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].password, b"abcd");
        assert!(
            core::ptr::eq(sessions[0].password.as_ptr(), area[9..].as_ptr()),
            "the password borrows from the authorization area"
        );
    }

    #[test]
    fn the_password_acknowledgement_bytes_match_upstream() {
        assert_eq!(password_auth_response(0), Vec::<u8>::new());
        assert_eq!(
            password_auth_response(1),
            [0x00, 0x00, 0x01, 0x00, 0x00],
            "empty nonce, continueSession, empty hmac"
        );
        assert_eq!(password_auth_response(2).len(), 10);
    }
}
