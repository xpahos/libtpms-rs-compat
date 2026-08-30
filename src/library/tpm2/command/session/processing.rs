use crate::library::constants::{
    TPM_RC_ATTRIBUTES, TPM_RC_AUTH_FAIL, TPM_RC_AUTH_MISSING, TPM_RC_AUTH_TYPE,
    TPM_RC_AUTH_UNAVAILABLE, TPM_RC_BAD_AUTH, TPM_RC_EXCLUSIVE, TPM_RC_EXPIRED, TPM_RC_FAILURE,
    TPM_RC_HANDLE, TPM_RC_INSUFFICIENT, TPM_RC_LOCALITY, TPM_RC_MODE, TPM_RC_NONCE,
    TPM_RC_PCR_CHANGED, TPM_RC_POLICY_CC, TPM_RC_POLICY_FAIL, TPM_RC_PP, TPM_RC_REFERENCE_S0,
    TPM_RC_RESERVED_BITS, TPM_RC_SIZE, TPM_RC_SYMMETRIC, TPM_RC_VALUE,
};
use crate::library::tpm2::algorithm::{TPM_ALG_NULL, TPM_ALG_XOR};
use crate::library::tpm2::command::core::registry::{CommandDescriptor, NvAccess};
use crate::library::tpm2::crypto::{
    Hasher, HmacState, kdfa, sym_block_size, sym_cfb_decrypt, sym_cfb_encrypt,
};
use crate::library::tpm2::dictionary_attack::{
    check_locked_out, is_da_protected_handle, register_lockout_failure,
};
pub(in crate::library::tpm2::command) use crate::library::tpm2::entity::strip_trailing_zeros;
use crate::library::tpm2::entity::{
    entity_auth_policy, entity_auth_value, entity_name, normalize_hierarchy_handle,
};
pub(in crate::library::tpm2::command) use crate::library::tpm2::hierarchy::TPM_RS_PW;
use crate::library::tpm2::hierarchy::{TPM_RH_NULL, TPM_RH_PLATFORM, TPM_RH_UNASSIGNED};
use crate::library::tpm2::live::RestoredVolatile;
use crate::library::tpm2::marshal::{BlobReader, BlobWriter, Tpm2bError};
use crate::library::tpm2::nv::{
    IndexWrite, TPMA_NV_AUTHREAD, TPMA_NV_AUTHWRITE, TPMA_NV_WRITTEN, is_nv_index_handle,
    is_pin_fail_index, is_pin_index, is_pin_pass_index, read_uint64_data, resolve_index,
};
use crate::library::tpm2::object::ATTR_PUBLIC_ONLY;
use crate::library::tpm2::object_create::{
    is_object_handle, object_auth_value, object_public_attributes, resolve_any_object,
};
use crate::library::tpm2::persistent::OwnedSecret;
use crate::library::tpm2::pp_list::physical_presence_is_required;
use crate::library::tpm2::random::generate_random;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::self_test::self_test_algorithm;
use crate::library::tpm2::sequence::sequence_kind;
use crate::library::tpm2::session::{
    SESSION_ATTR_CHECK_NV_WRITTEN, SESSION_ATTR_IS_AUDIT, SESSION_ATTR_IS_AUTH_VALUE_NEEDED,
    SESSION_ATTR_IS_BOUND, SESSION_ATTR_IS_CP_HASH_DEFINED, SESSION_ATTR_IS_DA_BOUND,
    SESSION_ATTR_IS_LOCKOUT_BOUND, SESSION_ATTR_IS_NAME_HASH_DEFINED,
    SESSION_ATTR_IS_PARAMETERS_HASH_DEFINED, SESSION_ATTR_IS_PASSWORD_NEEDED,
    SESSION_ATTR_IS_POLICY, SESSION_ATTR_IS_PP_REQUIRED, SESSION_ATTR_IS_TEMPLATE_HASH_DEFINED,
    SESSION_ATTR_IS_TRIAL_POLICY, SESSION_ATTR_NV_WRITTEN_STATE, digest_size, digests_equal,
    flush_session, is_policy_session_handle, is_session_handle, loaded_session, loaded_session_mut,
    reset_policy_data, set_start_time,
};
use crate::library::tpm2::state::MAX_ACTIVE_SESSIONS;
use crate::library::tpm2::template::{TPMA_OBJECT_ADMIN_WITH_POLICY, TPMA_OBJECT_USER_WITH_AUTH};
use crate::types::TpmResult;
use subtle::ConstantTimeEq;

const TPM_RC_S: TpmResult = 0x800;
const TPM_RC_1: TpmResult = 0x100;

#[cfg(test)]
pub(in crate::library::tpm2::command) const HMAC_SESSION_FIRST: u32 = 0x0200_0000;
#[cfg(test)]
pub(in crate::library::tpm2::command) const POLICY_SESSION_FIRST: u32 = 0x0300_0000;

const MAX_SESSION_NUM: usize = 3;

const NAME_HASH_ATTRIBUTE_LEVEL: u32 = 4;
const SESSION_TPM2B_MAX: usize = 64;
const UNDEFINED_INDEX: usize = usize::MAX;
const UNDEFINED_SESSION_INDEX: u32 = 0xffff;

const TPMA_SESSION_CONTINUE_SESSION: u8 = 0x01;
const TPMA_SESSION_AUDIT_EXCLUSIVE: u8 = 0x02;
const TPMA_SESSION_AUDIT_RESET: u8 = 0x04;
const TPMA_SESSION_RESERVED: u8 = 0x18;
const TPMA_SESSION_DECRYPT: u8 = 0x20;
const TPMA_SESSION_ENCRYPT: u8 = 0x40;
const TPMA_SESSION_AUDIT: u8 = 0x80;
const TPMA_SESSION_PW_FORBIDDEN: u8 = TPMA_SESSION_DECRYPT
    | TPMA_SESSION_ENCRYPT
    | TPMA_SESSION_AUDIT
    | TPMA_SESSION_AUDIT_EXCLUSIVE
    | TPMA_SESSION_AUDIT_RESET;

const CFB_LABEL: &[u8] = b"CFB\0";
const XOR_LABEL: &[u8] = b"XOR\0";

pub(in crate::library::tpm2::command) struct CommandSession<'a> {
    pub(in crate::library::tpm2::command) handle: u32,
    nonce_caller: &'a [u8],
    pub(in crate::library::tpm2::command) attributes: u8,
    auth: &'a [u8],
    associated: u32,
    include_auth: bool,
    cp_hash: Option<Vec<u8>>,
}

impl core::fmt::Debug for CommandSession<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CommandSession")
            .field("handle", &format_args!("{:#010x}", self.handle))
            .field("attributes", &format_args!("{:#04x}", self.attributes))
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub(in crate::library::tpm2::command) struct SessionArea<'a> {
    pub(in crate::library::tpm2::command) sessions: Vec<CommandSession<'a>>,
    decrypt_index: usize,
    encrypt_index: usize,
    audit_index: usize,
}

impl SessionArea<'_> {
    pub(in crate::library::tpm2::command) fn none() -> Self {
        Self {
            sessions: Vec::new(),
            decrypt_index: UNDEFINED_INDEX,
            encrypt_index: UNDEFINED_INDEX,
            audit_index: UNDEFINED_INDEX,
        }
    }
}

fn session_handle_in_range(handle: u32) -> bool {
    is_session_handle(handle) && (handle & 0x00ff_ffff) < MAX_ACTIVE_SESSIONS as u32
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

pub(in crate::library::tpm2::command) fn parse_session_area<'a>(
    runtime: &Tpm2Runtime,
    descriptor: &CommandDescriptor,
    auth_area: &'a [u8],
) -> Result<SessionArea<'a>, TpmResult> {
    let mut reader = BlobReader::new(auth_area);
    let mut area = SessionArea {
        sessions: Vec::new(),
        decrypt_index: UNDEFINED_INDEX,
        encrypt_index: UNDEFINED_INDEX,
        audit_index: UNDEFINED_INDEX,
    };
    let mut index: usize = 0;
    while !reader.remaining().is_empty() {
        let error_index = TPM_RC_S + TPM_RC_1 * (index as u32 + 1);
        if index == MAX_SESSION_NUM {
            return Err(TPM_RC_SIZE + error_index);
        }
        let handle = reader
            .read_u32()
            .map_err(|_| TPM_RC_INSUFFICIENT + error_index)?;
        if handle != TPM_RS_PW && !session_handle_in_range(handle) {
            return Err(TPM_RC_VALUE + error_index);
        }
        let nonce_caller = read_session_tpm2b(&mut reader, error_index)?;
        let attributes = reader
            .read_u8()
            .map_err(|_| TPM_RC_INSUFFICIENT + error_index)?;
        if attributes & TPMA_SESSION_RESERVED != 0 {
            return Err(TPM_RC_RESERVED_BITS + error_index);
        }
        let auth = read_session_tpm2b(&mut reader, error_index)?;

        let session = CommandSession {
            handle,
            nonce_caller,
            attributes,
            auth,
            associated: TPM_RH_UNASSIGNED,
            include_auth: false,
            cp_hash: None,
        };

        if handle == TPM_RS_PW {
            if attributes & TPMA_SESSION_PW_FORBIDDEN != 0 {
                return Err(TPM_RC_ATTRIBUTES + error_index);
            }
            if !nonce_caller.is_empty() {
                return Err(TPM_RC_NONCE + error_index);
            }
            area.sessions.push(session);
            index += 1;
            continue;
        }

        let Some(loaded) = loaded_session(&runtime.live, handle) else {
            return Err(TPM_RC_REFERENCE_S0 + index as u32);
        };
        let is_policy = loaded.attributes & SESSION_ATTR_IS_POLICY != 0;
        if is_policy != is_policy_session_handle(handle) {
            return Err(TPM_RC_HANDLE + error_index);
        }
        if area.sessions.iter().any(|earlier| earlier.handle == handle) {
            return Err(TPM_RC_HANDLE + error_index);
        }
        let symmetric_is_null = loaded.symmetric.algorithm == TPM_ALG_NULL;

        if attributes & TPMA_SESSION_DECRYPT != 0 {
            if descriptor.decrypt_size == 0 || area.decrypt_index != UNDEFINED_INDEX {
                return Err(TPM_RC_ATTRIBUTES + error_index);
            }
            if symmetric_is_null {
                return Err(TPM_RC_SYMMETRIC + error_index);
            }
            area.decrypt_index = index;
        }
        if attributes & TPMA_SESSION_ENCRYPT != 0 {
            if descriptor.encrypt_size == 0 || area.encrypt_index != UNDEFINED_INDEX {
                return Err(TPM_RC_ATTRIBUTES + error_index);
            }
            if symmetric_is_null {
                return Err(TPM_RC_SYMMETRIC + error_index);
            }
            area.encrypt_index = index;
        }
        if attributes & TPMA_SESSION_AUDIT != 0 {
            if area.audit_index != UNDEFINED_INDEX || is_policy_session_handle(handle) {
                return Err(TPM_RC_ATTRIBUTES + error_index);
            }
            if attributes & TPMA_SESSION_AUDIT_RESET == 0
                && loaded.attributes & SESSION_ATTR_IS_AUDIT != 0
                && attributes & TPMA_SESSION_AUDIT_EXCLUSIVE != 0
                && exclusive_audit_session(runtime) != handle
            {
                return Err(TPM_RC_EXCLUSIVE);
            }
            area.audit_index = index;
        }
        area.sessions.push(session);
        index += 1;
    }
    Ok(area)
}

pub(in crate::library::tpm2::command) fn exclusive_audit_session(runtime: &Tpm2Runtime) -> u32 {
    runtime
        .restored_volatile
        .as_ref()
        .map_or(TPM_RH_UNASSIGNED, |restored| {
            restored.exclusive_audit_session
        })
}

fn set_exclusive_audit_session(runtime: &mut Tpm2Runtime, handle: u32) {
    runtime
        .restored_volatile
        .get_or_insert_with(RestoredVolatile::power_on)
        .exclusive_audit_session = handle;
}

fn effective_auth_value(runtime: &Tpm2Runtime, handle: u32) -> Result<&[u8], TpmResult> {
    entity_auth_value(runtime, handle)
}

pub(in crate::library::tpm2::command) fn state_format_level(
    runtime: &Tpm2Runtime,
) -> Result<u32, TpmResult> {
    Ok(runtime
        .state
        .as_ref()
        .ok_or(TPM_RC_FAILURE)?
        .profile
        .state_format_level)
}

pub(in crate::library::tpm2::command) fn remove_session_association(
    runtime: &mut Tpm2Runtime,
    handle: u32,
) {
    let handle = normalize_hierarchy_handle(handle);
    if !runtime.removed_session_associations.contains(&handle) {
        runtime.removed_session_associations.push(handle);
    }
}

pub(in crate::library::tpm2::command) fn clear_session_associations(runtime: &mut Tpm2Runtime) {
    runtime.removed_session_associations.clear();
}

fn surviving_association(runtime: &Tpm2Runtime, associated: u32) -> u32 {
    if runtime.removed_session_associations.contains(&associated) {
        TPM_RH_NULL
    } else {
        associated
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

fn object_auth_value_is_available(
    runtime: &Tpm2Runtime,
    handle: u32,
    admin_role: bool,
) -> Result<bool, TpmResult> {
    let object = resolve_any_object(runtime, handle).ok_or(TPM_RC_FAILURE)?;
    if sequence_kind(object.attributes).is_some() {
        return Ok(true);
    }
    let attributes = object_public_attributes(runtime, handle).ok_or(TPM_RC_FAILURE)?;
    if object.attributes & ATTR_PUBLIC_ONLY != 0 || object_auth_value(runtime, handle).is_none() {
        return Ok(false);
    }
    Ok(attributes & TPMA_OBJECT_USER_WITH_AUTH != 0
        || (admin_role && attributes & TPMA_OBJECT_ADMIN_WITH_POLICY == 0))
}

fn auth_value_is_available(
    runtime: &Tpm2Runtime,
    handle: u32,
    access: NvAccess,
    admin_role: bool,
) -> Result<bool, TpmResult> {
    if is_nv_index_handle(handle) {
        return nv_auth_value_is_available(runtime, handle, access);
    }
    if is_object_handle(handle) {
        return object_auth_value_is_available(runtime, handle, admin_role);
    }
    Ok(true)
}

fn auth_policy_is_available(runtime: &Tpm2Runtime, handle: u32) -> Result<bool, TpmResult> {
    if is_object_handle(handle) {
        let object = resolve_any_object(runtime, handle).ok_or(TPM_RC_FAILURE)?;
        return Ok(
            object.attributes & ATTR_PUBLIC_ONLY == 0 && sequence_kind(object.attributes).is_none()
        );
    }
    let (_, policy) = entity_auth_policy(runtime, handle)?;
    Ok(!policy.is_empty())
}

fn policy_session_is_required(
    runtime: &Tpm2Runtime,
    descriptor: &CommandDescriptor,
    index: usize,
    handle: u32,
) -> bool {
    let Some(spec) = descriptor.handles.get(index) else {
        return false;
    };
    if spec.dup_role() {
        return true;
    }
    if !spec.admin_role() {
        return false;
    }
    if is_object_handle(handle) {
        return object_public_attributes(runtime, handle)
            .is_some_and(|attributes| attributes & TPMA_OBJECT_ADMIN_WITH_POLICY != 0);
    }
    true
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

pub(in crate::library::tpm2::command) fn record_session_state(
    runtime: &mut Tpm2Runtime,
    area: &SessionArea<'_>,
) {
    let surviving: Vec<u32> = area
        .sessions
        .iter()
        .map(|session| surviving_association(runtime, session.associated))
        .collect();
    let process = &mut runtime
        .restored_volatile
        .get_or_insert_with(RestoredVolatile::power_on)
        .session_process;
    process.decrypt_session_index = index_or_undefined(area.decrypt_index);
    process.encrypt_session_index = index_or_undefined(area.encrypt_index);
    process.audit_session_index = index_or_undefined(area.audit_index);
    for (index, session) in area.sessions.iter().enumerate() {
        process.session_handles[index] = session.handle;
        process.nonce_callers[index] = OwnedSecret::copy_of(session.nonce_caller);
        process.attributes[index] = session.attributes;
        process.input_auth_values[index] = if session.handle == TPM_RS_PW {
            OwnedSecret::copy_of(strip_trailing_zeros(session.auth))
        } else {
            OwnedSecret::copy_of(session.auth)
        };
        process.associated_handles[index] = surviving[index];
    }
}

fn index_or_undefined(index: usize) -> u32 {
    if index == UNDEFINED_INDEX {
        UNDEFINED_SESSION_INDEX
    } else {
        index as u32
    }
}

fn associate_handles(
    descriptor: &CommandDescriptor,
    handles: &[u32],
    area: &mut SessionArea<'_>,
) -> Result<(), TpmResult> {
    for (index, spec) in descriptor.handles.iter().enumerate() {
        if !spec.user_auth {
            continue;
        }
        if index >= area.sessions.len() {
            return Err(TPM_RC_AUTH_MISSING);
        }
        let Some(&handle) = handles.get(index) else {
            return Err(TPM_RC_AUTH_MISSING);
        };
        area.sessions[index].associated = normalize_hierarchy_handle(handle);
    }
    Ok(())
}

pub(in crate::library::tpm2::command) struct CommandContext<'a> {
    pub(in crate::library::tpm2::command) code: u32,
    pub(in crate::library::tpm2::command) handles: &'a [u32],
    pub(in crate::library::tpm2::command) parameters: &'a [u8],
}

pub(in crate::library::tpm2::command) fn compute_cp_hash(
    runtime: &mut Tpm2Runtime,
    context: &CommandContext<'_>,
    hash_alg: u16,
) -> Result<Vec<u8>, TpmResult> {
    self_test_algorithm(runtime, hash_alg)?;
    let mut hasher = Hasher::new(hash_alg).ok_or(TPM_RC_FAILURE)?;
    hasher.update(&context.code.to_be_bytes());
    for &handle in context.handles {
        hasher.update(&entity_name(runtime, handle)?);
    }
    hasher.update(context.parameters);
    Ok(hasher.finalize())
}

pub(in crate::library::tpm2::command) fn compute_rp_hash(
    runtime: &mut Tpm2Runtime,
    code: u32,
    parameters: &[u8],
    hash_alg: u16,
) -> Result<Vec<u8>, TpmResult> {
    self_test_algorithm(runtime, hash_alg)?;
    let mut hasher = Hasher::new(hash_alg).ok_or(TPM_RC_FAILURE)?;
    hasher.update(&0u32.to_be_bytes());
    hasher.update(&code.to_be_bytes());
    hasher.update(parameters);
    Ok(hasher.finalize())
}

fn hmac_key(runtime: &Tpm2Runtime, session: &CommandSession<'_>) -> Result<Vec<u8>, TpmResult> {
    let loaded = loaded_session(&runtime.live, session.handle).ok_or(TPM_RC_FAILURE)?;
    let mut key = loaded.session_key.as_bytes().to_vec();
    if session.include_auth {
        let associated = surviving_association(runtime, session.associated);
        key.extend_from_slice(strip_trailing_zeros(effective_auth_value(
            runtime, associated,
        )?));
    }
    Ok(key)
}

fn ensure_cp_hash(
    runtime: &mut Tpm2Runtime,
    context: &CommandContext<'_>,
    area: &mut SessionArea<'_>,
    index: usize,
) -> Result<Vec<u8>, TpmResult> {
    if let Some(cached) = &area.sessions[index].cp_hash {
        return Ok(cached.clone());
    }
    let hash_alg = loaded_session(&runtime.live, area.sessions[index].handle)
        .ok_or(TPM_RC_FAILURE)?
        .auth_hash_alg;
    let cp_hash = compute_cp_hash(runtime, context, hash_alg)?;
    area.sessions[index].cp_hash = Some(cp_hash.clone());
    Ok(cp_hash)
}

fn command_hmac(
    runtime: &mut Tpm2Runtime,
    context: &CommandContext<'_>,
    area: &mut SessionArea<'_>,
    index: usize,
) -> Result<Vec<u8>, TpmResult> {
    let session = &area.sessions[index];
    let hash_alg = loaded_session(&runtime.live, session.handle)
        .ok_or(TPM_RC_FAILURE)?
        .auth_hash_alg;
    let key = hmac_key(runtime, session)?;
    if key.is_empty() && session.auth.is_empty() {
        return Ok(Vec::new());
    }

    let mut extra_nonces: Vec<Vec<u8>> = Vec::new();
    if index == 0 && session.associated != TPM_RH_UNASSIGNED {
        if area.decrypt_index != UNDEFINED_INDEX && area.decrypt_index != index {
            extra_nonces.push(session_nonce_tpm(
                runtime,
                &area.sessions[area.decrypt_index],
            )?);
        }
        if area.encrypt_index != UNDEFINED_INDEX
            && area.encrypt_index != index
            && area.encrypt_index != area.decrypt_index
        {
            extra_nonces.push(session_nonce_tpm(
                runtime,
                &area.sessions[area.encrypt_index],
            )?);
        }
    }

    let cp_hash = ensure_cp_hash(runtime, context, area, index)?;
    let session = &area.sessions[index];
    let nonce_tpm = session_nonce_tpm(runtime, session)?;
    let mut hmac = HmacState::new(hash_alg, &key).ok_or(TPM_RC_FAILURE)?;
    hmac.update(&cp_hash);
    hmac.update(session.nonce_caller);
    hmac.update(&nonce_tpm);
    for nonce in &extra_nonces {
        hmac.update(nonce);
    }
    hmac.update(&[session.attributes]);
    Ok(hmac.finalize())
}

fn session_nonce_tpm(
    runtime: &Tpm2Runtime,
    session: &CommandSession<'_>,
) -> Result<Vec<u8>, TpmResult> {
    Ok(loaded_session(&runtime.live, session.handle)
        .ok_or(TPM_RC_FAILURE)?
        .nonce_tpm
        .as_bytes()
        .to_vec())
}

fn check_session_hmac(
    runtime: &mut Tpm2Runtime,
    context: &CommandContext<'_>,
    area: &mut SessionArea<'_>,
    index: usize,
) -> Result<TpmResult, TpmResult> {
    let expected = command_hmac(runtime, context, area, index)?;
    let session = &area.sessions[index];
    let matched = expected.len() == session.auth.len() && bool::from(expected.ct_eq(session.auth));
    if matched {
        return Ok(0);
    }
    failed_password_code(runtime, session.associated)
}

fn check_policy_session(
    runtime: &mut Tpm2Runtime,
    descriptor: &CommandDescriptor,
    context: &CommandContext<'_>,
    area: &mut SessionArea<'_>,
    index: usize,
) -> Result<(), TpmResult> {
    let session = &area.sessions[index];
    if context.code == crate::library::tpm2::command::core::registry::TPM_CC_POLICY_SECRET {
        let loaded = loaded_session(&runtime.live, session.handle).ok_or(TPM_RC_FAILURE)?;
        if loaded.attributes & (SESSION_ATTR_IS_PASSWORD_NEEDED | SESSION_ATTR_IS_AUTH_VALUE_NEEDED)
            == 0
        {
            return Err(TPM_RC_MODE);
        }
    }
    let loaded = loaded_session(&runtime.live, session.handle).ok_or(TPM_RC_FAILURE)?;
    let pcr_counter = runtime
        .live
        .state_reset
        .as_ref()
        .ok_or(TPM_RC_FAILURE)?
        .pcr_counter;
    if loaded.pcr_counter != 0 && loaded.pcr_counter != pcr_counter {
        return Err(TPM_RC_PCR_CHANGED);
    }

    let (policy_alg, policy) = entity_auth_policy(runtime, session.associated)?;
    let loaded = loaded_session(&runtime.live, session.handle).ok_or(TPM_RC_FAILURE)?;
    if loaded.audit_digest.len() != policy.len() || !bool::from(loaded.audit_digest.ct_eq(&policy))
    {
        return Err(TPM_RC_POLICY_FAIL);
    }
    if policy_alg != loaded.auth_hash_alg {
        return Err(TPM_RC_POLICY_FAIL);
    }
    if loaded.timeout != 0 {
        let epoch = runtime
            .state
            .as_ref()
            .ok_or(TPM_RC_FAILURE)?
            .persistent
            .time_epoch;
        if loaded.timeout < runtime.timer.time_ms || loaded.epoch != epoch {
            return Err(TPM_RC_EXPIRED);
        }
    }
    if loaded.command_code != 0 {
        if loaded.command_code != context.code {
            return Err(TPM_RC_POLICY_CC);
        }
    } else if descriptor
        .handles
        .get(index)
        .is_some_and(|spec| spec.policy_only_role())
    {
        return Err(TPM_RC_POLICY_FAIL);
    }
    if loaded.command_locality != 0 {
        let locality = u32::from(runtime.locality);
        let allowed = if locality < 5 {
            loaded.command_locality & (1 << locality) != 0 && loaded.command_locality <= 31
        } else if locality > 31 {
            u32::from(loaded.command_locality) == u32::from(locality)
        } else {
            false
        };
        if !allowed {
            return Err(TPM_RC_LOCALITY);
        }
    }
    if loaded.attributes & SESSION_ATTR_IS_PP_REQUIRED != 0 && !runtime.physical_presence {
        return Err(TPM_RC_PP);
    }
    check_policy_restriction(runtime, context, area, index)?;
    check_policy_nv_written(runtime, area, index)
}

fn check_policy_restriction(
    runtime: &mut Tpm2Runtime,
    context: &CommandContext<'_>,
    area: &mut SessionArea<'_>,
    index: usize,
) -> Result<(), TpmResult> {
    let handle = area.sessions[index].handle;
    let loaded = loaded_session(&runtime.live, handle).ok_or(TPM_RC_FAILURE)?;
    let expected = loaded.bound_entity.clone();
    if expected.is_empty() {
        return Ok(());
    }
    let attributes = loaded.attributes;
    let hash_alg = loaded.auth_hash_alg;
    let tagged_name_hash = state_format_level(runtime)? >= NAME_HASH_ATTRIBUTE_LEVEL;
    let matched = if attributes & SESSION_ATTR_IS_CP_HASH_DEFINED != 0 {
        let actual = ensure_cp_hash(runtime, context, area, index)?;
        digests_equal(&expected, &actual)
    } else if tagged_name_hash && attributes & SESSION_ATTR_IS_NAME_HASH_DEFINED != 0 {
        compare_name_hash(runtime, context, hash_alg, &expected)?
    } else if attributes & SESSION_ATTR_IS_PARAMETERS_HASH_DEFINED != 0 {
        compare_parameters_hash(runtime, context, hash_alg, &expected)?
    } else if attributes & SESSION_ATTR_IS_TEMPLATE_HASH_DEFINED != 0 {
        compare_template_hash(runtime, context, hash_alg, &expected)?
    } else if !tagged_name_hash {
        compare_name_hash(runtime, context, hash_alg, &expected)?
    } else {
        false
    };
    if matched {
        Ok(())
    } else {
        Err(TPM_RC_POLICY_FAIL)
    }
}

fn compare_name_hash(
    runtime: &mut Tpm2Runtime,
    context: &CommandContext<'_>,
    hash_alg: u16,
    expected: &[u8],
) -> Result<bool, TpmResult> {
    self_test_algorithm(runtime, hash_alg)?;
    let mut hasher = Hasher::new(hash_alg).ok_or(TPM_RC_FAILURE)?;
    for &handle in context.handles {
        hasher.update(&entity_name(runtime, handle)?);
    }
    Ok(digests_equal(expected, &hasher.finalize()))
}

fn compare_parameters_hash(
    runtime: &mut Tpm2Runtime,
    context: &CommandContext<'_>,
    hash_alg: u16,
    expected: &[u8],
) -> Result<bool, TpmResult> {
    self_test_algorithm(runtime, hash_alg)?;
    let mut hasher = Hasher::new(hash_alg).ok_or(TPM_RC_FAILURE)?;
    hasher.update(&context.code.to_be_bytes());
    hasher.update(context.parameters);
    Ok(digests_equal(expected, &hasher.finalize()))
}

fn compare_template_hash(
    runtime: &mut Tpm2Runtime,
    context: &CommandContext<'_>,
    hash_alg: u16,
    expected: &[u8],
) -> Result<bool, TpmResult> {
    use crate::library::tpm2::command::core::registry::{
        TPM_CC_CREATE, TPM_CC_CREATE_LOADED, TPM_CC_CREATE_PRIMARY,
    };
    if !matches!(
        context.code,
        TPM_CC_CREATE | TPM_CC_CREATE_PRIMARY | TPM_CC_CREATE_LOADED
    ) {
        return Ok(false);
    }
    let mut reader = BlobReader::new(context.parameters);
    if reader.read_tpm2b(usize::from(u16::MAX)).is_err() {
        return Ok(false);
    }
    let Ok(template) = reader.read_tpm2b(usize::from(u16::MAX)) else {
        return Ok(false);
    };
    self_test_algorithm(runtime, hash_alg)?;
    let mut hasher = Hasher::new(hash_alg).ok_or(TPM_RC_FAILURE)?;
    hasher.update(template);
    Ok(digests_equal(expected, &hasher.finalize()))
}

fn check_policy_nv_written(
    runtime: &Tpm2Runtime,
    area: &SessionArea<'_>,
    index: usize,
) -> Result<(), TpmResult> {
    let handle = area.sessions[index].handle;
    let associated = area.sessions[index].associated;
    let loaded = loaded_session(&runtime.live, handle).ok_or(TPM_RC_FAILURE)?;
    if loaded.attributes & SESSION_ATTR_CHECK_NV_WRITTEN == 0 {
        return Ok(());
    }
    if !is_nv_index_handle(associated) {
        return Err(TPM_RC_POLICY_FAIL);
    }
    let required = loaded.attributes & SESSION_ATTR_NV_WRITTEN_STATE != 0;
    let index = resolve_index(runtime, associated).ok_or(TPM_RC_FAILURE)?;
    if (index.attributes() & TPMA_NV_WRITTEN != 0) != required {
        return Err(TPM_RC_POLICY_FAIL);
    }
    Ok(())
}

fn check_auth_session(
    runtime: &mut Tpm2Runtime,
    descriptor: &CommandDescriptor,
    context: &CommandContext<'_>,
    area: &mut SessionArea<'_>,
    index: usize,
) -> Result<(), TpmResult> {
    let handle = area.sessions[index].handle;
    let associated = area.sessions[index].associated;
    let admin_role = descriptor
        .handles
        .get(index)
        .is_some_and(|spec| spec.admin_role());

    if associated == TPM_RH_PLATFORM
        && physical_presence_is_required(runtime, context.code)
        && !runtime.physical_presence
    {
        return Err(TPM_RC_PP);
    }

    let auth_used = if handle == TPM_RS_PW {
        area.sessions[index].include_auth = true;
        true
    } else {
        let bound = session_is_bind_entity(runtime, handle, associated)?;
        let loaded = loaded_session(&runtime.live, handle).ok_or(TPM_RC_FAILURE)?;
        let include = if is_policy_session_handle(handle) {
            loaded.attributes
                & (SESSION_ATTR_IS_AUTH_VALUE_NEEDED | SESSION_ATTR_IS_PASSWORD_NEEDED)
                != 0
        } else {
            !bound
        };
        area.sessions[index].include_auth = include;
        include
    };

    if auth_used && is_da_protected_handle(runtime, associated) {
        check_locked_out(runtime, associated)?;
    }

    if !is_policy_session_handle(handle) {
        if policy_session_is_required(runtime, descriptor, index, associated) {
            return Err(TPM_RC_AUTH_TYPE);
        }
        if !auth_value_is_available(runtime, associated, descriptor.nv_access, admin_role)? {
            return Err(TPM_RC_AUTH_UNAVAILABLE);
        }
    } else {
        if !auth_policy_is_available(runtime, associated)? {
            return Err(TPM_RC_AUTH_UNAVAILABLE);
        }
        check_policy_session(runtime, descriptor, context, area, index)?;
    }

    let password_needed = handle == TPM_RS_PW
        || loaded_session(&runtime.live, handle)
            .is_some_and(|loaded| loaded.attributes & SESSION_ATTR_IS_PASSWORD_NEEDED != 0);
    let code = if password_needed {
        let matched = password_matches(
            effective_auth_value(runtime, associated)?,
            area.sessions[index].auth,
        );
        if matched {
            0
        } else {
            failed_password_code(runtime, associated)?
        }
    } else {
        check_session_hmac(runtime, context, area, index)?
    };
    if auth_used && is_nv_index_handle(associated) {
        update_pin_index(runtime, associated, code == 0)?;
    }
    if code != 0 {
        return Err(code);
    }
    Ok(())
}

fn update_pin_index(
    runtime: &mut Tpm2Runtime,
    handle: u32,
    authorized: bool,
) -> Result<(), TpmResult> {
    let resolved = resolve_index(runtime, handle).ok_or(TPM_RC_FAILURE)?;
    let attributes = resolved.attributes();
    let fail_index = is_pin_fail_index(attributes);
    let pass_index = is_pin_pass_index(attributes) && authorized;
    if attributes & TPMA_NV_WRITTEN == 0 || !(fail_index || pass_index) {
        return Ok(());
    }
    let value = read_uint64_data(runtime, &resolved)?;
    let limit = value as u32;
    let count = (value >> 32) as u32;
    let updated = if fail_index {
        if authorized { 0 } else { count.wrapping_add(1) }
    } else {
        count.wrapping_add(1)
    };
    let data = ((u64::from(updated) << 32) | u64::from(limit))
        .to_be_bytes()
        .to_vec();
    crate::library::tpm2::command::nv::write::apply_write(
        runtime,
        &resolved,
        IndexWrite { offset: 0, data },
        false,
    )
}

fn session_is_bind_entity(
    runtime: &Tpm2Runtime,
    handle: u32,
    associated: u32,
) -> Result<bool, TpmResult> {
    let loaded = loaded_session(&runtime.live, handle).ok_or(TPM_RC_FAILURE)?;
    if loaded.attributes & SESSION_ATTR_IS_BOUND == 0 {
        return Ok(false);
    }
    let expected = loaded.bound_entity.clone();
    let candidate = bound_entity_value(runtime, associated)?;
    Ok(digests_equal(&expected, &candidate))
}

pub(in crate::library::tpm2::command) fn bound_entity_value(
    runtime: &Tpm2Runtime,
    handle: u32,
) -> Result<Vec<u8>, TpmResult> {
    use crate::library::tpm2::public::NAME_SIZE;
    let name = entity_name(runtime, handle)?;
    let auth = strip_trailing_zeros(effective_auth_value(runtime, handle)?).to_vec();
    let mut buffer = vec![0u8; NAME_SIZE];
    let copied = name.len().min(NAME_SIZE);
    buffer[..copied].copy_from_slice(&name[..copied]);
    for (index, byte) in auth.iter().enumerate() {
        let at = NAME_SIZE - auth.len() + index;
        buffer[at] ^= byte;
    }
    Ok(buffer)
}

pub(in crate::library::tpm2::command) fn authorize_sessions(
    runtime: &mut Tpm2Runtime,
    descriptor: &CommandDescriptor,
    handles: &[u32],
    context: &CommandContext<'_>,
    area: &mut SessionArea<'_>,
) -> Result<(), TpmResult> {
    associate_handles(descriptor, handles, area)?;

    for index in 0..area.sessions.len() {
        let error_index = TPM_RC_S + TPM_RC_1 * (index as u32 + 1);
        let handle = area.sessions[index].handle;
        let attributes = area.sessions[index].attributes;
        if handle == TPM_RS_PW {
            if area.sessions[index].associated == TPM_RH_UNASSIGNED {
                return Err(TPM_RC_HANDLE + error_index);
            }
        } else {
            let loaded = loaded_session(&runtime.live, handle).ok_or(TPM_RC_FAILURE)?;
            if loaded.attributes & SESSION_ATTR_IS_TRIAL_POLICY != 0 {
                return Err(TPM_RC_ATTRIBUTES + error_index);
            }
            if loaded.attributes & SESSION_ATTR_IS_DA_BOUND != 0 {
                let lockout_bound = loaded.attributes & SESSION_ATTR_IS_LOCKOUT_BOUND != 0;
                check_locked_out_for_binding(runtime, lockout_bound)?;
            }
            if attributes & TPMA_SESSION_AUDIT != 0 {
                ensure_cp_hash(runtime, context, area, index)?;
            }
        }

        if area.sessions[index].associated != TPM_RH_UNASSIGNED {
            check_auth_session(runtime, descriptor, context, area, index)
                .map_err(|code| decorate(code, error_index))?;
        } else {
            if attributes & (TPMA_SESSION_AUDIT | TPMA_SESSION_ENCRYPT | TPMA_SESSION_DECRYPT) == 0
            {
                return Err(TPM_RC_ATTRIBUTES + error_index);
            }
            area.sessions[index].include_auth = false;
            let code = check_session_hmac(runtime, context, area, index)
                .map_err(|code| decorate(code, error_index))?;
            if code != 0 {
                return Err(decorate(code, error_index));
            }
        }
    }
    Ok(())
}

fn decorate(code: TpmResult, error_index: TpmResult) -> TpmResult {
    if code & 0x080 != 0 && code & 0xf40 == 0 {
        code + error_index
    } else {
        code
    }
}

fn check_locked_out_for_binding(
    runtime: &mut Tpm2Runtime,
    lockout_bound: bool,
) -> Result<(), TpmResult> {
    let handle = if lockout_bound {
        crate::library::tpm2::hierarchy::TPM_RH_LOCKOUT
    } else {
        TPM_RH_NULL
    };
    check_locked_out(runtime, handle)
}

pub(in crate::library::tpm2::command) fn decrypt_first_parameter(
    runtime: &mut Tpm2Runtime,
    descriptor: &CommandDescriptor,
    area: &SessionArea<'_>,
    parameters: &[u8],
) -> Result<Option<Vec<u8>>, TpmResult> {
    if area.decrypt_index == UNDEFINED_INDEX {
        return Ok(None);
    }
    let index = area.decrypt_index;
    let session = &area.sessions[index];
    let error_index = TPM_RC_S + TPM_RC_1 * (index as u32 + 1);
    let extra = if session.associated == TPM_RH_UNASSIGNED {
        Vec::new()
    } else {
        strip_trailing_zeros(effective_auth_value(runtime, session.associated)?).to_vec()
    };
    let _ = descriptor;

    let mut buffer = parameters.to_vec();
    let size = usize::from(u16::from_be_bytes(
        buffer
            .get(..2)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(TPM_RC_INSUFFICIENT + error_index)?,
    ));
    if size > buffer.len() - 2 {
        return Err(TPM_RC_SIZE + error_index);
    }
    let nonce_caller = session.nonce_caller.to_vec();
    let nonce_tpm = session_nonce_tpm(runtime, session)?;
    apply_parameter_cipher(
        runtime,
        session.handle,
        &extra,
        &nonce_caller,
        &nonce_tpm,
        &mut buffer[2..2 + size],
        true,
    )?;
    Ok(Some(buffer))
}

fn apply_parameter_cipher(
    runtime: &mut Tpm2Runtime,
    handle: u32,
    extra: &[u8],
    nonce_newer: &[u8],
    nonce_older: &[u8],
    data: &mut [u8],
    decrypt: bool,
) -> Result<(), TpmResult> {
    let loaded = loaded_session(&runtime.live, handle).ok_or(TPM_RC_FAILURE)?;
    let hash_alg = loaded.auth_hash_alg;
    let symmetric = loaded.symmetric;
    let mut key = loaded.session_key.as_bytes().to_vec();
    key.extend_from_slice(extra);

    if symmetric.algorithm == TPM_ALG_XOR {
        self_test_algorithm(runtime, hash_alg)?;
        let mask = kdfa(
            hash_alg,
            &key,
            XOR_LABEL,
            nonce_newer,
            nonce_older,
            (data.len() * 8) as u32,
        )
        .ok_or(TPM_RC_FAILURE)?;
        for (byte, mask_byte) in data.iter_mut().zip(mask.iter()) {
            *byte ^= mask_byte;
        }
        return Ok(());
    }

    let key_bits = symmetric.key_bits.ok_or(TPM_RC_FAILURE)?;
    let block_size = sym_block_size(symmetric.algorithm).ok_or(TPM_RC_SYMMETRIC)?;
    let key_bytes = usize::from(key_bits).div_ceil(8);
    self_test_algorithm(runtime, hash_alg)?;
    let material = kdfa(
        hash_alg,
        &key,
        CFB_LABEL,
        nonce_newer,
        nonce_older,
        (key_bytes + block_size) as u32 * 8,
    )
    .ok_or(TPM_RC_FAILURE)?;
    let (cipher_key, iv) = material.split_at(key_bytes);
    if decrypt {
        sym_cfb_decrypt(symmetric.algorithm, cipher_key, iv, data)
    } else {
        sym_cfb_encrypt(symmetric.algorithm, cipher_key, iv, data)
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) enum ResponseFault {
    ResponseHmac,
    AuditInit,
    AuditExtend,
    SecondSession,
    BeforeFlush,
}

#[cfg(test)]
thread_local! {
    static RESPONSE_FAULT: core::cell::Cell<Option<ResponseFault>> =
        const { core::cell::Cell::new(None) };
}

#[cfg(test)]
pub(in crate::library::tpm2) fn inject_response_fault(fault: Option<ResponseFault>) {
    RESPONSE_FAULT.with(|cell| cell.set(fault));
}

#[cfg(test)]
fn fault_point(fault: ResponseFault) -> Result<(), TpmResult> {
    if RESPONSE_FAULT.with(core::cell::Cell::get) == Some(fault) {
        return Err(TPM_RC_FAILURE);
    }
    Ok(())
}

pub(in crate::library::tpm2::command) fn build_response_sessions(
    runtime: &mut Tpm2Runtime,
    descriptor: &CommandDescriptor,
    code: u32,
    parameters: &mut Vec<u8>,
    area: &mut SessionArea<'_>,
    tagged: bool,
    audit_cp_hash: Option<&[u8]>,
) -> Result<Vec<u8>, TpmResult> {
    if tagged {
        update_all_nonce_tpm(runtime, area)?;
        encrypt_first_parameter(runtime, area, parameters)?;
    }
    update_audit_sessions(runtime, descriptor, code, parameters, area)?;
    crate::library::tpm2::command::administration::command_audit_state::update(
        runtime,
        descriptor,
        audit_cp_hash,
        parameters,
    )?;
    if !tagged {
        return Ok(Vec::new());
    }

    let mut writer = BlobWriter::new();
    let mut flushed: Vec<u32> = Vec::new();
    for index in 0..area.sessions.len() {
        #[cfg(test)]
        if index == 1 {
            fault_point(ResponseFault::SecondSession)?;
        }
        let handle = area.sessions[index].handle;
        let (nonce, auth) = if handle == TPM_RS_PW {
            area.sessions[index].attributes |= TPMA_SESSION_CONTINUE_SESSION;
            (Vec::new(), Vec::new())
        } else {
            let password_needed = is_policy_session_handle(handle)
                && loaded_session(&runtime.live, handle)
                    .is_some_and(|loaded| loaded.attributes & SESSION_ATTR_IS_PASSWORD_NEEDED != 0);
            let auth = if password_needed {
                Vec::new()
            } else {
                response_hmac(runtime, code, parameters, area, index)?
            };
            let nonce = session_nonce_tpm(runtime, &area.sessions[index])?;
            update_internal_session(runtime, area, index)?;
            (nonce, auth)
        };
        writer.write_tpm2b(&nonce).map_err(|_| TPM_RC_FAILURE)?;
        writer.write_u8(area.sessions[index].attributes);
        writer.write_tpm2b(&auth).map_err(|_| TPM_RC_FAILURE)?;
        if area.sessions[index].attributes & TPMA_SESSION_CONTINUE_SESSION == 0
            && handle != TPM_RS_PW
        {
            flushed.push(handle);
        }
    }
    #[cfg(test)]
    fault_point(ResponseFault::BeforeFlush)?;
    for handle in flushed {
        flush_session(&mut runtime.live, handle);
    }
    Ok(writer.into_bytes())
}

fn update_all_nonce_tpm(
    runtime: &mut Tpm2Runtime,
    area: &SessionArea<'_>,
) -> Result<(), TpmResult> {
    for session in &area.sessions {
        if session.handle == TPM_RS_PW {
            continue;
        }
        let size = loaded_session(&runtime.live, session.handle)
            .ok_or(TPM_RC_FAILURE)?
            .nonce_tpm
            .as_bytes()
            .len();
        let fresh = generate_random(runtime, size)?;
        loaded_session_mut(&mut runtime.live, session.handle)
            .ok_or(TPM_RC_FAILURE)?
            .nonce_tpm = OwnedSecret::from_vec(fresh);
    }
    Ok(())
}

fn encrypt_first_parameter(
    runtime: &mut Tpm2Runtime,
    area: &SessionArea<'_>,
    parameters: &mut [u8],
) -> Result<(), TpmResult> {
    if area.encrypt_index == UNDEFINED_INDEX {
        return Ok(());
    }
    let session = &area.sessions[area.encrypt_index];
    let extra = if session.associated == TPM_RH_UNASSIGNED {
        Vec::new()
    } else {
        let associated = surviving_association(runtime, session.associated);
        strip_trailing_zeros(effective_auth_value(runtime, associated)?).to_vec()
    };
    let Some(size_bytes) = parameters.get(..2) else {
        return Ok(());
    };
    let size = usize::from(u16::from_be_bytes(
        size_bytes.try_into().expect("two bytes"),
    ));
    if size + 2 > parameters.len() {
        return Ok(());
    }
    let nonce_caller = session.nonce_caller.to_vec();
    let nonce_tpm = session_nonce_tpm(runtime, session)?;
    apply_parameter_cipher(
        runtime,
        session.handle,
        &extra,
        &nonce_tpm,
        &nonce_caller,
        &mut parameters[2..2 + size],
        false,
    )
}

fn response_hmac(
    runtime: &mut Tpm2Runtime,
    code: u32,
    parameters: &[u8],
    area: &SessionArea<'_>,
    index: usize,
) -> Result<Vec<u8>, TpmResult> {
    #[cfg(test)]
    fault_point(ResponseFault::ResponseHmac)?;
    let session = &area.sessions[index];
    let hash_alg = loaded_session(&runtime.live, session.handle)
        .ok_or(TPM_RC_FAILURE)?
        .auth_hash_alg;
    let key = hmac_key(runtime, session)?;
    if key.is_empty() && session.auth.is_empty() {
        return Ok(Vec::new());
    }
    let rp_hash = compute_rp_hash(runtime, code, parameters, hash_alg)?;
    let nonce_tpm = session_nonce_tpm(runtime, session)?;
    let mut hmac = HmacState::new(hash_alg, &key).ok_or(TPM_RC_FAILURE)?;
    hmac.update(&rp_hash);
    hmac.update(&nonce_tpm);
    hmac.update(session.nonce_caller);
    hmac.update(&[session.attributes]);
    Ok(hmac.finalize())
}

fn update_internal_session(
    runtime: &mut Tpm2Runtime,
    area: &SessionArea<'_>,
    index: usize,
) -> Result<(), TpmResult> {
    let session = &area.sessions[index];
    if !is_policy_session_handle(session.handle)
        || session.attributes & TPMA_SESSION_CONTINUE_SESSION == 0
    {
        return Ok(());
    }
    let time = runtime.timer.time_ms;
    let epoch = runtime
        .state
        .as_ref()
        .ok_or(TPM_RC_FAILURE)?
        .persistent
        .time_epoch;
    let loaded = loaded_session_mut(&mut runtime.live, session.handle).ok_or(TPM_RC_FAILURE)?;
    reset_policy_data(loaded);
    set_start_time(loaded, time, epoch);
    Ok(())
}

fn update_audit_sessions(
    runtime: &mut Tpm2Runtime,
    descriptor: &CommandDescriptor,
    code: u32,
    parameters: &[u8],
    area: &mut SessionArea<'_>,
) -> Result<(), TpmResult> {
    let mut audit_session = TPM_RH_UNASSIGNED;
    for index in 0..area.sessions.len() {
        let handle = area.sessions[index].handle;
        if handle == TPM_RS_PW || area.sessions[index].attributes & TPMA_SESSION_AUDIT == 0 {
            continue;
        }
        audit_session = handle;
        let reset = area.sessions[index].attributes & TPMA_SESSION_AUDIT_RESET != 0;
        let was_audit = loaded_session(&runtime.live, handle)
            .ok_or(TPM_RC_FAILURE)?
            .attributes
            & SESSION_ATTR_IS_AUDIT
            != 0;
        if !was_audit || reset {
            init_audit_session(runtime, handle)?;
            set_exclusive_audit_session(runtime, handle);
        } else if exclusive_audit_session(runtime) != handle {
            set_exclusive_audit_session(runtime, TPM_RH_UNASSIGNED);
        }
        if exclusive_audit_session(runtime) == handle {
            area.sessions[index].attributes |= TPMA_SESSION_AUDIT_EXCLUSIVE;
        } else {
            area.sessions[index].attributes &= !TPMA_SESSION_AUDIT_EXCLUSIVE;
        }
        extend_audit_digest(runtime, handle, code, parameters, area, index)?;
    }
    if audit_session == TPM_RH_UNASSIGNED && descriptor.sessions_allowed {
        set_exclusive_audit_session(runtime, TPM_RH_UNASSIGNED);
    }
    Ok(())
}

fn init_audit_session(runtime: &mut Tpm2Runtime, handle: u32) -> Result<(), TpmResult> {
    let hash_alg = loaded_session(&runtime.live, handle)
        .ok_or(TPM_RC_FAILURE)?
        .auth_hash_alg;
    let size = digest_size(hash_alg).ok_or(TPM_RC_FAILURE)?;
    let loaded = loaded_session_mut(&mut runtime.live, handle).ok_or(TPM_RC_FAILURE)?;
    loaded.attributes |= SESSION_ATTR_IS_AUDIT;
    loaded.attributes &= !SESSION_ATTR_IS_BOUND;
    loaded.audit_digest = vec![0u8; size];
    #[cfg(test)]
    fault_point(ResponseFault::AuditInit)?;
    Ok(())
}

fn extend_audit_digest(
    runtime: &mut Tpm2Runtime,
    handle: u32,
    code: u32,
    parameters: &[u8],
    area: &mut SessionArea<'_>,
    index: usize,
) -> Result<(), TpmResult> {
    let hash_alg = loaded_session(&runtime.live, handle)
        .ok_or(TPM_RC_FAILURE)?
        .auth_hash_alg;
    let cp_hash = area.sessions[index].cp_hash.clone().ok_or(TPM_RC_FAILURE)?;
    let rp_hash = compute_rp_hash(runtime, code, parameters, hash_alg)?;
    let previous = loaded_session(&runtime.live, handle)
        .ok_or(TPM_RC_FAILURE)?
        .audit_digest
        .clone();
    self_test_algorithm(runtime, hash_alg)?;
    let mut hasher = Hasher::new(hash_alg).ok_or(TPM_RC_FAILURE)?;
    hasher.update(&previous);
    hasher.update(&cp_hash);
    hasher.update(&rp_hash);
    let digest = hasher.finalize();
    loaded_session_mut(&mut runtime.live, handle)
        .ok_or(TPM_RC_FAILURE)?
        .audit_digest = digest;
    #[cfg(test)]
    fault_point(ResponseFault::AuditExtend)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::CommandInput;
    use crate::library::tpm2::command::core::header::{parse_command, serialize_response};
    use crate::library::tpm2::command::policy::session::test_support::{
        HMAC_SESSION_0, restored, session_of,
    };
    use crate::library::tpm2::golden_responses::policy_sessions::vector;
    use crate::library::tpm2::runtime::empty_state_runtime;

    fn hex(text: &str) -> Vec<u8> {
        let digits: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        (0..digits.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&digits[at..at + 2], 16).expect("hex digits"))
            .collect()
    }

    #[track_caller]
    fn send(runtime: &mut Tpm2Runtime, bytes: &[u8]) -> Vec<u8> {
        let input = CommandInput::new(bytes.len() as u32, bytes.to_vec());
        let parsed = parse_command(&input).expect("the header parses");
        serialize_response(&crate::library::tpm2::command::core::dispatcher::dispatch(
            runtime,
            &parsed,
            crate::library::cancel::CancellationToken::disabled(),
        ))
        .expect("the response serializes")
    }

    const SALTED_START: &str = "80010000012b00000176800000004000000700105a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a010088499b20c9d3c25808e7ab35f9b514d799ddc4bc0c4846873cb16e02e0571f537b43ff9ae3013b0a02717ae3a2717a15fc4db7c75ad31219245af67f0e235e3984c346cc34a15800dedd961055e081ce056f82536b433eb23d597c40e81676a7d673418f7523e66ecabad4b6ac910a7a9486e029ce5cb88a975ff7f69e4522ccaf3a8a1c63f89b3a225c95e4ee9694363903477fa9f2e54e2878b7dd6ed8b31f02eb84c644e6112d3e7e096c47c5e31bb0477c875e2225875ae579d93594567519d71bdb1a3f3f29c06156dfa15371e6078d7b83d82e227c59bd85d79bd95e9f2e4fb1fcd363a81ec1afa78e1f8b94d1698233acfa4fdf01f81b91283171828a000010000b";
    const UNSALTED_START: &str =
        "80010000002b00000176400000074000000700105a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a0000000010000b";
    const POLICY_START: &str =
        "80010000002b00000176400000074000000700105a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a0000010010000b";
    const TRIAL_START: &str =
        "80010000002b00000176400000074000000700105a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a0000030010000b";
    const POLICY_COMMAND_CODE_NV_READ: &str = "8001000000120000016c030000000000014e";

    const HMAC_AUTH_PCR_EXTEND: &str = "8002000000710000018200000000000000390200000000105a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a010020625ee1ff1951173deb4e6e8473c998db786d0a72a7c8564e1c264daf8988291000000001000b0000000000000000000000000000000000000000000000000000000000000000";
    const HMAC_AUTH_PCR_EXTEND_AGAIN: &str = "8002000000710000018200000000000000390200000000105a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a010020bcea4af9cfb822d910c6edceacb03ab659285050d32b43f94af2dad9087be7f700000001000b0000000000000000000000000000000000000000000000000000000000000000";
    const HMAC_AUTH_WRONG_MAC: &str = "8002000000710000018200000000000000390200000000105a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a010020000000000000000000000000000000000000000000000000000000000000000000000001000b0000000000000000000000000000000000000000000000000000000000000000";
    const HMAC_AUTH_CLOSE_SESSION: &str = "8002000000710000018200000000000000390200000000105a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a00002094ca2e0c68049abd32a20e94718b4dfc8e691623c0933805db87ee90af02252900000001000b0000000000000000000000000000000000000000000000000000000000000000";
    const HMAC_AUTH_AFTER_CLOSE: &str = "8002000000710000018200000000000000390200000000105a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a010020c260f41f10d5e40f3cf3876a4fce99bdefd20df2014d77e4ed4207de0a55e67a00000001000b0000000000000000000000000000000000000000000000000000000000000000";
    const EMPTY_HMAC_PCR_EXTEND: &str = "8002000000510000018200000000000000190200000000105a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a01000000000001000b0000000000000000000000000000000000000000000000000000000000000000";
    const CAP_LOADED: &str = "8001000000160000017a000000010200000000000008";
    const NV_DEFINE_POLICY_INDEX: &str = "80020000004d0000012a40000001000000094000000900000000000000002e01000000000b02080006002047ce3032d8bad1f3089cb0c09088de43501491d460402b90cd1b7fc0b68ca92f0008";
    const NV_WRITE_POLICY_INDEX: &str =
        "80020000002b00000137400000010100000000000009400000090000000000000800000000000000000000";
    const POLICY_NV_READ: &str = "8002000000330000014e0100000001000000000000190300000000105a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a01000000080000";
    const POLICY_HANDLE_FOR_HMAC_SESSION: &str = "8002000000510000018200000000000000190300000000105a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a01000000000001000b0000000000000000000000000000000000000000000000000000000000000000";
    const UNLOADED_SESSION_HANDLE: &str = "8002000000510000018200000000000000190200000500105a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a01000000000001000b0000000000000000000000000000000000000000000000000000000000000000";
    const DUPLICATE_SESSION_HANDLE: &str = "80020000006a0000018200000000000000320200000000105a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a0100000200000000105a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a01000000000001000b0000000000000000000000000000000000000000000000000000000000000000";
    const TRIAL_SESSION_IN_AUTH_AREA: &str = "8002000000510000018200000000000000190300000200105a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a01000000000001000b0000000000000000000000000000000000000000000000000000000000000000";

    const POLICY_NV_WRITTEN_SET: &str = "80010000000f0000018f0300000001";
    const POLICY_NV_WRITTEN_CLEAR: &str = "80010000000f0000018f0300000000";
    const POLICY_LOCALITY_ZERO: &str = "80010000000f0000016f0300000001";
    const POLICY_PHYSICAL_PRESENCE: &str = "80010000000e0000018703000000";

    fn digest_of(runtime: &mut Tpm2Runtime) -> Vec<u8> {
        let response = send(runtime, &hex("80010000000e0000018903000000"));
        response[12..].to_vec()
    }

    #[track_caller]
    fn assert_flow(snapshot: &str, assertions: &[&str], digest_record: &str, read_record: &str) {
        let mut runtime = restored(snapshot);
        for assertion in assertions {
            assert_eq!(
                response_code_of(&send(&mut runtime, &hex(assertion))),
                0,
                "{snapshot}: the policy assertion succeeds"
            );
        }
        assert_eq!(
            send(&mut runtime, &hex("80010000000e0000018903000000")),
            vector(digest_record),
            "{snapshot}: the built policy digest"
        );
        assert_eq!(
            send(&mut runtime, &hex(POLICY_NV_READ)),
            vector(read_record),
            "{snapshot}: the authorized read"
        );
    }

    fn response_code_of(response: &[u8]) -> u32 {
        u32::from_be_bytes(response[6..10].try_into().expect("a response code"))
    }

    const NVUSS_POLICY_COMMAND_CODE: &str = "8001000000120000016c030000000000011f";
    const NVUSS_POLICY_AUTH_VALUE: &str = "80010000000e0000016b03000000";
    const NVUSS_CONTINUED: &str = "8002000000580000011f010000004000000c000000420300000000105a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a01002060f3070258022ff34c724a32b8649be820090dc8624e98b07b91528b9665c0e0400000090000000000";
    const NVUSS_CLOSED: &str = "8002000000580000011f010000004000000c000000420300000000105a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a000020466c6e569f42135a5ab579cbb012bddee4af02a44feb262a4baac686d8b4e56f400000090000000000";
    const NVUSS_LOADED_SESSIONS: &str = "8001000000160000017a000000010300000000000008";
    const NVUSS_INDEX: u32 = 0x0100_0000;
    const HCA_CHANGED: &str = "8002000000500000012940000001000000390200000000105a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a010020ce5941d36d750dee870ff8f5b13e7adf5238f129c2d344486f986a2c05a52af60003717171";

    #[track_caller]
    fn open_undefine_policy(assertions: &[&str]) -> Tpm2Runtime {
        let mut runtime = restored("NVUSS_READY");
        for assertion in assertions {
            assert_eq!(
                response_code_of(&send(&mut runtime, &hex(assertion))),
                0,
                "the policy assertion succeeds"
            );
        }
        runtime
    }

    fn expected_response_hmac(code: u32, key: &[u8], nonce_tpm: &[u8], attributes: u8) -> Vec<u8> {
        let mut hasher = Hasher::new(0x000b).expect("sha256");
        hasher.update(&0u32.to_be_bytes());
        hasher.update(&code.to_be_bytes());
        let rp_hash = hasher.finalize();
        let mut hmac = HmacState::new(0x000b, key).expect("sha256");
        hmac.update(&rp_hash);
        hmac.update(nonce_tpm);
        hmac.update(&[0x5a; 16]);
        hmac.update(&[attributes]);
        hmac.finalize()
    }

    fn response_session_parts(response: &[u8]) -> (Vec<u8>, u8, Vec<u8>) {
        let parameter_size =
            u32::from_be_bytes(response[10..14].try_into().expect("a parameter size")) as usize;
        let area = &response[14 + parameter_size..];
        let nonce_size = usize::from(u16::from_be_bytes(area[..2].try_into().expect("a size")));
        let attributes = area[2 + nonce_size];
        let auth_at = 2 + nonce_size + 1;
        let auth_size = usize::from(u16::from_be_bytes(
            area[auth_at..auth_at + 2].try_into().expect("a size"),
        ));
        (
            area[2..2 + nonce_size].to_vec(),
            attributes,
            area[auth_at + 2..auth_at + 2 + auth_size].to_vec(),
        )
    }

    #[test]
    fn undefine_space_special_success_after_policy_auth_value() {
        let mut runtime =
            open_undefine_policy(&[NVUSS_POLICY_COMMAND_CODE, NVUSS_POLICY_AUTH_VALUE]);
        assert!(resolve_index(&runtime, NVUSS_INDEX).is_some());

        let response = send(&mut runtime, &hex(NVUSS_CONTINUED));
        assert_eq!(response, vector("NVUSS_CONTINUED"));
        assert_eq!(response_code_of(&response), 0);
        assert!(!runtime.failure_mode, "no internal failure is reported");
        assert!(
            resolve_index(&runtime, NVUSS_INDEX).is_none(),
            "the deletion is committed"
        );
    }

    #[test]
    fn response_hmac_deleted_entity_auth_exclusion() {
        let mut runtime =
            open_undefine_policy(&[NVUSS_POLICY_COMMAND_CODE, NVUSS_POLICY_AUTH_VALUE]);
        let response = send(&mut runtime, &hex(NVUSS_CONTINUED));
        let (nonce_tpm, attributes, auth) = response_session_parts(&response);
        assert_eq!(
            auth,
            expected_response_hmac(0x0000_011f, &[], &nonce_tpm, attributes),
            "the key is the session key alone once the index is gone"
        );
        assert_ne!(
            auth,
            expected_response_hmac(0x0000_011f, b"ppp", &nonce_tpm, attributes),
            "the authValue of the deleted index is not used"
        );
    }

    #[test]
    fn continued_and_closed_session_preservation_across_deletion() {
        let mut continued =
            open_undefine_policy(&[NVUSS_POLICY_COMMAND_CODE, NVUSS_POLICY_AUTH_VALUE]);
        assert_eq!(
            send(&mut continued, &hex(NVUSS_CONTINUED)),
            vector("NVUSS_CONTINUED")
        );
        assert_eq!(
            send(&mut continued, &hex(NVUSS_LOADED_SESSIONS)),
            vector("NVUSS_LOADED_AFTER_CONTINUE")
        );
        assert!(loaded_session(&continued.live, POLICY_SESSION_FIRST).is_some());

        let mut closed =
            open_undefine_policy(&[NVUSS_POLICY_COMMAND_CODE, NVUSS_POLICY_AUTH_VALUE]);
        assert_eq!(
            send(&mut closed, &hex(NVUSS_CLOSED)),
            vector("NVUSS_CLOSED")
        );
        assert_eq!(
            send(&mut closed, &hex(NVUSS_LOADED_SESSIONS)),
            vector("NVUSS_LOADED_AFTER_CLOSE")
        );
        assert!(
            loaded_session(&closed.live, POLICY_SESSION_FIRST).is_none(),
            "clearing continueSession still flushes the session"
        );
    }

    #[test]
    fn rejected_undefine_special_index_and_policy_preservation() {
        let mut runtime = open_undefine_policy(&[NVUSS_POLICY_COMMAND_CODE]);
        let before = loaded_session(&runtime.live, POLICY_SESSION_FIRST)
            .expect("a policy session")
            .clone();
        assert_eq!(
            send(&mut runtime, &hex(NVUSS_CONTINUED)),
            vector("NVUSS_WITHOUT_AUTH_VALUE")
        );
        assert!(!runtime.failure_mode, "a policy failure is recoverable");
        assert!(
            resolve_index(&runtime, NVUSS_INDEX).is_some(),
            "the rejected command deletes nothing"
        );
        let after = loaded_session(&runtime.live, POLICY_SESSION_FIRST).expect("a policy session");
        assert_eq!(after.audit_digest, before.audit_digest);
        assert_eq!(after.attributes, before.attributes);
        assert_eq!(after.nonce_tpm.as_bytes(), before.nonce_tpm.as_bytes());
        assert!(runtime.removed_session_associations.is_empty());
        assert_eq!(
            send(&mut runtime, &hex("80010000000e0000018903000000")),
            vector("NVUSS_DIGEST_AFTER_FAILURE")
        );
    }

    #[test]
    fn auth_change_response_hmac_installed_value() {
        let mut runtime = restored("HCA_READY");
        let response = send(&mut runtime, &hex(HCA_CHANGED));
        assert_eq!(response, vector("HCA_CHANGED"));
        assert_eq!(response_code_of(&response), 0);
        let (nonce_tpm, attributes, auth) = response_session_parts(&response);
        assert_eq!(
            auth,
            expected_response_hmac(0x0000_0129, b"qqq", &nonce_tpm, attributes),
            "the reference answers with the authorization the command installed"
        );
        assert_ne!(
            auth,
            expected_response_hmac(0x0000_0129, &[], &nonce_tpm, attributes),
            "the empty authorization the command was given is not reused"
        );
    }

    fn recorded_association(runtime: &Tpm2Runtime, index: usize) -> u32 {
        runtime
            .restored_volatile
            .as_ref()
            .expect("recorded session state")
            .session_process
            .associated_handles[index]
    }

    #[test]
    fn deleted_association_null_handle_record() {
        let mut runtime =
            open_undefine_policy(&[NVUSS_POLICY_COMMAND_CODE, NVUSS_POLICY_AUTH_VALUE]);
        assert_eq!(
            send(&mut runtime, &hex(NVUSS_CONTINUED)),
            vector("NVUSS_CONTINUED")
        );
        assert_eq!(
            recorded_association(&runtime, 0),
            TPM_RH_NULL,
            "the deleted index is replaced before the state is recorded"
        );
        assert_eq!(recorded_association(&runtime, 1), TPM_RH_PLATFORM);
    }

    #[test]
    fn volatile_state_null_handle_round_trip() {
        use crate::library::tpm2::clock::RecordingClock;
        use crate::library::tpm2::volatile::volatile_all_store;
        use crate::library::tpm2::{
            attach_volatile_blob_for_test, restore_permanent_blob_for_test,
        };

        let mut runtime =
            open_undefine_policy(&[NVUSS_POLICY_COMMAND_CODE, NVUSS_POLICY_AUTH_VALUE]);
        send(&mut runtime, &hex(NVUSS_CONTINUED));

        let clock = RecordingClock::new(1_700_000_100_000, 4_000_000);
        let volatile = volatile_all_store(&runtime, &clock).expect("the volatile state saves");
        let permanent = crate::library::tpm2::persistent::persistent_all_store(runtime.state())
            .expect("the permanent state saves");
        let mut reloaded = restore_permanent_blob_for_test(&permanent).expect("restores");
        attach_volatile_blob_for_test(&mut reloaded, &volatile).expect("attaches");
        assert_eq!(recorded_association(&reloaded, 0), TPM_RH_NULL);
        assert_eq!(recorded_association(&reloaded, 1), TPM_RH_PLATFORM);
    }

    #[test]
    fn recorded_association_oracle_match() {
        let reference = restored("NVUSS_AFTER_DELETE");
        assert_eq!(
            recorded_association(&reference, 0),
            TPM_RH_NULL,
            "the vendored implementation stores the null handle"
        );

        let mut runtime =
            open_undefine_policy(&[NVUSS_POLICY_COMMAND_CODE, NVUSS_POLICY_AUTH_VALUE]);
        send(&mut runtime, &hex(NVUSS_CONTINUED));
        for index in 0..3 {
            assert_eq!(
                recorded_association(&runtime, index),
                recorded_association(&reference, index),
                "session slot {index}"
            );
        }
    }

    #[test]
    fn rejected_deletion_association_preservation() {
        let mut runtime = open_undefine_policy(&[NVUSS_POLICY_COMMAND_CODE]);
        assert_eq!(
            send(&mut runtime, &hex(NVUSS_CONTINUED)),
            vector("NVUSS_WITHOUT_AUTH_VALUE")
        );
        assert_eq!(recorded_association(&runtime, 0), NVUSS_INDEX);
    }

    #[test]
    fn removed_association_no_inheritance() {
        let mut runtime =
            open_undefine_policy(&[NVUSS_POLICY_COMMAND_CODE, NVUSS_POLICY_AUTH_VALUE]);
        send(&mut runtime, &hex(NVUSS_CONTINUED));
        assert!(!runtime.removed_session_associations.is_empty());

        assert_eq!(
            send(&mut runtime, &hex(NVUSS_LOADED_SESSIONS)),
            vector("NVUSS_LOADED_AFTER_CONTINUE")
        );
        assert!(
            runtime.removed_session_associations.is_empty(),
            "the next command boundary clears the scratch state"
        );
    }

    #[test]
    fn written_index_policy_read_authorization() {
        assert_flow(
            "FLOW_NV_WRITTEN",
            &[POLICY_NV_WRITTEN_SET, POLICY_COMMAND_CODE_NV_READ],
            "FLOW_NV_WRITTEN_DIGEST",
            "FLOW_NV_READ_WRITTEN",
        );
    }

    #[test]
    fn unwritten_index_policy_written_index_rejection() {
        assert_flow(
            "FLOW_NV_UNWRITTEN",
            &[POLICY_NV_WRITTEN_CLEAR, POLICY_COMMAND_CODE_NV_READ],
            "FLOW_NV_UNWRITTEN_DIGEST",
            "FLOW_NV_READ_UNWRITTEN",
        );
    }

    #[test]
    fn locality_restriction_enforcement() {
        assert_flow(
            "FLOW_LOCALITY",
            &[POLICY_LOCALITY_ZERO, POLICY_COMMAND_CODE_NV_READ],
            "FLOW_LOCALITY_DIGEST",
            "FLOW_NV_READ_LOCALITY_ZERO",
        );

        let mut runtime = restored("FLOW_LOCALITY");
        for assertion in [POLICY_LOCALITY_ZERO, POLICY_COMMAND_CODE_NV_READ] {
            send(&mut runtime, &hex(assertion));
        }
        runtime.locality = 2;
        assert_eq!(
            send(&mut runtime, &hex(POLICY_NV_READ)),
            vector("FLOW_NV_READ_LOCALITY_TWO")
        );
    }

    #[test]
    fn physical_presence_restriction_enforcement() {
        assert_flow(
            "FLOW_PHYSICAL_PRESENCE",
            &[POLICY_PHYSICAL_PRESENCE, POLICY_COMMAND_CODE_NV_READ],
            "FLOW_PHYSICAL_PRESENCE_DIGEST",
            "FLOW_NV_READ_PHYSICAL_PRESENCE",
        );
    }

    #[test]
    fn asserted_physical_presence_policy_satisfaction() {
        let mut runtime = restored("FLOW_PHYSICAL_PRESENCE");
        for assertion in [POLICY_PHYSICAL_PRESENCE, POLICY_COMMAND_CODE_NV_READ] {
            send(&mut runtime, &hex(assertion));
        }
        assert!(
            !runtime.physical_presence,
            "the reference platform never asserts physical presence"
        );
        runtime.physical_presence = true;
        let response = send(&mut runtime, &hex(POLICY_NV_READ));
        assert_eq!(
            response_code_of(&response),
            0,
            "the same policy authorizes once the platform asserts physical presence"
        );
        assert_eq!(
            &response[response.len() - 4..],
            &vector("FLOW_NV_READ_WRITTEN")[vector("FLOW_NV_READ_WRITTEN").len() - 4..],
            "the authorized read answers like every other flow"
        );
    }

    #[test]
    fn flow_digest_extension_chain_match() {
        let mut runtime = restored("FLOW_NV_WRITTEN");
        for assertion in [POLICY_NV_WRITTEN_SET, POLICY_COMMAND_CODE_NV_READ] {
            send(&mut runtime, &hex(assertion));
        }
        let mut hasher = Hasher::new(0x000b).expect("sha256");
        hasher.update(&[0x00; 32]);
        hasher.update(&0x0000_018fu32.to_be_bytes());
        hasher.update(&[0x01]);
        let first = hasher.finalize();
        let mut hasher = Hasher::new(0x000b).expect("sha256");
        hasher.update(&first);
        hasher.update(&0x0000_016cu32.to_be_bytes());
        hasher.update(&0x0000_014eu32.to_be_bytes());
        assert_eq!(digest_of(&mut runtime), hasher.finalize());
    }

    #[test]
    fn policy_session_reset_after_authorization() {
        let mut runtime = restored("FLOW_NV_WRITTEN");
        for assertion in [POLICY_NV_WRITTEN_SET, POLICY_COMMAND_CODE_NV_READ] {
            send(&mut runtime, &hex(assertion));
        }
        assert_ne!(
            loaded_session(&runtime.live, 0x0300_0000)
                .expect("a policy session")
                .attributes
                & SESSION_ATTR_CHECK_NV_WRITTEN,
            0
        );
        assert_eq!(
            send(&mut runtime, &hex(POLICY_NV_READ)),
            vector("FLOW_NV_READ_WRITTEN")
        );
        let session = loaded_session(&runtime.live, 0x0300_0000).expect("a policy session");
        assert_eq!(session.attributes & SESSION_ATTR_CHECK_NV_WRITTEN, 0);
        assert_eq!(session.command_code, 0);
        assert_eq!(session.audit_digest, vec![0u8; 32]);
    }

    #[test]
    fn salted_session_authorization_and_nonce_roll() {
        let mut runtime = restored("RSA_KEY");
        assert_eq!(
            send(&mut runtime, &hex(SALTED_START)),
            vector("SAS_SALTED_RSA")
        );
        assert_eq!(
            send(&mut runtime, &hex(HMAC_AUTH_PCR_EXTEND)),
            vector("HMAC_AUTH_PCR_EXTEND")
        );
        assert_eq!(
            send(&mut runtime, &hex(HMAC_AUTH_PCR_EXTEND_AGAIN)),
            vector("HMAC_AUTH_PCR_EXTEND_AGAIN"),
            "the rolled nonce feeds the next command HMAC"
        );
    }

    #[test]
    fn wrong_command_hmac_rejection() {
        let mut runtime = restored("RSA_KEY");
        send(&mut runtime, &hex(SALTED_START));
        assert_eq!(
            send(&mut runtime, &hex(HMAC_AUTH_WRONG_MAC)),
            vector("HMAC_AUTH_WRONG_MAC")
        );
    }

    #[test]
    fn continue_session_clear_session_flush() {
        let mut runtime = restored("RSA_KEY");
        send(&mut runtime, &hex(SALTED_START));
        send(&mut runtime, &hex(HMAC_AUTH_PCR_EXTEND));
        send(&mut runtime, &hex(HMAC_AUTH_PCR_EXTEND_AGAIN));
        assert_eq!(
            send(&mut runtime, &hex(HMAC_AUTH_CLOSE_SESSION)),
            vector("HMAC_AUTH_CLOSE_SESSION")
        );
        assert_eq!(
            send(&mut runtime, &hex(CAP_LOADED)),
            vector("CAP_LOADED_AFTER_CLOSE")
        );
        assert_eq!(
            send(&mut runtime, &hex(HMAC_AUTH_AFTER_CLOSE)),
            vector("HMAC_AUTH_AFTER_CLOSE")
        );
        assert_eq!(runtime.live.free_session_slots, 3);
    }

    #[test]
    fn unbound_empty_key_empty_hmac_authorization() {
        let mut runtime = restored("READY");
        assert_eq!(
            send(&mut runtime, &hex(UNSALTED_START)),
            vector("SAS_HMAC_UNBOUND")
        );
        assert_eq!(
            send(&mut runtime, &hex(EMPTY_HMAC_PCR_EXTEND)),
            vector("EMPTY_HMAC_PCR_EXTEND")
        );
    }

    #[test]
    fn policy_session_matching_digest_authorization() {
        let mut runtime = restored("POLICY_NV");
        assert_eq!(
            send(&mut runtime, &hex(POLICY_START)),
            vector("SAS_POLICY_UNBOUND_ALONE")
        );
        assert_eq!(
            send(&mut runtime, &hex(POLICY_COMMAND_CODE_NV_READ))[6..10],
            [0, 0, 0, 0]
        );
        assert_eq!(
            send(&mut runtime, &hex(POLICY_NV_READ)),
            vector("POLICY_AUTH_NV_READ")
        );
    }

    #[test]
    fn policy_session_digest_mismatch_rejection() {
        let mut runtime = restored("POLICY_NV");
        send(&mut runtime, &hex(POLICY_START));
        assert_eq!(
            send(&mut runtime, &hex(POLICY_NV_READ)),
            vector("POLICY_AUTH_NV_READ_WITHOUT_POLICY")
        );
    }

    #[test]
    fn trial_session_authorization_rejection() {
        let mut runtime = restored("POLICY_NV");
        send(&mut runtime, &hex(TRIAL_START));
        send(&mut runtime, &hex(POLICY_COMMAND_CODE_NV_READ));
        assert_eq!(
            send(&mut runtime, &hex(POLICY_NV_READ)),
            vector("TRIAL_SESSION_CANNOT_AUTHORIZE")
        );
    }

    #[test]
    fn nv_index_and_policy_creation_oracle_match() {
        let mut runtime = restored("READY");
        assert_eq!(
            send(&mut runtime, &hex(NV_DEFINE_POLICY_INDEX)),
            vector("NV_DEFINE_POLICY_INDEX")
        );
        assert_eq!(
            send(&mut runtime, &hex(NV_WRITE_POLICY_INDEX))[6..10],
            [0, 0, 0, 0]
        );
    }

    #[test]
    fn password_session_forbidden_attribute_rejection() {
        let mut runtime = restored("THREE_SESSIONS");
        for (record, attributes) in [
            ("PW_WITH_DECRYPT", 0x20u8),
            ("PW_WITH_ENCRYPT", 0x40),
            ("PW_WITH_AUDIT", 0x80),
            ("PW_WITH_AUDIT_RESET", 0x04),
            ("PW_WITH_AUDIT_EXCLUSIVE", 0x02),
        ] {
            let mut command = hex(
                "80020000004100000182000000000000000940000009000000000000000001000b0000000000000000000000000000000000000000000000000000000000000000",
            );
            command[24] = attributes;
            assert_eq!(send(&mut runtime, &command), vector(record), "{record}");
        }
        assert_eq!(
            send(
                &mut runtime,
                &hex(
                    "8002000000510000018200000000000000194000000900105a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a01000000000001000b0000000000000000000000000000000000000000000000000000000000000000"
                )
            ),
            vector("PW_WITH_NONCE")
        );
    }

    #[test]
    fn wrong_kind_session_handle_rejection() {
        let mut runtime = restored("THREE_SESSIONS");
        for (record, command) in [
            (
                "POLICY_HANDLE_FOR_HMAC_SESSION",
                POLICY_HANDLE_FOR_HMAC_SESSION,
            ),
            ("UNLOADED_SESSION_HANDLE", UNLOADED_SESSION_HANDLE),
            ("DUPLICATE_SESSION_HANDLE", DUPLICATE_SESSION_HANDLE),
            ("TRIAL_SESSION_IN_AUTH_AREA", TRIAL_SESSION_IN_AUTH_AREA),
        ] {
            assert_eq!(
                send(&mut runtime, &hex(command)),
                vector(record),
                "{record}"
            );
        }
    }

    const AUDIT_GET_RANDOM: &str =
        "8002000000290000017b000000190200000000105a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a8100000004";
    const AUDIT_GET_RANDOM_EXCLUSIVE: &str =
        "8002000000290000017b000000190200000000105a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a8300000004";
    const AUDIT_GET_RANDOM_CLOSE: &str =
        "8002000000290000017b000000190200000000105a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a8000000004";
    const AUDIT_ON_FAILING_COMMAND: &str = "80020000002f0000018200000000000000190200000000105a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a81000000000009";

    fn audit_digest(runtime: &Tpm2Runtime) -> Vec<u8> {
        session_of(runtime, HMAC_SESSION_0).audit_digest.clone()
    }

    #[test]
    fn empty_hmac_audit_session_oracle_match() {
        let mut runtime = restored("AUDIT_SESSION");
        assert!(audit_digest(&runtime).is_empty(), "no audit digest yet");
        assert_eq!(
            session_of(&runtime, HMAC_SESSION_0).attributes & SESSION_ATTR_IS_AUDIT,
            0
        );

        assert_eq!(
            send(&mut runtime, &hex(AUDIT_GET_RANDOM)),
            vector("AUDIT_GET_RANDOM"),
            "an empty command HMAC still audits"
        );
        let session = session_of(&runtime, HMAC_SESSION_0);
        assert_ne!(session.attributes & SESSION_ATTR_IS_AUDIT, 0);
        assert_eq!(session.audit_digest.len(), 32);
        assert_ne!(session.audit_digest, vec![0u8; 32]);
        assert_eq!(exclusive_audit_session(&runtime), HMAC_SESSION_0);

        assert_eq!(
            send(&mut runtime, &hex(AUDIT_GET_RANDOM_EXCLUSIVE)),
            vector("AUDIT_GET_RANDOM_EXCLUSIVE"),
            "the session stays exclusive across consecutive audited commands"
        );
        let extended = audit_digest(&runtime);
        assert_ne!(extended, vec![0u8; 32]);

        let reference = restored("AUDIT_EXTENDED");
        assert_eq!(
            extended,
            audit_digest(&reference),
            "the audit digest matches the reference volatile state"
        );
    }

    #[test]
    fn unaudited_command_exclusivity_loss_next_audit_failure() {
        let mut runtime = restored("AUDIT_SESSION");
        send(&mut runtime, &hex(AUDIT_GET_RANDOM));
        send(&mut runtime, &hex(AUDIT_GET_RANDOM_EXCLUSIVE));
        assert_eq!(
            send(&mut runtime, &hex(CAP_LOADED)),
            vector("CAP_BETWEEN_AUDITS")
        );
        assert_eq!(exclusive_audit_session(&runtime), TPM_RH_UNASSIGNED);
        assert_eq!(
            send(&mut runtime, &hex(AUDIT_GET_RANDOM_EXCLUSIVE)),
            vector("AUDIT_EXCLUSIVE_AFTER_OTHER_COMMAND")
        );
        assert_eq!(
            send(&mut runtime, &hex(AUDIT_GET_RANDOM_CLOSE)),
            vector("AUDIT_GET_RANDOM_CLOSE"),
            "the reply clears auditExclusive and drops continueSession"
        );
        assert_eq!(
            send(&mut runtime, &hex(CAP_LOADED)),
            vector("CAP_LOADED_AFTER_AUDIT_CLOSE")
        );
        assert_eq!(runtime.live.free_session_slots, 3);
    }

    #[test]
    fn failed_command_audit_digest_and_nonce_unchanged() {
        let mut runtime = restored("AUDIT_SESSION");
        let before = session_of(&runtime, HMAC_SESSION_0).clone();
        assert_eq!(
            send(&mut runtime, &hex(AUDIT_ON_FAILING_COMMAND)),
            vector("AUDIT_ON_FAILING_COMMAND")
        );
        let after = session_of(&runtime, HMAC_SESSION_0);
        assert_eq!(after.audit_digest, before.audit_digest);
        assert_eq!(after.attributes, before.attributes);
        assert_eq!(after.nonce_tpm.as_bytes(), before.nonce_tpm.as_bytes());
        assert_eq!(
            send(&mut runtime, &hex(AUDIT_GET_RANDOM)),
            vector("AUDIT_DIGEST_AFTER_FAILURE"),
            "the failed command committed nothing"
        );
    }

    #[test]
    fn audit_session_cp_hash_before_handler() {
        let mut runtime = restored("AUDIT_SESSION");
        let descriptor =
            crate::library::tpm2::command::core::registry::find(0x0000_017b).expect("GetRandom");
        let auth_area = hex("0200000000105a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a810000");
        let mut area =
            parse_session_area(&runtime, descriptor, &auth_area).expect("the area parses");
        let context = CommandContext {
            code: 0x0000_017b,
            handles: &[],
            parameters: &[0x00, 0x04],
        };
        authorize_sessions(&mut runtime, descriptor, &[], &context, &mut area)
            .expect("an empty HMAC authorizes an audit-only session");
        assert!(
            area.sessions[0].cp_hash.is_some(),
            "the audit cpHash is computed before the handler runs"
        );
    }

    mod pre_v4_name_hash {
        use super::*;
        use crate::library::tpm2::command::core::test_support::{
            RC_SUCCESS, command, dispatch_bytes, framed, response_code, started_runtime,
        };
        use crate::library::tpm2::command::nv::test_support::nv_public;
        use crate::library::tpm2::hierarchy::TPM_RH_OWNER;
        use crate::library::tpm2::profile::STATE_FORMAT_LEVEL_CURRENT;

        const TPM_CC_POLICY_NAME_HASH: u32 = 0x0000_0170;
        const TPM_CC_HIERARCHY_CHANGE_AUTH: u32 = 0x0000_0129;
        const TPM_CC_SET_PRIMARY_POLICY: u32 = 0x0000_012e;
        const TPM_CC_NV_UNDEFINE_SPACE: u32 = 0x0000_0122;
        const TPM_CC_START_AUTH_SESSION: u32 = 0x0000_0176;
        const NV_INDEX: u32 = 0x0100_0001;

        fn digest_of(parts: &[&[u8]]) -> Vec<u8> {
            let mut hasher = Hasher::new(0x000b).expect("sha256");
            for part in parts {
                hasher.update(part);
            }
            hasher.finalize()
        }

        fn owner_name_hash() -> Vec<u8> {
            digest_of(&[&TPM_RH_OWNER.to_be_bytes()])
        }

        fn owner_policy_for(name_hash: &[u8]) -> Vec<u8> {
            digest_of(&[
                &[0u8; 32],
                &TPM_CC_POLICY_NAME_HASH.to_be_bytes(),
                name_hash,
            ])
        }

        fn sized(payload: &[u8]) -> Vec<u8> {
            let mut out = (payload.len() as u16).to_be_bytes().to_vec();
            out.extend_from_slice(payload);
            out
        }

        #[track_caller]
        fn armed_runtime(name_hash: &[u8]) -> Tpm2Runtime {
            let mut runtime = started_runtime();
            let mut parameters = sized(&owner_policy_for(name_hash));
            parameters.extend_from_slice(&0x000bu16.to_be_bytes());
            assert_eq!(
                response_code(&dispatch_bytes(
                    &mut runtime,
                    &command(
                        TPM_CC_SET_PRIMARY_POLICY,
                        &[TPM_RH_OWNER],
                        &[&[]],
                        &parameters
                    ),
                )),
                RC_SUCCESS,
                "the owner policy is installed"
            );

            let mut start = sized(&[0x5a; 16]);
            start.extend_from_slice(&sized(&[]));
            start.push(0x01);
            start.extend_from_slice(&[0x00, 0x10]);
            start.extend_from_slice(&0x000bu16.to_be_bytes());
            assert_eq!(
                response_code(&dispatch_bytes(
                    &mut runtime,
                    &command(
                        TPM_CC_START_AUTH_SESSION,
                        &[TPM_RH_NULL, TPM_RH_NULL],
                        &[],
                        &start
                    ),
                )),
                RC_SUCCESS,
                "the policy session starts"
            );
            assert_eq!(
                response_code(&dispatch_bytes(
                    &mut runtime,
                    &command(
                        TPM_CC_POLICY_NAME_HASH,
                        &[POLICY_SESSION_FIRST],
                        &[],
                        &sized(name_hash)
                    ),
                )),
                RC_SUCCESS,
                "the name hash is asserted"
            );
            runtime
        }

        fn policy_authorized(code: u32, handles: &[u32], parameters: &[u8]) -> Vec<u8> {
            let mut payload = Vec::new();
            for handle in handles {
                payload.extend_from_slice(&handle.to_be_bytes());
            }
            let mut area = POLICY_SESSION_FIRST.to_be_bytes().to_vec();
            area.extend_from_slice(&sized(&[0x5a; 16]));
            area.push(0x01);
            area.extend_from_slice(&sized(&[]));
            payload.extend_from_slice(&(area.len() as u32).to_be_bytes());
            payload.extend_from_slice(&area);
            payload.extend_from_slice(parameters);
            framed(code, &payload, true)
        }

        fn change_owner_auth() -> Vec<u8> {
            policy_authorized(
                TPM_CC_HIERARCHY_CHANGE_AUTH,
                &[TPM_RH_OWNER],
                &sized(&[0x71; 3]),
            )
        }

        #[test]
        fn untagged_record_format() {
            let runtime = armed_runtime(&owner_name_hash());
            assert_eq!(
                runtime.state().profile.state_format_level,
                1,
                "the null profile is a pre-v4 profile"
            );
            let session = loaded_session(&runtime.live, POLICY_SESSION_FIRST).expect("a session");
            assert_eq!(session.bound_entity, owner_name_hash());
            assert_eq!(
                session.attributes & SESSION_ATTR_IS_NAME_HASH_DEFINED,
                0,
                "the attribute does not exist below state format level 4"
            );
        }

        #[test]
        fn matching_command_authorization() {
            let mut runtime = armed_runtime(&owner_name_hash());
            assert_eq!(
                response_code(&dispatch_bytes(&mut runtime, &change_owner_auth())),
                RC_SUCCESS,
                "the untagged name hash still gates the command"
            );
        }

        #[test]
        fn different_handle_set_rejection() {
            let mut runtime = armed_runtime(&owner_name_hash());
            let mut public = nv_public(NV_INDEX, 0x0202_0006, 8);
            public.auth_policy = Vec::new();
            let mut define = 0u16.to_be_bytes().to_vec();
            define.extend_from_slice(&crate::library::tpm2::nv::marshal_sized_nv_public(&public));
            assert_eq!(
                response_code(&dispatch_bytes(
                    &mut runtime,
                    &command(0x0000_012a, &[TPM_RH_OWNER], &[&[]], &define),
                )),
                RC_SUCCESS,
                "the index is defined"
            );
            assert_eq!(
                response_code(&dispatch_bytes(
                    &mut runtime,
                    &policy_authorized(TPM_CC_NV_UNDEFINE_SPACE, &[TPM_RH_OWNER, NV_INDEX], &[]),
                )),
                0x99d,
                "a command whose handle names differ fails the name hash"
            );
        }

        #[test]
        fn volatile_round_trip_preservation() {
            use crate::library::tpm2::clock::RecordingClock;
            use crate::library::tpm2::volatile::volatile_all_store;
            use crate::library::tpm2::{
                attach_volatile_blob_for_test, restore_permanent_blob_for_test,
            };

            let runtime = armed_runtime(&owner_name_hash());
            let clock = RecordingClock::new(1_700_000_100_000, 4_000_000);
            let volatile = volatile_all_store(&runtime, &clock).expect("the volatile state saves");
            let permanent = crate::library::tpm2::persistent::persistent_all_store(runtime.state())
                .expect("the permanent state saves");
            let mut reloaded = restore_permanent_blob_for_test(&permanent).expect("restores");
            attach_volatile_blob_for_test(&mut reloaded, &volatile).expect("attaches");

            let session = loaded_session(&reloaded.live, POLICY_SESSION_FIRST).expect("a session");
            assert_eq!(session.bound_entity, owner_name_hash());
            assert_eq!(session.attributes & SESSION_ATTR_IS_NAME_HASH_DEFINED, 0);
            assert_eq!(
                response_code(&dispatch_bytes(&mut reloaded, &change_owner_auth())),
                RC_SUCCESS,
                "a restored pre-v4 name hash still authorizes"
            );
        }

        #[test]
        fn current_profile_tag_requirement() {
            let mut runtime = restored("POLICY_FRESH");
            assert_eq!(
                runtime.state().profile.state_format_level,
                STATE_FORMAT_LEVEL_CURRENT
            );
            assert_eq!(
                response_code(&dispatch_bytes(
                    &mut runtime,
                    &command(
                        TPM_CC_POLICY_NAME_HASH,
                        &[POLICY_SESSION_FIRST],
                        &[],
                        &sized(&[0x22; 32])
                    ),
                )),
                RC_SUCCESS
            );
            let session = loaded_session(&runtime.live, POLICY_SESSION_FIRST).expect("a session");
            assert_ne!(
                session.attributes & SESSION_ATTR_IS_NAME_HASH_DEFINED,
                0,
                "state format level 4 and newer tag the name hash"
            );
        }

        #[test]
        fn current_profile_no_untagged_fallback() {
            let mut runtime = armed_runtime(&owner_name_hash());
            let state = runtime.state.as_mut().expect("decoded state");
            state.profile.state_format_level = STATE_FORMAT_LEVEL_CURRENT;
            assert_eq!(
                response_code(&dispatch_bytes(&mut runtime, &change_owner_auth())),
                0x99d,
                "an untagged shared value is not a name hash at level 4 and newer"
            );
        }

        #[test]
        fn duplication_select_state_format_contract() {
            let mut parameters = sized(&[0xa1; 34]);
            parameters.extend_from_slice(&sized(&[0xb2; 34]));
            parameters.push(0x01);

            let mut pre_v4 = armed_runtime(&owner_name_hash());
            let restart = command(0x0000_0180, &[POLICY_SESSION_FIRST], &[], &[]);
            assert_eq!(
                response_code(&dispatch_bytes(&mut pre_v4, &restart)),
                RC_SUCCESS
            );
            assert_eq!(
                response_code(&dispatch_bytes(
                    &mut pre_v4,
                    &command(0x0000_0188, &[POLICY_SESSION_FIRST], &[], &parameters),
                )),
                RC_SUCCESS
            );
            let session = loaded_session(&pre_v4.live, POLICY_SESSION_FIRST).expect("a session");
            assert_eq!(session.bound_entity.len(), 32);
            assert_eq!(session.attributes & SESSION_ATTR_IS_NAME_HASH_DEFINED, 0);

            let mut current = restored("POLICY_FRESH");
            assert_eq!(
                response_code(&dispatch_bytes(
                    &mut current,
                    &command(0x0000_0188, &[POLICY_SESSION_FIRST], &[], &parameters),
                )),
                RC_SUCCESS
            );
            assert_ne!(
                loaded_session(&current.live, POLICY_SESSION_FIRST)
                    .expect("a session")
                    .attributes
                    & SESSION_ATTR_IS_NAME_HASH_DEFINED,
                0
            );
        }
    }

    mod pin_index_counters {
        use super::*;
        use crate::library::tpm2::golden_responses::nv::nv_vector;

        const PIN_PASS_DEFINE: &str = "8002000000300000012a4000000100000009400000090000000000000370696e000e01000040000b0206009200000008";
        const PIN_PASS_SET_LIMIT: &str = "80020000002b00000137400000010100004000000009400000090000000000000800000000000000020000";
        const PIN_PASS_OWNER_READ_BEFORE: &str =
            "8002000000230000014e40000001010000400000000940000009000000000000080000";
        const PIN_PASS_FIRST_USE: &str =
            "8002000000260000014e01000040010000400000000c40000009000000000370696e00080000";
        const PIN_PASS_SECOND_USE: &str =
            "8002000000260000014e01000040010000400000000c40000009000000000370696e00080000";
        const PIN_PASS_EXHAUSTED: &str =
            "8002000000260000014e01000040010000400000000c40000009000000000370696e00080000";
        const PIN_PASS_OWNER_READ_AFTER: &str =
            "8002000000230000014e40000001010000400000000940000009000000000000080000";
        const PIN_FAIL_DEFINE: &str = "8002000000300000012a4000000100000009400000090000000000000370696e000e01000041000b0206008200000008";
        const PIN_FAIL_SET_LIMIT: &str = "80020000002b00000137400000010100004100000009400000090000000000000800000000000000020000";
        const PIN_FAIL_BAD_AUTH: &str =
            "8002000000260000014e01000041010000410000000c40000009000000000362616400080000";
        const PIN_FAIL_OWNER_READ_AFTER_BAD: &str =
            "8002000000230000014e40000001010000410000000940000009000000000000080000";
        const PIN_FAIL_GOOD_AUTH: &str =
            "8002000000260000014e01000041010000410000000c40000009000000000370696e00080000";
        const PIN_FAIL_OWNER_READ_AFTER_GOOD: &str =
            "8002000000230000014e40000001010000410000000940000009000000000000080000";

        #[track_caller]
        fn pin_runtime() -> Tpm2Runtime {
            use crate::library::tpm2::restore_permanent_blob_for_test;
            let mut runtime = restore_permanent_blob_for_test(nv_vector("PERMALL_BASE"))
                .expect("the oracle permanent state restores");
            assert_eq!(
                response_code_of(&send(&mut runtime, &hex("80010000000c000001440000"))),
                0,
                "the oracle state starts up"
            );
            runtime.nv_update_pending = false;
            runtime
        }

        #[track_caller]
        fn replay(runtime: &mut Tpm2Runtime, steps: &[(&str, &str)]) {
            for (command, record) in steps {
                assert_eq!(send(runtime, &hex(command)), nv_vector(record), "{record}");
            }
        }

        #[test]
        fn pin_pass_authorized_use_count() {
            let mut runtime = pin_runtime();
            replay(
                &mut runtime,
                &[
                    (PIN_PASS_DEFINE, "PIN_PASS_DEFINE"),
                    (PIN_PASS_SET_LIMIT, "PIN_PASS_SET_LIMIT"),
                    (PIN_PASS_OWNER_READ_BEFORE, "PIN_PASS_OWNER_READ_BEFORE"),
                    (PIN_PASS_FIRST_USE, "PIN_PASS_FIRST_USE"),
                    (PIN_PASS_SECOND_USE, "PIN_PASS_SECOND_USE"),
                ],
            );
        }

        #[test]
        fn exhausted_pin_pass_authorization_rejection() {
            let mut runtime = pin_runtime();
            replay(
                &mut runtime,
                &[
                    (PIN_PASS_DEFINE, "PIN_PASS_DEFINE"),
                    (PIN_PASS_SET_LIMIT, "PIN_PASS_SET_LIMIT"),
                    (PIN_PASS_FIRST_USE, "PIN_PASS_FIRST_USE"),
                    (PIN_PASS_SECOND_USE, "PIN_PASS_SECOND_USE"),
                    (PIN_PASS_EXHAUSTED, "PIN_PASS_EXHAUSTED"),
                    (PIN_PASS_OWNER_READ_AFTER, "PIN_PASS_OWNER_READ_AFTER"),
                ],
            );
            assert_eq!(
                response_code_of(&send(&mut runtime, &hex(PIN_PASS_EXHAUSTED))),
                0x12f,
                "the exhausted index reports an unavailable authorization value"
            );
        }

        #[test]
        fn pin_fail_count_increment_and_success_reset() {
            let mut runtime = pin_runtime();
            replay(
                &mut runtime,
                &[
                    (PIN_FAIL_DEFINE, "PIN_FAIL_DEFINE"),
                    (PIN_FAIL_SET_LIMIT, "PIN_FAIL_SET_LIMIT"),
                    (PIN_FAIL_BAD_AUTH, "PIN_FAIL_BAD_AUTH"),
                    (
                        PIN_FAIL_OWNER_READ_AFTER_BAD,
                        "PIN_FAIL_OWNER_READ_AFTER_BAD",
                    ),
                    (PIN_FAIL_GOOD_AUTH, "PIN_FAIL_GOOD_AUTH"),
                    (
                        PIN_FAIL_OWNER_READ_AFTER_GOOD,
                        "PIN_FAIL_OWNER_READ_AFTER_GOOD",
                    ),
                ],
            );
        }

        #[test]
        fn owner_authorized_read_counter_unchanged() {
            let mut runtime = pin_runtime();
            replay(
                &mut runtime,
                &[
                    (PIN_PASS_DEFINE, "PIN_PASS_DEFINE"),
                    (PIN_PASS_SET_LIMIT, "PIN_PASS_SET_LIMIT"),
                ],
            );
            for _ in 0..4 {
                assert_eq!(
                    send(&mut runtime, &hex(PIN_PASS_OWNER_READ_BEFORE)),
                    nv_vector("PIN_PASS_OWNER_READ_BEFORE"),
                    "the owner authorization does not use the index authValue"
                );
            }
        }
    }

    mod transactional {
        use super::*;
        use crate::library::tpm2::failure_mode::FailureLocation;
        use crate::library::tpm2::persistent::persistent_all_store;

        const FAILURE: u32 = 0x101;
        const SIZE_PARAMETER_1: u32 = 0x1d5;
        const UNSUPPORTED_SYMMETRIC: u16 = 0x0013;
        const SAS_SYM_AES_CFB: &str = "80010000002f00000176400000074000000700105a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a000000000600800043000b";
        const HMAC_SESSION_1: u32 = 0x0200_0001;
        const NV_DEFINE_PASSWORD_AREA: [u8; 13] = [0, 0, 0, 9, 0x40, 0, 0, 9, 0, 0, 0, 0, 0];

        #[derive(Debug, Eq, PartialEq)]
        struct Observable {
            permanent: Vec<u8>,
            nv_memory: Vec<u8>,
            nv_update_pending: bool,
            pcrs: Vec<[Option<Vec<u8>>; 4]>,
            free_session_slots: u32,
            exclusive_audit: u32,
            sessions: Vec<Option<(u32, u32, Vec<u8>, Vec<u8>, Vec<u8>)>>,
        }

        fn observable(runtime: &Tpm2Runtime) -> Observable {
            Observable {
                permanent: persistent_all_store(runtime.state.as_ref().expect("decoded state"))
                    .expect("the permanent state serializes"),
                nv_memory: runtime.nv_memory.to_vec(),
                nv_update_pending: runtime.nv_update_pending,
                pcrs: runtime
                    .live
                    .pcrs
                    .iter()
                    .map(|pcr| pcr.banks.clone())
                    .collect(),
                free_session_slots: runtime.live.free_session_slots,
                exclusive_audit: exclusive_audit_session(runtime),
                sessions: runtime
                    .live
                    .sessions
                    .iter()
                    .map(|slot| {
                        slot.session.as_ref().map(|session| {
                            (
                                session.attributes,
                                session.command_code,
                                session.nonce_tpm.as_bytes().to_vec(),
                                session.audit_digest.clone(),
                                session.session_key.as_bytes().to_vec(),
                            )
                        })
                    })
                    .collect(),
            }
        }

        fn drbg_requests(runtime: &Tpm2Runtime) -> u64 {
            runtime.live.orderly.drbg_state.reseed_counter
        }

        #[track_caller]
        fn assert_mutates(snapshot: &str, starts: &[&str], command: &[u8]) {
            let mut runtime = opened(snapshot, starts);
            let before = observable(&runtime);
            send(&mut runtime, command);
            assert_ne!(
                observable(&runtime),
                before,
                "the command under test has to change something to be worth rolling back"
            );
        }

        #[track_caller]
        fn assert_same(now: &Observable, before: &Observable) {
            assert_eq!(now.permanent == before.permanent, true, "permanent");
            assert_eq!(now.nv_memory == before.nv_memory, true, "nv_memory");
            assert_eq!(
                now.nv_update_pending, before.nv_update_pending,
                "nv_pending"
            );
            assert_eq!(now.pcrs == before.pcrs, true, "pcrs");
            assert_eq!(now.free_session_slots, before.free_session_slots, "slots");
            assert_eq!(now.exclusive_audit, before.exclusive_audit, "exclusive");
            assert_eq!(now.sessions, before.sessions, "sessions");
        }

        struct FaultGuard;

        impl FaultGuard {
            fn arm(fault: ResponseFault) -> Self {
                inject_response_fault(Some(fault));
                Self
            }
        }

        impl Drop for FaultGuard {
            fn drop(&mut self) {
                inject_response_fault(None);
            }
        }

        fn hmac_authorized(command: &str, handle: u32) -> Vec<u8> {
            let bytes = hex(command);
            let at = bytes
                .windows(NV_DEFINE_PASSWORD_AREA.len())
                .position(|window| window == NV_DEFINE_PASSWORD_AREA)
                .expect("a password authorization area");
            let mut area = 25u32.to_be_bytes().to_vec();
            area.extend_from_slice(&handle.to_be_bytes());
            area.extend_from_slice(&16u16.to_be_bytes());
            area.extend_from_slice(&[0x5a; 16]);
            area.push(0x01);
            area.extend_from_slice(&0u16.to_be_bytes());

            let mut out = bytes[..at].to_vec();
            out.extend_from_slice(&area);
            out.extend_from_slice(&bytes[at + NV_DEFINE_PASSWORD_AREA.len()..]);
            let size = out.len() as u32;
            out[2..6].copy_from_slice(&size.to_be_bytes());
            out
        }

        fn two_session_pcr_extend() -> Vec<u8> {
            let mut bytes = hex(DUPLICATE_SESSION_HANDLE);
            bytes[43..47].copy_from_slice(&HMAC_SESSION_1.to_be_bytes());
            bytes[65] = 0x81;
            bytes
        }

        fn opened(snapshot: &str, starts: &[&str]) -> Tpm2Runtime {
            let mut runtime = restored(snapshot);
            for start in starts {
                assert_eq!(
                    response_code(&send(&mut runtime, &hex(start))),
                    0,
                    "the session opens"
                );
            }
            runtime
        }

        fn response_code(response: &[u8]) -> u32 {
            u32::from_be_bytes(response[6..10].try_into().expect("four bytes"))
        }

        #[test]
        fn response_nonce_failure_pcr_extend_rollback() {
            assert_mutates("READY", &[UNSALTED_START], &hex(EMPTY_HMAC_PCR_EXTEND));
            let mut runtime = opened("READY", &[UNSALTED_START]);
            let before = observable(&runtime);
            runtime.live.orderly.drbg_state.drbg_magic ^= 0xffff_ffff;

            assert_eq!(
                response_code(&send(&mut runtime, &hex(EMPTY_HMAC_PCR_EXTEND))),
                FAILURE
            );
            assert!(runtime.failure_mode, "the reference latches the failure");
            assert_eq!(
                runtime.failure_diagnostics,
                FailureLocation::DrbgInvalidState.diagnostics()
            );
            runtime.live.orderly.drbg_state.drbg_magic ^= 0xffff_ffff;
            assert_same(&observable(&runtime), &before);
        }

        #[test]
        fn response_nonce_failure_nv_define_rollback() {
            assert_mutates(
                "READY",
                &[UNSALTED_START],
                &hmac_authorized(NV_DEFINE_POLICY_INDEX, HMAC_SESSION_0),
            );
            let mut runtime = opened("READY", &[UNSALTED_START]);
            let before = observable(&runtime);
            runtime.live.orderly.drbg_state.drbg_magic ^= 0xffff_ffff;

            let command = hmac_authorized(NV_DEFINE_POLICY_INDEX, HMAC_SESSION_0);
            assert_eq!(response_code(&send(&mut runtime, &command)), FAILURE);
            assert!(runtime.failure_mode);
            runtime.live.orderly.drbg_state.drbg_magic ^= 0xffff_ffff;
            assert_same(&observable(&runtime), &before);
        }

        #[test]
        fn response_encryption_failure_rollback() {
            let mut runtime = opened("READY", &[SAS_SYM_AES_CFB]);
            let symmetric = loaded_session(&runtime.live, HMAC_SESSION_0)
                .expect("the session is loaded")
                .symmetric;
            let before = observable(&runtime);
            let requests = drbg_requests(&runtime);
            loaded_session_mut(&mut runtime.live, HMAC_SESSION_0)
                .expect("the session is loaded")
                .symmetric
                .algorithm = UNSUPPORTED_SYMMETRIC;

            let mut command = hex(AUDIT_GET_RANDOM);
            command[36] = 0xc1;
            assert_eq!(
                response_code(&send(&mut runtime, &command)),
                TPM_RC_SYMMETRIC
            );
            loaded_session_mut(&mut runtime.live, HMAC_SESSION_0)
                .expect("the session is loaded")
                .symmetric = symmetric;
            assert_same(&observable(&runtime), &before);
            assert!(
                drbg_requests(&runtime) > requests,
                "the reference never rewinds a nonce it already drew"
            );
        }

        #[test]
        fn response_hmac_failure_pcr_extend_rollback() {
            let mut runtime = opened("READY", &[UNSALTED_START]);
            let before = observable(&runtime);
            let _guard = FaultGuard::arm(ResponseFault::ResponseHmac);

            assert_eq!(
                response_code(&send(&mut runtime, &hex(EMPTY_HMAC_PCR_EXTEND))),
                FAILURE
            );
            assert_same(&observable(&runtime), &before);
            assert!(!runtime.failure_mode, "a returned error is not fatal");
        }

        #[test]
        fn response_hmac_failure_policy_deletion_rollback() {
            let mut runtime = restored("NVUSS_READY");
            for assertion in [NVUSS_POLICY_COMMAND_CODE, NVUSS_POLICY_AUTH_VALUE] {
                send(&mut runtime, &hex(assertion));
            }
            let before = observable(&runtime);
            let _guard = FaultGuard::arm(ResponseFault::ResponseHmac);

            assert_eq!(
                response_code(&send(&mut runtime, &hex(NVUSS_CONTINUED))),
                FAILURE
            );
            assert_same(&observable(&runtime), &before);
            assert!(runtime.removed_session_associations.is_empty());
            assert!(!runtime.failure_mode, "a returned error is not fatal");
        }

        #[test]
        fn rolled_back_deletion_association_restoration() {
            let mut runtime = restored("NVUSS_READY");
            for assertion in [NVUSS_POLICY_COMMAND_CODE, NVUSS_POLICY_AUTH_VALUE] {
                send(&mut runtime, &hex(assertion));
            }
            let _guard = FaultGuard::arm(ResponseFault::ResponseHmac);
            assert_eq!(
                response_code(&send(&mut runtime, &hex(NVUSS_CONTINUED))),
                FAILURE
            );
            assert_eq!(
                runtime
                    .restored_volatile
                    .as_ref()
                    .expect("recorded session state")
                    .session_process
                    .associated_handles[0],
                NVUSS_INDEX,
                "the rolled back command keeps the original association"
            );
        }

        #[test]
        fn audit_init_failure_rollback() {
            let mut runtime = restored("AUDIT_SESSION");
            let before = observable(&runtime);
            let _guard = FaultGuard::arm(ResponseFault::AuditInit);

            assert_eq!(
                response_code(&send(&mut runtime, &hex(AUDIT_GET_RANDOM))),
                FAILURE
            );
            assert_same(&observable(&runtime), &before);
        }

        #[test]
        fn audit_extension_failure_rollback() {
            let mut runtime = restored("AUDIT_SESSION");
            let before = observable(&runtime);
            let _guard = FaultGuard::arm(ResponseFault::AuditExtend);

            assert_eq!(
                response_code(&send(&mut runtime, &hex(AUDIT_GET_RANDOM))),
                FAILURE
            );
            assert_same(&observable(&runtime), &before);
            assert_eq!(exclusive_audit_session(&runtime), before.exclusive_audit);
        }

        #[test]
        fn second_session_failure_first_session_rollback() {
            assert_mutates(
                "READY",
                &[UNSALTED_START, UNSALTED_START],
                &two_session_pcr_extend(),
            );
            let mut runtime = opened("READY", &[UNSALTED_START, UNSALTED_START]);
            let before = observable(&runtime);
            let requests = drbg_requests(&runtime);
            let _guard = FaultGuard::arm(ResponseFault::SecondSession);

            assert_eq!(
                response_code(&send(&mut runtime, &two_session_pcr_extend())),
                FAILURE
            );
            assert_same(&observable(&runtime), &before);
            assert!(
                drbg_requests(&runtime) > requests,
                "the nonces already drawn are not rewound"
            );
        }

        #[test]
        fn pre_flush_failure_session_retention() {
            let mut runtime = opened("READY", &[UNSALTED_START]);
            let before = observable(&runtime);
            let _guard = FaultGuard::arm(ResponseFault::BeforeFlush);

            let mut command = hex(EMPTY_HMAC_PCR_EXTEND);
            command[40] = 0x00;
            assert_eq!(response_code(&send(&mut runtime, &command)), FAILURE);
            assert!(
                loaded_session(&runtime.live, HMAC_SESSION_0).is_some(),
                "the session scheduled for flushing is still loaded"
            );
            assert_same(&observable(&runtime), &before);
        }

        #[test]
        fn rollback_entropy_latch_and_self_test_preservation() {
            let mut runtime = opened("READY", &[UNSALTED_START]);
            runtime.entropy_bad = true;
            let pending = runtime.self_test.pending;
            let _guard = FaultGuard::arm(ResponseFault::ResponseHmac);

            assert_eq!(
                response_code(&send(&mut runtime, &hex(EMPTY_HMAC_PCR_EXTEND))),
                FAILURE
            );
            assert!(runtime.entropy_bad, "the entropy latch survives");
            assert_eq!(
                runtime.self_test.pending, pending,
                "consumed self tests are not re-armed"
            );
        }

        #[test]
        fn handler_failure_no_partial_change() {
            let mut runtime = opened("READY", &[UNSALTED_START]);
            let before = observable(&runtime);
            assert_eq!(
                response_code(&send(&mut runtime, &hex(AUDIT_ON_FAILING_COMMAND))),
                SIZE_PARAMETER_1
            );
            assert_same(&observable(&runtime), &before);
        }

        #[test]
        fn successful_command_full_commit() {
            let mut runtime = opened("READY", &[UNSALTED_START]);
            let before = observable(&runtime);
            assert_eq!(
                response_code(&send(&mut runtime, &hex(EMPTY_HMAC_PCR_EXTEND))),
                0
            );
            assert_ne!(observable(&runtime), before);
        }
    }

    #[test]
    fn password_comparison_trailing_zero_only_tolerance() {
        assert!(password_matches(&[], &[]));
        assert!(password_matches(&[], &[0x00, 0x00]));
        assert!(password_matches(b"pw", &[b'p', b'w', 0x00]));
        assert!(!password_matches(b"pw", b"pW"));
        assert!(!password_matches(&[], b"pw"));
        assert!(!password_matches(&[0x00, 0x01], &[0x01, 0x00]));
    }

    #[test]
    fn format_zero_code_no_decoration() {
        assert_eq!(
            decorate(TPM_RC_FAILURE, TPM_RC_S + TPM_RC_1),
            TPM_RC_FAILURE
        );
        assert_eq!(
            decorate(TPM_RC_BAD_AUTH, TPM_RC_S + TPM_RC_1),
            TPM_RC_BAD_AUTH + TPM_RC_S + TPM_RC_1
        );
        assert_eq!(
            decorate(TPM_RC_POLICY_FAIL, TPM_RC_S + TPM_RC_1),
            TPM_RC_POLICY_FAIL + TPM_RC_S + TPM_RC_1
        );
    }

    #[test]
    fn internal_failure_no_session_decoration() {
        let runtime = empty_state_runtime();
        assert_eq!(
            entity_auth_value(&runtime, 0x4000_000c).unwrap_err(),
            TPM_RC_FAILURE
        );
    }

    #[test]
    fn authorization_area_mutation_panic_safety() {
        let valid = hex(HMAC_AUTH_PCR_EXTEND);
        for length in 10..valid.len() {
            for byte in [0x00u8, 0x01, 0x80, 0xff] {
                let mut mutated = valid[..length].to_vec();
                *mutated.last_mut().expect("a non-empty prefix") = byte;
                let size = (mutated.len() as u32).to_be_bytes();
                mutated[2..6].copy_from_slice(&size);
                let mut runtime = restored("THREE_SESSIONS");
                let _ = send(&mut runtime, &mutated);
            }
        }
    }
}
