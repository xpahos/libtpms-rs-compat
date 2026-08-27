use crate::library::constants::{
    TPM_RC_CPHASH, TPM_RC_EXPIRED, TPM_RC_FAILURE, TPM_RC_NONCE, TPM_RC_NV_UNAVAILABLE, TPM_RC_SIZE,
};
use crate::library::tpm2::command::core::dispatcher::{CommandFrame, handle_at};
use crate::library::tpm2::crypto::Hasher;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::self_test::self_test_algorithm;
use crate::library::tpm2::session::{
    SESSION_ATTR_IS_BOUND, SESSION_ATTR_IS_CP_HASH_DEFINED, SESSION_ATTR_IS_NAME_HASH_DEFINED,
    SESSION_ATTR_IS_PARAMETERS_HASH_DEFINED, SESSION_ATTR_IS_TEMPLATE_HASH_DEFINED,
    SESSION_ATTR_IS_TRIAL_POLICY, digest_size, digests_equal, loaded_session, loaded_session_mut,
};
use crate::library::tpm2::volatile::OwnedSession;
use crate::types::TpmResult;
pub(in crate::library::tpm2::command) const EXPIRATION_BIT: u64 = 1 << 63;

pub(in crate::library::tpm2::command) const TPM_EO_EQ: u16 = 0x0000;
pub(in crate::library::tpm2::command) const TPM_EO_NEQ: u16 = 0x0001;
pub(in crate::library::tpm2::command) const TPM_EO_SIGNED_GT: u16 = 0x0002;
pub(in crate::library::tpm2::command) const TPM_EO_UNSIGNED_GT: u16 = 0x0003;
pub(in crate::library::tpm2::command) const TPM_EO_SIGNED_LT: u16 = 0x0004;
pub(in crate::library::tpm2::command) const TPM_EO_UNSIGNED_LT: u16 = 0x0005;
pub(in crate::library::tpm2::command) const TPM_EO_SIGNED_GE: u16 = 0x0006;
pub(in crate::library::tpm2::command) const TPM_EO_UNSIGNED_GE: u16 = 0x0007;
pub(in crate::library::tpm2::command) const TPM_EO_SIGNED_LE: u16 = 0x0008;
pub(in crate::library::tpm2::command) const TPM_EO_UNSIGNED_LE: u16 = 0x0009;
pub(in crate::library::tpm2::command) const TPM_EO_BITSET: u16 = 0x000a;
pub(in crate::library::tpm2::command) const TPM_EO_BITCLEAR: u16 = 0x000b;

pub(in crate::library::tpm2::command) struct PolicySession {
    pub(in crate::library::tpm2::command) handle: u32,
    pub(in crate::library::tpm2::command) hash_alg: u16,
    pub(in crate::library::tpm2::command) is_trial: bool,
}

pub(in crate::library::tpm2::command) fn policy_session_at(
    runtime: &Tpm2Runtime,
    frame: &CommandFrame<'_>,
    position: usize,
) -> Result<PolicySession, TpmResult> {
    let handle = handle_at(frame, position)?;
    let session = loaded_session(&runtime.live, handle).ok_or(TPM_RC_FAILURE)?;
    Ok(PolicySession {
        handle,
        hash_alg: session.auth_hash_alg,
        is_trial: session.attributes & SESSION_ATTR_IS_TRIAL_POLICY != 0,
    })
}

pub(in crate::library::tpm2::command) fn policy_session(
    runtime: &Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<PolicySession, TpmResult> {
    policy_session_at(runtime, frame, 0)
}

pub(in crate::library::tpm2::command) fn live_session<'a>(
    runtime: &'a Tpm2Runtime,
    session: &PolicySession,
) -> Result<&'a OwnedSession, TpmResult> {
    loaded_session(&runtime.live, session.handle).ok_or(TPM_RC_FAILURE)
}

pub(in crate::library::tpm2::command) fn live_session_mut<'a>(
    runtime: &'a mut Tpm2Runtime,
    session: &PolicySession,
) -> Result<&'a mut OwnedSession, TpmResult> {
    loaded_session_mut(&mut runtime.live, session.handle).ok_or(TPM_RC_FAILURE)
}

pub(in crate::library::tpm2::command) fn no_parameters(
    frame: &CommandFrame<'_>,
) -> Result<(), TpmResult> {
    if frame.parameters.is_empty() {
        Ok(())
    } else {
        Err(TPM_RC_SIZE)
    }
}

pub(in crate::library::tpm2::command) fn policy_digest(
    runtime: &Tpm2Runtime,
    handle: u32,
) -> Result<Vec<u8>, TpmResult> {
    loaded_session(&runtime.live, handle)
        .map(|session| session.audit_digest.clone())
        .ok_or(TPM_RC_FAILURE)
}

pub(in crate::library::tpm2::command) fn start_policy_hash(
    runtime: &mut Tpm2Runtime,
    hash_alg: u16,
) -> Result<Hasher, TpmResult> {
    self_test_algorithm(runtime, hash_alg)?;
    Hasher::new(hash_alg).ok_or(TPM_RC_FAILURE)
}

pub(in crate::library::tpm2::command) fn store_policy_digest(
    runtime: &mut Tpm2Runtime,
    handle: u32,
    digest: Vec<u8>,
) -> Result<(), TpmResult> {
    let session = loaded_session_mut(&mut runtime.live, handle).ok_or(TPM_RC_FAILURE)?;
    session.audit_digest = digest;
    Ok(())
}

pub(in crate::library::tpm2::command) fn zero_policy_digest(
    hash_alg: u16,
) -> Result<Vec<u8>, TpmResult> {
    Ok(vec![0u8; digest_size(hash_alg).ok_or(TPM_RC_FAILURE)?])
}

pub(in crate::library::tpm2::command) fn hash_parts(
    runtime: &mut Tpm2Runtime,
    hash_alg: u16,
    parts: &[&[u8]],
) -> Result<Vec<u8>, TpmResult> {
    let mut hasher = start_policy_hash(runtime, hash_alg)?;
    for part in parts {
        hasher.update(part);
    }
    Ok(hasher.finalize())
}

pub(in crate::library::tpm2::command) fn next_policy_digest(
    runtime: &mut Tpm2Runtime,
    session: &PolicySession,
    command_code: u32,
    extra: &[&[u8]],
) -> Result<Vec<u8>, TpmResult> {
    let previous = policy_digest(runtime, session.handle)?;
    let code = command_code.to_be_bytes();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(extra.len() + 2);
    parts.push(&previous);
    parts.push(&code);
    parts.extend_from_slice(extra);
    hash_parts(runtime, session.hash_alg, &parts)
}

pub(in crate::library::tpm2::command) fn extend_policy_digest(
    runtime: &mut Tpm2Runtime,
    session: &PolicySession,
    command_code: u32,
    extra: &[&[u8]],
) -> Result<(), TpmResult> {
    let digest = next_policy_digest(runtime, session, command_code, extra)?;
    store_policy_digest(runtime, session.handle, digest)
}

pub(in crate::library::tpm2::command) fn is_cp_hash_union_occupied(attributes: u32) -> bool {
    attributes
        & (SESSION_ATTR_IS_BOUND
            | SESSION_ATTR_IS_CP_HASH_DEFINED
            | SESSION_ATTR_IS_NAME_HASH_DEFINED
            | SESSION_ATTR_IS_PARAMETERS_HASH_DEFINED
            | SESSION_ATTR_IS_TEMPLATE_HASH_DEFINED)
        != 0
}

pub(in crate::library::tpm2::command) struct PolicyUpdate<'a> {
    pub(in crate::library::tpm2::command) command_code: u32,
    pub(in crate::library::tpm2::command) name: Option<&'a [u8]>,
    pub(in crate::library::tpm2::command) policy_ref: Option<&'a [u8]>,
    pub(in crate::library::tpm2::command) cp_hash: Option<&'a [u8]>,
    pub(in crate::library::tpm2::command) timeout: u64,
}

impl<'a> PolicyUpdate<'a> {
    pub(in crate::library::tpm2::command) fn new(command_code: u32) -> Self {
        Self {
            command_code,
            name: None,
            policy_ref: None,
            cp_hash: None,
            timeout: 0,
        }
    }

    pub(in crate::library::tpm2::command) fn with_name(mut self, name: &'a [u8]) -> Self {
        self.name = Some(name);
        self
    }

    pub(in crate::library::tpm2::command) fn with_policy_ref(
        mut self,
        policy_ref: &'a [u8],
    ) -> Self {
        self.policy_ref = Some(policy_ref);
        self
    }

    pub(in crate::library::tpm2::command) fn with_cp_hash(mut self, cp_hash: &'a [u8]) -> Self {
        self.cp_hash = Some(cp_hash);
        self
    }

    pub(in crate::library::tpm2::command) fn with_timeout(mut self, timeout: u64) -> Self {
        self.timeout = timeout;
        self
    }
}

pub(in crate::library::tpm2::command) fn policy_context_update(
    runtime: &mut Tpm2Runtime,
    session: &PolicySession,
    update: PolicyUpdate<'_>,
) -> Result<(), TpmResult> {
    let named: &[&[u8]] = match &update.name {
        Some(name) => core::slice::from_ref(name),
        None => &[],
    };
    let mut digest = next_policy_digest(runtime, session, update.command_code, named)?;
    if let Some(policy_ref) = update.policy_ref {
        digest = hash_parts(runtime, session.hash_alg, &[&digest, policy_ref])?;
    }

    let entry = live_session_mut(runtime, session)?;
    entry.audit_digest = digest;
    if let Some(cp_hash) = update.cp_hash
        && !cp_hash.is_empty()
    {
        entry.bound_entity = cp_hash.to_vec();
        entry.attributes |= SESSION_ATTR_IS_CP_HASH_DEFINED;
    }
    if update.timeout != 0 && (entry.timeout == 0 || entry.timeout > update.timeout) {
        entry.timeout = update.timeout;
    }
    Ok(())
}

pub(in crate::library::tpm2::command) fn policy_digest_clear(
    runtime: &mut Tpm2Runtime,
    session: &PolicySession,
) -> Result<(), TpmResult> {
    let zeroed = zero_policy_digest(session.hash_alg)?;
    store_policy_digest(runtime, session.handle, zeroed)
}

pub(in crate::library::tpm2::command) struct ParameterBlame {
    pub(in crate::library::tpm2::command) nonce: TpmResult,
    pub(in crate::library::tpm2::command) cp_hash: TpmResult,
    pub(in crate::library::tpm2::command) expiration: TpmResult,
}

pub(in crate::library::tpm2::command) fn policy_parameter_checks(
    runtime: &Tpm2Runtime,
    session: &PolicySession,
    auth_timeout: u64,
    cp_hash: Option<&[u8]>,
    nonce: Option<&[u8]>,
    blame: &ParameterBlame,
) -> Result<(), TpmResult> {
    let entry = live_session(runtime, session)?;
    if let Some(nonce) = nonce
        && !nonce.is_empty()
        && !digests_equal(nonce, entry.nonce_tpm.as_bytes())
    {
        return Err(TPM_RC_NONCE + blame.nonce);
    }
    if auth_timeout != 0 {
        if !runtime.nv_available {
            return Err(TPM_RC_NV_UNAVAILABLE);
        }
        let epoch = runtime
            .state
            .as_ref()
            .ok_or(TPM_RC_FAILURE)?
            .persistent
            .time_epoch;
        let entry = live_session(runtime, session)?;
        if auth_timeout < runtime.timer.time_ms || entry.epoch != epoch {
            return Err(TPM_RC_EXPIRED + blame.expiration);
        }
    }
    if let Some(cp_hash) = cp_hash
        && !cp_hash.is_empty()
    {
        let entry = live_session(runtime, session)?;
        if cp_hash.len() != entry.audit_digest.len() {
            return Err(TPM_RC_SIZE + blame.cp_hash);
        }
        if !entry.bound_entity.is_empty() && !digests_equal(cp_hash, &entry.bound_entity) {
            return Err(TPM_RC_CPHASH);
        }
    }
    Ok(())
}

pub(in crate::library::tpm2::command) fn compute_auth_timeout(
    runtime: &Tpm2Runtime,
    session_start_time: u64,
    expiration: i32,
    nonce_is_empty: bool,
) -> u64 {
    if expiration == 0 {
        return 0;
    }
    let mut seconds = expiration;
    if seconds < 0 {
        if seconds == i32::MIN {
            seconds += 1;
        }
        seconds = -seconds;
    }
    let milliseconds = (seconds as u64).wrapping_mul(1000);
    if nonce_is_empty {
        milliseconds.wrapping_add(runtime.timer.time_ms % 1000)
    } else {
        session_start_time.wrapping_add(milliseconds)
    }
}

fn unsigned_compare(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    match a.len().cmp(&b.len()) {
        core::cmp::Ordering::Equal => a.cmp(b),
        other => other,
    }
}

fn signed_compare(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    match (a.first(), b.first()) {
        (Some(first_a), Some(first_b)) if (first_a ^ first_b) & 0x80 != 0 => {
            if first_a & 0x80 != 0 {
                core::cmp::Ordering::Less
            } else {
                core::cmp::Ordering::Greater
            }
        }
        _ => unsigned_compare(a, b),
    }
}

pub(in crate::library::tpm2::command) fn operation_is_supported(operation: u16) -> bool {
    (TPM_EO_EQ..=TPM_EO_BITCLEAR).contains(&operation)
}

pub(in crate::library::tpm2::command) fn check_condition(
    operation: u16,
    a: &[u8],
    b: &[u8],
) -> Result<bool, TpmResult> {
    use core::cmp::Ordering;
    let unsigned = || unsigned_compare(a, b);
    let signed = || signed_compare(a, b);
    Ok(match operation {
        TPM_EO_EQ => unsigned() == Ordering::Equal,
        TPM_EO_NEQ => unsigned() != Ordering::Equal,
        TPM_EO_SIGNED_GT => signed() == Ordering::Greater,
        TPM_EO_UNSIGNED_GT => unsigned() == Ordering::Greater,
        TPM_EO_SIGNED_LT => signed() == Ordering::Less,
        TPM_EO_UNSIGNED_LT => unsigned() == Ordering::Less,
        TPM_EO_SIGNED_GE => signed() != Ordering::Less,
        TPM_EO_UNSIGNED_GE => unsigned() != Ordering::Less,
        TPM_EO_SIGNED_LE => signed() != Ordering::Greater,
        TPM_EO_UNSIGNED_LE => unsigned() != Ordering::Greater,
        TPM_EO_BITSET => a.iter().zip(b).all(|(left, right)| left & right == *right),
        TPM_EO_BITCLEAR => a.iter().zip(b).all(|(left, right)| left & right == 0),
        _ => return Err(TPM_RC_FAILURE),
    })
}

#[cfg(test)]
pub(in crate::library::tpm2::command) mod test_support {
    use crate::library::tpm2::golden_responses::policy_sessions::vector;
    use crate::library::tpm2::runtime::Tpm2Runtime;
    use crate::library::tpm2::session::loaded_session;
    use crate::library::tpm2::volatile::OwnedSession;
    use crate::library::tpm2::{attach_volatile_blob_for_test, restore_permanent_blob_for_test};

    pub(in crate::library::tpm2::command) const POLICY_SESSION_0: u32 = 0x0300_0000;
    pub(in crate::library::tpm2::command) const HMAC_SESSION_0: u32 = 0x0200_0000;

    pub(in crate::library::tpm2::command) const CC_START_AUTH_SESSION: u32 = 0x0000_0176;
    pub(in crate::library::tpm2::command) const CC_POLICY_NV: u32 = 0x0000_0149;
    pub(in crate::library::tpm2::command) const CC_POLICY_SECRET: u32 = 0x0000_0151;
    pub(in crate::library::tpm2::command) const CC_POLICY_SIGNED: u32 = 0x0000_0160;
    pub(in crate::library::tpm2::command) const CC_POLICY_AUTHORIZE: u32 = 0x0000_016a;
    pub(in crate::library::tpm2::command) const CC_POLICY_OR: u32 = 0x0000_0171;
    pub(in crate::library::tpm2::command) const CC_POLICY_AUTH_VALUE: u32 = 0x0000_016b;
    pub(in crate::library::tpm2::command) const CC_POLICY_COMMAND_CODE: u32 = 0x0000_016c;
    pub(in crate::library::tpm2::command) const CC_POLICY_COUNTER_TIMER: u32 = 0x0000_016d;
    pub(in crate::library::tpm2::command) const CC_POLICY_CP_HASH: u32 = 0x0000_016e;
    pub(in crate::library::tpm2::command) const CC_POLICY_LOCALITY: u32 = 0x0000_016f;
    pub(in crate::library::tpm2::command) const CC_POLICY_NAME_HASH: u32 = 0x0000_0170;
    pub(in crate::library::tpm2::command) const CC_POLICY_TICKET: u32 = 0x0000_0172;
    pub(in crate::library::tpm2::command) const CC_POLICY_PCR: u32 = 0x0000_017f;
    pub(in crate::library::tpm2::command) const CC_POLICY_RESTART: u32 = 0x0000_0180;
    pub(in crate::library::tpm2::command) const CC_POLICY_PHYSICAL_PRESENCE: u32 = 0x0000_0187;
    pub(in crate::library::tpm2::command) const CC_POLICY_DUPLICATION_SELECT: u32 = 0x0000_0188;
    pub(in crate::library::tpm2::command) const CC_POLICY_GET_DIGEST: u32 = 0x0000_0189;
    pub(in crate::library::tpm2::command) const CC_POLICY_PASSWORD: u32 = 0x0000_018c;
    pub(in crate::library::tpm2::command) const CC_POLICY_NV_WRITTEN: u32 = 0x0000_018f;
    pub(in crate::library::tpm2::command) const CC_POLICY_TEMPLATE: u32 = 0x0000_0190;
    pub(in crate::library::tpm2::command) const CC_POLICY_AUTHORIZE_NV: u32 = 0x0000_0192;
    pub(in crate::library::tpm2::command) const CC_POLICY_CAPABILITY: u32 = 0x0000_019b;
    pub(in crate::library::tpm2::command) const CC_POLICY_PARAMETERS: u32 = 0x0000_019c;

    #[track_caller]
    pub(in crate::library::tpm2::command) fn restored(snapshot: &str) -> Box<Tpm2Runtime> {
        let mut runtime = restore_permanent_blob_for_test(vector(&format!("PERMALL_{snapshot}")))
            .expect("the oracle permanent state restores");
        attach_volatile_blob_for_test(&mut runtime, vector(&format!("VOLATILE_{snapshot}")))
            .expect("the oracle volatile state attaches");
        assert!(
            runtime.startup_received,
            "the {snapshot} snapshot is past TPM2_Startup"
        );
        runtime
    }

    pub(in crate::library::tpm2::command) fn session_of(
        runtime: &Tpm2Runtime,
        handle: u32,
    ) -> &OwnedSession {
        loaded_session(&runtime.live, handle).expect("a loaded session")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_comparison_operators_match_the_vendored_selectors() {
        assert_eq!(TPM_EO_EQ, 0x0000);
        assert_eq!(TPM_EO_NEQ, 0x0001);
        assert_eq!(TPM_EO_SIGNED_GT, 0x0002);
        assert_eq!(TPM_EO_UNSIGNED_GT, 0x0003);
        assert_eq!(TPM_EO_SIGNED_LT, 0x0004);
        assert_eq!(TPM_EO_UNSIGNED_LT, 0x0005);
        assert_eq!(TPM_EO_SIGNED_GE, 0x0006);
        assert_eq!(TPM_EO_UNSIGNED_GE, 0x0007);
        assert_eq!(TPM_EO_SIGNED_LE, 0x0008);
        assert_eq!(TPM_EO_UNSIGNED_LE, 0x0009);
        assert_eq!(TPM_EO_BITSET, 0x000a);
        assert_eq!(TPM_EO_BITCLEAR, 0x000b);
        for operation in 0..0x0cu16 {
            assert!(operation_is_supported(operation), "{operation:#x}");
        }
        for operation in [0x000cu16, 0x0010, 0xffff] {
            assert!(!operation_is_supported(operation), "{operation:#x}");
        }
    }

    #[test]
    fn unsigned_comparisons_treat_the_buffers_as_big_endian_magnitudes() {
        let a = [0x80u8, 0x00];
        let b = [0x00u8, 0x01];
        assert!(check_condition(TPM_EO_UNSIGNED_GT, &a, &b).unwrap());
        assert!(!check_condition(TPM_EO_UNSIGNED_LT, &a, &b).unwrap());
        assert!(check_condition(TPM_EO_UNSIGNED_GE, &a, &b).unwrap());
        assert!(!check_condition(TPM_EO_UNSIGNED_LE, &a, &b).unwrap());
        assert!(check_condition(TPM_EO_NEQ, &a, &b).unwrap());
        assert!(!check_condition(TPM_EO_EQ, &a, &b).unwrap());
        assert!(check_condition(TPM_EO_EQ, &a, &a).unwrap());
        assert!(check_condition(TPM_EO_UNSIGNED_GE, &a, &a).unwrap());
        assert!(check_condition(TPM_EO_UNSIGNED_LE, &a, &a).unwrap());
    }

    #[test]
    fn signed_comparisons_read_the_leading_sign_bit() {
        let negative = [0x80u8, 0x00];
        let positive = [0x00u8, 0x01];
        assert!(check_condition(TPM_EO_SIGNED_LT, &negative, &positive).unwrap());
        assert!(check_condition(TPM_EO_SIGNED_GT, &positive, &negative).unwrap());
        assert!(check_condition(TPM_EO_SIGNED_LE, &negative, &positive).unwrap());
        assert!(!check_condition(TPM_EO_SIGNED_GE, &negative, &positive).unwrap());
        assert!(
            check_condition(TPM_EO_SIGNED_GT, &[0x00, 0x02], &[0x00, 0x01]).unwrap(),
            "same sign falls back to the unsigned comparison"
        );
        assert!(check_condition(TPM_EO_SIGNED_LT, &[0xfe], &[0xff]).unwrap());
    }

    #[test]
    fn different_lengths_order_by_length_first() {
        assert!(check_condition(TPM_EO_UNSIGNED_GT, &[0x00, 0x00], &[0xff]).unwrap());
        assert!(check_condition(TPM_EO_UNSIGNED_LT, &[0xff], &[0x00, 0x00]).unwrap());
        assert!(check_condition(TPM_EO_EQ, &[], &[]).unwrap());
    }

    #[test]
    fn the_bit_operations_test_every_byte() {
        assert!(check_condition(TPM_EO_BITSET, &[0xff, 0x0f], &[0x0f, 0x0f]).unwrap());
        assert!(!check_condition(TPM_EO_BITSET, &[0xff, 0x0e], &[0x0f, 0x0f]).unwrap());
        assert!(check_condition(TPM_EO_BITCLEAR, &[0xf0, 0xf0], &[0x0f, 0x0f]).unwrap());
        assert!(!check_condition(TPM_EO_BITCLEAR, &[0xf0, 0xf1], &[0x0f, 0x0f]).unwrap());
        assert!(check_condition(TPM_EO_BITSET, &[], &[]).unwrap());
        assert!(check_condition(TPM_EO_BITCLEAR, &[], &[]).unwrap());
    }

    #[test]
    fn an_unsupported_operation_is_an_internal_failure() {
        assert_eq!(
            check_condition(0x000c, &[0x00], &[0x00]),
            Err(TPM_RC_FAILURE)
        );
    }

    #[test]
    fn the_expiration_bit_is_the_most_significant_timeout_bit() {
        assert_eq!(EXPIRATION_BIT, 0x8000_0000_0000_0000);
    }
}
