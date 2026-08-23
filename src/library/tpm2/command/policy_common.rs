use crate::ffi_types::TpmResult;
use crate::library::constants::TPM_RC_FAILURE;

use super::super::crypto::Hasher;
use super::super::runtime::Tpm2Runtime;
use super::super::self_test::self_test_algorithm;
use super::super::session::{
    SESSION_ATTR_IS_TRIAL_POLICY, digest_size, loaded_session, loaded_session_mut,
};
use super::dispatcher::CommandFrame;
use super::nv_common::handle_at;

pub(super) struct PolicySession {
    pub(super) handle: u32,
    pub(super) hash_alg: u16,
    pub(super) is_trial: bool,
}

pub(super) fn policy_session(
    runtime: &Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<PolicySession, TpmResult> {
    let handle = handle_at(frame, 0)?;
    let session = loaded_session(&runtime.live, handle).ok_or(TPM_RC_FAILURE)?;
    Ok(PolicySession {
        handle,
        hash_alg: session.auth_hash_alg,
        is_trial: session.attributes & SESSION_ATTR_IS_TRIAL_POLICY != 0,
    })
}

pub(super) fn policy_digest(runtime: &Tpm2Runtime, handle: u32) -> Result<Vec<u8>, TpmResult> {
    loaded_session(&runtime.live, handle)
        .map(|session| session.audit_digest.clone())
        .ok_or(TPM_RC_FAILURE)
}

pub(super) fn start_policy_hash(
    runtime: &mut Tpm2Runtime,
    hash_alg: u16,
) -> Result<Hasher, TpmResult> {
    self_test_algorithm(runtime, hash_alg)?;
    Hasher::new(hash_alg).ok_or(TPM_RC_FAILURE)
}

pub(super) fn store_policy_digest(
    runtime: &mut Tpm2Runtime,
    handle: u32,
    digest: Vec<u8>,
) -> Result<(), TpmResult> {
    let session = loaded_session_mut(&mut runtime.live, handle).ok_or(TPM_RC_FAILURE)?;
    session.audit_digest = digest;
    Ok(())
}

pub(super) fn zero_policy_digest(hash_alg: u16) -> Result<Vec<u8>, TpmResult> {
    Ok(vec![0u8; digest_size(hash_alg).ok_or(TPM_RC_FAILURE)?])
}

pub(super) fn extend_policy_digest(
    runtime: &mut Tpm2Runtime,
    session: &PolicySession,
    command_code: u32,
    extra: &[&[u8]],
) -> Result<(), TpmResult> {
    let previous = policy_digest(runtime, session.handle)?;
    let mut hasher = start_policy_hash(runtime, session.hash_alg)?;
    hasher.update(&previous);
    hasher.update(&command_code.to_be_bytes());
    for part in extra {
        hasher.update(part);
    }
    let digest = hasher.finalize();
    store_policy_digest(runtime, session.handle, digest)
}

#[cfg(test)]
pub(super) mod harness {
    use crate::library::tpm2::golden_responses::policy_sessions::vector;
    use crate::library::tpm2::runtime::Tpm2Runtime;
    use crate::library::tpm2::session::loaded_session;
    use crate::library::tpm2::volatile::OwnedSession;
    use crate::library::tpm2::{attach_volatile_blob_for_test, restore_permanent_blob_for_test};

    pub(in crate::library::tpm2::command) const POLICY_SESSION_0: u32 = 0x0300_0000;
    pub(in crate::library::tpm2::command) const HMAC_SESSION_0: u32 = 0x0200_0000;

    pub(in crate::library::tpm2::command) const CC_START_AUTH_SESSION: u32 = 0x0000_0176;
    pub(in crate::library::tpm2::command) const CC_POLICY_OR: u32 = 0x0000_0171;
    pub(in crate::library::tpm2::command) const CC_POLICY_AUTH_VALUE: u32 = 0x0000_016b;
    pub(in crate::library::tpm2::command) const CC_POLICY_COMMAND_CODE: u32 = 0x0000_016c;
    pub(in crate::library::tpm2::command) const CC_POLICY_PCR: u32 = 0x0000_017f;
    pub(in crate::library::tpm2::command) const CC_POLICY_RESTART: u32 = 0x0000_0180;
    pub(in crate::library::tpm2::command) const CC_POLICY_GET_DIGEST: u32 = 0x0000_0189;
    pub(in crate::library::tpm2::command) const CC_POLICY_PASSWORD: u32 = 0x0000_018c;

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
