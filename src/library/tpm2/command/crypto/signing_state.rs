use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_KEY};
use crate::library::tpm2::command::core::response_code::{TPM_RC_1, TPM_RC_H};
use crate::library::tpm2::commit::CommitState;
use crate::library::tpm2::hierarchy::{TPM_RH_NULL, hierarchy_proof};
use crate::library::tpm2::object_create::resolve_any_object;
use crate::library::tpm2::persistent::{OwnedAnyObjectBody, OwnedObjectBody};
use crate::library::tpm2::random::{finish_live_rand, take_live_rand};
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::signature::{Signature, SigningState};
use crate::types::TpmResult;
pub(in crate::library::tpm2::command) const RC_SIGN_HANDLE: TpmResult = TPM_RC_H + TPM_RC_1;

pub(in crate::library::tpm2::command) fn signing_object(
    runtime: &Tpm2Runtime,
    handle: u32,
) -> Result<Option<Box<OwnedObjectBody>>, TpmResult> {
    if handle == TPM_RH_NULL {
        return Ok(None);
    }
    let object = resolve_any_object(runtime, handle).ok_or(TPM_RC_FAILURE)?;
    match &object.body {
        OwnedAnyObjectBody::Object(body) => Ok(Some(body.clone())),
        _ => Err(TPM_RC_KEY + RC_SIGN_HANDLE),
    }
}

pub(in crate::library::tpm2::command) fn hierarchy_proof_for(
    runtime: &Tpm2Runtime,
    hierarchy: u32,
) -> Result<&[u8], TpmResult> {
    if hierarchy == TPM_RH_NULL {
        return Ok(runtime
            .live
            .state_reset
            .as_ref()
            .ok_or(TPM_RC_FAILURE)?
            .null_proof
            .as_bytes());
    }
    let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
    hierarchy_proof(&state.persistent, hierarchy).ok_or(TPM_RC_FAILURE)
}

pub(in crate::library::tpm2::command) fn load_signing_state(
    runtime: &mut Tpm2Runtime,
) -> Result<SigningState, TpmResult> {
    let rand = take_live_rand(runtime)?;
    let commit = CommitState::load(runtime)?;
    Ok(SigningState { rand, commit })
}

pub(in crate::library::tpm2::command) fn publish_signing_outcome(
    runtime: &mut Tpm2Runtime,
    signing: SigningState,
    signature: Result<Signature, TpmResult>,
) -> Result<Signature, TpmResult> {
    let SigningState { rand, commit } = signing;
    finish_live_rand(runtime, rand)?;
    commit.publish(runtime)?;
    signature
}
