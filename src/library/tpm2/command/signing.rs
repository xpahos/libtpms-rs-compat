use crate::ffi_types::TpmResult;
use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_KEY};

use super::super::commit::CommitState;
use super::super::hierarchy::{TPM_RH_NULL, hierarchy_proof};
use super::super::object_create::resolve_any_object;
use super::super::persistent::{OwnedAnyObjectBody, OwnedObjectBody};
use super::super::random::{finish_live_rand, take_live_rand};
use super::super::runtime::Tpm2Runtime;
use super::super::signature::{Signature, SigningState};
use super::nv_common::{TPM_RC_1, TPM_RC_H};

pub(super) const RC_SIGN_HANDLE: TpmResult = TPM_RC_H + TPM_RC_1;

pub(super) fn signing_object(
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

pub(super) fn hierarchy_proof_for(
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

pub(super) fn load_signing_state(runtime: &mut Tpm2Runtime) -> Result<SigningState, TpmResult> {
    let rand = take_live_rand(runtime)?;
    let commit = CommitState::load(runtime)?;
    Ok(SigningState { rand, commit })
}

pub(super) fn publish_signing_outcome(
    runtime: &mut Tpm2Runtime,
    signing: SigningState,
    signature: Result<Signature, TpmResult>,
) -> Result<Signature, TpmResult> {
    let SigningState { rand, commit } = signing;
    finish_live_rand(runtime, rand)?;
    commit.publish(runtime)?;
    signature
}
