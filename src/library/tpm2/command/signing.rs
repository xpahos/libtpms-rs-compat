use crate::ffi_types::TpmResult;
use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_KEY};

use super::super::hierarchy::TPM_RH_NULL;
use super::super::object_create::{
    is_transient_object_handle, occupied_object_slot, persistent_object_entry,
};
use super::super::persistent::{OwnedAnyObjectBody, OwnedObjectBody, OwnedUserNvramEntry};
use super::super::random::{finish_live_rand, take_live_rand};
use super::super::runtime::Tpm2Runtime;
use super::super::signature::{Signature, SigningState};
use super::super::state::COMMIT_ARRAY_SIZE;
use super::nv_common::{TPM_RC_1, TPM_RC_H};

pub(super) const RC_SIGN_HANDLE: TpmResult = TPM_RC_H + TPM_RC_1;

pub(super) fn signing_object(
    runtime: &Tpm2Runtime,
    handle: u32,
) -> Result<Option<Box<OwnedObjectBody>>, TpmResult> {
    if handle == TPM_RH_NULL {
        return Ok(None);
    }
    let object = if is_transient_object_handle(handle) {
        let slot = occupied_object_slot(runtime, handle).ok_or(TPM_RC_FAILURE)?;
        runtime.live.objects.get(slot).ok_or(TPM_RC_FAILURE)?
    } else {
        let entry = persistent_object_entry(runtime, handle).ok_or(TPM_RC_FAILURE)?;
        match runtime
            .state
            .as_ref()
            .ok_or(TPM_RC_FAILURE)?
            .user_nvram
            .entries
            .get(entry)
            .ok_or(TPM_RC_FAILURE)?
        {
            OwnedUserNvramEntry::Persistent { object, .. } => object,
            OwnedUserNvramEntry::NvIndex { .. } => return Err(TPM_RC_FAILURE),
        }
    };
    match &object.body {
        OwnedAnyObjectBody::Object(body) => Ok(Some(body.clone())),
        _ => Err(TPM_RC_KEY + RC_SIGN_HANDLE),
    }
}

pub(super) fn load_signing_state(runtime: &mut Tpm2Runtime) -> Result<SigningState, TpmResult> {
    let rand = take_live_rand(runtime)?;
    let reset = runtime.live.state_reset.as_ref().ok_or(TPM_RC_FAILURE)?;
    Ok(SigningState {
        rand,
        commit_counter: reset.commit_counter,
        commit_nonce: reset.commit_nonce.clone(),
        commit_array: reset.commit_array,
    })
}

fn publish_commit_array(
    runtime: &mut Tpm2Runtime,
    commit_array: [u8; COMMIT_ARRAY_SIZE],
) -> Result<(), TpmResult> {
    runtime
        .live
        .state_reset
        .as_mut()
        .ok_or(TPM_RC_FAILURE)?
        .commit_array = commit_array;
    Ok(())
}

pub(super) fn publish_signing_outcome(
    runtime: &mut Tpm2Runtime,
    signing: SigningState,
    signature: Result<Signature, TpmResult>,
) -> Result<Signature, TpmResult> {
    let SigningState {
        rand, commit_array, ..
    } = signing;
    finish_live_rand(runtime, rand)?;
    publish_commit_array(runtime, commit_array)?;
    signature
}
