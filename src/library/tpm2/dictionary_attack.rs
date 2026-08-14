use crate::ffi_types::TpmResult;
use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_LOCKOUT, TPM_RC_NV_UNAVAILABLE};

use super::hierarchy::TPM_RH_LOCKOUT;
use super::nv::build_nv_image;
use super::orderly::is_orderly;
use super::runtime::Tpm2Runtime;

// TODO: transient objects and NV indexes carry their own noDA / TPMA_NV_NO_DA
// attribute; extend this once those handle types become dispatchable.
pub(super) fn is_da_protected_handle(handle: u32) -> bool {
    handle == TPM_RH_LOCKOUT
}

pub(super) fn check_locked_out(runtime: &mut Tpm2Runtime) -> Result<(), TpmResult> {
    let persistent = &runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?.persistent;
    let orderly = is_orderly(persistent.orderly_state);
    let lockout_auth_enabled = persistent.lockout_auth_enabled;

    if !runtime.nv_available && orderly {
        return Err(TPM_RC_NV_UNAVAILABLE);
    }
    if runtime.live.da_pending_on_nv {
        if !runtime.nv_available {
            return Err(TPM_RC_NV_UNAVAILABLE);
        }
        commit_dictionary_attack_state(runtime)?;
        runtime.live.da_pending_on_nv = false;
    }
    if !lockout_auth_enabled {
        return Err(TPM_RC_LOCKOUT);
    }
    Ok(())
}

// TODO: upstream DARegisterFailure() also rewinds the lockout self-heal timer
// to g_time; this port has no TPM time model yet.
pub(super) fn register_lockout_failure(runtime: &mut Tpm2Runtime) -> Result<(), TpmResult> {
    let nv_available = runtime.nv_available;
    let state = runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?;
    let lockout_recovery = state.persistent.lockout_recovery;
    let backup = state.persistent.lockout_auth_enabled;
    state.persistent.lockout_auth_enabled = false;

    if lockout_recovery == 0 {
        return Ok(());
    }
    if !nv_available {
        runtime.live.da_pending_on_nv = true;
        return Ok(());
    }
    if commit_dictionary_attack_state(runtime).is_err() {
        if let Some(state) = runtime.state.as_mut() {
            state.persistent.lockout_auth_enabled = backup;
        }
        return Err(TPM_RC_FAILURE);
    }
    Ok(())
}

fn commit_dictionary_attack_state(runtime: &mut Tpm2Runtime) -> Result<(), TpmResult> {
    let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
    let image = build_nv_image(state).map_err(|_| TPM_RC_FAILURE)?;
    runtime.nv_memory = image;
    runtime.nv_update_pending = true;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::hierarchy::{
        TPM_RH_ENDORSEMENT, TPM_RH_NULL, TPM_RH_OWNER, TPM_RH_PLATFORM,
    };
    use crate::library::tpm2::runtime::empty_state_runtime;

    #[test]
    fn only_the_lockout_hierarchy_is_dictionary_attack_protected() {
        assert!(is_da_protected_handle(TPM_RH_LOCKOUT));
        for handle in [
            TPM_RH_OWNER,
            TPM_RH_ENDORSEMENT,
            TPM_RH_PLATFORM,
            TPM_RH_NULL,
            0x0000_0000,
            0x0000_0017,
            0x0100_0000,
            0x0200_0000,
            0x8000_0000,
            u32::MAX,
        ] {
            assert!(!is_da_protected_handle(handle), "handle {handle:#x}");
        }
    }

    #[test]
    fn a_runtime_without_state_never_panics() {
        let mut runtime = empty_state_runtime();
        assert_eq!(check_locked_out(&mut runtime), Err(TPM_RC_FAILURE));
        assert_eq!(register_lockout_failure(&mut runtime), Err(TPM_RC_FAILURE));
        assert_eq!(
            commit_dictionary_attack_state(&mut runtime),
            Err(TPM_RC_FAILURE)
        );
    }
}
