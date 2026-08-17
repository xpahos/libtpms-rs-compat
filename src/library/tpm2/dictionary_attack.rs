use crate::ffi_types::TpmResult;
use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_LOCKOUT, TPM_RC_NV_UNAVAILABLE};

use super::hierarchy::TPM_RH_LOCKOUT;
use super::nv::{TPMA_NV_NO_DA, build_nv_image, is_nv_index_handle, resolve_index};
use super::orderly::{SU_DA_USED_VALUE, is_orderly};
use super::runtime::Tpm2Runtime;

// TODO: transient objects carry their own noDA attribute; extend this once
// object handles become dispatchable authorization targets.
pub(super) fn is_da_protected_handle(runtime: &Tpm2Runtime, handle: u32) -> bool {
    if is_nv_index_handle(handle) {
        return resolve_index(runtime, handle)
            .is_some_and(|resolved| resolved.attributes() & TPMA_NV_NO_DA == 0);
    }
    handle == TPM_RH_LOCKOUT
}

pub(super) fn check_locked_out(runtime: &mut Tpm2Runtime, handle: u32) -> Result<(), TpmResult> {
    let persistent = &runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?.persistent;
    let orderly = is_orderly(persistent.orderly_state);
    let lockout_auth_enabled = persistent.lockout_auth_enabled;
    let locked_out = persistent.failed_tries >= persistent.max_tries;

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
    if handle == TPM_RH_LOCKOUT {
        if !lockout_auth_enabled {
            return Err(TPM_RC_LOCKOUT);
        }
        return Ok(());
    }
    if locked_out {
        return Err(TPM_RC_LOCKOUT);
    }
    if !runtime.live.da_used {
        if !runtime.nv_available {
            return Err(TPM_RC_NV_UNAVAILABLE);
        }
        record_da_used(runtime)?;
    }
    Ok(())
}

fn record_da_used(runtime: &mut Tpm2Runtime) -> Result<(), TpmResult> {
    let state = runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?;
    let backup = state.persistent.orderly_state;
    state.persistent.orderly_state = SU_DA_USED_VALUE;
    if commit_dictionary_attack_state(runtime).is_err() {
        if let Some(state) = runtime.state.as_mut() {
            state.persistent.orderly_state = backup;
        }
        return Err(TPM_RC_FAILURE);
    }
    runtime.live.da_used = true;
    Ok(())
}

// TODO: upstream DARegisterFailure() also rewinds the lockout self-heal timer
// to g_time; this port has no TPM time model yet.
pub(super) fn register_lockout_failure(
    runtime: &mut Tpm2Runtime,
    handle: u32,
) -> Result<(), TpmResult> {
    let nv_available = runtime.nv_available;
    let state = runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?;

    let (pending, backup) = if handle == TPM_RH_LOCKOUT {
        let backup = state.persistent.lockout_auth_enabled;
        state.persistent.lockout_auth_enabled = false;
        (
            state.persistent.lockout_recovery != 0,
            Restore::Lockout(backup),
        )
    } else {
        if state.persistent.recovery_time == 0 {
            return Ok(());
        }
        let backup = state.persistent.failed_tries;
        state.persistent.failed_tries = backup.saturating_add(1);
        (true, Restore::FailedTries(backup))
    };

    if !pending {
        return Ok(());
    }
    if !nv_available {
        runtime.live.da_pending_on_nv = true;
        return Ok(());
    }
    if commit_dictionary_attack_state(runtime).is_err() {
        if let Some(state) = runtime.state.as_mut() {
            match backup {
                Restore::Lockout(value) => state.persistent.lockout_auth_enabled = value,
                Restore::FailedTries(value) => state.persistent.failed_tries = value,
            }
        }
        return Err(TPM_RC_FAILURE);
    }
    Ok(())
}

enum Restore {
    Lockout(bool),
    FailedTries(u32),
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
        let runtime = empty_state_runtime();
        assert!(is_da_protected_handle(&runtime, TPM_RH_LOCKOUT));
        for handle in [
            TPM_RH_OWNER,
            TPM_RH_ENDORSEMENT,
            TPM_RH_PLATFORM,
            TPM_RH_NULL,
            0x0000_0000,
            0x0000_0017,
            0x0200_0000,
            0x8000_0000,
            u32::MAX,
        ] {
            assert!(
                !is_da_protected_handle(&runtime, handle),
                "handle {handle:#x}"
            );
        }
    }

    #[test]
    fn an_undefined_nv_index_is_dictionary_attack_exempt() {
        let runtime = empty_state_runtime();
        for handle in [0x0100_0000u32, 0x0100_0001, 0x01ff_ffff] {
            assert!(
                !is_da_protected_handle(&runtime, handle),
                "handle {handle:#010x} resolves to no index"
            );
        }
    }

    #[test]
    fn a_runtime_without_state_never_panics() {
        let mut runtime = empty_state_runtime();
        assert_eq!(
            check_locked_out(&mut runtime, TPM_RH_LOCKOUT),
            Err(TPM_RC_FAILURE)
        );
        assert_eq!(
            register_lockout_failure(&mut runtime, TPM_RH_LOCKOUT),
            Err(TPM_RC_FAILURE)
        );
        assert_eq!(
            commit_dictionary_attack_state(&mut runtime),
            Err(TPM_RC_FAILURE)
        );
    }
}
