use crate::ffi_types::TpmResult;
use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_NV_UNAVAILABLE};

use super::nv::build_nv_image;
use super::runtime::Tpm2Runtime;

pub(super) const SU_NONE_VALUE: u16 = 0xffff;
pub(super) const SU_DA_USED_VALUE: u16 = 0xfffe;

pub(super) fn is_orderly(orderly_state: u16) -> bool {
    orderly_state < SU_DA_USED_VALUE
}

pub(super) fn prepare_clear_orderly(runtime: &Tpm2Runtime) -> Result<Option<u16>, TpmResult> {
    let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
    if !is_orderly(state.persistent.orderly_state) {
        return Ok(None);
    }
    if !runtime.nv_available {
        return Err(TPM_RC_NV_UNAVAILABLE);
    }
    Ok(Some(if runtime.live.da_used {
        SU_DA_USED_VALUE
    } else {
        SU_NONE_VALUE
    }))
}

pub(super) fn commit_clear_orderly(
    runtime: &mut Tpm2Runtime,
    orderly_state: Option<u16>,
) -> Result<(), TpmResult> {
    let Some(orderly_state) = orderly_state else {
        return Ok(());
    };
    let state = runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?;
    let backup_orderly_state = state.persistent.orderly_state;
    state.persistent.orderly_state = orderly_state;
    match build_nv_image(state) {
        Ok(image) => runtime.nv_memory = image,
        Err(_) => {
            state.persistent.orderly_state = backup_orderly_state;
            return Err(TPM_RC_FAILURE);
        }
    }
    runtime.nv_update_pending = true;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::runtime::empty_state_runtime;

    #[test]
    fn the_marker_values_match_upstream() {
        assert_eq!(SU_NONE_VALUE, 0xffff);
        assert_eq!(SU_DA_USED_VALUE, 0xfffe);
    }

    #[test]
    fn values_below_the_da_used_marker_are_orderly() {
        for orderly_state in [0x0000u16, 0x0001, 0x8001, 0x4001, SU_DA_USED_VALUE - 1] {
            assert!(is_orderly(orderly_state), "state {orderly_state:#06x}");
        }
    }

    #[test]
    fn the_da_used_marker_is_not_orderly() {
        assert!(!is_orderly(SU_DA_USED_VALUE));
    }

    #[test]
    fn the_none_marker_is_not_orderly() {
        assert!(!is_orderly(SU_NONE_VALUE));
    }

    #[test]
    fn the_boundary_is_exact() {
        assert!(is_orderly(SU_DA_USED_VALUE - 1));
        assert!(!is_orderly(SU_DA_USED_VALUE));
        assert!(!is_orderly(SU_NONE_VALUE));
    }

    #[test]
    fn a_runtime_without_state_never_panics() {
        let mut runtime = empty_state_runtime();
        assert_eq!(prepare_clear_orderly(&runtime), Err(TPM_RC_FAILURE));
        assert_eq!(
            commit_clear_orderly(&mut runtime, Some(SU_NONE_VALUE)),
            Err(TPM_RC_FAILURE)
        );
        assert_eq!(commit_clear_orderly(&mut runtime, None), Ok(()));
    }
}
