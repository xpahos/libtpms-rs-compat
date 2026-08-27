use crate::ffi::types::TpmResult;
use crate::library::constants::TPM_RC_FAILURE;

use super::algorithm::TPM_ALG_NULL;
use super::hierarchy::{
    TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT, TPM_RH_NULL, TPM_RH_OWNER, TPM_RH_PLATFORM,
    TPM_RH_PLATFORM_NV, is_hierarchy_auth_handle,
};
use super::nv::{
    TPMA_NV_PLATFORMCREATE, index_auth_value, is_nv_index_handle, nv_index_name, resolve_index,
};
use super::object_create::{
    is_object_handle, object_auth_value, object_hierarchy, resolve_any_object,
};
use super::pcr::pcr_auth_value_group;
use super::persistent::OwnedAnyObjectBody;
use super::runtime::Tpm2Runtime;

pub(super) fn strip_trailing_zeros(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .rposition(|&byte| byte != 0)
        .map_or(0, |position| position + 1);
    &bytes[..end]
}

pub(super) fn normalize_hierarchy_handle(handle: u32) -> u32 {
    if handle == TPM_RH_PLATFORM_NV {
        TPM_RH_PLATFORM
    } else {
        handle
    }
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

pub(super) fn entity_auth_value(runtime: &Tpm2Runtime, handle: u32) -> Result<&[u8], TpmResult> {
    let handle = normalize_hierarchy_handle(handle);
    if handle == TPM_RH_NULL {
        return Ok(&[]);
    }
    if is_hierarchy_auth_handle(handle) {
        return hierarchy_auth_value(runtime, handle);
    }
    if is_nv_index_handle(handle) {
        return index_auth_value(runtime, handle).ok_or(TPM_RC_FAILURE);
    }
    if is_object_handle(handle) {
        return object_auth_value(runtime, handle).ok_or(TPM_RC_FAILURE);
    }
    match pcr_auth_value_group(handle as usize) {
        Some(group) => auth_value_group(runtime, group),
        None => Ok(&[]),
    }
}

pub(super) fn entity_name(runtime: &Tpm2Runtime, handle: u32) -> Result<Vec<u8>, TpmResult> {
    if is_object_handle(handle) {
        let object = resolve_any_object(runtime, handle).ok_or(TPM_RC_FAILURE)?;
        return Ok(match &object.body {
            OwnedAnyObjectBody::Object(body) if body.public.name_alg != TPM_ALG_NULL => {
                body.name.clone()
            }
            _ => Vec::new(),
        });
    }
    if is_nv_index_handle(handle) {
        let resolved = resolve_index(runtime, handle).ok_or(TPM_RC_FAILURE)?;
        return nv_index_name(&resolved.public);
    }
    Ok(handle.to_be_bytes().to_vec())
}

pub(super) fn entity_hierarchy(runtime: &Tpm2Runtime, handle: u32) -> Result<u32, TpmResult> {
    if is_object_handle(handle) {
        let object = resolve_any_object(runtime, handle).ok_or(TPM_RC_FAILURE)?;
        return Ok(match &object.body {
            OwnedAnyObjectBody::Object(body) => object_hierarchy(object.attributes, body),
            _ => TPM_RH_NULL,
        });
    }
    if is_nv_index_handle(handle) {
        let resolved = resolve_index(runtime, handle).ok_or(TPM_RC_FAILURE)?;
        return Ok(if resolved.attributes() & TPMA_NV_PLATFORMCREATE != 0 {
            TPM_RH_PLATFORM
        } else {
            TPM_RH_OWNER
        });
    }
    Ok(match handle {
        TPM_RH_PLATFORM | TPM_RH_ENDORSEMENT | TPM_RH_NULL => handle,
        _ => TPM_RH_OWNER,
    })
}

pub(super) fn entity_auth_policy(
    runtime: &Tpm2Runtime,
    handle: u32,
) -> Result<(u16, Vec<u8>), TpmResult> {
    if is_object_handle(handle) {
        let object = resolve_any_object(runtime, handle).ok_or(TPM_RC_FAILURE)?;
        return match &object.body {
            OwnedAnyObjectBody::Object(body) => {
                Ok((body.public.name_alg, body.public.auth_policy.clone()))
            }
            _ => Ok((TPM_ALG_NULL, Vec::new())),
        };
    }
    if is_nv_index_handle(handle) {
        let resolved = resolve_index(runtime, handle).ok_or(TPM_RC_FAILURE)?;
        return Ok((
            resolved.public.name_alg,
            resolved.public.auth_policy.clone(),
        ));
    }
    let handle = normalize_hierarchy_handle(handle);
    if handle == TPM_RH_PLATFORM {
        let clear = runtime.live.state_clear.as_ref().ok_or(TPM_RC_FAILURE)?;
        return Ok((clear.platform_alg, clear.platform_policy.clone()));
    }
    let persistent = &runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?.persistent;
    Ok(match handle {
        TPM_RH_OWNER => (persistent.owner_alg, persistent.owner_policy.clone()),
        TPM_RH_ENDORSEMENT => (
            persistent.endorsement_alg,
            persistent.endorsement_policy.clone(),
        ),
        TPM_RH_LOCKOUT => (persistent.lockout_alg, persistent.lockout_policy.clone()),
        _ => (TPM_ALG_NULL, Vec::new()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::runtime::empty_state_runtime;
    use crate::library::tpm2::volatile::IMPLEMENTATION_PCR;

    #[test]
    fn trailing_zeros_are_stripped_like_upstream() {
        assert_eq!(strip_trailing_zeros(&[]), &[] as &[u8]);
        assert_eq!(strip_trailing_zeros(&[0, 0, 0]), &[] as &[u8]);
        assert_eq!(strip_trailing_zeros(&[1, 2, 0, 0]), &[1, 2]);
        assert_eq!(strip_trailing_zeros(&[0, 1]), &[0, 1]);
    }

    #[test]
    fn permanent_handles_name_themselves() {
        let runtime = empty_state_runtime();
        for handle in [TPM_RH_OWNER, TPM_RH_PLATFORM, TPM_RH_NULL, TPM_RH_LOCKOUT] {
            assert_eq!(
                entity_name(&runtime, handle).unwrap(),
                handle.to_be_bytes().to_vec(),
                "handle {handle:#x}"
            );
        }
    }

    #[test]
    fn pcr_handles_name_themselves() {
        let runtime = empty_state_runtime();
        for pcr in 0..IMPLEMENTATION_PCR as u32 {
            assert_eq!(entity_name(&runtime, pcr).unwrap(), pcr.to_be_bytes());
        }
    }

    #[test]
    fn the_platform_nv_handle_normalizes_to_the_platform_hierarchy() {
        assert_eq!(
            normalize_hierarchy_handle(TPM_RH_PLATFORM_NV),
            TPM_RH_PLATFORM
        );
        for handle in [TPM_RH_OWNER, TPM_RH_PLATFORM, TPM_RH_NULL, 0x8000_0000] {
            assert_eq!(normalize_hierarchy_handle(handle), handle);
        }
    }

    #[test]
    fn every_pcr_handle_and_the_null_handle_have_an_empty_auth_value() {
        let runtime = empty_state_runtime();
        for pcr in 0..IMPLEMENTATION_PCR as u32 {
            assert_eq!(entity_auth_value(&runtime, pcr), Ok(&[][..]), "PCR {pcr}");
        }
        assert_eq!(entity_auth_value(&runtime, TPM_RH_NULL), Ok(&[][..]));
    }

    #[test]
    fn a_missing_state_clear_is_an_undecorated_internal_failure() {
        let runtime = empty_state_runtime();
        assert!(runtime.live.state_clear.is_none());
        assert_eq!(auth_value_group(&runtime, 0), Err(TPM_RC_FAILURE));
        assert_eq!(
            entity_auth_value(&runtime, TPM_RH_PLATFORM),
            Err(TPM_RC_FAILURE)
        );
    }
}
