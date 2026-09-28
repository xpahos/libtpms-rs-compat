// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/Hierarchy.c
// - libtpms/src/tpm2/HierarchyCommands.c
//
// Original upstream authors and copyright notices:
// Written by Ken Goldman
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corp. and others, 2016 - 2023
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

pub(super) mod change_auth;
pub(super) mod change_eps;
pub(super) mod change_pps;
pub(super) mod clear;
pub(super) mod clear_control;
pub(super) mod control;
pub(super) mod lock_reset;
pub(super) mod pcr_policy;
pub(super) mod primary_policy;

use crate::library::constants::TPM_RC_FAILURE;
use crate::library::tpm2::hierarchy::{TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM};
use crate::library::tpm2::nv::stored_object_attributes;
use crate::library::tpm2::object::{
    ATTR_EPS_HIERARCHY, ATTR_OCCUPIED, ATTR_PPS_HIERARCHY, ATTR_SPS_HIERARCHY,
};
use crate::library::tpm2::persistent::{
    OwnedAnyObject, OwnedAnyObjectBody, OwnedPersistentState, OwnedSecret, OwnedUserNvramEntry,
    user_nvram_required_capacity,
};
use crate::library::tpm2::profile::PersistentObjectFormat;
use crate::library::tpm2::random::regenerate_secret;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::types::TpmResult;
pub(in crate::library::tpm2::command) const PRIMARY_SEED_SIZE: usize = 64;
pub(in crate::library::tpm2::command) const PROOF_SIZE: usize = 64;

pub(in crate::library::tpm2::command) fn regenerate_hierarchy_secrets(
    runtime: &mut Tpm2Runtime,
    sizes: &[usize],
) -> Result<Vec<Option<OwnedSecret>>, TpmResult> {
    let drbg = runtime.live.orderly.drbg_state.clone();
    let mut secrets = Vec::with_capacity(sizes.len());
    for &size in sizes {
        match regenerate_secret(runtime, size) {
            Ok(secret) => secrets.push(secret.map(OwnedSecret::from_vec)),
            Err(code) => {
                if runtime.failure_mode {
                    runtime.live.orderly.drbg_state = drbg;
                }
                return Err(code);
            }
        }
    }
    Ok(secrets)
}

pub(in crate::library::tpm2::command) fn hierarchy_object_attribute(hierarchy: u32) -> Option<u32> {
    match hierarchy {
        TPM_RH_PLATFORM => Some(ATTR_PPS_HIERARCHY),
        TPM_RH_OWNER => Some(ATTR_SPS_HIERARCHY),
        TPM_RH_ENDORSEMENT => Some(ATTR_EPS_HIERARCHY),
        _ => None,
    }
}

pub(in crate::library::tpm2::command) fn flush_loaded_hierarchy_objects(
    objects: &mut [OwnedAnyObject],
    attribute: u32,
) {
    let flushed = ATTR_OCCUPIED | attribute;
    for object in objects {
        if object.attributes & flushed == flushed {
            object.attributes &= !ATTR_OCCUPIED;
            object.body = OwnedAnyObjectBody::Unoccupied;
        }
    }
}

fn belongs_to_hierarchy(
    entry: &OwnedUserNvramEntry,
    attribute: u32,
    object_format: PersistentObjectFormat,
) -> bool {
    match entry {
        OwnedUserNvramEntry::NvIndex { .. } => false,
        OwnedUserNvramEntry::Persistent { object, .. } => {
            stored_object_attributes(object, object_format) & attribute != 0
        }
    }
}

pub(in crate::library::tpm2::command) fn remove_hierarchy_persistent_objects(
    state: &mut OwnedPersistentState,
    attribute: u32,
) -> Result<(), TpmResult> {
    let object_format = state.profile.object_format();
    let kept_capacity = user_nvram_required_capacity(
        state
            .user_nvram
            .entries
            .iter()
            .filter(|entry| !belongs_to_hierarchy(entry, attribute, object_format)),
    )
    .ok_or(TPM_RC_FAILURE)?;

    state
        .user_nvram
        .entries
        .retain(|entry| !belongs_to_hierarchy(entry, attribute, object_format));
    state.user_nvram.required_capacity = kept_capacity;
    Ok(())
}

pub(in crate::library::tpm2::command) fn digest_size_of(hash_alg: u16) -> usize {
    crate::library::tpm2::crypto::COMPILED_HASHES
        .iter()
        .find(|&&(alg, _)| alg == hash_alg)
        .map_or(0, |&(_, size)| size)
}

pub(in crate::library::tpm2::command) fn recompute_user_nvram_capacity(
    state: &mut OwnedPersistentState,
) -> Result<(), TpmResult> {
    state.user_nvram.required_capacity =
        user_nvram_required_capacity(&state.user_nvram.entries).ok_or(TPM_RC_FAILURE)?;
    Ok(())
}

pub(in crate::library::tpm2::command) use crate::library::tpm2::command::core::transaction::{
    commit_persistent_state, with_persistent_rollback, with_rollback,
};

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod tests {
    use super::test_support::{
        NV_OWNER_ATTRIBUTES, NV_PLATFORM_ATTRIBUTES, OWNER_INDEX, OWNER_PERSISTENT, PLATFORM_INDEX,
        PLATFORM_PERSISTENT, RC_AUTH_FAIL, RC_AUTH_MISSING, RC_AUTH_TYPE, RC_DISABLED,
        RC_HIERARCHY_H1, RC_INSUFFICIENT_H1, RC_LOCKOUT, RC_SESSION1_BAD_AUTH, RC_SIZE, RC_SUCCESS,
        RC_VALUE_H1, TPM_ALG_NULL, TRANSIENT_FIRST, change_pps, clear, clear_control,
        create_primary, da_lock_reset, evict_control, exec, flush, hierarchy_control, nv_define,
        oracle_runtime, pcr_set_auth_policy, replay_clock, set_primary_policy,
    };
    use super::*;
    use crate::library::tpm2::command::core::test_support::{
        assert_scenario_response, dispatch_bytes, manufactured_runtime, response_code,
        started_runtime,
    };
    use crate::library::tpm2::golden_responses::hierarchy_management::vector;
    use crate::library::tpm2::hierarchy::{TPM_RH_LOCKOUT, TPM_RH_NULL, TPM_RH_PLATFORM_NV};
    use crate::library::tpm2::persistent::OwnedUserNvramEntry;
    use crate::library::tpm2::profile::PersistentObjectFormat;

    fn capability_handles(response: &[u8]) -> Vec<u32> {
        let count = u32::from_be_bytes(response[15..19].try_into().expect("a handle count"));
        (0..count as usize)
            .map(|index| {
                let at = 19 + index * 4;
                u32::from_be_bytes(response[at..at + 4].try_into().expect("a handle"))
            })
            .collect()
    }

    fn persistent_handles(runtime: &Tpm2Runtime) -> Vec<u32> {
        runtime
            .state()
            .user_nvram
            .entries
            .iter()
            .filter_map(|entry| match entry {
                OwnedUserNvramEntry::Persistent { handle, .. } => Some(*handle),
                OwnedUserNvramEntry::NvIndex { .. } => None,
            })
            .collect()
    }

    fn nv_index_handles(runtime: &Tpm2Runtime) -> Vec<u32> {
        runtime
            .state()
            .user_nvram
            .entries
            .iter()
            .filter_map(|entry| match entry {
                OwnedUserNvramEntry::NvIndex { handle, .. } => Some(*handle),
                OwnedUserNvramEntry::Persistent { .. } => None,
            })
            .collect()
    }

    #[track_caller]
    fn provisioned_legacy() -> Tpm2Runtime {
        let mut runtime = started_runtime();
        for bytes in [
            create_primary(TPM_RH_OWNER),
            evict_control(TPM_RH_OWNER, TRANSIENT_FIRST, OWNER_PERSISTENT),
            flush(TRANSIENT_FIRST),
            create_primary(TPM_RH_ENDORSEMENT),
            evict_control(TPM_RH_OWNER, TRANSIENT_FIRST, 0x8100_0002),
            flush(TRANSIENT_FIRST),
            create_primary(TPM_RH_PLATFORM),
            evict_control(TPM_RH_PLATFORM, TRANSIENT_FIRST, PLATFORM_PERSISTENT),
            flush(TRANSIENT_FIRST),
            nv_define(TPM_RH_OWNER, OWNER_INDEX, NV_OWNER_ATTRIBUTES, 8),
            nv_define(TPM_RH_PLATFORM, PLATFORM_INDEX, NV_PLATFORM_ATTRIBUTES, 8),
        ] {
            let response = dispatch_bytes(&mut runtime, &bytes);
            assert_eq!(response_code(&response), RC_SUCCESS, "{bytes:02x?}");
        }
        runtime
    }

    #[test]
    fn per_hierarchy_object_attribute_selection() {
        assert_eq!(
            hierarchy_object_attribute(TPM_RH_PLATFORM),
            Some(ATTR_PPS_HIERARCHY)
        );
        assert_eq!(
            hierarchy_object_attribute(TPM_RH_OWNER),
            Some(ATTR_SPS_HIERARCHY)
        );
        assert_eq!(
            hierarchy_object_attribute(TPM_RH_ENDORSEMENT),
            Some(ATTR_EPS_HIERARCHY)
        );
        for handle in [
            TPM_RH_NULL,
            TPM_RH_LOCKOUT,
            TPM_RH_PLATFORM_NV,
            0,
            0x8000_0000,
            u32::MAX,
        ] {
            assert_eq!(hierarchy_object_attribute(handle), None, "{handle:#x}");
        }
    }

    #[test]
    fn seed_proof_size_vendored_buffer_match() {
        assert_eq!(PRIMARY_SEED_SIZE, 64);
        assert_eq!(PROOF_SIZE, 64);
    }

    #[test]
    fn digest_size_helper_null_algorithm_zero() {
        assert_eq!(digest_size_of(0x0010), 0);
        assert_eq!(digest_size_of(0x0004), 20);
        assert_eq!(digest_size_of(0x000b), 32);
        assert_eq!(digest_size_of(0x000c), 48);
        assert_eq!(digest_size_of(0x000d), 64);
        assert_eq!(digest_size_of(0x0044), 0);
    }

    #[test]
    fn stored_attribute_word_evict_object_image_match() {
        let mut object = OwnedAnyObject {
            attributes: ATTR_OCCUPIED | ATTR_SPS_HIERARCHY,
            body: OwnedAnyObjectBody::Unoccupied,
        };
        assert_eq!(
            stored_object_attributes(&object, PersistentObjectFormat::LegacyRsa3072),
            object.attributes,
            "the legacy image starts with the attribute word"
        );
        let marshalled = stored_object_attributes(
            &object,
            PersistentObjectFormat::AnyObject { object_version: 3 },
        );
        assert_eq!(
            marshalled & (ATTR_EPS_HIERARCHY | ATTR_PPS_HIERARCHY | ATTR_SPS_HIERARCHY),
            0,
            "the ANY_OBJECT header never sets a hierarchy bit"
        );
        object.attributes = ATTR_OCCUPIED | ATTR_PPS_HIERARCHY;
        assert_eq!(
            stored_object_attributes(
                &object,
                PersistentObjectFormat::AnyObject { object_version: 4 }
            ),
            marshalled,
            "the header is the same for every stored evict object"
        );
    }

    #[test]
    fn pre_startup_lifecycle_reference_match() {
        let mut runtime = manufactured_runtime();
        for (command, label, bytes) in [
            (
                "TPM2_HierarchyControl",
                "LIFECYCLE_HIERARCHY_CONTROL",
                hierarchy_control(TPM_RH_PLATFORM, TPM_RH_OWNER, 0, &[]),
            ),
            (
                "TPM2_ChangePPS",
                "LIFECYCLE_CHANGE_PPS",
                change_pps(TPM_RH_PLATFORM, &[]),
            ),
            ("TPM2_Clear", "LIFECYCLE_CLEAR", clear(TPM_RH_PLATFORM, &[])),
            (
                "TPM2_ClearControl",
                "LIFECYCLE_CLEAR_CONTROL",
                clear_control(TPM_RH_PLATFORM, 1, &[]),
            ),
            (
                "TPM2_PCR_SetAuthPolicy",
                "LIFECYCLE_PCR_SET_AUTH_POLICY",
                pcr_set_auth_policy(TPM_RH_PLATFORM, &[], TPM_ALG_NULL, 20, &[]),
            ),
            (
                "TPM2_SetPrimaryPolicy",
                "LIFECYCLE_SET_PRIMARY_POLICY",
                set_primary_policy(TPM_RH_OWNER, &[], TPM_ALG_NULL, &[]),
            ),
            (
                "TPM2_DictionaryAttackLockReset",
                "LIFECYCLE_DA_LOCK_RESET",
                da_lock_reset(TPM_RH_LOCKOUT, &[]),
            ),
        ] {
            assert_scenario_response(
                &format!("{command} before TPM2_Startup: hierarchy-management {label}"),
                vector(label),
                || dispatch_bytes(&mut runtime, &bytes),
            );
        }
    }

    #[test]
    fn reference_error_code_upstream_values() {
        for (label, code) in [
            ("HC_BAD_AUTH_NULL", RC_VALUE_H1),
            ("HC_TRUNCATED_HANDLE_0", RC_INSUFFICIENT_H1),
            ("HC_OWNER_BY_ENDORSEMENT", RC_AUTH_TYPE),
            ("HC_NO_SESSIONS", RC_AUTH_MISSING),
            ("HC_TRAILING", RC_SIZE),
            ("HC_WRONG_PASSWORD", RC_SESSION1_BAD_AUTH),
            ("SH_CREATE_PRIMARY_DISABLED", RC_HIERARCHY_H1),
            ("CTL_CLEAR_WHILE_DISABLED", RC_DISABLED),
            ("CTL_ENABLE_BY_LOCKOUT", RC_AUTH_FAIL),
            ("DALR_WHILE_LOCKOUT_AUTH_DISABLED", RC_LOCKOUT),
            ("SH_DISABLE_OWNER", RC_SUCCESS),
        ] {
            assert_eq!(response_code(vector(label)), code, "{label}");
        }
    }

    #[test]
    fn legacy_object_format_per_hierarchy_persistent_flush() {
        let mut runtime = provisioned_legacy();
        assert_eq!(
            runtime.state().profile.object_format(),
            PersistentObjectFormat::LegacyRsa3072
        );
        assert_eq!(
            persistent_handles(&runtime),
            capability_handles(vector("LEGACY_CAP_PERSISTENT_BEFORE"))
        );
        assert_eq!(
            nv_index_handles(&runtime),
            capability_handles(vector("LEGACY_CAP_NV_BEFORE"))
        );

        let mut cleared = provisioned_legacy();
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &change_pps(TPM_RH_PLATFORM, &[])
            )),
            RC_SUCCESS
        );
        assert_eq!(
            persistent_handles(&runtime),
            capability_handles(vector("LEGACY_CAP_PERSISTENT_AFTER_CHANGE_PPS")),
            "TPM2_ChangePPS deletes the platform evict object"
        );
        assert_eq!(
            nv_index_handles(&runtime),
            capability_handles(vector("LEGACY_CAP_NV_AFTER_CHANGE_PPS")),
            "TPM2_ChangePPS keeps every NV index"
        );

        assert_eq!(
            response_code(&dispatch_bytes(&mut cleared, &clear(TPM_RH_PLATFORM, &[]))),
            RC_SUCCESS
        );
        assert_eq!(
            persistent_handles(&cleared),
            capability_handles(vector("LEGACY_CAP_PERSISTENT_AFTER_CLEAR")),
            "TPM2_Clear deletes the owner and endorsement evict objects"
        );
        assert_eq!(
            nv_index_handles(&cleared),
            capability_handles(vector("LEGACY_CAP_NV_AFTER_CLEAR")),
            "TPM2_Clear deletes the owner-created NV index"
        );
    }

    #[test]
    fn marshalled_object_format_no_persistent_flush() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        assert!(matches!(
            runtime.state().profile.object_format(),
            PersistentObjectFormat::AnyObject { .. }
        ));
        for bytes in [
            create_primary(TPM_RH_OWNER),
            evict_control(TPM_RH_OWNER, TRANSIENT_FIRST, OWNER_PERSISTENT),
            flush(TRANSIENT_FIRST),
            create_primary(TPM_RH_PLATFORM),
            evict_control(TPM_RH_PLATFORM, TRANSIENT_FIRST, PLATFORM_PERSISTENT),
            flush(TRANSIENT_FIRST),
        ] {
            assert_eq!(
                response_code(&exec(&mut runtime, &clock, &bytes)),
                RC_SUCCESS
            );
        }
        let before = persistent_handles(&runtime);
        assert_eq!(before, [OWNER_PERSISTENT, PLATFORM_PERSISTENT]);

        assert_eq!(
            response_code(&exec(
                &mut runtime,
                &clock,
                &change_pps(TPM_RH_PLATFORM, &[])
            )),
            RC_SUCCESS
        );
        assert_eq!(persistent_handles(&runtime), before);
        assert_eq!(
            response_code(&exec(&mut runtime, &clock, &clear(TPM_RH_PLATFORM, &[]))),
            RC_SUCCESS
        );
        assert_eq!(persistent_handles(&runtime), before);
    }
}
