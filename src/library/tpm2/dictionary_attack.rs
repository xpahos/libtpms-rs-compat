use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_LOCKOUT, TPM_RC_NV_UNAVAILABLE};
use crate::types::TpmResult;

use super::hierarchy::TPM_RH_LOCKOUT;
use super::nv::{TPMA_NV_NO_DA, build_nv_image, is_nv_index_handle, resolve_index};
use super::object_create::{is_object_handle, object_public_attributes};
use super::orderly::{SU_DA_USED_VALUE, is_orderly};
use super::runtime::Tpm2Runtime;
use super::template::TPMA_OBJECT_NO_DA;

pub(super) fn is_da_protected_handle(runtime: &Tpm2Runtime, handle: u32) -> bool {
    if is_nv_index_handle(handle) {
        return resolve_index(runtime, handle)
            .is_some_and(|resolved| resolved.attributes() & TPMA_NV_NO_DA == 0);
    }
    if is_object_handle(handle) {
        return object_public_attributes(runtime, handle)
            .is_some_and(|attributes| attributes & TPMA_OBJECT_NO_DA == 0);
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

pub(super) fn record_da_used(runtime: &mut Tpm2Runtime) -> Result<(), TpmResult> {
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
    } else if state.persistent.recovery_time != 0 {
        let backup = state.persistent.failed_tries;
        state.persistent.failed_tries = backup.wrapping_add(1);
        (true, Restore::FailedTries(backup))
    } else {
        (false, Restore::FailedTries(state.persistent.failed_tries))
    };

    if pending {
        if !nv_available {
            runtime.live.da_pending_on_nv = true;
        } else if commit_dictionary_attack_state(runtime).is_err() {
            if let Some(state) = runtime.state.as_mut() {
                match backup {
                    Restore::Lockout(value) => state.persistent.lockout_auth_enabled = value,
                    Restore::FailedTries(value) => state.persistent.failed_tries = value,
                }
            }
            return Err(TPM_RC_FAILURE);
        }
    }
    if handle == TPM_RH_LOCKOUT {
        runtime.live.orderly.lockout_timer = runtime.timer.time_ms;
    } else {
        runtime.live.orderly.self_heal_timer = runtime.timer.time_ms;
    }
    Ok(())
}

enum Restore {
    Lockout(bool),
    FailedTries(u32),
}

pub(super) fn da_self_heal(runtime: &mut Tpm2Runtime) -> Result<(), TpmResult> {
    let time = runtime.timer.time_ms;
    let Some(state) = runtime.state.as_ref() else {
        return Ok(());
    };

    if state.persistent.failed_tries != 0 {
        if state.persistent.recovery_time == 0 {
            let state = runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?;
            let backup = state.persistent.failed_tries;
            state.persistent.failed_tries = 0;
            if commit_dictionary_attack_state(runtime).is_err() {
                if let Some(state) = runtime.state.as_mut() {
                    state.persistent.failed_tries = backup;
                }
                return Err(TPM_RC_FAILURE);
            }
        } else {
            let recovery_time = u64::from(state.persistent.recovery_time);
            let decrease_count = time
                .wrapping_sub(runtime.live.orderly.self_heal_timer)
                .wrapping_div(1000)
                / recovery_time;
            let decrease = decrease_count as u32;
            let state = runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?;
            let backup = state.persistent.failed_tries;
            if backup <= decrease {
                state.persistent.failed_tries = 0;
            } else {
                state.persistent.failed_tries = backup - decrease;
            }
            let timer_backup = runtime.live.orderly.self_heal_timer;
            runtime.live.orderly.self_heal_timer = timer_backup.wrapping_add(
                decrease_count
                    .wrapping_mul(recovery_time)
                    .wrapping_mul(1000),
            );
            if decrease_count != 0 && commit_dictionary_attack_state(runtime).is_err() {
                if let Some(state) = runtime.state.as_mut() {
                    state.persistent.failed_tries = backup;
                }
                runtime.live.orderly.self_heal_timer = timer_backup;
                return Err(TPM_RC_FAILURE);
            }
        }
    }

    let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
    if !state.persistent.lockout_auth_enabled
        && state.persistent.lockout_recovery != 0
        && time.wrapping_sub(runtime.live.orderly.lockout_timer) / 1000
            >= u64::from(state.persistent.lockout_recovery)
    {
        let state = runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?;
        state.persistent.lockout_auth_enabled = true;
        if commit_dictionary_attack_state(runtime).is_err() {
            if let Some(state) = runtime.state.as_mut() {
                state.persistent.lockout_auth_enabled = false;
            }
            return Err(TPM_RC_FAILURE);
        }
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
    use crate::library::tpm2::manufacture::manufacture_state;
    use crate::library::tpm2::orderly::SU_NONE_VALUE;
    use crate::library::tpm2::persistent::OwnedSecret;
    use crate::library::tpm2::profile::validate_user_profile;
    use crate::library::tpm2::runtime::{commit_manufactured_state, empty_state_runtime};

    const DA_INDEX: u32 = 0x0100_0000;

    const ENTROPY: crate::library::tpm2::crypto::EntropySource =
        crate::library::tpm2::test_support::counter_entropy::<0x11>;

    fn manufactured_runtime() -> Tpm2Runtime {
        let profile = validate_user_profile(None).expect("the null profile validates");
        let state = manufacture_state(profile, ENTROPY).expect("manufactures");
        commit_manufactured_state(state).expect("commits")
    }

    fn break_nv_serialization(runtime: &mut Tpm2Runtime) {
        runtime.state.as_mut().unwrap().persistent.owner_auth =
            OwnedSecret::from_vec(vec![0xaa; 4096]);
    }

    #[test]
    fn first_da_use_marker_record_success() {
        let mut runtime = manufactured_runtime();
        runtime.timer.time_ms = 1_234;
        assert!(!runtime.live.da_used);
        assert_eq!(check_locked_out(&mut runtime, DA_INDEX), Ok(()));
        assert!(runtime.live.da_used);
        assert_eq!(
            runtime.state().persistent.orderly_state,
            SU_DA_USED_VALUE,
            "the first use commits the DA-used orderly marker"
        );
        assert!(runtime.nv_update_pending);
        assert_eq!(
            runtime.state().persistent.failed_tries,
            0,
            "the retry is not a failed authorization"
        );
        assert_eq!(
            check_locked_out(&mut runtime, DA_INDEX),
            Ok(()),
            "the retried request follows normal authorization processing"
        );
    }

    fn install_symcipher_object(runtime: &mut Tpm2Runtime, slot: usize, no_da: bool) {
        use crate::library::tpm2::crypto::SeededRand;
        use crate::library::tpm2::object_create::{
            ObjectSecrets, PRIMARY_OBJECT_CREATION, create_object, store_created_object,
        };
        use crate::library::tpm2::persistent::{OwnedPublicId, OwnedTpmtPublic};
        use crate::library::tpm2::public::{
            PublicParms, SymDefObject, TPM_ALG_AES, TPM_ALG_CFB, TPM_ALG_SYMCIPHER,
        };
        use crate::library::tpm2::template::{
            TPMA_OBJECT_DECRYPT, TPMA_OBJECT_NO_DA, TPMA_OBJECT_SENSITIVE_DATA_ORIGIN,
            TPMA_OBJECT_SIGN, TPMA_OBJECT_USER_WITH_AUTH,
        };

        let mut public = OwnedTpmtPublic {
            object_type: TPM_ALG_SYMCIPHER,
            name_alg: 0x000b,
            object_attributes: TPMA_OBJECT_SENSITIVE_DATA_ORIGIN
                | TPMA_OBJECT_USER_WITH_AUTH
                | TPMA_OBJECT_DECRYPT
                | TPMA_OBJECT_SIGN
                | if no_da { TPMA_OBJECT_NO_DA } else { 0 },
            auth_policy: Vec::new(),
            parameters: PublicParms::SymCipher(SymDefObject {
                algorithm: TPM_ALG_AES,
                key_bits: Some(128),
                mode: Some(TPM_ALG_CFB),
            }),
            unique: OwnedPublicId::Sym(Vec::new()),
        };
        let mut rand = SeededRand::instantiate(
            &[0x5c; 64],
            PRIMARY_OBJECT_CREATION,
            &[slot as u8, u8::from(no_da)],
            &[],
            1,
            false,
        )
        .expect("a non-empty derivation input");
        let created = create_object(
            &mut public,
            vec![0u8; 32],
            &[],
            false,
            &ObjectSecrets {
                sh_proof: &[0x11; 64],
                eh_proof: &[0x22; 64],
            },
            &mut rand,
            crate::library::cancel::CancellationToken::disabled(),
        )
        .expect("the fixture object generates");
        store_created_object(runtime, slot, TPM_RH_OWNER, 1, created)
            .expect("the fixture object stores");
    }

    fn persist_object(runtime: &mut Tpm2Runtime, slot: usize, handle: u32) {
        use crate::library::tpm2::nv::persistent_object_image;
        use crate::library::tpm2::persistent::{
            OwnedAnyObjectBody, OwnedUserNvramEntry, user_nvram_required_capacity,
        };

        let mut object = runtime.live.objects[slot].clone();
        let OwnedAnyObjectBody::Object(body) = &mut object.body else {
            panic!("the fixture slot holds an object");
        };
        body.evict_handle = handle;
        let state = runtime.state.as_mut().expect("state present");
        let object_destination_size =
            persistent_object_image(&object, state.profile.object_format())
                .expect("the fixture object serializes")
                .len() as u64;
        let entry = OwnedUserNvramEntry::Persistent {
            declared_entry_size: 0,
            handle,
            object,
            object_destination_size,
        };
        state.user_nvram.required_capacity = user_nvram_required_capacity(
            state
                .user_nvram
                .entries
                .iter()
                .chain(core::iter::once(&entry)),
        )
        .expect("the fixture entries fit");
        state.user_nvram.entries.push(entry);
    }

    #[test]
    fn real_object_noda_attribute_da_classification() {
        use crate::library::tpm2::object_create::resolve_any_object;

        const PROTECTED_TRANSIENT: u32 = 0x8000_0000;
        const NODA_TRANSIENT: u32 = 0x8000_0001;
        const PROTECTED_PERSISTENT: u32 = 0x8100_0002;
        const NODA_PERSISTENT: u32 = 0x8100_0003;

        let mut runtime = manufactured_runtime();
        install_symcipher_object(&mut runtime, 0, false);
        install_symcipher_object(&mut runtime, 1, true);
        persist_object(&mut runtime, 0, PROTECTED_PERSISTENT);
        persist_object(&mut runtime, 1, NODA_PERSISTENT);

        for handle in [
            PROTECTED_TRANSIENT,
            NODA_TRANSIENT,
            PROTECTED_PERSISTENT,
            NODA_PERSISTENT,
        ] {
            assert!(
                resolve_any_object(&runtime, handle).is_some(),
                "the fixture installed an object at {handle:#010x}"
            );
        }

        assert!(is_da_protected_handle(&runtime, PROTECTED_TRANSIENT));
        assert!(is_da_protected_handle(&runtime, PROTECTED_PERSISTENT));
        assert!(
            !is_da_protected_handle(&runtime, NODA_TRANSIENT),
            "a loaded object with TPMA_OBJECT.noDA is exempt, so its \
             authorization never reaches the first-use transition"
        );
        assert!(!is_da_protected_handle(&runtime, NODA_PERSISTENT));

        assert!(
            !is_da_protected_handle(&runtime, 0x8000_0002),
            "an empty transient slot is not DA-protected"
        );
        assert!(
            !is_da_protected_handle(&runtime, 0x8100_0099),
            "an undefined persistent handle is not DA-protected"
        );
        assert!(!runtime.live.da_used, "classification records nothing");
        assert_ne!(runtime.state().persistent.orderly_state, SU_DA_USED_VALUE);

        assert_eq!(
            check_locked_out(&mut runtime, PROTECTED_PERSISTENT),
            Ok(()),
            "the first use of a real DA-protected persistent object proceeds"
        );
        assert!(runtime.live.da_used);
        assert_eq!(runtime.state().persistent.orderly_state, SU_DA_USED_VALUE);
        assert_eq!(
            check_locked_out(&mut runtime, PROTECTED_PERSISTENT),
            Ok(()),
            "the following authorization proceeds normally"
        );
        assert_eq!(
            check_locked_out(&mut runtime, PROTECTED_TRANSIENT),
            Ok(()),
            "the transition is per cycle, not per entity"
        );
    }

    #[test]
    fn lockout_authorization_no_first_use_transition() {
        let mut runtime = manufactured_runtime();
        let orderly_before = runtime.state().persistent.orderly_state;
        let nv_before = runtime.nv_memory.clone();
        assert!(!runtime.live.da_used);
        assert_eq!(
            check_locked_out(&mut runtime, TPM_RH_LOCKOUT),
            Ok(()),
            "a fresh cycle authorizes lockoutAuth without a retry"
        );
        assert!(
            !runtime.live.da_used,
            "lockout authorization records no DA-used marker"
        );
        assert_eq!(runtime.state().persistent.orderly_state, orderly_before);
        assert_eq!(runtime.nv_memory, nv_before);
        assert!(!runtime.nv_update_pending);

        runtime
            .state
            .as_mut()
            .unwrap()
            .persistent
            .lockout_auth_enabled = false;
        assert_eq!(
            check_locked_out(&mut runtime, TPM_RH_LOCKOUT),
            Err(TPM_RC_LOCKOUT),
            "lockoutAuthEnabled still gates the lockout hierarchy"
        );
        assert!(!runtime.live.da_used);
    }

    #[test]
    fn da_use_record_complete_transition_serialization() {
        let mut runtime = manufactured_runtime();
        let nv_before = runtime.nv_memory.clone();
        record_da_used(&mut runtime).expect("the transition commits");
        assert!(runtime.live.da_used);
        assert_eq!(runtime.state().persistent.orderly_state, SU_DA_USED_VALUE);
        assert!(runtime.nv_update_pending);
        assert_ne!(
            runtime.nv_memory, nv_before,
            "the rebuilt NV image carries the DA-used marker"
        );
    }

    #[test]
    fn first_da_use_nv_unavailable_rejection_no_marker() {
        let mut runtime = manufactured_runtime();
        runtime.state.as_mut().unwrap().persistent.orderly_state = SU_NONE_VALUE;
        runtime.nv_available = false;
        assert_eq!(
            check_locked_out(&mut runtime, DA_INDEX),
            Err(TPM_RC_NV_UNAVAILABLE)
        );
        assert!(!runtime.live.da_used);
        assert_eq!(runtime.state().persistent.orderly_state, SU_NONE_VALUE);
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn max_tries_da_lockout_and_lockout_hierarchy_exemption() {
        let mut runtime = manufactured_runtime();
        runtime.live.da_used = true;
        {
            let persistent = &mut runtime.state.as_mut().unwrap().persistent;
            persistent.failed_tries = persistent.max_tries;
        }
        assert_eq!(
            check_locked_out(&mut runtime, DA_INDEX),
            Err(TPM_RC_LOCKOUT)
        );
        assert_eq!(
            check_locked_out(&mut runtime, TPM_RH_LOCKOUT),
            Ok(()),
            "lockoutAuth is gated by lockoutAuthEnabled, not by failedTries"
        );
        runtime
            .state
            .as_mut()
            .unwrap()
            .persistent
            .lockout_auth_enabled = false;
        assert_eq!(
            check_locked_out(&mut runtime, TPM_RH_LOCKOUT),
            Err(TPM_RC_LOCKOUT)
        );
    }

    #[test]
    fn regular_failure_tries_increment_timer_rewind() {
        let mut runtime = manufactured_runtime();
        runtime.timer.time_ms = 5_000;
        runtime.live.orderly.self_heal_timer = 111;
        assert_eq!(register_lockout_failure(&mut runtime, DA_INDEX), Ok(()));
        assert_eq!(runtime.state().persistent.failed_tries, 1);
        assert_eq!(runtime.live.orderly.self_heal_timer, 5_000);
        assert!(runtime.nv_update_pending);
        assert!(!runtime.live.da_pending_on_nv);
    }

    #[test]
    fn regular_failure_zero_recovery_timer_rewind_only() {
        let mut runtime = manufactured_runtime();
        runtime.timer.time_ms = 5_000;
        runtime.state.as_mut().unwrap().persistent.recovery_time = 0;
        assert_eq!(register_lockout_failure(&mut runtime, DA_INDEX), Ok(()));
        assert_eq!(runtime.state().persistent.failed_tries, 0);
        assert_eq!(runtime.live.orderly.self_heal_timer, 5_000);
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn lockout_failure_auth_disable_timer_rewind() {
        let mut runtime = manufactured_runtime();
        runtime.timer.time_ms = 7_000;
        assert_eq!(
            register_lockout_failure(&mut runtime, TPM_RH_LOCKOUT),
            Ok(())
        );
        assert!(!runtime.state().persistent.lockout_auth_enabled);
        assert_eq!(runtime.live.orderly.lockout_timer, 7_000);
        assert!(runtime.nv_update_pending);
        assert_eq!(
            runtime.state().persistent.failed_tries,
            0,
            "lockout failures do not touch failedTries"
        );
    }

    #[test]
    fn lockout_failure_zero_recovery_nv_update_skip() {
        let mut runtime = manufactured_runtime();
        runtime.timer.time_ms = 7_000;
        runtime.state.as_mut().unwrap().persistent.lockout_recovery = 0;
        assert_eq!(
            register_lockout_failure(&mut runtime, TPM_RH_LOCKOUT),
            Ok(())
        );
        assert!(!runtime.state().persistent.lockout_auth_enabled);
        assert_eq!(runtime.live.orderly.lockout_timer, 7_000);
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn failed_tries_upstream_wrap_parity() {
        let mut runtime = manufactured_runtime();
        runtime.state.as_mut().unwrap().persistent.failed_tries = u32::MAX;
        assert_eq!(register_lockout_failure(&mut runtime, DA_INDEX), Ok(()));
        assert_eq!(runtime.state().persistent.failed_tries, 0);
    }

    #[test]
    fn nv_unavailable_failure_pending_update() {
        let mut runtime = manufactured_runtime();
        runtime.nv_available = false;
        assert_eq!(register_lockout_failure(&mut runtime, DA_INDEX), Ok(()));
        assert_eq!(runtime.state().persistent.failed_tries, 1);
        assert!(runtime.live.da_pending_on_nv);
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn pending_update_nv_available_commit() {
        let mut runtime = manufactured_runtime();
        runtime.live.da_used = true;
        runtime.live.da_pending_on_nv = true;
        assert_eq!(check_locked_out(&mut runtime, DA_INDEX), Ok(()));
        assert!(!runtime.live.da_pending_on_nv);
        assert!(runtime.nv_update_pending);
    }

    #[test]
    fn pending_update_authorization_block() {
        let mut runtime = manufactured_runtime();
        runtime.live.da_used = true;
        runtime.live.da_pending_on_nv = true;
        runtime.nv_available = false;
        assert_eq!(
            check_locked_out(&mut runtime, DA_INDEX),
            Err(TPM_RC_NV_UNAVAILABLE)
        );
        assert!(runtime.live.da_pending_on_nv);
    }

    #[test]
    fn persistence_failure_registration_rollback() {
        let mut runtime = manufactured_runtime();
        runtime.timer.time_ms = 5_000;
        runtime.live.orderly.self_heal_timer = 111;
        break_nv_serialization(&mut runtime);
        let nv_before = runtime.nv_memory.clone();
        assert_eq!(
            register_lockout_failure(&mut runtime, DA_INDEX),
            Err(TPM_RC_FAILURE)
        );
        assert_eq!(runtime.state().persistent.failed_tries, 0);
        assert_eq!(
            runtime.live.orderly.self_heal_timer, 111,
            "the timer rewind is rolled back with the counter"
        );
        assert!(!runtime.nv_update_pending);
        assert_eq!(runtime.nv_memory, nv_before);
    }

    #[test]
    fn self_heal_zero_recovery_immediate_clear() {
        let mut runtime = manufactured_runtime();
        {
            let persistent = &mut runtime.state.as_mut().unwrap().persistent;
            persistent.failed_tries = 3;
            persistent.recovery_time = 0;
        }
        assert_eq!(da_self_heal(&mut runtime), Ok(()));
        assert_eq!(runtime.state().persistent.failed_tries, 0);
        assert!(runtime.nv_update_pending);
    }

    #[test]
    fn self_heal_configured_interval_recovery() {
        let mut runtime = manufactured_runtime();
        {
            let persistent = &mut runtime.state.as_mut().unwrap().persistent;
            persistent.failed_tries = 3;
            persistent.recovery_time = 2;
        }
        runtime.live.orderly.self_heal_timer = 0;

        runtime.timer.time_ms = 1_999;
        assert_eq!(da_self_heal(&mut runtime), Ok(()));
        assert_eq!(runtime.state().persistent.failed_tries, 3);
        assert!(!runtime.nv_update_pending, "no change, no NV write");

        runtime.timer.time_ms = 2_000;
        assert_eq!(da_self_heal(&mut runtime), Ok(()));
        assert_eq!(runtime.state().persistent.failed_tries, 2);
        assert_eq!(
            runtime.live.orderly.self_heal_timer, 2_000,
            "the timer advances by the consumed interval"
        );
        assert!(runtime.nv_update_pending);
    }

    #[test]
    fn self_heal_multi_interval_single_sweep_recovery() {
        let mut runtime = manufactured_runtime();
        {
            let persistent = &mut runtime.state.as_mut().unwrap().persistent;
            persistent.failed_tries = 3;
            persistent.recovery_time = 2;
        }
        runtime.live.orderly.self_heal_timer = 1_000;
        runtime.timer.time_ms = 6_300;
        assert_eq!(da_self_heal(&mut runtime), Ok(()));
        assert_eq!(runtime.state().persistent.failed_tries, 1);
        assert_eq!(runtime.live.orderly.self_heal_timer, 5_000);
    }

    #[test]
    fn self_heal_zero_floor() {
        let mut runtime = manufactured_runtime();
        {
            let persistent = &mut runtime.state.as_mut().unwrap().persistent;
            persistent.failed_tries = 1;
            persistent.recovery_time = 1;
        }
        runtime.live.orderly.self_heal_timer = 0;
        runtime.timer.time_ms = 60_000;
        assert_eq!(da_self_heal(&mut runtime), Ok(()));
        assert_eq!(runtime.state().persistent.failed_tries, 0);
    }

    #[test]
    fn negative_self_heal_timer_upstream_cast_accumulation() {
        let mut runtime = manufactured_runtime();
        {
            let persistent = &mut runtime.state.as_mut().unwrap().persistent;
            persistent.failed_tries = 5;
            persistent.recovery_time = 2;
        }
        runtime.live.orderly.self_heal_timer = 0u64.wrapping_sub(5_000);
        runtime.timer.time_ms = 1_000;
        assert_eq!(da_self_heal(&mut runtime), Ok(()));
        assert_eq!(
            runtime.state().persistent.failed_tries,
            2,
            "six accumulated seconds recover three tries"
        );
    }

    #[test]
    fn extreme_timer_self_heal_panic_safety() {
        for (timer, time, recovery, failed) in [
            (u64::MAX, 0u64, 1u32, u32::MAX),
            (u64::MAX, u64::MAX, u32::MAX, u32::MAX),
            (0, u64::MAX, 1, 1),
            (1, 0, u32::MAX, u32::MAX),
        ] {
            let mut runtime = manufactured_runtime();
            {
                let persistent = &mut runtime.state.as_mut().unwrap().persistent;
                persistent.failed_tries = failed;
                persistent.recovery_time = recovery;
            }
            runtime.live.orderly.self_heal_timer = timer;
            runtime.live.orderly.lockout_timer = timer;
            runtime
                .state
                .as_mut()
                .unwrap()
                .persistent
                .lockout_auth_enabled = false;
            runtime.timer.time_ms = time;
            assert_eq!(
                da_self_heal(&mut runtime),
                Ok(()),
                "timer {timer} time {time}"
            );
        }
    }

    #[test]
    fn lockout_auth_configured_interval_reenable() {
        let mut runtime = manufactured_runtime();
        {
            let persistent = &mut runtime.state.as_mut().unwrap().persistent;
            persistent.lockout_auth_enabled = false;
            persistent.lockout_recovery = 2;
        }
        runtime.live.orderly.lockout_timer = 1_000;

        runtime.timer.time_ms = 2_999;
        assert_eq!(da_self_heal(&mut runtime), Ok(()));
        assert!(!runtime.state().persistent.lockout_auth_enabled);
        assert!(!runtime.nv_update_pending);

        runtime.timer.time_ms = 3_000;
        assert_eq!(da_self_heal(&mut runtime), Ok(()));
        assert!(runtime.state().persistent.lockout_auth_enabled);
        assert!(runtime.nv_update_pending);
    }

    #[test]
    fn zero_lockout_recovery_no_reenable() {
        let mut runtime = manufactured_runtime();
        {
            let persistent = &mut runtime.state.as_mut().unwrap().persistent;
            persistent.lockout_auth_enabled = false;
            persistent.lockout_recovery = 0;
        }
        runtime.live.orderly.lockout_timer = 0;
        runtime.timer.time_ms = u64::MAX / 2;
        assert_eq!(da_self_heal(&mut runtime), Ok(()));
        assert!(
            !runtime.state().persistent.lockout_auth_enabled,
            "only a reboot re-enables lockoutAuth when lockoutRecovery is zero"
        );
    }

    #[test]
    fn self_heal_persistence_failure_rollback() {
        let mut runtime = manufactured_runtime();
        {
            let persistent = &mut runtime.state.as_mut().unwrap().persistent;
            persistent.failed_tries = 2;
            persistent.recovery_time = 1;
        }
        runtime.live.orderly.self_heal_timer = 0;
        runtime.timer.time_ms = 1_500;
        break_nv_serialization(&mut runtime);
        assert_eq!(da_self_heal(&mut runtime), Err(TPM_RC_FAILURE));
        assert_eq!(runtime.state().persistent.failed_tries, 2);
        assert_eq!(runtime.live.orderly.self_heal_timer, 0);
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn permanent_blob_da_field_round_trip() {
        use crate::library::tpm2::parse_persistent_all_payload;
        use crate::library::tpm2::persistent::{
            PersistentAllEnvelope, materialize_persistent_state, persistent_all_store,
        };

        let mut runtime = manufactured_runtime();
        {
            let state = runtime.state.as_mut().unwrap();
            state.persistent.failed_tries = 3;
            state.persistent.max_tries = 7;
            state.persistent.recovery_time = 11;
            state.persistent.lockout_recovery = 13;
            state.persistent.lockout_auth_enabled = false;
            state.orderly.self_heal_timer = 0x1111_2222_3333_4444;
            state.orderly.lockout_timer = 0x5555_6666_7777_8888;
            state.orderly.time = 0x9999_aaaa_bbbb_cccc;
        }
        let blob = persistent_all_store(runtime.state.as_ref().unwrap()).unwrap();
        let envelope = PersistentAllEnvelope::parse(&blob).unwrap();
        let decoded = parse_persistent_all_payload(&envelope).unwrap();
        let state = materialize_persistent_state(decoded).unwrap();
        assert_eq!(state.persistent.failed_tries, 3);
        assert_eq!(state.persistent.max_tries, 7);
        assert_eq!(state.persistent.recovery_time, 11);
        assert_eq!(state.persistent.lockout_recovery, 13);
        assert!(!state.persistent.lockout_auth_enabled);
        assert_eq!(state.orderly.self_heal_timer, 0x1111_2222_3333_4444);
        assert_eq!(state.orderly.lockout_timer, 0x5555_6666_7777_8888);
        assert_eq!(state.orderly.time, 0x9999_aaaa_bbbb_cccc);
    }

    #[test]
    fn volatile_blob_da_field_round_trip() {
        use crate::library::tpm2::clock::SteppingClock;
        use crate::library::tpm2::runtime::merge_volatile_state;
        use crate::library::tpm2::volatile::volatile_all_store;
        use crate::library::tpm2::{decode_volatile_blob, volatile_validation_context};

        let clock = SteppingClock::new(1_600_000_000_000, 5_000_000);
        let mut runtime = manufactured_runtime();
        runtime.live.da_used = true;
        runtime.live.da_pending_on_nv = true;
        runtime.live.orderly.self_heal_timer = 0x0102_0304_0506_0708;
        runtime.live.orderly.lockout_timer = 0x090a_0b0c_0d0e_0f10;
        runtime.live.orderly.time = 0x1112_1314_1516_1718;
        runtime.timer.time_ms = 0x2122_2324;
        runtime.timer.tpm_time = 0x3132_3334;
        runtime.timer.real_time_previous = 0x4142_4344;
        runtime.timer.timer_reset = false;
        runtime.timer.timer_stopped = false;

        let blob = volatile_all_store(&runtime, &clock).expect("the volatile state saves");
        let context = volatile_validation_context(&runtime).expect("the context builds");
        let owned =
            decode_volatile_blob(&context, &blob, &clock).expect("the volatile state decodes");

        let mut restored = manufactured_runtime();
        merge_volatile_state(&mut restored, owned);
        assert!(restored.live.da_used);
        assert!(restored.live.da_pending_on_nv);
        assert_eq!(restored.live.orderly.self_heal_timer, 0x0102_0304_0506_0708);
        assert_eq!(restored.live.orderly.lockout_timer, 0x090a_0b0c_0d0e_0f10);
        assert_eq!(restored.live.orderly.time, 0x1112_1314_1516_1718);
        assert_eq!(restored.timer.time_ms, 0x2122_2324);
        assert_eq!(restored.timer.tpm_time, 0x3132_3334);
        assert_eq!(restored.timer.real_time_previous, 0x4142_4344);
        assert!(!restored.timer.timer_reset);
        assert!(!restored.timer.timer_stopped);
    }

    #[test]
    fn lockout_hierarchy_only_da_protection() {
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
    fn undefined_nv_index_da_exemption() {
        let runtime = empty_state_runtime();
        for handle in [0x0100_0000u32, 0x0100_0001, 0x01ff_ffff] {
            assert!(
                !is_da_protected_handle(&runtime, handle),
                "handle {handle:#010x} resolves to no index"
            );
        }
    }

    #[test]
    fn stateless_runtime_panic_safety() {
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
