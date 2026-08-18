use crate::ffi_types::TpmResult;
use crate::library::constants::{
    TPM_RC_FAILURE, TPM_RC_LOCKOUT, TPM_RC_NV_UNAVAILABLE, TPM_RC_RETRY,
};

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
        return Err(TPM_RC_RETRY);
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
    use crate::ffi_types::TpmResult;
    use crate::library::tpm2::hierarchy::{
        TPM_RH_ENDORSEMENT, TPM_RH_NULL, TPM_RH_OWNER, TPM_RH_PLATFORM,
    };
    use crate::library::tpm2::manufacture::manufacture_state;
    use crate::library::tpm2::orderly::SU_NONE_VALUE;
    use crate::library::tpm2::persistent::OwnedSecret;
    use crate::library::tpm2::profile::validate_user_profile;
    use crate::library::tpm2::runtime::{commit_manufactured_state, empty_state_runtime};

    const DA_INDEX: u32 = 0x0100_0000;

    fn deterministic_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
        let len = buffer.len() as u8;
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_add(len) ^ 0x11;
        }
        Ok(())
    }

    fn manufactured_runtime() -> Box<Tpm2Runtime> {
        let profile = validate_user_profile(None).expect("the null profile validates");
        let state = manufacture_state(profile, deterministic_entropy).expect("manufactures");
        commit_manufactured_state(state).expect("commits")
    }

    fn break_nv_serialization(runtime: &mut Tpm2Runtime) {
        runtime.state.as_mut().unwrap().persistent.owner_auth =
            OwnedSecret::from_vec(vec![0xaa; 4096]);
    }

    #[test]
    fn the_first_da_protected_authorization_records_the_marker_and_asks_for_a_retry() {
        let mut runtime = manufactured_runtime();
        runtime.timer.time_ms = 1_234;
        assert!(!runtime.live.da_used);
        assert_eq!(check_locked_out(&mut runtime, DA_INDEX), Err(TPM_RC_RETRY));
        assert!(runtime.live.da_used);
        assert_eq!(
            runtime.state().persistent.orderly_state,
            SU_DA_USED_VALUE,
            "the retry commits the DA-used orderly marker"
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

    #[test]
    fn the_first_da_use_without_nv_is_refused_without_recording_the_marker() {
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
    fn reaching_max_tries_locks_out_da_protected_handles_but_not_the_lockout_hierarchy() {
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
    fn a_regular_failure_increments_failed_tries_and_rewinds_the_self_heal_timer() {
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
    fn a_regular_failure_with_zero_recovery_time_only_rewinds_the_timer() {
        let mut runtime = manufactured_runtime();
        runtime.timer.time_ms = 5_000;
        runtime.state.as_mut().unwrap().persistent.recovery_time = 0;
        assert_eq!(register_lockout_failure(&mut runtime, DA_INDEX), Ok(()));
        assert_eq!(runtime.state().persistent.failed_tries, 0);
        assert_eq!(runtime.live.orderly.self_heal_timer, 5_000);
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn a_lockout_failure_disables_lockout_auth_and_rewinds_its_timer() {
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
    fn a_lockout_failure_with_zero_lockout_recovery_skips_the_nv_update() {
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
    fn failed_tries_wraps_like_the_upstream_plain_increment() {
        let mut runtime = manufactured_runtime();
        runtime.state.as_mut().unwrap().persistent.failed_tries = u32::MAX;
        assert_eq!(register_lockout_failure(&mut runtime, DA_INDEX), Ok(()));
        assert_eq!(runtime.state().persistent.failed_tries, 0);
    }

    #[test]
    fn a_failure_without_nv_becomes_a_pending_da_update() {
        let mut runtime = manufactured_runtime();
        runtime.nv_available = false;
        assert_eq!(register_lockout_failure(&mut runtime, DA_INDEX), Ok(()));
        assert_eq!(runtime.state().persistent.failed_tries, 1);
        assert!(runtime.live.da_pending_on_nv);
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn a_pending_da_update_commits_once_nv_becomes_available() {
        let mut runtime = manufactured_runtime();
        runtime.live.da_used = true;
        runtime.live.da_pending_on_nv = true;
        assert_eq!(check_locked_out(&mut runtime, DA_INDEX), Ok(()));
        assert!(!runtime.live.da_pending_on_nv);
        assert!(runtime.nv_update_pending);
    }

    #[test]
    fn a_pending_da_update_blocks_authorization_while_nv_is_unavailable() {
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
    fn a_persistence_failure_rolls_back_the_failure_registration() {
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
    fn self_heal_clears_failed_tries_immediately_when_recovery_time_is_zero() {
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
    fn self_heal_recovers_exactly_at_the_configured_interval() {
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
    fn self_heal_recovers_multiple_elapsed_intervals_in_one_sweep() {
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
    fn self_heal_never_decrements_below_zero() {
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
    fn a_wrapped_negative_self_heal_timer_accumulates_like_the_upstream_cast() {
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
    fn extreme_timer_values_never_panic_the_self_heal_arithmetic() {
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
    fn lockout_auth_reenables_exactly_at_the_configured_interval() {
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
    fn lockout_auth_stays_disabled_when_lockout_recovery_is_zero() {
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
    fn a_self_heal_persistence_failure_rolls_back_the_recovery() {
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
    fn the_permanent_blob_round_trips_every_persistent_da_field() {
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
    fn the_volatile_blob_round_trips_every_live_da_field() {
        use crate::library::tpm2::clock::SteppingClock;
        use crate::library::tpm2::runtime::merge_volatile_state;
        use crate::library::tpm2::volatile::volatile_all_store;
        use crate::library::tpm2::{
            VolatileDecodeBoundary, decode_volatile_blob, volatile_validation_context,
        };

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
        let owned = decode_volatile_blob(&context, &blob, &clock, VolatileDecodeBoundary::Restore)
            .expect("the volatile state decodes");

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
