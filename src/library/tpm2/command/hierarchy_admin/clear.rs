use crate::ffi_types::TpmResult;
use crate::library::constants::{
    TPM_RC_DISABLED, TPM_RC_FAILURE, TPM_RC_NV_UNAVAILABLE, TPM_RC_SIZE,
};

use super::super::super::algorithm::TPM_ALG_NULL;
use super::super::super::hierarchy::{TPM_RH_ENDORSEMENT, TPM_RH_OWNER};
use super::super::super::nv::{TPMA_NV_PLATFORMCREATE, delete_index, resolve_index};
use super::super::super::orderly::prepare_clear_orderly;
use super::super::super::persistent::{OwnedSecret, OwnedUserNvramEntry};
use super::super::super::runtime::Tpm2Runtime;
use super::super::dispatcher::CommandFrame;
use super::super::output::CommandOutput;
use super::super::pcr_update::{commit_pcr_counter, live_pcr_counter, pcr_changed};
use super::{
    PRIMARY_SEED_SIZE, PROOF_SIZE, commit_persistent_state, flush_loaded_hierarchy_objects,
    hierarchy_object_attribute, recompute_user_nvram_capacity, regenerate_hierarchy_secrets,
    remove_hierarchy_persistent_objects, with_rollback,
};

const DA_DEFAULT_MAX_TRIES: u32 = 3;
const DA_DEFAULT_RECOVERY_TIME: u32 = 1000;
const DA_DEFAULT_LOCKOUT_RECOVERY: u32 = 1000;

const CLEARED_PCR: usize = 0;

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    frame.handles.first().copied().ok_or(TPM_RC_FAILURE)?;
    if !frame.parameters.is_empty() {
        return Err(TPM_RC_SIZE);
    }
    if !runtime.nv_available {
        return Err(TPM_RC_NV_UNAVAILABLE);
    }
    if runtime
        .state
        .as_ref()
        .ok_or(TPM_RC_FAILURE)?
        .persistent
        .disable_clear
    {
        return Err(TPM_RC_DISABLED);
    }
    if runtime.live.state_clear.is_none() || runtime.live.state_reset.is_none() {
        return Err(TPM_RC_FAILURE);
    }

    let orderly_state = prepare_clear_orderly(runtime)?;
    // TODO: Support runtimes without decoded state after the NVChip fallback
    // is implemented.
    let seed_compat_level = runtime
        .state
        .as_ref()
        .ok_or(TPM_RC_FAILURE)?
        .profile
        .seed_compat_level();

    let mut secrets =
        regenerate_hierarchy_secrets(runtime, &[PRIMARY_SEED_SIZE, PROOF_SIZE, PROOF_SIZE])?
            .into_iter();
    let sp_seed = secrets.next().ok_or(TPM_RC_FAILURE)?;
    let sh_proof = secrets.next().ok_or(TPM_RC_FAILURE)?;
    let eh_proof = secrets.next().ok_or(TPM_RC_FAILURE)?;

    with_rollback(runtime, |runtime| {
        let owner = hierarchy_object_attribute(TPM_RH_OWNER).ok_or(TPM_RC_FAILURE)?;
        let endorsement = hierarchy_object_attribute(TPM_RH_ENDORSEMENT).ok_or(TPM_RC_FAILURE)?;
        let pcr_counter = pcr_changed(live_pcr_counter(runtime)?, CLEARED_PCR)?;

        let state = runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?;
        if let Some(sp_seed) = sp_seed {
            state.persistent.sp_seed = sp_seed;
        }
        state.persistent.sp_seed_compat_level = seed_compat_level;
        if let Some(sh_proof) = sh_proof {
            state.persistent.sh_proof = sh_proof;
        }
        if let Some(eh_proof) = eh_proof {
            state.persistent.eh_proof = eh_proof;
        }
        state.persistent.owner_auth = OwnedSecret::from_vec(Vec::new());
        state.persistent.endorsement_auth = OwnedSecret::from_vec(Vec::new());
        state.persistent.lockout_auth = OwnedSecret::from_vec(Vec::new());
        state.persistent.owner_alg = TPM_ALG_NULL;
        state.persistent.endorsement_alg = TPM_ALG_NULL;
        state.persistent.lockout_alg = TPM_ALG_NULL;
        state.persistent.owner_policy = Vec::new();
        state.persistent.endorsement_policy = Vec::new();
        state.persistent.lockout_policy = Vec::new();

        state.persistent.failed_tries = 0;
        state.persistent.max_tries = DA_DEFAULT_MAX_TRIES;
        state.persistent.recovery_time = DA_DEFAULT_RECOVERY_TIME;
        state.persistent.lockout_recovery = DA_DEFAULT_LOCKOUT_RECOVERY;
        state.persistent.lockout_auth_enabled = true;

        state.persistent.reset_count = 0;
        state.persistent.audit_counter = 0;
        if let Some(orderly_state) = orderly_state {
            state.persistent.orderly_state = orderly_state;
        }

        remove_hierarchy_persistent_objects(state, owner)?;
        remove_hierarchy_persistent_objects(state, endorsement)?;
        flush_owner_nv_indexes(runtime)?;
        recompute_user_nvram_capacity(runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?)?;

        flush_loaded_hierarchy_objects(&mut runtime.live.objects, owner);
        flush_loaded_hierarchy_objects(&mut runtime.live.objects, endorsement);

        runtime.live.orderly.clock = 0;
        runtime.live.orderly.clock_safe = 1;
        let orderly = runtime.live.orderly.clone();
        runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?.orderly = orderly;

        let reset = runtime.live.state_reset.as_mut().ok_or(TPM_RC_FAILURE)?;
        reset.restart_count = 0;
        reset.clear_count = 0;

        let clear = runtime.live.state_clear.as_mut().ok_or(TPM_RC_FAILURE)?;
        clear.sh_enable = true;
        clear.eh_enable = true;
        for auth_value in &mut clear.pcr_auth_values {
            *auth_value = OwnedSecret::from_vec(Vec::new());
        }

        commit_pcr_counter(runtime, pcr_counter)?;
        commit_persistent_state(runtime)
    })?;
    Ok(CommandOutput::empty())
}

fn owner_created_index(runtime: &Tpm2Runtime) -> Result<Option<u32>, TpmResult> {
    let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
    Ok(state
        .user_nvram
        .entries
        .iter()
        .find_map(|entry| match entry {
            OwnedUserNvramEntry::NvIndex { handle, index, .. }
                if index.attributes & TPMA_NV_PLATFORMCREATE == 0 =>
            {
                Some(*handle)
            }
            _ => None,
        }))
}

fn flush_owner_nv_indexes(runtime: &mut Tpm2Runtime) -> Result<(), TpmResult> {
    while let Some(handle) = owner_created_index(runtime)? {
        let resolved = resolve_index(runtime, handle).ok_or(TPM_RC_FAILURE)?;
        delete_index(runtime, &resolved)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::super::registry::{
        CommandLifecycle, HandleKind, NvAccess, TPM_CC_CLEAR, find,
    };
    use super::super::harness::*;
    use crate::library::tpm2::hierarchy::{
        TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT, TPM_RH_NULL, TPM_RH_OWNER, TPM_RH_PLATFORM,
    };
    use crate::library::tpm2::runtime::Tpm2Runtime;

    fn provisioned(clock: &crate::library::tpm2::clock::SteppingClock) -> Box<Tpm2Runtime> {
        let mut runtime = oracle_runtime(clock);
        expect(
            &mut runtime,
            clock,
            "CLR_OWNER_PRIMARY",
            &create_primary(TPM_RH_OWNER),
        );
        expect(
            &mut runtime,
            clock,
            "CLR_EVICT_OWNER",
            &evict_control(TPM_RH_OWNER, TRANSIENT_FIRST, OWNER_PERSISTENT),
        );
        exec(&mut runtime, clock, &flush(TRANSIENT_FIRST));
        expect(
            &mut runtime,
            clock,
            "CLR_PLATFORM_PRIMARY",
            &create_primary(TPM_RH_PLATFORM),
        );
        expect(
            &mut runtime,
            clock,
            "CLR_EVICT_PLATFORM",
            &evict_control(TPM_RH_PLATFORM, TRANSIENT_FIRST, PLATFORM_PERSISTENT),
        );
        exec(&mut runtime, clock, &flush(TRANSIENT_FIRST));
        for (label, bytes) in [
            (
                "CLR_DEFINE_OWNER_INDEX",
                nv_define(TPM_RH_OWNER, OWNER_INDEX, NV_OWNER_ATTRIBUTES, 8),
            ),
            (
                "CLR_DEFINE_PLATFORM_INDEX",
                nv_define(TPM_RH_PLATFORM, PLATFORM_INDEX, NV_PLATFORM_ATTRIBUTES, 8),
            ),
            ("CLR_OWNER_PRIMARY_LOADED", create_primary(TPM_RH_OWNER)),
            (
                "CLR_ENDORSEMENT_PRIMARY_LOADED",
                create_primary(TPM_RH_ENDORSEMENT),
            ),
            (
                "CLR_PLATFORM_PRIMARY_LOADED",
                create_primary(TPM_RH_PLATFORM),
            ),
            (
                "CLR_OWNER_AUTH",
                change_auth_command(TPM_RH_OWNER, &[], b"owner"),
            ),
            (
                "CLR_ENDORSEMENT_AUTH",
                change_auth_command(TPM_RH_ENDORSEMENT, &[], b"endorse"),
            ),
            (
                "CLR_LOCKOUT_AUTH",
                change_auth_command(TPM_RH_LOCKOUT, &[], b"lockout"),
            ),
            (
                "CLR_PLATFORM_AUTH",
                change_auth_command(TPM_RH_PLATFORM, &[], b"platform"),
            ),
            (
                "CLR_OWNER_POLICY",
                set_primary_policy(TPM_RH_OWNER, &DIGEST, TPM_ALG_SHA256, b"owner"),
            ),
            (
                "CLR_ENDORSEMENT_POLICY",
                set_primary_policy(TPM_RH_ENDORSEMENT, &DIGEST, TPM_ALG_SHA256, b"endorse"),
            ),
            (
                "CLR_LOCKOUT_POLICY",
                set_primary_policy(TPM_RH_LOCKOUT, &DIGEST, TPM_ALG_SHA256, b"lockout"),
            ),
            (
                "CLR_PLATFORM_POLICY",
                set_primary_policy(TPM_RH_PLATFORM, &DIGEST, TPM_ALG_SHA256, b"platform"),
            ),
            ("CLR_DA_PARAMETERS", da_parameters(9, 7, 5, b"lockout")),
            ("CLR_PERMANENT_BEFORE", cap_permanent_flags()),
            ("CLR_CAP_TRANSIENT_BEFORE", cap_transient()),
            ("CLR_CAP_PERSISTENT_BEFORE", cap_persistent()),
            ("CLR_CAP_NV_BEFORE", cap_nv()),
            ("CLR_PCR_READ_BEFORE", pcr_read_all()),
            ("CLR_LOCKOUT_BEFORE", cap_lockout()),
        ] {
            expect(&mut runtime, clock, label, &bytes);
        }
        runtime
    }

    #[test]
    fn the_command_is_registered_with_the_upstream_attributes() {
        let descriptor = find(TPM_CC_CLEAR).expect("the command is registered");
        assert_eq!(descriptor.attributes, 0x02c0_0126);
        assert!(descriptor.physical_presence);
        assert!(descriptor.sessions_allowed);
        assert_eq!(descriptor.decrypt_size, 0);
        assert_eq!(descriptor.encrypt_size, 0);
        assert!(matches!(descriptor.nv_access, NvAccess::Neither));
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
        assert_eq!(descriptor.handles.len(), 1);
        assert!(descriptor.handles[0].user_auth);
        assert!(matches!(descriptor.handles[0].kind, HandleKind::Clear));
    }

    #[test]
    fn the_reported_command_attributes_match_the_reference() {
        replay(&[("CCATTR_0126", cap_command_attributes(TPM_CC_CLEAR))]);
    }

    #[test]
    fn the_handle_and_parameter_errors_match_the_reference() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        let before = snapshot(&runtime);
        for (label, bytes) in [
            ("CLR_BY_OWNER", clear(TPM_RH_OWNER, &[])),
            ("CLR_BY_ENDORSEMENT", clear(TPM_RH_ENDORSEMENT, &[])),
            ("CLR_BY_NULL", clear(TPM_RH_NULL, &[])),
            (
                "CLR_NO_SESSIONS",
                framed(TPM_CC_CLEAR, &TPM_RH_PLATFORM.to_be_bytes(), false),
            ),
            (
                "CLR_TRAILING",
                command(TPM_CC_CLEAR, &[TPM_RH_PLATFORM], &[&[]], &[0xee]),
            ),
            ("CLR_WRONG_PASSWORD", clear(TPM_RH_PLATFORM, b"wrong")),
            (
                "CLR_TRUNCATED_HANDLE",
                framed(TPM_CC_CLEAR, &TPM_RH_PLATFORM.to_be_bytes()[..2], true),
            ),
            ("CLR_PERMANENT_AFTER_REJECTED", cap_permanent_flags()),
        ] {
            expect(&mut runtime, &clock, label, &bytes);
        }
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn lockout_authorization_clears_the_tpm() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        for (label, bytes) in [
            ("CLR_BY_LOCKOUT", clear(TPM_RH_LOCKOUT, &[])),
            ("CLR_PERMANENT_AFTER_LOCKOUT_CLEAR", cap_permanent_flags()),
        ] {
            expect(&mut runtime, &clock, label, &bytes);
        }
    }

    #[test]
    fn a_disabled_clear_changes_nothing_and_draws_no_randomness() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        expect(
            &mut runtime,
            &clock,
            "CTL_DISABLE_BY_PLATFORM",
            &clear_control(TPM_RH_PLATFORM, 1, &[]),
        );
        let before = snapshot(&runtime);
        let drbg_before = runtime.live.orderly.drbg_state.reseed_counter;
        for (label, bytes) in [
            ("CTL_CLEAR_WHILE_DISABLED", clear(TPM_RH_PLATFORM, &[])),
            (
                "CTL_CLEAR_BY_LOCKOUT_WHILE_DISABLED",
                clear(TPM_RH_LOCKOUT, &[]),
            ),
        ] {
            expect(&mut runtime, &clock, label, &bytes);
        }
        assert_unchanged(&runtime, &before);
        assert_eq!(
            runtime.live.orderly.drbg_state.reseed_counter, drbg_before,
            "a refused clear consumes no randomness"
        );
    }

    #[test]
    fn the_full_clear_matches_the_reference_and_the_expected_state() {
        let clock = replay_clock();
        let mut runtime = provisioned(&clock);

        let before = secrets(&runtime);
        let counters_before = counters(&runtime);
        let pcr_counter_before = counters_before.pcr_counter;

        expect(
            &mut runtime,
            &clock,
            "CLR_CLEAR",
            &clear(TPM_RH_PLATFORM, b"platform"),
        );

        let after = secrets(&runtime);
        assert_ne!(after.sp_seed, before.sp_seed, "the storage seed changes");
        assert_ne!(after.sh_proof, before.sh_proof, "the storage proof changes");
        assert_ne!(
            after.eh_proof, before.eh_proof,
            "the endorsement proof changes"
        );
        assert_eq!(after.pp_seed, before.pp_seed, "the platform seed survives");
        assert_eq!(
            after.ph_proof, before.ph_proof,
            "the platform proof survives"
        );
        assert_eq!(
            after.ep_seed, before.ep_seed,
            "the endorsement seed survives"
        );
        assert_eq!(
            after.sp_seed_compat_level,
            runtime.state().profile.seed_compat_level()
        );
        assert_eq!(after.ep_seed_compat_level, before.ep_seed_compat_level);
        assert_eq!(after.pp_seed_compat_level, before.pp_seed_compat_level);

        let empty = fingerprint(&[]);
        assert_eq!(after.owner_auth, empty);
        assert_eq!(after.endorsement_auth, empty);
        assert_eq!(after.lockout_auth, empty);
        assert_eq!(
            after.platform_auth, before.platform_auth,
            "platformAuth is not cleared"
        );

        let policies_after = policies(&runtime);
        assert_eq!(policies_after.owner, (TPM_ALG_NULL, Vec::new()));
        assert_eq!(policies_after.endorsement, (TPM_ALG_NULL, Vec::new()));
        assert_eq!(policies_after.lockout, (TPM_ALG_NULL, Vec::new()));
        assert_eq!(
            policies_after.platform,
            (TPM_ALG_SHA256, DIGEST.to_vec()),
            "the platform policy is not cleared"
        );

        assert_eq!(
            dictionary_attack_state(&runtime),
            DictionaryAttackState {
                failed_tries: 0,
                max_tries: 3,
                recovery_time: 1000,
                lockout_recovery: 1000,
                lockout_auth_enabled: true,
                self_heal_timer: dictionary_attack_state(&runtime).self_heal_timer,
                lockout_timer: dictionary_attack_state(&runtime).lockout_timer,
            },
            "the manufacturer dictionary-attack defaults are restored"
        );

        assert_eq!(
            counters(&runtime),
            Counters {
                reset_count: 0,
                total_reset_count: counters_before.total_reset_count,
                restart_count: 0,
                clear_count: 0,
                pcr_counter: pcr_counter_before + 1,
                audit_counter: 0,
            }
        );
        assert_eq!(runtime.live.orderly.clock, 0);
        assert_eq!(runtime.live.orderly.clock_safe, 1);
        assert_eq!(
            runtime.state().orderly.clock,
            0,
            "the orderly data is written back to NV"
        );
        assert_eq!(
            enables(&runtime),
            Enables {
                ph_enable: true,
                sh_enable: true,
                eh_enable: true,
                ph_enable_nv: true,
            }
        );
        for value in &snapshot(&runtime).pcr_auth_values {
            assert_eq!(*value, empty, "the PCR authorization values are cleared");
        }
        assert_eq!(
            nvram_handles(&runtime),
            [OWNER_PERSISTENT, PLATFORM_PERSISTENT, PLATFORM_INDEX],
            "the owner NV index is deleted and the evict objects survive"
        );
        assert_eq!(occupied_slots(&runtime), [2], "only the platform key stays");
        assert!(!runtime.state().persistent.disable_clear);
        assert_nv_image_is_current(&runtime);

        for (label, bytes) in [
            ("CLR_PERMANENT_AFTER", cap_permanent_flags()),
            ("CLR_CAP_STARTUP_CLEAR_AFTER", cap_startup_clear()),
            ("CLR_CAP_TRANSIENT_AFTER", cap_transient()),
            ("CLR_CAP_PERSISTENT_AFTER", cap_persistent()),
            ("CLR_CAP_NV_AFTER", cap_nv()),
            ("CLR_PCR_READ_AFTER", pcr_read_all()),
            ("CLR_LOCKOUT_AFTER", cap_lockout()),
            (
                "CLR_OWNER_AUTH_CLEARED",
                change_auth_command(TPM_RH_OWNER, &[], &[]),
            ),
            (
                "CLR_ENDORSEMENT_AUTH_CLEARED",
                change_auth_command(TPM_RH_ENDORSEMENT, &[], &[]),
            ),
            (
                "CLR_LOCKOUT_AUTH_CLEARED",
                change_auth_command(TPM_RH_LOCKOUT, &[], &[]),
            ),
            (
                "CLR_PLATFORM_AUTH_EMPTY_REFUSED",
                change_auth_command(TPM_RH_PLATFORM, &[], &[]),
            ),
            (
                "CLR_PLATFORM_AUTH_STILL_SET",
                change_auth_command(TPM_RH_PLATFORM, b"platform", b"platform"),
            ),
            (
                "CLR_PLATFORM_POLICY_KEPT",
                set_primary_policy(TPM_RH_PLATFORM, &DIGEST, TPM_ALG_SHA256, b"platform"),
            ),
            ("CLR_NV_READPUBLIC_OWNER_INDEX", nv_read_public(OWNER_INDEX)),
            (
                "CLR_NV_READPUBLIC_PLATFORM_INDEX",
                nv_read_public(PLATFORM_INDEX),
            ),
            (
                "CLR_READPUBLIC_PLATFORM_KEPT",
                read_public(TRANSIENT_FIRST + 2),
            ),
            ("CLR_OWNER_PRIMARY_AFTER", create_primary(TPM_RH_OWNER)),
            (
                "CLR_ENDORSEMENT_PRIMARY_AFTER",
                create_primary(TPM_RH_ENDORSEMENT),
            ),
            ("CLR_SECOND_CLEAR", clear(TPM_RH_PLATFORM, b"platform")),
            ("CLR_PERMANENT_AFTER_SECOND", cap_permanent_flags()),
            ("CLR_LOCKOUT_AFTER_SECOND", cap_lockout()),
        ] {
            expect(&mut runtime, &clock, label, &bytes);
        }
    }

    #[test]
    fn the_cleared_state_survives_a_permanent_state_round_trip() {
        let clock = replay_clock();
        let mut runtime = provisioned(&clock);
        expect(
            &mut runtime,
            &clock,
            "CLR_CLEAR",
            &clear(TPM_RH_PLATFORM, b"platform"),
        );
        let expected = secrets(&runtime);
        let reloaded = reload(runtime.state());
        let persistent = &reloaded.persistent;
        assert_eq!(fingerprint(persistent.sp_seed.expose()), expected.sp_seed);
        assert_eq!(fingerprint(persistent.sh_proof.expose()), expected.sh_proof);
        assert_eq!(fingerprint(persistent.eh_proof.expose()), expected.eh_proof);
        assert_eq!(fingerprint(persistent.pp_seed.expose()), expected.pp_seed);
        assert!(persistent.owner_auth.expose().is_empty());
        assert!(persistent.endorsement_auth.expose().is_empty());
        assert!(persistent.lockout_auth.expose().is_empty());
        assert_eq!(persistent.owner_alg, TPM_ALG_NULL);
        assert_eq!(persistent.endorsement_alg, TPM_ALG_NULL);
        assert_eq!(persistent.lockout_alg, TPM_ALG_NULL);
        assert_eq!(persistent.failed_tries, 0);
        assert_eq!(persistent.max_tries, 3);
        assert_eq!(persistent.recovery_time, 1000);
        assert_eq!(persistent.lockout_recovery, 1000);
        assert!(persistent.lockout_auth_enabled);
        assert_eq!(persistent.reset_count, 0);
        assert_eq!(persistent.audit_counter, 0);
        assert!(!persistent.disable_clear);
        assert_eq!(reloaded.orderly.clock, 0);
    }

    #[test]
    fn a_clear_clears_the_orderly_state() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        exec(&mut runtime, &clock, &shutdown(1));
        expect(
            &mut runtime,
            &clock,
            "CLR_ORDERLY_CLEAR",
            &clear(TPM_RH_PLATFORM, &[]),
        );
        assert!(!crate::library::tpm2::orderly::is_orderly(
            runtime.state().persistent.orderly_state
        ));
        let mut rebooted = reboot(&runtime, &clock);
        expect(
            &mut rebooted,
            &clock,
            "CLR_ORDERLY_STARTUP_STATE",
            &startup(1),
        );
    }

    #[test]
    fn an_unavailable_nv_refuses_the_command_before_the_disable_check() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        expect(
            &mut runtime,
            &clock,
            "CTL_DISABLE_BY_PLATFORM",
            &clear_control(TPM_RH_PLATFORM, 1, &[]),
        );
        runtime.nv_available = false;
        let before = snapshot(&runtime);
        let response = exec(&mut runtime, &clock, &clear(TPM_RH_PLATFORM, &[]));
        assert_eq!(
            response_code(&response),
            RC_NV_UNAVAILABLE,
            "the NV check precedes the disableClear check"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn a_successful_clear_draws_three_secrets_and_commits_once() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        let before = runtime.live.orderly.drbg_state.reseed_counter;
        let commits = core::cell::Cell::new(0u32);
        exec_counting(&mut runtime, &clock, &clear(TPM_RH_PLATFORM, &[]), &commits);
        assert_eq!(
            runtime.live.orderly.drbg_state.reseed_counter,
            before + 3,
            "one draw for the storage seed and one for each proof"
        );
        assert_eq!(commits.get(), 1);
        assert_eq!(commits_for(&clear(TPM_RH_OWNER, &[])), 0);
    }

    #[test]
    fn a_failing_host_commit_fails_the_tpm() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        let bytes = clear(TPM_RH_PLATFORM, &[]);
        let input = crate::library::CommandInput::new(bytes.len() as u32, bytes);
        let response =
            crate::library::tpm2::process::process(&mut runtime, 0, &input, &clock, |_| {
                Err(crate::library::constants::TPM_RC_FAILURE)
            })
            .expect("the command processes");
        assert_eq!(response, error_response(0x101));
        assert!(runtime.failure_mode);
    }

    #[test]
    fn a_failed_nv_image_keeps_the_consumed_draws_and_rolls_back_the_rest() {
        use crate::library::tpm2::nv::build_nv_image;

        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        runtime
            .state
            .as_mut()
            .expect("state present")
            .persistent
            .pp_seed = crate::library::tpm2::persistent::OwnedSecret::from_vec(vec![0x5a; 4096]);
        assert!(
            build_nv_image(runtime.state()).is_err(),
            "the oversized platform seed must not serialize"
        );
        let before = snapshot(&runtime);
        let drbg_before = runtime.live.orderly.drbg_state.reseed_counter;

        let commits = core::cell::Cell::new(0u32);
        let response = exec_counting(&mut runtime, &clock, &clear(TPM_RH_PLATFORM, &[]), &commits);
        assert_eq!(response_code(&response), 0x101);
        assert_eq!(commits.get(), 0);
        assert!(!runtime.failure_mode);
        assert_eq!(
            runtime.live.orderly.drbg_state.reseed_counter,
            drbg_before + 3,
            "the consumed draws are kept like the C generator"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn malformed_input_never_panics() {
        let clock = replay_clock();
        let valid = clear(TPM_RH_PLATFORM, &[]);
        for len in 0..=valid.len() {
            for index in 0..len {
                for flip in [0x01u8, 0x80, 0xff] {
                    let mut mutated = valid[..len].to_vec();
                    mutated[index] ^= flip;
                    let mut runtime = oracle_runtime(&clock);
                    let input = crate::library::CommandInput::new(mutated.len() as u32, mutated);
                    let _ = crate::library::tpm2::process::process(
                        &mut runtime,
                        0,
                        &input,
                        &clock,
                        |_| Ok(()),
                    );
                }
            }
        }
    }
}
