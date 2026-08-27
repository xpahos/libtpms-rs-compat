use super::{commit_persistent_state, with_rollback};
use crate::ffi_types::TpmResult;
use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_NV_UNAVAILABLE, TPM_RC_SIZE};
use crate::library::tpm2::command::core::dispatcher::CommandFrame;
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::runtime::Tpm2Runtime;
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

    with_rollback(runtime, |runtime| {
        runtime
            .state
            .as_mut()
            .ok_or(TPM_RC_FAILURE)?
            .persistent
            .failed_tries = 0;
        commit_persistent_state(runtime)
    })?;
    Ok(CommandOutput::empty())
}

#[cfg(test)]
mod tests {
    use crate::library::tpm2::command::core::registry::{
        CommandLifecycle, HandleKind, NvAccess, TPM_CC_DICTIONARY_ATTACK_LOCK_RESET, find,
    };
    use crate::library::tpm2::command::core::test_support::{
        command, error_response, framed, response_code,
    };
    use crate::library::tpm2::command::hierarchy::test_support::{
        NV_OWNER_ATTRIBUTES, OWNER_INDEX, RC_LOCKOUT, RC_NV_UNAVAILABLE, RC_SUCCESS,
        TPM_CC_DA_LOCK_RESET, assert_nv_image_is_current, assert_unchanged, cap_command_attributes,
        cap_lockout, cap_permanent_flags, commits_for, da_lock_reset, da_parameters,
        dictionary_attack_state, exec, expect, nv_define, nv_read, oracle_runtime, reboot, reload,
        replay, replay_clock, shutdown, snapshot, startup,
    };
    use crate::library::tpm2::hierarchy::{
        TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT, TPM_RH_NULL, TPM_RH_OWNER, TPM_RH_PLATFORM,
    };

    #[test]
    fn the_command_is_registered_with_the_upstream_attributes() {
        let descriptor =
            find(TPM_CC_DICTIONARY_ATTACK_LOCK_RESET).expect("the command is registered");
        assert_eq!(descriptor.attributes, 0x0240_0139);
        assert!(!descriptor.physical_presence);
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
        assert!(!descriptor.handles[0].admin_role());
        assert!(matches!(descriptor.handles[0].kind, HandleKind::Lockout));
    }

    #[test]
    fn the_reported_command_attributes_match_the_reference() {
        replay(&[(
            "CCATTR_0139",
            cap_command_attributes(TPM_CC_DICTIONARY_ATTACK_LOCK_RESET),
        )]);
    }

    #[test]
    fn the_failure_counter_lifecycle_matches_the_reference() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        for (label, bytes) in [
            ("DALR_DA_PARAMETERS", da_parameters(2, 3600, 3600, &[])),
            (
                "DALR_DEFINE_DA_INDEX",
                nv_define(TPM_RH_OWNER, OWNER_INDEX, NV_OWNER_ATTRIBUTES, 8),
            ),
            ("DALR_WRONG_AUTH_1", nv_read(OWNER_INDEX, b"bad")),
            ("DALR_LOCKOUT_AFTER_ONE_FAILURE", cap_lockout()),
        ] {
            expect(&mut runtime, &clock, label, &bytes);
        }
        let configured = dictionary_attack_state(&runtime);
        assert_eq!(configured.failed_tries, 1);
        assert_eq!(configured.max_tries, 2);
        assert_eq!(configured.recovery_time, 3600);
        assert_eq!(configured.lockout_recovery, 3600);

        expect(
            &mut runtime,
            &clock,
            "DALR_RESET",
            &da_lock_reset(TPM_RH_LOCKOUT, &[]),
        );
        let after_reset = dictionary_attack_state(&runtime);
        assert_eq!(after_reset.failed_tries, 0, "only failedTries is reset");
        assert_eq!(after_reset.max_tries, configured.max_tries);
        assert_eq!(after_reset.recovery_time, configured.recovery_time);
        assert_eq!(after_reset.lockout_recovery, configured.lockout_recovery);
        assert!(after_reset.lockout_auth_enabled);
        assert_eq!(
            after_reset.self_heal_timer, configured.self_heal_timer,
            "the self-heal timer is untouched"
        );
        assert_eq!(after_reset.lockout_timer, configured.lockout_timer);
        assert_nv_image_is_current(&runtime);

        for (label, bytes) in [
            ("DALR_LOCKOUT_AFTER_RESET", cap_lockout()),
            ("DALR_PERMANENT_AFTER_RESET", cap_permanent_flags()),
            ("DALR_WRONG_AUTH_2", nv_read(OWNER_INDEX, b"bad")),
            ("DALR_WRONG_AUTH_3", nv_read(OWNER_INDEX, b"bad")),
            ("DALR_WRONG_AUTH_4", nv_read(OWNER_INDEX, b"bad")),
            ("DALR_LOCKOUT_IN_LOCKOUT", cap_lockout()),
            ("DALR_PERMANENT_IN_LOCKOUT", cap_permanent_flags()),
        ] {
            expect(&mut runtime, &clock, label, &bytes);
        }
        assert_eq!(dictionary_attack_state(&runtime).failed_tries, 2);

        for (label, bytes) in [
            (
                "DALR_RESET_WHILE_LOCKED_OUT",
                da_lock_reset(TPM_RH_LOCKOUT, &[]),
            ),
            ("DALR_LOCKOUT_AFTER_LOCKOUT_RESET", cap_lockout()),
            ("DALR_PERMANENT_AFTER_LOCKOUT_RESET", cap_permanent_flags()),
            ("DALR_READ_AFTER_LOCKOUT_RESET", nv_read(OWNER_INDEX, &[])),
        ] {
            expect(&mut runtime, &clock, label, &bytes);
        }
        assert_eq!(dictionary_attack_state(&runtime).failed_tries, 0);
    }

    #[test]
    fn the_handle_and_parameter_errors_match_the_reference() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        let before = snapshot(&runtime);
        for (label, bytes) in [
            ("DALR_BY_OWNER", da_lock_reset(TPM_RH_OWNER, &[])),
            ("DALR_BY_PLATFORM", da_lock_reset(TPM_RH_PLATFORM, &[])),
            (
                "DALR_BY_ENDORSEMENT",
                da_lock_reset(TPM_RH_ENDORSEMENT, &[]),
            ),
            ("DALR_BY_NULL", da_lock_reset(TPM_RH_NULL, &[])),
            (
                "DALR_NO_SESSIONS",
                framed(TPM_CC_DA_LOCK_RESET, &TPM_RH_LOCKOUT.to_be_bytes(), false),
            ),
            (
                "DALR_TRAILING",
                command(TPM_CC_DA_LOCK_RESET, &[TPM_RH_LOCKOUT], &[&[]], &[0xee]),
            ),
            (
                "DALR_WRONG_PASSWORD",
                da_lock_reset(TPM_RH_LOCKOUT, b"wrong"),
            ),
            (
                "DALR_TRUNCATED_HANDLE",
                framed(
                    TPM_CC_DA_LOCK_RESET,
                    &TPM_RH_LOCKOUT.to_be_bytes()[..1],
                    true,
                ),
            ),
        ] {
            expect(&mut runtime, &clock, label, &bytes);
        }
        assert!(before.dictionary_attack.lockout_auth_enabled);
        assert!(
            !dictionary_attack_state(&runtime).lockout_auth_enabled,
            "the rejected lockout password disables lockoutAuth for the recovery time"
        );
        assert_eq!(
            dictionary_attack_state(&runtime).failed_tries,
            before.dictionary_attack.failed_tries,
            "a lockout failure never touches the ordinary failure counter"
        );
    }

    #[test]
    fn a_disabled_lockout_authorization_refuses_the_reset() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        for (label, bytes) in [
            (
                "DALR_LOCKOUT_RECOVERY_SETUP",
                da_parameters(2, 0, 3600, &[]),
            ),
            (
                "DALR_LOCKOUT_WRONG_AUTH",
                da_parameters(3, 0, 3600, b"wrong"),
            ),
            (
                "DALR_WHILE_LOCKOUT_AUTH_DISABLED",
                da_lock_reset(TPM_RH_LOCKOUT, &[]),
            ),
            (
                "DALR_PERMANENT_LOCKOUT_AUTH_DISABLED",
                cap_permanent_flags(),
            ),
        ] {
            expect(&mut runtime, &clock, label, &bytes);
        }
        assert!(!dictionary_attack_state(&runtime).lockout_auth_enabled);
        assert_eq!(
            response_code(&exec(
                &mut runtime,
                &clock,
                &da_lock_reset(TPM_RH_LOCKOUT, &[])
            )),
            RC_LOCKOUT
        );
    }

    #[test]
    fn the_command_never_clears_the_orderly_state() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        exec(&mut runtime, &clock, &shutdown(1));
        expect(
            &mut runtime,
            &clock,
            "DALR_ORDERLY_RESET",
            &da_lock_reset(TPM_RH_LOCKOUT, &[]),
        );
        assert!(crate::library::tpm2::orderly::is_orderly(
            runtime.state().persistent.orderly_state
        ));
        let mut rebooted = reboot(&runtime, &clock);
        expect(
            &mut rebooted,
            &clock,
            "DALR_ORDERLY_STARTUP_STATE",
            &startup(1),
        );
    }

    #[test]
    fn the_reset_counter_survives_a_permanent_state_round_trip() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        runtime
            .state
            .as_mut()
            .expect("state present")
            .persistent
            .failed_tries = 5;
        let response = exec(&mut runtime, &clock, &da_lock_reset(TPM_RH_LOCKOUT, &[]));
        assert_eq!(response_code(&response), RC_SUCCESS);
        let reloaded = reload(runtime.state());
        assert_eq!(reloaded.persistent.failed_tries, 0);
        assert_eq!(
            reloaded.persistent.max_tries,
            runtime.state().persistent.max_tries
        );
        assert_eq!(
            reloaded.persistent.recovery_time,
            runtime.state().persistent.recovery_time
        );
        assert_eq!(
            reloaded.persistent.lockout_recovery,
            runtime.state().persistent.lockout_recovery
        );
    }

    #[test]
    fn an_unavailable_nv_refuses_the_command_without_touching_the_state() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        runtime
            .state
            .as_mut()
            .expect("state present")
            .persistent
            .failed_tries = 4;
        runtime.nv_available = false;
        let before = snapshot(&runtime);
        let response = exec(&mut runtime, &clock, &da_lock_reset(TPM_RH_LOCKOUT, &[]));
        assert_eq!(response_code(&response), RC_NV_UNAVAILABLE);
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn only_an_accepted_reset_commits_an_nv_update() {
        assert_eq!(commits_for(&da_lock_reset(TPM_RH_LOCKOUT, &[])), 1);
        assert_eq!(commits_for(&da_lock_reset(TPM_RH_OWNER, &[])), 0);
        assert_eq!(
            commits_for(&da_lock_reset(TPM_RH_LOCKOUT, b"wrong")),
            1,
            "the dictionary-attack logic records the disabled lockoutAuth in NV"
        );
    }

    #[test]
    fn a_failing_host_commit_fails_the_tpm() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        let bytes = da_lock_reset(TPM_RH_LOCKOUT, &[]);
        let input = crate::library::CommandInput::new(bytes.len() as u32, bytes);
        let response = crate::library::tpm2::process::process(
            &mut runtime,
            crate::library::tpm2::PlatformInputs::at_locality(0),
            &input,
            &clock,
            |_| Err(crate::library::constants::TPM_RC_FAILURE),
        )
        .expect("the command processes");
        assert_eq!(response, error_response(0x101));
        assert!(runtime.failure_mode);
    }

    #[test]
    fn prefixes_and_bit_flips_do_not_panic() {
        let clock = replay_clock();
        let valid = da_lock_reset(TPM_RH_LOCKOUT, &[]);
        for len in 0..=valid.len() {
            for index in 0..len {
                for flip in [0x01u8, 0x80, 0xff] {
                    let mut mutated = valid[..len].to_vec();
                    mutated[index] ^= flip;
                    let mut runtime = oracle_runtime(&clock);
                    let input = crate::library::CommandInput::new(mutated.len() as u32, mutated);
                    let _ = crate::library::tpm2::process::process(
                        &mut runtime,
                        crate::library::tpm2::PlatformInputs::at_locality(0),
                        &input,
                        &clock,
                        |_| Ok(()),
                    );
                }
            }
        }
    }
}
