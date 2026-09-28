// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/DA.c
// - libtpms/src/tpm2/DictionaryCommands.c
//
// Original upstream authors and copyright notices:
// Written by Ken Goldman
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corp. and others, 2016 - 2019
// (c) Copyright IBM Corp. and others, 2016 - 2021
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use super::with_persistent_rollback;
use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_NV_UNAVAILABLE, TPM_RC_SIZE};
use crate::library::tpm2::command::core::dispatcher::CommandFrame;
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::types::TpmResult;
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

    with_persistent_rollback(runtime, |persistent| {
        persistent.failed_tries = 0;
        Ok(())
    })?;
    Ok(CommandOutput::empty())
}

#[cfg(test)]
mod tests {
    use crate::library::cancel::CancellationToken;

    use crate::library::tpm2::command::core::test_support::{
        command, error_response, for_each_mutation, framed, prefix_bit_flips, response_code,
    };
    use crate::library::tpm2::command::hierarchy::test_support::{
        NV_OWNER_ATTRIBUTES, OWNER_INDEX, RC_LOCKOUT, RC_NV_UNAVAILABLE, RC_SUCCESS,
        TPM_CC_DA_LOCK_RESET, assert_nv_image_is_current, assert_unchanged, cap_lockout,
        cap_permanent_flags, commits_for, da_lock_reset, da_parameters, dictionary_attack_state,
        exec, expect, nv_define, nv_read, oracle_runtime, reboot, reload, replay_clock, shutdown,
        snapshot, startup, try_exec,
    };
    use crate::library::tpm2::hierarchy::{
        TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT, TPM_RH_NULL, TPM_RH_OWNER, TPM_RH_PLATFORM,
    };

    #[test]
    fn failure_counter_lifecycle_reference_match() {
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
    fn handle_parameter_error_reference_match() {
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
    fn disabled_lockout_auth_rejection() {
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
    fn orderly_state_preservation() {
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
    fn reset_counter_permanent_round_trip() {
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
    fn unavailable_nv_rejection_state_unchanged() {
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
    fn accepted_reset_only_nv_update_commit() {
        assert_eq!(commits_for(&da_lock_reset(TPM_RH_LOCKOUT, &[])), 1);
        assert_eq!(commits_for(&da_lock_reset(TPM_RH_OWNER, &[])), 0);
        assert_eq!(
            commits_for(&da_lock_reset(TPM_RH_LOCKOUT, b"wrong")),
            1,
            "the dictionary-attack logic records the disabled lockoutAuth in NV"
        );
    }

    #[test]
    fn host_commit_failure_mode() {
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
            CancellationToken::disabled(),
        )
        .expect("the command processes");
        assert_eq!(response, error_response(0x101));
        assert!(runtime.failure_mode);
    }

    #[test]
    fn prefix_and_bit_flip_panic_safety() {
        let clock = replay_clock();
        let valid = da_lock_reset(TPM_RH_LOCKOUT, &[]);
        for_each_mutation(
            "TPM2_DictionaryAttackLockReset",
            prefix_bit_flips(&valid, 0, 0, false),
            |bytes| {
                let _ = try_exec(&mut oracle_runtime(&clock), &clock, &bytes);
            },
        );
    }
}
