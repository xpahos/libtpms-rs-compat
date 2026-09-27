use super::with_persistent_rollback;
use crate::library::constants::{
    TPM_RC_AUTH_FAIL, TPM_RC_FAILURE, TPM_RC_INSUFFICIENT, TPM_RC_NV_UNAVAILABLE, TPM_RC_SIZE,
    TPM_RC_VALUE,
};
use crate::library::tpm2::command::core::dispatcher::CommandFrame;
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::hierarchy::TPM_RH_LOCKOUT;
use crate::library::tpm2::marshal::BlobReader;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::types::TpmResult;

const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;
const RC_DISABLE: TpmResult = TPM_RC_P + TPM_RC_1;

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let auth_handle = frame.handles.first().copied().ok_or(TPM_RC_FAILURE)?;
    let disable = parse_parameters(frame.parameters)?;

    if !runtime.nv_available {
        return Err(TPM_RC_NV_UNAVAILABLE);
    }
    if auth_handle == TPM_RH_LOCKOUT && !disable {
        return Err(TPM_RC_AUTH_FAIL);
    }

    with_persistent_rollback(runtime, |persistent| {
        persistent.disable_clear = disable;
        Ok(())
    })?;
    Ok(CommandOutput::empty())
}

fn parse_parameters(parameters: &[u8]) -> Result<bool, TpmResult> {
    let mut reader = BlobReader::new(parameters);
    let disable = match reader
        .read_u8()
        .map_err(|_| TPM_RC_INSUFFICIENT + RC_DISABLE)?
    {
        0 => false,
        1 => true,
        _ => return Err(TPM_RC_VALUE + RC_DISABLE),
    };
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(disable)
}

#[cfg(test)]
mod tests {

    use crate::library::tpm2::command::core::registry::TPM_CC_CLEAR_CONTROL;
    use crate::library::tpm2::command::core::test_support::{
        command, for_each_mutation, framed, prefix_bit_flips, response_code,
    };
    use crate::library::tpm2::command::hierarchy::test_support::{
        RC_AUTH_FAIL, RC_NV_UNAVAILABLE, assert_nv_image_is_current, assert_unchanged,
        cap_permanent_flags, clear, clear_control, commits_for, exec, expect, oracle_runtime,
        reboot, reload, replay_clock, shutdown, snapshot, startup, try_exec,
    };
    use crate::library::tpm2::hierarchy::{
        TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT, TPM_RH_NULL, TPM_RH_OWNER, TPM_RH_PLATFORM,
    };

    #[test]
    fn disable_clear_lifecycle_reference_match() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        assert!(!runtime.state().persistent.disable_clear);
        for (label, bytes) in [
            ("CTL_PERMANENT_BEFORE", cap_permanent_flags()),
            (
                "CTL_DISABLE_BY_PLATFORM",
                clear_control(TPM_RH_PLATFORM, 1, &[]),
            ),
            ("CTL_PERMANENT_AFTER_DISABLE", cap_permanent_flags()),
        ] {
            expect(&mut runtime, &clock, label, &bytes);
        }
        assert!(runtime.state().persistent.disable_clear);
        assert_nv_image_is_current(&runtime);

        for (label, bytes) in [
            ("CTL_CLEAR_WHILE_DISABLED", clear(TPM_RH_PLATFORM, &[])),
            (
                "CTL_CLEAR_BY_LOCKOUT_WHILE_DISABLED",
                clear(TPM_RH_LOCKOUT, &[]),
            ),
            ("CTL_PERMANENT_AFTER_REFUSED_CLEAR", cap_permanent_flags()),
            (
                "CTL_ENABLE_BY_LOCKOUT",
                clear_control(TPM_RH_LOCKOUT, 0, &[]),
            ),
        ] {
            expect(&mut runtime, &clock, label, &bytes);
        }
        assert!(
            runtime.state().persistent.disable_clear,
            "lockoutAuth may not clear disableClear"
        );

        for (label, bytes) in [
            (
                "CTL_ENABLE_BY_PLATFORM",
                clear_control(TPM_RH_PLATFORM, 0, &[]),
            ),
            ("CTL_PERMANENT_AFTER_ENABLE", cap_permanent_flags()),
            (
                "CTL_DISABLE_BY_LOCKOUT",
                clear_control(TPM_RH_LOCKOUT, 1, &[]),
            ),
            ("CTL_PERMANENT_AFTER_LOCKOUT_DISABLE", cap_permanent_flags()),
            (
                "CTL_REDISABLE_BY_PLATFORM",
                clear_control(TPM_RH_PLATFORM, 1, &[]),
            ),
            (
                "CTL_ENABLE_BY_PLATFORM_AGAIN",
                clear_control(TPM_RH_PLATFORM, 0, &[]),
            ),
            ("CTL_PERMANENT_FINAL", cap_permanent_flags()),
        ] {
            expect(&mut runtime, &clock, label, &bytes);
        }
        assert!(!runtime.state().persistent.disable_clear);
    }

    #[test]
    fn handle_and_parameter_error_reference_match() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        let before = snapshot(&runtime);
        let mut trailing = vec![0x01u8, 0xee];
        for (label, bytes) in [
            ("CTL_BY_OWNER", clear_control(TPM_RH_OWNER, 1, &[])),
            (
                "CTL_BY_ENDORSEMENT",
                clear_control(TPM_RH_ENDORSEMENT, 1, &[]),
            ),
            ("CTL_BY_NULL", clear_control(TPM_RH_NULL, 1, &[])),
            (
                "CTL_NO_SESSIONS",
                framed(
                    TPM_CC_CLEAR_CONTROL,
                    &[&TPM_RH_PLATFORM.to_be_bytes()[..], &[0x01][..]].concat(),
                    false,
                ),
            ),
            (
                "CTL_TRUNCATED_DISABLE",
                command(TPM_CC_CLEAR_CONTROL, &[TPM_RH_PLATFORM], &[&[]], &[]),
            ),
            ("CTL_BAD_DISABLE_02", clear_control(TPM_RH_PLATFORM, 2, &[])),
            (
                "CTL_BAD_DISABLE_FF",
                clear_control(TPM_RH_PLATFORM, 0xff, &[]),
            ),
            (
                "CTL_TRAILING",
                command(
                    TPM_CC_CLEAR_CONTROL,
                    &[TPM_RH_PLATFORM],
                    &[&[]],
                    core::mem::take(&mut trailing).as_slice(),
                ),
            ),
            (
                "CTL_WRONG_PASSWORD",
                clear_control(TPM_RH_PLATFORM, 1, b"wrong"),
            ),
            (
                "CTL_TRUNCATED_HANDLE",
                framed(
                    TPM_CC_CLEAR_CONTROL,
                    &TPM_RH_PLATFORM.to_be_bytes()[..1],
                    true,
                ),
            ),
        ] {
            expect(&mut runtime, &clock, label, &bytes);
        }
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn lockout_authorization_disable_clear_set_only() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        let response = exec(&mut runtime, &clock, &clear_control(TPM_RH_LOCKOUT, 0, &[]));
        assert_eq!(response_code(&response), RC_AUTH_FAIL);
        assert!(!runtime.state().persistent.disable_clear);
    }

    #[test]
    fn orderly_state_preservation() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        exec(&mut runtime, &clock, &shutdown(1));
        expect(
            &mut runtime,
            &clock,
            "CTL_ORDERLY_DISABLE",
            &clear_control(TPM_RH_PLATFORM, 1, &[]),
        );
        assert!(crate::library::tpm2::orderly::is_orderly(
            runtime.state().persistent.orderly_state
        ));
        let mut rebooted = reboot(&runtime, &clock);
        expect(
            &mut rebooted,
            &clock,
            "CTL_ORDERLY_STARTUP_STATE",
            &startup(1),
        );
        assert!(
            rebooted.state().persistent.disable_clear,
            "disableClear survives the state-preserving reboot"
        );
    }

    #[test]
    fn disable_clear_permanent_state_round_trip() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        expect(
            &mut runtime,
            &clock,
            "CTL_DISABLE_BY_PLATFORM",
            &clear_control(TPM_RH_PLATFORM, 1, &[]),
        );
        assert!(reload(runtime.state()).persistent.disable_clear);
        expect(
            &mut runtime,
            &clock,
            "CTL_ENABLE_BY_PLATFORM",
            &clear_control(TPM_RH_PLATFORM, 0, &[]),
        );
        assert!(!reload(runtime.state()).persistent.disable_clear);
    }

    #[test]
    fn unavailable_nv_rejection_state_unchanged() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        runtime.nv_available = false;
        let before = snapshot(&runtime);
        let response = exec(
            &mut runtime,
            &clock,
            &clear_control(TPM_RH_PLATFORM, 1, &[]),
        );
        assert_eq!(response_code(&response), RC_NV_UNAVAILABLE);
        assert_unchanged(&runtime, &before);

        let response = exec(
            &mut runtime,
            &clock,
            &clear_control(TPM_RH_PLATFORM, 2, &[]),
        );
        assert_eq!(
            response_code(&response),
            0x1c4,
            "the parameter is unmarshalled before the NV check"
        );
    }

    #[test]
    fn accepted_request_single_nv_update_commit() {
        assert_eq!(commits_for(&clear_control(TPM_RH_PLATFORM, 1, &[])), 1);
        assert_eq!(
            commits_for(&clear_control(TPM_RH_PLATFORM, 0, &[])),
            1,
            "upstream always synchronizes disableClear"
        );
        assert_eq!(commits_for(&clear_control(TPM_RH_LOCKOUT, 0, &[])), 0);
        assert_eq!(commits_for(&clear_control(TPM_RH_OWNER, 1, &[])), 0);
    }

    #[test]
    fn prefix_and_bit_flip_panic_safety() {
        let clock = replay_clock();
        let valid = clear_control(TPM_RH_PLATFORM, 1, &[]);
        for_each_mutation(
            "TPM2_ClearControl",
            prefix_bit_flips(&valid, 0, 0, false),
            |bytes| {
                let _ = try_exec(&mut oracle_runtime(&clock), &clock, &bytes);
            },
        );
    }
}
