use crate::ffi_types::TpmResult;
use crate::library::constants::{
    TPM_RC_AUTH_FAIL, TPM_RC_FAILURE, TPM_RC_INSUFFICIENT, TPM_RC_NV_UNAVAILABLE, TPM_RC_SIZE,
    TPM_RC_VALUE,
};

use super::super::super::hierarchy::TPM_RH_LOCKOUT;
use super::super::super::marshal::BlobReader;
use super::super::super::runtime::Tpm2Runtime;
use super::super::dispatcher::CommandFrame;
use super::super::output::CommandOutput;
use super::{commit_persistent_state, with_rollback};

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

    with_rollback(runtime, |runtime| {
        runtime
            .state
            .as_mut()
            .ok_or(TPM_RC_FAILURE)?
            .persistent
            .disable_clear = disable;
        commit_persistent_state(runtime)
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
    use super::super::super::registry::{
        CommandLifecycle, HandleKind, NvAccess, TPM_CC_CLEAR_CONTROL, find,
    };
    use super::super::harness::*;
    use crate::library::tpm2::hierarchy::{
        TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT, TPM_RH_NULL, TPM_RH_OWNER, TPM_RH_PLATFORM,
        TPM_RH_PLATFORM_NV, TPM_RS_PW,
    };

    #[test]
    fn the_command_is_registered_with_the_upstream_attributes() {
        let descriptor = find(TPM_CC_CLEAR_CONTROL).expect("the command is registered");
        assert_eq!(descriptor.attributes, 0x0240_0127);
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
    fn the_authorization_handle_takes_only_lockout_and_platform() {
        let kind = find(TPM_CC_CLEAR_CONTROL).unwrap().handles[0].kind;
        for handle in [TPM_RH_LOCKOUT, TPM_RH_PLATFORM] {
            assert!(kind.accepts(handle), "handle {handle:#x}");
        }
        for handle in [
            TPM_RH_OWNER,
            TPM_RH_ENDORSEMENT,
            TPM_RH_NULL,
            TPM_RH_PLATFORM_NV,
            TPM_RS_PW,
            0,
            23,
            0x0100_0000,
            0x8000_0000,
            u32::MAX,
        ] {
            assert!(!kind.accepts(handle), "handle {handle:#x}");
        }
    }

    #[test]
    fn the_reported_command_attributes_match_the_reference() {
        replay(&[("CCATTR_0127", cap_command_attributes(TPM_CC_CLEAR_CONTROL))]);
    }

    #[test]
    fn the_disable_clear_lifecycle_matches_the_reference() {
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
    fn the_handle_and_parameter_errors_match_the_reference() {
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
    fn lockout_authorization_may_only_set_disable_clear() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        let response = exec(&mut runtime, &clock, &clear_control(TPM_RH_LOCKOUT, 0, &[]));
        assert_eq!(response_code(&response), RC_AUTH_FAIL);
        assert!(!runtime.state().persistent.disable_clear);
    }

    #[test]
    fn the_command_never_clears_the_orderly_state() {
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
    fn disable_clear_survives_a_permanent_state_round_trip() {
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
    fn an_unavailable_nv_refuses_the_command_without_touching_the_state() {
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
    fn every_accepted_request_commits_exactly_one_nv_update() {
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
    fn malformed_input_never_panics() {
        let clock = replay_clock();
        let valid = clear_control(TPM_RH_PLATFORM, 1, &[]);
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
