use crate::ffi_types::TpmResult;
use crate::library::constants::{
    TPM_RC_FAILURE, TPM_RC_INSUFFICIENT, TPM_RC_NV_UNAVAILABLE, TPM_RC_SIZE,
};

use super::super::super::marshal::BlobReader;
use super::super::super::runtime::Tpm2Runtime;
use super::super::dispatcher::CommandFrame;
use super::super::nv_common::{TPM_RC_1, TPM_RC_P};
use super::super::output::CommandOutput;
use super::super::transaction::{commit_persistent_state, with_rollback};

const RC_ALGORITHM_SET: TpmResult = TPM_RC_P + TPM_RC_1;

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let algorithm_set = parse_algorithm_set(frame.parameters)?;
    if !runtime.nv_available {
        return Err(TPM_RC_NV_UNAVAILABLE);
    }
    with_rollback(runtime, |runtime| {
        runtime
            .state
            .as_mut()
            .ok_or(TPM_RC_FAILURE)?
            .persistent
            .algorithm_set = algorithm_set;
        commit_persistent_state(runtime)
    })?;
    Ok(CommandOutput::empty())
}

fn parse_algorithm_set(parameters: &[u8]) -> Result<u32, TpmResult> {
    let mut reader = BlobReader::new(parameters);
    let algorithm_set = reader
        .read_u32()
        .map_err(|_| TPM_RC_INSUFFICIENT + RC_ALGORITHM_SET)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(algorithm_set)
}

#[cfg(test)]
mod tests {
    use super::super::harness::*;
    use crate::library::tpm2::command::registry::{
        CommandLifecycle, HandleKind, NvAccess, TPM_CC_SET_ALGORITHM_SET, find,
    };

    fn algorithm_set_property() -> Vec<u8> {
        get_capability(TPM_CAP_TPM_PROPERTIES, TPM_PT_ALGORITHM_SET, 1)
    }

    #[test]
    fn the_command_is_registered_with_the_reference_attributes() {
        let descriptor = find(TPM_CC_SET_ALGORITHM_SET).expect("the command is registered");
        assert_eq!(descriptor.attributes, 0x0240_013f);
        assert_eq!(
            descriptor.attributes,
            u32::from_be_bytes(
                vector("CCATTR_013F")[19..23]
                    .try_into()
                    .expect("four bytes")
            )
        );
        assert_eq!(descriptor.handles.len(), 1);
        assert!(matches!(descriptor.handles[0].kind, HandleKind::Platform));
        assert!(descriptor.handles[0].user_auth);
        assert_eq!(descriptor.decrypt_size, 0);
        assert_eq!(descriptor.encrypt_size, 0);
        assert!(descriptor.sessions_allowed);
        assert!(matches!(descriptor.nv_access, NvAccess::Neither));
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
        assert!(
            !descriptor.physical_presence,
            "the vendored table gives TPM2_SetAlgorithmSet no physical-presence attribute"
        );
        assert!(!descriptor.physical_presence_required);
    }

    #[test]
    fn the_command_needs_a_started_tpm() {
        let clock = replay_clock();
        let mut runtime = manufactured(&clock);
        expect(
            &mut runtime,
            &clock,
            "LIFECYCLE_SET_ALGORITHM_SET",
            &set_algorithm_set(TPM_RH_PLATFORM, 1, &[]),
        );
        assert_eq!(
            response_code(vector("LIFECYCLE_SET_ALGORITHM_SET")),
            RC_INITIALIZE
        );
    }

    #[test]
    fn the_property_follows_every_accepted_value() {
        let clock = replay_clock();
        let host = Host::at("READY");
        let mut runtime = ready(&clock);
        for (label, bytes) in [
            ("SAS_PROP_BASE", algorithm_set_property()),
            ("SAS_SET_ONE", set_algorithm_set(TPM_RH_PLATFORM, 1, &[])),
            ("SAS_PROP_AFTER_ONE", algorithm_set_property()),
            ("SAS_SET_ZERO", set_algorithm_set(TPM_RH_PLATFORM, 0, &[])),
            ("SAS_PROP_AFTER_ZERO", algorithm_set_property()),
            (
                "SAS_SET_MAX",
                set_algorithm_set(TPM_RH_PLATFORM, u32::MAX, &[]),
            ),
            ("SAS_PROP_AFTER_MAX", algorithm_set_property()),
            (
                "SAS_REPEATED",
                set_algorithm_set(TPM_RH_PLATFORM, u32::MAX, &[]),
            ),
            ("SAS_PROP_AFTER_REPEAT", algorithm_set_property()),
        ] {
            host.expect(&mut runtime, &clock, label, &bytes);
        }
        assert_eq!(capability_property(vector("SAS_PROP_BASE")), 0);
        assert_eq!(capability_property(vector("SAS_PROP_AFTER_ONE")), 1);
        assert_eq!(capability_property(vector("SAS_PROP_AFTER_ZERO")), 0);
        assert_eq!(capability_property(vector("SAS_PROP_AFTER_MAX")), u32::MAX);
        assert_eq!(
            capability_property(vector("SAS_PROP_AFTER_REPEAT")),
            u32::MAX
        );
        assert_eq!(runtime.state().persistent.algorithm_set, u32::MAX);
    }

    #[test]
    fn the_authorization_and_parsing_errors_match_the_reference() {
        let clock = replay_clock();
        let host = Host::at("READY");
        let mut runtime = restored("AFTER_ALGORITHM_SET", &clock);
        let before = snapshot(&runtime);
        for (label, bytes) in [
            ("SAS_BY_OWNER", set_algorithm_set(TPM_RH_OWNER, 2, &[])),
            ("SAS_BY_LOCKOUT", set_algorithm_set(TPM_RH_LOCKOUT, 2, &[])),
            ("SAS_BY_NULL", set_algorithm_set(TPM_RH_NULL, 2, &[])),
            (
                "SAS_WRONG_PASSWORD",
                set_algorithm_set(TPM_RH_PLATFORM, 2, b"wrong"),
            ),
            (
                "SAS_NO_SESSIONS",
                framed(
                    TPM_CC_SET_ALGORITHM_SET,
                    &[&TPM_RH_PLATFORM.to_be_bytes()[..], &2u32.to_be_bytes()[..]].concat(),
                    false,
                ),
            ),
            (
                "SAS_TRUNCATED_VALUE",
                command(
                    TPM_CC_SET_ALGORITHM_SET,
                    &[TPM_RH_PLATFORM],
                    &[&[]],
                    &2u32.to_be_bytes()[..3],
                ),
            ),
            (
                "SAS_MISSING_VALUE",
                command(TPM_CC_SET_ALGORITHM_SET, &[TPM_RH_PLATFORM], &[&[]], &[]),
            ),
            (
                "SAS_TRAILING",
                command(
                    TPM_CC_SET_ALGORITHM_SET,
                    &[TPM_RH_PLATFORM],
                    &[&[]],
                    &[&2u32.to_be_bytes()[..], &[0xee][..]].concat(),
                ),
            ),
            (
                "SAS_TRUNCATED_HANDLE",
                framed(
                    TPM_CC_SET_ALGORITHM_SET,
                    &TPM_RH_PLATFORM.to_be_bytes()[..2],
                    true,
                ),
            ),
        ] {
            host.expect(&mut runtime, &clock, label, &bytes);
        }
        assert_unchanged(&runtime, &before);
        host.expect(
            &mut runtime,
            &clock,
            "SAS_PROP_AFTER_FAILURES",
            &algorithm_set_property(),
        );
        assert_eq!(
            capability_property(vector("SAS_PROP_AFTER_FAILURES")),
            u32::MAX,
            "no failed request changed the stored value"
        );
        assert_matches_permall(&runtime, "AFTER_ALGORITHM_SET");

        for (label, code) in [
            ("SAS_BY_OWNER", RC_VALUE_H1),
            ("SAS_BY_LOCKOUT", RC_VALUE_H1),
            ("SAS_BY_NULL", RC_VALUE_H1),
            ("SAS_WRONG_PASSWORD", RC_SESSION1_BAD_AUTH),
            ("SAS_NO_SESSIONS", RC_AUTH_MISSING),
            ("SAS_TRUNCATED_VALUE", RC_INSUFFICIENT_P1),
            ("SAS_MISSING_VALUE", RC_INSUFFICIENT_P1),
            ("SAS_TRAILING", RC_SIZE),
            ("SAS_TRUNCATED_HANDLE", RC_INSUFFICIENT_H1),
        ] {
            assert_eq!(response_code(vector(label)), code, "{label}");
        }
    }

    #[test]
    fn the_stored_value_survives_a_restart() {
        let clock = replay_clock();
        let host = Host::at("AFTER_ALGORITHM_SET");
        let mut runtime = restored("AFTER_ALGORITHM_SET", &clock);
        host.expect(
            &mut runtime,
            &clock,
            "SHUTDOWN_FOR_ALGORITHM_SET",
            &shutdown(0),
        );
        let mut rebooted = host.reboot();
        host.expect(
            &mut rebooted,
            &clock,
            "STARTUP_FOR_ALGORITHM_SET",
            &startup(0),
        );
        host.expect(
            &mut rebooted,
            &clock,
            "SAS_PROP_AFTER_RESTART",
            &algorithm_set_property(),
        );
        assert_eq!(
            capability_property(vector("SAS_PROP_AFTER_RESTART")),
            u32::MAX
        );
        assert_durable_state(&rebooted, "AFTER_ALGORITHM_SET_RESTART");
    }

    #[test]
    fn an_unavailable_nv_leaves_the_stored_value_alone() {
        let clock = replay_clock();
        let mut runtime = ready(&clock);
        runtime.nv_available = false;
        let before = snapshot(&runtime);
        assert_eq!(
            response_code(&exec(
                &mut runtime,
                &clock,
                &set_algorithm_set(TPM_RH_PLATFORM, 7, &[])
            )),
            RC_NV_UNAVAILABLE
        );
        assert_unchanged(&runtime, &before);
        assert_eq!(
            response_code(&exec(
                &mut runtime,
                &clock,
                &command(TPM_CC_SET_ALGORITHM_SET, &[TPM_RH_PLATFORM], &[&[]], &[])
            )),
            RC_INSUFFICIENT_P1,
            "a malformed value is reported before the NV state is consulted"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn a_failed_commit_restores_the_previous_value() {
        use crate::library::tpm2::persistent::OwnedSecret;

        let clock = replay_clock();
        let mut runtime = ready(&clock);
        let before = snapshot(&runtime);
        runtime
            .state
            .as_mut()
            .expect("a decoded state")
            .persistent
            .owner_auth = OwnedSecret::from_vec(vec![0xaa; 4096]);
        assert_ne!(
            response_code(&exec(
                &mut runtime,
                &clock,
                &set_algorithm_set(TPM_RH_PLATFORM, 9, &[])
            )),
            RC_SUCCESS
        );
        assert_eq!(
            runtime.state().persistent.algorithm_set,
            before.algorithm_set
        );
    }

    #[test]
    fn malformed_requests_never_panic() {
        let clock = replay_clock();
        let valid = set_algorithm_set(TPM_RH_PLATFORM, 3, &[]);
        for len in 0..=valid.len() {
            for index in 0..len {
                for flip in [0x01u8, 0x80, 0xff] {
                    let mut mutated = valid[..len].to_vec();
                    mutated[index] ^= flip;
                    let mut runtime = ready(&clock);
                    let _ = exec(&mut runtime, &clock, &mutated);
                }
            }
        }
    }
}
