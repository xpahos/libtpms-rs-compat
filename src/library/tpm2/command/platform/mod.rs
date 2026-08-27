pub(super) mod algorithm_set;
pub(super) mod clock;
pub(super) mod pcr_auth_value;
pub(super) mod pp_commands;

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod tests {
    use super::test_support::{
        Host, RC_COMMAND_CODE, RC_SUCCESS, RC_VALUE_P2, TPM_CAP_ACT, TPM_CAP_COMMANDS,
        TPM_CAP_PP_COMMANDS, TPM_CC_ACT_SET_TIMEOUT, TPM_CC_CLOCK_RATE_ADJUST, TPM_CC_CLOCK_SET,
        TPM_CC_PCR_SET_AUTH_VALUE, TPM_CC_PP_COMMANDS, TPM_CC_READ_CLOCK, TPM_CC_SET_ALGORITHM_SET,
        TPM_RH_ACT_0, TPM_RH_PLATFORM, act_set_timeout, assert_unchanged, cap_pp_commands,
        capability_codes, expect, get_capability, manufactured, ready, replay_clock, restored,
        snapshot,
    };
    use crate::library::tpm2::capability::single::{LookupError, lookup};
    use crate::library::tpm2::command::core::registry::{TPM_CC_ECC_ENCRYPT, find};
    use crate::library::tpm2::command::core::test_support::{command, framed, response_code};
    use crate::library::tpm2::command::upstream_implements;
    use crate::library::tpm2::golden_responses::platform_state::vector;

    const TPM_RH_ACT_F: u32 = 0x4000_011f;

    #[test]
    fn the_reference_profile_compiles_act_set_timeout_out() {
        assert!(
            !upstream_implements(TPM_CC_ACT_SET_TIMEOUT),
            "the pinned profile sets CC_ACT_SetTimeout to CC_NO"
        );
        assert!(
            find(TPM_CC_ACT_SET_TIMEOUT).is_none(),
            "an unimplemented command must not be registered"
        );
        assert_eq!(
            u32::from_be_bytes(
                vector("CCATTR_0198")[19..23]
                    .try_into()
                    .expect("four bytes")
            ) & 0xffff,
            TPM_CC_ECC_ENCRYPT & 0xffff,
            "TPM_CAP_COMMANDS skips 0x0198 and reports TPM2_ECC_Encrypt instead"
        );
    }

    #[test]
    fn every_act_request_answers_the_reference_command_code_error() {
        let clock = replay_clock();
        let mut runtime = ready(&clock);
        let before = snapshot(&runtime);
        for (label, bytes) in [
            ("ACT_HANDLE_0", act_set_timeout(TPM_RH_ACT_0, 1000)),
            ("ACT_HANDLE_F", act_set_timeout(TPM_RH_ACT_F, 1000)),
            (
                "ACT_HANDLE_BELOW_RANGE",
                act_set_timeout(TPM_RH_ACT_0 - 1, 1000),
            ),
            (
                "ACT_HANDLE_ABOVE_RANGE",
                act_set_timeout(TPM_RH_ACT_F + 1, 1000),
            ),
            (
                "ACT_HANDLE_PLATFORM",
                act_set_timeout(TPM_RH_PLATFORM, 1000),
            ),
            ("ACT_TIMEOUT_MAX", act_set_timeout(TPM_RH_ACT_0, u32::MAX)),
            ("ACT_TIMEOUT_ZERO", act_set_timeout(TPM_RH_ACT_0, 0)),
            (
                "ACT_NO_SESSIONS",
                framed(
                    TPM_CC_ACT_SET_TIMEOUT,
                    &[&TPM_RH_ACT_0.to_be_bytes()[..], &1000u32.to_be_bytes()[..]].concat(),
                    false,
                ),
            ),
            (
                "ACT_MISSING_TIMEOUT",
                command(TPM_CC_ACT_SET_TIMEOUT, &[TPM_RH_ACT_0], &[&[]], &[]),
            ),
            (
                "ACT_TRAILING",
                command(
                    TPM_CC_ACT_SET_TIMEOUT,
                    &[TPM_RH_ACT_0],
                    &[&[]],
                    &[&1000u32.to_be_bytes()[..], &[0xee][..]].concat(),
                ),
            ),
            (
                "ACT_TRUNCATED_HANDLE",
                framed(
                    TPM_CC_ACT_SET_TIMEOUT,
                    &TPM_RH_ACT_0.to_be_bytes()[..2],
                    true,
                ),
            ),
        ] {
            expect(&mut runtime, &clock, label, &bytes);
            assert_eq!(response_code(vector(label)), RC_COMMAND_CODE, "{label}");
        }
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn an_act_request_before_startup_answers_the_same_error() {
        let clock = replay_clock();
        let mut runtime = manufactured(&clock);
        expect(
            &mut runtime,
            &clock,
            "LIFECYCLE_ACT_SET_TIMEOUT",
            &act_set_timeout(TPM_RH_ACT_0, 1000),
        );
        assert_eq!(
            response_code(vector("LIFECYCLE_ACT_SET_TIMEOUT")),
            RC_COMMAND_CODE,
            "the command code is resolved before the lifecycle gate"
        );
    }

    #[test]
    fn the_act_capability_reports_an_empty_list_for_every_act_handle() {
        let clock = replay_clock();
        let mut runtime = ready(&clock);
        for (label, bytes) in [
            (
                "ACT_CAP_BASE",
                get_capability(TPM_CAP_ACT, TPM_RH_ACT_0, 16),
            ),
            (
                "ACT_CAP_LAST",
                get_capability(TPM_CAP_ACT, TPM_RH_ACT_F, 16),
            ),
            (
                "ACT_CAP_ZERO_COUNT",
                get_capability(TPM_CAP_ACT, TPM_RH_ACT_0, 0),
            ),
        ] {
            expect(&mut runtime, &clock, label, &bytes);
            assert_eq!(response_code(vector(label)), RC_SUCCESS, "{label}");
            assert_eq!(capability_codes(vector(label)), [] as [u32; 0], "{label}");
        }
        for (label, bytes) in [
            (
                "ACT_CAP_BELOW_RANGE",
                get_capability(TPM_CAP_ACT, TPM_RH_ACT_0 - 1, 16),
            ),
            (
                "ACT_CAP_ABOVE_RANGE",
                get_capability(TPM_CAP_ACT, TPM_RH_ACT_F + 1, 16),
            ),
        ] {
            expect(&mut runtime, &clock, label, &bytes);
            assert_eq!(response_code(vector(label)), RC_VALUE_P2, "{label}");
        }
    }

    #[test]
    fn the_single_capability_lookup_still_rejects_the_act_selector() {
        let clock = replay_clock();
        let runtime = ready(&clock);
        assert_eq!(
            lookup(&runtime, TPM_CAP_ACT, TPM_RH_ACT_0),
            Err(LookupError::Capability),
            "the reference mixes no ACT data into a policy digest"
        );
    }

    #[test]
    fn the_physical_presence_capability_matches_the_single_lookup() {
        let clock = replay_clock();
        let host = Host::at("AFTER_PP_COMMANDS");
        let mut runtime = restored("AFTER_PP_COMMANDS", &clock);
        let listed =
            capability_codes(&host.run(&mut runtime, &clock, &cap_pp_commands(0x0000_011f, 64)));
        for code in 0x0000_011eu32..=0x0000_019f {
            let reported = lookup(&runtime, TPM_CAP_PP_COMMANDS, code)
                .expect("the capability lookup answers")
                != Vec::<u8>::new();
            assert_eq!(reported, listed.contains(&code), "code {code:#x}");
        }
    }

    #[test]
    fn the_group_reports_the_reference_command_attributes() {
        let clock = replay_clock();
        let mut runtime = ready(&clock);
        for (record, code) in [
            ("CCATTR_0128", TPM_CC_CLOCK_SET),
            ("CCATTR_012D", TPM_CC_PP_COMMANDS),
            ("CCATTR_0130", TPM_CC_CLOCK_RATE_ADJUST),
            ("CCATTR_013F", TPM_CC_SET_ALGORITHM_SET),
            ("CCATTR_0181", TPM_CC_READ_CLOCK),
            ("CCATTR_0183", TPM_CC_PCR_SET_AUTH_VALUE),
            ("CCATTR_0198", TPM_CC_ACT_SET_TIMEOUT),
        ] {
            expect(
                &mut runtime,
                &clock,
                record,
                &get_capability(TPM_CAP_COMMANDS, code, 1),
            );
        }
    }
}
