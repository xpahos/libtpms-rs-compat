use crate::ffi::types::TpmResult;
use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_NV_UNAVAILABLE, TPM_RC_SIZE};
use crate::library::tpm2::capability::commands::MAX_CAP_CC;
use crate::library::tpm2::command::core::dispatcher::CommandFrame;
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::command::core::registry::find;
use crate::library::tpm2::command::core::response_code::{TPM_RC_1, TPM_RC_2, TPM_RC_P};
use crate::library::tpm2::command::core::transaction::{commit_persistent_state, with_rollback};
use crate::library::tpm2::command::{command_bitmap_index, upstream_implements};
use crate::library::tpm2::nv::command_bitmap_image;
use crate::library::tpm2::persistent::OwnedCommandBitmap;
use crate::library::tpm2::pp_list::PP_LIST_SIZE;
use crate::library::tpm2::profile::command_enabled;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::template::TemplateReader;

const RC_SET_LIST: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_CLEAR_LIST: TpmResult = TPM_RC_P + TPM_RC_2;

struct Parameters {
    set_list: Vec<u32>,
    clear_list: Vec<u32>,
}

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let parameters = parse_parameters(frame.parameters)?;
    if !runtime.nv_available {
        return Err(TPM_RC_NV_UNAVAILABLE);
    }

    let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
    let profile_commands = state.profile.commands.clone();
    let mut bitmap = command_bitmap_image(&state.persistent.pp_list, PP_LIST_SIZE)?;
    for &code in &parameters.set_list {
        set_command(&mut bitmap, &profile_commands, code);
    }
    for &code in &parameters.clear_list {
        clear_command(&mut bitmap, &profile_commands, code);
    }

    with_rollback(runtime, |runtime| {
        runtime
            .state
            .as_mut()
            .ok_or(TPM_RC_FAILURE)?
            .persistent
            .pp_list = OwnedCommandBitmap {
            compressed: false,
            bytes: bitmap,
        };
        commit_persistent_state(runtime)
    })?;
    Ok(CommandOutput::empty())
}

fn controllable(profile_commands: &[u8], code: u32) -> Option<usize> {
    if !upstream_implements(code) || !command_enabled(profile_commands, code) {
        return None;
    }
    command_bitmap_index(code)
}

fn set_command(bitmap: &mut [u8], profile_commands: &[u8], code: u32) {
    let Some(index) = controllable(profile_commands, code) else {
        return;
    };
    if find(code).is_some_and(|descriptor| descriptor.physical_presence) {
        bitmap[index / 8] |= 1 << (index % 8);
    }
}

fn clear_command(bitmap: &mut [u8], profile_commands: &[u8], code: u32) {
    let Some(index) = controllable(profile_commands, code) else {
        return;
    };
    if find(code).is_some_and(|descriptor| descriptor.physical_presence_required) {
        return;
    }
    bitmap[index / 8] &= !(1 << (index % 8));
}

fn parse_parameters(parameters: &[u8]) -> Result<Parameters, TpmResult> {
    let mut reader = TemplateReader::new(parameters);
    let set_list = parse_command_list(&mut reader, RC_SET_LIST)?;
    let clear_list = parse_command_list(&mut reader, RC_CLEAR_LIST)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(Parameters {
        set_list,
        clear_list,
    })
}

fn parse_command_list(
    reader: &mut TemplateReader<'_>,
    error_index: TpmResult,
) -> Result<Vec<u32>, TpmResult> {
    let count = reader.u32().map_err(|code| code + error_index)?;
    if count > MAX_CAP_CC as u32 {
        return Err(TPM_RC_SIZE + error_index);
    }
    let mut codes = Vec::with_capacity(count as usize);
    for _ in 0..count {
        codes.push(reader.u32().map_err(|code| code + error_index)?);
    }
    Ok(codes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::command::core::registry::{
        CommandLifecycle, HandleKind, NvAccess, implemented,
    };
    use crate::library::tpm2::command::core::test_support::{command, framed, response_code};
    use crate::library::tpm2::command::platform::test_support::{
        Host, RC_AUTH_MISSING, RC_INITIALIZE, RC_INSUFFICIENT_H1, RC_INSUFFICIENT_P1,
        RC_INSUFFICIENT_P2, RC_NV_UNAVAILABLE, RC_SESSION1_BAD_AUTH, RC_SESSION1_PP, RC_SIZE,
        RC_SIZE_P1, RC_SUCCESS, RC_VALUE_H1, TPM_CC_ACT_SET_TIMEOUT, TPM_CC_CLEAR_CONTROL,
        TPM_CC_CLOCK_RATE_ADJUST, TPM_CC_CLOCK_SET, TPM_CC_CREATE_PRIMARY,
        TPM_CC_HIERARCHY_CONTROL, TPM_CC_PP_COMMANDS, TPM_CC_SET_ALGORITHM_SET, TPM_RH_ENDORSEMENT,
        TPM_RH_LOCKOUT, TPM_RH_OWNER, TPM_RH_PLATFORM, assert_durable_state,
        assert_matches_permall, assert_unchanged, cap_pp_commands, capability_codes, clear_control,
        command_list, exec, expect, hierarchy_control, manufactured, pp_commands, ready,
        replay_clock, restored, shutdown, snapshot, startup,
    };
    use crate::library::tpm2::golden_responses::platform_state::vector;
    const TPM_CC_CHANGE_EPS: u32 = 0x0000_0124;
    const TPM_CC_ACTIVATE_CREDENTIAL: u32 = 0x0000_0147;
    const TPM_CC_FIELD_UPGRADE_START: u32 = 0x0000_012f;

    fn listed(runtime: &Tpm2Runtime) -> Vec<u32> {
        implemented()
            .map(|descriptor| descriptor.code)
            .filter(|&code| {
                crate::library::tpm2::pp_list::physical_presence_is_required(runtime, code)
            })
            .collect()
    }

    #[test]
    fn the_command_is_registered_with_the_reference_attributes() {
        let descriptor = find(TPM_CC_PP_COMMANDS).expect("the command is registered");
        assert_eq!(descriptor.attributes, 0x0240_012d);
        assert_eq!(
            descriptor.attributes,
            u32::from_be_bytes(
                vector("CCATTR_012D")[19..23]
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
            "the vendored table gives TPM2_PP_Commands PP_REQUIRED, not PP_COMMAND"
        );
        assert!(descriptor.physical_presence_required);
    }

    #[test]
    fn only_pp_commands_carries_the_required_attribute() {
        let required: Vec<u32> = implemented()
            .filter(|descriptor| descriptor.physical_presence_required)
            .map(|descriptor| descriptor.code)
            .collect();
        assert_eq!(required, [TPM_CC_PP_COMMANDS]);
    }

    #[test]
    fn every_command_the_reference_allows_in_the_list_is_registered() {
        const PP_COMMANDS: [u32; 19] = [
            0x0000_011f,
            0x0000_0120,
            0x0000_0121,
            0x0000_0122,
            0x0000_0124,
            0x0000_0125,
            0x0000_0126,
            0x0000_0127,
            0x0000_0128,
            0x0000_0129,
            0x0000_012a,
            0x0000_012b,
            0x0000_012c,
            0x0000_012e,
            0x0000_0130,
            0x0000_0131,
            0x0000_0132,
            0x0000_0140,
            0x0000_0191,
        ];
        let registered: Vec<u32> = implemented()
            .filter(|descriptor| descriptor.physical_presence)
            .map(|descriptor| descriptor.code)
            .collect();
        assert_eq!(registered, PP_COMMANDS);
        for code in PP_COMMANDS {
            assert!(upstream_implements(code), "code {code:#x}");
        }
    }

    #[test]
    fn the_command_needs_a_started_tpm() {
        let clock = replay_clock();
        let mut runtime = manufactured(&clock);
        expect(
            &mut runtime,
            &clock,
            "LIFECYCLE_PP_COMMANDS",
            &pp_commands(TPM_RH_PLATFORM, &[TPM_CC_CLEAR_CONTROL], &[], &[]),
        );
        assert_eq!(
            response_code(vector("LIFECYCLE_PP_COMMANDS")),
            RC_INITIALIZE
        );
    }

    #[test]
    fn the_bitmap_mutations_replay_the_reference_section() {
        let clock = replay_clock();
        let host = Host::at("READY");
        let mut runtime = ready(&clock);

        host.expect(
            &mut runtime,
            &clock,
            "PPC_CAP_BASE",
            &cap_pp_commands(0x0000_011f, 64),
        );
        assert_eq!(
            capability_codes(vector("PPC_CAP_BASE")),
            [TPM_CC_PP_COMMANDS],
            "manufacturing installs the PP_REQUIRED command only"
        );
        host.expect(
            &mut runtime,
            &clock,
            "PPC_WITHOUT_PP",
            &pp_commands(TPM_RH_PLATFORM, &[TPM_CC_CLEAR_CONTROL], &[], &[]),
        );
        assert_eq!(response_code(vector("PPC_WITHOUT_PP")), RC_SESSION1_PP);

        host.set_physical_presence(true);
        host.expect(
            &mut runtime,
            &clock,
            "PPC_SET_CLEAR_CONTROL",
            &pp_commands(TPM_RH_PLATFORM, &[TPM_CC_CLEAR_CONTROL], &[], &[]),
        );
        host.expect(
            &mut runtime,
            &clock,
            "PPC_CAP_AFTER_SET",
            &cap_pp_commands(0x0000_011f, 64),
        );
        assert_eq!(
            capability_codes(vector("PPC_CAP_AFTER_SET")),
            [TPM_CC_CLEAR_CONTROL, TPM_CC_PP_COMMANDS]
        );

        host.set_physical_presence(false);
        host.expect(
            &mut runtime,
            &clock,
            "PPC_CLEAR_CONTROL_NEEDS_PP",
            &clear_control(TPM_RH_PLATFORM, 0),
        );
        assert_eq!(
            response_code(vector("PPC_CLEAR_CONTROL_NEEDS_PP")),
            RC_SESSION1_PP,
            "the new bitmap entry gates the dispatch of TPM2_ClearControl"
        );
        host.set_physical_presence(true);
        host.expect(
            &mut runtime,
            &clock,
            "PPC_CLEAR_CONTROL_WITH_PP",
            &clear_control(TPM_RH_PLATFORM, 0),
        );

        host.expect(
            &mut runtime,
            &clock,
            "PPC_CLEAR_CLEAR_CONTROL",
            &pp_commands(TPM_RH_PLATFORM, &[], &[TPM_CC_CLEAR_CONTROL], &[]),
        );
        host.expect(
            &mut runtime,
            &clock,
            "PPC_CAP_AFTER_CLEAR",
            &cap_pp_commands(0x0000_011f, 64),
        );
        host.set_physical_presence(false);
        host.expect(
            &mut runtime,
            &clock,
            "PPC_CLEAR_CONTROL_AFTER_CLEAR",
            &clear_control(TPM_RH_PLATFORM, 0),
        );
        assert_eq!(
            response_code(vector("PPC_CLEAR_CONTROL_AFTER_CLEAR")),
            RC_SUCCESS
        );

        host.set_physical_presence(true);
        host.expect(
            &mut runtime,
            &clock,
            "PPC_SET_AND_CLEAR_SAME",
            &pp_commands(
                TPM_RH_PLATFORM,
                &[TPM_CC_HIERARCHY_CONTROL],
                &[TPM_CC_HIERARCHY_CONTROL],
                &[],
            ),
        );
        host.expect(
            &mut runtime,
            &clock,
            "PPC_CAP_AFTER_SAME",
            &cap_pp_commands(0x0000_011f, 64),
        );
        assert_eq!(
            capability_codes(vector("PPC_CAP_AFTER_SAME")),
            [TPM_CC_PP_COMMANDS],
            "the clear list runs after the set list"
        );

        host.expect(
            &mut runtime,
            &clock,
            "PPC_DUPLICATES",
            &pp_commands(
                TPM_RH_PLATFORM,
                &[
                    TPM_CC_HIERARCHY_CONTROL,
                    TPM_CC_HIERARCHY_CONTROL,
                    TPM_CC_CLOCK_SET,
                ],
                &[],
                &[],
            ),
        );
        host.expect(
            &mut runtime,
            &clock,
            "PPC_CAP_AFTER_DUPLICATES",
            &cap_pp_commands(0x0000_011f, 64),
        );
        assert_eq!(
            capability_codes(vector("PPC_CAP_AFTER_DUPLICATES")),
            [
                TPM_CC_HIERARCHY_CONTROL,
                TPM_CC_CLOCK_SET,
                TPM_CC_PP_COMMANDS
            ]
        );

        host.expect(
            &mut runtime,
            &clock,
            "PPC_NOT_A_PP_COMMAND",
            &pp_commands(
                TPM_RH_PLATFORM,
                &[TPM_CC_SET_ALGORITHM_SET, TPM_CC_ACTIVATE_CREDENTIAL],
                &[],
                &[],
            ),
        );
        host.expect(
            &mut runtime,
            &clock,
            "PPC_UNIMPLEMENTED_COMMAND",
            &pp_commands(
                TPM_RH_PLATFORM,
                &[TPM_CC_ACT_SET_TIMEOUT, TPM_CC_FIELD_UPGRADE_START],
                &[],
                &[],
            ),
        );
        host.expect(
            &mut runtime,
            &clock,
            "PPC_OUT_OF_RANGE_COMMAND",
            &pp_commands(TPM_RH_PLATFORM, &[0x2000_0000, 0x0000_0000], &[], &[]),
        );
        host.expect(
            &mut runtime,
            &clock,
            "PPC_CAP_AFTER_IGNORED",
            &cap_pp_commands(0x0000_011f, 64),
        );
        assert_eq!(
            capability_codes(vector("PPC_CAP_AFTER_IGNORED")),
            capability_codes(vector("PPC_CAP_AFTER_DUPLICATES")),
            "codes the reference cannot control leave the bitmap alone"
        );

        host.expect(
            &mut runtime,
            &clock,
            "PPC_CLEAR_SELF",
            &pp_commands(TPM_RH_PLATFORM, &[], &[TPM_CC_PP_COMMANDS], &[]),
        );
        host.expect(
            &mut runtime,
            &clock,
            "PPC_CAP_AFTER_CLEAR_SELF",
            &cap_pp_commands(0x0000_011f, 64),
        );
        assert!(
            capability_codes(vector("PPC_CAP_AFTER_CLEAR_SELF")).contains(&TPM_CC_PP_COMMANDS),
            "TPM2_PP_Commands cannot drop its own physical-presence requirement"
        );

        host.expect(
            &mut runtime,
            &clock,
            "PPC_EMPTY_LISTS",
            &pp_commands(TPM_RH_PLATFORM, &[], &[], &[]),
        );
        host.expect(
            &mut runtime,
            &clock,
            "PPC_CLEAR_EVERYTHING",
            &pp_commands(
                TPM_RH_PLATFORM,
                &[],
                &[
                    TPM_CC_HIERARCHY_CONTROL,
                    TPM_CC_CLOCK_SET,
                    TPM_CC_CLEAR_CONTROL,
                    TPM_CC_PP_COMMANDS,
                ],
                &[],
            ),
        );
        host.expect(
            &mut runtime,
            &clock,
            "PPC_CAP_AFTER_CLEAR_EVERYTHING",
            &cap_pp_commands(0x0000_011f, 64),
        );
        assert_eq!(
            capability_codes(vector("PPC_CAP_AFTER_CLEAR_EVERYTHING")),
            [TPM_CC_PP_COMMANDS]
        );

        host.expect(
            &mut runtime,
            &clock,
            "PPC_SET_MANY",
            &pp_commands(
                TPM_RH_PLATFORM,
                &[
                    TPM_CC_HIERARCHY_CONTROL,
                    TPM_CC_CLOCK_SET,
                    TPM_CC_CLOCK_RATE_ADJUST,
                    TPM_CC_CLEAR_CONTROL,
                    TPM_CC_CREATE_PRIMARY,
                ],
                &[],
                &[],
            ),
        );
        host.expect(
            &mut runtime,
            &clock,
            "PPC_CAP_AFTER_SET_MANY",
            &cap_pp_commands(0x0000_011f, 64),
        );
        host.expect(
            &mut runtime,
            &clock,
            "PPC_CAP_PAGE_ONE",
            &cap_pp_commands(0x0000_011f, 2),
        );
        assert_eq!(
            vector("PPC_CAP_PAGE_ONE")[10],
            1,
            "the page is not the last"
        );
        host.expect(
            &mut runtime,
            &clock,
            "PPC_CAP_FROM_MIDDLE",
            &cap_pp_commands(TPM_CC_CLOCK_SET, 64),
        );
        assert_eq!(
            listed(&runtime),
            capability_codes(vector("PPC_CAP_AFTER_SET_MANY"))
        );
        assert_matches_permall(&runtime, "AFTER_PP_COMMANDS");
    }

    #[test]
    fn the_input_and_authorization_errors_match_the_reference() {
        let clock = replay_clock();
        let host = Host::at("AFTER_PP_COMMANDS");
        host.set_physical_presence(true);
        let mut runtime = restored("AFTER_PP_COMMANDS", &clock);
        let before = snapshot(&runtime);
        for (label, bytes) in [
            (
                "PPC_COUNT_TOO_LARGE",
                command(
                    TPM_CC_PP_COMMANDS,
                    &[TPM_RH_PLATFORM],
                    &[&[]],
                    &[&255u32.to_be_bytes()[..], &[0x00; 4][..], &[0x00; 4][..]].concat(),
                ),
            ),
            (
                "PPC_COUNT_BEYOND_INPUT",
                command(
                    TPM_CC_PP_COMMANDS,
                    &[TPM_RH_PLATFORM],
                    &[&[]],
                    &[
                        &4u32.to_be_bytes()[..],
                        &TPM_CC_HIERARCHY_CONTROL.to_be_bytes()[..],
                        &0u32.to_be_bytes()[..],
                    ]
                    .concat(),
                ),
            ),
            (
                "PPC_TRUNCATED_SET_COUNT",
                command(
                    TPM_CC_PP_COMMANDS,
                    &[TPM_RH_PLATFORM],
                    &[&[]],
                    &[0x00, 0x00, 0x00],
                ),
            ),
            (
                "PPC_MISSING_CLEAR_LIST",
                command(
                    TPM_CC_PP_COMMANDS,
                    &[TPM_RH_PLATFORM],
                    &[&[]],
                    &command_list(&[TPM_CC_HIERARCHY_CONTROL]),
                ),
            ),
            (
                "PPC_TRAILING",
                command(
                    TPM_CC_PP_COMMANDS,
                    &[TPM_RH_PLATFORM],
                    &[&[]],
                    &[&command_list(&[])[..], &command_list(&[])[..], &[0xee][..]].concat(),
                ),
            ),
            ("PPC_BY_OWNER", pp_commands(TPM_RH_OWNER, &[], &[], &[])),
            ("PPC_BY_LOCKOUT", pp_commands(TPM_RH_LOCKOUT, &[], &[], &[])),
            (
                "PPC_WRONG_PASSWORD",
                pp_commands(TPM_RH_PLATFORM, &[], &[], b"wrong"),
            ),
            (
                "PPC_NO_SESSIONS",
                framed(
                    TPM_CC_PP_COMMANDS,
                    &[
                        &TPM_RH_PLATFORM.to_be_bytes()[..],
                        &command_list(&[])[..],
                        &command_list(&[])[..],
                    ]
                    .concat(),
                    false,
                ),
            ),
            (
                "PPC_TRUNCATED_HANDLE",
                framed(
                    TPM_CC_PP_COMMANDS,
                    &TPM_RH_PLATFORM.to_be_bytes()[..1],
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
            "PPC_CAP_AFTER_FAILURES",
            &cap_pp_commands(0x0000_011f, 64),
        );

        for (label, code) in [
            ("PPC_COUNT_TOO_LARGE", RC_SIZE_P1),
            ("PPC_COUNT_BEYOND_INPUT", RC_INSUFFICIENT_P1),
            ("PPC_TRUNCATED_SET_COUNT", RC_INSUFFICIENT_P1),
            ("PPC_MISSING_CLEAR_LIST", RC_INSUFFICIENT_P2),
            ("PPC_TRAILING", RC_SIZE),
            ("PPC_BY_OWNER", RC_VALUE_H1),
            ("PPC_BY_LOCKOUT", RC_VALUE_H1),
            ("PPC_WRONG_PASSWORD", RC_SESSION1_BAD_AUTH),
            ("PPC_NO_SESSIONS", RC_AUTH_MISSING),
            ("PPC_TRUNCATED_HANDLE", RC_INSUFFICIENT_H1),
        ] {
            assert_eq!(response_code(vector(label)), code, "{label}");
        }
    }

    #[test]
    fn the_bitmap_survives_a_restart_and_still_gates_dispatch() {
        let clock = replay_clock();
        let host = Host::at("AFTER_PP_COMMANDS");
        host.set_physical_presence(true);
        let mut runtime = restored("AFTER_PP_COMMANDS", &clock);
        host.expect(&mut runtime, &clock, "SHUTDOWN_FOR_PP", &shutdown(0));
        let mut rebooted = host.reboot();
        host.expect(&mut rebooted, &clock, "STARTUP_FOR_PP", &startup(0));
        host.expect(
            &mut rebooted,
            &clock,
            "PPC_CAP_AFTER_RESTART",
            &cap_pp_commands(0x0000_011f, 64),
        );
        assert_eq!(
            capability_codes(vector("PPC_CAP_AFTER_RESTART")),
            capability_codes(vector("PPC_CAP_AFTER_SET_MANY"))
        );

        host.set_physical_presence(false);
        host.expect(
            &mut rebooted,
            &clock,
            "PPC_HIERARCHY_CONTROL_AFTER_RESTART_WITHOUT_PP",
            &hierarchy_control(TPM_RH_PLATFORM, TPM_RH_ENDORSEMENT, 1),
        );
        assert_eq!(
            response_code(vector("PPC_HIERARCHY_CONTROL_AFTER_RESTART_WITHOUT_PP")),
            RC_SESSION1_PP
        );
        host.set_physical_presence(true);
        host.expect(
            &mut rebooted,
            &clock,
            "PPC_HIERARCHY_CONTROL_AFTER_RESTART",
            &hierarchy_control(TPM_RH_PLATFORM, TPM_RH_ENDORSEMENT, 1),
        );
        assert_eq!(
            response_code(vector("PPC_HIERARCHY_CONTROL_AFTER_RESTART")),
            RC_SUCCESS
        );
        assert_durable_state(&rebooted, "AFTER_PP_RESTART");
    }

    #[test]
    fn an_unavailable_nv_leaves_the_bitmap_alone() {
        let clock = replay_clock();
        let host = Host::at("READY");
        host.set_physical_presence(true);
        let mut runtime = ready(&clock);
        runtime.nv_available = false;
        let before = snapshot(&runtime);
        assert_eq!(
            response_code(&host.run(
                &mut runtime,
                &clock,
                &pp_commands(TPM_RH_PLATFORM, &[TPM_CC_CLEAR_CONTROL], &[], &[])
            )),
            RC_NV_UNAVAILABLE
        );
        assert_unchanged(&runtime, &before);
        assert_eq!(
            response_code(&host.run(
                &mut runtime,
                &clock,
                &command(TPM_CC_PP_COMMANDS, &[TPM_RH_PLATFORM], &[&[]], &[0x00; 3])
            )),
            RC_INSUFFICIENT_P1,
            "a malformed list is reported before the NV state is consulted"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn the_physical_presence_gate_is_checked_before_the_lists_are_parsed() {
        let clock = replay_clock();
        let host = Host::at("READY");
        let mut runtime = ready(&clock);
        runtime.nv_available = false;
        let before = snapshot(&runtime);
        assert_eq!(
            response_code(&host.run(
                &mut runtime,
                &clock,
                &command(TPM_CC_PP_COMMANDS, &[TPM_RH_PLATFORM], &[&[]], &[0x00; 3])
            )),
            RC_SESSION1_PP,
            "authorization runs before the parameter area is unmarshaled"
        );
        assert_eq!(
            response_code(&host.run(
                &mut runtime,
                &clock,
                &pp_commands(TPM_RH_OWNER, &[], &[], &[])
            )),
            RC_VALUE_H1,
            "the handle interface is resolved before the physical-presence gate"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn a_command_the_profile_disables_is_never_added_to_the_bitmap() {
        let clock = replay_clock();
        let host = Host::at("READY");
        host.set_physical_presence(true);
        let mut runtime = ready(&clock);
        runtime
            .state
            .as_mut()
            .expect("a decoded state")
            .profile
            .commands = b"0x11f-0x126".to_vec();
        assert_eq!(
            response_code(&host.run(
                &mut runtime,
                &clock,
                &pp_commands(
                    TPM_RH_PLATFORM,
                    &[TPM_CC_CHANGE_EPS, TPM_CC_CLEAR_CONTROL],
                    &[],
                    &[]
                )
            )),
            RC_SUCCESS
        );
        assert!(listed(&runtime).contains(&TPM_CC_CHANGE_EPS));
        assert!(
            !listed(&runtime).contains(&TPM_CC_CLEAR_CONTROL),
            "0x127 is outside the profile's command range"
        );
    }

    #[test]
    fn prefixes_and_bit_flips_do_not_panic() {
        let clock = replay_clock();
        let valid = pp_commands(
            TPM_RH_PLATFORM,
            &[TPM_CC_CLEAR_CONTROL],
            &[TPM_CC_HIERARCHY_CONTROL],
            &[],
        );
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
