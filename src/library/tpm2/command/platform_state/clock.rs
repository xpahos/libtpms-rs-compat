use crate::ffi_types::TpmResult;
use crate::library::constants::{
    TPM_RC_INSUFFICIENT, TPM_RC_NV_UNAVAILABLE, TPM_RC_SIZE, TPM_RC_VALUE,
};

use super::super::super::clock::{ClockAdjust, plat_clock_rate_adjust, time_clock_update};
use super::super::super::marshal::BlobReader;
use super::super::super::runtime::Tpm2Runtime;
use super::super::attest::marshaled_time_info;
use super::super::dispatcher::CommandFrame;
use super::super::nv_common::{TPM_RC_1, TPM_RC_P};
use super::super::output::CommandOutput;

const RC_NEW_TIME: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_RATE_ADJUST: TpmResult = TPM_RC_P + TPM_RC_1;

pub(in crate::library::tpm2::command) const MAX_CLOCK_VALUE: u64 = 0xffff_0000_0000_0000;

pub(in crate::library::tpm2::command) fn execute_read_clock(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    if !frame.parameters.is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(CommandOutput::from_parameters(marshaled_time_info(
        runtime,
    )?))
}

pub(in crate::library::tpm2::command) fn execute_clock_set(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let new_time = parse_new_time(frame.parameters)?;
    if new_time > MAX_CLOCK_VALUE || new_time < runtime.live.orderly.clock {
        return Err(TPM_RC_VALUE + RC_NEW_TIME);
    }
    if !runtime.nv_available {
        return Err(TPM_RC_NV_UNAVAILABLE);
    }
    time_clock_update(runtime, new_time);
    Ok(CommandOutput::empty())
}

pub(in crate::library::tpm2::command) fn execute_clock_rate_adjust(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let adjust = parse_rate_adjust(frame.parameters)?;
    plat_clock_rate_adjust(&mut runtime.timer, adjust);
    Ok(CommandOutput::empty())
}

fn parse_new_time(parameters: &[u8]) -> Result<u64, TpmResult> {
    let mut reader = BlobReader::new(parameters);
    let new_time = reader
        .read_u64()
        .map_err(|_| TPM_RC_INSUFFICIENT + RC_NEW_TIME)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(new_time)
}

fn parse_rate_adjust(parameters: &[u8]) -> Result<ClockAdjust, TpmResult> {
    let mut reader = BlobReader::new(parameters);
    let encoded = reader
        .read_u8()
        .map_err(|_| TPM_RC_INSUFFICIENT + RC_RATE_ADJUST)?;
    let adjust = ClockAdjust::from_encoded(encoded).ok_or(TPM_RC_VALUE + RC_RATE_ADJUST)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(adjust)
}

#[cfg(test)]
mod tests {
    use super::super::harness::*;
    use super::*;
    use crate::library::tpm2::command::registry::{
        CommandLifecycle, HandleKind, NvAccess, TPM_CC_CLOCK_RATE_ADJUST, TPM_CC_CLOCK_SET,
        TPM_CC_READ_CLOCK, find,
    };

    const NOMINAL: u32 = 30_000;
    const COARSE_SLOWER: u8 = 0xfd;
    const MEDIUM_SLOWER: u8 = 0xfe;
    const FINE_SLOWER: u8 = 0xff;
    const NO_CHANGE: u8 = 0x00;
    const FINE_FASTER: u8 = 0x01;
    const MEDIUM_FASTER: u8 = 0x02;
    const COARSE_FASTER: u8 = 0x03;

    #[test]
    fn the_three_commands_are_registered_with_the_reference_attributes() {
        for (code, attributes, record, handles, decrypt) in [
            (
                TPM_CC_CLOCK_SET,
                0x0240_0128u32,
                "CCATTR_0128",
                1usize,
                0u16,
            ),
            (TPM_CC_CLOCK_RATE_ADJUST, 0x0200_0130, "CCATTR_0130", 1, 0),
            (TPM_CC_READ_CLOCK, 0x0000_0181, "CCATTR_0181", 0, 0),
        ] {
            let descriptor = find(code).expect("the command is registered");
            assert_eq!(descriptor.attributes, attributes, "code {code:#x}");
            assert_eq!(
                descriptor.attributes,
                u32::from_be_bytes(vector(record)[19..23].try_into().expect("four bytes")),
                "code {code:#x}"
            );
            assert_eq!(descriptor.handles.len(), handles, "code {code:#x}");
            assert_eq!(descriptor.decrypt_size, decrypt, "code {code:#x}");
            assert_eq!(descriptor.encrypt_size, 0, "code {code:#x}");
            assert!(descriptor.sessions_allowed, "code {code:#x}");
            assert!(matches!(descriptor.nv_access, NvAccess::Neither));
            assert!(matches!(
                descriptor.lifecycle,
                CommandLifecycle::RequiresStarted
            ));
        }
        assert!(matches!(
            find(TPM_CC_CLOCK_SET).unwrap().handles[0].kind,
            HandleKind::Provision
        ));
        assert!(matches!(
            find(TPM_CC_CLOCK_RATE_ADJUST).unwrap().handles[0].kind,
            HandleKind::Provision
        ));
        assert!(find(TPM_CC_CLOCK_SET).unwrap().physical_presence);
        assert!(find(TPM_CC_CLOCK_RATE_ADJUST).unwrap().physical_presence);
        assert!(!find(TPM_CC_READ_CLOCK).unwrap().physical_presence);
    }

    #[test]
    fn the_clock_commands_need_a_started_tpm() {
        let clock = replay_clock();
        for (label, bytes) in [
            ("LIFECYCLE_READ_CLOCK", read_clock()),
            (
                "LIFECYCLE_CLOCK_SET",
                clock_set(TPM_RH_PLATFORM, 0x10000, &[]),
            ),
            (
                "LIFECYCLE_CLOCK_RATE_ADJUST",
                clock_rate_adjust(TPM_RH_PLATFORM, NO_CHANGE, &[]),
            ),
        ] {
            let mut runtime = manufactured(&clock);
            expect(&mut runtime, &clock, label, &bytes);
            assert_eq!(response_code(vector(label)), RC_INITIALIZE, "{label}");
        }
    }

    #[test]
    fn read_clock_reports_the_reference_time_info() {
        let clock = replay_clock();
        let mut runtime = ready(&clock);
        expect(&mut runtime, &clock, "RCLK_BASE", &read_clock());
        expect(&mut runtime, &clock, "RCLK_REPEATED", &read_clock());
        clock.advance(5000);
        expect(&mut runtime, &clock, "RCLK_AFTER_ADVANCE", &read_clock());

        let (time, tpm_clock, reset, restart, safe) = time_info(vector("RCLK_AFTER_ADVANCE"));
        assert_eq!(time, 5000);
        assert_eq!(tpm_clock, 5000);
        assert_eq!(reset, runtime.state().persistent.reset_count);
        assert_eq!(
            restart,
            runtime
                .live
                .state_reset
                .as_ref()
                .expect("a started runtime")
                .restart_count
        );
        assert_eq!(safe, runtime.live.orderly.clock_safe);
        assert_eq!(time, runtime.timer.time_ms);
        assert_eq!(tpm_clock, runtime.live.orderly.clock);
    }

    #[test]
    fn read_clock_rejects_trailing_bytes_and_an_unusable_session() {
        let clock = replay_clock();
        let mut runtime = ready(&clock);
        expect(
            &mut runtime,
            &clock,
            "RCLK_TRAILING",
            &framed(TPM_CC_READ_CLOCK, &[0x00], false),
        );
        assert_eq!(response_code(vector("RCLK_TRAILING")), RC_SIZE);
        expect(
            &mut runtime,
            &clock,
            "RCLK_WITH_SESSION",
            &command(TPM_CC_READ_CLOCK, &[], &[&[]], &[]),
        );
        assert_eq!(
            response_code(vector("RCLK_WITH_SESSION")),
            RC_SESSION1_HANDLE
        );
    }

    #[test]
    fn read_clock_never_reports_a_safe_clock_while_nv_is_unavailable() {
        let clock = replay_clock();
        let mut runtime = ready(&clock);
        runtime.live.orderly.clock_safe = 1;
        runtime.nv_available = false;
        let response = exec(&mut runtime, &clock, &read_clock());
        assert_eq!(time_info(&response).4, 0);
    }

    #[test]
    fn clock_set_replays_the_reference_section() {
        let clock = replay_clock();
        let host = Host::at("READY");
        let mut runtime = ready(&clock);
        for (label, bytes) in [
            ("CS_READ_BEFORE", read_clock()),
            ("CS_FORWARD", clock_set(TPM_RH_PLATFORM, 0x10000, &[])),
            ("CS_READ_AFTER_FORWARD", read_clock()),
            ("CS_SAME", clock_set(TPM_RH_PLATFORM, 0x10000, &[])),
            ("CS_BACKWARDS_ZERO", clock_set(TPM_RH_PLATFORM, 0, &[])),
            (
                "CS_BACKWARDS_ONE_BELOW",
                clock_set(TPM_RH_PLATFORM, 0xffff, &[]),
            ),
            ("CS_BY_OWNER", clock_set(TPM_RH_OWNER, 0x20000, &[])),
            ("CS_READ_AFTER_OWNER", read_clock()),
            (
                "CS_BY_ENDORSEMENT",
                clock_set(TPM_RH_ENDORSEMENT, 0x30000, &[]),
            ),
            ("CS_BY_LOCKOUT", clock_set(TPM_RH_LOCKOUT, 0x30000, &[])),
            ("CS_BY_NULL", clock_set(TPM_RH_NULL, 0x30000, &[])),
            (
                "CS_WRONG_PASSWORD",
                clock_set(TPM_RH_PLATFORM, 0x30000, b"wrong"),
            ),
            (
                "CS_NO_SESSIONS",
                framed(
                    TPM_CC_CLOCK_SET,
                    &[
                        &TPM_RH_PLATFORM.to_be_bytes()[..],
                        &0x30000u64.to_be_bytes()[..],
                    ]
                    .concat(),
                    false,
                ),
            ),
            (
                "CS_TRUNCATED_TIME",
                command(
                    TPM_CC_CLOCK_SET,
                    &[TPM_RH_PLATFORM],
                    &[&[]],
                    &0x30000u64.to_be_bytes()[..7],
                ),
            ),
            (
                "CS_MISSING_TIME",
                command(TPM_CC_CLOCK_SET, &[TPM_RH_PLATFORM], &[&[]], &[]),
            ),
            (
                "CS_TRAILING",
                command(
                    TPM_CC_CLOCK_SET,
                    &[TPM_RH_PLATFORM],
                    &[&[]],
                    &[&0x30000u64.to_be_bytes()[..], &[0xee][..]].concat(),
                ),
            ),
            (
                "CS_TRUNCATED_HANDLE",
                framed(TPM_CC_CLOCK_SET, &TPM_RH_PLATFORM.to_be_bytes()[..2], true),
            ),
            (
                "CS_ABOVE_MAX",
                clock_set(TPM_RH_PLATFORM, MAX_CLOCK_VALUE + 1, &[]),
            ),
            ("CS_MAX", clock_set(TPM_RH_PLATFORM, MAX_CLOCK_VALUE, &[])),
            ("CS_READ_AT_MAX", read_clock()),
            (
                "CS_ABOVE_MAX_AT_MAX",
                clock_set(TPM_RH_PLATFORM, MAX_CLOCK_VALUE + 1, &[]),
            ),
        ] {
            host.expect(&mut runtime, &clock, label, &bytes);
        }
        assert_eq!(runtime.live.orderly.clock, MAX_CLOCK_VALUE);
        assert_matches_permall(&runtime, "AFTER_CLOCK_SET");
        host.expect(
            &mut runtime,
            &clock,
            "CS_CAP_PERMANENT_AT_MAX",
            &get_capability(TPM_CAP_TPM_PROPERTIES, 0x0000_0201, 1),
        );

        host.expect(&mut runtime, &clock, "SHUTDOWN_FOR_CLOCK", &shutdown(0));
        let mut rebooted = host.reboot();
        host.expect(&mut rebooted, &clock, "STARTUP_FOR_CLOCK", &startup(0));
        host.expect(
            &mut rebooted,
            &clock,
            "CS_READ_AFTER_RESTART",
            &read_clock(),
        );
        assert_eq!(
            time_info(vector("CS_READ_AFTER_RESTART")).1,
            MAX_CLOCK_VALUE,
            "the persisted clock survives the restart"
        );
        assert_durable_state(&rebooted, "AFTER_CLOCK_SET_RESTART");
    }

    #[test]
    fn the_reference_clock_set_error_codes_are_the_documented_values() {
        for (label, code) in [
            ("CS_FORWARD", RC_SUCCESS),
            ("CS_SAME", RC_SUCCESS),
            ("CS_BY_OWNER", RC_SUCCESS),
            ("CS_MAX", RC_SUCCESS),
            ("CS_BACKWARDS_ZERO", RC_VALUE_P1),
            ("CS_BACKWARDS_ONE_BELOW", RC_VALUE_P1),
            ("CS_ABOVE_MAX", RC_VALUE_P1),
            ("CS_ABOVE_MAX_AT_MAX", RC_VALUE_P1),
            ("CS_BY_ENDORSEMENT", RC_VALUE_H1),
            ("CS_BY_LOCKOUT", RC_VALUE_H1),
            ("CS_BY_NULL", RC_VALUE_H1),
            ("CS_WRONG_PASSWORD", RC_SESSION1_BAD_AUTH),
            ("CS_NO_SESSIONS", RC_AUTH_MISSING),
            ("CS_TRUNCATED_TIME", RC_INSUFFICIENT_P1),
            ("CS_MISSING_TIME", RC_INSUFFICIENT_P1),
            ("CS_TRAILING", RC_SIZE),
            ("CS_TRUNCATED_HANDLE", RC_INSUFFICIENT_H1),
        ] {
            assert_eq!(response_code(vector(label)), code, "{label}");
        }
    }

    #[test]
    fn a_failed_clock_set_changes_nothing() {
        let clock = replay_clock();
        let mut runtime = ready(&clock);
        exec(
            &mut runtime,
            &clock,
            &clock_set(TPM_RH_PLATFORM, 0x10000, &[]),
        );
        let before = snapshot(&runtime);
        for bytes in [
            clock_set(TPM_RH_PLATFORM, 0, &[]),
            clock_set(TPM_RH_PLATFORM, MAX_CLOCK_VALUE + 1, &[]),
            clock_set(TPM_RH_LOCKOUT, 0x20000, &[]),
            clock_set(TPM_RH_PLATFORM, 0x20000, b"wrong"),
            command(TPM_CC_CLOCK_SET, &[TPM_RH_PLATFORM], &[&[]], &[]),
        ] {
            let response = exec(&mut runtime, &clock, &bytes);
            assert_ne!(response_code(&response), RC_SUCCESS, "{bytes:02x?}");
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn an_unavailable_nv_is_reported_after_the_value_check() {
        let clock = replay_clock();
        let mut runtime = ready(&clock);
        runtime.nv_available = false;
        let before = snapshot(&runtime);
        assert_eq!(
            response_code(&exec(
                &mut runtime,
                &clock,
                &clock_set(TPM_RH_PLATFORM, MAX_CLOCK_VALUE + 1, &[])
            )),
            RC_VALUE_P1,
            "an out-of-range value is rejected before the NV state is consulted"
        );
        assert_eq!(
            response_code(&exec(
                &mut runtime,
                &clock,
                &clock_set(TPM_RH_PLATFORM, 0x10000, &[])
            )),
            RC_NV_UNAVAILABLE
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn the_handle_interface_is_checked_before_the_value_and_the_nv_state() {
        let clock = replay_clock();
        let mut runtime = ready(&clock);
        runtime.nv_available = false;
        let before = snapshot(&runtime);
        assert_eq!(
            response_code(&exec(
                &mut runtime,
                &clock,
                &clock_set(TPM_RH_LOCKOUT, MAX_CLOCK_VALUE + 1, &[])
            )),
            RC_VALUE_H1,
            "the handle interface is resolved before any parameter or NV check"
        );
        assert_eq!(
            response_code(&exec(
                &mut runtime,
                &clock,
                &clock_set(TPM_RH_PLATFORM, MAX_CLOCK_VALUE + 1, b"wrong")
            )),
            RC_SESSION1_BAD_AUTH,
            "authorization is checked before the parameter is unmarshaled"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn clock_set_marks_the_clock_safe_when_it_crosses_the_update_interval() {
        let clock = replay_clock();
        let host = Host::at("READY");
        let mut runtime = ready(&clock);
        clock.advance(9000);
        host.run(&mut runtime, &clock, &read_clock());

        let mut rebooted = host.reboot();
        host.expect(&mut rebooted, &clock, "STARTUP_UNORDERLY", &startup(0));
        host.expect(
            &mut rebooted,
            &clock,
            "CLK_READ_AFTER_UNORDERLY",
            &read_clock(),
        );
        assert_eq!(
            time_info(vector("CLK_READ_AFTER_UNORDERLY")).4,
            0,
            "an unorderly restart clears the clock-safe flag"
        );
        host.expect(
            &mut rebooted,
            &clock,
            "CLK_SET_AFTER_UNORDERLY",
            &clock_set(TPM_RH_PLATFORM, 0x40000, &[]),
        );
        host.expect(
            &mut rebooted,
            &clock,
            "CLK_READ_AFTER_SET_UNORDERLY",
            &read_clock(),
        );
        assert_eq!(
            time_info(vector("CLK_READ_AFTER_SET_UNORDERLY")).4,
            1,
            "crossing the NV update interval makes the clock safe again"
        );
        clock.advance(9000);
        host.expect(
            &mut rebooted,
            &clock,
            "CLK_READ_AFTER_ADVANCE_UNORDERLY",
            &read_clock(),
        );
        assert_durable_state(&rebooted, "AFTER_UNORDERLY_CLOCK");
    }

    #[test]
    fn every_clock_adjustment_value_answers_like_the_reference() {
        let clock = replay_clock();
        let mut runtime = ready(&clock);
        for (label, adjust) in [
            ("CRA_NO_CHANGE", NO_CHANGE),
            ("CRA_FINE_FASTER", FINE_FASTER),
            ("CRA_MEDIUM_FASTER", MEDIUM_FASTER),
            ("CRA_COARSE_FASTER", COARSE_FASTER),
            ("CRA_FINE_SLOWER", FINE_SLOWER),
            ("CRA_MEDIUM_SLOWER", MEDIUM_SLOWER),
            ("CRA_COARSE_SLOWER", COARSE_SLOWER),
        ] {
            expect(
                &mut runtime,
                &clock,
                label,
                &clock_rate_adjust(TPM_RH_PLATFORM, adjust, &[]),
            );
            assert_eq!(response_code(vector(label)), RC_SUCCESS, "{label}");
        }
        assert_eq!(
            runtime.timer.adjust_rate, NOMINAL,
            "the faster and slower steps cancel out"
        );

        let rate_before = runtime.timer.adjust_rate;
        for (label, adjust) in [
            ("CRA_INVALID_FOUR", 4u8),
            ("CRA_INVALID_FC", 0xfc),
            ("CRA_INVALID_SEVEN_F", 0x7f),
            ("CRA_INVALID_EIGHTY", 0x80),
        ] {
            expect(
                &mut runtime,
                &clock,
                label,
                &clock_rate_adjust(TPM_RH_PLATFORM, adjust, &[]),
            );
            assert_eq!(response_code(vector(label)), RC_VALUE_P1, "{label}");
        }
        assert_eq!(runtime.timer.adjust_rate, rate_before);
    }

    #[test]
    fn the_clock_rate_authorization_and_parsing_errors_match_the_reference() {
        let clock = replay_clock();
        let mut runtime = ready(&clock);
        let before = snapshot(&runtime);
        for (label, bytes) in [
            (
                "CRA_BY_LOCKOUT",
                clock_rate_adjust(TPM_RH_LOCKOUT, NO_CHANGE, &[]),
            ),
            (
                "CRA_BY_NULL",
                clock_rate_adjust(TPM_RH_NULL, NO_CHANGE, &[]),
            ),
            (
                "CRA_WRONG_PASSWORD",
                clock_rate_adjust(TPM_RH_PLATFORM, NO_CHANGE, b"wrong"),
            ),
            (
                "CRA_NO_SESSIONS",
                framed(
                    TPM_CC_CLOCK_RATE_ADJUST,
                    &[&TPM_RH_PLATFORM.to_be_bytes()[..], &[NO_CHANGE][..]].concat(),
                    false,
                ),
            ),
            (
                "CRA_MISSING_ADJUST",
                command(TPM_CC_CLOCK_RATE_ADJUST, &[TPM_RH_PLATFORM], &[&[]], &[]),
            ),
            (
                "CRA_TRAILING",
                command(
                    TPM_CC_CLOCK_RATE_ADJUST,
                    &[TPM_RH_PLATFORM],
                    &[&[]],
                    &[NO_CHANGE, 0xee],
                ),
            ),
            (
                "CRA_TRUNCATED_HANDLE",
                framed(
                    TPM_CC_CLOCK_RATE_ADJUST,
                    &TPM_RH_PLATFORM.to_be_bytes()[..3],
                    true,
                ),
            ),
        ] {
            expect(&mut runtime, &clock, label, &bytes);
        }
        assert_unchanged(&runtime, &before);

        expect(
            &mut runtime,
            &clock,
            "CRA_BY_OWNER",
            &clock_rate_adjust(TPM_RH_OWNER, NO_CHANGE, &[]),
        );
        assert_eq!(response_code(vector("CRA_BY_OWNER")), RC_SUCCESS);
        for (label, code) in [
            ("CRA_BY_LOCKOUT", RC_VALUE_H1),
            ("CRA_BY_NULL", RC_VALUE_H1),
            ("CRA_WRONG_PASSWORD", RC_SESSION1_BAD_AUTH),
            ("CRA_NO_SESSIONS", RC_AUTH_MISSING),
            ("CRA_MISSING_ADJUST", RC_INSUFFICIENT_P1),
            ("CRA_TRAILING", RC_SIZE),
            ("CRA_TRUNCATED_HANDLE", RC_INSUFFICIENT_H1),
        ] {
            assert_eq!(response_code(vector(label)), code, "{label}");
        }
    }

    #[test]
    fn the_adjustment_rate_changes_how_fast_the_reported_clock_runs() {
        let clock = replay_clock();
        let mut runtime = ready(&clock);
        expect(&mut runtime, &clock, "RATE_READ_START", &read_clock());
        clock.advance(30_300);
        expect(&mut runtime, &clock, "RATE_READ_NOMINAL", &read_clock());
        exec(
            &mut runtime,
            &clock,
            &clock_rate_adjust(TPM_RH_PLATFORM, COARSE_SLOWER, &[]),
        );
        assert_eq!(runtime.timer.adjust_rate, NOMINAL + 300);
        clock.advance(30_300);
        expect(
            &mut runtime,
            &clock,
            "RATE_READ_COARSE_SLOWER",
            &read_clock(),
        );
        exec(
            &mut runtime,
            &clock,
            &clock_rate_adjust(TPM_RH_PLATFORM, COARSE_FASTER, &[]),
        );
        expect(
            &mut runtime,
            &clock,
            "RATE_BACK_TO_NOMINAL",
            &clock_rate_adjust(TPM_RH_PLATFORM, COARSE_FASTER, &[]),
        );
        assert_eq!(runtime.timer.adjust_rate, NOMINAL - 300);
        clock.advance(29_700);
        expect(
            &mut runtime,
            &clock,
            "RATE_READ_COARSE_FASTER",
            &read_clock(),
        );

        let base = time_info(vector("RATE_READ_NOMINAL")).0;
        assert_eq!(base, 30_300, "a nominal rate reports real time");
        assert_eq!(
            time_info(vector("RATE_READ_COARSE_SLOWER")).0 - base,
            30_000,
            "a slower rate reports less than the elapsed real time"
        );
        assert_eq!(
            time_info(vector("RATE_READ_COARSE_FASTER")).0
                - time_info(vector("RATE_READ_COARSE_SLOWER")).0,
            30_000,
            "a faster rate reports more than the elapsed real time"
        );
    }

    #[test]
    fn the_adjustment_rate_saturates_at_the_platform_limit() {
        let clock = replay_clock();
        let mut runtime = ready(&clock);
        expect(&mut runtime, &clock, "RATE_CLAMP_READ_START", &read_clock());
        for _ in 0..17 {
            exec(
                &mut runtime,
                &clock,
                &clock_rate_adjust(TPM_RH_PLATFORM, COARSE_SLOWER, &[]),
            );
        }
        assert_eq!(runtime.timer.adjust_rate, NOMINAL + 5_000);
        clock.advance(35_000);
        expect(
            &mut runtime,
            &clock,
            "RATE_READ_CLAMPED_SLOW",
            &read_clock(),
        );
        for _ in 0..34 {
            exec(
                &mut runtime,
                &clock,
                &clock_rate_adjust(TPM_RH_PLATFORM, COARSE_FASTER, &[]),
            );
        }
        assert_eq!(runtime.timer.adjust_rate, NOMINAL - 5_000);
        clock.advance(25_000);
        expect(
            &mut runtime,
            &clock,
            "RATE_READ_CLAMPED_FAST",
            &read_clock(),
        );
        assert_eq!(time_info(vector("RATE_READ_CLAMPED_SLOW")).0, 30_000);
        assert_eq!(time_info(vector("RATE_READ_CLAMPED_FAST")).0, 60_000);
    }

    #[test]
    fn the_adjustment_rate_survives_a_volatile_state_round_trip() {
        use crate::library::tpm2::volatile::volatile_all_store;
        use crate::library::tpm2::{VolatileDecodeBoundary, attach_volatile_blob};

        let clock = replay_clock();
        let mut runtime = ready(&clock);
        exec(
            &mut runtime,
            &clock,
            &clock_rate_adjust(TPM_RH_PLATFORM, COARSE_SLOWER, &[]),
        );
        let blob = volatile_all_store(&runtime, &clock).expect("the volatile state saves");
        let mut restored = ready(&clock);
        attach_volatile_blob(
            &mut restored,
            &blob,
            &clock,
            VolatileDecodeBoundary::Restore,
        )
        .expect("the volatile state attaches");
        assert_eq!(restored.timer.adjust_rate, NOMINAL + 300);
    }

    #[test]
    fn a_shutdown_and_restart_returns_the_adjustment_rate_to_nominal() {
        let clock = replay_clock();
        let host = Host::at("READY");
        let mut runtime = ready(&clock);
        exec(
            &mut runtime,
            &clock,
            &clock_rate_adjust(TPM_RH_PLATFORM, COARSE_SLOWER, &[]),
        );
        assert_eq!(runtime.timer.adjust_rate, NOMINAL + 300);
        host.run(&mut runtime, &clock, &shutdown(1));
        let mut rebooted = host.reboot();
        host.expect(&mut rebooted, &clock, "STARTUP_RESUME_RATE", &startup(1));
        host.expect(
            &mut rebooted,
            &clock,
            "RATE_READ_AFTER_RESUME_BASE",
            &read_clock(),
        );
        assert_eq!(
            rebooted.timer.adjust_rate, NOMINAL,
            "the platform timer is reset by the restart"
        );
        clock.advance(30_300);
        host.expect(
            &mut rebooted,
            &clock,
            "RATE_READ_AFTER_RESUME",
            &read_clock(),
        );
        assert_eq!(time_info(vector("RATE_READ_AFTER_RESUME")).0, 30_300);
    }

    #[test]
    fn malformed_clock_requests_never_panic() {
        let clock = replay_clock();
        for valid in [
            clock_set(TPM_RH_PLATFORM, 0x10000, &[]),
            clock_rate_adjust(TPM_RH_PLATFORM, NO_CHANGE, &[]),
            read_clock(),
        ] {
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
}
