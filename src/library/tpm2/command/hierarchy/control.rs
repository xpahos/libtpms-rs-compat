use super::{flush_loaded_hierarchy_objects, hierarchy_object_attribute, with_rollback};
use crate::ffi_types::TpmResult;
use crate::library::constants::{
    TPM_RC_AUTH_TYPE, TPM_RC_FAILURE, TPM_RC_INSUFFICIENT, TPM_RC_SIZE, TPM_RC_VALUE,
};
use crate::library::tpm2::command::core::dispatcher::CommandFrame;
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::hierarchy::{
    TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM, TPM_RH_PLATFORM_NV,
};
use crate::library::tpm2::marshal::BlobReader;
use crate::library::tpm2::orderly::{commit_clear_orderly, prepare_clear_orderly};
use crate::library::tpm2::runtime::Tpm2Runtime;

const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;
const TPM_RC_2: TpmResult = 0x200;
const RC_ENABLE: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_STATE: TpmResult = TPM_RC_P + TPM_RC_2;

struct HierarchyControlIn {
    enable: u32,
    state: bool,
}

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let auth_handle = frame.handles.first().copied().ok_or(TPM_RC_FAILURE)?;
    let input = parse_parameters(frame.parameters)?;

    check_authorized_hierarchy(runtime, auth_handle, &input)?;

    if selected_state(runtime, input.enable)? == input.state {
        return Ok(CommandOutput::empty());
    }
    let orderly_state = prepare_clear_orderly(runtime)?;

    with_rollback(runtime, |runtime| {
        apply_state(runtime, input.enable, input.state)?;
        if !input.state && input.enable != TPM_RH_PLATFORM_NV {
            let attribute = hierarchy_object_attribute(input.enable).ok_or(TPM_RC_FAILURE)?;
            flush_loaded_hierarchy_objects(&mut runtime.live.objects, attribute);
        }
        commit_clear_orderly(runtime, orderly_state)
    })?;
    Ok(CommandOutput::empty())
}

fn parse_parameters(parameters: &[u8]) -> Result<HierarchyControlIn, TpmResult> {
    let mut reader = BlobReader::new(parameters);
    let enable = reader
        .read_u32()
        .map_err(|_| TPM_RC_INSUFFICIENT + RC_ENABLE)?;
    if !matches!(
        enable,
        TPM_RH_OWNER | TPM_RH_PLATFORM | TPM_RH_ENDORSEMENT | TPM_RH_PLATFORM_NV
    ) {
        return Err(TPM_RC_VALUE + RC_ENABLE);
    }
    let state = match reader
        .read_u8()
        .map_err(|_| TPM_RC_INSUFFICIENT + RC_STATE)?
    {
        0 => false,
        1 => true,
        _ => return Err(TPM_RC_VALUE + RC_STATE),
    };
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(HierarchyControlIn { enable, state })
}

fn check_authorized_hierarchy(
    runtime: &Tpm2Runtime,
    auth_handle: u32,
    input: &HierarchyControlIn,
) -> Result<(), TpmResult> {
    match input.enable {
        TPM_RH_PLATFORM | TPM_RH_PLATFORM_NV => {
            if auth_handle != TPM_RH_PLATFORM {
                return Err(TPM_RC_AUTH_TYPE);
            }
        }
        TPM_RH_OWNER | TPM_RH_ENDORSEMENT => {
            if auth_handle != TPM_RH_PLATFORM && auth_handle != input.enable {
                return Err(TPM_RC_AUTH_TYPE);
            }
            if !selected_state(runtime, input.enable)?
                && input.state
                && auth_handle != TPM_RH_PLATFORM
            {
                return Err(TPM_RC_AUTH_TYPE);
            }
        }
        _ => return Err(TPM_RC_FAILURE),
    }
    Ok(())
}

fn selected_state(runtime: &Tpm2Runtime, enable: u32) -> Result<bool, TpmResult> {
    if enable == TPM_RH_PLATFORM {
        return Ok(runtime.live.ph_enable);
    }
    let clear = runtime.live.state_clear.as_ref().ok_or(TPM_RC_FAILURE)?;
    match enable {
        TPM_RH_OWNER => Ok(clear.sh_enable),
        TPM_RH_ENDORSEMENT => Ok(clear.eh_enable),
        TPM_RH_PLATFORM_NV => Ok(clear.ph_enable_nv),
        _ => Err(TPM_RC_FAILURE),
    }
}

fn apply_state(runtime: &mut Tpm2Runtime, enable: u32, state: bool) -> Result<(), TpmResult> {
    if enable == TPM_RH_PLATFORM {
        runtime.live.ph_enable = state;
        return Ok(());
    }
    let clear = runtime.live.state_clear.as_mut().ok_or(TPM_RC_FAILURE)?;
    match enable {
        TPM_RH_OWNER => clear.sh_enable = state,
        TPM_RH_ENDORSEMENT => clear.eh_enable = state,
        TPM_RH_PLATFORM_NV => clear.ph_enable_nv = state,
        _ => return Err(TPM_RC_FAILURE),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::library::tpm2::command::core::registry::{
        CommandLifecycle, HandleKind, NvAccess, TPM_CC_HIERARCHY_CONTROL, find,
    };
    use crate::library::tpm2::command::core::test_support::{command, framed, response_code};
    use crate::library::tpm2::command::hierarchy::test_support::{
        DIGEST, Enables, NV_OWNER_ATTRIBUTES, NV_PLATFORM_ATTRIBUTES, OWNER_INDEX,
        OWNER_PERSISTENT, PLATFORM_INDEX, RC_NV_UNAVAILABLE, RC_SUCCESS, TPM_ALG_NULL,
        TPM_ALG_SHA256, TRANSIENT_FIRST, assert_unchanged, cap_command_attributes, cap_nv,
        cap_persistent, cap_startup_clear, cap_transient, change_auth_command, change_pps, clear,
        clear_control, commits_for, create_primary, enables, evict_control, exec, exec_counting,
        expect, flush, hierarchy_control, nv_define, nv_read_public, nvram_handles, occupied_slots,
        oracle_runtime, pcr_set_auth_policy, read_public, reboot, replay, replay_clock,
        set_primary_policy, shutdown, snapshot, startup,
    };
    use crate::library::tpm2::hierarchy::{
        TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT, TPM_RH_NULL, TPM_RH_OWNER, TPM_RH_PLATFORM,
        TPM_RH_PLATFORM_NV, TPM_RS_PW,
    };

    #[test]
    fn the_command_is_registered_with_the_upstream_attributes() {
        let descriptor = find(TPM_CC_HIERARCHY_CONTROL).expect("the command is registered");
        assert_eq!(descriptor.attributes, 0x02c0_0121);
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
        assert!(!descriptor.handles[0].admin_role());
        assert!(matches!(
            descriptor.handles[0].kind,
            HandleKind::BaseHierarchy
        ));
    }

    #[test]
    fn the_authorization_handle_takes_only_the_three_base_hierarchies() {
        let kind = find(TPM_CC_HIERARCHY_CONTROL).unwrap().handles[0].kind;
        for handle in [TPM_RH_OWNER, TPM_RH_ENDORSEMENT, TPM_RH_PLATFORM] {
            assert!(kind.accepts(handle), "handle {handle:#x}");
        }
        for handle in [
            TPM_RH_NULL,
            TPM_RH_LOCKOUT,
            TPM_RH_PLATFORM_NV,
            TPM_RS_PW,
            0,
            23,
            0x0100_0000,
            0x4000_0110,
            0x8000_0000,
            0x8100_0000,
            u32::MAX,
        ] {
            assert!(!kind.accepts(handle), "handle {handle:#x}");
        }
    }

    #[test]
    fn the_reported_command_attributes_match_the_reference() {
        replay(&[(
            "CCATTR_0121",
            cap_command_attributes(TPM_CC_HIERARCHY_CONTROL),
        )]);
    }

    #[test]
    fn the_framing_errors_match_the_reference() {
        let mut steps: Vec<(&str, Vec<u8>)> = vec![(
            "HC_NO_SESSIONS",
            framed(
                TPM_CC_HIERARCHY_CONTROL,
                &[
                    &TPM_RH_PLATFORM.to_be_bytes()[..],
                    &TPM_RH_OWNER.to_be_bytes()[..],
                    &[0x00][..],
                ]
                .concat(),
                false,
            ),
        )];
        for (label, count) in [
            ("HC_TRUNCATED_HANDLE_0", 0usize),
            ("HC_TRUNCATED_HANDLE_1", 1),
            ("HC_TRUNCATED_HANDLE_2", 2),
            ("HC_TRUNCATED_HANDLE_3", 3),
        ] {
            steps.push((
                label,
                framed(
                    TPM_CC_HIERARCHY_CONTROL,
                    &TPM_RH_PLATFORM.to_be_bytes()[..count],
                    true,
                ),
            ));
        }
        for (label, handle) in [
            ("HC_BAD_AUTH_NULL", TPM_RH_NULL),
            ("HC_BAD_AUTH_LOCKOUT", TPM_RH_LOCKOUT),
            ("HC_BAD_AUTH_PLATFORM_NV", TPM_RH_PLATFORM_NV),
            ("HC_BAD_AUTH_PW", TPM_RS_PW),
            ("HC_BAD_AUTH_TRANSIENT", TRANSIENT_FIRST),
            ("HC_BAD_AUTH_PERSISTENT", 0x8100_0000),
        ] {
            steps.push((label, hierarchy_control(handle, TPM_RH_OWNER, 0, &[])));
        }
        steps.push((
            "HC_ZERO_AUTH_SIZE",
            framed(
                TPM_CC_HIERARCHY_CONTROL,
                &[&TPM_RH_PLATFORM.to_be_bytes()[..], &0u32.to_be_bytes()[..]].concat(),
                true,
            ),
        ));
        steps.push((
            "HC_TRUNCATED_AUTH_SIZE",
            framed(
                TPM_CC_HIERARCHY_CONTROL,
                &[&TPM_RH_PLATFORM.to_be_bytes()[..], &[0x00, 0x00][..]].concat(),
                true,
            ),
        ));
        for (label, count) in [
            ("HC_TRUNCATED_ENABLE_0", 0usize),
            ("HC_TRUNCATED_ENABLE_1", 1),
            ("HC_TRUNCATED_ENABLE_2", 2),
            ("HC_TRUNCATED_ENABLE_3", 3),
        ] {
            steps.push((
                label,
                command(
                    TPM_CC_HIERARCHY_CONTROL,
                    &[TPM_RH_PLATFORM],
                    &[&[]],
                    &TPM_RH_OWNER.to_be_bytes()[..count],
                ),
            ));
        }
        for (label, handle) in [
            ("HC_BAD_ENABLE_NULL", TPM_RH_NULL),
            ("HC_BAD_ENABLE_LOCKOUT", TPM_RH_LOCKOUT),
            ("HC_BAD_ENABLE_PW", TPM_RS_PW),
            ("HC_BAD_ENABLE_ZERO", 0),
        ] {
            steps.push((label, hierarchy_control(TPM_RH_PLATFORM, handle, 0, &[])));
        }
        steps.push((
            "HC_TRUNCATED_STATE",
            command(
                TPM_CC_HIERARCHY_CONTROL,
                &[TPM_RH_PLATFORM],
                &[&[]],
                &TPM_RH_OWNER.to_be_bytes(),
            ),
        ));
        steps.push((
            "HC_BAD_STATE_02",
            hierarchy_control(TPM_RH_PLATFORM, TPM_RH_OWNER, 0x02, &[]),
        ));
        steps.push((
            "HC_BAD_STATE_FF",
            hierarchy_control(TPM_RH_PLATFORM, TPM_RH_OWNER, 0xff, &[]),
        ));
        let mut trailing = TPM_RH_OWNER.to_be_bytes().to_vec();
        trailing.extend_from_slice(&[0x00, 0xee]);
        steps.push((
            "HC_TRAILING",
            command(
                TPM_CC_HIERARCHY_CONTROL,
                &[TPM_RH_PLATFORM],
                &[&[]],
                &trailing,
            ),
        ));
        steps.push((
            "HC_WRONG_PASSWORD",
            hierarchy_control(TPM_RH_PLATFORM, TPM_RH_OWNER, 0, b"wrong"),
        ));

        let runtime = replay(&steps);
        assert_eq!(
            enables(&runtime),
            Enables {
                ph_enable: true,
                sh_enable: true,
                eh_enable: true,
                ph_enable_nv: true,
            },
            "a rejected request never changes a hierarchy flag"
        );
    }

    #[test]
    fn the_illegal_authorization_combinations_match_the_reference() {
        replay(&[
            (
                "HC_OWNER_BY_ENDORSEMENT",
                hierarchy_control(TPM_RH_ENDORSEMENT, TPM_RH_OWNER, 0, &[]),
            ),
            (
                "HC_ENDORSEMENT_BY_OWNER",
                hierarchy_control(TPM_RH_OWNER, TPM_RH_ENDORSEMENT, 0, &[]),
            ),
            (
                "HC_PLATFORM_BY_OWNER",
                hierarchy_control(TPM_RH_OWNER, TPM_RH_PLATFORM, 0, &[]),
            ),
            (
                "HC_PLATFORM_BY_ENDORSEMENT",
                hierarchy_control(TPM_RH_ENDORSEMENT, TPM_RH_PLATFORM, 0, &[]),
            ),
            (
                "HC_PLATFORM_NV_BY_OWNER",
                hierarchy_control(TPM_RH_OWNER, TPM_RH_PLATFORM_NV, 0, &[]),
            ),
            (
                "HC_PLATFORM_NV_BY_ENDORSEMENT",
                hierarchy_control(TPM_RH_ENDORSEMENT, TPM_RH_PLATFORM_NV, 0, &[]),
            ),
        ]);
    }

    #[test]
    fn enabling_an_enabled_hierarchy_changes_nothing() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        let before = snapshot(&runtime);
        for (label, bytes) in [
            (
                "HC_ENABLE_OWNER_ALREADY_ENABLED",
                hierarchy_control(TPM_RH_OWNER, TPM_RH_OWNER, 1, &[]),
            ),
            (
                "HC_ENABLE_ENDORSEMENT_ALREADY_ENABLED",
                hierarchy_control(TPM_RH_ENDORSEMENT, TPM_RH_ENDORSEMENT, 1, &[]),
            ),
            (
                "HC_ENABLE_PLATFORM_ALREADY_ENABLED",
                hierarchy_control(TPM_RH_PLATFORM, TPM_RH_PLATFORM, 1, &[]),
            ),
            (
                "HC_ENABLE_PLATFORM_NV_ALREADY_ENABLED",
                hierarchy_control(TPM_RH_PLATFORM, TPM_RH_PLATFORM_NV, 1, &[]),
            ),
            ("HC_CAP_STARTUP_CLEAR_NOOP", cap_startup_clear()),
        ] {
            expect(&mut runtime, &clock, label, &bytes);
        }
        assert_unchanged(&runtime, &before);
        assert!(
            !runtime.nv_update_pending,
            "an unchanged hierarchy flag requests no NV update"
        );
    }

    #[test]
    fn disabling_the_storage_hierarchy_matches_the_reference() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        for (label, bytes) in [
            ("SH_CAP_STARTUP_CLEAR_BEFORE", cap_startup_clear()),
            ("SH_OWNER_PRIMARY", create_primary(TPM_RH_OWNER)),
            (
                "SH_EVICT_OWNER",
                evict_control(TPM_RH_OWNER, TRANSIENT_FIRST, OWNER_PERSISTENT),
            ),
        ] {
            expect(&mut runtime, &clock, label, &bytes);
        }
        exec(&mut runtime, &clock, &flush(TRANSIENT_FIRST));
        for (label, bytes) in [
            (
                "SH_DEFINE_OWNER_INDEX",
                nv_define(TPM_RH_OWNER, OWNER_INDEX, NV_OWNER_ATTRIBUTES, 8),
            ),
            ("SH_OWNER_PRIMARY_LOADED", create_primary(TPM_RH_OWNER)),
            (
                "SH_ENDORSEMENT_PRIMARY_LOADED",
                create_primary(TPM_RH_ENDORSEMENT),
            ),
            (
                "SH_PLATFORM_PRIMARY_LOADED",
                create_primary(TPM_RH_PLATFORM),
            ),
            ("SH_CAP_TRANSIENT_BEFORE", cap_transient()),
            (
                "SH_DISABLE_OWNER",
                hierarchy_control(TPM_RH_OWNER, TPM_RH_OWNER, 0, &[]),
            ),
        ] {
            expect(&mut runtime, &clock, label, &bytes);
        }

        assert_eq!(
            enables(&runtime),
            Enables {
                ph_enable: true,
                sh_enable: false,
                eh_enable: true,
                ph_enable_nv: true,
            }
        );
        assert_eq!(
            occupied_slots(&runtime),
            [1, 2],
            "only the storage-hierarchy object is flushed"
        );
        assert_eq!(
            nvram_handles(&runtime),
            [OWNER_PERSISTENT, OWNER_INDEX],
            "the owner evict object and NV index stay in NV"
        );

        for (label, bytes) in [
            ("SH_CAP_STARTUP_CLEAR_AFTER", cap_startup_clear()),
            ("SH_CAP_TRANSIENT_AFTER", cap_transient()),
            ("SH_CAP_PERSISTENT_AFTER", cap_persistent()),
            ("SH_CAP_NV_AFTER", cap_nv()),
            ("SH_READPUBLIC_FLUSHED", read_public(TRANSIENT_FIRST)),
            (
                "SH_READPUBLIC_ENDORSEMENT_KEPT",
                read_public(TRANSIENT_FIRST + 1),
            ),
            (
                "SH_READPUBLIC_PLATFORM_KEPT",
                read_public(TRANSIENT_FIRST + 2),
            ),
            ("SH_NV_READPUBLIC_HIDDEN", nv_read_public(OWNER_INDEX)),
            ("SH_CREATE_PRIMARY_DISABLED", create_primary(TPM_RH_OWNER)),
            (
                "SH_EVICT_BY_OWNER_DISABLED",
                evict_control(TPM_RH_OWNER, OWNER_PERSISTENT, OWNER_PERSISTENT),
            ),
            (
                "SH_EVICT_BY_PLATFORM_DISABLED",
                evict_control(TPM_RH_PLATFORM, OWNER_PERSISTENT, OWNER_PERSISTENT),
            ),
            (
                "SH_CHANGE_AUTH_DISABLED",
                change_auth_command(TPM_RH_OWNER, &[], b"owner"),
            ),
            (
                "SH_SET_PRIMARY_POLICY_DISABLED",
                set_primary_policy(TPM_RH_OWNER, &DIGEST, TPM_ALG_SHA256, &[]),
            ),
            (
                "SH_ENABLE_BY_OWNER",
                hierarchy_control(TPM_RH_OWNER, TPM_RH_OWNER, 1, &[]),
            ),
            (
                "SH_ENABLE_BY_ENDORSEMENT",
                hierarchy_control(TPM_RH_ENDORSEMENT, TPM_RH_OWNER, 1, &[]),
            ),
            (
                "SH_ENABLE_BY_PLATFORM",
                hierarchy_control(TPM_RH_PLATFORM, TPM_RH_OWNER, 1, &[]),
            ),
            ("SH_CAP_STARTUP_CLEAR_REENABLED", cap_startup_clear()),
            (
                "SH_NV_READPUBLIC_VISIBLE_AGAIN",
                nv_read_public(OWNER_INDEX),
            ),
            (
                "SH_EVICT_BY_OWNER_REENABLED",
                evict_control(TPM_RH_OWNER, OWNER_PERSISTENT, OWNER_PERSISTENT),
            ),
        ] {
            expect(&mut runtime, &clock, label, &bytes);
        }
        assert!(enables(&runtime).sh_enable);
        assert_eq!(nvram_handles(&runtime), [OWNER_INDEX]);
    }

    #[test]
    fn disabling_the_endorsement_hierarchy_matches_the_reference() {
        let runtime = replay(&[
            ("EH_ENDORSEMENT_PRIMARY", create_primary(TPM_RH_ENDORSEMENT)),
            ("EH_OWNER_PRIMARY", create_primary(TPM_RH_OWNER)),
            (
                "EH_DISABLE_BY_ENDORSEMENT",
                hierarchy_control(TPM_RH_ENDORSEMENT, TPM_RH_ENDORSEMENT, 0, &[]),
            ),
            ("EH_CAP_STARTUP_CLEAR", cap_startup_clear()),
            ("EH_CAP_TRANSIENT", cap_transient()),
            (
                "EH_CREATE_PRIMARY_DISABLED",
                create_primary(TPM_RH_ENDORSEMENT),
            ),
            (
                "EH_CHANGE_AUTH_DISABLED",
                change_auth_command(TPM_RH_ENDORSEMENT, &[], b"endorse"),
            ),
            (
                "EH_ENABLE_BY_ENDORSEMENT",
                hierarchy_control(TPM_RH_ENDORSEMENT, TPM_RH_ENDORSEMENT, 1, &[]),
            ),
            (
                "EH_ENABLE_BY_PLATFORM",
                hierarchy_control(TPM_RH_PLATFORM, TPM_RH_ENDORSEMENT, 1, &[]),
            ),
            ("EH_CAP_STARTUP_CLEAR_REENABLED", cap_startup_clear()),
        ]);
        assert!(enables(&runtime).eh_enable);
        assert_eq!(occupied_slots(&runtime), [1]);
    }

    #[test]
    fn disabling_platform_nv_matches_the_reference() {
        let runtime = replay(&[
            (
                "PNV_DEFINE_PLATFORM_INDEX",
                nv_define(TPM_RH_PLATFORM, PLATFORM_INDEX, NV_PLATFORM_ATTRIBUTES, 8),
            ),
            (
                "PNV_DEFINE_OWNER_INDEX",
                nv_define(TPM_RH_OWNER, OWNER_INDEX, NV_OWNER_ATTRIBUTES, 8),
            ),
            ("PNV_PLATFORM_PRIMARY", create_primary(TPM_RH_PLATFORM)),
            (
                "PNV_DISABLE",
                hierarchy_control(TPM_RH_PLATFORM, TPM_RH_PLATFORM_NV, 0, &[]),
            ),
            ("PNV_CAP_STARTUP_CLEAR", cap_startup_clear()),
            ("PNV_CAP_TRANSIENT", cap_transient()),
            ("PNV_CAP_NV", cap_nv()),
            (
                "PNV_READPUBLIC_PLATFORM_INDEX",
                nv_read_public(PLATFORM_INDEX),
            ),
            ("PNV_READPUBLIC_OWNER_INDEX", nv_read_public(OWNER_INDEX)),
            (
                "PNV_ENABLE",
                hierarchy_control(TPM_RH_PLATFORM, TPM_RH_PLATFORM_NV, 1, &[]),
            ),
            (
                "PNV_READPUBLIC_PLATFORM_INDEX_AGAIN",
                nv_read_public(PLATFORM_INDEX),
            ),
        ]);
        assert!(enables(&runtime).ph_enable_nv);
        assert_eq!(
            occupied_slots(&runtime),
            [0],
            "platform NV never flushes loaded objects"
        );
    }

    #[test]
    fn disabling_the_platform_hierarchy_matches_the_reference() {
        let runtime = replay(&[
            ("PH_PLATFORM_PRIMARY", create_primary(TPM_RH_PLATFORM)),
            ("PH_OWNER_PRIMARY", create_primary(TPM_RH_OWNER)),
            (
                "PH_DISABLE",
                hierarchy_control(TPM_RH_PLATFORM, TPM_RH_PLATFORM, 0, &[]),
            ),
            ("PH_CAP_STARTUP_CLEAR", cap_startup_clear()),
            ("PH_CAP_TRANSIENT", cap_transient()),
            (
                "PH_ENABLE_AGAIN",
                hierarchy_control(TPM_RH_PLATFORM, TPM_RH_PLATFORM, 1, &[]),
            ),
            ("PH_CHANGE_PPS_DISABLED", change_pps(TPM_RH_PLATFORM, &[])),
            ("PH_CLEAR_BY_PLATFORM_DISABLED", clear(TPM_RH_PLATFORM, &[])),
            ("PH_CLEAR_BY_LOCKOUT_DISABLED", clear(TPM_RH_LOCKOUT, &[])),
            (
                "PH_CLEAR_CONTROL_BY_LOCKOUT_DISABLED",
                clear_control(TPM_RH_LOCKOUT, 1, &[]),
            ),
            (
                "PH_PCR_SET_AUTH_POLICY_DISABLED",
                pcr_set_auth_policy(TPM_RH_PLATFORM, &[], TPM_ALG_NULL, 20, &[]),
            ),
            (
                "PH_DISABLE_OWNER_BY_OWNER",
                hierarchy_control(TPM_RH_OWNER, TPM_RH_OWNER, 0, &[]),
            ),
            (
                "PH_ENABLE_OWNER_NO_PLATFORM",
                hierarchy_control(TPM_RH_OWNER, TPM_RH_OWNER, 1, &[]),
            ),
            ("PH_CAP_STARTUP_CLEAR_FINAL", cap_startup_clear()),
        ]);
        assert_eq!(
            enables(&runtime),
            Enables {
                ph_enable: false,
                sh_enable: false,
                eh_enable: true,
                ph_enable_nv: true,
            },
            "a cleared phEnable can only be restored by a reboot"
        );
        assert!(occupied_slots(&runtime).is_empty());
    }

    #[test]
    fn a_state_change_clears_the_orderly_state_and_a_no_op_does_not() {
        for (label, startup_label, request, orderly) in [
            (
                "HC_ORDERLY_DISABLE_OWNER",
                "HC_ORDERLY_STARTUP_STATE",
                hierarchy_control(TPM_RH_OWNER, TPM_RH_OWNER, 0, &[]),
                false,
            ),
            (
                "HC_ORDERLY_NOOP",
                "HC_ORDERLY_NOOP_STARTUP_STATE",
                hierarchy_control(TPM_RH_OWNER, TPM_RH_OWNER, 1, &[]),
                true,
            ),
        ] {
            let clock = replay_clock();
            let mut runtime = oracle_runtime(&clock);
            exec(&mut runtime, &clock, &shutdown(1));
            expect(&mut runtime, &clock, label, &request);
            assert_eq!(
                crate::library::tpm2::orderly::is_orderly(runtime.state().persistent.orderly_state),
                orderly,
                "{label}"
            );
            let mut rebooted = reboot(&runtime, &clock);
            expect(&mut rebooted, &clock, startup_label, &startup(1));
        }
    }

    #[test]
    fn a_hierarchy_change_survives_a_volatile_state_round_trip() {
        use crate::library::tpm2::volatile::volatile_all_store;
        use crate::library::tpm2::{
            VolatileDecodeBoundary, decode_volatile_blob, volatile_validation_context,
        };

        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        expect(
            &mut runtime,
            &clock,
            "SH_DISABLE_OWNER",
            &hierarchy_control(TPM_RH_OWNER, TPM_RH_OWNER, 0, &[]),
        );
        let blob = volatile_all_store(&runtime, &clock).expect("the volatile state saves");
        let context = volatile_validation_context(&runtime).expect("the context builds");
        let decoded =
            decode_volatile_blob(&context, &blob, &clock, VolatileDecodeBoundary::Validate)
                .expect("the volatile state decodes");
        assert!(decoded.ph_enable);
        assert!(!decoded.state_clear.sh_enable);
        assert!(decoded.state_clear.eh_enable);
        assert!(decoded.state_clear.ph_enable_nv);
    }

    #[test]
    fn an_unavailable_nv_only_blocks_a_state_change_that_must_clear_the_orderly_state() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        runtime.nv_available = false;
        assert!(
            !crate::library::tpm2::orderly::is_orderly(runtime.state().persistent.orderly_state),
            "a started TPM is already unorderly"
        );
        let response = exec(
            &mut runtime,
            &clock,
            &hierarchy_control(TPM_RH_OWNER, TPM_RH_OWNER, 0, &[]),
        );
        assert_eq!(
            response_code(&response),
            RC_SUCCESS,
            "an unorderly TPM needs no NV write to record the change"
        );
        assert!(!enables(&runtime).sh_enable);

        let mut orderly = oracle_runtime(&clock);
        exec(&mut orderly, &clock, &shutdown(1));
        orderly.nv_available = false;
        let before = snapshot(&orderly);
        let response = exec(
            &mut orderly,
            &clock,
            &hierarchy_control(TPM_RH_OWNER, TPM_RH_OWNER, 0, &[]),
        );
        assert_eq!(response_code(&response), RC_NV_UNAVAILABLE);
        assert_unchanged(&orderly, &before);
    }

    #[test]
    fn a_state_change_requests_an_nv_update_only_while_orderly() {
        assert_eq!(
            commits_for(&hierarchy_control(TPM_RH_OWNER, TPM_RH_OWNER, 0, &[])),
            0,
            "an unorderly TPM writes nothing"
        );
        assert_eq!(
            commits_for(&hierarchy_control(TPM_RH_OWNER, TPM_RH_OWNER, 1, &[])),
            0,
            "an unchanged flag writes nothing"
        );

        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        let commits = core::cell::Cell::new(0u32);
        exec_counting(&mut runtime, &clock, &shutdown(1), &commits);
        commits.set(0);
        exec_counting(
            &mut runtime,
            &clock,
            &hierarchy_control(TPM_RH_OWNER, TPM_RH_OWNER, 0, &[]),
            &commits,
        );
        assert_eq!(
            commits.get(),
            1,
            "the cleared orderly state is written back"
        );
    }

    #[test]
    fn prefixes_and_bit_flips_do_not_panic() {
        let clock = replay_clock();
        let valid = hierarchy_control(TPM_RH_PLATFORM, TPM_RH_OWNER, 0, &[]);
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
