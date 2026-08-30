use super::{
    PRIMARY_SEED_SIZE, PROOF_SIZE, commit_persistent_state, flush_loaded_hierarchy_objects,
    hierarchy_object_attribute, regenerate_hierarchy_secrets, remove_hierarchy_persistent_objects,
    with_rollback,
};
use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_NV_UNAVAILABLE, TPM_RC_SIZE};
use crate::library::tpm2::algorithm::TPM_ALG_NULL;
use crate::library::tpm2::command::core::dispatcher::CommandFrame;
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::hierarchy::TPM_RH_PLATFORM;
use crate::library::tpm2::orderly::prepare_clear_orderly;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::types::TpmResult;
pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let auth_handle = frame.handles.first().copied().ok_or(TPM_RC_FAILURE)?;
    if auth_handle != TPM_RH_PLATFORM {
        return Err(TPM_RC_FAILURE);
    }
    if !frame.parameters.is_empty() {
        return Err(TPM_RC_SIZE);
    }
    if !runtime.nv_available {
        return Err(TPM_RC_NV_UNAVAILABLE);
    }

    change_platform_primary_seed(runtime)?;
    Ok(CommandOutput::empty())
}

fn change_platform_primary_seed(runtime: &mut Tpm2Runtime) -> Result<(), TpmResult> {
    if runtime.live.state_clear.is_none() {
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
        regenerate_hierarchy_secrets(runtime, &[PRIMARY_SEED_SIZE, PROOF_SIZE])?.into_iter();
    let pp_seed = secrets.next().ok_or(TPM_RC_FAILURE)?;
    let ph_proof = secrets.next().ok_or(TPM_RC_FAILURE)?;

    with_rollback(runtime, |runtime| {
        let attribute = hierarchy_object_attribute(TPM_RH_PLATFORM).ok_or(TPM_RC_FAILURE)?;
        let state = runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?;
        if let Some(pp_seed) = pp_seed {
            state.persistent.pp_seed = pp_seed;
        }
        state.persistent.pp_seed_compat_level = seed_compat_level;
        if let Some(ph_proof) = ph_proof {
            state.persistent.ph_proof = ph_proof;
        }
        for entry in &mut state.persistent.pcr_policies {
            entry.hash_alg = TPM_ALG_NULL;
            entry.policy = Vec::new();
        }
        if let Some(orderly_state) = orderly_state {
            state.persistent.orderly_state = orderly_state;
        }
        remove_hierarchy_persistent_objects(state, attribute)?;

        let clear = runtime.live.state_clear.as_mut().ok_or(TPM_RC_FAILURE)?;
        clear.platform_alg = TPM_ALG_NULL;
        clear.platform_policy = Vec::new();

        flush_loaded_hierarchy_objects(&mut runtime.live.objects, attribute);
        commit_persistent_state(runtime)
    })
}

#[cfg(test)]
mod tests {
    use crate::library::cancel::Cancellation;
    use crate::library::tpm2::command::core::registry::{
        CommandLifecycle, HandleKind, NvAccess, TPM_CC_CHANGE_PPS, find,
    };
    use crate::library::tpm2::command::core::test_support::{
        command, error_response, framed, response_code,
    };
    use crate::library::tpm2::command::hierarchy::test_support::{
        DIGEST, NV_OWNER_ATTRIBUTES, NV_PLATFORM_ATTRIBUTES, OWNER_INDEX, OWNER_PERSISTENT,
        PLATFORM_INDEX, PLATFORM_PERSISTENT, RC_NV_UNAVAILABLE, TPM_ALG_NULL, TPM_ALG_SHA256,
        TRANSIENT_FIRST, assert_nv_image_is_current, assert_unchanged, cap_command_attributes,
        cap_nv, cap_permanent_flags, cap_persistent, cap_startup_clear, cap_transient,
        change_auth_command, change_pps, commits_for, counters, create_primary,
        dictionary_attack_state, evict_control, exec, exec_counting, expect, fingerprint, flush,
        nv_define, nv_read_public, oracle_runtime, policies, read_public, reboot, reload, replay,
        replay_clock, secrets, set_primary_policy, shutdown, snapshot, startup,
    };
    use crate::library::tpm2::hierarchy::{
        TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT, TPM_RH_OWNER, TPM_RH_PLATFORM,
    };

    #[test]
    fn command_registration_upstream_attributes() {
        let descriptor = find(TPM_CC_CHANGE_PPS).expect("the command is registered");
        assert_eq!(descriptor.attributes, 0x02c0_0125);
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
        assert!(matches!(descriptor.handles[0].kind, HandleKind::Platform));
    }

    #[test]
    fn reported_attributes_reference_match() {
        replay(&[("CCATTR_0125", cap_command_attributes(TPM_CC_CHANGE_PPS))]);
    }

    #[test]
    fn handle_parameter_error_reference_match() {
        let runtime = replay(&[
            ("PPS_BY_OWNER", change_pps(TPM_RH_OWNER, &[])),
            ("PPS_BY_LOCKOUT", change_pps(TPM_RH_LOCKOUT, &[])),
            ("PPS_BY_ENDORSEMENT", change_pps(TPM_RH_ENDORSEMENT, &[])),
            (
                "PPS_NO_SESSIONS",
                framed(TPM_CC_CHANGE_PPS, &TPM_RH_PLATFORM.to_be_bytes(), false),
            ),
            (
                "PPS_TRAILING",
                command(TPM_CC_CHANGE_PPS, &[TPM_RH_PLATFORM], &[&[]], &[0xee]),
            ),
            ("PPS_WRONG_PASSWORD", change_pps(TPM_RH_PLATFORM, b"wrong")),
            (
                "PPS_TRUNCATED_HANDLE",
                framed(TPM_CC_CHANGE_PPS, &TPM_RH_PLATFORM.to_be_bytes()[..3], true),
            ),
        ]);
        assert_nv_image_is_current(&runtime);
    }

    #[test]
    fn nv_commit_successful_change_only() {
        assert_eq!(commits_for(&change_pps(TPM_RH_PLATFORM, &[])), 1);
        for rejected in [
            change_pps(TPM_RH_OWNER, &[]),
            change_pps(TPM_RH_PLATFORM, b"wrong"),
            command(TPM_CC_CHANGE_PPS, &[TPM_RH_PLATFORM], &[&[]], &[0xee]),
        ] {
            assert_eq!(commits_for(&rejected), 0);
        }
    }

    #[test]
    fn rejected_request_seed_proof_unchanged() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        let before = snapshot(&runtime);
        for (label, bytes) in [
            ("PPS_BY_OWNER", change_pps(TPM_RH_OWNER, &[])),
            ("PPS_WRONG_PASSWORD", change_pps(TPM_RH_PLATFORM, b"wrong")),
            (
                "PPS_TRAILING",
                command(TPM_CC_CHANGE_PPS, &[TPM_RH_PLATFORM], &[&[]], &[0xee]),
            ),
        ] {
            expect(&mut runtime, &clock, label, &bytes);
        }
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn platform_reseed_other_hierarchies_preservation() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        for (label, bytes) in [
            ("PPS_PERMANENT_BEFORE", cap_permanent_flags()),
            ("PPS_PLATFORM_PRIMARY", create_primary(TPM_RH_PLATFORM)),
            (
                "PPS_EVICT_PLATFORM",
                evict_control(TPM_RH_PLATFORM, TRANSIENT_FIRST, PLATFORM_PERSISTENT),
            ),
        ] {
            expect(&mut runtime, &clock, label, &bytes);
        }
        exec(&mut runtime, &clock, &flush(TRANSIENT_FIRST));
        expect(
            &mut runtime,
            &clock,
            "PPS_OWNER_PRIMARY",
            &create_primary(TPM_RH_OWNER),
        );
        expect(
            &mut runtime,
            &clock,
            "PPS_EVICT_OWNER",
            &evict_control(TPM_RH_OWNER, TRANSIENT_FIRST, OWNER_PERSISTENT),
        );
        exec(&mut runtime, &clock, &flush(TRANSIENT_FIRST));
        for (label, bytes) in [
            (
                "PPS_DEFINE_OWNER_INDEX",
                nv_define(TPM_RH_OWNER, OWNER_INDEX, NV_OWNER_ATTRIBUTES, 8),
            ),
            (
                "PPS_DEFINE_PLATFORM_INDEX",
                nv_define(TPM_RH_PLATFORM, PLATFORM_INDEX, NV_PLATFORM_ATTRIBUTES, 8),
            ),
            (
                "PPS_PLATFORM_POLICY",
                set_primary_policy(TPM_RH_PLATFORM, &DIGEST, TPM_ALG_SHA256, &[]),
            ),
            (
                "PPS_PLATFORM_PRIMARY_BEFORE",
                create_primary(TPM_RH_PLATFORM),
            ),
            ("PPS_OWNER_PRIMARY_BEFORE", create_primary(TPM_RH_OWNER)),
            ("PPS_CAP_TRANSIENT_BEFORE", cap_transient()),
            ("PPS_CAP_PERSISTENT_BEFORE", cap_persistent()),
            ("PPS_CAP_NV_BEFORE", cap_nv()),
        ] {
            expect(&mut runtime, &clock, label, &bytes);
        }

        let before = secrets(&runtime);
        let policies_before = policies(&runtime);
        let counters_before = counters(&runtime);
        let dictionary_before = dictionary_attack_state(&runtime);

        expect(
            &mut runtime,
            &clock,
            "PPS_CHANGE",
            &change_pps(TPM_RH_PLATFORM, &[]),
        );

        let after = secrets(&runtime);
        assert_ne!(after.pp_seed, before.pp_seed, "the platform seed changes");
        assert_ne!(
            after.ph_proof, before.ph_proof,
            "the platform proof changes"
        );
        assert_eq!(after.sp_seed, before.sp_seed);
        assert_eq!(after.ep_seed, before.ep_seed);
        assert_eq!(after.sh_proof, before.sh_proof);
        assert_eq!(after.eh_proof, before.eh_proof);
        assert_eq!(after.owner_auth, before.owner_auth);
        assert_eq!(after.endorsement_auth, before.endorsement_auth);
        assert_eq!(after.lockout_auth, before.lockout_auth);
        assert_eq!(
            after.platform_auth, before.platform_auth,
            "TPM2_ChangePPS keeps platformAuth"
        );
        assert_eq!(
            after.pp_seed_compat_level,
            runtime.state().profile.seed_compat_level()
        );
        assert_eq!(after.sp_seed_compat_level, before.sp_seed_compat_level);
        assert_eq!(after.ep_seed_compat_level, before.ep_seed_compat_level);

        let policies_after = policies(&runtime);
        assert_eq!(policies_after.platform, (TPM_ALG_NULL, Vec::new()));
        assert_eq!(policies_after.owner, policies_before.owner);
        assert_eq!(policies_after.endorsement, policies_before.endorsement);
        assert_eq!(policies_after.lockout, policies_before.lockout);
        for entry in &policies_after.pcr {
            assert_eq!(entry, &(TPM_ALG_NULL, Vec::new()));
        }
        assert_eq!(counters(&runtime), counters_before);
        assert_eq!(dictionary_attack_state(&runtime), dictionary_before);
        assert_nv_image_is_current(&runtime);

        for (label, bytes) in [
            ("PPS_CAP_TRANSIENT_AFTER", cap_transient()),
            ("PPS_CAP_PERSISTENT_AFTER", cap_persistent()),
            ("PPS_CAP_NV_AFTER", cap_nv()),
            ("PPS_CAP_STARTUP_CLEAR_AFTER", cap_startup_clear()),
            ("PPS_NV_READPUBLIC_OWNER_INDEX", nv_read_public(OWNER_INDEX)),
            (
                "PPS_NV_READPUBLIC_PLATFORM_INDEX",
                nv_read_public(PLATFORM_INDEX),
            ),
            (
                "PPS_READPUBLIC_OWNER_KEPT",
                read_public(TRANSIENT_FIRST + 1),
            ),
            (
                "PPS_PLATFORM_PRIMARY_AFTER",
                create_primary(TPM_RH_PLATFORM),
            ),
            ("PPS_OWNER_PRIMARY_AFTER", create_primary(TPM_RH_OWNER)),
            (
                "PPS_PLATFORM_POLICY_CLEARED",
                change_auth_command(TPM_RH_PLATFORM, &[], &[]),
            ),
        ] {
            expect(&mut runtime, &clock, label, &bytes);
        }
    }

    #[test]
    fn seed_change_orderly_state_clearing() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        exec(&mut runtime, &clock, &shutdown(1));
        expect(
            &mut runtime,
            &clock,
            "PPS_ORDERLY_CHANGE",
            &change_pps(TPM_RH_PLATFORM, &[]),
        );
        let mut rebooted = reboot(&runtime, &clock);
        expect(
            &mut rebooted,
            &clock,
            "PPS_ORDERLY_STARTUP_STATE",
            &startup(1),
        );
    }

    #[test]
    fn new_seed_permanent_state_round_trip() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        expect(
            &mut runtime,
            &clock,
            "PPS_CHANGE",
            &change_pps(TPM_RH_PLATFORM, &[]),
        );
        let expected = secrets(&runtime);
        let reloaded = reload(runtime.state());
        let persistent = &reloaded.persistent;
        assert_eq!(fingerprint(persistent.pp_seed.expose()), expected.pp_seed);
        assert_eq!(fingerprint(persistent.ph_proof.expose()), expected.ph_proof);
        assert_eq!(
            persistent.pp_seed_compat_level,
            expected.pp_seed_compat_level
        );
        for entry in &persistent.pcr_policies {
            assert_eq!(entry.hash_alg, TPM_ALG_NULL);
            assert!(entry.policy.is_empty());
        }
    }

    #[test]
    fn unavailable_nv_rejection_state_unchanged() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        runtime.nv_available = false;
        let before = snapshot(&runtime);
        let response = exec(&mut runtime, &clock, &change_pps(TPM_RH_PLATFORM, &[]));
        assert_eq!(response_code(&response), RC_NV_UNAVAILABLE);
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn host_commit_failure_tpm_failure_mode() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        let bytes = change_pps(TPM_RH_PLATFORM, &[]);
        let input = crate::library::CommandInput::new(bytes.len() as u32, bytes);
        let response = crate::library::tpm2::process::process(
            &mut runtime,
            crate::library::tpm2::PlatformInputs::at_locality(0),
            &input,
            &clock,
            |_| Err(crate::library::constants::TPM_RC_FAILURE),
            Cancellation::disabled(),
        )
        .expect("the command processes");
        assert_eq!(response, error_response(0x101));
        assert!(runtime.failure_mode);
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn nv_image_failure_draw_consumption_rollback() {
        use crate::library::tpm2::nv::build_nv_image;

        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        runtime
            .state
            .as_mut()
            .expect("state present")
            .persistent
            .owner_policy = vec![0x5a; 4096];
        assert!(
            build_nv_image(runtime.state()).is_err(),
            "the oversized owner policy must not serialize"
        );
        let before = snapshot(&runtime);
        let drbg_before = runtime.live.orderly.drbg_state.reseed_counter;

        let commits = core::cell::Cell::new(0u32);
        let response = exec_counting(
            &mut runtime,
            &clock,
            &change_pps(TPM_RH_PLATFORM, &[]),
            &commits,
        );
        assert_eq!(response_code(&response), 0x101);
        assert_eq!(commits.get(), 0);
        assert!(!runtime.failure_mode);
        assert_eq!(
            runtime.live.orderly.drbg_state.reseed_counter,
            drbg_before + 2,
            "the consumed draws are kept like the C generator"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn prefix_and_bit_flip_panic_safety() {
        let clock = replay_clock();
        let valid = change_pps(TPM_RH_PLATFORM, &[]);
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
                        Cancellation::disabled(),
                    );
                }
            }
        }
    }
}
