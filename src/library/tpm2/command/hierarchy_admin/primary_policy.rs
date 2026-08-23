use crate::ffi_types::TpmResult;
use crate::library::constants::{
    TPM_RC_FAILURE, TPM_RC_HASH, TPM_RC_INSUFFICIENT, TPM_RC_NV_UNAVAILABLE, TPM_RC_SIZE,
};

use super::super::super::algorithm::{TPM_ALG_NULL, algorithm_enabled, hash_profile_name};
use super::super::super::crypto::COMPILED_HASHES;
use super::super::super::hierarchy::{
    TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT, TPM_RH_OWNER, TPM_RH_PLATFORM,
};
use super::super::super::marshal::{BlobReader, Tpm2bError};
use super::super::super::orderly::{commit_clear_orderly, prepare_clear_orderly};
use super::super::super::runtime::Tpm2Runtime;
use super::super::dispatcher::CommandFrame;
use super::super::output::CommandOutput;
use super::{commit_persistent_state, with_rollback};

const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;
const TPM_RC_2: TpmResult = 0x200;
const RC_AUTH_POLICY: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_HASH_ALG: TpmResult = TPM_RC_P + TPM_RC_2;

const MAX_DIGEST_SIZE: usize = 64;

struct SetPrimaryPolicyIn<'a> {
    auth_policy: &'a [u8],
    hash_alg: u16,
}

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let auth_handle = frame.handles.first().copied().ok_or(TPM_RC_FAILURE)?;
    let input = {
        // TODO: Support runtimes without decoded state after the NVChip fallback
        // is implemented.
        let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
        parse_parameters(&state.profile.algorithms, frame.parameters)?
    };

    if input.auth_policy.len() != super::digest_size_of(input.hash_alg) {
        return Err(TPM_RC_SIZE + RC_AUTH_POLICY);
    }
    if !runtime.nv_available {
        return Err(TPM_RC_NV_UNAVAILABLE);
    }

    let hash_alg = input.hash_alg;
    let auth_policy = input.auth_policy.to_vec();
    match auth_handle {
        TPM_RH_PLATFORM => {
            let orderly_state = prepare_clear_orderly(runtime)?;
            with_rollback(runtime, |runtime| {
                let clear = runtime.live.state_clear.as_mut().ok_or(TPM_RC_FAILURE)?;
                clear.platform_alg = hash_alg;
                clear.platform_policy = auth_policy;
                commit_clear_orderly(runtime, orderly_state)
            })
        }
        TPM_RH_OWNER | TPM_RH_ENDORSEMENT | TPM_RH_LOCKOUT => with_rollback(runtime, |runtime| {
            let persistent = &mut runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?.persistent;
            match auth_handle {
                TPM_RH_OWNER => {
                    persistent.owner_alg = hash_alg;
                    persistent.owner_policy = auth_policy;
                }
                TPM_RH_ENDORSEMENT => {
                    persistent.endorsement_alg = hash_alg;
                    persistent.endorsement_policy = auth_policy;
                }
                _ => {
                    persistent.lockout_alg = hash_alg;
                    persistent.lockout_policy = auth_policy;
                }
            }
            commit_persistent_state(runtime)
        }),
        _ => Err(TPM_RC_FAILURE),
    }?;
    Ok(CommandOutput::empty())
}

fn parse_parameters<'a>(
    profile_algorithms: &[u8],
    parameters: &'a [u8],
) -> Result<SetPrimaryPolicyIn<'a>, TpmResult> {
    let mut reader = BlobReader::new(parameters);
    let auth_policy = reader
        .read_tpm2b(MAX_DIGEST_SIZE)
        .map_err(|error| match error {
            Tpm2bError::Truncated => TPM_RC_INSUFFICIENT + RC_AUTH_POLICY,
            Tpm2bError::SizeExceeded { .. } => TPM_RC_SIZE + RC_AUTH_POLICY,
        })?;
    let hash_alg = reader
        .read_u16()
        .map_err(|_| TPM_RC_INSUFFICIENT + RC_HASH_ALG)?;
    if !hash_algorithm_allowed(profile_algorithms, hash_alg) {
        return Err(TPM_RC_HASH + RC_HASH_ALG);
    }
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(SetPrimaryPolicyIn {
        auth_policy,
        hash_alg,
    })
}

pub(in crate::library::tpm2::command) fn hash_algorithm_allowed(
    profile_algorithms: &[u8],
    hash_alg: u16,
) -> bool {
    if hash_alg == TPM_ALG_NULL {
        return true;
    }
    COMPILED_HASHES.iter().any(|&(alg, _)| alg == hash_alg)
        && hash_profile_name(hash_alg)
            .is_some_and(|name| algorithm_enabled(profile_algorithms, name))
}

#[cfg(test)]
mod tests {
    use super::super::super::registry::{
        CommandLifecycle, HandleKind, NvAccess, TPM_CC_SET_PRIMARY_POLICY, find,
    };
    use super::super::harness::*;
    use crate::library::tpm2::hierarchy::{
        TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT, TPM_RH_NULL, TPM_RH_OWNER, TPM_RH_PLATFORM,
        TPM_RH_PLATFORM_NV, TPM_RS_PW,
    };

    const TPM_ALG_SHA1: u16 = 0x0004;
    const TPM_ALG_SHA384: u16 = 0x000c;
    const TPM_ALG_ECB: u16 = 0x0044;

    #[test]
    fn the_command_is_registered_with_the_upstream_attributes() {
        let descriptor = find(TPM_CC_SET_PRIMARY_POLICY).expect("the command is registered");
        assert_eq!(descriptor.attributes, 0x0240_012e);
        assert!(descriptor.physical_presence);
        assert!(descriptor.sessions_allowed);
        assert_eq!(descriptor.decrypt_size, 2);
        assert_eq!(descriptor.encrypt_size, 0);
        assert!(matches!(descriptor.nv_access, NvAccess::Neither));
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
        assert_eq!(descriptor.handles.len(), 1);
        assert!(descriptor.handles[0].user_auth);
        assert!(matches!(
            descriptor.handles[0].kind,
            HandleKind::HierarchyAuth
        ));
    }

    #[test]
    fn the_authorization_handle_takes_only_the_four_hierarchy_policies() {
        let kind = find(TPM_CC_SET_PRIMARY_POLICY).unwrap().handles[0].kind;
        for handle in [
            TPM_RH_OWNER,
            TPM_RH_ENDORSEMENT,
            TPM_RH_PLATFORM,
            TPM_RH_LOCKOUT,
        ] {
            assert!(kind.accepts(handle), "handle {handle:#x}");
        }
        for handle in [
            TPM_RH_NULL,
            TPM_RH_PLATFORM_NV,
            TPM_RS_PW,
            0x4000_0110,
            0x4000_011f,
            0,
            0x0100_0000,
            0x8000_0000,
            u32::MAX,
        ] {
            assert!(!kind.accepts(handle), "handle {handle:#x}");
        }
    }

    #[test]
    fn the_reported_command_attributes_match_the_reference() {
        replay(&[(
            "CCATTR_012E",
            cap_command_attributes(TPM_CC_SET_PRIMARY_POLICY),
        )]);
    }

    #[test]
    fn every_hierarchy_policy_is_set_and_cleared_like_the_reference() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        for (label, handle) in [
            ("SPP_SET_OWNER", TPM_RH_OWNER),
            ("SPP_SET_ENDORSEMENT", TPM_RH_ENDORSEMENT),
            ("SPP_SET_PLATFORM", TPM_RH_PLATFORM),
            ("SPP_SET_LOCKOUT", TPM_RH_LOCKOUT),
        ] {
            expect(
                &mut runtime,
                &clock,
                label,
                &set_primary_policy(handle, &DIGEST, TPM_ALG_SHA256, &[]),
            );
        }
        expect(
            &mut runtime,
            &clock,
            "SPP_CAP_STARTUP_CLEAR",
            &cap_startup_clear(),
        );
        let set = policies(&runtime);
        let expected = (TPM_ALG_SHA256, DIGEST.to_vec());
        assert_eq!(set.owner, expected);
        assert_eq!(set.endorsement, expected);
        assert_eq!(set.platform, expected);
        assert_eq!(set.lockout, expected);
        assert_nv_image_is_current(&runtime);

        for (label, handle) in [
            ("SPP_CLEAR_OWNER", TPM_RH_OWNER),
            ("SPP_CLEAR_ENDORSEMENT", TPM_RH_ENDORSEMENT),
            ("SPP_CLEAR_PLATFORM", TPM_RH_PLATFORM),
            ("SPP_CLEAR_LOCKOUT", TPM_RH_LOCKOUT),
        ] {
            expect(
                &mut runtime,
                &clock,
                label,
                &set_primary_policy(handle, &[], TPM_ALG_NULL, &[]),
            );
        }
        let cleared = policies(&runtime);
        let empty = (TPM_ALG_NULL, Vec::new());
        assert_eq!(cleared.owner, empty);
        assert_eq!(cleared.endorsement, empty);
        assert_eq!(cleared.platform, empty);
        assert_eq!(cleared.lockout, empty);

        for (label, digest, alg) in [
            ("SPP_SET_SHA1_OWNER", DIGEST[..20].to_vec(), TPM_ALG_SHA1),
            (
                "SPP_SET_SHA384_OWNER",
                [&DIGEST[..], &DIGEST[..16]].concat(),
                TPM_ALG_SHA384,
            ),
        ] {
            expect(
                &mut runtime,
                &clock,
                label,
                &set_primary_policy(TPM_RH_OWNER, &digest, alg, &[]),
            );
            assert_eq!(policies(&runtime).owner, (alg, digest));
        }
    }

    #[test]
    fn setting_one_hierarchy_leaves_the_others_alone() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        let before = policies(&runtime);
        expect(
            &mut runtime,
            &clock,
            "SPP_SET_OWNER",
            &set_primary_policy(TPM_RH_OWNER, &DIGEST, TPM_ALG_SHA256, &[]),
        );
        let after = policies(&runtime);
        assert_eq!(after.owner, (TPM_ALG_SHA256, DIGEST.to_vec()));
        assert_eq!(after.endorsement, before.endorsement);
        assert_eq!(after.lockout, before.lockout);
        assert_eq!(after.platform, before.platform);
        assert_eq!(after.pcr, before.pcr);
        assert_eq!(secrets(&runtime), secrets(&oracle_runtime(&clock)));
    }

    #[test]
    fn the_handle_and_parameter_errors_match_the_reference() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        let before = snapshot(&runtime);
        for (label, bytes) in [
            (
                "SPP_BY_NULL",
                set_primary_policy(TPM_RH_NULL, &[], TPM_ALG_NULL, &[]),
            ),
            (
                "SPP_BY_PLATFORM_NV",
                set_primary_policy(TPM_RH_PLATFORM_NV, &[], TPM_ALG_NULL, &[]),
            ),
            (
                "SPP_BY_ACT_0",
                set_primary_policy(0x4000_0110, &[], TPM_ALG_NULL, &[]),
            ),
            (
                "SPP_BY_PW",
                set_primary_policy(TPM_RS_PW, &[], TPM_ALG_NULL, &[]),
            ),
            (
                "SPP_SIZE_MISMATCH_SHORT",
                set_primary_policy(TPM_RH_OWNER, &DIGEST[..16], TPM_ALG_SHA256, &[]),
            ),
            (
                "SPP_SIZE_MISMATCH_LONG",
                set_primary_policy(
                    TPM_RH_OWNER,
                    &[&DIGEST[..], &[0x00][..]].concat(),
                    TPM_ALG_SHA256,
                    &[],
                ),
            ),
            (
                "SPP_NULL_ALG_WITH_DIGEST",
                set_primary_policy(TPM_RH_OWNER, &DIGEST, TPM_ALG_NULL, &[]),
            ),
            (
                "SPP_BAD_ALG",
                set_primary_policy(TPM_RH_OWNER, &[], TPM_ALG_ECB, &[]),
            ),
            (
                "SPP_OVERSIZED_DIGEST",
                command(
                    TPM_CC_SET_PRIMARY_POLICY,
                    &[TPM_RH_OWNER],
                    &[&[]],
                    &[
                        &65u16.to_be_bytes()[..],
                        &[0u8; 65][..],
                        &TPM_ALG_SHA256.to_be_bytes()[..],
                    ]
                    .concat(),
                ),
            ),
            (
                "SPP_TRUNCATED_POLICY",
                command(
                    TPM_CC_SET_PRIMARY_POLICY,
                    &[TPM_RH_OWNER],
                    &[&[]],
                    &[0x00, 0x04, 0x00, 0x00],
                ),
            ),
            (
                "SPP_TRUNCATED_ALG",
                command(
                    TPM_CC_SET_PRIMARY_POLICY,
                    &[TPM_RH_OWNER],
                    &[&[]],
                    &[0x00, 0x00, 0x00],
                ),
            ),
            (
                "SPP_MISSING_PARAMETERS",
                command(TPM_CC_SET_PRIMARY_POLICY, &[TPM_RH_OWNER], &[&[]], &[]),
            ),
            (
                "SPP_TRAILING",
                command(
                    TPM_CC_SET_PRIMARY_POLICY,
                    &[TPM_RH_OWNER],
                    &[&[]],
                    &[0x00, 0x00, 0x00, 0x10, 0xee],
                ),
            ),
            (
                "SPP_NO_SESSIONS",
                framed(
                    TPM_CC_SET_PRIMARY_POLICY,
                    &[
                        &TPM_RH_OWNER.to_be_bytes()[..],
                        &[0x00, 0x00, 0x00, 0x10][..],
                    ]
                    .concat(),
                    false,
                ),
            ),
            (
                "SPP_WRONG_PASSWORD",
                set_primary_policy(TPM_RH_OWNER, &[], TPM_ALG_NULL, b"wrong"),
            ),
            (
                "SPP_TRUNCATED_HANDLE",
                framed(
                    TPM_CC_SET_PRIMARY_POLICY,
                    &TPM_RH_OWNER.to_be_bytes()[..3],
                    true,
                ),
            ),
        ] {
            expect(&mut runtime, &clock, label, &bytes);
        }
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn only_the_platform_policy_clears_the_orderly_state() {
        for (label, startup_label, handle, orderly) in [
            (
                "SPP_ORDERLY_PLATFORM",
                "SPP_ORDERLY_PLATFORM_STARTUP_STATE",
                TPM_RH_PLATFORM,
                false,
            ),
            (
                "SPP_ORDERLY_OWNER",
                "SPP_ORDERLY_OWNER_STARTUP_STATE",
                TPM_RH_OWNER,
                true,
            ),
        ] {
            let clock = replay_clock();
            let mut runtime = oracle_runtime(&clock);
            exec(&mut runtime, &clock, &shutdown(1));
            expect(
                &mut runtime,
                &clock,
                label,
                &set_primary_policy(handle, &DIGEST, TPM_ALG_SHA256, &[]),
            );
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
    fn the_new_policy_takes_effect_immediately_and_survives_a_round_trip() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        for handle in [TPM_RH_OWNER, TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT] {
            let response = exec(
                &mut runtime,
                &clock,
                &set_primary_policy(handle, &DIGEST, TPM_ALG_SHA256, &[]),
            );
            assert_eq!(response_code(&response), RC_SUCCESS);
        }
        let reloaded = reload(runtime.state());
        assert_eq!(reloaded.persistent.owner_alg, TPM_ALG_SHA256);
        assert_eq!(reloaded.persistent.owner_policy, DIGEST.to_vec());
        assert_eq!(reloaded.persistent.endorsement_alg, TPM_ALG_SHA256);
        assert_eq!(reloaded.persistent.endorsement_policy, DIGEST.to_vec());
        assert_eq!(reloaded.persistent.lockout_alg, TPM_ALG_SHA256);
        assert_eq!(reloaded.persistent.lockout_policy, DIGEST.to_vec());
    }

    #[test]
    fn the_platform_policy_lives_in_the_volatile_state_only() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        expect(
            &mut runtime,
            &clock,
            "SPP_SET_PLATFORM",
            &set_primary_policy(TPM_RH_PLATFORM, &DIGEST, TPM_ALG_SHA256, &[]),
        );
        assert_eq!(
            policies(&runtime).platform,
            (TPM_ALG_SHA256, DIGEST.to_vec())
        );
        let rebooted = reboot(&runtime, &clock);
        assert!(
            rebooted
                .live
                .state_clear
                .as_ref()
                .is_none_or(|clear| clear.platform_policy.is_empty()),
            "a reboot without saved state drops the platform policy"
        );
    }

    #[test]
    fn an_unavailable_nv_refuses_the_command_after_the_size_check() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        runtime.nv_available = false;
        let before = snapshot(&runtime);
        let response = exec(
            &mut runtime,
            &clock,
            &set_primary_policy(TPM_RH_OWNER, &DIGEST, TPM_ALG_SHA256, &[]),
        );
        assert_eq!(response_code(&response), RC_NV_UNAVAILABLE);
        assert_unchanged(&runtime, &before);

        let response = exec(
            &mut runtime,
            &clock,
            &set_primary_policy(TPM_RH_OWNER, &DIGEST[..16], TPM_ALG_SHA256, &[]),
        );
        assert_eq!(
            response_code(&response),
            0x1d5,
            "the digest size is checked before the NV availability"
        );
    }

    #[test]
    fn only_a_persistent_hierarchy_commits_an_nv_update() {
        assert_eq!(
            commits_for(&set_primary_policy(
                TPM_RH_OWNER,
                &DIGEST,
                TPM_ALG_SHA256,
                &[]
            )),
            1
        );
        assert_eq!(
            commits_for(&set_primary_policy(
                TPM_RH_PLATFORM,
                &DIGEST,
                TPM_ALG_SHA256,
                &[]
            )),
            0,
            "the platform policy is volatile and the state is already unorderly"
        );
        assert_eq!(
            commits_for(&set_primary_policy(TPM_RH_NULL, &[], TPM_ALG_NULL, &[])),
            0
        );
    }

    #[test]
    fn malformed_input_never_panics() {
        let clock = replay_clock();
        let valid = set_primary_policy(TPM_RH_OWNER, &DIGEST, TPM_ALG_SHA256, &[]);
        for len in 0..=valid.len() {
            for index in 0..len {
                for flip in [0x01u8, 0x80, 0xff] {
                    let mut mutated = valid[..len].to_vec();
                    mutated[index] ^= flip;
                    let mut runtime = oracle_runtime(&clock);
                    let input = crate::library::CommandInput::new(mutated.len() as u32, mutated);
                    let _ = crate::library::tpm2::process::process(
                        &mut runtime,
                        0,
                        &input,
                        &clock,
                        |_| Ok(()),
                    );
                }
            }
        }
    }
}
