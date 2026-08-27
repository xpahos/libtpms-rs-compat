use super::primary_policy::hash_algorithm_allowed;
use super::{commit_persistent_state, digest_size_of, with_rollback};
use crate::ffi::types::TpmResult;
use crate::library::constants::{
    TPM_RC_FAILURE, TPM_RC_HASH, TPM_RC_INSUFFICIENT, TPM_RC_NV_UNAVAILABLE, TPM_RC_SIZE,
    TPM_RC_VALUE,
};
use crate::library::tpm2::command::core::dispatcher::CommandFrame;
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::hierarchy::TPM_RH_PLATFORM;
use crate::library::tpm2::marshal::{BlobReader, Tpm2bError};
use crate::library::tpm2::pcr::pcr_policy_group;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::volatile::IMPLEMENTATION_PCR;

const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;
const TPM_RC_2: TpmResult = 0x200;
const TPM_RC_3: TpmResult = 0x300;
const RC_AUTH_POLICY: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_HASH_ALG: TpmResult = TPM_RC_P + TPM_RC_2;
const RC_PCR_NUM: TpmResult = TPM_RC_P + TPM_RC_3;

const MAX_DIGEST_SIZE: usize = 64;

struct PcrSetAuthPolicyIn<'a> {
    auth_policy: &'a [u8],
    hash_alg: u16,
    pcr_num: u32,
}

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let auth_handle = frame.handles.first().copied().ok_or(TPM_RC_FAILURE)?;
    if auth_handle != TPM_RH_PLATFORM {
        return Err(TPM_RC_FAILURE);
    }
    let input = {
        // TODO: Support runtimes without decoded state after the NVChip fallback
        // is implemented.
        let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
        parse_parameters(&state.profile.algorithms, frame.parameters)?
    };

    if !runtime.nv_available {
        return Err(TPM_RC_NV_UNAVAILABLE);
    }
    if input.auth_policy.len() != digest_size_of(input.hash_alg) {
        return Err(TPM_RC_SIZE + RC_AUTH_POLICY);
    }
    let Some(group) = pcr_policy_group(input.pcr_num as usize) else {
        return Err(TPM_RC_VALUE + RC_PCR_NUM);
    };

    let hash_alg = input.hash_alg;
    let auth_policy = input.auth_policy.to_vec();
    with_rollback(runtime, |runtime| {
        let entry = runtime
            .state
            .as_mut()
            .ok_or(TPM_RC_FAILURE)?
            .persistent
            .pcr_policies
            .get_mut(group)
            .ok_or(TPM_RC_FAILURE)?;
        entry.hash_alg = hash_alg;
        entry.policy = auth_policy;
        commit_persistent_state(runtime)
    })?;
    Ok(CommandOutput::empty())
}

fn parse_parameters<'a>(
    profile_algorithms: &[u8],
    parameters: &'a [u8],
) -> Result<PcrSetAuthPolicyIn<'a>, TpmResult> {
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
    let pcr_num = reader
        .read_u32()
        .map_err(|_| TPM_RC_INSUFFICIENT + RC_PCR_NUM)?;
    if pcr_num as usize >= IMPLEMENTATION_PCR {
        return Err(TPM_RC_VALUE + RC_PCR_NUM);
    }
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(PcrSetAuthPolicyIn {
        auth_policy,
        hash_alg,
        pcr_num,
    })
}

#[cfg(test)]
mod tests {
    use crate::library::tpm2::command::core::registry::{
        CommandLifecycle, HandleKind, NvAccess, TPM_CC_PCR_SET_AUTH_POLICY, find,
    };
    use crate::library::tpm2::command::core::test_support::{command, framed, response_code};
    use crate::library::tpm2::command::hierarchy::test_support::{
        DIGEST, RC_NV_UNAVAILABLE, TPM_ALG_NULL, TPM_ALG_SHA256, assert_unchanged,
        cap_command_attributes, commits_for, exec, expect, oracle_runtime, pcr_set_auth_policy,
        reload, replay, replay_clock, snapshot,
    };
    use crate::library::tpm2::hierarchy::{
        TPM_RH_LOCKOUT, TPM_RH_NULL, TPM_RH_OWNER, TPM_RH_PLATFORM,
    };
    use crate::library::tpm2::pcr::pcr_policy_group;
    use crate::library::tpm2::persistent::OwnedPcrPolicyEntry;
    use crate::library::tpm2::volatile::IMPLEMENTATION_PCR;

    const TPM_ALG_ECB: u16 = 0x0044;

    #[test]
    fn the_command_is_registered_with_the_upstream_attributes() {
        let descriptor = find(TPM_CC_PCR_SET_AUTH_POLICY).expect("the command is registered");
        assert_eq!(descriptor.attributes, 0x0240_012c);
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
        assert!(matches!(descriptor.handles[0].kind, HandleKind::Platform));
    }

    #[test]
    fn the_reported_command_attributes_match_the_reference() {
        replay(&[(
            "CCATTR_012C",
            cap_command_attributes(TPM_CC_PCR_SET_AUTH_POLICY),
        )]);
    }

    #[test]
    fn no_implemented_pcr_belongs_to_an_authorization_policy_group() {
        for pcr in 0..IMPLEMENTATION_PCR {
            assert_eq!(
                pcr_policy_group(pcr),
                None,
                "the vendored platform table puts PCR {pcr} in group zero"
            );
        }
    }

    #[test]
    fn every_pcr_is_rejected_like_the_reference() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        let before = snapshot(&runtime);
        for pcr in [0u32, 16, 19, 20, 21, 22, 23] {
            expect(
                &mut runtime,
                &clock,
                &format!("PSAP_PCR_{pcr:02}"),
                &pcr_set_auth_policy(TPM_RH_PLATFORM, &DIGEST, TPM_ALG_SHA256, pcr, &[]),
            );
        }
        for (label, bytes) in [
            (
                "PSAP_PCR_20_EMPTY_NULL",
                pcr_set_auth_policy(TPM_RH_PLATFORM, &[], TPM_ALG_NULL, 20, &[]),
            ),
            (
                "PSAP_PCR_24",
                pcr_set_auth_policy(TPM_RH_PLATFORM, &DIGEST, TPM_ALG_SHA256, 24, &[]),
            ),
            (
                "PSAP_PCR_NULL_HANDLE",
                pcr_set_auth_policy(TPM_RH_PLATFORM, &DIGEST, TPM_ALG_SHA256, TPM_RH_NULL, &[]),
            ),
        ] {
            expect(&mut runtime, &clock, label, &bytes);
        }
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn the_handle_and_parameter_errors_match_the_reference() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        let before = snapshot(&runtime);
        for (label, bytes) in [
            (
                "PSAP_SIZE_MISMATCH",
                pcr_set_auth_policy(TPM_RH_PLATFORM, &DIGEST[..16], TPM_ALG_SHA256, 20, &[]),
            ),
            (
                "PSAP_NULL_ALG_WITH_DIGEST",
                pcr_set_auth_policy(TPM_RH_PLATFORM, &DIGEST, TPM_ALG_NULL, 20, &[]),
            ),
            (
                "PSAP_BAD_ALG",
                pcr_set_auth_policy(TPM_RH_PLATFORM, &[], TPM_ALG_ECB, 20, &[]),
            ),
            (
                "PSAP_BY_OWNER",
                pcr_set_auth_policy(TPM_RH_OWNER, &[], TPM_ALG_NULL, 20, &[]),
            ),
            (
                "PSAP_BY_LOCKOUT",
                pcr_set_auth_policy(TPM_RH_LOCKOUT, &[], TPM_ALG_NULL, 20, &[]),
            ),
            (
                "PSAP_TRUNCATED_PCR",
                command(
                    TPM_CC_PCR_SET_AUTH_POLICY,
                    &[TPM_RH_PLATFORM],
                    &[&[]],
                    &[0x00, 0x00, 0x00, 0x10, 0x00, 0x00],
                ),
            ),
            (
                "PSAP_MISSING_PCR",
                command(
                    TPM_CC_PCR_SET_AUTH_POLICY,
                    &[TPM_RH_PLATFORM],
                    &[&[]],
                    &[0x00, 0x00, 0x00, 0x10],
                ),
            ),
            (
                "PSAP_TRUNCATED_ALG",
                command(
                    TPM_CC_PCR_SET_AUTH_POLICY,
                    &[TPM_RH_PLATFORM],
                    &[&[]],
                    &[0x00, 0x00, 0x00],
                ),
            ),
            (
                "PSAP_TRAILING",
                command(
                    TPM_CC_PCR_SET_AUTH_POLICY,
                    &[TPM_RH_PLATFORM],
                    &[&[]],
                    &[0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x14, 0xee],
                ),
            ),
            (
                "PSAP_NO_SESSIONS",
                framed(
                    TPM_CC_PCR_SET_AUTH_POLICY,
                    &[
                        &TPM_RH_PLATFORM.to_be_bytes()[..],
                        &[0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x14][..],
                    ]
                    .concat(),
                    false,
                ),
            ),
            (
                "PSAP_WRONG_PASSWORD",
                pcr_set_auth_policy(TPM_RH_PLATFORM, &[], TPM_ALG_NULL, 20, b"wrong"),
            ),
            (
                "PSAP_TRUNCATED_HANDLE",
                framed(
                    TPM_CC_PCR_SET_AUTH_POLICY,
                    &TPM_RH_PLATFORM.to_be_bytes()[..2],
                    true,
                ),
            ),
        ] {
            expect(&mut runtime, &clock, label, &bytes);
        }
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn an_unavailable_nv_is_reported_before_the_digest_size() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        runtime.nv_available = false;
        let before = snapshot(&runtime);
        let response = exec(
            &mut runtime,
            &clock,
            &pcr_set_auth_policy(TPM_RH_PLATFORM, &DIGEST[..16], TPM_ALG_SHA256, 20, &[]),
        );
        assert_eq!(response_code(&response), RC_NV_UNAVAILABLE);
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn no_request_ever_commits_an_nv_update() {
        for bytes in [
            pcr_set_auth_policy(TPM_RH_PLATFORM, &DIGEST, TPM_ALG_SHA256, 20, &[]),
            pcr_set_auth_policy(TPM_RH_PLATFORM, &[], TPM_ALG_NULL, 0, &[]),
            pcr_set_auth_policy(TPM_RH_OWNER, &[], TPM_ALG_NULL, 20, &[]),
        ] {
            assert_eq!(commits_for(&bytes), 0);
        }
    }

    #[test]
    fn a_stored_pcr_policy_survives_a_permanent_state_round_trip() {
        let clock = replay_clock();
        let mut runtime = oracle_runtime(&clock);
        {
            let entries = &mut runtime
                .state
                .as_mut()
                .expect("state present")
                .persistent
                .pcr_policies;
            for entry in entries.iter_mut() {
                *entry = OwnedPcrPolicyEntry {
                    hash_alg: TPM_ALG_SHA256,
                    policy: DIGEST.to_vec(),
                };
            }
        }
        let reloaded = reload(runtime.state());
        for entry in &reloaded.persistent.pcr_policies {
            assert_eq!(entry.hash_alg, TPM_ALG_SHA256);
            assert_eq!(entry.policy, DIGEST.to_vec());
        }
    }

    #[test]
    fn prefixes_and_bit_flips_do_not_panic() {
        let clock = replay_clock();
        let valid = pcr_set_auth_policy(TPM_RH_PLATFORM, &DIGEST, TPM_ALG_SHA256, 20, &[]);
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
