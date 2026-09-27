use super::primary_policy::hash_algorithm_allowed;
use super::{digest_size_of, with_persistent_rollback};
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
use crate::types::TpmResult;

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
    with_persistent_rollback(runtime, |persistent| {
        let entry = persistent
            .pcr_policies
            .get_mut(group)
            .ok_or(TPM_RC_FAILURE)?;
        entry.hash_alg = hash_alg;
        entry.policy = auth_policy;
        Ok(())
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

    use crate::library::tpm2::command::core::registry::TPM_CC_PCR_SET_AUTH_POLICY;
    use crate::library::tpm2::command::core::test_support::{
        command, for_each_mutation, framed, prefix_bit_flips, response_code,
    };
    use crate::library::tpm2::command::hierarchy::test_support::{
        DIGEST, RC_NV_UNAVAILABLE, TPM_ALG_NULL, TPM_ALG_SHA256, assert_unchanged, commits_for,
        exec, expect, oracle_runtime, pcr_set_auth_policy, reload, replay_clock, snapshot,
        try_exec,
    };
    use crate::library::tpm2::hierarchy::{
        TPM_RH_LOCKOUT, TPM_RH_NULL, TPM_RH_OWNER, TPM_RH_PLATFORM,
    };
    use crate::library::tpm2::pcr::pcr_policy_group;
    use crate::library::tpm2::persistent::OwnedPcrPolicyEntry;
    use crate::library::tpm2::volatile::IMPLEMENTATION_PCR;

    const TPM_ALG_ECB: u16 = 0x0044;

    #[test]
    fn implemented_pcr_policy_group_absence() {
        for pcr in 0..IMPLEMENTATION_PCR {
            assert_eq!(
                pcr_policy_group(pcr),
                None,
                "the vendored platform table puts PCR {pcr} in group zero"
            );
        }
    }

    #[test]
    fn per_pcr_rejection_reference_match() {
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
    fn handle_parameter_error_reference_match() {
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
    fn unavailable_nv_pre_digest_size_order() {
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
    fn nv_update_commit_absence() {
        for bytes in [
            pcr_set_auth_policy(TPM_RH_PLATFORM, &DIGEST, TPM_ALG_SHA256, 20, &[]),
            pcr_set_auth_policy(TPM_RH_PLATFORM, &[], TPM_ALG_NULL, 0, &[]),
            pcr_set_auth_policy(TPM_RH_OWNER, &[], TPM_ALG_NULL, 20, &[]),
        ] {
            assert_eq!(commits_for(&bytes), 0);
        }
    }

    #[test]
    fn stored_policy_permanent_round_trip() {
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
    fn prefix_and_bit_flip_panic_safety() {
        let clock = replay_clock();
        let valid = pcr_set_auth_policy(TPM_RH_PLATFORM, &DIGEST, TPM_ALG_SHA256, 20, &[]);
        for_each_mutation(
            "TPM2_PCR_SetAuthPolicy",
            prefix_bit_flips(&valid, 0, 0, false),
            |bytes| {
                let _ = try_exec(&mut oracle_runtime(&clock), &clock, &bytes);
            },
        );
    }
}
