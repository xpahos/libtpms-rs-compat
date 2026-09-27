use super::session::{
    PolicySession, policy_digest, policy_session, start_policy_hash, store_policy_digest,
    zero_policy_digest,
};
use crate::library::constants::{TPM_RC_INSUFFICIENT, TPM_RC_SIZE, TPM_RC_VALUE};
use crate::library::tpm2::command::core::dispatcher::CommandFrame;
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::command::core::registry::TPM_CC_POLICY_OR;
use crate::library::tpm2::command::core::response_code::{TPM_RC_1, TPM_RC_P};
use crate::library::tpm2::marshal::{BlobReader, Tpm2bError};
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::session::digests_equal;
use crate::types::TpmResult;

const RC_POLICY_OR_P_HASH_LIST: TpmResult = TPM_RC_P + TPM_RC_1;

const MIN_DIGEST_COUNT: u32 = 2;
const MAX_DIGEST_COUNT: u32 = 8;
const MAX_DIGEST_SIZE: usize = 64;

fn parse_digest_list(parameters: &[u8]) -> Result<Vec<&[u8]>, TpmResult> {
    let mut reader = BlobReader::new(parameters);
    let count = reader
        .read_u32()
        .map_err(|_| TPM_RC_INSUFFICIENT + RC_POLICY_OR_P_HASH_LIST)?;
    if !(MIN_DIGEST_COUNT..=MAX_DIGEST_COUNT).contains(&count) {
        return Err(TPM_RC_SIZE + RC_POLICY_OR_P_HASH_LIST);
    }
    let mut digests = Vec::with_capacity(count as usize);
    for _ in 0..count {
        digests.push(
            reader
                .read_tpm2b(MAX_DIGEST_SIZE)
                .map_err(|error| match error {
                    Tpm2bError::Truncated => TPM_RC_INSUFFICIENT + RC_POLICY_OR_P_HASH_LIST,
                    Tpm2bError::SizeExceeded { .. } => TPM_RC_SIZE + RC_POLICY_OR_P_HASH_LIST,
                })?,
        );
    }
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(digests)
}

fn branch_matches(current: &[u8], candidate: &[u8]) -> bool {
    digests_equal(current, candidate)
}

fn rebuild_digest(
    runtime: &mut Tpm2Runtime,
    session: &PolicySession,
    digests: &[&[u8]],
) -> Result<(), TpmResult> {
    let zeroed = zero_policy_digest(session.hash_alg)?;
    let mut hasher = start_policy_hash(runtime, session.hash_alg)?;
    hasher.update(&zeroed);
    hasher.update(&TPM_CC_POLICY_OR.to_be_bytes());
    for digest in digests {
        hasher.update(digest);
    }
    let updated = hasher.finalize();
    store_policy_digest(runtime, session.handle, updated)
}

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let session = policy_session(runtime, frame)?;
    let digests = parse_digest_list(frame.parameters)?;

    let current = policy_digest(runtime, session.handle)?;
    let matched = session.is_trial
        || digests
            .iter()
            .any(|candidate| branch_matches(&current, candidate));
    if !matched {
        return Err(TPM_RC_VALUE + RC_POLICY_OR_P_HASH_LIST);
    }

    rebuild_digest(runtime, &session, &digests)?;
    Ok(CommandOutput::empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::library::tpm2::command::core::test_support::{
        RC_SUCCESS, TAIL_BYTES, command, dispatch_bytes, for_each_mutation, response_code,
        response_parameters, truncated_tail_replacements,
    };
    use crate::library::tpm2::command::policy::session::test_support::{
        CC_POLICY_AUTH_VALUE, CC_POLICY_OR, CC_START_AUTH_SESSION, POLICY_SESSION_0, digest,
        restored, session_of,
    };
    use crate::library::tpm2::golden_responses::policy_sessions::vector;

    const BRANCH_A: [u8; 32] = [0x11; 32];
    const BRANCH_B: [u8; 32] = [0x22; 32];
    const ZERO: [u8; 32] = [0x00; 32];

    fn digest_list(digests: &[&[u8]]) -> Vec<u8> {
        list_with_count(digests, digests.len() as u32)
    }

    fn list_with_count(digests: &[&[u8]], count: u32) -> Vec<u8> {
        let mut out = count.to_be_bytes().to_vec();
        for digest in digests {
            out.extend_from_slice(&(digest.len() as u16).to_be_bytes());
            out.extend_from_slice(digest);
        }
        out
    }

    #[track_caller]
    fn policy_or(runtime: &mut Tpm2Runtime, parameters: &[u8]) -> Vec<u8> {
        dispatch_bytes(
            runtime,
            &command(CC_POLICY_OR, &[POLICY_SESSION_0], &[], parameters),
        )
    }

    #[test]
    fn matching_branch_digest_rebuild() {
        let mut runtime = restored("POLICY_FRESH");
        assert_eq!(
            policy_or(&mut runtime, &digest_list(&[&BRANCH_A, &BRANCH_B])),
            vector("POR_NO_MATCH")
        );
        assert_eq!(
            policy_or(&mut runtime, &digest_list(&[&ZERO, &BRANCH_A])),
            vector("POR_MATCH_FIRST")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_MATCH_FIRST"));
    }

    #[test]
    fn any_position_match_same_list_digest() {
        let mut runtime = restored("POLICY_FRESH");
        assert_eq!(
            policy_or(&mut runtime, &digest_list(&[&BRANCH_A, &ZERO])),
            vector("POR_MATCH_SECOND")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_MATCH_SECOND"));
    }

    #[test]
    fn maximum_branch_count_acceptance() {
        let mut runtime = restored("POLICY_FRESH");
        let branches: Vec<&[u8]> = core::iter::once(&ZERO[..])
            .chain(core::iter::repeat_n(&BRANCH_A[..], 7))
            .collect();
        assert_eq!(
            policy_or(&mut runtime, &digest_list(&branches)),
            vector("POR_EIGHT_BRANCHES")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_EIGHT_BRANCHES"));
    }

    #[test]
    fn malformed_branch_list_oracle_parity() {
        let mut runtime = restored("POLICY_FRESH");
        let nine: Vec<&[u8]> = core::iter::repeat_n(&ZERO[..], 9).collect();
        let short = [0u8; 20];
        let oversized = [0u8; 65];
        for (record, parameters) in [
            ("POR_ONE_BRANCH", digest_list(&[&ZERO])),
            ("POR_NINE_BRANCHES", digest_list(&nine)),
            ("POR_ZERO_BRANCHES", digest_list(&[])),
            ("POR_COUNT_WITHOUT_DIGESTS", list_with_count(&[], 2)),
            ("POR_SHORT_DIGEST", digest_list(&[&short, &BRANCH_A])),
            (
                "POR_OVERSIZED_DIGEST",
                digest_list(&[&oversized, &BRANCH_A]),
            ),
            ("POR_TRAILING", {
                let mut out = digest_list(&[&ZERO, &BRANCH_A]);
                out.push(0x00);
                out
            }),
        ] {
            assert_eq!(
                policy_or(&mut runtime, &parameters),
                vector(record),
                "{record}"
            );
        }
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_OR_FAILURES"));
    }

    #[test]
    fn trial_session_any_branch_list_acceptance() {
        let mut runtime = restored("TRIAL_FRESH");
        assert_eq!(
            policy_or(&mut runtime, &digest_list(&[&BRANCH_A, &BRANCH_B])),
            vector("TRIAL_POR_NO_MATCH")
        );
        assert_eq!(digest(&mut runtime), vector("TRIAL_PGD_AFTER_OR"));
    }

    #[test]
    fn sha1_session_digest_size_match() {
        let mut runtime = restored("READY");
        let mut parameters = 20u16.to_be_bytes().to_vec();
        parameters.extend_from_slice(&[0x5a; 20]);
        parameters.extend_from_slice(&0u16.to_be_bytes());
        parameters.push(0x01);
        parameters.extend_from_slice(&[0x00, 0x10]);
        parameters.extend_from_slice(&0x0004u16.to_be_bytes());
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &command(
                    CC_START_AUTH_SESSION,
                    &[0x4000_0007, 0x4000_0007],
                    &[],
                    &parameters
                )
            )),
            RC_SUCCESS
        );
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &command(CC_POLICY_AUTH_VALUE, &[POLICY_SESSION_0], &[], &[])
            )),
            RC_SUCCESS
        );
        let current = response_parameters(&digest(&mut runtime))[2..].to_vec();
        assert_eq!(current.len(), 20);
        assert_eq!(
            policy_or(&mut runtime, &digest_list(&[&current, &BRANCH_A[..20]])),
            vector("SHA1_POR_MATCH")
        );
        assert_eq!(digest(&mut runtime), vector("SHA1_PGD_AFTER_OR"));
    }

    #[test]
    fn rejected_branch_list_session_unchanged() {
        let mut runtime = restored("POLICY_FRESH");
        let before = session_of(&runtime, POLICY_SESSION_0).clone();
        let short = [0u8; 20];
        for parameters in [
            digest_list(&[&BRANCH_A, &BRANCH_B]),
            digest_list(&[&ZERO]),
            list_with_count(&[], 2),
            digest_list(&[&short, &BRANCH_A]),
        ] {
            assert_ne!(
                response_code(&policy_or(&mut runtime, &parameters)),
                RC_SUCCESS
            );
            let after = session_of(&runtime, POLICY_SESSION_0);
            assert_eq!(after.audit_digest, before.audit_digest);
            assert_eq!(after.attributes, before.attributes);
        }
    }

    #[test]
    fn successful_selection_digest_only_change() {
        let mut runtime = restored("POLICY_FRESH");
        let before = session_of(&runtime, POLICY_SESSION_0).clone();
        assert_eq!(
            policy_or(&mut runtime, &digest_list(&[&ZERO, &BRANCH_A])),
            vector("POR_MATCH_FIRST")
        );
        let after = session_of(&runtime, POLICY_SESSION_0);
        assert_ne!(after.audit_digest, before.audit_digest);
        assert_eq!(after.attributes, before.attributes);
        assert_eq!(after.command_code, before.command_code);
        assert_eq!(after.pcr_counter, before.pcr_counter);
        assert_eq!(after.nonce_tpm.as_bytes(), before.nonce_tpm.as_bytes());
    }

    #[test]
    fn branch_comparison_length_before_content() {
        assert!(branch_matches(&[1, 2, 3], &[1, 2, 3]));
        assert!(!branch_matches(&[1, 2, 3], &[1, 2]));
        assert!(!branch_matches(&[1, 2], &[1, 2, 3]));
        assert!(!branch_matches(&[1, 2, 3], &[1, 2, 4]));
        assert!(branch_matches(&[], &[]));
    }

    #[test]
    fn parameter_mutation_panic_safety() {
        let valid = command(
            CC_POLICY_OR,
            &[POLICY_SESSION_0],
            &[],
            &digest_list(&[&ZERO, &BRANCH_A]),
        );
        for_each_mutation(
            "TPM2_PolicyOR",
            truncated_tail_replacements(&valid, 10, &TAIL_BYTES),
            |bytes| {
                let _ = dispatch_bytes(&mut restored("POLICY_FRESH"), &bytes);
            },
        );
    }
}
