use crate::ffi_types::TpmResult;
use crate::library::constants::{
    TPM_RC_FAILURE, TPM_RC_HASH, TPM_RC_SIZE, TPM_RC_TAG, TPM_RC_VALUE,
};

use super::super::algorithm::{algorithm_enabled, hash_profile_name};
use super::super::entity::entity_name;
use super::super::hierarchy::{TPM_RH_ENDORSEMENT, TPM_RH_NULL, TPM_RH_OWNER, TPM_RH_PLATFORM};
use super::super::nv::read_index_data;
use super::super::public::NAME_SIZE;
use super::super::runtime::Tpm2Runtime;
use super::super::self_test::self_test_algorithm;
use super::super::session::{digest_size, digests_equal};
use super::super::template::TemplateReader;
use super::super::ticket::{CONTEXT_INTEGRITY_HASH_ALG, TPM_ST_VERIFIED, compute_verified};
use super::dispatcher::CommandFrame;
use super::nv_common::{
    TPM_RC_1, TPM_RC_2, TPM_RC_3, TPM_RC_4, TPM_RC_P, handle_at, read_access_checks, resolve,
};
use super::output::CommandOutput;
use super::policy_common::{
    PolicyUpdate, hash_parts, live_session, policy_context_update, policy_digest_clear,
    policy_session_at,
};
use super::registry::{TPM_CC_POLICY_AUTHORIZE, TPM_CC_POLICY_AUTHORIZE_NV};
use super::signing::hierarchy_proof_for;

const RC_APPROVED_POLICY: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_POLICY_REF: TpmResult = TPM_RC_P + TPM_RC_2;
const RC_KEY_SIGN: TpmResult = TPM_RC_P + TPM_RC_3;
const RC_CHECK_TICKET: TpmResult = TPM_RC_P + TPM_RC_4;

const MAX_DIGEST_SIZE: usize = 64;
const TPMT_HA_SIZE: usize = 2 + MAX_DIGEST_SIZE;

struct Authorize<'a> {
    approved_policy: &'a [u8],
    policy_ref: &'a [u8],
    key_sign: &'a [u8],
    ticket_hierarchy: u32,
    ticket_digest: &'a [u8],
}

fn parse_authorize(parameters: &[u8]) -> Result<Authorize<'_>, TpmResult> {
    let mut reader = TemplateReader::new(parameters);
    let approved_policy = reader
        .tpm2b(MAX_DIGEST_SIZE)
        .map_err(|code| code + RC_APPROVED_POLICY)?;
    let policy_ref = reader
        .tpm2b(MAX_DIGEST_SIZE)
        .map_err(|code| code + RC_POLICY_REF)?;
    let key_sign = reader.tpm2b(NAME_SIZE).map_err(|code| code + RC_KEY_SIGN)?;
    let tag = reader.u16().map_err(|code| code + RC_CHECK_TICKET)?;
    if tag != TPM_ST_VERIFIED {
        return Err(TPM_RC_TAG + RC_CHECK_TICKET);
    }
    let ticket_hierarchy = reader.u32().map_err(|code| code + RC_CHECK_TICKET)?;
    if !matches!(
        ticket_hierarchy,
        TPM_RH_OWNER | TPM_RH_PLATFORM | TPM_RH_ENDORSEMENT | TPM_RH_NULL
    ) {
        return Err(TPM_RC_VALUE + RC_CHECK_TICKET);
    }
    let ticket_digest = reader
        .tpm2b(MAX_DIGEST_SIZE)
        .map_err(|code| code + RC_CHECK_TICKET)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(Authorize {
        approved_policy,
        policy_ref,
        key_sign,
        ticket_hierarchy,
        ticket_digest,
    })
}

fn name_algorithm(runtime: &Tpm2Runtime, key_sign: &[u8]) -> Result<u16, TpmResult> {
    if key_sign.len() < 2 {
        return Err(TPM_RC_SIZE + RC_KEY_SIGN);
    }
    let hash_alg = u16::from_be_bytes([key_sign[0], key_sign[1]]);
    let algorithms = &runtime
        .state
        .as_ref()
        .ok_or(TPM_RC_FAILURE)?
        .profile
        .algorithms;
    let enabled =
        hash_profile_name(hash_alg).is_some_and(|name| algorithm_enabled(algorithms, name));
    if !enabled {
        return Err(TPM_RC_HASH + RC_KEY_SIGN);
    }
    let size = digest_size(hash_alg).ok_or(TPM_RC_HASH + RC_KEY_SIGN)?;
    if size != key_sign.len() - 2 {
        return Err(TPM_RC_SIZE + RC_KEY_SIGN);
    }
    Ok(hash_alg)
}

pub(super) fn execute_authorize(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let session = policy_session_at(runtime, frame, 0)?;
    let input = parse_authorize(frame.parameters)?;
    let hash_alg = name_algorithm(runtime, input.key_sign)?;

    if !session.is_trial {
        let current = live_session(runtime, &session)?.audit_digest.clone();
        if !digests_equal(&current, input.approved_policy) {
            return Err(TPM_RC_VALUE + RC_APPROVED_POLICY);
        }
        let auth_hash = hash_parts(
            runtime,
            hash_alg,
            &[input.approved_policy, input.policy_ref],
        )?;
        self_test_algorithm(runtime, CONTEXT_INTEGRITY_HASH_ALG)?;
        let proof = hierarchy_proof_for(runtime, input.ticket_hierarchy)?;
        let expected = compute_verified(input.ticket_hierarchy, proof, &auth_hash, input.key_sign)
            .ok_or(TPM_RC_FAILURE)?;
        if !digests_equal(input.ticket_digest, &expected.digest) {
            return Err(TPM_RC_VALUE + RC_CHECK_TICKET);
        }
    }

    policy_digest_clear(runtime, &session)?;
    policy_context_update(
        runtime,
        &session,
        PolicyUpdate::new(TPM_CC_POLICY_AUTHORIZE)
            .with_name(input.key_sign)
            .with_policy_ref(input.policy_ref),
    )
    .map(|()| CommandOutput::empty())
}

pub(super) fn execute_authorize_nv(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let auth_handle = handle_at(frame, 0)?;
    let nv_handle = handle_at(frame, 1)?;
    let session = policy_session_at(runtime, frame, 2)?;
    if !frame.parameters.is_empty() {
        return Err(TPM_RC_SIZE);
    }

    if !session.is_trial {
        let resolved = resolve(runtime, nv_handle)?;
        read_access_checks(auth_handle, nv_handle, resolved.attributes())?;
        let length = usize::from(resolved.public.data_size).min(TPMT_HA_SIZE);
        let stored = read_index_data(runtime, &resolved, 0, length)?;
        let (stored_alg, stored_digest) = parse_stored_policy(runtime, &stored)?;
        if stored_alg != session.hash_alg {
            return Err(TPM_RC_HASH);
        }
        let current = live_session(runtime, &session)?.audit_digest.clone();
        if stored_digest.len() < current.len()
            || !digests_equal(&stored_digest[..current.len()], &current)
        {
            return Err(TPM_RC_VALUE);
        }
    }

    let name = entity_name(runtime, nv_handle)?;
    policy_digest_clear(runtime, &session)?;
    policy_context_update(
        runtime,
        &session,
        PolicyUpdate::new(TPM_CC_POLICY_AUTHORIZE_NV).with_name(&name),
    )
    .map(|()| CommandOutput::empty())
}

fn parse_stored_policy(runtime: &Tpm2Runtime, stored: &[u8]) -> Result<(u16, Vec<u8>), TpmResult> {
    use crate::library::constants::TPM_RC_INSUFFICIENT;
    let mut reader = TemplateReader::new(stored);
    let hash_alg = reader.u16()?;
    let algorithms = &runtime
        .state
        .as_ref()
        .ok_or(TPM_RC_FAILURE)?
        .profile
        .algorithms;
    let enabled =
        hash_profile_name(hash_alg).is_some_and(|name| algorithm_enabled(algorithms, name));
    if !enabled {
        return Err(TPM_RC_HASH);
    }
    let size = digest_size(hash_alg).ok_or(TPM_RC_HASH)?;
    let digest = reader.bytes(size).map_err(|_| TPM_RC_INSUFFICIENT)?;
    Ok((hash_alg, digest.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::super::nv_common::harness::*;
    use super::super::policy_common::harness::*;
    use super::super::registry::{CommandLifecycle, HandleKind, NvAccess, find};
    use super::*;
    use crate::library::tpm2::golden_responses::policy_sessions::vector;

    const NV_INDEX: u32 = 0x0100_0000;

    fn sized(payload: &[u8]) -> Vec<u8> {
        let mut out = (payload.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(payload);
        out
    }

    fn read_tpm2b(data: &[u8], offset: usize) -> (&[u8], usize) {
        let size = usize::from(u16::from_be_bytes(
            data[offset..offset + 2].try_into().expect("a size prefix"),
        ));
        (&data[offset + 2..offset + 2 + size], offset + 2 + size)
    }

    fn signing_key_name() -> Vec<u8> {
        let parameters = response_parameters(vector("SIGNING_KEY_PUBLIC"));
        let (_, offset) = read_tpm2b(&parameters, 0);
        let (name, _) = read_tpm2b(&parameters, offset);
        name.to_vec()
    }

    fn verified_ticket() -> Vec<u8> {
        response_parameters(vector("VERIFY_APPROVED"))
    }

    fn null_ticket() -> Vec<u8> {
        let mut out = TPM_ST_VERIFIED.to_be_bytes().to_vec();
        out.extend_from_slice(&TPM_RH_OWNER.to_be_bytes());
        out.extend_from_slice(&sized(&[0x00; 64]));
        out
    }

    fn authorize_parameters(
        approved: &[u8],
        policy_ref: &[u8],
        key_sign: &[u8],
        ticket: &[u8],
    ) -> Vec<u8> {
        let mut out = sized(approved);
        out.extend_from_slice(&sized(policy_ref));
        out.extend_from_slice(&sized(key_sign));
        out.extend_from_slice(ticket);
        out
    }

    #[track_caller]
    fn authorize(runtime: &mut Tpm2Runtime, extra: &[u8]) -> Vec<u8> {
        dispatch_bytes(
            runtime,
            &command(CC_POLICY_AUTHORIZE, &[POLICY_SESSION_0], &[], extra),
        )
    }

    #[track_caller]
    fn authorize_nv(runtime: &mut Tpm2Runtime, extra: &[u8]) -> Vec<u8> {
        dispatch_bytes(
            runtime,
            &command(
                CC_POLICY_AUTHORIZE_NV,
                &[NV_INDEX, NV_INDEX, POLICY_SESSION_0],
                &[&[]],
                extra,
            ),
        )
    }

    #[track_caller]
    fn digest(runtime: &mut Tpm2Runtime) -> Vec<u8> {
        dispatch_bytes(
            runtime,
            &command(CC_POLICY_GET_DIGEST, &[POLICY_SESSION_0], &[], &[]),
        )
    }

    #[test]
    fn the_command_attributes_match_the_oracle() {
        for (code, record, expected, handles, decrypt) in [
            (
                CC_POLICY_AUTHORIZE,
                "CCATTR_016A",
                0x0200_016au32,
                1usize,
                2u16,
            ),
            (CC_POLICY_AUTHORIZE_NV, "CCATTR_0192", 0x0600_0192, 3, 0),
        ] {
            let oracle = vector(record);
            let attributes = u32::from_be_bytes(oracle[19..23].try_into().unwrap());
            let descriptor = find(code).expect("a registered command");
            assert_eq!(descriptor.attributes, attributes, "{record}");
            assert_eq!(descriptor.attributes, expected, "{record}");
            assert_eq!(descriptor.handles.len(), handles, "{record}");
            assert_eq!(descriptor.decrypt_size, decrypt, "{record}");
            assert_eq!(descriptor.encrypt_size, 0, "{record}");
            assert!(descriptor.sessions_allowed, "{record}");
            assert!(!descriptor.physical_presence, "{record}");
            assert!(
                matches!(descriptor.nv_access, NvAccess::Neither),
                "{record}"
            );
            assert!(
                matches!(descriptor.lifecycle, CommandLifecycle::RequiresStarted),
                "{record}"
            );
            assert!(matches!(
                descriptor.handles.last().expect("a handle").kind,
                HandleKind::PolicySession
            ));
        }
        let authorize_nv = find(CC_POLICY_AUTHORIZE_NV).expect("a registered command");
        assert!(matches!(authorize_nv.handles[0].kind, HandleKind::NvAuth));
        assert!(authorize_nv.handles[0].user_auth);
        assert!(matches!(authorize_nv.handles[1].kind, HandleKind::NvIndex));
        assert!(!authorize_nv.handles[1].user_auth);
    }

    #[test]
    fn a_verified_ticket_replaces_the_policy_digest() {
        let mut runtime = restored("SIGNED_READY");
        assert_eq!(
            authorize(
                &mut runtime,
                &authorize_parameters(&[0x00; 32], &[], &signing_key_name(), &verified_ticket())
            ),
            vector("PAUTH_ACCEPTED")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_AUTHORIZE"));
    }

    #[test]
    fn the_replaced_digest_is_the_zero_digest_extended_with_the_key_name() {
        let mut runtime = restored("SIGNED_READY");
        authorize(
            &mut runtime,
            &authorize_parameters(&[0x00; 32], &[], &signing_key_name(), &verified_ticket()),
        );
        let mut hasher = crate::library::tpm2::crypto::Hasher::new(0x000b).expect("sha256");
        hasher.update(&[0x00; 32]);
        hasher.update(&TPM_CC_POLICY_AUTHORIZE.to_be_bytes());
        hasher.update(&signing_key_name());
        let first = hasher.finalize();
        let mut hasher = crate::library::tpm2::crypto::Hasher::new(0x000b).expect("sha256");
        hasher.update(&first);
        let expected = hasher.finalize();
        assert_eq!(
            session_of(&runtime, POLICY_SESSION_0).audit_digest,
            expected,
            "an empty policyRef still triggers the second hash"
        );
    }

    #[test]
    fn a_real_session_needs_the_current_digest_and_a_valid_ticket() {
        let mut runtime = restored("SIGNED_READY");
        assert_eq!(
            authorize(
                &mut runtime,
                &authorize_parameters(&[0x11; 32], &[], &signing_key_name(), &verified_ticket())
            ),
            vector("PAUTH_WRONG_APPROVED_POLICY")
        );
        assert_eq!(
            authorize(
                &mut runtime,
                &authorize_parameters(&[0x00; 32], &[], &signing_key_name(), &null_ticket())
            ),
            vector("PAUTH_WRONG_TICKET")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_AUTHORIZE_FAILURES"));
    }

    #[test]
    fn a_trial_session_replaces_the_digest_without_a_ticket() {
        let mut runtime = restored("TRIAL_FRESH");
        let mut key_name = 0x000bu16.to_be_bytes().to_vec();
        key_name.extend_from_slice(&[0x22; 32]);
        assert_eq!(
            authorize(
                &mut runtime,
                &authorize_parameters(&[0x11; 32], &[0xaa], &key_name, &null_ticket())
            ),
            vector("TRIAL_PAUTH")
        );
        assert_eq!(digest(&mut runtime), vector("TRIAL_PGD_AFTER_AUTHORIZE"));

        for (record, key_sign) in [
            ("PAUTH_SHORT_NAME", vec![0x00]),
            ("PAUTH_UNKNOWN_HASH", vec![0x00, 0x05, 0x11, 0x22]),
            ("PAUTH_WRONG_NAME_SIZE", vec![0x00, 0x0b, 0x11, 0x22]),
        ] {
            assert_eq!(
                authorize(
                    &mut runtime,
                    &authorize_parameters(&[0x11; 32], &[], &key_sign, &null_ticket())
                ),
                vector(record),
                "{record}"
            );
        }
        assert_eq!(
            digest(&mut runtime),
            vector("TRIAL_PGD_AFTER_AUTH_FAILURES")
        );
    }

    #[test]
    fn policy_authorize_nv_reads_the_stored_policy() {
        let mut runtime = restored("AUTHORIZE_NV_READY");
        assert_eq!(authorize_nv(&mut runtime, &[]), vector("PANV_ACCEPTED"));
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_AUTHORIZE_NV"));
    }

    #[test]
    fn policy_authorize_nv_refuses_a_mismatched_stored_policy() {
        let mut runtime = restored("AUTHORIZE_NV_READY");
        dispatch_bytes(
            &mut runtime,
            &command(CC_POLICY_AUTH_VALUE, &[POLICY_SESSION_0], &[], &[]),
        );
        assert_eq!(authorize_nv(&mut runtime, &[]), vector("PANV_WRONG_DIGEST"));
        assert_eq!(authorize_nv(&mut runtime, &[0x00]), vector("PANV_TRAILING"));
        assert_eq!(
            digest(&mut runtime),
            vector("PGD_AFTER_AUTHORIZE_NV_FAILURES")
        );
    }

    #[test]
    fn a_trial_authorize_nv_never_reads_the_index() {
        let mut runtime = restored("AUTHORIZE_NV_TRIAL");
        assert_eq!(authorize_nv(&mut runtime, &[]), vector("TRIAL_PANV"));
        assert_eq!(digest(&mut runtime), vector("TRIAL_PGD_AFTER_AUTHORIZE_NV"));
    }

    #[test]
    fn a_failed_authorize_leaves_the_session_untouched() {
        let mut runtime = restored("SIGNED_READY");
        let before = session_of(&runtime, POLICY_SESSION_0).clone();
        for extra in [
            authorize_parameters(&[0x11; 32], &[], &signing_key_name(), &verified_ticket()),
            authorize_parameters(&[0x00; 32], &[], &[0x00, 0x0b], &verified_ticket()),
            authorize_parameters(&[0x00; 32], &[], &signing_key_name(), &null_ticket()),
        ] {
            let response = authorize(&mut runtime, &extra);
            assert_ne!(response_code(&response), RC_SUCCESS);
            let after = session_of(&runtime, POLICY_SESSION_0);
            assert_eq!(after.audit_digest, before.audit_digest);
            assert_eq!(after.attributes, before.attributes);
        }
    }

    #[test]
    fn parameter_mutations_do_not_panic() {
        let valid = command(
            CC_POLICY_AUTHORIZE,
            &[POLICY_SESSION_0],
            &[],
            &authorize_parameters(
                &[0x00; 32],
                &[0xaa],
                &signing_key_name(),
                &verified_ticket(),
            ),
        );
        for length in 10..valid.len() {
            for byte in [0x00u8, 0x01, 0x80, 0xff] {
                let mut mutated = valid[..length].to_vec();
                *mutated.last_mut().expect("a non-empty prefix") = byte;
                let size = (mutated.len() as u32).to_be_bytes();
                mutated[2..6].copy_from_slice(&size);
                let mut runtime = restored("SIGNED_READY");
                let _ = dispatch_bytes(&mut runtime, &mutated);
            }
        }
    }
}
