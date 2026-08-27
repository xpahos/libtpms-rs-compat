use super::session::{
    EXPIRATION_BIT, ParameterBlame, PolicySession, PolicyUpdate, compute_auth_timeout, hash_parts,
    live_session, policy_context_update, policy_parameter_checks, policy_session_at,
};
use crate::ffi_types::TpmResult;
use crate::library::constants::{
    TPM_RC_ATTRIBUTES, TPM_RC_FAILURE, TPM_RC_SCHEME, TPM_RC_SIZE, TPM_RC_TICKET,
};
use crate::library::tpm2::command::core::dispatcher::{CommandFrame, handle_at};
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::command::core::registry::{TPM_CC_POLICY_SECRET, TPM_CC_POLICY_SIGNED};
use crate::library::tpm2::command::core::response_code::{
    TPM_RC_1, TPM_RC_2, TPM_RC_3, TPM_RC_4, TPM_RC_5, TPM_RC_P,
};
use crate::library::tpm2::command::crypto::signing_state::hierarchy_proof_for;
use crate::library::tpm2::command::object::create_primary::add_modifier;
use crate::library::tpm2::entity::{entity_hierarchy, entity_name};
use crate::library::tpm2::hierarchy::TPM_RH_NULL;
use crate::library::tpm2::marshal::BlobWriter;
use crate::library::tpm2::nv::is_pin_pass_index;
use crate::library::tpm2::object::ATTR_PUBLIC_ONLY;
use crate::library::tpm2::persistent::OwnedAnyObjectBody;
use crate::library::tpm2::public::NAME_SIZE;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::self_test::self_test_algorithm;
use crate::library::tpm2::session::digests_equal;
use crate::library::tpm2::signature::{
    Signature, Verification, parse_signature, validate_signature,
};
use crate::library::tpm2::template::TemplateReader;
use crate::library::tpm2::ticket::{
    AuthTicketInput, CONTEXT_INTEGRITY_HASH_ALG, TPM_ST_AUTH_SECRET, TPM_ST_AUTH_SIGNED, Ticket,
    compute_auth,
};

const RC_NONCE_TPM: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_CP_HASH_A: TpmResult = TPM_RC_P + TPM_RC_2;
const RC_POLICY_REF: TpmResult = TPM_RC_P + TPM_RC_3;
const RC_EXPIRATION: TpmResult = TPM_RC_P + TPM_RC_4;
const RC_AUTH: TpmResult = TPM_RC_P + TPM_RC_5;

const RC_TICKET_TIMEOUT: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_TICKET_CP_HASH_A: TpmResult = TPM_RC_P + TPM_RC_2;
const RC_TICKET_POLICY_REF: TpmResult = TPM_RC_P + TPM_RC_3;
const RC_TICKET_AUTH_NAME: TpmResult = TPM_RC_P + TPM_RC_4;
const RC_TICKET_TICKET: TpmResult = TPM_RC_P + TPM_RC_5;

const RC_POLICY_TICKET_SESSION: TpmResult = TPM_RC_1;

const MAX_DIGEST_SIZE: usize = 64;
const TIMEOUT_SIZE: usize = 8;

struct DeferredAuthorization<'a> {
    nonce_tpm: &'a [u8],
    cp_hash: &'a [u8],
    policy_ref: &'a [u8],
    expiration: i32,
}

fn parse_deferred_authorization<'a>(
    reader: &mut TemplateReader<'a>,
) -> Result<DeferredAuthorization<'a>, TpmResult> {
    let nonce_tpm = reader
        .tpm2b(MAX_DIGEST_SIZE)
        .map_err(|code| code + RC_NONCE_TPM)?;
    let cp_hash = reader
        .tpm2b(MAX_DIGEST_SIZE)
        .map_err(|code| code + RC_CP_HASH_A)?;
    let policy_ref = reader
        .tpm2b(MAX_DIGEST_SIZE)
        .map_err(|code| code + RC_POLICY_REF)?;
    let expiration = reader.u32().map_err(|code| code + RC_EXPIRATION)? as i32;
    Ok(DeferredAuthorization {
        nonce_tpm,
        cp_hash,
        policy_ref,
        expiration,
    })
}

const DEFERRED_BLAME: ParameterBlame = ParameterBlame {
    nonce: RC_NONCE_TPM,
    cp_hash: RC_CP_HASH_A,
    expiration: RC_EXPIRATION,
};

struct AuthOutcome {
    timeout: u64,
    expires_on_reset: bool,
}

fn build_output(
    runtime: &Tpm2Runtime,
    tag: u16,
    hierarchy: u32,
    outcome: Option<AuthOutcome>,
    cp_hash: &[u8],
    policy_ref: &[u8],
    entity_name: &[u8],
) -> Result<CommandOutput, TpmResult> {
    let mut writer = BlobWriter::new();
    match outcome {
        None => {
            writer.write_tpm2b(&[]).map_err(|_| TPM_RC_SIZE)?;
            Ticket::empty(tag)
                .marshal(&mut writer)
                .map_err(|_| TPM_RC_SIZE)?;
        }
        Some(outcome) => {
            let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
            let time_epoch = state.persistent.time_epoch;
            let total_reset_count = state.persistent.total_reset_count;
            let proof = hierarchy_proof_for(runtime, hierarchy)?;
            let ticket = compute_auth(
                proof,
                &AuthTicketInput {
                    tag,
                    hierarchy,
                    timeout: outcome.timeout,
                    expires_on_reset: outcome.expires_on_reset,
                    cp_hash,
                    policy_ref,
                    entity_name,
                    time_epoch,
                    total_reset_count,
                },
            )
            .ok_or(TPM_RC_FAILURE)?;
            let mut stamped = outcome.timeout;
            if outcome.expires_on_reset {
                stamped |= EXPIRATION_BIT;
            }
            writer
                .write_tpm2b(&stamped.to_be_bytes())
                .map_err(|_| TPM_RC_SIZE)?;
            ticket.marshal(&mut writer).map_err(|_| TPM_RC_SIZE)?;
        }
    }
    Ok(CommandOutput::from_parameters(writer.into_bytes()))
}

fn ticket_outcome(
    session: &PolicySession,
    input: &DeferredAuthorization<'_>,
    auth_timeout: u64,
    suppressed: bool,
) -> Option<AuthOutcome> {
    if input.expiration >= 0 || session.is_trial || suppressed {
        return None;
    }
    Some(AuthOutcome {
        timeout: auth_timeout & !EXPIRATION_BIT,
        expires_on_reset: input.nonce_tpm.is_empty(),
    })
}

pub(in crate::library::tpm2::command) fn execute_secret(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let auth_handle = handle_at(frame, 0)?;
    let session = policy_session_at(runtime, frame, 1)?;

    let mut reader = TemplateReader::new(frame.parameters);
    let input = parse_deferred_authorization(&mut reader)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }

    let mut auth_timeout = 0;
    if !session.is_trial {
        let start_time = live_session(runtime, &session)?.start_time;
        auth_timeout = compute_auth_timeout(
            runtime,
            start_time,
            input.expiration,
            input.nonce_tpm.is_empty(),
        );
        policy_parameter_checks(
            runtime,
            &session,
            auth_timeout,
            Some(input.cp_hash),
            Some(input.nonce_tpm),
            &DEFERRED_BLAME,
        )?;
    }

    let name = entity_name(runtime, auth_handle)?;
    let hierarchy = entity_hierarchy(runtime, auth_handle)?;
    let pin_pass = index_is_pin_pass(runtime, auth_handle);
    let outcome = ticket_outcome(&session, &input, auth_timeout, pin_pass);
    if outcome.is_some() {
        self_test_algorithm(runtime, CONTEXT_INTEGRITY_HASH_ALG)?;
    }

    policy_context_update(
        runtime,
        &session,
        PolicyUpdate::new(TPM_CC_POLICY_SECRET)
            .with_name(&name)
            .with_policy_ref(input.policy_ref)
            .with_cp_hash(input.cp_hash)
            .with_timeout(auth_timeout),
    )?;

    build_output(
        runtime,
        TPM_ST_AUTH_SECRET,
        hierarchy,
        outcome,
        input.cp_hash,
        input.policy_ref,
        &name,
    )
}

fn index_is_pin_pass(runtime: &Tpm2Runtime, handle: u32) -> bool {
    use crate::library::tpm2::nv::{is_nv_index_handle, resolve_index};
    is_nv_index_handle(handle)
        && resolve_index(runtime, handle).is_some_and(|index| is_pin_pass_index(index.attributes()))
}

fn signature_hash_alg(signature: &Signature) -> u16 {
    use crate::library::tpm2::algorithm::{TPM_ALG_ECDAA, TPM_ALG_NULL};
    match signature {
        Signature::Null => TPM_ALG_NULL,
        Signature::Rsa { hash_alg, .. } | Signature::Hmac { hash_alg, .. } => *hash_alg,
        Signature::Ecc {
            scheme, hash_alg, ..
        } => {
            if *scheme == TPM_ALG_ECDAA {
                TPM_ALG_NULL
            } else {
                *hash_alg
            }
        }
    }
}

pub(in crate::library::tpm2::command) fn execute_signed(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let auth_object = handle_at(frame, 0)?;
    let session = policy_session_at(runtime, frame, 1)?;

    let profile = &runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?.profile;
    let mut reader = TemplateReader::new(frame.parameters);
    let input = parse_deferred_authorization(&mut reader)?;
    let signature = parse_signature(&mut reader, profile).map_err(|code| code + RC_AUTH)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }

    let mut auth_timeout = 0;
    if !session.is_trial {
        let start_time = live_session(runtime, &session)?.start_time;
        auth_timeout = compute_auth_timeout(
            runtime,
            start_time,
            input.expiration,
            input.nonce_tpm.is_empty(),
        );
        policy_parameter_checks(
            runtime,
            &session,
            auth_timeout,
            Some(input.cp_hash),
            Some(input.nonce_tpm),
            &DEFERRED_BLAME,
        )?;
        let hash_alg = signature_hash_alg(&signature);
        let expiration = (input.expiration as u32).to_be_bytes();
        let auth_hash = match hash_parts(
            runtime,
            hash_alg,
            &[
                input.nonce_tpm,
                &expiration,
                input.cp_hash,
                input.policy_ref,
            ],
        ) {
            Ok(digest) => digest,
            Err(_) => return Err(TPM_RC_SCHEME + RC_AUTH),
        };
        validate_authorizing_signature(runtime, auth_object, &auth_hash, &signature)?;
    }

    let name = entity_name(runtime, auth_object)?;
    let hierarchy = entity_hierarchy(runtime, auth_object)?;
    let outcome = ticket_outcome(&session, &input, auth_timeout, false);
    if outcome.is_some() {
        self_test_algorithm(runtime, CONTEXT_INTEGRITY_HASH_ALG)?;
    }

    policy_context_update(
        runtime,
        &session,
        PolicyUpdate::new(TPM_CC_POLICY_SIGNED)
            .with_name(&name)
            .with_policy_ref(input.policy_ref)
            .with_cp_hash(input.cp_hash)
            .with_timeout(auth_timeout),
    )?;

    build_output(
        runtime,
        TPM_ST_AUTH_SIGNED,
        hierarchy,
        outcome,
        input.cp_hash,
        input.policy_ref,
        &name,
    )
}

fn validate_authorizing_signature(
    runtime: &mut Tpm2Runtime,
    handle: u32,
    digest: &[u8],
    signature: &Signature,
) -> Result<(), TpmResult> {
    use crate::library::tpm2::object_create::resolve_any_object;
    let profile = runtime
        .state
        .as_ref()
        .ok_or(TPM_RC_FAILURE)?
        .profile
        .clone();
    let object = resolve_any_object(runtime, handle).ok_or(TPM_RC_FAILURE)?;
    let OwnedAnyObjectBody::Object(body) = &object.body else {
        return Err(TPM_RC_SCHEME + RC_AUTH);
    };
    let public_only = object.attributes & ATTR_PUBLIC_ONLY != 0;
    let verification = validate_signature(body, public_only, digest, signature, &profile)
        .map_err(|code| add_modifier(code, RC_AUTH))?;
    if let Verification::Hmac(hmac) = verification {
        self_test_algorithm(runtime, hmac.hash_alg())?;
        hmac.finish(digest)
            .map_err(|code| add_modifier(code, RC_AUTH))?;
    }
    Ok(())
}

struct TicketAssertion<'a> {
    timeout: &'a [u8],
    cp_hash: &'a [u8],
    policy_ref: &'a [u8],
    auth_name: &'a [u8],
    tag: u16,
    hierarchy: u32,
    digest: &'a [u8],
}

fn parse_ticket_assertion<'a>(parameters: &'a [u8]) -> Result<TicketAssertion<'a>, TpmResult> {
    use crate::library::constants::{TPM_RC_TAG, TPM_RC_VALUE};
    use crate::library::tpm2::hierarchy::{TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM};

    let mut reader = TemplateReader::new(parameters);
    let timeout = reader
        .tpm2b(MAX_DIGEST_SIZE)
        .map_err(|code| code + RC_TICKET_TIMEOUT)?;
    let cp_hash = reader
        .tpm2b(MAX_DIGEST_SIZE)
        .map_err(|code| code + RC_TICKET_CP_HASH_A)?;
    let policy_ref = reader
        .tpm2b(MAX_DIGEST_SIZE)
        .map_err(|code| code + RC_TICKET_POLICY_REF)?;
    let auth_name = reader
        .tpm2b(NAME_SIZE)
        .map_err(|code| code + RC_TICKET_AUTH_NAME)?;
    let tag = reader.u16().map_err(|code| code + RC_TICKET_TICKET)?;
    if tag != TPM_ST_AUTH_SIGNED && tag != TPM_ST_AUTH_SECRET {
        return Err(TPM_RC_TAG + RC_TICKET_TICKET);
    }
    let hierarchy = reader.u32().map_err(|code| code + RC_TICKET_TICKET)?;
    if !matches!(
        hierarchy,
        TPM_RH_OWNER | TPM_RH_PLATFORM | TPM_RH_ENDORSEMENT | TPM_RH_NULL
    ) {
        return Err(TPM_RC_VALUE + RC_TICKET_TICKET);
    }
    let digest = reader
        .tpm2b(MAX_DIGEST_SIZE)
        .map_err(|code| code + RC_TICKET_TICKET)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(TicketAssertion {
        timeout,
        cp_hash,
        policy_ref,
        auth_name,
        tag,
        hierarchy,
        digest,
    })
}

pub(in crate::library::tpm2::command) fn execute_ticket(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let session = policy_session_at(runtime, frame, 0)?;
    let input = parse_ticket_assertion(frame.parameters)?;

    if session.is_trial {
        return Err(TPM_RC_ATTRIBUTES + RC_POLICY_TICKET_SESSION);
    }
    if input.timeout.len() != TIMEOUT_SIZE {
        return Err(TPM_RC_SIZE + RC_TICKET_TIMEOUT);
    }
    let stamped = u64::from_be_bytes(input.timeout.try_into().map_err(|_| TPM_RC_FAILURE)?);
    let expires_on_reset = stamped & EXPIRATION_BIT != 0;
    let auth_timeout = stamped & !EXPIRATION_BIT;

    policy_parameter_checks(
        runtime,
        &session,
        auth_timeout,
        Some(input.cp_hash),
        None,
        &ParameterBlame {
            nonce: 0,
            cp_hash: RC_TICKET_CP_HASH_A,
            expiration: RC_TICKET_TIMEOUT,
        },
    )?;

    self_test_algorithm(runtime, CONTEXT_INTEGRITY_HASH_ALG)?;
    let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
    let time_epoch = state.persistent.time_epoch;
    let total_reset_count = state.persistent.total_reset_count;
    let proof = hierarchy_proof_for(runtime, input.hierarchy)?;
    let expected = compute_auth(
        proof,
        &AuthTicketInput {
            tag: input.tag,
            hierarchy: input.hierarchy,
            timeout: auth_timeout,
            expires_on_reset,
            cp_hash: input.cp_hash,
            policy_ref: input.policy_ref,
            entity_name: input.auth_name,
            time_epoch,
            total_reset_count,
        },
    )
    .ok_or(TPM_RC_FAILURE)?;
    if !digests_equal(input.digest, &expected.digest) {
        return Err(TPM_RC_TICKET + RC_TICKET_TICKET);
    }

    let command_code = if input.tag == TPM_ST_AUTH_SIGNED {
        TPM_CC_POLICY_SIGNED
    } else {
        TPM_CC_POLICY_SECRET
    };
    policy_context_update(
        runtime,
        &session,
        PolicyUpdate::new(command_code)
            .with_name(input.auth_name)
            .with_policy_ref(input.policy_ref)
            .with_cp_hash(input.cp_hash)
            .with_timeout(auth_timeout),
    )?;
    Ok(CommandOutput::empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::command::core::registry::{
        CommandLifecycle, HandleKind, NvAccess, find,
    };
    use crate::library::tpm2::command::core::test_support::{
        RC_SUCCESS, command, dispatch_bytes, response_code, response_parameters,
    };
    use crate::library::tpm2::command::policy::session::test_support::{
        CC_POLICY_GET_DIGEST, CC_POLICY_SECRET, CC_POLICY_SIGNED, CC_POLICY_TICKET,
        POLICY_SESSION_0, restored, session_of,
    };
    use crate::library::tpm2::golden_responses::policy_sessions::vector;
    use crate::library::tpm2::hierarchy::TPM_RH_OWNER;
    use crate::library::tpm2::session::SESSION_ATTR_IS_CP_HASH_DEFINED;

    const SIGNING_KEY: u32 = 0x8000_0000;

    fn sized(payload: &[u8]) -> Vec<u8> {
        let mut out = (payload.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(payload);
        out
    }

    fn secret_parameters(
        nonce: &[u8],
        cp_hash: &[u8],
        policy_ref: &[u8],
        expiration: i32,
    ) -> Vec<u8> {
        let mut out = sized(nonce);
        out.extend_from_slice(&sized(cp_hash));
        out.extend_from_slice(&sized(policy_ref));
        out.extend_from_slice(&(expiration as u32).to_be_bytes());
        out
    }

    #[track_caller]
    fn secret(runtime: &mut Tpm2Runtime, auth: u32, extra: &[u8]) -> Vec<u8> {
        dispatch_bytes(
            runtime,
            &command(CC_POLICY_SECRET, &[auth, POLICY_SESSION_0], &[&[]], extra),
        )
    }

    #[track_caller]
    fn session_only(runtime: &mut Tpm2Runtime, code: u32, extra: &[u8]) -> Vec<u8> {
        dispatch_bytes(runtime, &command(code, &[POLICY_SESSION_0], &[], extra))
    }

    #[track_caller]
    fn signed(runtime: &mut Tpm2Runtime, extra: &[u8]) -> Vec<u8> {
        dispatch_bytes(
            runtime,
            &command(
                CC_POLICY_SIGNED,
                &[SIGNING_KEY, POLICY_SESSION_0],
                &[],
                extra,
            ),
        )
    }

    #[track_caller]
    fn digest(runtime: &mut Tpm2Runtime) -> Vec<u8> {
        session_only(runtime, CC_POLICY_GET_DIGEST, &[])
    }

    fn read_tpm2b(data: &[u8], offset: usize) -> (&[u8], usize) {
        let size = usize::from(u16::from_be_bytes(
            data[offset..offset + 2].try_into().expect("a size prefix"),
        ));
        (&data[offset + 2..offset + 2 + size], offset + 2 + size)
    }

    fn produced_timeout_and_ticket() -> (Vec<u8>, Vec<u8>) {
        let parameters = response_parameters(vector("PSEC_TICKET_FOR_REUSE"));
        let (timeout, offset) = read_tpm2b(&parameters, 0);
        (timeout.to_vec(), parameters[offset..].to_vec())
    }

    fn ticket_parameters(
        timeout: &[u8],
        cp_hash: &[u8],
        policy_ref: &[u8],
        auth_name: &[u8],
        ticket: &[u8],
    ) -> Vec<u8> {
        let mut out = sized(timeout);
        out.extend_from_slice(&sized(cp_hash));
        out.extend_from_slice(&sized(policy_ref));
        out.extend_from_slice(&sized(auth_name));
        out.extend_from_slice(ticket);
        out
    }

    fn signed_parameters(expiration: i32, signature: &[u8]) -> Vec<u8> {
        let mut out = sized(&[]);
        out.extend_from_slice(&sized(&[]));
        out.extend_from_slice(&sized(&[]));
        out.extend_from_slice(&(expiration as u32).to_be_bytes());
        out.extend_from_slice(signature);
        out
    }

    #[test]
    fn the_command_attributes_match_the_oracle() {
        for (code, record, expected, handles, encrypt) in [
            (
                CC_POLICY_SECRET,
                "CCATTR_0151",
                0x0400_0151u32,
                2usize,
                2u16,
            ),
            (CC_POLICY_SIGNED, "CCATTR_0160", 0x0400_0160, 2, 2),
            (CC_POLICY_TICKET, "CCATTR_0172", 0x0200_0172, 1, 0),
        ] {
            let oracle = vector(record);
            let attributes = u32::from_be_bytes(oracle[19..23].try_into().unwrap());
            let descriptor = find(code).expect("a registered command");
            assert_eq!(descriptor.attributes, attributes, "{record}");
            assert_eq!(descriptor.attributes, expected, "{record}");
            assert_eq!(descriptor.handles.len(), handles, "{record}");
            assert_eq!(descriptor.decrypt_size, 2, "{record}");
            assert_eq!(descriptor.encrypt_size, encrypt, "{record}");
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
        let secret = find(CC_POLICY_SECRET).expect("a registered command");
        assert!(matches!(secret.handles[0].kind, HandleKind::Entity));
        assert!(secret.handles[0].user_auth);
        assert!(!secret.handles[0].admin_role());
        let signed = find(CC_POLICY_SIGNED).expect("a registered command");
        assert!(matches!(signed.handles[0].kind, HandleKind::Object));
        assert!(!signed.handles[0].user_auth);
    }

    #[test]
    fn policy_secret_extends_the_digest_with_the_authorizing_name() {
        let mut runtime = restored("POLICY_FRESH");
        assert_eq!(
            secret(
                &mut runtime,
                TPM_RH_OWNER,
                &secret_parameters(&[], &[], &[], 0)
            ),
            vector("PSEC_OWNER")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_SECRET"));
    }

    #[test]
    fn policy_secret_covers_the_cp_hash_and_the_policy_ref() {
        let mut runtime = restored("POLICY_FRESH");
        assert_eq!(
            secret(
                &mut runtime,
                TPM_RH_OWNER,
                &secret_parameters(&[], &[0x11; 32], &[0xaa, 0xbb], 0)
            ),
            vector("PSEC_CP_HASH_AND_REF")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_SECRET_REF"));
        let session = session_of(&runtime, POLICY_SESSION_0);
        assert_eq!(session.bound_entity, vec![0x11; 32]);
        assert_ne!(session.attributes & SESSION_ATTR_IS_CP_HASH_DEFINED, 0);
    }

    #[test]
    fn a_wrong_nonce_and_a_short_cp_hash_are_reported_by_parameter() {
        let mut runtime = restored("POLICY_FRESH");
        assert_eq!(
            secret(
                &mut runtime,
                TPM_RH_OWNER,
                &secret_parameters(&[0x5a; 32], &[], &[], 0)
            ),
            vector("PSEC_WRONG_NONCE")
        );
        assert_eq!(
            secret(
                &mut runtime,
                TPM_RH_OWNER,
                &secret_parameters(&[], &[0x11; 20], &[], 0)
            ),
            vector("PSEC_SHORT_CP_HASH")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_SECRET_FAILURES"));
    }

    #[test]
    fn a_negative_expiration_produces_a_timeout_and_a_ticket() {
        let mut runtime = restored("POLICY_FRESH");
        let response = secret(
            &mut runtime,
            TPM_RH_OWNER,
            &secret_parameters(&[], &[], &[], -1000),
        );
        assert_eq!(response, vector("PSEC_TICKET"));
        let parameters = response_parameters(&response);
        let (timeout, offset) = read_tpm2b(&parameters, 0);
        assert_eq!(timeout.len(), 8);
        assert_ne!(
            timeout[0] & 0x80,
            0,
            "an empty nonceTPM makes the ticket expire on reset"
        );
        assert_eq!(&parameters[offset..offset + 2], &[0x80, 0x23]);
        let session = session_of(&runtime, POLICY_SESSION_0);
        assert_ne!(session.timeout, 0);
        assert_eq!(session.timeout & EXPIRATION_BIT, 0);
    }

    #[test]
    fn a_positive_expiration_only_sets_the_session_timeout() {
        let mut runtime = restored("POLICY_FRESH");
        let response = secret(
            &mut runtime,
            TPM_RH_OWNER,
            &secret_parameters(&[], &[], &[], 1000),
        );
        assert_eq!(response, vector("PSEC_POSITIVE_EXPIRATION"));
        let parameters = response_parameters(&response);
        assert_eq!(&parameters[..2], &[0x00, 0x00], "no timeout is returned");
        assert_ne!(session_of(&runtime, POLICY_SESSION_0).timeout, 0);
    }

    #[test]
    fn the_null_hierarchy_is_not_a_policy_secret_entity() {
        let mut runtime = restored("POLICY_FRESH");
        assert_eq!(
            secret(
                &mut runtime,
                crate::library::tpm2::hierarchy::TPM_RH_NULL,
                &secret_parameters(&[], &[], &[], -1000)
            ),
            vector("PSEC_NULL_HIERARCHY")
        );
    }

    #[test]
    fn the_timeout_arithmetic_follows_the_nonce() {
        let runtime = restored("POLICY_FRESH");
        let start = session_of(&runtime, POLICY_SESSION_0).start_time;
        assert_eq!(compute_auth_timeout(&runtime, start, 0, true), 0);
        assert_eq!(compute_auth_timeout(&runtime, start, 0, false), 0);
        assert_eq!(
            compute_auth_timeout(&runtime, start, 5, false),
            start + 5_000
        );
        assert_eq!(
            compute_auth_timeout(&runtime, start, -5, false),
            start + 5_000
        );
        assert_eq!(
            compute_auth_timeout(&runtime, start, 5, true),
            5_000 + runtime.timer.time_ms % 1000
        );
        assert_eq!(
            compute_auth_timeout(&runtime, start, i32::MIN, false),
            start + 2_147_483_647_000
        );
    }

    #[test]
    fn a_trial_session_never_produces_a_ticket() {
        let mut runtime = restored("TRIAL_FRESH");
        assert_eq!(
            secret(
                &mut runtime,
                TPM_RH_OWNER,
                &secret_parameters(&[], &[], &[0xaa], -1000)
            ),
            vector("TRIAL_PSEC")
        );
        assert_eq!(digest(&mut runtime), vector("TRIAL_PGD_AFTER_SECRET"));
        assert_eq!(session_of(&runtime, POLICY_SESSION_0).timeout, 0);
    }

    #[test]
    fn a_trial_session_may_not_use_a_ticket() {
        let mut runtime = restored("TRIAL_FRESH");
        let mut ticket = 0x8023u16.to_be_bytes().to_vec();
        ticket.extend_from_slice(&TPM_RH_OWNER.to_be_bytes());
        ticket.extend_from_slice(&sized(&[0x00; 64]));
        assert_eq!(
            session_only(
                &mut runtime,
                CC_POLICY_TICKET,
                &ticket_parameters(&[0x00; 8], &[], &[], &TPM_RH_OWNER.to_be_bytes(), &ticket)
            ),
            vector("TRIAL_PTKT")
        );
    }

    #[test]
    fn a_ticket_replaces_the_authorization_it_was_issued_for() {
        let (timeout, ticket) = produced_timeout_and_ticket();
        let mut runtime = restored("POLICY_FRESH");
        assert_eq!(
            session_only(
                &mut runtime,
                CC_POLICY_TICKET,
                &ticket_parameters(&timeout, &[], &[0xaa], &TPM_RH_OWNER.to_be_bytes(), &ticket)
            ),
            vector("PTKT_ACCEPTED")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_TICKET"));
    }

    #[test]
    fn the_ticket_digest_reproduces_the_policy_secret_digest() {
        let mut runtime = restored("POLICY_FRESH");
        let produced = secret(
            &mut runtime,
            TPM_RH_OWNER,
            &secret_parameters(&[], &[], &[0xaa], -1000),
        );
        assert_eq!(produced, vector("PSEC_TICKET_FOR_REUSE"));
        let after_secret = digest(&mut runtime);

        let (timeout, ticket) = produced_timeout_and_ticket();
        let mut replayed = restored("POLICY_FRESH");
        assert_eq!(
            session_only(
                &mut replayed,
                CC_POLICY_TICKET,
                &ticket_parameters(&timeout, &[], &[0xaa], &TPM_RH_OWNER.to_be_bytes(), &ticket)
            ),
            vector("PTKT_ACCEPTED")
        );
        assert_eq!(
            digest(&mut replayed),
            after_secret,
            "the ticket rebuilds the same policy digest as the authorization"
        );
    }

    #[test]
    fn a_modified_or_mismatched_ticket_is_refused() {
        let (timeout, ticket) = produced_timeout_and_ticket();
        let mut runtime = restored("POLICY_FRESH");
        let mut modified = ticket.clone();
        *modified.last_mut().expect("a ticket digest") ^= 0xff;
        assert_eq!(
            session_only(
                &mut runtime,
                CC_POLICY_TICKET,
                &ticket_parameters(
                    &timeout,
                    &[],
                    &[0xaa],
                    &TPM_RH_OWNER.to_be_bytes(),
                    &modified
                )
            ),
            vector("PTKT_MODIFIED")
        );
        assert_eq!(
            session_only(
                &mut runtime,
                CC_POLICY_TICKET,
                &ticket_parameters(
                    &timeout,
                    &[],
                    &[0xaa],
                    &0x4000_000cu32.to_be_bytes(),
                    &ticket
                )
            ),
            vector("PTKT_WRONG_NAME")
        );
        assert_eq!(
            session_only(
                &mut runtime,
                CC_POLICY_TICKET,
                &ticket_parameters(&timeout, &[], &[0xbb], &TPM_RH_OWNER.to_be_bytes(), &ticket)
            ),
            vector("PTKT_WRONG_REF")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_TICKET_FAILURES"));
    }

    #[test]
    fn a_malformed_ticket_is_reported_by_parameter() {
        let mut runtime = restored("POLICY_FRESH");
        let mut ticket = 0x8023u16.to_be_bytes().to_vec();
        ticket.extend_from_slice(&TPM_RH_OWNER.to_be_bytes());
        ticket.extend_from_slice(&sized(&[0x00; 64]));
        assert_eq!(
            session_only(
                &mut runtime,
                CC_POLICY_TICKET,
                &ticket_parameters(&[0x00; 4], &[], &[], &TPM_RH_OWNER.to_be_bytes(), &ticket)
            ),
            vector("PTKT_SHORT_TIMEOUT")
        );

        let mut bad_tag = 0x8024u16.to_be_bytes().to_vec();
        bad_tag.extend_from_slice(&TPM_RH_OWNER.to_be_bytes());
        bad_tag.extend_from_slice(&sized(&[0x00; 64]));
        assert_eq!(
            session_only(
                &mut runtime,
                CC_POLICY_TICKET,
                &ticket_parameters(&[0x00; 8], &[], &[], &TPM_RH_OWNER.to_be_bytes(), &bad_tag)
            ),
            vector("PTKT_BAD_TAG")
        );

        let mut bad_hierarchy = 0x8023u16.to_be_bytes().to_vec();
        bad_hierarchy.extend_from_slice(&0x4000_000au32.to_be_bytes());
        bad_hierarchy.extend_from_slice(&sized(&[0x00; 64]));
        assert_eq!(
            session_only(
                &mut runtime,
                CC_POLICY_TICKET,
                &ticket_parameters(
                    &[0x00; 8],
                    &[],
                    &[],
                    &TPM_RH_OWNER.to_be_bytes(),
                    &bad_hierarchy
                )
            ),
            vector("PTKT_BAD_HIERARCHY")
        );
    }

    #[test]
    fn a_genuine_signature_authorizes_the_policy() {
        let mut runtime = restored("SIGNED_READY");
        let signature = response_parameters(vector("SIGN_AHASH"));
        assert_eq!(
            signed(&mut runtime, &signed_parameters(0, &signature)),
            vector("PSIGN_ACCEPTED")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_SIGNED"));
    }

    #[test]
    fn the_signed_digest_covers_the_expiration() {
        let signature = response_parameters(vector("SIGN_AHASH"));
        let mut accepted = restored("SIGNED_READY");
        assert_eq!(
            response_code(&signed(&mut accepted, &signed_parameters(0, &signature))),
            RC_SUCCESS
        );

        let mut refused = restored("SIGNED_READY");
        let response = signed(&mut refused, &signed_parameters(1, &signature));
        assert_eq!(
            response_code(&response),
            crate::library::constants::TPM_RC_SIGNATURE + RC_AUTH,
            "the same signature no longer matches once the expiration changes"
        );
    }

    #[test]
    fn a_wrong_signature_or_scheme_is_reported_by_parameter() {
        let mut runtime = restored("SIGNED_READY");
        let mut wrong = 0x0014u16.to_be_bytes().to_vec();
        wrong.extend_from_slice(&0x000bu16.to_be_bytes());
        wrong.extend_from_slice(&sized(&[0x00; 256]));
        assert_eq!(
            signed(&mut runtime, &signed_parameters(0, &wrong)),
            vector("PSIGN_WRONG_SIGNATURE")
        );

        for (record, selector) in [
            ("PSIGN_ECDAA_SCHEME", 0x001au16),
            ("PSIGN_ECDSA_SCHEME", 0x0018),
        ] {
            let mut ecc = selector.to_be_bytes().to_vec();
            ecc.extend_from_slice(&0x000bu16.to_be_bytes());
            ecc.extend_from_slice(&sized(&[0x00; 32]));
            ecc.extend_from_slice(&sized(&[0x00; 32]));
            assert_eq!(
                signed(&mut runtime, &signed_parameters(0, &ecc)),
                vector(record),
                "{record}"
            );
        }

        assert_eq!(
            signed(
                &mut runtime,
                &signed_parameters(0, &0x0010u16.to_be_bytes())
            ),
            vector("PSIGN_NULL_SCHEME")
        );

        let mut hmac = 0x0005u16.to_be_bytes().to_vec();
        hmac.extend_from_slice(&0x000bu16.to_be_bytes());
        hmac.extend_from_slice(&[0x00; 32]);
        assert_eq!(
            signed(&mut runtime, &signed_parameters(0, &hmac)),
            vector("PSIGN_HMAC_SCHEME")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_SIGNED_FAILURES"));
    }

    #[test]
    fn a_failed_authorization_leaves_the_session_untouched() {
        let mut runtime = restored("POLICY_FRESH");
        let before = session_of(&runtime, POLICY_SESSION_0).clone();
        for extra in [
            secret_parameters(&[0x5a; 32], &[], &[], 0),
            secret_parameters(&[], &[0x11; 20], &[], 0),
        ] {
            let response = secret(&mut runtime, TPM_RH_OWNER, &extra);
            assert_ne!(response_code(&response), RC_SUCCESS);
            let after = session_of(&runtime, POLICY_SESSION_0);
            assert_eq!(after.audit_digest, before.audit_digest);
            assert_eq!(after.timeout, before.timeout);
            assert_eq!(after.bound_entity, before.bound_entity);
            assert_eq!(after.attributes, before.attributes);
        }
    }

    #[test]
    fn parameter_mutations_do_not_panic() {
        let valid = command(
            CC_POLICY_SECRET,
            &[TPM_RH_OWNER, POLICY_SESSION_0],
            &[&[]],
            &secret_parameters(&[], &[0x11; 32], &[0xaa], -5),
        );
        for length in 10..valid.len() {
            for byte in [0x00u8, 0x01, 0x80, 0xff] {
                let mut mutated = valid[..length].to_vec();
                *mutated.last_mut().expect("a non-empty prefix") = byte;
                let size = (mutated.len() as u32).to_be_bytes();
                mutated[2..6].copy_from_slice(&size);
                let mut runtime = restored("POLICY_FRESH");
                let _ = dispatch_bytes(&mut runtime, &mutated);
            }
        }
    }
}
