use crate::ffi_types::TpmResult;
use crate::library::constants::{
    TPM_RC_COMMAND_CODE, TPM_RC_CPHASH, TPM_RC_FAILURE, TPM_RC_RANGE, TPM_RC_SIZE, TPM_RC_VALUE,
};

use super::super::public::NAME_SIZE;
use super::super::runtime::Tpm2Runtime;
use super::super::session::{
    SESSION_ATTR_CHECK_NV_WRITTEN, SESSION_ATTR_IS_CP_HASH_DEFINED,
    SESSION_ATTR_IS_NAME_HASH_DEFINED, SESSION_ATTR_IS_PARAMETERS_HASH_DEFINED,
    SESSION_ATTR_IS_PP_REQUIRED, SESSION_ATTR_IS_TEMPLATE_HASH_DEFINED,
    SESSION_ATTR_NV_WRITTEN_STATE, digest_size, digests_equal,
};
use super::super::template::TemplateReader;
use super::dispatcher::CommandFrame;
use super::nv_common::{TPM_RC_1, TPM_RC_2, TPM_RC_3, TPM_RC_P};
use super::output::CommandOutput;
use super::policy_common::{
    PolicySession, hash_parts, is_cp_hash_union_occupied, live_session, live_session_mut,
    next_policy_digest, no_parameters, policy_session,
};
use super::registry::{
    TPM_CC_DUPLICATE, TPM_CC_POLICY_CP_HASH, TPM_CC_POLICY_DUPLICATION_SELECT,
    TPM_CC_POLICY_LOCALITY, TPM_CC_POLICY_NAME_HASH, TPM_CC_POLICY_NV_WRITTEN,
    TPM_CC_POLICY_PARAMETERS, TPM_CC_POLICY_PHYSICAL_PRESENCE, TPM_CC_POLICY_TEMPLATE,
};
use super::session::state_format_level;

const RC_FIRST: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_SECOND: TpmResult = TPM_RC_P + TPM_RC_2;
const RC_THIRD: TpmResult = TPM_RC_P + TPM_RC_3;

const MAX_DIGEST_SIZE: usize = 64;

const NORMAL_LOCALITY_LIMIT: u8 = 32;
const ALL_NORMAL_LOCALITIES: u8 = 0x1f;

const NAME_HASH_ATTRIBUTE_LEVEL: u32 = 4;

fn name_hash_attribute(runtime: &Tpm2Runtime) -> Result<u32, TpmResult> {
    Ok(
        if state_format_level(runtime)? >= NAME_HASH_ATTRIBUTE_LEVEL {
            SESSION_ATTR_IS_NAME_HASH_DEFINED
        } else {
            0
        },
    )
}

fn sole_digest(frame: &CommandFrame<'_>, blame: TpmResult) -> Result<Vec<u8>, TpmResult> {
    let mut reader = TemplateReader::new(frame.parameters);
    let digest = reader
        .tpm2b(MAX_DIGEST_SIZE)
        .map_err(|code| code + blame)?
        .to_vec();
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(digest)
}

fn matches_session_digest_size(
    session: &PolicySession,
    digest: &[u8],
    blame: TpmResult,
) -> Result<(), TpmResult> {
    let expected = digest_size(session.hash_alg).ok_or(TPM_RC_FAILURE)?;
    if digest.len() == expected {
        Ok(())
    } else {
        Err(TPM_RC_SIZE + blame)
    }
}

fn session_attributes(runtime: &Tpm2Runtime, session: &PolicySession) -> Result<u32, TpmResult> {
    Ok(live_session(runtime, session)?.attributes)
}

struct Restriction {
    digest: Vec<u8>,
    value: Vec<u8>,
    attribute: u32,
}

fn publish_restriction(
    runtime: &mut Tpm2Runtime,
    session: &PolicySession,
    restriction: Restriction,
) -> Result<CommandOutput, TpmResult> {
    let entry = live_session_mut(runtime, session)?;
    entry.audit_digest = restriction.digest;
    entry.bound_entity = restriction.value;
    entry.attributes |= restriction.attribute;
    Ok(CommandOutput::empty())
}

pub(super) fn execute_cp_hash(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let session = policy_session(runtime, frame)?;
    let cp_hash = sole_digest(frame, RC_FIRST)?;
    matches_session_digest_size(&session, &cp_hash, RC_FIRST)?;

    let entry = live_session(runtime, &session)?;
    if is_cp_hash_union_occupied(entry.attributes)
        && (entry.attributes & SESSION_ATTR_IS_CP_HASH_DEFINED == 0
            || !digests_equal(&cp_hash, &entry.bound_entity))
    {
        return Err(TPM_RC_CPHASH);
    }

    let digest = next_policy_digest(runtime, &session, TPM_CC_POLICY_CP_HASH, &[&cp_hash])?;
    publish_restriction(
        runtime,
        &session,
        Restriction {
            digest,
            value: cp_hash,
            attribute: SESSION_ATTR_IS_CP_HASH_DEFINED,
        },
    )
}

pub(super) fn execute_name_hash(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let session = policy_session(runtime, frame)?;
    let name_hash = sole_digest(frame, RC_FIRST)?;
    matches_session_digest_size(&session, &name_hash, RC_FIRST)?;
    if is_cp_hash_union_occupied(session_attributes(runtime, &session)?) {
        return Err(TPM_RC_CPHASH);
    }

    let attribute = name_hash_attribute(runtime)?;
    let digest = next_policy_digest(runtime, &session, TPM_CC_POLICY_NAME_HASH, &[&name_hash])?;
    publish_restriction(
        runtime,
        &session,
        Restriction {
            digest,
            value: name_hash,
            attribute,
        },
    )
}

pub(super) fn execute_template(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let session = policy_session(runtime, frame)?;
    let template_hash = sole_digest(frame, RC_FIRST)?;

    let entry = live_session(runtime, &session)?;
    if is_cp_hash_union_occupied(entry.attributes)
        && (entry.attributes & SESSION_ATTR_IS_TEMPLATE_HASH_DEFINED == 0
            || !digests_equal(&template_hash, &entry.bound_entity))
    {
        return Err(TPM_RC_CPHASH);
    }
    matches_session_digest_size(&session, &template_hash, RC_FIRST)?;

    let digest = next_policy_digest(runtime, &session, TPM_CC_POLICY_TEMPLATE, &[&template_hash])?;
    publish_restriction(
        runtime,
        &session,
        Restriction {
            digest,
            value: template_hash,
            attribute: SESSION_ATTR_IS_TEMPLATE_HASH_DEFINED,
        },
    )
}

pub(super) fn execute_parameters(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let session = policy_session(runtime, frame)?;
    let parameters_hash = sole_digest(frame, RC_FIRST)?;
    matches_session_digest_size(&session, &parameters_hash, RC_FIRST)?;
    if is_cp_hash_union_occupied(session_attributes(runtime, &session)?) {
        return Err(TPM_RC_CPHASH);
    }

    let digest = next_policy_digest(
        runtime,
        &session,
        TPM_CC_POLICY_PARAMETERS,
        &[&parameters_hash],
    )?;
    publish_restriction(
        runtime,
        &session,
        Restriction {
            digest,
            value: parameters_hash,
            attribute: SESSION_ATTR_IS_PARAMETERS_HASH_DEFINED,
        },
    )
}

pub(super) fn execute_physical_presence(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let session = policy_session(runtime, frame)?;
    no_parameters(frame)?;

    let digest = next_policy_digest(runtime, &session, TPM_CC_POLICY_PHYSICAL_PRESENCE, &[])?;
    let entry = live_session_mut(runtime, &session)?;
    entry.audit_digest = digest;
    entry.attributes |= SESSION_ATTR_IS_PP_REQUIRED;
    Ok(CommandOutput::empty())
}

fn narrowed_locality(previous: u8, requested: u8) -> Result<u8, TpmResult> {
    if requested == 0 {
        return Err(TPM_RC_RANGE + RC_FIRST);
    }
    if previous != 0 && ((previous < NORMAL_LOCALITY_LIMIT) != (requested < NORMAL_LOCALITY_LIMIT))
    {
        return Err(TPM_RC_RANGE + RC_FIRST);
    }
    if requested < NORMAL_LOCALITY_LIMIT {
        let base = if previous == 0 {
            ALL_NORMAL_LOCALITIES
        } else {
            previous
        };
        let narrowed = base & requested;
        if narrowed == 0 {
            return Err(TPM_RC_RANGE + RC_FIRST);
        }
        Ok(narrowed)
    } else {
        if previous != 0 && previous != requested {
            return Err(TPM_RC_RANGE + RC_FIRST);
        }
        Ok(requested)
    }
}

pub(super) fn execute_locality(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let session = policy_session(runtime, frame)?;
    let mut reader = TemplateReader::new(frame.parameters);
    let requested = reader.u8().map_err(|code| code + RC_FIRST)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }

    let previous = live_session(runtime, &session)?.command_locality;
    let narrowed = narrowed_locality(previous, requested)?;

    let digest = next_policy_digest(runtime, &session, TPM_CC_POLICY_LOCALITY, &[&[requested]])?;
    let entry = live_session_mut(runtime, &session)?;
    entry.audit_digest = digest;
    entry.command_locality = narrowed;
    Ok(CommandOutput::empty())
}

fn yes_no(reader: &mut TemplateReader<'_>, blame: TpmResult) -> Result<u8, TpmResult> {
    let value = reader.u8().map_err(|code| code + blame)?;
    if value > 1 {
        return Err(TPM_RC_VALUE + blame);
    }
    Ok(value)
}

pub(super) fn execute_nv_written(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let session = policy_session(runtime, frame)?;
    let mut reader = TemplateReader::new(frame.parameters);
    let written_set = yes_no(&mut reader, RC_FIRST)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }

    let attributes = session_attributes(runtime, &session)?;
    if attributes & SESSION_ATTR_CHECK_NV_WRITTEN != 0
        && (attributes & SESSION_ATTR_NV_WRITTEN_STATE != 0) != (written_set == 1)
    {
        return Err(TPM_RC_VALUE + RC_FIRST);
    }

    let digest = next_policy_digest(
        runtime,
        &session,
        TPM_CC_POLICY_NV_WRITTEN,
        &[&[written_set]],
    )?;
    let entry = live_session_mut(runtime, &session)?;
    entry.audit_digest = digest;
    entry.attributes |= SESSION_ATTR_CHECK_NV_WRITTEN;
    if written_set == 1 {
        entry.attributes |= SESSION_ATTR_NV_WRITTEN_STATE;
    } else {
        entry.attributes &= !SESSION_ATTR_NV_WRITTEN_STATE;
    }
    Ok(CommandOutput::empty())
}

struct DuplicationSelect<'a> {
    object_name: &'a [u8],
    new_parent_name: &'a [u8],
    include_object: u8,
}

fn parse_duplication_select<'a>(parameters: &'a [u8]) -> Result<DuplicationSelect<'a>, TpmResult> {
    let mut reader = TemplateReader::new(parameters);
    let object_name = reader.tpm2b(NAME_SIZE).map_err(|code| code + RC_FIRST)?;
    let new_parent_name = reader.tpm2b(NAME_SIZE).map_err(|code| code + RC_SECOND)?;
    let include_object = yes_no(&mut reader, RC_THIRD)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(DuplicationSelect {
        object_name,
        new_parent_name,
        include_object,
    })
}

pub(super) fn execute_duplication_select(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let session = policy_session(runtime, frame)?;
    let input = parse_duplication_select(frame.parameters)?;

    let entry = live_session(runtime, &session)?;
    if !entry.bound_entity.is_empty() {
        return Err(TPM_RC_CPHASH);
    }
    if entry.command_code != 0 {
        return Err(TPM_RC_COMMAND_CODE);
    }

    let name_hash = hash_parts(
        runtime,
        session.hash_alg,
        &[input.object_name, input.new_parent_name],
    )?;
    let mut extra: Vec<&[u8]> = Vec::with_capacity(3);
    if input.include_object == 1 {
        extra.push(input.object_name);
    }
    extra.push(input.new_parent_name);
    let include = [input.include_object];
    extra.push(&include);
    let digest = next_policy_digest(runtime, &session, TPM_CC_POLICY_DUPLICATION_SELECT, &extra)?;

    let attribute = name_hash_attribute(runtime)?;
    let entry = live_session_mut(runtime, &session)?;
    entry.bound_entity = name_hash;
    entry.attributes |= attribute;
    entry.audit_digest = digest;
    entry.command_code = TPM_CC_DUPLICATE;
    Ok(CommandOutput::empty())
}

#[cfg(test)]
mod tests {
    use super::super::nv_common::harness::*;
    use super::super::policy_common::harness::*;
    use super::super::registry::{CommandLifecycle, HandleKind, NvAccess, find};
    use super::*;
    use crate::library::tpm2::golden_responses::policy_sessions::vector;
    use crate::library::tpm2::session::SESSION_ATTR_IS_TRIAL_POLICY;

    fn policy_command(code: u32, extra: &[u8]) -> Vec<u8> {
        command(code, &[POLICY_SESSION_0], &[], extra)
    }

    #[track_caller]
    fn run(runtime: &mut Tpm2Runtime, code: u32, extra: &[u8]) -> Vec<u8> {
        dispatch_bytes(runtime, &policy_command(code, extra))
    }

    #[track_caller]
    fn digest(runtime: &mut Tpm2Runtime) -> Vec<u8> {
        run(runtime, CC_POLICY_GET_DIGEST, &[])
    }

    fn sized(payload: &[u8]) -> Vec<u8> {
        let mut out = (payload.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn the_command_attributes_match_the_oracle() {
        for (code, record, expected, decrypt) in [
            (CC_POLICY_CP_HASH, "CCATTR_016E", 0x0200_016eu32, 2u16),
            (CC_POLICY_LOCALITY, "CCATTR_016F", 0x0200_016f, 0),
            (CC_POLICY_NAME_HASH, "CCATTR_0170", 0x0200_0170, 2),
            (CC_POLICY_PHYSICAL_PRESENCE, "CCATTR_0187", 0x0200_0187, 0),
            (CC_POLICY_DUPLICATION_SELECT, "CCATTR_0188", 0x0200_0188, 2),
            (CC_POLICY_NV_WRITTEN, "CCATTR_018F", 0x0200_018f, 0),
            (CC_POLICY_TEMPLATE, "CCATTR_0190", 0x0200_0190, 2),
            (CC_POLICY_PARAMETERS, "CCATTR_019C", 0x0200_019c, 2),
        ] {
            let oracle = vector(record);
            let attributes = u32::from_be_bytes(oracle[19..23].try_into().unwrap());
            let descriptor = find(code).expect("a registered command");
            assert_eq!(descriptor.attributes, attributes, "{record}");
            assert_eq!(descriptor.attributes, expected, "{record}");
            assert_eq!(descriptor.handles.len(), 1, "{record}");
            assert!(!descriptor.handles[0].user_auth, "{record}");
            assert!(!descriptor.handles[0].admin_role, "{record}");
            assert!(
                matches!(descriptor.handles[0].kind, HandleKind::PolicySession),
                "{record}"
            );
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
        }
    }

    #[test]
    fn every_direct_assertion_matches_the_oracle_digest() {
        let mut runtime = restored("POLICY_FRESH");
        assert_eq!(
            run(&mut runtime, CC_POLICY_CP_HASH, &sized(&[0x11; 32])),
            vector("PCPH_FIRST")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_CP_HASH"));

        let mut runtime = restored("POLICY_FRESH");
        assert_eq!(
            run(&mut runtime, CC_POLICY_NAME_HASH, &sized(&[0x22; 32])),
            vector("PNH_FIRST")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_NAME_HASH"));

        let mut runtime = restored("POLICY_FRESH");
        assert_eq!(
            run(&mut runtime, CC_POLICY_TEMPLATE, &sized(&[0x33; 32])),
            vector("PTPL_FIRST")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_TEMPLATE"));

        let mut runtime = restored("POLICY_FRESH");
        assert_eq!(
            run(&mut runtime, CC_POLICY_PARAMETERS, &sized(&[0x44; 32])),
            vector("PPARM_FIRST")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_PARAMETERS"));

        let mut runtime = restored("POLICY_FRESH");
        assert_eq!(
            run(&mut runtime, CC_POLICY_PHYSICAL_PRESENCE, &[]),
            vector("PPP_FIRST")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_PHYSICAL_PRESENCE"));

        let mut runtime = restored("POLICY_FRESH");
        assert_eq!(
            run(&mut runtime, CC_POLICY_LOCALITY, &[0x04]),
            vector("PLOC_FOUR")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_LOCALITY"));

        let mut runtime = restored("POLICY_FRESH");
        assert_eq!(
            run(&mut runtime, CC_POLICY_NV_WRITTEN, &[0x01]),
            vector("PNVW_SET")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_NV_WRITTEN"));
    }

    #[test]
    fn the_restriction_fields_follow_the_policy_digest() {
        let mut runtime = restored("POLICY_FRESH");
        run(&mut runtime, CC_POLICY_CP_HASH, &sized(&[0x11; 32]));
        let session = session_of(&runtime, POLICY_SESSION_0);
        assert_eq!(session.bound_entity, vec![0x11; 32]);
        assert_ne!(session.attributes & SESSION_ATTR_IS_CP_HASH_DEFINED, 0);

        let mut runtime = restored("POLICY_FRESH");
        run(&mut runtime, CC_POLICY_NAME_HASH, &sized(&[0x22; 32]));
        let session = session_of(&runtime, POLICY_SESSION_0);
        assert_eq!(session.bound_entity, vec![0x22; 32]);
        assert_ne!(session.attributes & SESSION_ATTR_IS_NAME_HASH_DEFINED, 0);

        let mut runtime = restored("POLICY_FRESH");
        run(&mut runtime, CC_POLICY_TEMPLATE, &sized(&[0x33; 32]));
        let session = session_of(&runtime, POLICY_SESSION_0);
        assert_eq!(session.bound_entity, vec![0x33; 32]);
        assert_ne!(
            session.attributes & SESSION_ATTR_IS_TEMPLATE_HASH_DEFINED,
            0
        );

        let mut runtime = restored("POLICY_FRESH");
        run(&mut runtime, CC_POLICY_PARAMETERS, &sized(&[0x44; 32]));
        let session = session_of(&runtime, POLICY_SESSION_0);
        assert_eq!(session.bound_entity, vec![0x44; 32]);
        assert_ne!(
            session.attributes & SESSION_ATTR_IS_PARAMETERS_HASH_DEFINED,
            0
        );

        let mut runtime = restored("POLICY_FRESH");
        run(&mut runtime, CC_POLICY_PHYSICAL_PRESENCE, &[]);
        assert_ne!(
            session_of(&runtime, POLICY_SESSION_0).attributes & SESSION_ATTR_IS_PP_REQUIRED,
            0
        );
    }

    #[test]
    fn the_locality_narrows_and_never_widens() {
        assert_eq!(narrowed_locality(0, 0x1f), Ok(0x1f));
        assert_eq!(narrowed_locality(0, 0x04), Ok(0x04));
        assert_eq!(narrowed_locality(0x1f, 0x05), Ok(0x05));
        assert_eq!(narrowed_locality(0x05, 0x04), Ok(0x04));
        assert_eq!(narrowed_locality(0x04, 0x0c), Ok(0x04));
        assert_eq!(narrowed_locality(0x04, 0x08), Err(TPM_RC_RANGE + RC_FIRST));
        assert_eq!(narrowed_locality(0x00, 0x00), Err(TPM_RC_RANGE + RC_FIRST));
        assert_eq!(narrowed_locality(0x04, 0x00), Err(TPM_RC_RANGE + RC_FIRST));
        assert_eq!(narrowed_locality(0, 40), Ok(40));
        assert_eq!(narrowed_locality(40, 40), Ok(40));
        assert_eq!(narrowed_locality(40, 41), Err(TPM_RC_RANGE + RC_FIRST));
        assert_eq!(narrowed_locality(40, 0x04), Err(TPM_RC_RANGE + RC_FIRST));
        assert_eq!(narrowed_locality(0x04, 40), Err(TPM_RC_RANGE + RC_FIRST));
    }

    #[test]
    fn repeated_and_conflicting_assertions_match_the_oracle() {
        let mut runtime = restored("POLICY_FRESH");
        run(&mut runtime, CC_POLICY_CP_HASH, &sized(&[0x11; 32]));
        assert_eq!(
            run(&mut runtime, CC_POLICY_CP_HASH, &sized(&[0x11; 32])),
            vector("PCPH_REPEATED")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_REPEATED_CP_HASH"));
        assert_eq!(
            run(&mut runtime, CC_POLICY_CP_HASH, &sized(&[0x99; 32])),
            vector("PCPH_CONFLICT")
        );
        assert_eq!(
            run(&mut runtime, CC_POLICY_NAME_HASH, &sized(&[0x22; 32])),
            vector("PNH_AFTER_CP_HASH")
        );
        assert_eq!(
            run(&mut runtime, CC_POLICY_TEMPLATE, &sized(&[0x33; 32])),
            vector("PTPL_AFTER_CP_HASH")
        );
        assert_eq!(
            run(&mut runtime, CC_POLICY_PARAMETERS, &sized(&[0x44; 32])),
            vector("PPARM_AFTER_CP_HASH")
        );

        let mut runtime = restored("POLICY_FRESH");
        run(&mut runtime, CC_POLICY_LOCALITY, &[0x0c]);
        assert_eq!(
            run(&mut runtime, CC_POLICY_LOCALITY, &[0x04]),
            vector("PLOC_NARROWED")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_NARROWED_LOCALITY"));
        assert_eq!(
            run(&mut runtime, CC_POLICY_LOCALITY, &[0x08]),
            vector("PLOC_DISJOINT")
        );
        assert_eq!(
            run(&mut runtime, CC_POLICY_LOCALITY, &[0x00]),
            vector("PLOC_ZERO")
        );

        let mut runtime = restored("POLICY_FRESH");
        run(&mut runtime, CC_POLICY_NV_WRITTEN, &[0x01]);
        assert_eq!(
            run(&mut runtime, CC_POLICY_NV_WRITTEN, &[0x01]),
            vector("PNVW_REPEATED")
        );
        assert_eq!(
            run(&mut runtime, CC_POLICY_NV_WRITTEN, &[0x00]),
            vector("PNVW_CONFLICT")
        );
    }

    #[test]
    fn duplication_select_seeds_the_name_hash_and_the_command_code() {
        let mut runtime = restored("POLICY_FRESH");
        let mut parameters = sized(&[0xa1; 34]);
        parameters.extend_from_slice(&sized(&[0xb2; 34]));
        parameters.push(0x01);
        assert_eq!(
            run(&mut runtime, CC_POLICY_DUPLICATION_SELECT, &parameters),
            vector("PDS_INCLUDED")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_DUPLICATION"));
        let session = session_of(&runtime, POLICY_SESSION_0);
        assert_eq!(session.command_code, TPM_CC_DUPLICATE);
        assert_ne!(session.attributes & SESSION_ATTR_IS_NAME_HASH_DEFINED, 0);
        assert_eq!(session.bound_entity.len(), 32);

        assert_eq!(
            run(&mut runtime, CC_POLICY_DUPLICATION_SELECT, &parameters),
            vector("PDS_REPEATED")
        );

        let mut runtime = restored("POLICY_FRESH");
        let mut excluded = sized(&[0xa1; 34]);
        excluded.extend_from_slice(&sized(&[0xb2; 34]));
        excluded.push(0x00);
        assert_eq!(
            run(&mut runtime, CC_POLICY_DUPLICATION_SELECT, &excluded),
            vector("PDS_EXCLUDED")
        );
        assert_eq!(
            digest(&mut runtime),
            vector("PGD_AFTER_DUPLICATION_EXCLUDED")
        );
    }

    #[test]
    fn duplication_select_refuses_a_session_that_already_carries_a_command_code() {
        let mut runtime = restored("POLICY_FRESH");
        run(
            &mut runtime,
            CC_POLICY_COMMAND_CODE,
            &0x0000_014bu32.to_be_bytes(),
        );
        let mut parameters = sized(&[0xa1; 34]);
        parameters.extend_from_slice(&sized(&[0xb2; 34]));
        parameters.push(0x01);
        assert_eq!(
            run(&mut runtime, CC_POLICY_DUPLICATION_SELECT, &parameters),
            vector("PDS_COMMAND_CODE_SET")
        );
    }

    #[test]
    fn malformed_direct_assertions_match_the_oracle() {
        let mut runtime = restored("POLICY_FRESH");
        for (record, code, extra) in [
            ("PCPH_SHORT", CC_POLICY_CP_HASH, sized(&[0x11; 20])),
            ("PCPH_OVERSIZED", CC_POLICY_CP_HASH, sized(&[0x11; 65])),
            ("PCPH_EMPTY", CC_POLICY_CP_HASH, sized(&[])),
            ("PCPH_TRUNCATED", CC_POLICY_CP_HASH, vec![0x00]),
            ("PCPH_TRAILING", CC_POLICY_CP_HASH, {
                let mut out = sized(&[0x11; 32]);
                out.push(0x00);
                out
            }),
            ("PNH_SHORT", CC_POLICY_NAME_HASH, sized(&[0x22; 20])),
            ("PTPL_SHORT", CC_POLICY_TEMPLATE, sized(&[0x33; 20])),
            ("PPARM_SHORT", CC_POLICY_PARAMETERS, sized(&[0x44; 20])),
            ("PPP_TRAILING", CC_POLICY_PHYSICAL_PRESENCE, vec![0x00]),
            ("PLOC_MISSING", CC_POLICY_LOCALITY, Vec::new()),
            ("PLOC_TRAILING", CC_POLICY_LOCALITY, vec![0x04, 0x00]),
            ("PNVW_MISSING", CC_POLICY_NV_WRITTEN, Vec::new()),
            ("PNVW_INVALID", CC_POLICY_NV_WRITTEN, vec![0x02]),
            ("PNVW_TRAILING", CC_POLICY_NV_WRITTEN, vec![0x01, 0x00]),
            (
                "PDS_TRUNCATED",
                CC_POLICY_DUPLICATION_SELECT,
                sized(&[0xa1; 34]),
            ),
            ("PDS_OVERSIZED_NAME", CC_POLICY_DUPLICATION_SELECT, {
                let mut out = sized(&[0xa1; 69]);
                out.extend_from_slice(&sized(&[0xb2; 34]));
                out.push(0x01);
                out
            }),
            ("PDS_INVALID_INCLUDE", CC_POLICY_DUPLICATION_SELECT, {
                let mut out = sized(&[0xa1; 34]);
                out.extend_from_slice(&sized(&[0xb2; 34]));
                out.push(0x05);
                out
            }),
        ] {
            assert_eq!(run(&mut runtime, code, &extra), vector(record), "{record}");
        }
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_DIRECT_FAILURES"));
    }

    #[test]
    fn a_failed_direct_assertion_leaves_the_session_untouched() {
        let mut runtime = restored("POLICY_FRESH");
        run(&mut runtime, CC_POLICY_CP_HASH, &sized(&[0x11; 32]));
        let before = session_of(&runtime, POLICY_SESSION_0).clone();
        for (code, extra) in [
            (CC_POLICY_CP_HASH, sized(&[0x99; 32])),
            (CC_POLICY_CP_HASH, sized(&[0x11; 20])),
            (CC_POLICY_NAME_HASH, sized(&[0x22; 32])),
            (CC_POLICY_TEMPLATE, sized(&[0x33; 32])),
            (CC_POLICY_PARAMETERS, sized(&[0x44; 32])),
            (CC_POLICY_LOCALITY, vec![0x00]),
            (CC_POLICY_NV_WRITTEN, vec![0x02]),
            (CC_POLICY_PHYSICAL_PRESENCE, vec![0x00]),
        ] {
            let response = run(&mut runtime, code, &extra);
            assert_ne!(response_code(&response), RC_SUCCESS);
            let after = session_of(&runtime, POLICY_SESSION_0);
            assert_eq!(after.attributes, before.attributes);
            assert_eq!(after.audit_digest, before.audit_digest);
            assert_eq!(after.bound_entity, before.bound_entity);
            assert_eq!(after.command_locality, before.command_locality);
            assert_eq!(after.command_code, before.command_code);
        }
    }

    #[test]
    fn a_trial_session_records_the_same_restrictions() {
        let mut runtime = restored("TRIAL_FRESH");
        assert_eq!(
            run(&mut runtime, CC_POLICY_CP_HASH, &sized(&[0x11; 32])),
            vector("TRIAL_PCPH")
        );
        assert_eq!(digest(&mut runtime), vector("TRIAL_PGD_AFTER_CP_HASH"));
        assert_eq!(
            run(&mut runtime, CC_POLICY_LOCALITY, &[0x04]),
            vector("TRIAL_PLOC")
        );
        assert_eq!(digest(&mut runtime), vector("TRIAL_PGD_AFTER_LOCALITY"));
        assert_eq!(
            run(&mut runtime, CC_POLICY_NV_WRITTEN, &[0x01]),
            vector("TRIAL_PNVW")
        );
        assert_eq!(digest(&mut runtime), vector("TRIAL_PGD_AFTER_NV_WRITTEN"));
        let session = session_of(&runtime, POLICY_SESSION_0);
        assert_ne!(session.attributes & SESSION_ATTR_IS_TRIAL_POLICY, 0);
        assert_ne!(session.attributes & SESSION_ATTR_CHECK_NV_WRITTEN, 0);
        assert_eq!(session.command_locality, 0x04);
    }

    #[test]
    fn malformed_direct_assertion_requests_never_panic() {
        let valid = policy_command(CC_POLICY_DUPLICATION_SELECT, &{
            let mut out = sized(&[0xa1; 34]);
            out.extend_from_slice(&sized(&[0xb2; 34]));
            out.push(0x01);
            out
        });
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
