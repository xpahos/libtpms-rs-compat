use super::session::{
    PolicySession, check_condition, extend_policy_digest, hash_parts, operation_is_supported,
    policy_session_at,
};
use crate::ffi::types::TpmResult;
use crate::library::constants::{
    TPM_RC_FAILURE, TPM_RC_HANDLE, TPM_RC_NV_UNAVAILABLE, TPM_RC_POLICY, TPM_RC_RANGE, TPM_RC_SIZE,
    TPM_RC_VALUE,
};
use crate::library::tpm2::capability::single::{LookupError, lookup};
use crate::library::tpm2::command::attestation::builder::{TIME_INFO_SIZE, marshaled_time_info};
use crate::library::tpm2::command::core::dispatcher::{CommandFrame, handle_at};
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::command::core::registry::{
    TPM_CC_POLICY_CAPABILITY, TPM_CC_POLICY_COUNTER_TIMER, TPM_CC_POLICY_NV,
};
use crate::library::tpm2::command::core::response_code::{
    TPM_RC_1, TPM_RC_2, TPM_RC_3, TPM_RC_4, TPM_RC_5, TPM_RC_P,
};
use crate::library::tpm2::command::nv::access::{read_access_checks, resolve};
use crate::library::tpm2::entity::entity_name;
use crate::library::tpm2::nv::read_index_data;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::template::TemplateReader;

const RC_OPERAND_B: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_OFFSET: TpmResult = TPM_RC_P + TPM_RC_2;
const RC_OPERATION: TpmResult = TPM_RC_P + TPM_RC_3;
const RC_CAPABILITY: TpmResult = TPM_RC_P + TPM_RC_4;
const RC_PROPERTY: TpmResult = TPM_RC_P + TPM_RC_5;

const MAX_OPERAND_SIZE: usize = 64;

const CLOCK_FIELDS_END: u16 = 16;

struct Comparison<'a> {
    operand_b: &'a [u8],
    offset: u16,
    operation: u16,
}

impl Comparison<'_> {
    fn argument_parts(&self) -> ([u8; 2], [u8; 2]) {
        (self.offset.to_be_bytes(), self.operation.to_be_bytes())
    }
}

fn parse_comparison<'a>(reader: &mut TemplateReader<'a>) -> Result<Comparison<'a>, TpmResult> {
    let operand_b = reader
        .tpm2b(MAX_OPERAND_SIZE)
        .map_err(|code| code + RC_OPERAND_B)?;
    let offset = reader.u16().map_err(|code| code + RC_OFFSET)?;
    let operation = reader.u16().map_err(|code| code + RC_OPERATION)?;
    if !operation_is_supported(operation) {
        return Err(TPM_RC_VALUE + RC_OPERATION);
    }
    Ok(Comparison {
        operand_b,
        offset,
        operation,
    })
}

fn argument_digest(
    runtime: &mut Tpm2Runtime,
    session: &PolicySession,
    comparison: &Comparison<'_>,
    trailer: &[&[u8]],
) -> Result<Vec<u8>, TpmResult> {
    let (offset, operation) = comparison.argument_parts();
    let mut parts: Vec<&[u8]> = vec![comparison.operand_b, &offset, &operation];
    parts.extend_from_slice(trailer);
    hash_parts(runtime, session.hash_alg, &parts)
}

pub(in crate::library::tpm2::command) fn execute_nv(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let auth_handle = handle_at(frame, 0)?;
    let nv_handle = handle_at(frame, 1)?;
    let session = policy_session_at(runtime, frame, 2)?;

    let mut reader = TemplateReader::new(frame.parameters);
    let comparison = parse_comparison(&mut reader)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }

    if !session.is_trial {
        let resolved = resolve(runtime, nv_handle)?;
        read_access_checks(auth_handle, nv_handle, resolved.attributes())?;
        let data_size = resolved.public.data_size;
        if comparison.offset > data_size {
            return Err(TPM_RC_VALUE + RC_OFFSET);
        }
        if usize::from(data_size - comparison.offset) < comparison.operand_b.len() {
            return Err(TPM_RC_SIZE + RC_OPERAND_B);
        }
        let stored = read_index_data(
            runtime,
            &resolved,
            usize::from(comparison.offset),
            comparison.operand_b.len(),
        )?;
        if !check_condition(comparison.operation, &stored, comparison.operand_b)? {
            return Err(TPM_RC_POLICY);
        }
    }

    let name = entity_name(runtime, nv_handle)?;
    let argument = argument_digest(runtime, &session, &comparison, &[])?;
    extend_policy_digest(runtime, &session, TPM_CC_POLICY_NV, &[&argument, &name])?;
    Ok(CommandOutput::empty())
}

pub(in crate::library::tpm2::command) fn execute_counter_timer(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let session = policy_session_at(runtime, frame, 0)?;

    let mut reader = TemplateReader::new(frame.parameters);
    let comparison = parse_comparison(&mut reader)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }

    let info_size = TIME_INFO_SIZE as u16;
    if comparison.offset > info_size {
        return Err(TPM_RC_VALUE + RC_OFFSET);
    }
    if u32::from(comparison.offset) + comparison.operand_b.len() as u32 > u32::from(info_size) {
        return Err(TPM_RC_RANGE);
    }

    if !session.is_trial {
        if comparison.offset < CLOCK_FIELDS_END && !runtime.nv_available {
            return Err(TPM_RC_NV_UNAVAILABLE);
        }
        let info = marshaled_time_info(runtime)?;
        let start = usize::from(comparison.offset);
        let selected = info
            .get(start..start + comparison.operand_b.len())
            .ok_or(TPM_RC_FAILURE)?;
        if !check_condition(comparison.operation, selected, comparison.operand_b)? {
            return Err(TPM_RC_POLICY);
        }
    }

    let argument = argument_digest(runtime, &session, &comparison, &[])?;
    extend_policy_digest(runtime, &session, TPM_CC_POLICY_COUNTER_TIMER, &[&argument])?;
    Ok(CommandOutput::empty())
}

pub(in crate::library::tpm2::command) fn execute_capability(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let session = policy_session_at(runtime, frame, 0)?;

    let mut reader = TemplateReader::new(frame.parameters);
    let comparison = parse_comparison(&mut reader)?;
    let capability = reader.u32().map_err(|code| code + RC_CAPABILITY)?;
    if !capability_is_defined(capability) {
        return Err(TPM_RC_VALUE + RC_CAPABILITY);
    }
    let property = reader.u32().map_err(|code| code + RC_PROPERTY)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }

    if !session.is_trial {
        let data = lookup(runtime, capability, property).map_err(|error| match error {
            LookupError::Capability => TPM_RC_VALUE + RC_CAPABILITY,
            LookupError::Property => TPM_RC_VALUE + RC_PROPERTY,
            LookupError::HandleType => TPM_RC_HANDLE + RC_PROPERTY,
            LookupError::Internal => TPM_RC_FAILURE,
        })?;
        if data.is_empty() {
            if comparison.operation != crate::library::tpm2::command::policy::session::TPM_EO_NEQ {
                return Err(TPM_RC_POLICY);
            }
        } else {
            if usize::from(comparison.offset) > data.len() {
                return Err(TPM_RC_VALUE + RC_OFFSET);
            }
            if data.len() - usize::from(comparison.offset) < comparison.operand_b.len() {
                return Err(TPM_RC_SIZE + RC_OPERAND_B);
            }
            let start = usize::from(comparison.offset);
            let selected = &data[start..start + comparison.operand_b.len()];
            if !check_condition(comparison.operation, selected, comparison.operand_b)? {
                return Err(TPM_RC_POLICY);
            }
        }
    }

    let capability_bytes = capability.to_be_bytes();
    let property_bytes = property.to_be_bytes();
    let argument = argument_digest(
        runtime,
        &session,
        &comparison,
        &[&capability_bytes, &property_bytes],
    )?;
    extend_policy_digest(runtime, &session, TPM_CC_POLICY_CAPABILITY, &[&argument])?;
    Ok(CommandOutput::empty())
}

fn capability_is_defined(capability: u32) -> bool {
    use crate::library::tpm2::capability::{
        TPM_CAP_ACT, TPM_CAP_ALGS, TPM_CAP_AUDIT_COMMANDS, TPM_CAP_AUTH_POLICIES, TPM_CAP_COMMANDS,
        TPM_CAP_ECC_CURVES, TPM_CAP_HANDLES, TPM_CAP_PCR_PROPERTIES, TPM_CAP_PCRS,
        TPM_CAP_PP_COMMANDS, TPM_CAP_TPM_PROPERTIES, TPM_CAP_VENDOR_PROPERTY,
    };
    matches!(
        capability,
        TPM_CAP_ALGS
            | TPM_CAP_HANDLES
            | TPM_CAP_COMMANDS
            | TPM_CAP_PP_COMMANDS
            | TPM_CAP_AUDIT_COMMANDS
            | TPM_CAP_PCRS
            | TPM_CAP_TPM_PROPERTIES
            | TPM_CAP_PCR_PROPERTIES
            | TPM_CAP_ECC_CURVES
            | TPM_CAP_AUTH_POLICIES
            | TPM_CAP_ACT
            | TPM_CAP_VENDOR_PROPERTY
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::command::core::registry::{
        CommandLifecycle, HandleKind, NvAccess, find,
    };
    use crate::library::tpm2::command::core::test_support::{
        RC_SUCCESS, command, dispatch_bytes, response_code,
    };
    use crate::library::tpm2::command::policy::session::test_support::{
        CC_POLICY_CAPABILITY, CC_POLICY_COUNTER_TIMER, CC_POLICY_GET_DIGEST, CC_POLICY_NV,
        POLICY_SESSION_0, restored, session_of,
    };
    use crate::library::tpm2::golden_responses::policy_sessions::vector;
    use crate::library::tpm2::hierarchy::TPM_RH_OWNER;

    const NV_INDEX: u32 = 0x0100_0000;

    fn operand(operand_b: &[u8], offset: u16, operation: u16) -> Vec<u8> {
        let mut out = (operand_b.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(operand_b);
        out.extend_from_slice(&offset.to_be_bytes());
        out.extend_from_slice(&operation.to_be_bytes());
        out
    }

    fn capability_operand(
        operand_b: &[u8],
        offset: u16,
        operation: u16,
        capability: u32,
        property: u32,
    ) -> Vec<u8> {
        let mut out = operand(operand_b, offset, operation);
        out.extend_from_slice(&capability.to_be_bytes());
        out.extend_from_slice(&property.to_be_bytes());
        out
    }

    #[track_caller]
    fn nv(runtime: &mut Tpm2Runtime, auth: u32, extra: &[u8]) -> Vec<u8> {
        dispatch_bytes(
            runtime,
            &command(
                CC_POLICY_NV,
                &[auth, NV_INDEX, POLICY_SESSION_0],
                &[&[]],
                extra,
            ),
        )
    }

    #[track_caller]
    fn session_only(runtime: &mut Tpm2Runtime, code: u32, extra: &[u8]) -> Vec<u8> {
        dispatch_bytes(runtime, &command(code, &[POLICY_SESSION_0], &[], extra))
    }

    #[track_caller]
    fn digest(runtime: &mut Tpm2Runtime) -> Vec<u8> {
        session_only(runtime, CC_POLICY_GET_DIGEST, &[])
    }

    #[test]
    fn the_command_attributes_match_the_oracle() {
        for (code, record, expected, handles) in [
            (CC_POLICY_NV, "CCATTR_0149", 0x0600_0149u32, 3usize),
            (CC_POLICY_COUNTER_TIMER, "CCATTR_016D", 0x0200_016d, 1),
            (CC_POLICY_CAPABILITY, "CCATTR_019B", 0x0200_019b, 1),
        ] {
            let oracle = vector(record);
            let attributes = u32::from_be_bytes(oracle[19..23].try_into().unwrap());
            let descriptor = find(code).expect("a registered command");
            assert_eq!(descriptor.attributes, attributes, "{record}");
            assert_eq!(descriptor.attributes, expected, "{record}");
            assert_eq!(descriptor.handles.len(), handles, "{record}");
            assert_eq!(descriptor.decrypt_size, 2, "{record}");
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
            let policy_handle = descriptor.handles.last().expect("a policy session handle");
            assert!(
                matches!(policy_handle.kind, HandleKind::PolicySession),
                "{record}"
            );
            assert!(!policy_handle.user_auth, "{record}");
        }
        let policy_nv = find(CC_POLICY_NV).expect("a registered command");
        assert!(matches!(policy_nv.handles[0].kind, HandleKind::NvAuth));
        assert!(policy_nv.handles[0].user_auth);
        assert!(!policy_nv.handles[0].admin_role());
        assert!(matches!(policy_nv.handles[1].kind, HandleKind::NvIndex));
        assert!(!policy_nv.handles[1].user_auth);
    }

    #[test]
    fn policy_nv_compares_the_stored_bytes_like_the_reference() {
        let mut runtime = restored("OPERAND_NV");
        assert_eq!(
            nv(
                &mut runtime,
                NV_INDEX,
                &operand(&[0x00, 0x00, 0x00, 0x2a], 0, 0x0000)
            ),
            vector("PNV_EQ")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_NV_EQ"));
    }

    #[test]
    fn every_comparison_operator_matches_the_oracle() {
        for (record, operand_b, offset, operation) in [
            ("PNV_OP_EQ", vec![0x00, 0x00, 0x00, 0x2a], 0u16, 0x0000u16),
            ("PNV_OP_NEQ", vec![0x00, 0x00, 0x00, 0x2b], 0, 0x0001),
            ("PNV_OP_SIGNED_GT", vec![0x00, 0x00, 0x00, 0x29], 0, 0x0002),
            (
                "PNV_OP_UNSIGNED_GT",
                vec![0x00, 0x00, 0x00, 0x29],
                0,
                0x0003,
            ),
            ("PNV_OP_SIGNED_LT", vec![0x00, 0x00, 0x00, 0x2b], 0, 0x0004),
            (
                "PNV_OP_UNSIGNED_LT",
                vec![0x00, 0x00, 0x00, 0x2b],
                0,
                0x0005,
            ),
            ("PNV_OP_SIGNED_GE", vec![0x00, 0x00, 0x00, 0x2a], 0, 0x0006),
            (
                "PNV_OP_UNSIGNED_GE",
                vec![0x00, 0x00, 0x00, 0x2a],
                0,
                0x0007,
            ),
            ("PNV_OP_SIGNED_LE", vec![0x00, 0x00, 0x00, 0x2a], 0, 0x0008),
            (
                "PNV_OP_UNSIGNED_LE",
                vec![0x00, 0x00, 0x00, 0x2a],
                0,
                0x0009,
            ),
            ("PNV_OP_BITSET", vec![0x00, 0x00, 0x00, 0x0a], 0, 0x000a),
            ("PNV_OP_BITCLEAR", vec![0x00, 0x00, 0x00, 0x10], 0, 0x000b),
            ("PNV_OP_OFFSET", vec![0x2a], 3, 0x0000),
            ("PNV_OP_FAILS", vec![0x00, 0x00, 0x00, 0x2a], 0, 0x0001),
        ] {
            let mut runtime = restored("OPERAND_NV");
            assert_eq!(
                nv(
                    &mut runtime,
                    NV_INDEX,
                    &operand(&operand_b, offset, operation)
                ),
                vector(record),
                "{record}"
            );
        }
    }

    #[test]
    fn policy_nv_rejects_out_of_range_reads_and_bad_operators() {
        let mut runtime = restored("OPERAND_NV");
        for (record, operand_b, offset, operation) in [
            ("PNV_OFFSET_PAST_END", vec![0x00], 9u16, 0x0000u16),
            ("PNV_OPERAND_TOO_LONG", vec![0x00; 8], 1, 0x0000),
            ("PNV_BAD_OPERATION", vec![0x00], 0, 0x000c),
        ] {
            assert_eq!(
                nv(
                    &mut runtime,
                    NV_INDEX,
                    &operand(&operand_b, offset, operation)
                ),
                vector(record),
                "{record}"
            );
        }
        assert_eq!(nv(&mut runtime, NV_INDEX, &[]), vector("PNV_NO_PARAMETERS"));
        assert_eq!(
            nv(
                &mut runtime,
                TPM_RH_OWNER,
                &operand(&[0x00, 0x00, 0x00, 0x2a], 0, 0x0000)
            ),
            vector("PNV_OWNER_WITHOUT_OWNERREAD"),
            "the owner may not read an index without TPMA_NV_OWNERREAD"
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_NV_FAILURES"));
    }

    #[test]
    fn a_trial_policy_nv_skips_the_comparison_entirely() {
        let mut runtime = restored("OPERAND_NV_TRIAL");
        assert_eq!(
            nv(
                &mut runtime,
                NV_INDEX,
                &operand(&[0xff, 0xff, 0xff, 0xff], 0, 0x0000)
            ),
            vector("TRIAL_PNV")
        );
        assert_eq!(digest(&mut runtime), vector("TRIAL_PGD_AFTER_NV"));
    }

    #[test]
    fn policy_counter_timer_bounds_the_offset_against_the_time_structure() {
        let mut runtime = restored("POLICY_FRESH");
        assert_eq!(
            session_only(
                &mut runtime,
                CC_POLICY_COUNTER_TIMER,
                &operand(&[0x00, 0x00, 0x00, 0x00], 26, 0x0000)
            ),
            vector("PCT_OFFSET_PAST_END")
        );
        assert_eq!(
            session_only(
                &mut runtime,
                CC_POLICY_COUNTER_TIMER,
                &operand(&[0x00, 0x00, 0x00, 0x00], 24, 0x0000)
            ),
            vector("PCT_OPERAND_PAST_END")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_COUNTER_FAILURES"));
    }

    #[test]
    fn policy_counter_timer_reads_the_marshaled_time_structure() {
        let mut runtime = restored("POLICY_FRESH");
        assert_eq!(
            session_only(
                &mut runtime,
                CC_POLICY_COUNTER_TIMER,
                &operand(&[0xfe], 24, 0x000b)
            ),
            vector("PCT_SAFE_BITCLEAR")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_COUNTER_TIMER"));
        assert_eq!(
            session_only(
                &mut runtime,
                CC_POLICY_COUNTER_TIMER,
                &operand(&[0x00; 8], 0, 0x0007)
            ),
            vector("PCT_TIME_UNSIGNED_GE")
        );
        assert_eq!(
            digest(&mut runtime),
            vector("PGD_AFTER_SECOND_COUNTER_TIMER")
        );
    }

    #[test]
    fn the_marshaled_time_structure_is_the_upstream_size_and_layout() {
        let runtime = restored("POLICY_FRESH");
        let info = marshaled_time_info(&runtime).expect("the time structure marshals");
        assert_eq!(info.len(), TIME_INFO_SIZE);
        assert_eq!(info.len(), 25);
        assert_eq!(
            u64::from_be_bytes(info[..8].try_into().unwrap()),
            runtime.timer.time_ms
        );
        assert_eq!(
            u64::from_be_bytes(info[8..16].try_into().unwrap()),
            runtime.live.orderly.clock
        );
    }

    #[test]
    fn a_trial_counter_timer_still_bounds_the_offset() {
        let mut runtime = restored("TRIAL_FRESH");
        assert_eq!(
            session_only(
                &mut runtime,
                CC_POLICY_COUNTER_TIMER,
                &operand(&[0x00], 26, 0x0000)
            ),
            vector("TRIAL_PCT_OFFSET_PAST_END")
        );
        assert_eq!(
            session_only(
                &mut runtime,
                CC_POLICY_COUNTER_TIMER,
                &operand(&[0xff; 8], 0, 0x0000)
            ),
            vector("TRIAL_PCT")
        );
        assert_eq!(digest(&mut runtime), vector("TRIAL_PGD_AFTER_COUNTER"));
    }

    #[test]
    fn policy_capability_compares_the_marshaled_property() {
        let mut runtime = restored("POLICY_FRESH");
        assert_eq!(
            session_only(
                &mut runtime,
                CC_POLICY_CAPABILITY,
                &capability_operand(&[0x00, 0x0b, 0x00, 0x00, 0x00, 0x04], 0, 0x0000, 0, 0x000b)
            ),
            vector("PCAP_ALG_SHA256")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_CAPABILITY"));
    }

    #[test]
    fn policy_capability_rejects_unsupported_capabilities_and_properties() {
        let mut runtime = restored("POLICY_FRESH");
        for (record, capability, property) in [
            ("PCAP_UNKNOWN_CAPABILITY", 0x0000_00ffu32, 0u32),
            ("PCAP_PCRS", 0x0000_0005, 0),
            ("PCAP_ACT", 0x0000_000a, 0x4001_0000),
            ("PCAP_VENDOR", 0x0000_0100, 0),
            ("PCAP_BAD_HANDLE_RANGE", 0x0000_0001, 0x0400_0000),
            ("PCAP_POLICY_NOT_PERMANENT", 0x0000_0009, 0x8000_0000),
        ] {
            assert_eq!(
                session_only(
                    &mut runtime,
                    CC_POLICY_CAPABILITY,
                    &capability_operand(&[0x00], 0, 0x0000, capability, property)
                ),
                vector(record),
                "{record}"
            );
        }
        assert_eq!(
            digest(&mut runtime),
            vector("PGD_AFTER_CAPABILITY_FAILURES")
        );
    }

    #[test]
    fn an_absent_capability_property_only_satisfies_not_equal() {
        let mut runtime = restored("POLICY_FRESH");
        assert_eq!(
            session_only(
                &mut runtime,
                CC_POLICY_CAPABILITY,
                &capability_operand(&[0x00], 0, 0x0001, 0, 0x0fff)
            ),
            vector("PCAP_ABSENT_NEQ")
        );
        assert_eq!(
            session_only(
                &mut runtime,
                CC_POLICY_CAPABILITY,
                &capability_operand(&[0x00], 0, 0x0000, 0, 0x0fff)
            ),
            vector("PCAP_ABSENT_EQ")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_CAPABILITY_ABSENT"));
    }

    #[test]
    fn every_supported_capability_selector_answers_like_the_reference() {
        let mut runtime = restored("POLICY_FRESH");
        for (record, operand_b, operation, capability, property) in [
            (
                "PCAP_PERMANENT_HANDLE",
                vec![0x40, 0x00, 0x00, 0x01],
                0x0000u16,
                0x0000_0001u32,
                0x4000_0001u32,
            ),
            (
                "PCAP_TPM_PROPERTY",
                vec![0x00, 0x00, 0x01, 0x00],
                0x0000,
                0x0000_0006,
                0x0000_0100,
            ),
            (
                "PCAP_PCR_PROPERTY",
                vec![0x00, 0x00, 0x00, 0x00],
                0x0000,
                0x0000_0007,
                0x0000_0000,
            ),
            (
                "PCAP_ECC_CURVE",
                vec![0x00, 0x03],
                0x0000,
                0x0000_0008,
                0x0000_0003,
            ),
            (
                "PCAP_PP_COMMAND",
                vec![0x00],
                0x0001,
                0x0000_0003,
                0x0000_0131,
            ),
            (
                "PCAP_AUDIT_COMMAND",
                vec![0x00],
                0x0001,
                0x0000_0004,
                0x0000_0131,
            ),
        ] {
            assert_eq!(
                session_only(
                    &mut runtime,
                    CC_POLICY_CAPABILITY,
                    &capability_operand(&operand_b, 0, operation, capability, property)
                ),
                vector(record),
                "{record}"
            );
        }
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_CAPABILITY_SWEEP"));
    }

    #[test]
    fn a_trial_capability_assertion_never_reads_the_capability() {
        let mut runtime = restored("TRIAL_FRESH");
        assert_eq!(
            session_only(
                &mut runtime,
                CC_POLICY_CAPABILITY,
                &capability_operand(&[0xff], 0, 0x0000, 0x0000_0005, 0x1234)
            ),
            vector("TRIAL_PCAP_PCRS")
        );
        assert_eq!(digest(&mut runtime), vector("TRIAL_PGD_AFTER_CAPABILITY"));
    }

    #[test]
    fn a_failed_operand_command_leaves_the_session_untouched() {
        let mut runtime = restored("OPERAND_NV");
        let before = session_of(&runtime, POLICY_SESSION_0).clone();
        for response in [
            nv(
                &mut runtime,
                NV_INDEX,
                &operand(&[0x00, 0x00, 0x00, 0x2b], 0, 0x0000),
            ),
            nv(&mut runtime, NV_INDEX, &operand(&[0x00], 0, 0x000c)),
            session_only(
                &mut runtime,
                CC_POLICY_COUNTER_TIMER,
                &operand(&[0x00], 30, 0x0000),
            ),
            session_only(
                &mut runtime,
                CC_POLICY_CAPABILITY,
                &capability_operand(&[0x00], 0, 0x0000, 0xdead_beef, 0),
            ),
        ] {
            assert_ne!(response_code(&response), RC_SUCCESS);
            let after = session_of(&runtime, POLICY_SESSION_0);
            assert_eq!(after.audit_digest, before.audit_digest);
            assert_eq!(after.attributes, before.attributes);
        }
    }

    #[test]
    fn parameter_mutations_do_not_panic() {
        let valid = command(
            CC_POLICY_NV,
            &[NV_INDEX, NV_INDEX, POLICY_SESSION_0],
            &[&[]],
            &operand(&[0x00, 0x00, 0x00, 0x2a], 0, 0x0000),
        );
        for length in 10..valid.len() {
            for byte in [0x00u8, 0x01, 0x80, 0xff] {
                let mut mutated = valid[..length].to_vec();
                *mutated.last_mut().expect("a non-empty prefix") = byte;
                let size = (mutated.len() as u32).to_be_bytes();
                mutated[2..6].copy_from_slice(&size);
                let mut runtime = restored("OPERAND_NV");
                let _ = dispatch_bytes(&mut runtime, &mutated);
            }
        }
    }
}
