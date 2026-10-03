// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/CommandCodeAttributes.c
// - libtpms/src/tpm2/CommandDispatcher.c
// - libtpms/src/tpm2/ExecCommand.c
// - libtpms/src/tpm2/SessionProcess.c
//
// Original upstream authors and copyright notices:
// Written by Ken Goldman
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corp. and others, 2016 - 2023
// (c) Copyright IBM Corp. and others, 2016 - 2021
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use super::header::{Command, Response, TPM_ST_NO_SESSIONS, TPM_ST_SESSIONS};
use super::registry::{self, CommandDescriptor, HandleKind};
use super::transaction;
use crate::library::cancel::CancellationToken;
use crate::library::constants::{
    TPM_RC_AUTH_CONTEXT, TPM_RC_AUTH_MISSING, TPM_RC_COMMAND_CODE, TPM_RC_FAILURE, TPM_RC_HANDLE,
    TPM_RC_HIERARCHY, TPM_RC_INITIALIZE, TPM_RC_INSUFFICIENT, TPM_RC_OBJECT_MEMORY,
    TPM_RC_REFERENCE_H0, TPM_RC_SIZE, TPM_RC_VALUE,
};
use crate::library::tpm2::command::administration::command_audit_state;
use crate::library::tpm2::command::session::processing::{
    CommandContext, SessionArea, authorize_sessions, build_response_sessions,
    clear_session_associations, decrypt_first_parameter, parse_session_area, record_session_state,
};
use crate::library::tpm2::hierarchy::{
    TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT, TPM_RH_NULL, TPM_RH_OWNER, TPM_RH_PLATFORM,
};
use crate::library::tpm2::marshal::BlobReader;
use crate::library::tpm2::nv::{index_is_accessible, is_nv_index_handle};
use crate::library::tpm2::object_create::{
    find_empty_object_slot, hierarchy_is_enabled, is_object_handle, is_transient_object_handle,
    occupied_object_slot, persistent_hierarchy_is_enabled, persistent_object_entry,
};
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::sequence::cleanup_evicted;
use crate::library::tpm2::session::{
    SESSION_ATTR_IS_POLICY, is_policy_session_handle, loaded_session,
};
use crate::library::tpm2::volatile::IMPLEMENTATION_PCR;
use crate::types::TpmResult;

const TPM_RC_H: TpmResult = 0x000;
const TPM_RC_1: TpmResult = 0x100;

const MIN_AUTH_AREA_SIZE: usize = 9;

pub(in crate::library::tpm2::command) struct CommandFrame<'a> {
    pub(in crate::library::tpm2::command) handles: Vec<u32>,
    pub(in crate::library::tpm2::command) parameters: &'a [u8],
    pub(in crate::library::tpm2::command) cancellation: CancellationToken<'a>,
}

pub(in crate::library::tpm2) fn dispatch(
    runtime: &mut Tpm2Runtime,
    command: &Command<'_>,
    cancellation: CancellationToken<'_>,
) -> Response {
    let Some(descriptor) = registry::find(command.command_code) else {
        return Response::error(TPM_RC_COMMAND_CODE);
    };
    if !runtime.command_enabled(command.command_code) {
        return Response::error(TPM_RC_COMMAND_CODE);
    }
    if !descriptor.lifecycle.allows(runtime) {
        return Response::error(TPM_RC_INITIALIZE);
    }
    clear_session_associations(runtime);
    let response = match run(runtime, descriptor, command, cancellation) {
        Ok(response) => response,
        Err(code) => Response::error(code),
    };
    cleanup_evicted(runtime);
    response
}

fn run(
    runtime: &mut Tpm2Runtime,
    descriptor: &CommandDescriptor,
    command: &Command<'_>,
    cancellation: CancellationToken<'_>,
) -> Result<Response, TpmResult> {
    let (handles, rest) = parse_handles(descriptor, command.payload)?;
    check_load_status(runtime, descriptor, &handles)?;

    if command.tag != TPM_ST_SESSIONS {
        if descriptor.handles.iter().any(|spec| spec.user_auth) {
            return Err(TPM_RC_AUTH_MISSING);
        }
        let context = CommandContext {
            code: command.command_code,
            handles: &handles,
            parameters: rest,
        };
        let audit_cp_hash = command_audit_state::prepare(runtime, &context)?;
        let frame = CommandFrame {
            handles,
            parameters: rest,
            cancellation,
        };
        let transaction = audit_cp_hash.as_ref().map(|_| transaction::begin(runtime));
        let (out_handles, mut out_parameters) = (descriptor.handler)(runtime, &frame)?.into_parts();
        let mut area = SessionArea::none();
        match build_response_sessions(
            runtime,
            descriptor,
            command.command_code,
            &mut out_parameters,
            &mut area,
            false,
            audit_cp_hash.as_deref(),
        ) {
            Ok(_) => {}
            Err(code) => {
                if let Some(transaction) = transaction {
                    transaction::roll_back(runtime, transaction);
                }
                return Err(code);
            }
        }
        #[cfg(test)]
        let (out_parameters, _) = publish_response(
            runtime,
            command.command_code,
            &out_handles,
            out_parameters,
            Vec::new(),
        );
        return Ok(Response::success_with_handles(
            TPM_ST_NO_SESSIONS,
            out_handles,
            out_parameters,
        ));
    }

    let (auth_area, parameters) = split_authorization_area(descriptor, rest)?;
    let mut area = parse_session_area(runtime, descriptor, auth_area)?;
    let context = CommandContext {
        code: command.command_code,
        handles: &handles,
        parameters,
    };
    let outcome = authorize_sessions(runtime, descriptor, &handles, &context, &mut area);
    record_session_state(runtime, &area);
    outcome?;
    let audit_cp_hash = command_audit_state::prepare(runtime, &context)?;

    let decrypted = decrypt_first_parameter(runtime, descriptor, &area, parameters)?;
    let frame = CommandFrame {
        handles,
        parameters: decrypted.as_deref().unwrap_or(parameters),
        cancellation,
    };
    let transaction = area
        .response_needs_rollback(descriptor.code, audit_cp_hash.as_deref())
        .then(|| transaction::begin(runtime));
    let (out_handles, mut out_parameters) = (descriptor.handler)(runtime, &frame)?.into_parts();
    let auth_response = match build_response_sessions(
        runtime,
        descriptor,
        command.command_code,
        &mut out_parameters,
        &mut area,
        true,
        audit_cp_hash.as_deref(),
    ) {
        Ok(auth_response) => auth_response,
        Err(code) => {
            if let Some(transaction) = transaction {
                transaction::roll_back(runtime, transaction);
            }
            return Err(code);
        }
    };
    record_session_state(runtime, &area);
    #[cfg(test)]
    let (out_parameters, auth_response) = publish_response(
        runtime,
        command.command_code,
        &out_handles,
        out_parameters,
        auth_response,
    );
    Ok(Response::success_with_sessions(
        out_handles,
        out_parameters,
        auth_response,
    ))
}

#[cfg(test)]
fn publish_response(
    runtime: &Tpm2Runtime,
    code: u32,
    handles: &[u8],
    parameters: Vec<u8>,
    auth_response: Vec<u8>,
) -> (Vec<u8>, Vec<u8>) {
    use crate::library::tpm2::memcheck::{publish, verification_copy};
    publish("command-response", &parameters);
    if !auth_response.is_empty() {
        publish("command-response-auth", &auth_response);
    }
    if code == registry::TPM_CC_CREATE_PRIMARY || code == registry::TPM_CC_CREATE_LOADED {
        release_public_copies(runtime, handles);
    }
    (
        verification_copy(&parameters),
        verification_copy(&auth_response),
    )
}

#[cfg(test)]
fn release_public_copies(runtime: &Tpm2Runtime, handles: &[u8]) {
    use crate::library::tpm2::persistent::{OwnedAnyObjectBody, OwnedPublicId};
    let Some(handle) = handles
        .first_chunk::<4>()
        .map(|bytes| u32::from_be_bytes(*bytes))
    else {
        return;
    };
    let Some(slot) = handle
        .checked_sub(0x8000_0000)
        .and_then(|slot| usize::try_from(slot).ok())
    else {
        return;
    };
    let Some(OwnedAnyObjectBody::Object(body)) =
        runtime.live.objects.get(slot).map(|entry| &entry.body)
    else {
        return;
    };
    let release = |bytes: &[u8]| {
        if !bytes.is_empty() {
            crate::library::tpm2::memcheck::publish("released-public-copy", bytes);
        }
    };
    match &body.public.unique {
        OwnedPublicId::Rsa(modulus) => release(modulus),
        OwnedPublicId::Ecc { x, y } => {
            release(x);
            release(y);
        }
        _ => {}
    }
    release(&body.name);
    release(&body.qualified_name);
}

fn split_authorization_area<'a>(
    descriptor: &CommandDescriptor,
    rest: &'a [u8],
) -> Result<(&'a [u8], &'a [u8]), TpmResult> {
    let (size_bytes, after_size) = rest.split_first_chunk::<4>().ok_or(TPM_RC_INSUFFICIENT)?;
    let auth_size = u32::from_be_bytes(*size_bytes) as usize;
    if auth_size < MIN_AUTH_AREA_SIZE || auth_size > after_size.len() {
        return Err(TPM_RC_SIZE);
    }
    if !descriptor.sessions_allowed {
        return Err(TPM_RC_AUTH_CONTEXT);
    }
    Ok((&after_size[..auth_size], &after_size[auth_size..]))
}

fn parse_handles<'a>(
    descriptor: &CommandDescriptor,
    payload: &'a [u8],
) -> Result<(Vec<u32>, &'a [u8]), TpmResult> {
    let mut reader = BlobReader::new(payload);
    let mut handles = Vec::with_capacity(descriptor.handles.len());
    for (index, spec) in descriptor.handles.iter().enumerate() {
        let error_index = TPM_RC_H + TPM_RC_1 * (index as u32 + 1);
        let handle = reader
            .read_u32()
            .map_err(|_| TPM_RC_INSUFFICIENT + error_index)?;
        if !spec.kind.accepts(handle) {
            return Err(TPM_RC_VALUE + error_index);
        }
        handles.push(handle);
    }
    Ok((handles, reader.remaining()))
}

fn check_load_status(
    runtime: &Tpm2Runtime,
    descriptor: &CommandDescriptor,
    handles: &[u32],
) -> Result<(), TpmResult> {
    for (index, spec) in descriptor.handles.iter().enumerate() {
        let Some(&handle) = handles.get(index) else {
            continue;
        };
        let indexed = TPM_RC_H + TPM_RC_1 * (index as u32 + 1);
        if matches!(handle, TPM_RH_OWNER | TPM_RH_ENDORSEMENT | TPM_RH_PLATFORM)
            && !hierarchy_is_enabled(runtime, handle)
        {
            return Err(TPM_RC_HIERARCHY + indexed);
        }
        match spec.kind {
            HandleKind::Object => check_object_present(runtime, handle, index)?,
            HandleKind::ObjectAllowNull if handle != TPM_RH_NULL => {
                check_object_present(runtime, handle, index)?;
            }
            HandleKind::Parent => {
                if is_object_handle(handle) {
                    check_object_present(runtime, handle, index)?;
                } else if !hierarchy_is_enabled(runtime, handle) {
                    return Err(TPM_RC_HIERARCHY + indexed);
                }
            }
            HandleKind::NvIndex => index_is_accessible(runtime, handle).map_err(|code| {
                if code == TPM_RC_HANDLE {
                    code + indexed
                } else {
                    code
                }
            })?,
            HandleKind::NvAuth if is_nv_index_handle(handle) => {
                index_is_accessible(runtime, handle).map_err(|code| {
                    if code == TPM_RC_HANDLE {
                        code + indexed
                    } else {
                        code
                    }
                })?;
            }
            HandleKind::Entity | HandleKind::EntityAllowNull => {
                check_entity_present(runtime, handle, index)?;
            }
            HandleKind::Context => {
                if is_transient_object_handle(handle) {
                    check_object_present(runtime, handle, index)?;
                } else {
                    match loaded_session(&runtime.live, handle) {
                        Some(session) => {
                            let is_policy = session.attributes & SESSION_ATTR_IS_POLICY != 0;
                            if is_policy != is_policy_session_handle(handle) {
                                return Err(TPM_RC_HANDLE + indexed);
                            }
                        }
                        None => return Err(TPM_RC_REFERENCE_H0 + index as u32),
                    }
                }
            }
            HandleKind::PolicySession => match loaded_session(&runtime.live, handle) {
                Some(session) if session.attributes & SESSION_ATTR_IS_POLICY != 0 => {}
                Some(_) => return Err(TPM_RC_HANDLE + indexed),
                None => return Err(TPM_RC_REFERENCE_H0 + index as u32),
            },
            HandleKind::HmacSession => match loaded_session(&runtime.live, handle) {
                Some(session) if session.attributes & SESSION_ATTR_IS_POLICY == 0 => {}
                Some(_) => return Err(TPM_RC_HANDLE + indexed),
                None => return Err(TPM_RC_REFERENCE_H0 + index as u32),
            },
            _ => {}
        }
    }
    Ok(())
}

fn check_entity_present(runtime: &Tpm2Runtime, handle: u32, index: usize) -> Result<(), TpmResult> {
    let indexed = TPM_RC_H + TPM_RC_1 * (index as u32 + 1);
    if is_object_handle(handle) {
        return check_object_present(runtime, handle, index);
    }
    if is_nv_index_handle(handle) {
        return index_is_accessible(runtime, handle).map_err(|code| {
            if code == TPM_RC_HANDLE {
                code + indexed
            } else {
                code
            }
        });
    }
    if (handle as usize) < IMPLEMENTATION_PCR || handle == TPM_RH_LOCKOUT {
        return Ok(());
    }
    if !matches!(
        handle,
        TPM_RH_OWNER | TPM_RH_ENDORSEMENT | TPM_RH_PLATFORM | TPM_RH_NULL
    ) {
        return Err(TPM_RC_VALUE + indexed);
    }
    if !hierarchy_is_enabled(runtime, handle) {
        return Err(TPM_RC_HIERARCHY + indexed);
    }
    Ok(())
}

fn check_object_present(runtime: &Tpm2Runtime, handle: u32, index: usize) -> Result<(), TpmResult> {
    let indexed_handle = TPM_RC_HANDLE + TPM_RC_H + TPM_RC_1 * (index as u32 + 1);
    if is_transient_object_handle(handle) {
        return match occupied_object_slot(runtime, handle) {
            Some(_) => Ok(()),
            None => Err(TPM_RC_REFERENCE_H0 + index as u32),
        };
    }
    if !persistent_hierarchy_is_enabled(runtime, handle) {
        return Err(indexed_handle);
    }
    if find_empty_object_slot(runtime).is_none() {
        return Err(TPM_RC_OBJECT_MEMORY);
    }
    if persistent_object_entry(runtime, handle).is_none() {
        return Err(indexed_handle);
    }
    Ok(())
}

pub(in crate::library::tpm2::command) fn handle_at(
    frame: &CommandFrame<'_>,
    position: usize,
) -> Result<u32, TpmResult> {
    frame.handles.get(position).copied().ok_or(TPM_RC_FAILURE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::CommandInput;
    use crate::library::tpm2::command::core::header::{parse_command, serialize_response};
    use crate::library::tpm2::command::core::registry::{
        TPM_CC_PCR_EXTEND, TPM_CC_SHUTDOWN, TPM_CC_STARTUP,
    };
    use crate::library::tpm2::command::core::test_support::{
        dispatch_ignoring_result, for_each_mutation, prefix_bit_flips,
    };
    use crate::library::tpm2::runtime::empty_state_runtime;

    fn command(code: u32) -> CommandInput {
        let mut out = vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0a];
        out.extend_from_slice(&code.to_be_bytes());
        CommandInput::new(out.len() as u32, out)
    }

    #[track_caller]
    fn dispatch_code(code: u32) -> Response {
        let mut runtime = empty_state_runtime();
        let input = command(code);
        let parsed = parse_command(&input).expect("a valid header");
        dispatch(&mut runtime, &parsed, CancellationToken::disabled())
    }

    #[track_caller]
    fn started_dispatch(bytes: &[u8]) -> u32 {
        let mut runtime = empty_state_runtime();
        runtime.startup_received = true;
        let input = CommandInput::new(bytes.len() as u32, bytes.to_vec());
        let parsed = parse_command(&input).expect("the header parses");
        dispatch(&mut runtime, &parsed, CancellationToken::disabled()).code()
    }

    fn framed(tag: u16, code: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = tag.to_be_bytes().to_vec();
        out.extend_from_slice(&(10 + payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&code.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    const HANDLE1_INSUFFICIENT: u32 = 0x19a;
    const HANDLE1_VALUE: u32 = 0x184;
    const SESSION1_HANDLE: u32 = 0x98b;
    const AUTH_MISSING: u32 = 0x125;
    const INSUFFICIENT: u32 = 0x09a;
    const SIZE: u32 = 0x095;

    #[test]
    fn unknown_code_command_code_error() {
        assert_eq!(dispatch_code(0x2000_0000).code(), TPM_RC_COMMAND_CODE);
    }

    fn runtime_with_profile(profile: &[u8]) -> Tpm2Runtime {
        use crate::library::tpm2::manufacture::manufacture_state;
        use crate::library::tpm2::profile::validate_user_profile;
        use crate::library::tpm2::runtime::commit_manufactured_state;

        let profile = validate_user_profile(Some(profile)).expect("a valid profile");
        let state = manufacture_state(profile, |bytes| {
            bytes.fill(0x5a);
            Ok(())
        })
        .expect("the TPM manufactures");
        commit_manufactured_state(state).expect("the state commits")
    }

    #[test]
    fn active_profile_rejection_precedes_lifecycle_and_parameters() {
        use crate::library::tpm2::command::core::test_support::{dispatch_bytes, response_code};

        let mut runtime = runtime_with_profile(br#"{"Name":"null"}"#);
        for started in [false, true] {
            if started {
                let startup = framed(TPM_ST_NO_SESSIONS, TPM_CC_STARTUP, &[0, 0]);
                assert_eq!(response_code(&dispatch_bytes(&mut runtime, &startup)), 0);
            }
            for code in [0x199, 0x19a, 0x19b, 0x19c] {
                for tag in [TPM_ST_NO_SESSIONS, TPM_ST_SESSIONS] {
                    let response = dispatch_bytes(&mut runtime, &framed(tag, code, &[]));
                    assert_eq!(
                        response_code(&response),
                        TPM_RC_COMMAND_CODE,
                        "command {code:#x}, tag {tag:#x}, started {started}"
                    );
                }
            }
        }
    }

    #[test]
    fn active_profile_policy_parameters_rejection_preserves_session() {
        use crate::library::tpm2::command::core::registry::{
            TPM_CC_POLICY_PARAMETERS, TPM_CC_START_AUTH_SESSION,
        };
        use crate::library::tpm2::command::core::test_support::{
            command, dispatch_bytes, response_code,
        };

        for (profile, expected) in [
            (br#"{"Name":"null"}"#.as_slice(), TPM_RC_COMMAND_CODE),
            (br#"{"Name":"default-v1"}"#.as_slice(), 0),
        ] {
            let mut runtime = runtime_with_profile(profile);
            let startup = command(TPM_CC_STARTUP, &[], &[], &[0, 0]);
            assert_eq!(response_code(&dispatch_bytes(&mut runtime, &startup)), 0);

            let mut parameters = vec![0, 16];
            parameters.extend_from_slice(&[0; 16]);
            parameters.extend_from_slice(&[0, 0, 3, 0, 16, 0, 11]);
            let start = command(
                TPM_CC_START_AUTH_SESSION,
                &[TPM_RH_NULL, TPM_RH_NULL],
                &[],
                &parameters,
            );
            assert_eq!(response_code(&dispatch_bytes(&mut runtime, &start)), 0);

            let handle = 0x0300_0000;
            let mut parameters = vec![0, 32];
            parameters.extend_from_slice(&[0; 32]);
            let request = command(TPM_CC_POLICY_PARAMETERS, &[handle], &[], &parameters);
            let response = dispatch_bytes(&mut runtime, &request);
            assert_eq!(response_code(&response), expected, "profile {profile:?}");
            let digest = &loaded_session(&runtime.live, handle).unwrap().audit_digest;
            if expected == TPM_RC_COMMAND_CODE {
                assert_eq!(
                    digest, &[0; 32],
                    "a rejected command leaves policy unchanged"
                );
            } else {
                assert_ne!(digest, &[0; 32], "the enabled command updates policy");
            }
        }
    }

    #[test]
    fn active_profile_custom_disables_get_random() {
        use crate::library::tpm2::command::core::registry::TPM_CC_GET_RANDOM;
        use crate::library::tpm2::command::core::test_support::{
            command, dispatch_bytes, response_code,
        };

        let profile = br#"{"Name":"custom","Commands":"0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,0x15b-0x15e,0x160-0x165,0x167-0x174,0x176-0x178,0x17a,0x17c-0x193,0x197,0x199-0x19c"}"#;
        let mut runtime = runtime_with_profile(profile);
        let startup = command(TPM_CC_STARTUP, &[], &[], &[0, 0]);
        assert_eq!(response_code(&dispatch_bytes(&mut runtime, &startup)), 0);
        let request = command(TPM_CC_GET_RANDOM, &[], &[], &[0, 8]);
        assert_eq!(
            response_code(&dispatch_bytes(&mut runtime, &request)),
            TPM_RC_COMMAND_CODE
        );
    }

    #[test]
    fn active_profile_survives_zeroed_nv_fallback() {
        use crate::library::tpm2::command::core::test_support::{dispatch_bytes, response_code};
        use crate::library::tpm2::runtime::manufactured_zeroed_nv_runtime;

        for (profile, expected) in [
            (br#"{"Name":"null"}"#.as_slice(), TPM_RC_COMMAND_CODE),
            (br#"{"Name":"default-v1"}"#.as_slice(), TPM_RC_INITIALIZE),
        ] {
            let manufactured = runtime_with_profile(profile);
            let mut runtime = manufactured_zeroed_nv_runtime(&manufactured);
            assert!(runtime.state.is_none());
            let request = framed(TPM_ST_NO_SESSIONS, 0x19c, &[]);
            assert_eq!(
                response_code(&dispatch_bytes(&mut runtime, &request)),
                expected,
                "profile {profile:?} remains active without decoded state"
            );
        }
    }

    #[test]
    fn profile_disabled_command_command_code_error() {
        for code in [
            0x0000_012f,
            0x0000_0141,
            0x0000_0179,
            0x0000_0194,
            0x0000_0195,
            0x0000_0196,
            0x0000_019d,
            0x0000_019e,
            0x0000_019f,
            0x2000_0000,
        ] {
            assert_eq!(
                dispatch_code(code).code(),
                TPM_RC_COMMAND_CODE,
                "code {code:#010x}"
            );
        }
    }

    #[test]
    fn startup_handler_routing() {
        use crate::library::constants::TPM_RC_FAILURE;
        let mut runtime = empty_state_runtime();
        let bytes = framed(0x8001, TPM_CC_STARTUP, &[0x00, 0x00]);
        let input = CommandInput::new(bytes.len() as u32, bytes);
        let parsed = parse_command(&input).unwrap();
        assert_eq!(
            dispatch(&mut runtime, &parsed, CancellationToken::disabled()).code(),
            TPM_RC_FAILURE
        );
    }

    #[test]
    fn started_tpm_startup_rejection_before_parse() {
        let mut runtime = empty_state_runtime();
        runtime.startup_received = true;
        let input = command(TPM_CC_STARTUP);
        let parsed = parse_command(&input).unwrap();
        assert_eq!(
            dispatch(&mut runtime, &parsed, CancellationToken::disabled()).code(),
            TPM_RC_INITIALIZE
        );
    }

    #[test]
    fn unstarted_tpm_shutdown_rejection_before_parse() {
        let mut runtime = empty_state_runtime();
        let input = command(TPM_CC_SHUTDOWN);
        let parsed = parse_command(&input).unwrap();
        assert_eq!(
            dispatch(&mut runtime, &parsed, CancellationToken::disabled()).code(),
            TPM_RC_INITIALIZE,
            "TPM2_Shutdown before TPM2_Startup: the lifecycle check precedes parameter parsing"
        );
    }

    #[test]
    fn shutdown_handler_routing() {
        use crate::library::constants::TPM_RC_FAILURE;
        let bytes = framed(0x8001, TPM_CC_SHUTDOWN, &[0x00, 0x00]);
        assert_eq!(started_dispatch(&bytes), TPM_RC_FAILURE);
    }

    #[test]
    fn profile_disabled_command_oracle_match() {
        use crate::library::tpm2::command::attestation::builder::test_support::{
            ready_runtime, run,
        };
        use crate::library::tpm2::golden_responses::disabled_commands::vector;

        let mut runtime = ready_runtime();
        for (label, code) in [
            ("FIELD_UPGRADE_START", 0x0000_012fu32),
            ("FIELD_UPGRADE_DATA", 0x0000_0141),
            ("FIRMWARE_READ", 0x0000_0179),
            ("AC_GET_CAPABILITY", 0x0000_0194),
            ("AC_SEND", 0x0000_0195),
            ("POLICY_AC_SEND_SELECT", 0x0000_0196),
            ("NV_DEFINE_SPACE2", 0x0000_019d),
            ("NV_READ_PUBLIC2", 0x0000_019e),
            ("SET_CAPABILITY", 0x0000_019f),
            ("VENDOR_TCG_TEST", 0x2000_0000),
        ] {
            assert!(
                registry::find(code).is_none(),
                "{label} stays out of the registry"
            );
            assert_eq!(
                run(&mut runtime, &framed(0x8001, code, &[])),
                vector(&format!("DC_{label}")),
                "{label}"
            );
            let mut sessions = 0x4000_0001u32.to_be_bytes().to_vec();
            sessions.extend_from_slice(&9u32.to_be_bytes());
            sessions.extend_from_slice(&[0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00]);
            assert_eq!(
                run(&mut runtime, &framed(0x8002, code, &sessions)),
                vector(&format!("DC_{label}_SESSIONS")),
                "{label} with sessions is refused at dispatch"
            );
            assert_eq!(
                run(&mut runtime, &framed(0x8001, code, &[0xff; 8])),
                vector(&format!("DC_{label}_MALFORMED")),
                "{label} with a malformed body is refused at dispatch"
            );
        }
    }

    #[test]
    fn unsupported_response_c_serialization_parity() {
        let response = dispatch_code(0x2000_0000);
        assert_eq!(
            serialize_response(&response).unwrap(),
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x43]
        );
    }

    #[test]
    fn unsupported_command_runtime_preservation() {
        let mut runtime = empty_state_runtime();
        let nv_before = runtime.nv_memory.clone();
        for code in [0x2000_0000, 0x0000_019f, 0xffff_ffff, 0x0000_0000] {
            let input = command(code);
            let parsed = parse_command(&input).unwrap();
            let response = dispatch(&mut runtime, &parsed, CancellationToken::disabled());
            assert_eq!(response.code(), TPM_RC_COMMAND_CODE, "code {code:#x}");
            assert!(!runtime.manufactured);
            assert!(!runtime.was_manufactured);
            assert!(!runtime.startup_received);
            assert!(!runtime.failure_mode);
            assert!(runtime.power_on && runtime.nv_available);
            assert_eq!(runtime.nv_memory, nv_before);
        }
    }

    #[test]
    fn session_tagged_command_path_parity() {
        let bytes = framed(0x8002, 0x0000_019f, &[0x00; 4]);
        let input = CommandInput::new(bytes.len() as u32, bytes);
        let parsed = parse_command(&input).unwrap();
        let mut runtime = empty_state_runtime();
        let response = dispatch(&mut runtime, &parsed, CancellationToken::disabled());
        assert_eq!(response.code(), TPM_RC_COMMAND_CODE);
        let bytes = serialize_response(&response).unwrap();
        assert_eq!(&bytes[..2], &TPM_ST_NO_SESSIONS.to_be_bytes());
    }

    #[test]
    fn handle_extraction_before_authorization_size() {
        for payload in [&[][..], &[0x00][..], &[0x00, 0x00, 0x00][..]] {
            assert_eq!(
                started_dispatch(&framed(0x8002, TPM_CC_PCR_EXTEND, payload)),
                HANDLE1_INSUFFICIENT,
                "the handle is unmarshaled before authorizationSize, payload {payload:02x?}"
            );
        }
    }

    #[test]
    fn invalid_first_handle_report_before_authorization_area() {
        let mut payload = 0x0000_0018u32.to_be_bytes().to_vec();
        payload.extend_from_slice(&0x20u32.to_be_bytes());
        assert_eq!(
            started_dispatch(&framed(0x8002, TPM_CC_PCR_EXTEND, &payload)),
            HANDLE1_VALUE,
            "an oversized authorizationSize never masks the handle error"
        );
    }

    #[test]
    fn handleless_command_authorization_layout_preservation() {
        let mut payload = 0x09u32.to_be_bytes().to_vec();
        payload.extend_from_slice(&[0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00]);
        payload.extend_from_slice(&[0x00; 12]);
        assert_eq!(
            started_dispatch(&framed(0x8002, 0x0000_017a, &payload)),
            SESSION1_HANDLE,
            "GetCapability's payload still starts at authorizationSize, and its \
             session has no handle to authorize"
        );
    }

    #[test]
    fn missing_authorization_size_insufficiency() {
        let payload = 0x0000_000au32.to_be_bytes().to_vec();
        assert_eq!(
            started_dispatch(&framed(0x8002, TPM_CC_PCR_EXTEND, &payload)),
            INSUFFICIENT
        );
        for extra in 1..4usize {
            let mut short = payload.clone();
            short.extend_from_slice(&vec![0u8; extra]);
            assert_eq!(
                started_dispatch(&framed(0x8002, TPM_CC_PCR_EXTEND, &short)),
                INSUFFICIENT,
                "{extra} of 4 authorizationSize bytes"
            );
        }
    }

    #[test]
    fn authorization_size_below_minimum_size_error() {
        for auth_size in 0..9u32 {
            let mut payload = 0x0000_000au32.to_be_bytes().to_vec();
            payload.extend_from_slice(&auth_size.to_be_bytes());
            payload.extend_from_slice(&[0x00; 16]);
            assert_eq!(
                started_dispatch(&framed(0x8002, TPM_CC_PCR_EXTEND, &payload)),
                SIZE,
                "authorizationSize {auth_size}"
            );
        }
    }

    #[test]
    fn authorization_size_beyond_command_size_error() {
        for auth_size in [10u32, 0x20, 0x1000, u32::MAX] {
            let mut payload = 0x0000_000au32.to_be_bytes().to_vec();
            payload.extend_from_slice(&auth_size.to_be_bytes());
            payload.extend_from_slice(&[0x00; 9]);
            assert_eq!(
                started_dispatch(&framed(0x8002, TPM_CC_PCR_EXTEND, &payload)),
                SIZE,
                "authorizationSize {auth_size}"
            );
        }
    }

    #[test]
    fn sessionless_command_auth_missing_error() {
        let mut payload = 0x0000_000au32.to_be_bytes().to_vec();
        payload.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(
            started_dispatch(&framed(0x8001, TPM_CC_PCR_EXTEND, &payload)),
            AUTH_MISSING
        );
    }

    #[test]
    fn parameter_area_mutation_panic_safety() {
        let mut valid = 0x0000_000au32.to_be_bytes().to_vec();
        valid.extend_from_slice(&0x09u32.to_be_bytes());
        valid.extend_from_slice(&[0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00]);
        valid.extend_from_slice(&0u32.to_be_bytes());
        for_each_mutation(
            "TPM2_PCR_Extend parameter area",
            prefix_bit_flips(&valid, 0, 0, false),
            |payload| {
                for tag in [0x8001u16, 0x8002] {
                    let mut runtime = empty_state_runtime();
                    runtime.startup_received = true;
                    dispatch_ignoring_result(
                        &mut runtime,
                        framed(tag, TPM_CC_PCR_EXTEND, &payload),
                    );
                }
            },
        );
    }

    mod lifecycle_gate {
        use super::*;
        use crate::library::tpm2::clock::RecordingClock;
        use crate::library::tpm2::command::core::registry::implemented;
        use crate::library::tpm2::command::core::test_support::{
            counter_entropy, dispatch_bytes, error_response, manufactured_runtime_with, pw_session,
            run_scenario,
        };
        use crate::library::tpm2::golden_responses::{
            create, create_loaded, encrypt_decrypt, flush_context, get_test_result,
            hierarchy_management, hmac, platform_state, policy_sessions, rsa_encryption,
            sequence_commands, test_parms,
        };
        use crate::library::tpm2::persistent::persistent_all_store;
        use crate::library::tpm2::restore_permanent_blob_for_test;
        use crate::library::tpm2::self_test::PrimitiveTestSet;
        use crate::library::tpm2::volatile::volatile_all_store;
        use crate::library::tpm2::{PlatformInputs, process};

        type Fixture = fn(&str) -> &'static [u8];

        const DISPATCH_LOCALITY: u8 = 3;
        const PLATFORM_LOCALITY: u8 = 2;

        fn unrequested_entropy(_buffer: &mut [u8]) -> Result<(), TpmResult> {
            panic!("a command refused before TPM2_Startup requested host entropy");
        }

        fn manufactured() -> Tpm2Runtime {
            manufactured_runtime_with(Some(br#"{"Name":"default-v1"}"#), counter_entropy::<0x6c>)
        }

        #[rustfmt::skip]
        const REFERENCE_STATES: &[(&str, Fixture, &str)] = &[
            ("encrypt-decrypt", encrypt_decrypt::vector, "PERMALL_MANUFACTURED"),
            ("hmac", hmac::vector, "PERMALL_MANUFACTURED"),
            ("platform-state", platform_state::vector, "PERMALL_MANUFACTURED"),
            ("rsa-encryption", rsa_encryption::vector, "PERMALL_BASE"),
            ("sequence-commands", sequence_commands::vector, "PERMALL_MANUFACTURED"),
            ("test-parms", test_parms::vector, "PERMALL_MANUFACTURED"),
        ];

        fn runtimes() -> Vec<(String, Tpm2Runtime)> {
            let mut runtimes = vec![("manufactured default-v1".to_owned(), manufactured())];
            for &(family, fixture, record) in REFERENCE_STATES {
                let runtime = restore_permanent_blob_for_test(fixture(record))
                    .expect("the reference permanent state restores");
                runtimes.push((format!("{family} {record}"), runtime));
            }
            runtimes.push(("stateless".to_owned(), empty_state_runtime()));
            for (_, runtime) in &mut runtimes {
                runtime.entropy = unrequested_entropy;
                runtime.nv_update_pending = false;
                runtime.locality = DISPATCH_LOCALITY;
            }
            runtimes
        }

        fn requests(code: u32) -> [Vec<u8>; 5] {
            let mut sessioned = Vec::new();
            for _ in 0..3 {
                sessioned.extend_from_slice(&TPM_RH_OWNER.to_be_bytes());
            }
            let session = pw_session(&[]);
            sessioned.extend_from_slice(&(session.len() as u32).to_be_bytes());
            sessioned.extend_from_slice(&session);
            [
                framed(TPM_ST_NO_SESSIONS, code, &[]),
                framed(TPM_ST_SESSIONS, code, &[]),
                framed(TPM_ST_NO_SESSIONS, code, &[0xff; 8]),
                framed(TPM_ST_SESSIONS, code, &[0xff; 8]),
                framed(TPM_ST_SESSIONS, code, &sessioned),
            ]
        }

        struct Snapshot {
            startup_received: bool,
            failure_mode: bool,
            nv_update_pending: bool,
            locality: u8,
            pending_self_tests: PrimitiveTestSet,
            nv_memory: Box<[u8]>,
            permanent: Option<Vec<u8>>,
            volatile: Option<Vec<u8>>,
            live: String,
        }

        fn snapshot(runtime: &Tpm2Runtime) -> Snapshot {
            let clock = RecordingClock::new(1_600_000_000_000, 5_000_000);
            Snapshot {
                startup_received: runtime.startup_received,
                failure_mode: runtime.failure_mode,
                nv_update_pending: runtime.nv_update_pending,
                locality: runtime.locality,
                pending_self_tests: runtime.self_test.pending,
                nv_memory: runtime.nv_memory.clone(),
                permanent: runtime
                    .state
                    .as_ref()
                    .map(|state| persistent_all_store(state).expect("the state serializes")),
                volatile: runtime
                    .state
                    .as_ref()
                    .map(|_| volatile_all_store(runtime, &clock).expect("the state serializes")),
                live: format!("{:?}", runtime.live),
            }
        }

        fn changed_fields(expected: &Snapshot, actual: &Snapshot) -> Vec<&'static str> {
            [
                (
                    "startup_received",
                    expected.startup_received == actual.startup_received,
                ),
                ("failure_mode", expected.failure_mode == actual.failure_mode),
                (
                    "nv_update_pending",
                    expected.nv_update_pending == actual.nv_update_pending,
                ),
                ("locality", expected.locality == actual.locality),
                (
                    "pending_self_tests",
                    expected.pending_self_tests == actual.pending_self_tests,
                ),
                ("nv_memory", expected.nv_memory == actual.nv_memory),
                ("permanent", expected.permanent == actual.permanent),
                ("volatile", expected.volatile == actual.volatile),
                ("live", expected.live == actual.live),
            ]
            .into_iter()
            .filter(|&(_, unchanged)| !unchanged)
            .map(|(field, _)| field)
            .collect()
        }

        #[track_caller]
        fn sweep(
            label: &str,
            runtime: &mut Tpm2Runtime,
            send: fn(&mut Tpm2Runtime, &[u8]) -> Vec<u8>,
            locality: u8,
        ) {
            let mut expected = snapshot(runtime);
            expected.locality = locality;
            let mut swept = 0;
            for descriptor in implemented() {
                let code = descriptor.code;
                if code == TPM_CC_STARTUP {
                    continue;
                }
                for request in requests(code) {
                    let scenario =
                        format!("{label}: {code:#06x} before TPM2_Startup, request {request:02x?}");
                    let response = run_scenario(&scenario, || send(runtime, &request));
                    assert_eq!(response, error_response(TPM_RC_INITIALIZE), "{scenario}");
                    let changed = changed_fields(&expected, &snapshot(runtime));
                    assert!(changed.is_empty(), "{scenario} changed {changed:?}");
                }
                swept += 1;
            }
            assert_eq!(
                swept,
                implemented().count() - 1,
                "{label}: every command but Startup"
            );
        }

        fn processed(runtime: &mut Tpm2Runtime, request: &[u8]) -> Vec<u8> {
            let input = CommandInput::new(request.len() as u32, request.to_vec());
            process(
                runtime,
                PlatformInputs::at_locality(PLATFORM_LOCALITY),
                &input,
                &RecordingClock::new(1_600_000_000_000, 5_000_000),
                |_| panic!("a refused command schedules no NV commit"),
                CancellationToken::disabled(),
            )
            .expect("the command processes")
        }

        #[test]
        fn dispatch_refuses_every_command_before_startup() {
            for (label, mut runtime) in runtimes() {
                sweep(&label, &mut runtime, dispatch_bytes, DISPATCH_LOCALITY);
            }
        }

        #[test]
        fn processing_refuses_every_command_before_startup() {
            for (label, mut runtime) in runtimes() {
                sweep(&label, &mut runtime, processed, PLATFORM_LOCALITY);
            }
        }

        #[test]
        fn startup_passes_the_lifecycle_gate() {
            let mut runtime = manufactured();
            let startup = framed(TPM_ST_NO_SESSIONS, TPM_CC_STARTUP, &[0x00, 0x00]);
            assert_eq!(dispatch_bytes(&mut runtime, &startup), error_response(0));
            assert!(runtime.startup_received);
        }

        #[rustfmt::skip]
        const REFERENCE_REJECTIONS: &[(&str, Fixture, &str)] = &[
            ("create", create::vector, "BEFORE_STARTUP"),
            ("create-loaded", create_loaded::vector, "BEFORE_STARTUP"),
            ("encrypt-decrypt", encrypt_decrypt::vector, "ED_BEFORE_STARTUP"),
            ("encrypt-decrypt", encrypt_decrypt::vector, "ED2_BEFORE_STARTUP"),
            ("flush-context", flush_context::vector, "BEFORE_STARTUP_RESPONSE"),
            ("get-test-result", get_test_result::vector, "GTR_BEFORE_STARTUP"),
            ("hierarchy-management", hierarchy_management::vector, "LIFECYCLE_CHANGE_PPS"),
            ("hierarchy-management", hierarchy_management::vector, "LIFECYCLE_CLEAR"),
            ("hierarchy-management", hierarchy_management::vector, "LIFECYCLE_CLEAR_CONTROL"),
            ("hierarchy-management", hierarchy_management::vector, "LIFECYCLE_DA_LOCK_RESET"),
            ("hierarchy-management", hierarchy_management::vector, "LIFECYCLE_HIERARCHY_CONTROL"),
            ("hierarchy-management", hierarchy_management::vector, "LIFECYCLE_PCR_SET_AUTH_POLICY"),
            ("hierarchy-management", hierarchy_management::vector, "LIFECYCLE_SET_PRIMARY_POLICY"),
            ("hmac", hmac::vector, "HMAC_BEFORE_STARTUP"),
            ("platform-state", platform_state::vector, "LIFECYCLE_CLOCK_RATE_ADJUST"),
            ("platform-state", platform_state::vector, "LIFECYCLE_CLOCK_SET"),
            ("platform-state", platform_state::vector, "LIFECYCLE_PCR_SET_AUTH_VALUE"),
            ("platform-state", platform_state::vector, "LIFECYCLE_PP_COMMANDS"),
            ("platform-state", platform_state::vector, "LIFECYCLE_READ_CLOCK"),
            ("platform-state", platform_state::vector, "LIFECYCLE_SET_ALGORITHM_SET"),
            ("policy-sessions", policy_sessions::vector, "PGD_BEFORE_STARTUP"),
            ("policy-sessions", policy_sessions::vector, "SAS_BEFORE_STARTUP"),
            ("rsa-encryption", rsa_encryption::vector, "DEC_BEFORE_STARTUP"),
            ("rsa-encryption", rsa_encryption::vector, "ENC_BEFORE_STARTUP"),
            ("sequence-commands", sequence_commands::vector, "ESC_BEFORE_STARTUP"),
            ("sequence-commands", sequence_commands::vector, "HMS_BEFORE_STARTUP"),
            ("sequence-commands", sequence_commands::vector, "HSS_BEFORE_STARTUP"),
            ("sequence-commands", sequence_commands::vector, "SC_BEFORE_STARTUP"),
            ("sequence-commands", sequence_commands::vector, "SU_BEFORE_STARTUP"),
            ("test-parms", test_parms::vector, "TP_BEFORE_STARTUP"),
        ];

        #[test]
        fn reference_rejections_match_the_gate_response() {
            for &(family, fixture, record) in REFERENCE_REJECTIONS {
                assert_eq!(
                    fixture(record),
                    error_response(TPM_RC_INITIALIZE),
                    "{family} {record}"
                );
            }
        }
    }

    mod exclusive_audit_lifecycle {
        use super::*;
        use crate::library::tpm2::clock::RecordingClock;
        use crate::library::tpm2::command::core::test_support::{
            counter_entropy, dispatch_bytes, manufactured_runtime_with,
        };
        use crate::library::tpm2::hierarchy::{TPM_RH_OWNER, TPM_RH_UNASSIGNED, TPM_RS_PW};
        use crate::library::tpm2::live::RestoredVolatile;

        use crate::library::tpm2::volatile::volatile_all_store;
        use crate::library::tpm2::{decode_volatile_blob, volatile_validation_context};

        const RESTORED_AUDIT_SESSION: u32 = 0x0200_0000;
        const TPM_CC_GET_CAPABILITY: u32 = 0x0000_017a;
        const TPM_CC_HIERARCHY_CHANGE_AUTH: u32 = 0x0000_0129;

        fn manufactured_runtime() -> Tpm2Runtime {
            manufactured_runtime_with(None, counter_entropy::<0x66>)
        }

        fn started_runtime_with_restored_audit() -> Tpm2Runtime {
            let mut runtime = manufactured_runtime();
            let bytes = [
                0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
            ];
            assert_eq!(dispatch_bytes(&mut runtime, &bytes)[6..], [0, 0, 0, 0]);
            runtime.nv_update_pending = false;
            set_restored_audit(&mut runtime);
            runtime
        }

        fn set_restored_audit(runtime: &mut Tpm2Runtime) {
            runtime
                .restored_volatile
                .get_or_insert_with(RestoredVolatile::power_on)
                .exclusive_audit_session = RESTORED_AUDIT_SESSION;
        }

        fn exclusive_audit(runtime: &Tpm2Runtime) -> u32 {
            runtime
                .restored_volatile
                .as_ref()
                .expect("the runtime carries restored state")
                .exclusive_audit_session
        }

        fn cap_command() -> Vec<u8> {
            let mut out = vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x16];
            out.extend_from_slice(&TPM_CC_GET_CAPABILITY.to_be_bytes());
            out.extend_from_slice(&6u32.to_be_bytes());
            out.extend_from_slice(&0x0000_020eu32.to_be_bytes());
            out.extend_from_slice(&1u32.to_be_bytes());
            out
        }

        #[test]
        fn sessionless_success_restored_session_clearing() {
            let mut runtime = started_runtime_with_restored_audit();
            let response = dispatch_bytes(&mut runtime, &cap_command());
            assert_eq!(response[6..10], [0, 0, 0, 0], "GetCapability succeeds");
            assert_eq!(
                exclusive_audit(&runtime),
                TPM_RH_UNASSIGNED,
                "a session-capable command without an audit session clears the exclusive state"
            );

            let clock = RecordingClock::new(1_600_000_000_000, 5_000_000);
            let blob = volatile_all_store(&runtime, &clock).expect("the volatile state saves");
            let context = volatile_validation_context(&runtime).expect("the context builds");
            let decoded =
                decode_volatile_blob(&context, &blob, &clock).expect("the volatile state decodes");
            assert_eq!(
                decoded.exclusive_audit_session, TPM_RH_UNASSIGNED,
                "the serialized volatile blob carries the cleared value"
            );
        }

        #[test]
        fn session_forbidding_command_preservation() {
            let mut runtime = manufactured_runtime();
            set_restored_audit(&mut runtime);
            let bytes = [
                0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
            ];
            assert_eq!(
                dispatch_bytes(&mut runtime, &bytes)[6..],
                [0, 0, 0, 0],
                "Startup succeeds"
            );
            assert_eq!(
                exclusive_audit(&runtime),
                RESTORED_AUDIT_SESSION,
                "IsSessionAllowed() gates the clear, so Startup leaves the field alone"
            );
        }

        #[test]
        fn failed_command_preservation() {
            let mut runtime = started_runtime_with_restored_audit();
            let mut truncated = vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0e];
            truncated.extend_from_slice(&TPM_CC_GET_CAPABILITY.to_be_bytes());
            truncated.extend_from_slice(&[0x00; 4]);
            let response = dispatch_bytes(&mut runtime, &truncated);
            assert_eq!(response[6..10], [0, 0, 0x02, 0xda], "the command fails");
            assert_eq!(
                exclusive_audit(&runtime),
                RESTORED_AUDIT_SESSION,
                "upstream skips BuildResponseSession() on failure"
            );
        }

        #[test]
        fn password_session_success_clearing_and_acknowledgement() {
            let mut runtime = started_runtime_with_restored_audit();
            let mut bytes = vec![0x80, 0x02, 0x00, 0x00, 0x00, 0x00];
            bytes.extend_from_slice(&TPM_CC_HIERARCHY_CHANGE_AUTH.to_be_bytes());
            bytes.extend_from_slice(&TPM_RH_OWNER.to_be_bytes());
            bytes.extend_from_slice(&9u32.to_be_bytes());
            bytes.extend_from_slice(&TPM_RS_PW.to_be_bytes());
            bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00]);
            bytes.extend_from_slice(&[0x00, 0x00]);
            let size = (bytes.len() as u32).to_be_bytes();
            bytes[2..6].copy_from_slice(&size);
            let response = dispatch_bytes(&mut runtime, &bytes);
            assert_eq!(
                response,
                [
                    0x80, 0x02, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x01, 0x00, 0x00
                ],
                "the password acknowledgement still carries continueSession"
            );
            assert_eq!(exclusive_audit(&runtime), TPM_RH_UNASSIGNED);
            assert_eq!(
                runtime
                    .restored_volatile
                    .as_ref()
                    .expect("restored state")
                    .session_process
                    .attributes[0],
                0x01,
                "the recorded password session attributes carry continueSession"
            );
        }
    }
}
