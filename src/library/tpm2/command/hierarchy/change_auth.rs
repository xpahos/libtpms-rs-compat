// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/Hierarchy.c
// - libtpms/src/tpm2/HierarchyCommands.c
//
// Original upstream authors and copyright notices:
// Written by Ken Goldman
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corp. and others, 2016 - 2023
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use crate::library::constants::{
    TPM_RC_FAILURE, TPM_RC_INSUFFICIENT, TPM_RC_NV_UNAVAILABLE, TPM_RC_SIZE,
};
use crate::library::tpm2::command::core::dispatcher::CommandFrame;
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::command::session::processing::strip_trailing_zeros;
use crate::library::tpm2::hierarchy::{
    TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT, TPM_RH_OWNER, TPM_RH_PLATFORM,
};
use crate::library::tpm2::marshal::{BlobReader, Tpm2bError};
use crate::library::tpm2::nv::build_nv_image;
use crate::library::tpm2::orderly::{commit_clear_orderly, prepare_clear_orderly};
use crate::library::tpm2::persistent::{OwnedPersistentState, OwnedSecret};
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::types::TpmResult;

const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;
const TPM_RC_2: TpmResult = 0x200;
const RC_UNMARSHAL_NEW_AUTH: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_HIERARCHY_CHANGE_AUTH_NEW_AUTH: TpmResult = TPM_RC_P + TPM_RC_2;

const MAX_AUTH_SIZE: usize = 64;
const CONTEXT_INTEGRITY_HASH_SIZE: usize = 64;

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let auth_handle = frame.handles.first().copied().ok_or(TPM_RC_FAILURE)?;
    let new_auth = parse_new_auth(frame.parameters)?;

    if !runtime.nv_available {
        return Err(TPM_RC_NV_UNAVAILABLE);
    }
    if new_auth.len() > CONTEXT_INTEGRITY_HASH_SIZE {
        return Err(TPM_RC_SIZE + RC_HIERARCHY_CHANGE_AUTH_NEW_AUTH);
    }

    match auth_handle {
        TPM_RH_OWNER | TPM_RH_ENDORSEMENT | TPM_RH_LOCKOUT => {
            set_persistent_auth(runtime, auth_handle, new_auth)
        }
        TPM_RH_PLATFORM => set_platform_auth(runtime, new_auth),
        _ => Err(TPM_RC_FAILURE),
    }?;
    Ok(CommandOutput::empty())
}

fn parse_new_auth(parameters: &[u8]) -> Result<&[u8], TpmResult> {
    let mut reader = BlobReader::new(parameters);
    let new_auth = match reader.read_tpm2b(MAX_AUTH_SIZE) {
        Ok(bytes) => bytes,
        Err(Tpm2bError::Truncated) => return Err(TPM_RC_INSUFFICIENT + RC_UNMARSHAL_NEW_AUTH),
        Err(Tpm2bError::SizeExceeded { .. }) => return Err(TPM_RC_SIZE + RC_UNMARSHAL_NEW_AUTH),
    };
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(strip_trailing_zeros(new_auth))
}

fn persistent_auth_slot(
    state: &mut OwnedPersistentState,
    auth_handle: u32,
) -> Option<&mut OwnedSecret> {
    match auth_handle {
        TPM_RH_OWNER => Some(&mut state.persistent.owner_auth),
        TPM_RH_ENDORSEMENT => Some(&mut state.persistent.endorsement_auth),
        TPM_RH_LOCKOUT => Some(&mut state.persistent.lockout_auth),
        _ => None,
    }
}

fn set_persistent_auth(
    runtime: &mut Tpm2Runtime,
    auth_handle: u32,
    new_auth: &[u8],
) -> Result<(), TpmResult> {
    let state = runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?;
    let backup = {
        let slot = persistent_auth_slot(state, auth_handle).ok_or(TPM_RC_FAILURE)?;
        core::mem::replace(slot, OwnedSecret::copy_of(new_auth))
    };
    let image = match build_nv_image(state) {
        Ok(image) => image,
        Err(_) => {
            if let Some(slot) = persistent_auth_slot(state, auth_handle) {
                *slot = backup;
            }
            return Err(TPM_RC_FAILURE);
        }
    };
    runtime.nv_memory = image;
    runtime.nv_update_pending = true;
    Ok(())
}

fn set_platform_auth(runtime: &mut Tpm2Runtime, new_auth: &[u8]) -> Result<(), TpmResult> {
    let orderly_state = prepare_clear_orderly(runtime)?;

    let clear = runtime.live.state_clear.as_mut().ok_or(TPM_RC_FAILURE)?;
    let backup = core::mem::replace(&mut clear.platform_auth, OwnedSecret::copy_of(new_auth));

    if let Err(code) = commit_clear_orderly(runtime, orderly_state) {
        if let Some(clear) = runtime.live.state_clear.as_mut() {
            clear.platform_auth = backup;
        }
        return Err(code);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::CommandInput;
    use crate::library::cancel::CancellationToken;
    use crate::library::constants::{TPM_RC_AUTH_MISSING, TPM_RC_INITIALIZE};
    use crate::library::tpm2::command::core::dispatcher::dispatch;
    use crate::library::tpm2::command::core::header::{parse_command, serialize_response};
    use crate::library::tpm2::command::core::registry::{
        TPM_CC_HIERARCHY_CHANGE_AUTH, TPM_RH_NULL,
    };
    use crate::library::tpm2::command::core::test_support::{
        auth_session, dispatch_bytes, dispatch_ignoring_result, error_response, for_each_mutation,
        hex, make_orderly, manufactured_runtime, prefix_bit_flips, process, pw_session,
        session_success_response, started_runtime, tpm2b,
    };
    use crate::library::tpm2::command::session::processing::{
        HMAC_SESSION_FIRST, POLICY_SESSION_FIRST, TPM_RS_PW,
    };

    use crate::library::tpm2::orderly::{SU_DA_USED_VALUE, SU_NONE_VALUE};

    use crate::library::tpm2::volatile::IMPLEMENTATION_PCR;

    const RC_SUCCESS: u32 = 0x000;
    const RC_SIZE: u32 = 0x095;
    const RC_NV_UNAVAILABLE: u32 = 0x923;

    const RC_HANDLE1_INSUFFICIENT: u32 = 0x19a;
    const RC_HANDLE1_VALUE: u32 = 0x184;

    const RC_PARAM1_INSUFFICIENT: u32 = 0x1da;
    const RC_PARAM1_SIZE: u32 = 0x1d5;
    const RC_PARAM2_SIZE: u32 = 0x2d5;

    const RC_LOCKOUT: u32 = 0x921;
    const RC_SESSION1_AUTH_FAIL: u32 = 0x98e;
    const RC_SESSION1_BAD_AUTH: u32 = 0x9a2;
    const RC_SESSION2_BAD_AUTH: u32 = 0xaa2;
    const RC_SESSION2_HANDLE: u32 = 0xa8b;
    const RC_REFERENCE_S0: u32 = 0x918;

    const HIERARCHY_HANDLES: [u32; 4] = [
        TPM_RH_OWNER,
        TPM_RH_ENDORSEMENT,
        TPM_RH_PLATFORM,
        TPM_RH_LOCKOUT,
    ];

    const DA_EXEMPT_HIERARCHIES: [u32; 3] = [TPM_RH_OWNER, TPM_RH_ENDORSEMENT, TPM_RH_PLATFORM];

    const BIOS_AUTH: [u8; 20] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13,
    ];

    fn command(handle: u32, auth: Option<&[u8]>, parameters: &[u8]) -> Vec<u8> {
        let mut payload = handle.to_be_bytes().to_vec();
        if let Some(auth) = auth {
            payload.extend_from_slice(&(auth.len() as u32).to_be_bytes());
            payload.extend_from_slice(auth);
        }
        payload.extend_from_slice(parameters);

        let tag: u16 = if auth.is_some() { 0x8002 } else { 0x8001 };
        let mut out = tag.to_be_bytes().to_vec();
        out.extend_from_slice(&(10 + payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&TPM_CC_HIERARCHY_CHANGE_AUTH.to_be_bytes());
        out.extend_from_slice(&payload);
        out
    }

    fn change_auth(handle: u32, password: &[u8], new_auth: &[u8]) -> Vec<u8> {
        command(handle, Some(&pw_session(password)), &tpm2b(new_auth))
    }

    fn stored_auth(runtime: &Tpm2Runtime, handle: u32) -> Option<Vec<u8>> {
        let secret = match handle {
            TPM_RH_OWNER => Some(&runtime.state().persistent.owner_auth),
            TPM_RH_ENDORSEMENT => Some(&runtime.state().persistent.endorsement_auth),
            TPM_RH_LOCKOUT => Some(&runtime.state().persistent.lockout_auth),
            TPM_RH_PLATFORM => runtime
                .live
                .state_clear
                .as_ref()
                .map(|clear| &clear.platform_auth),
            other => panic!("handle {other:#x} is not a hierarchy"),
        };
        secret.map(|secret| secret.expose().to_vec())
    }

    #[track_caller]
    fn assert_stored_auth(runtime: &Tpm2Runtime, handle: u32, expected: &[u8]) {
        assert_eq!(
            stored_auth(runtime, handle).as_deref(),
            Some(expected),
            "handle {handle:#x}"
        );
    }

    struct Snapshot {
        failure_mode: bool,
        nv_update_pending: bool,
        orderly_state: u16,
        nv_memory: Box<[u8]>,
        auths: [Option<Vec<u8>>; 4],
        lockout_auth_enabled: bool,
        da_pending_on_nv: bool,
        locality: u8,
        pcr_banks: Vec<Vec<Option<Vec<u8>>>>,
        pcr_counter: Option<u32>,
        free_session_slots: u32,
        sessions_occupied: Vec<bool>,
    }

    fn snapshot(runtime: &Tpm2Runtime) -> Snapshot {
        Snapshot {
            failure_mode: runtime.failure_mode,
            nv_update_pending: runtime.nv_update_pending,
            orderly_state: runtime.state().persistent.orderly_state,
            nv_memory: runtime.nv_memory.clone(),
            auths: HIERARCHY_HANDLES.map(|handle| stored_auth(runtime, handle)),
            lockout_auth_enabled: runtime.state().persistent.lockout_auth_enabled,
            da_pending_on_nv: runtime.live.da_pending_on_nv,
            locality: runtime.locality,
            pcr_banks: runtime
                .live
                .pcrs
                .iter()
                .map(|pcr| pcr.banks.to_vec())
                .collect(),
            pcr_counter: runtime
                .live
                .state_reset
                .as_ref()
                .map(|reset| reset.pcr_counter),
            free_session_slots: runtime.live.free_session_slots,
            sessions_occupied: runtime
                .live
                .sessions
                .iter()
                .map(|slot| slot.occupied)
                .collect(),
        }
    }

    #[track_caller]
    fn assert_unchanged(runtime: &Tpm2Runtime, before: &Snapshot) {
        assert_eq!(runtime.failure_mode, before.failure_mode, "failure_mode");
        assert_eq!(
            runtime.nv_update_pending, before.nv_update_pending,
            "nv_update_pending"
        );
        assert_eq!(
            runtime.state().persistent.orderly_state,
            before.orderly_state,
            "orderly_state"
        );
        assert_eq!(runtime.nv_memory, before.nv_memory, "nv_memory");
        assert_eq!(
            HIERARCHY_HANDLES.map(|handle| stored_auth(runtime, handle)),
            before.auths,
            "an authorization value changed"
        );
        assert_eq!(
            runtime.state().persistent.lockout_auth_enabled,
            before.lockout_auth_enabled,
            "lockout_auth_enabled"
        );
        assert_eq!(
            runtime.live.da_pending_on_nv, before.da_pending_on_nv,
            "da_pending_on_nv"
        );
        assert_eq!(runtime.locality, before.locality, "locality");
        let pcr_banks: Vec<Vec<Option<Vec<u8>>>> = runtime
            .live
            .pcrs
            .iter()
            .map(|pcr| pcr.banks.to_vec())
            .collect();
        assert_eq!(pcr_banks, before.pcr_banks, "pcr_banks");
        assert_eq!(
            runtime
                .live
                .state_reset
                .as_ref()
                .map(|reset| reset.pcr_counter),
            before.pcr_counter,
            "pcr_counter"
        );
        assert_eq!(
            runtime.live.free_session_slots, before.free_session_slots,
            "free_session_slots"
        );
        assert_eq!(
            runtime
                .live
                .sessions
                .iter()
                .map(|slot| slot.occupied)
                .collect::<Vec<bool>>(),
            before.sessions_occupied,
            "sessions_occupied"
        );
    }

    #[test]
    fn pre_startup_initialize_rejection() {
        let mut runtime = manufactured_runtime();
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &change_auth(TPM_RH_PLATFORM, &[], &BIOS_AUTH)),
            error_response(TPM_RC_INITIALIZE),
            "TPM2_HierarchyChangeAuth before TPM2_Startup"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn hierarchy_handle_acceptance() {
        for handle in HIERARCHY_HANDLES {
            let mut runtime = started_runtime();
            assert_eq!(
                dispatch_bytes(&mut runtime, &change_auth(handle, &[], &BIOS_AUTH)),
                session_success_response(),
                "handle {handle:#x}"
            );
            assert_stored_auth(&runtime, handle, &BIOS_AUTH);
        }
    }

    #[test]
    fn per_hierarchy_auth_value_isolation() {
        for handle in HIERARCHY_HANDLES {
            let mut runtime = started_runtime();
            assert_eq!(
                dispatch_bytes(&mut runtime, &change_auth(handle, &[], &BIOS_AUTH)),
                session_success_response(),
                "handle {handle:#x}"
            );
            for other in HIERARCHY_HANDLES {
                let expected: &[u8] = if other == handle { &BIOS_AUTH } else { &[] };
                assert_eq!(
                    stored_auth(&runtime, other).as_deref(),
                    Some(expected),
                    "handle {handle:#x} changed {other:#x}"
                );
            }
        }
    }

    #[test]
    fn non_hierarchy_handle_rejection() {
        let mut handles = vec![
            TPM_RH_NULL,
            TPM_RS_PW,
            HMAC_SESSION_FIRST,
            POLICY_SESSION_FIRST,
            0x0100_0000,
            0x4000_0000,
            0x4000_0002,
            0x4000_0008,
            0x4000_0009,
            0x4000_000d,
            0x4000_0110,
            0x8000_0000,
            0x8100_0000,
            u32::MAX,
        ];
        handles.extend(0..IMPLEMENTATION_PCR as u32);
        for handle in handles {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(&mut runtime, &change_auth(handle, &[], &BIOS_AUTH)),
                error_response(RC_HANDLE1_VALUE),
                "handle {handle:#x}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn truncated_handle_decoration() {
        for len in 0..4usize {
            let mut runtime = started_runtime();
            let mut bytes = hex("8002 00000000 00000129");
            bytes.extend_from_slice(&[0x40, 0x00, 0x00, 0x0c][..len]);
            let size = bytes.len() as u32;
            bytes[2..6].copy_from_slice(&size.to_be_bytes());
            assert_eq!(
                dispatch_bytes(&mut runtime, &bytes),
                error_response(RC_HANDLE1_INSUFFICIENT),
                "{len} of 4 handle bytes"
            );
        }
    }

    #[test]
    fn missing_auth_area_auth_missing() {
        for handle in HIERARCHY_HANDLES {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(&mut runtime, &command(handle, None, &tpm2b(&BIOS_AUTH))),
                error_response(TPM_RC_AUTH_MISSING),
                "handle {handle:#x}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn da_exempt_bad_auth_no_side_effects() {
        for handle in DA_EXEMPT_HIERARCHIES {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(&mut runtime, &change_auth(handle, b"wrong", &BIOS_AUTH)),
                error_response(RC_SESSION1_BAD_AUTH),
                "handle {handle:#x}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn wrong_lockout_password_da_failure() {
        let mut runtime = started_runtime();
        assert!(runtime.state().persistent.lockout_auth_enabled);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &change_auth(TPM_RH_LOCKOUT, b"wrong", &BIOS_AUTH)
            ),
            error_response(RC_SESSION1_AUTH_FAIL),
            "TPM_RH_LOCKOUT is the one hierarchy that is not DA exempt"
        );
        assert_stored_auth(&runtime, TPM_RH_LOCKOUT, &[]);
    }

    #[test]
    fn lockout_failure_auth_disable() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &change_auth(TPM_RH_LOCKOUT, b"wrong", &BIOS_AUTH)
            ),
            error_response(RC_SESSION1_AUTH_FAIL)
        );
        assert!(!runtime.state().persistent.lockout_auth_enabled);
    }

    #[test]
    fn locked_out_lockout_auth_rejection() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(&mut runtime, &change_auth(TPM_RH_LOCKOUT, &[], &BIOS_AUTH)),
            session_success_response(),
            "lockoutAuth starts empty and is set to a known value"
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &change_auth(TPM_RH_LOCKOUT, &[], &BIOS_AUTH)),
            error_response(RC_SESSION1_AUTH_FAIL)
        );
        for (label, bytes) in [
            (
                "the correct password",
                change_auth(TPM_RH_LOCKOUT, &BIOS_AUTH, b"next"),
            ),
            (
                "an empty password",
                change_auth(TPM_RH_LOCKOUT, &[], b"next"),
            ),
            (
                "a malformed parameter area",
                command(TPM_RH_LOCKOUT, Some(&pw_session(&BIOS_AUTH)), &[]),
            ),
        ] {
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(&mut runtime, &bytes),
                error_response(RC_LOCKOUT),
                "{label} is refused before the password comparison"
            );
            assert_unchanged(&runtime, &before);
        }
        assert_stored_auth(&runtime, TPM_RH_LOCKOUT, &BIOS_AUTH);
    }

    #[test]
    fn lockout_failure_hierarchy_isolation() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &change_auth(TPM_RH_LOCKOUT, b"wrong", &BIOS_AUTH)
            ),
            error_response(RC_SESSION1_AUTH_FAIL)
        );
        for handle in DA_EXEMPT_HIERARCHIES {
            assert_eq!(
                dispatch_bytes(&mut runtime, &change_auth(handle, &[], &BIOS_AUTH)),
                session_success_response(),
                "handle {handle:#x} is DA exempt"
            );
        }
    }

    #[test]
    fn lockout_failure_nonzero_recovery_nv_write() {
        let mut runtime = started_runtime();
        assert_ne!(runtime.state().persistent.lockout_recovery, 0);
        let nv_before = runtime.nv_memory.clone();

        let bytes = change_auth(TPM_RH_LOCKOUT, b"wrong", &BIOS_AUTH);
        let input = CommandInput::new(bytes.len() as u32, bytes);
        let mut commits = 0usize;
        let response = process(&mut runtime, 0, &input, |_| {
            commits += 1;
            Ok(())
        })
        .expect("the command processes");

        assert_eq!(response, error_response(RC_SESSION1_AUTH_FAIL));
        assert_eq!(
            commits, 1,
            "a failed command still commits pending NV state"
        );
        assert_ne!(runtime.nv_memory, nv_before);
        assert_eq!(
            runtime.nv_memory,
            build_nv_image(runtime.state()).expect("the state serializes")
        );
        assert!(!runtime.nv_update_pending, "the pending flag is consumed");
        assert!(!runtime.live.da_pending_on_nv);

        runtime
            .state
            .as_mut()
            .unwrap()
            .persistent
            .lockout_auth_enabled = true;
        assert_ne!(
            runtime.nv_memory,
            build_nv_image(runtime.state()).expect("the state serializes"),
            "the committed image carries the disabled lockout authorization"
        );
    }

    #[test]
    fn lockout_failure_zero_recovery_nv_skip() {
        let mut runtime = started_runtime();
        runtime.state.as_mut().unwrap().persistent.lockout_recovery = 0;
        runtime.nv_memory = build_nv_image(runtime.state()).expect("the state serializes");
        runtime.nv_update_pending = false;
        let nv_before = runtime.nv_memory.clone();

        let bytes = change_auth(TPM_RH_LOCKOUT, b"wrong", &BIOS_AUTH);
        let input = CommandInput::new(bytes.len() as u32, bytes);
        let response = process(&mut runtime, 0, &input, |_| {
            panic!("a zero lockoutRecovery is re-enabled at startup, so NV is not written")
        })
        .expect("the command processes");

        assert_eq!(response, error_response(RC_SESSION1_AUTH_FAIL));
        assert!(!runtime.state().persistent.lockout_auth_enabled);
        assert_eq!(runtime.nv_memory, nv_before);
        assert!(!runtime.nv_update_pending);
        assert!(!runtime.live.da_pending_on_nv);
    }

    #[test]
    fn lockout_failure_no_nv_deferred_da_write() {
        let mut runtime = started_runtime();
        make_orderly(&mut runtime, SU_NONE_VALUE);
        runtime.nv_available = false;
        let nv_before = runtime.nv_memory.clone();

        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &change_auth(TPM_RH_LOCKOUT, b"wrong", &BIOS_AUTH)
            ),
            error_response(RC_SESSION1_AUTH_FAIL)
        );
        assert!(!runtime.state().persistent.lockout_auth_enabled);
        assert!(runtime.live.da_pending_on_nv);
        assert_eq!(runtime.nv_memory, nv_before);
        assert!(!runtime.nv_update_pending);

        assert_eq!(
            dispatch_bytes(&mut runtime, &change_auth(TPM_RH_LOCKOUT, &[], &BIOS_AUTH)),
            error_response(RC_NV_UNAVAILABLE),
            "the pending DA write has to reach NV before any lockout check"
        );
        assert!(runtime.live.da_pending_on_nv);

        runtime.nv_available = true;
        assert_eq!(
            dispatch_bytes(&mut runtime, &change_auth(TPM_RH_LOCKOUT, &[], &BIOS_AUTH)),
            error_response(RC_LOCKOUT)
        );
        assert!(
            !runtime.live.da_pending_on_nv,
            "the pending write is flushed"
        );
        assert!(runtime.nv_update_pending);
        assert_eq!(
            runtime.nv_memory,
            build_nv_image(runtime.state()).expect("the state serializes")
        );
    }

    #[test]
    fn orderly_no_nv_lockout_check_rejection() {
        let mut runtime = started_runtime();
        make_orderly(&mut runtime, 0x0001);
        runtime.nv_available = false;
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &change_auth(TPM_RH_LOCKOUT, &[], &BIOS_AUTH)),
            error_response(RC_NV_UNAVAILABLE),
            "a DA failure could not be recorded, so no authorization is checked"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn lockout_nv_image_failure_no_partial_mutation() {
        let mut runtime = started_runtime();
        runtime.state.as_mut().unwrap().persistent.owner_policy = vec![0x5a; 4096];
        assert!(
            build_nv_image(runtime.state()).is_err(),
            "the oversized policy must not serialize"
        );
        let enabled_before = runtime.state().persistent.lockout_auth_enabled;
        let nv_before = runtime.nv_memory.clone();

        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &change_auth(TPM_RH_LOCKOUT, b"wrong", &BIOS_AUTH)
            ),
            error_response(TPM_RC_FAILURE),
            "an undecorated internal failure, never a session-decorated code"
        );
        assert_eq!(
            runtime.state().persistent.lockout_auth_enabled,
            enabled_before,
            "the rolled back DA state leaves lockout authorization usable"
        );
        assert_eq!(runtime.nv_memory, nv_before);
        assert!(!runtime.nv_update_pending);
        assert!(!runtime.live.da_pending_on_nv);
    }

    #[test]
    fn lockout_nv_commit_failure_mode() {
        let mut runtime = started_runtime();
        let bytes = change_auth(TPM_RH_LOCKOUT, b"wrong", &BIOS_AUTH);
        let input = CommandInput::new(bytes.len() as u32, bytes);
        let response = process(&mut runtime, 0, &input, |_| Err(TPM_RC_FAILURE))
            .expect("the command processes");
        assert_eq!(response, error_response(TPM_RC_FAILURE));
        assert!(runtime.failure_mode);
    }

    #[test]
    fn extra_password_session_no_handle() {
        let mut runtime = started_runtime();
        for second in [&[][..], b"wrong"] {
            let mut auth = pw_session(&[]);
            auth.extend_from_slice(&pw_session(second));
            let before = snapshot(&runtime);
            let response = dispatch_bytes(
                &mut runtime,
                &command(TPM_RH_PLATFORM, Some(&auth), &tpm2b(&BIOS_AUTH)),
            );
            assert_eq!(response, error_response(RC_SESSION2_HANDLE));
            assert_ne!(
                response,
                error_response(RC_SESSION2_BAD_AUTH),
                "the missing handle outranks the password comparison"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn authorization_old_auth_value_comparison() {
        for handle in HIERARCHY_HANDLES {
            let mut runtime = started_runtime();
            assert_eq!(
                dispatch_bytes(&mut runtime, &change_auth(handle, &[], &BIOS_AUTH)),
                session_success_response(),
                "handle {handle:#x}"
            );
            assert_eq!(
                dispatch_bytes(&mut runtime, &change_auth(handle, &BIOS_AUTH, b"second")),
                session_success_response(),
                "the command authorizes with the value it is about to replace"
            );
            assert_stored_auth(&runtime, handle, b"second");
        }
    }

    #[test]
    fn new_password_requirement() {
        for handle in DA_EXEMPT_HIERARCHIES {
            let mut runtime = started_runtime();
            assert_eq!(
                dispatch_bytes(&mut runtime, &change_auth(handle, &[], &BIOS_AUTH)),
                session_success_response(),
                "handle {handle:#x}"
            );
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(&mut runtime, &change_auth(handle, &[], &BIOS_AUTH)),
                error_response(RC_SESSION1_BAD_AUTH),
                "the old empty password no longer authorizes {handle:#x}"
            );
            assert_unchanged(&runtime, &before);
            assert_eq!(
                dispatch_bytes(&mut runtime, &change_auth(handle, &BIOS_AUTH, b"next")),
                session_success_response(),
                "the new password authorizes {handle:#x}"
            );
        }
    }

    #[test]
    fn empty_new_auth_clear() {
        for handle in HIERARCHY_HANDLES {
            let mut runtime = started_runtime();
            assert_eq!(
                dispatch_bytes(&mut runtime, &change_auth(handle, &[], &BIOS_AUTH)),
                session_success_response()
            );
            assert_eq!(
                dispatch_bytes(&mut runtime, &change_auth(handle, &BIOS_AUTH, &[])),
                session_success_response(),
                "handle {handle:#x}"
            );
            assert_stored_auth(&runtime, handle, &[]);
            assert_eq!(
                dispatch_bytes(&mut runtime, &change_auth(handle, &[], &BIOS_AUTH)),
                session_success_response(),
                "the empty password authorizes again"
            );
        }
    }

    #[test]
    fn trailing_zero_trim() {
        for handle in HIERARCHY_HANDLES {
            let mut runtime = started_runtime();
            assert_eq!(
                dispatch_bytes(
                    &mut runtime,
                    &change_auth(handle, &[], &[0x41, 0x42, 0x00, 0x00])
                ),
                session_success_response(),
                "handle {handle:#x}"
            );
            assert_stored_auth(&runtime, handle, &[0x41, 0x42]);
            assert_eq!(
                dispatch_bytes(&mut runtime, &change_auth(handle, &[0x41, 0x42], &[])),
                session_success_response(),
                "the stripped value is what authorizes"
            );
        }
    }

    #[test]
    fn all_zero_auth_empty_normalization() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &change_auth(TPM_RH_PLATFORM, &[], &[0x00; 32])
            ),
            session_success_response()
        );
        assert_stored_auth(&runtime, TPM_RH_PLATFORM, &[]);
        assert_eq!(
            dispatch_bytes(&mut runtime, &change_auth(TPM_RH_PLATFORM, &[], &[])),
            session_success_response(),
            "an empty password still authorizes"
        );
    }

    #[test]
    fn max_size_auth_acceptance() {
        for handle in HIERARCHY_HANDLES {
            let mut runtime = started_runtime();
            let maximum = [0xa5u8; MAX_AUTH_SIZE];
            assert_eq!(
                dispatch_bytes(&mut runtime, &change_auth(handle, &[], &maximum)),
                session_success_response(),
                "handle {handle:#x}"
            );
            assert_stored_auth(&runtime, handle, &maximum);
            assert_eq!(
                dispatch_bytes(&mut runtime, &change_auth(handle, &maximum, &[])),
                session_success_response()
            );
        }
    }

    #[test]
    fn oversized_auth_p1_size_error() {
        for size in [MAX_AUTH_SIZE + 1, MAX_AUTH_SIZE + 2, 128, 0xffff] {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            let mut parameters = (size as u16).to_be_bytes().to_vec();
            parameters.extend_from_slice(&vec![0xaa; size.min(128)]);
            assert_eq!(
                dispatch_bytes(
                    &mut runtime,
                    &command(TPM_RH_PLATFORM, Some(&pw_session(&[])), &parameters)
                ),
                error_response(RC_PARAM1_SIZE),
                "declared size {size}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn truncated_size_field_p1_insufficient() {
        for parameters in [&[][..], &[0x00][..], &[0x14][..]] {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(
                    &mut runtime,
                    &command(TPM_RH_PLATFORM, Some(&pw_session(&[])), parameters)
                ),
                error_response(RC_PARAM1_INSUFFICIENT),
                "{} of 2 size bytes",
                parameters.len()
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn short_payload_insufficient() {
        for present in 0..20usize {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            let mut parameters = 20u16.to_be_bytes().to_vec();
            parameters.extend_from_slice(&BIOS_AUTH[..present]);
            assert_eq!(
                dispatch_bytes(
                    &mut runtime,
                    &command(TPM_RH_PLATFORM, Some(&pw_session(&[])), &parameters)
                ),
                error_response(RC_PARAM1_INSUFFICIENT),
                "{present} of 20 declared bytes"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn trailing_parameter_bytes_undecorated_size_error() {
        for trailing in [&[0xeeu8][..], &[0x00; 4][..], &[0xaa; 32][..]] {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            let mut parameters = tpm2b(&BIOS_AUTH);
            parameters.extend_from_slice(trailing);
            assert_eq!(
                dispatch_bytes(
                    &mut runtime,
                    &command(TPM_RH_PLATFORM, Some(&pw_session(&[])), &parameters)
                ),
                error_response(RC_SIZE),
                "{} trailing bytes",
                trailing.len()
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn integrity_hash_limit_p2_decoration() {
        assert_eq!(
            RC_HIERARCHY_CHANGE_AUTH_NEW_AUTH + TPM_RC_SIZE,
            RC_PARAM2_SIZE
        );
        const { assert!(MAX_AUTH_SIZE <= CONTEXT_INTEGRITY_HASH_SIZE) };
        assert_eq!(
            parse_new_auth(&tpm2b(&[0xaa; MAX_AUTH_SIZE])).map(<[u8]>::len),
            Ok(CONTEXT_INTEGRITY_HASH_SIZE),
            "the unmarshal maximum and CONTEXT_INTEGRITY_HASH_SIZE coincide under this \
             profile, so no accepted value can reach the parameter-2 branch"
        );
    }

    #[test]
    fn unavailable_nv_rejection_no_mutation() {
        for handle in HIERARCHY_HANDLES {
            let mut runtime = started_runtime();
            runtime.nv_available = false;
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(&mut runtime, &change_auth(handle, &[], &BIOS_AUTH)),
                error_response(RC_NV_UNAVAILABLE),
                "handle {handle:#x}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn nv_unavailable_post_parse_order() {
        let mut runtime = started_runtime();
        runtime.nv_available = false;
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &command(TPM_RH_PLATFORM, Some(&pw_session(&[])), &[])
            ),
            error_response(RC_PARAM1_INSUFFICIENT),
            "upstream unmarshals every parameter before the command action runs"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn owner_endorsement_lockout_change_permanent_nv_image_rebuild() {
        for handle in [TPM_RH_OWNER, TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT] {
            let mut runtime = started_runtime();
            let nv_before = runtime.nv_memory.clone();
            assert_eq!(
                dispatch_bytes(&mut runtime, &change_auth(handle, &[], &BIOS_AUTH)),
                session_success_response(),
                "handle {handle:#x}"
            );
            assert_ne!(runtime.nv_memory, nv_before, "handle {handle:#x}");
            assert!(runtime.nv_update_pending, "handle {handle:#x}");
            let rebuilt = build_nv_image(runtime.state()).expect("the state serializes");
            assert_eq!(runtime.nv_memory, rebuilt);
        }
    }

    #[test]
    fn owner_endorsement_lockout_change_host_nvram_commit() {
        for handle in [TPM_RH_OWNER, TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT] {
            let mut runtime = started_runtime();
            let bytes = change_auth(handle, &[], &BIOS_AUTH);
            let input = CommandInput::new(bytes.len() as u32, bytes);
            let mut commits = 0usize;
            let response = process(&mut runtime, 0, &input, |_| {
                commits += 1;
                Ok(())
            })
            .expect("the command processes");
            assert_eq!(response, session_success_response(), "handle {handle:#x}");
            assert_eq!(commits, 1, "handle {handle:#x}");
        }
    }

    #[test]
    fn platform_change_state_clear_auth_only() {
        let mut runtime = started_runtime();
        let nv_before = runtime.nv_memory.clone();
        assert_eq!(
            dispatch_bytes(&mut runtime, &change_auth(TPM_RH_PLATFORM, &[], &BIOS_AUTH)),
            session_success_response()
        );
        assert_stored_auth(&runtime, TPM_RH_PLATFORM, &BIOS_AUTH);
        assert_eq!(
            runtime.nv_memory, nv_before,
            "platformAuth is not permanent hierarchy data"
        );
        assert!(!runtime.nv_update_pending);
        assert!(
            runtime.state().state_clear.is_none(),
            "the NV state-clear copy is only written by TPM2_Shutdown(TPM_SU_STATE)"
        );
    }

    #[test]
    fn platform_change_no_nv_commit_outside_orderly() {
        let mut runtime = started_runtime();
        let bytes = change_auth(TPM_RH_PLATFORM, &[], &BIOS_AUTH);
        let input = CommandInput::new(bytes.len() as u32, bytes);
        let response = process(&mut runtime, 0, &input, |_| {
            panic!("a non-orderly platformAuth change must not schedule an NV commit")
        })
        .expect("the command processes");
        assert_eq!(response, session_success_response());
    }

    #[test]
    fn platform_change_orderly_marker_clear() {
        let mut runtime = started_runtime();
        make_orderly(&mut runtime, 0x0001);
        assert_eq!(
            dispatch_bytes(&mut runtime, &change_auth(TPM_RH_PLATFORM, &[], &BIOS_AUTH)),
            session_success_response()
        );
        assert_eq!(runtime.state().persistent.orderly_state, SU_NONE_VALUE);
        assert!(runtime.nv_update_pending);
        assert_eq!(
            runtime.nv_memory,
            build_nv_image(runtime.state()).expect("the state serializes")
        );
    }

    #[test]
    fn platform_change_da_used_marker() {
        let mut runtime = started_runtime();
        make_orderly(&mut runtime, 0x0001);
        runtime.live.da_used = true;
        assert_eq!(
            dispatch_bytes(&mut runtime, &change_auth(TPM_RH_PLATFORM, &[], &BIOS_AUTH)),
            session_success_response()
        );
        assert_eq!(runtime.state().persistent.orderly_state, SU_DA_USED_VALUE);
    }

    #[test]
    fn platform_change_non_orderly_marker_unchanged() {
        for orderly_state in [SU_DA_USED_VALUE, SU_NONE_VALUE] {
            let mut runtime = started_runtime();
            make_orderly(&mut runtime, orderly_state);
            let nv_before = runtime.nv_memory.clone();
            assert_eq!(
                dispatch_bytes(&mut runtime, &change_auth(TPM_RH_PLATFORM, &[], &BIOS_AUTH)),
                session_success_response(),
                "orderly state {orderly_state:#06x}"
            );
            assert_eq!(runtime.state().persistent.orderly_state, orderly_state);
            assert_eq!(runtime.nv_memory, nv_before);
            assert!(!runtime.nv_update_pending);
        }
    }

    #[test]
    fn owner_change_orderly_marker_unchanged() {
        let mut runtime = started_runtime();
        make_orderly(&mut runtime, 0x0001);
        assert_eq!(
            dispatch_bytes(&mut runtime, &change_auth(TPM_RH_OWNER, &[], &BIOS_AUTH)),
            session_success_response()
        );
        assert_eq!(
            runtime.state().persistent.orderly_state,
            0x0001,
            "only TPM_RH_PLATFORM sets g_clearOrderly"
        );
    }

    #[test]
    fn rejected_command_no_nv_update() {
        let mut runtime = started_runtime();
        for bytes in [
            change_auth(TPM_RH_NULL, &[], &BIOS_AUTH),
            change_auth(TPM_RH_OWNER, b"wrong", &BIOS_AUTH),
            command(TPM_RH_OWNER, Some(&pw_session(&[])), &[]),
            command(TPM_RH_OWNER, None, &tpm2b(&BIOS_AUTH)),
        ] {
            let before = snapshot(&runtime);
            let response = dispatch_bytes(&mut runtime, &bytes);
            assert_ne!(&response[6..10], &RC_SUCCESS.to_be_bytes());
            assert!(!runtime.nv_update_pending);
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn unrelated_runtime_state_preservation() {
        for handle in HIERARCHY_HANDLES {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(&mut runtime, &change_auth(handle, &[], &BIOS_AUTH)),
                session_success_response()
            );
            assert_eq!(runtime.failure_mode, before.failure_mode);
            assert_eq!(runtime.locality, before.locality);
            assert!(runtime.startup_received);
            assert_eq!(
                runtime
                    .live
                    .pcrs
                    .iter()
                    .map(|pcr| pcr.banks.to_vec())
                    .collect::<Vec<_>>(),
                before.pcr_banks
            );
            assert_eq!(
                runtime
                    .live
                    .state_reset
                    .as_ref()
                    .map(|reset| reset.pcr_counter),
                before.pcr_counter
            );
            assert_eq!(runtime.live.free_session_slots, before.free_session_slots);
            assert!(runtime.live.sessions.iter().all(|slot| !slot.occupied));
        }
    }

    #[test]
    fn missing_state_clear_panic_safety() {
        let mut runtime = started_runtime();
        runtime.live.state_clear = None;
        assert_eq!(
            dispatch_bytes(&mut runtime, &change_auth(TPM_RH_PLATFORM, &[], &BIOS_AUTH)),
            error_response(TPM_RC_FAILURE)
        );
    }

    #[test]
    fn missing_persistent_state_panic_safety() {
        let mut runtime = started_runtime();
        runtime.state = None;
        for handle in [TPM_RH_OWNER, TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT] {
            assert_eq!(
                dispatch_bytes(&mut runtime, &change_auth(handle, &[], &BIOS_AUTH)),
                error_response(TPM_RC_FAILURE),
                "handle {handle:#x}"
            );
        }
    }

    #[test]
    fn malformed_authorization_area_shared_session_codes() {
        for (label, auth, expected) in [
            (
                "hmac_session",
                auth_session(HMAC_SESSION_FIRST, &[], 0x00, &[]),
                RC_REFERENCE_S0,
            ),
            (
                "policy_session",
                auth_session(POLICY_SESSION_FIRST, &[], 0x00, &[]),
                RC_REFERENCE_S0,
            ),
            (
                "non_empty_nonce",
                auth_session(TPM_RS_PW, &[0xaa], 0x00, &[]),
                0x98f,
            ),
        ] {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(
                    &mut runtime,
                    &command(TPM_RH_PLATFORM, Some(&auth), &tpm2b(&BIOS_AUTH))
                ),
                error_response(expected),
                "{label}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn debug_output_auth_redaction() {
        let mut runtime = started_runtime();
        for handle in HIERARCHY_HANDLES {
            assert_eq!(
                dispatch_bytes(&mut runtime, &change_auth(handle, &[], &BIOS_AUTH)),
                session_success_response(),
                "handle {handle:#x}"
            );
        }
        assert_eq!(
            dispatch_bytes(&mut runtime, &change_auth(TPM_RH_LOCKOUT, b"wrong", &[])),
            error_response(RC_SESSION1_AUTH_FAIL),
            "a DA failure must not leak the value either"
        );
        let persistent = &runtime.state().persistent;
        let rendered = format!(
            "{:?} {:?} {:?} {:?} {:?} {:?}",
            runtime,
            runtime.live,
            persistent.owner_auth,
            persistent.endorsement_auth,
            persistent.lockout_auth,
            runtime
                .live
                .state_clear
                .as_ref()
                .expect("live state clear")
                .platform_auth
        );
        assert!(!rendered.contains("0, 1, 2, 3"), "{rendered}");
        assert!(!rendered.contains("18, 19"), "{rendered}");
        assert!(!rendered.contains("wrong"), "{rendered}");
        assert!(rendered.contains("OwnedSecret { len: 20 }"), "{rendered}");
    }

    #[test]
    fn bit_flip_panic_safety() {
        let valid = change_auth(TPM_RH_PLATFORM, &[], &BIOS_AUTH);
        for_each_mutation(
            "TPM2_HierarchyChangeAuth",
            prefix_bit_flips(&valid, valid.len(), 6, false),
            |bytes| {
                dispatch_ignoring_result(&mut started_runtime(), bytes);
            },
        );
    }

    #[test]
    fn truncated_prefix_rejection_safety() {
        let valid = change_auth(TPM_RH_PLATFORM, &[], &BIOS_AUTH);
        for len in 10..valid.len() {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            let mut truncated = valid[..len].to_vec();
            truncated[2..6].copy_from_slice(&(len as u32).to_be_bytes());
            let input = CommandInput::new(truncated.len() as u32, truncated);
            let parsed = parse_command(&input).expect("the header parses");
            let response = serialize_response(&dispatch(
                &mut runtime,
                &parsed,
                CancellationToken::disabled(),
            ))
            .unwrap();
            assert_ne!(&response[6..10], &RC_SUCCESS.to_be_bytes(), "length {len}");
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn swtpm_bios_flow_byte_match() {
        let mut runtime = started_runtime();
        let request = hex(
            "8002 00000031 00000129 4000000c 00000009 40000009 0000 01 0000 \
             0014 000102030405060708090a0b0c0d0e0f10111213",
        );
        assert_eq!(request.len(), 0x31, "the upstream command size");
        assert_eq!(
            dispatch_bytes(&mut runtime, &request),
            hex("8002 00000013 00000000 00000000 0000 01 0000"),
            "the 19-byte session-tagged response"
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &request),
            hex("8001 0000000a 000009a2"),
            "platformAuth has changed, so the empty password no longer authorizes"
        );
    }

    #[test]
    fn startup_clear_platform_auth_reset() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(&mut runtime, &change_auth(TPM_RH_PLATFORM, &[], &BIOS_AUTH)),
            session_success_response()
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &change_auth(TPM_RH_OWNER, &[], &BIOS_AUTH)),
            session_success_response()
        );

        runtime.startup_received = false;
        runtime.live = crate::library::tpm2::live::LiveState::power_on();
        assert_eq!(
            dispatch_bytes(&mut runtime, &hex("80010000000c0000014400 00")),
            hex("80010000000a00000000")
        );

        assert_stored_auth(&runtime, TPM_RH_PLATFORM, &[]);
        assert_eq!(
            dispatch_bytes(&mut runtime, &change_auth(TPM_RH_PLATFORM, &[], &BIOS_AUTH)),
            session_success_response(),
            "the empty password authorizes platformAuth again"
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &change_auth(TPM_RH_OWNER, &[], &BIOS_AUTH)),
            error_response(RC_SESSION1_BAD_AUTH),
            "ownerAuth survives the reset"
        );
    }
}
