use super::update::{
    commit_orderly_clear, commit_pcr_counter, live_pcr_counter, pcr_changed, prepare_orderly_clear,
};
use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_LOCALITY, TPM_RC_SIZE};
use crate::library::tpm2::command::core::dispatcher::CommandFrame;
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::pcr::{PCR_SLOT_BANKS, allocation_selects, pcr_reset_allowed};
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::types::TpmResult;

struct PreparedReset {
    banks: [Option<Vec<u8>>; PCR_SLOT_BANKS.len()],
    pcr_counter: u32,
    orderly_state: Option<u16>,
}

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let pcr_handle = frame.handles.first().copied().ok_or(TPM_RC_FAILURE)?;
    if !frame.parameters.is_empty() {
        return Err(TPM_RC_SIZE);
    }

    let pcr = pcr_handle as usize;
    if !pcr_reset_allowed(pcr, runtime.locality) {
        return Err(TPM_RC_LOCALITY);
    }

    let prepared = prepare_reset(runtime, pcr)?;
    commit_reset(runtime, pcr, prepared)?;
    Ok(CommandOutput::empty())
}

fn prepare_reset(runtime: &Tpm2Runtime, pcr: usize) -> Result<PreparedReset, TpmResult> {
    let orderly_state = prepare_orderly_clear(runtime, pcr)?;

    let allocation = runtime.effective_pcr_allocated().ok_or(TPM_RC_FAILURE)?;
    if runtime.live.pcrs.get(pcr).is_none() {
        return Err(TPM_RC_FAILURE);
    }
    let mut banks: [Option<Vec<u8>>; PCR_SLOT_BANKS.len()] = core::array::from_fn(|_| None);
    for (slot, &(hash_alg, digest_size)) in PCR_SLOT_BANKS.iter().enumerate() {
        if allocation_selects(allocation, hash_alg, pcr) {
            banks[slot] = Some(vec![0u8; digest_size]);
        }
    }

    let pcr_counter = pcr_changed(live_pcr_counter(runtime)?, pcr)?;

    Ok(PreparedReset {
        banks,
        pcr_counter,
        orderly_state,
    })
}

fn commit_reset(
    runtime: &mut Tpm2Runtime,
    pcr: usize,
    prepared: PreparedReset,
) -> Result<(), TpmResult> {
    commit_orderly_clear(runtime, prepared.orderly_state)?;

    let live_pcr = runtime.live.pcrs.get_mut(pcr).ok_or(TPM_RC_FAILURE)?;
    for (slot, value) in prepared.banks.into_iter().enumerate() {
        if let Some(value) = value {
            live_pcr.banks[slot] = Some(value);
        }
    }
    commit_pcr_counter(runtime, prepared.pcr_counter)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::CommandInput;
    use crate::library::cancel::CancellationToken;
    use crate::library::constants::{
        TPM_RC_AUTH_MISSING, TPM_RC_INITIALIZE, TPM_RC_NV_UNAVAILABLE,
    };
    use crate::library::tpm2::command::core::dispatcher::dispatch;
    use crate::library::tpm2::command::core::header::{parse_command, serialize_response};
    use crate::library::tpm2::command::core::registry::{TPM_CC_PCR_RESET, TPM_RH_NULL};
    use crate::library::tpm2::command::core::test_support::{
        auth_session, dispatch_bytes, dispatch_ignoring_result, error_response, for_each_mutation,
        hex, make_orderly, manufactured_runtime, prefix_bit_flips, process, pw_session,
        session_success_response, started_runtime,
    };
    use crate::library::tpm2::command::pcr::test_support::{
        assert_unchanged, bank, pcr_counter, snapshot,
    };
    use crate::library::tpm2::command::session::processing::{
        HMAC_SESSION_FIRST, POLICY_SESSION_FIRST, TPM_RS_PW,
    };

    use crate::library::tpm2::orderly::{SU_DA_USED_VALUE, SU_NONE_VALUE};
    use crate::library::tpm2::persistent::{OwnedPcrAllocation, OwnedPcrSelection};

    use crate::library::tpm2::volatile::IMPLEMENTATION_PCR;

    const TPM_ALG_SHA256: u16 = 0x000b;

    const SHA1_SLOT: usize = 0;
    const SHA256_SLOT: usize = 1;

    const STARTUP_PCR_COUNTER: u32 = 20;

    const RC_SUCCESS: u32 = 0x000;
    const RC_SIZE: u32 = 0x095;
    const RC_LOCALITY: u32 = 0x907;
    const RC_FAILURE: u32 = 0x101;
    const RC_REFERENCE_S0: u32 = 0x918;

    const RC_HANDLE1_INSUFFICIENT: u32 = 0x19a;
    const RC_HANDLE1_VALUE: u32 = 0x184;

    const RC_SESSION1_NONCE: u32 = 0x98f;
    const RC_SESSION1_ATTRIBUTES: u32 = 0x982;
    const RC_SESSION1_RESERVED: u32 = 0x9a1;
    const RC_SESSION1_VALUE: u32 = 0x984;
    const RC_SESSION1_INSUFFICIENT: u32 = 0x99a;
    const RC_SESSION1_SIZE: u32 = 0x995;
    const RC_SESSION1_BAD_AUTH: u32 = 0x9a2;
    const RC_SESSION2_HANDLE: u32 = 0xa8b;
    const RC_SESSION2_INSUFFICIENT: u32 = 0xa9a;

    const RESETTABLE_PCRS: [u32; 5] = [16, 20, 21, 22, 23];

    #[track_caller]
    fn runtime_at(locality: u8) -> Tpm2Runtime {
        let mut runtime = started_runtime();
        runtime.locality = locality;
        runtime
    }

    fn reset_command(handle: u32, auth: Option<&[u8]>, parameters: &[u8]) -> Vec<u8> {
        let mut payload = handle.to_be_bytes().to_vec();
        if let Some(auth) = auth {
            payload.extend_from_slice(&(auth.len() as u32).to_be_bytes());
            payload.extend_from_slice(auth);
        }
        payload.extend_from_slice(parameters);

        let tag: u16 = if auth.is_some() { 0x8002 } else { 0x8001 };
        let mut out = tag.to_be_bytes().to_vec();
        out.extend_from_slice(&(10 + payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&TPM_CC_PCR_RESET.to_be_bytes());
        out.extend_from_slice(&payload);
        out
    }

    fn authorized_reset(pcr: u32) -> Vec<u8> {
        reset_command(pcr, Some(&pw_session(&[])), &[])
    }

    #[test]
    fn pcr_reset_pre_startup_initialize_rejection() {
        let mut runtime = manufactured_runtime();
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_reset(20)),
            error_response(TPM_RC_INITIALIZE),
            "TPM2_PCR_Reset before TPM2_Startup"
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &reset_command(20, None, &[])),
            error_response(TPM_RC_INITIALIZE),
            "TPM2_PCR_Reset before TPM2_Startup: the lifecycle check precedes handle parsing"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn pcr_twenty_locality_two_reset() {
        let mut runtime = runtime_at(2);
        assert_ne!(bank(&runtime, 20, SHA256_SLOT), vec![0u8; 32]);
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_reset(20)),
            session_success_response()
        );
        assert_eq!(bank(&runtime, 20, SHA256_SLOT), vec![0u8; 32]);
    }

    #[test]
    fn pcr20_locality1_rejection() {
        let mut runtime = runtime_at(1);
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_reset(20)),
            error_response(RC_LOCALITY)
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn upstream_swtpm_locality_flow_byte_match() {
        let mut runtime = runtime_at(2);
        let reset = hex("8002 0000001b 0000013d 00000014 00000009 40000009 0000 00 0000");
        assert_eq!(reset.len(), 0x1b, "the upstream command size");
        assert_eq!(
            dispatch_bytes(&mut runtime, &reset),
            hex("8002 00000013 00000000 00000000 0000 01 0000"),
            "the 19-byte session-tagged response"
        );

        runtime.locality = 1;
        assert_eq!(
            dispatch_bytes(&mut runtime, &reset),
            hex("8001 0000000a 00000907"),
            "locality 1 may not reset PCR 20"
        );
    }

    #[test]
    fn success_response_upstream_19_bytes() {
        let mut runtime = runtime_at(2);
        let response = dispatch_bytes(&mut runtime, &authorized_reset(20));
        assert_eq!(
            response,
            hex("8002 00000013 00000000 00000000 0000 01 0000")
        );
        assert_eq!(response.len(), 19);
        assert_eq!(&response[..2], &[0x80, 0x02], "TPM_ST_SESSIONS");
        assert_eq!(&response[6..10], &[0x00; 4], "TPM_RC_SUCCESS");
        assert_eq!(&response[10..14], &[0x00; 4], "empty parameter area");
        assert_eq!(
            &response[14..],
            &[0x00, 0x00, 0x01, 0x00, 0x00],
            "empty nonce | continueSession | empty hmac"
        );
    }

    #[test]
    fn locality_matrix_upstream_table_match() {
        const RESET_LOCALITY: [u8; IMPLEMENTATION_PCR] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x0f, 0x10, 0x10, 0x10, 0x1c, 0x1c, 0x1c, 0x0f,
        ];
        for (pcr, reset_locality) in RESET_LOCALITY.into_iter().enumerate() {
            for locality in 0..5u8 {
                let allowed = locality != 4 && reset_locality & (1 << locality) != 0;
                let mut runtime = runtime_at(locality);
                let before = snapshot(&runtime);
                let response = dispatch_bytes(&mut runtime, &authorized_reset(pcr as u32));
                if allowed {
                    assert_eq!(
                        response,
                        session_success_response(),
                        "PCR {pcr} from locality {locality}"
                    );
                } else {
                    assert_eq!(
                        response,
                        error_response(RC_LOCALITY),
                        "PCR {pcr} from locality {locality}"
                    );
                    assert_unchanged(&runtime, &before);
                }
            }
        }
    }

    #[test]
    fn locality_four_pcr_reset_denial() {
        for pcr in 0..IMPLEMENTATION_PCR as u32 {
            let mut runtime = runtime_at(4);
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(&mut runtime, &authorized_reset(pcr)),
                error_response(RC_LOCALITY),
                "DRTM forbids a command reset from locality 4, PCR {pcr}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn drtm_pcrs_command_reset_rejection() {
        for pcr in [17u32, 18, 19] {
            for locality in 0..5u8 {
                let mut runtime = runtime_at(locality);
                assert_eq!(
                    dispatch_bytes(&mut runtime, &authorized_reset(pcr)),
                    error_response(RC_LOCALITY),
                    "PCR {pcr} only lists locality 4, which DRTM blocks"
                );
            }
        }
    }

    #[test]
    fn allocated_banks_zero_digest_reset() {
        for pcr in RESETTABLE_PCRS {
            let mut runtime = runtime_at(2);
            assert_eq!(
                dispatch_bytes(&mut runtime, &authorized_reset(pcr)),
                session_success_response(),
                "PCR {pcr}"
            );
            for (slot, &(_, digest_size)) in PCR_SLOT_BANKS.iter().enumerate() {
                assert_eq!(
                    bank(&runtime, pcr as usize, slot),
                    vec![0u8; digest_size],
                    "PCR {pcr} bank {slot}"
                );
            }
        }
    }

    #[test]
    fn unallocated_bank_value_preservation() {
        let mut runtime = runtime_at(2);
        runtime.live_pcr_allocated = Some(OwnedPcrAllocation {
            selections: vec![OwnedPcrSelection {
                hash_alg: TPM_ALG_SHA256,
                select: vec![0xff, 0xff, 0xff],
            }],
        });
        let sha1_before = bank(&runtime, 20, SHA1_SLOT);
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_reset(20)),
            session_success_response()
        );
        assert_eq!(bank(&runtime, 20, SHA256_SLOT), vec![0u8; 32]);
        assert_eq!(
            bank(&runtime, 20, SHA1_SLOT),
            sha1_before,
            "an unallocated bank keeps its value"
        );
    }

    #[test]
    fn unallocated_bank_none_preservation() {
        let mut runtime = runtime_at(2);
        runtime.live_pcr_allocated = Some(OwnedPcrAllocation {
            selections: vec![OwnedPcrSelection {
                hash_alg: TPM_ALG_SHA256,
                select: vec![0xff, 0xff, 0xff],
            }],
        });
        runtime.live.pcrs[20].banks[SHA1_SLOT] = None;
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_reset(20)),
            session_success_response()
        );
        assert!(runtime.live.pcrs[20].banks[SHA1_SLOT].is_none());
        assert_eq!(bank(&runtime, 20, SHA256_SLOT), vec![0u8; 32]);
    }

    #[test]
    fn empty_pcr_allocation_single_counter_increment() {
        let mut runtime = runtime_at(2);
        runtime.live_pcr_allocated = Some(OwnedPcrAllocation {
            selections: Vec::new(),
        });
        let banks_before = runtime.live.pcrs[20].banks.to_vec();
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_reset(20)),
            session_success_response()
        );
        assert_eq!(runtime.live.pcrs[20].banks.to_vec(), banks_before);
        assert_eq!(
            pcr_counter(&runtime),
            STARTUP_PCR_COUNTER + 1,
            "upstream calls PCRChanged() once per command, not once per bank"
        );
    }

    #[test]
    fn counter_increment_per_command_outside_tcb() {
        let mut runtime = runtime_at(2);
        for round in 1..=3u32 {
            assert_eq!(
                dispatch_bytes(&mut runtime, &authorized_reset(20)),
                session_success_response(),
                "round {round}"
            );
            assert_eq!(pcr_counter(&runtime), STARTUP_PCR_COUNTER + round);
        }
    }

    #[test]
    fn non_incrementing_pcr_counter_preservation() {
        for pcr in [16u32, 21, 22, 23] {
            let mut runtime = runtime_at(2);
            let before = pcr_counter(&runtime);
            assert_eq!(
                dispatch_bytes(&mut runtime, &authorized_reset(pcr)),
                session_success_response(),
                "PCR {pcr}"
            );
            assert_eq!(
                bank(&runtime, pcr as usize, SHA256_SLOT),
                vec![0u8; 32],
                "PCR {pcr} was still reset"
            );
            assert_eq!(
                pcr_counter(&runtime),
                before,
                "PCR {pcr} is in the TCB group"
            );
        }
    }

    #[test]
    fn counter_overflow_panic_safety() {
        let mut runtime = runtime_at(2);
        runtime.live.state_reset.as_mut().unwrap().pcr_counter = u32::MAX;
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_reset(20)),
            error_response(RC_FAILURE),
            "the overflow is detected before any PCR is written"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn missing_state_reset_panic_safety() {
        let mut runtime = runtime_at(2);
        runtime.live.state_reset = None;
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_reset(20)),
            error_response(RC_FAILURE)
        );
    }

    #[test]
    fn missing_live_pcr_panic_safety() {
        let mut runtime = runtime_at(2);
        runtime.live.pcrs.clear();
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_reset(20)),
            error_response(RC_FAILURE)
        );
    }

    #[test]
    fn resettable_pcr_no_orderly_nv_mutation() {
        for pcr in RESETTABLE_PCRS {
            let mut runtime = runtime_at(2);
            make_orderly(&mut runtime, 0x0001);
            runtime.nv_available = false;
            let nv_before = runtime.nv_memory.clone();
            assert_eq!(
                dispatch_bytes(&mut runtime, &authorized_reset(pcr)),
                session_success_response(),
                "PCR {pcr} is not state saved"
            );
            assert_eq!(
                runtime.state.as_ref().unwrap().persistent.orderly_state,
                0x0001
            );
            assert!(!runtime.nv_update_pending);
            assert_eq!(runtime.nv_memory, nv_before);
        }
    }

    #[test]
    fn pcr_reset_no_nv_commit_callback() {
        let mut runtime = runtime_at(2);
        make_orderly(&mut runtime, 0x0001);
        let command = authorized_reset(20);
        let input = CommandInput::new(command.len() as u32, command);
        let response = process(&mut runtime, 2, &input, |_| {
            panic!("resetting a non-state-saved PCR must not schedule an NV commit")
        })
        .expect("the command processes");
        assert_eq!(response, session_success_response());
    }

    #[test]
    fn state_saved_pcr_orderly_rules() {
        let mut runtime = started_runtime();
        assert_eq!(
            prepare_reset(&runtime, 10).map(|prepared| prepared.orderly_state),
            Ok(None),
            "a non-orderly TPM has nothing to clear"
        );

        make_orderly(&mut runtime, 0x0001);
        assert_eq!(
            prepare_reset(&runtime, 10).map(|prepared| prepared.orderly_state),
            Ok(Some(SU_NONE_VALUE))
        );

        runtime.live.da_used = true;
        assert_eq!(
            prepare_reset(&runtime, 10).map(|prepared| prepared.orderly_state),
            Ok(Some(SU_DA_USED_VALUE))
        );

        runtime.nv_available = false;
        assert_eq!(
            prepare_reset(&runtime, 10).map(|prepared| prepared.orderly_state),
            Err(TPM_RC_NV_UNAVAILABLE),
            "RETURN_IF_ORDERLY fails before any PCR mutation"
        );
    }

    #[test]
    fn null_handle_rejection() {
        let mut runtime = runtime_at(2);
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_reset(TPM_RH_NULL)),
            error_response(RC_HANDLE1_VALUE),
            "PCR_Reset unmarshals its handle without allowNull"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn out_of_range_handle_rejection() {
        for handle in [
            IMPLEMENTATION_PCR as u32,
            25,
            100,
            0x0100_0000,
            0x0200_0000,
            0x4000_0000,
            0x4000_0001,
            TPM_RS_PW,
            0x8100_0000,
            u32::MAX,
        ] {
            let mut runtime = runtime_at(2);
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(&mut runtime, &authorized_reset(handle)),
                error_response(RC_HANDLE1_VALUE),
                "handle {handle:#x}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn truncated_handle_decorated_error() {
        for len in 0..4usize {
            let mut runtime = runtime_at(2);
            let mut command = hex("8002 00000000 0000013d");
            command.extend_from_slice(&[0u8; 4][..len]);
            let size = command.len() as u32;
            command[2..6].copy_from_slice(&size.to_be_bytes());
            assert_eq!(
                dispatch_bytes(&mut runtime, &command),
                error_response(RC_HANDLE1_INSUFFICIENT),
                "{len} of 4 handle bytes"
            );
        }
    }

    #[test]
    fn trailing_parameter_bytes_size_error() {
        for parameters in [&[0x00u8][..], &[0xee][..], &[0x00; 4][..], &[0xaa; 32][..]] {
            let mut runtime = runtime_at(2);
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(
                    &mut runtime,
                    &reset_command(20, Some(&pw_session(&[])), parameters)
                ),
                error_response(RC_SIZE),
                "{} trailing bytes",
                parameters.len()
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn trailing_parameters_pre_locality_rejection() {
        let mut runtime = runtime_at(1);
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &reset_command(20, Some(&pw_session(&[])), &[0xee])
            ),
            error_response(RC_SIZE),
            "upstream unmarshals the parameter area before TPM2_PCR_Reset runs"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn missing_auth_area_auth_missing_error() {
        let mut runtime = runtime_at(2);
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &reset_command(20, None, &[])),
            error_response(TPM_RC_AUTH_MISSING)
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn single_empty_password_session_success() {
        let mut runtime = runtime_at(2);
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_reset(20)),
            session_success_response()
        );
    }

    #[test]
    fn nonempty_password_empty_auth_value_rejection() {
        let mut runtime = runtime_at(2);
        let before = snapshot(&runtime);
        let auth = auth_session(TPM_RS_PW, &[], 0x00, b"wrong");
        assert_eq!(
            dispatch_bytes(&mut runtime, &reset_command(20, Some(&auth), &[])),
            error_response(RC_SESSION1_BAD_AUTH),
            "every implemented PCR has an empty effective authValue"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn trailing_zero_password_empty_auth_match() {
        let mut runtime = runtime_at(2);
        for password in [&[0x00][..], &[0x00, 0x00][..], &[0x00; 32][..]] {
            let auth = auth_session(TPM_RS_PW, &[], 0x00, password);
            assert_eq!(
                dispatch_bytes(&mut runtime, &reset_command(20, Some(&auth), &[])),
                session_success_response(),
                "upstream strips trailing zeros before comparing ({} bytes)",
                password.len()
            );
        }
    }

    #[test]
    fn malformed_authorization_area_oracle_code_parity() {
        let declared_password_size = |size: u16| {
            let mut session = auth_session(TPM_RS_PW, &[], 0x00, &[0xaa; 8]);
            session[7..9].copy_from_slice(&size.to_be_bytes());
            session
        };

        for (label, auth, expected) in [
            (
                "authorization_area_below_the_minimum",
                pw_session(&[])[..4].to_vec(),
                RC_SIZE,
            ),
            (
                "invalid_handle",
                auth_session(0x4000_0008, &[], 0x00, &[]),
                RC_SESSION1_VALUE,
            ),
            (
                "non_empty_nonce",
                auth_session(TPM_RS_PW, &[0xaa, 0xbb], 0x00, &[]),
                RC_SESSION1_NONCE,
            ),
            (
                "reserved_attributes",
                auth_session(TPM_RS_PW, &[], 0x08, &[]),
                RC_SESSION1_RESERVED,
            ),
            (
                "audit_attribute",
                auth_session(TPM_RS_PW, &[], 0x80, &[]),
                RC_SESSION1_ATTRIBUTES,
            ),
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
                "password_size_above_the_tpm2b_maximum",
                declared_password_size(65),
                RC_SESSION1_SIZE,
            ),
            (
                "password_size_beyond_the_authorization_area",
                declared_password_size(64),
                RC_SESSION1_INSUFFICIENT,
            ),
        ] {
            let mut runtime = runtime_at(2);
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(&mut runtime, &reset_command(20, Some(&auth), &[])),
                error_response(expected),
                "{label}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn truncated_second_session_indexed_error() {
        let mut auth = pw_session(&[]);
        auth.extend_from_slice(&pw_session(&[]));
        for len in 10..auth.len() {
            let mut runtime = runtime_at(2);
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(&mut runtime, &reset_command(20, Some(&auth[..len]), &[])),
                error_response(RC_SESSION2_INSUFFICIENT),
                "authorization area of {len} bytes"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn extra_password_session_handle_error() {
        let mut auth = pw_session(&[]);
        auth.extend_from_slice(&pw_session(&[]));
        let mut runtime = runtime_at(2);
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &reset_command(20, Some(&auth), &[])),
            error_response(RC_SESSION2_HANDLE)
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn invalid_handle_pre_session_error() {
        let mut runtime = runtime_at(2);
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &reset_command(
                    IMPLEMENTATION_PCR as u32,
                    Some(&auth_session(0x4000_0008, &[], 0x00, &[])),
                    &[]
                )
            ),
            error_response(RC_HANDLE1_VALUE),
            "a malformed session never masks the handle error"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn pcr_reset_zero_session_slot_consumption() {
        let mut runtime = runtime_at(2);
        let free_before = runtime.live.free_session_slots;
        for round in 0..4 {
            assert_eq!(
                dispatch_bytes(&mut runtime, &authorized_reset(20)),
                session_success_response(),
                "round {round}"
            );
            assert_eq!(runtime.live.free_session_slots, free_before);
            assert!(
                runtime.live.sessions.iter().all(|slot| !slot.occupied),
                "a password session creates no persistent session object"
            );
        }
    }

    #[test]
    fn bit_flip_panic_safety() {
        let valid = authorized_reset(20);
        for_each_mutation(
            "TPM2_PCR_Reset",
            prefix_bit_flips(&valid, valid.len(), 6, false),
            |bytes| {
                dispatch_ignoring_result(&mut runtime_at(2), bytes);
            },
        );
    }

    #[test]
    fn truncated_prefix_rejection_safety() {
        let valid = authorized_reset(20);
        for len in 10..valid.len() {
            let mut runtime = runtime_at(2);
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
}
