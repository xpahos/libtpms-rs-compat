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
    fn process(
        runtime: &mut crate::library::tpm2::runtime::Tpm2Runtime,
        locality: u8,
        command: &crate::library::CommandInput,
        commit_nv: impl FnOnce(
            &crate::library::tpm2::runtime::Tpm2Runtime,
        ) -> Result<(), crate::types::TpmResult>,
    ) -> Result<Vec<u8>, crate::types::TpmResult> {
        crate::library::tpm2::process(
            runtime,
            crate::library::tpm2::PlatformInputs::at_locality(locality),
            command,
            &crate::library::tpm2::clock::RecordingClock::new(1_600_000_000_000, 5_000_000),
            commit_nv,
        )
    }
    use super::*;
    use crate::library::CommandInput;
    use crate::library::constants::{
        TPM_RC_AUTH_MISSING, TPM_RC_INITIALIZE, TPM_RC_NV_UNAVAILABLE,
    };
    use crate::library::tpm2::command::core::dispatcher::dispatch;
    use crate::library::tpm2::command::core::header::{parse_command, serialize_response};
    use crate::library::tpm2::command::core::registry::{TPM_CC_PCR_RESET, TPM_RH_NULL};
    use crate::library::tpm2::command::session::processing::{
        HMAC_SESSION_FIRST, POLICY_SESSION_FIRST, TPM_RS_PW,
    };
    use crate::library::tpm2::manufacture::manufacture_state;
    use crate::library::tpm2::nv::build_nv_image;
    use crate::library::tpm2::orderly::{SU_DA_USED_VALUE, SU_NONE_VALUE};
    use crate::library::tpm2::persistent::{OwnedPcrAllocation, OwnedPcrSelection};
    use crate::library::tpm2::profile::validate_user_profile;
    use crate::library::tpm2::runtime::commit_manufactured_state;
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

    fn hex(value: &str) -> Vec<u8> {
        let cleaned: String = value.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(cleaned.len().is_multiple_of(2));
        (0..cleaned.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&cleaned[index..index + 2], 16).unwrap())
            .collect()
    }

    fn deterministic_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
        let len = buffer.len() as u8;
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_add(len) ^ 0x55;
        }
        Ok(())
    }

    fn manufactured_runtime() -> Box<Tpm2Runtime> {
        let profile = validate_user_profile(None).expect("the null profile validates");
        let state = manufacture_state(profile, deterministic_entropy).expect("manufactures");
        let mut runtime = commit_manufactured_state(state).expect("commits");
        runtime.entropy = deterministic_entropy;
        runtime
    }

    #[track_caller]
    fn dispatch_bytes(runtime: &mut Tpm2Runtime, bytes: &[u8]) -> Vec<u8> {
        let input = CommandInput::new(bytes.len() as u32, bytes.to_vec());
        let parsed = parse_command(&input).expect("the header parses");
        serialize_response(&dispatch(runtime, &parsed)).expect("the response serializes")
    }

    #[track_caller]
    fn started_runtime() -> Box<Tpm2Runtime> {
        let mut runtime = manufactured_runtime();
        assert_eq!(
            dispatch_bytes(&mut runtime, &hex("80010000000c0000014400 00")),
            hex("80010000000a00000000")
        );
        runtime.nv_update_pending = false;
        runtime
    }

    #[track_caller]
    fn runtime_at(locality: u8) -> Box<Tpm2Runtime> {
        let mut runtime = started_runtime();
        runtime.locality = locality;
        runtime
    }

    fn password_session(handle: u32, nonce: &[u8], attributes: u8, password: &[u8]) -> Vec<u8> {
        let mut out = handle.to_be_bytes().to_vec();
        out.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
        out.extend_from_slice(nonce);
        out.push(attributes);
        out.extend_from_slice(&(password.len() as u16).to_be_bytes());
        out.extend_from_slice(password);
        out
    }

    fn empty_password_session() -> Vec<u8> {
        password_session(TPM_RS_PW, &[], 0x00, &[])
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
        reset_command(pcr, Some(&empty_password_session()), &[])
    }

    fn error_response(code: u32) -> Vec<u8> {
        let mut out = hex("80010000000a");
        out.extend_from_slice(&code.to_be_bytes());
        out
    }

    fn session_success_response() -> Vec<u8> {
        hex("8002 00000013 00000000 00000000 0000 01 0000")
    }

    struct Snapshot {
        failure_mode: bool,
        nv_update_pending: bool,
        orderly_state: u16,
        nv_memory: Box<[u8]>,
        pcr_counter: Option<u32>,
        pcr_banks: Vec<Vec<Option<Vec<u8>>>>,
        free_session_slots: u32,
        sessions_occupied: Vec<bool>,
    }

    fn snapshot(runtime: &Tpm2Runtime) -> Snapshot {
        Snapshot {
            failure_mode: runtime.failure_mode,
            nv_update_pending: runtime.nv_update_pending,
            orderly_state: runtime.state.as_ref().unwrap().persistent.orderly_state,
            nv_memory: runtime.nv_memory.clone(),
            pcr_counter: runtime
                .live
                .state_reset
                .as_ref()
                .map(|reset| reset.pcr_counter),
            pcr_banks: runtime
                .live
                .pcrs
                .iter()
                .map(|pcr| pcr.banks.to_vec())
                .collect(),
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
        assert_eq!(runtime.failure_mode, before.failure_mode);
        assert_eq!(runtime.nv_update_pending, before.nv_update_pending);
        assert_eq!(
            runtime.state.as_ref().unwrap().persistent.orderly_state,
            before.orderly_state
        );
        assert_eq!(runtime.nv_memory, before.nv_memory);
        assert_eq!(
            runtime
                .live
                .state_reset
                .as_ref()
                .map(|reset| reset.pcr_counter),
            before.pcr_counter
        );
        let pcr_banks: Vec<Vec<Option<Vec<u8>>>> = runtime
            .live
            .pcrs
            .iter()
            .map(|pcr| pcr.banks.to_vec())
            .collect();
        assert_eq!(pcr_banks, before.pcr_banks);
        assert_eq!(runtime.live.free_session_slots, before.free_session_slots);
        assert_eq!(
            runtime
                .live
                .sessions
                .iter()
                .map(|slot| slot.occupied)
                .collect::<Vec<bool>>(),
            before.sessions_occupied
        );
    }

    #[track_caller]
    fn bank(runtime: &Tpm2Runtime, pcr: usize, slot: usize) -> Vec<u8> {
        runtime.live.pcrs[pcr].banks[slot]
            .clone()
            .expect("an allocated bank")
    }

    fn pcr_counter(runtime: &Tpm2Runtime) -> u32 {
        runtime.live.state_reset.as_ref().unwrap().pcr_counter
    }

    fn make_orderly(runtime: &mut Tpm2Runtime, orderly_state: u16) {
        let state = runtime.state.as_mut().expect("state present");
        state.persistent.orderly_state = orderly_state;
        runtime.nv_memory = build_nv_image(state).expect("the orderly state serializes");
        runtime.nv_update_pending = false;
    }

    #[test]
    fn pcr_reset_before_startup_returns_initialize() {
        let mut runtime = manufactured_runtime();
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_reset(20)),
            error_response(TPM_RC_INITIALIZE)
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &reset_command(20, None, &[])),
            error_response(TPM_RC_INITIALIZE),
            "the lifecycle check precedes handle parsing"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn pcr_twenty_resets_from_locality_two() {
        let mut runtime = runtime_at(2);
        assert_ne!(bank(&runtime, 20, SHA256_SLOT), vec![0u8; 32]);
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_reset(20)),
            session_success_response()
        );
        assert_eq!(bank(&runtime, 20, SHA256_SLOT), vec![0u8; 32]);
    }

    #[test]
    fn pcr_twenty_is_not_resettable_from_locality_one() {
        let mut runtime = runtime_at(1);
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_reset(20)),
            error_response(RC_LOCALITY)
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn the_upstream_swtpm_locality_flow_matches_byte_for_byte() {
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
    fn the_successful_response_is_the_exact_nineteen_upstream_bytes() {
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
    fn the_reset_locality_matrix_matches_the_upstream_platform_table() {
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
    fn locality_four_never_resets_a_pcr() {
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
    fn the_drtm_pcrs_are_never_resettable_by_command() {
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
    fn every_allocated_bank_is_reset_to_an_all_zero_digest() {
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
    fn an_unallocated_bank_is_left_untouched() {
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
    fn an_unallocated_bank_stays_unallocated() {
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
    fn a_reset_with_no_allocated_bank_still_moves_the_counter_once() {
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
    fn the_counter_advances_once_per_command_outside_the_tcb_group() {
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
    fn do_not_increment_pcrs_preserve_the_counter() {
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
    fn a_counter_at_its_maximum_fails_without_panicking() {
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
    fn a_missing_state_reset_fails_without_panicking() {
        let mut runtime = runtime_at(2);
        runtime.live.state_reset = None;
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_reset(20)),
            error_response(RC_FAILURE)
        );
    }

    #[test]
    fn a_missing_live_pcr_fails_without_panicking() {
        let mut runtime = runtime_at(2);
        runtime.live.pcrs.clear();
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_reset(20)),
            error_response(RC_FAILURE)
        );
    }

    #[test]
    fn a_resettable_pcr_never_touches_the_orderly_state_or_nv() {
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
    fn pcr_reset_never_invokes_the_nv_commit_callback() {
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
    fn a_state_saved_pcr_would_apply_the_upstream_orderly_rules() {
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
    fn the_null_handle_is_rejected() {
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
    fn out_of_range_and_non_pcr_handles_are_rejected() {
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
    fn a_truncated_handle_is_reported_with_the_handle_decoration() {
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
    fn trailing_parameter_bytes_return_size() {
        for parameters in [&[0x00u8][..], &[0xee][..], &[0x00; 4][..], &[0xaa; 32][..]] {
            let mut runtime = runtime_at(2);
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(
                    &mut runtime,
                    &reset_command(20, Some(&empty_password_session()), parameters)
                ),
                error_response(RC_SIZE),
                "{} trailing bytes",
                parameters.len()
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn trailing_parameters_are_rejected_before_the_locality_check() {
        let mut runtime = runtime_at(1);
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &reset_command(20, Some(&empty_password_session()), &[0xee])
            ),
            error_response(RC_SIZE),
            "upstream unmarshals the parameter area before TPM2_PCR_Reset runs"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn a_missing_authorization_area_is_auth_missing() {
        let mut runtime = runtime_at(2);
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &reset_command(20, None, &[])),
            error_response(TPM_RC_AUTH_MISSING)
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn one_valid_empty_password_session_succeeds() {
        let mut runtime = runtime_at(2);
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_reset(20)),
            session_success_response()
        );
    }

    #[test]
    fn a_non_empty_password_against_an_empty_auth_value_fails() {
        let mut runtime = runtime_at(2);
        let before = snapshot(&runtime);
        let auth = password_session(TPM_RS_PW, &[], 0x00, b"wrong");
        assert_eq!(
            dispatch_bytes(&mut runtime, &reset_command(20, Some(&auth), &[])),
            error_response(RC_SESSION1_BAD_AUTH),
            "every implemented PCR has an empty effective authValue"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn a_password_of_only_trailing_zeros_matches_the_empty_auth_value() {
        let mut runtime = runtime_at(2);
        for password in [&[0x00][..], &[0x00, 0x00][..], &[0x00; 32][..]] {
            let auth = password_session(TPM_RS_PW, &[], 0x00, password);
            assert_eq!(
                dispatch_bytes(&mut runtime, &reset_command(20, Some(&auth), &[])),
                session_success_response(),
                "upstream strips trailing zeros before comparing ({} bytes)",
                password.len()
            );
        }
    }

    #[test]
    fn malformed_authorization_areas_match_the_oracle_codes() {
        let declared_password_size = |size: u16| {
            let mut session = password_session(TPM_RS_PW, &[], 0x00, &[0xaa; 8]);
            session[7..9].copy_from_slice(&size.to_be_bytes());
            session
        };

        for (label, auth, expected) in [
            (
                "authorization_area_below_the_minimum",
                empty_password_session()[..4].to_vec(),
                RC_SIZE,
            ),
            (
                "invalid_handle",
                password_session(0x4000_0008, &[], 0x00, &[]),
                RC_SESSION1_VALUE,
            ),
            (
                "non_empty_nonce",
                password_session(TPM_RS_PW, &[0xaa, 0xbb], 0x00, &[]),
                RC_SESSION1_NONCE,
            ),
            (
                "reserved_attributes",
                password_session(TPM_RS_PW, &[], 0x08, &[]),
                RC_SESSION1_RESERVED,
            ),
            (
                "audit_attribute",
                password_session(TPM_RS_PW, &[], 0x80, &[]),
                RC_SESSION1_ATTRIBUTES,
            ),
            (
                "hmac_session",
                password_session(HMAC_SESSION_FIRST, &[], 0x00, &[]),
                RC_REFERENCE_S0,
            ),
            (
                "policy_session",
                password_session(POLICY_SESSION_FIRST, &[], 0x00, &[]),
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
    fn a_truncated_second_session_is_reported_against_that_session() {
        let mut auth = empty_password_session();
        auth.extend_from_slice(&empty_password_session());
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
    fn extra_password_sessions_have_no_handle_to_authorize() {
        let mut auth = empty_password_session();
        auth.extend_from_slice(&empty_password_session());
        let mut runtime = runtime_at(2);
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &reset_command(20, Some(&auth), &[])),
            error_response(RC_SESSION2_HANDLE)
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn an_invalid_command_handle_is_reported_before_the_session_area() {
        let mut runtime = runtime_at(2);
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &reset_command(
                    IMPLEMENTATION_PCR as u32,
                    Some(&password_session(0x4000_0008, &[], 0x00, &[])),
                    &[]
                )
            ),
            error_response(RC_HANDLE1_VALUE),
            "a malformed session never masks the handle error"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn pcr_reset_consumes_no_runtime_session_slots() {
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
    fn bit_flips_do_not_panic() {
        let valid = authorized_reset(20);
        for index in 6..valid.len() {
            for flip in [0x01u8, 0x80, 0xff] {
                let mut mutated = valid.clone();
                mutated[index] ^= flip;
                let mut runtime = runtime_at(2);
                let input = CommandInput::new(mutated.len() as u32, mutated);
                let parsed = parse_command(&input).expect("the header parses");
                let _ = serialize_response(&dispatch(&mut runtime, &parsed));
            }
        }
    }

    #[test]
    fn every_truncated_prefix_of_a_valid_command_is_rejected_safely() {
        let valid = authorized_reset(20);
        for len in 10..valid.len() {
            let mut runtime = runtime_at(2);
            let before = snapshot(&runtime);
            let mut truncated = valid[..len].to_vec();
            truncated[2..6].copy_from_slice(&(len as u32).to_be_bytes());
            let input = CommandInput::new(truncated.len() as u32, truncated);
            let parsed = parse_command(&input).expect("the header parses");
            let response = serialize_response(&dispatch(&mut runtime, &parsed)).unwrap();
            assert_ne!(&response[6..10], &RC_SUCCESS.to_be_bytes(), "length {len}");
            assert_unchanged(&runtime, &before);
        }
    }
}
