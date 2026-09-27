use super::update::{RC_BUFFER_P1, RC_HANDLE_H2, parse_buffer};
use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_LOCALITY, TPM_RC_MODE};
use crate::library::tpm2::command::core::dispatcher::CommandFrame;
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::command::core::registry::TPM_RH_NULL;
use crate::library::tpm2::command::pcr::extend::{DigestValue, commit_extend, prepare_extend};
use crate::library::tpm2::pcr::{PCR_SLOT_BANKS, pcr_extend_allowed};
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::sequence::{
    SequenceKind, finalize_event, mark_evicted, resolve_sequence_slot, slot_kind,
};
use crate::types::TpmResult;
pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let pcr_handle = frame.handles.first().copied().ok_or(TPM_RC_FAILURE)?;
    let sequence_handle = frame.handles.get(1).copied().ok_or(TPM_RC_FAILURE)?;
    let buffer = parse_buffer(frame.parameters, RC_BUFFER_P1)?;

    let slot = resolve_sequence_slot(runtime, sequence_handle).ok_or(TPM_RC_MODE + RC_HANDLE_H2)?;
    if slot_kind(runtime, slot) != Some(SequenceKind::Event) {
        return Err(TPM_RC_MODE + RC_HANDLE_H2);
    }

    if pcr_handle != TPM_RH_NULL && !pcr_extend_allowed(pcr_handle as usize, runtime.locality) {
        return Err(TPM_RC_LOCALITY);
    }

    let digests = finalize_event(runtime, slot, buffer)?;

    if pcr_handle != TPM_RH_NULL {
        let entries: Vec<DigestValue<'_>> = digests
            .iter()
            .enumerate()
            .map(|(slot, (_, digest))| DigestValue {
                slot,
                digest: digest.as_slice(),
            })
            .collect();
        let prepared = prepare_extend(runtime, pcr_handle as usize, &entries)?;
        commit_extend(runtime, pcr_handle as usize, prepared)?;
    }

    mark_evicted(runtime, slot)?;

    let mut parameters = (PCR_SLOT_BANKS.len() as u32).to_be_bytes().to_vec();
    for (hash_alg, digest) in &digests {
        parameters.extend_from_slice(&hash_alg.to_be_bytes());
        parameters.extend_from_slice(digest);
    }
    Ok(CommandOutput::from_parameters(parameters))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::command::core::registry::TPM_CC_EVENT_SEQUENCE_COMPLETE;
    use crate::library::tpm2::command::core::test_support::{
        assert_scenario_response, for_each_mutation, occupied, prefix_bit_flips,
    };
    use crate::library::tpm2::command::crypto::test_support::max_buffer;

    use crate::library::tpm2::sequence::replay::clock as fresh_clock;
    use crate::library::tpm2::sequence::replay::{self, *};

    const TPM_ALG_SHA256: u16 = 0x000b;

    fn started_event_sequence(clock: &crate::library::tpm2::clock::SteppingClock) -> Tpm2Runtime {
        let mut runtime = base_runtime(clock);
        exec(
            &mut runtime,
            clock,
            "N_START_EVENT",
            hash_sequence_start(&[], replay::TPM_ALG_NULL),
        );
        exec(
            &mut runtime,
            clock,
            "N_EVENT_UPDATE",
            sequence_update(0x8000_0000, b"abc", &[]),
        );
        runtime
    }

    #[test]
    fn pre_startup_rejection() {
        let clock = fresh_clock();
        let mut runtime =
            crate::library::tpm2::restore_permanent_blob_for_test(vector("PERMALL_MANUFACTURED"))
                .expect("the oracle permanent state restores");
        runtime.entropy = unreachable_entropy;
        assert_scenario_response(
            "TPM2_EventSequenceComplete before TPM2_Startup: sequence-commands ESC_BEFORE_STARTUP",
            vector("ESC_BEFORE_STARTUP"),
            || {
                exec_raw(
                    &mut runtime,
                    &clock,
                    event_sequence_complete(10, 0x8000_0000, b""),
                )
            },
        );
    }

    #[test]
    fn completed_event_all_bank_extension() {
        let clock = fresh_clock();
        let mut runtime = started_event_sequence(&clock);
        exec(&mut runtime, &clock, "N_PCR10_BEFORE", pcr_read(10));
        exec(
            &mut runtime,
            &clock,
            "N_EVENT_COMPLETE_PCR10",
            event_sequence_complete(10, 0x8000_0000, b"def"),
        );
        exec(&mut runtime, &clock, "N_PCR10_AFTER", pcr_read(10));
        assert_eq!(
            occupied(&runtime),
            [false, false, false],
            "the completed event sequence releases its handle"
        );
        exec(
            &mut runtime,
            &clock,
            "N_EVENT_COMPLETE_AGAIN",
            event_sequence_complete(10, 0x8000_0000, b"def"),
        );
    }

    #[test]
    fn null_pcr_handle_digests_no_extension() {
        let clock = fresh_clock();
        let mut runtime = started_event_sequence(&clock);
        exec(
            &mut runtime,
            &clock,
            "N_EVENT_COMPLETE_NULL",
            event_sequence_complete(RH_NULL, 0x8000_0000, b"def"),
        );
        exec(&mut runtime, &clock, "N_PCR10_AFTER_NULL", pcr_read(10));
        assert_eq!(occupied(&runtime), [false, false, false]);
    }

    #[test]
    fn tcb_group_pcr_extension_reference_match() {
        let clock = fresh_clock();
        let mut runtime = started_event_sequence(&clock);
        exec(
            &mut runtime,
            &clock,
            "N_EVENT_COMPLETE_PCR16",
            event_sequence_complete(16, 0x8000_0000, b"def"),
        );
        exec(&mut runtime, &clock, "N_PCR16_AFTER", pcr_read(16));
    }

    #[test]
    fn locality_gate_reference_match() {
        let clock = fresh_clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "P_START_EVENT",
            hash_sequence_start(&[], replay::TPM_ALG_NULL),
        );
        exec(
            &mut runtime,
            &clock,
            "P_EVENT_COMPLETE_PCR21_LOCALITY0",
            event_sequence_complete(21, 0x8000_0000, b"def"),
        );
        assert_eq!(
            occupied(&runtime),
            [true, false, false],
            "a locality failure keeps the sequence"
        );
        exec_locality(
            &mut runtime,
            &clock,
            2,
            "P_EVENT_COMPLETE_PCR21_LOCALITY2",
            event_sequence_complete(21, 0x8000_0000, b"def"),
        );
        exec_locality(
            &mut runtime,
            &clock,
            2,
            "P_PCR21_AFTER_LOCALITY2",
            pcr_read(21),
        );
    }

    #[test]
    fn state_saved_pcr_extension_reference_match() {
        let clock = fresh_clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "P_START_EVENT",
            hash_sequence_start(&[], replay::TPM_ALG_NULL),
        );
        exec(
            &mut runtime,
            &clock,
            "P_EVENT_COMPLETE_PCR0",
            event_sequence_complete(0, 0x8000_0000, b"def"),
        );
        exec(&mut runtime, &clock, "P_PCR0_AFTER", pcr_read(0));
    }

    #[test]
    fn invalid_pcr_handle_rejection_sequence_untouched() {
        let clock = fresh_clock();
        let mut runtime = started_event_sequence(&clock);
        exec(
            &mut runtime,
            &clock,
            "N_EVENT_COMPLETE_PCR24",
            event_sequence_complete(24, 0x8000_0000, b"def"),
        );
        exec(
            &mut runtime,
            &clock,
            "N_EVENT_COMPLETE_OWNER_PCR",
            event_sequence_complete(RH_OWNER, 0x8000_0000, b"def"),
        );
        assert_eq!(occupied(&runtime), [true, false, false]);
        exec(
            &mut runtime,
            &clock,
            "N_EVENT_COMPLETE_EMPTY",
            event_sequence_complete(RH_NULL, 0x8000_0000, b""),
        );
    }

    #[test]
    fn buffer_limit_reference_parity() {
        let clock = fresh_clock();
        let mut runtime = started_event_sequence(&clock);
        exec(
            &mut runtime,
            &clock,
            "N_EVENT_COMPLETE_MAX",
            event_sequence_complete(RH_NULL, 0x8000_0000, &max_buffer()),
        );

        let clock = fresh_clock();
        let mut runtime = started_event_sequence(&clock);
        let mut oversized = max_buffer();
        oversized.push(0);
        exec(
            &mut runtime,
            &clock,
            "N_EVENT_COMPLETE_OVERSIZED",
            event_sequence_complete(RH_NULL, 0x8000_0000, &oversized),
        );
        exec(
            &mut runtime,
            &clock,
            "N_EVENT_COMPLETE_TRAILING",
            event_sequence_complete_raw(RH_NULL, 0x8000_0000, &[0x00, 0x02, 0x61, 0x62, 0xee]),
        );
        exec(
            &mut runtime,
            &clock,
            "N_EVENT_COMPLETE_NO_PARAMETERS",
            event_sequence_complete_raw(RH_NULL, 0x8000_0000, &[]),
        );
        assert_eq!(occupied(&runtime), [true, false, false]);
    }

    #[test]
    fn hash_sequence_rejection_second_handle_index() {
        let clock = fresh_clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "O_START_HASH",
            hash_sequence_start(&[], TPM_ALG_SHA256),
        );
        exec(
            &mut runtime,
            &clock,
            "O_EVENT_COMPLETE_ON_HASH",
            event_sequence_complete(RH_NULL, 0x8000_0000, b"def"),
        );
        exec(
            &mut runtime,
            &clock,
            "O_EVENT_COMPLETE_UNLOADED",
            event_sequence_complete(RH_NULL, 0x8000_0002, b"def"),
        );
        exec(
            &mut runtime,
            &clock,
            "O_EVENT_COMPLETE_PERMANENT",
            event_sequence_complete(RH_NULL, RH_OWNER, b"def"),
        );
        assert_eq!(occupied(&runtime), [true, false, false]);
    }

    #[test]
    fn ordinary_object_rejection_second_handle_index() {
        let clock = fresh_clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "U_CREATE_RSA_KEY",
            create_primary(RH_OWNER, &rsa_storage_public(), &[], &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "U_ESC_ON_RSA_KEY",
            event_sequence_complete(RH_NULL, 0x8000_0000, b"abc"),
        );
    }

    #[test]
    fn per_handle_authorization_session_requirement() {
        let clock = fresh_clock();
        let mut runtime = started_event_sequence(&clock);
        let mut payload = RH_NULL.to_be_bytes().to_vec();
        payload.extend_from_slice(&0x8000_0000u32.to_be_bytes());
        payload.extend_from_slice(&[0x00, 0x03, 0x64, 0x65, 0x66]);
        exec(
            &mut runtime,
            &clock,
            "N_EVENT_NO_SESSIONS",
            command(0x8001, TPM_CC_EVENT_SEQUENCE_COMPLETE, &payload),
        );
        let mut payload = RH_NULL.to_be_bytes().to_vec();
        payload.extend_from_slice(&0x8000_0000u32.to_be_bytes());
        payload.extend_from_slice(&auth_area(&[password(&[])]));
        payload.extend_from_slice(&[0x00, 0x03, 0x64, 0x65, 0x66]);
        exec(
            &mut runtime,
            &clock,
            "N_EVENT_ONE_SESSION",
            command(0x8002, TPM_CC_EVENT_SEQUENCE_COMPLETE, &payload),
        );
        assert_eq!(occupied(&runtime), [true, false, false]);
    }

    #[test]
    fn truncated_handle_area_second_handle_index() {
        let clock = fresh_clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "L_ESC_TRUNCATED_HANDLES",
            command(
                0x8002,
                TPM_CC_EVENT_SEQUENCE_COMPLETE,
                &[0x00, 0x00, 0x00, 0x0a, 0x80],
            ),
        );
    }

    #[test]
    fn extra_update_digest_change() {
        let clock = fresh_clock();
        let mut runtime = started_event_sequence(&clock);
        exec(
            &mut runtime,
            &clock,
            "N_EVENT_UPDATE_SECOND",
            sequence_update(0x8000_0000, b"ghi", &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "N_EVENT_COMPLETE_AFTER_UPDATE",
            event_sequence_complete(RH_NULL, 0x8000_0000, b"def"),
        );
    }

    #[test]
    fn disabled_bank_compiled_digest_report() {
        let clock = fresh_clock();
        let mut runtime = minimal_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "X_START_EVENT",
            hash_sequence_start(&[], replay::TPM_ALG_NULL),
        );
        exec(&mut runtime, &clock, "X_PCR10_BEFORE", pcr_read(10));
        exec(
            &mut runtime,
            &clock,
            "X_EVENT_COMPLETE",
            event_sequence_complete(10, 0x8000_0000, b"def"),
        );
        exec(&mut runtime, &clock, "X_PCR10_AFTER", pcr_read(10));
    }

    #[test]
    fn prefix_and_bit_flip_panic_safety() {
        let clock = fresh_clock();
        let mut runtime = started_event_sequence(&clock);
        let valid = event_sequence_complete(10, 0x8000_0000, b"ab");
        for_each_mutation(
            "TPM2_EventSequenceComplete",
            prefix_bit_flips(&valid, 10, 10, true),
            |bytes| {
                let _ = exec_raw(&mut runtime, &clock, bytes);
            },
        );
    }
}
