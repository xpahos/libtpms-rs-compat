// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/HashCommands.c
// - libtpms/src/tpm2/Object.c
//
// Original upstream authors and copyright notices:
// Written by Ken Goldman
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corp. and others, 2016 - 2021
// (c) Copyright IBM Corp. and others, 2016 - 2023
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_INSUFFICIENT, TPM_RC_MODE, TPM_RC_SIZE};
use crate::library::tpm2::command::core::dispatcher::CommandFrame;
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::marshal::{BlobReader, Tpm2bError};
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::sequence::{
    SequenceKind, first_block_seen, mark_first_block, resolve_sequence_slot, slot_kind,
    update_sequence,
};
use crate::library::tpm2::ticket::ticket_is_safe;
use crate::types::TpmResult;

const TPM_RC_H: TpmResult = 0x000;
const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;
const TPM_RC_2: TpmResult = 0x200;
const RC_SEQUENCE_HANDLE: TpmResult = TPM_RC_P + TPM_RC_1;

pub(super) const MAX_DIGEST_BUFFER: usize = 1024;
pub(super) const RC_BUFFER_P1: TpmResult = TPM_RC_P + TPM_RC_1;
pub(super) const RC_HANDLE_H1: TpmResult = TPM_RC_H + TPM_RC_1;
pub(super) const RC_HANDLE_H2: TpmResult = TPM_RC_H + TPM_RC_2;

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let sequence_handle = frame.handles.first().copied().ok_or(TPM_RC_FAILURE)?;
    let buffer = parse_buffer(frame.parameters, RC_BUFFER_P1)?;

    let slot =
        resolve_sequence_slot(runtime, sequence_handle).ok_or(TPM_RC_MODE + RC_SEQUENCE_HANDLE)?;
    let kind = slot_kind(runtime, slot).ok_or(TPM_RC_FAILURE)?;

    let first_block = kind == SequenceKind::Hash && !first_block_seen(runtime, slot)?;
    update_sequence(runtime, slot, buffer)?;
    if first_block {
        mark_first_block(runtime, slot, ticket_is_safe(buffer))?;
    }

    Ok(CommandOutput::empty())
}

pub(super) fn parse_buffer(parameters: &[u8], error_index: TpmResult) -> Result<&[u8], TpmResult> {
    let mut reader = BlobReader::new(parameters);
    let buffer = read_max_buffer(&mut reader, error_index)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(buffer)
}

pub(super) fn read_max_buffer<'a>(
    reader: &mut BlobReader<'a>,
    error_index: TpmResult,
) -> Result<&'a [u8], TpmResult> {
    reader
        .read_tpm2b(MAX_DIGEST_BUFFER)
        .map_err(|error| match error {
            Tpm2bError::Truncated => TPM_RC_INSUFFICIENT + error_index,
            Tpm2bError::SizeExceeded { .. } => TPM_RC_SIZE + error_index,
        })
}

#[cfg(test)]
mod tests {
    use crate::library::tpm2::command::core::registry::TPM_CC_SEQUENCE_UPDATE;
    use crate::library::tpm2::command::core::test_support::{
        assert_scenario_response, for_each_mutation, prefix_bit_flips,
    };
    use crate::library::tpm2::object::{ATTR_HASH_SEQ, ATTR_OCCUPIED};
    use crate::library::tpm2::sequence::replay::{self, *};

    const TPM_ALG_SHA256: u16 = 0x000b;

    const MAX_BUFFER: [u8; 1024] = {
        let mut out = [0u8; 1024];
        let mut index = 0;
        while index < 1024 {
            out[index] = (index % 256) as u8;
            index += 1;
        }
        out
    };

    #[test]
    fn pre_startup_rejection() {
        let clock = clock();
        let mut runtime =
            crate::library::tpm2::restore_permanent_blob_for_test(vector("PERMALL_MANUFACTURED"))
                .expect("the oracle permanent state restores");
        runtime.entropy = unreachable_entropy;
        assert_scenario_response(
            "TPM2_SequenceUpdate before TPM2_Startup: sequence-commands SU_BEFORE_STARTUP",
            vector("SU_BEFORE_STARTUP"),
            || {
                exec_raw(
                    &mut runtime,
                    &clock,
                    sequence_update(0x8000_0000, b"abc", &[]),
                )
            },
        );
    }

    #[test]
    fn repeated_update_concatenated_input_hashing() {
        let clock = clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "A_START_SHA256",
            hash_sequence_start(&[], TPM_ALG_SHA256),
        );
        exec(
            &mut runtime,
            &clock,
            "A_UPDATE_ABC",
            sequence_update(0x8000_0000, b"abc", &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "A_UPDATE_EMPTY",
            sequence_update(0x8000_0000, b"", &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "A_UPDATE_DEF",
            sequence_update(0x8000_0000, b"def", &[]),
        );
        assert_ne!(runtime.live.objects[0].attributes & ATTR_HASH_SEQ, 0);
        exec(
            &mut runtime,
            &clock,
            "A_COMPLETE_GHI",
            sequence_complete(0x8000_0000, b"ghi", RH_NULL, &[]),
        );
    }

    #[test]
    fn completed_sequence_update_rejection() {
        let clock = clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "A_START_SHA256",
            hash_sequence_start(&[], TPM_ALG_SHA256),
        );
        exec(
            &mut runtime,
            &clock,
            "A_UPDATE_ABC",
            sequence_update(0x8000_0000, b"abc", &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "A_UPDATE_EMPTY",
            sequence_update(0x8000_0000, b"", &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "A_UPDATE_DEF",
            sequence_update(0x8000_0000, b"def", &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "A_COMPLETE_GHI",
            sequence_complete(0x8000_0000, b"ghi", RH_NULL, &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "A_COMPLETE_AGAIN",
            sequence_complete(0x8000_0000, b"", RH_NULL, &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "A_UPDATE_AFTER_COMPLETE",
            sequence_update(0x8000_0000, b"x", &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "A_REUSED_START",
            hash_sequence_start(&[], TPM_ALG_SHA256),
        );
    }

    #[test]
    fn event_sequence_update_acceptance() {
        let clock = clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "N_START_EVENT",
            hash_sequence_start(&[], replay::TPM_ALG_NULL),
        );
        exec(
            &mut runtime,
            &clock,
            "N_EVENT_UPDATE",
            sequence_update(0x8000_0000, b"abc", &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "N_EVENT_COMPLETE_NULL",
            event_sequence_complete(RH_NULL, 0x8000_0000, b"def"),
        );
    }

    #[test]
    fn malformed_parameter_and_handle_indexed_errors() {
        let clock = clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "L_START",
            hash_sequence_start(&[], TPM_ALG_SHA256),
        );
        for (label, params) in [
            ("L_SU_NO_PARAMETERS", vec![]),
            ("L_SU_TRUNCATED_SIZE", vec![0x00]),
            ("L_SU_TRUNCATED_BODY", vec![0x00, 0x03, 0x61, 0x62]),
            ("L_SU_SIZE_FFFF", vec![0xff, 0xff]),
            ("L_SU_TRAILING", vec![0x00, 0x02, 0x61, 0x62, 0xee]),
        ] {
            exec(
                &mut runtime,
                &clock,
                label,
                sequence_update_raw(0x8000_0000, &params, &[]),
            );
        }
        let mut oversized = MAX_BUFFER.to_vec();
        oversized.push(0);
        exec(
            &mut runtime,
            &clock,
            "L_SU_OVERSIZED",
            sequence_update(0x8000_0000, &oversized, &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "L_SU_MAX",
            sequence_update(0x8000_0000, &MAX_BUFFER, &[]),
        );
        assert_ne!(
            runtime.live.objects[0].attributes & ATTR_OCCUPIED,
            0,
            "an invalid update preserves the sequence object"
        );
    }

    #[test]
    fn wrong_handle_kind_reference_errors() {
        let clock = clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "L_START",
            hash_sequence_start(&[], TPM_ALG_SHA256),
        );
        exec(
            &mut runtime,
            &clock,
            "L_SU_PERMANENT_HANDLE",
            sequence_update(RH_OWNER, b"abc", &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "L_SU_UNLOADED_HANDLE",
            sequence_update(0x8000_0002, b"abc", &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "L_SU_UNDEFINED_PERSISTENT",
            sequence_update(0x8100_0099, b"abc", &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "L_SU_TRUNCATED_HANDLE",
            command(0x8002, TPM_CC_SEQUENCE_UPDATE, &[0x80, 0x00, 0x00]),
        );
    }

    #[test]
    fn ordinary_object_non_sequence_rejection() {
        let clock = clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "U_CREATE_RSA_KEY",
            create_primary(
                RH_OWNER,
                &crate::library::tpm2::sequence::replay::rsa_storage_public(),
                &[],
                &[],
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "U_SU_ON_RSA_KEY",
            sequence_update(0x8000_0000, b"abc", &[]),
        );
    }

    #[test]
    fn sequence_authorization_enforcement() {
        let clock = clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "H_START_AUTH",
            hash_sequence_start(b"sequence-auth", TPM_ALG_SHA256),
        );
        exec(
            &mut runtime,
            &clock,
            "H_UPDATE_WRONG_AUTH",
            sequence_update(0x8000_0000, b"abc", b"wrong"),
        );
        exec(
            &mut runtime,
            &clock,
            "H_UPDATE_EMPTY_AUTH",
            sequence_update(0x8000_0000, b"abc", &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "H_UPDATE_GOOD_AUTH",
            sequence_update(0x8000_0000, b"abc", b"sequence-auth"),
        );
        exec(
            &mut runtime,
            &clock,
            "H_UPDATE_NO_SESSION",
            command(0x8001, TPM_CC_SEQUENCE_UPDATE, &{
                let mut out = 0x8000_0000u32.to_be_bytes().to_vec();
                out.extend_from_slice(&[0x00, 0x03, 0x61, 0x62, 0x63]);
                out
            }),
        );
    }

    #[test]
    fn prefix_and_bit_flip_panic_safety() {
        let clock = clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "L_START",
            hash_sequence_start(&[], TPM_ALG_SHA256),
        );
        let valid = sequence_update(0x8000_0000, b"ab", &[]);
        for_each_mutation(
            "TPM2_SequenceUpdate",
            prefix_bit_flips(&valid, 10, 10, true),
            |bytes| {
                let _ = exec_raw(&mut runtime, &clock, bytes);
            },
        );
    }
}
