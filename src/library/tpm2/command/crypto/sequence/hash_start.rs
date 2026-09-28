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

use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_HASH, TPM_RC_INSUFFICIENT, TPM_RC_SIZE};
use crate::library::tpm2::algorithm::{algorithm_enabled, hash_profile_name};
use crate::library::tpm2::command::core::dispatcher::CommandFrame;
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::crypto::COMPILED_HASHES;
use crate::library::tpm2::marshal::{BlobReader, Tpm2bError};
use crate::library::tpm2::public::{DIGEST_SIZE, TPM_ALG_NULL};
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::self_test::self_test_algorithm;
use crate::library::tpm2::sequence::{
    SequenceKind, allocate_sequence_slot, init_event_sequence, init_hash_sequence,
};
use crate::types::TpmResult;

const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;
const TPM_RC_2: TpmResult = 0x200;
const RC_AUTH: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_HASH_ALG: TpmResult = TPM_RC_P + TPM_RC_2;

struct HashSequenceStartIn<'a> {
    auth: &'a [u8],
    hash_alg: u16,
}

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let input = {
        let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
        parse_parameters(&state.profile.algorithms, frame.parameters)?
    };

    let handle = if input.hash_alg == TPM_ALG_NULL {
        let allocated = allocate_sequence_slot(runtime, SequenceKind::Event, input.auth)?;
        for &(hash_alg, _) in &COMPILED_HASHES {
            self_test_algorithm(runtime, hash_alg)?;
        }
        init_event_sequence(runtime, allocated.slot)?;
        allocated.handle
    } else {
        let allocated = allocate_sequence_slot(runtime, SequenceKind::Hash, input.auth)?;
        self_test_algorithm(runtime, input.hash_alg)?;
        init_hash_sequence(runtime, allocated.slot, input.hash_alg)?;
        allocated.handle
    };

    Ok(CommandOutput::with_handle(handle, Vec::new()))
}

pub(super) fn parse_hash_algorithm(
    profile_algorithms: &[u8],
    reader: &mut BlobReader<'_>,
    error_index: TpmResult,
) -> Result<u16, TpmResult> {
    let hash_alg = reader
        .read_u16()
        .map_err(|_| TPM_RC_INSUFFICIENT + error_index)?;
    if hash_alg == TPM_ALG_NULL {
        return Ok(hash_alg);
    }
    let enabled = COMPILED_HASHES.iter().any(|&(alg, _)| alg == hash_alg)
        && hash_profile_name(hash_alg)
            .is_some_and(|name| algorithm_enabled(profile_algorithms, name));
    if !enabled {
        return Err(TPM_RC_HASH + error_index);
    }
    Ok(hash_alg)
}

pub(super) fn parse_auth<'a>(
    reader: &mut BlobReader<'a>,
    error_index: TpmResult,
) -> Result<&'a [u8], TpmResult> {
    reader.read_tpm2b(DIGEST_SIZE).map_err(|error| match error {
        Tpm2bError::Truncated => TPM_RC_INSUFFICIENT + error_index,
        Tpm2bError::SizeExceeded { .. } => TPM_RC_SIZE + error_index,
    })
}

fn parse_parameters<'a>(
    profile_algorithms: &[u8],
    parameters: &'a [u8],
) -> Result<HashSequenceStartIn<'a>, TpmResult> {
    let mut reader = BlobReader::new(parameters);
    let auth = parse_auth(&mut reader, RC_AUTH)?;
    let hash_alg = parse_hash_algorithm(profile_algorithms, &mut reader, RC_HASH_ALG)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(HashSequenceStartIn { auth, hash_alg })
}

#[cfg(test)]
mod tests {

    use crate::library::tpm2::command::core::test_support::{
        assert_scenario_response, for_each_mutation, prefix_bit_flips,
    };
    use crate::library::tpm2::object::{ATTR_EVENT_SEQ, ATTR_HASH_SEQ, ATTR_OCCUPIED};
    use crate::library::tpm2::sequence::replay::{self, *};

    const TPM_ALG_SHA1: u16 = 0x0004;
    const TPM_ALG_SHA256: u16 = 0x000b;
    const TPM_ALG_SHA384: u16 = 0x000c;
    const TPM_ALG_SHA512: u16 = 0x000d;

    const ALL_ALGORITHMS: [(&str, u16); 4] = [
        ("SHA1", TPM_ALG_SHA1),
        ("SHA256", TPM_ALG_SHA256),
        ("SHA384", TPM_ALG_SHA384),
        ("SHA512", TPM_ALG_SHA512),
    ];

    #[test]
    fn pre_startup_rejection() {
        let clock = clock();
        let mut runtime =
            crate::library::tpm2::restore_permanent_blob_for_test(vector("PERMALL_MANUFACTURED"))
                .expect("the oracle permanent state restores");
        runtime.entropy = unreachable_entropy;
        assert_scenario_response(
            "TPM2_HashSequenceStart before TPM2_Startup: sequence-commands HSS_BEFORE_STARTUP",
            vector("HSS_BEFORE_STARTUP"),
            || {
                exec_raw(
                    &mut runtime,
                    &clock,
                    hash_sequence_start(&[], TPM_ALG_SHA256),
                )
            },
        );
    }

    #[test]
    fn sequence_first_free_slot_allocation() {
        let clock = clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "A_START_SHA256",
            hash_sequence_start(&[], TPM_ALG_SHA256),
        );
        assert_ne!(runtime.live.objects[0].attributes & ATTR_OCCUPIED, 0);
        assert_ne!(runtime.live.objects[0].attributes & ATTR_HASH_SEQ, 0);
        assert_eq!(runtime.live.objects[1].attributes & ATTR_OCCUPIED, 0);
    }

    #[test]
    fn per_compiled_algorithm_sequence_start_and_completion() {
        let clock = clock();
        let mut runtime = base_runtime(&clock);
        for (label, hash_alg) in ALL_ALGORITHMS {
            exec(
                &mut runtime,
                &clock,
                &format!("B_START_{label}"),
                hash_sequence_start(&[], hash_alg),
            );
            exec(
                &mut runtime,
                &clock,
                &format!("B_UPDATE_{label}"),
                sequence_update(0x8000_0000, MESSAGE, &[]),
            );
            exec(
                &mut runtime,
                &clock,
                &format!("B_COMPLETE_{label}"),
                sequence_complete(0x8000_0000, b" tail", RH_OWNER, &[]),
            );
        }
    }

    #[test]
    fn null_algorithm_event_sequence() {
        let clock = clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "N_START_EVENT",
            hash_sequence_start(&[], replay::TPM_ALG_NULL),
        );
        assert_ne!(runtime.live.objects[0].attributes & ATTR_EVENT_SEQ, 0);
        assert_eq!(runtime.live.objects[0].attributes & ATTR_HASH_SEQ, 0);
    }

    #[test]
    fn unsupported_algorithm_indexed_hash_error() {
        let clock = clock();
        let mut runtime = base_runtime(&clock);
        for (label, hash_alg) in [
            ("SM3", 0x0012u16),
            ("AES", 0x0006),
            ("ZERO", 0x0000),
            ("FFFF", 0xffff),
            ("HMAC", 0x0005),
        ] {
            exec(
                &mut runtime,
                &clock,
                &format!("J_START_ALG_{label}"),
                hash_sequence_start(&[], hash_alg),
            );
        }
        assert!(
            runtime
                .live
                .objects
                .iter()
                .all(|object| object.attributes & ATTR_OCCUPIED == 0),
            "a rejected algorithm leaves every slot free"
        );
    }

    #[test]
    fn profile_disabled_algorithm_indexed_hash_error() {
        let clock = clock();
        let mut runtime = minimal_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "X_START_SHA1_DISABLED",
            hash_sequence_start(&[], TPM_ALG_SHA1),
        );
        exec(
            &mut runtime,
            &clock,
            "X_START_SHA512_DISABLED",
            hash_sequence_start(&[], TPM_ALG_SHA512),
        );
        exec(
            &mut runtime,
            &clock,
            "X_START_SHA256",
            hash_sequence_start(&[], TPM_ALG_SHA256),
        );
    }

    #[test]
    fn auth_value_digest_size_bound() {
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
            "I_START_AUTH_64",
            hash_sequence_start(&[b'a'; 64], TPM_ALG_SHA256),
        );
        exec(
            &mut runtime,
            &clock,
            "I_START_AUTH_65",
            hash_sequence_start(&[b'a'; 65], TPM_ALG_SHA256),
        );
    }

    #[test]
    fn malformed_parameter_indexed_parse_errors() {
        let clock = clock();
        let mut runtime = base_runtime(&clock);
        for (label, params) in [
            ("K_HSS_NO_PARAMETERS", vec![]),
            ("K_HSS_TRUNCATED_AUTH_SIZE", vec![0x00]),
            ("K_HSS_TRUNCATED_AUTH_BODY", vec![0x00, 0x03, 0x61, 0x62]),
            ("K_HSS_AUTH_SIZE_FFFF", vec![0xff, 0xff]),
            ("K_HSS_TRUNCATED_ALG", vec![0x00, 0x00, 0x00]),
            ("K_HSS_TRAILING", vec![0x00, 0x00, 0x00, 0x0b, 0xee]),
        ] {
            exec(
                &mut runtime,
                &clock,
                label,
                hash_sequence_start_raw(&params),
            );
        }
    }

    #[test]
    fn exhausted_object_slots_object_memory_error() {
        let clock = clock();
        let mut runtime = base_runtime(&clock);
        for (label, hash_alg) in [
            ("M_START_1", TPM_ALG_SHA1),
            ("M_START_2", TPM_ALG_SHA256),
            ("M_START_3", TPM_ALG_SHA384),
            ("M_START_4", TPM_ALG_SHA512),
        ] {
            exec(
                &mut runtime,
                &clock,
                label,
                hash_sequence_start(&[], hash_alg),
            );
        }
        assert!(
            runtime
                .live
                .objects
                .iter()
                .all(|object| object.attributes & ATTR_OCCUPIED != 0),
            "every slot stays occupied after the refused start"
        );
    }

    #[test]
    fn flushed_slot_reuse() {
        let clock = clock();
        let mut runtime = base_runtime(&clock);
        for (label, hash_alg) in [
            ("M_START_1", TPM_ALG_SHA1),
            ("M_START_2", TPM_ALG_SHA256),
            ("M_START_3", TPM_ALG_SHA384),
            ("M_START_4", TPM_ALG_SHA512),
        ] {
            exec(
                &mut runtime,
                &clock,
                label,
                hash_sequence_start(&[], hash_alg),
            );
        }
        exec(
            &mut runtime,
            &clock,
            "M_FLUSH_FIRST",
            flush_context(0x8000_0000),
        );
        exec(
            &mut runtime,
            &clock,
            "M_UPDATE_FLUSHED",
            sequence_update(0x8000_0000, b"abc", &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "M_START_AFTER_FLUSH",
            hash_sequence_start(&[], TPM_ALG_SHA512),
        );
        exec(
            &mut runtime,
            &clock,
            "M_COMPLETE_SECOND",
            sequence_complete(0x8000_0001, b"abc", RH_NULL, &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "M_START_AFTER_COMPLETE",
            hash_sequence_start(&[], TPM_ALG_SHA1),
        );
    }

    #[test]
    fn prefix_and_bit_flip_panic_safety() {
        let clock = clock();
        let mut runtime = base_runtime(&clock);
        let valid = hash_sequence_start(b"a", TPM_ALG_SHA256);
        for_each_mutation(
            "TPM2_HashSequenceStart",
            prefix_bit_flips(&valid, 10, 10, true),
            |bytes| {
                let _ = exec_raw(&mut runtime, &clock, bytes);
            },
        );
    }
}
