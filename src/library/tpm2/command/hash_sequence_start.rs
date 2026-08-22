use crate::ffi_types::TpmResult;
use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_HASH, TPM_RC_INSUFFICIENT, TPM_RC_SIZE};

use super::super::algorithm::{algorithm_enabled, hash_profile_name};
use super::super::crypto::COMPILED_HASHES;
use super::super::marshal::{BlobReader, Tpm2bError};
use super::super::public::{DIGEST_SIZE, TPM_ALG_NULL};
use super::super::runtime::Tpm2Runtime;
use super::super::self_test::self_test_algorithm;
use super::super::sequence::{
    SequenceKind, allocate_sequence_slot, init_event_sequence, init_hash_sequence,
};
use super::dispatcher::CommandFrame;
use super::output::CommandOutput;

const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;
const TPM_RC_2: TpmResult = 0x200;
const RC_AUTH: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_HASH_ALG: TpmResult = TPM_RC_P + TPM_RC_2;

struct HashSequenceStartIn<'a> {
    auth: &'a [u8],
    hash_alg: u16,
}

pub(super) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let input = {
        // TODO: Support runtimes without decoded state after the NVChip fallback
        // is implemented.
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
    use super::super::registry::{self, HandleKind, TPM_CC_HASH_SEQUENCE_START};
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
    fn the_command_is_registered_with_the_upstream_attributes() {
        assert_eq!(TPM_CC_HASH_SEQUENCE_START, 0x0000_0186);
        let descriptor = registry::find(TPM_CC_HASH_SEQUENCE_START).expect("registered");
        assert_eq!(descriptor.attributes, 0x1000_0186);
        assert!(!descriptor.physical_presence);
        assert!(descriptor.sessions_allowed);
        assert_ne!(descriptor.attributes & (1 << 28), 0, "a response handle");
        assert_eq!(descriptor.attributes & (1 << 22), 0, "no NVRAM update");
        assert_eq!(descriptor.attributes & (1 << 23), 0, "not extensive");
        assert_eq!(descriptor.attributes & (1 << 24), 0, "no flushed handle");
        assert_eq!((descriptor.attributes >> 25) & 0x7, 0, "no command handle");
        assert!(descriptor.handles.is_empty());
    }

    #[test]
    fn the_capability_report_matches_the_oracle() {
        let clock = clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "CAP_CC_HASH_SEQUENCE_START",
            command(0x8001, 0x0000_017a, &{
                let mut out = 2u32.to_be_bytes().to_vec();
                out.extend_from_slice(&0x0186u32.to_be_bytes());
                out.extend_from_slice(&1u32.to_be_bytes());
                out
            }),
        );
    }

    #[test]
    fn the_command_is_rejected_before_startup() {
        let clock = clock();
        let mut runtime =
            crate::library::tpm2::restore_permanent_blob_for_test(vector("PERMALL_MANUFACTURED"))
                .expect("the oracle permanent state restores");
        runtime.entropy = unreachable_entropy;
        exec(
            &mut runtime,
            &clock,
            "HSS_BEFORE_STARTUP",
            hash_sequence_start(&[], TPM_ALG_SHA256),
        );
    }

    #[test]
    fn a_started_sequence_takes_the_first_free_transient_slot() {
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
    fn every_compiled_algorithm_starts_and_completes_a_sequence() {
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
    fn a_null_algorithm_starts_an_event_sequence() {
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
    fn unsupported_algorithms_report_the_indexed_hash_error() {
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
    fn profile_disabled_algorithms_report_the_indexed_hash_error() {
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
    fn the_authorization_value_size_is_bounded_by_the_digest_size() {
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
    fn malformed_parameters_report_the_indexed_parse_errors() {
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
    fn exhausted_object_slots_report_object_memory() {
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
    fn a_flushed_slot_is_reused_by_the_next_start() {
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
    fn a_malformed_command_never_panics() {
        let clock = clock();
        let mut runtime = base_runtime(&clock);
        let valid = hash_sequence_start(b"a", TPM_ALG_SHA256);
        for length in 10..=valid.len() {
            for index in 10..length {
                for flip in [0x01u8, 0x80, 0xff] {
                    let mut mutated = valid[..length].to_vec();
                    mutated[index] ^= flip;
                    let size = (mutated.len() as u32).to_be_bytes();
                    mutated[2..6].copy_from_slice(&size);
                    let _ = exec_raw(&mut runtime, &clock, mutated);
                }
            }
        }
    }

    #[test]
    fn the_registry_descriptor_accepts_no_handles() {
        let descriptor = registry::find(TPM_CC_HASH_SEQUENCE_START).expect("registered");
        assert!(descriptor.handles.is_empty());
        assert!(matches!(
            registry::find(super::super::registry::TPM_CC_SEQUENCE_UPDATE)
                .expect("registered")
                .handles[0]
                .kind,
            HandleKind::Object
        ));
    }
}
