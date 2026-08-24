use crate::ffi_types::TpmResult;
use crate::library::constants::{
    TPM_RC_FAILURE, TPM_RC_INSUFFICIENT, TPM_RC_MODE, TPM_RC_SIZE, TPM_RC_VALUE,
};

use super::super::hierarchy::{TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM, hierarchy_proof};
use super::super::marshal::{BlobReader, BlobWriter};
use super::super::runtime::Tpm2Runtime;
use super::super::self_test::self_test_algorithm;
use super::super::sequence::{
    SequenceKind, finalize_hash, finalize_hmac, first_block_seen, mark_evicted,
    resolve_sequence_slot, sequence_hash_alg, slot_kind, ticket_safe,
};
use super::super::ticket::{
    CONTEXT_INTEGRITY_HASH_ALG, TPM_ST_HASHCHECK, Ticket, compute_hash_check, ticket_is_safe,
};
use super::dispatcher::CommandFrame;
use super::output::CommandOutput;
use super::registry::TPM_RH_NULL;
use super::sequence_update::{RC_BUFFER_P1, RC_HANDLE_H1, read_max_buffer};

const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_2: TpmResult = 0x200;
const RC_HIERARCHY: TpmResult = TPM_RC_P + TPM_RC_2;

struct SequenceCompleteIn<'a> {
    buffer: &'a [u8],
    hierarchy: u32,
}

pub(super) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let sequence_handle = frame.handles.first().copied().ok_or(TPM_RC_FAILURE)?;
    let input = parse_parameters(frame.parameters)?;

    let slot = resolve_sequence_slot(runtime, sequence_handle).ok_or(TPM_RC_MODE + RC_HANDLE_H1)?;
    let kind = slot_kind(runtime, slot).ok_or(TPM_RC_FAILURE)?;
    if kind == SequenceKind::Event {
        return Err(TPM_RC_MODE + RC_HANDLE_H1);
    }

    let hash_alg = sequence_hash_alg(runtime, slot)?;

    let (result, validation) = match kind {
        SequenceKind::Hash => {
            let digest = finalize_hash(runtime, slot, input.buffer)?;
            let safe = if first_block_seen(runtime, slot)? {
                ticket_safe(runtime, slot)?
            } else {
                ticket_is_safe(input.buffer)
            };
            let validation = hash_check(runtime, input.hierarchy, hash_alg, &digest, safe)?;
            (digest, validation)
        }
        _ => {
            let mac = finalize_hmac(runtime, slot, input.buffer)?;
            self_test_algorithm(runtime, hash_alg)?;
            (mac, Ticket::empty(TPM_ST_HASHCHECK))
        }
    };

    mark_evicted(runtime, slot)?;

    let mut writer = BlobWriter::with_capacity(2 + result.len() + 8 + validation.digest.len());
    writer.write_tpm2b(&result).map_err(|_| TPM_RC_FAILURE)?;
    validation
        .marshal(&mut writer)
        .map_err(|_| TPM_RC_FAILURE)?;
    Ok(CommandOutput::from_parameters(writer.into_bytes()))
}

fn hash_check(
    runtime: &mut Tpm2Runtime,
    hierarchy: u32,
    hash_alg: u16,
    digest: &[u8],
    safe: bool,
) -> Result<Ticket, TpmResult> {
    if hierarchy == TPM_RH_NULL || !safe {
        return Ok(Ticket::empty(TPM_ST_HASHCHECK));
    }
    self_test_algorithm(runtime, CONTEXT_INTEGRITY_HASH_ALG)?;
    let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
    let proof = hierarchy_proof(&state.persistent, hierarchy).ok_or(TPM_RC_FAILURE)?;
    compute_hash_check(hierarchy, proof, hash_alg, digest).ok_or(TPM_RC_FAILURE)
}

fn parse_parameters(parameters: &[u8]) -> Result<SequenceCompleteIn<'_>, TpmResult> {
    let mut reader = BlobReader::new(parameters);
    let buffer = read_max_buffer(&mut reader, RC_BUFFER_P1)?;
    let hierarchy = reader
        .read_u32()
        .map_err(|_| TPM_RC_INSUFFICIENT + RC_HIERARCHY)?;
    if !matches!(
        hierarchy,
        TPM_RH_OWNER | TPM_RH_PLATFORM | TPM_RH_ENDORSEMENT | TPM_RH_NULL
    ) {
        return Err(TPM_RC_VALUE + RC_HIERARCHY);
    }
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(SequenceCompleteIn { buffer, hierarchy })
}

#[cfg(test)]
mod tests {
    use super::super::registry::{self, HandleKind, TPM_CC_SEQUENCE_COMPLETE};
    use super::*;
    use crate::library::tpm2::object::ATTR_OCCUPIED;
    use crate::library::tpm2::sequence::replay::{self, *};

    use crate::library::tpm2::sequence::replay::clock as fresh_clock;

    const TPM_ALG_SHA1: u16 = 0x0004;
    const TPM_ALG_SHA256: u16 = 0x000b;
    const TPM_ALG_SHA384: u16 = 0x000c;
    const TPM_ALG_SHA512: u16 = 0x000d;

    const GENERATED: &[u8] = b"\xff\x54\x43\x47generated value payload";
    const ALMOST_GENERATED: &[u8] = b"\xff\x54\x43\x48nearly generated";

    fn max_buffer() -> Vec<u8> {
        (0..1024).map(|index| (index % 256) as u8).collect()
    }

    fn occupied(runtime: &Tpm2Runtime) -> Vec<bool> {
        runtime
            .live
            .objects
            .iter()
            .map(|object| object.attributes & ATTR_OCCUPIED != 0)
            .collect()
    }

    #[test]
    fn the_command_is_registered_with_the_upstream_attributes() {
        assert_eq!(TPM_CC_SEQUENCE_COMPLETE, 0x0000_013e);
        let descriptor = registry::find(TPM_CC_SEQUENCE_COMPLETE).expect("registered");
        assert_eq!(descriptor.attributes, 0x0300_013e);
        assert!(!descriptor.physical_presence);
        assert!(descriptor.sessions_allowed);
        assert_eq!(descriptor.attributes & (1 << 28), 0, "no response handle");
        assert_eq!(descriptor.attributes & (1 << 22), 0, "no NVRAM update");
        assert_eq!(descriptor.attributes & (1 << 23), 0, "not extensive");
        assert_ne!(descriptor.attributes & (1 << 24), 0, "flushes its handle");
        assert_eq!((descriptor.attributes >> 25) & 0x7, 1, "one command handle");
        assert_eq!(descriptor.handles.len(), 1);
        assert!(descriptor.handles[0].user_auth);
        assert!(!descriptor.handles[0].admin_role());
        assert!(matches!(descriptor.handles[0].kind, HandleKind::Object));
    }

    #[test]
    fn the_capability_report_matches_the_oracle() {
        let clock = fresh_clock();
        let mut runtime = base_runtime(&clock);
        let mut params = 2u32.to_be_bytes().to_vec();
        params.extend_from_slice(&0x013eu32.to_be_bytes());
        params.extend_from_slice(&1u32.to_be_bytes());
        exec(
            &mut runtime,
            &clock,
            "CAP_CC_SEQUENCE_COMPLETE",
            command(0x8001, 0x0000_017a, &params),
        );
    }

    #[test]
    fn the_command_is_rejected_before_startup() {
        let clock = fresh_clock();
        let mut runtime =
            crate::library::tpm2::restore_permanent_blob_for_test(vector("PERMALL_MANUFACTURED"))
                .expect("the oracle permanent state restores");
        runtime.entropy = unreachable_entropy;
        exec(
            &mut runtime,
            &clock,
            "SC_BEFORE_STARTUP",
            sequence_complete(0x8000_0000, b"", RH_NULL, &[]),
        );
    }

    #[test]
    fn an_untouched_sequence_completes_to_the_empty_digest() {
        let clock = fresh_clock();
        let mut runtime = base_runtime(&clock);
        for (label, hash_alg) in [
            ("SHA1", TPM_ALG_SHA1),
            ("SHA256", TPM_ALG_SHA256),
            ("SHA384", TPM_ALG_SHA384),
            ("SHA512", TPM_ALG_SHA512),
        ] {
            exec(
                &mut runtime,
                &clock,
                &format!("C_START_{label}"),
                hash_sequence_start(&[], hash_alg),
            );
            exec(
                &mut runtime,
                &clock,
                &format!("C_COMPLETE_EMPTY_{label}"),
                sequence_complete(0x8000_0000, b"", RH_NULL, &[]),
            );
        }
    }

    #[test]
    fn every_hierarchy_produces_its_own_ticket() {
        let seed_clock = fresh_clock();
        let mut seed = base_runtime(&seed_clock);
        exec(
            &mut seed,
            &seed_clock,
            "D_START",
            hash_sequence_start(&[], TPM_ALG_SHA256),
        );
        let (permanent, volatile) = state_blobs(&seed, &seed_clock);
        drop(seed);
        let clock = fresh_clock();
        for (label, hierarchy) in [
            ("D_COMPLETE_OWNER", RH_OWNER),
            ("D_COMPLETE_PLATFORM", RH_PLATFORM),
            ("D_COMPLETE_ENDORSEMENT", RH_ENDORSEMENT),
            ("D_COMPLETE_NULL", RH_NULL),
        ] {
            let mut runtime = reload(&permanent, &volatile, &clock);
            exec(
                &mut runtime,
                &clock,
                label,
                sequence_complete(0x8000_0000, MESSAGE, hierarchy, &[]),
            );
            assert_eq!(
                occupied(&runtime),
                [false, false, false],
                "{label} releases the sequence handle"
            );
        }
    }

    #[test]
    fn ticket_generation_follows_the_reference_safety_rule() {
        let seed_clock = fresh_clock();
        let mut seed = base_runtime(&seed_clock);
        exec(
            &mut seed,
            &seed_clock,
            "D_START",
            hash_sequence_start(&[], TPM_ALG_SHA256),
        );
        let (permanent, volatile) = state_blobs(&seed, &seed_clock);
        drop(seed);
        let clock = fresh_clock();
        for (label, buffer) in [
            ("D_COMPLETE_GENERATED", GENERATED.to_vec()),
            ("D_COMPLETE_ALMOST_GENERATED", ALMOST_GENERATED.to_vec()),
            ("D_COMPLETE_EMPTY_OWNER", Vec::new()),
            ("D_COMPLETE_SHORT_OWNER", vec![0xff, 0x54, 0x43]),
            ("D_COMPLETE_MAX_OWNER", max_buffer()),
        ] {
            let mut runtime = reload(&permanent, &volatile, &clock);
            exec(
                &mut runtime,
                &clock,
                label,
                sequence_complete(0x8000_0000, &buffer, RH_OWNER, &[]),
            );
        }
    }

    #[test]
    fn an_unsafe_first_update_suppresses_the_ticket_for_the_whole_sequence() {
        let clock = fresh_clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "E_START",
            hash_sequence_start(&[], TPM_ALG_SHA256),
        );
        exec(
            &mut runtime,
            &clock,
            "E_UPDATE_GENERATED",
            sequence_update(0x8000_0000, GENERATED, &[]),
        );
        let (permanent, volatile) = state_blobs(&runtime, &clock);
        drop(runtime);

        let restore_clock = fresh_clock();
        let clock = restore_clock;
        let mut first = reload(&permanent, &volatile, &clock);
        exec(
            &mut first,
            &clock,
            "E_COMPLETE_AFTER_UNSAFE",
            sequence_complete(0x8000_0000, b"abc", RH_OWNER, &[]),
        );

        let mut second = reload(&permanent, &volatile, &clock);
        exec(
            &mut second,
            &clock,
            "E_UPDATE_SECOND",
            sequence_update(0x8000_0000, b"abc", &[]),
        );
        exec(
            &mut second,
            &clock,
            "E_COMPLETE_STILL_UNSAFE",
            sequence_complete(0x8000_0000, b"abc", RH_OWNER, &[]),
        );
    }

    #[test]
    fn a_short_first_update_leaves_the_sequence_unsafe() {
        let clock = fresh_clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "F_START",
            hash_sequence_start(&[], TPM_ALG_SHA256),
        );
        exec(
            &mut runtime,
            &clock,
            "F_UPDATE_EMPTY_FIRST",
            sequence_update(0x8000_0000, b"", &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "F_COMPLETE_GENERATED",
            sequence_complete(0x8000_0000, GENERATED, RH_OWNER, &[]),
        );

        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "G_START",
            hash_sequence_start(&[], TPM_ALG_SHA256),
        );
        exec(
            &mut runtime,
            &clock,
            "G_UPDATE_SAFE_FIRST",
            sequence_update(0x8000_0000, b"abc", &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "G_COMPLETE_GENERATED",
            sequence_complete(0x8000_0000, GENERATED, RH_OWNER, &[]),
        );
    }

    #[test]
    fn an_invalid_hierarchy_is_rejected_and_keeps_the_sequence() {
        let clock = fresh_clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "D_START",
            hash_sequence_start(&[], TPM_ALG_SHA256),
        );
        for (label, hierarchy) in [
            ("D_COMPLETE_BAD_HIERARCHY", 0x4000_0005u32),
            ("D_COMPLETE_LOCKOUT_HIERARCHY", 0x4000_000a),
        ] {
            exec(
                &mut runtime,
                &clock,
                label,
                sequence_complete(0x8000_0000, b"abc", hierarchy, &[]),
            );
            assert_eq!(
                occupied(&runtime),
                [true, false, false],
                "{label} keeps the sequence handle"
            );
        }
    }

    #[test]
    fn malformed_parameters_report_the_indexed_errors() {
        let clock = fresh_clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "L_START",
            hash_sequence_start(&[], TPM_ALG_SHA256),
        );
        for (label, params) in [
            ("L_SC_NO_PARAMETERS", vec![]),
            ("L_SC_TRUNCATED_SIZE", vec![0x00]),
            ("L_SC_TRUNCATED_BODY", vec![0x00, 0x03, 0x61, 0x62]),
            ("L_SC_SIZE_FFFF", vec![0xff, 0xff]),
            ("L_SC_MISSING_HIERARCHY", vec![0x00, 0x02, 0x61, 0x62]),
            (
                "L_SC_TRUNCATED_HIERARCHY",
                vec![0x00, 0x02, 0x61, 0x62, 0x40, 0x00, 0x00],
            ),
            (
                "L_SC_TRAILING",
                vec![0x00, 0x02, 0x61, 0x62, 0x40, 0x00, 0x00, 0x07, 0xee],
            ),
        ] {
            exec(
                &mut runtime,
                &clock,
                label,
                sequence_complete_raw(0x8000_0000, &params, &[]),
            );
        }
        let mut oversized = max_buffer();
        oversized.push(0);
        exec(
            &mut runtime,
            &clock,
            "L_SC_OVERSIZED",
            sequence_complete(0x8000_0000, &oversized, RH_NULL, &[]),
        );
        assert_eq!(
            occupied(&runtime),
            [true, false, false],
            "a parse failure preserves the sequence object"
        );
    }

    #[test]
    fn wrong_handle_kinds_report_the_reference_errors() {
        let clock = fresh_clock();
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
            "L_SC_PERMANENT_HANDLE",
            sequence_complete(RH_OWNER, b"abc", RH_NULL, &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "L_SC_UNLOADED_HANDLE",
            sequence_complete(0x8000_0002, b"abc", RH_NULL, &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "L_SC_TRUNCATED_HANDLE",
            command(0x8002, TPM_CC_SEQUENCE_COMPLETE, &[0x80, 0x00, 0x00]),
        );
    }

    #[test]
    fn an_event_sequence_is_refused_with_the_handle_indexed_mode_error() {
        let clock = fresh_clock();
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
            "N_SEQUENCE_COMPLETE_ON_EVENT",
            sequence_complete(0x8000_0000, b"abc", RH_NULL, &[]),
        );
        assert_eq!(
            occupied(&runtime),
            [true, false, false],
            "the refused completion keeps the event sequence"
        );
    }

    #[test]
    fn an_ordinary_object_is_refused_with_the_handle_indexed_mode_error() {
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
            "U_SC_ON_RSA_KEY",
            sequence_complete(0x8000_0000, b"abc", RH_NULL, &[]),
        );
        assert_eq!(occupied(&runtime), [true, false, false]);
    }

    #[test]
    fn the_sequence_authorization_is_enforced() {
        let clock = fresh_clock();
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
            "H_UPDATE_GOOD_AUTH",
            sequence_update(0x8000_0000, b"abc", b"sequence-auth"),
        );
        exec(
            &mut runtime,
            &clock,
            "H_COMPLETE_WRONG_AUTH",
            sequence_complete(0x8000_0000, b"", RH_NULL, b"bad"),
        );
        assert_eq!(
            occupied(&runtime),
            [true, false, false],
            "a rejected authorization keeps the sequence"
        );
        exec(
            &mut runtime,
            &clock,
            "H_COMPLETE_NO_SESSION",
            command(0x8001, TPM_CC_SEQUENCE_COMPLETE, &{
                let mut out = 0x8000_0000u32.to_be_bytes().to_vec();
                out.extend_from_slice(&[0x00, 0x00, 0x40, 0x00, 0x00, 0x07]);
                out
            }),
        );
        exec(
            &mut runtime,
            &clock,
            "H_COMPLETE_GOOD_AUTH",
            sequence_complete(0x8000_0000, b"", RH_NULL, b"sequence-auth"),
        );
        assert_eq!(occupied(&runtime), [false, false, false]);
    }

    #[test]
    fn a_malformed_command_never_panics() {
        let clock = fresh_clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "L_START",
            hash_sequence_start(&[], TPM_ALG_SHA256),
        );
        let valid = sequence_complete(0x8000_0000, b"ab", RH_NULL, &[]);
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

    mod save_and_restore {
        use super::*;

        #[track_caller]
        fn hash_sequence_survives(hash_alg: u16, start: &str, update: &str, complete: &str) {
            let clock = fresh_clock();
            let mut runtime = base_runtime(&clock);
            exec(
                &mut runtime,
                &clock,
                start,
                hash_sequence_start(&[], hash_alg),
            );
            exec(
                &mut runtime,
                &clock,
                update,
                sequence_update(0x8000_0000, MESSAGE, &[]),
            );
            let (permanent, volatile) = state_blobs(&runtime, &clock);
            drop(runtime);

            let restore_clock = fresh_clock();
            let clock = restore_clock;
            let mut restored = reload(&permanent, &volatile, &clock);
            assert_eq!(
                occupied(&restored),
                [true, false, false],
                "the restored runtime carries the sequence"
            );
            exec(
                &mut restored,
                &clock,
                complete,
                sequence_complete(0x8000_0000, b" tail", RH_OWNER, &[]),
            );
            assert_eq!(
                occupied(&restored),
                [false, false, false],
                "the completed sequence releases its handle"
            );
        }

        #[test]
        fn a_sha1_hash_sequence_survives_a_state_round_trip() {
            hash_sequence_survives(
                TPM_ALG_SHA1,
                "B_START_SHA1",
                "B_UPDATE_SHA1",
                "B_COMPLETE_SHA1",
            );
        }

        #[test]
        fn a_sha256_hash_sequence_survives_a_state_round_trip() {
            hash_sequence_survives(
                TPM_ALG_SHA256,
                "B_START_SHA256",
                "B_UPDATE_SHA256",
                "B_COMPLETE_SHA256",
            );
        }

        #[test]
        fn a_sha384_hash_sequence_survives_a_state_round_trip() {
            hash_sequence_survives(
                TPM_ALG_SHA384,
                "B_START_SHA384",
                "B_UPDATE_SHA384",
                "B_COMPLETE_SHA384",
            );
        }

        #[test]
        fn a_sha512_hash_sequence_survives_a_state_round_trip() {
            hash_sequence_survives(
                TPM_ALG_SHA512,
                "B_START_SHA512",
                "B_UPDATE_SHA512",
                "B_COMPLETE_SHA512",
            );
        }

        #[test]
        fn an_hmac_sequence_survives_a_state_round_trip() {
            let clock = fresh_clock();
            let mut runtime = base_runtime(&clock);
            exec(
                &mut runtime,
                &clock,
                "Q_CREATE_HMAC_KEY",
                create_primary(RH_OWNER, &hmac_key(TPM_ALG_SHA256), &[], &[]),
            );
            exec(
                &mut runtime,
                &clock,
                "Q_HMS_DEFAULT",
                mac_start(0x8000_0000, &[], replay::TPM_ALG_NULL),
            );
            exec(
                &mut runtime,
                &clock,
                "Q_HMAC_UPDATE",
                sequence_update(0x8000_0001, b"abc", &[]),
            );
            let (permanent, volatile) = state_blobs(&runtime, &clock);
            drop(runtime);

            let restore_clock = fresh_clock();
            let clock = restore_clock;
            let mut restored = reload(&permanent, &volatile, &clock);
            exec(
                &mut restored,
                &clock,
                "Q_HMAC_UPDATE_SECOND",
                sequence_update(0x8000_0001, MESSAGE, &[]),
            );
            exec(
                &mut restored,
                &clock,
                "Q_HMAC_COMPLETE",
                sequence_complete(0x8000_0001, b" tail", RH_OWNER, &[]),
            );
            assert_eq!(occupied(&restored), [true, false, false]);
        }

        #[test]
        fn an_event_sequence_survives_a_state_round_trip() {
            let clock = fresh_clock();
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
            let (permanent, volatile) = state_blobs(&runtime, &clock);
            drop(runtime);

            let restore_clock = fresh_clock();
            let clock = restore_clock;
            let mut restored = reload(&permanent, &volatile, &clock);
            exec(
                &mut restored,
                &clock,
                "N_PCR10_BEFORE",
                crate::library::tpm2::sequence::replay::pcr_read(10),
            );
            exec(
                &mut restored,
                &clock,
                "N_EVENT_COMPLETE_PCR10",
                event_sequence_complete(10, 0x8000_0000, b"def"),
            );
            exec(
                &mut restored,
                &clock,
                "N_PCR10_AFTER",
                crate::library::tpm2::sequence::replay::pcr_read(10),
            );
            assert_eq!(occupied(&restored), [false, false, false]);
        }

        #[test]
        fn the_serialized_sequence_object_matches_the_reference_bytes() {
            let clock = fresh_clock();
            let mut runtime = base_runtime(&clock);
            for (label, command, snapshot) in [
                (
                    "A_START_SHA256",
                    hash_sequence_start(&[], TPM_ALG_SHA256),
                    "VOLATILE_A_AFTER_START",
                ),
                (
                    "A_UPDATE_ABC",
                    sequence_update(0x8000_0000, b"abc", &[]),
                    "VOLATILE_A_AFTER_UPDATE",
                ),
            ] {
                exec(&mut runtime, &clock, label, command);
                let (_, volatile) = state_blobs(&runtime, &clock);
                assert_eq!(
                    object_region(&volatile),
                    object_region(vector(snapshot)),
                    "{snapshot}"
                );
            }
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
            let (_, volatile) = state_blobs(&runtime, &clock);
            assert_eq!(
                object_region(&volatile),
                object_region(vector("VOLATILE_A_AFTER_THIRD_UPDATE"))
            );
            exec(
                &mut runtime,
                &clock,
                "A_COMPLETE_GHI",
                sequence_complete(0x8000_0000, b"ghi", RH_NULL, &[]),
            );
            let (_, volatile) = state_blobs(&runtime, &clock);
            assert_eq!(
                object_region(&volatile),
                object_region(vector("VOLATILE_A_AFTER_COMPLETE")),
                "the released slot keeps the reference residue"
            );
        }

        #[test]
        fn every_sequence_kind_serializes_like_the_reference() {
            let clock = fresh_clock();
            let mut runtime = base_runtime(&clock);
            exec(
                &mut runtime,
                &clock,
                "N_START_EVENT",
                hash_sequence_start(&[], replay::TPM_ALG_NULL),
            );
            let (_, volatile) = state_blobs(&runtime, &clock);
            assert_eq!(
                object_region(&volatile),
                object_region(vector("VOLATILE_N_AFTER_EVENT_START")),
                "a fresh event sequence"
            );

            let clock = fresh_clock();
            let mut runtime = base_runtime(&clock);
            exec(
                &mut runtime,
                &clock,
                "Q_CREATE_HMAC_KEY",
                create_primary(RH_OWNER, &hmac_key(TPM_ALG_SHA256), &[], &[]),
            );
            exec(
                &mut runtime,
                &clock,
                "Q_HMS_DEFAULT",
                mac_start(0x8000_0000, &[], replay::TPM_ALG_NULL),
            );
            let (_, volatile) = state_blobs(&runtime, &clock);
            assert_eq!(
                object_region(&volatile),
                object_region(vector("VOLATILE_Q_AFTER_HMS")),
                "a fresh HMAC sequence next to its key"
            );
            exec(
                &mut runtime,
                &clock,
                "Q_HMAC_UPDATE",
                sequence_update(0x8000_0001, b"abc", &[]),
            );
            let (_, volatile) = state_blobs(&runtime, &clock);
            assert_eq!(
                object_region(&volatile),
                object_region(vector("VOLATILE_Q_AFTER_HMAC_UPDATE")),
                "an updated HMAC sequence"
            );
        }

        #[test]
        fn a_filled_object_array_serializes_like_the_reference() {
            let clock = fresh_clock();
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
            let (_, volatile) = state_blobs(&runtime, &clock);
            assert_eq!(
                object_region(&volatile),
                object_region(vector("VOLATILE_M_SLOTS_FULL"))
            );
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
            let (_, volatile) = state_blobs(&runtime, &clock);
            assert_eq!(
                object_region(&volatile),
                object_region(vector("VOLATILE_M_AFTER_REUSE"))
            );
        }
    }
}
