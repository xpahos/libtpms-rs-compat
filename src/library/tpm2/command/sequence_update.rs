use crate::ffi_types::TpmResult;
use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_INSUFFICIENT, TPM_RC_MODE, TPM_RC_SIZE};

use super::super::marshal::{BlobReader, Tpm2bError};
use super::super::runtime::Tpm2Runtime;
use super::super::sequence::{
    SequenceKind, first_block_seen, mark_first_block, resolve_sequence_slot, slot_kind,
    update_sequence,
};
use super::super::ticket::ticket_is_safe;
use super::dispatcher::CommandFrame;
use super::output::CommandOutput;

const TPM_RC_H: TpmResult = 0x000;
const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;
const TPM_RC_2: TpmResult = 0x200;
const RC_SEQUENCE_HANDLE: TpmResult = TPM_RC_P + TPM_RC_1;

pub(super) const MAX_DIGEST_BUFFER: usize = 1024;
pub(super) const RC_BUFFER_P1: TpmResult = TPM_RC_P + TPM_RC_1;
pub(super) const RC_HANDLE_H1: TpmResult = TPM_RC_H + TPM_RC_1;
pub(super) const RC_HANDLE_H2: TpmResult = TPM_RC_H + TPM_RC_2;

pub(super) fn execute(
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
    use super::super::registry::{self, HandleKind, TPM_CC_SEQUENCE_UPDATE};
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
    fn the_command_is_registered_with_the_upstream_attributes() {
        assert_eq!(TPM_CC_SEQUENCE_UPDATE, 0x0000_015c);
        let descriptor = registry::find(TPM_CC_SEQUENCE_UPDATE).expect("registered");
        assert_eq!(descriptor.attributes, 0x0200_015c);
        assert!(!descriptor.physical_presence);
        assert!(descriptor.sessions_allowed);
        assert_eq!(descriptor.attributes & (1 << 28), 0, "no response handle");
        assert_eq!(descriptor.attributes & (1 << 22), 0, "no NVRAM update");
        assert_eq!(descriptor.attributes & (1 << 23), 0, "not extensive");
        assert_eq!(descriptor.attributes & (1 << 24), 0, "no flushed handle");
        assert_eq!((descriptor.attributes >> 25) & 0x7, 1, "one command handle");
        assert_eq!(descriptor.handles.len(), 1);
        assert!(descriptor.handles[0].user_auth);
        assert!(!descriptor.handles[0].admin_role);
        assert!(matches!(descriptor.handles[0].kind, HandleKind::Object));
    }

    #[test]
    fn the_capability_report_matches_the_oracle() {
        let clock = clock();
        let mut runtime = base_runtime(&clock);
        let mut params = 2u32.to_be_bytes().to_vec();
        params.extend_from_slice(&0x015cu32.to_be_bytes());
        params.extend_from_slice(&1u32.to_be_bytes());
        exec(
            &mut runtime,
            &clock,
            "CAP_CC_SEQUENCE_UPDATE",
            command(0x8001, 0x0000_017a, &params),
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
            "SU_BEFORE_STARTUP",
            sequence_update(0x8000_0000, b"abc", &[]),
        );
    }

    #[test]
    fn repeated_updates_hash_the_concatenated_input() {
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
    fn a_completed_sequence_no_longer_accepts_updates() {
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
    fn an_event_sequence_accepts_updates() {
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
    fn malformed_parameters_and_handles_report_the_indexed_errors() {
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
    fn wrong_handle_kinds_report_the_reference_errors() {
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
    fn an_ordinary_object_is_not_a_sequence() {
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
    fn the_sequence_authorization_is_enforced() {
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
    fn a_malformed_command_never_panics() {
        let clock = clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "L_START",
            hash_sequence_start(&[], TPM_ALG_SHA256),
        );
        let valid = sequence_update(0x8000_0000, b"ab", &[]);
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
}
