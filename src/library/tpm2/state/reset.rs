use crate::library::tpm2::marshal::{
    BlobReader, BlockDisposition, BlockSkipError, Tpm2bError, skip_optional_block,
};
use crate::library::tpm2::persistent::{
    PersistentAllError, PersistentField, SEED_COMPAT_LEVEL_LAST, SEED_COMPAT_LEVEL_ORIGINAL,
    StateSection, parse_nv_header,
};

pub(in crate::library::tpm2) const STATE_RESET_DATA_MAGIC: u32 = 0x0110_2332;
const STATE_RESET_DATA_VERSION: u16 = 4;

const PROOF_SIZE: usize = 64;
const PRIMARY_SEED_SIZE: usize = 64;
const DIGEST_SIZE: usize = 64;
pub(in crate::library::tpm2) const MAX_ACTIVE_SESSIONS: usize = 64;
pub(in crate::library::tpm2) const COMMIT_ARRAY_SIZE: usize = 16;

const WIDE_CONTEXT_SLOTS_SINCE_VERSION: u16 = 4;
const BLOCK_SKIP_SINCE_VERSION: u16 = 2;
const SEED_COMPAT_REQUIRED_SINCE_VERSION: u16 = 3;

const SECTION: StateSection = StateSection::StateResetData;

fn truncated() -> PersistentAllError {
    PersistentAllError::Truncated { section: SECTION }
}

fn read_tpm2b<'a>(
    reader: &mut BlobReader<'a>,
    field: PersistentField,
    maximum: usize,
) -> Result<&'a [u8], PersistentAllError> {
    reader.read_tpm2b(maximum).map_err(|error| match error {
        Tpm2bError::Truncated => truncated(),
        Tpm2bError::SizeExceeded { actual, maximum } => PersistentAllError::Tpm2bSizeExceeded {
            section: SECTION,
            field,
            actual,
            maximum,
        },
    })
}

fn read_block(
    reader: &mut BlobReader<'_>,
    needs_block: bool,
) -> Result<BlockDisposition, PersistentAllError> {
    skip_optional_block(reader, needs_block).map_err(|error| match error {
        BlockSkipError::Truncated => truncated(),
        BlockSkipError::MissingRequiredBlock => {
            PersistentAllError::MissingRequiredBlock { section: SECTION }
        }
    })
}

#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::library::tpm2) struct StateResetData<'a> {
    pub(in crate::library::tpm2) null_proof: &'a [u8],
    pub(in crate::library::tpm2) null_seed: &'a [u8],
    pub(in crate::library::tpm2) clear_count: u32,
    pub(in crate::library::tpm2) object_context_id: u64,
    pub(in crate::library::tpm2) context_array: [u16; MAX_ACTIVE_SESSIONS],
    pub(in crate::library::tpm2) context_slot_mask: u16,
    pub(in crate::library::tpm2) context_counter: u64,
    pub(in crate::library::tpm2) command_audit_digest: &'a [u8],
    pub(in crate::library::tpm2) restart_count: u32,
    pub(in crate::library::tpm2) pcr_counter: u32,
    pub(in crate::library::tpm2) commit_counter: u64,
    pub(in crate::library::tpm2) commit_nonce: &'a [u8],
    pub(in crate::library::tpm2) commit_array: &'a [u8],
    pub(in crate::library::tpm2) null_seed_compat_level: u8,
    pub(in crate::library::tpm2) remaining: &'a [u8],
}

impl core::fmt::Debug for StateResetData<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StateResetData")
            .field("null_proof_len", &self.null_proof.len())
            .field("null_seed_len", &self.null_seed.len())
            .field("clear_count", &self.clear_count)
            .field("restart_count", &self.restart_count)
            .finish_non_exhaustive()
    }
}

pub(in crate::library::tpm2) fn parse_state_reset_data(
    input: &[u8],
) -> Result<StateResetData<'_>, PersistentAllError> {
    use PersistentField as F;
    let mut reader = BlobReader::new(input);

    let header = parse_nv_header(
        &mut reader,
        SECTION,
        STATE_RESET_DATA_MAGIC,
        STATE_RESET_DATA_VERSION,
    )?;

    let null_proof = read_tpm2b(&mut reader, F::NullProof, PROOF_SIZE)?;
    let null_seed = read_tpm2b(&mut reader, F::NullSeed, PRIMARY_SEED_SIZE)?;
    let clear_count = reader.read_u32().map_err(|_| truncated())?;
    let object_context_id = reader.read_u64().map_err(|_| truncated())?;

    let declared = reader.read_u16().map_err(|_| truncated())?;
    if usize::from(declared) != MAX_ACTIVE_SESSIONS {
        return Err(PersistentAllError::ArraySizeInvalid {
            section: SECTION,
            declared,
            expected: MAX_ACTIVE_SESSIONS,
        });
    }
    let mut context_array = [0u16; MAX_ACTIVE_SESSIONS];
    let context_slot_mask = if header.version < WIDE_CONTEXT_SLOTS_SINCE_VERSION {
        for slot in &mut context_array {
            *slot = u16::from(reader.read_u8().map_err(|_| truncated())?);
        }
        0x00ff
    } else {
        for slot in &mut context_array {
            *slot = reader.read_u16().map_err(|_| truncated())?;
        }
        let mask = reader.read_u16().map_err(|_| truncated())?;
        if mask != 0xffff && mask != 0x00ff {
            return Err(PersistentAllError::InvalidContextSlotMask { actual: mask });
        }
        mask
    };

    let context_counter = reader.read_u64().map_err(|_| truncated())?;
    let command_audit_digest = read_tpm2b(&mut reader, F::CommandAuditDigest, DIGEST_SIZE)?;
    let restart_count = reader.read_u32().map_err(|_| truncated())?;
    let pcr_counter = reader.read_u32().map_err(|_| truncated())?;

    read_block(&mut reader, true)?;
    let commit_counter = reader.read_u64().map_err(|_| truncated())?;
    let commit_nonce = read_tpm2b(&mut reader, F::CommitNonce, DIGEST_SIZE)?;
    let declared = reader.read_u16().map_err(|_| truncated())?;
    if usize::from(declared) != COMMIT_ARRAY_SIZE {
        return Err(PersistentAllError::ArraySizeInvalid {
            section: SECTION,
            declared,
            expected: COMMIT_ARRAY_SIZE,
        });
    }
    let commit_array = reader.take(COMMIT_ARRAY_SIZE).map_err(|_| truncated())?;

    let mut null_seed_compat_level = SEED_COMPAT_LEVEL_ORIGINAL;
    if header.version >= BLOCK_SKIP_SINCE_VERSION
        && let BlockDisposition::Present { .. } = read_block(
            &mut reader,
            header.version >= SEED_COMPAT_REQUIRED_SINCE_VERSION,
        )?
    {
        let level = reader.read_u8().map_err(|_| truncated())?;
        if level > SEED_COMPAT_LEVEL_LAST {
            return Err(PersistentAllError::SeedCompatLevelTooNew {
                field: PersistentField::NullSeedCompat,
                actual: level,
                supported: SEED_COMPAT_LEVEL_LAST,
            });
        }
        null_seed_compat_level = level;

        read_block(&mut reader, false)?;
    }

    Ok(StateResetData {
        null_proof,
        null_seed,
        clear_count,
        object_context_id,
        context_array,
        context_slot_mask,
        context_counter,
        command_audit_digest,
        restart_count,
        pcr_counter,
        commit_counter,
        commit_nonce,
        commit_array,
        null_seed_compat_level,
        remaining: reader.remaining(),
    })
}

#[cfg(test)]
pub(in crate::library::tpm2) struct StateResetFixture {
    pub(in crate::library::tpm2) version: u16,
    pub(in crate::library::tpm2) magic: u32,
    pub(in crate::library::tpm2) min_version: u16,
    pub(in crate::library::tpm2) null_proof: Vec<u8>,
    pub(in crate::library::tpm2) null_seed: Vec<u8>,
    pub(in crate::library::tpm2) clear_count: u32,
    pub(in crate::library::tpm2) object_context_id: u64,
    pub(in crate::library::tpm2) context_array_size: u16,
    pub(in crate::library::tpm2) context_array: Vec<u16>,
    pub(in crate::library::tpm2) context_slot_mask: u16,
    pub(in crate::library::tpm2) context_counter: u64,
    pub(in crate::library::tpm2) command_audit_digest: Vec<u8>,
    pub(in crate::library::tpm2) restart_count: u32,
    pub(in crate::library::tpm2) pcr_counter: u32,
    pub(in crate::library::tpm2) ecc_has_block: u8,
    pub(in crate::library::tpm2) commit_counter: u64,
    pub(in crate::library::tpm2) commit_nonce: Vec<u8>,
    pub(in crate::library::tpm2) commit_array_size: u16,
    pub(in crate::library::tpm2) commit_array: Vec<u8>,
    pub(in crate::library::tpm2) seed_has_block: Option<u8>,
    pub(in crate::library::tpm2) seed_block_size: Option<u16>,
    pub(in crate::library::tpm2) null_seed_compat_level: u8,
    pub(in crate::library::tpm2) future_block: Option<(u8, u16, Vec<u8>)>,
    pub(in crate::library::tpm2) tail: Vec<u8>,
}

#[cfg(test)]
impl Default for StateResetFixture {
    fn default() -> Self {
        Self {
            version: STATE_RESET_DATA_VERSION,
            magic: STATE_RESET_DATA_MAGIC,
            min_version: 4,
            null_proof: vec![0x0f; 8],
            null_seed: vec![0x5e; 8],
            clear_count: 0,
            object_context_id: 0,
            context_array_size: MAX_ACTIVE_SESSIONS as u16,
            context_array: vec![0; MAX_ACTIVE_SESSIONS],
            context_slot_mask: 0xffff,
            context_counter: 0,
            command_audit_digest: Vec::new(),
            restart_count: 0,
            pcr_counter: 0,
            ecc_has_block: 1,
            commit_counter: 0,
            commit_nonce: Vec::new(),
            commit_array_size: COMMIT_ARRAY_SIZE as u16,
            commit_array: vec![0; COMMIT_ARRAY_SIZE],
            seed_has_block: Some(1),
            seed_block_size: None,
            null_seed_compat_level: SEED_COMPAT_LEVEL_ORIGINAL,
            future_block: Some((1, 0, Vec::new())),
            tail: Vec::new(),
        }
    }
}

#[cfg(test)]
impl StateResetFixture {
    fn push_tpm2b(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&u16::try_from(bytes.len()).unwrap().to_be_bytes());
        out.extend_from_slice(bytes);
    }

    pub(in crate::library::tpm2) fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.magic.to_be_bytes());
        if self.version >= 2 {
            out.extend_from_slice(&self.min_version.to_be_bytes());
        }
        Self::push_tpm2b(&mut out, &self.null_proof);
        Self::push_tpm2b(&mut out, &self.null_seed);
        out.extend_from_slice(&self.clear_count.to_be_bytes());
        out.extend_from_slice(&self.object_context_id.to_be_bytes());
        out.extend_from_slice(&self.context_array_size.to_be_bytes());
        for slot in &self.context_array {
            if self.version < WIDE_CONTEXT_SLOTS_SINCE_VERSION {
                out.push(*slot as u8);
            } else {
                out.extend_from_slice(&slot.to_be_bytes());
            }
        }
        if self.version >= WIDE_CONTEXT_SLOTS_SINCE_VERSION {
            out.extend_from_slice(&self.context_slot_mask.to_be_bytes());
        }
        out.extend_from_slice(&self.context_counter.to_be_bytes());
        Self::push_tpm2b(&mut out, &self.command_audit_digest);
        out.extend_from_slice(&self.restart_count.to_be_bytes());
        out.extend_from_slice(&self.pcr_counter.to_be_bytes());

        let mut ecc = Vec::new();
        if self.ecc_has_block != 0 {
            ecc.extend_from_slice(&self.commit_counter.to_be_bytes());
            Self::push_tpm2b(&mut ecc, &self.commit_nonce);
            ecc.extend_from_slice(&self.commit_array_size.to_be_bytes());
            ecc.extend_from_slice(&self.commit_array);
        }
        out.push(self.ecc_has_block);
        out.extend_from_slice(&u16::try_from(ecc.len()).unwrap().to_be_bytes());
        out.extend_from_slice(&ecc);

        if self.version >= BLOCK_SKIP_SINCE_VERSION
            && let Some(seed_has_block) = self.seed_has_block
        {
            let mut payload = Vec::new();
            if seed_has_block != 0 {
                payload.push(self.null_seed_compat_level);
                if let Some((has_block, size, future)) = &self.future_block {
                    payload.push(*has_block);
                    payload.extend_from_slice(&size.to_be_bytes());
                    payload.extend_from_slice(future);
                }
            }
            out.push(seed_has_block);
            let size = self
                .seed_block_size
                .unwrap_or_else(|| u16::try_from(payload.len()).unwrap());
            out.extend_from_slice(&size.to_be_bytes());
            out.extend_from_slice(&payload);
        }
        out.extend_from_slice(&self.tail);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::constants::{
        TPM_RC_BAD_PARAMETER, TPM_RC_BAD_VERSION, TPM_RC_INSUFFICIENT, TPM_RC_SIZE,
    };

    const SENTINEL: [u8; 3] = [0xc1, 0xc2, 0xc3];

    fn with_tail() -> StateResetFixture {
        StateResetFixture {
            tail: SENTINEL.to_vec(),
            ..StateResetFixture::default()
        }
    }

    #[test]
    fn current_version_fixture_full_field_decode() {
        let mut context_array: Vec<u16> = (0..MAX_ACTIVE_SESSIONS as u16).collect();
        context_array[0] = 0xbeef;
        let data = StateResetFixture {
            null_proof: vec![0x11; PROOF_SIZE],
            null_seed: vec![0x22; PRIMARY_SEED_SIZE],
            clear_count: 3,
            object_context_id: 4,
            context_array: context_array.clone(),
            context_counter: 5,
            command_audit_digest: vec![0x33; 32],
            restart_count: 6,
            pcr_counter: 7,
            commit_counter: 8,
            commit_nonce: vec![0x44; 20],
            commit_array: vec![0x55; COMMIT_ARRAY_SIZE],
            null_seed_compat_level: 1,
            tail: SENTINEL.to_vec(),
            ..StateResetFixture::default()
        }
        .bytes();
        let parsed = parse_state_reset_data(&data).unwrap();
        assert_eq!(parsed.null_proof, &[0x11; PROOF_SIZE]);
        assert_eq!(parsed.null_seed, &[0x22; PRIMARY_SEED_SIZE]);
        assert_eq!(parsed.clear_count, 3);
        assert_eq!(parsed.object_context_id, 4);
        assert_eq!(parsed.context_array.to_vec(), context_array);
        assert_eq!(parsed.context_slot_mask, 0xffff);
        assert_eq!(parsed.context_counter, 5);
        assert_eq!(parsed.command_audit_digest, &[0x33; 32]);
        assert_eq!(parsed.restart_count, 6);
        assert_eq!(parsed.pcr_counter, 7);
        assert_eq!(parsed.commit_counter, 8);
        assert_eq!(parsed.commit_nonce, &[0x44; 20]);
        assert_eq!(parsed.commit_array, &[0x55; COMMIT_ARRAY_SIZE]);
        assert_eq!(parsed.null_seed_compat_level, 1);
        assert_eq!(parsed.remaining, &SENTINEL);
    }

    #[test]
    fn oversized_tpm2b_field_size_errors() {
        for (fixture, field) in [
            (
                StateResetFixture {
                    null_proof: vec![0; PROOF_SIZE + 1],
                    ..with_tail()
                },
                PersistentField::NullProof,
            ),
            (
                StateResetFixture {
                    null_seed: vec![0; PRIMARY_SEED_SIZE + 1],
                    ..with_tail()
                },
                PersistentField::NullSeed,
            ),
            (
                StateResetFixture {
                    command_audit_digest: vec![0; DIGEST_SIZE + 1],
                    ..with_tail()
                },
                PersistentField::CommandAuditDigest,
            ),
            (
                StateResetFixture {
                    commit_nonce: vec![0; DIGEST_SIZE + 1],
                    ..with_tail()
                },
                PersistentField::CommitNonce,
            ),
        ] {
            let error = parse_state_reset_data(&fixture.bytes()).unwrap_err();
            assert!(
                matches!(
                    error,
                    PersistentAllError::Tpm2bSizeExceeded { field: f, .. } if f == field
                ),
                "{field:?}: {error:?}"
            );
            assert_eq!(error.tpm_result(), TPM_RC_SIZE);
        }
    }

    #[test]
    fn exact_capacity_tpm2b_acceptance() {
        let data = StateResetFixture {
            null_proof: vec![0x66; PROOF_SIZE],
            null_seed: vec![0x77; PRIMARY_SEED_SIZE],
            command_audit_digest: vec![0x88; DIGEST_SIZE],
            commit_nonce: vec![0x99; DIGEST_SIZE],
            ..with_tail()
        }
        .bytes();
        assert!(parse_state_reset_data(&data).is_ok());
    }

    #[test]
    fn wrong_context_array_size_bad_parameter() {
        for declared in [0u16, 63, 65, u16::MAX] {
            let mut data = with_tail();
            data.context_array_size = declared;
            let error = parse_state_reset_data(&data.bytes()).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::ArraySizeInvalid {
                    section: StateSection::StateResetData,
                    declared,
                    expected: MAX_ACTIVE_SESSIONS,
                },
                "declared {declared}"
            );
            assert_eq!(error.tpm_result(), TPM_RC_BAD_PARAMETER);
        }
    }

    #[test]
    fn version_3_blob_maskless_narrow_slot_decode() {
        let data = StateResetFixture {
            version: 3,
            min_version: 1,
            context_array: (0..64).map(|i| i as u16).collect(),
            null_seed_compat_level: 1,
            tail: SENTINEL.to_vec(),
            ..StateResetFixture::default()
        }
        .bytes();
        let parsed = parse_state_reset_data(&data).unwrap();
        assert_eq!(parsed.context_slot_mask, 0x00ff);
        assert_eq!(parsed.context_array[63], 63);
        assert_eq!(parsed.null_seed_compat_level, 1);
        assert_eq!(parsed.remaining, &SENTINEL);
    }

    #[test]
    fn version_2_blob_present_seed_block_skip() {
        let data = StateResetFixture {
            version: 2,
            min_version: 1,
            null_seed_compat_level: 0xff,
            tail: SENTINEL.to_vec(),
            ..StateResetFixture::default()
        }
        .bytes();
        let parsed = parse_state_reset_data(&data).unwrap();
        assert_eq!(parsed.null_seed_compat_level, SEED_COMPAT_LEVEL_ORIGINAL);
        assert_eq!(parsed.remaining, &SENTINEL);
    }

    #[test]
    fn version_2_blob_absent_seed_block_acceptance() {
        let data = StateResetFixture {
            version: 2,
            min_version: 1,
            seed_has_block: Some(0),
            tail: SENTINEL.to_vec(),
            ..StateResetFixture::default()
        }
        .bytes();
        let parsed = parse_state_reset_data(&data).unwrap();
        assert_eq!(parsed.null_seed_compat_level, SEED_COMPAT_LEVEL_ORIGINAL);
        assert_eq!(parsed.remaining, &SENTINEL);
    }

    #[test]
    fn missing_seed_block_versions_3_4_bad_parameter() {
        for version in [3u16, 4] {
            let data = StateResetFixture {
                version,
                min_version: 1,
                seed_has_block: Some(0),
                ..StateResetFixture::default()
            }
            .bytes();
            let error = parse_state_reset_data(&data).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::MissingRequiredBlock {
                    section: StateSection::StateResetData,
                },
                "version {version}"
            );
        }
    }

    #[test]
    fn invalid_context_slot_mask_bad_parameter() {
        for mask in [0x0000u16, 0x0001, 0xff00, 0xfffe] {
            let data = StateResetFixture {
                context_slot_mask: mask,
                ..StateResetFixture::default()
            }
            .bytes();
            let error = parse_state_reset_data(&data).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::InvalidContextSlotMask { actual: mask },
                "mask {mask:#06x}"
            );
        }
    }

    #[test]
    fn valid_context_slot_mask_acceptance() {
        for mask in [0x00ffu16, 0xffff] {
            let data = StateResetFixture {
                context_slot_mask: mask,
                tail: SENTINEL.to_vec(),
                ..StateResetFixture::default()
            }
            .bytes();
            assert_eq!(
                parse_state_reset_data(&data).unwrap().context_slot_mask,
                mask
            );
        }
    }

    #[test]
    fn missing_ecc_block_bad_parameter() {
        let data = StateResetFixture {
            ecc_has_block: 0,
            ..StateResetFixture::default()
        }
        .bytes();
        let error = parse_state_reset_data(&data).unwrap_err();
        assert_eq!(
            error,
            PersistentAllError::MissingRequiredBlock {
                section: StateSection::StateResetData,
            }
        );
    }

    #[test]
    fn wrong_commit_array_size_bad_parameter() {
        for declared in [0u16, 15, 17] {
            let data = StateResetFixture {
                commit_array_size: declared,
                ..StateResetFixture::default()
            }
            .bytes();
            let error = parse_state_reset_data(&data).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::ArraySizeInvalid {
                    section: StateSection::StateResetData,
                    declared,
                    expected: COMMIT_ARRAY_SIZE,
                },
                "declared {declared}"
            );
        }
    }

    #[test]
    fn too_new_seed_compat_level_bad_version() {
        for level in [2u8, 0x80, 0xff] {
            let data = StateResetFixture {
                null_seed_compat_level: level,
                ..StateResetFixture::default()
            }
            .bytes();
            let error = parse_state_reset_data(&data).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::SeedCompatLevelTooNew {
                    field: PersistentField::NullSeedCompat,
                    actual: level,
                    supported: SEED_COMPAT_LEVEL_LAST,
                },
                "level {level}"
            );
            assert_eq!(error.tpm_result(), TPM_RC_BAD_VERSION);
        }
    }

    #[test]
    fn secret_field_input_borrowing() {
        let data = StateResetFixture {
            null_proof: vec![0xaa; 8],
            ..with_tail()
        }
        .bytes();
        let parsed = parse_state_reset_data(&data).unwrap();
        assert!(data.as_ptr_range().contains(&parsed.null_proof.as_ptr()));
        assert!(data.as_ptr_range().contains(&parsed.commit_array.as_ptr()));
    }

    #[test]
    fn strict_prefix_rejection_safety() {
        for version in [2u16, 3, 4] {
            let full = StateResetFixture {
                version,
                min_version: 1,
                null_proof: vec![0x11; 4],
                command_audit_digest: vec![0x22; 4],
                commit_nonce: vec![0x33; 4],
                ..StateResetFixture::default()
            }
            .bytes();
            for len in 0..full.len() {
                let error = parse_state_reset_data(&full[..len]).unwrap_err();
                assert_eq!(
                    error.tpm_result(),
                    TPM_RC_INSUFFICIENT,
                    "version {version}, prefix length {len} of {}",
                    full.len()
                );
            }
            assert!(parse_state_reset_data(&full).is_ok(), "version {version}");
        }
    }

    #[test]
    fn state_reset_byte_mutation_panic_safety() {
        let full = StateResetFixture::default().bytes();
        for index in 0..full.len() {
            for byte in [0x00u8, 0x01, 0xff] {
                let mut data = full.clone();
                data[index] = byte;
                let _ = parse_state_reset_data(&data);
            }
        }
    }
}
