use super::{PersistentAllError, PersistentField, StateSection};
use crate::library::tpm2::marshal::{
    BlobReader, BlockDisposition, BlockSkipError, skip_optional_block,
};
use crate::library::tpm2::pcr::{PcrAllocation, parse_pcr_allocation};

pub(in crate::library::tpm2) const SEED_COMPAT_LEVEL_ORIGINAL: u8 = 0;
pub(in crate::library::tpm2) const SEED_COMPAT_LEVEL_LAST: u8 = 1;

const FRAMED_SINCE_VERSION: u16 = 2;
const OUTER_REQUIRED_SINCE_VERSION: u16 = 3;
const SEED_REQUIRED_SINCE_VERSION: u16 = 4;

const SECTION: StateSection = StateSection::CompatTail;

fn truncated() -> PersistentAllError {
    PersistentAllError::Truncated { section: SECTION }
}

#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::library::tpm2) struct CompatTail<'a> {
    pub(in crate::library::tpm2) shadow_pcr_allocated: Option<PcrAllocation<'a>>,
    pub(in crate::library::tpm2) ep_seed_compat_level: u8,
    pub(in crate::library::tpm2) sp_seed_compat_level: u8,
    pub(in crate::library::tpm2) pp_seed_compat_level: u8,
    pub(in crate::library::tpm2) remaining: &'a [u8],
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

fn read_seed_compat_level(
    reader: &mut BlobReader<'_>,
    field: PersistentField,
) -> Result<u8, PersistentAllError> {
    let level = reader.read_u8().map_err(|_| truncated())?;
    if level > SEED_COMPAT_LEVEL_LAST {
        return Err(PersistentAllError::SeedCompatLevelTooNew {
            field,
            actual: level,
            supported: SEED_COMPAT_LEVEL_LAST,
        });
    }
    Ok(level)
}

pub(in crate::library::tpm2) fn parse_compat_tail(
    input: &[u8],
    blob_version: u16,
) -> Result<CompatTail<'_>, PersistentAllError> {
    use PersistentField as F;

    let mut ep_seed_compat_level = SEED_COMPAT_LEVEL_ORIGINAL;
    let mut sp_seed_compat_level = SEED_COMPAT_LEVEL_ORIGINAL;
    let mut pp_seed_compat_level = SEED_COMPAT_LEVEL_ORIGINAL;
    let mut shadow_pcr_allocated = None;

    let mut reader = BlobReader::new(input);
    if blob_version >= FRAMED_SINCE_VERSION
        && let BlockDisposition::Present { .. } =
            read_block(&mut reader, blob_version >= OUTER_REQUIRED_SINCE_VERSION)?
    {
        let allocation = parse_pcr_allocation(reader.remaining())?;
        reader = BlobReader::new(allocation.remaining);
        shadow_pcr_allocated = Some(allocation);

        if let BlockDisposition::Present { .. } =
            read_block(&mut reader, blob_version >= SEED_REQUIRED_SINCE_VERSION)?
        {
            ep_seed_compat_level = read_seed_compat_level(&mut reader, F::EpSeed)?;
            sp_seed_compat_level = read_seed_compat_level(&mut reader, F::SpSeed)?;
            pp_seed_compat_level = read_seed_compat_level(&mut reader, F::PpSeed)?;

            read_block(&mut reader, false)?;
        }
    }

    Ok(CompatTail {
        shadow_pcr_allocated,
        ep_seed_compat_level,
        sp_seed_compat_level,
        pp_seed_compat_level,
        remaining: reader.remaining(),
    })
}

#[cfg(test)]
pub(in crate::library::tpm2) struct CompatTailFixture {
    pub(in crate::library::tpm2) outer_has_block: Option<u8>,
    pub(in crate::library::tpm2) outer_block_size: Option<u16>,
    pub(in crate::library::tpm2) shadow: Vec<u8>,
    pub(in crate::library::tpm2) seed_has_block: Option<u8>,
    pub(in crate::library::tpm2) seed_block_size: Option<u16>,
    pub(in crate::library::tpm2) seed_levels: [u8; 3],
    pub(in crate::library::tpm2) future_block: Option<(u8, u16, Vec<u8>)>,
    pub(in crate::library::tpm2) tail: Vec<u8>,
}

#[cfg(test)]
impl Default for CompatTailFixture {
    fn default() -> Self {
        Self {
            outer_has_block: Some(1),
            outer_block_size: None,
            shadow: crate::library::tpm2::pcr::PcrAllocationFixture::default().bytes(),
            seed_has_block: Some(1),
            seed_block_size: None,
            seed_levels: [SEED_COMPAT_LEVEL_ORIGINAL; 3],
            future_block: Some((1, 0, Vec::new())),
            tail: Vec::new(),
        }
    }
}

#[cfg(test)]
impl CompatTailFixture {
    pub(in crate::library::tpm2) fn bytes(&self) -> Vec<u8> {
        let mut inner = Vec::new();
        inner.extend_from_slice(&self.shadow);
        if let Some(seed_has_block) = self.seed_has_block {
            let mut seed_payload = Vec::new();
            if seed_has_block != 0 {
                seed_payload.extend_from_slice(&self.seed_levels);
                if let Some((has_block, size, payload)) = &self.future_block {
                    seed_payload.push(*has_block);
                    seed_payload.extend_from_slice(&size.to_be_bytes());
                    seed_payload.extend_from_slice(payload);
                }
            }
            inner.push(seed_has_block);
            let size = self
                .seed_block_size
                .unwrap_or_else(|| u16::try_from(seed_payload.len()).unwrap());
            inner.extend_from_slice(&size.to_be_bytes());
            inner.extend_from_slice(&seed_payload);
        }

        let mut out = Vec::new();
        if let Some(outer_has_block) = self.outer_has_block {
            let payload = if outer_has_block != 0 {
                inner
            } else {
                Vec::new()
            };
            out.push(outer_has_block);
            let size = self
                .outer_block_size
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
        TPM_RC_BAD_PARAMETER, TPM_RC_BAD_VERSION, TPM_RC_HASH, TPM_RC_INSUFFICIENT, TPM_RC_SIZE,
    };
    use crate::library::tpm2::pcr::PcrAllocationFixture;

    const ORDERLY_SENTINEL: [u8; 3] = [0x56, 0x65, 0x78];

    fn parse(input: &[u8], blob_version: u16) -> Result<CompatTail<'_>, PersistentAllError> {
        parse_compat_tail(input, blob_version)
    }

    fn with_tail() -> CompatTailFixture {
        CompatTailFixture {
            tail: ORDERLY_SENTINEL.to_vec(),
            ..CompatTailFixture::default()
        }
    }

    #[test]
    fn hand_built_fixture_matches_the_upstream_marshal_order() {
        let fixture = [
            0x01, 0x00, 0x15, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0b, 0x03, 0xa1, 0xa2, 0xa3, 0x01,
            0x00, 0x06, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x56, 0x65, 0x78,
        ];
        let parsed = parse(&fixture, 5).unwrap();
        let shadow = parsed.shadow_pcr_allocated.as_ref().unwrap();
        assert_eq!(shadow.declared_count, 1);
        assert_eq!(shadow.selections[0].hash_alg, 0x000b);
        assert_eq!(shadow.selections[0].select, &[0xa1, 0xa2, 0xa3]);
        assert_eq!(parsed.ep_seed_compat_level, 1);
        assert_eq!(parsed.sp_seed_compat_level, 1);
        assert_eq!(parsed.pp_seed_compat_level, 1);
        assert_eq!(parsed.remaining, &ORDERLY_SENTINEL);
    }

    #[test]
    fn version_1_has_no_framing_and_keeps_the_defaults() {
        let input = [0x01, 0x00, 0x05, 0x44];
        let parsed = parse(&input, 1).unwrap();
        assert!(parsed.shadow_pcr_allocated.is_none());
        assert_eq!(parsed.ep_seed_compat_level, SEED_COMPAT_LEVEL_ORIGINAL);
        assert_eq!(parsed.sp_seed_compat_level, SEED_COMPAT_LEVEL_ORIGINAL);
        assert_eq!(parsed.pp_seed_compat_level, SEED_COMPAT_LEVEL_ORIGINAL);
        assert_eq!(parsed.remaining, &input);
        assert!(core::ptr::eq(parsed.remaining.as_ptr(), input.as_ptr()));
    }

    #[test]
    fn version_2_absent_outer_block_keeps_the_defaults() {
        let data = CompatTailFixture {
            outer_has_block: Some(0),
            tail: ORDERLY_SENTINEL.to_vec(),
            ..CompatTailFixture::default()
        }
        .bytes();
        let parsed = parse(&data, 2).unwrap();
        assert!(parsed.shadow_pcr_allocated.is_none());
        assert_eq!(parsed.ep_seed_compat_level, SEED_COMPAT_LEVEL_ORIGINAL);
        assert_eq!(parsed.remaining, &ORDERLY_SENTINEL);
    }

    #[test]
    fn version_2_present_outer_block_is_skipped_by_its_declared_size() {
        let data = CompatTailFixture {
            seed_levels: [0xff; 3],
            tail: ORDERLY_SENTINEL.to_vec(),
            ..CompatTailFixture::default()
        }
        .bytes();
        let parsed = parse(&data, 2).unwrap();
        assert!(parsed.shadow_pcr_allocated.is_none());
        assert_eq!(parsed.ep_seed_compat_level, SEED_COMPAT_LEVEL_ORIGINAL);
        assert_eq!(parsed.remaining, &ORDERLY_SENTINEL);
    }

    #[test]
    fn outer_block_is_required_for_versions_3_and_newer() {
        for version in [3u16, 4, 5, 9] {
            let data = CompatTailFixture {
                outer_has_block: Some(0),
                ..CompatTailFixture::default()
            }
            .bytes();
            let error = parse(&data, version).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::MissingRequiredBlock { section: SECTION },
                "version {version}"
            );
            assert_eq!(error.tpm_result(), TPM_RC_BAD_PARAMETER);
        }
    }

    #[test]
    fn version_3_absent_seed_block_keeps_the_defaults() {
        let data = CompatTailFixture {
            seed_has_block: Some(0),
            tail: ORDERLY_SENTINEL.to_vec(),
            ..CompatTailFixture::default()
        }
        .bytes();
        let parsed = parse(&data, 3).unwrap();
        assert!(parsed.shadow_pcr_allocated.is_some());
        assert_eq!(parsed.ep_seed_compat_level, SEED_COMPAT_LEVEL_ORIGINAL);
        assert_eq!(parsed.sp_seed_compat_level, SEED_COMPAT_LEVEL_ORIGINAL);
        assert_eq!(parsed.pp_seed_compat_level, SEED_COMPAT_LEVEL_ORIGINAL);
        assert_eq!(parsed.remaining, &ORDERLY_SENTINEL);
    }

    #[test]
    fn version_3_present_seed_block_is_skipped_by_its_declared_size() {
        let data = CompatTailFixture {
            seed_levels: [0xff; 3],
            tail: ORDERLY_SENTINEL.to_vec(),
            ..CompatTailFixture::default()
        }
        .bytes();
        let parsed = parse(&data, 3).unwrap();
        assert!(parsed.shadow_pcr_allocated.is_some());
        assert_eq!(parsed.ep_seed_compat_level, SEED_COMPAT_LEVEL_ORIGINAL);
        assert_eq!(parsed.remaining, &ORDERLY_SENTINEL);
    }

    #[test]
    fn seed_block_is_required_for_versions_4_and_newer() {
        for version in [4u16, 5, 9] {
            let data = CompatTailFixture {
                seed_has_block: Some(0),
                ..CompatTailFixture::default()
            }
            .bytes();
            let error = parse(&data, version).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::MissingRequiredBlock { section: SECTION },
                "version {version}"
            );
        }
    }

    #[test]
    fn versions_4_and_5_decode_the_full_tail() {
        for version in [4u16, 5] {
            let data = CompatTailFixture {
                seed_levels: [1, 0, 1],
                tail: ORDERLY_SENTINEL.to_vec(),
                ..CompatTailFixture::default()
            }
            .bytes();
            let parsed = parse(&data, version)
                .unwrap_or_else(|error| panic!("version {version}: {error:?}"));
            assert_eq!(parsed.ep_seed_compat_level, 1, "version {version}");
            assert_eq!(parsed.sp_seed_compat_level, 0, "version {version}");
            assert_eq!(parsed.pp_seed_compat_level, 1, "version {version}");
            assert_eq!(parsed.remaining, &ORDERLY_SENTINEL);
        }
    }

    #[test]
    fn minimum_and_maximum_levels_are_accepted_per_field() {
        for levels in [[0u8; 3], [1; 3], [0, 1, 0], [1, 0, 1]] {
            let data = CompatTailFixture {
                seed_levels: levels,
                ..CompatTailFixture::default()
            }
            .bytes();
            let parsed =
                parse(&data, 5).unwrap_or_else(|error| panic!("levels {levels:?}: {error:?}"));
            assert_eq!(
                [
                    parsed.ep_seed_compat_level,
                    parsed.sp_seed_compat_level,
                    parsed.pp_seed_compat_level,
                ],
                levels
            );
        }
    }

    #[test]
    fn each_seed_level_above_last_is_bad_version_and_names_its_field() {
        let fields = [
            PersistentField::EpSeed,
            PersistentField::SpSeed,
            PersistentField::PpSeed,
        ];
        for (index, field) in fields.into_iter().enumerate() {
            for actual in [2u8, 0x80, 0xff] {
                let mut levels = [SEED_COMPAT_LEVEL_ORIGINAL; 3];
                levels[index] = actual;
                let data = CompatTailFixture {
                    seed_levels: levels,
                    ..CompatTailFixture::default()
                }
                .bytes();
                let error = parse(&data, 5).unwrap_err();
                assert_eq!(
                    error,
                    PersistentAllError::SeedCompatLevelTooNew {
                        field,
                        actual,
                        supported: SEED_COMPAT_LEVEL_LAST,
                    },
                    "{field:?} level {actual}"
                );
                assert_eq!(error.tpm_result(), TPM_RC_BAD_VERSION);
            }
        }
    }

    #[test]
    fn shadow_list_reuses_the_strict_allocation_rules() {
        let bad_hash = CompatTailFixture {
            shadow: PcrAllocationFixture {
                selections: vec![(0x0010, 3, vec![0x00; 3])],
                ..PcrAllocationFixture::default()
            }
            .bytes(),
            ..CompatTailFixture::default()
        }
        .bytes();
        assert_eq!(parse(&bad_hash, 5).unwrap_err().tpm_result(), TPM_RC_HASH);

        let bad_count = CompatTailFixture {
            shadow: PcrAllocationFixture {
                count: Some(5),
                ..PcrAllocationFixture::default()
            }
            .bytes(),
            ..CompatTailFixture::default()
        }
        .bytes();
        assert_eq!(parse(&bad_count, 5).unwrap_err().tpm_result(), TPM_RC_SIZE);
    }

    #[test]
    fn shadow_list_entries_are_decoded_and_borrow_the_input() {
        let data = CompatTailFixture {
            shadow: PcrAllocationFixture {
                selections: vec![(0x0004, 3, vec![0x0f, 0xf0, 0xaa])],
                ..PcrAllocationFixture::default()
            }
            .bytes(),
            ..CompatTailFixture::default()
        }
        .bytes();
        let parsed = parse(&data, 5).unwrap();
        let shadow = parsed.shadow_pcr_allocated.as_ref().unwrap();
        assert_eq!(shadow.declared_count, 1);
        assert_eq!(shadow.selections[0].hash_alg, 0x0004);
        assert_eq!(shadow.selections[0].select, &[0x0f, 0xf0, 0xaa]);
        assert!(
            data.as_ptr_range()
                .contains(&shadow.selections[0].select.as_ptr()),
            "the shadow bitmap must borrow the input"
        );
    }

    #[test]
    fn absent_empty_and_nonempty_future_blocks_land_at_the_same_boundary() {
        for future in [
            (0u8, 0u16, Vec::new()),
            (1, 0, Vec::new()),
            (1, 3, vec![0xf1, 0xf2, 0xf3]),
        ] {
            let payload_len = future.2.len();
            let data = CompatTailFixture {
                future_block: Some(future),
                tail: ORDERLY_SENTINEL.to_vec(),
                ..CompatTailFixture::default()
            }
            .bytes();
            let parsed = parse(&data, 5)
                .unwrap_or_else(|error| panic!("future payload {payload_len}: {error:?}"));
            assert_eq!(
                parsed.remaining, &ORDERLY_SENTINEL,
                "future payload {payload_len}: skipped bytes must not leak into ORDERLY_DATA"
            );
        }
    }

    #[test]
    fn future_block_contents_are_never_interpreted() {
        let data = CompatTailFixture {
            future_block: Some((1, 5, vec![0xff, 0xff, 0xff, 0xff, 0xff])),
            tail: ORDERLY_SENTINEL.to_vec(),
            ..CompatTailFixture::default()
        }
        .bytes();
        assert_eq!(parse(&data, 5).unwrap().remaining, &ORDERLY_SENTINEL);
    }

    #[test]
    fn every_strict_prefix_of_a_full_tail_fails_safely() {
        let full = CompatTailFixture {
            seed_levels: [1, 1, 1],
            future_block: Some((1, 2, vec![0xd1, 0xd2])),
            ..CompatTailFixture::default()
        }
        .bytes();
        for len in 0..full.len() {
            let error = parse(&full[..len], 5).unwrap_err();
            assert_eq!(
                error.tpm_result(),
                TPM_RC_INSUFFICIENT,
                "prefix length {len} of {}",
                full.len()
            );
        }
        assert!(parse(&full, 5).is_ok());
    }

    #[test]
    fn skipped_block_size_beyond_input_is_insufficient() {
        let data = CompatTailFixture {
            outer_block_size: Some(0x4000),
            ..CompatTailFixture::default()
        }
        .bytes();
        assert_eq!(parse(&data, 2).unwrap_err(), truncated());
    }

    #[test]
    fn future_block_size_beyond_input_is_insufficient() {
        let data = CompatTailFixture {
            future_block: Some((1, 9, vec![0x11])),
            ..CompatTailFixture::default()
        }
        .bytes();
        assert_eq!(parse(&data, 5).unwrap_err(), truncated());
    }

    #[test]
    fn compat_tail_byte_mutations_do_not_panic() {
        for version in [1u16, 2, 3, 4, 5, 0xffff] {
            for len in 0..8usize {
                for byte in [0x00u8, 0x01, 0xff] {
                    let _ = parse(&vec![byte; len], version);
                }
            }
            let full = with_tail().bytes();
            for index in 0..full.len() {
                for byte in [0x00u8, 0x02, 0xff] {
                    let mut data = full.clone();
                    data[index] = byte;
                    let _ = parse(&data, version);
                }
            }
        }
    }
}
