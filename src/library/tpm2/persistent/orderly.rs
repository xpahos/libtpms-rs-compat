use super::{PersistentAllError, StateSection, parse_nv_header};
use crate::library::tpm2::marshal::{
    BlobReader, BlockDisposition, BlockSkipError, skip_optional_block,
};

pub(in crate::library::tpm2) const ORDERLY_DATA_MAGIC: u32 = 0x5665_7887;
const ORDERLY_DATA_VERSION: u16 = 2;
pub(in crate::library::tpm2) const DRBG_STATE_MAGIC: u32 = 0x6fe8_3ea1;
const DRBG_STATE_VERSION: u16 = 2;

pub(in crate::library::tpm2) const DRBG_SEED_SIZE: usize = 48;
pub(in crate::library::tpm2) const DRBG_LAST_VALUE_COUNT: usize = 4;

const BLOCK_SKIP_SINCE_VERSION: u16 = 2;

const SECTION: StateSection = StateSection::OrderlyData;

fn truncated(section: StateSection) -> PersistentAllError {
    PersistentAllError::Truncated { section }
}

fn read_block(
    reader: &mut BlobReader<'_>,
    section: StateSection,
    needs_block: bool,
) -> Result<BlockDisposition, PersistentAllError> {
    skip_optional_block(reader, needs_block).map_err(|error| match error {
        BlockSkipError::Truncated => truncated(section),
        BlockSkipError::MissingRequiredBlock => {
            PersistentAllError::MissingRequiredBlock { section }
        }
    })
}

#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::library::tpm2) struct DrbgState<'a> {
    pub(in crate::library::tpm2) reseed_counter: u64,
    pub(in crate::library::tpm2) drbg_magic: u32,
    pub(in crate::library::tpm2) seed: &'a [u8],
    pub(in crate::library::tpm2) last_value: [u32; DRBG_LAST_VALUE_COUNT],
}

impl core::fmt::Debug for DrbgState<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DrbgState")
            .field("reseed_counter", &self.reseed_counter)
            .field("seed_len", &self.seed.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::library::tpm2) struct OrderlyData<'a> {
    pub(in crate::library::tpm2) clock: u64,
    pub(in crate::library::tpm2) clock_safe: u8,
    pub(in crate::library::tpm2) drbg_state: DrbgState<'a>,
    pub(in crate::library::tpm2) self_heal_timer: u64,
    pub(in crate::library::tpm2) lockout_timer: u64,
    pub(in crate::library::tpm2) time: u64,
    pub(in crate::library::tpm2) remaining: &'a [u8],
}

fn parse_drbg_state<'a>(reader: &mut BlobReader<'a>) -> Result<DrbgState<'a>, PersistentAllError> {
    const SECTION: StateSection = StateSection::DrbgState;

    let header = parse_nv_header(reader, SECTION, DRBG_STATE_MAGIC, DRBG_STATE_VERSION)?;
    let reseed_counter = reader.read_u64().map_err(|_| truncated(SECTION))?;
    let drbg_magic = reader.read_u32().map_err(|_| truncated(SECTION))?;

    let seed_size = reader.read_u16().map_err(|_| truncated(SECTION))?;
    if usize::from(seed_size) != DRBG_SEED_SIZE {
        return Err(PersistentAllError::ArraySizeMismatch {
            section: SECTION,
            declared: seed_size,
            expected: DRBG_SEED_SIZE,
        });
    }
    let seed = reader
        .take(DRBG_SEED_SIZE)
        .map_err(|_| truncated(SECTION))?;

    let last_value_count = reader.read_u16().map_err(|_| truncated(SECTION))?;
    if usize::from(last_value_count) != DRBG_LAST_VALUE_COUNT {
        return Err(PersistentAllError::ArraySizeMismatch {
            section: SECTION,
            declared: last_value_count,
            expected: DRBG_LAST_VALUE_COUNT,
        });
    }
    let mut last_value = [0u32; DRBG_LAST_VALUE_COUNT];
    for value in &mut last_value {
        *value = reader.read_u32().map_err(|_| truncated(SECTION))?;
    }

    if header.version >= BLOCK_SKIP_SINCE_VERSION {
        read_block(reader, SECTION, false)?;
    }

    Ok(DrbgState {
        reseed_counter,
        drbg_magic,
        seed,
        last_value,
    })
}

pub(in crate::library::tpm2) fn parse_orderly_data(
    input: &[u8],
) -> Result<OrderlyData<'_>, PersistentAllError> {
    let mut reader = BlobReader::new(input);

    let header = parse_nv_header(
        &mut reader,
        SECTION,
        ORDERLY_DATA_MAGIC,
        ORDERLY_DATA_VERSION,
    )?;
    let clock = reader.read_u64().map_err(|_| truncated(SECTION))?;
    let clock_safe = reader.read_u8().map_err(|_| truncated(SECTION))?;
    let drbg_state = parse_drbg_state(&mut reader)?;

    read_block(&mut reader, SECTION, true)?;
    let self_heal_timer = reader.read_u64().map_err(|_| truncated(SECTION))?;
    let lockout_timer = reader.read_u64().map_err(|_| truncated(SECTION))?;
    let time = reader.read_u64().map_err(|_| truncated(SECTION))?;

    if header.version >= BLOCK_SKIP_SINCE_VERSION {
        read_block(&mut reader, SECTION, false)?;
    }

    Ok(OrderlyData {
        clock,
        clock_safe,
        drbg_state,
        self_heal_timer,
        lockout_timer,
        time,
        remaining: reader.remaining(),
    })
}

#[cfg(test)]
pub(in crate::library::tpm2) struct DrbgFixture {
    pub(in crate::library::tpm2) version: u16,
    pub(in crate::library::tpm2) magic: u32,
    pub(in crate::library::tpm2) reseed_counter: u64,
    pub(in crate::library::tpm2) drbg_magic: u32,
    pub(in crate::library::tpm2) seed_size: u16,
    pub(in crate::library::tpm2) seed: Vec<u8>,
    pub(in crate::library::tpm2) last_value_count: u16,
    pub(in crate::library::tpm2) last_value: [u32; DRBG_LAST_VALUE_COUNT],
    pub(in crate::library::tpm2) future_block: Option<(u8, u16, Vec<u8>)>,
}

#[cfg(test)]
impl Default for DrbgFixture {
    fn default() -> Self {
        Self {
            version: DRBG_STATE_VERSION,
            magic: DRBG_STATE_MAGIC,
            reseed_counter: 0,
            drbg_magic: 0x4742_5244,
            seed_size: DRBG_SEED_SIZE as u16,
            seed: vec![0x5a; DRBG_SEED_SIZE],
            last_value_count: DRBG_LAST_VALUE_COUNT as u16,
            last_value: [0; DRBG_LAST_VALUE_COUNT],
            future_block: Some((1, 0, Vec::new())),
        }
    }
}

#[cfg(test)]
impl DrbgFixture {
    pub(in crate::library::tpm2) fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.magic.to_be_bytes());
        if self.version >= 2 {
            out.extend_from_slice(&1u16.to_be_bytes());
        }
        out.extend_from_slice(&self.reseed_counter.to_be_bytes());
        out.extend_from_slice(&self.drbg_magic.to_be_bytes());
        out.extend_from_slice(&self.seed_size.to_be_bytes());
        out.extend_from_slice(&self.seed);
        out.extend_from_slice(&self.last_value_count.to_be_bytes());
        for value in self.last_value {
            out.extend_from_slice(&value.to_be_bytes());
        }
        if self.version >= 2
            && let Some((has_block, size, payload)) = &self.future_block
        {
            out.push(*has_block);
            out.extend_from_slice(&size.to_be_bytes());
            out.extend_from_slice(payload);
        }
        out
    }
}

#[cfg(test)]
pub(in crate::library::tpm2) struct OrderlyFixture {
    pub(in crate::library::tpm2) version: u16,
    pub(in crate::library::tpm2) magic: u32,
    pub(in crate::library::tpm2) clock: u64,
    pub(in crate::library::tpm2) clock_safe: u8,
    pub(in crate::library::tpm2) drbg: Vec<u8>,
    pub(in crate::library::tpm2) self_heal_has_block: u8,
    pub(in crate::library::tpm2) self_heal_block_size: Option<u16>,
    pub(in crate::library::tpm2) self_heal: [u64; 3],
    pub(in crate::library::tpm2) future_block: Option<(u8, u16, Vec<u8>)>,
    pub(in crate::library::tpm2) tail: Vec<u8>,
}

#[cfg(test)]
impl Default for OrderlyFixture {
    fn default() -> Self {
        Self {
            version: ORDERLY_DATA_VERSION,
            magic: ORDERLY_DATA_MAGIC,
            clock: 0,
            clock_safe: 1,
            drbg: DrbgFixture::default().bytes(),
            self_heal_has_block: 1,
            self_heal_block_size: None,
            self_heal: [0; 3],
            future_block: Some((1, 0, Vec::new())),
            tail: Vec::new(),
        }
    }
}

#[cfg(test)]
impl OrderlyFixture {
    pub(in crate::library::tpm2) fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.magic.to_be_bytes());
        if self.version >= 2 {
            out.extend_from_slice(&1u16.to_be_bytes());
        }
        out.extend_from_slice(&self.clock.to_be_bytes());
        out.push(self.clock_safe);
        out.extend_from_slice(&self.drbg);

        let mut payload = Vec::new();
        if self.self_heal_has_block != 0 {
            for value in self.self_heal {
                payload.extend_from_slice(&value.to_be_bytes());
            }
        }
        out.push(self.self_heal_has_block);
        let size = self
            .self_heal_block_size
            .unwrap_or_else(|| u16::try_from(payload.len()).unwrap());
        out.extend_from_slice(&size.to_be_bytes());
        out.extend_from_slice(&payload);

        if self.version >= 2
            && let Some((has_block, size, payload)) = &self.future_block
        {
            out.push(*has_block);
            out.extend_from_slice(&size.to_be_bytes());
            out.extend_from_slice(payload);
        }
        out.extend_from_slice(&self.tail);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::constants::{
        TPM_RC_BAD_PARAMETER, TPM_RC_BAD_TAG, TPM_RC_BAD_VERSION, TPM_RC_INSUFFICIENT, TPM_RC_SIZE,
    };

    const NEXT_SECTION_SENTINEL: [u8; 3] = [0xa1, 0xa2, 0xa3];

    fn with_tail() -> OrderlyFixture {
        OrderlyFixture {
            tail: NEXT_SECTION_SENTINEL.to_vec(),
            ..OrderlyFixture::default()
        }
    }

    #[test]
    fn hand_built_fixture_matches_the_upstream_marshal_order() {
        let mut fixture = vec![
            0x00, 0x02, 0x56, 0x65, 0x78, 0x87, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x2a, 0x01, 0x00, 0x02, 0x6f, 0xe8, 0x3e, 0xa1, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x07, 0x47, 0x42, 0x52, 0x44, 0x00, 0x30,
        ];
        fixture.extend_from_slice(&[0x11; 48]);
        fixture.extend_from_slice(&[
            0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03,
            0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x01, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x01, 0x00, 0x00, 0xa1, 0xa2, 0xa3,
        ]);
        let parsed = parse_orderly_data(&fixture).unwrap();
        assert_eq!(parsed.clock, 42);
        assert_eq!(parsed.clock_safe, 1);
        assert_eq!(parsed.drbg_state.reseed_counter, 7);
        assert_eq!(parsed.drbg_state.drbg_magic, 0x4742_5244);
        assert_eq!(parsed.drbg_state.seed, &[0x11; 48]);
        assert_eq!(parsed.drbg_state.last_value, [1, 2, 3, 4]);
        assert_eq!(parsed.self_heal_timer, 5);
        assert_eq!(parsed.lockout_timer, 6);
        assert_eq!(parsed.time, 9);
        assert_eq!(parsed.remaining, &NEXT_SECTION_SENTINEL);
    }

    #[test]
    fn fixture_default_roundtrips() {
        let data = with_tail().bytes();
        let parsed = parse_orderly_data(&data).unwrap();
        assert_eq!(parsed.remaining, &NEXT_SECTION_SENTINEL);
        assert!(
            data.as_ptr_range()
                .contains(&parsed.drbg_state.seed.as_ptr()),
            "the seed must borrow the input"
        );
    }

    #[test]
    fn incorrect_section_magic_is_bad_tag() {
        let mut data = with_tail().bytes();
        data[2] = 0xff;
        let error = parse_orderly_data(&data).unwrap_err();
        assert_eq!(
            error,
            PersistentAllError::InvalidHeaderMagic {
                section: StateSection::OrderlyData,
                actual: 0xff65_7887,
            }
        );
        assert_eq!(error.tpm_result(), TPM_RC_BAD_TAG);
    }

    #[test]
    fn min_version_newer_than_implementation_is_rejected() {
        let mut data = with_tail().bytes();
        data[6..8].copy_from_slice(&3u16.to_be_bytes());
        let error = parse_orderly_data(&data).unwrap_err();
        assert_eq!(error.tpm_result(), TPM_RC_BAD_VERSION);
    }

    #[test]
    fn version_1_section_has_no_min_version_and_no_future_block() {
        let data = OrderlyFixture {
            version: 1,
            tail: NEXT_SECTION_SENTINEL.to_vec(),
            ..OrderlyFixture::default()
        }
        .bytes();
        let parsed = parse_orderly_data(&data).unwrap();
        assert_eq!(parsed.remaining, &NEXT_SECTION_SENTINEL);
    }

    #[test]
    fn incorrect_drbg_magic_is_bad_tag_with_drbg_identity() {
        let mut drbg = DrbgFixture::default().bytes();
        drbg[2] = 0x00;
        let data = OrderlyFixture {
            drbg,
            ..OrderlyFixture::default()
        }
        .bytes();
        let error = parse_orderly_data(&data).unwrap_err();
        assert!(matches!(
            error,
            PersistentAllError::InvalidHeaderMagic {
                section: StateSection::DrbgState,
                ..
            }
        ));
    }

    #[test]
    fn drbg_in_memory_magic_is_raw_and_never_validated() {
        for magic in [0u32, 0xdead_beef, u32::MAX] {
            let data = OrderlyFixture {
                drbg: DrbgFixture {
                    drbg_magic: magic,
                    ..DrbgFixture::default()
                }
                .bytes(),
                ..OrderlyFixture::default()
            }
            .bytes();
            let parsed = parse_orderly_data(&data).unwrap();
            assert_eq!(parsed.drbg_state.drbg_magic, magic, "magic {magic:#010x}");
        }
    }

    #[test]
    fn wrong_drbg_seed_size_is_a_size_error() {
        for seed_size in [0u16, 47, 49, u16::MAX] {
            let data = OrderlyFixture {
                drbg: DrbgFixture {
                    seed_size,
                    ..DrbgFixture::default()
                }
                .bytes(),
                ..OrderlyFixture::default()
            }
            .bytes();
            let error = parse_orderly_data(&data).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::ArraySizeMismatch {
                    section: StateSection::DrbgState,
                    declared: seed_size,
                    expected: DRBG_SEED_SIZE,
                },
                "seed size {seed_size}"
            );
            assert_eq!(error.tpm_result(), TPM_RC_SIZE);
        }
    }

    #[test]
    fn wrong_drbg_last_value_count_is_a_size_error() {
        for count in [0u16, 3, 5, u16::MAX] {
            let data = OrderlyFixture {
                drbg: DrbgFixture {
                    last_value_count: count,
                    ..DrbgFixture::default()
                }
                .bytes(),
                ..OrderlyFixture::default()
            }
            .bytes();
            let error = parse_orderly_data(&data).unwrap_err();
            assert_eq!(error.tpm_result(), TPM_RC_SIZE, "count {count}");
        }
    }

    #[test]
    fn missing_self_heal_block_is_bad_parameter() {
        let data = OrderlyFixture {
            self_heal_has_block: 0,
            ..OrderlyFixture::default()
        }
        .bytes();
        let error = parse_orderly_data(&data).unwrap_err();
        assert_eq!(
            error,
            PersistentAllError::MissingRequiredBlock {
                section: StateSection::OrderlyData,
            }
        );
        assert_eq!(error.tpm_result(), TPM_RC_BAD_PARAMETER);
    }

    #[test]
    fn noncanonical_self_heal_block_boolean_is_true() {
        for byte in [0x02u8, 0x80, 0xff] {
            let data = OrderlyFixture {
                self_heal_has_block: byte,
                tail: NEXT_SECTION_SENTINEL.to_vec(),
                ..OrderlyFixture::default()
            }
            .bytes();
            let parsed = parse_orderly_data(&data).unwrap();
            assert_eq!(parsed.remaining, &NEXT_SECTION_SENTINEL, "byte {byte:#04x}");
        }
    }

    #[test]
    fn self_heal_declared_size_is_ignored_when_needed() {
        let data = OrderlyFixture {
            self_heal_block_size: Some(0xffff),
            self_heal: [10, 11, 12],
            tail: NEXT_SECTION_SENTINEL.to_vec(),
            ..OrderlyFixture::default()
        }
        .bytes();
        let parsed = parse_orderly_data(&data).unwrap();
        assert_eq!(parsed.self_heal_timer, 10);
        assert_eq!(parsed.lockout_timer, 11);
        assert_eq!(parsed.time, 12);
    }

    #[test]
    fn absent_empty_and_nonempty_future_blocks_land_at_the_same_boundary() {
        for future in [
            (0u8, 0u16, Vec::new()),
            (1, 0, Vec::new()),
            (1, 4, vec![0xf1, 0xf2, 0xf3, 0xf4]),
        ] {
            let len = future.2.len();
            let data = OrderlyFixture {
                future_block: Some(future),
                tail: NEXT_SECTION_SENTINEL.to_vec(),
                ..OrderlyFixture::default()
            }
            .bytes();
            let parsed = parse_orderly_data(&data).unwrap();
            assert_eq!(parsed.remaining, &NEXT_SECTION_SENTINEL, "payload {len}");
        }
    }

    #[test]
    fn every_strict_prefix_fails_safely() {
        let full = OrderlyFixture::default().bytes();
        for len in 0..full.len() {
            let error = parse_orderly_data(&full[..len]).unwrap_err();
            assert_eq!(
                error.tpm_result(),
                TPM_RC_INSUFFICIENT,
                "prefix length {len} of {}",
                full.len()
            );
        }
        assert!(parse_orderly_data(&full).is_ok());
    }

    #[test]
    fn orderly_block_byte_mutations_do_not_panic() {
        let full = OrderlyFixture::default().bytes();
        for index in 0..full.len() {
            for byte in [0x00u8, 0x01, 0xff] {
                let mut data = full.clone();
                data[index] = byte;
                let _ = parse_orderly_data(&data);
            }
        }
    }
}
