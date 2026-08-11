use super::command_bitmap::{COMMAND_COUNT, parse_command_bitmap};
use super::marshal::BlobReader;
use super::persistent::{PersistentAllError, StateSection};

pub(super) const AUDIT_COMMANDS_SIZE: usize = (COMMAND_COUNT + 1).div_ceil(8);

const CLOCK_SIZE: u8 = 4;

const SECTION: StateSection = StateSection::Audit;
const EPOCH_SECTION: StateSection = StateSection::ClockEpoch;

fn truncated() -> PersistentAllError {
    PersistentAllError::Truncated { section: SECTION }
}

fn epoch_truncated() -> PersistentAllError {
    PersistentAllError::Truncated {
        section: EPOCH_SECTION,
    }
}

#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct AuditState<'a> {
    pub(super) commands_compressed: bool,
    pub(super) commands: &'a [u8],
    pub(super) audit_hash_alg: u16,
    pub(super) audit_counter: u64,
    pub(super) algorithm_set: u32,
    pub(super) firmware_v1: u32,
    pub(super) firmware_v2: u32,
    pub(super) time_epoch: u32,
    pub(super) remaining: &'a [u8],
}

pub(super) fn parse_audit_state(
    input: &[u8],
    blob_version: u16,
) -> Result<AuditState<'_>, PersistentAllError> {
    let mut reader = BlobReader::new(input);

    let (commands_compressed, commands) =
        parse_command_bitmap(&mut reader, blob_version, SECTION, AUDIT_COMMANDS_SIZE)?;

    let audit_hash_alg = reader.read_u16().map_err(|_| truncated())?;
    let audit_counter = reader.read_u64().map_err(|_| truncated())?;
    let algorithm_set = reader.read_u32().map_err(|_| truncated())?;
    let firmware_v1 = reader.read_u32().map_err(|_| truncated())?;
    let firmware_v2 = reader.read_u32().map_err(|_| truncated())?;

    let clocksize = reader.read_u8().map_err(|_| epoch_truncated())?;
    if clocksize != CLOCK_SIZE {
        return Err(PersistentAllError::InvalidClockSize {
            actual: clocksize,
            expected: CLOCK_SIZE,
        });
    }
    let time_epoch = reader.read_u32().map_err(|_| epoch_truncated())?;

    Ok(AuditState {
        commands_compressed,
        commands,
        audit_hash_alg,
        audit_counter,
        algorithm_set,
        firmware_v1,
        firmware_v2,
        time_epoch,
        remaining: reader.remaining(),
    })
}

#[cfg(test)]
pub(super) struct AuditFixture {
    pub(super) size: Option<u16>,
    pub(super) commands: Vec<u8>,
    pub(super) audit_hash_alg: u16,
    pub(super) audit_counter: u64,
    pub(super) algorithm_set: u32,
    pub(super) firmware_v1: u32,
    pub(super) firmware_v2: u32,
    pub(super) clocksize: u8,
    pub(super) time_epoch: u32,
    pub(super) tail: Vec<u8>,
}

#[cfg(test)]
impl Default for AuditFixture {
    fn default() -> Self {
        Self {
            size: None,
            commands: vec![0x00; AUDIT_COMMANDS_SIZE],
            audit_hash_alg: 0,
            audit_counter: 0,
            algorithm_set: 0,
            firmware_v1: 0,
            firmware_v2: 0,
            clocksize: CLOCK_SIZE,
            time_epoch: 0,
            tail: Vec::new(),
        }
    }
}

#[cfg(test)]
impl AuditFixture {
    pub(super) fn bytes(&self) -> Vec<u8> {
        let size = self
            .size
            .unwrap_or_else(|| u16::try_from(self.commands.len()).unwrap());
        let mut out = Vec::new();
        out.extend_from_slice(&size.to_be_bytes());
        out.extend_from_slice(&self.commands);
        out.extend_from_slice(&self.audit_hash_alg.to_be_bytes());
        out.extend_from_slice(&self.audit_counter.to_be_bytes());
        out.extend_from_slice(&self.algorithm_set.to_be_bytes());
        out.extend_from_slice(&self.firmware_v1.to_be_bytes());
        out.extend_from_slice(&self.firmware_v2.to_be_bytes());
        out.push(self.clocksize);
        out.extend_from_slice(&self.time_epoch.to_be_bytes());
        out.extend_from_slice(&self.tail);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::constants::{TPM_RC_BAD_PARAMETER, TPM_RC_INSUFFICIENT, TPM_RC_SIZE};

    const RAW_VERSIONS: [u16; 3] = [5, 6, 0xffff];
    const COMPRESSED_VERSIONS: [u16; 5] = [0, 1, 2, 3, 4];

    fn parse(input: &[u8], blob_version: u16) -> Result<AuditState<'_>, PersistentAllError> {
        parse_audit_state(input, blob_version)
    }

    #[test]
    fn hand_built_fixture_matches_the_upstream_marshal_order() {
        let mut fixture = vec![0x00, 0x11];
        let commands: Vec<u8> = (1..=17).collect();
        fixture.extend_from_slice(&commands);
        fixture.extend_from_slice(&[
            0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x08,
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x0a, 0x04, 0x00, 0x00, 0x00, 0x0b, 0x01,
            0x00,
        ]);
        let parsed = parse(&fixture, 5).unwrap();
        assert!(!parsed.commands_compressed);
        assert_eq!(parsed.commands, &commands[..]);
        assert_eq!(parsed.audit_hash_alg, 0x000b);
        assert_eq!(parsed.audit_counter, 7);
        assert_eq!(parsed.algorithm_set, 8);
        assert_eq!(parsed.firmware_v1, 9);
        assert_eq!(parsed.firmware_v2, 10);
        assert_eq!(parsed.time_epoch, 11);
        assert_eq!(parsed.remaining, &[0x01, 0x00]);
    }

    #[test]
    fn every_size_up_to_the_array_capacity_is_valid_for_raw_blobs() {
        for version in RAW_VERSIONS {
            for size in 0..=AUDIT_COMMANDS_SIZE {
                let data = AuditFixture {
                    commands: vec![0x5a; size],
                    ..AuditFixture::default()
                }
                .bytes();
                let parsed = parse(&data, version)
                    .unwrap_or_else(|error| panic!("version {version} size {size}: {error:?}"));
                assert_eq!(parsed.commands.len(), size, "version {version} size {size}");
                assert!(!parsed.commands_compressed);
            }
        }
    }

    #[test]
    fn capacity_plus_one_is_a_size_error_for_raw_blobs() {
        for version in RAW_VERSIONS {
            for size in [AUDIT_COMMANDS_SIZE + 1, 100, usize::from(u16::MAX)] {
                let data = AuditFixture {
                    commands: vec![0x5a; size],
                    ..AuditFixture::default()
                }
                .bytes();
                let error = parse(&data, version).unwrap_err();
                assert_eq!(
                    error,
                    PersistentAllError::CommandArraySizeExceeded {
                        section: SECTION,
                        actual: size as u16,
                        maximum: AUDIT_COMMANDS_SIZE,
                    },
                    "version {version} size {size}"
                );
                assert_eq!(error.tpm_result(), TPM_RC_SIZE);
            }
        }
    }

    #[test]
    fn oversized_raw_count_is_rejected_before_any_byte_is_read() {
        let data = u16::MAX.to_be_bytes();
        let error = parse(&data, 5).unwrap_err();
        assert_eq!(error.tpm_result(), TPM_RC_SIZE);
    }

    #[test]
    fn compressed_blobs_accept_any_size_and_record_their_indexing() {
        for version in COMPRESSED_VERSIONS {
            for size in [
                0usize,
                1,
                14,
                AUDIT_COMMANDS_SIZE,
                AUDIT_COMMANDS_SIZE + 1,
                100,
            ] {
                let data = AuditFixture {
                    commands: vec![0xff; size],
                    ..AuditFixture::default()
                }
                .bytes();
                let parsed = parse(&data, version)
                    .unwrap_or_else(|error| panic!("version {version} size {size}: {error:?}"));
                assert!(parsed.commands_compressed, "version {version} size {size}");
                assert_eq!(parsed.commands.len(), size);
            }
        }
    }

    #[test]
    fn version_gate_matches_the_upstream_comparison() {
        let data = AuditFixture::default().bytes();
        assert!(parse(&data, 4).unwrap().commands_compressed);
        assert!(!parse(&data, 5).unwrap().commands_compressed);
    }

    #[test]
    fn all_bitmap_bit_patterns_are_preserved_verbatim_and_borrow_the_input() {
        for commands in [vec![0xff; 17], vec![0xa5; 17], (0x80..0x91).collect()] {
            let data = AuditFixture {
                commands: commands.clone(),
                ..AuditFixture::default()
            }
            .bytes();
            let parsed = parse(&data, 5).unwrap();
            assert_eq!(parsed.commands, &commands[..], "commands {commands:02x?}");
            assert!(
                core::ptr::eq(parsed.commands.as_ptr(), data[2..].as_ptr()),
                "the array must borrow the input, not copy it"
            );
        }
    }

    #[test]
    fn commands_array_transitions_exactly_into_audit_hash_alg() {
        let data = AuditFixture {
            commands: vec![0x99],
            audit_hash_alg: 0x1234,
            ..AuditFixture::default()
        }
        .bytes();
        let parsed = parse(&data, 5).unwrap();
        assert_eq!(parsed.commands, &[0x99]);
        assert_eq!(parsed.audit_hash_alg, 0x1234);
    }

    #[test]
    fn raw_audit_hash_alg_is_preserved_without_validation() {
        for alg in [0x0000u16, 0x0010, 0x0012, 0xffff] {
            let data = AuditFixture {
                audit_hash_alg: alg,
                ..AuditFixture::default()
            }
            .bytes();
            assert_eq!(
                parse(&data, 5).unwrap().audit_hash_alg,
                alg,
                "alg {alg:#06x}"
            );
        }
    }

    #[test]
    fn counters_and_firmware_versions_are_read_big_endian() {
        let data = AuditFixture {
            audit_counter: 0x0102_0304_0506_0708,
            algorithm_set: 0x0a0b_0c0d,
            firmware_v1: 0x1a1b_1c1d,
            firmware_v2: 0x2a2b_2c2d,
            time_epoch: 0x3a3b_3c3d,
            ..AuditFixture::default()
        }
        .bytes();
        let parsed = parse(&data, 5).unwrap();
        assert_eq!(parsed.audit_counter, 0x0102_0304_0506_0708);
        assert_eq!(parsed.algorithm_set, 0x0a0b_0c0d);
        assert_eq!(parsed.firmware_v1, 0x1a1b_1c1d);
        assert_eq!(parsed.firmware_v2, 0x2a2b_2c2d);
        assert_eq!(parsed.time_epoch, 0x3a3b_3c3d);
    }

    #[test]
    fn clocksize_four_is_accepted() {
        assert!(parse(&AuditFixture::default().bytes(), 5).is_ok());
    }

    #[test]
    fn invalid_clock_sizes_are_bad_parameter() {
        for clocksize in [0u8, 1, 3, 5, 8, 0xff] {
            let data = AuditFixture {
                clocksize,
                ..AuditFixture::default()
            }
            .bytes();
            let error = parse(&data, 5).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::InvalidClockSize {
                    actual: clocksize,
                    expected: 4,
                },
                "clocksize {clocksize}"
            );
            assert_eq!(error.tpm_result(), TPM_RC_BAD_PARAMETER);
        }
    }

    #[test]
    fn invalid_clocksize_does_not_consume_epoch_bytes() {
        let mut data = AuditFixture {
            clocksize: 8,
            ..AuditFixture::default()
        }
        .bytes();
        data.truncate(data.len() - 4);
        let error = parse(&data, 5).unwrap_err();
        assert_eq!(error.tpm_result(), TPM_RC_BAD_PARAMETER);
    }

    #[test]
    fn every_strict_prefix_is_truncated_and_never_panics() {
        let full = AuditFixture {
            commands: (0..17).collect(),
            audit_hash_alg: 0x000b,
            audit_counter: 7,
            algorithm_set: 8,
            firmware_v1: 9,
            firmware_v2: 10,
            time_epoch: 11,
            ..AuditFixture::default()
        }
        .bytes();
        for version in [4u16, 5] {
            for len in 0..full.len() {
                let error = parse(&full[..len], version).unwrap_err();
                assert_eq!(
                    error.tpm_result(),
                    TPM_RC_INSUFFICIENT,
                    "version {version} prefix length {len} of {}",
                    full.len()
                );
            }
            assert!(parse(&full, version).is_ok());
        }
    }

    #[test]
    fn truncation_sections_distinguish_audit_from_clock_epoch() {
        let full = AuditFixture::default().bytes();
        let audit_cut = full.len() - 5 - 2;
        assert_eq!(
            parse(&full[..audit_cut], 5).unwrap_err(),
            PersistentAllError::Truncated { section: SECTION }
        );
        for cut in [full.len() - 5, full.len() - 2] {
            assert_eq!(
                parse(&full[..cut], 5).unwrap_err(),
                PersistentAllError::Truncated {
                    section: EPOCH_SECTION
                },
                "cut {cut}"
            );
        }
    }

    #[test]
    fn remainder_begins_exactly_at_the_compat_tail_sentinel() {
        let data = AuditFixture {
            tail: vec![0x01, 0x00, 0x2a],
            ..AuditFixture::default()
        }
        .bytes();
        let parsed = parse(&data, 5).unwrap();
        assert_eq!(parsed.remaining, &[0x01, 0x00, 0x2a]);
        assert!(core::ptr::eq(
            parsed.remaining.as_ptr(),
            data[data.len() - 3..].as_ptr()
        ));
    }

    #[test]
    fn malformed_input_never_panics() {
        for version in [0u16, 4, 5, 0xffff] {
            for len in 0..8usize {
                for byte in [0x00u8, 0x11, 0xff] {
                    let _ = parse(&vec![byte; len], version);
                }
            }
            let full = AuditFixture::default().bytes();
            for index in 0..full.len() {
                for byte in [0x00u8, 0x12, 0xff] {
                    let mut data = full.clone();
                    data[index] = byte;
                    let _ = parse(&data, version);
                }
            }
        }
    }
}
