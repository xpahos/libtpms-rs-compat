use super::command::{command_bitmap_index, upstream_implements};
use super::command_bitmap::{COMMAND_COUNT, parse_command_bitmap};
use super::marshal::BlobReader;
use super::nv::command_bitmap_image;
use super::persistent::{PersistentAllError, StateSection};
use super::runtime::Tpm2Runtime;

pub(super) const PP_LIST_SIZE: usize = COMMAND_COUNT.div_ceil(8);

const SECTION: StateSection = StateSection::PpList;

pub(super) fn physical_presence_is_required(runtime: &Tpm2Runtime, code: u32) -> bool {
    if !upstream_implements(code) {
        return false;
    }
    let Some(index) = command_bitmap_index(code) else {
        return false;
    };
    let Some(state) = runtime.state.as_ref() else {
        return false;
    };
    command_bitmap_image(&state.persistent.pp_list, PP_LIST_SIZE).is_ok_and(|bitmap| {
        bitmap
            .get(index / 8)
            .is_some_and(|byte| byte & (1 << (index % 8)) != 0)
    })
}

#[cfg(test)]
pub(in crate::library) fn require_physical_presence(runtime: &mut Tpm2Runtime, code: u32) {
    use super::persistent::OwnedCommandBitmap;
    let index = command_bitmap_index(code).expect("a command inside the bitmap range");
    let state = runtime.state.as_mut().expect("a decoded persistent state");
    let mut bytes =
        command_bitmap_image(&state.persistent.pp_list, PP_LIST_SIZE).expect("a pp-list image");
    bytes[index / 8] |= 1 << (index % 8);
    state.persistent.pp_list = OwnedCommandBitmap {
        compressed: false,
        bytes,
    };
}

#[cfg(test)]
fn truncated() -> PersistentAllError {
    PersistentAllError::Truncated { section: SECTION }
}

#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct PpList<'a> {
    pub(super) compressed: bool,
    pub(super) array: &'a [u8],
    pub(super) remaining: &'a [u8],
}

pub(super) fn parse_pp_list(
    input: &[u8],
    blob_version: u16,
) -> Result<PpList<'_>, PersistentAllError> {
    let mut reader = BlobReader::new(input);
    let (compressed, array) =
        parse_command_bitmap(&mut reader, blob_version, SECTION, PP_LIST_SIZE)?;
    Ok(PpList {
        compressed,
        array,
        remaining: reader.remaining(),
    })
}

#[cfg(test)]
pub(super) struct PpListFixture {
    pub(super) size: Option<u16>,
    pub(super) array: Vec<u8>,
    pub(super) tail: Vec<u8>,
}

#[cfg(test)]
impl Default for PpListFixture {
    fn default() -> Self {
        Self {
            size: None,
            array: vec![0x00; PP_LIST_SIZE],
            tail: Vec::new(),
        }
    }
}

#[cfg(test)]
impl PpListFixture {
    pub(super) fn bytes(&self) -> Vec<u8> {
        let size = self
            .size
            .unwrap_or_else(|| u16::try_from(self.array.len()).unwrap());
        let mut out = Vec::new();
        out.extend_from_slice(&size.to_be_bytes());
        out.extend_from_slice(&self.array);
        out.extend_from_slice(&self.tail);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::constants::{TPM_RC_INSUFFICIENT, TPM_RC_SIZE};

    const RAW_VERSIONS: [u16; 3] = [5, 6, 0xffff];
    const COMPRESSED_VERSIONS: [u16; 5] = [0, 1, 2, 3, 4];

    fn parse(input: &[u8], blob_version: u16) -> Result<PpList<'_>, PersistentAllError> {
        parse_pp_list(input, blob_version)
    }

    #[test]
    fn hand_built_fixture_matches_the_upstream_marshal_order() {
        let mut fixture = vec![0x00, 0x11];
        let array: Vec<u8> = (1..=17).collect();
        fixture.extend_from_slice(&array);
        fixture.extend_from_slice(&[0xfa, 0x17]);
        let parsed = parse(&fixture, 5).unwrap();
        assert!(!parsed.compressed);
        assert_eq!(parsed.array, &array[..]);
        assert_eq!(parsed.remaining, &[0xfa, 0x17]);
    }

    #[test]
    fn every_size_up_to_the_array_capacity_is_valid_for_raw_blobs() {
        for version in RAW_VERSIONS {
            for size in 0..=PP_LIST_SIZE {
                let data = PpListFixture {
                    array: vec![0x5a; size],
                    ..PpListFixture::default()
                }
                .bytes();
                let parsed = parse(&data, version)
                    .unwrap_or_else(|error| panic!("version {version} size {size}: {error:?}"));
                assert_eq!(parsed.array.len(), size, "version {version} size {size}");
                assert!(!parsed.compressed);
            }
        }
    }

    #[test]
    fn capacity_plus_one_is_a_size_error_for_raw_blobs() {
        for version in RAW_VERSIONS {
            for size in [PP_LIST_SIZE + 1, 100, usize::from(u16::MAX)] {
                let data = PpListFixture {
                    array: vec![0x5a; size],
                    ..PpListFixture::default()
                }
                .bytes();
                let error = parse(&data, version).unwrap_err();
                assert_eq!(
                    error,
                    PersistentAllError::CommandArraySizeExceeded {
                        section: SECTION,
                        actual: size as u16,
                        maximum: PP_LIST_SIZE,
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
    fn compressed_blobs_accept_any_size_the_input_carries() {
        for version in COMPRESSED_VERSIONS {
            for size in [0usize, 1, 14, PP_LIST_SIZE, PP_LIST_SIZE + 1, 100, 5000] {
                let data = PpListFixture {
                    array: vec![0xff; size],
                    tail: vec![0xdd],
                    ..PpListFixture::default()
                }
                .bytes();
                let parsed = parse(&data, version)
                    .unwrap_or_else(|error| panic!("version {version} size {size}: {error:?}"));
                assert!(parsed.compressed, "version {version} size {size}");
                assert_eq!(parsed.array.len(), size);
                assert_eq!(parsed.remaining, &[0xdd]);
            }
        }
    }

    #[test]
    fn version_gate_matches_the_upstream_comparison() {
        let data = PpListFixture::default().bytes();
        assert!(parse(&data, 4).unwrap().compressed);
        assert!(!parse(&data, 5).unwrap().compressed);
    }

    #[test]
    fn truncated_size_field_is_insufficient() {
        for version in [4u16, 5] {
            for len in 0..2usize {
                let data = vec![0x00; len];
                let error = parse(&data, version).unwrap_err();
                assert_eq!(error, truncated(), "version {version} length {len}");
                assert_eq!(error.tpm_result(), TPM_RC_INSUFFICIENT);
            }
        }
    }

    #[test]
    fn truncated_array_is_insufficient_on_both_paths() {
        for (version, size) in [(5u16, PP_LIST_SIZE), (4, 40)] {
            let full = PpListFixture {
                array: vec![0x77; size],
                ..PpListFixture::default()
            }
            .bytes();
            for len in 2..full.len() {
                let error = parse(&full[..len], version).unwrap_err();
                assert_eq!(error, truncated(), "version {version} prefix {len}");
                assert_eq!(error.tpm_result(), TPM_RC_INSUFFICIENT);
            }
        }
    }

    #[test]
    fn every_strict_prefix_of_a_valid_array_fails_safely() {
        let full = PpListFixture {
            array: (0..17).collect(),
            ..PpListFixture::default()
        }
        .bytes();
        for version in [4u16, 5] {
            for len in 0..full.len() {
                assert_eq!(
                    parse(&full[..len], version).unwrap_err(),
                    truncated(),
                    "version {version} prefix length {len} of {}",
                    full.len()
                );
            }
            assert!(parse(&full, version).is_ok());
        }
    }

    #[test]
    fn all_bit_patterns_are_preserved_verbatim() {
        for array in [vec![0xff; 17], vec![0xa5; 17], (0x80..0x91).collect()] {
            let data = PpListFixture {
                array: array.clone(),
                ..PpListFixture::default()
            }
            .bytes();
            let parsed = parse(&data, 5).unwrap();
            assert_eq!(parsed.array, &array[..], "array {array:02x?}");
        }
    }

    #[test]
    fn array_borrows_the_original_blob() {
        let data = PpListFixture {
            array: vec![0x42; 17],
            ..PpListFixture::default()
        }
        .bytes();
        let parsed = parse(&data, 5).unwrap();
        assert!(
            core::ptr::eq(parsed.array.as_ptr(), data[2..].as_ptr()),
            "the array must borrow the input, not copy it"
        );
    }

    #[test]
    fn remainder_begins_exactly_at_the_failed_tries_sentinel() {
        let data = PpListFixture {
            tail: vec![0xde, 0xad, 0xbe],
            ..PpListFixture::default()
        }
        .bytes();
        let parsed = parse(&data, 5).unwrap();
        assert_eq!(parsed.remaining, &[0xde, 0xad, 0xbe]);
        assert!(core::ptr::eq(
            parsed.remaining.as_ptr(),
            data[data.len() - 3..].as_ptr()
        ));
    }

    #[test]
    fn exact_end_array_read_succeeds() {
        let data = PpListFixture::default().bytes();
        let parsed = parse(&data, 5).unwrap();
        assert_eq!(parsed.array.len(), PP_LIST_SIZE);
        assert_eq!(parsed.remaining, &[] as &[u8]);
    }

    #[test]
    fn malformed_input_never_panics() {
        for version in [0u16, 4, 5, 0xffff] {
            for len in 0..6usize {
                for byte in [0x00u8, 0x11, 0xff] {
                    let _ = parse(&vec![byte; len], version);
                }
            }
            let full = PpListFixture::default().bytes();
            for index in 0..full.len() {
                for byte in [0x00u8, 0x12, 0xff] {
                    let mut data = full.clone();
                    data[index] = byte;
                    let _ = parse(&data, version);
                }
            }
        }
    }

    #[test]
    fn the_capability_and_the_authorization_gate_share_one_membership_decision() {
        use super::super::capability::TPM_CAP_PP_COMMANDS;
        use super::super::capability::single::lookup;
        use super::super::golden_responses::policy_sessions::vector;
        use super::super::restore_permanent_blob_for_test;

        const CLEAR_CONTROL: u32 = 0x0000_0127;
        const CHANGE_EPS: u32 = 0x0000_0124;
        const UNIMPLEMENTED: u32 = 0x0000_0179;
        const PP_COMMANDS: u32 = 0x0000_012d;

        let mut runtime = restore_permanent_blob_for_test(vector("PERMALL_READY"))
            .expect("the oracle permanent state restores");
        assert!(
            physical_presence_is_required(&runtime, PP_COMMANDS),
            "the reference ships TPM2_PP_Commands in the pp-list"
        );
        for code in [CLEAR_CONTROL, CHANGE_EPS, UNIMPLEMENTED] {
            assert!(!physical_presence_is_required(&runtime, code));
            assert_eq!(
                lookup(&runtime, TPM_CAP_PP_COMMANDS, code),
                Ok(Vec::new()),
                "code {code:#x} is absent from an empty pp-list"
            );
        }

        require_physical_presence(&mut runtime, CLEAR_CONTROL);
        assert!(physical_presence_is_required(&runtime, CLEAR_CONTROL));
        assert_eq!(
            lookup(&runtime, TPM_CAP_PP_COMMANDS, CLEAR_CONTROL),
            Ok(CLEAR_CONTROL.to_be_bytes().to_vec())
        );
        assert!(!physical_presence_is_required(&runtime, CHANGE_EPS));
        assert_eq!(
            lookup(&runtime, TPM_CAP_PP_COMMANDS, CHANGE_EPS),
            Ok(Vec::new())
        );

        require_physical_presence(&mut runtime, CHANGE_EPS);
        for code in 0x0000_011eu32..=0x0000_019d {
            let listed = physical_presence_is_required(&runtime, code);
            let reported = lookup(&runtime, TPM_CAP_PP_COMMANDS, code)
                .expect("the capability lookup answers")
                != Vec::<u8>::new();
            assert_eq!(listed, reported, "code {code:#x}");
            assert_eq!(
                listed,
                matches!(code, CLEAR_CONTROL | CHANGE_EPS | PP_COMMANDS),
                "code {code:#x}"
            );
        }
    }
}
