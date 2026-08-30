use crate::library::tpm2::marshal::BlobReader;
use crate::library::tpm2::persistent::{PersistentAllError, StateSection};

pub(in crate::library::tpm2) const HASH_COUNT: usize = 4;

pub(in crate::library::tpm2) const PCR_SELECT_MIN: usize = 3;
pub(in crate::library::tpm2) const PCR_SELECT_MAX: usize = 3;

const TPM_ALG_SHA1: u16 = 0x0004;
const TPM_ALG_SHA256: u16 = 0x000b;
const TPM_ALG_SHA384: u16 = 0x000c;
const TPM_ALG_SHA512: u16 = 0x000d;

const COMPILED_HASH_ALGORITHMS: [u16; HASH_COUNT] =
    [TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512];

const SECTION: StateSection = StateSection::PcrAllocation;

fn truncated() -> PersistentAllError {
    PersistentAllError::Truncated { section: SECTION }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) struct PcrSelection<'a> {
    pub(in crate::library::tpm2) hash_alg: u16,
    pub(in crate::library::tpm2) select: &'a [u8],
}

#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::library::tpm2) struct PcrAllocation<'a> {
    pub(in crate::library::tpm2) declared_count: u32,
    pub(in crate::library::tpm2) selections: [PcrSelection<'a>; HASH_COUNT],
    pub(in crate::library::tpm2) remaining: &'a [u8],
}

pub(in crate::library::tpm2) fn parse_pcr_allocation(
    input: &[u8],
) -> Result<PcrAllocation<'_>, PersistentAllError> {
    let mut reader = BlobReader::new(input);

    let declared_count = reader.read_u32().map_err(|_| truncated())?;
    if declared_count > HASH_COUNT as u32 {
        return Err(PersistentAllError::ListCountExceeded {
            section: SECTION,
            actual: declared_count,
            maximum: HASH_COUNT,
        });
    }

    let mut selections = [PcrSelection {
        hash_alg: 0,
        select: &[],
    }; HASH_COUNT];
    for entry in selections.iter_mut().take(declared_count as usize) {
        *entry = parse_pcr_selection(&mut reader)?;
    }

    Ok(PcrAllocation {
        declared_count,
        selections,
        remaining: reader.remaining(),
    })
}

fn parse_pcr_selection<'a>(
    reader: &mut BlobReader<'a>,
) -> Result<PcrSelection<'a>, PersistentAllError> {
    let hash_alg = reader.read_u16().map_err(|_| truncated())?;
    if !COMPILED_HASH_ALGORITHMS.contains(&hash_alg) {
        return Err(PersistentAllError::InvalidHashAlgorithm {
            section: SECTION,
            actual: hash_alg,
        });
    }

    let sizeof_select = reader.read_u8().map_err(|_| truncated())?;
    if usize::from(sizeof_select) < PCR_SELECT_MIN || usize::from(sizeof_select) > PCR_SELECT_MAX {
        return Err(PersistentAllError::InvalidPcrSelectSize {
            actual: sizeof_select,
            minimum: PCR_SELECT_MIN,
            maximum: PCR_SELECT_MAX,
        });
    }

    let select = reader
        .take(usize::from(sizeof_select))
        .map_err(|_| truncated())?;
    Ok(PcrSelection { hash_alg, select })
}

#[cfg(test)]
pub(in crate::library::tpm2) struct PcrAllocationFixture {
    pub(in crate::library::tpm2) count: Option<u32>,
    pub(in crate::library::tpm2) selections: Vec<(u16, u8, Vec<u8>)>,
    pub(in crate::library::tpm2) tail: Vec<u8>,
}

#[cfg(test)]
impl Default for PcrAllocationFixture {
    fn default() -> Self {
        Self {
            count: None,
            selections: vec![(TPM_ALG_SHA256, 3, vec![0x00, 0x00, 0x00])],
            tail: Vec::new(),
        }
    }
}

#[cfg(test)]
impl PcrAllocationFixture {
    pub(in crate::library::tpm2) fn bytes(&self) -> Vec<u8> {
        let count = self
            .count
            .unwrap_or_else(|| u32::try_from(self.selections.len()).unwrap());
        let mut out = Vec::new();
        out.extend_from_slice(&count.to_be_bytes());
        for (hash, sizeof_select, bitmap) in &self.selections {
            out.extend_from_slice(&hash.to_be_bytes());
            out.push(*sizeof_select);
            out.extend_from_slice(bitmap);
        }
        out.extend_from_slice(&self.tail);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::constants::{TPM_RC_HASH, TPM_RC_INSUFFICIENT, TPM_RC_SIZE, TPM_RC_VALUE};

    const TPM_ALG_NULL: u16 = 0x0010;
    const TPM_ALG_SM3_256: u16 = 0x0012;
    const TPM_ALG_SHA3_256: u16 = 0x0027;

    fn parse(input: &[u8]) -> Result<PcrAllocation<'_>, PersistentAllError> {
        parse_pcr_allocation(input)
    }

    #[test]
    fn hand_built_fixture_upstream_marshal_order_parity() {
        let fixture = [
            0x00, 0x00, 0x00, 0x01, 0x00, 0x0b, 0x03, 0x00, 0x00, 0x00, 0x99, 0x98,
        ];
        let parsed = parse(&fixture).unwrap();
        assert_eq!(parsed.declared_count, 1);
        assert_eq!(
            parsed.selections[0],
            PcrSelection {
                hash_alg: TPM_ALG_SHA256,
                select: &[0x00, 0x00, 0x00],
            }
        );
        assert_eq!(parsed.remaining, &[0x99, 0x98]);
    }

    #[test]
    fn zero_count_no_entry_read() {
        let data = PcrAllocationFixture {
            selections: Vec::new(),
            tail: vec![0xaa, 0xbb],
            ..PcrAllocationFixture::default()
        }
        .bytes();
        let parsed = parse(&data).unwrap();
        assert_eq!(parsed.declared_count, 0);
        assert_eq!(parsed.remaining, &[0xaa, 0xbb]);
    }

    #[test]
    fn count_range_validity() {
        for count in 1..=HASH_COUNT {
            let data = PcrAllocationFixture {
                selections: vec![(TPM_ALG_SHA256, 3, vec![0x00; 3]); count],
                ..PcrAllocationFixture::default()
            }
            .bytes();
            let parsed = parse(&data).unwrap_or_else(|error| panic!("count {count}: {error:?}"));
            assert_eq!(parsed.declared_count, count as u32);
        }
    }

    #[test]
    fn oversized_count_size_error_before_entry_read() {
        for count in [5u32, 100, u32::MAX] {
            let data = PcrAllocationFixture {
                count: Some(count),
                selections: vec![(0xffff, 0xff, vec![0xff; 3]); 5],
                ..PcrAllocationFixture::default()
            }
            .bytes();
            let error = parse(&data).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::ListCountExceeded {
                    section: SECTION,
                    actual: count,
                    maximum: HASH_COUNT,
                },
                "count {count}"
            );
            assert_eq!(error.tpm_result(), TPM_RC_SIZE);
        }
    }

    #[test]
    fn attacker_controlled_count_safety() {
        let data = u32::MAX.to_be_bytes();
        assert_eq!(parse(&data).unwrap_err().tpm_result(), TPM_RC_SIZE);
    }

    #[test]
    fn truncated_count_insufficiency() {
        for len in 0..4usize {
            let data = vec![0x00; len];
            let error = parse(&data).unwrap_err();
            assert_eq!(error, truncated(), "length {len}");
            assert_eq!(error.tpm_result(), TPM_RC_INSUFFICIENT);
        }
    }

    #[test]
    fn count_beyond_entry_data_insufficiency() {
        let data = PcrAllocationFixture {
            count: Some(4),
            ..PcrAllocationFixture::default()
        }
        .bytes();
        assert_eq!(parse(&data).unwrap_err(), truncated());
    }

    #[test]
    fn compiled_hash_algorithm_acceptance_preservation() {
        for alg in COMPILED_HASH_ALGORITHMS {
            let data = PcrAllocationFixture {
                selections: vec![(alg, 3, vec![0x00; 3])],
                tail: vec![0x77],
                ..PcrAllocationFixture::default()
            }
            .bytes();
            let parsed = parse(&data).unwrap_or_else(|error| panic!("alg {alg:#06x}: {error:?}"));
            assert_eq!(parsed.selections[0].hash_alg, alg, "alg {alg:#06x}");
            assert_eq!(parsed.remaining, &[0x77], "alg {alg:#06x}");
        }
    }

    #[test]
    fn invalid_hash_algorithm_hash_code_rejection() {
        for alg in [
            0x0000u16,
            TPM_ALG_NULL,
            TPM_ALG_SM3_256,
            TPM_ALG_SHA3_256,
            0xffff,
        ] {
            let data = PcrAllocationFixture {
                selections: vec![(alg, 3, vec![0x00; 3])],
                ..PcrAllocationFixture::default()
            }
            .bytes();
            let error = parse(&data).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::InvalidHashAlgorithm {
                    section: SECTION,
                    actual: alg,
                },
                "alg {alg:#06x}"
            );
            assert_eq!(error.tpm_result(), TPM_RC_HASH, "alg {alg:#06x}");
        }
    }

    #[test]
    fn truncated_hash_algorithm_insufficiency() {
        let data = [0x00, 0x00, 0x00, 0x01, 0x00];
        assert_eq!(parse(&data).unwrap_err(), truncated());
    }

    #[test]
    fn sizeof_select_three_acceptance() {
        assert!(parse(&PcrAllocationFixture::default().bytes()).is_ok());
    }

    #[test]
    fn out_of_range_sizeof_select_value_error_no_bitmap_read() {
        for size in [0u8, 1, 2, 4, 255] {
            let data = PcrAllocationFixture {
                selections: vec![(TPM_ALG_SHA256, size, Vec::new())],
                ..PcrAllocationFixture::default()
            }
            .bytes();
            let error = parse(&data).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::InvalidPcrSelectSize {
                    actual: size,
                    minimum: PCR_SELECT_MIN,
                    maximum: PCR_SELECT_MAX,
                },
                "size {size}"
            );
            assert_eq!(error.tpm_result(), TPM_RC_VALUE, "size {size}");
        }
    }

    #[test]
    fn invalid_sizeof_select_no_trailing_consumption() {
        let data = PcrAllocationFixture {
            selections: vec![(TPM_ALG_SHA256, 4, vec![0xde, 0xad, 0xbe, 0xef])],
            ..PcrAllocationFixture::default()
        }
        .bytes();
        assert_eq!(parse(&data).unwrap_err().tpm_result(), TPM_RC_VALUE);
    }

    #[test]
    fn truncated_sizeof_select_insufficiency() {
        let data = [0x00, 0x00, 0x00, 0x01, 0x00, 0x0b];
        assert_eq!(parse(&data).unwrap_err(), truncated());
    }

    #[test]
    fn bitmap_pattern_verbatim_acceptance() {
        for bitmap in [[0x00u8; 3], [0xff; 3], [0xa5, 0x3c, 0x81]] {
            let data = PcrAllocationFixture {
                selections: vec![(TPM_ALG_SHA1, 3, bitmap.to_vec())],
                ..PcrAllocationFixture::default()
            }
            .bytes();
            let parsed = parse(&data).unwrap();
            assert_eq!(parsed.selections[0].select, &bitmap, "bitmap {bitmap:02x?}");
        }
    }

    #[test]
    fn exact_end_bitmap_read_success() {
        let data = PcrAllocationFixture::default().bytes();
        let parsed = parse(&data).unwrap();
        assert_eq!(parsed.selections[0].select.len(), 3);
        assert_eq!(parsed.remaining, &[] as &[u8]);
    }

    #[test]
    fn truncated_bitmap_insufficiency() {
        for len in 0..3usize {
            let data = PcrAllocationFixture {
                selections: vec![(TPM_ALG_SHA256, 3, vec![0x11; len])],
                ..PcrAllocationFixture::default()
            }
            .bytes();
            let error = parse(&data).unwrap_err();
            assert_eq!(error, truncated(), "bitmap length {len}");
            assert_eq!(error.tpm_result(), TPM_RC_INSUFFICIENT);
        }
    }

    #[test]
    fn bitmap_original_blob_borrow() {
        let data = PcrAllocationFixture {
            selections: vec![(TPM_ALG_SHA512, 3, vec![0x01, 0x02, 0x03])],
            ..PcrAllocationFixture::default()
        }
        .bytes();
        let parsed = parse(&data).unwrap();
        assert_eq!(parsed.selections[0].select, &[0x01, 0x02, 0x03]);
        assert!(
            core::ptr::eq(parsed.selections[0].select.as_ptr(), data[7..].as_ptr()),
            "the bitmap must borrow the input, not copy it"
        );
    }

    #[test]
    fn four_entry_input_order_and_duplicate_preservation() {
        let entries = [
            (TPM_ALG_SHA512, [0x01, 0x00, 0x00]),
            (TPM_ALG_SHA256, [0x02, 0x00, 0x00]),
            (TPM_ALG_SHA256, [0x03, 0x00, 0x00]),
            (TPM_ALG_SHA1, [0x04, 0x00, 0x00]),
        ];
        let data = PcrAllocationFixture {
            selections: entries
                .iter()
                .map(|(alg, bitmap)| (*alg, 3, bitmap.to_vec()))
                .collect(),
            tail: vec![0x55],
            ..PcrAllocationFixture::default()
        }
        .bytes();
        let parsed = parse(&data).unwrap();
        assert_eq!(parsed.declared_count, 4);
        for (index, (alg, bitmap)) in entries.iter().enumerate() {
            assert_eq!(
                parsed.selections[index],
                PcrSelection {
                    hash_alg: *alg,
                    select: bitmap,
                },
                "entry {index}"
            );
        }
        assert_eq!(parsed.remaining, &[0x55]);
    }

    #[test]
    fn partial_entry_count_acceptance() {
        for count in [1usize, 2, 3] {
            let data = PcrAllocationFixture {
                selections: vec![(TPM_ALG_SHA384, 3, vec![0x00; 3]); count],
                ..PcrAllocationFixture::default()
            }
            .bytes();
            assert_eq!(
                parse(&data).unwrap().declared_count,
                count as u32,
                "count {count}"
            );
        }
    }

    #[test]
    fn later_entry_error_propagation() {
        let data = PcrAllocationFixture {
            selections: vec![
                (TPM_ALG_SHA1, 3, vec![0x00; 3]),
                (TPM_ALG_NULL, 3, vec![0x00; 3]),
            ],
            ..PcrAllocationFixture::default()
        }
        .bytes();
        assert_eq!(parse(&data).unwrap_err().tpm_result(), TPM_RC_HASH);
    }

    #[test]
    fn remainder_pp_list_sentinel_boundary() {
        let data = PcrAllocationFixture {
            tail: vec![0xde, 0xad, 0xbe],
            ..PcrAllocationFixture::default()
        }
        .bytes();
        let parsed = parse(&data).unwrap();
        assert_eq!(parsed.remaining, &[0xde, 0xad, 0xbe]);
        assert!(core::ptr::eq(
            parsed.remaining.as_ptr(),
            data[data.len() - 3..].as_ptr()
        ));
    }

    #[test]
    fn strict_prefix_rejection_safety() {
        let full = PcrAllocationFixture {
            selections: vec![
                (TPM_ALG_SHA1, 3, vec![0xff; 3]),
                (TPM_ALG_SHA512, 3, vec![0x0f; 3]),
            ],
            ..PcrAllocationFixture::default()
        }
        .bytes();
        for len in 0..full.len() {
            let error = parse(&full[..len]).unwrap_err();
            assert_eq!(
                error.tpm_result(),
                TPM_RC_INSUFFICIENT,
                "prefix length {len} of {}",
                full.len()
            );
        }
        assert!(parse(&full).is_ok());
    }

    #[test]
    fn pcr_selection_byte_mutation_panic_safety() {
        for len in 0..12usize {
            for byte in [0x00u8, 0x03, 0x0b, 0xff] {
                let _ = parse(&vec![byte; len]);
            }
        }
        let full = PcrAllocationFixture::default().bytes();
        for index in 0..full.len() {
            for byte in [0x00u8, 0x04, 0xff] {
                let mut data = full.clone();
                data[index] = byte;
                let _ = parse(&data);
            }
        }
    }
}
