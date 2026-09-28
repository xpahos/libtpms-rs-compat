// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/NVDynamic.c
// - libtpms/src/tpm2/NVMarshal.c
//
// Original upstream authors and copyright notices:
// Written by Ken Goldman
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corp. and others, 2016 - 2023
// Written by Stefan Berger
// (c) Copyright IBM Corporation 2017,2018.
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use crate::library::tpm2::marshal::{BlobReader, BlockSkipError, skip_optional_block};
use crate::library::tpm2::persistent::{PersistentAllError, StateSection, parse_nv_header};

pub(in crate::library::tpm2) const INDEX_ORDERLY_RAM_MAGIC: u32 = 0x5346_feab;
const INDEX_ORDERLY_RAM_VERSION: u16 = 2;

pub(in crate::library::tpm2) const RAM_INDEX_SPACE: u64 = 512;
pub(in crate::library::tpm2) const NV_RAM_HEADER_SIZE: u64 = 12;

use super::attributes::TPMA_NV_RESERVED;

const BLOCK_SKIP_SINCE_VERSION: u16 = 2;

const SECTION: StateSection = StateSection::IndexOrderlyRam;

fn truncated() -> PersistentAllError {
    PersistentAllError::Truncated { section: SECTION }
}

fn capacity_exceeded(needed: u64) -> PersistentAllError {
    PersistentAllError::DestinationCapacityExceeded {
        section: SECTION,
        needed,
        capacity: RAM_INDEX_SPACE,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) struct OrderlyRamEntry<'a> {
    pub(in crate::library::tpm2) declared_size: u32,
    pub(in crate::library::tpm2) handle: u32,
    pub(in crate::library::tpm2) attributes: u32,
    pub(in crate::library::tpm2) data: &'a [u8],
}

impl OrderlyRamEntry<'_> {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(in crate::library::tpm2) fn destination_size(&self) -> u64 {
        NV_RAM_HEADER_SIZE + self.data.len() as u64
    }
}

#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::library::tpm2) struct IndexOrderlyRam<'a> {
    pub(in crate::library::tpm2) sourceside_size: u32,
    pub(in crate::library::tpm2) entries: Vec<OrderlyRamEntry<'a>>,
    pub(in crate::library::tpm2) terminated: bool,
    pub(in crate::library::tpm2) remaining: &'a [u8],
}

pub(in crate::library::tpm2) fn parse_index_orderly_ram(
    input: &[u8],
) -> Result<IndexOrderlyRam<'_>, PersistentAllError> {
    let mut reader = BlobReader::new(input);

    let header = parse_nv_header(
        &mut reader,
        SECTION,
        INDEX_ORDERLY_RAM_MAGIC,
        INDEX_ORDERLY_RAM_VERSION,
    )?;
    let sourceside_size = reader.read_u32().map_err(|_| truncated())?;

    let mut entries = Vec::new();
    let mut offset: u64 = 0;
    let mut terminated = false;
    loop {
        if offset + NV_RAM_HEADER_SIZE > u64::from(sourceside_size) {
            break;
        }
        if offset + 4 > RAM_INDEX_SPACE {
            return Err(capacity_exceeded(offset + 4));
        }
        let declared_size = reader.read_u32().map_err(|_| truncated())?;
        if declared_size == 0 {
            terminated = true;
            break;
        }
        if offset + NV_RAM_HEADER_SIZE > RAM_INDEX_SPACE {
            return Err(capacity_exceeded(offset + NV_RAM_HEADER_SIZE));
        }
        let handle = reader.read_u32().map_err(|_| truncated())?;
        let attributes = reader.read_u32().map_err(|_| truncated())?;
        if attributes & TPMA_NV_RESERVED != 0 {
            return Err(PersistentAllError::ReservedBitsSet {
                section: SECTION,
                actual: attributes,
            });
        }
        let datasize = reader.read_u16().map_err(|_| truncated())?;
        let needed = offset + NV_RAM_HEADER_SIZE + u64::from(datasize);
        if needed > RAM_INDEX_SPACE {
            return Err(capacity_exceeded(needed));
        }
        let data = reader
            .take(usize::from(datasize))
            .map_err(|_| truncated())?;
        entries.push(OrderlyRamEntry {
            declared_size,
            handle,
            attributes,
            data,
        });
        offset = needed;
    }

    if header.version >= BLOCK_SKIP_SINCE_VERSION {
        skip_optional_block(&mut reader, false).map_err(|error| match error {
            BlockSkipError::Truncated => truncated(),
            BlockSkipError::MissingRequiredBlock => {
                PersistentAllError::MissingRequiredBlock { section: SECTION }
            }
        })?;
    }

    Ok(IndexOrderlyRam {
        sourceside_size,
        entries,
        terminated,
        remaining: reader.remaining(),
    })
}

#[cfg(test)]
pub(in crate::library::tpm2) struct IndexOrderlyRamFixture {
    pub(in crate::library::tpm2) version: u16,
    pub(in crate::library::tpm2) magic: u32,
    pub(in crate::library::tpm2) sourceside_size: u32,
    pub(in crate::library::tpm2) entries: Vec<(u32, u32, u32, u16, Vec<u8>)>,
    pub(in crate::library::tpm2) terminator: bool,
    pub(in crate::library::tpm2) future_block: Option<(u8, u16, Vec<u8>)>,
    pub(in crate::library::tpm2) tail: Vec<u8>,
}

#[cfg(test)]
impl Default for IndexOrderlyRamFixture {
    fn default() -> Self {
        Self {
            version: INDEX_ORDERLY_RAM_VERSION,
            magic: INDEX_ORDERLY_RAM_MAGIC,
            sourceside_size: RAM_INDEX_SPACE as u32,
            entries: Vec::new(),
            terminator: true,
            future_block: Some((1, 0, Vec::new())),
            tail: Vec::new(),
        }
    }
}

#[cfg(test)]
impl IndexOrderlyRamFixture {
    pub(in crate::library::tpm2) fn entry(
        handle: u32,
        attributes: u32,
        data: &[u8],
    ) -> (u32, u32, u32, u16, Vec<u8>) {
        (
            NV_RAM_HEADER_SIZE as u32 + data.len() as u32,
            handle,
            attributes,
            data.len() as u16,
            data.to_vec(),
        )
    }

    pub(in crate::library::tpm2) fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.magic.to_be_bytes());
        if self.version >= 2 {
            out.extend_from_slice(&1u16.to_be_bytes());
        }
        out.extend_from_slice(&self.sourceside_size.to_be_bytes());
        for (size, handle, attributes, datasize, data) in &self.entries {
            out.extend_from_slice(&size.to_be_bytes());
            out.extend_from_slice(&handle.to_be_bytes());
            out.extend_from_slice(&attributes.to_be_bytes());
            out.extend_from_slice(&datasize.to_be_bytes());
            out.extend_from_slice(data);
        }
        if self.terminator {
            out.extend_from_slice(&0u32.to_be_bytes());
        }
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
    use crate::library::constants::{TPM_RC_INSUFFICIENT, TPM_RC_RESERVED_BITS, TPM_RC_SIZE};

    const SENTINEL: [u8; 3] = [0xe1, 0xe2, 0xe3];

    fn with_tail() -> IndexOrderlyRamFixture {
        IndexOrderlyRamFixture {
            tail: SENTINEL.to_vec(),
            ..IndexOrderlyRamFixture::default()
        }
    }

    #[test]
    fn empty_ram_image_parse_success() {
        let data = with_tail().bytes();
        let parsed = parse_index_orderly_ram(&data).unwrap();
        assert!(parsed.entries.is_empty());
        assert!(parsed.terminated);
        assert_eq!(parsed.sourceside_size, RAM_INDEX_SPACE as u32);
        assert_eq!(parsed.remaining, &SENTINEL);
    }

    #[test]
    fn valid_entry_wire_order_decode() {
        let data = IndexOrderlyRamFixture {
            entries: vec![
                IndexOrderlyRamFixture::entry(0x0100_0001, 0x0000_0001, &[0xaa; 8]),
                IndexOrderlyRamFixture::entry(0x0100_0002, 0x0400_0000, &[0xbb; 4]),
            ],
            ..with_tail()
        }
        .bytes();
        let parsed = parse_index_orderly_ram(&data).unwrap();
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].handle, 0x0100_0001);
        assert_eq!(parsed.entries[0].data, &[0xaa; 8]);
        assert_eq!(parsed.entries[0].destination_size(), 20);
        assert_eq!(parsed.entries[1].handle, 0x0100_0002);
        assert_eq!(parsed.entries[1].attributes, 0x0400_0000);
        assert!(parsed.terminated);
        assert_eq!(parsed.remaining, &SENTINEL);
        assert!(
            data.as_ptr_range()
                .contains(&parsed.entries[0].data.as_ptr())
        );
    }

    #[test]
    fn declared_entry_size_raw_untrusted_record() {
        let data = IndexOrderlyRamFixture {
            entries: vec![(0xffff_ffff, 0x0100_0003, 0, 2, vec![0x01, 0x02])],
            ..with_tail()
        }
        .bytes();
        let parsed = parse_index_orderly_ram(&data).unwrap();
        assert_eq!(parsed.entries[0].declared_size, 0xffff_ffff);
        assert_eq!(parsed.entries[0].data, &[0x01, 0x02]);
    }

    #[test]
    fn maximum_capacity_image_acceptance() {
        let data = IndexOrderlyRamFixture {
            entries: vec![IndexOrderlyRamFixture::entry(0x0100_0004, 0, &[0x33; 488])],
            ..with_tail()
        }
        .bytes();
        let parsed = parse_index_orderly_ram(&data).unwrap();
        assert_eq!(parsed.entries[0].destination_size(), 500);
        assert!(parsed.terminated);
    }

    #[test]
    fn entry_beyond_capacity_size_error() {
        let data = IndexOrderlyRamFixture {
            entries: vec![IndexOrderlyRamFixture::entry(0x0100_0005, 0, &[0x44; 501])],
            ..IndexOrderlyRamFixture::default()
        }
        .bytes();
        let error = parse_index_orderly_ram(&data).unwrap_err();
        assert_eq!(
            error,
            PersistentAllError::DestinationCapacityExceeded {
                section: StateSection::IndexOrderlyRam,
                needed: 513,
                capacity: RAM_INDEX_SPACE,
            }
        );
        assert_eq!(error.tpm_result(), TPM_RC_SIZE);
    }

    #[test]
    fn accumulated_entries_beyond_capacity_size_error() {
        let data = IndexOrderlyRamFixture {
            entries: vec![
                IndexOrderlyRamFixture::entry(0x0100_0006, 0, &[0x55; 250]),
                IndexOrderlyRamFixture::entry(0x0100_0007, 0, &[0x66; 250]),
            ],
            ..IndexOrderlyRamFixture::default()
        }
        .bytes();
        let error = parse_index_orderly_ram(&data).unwrap_err();
        assert_eq!(error.tpm_result(), TPM_RC_SIZE);
    }

    #[test]
    fn brim_filled_source_no_terminator() {
        let data = IndexOrderlyRamFixture {
            sourceside_size: 20,
            entries: vec![IndexOrderlyRamFixture::entry(0x0100_0008, 0, &[0x77; 8])],
            terminator: false,
            ..with_tail()
        }
        .bytes();
        let parsed = parse_index_orderly_ram(&data).unwrap();
        assert_eq!(parsed.entries.len(), 1);
        assert!(!parsed.terminated);
        assert_eq!(parsed.remaining, &SENTINEL);
    }

    #[test]
    fn small_sourceside_size_no_entry_reads() {
        let data = IndexOrderlyRamFixture {
            sourceside_size: 11,
            terminator: false,
            ..with_tail()
        }
        .bytes();
        let parsed = parse_index_orderly_ram(&data).unwrap();
        assert!(parsed.entries.is_empty());
        assert!(!parsed.terminated);
        assert_eq!(parsed.remaining, &SENTINEL);
    }

    #[test]
    fn huge_sourceside_size_no_allocation_no_overread() {
        let data = IndexOrderlyRamFixture {
            sourceside_size: u32::MAX,
            ..with_tail()
        }
        .bytes();
        let parsed = parse_index_orderly_ram(&data).unwrap();
        assert!(parsed.entries.is_empty());
        assert!(parsed.terminated);
    }

    #[test]
    fn reserved_attribute_bits_rejection() {
        for attributes in [0x0000_0100u32, 0x0010_0000, 0x01f0_0300] {
            let data = IndexOrderlyRamFixture {
                entries: vec![IndexOrderlyRamFixture::entry(0x0100_0009, attributes, &[])],
                ..IndexOrderlyRamFixture::default()
            }
            .bytes();
            let error = parse_index_orderly_ram(&data).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::ReservedBitsSet {
                    section: StateSection::IndexOrderlyRam,
                    actual: attributes,
                },
                "attributes {attributes:#010x}"
            );
            assert_eq!(error.tpm_result(), TPM_RC_RESERVED_BITS);
        }
    }

    #[test]
    fn truncation_all_boundaries_insufficiency() {
        let full = IndexOrderlyRamFixture {
            entries: vec![IndexOrderlyRamFixture::entry(0x0100_000a, 1, &[0x88; 5])],
            ..IndexOrderlyRamFixture::default()
        }
        .bytes();
        for len in 0..full.len() {
            let error = parse_index_orderly_ram(&full[..len]).unwrap_err();
            assert_eq!(
                error.tpm_result(),
                TPM_RC_INSUFFICIENT,
                "prefix length {len} of {}",
                full.len()
            );
        }
        assert!(parse_index_orderly_ram(&full).is_ok());
    }

    #[test]
    fn orderly_ram_byte_mutation_panic_safety() {
        let full = IndexOrderlyRamFixture {
            entries: vec![IndexOrderlyRamFixture::entry(0x0100_000b, 1, &[0x99; 5])],
            ..IndexOrderlyRamFixture::default()
        }
        .bytes();
        for index in 0..full.len() {
            for byte in [0x00u8, 0x01, 0xff] {
                let mut data = full.clone();
                data[index] = byte;
                let _ = parse_index_orderly_ram(&data);
            }
        }
    }
}
