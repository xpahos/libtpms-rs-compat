use crate::library::constants::TPM_RC_FAILURE;
use crate::types::TpmResult;

use super::orderly_ram::{IndexOrderlyRam, NV_RAM_HEADER_SIZE, RAM_INDEX_SPACE};

const SPACE: usize = RAM_INDEX_SPACE as usize;
const HEADER: usize = NV_RAM_HEADER_SIZE as usize;
const HANDLE: usize = 4;
const ATTRIBUTES: usize = 8;
const TERMINATOR: usize = 4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) struct OrderlyRamImage(Box<[u8; SPACE]>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) struct RamEntry {
    pub(in crate::library::tpm2) offset: usize,
    pub(in crate::library::tpm2) size: u32,
    pub(in crate::library::tpm2) handle: u32,
}

impl OrderlyRamImage {
    pub(in crate::library::tpm2) fn zeroed() -> Self {
        Self(Box::new([0; SPACE]))
    }

    pub(in crate::library::tpm2) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        <[u8; SPACE]>::try_from(bytes)
            .ok()
            .map(|image| Self(Box::new(image)))
    }

    pub(in crate::library::tpm2) fn from_portable(ram: &IndexOrderlyRam<'_>) -> Option<Self> {
        let mut image = Self::zeroed();
        let mut at = 0usize;
        for entry in &ram.entries {
            let size = HEADER + entry.data.len();
            if at + size > SPACE {
                return None;
            }
            image.put_u32(at, size as u32);
            image.put_u32(at + HANDLE, entry.handle);
            image.put_u32(at + ATTRIBUTES, entry.attributes);
            image.0[at + HEADER..at + size].copy_from_slice(entry.data);
            at += size;
        }
        Some(image)
    }

    pub(in crate::library::tpm2) fn portable_entries(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut at = 0usize;
        loop {
            let size = self.u32_at(at);
            out.extend_from_slice(&size.to_be_bytes());
            if size == 0 {
                break;
            }
            out.extend_from_slice(&self.u32_at(at + HANDLE).to_be_bytes());
            out.extend_from_slice(&self.u32_at(at + ATTRIBUTES).to_be_bytes());
            let size = size as usize;
            if size < HEADER || at.saturating_add(size) > SPACE {
                break;
            }
            let data_size = (size - HEADER) as u16;
            out.extend_from_slice(&data_size.to_be_bytes());
            out.extend_from_slice(&self.0[at + HEADER..at + size]);
            at += size;
            if at + HEADER > SPACE {
                break;
            }
        }
        out
    }

    pub(in crate::library::tpm2) fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    fn u32_at(&self, at: usize) -> u32 {
        u32::from_le_bytes([self.0[at], self.0[at + 1], self.0[at + 2], self.0[at + 3]])
    }

    fn put_u32(&mut self, at: usize, value: u32) {
        self.0[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn entry_at(&self, at: usize) -> Option<RamEntry> {
        if at.checked_add(HEADER).is_none_or(|end| end > SPACE) {
            return None;
        }
        let size = self.u32_at(at);
        (size != 0).then(|| RamEntry {
            offset: at,
            size,
            handle: self.u32_at(at + HANDLE),
        })
    }

    pub(in crate::library::tpm2) fn entries(&self) -> impl Iterator<Item = RamEntry> + '_ {
        let mut at = 0usize;
        core::iter::from_fn(move || {
            let entry = self.entry_at(at)?;
            at = at.saturating_add(entry.size as usize);
            Some(entry)
        })
    }

    fn end(&self) -> usize {
        let mut at = 0usize;
        while let Some(entry) = self.entry_at(at) {
            at = at.saturating_add(entry.size as usize);
        }
        at
    }

    pub(in crate::library::tpm2) fn find(&self, handle: u32) -> Option<RamEntry> {
        self.entries().find(|entry| entry.handle == handle)
    }

    pub(in crate::library::tpm2) fn attributes(&self, entry: RamEntry) -> u32 {
        self.u32_at(entry.offset + ATTRIBUTES)
    }

    pub(in crate::library::tpm2) fn set_attributes(&mut self, entry: RamEntry, attributes: u32) {
        self.put_u32(entry.offset + ATTRIBUTES, attributes);
    }

    fn data_range(entry: RamEntry, offset: usize, size: usize) -> Option<core::ops::Range<usize>> {
        let start = (entry.offset + HEADER).checked_add(offset)?;
        let end = start.checked_add(size)?;
        (end <= SPACE).then_some(start..end)
    }

    pub(in crate::library::tpm2) fn read(
        &self,
        entry: RamEntry,
        offset: usize,
        size: usize,
    ) -> Option<&[u8]> {
        Self::data_range(entry, offset, size).map(|range| &self.0[range])
    }

    pub(in crate::library::tpm2) fn write(
        &mut self,
        entry: RamEntry,
        offset: usize,
        data: &[u8],
    ) -> Option<()> {
        let range = Self::data_range(entry, offset, data.len())?;
        self.0[range].copy_from_slice(data);
        Some(())
    }

    pub(in crate::library::tpm2) fn available(&self) -> u32 {
        (SPACE as i64).wrapping_sub(self.end() as i64) as u32
    }

    pub(in crate::library::tpm2) fn has_room_for(&self, data_size: u64) -> bool {
        u64::from(self.available()) >= NV_RAM_HEADER_SIZE + data_size
    }

    pub(in crate::library::tpm2) fn add(
        &mut self,
        handle: u32,
        attributes: u32,
        data_size: u16,
    ) -> Result<(), TpmResult> {
        let end = self.end();
        let size = HEADER + usize::from(data_size);
        if end.checked_add(size).is_none_or(|last| last > SPACE) {
            return Err(TPM_RC_FAILURE);
        }
        self.put_u32(end, size as u32);
        self.put_u32(end + HANDLE, handle);
        self.put_u32(end + ATTRIBUTES, attributes);
        self.0[end + HEADER..end + size].fill(0);
        let next = end + size;
        if next + TERMINATOR < SPACE {
            self.0[next..next + TERMINATOR].fill(0);
        }
        Ok(())
    }

    pub(in crate::library::tpm2) fn delete(&mut self, handle: u32) -> Result<(), TpmResult> {
        let last_used = self.end();
        let entry = self.find(handle).ok_or(TPM_RC_FAILURE)?;
        let size = entry.size as usize;
        let next = entry.offset.checked_add(size).ok_or(TPM_RC_FAILURE)?;
        if last_used > SPACE || next > last_used {
            return Err(TPM_RC_FAILURE);
        }
        self.0.copy_within(next..last_used, entry.offset);
        self.0[last_used - size..last_used].fill(0);
        Ok(())
    }

    #[cfg(test)]
    pub(in crate::library::tpm2) fn used_bytes(&self) -> u64 {
        RAM_INDEX_SPACE - u64::from(self.available())
    }

    #[cfg(test)]
    pub(in crate::library::tpm2) fn views(&self) -> Vec<RamEntryView> {
        self.entries()
            .map(|entry| RamEntryView {
                handle: entry.handle,
                attributes: self.attributes(entry),
                data: self
                    .read(entry, 0, (entry.size as usize).saturating_sub(HEADER))
                    .unwrap_or_default()
                    .to_vec(),
            })
            .collect()
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) struct RamEntryView {
    pub(in crate::library::tpm2) handle: u32,
    pub(in crate::library::tpm2) attributes: u32,
    pub(in crate::library::tpm2) data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::nv::attributes::{TPMA_NV_ORDERLY as ORDERLY, TPMA_NV_WRITTEN};

    fn header(image: &OrderlyRamImage, at: usize) -> [u32; 3] {
        [
            image.u32_at(at),
            image.u32_at(at + HANDLE),
            image.u32_at(at + ATTRIBUTES),
        ]
    }

    #[test]
    fn a_zeroed_image_has_no_entries_and_all_of_its_space() {
        let image = OrderlyRamImage::zeroed();
        assert_eq!(image.entries().count(), 0);
        assert_eq!(image.available(), 512);
        assert!(image.has_room_for(500));
        assert!(!image.has_room_for(501));
    }

    #[test]
    fn added_entries_carry_native_headers_zero_data_and_a_terminator() {
        let mut image = OrderlyRamImage::from_bytes(&[0xee; 512]).unwrap();
        image.put_u32(0, 0);
        image.add(0x0100_0001, ORDERLY, 8).unwrap();
        assert_eq!(header(&image, 0), [20, 0x0100_0001, ORDERLY]);
        assert_eq!(&image.as_bytes()[12..20], &[0; 8]);
        assert_eq!(&image.as_bytes()[20..24], &[0; 4]);
        assert_eq!(image.as_bytes()[24], 0xee);
        image.add(0x0100_0002, ORDERLY, 4).unwrap();
        let entries: Vec<RamEntry> = image.entries().collect();
        assert_eq!(
            entries,
            vec![
                RamEntry {
                    offset: 0,
                    size: 20,
                    handle: 0x0100_0001
                },
                RamEntry {
                    offset: 20,
                    size: 16,
                    handle: 0x0100_0002
                },
            ]
        );
        assert_eq!(image.available(), 512 - 36);
    }

    #[test]
    fn the_terminator_is_only_written_when_it_fits_before_the_end() {
        let mut image = OrderlyRamImage::from_bytes(&[0xee; 512]).unwrap();
        image.put_u32(0, 0);
        image.add(0x0100_0001, ORDERLY, 496).unwrap();
        assert_eq!(&image.as_bytes()[508..512], &[0xee; 4]);
        assert_eq!(image.entries().count(), 1);
        assert_eq!(image.available(), 4);
        assert_eq!(image.add(0x0100_0002, ORDERLY, 0), Err(TPM_RC_FAILURE));
    }

    #[test]
    fn deleting_an_entry_moves_the_rest_up_and_clears_the_reclaimed_space() {
        let mut image = OrderlyRamImage::zeroed();
        image.add(0x0100_0001, ORDERLY, 8).unwrap();
        image.add(0x0100_0002, ORDERLY, 4).unwrap();
        let second = image.find(0x0100_0002).unwrap();
        image.write(second, 0, &[1, 2, 3, 4]).unwrap();
        image.0[100] = 0x5a;
        image.delete(0x0100_0001).unwrap();
        assert_eq!(header(&image, 0), [16, 0x0100_0002, ORDERLY]);
        assert_eq!(&image.as_bytes()[12..16], &[1, 2, 3, 4]);
        assert!(image.as_bytes()[16..36].iter().all(|&byte| byte == 0));
        assert_eq!(image.as_bytes()[100], 0x5a);
        assert_eq!(image.delete(0x0100_0001), Err(TPM_RC_FAILURE));
    }

    #[test]
    fn iteration_stops_at_a_zero_size_or_when_no_header_fits() {
        let mut image = OrderlyRamImage::zeroed();
        image.put_u32(0, 0);
        image.0[7] = 0xa5;
        assert_eq!(image.entries().count(), 0);
        assert_eq!(image.available(), 512);
        image.put_u32(0, 501);
        assert_eq!(image.entries().count(), 1);
        assert_eq!(image.available(), 11);
        image.put_u32(0, 600);
        assert_eq!(image.entries().count(), 1);
        assert_eq!(image.available(), (512i64 - 600) as u32);
    }

    fn portable(image: &OrderlyRamImage) -> Vec<u8> {
        image.portable_entries()
    }

    fn words(values: &[u32]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value| value.to_be_bytes())
            .collect()
    }

    #[test]
    fn the_portable_form_walks_entries_like_the_c_marshaller() {
        let mut image = OrderlyRamImage::zeroed();
        image.add(0x0100_0001, ORDERLY, 2).unwrap();
        image
            .add(0x0100_0002, ORDERLY | TPMA_NV_WRITTEN, 3)
            .unwrap();
        let second = image.find(0x0100_0002).unwrap();
        image.write(second, 0, &[7, 8, 9]).unwrap();
        image.0[200] = 0xa5;
        let mut expected = words(&[14, 0x0100_0001, ORDERLY]);
        expected.extend_from_slice(&[0, 2, 0, 0]);
        expected.extend_from_slice(&words(&[15, 0x0100_0002, ORDERLY | TPMA_NV_WRITTEN]));
        expected.extend_from_slice(&[0, 3, 7, 8, 9]);
        expected.extend_from_slice(&words(&[0]));
        assert_eq!(portable(&image), expected);
    }

    #[test]
    fn the_portable_form_stops_after_a_malformed_header() {
        let mut image = OrderlyRamImage::zeroed();
        image
            .add(0x0100_0001, ORDERLY | TPMA_NV_WRITTEN, 8)
            .unwrap();
        image.put_u32(0, 4);
        image.put_u32(HANDLE, 0);
        assert_eq!(
            portable(&image),
            words(&[4, 0, ORDERLY | TPMA_NV_WRITTEN]),
            "a size below the header is written with its handle and attributes, then the walk ends"
        );
        image.put_u32(0, 1024);
        image.put_u32(HANDLE, 0x0100_0001);
        assert_eq!(
            portable(&image),
            words(&[1024, 0x0100_0001, ORDERLY | TPMA_NV_WRITTEN]),
            "a size past the image ends the walk the same way"
        );
        image.put_u32(0, 508);
        assert_eq!(
            portable(&image)[..14],
            [
                words(&[508, 0x0100_0001, ORDERLY | TPMA_NV_WRITTEN]),
                vec![0x01, 0xf0]
            ]
            .concat()
        );
        assert_eq!(
            portable(&image).len(),
            14 + 496,
            "no terminator fits after an entry that leaves less than a header"
        );
    }

    #[test]
    fn the_portable_form_round_trips_through_the_unmarshal_placement() {
        use crate::library::tpm2::nv::{IndexOrderlyRamFixture, parse_index_orderly_ram};

        let mut image = OrderlyRamImage::zeroed();
        image.add(0x0100_0001, ORDERLY, 8).unwrap();
        image
            .add(0x0100_0002, ORDERLY | TPMA_NV_WRITTEN, 3)
            .unwrap();
        let mut section = IndexOrderlyRamFixture {
            entries: Vec::new(),
            terminator: false,
            ..IndexOrderlyRamFixture::default()
        }
        .bytes();
        let entries_at = section.len() - 3;
        section.splice(entries_at..entries_at, portable(&image));
        let parsed = parse_index_orderly_ram(&section).unwrap();
        assert_eq!(OrderlyRamImage::from_portable(&parsed), Some(image));
    }

    #[test]
    fn data_access_stays_inside_the_image() {
        let mut image = OrderlyRamImage::zeroed();
        image.add(0x0100_0001, ORDERLY, 8).unwrap();
        let entry = image.find(0x0100_0001).unwrap();
        assert_eq!(image.read(entry, 0, 8), Some(&[0u8; 8][..]));
        assert_eq!(image.read(entry, 8, 20), Some(&[0u8; 20][..]));
        assert_eq!(image.read(entry, 0, 501), None);
        assert_eq!(image.write(entry, 499, &[1, 2]), None);
        assert_eq!(image.write(entry, 498, &[1, 2]), Some(()));
        assert_eq!(&image.as_bytes()[510..512], &[1, 2]);
    }
}
