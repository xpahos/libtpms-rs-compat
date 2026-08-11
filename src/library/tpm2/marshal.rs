#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Truncated;

pub(super) struct BlobReader<'a> {
    remaining: &'a [u8],
    consumed: usize,
}

impl<'a> BlobReader<'a> {
    pub(super) fn new(data: &'a [u8]) -> Self {
        Self {
            remaining: data,
            consumed: 0,
        }
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], Truncated> {
        let (chunk, rest) = self.remaining.split_first_chunk::<N>().ok_or(Truncated)?;
        self.remaining = rest;
        self.consumed += N;
        Ok(*chunk)
    }

    pub(super) fn read_u8(&mut self) -> Result<u8, Truncated> {
        Ok(self.read_array::<1>()?[0])
    }

    pub(super) fn read_u16(&mut self) -> Result<u16, Truncated> {
        Ok(u16::from_be_bytes(self.read_array()?))
    }

    pub(super) fn read_u32(&mut self) -> Result<u32, Truncated> {
        Ok(u32::from_be_bytes(self.read_array()?))
    }

    pub(super) fn read_u64(&mut self) -> Result<u64, Truncated> {
        Ok(u64::from_be_bytes(self.read_array()?))
    }

    pub(super) fn read_bool(&mut self) -> Result<bool, Truncated> {
        Ok(self.read_u8()? != 0)
    }

    pub(super) fn read_tpm2b(&mut self, maximum: usize) -> Result<&'a [u8], Tpm2bError> {
        let length = self.read_u16().map_err(|_| Tpm2bError::Truncated)?;
        if usize::from(length) > maximum {
            return Err(Tpm2bError::SizeExceeded {
                actual: length,
                maximum,
            });
        }
        self.take(usize::from(length))
            .map_err(|_| Tpm2bError::Truncated)
    }

    pub(super) fn take(&mut self, length: usize) -> Result<&'a [u8], Truncated> {
        let (taken, rest) = self.remaining.split_at_checked(length).ok_or(Truncated)?;
        self.remaining = rest;
        self.consumed += length;
        Ok(taken)
    }

    pub(super) fn remaining(&self) -> &'a [u8] {
        self.remaining
    }

    #[allow(dead_code)]
    pub(super) fn position(&self) -> usize {
        self.consumed
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Tpm2bError {
    Truncated,
    SizeExceeded { actual: u16, maximum: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BlockDisposition {
    AbsentNotNeeded,
    SkippedBytes(u16),
    Present { declared_size: u16 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BlockSkipError {
    Truncated,
    MissingRequiredBlock,
}

pub(super) fn skip_optional_block(
    reader: &mut BlobReader<'_>,
    needs_block: bool,
) -> Result<BlockDisposition, BlockSkipError> {
    let has_block = reader.read_u8().map_err(|_| BlockSkipError::Truncated)? != 0;
    let block_size = reader.read_u16().map_err(|_| BlockSkipError::Truncated)?;
    match (has_block, needs_block) {
        (false, false) => Ok(BlockDisposition::AbsentNotNeeded),
        (true, false) => {
            reader
                .take(usize::from(block_size))
                .map_err(|_| BlockSkipError::Truncated)?;
            Ok(BlockDisposition::SkippedBytes(block_size))
        }
        (true, true) => Ok(BlockDisposition::Present {
            declared_size: block_size,
        }),
        (false, true) => Err(BlockSkipError::MissingRequiredBlock),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u16_is_read_big_endian() {
        let mut reader = BlobReader::new(&[0x12, 0x34]);
        assert_eq!(reader.read_u16(), Ok(0x1234));
    }

    #[test]
    fn u32_is_read_big_endian() {
        let mut reader = BlobReader::new(&[0xab, 0x36, 0x47, 0x23]);
        assert_eq!(reader.read_u32(), Ok(0xab36_4723));
    }

    #[test]
    fn reads_advance_the_cursor() {
        let mut reader = BlobReader::new(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(reader.position(), 0);
        assert_eq!(reader.read_u8(), Ok(0x01));
        assert_eq!(reader.position(), 1);
        assert_eq!(reader.read_u16(), Ok(0x0203));
        assert_eq!(reader.position(), 3);
        assert_eq!(reader.read_u32(), Ok(0x0405_0607));
        assert_eq!(reader.position(), 7);
        assert_eq!(reader.remaining(), &[0x08]);
    }

    #[test]
    fn exact_end_reads_succeed() {
        let mut reader = BlobReader::new(&[0x00, 0x01]);
        assert_eq!(reader.read_u16(), Ok(1));
        assert_eq!(reader.remaining(), &[] as &[u8]);
        let mut reader = BlobReader::new(&[0x00, 0x00, 0x00, 0x01]);
        assert_eq!(reader.read_u32(), Ok(1));
        assert_eq!(reader.remaining(), &[] as &[u8]);
    }

    #[test]
    fn truncated_u8_fails_without_panicking() {
        assert_eq!(BlobReader::new(&[]).read_u8(), Err(Truncated));
    }

    #[test]
    fn truncated_u16_fails_and_consumes_nothing() {
        let mut reader = BlobReader::new(&[0xff]);
        assert_eq!(reader.read_u16(), Err(Truncated));
        assert_eq!(reader.remaining(), &[0xff]);
        assert_eq!(reader.position(), 0);
    }

    #[test]
    fn truncated_u32_fails_and_consumes_nothing() {
        let mut reader = BlobReader::new(&[0x01, 0x02, 0x03]);
        assert_eq!(reader.read_u32(), Err(Truncated));
        assert_eq!(reader.remaining(), &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn oversized_take_fails_and_consumes_nothing() {
        let mut reader = BlobReader::new(&[0x01, 0x02]);
        assert_eq!(reader.take(3), Err(Truncated));
        assert_eq!(reader.remaining(), &[0x01, 0x02]);
        assert_eq!(reader.take(usize::MAX), Err(Truncated));
    }

    #[test]
    fn zero_length_take_yields_empty_slice() {
        let mut reader = BlobReader::new(&[0x01]);
        assert_eq!(reader.take(0), Ok(&[] as &[u8]));
        assert_eq!(reader.remaining(), &[0x01]);
        assert_eq!(reader.position(), 0);
    }

    #[test]
    fn take_borrows_the_original_bytes() {
        let data = [0x01, 0x02, 0x03];
        let mut reader = BlobReader::new(&data);
        let taken = reader.take(2).unwrap();
        assert_eq!(taken, &[0x01, 0x02]);
        assert!(core::ptr::eq(taken.as_ptr(), data.as_ptr()));
    }

    #[test]
    fn u64_is_read_big_endian() {
        let mut reader = BlobReader::new(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        assert_eq!(reader.read_u64(), Ok(0x0123_4567_89ab_cdef));
    }

    #[test]
    fn exact_end_u64_succeeds() {
        let mut reader = BlobReader::new(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(reader.read_u64(), Ok(1));
        assert_eq!(reader.remaining(), &[] as &[u8]);
    }

    #[test]
    fn truncated_u64_fails_and_consumes_nothing() {
        for len in 0..8usize {
            let data = vec![0x5a; len];
            let mut reader = BlobReader::new(&data);
            assert_eq!(reader.read_u64(), Err(Truncated), "length {len}");
            assert_eq!(reader.remaining(), &data[..], "length {len}");
            assert_eq!(reader.position(), 0, "length {len}");
        }
    }

    #[test]
    fn canonical_and_noncanonical_bools_decode_like_upstream() {
        assert_eq!(BlobReader::new(&[0x00]).read_bool(), Ok(false));
        for byte in [0x01u8, 0x02, 0x80, 0xff] {
            assert_eq!(
                BlobReader::new(&[byte]).read_bool(),
                Ok(true),
                "byte {byte:#04x}"
            );
        }
        assert_eq!(BlobReader::new(&[]).read_bool(), Err(Truncated));
    }

    #[test]
    fn zero_length_tpm2b_yields_an_empty_borrowed_slice() {
        let mut reader = BlobReader::new(&[0x00, 0x00, 0x77]);
        assert_eq!(reader.read_tpm2b(64), Ok(&[] as &[u8]));
        assert_eq!(reader.remaining(), &[0x77]);
    }

    #[test]
    fn nonempty_tpm2b_is_read_in_full() {
        let mut reader = BlobReader::new(&[0x00, 0x03, 0xaa, 0xbb, 0xcc, 0xdd]);
        assert_eq!(reader.read_tpm2b(64).unwrap(), &[0xaa, 0xbb, 0xcc]);
        assert_eq!(reader.remaining(), &[0xdd]);
    }

    #[test]
    fn exact_maximum_length_tpm2b_is_accepted() {
        let mut data = vec![0x00, 0x04];
        data.extend_from_slice(&[0x11; 4]);
        let mut reader = BlobReader::new(&data);
        assert_eq!(reader.read_tpm2b(4).unwrap(), &[0x11; 4]);
        assert_eq!(reader.remaining(), &[] as &[u8]);
    }

    #[test]
    fn tpm2b_maximum_plus_one_is_a_size_error() {
        let mut data = vec![0x00, 0x05];
        data.extend_from_slice(&[0x11; 5]);
        let mut reader = BlobReader::new(&data);
        assert_eq!(
            reader.read_tpm2b(4),
            Err(Tpm2bError::SizeExceeded {
                actual: 5,
                maximum: 4
            })
        );
        assert_eq!(reader.remaining(), &[0x11; 5]);
    }

    #[test]
    fn truncated_tpm2b_length_field_consumes_nothing() {
        for data in [&[] as &[u8], &[0x00]] {
            let mut reader = BlobReader::new(data);
            assert_eq!(reader.read_tpm2b(64), Err(Tpm2bError::Truncated));
            assert_eq!(reader.remaining(), data);
        }
    }

    #[test]
    fn truncated_tpm2b_contents_are_distinct_from_oversized() {
        let mut reader = BlobReader::new(&[0x00, 0x04, 0x11, 0x22]);
        assert_eq!(reader.read_tpm2b(64), Err(Tpm2bError::Truncated));
    }

    #[test]
    fn oversized_tpm2b_length_neither_allocates_nor_indexes() {
        let mut reader = BlobReader::new(&[0xff, 0xff]);
        assert_eq!(
            reader.read_tpm2b(4),
            Err(Tpm2bError::SizeExceeded {
                actual: 0xffff,
                maximum: 4
            })
        );
    }

    #[test]
    fn tpm2b_bytes_borrow_the_original_input() {
        let data = [0x00, 0x02, 0xa1, 0xa2];
        let mut reader = BlobReader::new(&data);
        let bytes = reader.read_tpm2b(64).unwrap();
        assert_eq!(bytes, &[0xa1, 0xa2]);
        assert!(core::ptr::eq(bytes.as_ptr(), data[2..].as_ptr()));
    }

    #[test]
    fn malformed_input_never_panics() {
        for len in 0..8usize {
            let data = vec![0xa5; len];
            let mut reader = BlobReader::new(&data);
            let _ = reader.read_u8();
            let _ = reader.read_u16();
            let _ = reader.read_u32();
            let _ = reader.read_u64();
            let _ = reader.read_bool();
            let _ = reader.read_tpm2b(0);
            let _ = reader.read_tpm2b(usize::MAX);
            let _ = reader.take(len + 1);
            let _ = reader.take(0);
        }
    }

    #[test]
    fn absent_block_consumes_only_the_framing() {
        let mut reader = BlobReader::new(&[0x00, 0x00, 0x00, 0xaa]);
        assert_eq!(
            skip_optional_block(&mut reader, false),
            Ok(BlockDisposition::AbsentNotNeeded)
        );
        assert_eq!(reader.remaining(), &[0xaa]);
    }

    #[test]
    fn absent_block_ignores_a_nonzero_length_field() {
        let mut reader = BlobReader::new(&[0x00, 0x00, 0x10, 0xaa]);
        assert_eq!(
            skip_optional_block(&mut reader, false),
            Ok(BlockDisposition::AbsentNotNeeded)
        );
        assert_eq!(reader.remaining(), &[0xaa]);
    }

    #[test]
    fn present_zero_length_block_is_skipped() {
        let mut reader = BlobReader::new(&[0x01, 0x00, 0x00, 0xbb]);
        assert_eq!(
            skip_optional_block(&mut reader, false),
            Ok(BlockDisposition::SkippedBytes(0))
        );
        assert_eq!(reader.remaining(), &[0xbb]);
    }

    #[test]
    fn present_nonempty_block_is_skipped_in_full() {
        let mut reader = BlobReader::new(&[0x01, 0x00, 0x03, 0x11, 0x22, 0x33, 0xcc]);
        assert_eq!(
            skip_optional_block(&mut reader, false),
            Ok(BlockDisposition::SkippedBytes(3))
        );
        assert_eq!(reader.remaining(), &[0xcc]);
    }

    #[test]
    fn noncanonical_nonzero_boolean_is_true() {
        for boolean in [0x01u8, 0x02, 0x80, 0xff] {
            let data = [boolean, 0x00, 0x01, 0x99, 0xdd];
            let mut reader = BlobReader::new(&data);
            assert_eq!(
                skip_optional_block(&mut reader, false),
                Ok(BlockDisposition::SkippedBytes(1)),
                "boolean byte {boolean:#04x}"
            );
            assert_eq!(reader.remaining(), &[0xdd]);
        }
    }

    #[test]
    fn needed_present_block_leaves_the_payload_unread() {
        let mut reader = BlobReader::new(&[0x01, 0x00, 0x02, 0x11, 0x22]);
        assert_eq!(
            skip_optional_block(&mut reader, true),
            Ok(BlockDisposition::Present { declared_size: 2 })
        );
        assert_eq!(reader.remaining(), &[0x11, 0x22]);
    }

    #[test]
    fn needed_present_block_preserves_a_misleading_declared_size() {
        let mut reader = BlobReader::new(&[0x01, 0xff, 0xff, 0x11]);
        assert_eq!(
            skip_optional_block(&mut reader, true),
            Ok(BlockDisposition::Present {
                declared_size: 0xffff
            })
        );
        assert_eq!(reader.remaining(), &[0x11]);
    }

    #[test]
    fn needed_missing_block_is_an_error() {
        let mut reader = BlobReader::new(&[0x00, 0x00, 0x00]);
        assert_eq!(
            skip_optional_block(&mut reader, true),
            Err(BlockSkipError::MissingRequiredBlock)
        );
    }

    #[test]
    fn truncated_block_framing_fails() {
        let mut reader = BlobReader::new(&[]);
        assert_eq!(
            skip_optional_block(&mut reader, false),
            Err(BlockSkipError::Truncated)
        );
        for data in [&[0x01u8] as &[u8], &[0x01, 0x00]] {
            let mut reader = BlobReader::new(data);
            assert_eq!(
                skip_optional_block(&mut reader, false),
                Err(BlockSkipError::Truncated)
            );
        }
    }

    #[test]
    fn block_size_beyond_input_fails_without_advancing_past_the_end() {
        let data = [0x01, 0x00, 0x04, 0x11, 0x22];
        let mut reader = BlobReader::new(&data);
        assert_eq!(
            skip_optional_block(&mut reader, false),
            Err(BlockSkipError::Truncated)
        );
        assert_eq!(reader.remaining(), &[0x11, 0x22]);
    }
}
