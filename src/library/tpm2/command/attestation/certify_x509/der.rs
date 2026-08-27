pub(super) const TAG_INTEGER: u8 = 0x02;
pub(super) const TAG_BIT_STRING: u8 = 0x03;
pub(super) const TAG_OCTET_STRING: u8 = 0x04;
pub(super) const TAG_NULL: u8 = 0x05;
pub(super) const TAG_OBJECT_IDENTIFIER: u8 = 0x06;
pub(super) const TAG_CONSTRUCTED_SEQUENCE: u8 = 0x30;
pub(super) const TAG_APPLICATION_SPECIFIC: u8 = 0xa0;

pub(super) const MAX_MARSHAL_DEPTH: usize = 10;

pub(super) struct DerReader<'a> {
    buffer: &'a [u8],
    size: i32,
    offset: i32,
    tag: u8,
}

impl<'a> DerReader<'a> {
    pub(super) fn new(buffer: &'a [u8]) -> Option<Self> {
        if buffer.is_empty() || buffer.len() > i32::MAX as usize {
            return None;
        }
        Some(Self {
            buffer,
            size: buffer.len() as i32,
            offset: 0,
            tag: 0xff,
        })
    }

    pub(super) fn tag(&self) -> u8 {
        self.tag
    }

    pub(super) fn size(&self) -> i32 {
        self.size
    }

    pub(super) fn offset(&self) -> i32 {
        self.offset
    }

    #[cfg(test)]
    pub(super) fn failed(&self) -> bool {
        self.size < 0
    }

    pub(super) fn at_end(&self) -> bool {
        self.offset >= self.size
    }

    pub(super) fn exhausted(&self) -> bool {
        self.offset == self.size
    }

    pub(super) fn slice_from(&self, start: i32, length: i32) -> Option<&'a [u8]> {
        let start = usize::try_from(start).ok()?;
        let length = usize::try_from(length).ok()?;
        let end = start.checked_add(length)?;
        self.buffer.get(start..end)
    }

    pub(super) fn skip(&mut self, length: i32) {
        self.offset = self.offset.saturating_add(length);
    }

    pub(super) fn duplicate(&self) -> Self {
        Self {
            buffer: self.buffer,
            size: self.size,
            offset: self.offset,
            tag: self.tag,
        }
    }

    pub(super) fn poison(&mut self) {
        self.size = -1;
    }

    fn fail(&mut self) -> i32 {
        self.size = -1;
        -1
    }

    fn next_octet(&mut self) -> Option<u8> {
        let index = usize::try_from(self.offset).ok()?;
        let byte = *self.buffer.get(index)?;
        self.offset = self.offset.checked_add(1)?;
        Some(byte)
    }

    fn check_size(&self, length: i32) -> Option<()> {
        let sum = length.checked_add(self.offset)?;
        if sum >= self.offset && sum <= self.size {
            Some(())
        } else {
            None
        }
    }

    pub(super) fn decode_length(&mut self) -> i32 {
        match self.decode_length_inner() {
            Some(value) => value,
            None => self.fail(),
        }
    }

    fn decode_length_inner(&mut self) -> Option<i32> {
        if self.offset >= self.size {
            return None;
        }
        let first = self.next_octet()?;
        let value = if first >= 0x80 {
            self.check_size(i32::from(first & 0x7f))?;
            if first == 0x82 {
                let high = i32::from(self.next_octet()?);
                if high >= 0x80 {
                    return None;
                }
                (high << 8) + i32::from(self.next_octet()?)
            } else if first == 0x81 {
                i32::from(self.next_octet()?)
            } else {
                return None;
            }
        } else {
            i32::from(first)
        };
        self.check_size(value)?;
        Some(value)
    }

    pub(super) fn next_tag(&mut self) -> i32 {
        if self.offset >= self.size {
            self.tag = 0xff;
            return self.fail();
        }
        let Some(tag) = self.next_octet() else {
            self.tag = 0xff;
            return self.fail();
        };
        self.tag = tag;
        if tag & 0x1f == 0x1f {
            self.tag = 0xff;
            return self.fail();
        }
        self.decode_length()
    }

    pub(super) fn narrow_to(&mut self, length: i32) -> bool {
        let Ok(start) = usize::try_from(self.offset) else {
            return false;
        };
        let Ok(span) = usize::try_from(length) else {
            return false;
        };
        if start > self.buffer.len() || self.buffer.len() - start < span {
            return false;
        }
        self.buffer = &self.buffer[start..];
        self.offset = 0;
        self.size = length;
        true
    }

    pub(super) fn matches_at_offset(&self, expected: &[u8]) -> bool {
        let Ok(start) = usize::try_from(self.offset) else {
            return false;
        };
        self.buffer
            .get(start..start.saturating_add(expected.len()))
            .is_some_and(|found| found == expected)
    }

    pub(super) fn bit_string_value(&mut self) -> Option<u32> {
        match self.bit_string_value_inner() {
            Some(value) => Some(value),
            None => {
                self.fail();
                None
            }
        }
    }

    fn bit_string_value_inner(&mut self) -> Option<u32> {
        let mut length = self.next_tag();
        if length < 1 || self.tag != TAG_BIT_STRING {
            return None;
        }
        let shift = i32::from(self.next_octet()?);
        length -= 1;
        let input_bits = 8i32.checked_mul(length)?.checked_sub(shift)?;
        if shift >= 8 || (length <= 0 && shift != 0) {
            return None;
        }
        let mut value: u32 = 0;
        while length > 1 {
            if value & 0xff00_0000 != 0 {
                return None;
            }
            value = (value << 8) + u32::from(self.next_octet()?);
            length -= 1;
        }
        if length == 1 {
            let mask = 0xff00_0000u32.wrapping_shl((8 - shift) as u32);
            if value & mask != 0 {
                return None;
            }
            value = value.wrapping_shl((8 - shift) as u32)
                + u32::from(self.next_octet()? >> (shift as u32));
        }
        if input_bits > 0 {
            value = value.wrapping_shl((32 - input_bits) as u32);
        }
        Some(value)
    }
}

pub(super) struct DerWriter {
    buffer: Vec<u8>,
    offset: i32,
    end: i32,
    ends: Vec<i32>,
}

impl DerWriter {
    pub(super) fn new(capacity: usize) -> Self {
        let offset = capacity as i32;
        Self {
            buffer: vec![0u8; capacity],
            offset,
            end: offset,
            ends: Vec::with_capacity(MAX_MARSHAL_DEPTH),
        }
    }

    #[cfg(test)]
    pub(super) fn offset(&self) -> i32 {
        self.offset
    }

    pub(super) fn failed(&self) -> bool {
        self.offset < 0
    }

    pub(super) fn slice_at(&self, offset: i32, length: i32) -> Option<&[u8]> {
        let start = usize::try_from(offset).ok()?;
        let length = usize::try_from(length).ok()?;
        self.buffer.get(start..start.checked_add(length)?)
    }

    pub(super) fn taken(&self, length: i32) -> Vec<u8> {
        self.slice_at(self.offset, length)
            .map(<[u8]>::to_vec)
            .unwrap_or_default()
    }

    pub(super) fn release(&mut self, length: i32) {
        if self.offset >= 0 && length >= 0 {
            self.offset = self.offset.saturating_add(length);
        }
    }

    pub(super) fn start(&mut self) -> bool {
        if self.ends.len() >= MAX_MARSHAL_DEPTH {
            self.offset = -1;
            return false;
        }
        self.ends.push(self.end);
        self.end = self.offset;
        true
    }

    pub(super) fn end_context(&mut self) -> i32 {
        let Some(previous) = self.ends.pop() else {
            self.offset = -1;
            return 0;
        };
        let length = self.end - self.offset;
        self.end = previous;
        length
    }

    pub(super) fn end_encapsulation(&mut self, tag: u8) -> i32 {
        if tag == TAG_BIT_STRING {
            self.push_byte(0);
        }
        let length = self.end - self.offset;
        self.push_tag_and_length(tag, length);
        self.end_context()
    }

    pub(super) fn push_byte(&mut self, byte: u8) -> bool {
        if self.offset > 0 {
            self.offset -= 1;
            if let Ok(index) = usize::try_from(self.offset)
                && let Some(slot) = self.buffer.get_mut(index)
            {
                *slot = byte;
            }
            return true;
        }
        self.offset = -1;
        false
    }

    pub(super) fn push_bytes(&mut self, bytes: &[u8]) -> i32 {
        let Ok(count) = i32::try_from(bytes.len()) else {
            self.offset = -1;
            return 0;
        };
        self.offset = match self.offset.checked_sub(count) {
            Some(offset) => offset,
            None => {
                self.offset = -1;
                return 0;
            }
        };
        if self.offset < 0 {
            self.offset = -1;
            return 0;
        }
        if let Ok(index) = usize::try_from(self.offset)
            && let Some(slot) = self
                .buffer
                .get_mut(index..index.saturating_add(bytes.len()))
        {
            slot.copy_from_slice(bytes);
        }
        count
    }

    pub(super) fn push_null(&mut self) -> i32 {
        self.push_byte(0);
        self.push_byte(TAG_NULL);
        if self.offset >= 0 { 2 } else { 0 }
    }

    pub(super) fn push_length(&mut self, length: i32) -> i32 {
        let start = self.offset;
        if length < 0 {
            self.offset = -1;
            return 0;
        }
        if length <= 127 {
            self.push_byte(length as u8);
        } else {
            self.push_byte((length & 0xff) as u8);
            let shifted = length >> 8;
            if shifted == 0 {
                self.push_byte(0x81);
            } else {
                self.push_byte(shifted as u8);
                self.push_byte(0x82);
            }
        }
        if self.offset > 0 {
            start - self.offset
        } else {
            0
        }
    }

    pub(super) fn push_tag_and_length(&mut self, tag: u8, length: i32) -> i32 {
        let mut bytes = self.push_length(length);
        if self.push_byte(tag) {
            bytes += 1;
        }
        if self.offset < 0 { 0 } else { bytes }
    }

    pub(super) fn push_uint(&mut self, value: u32) -> i32 {
        self.push_integer(&value.to_be_bytes())
    }

    pub(super) fn push_integer(&mut self, integer: &[u8]) -> i32 {
        if integer.is_empty() {
            self.offset = -1;
            return 0;
        }
        let mut start = 0usize;
        let mut length = integer.len();
        while integer[start] == 0 && length > 1 {
            length -= 1;
            start += 1;
        }
        let value = &integer[start..];
        let mut marshaled = self.push_bytes(value);
        if value[0] & 0x80 != 0 && self.push_byte(0) {
            marshaled += 1;
        }
        marshaled + self.push_tag_and_length(TAG_INTEGER, marshaled)
    }

    pub(super) fn push_oid(&mut self, oid: &[u8]) -> i32 {
        match oid.split_first() {
            Some((&TAG_OBJECT_IDENTIFIER, rest)) => match rest.split_first() {
                Some((&length, _)) if length & 0x80 == 0 => {
                    let wanted = usize::from(length) + 2;
                    match oid.get(..wanted) {
                        Some(bytes) => self.push_bytes(bytes),
                        None => {
                            self.offset = -1;
                            0
                        }
                    }
                }
                _ => {
                    self.offset = -1;
                    0
                }
            },
            _ => {
                self.offset = -1;
                0
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_buffer_cannot_open_a_reader() {
        assert!(DerReader::new(&[]).is_none());
    }

    #[test]
    fn a_short_form_length_is_read_as_written() {
        let mut reader = DerReader::new(&[0x30, 0x02, 0xaa, 0xbb]).expect("a reader");
        assert_eq!(reader.next_tag(), 2);
        assert_eq!(reader.tag(), TAG_CONSTRUCTED_SEQUENCE);
        assert_eq!(reader.offset(), 2);
    }

    #[test]
    fn a_one_octet_long_form_length_is_accepted() {
        let mut bytes = vec![0x30, 0x81, 0x80];
        bytes.extend(std::iter::repeat_n(0u8, 0x80));
        let mut reader = DerReader::new(&bytes).expect("a reader");
        assert_eq!(reader.next_tag(), 0x80);
        assert_eq!(reader.offset(), 3);
    }

    #[test]
    fn a_two_octet_long_form_length_is_accepted() {
        let mut bytes = vec![0x30, 0x82, 0x01, 0x00];
        bytes.extend(std::iter::repeat_n(0u8, 0x100));
        let mut reader = DerReader::new(&bytes).expect("a reader");
        assert_eq!(reader.next_tag(), 0x100);
        assert_eq!(reader.offset(), 4);
    }

    #[test]
    fn a_two_octet_length_above_thirty_two_thousand_is_refused() {
        let mut bytes = vec![0x30, 0x82, 0x80, 0x00];
        bytes.extend(std::iter::repeat_n(0u8, 0x100));
        let mut reader = DerReader::new(&bytes).expect("a reader");
        assert_eq!(reader.next_tag(), -1);
        assert!(reader.failed());
    }

    #[test]
    fn three_or_more_length_octets_are_refused() {
        for first in [0x80u8, 0x83, 0x84, 0xfe, 0xff] {
            let mut bytes = vec![0x30, first];
            bytes.extend(std::iter::repeat_n(0u8, 8));
            let mut reader = DerReader::new(&bytes).expect("a reader");
            assert_eq!(reader.next_tag(), -1, "first length octet {first:#04x}");
            assert!(reader.failed());
        }
    }

    #[test]
    fn a_length_that_leaves_the_buffer_is_refused() {
        let mut reader = DerReader::new(&[0x30, 0x08, 0x00]).expect("a reader");
        assert_eq!(reader.next_tag(), -1);
        assert!(reader.failed());
    }

    #[test]
    fn an_extended_tag_is_refused() {
        let mut reader = DerReader::new(&[0x1f, 0x01, 0x00]).expect("a reader");
        assert_eq!(reader.next_tag(), -1);
        assert_eq!(reader.tag(), 0xff);
    }

    #[test]
    fn a_failed_reader_stays_failed() {
        let mut reader = DerReader::new(&[0x1f, 0x01, 0x00]).expect("a reader");
        assert_eq!(reader.next_tag(), -1);
        assert_eq!(reader.next_tag(), -1);
        assert_eq!(reader.decode_length(), -1);
        assert!(reader.bit_string_value().is_none());
    }

    #[test]
    fn a_thirty_two_bit_bit_string_is_left_justified() {
        let mut reader =
            DerReader::new(&[0x03, 0x05, 0x00, 0x00, 0x04, 0x00, 0x72]).expect("a reader");
        assert_eq!(reader.bit_string_value(), Some(0x0004_0072));
    }

    #[test]
    fn a_short_bit_string_is_left_justified() {
        let mut reader = DerReader::new(&[0x03, 0x02, 0x07, 0x80]).expect("a reader");
        assert_eq!(reader.bit_string_value(), Some(0x8000_0000));
    }

    #[test]
    fn a_bit_string_with_an_impossible_shift_is_refused() {
        for shift in [0x08u8, 0x09, 0xff] {
            let bytes = [0x03, 0x02, shift, 0x80];
            let mut reader = DerReader::new(&bytes).expect("a reader");
            assert!(reader.bit_string_value().is_none(), "shift {shift}");
        }
    }

    #[test]
    fn an_empty_bit_string_needs_a_zero_shift() {
        let mut reader = DerReader::new(&[0x03, 0x01, 0x00]).expect("a reader");
        assert_eq!(reader.bit_string_value(), Some(0));
        let mut reader = DerReader::new(&[0x03, 0x01, 0x01]).expect("a reader");
        assert!(reader.bit_string_value().is_none());
    }

    #[test]
    fn a_bit_string_that_is_not_a_bit_string_is_refused() {
        let mut reader = DerReader::new(&[0x04, 0x02, 0x00, 0x80]).expect("a reader");
        assert!(reader.bit_string_value().is_none());
    }

    #[test]
    fn an_oversized_bit_string_never_panics() {
        for length in 5usize..12 {
            let mut bytes = vec![0x03, (length + 1) as u8, 0x00];
            bytes.extend(std::iter::repeat_n(0xffu8, length));
            let mut reader = DerReader::new(&bytes).expect("a reader");
            let _ = reader.bit_string_value();
        }
    }

    #[track_caller]
    fn parsed_bit_string(bytes: &[u8]) -> Option<u32> {
        let mut reader = DerReader::new(bytes).expect("a reader");
        let value = reader.bit_string_value();
        assert_eq!(
            value.is_none(),
            reader.failed(),
            "a refused bit string leaves the reader persistently failed"
        );
        value
    }

    #[test]
    fn a_thirty_three_bit_zero_valued_bit_string_is_left_justified_like_the_reference() {
        assert_eq!(
            parsed_bit_string(&[0x03, 0x06, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00]),
            Some(0)
        );
    }

    #[test]
    fn the_thirty_two_bit_boundary_is_exact() {
        assert_eq!(
            parsed_bit_string(&[0x03, 0x05, 0x00, 0x12, 0x34, 0x56, 0x78]),
            Some(0x1234_5678),
            "thirty-two significant bits are kept as written"
        );
        assert_eq!(
            parsed_bit_string(&[0x03, 0x06, 0x07, 0x00, 0x12, 0x34, 0x56, 0x78]),
            Some(0),
            "thirty-three significant bits keep only the lowest one"
        );
    }

    #[test]
    fn every_unused_bit_count_left_justifies_a_narrow_bit_string() {
        for shift in 0u32..8 {
            let bytes = [0x03, 0x02, shift as u8, 0xa5];
            let significant = 8 - shift;
            assert_eq!(
                parsed_bit_string(&bytes),
                Some((0xa5u32 >> shift) << (32 - significant)),
                "unused bit count {shift}"
            );
        }
    }

    #[test]
    fn bit_strings_with_zero_high_bytes_stay_total_beyond_thirty_two_bits() {
        for content in 5usize..=18 {
            for shift in 0u8..=7 {
                let mut bytes = vec![0x03, (content + 1) as u8, shift];
                bytes.extend(std::iter::repeat_n(0u8, content));
                assert_eq!(parsed_bit_string(&bytes), Some(0), "{content} zero octets");
            }
        }
    }

    #[test]
    fn every_bit_string_shape_is_total() {
        let patterns: [fn(usize) -> u8; 6] = [
            |_| 0x00,
            |_| 0xff,
            |_| 0x80,
            |index| if index == 0 { 0x00 } else { 0xff },
            |index| if index == 0 { 0x80 } else { 0x00 },
            |index| index as u8,
        ];
        for content in 0usize..=20 {
            for shift in 0u8..=9 {
                for pattern in patterns {
                    let mut bytes = vec![0x03, (content + 1) as u8, shift];
                    bytes.extend((0..content).map(pattern));
                    let _ = parsed_bit_string(&bytes);
                }
            }
        }
    }

    #[test]
    fn every_truncation_of_a_structure_is_refused_without_panicking() {
        let full = [
            0x30u8, 0x0c, 0x30, 0x03, 0x02, 0x01, 0x02, 0xa3, 0x05, 0x03, 0x03, 0x07, 0x80, 0x00,
        ];
        for length in 1..full.len() {
            let Some(mut reader) = DerReader::new(&full[..length]) else {
                continue;
            };
            while !reader.failed() && !reader.at_end() {
                let advance = reader.next_tag();
                if advance < 0 {
                    break;
                }
                reader.skip(advance);
            }
        }
    }

    fn marshaled(writer: &DerWriter, length: i32) -> Vec<u8> {
        writer
            .slice_at(writer.offset(), length)
            .expect("the marshaled bytes")
            .to_vec()
    }

    #[test]
    fn a_small_integer_drops_its_leading_zeros() {
        let mut writer = DerWriter::new(64);
        let length = writer.push_uint(2);
        assert_eq!(length, 3);
        assert_eq!(marshaled(&writer, length), [0x02, 0x01, 0x02]);
    }

    #[test]
    fn a_negative_looking_integer_gains_a_leading_zero() {
        let mut writer = DerWriter::new(64);
        let length = writer.push_integer(&[0x80, 0x01]);
        assert_eq!(length, 5);
        assert_eq!(marshaled(&writer, length), [0x02, 0x03, 0x00, 0x80, 0x01]);
    }

    #[test]
    fn an_all_zero_integer_keeps_one_octet() {
        let mut writer = DerWriter::new(64);
        let length = writer.push_integer(&[0x00, 0x00, 0x00]);
        assert_eq!(length, 3);
        assert_eq!(marshaled(&writer, length), [0x02, 0x01, 0x00]);
    }

    #[test]
    fn a_long_value_uses_the_one_octet_long_form() {
        let mut writer = DerWriter::new(1024);
        writer.start();
        writer.push_bytes(&[0xaa; 200]);
        let length = writer.end_encapsulation(TAG_CONSTRUCTED_SEQUENCE);
        assert_eq!(length, 203);
        assert_eq!(marshaled(&writer, 3), [0x30, 0x81, 0xc8]);
    }

    #[test]
    fn a_very_long_value_uses_the_two_octet_long_form() {
        let mut writer = DerWriter::new(1024);
        writer.start();
        writer.push_bytes(&[0xaa; 300]);
        let length = writer.end_encapsulation(TAG_CONSTRUCTED_SEQUENCE);
        assert_eq!(length, 304);
        assert_eq!(marshaled(&writer, 4), [0x30, 0x82, 0x01, 0x2c]);
    }

    #[test]
    fn an_encapsulated_bit_string_gains_a_leading_zero() {
        let mut writer = DerWriter::new(64);
        writer.start();
        writer.push_bytes(&[0xaa, 0xbb]);
        let length = writer.end_encapsulation(TAG_BIT_STRING);
        assert_eq!(length, 5);
        assert_eq!(marshaled(&writer, length), [0x03, 0x03, 0x00, 0xaa, 0xbb]);
    }

    #[test]
    fn a_malformed_object_identifier_fails_the_writer() {
        let mut writer = DerWriter::new(64);
        assert_eq!(writer.push_oid(&[0x05, 0x01, 0x00]), 0);
        assert!(writer.failed());
        let mut writer = DerWriter::new(64);
        assert_eq!(writer.push_oid(&[0x06, 0x80, 0x00]), 0);
        assert!(writer.failed());
        let mut writer = DerWriter::new(64);
        assert_eq!(writer.push_oid(&[0x06, 0x04, 0x00]), 0);
        assert!(writer.failed());
    }

    #[test]
    fn an_overfull_writer_reports_a_negative_offset() {
        let mut writer = DerWriter::new(8);
        writer.push_bytes(&[0x00; 8]);
        assert!(!writer.failed());
        writer.push_byte(0x01);
        assert!(writer.failed());
    }

    #[test]
    fn pushing_past_the_buffer_never_panics() {
        let mut writer = DerWriter::new(4);
        assert_eq!(writer.push_bytes(&[0x00; 16]), 0);
        assert!(writer.failed());
        let _ = writer.push_uint(0xffff_ffff);
        let _ = writer.push_tag_and_length(TAG_CONSTRUCTED_SEQUENCE, 0x4000);
    }

    #[test]
    fn the_marshaling_depth_is_bounded() {
        let mut writer = DerWriter::new(1024);
        for _ in 0..MAX_MARSHAL_DEPTH {
            assert!(writer.start());
        }
        assert!(!writer.start());
        assert!(writer.failed());
    }
}
