use crate::ffi_types::TpmResult;

use super::constants::TPM_FAIL;

const INITSTATE_BEGIN_TAG: &[u8] = b"-----BEGIN INITSTATE-----";
const INITSTATE_END_TAG: &[u8] = b"-----END INITSTATE-----";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodedBlobKind {
    InitState,
}

impl EncodedBlobKind {
    const fn tags(self) -> (&'static [u8], &'static [u8]) {
        match self {
            Self::InitState => (INITSTATE_BEGIN_TAG, INITSTATE_END_TAG),
        }
    }
}

pub fn decode_blob(kind: EncodedBlobKind, data: &[u8]) -> Result<Vec<u8>, TpmResult> {
    let (begin_tag, end_tag) = kind.tags();
    let payload = tagged_payload(until_nul(data), begin_tag, end_tag).ok_or(TPM_FAIL)?;
    let decoded = decode_base64(&base64_characters(payload)).ok_or(TPM_FAIL)?;
    if decoded.is_empty() {
        return Err(TPM_FAIL);
    }
    Ok(decoded)
}

fn until_nul(data: &[u8]) -> &[u8] {
    match data.iter().position(|byte| *byte == 0) {
        Some(terminator) => &data[..terminator],
        None => data,
    }
}

fn tagged_payload<'a>(data: &'a [u8], begin_tag: &[u8], end_tag: &[u8]) -> Option<&'a [u8]> {
    let after_begin = find(data, begin_tag)? + begin_tag.len();
    let rest = data.get(after_begin..)?;
    let payload = match rest.iter().position(|byte| !is_whitespace(*byte)) {
        Some(offset) => &rest[offset..],
        None => return None,
    };
    Some(&payload[..find(payload, end_tag)?])
}

fn find(data: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > data.len() {
        return None;
    }
    data.windows(needle.len())
        .position(|window| window == needle)
}

fn is_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

fn base64_characters(payload: &[u8]) -> Vec<u8> {
    payload
        .iter()
        .copied()
        .filter(|byte| is_base64_character(*byte))
        .collect()
}

fn is_base64_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
}

fn decode_base64(encoded: &[u8]) -> Option<Vec<u8>> {
    if !encoded.len().is_multiple_of(4) {
        return None;
    }
    let mut decoded = Vec::with_capacity(encoded.len() / 4 * 3);
    let mut groups = encoded.chunks_exact(4).peekable();
    while let Some(group) = groups.next() {
        let padding = if groups.peek().is_none() {
            trailing_padding(group)?
        } else {
            0
        };
        let mut bits: u32 = 0;
        for &byte in &group[..4 - padding] {
            bits = (bits << 6) | sextet(byte)?;
        }
        bits <<= 6 * padding as u32;
        for shift in [16u32, 8, 0].into_iter().take(3 - padding) {
            decoded.push((bits >> shift) as u8);
        }
    }
    Some(decoded)
}

fn trailing_padding(group: &[u8]) -> Option<usize> {
    match group.iter().rev().take_while(|byte| **byte == b'=').count() {
        padding @ 0..=2 => Some(padding),
        _ => None,
    }
}

fn sextet(byte: u8) -> Option<u32> {
    let value = match byte {
        b'A'..=b'Z' => byte - b'A',
        b'a'..=b'z' => byte - b'a' + 26,
        b'0'..=b'9' => byte - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(u32::from(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BEGIN: &str = "-----BEGIN INITSTATE-----";
    const END: &str = "-----END INITSTATE-----";

    fn decode(data: &str) -> Result<Vec<u8>, TpmResult> {
        decode_blob(EncodedBlobKind::InitState, data.as_bytes())
    }

    fn tagged(payload: &str) -> String {
        format!("{BEGIN}\n{payload}\n{END}")
    }

    fn decode_payload(payload: &str) -> Result<Vec<u8>, TpmResult> {
        decode(&tagged(payload))
    }

    fn decode_bytes(data: &[u8]) -> Result<Vec<u8>, TpmResult> {
        decode_blob(EncodedBlobKind::InitState, data)
    }

    #[test]
    fn a_valid_initstate_block_decodes() {
        assert_eq!(decode_payload("QUJD").unwrap(), b"ABC");
    }

    #[test]
    fn tags_without_any_separator_decode() {
        assert_eq!(decode(&format!("{BEGIN}QUJD{END}")).unwrap(), b"ABC");
    }

    #[test]
    fn wrapped_base64_lines_decode() {
        assert_eq!(
            decode_payload("QUJD\nRUZH\nSElK").unwrap(),
            b"ABCEFGHIJ".to_vec()
        );
    }

    #[test]
    fn spaces_tabs_cr_and_lf_inside_the_payload_are_ignored() {
        assert_eq!(decode_payload("Q U\tJ\rD\n").unwrap(), b"ABC");
        assert_eq!(decode_payload("\r\nQUJD\r\n").unwrap(), b"ABC");
        assert_eq!(decode_payload("Q\u{b}U\u{c}JD").unwrap(), b"ABC");
    }

    #[test]
    fn whitespace_after_the_begin_tag_is_skipped() {
        assert_eq!(
            decode(&format!("{BEGIN} \t\r\n QUJD\n{END}")).unwrap(),
            b"ABC"
        );
    }

    #[test]
    fn every_padding_variant_decodes_to_its_exact_length() {
        assert_eq!(decode_payload("QUJD").unwrap(), b"ABC");
        assert_eq!(decode_payload("QUJDRA==").unwrap(), b"ABCD");
        assert_eq!(decode_payload("QUJDRUY=").unwrap(), b"ABCEF");
        assert_eq!(decode_payload("QQ==").unwrap(), b"A");
        assert_eq!(decode_payload("QUJ=").unwrap(), b"AB");
    }

    #[test]
    fn non_canonical_trailing_bits_are_accepted_like_upstream() {
        assert_eq!(decode_payload("QR==").unwrap(), b"A");
        assert_eq!(decode_payload("QUL=").unwrap(), b"AB");
    }

    #[test]
    fn the_whole_base64_alphabet_decodes() {
        assert_eq!(decode_payload("+/+/").unwrap(), [0xfb, 0xff, 0xbf]);
        assert_eq!(
            decode_payload("aA0+/z==").unwrap(),
            [0x68, 0x0d, 0x3e, 0xff]
        );
    }

    #[test]
    fn text_around_the_tagged_block_is_ignored() {
        assert_eq!(
            decode(&format!("junk before\n{BEGIN}\nQUJD\n{END}\njunk after\n")).unwrap(),
            b"ABC"
        );
    }

    #[test]
    fn a_missing_begin_tag_fails() {
        assert_eq!(decode(&format!("QUJD\n{END}")), Err(TPM_FAIL));
        assert_eq!(decode("-----BEGIN INITSTATE----\nQUJD\n"), Err(TPM_FAIL));
        assert_eq!(decode("hello world"), Err(TPM_FAIL));
        assert_eq!(decode(""), Err(TPM_FAIL));
    }

    #[test]
    fn a_missing_end_tag_fails() {
        assert_eq!(decode(&format!("{BEGIN}\nQUJD\n")), Err(TPM_FAIL));
        assert_eq!(
            decode(&format!("{BEGIN}\nQUJD\n-----END INITSTATE----")),
            Err(TPM_FAIL)
        );
    }

    #[test]
    fn an_end_tag_before_the_begin_tag_fails() {
        assert_eq!(
            decode(&format!("{END}\nQUJD\n{BEGIN}\nQUJD\n")),
            Err(TPM_FAIL)
        );
        assert_eq!(decode(&format!("{END}{BEGIN}QUJD")), Err(TPM_FAIL));
    }

    #[test]
    fn an_empty_payload_fails() {
        assert_eq!(decode(&format!("{BEGIN}{END}")), Err(TPM_FAIL));
        assert_eq!(decode(&format!("{BEGIN}\n{END}")), Err(TPM_FAIL));
        assert_eq!(decode(&format!("{BEGIN}  \t\r\n  {END}")), Err(TPM_FAIL));
    }

    #[test]
    fn invalid_base64_characters_are_dropped_from_the_payload() {
        assert_eq!(decode_payload("QU!JD").unwrap(), b"ABC");
        assert_eq!(decode_payload("Q-U-J-D").unwrap(), b"ABC");
        assert_eq!(
            decode_bytes(&[BEGIN.as_bytes(), b"\nQU\x80\xffJD\n", END.as_bytes()].concat())
                .unwrap(),
            b"ABC"
        );
    }

    #[test]
    fn parsing_stops_at_the_first_nul_like_a_c_string() {
        let block = tagged("QUJD");
        for (what, data) in [
            (
                "before the begin tag",
                [b"\0".as_slice(), block.as_bytes()].concat(),
            ),
            (
                "between the begin tag and the payload",
                [BEGIN.as_bytes(), b"\0QUJD\n", END.as_bytes()].concat(),
            ),
            (
                "inside the payload",
                [BEGIN.as_bytes(), b"\nQU\0JD\n", END.as_bytes()].concat(),
            ),
            (
                "before the end tag",
                [BEGIN.as_bytes(), b"\nQUJD\n\0", END.as_bytes()].concat(),
            ),
        ] {
            assert_eq!(decode_bytes(&data), Err(TPM_FAIL), "a NUL {what}");
        }

        assert_eq!(
            decode_bytes(&[block.as_bytes(), b"\0junk after"].concat()).unwrap(),
            b"ABC",
            "bytes after the terminator are not part of the input"
        );
        assert_eq!(
            decode_bytes(&[block.as_bytes(), b"\0", tagged("RUZH").as_bytes()].concat()).unwrap(),
            b"ABC"
        );
    }

    #[test]
    fn a_payload_of_only_invalid_characters_fails() {
        assert_eq!(decode_payload("!!!!"), Err(TPM_FAIL));
        assert_eq!(decode_payload("-----"), Err(TPM_FAIL));
    }

    #[test]
    fn a_base64_length_that_is_not_a_multiple_of_four_fails() {
        for payload in ["Q", "QQ", "QUJ", "QUJDRA", "QUJDRUZH SElKS"] {
            assert_eq!(decode_payload(payload), Err(TPM_FAIL), "payload {payload}");
        }
    }

    #[test]
    fn truncated_and_misplaced_padding_fails() {
        for payload in [
            "Q===", "====", "AAAA====", "QUJDRA=", "QQ==QQ==", "QQ==QUJD", "QQ=A", "=QUJD",
            "AAAA==",
        ] {
            assert_eq!(decode_payload(payload), Err(TPM_FAIL), "payload {payload}");
        }
    }

    #[test]
    fn the_first_tagged_block_wins() {
        assert_eq!(
            decode(&format!("{BEGIN}\nQUJD\n{END}\n{BEGIN}\nRUZH\n{END}")).unwrap(),
            b"ABC"
        );
        assert_eq!(
            decode(&format!("{BEGIN}\nQUJD\n{END}\nRUZH\n{END}")).unwrap(),
            b"ABC"
        );
    }

    #[test]
    fn a_repeated_begin_tag_becomes_payload() {
        assert_eq!(
            decode(&format!("{BEGIN}\n{BEGIN}\nQUJD\n{END}")),
            Err(TPM_FAIL),
            "the letters of the second tag join the payload and unbalance it"
        );
        assert_eq!(
            decode(&format!("{BEGIN}\n{BEGIN}\nQU\n{END}")).unwrap(),
            decode_payload("BEGININITSTATEQU").unwrap()
        );
    }

    #[test]
    fn a_large_wrapped_blob_decodes_to_its_exact_length() {
        let blob: Vec<u8> = (0..3000u32).map(|index| (index % 251) as u8).collect();
        let encoded = encode_base64(&blob);
        let wrapped: Vec<String> = encoded
            .as_bytes()
            .chunks(64)
            .map(|line| String::from_utf8(line.to_vec()).unwrap())
            .collect();
        assert_eq!(decode_payload(&wrapped.join("\n")).unwrap(), blob);
    }

    fn encode_base64(data: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut encoded = Vec::new();
        for group in data.chunks(3) {
            let mut bits = 0u32;
            for (index, byte) in group.iter().enumerate() {
                bits |= u32::from(*byte) << (16 - 8 * index);
            }
            for index in 0..group.len() + 1 {
                encoded.push(ALPHABET[(bits >> (18 - 6 * index)) as usize & 0x3f]);
            }
            encoded.resize(encoded.len() + (3 - group.len()), b'=');
        }
        String::from_utf8(encoded).unwrap()
    }

    #[test]
    fn round_trips_every_length_up_to_four_groups() {
        for length in 1..=12usize {
            let blob: Vec<u8> = (0..length).map(|index| (index * 37 + 1) as u8).collect();
            assert_eq!(
                decode_payload(&encode_base64(&blob)).unwrap(),
                blob,
                "length {length}"
            );
        }
    }

    #[test]
    fn arbitrary_malformed_input_never_panics() {
        let mut seed = 0x1234_5678u32;
        let mut next = move || {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (seed >> 16) as u8
        };
        let alphabet = b"ABCyz09+/=- \t\r\n\0\x80\xff";
        for case in 0..2000 {
            let length = usize::from(next()) % 96;
            let mut data: Vec<u8> = (0..length)
                .map(|_| alphabet[usize::from(next()) % alphabet.len()])
                .collect();
            if case % 3 == 0 {
                data.splice(0..0, BEGIN.bytes());
            }
            if case % 5 == 0 {
                let at = usize::from(next()) % (data.len() + 1);
                data.splice(at..at, END.bytes());
            }
            if case % 7 == 0 {
                let at = usize::from(next()) % (data.len() + 1);
                data.insert(at, 0);
            }
            let _ = decode_bytes(&data);
        }
    }

    const DECODE_BLOB_ORACLE: &str = include_str!("testdata/decode_blob_oracle.txt");

    struct OracleRecord {
        name: String,
        input: Vec<u8>,
        expected: Result<Vec<u8>, TpmResult>,
    }

    fn unhex(field: &str, record: &str) -> Vec<u8> {
        assert!(
            field.len().is_multiple_of(2),
            "{record}: odd-length hex field {field}"
        );
        field
            .as_bytes()
            .chunks(2)
            .map(|byte| {
                u8::from_str_radix(core::str::from_utf8(byte).unwrap(), 16)
                    .unwrap_or_else(|_| panic!("{record}: unparsable hex field {field}"))
            })
            .collect()
    }

    fn oracle_records() -> Vec<OracleRecord> {
        DECODE_BLOB_ORACLE
            .lines()
            .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
            .map(|line| {
                let fields: Vec<&str> = line.split('\t').collect();
                assert_eq!(fields.len(), 4, "unparsable oracle record {line}");
                let expected = match (fields[2], fields[3]) {
                    ("0", decoded) => Ok(unhex(decoded, line)),
                    (result, "-") => Err(result
                        .parse()
                        .unwrap_or_else(|_| panic!("{line}: unparsable oracle result {result}"))),
                    _ => panic!("{line}: a failing record must not carry decoded bytes"),
                };
                OracleRecord {
                    name: fields[0].to_owned(),
                    input: unhex(fields[1], line),
                    expected,
                }
            })
            .collect()
    }

    #[test]
    fn every_c_oracle_record_is_replayed() {
        let records = oracle_records();
        assert!(!records.is_empty(), "the oracle fixture has no records");
        let mut names: Vec<&str> = records.iter().map(|record| record.name.as_str()).collect();
        names.sort_unstable();
        let unique = names.len();
        names.dedup();
        assert_eq!(names.len(), unique, "the oracle fixture repeats a scenario");

        let mut replayed = 0;
        for record in &records {
            assert_eq!(
                decode_bytes(&record.input),
                record.expected,
                "{}: vendored C TPMLIB_DecodeBlob",
                record.name
            );
            replayed += 1;
        }
        assert_eq!(replayed, records.len());
    }
}
