const COMMAND_FIXTURE: &[u8] = include_bytes!("testdata/nv_command_vectors.bin");
const CERTIFY_FIXTURE: &[u8] = include_bytes!("testdata/nv_certify_vectors.bin");

const MAGIC: &[u8; 8] = b"NVORACLE";
const VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) struct OracleVector<'a> {
    pub(in crate::library::tpm2) name: &'a str,
    pub(in crate::library::tpm2) bytes: &'a [u8],
}

struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, at: 0 }
    }

    fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(length)?;
        let slice = self.data.get(self.at..end)?;
        self.at = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|bytes| bytes[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2)
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn is_empty(&self) -> bool {
        self.at == self.data.len()
    }
}

fn parse(fixture: &[u8]) -> Option<Vec<OracleVector<'_>>> {
    let mut reader = Reader::new(fixture);
    if reader.take(MAGIC.len())? != MAGIC {
        return None;
    }
    if reader.u16()? != VERSION {
        return None;
    }
    let count = usize::from(reader.u16()?);
    let mut vectors: Vec<OracleVector<'_>> = Vec::with_capacity(count);
    for _ in 0..count {
        let name_length = usize::from(reader.u8()?);
        if name_length == 0 {
            return None;
        }
        let name = core::str::from_utf8(reader.take(name_length)?).ok()?;
        if !name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return None;
        }
        let payload_length = usize::try_from(reader.u32()?).ok()?;
        let bytes = reader.take(payload_length)?;
        if let Some(previous) = vectors.last()
            && previous.name >= name
        {
            return None;
        }
        vectors.push(OracleVector { name, bytes });
    }
    if !reader.is_empty() {
        return None;
    }
    Some(vectors)
}

fn lookup(fixture: &'static [u8], name: &str) -> Option<&'static [u8]> {
    parse(fixture)?
        .into_iter()
        .find(|vector| vector.name == name)
        .map(|vector| vector.bytes)
}

#[track_caller]
pub(in crate::library::tpm2) fn nv_vector(name: &str) -> &'static [u8] {
    lookup(COMMAND_FIXTURE, name).unwrap_or_else(|| panic!("no NV command vector named {name}"))
}

#[track_caller]
pub(in crate::library::tpm2) fn certify_vector(name: &str) -> &'static [u8] {
    lookup(CERTIFY_FIXTURE, name)
        .unwrap_or_else(|| panic!("no TPM2_NV_Certify vector named {name}"))
}

#[track_caller]
pub(in crate::library::tpm2) fn nv_vectors() -> Vec<OracleVector<'static>> {
    parse(COMMAND_FIXTURE).expect("the NV command fixture parses")
}

#[track_caller]
pub(in crate::library::tpm2) fn certify_vectors() -> Vec<OracleVector<'static>> {
    parse(CERTIFY_FIXTURE).expect("the TPM2_NV_Certify fixture parses")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_fixtures_parse_into_named_records() {
        assert_eq!(nv_vectors().len(), 81);
        assert_eq!(certify_vectors().len(), 24);
        for vectors in [nv_vectors(), certify_vectors()] {
            for vector in &vectors {
                assert!(!vector.name.is_empty());
                assert!(!vector.bytes.is_empty(), "{}", vector.name);
            }
        }
    }

    #[test]
    fn the_records_are_sorted_and_unique() {
        for vectors in [nv_vectors(), certify_vectors()] {
            for pair in vectors.windows(2) {
                assert!(
                    pair[0].name < pair[1].name,
                    "{} then {}",
                    pair[0].name,
                    pair[1].name
                );
            }
        }
    }

    #[test]
    fn a_lookup_finds_every_declared_name() {
        for vector in nv_vectors() {
            assert_eq!(nv_vector(vector.name), vector.bytes);
        }
        for vector in certify_vectors() {
            assert_eq!(certify_vector(vector.name), vector.bytes);
        }
        assert!(lookup(COMMAND_FIXTURE, "NOT_A_VECTOR").is_none());
        assert!(lookup(CERTIFY_FIXTURE, "").is_none());
    }

    #[test]
    fn the_command_responses_are_well_formed_tpm_replies() {
        for vector in nv_vectors()
            .into_iter()
            .chain(certify_vectors())
            .filter(|vector| !vector.name.starts_with("PERMALL"))
        {
            assert!(vector.bytes.len() >= 10, "{}", vector.name);
            let tag = u16::from_be_bytes([vector.bytes[0], vector.bytes[1]]);
            assert!(
                tag == 0x8001 || tag == 0x8002,
                "{} carries a response tag, found {tag:#06x}",
                vector.name
            );
            let size =
                u32::from_be_bytes(vector.bytes[2..6].try_into().expect("four bytes")) as usize;
            assert_eq!(size, vector.bytes.len(), "{}", vector.name);
        }
    }

    #[test]
    fn a_truncated_fixture_is_rejected_without_panicking() {
        for fixture in [COMMAND_FIXTURE, CERTIFY_FIXTURE] {
            for length in 0..fixture.len() {
                assert!(
                    parse(&fixture[..length]).is_none(),
                    "a {length}-byte prefix must not parse"
                );
            }
            let mut extended = fixture.to_vec();
            extended.push(0x00);
            assert!(parse(&extended).is_none(), "trailing bytes are rejected");
        }
    }

    #[test]
    fn a_corrupted_header_is_rejected() {
        let mut fixture = COMMAND_FIXTURE.to_vec();
        fixture[0] ^= 0xff;
        assert!(parse(&fixture).is_none(), "the magic is checked");

        let mut fixture = COMMAND_FIXTURE.to_vec();
        fixture[9] = 0x02;
        assert!(parse(&fixture).is_none(), "the version is checked");

        let mut fixture = COMMAND_FIXTURE.to_vec();
        fixture[11] = fixture[11].wrapping_add(1);
        assert!(parse(&fixture).is_none(), "the record count is checked");
    }

    #[test]
    fn a_corrupted_record_is_rejected() {
        let header = MAGIC.len() + 4;
        for offset in [header, header + 1, header + 2] {
            let mut fixture = COMMAND_FIXTURE.to_vec();
            fixture[offset] = 0xff;
            assert!(
                parse(&fixture).is_none(),
                "byte {offset} must not be accepted"
            );
        }
        let mut fixture = COMMAND_FIXTURE.to_vec();
        fixture[header] = 0x00;
        assert!(parse(&fixture).is_none(), "an empty name is rejected");
    }

    #[test]
    fn out_of_order_records_are_rejected() {
        let mut writer = Vec::new();
        writer.extend_from_slice(MAGIC);
        writer.extend_from_slice(&VERSION.to_be_bytes());
        writer.extend_from_slice(&2u16.to_be_bytes());
        for name in ["B", "A"] {
            writer.push(name.len() as u8);
            writer.extend_from_slice(name.as_bytes());
            writer.extend_from_slice(&1u32.to_be_bytes());
            writer.push(0xaa);
        }
        assert!(parse(&writer).is_none());
    }
}
