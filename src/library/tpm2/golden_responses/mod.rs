use std::sync::OnceLock;

pub(in crate::library::tpm2) mod attestation;
pub(in crate::library::tpm2) mod certify_x509;
pub(in crate::library::tpm2) mod create;
pub(in crate::library::tpm2) mod create_loaded;
pub(in crate::library::tpm2) mod create_primary;
pub(in crate::library::tpm2) mod credential_activation;
pub(in crate::library::tpm2) mod dictionary_attack;
pub(in crate::library::tpm2) mod disabled_commands;
pub(in crate::library::tpm2) mod ecc_commands;
pub(in crate::library::tpm2) mod encrypt_decrypt;
pub(in crate::library::tpm2) mod evict_control;
pub(in crate::library::tpm2) mod flush_context;
pub(in crate::library::tpm2) mod get_test_result;
pub(in crate::library::tpm2) mod hierarchy_management;
pub(in crate::library::tpm2) mod hmac;
pub(in crate::library::tpm2) mod nv;
pub(in crate::library::tpm2) mod object_lifecycle;
pub(in crate::library::tpm2) mod object_transfer;
pub(in crate::library::tpm2) mod pcr_event;
pub(in crate::library::tpm2) mod platform_state;
pub(in crate::library::tpm2) mod policy_sessions;
pub(in crate::library::tpm2) mod read_public_verify_signature;
pub(in crate::library::tpm2) mod rsa_encryption;
pub(in crate::library::tpm2) mod sequence_commands;
pub(in crate::library::tpm2) mod sign;
pub(in crate::library::tpm2) mod test_parms;

pub(in crate::library::tpm2) const VERSION: u16 = 1;

const MAGIC_LENGTH: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) struct GoldenVector<'a> {
    pub(in crate::library::tpm2) name: &'a str,
    pub(in crate::library::tpm2) bytes: &'a [u8],
}

pub(in crate::library::tpm2) struct Fixture {
    label: &'static str,
    magic: &'static [u8; MAGIC_LENGTH],
    data: &'static [u8],
    cache: OnceLock<Vec<GoldenVector<'static>>>,
}

impl Fixture {
    pub(in crate::library::tpm2) const fn new(
        label: &'static str,
        magic: &'static [u8; MAGIC_LENGTH],
        data: &'static [u8],
    ) -> Self {
        Self {
            label,
            magic,
            data,
            cache: OnceLock::new(),
        }
    }

    #[track_caller]
    fn records(&self) -> &[GoldenVector<'static>] {
        self.cache.get_or_init(|| {
            parse(self.magic, self.data)
                .unwrap_or_else(|| panic!("the {} oracle fixture parses", self.label))
        })
    }

    pub(in crate::library::tpm2) fn magic(&self) -> &'static [u8; MAGIC_LENGTH] {
        self.magic
    }

    pub(in crate::library::tpm2) fn bytes(&self) -> &'static [u8] {
        self.data
    }

    #[track_caller]
    pub(in crate::library::tpm2) fn vectors(&self) -> Vec<GoldenVector<'static>> {
        self.records().to_vec()
    }

    #[track_caller]
    pub(in crate::library::tpm2) fn find(&self, name: &str) -> Option<&'static [u8]> {
        let records = self.records();
        records
            .binary_search_by(|record| record.name.cmp(name))
            .ok()
            .map(|index| records[index].bytes)
    }

    #[track_caller]
    pub(in crate::library::tpm2) fn get(&self, name: &str) -> &'static [u8] {
        self.find(name)
            .unwrap_or_else(|| panic!("no {} oracle vector named {name}", self.label))
    }
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

fn parse<'a>(magic: &[u8; MAGIC_LENGTH], data: &'a [u8]) -> Option<Vec<GoldenVector<'a>>> {
    let mut reader = Reader::new(data);
    if reader.take(MAGIC_LENGTH)? != magic {
        return None;
    }
    if reader.u16()? != VERSION {
        return None;
    }
    let count = usize::from(reader.u16()?);
    let mut vectors: Vec<GoldenVector<'a>> = Vec::with_capacity(count.min(64));
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
        vectors.push(GoldenVector { name, bytes });
    }
    if !reader.is_empty() {
        return None;
    }
    Some(vectors)
}

#[cfg(test)]
fn synthesize(
    magic: &[u8; MAGIC_LENGTH],
    version: u16,
    declared_count: u16,
    records: &[(&str, &[u8])],
) -> Vec<u8> {
    let mut out = magic.to_vec();
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&declared_count.to_be_bytes());
    for (name, payload) in records {
        out.push(name.len() as u8);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
    }
    out
}

#[track_caller]
pub(in crate::library::tpm2) fn assert_fixture_integrity(fixture: &Fixture) {
    let vectors = fixture.vectors();
    assert!(!vectors.is_empty(), "{} has no records", fixture.label);
    for vector in &vectors {
        assert!(
            !vector.name.is_empty(),
            "{} has an empty name",
            fixture.label
        );
        assert!(!vector.bytes.is_empty(), "{}", vector.name);
        assert_eq!(fixture.get(vector.name), vector.bytes, "{}", vector.name);
    }
    for pair in vectors.windows(2) {
        assert!(
            pair[0].name < pair[1].name,
            "{} then {} is not sorted",
            pair[0].name,
            pair[1].name
        );
    }
}

macro_rules! golden_fixture {
    (
        module: $module:ident,
        fixture: $fixture:ident,
        lookup: $lookup:ident,
        magic: $magic:expr,
        file: $file:expr $(,)?
    ) => {
        mod $module {
            use crate::library::tpm2::golden_responses;

            #[test]
            fn fixture_records_are_sorted_and_unique() {
                golden_responses::assert_fixture_integrity(&super::super::$fixture);
            }

            #[test]
            fn fixture_lookup_finds_only_known_names() {
                let fixture = &super::super::$fixture;
                for absent in ["NOT_A_VECTOR", "NO_SUCH_VECTOR", ""] {
                    assert!(fixture.find(absent).is_none(), "{absent}");
                }
                for record in fixture.vectors() {
                    assert_eq!(
                        super::super::$lookup(record.name),
                        record.bytes,
                        "{}",
                        record.name
                    );
                }
            }

            #[test]
            fn reader_uses_expected_magic_and_file() {
                let fixture = &super::super::$fixture;
                assert_eq!(fixture.magic(), $magic);
                assert_eq!(fixture.bytes(), include_bytes!($file).as_slice());
            }
        }
    };
}

pub(in crate::library::tpm2) use golden_fixture;

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER_LENGTH: usize = MAGIC_LENGTH + 4;
    const MAGIC: &[u8; MAGIC_LENGTH] = b"SYNORCLE";
    const RECORDS: [(&str, &[u8]); 3] = [
        ("ALPHA", &[0xa0]),
        ("BETA_1", &[0xb0, 0xb1]),
        ("GAMMA", &[0xc0, 0xc1, 0xc2]),
    ];

    fn fixture() -> Vec<u8> {
        synthesize(MAGIC, VERSION, RECORDS.len() as u16, &RECORDS)
    }

    fn expected() -> Vec<GoldenVector<'static>> {
        RECORDS
            .iter()
            .map(|&(name, bytes)| GoldenVector { name, bytes })
            .collect()
    }

    #[test]
    fn well_formed_fixture_parses() {
        let data = fixture();
        assert_eq!(parse(MAGIC, &data).expect("the fixture parses"), expected());
    }

    #[test]
    fn invalid_magic_is_rejected() {
        for offset in 0..MAGIC_LENGTH {
            let mut broken = fixture();
            broken[offset] ^= 0xff;
            assert!(
                parse(MAGIC, &broken).is_none(),
                "magic byte {offset} must be checked"
            );
        }
        let alien = synthesize(b"OTHRORCL", VERSION, RECORDS.len() as u16, &RECORDS);
        assert!(parse(MAGIC, &alien).is_none());
        assert!(parse(b"OTHRORCL", &fixture()).is_none());
    }

    #[test]
    fn an_unsupported_version_is_rejected() {
        for version in [0u16, VERSION + 1, VERSION + 2, u16::MAX] {
            let data = synthesize(MAGIC, version, RECORDS.len() as u16, &RECORDS);
            assert!(parse(MAGIC, &data).is_none(), "version {version}");
        }
    }

    #[test]
    fn wrong_record_count_is_rejected() {
        for declared in [0u16, 1, 2, 4, u16::MAX] {
            let data = synthesize(MAGIC, VERSION, declared, &RECORDS);
            assert!(parse(MAGIC, &data).is_none(), "record count {declared}");
        }
    }

    #[test]
    fn invalid_record_names_and_order_are_rejected() {
        let payload: &[u8] = &[0xaa];
        for (what, count, records) in [
            ("an empty name", 1u16, vec![("", payload)]),
            ("a lower-case name", 1, vec![("alpha", payload)]),
            ("a punctuated name", 1, vec![("AL-PHA", payload)]),
            ("a spaced name", 1, vec![("AL PHA", payload)]),
            (
                "duplicates",
                2,
                vec![("ALPHA", payload), ("ALPHA", payload)],
            ),
            (
                "out-of-order names",
                2,
                vec![("BETA", payload), ("ALPHA", payload)],
            ),
        ] {
            let data = synthesize(MAGIC, VERSION, count, &records);
            assert!(parse(MAGIC, &data).is_none(), "{what} must be rejected");
        }

        let mut non_ascii = fixture();
        non_ascii[HEADER_LENGTH + 1] = 0xff;
        assert!(parse(MAGIC, &non_ascii).is_none(), "a non-ASCII name");
    }

    #[test]
    fn truncated_fields_are_rejected() {
        let data = fixture();
        let name_length = usize::from(data[HEADER_LENGTH]);
        for cut in [
            MAGIC_LENGTH - 1,
            MAGIC_LENGTH,
            MAGIC_LENGTH + 1,
            HEADER_LENGTH - 1,
            HEADER_LENGTH,
            HEADER_LENGTH + 1,
            HEADER_LENGTH + name_length,
            HEADER_LENGTH + 1 + name_length,
            HEADER_LENGTH + 1 + name_length + 3,
            HEADER_LENGTH + 1 + name_length + 4,
        ] {
            assert!(
                parse(MAGIC, &data[..cut]).is_none(),
                "a {cut}-byte prefix must not parse"
            );
        }
    }

    #[test]
    fn oversized_lengths_are_rejected() {
        let data = fixture();
        let name_length = usize::from(data[HEADER_LENGTH]);
        let payload_length_at = HEADER_LENGTH + 1 + name_length;

        let mut long_name = data.clone();
        long_name[HEADER_LENGTH] = 0xff;
        assert!(parse(MAGIC, &long_name).is_none(), "an overlong name");

        let mut long_payload = data.clone();
        long_payload[payload_length_at..payload_length_at + 4]
            .copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(
            parse(MAGIC, &long_payload).is_none(),
            "an enormous payload length"
        );

        let mut short_payload = data;
        short_payload[payload_length_at + 3] = 0x00;
        assert!(
            parse(MAGIC, &short_payload).is_none(),
            "a shortened payload length"
        );
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        for trailer in [vec![0x00], vec![0xff; 16]] {
            let mut extended = fixture();
            extended.extend_from_slice(&trailer);
            assert!(parse(MAGIC, &extended).is_none(), "{} bytes", trailer.len());
        }
    }

    #[test]
    fn fixture_truncations_are_rejected() {
        let data = fixture();
        for length in 0..data.len() {
            assert!(
                parse(MAGIC, &data[..length]).is_none(),
                "a {length}-byte prefix must not parse"
            );
        }
    }

    #[test]
    fn fixture_repacking_is_stable() {
        let data = fixture();
        let vectors = parse(MAGIC, &data).expect("the fixture parses");
        let records: Vec<(&str, &[u8])> = vectors
            .iter()
            .map(|vector| (vector.name, vector.bytes))
            .collect();
        assert_eq!(
            synthesize(MAGIC, VERSION, records.len() as u16, &records),
            data
        );
    }
}
