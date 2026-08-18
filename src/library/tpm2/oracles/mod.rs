pub(in crate::library::tpm2) mod create_primary;
pub(in crate::library::tpm2) mod dictionary_attack;
pub(in crate::library::tpm2) mod evict_control;
pub(in crate::library::tpm2) mod flush_context;
pub(in crate::library::tpm2) mod nv;

use super::crypto::Hasher;
use super::public::TPM_ALG_SHA256;

pub(in crate::library::tpm2) const VERSION: u16 = 1;

const MAGIC_LENGTH: usize = 8;
const HEADER_LENGTH: usize = MAGIC_LENGTH + 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) struct OracleVector<'a> {
    pub(in crate::library::tpm2) name: &'a str,
    pub(in crate::library::tpm2) bytes: &'a [u8],
}

pub(in crate::library::tpm2) struct Fixture {
    label: &'static str,
    magic: &'static [u8; MAGIC_LENGTH],
    data: &'static [u8],
}

impl Fixture {
    pub(in crate::library::tpm2) const fn new(
        label: &'static str,
        magic: &'static [u8; MAGIC_LENGTH],
        data: &'static [u8],
    ) -> Self {
        Self { label, magic, data }
    }

    pub(in crate::library::tpm2) fn parse<'a>(
        &self,
        data: &'a [u8],
    ) -> Option<Vec<OracleVector<'a>>> {
        parse(self.magic, data)
    }

    pub(in crate::library::tpm2) fn magic(&self) -> &'static [u8; MAGIC_LENGTH] {
        self.magic
    }

    pub(in crate::library::tpm2) fn bytes(&self) -> &'static [u8] {
        self.data
    }

    #[track_caller]
    pub(in crate::library::tpm2) fn vectors(&self) -> Vec<OracleVector<'static>> {
        parse(self.magic, self.data)
            .unwrap_or_else(|| panic!("the {} oracle fixture parses", self.label))
    }

    pub(in crate::library::tpm2) fn find(&self, name: &str) -> Option<&'static [u8]> {
        parse(self.magic, self.data)?
            .into_iter()
            .find(|vector| vector.name == name)
            .map(|vector| vector.bytes)
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

fn parse<'a>(magic: &[u8; MAGIC_LENGTH], data: &'a [u8]) -> Option<Vec<OracleVector<'a>>> {
    let mut reader = Reader::new(data);
    if reader.take(MAGIC_LENGTH)? != magic {
        return None;
    }
    if reader.u16()? != VERSION {
        return None;
    }
    let count = usize::from(reader.u16()?);
    let mut vectors: Vec<OracleVector<'a>> = Vec::with_capacity(count.min(64));
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

pub(in crate::library::tpm2) fn synthesize(
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

fn digest(bytes: &[u8]) -> String {
    let mut hasher = Hasher::new(TPM_ALG_SHA256).expect("SHA-256 is compiled in");
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[track_caller]
pub(in crate::library::tpm2) fn assert_records_match(
    fixture: &Fixture,
    expected: &[(&str, usize, &str)],
) {
    let vectors = fixture.vectors();
    let names: Vec<&str> = vectors.iter().map(|vector| vector.name).collect();
    let wanted: Vec<&str> = expected.iter().map(|(name, _, _)| *name).collect();
    assert_eq!(names, wanted, "the fixture holds exactly the named vectors");
    for (name, length, sha256) in expected {
        let bytes = fixture.get(name);
        assert_eq!(bytes.len(), *length, "{name} length");
        assert_eq!(&digest(bytes), sha256, "{name} contents");
    }
}

#[track_caller]
pub(in crate::library::tpm2) fn assert_names_are_sorted_and_unique(fixture: &Fixture) {
    let vectors = fixture.vectors();
    assert!(!vectors.is_empty());
    for vector in &vectors {
        assert!(!vector.name.is_empty());
        assert!(!vector.bytes.is_empty(), "{}", vector.name);
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

#[track_caller]
pub(in crate::library::tpm2) fn assert_rejects_a_corrupted_header(fixture: &Fixture) {
    for offset in 0..MAGIC_LENGTH {
        let mut broken = fixture.bytes().to_vec();
        broken[offset] ^= 0xff;
        assert!(
            fixture.parse(&broken).is_none(),
            "magic byte {offset} must be checked"
        );
    }
    for version in [0u16, VERSION + 1, u16::MAX] {
        let mut broken = fixture.bytes().to_vec();
        broken[MAGIC_LENGTH..MAGIC_LENGTH + 2].copy_from_slice(&version.to_be_bytes());
        assert!(
            fixture.parse(&broken).is_none(),
            "version {version} must be rejected"
        );
    }
    let count_at = MAGIC_LENGTH + 2;
    let count = u16::from_be_bytes([fixture.bytes()[count_at], fixture.bytes()[count_at + 1]]);
    for declared in [count - 1, count + 1, 0, u16::MAX] {
        let mut broken = fixture.bytes().to_vec();
        broken[count_at..count_at + 2].copy_from_slice(&declared.to_be_bytes());
        assert!(
            fixture.parse(&broken).is_none(),
            "a record count of {declared} must be rejected"
        );
    }
}

#[track_caller]
pub(in crate::library::tpm2) fn assert_rejects_a_corrupted_record(fixture: &Fixture) {
    let name_length = usize::from(fixture.bytes()[HEADER_LENGTH]);
    let length_at = HEADER_LENGTH + 1 + name_length;
    for (what, offset, value) in [
        ("an empty name", HEADER_LENGTH, 0x00),
        ("an overlong name", HEADER_LENGTH, 0xff),
        ("a lower-case name", HEADER_LENGTH + 1, b'a'),
        ("a punctuated name", HEADER_LENGTH + 1, b'-'),
        ("a non-ASCII name", HEADER_LENGTH + 1, 0xff),
        ("an enormous payload", length_at, 0xff),
        ("a shortened payload", length_at + 3, 0x00),
    ] {
        let mut broken = fixture.bytes().to_vec();
        assert_ne!(broken[offset], value, "{what} would not change a byte");
        broken[offset] = value;
        assert!(fixture.parse(&broken).is_none(), "{what} must be rejected");
    }

    let magic = fixture.magic();
    let payload: &[u8] = &[0xaa];
    for (what, count, records) in [
        (
            "duplicates",
            2u16,
            vec![("ALPHA", payload), ("ALPHA", payload)],
        ),
        (
            "out-of-order names",
            2,
            vec![("BETA", payload), ("ALPHA", payload)],
        ),
        ("an empty name", 1, vec![("", payload)]),
        ("a lower-case name", 1, vec![("alpha", payload)]),
        ("a missing record", 2, vec![("ALPHA", payload)]),
        (
            "an unannounced record",
            1,
            vec![("ALPHA", payload), ("BETA", payload)],
        ),
    ] {
        let broken = synthesize(magic, VERSION, count, &records);
        assert!(fixture.parse(&broken).is_none(), "{what} must be rejected");
    }

    let sound = synthesize(magic, VERSION, 2, &[("ALPHA", payload), ("BETA", payload)]);
    assert_eq!(
        fixture.parse(&sound).expect("well-formed records parse"),
        [
            OracleVector {
                name: "ALPHA",
                bytes: payload
            },
            OracleVector {
                name: "BETA",
                bytes: payload
            },
        ]
    );
}

#[track_caller]
pub(in crate::library::tpm2) fn assert_rejects_truncation_and_trailing_bytes(fixture: &Fixture) {
    let data = fixture.bytes();
    for length in 0..data.len() {
        assert!(
            fixture.parse(&data[..length]).is_none(),
            "a {length}-byte prefix must not parse"
        );
    }
    let mut extended = data.to_vec();
    extended.push(0x00);
    assert!(
        fixture.parse(&extended).is_none(),
        "trailing bytes must be rejected"
    );
}
