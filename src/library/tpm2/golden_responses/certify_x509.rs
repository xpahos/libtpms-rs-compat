use super::{Fixture, GoldenVector};

const MAGIC: &[u8; 8] = b"CXORACLE";

static FIXTURE: Fixture = Fixture::new(
    "certify-x509",
    MAGIC,
    include_bytes!("../testdata/golden_responses/certify_x509.bin"),
);

#[track_caller]
pub(in crate::library::tpm2) fn vector(name: &str) -> &'static [u8] {
    FIXTURE.get(name)
}

#[track_caller]
pub(in crate::library::tpm2) fn vectors() -> Vec<GoldenVector<'static>> {
    FIXTURE.vectors()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::golden_responses::golden_fixture;

    golden_fixture! {
        module: fixture,
        fixture: FIXTURE,
        lookup: vector,
        magic: b"CXORACLE",
        file: "../testdata/golden_responses/certify_x509.bin",
    }

    #[test]
    fn command_response_well_formedness() {
        for record in vectors().into_iter().filter(|record| {
            !record.name.starts_with("PERMALL") && !record.name.starts_with("VOLATILE")
        }) {
            assert!(record.bytes.len() >= 10, "{}", record.name);
            let tag = u16::from_be_bytes([record.bytes[0], record.bytes[1]]);
            assert!(
                tag == 0x8001 || tag == 0x8002,
                "{} carries a response tag, found {tag:#06x}",
                record.name
            );
            let size =
                u32::from_be_bytes(record.bytes[2..6].try_into().expect("four bytes")) as usize;
            assert_eq!(size, record.bytes.len(), "{}", record.name);
        }
    }
}
