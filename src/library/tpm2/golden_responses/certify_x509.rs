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
    use crate::library::tpm2::golden_responses::{
        assert_command_responses_well_formed, golden_fixture,
    };

    golden_fixture! {
        module: fixture,
        fixture: FIXTURE,
        lookup: vector,
        magic: b"CXORACLE",
        file: "../testdata/golden_responses/certify_x509.bin",
    }

    #[test]
    fn command_response_well_formedness() {
        assert_command_responses_well_formed("certify-x509", &vectors(), &["PERMALL", "VOLATILE"]);
    }
}
