use super::{Fixture, GoldenVector};

const MAGIC: &[u8; 8] = b"ATORACLE";

static FIXTURE: Fixture = Fixture::new(
    "attestation",
    MAGIC,
    include_bytes!("../testdata/golden_responses/attestation.bin"),
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
        magic: b"ATORACLE",
        file: "../testdata/golden_responses/attestation.bin",
    }

    #[test]
    fn command_response_well_formedness() {
        assert_command_responses_well_formed(
            "attestation",
            &vectors(),
            &["PERMALL", "VOLATILE", "EXCLUSIVE"],
        );
    }
}
