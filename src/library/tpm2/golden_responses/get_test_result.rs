use super::Fixture;

const MAGIC: &[u8; 8] = b"GTORACLE";

static FIXTURE: Fixture = Fixture::new(
    "TPM2_GetTestResult",
    MAGIC,
    include_bytes!("../testdata/golden_responses/get_test_result.bin"),
);

#[track_caller]
pub(in crate::library::tpm2) fn vector(name: &str) -> &'static [u8] {
    FIXTURE.get(name)
}

#[cfg(test)]
mod tests {
    use crate::library::tpm2::golden_responses::golden_fixture;

    golden_fixture! {
        module: fixture,
        fixture: FIXTURE,
        lookup: vector,
        magic: b"GTORACLE",
        file: "../testdata/golden_responses/get_test_result.bin",
    }
}
