use super::Fixture;

const MAGIC: &[u8; 8] = b"PEORACLE";

static FIXTURE: Fixture = Fixture::new(
    "TPM2_PCR_Event",
    MAGIC,
    include_bytes!("../testdata/golden_responses/pcr_event.bin"),
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
        magic: b"PEORACLE",
        file: "../testdata/golden_responses/pcr_event.bin",
    }
}
