use super::Fixture;

const MAGIC: &[u8; 8] = b"RVORACLE";

static FIXTURE: Fixture = Fixture::new(
    "TPM2_ReadPublic and TPM2_VerifySignature",
    MAGIC,
    include_bytes!("../testdata/golden_responses/read_public_verify_signature.bin"),
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
        magic: b"RVORACLE",
        file: "../testdata/golden_responses/read_public_verify_signature.bin",
    }
}
