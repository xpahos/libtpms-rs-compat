use super::Fixture;

const MAGIC: &[u8; 8] = b"PLORACLE";

static FIXTURE: Fixture = Fixture::new(
    "platform and state management",
    MAGIC,
    include_bytes!("../testdata/golden_responses/platform_state.bin"),
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
        magic: b"PLORACLE",
        file: "../testdata/golden_responses/platform_state.bin",
    }
}
