// Part of the Rust port of libtpms.
//
// Upstream behavior references for this Rust implementation:
// - libtpms/src/tpm2/EACommands.c
// - libtpms/src/tpm2/SessionCommands.c
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust implementation:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use super::Fixture;

const MAGIC: &[u8; 8] = b"PSORACLE";

static FIXTURE: Fixture = Fixture::new(
    "TPM2_StartAuthSession and the policy commands",
    MAGIC,
    include_bytes!("../testdata/golden_responses/policy_sessions.bin"),
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
        magic: b"PSORACLE",
        file: "../testdata/golden_responses/policy_sessions.bin",
    }
}
