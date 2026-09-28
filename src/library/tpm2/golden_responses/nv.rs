// Part of the Rust port of libtpms.
//
// Upstream behavior references for this Rust implementation:
// - libtpms/src/tpm2/NVCommands.c
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust implementation:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use super::{Fixture, GoldenVector};

const COMMAND_MAGIC: &[u8; 8] = b"NVORACLE";
const CERTIFY_MAGIC: &[u8; 8] = b"NCORACLE";

static COMMAND_FIXTURE: Fixture = Fixture::new(
    "NV command",
    COMMAND_MAGIC,
    include_bytes!("../testdata/golden_responses/nv_commands.bin"),
);

static CERTIFY_FIXTURE: Fixture = Fixture::new(
    "TPM2_NV_Certify",
    CERTIFY_MAGIC,
    include_bytes!("../testdata/golden_responses/nv_certify.bin"),
);

#[track_caller]
pub(in crate::library::tpm2) fn nv_vector(name: &str) -> &'static [u8] {
    COMMAND_FIXTURE.get(name)
}

#[track_caller]
pub(in crate::library::tpm2) fn certify_vector(name: &str) -> &'static [u8] {
    CERTIFY_FIXTURE.get(name)
}

#[track_caller]
pub(in crate::library::tpm2) fn nv_vectors() -> Vec<GoldenVector<'static>> {
    COMMAND_FIXTURE.vectors()
}

#[track_caller]
pub(in crate::library::tpm2) fn certify_vectors() -> Vec<GoldenVector<'static>> {
    CERTIFY_FIXTURE.vectors()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::golden_responses::{
        assert_command_responses_well_formed, golden_fixture,
    };

    golden_fixture! {
        module: command_fixture,
        fixture: COMMAND_FIXTURE,
        lookup: nv_vector,
        magic: b"NVORACLE",
        file: "../testdata/golden_responses/nv_commands.bin",
    }

    golden_fixture! {
        module: certify_fixture,
        fixture: CERTIFY_FIXTURE,
        lookup: certify_vector,
        magic: b"NCORACLE",
        file: "../testdata/golden_responses/nv_certify.bin",
    }

    #[test]
    fn well_formed_command_responses() {
        assert_command_responses_well_formed("NV command", &nv_vectors(), &["PERMALL"]);
        assert_command_responses_well_formed("TPM2_NV_Certify", &certify_vectors(), &["PERMALL"]);
    }
}
