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
    use crate::library::tpm2::golden_responses::golden_fixture;

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
        for vector in nv_vectors()
            .into_iter()
            .chain(certify_vectors())
            .filter(|vector| !vector.name.starts_with("PERMALL"))
        {
            assert!(vector.bytes.len() >= 10, "{}", vector.name);
            let tag = u16::from_be_bytes([vector.bytes[0], vector.bytes[1]]);
            assert!(
                tag == 0x8001 || tag == 0x8002,
                "{} carries a response tag, found {tag:#06x}",
                vector.name
            );
            let size =
                u32::from_be_bytes(vector.bytes[2..6].try_into().expect("four bytes")) as usize;
            assert_eq!(size, vector.bytes.len(), "{}", vector.name);
        }
    }
}
