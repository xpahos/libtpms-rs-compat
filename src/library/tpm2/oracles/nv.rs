use super::{Fixture, OracleVector};

const MAGIC: &[u8; 8] = b"NVORACLE";

const COMMAND_FIXTURE: Fixture = Fixture::new(
    "NV command",
    MAGIC,
    include_bytes!("../testdata/oracles/nv_commands.bin"),
);

const CERTIFY_FIXTURE: Fixture = Fixture::new(
    "TPM2_NV_Certify",
    MAGIC,
    include_bytes!("../testdata/oracles/nv_certify.bin"),
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
pub(in crate::library::tpm2) fn nv_vectors() -> Vec<OracleVector<'static>> {
    COMMAND_FIXTURE.vectors()
}

#[track_caller]
pub(in crate::library::tpm2) fn certify_vectors() -> Vec<OracleVector<'static>> {
    CERTIFY_FIXTURE.vectors()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::oracles;

    #[test]
    fn both_fixtures_parse_into_named_records() {
        assert_eq!(nv_vectors().len(), 81);
        assert_eq!(certify_vectors().len(), 24);
        for vectors in [nv_vectors(), certify_vectors()] {
            for vector in &vectors {
                assert!(!vector.name.is_empty());
                assert!(!vector.bytes.is_empty(), "{}", vector.name);
            }
        }
    }

    #[test]
    fn the_records_are_sorted_and_unique() {
        oracles::assert_names_are_sorted_and_unique(&COMMAND_FIXTURE);
        oracles::assert_names_are_sorted_and_unique(&CERTIFY_FIXTURE);
    }

    #[test]
    fn a_lookup_finds_every_declared_name() {
        for vector in nv_vectors() {
            assert_eq!(nv_vector(vector.name), vector.bytes);
        }
        for vector in certify_vectors() {
            assert_eq!(certify_vector(vector.name), vector.bytes);
        }
        assert!(COMMAND_FIXTURE.find("NOT_A_VECTOR").is_none());
        assert!(CERTIFY_FIXTURE.find("").is_none());
    }

    #[test]
    fn the_command_responses_are_well_formed_tpm_replies() {
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

    #[test]
    fn a_truncated_or_extended_fixture_is_rejected_without_panicking() {
        oracles::assert_rejects_truncation_and_trailing_bytes(&COMMAND_FIXTURE);
        oracles::assert_rejects_truncation_and_trailing_bytes(&CERTIFY_FIXTURE);
    }

    #[test]
    fn a_corrupted_header_is_rejected() {
        oracles::assert_rejects_a_corrupted_header(&COMMAND_FIXTURE);
        oracles::assert_rejects_a_corrupted_header(&CERTIFY_FIXTURE);
    }

    #[test]
    fn a_corrupted_record_is_rejected() {
        oracles::assert_rejects_a_corrupted_record(&COMMAND_FIXTURE);
        oracles::assert_rejects_a_corrupted_record(&CERTIFY_FIXTURE);
    }

    #[test]
    fn the_command_magics_do_not_open_the_nv_fixtures() {
        for magic in [b"CPORACLE", b"ECORACLE"] {
            let foreign = oracles::synthesize(magic, oracles::VERSION, 1, &[("ALPHA", &[0xaa])]);
            assert!(COMMAND_FIXTURE.parse(&foreign).is_none());
            assert!(CERTIFY_FIXTURE.parse(&foreign).is_none());
        }
    }
}
