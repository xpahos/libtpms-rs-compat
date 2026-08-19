use super::Fixture;

const MAGIC: &[u8; 8] = b"GTORACLE";

const FIXTURE: Fixture = Fixture::new(
    "TPM2_GetTestResult",
    MAGIC,
    include_bytes!("../testdata/oracles/get_test_result.bin"),
);

#[track_caller]
pub(in crate::library::tpm2) fn vector(name: &str) -> &'static [u8] {
    FIXTURE.get(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::oracles;

    const DIGESTS: &str = include_str!("../testdata/oracles/get_test_result_digests.txt");

    fn expected_records() -> Vec<(String, usize, String)> {
        DIGESTS
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .map(|line| {
                let mut fields = line.split(' ');
                let mut next = |what: &str| {
                    fields
                        .next()
                        .unwrap_or_else(|| panic!("every record carries a {what}"))
                };
                let record = (
                    next("name").to_owned(),
                    next("length").parse().expect("a decimal payload length"),
                    next("digest").to_owned(),
                );
                assert_eq!(fields.next(), None, "records have exactly three fields");
                record
            })
            .collect()
    }

    #[test]
    fn every_named_vector_still_decodes_to_its_original_bytes() {
        let expected = expected_records();
        assert!(!expected.is_empty());
        let borrowed: Vec<(&str, usize, &str)> = expected
            .iter()
            .map(|(name, length, digest)| (name.as_str(), *length, digest.as_str()))
            .collect();
        oracles::assert_records_match(&FIXTURE, &borrowed);
    }

    #[test]
    fn the_record_names_are_sorted_and_unique() {
        oracles::assert_names_are_sorted_and_unique(&FIXTURE);
    }

    #[test]
    fn a_missing_vector_is_reported_rather_than_guessed() {
        assert!(FIXTURE.find("NOT_A_VECTOR").is_none());
        assert!(FIXTURE.find("").is_none());
        for (name, _, _) in expected_records() {
            assert_eq!(vector(&name), FIXTURE.find(&name).expect("present"));
        }
    }

    #[test]
    fn a_corrupted_header_is_rejected() {
        oracles::assert_rejects_a_corrupted_header(&FIXTURE);
    }

    #[test]
    fn a_corrupted_record_is_rejected() {
        oracles::assert_rejects_a_corrupted_record(&FIXTURE);
    }

    #[test]
    fn truncated_and_extended_fixtures_are_rejected() {
        oracles::assert_rejects_truncation_and_trailing_bytes(&FIXTURE);
    }

    #[test]
    fn the_flush_context_magic_does_not_open_this_fixture() {
        let foreign = oracles::synthesize(b"FCORACLE", oracles::VERSION, 1, &[("ALPHA", &[0xaa])]);
        assert!(FIXTURE.parse(&foreign).is_none());
    }
}
