use super::Fixture;

const MAGIC: &[u8; 8] = b"ECORACLE";

const FIXTURE: Fixture = Fixture::new(
    "TPM2_EvictControl",
    MAGIC,
    include_bytes!("../testdata/oracles/evict_control.bin"),
);

#[track_caller]
pub(in crate::library::tpm2) fn vector(name: &str) -> &'static [u8] {
    FIXTURE.get(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::oracles;

    const EXPECTED: [(&str, usize, &str); 9] = [
        (
            "OWNER_PRIMARY_RESPONSE",
            274,
            "76407e8d046aa9208ce03b657af34bb0fc48a5d3efc876b0112e37171a4bef53",
        ),
        (
            "PERMALL",
            1978,
            "c408d3cbff6cafaaa91b3761348a2aab06d2e781546f75cb66bfdea5f9d07e82",
        ),
        (
            "PERMALL_AFTER_DELETE",
            2237,
            "faae666005e2319a8728c4bba4f05e6200bfc23d26db4ce5c6d6ada19c1e494c",
        ),
        (
            "PERMALL_ALL_DELETED",
            1978,
            "b3203d1ff9d0c5166d7790adb2c92650ab196403a39b593a9f80fd4bb67f3b09",
        ),
        (
            "PERMALL_OWNER_PERSIST",
            2237,
            "d6434125f7b32cba4b7b9a720d9e81d0d2a8210ec9c6c66b223ad43a55424db1",
        ),
        (
            "PERMALL_PLATFORM_PERSIST",
            2496,
            "c191629294ac74462b76153b6fa0365f21e15645463043a53e8b815007cd0d17",
        ),
        (
            "PERMALL_STARTED",
            1978,
            "b3203d1ff9d0c5166d7790adb2c92650ab196403a39b593a9f80fd4bb67f3b09",
        ),
        (
            "PERMALL_TWO_EVICTS",
            2496,
            "d6a04eedd63ab7b7e4d5d0c78a5b8f921bc94956cc5a371b0d5baefa9da743c4",
        ),
        (
            "PLATFORM_PRIMARY_RESPONSE",
            274,
            "6ef9aefd9114e92fc839ba317502d7e1ff396779f2c57d920230a5f05a102128",
        ),
    ];

    #[test]
    fn every_named_vector_still_decodes_to_its_original_bytes() {
        oracles::assert_records_match(&FIXTURE, &EXPECTED);
    }

    #[test]
    fn the_record_names_are_sorted_and_unique() {
        oracles::assert_names_are_sorted_and_unique(&FIXTURE);
    }

    #[test]
    fn a_missing_vector_is_reported_rather_than_guessed() {
        assert!(FIXTURE.find("NOT_A_VECTOR").is_none());
        assert!(FIXTURE.find("").is_none());
        for (name, _, _) in EXPECTED {
            assert_eq!(vector(name), FIXTURE.find(name).expect("present"));
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
    fn the_create_primary_magic_does_not_open_this_fixture() {
        let foreign = oracles::synthesize(b"CPORACLE", oracles::VERSION, 1, &[("ALPHA", &[0xaa])]);
        assert!(FIXTURE.parse(&foreign).is_none());
    }
}
