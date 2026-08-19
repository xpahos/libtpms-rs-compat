use super::Fixture;

const MAGIC: &[u8; 8] = b"PEORACLE";

const FIXTURE: Fixture = Fixture::new(
    "TPM2_PCR_Event",
    MAGIC,
    include_bytes!("../testdata/oracles/pcr_event.bin"),
);

#[track_caller]
pub(in crate::library::tpm2) fn vector(name: &str) -> &'static [u8] {
    FIXTURE.get(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::oracles;

    const EXPECTED: [(&str, usize, &str); 35] = [
        (
            "EVENT_BEFORE_STARTUP",
            10,
            "c6fa200587f4161bcec91735d842cae60adb218e6e3127043250517eb8a2dc42",
        ),
        (
            "EVENT_DECLARED_FFFF",
            10,
            "92d4f79e38adac2e10fa29d2e27613954b9b5db41e48a22f8627cface96f4897",
        ),
        (
            "EVENT_EMPTY",
            195,
            "d633572dc23f8fc4140782bbdd6317d1e3555cdb3769e3db1d69d83c5b64f8cc",
        ),
        (
            "EVENT_HANDLE_24",
            10,
            "e67548c34583f4d5bc56e2544d26ff1c12a007f432b01ec479b44cfba8e9ba35",
        ),
        (
            "EVENT_HANDLE_OWNER",
            10,
            "e67548c34583f4d5bc56e2544d26ff1c12a007f432b01ec479b44cfba8e9ba35",
        ),
        (
            "EVENT_MAX",
            195,
            "38caefdf2833935a328b309acb034599ec1c78d40d3a7a057f07c89b20001191",
        ),
        (
            "EVENT_MISSING_AUTH",
            10,
            "e1b1d456f4494ed90222af7a74c8ec34f7960a824475f163880c679ce90e23d4",
        ),
        (
            "EVENT_NULL",
            195,
            "b71ad1b83ae7ec428e1802a17e61a2425c750a5bb9309420496251d6117e2e12",
        ),
        (
            "EVENT_NULL_LOCALITY4",
            195,
            "b71ad1b83ae7ec428e1802a17e61a2425c750a5bb9309420496251d6117e2e12",
        ),
        (
            "EVENT_OVERSIZED",
            10,
            "92d4f79e38adac2e10fa29d2e27613954b9b5db41e48a22f8627cface96f4897",
        ),
        (
            "EVENT_PCR10",
            195,
            "b71ad1b83ae7ec428e1802a17e61a2425c750a5bb9309420496251d6117e2e12",
        ),
        (
            "EVENT_PCR10_ORDERLY",
            195,
            "b71ad1b83ae7ec428e1802a17e61a2425c750a5bb9309420496251d6117e2e12",
        ),
        (
            "EVENT_PCR16",
            195,
            "b71ad1b83ae7ec428e1802a17e61a2425c750a5bb9309420496251d6117e2e12",
        ),
        (
            "EVENT_PCR16_ORDERLY",
            195,
            "b71ad1b83ae7ec428e1802a17e61a2425c750a5bb9309420496251d6117e2e12",
        ),
        (
            "EVENT_PCR21_LOCALITY0",
            10,
            "89bb0ae2eb006ea855eebd32d89aa5ceb13b26da88ed3f9ce5cfaeadda87af9e",
        ),
        (
            "EVENT_PCR21_LOCALITY2",
            195,
            "b71ad1b83ae7ec428e1802a17e61a2425c750a5bb9309420496251d6117e2e12",
        ),
        (
            "EVENT_TRAILING",
            10,
            "bbf6f3b0d8a34be4575ccc58a90597ec7238aa643579fe7b638b79c6c0836f6d",
        ),
        (
            "EVENT_TRUNCATED_HANDLE",
            10,
            "dbb122bcd41ef4f88bf1e8dc2c458f3bbec3417103baa3290f842c2e1e914e19",
        ),
        (
            "EVENT_TRUNCATED_PAYLOAD",
            10,
            "283318ac529c38100a5254105aca20a10ab26f57f2401f2b3775b1955f2e1990",
        ),
        (
            "EVENT_TRUNCATED_TPM2B",
            10,
            "283318ac529c38100a5254105aca20a10ab26f57f2401f2b3775b1955f2e1990",
        ),
        (
            "EVENT_WRONG_PASSWORD",
            10,
            "3ed8c53ddb27cf6f73a00c9822f4ad00f93770b54e6843e7f33b1637574b37e2",
        ),
        (
            "READ_PCR10_AFTER",
            218,
            "1794fe3cfbfa7c9ec0ffb41fc659c41f2908d129e637d781657e050569baba34",
        ),
        (
            "READ_PCR10_AFTER_MAX",
            218,
            "b08aa363c01b09806f58dfdf6f83f4788b23d0c32b7faeb7ab15eff701a84889",
        ),
        (
            "READ_PCR10_AFTER_NULL",
            218,
            "1794fe3cfbfa7c9ec0ffb41fc659c41f2908d129e637d781657e050569baba34",
        ),
        (
            "READ_PCR10_BEFORE",
            218,
            "891e26813056a0bcf5cc2bbf8c5c9f764dc8ad1ae0f484df8975fc31e19891a5",
        ),
        (
            "READ_PCR16_AFTER",
            218,
            "db87845029cfd5e87593c33deb2ba7538b79cc28f0825a6957f24f8e820f9c0a",
        ),
        (
            "READ_PCR21_AFTER_LOCALITY0",
            218,
            "53391e74f04d76d8588b1d7136f388a3e5661a1f241000b35146a9c11699693e",
        ),
        (
            "READ_PCR21_AFTER_LOCALITY2",
            218,
            "0894e7f6e2cbc006cef7f4ee45909e260feb7d8395b3f1f41f92efd1ded74780",
        ),
        (
            "READ_PCR21_BEFORE",
            218,
            "53391e74f04d76d8588b1d7136f388a3e5661a1f241000b35146a9c11699693e",
        ),
        (
            "SHUTDOWN_STATE",
            10,
            "5b2896e614c8b5077c7bea543c34c66431aa403bd731a18d35b9d5e07cd08613",
        ),
        (
            "SHUTDOWN_STATE_SECOND",
            10,
            "5b2896e614c8b5077c7bea543c34c66431aa403bd731a18d35b9d5e07cd08613",
        ),
        (
            "STARTUP_CLEAR",
            10,
            "5b2896e614c8b5077c7bea543c34c66431aa403bd731a18d35b9d5e07cd08613",
        ),
        (
            "STARTUP_CLEAR_RETRY",
            10,
            "5b2896e614c8b5077c7bea543c34c66431aa403bd731a18d35b9d5e07cd08613",
        ),
        (
            "STARTUP_STATE_AFTER_ORDERLY_EVENT",
            10,
            "8d20edb6806b22f433066b2e2eecf8ad1619f60fe604e1603a31122d52002230",
        ),
        (
            "STARTUP_STATE_AFTER_PCR16_EVENT",
            10,
            "5b2896e614c8b5077c7bea543c34c66431aa403bd731a18d35b9d5e07cd08613",
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
    fn the_flush_context_magic_does_not_open_this_fixture() {
        let foreign = oracles::synthesize(b"FCORACLE", oracles::VERSION, 1, &[("ALPHA", &[0xaa])]);
        assert!(FIXTURE.parse(&foreign).is_none());
    }
}
