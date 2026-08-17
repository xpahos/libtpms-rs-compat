use super::Fixture;

const MAGIC: &[u8; 8] = b"FCORACLE";

const FIXTURE: Fixture = Fixture::new(
    "TPM2_FlushContext",
    MAGIC,
    include_bytes!("../testdata/oracles/flush_context.bin"),
);

#[track_caller]
pub(in crate::library::tpm2) fn vector(name: &str) -> &'static [u8] {
    FIXTURE.get(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::oracles;

    const EXPECTED: [(&str, usize, &str); 34] = [
        (
            "ABSENT_HMAC_RESPONSE",
            10,
            "f146aa9565261006840e1e51a4bfafb35264e820b66fb131bec9b464b9b70061",
        ),
        (
            "ABSENT_POLICY_RESPONSE",
            10,
            "f146aa9565261006840e1e51a4bfafb35264e820b66fb131bec9b464b9b70061",
        ),
        (
            "ABSENT_TRANSIENT_RESPONSE",
            10,
            "f146aa9565261006840e1e51a4bfafb35264e820b66fb131bec9b464b9b70061",
        ),
        (
            "BAD_HANDLE_RESPONSE",
            10,
            "8d20edb6806b22f433066b2e2eecf8ad1619f60fe604e1603a31122d52002230",
        ),
        (
            "BEFORE_STARTUP_RESPONSE",
            10,
            "c6fa200587f4161bcec91735d842cae60adb218e6e3127043250517eb8a2dc42",
        ),
        (
            "CAP_COMMANDS_RESPONSE",
            23,
            "ba4e3fdb992fdeb4fa16516e81f9f404aa9a8de0c1891b31d064a5e19d01e8f0",
        ),
        (
            "CAP_LOADED_ONE",
            23,
            "cb546ec380df979f2d64028bd1ac8982d37fec672c86676f4a3a00102b4d73f0",
        ),
        (
            "CAP_LOADED_THREE",
            31,
            "fde7eda41f5b85309a51843348a11c4a08d3c1adec496ad069ba83f93a61cdb0",
        ),
        (
            "CAP_LOADED_TWO",
            27,
            "f5edfc82a7e3d9f429e235604ffa7df552c6b66001b10aac9b52b57f7b1d6f59",
        ),
        (
            "CAP_PERSISTENT_AFTER_FLUSH",
            23,
            "05dfbeee2a30a8fc0b06755f20cd9f0802da95a7bb1782368d4d0f1d059d6275",
        ),
        (
            "CAP_PERSISTENT_SPK",
            23,
            "05dfbeee2a30a8fc0b06755f20cd9f0802da95a7bb1782368d4d0f1d059d6275",
        ),
        (
            "CAP_SAVED_NONE",
            19,
            "b5bcc52e71fb85240180472ac7c248fc11657bf24e5cf8110d6883ff6eef7859",
        ),
        (
            "CAP_SAVED_ONE",
            23,
            "cb546ec380df979f2d64028bd1ac8982d37fec672c86676f4a3a00102b4d73f0",
        ),
        (
            "CAP_TRANSIENT_NONE",
            19,
            "b5bcc52e71fb85240180472ac7c248fc11657bf24e5cf8110d6883ff6eef7859",
        ),
        (
            "CAP_TRANSIENT_ONE",
            23,
            "916750dfac072ca2a7afc2200f830ff1e220ab4a358dad8e043bb2002c296eab",
        ),
        (
            "CAP_TRANSIENT_TWO",
            27,
            "0708c73c0ba27e09f67691dc23b7fdee509474609e45331cc7cb0949593a089f",
        ),
        (
            "EVICT_SPK_RESPONSE",
            19,
            "7e32c80d21957e03ca8d4036a59e432769a2bf9ba87fc3cb03ed1159030fa80a",
        ),
        (
            "EXCLUSIVE_AUDIT_CLEARED",
            4,
            "3292323498ff25f7b41f9d465aa9368fe56878bb8f88f54c6e7ffd1dc1882600",
        ),
        (
            "EXCLUSIVE_AUDIT_KEPT",
            4,
            "26b25d457597a7b0463f9620f666dd10aa2c4373a505967c7c8d70922a2d6ece",
        ),
        (
            "EXCLUSIVE_AUDIT_SET",
            4,
            "26b25d457597a7b0463f9620f666dd10aa2c4373a505967c7c8d70922a2d6ece",
        ),
        (
            "EXCLUSIVE_AUDIT_UNSET",
            4,
            "3292323498ff25f7b41f9d465aa9368fe56878bb8f88f54c6e7ffd1dc1882600",
        ),
        (
            "NO_PARAMETERS_RESPONSE",
            10,
            "283318ac529c38100a5254105aca20a10ab26f57f2401f2b3775b1955f2e1990",
        ),
        (
            "OWNER_PRIMARY_RESPONSE",
            274,
            "c36bcaa5fbc61ac962ed8d6e9feb896d8f2eca9d919e7f6695d873d9838a6f67",
        ),
        (
            "PERMALL",
            1978,
            "ad9baf89ab40353599c56c7d238f14570700fbbb8783e50a8ec354251a2770ac",
        ),
        (
            "PERMALL_AFTER_SPK_FLUSH",
            2237,
            "7b88a7b2ed0f99489ed1a3dff8957156411f97f79b2c2af88514bd358104fce1",
        ),
        (
            "PERMALL_SPK_PERSISTED",
            2237,
            "7b88a7b2ed0f99489ed1a3dff8957156411f97f79b2c2af88514bd358104fce1",
        ),
        (
            "PERMALL_STARTED",
            1978,
            "a7258670d6bbb5b7cedbd304943cb7d3ecde8c2e269a70782a79fcf48b8a8683",
        ),
        (
            "PLATFORM_PRIMARY_RESPONSE",
            274,
            "e34fec346f1b2d17e346e6846aea2a9dd56bce5510df2391d7162249b62bce1e",
        ),
        (
            "REUSED_PRIMARY_RESPONSE",
            274,
            "c36bcaa5fbc61ac962ed8d6e9feb896d8f2eca9d919e7f6695d873d9838a6f67",
        ),
        (
            "SESSION_TAGGED_RESPONSE",
            10,
            "df8f39a5a21cf35cb7af27b58870f8c520f0970269f56299841359cfe3361275",
        ),
        (
            "SPK_PRIMARY_RESPONSE",
            274,
            "c36bcaa5fbc61ac962ed8d6e9feb896d8f2eca9d919e7f6695d873d9838a6f67",
        ),
        (
            "SUCCESS_RESPONSE",
            10,
            "5b2896e614c8b5077c7bea543c34c66431aa403bd731a18d35b9d5e07cd08613",
        ),
        (
            "TRAILING_RESPONSE",
            10,
            "bbf6f3b0d8a34be4575ccc58a90597ec7238aa643579fe7b638b79c6c0836f6d",
        ),
        (
            "TRUNCATED_RESPONSE",
            10,
            "283318ac529c38100a5254105aca20a10ab26f57f2401f2b3775b1955f2e1990",
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
    fn the_evict_control_magic_does_not_open_this_fixture() {
        let foreign = oracles::synthesize(b"ECORACLE", oracles::VERSION, 1, &[("ALPHA", &[0xaa])]);
        assert!(FIXTURE.parse(&foreign).is_none());
    }
}
