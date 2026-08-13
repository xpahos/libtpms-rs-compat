use super::super::algorithm::{
    TPM_ALG_AES, TPM_ALG_CAMELLIA, TPM_ALG_CBC, TPM_ALG_CFB, TPM_ALG_CMAC, TPM_ALG_CTR,
    TPM_ALG_ECB, TPM_ALG_ECC, TPM_ALG_ECDAA, TPM_ALG_ECDH, TPM_ALG_ECDSA, TPM_ALG_ECMQV,
    TPM_ALG_ECSCHNORR, TPM_ALG_HMAC, TPM_ALG_KDF1_SP800_56A, TPM_ALG_KDF1_SP800_108, TPM_ALG_KDF2,
    TPM_ALG_KEYEDHASH, TPM_ALG_MGF1, TPM_ALG_OAEP, TPM_ALG_OFB, TPM_ALG_RSA, TPM_ALG_RSAES,
    TPM_ALG_RSAPSS, TPM_ALG_RSASSA, TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512,
    TPM_ALG_SM2, TPM_ALG_SYMCIPHER, TPM_ALG_TDES, TPM_ALG_XOR, algorithm_enabled,
};
use super::{CapabilityPage, MAX_CAP_DATA, paginate};

const TPMA_ALGORITHM_ASYMMETRIC: u32 = 1 << 0;
const TPMA_ALGORITHM_SYMMETRIC: u32 = 1 << 1;
const TPMA_ALGORITHM_HASH: u32 = 1 << 2;
const TPMA_ALGORITHM_OBJECT: u32 = 1 << 3;
const TPMA_ALGORITHM_SIGNING: u32 = 1 << 8;
const TPMA_ALGORITHM_ENCRYPTING: u32 = 1 << 9;
const TPMA_ALGORITHM_METHOD: u32 = 1 << 10;

const SIZEOF_TPMS_ALG_PROPERTY: usize = 8;
pub(super) const MAX_CAP_ALGS: usize = MAX_CAP_DATA / SIZEOF_TPMS_ALG_PROPERTY;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) struct AlgorithmProperty {
    pub(in crate::library::tpm2) algorithm: u16,
    pub(in crate::library::tpm2) attributes: u32,
}

struct AlgorithmEntry {
    algorithm: u16,
    attributes: u32,
    profile_name: &'static [u8],
}

const fn entry(algorithm: u16, attributes: u32, profile_name: &'static [u8]) -> AlgorithmEntry {
    AlgorithmEntry {
        algorithm,
        attributes,
        profile_name,
    }
}

static S_ALGORITHMS: &[AlgorithmEntry] = &[
    entry(
        TPM_ALG_RSA,
        TPMA_ALGORITHM_ASYMMETRIC | TPMA_ALGORITHM_OBJECT,
        b"rsa",
    ),
    entry(TPM_ALG_TDES, TPMA_ALGORITHM_SYMMETRIC, b"tdes"),
    entry(TPM_ALG_SHA1, TPMA_ALGORITHM_HASH, b"sha1"),
    entry(
        TPM_ALG_HMAC,
        TPMA_ALGORITHM_HASH | TPMA_ALGORITHM_SIGNING,
        b"hmac",
    ),
    entry(TPM_ALG_AES, TPMA_ALGORITHM_SYMMETRIC, b"aes"),
    entry(
        TPM_ALG_MGF1,
        TPMA_ALGORITHM_HASH | TPMA_ALGORITHM_METHOD,
        b"mgf1",
    ),
    entry(
        TPM_ALG_KEYEDHASH,
        TPMA_ALGORITHM_HASH
            | TPMA_ALGORITHM_OBJECT
            | TPMA_ALGORITHM_SIGNING
            | TPMA_ALGORITHM_ENCRYPTING,
        b"keyedhash",
    ),
    entry(
        TPM_ALG_XOR,
        TPMA_ALGORITHM_SYMMETRIC | TPMA_ALGORITHM_HASH,
        b"xor",
    ),
    entry(TPM_ALG_SHA256, TPMA_ALGORITHM_HASH, b"sha256"),
    entry(TPM_ALG_SHA384, TPMA_ALGORITHM_HASH, b"sha384"),
    entry(TPM_ALG_SHA512, TPMA_ALGORITHM_HASH, b"sha512"),
    entry(
        TPM_ALG_RSASSA,
        TPMA_ALGORITHM_ASYMMETRIC | TPMA_ALGORITHM_SIGNING,
        b"rsassa",
    ),
    entry(
        TPM_ALG_RSAES,
        TPMA_ALGORITHM_ASYMMETRIC | TPMA_ALGORITHM_ENCRYPTING,
        b"rsaes",
    ),
    entry(
        TPM_ALG_RSAPSS,
        TPMA_ALGORITHM_ASYMMETRIC | TPMA_ALGORITHM_SIGNING,
        b"rsapss",
    ),
    entry(
        TPM_ALG_OAEP,
        TPMA_ALGORITHM_ASYMMETRIC | TPMA_ALGORITHM_ENCRYPTING,
        b"oaep",
    ),
    entry(
        TPM_ALG_ECDSA,
        TPMA_ALGORITHM_ASYMMETRIC | TPMA_ALGORITHM_SIGNING,
        b"ecdsa",
    ),
    entry(
        TPM_ALG_ECDH,
        TPMA_ALGORITHM_ASYMMETRIC | TPMA_ALGORITHM_METHOD,
        b"ecdh",
    ),
    entry(
        TPM_ALG_ECDAA,
        TPMA_ALGORITHM_ASYMMETRIC | TPMA_ALGORITHM_SIGNING,
        b"ecdaa",
    ),
    entry(
        TPM_ALG_SM2,
        TPMA_ALGORITHM_ASYMMETRIC | TPMA_ALGORITHM_SIGNING | TPMA_ALGORITHM_METHOD,
        b"sm2",
    ),
    entry(
        TPM_ALG_ECSCHNORR,
        TPMA_ALGORITHM_ASYMMETRIC | TPMA_ALGORITHM_SIGNING,
        b"ecschnorr",
    ),
    entry(
        TPM_ALG_ECMQV,
        TPMA_ALGORITHM_ASYMMETRIC | TPMA_ALGORITHM_METHOD,
        b"ecmqv",
    ),
    entry(
        TPM_ALG_KDF1_SP800_56A,
        TPMA_ALGORITHM_HASH | TPMA_ALGORITHM_METHOD,
        b"kdf1-sp800-56a",
    ),
    entry(
        TPM_ALG_KDF2,
        TPMA_ALGORITHM_HASH | TPMA_ALGORITHM_METHOD,
        b"kdf2",
    ),
    entry(
        TPM_ALG_KDF1_SP800_108,
        TPMA_ALGORITHM_HASH | TPMA_ALGORITHM_METHOD,
        b"kdf1-sp800-108",
    ),
    entry(
        TPM_ALG_ECC,
        TPMA_ALGORITHM_ASYMMETRIC | TPMA_ALGORITHM_OBJECT,
        b"ecc",
    ),
    entry(TPM_ALG_SYMCIPHER, TPMA_ALGORITHM_OBJECT, b"symcipher"),
    entry(TPM_ALG_CAMELLIA, TPMA_ALGORITHM_SYMMETRIC, b"camellia"),
    entry(
        TPM_ALG_CMAC,
        TPMA_ALGORITHM_SYMMETRIC | TPMA_ALGORITHM_SIGNING,
        b"cmac",
    ),
    entry(
        TPM_ALG_CTR,
        TPMA_ALGORITHM_SYMMETRIC | TPMA_ALGORITHM_ENCRYPTING,
        b"ctr",
    ),
    entry(
        TPM_ALG_OFB,
        TPMA_ALGORITHM_SYMMETRIC | TPMA_ALGORITHM_ENCRYPTING,
        b"ofb",
    ),
    entry(
        TPM_ALG_CBC,
        TPMA_ALGORITHM_SYMMETRIC | TPMA_ALGORITHM_ENCRYPTING,
        b"cbc",
    ),
    entry(
        TPM_ALG_CFB,
        TPMA_ALGORITHM_SYMMETRIC | TPMA_ALGORITHM_ENCRYPTING,
        b"cfb",
    ),
    entry(
        TPM_ALG_ECB,
        TPMA_ALGORITHM_SYMMETRIC | TPMA_ALGORITHM_ENCRYPTING,
        b"ecb",
    ),
];

pub(in crate::library::tpm2) fn enabled_algorithms(
    profile_algorithms: &[u8],
) -> impl Iterator<Item = u16> {
    S_ALGORITHMS
        .iter()
        .filter(move |entry| algorithm_enabled(profile_algorithms, entry.profile_name))
        .map(|entry| entry.algorithm)
}

pub(in crate::library::tpm2) fn implemented(
    profile_algorithms: &[u8],
    starting_algorithm: u16,
    requested_count: u32,
) -> CapabilityPage<AlgorithmProperty> {
    paginate(
        S_ALGORITHMS
            .iter()
            .filter(|entry| entry.algorithm >= starting_algorithm)
            .filter(|entry| algorithm_enabled(profile_algorithms, entry.profile_name))
            .map(|entry| AlgorithmProperty {
                algorithm: entry.algorithm,
                attributes: entry.attributes,
            }),
        requested_count,
        MAX_CAP_ALGS,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const NULL_PROFILE_ALGORITHMS: &[u8] = b"rsa,rsa-min-size=1024,tdes,tdes-min-size=128,\
sha1,hmac,aes,aes-min-size=128,mgf1,keyedhash,xor,sha256,sha384,sha512,null,rsassa,rsaes,\
rsapss,oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,ecmqv,kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,\
ecc-min-size=192,ecc-nist,ecc-bn,ecc-sm2-p256,symcipher,camellia,camellia-min-size=128,\
cmac,ctr,ofb,cbc,cfb,ecb";

    const ORACLE_ALGORITHMS: [(u16, u32); 33] = [
        (0x0001, 0x0000_0009),
        (0x0003, 0x0000_0002),
        (0x0004, 0x0000_0004),
        (0x0005, 0x0000_0104),
        (0x0006, 0x0000_0002),
        (0x0007, 0x0000_0404),
        (0x0008, 0x0000_030c),
        (0x000a, 0x0000_0006),
        (0x000b, 0x0000_0004),
        (0x000c, 0x0000_0004),
        (0x000d, 0x0000_0004),
        (0x0014, 0x0000_0101),
        (0x0015, 0x0000_0201),
        (0x0016, 0x0000_0101),
        (0x0017, 0x0000_0201),
        (0x0018, 0x0000_0101),
        (0x0019, 0x0000_0401),
        (0x001a, 0x0000_0101),
        (0x001b, 0x0000_0501),
        (0x001c, 0x0000_0101),
        (0x001d, 0x0000_0401),
        (0x0020, 0x0000_0404),
        (0x0021, 0x0000_0404),
        (0x0022, 0x0000_0404),
        (0x0023, 0x0000_0009),
        (0x0025, 0x0000_0008),
        (0x0026, 0x0000_0002),
        (0x003f, 0x0000_0102),
        (0x0040, 0x0000_0202),
        (0x0041, 0x0000_0202),
        (0x0042, 0x0000_0202),
        (0x0043, 0x0000_0202),
        (0x0044, 0x0000_0202),
    ];

    #[test]
    fn the_table_is_strictly_sorted_and_unique() {
        let ids: Vec<u16> = S_ALGORITHMS.iter().map(|entry| entry.algorithm).collect();
        assert!(
            ids.windows(2).all(|pair| pair[0] < pair[1]),
            "ascending algorithm IDs: {ids:#x?}"
        );
    }

    #[test]
    fn the_null_profile_reports_the_oracle_algorithm_list() {
        let page = implemented(NULL_PROFILE_ALGORITHMS, 0, 1000);
        assert!(!page.more_data);
        let reported: Vec<(u16, u32)> = page
            .entries
            .iter()
            .map(|property| (property.algorithm, property.attributes))
            .collect();
        assert_eq!(reported, ORACLE_ALGORITHMS);
    }

    #[test]
    fn the_starting_algorithm_is_inclusive() {
        let page = implemented(NULL_PROFILE_ALGORITHMS, TPM_ALG_RSA, 1);
        assert_eq!(
            page.entries,
            [AlgorithmProperty {
                algorithm: TPM_ALG_RSA,
                attributes: 0x9
            }]
        );
        assert!(page.more_data);
    }

    #[test]
    fn a_start_inside_a_gap_skips_to_the_next_entry() {
        let page = implemented(NULL_PROFILE_ALGORITHMS, TPM_ALG_SHA512 + 1, 1);
        assert_eq!(page.entries[0].algorithm, TPM_ALG_RSASSA);
        assert!(page.more_data);
    }

    #[test]
    fn the_upper_boundary_returns_the_last_entry_without_more_data() {
        let page = implemented(NULL_PROFILE_ALGORITHMS, TPM_ALG_ECB, 10);
        assert_eq!(
            page.entries,
            [AlgorithmProperty {
                algorithm: TPM_ALG_ECB,
                attributes: 0x202
            }]
        );
        assert!(!page.more_data);
    }

    #[test]
    fn a_start_above_the_last_entry_is_empty_without_more_data() {
        let page = implemented(NULL_PROFILE_ALGORITHMS, TPM_ALG_ECB + 1, 10);
        assert!(page.entries.is_empty());
        assert!(!page.more_data);
    }

    #[test]
    fn count_zero_reports_more_data_only_when_entries_remain() {
        let page = implemented(NULL_PROFILE_ALGORITHMS, 0, 0);
        assert!(page.entries.is_empty());
        assert!(page.more_data);

        let page = implemented(NULL_PROFILE_ALGORITHMS, TPM_ALG_ECB + 1, 0);
        assert!(page.entries.is_empty());
        assert!(!page.more_data);
    }

    #[test]
    fn oversized_counts_return_the_full_list() {
        let page = implemented(NULL_PROFILE_ALGORITHMS, 0, u32::MAX);
        assert_eq!(page.entries.len(), ORACLE_ALGORITHMS.len());
        assert!(!page.more_data);
    }

    #[test]
    fn an_exact_count_consumes_the_list_without_more_data() {
        let page = implemented(NULL_PROFILE_ALGORITHMS, 0, ORACLE_ALGORITHMS.len() as u32);
        assert_eq!(page.entries.len(), ORACLE_ALGORITHMS.len());
        assert!(!page.more_data);

        let page = implemented(
            NULL_PROFILE_ALGORITHMS,
            0,
            ORACLE_ALGORITHMS.len() as u32 - 1,
        );
        assert_eq!(page.entries.len(), ORACLE_ALGORITHMS.len() - 1);
        assert!(page.more_data);
    }

    #[test]
    fn profile_filtering_removes_disabled_algorithms() {
        let profile = b"rsa,sha1,hmac,aes,sha256,rsassa,ecc,symcipher,cfb";
        let page = implemented(profile, 0, 1000);
        let ids: Vec<u16> = page
            .entries
            .iter()
            .map(|property| property.algorithm)
            .collect();
        assert_eq!(
            ids,
            [
                TPM_ALG_RSA,
                TPM_ALG_SHA1,
                TPM_ALG_HMAC,
                TPM_ALG_AES,
                TPM_ALG_SHA256,
                TPM_ALG_RSASSA,
                TPM_ALG_ECC,
                TPM_ALG_SYMCIPHER,
                TPM_ALG_CFB
            ]
        );
        assert!(!page.more_data);
    }

    #[test]
    fn min_size_tokens_do_not_enable_their_base_algorithm() {
        let page = implemented(b"rsa-min-size=1024,sha256", 0, 1000);
        let ids: Vec<u16> = page
            .entries
            .iter()
            .map(|property| property.algorithm)
            .collect();
        assert_eq!(ids, [TPM_ALG_SHA256]);
    }

    #[test]
    fn filtering_interacts_with_more_data() {
        let page = implemented(b"rsa,sha256", 0, 1);
        assert_eq!(page.entries[0].algorithm, TPM_ALG_RSA);
        assert!(page.more_data);

        let page = implemented(b"rsa,sha256", TPM_ALG_SHA256, 1);
        assert_eq!(page.entries[0].algorithm, TPM_ALG_SHA256);
        assert!(!page.more_data);
    }

    #[test]
    fn the_enabled_iterator_reports_the_profile_filtered_table_in_table_order() {
        let ids: Vec<u16> = enabled_algorithms(NULL_PROFILE_ALGORITHMS).collect();
        let expected: Vec<u16> = ORACLE_ALGORITHMS.iter().map(|entry| entry.0).collect();
        assert_eq!(ids, expected);

        let ids: Vec<u16> = enabled_algorithms(b"sha256,aes,rsa").collect();
        assert_eq!(ids, [TPM_ALG_RSA, TPM_ALG_AES, TPM_ALG_SHA256]);
    }

    #[test]
    fn the_enabled_iterator_reports_nothing_for_an_empty_or_unknown_profile() {
        assert_eq!(enabled_algorithms(b"").count(), 0);
        assert_eq!(enabled_algorithms(b"nosuchalgorithm,sha25").count(), 0);
    }

    #[test]
    fn the_enabled_iterator_agrees_with_the_reported_capability_page() {
        for profile in [
            NULL_PROFILE_ALGORITHMS,
            b"rsa,sha1,hmac,aes,sha256,rsassa,ecc,symcipher,cfb",
            b"rsa-min-size=1024,sha256",
        ] {
            let reported: Vec<u16> = implemented(profile, 0, 1000)
                .entries
                .iter()
                .map(|property| property.algorithm)
                .collect();
            let enabled: Vec<u16> = enabled_algorithms(profile).collect();
            assert_eq!(reported, enabled);
        }
    }

    #[test]
    fn the_capacity_constant_matches_the_upstream_padded_struct_size() {
        assert_eq!(MAX_CAP_ALGS, 127);
    }
}
