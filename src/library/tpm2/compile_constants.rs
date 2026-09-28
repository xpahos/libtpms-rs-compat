// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/NVMarshal.c
//
// Original upstream authors and copyright notices:
// Written by Stefan Berger
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corporation 2017,2018.
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use super::marshal::{BlobReader, BlockSkipError, skip_optional_block};
use super::persistent::{NvHeader, PersistentAllError, StateSection, parse_nv_header};

const PA_COMPILE_CONSTANTS_MAGIC: u32 = 0xc9ea_6431;
const PA_COMPILE_CONSTANTS_VERSION: u16 = 3;

const SHARED_ENTRY_COUNT: usize = 88;
const VERSION_3_ENTRY_COUNT: usize = 120;

const BLOCK_SKIP_SINCE_VERSION: u16 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CompareOp {
    Equal,
    SavedLessOrEqual,
    #[allow(dead_code)]
    SavedGreaterOrEqual,
    #[allow(dead_code)]
    DontCare,
}

impl CompareOp {
    fn is_compatible(self, saved: u32, current: u32) -> bool {
        match self {
            Self::Equal => saved == current,
            Self::SavedLessOrEqual => saved <= current,
            Self::SavedGreaterOrEqual => saved >= current,
            Self::DontCare => true,
        }
    }
}

struct CompileConstant {
    name: &'static str,
    current: u32,
    comparison: CompareOp,
}

const fn entry(name: &'static str, current: u32, comparison: CompareOp) -> CompileConstant {
    CompileConstant {
        name,
        current,
        comparison,
    }
}

use CompareOp::{Equal, SavedLessOrEqual};

static PA_COMPILE_CONSTANTS: [CompileConstant; VERSION_3_ENTRY_COUNT] = [
    entry("ALG_RSA", 1, Equal),
    entry("ALG_SHA1", 1, Equal),
    entry("ALG_HMAC", 1, Equal),
    entry("ALG_TDES", 1, SavedLessOrEqual),
    entry("ALG_AES", 1, Equal),
    entry("ALG_MGF1", 1, Equal),
    entry("ALG_XOR", 1, Equal),
    entry("ALG_KEYEDHASH", 1, Equal),
    entry("ALG_SHA256", 1, Equal),
    entry("ALG_SHA384", 1, Equal),
    entry("ALG_SHA512", 1, Equal),
    entry("ALG_SM3_256", 0, Equal),
    entry("ALG_SM4", 0, Equal),
    entry("ALG_RSASSA", 1, Equal),
    entry("ALG_RSAES", 1, Equal),
    entry("ALG_RSAPSS", 1, Equal),
    entry("ALG_OAEP", 1, Equal),
    entry("ALG_ECC", 1, Equal),
    entry("ALG_ECDH", 1, Equal),
    entry("ALG_ECDSA", 1, Equal),
    entry("ALG_ECDAA", 1, Equal),
    entry("ALG_SM2", 1, SavedLessOrEqual),
    entry("ALG_ECSCHNORR", 1, Equal),
    entry("ALG_ECMQV", 1, SavedLessOrEqual),
    entry("ALG_SYMCIPHER", 1, Equal),
    entry("ALG_KDF1_SP800_56A", 1, Equal),
    entry("ALG_KDF2", 1, SavedLessOrEqual),
    entry("ALG_KDF1_SP800_108", 1, Equal),
    entry("ALG_CMAC", 1, SavedLessOrEqual),
    entry("ALG_CTR", 1, Equal),
    entry("ALG_OFB", 1, Equal),
    entry("ALG_CBC", 1, Equal),
    entry("ALG_CFB", 1, Equal),
    entry("ALG_ECB", 1, Equal),
    entry("MAX_RSA_KEY_BITS", 3072, SavedLessOrEqual),
    entry("MAX_TDES_KEY_BITS", 192, Equal),
    entry("MAX_AES_KEY_BITS", 256, Equal),
    entry("128", 128, Equal),
    entry("128", 128, Equal),
    entry("ECC_NIST_P192", 1, SavedLessOrEqual),
    entry("ECC_NIST_P224", 1, SavedLessOrEqual),
    entry("ECC_NIST_P256", 1, SavedLessOrEqual),
    entry("ECC_NIST_P384", 1, SavedLessOrEqual),
    entry("ECC_NIST_P521", 1, SavedLessOrEqual),
    entry("ECC_BN_P256", 1, SavedLessOrEqual),
    entry("ECC_BN_P638", 1, SavedLessOrEqual),
    entry("ECC_SM2_P256", 1, SavedLessOrEqual),
    entry("MAX_ECC_KEY_BITS", 638, SavedLessOrEqual),
    entry("4", 4, Equal),
    entry("SYM_ALIGNMENT", 4, Equal),
    entry("IMPLEMENTATION_PCR", 24, Equal),
    entry("PLATFORM_PCR", 24, Equal),
    entry("DRTM_PCR", 17, Equal),
    entry("HCRTM_PCR", 0, Equal),
    entry("NUM_LOCALITIES", 5, Equal),
    entry("MAX_HANDLE_NUM", 3, Equal),
    entry("MAX_ACTIVE_SESSIONS", 64, Equal),
    entry("MAX_LOADED_SESSIONS", 3, Equal),
    entry("MAX_SESSION_NUM", 3, Equal),
    entry("MAX_LOADED_OBJECTS", 3, Equal),
    entry("MIN_EVICT_OBJECTS", 7, SavedLessOrEqual),
    entry("NUM_POLICY_PCR_GROUP", 1, Equal),
    entry("NUM_AUTHVALUE_PCR_GROUP", 1, Equal),
    entry("MAX_CONTEXT_SIZE", 2680, SavedLessOrEqual),
    entry("MAX_DIGEST_BUFFER", 1024, Equal),
    entry("MAX_NV_INDEX_SIZE", 2048, Equal),
    entry("MAX_NV_BUFFER_SIZE", 1024, Equal),
    entry("MAX_CAP_BUFFER", 1024, Equal),
    entry("NV_MEMORY_SIZE", 176_832, SavedLessOrEqual),
    entry("MIN_COUNTER_INDICES", 8, Equal),
    entry("NUM_STATIC_PCR", 16, Equal),
    entry("MAX_ALG_LIST_SIZE", 64, Equal),
    entry("PRIMARY_SEED_SIZE", 64, Equal),
    entry("CONTEXT_ENCRYPT_ALGORITHM_", 6, Equal),
    entry("NV_CLOCK_UPDATE_INTERVAL", 12, Equal),
    entry("NUM_POLICY_PCR", 1, Equal),
    entry("ORDERLY_BITS", 8, Equal),
    entry("MAX_SYM_DATA", 128, Equal),
    entry("MAX_RNG_ENTROPY_SIZE", 64, Equal),
    entry("RAM_INDEX_SPACE", 512, Equal),
    entry("RSA_DEFAULT_PUBLIC_EXPONENT", 65_537, Equal),
    entry("ENABLE_PCR_NO_INCREMENT", 1, Equal),
    entry("CRT_FORMAT_RSA", 1, Equal),
    entry("VENDOR_COMMAND_COUNT", 0, Equal),
    entry("MAX_VENDOR_BUFFER_SIZE", 1024, Equal),
    entry("TPM_MAX_DERIVATION_BITS", 8192, Equal),
    entry("PROOF_SIZE", 64, Equal),
    entry("HASH_COUNT", 4, Equal),
    entry("AES_128", 1, SavedLessOrEqual),
    entry("0", 0, SavedLessOrEqual),
    entry("AES_256", 1, SavedLessOrEqual),
    entry("SM4_128", 0, SavedLessOrEqual),
    entry("ALG_CAMELLIA", 1, SavedLessOrEqual),
    entry("CAMELLIA_128", 1, SavedLessOrEqual),
    entry("0", 0, SavedLessOrEqual),
    entry("CAMELLIA_256", 1, SavedLessOrEqual),
    entry("ALG_SHA3_256", 0, SavedLessOrEqual),
    entry("ALG_SHA3_384", 0, SavedLessOrEqual),
    entry("ALG_SHA3_512", 0, SavedLessOrEqual),
    entry("RSA_1024", 1, SavedLessOrEqual),
    entry("RSA_2048", 1, SavedLessOrEqual),
    entry("RSA_3072", 1, SavedLessOrEqual),
    entry("RSA_4096", 0, SavedLessOrEqual),
    entry("RSA_16384", 0, SavedLessOrEqual),
    entry("RH_ACT_0", 0, SavedLessOrEqual),
    entry("RH_ACT_1", 0, SavedLessOrEqual),
    entry("RH_ACT_2", 0, SavedLessOrEqual),
    entry("RH_ACT_3", 0, SavedLessOrEqual),
    entry("RH_ACT_4", 0, SavedLessOrEqual),
    entry("RH_ACT_5", 0, SavedLessOrEqual),
    entry("RH_ACT_6", 0, SavedLessOrEqual),
    entry("RH_ACT_7", 0, SavedLessOrEqual),
    entry("RH_ACT_8", 0, SavedLessOrEqual),
    entry("RH_ACT_9", 0, SavedLessOrEqual),
    entry("RH_ACT_A", 0, SavedLessOrEqual),
    entry("RH_ACT_B", 0, SavedLessOrEqual),
    entry("RH_ACT_C", 0, SavedLessOrEqual),
    entry("RH_ACT_D", 0, SavedLessOrEqual),
    entry("RH_ACT_E", 0, SavedLessOrEqual),
    entry("RH_ACT_F", 0, SavedLessOrEqual),
];

const _: () = assert!(SHARED_ENTRY_COUNT < VERSION_3_ENTRY_COUNT);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ConstantMismatch {
    pub(super) index: usize,
    pub(super) name: &'static str,
    pub(super) saved: u32,
    pub(super) current: u32,
    pub(super) comparison: CompareOp,
    pub(super) section_version: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ArraySizeInfo {
    pub(super) declared: u32,
    pub(super) expected: usize,
}

impl ArraySizeInfo {
    #[cfg(test)]
    pub(super) fn matches(self) -> bool {
        u32::try_from(self.expected) == Ok(self.declared)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ValidatedPaCompileConstants<'a> {
    pub(super) header: NvHeader,
    pub(super) count: ArraySizeInfo,
    pub(super) remaining: &'a [u8],
}

pub(super) fn parse_and_validate_pa_compile_constants(
    payload: &[u8],
) -> Result<ValidatedPaCompileConstants<'_>, PersistentAllError> {
    const SECTION: StateSection = StateSection::PaCompileConstants;
    let mut reader = BlobReader::new(payload);

    let header = parse_nv_header(
        &mut reader,
        SECTION,
        PA_COMPILE_CONSTANTS_MAGIC,
        PA_COMPILE_CONSTANTS_VERSION,
    )?;
    let expected = match header.version {
        1 | 2 => SHARED_ENTRY_COUNT,
        3 => VERSION_3_ENTRY_COUNT,
        actual => {
            return Err(PersistentAllError::UnsupportedSectionVersion {
                section: SECTION,
                actual,
                supported: PA_COMPILE_CONSTANTS_VERSION,
            });
        }
    };

    let declared = reader
        .read_u32()
        .map_err(|_| PersistentAllError::Truncated { section: SECTION })?;
    let count = ArraySizeInfo { declared, expected };

    for (index, constant) in PA_COMPILE_CONSTANTS[..expected].iter().enumerate() {
        let saved = reader
            .read_u32()
            .map_err(|_| PersistentAllError::Truncated { section: SECTION })?;
        if !constant.comparison.is_compatible(saved, constant.current) {
            return Err(PersistentAllError::CompileConstantMismatch(
                ConstantMismatch {
                    index,
                    name: constant.name,
                    saved,
                    current: constant.current,
                    comparison: constant.comparison,
                    section_version: header.version,
                },
            ));
        }
    }

    if header.version >= BLOCK_SKIP_SINCE_VERSION {
        skip_optional_block(&mut reader, false).map_err(|error| match error {
            BlockSkipError::Truncated => PersistentAllError::Truncated { section: SECTION },
            BlockSkipError::MissingRequiredBlock => {
                PersistentAllError::MissingRequiredBlock { section: SECTION }
            }
        })?;
    }

    Ok(ValidatedPaCompileConstants {
        header,
        count,
        remaining: reader.remaining(),
    })
}

pub(super) fn marshalled_section(version: u16) -> Vec<u8> {
    let expected = match version {
        1 | 2 => SHARED_ENTRY_COUNT,
        _ => VERSION_3_ENTRY_COUNT,
    };
    let mut out = Vec::new();
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&PA_COMPILE_CONSTANTS_MAGIC.to_be_bytes());
    if version >= 2 {
        out.extend_from_slice(&1u16.to_be_bytes());
    }
    out.extend_from_slice(&(expected as u32).to_be_bytes());
    for constant in &PA_COMPILE_CONSTANTS[..expected] {
        out.extend_from_slice(&constant.current.to_be_bytes());
    }
    if version >= BLOCK_SKIP_SINCE_VERSION {
        out.extend_from_slice(&[0x01, 0x00, 0x00]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const UPSTREAM_FIXTURE: &[u8] = include_bytes!("testdata/pa_compile_constants_v3.bin");

    const SECTION: StateSection = StateSection::PaCompileConstants;
    const VALUES_OFFSET: usize = 12;

    fn truncated() -> PersistentAllError {
        PersistentAllError::Truncated { section: SECTION }
    }

    fn parse(payload: &[u8]) -> Result<ValidatedPaCompileConstants<'_>, PersistentAllError> {
        parse_and_validate_pa_compile_constants(payload)
    }

    #[test]
    fn table_upstream_entry_counts() {
        assert_eq!(PA_COMPILE_CONSTANTS.len(), 120);
        assert_eq!(SHARED_ENTRY_COUNT, 88);
        assert_eq!(
            PA_COMPILE_CONSTANTS[SHARED_ENTRY_COUNT - 1].name,
            "HASH_COUNT"
        );
        assert_eq!(PA_COMPILE_CONSTANTS[SHARED_ENTRY_COUNT].name, "AES_128");
    }

    #[test]
    fn upstream_fixture_validation_success() {
        let validated = parse(UPSTREAM_FIXTURE).unwrap();
        assert_eq!(validated.header.version, 3);
        assert_eq!(validated.header.min_version, 1);
        assert_eq!(
            validated.count,
            ArraySizeInfo {
                declared: 120,
                expected: 120
            }
        );
        assert!(validated.count.matches());
        assert_eq!(validated.remaining, &[] as &[u8]);
    }

    #[test]
    fn own_marshalling_upstream_fixture_parity() {
        assert_eq!(marshalled_section(3), UPSTREAM_FIXTURE);
    }

    #[test]
    fn fixture_value_mutation_failure() {
        let cases = [
            (0, 0u32, true),
            (0, 2, true),
            (3, 0, false),
            (3, 2, true),
            (34, 2048, false),
            (34, 4096, true),
            (72, 32, true),
            (102, 1, true),
            (119, 1, true),
        ];
        for (index, saved, expect_failure) in cases {
            let mut data = UPSTREAM_FIXTURE.to_vec();
            let offset = VALUES_OFFSET + 4 * index;
            data[offset..offset + 4].copy_from_slice(&saved.to_be_bytes());
            let result = parse(&data);
            if expect_failure {
                let Err(PersistentAllError::CompileConstantMismatch(mismatch)) = result else {
                    panic!("index {index}: expected a mismatch, got {result:?}");
                };
                assert_eq!(mismatch.index, index);
                assert_eq!(mismatch.name, PA_COMPILE_CONSTANTS[index].name);
                assert_eq!(mismatch.saved, saved);
                assert_eq!(mismatch.current, PA_COMPILE_CONSTANTS[index].current);
                assert_eq!(mismatch.section_version, 3);
            } else {
                assert!(result.is_ok(), "index {index}: {result:?}");
            }
        }
    }

    #[test]
    fn comparison_operator_upstream_semantics() {
        assert!(CompareOp::Equal.is_compatible(5, 5));
        assert!(!CompareOp::Equal.is_compatible(4, 5));
        assert!(!CompareOp::Equal.is_compatible(6, 5));
        assert!(CompareOp::SavedLessOrEqual.is_compatible(4, 5));
        assert!(CompareOp::SavedLessOrEqual.is_compatible(5, 5));
        assert!(!CompareOp::SavedLessOrEqual.is_compatible(6, 5));
        assert!(CompareOp::SavedGreaterOrEqual.is_compatible(6, 5));
        assert!(CompareOp::SavedGreaterOrEqual.is_compatible(5, 5));
        assert!(!CompareOp::SavedGreaterOrEqual.is_compatible(4, 5));
        assert!(CompareOp::DontCare.is_compatible(4, 5));
        assert!(CompareOp::DontCare.is_compatible(5, 5));
        assert!(CompareOp::DontCare.is_compatible(6, 5));
    }

    #[test]
    fn version_1_2_3_acceptance() {
        for version in [1u16, 2, 3] {
            let data = marshalled_section(version);
            let validated = parse(&data).unwrap();
            assert_eq!(validated.header.version, version, "version {version}");
            assert_eq!(validated.remaining, &[] as &[u8]);
        }
    }

    #[test]
    fn version_entry_count_expectations() {
        for (version, expected) in [(1u16, 88usize), (2, 88), (3, 120)] {
            let data = marshalled_section(version);
            let validated = parse(&data).unwrap();
            assert_eq!(validated.count.expected, expected, "version {version}");
        }
    }

    #[test]
    fn version_1_six_byte_header_no_skip_block() {
        let data = marshalled_section(1);
        assert_eq!(data.len(), 6 + 4 + 88 * 4);
        let validated = parse(&data).unwrap();
        assert_eq!(validated.header.min_version, 0);
    }

    #[test]
    fn version_0_unsupported_rejection() {
        let mut data = marshalled_section(1);
        data[0..2].copy_from_slice(&0u16.to_be_bytes());
        assert_eq!(
            parse(&data),
            Err(PersistentAllError::UnsupportedSectionVersion {
                section: SECTION,
                actual: 0,
                supported: 3,
            })
        );
    }

    #[test]
    fn version_4_rejection_despite_supported_min_version() {
        let mut data = marshalled_section(3);
        data[0..2].copy_from_slice(&4u16.to_be_bytes());
        assert_eq!(
            parse(&data),
            Err(PersistentAllError::UnsupportedSectionVersion {
                section: SECTION,
                actual: 4,
                supported: 3,
            })
        );
    }

    #[test]
    fn newer_min_version_rejection() {
        let mut data = marshalled_section(3);
        data[6..8].copy_from_slice(&4u16.to_be_bytes());
        assert_eq!(
            parse(&data),
            Err(PersistentAllError::MinimumVersionTooNew {
                section: SECTION,
                minimum: 4,
                supported: 3,
            })
        );
    }

    #[test]
    fn incorrect_section_magic_rejection() {
        let mut data = marshalled_section(3);
        data[2] = 0xde;
        assert_eq!(
            parse(&data),
            Err(PersistentAllError::InvalidHeaderMagic {
                section: SECTION,
                actual: 0xdeea_6431,
            })
        );
    }

    #[test]
    fn truncated_section_header_truncation_error() {
        for len in 0..8 {
            let data = &marshalled_section(3)[..len];
            assert_eq!(parse(data), Err(truncated()), "prefix length {len}");
        }
    }

    #[test]
    fn declared_count_mismatch_metadata_no_error() {
        let mut data = marshalled_section(3);
        data[8..12].copy_from_slice(&7u32.to_be_bytes());
        let validated = parse(&data).unwrap();
        assert_eq!(
            validated.count,
            ArraySizeInfo {
                declared: 7,
                expected: 120
            }
        );
        assert!(!validated.count.matches());
    }

    #[test]
    fn declared_count_zero_full_entry_read() {
        let mut data = marshalled_section(3);
        data[8..12].copy_from_slice(&0u32.to_be_bytes());
        let validated = parse(&data).unwrap();
        assert_eq!(validated.remaining, &[] as &[u8]);
    }

    #[test]
    fn huge_declared_count_allocation_and_overread_safety() {
        let mut data = marshalled_section(3);
        data[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        let validated = parse(&data).unwrap();
        assert_eq!(validated.count.declared, u32::MAX);
        assert_eq!(validated.remaining, &[] as &[u8]);
    }

    #[test]
    fn exact_value_count_consumption() {
        let mut data = marshalled_section(3);
        data.extend_from_slice(&[0xaa, 0xbb]);
        let validated = parse(&data).unwrap();
        assert_eq!(validated.remaining, &[0xaa, 0xbb]);
        assert!(core::ptr::eq(
            validated.remaining.as_ptr(),
            data[data.len() - 2..].as_ptr()
        ));
    }

    #[test]
    fn entry_boundary_truncation_error() {
        let full = marshalled_section(3);
        for index in 0..120 {
            let end = VALUES_OFFSET + 4 * index;
            for slack in [0usize, 1, 2, 3] {
                let data = &full[..end + slack];
                assert_eq!(parse(data), Err(truncated()), "entry {index}, +{slack}");
            }
        }
    }

    #[test]
    fn validation_first_mismatch_stop() {
        let mut data = marshalled_section(3);
        let base = VALUES_OFFSET;
        data[base + 4 * 5..base + 4 * 6].copy_from_slice(&9u32.to_be_bytes());
        data[base + 4 * 10..base + 4 * 11].copy_from_slice(&9u32.to_be_bytes());
        data.truncate(base + 4 * 11);
        let Err(PersistentAllError::CompileConstantMismatch(mismatch)) = parse(&data) else {
            panic!("expected a mismatch");
        };
        assert_eq!(mismatch.index, 5);
        assert_eq!(mismatch.name, "ALG_MGF1");
        assert_eq!(mismatch.comparison, CompareOp::Equal);
    }

    #[test]
    fn version_1_2_shared_prefix_only_validation() {
        for version in [1u16, 2] {
            let data = marshalled_section(version);
            let validated = parse(&data).unwrap();
            assert_eq!(validated.count.expected, 88, "version {version}");
            assert_eq!(validated.remaining, &[] as &[u8]);
        }
    }

    #[test]
    fn version_3_full_120_entry_validation() {
        let mut data = marshalled_section(3);
        let offset = VALUES_OFFSET + 4 * 119;
        data[offset..offset + 4].copy_from_slice(&1u32.to_be_bytes());
        let Err(PersistentAllError::CompileConstantMismatch(mismatch)) = parse(&data) else {
            panic!("expected a mismatch");
        };
        assert_eq!(mismatch.index, 119);
        assert_eq!(mismatch.name, "RH_ACT_F");
    }

    fn section_without_block(version: u16) -> Vec<u8> {
        let mut data = marshalled_section(version);
        data.truncate(data.len() - 3);
        data
    }

    #[test]
    fn version_2_3_absent_future_block_acceptance() {
        for version in [2u16, 3] {
            let mut data = section_without_block(version);
            data.extend_from_slice(&[0x00, 0x00, 0x00]);
            data.extend_from_slice(&[0x42]);
            let validated = parse(&data).unwrap();
            assert_eq!(validated.remaining, &[0x42], "version {version}");
        }
    }

    #[test]
    fn version_2_3_nonempty_future_block_skip() {
        for version in [2u16, 3] {
            let mut data = section_without_block(version);
            data.extend_from_slice(&[0x01, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef]);
            data.extend_from_slice(&[0x77]);
            let validated = parse(&data).unwrap();
            assert_eq!(validated.remaining, &[0x77], "version {version}");
        }
    }

    #[test]
    fn noncanonical_block_boolean_true_interpretation() {
        let mut data = section_without_block(3);
        data.extend_from_slice(&[0xff, 0x00, 0x01, 0x99]);
        let validated = parse(&data).unwrap();
        assert_eq!(validated.remaining, &[] as &[u8]);
    }

    #[test]
    fn truncated_future_block_truncation_error() {
        let base = section_without_block(3);
        assert_eq!(parse(&base), Err(truncated()));
        let mut data = base.clone();
        data.extend_from_slice(&[0x01, 0x00]);
        assert_eq!(parse(&data), Err(truncated()));
        let mut data = base.clone();
        data.extend_from_slice(&[0x01, 0x00, 0x05, 0x01, 0x02]);
        assert_eq!(parse(&data), Err(truncated()));
    }

    #[test]
    fn version_1_no_block_read() {
        let mut data = marshalled_section(1);
        data.extend_from_slice(&[0x01, 0x00, 0x01, 0x55]);
        let validated = parse(&data).unwrap();
        assert_eq!(validated.remaining, &[0x01, 0x00, 0x01, 0x55]);
    }
}
