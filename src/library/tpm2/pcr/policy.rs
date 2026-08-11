use crate::library::tpm2::marshal::{
    BlobReader, BlockDisposition, BlockSkipError, Tpm2bError, skip_optional_block,
};
use crate::library::tpm2::persistent::{
    NvHeader, PersistentAllError, PersistentField, StateSection, parse_nv_header,
};

pub(in crate::library::tpm2) const PCR_POLICY_MAGIC: u32 = 0x176b_e626;
const PCR_POLICY_VERSION: u16 = 2;

pub(in crate::library::tpm2) const NUM_POLICY_PCR_GROUP: usize = 1;

const MAX_DIGEST_SIZE: usize = 64;

#[cfg(test)]
const TPM_ALG_SHA256: u16 = 0x000b;

const NESTED_BLOCK_SINCE_VERSION: u16 = 2;

const SECTION: StateSection = StateSection::PcrPolicy;

fn truncated() -> PersistentAllError {
    PersistentAllError::Truncated { section: SECTION }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) struct PcrPolicyEntry<'a> {
    pub(in crate::library::tpm2) hash_alg: u16,
    pub(in crate::library::tpm2) policy: &'a [u8],
}

#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::library::tpm2) struct ParsedPcrPolicies<'a> {
    pub(in crate::library::tpm2) header: NvHeader,
    pub(in crate::library::tpm2) outer_declared_size: u16,
    pub(in crate::library::tpm2) entries: [PcrPolicyEntry<'a>; NUM_POLICY_PCR_GROUP],
    pub(in crate::library::tpm2) remaining: &'a [u8],
}

pub(in crate::library::tpm2) fn parse_pcr_policies(
    input: &[u8],
) -> Result<ParsedPcrPolicies<'_>, PersistentAllError> {
    let mut reader = BlobReader::new(input);

    let outer_declared_size =
        match skip_optional_block(&mut reader, true).map_err(|error| match error {
            BlockSkipError::Truncated => PersistentAllError::Truncated {
                section: StateSection::PersistentData,
            },
            BlockSkipError::MissingRequiredBlock => PersistentAllError::MissingRequiredBlock {
                section: StateSection::PersistentData,
            },
        })? {
            BlockDisposition::Present { declared_size } => declared_size,
            BlockDisposition::AbsentNotNeeded | BlockDisposition::SkippedBytes(_) => {
                unreachable!("a needed block is either present or an error")
            }
        };

    let header = parse_nv_header(&mut reader, SECTION, PCR_POLICY_MAGIC, PCR_POLICY_VERSION)?;

    let declared_count = reader.read_u16().map_err(|_| truncated())?;
    if usize::from(declared_count) != NUM_POLICY_PCR_GROUP {
        return Err(PersistentAllError::ArraySizeMismatch {
            section: SECTION,
            declared: declared_count,
            expected: NUM_POLICY_PCR_GROUP,
        });
    }

    let mut entries = [PcrPolicyEntry {
        hash_alg: 0,
        policy: &[],
    }; NUM_POLICY_PCR_GROUP];
    for entry in &mut entries {
        let hash_alg = reader.read_u16().map_err(|_| truncated())?;
        let policy = reader
            .read_tpm2b(MAX_DIGEST_SIZE)
            .map_err(|error| match error {
                Tpm2bError::Truncated => truncated(),
                Tpm2bError::SizeExceeded { actual, maximum } => {
                    PersistentAllError::Tpm2bSizeExceeded {
                        section: SECTION,
                        field: PersistentField::PcrPolicyDigest,
                        actual,
                        maximum,
                    }
                }
            })?;
        *entry = PcrPolicyEntry { hash_alg, policy };
    }

    if header.version >= NESTED_BLOCK_SINCE_VERSION {
        skip_optional_block(&mut reader, false).map_err(|error| match error {
            BlockSkipError::Truncated => truncated(),
            BlockSkipError::MissingRequiredBlock => {
                PersistentAllError::MissingRequiredBlock { section: SECTION }
            }
        })?;
    }

    Ok(ParsedPcrPolicies {
        header,
        outer_declared_size,
        entries,
        remaining: reader.remaining(),
    })
}

#[cfg(test)]
pub(in crate::library::tpm2) struct PcrPoliciesFixture {
    pub(in crate::library::tpm2) outer_has_block: u8,
    pub(in crate::library::tpm2) outer_block_size: Option<u16>,
    pub(in crate::library::tpm2) version: u16,
    pub(in crate::library::tpm2) min_version: u16,
    pub(in crate::library::tpm2) array_size: u16,
    pub(in crate::library::tpm2) hash_alg: u16,
    pub(in crate::library::tpm2) policy: Vec<u8>,
    pub(in crate::library::tpm2) future_block: Option<(u8, u16, Vec<u8>)>,
    pub(in crate::library::tpm2) tail: Vec<u8>,
}

#[cfg(test)]
impl Default for PcrPoliciesFixture {
    fn default() -> Self {
        Self {
            outer_has_block: 1,
            outer_block_size: None,
            version: PCR_POLICY_VERSION,
            min_version: 1,
            array_size: NUM_POLICY_PCR_GROUP as u16,
            hash_alg: TPM_ALG_SHA256,
            policy: Vec::new(),
            future_block: Some((1, 0, Vec::new())),
            tail: Vec::new(),
        }
    }
}

#[cfg(test)]
impl PcrPoliciesFixture {
    fn nested_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&PCR_POLICY_MAGIC.to_be_bytes());
        if self.version >= 2 {
            out.extend_from_slice(&self.min_version.to_be_bytes());
        }
        out.extend_from_slice(&self.array_size.to_be_bytes());
        out.extend_from_slice(&self.hash_alg.to_be_bytes());
        out.extend_from_slice(&u16::try_from(self.policy.len()).unwrap().to_be_bytes());
        out.extend_from_slice(&self.policy);
        if let Some((has_block, size, payload)) = &self.future_block {
            out.push(*has_block);
            out.extend_from_slice(&size.to_be_bytes());
            out.extend_from_slice(payload);
        }
        out
    }

    pub(in crate::library::tpm2) fn bytes(&self) -> Vec<u8> {
        let nested = self.nested_bytes();
        let mut out = vec![self.outer_has_block];
        let size = self
            .outer_block_size
            .unwrap_or_else(|| u16::try_from(nested.len()).unwrap());
        out.extend_from_slice(&size.to_be_bytes());
        out.extend_from_slice(&nested);
        out.extend_from_slice(&self.tail);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::constants::{
        TPM_RC_BAD_PARAMETER, TPM_RC_BAD_TAG, TPM_RC_BAD_VERSION, TPM_RC_INSUFFICIENT, TPM_RC_SIZE,
    };

    const TPM_ALG_NULL: u16 = 0x0010;
    const TPM_ALG_SM3_256: u16 = 0x0012;
    const TPM_ALG_SHA3_256: u16 = 0x0027;

    fn parse(input: &[u8]) -> Result<ParsedPcrPolicies<'_>, PersistentAllError> {
        parse_pcr_policies(input)
    }

    #[test]
    fn hand_built_fixture_matches_the_upstream_marshal_order() {
        let fixture = [
            0x01, 0x00, 0x13, 0x00, 0x02, 0x17, 0x6b, 0xe6, 0x26, 0x00, 0x01, 0x00, 0x01, 0x00,
            0x0b, 0x00, 0x02, 0xe1, 0xe2, 0x01, 0x00, 0x00, 0x99, 0x98,
        ];
        let parsed = parse(&fixture).unwrap();
        assert_eq!(
            parsed.header,
            NvHeader {
                version: 2,
                magic: PCR_POLICY_MAGIC,
                min_version: 1,
            }
        );
        assert_eq!(parsed.outer_declared_size, 19);
        assert_eq!(
            parsed.entries,
            [PcrPolicyEntry {
                hash_alg: TPM_ALG_SHA256,
                policy: &[0xe1, 0xe2],
            }]
        );
        assert_eq!(parsed.remaining, &[0x99, 0x98]);
    }

    #[test]
    fn default_fixture_parses_and_stops_at_the_sentinel() {
        let data = PcrPoliciesFixture {
            tail: vec![0xaa, 0xbb],
            ..PcrPoliciesFixture::default()
        }
        .bytes();
        let parsed = parse(&data).unwrap();
        assert_eq!(parsed.entries[0].hash_alg, TPM_ALG_SHA256);
        assert_eq!(parsed.entries[0].policy, &[] as &[u8]);
        assert_eq!(parsed.remaining, &[0xaa, 0xbb]);
        assert!(core::ptr::eq(
            parsed.remaining.as_ptr(),
            data[data.len() - 2..].as_ptr()
        ));
    }

    #[test]
    fn absent_required_outer_block_is_bad_parameter() {
        let error = parse(&[0x00, 0x00, 0x00]).unwrap_err();
        assert_eq!(
            error,
            PersistentAllError::MissingRequiredBlock {
                section: StateSection::PersistentData,
            }
        );
        assert_eq!(error.tpm_result(), TPM_RC_BAD_PARAMETER);
    }

    #[test]
    fn noncanonical_nonzero_outer_booleans_are_true() {
        for boolean in [0x01u8, 0x02, 0x80, 0xff] {
            let data = PcrPoliciesFixture {
                outer_has_block: boolean,
                ..PcrPoliciesFixture::default()
            }
            .bytes();
            assert!(parse(&data).is_ok(), "boolean byte {boolean:#04x}");
        }
    }

    #[test]
    fn truncated_outer_framing_is_insufficient() {
        for data in [&[] as &[u8], &[0x01], &[0x01, 0x00]] {
            let error = parse(data).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::Truncated {
                    section: StateSection::PersistentData,
                },
                "input {data:02x?}"
            );
            assert_eq!(error.tpm_result(), TPM_RC_INSUFFICIENT);
        }
    }

    #[test]
    fn misleading_outer_declared_sizes_do_not_affect_the_nested_parse() {
        for declared in [0u16, 1, 5, 0x0100, u16::MAX] {
            let data = PcrPoliciesFixture {
                outer_block_size: Some(declared),
                tail: vec![0x77],
                ..PcrPoliciesFixture::default()
            }
            .bytes();
            let parsed =
                parse(&data).unwrap_or_else(|error| panic!("declared size {declared}: {error:?}"));
            assert_eq!(parsed.outer_declared_size, declared);
            assert_eq!(parsed.remaining, &[0x77], "declared size {declared}");
        }
    }

    #[test]
    fn huge_outer_declared_size_neither_allocates_nor_skips() {
        let data = PcrPoliciesFixture {
            outer_block_size: Some(u16::MAX),
            ..PcrPoliciesFixture::default()
        }
        .bytes();
        assert!(u16::MAX as usize > data.len());
        assert_eq!(parse(&data).unwrap().outer_declared_size, u16::MAX);
    }

    #[test]
    fn incorrect_nested_magic_is_bad_tag() {
        let mut data = PcrPoliciesFixture::default().bytes();
        data[6] = 0xff;
        let error = parse(&data).unwrap_err();
        assert_eq!(
            error,
            PersistentAllError::InvalidHeaderMagic {
                section: SECTION,
                actual: 0x17ff_e626,
            }
        );
        assert_eq!(error.tpm_result(), TPM_RC_BAD_TAG);
    }

    #[test]
    fn truncated_header_fields_are_insufficient() {
        let full = PcrPoliciesFixture::default().bytes();
        for len in [3usize, 4, 5, 8, 10] {
            let error = parse(&full[..len]).unwrap_err();
            assert_eq!(error, truncated(), "prefix length {len}");
            assert_eq!(error.tpm_result(), TPM_RC_INSUFFICIENT);
        }
    }

    #[test]
    fn version_1_uses_a_six_byte_header_without_future_block() {
        let data = PcrPoliciesFixture {
            version: 1,
            future_block: None,
            tail: vec![0x55],
            ..PcrPoliciesFixture::default()
        }
        .bytes();
        let parsed = parse(&data).unwrap();
        assert_eq!(
            parsed.header,
            NvHeader {
                version: 1,
                magic: PCR_POLICY_MAGIC,
                min_version: 0,
            }
        );
        assert_eq!(parsed.remaining, &[0x55]);
    }

    #[test]
    fn version_2_uses_an_eight_byte_header() {
        let data = PcrPoliciesFixture::default().bytes();
        let parsed = parse(&data).unwrap();
        assert_eq!(parsed.header.version, 2);
        assert_eq!(parsed.header.min_version, 1);
    }

    #[test]
    fn future_version_with_supported_min_version_is_accepted() {
        for min_version in [0u16, 1, 2] {
            let data = PcrPoliciesFixture {
                version: 9,
                min_version,
                ..PcrPoliciesFixture::default()
            }
            .bytes();
            let parsed =
                parse(&data).unwrap_or_else(|error| panic!("min_version {min_version}: {error:?}"));
            assert_eq!(parsed.header.version, 9);
        }
    }

    #[test]
    fn min_version_newer_than_2_is_rejected() {
        let data = PcrPoliciesFixture {
            version: 9,
            min_version: 3,
            ..PcrPoliciesFixture::default()
        }
        .bytes();
        let error = parse(&data).unwrap_err();
        assert_eq!(
            error,
            PersistentAllError::MinimumVersionTooNew {
                section: SECTION,
                minimum: 3,
                supported: 2,
            }
        );
        assert_eq!(error.tpm_result(), TPM_RC_BAD_VERSION);
    }

    #[test]
    fn declared_count_1_is_accepted() {
        assert!(parse(&PcrPoliciesFixture::default().bytes()).is_ok());
    }

    #[test]
    fn mismatching_counts_are_size_errors_without_reading_entries() {
        for declared in [0u16, 2, u16::MAX] {
            let fixture = PcrPoliciesFixture {
                array_size: declared,
                future_block: None,
                ..PcrPoliciesFixture::default()
            };
            let full = fixture.bytes();
            let data = &full[..full.len() - 4];
            let error = parse(data).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::ArraySizeMismatch {
                    section: SECTION,
                    declared,
                    expected: NUM_POLICY_PCR_GROUP,
                },
                "declared {declared}"
            );
            assert_eq!(error.tpm_result(), TPM_RC_SIZE);
        }
    }

    #[test]
    fn truncated_count_is_insufficient() {
        let full = PcrPoliciesFixture::default().bytes();
        assert_eq!(parse(&full[..12]).unwrap_err(), truncated());
    }

    #[test]
    fn every_raw_hash_algorithm_id_is_accepted_and_preserved() {
        for alg in [
            0x0000u16,
            0x0004,
            TPM_ALG_SHA256,
            0x000c,
            0x000d,
            TPM_ALG_NULL,
            TPM_ALG_SM3_256,
            TPM_ALG_SHA3_256,
            0xffff,
        ] {
            let data = PcrPoliciesFixture {
                hash_alg: alg,
                tail: vec![0x99, 0x98],
                ..PcrPoliciesFixture::default()
            }
            .bytes();
            let parsed = parse(&data).unwrap_or_else(|error| panic!("alg {alg:#06x}: {error:?}"));
            assert_eq!(parsed.entries[0].hash_alg, alg, "alg {alg:#06x}");
            assert_eq!(parsed.remaining, &[0x99, 0x98], "alg {alg:#06x}");
        }
    }

    #[test]
    fn truncated_hash_algorithm_is_insufficient() {
        let full = PcrPoliciesFixture::default().bytes();
        assert_eq!(parse(&full[..14]).unwrap_err(), truncated());
    }

    #[test]
    fn nonempty_policy_digest_borrows_the_input() {
        let data = PcrPoliciesFixture {
            policy: vec![0x5c; 5],
            ..PcrPoliciesFixture::default()
        }
        .bytes();
        let parsed = parse(&data).unwrap();
        assert_eq!(parsed.entries[0].policy, &[0x5c; 5]);
        assert!(
            data.as_ptr_range()
                .contains(&parsed.entries[0].policy.as_ptr()),
            "the digest must borrow the input, not copy it"
        );
    }

    #[test]
    fn exact_capacity_policy_digest_is_accepted() {
        let data = PcrPoliciesFixture {
            policy: vec![0x11; MAX_DIGEST_SIZE],
            ..PcrPoliciesFixture::default()
        }
        .bytes();
        assert_eq!(parse(&data).unwrap().entries[0].policy.len(), 64);
    }

    #[test]
    fn oversized_policy_digest_is_a_size_error() {
        let data = PcrPoliciesFixture {
            policy: vec![0x11; MAX_DIGEST_SIZE + 1],
            ..PcrPoliciesFixture::default()
        }
        .bytes();
        let error = parse(&data).unwrap_err();
        assert_eq!(
            error,
            PersistentAllError::Tpm2bSizeExceeded {
                section: SECTION,
                field: PersistentField::PcrPolicyDigest,
                actual: 65,
                maximum: MAX_DIGEST_SIZE,
            }
        );
        assert_eq!(error.tpm_result(), TPM_RC_SIZE);
    }

    #[test]
    fn attacker_controlled_digest_length_neither_allocates_nor_panics() {
        let fixture = PcrPoliciesFixture {
            future_block: None,
            ..PcrPoliciesFixture::default()
        };
        let mut data = fixture.bytes();
        let len = data.len();
        data[len - 2..].copy_from_slice(&[0xff, 0xff]);
        data.extend_from_slice(&[0x01, 0x02]);
        assert_eq!(
            parse(&data).unwrap_err().tpm_result(),
            TPM_RC_SIZE,
            "declared length beyond capacity is TPM_RC_SIZE"
        );
    }

    #[test]
    fn truncated_policy_digest_is_insufficient() {
        let full = PcrPoliciesFixture {
            policy: vec![0x33; 8],
            future_block: None,
            tail: Vec::new(),
            ..PcrPoliciesFixture::default()
        }
        .bytes();
        let length_start = full.len() - 10;
        for len in [length_start + 1, length_start + 2 + 4] {
            assert_eq!(parse(&full[..len]).unwrap_err(), truncated(), "cut {len}");
        }
    }

    #[test]
    fn version_1_consumes_no_future_block_framing() {
        let data = PcrPoliciesFixture {
            version: 1,
            future_block: None,
            tail: vec![0x01, 0x00, 0x05, 0x44],
            ..PcrPoliciesFixture::default()
        }
        .bytes();
        let parsed = parse(&data).unwrap();
        assert_eq!(parsed.remaining, &[0x01, 0x00, 0x05, 0x44]);
    }

    #[test]
    fn version_2_absent_future_block_continues() {
        let data = PcrPoliciesFixture {
            future_block: Some((0, 0, Vec::new())),
            tail: vec![0x66],
            ..PcrPoliciesFixture::default()
        }
        .bytes();
        assert_eq!(parse(&data).unwrap().remaining, &[0x66]);
    }

    #[test]
    fn version_2_present_future_blocks_are_skipped_exactly() {
        for payload in [vec![], vec![0xf1, 0xf2, 0xf3]] {
            let data = PcrPoliciesFixture {
                future_block: Some((1, payload.len() as u16, payload.clone())),
                tail: vec![0x66, 0x67],
                ..PcrPoliciesFixture::default()
            }
            .bytes();
            let parsed = parse(&data).unwrap();
            assert_eq!(
                parsed.remaining,
                &[0x66, 0x67],
                "payload length {}: skipped bytes must not leak into pcrAllocated",
                payload.len()
            );
        }
    }

    #[test]
    fn noncanonical_nonzero_future_block_booleans_are_true() {
        for boolean in [0x02u8, 0x80, 0xff] {
            let data = PcrPoliciesFixture {
                future_block: Some((boolean, 1, vec![0xee])),
                tail: vec![0x66],
                ..PcrPoliciesFixture::default()
            }
            .bytes();
            let parsed = parse(&data).unwrap();
            assert_eq!(parsed.remaining, &[0x66], "boolean byte {boolean:#04x}");
        }
    }

    #[test]
    fn truncated_future_block_framing_is_insufficient() {
        let full = PcrPoliciesFixture::default().bytes();
        for len in [full.len() - 3, full.len() - 2, full.len() - 1] {
            assert_eq!(parse(&full[..len]).unwrap_err(), truncated(), "cut {len}");
        }
    }

    #[test]
    fn future_block_size_beyond_input_is_insufficient() {
        let data = PcrPoliciesFixture {
            future_block: Some((1, 4, vec![0x11, 0x22])),
            ..PcrPoliciesFixture::default()
        }
        .bytes();
        assert_eq!(parse(&data).unwrap_err(), truncated());
    }

    #[test]
    fn every_strict_prefix_of_a_valid_section_fails_without_panic() {
        let full = PcrPoliciesFixture {
            policy: vec![0x2b; 3],
            future_block: Some((1, 2, vec![0xd1, 0xd2])),
            ..PcrPoliciesFixture::default()
        }
        .bytes();
        for len in 0..full.len() {
            let error = parse(&full[..len]).unwrap_err();
            assert_eq!(
                error.tpm_result(),
                TPM_RC_INSUFFICIENT,
                "prefix length {len} of {}",
                full.len()
            );
        }
        assert!(parse(&full).is_ok());
    }
}
