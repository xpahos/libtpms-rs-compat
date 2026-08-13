mod hasher;
mod policy;
mod selection;

pub(super) use hasher::BankHasher;

pub(super) use policy::{
    NUM_POLICY_PCR_GROUP, PCR_POLICY_MAGIC, ParsedPcrPolicies, PcrPolicyEntry, parse_pcr_policies,
};
pub(super) use selection::{
    HASH_COUNT, PCR_SELECT_MAX, PCR_SELECT_MIN, PcrAllocation, PcrSelection, parse_pcr_allocation,
};

#[cfg(test)]
pub(super) use policy::PcrPoliciesFixture;
#[cfg(test)]
pub(super) use selection::PcrAllocationFixture;

use super::marshal::{BlobReader, BlockSkipError, skip_optional_block};
use super::persistent::{PersistentAllError, StateSection, parse_nv_header};
use super::public::{TPM_ALG_NULL, TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512};
use super::state::algs_active;

pub(super) const PCR_MAGIC: u32 = 0xe95f_0387;
const PCR_VERSION: u16 = 2;

pub(super) const PCR_SLOT_BANKS: [(u16, usize); 4] = [
    (TPM_ALG_SHA1, 20),
    (TPM_ALG_SHA256, 32),
    (TPM_ALG_SHA384, 48),
    (TPM_ALG_SHA512, 64),
];

pub(super) const HCRTM_PCR: usize = 0;
pub(super) const DRTM_PCR: usize = 17;

const DRTM_ENABLED: bool = true;
const DRTM_LOCALITY: u8 = 4;

#[derive(Clone, Copy)]
pub(super) struct PcrPlatformAttributes {
    pub(super) state_save: bool,
    pub(super) do_not_increment_pcr_counter: bool,
    pub(super) auth_values_group: u8,
    pub(super) reset_locality: u8,
    pub(super) extend_locality: u8,
}

const fn static_rtm_pcr() -> PcrPlatformAttributes {
    PcrPlatformAttributes {
        state_save: true,
        do_not_increment_pcr_counter: false,
        auth_values_group: 0,
        reset_locality: 0x00,
        extend_locality: 0x1f,
    }
}

const fn dynamic_pcr(
    do_not_increment_pcr_counter: bool,
    reset_locality: u8,
    extend_locality: u8,
) -> PcrPlatformAttributes {
    PcrPlatformAttributes {
        state_save: false,
        do_not_increment_pcr_counter,
        auth_values_group: 0,
        reset_locality,
        extend_locality,
    }
}

pub(super) fn pcr_platform_attributes(pcr: usize) -> PcrPlatformAttributes {
    match pcr {
        0..=15 => static_rtm_pcr(),
        16 => dynamic_pcr(true, 0x0f, 0x1f),
        17 | 18 => dynamic_pcr(false, 0x10, 0x1c),
        19 => dynamic_pcr(false, 0x10, 0x0c),
        20 => dynamic_pcr(false, 0x1c, 0x0e),
        21 | 22 => dynamic_pcr(true, 0x1c, 0x04),
        23 => dynamic_pcr(true, 0x0f, 0x1f),
        _ => static_rtm_pcr(),
    }
}

pub(super) fn pcr_extend_allowed(pcr: usize, locality: u8) -> bool {
    locality <= 4 && pcr_platform_attributes(pcr).extend_locality & (1 << locality) != 0
}

pub(super) fn pcr_reset_allowed(pcr: usize, locality: u8) -> bool {
    if locality > 4 || (DRTM_ENABLED && locality == DRTM_LOCALITY) {
        return false;
    }
    pcr_platform_attributes(pcr).reset_locality & (1 << locality) != 0
}

pub(super) fn pcr_is_state_saved(pcr: usize) -> bool {
    pcr_platform_attributes(pcr).state_save
}

pub(super) fn pcr_auth_value_group(pcr: usize) -> Option<usize> {
    match pcr_platform_attributes(pcr).auth_values_group {
        0 => None,
        group => Some(usize::from(group) - 1),
    }
}

pub(super) fn pcr_in_tcb_group(pcr: usize) -> bool {
    pcr_platform_attributes(pcr).do_not_increment_pcr_counter
}

pub(super) fn bank_slot(hash_alg: u16) -> Option<(usize, usize)> {
    PCR_SLOT_BANKS
        .iter()
        .enumerate()
        .find(|&(_, &(bank_alg, _))| bank_alg == hash_alg)
        .map(|(slot, &(_, digest_size))| (slot, digest_size))
}

pub(super) fn pcr_resets_to_ones(pcr: usize) -> bool {
    (17..=22).contains(&pcr)
}

pub(super) fn allocation_selects(
    allocation: &super::persistent::OwnedPcrAllocation,
    hash_alg: u16,
    pcr: usize,
) -> bool {
    allocation.selections.iter().any(|selection| {
        selection.hash_alg == hash_alg
            && selection
                .select
                .get(pcr / 8)
                .is_some_and(|byte| byte & (1 << (pcr % 8)) != 0)
    })
}

const BLOCK_SKIP_SINCE_VERSION: u16 = 2;

const SECTION: StateSection = StateSection::Pcr;

fn truncated() -> PersistentAllError {
    PersistentAllError::Truncated { section: SECTION }
}

#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct Pcr<'a> {
    pub(super) banks: [Option<&'a [u8]>; PCR_SLOT_BANKS.len()],
}

pub(super) fn parse_pcr<'a>(
    reader: &mut BlobReader<'a>,
    shadow: &[PcrSelection<'_>],
) -> Result<Pcr<'a>, PersistentAllError> {
    let header = parse_nv_header(reader, SECTION, PCR_MAGIC, PCR_VERSION)?;

    let mut algs_needed = algs_active(shadow);
    let mut banks = [None; PCR_SLOT_BANKS.len()];
    loop {
        let alg = reader.read_u16().map_err(|_| truncated())?;
        if alg == TPM_ALG_NULL {
            break;
        }
        let Some(index) = PCR_SLOT_BANKS
            .iter()
            .position(|&(bank_alg, _)| bank_alg == alg)
        else {
            return Err(PersistentAllError::UnsupportedPcrBank { actual: alg });
        };
        algs_needed &= !(1u64 << alg);
        let expected = PCR_SLOT_BANKS[index].1;
        let declared = reader.read_u16().map_err(|_| truncated())?;
        if usize::from(declared) != expected {
            return Err(PersistentAllError::ArraySizeInvalid {
                section: SECTION,
                declared,
                expected,
            });
        }
        banks[index] = Some(reader.take(expected).map_err(|_| truncated())?);
    }

    if algs_needed != 0 {
        let algorithm = algs_needed.trailing_zeros() as u16;
        return Err(PersistentAllError::MissingPcrBank { algorithm });
    }

    if header.version >= BLOCK_SKIP_SINCE_VERSION {
        skip_optional_block(reader, false)
            .map(|_| ())
            .map_err(|error| match error {
                BlockSkipError::Truncated => truncated(),
                BlockSkipError::MissingRequiredBlock => {
                    PersistentAllError::MissingRequiredBlock { section: SECTION }
                }
            })?;
    }

    Ok(Pcr { banks })
}

#[cfg(test)]
pub(super) struct PcrFixture {
    pub(super) version: u16,
    pub(super) magic: u32,
    pub(super) banks: Vec<(u16, u16, Vec<u8>)>,
    pub(super) end_marker: bool,
    pub(super) future_block: Option<(u8, u16, Vec<u8>)>,
}

#[cfg(test)]
impl Default for PcrFixture {
    fn default() -> Self {
        Self {
            version: PCR_VERSION,
            magic: PCR_MAGIC,
            banks: PCR_SLOT_BANKS
                .iter()
                .map(|&(alg, size)| (alg, size as u16, vec![alg as u8; size]))
                .collect(),
            end_marker: true,
            future_block: Some((1, 0, Vec::new())),
        }
    }
}

#[cfg(test)]
impl PcrFixture {
    pub(super) fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.magic.to_be_bytes());
        if self.version >= 2 {
            out.extend_from_slice(&1u16.to_be_bytes());
        }
        for (alg, declared, digest) in &self.banks {
            out.extend_from_slice(&alg.to_be_bytes());
            out.extend_from_slice(&declared.to_be_bytes());
            out.extend_from_slice(digest);
        }
        if self.end_marker {
            out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        }
        if self.version >= 2
            && let Some((has_block, size, payload)) = &self.future_block
        {
            out.push(*has_block);
            out.extend_from_slice(&size.to_be_bytes());
            out.extend_from_slice(payload);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::constants::{TPM_RC_BAD_PARAMETER, TPM_RC_BAD_TAG, TPM_RC_INSUFFICIENT};
    use crate::library::tpm2::volatile::IMPLEMENTATION_PCR;

    const TAIL_SENTINEL: [u8; 3] = [0xc1, 0xc2, 0xc3];

    const UPSTREAM_RESET_LOCALITY: [u8; IMPLEMENTATION_PCR] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x0f, 0x10, 0x10, 0x10, 0x1c, 0x1c, 0x1c, 0x0f,
    ];

    #[test]
    fn the_reset_locality_attribute_matches_the_upstream_platform_table() {
        for (pcr, expected) in UPSTREAM_RESET_LOCALITY.into_iter().enumerate() {
            assert_eq!(
                pcr_platform_attributes(pcr).reset_locality,
                expected,
                "PCR {pcr}"
            );
        }
    }

    #[test]
    fn pcr_reset_allowed_matches_the_upstream_platform_table() {
        for (pcr, reset_locality) in UPSTREAM_RESET_LOCALITY.into_iter().enumerate() {
            for locality in 0..=4u8 {
                let expected = locality != 4 && reset_locality & (1 << locality) != 0;
                assert_eq!(
                    pcr_reset_allowed(pcr, locality),
                    expected,
                    "PCR {pcr} from locality {locality}"
                );
            }
        }
    }

    #[test]
    fn drtm_blocks_every_command_reset_from_locality_four() {
        for pcr in 0..IMPLEMENTATION_PCR {
            assert!(!pcr_reset_allowed(pcr, 4), "PCR {pcr}");
        }
    }

    #[test]
    fn localities_above_four_never_allow_a_reset() {
        for pcr in 0..IMPLEMENTATION_PCR {
            for locality in 5..=u8::MAX {
                assert!(!pcr_reset_allowed(pcr, locality), "PCR {pcr}, {locality}");
            }
        }
    }

    #[test]
    fn static_rtm_pcrs_can_never_be_reset_by_a_command() {
        for pcr in 0..16 {
            for locality in 0..=u8::MAX {
                assert!(!pcr_reset_allowed(pcr, locality), "PCR {pcr}, {locality}");
            }
        }
    }

    fn sha256_shadow() -> Vec<u8> {
        vec![0x01]
    }

    fn shadow_selections(select: &[u8]) -> [PcrSelection<'_>; 1] {
        [PcrSelection {
            hash_alg: TPM_ALG_SHA256,
            select,
        }]
    }

    fn parse<'a>(
        data: &'a [u8],
        shadow: &[PcrSelection<'_>],
    ) -> Result<(Pcr<'a>, usize), PersistentAllError> {
        let mut reader = BlobReader::new(data);
        let pcr = parse_pcr(&mut reader, shadow)?;
        Ok((pcr, reader.remaining().len()))
    }

    #[test]
    fn full_bank_set_decodes_in_compiled_order() {
        let select = sha256_shadow();
        let mut data = PcrFixture::default().bytes();
        data.extend_from_slice(&TAIL_SENTINEL);
        let (pcr, remaining) = parse(&data, &shadow_selections(&select)).unwrap();
        for (slot, &(alg, size)) in pcr.banks.iter().zip(PCR_SLOT_BANKS.iter()) {
            let digest = slot.expect("every compiled bank is present");
            assert_eq!(digest, vec![alg as u8; size]);
        }
        assert_eq!(remaining, TAIL_SENTINEL.len());
    }

    #[test]
    fn banks_not_in_the_shadow_are_accepted_and_optional() {
        let data = PcrFixture {
            banks: vec![(TPM_ALG_SHA1, 20, vec![0xaa; 20])],
            ..PcrFixture::default()
        }
        .bytes();
        let (pcr, _) = parse(&data, &[]).unwrap();
        assert_eq!(pcr.banks[0], Some(&[0xaa; 20][..]));
        assert!(pcr.banks[1].is_none());
    }

    #[test]
    fn missing_shadow_active_bank_is_bad_parameter() {
        let select = sha256_shadow();
        let data = PcrFixture {
            banks: vec![(TPM_ALG_SHA1, 20, vec![0xaa; 20])],
            ..PcrFixture::default()
        }
        .bytes();
        let error = parse(&data, &shadow_selections(&select)).unwrap_err();
        assert_eq!(
            error,
            PersistentAllError::MissingPcrBank {
                algorithm: TPM_ALG_SHA256,
            }
        );
        assert_eq!(error.tpm_result(), TPM_RC_BAD_PARAMETER);
    }

    #[test]
    fn shadow_selection_with_all_zero_bitmap_requires_nothing() {
        let select = vec![0x00, 0x00, 0x00];
        let data = PcrFixture {
            banks: Vec::new(),
            ..PcrFixture::default()
        }
        .bytes();
        assert!(parse(&data, &shadow_selections(&select)).is_ok());
    }

    #[test]
    fn unsupported_bank_algorithm_is_bad_parameter() {
        let data = PcrFixture {
            banks: vec![(0x0012, 32, vec![0; 32])],
            ..PcrFixture::default()
        }
        .bytes();
        let error = parse(&data, &[]).unwrap_err();
        assert_eq!(
            error,
            PersistentAllError::UnsupportedPcrBank { actual: 0x0012 }
        );
    }

    #[test]
    fn wrong_bank_digest_size_is_bad_parameter() {
        for declared in [0u16, 19, 21, 0xffff] {
            let data = PcrFixture {
                banks: vec![(TPM_ALG_SHA1, declared, vec![0; declared as usize])],
                ..PcrFixture::default()
            }
            .bytes();
            let error = parse(&data, &[]).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::ArraySizeInvalid {
                    section: StateSection::Pcr,
                    declared,
                    expected: 20,
                },
                "declared {declared}"
            );
        }
    }

    #[test]
    fn wrong_magic_is_bad_tag() {
        let mut data = PcrFixture::default().bytes();
        data[2] ^= 0xff;
        let error = parse(&data, &[]).unwrap_err();
        assert_eq!(error.tpm_result(), TPM_RC_BAD_TAG);
    }

    #[test]
    fn every_strict_prefix_fails_safely() {
        let full = PcrFixture::default().bytes();
        for len in 0..full.len() {
            let error = parse(&full[..len], &[]).unwrap_err();
            assert_eq!(
                error.tpm_result(),
                TPM_RC_INSUFFICIENT,
                "prefix length {len} of {}",
                full.len()
            );
        }
        assert!(parse(&full, &[]).is_ok());
    }

    #[test]
    fn malformed_input_never_panics() {
        let full = PcrFixture::default().bytes();
        for index in 0..full.len() {
            for byte in [0x00u8, 0x01, 0xff] {
                let mut data = full.clone();
                data[index] = byte;
                let _ = parse(&data, &[]);
            }
        }
    }
}
