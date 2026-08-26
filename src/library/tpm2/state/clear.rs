use crate::library::tpm2::marshal::{BlobReader, BlockSkipError, Tpm2bError, skip_optional_block};
use crate::library::tpm2::pcr::PcrSelection;
use crate::library::tpm2::persistent::{
    PersistentAllError, PersistentField, StateSection, parse_nv_header,
};

pub(in crate::library::tpm2) const STATE_CLEAR_DATA_MAGIC: u32 = 0x9889_7667;
const STATE_CLEAR_DATA_VERSION: u16 = 2;
pub(in crate::library::tpm2) const PCR_SAVE_MAGIC: u32 = 0x7372_eabc;
const PCR_SAVE_VERSION: u16 = 2;
pub(in crate::library::tpm2) const PCR_AUTHVALUE_MAGIC: u32 = 0x6be8_2eaf;
const PCR_AUTHVALUE_VERSION: u16 = 2;

const DIGEST_SIZE: usize = 64;
pub(in crate::library::tpm2) const NUM_STATIC_PCR: usize = 16;
pub(in crate::library::tpm2) const NUM_AUTHVALUE_PCR_GROUP: usize = 1;

const TPM_ALG_SHA1: u16 = 0x0004;
const TPM_ALG_SHA256: u16 = 0x000b;
const TPM_ALG_SHA384: u16 = 0x000c;
const TPM_ALG_SHA512: u16 = 0x000d;
const TPM_ALG_NULL: u16 = 0x0010;

pub(in crate::library::tpm2) const PCR_BANKS: [(u16, usize); 4] = [
    (TPM_ALG_SHA1, NUM_STATIC_PCR * 20),
    (TPM_ALG_SHA256, NUM_STATIC_PCR * 32),
    (TPM_ALG_SHA384, NUM_STATIC_PCR * 48),
    (TPM_ALG_SHA512, NUM_STATIC_PCR * 64),
];

const BLOCK_SKIP_SINCE_VERSION: u16 = 2;

const SECTION: StateSection = StateSection::StateClearData;

fn truncated(section: StateSection) -> PersistentAllError {
    PersistentAllError::Truncated { section }
}

fn read_tpm2b<'a>(
    reader: &mut BlobReader<'a>,
    section: StateSection,
    field: PersistentField,
    maximum: usize,
) -> Result<&'a [u8], PersistentAllError> {
    reader.read_tpm2b(maximum).map_err(|error| match error {
        Tpm2bError::Truncated => truncated(section),
        Tpm2bError::SizeExceeded { actual, maximum } => PersistentAllError::Tpm2bSizeExceeded {
            section,
            field,
            actual,
            maximum,
        },
    })
}

fn skip_future_block(
    reader: &mut BlobReader<'_>,
    section: StateSection,
) -> Result<(), PersistentAllError> {
    skip_optional_block(reader, false)
        .map_err(|error| match error {
            BlockSkipError::Truncated => truncated(section),
            BlockSkipError::MissingRequiredBlock => {
                PersistentAllError::MissingRequiredBlock { section }
            }
        })
        .map(|_| ())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) struct PcrBank<'a> {
    pub(in crate::library::tpm2) hash_alg: u16,
    pub(in crate::library::tpm2) pcrs: &'a [u8],
}

#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::library::tpm2) struct PcrSave<'a> {
    pub(in crate::library::tpm2) banks: [Option<PcrBank<'a>>; PCR_BANKS.len()],
}

#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::library::tpm2) struct StateClearData<'a> {
    pub(in crate::library::tpm2) sh_enable: bool,
    pub(in crate::library::tpm2) eh_enable: bool,
    pub(in crate::library::tpm2) ph_enable_nv: bool,
    pub(in crate::library::tpm2) platform_alg: u16,
    pub(in crate::library::tpm2) platform_policy: &'a [u8],
    pub(in crate::library::tpm2) platform_auth: &'a [u8],
    pub(in crate::library::tpm2) pcr_save: PcrSave<'a>,
    pub(in crate::library::tpm2) pcr_auth_values: [&'a [u8]; NUM_AUTHVALUE_PCR_GROUP],
    pub(in crate::library::tpm2) remaining: &'a [u8],
}

impl core::fmt::Debug for StateClearData<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StateClearData")
            .field("sh_enable", &self.sh_enable)
            .field("eh_enable", &self.eh_enable)
            .field("ph_enable_nv", &self.ph_enable_nv)
            .field("platform_alg", &self.platform_alg)
            .field("platform_auth_len", &self.platform_auth.len())
            .finish_non_exhaustive()
    }
}

pub(in crate::library::tpm2) fn algs_active(shadow: &[PcrSelection<'_>]) -> u64 {
    let mut active = 0u64;
    for selection in shadow {
        if selection.select.iter().any(|&byte| byte != 0) && selection.hash_alg < 64 {
            active |= 1u64 << selection.hash_alg;
        }
    }
    active
}

fn parse_pcr_save<'a>(
    reader: &mut BlobReader<'a>,
    shadow: &[PcrSelection<'_>],
) -> Result<PcrSave<'a>, PersistentAllError> {
    const SECTION: StateSection = StateSection::PcrSave;

    let header = parse_nv_header(reader, SECTION, PCR_SAVE_MAGIC, PCR_SAVE_VERSION)?;

    let declared = reader.read_u16().map_err(|_| truncated(SECTION))?;
    if usize::from(declared) != NUM_STATIC_PCR {
        return Err(PersistentAllError::ArraySizeMismatch {
            section: SECTION,
            declared,
            expected: NUM_STATIC_PCR,
        });
    }

    let mut algs_needed = algs_active(shadow);
    let mut banks = [None; PCR_BANKS.len()];
    loop {
        let alg = reader.read_u16().map_err(|_| truncated(SECTION))?;
        if alg == TPM_ALG_NULL {
            break;
        }
        let Some(index) = PCR_BANKS.iter().position(|&(bank_alg, _)| bank_alg == alg) else {
            return Err(PersistentAllError::UnsupportedPcrBank { actual: alg });
        };
        algs_needed &= !(1u64 << alg);
        let expected = PCR_BANKS[index].1;
        let declared = reader.read_u16().map_err(|_| truncated(SECTION))?;
        if usize::from(declared) != expected {
            return Err(PersistentAllError::ArraySizeInvalid {
                section: SECTION,
                declared,
                expected,
            });
        }
        let pcrs = reader.take(expected).map_err(|_| truncated(SECTION))?;
        banks[index] = Some(PcrBank {
            hash_alg: alg,
            pcrs,
        });
    }

    if algs_needed != 0 {
        let algorithm = algs_needed.trailing_zeros() as u16;
        return Err(PersistentAllError::MissingPcrBank { algorithm });
    }

    if header.version >= BLOCK_SKIP_SINCE_VERSION {
        skip_future_block(reader, SECTION)?;
    }
    Ok(PcrSave { banks })
}

fn parse_pcr_auth_values<'a>(
    reader: &mut BlobReader<'a>,
) -> Result<[&'a [u8]; NUM_AUTHVALUE_PCR_GROUP], PersistentAllError> {
    const SECTION: StateSection = StateSection::PcrAuthValue;

    let header = parse_nv_header(reader, SECTION, PCR_AUTHVALUE_MAGIC, PCR_AUTHVALUE_VERSION)?;

    let declared = reader.read_u16().map_err(|_| truncated(SECTION))?;
    if usize::from(declared) != NUM_AUTHVALUE_PCR_GROUP {
        return Err(PersistentAllError::ArraySizeInvalid {
            section: SECTION,
            declared,
            expected: NUM_AUTHVALUE_PCR_GROUP,
        });
    }
    let mut auth_values = [&[] as &[u8]; NUM_AUTHVALUE_PCR_GROUP];
    for value in &mut auth_values {
        *value = read_tpm2b(reader, SECTION, PersistentField::PcrAuthValue, DIGEST_SIZE)?;
    }

    if header.version >= BLOCK_SKIP_SINCE_VERSION {
        skip_future_block(reader, SECTION)?;
    }
    Ok(auth_values)
}

pub(in crate::library::tpm2) fn parse_state_clear_data<'a>(
    input: &'a [u8],
    shadow: &[PcrSelection<'_>],
) -> Result<StateClearData<'a>, PersistentAllError> {
    use PersistentField as F;
    let mut reader = BlobReader::new(input);

    let header = parse_nv_header(
        &mut reader,
        SECTION,
        STATE_CLEAR_DATA_MAGIC,
        STATE_CLEAR_DATA_VERSION,
    )?;

    let sh_enable = reader.read_bool().map_err(|_| truncated(SECTION))?;
    let eh_enable = reader.read_bool().map_err(|_| truncated(SECTION))?;
    let ph_enable_nv = reader.read_bool().map_err(|_| truncated(SECTION))?;
    let platform_alg = reader.read_u16().map_err(|_| truncated(SECTION))?;
    let platform_policy = read_tpm2b(&mut reader, SECTION, F::PlatformPolicy, DIGEST_SIZE)?;
    let platform_auth = read_tpm2b(&mut reader, SECTION, F::PlatformAuth, DIGEST_SIZE)?;
    let pcr_save = parse_pcr_save(&mut reader, shadow)?;
    let pcr_auth_values = parse_pcr_auth_values(&mut reader)?;

    if header.version >= BLOCK_SKIP_SINCE_VERSION {
        skip_future_block(&mut reader, SECTION)?;
    }

    Ok(StateClearData {
        sh_enable,
        eh_enable,
        ph_enable_nv,
        platform_alg,
        platform_policy,
        platform_auth,
        pcr_save,
        pcr_auth_values,
        remaining: reader.remaining(),
    })
}

#[cfg(test)]
pub(in crate::library::tpm2) struct PcrSaveFixture {
    pub(in crate::library::tpm2) version: u16,
    pub(in crate::library::tpm2) magic: u32,
    pub(in crate::library::tpm2) num_static_pcr: u16,
    pub(in crate::library::tpm2) banks: Vec<(u16, u16, Vec<u8>)>,
    pub(in crate::library::tpm2) end_marker: Option<u16>,
    pub(in crate::library::tpm2) future_block: Option<(u8, u16, Vec<u8>)>,
}

#[cfg(test)]
impl Default for PcrSaveFixture {
    fn default() -> Self {
        Self {
            version: PCR_SAVE_VERSION,
            magic: PCR_SAVE_MAGIC,
            num_static_pcr: NUM_STATIC_PCR as u16,
            banks: PCR_BANKS
                .iter()
                .map(|&(alg, size)| (alg, size as u16, vec![0u8; size]))
                .collect(),
            end_marker: Some(TPM_ALG_NULL),
            future_block: Some((1, 0, Vec::new())),
        }
    }
}

#[cfg(test)]
impl PcrSaveFixture {
    pub(in crate::library::tpm2) fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.magic.to_be_bytes());
        if self.version >= 2 {
            out.extend_from_slice(&1u16.to_be_bytes());
        }
        out.extend_from_slice(&self.num_static_pcr.to_be_bytes());
        for (alg, size, contents) in &self.banks {
            out.extend_from_slice(&alg.to_be_bytes());
            out.extend_from_slice(&size.to_be_bytes());
            out.extend_from_slice(contents);
        }
        if let Some(end) = self.end_marker {
            out.extend_from_slice(&end.to_be_bytes());
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
pub(in crate::library::tpm2) struct PcrAuthValueFixture {
    pub(in crate::library::tpm2) version: u16,
    pub(in crate::library::tpm2) magic: u32,
    pub(in crate::library::tpm2) count: u16,
    pub(in crate::library::tpm2) auth_values: Vec<Vec<u8>>,
    pub(in crate::library::tpm2) future_block: Option<(u8, u16, Vec<u8>)>,
}

#[cfg(test)]
impl Default for PcrAuthValueFixture {
    fn default() -> Self {
        Self {
            version: PCR_AUTHVALUE_VERSION,
            magic: PCR_AUTHVALUE_MAGIC,
            count: NUM_AUTHVALUE_PCR_GROUP as u16,
            auth_values: vec![Vec::new(); NUM_AUTHVALUE_PCR_GROUP],
            future_block: Some((1, 0, Vec::new())),
        }
    }
}

#[cfg(test)]
impl PcrAuthValueFixture {
    pub(in crate::library::tpm2) fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.magic.to_be_bytes());
        if self.version >= 2 {
            out.extend_from_slice(&1u16.to_be_bytes());
        }
        out.extend_from_slice(&self.count.to_be_bytes());
        for value in &self.auth_values {
            out.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
            out.extend_from_slice(value);
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
pub(in crate::library::tpm2) struct StateClearFixture {
    pub(in crate::library::tpm2) version: u16,
    pub(in crate::library::tpm2) magic: u32,
    pub(in crate::library::tpm2) sh_enable: u8,
    pub(in crate::library::tpm2) eh_enable: u8,
    pub(in crate::library::tpm2) ph_enable_nv: u8,
    pub(in crate::library::tpm2) platform_alg: u16,
    pub(in crate::library::tpm2) platform_policy: Vec<u8>,
    pub(in crate::library::tpm2) platform_auth: Vec<u8>,
    pub(in crate::library::tpm2) pcr_save: Vec<u8>,
    pub(in crate::library::tpm2) pcr_auth_values: Vec<u8>,
    pub(in crate::library::tpm2) future_block: Option<(u8, u16, Vec<u8>)>,
    pub(in crate::library::tpm2) tail: Vec<u8>,
}

#[cfg(test)]
impl Default for StateClearFixture {
    fn default() -> Self {
        Self {
            version: STATE_CLEAR_DATA_VERSION,
            magic: STATE_CLEAR_DATA_MAGIC,
            sh_enable: 1,
            eh_enable: 1,
            ph_enable_nv: 1,
            platform_alg: 0x0010,
            platform_policy: Vec::new(),
            platform_auth: Vec::new(),
            pcr_save: PcrSaveFixture::default().bytes(),
            pcr_auth_values: PcrAuthValueFixture::default().bytes(),
            future_block: Some((1, 0, Vec::new())),
            tail: Vec::new(),
        }
    }
}

#[cfg(test)]
impl StateClearFixture {
    pub(in crate::library::tpm2) fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.magic.to_be_bytes());
        if self.version >= 2 {
            out.extend_from_slice(&1u16.to_be_bytes());
        }
        out.push(self.sh_enable);
        out.push(self.eh_enable);
        out.push(self.ph_enable_nv);
        out.extend_from_slice(&self.platform_alg.to_be_bytes());
        out.extend_from_slice(
            &u16::try_from(self.platform_policy.len())
                .unwrap()
                .to_be_bytes(),
        );
        out.extend_from_slice(&self.platform_policy);
        out.extend_from_slice(
            &u16::try_from(self.platform_auth.len())
                .unwrap()
                .to_be_bytes(),
        );
        out.extend_from_slice(&self.platform_auth);
        out.extend_from_slice(&self.pcr_save);
        out.extend_from_slice(&self.pcr_auth_values);
        if self.version >= 2
            && let Some((has_block, size, payload)) = &self.future_block
        {
            out.push(*has_block);
            out.extend_from_slice(&size.to_be_bytes());
            out.extend_from_slice(payload);
        }
        out.extend_from_slice(&self.tail);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::constants::{
        TPM_RC_BAD_PARAMETER, TPM_RC_BAD_TAG, TPM_RC_INSUFFICIENT, TPM_RC_SIZE,
    };

    const SENTINEL: [u8; 3] = [0xd1, 0xd2, 0xd3];

    fn no_shadow() -> Vec<PcrSelection<'static>> {
        Vec::new()
    }

    fn parse<'a>(
        input: &'a [u8],
        shadow: &[PcrSelection<'_>],
    ) -> Result<StateClearData<'a>, PersistentAllError> {
        parse_state_clear_data(input, shadow)
    }

    fn with_tail() -> StateClearFixture {
        StateClearFixture {
            tail: SENTINEL.to_vec(),
            ..StateClearFixture::default()
        }
    }

    #[test]
    fn current_writer_fixture_decodes_every_field() {
        let data = StateClearFixture {
            sh_enable: 1,
            eh_enable: 0,
            ph_enable_nv: 0xff,
            platform_alg: 0x000b,
            platform_policy: vec![0x11; 32],
            platform_auth: vec![0x22; 20],
            tail: SENTINEL.to_vec(),
            ..StateClearFixture::default()
        }
        .bytes();
        let parsed = parse(&data, &no_shadow()).unwrap();
        assert!(parsed.sh_enable);
        assert!(!parsed.eh_enable);
        assert!(parsed.ph_enable_nv);
        assert_eq!(parsed.platform_alg, 0x000b);
        assert_eq!(parsed.platform_policy, &[0x11; 32]);
        assert_eq!(parsed.platform_auth, &[0x22; 20]);
        for (index, &(alg, size)) in PCR_BANKS.iter().enumerate() {
            let bank = parsed.pcr_save.banks[index].expect("bank present");
            assert_eq!(bank.hash_alg, alg);
            assert_eq!(bank.pcrs.len(), size);
        }
        assert_eq!(parsed.pcr_auth_values, [&[] as &[u8]]);
        assert_eq!(parsed.remaining, &SENTINEL);
    }

    #[test]
    fn platform_alg_is_raw_and_never_validated() {
        for alg in [0x0000u16, 0x0012, 0xffff] {
            let data = StateClearFixture {
                platform_alg: alg,
                ..with_tail()
            }
            .bytes();
            assert_eq!(
                parse(&data, &no_shadow()).unwrap().platform_alg,
                alg,
                "alg {alg:#06x}"
            );
        }
    }

    #[test]
    fn subset_of_banks_parses_when_shadow_needs_none() {
        let pcr_save = PcrSaveFixture {
            banks: vec![(TPM_ALG_SHA256, 512, vec![0xaa; 512])],
            ..PcrSaveFixture::default()
        }
        .bytes();
        let data = StateClearFixture {
            pcr_save,
            ..with_tail()
        }
        .bytes();
        let parsed = parse(&data, &no_shadow()).unwrap();
        assert!(parsed.pcr_save.banks[0].is_none());
        assert_eq!(parsed.pcr_save.banks[1].unwrap().pcrs, &[0xaa; 512][..]);
        assert_eq!(parsed.remaining, &SENTINEL);
    }

    #[test]
    fn missing_shadow_active_bank_is_bad_parameter() {
        let shadow = vec![PcrSelection {
            hash_alg: 0x000c,
            select: &[0x01, 0x00, 0x00],
        }];
        let pcr_save = PcrSaveFixture {
            banks: vec![(TPM_ALG_SHA256, 512, vec![0x00; 512])],
            ..PcrSaveFixture::default()
        }
        .bytes();
        let data = StateClearFixture {
            pcr_save,
            ..StateClearFixture::default()
        }
        .bytes();
        let error = parse(&data, &shadow).unwrap_err();
        assert_eq!(
            error,
            PersistentAllError::MissingPcrBank { algorithm: 0x000c }
        );
        assert_eq!(error.tpm_result(), TPM_RC_BAD_PARAMETER);
    }

    #[test]
    fn shadow_selection_with_all_zero_bitmap_needs_no_bank() {
        let shadow = vec![PcrSelection {
            hash_alg: 0x000c,
            select: &[0x00, 0x00, 0x00],
        }];
        let pcr_save = PcrSaveFixture {
            banks: Vec::new(),
            ..PcrSaveFixture::default()
        }
        .bytes();
        let data = StateClearFixture {
            pcr_save,
            ..with_tail()
        }
        .bytes();
        assert!(parse(&data, &shadow).is_ok());
    }

    #[test]
    fn unsupported_bank_algorithm_is_bad_parameter() {
        for alg in [0x0000u16, 0x0012, 0xffff] {
            let pcr_save = PcrSaveFixture {
                banks: vec![(alg, 4, vec![0x00; 4])],
                ..PcrSaveFixture::default()
            }
            .bytes();
            let data = StateClearFixture {
                pcr_save,
                ..StateClearFixture::default()
            }
            .bytes();
            let error = parse(&data, &no_shadow()).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::UnsupportedPcrBank { actual: alg },
                "alg {alg:#06x}"
            );
        }
    }

    #[test]
    fn wrong_bank_size_is_bad_parameter() {
        for size in [0u16, 511, 513] {
            let pcr_save = PcrSaveFixture {
                banks: vec![(TPM_ALG_SHA256, size, vec![0x00; usize::from(size)])],
                ..PcrSaveFixture::default()
            }
            .bytes();
            let data = StateClearFixture {
                pcr_save,
                ..StateClearFixture::default()
            }
            .bytes();
            let error = parse(&data, &no_shadow()).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::ArraySizeInvalid {
                    section: StateSection::PcrSave,
                    declared: size,
                    expected: 512,
                },
                "size {size}"
            );
        }
    }

    #[test]
    fn wrong_num_static_pcr_is_a_size_error() {
        let pcr_save = PcrSaveFixture {
            num_static_pcr: 24,
            ..PcrSaveFixture::default()
        }
        .bytes();
        let data = StateClearFixture {
            pcr_save,
            ..StateClearFixture::default()
        }
        .bytes();
        let error = parse(&data, &no_shadow()).unwrap_err();
        assert_eq!(
            error,
            PersistentAllError::ArraySizeMismatch {
                section: StateSection::PcrSave,
                declared: 24,
                expected: NUM_STATIC_PCR,
            }
        );
        assert_eq!(error.tpm_result(), TPM_RC_SIZE);
    }

    #[test]
    fn missing_end_marker_is_reported_as_truncation() {
        let pcr_save = PcrSaveFixture {
            end_marker: None,
            future_block: None,
            ..PcrSaveFixture::default()
        }
        .bytes();
        let data = StateClearFixture {
            pcr_save,
            pcr_auth_values: Vec::new(),
            future_block: None,
            ..StateClearFixture::default()
        }
        .bytes();
        let error = parse(&data, &no_shadow()).unwrap_err();
        assert_eq!(error.tpm_result(), TPM_RC_INSUFFICIENT);
    }

    #[test]
    fn wrong_pcr_authvalue_count_is_bad_parameter() {
        for count in [0u16, 2, u16::MAX] {
            let pcr_auth_values = PcrAuthValueFixture {
                count,
                ..PcrAuthValueFixture::default()
            }
            .bytes();
            let data = StateClearFixture {
                pcr_auth_values,
                ..StateClearFixture::default()
            }
            .bytes();
            let error = parse(&data, &no_shadow()).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::ArraySizeInvalid {
                    section: StateSection::PcrAuthValue,
                    declared: count,
                    expected: NUM_AUTHVALUE_PCR_GROUP,
                },
                "count {count}"
            );
        }
    }

    #[test]
    fn oversized_platform_tpm2bs_are_size_errors() {
        for (fixture, field) in [
            (
                StateClearFixture {
                    platform_policy: vec![0; DIGEST_SIZE + 1],
                    ..StateClearFixture::default()
                },
                PersistentField::PlatformPolicy,
            ),
            (
                StateClearFixture {
                    platform_auth: vec![0; DIGEST_SIZE + 1],
                    ..StateClearFixture::default()
                },
                PersistentField::PlatformAuth,
            ),
        ] {
            let error = parse(&fixture.bytes(), &no_shadow()).unwrap_err();
            assert!(
                matches!(
                    error,
                    PersistentAllError::Tpm2bSizeExceeded { field: f, .. } if f == field
                ),
                "{field:?}: {error:?}"
            );
        }
    }

    #[test]
    fn nested_section_magic_errors_carry_their_own_identity() {
        let mut pcr_save = PcrSaveFixture::default().bytes();
        pcr_save[2] = 0x00;
        let data = StateClearFixture {
            pcr_save,
            ..StateClearFixture::default()
        }
        .bytes();
        let error = parse(&data, &no_shadow()).unwrap_err();
        assert!(matches!(
            error,
            PersistentAllError::InvalidHeaderMagic {
                section: StateSection::PcrSave,
                ..
            }
        ));
        assert_eq!(error.tpm_result(), TPM_RC_BAD_TAG);

        let mut pcr_auth_values = PcrAuthValueFixture::default().bytes();
        pcr_auth_values[2] = 0x00;
        let data = StateClearFixture {
            pcr_auth_values,
            ..StateClearFixture::default()
        }
        .bytes();
        let error = parse(&data, &no_shadow()).unwrap_err();
        assert!(matches!(
            error,
            PersistentAllError::InvalidHeaderMagic {
                section: StateSection::PcrAuthValue,
                ..
            }
        ));
    }

    #[test]
    fn every_strict_prefix_fails_safely() {
        let full = StateClearFixture::default().bytes();
        for len in 0..full.len() {
            let error = parse(&full[..len], &no_shadow()).unwrap_err();
            assert_eq!(
                error.tpm_result(),
                TPM_RC_INSUFFICIENT,
                "prefix length {len} of {}",
                full.len()
            );
        }
        assert!(parse(&full, &no_shadow()).is_ok());
    }

    #[test]
    fn state_clear_byte_mutations_do_not_panic() {
        let full = StateClearFixture::default().bytes();
        for index in 0..full.len() {
            for byte in [0x00u8, 0x01, 0xff] {
                let mut data = full.clone();
                data[index] = byte;
                let _ = parse(&data, &no_shadow());
            }
        }
    }
}
