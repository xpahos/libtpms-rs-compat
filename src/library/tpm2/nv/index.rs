use crate::library::tpm2::marshal::{BlobReader, BlockSkipError, skip_optional_block};
use crate::library::tpm2::persistent::{
    PersistentAllError, PersistentField, StateSection, parse_nv_header,
};
use crate::library::tpm2::public::{DIGEST_SIZE, read_hash_alg, read_tpm2b};

use super::attributes::TPMA_NV_RESERVED;
use super::public_area::{NV_INDEX_FIRST, NV_INDEX_LAST};

pub(in crate::library::tpm2) const NV_INDEX_MAGIC: u32 = 0x2547_265a;
const NV_INDEX_VERSION: u16 = 2;

pub(in crate::library::tpm2) const MAX_NV_INDEX_SIZE: u32 = 2048;

const BLOCK_SKIP_SINCE_VERSION: u16 = 2;

const SECTION: StateSection = StateSection::NvIndex;

fn truncated() -> PersistentAllError {
    PersistentAllError::Truncated { section: SECTION }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::library::tpm2) struct NvIndex<'a> {
    pub(in crate::library::tpm2) nv_index: u32,
    pub(in crate::library::tpm2) name_alg: u16,
    pub(in crate::library::tpm2) attributes: u32,
    pub(in crate::library::tpm2) auth_policy: &'a [u8],
    pub(in crate::library::tpm2) data_size: u16,
    pub(in crate::library::tpm2) auth_value: &'a [u8],
}

impl core::fmt::Debug for NvIndex<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NvIndex")
            .field("nv_index", &format_args!("{:#010x}", self.nv_index))
            .field("name_alg", &self.name_alg)
            .field("attributes", &format_args!("{:#010x}", self.attributes))
            .field("data_size", &self.data_size)
            .field("auth_value_len", &self.auth_value.len())
            .finish_non_exhaustive()
    }
}

pub(in crate::library::tpm2) fn parse_nv_index<'a>(
    reader: &mut BlobReader<'a>,
) -> Result<NvIndex<'a>, PersistentAllError> {
    let header = parse_nv_header(reader, SECTION, NV_INDEX_MAGIC, NV_INDEX_VERSION)?;

    let nv_index = reader.read_u32().map_err(|_| truncated())?;
    if !(NV_INDEX_FIRST..=NV_INDEX_LAST).contains(&nv_index) {
        return Err(PersistentAllError::InvalidHandleValue {
            section: SECTION,
            actual: nv_index,
        });
    }
    let name_alg = read_hash_alg(reader, SECTION, false)?;
    let attributes = reader.read_u32().map_err(|_| truncated())?;
    if attributes & TPMA_NV_RESERVED != 0 {
        return Err(PersistentAllError::ReservedBitsSet {
            section: SECTION,
            actual: attributes,
        });
    }
    let auth_policy = read_tpm2b(reader, SECTION, PersistentField::NvAuthPolicy, DIGEST_SIZE)?;
    let data_size = reader.read_u16().map_err(|_| truncated())?;
    if u32::from(data_size) > MAX_NV_INDEX_SIZE {
        return Err(PersistentAllError::NvDataSizeExceeded {
            actual: u32::from(data_size),
            maximum: MAX_NV_INDEX_SIZE,
        });
    }
    let auth_value = read_tpm2b(reader, SECTION, PersistentField::NvAuthValue, DIGEST_SIZE)?;

    if header.version >= BLOCK_SKIP_SINCE_VERSION {
        skip_optional_block(reader, false).map_err(|error| match error {
            BlockSkipError::Truncated => truncated(),
            BlockSkipError::MissingRequiredBlock => {
                PersistentAllError::MissingRequiredBlock { section: SECTION }
            }
        })?;
    }

    Ok(NvIndex {
        nv_index,
        name_alg,
        attributes,
        auth_policy,
        data_size,
        auth_value,
    })
}

#[cfg(test)]
pub(in crate::library::tpm2) struct NvIndexFixture {
    pub(in crate::library::tpm2) version: u16,
    pub(in crate::library::tpm2) magic: u32,
    pub(in crate::library::tpm2) nv_index: u32,
    pub(in crate::library::tpm2) name_alg: u16,
    pub(in crate::library::tpm2) attributes: u32,
    pub(in crate::library::tpm2) auth_policy: Vec<u8>,
    pub(in crate::library::tpm2) data_size: u16,
    pub(in crate::library::tpm2) auth_value: Vec<u8>,
    pub(in crate::library::tpm2) future_block: Option<(u8, u16, Vec<u8>)>,
}

#[cfg(test)]
impl Default for NvIndexFixture {
    fn default() -> Self {
        Self {
            version: NV_INDEX_VERSION,
            magic: NV_INDEX_MAGIC,
            nv_index: 0x0100_0001,
            name_alg: 0x000b,
            attributes: 0x0004_0002,
            auth_policy: Vec::new(),
            data_size: 8,
            auth_value: Vec::new(),
            future_block: Some((1, 0, Vec::new())),
        }
    }
}

#[cfg(test)]
impl NvIndexFixture {
    pub(in crate::library::tpm2) fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.magic.to_be_bytes());
        if self.version >= 2 {
            out.extend_from_slice(&1u16.to_be_bytes());
        }
        out.extend_from_slice(&self.nv_index.to_be_bytes());
        out.extend_from_slice(&self.name_alg.to_be_bytes());
        out.extend_from_slice(&self.attributes.to_be_bytes());
        out.extend_from_slice(&u16::try_from(self.auth_policy.len()).unwrap().to_be_bytes());
        out.extend_from_slice(&self.auth_policy);
        out.extend_from_slice(&self.data_size.to_be_bytes());
        out.extend_from_slice(&u16::try_from(self.auth_value.len()).unwrap().to_be_bytes());
        out.extend_from_slice(&self.auth_value);
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
    use crate::library::constants::{
        TPM_RC_HASH, TPM_RC_INSUFFICIENT, TPM_RC_RESERVED_BITS, TPM_RC_SIZE, TPM_RC_VALUE,
    };

    fn parse(data: &[u8]) -> Result<NvIndex<'_>, PersistentAllError> {
        let mut reader = BlobReader::new(data);
        let index = parse_nv_index(&mut reader)?;
        assert_eq!(reader.remaining(), &[] as &[u8], "exact consumption");
        Ok(index)
    }

    #[test]
    fn default_fixture_decodes() {
        let data = NvIndexFixture {
            auth_policy: vec![0x11; 32],
            auth_value: vec![0x22; 20],
            ..NvIndexFixture::default()
        }
        .bytes();
        let index = parse(&data).unwrap();
        assert_eq!(index.nv_index, 0x0100_0001);
        assert_eq!(index.name_alg, 0x000b);
        assert_eq!(index.attributes, 0x0004_0002);
        assert_eq!(index.auth_policy, &[0x11; 32]);
        assert_eq!(index.data_size, 8);
        assert_eq!(index.auth_value, &[0x22; 20]);
    }

    #[test]
    fn out_of_range_handles_are_rc_value() {
        for handle in [0x0000_0001u32, 0x00ff_ffff, 0x0200_0000, 0x8100_0000] {
            let data = NvIndexFixture {
                nv_index: handle,
                ..NvIndexFixture::default()
            }
            .bytes();
            let error = parse(&data).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::InvalidHandleValue {
                    section: StateSection::NvIndex,
                    actual: handle,
                },
                "handle {handle:#010x}"
            );
            assert_eq!(error.tpm_result(), TPM_RC_VALUE);
        }
        for handle in [NV_INDEX_FIRST, NV_INDEX_LAST] {
            let data = NvIndexFixture {
                nv_index: handle,
                ..NvIndexFixture::default()
            }
            .bytes();
            assert!(parse(&data).is_ok(), "handle {handle:#010x}");
        }
    }

    #[test]
    fn invalid_name_alg_is_rc_hash() {
        for alg in [0x0000u16, 0x0010, 0x0012, 0xffff] {
            let data = NvIndexFixture {
                name_alg: alg,
                ..NvIndexFixture::default()
            }
            .bytes();
            let error = parse(&data).unwrap_err();
            assert_eq!(error.tpm_result(), TPM_RC_HASH, "alg {alg:#06x}");
        }
    }

    #[test]
    fn reserved_attribute_bits_are_rejected() {
        let data = NvIndexFixture {
            attributes: 0x0010_0000,
            ..NvIndexFixture::default()
        }
        .bytes();
        let error = parse(&data).unwrap_err();
        assert_eq!(error.tpm_result(), TPM_RC_RESERVED_BITS);
    }

    #[test]
    fn oversized_data_size_is_rc_size() {
        for size in [2049u16, u16::MAX] {
            let data = NvIndexFixture {
                data_size: size,
                ..NvIndexFixture::default()
            }
            .bytes();
            let error = parse(&data).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::NvDataSizeExceeded {
                    actual: u32::from(size),
                    maximum: MAX_NV_INDEX_SIZE,
                },
                "size {size}"
            );
            assert_eq!(error.tpm_result(), TPM_RC_SIZE);
        }
        let data = NvIndexFixture {
            data_size: 2048,
            ..NvIndexFixture::default()
        }
        .bytes();
        assert!(parse(&data).is_ok());
    }

    #[test]
    fn truncation_at_every_boundary_is_insufficient() {
        let full = NvIndexFixture {
            auth_policy: vec![0x33; 8],
            auth_value: vec![0x44; 8],
            ..NvIndexFixture::default()
        }
        .bytes();
        for len in 0..full.len() {
            let mut reader = BlobReader::new(&full[..len]);
            let error = parse_nv_index(&mut reader).unwrap_err();
            assert_eq!(
                error.tpm_result(),
                TPM_RC_INSUFFICIENT,
                "prefix length {len} of {}",
                full.len()
            );
        }
    }

    #[test]
    fn index_entry_byte_mutations_do_not_panic() {
        let full = NvIndexFixture::default().bytes();
        for index in 0..full.len() {
            for byte in [0x00u8, 0x01, 0xff] {
                let mut data = full.clone();
                data[index] = byte;
                let mut reader = BlobReader::new(&data);
                let _ = parse_nv_index(&mut reader);
            }
        }
    }
}
