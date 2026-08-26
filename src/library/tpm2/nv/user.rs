use super::index::{NvIndex, parse_nv_index};
use crate::library::tpm2::marshal::{BlobReader, BlockSkipError, skip_optional_block};
use crate::library::tpm2::object::{AnyObject, parse_any_object};
use crate::library::tpm2::persistent::{PersistentAllError, StateSection, parse_nv_header};
use crate::library::tpm2::profile::PersistentObjectFormat;
use crate::library::tpm2::public::{
    StateFormatLimit, TPM_ALG_ECC, TPM_ALG_KEYEDHASH, TPM_ALG_RSA, TPM_ALG_SYMCIPHER,
};

pub(in crate::library::tpm2) const USER_NVRAM_MAGIC: u32 = 0x094f_22c3;
const USER_NVRAM_VERSION: u16 = 2;

pub(in crate::library::tpm2) const USER_NVRAM_CAPACITY: u64 = 171_200;

pub(in crate::library::tpm2) const SIZEOF_NV_INDEX: u64 = 148;
pub(in crate::library::tpm2) const SIZEOF_OBJECT: u64 = 2608;
pub(in crate::library::tpm2) const SIZEOF_RSA3072_OBJECT: u64 = 2600;

const MAX_NV_INDEX_DATA: u32 = 0x10000 + 0x100;

const TPM_HT_NV_INDEX: u32 = 0x01;
const TPM_HT_PERSISTENT: u32 = 0x81;

const BLOCK_SKIP_SINCE_VERSION: u16 = 2;

const SECTION: StateSection = StateSection::UserNvram;

fn truncated() -> PersistentAllError {
    PersistentAllError::Truncated { section: SECTION }
}

fn capacity_exceeded(needed: u64) -> PersistentAllError {
    PersistentAllError::DestinationCapacityExceeded {
        section: SECTION,
        needed,
        capacity: USER_NVRAM_CAPACITY,
    }
}

#[allow(dead_code)]
pub(in crate::library::tpm2) enum UserNvramEntry<'a> {
    NvIndex {
        declared_entry_size: u32,
        handle: u32,
        index: NvIndex<'a>,
        data: &'a [u8],
    },
    Persistent {
        declared_entry_size: u32,
        handle: u32,
        object: AnyObject<'a>,
        object_destination_size: u64,
    },
}

impl UserNvramEntry<'_> {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(in crate::library::tpm2) fn destination_size(&self) -> u64 {
        match self {
            Self::NvIndex { data, .. } => 4 + SIZEOF_NV_INDEX + data.len() as u64,
            Self::Persistent {
                object_destination_size,
                ..
            } => 4 + 4 + object_destination_size,
        }
    }
}

impl core::fmt::Debug for UserNvramEntry<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NvIndex { handle, data, .. } => f
                .debug_struct("NvIndex")
                .field("handle", &format_args!("{handle:#010x}"))
                .field("data_len", &data.len())
                .finish_non_exhaustive(),
            Self::Persistent {
                handle,
                object_destination_size,
                ..
            } => f
                .debug_struct("Persistent")
                .field("handle", &format_args!("{handle:#010x}"))
                .field("object_destination_size", object_destination_size)
                .finish_non_exhaustive(),
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub(in crate::library::tpm2) struct UserNvram<'a> {
    pub(in crate::library::tpm2) sourceside_size: u64,
    pub(in crate::library::tpm2) entries: Vec<UserNvramEntry<'a>>,
    pub(in crate::library::tpm2) max_count: u64,
    pub(in crate::library::tpm2) required_capacity: u64,
    pub(in crate::library::tpm2) remaining: &'a [u8],
}

pub(in crate::library::tpm2) fn parse_user_nvram(
    input: &[u8],
    object_format: PersistentObjectFormat,
    state_format: StateFormatLimit,
) -> Result<UserNvram<'_>, PersistentAllError> {
    let mut reader = BlobReader::new(input);

    let header = parse_nv_header(&mut reader, SECTION, USER_NVRAM_MAGIC, USER_NVRAM_VERSION)?;
    let sourceside_size = reader.read_u64().map_err(|_| truncated())?;

    let mut entries = Vec::new();
    let mut o: u64 = 0;
    loop {
        if o + 4 > USER_NVRAM_CAPACITY {
            return Err(capacity_exceeded(o + 4));
        }
        let declared_entry_size = reader.read_u32().map_err(|_| truncated())?;
        if declared_entry_size == 0 {
            break;
        }
        let handle = reader.read_u32().map_err(|_| truncated())?;
        let offset: u64 = 4;
        match handle >> 24 {
            TPM_HT_NV_INDEX => {
                if o + offset + SIZEOF_NV_INDEX > USER_NVRAM_CAPACITY {
                    return Err(capacity_exceeded(o + offset + SIZEOF_NV_INDEX));
                }
                let index = parse_nv_index(&mut reader)?;
                let datasize = reader.read_u32().map_err(|_| truncated())?;
                if datasize > MAX_NV_INDEX_DATA {
                    return Err(PersistentAllError::NvDataSizeExceeded {
                        actual: datasize,
                        maximum: MAX_NV_INDEX_DATA,
                    });
                }
                let needed = o + offset + SIZEOF_NV_INDEX + u64::from(datasize);
                if needed > USER_NVRAM_CAPACITY {
                    return Err(capacity_exceeded(needed));
                }
                let data = reader.take(datasize as usize).map_err(|_| truncated())?;
                o += offset + SIZEOF_NV_INDEX + u64::from(datasize);
                entries.push(UserNvramEntry::NvIndex {
                    declared_entry_size,
                    handle,
                    index,
                    data,
                });
            }
            TPM_HT_PERSISTENT => {
                if o + offset + 4 + SIZEOF_OBJECT > USER_NVRAM_CAPACITY {
                    return Err(capacity_exceeded(o + offset + 4 + SIZEOF_OBJECT));
                }
                let object = parse_any_object(&mut reader, state_format)?;
                let object_type = object.public_type().unwrap_or(0);
                if !matches!(
                    object_type,
                    TPM_ALG_RSA | TPM_ALG_ECC | TPM_ALG_KEYEDHASH | TPM_ALG_SYMCIPHER
                ) {
                    return Err(PersistentAllError::UnstorableUserNvramObject {
                        object_type,
                        occupied: object.occupied(),
                    });
                }
                let object_destination_size = match object_format {
                    PersistentObjectFormat::LegacyRsa3072 => SIZEOF_RSA3072_OBJECT,
                    PersistentObjectFormat::AnyObject { object_version } => {
                        object.marshalled_size(object_version)
                    }
                };
                o += offset + 4 + object_destination_size;
                entries.push(UserNvramEntry::Persistent {
                    declared_entry_size,
                    handle,
                    object,
                    object_destination_size,
                });
            }
            _ => {
                return Err(PersistentAllError::UnknownHandleType { actual: handle });
            }
        }
    }

    let required_capacity = o + 4 + 8;
    if required_capacity > USER_NVRAM_CAPACITY {
        return Err(capacity_exceeded(required_capacity));
    }
    let max_count = reader.read_u64().map_err(|_| truncated())?;

    if header.version >= BLOCK_SKIP_SINCE_VERSION {
        skip_optional_block(&mut reader, false).map_err(|error| match error {
            BlockSkipError::Truncated => truncated(),
            BlockSkipError::MissingRequiredBlock => {
                PersistentAllError::MissingRequiredBlock { section: SECTION }
            }
        })?;
    }

    Ok(UserNvram {
        sourceside_size,
        entries,
        max_count,
        required_capacity,
        remaining: reader.remaining(),
    })
}

#[cfg(test)]
pub(in crate::library::tpm2) struct UserNvramFixture {
    pub(in crate::library::tpm2) version: u16,
    pub(in crate::library::tpm2) magic: u32,
    pub(in crate::library::tpm2) sourceside_size: u64,
    pub(in crate::library::tpm2) entries: Vec<Vec<u8>>,
    pub(in crate::library::tpm2) terminator: bool,
    pub(in crate::library::tpm2) max_count: Option<u64>,
    pub(in crate::library::tpm2) future_block: Option<(u8, u16, Vec<u8>)>,
    pub(in crate::library::tpm2) tail: Vec<u8>,
}

#[cfg(test)]
impl Default for UserNvramFixture {
    fn default() -> Self {
        Self {
            version: USER_NVRAM_VERSION,
            magic: USER_NVRAM_MAGIC,
            sourceside_size: USER_NVRAM_CAPACITY,
            entries: Vec::new(),
            terminator: true,
            max_count: Some(0),
            future_block: Some((1, 0, Vec::new())),
            tail: Vec::new(),
        }
    }
}

#[cfg(test)]
impl UserNvramFixture {
    pub(in crate::library::tpm2) fn nv_index_entry(
        handle: u32,
        index: &[u8],
        data: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        let entrysize = 4 + SIZEOF_NV_INDEX as u32 + data.len() as u32;
        out.extend_from_slice(&entrysize.to_be_bytes());
        out.extend_from_slice(&handle.to_be_bytes());
        out.extend_from_slice(index);
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    pub(in crate::library::tpm2) fn persistent_entry(handle: u32, object: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(8 + object.len() as u32).to_be_bytes());
        out.extend_from_slice(&handle.to_be_bytes());
        out.extend_from_slice(object);
        out
    }

    pub(in crate::library::tpm2) fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.magic.to_be_bytes());
        if self.version >= 2 {
            out.extend_from_slice(&1u16.to_be_bytes());
        }
        out.extend_from_slice(&self.sourceside_size.to_be_bytes());
        for entry in &self.entries {
            out.extend_from_slice(entry);
        }
        if self.terminator {
            out.extend_from_slice(&0u32.to_be_bytes());
        }
        if let Some(max_count) = self.max_count {
            out.extend_from_slice(&max_count.to_be_bytes());
        }
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
    use super::super::index::NvIndexFixture;
    use super::*;
    use crate::library::constants::{
        TPM_RC_BAD_PARAMETER, TPM_RC_HANDLE, TPM_RC_INSUFFICIENT, TPM_RC_SIZE,
    };
    use crate::library::tpm2::object::fixtures as object_fixtures;

    const SENTINEL: [u8; 3] = [0xf1, 0xf2, 0xf3];

    fn parse(data: &[u8]) -> Result<UserNvram<'_>, PersistentAllError> {
        parse_at(data, StateFormatLimit::CURRENT)
    }

    fn parse_at(
        data: &[u8],
        state_format: StateFormatLimit,
    ) -> Result<UserNvram<'_>, PersistentAllError> {
        parse_user_nvram(
            data,
            PersistentObjectFormat::AnyObject { object_version: 4 },
            state_format,
        )
    }

    fn with_tail() -> UserNvramFixture {
        UserNvramFixture {
            tail: SENTINEL.to_vec(),
            ..UserNvramFixture::default()
        }
    }

    #[test]
    fn empty_user_nvram_parses() {
        let data = UserNvramFixture {
            max_count: Some(7),
            ..with_tail()
        }
        .bytes();
        let parsed = parse(&data).unwrap();
        assert!(parsed.entries.is_empty());
        assert_eq!(parsed.max_count, 7);
        assert_eq!(parsed.required_capacity, 12);
        assert_eq!(parsed.remaining, &SENTINEL);
    }

    #[test]
    fn nv_index_entry_decodes() {
        let index = NvIndexFixture {
            data_size: 32,
            ..NvIndexFixture::default()
        }
        .bytes();
        let data = UserNvramFixture {
            entries: vec![UserNvramFixture::nv_index_entry(
                0x0100_0001,
                &index,
                &[0xab; 32],
            )],
            ..with_tail()
        }
        .bytes();
        let parsed = parse(&data).unwrap();
        assert_eq!(parsed.entries.len(), 1);
        let UserNvramEntry::NvIndex {
            handle,
            index,
            data: bulk,
            ..
        } = &parsed.entries[0]
        else {
            panic!("expected an NV index entry");
        };
        assert_eq!(*handle, 0x0100_0001);
        assert_eq!(index.nv_index, 0x0100_0001);
        assert_eq!(*bulk, &[0xab; 32]);
        assert_eq!(parsed.entries[0].destination_size(), 4 + 148 + 32);
        assert_eq!(parsed.required_capacity, 4 + 148 + 32 + 4 + 8);
    }

    #[test]
    fn persistent_object_entry_decodes() {
        let object = object_fixtures::any_rsa_object(4);
        let data = UserNvramFixture {
            entries: vec![UserNvramFixture::persistent_entry(0x8100_0002, &object)],
            ..with_tail()
        }
        .bytes();
        let parsed = parse(&data).unwrap();
        let UserNvramEntry::Persistent {
            handle,
            object_destination_size,
            ..
        } = &parsed.entries[0]
        else {
            panic!("expected a persistent entry");
        };
        assert_eq!(*handle, 0x8100_0002);
        assert_eq!(*object_destination_size, object.len() as u64);
        assert_eq!(parsed.remaining, &SENTINEL);
    }

    #[test]
    fn persistent_objects_obey_the_permanent_state_format_level() {
        use crate::library::constants::{TPM_RC_CURVE, TPM_RC_VALUE};
        use crate::library::tpm2::public::fixtures as public_fixtures;

        for (what, public, required_level, rejection) in [
            (
                "aes-128",
                public_fixtures::symcipher_public(128),
                1,
                TPM_RC_VALUE,
            ),
            (
                "aes-192",
                public_fixtures::symcipher_public(192),
                4,
                TPM_RC_VALUE,
            ),
            (
                "rsa-2048",
                public_fixtures::rsa_public(256),
                1,
                TPM_RC_VALUE,
            ),
            ("ecc-p256", public_fixtures::ecc_public(), 1, TPM_RC_CURVE),
        ] {
            let object = object_fixtures::any_public_only_object(&public);
            let data = UserNvramFixture {
                entries: vec![UserNvramFixture::persistent_entry(0x8100_0002, &object)],
                ..with_tail()
            }
            .bytes();
            for level in [0u32, 1, 4, 7] {
                let result = parse_at(&data, StateFormatLimit::new(level));
                if level >= required_level {
                    assert!(result.is_ok(), "{what} at level {level}");
                } else {
                    assert_eq!(
                        result.unwrap_err().tpm_result(),
                        rejection,
                        "{what} at level {level}"
                    );
                }
            }
        }
    }

    #[test]
    fn legacy_format_uses_the_fixed_rsa3072_size() {
        let object = object_fixtures::any_rsa_object(3);
        let data = UserNvramFixture {
            entries: vec![UserNvramFixture::persistent_entry(0x8100_0002, &object)],
            ..with_tail()
        }
        .bytes();
        let parsed = parse_user_nvram(
            &data,
            PersistentObjectFormat::LegacyRsa3072,
            StateFormatLimit::CURRENT,
        )
        .unwrap();
        let UserNvramEntry::Persistent {
            object_destination_size,
            ..
        } = &parsed.entries[0]
        else {
            panic!("expected a persistent entry");
        };
        assert_eq!(*object_destination_size, SIZEOF_RSA3072_OBJECT);
    }

    #[test]
    fn mixed_entries_preserve_wire_order() {
        let index = NvIndexFixture::default().bytes();
        let object = object_fixtures::any_rsa_object(4);
        let data = UserNvramFixture {
            entries: vec![
                UserNvramFixture::nv_index_entry(0x0100_0001, &index, &[0x01; 8]),
                UserNvramFixture::persistent_entry(0x8100_0002, &object),
                UserNvramFixture::nv_index_entry(0x0100_0003, &index, &[]),
            ],
            ..with_tail()
        }
        .bytes();
        let parsed = parse(&data).unwrap();
        assert_eq!(parsed.entries.len(), 3);
        assert!(matches!(parsed.entries[0], UserNvramEntry::NvIndex { .. }));
        assert!(matches!(
            parsed.entries[1],
            UserNvramEntry::Persistent { .. }
        ));
        assert!(matches!(
            parsed.entries[2],
            UserNvramEntry::NvIndex {
                handle: 0x0100_0003,
                ..
            }
        ));
    }

    #[test]
    fn unknown_handle_type_is_rc_handle() {
        for handle in [0x0000_0001u32, 0x0200_0000, 0x4000_0001, 0x8000_0000] {
            let mut entry = Vec::new();
            entry.extend_from_slice(&10u32.to_be_bytes());
            entry.extend_from_slice(&handle.to_be_bytes());
            let data = UserNvramFixture {
                entries: vec![entry],
                ..UserNvramFixture::default()
            }
            .bytes();
            let error = parse(&data).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::UnknownHandleType { actual: handle },
                "handle {handle:#010x}"
            );
            assert_eq!(error.tpm_result(), TPM_RC_HANDLE);
        }
    }

    #[test]
    fn oversized_nv_index_datasize_is_rc_size() {
        let index = NvIndexFixture::default().bytes();
        let mut entry = Vec::new();
        entry.extend_from_slice(&200u32.to_be_bytes());
        entry.extend_from_slice(&0x0100_0001u32.to_be_bytes());
        entry.extend_from_slice(&index);
        entry.extend_from_slice(&(MAX_NV_INDEX_DATA + 1).to_be_bytes());
        let data = UserNvramFixture {
            entries: vec![entry],
            ..UserNvramFixture::default()
        }
        .bytes();
        let error = parse(&data).unwrap_err();
        assert_eq!(
            error,
            PersistentAllError::NvDataSizeExceeded {
                actual: MAX_NV_INDEX_DATA + 1,
                maximum: MAX_NV_INDEX_DATA,
            }
        );
        assert_eq!(error.tpm_result(), TPM_RC_SIZE);
    }

    #[test]
    fn nv_index_data_beyond_capacity_is_a_size_error() {
        let index = NvIndexFixture::default().bytes();
        let bulk = vec![0x5a; 65535];
        let entries: Vec<Vec<u8>> = (0..3)
            .map(|i| UserNvramFixture::nv_index_entry(0x0100_0001 + i, &index, &bulk))
            .collect();
        let data = UserNvramFixture {
            entries,
            ..UserNvramFixture::default()
        }
        .bytes();
        let error = parse(&data).unwrap_err();
        assert!(
            matches!(
                error,
                PersistentAllError::DestinationCapacityExceeded {
                    section: StateSection::UserNvram,
                    ..
                }
            ),
            "{error:?}"
        );
        assert_eq!(error.tpm_result(), TPM_RC_SIZE);
    }

    #[test]
    fn unoccupied_persistent_object_is_rejected() {
        let object = object_fixtures::any_unoccupied_object();
        let data = UserNvramFixture {
            entries: vec![UserNvramFixture::persistent_entry(0x8100_0002, &object)],
            ..UserNvramFixture::default()
        }
        .bytes();
        let error = parse(&data).unwrap_err();
        assert_eq!(
            error,
            PersistentAllError::UnstorableUserNvramObject {
                object_type: 0,
                occupied: false,
            }
        );
        assert_eq!(error.tpm_result(), TPM_RC_BAD_PARAMETER);
    }

    #[test]
    fn sequence_object_with_key_type_is_storable() {
        let object = object_fixtures::any_sequence_object(object_fixtures::SEQ_HASH);
        let data = UserNvramFixture {
            entries: vec![UserNvramFixture::persistent_entry(0x8100_0002, &object)],
            ..with_tail()
        }
        .bytes();
        let parsed = parse(&data).unwrap();
        let UserNvramEntry::Persistent {
            object_destination_size,
            ..
        } = &parsed.entries[0]
        else {
            panic!("expected a persistent entry");
        };
        assert_eq!(*object_destination_size, object.len() as u64);
    }

    #[test]
    fn terminal_max_count_is_decoded() {
        let data = UserNvramFixture {
            max_count: Some(0x0102_0304_0506_0708),
            ..with_tail()
        }
        .bytes();
        assert_eq!(parse(&data).unwrap().max_count, 0x0102_0304_0506_0708);
    }

    #[test]
    fn missing_max_count_is_insufficient() {
        let data = UserNvramFixture {
            max_count: None,
            future_block: None,
            ..UserNvramFixture::default()
        }
        .bytes();
        assert_eq!(parse(&data).unwrap_err().tpm_result(), TPM_RC_INSUFFICIENT);
    }

    #[test]
    fn declared_entry_size_is_recorded_raw() {
        let index = NvIndexFixture::default().bytes();
        let mut entry = UserNvramFixture::nv_index_entry(0x0100_0001, &index, &[]);
        entry[0..4].copy_from_slice(&0xdead_beefu32.to_be_bytes());
        let data = UserNvramFixture {
            entries: vec![entry],
            ..with_tail()
        }
        .bytes();
        let parsed = parse(&data).unwrap();
        let UserNvramEntry::NvIndex {
            declared_entry_size,
            ..
        } = parsed.entries[0]
        else {
            panic!("expected an NV index entry");
        };
        assert_eq!(declared_entry_size, 0xdead_beef);
    }

    #[test]
    fn future_blocks_are_skipped_without_interpretation() {
        for future in [
            (0u8, 0u16, Vec::new()),
            (1, 0, Vec::new()),
            (1, 3, vec![0xff, 0xff, 0xff]),
        ] {
            let data = UserNvramFixture {
                future_block: Some(future),
                ..with_tail()
            }
            .bytes();
            assert_eq!(parse(&data).unwrap().remaining, &SENTINEL);
        }
    }

    #[test]
    fn truncation_at_every_boundary_is_insufficient() {
        let index = NvIndexFixture::default().bytes();
        let object = object_fixtures::any_rsa_object(4);
        let full = UserNvramFixture {
            entries: vec![
                UserNvramFixture::nv_index_entry(0x0100_0001, &index, &[0x01; 4]),
                UserNvramFixture::persistent_entry(0x8100_0002, &object),
            ],
            ..UserNvramFixture::default()
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

    #[test]
    fn user_nv_byte_mutations_do_not_panic() {
        let index = NvIndexFixture::default().bytes();
        let full = UserNvramFixture {
            entries: vec![UserNvramFixture::nv_index_entry(
                0x0100_0001,
                &index,
                &[0x01; 4],
            )],
            ..UserNvramFixture::default()
        }
        .bytes();
        for i in 0..full.len() {
            for byte in [0x00u8, 0x01, 0x81, 0xff] {
                let mut data = full.clone();
                data[i] = byte;
                let _ = parse(&data);
            }
        }
    }
}
