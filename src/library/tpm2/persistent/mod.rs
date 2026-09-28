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

use crate::library::constants::{
    TPM_RC_BAD_PARAMETER, TPM_RC_BAD_TAG, TPM_RC_BAD_VERSION, TPM_RC_CURVE, TPM_RC_FAILURE,
    TPM_RC_HANDLE, TPM_RC_HASH, TPM_RC_INSUFFICIENT, TPM_RC_KDF, TPM_RC_KEY_SIZE, TPM_RC_MODE,
    TPM_RC_NO_RESULT, TPM_RC_RESERVED_BITS, TPM_RC_SCHEME, TPM_RC_SIZE, TPM_RC_SYMMETRIC,
    TPM_RC_TYPE, TPM_RC_VALUE,
};
use crate::types::TpmResult;

mod attach;
mod compat_tail;
mod data;
mod orderly;
mod store;

pub(super) use attach::{
    OwnedAnyObject, OwnedAnyObjectBody, OwnedBnPrime, OwnedCommandBitmap, OwnedDrbgState,
    OwnedHashObjectBody, OwnedHashPayload, OwnedHashState, OwnedNvIndex, OwnedObjectBody,
    OwnedOrderlyData, OwnedPcrAllocation, OwnedPcrBank, OwnedPcrPolicyEntry, OwnedPcrSelection,
    OwnedPersistentData, OwnedPersistentState, OwnedPrivateExponent, OwnedPublicId, OwnedSecret,
    OwnedStateClearData, OwnedStateResetData, OwnedTpmtPublic, OwnedTpmtSensitive, OwnedUserNvram,
    OwnedUserNvramEntry, materialize_persistent_state, own_any_object, own_orderly_data,
    own_state_clear, own_state_reset, user_nvram_required_capacity,
};
pub(super) use compat_tail::{
    CompatTail, SEED_COMPAT_LEVEL_LAST, SEED_COMPAT_LEVEL_ORIGINAL, parse_compat_tail,
};
pub(super) use data::{PersistentDataPrefix, parse_persistent_data_prefix};
pub(super) use orderly::{
    DRBG_LAST_VALUE_COUNT, DRBG_SEED_SIZE, DRBG_STATE_MAGIC, DRBG_STATE_VERSION,
    ORDERLY_DATA_MAGIC, ORDERLY_DATA_VERSION, OrderlyData, parse_orderly_data,
};
pub(super) use store::{
    marshal_orderly_data, marshal_state_clear, marshal_state_reset, persistent_all_store,
};

#[cfg(test)]
pub(super) use compat_tail::CompatTailFixture;
#[cfg(test)]
pub(super) use data::PrefixFixture;
#[cfg(test)]
pub(super) use orderly::{DrbgFixture, OrderlyFixture};

use super::compile_constants::ConstantMismatch;
use super::marshal::BlobReader;

pub(super) const PERSISTENT_ALL_VERSION: u16 = 4;
pub(super) const PERSISTENT_ALL_MAGIC: u32 = 0xab36_4723;

const PROFILE_SINCE_VERSION: u16 = 4;
const MIN_VERSION_SINCE_VERSION: u16 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StateSection {
    PersistentAll,
    PaCompileConstants,
    PersistentData,
    PcrPolicy,
    PcrAllocation,
    PpList,
    Lockout,
    Audit,
    ClockEpoch,
    CompatTail,
    OrderlyData,
    DrbgState,
    StateResetData,
    StateClearData,
    PcrSave,
    PcrAuthValue,
    IndexOrderlyRam,
    UserNvram,
    NvIndex,
    AnyObject,
    Object,
    HashObject,
    HashState,
    PrivateExponent,
    BnPrime,
    PersistentAllTail,
    VolatileState,
    Session,
    SessionSlot,
    Pcr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PersistentField {
    OwnerPolicy,
    EndorsementPolicy,
    LockoutPolicy,
    OwnerAuth,
    EndorsementAuth,
    LockoutAuth,
    EpSeed,
    SpSeed,
    PpSeed,
    PhProof,
    ShProof,
    EhProof,
    PcrPolicyDigest,
    NullProof,
    NullSeed,
    CommandAuditDigest,
    CommitNonce,
    NullSeedCompat,
    ObjectSeedCompat,
    PlatformPolicy,
    PlatformAuth,
    PcrAuthValue,
    NvAuthPolicy,
    NvAuthValue,
    ObjectAuthPolicy,
    ObjectAuthValue,
    ObjectSeedValue,
    ObjectUnique,
    RsaPublicKey,
    RsaPrivateKey,
    EccParameter,
    SymKey,
    SensitiveData,
    QualifiedName,
    ObjectName,
    HmacKey,
    PlatformUniqueDetails,
    NonceCaller,
    InputAuthValue,
    CpHashForCommandAudit,
    SessionKey,
    NonceTpm,
    BoundEntity,
    SessionAuditDigest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AlgInterface {
    Hash,
    Sym,
    SymObject,
    SymMode,
    Kdf,
    KeyedHashScheme,
    RsaScheme,
    EccScheme,
    Public,
    KeyBits,
    EccCurve,
}

impl AlgInterface {
    pub(super) fn tpm_result(self) -> TpmResult {
        match self {
            Self::Hash => TPM_RC_HASH,
            Self::Sym | Self::SymObject => TPM_RC_SYMMETRIC,
            Self::SymMode => TPM_RC_MODE,
            Self::Kdf => TPM_RC_KDF,
            Self::KeyedHashScheme | Self::RsaScheme | Self::KeyBits => TPM_RC_VALUE,
            Self::EccScheme => TPM_RC_SCHEME,
            Self::Public => TPM_RC_TYPE,
            Self::EccCurve => TPM_RC_CURVE,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PersistentAllError {
    Truncated {
        section: StateSection,
    },
    InvalidHeaderMagic {
        section: StateSection,
        actual: u32,
    },
    MinimumVersionTooNew {
        section: StateSection,
        minimum: u16,
        supported: u16,
    },
    UnsupportedSectionVersion {
        section: StateSection,
        actual: u16,
        supported: u16,
    },
    MissingRequiredBlock {
        section: StateSection,
    },
    Tpm2bSizeExceeded {
        section: StateSection,
        field: PersistentField,
        actual: u16,
        maximum: usize,
    },
    ArraySizeMismatch {
        section: StateSection,
        declared: u16,
        expected: usize,
    },
    ListCountExceeded {
        section: StateSection,
        actual: u32,
        maximum: usize,
    },
    CommandArraySizeExceeded {
        section: StateSection,
        actual: u16,
        maximum: usize,
    },
    InvalidHashAlgorithm {
        section: StateSection,
        actual: u16,
    },
    InvalidPcrSelectSize {
        actual: u8,
        minimum: usize,
        maximum: usize,
    },
    InvalidClockSize {
        actual: u8,
        expected: u8,
    },
    SeedCompatLevelTooNew {
        field: PersistentField,
        actual: u8,
        supported: u8,
    },
    InvalidProfileEncoding,
    MissingFooter,
    InvalidFooterMagic {
        actual: u32,
    },
    CompileConstantMismatch(ConstantMismatch),
    InvalidAlgorithm {
        section: StateSection,
        interface: AlgInterface,
        actual: u16,
    },
    ReservedBitsSet {
        section: StateSection,
        actual: u32,
    },
    InvalidHandleValue {
        section: StateSection,
        actual: u32,
    },
    UnknownHandleType {
        actual: u32,
    },
    DestinationCapacityExceeded {
        section: StateSection,
        needed: u64,
        capacity: u64,
    },
    NvDataSizeExceeded {
        actual: u32,
        maximum: u32,
    },
    ArraySizeInvalid {
        section: StateSection,
        declared: u16,
        expected: usize,
    },
    InvalidContextSlotMask {
        actual: u16,
    },
    UnsupportedPcrBank {
        actual: u16,
    },
    MissingPcrBank {
        algorithm: u16,
    },
    UnstorableUserNvramObject {
        object_type: u16,
        occupied: bool,
    },
    InvalidPublicOnlySensitive {
        actual_type: u16,
    },
    TrailingPayloadBytes {
        remaining: usize,
    },
    InvalidTrailingMagic {
        section: StateSection,
        actual: u32,
    },
    SeedTieMismatch {
        field: PersistentField,
    },
    IntegrityDigestMismatch,
    MalformedProfileJson,
    MissingProfileName,
    MissingStateFormatLevel,
    StateFormatLevelNotANumber,
    StateFormatLevelTooNew {
        actual: u32,
        supported: u32,
    },
    UnknownProfileName,
    ProfileCustomizationNotAllowed,
    CustomProfileLevelTooLow,
    UnknownProfileAttribute,
    UnknownProfileAlgorithm,
    ProfileEntryLevelTooNew {
        component: ProfileComponent,
        required: u32,
        maximum: u32,
    },
    MissingRequiredProfileEntry {
        component: ProfileComponent,
    },
    InvalidProfileKeySize,
    InvalidProfileCommandRange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProfileComponent {
    Attributes,
    Algorithms,
    Commands,
}

impl PersistentAllError {
    pub(super) fn tpm_result(self) -> TpmResult {
        match self {
            Self::Truncated { .. } | Self::MissingFooter => TPM_RC_INSUFFICIENT,
            Self::InvalidHeaderMagic { .. }
            | Self::InvalidFooterMagic { .. }
            | Self::InvalidTrailingMagic { .. }
            | Self::TrailingPayloadBytes { .. } => TPM_RC_BAD_TAG,
            Self::MinimumVersionTooNew { .. }
            | Self::UnsupportedSectionVersion { .. }
            | Self::SeedCompatLevelTooNew { .. } => TPM_RC_BAD_VERSION,
            Self::Tpm2bSizeExceeded { .. }
            | Self::ArraySizeMismatch { .. }
            | Self::ListCountExceeded { .. }
            | Self::CommandArraySizeExceeded { .. }
            | Self::DestinationCapacityExceeded { .. }
            | Self::NvDataSizeExceeded { .. } => TPM_RC_SIZE,
            Self::InvalidHashAlgorithm { .. } | Self::IntegrityDigestMismatch => TPM_RC_HASH,
            Self::InvalidPcrSelectSize { .. }
            | Self::SeedTieMismatch { .. }
            | Self::InvalidHandleValue { .. }
            | Self::StateFormatLevelNotANumber
            | Self::StateFormatLevelTooNew { .. }
            | Self::UnknownProfileName
            | Self::ProfileCustomizationNotAllowed
            | Self::CustomProfileLevelTooLow
            | Self::UnknownProfileAlgorithm
            | Self::ProfileEntryLevelTooNew { .. }
            | Self::MissingRequiredProfileEntry { .. }
            | Self::InvalidProfileCommandRange => TPM_RC_VALUE,
            Self::MalformedProfileJson
            | Self::MissingProfileName
            | Self::MissingStateFormatLevel => TPM_RC_NO_RESULT,
            Self::UnknownProfileAttribute => TPM_RC_FAILURE,
            Self::InvalidProfileKeySize => TPM_RC_KEY_SIZE,
            Self::InvalidAlgorithm { interface, .. } => interface.tpm_result(),
            Self::ReservedBitsSet { .. } => TPM_RC_RESERVED_BITS,
            Self::UnknownHandleType { .. } => TPM_RC_HANDLE,
            Self::InvalidProfileEncoding
            | Self::MissingRequiredBlock { .. }
            | Self::InvalidClockSize { .. }
            | Self::CompileConstantMismatch(_)
            | Self::ArraySizeInvalid { .. }
            | Self::InvalidContextSlotMask { .. }
            | Self::UnsupportedPcrBank { .. }
            | Self::MissingPcrBank { .. }
            | Self::UnstorableUserNvramObject { .. }
            | Self::InvalidPublicOnlySensitive { .. } => TPM_RC_BAD_PARAMETER,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct NvHeader {
    pub(super) version: u16,
    pub(super) magic: u32,
    pub(super) min_version: u16,
}

pub(super) fn parse_nv_header(
    reader: &mut BlobReader<'_>,
    section: StateSection,
    expected_magic: u32,
    current_version: u16,
) -> Result<NvHeader, PersistentAllError> {
    let version = reader
        .read_u16()
        .map_err(|_| PersistentAllError::Truncated { section })?;
    let magic = reader
        .read_u32()
        .map_err(|_| PersistentAllError::Truncated { section })?;
    if magic != expected_magic {
        return Err(PersistentAllError::InvalidHeaderMagic {
            section,
            actual: magic,
        });
    }
    let min_version = if version >= MIN_VERSION_SINCE_VERSION {
        let min_version = reader
            .read_u16()
            .map_err(|_| PersistentAllError::Truncated { section })?;
        if min_version > current_version {
            return Err(PersistentAllError::MinimumVersionTooNew {
                section,
                minimum: min_version,
                supported: current_version,
            });
        }
        min_version
    } else {
        0
    };
    Ok(NvHeader {
        version,
        magic,
        min_version,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProfileField<'a> {
    Absent,
    Null,
    Bytes(&'a [u8]),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PersistentAllEnvelope<'a> {
    pub(super) header: NvHeader,
    pub(super) profile: ProfileField<'a>,
    pub(super) payload: &'a [u8],
}

impl<'a> PersistentAllEnvelope<'a> {
    pub(super) fn parse(blob: &'a [u8]) -> Result<Self, PersistentAllError> {
        const SECTION: StateSection = StateSection::PersistentAll;
        let mut reader = BlobReader::new(blob);

        let header = parse_nv_header(
            &mut reader,
            SECTION,
            PERSISTENT_ALL_MAGIC,
            PERSISTENT_ALL_VERSION,
        )?;

        let profile = if header.version >= PROFILE_SINCE_VERSION {
            let length = reader
                .read_u16()
                .map_err(|_| PersistentAllError::Truncated { section: SECTION })?;
            if length == 0 {
                ProfileField::Null
            } else {
                let bytes = reader
                    .take(usize::from(length))
                    .map_err(|_| PersistentAllError::Truncated { section: SECTION })?;
                match bytes.split_last() {
                    Some((&0, without_nul)) => ProfileField::Bytes(without_nul),
                    _ => return Err(PersistentAllError::InvalidProfileEncoding),
                }
            }
        } else {
            ProfileField::Absent
        };

        let rest = reader.remaining();
        let Some((payload, footer)) = rest.split_last_chunk::<4>() else {
            return Err(PersistentAllError::MissingFooter);
        };
        let footer = u32::from_be_bytes(*footer);
        if footer != PERSISTENT_ALL_MAGIC {
            return Err(PersistentAllError::InvalidFooterMagic { actual: footer });
        }

        Ok(Self {
            header,
            profile,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAGIC_BYTES: [u8; 4] = [0xab, 0x36, 0x47, 0x23];
    const OUTER: StateSection = StateSection::PersistentAll;

    fn truncated() -> PersistentAllError {
        PersistentAllError::Truncated { section: OUTER }
    }

    fn blob(version: u16, min_version: Option<u16>, tail: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&version.to_be_bytes());
        out.extend_from_slice(&MAGIC_BYTES);
        if let Some(min_version) = min_version {
            out.extend_from_slice(&min_version.to_be_bytes());
        }
        out.extend_from_slice(tail);
        out
    }

    fn profile_field(profile: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let length = u16::try_from(profile.len() + 1).unwrap();
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(profile);
        out.push(0);
        out
    }

    #[test]
    fn current_version_fixture_upstream_marshal_parity() {
        let fixture = [
            0x00, 0x04, 0xab, 0x36, 0x47, 0x23, 0x00, 0x04, 0x00, 0x03, b'{', b'}', 0x00, 0xde,
            0xad, 0xab, 0x36, 0x47, 0x23,
        ];
        let envelope = PersistentAllEnvelope::parse(&fixture).unwrap();
        assert_eq!(
            envelope.header,
            NvHeader {
                version: 4,
                magic: PERSISTENT_ALL_MAGIC,
                min_version: 4,
            }
        );
        assert_eq!(envelope.profile, ProfileField::Bytes(b"{}"));
        assert_eq!(envelope.payload, &[0xde, 0xad]);
    }

    #[test]
    fn version_1_six_byte_header() {
        let data = blob(1, None, &MAGIC_BYTES);
        let envelope = PersistentAllEnvelope::parse(&data).unwrap();
        assert_eq!(
            envelope.header,
            NvHeader {
                version: 1,
                magic: PERSISTENT_ALL_MAGIC,
                min_version: 0,
            }
        );
        assert_eq!(envelope.profile, ProfileField::Absent);
        assert_eq!(envelope.payload, &[] as &[u8]);
    }

    #[test]
    fn version_zero_header_layer_acceptance() {
        let data = blob(0, None, &MAGIC_BYTES);
        assert_eq!(
            PersistentAllEnvelope::parse(&data).unwrap().header.version,
            0
        );
    }

    #[test]
    fn version_2_and_3_eight_byte_header_no_profile() {
        for version in [2u16, 3] {
            let data = blob(version, Some(1), &[0x55, 0xab, 0x36, 0x47, 0x23]);
            let envelope = PersistentAllEnvelope::parse(&data).unwrap();
            assert_eq!(envelope.header.version, version);
            assert_eq!(envelope.header.min_version, 1);
            assert_eq!(envelope.profile, ProfileField::Absent, "version {version}");
            assert_eq!(envelope.payload, &[0x55]);
        }
    }

    #[test]
    fn incorrect_header_magic_bad_tag_rejection() {
        let mut data = blob(4, Some(4), &MAGIC_BYTES);
        data[2] = 0xff;
        assert_eq!(
            PersistentAllEnvelope::parse(&data),
            Err(PersistentAllError::InvalidHeaderMagic {
                section: OUTER,
                actual: 0xff36_4723
            })
        );
    }

    #[test]
    fn truncated_version_magic_error() {
        assert_eq!(PersistentAllEnvelope::parse(&[]), Err(truncated()));
        assert_eq!(
            PersistentAllEnvelope::parse(&[0x00]),
            Err(truncated()),
            "truncated version"
        );
        assert_eq!(
            PersistentAllEnvelope::parse(&[0x00, 0x04, 0xab, 0x36]),
            Err(truncated()),
            "truncated magic"
        );
    }

    #[test]
    fn truncated_min_version_error() {
        assert_eq!(
            PersistentAllEnvelope::parse(&[0x00, 0x02, 0xab, 0x36, 0x47, 0x23, 0x00]),
            Err(truncated())
        );
    }

    #[test]
    fn supported_min_version_acceptance() {
        for min_version in [0u16, 1, 3, PERSISTENT_ALL_VERSION] {
            let data = blob(4, Some(min_version), &[0x00, 0x00, 0xab, 0x36, 0x47, 0x23]);
            let envelope = PersistentAllEnvelope::parse(&data).unwrap();
            assert_eq!(envelope.header.min_version, min_version);
        }
    }

    #[test]
    fn newer_min_version_rejection() {
        let data = blob(5, Some(5), &MAGIC_BYTES);
        assert_eq!(
            PersistentAllEnvelope::parse(&data),
            Err(PersistentAllError::MinimumVersionTooNew {
                section: OUTER,
                minimum: 5,
                supported: 4,
            })
        );
    }

    #[test]
    fn future_version_supported_min_acceptance() {
        let mut tail = profile_field(b"{}");
        tail.extend_from_slice(&[0x01, 0x02]);
        tail.extend_from_slice(&MAGIC_BYTES);
        let data = blob(9, Some(4), &tail);
        let envelope = PersistentAllEnvelope::parse(&data).unwrap();
        assert_eq!(envelope.header.version, 9);
        assert_eq!(envelope.profile, ProfileField::Bytes(b"{}"));
        assert_eq!(envelope.payload, &[0x01, 0x02]);
    }

    #[test]
    fn pre_v4_no_profile_field() {
        for (version, min_version) in [(1u16, None), (2, Some(1)), (3, Some(1))] {
            let data = blob(version, min_version, &[0x00, 0x01, 0xab, 0x36, 0x47, 0x23]);
            let envelope = PersistentAllEnvelope::parse(&data).unwrap();
            assert_eq!(envelope.profile, ProfileField::Absent);
            assert_eq!(envelope.payload, &[0x00, 0x01], "version {version}");
        }
    }

    #[test]
    fn v4_null_profile_bytes_distinction() {
        let mut tail = vec![0x00, 0x00];
        tail.extend_from_slice(&MAGIC_BYTES);
        let data = blob(4, Some(4), &tail);
        let envelope = PersistentAllEnvelope::parse(&data).unwrap();
        assert_eq!(envelope.profile, ProfileField::Null);
        assert_eq!(envelope.payload, &[] as &[u8]);
    }

    #[test]
    fn version_4_profile_bytes_terminating_nul_exclusion() {
        let mut tail = profile_field(b"{\"Name\":\"null\"}");
        tail.extend_from_slice(&MAGIC_BYTES);
        let data = blob(4, Some(4), &tail);
        let envelope = PersistentAllEnvelope::parse(&data).unwrap();
        assert_eq!(
            envelope.profile,
            ProfileField::Bytes(b"{\"Name\":\"null\"}")
        );
    }

    #[test]
    fn profile_length_big_endian() {
        let mut tail = vec![0x01, 0x01];
        tail.extend_from_slice(&[b'x'; 256]);
        tail.push(0);
        tail.extend_from_slice(&MAGIC_BYTES);
        let data = blob(4, Some(4), &tail);
        let envelope = PersistentAllEnvelope::parse(&data).unwrap();
        assert_eq!(envelope.profile, ProfileField::Bytes(&[b'x'; 256] as &[u8]));
    }

    #[test]
    fn profile_bytes_no_utf8_conversion() {
        let mut tail = profile_field(&[0xff, 0xfe]);
        tail.extend_from_slice(&MAGIC_BYTES);
        let data = blob(4, Some(4), &tail);
        let envelope = PersistentAllEnvelope::parse(&data).unwrap();
        assert_eq!(envelope.profile, ProfileField::Bytes(&[0xffu8, 0xfe]));
    }

    #[test]
    fn truncated_profile_length_error() {
        let data = blob(4, Some(4), &[0x00]);
        assert_eq!(PersistentAllEnvelope::parse(&data), Err(truncated()));
    }

    #[test]
    fn profile_length_beyond_input_truncation_error() {
        let data = blob(4, Some(4), &[0x00, 0x10, b'x']);
        assert_eq!(PersistentAllEnvelope::parse(&data), Err(truncated()));
    }

    #[test]
    fn missing_profile_nul_rejection() {
        let mut tail = vec![0x00, 0x02, b'{', b'}'];
        tail.extend_from_slice(&MAGIC_BYTES);
        let data = blob(4, Some(4), &tail);
        assert_eq!(
            PersistentAllEnvelope::parse(&data),
            Err(PersistentAllError::InvalidProfileEncoding)
        );
    }

    #[test]
    fn incorrect_footer_magic_rejection() {
        let data = blob(1, None, &[0xab, 0x36, 0x47, 0x24]);
        assert_eq!(
            PersistentAllEnvelope::parse(&data),
            Err(PersistentAllError::InvalidFooterMagic {
                actual: 0xab36_4724
            })
        );
    }

    #[test]
    fn truncated_footer_missing_error() {
        let data = blob(1, None, &[0xab, 0x36, 0x47]);
        assert_eq!(
            PersistentAllEnvelope::parse(&data),
            Err(PersistentAllError::MissingFooter)
        );
    }

    #[test]
    fn payload_footer_exclusion_and_blob_borrow() {
        let mut tail = vec![0x11, 0x22, 0x33];
        tail.extend_from_slice(&MAGIC_BYTES);
        let data = blob(1, None, &tail);
        let envelope = PersistentAllEnvelope::parse(&data).unwrap();
        assert_eq!(envelope.payload, &[0x11, 0x22, 0x33]);
        assert!(core::ptr::eq(envelope.payload.as_ptr(), data[6..].as_ptr()));
    }

    #[test]
    fn payload_magic_bytes_footer_distinction() {
        let mut tail = Vec::new();
        tail.extend_from_slice(&MAGIC_BYTES);
        tail.extend_from_slice(&[0x99]);
        tail.extend_from_slice(&MAGIC_BYTES);
        let data = blob(1, None, &tail);
        let envelope = PersistentAllEnvelope::parse(&data).unwrap();
        assert_eq!(envelope.payload, &[0xab, 0x36, 0x47, 0x23, 0x99]);
    }

    #[test]
    fn magic_like_sequence_final_four_byte_decision() {
        let mut tail = Vec::new();
        tail.extend_from_slice(&MAGIC_BYTES);
        tail.extend_from_slice(&[0x00, 0x00]);
        let data = blob(1, None, &tail);
        assert_eq!(
            PersistentAllEnvelope::parse(&data),
            Err(PersistentAllError::InvalidFooterMagic {
                actual: 0x4723_0000
            })
        );
    }

    #[test]
    fn structurally_complete_empty_payload_envelope_acceptance() {
        let data = blob(4, Some(4), &{
            let mut tail = vec![0x00, 0x00];
            tail.extend_from_slice(&MAGIC_BYTES);
            tail
        });
        let envelope = PersistentAllEnvelope::parse(&data).unwrap();
        assert_eq!(envelope.payload, &[] as &[u8]);
    }

    #[test]
    fn error_upstream_result_code_mapping() {
        use super::super::compile_constants::{CompareOp, ConstantMismatch};
        use crate::library::constants::{
            TPM_RC_BAD_PARAMETER, TPM_RC_BAD_TAG, TPM_RC_BAD_VERSION, TPM_RC_HASH,
            TPM_RC_INSUFFICIENT, TPM_RC_SIZE, TPM_RC_VALUE,
        };

        for section in [
            StateSection::PersistentAll,
            StateSection::PaCompileConstants,
            StateSection::PersistentData,
            StateSection::PcrPolicy,
            StateSection::PcrAllocation,
            StateSection::PpList,
            StateSection::Lockout,
            StateSection::Audit,
            StateSection::ClockEpoch,
            StateSection::CompatTail,
        ] {
            assert_eq!(
                PersistentAllError::Truncated { section }.tpm_result(),
                TPM_RC_INSUFFICIENT
            );
            assert_eq!(
                PersistentAllError::InvalidHeaderMagic { section, actual: 0 }.tpm_result(),
                TPM_RC_BAD_TAG
            );
            assert_eq!(
                PersistentAllError::MinimumVersionTooNew {
                    section,
                    minimum: 5,
                    supported: 4
                }
                .tpm_result(),
                TPM_RC_BAD_VERSION
            );
            assert_eq!(
                PersistentAllError::UnsupportedSectionVersion {
                    section,
                    actual: 4,
                    supported: 3
                }
                .tpm_result(),
                TPM_RC_BAD_VERSION
            );
            assert_eq!(
                PersistentAllError::MissingRequiredBlock { section }.tpm_result(),
                TPM_RC_BAD_PARAMETER
            );
            assert_eq!(
                PersistentAllError::Tpm2bSizeExceeded {
                    section,
                    field: PersistentField::OwnerAuth,
                    actual: 65,
                    maximum: 64,
                }
                .tpm_result(),
                TPM_RC_SIZE
            );
            assert_eq!(
                PersistentAllError::ArraySizeMismatch {
                    section,
                    declared: 2,
                    expected: 1,
                }
                .tpm_result(),
                TPM_RC_SIZE
            );
            assert_eq!(
                PersistentAllError::ListCountExceeded {
                    section,
                    actual: 5,
                    maximum: 4,
                }
                .tpm_result(),
                TPM_RC_SIZE
            );
            assert_eq!(
                PersistentAllError::CommandArraySizeExceeded {
                    section,
                    actual: 18,
                    maximum: 17,
                }
                .tpm_result(),
                TPM_RC_SIZE
            );
            assert_eq!(
                PersistentAllError::InvalidHashAlgorithm {
                    section,
                    actual: 0x0010,
                }
                .tpm_result(),
                TPM_RC_HASH
            );
        }
        assert_eq!(
            PersistentAllError::InvalidClockSize {
                actual: 8,
                expected: 4,
            }
            .tpm_result(),
            TPM_RC_BAD_PARAMETER
        );
        for field in [
            PersistentField::EpSeed,
            PersistentField::SpSeed,
            PersistentField::PpSeed,
        ] {
            assert_eq!(
                PersistentAllError::SeedCompatLevelTooNew {
                    field,
                    actual: 2,
                    supported: 1,
                }
                .tpm_result(),
                TPM_RC_BAD_VERSION
            );
        }
        assert_eq!(
            PersistentAllError::InvalidPcrSelectSize {
                actual: 4,
                minimum: 3,
                maximum: 3,
            }
            .tpm_result(),
            TPM_RC_VALUE
        );
        assert_eq!(
            PersistentAllError::MissingFooter.tpm_result(),
            TPM_RC_INSUFFICIENT
        );
        assert_eq!(
            PersistentAllError::InvalidFooterMagic { actual: 0 }.tpm_result(),
            TPM_RC_BAD_TAG
        );
        assert_eq!(
            PersistentAllError::InvalidProfileEncoding.tpm_result(),
            TPM_RC_BAD_PARAMETER
        );
        assert_eq!(
            PersistentAllError::CompileConstantMismatch(ConstantMismatch {
                index: 0,
                name: "ALG_RSA",
                saved: 0,
                current: 1,
                comparison: CompareOp::Equal,
                section_version: 3,
            })
            .tpm_result(),
            TPM_RC_BAD_PARAMETER
        );
    }
}
