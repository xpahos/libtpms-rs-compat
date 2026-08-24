use super::crypto::COMPILED_HASHES;
use super::hierarchy::{TPM_RH_ENDORSEMENT, TPM_RH_NULL, TPM_RH_OWNER, TPM_RH_PLATFORM};
use super::marshal::{BlobReader, BlockDisposition, BlockSkipError, skip_optional_block};
use super::persistent::{PersistentAllError, PersistentField, StateSection, parse_nv_header};
use super::public::{
    self, DIGEST_SIZE, NAME_SIZE, StateFormatLimit, TPM_ALG_RSA, TPM_ALG_SHA1, TPM_ALG_SHA256,
    TPM_ALG_SHA384, TPM_ALG_SHA512, TpmtPublic, TpmtSensitive, parse_nv_tpmt_sensitive,
    parse_tpmt_public, read_tpm2b,
};

pub(super) const ANY_OBJECT_MAGIC: u32 = 0xfe9a_3974;
pub(super) const ANY_OBJECT_VERSION: u16 = 2;
pub(super) const OBJECT_MAGIC: u32 = 0x75be_73af;
const OBJECT_VERSION: u16 = 4;
pub(super) const HASH_OBJECT_MAGIC: u32 = 0xb874_fe38;
pub(super) const HASH_OBJECT_VERSION: u16 = 3;
pub(super) const HASH_STATE_MAGIC: u32 = 0x5628_78a2;
pub(super) const HASH_STATE_VERSION: u16 = 2;
pub(super) const ANY_HASH_STATE_MAGIC: u32 = 0x349d_494b;
pub(super) const ANY_HASH_STATE_VERSION: u16 = 2;
pub(super) const HASH_STATE_SHA1_MAGIC: u32 = 0x19d4_6f50;
pub(super) const HASH_STATE_SHA256_MAGIC: u32 = 0x6ea0_59d0;
pub(super) const HASH_STATE_SHA384_MAGIC: u32 = 0x1481_4b08;
pub(super) const HASH_STATE_SHA512_MAGIC: u32 = 0x269e_8ae0;
pub(super) const HASH_STATE_SHA_VERSION: u16 = 2;
pub(super) const PRIVATE_EXPONENT_T_MAGIC: u32 = 0x0854_eab2;
pub(super) const PRIVATE_EXPONENT_T_VERSION: u16 = 2;
pub(super) const BN_PRIME_T_MAGIC: u32 = 0x2fe7_36ab;
pub(super) const BN_PRIME_T_VERSION: u16 = 2;

const BN_PRIME_WORDS: usize = 24;
const CRYPT_UWORD_BYTES: usize = 8;

pub(super) const ATTR_PUBLIC_ONLY: u32 = 1 << 0;
pub(super) const ATTR_EPS_HIERARCHY: u32 = 1 << 1;
pub(super) const ATTR_PPS_HIERARCHY: u32 = 1 << 2;
pub(super) const ATTR_SPS_HIERARCHY: u32 = 1 << 3;
pub(super) const ATTR_EVICT: u32 = 1 << 4;
pub(super) const ATTR_PRIMARY: u32 = 1 << 5;
pub(super) const ATTR_TEMPORARY: u32 = 1 << 6;
pub(super) const ATTR_ST_CLEAR: u32 = 1 << 7;
pub(super) const ATTR_IS_PARENT: u32 = 1 << 13;
pub(super) const ATTR_PRIVATE_EXP: u32 = 1 << 14;
pub(super) const ATTR_DERIVATION: u32 = 1 << 16;
pub(super) const ATTR_EXTERNAL: u32 = 1 << 17;
pub(super) const ATTR_HMAC_SEQ: u32 = 1 << 8;
pub(super) const ATTR_HASH_SEQ: u32 = 1 << 9;
pub(super) const ATTR_EVENT_SEQ: u32 = 1 << 10;
pub(super) const ATTR_TICKET_SAFE: u32 = 1 << 11;
pub(super) const ATTR_FIRST_BLOCK: u32 = 1 << 12;
pub(super) const ATTR_OCCUPIED: u32 = 1 << 15;

pub(super) const HASH_STATE_COUNT: usize = 4;

const _: () = assert!(COMPILED_HASHES.len() == HASH_STATE_COUNT);

pub(super) const HASH_STATE_EMPTY: u8 = 0;
pub(super) const HASH_STATE_HASH: u8 = 1;
pub(super) const HASH_STATE_HMAC: u8 = 2;
pub(super) const HASH_STATE_SMAC: u8 = 3;

const SEED_COMPAT_LEVEL_ORIGINAL: u8 = 0;
const SEED_COMPAT_LEVEL_LAST: u8 = 1;

const BLOCK_SKIP_SINCE_VERSION: u16 = 2;

fn truncated(section: StateSection) -> PersistentAllError {
    PersistentAllError::Truncated { section }
}

fn read_block(
    reader: &mut BlobReader<'_>,
    section: StateSection,
    needs_block: bool,
) -> Result<BlockDisposition, PersistentAllError> {
    skip_optional_block(reader, needs_block).map_err(|error| match error {
        BlockSkipError::Truncated => truncated(section),
        BlockSkipError::MissingRequiredBlock => {
            PersistentAllError::MissingRequiredBlock { section }
        }
    })
}

#[allow(dead_code)]
pub(super) enum HashPayload<'a> {
    Sha1 {
        h: [u32; 5],
        nl: u32,
        nh: u32,
        data: &'a [u8],
        num: u32,
    },
    Sha256 {
        h: [u32; 8],
        nl: u32,
        nh: u32,
        data: &'a [u8],
        num: u32,
        md_len: u32,
    },
    Sha512 {
        h: [u64; 8],
        nl: u64,
        nh: u64,
        data: &'a [u8],
        num: u32,
        md_len: u32,
    },
}

#[allow(dead_code)]
pub(super) struct HashState<'a> {
    pub(super) state_type: u8,
    pub(super) hash_alg: u16,
    pub(super) payload: Option<HashPayload<'a>>,
}

const SHA1_PAYLOAD_SIZE: u64 = 7 * 4 + 2 + 64 + 4;
const SHA256_PAYLOAD_SIZE: u64 = 2 + 8 * 4 + 2 * 4 + 2 + 64 + 4 + 4;
const SHA512_PAYLOAD_SIZE: u64 = 2 + 8 * 8 + 2 * 8 + 2 + 128 + 4 + 4;

const SECTION_HASH_STATE: StateSection = StateSection::HashState;

fn parse_sha1_state<'a>(
    reader: &mut BlobReader<'a>,
) -> Result<HashPayload<'a>, PersistentAllError> {
    const S: StateSection = SECTION_HASH_STATE;
    let header = parse_nv_header(reader, S, HASH_STATE_SHA1_MAGIC, HASH_STATE_SHA_VERSION)?;
    let mut h = [0u32; 5];
    for value in &mut h {
        *value = reader.read_u32().map_err(|_| truncated(S))?;
    }
    let nl = reader.read_u32().map_err(|_| truncated(S))?;
    let nh = reader.read_u32().map_err(|_| truncated(S))?;
    let declared = reader.read_u16().map_err(|_| truncated(S))?;
    if usize::from(declared) != 64 {
        return Err(PersistentAllError::ArraySizeInvalid {
            section: S,
            declared,
            expected: 64,
        });
    }
    let data = reader.take(64).map_err(|_| truncated(S))?;
    let num = reader.read_u32().map_err(|_| truncated(S))?;
    if header.version >= BLOCK_SKIP_SINCE_VERSION {
        read_block(reader, S, false)?;
    }
    Ok(HashPayload::Sha1 {
        h,
        nl,
        nh,
        data,
        num,
    })
}

fn parse_sha256_state<'a>(
    reader: &mut BlobReader<'a>,
) -> Result<HashPayload<'a>, PersistentAllError> {
    const S: StateSection = SECTION_HASH_STATE;
    let header = parse_nv_header(reader, S, HASH_STATE_SHA256_MAGIC, HASH_STATE_SHA_VERSION)?;
    let declared = reader.read_u16().map_err(|_| truncated(S))?;
    if usize::from(declared) != 8 {
        return Err(PersistentAllError::ArraySizeInvalid {
            section: S,
            declared,
            expected: 8,
        });
    }
    let mut h = [0u32; 8];
    for value in &mut h {
        *value = reader.read_u32().map_err(|_| truncated(S))?;
    }
    let nl = reader.read_u32().map_err(|_| truncated(S))?;
    let nh = reader.read_u32().map_err(|_| truncated(S))?;
    let declared = reader.read_u16().map_err(|_| truncated(S))?;
    if usize::from(declared) != 64 {
        return Err(PersistentAllError::ArraySizeInvalid {
            section: S,
            declared,
            expected: 64,
        });
    }
    let data = reader.take(64).map_err(|_| truncated(S))?;
    let num = reader.read_u32().map_err(|_| truncated(S))?;
    let md_len = reader.read_u32().map_err(|_| truncated(S))?;
    if header.version >= BLOCK_SKIP_SINCE_VERSION {
        read_block(reader, S, false)?;
    }
    Ok(HashPayload::Sha256 {
        h,
        nl,
        nh,
        data,
        num,
        md_len,
    })
}

fn parse_sha512_state<'a>(
    reader: &mut BlobReader<'a>,
    magic: u32,
) -> Result<HashPayload<'a>, PersistentAllError> {
    const S: StateSection = SECTION_HASH_STATE;
    let header = parse_nv_header(reader, S, magic, HASH_STATE_SHA_VERSION)?;
    let declared = reader.read_u16().map_err(|_| truncated(S))?;
    if usize::from(declared) != 8 {
        return Err(PersistentAllError::ArraySizeInvalid {
            section: S,
            declared,
            expected: 8,
        });
    }
    let mut h = [0u64; 8];
    for value in &mut h {
        *value = reader.read_u64().map_err(|_| truncated(S))?;
    }
    let nl = reader.read_u64().map_err(|_| truncated(S))?;
    let nh = reader.read_u64().map_err(|_| truncated(S))?;
    let declared = reader.read_u16().map_err(|_| truncated(S))?;
    if usize::from(declared) != 128 {
        return Err(PersistentAllError::ArraySizeInvalid {
            section: S,
            declared,
            expected: 128,
        });
    }
    let data = reader.take(128).map_err(|_| truncated(S))?;
    let num = reader.read_u32().map_err(|_| truncated(S))?;
    let md_len = reader.read_u32().map_err(|_| truncated(S))?;
    if header.version >= BLOCK_SKIP_SINCE_VERSION {
        read_block(reader, S, false)?;
    }
    Ok(HashPayload::Sha512 {
        h,
        nl,
        nh,
        data,
        num,
        md_len,
    })
}

fn live_state_is_usable(state: &HashState<'_>, mac: bool) -> bool {
    let digested = matches!(
        state.hash_alg,
        TPM_ALG_SHA1 | TPM_ALG_SHA256 | TPM_ALG_SHA384 | TPM_ALG_SHA512
    );
    match state.state_type {
        HASH_STATE_HASH => !mac && digested && state.payload.is_some(),
        HASH_STATE_HMAC => mac && digested && state.payload.is_some(),
        HASH_STATE_SMAC => mac && state.hash_alg == 0 && state.payload.is_none(),
        _ => false,
    }
}

fn check_live_state(state: &HashState<'_>, mac: bool) -> Result<(), PersistentAllError> {
    if live_state_is_usable(state, mac) {
        return Ok(());
    }
    Err(unusable_state(state))
}

fn unusable_state(state: &HashState<'_>) -> PersistentAllError {
    PersistentAllError::InvalidHashAlgorithm {
        section: SECTION_HASH_STATE,
        actual: state.hash_alg,
    }
}

fn check_event_states(
    states: &[HashState<'_>; HASH_STATE_COUNT],
) -> Result<(), PersistentAllError> {
    for (state, &(hash_alg, _)) in states.iter().zip(COMPILED_HASHES.iter()) {
        if state.state_type != HASH_STATE_HASH
            || state.hash_alg != hash_alg
            || state.payload.is_none()
        {
            return Err(unusable_state(state));
        }
    }
    Ok(())
}

fn parse_hash_state<'a>(reader: &mut BlobReader<'a>) -> Result<HashState<'a>, PersistentAllError> {
    const S: StateSection = SECTION_HASH_STATE;
    let header = parse_nv_header(reader, S, HASH_STATE_MAGIC, HASH_STATE_VERSION)?;
    let state_type = reader.read_u8().map_err(|_| truncated(S))?;
    let hash_alg = reader.read_u16().map_err(|_| truncated(S))?;

    let any_header = parse_nv_header(reader, S, ANY_HASH_STATE_MAGIC, ANY_HASH_STATE_VERSION)?;
    let payload = match hash_alg {
        TPM_ALG_SHA1 => Some(parse_sha1_state(reader)?),
        TPM_ALG_SHA256 => Some(parse_sha256_state(reader)?),
        TPM_ALG_SHA384 => Some(parse_sha512_state(reader, HASH_STATE_SHA384_MAGIC)?),
        TPM_ALG_SHA512 => Some(parse_sha512_state(reader, HASH_STATE_SHA512_MAGIC)?),
        _ => None,
    };
    if any_header.version >= BLOCK_SKIP_SINCE_VERSION {
        read_block(reader, S, false)?;
    }
    if header.version >= BLOCK_SKIP_SINCE_VERSION {
        read_block(reader, S, false)?;
    }
    Ok(HashState {
        state_type,
        hash_alg,
        payload,
    })
}

impl HashState<'_> {
    fn marshalled_size(&self) -> u64 {
        let payload = match self.payload {
            Some(HashPayload::Sha1 { .. }) => 8 + SHA1_PAYLOAD_SIZE + 3,
            Some(HashPayload::Sha256 { .. }) => 8 + SHA256_PAYLOAD_SIZE + 3,
            Some(HashPayload::Sha512 { .. }) => 8 + SHA512_PAYLOAD_SIZE + 3,
            None => 0,
        };
        8 + 1 + 2 + (8 + payload + 3) + 3
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct BnPrime<'a> {
    pub(super) numbytes: u16,
    pub(super) data: &'a [u8],
}

impl core::fmt::Debug for BnPrime<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BnPrime")
            .field("numbytes", &self.numbytes)
            .finish_non_exhaustive()
    }
}

impl BnPrime<'_> {
    fn size_words(&self) -> u64 {
        (u64::from(self.numbytes)).div_ceil(CRYPT_UWORD_BYTES as u64)
    }

    fn marshalled_size(&self) -> u64 {
        8 + 2 + self.size_words() * CRYPT_UWORD_BYTES as u64 + 3
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct PrivateExponent<'a> {
    pub(super) primes: [BnPrime<'a>; 4],
}

impl PrivateExponent<'_> {
    fn marshalled_size(&self) -> u64 {
        8 + self
            .primes
            .iter()
            .map(BnPrime::marshalled_size)
            .sum::<u64>()
            + 3
    }
}

fn parse_bn_prime<'a>(reader: &mut BlobReader<'a>) -> Result<BnPrime<'a>, PersistentAllError> {
    const S: StateSection = StateSection::BnPrime;
    let header = parse_nv_header(reader, S, BN_PRIME_T_MAGIC, BN_PRIME_T_VERSION)?;
    let numbytes = reader.read_u16().map_err(|_| truncated(S))?;
    if usize::from(numbytes).div_ceil(CRYPT_UWORD_BYTES) > BN_PRIME_WORDS {
        return Err(PersistentAllError::ArraySizeMismatch {
            section: S,
            declared: numbytes,
            expected: BN_PRIME_WORDS * CRYPT_UWORD_BYTES,
        });
    }
    let wire_len = usize::from(numbytes).div_ceil(4) * 4;
    let data = reader.take(wire_len).map_err(|_| truncated(S))?;
    if header.version >= BLOCK_SKIP_SINCE_VERSION {
        read_block(reader, S, false)?;
    }
    Ok(BnPrime { numbytes, data })
}

fn parse_private_exponent<'a>(
    reader: &mut BlobReader<'a>,
) -> Result<PrivateExponent<'a>, PersistentAllError> {
    const S: StateSection = StateSection::PrivateExponent;
    let header = parse_nv_header(
        reader,
        S,
        PRIVATE_EXPONENT_T_MAGIC,
        PRIVATE_EXPONENT_T_VERSION,
    )?;
    let primes = [
        parse_bn_prime(reader)?,
        parse_bn_prime(reader)?,
        parse_bn_prime(reader)?,
        parse_bn_prime(reader)?,
    ];
    if header.version >= BLOCK_SKIP_SINCE_VERSION {
        read_block(reader, S, false)?;
    }
    Ok(PrivateExponent { primes })
}

#[allow(dead_code)]
pub(super) struct ObjectBody<'a> {
    pub(super) section_version: u16,
    pub(super) public: TpmtPublic<'a>,
    public_wire_len: u64,
    pub(super) sensitive: TpmtSensitive<'a>,
    sensitive_wire_len: u64,
    pub(super) private_exponent: Option<PrivateExponent<'a>>,
    pub(super) qualified_name: &'a [u8],
    pub(super) evict_handle: u32,
    pub(super) name: &'a [u8],
    pub(super) seed_compat_level: u8,
    pub(super) hierarchy: Option<u32>,
}

#[allow(dead_code)]
pub(super) struct HashObjectBody<'a> {
    pub(super) section_version: u16,
    pub(super) object_type: u16,
    pub(super) name_alg: u16,
    pub(super) object_attributes: u32,
    pub(super) auth: &'a [u8],
    pub(super) states: Option<[HashState<'a>; HASH_STATE_COUNT]>,
    pub(super) hmac_state: Option<(HashState<'a>, &'a [u8])>,
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) enum AnyObjectBody<'a> {
    Unoccupied,
    Object(Box<ObjectBody<'a>>),
    Sequence(Box<HashObjectBody<'a>>),
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct AnyObject<'a> {
    pub(super) attributes: u32,
    pub(super) body: AnyObjectBody<'a>,
}

impl core::fmt::Debug for AnyObject<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let kind = match &self.body {
            AnyObjectBody::Unoccupied => "unoccupied",
            AnyObjectBody::Object(_) => "object",
            AnyObjectBody::Sequence(_) => "sequence",
        };
        f.debug_struct("AnyObject")
            .field("attributes", &format_args!("{:#010x}", self.attributes))
            .field("body", &kind)
            .finish()
    }
}

impl AnyObject<'_> {
    pub(super) fn occupied(&self) -> bool {
        self.attributes & ATTR_OCCUPIED != 0
    }

    fn is_sequence(attributes: u32) -> bool {
        attributes & (ATTR_HMAC_SEQ | ATTR_HASH_SEQ | ATTR_EVENT_SEQ) != 0
    }

    pub(super) fn public_type(&self) -> Option<u16> {
        match &self.body {
            AnyObjectBody::Unoccupied => None,
            AnyObjectBody::Object(object) => Some(object.public.object_type),
            AnyObjectBody::Sequence(sequence) => Some(sequence.object_type),
        }
    }

    pub(super) fn marshalled_size(&self, object_version: u16) -> u64 {
        let body = match &self.body {
            AnyObjectBody::Unoccupied => 0,
            AnyObjectBody::Object(object) => object.marshalled_size(object_version),
            AnyObjectBody::Sequence(sequence) => sequence.marshalled_size(self.attributes),
        };
        8 + 4 + body + 3
    }
}

impl ObjectBody<'_> {
    fn marshalled_size(&self, version: u16) -> u64 {
        let has_private_block = version < 4 || self.sensitive.sensitive_type == public::TPM_ALG_RSA;
        let private_exponent = if has_private_block {
            match &self.private_exponent {
                Some(exponent) => exponent.marshalled_size(),
                None => 8 + 4 * (8 + 2 + 3) + 3,
            }
        } else {
            0
        };
        8 + self.public_wire_len
            + self.sensitive_wire_len
            + 3
            + private_exponent
            + (2 + self.qualified_name.len() as u64)
            + 4
            + (2 + self.name.len() as u64)
            + 3
            + 1
            + 3
            + if version >= 4 { 4 } else { 0 }
    }
}

impl HashObjectBody<'_> {
    fn marshalled_size(&self, attributes: u32) -> u64 {
        let hash_seq = attributes & (ATTR_HASH_SEQ | ATTR_EVENT_SEQ) != 0;
        let hmac_seq = attributes & ATTR_HMAC_SEQ != 0;
        const ZEROED_STATE_SIZE: u64 = 8 + 1 + 2 + (8 + 3) + 3;
        let state = if hash_seq {
            2 + match &self.states {
                Some(states) => states.iter().map(HashState::marshalled_size).sum::<u64>(),
                None => HASH_STATE_COUNT as u64 * ZEROED_STATE_SIZE,
            }
        } else if hmac_seq {
            match &self.hmac_state {
                Some((state, key)) => state.marshalled_size() + 2 + key.len() as u64,
                None => ZEROED_STATE_SIZE + 2,
            }
        } else {
            0
        };
        8 + 2 + 2 + 4 + (2 + self.auth.len() as u64) + state + 3
    }
}

fn parse_hash_object<'a>(
    reader: &mut BlobReader<'a>,
    attributes: u32,
) -> Result<HashObjectBody<'a>, PersistentAllError> {
    const S: StateSection = StateSection::HashObject;
    let header = parse_nv_header(reader, S, HASH_OBJECT_MAGIC, HASH_OBJECT_VERSION)?;

    let object_type = reader.read_u16().map_err(|_| truncated(S))?;
    let name_alg = public::read_hash_alg(reader, S, true)?;
    let object_attributes = reader.read_u32().map_err(|_| truncated(S))?;
    if object_attributes & 0xfff0_f009 != 0 {
        return Err(PersistentAllError::ReservedBitsSet {
            section: S,
            actual: object_attributes,
        });
    }
    let auth = read_tpm2b(reader, S, PersistentField::ObjectAuthValue, DIGEST_SIZE)?;

    let mut states = None;
    let mut hmac_state = None;
    if attributes & ATTR_HASH_SEQ != 0 || (attributes & ATTR_EVENT_SEQ != 0 && header.version >= 3)
    {
        let declared = reader.read_u16().map_err(|_| truncated(S))?;
        if usize::from(declared) != HASH_STATE_COUNT {
            return Err(PersistentAllError::ArraySizeMismatch {
                section: S,
                declared,
                expected: HASH_STATE_COUNT,
            });
        }
        let parsed = [
            parse_hash_state(reader)?,
            parse_hash_state(reader)?,
            parse_hash_state(reader)?,
            parse_hash_state(reader)?,
        ];
        if attributes & ATTR_HASH_SEQ != 0 {
            check_live_state(&parsed[0], false)?;
        } else {
            check_event_states(&parsed)?;
        }
        states = Some(parsed);
    } else if attributes & ATTR_HMAC_SEQ != 0 {
        let state = parse_hash_state(reader)?;
        check_live_state(&state, true)?;
        let key = read_tpm2b(reader, S, PersistentField::HmacKey, 128)?;
        hmac_state = Some((state, key));
    }

    if header.version >= BLOCK_SKIP_SINCE_VERSION {
        read_block(reader, S, false)?;
    }

    Ok(HashObjectBody {
        section_version: header.version,
        object_type,
        name_alg,
        object_attributes,
        auth,
        states,
        hmac_state,
    })
}

fn parse_object<'a>(
    reader: &mut BlobReader<'a>,
    state_format: StateFormatLimit,
) -> Result<ObjectBody<'a>, PersistentAllError> {
    const S: StateSection = StateSection::Object;
    let header = parse_nv_header(reader, S, OBJECT_MAGIC, OBJECT_VERSION)?;

    let start = reader.position();
    let public = parse_tpmt_public(reader, S, true, state_format)?;
    let public_wire_len = (reader.position() - start) as u64;

    let start = reader.position();
    let sensitive = parse_nv_tpmt_sensitive(reader, S)?;
    let sensitive_wire_len = (reader.position() - start) as u64;

    let needs_private = header.version < 4 || sensitive.sensitive_type == TPM_ALG_RSA;
    let private_exponent = match read_block(reader, S, needs_private)? {
        BlockDisposition::Present { .. } if needs_private => Some(parse_private_exponent(reader)?),
        _ => None,
    };

    let qualified_name = read_tpm2b(reader, S, PersistentField::QualifiedName, NAME_SIZE)?;
    let evict_handle = reader.read_u32().map_err(|_| truncated(S))?;
    let name = read_tpm2b(reader, S, PersistentField::ObjectName, NAME_SIZE)?;

    let mut seed_compat_level = SEED_COMPAT_LEVEL_ORIGINAL;
    let mut hierarchy = None;
    if header.version >= BLOCK_SKIP_SINCE_VERSION
        && let BlockDisposition::Present { .. } = read_block(reader, S, header.version >= 3)?
    {
        let level = reader.read_u8().map_err(|_| truncated(S))?;
        if level > SEED_COMPAT_LEVEL_LAST {
            return Err(PersistentAllError::SeedCompatLevelTooNew {
                field: PersistentField::ObjectSeedCompat,
                actual: level,
                supported: SEED_COMPAT_LEVEL_LAST,
            });
        }
        seed_compat_level = level;

        if let BlockDisposition::Present { .. } = read_block(reader, S, header.version >= 4)? {
            let handle = reader.read_u32().map_err(|_| truncated(S))?;
            if !matches!(
                handle,
                TPM_RH_OWNER | TPM_RH_PLATFORM | TPM_RH_ENDORSEMENT | TPM_RH_NULL
            ) {
                return Err(PersistentAllError::InvalidHandleValue {
                    section: S,
                    actual: handle,
                });
            }
            hierarchy = Some(handle);
        }
    }

    Ok(ObjectBody {
        section_version: header.version,
        public,
        public_wire_len,
        sensitive,
        sensitive_wire_len,
        private_exponent,
        qualified_name,
        evict_handle,
        name,
        seed_compat_level,
        hierarchy,
    })
}

pub(super) fn parse_any_object<'a>(
    reader: &mut BlobReader<'a>,
    state_format: StateFormatLimit,
) -> Result<AnyObject<'a>, PersistentAllError> {
    const S: StateSection = StateSection::AnyObject;
    let header = parse_nv_header(reader, S, ANY_OBJECT_MAGIC, ANY_OBJECT_VERSION)?;

    let attributes = reader.read_u32().map_err(|_| truncated(S))?;

    let body = if attributes & ATTR_OCCUPIED == 0 {
        AnyObjectBody::Unoccupied
    } else if AnyObject::is_sequence(attributes) {
        AnyObjectBody::Sequence(Box::new(parse_hash_object(reader, attributes)?))
    } else {
        AnyObjectBody::Object(Box::new(parse_object(reader, state_format)?))
    };

    if header.version >= BLOCK_SKIP_SINCE_VERSION {
        read_block(reader, S, false)?;
    }

    Ok(AnyObject { attributes, body })
}

#[cfg(test)]
pub(super) mod fixtures {
    use super::super::public::fixtures as public_fixtures;
    use super::*;

    pub(in crate::library::tpm2) fn nv_header(
        version: u16,
        magic: u32,
        min_version: u16,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&version.to_be_bytes());
        out.extend_from_slice(&magic.to_be_bytes());
        if version >= 2 {
            out.extend_from_slice(&min_version.to_be_bytes());
        }
        out
    }

    pub(in crate::library::tpm2) fn empty_future_block() -> Vec<u8> {
        vec![0x01, 0x00, 0x00]
    }

    pub(in crate::library::tpm2) fn bn_prime(numbytes: u16) -> Vec<u8> {
        let mut out = nv_header(BN_PRIME_T_VERSION, BN_PRIME_T_MAGIC, 1);
        out.extend_from_slice(&numbytes.to_be_bytes());
        out.extend_from_slice(&vec![0x42; usize::from(numbytes).div_ceil(4) * 4]);
        out.extend_from_slice(&empty_future_block());
        out
    }

    pub(in crate::library::tpm2) fn private_exponent(prime_numbytes: u16) -> Vec<u8> {
        let mut out = nv_header(PRIVATE_EXPONENT_T_VERSION, PRIVATE_EXPONENT_T_MAGIC, 1);
        for _ in 0..4 {
            out.extend_from_slice(&bn_prime(prime_numbytes));
        }
        out.extend_from_slice(&empty_future_block());
        out
    }

    pub(in crate::library::tpm2) fn rsa_object(version: u16) -> Vec<u8> {
        let mut out = nv_header(version, OBJECT_MAGIC, version);
        out.extend_from_slice(&public_fixtures::rsa_public(256));
        out.extend_from_slice(&public_fixtures::rsa_sensitive(128));
        let exponent = private_exponent(96);
        out.push(0x01);
        out.extend_from_slice(&u16::try_from(exponent.len()).unwrap().to_be_bytes());
        out.extend_from_slice(&exponent);
        public_fixtures::push_tpm2b(&mut out, &[0x51; 34]);
        out.extend_from_slice(&0x8100_0001u32.to_be_bytes());
        public_fixtures::push_tpm2b(&mut out, &[0x52; 34]);
        let mut nested = Vec::new();
        if version >= 4 {
            nested.extend_from_slice(&TPM_RH_OWNER.to_be_bytes());
        }
        let mut seed = vec![0x00u8];
        seed.push(0x01);
        seed.extend_from_slice(&u16::try_from(nested.len()).unwrap().to_be_bytes());
        seed.extend_from_slice(&nested);
        out.push(0x01);
        out.extend_from_slice(&u16::try_from(seed.len()).unwrap().to_be_bytes());
        out.extend_from_slice(&seed);
        out
    }

    pub(in crate::library::tpm2) fn any_rsa_object(version: u16) -> Vec<u8> {
        let mut out = nv_header(ANY_OBJECT_VERSION, ANY_OBJECT_MAGIC, 1);
        out.extend_from_slice(&(super::ATTR_OCCUPIED).to_be_bytes());
        out.extend_from_slice(&rsa_object(version));
        out.extend_from_slice(&empty_future_block());
        out
    }

    pub(in crate::library::tpm2) fn public_only_object(public: &[u8]) -> Vec<u8> {
        let mut out = nv_header(4, OBJECT_MAGIC, 4);
        out.extend_from_slice(public);
        out.extend_from_slice(&public_fixtures::public_only_sensitive());
        out.extend_from_slice(&[0x00, 0x00, 0x00]);
        public_fixtures::push_tpm2b(&mut out, &[0x51; 34]);
        out.extend_from_slice(&0x8100_0001u32.to_be_bytes());
        public_fixtures::push_tpm2b(&mut out, &[0x52; 34]);
        let mut nested = Vec::new();
        nested.extend_from_slice(&TPM_RH_OWNER.to_be_bytes());
        let mut seed = vec![0x00u8];
        seed.push(0x01);
        seed.extend_from_slice(&u16::try_from(nested.len()).unwrap().to_be_bytes());
        seed.extend_from_slice(&nested);
        out.push(0x01);
        out.extend_from_slice(&u16::try_from(seed.len()).unwrap().to_be_bytes());
        out.extend_from_slice(&seed);
        out
    }

    pub(in crate::library::tpm2) fn any_public_only_object(public: &[u8]) -> Vec<u8> {
        let mut out = nv_header(ANY_OBJECT_VERSION, ANY_OBJECT_MAGIC, 1);
        out.extend_from_slice(&(super::ATTR_OCCUPIED).to_be_bytes());
        out.extend_from_slice(&public_only_object(public));
        out.extend_from_slice(&empty_future_block());
        out
    }

    pub(in crate::library::tpm2) fn any_unoccupied_object() -> Vec<u8> {
        let mut out = nv_header(ANY_OBJECT_VERSION, ANY_OBJECT_MAGIC, 1);
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&empty_future_block());
        out
    }

    pub(in crate::library::tpm2) fn hash_state(state_type: u8, hash_alg: u16) -> Vec<u8> {
        let mut out = nv_header(HASH_STATE_VERSION, HASH_STATE_MAGIC, 1);
        out.push(state_type);
        out.extend_from_slice(&hash_alg.to_be_bytes());
        out.extend_from_slice(&nv_header(ANY_HASH_STATE_VERSION, ANY_HASH_STATE_MAGIC, 1));
        match hash_alg {
            TPM_ALG_SHA1 => {
                out.extend_from_slice(&nv_header(HASH_STATE_SHA_VERSION, HASH_STATE_SHA1_MAGIC, 1));
                out.extend_from_slice(&[0; 7 * 4]);
                out.extend_from_slice(&64u16.to_be_bytes());
                out.extend_from_slice(&[0; 64]);
                out.extend_from_slice(&[0; 4]);
                out.extend_from_slice(&empty_future_block());
            }
            TPM_ALG_SHA256 => {
                out.extend_from_slice(&nv_header(
                    HASH_STATE_SHA_VERSION,
                    HASH_STATE_SHA256_MAGIC,
                    1,
                ));
                out.extend_from_slice(&8u16.to_be_bytes());
                out.extend_from_slice(&[0; 8 * 4]);
                out.extend_from_slice(&[0; 8]);
                out.extend_from_slice(&64u16.to_be_bytes());
                out.extend_from_slice(&[0; 64]);
                out.extend_from_slice(&[0; 8]);
                out.extend_from_slice(&empty_future_block());
            }
            TPM_ALG_SHA384 | TPM_ALG_SHA512 => {
                let magic = if hash_alg == TPM_ALG_SHA384 {
                    HASH_STATE_SHA384_MAGIC
                } else {
                    HASH_STATE_SHA512_MAGIC
                };
                out.extend_from_slice(&nv_header(HASH_STATE_SHA_VERSION, magic, 1));
                out.extend_from_slice(&8u16.to_be_bytes());
                out.extend_from_slice(&[0; 8 * 8]);
                out.extend_from_slice(&[0; 16]);
                out.extend_from_slice(&128u16.to_be_bytes());
                out.extend_from_slice(&[0; 128]);
                out.extend_from_slice(&[0; 8]);
                out.extend_from_slice(&empty_future_block());
            }
            _ => {}
        }
        out.extend_from_slice(&empty_future_block());
        out.extend_from_slice(&empty_future_block());
        out
    }

    pub(in crate::library::tpm2) fn hash_object(attributes: u32) -> Vec<u8> {
        let mut out = nv_header(HASH_OBJECT_VERSION, HASH_OBJECT_MAGIC, 1);
        out.extend_from_slice(&TPM_ALG_RSA.to_be_bytes());
        out.extend_from_slice(&0x0010u16.to_be_bytes());
        out.extend_from_slice(&0x0000_0002u32.to_be_bytes());
        public_fixtures::push_tpm2b(&mut out, &[]);
        if attributes & ATTR_EVENT_SEQ != 0 && attributes & ATTR_HASH_SEQ == 0 {
            out.extend_from_slice(&(HASH_STATE_COUNT as u16).to_be_bytes());
            for &(alg, _) in COMPILED_HASHES.iter() {
                out.extend_from_slice(&hash_state(HASH_STATE_HASH, alg));
            }
        } else if attributes & ATTR_HASH_SEQ != 0 {
            out.extend_from_slice(&(HASH_STATE_COUNT as u16).to_be_bytes());
            for (state_type, alg) in [
                (HASH_STATE_HASH, TPM_ALG_SHA1),
                (HASH_STATE_HASH, TPM_ALG_SHA256),
                (HASH_STATE_EMPTY, 0x0000),
                (HASH_STATE_EMPTY, 0x0000),
            ] {
                out.extend_from_slice(&hash_state(state_type, alg));
            }
        } else if attributes & ATTR_HMAC_SEQ != 0 {
            out.extend_from_slice(&hash_state(HASH_STATE_HMAC, TPM_ALG_SHA256));
            public_fixtures::push_tpm2b(&mut out, &[0x66; 32]);
        }
        out.extend_from_slice(&empty_future_block());
        out
    }

    pub(in crate::library::tpm2) fn any_sequence_object(sequence_bits: u32) -> Vec<u8> {
        let attributes = ATTR_OCCUPIED | sequence_bits;
        let mut out = nv_header(ANY_OBJECT_VERSION, ANY_OBJECT_MAGIC, 1);
        out.extend_from_slice(&attributes.to_be_bytes());
        out.extend_from_slice(&hash_object(attributes));
        out.extend_from_slice(&empty_future_block());
        out
    }

    pub(in crate::library::tpm2) const SEQ_HASH: u32 = ATTR_HASH_SEQ;
    pub(in crate::library::tpm2) const SEQ_HMAC: u32 = ATTR_HMAC_SEQ;
    pub(in crate::library::tpm2) const SEQ_EVENT: u32 = ATTR_EVENT_SEQ;
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use crate::library::constants::{TPM_RC_INSUFFICIENT, TPM_RC_SIZE, TPM_RC_VALUE};

    fn parse(data: &[u8]) -> Result<AnyObject<'_>, PersistentAllError> {
        let mut reader = BlobReader::new(data);
        let object = parse_any_object(&mut reader, StateFormatLimit::CURRENT)?;
        assert_eq!(reader.remaining(), &[] as &[u8], "exact consumption");
        Ok(object)
    }

    #[test]
    fn occupied_rsa_object_decodes() {
        let data = any_rsa_object(4);
        let object = parse(&data).unwrap();
        assert!(object.occupied());
        assert_eq!(object.public_type(), Some(TPM_ALG_RSA));
        let AnyObjectBody::Object(body) = &object.body else {
            panic!("expected ordinary object");
        };
        assert_eq!(body.section_version, 4);
        assert_eq!(body.evict_handle, 0x8100_0001);
        assert_eq!(body.qualified_name.len(), 34);
        assert_eq!(body.name.len(), 34);
        assert_eq!(body.seed_compat_level, 0);
        assert_eq!(body.hierarchy, Some(0x4000_0001));
        let exponent = body.private_exponent.as_ref().unwrap();
        assert_eq!(exponent.primes[0].numbytes, 96);
        assert_eq!(exponent.primes[0].size_words(), 12);
    }

    #[test]
    fn version_3_object_has_no_hierarchy() {
        let data = any_rsa_object(3);
        let object = parse(&data).unwrap();
        let AnyObjectBody::Object(body) = &object.body else {
            panic!("expected ordinary object");
        };
        assert_eq!(body.section_version, 3);
        assert_eq!(body.hierarchy, None);
    }

    #[test]
    fn unoccupied_object_reads_no_body() {
        let data = any_unoccupied_object();
        let object = parse(&data).unwrap();
        assert!(!object.occupied());
        assert!(matches!(object.body, AnyObjectBody::Unoccupied));
        assert_eq!(object.public_type(), None);
        for object_version in [3u16, 4] {
            assert_eq!(object.marshalled_size(object_version), 15);
        }
    }

    #[test]
    fn hash_sequence_object_decodes_states() {
        let data = any_sequence_object(SEQ_HASH);
        let object = parse(&data).unwrap();
        let AnyObjectBody::Sequence(body) = &object.body else {
            panic!("expected sequence object");
        };
        let states = body.states.as_ref().unwrap();
        assert_eq!(states[0].hash_alg, TPM_ALG_SHA1);
        assert!(states[0].payload.is_some());
        assert_eq!(states[1].hash_alg, TPM_ALG_SHA256);
        assert!(states[2].payload.is_none(), "raw alg 0 has no payload");
        assert!(body.hmac_state.is_none());
    }

    #[test]
    fn hmac_sequence_object_decodes_state_and_key() {
        let data = any_sequence_object(SEQ_HMAC);
        let object = parse(&data).unwrap();
        let AnyObjectBody::Sequence(body) = &object.body else {
            panic!("expected sequence object");
        };
        assert!(body.states.is_none());
        let (state, key) = body.hmac_state.as_ref().unwrap();
        assert_eq!(state.hash_alg, TPM_ALG_SHA256);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn event_sequence_object_reads_states_at_version_3() {
        let data = any_sequence_object(SEQ_EVENT);
        let object = parse(&data).unwrap();
        let AnyObjectBody::Sequence(body) = &object.body else {
            panic!("expected sequence object");
        };
        assert!(body.states.is_some());
    }

    fn typed_hash_state(state_type: u8, hash_alg: u16) -> Vec<u8> {
        hash_state(state_type, hash_alg)
    }

    fn sequence_with_states(attributes: u32, states: &[(u8, u16); HASH_STATE_COUNT]) -> Vec<u8> {
        let mut body = nv_header(HASH_OBJECT_VERSION, HASH_OBJECT_MAGIC, 1);
        body.extend_from_slice(&TPM_ALG_RSA.to_be_bytes());
        body.extend_from_slice(&0x0010u16.to_be_bytes());
        body.extend_from_slice(&0x0000_0002u32.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&(HASH_STATE_COUNT as u16).to_be_bytes());
        for &(state_type, hash_alg) in states {
            body.extend_from_slice(&typed_hash_state(state_type, hash_alg));
        }
        body.extend_from_slice(&empty_future_block());
        let mut out = nv_header(ANY_OBJECT_VERSION, ANY_OBJECT_MAGIC, 1);
        out.extend_from_slice(&attributes.to_be_bytes());
        out.extend_from_slice(&body);
        out.extend_from_slice(&empty_future_block());
        out
    }

    fn mac_sequence(state_type: u8, hash_alg: u16) -> Vec<u8> {
        let mut body = nv_header(HASH_OBJECT_VERSION, HASH_OBJECT_MAGIC, 1);
        body.extend_from_slice(&TPM_ALG_RSA.to_be_bytes());
        body.extend_from_slice(&0x0010u16.to_be_bytes());
        body.extend_from_slice(&0x0000_0002u32.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&typed_hash_state(state_type, hash_alg));
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&empty_future_block());
        let mut out = nv_header(ANY_OBJECT_VERSION, ANY_OBJECT_MAGIC, 1);
        out.extend_from_slice(&(ATTR_OCCUPIED | ATTR_HMAC_SEQ).to_be_bytes());
        out.extend_from_slice(&body);
        out.extend_from_slice(&empty_future_block());
        out
    }

    #[test]
    fn every_live_sequence_state_combination_is_accepted() {
        for hash_alg in [TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512] {
            let data = sequence_with_states(
                ATTR_OCCUPIED | ATTR_HASH_SEQ,
                &[
                    (HASH_STATE_HASH, hash_alg),
                    (HASH_STATE_EMPTY, 0),
                    (HASH_STATE_EMPTY, 0),
                    (HASH_STATE_EMPTY, 0),
                ],
            );
            parse(&data).unwrap_or_else(|error| panic!("hash {hash_alg:#06x}: {error:?}"));
            let data = mac_sequence(HASH_STATE_HMAC, hash_alg);
            parse(&data).unwrap_or_else(|error| panic!("hmac {hash_alg:#06x}: {error:?}"));
        }
        parse(&mac_sequence(HASH_STATE_SMAC, 0)).expect("a symmetric mac sequence");
    }

    #[test]
    fn unused_hash_state_slots_may_hold_uninitialised_bytes() {
        let data = sequence_with_states(
            ATTR_OCCUPIED | ATTR_HASH_SEQ,
            &[
                (HASH_STATE_HASH, TPM_ALG_SHA1),
                (246, 0x6cd2),
                (166, 0xa859),
                (HASH_STATE_EMPTY, 0),
            ],
        );
        let object = parse(&data).expect("the reference leaves stale slots behind");
        let AnyObjectBody::Sequence(body) = &object.body else {
            panic!("expected sequence object");
        };
        let states = body.states.as_ref().expect("four states");
        assert_eq!(states[1].state_type, 246);
        assert!(states[1].payload.is_none());
    }

    #[test]
    fn an_unusable_live_sequence_state_is_rejected() {
        for (attributes, states) in [
            (
                ATTR_OCCUPIED | ATTR_HASH_SEQ,
                [
                    (HASH_STATE_HMAC, TPM_ALG_SHA256),
                    (HASH_STATE_EMPTY, 0),
                    (HASH_STATE_EMPTY, 0),
                    (HASH_STATE_EMPTY, 0),
                ],
            ),
            (
                ATTR_OCCUPIED | ATTR_HASH_SEQ,
                [
                    (HASH_STATE_HASH, 0x0010),
                    (HASH_STATE_EMPTY, 0),
                    (HASH_STATE_EMPTY, 0),
                    (HASH_STATE_EMPTY, 0),
                ],
            ),
            (
                ATTR_OCCUPIED | ATTR_HASH_SEQ,
                [
                    (HASH_STATE_EMPTY, 0),
                    (HASH_STATE_EMPTY, 0),
                    (HASH_STATE_EMPTY, 0),
                    (HASH_STATE_EMPTY, 0),
                ],
            ),
        ] {
            let data = sequence_with_states(attributes, &states);
            let mut reader = BlobReader::new(&data);
            let error = parse_any_object(&mut reader, StateFormatLimit::CURRENT).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::InvalidHashAlgorithm {
                    section: SECTION_HASH_STATE,
                    actual: states[0].1,
                },
                "states {states:?}"
            );
            assert_eq!(error.tpm_result(), crate::library::constants::TPM_RC_HASH);
        }
        for (state_type, hash_alg) in [
            (HASH_STATE_HASH, TPM_ALG_SHA256),
            (HASH_STATE_HMAC, 0x0000),
            (HASH_STATE_HMAC, 0x0012),
            (HASH_STATE_SMAC, TPM_ALG_SHA256),
            (HASH_STATE_EMPTY, 0),
            (4, 0),
        ] {
            let data = mac_sequence(state_type, hash_alg);
            let mut reader = BlobReader::new(&data);
            let error = parse_any_object(&mut reader, StateFormatLimit::CURRENT).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::InvalidHashAlgorithm {
                    section: SECTION_HASH_STATE,
                    actual: hash_alg,
                },
                "type {state_type} alg {hash_alg:#06x}"
            );
        }
    }

    #[test]
    fn a_truncated_hash_state_payload_is_insufficient() {
        let full = typed_hash_state(HASH_STATE_HASH, TPM_ALG_SHA256);
        for length in 0..full.len() {
            let mut reader = BlobReader::new(&full[..length]);
            assert!(
                matches!(
                    parse_hash_state(&mut reader),
                    Err(PersistentAllError::Truncated { .. }
                        | PersistentAllError::MissingRequiredBlock { .. })
                ),
                "prefix {length}"
            );
        }
    }

    fn event_banks() -> [(u8, u16); HASH_STATE_COUNT] {
        core::array::from_fn(|index| (HASH_STATE_HASH, COMPILED_HASHES[index].0))
    }

    fn event_sequence(states: &[(u8, u16); HASH_STATE_COUNT]) -> Vec<u8> {
        sequence_with_states(ATTR_OCCUPIED | ATTR_EVENT_SEQ, states)
    }

    #[test]
    fn an_event_sequence_needs_every_compiled_bank_in_order() {
        let data = event_sequence(&event_banks());
        let object = parse(&data).expect("all four banks in the compiled order");
        let AnyObjectBody::Sequence(body) = &object.body else {
            panic!("expected sequence object");
        };
        let states = body.states.as_ref().expect("four states");
        for (index, &(hash_alg, _)) in COMPILED_HASHES.iter().enumerate() {
            assert_eq!(states[index].hash_alg, hash_alg);
            assert_eq!(states[index].state_type, HASH_STATE_HASH);
            assert!(states[index].payload.is_some());
        }
    }

    #[test]
    fn a_malformed_event_bank_is_rejected_before_the_object_exists() {
        let sha1 = COMPILED_HASHES[0].0;
        let sha256 = COMPILED_HASHES[1].0;
        let sha384 = COMPILED_HASHES[2].0;
        let sha512 = COMPILED_HASHES[3].0;
        let mut cases: Vec<(&str, [(u8, u16); HASH_STATE_COUNT], u16)> = Vec::new();

        let mut banks = event_banks();
        banks[0] = (HASH_STATE_HMAC, sha1);
        cases.push(("an hmac state in the first bank", banks, sha1));

        let mut banks = event_banks();
        banks[2] = (HASH_STATE_SMAC, sha384);
        cases.push(("a symmetric mac state in a middle bank", banks, sha384));

        let mut banks = event_banks();
        banks[3] = (HASH_STATE_HMAC, sha512);
        cases.push(("an hmac state in the last bank", banks, sha512));

        let mut banks = event_banks();
        banks[1] = (HASH_STATE_HASH, 0x0012);
        cases.push(("an unknown algorithm", banks, 0x0012));

        let mut banks = event_banks();
        banks.swap(1, 2);
        cases.push(("two swapped banks", banks, sha384));

        let mut banks = event_banks();
        banks[2] = (HASH_STATE_HASH, sha256);
        cases.push(("a duplicated algorithm", banks, sha256));

        let mut banks = event_banks();
        banks[1] = (HASH_STATE_EMPTY, 0);
        cases.push(("an empty bank", banks, 0));

        let mut banks = event_banks();
        banks[3] = (HASH_STATE_HASH, 0);
        cases.push(("a bank without a payload", banks, 0));

        for (what, banks, actual) in cases {
            let data = event_sequence(&banks);
            let mut reader = BlobReader::new(&data);
            let error = parse_any_object(&mut reader, StateFormatLimit::CURRENT).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::InvalidHashAlgorithm {
                    section: SECTION_HASH_STATE,
                    actual,
                },
                "{what}"
            );
            assert_eq!(error.tpm_result(), crate::library::constants::TPM_RC_HASH);
        }
    }

    #[test]
    fn a_truncated_event_bank_payload_is_insufficient() {
        let full = event_sequence(&event_banks());
        let complete = {
            let mut reader = BlobReader::new(&full);
            parse_any_object(&mut reader, StateFormatLimit::CURRENT).expect("a valid sequence");
            full.len() - reader.remaining().len()
        };
        for length in (complete - 200..complete).step_by(7) {
            let mut reader = BlobReader::new(&full[..length]);
            assert!(
                matches!(
                    parse_any_object(&mut reader, StateFormatLimit::CURRENT),
                    Err(PersistentAllError::Truncated { .. }
                        | PersistentAllError::MissingRequiredBlock { .. })
                ),
                "prefix {length} of {complete}"
            );
        }
    }

    #[test]
    fn wrong_hash_state_count_is_a_size_error() {
        let mut data = any_sequence_object(SEQ_HASH);
        let offset = 8 + 4 + 8 + 2 + 2 + 4 + 2;
        data[offset..offset + 2].copy_from_slice(&3u16.to_be_bytes());
        let mut reader = BlobReader::new(&data);
        let error = parse_any_object(&mut reader, StateFormatLimit::CURRENT).unwrap_err();
        assert_eq!(
            error,
            PersistentAllError::ArraySizeMismatch {
                section: StateSection::HashObject,
                declared: 3,
                expected: HASH_STATE_COUNT,
            }
        );
        assert_eq!(error.tpm_result(), TPM_RC_SIZE);
    }

    #[test]
    fn oversized_bn_prime_is_a_size_error() {
        for numbytes in [193u16, 200, u16::MAX] {
            let data = bn_prime(numbytes);
            let mut reader = BlobReader::new(&data);
            let error = parse_bn_prime(&mut reader).unwrap_err();
            assert_eq!(error.tpm_result(), TPM_RC_SIZE, "numbytes {numbytes}");
        }
        let data = bn_prime(192);
        let mut reader = BlobReader::new(&data);
        assert!(parse_bn_prime(&mut reader).is_ok());
    }

    #[test]
    fn bn_prime_word_rounding_matches_upstream() {
        let data = bn_prime(5);
        let mut reader = BlobReader::new(&data);
        let prime = parse_bn_prime(&mut reader).unwrap();
        assert_eq!(prime.data.len(), 8);
        assert_eq!(prime.size_words(), 1);
        assert_eq!(prime.marshalled_size(), 8 + 2 + 8 + 3);
    }

    #[test]
    fn invalid_hierarchy_handle_is_rc_value() {
        let mut data = any_rsa_object(4);
        let len = data.len();
        data[len - 7..len - 3].copy_from_slice(&0x4000_0002u32.to_be_bytes());
        let mut reader = BlobReader::new(&data);
        let error = parse_any_object(&mut reader, StateFormatLimit::CURRENT).unwrap_err();
        assert_eq!(
            error,
            PersistentAllError::InvalidHandleValue {
                section: StateSection::Object,
                actual: 0x4000_0002,
            }
        );
        assert_eq!(error.tpm_result(), TPM_RC_VALUE);
    }

    #[test]
    fn all_valid_hierarchy_handles_are_accepted() {
        for handle in [
            TPM_RH_OWNER,
            TPM_RH_PLATFORM,
            TPM_RH_ENDORSEMENT,
            TPM_RH_NULL,
        ] {
            let mut data = any_rsa_object(4);
            let len = data.len();
            data[len - 7..len - 3].copy_from_slice(&handle.to_be_bytes());
            let object = parse(&data).unwrap();
            let AnyObjectBody::Object(body) = &object.body else {
                panic!("expected ordinary object");
            };
            assert_eq!(body.hierarchy, Some(handle), "handle {handle:#010x}");
        }
    }

    #[test]
    fn marshalled_size_matches_wire_size_for_a_current_object() {
        for version in [3u16, 4] {
            let data = any_rsa_object(version);
            let object = parse(&data).unwrap();
            assert_eq!(
                object.marshalled_size(version),
                data.len() as u64,
                "version {version}"
            );
        }
        for bits in [SEQ_HASH, SEQ_HMAC] {
            let data = any_sequence_object(bits);
            let object = parse(&data).unwrap();
            for object_version in [3u16, 4] {
                assert_eq!(
                    object.marshalled_size(object_version),
                    data.len() as u64,
                    "bits {bits:#x}"
                );
            }
        }
    }

    #[test]
    fn remarshal_version_changes_the_private_exponent_accounting() {
        let data = any_rsa_object(3);
        let object = parse(&data).unwrap();
        assert_eq!(
            object.marshalled_size(4),
            object.marshalled_size(3) + 4,
            "RSA keeps the exponent block; v4 adds the hierarchy field"
        );
    }

    #[test]
    fn marshalled_size_rounds_partial_primes_up() {
        let mut out = nv_header(ANY_OBJECT_VERSION, ANY_OBJECT_MAGIC, 1);
        out.extend_from_slice(&ATTR_OCCUPIED.to_be_bytes());
        let mut object = nv_header(4, OBJECT_MAGIC, 4);
        object.extend_from_slice(&super::super::public::fixtures::rsa_public(16));
        object.extend_from_slice(&super::super::public::fixtures::rsa_sensitive(16));
        let exponent = private_exponent(3);
        object.push(0x01);
        object.extend_from_slice(&u16::try_from(exponent.len()).unwrap().to_be_bytes());
        object.extend_from_slice(&exponent);
        super::super::public::fixtures::push_tpm2b(&mut object, &[]);
        object.extend_from_slice(&0x8100_0001u32.to_be_bytes());
        super::super::public::fixtures::push_tpm2b(&mut object, &[]);
        object.push(0x01);
        object.extend_from_slice(&8u16.to_be_bytes());
        object.push(0x00);
        object.extend_from_slice(&[0x01, 0x00, 0x04]);
        object.extend_from_slice(&TPM_RH_OWNER.to_be_bytes());
        out.extend_from_slice(&object);
        out.extend_from_slice(&empty_future_block());
        let parsed = parse(&out).unwrap();
        assert_eq!(
            parsed.marshalled_size(4),
            out.len() as u64 + 4 * 4,
            "each of the four primes re-marshals 4 bytes larger"
        );
    }

    #[test]
    fn truncation_at_every_boundary_is_insufficient() {
        let full = any_rsa_object(4);
        for len in 0..full.len() {
            let mut reader = BlobReader::new(&full[..len]);
            let error = parse_any_object(&mut reader, StateFormatLimit::CURRENT).unwrap_err();
            assert_eq!(
                error.tpm_result(),
                TPM_RC_INSUFFICIENT,
                "prefix length {len} of {}",
                full.len()
            );
        }
    }

    #[test]
    fn malformed_input_never_panics() {
        for full in [
            any_rsa_object(3),
            any_rsa_object(4),
            any_sequence_object(SEQ_HASH),
            any_sequence_object(SEQ_HMAC),
            any_unoccupied_object(),
        ] {
            for index in 0..full.len() {
                for byte in [0x00u8, 0x01, 0xff] {
                    let mut data = full.clone();
                    data[index] = byte;
                    let mut reader = BlobReader::new(&data);
                    let _ = parse_any_object(&mut reader, StateFormatLimit::CURRENT);
                }
            }
        }
    }
}
