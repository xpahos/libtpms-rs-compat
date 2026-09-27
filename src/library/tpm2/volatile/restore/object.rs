use crate::library::tpm2::hierarchy::{
    TPM_RH_ENDORSEMENT, TPM_RH_NULL, TPM_RH_OWNER, TPM_RH_PLATFORM,
};
use crate::library::tpm2::marshal::BlobReader;
use crate::library::tpm2::object::{
    ANY_HASH_STATE_MAGIC, ANY_HASH_STATE_VERSION, ANY_OBJECT_MAGIC, ANY_OBJECT_VERSION,
    ATTR_EVENT_SEQ, ATTR_HASH_SEQ, ATTR_HMAC_SEQ, ATTR_OCCUPIED, BN_PRIME_T_MAGIC,
    BN_PRIME_T_VERSION, BN_PRIME_WORDS, CRYPT_UWORD_BYTES, HASH_OBJECT_MAGIC, HASH_OBJECT_VERSION,
    HASH_STATE_COUNT, HASH_STATE_MAGIC, HASH_STATE_SHA_VERSION, HASH_STATE_SHA1_MAGIC,
    HASH_STATE_SHA256_MAGIC, HASH_STATE_SHA384_MAGIC, HASH_STATE_SHA512_MAGIC, HASH_STATE_SMAC,
    HASH_STATE_VERSION, OBJECT_MAGIC, OBJECT_VERSION, PRIVATE_EXPONENT_T_MAGIC,
    PRIVATE_EXPONENT_T_VERSION, SEED_COMPAT_LEVEL_LAST, SEED_COMPAT_LEVEL_ORIGINAL,
    event_state_is_usable, hash_state_is_usable, peek_u16,
};
use crate::library::tpm2::persistent::{
    OwnedAnyObject, OwnedAnyObjectBody, OwnedBnPrime, OwnedHashObjectBody, OwnedHashPayload,
    OwnedHashState, OwnedObjectBody, OwnedPrivateExponent, OwnedPublicId, OwnedSecret,
    OwnedTpmtPublic, OwnedTpmtSensitive, StateSection,
};
use crate::library::tpm2::public::{
    DIGEST_SIZE, MAX_ECC_KEY_BYTES, MAX_RSA_KEY_BYTES, MAX_SYM_DATA, MAX_SYM_KEY_BYTES, NAME_SIZE,
    PublicParms, RSA_PRIVATE_SIZE, Scheme, SchemeKind, StateFormatLimit, SymDefObject, TPM_ALG_ECC,
    TPM_ALG_KEYEDHASH, TPM_ALG_NULL, TPM_ALG_RSA, TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384,
    TPM_ALG_SHA512, TPM_ALG_SYMCIPHER, TPM_ALG_XOR, ecc_curve_valid, is_hash_alg, is_public_type,
    is_sym_algorithm, is_sym_mode, object_attributes_valid, rsa_key_bits_valid, sym_key_bits_valid,
};

use super::{Defect, Step, block, header, secret_into, tpm2b_into};

const HMAC_KEY_SIZE: usize = 128;
const OBJECT_V3_BLOCK_SINCE_VERSION: u16 = 3;
const OBJECT_V4_BLOCK_SINCE_VERSION: u16 = 4;
const OBJECT_BLOCKS_SINCE_VERSION: u16 = 2;
const HASH_OBJECT_EVENT_STATES_SINCE_VERSION: u16 = 3;

fn u8_from(reader: &mut BlobReader<'_>) -> Step<u8> {
    reader.read_u8().map_err(|_| Defect)
}

fn u16_from(reader: &mut BlobReader<'_>) -> Step<u16> {
    reader.read_u16().map_err(|_| Defect)
}

fn u32_from(reader: &mut BlobReader<'_>) -> Step<u32> {
    reader.read_u32().map_err(|_| Defect)
}

fn u64_from(reader: &mut BlobReader<'_>) -> Step<u64> {
    reader.read_u64().map_err(|_| Defect)
}

fn empty_secret() -> OwnedSecret {
    OwnedSecret::from_vec(Vec::new())
}

fn unset_object() -> OwnedObjectBody {
    OwnedObjectBody {
        section_version: 0,
        public: OwnedTpmtPublic {
            object_type: 0,
            name_alg: 0,
            object_attributes: 0,
            auth_policy: Vec::new(),
            parameters: PublicParms::Unselected,
            unique: OwnedPublicId::Unselected,
        },
        sensitive: OwnedTpmtSensitive {
            sensitive_type: 0,
            auth_value: empty_secret(),
            seed_value: empty_secret(),
            sensitive: None,
        },
        private_exponent: None,
        qualified_name: Vec::new(),
        evict_handle: 0,
        name: Vec::new(),
        seed_compat_level: SEED_COMPAT_LEVEL_ORIGINAL,
        hierarchy: None,
    }
}

fn unset_sequence() -> OwnedHashObjectBody {
    OwnedHashObjectBody {
        section_version: 0,
        object_type: 0,
        name_alg: 0,
        object_attributes: 0,
        auth: empty_secret(),
        states: None,
        hmac_state: None,
        cmac: None,
    }
}

fn unset_hash_state() -> OwnedHashState {
    OwnedHashState {
        state_type: 0,
        hash_alg: 0,
        payload: None,
    }
}

fn unset_prime() -> OwnedBnPrime {
    OwnedBnPrime {
        numbytes: 0,
        data: empty_secret(),
    }
}

fn take_object(slot: &mut OwnedAnyObject) -> Box<OwnedObjectBody> {
    match core::mem::replace(&mut slot.body, OwnedAnyObjectBody::Unoccupied) {
        OwnedAnyObjectBody::Object(body) => body,
        _ => Box::new(unset_object()),
    }
}

fn take_sequence(slot: &mut OwnedAnyObject) -> Box<OwnedHashObjectBody> {
    match core::mem::replace(&mut slot.body, OwnedAnyObjectBody::Unoccupied) {
        OwnedAnyObjectBody::Sequence(body) => body,
        _ => Box::new(unset_sequence()),
    }
}

fn is_sequence(attributes: u32) -> bool {
    attributes & (ATTR_HMAC_SEQ | ATTR_HASH_SEQ | ATTR_EVENT_SEQ) != 0
}

fn resumable(slot: &OwnedAnyObject) -> bool {
    if slot.attributes & (ATTR_OCCUPIED | ATTR_HMAC_SEQ) != ATTR_OCCUPIED | ATTR_HMAC_SEQ {
        return true;
    }
    let OwnedAnyObjectBody::Sequence(sequence) = &slot.body else {
        return true;
    };
    sequence
        .hmac_state
        .as_ref()
        .is_none_or(|(state, _)| state.state_type != HASH_STATE_SMAC)
}

pub(super) fn any_object_into(
    reader: &mut BlobReader<'_>,
    slot: &mut OwnedAnyObject,
    state_format: StateFormatLimit,
) -> Step {
    let version = header(
        reader,
        StateSection::AnyObject,
        ANY_OBJECT_MAGIC,
        ANY_OBJECT_VERSION,
    )?;
    slot.attributes = u32_from(reader)?;
    if slot.attributes & ATTR_OCCUPIED != 0 {
        if is_sequence(slot.attributes) {
            let mut body = take_sequence(slot);
            let outcome = hash_object_into(reader, slot.attributes, &mut body);
            slot.body = OwnedAnyObjectBody::Sequence(body);
            outcome?;
        } else {
            let mut body = take_object(slot);
            let outcome = object_into(reader, &mut body, state_format);
            slot.body = OwnedAnyObjectBody::Object(body);
            outcome?;
        }
    }
    if version >= OBJECT_BLOCKS_SINCE_VERSION {
        block(reader, false)?;
    }
    if resumable(slot) { Ok(()) } else { Err(Defect) }
}

fn object_into(
    reader: &mut BlobReader<'_>,
    body: &mut OwnedObjectBody,
    state_format: StateFormatLimit,
) -> Step {
    let outcome = object_fields_into(reader, body, state_format);
    body.seed_compat_level = SEED_COMPAT_LEVEL_ORIGINAL;
    body.hierarchy = None;
    let version = outcome?;
    if version < OBJECT_BLOCKS_SINCE_VERSION
        || !block(reader, version >= OBJECT_V3_BLOCK_SINCE_VERSION)?
    {
        return Ok(());
    }
    body.seed_compat_level = u8_from(reader)?;
    if body.seed_compat_level > SEED_COMPAT_LEVEL_LAST {
        return Err(Defect);
    }
    if !block(reader, version >= OBJECT_V4_BLOCK_SINCE_VERSION)? {
        return Ok(());
    }
    let hierarchy = u32_from(reader)?;
    if !matches!(
        hierarchy,
        TPM_RH_OWNER | TPM_RH_PLATFORM | TPM_RH_ENDORSEMENT | TPM_RH_NULL
    ) {
        return Err(Defect);
    }
    body.hierarchy = Some(hierarchy);
    Ok(())
}

fn object_fields_into(
    reader: &mut BlobReader<'_>,
    body: &mut OwnedObjectBody,
    state_format: StateFormatLimit,
) -> Step<u16> {
    let version = header(reader, StateSection::Object, OBJECT_MAGIC, OBJECT_VERSION)?;
    body.section_version = version;
    public_into(reader, &mut body.public, state_format)?;
    sensitive_into(reader, &mut body.sensitive)?;
    let needs_private = version < 4 || body.sensitive.sensitive_type == TPM_ALG_RSA;
    if block(reader, needs_private)? {
        let exponent = body
            .private_exponent
            .get_or_insert_with(|| OwnedPrivateExponent {
                primes: core::array::from_fn(|_| unset_prime()),
            });
        private_exponent_into(reader, exponent)?;
    }
    tpm2b_into(reader, NAME_SIZE, &mut body.qualified_name)?;
    body.evict_handle = u32_from(reader)?;
    tpm2b_into(reader, NAME_SIZE, &mut body.name)?;
    Ok(version)
}

fn unique_selected_by(object_type: u16) -> OwnedPublicId {
    match object_type {
        TPM_ALG_KEYEDHASH => OwnedPublicId::KeyedHash(Vec::new()),
        TPM_ALG_SYMCIPHER => OwnedPublicId::Sym(Vec::new()),
        TPM_ALG_RSA => OwnedPublicId::Rsa(Vec::new()),
        TPM_ALG_ECC => OwnedPublicId::Ecc {
            x: Vec::new(),
            y: Vec::new(),
        },
        _ => OwnedPublicId::Unselected,
    }
}

fn public_into(
    reader: &mut BlobReader<'_>,
    public: &mut OwnedTpmtPublic,
    state_format: StateFormatLimit,
) -> Step {
    let object_type = u16_from(reader)?;
    if !is_public_type(object_type) {
        return Err(Defect);
    }
    public.object_type = object_type;
    public.parameters = PublicParms::selected_by(object_type);
    public.unique = unique_selected_by(object_type);
    let name_alg = u16_from(reader)?;
    if !is_hash_alg(name_alg, true) {
        return Err(Defect);
    }
    public.name_alg = name_alg;
    let object_attributes = u32_from(reader)?;
    if !object_attributes_valid(object_attributes) {
        return Err(Defect);
    }
    public.object_attributes = object_attributes;
    tpm2b_into(reader, DIGEST_SIZE, &mut public.auth_policy)?;
    parameters_into(reader, &mut public.parameters, state_format)?;
    match &mut public.unique {
        OwnedPublicId::KeyedHash(bytes) | OwnedPublicId::Sym(bytes) => {
            tpm2b_into(reader, DIGEST_SIZE, bytes)
        }
        OwnedPublicId::Rsa(bytes) => tpm2b_into(reader, MAX_RSA_KEY_BYTES, bytes),
        OwnedPublicId::Ecc { x, y } => {
            let (mut new_x, mut new_y) = (x.clone(), y.clone());
            tpm2b_into(reader, MAX_ECC_KEY_BYTES, &mut new_x)?;
            tpm2b_into(reader, MAX_ECC_KEY_BYTES, &mut new_y)?;
            (*x, *y) = (new_x, new_y);
            Ok(())
        }
        OwnedPublicId::Unselected => Err(Defect),
    }
}

fn parameters_into(
    reader: &mut BlobReader<'_>,
    parameters: &mut PublicParms,
    state_format: StateFormatLimit,
) -> Step {
    match parameters {
        PublicParms::KeyedHash(scheme) => scheme_into(reader, scheme, SchemeKind::KeyedHash, true),
        PublicParms::SymCipher(sym) => sym_def_into(reader, sym, false, false, state_format),
        PublicParms::Rsa {
            symmetric,
            scheme,
            key_bits,
            exponent,
        } => {
            sym_def_into(reader, symmetric, false, true, state_format)?;
            scheme_into(reader, scheme, SchemeKind::Rsa, true)?;
            let bits = u16_from(reader)?;
            if !rsa_key_bits_valid(bits, state_format) {
                return Err(Defect);
            }
            *key_bits = bits;
            *exponent = u32_from(reader)?;
            Ok(())
        }
        PublicParms::Ecc { .. } => {
            let mut working = *parameters;
            let PublicParms::Ecc {
                symmetric,
                scheme,
                curve_id,
                kdf,
            } = &mut working
            else {
                return Err(Defect);
            };
            sym_def_into(reader, symmetric, false, true, state_format)?;
            scheme_into(reader, scheme, SchemeKind::Ecc, true)?;
            let curve = u16_from(reader)?;
            if !ecc_curve_valid(curve, state_format) {
                return Err(Defect);
            }
            *curve_id = curve;
            scheme_into(reader, kdf, SchemeKind::Kdf, true)?;
            *parameters = working;
            Ok(())
        }
        PublicParms::Unselected => Err(Defect),
    }
}

pub(super) fn sym_def_into(
    reader: &mut BlobReader<'_>,
    sym: &mut SymDefObject,
    with_xor: bool,
    allow_null: bool,
    state_format: StateFormatLimit,
) -> Step {
    let algorithm = u16_from(reader)?;
    if !is_sym_algorithm(algorithm, with_xor, allow_null) {
        return Err(Defect);
    }
    sym.select(algorithm);
    match algorithm {
        TPM_ALG_NULL => return Ok(()),
        TPM_ALG_XOR => {
            let hash_alg = u16_from(reader)?;
            if !is_hash_alg(hash_alg, false) {
                return Err(Defect);
            }
            sym.key_bits = Some(hash_alg);
            return Ok(());
        }
        _ => {}
    }
    let key_bits = u16_from(reader)?;
    if !sym_key_bits_valid(algorithm, key_bits, state_format) {
        return Err(Defect);
    }
    sym.key_bits = Some(key_bits);
    let mode = u16_from(reader)?;
    if !is_sym_mode(mode) {
        return Err(Defect);
    }
    sym.mode = Some(mode);
    Ok(())
}

fn scheme_into(
    reader: &mut BlobReader<'_>,
    target: &mut Scheme,
    kind: SchemeKind,
    allow_null: bool,
) -> Step {
    let scheme = u16_from(reader)?;
    if !kind.allows(scheme, allow_null) {
        return Err(Defect);
    }
    target.select(kind, scheme);
    if target.hash_alg.is_some() {
        let hash_alg = u16_from(reader)?;
        if !is_hash_alg(hash_alg, false) {
            return Err(Defect);
        }
        target.hash_alg = Some(hash_alg);
    }
    if target.count.is_some() {
        target.count = Some(u16_from(reader)?);
    }
    if target.kdf.is_some() {
        let kdf = u16_from(reader)?;
        if !SchemeKind::Kdf.allows(kdf, true) {
            return Err(Defect);
        }
        target.kdf = Some(kdf);
    }
    Ok(())
}

fn sensitive_into(reader: &mut BlobReader<'_>, sensitive: &mut OwnedTpmtSensitive) -> Step {
    sensitive.sensitive_type = u16_from(reader)?;
    let composite_size = match sensitive.sensitive_type {
        TPM_ALG_RSA => Some(RSA_PRIVATE_SIZE),
        TPM_ALG_ECC => Some(MAX_ECC_KEY_BYTES),
        TPM_ALG_KEYEDHASH => Some(MAX_SYM_DATA),
        TPM_ALG_SYMCIPHER => Some(MAX_SYM_KEY_BYTES),
        _ => None,
    };
    if composite_size.is_some() {
        sensitive.sensitive.get_or_insert_with(empty_secret);
    } else {
        sensitive.sensitive = None;
    }
    secret_into(reader, DIGEST_SIZE, &mut sensitive.auth_value)?;
    secret_into(reader, DIGEST_SIZE, &mut sensitive.seed_value)?;
    match (composite_size, sensitive.sensitive.as_mut()) {
        (Some(maximum), Some(composite)) => secret_into(reader, maximum, composite),
        _ if sensitive.sensitive_type == 0
            && sensitive.auth_value.as_bytes().is_empty()
            && sensitive.seed_value.as_bytes().is_empty() =>
        {
            Ok(())
        }
        _ => Err(Defect),
    }
}

fn private_exponent_into(reader: &mut BlobReader<'_>, exponent: &mut OwnedPrivateExponent) -> Step {
    let version = header(
        reader,
        StateSection::PrivateExponent,
        PRIVATE_EXPONENT_T_MAGIC,
        PRIVATE_EXPONENT_T_VERSION,
    )?;
    for prime in &mut exponent.primes {
        prime_into(reader, prime)?;
    }
    if version >= OBJECT_BLOCKS_SINCE_VERSION {
        block(reader, false)?;
    }
    Ok(())
}

fn words_of(prime: &OwnedBnPrime, count: usize) -> Vec<u64> {
    let mut words: Vec<u64> = prime
        .data
        .as_bytes()
        .chunks(CRYPT_UWORD_BYTES)
        .map(|chunk| {
            let mut word = [0u8; CRYPT_UWORD_BYTES];
            word[..chunk.len()].copy_from_slice(chunk);
            u64::from_be_bytes(word)
        })
        .collect();
    words.resize(count, 0);
    words
}

fn store_words(prime: &mut OwnedBnPrime, words: &[u64]) {
    prime.data = OwnedSecret::from_vec(words.iter().flat_map(|word| word.to_be_bytes()).collect());
}

fn prime_into(reader: &mut BlobReader<'_>, prime: &mut OwnedBnPrime) -> Step {
    let version = header(
        reader,
        StateSection::BnPrime,
        BN_PRIME_T_MAGIC,
        BN_PRIME_T_VERSION,
    )?;
    let numbytes = u16_from(reader)?;
    let size = usize::from(numbytes).div_ceil(CRYPT_UWORD_BYTES);
    if size > BN_PRIME_WORDS {
        *prime = unset_prime();
        return Err(Defect);
    }
    let mut words = words_of(prime, size);
    prime.numbytes = numbytes;
    store_words(prime, &words);
    let halves = usize::from(numbytes).div_ceil(4);
    let mut word = 0u32;
    for index in 0..halves {
        let read = reader.read_u32();
        if let Ok(value) = read {
            word = value;
        }
        words[index / 2] = (words[index / 2] << 32) | u64::from(word);
        if read.is_err() {
            store_words(prime, &words);
            return Err(Defect);
        }
    }
    if halves % 2 == 1 {
        words[halves / 2] <<= 32;
    }
    store_words(prime, &words);
    if version >= OBJECT_BLOCKS_SINCE_VERSION {
        block(reader, false)?;
    }
    Ok(())
}

fn hash_object_into(
    reader: &mut BlobReader<'_>,
    attributes: u32,
    body: &mut OwnedHashObjectBody,
) -> Step {
    let version = header(
        reader,
        StateSection::HashObject,
        HASH_OBJECT_MAGIC,
        HASH_OBJECT_VERSION,
    )?;
    body.section_version = version;
    let object_type = u16_from(reader)?;
    if is_public_type(object_type) {
        body.object_type = object_type;
    }
    let name_alg = u16_from(reader)?;
    if !is_hash_alg(name_alg, true) {
        return Err(Defect);
    }
    body.name_alg = name_alg;
    let object_attributes = u32_from(reader)?;
    if !object_attributes_valid(object_attributes) {
        return Err(Defect);
    }
    body.object_attributes = object_attributes;
    secret_into(reader, DIGEST_SIZE, &mut body.auth)?;
    if attributes & ATTR_HASH_SEQ != 0
        || (attributes & ATTR_EVENT_SEQ != 0 && version >= HASH_OBJECT_EVENT_STATES_SINCE_VERSION)
    {
        if usize::from(u16_from(reader)?) != HASH_STATE_COUNT {
            return Err(Defect);
        }
        let states = body
            .states
            .get_or_insert_with(|| Box::new(core::array::from_fn(|_| unset_hash_state())));
        for state in states.iter_mut() {
            hash_state_into(reader, state)?;
        }
        let usable = if attributes & ATTR_HASH_SEQ != 0 {
            let state = &states[0];
            hash_state_is_usable(
                state.state_type,
                state.hash_alg,
                state.payload.is_some(),
                false,
            )
        } else {
            states.iter().enumerate().all(|(index, state)| {
                event_state_is_usable(
                    index,
                    state.state_type,
                    state.hash_alg,
                    state.payload.is_some(),
                )
            })
        };
        if !usable {
            return Err(Defect);
        }
    } else if attributes & ATTR_HMAC_SEQ != 0 {
        let (state, key) = body
            .hmac_state
            .get_or_insert_with(|| (unset_hash_state(), empty_secret()));
        hash_state_into(reader, state)?;
        if !hash_state_is_usable(
            state.state_type,
            state.hash_alg,
            state.payload.is_some(),
            true,
        ) {
            return Err(Defect);
        }
        secret_into(reader, HMAC_KEY_SIZE, key)?;
    }
    if version >= OBJECT_BLOCKS_SINCE_VERSION {
        block(reader, false)?;
    }
    Ok(())
}

fn payload_selected_by(hash_alg: u16) -> Option<OwnedHashPayload> {
    let block = |size: usize| OwnedSecret::from_vec(vec![0; size]);
    match hash_alg {
        TPM_ALG_SHA1 => Some(OwnedHashPayload::Sha1 {
            h: [0; 5],
            nl: 0,
            nh: 0,
            data: block(64),
            num: 0,
        }),
        TPM_ALG_SHA256 => Some(OwnedHashPayload::Sha256 {
            h: [0; 8],
            nl: 0,
            nh: 0,
            data: block(64),
            num: 0,
            md_len: 0,
        }),
        TPM_ALG_SHA384 | TPM_ALG_SHA512 => Some(OwnedHashPayload::Sha512 {
            h: [0; 8],
            nl: 0,
            nh: 0,
            data: block(128),
            num: 0,
            md_len: 0,
        }),
        _ => None,
    }
}

fn hash_state_into(reader: &mut BlobReader<'_>, state: &mut OwnedHashState) -> Step {
    let version = header(
        reader,
        StateSection::HashState,
        HASH_STATE_MAGIC,
        HASH_STATE_VERSION,
    )?;
    state.state_type = u8_from(reader)?;
    let hash_alg = u16_from(reader)?;
    state.hash_alg = hash_alg;
    state.payload = payload_selected_by(hash_alg);
    let any_version = peek_u16(reader);
    let any_header = header(
        reader,
        StateSection::HashState,
        ANY_HASH_STATE_MAGIC,
        ANY_HASH_STATE_VERSION,
    );
    match state.payload.as_mut() {
        Some(payload) => payload_into(reader, payload, hash_alg)?,
        None => {
            any_header?;
        }
    }
    if any_version.is_some_and(|version| version >= OBJECT_BLOCKS_SINCE_VERSION) {
        block(reader, false)?;
    }
    if version >= OBJECT_BLOCKS_SINCE_VERSION {
        block(reader, false)?;
    }
    Ok(())
}

fn array_size_from(reader: &mut BlobReader<'_>, expected: usize) -> Step {
    if usize::from(u16_from(reader)?) == expected {
        Ok(())
    } else {
        Err(Defect)
    }
}

fn block_into(reader: &mut BlobReader<'_>, data: &mut OwnedSecret, size: usize) -> Step {
    array_size_from(reader, size)?;
    let bytes = reader.take(size).map_err(|_| Defect)?;
    *data = OwnedSecret::copy_of(bytes);
    Ok(())
}

fn payload_into(
    reader: &mut BlobReader<'_>,
    payload: &mut OwnedHashPayload,
    hash_alg: u16,
) -> Step {
    let magic = match hash_alg {
        TPM_ALG_SHA1 => HASH_STATE_SHA1_MAGIC,
        TPM_ALG_SHA256 => HASH_STATE_SHA256_MAGIC,
        TPM_ALG_SHA384 => HASH_STATE_SHA384_MAGIC,
        _ => HASH_STATE_SHA512_MAGIC,
    };
    let version = header(
        reader,
        StateSection::HashState,
        magic,
        HASH_STATE_SHA_VERSION,
    )?;
    match payload {
        OwnedHashPayload::Sha1 {
            h,
            nl,
            nh,
            data,
            num,
        } => {
            for value in h.iter_mut() {
                *value = u32_from(reader)?;
            }
            *nl = u32_from(reader)?;
            *nh = u32_from(reader)?;
            block_into(reader, data, 64)?;
            *num = u32_from(reader)?;
        }
        OwnedHashPayload::Sha256 {
            h,
            nl,
            nh,
            data,
            num,
            md_len,
        } => {
            array_size_from(reader, h.len())?;
            for value in h.iter_mut() {
                *value = u32_from(reader)?;
            }
            *nl = u32_from(reader)?;
            *nh = u32_from(reader)?;
            block_into(reader, data, 64)?;
            *num = u32_from(reader)?;
            *md_len = u32_from(reader)?;
        }
        OwnedHashPayload::Sha512 {
            h,
            nl,
            nh,
            data,
            num,
            md_len,
        } => {
            array_size_from(reader, h.len())?;
            for value in h.iter_mut() {
                *value = u64_from(reader)?;
            }
            *nl = u64_from(reader)?;
            *nh = u64_from(reader)?;
            block_into(reader, data, 128)?;
            *num = u32_from(reader)?;
            *md_len = u32_from(reader)?;
        }
    }
    if version >= OBJECT_BLOCKS_SINCE_VERSION {
        block(reader, false)?;
    }
    Ok(())
}
