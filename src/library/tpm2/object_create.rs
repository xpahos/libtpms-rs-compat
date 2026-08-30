use crate::library::cancel::Cancellation;
use crate::library::constants::{
    TPM_RC_CANCELED, TPM_RC_CURVE, TPM_RC_FAILURE, TPM_RC_HASH, TPM_RC_KEY, TPM_RC_KEY_SIZE,
    TPM_RC_NO_RESULT, TPM_RC_RANGE, TPM_RC_SIZE, TPM_RC_VALUE,
};
use crate::types::TpmResult;

use super::crypto::{
    BigUint, EccKeyError, Hasher, HmacState, RsaKeyError, SeededRand, generate_ecc_key,
    generate_rsa_key, generate_tdes_key, validate_tdes_key,
};
use super::hierarchy::{TPM_RH_ENDORSEMENT, TPM_RH_NULL, TPM_RH_OWNER, TPM_RH_PLATFORM};
use super::object::{
    ATTR_DERIVATION, ATTR_EPS_HIERARCHY, ATTR_IS_PARENT, ATTR_OCCUPIED, ATTR_PPS_HIERARCHY,
    ATTR_PRIMARY, ATTR_PRIVATE_EXP, ATTR_SPS_HIERARCHY, ATTR_ST_CLEAR, ATTR_TEMPORARY,
};
use super::persistent::{
    OwnedAnyObject, OwnedAnyObjectBody, OwnedBnPrime, OwnedObjectBody, OwnedPrivateExponent,
    OwnedPublicId, OwnedSecret, OwnedTpmtPublic, OwnedTpmtSensitive,
};
use super::public::{
    PublicParms, TPM_ALG_ECC, TPM_ALG_KEYEDHASH, TPM_ALG_NULL, TPM_ALG_RSA, TPM_ALG_SYMCIPHER,
    TPM_ALG_TDES, TPM_ALG_XOR,
};
use super::runtime::Tpm2Runtime;
use super::template::{
    TPMA_OBJECT_DECRYPT, TPMA_OBJECT_RESTRICTED, TPMA_OBJECT_SENSITIVE_DATA_ORIGIN,
    TPMA_OBJECT_SIGN, TPMA_OBJECT_ST_CLEAR, digest_size, object_name,
};
use super::volatile::{CURRENT_OBJECT_VERSION, MAX_LOADED_OBJECTS};

pub(super) const TRANSIENT_FIRST: u32 = 0x8000_0000;
pub(super) const TRANSIENT_LAST: u32 = TRANSIENT_FIRST + MAX_LOADED_OBJECTS as u32 - 1;
pub(super) const PERSISTENT_FIRST: u32 = 0x8100_0000;
pub(super) const PLATFORM_PERSISTENT: u32 = 0x8180_0000;
pub(super) const PERSISTENT_LAST: u32 = 0x81ff_ffff;

pub(super) const PRIMARY_OBJECT_CREATION: &[u8] = b"Primary Object Creation\0";

const SYMMETRIC_KEY_RADIX_BITS: u16 = 64;

pub(super) fn is_object_handle(handle: u32) -> bool {
    is_transient_object_handle(handle) || is_persistent_object_handle(handle)
}

pub(super) fn is_transient_object_handle(handle: u32) -> bool {
    (TRANSIENT_FIRST..=TRANSIENT_LAST).contains(&handle)
}

pub(super) fn is_persistent_object_handle(handle: u32) -> bool {
    (PERSISTENT_FIRST..=PERSISTENT_LAST).contains(&handle)
}

pub(super) fn occupied_object_slot(runtime: &Tpm2Runtime, handle: u32) -> Option<usize> {
    let slot = usize::try_from(handle.checked_sub(TRANSIENT_FIRST)?).ok()?;
    runtime
        .live
        .objects
        .get(slot)
        .filter(|object| object.attributes & ATTR_OCCUPIED != 0)
        .map(|_| slot)
}

pub(super) fn persistent_object_entry(runtime: &Tpm2Runtime, handle: u32) -> Option<usize> {
    runtime
        .state
        .as_ref()?
        .user_nvram
        .entries
        .iter()
        .position(|entry| {
            matches!(entry, super::persistent::OwnedUserNvramEntry::Persistent {
                handle: stored, ..
            } if *stored == handle)
        })
}

pub(super) fn persistent_hierarchy_is_enabled(runtime: &Tpm2Runtime, handle: u32) -> bool {
    if handle >= PLATFORM_PERSISTENT {
        runtime.live.ph_enable
    } else {
        runtime
            .live
            .state_clear
            .as_ref()
            .is_some_and(|clear| clear.sh_enable)
    }
}

pub(super) fn find_empty_object_slot(runtime: &Tpm2Runtime) -> Option<(usize, u32)> {
    empty_object_slots(runtime).next()
}

pub(super) fn empty_object_slots(runtime: &Tpm2Runtime) -> impl Iterator<Item = (usize, u32)> + '_ {
    runtime
        .live
        .objects
        .iter()
        .enumerate()
        .take(MAX_LOADED_OBJECTS)
        .filter(|(_, object)| object.attributes & ATTR_OCCUPIED == 0)
        .map(|(index, _)| (index, TRANSIENT_FIRST + index as u32))
}

pub(super) fn resolve_any_object<'a>(
    runtime: &'a Tpm2Runtime,
    handle: u32,
) -> Option<&'a OwnedAnyObject> {
    if is_transient_object_handle(handle) {
        let slot = occupied_object_slot(runtime, handle)?;
        return runtime.live.objects.get(slot);
    }
    if is_persistent_object_handle(handle) {
        let entry = persistent_object_entry(runtime, handle)?;
        match runtime.state.as_ref()?.user_nvram.entries.get(entry)? {
            super::persistent::OwnedUserNvramEntry::Persistent { object, .. } => {
                return Some(object);
            }
            super::persistent::OwnedUserNvramEntry::NvIndex { .. } => return None,
        }
    }
    None
}

pub(super) fn object_auth_value<'a>(runtime: &'a Tpm2Runtime, handle: u32) -> Option<&'a [u8]> {
    match &resolve_any_object(runtime, handle)?.body {
        OwnedAnyObjectBody::Object(body) => Some(body.sensitive.auth_value.as_bytes()),
        OwnedAnyObjectBody::Sequence(body) => Some(body.auth.as_bytes()),
        OwnedAnyObjectBody::Unoccupied => None,
    }
}

pub(super) fn object_hierarchy(slot_attributes: u32, body: &OwnedObjectBody) -> u32 {
    if let Some(hierarchy) = body.hierarchy {
        return hierarchy;
    }
    if slot_attributes & ATTR_SPS_HIERARCHY != 0 {
        TPM_RH_OWNER
    } else if slot_attributes & ATTR_EPS_HIERARCHY != 0 {
        TPM_RH_ENDORSEMENT
    } else if slot_attributes & ATTR_PPS_HIERARCHY != 0 {
        TPM_RH_PLATFORM
    } else {
        TPM_RH_NULL
    }
}

pub(super) fn object_public_attributes(runtime: &Tpm2Runtime, handle: u32) -> Option<u32> {
    match &resolve_any_object(runtime, handle)?.body {
        OwnedAnyObjectBody::Object(body) => Some(body.public.object_attributes),
        _ => None,
    }
}

pub(super) fn object_is_storage(runtime: &Tpm2Runtime, handle: u32) -> bool {
    let Some(object) = resolve_any_object(runtime, handle) else {
        return false;
    };
    let OwnedAnyObjectBody::Object(body) = &object.body else {
        return false;
    };
    let attributes = body.public.object_attributes;
    attributes & TPMA_OBJECT_RESTRICTED != 0
        && attributes & TPMA_OBJECT_DECRYPT != 0
        && attributes & TPMA_OBJECT_SIGN == 0
        && matches!(body.public.object_type, TPM_ALG_RSA | TPM_ALG_ECC)
}

pub(super) struct CreatedObject {
    pub(super) public: OwnedTpmtPublic,
    pub(super) sensitive: OwnedTpmtSensitive,
    pub(super) private_exponent: Option<OwnedPrivateExponent>,
    pub(super) name: Vec<u8>,
}

pub(super) fn hash_block_size(hash_alg: u16) -> Option<usize> {
    match digest_size(hash_alg)? {
        20 | 32 => Some(64),
        _ => Some(128),
    }
}

pub(super) fn owned_prime(value: &BigUint) -> OwnedBnPrime {
    let mut data = Vec::with_capacity(value.limb_count() * 8);
    for index in 0..value.limb_count() {
        let limb = value.shr(index * 64).low_u64();
        data.extend_from_slice(&limb.to_be_bytes());
    }
    OwnedBnPrime {
        numbytes: (value.limb_count() * 8) as u16,
        data: OwnedSecret::from_vec(data),
    }
}

fn rsa_error(error: RsaKeyError) -> TpmResult {
    match error {
        RsaKeyError::Range => TPM_RC_RANGE,
        RsaKeyError::Value => TPM_RC_VALUE,
        RsaKeyError::NoResult => TPM_RC_NO_RESULT,
        RsaKeyError::Failure => TPM_RC_FAILURE,
        RsaKeyError::Canceled => TPM_RC_CANCELED,
    }
}

fn ecc_error(error: EccKeyError) -> TpmResult {
    match error {
        EccKeyError::Curve => TPM_RC_CURVE,
        EccKeyError::NoResult => TPM_RC_NO_RESULT,
    }
}

pub(super) struct ObjectSecrets<'a> {
    pub(super) sh_proof: &'a [u8],
    pub(super) eh_proof: &'a [u8],
}

pub(super) fn create_object(
    public: &mut OwnedTpmtPublic,
    user_auth: Vec<u8>,
    sensitive_data: &[u8],
    eps_primary: bool,
    secrets: &ObjectSecrets<'_>,
    rand: &mut SeededRand,
    cancellation: Cancellation<'_>,
) -> Result<CreatedObject, TpmResult> {
    let attributes = public.object_attributes;
    let provided: &[u8] = if attributes & TPMA_OBJECT_SENSITIVE_DATA_ORIGIN != 0 {
        &[]
    } else {
        sensitive_data
    };

    let mut private_exponent = None;
    let sensitive_composite = match &public.parameters {
        PublicParms::Rsa {
            key_bits, exponent, ..
        } => {
            let key = generate_rsa_key(
                *key_bits,
                *exponent,
                attributes & TPMA_OBJECT_SIGN != 0,
                rand,
                cancellation,
            )
            .map_err(rsa_error)?;
            public.unique = OwnedPublicId::Rsa(key.modulus);
            private_exponent = Some(OwnedPrivateExponent {
                primes: [
                    owned_prime(&key.q),
                    owned_prime(&key.d_p),
                    owned_prime(&key.d_q),
                    owned_prime(&key.q_inv),
                ],
            });
            key.prime
        }
        PublicParms::Ecc { curve_id, .. } => {
            let key = generate_ecc_key(*curve_id, rand).map_err(ecc_error)?;
            public.unique = OwnedPublicId::Ecc { x: key.x, y: key.y };
            key.private
        }
        PublicParms::SymCipher(sym) => {
            let key_bits = sym.key_bits.ok_or(TPM_RC_KEY_SIZE)?;
            if !key_bits.is_multiple_of(SYMMETRIC_KEY_RADIX_BITS) {
                return Err(TPM_RC_KEY_SIZE);
            }
            if !provided.is_empty() {
                if provided.len() != usize::from(key_bits) / 8 {
                    return Err(TPM_RC_KEY_SIZE);
                }
                if sym.algorithm == TPM_ALG_TDES && !validate_tdes_key(provided) {
                    return Err(TPM_RC_KEY);
                }
                provided.to_vec()
            } else if sym.algorithm == TPM_ALG_TDES {
                generate_tdes_key(key_bits, rand)?
            } else {
                rand.random_bytes(usize::from(key_bits) / 8)?
            }
        }
        PublicParms::KeyedHash(scheme) => {
            let hash_alg = match scheme.scheme {
                TPM_ALG_NULL => public.name_alg,
                TPM_ALG_XOR => scheme.hash_alg.unwrap_or(TPM_ALG_NULL),
                _ => scheme.hash_alg.unwrap_or(TPM_ALG_NULL),
            };
            let digest = digest_size(hash_alg).ok_or(TPM_RC_HASH)?;
            if !provided.is_empty() {
                if attributes & (TPMA_OBJECT_DECRYPT | TPMA_OBJECT_SIGN) != 0
                    && provided.len() > hash_block_size(hash_alg).ok_or(TPM_RC_HASH)?
                {
                    return Err(TPM_RC_SIZE);
                }
                provided.to_vec()
            } else {
                rand.random_bytes(digest)?
            }
        }
    };

    if eps_primary {
        rand.additional_data(secrets.sh_proof)?;
        rand.additional_data(secrets.eh_proof)?;
    }

    let seed_size = digest_size(public.name_alg).ok_or(TPM_RC_HASH)?;
    let mut seed_value = rand.random_bytes(seed_size)?;

    if matches!(public.object_type, TPM_ALG_SYMCIPHER | TPM_ALG_KEYEDHASH) {
        let unique = symmetric_unique(public, &seed_value, &sensitive_composite)?;
        public.unique = match public.object_type {
            TPM_ALG_SYMCIPHER => OwnedPublicId::Sym(unique),
            _ => OwnedPublicId::KeyedHash(unique),
        };
    } else if attributes & TPMA_OBJECT_SIGN != 0 || attributes & TPMA_OBJECT_RESTRICTED == 0 {
        seed_value.clear();
    }

    let name = object_name(public)?;

    Ok(CreatedObject {
        public: public.clone(),
        sensitive: OwnedTpmtSensitive {
            sensitive_type: public.object_type,
            auth_value: OwnedSecret::from_vec(user_auth),
            seed_value: OwnedSecret::from_vec(seed_value),
            sensitive: Some(OwnedSecret::from_vec(sensitive_composite)),
        },
        private_exponent,
        name,
    })
}

fn symmetric_unique(
    public: &OwnedTpmtPublic,
    seed_value: &[u8],
    sensitive: &[u8],
) -> Result<Vec<u8>, TpmResult> {
    let attributes = public.object_attributes;
    if attributes & TPMA_OBJECT_RESTRICTED != 0 && attributes & TPMA_OBJECT_DECRYPT != 0 {
        let mut hmac = HmacState::new(public.name_alg, seed_value).ok_or(TPM_RC_HASH)?;
        hmac.update(sensitive);
        Ok(hmac.finalize())
    } else {
        let mut hasher = Hasher::new(public.name_alg).ok_or(TPM_RC_HASH)?;
        hasher.update(seed_value);
        hasher.update(sensitive);
        Ok(hasher.finalize())
    }
}

pub(super) fn compute_qualified_name(
    parent_handle: u32,
    name_alg: u16,
    name: &[u8],
) -> Result<Vec<u8>, TpmResult> {
    compute_qualified_name_from(&parent_handle.to_be_bytes(), name_alg, name)
}

pub(super) fn compute_qualified_name_from(
    parent_name: &[u8],
    name_alg: u16,
    name: &[u8],
) -> Result<Vec<u8>, TpmResult> {
    let mut hasher = Hasher::new(name_alg).ok_or(TPM_RC_HASH)?;
    hasher.update(parent_name);
    hasher.update(name);
    let mut qualified = name_alg.to_be_bytes().to_vec();
    qualified.extend_from_slice(&hasher.finalize());
    Ok(qualified)
}

pub(super) fn parent_kind_attributes(public: &OwnedTpmtPublic) -> u32 {
    if public.object_attributes & TPMA_OBJECT_RESTRICTED != 0
        && public.object_attributes & TPMA_OBJECT_DECRYPT != 0
        && public.name_alg != TPM_ALG_NULL
    {
        if public.object_type == TPM_ALG_KEYEDHASH {
            ATTR_DERIVATION
        } else {
            ATTR_IS_PARENT
        }
    } else {
        0
    }
}

pub(super) fn loaded_object_attributes(public: &OwnedTpmtPublic, hierarchy: u32) -> u32 {
    let mut attributes = ATTR_OCCUPIED;
    if public.object_attributes & TPMA_OBJECT_ST_CLEAR != 0 {
        attributes |= ATTR_ST_CLEAR;
    }
    match hierarchy {
        TPM_RH_ENDORSEMENT => attributes |= ATTR_PRIMARY | ATTR_EPS_HIERARCHY,
        TPM_RH_OWNER => attributes |= ATTR_PRIMARY | ATTR_SPS_HIERARCHY,
        TPM_RH_PLATFORM => attributes |= ATTR_PRIMARY | ATTR_PPS_HIERARCHY,
        _ => attributes |= ATTR_TEMPORARY,
    }
    attributes | parent_kind_attributes(public)
}

pub(super) struct ParentSnapshot {
    pub(super) slot_attributes: u32,
    pub(super) hierarchy: u32,
    pub(super) qualified_name: Vec<u8>,
}

pub(super) fn store_loaded_child_object(
    runtime: &mut Tpm2Runtime,
    slot: usize,
    parent: &ParentSnapshot,
    seed_compat_level: u8,
    created: CreatedObject,
) -> Result<(), TpmResult> {
    let qualified_name = compute_qualified_name_from(
        &parent.qualified_name,
        created.public.name_alg,
        &created.name,
    )?;
    let mut attributes = ATTR_OCCUPIED;
    if created.public.object_attributes & TPMA_OBJECT_ST_CLEAR != 0
        || parent.slot_attributes & ATTR_ST_CLEAR != 0
    {
        attributes |= ATTR_ST_CLEAR;
    }
    attributes |= parent.slot_attributes
        & (ATTR_EPS_HIERARCHY | ATTR_SPS_HIERARCHY | ATTR_PPS_HIERARCHY | ATTR_TEMPORARY);
    attributes |= parent_kind_attributes(&created.public);
    if created.private_exponent.is_some() {
        attributes |= ATTR_PRIVATE_EXP;
    }
    let hierarchy = parent.hierarchy;
    let slot_entry = runtime.live.objects.get_mut(slot).ok_or(TPM_RC_FAILURE)?;
    *slot_entry = OwnedAnyObject {
        attributes,
        body: OwnedAnyObjectBody::Object(Box::new(OwnedObjectBody {
            section_version: CURRENT_OBJECT_VERSION,
            public: created.public,
            sensitive: created.sensitive,
            private_exponent: created.private_exponent,
            qualified_name,
            evict_handle: 0,
            name: created.name,
            seed_compat_level,
            hierarchy: Some(hierarchy),
        })),
    };
    Ok(())
}

pub(super) fn store_created_object(
    runtime: &mut Tpm2Runtime,
    slot: usize,
    hierarchy: u32,
    seed_compat_level: u8,
    created: CreatedObject,
) -> Result<(), TpmResult> {
    let qualified_name = compute_qualified_name(hierarchy, created.public.name_alg, &created.name)?;
    let mut attributes = loaded_object_attributes(&created.public, hierarchy);
    if created.private_exponent.is_some() {
        attributes |= ATTR_PRIVATE_EXP;
    }
    let slot_entry = runtime.live.objects.get_mut(slot).ok_or(TPM_RC_FAILURE)?;
    *slot_entry = OwnedAnyObject {
        attributes,
        body: OwnedAnyObjectBody::Object(Box::new(OwnedObjectBody {
            section_version: CURRENT_OBJECT_VERSION,
            public: created.public,
            sensitive: created.sensitive,
            private_exponent: created.private_exponent,
            qualified_name,
            evict_handle: 0,
            name: created.name,
            seed_compat_level,
            hierarchy: Some(hierarchy),
        })),
    };
    Ok(())
}

#[cfg(test)]
pub(super) fn asymmetric_key_bytes(public: &OwnedTpmtPublic) -> Option<usize> {
    match &public.parameters {
        PublicParms::Rsa { key_bits, .. } => Some(usize::from(*key_bits) / 8),
        PublicParms::Ecc { curve_id, .. } => super::template::ecc_key_size_bytes(*curve_id),
        _ => None,
    }
}

pub(super) fn primary_seed<'a>(
    runtime: &'a Tpm2Runtime,
    hierarchy: u32,
) -> Result<(&'a [u8], u8), TpmResult> {
    let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
    let persistent = &state.persistent;
    Ok(match hierarchy {
        TPM_RH_PLATFORM => (
            persistent.pp_seed.as_bytes(),
            persistent.pp_seed_compat_level,
        ),
        TPM_RH_OWNER => (
            persistent.sp_seed.as_bytes(),
            persistent.sp_seed_compat_level,
        ),
        TPM_RH_ENDORSEMENT => (
            persistent.ep_seed.as_bytes(),
            persistent.ep_seed_compat_level,
        ),
        _ => (
            runtime
                .live
                .state_reset
                .as_ref()
                .ok_or(TPM_RC_FAILURE)?
                .null_seed
                .as_bytes(),
            runtime.live.null_seed_compat_level,
        ),
    })
}

pub(super) fn hierarchy_is_enabled(runtime: &Tpm2Runtime, hierarchy: u32) -> bool {
    match hierarchy {
        TPM_RH_PLATFORM => runtime.live.ph_enable,
        TPM_RH_OWNER => runtime
            .live
            .state_clear
            .as_ref()
            .is_some_and(|clear| clear.sh_enable),
        TPM_RH_ENDORSEMENT => runtime
            .live
            .state_clear
            .as_ref()
            .is_some_and(|clear| clear.eh_enable),
        TPM_RH_NULL => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::profile::DEFAULT_ALGORITHMS_PROFILE;
    use crate::library::tpm2::public::StateFormatLimit;
    use crate::library::tpm2::public::{
        TPM_ALG_AES, TPM_ALG_CFB, TPM_ALG_ECC, TPM_ALG_RSA, TPM_ALG_SHA256,
    };
    use crate::library::tpm2::runtime::empty_state_runtime;
    use crate::library::tpm2::template::{
        AlgorithmPolicy, TPMA_OBJECT_FIXED_PARENT, TPMA_OBJECT_FIXED_TPM,
        TPMA_OBJECT_USER_WITH_AUTH, TemplateReader, marshal_public_area, parse_public_area,
    };

    fn rand(label: &[u8]) -> SeededRand {
        SeededRand::instantiate(&[0x77; 64], PRIMARY_OBJECT_CREATION, label, &[], 1, false)
            .expect("a non-empty derivation input")
    }

    fn policy() -> AlgorithmPolicy<'static> {
        AlgorithmPolicy {
            profile_algorithms: DEFAULT_ALGORITHMS_PROFILE,
            state_format: StateFormatLimit::CURRENT,
        }
    }

    fn template(object_type: u16, attributes: u32, tail: &[u8]) -> OwnedTpmtPublic {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&object_type.to_be_bytes());
        bytes.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        bytes.extend_from_slice(&attributes.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(tail);
        let mut reader = TemplateReader::new(&bytes);
        parse_public_area(&mut reader, &policy(), false).expect("a valid template")
    }

    fn rsa_storage(key_bits: u16) -> OwnedTpmtPublic {
        let mut tail = Vec::new();
        tail.extend_from_slice(&TPM_ALG_AES.to_be_bytes());
        tail.extend_from_slice(&128u16.to_be_bytes());
        tail.extend_from_slice(&TPM_ALG_CFB.to_be_bytes());
        tail.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        tail.extend_from_slice(&key_bits.to_be_bytes());
        tail.extend_from_slice(&0u32.to_be_bytes());
        tail.extend_from_slice(&0u16.to_be_bytes());
        template(
            TPM_ALG_RSA,
            TPMA_OBJECT_FIXED_TPM
                | TPMA_OBJECT_FIXED_PARENT
                | TPMA_OBJECT_SENSITIVE_DATA_ORIGIN
                | TPMA_OBJECT_USER_WITH_AUTH
                | TPMA_OBJECT_RESTRICTED
                | TPMA_OBJECT_DECRYPT,
            &tail,
        )
    }

    fn ecc_storage(curve_id: u16) -> OwnedTpmtPublic {
        let mut tail = Vec::new();
        tail.extend_from_slice(&TPM_ALG_AES.to_be_bytes());
        tail.extend_from_slice(&128u16.to_be_bytes());
        tail.extend_from_slice(&TPM_ALG_CFB.to_be_bytes());
        tail.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        tail.extend_from_slice(&curve_id.to_be_bytes());
        tail.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        tail.extend_from_slice(&0u16.to_be_bytes());
        tail.extend_from_slice(&0u16.to_be_bytes());
        template(
            TPM_ALG_ECC,
            TPMA_OBJECT_FIXED_TPM
                | TPMA_OBJECT_FIXED_PARENT
                | TPMA_OBJECT_SENSITIVE_DATA_ORIGIN
                | TPMA_OBJECT_USER_WITH_AUTH
                | TPMA_OBJECT_RESTRICTED
                | TPMA_OBJECT_DECRYPT,
            &tail,
        )
    }

    fn secrets() -> ObjectSecrets<'static> {
        ObjectSecrets {
            sh_proof: &[0x11; 64],
            eh_proof: &[0x22; 64],
        }
    }

    #[test]
    fn primary_creation_label_null_termination() {
        assert_eq!(PRIMARY_OBJECT_CREATION, b"Primary Object Creation\0");
        assert_eq!(PRIMARY_OBJECT_CREATION.len(), 24);
    }

    #[test]
    fn transient_handle_range_upstream_base() {
        assert_eq!(TRANSIENT_FIRST, 0x8000_0000);
    }

    #[test]
    fn first_free_slot_handle_return() {
        let mut runtime = empty_state_runtime();
        assert_eq!(find_empty_object_slot(&runtime), Some((0, 0x8000_0000)));
        runtime.live.objects[0].attributes = ATTR_OCCUPIED;
        assert_eq!(find_empty_object_slot(&runtime), Some((1, 0x8000_0001)));
        runtime.live.objects[1].attributes = ATTR_OCCUPIED;
        assert_eq!(find_empty_object_slot(&runtime), Some((2, 0x8000_0002)));
        runtime.live.objects[2].attributes = ATTR_OCCUPIED;
        assert_eq!(find_empty_object_slot(&runtime), None);
    }

    #[test]
    fn freed_slot_reuse_priority() {
        let mut runtime = empty_state_runtime();
        for object in &mut runtime.live.objects {
            object.attributes = ATTR_OCCUPIED;
        }
        runtime.live.objects[1].attributes = 0;
        assert_eq!(find_empty_object_slot(&runtime), Some((1, 0x8000_0001)));
    }

    #[test]
    fn rsa_primary_modulus_and_prime_population() {
        let mut public = rsa_storage(2048);
        let created = create_object(
            &mut public,
            vec![0u8; 32],
            &[],
            false,
            &secrets(),
            &mut rand(b"rsa"),
            Cancellation::disabled(),
        )
        .expect("a key");
        let OwnedPublicId::Rsa(modulus) = &created.public.unique else {
            panic!("an RSA unique field");
        };
        assert_eq!(modulus.len(), 256);
        assert_ne!(modulus[0] & 0x80, 0);
        let prime = created
            .sensitive
            .sensitive
            .as_ref()
            .expect("a private prime");
        assert_eq!(prime.as_bytes().len(), 128);
        assert_eq!(created.sensitive.sensitive_type, TPM_ALG_RSA);
        assert_eq!(created.private_exponent.as_ref().map(|_| ()), Some(()));
    }

    #[test]
    fn restricted_decryption_primary_seed_retention() {
        let mut public = rsa_storage(1024);
        let created = create_object(
            &mut public,
            vec![0u8; 32],
            &[],
            false,
            &secrets(),
            &mut rand(b"seed"),
            Cancellation::disabled(),
        )
        .expect("a key");
        assert_eq!(created.sensitive.seed_value.as_bytes().len(), 32);
    }

    #[test]
    fn signing_primary_seed_discard() {
        let mut tail = Vec::new();
        tail.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        tail.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        tail.extend_from_slice(&1024u16.to_be_bytes());
        tail.extend_from_slice(&0u32.to_be_bytes());
        tail.extend_from_slice(&0u16.to_be_bytes());
        let mut public = template(
            TPM_ALG_RSA,
            TPMA_OBJECT_FIXED_TPM
                | TPMA_OBJECT_FIXED_PARENT
                | TPMA_OBJECT_SENSITIVE_DATA_ORIGIN
                | TPMA_OBJECT_USER_WITH_AUTH
                | TPMA_OBJECT_SIGN,
            &tail,
        );
        let created = create_object(
            &mut public,
            vec![0u8; 32],
            &[],
            false,
            &secrets(),
            &mut rand(b"sign"),
            Cancellation::disabled(),
        )
        .expect("a key");
        assert!(created.sensitive.seed_value.as_bytes().is_empty());
    }

    #[test]
    fn ecc_primary_coordinates_and_scalar_population() {
        let mut public = ecc_storage(0x0004);
        let created = create_object(
            &mut public,
            vec![0u8; 32],
            &[],
            false,
            &secrets(),
            &mut rand(b"ecc"),
            Cancellation::disabled(),
        )
        .expect("a key");
        let OwnedPublicId::Ecc { x, y } = &created.public.unique else {
            panic!("an ECC unique field");
        };
        assert_eq!(x.len(), 48);
        assert_eq!(y.len(), 48);
        assert_eq!(
            created
                .sensitive
                .sensitive
                .as_ref()
                .unwrap()
                .as_bytes()
                .len(),
            48
        );
        assert!(created.private_exponent.is_none());
    }

    #[test]
    fn computed_name_unique_field_coverage() {
        let mut public = ecc_storage(0x0004);
        let created = create_object(
            &mut public,
            vec![0u8; 32],
            &[],
            false,
            &secrets(),
            &mut rand(b"name"),
            Cancellation::disabled(),
        )
        .expect("a key");
        let marshalled = marshal_public_area(&created.public).unwrap();
        let mut hasher = Hasher::new(TPM_ALG_SHA256).unwrap();
        hasher.update(&marshalled);
        let mut expected = TPM_ALG_SHA256.to_be_bytes().to_vec();
        expected.extend_from_slice(&hasher.finalize());
        assert_eq!(created.name, expected);
    }

    #[test]
    fn endorsement_primary_dual_hierarchy_proof_seeding() {
        let mut plain = rsa_storage(1024);
        let mut stirred = rsa_storage(1024);
        let without = create_object(
            &mut plain,
            vec![0u8; 32],
            &[],
            false,
            &secrets(),
            &mut rand(b"eps"),
            Cancellation::disabled(),
        )
        .expect("a key");
        let with = create_object(
            &mut stirred,
            vec![0u8; 32],
            &[],
            true,
            &secrets(),
            &mut rand(b"eps"),
            Cancellation::disabled(),
        )
        .expect("a key");
        assert_eq!(
            without.public.unique, with.public.unique,
            "the key itself is generated before the additional data"
        );
        assert_ne!(
            without.sensitive.seed_value.as_bytes(),
            with.sensitive.seed_value.as_bytes()
        );
    }

    #[test]
    fn primary_qualified_name_hierarchy_handle_hash() {
        let name = vec![0x00, 0x0b, 0xaa, 0xbb];
        let qualified = compute_qualified_name(TPM_RH_OWNER, TPM_ALG_SHA256, &name).unwrap();
        let mut hasher = Hasher::new(TPM_ALG_SHA256).unwrap();
        hasher.update(&TPM_RH_OWNER.to_be_bytes());
        hasher.update(&name);
        let mut expected = TPM_ALG_SHA256.to_be_bytes().to_vec();
        expected.extend_from_slice(&hasher.finalize());
        assert_eq!(qualified, expected);
        assert_eq!(qualified.len(), 34);
    }

    #[test]
    fn per_hierarchy_object_attribute_selection() {
        let public = rsa_storage(1024);
        for (hierarchy, expected) in [
            (TPM_RH_OWNER, ATTR_PRIMARY | ATTR_SPS_HIERARCHY),
            (TPM_RH_PLATFORM, ATTR_PRIMARY | ATTR_PPS_HIERARCHY),
            (TPM_RH_ENDORSEMENT, ATTR_PRIMARY | ATTR_EPS_HIERARCHY),
            (TPM_RH_NULL, ATTR_TEMPORARY),
        ] {
            let attributes = loaded_object_attributes(&public, hierarchy);
            assert_eq!(
                attributes & (ATTR_PRIMARY | ATTR_TEMPORARY | 0x0e),
                expected,
                "hierarchy {hierarchy:#010x}"
            );
            assert_ne!(attributes & ATTR_OCCUPIED, 0);
            assert_ne!(attributes & ATTR_IS_PARENT, 0, "a storage key is a parent");
        }
    }

    #[test]
    fn non_storage_key_no_parent_flag() {
        let mut tail = Vec::new();
        tail.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        tail.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        tail.extend_from_slice(&1024u16.to_be_bytes());
        tail.extend_from_slice(&0u32.to_be_bytes());
        tail.extend_from_slice(&0u16.to_be_bytes());
        let public = template(
            TPM_ALG_RSA,
            TPMA_OBJECT_FIXED_TPM
                | TPMA_OBJECT_FIXED_PARENT
                | TPMA_OBJECT_SENSITIVE_DATA_ORIGIN
                | TPMA_OBJECT_SIGN,
            &tail,
        );
        assert_eq!(
            loaded_object_attributes(&public, TPM_RH_OWNER) & ATTR_IS_PARENT,
            0
        );
    }

    #[test]
    fn stored_object_name_hierarchy_seed_level_fields() {
        let mut runtime = empty_state_runtime();
        let mut public = rsa_storage(1024);
        let created = create_object(
            &mut public,
            vec![0u8; 32],
            &[],
            false,
            &secrets(),
            &mut rand(b"store"),
            Cancellation::disabled(),
        )
        .expect("a key");
        let name = created.name.clone();
        store_created_object(&mut runtime, 0, TPM_RH_OWNER, 1, created).expect("stores");
        let OwnedAnyObjectBody::Object(body) = &runtime.live.objects[0].body else {
            panic!("an object body");
        };
        assert_eq!(body.name, name);
        assert_eq!(body.hierarchy, Some(TPM_RH_OWNER));
        assert_eq!(body.seed_compat_level, 1);
        assert_eq!(body.evict_handle, 0);
        assert_eq!(body.section_version, CURRENT_OBJECT_VERSION);
        assert_ne!(runtime.live.objects[0].attributes & ATTR_OCCUPIED, 0);
        assert_ne!(runtime.live.objects[0].attributes & ATTR_PRIVATE_EXP, 0);
    }

    #[test]
    fn ecc_object_no_private_exponent_marker() {
        let mut runtime = empty_state_runtime();
        let mut public = ecc_storage(0x0003);
        let created = create_object(
            &mut public,
            vec![0u8; 32],
            &[],
            false,
            &secrets(),
            &mut rand(b"eccstore"),
            Cancellation::disabled(),
        )
        .expect("a key");
        store_created_object(&mut runtime, 1, TPM_RH_NULL, 0, created).expect("stores");
        assert_eq!(runtime.live.objects[1].attributes & ATTR_PRIVATE_EXP, 0);
        assert_ne!(runtime.live.objects[1].attributes & ATTR_TEMPORARY, 0);
    }

    #[test]
    fn asymmetric_key_size_public_parameter_derivation() {
        assert_eq!(asymmetric_key_bytes(&rsa_storage(2048)), Some(256));
        assert_eq!(asymmetric_key_bytes(&rsa_storage(3072)), Some(384));
        assert_eq!(asymmetric_key_bytes(&ecc_storage(0x0004)), Some(48));
    }

    #[test]
    fn enabled_hierarchy_only_reporting() {
        use crate::library::tpm2::persistent::OwnedStateClearData;
        let mut runtime = empty_state_runtime();
        assert!(hierarchy_is_enabled(&runtime, TPM_RH_NULL));
        assert!(!hierarchy_is_enabled(&runtime, TPM_RH_PLATFORM));
        assert!(!hierarchy_is_enabled(&runtime, TPM_RH_OWNER));
        assert!(!hierarchy_is_enabled(&runtime, TPM_RH_ENDORSEMENT));
        runtime.live.ph_enable = true;
        runtime.live.state_clear = Some(OwnedStateClearData {
            sh_enable: true,
            eh_enable: false,
            ph_enable_nv: true,
            platform_alg: 0,
            platform_policy: Vec::new(),
            platform_auth: OwnedSecret::from_vec(Vec::new()),
            pcr_save: core::array::from_fn(|_| None),
            pcr_auth_values: core::array::from_fn(|_| OwnedSecret::from_vec(Vec::new())),
        });
        assert!(hierarchy_is_enabled(&runtime, TPM_RH_PLATFORM));
        assert!(hierarchy_is_enabled(&runtime, TPM_RH_OWNER));
        assert!(!hierarchy_is_enabled(&runtime, TPM_RH_ENDORSEMENT));
        assert!(!hierarchy_is_enabled(&runtime, 0x4000_000a));
    }

    #[test]
    fn marshalled_private_exponent_limb_big_endian() {
        let value = BigUint::from_be_bytes(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        let prime = owned_prime(&value);
        assert_eq!(prime.numbytes, 8);
        assert_eq!(
            prime.data.as_bytes(),
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
        let wide = BigUint::from_be_bytes(&[0xaa; 9]);
        let prime = owned_prime(&wide);
        assert_eq!(prime.numbytes, 16);
        assert_eq!(prime.data.as_bytes().len(), 16);
        assert_eq!(&prime.data.as_bytes()[..8], &[0xaa; 8]);
        assert_eq!(prime.data.as_bytes()[15], 0xaa);
    }

    #[test]
    fn hash_block_size_digest_size_mapping() {
        use crate::library::tpm2::public::{TPM_ALG_SHA1, TPM_ALG_SHA384, TPM_ALG_SHA512};
        assert_eq!(hash_block_size(TPM_ALG_SHA1), Some(64));
        assert_eq!(hash_block_size(TPM_ALG_SHA256), Some(64));
        assert_eq!(hash_block_size(TPM_ALG_SHA384), Some(128));
        assert_eq!(hash_block_size(TPM_ALG_SHA512), Some(128));
        assert_eq!(hash_block_size(TPM_ALG_NULL), None);
    }
}
