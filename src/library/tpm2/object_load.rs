// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/Context_spt.c
// - libtpms/src/tpm2/Object.c
// - libtpms/src/tpm2/Object_spt.c
//
// Original upstream authors and copyright notices:
// Written by Ken Goldman
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corp. and others, 2016 - 2023
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use crate::library::constants::{
    TPM_RC_BINDING, TPM_RC_CURVE, TPM_RC_ECC_POINT, TPM_RC_FAILURE, TPM_RC_HASH, TPM_RC_KEY,
    TPM_RC_KEY_SIZE, TPM_RC_SCHEME, TPM_RC_SIZE, TPM_RC_TYPE, TPM_RC_VALUE,
};
use crate::types::TpmResult;

use super::crypto::{
    EccCurve, Hasher, HmacState, RecoveryError, curve_key_size_bits, recover_rsa_components,
    validate_tdes_key,
};
use super::ecc::fit_be;
use super::hierarchy::{TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM};
use super::object::{
    ATTR_EPS_HIERARCHY, ATTR_EXTERNAL, ATTR_OCCUPIED, ATTR_PPS_HIERARCHY, ATTR_PRIMARY,
    ATTR_PRIVATE_EXP, ATTR_PUBLIC_ONLY, ATTR_SPS_HIERARCHY, ATTR_ST_CLEAR, ATTR_TEMPORARY,
};
use super::object_create::{
    compute_qualified_name_from, hash_block_size, owned_prime, parent_kind_attributes,
};
use super::object_wrap::Protector;
use super::persistent::{
    OwnedAnyObjectBody, OwnedObjectBody, OwnedPrivateExponent, OwnedPublicId, OwnedSecret,
    OwnedTpmtPublic, OwnedTpmtSensitive,
};
use super::public::{
    DIGEST_SIZE, MAX_ECC_KEY_BYTES, MAX_SYM_DATA, MAX_SYM_KEY_BYTES, PublicParms, RSA_PRIVATE_SIZE,
    TPM_ALG_ECC, TPM_ALG_HMAC, TPM_ALG_KEYEDHASH, TPM_ALG_NULL, TPM_ALG_RSA, TPM_ALG_SYMCIPHER,
    TPM_ALG_TDES, TPM_ALG_XOR,
};
use super::runtime::Tpm2Runtime;
use super::session::digests_equal;
use super::template::{
    ParentPublicInfo, TPMA_OBJECT_DECRYPT, TPMA_OBJECT_FIXED_TPM, TPMA_OBJECT_RESTRICTED,
    TPMA_OBJECT_ST_CLEAR, TemplateReader, digest_size, object_name, parent_public_info,
    public_attributes_validation, scheme_checks,
};
use super::volatile::CURRENT_OBJECT_VERSION;

const RC_FMT1: TpmResult = 0x080;
const RC_MODIFIER_MASK: TpmResult = 0xf40;

pub(super) const SEED_COMPAT_LEVEL_ORIGINAL: u8 = 0;

pub(super) fn add_modifier(code: TpmResult, modifier: TpmResult) -> TpmResult {
    if code & RC_FMT1 != 0 && code & RC_MODIFIER_MASK == 0 {
        code + modifier
    } else {
        code
    }
}

pub(super) fn read_sensitive_area(
    reader: &mut TemplateReader<'_>,
) -> Result<OwnedTpmtSensitive, TpmResult> {
    let sensitive_type = reader.u16()?;
    if !matches!(
        sensitive_type,
        TPM_ALG_KEYEDHASH | TPM_ALG_RSA | TPM_ALG_ECC | TPM_ALG_SYMCIPHER
    ) {
        return Err(TPM_RC_TYPE);
    }
    let auth_value = OwnedSecret::copy_of(reader.tpm2b(DIGEST_SIZE)?);
    let seed_value = OwnedSecret::copy_of(reader.tpm2b(DIGEST_SIZE)?);
    let sensitive = match sensitive_type {
        TPM_ALG_RSA => reader.tpm2b(RSA_PRIVATE_SIZE)?,
        TPM_ALG_ECC => reader.tpm2b(MAX_ECC_KEY_BYTES)?,
        TPM_ALG_KEYEDHASH => reader.tpm2b(MAX_SYM_DATA)?,
        _ => reader.tpm2b(MAX_SYM_KEY_BYTES)?,
    };
    Ok(OwnedTpmtSensitive {
        sensitive_type,
        auth_value,
        seed_value,
        sensitive: Some(OwnedSecret::copy_of(sensitive)),
    })
}

pub(super) fn read_sized_sensitive_area(
    reader: &mut TemplateReader<'_>,
) -> Result<Option<OwnedTpmtSensitive>, TpmResult> {
    let declared = usize::from(reader.u16()?);
    if declared == 0 {
        return Ok(None);
    }
    let before = reader.consumed();
    let sensitive = read_sensitive_area(reader)?;
    if reader.consumed() - before != declared {
        return Err(TPM_RC_SIZE);
    }
    Ok(Some(sensitive))
}

fn symmetric_unique(
    public: &OwnedTpmtPublic,
    sensitive: &OwnedTpmtSensitive,
) -> Result<Vec<u8>, TpmResult> {
    let attributes = public.object_attributes;
    let seed = sensitive.seed_value.as_bytes();
    let data = sensitive
        .sensitive
        .as_ref()
        .map_or(&[][..], OwnedSecret::as_bytes);
    if attributes & TPMA_OBJECT_RESTRICTED != 0 && attributes & TPMA_OBJECT_DECRYPT != 0 {
        let mut hmac = HmacState::new(public.name_alg, seed).ok_or(TPM_RC_HASH)?;
        hmac.update(data);
        Ok(hmac.finalize())
    } else {
        let mut hasher = Hasher::new(public.name_alg).ok_or(TPM_RC_HASH)?;
        hasher.update(seed);
        hasher.update(data);
        Ok(hasher.finalize())
    }
}

fn keyed_hash_key_limit(public: &OwnedTpmtPublic) -> Result<usize, TpmResult> {
    let PublicParms::KeyedHash(scheme) = &public.parameters else {
        return Err(TPM_RC_FAILURE);
    };
    match scheme.scheme {
        TPM_ALG_XOR | TPM_ALG_HMAC => {
            hash_block_size(scheme.hash_alg.unwrap_or(TPM_ALG_NULL)).ok_or(TPM_RC_HASH)
        }
        TPM_ALG_NULL => Ok(128),
        _ => Err(TPM_RC_SCHEME),
    }
}

fn validate_symmetric_key(public: &OwnedTpmtPublic, key: &[u8]) -> Result<(), TpmResult> {
    let PublicParms::SymCipher(sym) = &public.parameters else {
        return Err(TPM_RC_FAILURE);
    };
    let key_bits = sym.key_bits.ok_or(TPM_RC_KEY_SIZE)?;
    if key.len() * 8 != usize::from(key_bits) {
        return Err(TPM_RC_KEY_SIZE);
    }
    if sym.algorithm == TPM_ALG_TDES && !validate_tdes_key(key) {
        return Err(TPM_RC_KEY);
    }
    Ok(())
}

fn validate_rsa(
    public: &OwnedTpmtPublic,
    secret: Option<&[u8]>,
    blame_public: TpmResult,
    blame_sensitive: TpmResult,
) -> Result<(), TpmResult> {
    let PublicParms::Rsa {
        key_bits, exponent, ..
    } = &public.parameters
    else {
        return Err(TPM_RC_FAILURE);
    };
    let OwnedPublicId::Rsa(modulus) = &public.unique else {
        return Err(TPM_RC_FAILURE);
    };
    let key_bytes = usize::from(*key_bits) / 8;
    if modulus.len() != key_bytes || modulus.first().copied().unwrap_or(0) < 0x80 {
        return Err(TPM_RC_KEY + blame_public);
    }
    if *exponent != 0 && *exponent < 7 {
        return Err(TPM_RC_VALUE + blame_public);
    }
    if let Some(secret) = secret {
        #[cfg(test)]
        crate::library::tpm2::memcheck::observe("imported-prime-validation", secret);
        let top_bit = subtle::Choice::from(secret.first().copied().unwrap_or(0) >> 7);
        if secret.len() * 2 != key_bytes || !bool::from(top_bit) {
            return Err(TPM_RC_KEY_SIZE + blame_sensitive);
        }
    }
    Ok(())
}

fn validate_ecc(
    public: &OwnedTpmtPublic,
    secret: Option<Option<&OwnedSecret>>,
    blame_public: TpmResult,
) -> Result<(), TpmResult> {
    let PublicParms::Ecc { curve_id, .. } = &public.parameters else {
        return Err(TPM_RC_FAILURE);
    };
    let OwnedPublicId::Ecc { x, y } = &public.unique else {
        return Err(TPM_RC_FAILURE);
    };
    let curve = EccCurve::lookup(*curve_id).ok_or(TPM_RC_CURVE)?;
    let key_bytes = usize::from(curve_key_size_bits(*curve_id).ok_or(TPM_RC_CURVE)?).div_ceil(8);
    match secret {
        None => {
            if x.len() != key_bytes || y.len() != key_bytes {
                return Err(TPM_RC_KEY + blame_public);
            }
            if public.name_alg != TPM_ALG_NULL
                && !curve.is_on_curve(x, y).map_err(|_| TPM_RC_FAILURE)?
            {
                return Err(TPM_RC_ECC_POINT + blame_public);
            }
        }
        Some(stored) => {
            let Some(stored) = stored
                .and_then(OwnedSecret::fixed_width)
                .filter(|stored| curve.private_scalar_in_range(stored))
            else {
                return Err(TPM_RC_KEY_SIZE);
            };
            if public.name_alg != TPM_ALG_NULL {
                let scalar = curve.private_scalar(stored).ok_or(TPM_RC_FAILURE)?;
                let computed = curve.mul_generator(&scalar).ok_or(TPM_RC_FAILURE)?;
                let matches = fit_be(&computed.x, x.len()).is_some_and(|value| value == *x)
                    && fit_be(&computed.y, y.len()).is_some_and(|value| value == *y);
                if !matches {
                    return Err(TPM_RC_BINDING);
                }
            }
        }
    }
    Ok(())
}

pub(super) fn validate_keys(
    public: &OwnedTpmtPublic,
    sensitive: Option<&OwnedTpmtSensitive>,
    blame_public: TpmResult,
    blame_sensitive: TpmResult,
) -> Result<(), TpmResult> {
    let digest = digest_size(public.name_alg).unwrap_or(0);
    if let Some(sensitive) = sensitive {
        if public.object_type != sensitive.sensitive_type {
            return Err(TPM_RC_TYPE + blame_sensitive);
        }
        if sensitive.auth_value.as_bytes().len() > digest && digest > 0 {
            return Err(TPM_RC_SIZE + blame_sensitive);
        }
    }
    let secret = sensitive.map(|sensitive| {
        sensitive
            .sensitive
            .as_ref()
            .map_or(&[][..], OwnedSecret::as_bytes)
    });
    match public.object_type {
        TPM_ALG_RSA => validate_rsa(public, secret, blame_public, blame_sensitive)?,
        TPM_ALG_ECC => validate_ecc(
            public,
            sensitive.map(|sensitive| sensitive.sensitive.as_ref()),
            blame_public,
        )?,
        _ => {
            let unique = match &public.unique {
                OwnedPublicId::KeyedHash(unique) | OwnedPublicId::Sym(unique) => unique,
                _ => return Err(TPM_RC_FAILURE),
            };
            match sensitive {
                None => {
                    if unique.len() != digest {
                        return Err(TPM_RC_KEY + blame_public);
                    }
                }
                Some(sensitive) => {
                    let secret = secret.unwrap_or(&[]);
                    if public.object_type == TPM_ALG_SYMCIPHER {
                        validate_symmetric_key(public, secret)
                            .map_err(|code| code + blame_sensitive)?;
                    } else {
                        let limit =
                            keyed_hash_key_limit(public).map_err(|code| code + blame_public)?;
                        if secret.len() > limit {
                            return Err(TPM_RC_KEY_SIZE + blame_sensitive);
                        }
                    }
                    if public.name_alg != TPM_ALG_NULL {
                        if sensitive.seed_value.as_bytes().len() != digest {
                            return Err(TPM_RC_KEY_SIZE + blame_sensitive);
                        }
                        if !digests_equal(unique, &symmetric_unique(public, sensitive)?) {
                            return Err(TPM_RC_BINDING);
                        }
                    }
                }
            }
        }
    }
    if public.object_attributes & TPMA_OBJECT_RESTRICTED != 0
        && public.object_attributes & TPMA_OBJECT_DECRYPT != 0
        && public.name_alg != TPM_ALG_NULL
        && let Some(sensitive) = sensitive
    {
        let seed = sensitive.seed_value.as_bytes().len();
        if seed < digest / 2 || seed > digest {
            return Err(TPM_RC_SIZE + blame_sensitive);
        }
    }
    Ok(())
}

pub(super) struct ParentContext {
    pub(super) slot_attributes: u32,
    pub(super) public: OwnedTpmtPublic,
    pub(super) seed_value: Vec<u8>,
    pub(super) hierarchy: u32,
    pub(super) qualified_name: Vec<u8>,
    pub(super) seed_compat_level: u8,
}

impl ParentContext {
    pub(super) fn info(&self) -> ParentPublicInfo {
        parent_public_info(&self.public, false)
    }

    pub(super) fn protector(&self) -> Protector<'_> {
        Protector {
            public: &self.public,
            seed_value: &self.seed_value,
        }
    }
}

pub(super) struct LoadedObject {
    pub(super) public: OwnedTpmtPublic,
    pub(super) sensitive: Option<OwnedTpmtSensitive>,
    pub(super) private_exponent: Option<OwnedPrivateExponent>,
    pub(super) name: Vec<u8>,
}

pub(super) fn object_load(
    parent: Option<&ParentContext>,
    public: OwnedTpmtPublic,
    sensitive: Option<OwnedTpmtSensitive>,
    blame_public: TpmResult,
    blame_sensitive: TpmResult,
    name: Vec<u8>,
) -> Result<LoadedObject, TpmResult> {
    #[cfg(test)]
    if public.object_type == TPM_ALG_RSA
        && let Some(prime) = sensitive.as_ref().and_then(|s| s.sensitive.as_ref())
    {
        crate::library::tpm2::memcheck::secret(prime.as_bytes());
    }
    let parent_info = parent.map(ParentContext::info);
    if sensitive.is_none() || public.name_alg == TPM_ALG_NULL {
        scheme_checks(None, &public).map_err(|code| add_modifier(code, blame_public))?;
    } else {
        let seed = sensitive
            .as_ref()
            .map_or(0, |sensitive| sensitive.seed_value.as_bytes().len());
        if seed > digest_size(public.name_alg).unwrap_or(0) {
            return Err(TPM_RC_KEY_SIZE + blame_sensitive);
        }
        public_attributes_validation(parent_info.as_ref(), &public)
            .map_err(|code| add_modifier(code, blame_public))?;
    }

    let parent_is_fixed_tpm =
        parent.is_some_and(|parent| parent.public.object_attributes & TPMA_OBJECT_FIXED_TPM != 0);
    if !parent_is_fixed_tpm {
        validate_keys(&public, sensitive.as_ref(), blame_public, blame_sensitive)?;
    }

    let mut private_exponent = None;
    if public.object_type == TPM_ALG_RSA
        && let Some(sensitive) = sensitive.as_ref()
    {
        let PublicParms::Rsa { exponent, .. } = &public.parameters else {
            return Err(TPM_RC_FAILURE);
        };
        let OwnedPublicId::Rsa(modulus) = &public.unique else {
            return Err(TPM_RC_FAILURE);
        };
        let prime = sensitive
            .sensitive
            .as_ref()
            .map_or(&[][..], OwnedSecret::as_bytes);
        let recovered =
            recover_rsa_components(modulus, prime, *exponent).map_err(|error| match error {
                RecoveryError::Invalid => TPM_RC_BINDING,
                RecoveryError::Backend => TPM_RC_FAILURE,
            })?;
        private_exponent = Some(OwnedPrivateExponent {
            primes: [
                owned_prime(recovered.q),
                owned_prime(recovered.d_p),
                owned_prime(recovered.d_q),
                owned_prime(recovered.q_inv),
            ],
            runtime: crate::library::tpm2::crypto::RsaRuntimeCache::default(),
        });
    }

    Ok(LoadedObject {
        public,
        sensitive,
        private_exponent,
        name,
    })
}

fn empty_sensitive() -> OwnedTpmtSensitive {
    OwnedTpmtSensitive {
        sensitive_type: 0,
        auth_value: OwnedSecret::from_vec(Vec::new()),
        seed_value: OwnedSecret::from_vec(Vec::new()),
        sensitive: None,
    }
}

fn write_slot(
    runtime: &mut Tpm2Runtime,
    slot: usize,
    attributes: u32,
    body: OwnedObjectBody,
) -> Result<(), TpmResult> {
    let entry = runtime.live.objects.get_mut(slot).ok_or(TPM_RC_FAILURE)?;
    entry.attributes = attributes;
    entry.body = OwnedAnyObjectBody::Object(Box::new(body));
    Ok(())
}

pub(super) fn store_child_object(
    runtime: &mut Tpm2Runtime,
    slot: usize,
    parent: &ParentContext,
    loaded: LoadedObject,
) -> Result<(), TpmResult> {
    let public_only = loaded.sensitive.is_none();
    let mut attributes = ATTR_OCCUPIED;
    if public_only {
        attributes |= ATTR_PUBLIC_ONLY;
    } else {
        attributes |= parent_kind_attributes(&loaded.public);
    }
    if loaded.private_exponent.is_some() {
        attributes |= ATTR_PRIVATE_EXP;
    }
    if loaded.public.object_attributes & TPMA_OBJECT_ST_CLEAR != 0
        || parent.slot_attributes & ATTR_ST_CLEAR != 0
    {
        attributes |= ATTR_ST_CLEAR;
    }
    attributes |= parent.slot_attributes
        & (ATTR_EPS_HIERARCHY | ATTR_SPS_HIERARCHY | ATTR_PPS_HIERARCHY | ATTR_TEMPORARY);

    let qualified_name =
        compute_qualified_name_from(&parent.qualified_name, loaded.public.name_alg, &loaded.name)?;
    write_slot(
        runtime,
        slot,
        attributes,
        OwnedObjectBody {
            section_version: CURRENT_OBJECT_VERSION,
            public: loaded.public,
            sensitive: loaded.sensitive.unwrap_or_else(empty_sensitive),
            private_exponent: loaded.private_exponent,
            qualified_name,
            evict_handle: 0,
            name: loaded.name,
            seed_compat_level: parent.seed_compat_level,
            hierarchy: Some(parent.hierarchy),
        },
    )
}

pub(super) fn store_external_object(
    runtime: &mut Tpm2Runtime,
    slot: usize,
    hierarchy: u32,
    loaded: LoadedObject,
) -> Result<(), TpmResult> {
    let mut attributes = ATTR_OCCUPIED | ATTR_EXTERNAL;
    if loaded.sensitive.is_none() {
        attributes |= ATTR_PUBLIC_ONLY;
    }
    if loaded.private_exponent.is_some() {
        attributes |= ATTR_PRIVATE_EXP;
    }
    if loaded.public.object_attributes & TPMA_OBJECT_ST_CLEAR != 0 {
        attributes |= ATTR_ST_CLEAR;
    }
    attributes |= match hierarchy {
        TPM_RH_ENDORSEMENT => ATTR_PRIMARY | ATTR_EPS_HIERARCHY,
        TPM_RH_OWNER => ATTR_PRIMARY | ATTR_SPS_HIERARCHY,
        TPM_RH_PLATFORM => ATTR_PRIMARY | ATTR_PPS_HIERARCHY,
        _ => ATTR_TEMPORARY,
    };

    let qualified_name = loaded.name.clone();
    write_slot(
        runtime,
        slot,
        attributes,
        OwnedObjectBody {
            section_version: CURRENT_OBJECT_VERSION,
            public: loaded.public,
            sensitive: loaded.sensitive.unwrap_or_else(empty_sensitive),
            private_exponent: loaded.private_exponent,
            qualified_name,
            evict_handle: 0,
            name: loaded.name,
            seed_compat_level: SEED_COMPAT_LEVEL_ORIGINAL,
            hierarchy: Some(hierarchy),
        },
    )
}

pub(super) fn public_marshal_and_compute_name(
    public: &OwnedTpmtPublic,
) -> Result<Vec<u8>, TpmResult> {
    if public.name_alg == TPM_ALG_NULL {
        return Ok(Vec::new());
    }
    object_name(public)
}

pub(super) fn parse_object_context_image(
    bytes: &[u8],
    state_format: super::public::StateFormatLimit,
) -> Option<super::persistent::OwnedAnyObject> {
    let mut reader = super::marshal::BlobReader::new(bytes);
    let object = super::object::parse_any_object(&mut reader, state_format).ok()?;
    Some(super::persistent::own_any_object(&object))
}

#[cfg(test)]
pub(in crate::library::tpm2) mod replay {
    use crate::library::CommandInput;
    use crate::library::tpm2::clock::SteppingClock;
    pub(in crate::library::tpm2) use crate::library::tpm2::golden_responses::object_lifecycle::vector;
    use crate::library::tpm2::process::process;
    use crate::library::tpm2::runtime::Tpm2Runtime;
    use crate::library::tpm2::{attach_volatile_blob, restore_permanent_blob_for_test};
    use crate::types::TpmResult;

    pub(in crate::library::tpm2) const RH_OWNER: u32 = 0x4000_0001;
    pub(in crate::library::tpm2) const RH_NULL: u32 = 0x4000_0007;
    pub(in crate::library::tpm2) const RH_PLATFORM: u32 = 0x4000_000c;
    pub(in crate::library::tpm2) const RH_LOCKOUT: u32 = 0x4000_000a;
    const RS_PW: u32 = 0x4000_0009;

    pub(in crate::library::tpm2) const CC_OBJECT_CHANGE_AUTH: u32 = 0x0000_0150;
    pub(in crate::library::tpm2) const CC_LOAD: u32 = 0x0000_0157;
    pub(in crate::library::tpm2) const CC_UNSEAL: u32 = 0x0000_015e;
    pub(in crate::library::tpm2) const CC_CONTEXT_LOAD: u32 = 0x0000_0161;
    pub(in crate::library::tpm2) const CC_CONTEXT_SAVE: u32 = 0x0000_0162;
    pub(in crate::library::tpm2) const CC_LOAD_EXTERNAL: u32 = 0x0000_0167;
    pub(in crate::library::tpm2) const CC_READ_PUBLIC: u32 = 0x0000_0173;
    pub(in crate::library::tpm2) const CC_GET_CAPABILITY: u32 = 0x0000_017a;

    fn unreachable_entropy(_buffer: &mut [u8]) -> Result<(), TpmResult> {
        panic!("the replay must not draw host entropy");
    }

    pub(in crate::library::tpm2) fn clock() -> SteppingClock {
        SteppingClock::new(1_700_000_000_000, 4_000_000)
    }

    pub(in crate::library::tpm2) fn runtime_at(
        snapshot: &str,
        clock: &SteppingClock,
    ) -> Tpm2Runtime {
        runtime_from(
            vector(&format!("PERMALL_{snapshot}")),
            vector(&format!("VOLATILE_{snapshot}")),
            clock,
        )
    }

    pub(in crate::library::tpm2) fn runtime_from(
        permanent: &[u8],
        volatile: &[u8],
        clock: &SteppingClock,
    ) -> Tpm2Runtime {
        let mut runtime = restore_permanent_blob_for_test(permanent)
            .expect("the oracle permanent state restores");
        attach_volatile_blob(&mut runtime, volatile, clock)
            .expect("the oracle volatile state attaches");
        runtime.entropy = unreachable_entropy;
        runtime
    }

    #[track_caller]
    pub(in crate::library::tpm2) fn exec_raw(
        runtime: &mut Tpm2Runtime,
        clock: &SteppingClock,
        bytes: Vec<u8>,
    ) -> Vec<u8> {
        let input = CommandInput::new(bytes.len() as u32, bytes);
        process(
            runtime,
            crate::library::tpm2::PlatformInputs::at_locality(0),
            &input,
            clock,
            |_| Ok(()),
            crate::library::cancel::CancellationToken::disabled(),
        )
        .expect("the command processes")
    }

    #[track_caller]
    pub(in crate::library::tpm2) fn exec(
        runtime: &mut Tpm2Runtime,
        clock: &SteppingClock,
        label: &str,
        bytes: Vec<u8>,
    ) {
        assert_eq!(exec_raw(runtime, clock, bytes), vector(label), "{label}");
    }

    pub(in crate::library::tpm2) use crate::library::tpm2::test_support::{push_tpm2b, tpm2b};

    pub(in crate::library::tpm2) fn framed(tag: u16, code: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = tag.to_be_bytes().to_vec();
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&code.to_be_bytes());
        out.extend_from_slice(payload);
        let size = (out.len() as u32).to_be_bytes();
        out[2..6].copy_from_slice(&size);
        out
    }

    pub(in crate::library::tpm2) fn plain(code: u32, payload: &[u8]) -> Vec<u8> {
        framed(0x8001, code, payload)
    }

    pub(in crate::library::tpm2) fn password_area(password: &[u8]) -> Vec<u8> {
        let mut area = RS_PW.to_be_bytes().to_vec();
        push_tpm2b(&mut area, &[]);
        area.push(0x00);
        push_tpm2b(&mut area, password);
        let mut out = (area.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(&area);
        out
    }

    pub(in crate::library::tpm2) fn sessioned(
        code: u32,
        handles: &[u32],
        password: &[u8],
        parameters: &[u8],
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        for handle in handles {
            payload.extend_from_slice(&handle.to_be_bytes());
        }
        payload.extend_from_slice(&password_area(password));
        payload.extend_from_slice(parameters);
        framed(0x8002, code, &payload)
    }

    pub(in crate::library::tpm2) fn handles(list: &[u32]) -> Vec<u8> {
        let mut out = Vec::new();
        for handle in list {
            out.extend_from_slice(&handle.to_be_bytes());
        }
        out
    }

    pub(in crate::library::tpm2) fn cap_transient() -> Vec<u8> {
        let mut payload = 1u32.to_be_bytes().to_vec();
        payload.extend_from_slice(&0x8000_0000u32.to_be_bytes());
        payload.extend_from_slice(&8u32.to_be_bytes());
        plain(CC_GET_CAPABILITY, &payload)
    }

    pub(in crate::library::tpm2) fn read_public(handle: u32) -> Vec<u8> {
        plain(CC_READ_PUBLIC, &handle.to_be_bytes())
    }

    pub(in crate::library::tpm2) fn load_external(
        sensitive: &[u8],
        public: &[u8],
        hierarchy: u32,
    ) -> Vec<u8> {
        let mut payload = tpm2b(sensitive);
        payload.extend_from_slice(&tpm2b(public));
        payload.extend_from_slice(&hierarchy.to_be_bytes());
        plain(CC_LOAD_EXTERNAL, &payload)
    }

    pub(in crate::library::tpm2) fn load(
        parent: u32,
        password: &[u8],
        private: &[u8],
        public: &[u8],
    ) -> Vec<u8> {
        let mut parameters = tpm2b(private);
        parameters.extend_from_slice(&tpm2b(public));
        sessioned(CC_LOAD, &[parent], password, &parameters)
    }

    pub(in crate::library::tpm2) fn unseal(handle: u32, password: &[u8]) -> Vec<u8> {
        sessioned(CC_UNSEAL, &[handle], password, &[])
    }

    pub(in crate::library::tpm2) fn object_change_auth(
        object: u32,
        parent: u32,
        password: &[u8],
        new_auth: &[u8],
    ) -> Vec<u8> {
        sessioned(
            CC_OBJECT_CHANGE_AUTH,
            &[object, parent],
            password,
            &tpm2b(new_auth),
        )
    }

    pub(in crate::library::tpm2) fn context_save(handle: u32) -> Vec<u8> {
        plain(CC_CONTEXT_SAVE, &handle.to_be_bytes())
    }

    pub(in crate::library::tpm2) fn context_load(context: &[u8]) -> Vec<u8> {
        plain(CC_CONTEXT_LOAD, context)
    }

    pub(in crate::library::tpm2) fn response_parameters(response: &[u8]) -> Vec<u8> {
        if response[..2] == [0x80, 0x01] {
            return response[10..].to_vec();
        }
        let size = u32::from_be_bytes(response[10..14].try_into().unwrap()) as usize;
        response[14..14 + size].to_vec()
    }

    pub(in crate::library::tpm2) fn saved_context(label: &str) -> Vec<u8> {
        response_parameters(vector(label))
    }

    pub(in crate::library::tpm2) fn created_child(label: &str) -> (Vec<u8>, Vec<u8>) {
        let parameters = response_parameters(vector(label));
        let private_len = u16::from_be_bytes(parameters[..2].try_into().unwrap()) as usize;
        let private = parameters[2..2 + private_len].to_vec();
        let rest = &parameters[2 + private_len..];
        let public_len = u16::from_be_bytes(rest[..2].try_into().unwrap()) as usize;
        (private, rest[2..2 + public_len].to_vec())
    }

    pub(in crate::library::tpm2) fn rotated_private(label: &str) -> Vec<u8> {
        let parameters = response_parameters(vector(label));
        let length = u16::from_be_bytes(parameters[..2].try_into().unwrap()) as usize;
        parameters[2..2 + length].to_vec()
    }

    pub(in crate::library::tpm2) fn rsa_sign_public(modulus: &[u8]) -> Vec<u8> {
        let mut out = 0x0001u16.to_be_bytes().to_vec();
        out.extend_from_slice(&0x000bu16.to_be_bytes());
        out.extend_from_slice(&0x0004_0472u32.to_be_bytes());
        push_tpm2b(&mut out, &[]);
        out.extend_from_slice(&0x0010u16.to_be_bytes());
        out.extend_from_slice(&0x0014u16.to_be_bytes());
        out.extend_from_slice(&0x000bu16.to_be_bytes());
        out.extend_from_slice(&2048u16.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        push_tpm2b(&mut out, modulus);
        out
    }

    pub(in crate::library::tpm2) fn external_modulus() -> Vec<u8> {
        let mut modulus = vec![0xc7u8];
        modulus.extend((1..255u32).map(|index| ((index * 7 + 3) & 0xff) as u8));
        modulus.push(0x8f);
        modulus
    }

    pub(in crate::library::tpm2) fn keyed_hash_public(unique: &[u8], attributes: u32) -> Vec<u8> {
        let mut out = 0x0008u16.to_be_bytes().to_vec();
        out.extend_from_slice(&0x000bu16.to_be_bytes());
        out.extend_from_slice(&attributes.to_be_bytes());
        push_tpm2b(&mut out, &[]);
        out.extend_from_slice(&0x0010u16.to_be_bytes());
        push_tpm2b(&mut out, unique);
        out
    }

    pub(in crate::library::tpm2) fn keyed_hash_sensitive(
        seed: &[u8],
        data: &[u8],
        auth: &[u8],
    ) -> Vec<u8> {
        let mut out = 0x0008u16.to_be_bytes().to_vec();
        push_tpm2b(&mut out, auth);
        push_tpm2b(&mut out, seed);
        push_tpm2b(&mut out, data);
        out
    }

    pub(in crate::library::tpm2) fn seal_seed() -> Vec<u8> {
        (0..32u8).collect()
    }

    pub(in crate::library::tpm2) const SEAL_DATA: &[u8] = b"external sealed payload";

    pub(in crate::library::tpm2) const ENC_NONCE_CALLER: [u8; 32] = [0x5a; 32];

    pub(in crate::library::tpm2) fn encrypting_session() -> Vec<u8> {
        let mut payload = handles(&[RH_NULL, RH_NULL]);
        push_tpm2b(&mut payload, &ENC_NONCE_CALLER);
        push_tpm2b(&mut payload, &[]);
        payload.push(0x00);
        payload.extend_from_slice(&0x000au16.to_be_bytes());
        payload.extend_from_slice(&0x000bu16.to_be_bytes());
        payload.extend_from_slice(&0x000bu16.to_be_bytes());
        plain(0x0000_0176, &payload)
    }

    pub(in crate::library::tpm2) fn session_nonce_tpm(label: &str) -> Vec<u8> {
        let response = vector(label);
        let length = u16::from_be_bytes(response[14..16].try_into().unwrap()) as usize;
        response[16..16 + length].to_vec()
    }

    pub(in crate::library::tpm2) fn object_name(public: &[u8]) -> Vec<u8> {
        let mut hasher = crate::library::tpm2::crypto::Hasher::new(0x000b).expect("sha256");
        hasher.update(public);
        let mut name = 0x000bu16.to_be_bytes().to_vec();
        name.extend_from_slice(&hasher.finalize());
        name
    }

    pub(in crate::library::tpm2) fn created_public(label: &str) -> Vec<u8> {
        created_child(label).1
    }

    pub(in crate::library::tpm2) fn primary_public(label: &str) -> Vec<u8> {
        let response = vector(label);
        let size = u32::from_be_bytes(response[14..18].try_into().unwrap()) as usize;
        let parameters = &response[18..18 + size];
        let length = u16::from_be_bytes(parameters[..2].try_into().unwrap()) as usize;
        parameters[2..2 + length].to_vec()
    }

    fn xor_mask(key: &[u8], newer: &[u8], older: &[u8], length: usize) -> Vec<u8> {
        crate::library::tpm2::crypto::kdfa(0x000b, key, b"XOR\0", newer, older, (length * 8) as u32)
            .expect("the mask derives")
    }

    pub(in crate::library::tpm2) struct EncryptedCommand<'a> {
        pub(in crate::library::tpm2) code: u32,
        pub(in crate::library::tpm2) handle_list: &'a [u32],
        pub(in crate::library::tpm2) names: &'a [Vec<u8>],
        pub(in crate::library::tpm2) parameters: Vec<u8>,
        pub(in crate::library::tpm2) session_value: &'a [u8],
        pub(in crate::library::tpm2) attributes: u8,
        pub(in crate::library::tpm2) nonce_tpm: Vec<u8>,
    }

    impl EncryptedCommand<'_> {
        pub(in crate::library::tpm2) fn build(&self) -> Vec<u8> {
            let mut parameters = self.parameters.clone();
            if self.attributes & 0x20 != 0 {
                let size = u16::from_be_bytes(parameters[..2].try_into().unwrap()) as usize;
                let mask = xor_mask(self.session_value, &ENC_NONCE_CALLER, &self.nonce_tpm, size);
                for (byte, mask_byte) in parameters[2..2 + size].iter_mut().zip(mask.iter()) {
                    *byte ^= mask_byte;
                }
            }
            let mut hasher = crate::library::tpm2::crypto::Hasher::new(0x000b).expect("sha256");
            hasher.update(&self.code.to_be_bytes());
            for name in self.names {
                hasher.update(name);
            }
            hasher.update(&parameters);
            let cp_hash = hasher.finalize();

            let mut hmac = crate::library::tpm2::crypto::HmacState::new(0x000b, self.session_value)
                .expect("sha256 hmac");
            hmac.update(&cp_hash);
            hmac.update(&ENC_NONCE_CALLER);
            hmac.update(&self.nonce_tpm);
            hmac.update(&[self.attributes]);
            let digest = hmac.finalize();

            let mut area = 0x0200_0000u32.to_be_bytes().to_vec();
            push_tpm2b(&mut area, &ENC_NONCE_CALLER);
            area.push(self.attributes);
            push_tpm2b(&mut area, &digest);

            let mut payload = handles(self.handle_list);
            payload.extend_from_slice(&(area.len() as u32).to_be_bytes());
            payload.extend_from_slice(&area);
            payload.extend_from_slice(&parameters);
            framed(0x8002, self.code, &payload)
        }
    }

    pub(in crate::library::tpm2) fn decode_volatile(
        snapshot: &str,
    ) -> crate::library::tpm2::volatile::OwnedVolatileState {
        use crate::library::tpm2::persistent::{
            PersistentAllEnvelope, materialize_persistent_state,
        };
        use crate::library::tpm2::runtime::commit_restored_state;
        use crate::library::tpm2::{
            decode_volatile_blob, parse_persistent_all_payload, volatile_validation_context,
        };
        let envelope = PersistentAllEnvelope::parse(vector(&format!("PERMALL_{snapshot}")))
            .expect("the envelope parses");
        let decoded = parse_persistent_all_payload(&envelope).expect("the payload decodes");
        let state = materialize_persistent_state(decoded).expect("the state materializes");
        let runtime = commit_restored_state(state).expect("the state commits");
        let context = volatile_validation_context(&runtime).expect("the context builds");
        decode_volatile_blob(&context, vector(&format!("VOLATILE_{snapshot}")), &clock())
            .expect("the volatile record decodes")
    }

    pub(in crate::library::tpm2) fn seal_unique() -> Vec<u8> {
        let mut hasher = crate::library::tpm2::crypto::Hasher::new(0x000b).expect("sha256");
        hasher.update(&seal_seed());
        hasher.update(SEAL_DATA);
        hasher.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::constants::TPM_RC_INSUFFICIENT;

    fn sensitive_bytes(sensitive_type: u16, auth: &[u8], seed: &[u8], secret: &[u8]) -> Vec<u8> {
        let mut out = sensitive_type.to_be_bytes().to_vec();
        for field in [auth, seed, secret] {
            out.extend_from_slice(&(field.len() as u16).to_be_bytes());
            out.extend_from_slice(field);
        }
        out
    }

    #[test]
    fn modifier_upstream_safe_addition_rule() {
        assert_eq!(add_modifier(0x08a, 0x140), 0x1ca);
        assert_eq!(add_modifier(0x1ca, 0x140), 0x1ca, "already decorated");
        assert_eq!(add_modifier(0x145, 0x140), 0x145, "not a format-one code");
        assert_eq!(add_modifier(0x09a, 0x140), 0x1da);
    }

    #[test]
    fn sensitive_area_unknown_type_rejection() {
        for sensitive_type in [0x0000u16, 0x0010, 0x0004, 0xffff] {
            let bytes = sensitive_bytes(sensitive_type, &[], &[], &[]);
            let mut reader = TemplateReader::new(&bytes);
            assert_eq!(read_sensitive_area(&mut reader).err(), Some(TPM_RC_TYPE));
        }
    }

    #[test]
    fn sensitive_area_strict_prefix_insufficiency() {
        let bytes = sensitive_bytes(TPM_ALG_KEYEDHASH, b"auth", &[0x11; 32], b"payload");
        for length in 0..bytes.len() {
            let mut reader = TemplateReader::new(&bytes[..length]);
            let error = read_sensitive_area(&mut reader)
                .err()
                .expect("a strict prefix fails");
            assert!(
                error == TPM_RC_INSUFFICIENT || error == TPM_RC_TYPE,
                "prefix {length} produced {error:#05x}"
            );
        }
        let mut reader = TemplateReader::new(&bytes);
        assert!(read_sensitive_area(&mut reader).is_ok());
    }

    #[test]
    fn oversized_sensitive_field_size_errors() {
        for (sensitive_type, secret) in [
            (TPM_ALG_KEYEDHASH, vec![0u8; MAX_SYM_DATA + 1]),
            (TPM_ALG_SYMCIPHER, vec![0u8; MAX_SYM_KEY_BYTES + 1]),
            (TPM_ALG_ECC, vec![0u8; MAX_ECC_KEY_BYTES + 1]),
            (TPM_ALG_RSA, vec![0u8; RSA_PRIVATE_SIZE + 1]),
        ] {
            let bytes = sensitive_bytes(sensitive_type, &[], &[], &secret);
            let mut reader = TemplateReader::new(&bytes);
            assert_eq!(
                read_sensitive_area(&mut reader).err(),
                Some(TPM_RC_SIZE),
                "type {sensitive_type:#06x}"
            );
        }
    }

    #[test]
    fn sized_sensitive_area_declared_length_check() {
        let inner = sensitive_bytes(TPM_ALG_KEYEDHASH, &[], &[0x11; 32], b"data");
        let mut exact = (inner.len() as u16).to_be_bytes().to_vec();
        exact.extend_from_slice(&inner);
        let mut reader = TemplateReader::new(&exact);
        assert!(
            read_sized_sensitive_area(&mut reader)
                .ok()
                .flatten()
                .is_some()
        );

        let mut empty = 0u16.to_be_bytes().to_vec();
        empty.extend_from_slice(&inner);
        let mut reader = TemplateReader::new(&empty);
        assert!(
            read_sized_sensitive_area(&mut reader)
                .expect("a zero-sized area parses")
                .is_none()
        );

        let mut short = ((inner.len() - 1) as u16).to_be_bytes().to_vec();
        short.extend_from_slice(&inner);
        let mut reader = TemplateReader::new(&short);
        assert_eq!(
            read_sized_sensitive_area(&mut reader).err(),
            Some(TPM_RC_SIZE)
        );
    }
}
