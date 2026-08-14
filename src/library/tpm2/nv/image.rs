use crate::ffi_types::TpmResult;
use crate::library::constants::TPM_FAIL;

use super::layout;
use crate::library::tpm2::hierarchy::{
    TPM_RH_ENDORSEMENT, TPM_RH_NULL, TPM_RH_OWNER, TPM_RH_PLATFORM,
};
use crate::library::tpm2::object::{
    ANY_HASH_STATE_MAGIC, ANY_HASH_STATE_VERSION, ANY_OBJECT_MAGIC, ANY_OBJECT_VERSION,
    ATTR_EPS_HIERARCHY, ATTR_EVENT_SEQ, ATTR_HASH_SEQ, ATTR_HMAC_SEQ, ATTR_OCCUPIED,
    ATTR_PPS_HIERARCHY, ATTR_SPS_HIERARCHY, BN_PRIME_T_MAGIC, BN_PRIME_T_VERSION,
    HASH_OBJECT_MAGIC, HASH_OBJECT_VERSION, HASH_STATE_COUNT, HASH_STATE_MAGIC,
    HASH_STATE_SHA_VERSION, HASH_STATE_SHA1_MAGIC, HASH_STATE_SHA256_MAGIC,
    HASH_STATE_SHA384_MAGIC, HASH_STATE_SHA512_MAGIC, HASH_STATE_VERSION, OBJECT_MAGIC,
    PRIVATE_EXPONENT_T_MAGIC, PRIVATE_EXPONENT_T_VERSION,
};
use crate::library::tpm2::persistent::{
    OwnedAnyObject, OwnedAnyObjectBody, OwnedBnPrime, OwnedCommandBitmap, OwnedHashObjectBody,
    OwnedHashPayload, OwnedHashState, OwnedIndexOrderlyRam, OwnedNvIndex, OwnedObjectBody,
    OwnedOrderlyData, OwnedPcrAllocation, OwnedPersistentData, OwnedPersistentState, OwnedPublicId,
    OwnedStateClearData, OwnedStateResetData, OwnedTpmtPublic, OwnedTpmtSensitive, OwnedUserNvram,
    OwnedUserNvramEntry,
};
use crate::library::tpm2::profile::PersistentObjectFormat;
use crate::library::tpm2::public::{
    PublicParms, Scheme, SymDefObject, TPM_ALG_RSA, TPM_ALG_SHA384,
};

const _: () = assert!(cfg!(target_endian = "little") == (layout::NATIVE_LITTLE_ENDIAN == 1));

struct Region<'a> {
    bytes: &'a mut [u8],
}

impl Region<'_> {
    fn put(&mut self, offset: usize, data: &[u8]) -> Result<(), TpmResult> {
        let end = offset.checked_add(data.len()).ok_or(TPM_FAIL)?;
        if end > self.bytes.len() {
            return Err(TPM_FAIL);
        }
        self.bytes[offset..end].copy_from_slice(data);
        Ok(())
    }

    fn put_u8(&mut self, offset: usize, value: u8) -> Result<(), TpmResult> {
        self.put(offset, &[value])
    }

    fn put_u16(&mut self, offset: usize, value: u16) -> Result<(), TpmResult> {
        self.put(offset, &value.to_le_bytes())
    }

    fn put_u32(&mut self, offset: usize, value: u32) -> Result<(), TpmResult> {
        self.put(offset, &value.to_le_bytes())
    }

    fn put_u64(&mut self, offset: usize, value: u64) -> Result<(), TpmResult> {
        self.put(offset, &value.to_le_bytes())
    }

    fn put_bool(&mut self, offset: usize, value: bool) -> Result<(), TpmResult> {
        self.put_u32(offset, u32::from(value))
    }

    fn put_tpm2b(
        &mut self,
        offset: usize,
        total_size: usize,
        data: &[u8],
    ) -> Result<(), TpmResult> {
        if data.len() + layout::TPM2B_DIGEST_BUFFER > total_size {
            return Err(TPM_FAIL);
        }
        self.put_u16(offset, u16::try_from(data.len()).map_err(|_| TPM_FAIL)?)?;
        self.put(offset + layout::TPM2B_DIGEST_BUFFER, data)
    }
}

pub(in crate::library::tpm2) fn command_bitmap_image(
    bitmap: &OwnedCommandBitmap,
    capacity: usize,
) -> Result<Vec<u8>, TpmResult> {
    let mut image = vec![0u8; capacity];
    if !bitmap.compressed {
        if bitmap.bytes.len() > capacity {
            return Err(TPM_FAIL);
        }
        image[..bitmap.bytes.len()].copy_from_slice(&bitmap.bytes);
        return Ok(image);
    }
    let max_bit = (bitmap.bytes.len() * 8).min(layout::COMPRESSED_COMMAND_BITS.len());
    for bit in 0..max_bit {
        if bitmap.bytes[bit / 8] & (1 << (bit % 8)) != 0 {
            let index = usize::from(layout::COMPRESSED_COMMAND_BITS[bit]);
            let byte = index / 8;
            if byte >= capacity {
                return Err(TPM_FAIL);
            }
            image[byte] |= 1 << (index % 8);
        }
    }
    Ok(image)
}

fn put_pcr_allocation(
    region: &mut Region<'_>,
    base: usize,
    allocation: &OwnedPcrAllocation,
) -> Result<(), TpmResult> {
    use layout::{
        SIZEOF_TPMS_PCR_SELECT_ARRAY, SIZEOF_TPMS_PCR_SELECTION, TPML_PCR_SELECTION_SELECTIONS,
        TPMS_PCR_SELECTION_PCR_SELECT, TPMS_PCR_SELECTION_SIZEOF_SELECT,
    };

    let count = allocation.selections.len();
    if count
        > (layout::SIZEOF_TPML_PCR_SELECTION - TPML_PCR_SELECTION_SELECTIONS)
            / SIZEOF_TPMS_PCR_SELECTION
    {
        return Err(TPM_FAIL);
    }
    region.put_u32(base, u32::try_from(count).map_err(|_| TPM_FAIL)?)?;
    for (index, selection) in allocation.selections.iter().enumerate() {
        let entry = base + TPML_PCR_SELECTION_SELECTIONS + index * SIZEOF_TPMS_PCR_SELECTION;
        if selection.select.len() > SIZEOF_TPMS_PCR_SELECT_ARRAY {
            return Err(TPM_FAIL);
        }
        region.put_u16(entry, selection.hash_alg)?;
        region.put_u8(
            entry + TPMS_PCR_SELECTION_SIZEOF_SELECT,
            u8::try_from(selection.select.len()).map_err(|_| TPM_FAIL)?,
        )?;
        region.put(entry + TPMS_PCR_SELECTION_PCR_SELECT, &selection.select)?;
    }
    Ok(())
}

fn write_persistent_data(
    region: &mut Region<'_>,
    data: &OwnedPersistentData,
) -> Result<(), TpmResult> {
    use layout::*;

    region.put_bool(PD_DISABLE_CLEAR, data.disable_clear)?;
    region.put_u16(PD_OWNER_ALG, data.owner_alg)?;
    region.put_u16(PD_ENDORSEMENT_ALG, data.endorsement_alg)?;
    region.put_u16(PD_LOCKOUT_ALG, data.lockout_alg)?;
    region.put_tpm2b(PD_OWNER_POLICY, SIZEOF_TPM2B_DIGEST, &data.owner_policy)?;
    region.put_tpm2b(
        PD_ENDORSEMENT_POLICY,
        SIZEOF_TPM2B_DIGEST,
        &data.endorsement_policy,
    )?;
    region.put_tpm2b(PD_LOCKOUT_POLICY, SIZEOF_TPM2B_DIGEST, &data.lockout_policy)?;
    region.put_tpm2b(
        PD_OWNER_AUTH,
        SIZEOF_TPM2B_DIGEST,
        data.owner_auth.as_bytes(),
    )?;
    region.put_tpm2b(
        PD_ENDORSEMENT_AUTH,
        SIZEOF_TPM2B_DIGEST,
        data.endorsement_auth.as_bytes(),
    )?;
    region.put_tpm2b(
        PD_LOCKOUT_AUTH,
        SIZEOF_TPM2B_DIGEST,
        data.lockout_auth.as_bytes(),
    )?;
    region.put_tpm2b(PD_EP_SEED, SIZEOF_TPM2B_SEED, data.ep_seed.as_bytes())?;
    region.put_tpm2b(PD_SP_SEED, SIZEOF_TPM2B_SEED, data.sp_seed.as_bytes())?;
    region.put_tpm2b(PD_PP_SEED, SIZEOF_TPM2B_SEED, data.pp_seed.as_bytes())?;
    region.put_u8(PD_EP_SEED_COMPAT_LEVEL, data.ep_seed_compat_level)?;
    region.put_u8(PD_SP_SEED_COMPAT_LEVEL, data.sp_seed_compat_level)?;
    region.put_u8(PD_PP_SEED_COMPAT_LEVEL, data.pp_seed_compat_level)?;
    region.put_tpm2b(PD_PH_PROOF, SIZEOF_TPM2B_PROOF, data.ph_proof.as_bytes())?;
    region.put_tpm2b(PD_SH_PROOF, SIZEOF_TPM2B_PROOF, data.sh_proof.as_bytes())?;
    region.put_tpm2b(PD_EH_PROOF, SIZEOF_TPM2B_PROOF, data.eh_proof.as_bytes())?;
    region.put_u64(PD_TOTAL_RESET_COUNT, data.total_reset_count)?;
    region.put_u32(PD_RESET_COUNT, data.reset_count)?;

    for (index, policy) in data.pcr_policies.iter().enumerate() {
        region.put_u16(
            PD_PCR_POLICIES + PCR_POLICY_HASH_ALG + index * 2,
            policy.hash_alg,
        )?;
        region.put_tpm2b(
            PD_PCR_POLICIES + PCR_POLICY_POLICY + index * SIZEOF_TPM2B_DIGEST,
            SIZEOF_TPM2B_DIGEST,
            &policy.policy,
        )?;
    }

    put_pcr_allocation(region, PD_PCR_ALLOCATED, &data.pcr_allocated)?;

    region.put(
        PD_PP_LIST,
        &command_bitmap_image(&data.pp_list, SIZEOF_PD_PP_LIST)?,
    )?;

    region.put_u32(PD_FAILED_TRIES, data.failed_tries)?;
    region.put_u32(PD_MAX_TRIES, data.max_tries)?;
    region.put_u32(PD_RECOVERY_TIME, data.recovery_time)?;
    region.put_u32(PD_LOCKOUT_RECOVERY, data.lockout_recovery)?;
    region.put_bool(PD_LOCKOUT_AUTH_ENABLED, data.lockout_auth_enabled)?;
    region.put_u16(PD_ORDERLY_STATE, data.orderly_state)?;
    region.put(
        PD_AUDIT_COMMANDS,
        &command_bitmap_image(&data.audit_commands, SIZEOF_PD_AUDIT_COMMANDS)?,
    )?;
    region.put_u16(PD_AUDIT_HASH_ALG, data.audit_hash_alg)?;
    region.put_u64(PD_AUDIT_COUNTER, data.audit_counter)?;
    region.put_u32(PD_ALGORITHM_SET, data.algorithm_set)?;
    region.put_u32(PD_FIRMWARE_V1, data.firmware_v1)?;
    region.put_u32(PD_FIRMWARE_V2, data.firmware_v2)?;
    region.put_u32(PD_TIME_EPOCH, data.time_epoch)?;
    Ok(())
}

fn write_orderly_data(region: &mut Region<'_>, data: &OwnedOrderlyData) -> Result<(), TpmResult> {
    use layout::*;

    region.put_u64(OD_CLOCK, data.clock)?;
    region.put_u8(OD_CLOCK_SAFE, data.clock_safe)?;

    let drbg = OD_DRBG_STATE;
    region.put_u64(drbg + DRBG_RESEED_COUNTER, data.drbg_state.reseed_counter)?;
    region.put_u32(drbg + DRBG_MAGIC_FIELD, data.drbg_state.drbg_magic)?;
    let seed = data.drbg_state.seed.as_bytes();
    if seed.len() != SIZEOF_DRBG_SEED {
        return Err(TPM_FAIL);
    }
    region.put(drbg + DRBG_SEED_FIELD, seed)?;
    for (index, value) in data.drbg_state.last_value.iter().enumerate() {
        region.put_u32(drbg + DRBG_LAST_VALUE + index * 4, *value)?;
    }

    region.put_u64(OD_SELF_HEAL_TIMER, data.self_heal_timer)?;
    region.put_u64(OD_LOCKOUT_TIMER, data.lockout_timer)?;
    region.put_u64(OD_TIME, data.time)?;
    Ok(())
}

fn write_state_reset(region: &mut Region<'_>, data: &OwnedStateResetData) -> Result<(), TpmResult> {
    use layout::*;

    region.put_tpm2b(
        SRD_NULL_PROOF,
        SIZEOF_TPM2B_PROOF,
        data.null_proof.as_bytes(),
    )?;
    region.put_tpm2b(SRD_NULL_SEED, SIZEOF_TPM2B_SEED, data.null_seed.as_bytes())?;
    region.put_u32(SRD_CLEAR_COUNT, data.clear_count)?;
    region.put_u64(SRD_OBJECT_CONTEXT_ID, data.object_context_id)?;
    for (index, slot) in data.context_array.iter().enumerate() {
        region.put_u16(SRD_CONTEXT_ARRAY + index * SIZEOF_CONTEXT_SLOT, *slot)?;
    }
    region.put_u64(SRD_CONTEXT_COUNTER, data.context_counter)?;
    region.put_tpm2b(
        SRD_COMMAND_AUDIT_DIGEST,
        SIZEOF_TPM2B_DIGEST,
        &data.command_audit_digest,
    )?;
    region.put_u32(SRD_RESTART_COUNT, data.restart_count)?;
    region.put_u32(SRD_PCR_COUNTER, data.pcr_counter)?;
    region.put_u64(SRD_COMMIT_COUNTER, data.commit_counter)?;
    region.put_tpm2b(
        SRD_COMMIT_NONCE,
        SIZEOF_TPM2B_DIGEST,
        data.commit_nonce.as_bytes(),
    )?;
    if data.commit_array.len() != SIZEOF_SRD_COMMIT_ARRAY {
        return Err(TPM_FAIL);
    }
    region.put(SRD_COMMIT_ARRAY, &data.commit_array)?;
    Ok(())
}

fn write_state_clear(region: &mut Region<'_>, data: &OwnedStateClearData) -> Result<(), TpmResult> {
    use layout::*;

    region.put_bool(SCD_SH_ENABLE, data.sh_enable)?;
    region.put_bool(SCD_EH_ENABLE, data.eh_enable)?;
    region.put_bool(SCD_PH_ENABLE_NV, data.ph_enable_nv)?;
    region.put_u16(SCD_PLATFORM_ALG, data.platform_alg)?;
    region.put_tpm2b(
        SCD_PLATFORM_POLICY,
        SIZEOF_TPM2B_DIGEST,
        &data.platform_policy,
    )?;
    region.put_tpm2b(
        SCD_PLATFORM_AUTH,
        SIZEOF_TPM2B_DIGEST,
        data.platform_auth.as_bytes(),
    )?;

    const BANK_OFFSETS: [usize; 4] = [
        layout::PCR_SAVE_SHA1,
        layout::PCR_SAVE_SHA256,
        layout::PCR_SAVE_SHA384,
        layout::PCR_SAVE_SHA512,
    ];
    const BANK_SIZES: [usize; 4] = [
        layout::PCR_SAVE_SHA256 - layout::PCR_SAVE_SHA1,
        layout::PCR_SAVE_SHA384 - layout::PCR_SAVE_SHA256,
        layout::PCR_SAVE_SHA512 - layout::PCR_SAVE_SHA384,
        layout::PCR_SAVE_PCR_COUNTER - layout::PCR_SAVE_SHA512,
    ];
    for (index, bank) in data.pcr_save.iter().enumerate() {
        let Some(bank) = bank else { continue };
        if bank.pcrs.len() != BANK_SIZES[index] {
            return Err(TPM_FAIL);
        }
        region.put(SCD_PCR_SAVE + BANK_OFFSETS[index], &bank.pcrs)?;
    }

    for (index, auth) in data.pcr_auth_values.iter().enumerate() {
        region.put_tpm2b(
            SCD_PCR_AUTH_VALUES + PCR_AUTHVALUE_AUTH + index * SIZEOF_TPM2B_DIGEST,
            SIZEOF_TPM2B_DIGEST,
            auth.as_bytes(),
        )?;
    }
    Ok(())
}

fn write_index_orderly_ram(
    region: &mut Region<'_>,
    ram: &OwnedIndexOrderlyRam,
) -> Result<(), TpmResult> {
    use layout::*;

    let mut offset = 0usize;
    for entry in &ram.entries {
        let size = SIZEOF_NV_RAM_HEADER
            .checked_add(entry.data.len())
            .ok_or(TPM_FAIL)?;
        region.put_u32(
            offset + NV_RAM_HEADER_SIZE_FIELD,
            u32::try_from(size).map_err(|_| TPM_FAIL)?,
        )?;
        region.put_u32(offset + NV_RAM_HEADER_HANDLE, entry.handle)?;
        region.put_u32(offset + NV_RAM_HEADER_ATTRIBUTES, entry.attributes)?;
        region.put(offset + SIZEOF_NV_RAM_HEADER, &entry.data)?;
        offset = offset.checked_add(size).ok_or(TPM_FAIL)?;
    }
    Ok(())
}

pub(in crate::library::tpm2) struct WireWriter {
    pub(in crate::library::tpm2) out: Vec<u8>,
}

impl WireWriter {
    pub(in crate::library::tpm2) fn new() -> Self {
        Self { out: Vec::new() }
    }

    pub(in crate::library::tpm2) fn u8(&mut self, value: u8) {
        self.out.push(value);
    }

    pub(in crate::library::tpm2) fn u16(&mut self, value: u16) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }

    pub(in crate::library::tpm2) fn u32(&mut self, value: u32) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }

    pub(in crate::library::tpm2) fn u64(&mut self, value: u64) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }

    pub(in crate::library::tpm2) fn bytes(&mut self, data: &[u8]) {
        self.out.extend_from_slice(data);
    }

    pub(in crate::library::tpm2) fn tpm2b(&mut self, data: &[u8]) -> Result<(), TpmResult> {
        self.u16(u16::try_from(data.len()).map_err(|_| TPM_FAIL)?);
        self.bytes(data);
        Ok(())
    }

    pub(in crate::library::tpm2) fn nv_header(
        &mut self,
        version: u16,
        magic: u32,
        min_version: u16,
    ) {
        self.u16(version);
        self.u32(magic);
        self.u16(min_version);
    }

    pub(in crate::library::tpm2) fn block(
        &mut self,
        present: bool,
        payload: impl FnOnce(&mut Self) -> Result<(), TpmResult>,
    ) -> Result<(), TpmResult> {
        self.u8(u8::from(present));
        let patch = self.out.len();
        self.u16(0);
        if present {
            payload(self)?;
        }
        let size = u16::try_from(self.out.len() - patch - 2).map_err(|_| TPM_FAIL)?;
        self.out[patch..patch + 2].copy_from_slice(&size.to_be_bytes());
        Ok(())
    }
}

fn marshal_sym_def_object(w: &mut WireWriter, sym: &SymDefObject) {
    w.u16(sym.algorithm);
    if let Some(key_bits) = sym.key_bits {
        w.u16(key_bits);
    }
    if let Some(mode) = sym.mode {
        w.u16(mode);
    }
}

fn marshal_scheme(w: &mut WireWriter, scheme: &Scheme) {
    w.u16(scheme.scheme);
    if let Some(hash_alg) = scheme.hash_alg {
        w.u16(hash_alg);
    }
    if let Some(count) = scheme.count {
        w.u16(count);
    }
    if let Some(kdf) = scheme.kdf {
        w.u16(kdf);
    }
}

fn marshal_tpmt_public(w: &mut WireWriter, public: &OwnedTpmtPublic) -> Result<(), TpmResult> {
    w.u16(public.object_type);
    w.u16(public.name_alg);
    w.u32(public.object_attributes);
    w.tpm2b(&public.auth_policy)?;
    match &public.parameters {
        PublicParms::KeyedHash(scheme) => marshal_scheme(w, scheme),
        PublicParms::SymCipher(sym) => marshal_sym_def_object(w, sym),
        PublicParms::Rsa {
            symmetric,
            scheme,
            key_bits,
            exponent,
        } => {
            marshal_sym_def_object(w, symmetric);
            marshal_scheme(w, scheme);
            w.u16(*key_bits);
            w.u32(*exponent);
        }
        PublicParms::Ecc {
            symmetric,
            scheme,
            curve_id,
            kdf,
        } => {
            marshal_sym_def_object(w, symmetric);
            marshal_scheme(w, scheme);
            w.u16(*curve_id);
            marshal_scheme(w, kdf);
        }
    }
    match &public.unique {
        OwnedPublicId::KeyedHash(bytes) | OwnedPublicId::Sym(bytes) | OwnedPublicId::Rsa(bytes) => {
            w.tpm2b(bytes)?
        }
        OwnedPublicId::Ecc { x, y } => {
            w.tpm2b(x)?;
            w.tpm2b(y)?;
        }
    }
    Ok(())
}

fn marshal_nv_tpmt_sensitive(
    w: &mut WireWriter,
    sensitive: &OwnedTpmtSensitive,
) -> Result<(), TpmResult> {
    w.u16(sensitive.sensitive_type);
    w.tpm2b(sensitive.auth_value.as_bytes())?;
    w.tpm2b(sensitive.seed_value.as_bytes())?;
    if let Some(composite) = &sensitive.sensitive {
        w.tpm2b(composite.as_bytes())?;
    }
    Ok(())
}

fn bn_prime_word_bytes(prime: &OwnedBnPrime) -> Result<Vec<u8>, TpmResult> {
    let size_words = usize::from(prime.numbytes).div_ceil(8);
    let padded = size_words.checked_mul(8).ok_or(TPM_FAIL)?;
    let mut data = prime.data.as_bytes().to_vec();
    if data.len() > padded {
        return Err(TPM_FAIL);
    }
    data.resize(padded, 0);
    Ok(data)
}

fn marshal_bn_prime(w: &mut WireWriter, prime: Option<&OwnedBnPrime>) -> Result<(), TpmResult> {
    w.nv_header(BN_PRIME_T_VERSION, BN_PRIME_T_MAGIC, 1);
    match prime {
        Some(prime) => {
            let data = bn_prime_word_bytes(prime)?;
            w.u16(u16::try_from(data.len()).map_err(|_| TPM_FAIL)?);
            w.bytes(&data);
        }
        None => w.u16(0),
    }
    w.block(true, |_| Ok(()))
}

fn marshal_private_exponent(
    w: &mut WireWriter,
    primes: [Option<&OwnedBnPrime>; 4],
) -> Result<(), TpmResult> {
    w.nv_header(PRIVATE_EXPONENT_T_VERSION, PRIVATE_EXPONENT_T_MAGIC, 1);
    for prime in primes {
        marshal_bn_prime(w, prime)?;
    }
    w.block(true, |_| Ok(()))
}

fn hierarchy_from_attributes(attributes: u32) -> u32 {
    if attributes & ATTR_SPS_HIERARCHY != 0 {
        TPM_RH_OWNER
    } else if attributes & ATTR_EPS_HIERARCHY != 0 {
        TPM_RH_ENDORSEMENT
    } else if attributes & ATTR_PPS_HIERARCHY != 0 {
        TPM_RH_PLATFORM
    } else {
        TPM_RH_NULL
    }
}

fn marshal_object(
    w: &mut WireWriter,
    body: &OwnedObjectBody,
    attributes: u32,
    version: u16,
) -> Result<(), TpmResult> {
    w.nv_header(version, OBJECT_MAGIC, version);
    marshal_tpmt_public(w, &body.public)?;
    marshal_nv_tpmt_sensitive(w, &body.sensitive)?;

    let has_block = version < 4 || body.sensitive.sensitive_type == TPM_ALG_RSA;
    w.block(has_block, |w| {
        let primes = match &body.private_exponent {
            Some(exponent) => core::array::from_fn(|index| Some(&exponent.primes[index])),
            None => [None; 4],
        };
        marshal_private_exponent(w, primes)
    })?;

    w.tpm2b(&body.qualified_name)?;
    w.u32(body.evict_handle);
    w.tpm2b(&body.name)?;

    w.block(true, |w| {
        w.u8(body.seed_compat_level);
        w.block(true, |w| {
            if version >= 4 {
                w.u32(
                    body.hierarchy
                        .unwrap_or_else(|| hierarchy_from_attributes(attributes)),
                );
            }
            Ok(())
        })
    })
}

fn marshal_hash_state(w: &mut WireWriter, state: Option<&OwnedHashState>) -> Result<(), TpmResult> {
    w.nv_header(HASH_STATE_VERSION, HASH_STATE_MAGIC, 1);
    let (state_type, hash_alg) = match state {
        Some(state) => (state.state_type, state.hash_alg),
        None => (0, 0),
    };
    w.u8(state_type);
    w.u16(hash_alg);
    w.nv_header(ANY_HASH_STATE_VERSION, ANY_HASH_STATE_MAGIC, 1);
    if let Some(payload) = state.and_then(|state| state.payload.as_ref()) {
        match payload {
            OwnedHashPayload::Sha1 {
                h,
                nl,
                nh,
                data,
                num,
            } => {
                w.nv_header(HASH_STATE_SHA_VERSION, HASH_STATE_SHA1_MAGIC, 1);
                for value in h {
                    w.u32(*value);
                }
                w.u32(*nl);
                w.u32(*nh);
                w.u16(u16::try_from(data.as_bytes().len()).map_err(|_| TPM_FAIL)?);
                w.bytes(data.as_bytes());
                w.u32(*num);
                w.block(true, |_| Ok(()))?;
            }
            OwnedHashPayload::Sha256 {
                h,
                nl,
                nh,
                data,
                num,
                md_len,
            } => {
                w.nv_header(HASH_STATE_SHA_VERSION, HASH_STATE_SHA256_MAGIC, 1);
                w.u16(u16::try_from(h.len()).map_err(|_| TPM_FAIL)?);
                for value in h {
                    w.u32(*value);
                }
                w.u32(*nl);
                w.u32(*nh);
                w.u16(u16::try_from(data.as_bytes().len()).map_err(|_| TPM_FAIL)?);
                w.bytes(data.as_bytes());
                w.u32(*num);
                w.u32(*md_len);
                w.block(true, |_| Ok(()))?;
            }
            OwnedHashPayload::Sha512 {
                h,
                nl,
                nh,
                data,
                num,
                md_len,
            } => {
                let magic = match hash_alg {
                    TPM_ALG_SHA384 => HASH_STATE_SHA384_MAGIC,
                    _ => HASH_STATE_SHA512_MAGIC,
                };
                w.nv_header(HASH_STATE_SHA_VERSION, magic, 1);
                w.u16(u16::try_from(h.len()).map_err(|_| TPM_FAIL)?);
                for value in h {
                    w.u64(*value);
                }
                w.u64(*nl);
                w.u64(*nh);
                w.u16(u16::try_from(data.as_bytes().len()).map_err(|_| TPM_FAIL)?);
                w.bytes(data.as_bytes());
                w.u32(*num);
                w.u32(*md_len);
                w.block(true, |_| Ok(()))?;
            }
        }
    }
    w.block(true, |_| Ok(()))?;
    w.block(true, |_| Ok(()))
}

fn marshal_hash_object(
    w: &mut WireWriter,
    body: &OwnedHashObjectBody,
    attributes: u32,
) -> Result<(), TpmResult> {
    w.nv_header(HASH_OBJECT_VERSION, HASH_OBJECT_MAGIC, 1);
    w.u16(body.object_type);
    w.u16(body.name_alg);
    w.u32(body.object_attributes);
    w.tpm2b(body.auth.as_bytes())?;
    if attributes & (ATTR_HASH_SEQ | ATTR_EVENT_SEQ) != 0 {
        w.u16(u16::try_from(HASH_STATE_COUNT).map_err(|_| TPM_FAIL)?);
        for index in 0..HASH_STATE_COUNT {
            let state = body.states.as_ref().map(|states| &states[index]);
            marshal_hash_state(w, state)?;
        }
    } else if attributes & ATTR_HMAC_SEQ != 0 {
        match &body.hmac_state {
            Some((state, key)) => {
                marshal_hash_state(w, Some(state))?;
                w.tpm2b(key.as_bytes())?;
            }
            None => {
                marshal_hash_state(w, None)?;
                w.tpm2b(&[])?;
            }
        }
    }
    w.block(true, |_| Ok(()))
}

pub(in crate::library::tpm2) fn any_object_image(
    object: &OwnedAnyObject,
    object_version: u16,
) -> Result<Vec<u8>, TpmResult> {
    let mut w = WireWriter::new();
    w.nv_header(ANY_OBJECT_VERSION, ANY_OBJECT_MAGIC, 1);
    w.u32(object.attributes);
    if object.attributes & ATTR_OCCUPIED != 0 {
        match &object.body {
            OwnedAnyObjectBody::Unoccupied => return Err(TPM_FAIL),
            OwnedAnyObjectBody::Object(body) => {
                marshal_object(&mut w, body, object.attributes, object_version)?
            }
            OwnedAnyObjectBody::Sequence(body) => {
                marshal_hash_object(&mut w, body, object.attributes)?
            }
        }
    }
    w.block(true, |_| Ok(()))?;
    Ok(w.out)
}

pub(in crate::library::tpm2) fn rsa3072_object_image(
    object: &OwnedAnyObject,
) -> Result<Vec<u8>, TpmResult> {
    use layout::*;

    let OwnedAnyObjectBody::Object(body) = &object.body else {
        return Err(TPM_FAIL);
    };

    let mut image = vec![0u8; SIZEOF_RSA3072_OBJECT];
    let mut region = Region { bytes: &mut image };

    region.put_u32(R3K_ATTRIBUTES, object.attributes)?;

    let public = &body.public;
    let base = R3K_PUBLIC_AREA;
    region.put_u16(base + R3K_PUBLIC_TYPE, public.object_type)?;
    region.put_u16(base + R3K_PUBLIC_NAME_ALG, public.name_alg)?;
    region.put_u32(
        base + R3K_PUBLIC_OBJECT_ATTRIBUTES,
        public.object_attributes,
    )?;
    region.put_tpm2b(
        base + R3K_PUBLIC_AUTH_POLICY,
        SIZEOF_TPM2B_DIGEST,
        &public.auth_policy,
    )?;

    let parms = base + R3K_PUBLIC_PARAMETERS;
    let put_sym = |region: &mut Region<'_>, offset: usize, sym: &SymDefObject| {
        region.put_u16(offset + SYM_DEF_ALGORITHM, sym.algorithm)?;
        if let Some(key_bits) = sym.key_bits {
            region.put_u16(offset + SYM_DEF_KEY_BITS, key_bits)?;
        }
        if let Some(mode) = sym.mode {
            region.put_u16(offset + SYM_DEF_MODE, mode)?;
        }
        Ok::<(), TpmResult>(())
    };
    let put_scheme = |region: &mut Region<'_>, offset: usize, details: usize, scheme: &Scheme| {
        region.put_u16(offset, scheme.scheme)?;
        if let Some(hash_alg) = scheme.hash_alg {
            region.put_u16(offset + details + SCHEME_ECDAA_HASH_ALG, hash_alg)?;
        }
        if let Some(count) = scheme.count {
            region.put_u16(offset + details + SCHEME_ECDAA_COUNT, count)?;
        }
        if let Some(kdf) = scheme.kdf {
            region.put_u16(offset + details + SCHEME_XOR_KDF, kdf)?;
        }
        Ok::<(), TpmResult>(())
    };
    match &public.parameters {
        PublicParms::KeyedHash(scheme) => {
            put_scheme(
                &mut region,
                parms + PARMS_KEYEDHASH_SCHEME + KEYEDHASH_SCHEME_SCHEME,
                KEYEDHASH_SCHEME_DETAILS,
                scheme,
            )?;
        }
        PublicParms::SymCipher(sym) => put_sym(&mut region, parms + PARMS_SYM_SYM, sym)?,
        PublicParms::Rsa {
            symmetric,
            scheme,
            key_bits,
            exponent,
        } => {
            put_sym(&mut region, parms + PARMS_RSA_SYMMETRIC, symmetric)?;
            put_scheme(
                &mut region,
                parms + PARMS_RSA_SCHEME + RSA_SCHEME_SCHEME,
                RSA_SCHEME_DETAILS,
                scheme,
            )?;
            region.put_u16(parms + PARMS_RSA_KEY_BITS, *key_bits)?;
            region.put_u32(parms + PARMS_RSA_EXPONENT, *exponent)?;
        }
        PublicParms::Ecc {
            symmetric,
            scheme,
            curve_id,
            kdf,
        } => {
            put_sym(&mut region, parms + PARMS_ECC_SYMMETRIC, symmetric)?;
            put_scheme(
                &mut region,
                parms + PARMS_ECC_SCHEME + ECC_SCHEME_SCHEME,
                ECC_SCHEME_DETAILS,
                scheme,
            )?;
            region.put_u16(parms + PARMS_ECC_CURVE_ID, *curve_id)?;
            put_scheme(
                &mut region,
                parms + PARMS_ECC_KDF + KDF_SCHEME_SCHEME,
                KDF_SCHEME_DETAILS,
                kdf,
            )?;
        }
    }

    let unique = base + R3K_PUBLIC_UNIQUE;
    match &public.unique {
        OwnedPublicId::KeyedHash(bytes) | OwnedPublicId::Sym(bytes) => {
            region.put_tpm2b(unique, SIZEOF_TPM2B_DIGEST, bytes)?
        }
        OwnedPublicId::Rsa(bytes) => region.put_tpm2b(unique, SIZEOF_R3K_PUBLIC_KEY_RSA, bytes)?,
        OwnedPublicId::Ecc { x, y } => {
            region.put_tpm2b(unique + ECC_POINT_X, SIZEOF_TPM2B_ECC_PARAMETER, x)?;
            region.put_tpm2b(unique + ECC_POINT_Y, SIZEOF_TPM2B_ECC_PARAMETER, y)?;
        }
    }

    let sensitive = &body.sensitive;
    let base = R3K_SENSITIVE;
    region.put_u16(base + R3K_SENSITIVE_TYPE, sensitive.sensitive_type)?;
    region.put_tpm2b(
        base + R3K_SENSITIVE_AUTH_VALUE,
        SIZEOF_TPM2B_DIGEST,
        sensitive.auth_value.as_bytes(),
    )?;
    region.put_tpm2b(
        base + R3K_SENSITIVE_SEED_VALUE,
        SIZEOF_TPM2B_DIGEST,
        sensitive.seed_value.as_bytes(),
    )?;
    region.put_tpm2b(
        base + R3K_SENSITIVE_SENSITIVE,
        SIZEOF_R3K_SENSITIVE_COMPOSITE,
        sensitive
            .sensitive
            .as_ref()
            .map_or(&[][..], |composite| composite.as_bytes()),
    )?;

    if public.object_type == TPM_ALG_RSA
        && let Some(exponent) = &body.private_exponent
    {
        for (index, prime) in exponent.primes.iter().enumerate() {
            let entry = R3K_PRIVATE_EXPONENT + index * SIZEOF_BN_RSA3072_PRIME;
            let words = bn_prime_word_bytes(prime)?;
            if words.len() > SIZEOF_BN_PRIME_D {
                return Err(TPM_FAIL);
            }
            region.put_u64(entry + BN_PRIME_ALLOCATED, (SIZEOF_BN_PRIME_D / 8) as u64)?;
            region.put_u64(entry + BN_PRIME_SIZE, (words.len() / 8) as u64)?;
            for (word_index, word) in words.chunks_exact(8).enumerate() {
                let value = u64::from_be_bytes(word.try_into().map_err(|_| TPM_FAIL)?);
                region.put_u64(entry + BN_PRIME_D + word_index * 8, value)?;
            }
        }
    }

    region.put_tpm2b(R3K_QUALIFIED_NAME, SIZEOF_TPM2B_NAME, &body.qualified_name)?;
    region.put_u32(R3K_EVICT_HANDLE, body.evict_handle)?;
    region.put_tpm2b(R3K_NAME, SIZEOF_TPM2B_NAME, &body.name)?;
    region.put_u8(R3K_SEED_COMPAT_LEVEL, body.seed_compat_level)?;

    Ok(image)
}

fn write_user_nvram(
    region: &mut Region<'_>,
    user: &OwnedUserNvram,
    object_format: PersistentObjectFormat,
) -> Result<(), TpmResult> {
    use layout::*;

    let mut offset = 0usize;
    for entry in &user.entries {
        match entry {
            OwnedUserNvramEntry::NvIndex { index, data, .. } => {
                let entrysize = 4usize
                    .checked_add(SIZEOF_NV_INDEX)
                    .and_then(|size| size.checked_add(data.len()))
                    .ok_or(TPM_FAIL)?;
                region.put_u32(offset, u32::try_from(entrysize).map_err(|_| TPM_FAIL)?)?;
                write_nv_index(region, offset + 4, index)?;
                region.put(offset + 4 + SIZEOF_NV_INDEX, data)?;
                offset = offset.checked_add(entrysize).ok_or(TPM_FAIL)?;
            }
            OwnedUserNvramEntry::Persistent {
                handle,
                object,
                object_destination_size,
                ..
            } => {
                let image = match object_format {
                    PersistentObjectFormat::LegacyRsa3072 => rsa3072_object_image(object)?,
                    PersistentObjectFormat::AnyObject { object_version } => {
                        any_object_image(object, object_version)?
                    }
                };
                if image.len() as u64 != *object_destination_size {
                    return Err(TPM_FAIL);
                }
                let entrysize = 8usize.checked_add(image.len()).ok_or(TPM_FAIL)?;
                region.put_u32(offset, u32::try_from(entrysize).map_err(|_| TPM_FAIL)?)?;
                region.put_u32(offset + 4, *handle)?;
                region.put(offset + 8, &image)?;
                offset = offset.checked_add(entrysize).ok_or(TPM_FAIL)?;
            }
        }
    }

    let end = offset
        .checked_add(SIZEOF_NV_LIST_TERMINATOR)
        .ok_or(TPM_FAIL)?;
    if end > region.bytes.len() {
        return Err(TPM_FAIL);
    }
    region.put_u64(offset + 4, user.max_count)?;
    Ok(())
}

fn write_nv_index(
    region: &mut Region<'_>,
    base: usize,
    index: &OwnedNvIndex,
) -> Result<(), TpmResult> {
    use layout::*;

    let public = base + NV_INDEX_PUBLIC_AREA;
    region.put_u32(public + NV_PUBLIC_NV_INDEX, index.nv_index)?;
    region.put_u16(public + NV_PUBLIC_NAME_ALG, index.name_alg)?;
    region.put_u32(public + NV_PUBLIC_ATTRIBUTES, index.attributes)?;
    region.put_tpm2b(
        public + NV_PUBLIC_AUTH_POLICY,
        SIZEOF_TPM2B_DIGEST,
        &index.auth_policy,
    )?;
    region.put_u16(public + NV_PUBLIC_DATA_SIZE, index.data_size)?;
    region.put_tpm2b(
        base + NV_INDEX_AUTH_VALUE,
        SIZEOF_TPM2B_DIGEST,
        index.auth_value.as_bytes(),
    )?;
    Ok(())
}

pub(in crate::library::tpm2) fn build_nv_image(
    state: &OwnedPersistentState,
) -> Result<Box<[u8]>, TpmResult> {
    use layout::*;

    let mut image = vec![0u8; NV_MEMORY_SIZE].into_boxed_slice();

    write_persistent_data(
        &mut Region {
            bytes: &mut image[NV_PERSISTENT_DATA..NV_PERSISTENT_DATA + SIZEOF_PERSISTENT_DATA],
        },
        &state.persistent,
    )?;
    write_orderly_data(
        &mut Region {
            bytes: &mut image[NV_ORDERLY_DATA..NV_ORDERLY_DATA + SIZEOF_ORDERLY_DATA],
        },
        &state.orderly,
    )?;
    if let Some(reset) = &state.state_reset {
        write_state_reset(
            &mut Region {
                bytes: &mut image
                    [NV_STATE_RESET_DATA..NV_STATE_RESET_DATA + SIZEOF_STATE_RESET_DATA],
            },
            reset,
        )?;
    }
    if let Some(clear) = &state.state_clear {
        write_state_clear(
            &mut Region {
                bytes: &mut image
                    [NV_STATE_CLEAR_DATA..NV_STATE_CLEAR_DATA + SIZEOF_STATE_CLEAR_DATA],
            },
            clear,
        )?;
    }
    write_index_orderly_ram(
        &mut Region {
            bytes: &mut image[NV_INDEX_RAM_DATA..NV_INDEX_RAM_DATA + SIZEOF_INDEX_ORDERLY_RAM],
        },
        &state.index_orderly_ram,
    )?;
    write_user_nvram(
        &mut Region {
            bytes: &mut image[NV_USER_DYNAMIC..NV_USER_DYNAMIC_END],
        },
        &state.user_nvram,
        state.profile.object_format(),
    )?;

    Ok(image)
}

#[cfg(test)]
mod tests {
    use super::super::{IndexOrderlyRamFixture, NvIndexFixture, UserNvramFixture};
    use super::layout::*;
    use super::*;
    use crate::library::constants::TPM_FAIL;
    use crate::library::tpm2::pcr::{PcrAllocationFixture, PcrPoliciesFixture};
    use crate::library::tpm2::persistent::{
        CompatTailFixture, OrderlyFixture, PersistentAllEnvelope, PrefixFixture,
        materialize_persistent_state,
    };
    use crate::library::tpm2::{
        audit, compile_constants, lockout, object, parse_persistent_all_payload, pp_list,
        remaining_sections_with_su_state, valid_permanent_state_fixture,
    };

    fn envelope_with_payload(payload: &[u8]) -> Vec<u8> {
        let mut blob = vec![0x00, 0x03, 0xab, 0x36, 0x47, 0x23, 0x00, 0x01];
        blob.extend_from_slice(payload);
        blob.extend_from_slice(&[0xab, 0x36, 0x47, 0x23]);
        blob
    }

    fn envelope_v4_with_profile(profile: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut blob = vec![0x00, 0x04, 0xab, 0x36, 0x47, 0x23, 0x00, 0x04];
        blob.extend_from_slice(&u16::try_from(profile.len() + 1).unwrap().to_be_bytes());
        blob.extend_from_slice(profile);
        blob.push(0);
        blob.extend_from_slice(payload);
        blob.extend_from_slice(&[0xab, 0x36, 0x47, 0x23]);
        blob
    }

    fn simple_payload(orderly_state: u16, sections: Vec<u8>) -> Vec<u8> {
        let mut payload = compile_constants::marshalled_section(3);
        payload.extend_from_slice(
            &PrefixFixture {
                tail: PcrPoliciesFixture {
                    tail: PcrAllocationFixture {
                        tail: pp_list::PpListFixture {
                            tail: lockout::LockoutFixture {
                                orderly_state,
                                tail: audit::AuditFixture {
                                    tail: CompatTailFixture {
                                        tail: sections,
                                        ..CompatTailFixture::default()
                                    }
                                    .bytes(),
                                    ..audit::AuditFixture::default()
                                }
                                .bytes(),
                                ..lockout::LockoutFixture::default()
                            }
                            .bytes(),
                            ..pp_list::PpListFixture::default()
                        }
                        .bytes(),
                        ..PcrAllocationFixture::default()
                    }
                    .bytes(),
                    ..PcrPoliciesFixture::default()
                }
                .bytes(),
                ..PrefixFixture::default()
            }
            .bytes(),
        );
        payload
    }

    fn sections_with_user_nvram(user: Vec<u8>) -> Vec<u8> {
        let mut sections = OrderlyFixture::default().bytes();
        sections.extend_from_slice(&IndexOrderlyRamFixture::default().bytes());
        sections.extend_from_slice(&user);
        sections.extend_from_slice(&[0x01, 0x00, 0x00]);
        sections
    }

    fn candidate(blob: &[u8]) -> OwnedPersistentState {
        let envelope = PersistentAllEnvelope::parse(blob).unwrap();
        let decoded = parse_persistent_all_payload(&envelope).unwrap();
        materialize_persistent_state(decoded).unwrap()
    }

    fn image_for(blob: &[u8]) -> Box<[u8]> {
        build_nv_image(&candidate(blob)).unwrap()
    }

    fn le16(image: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes(image[offset..offset + 2].try_into().unwrap())
    }

    fn le32(image: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(image[offset..offset + 4].try_into().unwrap())
    }

    fn le64(image: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(image[offset..offset + 8].try_into().unwrap())
    }

    #[test]
    fn image_has_exactly_nv_memory_size_bytes() {
        let image = image_for(&valid_permanent_state_fixture());
        assert_eq!(image.len(), NV_MEMORY_SIZE);
        assert_eq!(image.len(), crate::library::tpm2::runtime::NV_MEMORY_SIZE);
    }

    #[test]
    fn reserved_regions_hold_the_expected_native_images() {
        let image = image_for(&valid_permanent_state_fixture());

        assert_eq!(le32(&image, NV_PERSISTENT_DATA + PD_DISABLE_CLEAR), 0);
        assert_eq!(le16(&image, NV_PERSISTENT_DATA + PD_ORDERLY_STATE), 0);
        assert_eq!(le64(&image, NV_PERSISTENT_DATA + PD_TOTAL_RESET_COUNT), 0);
        let allocated = NV_PERSISTENT_DATA + PD_PCR_ALLOCATED;
        assert_eq!(le32(&image, allocated + TPML_PCR_SELECTION_COUNT), 1);
        let selection = allocated + TPML_PCR_SELECTION_SELECTIONS;
        assert_eq!(le16(&image, selection + TPMS_PCR_SELECTION_HASH), 0x000b);
        assert_eq!(image[selection + TPMS_PCR_SELECTION_SIZEOF_SELECT], 3);
        assert_eq!(
            &image[selection + TPMS_PCR_SELECTION_PCR_SELECT
                ..selection + TPMS_PCR_SELECTION_PCR_SELECT + 3],
            &[0, 0, 0]
        );

        assert_eq!(le64(&image, NV_ORDERLY_DATA + OD_CLOCK), 0);
        assert_eq!(image[NV_ORDERLY_DATA + OD_CLOCK_SAFE], 1);
        let drbg = NV_ORDERLY_DATA + OD_DRBG_STATE;
        assert_eq!(le32(&image, drbg + DRBG_MAGIC_FIELD), 0x4742_5244);
        assert_eq!(
            &image[drbg + DRBG_SEED_FIELD..drbg + DRBG_SEED_FIELD + SIZEOF_DRBG_SEED],
            &[0x5a; SIZEOF_DRBG_SEED][..]
        );
        assert_eq!(image[drbg + DRBG_SEED_COMPAT_LEVEL], 0);

        assert!(
            image[NV_STATE_RESET_DATA..NV_STATE_RESET_DATA + SIZEOF_STATE_RESET_DATA]
                .iter()
                .all(|&byte| byte == 0)
        );
        assert!(
            image[NV_STATE_CLEAR_DATA..NV_STATE_CLEAR_DATA + SIZEOF_STATE_CLEAR_DATA]
                .iter()
                .all(|&byte| byte == 0)
        );

        assert!(
            image[NV_INDEX_RAM_DATA..NV_USER_DYNAMIC_END]
                .iter()
                .all(|&byte| byte == 0)
        );
    }

    #[test]
    fn su_state_blob_commits_reset_and_clear_regions() {
        let blob =
            envelope_with_payload(&simple_payload(0x0001, remaining_sections_with_su_state()));
        let image = image_for(&blob);

        let srd = NV_STATE_RESET_DATA;
        assert_eq!(le16(&image, srd + SRD_NULL_PROOF), 8);
        assert_eq!(
            &image[srd + SRD_NULL_PROOF + 2..srd + SRD_NULL_PROOF + 10],
            &[0x0f; 8]
        );
        assert_eq!(le16(&image, srd + SRD_NULL_SEED), 8);
        assert_eq!(
            &image[srd + SRD_NULL_SEED + 2..srd + SRD_NULL_SEED + 10],
            &[0x5e; 8]
        );
        assert_eq!(image[srd + SRD_NULL_SEED_COMPAT_LEVEL], 0);

        let scd = NV_STATE_CLEAR_DATA;
        assert_eq!(le32(&image, scd + SCD_SH_ENABLE), 1);
        assert_eq!(le32(&image, scd + SCD_EH_ENABLE), 1);
        assert_eq!(le32(&image, scd + SCD_PH_ENABLE_NV), 1);
        assert_eq!(le16(&image, scd + SCD_PLATFORM_ALG), 0x0010);
        assert_eq!(le32(&image, scd + SCD_PCR_SAVE + PCR_SAVE_PCR_COUNTER), 0);
    }

    #[test]
    fn orderly_ram_entries_serialize_with_recomputed_sizes() {
        let mut sections = OrderlyFixture::default().bytes();
        sections.extend_from_slice(
            &IndexOrderlyRamFixture {
                entries: vec![IndexOrderlyRamFixture::entry(
                    0x0100_0001,
                    0x0000_0001,
                    &[0xaa; 8],
                )],
                ..IndexOrderlyRamFixture::default()
            }
            .bytes(),
        );
        sections.extend_from_slice(&UserNvramFixture::default().bytes());
        sections.extend_from_slice(&[0x01, 0x00, 0x00]);
        let with_terminator = image_for(&envelope_with_payload(&simple_payload(0, sections)));

        let ram = NV_INDEX_RAM_DATA;
        assert_eq!(le32(&with_terminator, ram + NV_RAM_HEADER_SIZE_FIELD), 20);
        assert_eq!(
            le32(&with_terminator, ram + NV_RAM_HEADER_HANDLE),
            0x0100_0001
        );
        assert_eq!(le32(&with_terminator, ram + NV_RAM_HEADER_ATTRIBUTES), 1);
        assert_eq!(
            &with_terminator[ram + SIZEOF_NV_RAM_HEADER..ram + 20],
            &[0xaa; 8]
        );
        assert!(
            with_terminator[ram + 20..NV_USER_DYNAMIC]
                .iter()
                .all(|&byte| byte == 0)
        );

        let mut sections = OrderlyFixture::default().bytes();
        sections.extend_from_slice(
            &IndexOrderlyRamFixture {
                sourceside_size: 20,
                entries: vec![IndexOrderlyRamFixture::entry(
                    0x0100_0001,
                    0x0000_0001,
                    &[0xaa; 8],
                )],
                terminator: false,
                ..IndexOrderlyRamFixture::default()
            }
            .bytes(),
        );
        sections.extend_from_slice(&UserNvramFixture::default().bytes());
        sections.extend_from_slice(&[0x01, 0x00, 0x00]);
        let without_terminator = image_for(&envelope_with_payload(&simple_payload(0, sections)));
        assert_eq!(
            &with_terminator[ram..NV_USER_DYNAMIC],
            &without_terminator[ram..NV_USER_DYNAMIC],
        );
    }

    #[test]
    fn empty_user_nvram_writes_terminator_and_max_count() {
        let user = UserNvramFixture {
            max_count: Some(41),
            ..UserNvramFixture::default()
        }
        .bytes();
        let blob = envelope_with_payload(&simple_payload(0, sections_with_user_nvram(user)));
        let image = image_for(&blob);
        assert_eq!(le32(&image, NV_USER_DYNAMIC), 0, "the list terminator");
        assert_eq!(le64(&image, NV_USER_DYNAMIC + 4), 41, "native maxCount");
        assert!(
            image[NV_USER_DYNAMIC + SIZEOF_NV_LIST_TERMINATOR..NV_USER_DYNAMIC_END]
                .iter()
                .all(|&byte| byte == 0)
        );
    }

    #[test]
    fn mixed_entries_produce_the_expected_offsets_and_sizes() {
        let index_bytes = NvIndexFixture::default().bytes();
        let bulk = vec![0xa5u8; 24];
        let object_bytes = object::fixtures::any_rsa_object(4);
        let user = UserNvramFixture {
            entries: vec![
                UserNvramFixture::nv_index_entry(0x0100_0001, &index_bytes, &bulk),
                UserNvramFixture::persistent_entry(0x8100_0001, &object_bytes),
            ],
            max_count: Some(7),
            ..UserNvramFixture::default()
        }
        .bytes();
        let blob = envelope_v4_with_profile(
            br#"{"Name":"default-v1","StateFormatLevel":7}"#,
            &simple_payload(0, sections_with_user_nvram(user)),
        );
        let image = image_for(&blob);

        let first = NV_USER_DYNAMIC;
        let first_size = 4 + SIZEOF_NV_INDEX + bulk.len();
        assert_eq!(le32(&image, first), u32::try_from(first_size).unwrap());
        let nvi = first + 4;
        assert_eq!(le32(&image, nvi + NV_PUBLIC_NV_INDEX), 0x0100_0001);
        assert_eq!(le16(&image, nvi + NV_PUBLIC_NAME_ALG), 0x000b);
        assert_eq!(le16(&image, nvi + NV_PUBLIC_DATA_SIZE), 8);
        assert_eq!(
            &image[nvi + SIZEOF_NV_INDEX..nvi + SIZEOF_NV_INDEX + 24],
            &bulk[..]
        );

        let second = first + first_size;
        assert_eq!(
            le32(&image, second),
            u32::try_from(8 + object_bytes.len()).unwrap()
        );
        assert_eq!(le32(&image, second + 4), 0x8100_0001);
        assert_eq!(
            &image[second + 8..second + 8 + object_bytes.len()],
            &object_bytes[..]
        );

        let end = second + 8 + object_bytes.len();
        assert_eq!(le32(&image, end), 0);
        assert_eq!(le64(&image, end + 4), 7);
    }

    #[test]
    fn version_matched_objects_remarshal_to_their_wire_bytes() {
        for (profile, version) in [
            (&br#"{"Name":"default-v1","StateFormatLevel":5}"#[..], 3u16),
            (br#"{"Name":"default-v1","StateFormatLevel":7}"#, 4),
        ] {
            let object_bytes = object::fixtures::any_rsa_object(version);
            let user = UserNvramFixture {
                entries: vec![UserNvramFixture::persistent_entry(
                    0x8100_0001,
                    &object_bytes,
                )],
                ..UserNvramFixture::default()
            }
            .bytes();
            let blob = envelope_v4_with_profile(
                profile,
                &simple_payload(0, sections_with_user_nvram(user)),
            );
            let image = image_for(&blob);
            let entry = NV_USER_DYNAMIC;
            assert_eq!(
                &image[entry + 8..entry + 8 + object_bytes.len()],
                &object_bytes[..],
                "version {version}"
            );
        }

        for bits in [object::fixtures::SEQ_HASH, object::fixtures::SEQ_HMAC] {
            let object_bytes = object::fixtures::any_sequence_object(bits);
            let user = UserNvramFixture {
                entries: vec![UserNvramFixture::persistent_entry(
                    0x8100_0001,
                    &object_bytes,
                )],
                ..UserNvramFixture::default()
            }
            .bytes();
            let blob = envelope_v4_with_profile(
                br#"{"Name":"default-v1","StateFormatLevel":7}"#,
                &simple_payload(0, sections_with_user_nvram(user)),
            );
            let image = image_for(&blob);
            let entry = NV_USER_DYNAMIC;
            assert_eq!(
                &image[entry + 8..entry + 8 + object_bytes.len()],
                &object_bytes[..],
                "sequence bits {bits:#x}"
            );
        }
    }

    #[test]
    fn legacy_profile_produces_the_rsa3072_native_layout() {
        let object_bytes = object::fixtures::any_rsa_object(4);
        let user = UserNvramFixture {
            entries: vec![UserNvramFixture::persistent_entry(
                0x8100_0002,
                &object_bytes,
            )],
            ..UserNvramFixture::default()
        }
        .bytes();
        let blob = envelope_v4_with_profile(
            br#"{"Name":"null","StateFormatLevel":1}"#,
            &simple_payload(0, sections_with_user_nvram(user)),
        );
        let image = image_for(&blob);

        let entry = NV_USER_DYNAMIC;
        assert_eq!(
            le32(&image, entry),
            u32::try_from(8 + SIZEOF_RSA3072_OBJECT).unwrap(),
            "the legacy entry charges the fixed native size"
        );
        assert_eq!(le32(&image, entry + 4), 0x8100_0002);

        let obj = entry + 8;
        assert_eq!(le32(&image, obj + R3K_ATTRIBUTES), 1 << 15, "occupied");
        let public = obj + R3K_PUBLIC_AREA;
        assert_eq!(
            le16(&image, public + R3K_PUBLIC_TYPE),
            0x0001,
            "TPM_ALG_RSA"
        );
        assert_eq!(le16(&image, public + R3K_PUBLIC_UNIQUE), 256);
        assert_eq!(
            le16(&image, public + R3K_PUBLIC_PARAMETERS + PARMS_RSA_KEY_BITS),
            2048
        );
        let sensitive = obj + R3K_SENSITIVE;
        assert_eq!(le16(&image, sensitive + R3K_SENSITIVE_TYPE), 0x0001);
        assert_eq!(le16(&image, sensitive + R3K_SENSITIVE_SENSITIVE), 128);
        let prime = obj + R3K_PRIVATE_EXPONENT;
        assert_eq!(le64(&image, prime + BN_PRIME_ALLOCATED), 25);
        assert_eq!(le64(&image, prime + BN_PRIME_SIZE), 12);
        assert_eq!(le64(&image, prime + BN_PRIME_D), 0x4242_4242_4242_4242);
        assert_eq!(
            le64(&image, prime + BN_PRIME_D + 12 * 8 - 8),
            0x4242_4242_4242_4242
        );
        assert_eq!(
            le64(&image, prime + BN_PRIME_D + 12 * 8),
            0,
            "beyond size: zero"
        );
        assert_eq!(le16(&image, obj + R3K_QUALIFIED_NAME), 34);
        assert_eq!(
            &image[obj + R3K_QUALIFIED_NAME + 2..obj + R3K_QUALIFIED_NAME + 2 + 34],
            &[0x51; 34]
        );
        assert_eq!(le32(&image, obj + R3K_EVICT_HANDLE), 0x8100_0001);
        assert_eq!(le16(&image, obj + R3K_NAME), 34);
        assert_eq!(image[obj + R3K_SEED_COMPAT_LEVEL], 0);
    }

    #[test]
    fn exact_capacity_user_nvram_commits() {
        let index_bytes = NvIndexFixture::default().bytes();
        let entries = [65792u32, 65792, 39148]
            .iter()
            .enumerate()
            .map(|(i, &datasize)| {
                UserNvramFixture::nv_index_entry(
                    0x0100_0001 + i as u32,
                    &index_bytes,
                    &vec![0u8; datasize as usize],
                )
            })
            .collect();
        let user = UserNvramFixture {
            entries,
            ..UserNvramFixture::default()
        }
        .bytes();
        let blob = envelope_with_payload(&simple_payload(0, sections_with_user_nvram(user)));
        let image = image_for(&blob);
        let end = NV_USER_DYNAMIC_END - SIZEOF_NV_LIST_TERMINATOR;
        assert_eq!(le32(&image, end), 0);
        assert_eq!(le64(&image, end + 4), 0);
    }

    #[test]
    fn legacy_sequence_object_is_rejected_at_commit() {
        let object_bytes = object::fixtures::any_sequence_object(object::fixtures::SEQ_HASH);
        let user = UserNvramFixture {
            entries: vec![UserNvramFixture::persistent_entry(
                0x8100_0001,
                &object_bytes,
            )],
            ..UserNvramFixture::default()
        }
        .bytes();
        let blob = envelope_v4_with_profile(
            br#"{"Name":"null","StateFormatLevel":1}"#,
            &simple_payload(0, sections_with_user_nvram(user)),
        );
        assert_eq!(build_nv_image(&candidate(&blob)).unwrap_err(), TPM_FAIL);
    }

    #[test]
    fn inconsistent_destination_accounting_is_rejected() {
        let object_bytes = object::fixtures::any_rsa_object(4);
        let user = UserNvramFixture {
            entries: vec![UserNvramFixture::persistent_entry(
                0x8100_0001,
                &object_bytes,
            )],
            ..UserNvramFixture::default()
        }
        .bytes();
        let blob = envelope_v4_with_profile(
            br#"{"Name":"default-v1","StateFormatLevel":7}"#,
            &simple_payload(0, sections_with_user_nvram(user)),
        );
        let mut state = candidate(&blob);
        let OwnedUserNvramEntry::Persistent {
            object_destination_size,
            ..
        } = &mut state.user_nvram.entries[0]
        else {
            panic!("expected a persistent entry");
        };
        *object_destination_size += 1;
        assert_eq!(build_nv_image(&state).unwrap_err(), TPM_FAIL);
    }

    #[test]
    fn uncompressed_bitmaps_are_copied_and_zero_extended() {
        let bitmap = OwnedCommandBitmap {
            compressed: false,
            bytes: vec![0xff, 0x01],
        };
        let image = command_bitmap_image(&bitmap, 17).unwrap();
        assert_eq!(image.len(), 17);
        assert_eq!(&image[..2], &[0xff, 0x01]);
        assert!(image[2..].iter().all(|&byte| byte == 0));
    }

    #[test]
    fn compressed_bitmaps_are_remapped_through_the_pinned_table() {
        let mut bytes = vec![0u8; 14];
        bytes[0] |= 1 << 0;
        bytes[0] |= 1 << 4;
        bytes[13] |= 1 << 5;
        let bitmap = OwnedCommandBitmap {
            compressed: true,
            bytes,
        };
        let image = command_bitmap_image(&bitmap, 17).unwrap();
        let bit = |index: usize| image[index / 8] & (1 << (index % 8)) != 0;
        assert!(bit(0));
        assert!(bit(5));
        assert!(bit(120));
        assert_eq!(
            image.iter().map(|byte| byte.count_ones()).sum::<u32>(),
            3,
            "no other bit is set"
        );
    }

    #[test]
    fn compressed_bits_past_the_table_are_ignored() {
        let bitmap = OwnedCommandBitmap {
            compressed: true,
            bytes: vec![0xff; 15],
        };
        let image = command_bitmap_image(&bitmap, 17).unwrap();
        let expected: u32 = 110;
        assert_eq!(
            image.iter().map(|byte| byte.count_ones()).sum::<u32>(),
            expected,
            "exactly the 110 mapped bits"
        );
    }

    #[test]
    fn image_survives_dropping_the_blob_and_candidate() {
        let image = {
            let blob = valid_permanent_state_fixture();
            let state = candidate(&blob);
            build_nv_image(&state).unwrap()
        };
        assert_eq!(image.len(), NV_MEMORY_SIZE);
        assert_eq!(image[NV_ORDERLY_DATA + OD_CLOCK_SAFE], 1);
    }
}
