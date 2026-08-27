use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_SIZE};
use crate::types::TpmResult;

use super::crypto::{HmacState, kdfa};
use super::nv::layout::{
    CONTEXT_ENCRYPT_KEY_BITS, CONTEXT_INTEGRITY_HASH_SIZE, SESSION_AUDIT_DIGEST,
    SESSION_AUTH_HASH_ALG, SESSION_BOUND_ENTITY, SESSION_COMMAND_CODE, SESSION_COMMAND_LOCALITY,
    SESSION_EPOCH, SESSION_NONCE_TPM, SESSION_PCR_COUNTER, SESSION_SESSION_KEY, SESSION_START_TIME,
    SESSION_SYMMETRIC, SESSION_TIMEOUT, SIZEOF_SESSION, SIZEOF_SESSION_U1, SIZEOF_SESSION_U2,
};
use super::persistent::OwnedSecret;
use super::public::{SymDefObject, TPM_ALG_SHA512};
use super::volatile::OwnedSession;

pub(super) const CONTEXT_INTEGRITY_HASH_ALG: u16 = TPM_ALG_SHA512;
pub(super) const CONTEXT_ENCRYPT_ALG: u16 = super::public::TPM_ALG_AES;
pub(super) const CONTEXT_ENCRYPT_KEY_BYTES: usize = CONTEXT_ENCRYPT_KEY_BITS / 8;
pub(super) const CONTEXT_IV_BYTES: usize = 16;
pub(super) const CONTEXT_KEY_LABEL: &[u8] = b"CONTEXT\0";

pub(super) const FINGERPRINT_SIZE: usize = 8;
pub(super) const INTEGRITY_SIZE: usize = 2 + CONTEXT_INTEGRITY_HASH_SIZE;

pub(super) const SAVED_OBJECT: u32 = 0x8000_0000;
pub(super) const SAVED_SEQUENCE: u32 = 0x8000_0001;
pub(super) const SAVED_ST_CLEAR: u32 = 0x8000_0002;

const SESSION_KEY_CAPACITY: usize = SESSION_NONCE_TPM - SESSION_SESSION_KEY - 2;
const NONCE_TPM_CAPACITY: usize = SESSION_BOUND_ENTITY - SESSION_NONCE_TPM - 2;
const BOUND_ENTITY_CAPACITY: usize = SIZEOF_SESSION_U1 - 2;
const AUDIT_DIGEST_CAPACITY: usize = SIZEOF_SESSION_U2 - 2;

fn put_tpm2b(
    image: &mut [u8],
    offset: usize,
    capacity: usize,
    value: &[u8],
) -> Result<(), TpmResult> {
    if value.len() > capacity {
        return Err(TPM_RC_SIZE);
    }
    let size = u16::try_from(value.len()).map_err(|_| TPM_RC_SIZE)?;
    image[offset..offset + 2].copy_from_slice(&size.to_le_bytes());
    image[offset + 2..offset + 2 + value.len()].copy_from_slice(value);
    Ok(())
}

fn take_tpm2b(image: &[u8], offset: usize, capacity: usize) -> Result<Vec<u8>, TpmResult> {
    let size = usize::from(u16::from_le_bytes([image[offset], image[offset + 1]]));
    if size > capacity {
        return Err(TPM_RC_SIZE);
    }
    Ok(image[offset + 2..offset + 2 + size].to_vec())
}

pub(super) fn session_image(session: &OwnedSession) -> Result<Vec<u8>, TpmResult> {
    let mut image = vec![0u8; SIZEOF_SESSION];
    image[0..4].copy_from_slice(&session.attributes.to_le_bytes());
    image[SESSION_PCR_COUNTER..SESSION_PCR_COUNTER + 4]
        .copy_from_slice(&session.pcr_counter.to_le_bytes());
    image[SESSION_START_TIME..SESSION_START_TIME + 8]
        .copy_from_slice(&session.start_time.to_le_bytes());
    image[SESSION_TIMEOUT..SESSION_TIMEOUT + 8].copy_from_slice(&session.timeout.to_le_bytes());
    image[SESSION_EPOCH..SESSION_EPOCH + 4].copy_from_slice(&session.epoch.to_le_bytes());
    image[SESSION_COMMAND_CODE..SESSION_COMMAND_CODE + 4]
        .copy_from_slice(&session.command_code.to_le_bytes());
    image[SESSION_AUTH_HASH_ALG..SESSION_AUTH_HASH_ALG + 2]
        .copy_from_slice(&session.auth_hash_alg.to_le_bytes());
    image[SESSION_COMMAND_LOCALITY] = session.command_locality;
    image[SESSION_SYMMETRIC..SESSION_SYMMETRIC + 2]
        .copy_from_slice(&session.symmetric.algorithm.to_le_bytes());
    image[SESSION_SYMMETRIC + 2..SESSION_SYMMETRIC + 4]
        .copy_from_slice(&session.symmetric.key_bits.unwrap_or(0).to_le_bytes());
    image[SESSION_SYMMETRIC + 4..SESSION_SYMMETRIC + 6]
        .copy_from_slice(&session.symmetric.mode.unwrap_or(0).to_le_bytes());
    put_tpm2b(
        &mut image,
        SESSION_SESSION_KEY,
        SESSION_KEY_CAPACITY,
        session.session_key.as_bytes(),
    )?;
    put_tpm2b(
        &mut image,
        SESSION_NONCE_TPM,
        NONCE_TPM_CAPACITY,
        session.nonce_tpm.as_bytes(),
    )?;
    put_tpm2b(
        &mut image,
        SESSION_BOUND_ENTITY,
        BOUND_ENTITY_CAPACITY,
        &session.bound_entity,
    )?;
    put_tpm2b(
        &mut image,
        SESSION_AUDIT_DIGEST,
        AUDIT_DIGEST_CAPACITY,
        &session.audit_digest,
    )?;
    Ok(image)
}

pub(super) fn parse_session_image(image: &[u8]) -> Result<OwnedSession, TpmResult> {
    if image.len() != SIZEOF_SESSION {
        return Err(TPM_RC_SIZE);
    }
    let u32_at = |offset: usize| {
        u32::from_le_bytes([
            image[offset],
            image[offset + 1],
            image[offset + 2],
            image[offset + 3],
        ])
    };
    let u64_at = |offset: usize| {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&image[offset..offset + 8]);
        u64::from_le_bytes(bytes)
    };
    let u16_at = |offset: usize| u16::from_le_bytes([image[offset], image[offset + 1]]);

    let algorithm = u16_at(SESSION_SYMMETRIC);
    let key_bits = u16_at(SESSION_SYMMETRIC + 2);
    let mode = u16_at(SESSION_SYMMETRIC + 4);
    Ok(OwnedSession {
        attributes: u32_at(0),
        pcr_counter: u32_at(SESSION_PCR_COUNTER),
        start_time: u64_at(SESSION_START_TIME),
        timeout: u64_at(SESSION_TIMEOUT),
        epoch: u32_at(SESSION_EPOCH),
        command_code: u32_at(SESSION_COMMAND_CODE),
        auth_hash_alg: u16_at(SESSION_AUTH_HASH_ALG),
        command_locality: image[SESSION_COMMAND_LOCALITY],
        symmetric: SymDefObject {
            algorithm,
            key_bits: Some(key_bits),
            mode: Some(mode),
        },
        session_key: OwnedSecret::from_vec(take_tpm2b(
            image,
            SESSION_SESSION_KEY,
            SESSION_KEY_CAPACITY,
        )?),
        nonce_tpm: OwnedSecret::from_vec(take_tpm2b(image, SESSION_NONCE_TPM, NONCE_TPM_CAPACITY)?),
        bound_entity: take_tpm2b(image, SESSION_BOUND_ENTITY, BOUND_ENTITY_CAPACITY)?,
        audit_digest: take_tpm2b(image, SESSION_AUDIT_DIGEST, AUDIT_DIGEST_CAPACITY)?,
    })
}

pub(super) struct ContextProtection {
    pub(super) key: Vec<u8>,
    pub(super) iv: Vec<u8>,
}

pub(super) fn context_protection_key(
    proof: &[u8],
    sequence: u64,
    saved_handle: u32,
) -> Result<ContextProtection, TpmResult> {
    let bits = ((CONTEXT_ENCRYPT_KEY_BYTES + CONTEXT_IV_BYTES) * 8) as u32;
    let derived = kdfa(
        CONTEXT_INTEGRITY_HASH_ALG,
        proof,
        CONTEXT_KEY_LABEL,
        &sequence.to_le_bytes(),
        &saved_handle.to_le_bytes(),
        bits,
    )
    .ok_or(TPM_RC_FAILURE)?;
    Ok(ContextProtection {
        key: derived[..CONTEXT_ENCRYPT_KEY_BYTES].to_vec(),
        iv: derived[CONTEXT_ENCRYPT_KEY_BYTES..CONTEXT_ENCRYPT_KEY_BYTES + CONTEXT_IV_BYTES]
            .to_vec(),
    })
}

pub(super) struct ContextIntegrityInput<'a> {
    pub(super) proof: &'a [u8],
    pub(super) total_reset_count: u64,
    pub(super) clear_count: u32,
    pub(super) sequence: u64,
    pub(super) saved_handle: u32,
    pub(super) protected: &'a [u8],
}

pub(super) fn context_integrity(input: &ContextIntegrityInput<'_>) -> Result<Vec<u8>, TpmResult> {
    let mut hmac = HmacState::new(CONTEXT_INTEGRITY_HASH_ALG, input.proof).ok_or(TPM_RC_FAILURE)?;
    hmac.update(&input.total_reset_count.to_be_bytes());
    if input.saved_handle == SAVED_ST_CLEAR {
        hmac.update(&input.clear_count.to_be_bytes());
    }
    hmac.update(&input.sequence.to_be_bytes());
    hmac.update(&input.saved_handle.to_be_bytes());
    hmac.update(input.protected);
    Ok(hmac.finalize())
}

pub(super) fn fingerprint(sequence: u64) -> [u8; FINGERPRINT_SIZE] {
    sequence.to_le_bytes()
}
