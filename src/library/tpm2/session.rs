use subtle::ConstantTimeEq;

use crate::library::constants::{
    TPM_RC_CONTEXT_GAP, TPM_RC_FAILURE, TPM_RC_SESSION_HANDLES, TPM_RC_SESSION_MEMORY,
    TPM_RC_TOO_MANY_CONTEXTS,
};
use crate::types::TpmResult;

use super::crypto::COMPILED_HASHES;
use super::live::LiveState;
use super::marshal::{BlobReader, BlockSkipError, skip_optional_block};
use super::persistent::{PersistentAllError, PersistentField, StateSection, parse_nv_header};
use super::public::{
    DIGEST_SIZE, NAME_SIZE, StateFormatLimit, SymDefObject, parse_sym_def, read_tpm2b,
};
use super::state::MAX_ACTIVE_SESSIONS;
use super::volatile::{MAX_LOADED_SESSIONS, OwnedSession};

pub(super) const SESSION_MAGIC: u32 = 0x44be_9f45;
pub(super) const SESSION_VERSION: u16 = 2;
pub(super) const SESSION_SLOT_MAGIC: u32 = 0x3664_aebc;
pub(super) const SESSION_SLOT_VERSION: u16 = 2;

pub(super) const EPOCH_CLOCK_SIZE: u8 = 4;

const HMAC_SESSION_FIRST: u32 = 0x0200_0000;
const HMAC_SESSION_LAST: u32 = HMAC_SESSION_FIRST + MAX_ACTIVE_SESSIONS as u32 - 1;
const POLICY_SESSION_FIRST: u32 = 0x0300_0000;
const POLICY_SESSION_LAST: u32 = POLICY_SESSION_FIRST + MAX_ACTIVE_SESSIONS as u32 - 1;

const HR_HANDLE_MASK: u32 = 0x00ff_ffff;

const BLOCK_SKIP_SINCE_VERSION: u16 = 2;

pub(super) const SESSION_ATTR_IS_POLICY: u32 = 1 << 0;
pub(super) const SESSION_ATTR_IS_AUDIT: u32 = 1 << 1;
pub(super) const SESSION_ATTR_IS_BOUND: u32 = 1 << 2;
pub(super) const SESSION_ATTR_IS_CP_HASH_DEFINED: u32 = 1 << 3;
pub(super) const SESSION_ATTR_IS_AUTH_VALUE_NEEDED: u32 = 1 << 4;
pub(super) const SESSION_ATTR_IS_PASSWORD_NEEDED: u32 = 1 << 5;
pub(super) const SESSION_ATTR_IS_PP_REQUIRED: u32 = 1 << 6;
pub(super) const SESSION_ATTR_IS_TRIAL_POLICY: u32 = 1 << 7;
pub(super) const SESSION_ATTR_IS_DA_BOUND: u32 = 1 << 8;
pub(super) const SESSION_ATTR_IS_LOCKOUT_BOUND: u32 = 1 << 9;
#[cfg_attr(not(test), allow(dead_code))]
pub(super) const SESSION_ATTR_INCLUDE_AUTH: u32 = 1 << 10;
pub(super) const SESSION_ATTR_CHECK_NV_WRITTEN: u32 = 1 << 11;
pub(super) const SESSION_ATTR_NV_WRITTEN_STATE: u32 = 1 << 12;
pub(super) const SESSION_ATTR_IS_TEMPLATE_HASH_DEFINED: u32 = 1 << 13;
pub(super) const SESSION_ATTR_IS_NAME_HASH_DEFINED: u32 = 1 << 14;
pub(super) const SESSION_ATTR_IS_PARAMETERS_HASH_DEFINED: u32 = 1 << 15;

pub(super) const TPM_SE_HMAC: u8 = 0x00;
pub(super) const TPM_SE_POLICY: u8 = 0x01;
pub(super) const TPM_SE_TRIAL: u8 = 0x03;

pub(super) fn is_session_handle(handle: u32) -> bool {
    (HMAC_SESSION_FIRST..=HMAC_SESSION_LAST).contains(&handle)
        || (POLICY_SESSION_FIRST..=POLICY_SESSION_LAST).contains(&handle)
}

pub(super) fn is_policy_session_handle(handle: u32) -> bool {
    (POLICY_SESSION_FIRST..=POLICY_SESSION_LAST).contains(&handle)
}

pub(super) fn is_hmac_session_handle(handle: u32) -> bool {
    (HMAC_SESSION_FIRST..=HMAC_SESSION_LAST).contains(&handle)
}

pub(super) fn digests_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

pub(super) fn digest_size(hash_alg: u16) -> Option<usize> {
    COMPILED_HASHES
        .iter()
        .find(|(algorithm, _)| *algorithm == hash_alg)
        .map(|(_, size)| *size)
}

fn loaded_ram_slot(live: &LiveState, handle: u32) -> Option<usize> {
    let (_, context) = context_slot(live, handle)?;
    if context == 0 || usize::from(context) > MAX_LOADED_SESSIONS {
        return None;
    }
    usize::from(context).checked_sub(1)
}

pub(super) fn loaded_session<'a>(live: &'a LiveState, handle: u32) -> Option<&'a OwnedSession> {
    let slot = loaded_ram_slot(live, handle)?;
    live.sessions.get(slot)?.session.as_ref()
}

pub(super) fn loaded_session_mut<'a>(
    live: &'a mut LiveState,
    handle: u32,
) -> Option<&'a mut OwnedSession> {
    let slot = loaded_ram_slot(live, handle)?;
    live.sessions.get_mut(slot)?.session.as_mut()
}

fn free_ram_slot(live: &LiveState) -> Option<usize> {
    live.sessions.iter().position(|slot| !slot.occupied)
}

fn assign_context_slot(live: &mut LiveState, ram_slot: usize) -> Result<(u32, u16), TpmResult> {
    let mask = live.context_slot_mask;
    let reset = live.state_reset.as_mut().ok_or(TPM_RC_SESSION_HANDLES)?;
    if (live.oldest_saved_session as usize) < MAX_ACTIVE_SESSIONS
        && live.free_session_slots == 1
        && let Some(&oldest) = reset.context_array.get(live.oldest_saved_session as usize)
        && (reset.context_counter as u16) & mask == oldest
    {
        return Err(TPM_RC_CONTEXT_GAP);
    }
    for index in 0..MAX_ACTIVE_SESSIONS {
        if reset.context_array[index] == 0 {
            let previous = reset.context_array[index];
            reset.context_array[index] = (ram_slot as u16 + 1) & mask;
            return Ok((index as u32, previous));
        }
    }
    Err(TPM_RC_SESSION_HANDLES)
}

pub(super) struct AllocatedSession {
    pub(super) context_index: u32,
    pub(super) ram_slot: usize,
    previous_free_slots: u32,
    previous_occupied: bool,
    previous_session: Option<OwnedSession>,
    previous_context: u16,
}

pub(super) fn allocate_session(live: &mut LiveState) -> Result<AllocatedSession, TpmResult> {
    if live.free_session_slots == 0 {
        return Err(TPM_RC_SESSION_MEMORY);
    }
    let ram_slot = free_ram_slot(live).ok_or(TPM_RC_SESSION_MEMORY)?;
    let previous_free_slots = live.free_session_slots;
    let previous_occupied = live.sessions[ram_slot].occupied;
    let (context_index, previous_context) = assign_context_slot(live, ram_slot)?;
    let previous_session = live.sessions[ram_slot].session.take();
    live.free_session_slots -= 1;
    live.sessions[ram_slot].occupied = true;
    Ok(AllocatedSession {
        context_index,
        ram_slot,
        previous_free_slots,
        previous_occupied,
        previous_session,
        previous_context,
    })
}

pub(super) fn publish_session(
    live: &mut LiveState,
    allocated: AllocatedSession,
    session: OwnedSession,
) {
    live.sessions[allocated.ram_slot].session = Some(session);
}

pub(super) fn release_session(live: &mut LiveState, allocated: AllocatedSession) {
    if let Some(reset) = live.state_reset.as_mut()
        && let Some(entry) = reset
            .context_array
            .get_mut(allocated.context_index as usize)
    {
        *entry = allocated.previous_context;
    }
    if let Some(slot) = live.sessions.get_mut(allocated.ram_slot) {
        slot.occupied = allocated.previous_occupied;
        slot.session = allocated.previous_session;
    }
    live.free_session_slots = allocated.previous_free_slots;
}

pub(super) fn reset_policy_data(session: &mut OwnedSession) {
    let preserved = session.attributes
        & (SESSION_ATTR_IS_TRIAL_POLICY | SESSION_ATTR_IS_DA_BOUND | SESSION_ATTR_IS_LOCKOUT_BOUND);
    session.command_code = 0;
    session.command_locality = 0;
    session.bound_entity.clear();
    session.timeout = 0;
    session.pcr_counter = 0;
    session.audit_digest.fill(0);
    session.attributes = SESSION_ATTR_IS_POLICY | preserved;
}

pub(super) fn set_start_time(session: &mut OwnedSession, time: u64, epoch: u32) {
    session.start_time = time;
    session.epoch = epoch;
    session.timeout = 0;
}

fn context_slot(live: &LiveState, handle: u32) -> Option<(usize, u16)> {
    let slot = usize::try_from(handle & HR_HANDLE_MASK).ok()?;
    let context = *live.state_reset.as_ref()?.context_array.get(slot)?;
    Some((slot, context))
}

pub(super) fn session_is_loaded(live: &LiveState, handle: u32) -> bool {
    context_slot(live, handle)
        .is_some_and(|(_, context)| context != 0 && usize::from(context) <= MAX_LOADED_SESSIONS)
}

pub(super) fn session_is_saved(live: &LiveState, handle: u32) -> bool {
    context_slot(live, handle)
        .is_some_and(|(_, context)| usize::from(context) > MAX_LOADED_SESSIONS)
}

pub(super) const NO_OLDEST_SAVED_SESSION: u32 = MAX_ACTIVE_SESSIONS as u32 + 1;

fn set_oldest_saved_session(live: &mut LiveState) {
    let mask = live.context_slot_mask;
    let mut smallest = mask;
    let mut oldest = NO_OLDEST_SAVED_SESSION;
    if let Some(reset) = live.state_reset.as_ref() {
        let low_bits = (reset.context_counter as u16) & mask;
        for (slot, &entry) in reset.context_array.iter().enumerate() {
            if usize::from(entry) <= MAX_LOADED_SESSIONS {
                continue;
            }
            let age = entry.wrapping_sub(low_bits) & mask;
            if age <= smallest {
                smallest = age;
                oldest = slot as u32;
            }
        }
    }
    live.oldest_saved_session = oldest;
}

pub(super) fn sequence_number_for_saved_context_is_valid(
    live: &LiveState,
    saved_handle: u32,
    sequence: u64,
) -> bool {
    let mask = live.context_slot_mask;
    let max_context_gap = u64::from(mask) + 1;
    let Some(reset) = live.state_reset.as_ref() else {
        return false;
    };
    let index = (saved_handle & HR_HANDLE_MASK) as usize;
    if index >= MAX_ACTIVE_SESSIONS {
        return false;
    }
    let entry = reset.context_array[index];
    usize::from(entry) > MAX_LOADED_SESSIONS
        && entry == (sequence as u16) & mask
        && sequence <= reset.context_counter
        && reset.context_counter - sequence <= max_context_gap
}

pub(super) fn session_context_save(live: &mut LiveState, handle: u32) -> Result<u64, TpmResult> {
    let mask = live.context_slot_mask;
    let oldest = live.oldest_saved_session as usize;
    let reset = live.state_reset.as_mut().ok_or(TPM_RC_FAILURE)?;
    if oldest < MAX_ACTIVE_SESSIONS
        && reset.context_array[oldest] == (reset.context_counter as u16) & mask
    {
        return Err(TPM_RC_CONTEXT_GAP);
    }
    let context_id = reset.context_counter;
    let context_index = (handle & HR_HANDLE_MASK) as usize;
    if context_index >= MAX_ACTIVE_SESSIONS {
        return Err(TPM_RC_FAILURE);
    }
    let ram_slot = usize::from(reset.context_array[context_index])
        .checked_sub(1)
        .ok_or(TPM_RC_FAILURE)?;
    reset.context_array[context_index] = (reset.context_counter as u16) & mask;
    reset.context_counter = reset.context_counter.wrapping_add(1);
    if reset.context_counter == 0 {
        reset.context_counter -= 1;
        return Err(TPM_RC_TOO_MANY_CONTEXTS);
    }
    if (reset.context_counter as u16) & mask == 0 {
        reset.context_counter += MAX_LOADED_SESSIONS as u64 + 1;
    }
    if live.oldest_saved_session as usize >= MAX_ACTIVE_SESSIONS {
        live.oldest_saved_session = context_index as u32;
    }
    let slot = live.sessions.get_mut(ram_slot).ok_or(TPM_RC_FAILURE)?;
    slot.occupied = false;
    slot.session = None;
    live.free_session_slots += 1;
    Ok(context_id)
}

pub(super) fn session_context_load(
    live: &mut LiveState,
    handle: u32,
    session: OwnedSession,
) -> Result<(), TpmResult> {
    if live.free_session_slots == 0 {
        return Err(TPM_RC_SESSION_MEMORY);
    }
    let ram_slot = free_ram_slot(live).ok_or(TPM_RC_SESSION_MEMORY)?;
    let context_index = (handle & HR_HANDLE_MASK) as usize;
    if context_index >= MAX_ACTIVE_SESSIONS {
        return Err(TPM_RC_FAILURE);
    }
    let mask = live.context_slot_mask;
    let oldest = live.oldest_saved_session as usize;
    {
        let reset = live.state_reset.as_ref().ok_or(TPM_RC_FAILURE)?;
        if oldest < MAX_ACTIVE_SESSIONS
            && live.free_session_slots == 1
            && (reset.context_counter as u16) & mask == reset.context_array[oldest]
            && context_index != oldest
        {
            return Err(TPM_RC_CONTEXT_GAP);
        }
    }
    let reset = live.state_reset.as_mut().ok_or(TPM_RC_FAILURE)?;
    reset.context_array[context_index] = ram_slot as u16 + 1;
    if context_index == oldest {
        set_oldest_saved_session(live);
    }
    let slot = live.sessions.get_mut(ram_slot).ok_or(TPM_RC_FAILURE)?;
    slot.session = Some(session);
    slot.occupied = true;
    live.free_session_slots -= 1;
    Ok(())
}

pub(super) fn flush_session(live: &mut LiveState, handle: u32) {
    let Some((slot, context)) = context_slot(live, handle) else {
        return;
    };
    if let Some(reset) = live.state_reset.as_mut() {
        reset.context_array[slot] = 0;
    }
    if usize::from(context) > MAX_LOADED_SESSIONS {
        if slot as u32 == live.oldest_saved_session {
            set_oldest_saved_session(live);
        }
        return;
    }
    let Some(ram_slot) = usize::from(context)
        .checked_sub(1)
        .and_then(|index| live.sessions.get_mut(index))
    else {
        return;
    };
    ram_slot.occupied = false;
    ram_slot.session = None;
    live.free_session_slots += 1;
}

fn truncated(section: StateSection) -> PersistentAllError {
    PersistentAllError::Truncated { section }
}

fn skip_future_block(
    reader: &mut BlobReader<'_>,
    section: StateSection,
) -> Result<(), PersistentAllError> {
    skip_optional_block(reader, false)
        .map(|_| ())
        .map_err(|error| match error {
            BlockSkipError::Truncated => truncated(section),
            BlockSkipError::MissingRequiredBlock => {
                PersistentAllError::MissingRequiredBlock { section }
            }
        })
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct Session<'a> {
    pub(super) attributes: u32,
    pub(super) pcr_counter: u32,
    pub(super) start_time: u64,
    pub(super) timeout: u64,
    pub(super) epoch: u32,
    pub(super) command_code: u32,
    pub(super) auth_hash_alg: u16,
    pub(super) command_locality: u8,
    pub(super) symmetric: SymDefObject,
    pub(super) session_key: &'a [u8],
    pub(super) nonce_tpm: &'a [u8],
    pub(super) bound_entity: &'a [u8],
    pub(super) audit_digest: &'a [u8],
}

impl core::fmt::Debug for Session<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session")
            .field("attributes", &format_args!("{:#010x}", self.attributes))
            .field("command_code", &self.command_code)
            .field("session_key_len", &self.session_key.len())
            .field("nonce_tpm_len", &self.nonce_tpm.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct SessionSlot<'a> {
    pub(super) occupied: bool,
    pub(super) session: Option<Session<'a>>,
}

fn parse_session<'a>(
    reader: &mut BlobReader<'a>,
    state_format: StateFormatLimit,
) -> Result<Session<'a>, PersistentAllError> {
    const SECTION: StateSection = StateSection::Session;

    let header = parse_nv_header(reader, SECTION, SESSION_MAGIC, SESSION_VERSION)?;
    let attributes = reader.read_u32().map_err(|_| truncated(SECTION))?;
    let pcr_counter = reader.read_u32().map_err(|_| truncated(SECTION))?;
    let start_time = reader.read_u64().map_err(|_| truncated(SECTION))?;
    let timeout = reader.read_u64().map_err(|_| truncated(SECTION))?;

    let clock_size = reader.read_u8().map_err(|_| truncated(SECTION))?;
    if clock_size != EPOCH_CLOCK_SIZE {
        return Err(PersistentAllError::InvalidClockSize {
            actual: clock_size,
            expected: EPOCH_CLOCK_SIZE,
        });
    }
    let epoch = reader.read_u32().map_err(|_| truncated(SECTION))?;

    let command_code = reader.read_u32().map_err(|_| truncated(SECTION))?;
    let auth_hash_alg = reader.read_u16().map_err(|_| truncated(SECTION))?;
    let command_locality = reader.read_u8().map_err(|_| truncated(SECTION))?;
    let symmetric = parse_sym_def(reader, SECTION, state_format)?;
    let session_key = read_tpm2b(reader, SECTION, PersistentField::SessionKey, DIGEST_SIZE)?;
    let nonce_tpm = read_tpm2b(reader, SECTION, PersistentField::NonceTpm, DIGEST_SIZE)?;
    let bound_entity = read_tpm2b(reader, SECTION, PersistentField::BoundEntity, NAME_SIZE)?;
    let audit_digest = read_tpm2b(
        reader,
        SECTION,
        PersistentField::SessionAuditDigest,
        DIGEST_SIZE,
    )?;

    if header.version >= BLOCK_SKIP_SINCE_VERSION {
        skip_future_block(reader, SECTION)?;
    }

    Ok(Session {
        attributes,
        pcr_counter,
        start_time,
        timeout,
        epoch,
        command_code,
        auth_hash_alg,
        command_locality,
        symmetric,
        session_key,
        nonce_tpm,
        bound_entity,
        audit_digest,
    })
}

pub(super) fn parse_session_slot<'a>(
    reader: &mut BlobReader<'a>,
    state_format: StateFormatLimit,
) -> Result<SessionSlot<'a>, PersistentAllError> {
    const SECTION: StateSection = StateSection::SessionSlot;

    let header = parse_nv_header(reader, SECTION, SESSION_SLOT_MAGIC, SESSION_SLOT_VERSION)?;
    let occupied = reader.read_bool().map_err(|_| truncated(SECTION))?;
    if !occupied {
        return Ok(SessionSlot {
            occupied,
            session: None,
        });
    }

    let session = parse_session(reader, state_format)?;

    if header.version >= BLOCK_SKIP_SINCE_VERSION {
        skip_future_block(reader, SECTION)?;
    }

    Ok(SessionSlot {
        occupied,
        session: Some(session),
    })
}

#[cfg(test)]
pub(super) struct SessionFixture {
    pub(super) version: u16,
    pub(super) magic: u32,
    pub(super) attributes: u32,
    pub(super) pcr_counter: u32,
    pub(super) start_time: u64,
    pub(super) timeout: u64,
    pub(super) clock_size: u8,
    pub(super) epoch: u32,
    pub(super) command_code: u32,
    pub(super) auth_hash_alg: u16,
    pub(super) command_locality: u8,
    pub(super) symmetric: Vec<u8>,
    pub(super) session_key: Vec<u8>,
    pub(super) nonce_tpm: Vec<u8>,
    pub(super) bound_entity: Vec<u8>,
    pub(super) audit_digest: Vec<u8>,
    pub(super) future_block: Option<(u8, u16, Vec<u8>)>,
}

#[cfg(test)]
impl Default for SessionFixture {
    fn default() -> Self {
        Self {
            version: SESSION_VERSION,
            magic: SESSION_MAGIC,
            attributes: 0x0000_0001,
            pcr_counter: 7,
            start_time: 100,
            timeout: 5000,
            clock_size: EPOCH_CLOCK_SIZE,
            epoch: 12,
            command_code: 0x0000_0176,
            auth_hash_alg: 0x000b,
            command_locality: 0,
            symmetric: vec![0x00, 0x06, 0x00, 0x80, 0x00, 0x43],
            session_key: vec![0x33; 32],
            nonce_tpm: vec![0x44; 20],
            bound_entity: vec![0x55; 34],
            audit_digest: Vec::new(),
            future_block: Some((1, 0, Vec::new())),
        }
    }
}

#[cfg(test)]
impl SessionFixture {
    pub(super) fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.magic.to_be_bytes());
        if self.version >= 2 {
            out.extend_from_slice(&1u16.to_be_bytes());
        }
        out.extend_from_slice(&self.attributes.to_be_bytes());
        out.extend_from_slice(&self.pcr_counter.to_be_bytes());
        out.extend_from_slice(&self.start_time.to_be_bytes());
        out.extend_from_slice(&self.timeout.to_be_bytes());
        out.push(self.clock_size);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.command_code.to_be_bytes());
        out.extend_from_slice(&self.auth_hash_alg.to_be_bytes());
        out.push(self.command_locality);
        out.extend_from_slice(&self.symmetric);
        for tpm2b in [
            &self.session_key,
            &self.nonce_tpm,
            &self.bound_entity,
            &self.audit_digest,
        ] {
            out.extend_from_slice(&u16::try_from(tpm2b.len()).unwrap().to_be_bytes());
            out.extend_from_slice(tpm2b);
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
pub(super) struct SessionSlotFixture {
    pub(super) version: u16,
    pub(super) magic: u32,
    pub(super) occupied: u8,
    pub(super) session: Vec<u8>,
    pub(super) future_block: Option<(u8, u16, Vec<u8>)>,
}

#[cfg(test)]
impl Default for SessionSlotFixture {
    fn default() -> Self {
        Self {
            version: SESSION_SLOT_VERSION,
            magic: SESSION_SLOT_MAGIC,
            occupied: 0,
            session: Vec::new(),
            future_block: Some((1, 0, Vec::new())),
        }
    }
}

#[cfg(test)]
impl SessionSlotFixture {
    pub(super) fn occupied() -> Self {
        Self {
            occupied: 1,
            session: SessionFixture::default().bytes(),
            ..Self::default()
        }
    }

    pub(super) fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.magic.to_be_bytes());
        if self.version >= 2 {
            out.extend_from_slice(&1u16.to_be_bytes());
        }
        out.push(self.occupied);
        if self.occupied == 0 {
            return out;
        }
        out.extend_from_slice(&self.session);
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
    use super::super::persistent::AlgInterface;
    use super::*;
    use crate::library::constants::{
        TPM_RC_BAD_PARAMETER, TPM_RC_BAD_TAG, TPM_RC_HASH, TPM_RC_INSUFFICIENT, TPM_RC_SIZE,
        TPM_RC_SYMMETRIC,
    };

    const TAIL_SENTINEL: [u8; 3] = [0xb1, 0xb2, 0xb3];

    #[test]
    fn digest_comparison_length_first_order() {
        assert!(digests_equal(&[], &[]));
        assert!(digests_equal(&[0xa5; 32], &[0xa5; 32]));
        assert!(!digests_equal(&[0xa5; 32], &[0xa5; 20]));
        assert!(!digests_equal(&[0xa5; 20], &[0xa5; 32]));
        let base = [0x10u8, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
        for position in 0..base.len() {
            let mut other = base;
            other[position] ^= 0x80;
            assert!(!digests_equal(&base, &other), "byte {position}");
        }
    }

    #[test]
    fn attribute_bits_vendored_bitfield_match() {
        assert_eq!(SESSION_ATTR_IS_POLICY, 0x0000_0001);
        assert_eq!(SESSION_ATTR_IS_AUDIT, 0x0000_0002);
        assert_eq!(SESSION_ATTR_IS_BOUND, 0x0000_0004);
        assert_eq!(SESSION_ATTR_IS_CP_HASH_DEFINED, 0x0000_0008);
        assert_eq!(SESSION_ATTR_IS_AUTH_VALUE_NEEDED, 0x0000_0010);
        assert_eq!(SESSION_ATTR_IS_PASSWORD_NEEDED, 0x0000_0020);
        assert_eq!(SESSION_ATTR_IS_PP_REQUIRED, 0x0000_0040);
        assert_eq!(SESSION_ATTR_IS_TRIAL_POLICY, 0x0000_0080);
        assert_eq!(SESSION_ATTR_IS_DA_BOUND, 0x0000_0100);
        assert_eq!(SESSION_ATTR_IS_LOCKOUT_BOUND, 0x0000_0200);
        assert_eq!(SESSION_ATTR_INCLUDE_AUTH, 0x0000_0400);
        assert_eq!(SESSION_ATTR_CHECK_NV_WRITTEN, 0x0000_0800);
        assert_eq!(SESSION_ATTR_NV_WRITTEN_STATE, 0x0000_1000);
        assert_eq!(SESSION_ATTR_IS_TEMPLATE_HASH_DEFINED, 0x0000_2000);
        assert_eq!(SESSION_ATTR_IS_NAME_HASH_DEFINED, 0x0000_4000);
        assert_eq!(SESSION_ATTR_IS_PARAMETERS_HASH_DEFINED, 0x0000_8000);
    }

    fn parse_slot(data: &[u8]) -> Result<(SessionSlot<'_>, usize), PersistentAllError> {
        let mut reader = BlobReader::new(data);
        let slot = parse_session_slot(&mut reader, StateFormatLimit::CURRENT)?;
        Ok((slot, reader.remaining().len()))
    }

    #[test]
    fn unoccupied_slot_immediate_end_no_future_block() {
        let mut data = SessionSlotFixture::default().bytes();
        data.extend_from_slice(&TAIL_SENTINEL);
        let (slot, remaining) = parse_slot(&data).unwrap();
        assert!(!slot.occupied);
        assert!(slot.session.is_none());
        assert_eq!(remaining, TAIL_SENTINEL.len());
    }

    #[test]
    fn occupied_slot_full_session_decode() {
        let mut data = SessionSlotFixture::occupied().bytes();
        data.extend_from_slice(&TAIL_SENTINEL);
        let (slot, remaining) = parse_slot(&data).unwrap();
        assert!(slot.occupied);
        let session = slot.session.unwrap();
        assert_eq!(session.attributes, 0x0000_0001);
        assert_eq!(session.pcr_counter, 7);
        assert_eq!(session.start_time, 100);
        assert_eq!(session.timeout, 5000);
        assert_eq!(session.epoch, 12);
        assert_eq!(session.command_code, 0x0000_0176);
        assert_eq!(session.auth_hash_alg, 0x000b);
        assert_eq!(session.command_locality, 0);
        assert_eq!(session.symmetric.algorithm, 0x0006);
        assert_eq!(session.symmetric.key_bits, Some(128));
        assert_eq!(session.symmetric.mode, Some(0x0043));
        assert_eq!(session.session_key, &[0x33; 32][..]);
        assert_eq!(session.nonce_tpm, &[0x44; 20][..]);
        assert_eq!(session.bound_entity, &[0x55; 34][..]);
        assert_eq!(session.audit_digest, &[] as &[u8]);
        assert_eq!(remaining, TAIL_SENTINEL.len());
    }

    #[test]
    fn slot_session_magic_mismatch_bad_tag() {
        let mut data = SessionSlotFixture::occupied().bytes();
        data[2] ^= 0xff;
        let error = parse_slot(&data).unwrap_err();
        assert!(matches!(
            error,
            PersistentAllError::InvalidHeaderMagic {
                section: StateSection::SessionSlot,
                ..
            }
        ));
        assert_eq!(error.tpm_result(), TPM_RC_BAD_TAG);

        let mut data = SessionSlotFixture::occupied().bytes();
        data[11] ^= 0xff;
        let error = parse_slot(&data).unwrap_err();
        assert!(matches!(
            error,
            PersistentAllError::InvalidHeaderMagic {
                section: StateSection::Session,
                ..
            }
        ));
    }

    #[test]
    fn wrong_epoch_clock_size_bad_parameter() {
        for clock_size in [0u8, 8, 0xff] {
            let data = SessionSlotFixture {
                occupied: 1,
                session: SessionFixture {
                    clock_size,
                    ..SessionFixture::default()
                }
                .bytes(),
                ..SessionSlotFixture::default()
            }
            .bytes();
            let error = parse_slot(&data).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::InvalidClockSize {
                    actual: clock_size,
                    expected: EPOCH_CLOCK_SIZE,
                },
                "clock size {clock_size}"
            );
            assert_eq!(error.tpm_result(), TPM_RC_BAD_PARAMETER);
        }
    }

    #[test]
    fn xor_and_null_symmetric_def_union_layout() {
        for (symmetric, algorithm, key_bits, mode) in [
            (vec![0x00, 0x0a, 0x00, 0x04], 0x000a, Some(0x0004), None),
            (vec![0x00, 0x10], 0x0010, None, None),
        ] {
            let data = SessionSlotFixture {
                occupied: 1,
                session: SessionFixture {
                    symmetric,
                    ..SessionFixture::default()
                }
                .bytes(),
                ..SessionSlotFixture::default()
            }
            .bytes();
            let (slot, _) = parse_slot(&data).unwrap();
            let session = slot.session.unwrap();
            assert_eq!(session.symmetric.algorithm, algorithm);
            assert_eq!(session.symmetric.key_bits, key_bits);
            assert_eq!(session.symmetric.mode, mode);
        }
    }

    #[test]
    fn invalid_symmetric_algorithm_rc_symmetric() {
        for algorithm in [0x0013u16, 0x0000] {
            let data = SessionSlotFixture {
                occupied: 1,
                session: SessionFixture {
                    symmetric: algorithm.to_be_bytes().to_vec(),
                    ..SessionFixture::default()
                }
                .bytes(),
                ..SessionSlotFixture::default()
            }
            .bytes();
            let error = parse_slot(&data).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::InvalidAlgorithm {
                    section: StateSection::Session,
                    interface: AlgInterface::Sym,
                    actual: algorithm,
                }
            );
            assert_eq!(error.tpm_result(), TPM_RC_SYMMETRIC);
        }
    }

    #[test]
    fn uncompiled_xor_hash_rc_hash() {
        let data = SessionSlotFixture {
            occupied: 1,
            session: SessionFixture {
                symmetric: vec![0x00, 0x0a, 0x00, 0x12],
                ..SessionFixture::default()
            }
            .bytes(),
            ..SessionSlotFixture::default()
        }
        .bytes();
        let error = parse_slot(&data).unwrap_err();
        assert_eq!(error.tpm_result(), TPM_RC_HASH);
    }

    #[test]
    fn oversized_session_tpm2b_size_errors() {
        for (field, oversized) in [
            ("session_key", 65usize),
            ("nonce_tpm", 65),
            ("bound_entity", 69),
            ("audit_digest", 65),
        ] {
            let mut fixture = SessionFixture::default();
            match field {
                "session_key" => fixture.session_key = vec![0; oversized],
                "nonce_tpm" => fixture.nonce_tpm = vec![0; oversized],
                "bound_entity" => fixture.bound_entity = vec![0; oversized],
                _ => fixture.audit_digest = vec![0; oversized],
            }
            let data = SessionSlotFixture {
                occupied: 1,
                session: fixture.bytes(),
                ..SessionSlotFixture::default()
            }
            .bytes();
            let error = parse_slot(&data).unwrap_err();
            assert_eq!(error.tpm_result(), TPM_RC_SIZE, "field {field}");
        }
    }

    #[test]
    fn session_debug_output_secret_byte_absence() {
        let data = SessionSlotFixture {
            occupied: 1,
            session: SessionFixture {
                session_key: b"session-key-mark".to_vec(),
                nonce_tpm: b"nonce-secret-mrk".to_vec(),
                ..SessionFixture::default()
            }
            .bytes(),
            ..SessionSlotFixture::default()
        }
        .bytes();
        let (slot, _) = parse_slot(&data).unwrap();
        let formatted = format!("{slot:?}");
        assert!(!formatted.contains("session-key-mark"), "{formatted}");
        assert!(!formatted.contains("nonce-secret-mrk"), "{formatted}");
        assert!(formatted.contains("session_key_len"), "{formatted}");
    }

    #[test]
    fn strict_prefix_rejection_safety() {
        let full = SessionSlotFixture::occupied().bytes();
        for len in 0..full.len() {
            let error = parse_slot(&full[..len]).unwrap_err();
            assert_eq!(
                error.tpm_result(),
                TPM_RC_INSUFFICIENT,
                "prefix length {len} of {}",
                full.len()
            );
        }
        assert!(parse_slot(&full).is_ok());
    }

    #[test]
    fn session_slot_byte_mutation_panic_safety() {
        let full = SessionSlotFixture::occupied().bytes();
        for index in 0..full.len() {
            for byte in [0x00u8, 0x01, 0xff] {
                let mut data = full.clone();
                data[index] = byte;
                let _ = parse_slot(&data);
            }
        }
    }
}
