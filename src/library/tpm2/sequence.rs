use crate::ffi_types::TpmResult;
use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_OBJECT_MEMORY};

use super::crypto::{COMPILED_HASHES, SequenceHmac, ShaState, ShaStatePayload};
use super::object::{
    ATTR_EVENT_SEQ, ATTR_EVICT, ATTR_FIRST_BLOCK, ATTR_HASH_SEQ, ATTR_HMAC_SEQ, ATTR_OCCUPIED,
    ATTR_TEMPORARY, ATTR_TICKET_SAFE, HASH_OBJECT_VERSION, HASH_STATE_COUNT,
};
use super::object_create::{find_empty_object_slot, occupied_object_slot};
use super::persistent::{
    OwnedAnyObject, OwnedAnyObjectBody, OwnedHashObjectBody, OwnedHashPayload, OwnedHashState,
    OwnedSecret,
};
use super::public::TPM_ALG_NULL;
use super::runtime::Tpm2Runtime;
use super::template::TPMA_OBJECT_NO_DA;

const HASH_STATE_EMPTY: u8 = 0;
const HASH_STATE_HASH: u8 = 1;
const HASH_STATE_HMAC: u8 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SequenceKind {
    Hash,
    Hmac,
    Event,
}

pub(super) fn sequence_kind(attributes: u32) -> Option<SequenceKind> {
    if attributes & ATTR_OCCUPIED == 0 {
        return None;
    }
    if attributes & ATTR_HMAC_SEQ != 0 {
        return Some(SequenceKind::Hmac);
    }
    if attributes & ATTR_HASH_SEQ != 0 {
        return Some(SequenceKind::Hash);
    }
    if attributes & ATTR_EVENT_SEQ != 0 {
        return Some(SequenceKind::Event);
    }
    None
}

pub(super) fn resolve_sequence_slot(runtime: &Tpm2Runtime, handle: u32) -> Option<usize> {
    let slot = occupied_object_slot(runtime, handle)?;
    let object = runtime.live.objects.get(slot)?;
    sequence_kind(object.attributes)?;
    matches!(object.body, OwnedAnyObjectBody::Sequence(_)).then_some(slot)
}

pub(super) fn slot_kind(runtime: &Tpm2Runtime, slot: usize) -> Option<SequenceKind> {
    sequence_kind(runtime.live.objects.get(slot)?.attributes)
}

fn empty_hash_state() -> OwnedHashState {
    OwnedHashState {
        state_type: HASH_STATE_EMPTY,
        hash_alg: 0,
        payload: None,
    }
}

fn owned_state(state_type: u8, state: &ShaState) -> OwnedHashState {
    let payload = match state.export() {
        ShaStatePayload::Sha1 {
            h,
            nl,
            nh,
            data,
            num,
        } => OwnedHashPayload::Sha1 {
            h,
            nl,
            nh,
            data: OwnedSecret::from_vec(data),
            num,
        },
        ShaStatePayload::Sha256 {
            h,
            nl,
            nh,
            data,
            num,
            md_len,
        } => OwnedHashPayload::Sha256 {
            h,
            nl,
            nh,
            data: OwnedSecret::from_vec(data),
            num,
            md_len,
        },
        ShaStatePayload::Sha512 {
            h,
            nl,
            nh,
            data,
            num,
            md_len,
        } => OwnedHashPayload::Sha512 {
            h,
            nl,
            nh,
            data: OwnedSecret::from_vec(data),
            num,
            md_len,
        },
    };
    OwnedHashState {
        state_type,
        hash_alg: state.hash_alg(),
        payload: Some(payload),
    }
}

fn restore_state(stored: &OwnedHashState) -> Option<ShaState> {
    let payload = match stored.payload.as_ref()? {
        OwnedHashPayload::Sha1 {
            h,
            nl,
            nh,
            data,
            num,
        } => ShaStatePayload::Sha1 {
            h: *h,
            nl: *nl,
            nh: *nh,
            data: data.as_bytes().to_vec(),
            num: *num,
        },
        OwnedHashPayload::Sha256 {
            h,
            nl,
            nh,
            data,
            num,
            md_len,
        } => ShaStatePayload::Sha256 {
            h: *h,
            nl: *nl,
            nh: *nh,
            data: data.as_bytes().to_vec(),
            num: *num,
            md_len: *md_len,
        },
        OwnedHashPayload::Sha512 {
            h,
            nl,
            nh,
            data,
            num,
            md_len,
        } => ShaStatePayload::Sha512 {
            h: *h,
            nl: *nl,
            nh: *nh,
            data: data.as_bytes().to_vec(),
            num: *num,
            md_len: *md_len,
        },
    };
    ShaState::import(stored.hash_alg, &payload)
}

fn sequence_object(auth: &[u8], sequence_bit: u32, body: OwnedHashObjectBody) -> OwnedAnyObject {
    OwnedAnyObject {
        attributes: ATTR_OCCUPIED | ATTR_TEMPORARY | sequence_bit,
        body: OwnedAnyObjectBody::Sequence(Box::new(OwnedHashObjectBody {
            auth: OwnedSecret::copy_of(auth),
            ..body
        })),
    }
}

fn blank_body() -> OwnedHashObjectBody {
    OwnedHashObjectBody {
        section_version: HASH_OBJECT_VERSION,
        object_type: TPM_ALG_NULL,
        name_alg: TPM_ALG_NULL,
        object_attributes: TPMA_OBJECT_NO_DA,
        auth: OwnedSecret::from_vec(Vec::new()),
        states: None,
        hmac_state: None,
    }
}

pub(super) struct SequenceSlot {
    pub(super) slot: usize,
    pub(super) handle: u32,
}

pub(super) fn allocate_sequence_slot(
    runtime: &mut Tpm2Runtime,
    kind: SequenceKind,
    auth: &[u8],
) -> Result<SequenceSlot, TpmResult> {
    let (slot, handle) = find_empty_object_slot(runtime).ok_or(TPM_RC_OBJECT_MEMORY)?;
    let sequence_bit = match kind {
        SequenceKind::Hash => ATTR_HASH_SEQ,
        SequenceKind::Hmac => ATTR_HMAC_SEQ,
        SequenceKind::Event => ATTR_EVENT_SEQ,
    };
    let entry = runtime.live.objects.get_mut(slot).ok_or(TPM_RC_FAILURE)?;
    *entry = sequence_object(auth, sequence_bit, blank_body());
    Ok(SequenceSlot { slot, handle })
}

pub(super) fn reserve_evict_slot(
    runtime: &mut Tpm2Runtime,
    attributes: u32,
) -> Result<usize, TpmResult> {
    let (slot, _) = find_empty_object_slot(runtime).ok_or(TPM_RC_OBJECT_MEMORY)?;
    let entry = runtime.live.objects.get_mut(slot).ok_or(TPM_RC_FAILURE)?;
    entry.attributes = attributes | ATTR_OCCUPIED | ATTR_EVICT;
    entry.body = OwnedAnyObjectBody::Unoccupied;
    Ok(slot)
}

pub(super) fn init_hash_sequence(
    runtime: &mut Tpm2Runtime,
    slot: usize,
    hash_alg: u16,
) -> Result<(), TpmResult> {
    let state = ShaState::new(hash_alg).ok_or(TPM_RC_FAILURE)?;
    let states = Box::new([
        owned_state(HASH_STATE_HASH, &state),
        empty_hash_state(),
        empty_hash_state(),
        empty_hash_state(),
    ]);
    sequence_body_mut(runtime, slot)?.states = Some(states);
    Ok(())
}

pub(super) fn init_event_sequence(runtime: &mut Tpm2Runtime, slot: usize) -> Result<(), TpmResult> {
    let mut states = Vec::with_capacity(HASH_STATE_COUNT);
    for &(hash_alg, _) in &COMPILED_HASHES {
        let state = ShaState::new(hash_alg).ok_or(TPM_RC_FAILURE)?;
        states.push(owned_state(HASH_STATE_HASH, &state));
    }
    let states: [OwnedHashState; HASH_STATE_COUNT] =
        states.try_into().map_err(|_| TPM_RC_FAILURE)?;
    sequence_body_mut(runtime, slot)?.states = Some(Box::new(states));
    Ok(())
}

pub(super) fn init_hmac_sequence(
    runtime: &mut Tpm2Runtime,
    slot: usize,
    hash_alg: u16,
    key: &[u8],
) -> Result<(), TpmResult> {
    let hmac = SequenceHmac::start(hash_alg, key).ok_or(TPM_RC_FAILURE)?;
    let stored = owned_state(HASH_STATE_HMAC, &hmac.state);
    sequence_body_mut(runtime, slot)?.hmac_state =
        Some((stored, OwnedSecret::from_vec(hmac.opad_key)));
    Ok(())
}

#[cfg(test)]
pub(super) fn create_hash_sequence(
    runtime: &mut Tpm2Runtime,
    hash_alg: u16,
    auth: &[u8],
) -> Result<u32, TpmResult> {
    let allocated = allocate_sequence_slot(runtime, SequenceKind::Hash, auth)?;
    match init_hash_sequence(runtime, allocated.slot, hash_alg) {
        Ok(()) => Ok(allocated.handle),
        Err(code) => {
            release_sequence(runtime, allocated.slot);
            Err(code)
        }
    }
}

#[cfg(test)]
pub(super) fn create_event_sequence(
    runtime: &mut Tpm2Runtime,
    auth: &[u8],
) -> Result<u32, TpmResult> {
    let allocated = allocate_sequence_slot(runtime, SequenceKind::Event, auth)?;
    match init_event_sequence(runtime, allocated.slot) {
        Ok(()) => Ok(allocated.handle),
        Err(code) => {
            release_sequence(runtime, allocated.slot);
            Err(code)
        }
    }
}

#[cfg(test)]
pub(super) fn create_hmac_sequence(
    runtime: &mut Tpm2Runtime,
    hash_alg: u16,
    key: &[u8],
    auth: &[u8],
) -> Result<u32, TpmResult> {
    let allocated = allocate_sequence_slot(runtime, SequenceKind::Hmac, auth)?;
    match init_hmac_sequence(runtime, allocated.slot, hash_alg, key) {
        Ok(()) => Ok(allocated.handle),
        Err(code) => {
            release_sequence(runtime, allocated.slot);
            Err(code)
        }
    }
}

#[cfg(test)]
pub(super) fn release_sequence(runtime: &mut Tpm2Runtime, slot: usize) {
    if let Some(object) = runtime.live.objects.get_mut(slot) {
        object.attributes &= !ATTR_OCCUPIED;
    }
}

fn sequence_body_mut(
    runtime: &mut Tpm2Runtime,
    slot: usize,
) -> Result<&mut OwnedHashObjectBody, TpmResult> {
    let object = runtime.live.objects.get_mut(slot).ok_or(TPM_RC_FAILURE)?;
    match &mut object.body {
        OwnedAnyObjectBody::Sequence(body) => Ok(body),
        _ => Err(TPM_RC_FAILURE),
    }
}

pub(super) fn update_sequence(
    runtime: &mut Tpm2Runtime,
    slot: usize,
    buffer: &[u8],
) -> Result<(), TpmResult> {
    let kind = slot_kind(runtime, slot).ok_or(TPM_RC_FAILURE)?;
    let body = sequence_body_mut(runtime, slot)?;
    match kind {
        SequenceKind::Hash => {
            let states = body.states.as_mut().ok_or(TPM_RC_FAILURE)?;
            let mut state = restore_state(&states[0]).ok_or(TPM_RC_FAILURE)?;
            state.update(buffer);
            states[0] = owned_state(HASH_STATE_HASH, &state);
        }
        SequenceKind::Event => {
            let states = body.states.as_ref().ok_or(TPM_RC_FAILURE)?;
            let mut updated = Vec::with_capacity(HASH_STATE_COUNT);
            for stored in states.iter() {
                let mut state = restore_state(stored).ok_or(TPM_RC_FAILURE)?;
                state.update(buffer);
                updated.push(owned_state(HASH_STATE_HASH, &state));
            }
            let updated: [OwnedHashState; HASH_STATE_COUNT] =
                updated.try_into().map_err(|_| TPM_RC_FAILURE)?;
            body.states = Some(Box::new(updated));
        }
        SequenceKind::Hmac => {
            let (stored, _) = body.hmac_state.as_mut().ok_or(TPM_RC_FAILURE)?;
            let mut state = restore_state(stored).ok_or(TPM_RC_FAILURE)?;
            state.update(buffer);
            *stored = owned_state(HASH_STATE_HMAC, &state);
        }
    }
    Ok(())
}

pub(super) fn sequence_hash_alg(runtime: &Tpm2Runtime, slot: usize) -> Result<u16, TpmResult> {
    let object = runtime.live.objects.get(slot).ok_or(TPM_RC_FAILURE)?;
    let OwnedAnyObjectBody::Sequence(body) = &object.body else {
        return Err(TPM_RC_FAILURE);
    };
    match sequence_kind(object.attributes).ok_or(TPM_RC_FAILURE)? {
        SequenceKind::Hash | SequenceKind::Event => Ok(body
            .states
            .as_ref()
            .ok_or(TPM_RC_FAILURE)?
            .first()
            .ok_or(TPM_RC_FAILURE)?
            .hash_alg),
        SequenceKind::Hmac => Ok(body.hmac_state.as_ref().ok_or(TPM_RC_FAILURE)?.0.hash_alg),
    }
}

pub(super) fn finalize_hash(
    runtime: &Tpm2Runtime,
    slot: usize,
    buffer: &[u8],
) -> Result<Vec<u8>, TpmResult> {
    let object = runtime.live.objects.get(slot).ok_or(TPM_RC_FAILURE)?;
    let OwnedAnyObjectBody::Sequence(body) = &object.body else {
        return Err(TPM_RC_FAILURE);
    };
    let states = body.states.as_ref().ok_or(TPM_RC_FAILURE)?;
    let mut state = restore_state(&states[0]).ok_or(TPM_RC_FAILURE)?;
    state.update(buffer);
    Ok(state.finalize())
}

pub(super) fn finalize_hmac(
    runtime: &Tpm2Runtime,
    slot: usize,
    buffer: &[u8],
) -> Result<Vec<u8>, TpmResult> {
    let object = runtime.live.objects.get(slot).ok_or(TPM_RC_FAILURE)?;
    let OwnedAnyObjectBody::Sequence(body) = &object.body else {
        return Err(TPM_RC_FAILURE);
    };
    let (stored, key) = body.hmac_state.as_ref().ok_or(TPM_RC_FAILURE)?;
    let mut state = restore_state(stored).ok_or(TPM_RC_FAILURE)?;
    state.update(buffer);
    let hmac = SequenceHmac {
        state,
        opad_key: key.as_bytes().to_vec(),
    };
    hmac.finalize().ok_or(TPM_RC_FAILURE)
}

pub(super) fn finalize_event(
    runtime: &Tpm2Runtime,
    slot: usize,
    buffer: &[u8],
) -> Result<Vec<(u16, Vec<u8>)>, TpmResult> {
    let object = runtime.live.objects.get(slot).ok_or(TPM_RC_FAILURE)?;
    let OwnedAnyObjectBody::Sequence(body) = &object.body else {
        return Err(TPM_RC_FAILURE);
    };
    let states = body.states.as_ref().ok_or(TPM_RC_FAILURE)?;
    let mut digests = Vec::with_capacity(HASH_STATE_COUNT);
    for (index, &(hash_alg, _)) in COMPILED_HASHES.iter().enumerate() {
        let stored = states.get(index).ok_or(TPM_RC_FAILURE)?;
        let mut state = restore_state(stored).ok_or(TPM_RC_FAILURE)?;
        state.update(buffer);
        digests.push((hash_alg, state.finalize()));
    }
    Ok(digests)
}

pub(super) fn first_block_seen(runtime: &Tpm2Runtime, slot: usize) -> Result<bool, TpmResult> {
    let object = runtime.live.objects.get(slot).ok_or(TPM_RC_FAILURE)?;
    Ok(object.attributes & ATTR_FIRST_BLOCK != 0)
}

pub(super) fn ticket_safe(runtime: &Tpm2Runtime, slot: usize) -> Result<bool, TpmResult> {
    let object = runtime.live.objects.get(slot).ok_or(TPM_RC_FAILURE)?;
    Ok(object.attributes & ATTR_TICKET_SAFE != 0)
}

pub(super) fn mark_first_block(
    runtime: &mut Tpm2Runtime,
    slot: usize,
    safe: bool,
) -> Result<(), TpmResult> {
    let object = runtime.live.objects.get_mut(slot).ok_or(TPM_RC_FAILURE)?;
    object.attributes |= ATTR_FIRST_BLOCK;
    if safe {
        object.attributes |= ATTR_TICKET_SAFE;
    }
    Ok(())
}

pub(super) fn mark_evicted(runtime: &mut Tpm2Runtime, slot: usize) -> Result<(), TpmResult> {
    let object = runtime.live.objects.get_mut(slot).ok_or(TPM_RC_FAILURE)?;
    object.attributes |= ATTR_EVICT;
    Ok(())
}

pub(super) fn cleanup_evicted(runtime: &mut Tpm2Runtime) {
    for object in runtime.live.objects.iter_mut() {
        if object.attributes & ATTR_EVICT != 0 {
            object.attributes &= !ATTR_OCCUPIED;
        }
    }
}

#[cfg(test)]
pub(in crate::library::tpm2) mod replay {
    use crate::ffi_types::TpmResult;
    use crate::library::CommandInput;
    use crate::library::tpm2::clock::SteppingClock;
    pub(in crate::library::tpm2) use crate::library::tpm2::golden_responses::sequence_commands::vector;
    use crate::library::tpm2::persistent::persistent_all_store;
    use crate::library::tpm2::process::process;
    use crate::library::tpm2::runtime::Tpm2Runtime;
    use crate::library::tpm2::volatile::volatile_all_store;
    use crate::library::tpm2::{
        VolatileDecodeBoundary, attach_volatile_blob, restore_permanent_blob_for_test,
    };

    pub(in crate::library::tpm2) const RH_OWNER: u32 = 0x4000_0001;
    pub(in crate::library::tpm2) const RH_ENDORSEMENT: u32 = 0x4000_000b;
    pub(in crate::library::tpm2) const RH_PLATFORM: u32 = 0x4000_000c;
    pub(in crate::library::tpm2) const RH_NULL: u32 = 0x4000_0007;
    const RS_PW: u32 = 0x4000_0009;

    pub(in crate::library::tpm2) const CC_SEQUENCE_COMPLETE: u32 = 0x0000_013e;
    pub(in crate::library::tpm2) const CC_HMAC_START: u32 = 0x0000_015b;
    pub(in crate::library::tpm2) const CC_SEQUENCE_UPDATE: u32 = 0x0000_015c;
    pub(in crate::library::tpm2) const CC_EVENT_SEQUENCE_COMPLETE: u32 = 0x0000_0185;
    pub(in crate::library::tpm2) const CC_HASH_SEQUENCE_START: u32 = 0x0000_0186;

    pub(in crate::library::tpm2) const TPM_ALG_NULL: u16 = 0x0010;

    pub(in crate::library::tpm2) const MESSAGE: &[u8] = b"libtpms-rs sequence data";

    pub(in crate::library::tpm2) fn unreachable_entropy(
        _buffer: &mut [u8],
    ) -> Result<(), TpmResult> {
        panic!("the replay must not draw host entropy");
    }

    pub(in crate::library::tpm2) fn clock() -> SteppingClock {
        SteppingClock::new(1_700_000_000_000, 4_000_000)
    }

    pub(in crate::library::tpm2) fn runtime_from(
        permanent: &str,
        volatile: &str,
        clock: &SteppingClock,
    ) -> Box<Tpm2Runtime> {
        let mut runtime = restore_permanent_blob_for_test(vector(permanent))
            .expect("the oracle permanent state restores");
        attach_volatile_blob(
            &mut runtime,
            vector(volatile),
            clock,
            VolatileDecodeBoundary::Restore,
        )
        .expect("the oracle volatile state attaches");
        runtime.entropy = unreachable_entropy;
        runtime.was_manufactured = true;
        runtime
    }

    pub(in crate::library::tpm2) fn base_runtime(clock: &SteppingClock) -> Box<Tpm2Runtime> {
        runtime_from("PERMALL_BASE", "VOLATILE_BASE", clock)
    }

    pub(in crate::library::tpm2) fn minimal_runtime(clock: &SteppingClock) -> Box<Tpm2Runtime> {
        runtime_from("PERMALL_MINIMAL_BASE", "VOLATILE_MINIMAL_BASE", clock)
    }

    pub(in crate::library::tpm2) fn state_blobs(
        runtime: &Tpm2Runtime,
        clock: &SteppingClock,
    ) -> (Vec<u8>, Vec<u8>) {
        let permanent = persistent_all_store(runtime.state.as_ref().expect("decoded state"))
            .expect("the permanent state serializes");
        let volatile = volatile_all_store(runtime, clock).expect("the volatile state saves");
        (permanent, volatile)
    }

    pub(in crate::library::tpm2) fn reload(
        permanent: &[u8],
        volatile: &[u8],
        clock: &SteppingClock,
    ) -> Box<Tpm2Runtime> {
        let mut runtime =
            restore_permanent_blob_for_test(permanent).expect("the saved permanent state restores");
        attach_volatile_blob(
            &mut runtime,
            volatile,
            clock,
            VolatileDecodeBoundary::Restore,
        )
        .expect("the saved volatile state attaches");
        runtime.entropy = unreachable_entropy;
        runtime.was_manufactured = true;
        runtime
    }

    #[track_caller]
    pub(in crate::library::tpm2) fn exec_at(
        runtime: &mut Tpm2Runtime,
        clock: &SteppingClock,
        locality: u8,
        bytes: Vec<u8>,
    ) -> Vec<u8> {
        let input = CommandInput::new(bytes.len() as u32, bytes);
        process(
            runtime,
            crate::library::tpm2::PlatformInputs::at_locality(locality),
            &input,
            clock,
            |_| Ok(()),
        )
        .expect("the command processes")
    }

    #[track_caller]
    pub(in crate::library::tpm2) fn exec_raw(
        runtime: &mut Tpm2Runtime,
        clock: &SteppingClock,
        bytes: Vec<u8>,
    ) -> Vec<u8> {
        exec_at(runtime, clock, 0, bytes)
    }

    #[track_caller]
    pub(in crate::library::tpm2) fn exec(
        runtime: &mut Tpm2Runtime,
        clock: &SteppingClock,
        label: &str,
        bytes: Vec<u8>,
    ) -> Vec<u8> {
        let response = exec_raw(runtime, clock, bytes);
        assert_eq!(response, vector(label), "{label}");
        response
    }

    #[track_caller]
    pub(in crate::library::tpm2) fn exec_locality(
        runtime: &mut Tpm2Runtime,
        clock: &SteppingClock,
        locality: u8,
        label: &str,
        bytes: Vec<u8>,
    ) -> Vec<u8> {
        let response = exec_at(runtime, clock, locality, bytes);
        assert_eq!(response, vector(label), "{label}");
        response
    }

    pub(in crate::library::tpm2) fn tpm2b(payload: &[u8]) -> Vec<u8> {
        let mut out = (payload.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(payload);
        out
    }

    pub(in crate::library::tpm2) fn password(secret: &[u8]) -> Vec<u8> {
        let mut out = RS_PW.to_be_bytes().to_vec();
        out.extend_from_slice(&[0x00, 0x00, 0x00]);
        out.extend_from_slice(&tpm2b(secret));
        out
    }

    pub(in crate::library::tpm2) fn auth_area(sessions: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = sessions.concat();
        let mut out = (body.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(&body);
        out
    }

    pub(in crate::library::tpm2) fn command(tag: u16, code: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = tag.to_be_bytes().to_vec();
        out.extend_from_slice(&((10 + payload.len()) as u32).to_be_bytes());
        out.extend_from_slice(&code.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    pub(in crate::library::tpm2) fn hash_sequence_start(auth: &[u8], hash_alg: u16) -> Vec<u8> {
        let mut params = tpm2b(auth);
        params.extend_from_slice(&hash_alg.to_be_bytes());
        command(0x8001, CC_HASH_SEQUENCE_START, &params)
    }

    pub(in crate::library::tpm2) fn hash_sequence_start_raw(params: &[u8]) -> Vec<u8> {
        command(0x8001, CC_HASH_SEQUENCE_START, params)
    }

    pub(in crate::library::tpm2) fn sequence_update(
        handle: u32,
        buffer: &[u8],
        secret: &[u8],
    ) -> Vec<u8> {
        sequence_update_raw(handle, &tpm2b(buffer), secret)
    }

    pub(in crate::library::tpm2) fn sequence_update_raw(
        handle: u32,
        params: &[u8],
        secret: &[u8],
    ) -> Vec<u8> {
        let mut payload = handle.to_be_bytes().to_vec();
        payload.extend_from_slice(&auth_area(&[password(secret)]));
        payload.extend_from_slice(params);
        command(0x8002, CC_SEQUENCE_UPDATE, &payload)
    }

    pub(in crate::library::tpm2) fn sequence_complete(
        handle: u32,
        buffer: &[u8],
        hierarchy: u32,
        secret: &[u8],
    ) -> Vec<u8> {
        let mut params = tpm2b(buffer);
        params.extend_from_slice(&hierarchy.to_be_bytes());
        sequence_complete_raw(handle, &params, secret)
    }

    pub(in crate::library::tpm2) fn sequence_complete_raw(
        handle: u32,
        params: &[u8],
        secret: &[u8],
    ) -> Vec<u8> {
        let mut payload = handle.to_be_bytes().to_vec();
        payload.extend_from_slice(&auth_area(&[password(secret)]));
        payload.extend_from_slice(params);
        command(0x8002, CC_SEQUENCE_COMPLETE, &payload)
    }

    pub(in crate::library::tpm2) fn event_sequence_complete(
        pcr_handle: u32,
        handle: u32,
        buffer: &[u8],
    ) -> Vec<u8> {
        event_sequence_complete_raw(pcr_handle, handle, &tpm2b(buffer))
    }

    pub(in crate::library::tpm2) fn event_sequence_complete_raw(
        pcr_handle: u32,
        handle: u32,
        params: &[u8],
    ) -> Vec<u8> {
        let mut payload = pcr_handle.to_be_bytes().to_vec();
        payload.extend_from_slice(&handle.to_be_bytes());
        payload.extend_from_slice(&auth_area(&[password(&[]), password(&[])]));
        payload.extend_from_slice(params);
        command(0x8002, CC_EVENT_SEQUENCE_COMPLETE, &payload)
    }

    pub(in crate::library::tpm2) fn mac_start(handle: u32, auth: &[u8], scheme: u16) -> Vec<u8> {
        let mut params = tpm2b(auth);
        params.extend_from_slice(&scheme.to_be_bytes());
        mac_start_raw(handle, &params, &[])
    }

    pub(in crate::library::tpm2) fn mac_start_raw(
        handle: u32,
        params: &[u8],
        secret: &[u8],
    ) -> Vec<u8> {
        let mut payload = handle.to_be_bytes().to_vec();
        payload.extend_from_slice(&auth_area(&[password(secret)]));
        payload.extend_from_slice(params);
        command(0x8002, CC_HMAC_START, &payload)
    }

    pub(in crate::library::tpm2) fn flush_context(handle: u32) -> Vec<u8> {
        command(0x8001, 0x0000_0165, &handle.to_be_bytes())
    }

    pub(in crate::library::tpm2) fn create_primary(
        hierarchy: u32,
        public: &[u8],
        user_auth: &[u8],
        data: &[u8],
    ) -> Vec<u8> {
        let mut sensitive = tpm2b(user_auth);
        sensitive.extend_from_slice(&tpm2b(data));
        let mut payload = hierarchy.to_be_bytes().to_vec();
        payload.extend_from_slice(&auth_area(&[password(&[])]));
        payload.extend_from_slice(&tpm2b(&sensitive));
        payload.extend_from_slice(&tpm2b(public));
        payload.extend_from_slice(&tpm2b(&[]));
        payload.extend_from_slice(&0u32.to_be_bytes());
        command(0x8002, 0x0000_0131, &payload)
    }

    pub(in crate::library::tpm2) fn evict_control(object: u32, persistent: u32) -> Vec<u8> {
        let mut payload = RH_OWNER.to_be_bytes().to_vec();
        payload.extend_from_slice(&object.to_be_bytes());
        payload.extend_from_slice(&auth_area(&[password(&[])]));
        payload.extend_from_slice(&persistent.to_be_bytes());
        command(0x8002, 0x0000_0120, &payload)
    }

    pub(in crate::library::tpm2) fn pcr_read(pcr: usize) -> Vec<u8> {
        const BANKS: [u16; 4] = [0x0004, 0x000b, 0x000c, 0x000d];
        let mut params = (BANKS.len() as u32).to_be_bytes().to_vec();
        for hash_alg in BANKS {
            let mut select = [0u8; 3];
            select[pcr / 8] |= 1 << (pcr % 8);
            params.extend_from_slice(&hash_alg.to_be_bytes());
            params.push(3);
            params.extend_from_slice(&select);
        }
        command(0x8001, 0x0000_017e, &params)
    }

    pub(in crate::library::tpm2) fn keyedhash_public(
        attributes: u32,
        scheme_alg: u16,
        scheme_hash: u16,
    ) -> Vec<u8> {
        let mut out = 0x0008u16.to_be_bytes().to_vec();
        out.extend_from_slice(&0x000bu16.to_be_bytes());
        out.extend_from_slice(&attributes.to_be_bytes());
        out.extend_from_slice(&tpm2b(&[]));
        out.extend_from_slice(&scheme_alg.to_be_bytes());
        if scheme_alg == 0x0005 {
            out.extend_from_slice(&scheme_hash.to_be_bytes());
        } else if scheme_alg == 0x000a {
            out.extend_from_slice(&scheme_hash.to_be_bytes());
            out.extend_from_slice(&0x0022u16.to_be_bytes());
        }
        out.extend_from_slice(&tpm2b(&[]));
        out
    }

    pub(in crate::library::tpm2) const HMAC_KEY_ATTRIBUTES: u32 = 0x0004_0472;
    pub(in crate::library::tpm2) const DA_KEY_ATTRIBUTES: u32 = 0x0004_0072;
    pub(in crate::library::tpm2) const RESTRICTED_KEY_ATTRIBUTES: u32 = 0x0005_0472;
    pub(in crate::library::tpm2) const SEALED_ATTRIBUTES: u32 = 0x0000_0452;
    pub(in crate::library::tpm2) const XOR_KEY_ATTRIBUTES: u32 = 0x0002_0472;

    pub(in crate::library::tpm2) fn hmac_key(hash_alg: u16) -> Vec<u8> {
        keyedhash_public(HMAC_KEY_ATTRIBUTES, 0x0005, hash_alg)
    }

    const ANY_OBJECT_HEADER: [u8; 8] = [0x00, 0x02, 0xfe, 0x9a, 0x39, 0x74, 0x00, 0x01];
    const SESSION_SLOT_MAGIC: [u8; 4] = [0x36, 0x64, 0xae, 0xbc];

    fn find(haystack: &[u8], needle: &[u8]) -> usize {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("the marker is present in the volatile blob")
    }

    pub(in crate::library::tpm2) fn object_region(blob: &[u8]) -> &[u8] {
        let start = find(blob, &ANY_OBJECT_HEADER);
        let end = find(blob, &SESSION_SLOT_MAGIC) - 2;
        &blob[start..end]
    }

    pub(in crate::library::tpm2) fn rsa_storage_public() -> Vec<u8> {
        vec![
            0x00, 0x01, 0x00, 0x0b, 0x00, 0x03, 0x04, 0x72, 0x00, 0x00, 0x00, 0x06, 0x00, 0x80,
            0x00, 0x43, 0x00, 0x10, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::algorithm::{
        TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512,
    };
    use crate::library::tpm2::crypto::Hasher;
    use crate::library::tpm2::object_create::TRANSIENT_FIRST;
    use crate::library::tpm2::runtime::empty_state_runtime;
    use crate::library::tpm2::volatile::MAX_LOADED_OBJECTS;

    fn digest(hash_alg: u16, data: &[u8]) -> Vec<u8> {
        let mut hasher = Hasher::new(hash_alg).expect("a compiled algorithm");
        hasher.update(data);
        hasher.finalize()
    }

    #[test]
    fn a_hash_sequence_takes_the_first_free_slot() {
        let mut runtime = empty_state_runtime();
        let handle =
            create_hash_sequence(&mut runtime, TPM_ALG_SHA256, b"auth").expect("a free slot");
        assert_eq!(handle, TRANSIENT_FIRST);
        assert_eq!(slot_kind(&runtime, 0), Some(SequenceKind::Hash));
        assert_eq!(
            crate::library::tpm2::object_create::object_auth_value(&runtime, handle),
            Some(&b"auth"[..])
        );
    }

    #[test]
    fn every_sequence_kind_is_recognised_by_its_own_handle() {
        let mut runtime = empty_state_runtime();
        let hash = create_hash_sequence(&mut runtime, TPM_ALG_SHA1, &[]).expect("a free slot");
        let hmac =
            create_hmac_sequence(&mut runtime, TPM_ALG_SHA256, b"key", &[]).expect("a free slot");
        let event = create_event_sequence(&mut runtime, &[]).expect("a free slot");
        assert_eq!(
            resolve_sequence_slot(&runtime, hash).and_then(|slot| slot_kind(&runtime, slot)),
            Some(SequenceKind::Hash)
        );
        assert_eq!(
            resolve_sequence_slot(&runtime, hmac).and_then(|slot| slot_kind(&runtime, slot)),
            Some(SequenceKind::Hmac)
        );
        assert_eq!(
            resolve_sequence_slot(&runtime, event).and_then(|slot| slot_kind(&runtime, slot)),
            Some(SequenceKind::Event)
        );
    }

    #[test]
    fn exhausted_slots_report_object_memory() {
        let mut runtime = empty_state_runtime();
        for _ in 0..MAX_LOADED_OBJECTS {
            create_hash_sequence(&mut runtime, TPM_ALG_SHA256, &[]).expect("a free slot");
        }
        assert_eq!(
            create_hash_sequence(&mut runtime, TPM_ALG_SHA256, &[]),
            Err(TPM_RC_OBJECT_MEMORY)
        );
        assert_eq!(
            create_event_sequence(&mut runtime, &[]),
            Err(TPM_RC_OBJECT_MEMORY)
        );
        assert_eq!(
            create_hmac_sequence(&mut runtime, TPM_ALG_SHA256, b"k", &[]),
            Err(TPM_RC_OBJECT_MEMORY)
        );
    }

    #[test]
    fn a_hash_sequence_digests_the_concatenated_updates() {
        for &(hash_alg, _) in &COMPILED_HASHES {
            let mut runtime = empty_state_runtime();
            let handle = create_hash_sequence(&mut runtime, hash_alg, &[]).expect("a free slot");
            let slot = resolve_sequence_slot(&runtime, handle).expect("the sequence resolves");
            update_sequence(&mut runtime, slot, b"abc").expect("updates");
            update_sequence(&mut runtime, slot, &[]).expect("updates");
            update_sequence(&mut runtime, slot, b"def").expect("updates");
            assert_eq!(
                finalize_hash(&runtime, slot, b"ghi").expect("finalizes"),
                digest(hash_alg, b"abcdefghi"),
                "alg {hash_alg:#06x}"
            );
        }
    }

    #[test]
    fn an_event_sequence_produces_every_compiled_bank() {
        let mut runtime = empty_state_runtime();
        let handle = create_event_sequence(&mut runtime, &[]).expect("a free slot");
        let slot = resolve_sequence_slot(&runtime, handle).expect("the sequence resolves");
        update_sequence(&mut runtime, slot, b"abc").expect("updates");
        let digests = finalize_event(&runtime, slot, b"def").expect("finalizes");
        assert_eq!(digests.len(), COMPILED_HASHES.len());
        for (index, (hash_alg, value)) in digests.iter().enumerate() {
            assert_eq!(*hash_alg, COMPILED_HASHES[index].0);
            assert_eq!(value, &digest(*hash_alg, b"abcdef"));
        }
    }

    #[test]
    fn the_event_digest_order_follows_the_compiled_table() {
        let mut runtime = empty_state_runtime();
        let handle = create_event_sequence(&mut runtime, &[]).expect("a free slot");
        let slot = resolve_sequence_slot(&runtime, handle).expect("the sequence resolves");
        let order: Vec<u16> = finalize_event(&runtime, slot, &[])
            .expect("finalizes")
            .into_iter()
            .map(|(hash_alg, _)| hash_alg)
            .collect();
        assert_eq!(
            order,
            [TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512]
        );
    }

    #[test]
    fn a_released_slot_is_reused_by_the_next_sequence() {
        let mut runtime = empty_state_runtime();
        let first = create_hash_sequence(&mut runtime, TPM_ALG_SHA256, &[]).expect("a free slot");
        let second = create_hash_sequence(&mut runtime, TPM_ALG_SHA256, &[]).expect("a free slot");
        assert_eq!(second, first + 1);
        let slot = resolve_sequence_slot(&runtime, first).expect("the sequence resolves");
        release_sequence(&mut runtime, slot);
        assert!(resolve_sequence_slot(&runtime, first).is_none());
        let third = create_hash_sequence(&mut runtime, TPM_ALG_SHA256, &[]).expect("a free slot");
        assert_eq!(third, first);
    }

    #[test]
    fn the_evict_cleanup_only_removes_marked_slots() {
        let mut runtime = empty_state_runtime();
        let kept = create_hash_sequence(&mut runtime, TPM_ALG_SHA256, &[]).expect("a free slot");
        let dropped = create_hash_sequence(&mut runtime, TPM_ALG_SHA256, &[]).expect("a free slot");
        let slot = resolve_sequence_slot(&runtime, dropped).expect("the sequence resolves");
        mark_evicted(&mut runtime, slot).expect("marks");
        cleanup_evicted(&mut runtime);
        assert!(resolve_sequence_slot(&runtime, dropped).is_none());
        assert!(resolve_sequence_slot(&runtime, kept).is_some());
    }

    #[test]
    fn the_first_block_flags_start_clear_and_latch() {
        let mut runtime = empty_state_runtime();
        let handle = create_hash_sequence(&mut runtime, TPM_ALG_SHA256, &[]).expect("a free slot");
        let slot = resolve_sequence_slot(&runtime, handle).expect("the sequence resolves");
        assert_eq!(first_block_seen(&runtime, slot), Ok(false));
        assert_eq!(ticket_safe(&runtime, slot), Ok(false));
        mark_first_block(&mut runtime, slot, false).expect("marks");
        assert_eq!(first_block_seen(&runtime, slot), Ok(true));
        assert_eq!(ticket_safe(&runtime, slot), Ok(false));
        mark_first_block(&mut runtime, slot, true).expect("marks");
        assert_eq!(ticket_safe(&runtime, slot), Ok(true));
    }

    #[test]
    fn a_sequence_hash_algorithm_is_reported_for_every_kind() {
        let mut runtime = empty_state_runtime();
        let hash = create_hash_sequence(&mut runtime, TPM_ALG_SHA384, &[]).expect("a free slot");
        let hmac =
            create_hmac_sequence(&mut runtime, TPM_ALG_SHA512, b"key", &[]).expect("a free slot");
        let event = create_event_sequence(&mut runtime, &[]).expect("a free slot");
        for (handle, expected) in [
            (hash, TPM_ALG_SHA384),
            (hmac, TPM_ALG_SHA512),
            (event, TPM_ALG_SHA1),
        ] {
            let slot = resolve_sequence_slot(&runtime, handle).expect("the sequence resolves");
            assert_eq!(sequence_hash_alg(&runtime, slot), Ok(expected));
        }
    }

    #[test]
    fn an_unknown_algorithm_never_creates_a_sequence() {
        let mut runtime = empty_state_runtime();
        assert_eq!(
            create_hash_sequence(&mut runtime, TPM_ALG_NULL, &[]),
            Err(TPM_RC_FAILURE)
        );
        assert_eq!(
            create_hmac_sequence(&mut runtime, TPM_ALG_NULL, b"k", &[]),
            Err(TPM_RC_FAILURE)
        );
        assert!(
            runtime
                .live
                .objects
                .iter()
                .all(|object| object.attributes & ATTR_OCCUPIED == 0),
            "a rejected algorithm leaves every slot free"
        );
    }

    #[test]
    fn a_non_sequence_handle_never_resolves_as_a_sequence() {
        let mut runtime = empty_state_runtime();
        runtime.live.objects[0].attributes = ATTR_OCCUPIED;
        assert!(resolve_sequence_slot(&runtime, TRANSIENT_FIRST).is_none());
        assert!(resolve_sequence_slot(&runtime, TRANSIENT_FIRST + 1).is_none());
        assert!(resolve_sequence_slot(&runtime, 0x4000_0001).is_none());
    }
}

#[cfg(test)]
mod failure_atomicity {
    use super::replay::clock as fresh_clock;
    use super::replay::{self, *};
    use super::*;
    use crate::library::constants::TPM_RC_FAILURE;
    use crate::library::tpm2::clock::SteppingClock;
    use crate::library::tpm2::runtime::Tpm2Runtime;
    use crate::library::tpm2::self_test::{always_fails, fails_on_sha512};

    const TPM_ALG_SHA256: u16 = 0x000b;
    const RC_FAILURE_RESPONSE: [u8; 10] = [0x80, 0x01, 0, 0, 0, 0x0a, 0, 0, 0x01, 0x01];

    struct Snapshot {
        occupied: Vec<bool>,
        bodies: Vec<Option<Vec<u8>>>,
        pcrs: Vec<[Option<Vec<u8>>; 4]>,
        pcr_counter: Option<u32>,
        failed_tries: u32,
        nv_memory: Box<[u8]>,
        nv_update_pending: bool,
        failure_mode: bool,
    }

    fn snapshot(runtime: &Tpm2Runtime) -> Snapshot {
        Snapshot {
            occupied: runtime
                .live
                .objects
                .iter()
                .map(|object| object.attributes & ATTR_OCCUPIED != 0)
                .collect(),
            bodies: runtime
                .live
                .objects
                .iter()
                .map(|object| {
                    crate::library::tpm2::nv::any_object_image(
                        object,
                        crate::library::tpm2::volatile::CURRENT_OBJECT_VERSION,
                    )
                    .ok()
                })
                .collect(),
            pcrs: runtime
                .live
                .pcrs
                .iter()
                .map(|pcr| pcr.banks.clone())
                .collect(),
            pcr_counter: runtime
                .live
                .state_reset
                .as_ref()
                .map(|reset| reset.pcr_counter),
            failed_tries: runtime
                .state
                .as_ref()
                .expect("decoded state")
                .persistent
                .failed_tries,
            nv_memory: runtime.nv_memory.clone(),
            nv_update_pending: runtime.nv_update_pending,
            failure_mode: runtime.failure_mode,
        }
    }

    #[track_caller]
    fn assert_unchanged(runtime: &Tpm2Runtime, before: &Snapshot) {
        let after = snapshot(runtime);
        assert_eq!(after.occupied, before.occupied, "transient slot occupancy");
        assert_eq!(after.bodies.len(), before.bodies.len());
        for (index, (left, right)) in after.bodies.iter().zip(&before.bodies).enumerate() {
            assert_eq!(left, right, "object slot {index} contents");
        }
        assert_eq!(after.pcrs, before.pcrs, "PCR values");
        assert_eq!(after.pcr_counter, before.pcr_counter, "the PCR counter");
        assert_eq!(after.failed_tries, before.failed_tries, "the DA counter");
        assert_eq!(after.nv_memory, before.nv_memory, "NV memory");
        assert_eq!(
            after.nv_update_pending, before.nv_update_pending,
            "the pending-update flag"
        );
        assert_eq!(after.failure_mode, before.failure_mode, "the failure mode");
    }

    fn started_hash_sequence(clock: &SteppingClock) -> Box<Tpm2Runtime> {
        let mut runtime = base_runtime(clock);
        exec(
            &mut runtime,
            clock,
            "A_START_SHA256",
            hash_sequence_start(&[], TPM_ALG_SHA256),
        );
        runtime
    }

    fn corrupt_stored_state(runtime: &mut Tpm2Runtime, slot: usize) {
        let OwnedAnyObjectBody::Sequence(body) = &mut runtime.live.objects[slot].body else {
            panic!("a sequence body");
        };
        if let Some(states) = body.states.as_mut() {
            for state in states.iter_mut() {
                state.payload = None;
            }
        }
        if let Some((state, _)) = body.hmac_state.as_mut() {
            state.payload = None;
        }
    }

    #[test]
    fn a_rejected_algorithm_never_allocates_a_slot() {
        let clock = fresh_clock();
        let mut runtime = base_runtime(&clock);
        let before = snapshot(&runtime);
        exec(
            &mut runtime,
            &clock,
            "J_START_ALG_SM3",
            hash_sequence_start(&[], 0x0012),
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn an_exhausted_slot_array_leaves_every_sequence_intact() {
        let clock = fresh_clock();
        let mut runtime = base_runtime(&clock);
        for (label, hash_alg) in [
            ("M_START_1", 0x0004u16),
            ("M_START_2", TPM_ALG_SHA256),
            ("M_START_3", 0x000c),
        ] {
            exec(
                &mut runtime,
                &clock,
                label,
                hash_sequence_start(&[], hash_alg),
            );
        }
        let before = snapshot(&runtime);
        exec(
            &mut runtime,
            &clock,
            "M_START_4",
            hash_sequence_start(&[], 0x000d),
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn a_self_test_failure_after_slot_selection_enters_failure_mode() {
        let clock = fresh_clock();
        let mut runtime = base_runtime(&clock);
        runtime.self_test.set_runner(always_fails);
        runtime.self_test = runtime.self_test.restarted();
        runtime.self_test.set_runner(always_fails);
        let response = exec_raw(
            &mut runtime,
            &clock,
            hash_sequence_start(&[], TPM_ALG_SHA256),
        );
        assert_eq!(response, RC_FAILURE_RESPONSE);
        assert!(runtime.failure_mode, "the TPM enters failure mode");
    }

    #[test]
    fn an_unreadable_hash_state_fails_the_update_without_losing_the_sequence() {
        let clock = fresh_clock();
        let mut runtime = started_hash_sequence(&clock);
        corrupt_stored_state(&mut runtime, 0);
        let before = snapshot(&runtime);
        let response = exec_raw(
            &mut runtime,
            &clock,
            sequence_update(0x8000_0000, b"abc", &[]),
        );
        assert_eq!(&response[6..10], TPM_RC_FAILURE.to_be_bytes());
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn an_unreadable_hash_state_fails_the_completion_without_releasing_the_handle() {
        let clock = fresh_clock();
        let mut runtime = started_hash_sequence(&clock);
        corrupt_stored_state(&mut runtime, 0);
        let before = snapshot(&runtime);
        let response = exec_raw(
            &mut runtime,
            &clock,
            sequence_complete(0x8000_0000, b"abc", RH_OWNER, &[]),
        );
        assert_eq!(&response[6..10], TPM_RC_FAILURE.to_be_bytes());
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn an_unreadable_event_state_fails_before_any_bank_is_extended() {
        let clock = fresh_clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "N_START_EVENT",
            hash_sequence_start(&[], replay::TPM_ALG_NULL),
        );
        corrupt_stored_state(&mut runtime, 0);
        let before = snapshot(&runtime);
        let response = exec_raw(
            &mut runtime,
            &clock,
            event_sequence_complete(10, 0x8000_0000, b"def"),
        );
        assert_eq!(&response[6..10], TPM_RC_FAILURE.to_be_bytes());
        assert_unchanged(&runtime, &before);
    }

    fn corrupt_event_bank(runtime: &mut Tpm2Runtime, slot: usize, bank: usize) {
        let OwnedAnyObjectBody::Sequence(body) = &mut runtime.live.objects[slot].body else {
            panic!("a sequence body");
        };
        let states = body.states.as_mut().expect("an event sequence");
        states[bank].payload = None;
    }

    fn event_bank_states(runtime: &Tpm2Runtime, slot: usize) -> Vec<Option<ShaStatePayload>> {
        let OwnedAnyObjectBody::Sequence(body) = &runtime.live.objects[slot].body else {
            panic!("a sequence body");
        };
        body.states
            .as_ref()
            .expect("an event sequence")
            .iter()
            .map(|stored| restore_state(stored).map(|state| state.export()))
            .collect()
    }

    #[test]
    fn a_later_unreadable_event_bank_leaves_the_earlier_banks_untouched() {
        for bank in [1usize, HASH_STATE_COUNT - 1] {
            let clock = fresh_clock();
            let mut runtime = base_runtime(&clock);
            exec(
                &mut runtime,
                &clock,
                "N_START_EVENT",
                hash_sequence_start(&[], replay::TPM_ALG_NULL),
            );
            exec(
                &mut runtime,
                &clock,
                "N_EVENT_UPDATE",
                sequence_update(0x8000_0000, b"abc", &[]),
            );
            corrupt_event_bank(&mut runtime, 0, bank);

            let banks_before = event_bank_states(&runtime, 0);
            assert!(
                banks_before[0].is_some() && banks_before[bank].is_none(),
                "bank {bank} is the only unreadable one"
            );
            let before = snapshot(&runtime);

            let response = exec_raw(
                &mut runtime,
                &clock,
                sequence_update(0x8000_0000, b"def", &[]),
            );
            assert_eq!(
                &response[6..10],
                TPM_RC_FAILURE.to_be_bytes(),
                "bank {bank} fails the update"
            );
            assert_unchanged(&runtime, &before);
            assert!(
                event_bank_states(&runtime, 0)
                    .iter()
                    .zip(&banks_before)
                    .all(|(after, before)| after == before),
                "bank {bank}: an earlier bank absorbed the input before the failure"
            );
        }
    }

    #[test]
    fn an_unusable_pcr_bank_leaves_every_bank_and_the_sequence_alone() {
        let clock = fresh_clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "N_START_EVENT",
            hash_sequence_start(&[], replay::TPM_ALG_NULL),
        );
        runtime.live.pcrs[10].banks[2] = Some(vec![0u8; 7]);
        let before = snapshot(&runtime);
        let response = exec_raw(
            &mut runtime,
            &clock,
            event_sequence_complete(10, 0x8000_0000, b"def"),
        );
        assert_eq!(&response[6..10], TPM_RC_FAILURE.to_be_bytes());
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn a_ticket_self_test_failure_keeps_the_sequence_and_enters_failure_mode() {
        let clock = fresh_clock();
        let mut runtime = base_runtime(&clock);
        runtime.self_test = runtime.self_test.restarted();
        runtime.self_test.set_runner(fails_on_sha512);
        exec_raw(
            &mut runtime,
            &clock,
            hash_sequence_start(&[], TPM_ALG_SHA256),
        );
        exec_raw(
            &mut runtime,
            &clock,
            sequence_update(0x8000_0000, b"a longer safe buffer", &[]),
        );
        assert!(!runtime.failure_mode);
        let occupied_before: Vec<bool> = runtime
            .live
            .objects
            .iter()
            .map(|object| object.attributes & ATTR_OCCUPIED != 0)
            .collect();
        let response = exec_raw(
            &mut runtime,
            &clock,
            sequence_complete(0x8000_0000, b"a longer safe buffer", RH_OWNER, &[]),
        );
        assert_eq!(&response[6..10], TPM_RC_FAILURE.to_be_bytes());
        assert!(runtime.failure_mode, "the ticket self test fails hard");
        assert_eq!(
            runtime
                .live
                .objects
                .iter()
                .map(|object| object.attributes & ATTR_OCCUPIED != 0)
                .collect::<Vec<bool>>(),
            occupied_before,
            "the sequence handle is not released"
        );
    }

    #[test]
    fn a_failed_completion_keeps_the_sequence_usable() {
        let clock = fresh_clock();
        let mut runtime = started_hash_sequence(&clock);
        exec(
            &mut runtime,
            &clock,
            "A_UPDATE_ABC",
            sequence_update(0x8000_0000, b"abc", &[]),
        );
        let _ = exec_raw(
            &mut runtime,
            &clock,
            sequence_complete(0x8000_0000, b"abc", 0x4000_0005, &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "A_UPDATE_EMPTY",
            sequence_update(0x8000_0000, b"", &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "A_UPDATE_DEF",
            sequence_update(0x8000_0000, b"def", &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "A_COMPLETE_GHI",
            sequence_complete(0x8000_0000, b"ghi", RH_NULL, &[]),
        );
    }

    #[test]
    fn a_refused_authorization_leaves_the_sequence_and_the_da_counter_alone() {
        let clock = fresh_clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "H_START_AUTH",
            hash_sequence_start(b"sequence-auth", TPM_ALG_SHA256),
        );
        let before = snapshot(&runtime);
        exec(
            &mut runtime,
            &clock,
            "H_UPDATE_WRONG_AUTH",
            sequence_update(0x8000_0000, b"abc", b"wrong"),
        );
        assert_unchanged(&runtime, &before);
    }
}
