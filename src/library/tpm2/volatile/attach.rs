use crate::ffi_types::TpmResult;
use crate::library::constants::TPM_FAIL;

use super::{
    DecodedVolatileState, IMPLEMENTATION_PCR, MAX_LOADED_OBJECTS, MAX_LOADED_SESSIONS,
    MAX_SESSION_NUM, RAM_INDEX_SPACE, SeedTie, SessionProcess, TailV4,
};
use crate::library::tpm2::clock::RuntimeClock;
use crate::library::tpm2::object::{ATTR_HMAC_SEQ, ATTR_OCCUPIED, AnyObjectBody, HASH_STATE_SMAC};
use crate::library::tpm2::pcr::PCR_SLOT_BANKS;
use crate::library::tpm2::persistent::{
    OwnedAnyObject, OwnedOrderlyData, OwnedSecret, OwnedStateClearData, OwnedStateResetData,
    own_any_object, own_orderly_data, own_state_clear, own_state_reset,
};
use crate::library::tpm2::public::SymDefObject;
use crate::library::tpm2::session::{Session, SessionSlot};

fn resumable_sequence(attributes: u32, body: &AnyObjectBody<'_>) -> bool {
    if attributes & (ATTR_OCCUPIED | ATTR_HMAC_SEQ) != ATTR_OCCUPIED | ATTR_HMAC_SEQ {
        return true;
    }
    let AnyObjectBody::Sequence(sequence) = body else {
        return true;
    };
    sequence
        .hmac_state
        .as_ref()
        .is_none_or(|(state, _)| state.state_type != HASH_STATE_SMAC)
}

#[derive(Clone)]
#[allow(dead_code)]
pub(in crate::library::tpm2) struct OwnedSession {
    pub(in crate::library::tpm2) attributes: u32,
    pub(in crate::library::tpm2) pcr_counter: u32,
    pub(in crate::library::tpm2) start_time: u64,
    pub(in crate::library::tpm2) timeout: u64,
    pub(in crate::library::tpm2) epoch: u32,
    pub(in crate::library::tpm2) command_code: u32,
    pub(in crate::library::tpm2) auth_hash_alg: u16,
    pub(in crate::library::tpm2) command_locality: u8,
    pub(in crate::library::tpm2) symmetric: SymDefObject,
    pub(in crate::library::tpm2) session_key: OwnedSecret,
    pub(in crate::library::tpm2) nonce_tpm: OwnedSecret,
    pub(in crate::library::tpm2) bound_entity: Vec<u8>,
    pub(in crate::library::tpm2) audit_digest: Vec<u8>,
}

impl core::fmt::Debug for OwnedSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OwnedSession")
            .field("attributes", &format_args!("{:#010x}", self.attributes))
            .field("command_code", &self.command_code)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(in crate::library::tpm2) struct OwnedSessionSlot {
    pub(in crate::library::tpm2) occupied: bool,
    pub(in crate::library::tpm2) session: Option<OwnedSession>,
}

#[derive(Clone)]
#[allow(dead_code)]
pub(in crate::library::tpm2) struct OwnedSessionProcess {
    pub(in crate::library::tpm2) session_handles: [u32; MAX_SESSION_NUM],
    pub(in crate::library::tpm2) attributes: [u8; MAX_SESSION_NUM],
    pub(in crate::library::tpm2) associated_handles: [u32; MAX_SESSION_NUM],
    pub(in crate::library::tpm2) nonce_callers: [OwnedSecret; MAX_SESSION_NUM],
    pub(in crate::library::tpm2) input_auth_values: [OwnedSecret; MAX_SESSION_NUM],
    pub(in crate::library::tpm2) encrypt_session_index: u32,
    pub(in crate::library::tpm2) decrypt_session_index: u32,
    pub(in crate::library::tpm2) audit_session_index: u32,
    pub(in crate::library::tpm2) cp_hash_for_command_audit: Vec<u8>,
    pub(in crate::library::tpm2) da_pending_on_nv: bool,
}

impl core::fmt::Debug for OwnedSessionProcess {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OwnedSessionProcess")
            .field("session_handles", &self.session_handles)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(in crate::library::tpm2) struct OwnedPcr {
    pub(in crate::library::tpm2) banks: [Option<Vec<u8>>; PCR_SLOT_BANKS.len()],
}

#[derive(Debug)]
#[allow(dead_code)]
pub(in crate::library::tpm2) struct OwnedVolatileState {
    pub(in crate::library::tpm2) header_version: u16,
    pub(in crate::library::tpm2) exclusive_audit_session: u32,
    pub(in crate::library::tpm2) time: u64,
    pub(in crate::library::tpm2) ph_enable: bool,
    pub(in crate::library::tpm2) pcr_reconfig: bool,
    pub(in crate::library::tpm2) drtm_handle: u32,
    pub(in crate::library::tpm2) drtm_pre_startup: bool,
    pub(in crate::library::tpm2) startup_locality3: bool,
    pub(in crate::library::tpm2) da_used: bool,
    pub(in crate::library::tpm2) power_was_lost: bool,
    pub(in crate::library::tpm2) prev_orderly_state: u16,
    pub(in crate::library::tpm2) nv_ok: bool,
    pub(in crate::library::tpm2) orderly: OwnedOrderlyData,
    pub(in crate::library::tpm2) state_clear: OwnedStateClearData,
    pub(in crate::library::tpm2) state_reset: OwnedStateResetData,
    pub(in crate::library::tpm2) manufactured: bool,
    pub(in crate::library::tpm2) initialized: bool,
    pub(in crate::library::tpm2) session_process: OwnedSessionProcess,
    pub(in crate::library::tpm2) evict_nv_end: u32,
    pub(in crate::library::tpm2) index_orderly_ram: Vec<u8>,
    pub(in crate::library::tpm2) max_counter: u64,
    pub(in crate::library::tpm2) objects: Vec<OwnedAnyObject>,
    pub(in crate::library::tpm2) pcrs: Vec<OwnedPcr>,
    pub(in crate::library::tpm2) sessions: Vec<OwnedSessionSlot>,
    pub(in crate::library::tpm2) oldest_saved_session: u32,
    pub(in crate::library::tpm2) free_session_slots: u32,
    pub(in crate::library::tpm2) in_failure_mode: bool,
    pub(in crate::library::tpm2) tpm_established: bool,
    pub(in crate::library::tpm2) fail_function: u32,
    pub(in crate::library::tpm2) fail_line: u32,
    pub(in crate::library::tpm2) fail_code: u32,
    pub(in crate::library::tpm2) real_time_previous: u64,
    pub(in crate::library::tpm2) tpm_time: u64,
    pub(in crate::library::tpm2) timer_reset: bool,
    pub(in crate::library::tpm2) timer_stopped: bool,
    pub(in crate::library::tpm2) adjust_rate: u32,
    pub(in crate::library::tpm2) backthen: u64,
    pub(in crate::library::tpm2) times_are_realtime: bool,
    pub(in crate::library::tpm2) tail_v4: Option<TailV4>,
    pub(in crate::library::tpm2) resume_clock: RuntimeClock,
    pub(in crate::library::tpm2) ep_seed: OwnedSecret,
    pub(in crate::library::tpm2) sp_seed: OwnedSecret,
    pub(in crate::library::tpm2) pp_seed: OwnedSecret,
    pub(in crate::library::tpm2) object_version: u16,
}

fn own_session(session: &Session<'_>) -> OwnedSession {
    OwnedSession {
        attributes: session.attributes,
        pcr_counter: session.pcr_counter,
        start_time: session.start_time,
        timeout: session.timeout,
        epoch: session.epoch,
        command_code: session.command_code,
        auth_hash_alg: session.auth_hash_alg,
        command_locality: session.command_locality,
        symmetric: session.symmetric,
        session_key: OwnedSecret::copy_of(session.session_key),
        nonce_tpm: OwnedSecret::copy_of(session.nonce_tpm),
        bound_entity: session.bound_entity.to_vec(),
        audit_digest: session.audit_digest.to_vec(),
    }
}

fn own_session_slot(slot: &SessionSlot<'_>) -> Result<OwnedSessionSlot, TpmResult> {
    if slot.occupied != slot.session.is_some() {
        return Err(TPM_FAIL);
    }
    Ok(OwnedSessionSlot {
        occupied: slot.occupied,
        session: slot.session.as_ref().map(own_session),
    })
}

fn own_session_process(process: &SessionProcess<'_>) -> OwnedSessionProcess {
    OwnedSessionProcess {
        session_handles: process.session_handles,
        attributes: process.attributes,
        associated_handles: process.associated_handles,
        nonce_callers: core::array::from_fn(|index| {
            OwnedSecret::copy_of(process.nonce_callers[index])
        }),
        input_auth_values: core::array::from_fn(|index| {
            OwnedSecret::copy_of(process.input_auth_values[index])
        }),
        encrypt_session_index: process.encrypt_session_index,
        decrypt_session_index: process.decrypt_session_index,
        audit_session_index: process.audit_session_index,
        cp_hash_for_command_audit: process.cp_hash_for_command_audit.to_vec(),
        da_pending_on_nv: process.da_pending_on_nv,
    }
}

pub(in crate::library::tpm2) fn materialize_volatile_state(
    decoded: &DecodedVolatileState<'_>,
    seeds: SeedTie<'_>,
    object_version: u16,
) -> Result<OwnedVolatileState, TpmResult> {
    if decoded.objects.len() != MAX_LOADED_OBJECTS
        || decoded.pcrs.len() != IMPLEMENTATION_PCR
        || decoded.sessions.len() != MAX_LOADED_SESSIONS
        || decoded.index_orderly_ram.len() != RAM_INDEX_SPACE
    {
        return Err(TPM_FAIL);
    }
    for pcr in &decoded.pcrs {
        for (bank, &(_, expected)) in pcr.banks.iter().zip(PCR_SLOT_BANKS.iter()) {
            if bank.is_some_and(|digest| digest.len() != expected) {
                return Err(TPM_FAIL);
            }
        }
    }

    for object in &decoded.objects {
        if !resumable_sequence(object.attributes, &object.body) {
            return Err(TPM_FAIL);
        }
    }

    let sessions = decoded
        .sessions
        .iter()
        .map(own_session_slot)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(OwnedVolatileState {
        header_version: decoded.header_version,
        exclusive_audit_session: decoded.exclusive_audit_session,
        time: decoded.time,
        ph_enable: decoded.ph_enable,
        pcr_reconfig: decoded.pcr_reconfig,
        drtm_handle: decoded.drtm_handle,
        drtm_pre_startup: decoded.drtm_pre_startup,
        startup_locality3: decoded.startup_locality3,
        da_used: decoded.da_used,
        power_was_lost: decoded.power_was_lost,
        prev_orderly_state: decoded.prev_orderly_state,
        nv_ok: decoded.nv_ok,
        orderly: own_orderly_data(&decoded.orderly),
        state_clear: own_state_clear(&decoded.state_clear),
        state_reset: own_state_reset(&decoded.state_reset),
        manufactured: decoded.manufactured,
        initialized: decoded.initialized,
        session_process: own_session_process(&decoded.session_process),
        evict_nv_end: decoded.evict_nv_end,
        index_orderly_ram: decoded.index_orderly_ram.to_vec(),
        max_counter: decoded.max_counter,
        objects: decoded.objects.iter().map(own_any_object).collect(),
        pcrs: decoded
            .pcrs
            .iter()
            .map(|pcr| OwnedPcr {
                banks: core::array::from_fn(|index| pcr.banks[index].map(<[u8]>::to_vec)),
            })
            .collect(),
        sessions,
        oldest_saved_session: decoded.oldest_saved_session,
        free_session_slots: decoded.free_session_slots,
        in_failure_mode: decoded.in_failure_mode,
        tpm_established: decoded.tpm_established,
        fail_function: decoded.fail_function,
        fail_line: decoded.fail_line,
        fail_code: decoded.fail_code,
        real_time_previous: decoded.real_time_previous,
        tpm_time: decoded.tpm_time,
        timer_reset: decoded.timer_reset,
        timer_stopped: decoded.timer_stopped,
        adjust_rate: decoded.adjust_rate,
        backthen: decoded.backthen,
        times_are_realtime: decoded.times_are_realtime,
        tail_v4: decoded.tail_v4,
        resume_clock: decoded.resume_clock,
        ep_seed: OwnedSecret::copy_of(seeds.ep_seed),
        sp_seed: OwnedSecret::copy_of(seeds.sp_seed),
        pp_seed: OwnedSecret::copy_of(seeds.pp_seed),
        object_version,
    })
}

#[cfg(test)]
mod tests {
    use super::super::super::public::StateFormatLimit;
    use super::super::store::CURRENT_OBJECT_VERSION;
    use super::super::{VolatileFixture, parse_volatile_state_blob};
    use super::*;
    use crate::library::tpm2::clock::RecordingClock;

    fn test_clock() -> RecordingClock {
        RecordingClock::new(1_600_000_500_000, 7_000_000)
    }

    fn decode_and_materialize(blob: &[u8]) -> OwnedVolatileState {
        let decoded = parse_volatile_state_blob(
            blob,
            &[],
            VolatileFixture::seed_tie(),
            &test_clock(),
            StateFormatLimit::CURRENT,
        )
        .expect("decodes");
        materialize_volatile_state(
            &decoded,
            VolatileFixture::seed_tie(),
            CURRENT_OBJECT_VERSION,
        )
        .expect("materializes")
    }

    #[test]
    fn candidate_survives_dropping_the_input_blob() {
        let candidate = {
            let blob = VolatileFixture::default().bytes();
            decode_and_materialize(&blob)
        };
        assert_eq!(candidate.time, 987_654);
        assert_eq!(candidate.index_orderly_ram.len(), RAM_INDEX_SPACE);
        assert_eq!(candidate.index_orderly_ram[7], 7);
        assert!(candidate.sessions[0].occupied);
        assert_eq!(
            candidate.sessions[0]
                .session
                .as_ref()
                .unwrap()
                .session_key
                .expose(),
            &[0x33; 32][..]
        );
        assert_eq!(
            candidate.session_process.nonce_callers[0].expose(),
            &[0x21; 16][..]
        );
        assert!(candidate.tail_v4.is_some());
    }

    #[test]
    fn candidate_debug_output_never_contains_secret_bytes() {
        let mut fixture = VolatileFixture::default();
        fixture.session_entries[0].3 = b"caller-nonce-mrk".to_vec();
        fixture.session_entries[0].4 = b"input-auth-mark!".to_vec();
        fixture.session_slots[0] = crate::library::tpm2::session::SessionSlotFixture {
            occupied: 1,
            session: crate::library::tpm2::session::SessionFixture {
                session_key: b"session-key-mark".to_vec(),
                nonce_tpm: b"nonce-tpm-mark!!".to_vec(),
                ..crate::library::tpm2::session::SessionFixture::default()
            }
            .bytes(),
            ..crate::library::tpm2::session::SessionSlotFixture::default()
        }
        .bytes();
        let blob = fixture.bytes();
        let candidate = decode_and_materialize(&blob);
        let formatted = format!("{candidate:?}");
        for secret in [
            "caller-nonce-mrk",
            "input-auth-mark!",
            "session-key-mark",
            "nonce-tpm-mark!!",
        ] {
            assert!(
                !formatted.contains(secret),
                "candidate Debug must not contain {secret:?}: {formatted}"
            );
        }
    }

    #[test]
    fn inconsistent_counts_are_rejected_transactionally() {
        let blob = VolatileFixture::default().bytes();
        let decoded = parse_volatile_state_blob(
            &blob,
            &[],
            VolatileFixture::seed_tie(),
            &test_clock(),
            StateFormatLimit::CURRENT,
        )
        .expect("decodes");

        let mut mutated = decoded;
        mutated.objects.pop();
        assert_eq!(
            materialize_volatile_state(
                &mutated,
                VolatileFixture::seed_tie(),
                CURRENT_OBJECT_VERSION
            )
            .unwrap_err(),
            TPM_FAIL
        );

        let decoded = parse_volatile_state_blob(
            &blob,
            &[],
            VolatileFixture::seed_tie(),
            &test_clock(),
            StateFormatLimit::CURRENT,
        )
        .expect("decodes");
        let mut mutated = decoded;
        mutated.pcrs.pop();
        assert_eq!(
            materialize_volatile_state(
                &mutated,
                VolatileFixture::seed_tie(),
                CURRENT_OBJECT_VERSION
            )
            .unwrap_err(),
            TPM_FAIL
        );

        let decoded = parse_volatile_state_blob(
            &blob,
            &[],
            VolatileFixture::seed_tie(),
            &test_clock(),
            StateFormatLimit::CURRENT,
        )
        .expect("decodes");
        let mut mutated = decoded;
        mutated.sessions.pop();
        assert_eq!(
            materialize_volatile_state(
                &mutated,
                VolatileFixture::seed_tie(),
                CURRENT_OBJECT_VERSION
            )
            .unwrap_err(),
            TPM_FAIL
        );

        let decoded = parse_volatile_state_blob(
            &blob,
            &[],
            VolatileFixture::seed_tie(),
            &test_clock(),
            StateFormatLimit::CURRENT,
        )
        .expect("decodes");
        let mut mutated = decoded;
        mutated.index_orderly_ram = &mutated.index_orderly_ram[..500];
        assert_eq!(
            materialize_volatile_state(
                &mutated,
                VolatileFixture::seed_tie(),
                CURRENT_OBJECT_VERSION
            )
            .unwrap_err(),
            TPM_FAIL
        );
    }

    #[test]
    fn contradictory_session_slot_is_rejected() {
        let blob = VolatileFixture::default().bytes();
        let mut decoded = parse_volatile_state_blob(
            &blob,
            &[],
            VolatileFixture::seed_tie(),
            &test_clock(),
            StateFormatLimit::CURRENT,
        )
        .expect("decodes");
        decoded.sessions[0].occupied = false;
        assert_eq!(
            materialize_volatile_state(
                &decoded,
                VolatileFixture::seed_tie(),
                CURRENT_OBJECT_VERSION
            )
            .unwrap_err(),
            TPM_FAIL
        );
    }
}
