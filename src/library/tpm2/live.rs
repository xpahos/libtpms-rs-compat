use super::clock::RuntimeClock;
use super::nv::RAM_INDEX_SPACE;
use super::persistent::{
    OwnedAnyObject, OwnedAnyObjectBody, OwnedDrbgState, OwnedIndexOrderlyRam, OwnedOrderlyData,
    OwnedSecret, OwnedStateClearData, OwnedStateResetData,
};
use super::volatile::{
    IMPLEMENTATION_PCR, MAX_LOADED_OBJECTS, MAX_LOADED_SESSIONS, OwnedPcr, OwnedSessionProcess,
    OwnedSessionSlot, OwnedVolatileState, TailV4,
};
use crate::library::tpm2::state::MAX_ACTIVE_SESSIONS;

const SEED_COMPAT_LEVEL_ORIGINAL: u8 = 0;

#[derive(Debug)]
pub(super) struct LiveState {
    pub(super) ph_enable: bool,
    pub(super) startup_locality3: bool,
    pub(super) prev_orderly_state: u16,
    pub(super) power_was_lost: bool,
    pub(super) drtm_pre_startup: bool,
    pub(super) da_used: bool,
    pub(super) pcr_reconfig: bool,
    pub(super) pcrs: Vec<OwnedPcr>,
    pub(super) sessions: Vec<OwnedSessionSlot>,
    pub(super) free_session_slots: u32,
    pub(super) oldest_saved_session: u32,
    pub(super) objects: Vec<OwnedAnyObject>,
    pub(super) context_slot_mask: u16,
    pub(super) null_seed_compat_level: u8,
    pub(super) index_orderly_ram: OwnedIndexOrderlyRam,
    pub(super) max_nv_counter: u64,
    pub(super) orderly: OwnedOrderlyData,
    pub(super) state_reset: Option<OwnedStateResetData>,
    pub(super) state_clear: Option<OwnedStateClearData>,
    pub(super) nv_ok: bool,
}

pub(super) fn unoccupied_sessions() -> Vec<OwnedSessionSlot> {
    (0..MAX_LOADED_SESSIONS)
        .map(|_| OwnedSessionSlot {
            occupied: false,
            session: None,
        })
        .collect()
}

pub(super) fn unoccupied_objects() -> Vec<OwnedAnyObject> {
    (0..MAX_LOADED_OBJECTS)
        .map(|_| OwnedAnyObject {
            attributes: 0,
            body: OwnedAnyObjectBody::Unoccupied,
        })
        .collect()
}

pub(super) fn empty_pcrs() -> Vec<OwnedPcr> {
    (0..IMPLEMENTATION_PCR)
        .map(|_| OwnedPcr {
            banks: core::array::from_fn(|_| None),
        })
        .collect()
}

fn empty_orderly_data() -> OwnedOrderlyData {
    OwnedOrderlyData {
        clock: 0,
        clock_safe: 1,
        drbg_state: OwnedDrbgState {
            reseed_counter: 0,
            drbg_magic: 0,
            seed: OwnedSecret::from_vec(Vec::new()),
            last_value: [0; 4],
        },
        self_heal_timer: 0,
        lockout_timer: 0,
        time: 0,
    }
}

pub(super) fn empty_index_orderly_ram() -> OwnedIndexOrderlyRam {
    OwnedIndexOrderlyRam {
        sourceside_size: RAM_INDEX_SPACE as u32,
        entries: Vec::new(),
        terminated: true,
        used_bytes: 0,
    }
}

impl LiveState {
    pub(super) fn power_on() -> Self {
        Self {
            ph_enable: false,
            startup_locality3: false,
            prev_orderly_state: 0,
            power_was_lost: true,
            drtm_pre_startup: false,
            da_used: false,
            pcr_reconfig: false,
            pcrs: empty_pcrs(),
            sessions: unoccupied_sessions(),
            free_session_slots: MAX_LOADED_SESSIONS as u32,
            oldest_saved_session: MAX_ACTIVE_SESSIONS as u32 + 1,
            objects: unoccupied_objects(),
            context_slot_mask: 0xffff,
            null_seed_compat_level: SEED_COMPAT_LEVEL_ORIGINAL,
            index_orderly_ram: empty_index_orderly_ram(),
            max_nv_counter: 0,
            orderly: empty_orderly_data(),
            state_reset: None,
            state_clear: None,
            nv_ok: true,
        }
    }

    pub(super) fn power_on_with_state_reset(reset: Option<&OwnedStateResetData>) -> Self {
        let mut live = Self::power_on();
        if let Some(reset) = reset {
            live.context_slot_mask = reset.context_slot_mask;
            live.null_seed_compat_level = reset.null_seed_compat_level;
        }
        live
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub(super) struct RestoredVolatile {
    pub(super) header_version: u16,
    pub(super) exclusive_audit_session: u32,
    pub(super) time: u64,
    pub(super) drtm_handle: u32,
    pub(super) session_process: OwnedSessionProcess,
    pub(super) evict_nv_end: u32,
    pub(super) index_orderly_ram_bytes: Vec<u8>,
    pub(super) max_counter: u64,
    pub(super) tpm_established: bool,
    pub(super) fail_function: u32,
    pub(super) fail_line: u32,
    pub(super) fail_code: u32,
    pub(super) real_time_previous: u64,
    pub(super) tpm_time: u64,
    pub(super) timer_reset: bool,
    pub(super) timer_stopped: bool,
    pub(super) adjust_rate: u32,
    pub(super) backthen: u64,
    pub(super) times_are_realtime: bool,
    pub(super) tail_v4: Option<TailV4>,
}

pub(super) struct RestoredRuntimeFlags {
    pub(super) manufactured: bool,
    pub(super) initialized: bool,
    pub(super) in_failure_mode: bool,
    pub(super) resume_clock: RuntimeClock,
}

pub(super) fn split_restored_volatile(
    volatile: OwnedVolatileState,
) -> (LiveState, RestoredRuntimeFlags, RestoredVolatile) {
    let OwnedVolatileState {
        header_version,
        exclusive_audit_session,
        time,
        ph_enable,
        pcr_reconfig,
        drtm_handle,
        drtm_pre_startup,
        startup_locality3,
        da_used,
        power_was_lost,
        prev_orderly_state,
        nv_ok,
        orderly,
        state_clear,
        state_reset,
        manufactured,
        initialized,
        session_process,
        evict_nv_end,
        index_orderly_ram,
        max_counter,
        objects,
        pcrs,
        sessions,
        oldest_saved_session,
        free_session_slots,
        in_failure_mode,
        tpm_established,
        fail_function,
        fail_line,
        fail_code,
        real_time_previous,
        tpm_time,
        timer_reset,
        timer_stopped,
        adjust_rate,
        backthen,
        times_are_realtime,
        tail_v4,
        resume_clock,
    } = volatile;

    let live = LiveState {
        ph_enable,
        startup_locality3,
        prev_orderly_state,
        power_was_lost,
        drtm_pre_startup,
        da_used,
        pcr_reconfig,
        pcrs,
        sessions,
        free_session_slots,
        oldest_saved_session,
        objects,
        context_slot_mask: state_reset.context_slot_mask,
        null_seed_compat_level: state_reset.null_seed_compat_level,
        index_orderly_ram: empty_index_orderly_ram(),
        max_nv_counter: max_counter,
        orderly,
        state_reset: Some(state_reset),
        state_clear: Some(state_clear),
        nv_ok,
    };

    let flags = RestoredRuntimeFlags {
        manufactured,
        initialized,
        in_failure_mode,
        resume_clock,
    };

    let carry = RestoredVolatile {
        header_version,
        exclusive_audit_session,
        time,
        drtm_handle,
        session_process,
        evict_nv_end,
        index_orderly_ram_bytes: index_orderly_ram,
        max_counter,
        tpm_established,
        fail_function,
        fail_line,
        fail_code,
        real_time_previous,
        tpm_time,
        timer_reset,
        timer_stopped,
        adjust_rate,
        backthen,
        times_are_realtime,
        tail_v4,
    };

    (live, flags, carry)
}
