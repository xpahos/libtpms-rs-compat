// Part of the Rust port of libtpms.
//
// Upstream behavior references for this Rust implementation:
// - libtpms/src/tpm2/Global.c
// - libtpms/src/tpm2/Global.h
// - libtpms/src/tpm2/Manufacture.c
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust implementation:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use super::clock::RuntimeClock;
use super::hierarchy::TPM_RH_UNASSIGNED;
use super::nv::OrderlyRamImage;
use super::pcr::PCR_SLOT_BANKS;
use super::persistent::{
    OwnedAnyObject, OwnedAnyObjectBody, OwnedDrbgState, OwnedOrderlyData, OwnedPersistentState,
    OwnedSecret, OwnedStateClearData, OwnedStateResetData,
};
use super::runtime::{FailureDiagnostics, NV_MEMORY_SIZE};
use super::volatile::{
    IMPLEMENTATION_PCR, MAX_LOADED_OBJECTS, MAX_LOADED_SESSIONS, MAX_SESSION_NUM, OwnedPcr,
    OwnedSessionProcess, OwnedSessionSlot, OwnedVolatileState, TailV4,
};
use crate::library::tpm2::state::{COMMIT_ARRAY_SIZE, MAX_ACTIVE_SESSIONS};

const SEED_COMPAT_LEVEL_ORIGINAL: u8 = 0;

pub(super) const CLOCK_NOMINAL: u32 = 30_000;

#[derive(Clone, Debug)]
pub(super) struct LiveState {
    pub(super) ph_enable: bool,
    pub(super) startup_locality3: bool,
    pub(super) prev_orderly_state: u16,
    pub(super) power_was_lost: bool,
    pub(super) drtm_pre_startup: bool,
    pub(super) da_used: bool,
    pub(super) da_pending_on_nv: bool,
    pub(super) pcr_reconfig: bool,
    pub(super) pcrs: Vec<OwnedPcr>,
    pub(super) sessions: Vec<OwnedSessionSlot>,
    pub(super) free_session_slots: u32,
    pub(super) oldest_saved_session: u32,
    pub(super) objects: Vec<OwnedAnyObject>,
    pub(super) context_slot_mask: u16,
    pub(super) null_seed_compat_level: u8,
    pub(super) index_orderly_ram: OrderlyRamImage,
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
            banks: core::array::from_fn(|slot| Some(vec![0u8; PCR_SLOT_BANKS[slot].1])),
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

pub(super) fn power_on_state_clear() -> OwnedStateClearData {
    OwnedStateClearData {
        sh_enable: false,
        eh_enable: false,
        ph_enable_nv: false,
        platform_alg: 0,
        platform_policy: Vec::new(),
        platform_auth: OwnedSecret::from_vec(Vec::new()),
        pcr_save: core::array::from_fn(|_| None),
        pcr_auth_values: core::array::from_fn(|_| OwnedSecret::from_vec(Vec::new())),
    }
}

pub(super) fn power_on_state_reset() -> OwnedStateResetData {
    OwnedStateResetData {
        null_proof: OwnedSecret::from_vec(Vec::new()),
        null_seed: OwnedSecret::from_vec(Vec::new()),
        clear_count: 0,
        object_context_id: 0,
        context_array: Box::new([0u16; MAX_ACTIVE_SESSIONS]),
        context_slot_mask: 0xffff,
        context_counter: 0,
        command_audit_digest: Vec::new(),
        restart_count: 0,
        pcr_counter: 0,
        commit_counter: 0,
        commit_nonce: OwnedSecret::from_vec(Vec::new()),
        commit_array: [0u8; COMMIT_ARRAY_SIZE],
        null_seed_compat_level: SEED_COMPAT_LEVEL_ORIGINAL,
    }
}

fn empty_session_process() -> OwnedSessionProcess {
    OwnedSessionProcess {
        session_handles: [0; MAX_SESSION_NUM],
        attributes: [0; MAX_SESSION_NUM],
        associated_handles: [0; MAX_SESSION_NUM],
        nonce_callers: core::array::from_fn(|_| OwnedSecret::from_vec(Vec::new())),
        input_auth_values: core::array::from_fn(|_| OwnedSecret::from_vec(Vec::new())),
        encrypt_session_index: 0,
        decrypt_session_index: 0,
        audit_session_index: 0,
        cp_hash_for_command_audit: Vec::new(),
        da_pending_on_nv: false,
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
            da_pending_on_nv: false,
            pcr_reconfig: false,
            pcrs: empty_pcrs(),
            sessions: unoccupied_sessions(),
            free_session_slots: 0,
            oldest_saved_session: 0,
            objects: unoccupied_objects(),
            context_slot_mask: 0xffff,
            null_seed_compat_level: SEED_COMPAT_LEVEL_ORIGINAL,
            index_orderly_ram: OrderlyRamImage::zeroed(),
            max_nv_counter: 0,
            orderly: empty_orderly_data(),
            state_reset: None,
            state_clear: None,
            nv_ok: true,
        }
    }

    pub(super) fn power_on_with_state_reset(state: &OwnedPersistentState) -> Self {
        let mut live = Self::power_on();
        if let Some(reset) = state.state_reset.as_ref() {
            live.context_slot_mask = reset.context_slot_mask;
        }
        live
    }
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(super) struct RestoredVolatile {
    pub(super) header_version: u16,
    pub(super) exclusive_audit_session: u32,
    pub(super) time: u64,
    pub(super) drtm_handle: u32,
    pub(super) session_process: OwnedSessionProcess,
    pub(super) evict_nv_end: u32,
    pub(super) max_counter: u64,
    pub(super) real_time_previous: u64,
    pub(super) tpm_time: u64,
    pub(super) timer_reset: bool,
    pub(super) timer_stopped: bool,
    pub(super) adjust_rate: u32,
    pub(super) backthen: u64,
    pub(super) times_are_realtime: bool,
    pub(super) tail_v4: Option<TailV4>,
}

impl RestoredVolatile {
    pub(super) fn power_on() -> Self {
        Self {
            header_version: 0,
            exclusive_audit_session: 0,
            time: 0,
            drtm_handle: TPM_RH_UNASSIGNED,
            session_process: empty_session_process(),
            evict_nv_end: NV_MEMORY_SIZE as u32,
            max_counter: 0,
            real_time_previous: 0,
            tpm_time: 0,
            timer_reset: true,
            timer_stopped: true,
            adjust_rate: CLOCK_NOMINAL,
            backthen: 0,
            times_are_realtime: false,
            tail_v4: None,
        }
    }
}

pub(super) struct RestoredRuntimeFlags {
    pub(super) manufactured: bool,
    pub(super) initialized: bool,
    pub(super) in_failure_mode: bool,
    pub(super) tpm_established: bool,
    pub(super) failure_diagnostics: FailureDiagnostics,
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
        ep_seed: _,
        sp_seed: _,
        pp_seed: _,
        object_version: _,
    } = volatile;

    let live = LiveState {
        ph_enable,
        startup_locality3,
        prev_orderly_state,
        power_was_lost,
        drtm_pre_startup,
        da_used,
        da_pending_on_nv: session_process.da_pending_on_nv,
        pcr_reconfig,
        pcrs,
        sessions,
        free_session_slots,
        oldest_saved_session,
        objects,
        context_slot_mask: state_reset.context_slot_mask,
        null_seed_compat_level: state_reset.null_seed_compat_level,
        index_orderly_ram: OrderlyRamImage::from_bytes(&index_orderly_ram)
            .unwrap_or_else(OrderlyRamImage::zeroed),
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
        tpm_established,
        failure_diagnostics: FailureDiagnostics {
            function: fail_function,
            line: fail_line,
            code: fail_code,
        },
        resume_clock,
    };

    let carry = RestoredVolatile {
        header_version,
        exclusive_audit_session,
        time,
        drtm_handle,
        session_process,
        evict_nv_end,
        max_counter,
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
