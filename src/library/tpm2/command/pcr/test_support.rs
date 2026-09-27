use crate::library::tpm2::runtime::Tpm2Runtime;

pub(super) struct Snapshot {
    failure_mode: bool,
    nv_update_pending: bool,
    orderly_state: u16,
    nv_memory: Box<[u8]>,
    pcr_counter: Option<u32>,
    pcr_banks: Vec<Vec<Option<Vec<u8>>>>,
    free_session_slots: u32,
    sessions_occupied: Vec<bool>,
}

pub(super) fn snapshot(runtime: &Tpm2Runtime) -> Snapshot {
    Snapshot {
        failure_mode: runtime.failure_mode,
        nv_update_pending: runtime.nv_update_pending,
        orderly_state: runtime.state.as_ref().unwrap().persistent.orderly_state,
        nv_memory: runtime.nv_memory.clone(),
        pcr_counter: runtime
            .live
            .state_reset
            .as_ref()
            .map(|reset| reset.pcr_counter),
        pcr_banks: runtime
            .live
            .pcrs
            .iter()
            .map(|pcr| pcr.banks.to_vec())
            .collect(),
        free_session_slots: runtime.live.free_session_slots,
        sessions_occupied: runtime
            .live
            .sessions
            .iter()
            .map(|slot| slot.occupied)
            .collect(),
    }
}

#[track_caller]
pub(super) fn assert_unchanged(runtime: &Tpm2Runtime, before: &Snapshot) {
    let now = snapshot(runtime);
    assert_eq!(now.failure_mode, before.failure_mode);
    assert_eq!(now.nv_update_pending, before.nv_update_pending);
    assert_eq!(now.orderly_state, before.orderly_state);
    assert_eq!(now.nv_memory, before.nv_memory);
    assert_eq!(now.pcr_counter, before.pcr_counter);
    assert_eq!(now.pcr_banks, before.pcr_banks);
    assert_eq!(now.free_session_slots, before.free_session_slots);
    assert_eq!(now.sessions_occupied, before.sessions_occupied);
}

#[track_caller]
pub(super) fn bank(runtime: &Tpm2Runtime, pcr: usize, slot: usize) -> Vec<u8> {
    runtime.live.pcrs[pcr].banks[slot]
        .clone()
        .expect("an allocated bank")
}

pub(super) fn pcr_counter(runtime: &Tpm2Runtime) -> u32 {
    runtime.live.state_reset.as_ref().unwrap().pcr_counter
}
