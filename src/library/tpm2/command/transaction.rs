use crate::ffi_types::TpmResult;
use crate::library::constants::TPM_RC_FAILURE;

use super::super::clock::{RuntimeClock, TpmTimer};
use super::super::live::{LiveState, RestoredVolatile};
use super::super::nv::build_nv_image;
use super::super::persistent::{OwnedPcrAllocation, OwnedPersistentState};
use super::super::runtime::Tpm2Runtime;

pub(super) struct CommandTransaction {
    state: Option<OwnedPersistentState>,
    live: LiveState,
    restored_volatile: Option<RestoredVolatile>,
    shadow_pcr_allocated: OwnedPcrAllocation,
    shadow_pcr_pending: bool,
    live_pcr_allocated: Option<OwnedPcrAllocation>,
    nv_memory: Box<[u8]>,
    nv_update_pending: bool,
    tpm_established: bool,
    clock: RuntimeClock,
    timer: TpmTimer,
    removed_session_associations: Vec<u32>,
}

pub(super) fn begin(runtime: &Tpm2Runtime) -> CommandTransaction {
    CommandTransaction {
        state: runtime.state.clone(),
        live: runtime.live.clone(),
        restored_volatile: runtime.restored_volatile.clone(),
        shadow_pcr_allocated: runtime.shadow_pcr_allocated.clone(),
        shadow_pcr_pending: runtime.shadow_pcr_pending,
        live_pcr_allocated: runtime.live_pcr_allocated.clone(),
        nv_memory: runtime.nv_memory.clone(),
        nv_update_pending: runtime.nv_update_pending,
        tpm_established: runtime.tpm_established,
        clock: runtime.clock,
        timer: runtime.timer,
        removed_session_associations: runtime.removed_session_associations.clone(),
    }
}

pub(super) fn roll_back(runtime: &mut Tpm2Runtime, transaction: CommandTransaction) {
    let drbg_state = runtime.live.orderly.drbg_state.clone();
    runtime.state = transaction.state;
    runtime.live = transaction.live;
    runtime.live.orderly.drbg_state = drbg_state;
    runtime.restored_volatile = transaction.restored_volatile;
    runtime.shadow_pcr_allocated = transaction.shadow_pcr_allocated;
    runtime.shadow_pcr_pending = transaction.shadow_pcr_pending;
    runtime.live_pcr_allocated = transaction.live_pcr_allocated;
    runtime.nv_memory = transaction.nv_memory;
    runtime.nv_update_pending = transaction.nv_update_pending;
    runtime.tpm_established = transaction.tpm_established;
    runtime.clock = transaction.clock;
    runtime.timer = transaction.timer;
    runtime.removed_session_associations = transaction.removed_session_associations;
}

pub(in crate::library::tpm2::command) fn commit_persistent_state(
    runtime: &mut Tpm2Runtime,
) -> Result<(), TpmResult> {
    let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
    let image = build_nv_image(state).map_err(|_| TPM_RC_FAILURE)?;
    runtime.nv_memory = image;
    runtime.nv_update_pending = true;
    Ok(())
}

pub(in crate::library::tpm2::command) fn with_rollback<F, T>(
    runtime: &mut Tpm2Runtime,
    apply: F,
) -> Result<T, TpmResult>
where
    F: FnOnce(&mut Tpm2Runtime) -> Result<T, TpmResult>,
{
    let backup = begin(runtime);
    match apply(runtime) {
        Ok(value) => Ok(value),
        Err(code) => {
            roll_back(runtime, backup);
            Err(code)
        }
    }
}
