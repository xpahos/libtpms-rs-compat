// Part of the Rust port of libtpms.
//
// Project licensing and upstream notices: LICENSE and LICENSES/README.md.
//
// Rust implementation:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use crate::library::constants::TPM_RC_FAILURE;
use crate::library::tpm2::clock::{RuntimeClock, TpmTimer};
use crate::library::tpm2::live::{LiveState, RestoredVolatile};
use crate::library::tpm2::nv::build_nv_image;
use crate::library::tpm2::persistent::{
    OwnedPcrAllocation, OwnedPersistentData, OwnedPersistentState,
};
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::types::TpmResult;
pub(in crate::library::tpm2::command) struct CommandTransaction {
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

pub(in crate::library::tpm2::command) fn begin(runtime: &Tpm2Runtime) -> CommandTransaction {
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

pub(in crate::library::tpm2::command) fn roll_back(
    runtime: &mut Tpm2Runtime,
    transaction: CommandTransaction,
) {
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

pub(in crate::library::tpm2::command) fn with_persistent_rollback(
    runtime: &mut Tpm2Runtime,
    apply: impl FnOnce(&mut OwnedPersistentData) -> Result<(), TpmResult>,
) -> Result<(), TpmResult> {
    let state = runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?;
    let backup = state.persistent.clone();
    let result = apply(&mut state.persistent)
        .and_then(|()| build_nv_image(state).map_err(|_| TPM_RC_FAILURE));
    match result {
        Ok(image) => {
            runtime.nv_memory = image;
            runtime.nv_update_pending = true;
            Ok(())
        }
        Err(code) => {
            state.persistent = backup;
            Err(code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::constants::TPM_RC_VALUE;
    use crate::library::tpm2::command::core::test_support::manufactured_runtime;
    use crate::library::tpm2::persistent::{OwnedSecret, persistent_all_store};

    #[test]
    fn persistent_mutation_error_restores_state() {
        for pending in [false, true] {
            let mut runtime = manufactured_runtime();
            runtime.nv_update_pending = pending;
            let before = persistent_all_store(runtime.state()).expect("state serializes");
            let nv_before = runtime.nv_memory.clone();

            let result = with_persistent_rollback(&mut runtime, |persistent| {
                persistent.algorithm_set = 9;
                persistent.owner_auth = OwnedSecret::from_vec(b"changed".to_vec());
                Err::<(), _>(TPM_RC_VALUE)
            });

            assert_eq!(result, Err(TPM_RC_VALUE));
            assert_eq!(
                persistent_all_store(runtime.state()).expect("state serializes"),
                before,
                "a rejected mutation restores all persistent fields"
            );
            assert_eq!(runtime.nv_memory, nv_before);
            assert_eq!(runtime.nv_update_pending, pending);
        }
    }

    #[test]
    fn persistent_image_error_restores_state() {
        for pending in [false, true] {
            let mut runtime = manufactured_runtime();
            runtime.nv_update_pending = pending;
            let before = persistent_all_store(runtime.state()).expect("state serializes");
            let nv_before = runtime.nv_memory.clone();

            let result = with_persistent_rollback(&mut runtime, |persistent| {
                persistent.algorithm_set = 9;
                persistent.owner_auth = OwnedSecret::from_vec(vec![0xaa; 4096]);
                Ok(())
            });

            assert_eq!(result, Err(TPM_RC_FAILURE));
            assert_eq!(
                persistent_all_store(runtime.state()).expect("state serializes"),
                before,
                "an unencodable mutation restores all persistent fields"
            );
            assert_eq!(runtime.nv_memory, nv_before);
            assert_eq!(runtime.nv_update_pending, pending);
        }
    }
}
