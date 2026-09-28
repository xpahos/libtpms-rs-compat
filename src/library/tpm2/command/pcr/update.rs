// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/IntegrityCommands.c
// - libtpms/src/tpm2/PCR.c
//
// Original upstream authors and copyright notices:
// Written by Ken Goldman
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corp. and others, 2016 - 2021
// (c) Copyright IBM Corp. and others, 2016 - 2023
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use crate::library::constants::TPM_RC_FAILURE;
use crate::library::tpm2::orderly::{commit_clear_orderly, prepare_clear_orderly};
use crate::library::tpm2::pcr::{pcr_in_tcb_group, pcr_is_state_saved};
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::types::TpmResult;
pub(in crate::library::tpm2::command) fn prepare_orderly_clear(
    runtime: &Tpm2Runtime,
    pcr: usize,
) -> Result<Option<u16>, TpmResult> {
    runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
    if !pcr_is_state_saved(pcr) {
        return Ok(None);
    }
    prepare_clear_orderly(runtime)
}

pub(in crate::library::tpm2::command) fn commit_orderly_clear(
    runtime: &mut Tpm2Runtime,
    orderly_state: Option<u16>,
) -> Result<(), TpmResult> {
    commit_clear_orderly(runtime, orderly_state)
}

pub(in crate::library::tpm2::command) fn live_pcr_counter(
    runtime: &Tpm2Runtime,
) -> Result<u32, TpmResult> {
    runtime
        .live
        .state_reset
        .as_ref()
        .map(|reset| reset.pcr_counter)
        .ok_or(TPM_RC_FAILURE)
}

pub(in crate::library::tpm2::command) fn pcr_changed(
    pcr_counter: u32,
    pcr: usize,
) -> Result<u32, TpmResult> {
    if pcr != 0 && pcr_in_tcb_group(pcr) {
        return Ok(pcr_counter);
    }
    pcr_counter.checked_add(1).ok_or(TPM_RC_FAILURE)
}

pub(in crate::library::tpm2::command) fn commit_pcr_counter(
    runtime: &mut Tpm2Runtime,
    pcr_counter: u32,
) -> Result<(), TpmResult> {
    let state_reset = runtime.live.state_reset.as_mut().ok_or(TPM_RC_FAILURE)?;
    state_reset.pcr_counter = pcr_counter;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::runtime::empty_state_runtime;

    #[test]
    fn tcb_group_counter_preservation_pcr_zero_increment() {
        for pcr in [16usize, 21, 22, 23] {
            assert_eq!(pcr_changed(7, pcr), Ok(7), "PCR {pcr}");
        }
        for pcr in [0usize, 1, 10, 17, 18, 19, 20] {
            assert_eq!(pcr_changed(7, pcr), Ok(8), "PCR {pcr}");
        }
    }

    #[test]
    fn counter_maximum_internal_failure() {
        assert_eq!(pcr_changed(u32::MAX, 10), Err(TPM_RC_FAILURE));
        assert_eq!(pcr_changed(u32::MAX, 21), Ok(u32::MAX), "no increment");
    }

    #[test]
    fn stateless_runtime_panic_safety() {
        let mut runtime = empty_state_runtime();
        assert_eq!(prepare_orderly_clear(&runtime, 10), Err(TPM_RC_FAILURE));
        assert_eq!(
            commit_orderly_clear(&mut runtime, Some(0xffff)),
            Err(TPM_RC_FAILURE)
        );
        assert_eq!(commit_orderly_clear(&mut runtime, None), Ok(()));
    }

    #[test]
    fn stateless_runtime_reset_panic_safety() {
        let mut runtime = empty_state_runtime();
        assert_eq!(live_pcr_counter(&runtime), Err(TPM_RC_FAILURE));
        assert_eq!(commit_pcr_counter(&mut runtime, 3), Err(TPM_RC_FAILURE));
    }
}
