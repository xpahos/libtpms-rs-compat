// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex
//
// License text: LICENSE.
// Upstream notices: LICENSES/libtpms-notices.txt.

use crate::library::{Platform, TPM_SUCCESS};
use crate::types::{TpmBool, TpmModifierIndicator, TpmResult};

const TPM_NUMBER: u32 = 0;

type IoInit = unsafe extern "C" fn() -> TpmResult;
type IoGetLocality = unsafe extern "C" fn(*mut TpmModifierIndicator, u32) -> TpmResult;
type IoGetPhysicalPresence = unsafe extern "C" fn(*mut TpmBool, u32) -> TpmResult;

pub(crate) struct CallbackPlatform {
    init: Option<IoInit>,
    get_locality: Option<IoGetLocality>,
    get_physical_presence: Option<IoGetPhysicalPresence>,
}

impl CallbackPlatform {
    pub(crate) fn new(
        init: Option<IoInit>,
        get_locality: Option<IoGetLocality>,
        get_physical_presence: Option<IoGetPhysicalPresence>,
    ) -> Self {
        Self {
            init,
            get_locality,
            get_physical_presence,
        }
    }
}

impl Platform for CallbackPlatform {
    fn initialize(&self) -> Result<(), TpmResult> {
        let Some(init) = self.init else {
            return Ok(());
        };
        // SAFETY: TPMLIB_RegisterCallbacks copied a function pointer with the
        // exact C ABI signature, which must not unwind. The host must keep its
        // code loaded while the callback is registered.
        match unsafe { init() } {
            TPM_SUCCESS => Ok(()),
            code => Err(code),
        }
    }

    fn locality(&self) -> u32 {
        let Some(get_locality) = self.get_locality else {
            return 0;
        };
        let mut locality: TpmModifierIndicator = 0;
        // SAFETY: same registration contract as `initialize`; the out-pointer
        // references a live local for the duration of the call.
        let _ = unsafe { get_locality(&mut locality, TPM_NUMBER) };
        locality
    }

    fn physical_presence(&self) -> bool {
        let Some(get_physical_presence) = self.get_physical_presence else {
            return false;
        };
        let mut asserted: TpmBool = 0;
        // SAFETY: same registration contract as `initialize`; the out-pointer
        // references a live local for the duration of the call.
        let result = unsafe { get_physical_presence(&mut asserted, TPM_NUMBER) };
        result == TPM_SUCCESS && asserted != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static LOCALITY_CALLS: Mutex<Vec<u32>> = Mutex::new(Vec::new());
    static PRESENCE_CALLS: Mutex<Vec<u32>> = Mutex::new(Vec::new());

    unsafe extern "C" fn io_init_ok() -> TpmResult {
        TPM_SUCCESS
    }

    unsafe extern "C" fn io_init_fail() -> TpmResult {
        42
    }

    unsafe extern "C" fn locality_three(
        locality: *mut TpmModifierIndicator,
        tpm_number: u32,
    ) -> TpmResult {
        LOCALITY_CALLS.lock().unwrap().push(tpm_number);
        // SAFETY: the adapter passes a live out-pointer per the contract.
        unsafe { *locality = 3 };
        TPM_SUCCESS
    }

    unsafe extern "C" fn locality_out_of_range_with_error(
        locality: *mut TpmModifierIndicator,
        _tpm_number: u32,
    ) -> TpmResult {
        // SAFETY: the adapter passes a live out-pointer per the contract.
        unsafe { *locality = 300 };
        77
    }

    unsafe extern "C" fn locality_untouched(
        _locality: *mut TpmModifierIndicator,
        _tpm_number: u32,
    ) -> TpmResult {
        TPM_SUCCESS
    }

    unsafe extern "C" fn presence_asserted(asserted: *mut TpmBool, tpm_number: u32) -> TpmResult {
        PRESENCE_CALLS.lock().unwrap().push(tpm_number);
        // SAFETY: the adapter passes a live out-pointer per the contract.
        unsafe { *asserted = 1 };
        TPM_SUCCESS
    }

    unsafe extern "C" fn presence_cleared(asserted: *mut TpmBool, _tpm_number: u32) -> TpmResult {
        // SAFETY: the adapter passes a live out-pointer per the contract.
        unsafe { *asserted = 0 };
        TPM_SUCCESS
    }

    unsafe extern "C" fn presence_asserted_with_error(
        asserted: *mut TpmBool,
        _tpm_number: u32,
    ) -> TpmResult {
        // SAFETY: the adapter passes a live out-pointer per the contract.
        unsafe { *asserted = 1 };
        88
    }

    fn platform(
        init: Option<IoInit>,
        get_locality: Option<IoGetLocality>,
        get_physical_presence: Option<IoGetPhysicalPresence>,
    ) -> CallbackPlatform {
        CallbackPlatform::new(init, get_locality, get_physical_presence)
    }

    #[test]
    fn missing_callback_defaults() {
        let platform = platform(None, None, None);
        assert_eq!(platform.initialize(), Ok(()));
        assert_eq!(platform.locality(), 0);
        assert!(!platform.physical_presence());
    }

    #[test]
    fn init_success_and_error_mapping() {
        assert_eq!(platform(Some(io_init_ok), None, None).initialize(), Ok(()));
        assert_eq!(
            platform(Some(io_init_fail), None, None).initialize(),
            Err(42)
        );
    }

    #[test]
    fn locality_tpm_number_zero_argument() {
        let _serial = TEST_LOCK.lock().unwrap();
        LOCALITY_CALLS.lock().unwrap().clear();
        assert_eq!(platform(None, Some(locality_three), None).locality(), 3);
        assert_eq!(*LOCALITY_CALLS.lock().unwrap(), [0]);
    }

    #[test]
    fn locality_callback_result_indifference() {
        assert_eq!(
            platform(None, Some(locality_out_of_range_with_error), None).locality(),
            300,
            "the raw value reaches the TPM locality validation unnarrowed"
        );
    }

    #[test]
    fn untouched_locality_zero_default() {
        assert_eq!(platform(None, Some(locality_untouched), None).locality(), 0);
    }

    #[test]
    fn presence_tpm_number_zero_argument() {
        let _serial = TEST_LOCK.lock().unwrap();
        PRESENCE_CALLS.lock().unwrap().clear();
        assert!(platform(None, None, Some(presence_asserted)).physical_presence());
        assert_eq!(*PRESENCE_CALLS.lock().unwrap(), [0]);
    }

    #[test]
    fn cleared_presence_false_result() {
        assert!(!platform(None, None, Some(presence_cleared)).physical_presence());
    }

    #[test]
    fn presence_error_false_fallback() {
        assert!(!platform(None, None, Some(presence_asserted_with_error)).physical_presence());
    }
}
