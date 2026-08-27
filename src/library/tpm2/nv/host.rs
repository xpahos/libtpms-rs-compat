use core::ffi::{CStr, c_uchar};
use core::ptr;

use crate::ffi::memory::MallocBuffer;
use crate::ffi::types::{LibtpmsCallbacks, TpmBool, TpmResult};
use crate::library::constants::{TPM_FAIL, TPM_RETRY, TPM_SUCCESS};
use crate::library::state_blob::StateBlobKind;

const TPM_NUMBER: u32 = 0;

unsafe fn adopt_loaddata_buffer(
    data: *mut c_uchar,
    length: u32,
) -> Result<Option<MallocBuffer>, TpmResult> {
    match usize::try_from(length) {
        // SAFETY: forwarded from the caller.
        Ok(length) => Ok(unsafe { MallocBuffer::from_raw(data, length) }),
        Err(_) => {
            // SAFETY: forwarded from the caller; the buffer is never read.
            drop(unsafe { MallocBuffer::from_raw(data, 0) });
            Err(TPM_FAIL)
        }
    }
}

fn state_name(kind: StateBlobKind) -> &'static CStr {
    match kind {
        StateBlobKind::Permanent => c"permall",
        StateBlobKind::Volatile => c"volatilestate",
        StateBlobKind::SaveState => c"savestate",
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) enum NvramLoad {
    NotRegistered,
    Missing,
    Data(Vec<u8>),
    SuccessWithoutData,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) enum NvramWrite {
    NotRegistered,
    Done,
}

#[derive(Clone, Copy)]
pub(in crate::library::tpm2) struct PermanentStateProbe {
    pub(in crate::library::tpm2) exists: bool,
    #[allow(dead_code)]
    pub(in crate::library::tpm2) has_load_callback: bool,
}

pub(in crate::library) struct HostNvram {
    callbacks: LibtpmsCallbacks,
}

impl HostNvram {
    pub(in crate::library) fn new(callbacks: LibtpmsCallbacks) -> Self {
        Self { callbacks }
    }

    pub(in crate::library::tpm2) fn init(&self) -> Result<NvramWrite, TpmResult> {
        let Some(init) = self.callbacks.tpm_nvram_init else {
            return Ok(NvramWrite::NotRegistered);
        };
        // SAFETY: TPMLIB_RegisterCallbacks copied a function pointer with
        // the exact C ABI signature, which must not unwind. The host must
        // keep its code loaded while the callback is registered.
        match unsafe { init() } {
            TPM_SUCCESS => Ok(NvramWrite::Done),
            code => Err(code),
        }
    }

    pub(in crate::library::tpm2) fn load(
        &self,
        kind: StateBlobKind,
    ) -> Result<NvramLoad, TpmResult> {
        let Some(loaddata) = self.callbacks.tpm_nvram_loaddata else {
            return Ok(NvramLoad::NotRegistered);
        };
        let mut data: *mut c_uchar = ptr::null_mut();
        let mut length: u32 = 0;
        // SAFETY: registered by the host via TPMLIB_RegisterCallbacks and
        // must not unwind; the out-pointers are valid locals and the name is
        // NUL-terminated.
        let result = unsafe {
            loaddata(
                &mut data,
                &mut length,
                TPM_NUMBER,
                state_name(kind).as_ptr(),
            )
        };
        // SAFETY: on any return the host either left `data` NULL or
        // transferred ownership of a malloc'ed buffer of `length` bytes
        // (freed-by-caller contract); the guard frees it on every path,
        // error results included.
        let buffer = unsafe { adopt_loaddata_buffer(data, length) }?;
        match result {
            TPM_SUCCESS => match buffer {
                Some(buffer) => Ok(NvramLoad::Data(buffer.as_slice().to_vec())),
                None => Ok(NvramLoad::SuccessWithoutData),
            },
            TPM_RETRY => Ok(NvramLoad::Missing),
            code => Err(code),
        }
    }

    pub(in crate::library::tpm2) fn can_store(&self) -> bool {
        self.callbacks.tpm_nvram_storedata.is_some()
    }

    pub(in crate::library::tpm2) fn store(
        &self,
        kind: StateBlobKind,
        data: &[u8],
    ) -> Result<NvramWrite, TpmResult> {
        let Some(storedata) = self.callbacks.tpm_nvram_storedata else {
            return Ok(NvramWrite::NotRegistered);
        };
        let length = u32::try_from(data.len()).map_err(|_| TPM_FAIL)?;
        // SAFETY: same registration and lifetime contract as `init`; the
        // data pointer stays valid for the duration of the call and the
        // host only reads `length` bytes from it.
        let result =
            unsafe { storedata(data.as_ptr(), length, TPM_NUMBER, state_name(kind).as_ptr()) };
        match result {
            TPM_SUCCESS => Ok(NvramWrite::Done),
            code => Err(code),
        }
    }

    #[allow(dead_code)]
    pub(in crate::library::tpm2) fn delete(
        &self,
        kind: StateBlobKind,
        must_exist: bool,
    ) -> Result<NvramWrite, TpmResult> {
        let Some(deletename) = self.callbacks.tpm_nvram_deletename else {
            return Ok(NvramWrite::NotRegistered);
        };
        // SAFETY: same registration and lifetime contract as `init`.
        let result = unsafe {
            deletename(
                TPM_NUMBER,
                state_name(kind).as_ptr(),
                TpmBool::from(must_exist),
            )
        };
        match result {
            TPM_SUCCESS => Ok(NvramWrite::Done),
            code => Err(code),
        }
    }

    pub(in crate::library::tpm2) fn probe_permanent(&self) -> PermanentStateProbe {
        let Some(loaddata) = self.callbacks.tpm_nvram_loaddata else {
            return PermanentStateProbe {
                exists: false,
                has_load_callback: false,
            };
        };
        let mut data: *mut c_uchar = ptr::null_mut();
        let mut length: u32 = 0;
        // SAFETY: same contract as `load`.
        let result = unsafe {
            loaddata(
                &mut data,
                &mut length,
                TPM_NUMBER,
                state_name(StateBlobKind::Permanent).as_ptr(),
            )
        };
        // SAFETY: same ownership-transfer contract as `load`; the guard
        // frees the buffer on every path, error results included. The
        // probe never reads the bytes, so an unrepresentable length only
        // means "free and ignore".
        let _ = unsafe { adopt_loaddata_buffer(data, length) };
        PermanentStateProbe {
            exists: result != TPM_RETRY,
            has_load_callback: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::c_char;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static LOAD_CALLS: Mutex<Vec<(u32, String)>> = Mutex::new(Vec::new());
    static STORE_CALLS: Mutex<Vec<(Vec<u8>, u32, String)>> = Mutex::new(Vec::new());
    static DELETE_CALLS: Mutex<Vec<(u32, String, TpmBool)>> = Mutex::new(Vec::new());

    fn name_to_string(name: *const c_char) -> String {
        // SAFETY: the wrapper passes a NUL-terminated &'static CStr.
        unsafe { CStr::from_ptr(name) }
            .to_string_lossy()
            .into_owned()
    }

    unsafe extern "C" fn nvram_init_ok() -> TpmResult {
        TPM_SUCCESS
    }

    unsafe extern "C" fn nvram_init_fail() -> TpmResult {
        43
    }

    unsafe extern "C" fn loaddata_retry(
        _data: *mut *mut c_uchar,
        _length: *mut u32,
        tpm_number: u32,
        name: *const c_char,
    ) -> TpmResult {
        LOAD_CALLS
            .lock()
            .unwrap()
            .push((tpm_number, name_to_string(name)));
        TPM_RETRY
    }

    unsafe extern "C" fn loaddata_found(
        data: *mut *mut c_uchar,
        length: *mut u32,
        tpm_number: u32,
        name: *const c_char,
    ) -> TpmResult {
        LOAD_CALLS
            .lock()
            .unwrap()
            .push((tpm_number, name_to_string(name)));
        // SAFETY: out-pointers are valid per the callback contract; the
        // buffer is malloc'ed and ownership transfers to the caller.
        unsafe {
            *data = crate::ffi::memory::malloc_bytes(&[1, 2, 3]);
            *length = 3;
        }
        TPM_SUCCESS
    }

    unsafe extern "C" fn loaddata_success_null(
        _data: *mut *mut c_uchar,
        _length: *mut u32,
        _tpm_number: u32,
        _name: *const c_char,
    ) -> TpmResult {
        TPM_SUCCESS
    }

    unsafe extern "C" fn loaddata_retry_with_buffer(
        data: *mut *mut c_uchar,
        length: *mut u32,
        _tpm_number: u32,
        _name: *const c_char,
    ) -> TpmResult {
        // SAFETY: out-pointers are valid per the callback contract; the
        // buffer is malloc'ed and ownership transfers to the caller even
        // though the result is TPM_RETRY.
        unsafe {
            *data = crate::ffi::memory::malloc_bytes(&[0xCC]);
            *length = 1;
        }
        TPM_RETRY
    }

    unsafe extern "C" fn loaddata_error_null(
        _data: *mut *mut c_uchar,
        _length: *mut u32,
        _tpm_number: u32,
        _name: *const c_char,
    ) -> TpmResult {
        77
    }

    unsafe extern "C" fn loaddata_error_with_buffer(
        data: *mut *mut c_uchar,
        length: *mut u32,
        _tpm_number: u32,
        _name: *const c_char,
    ) -> TpmResult {
        // SAFETY: out-pointers are valid per the callback contract; the
        // buffer is malloc'ed and ownership transfers to the caller even
        // though the result is an error (mirrors hosts that fill the
        // buffer before failing).
        unsafe {
            *data = crate::ffi::memory::malloc_bytes(&[0xAA, 0xBB]);
            *length = 2;
        }
        77
    }

    unsafe extern "C" fn storedata_recording(
        data: *const c_uchar,
        length: u32,
        tpm_number: u32,
        name: *const c_char,
    ) -> TpmResult {
        // SAFETY: the host may read `length` bytes from `data` per the
        // callback contract.
        let bytes = unsafe { core::slice::from_raw_parts(data, length as usize) }.to_vec();
        STORE_CALLS
            .lock()
            .unwrap()
            .push((bytes, tpm_number, name_to_string(name)));
        TPM_SUCCESS
    }

    unsafe extern "C" fn storedata_error(
        _data: *const c_uchar,
        _length: u32,
        _tpm_number: u32,
        _name: *const c_char,
    ) -> TpmResult {
        88
    }

    unsafe extern "C" fn deletename_recording(
        tpm_number: u32,
        name: *const c_char,
        must_exist: TpmBool,
    ) -> TpmResult {
        DELETE_CALLS
            .lock()
            .unwrap()
            .push((tpm_number, name_to_string(name), must_exist));
        TPM_SUCCESS
    }

    unsafe extern "C" fn deletename_error(
        _tpm_number: u32,
        _name: *const c_char,
        _must_exist: TpmBool,
    ) -> TpmResult {
        99
    }

    fn nvram_with(callbacks: LibtpmsCallbacks) -> HostNvram {
        HostNvram::new(callbacks)
    }

    #[test]
    fn state_names_match_upstream() {
        assert_eq!(state_name(StateBlobKind::Permanent).to_bytes(), b"permall");
        assert_eq!(
            state_name(StateBlobKind::Volatile).to_bytes(),
            b"volatilestate"
        );
        assert_eq!(
            state_name(StateBlobKind::SaveState).to_bytes(),
            b"savestate"
        );
    }

    #[test]
    fn init_without_callback_is_not_registered() {
        let nvram = nvram_with(LibtpmsCallbacks::empty());
        assert_eq!(nvram.init(), Ok(NvramWrite::NotRegistered));
    }

    #[test]
    fn init_invokes_registered_callback() {
        let nvram = nvram_with(LibtpmsCallbacks {
            tpm_nvram_init: Some(nvram_init_ok),
            ..LibtpmsCallbacks::empty()
        });
        assert_eq!(nvram.init(), Ok(NvramWrite::Done));
    }

    #[test]
    fn init_preserves_callback_error_code() {
        let nvram = nvram_with(LibtpmsCallbacks {
            tpm_nvram_init: Some(nvram_init_fail),
            ..LibtpmsCallbacks::empty()
        });
        assert_eq!(nvram.init(), Err(43));
    }

    #[test]
    fn load_without_callback_is_not_registered() {
        let nvram = nvram_with(LibtpmsCallbacks::empty());
        assert_eq!(
            nvram.load(StateBlobKind::Permanent),
            Ok(NvramLoad::NotRegistered)
        );
    }

    #[test]
    fn load_maps_retry_to_missing_and_passes_tpm_number_zero() {
        let _serial = TEST_LOCK.lock().unwrap();
        LOAD_CALLS.lock().unwrap().clear();
        let nvram = nvram_with(LibtpmsCallbacks {
            tpm_nvram_loaddata: Some(loaddata_retry),
            ..LibtpmsCallbacks::empty()
        });
        assert_eq!(nvram.load(StateBlobKind::Volatile), Ok(NvramLoad::Missing));
        assert_eq!(
            *LOAD_CALLS.lock().unwrap(),
            [(0, "volatilestate".to_owned())]
        );
    }

    #[test]
    fn load_uses_the_exact_upstream_name_for_each_kind() {
        let _serial = TEST_LOCK.lock().unwrap();
        LOAD_CALLS.lock().unwrap().clear();
        let nvram = nvram_with(LibtpmsCallbacks {
            tpm_nvram_loaddata: Some(loaddata_retry),
            ..LibtpmsCallbacks::empty()
        });
        for kind in [
            StateBlobKind::Permanent,
            StateBlobKind::Volatile,
            StateBlobKind::SaveState,
        ] {
            assert_eq!(nvram.load(kind), Ok(NvramLoad::Missing));
        }
        assert_eq!(
            *LOAD_CALLS.lock().unwrap(),
            [
                (0, "permall".to_owned()),
                (0, "volatilestate".to_owned()),
                (0, "savestate".to_owned()),
            ]
        );
    }

    #[test]
    fn load_returns_owned_copy_of_host_buffer() {
        let _serial = TEST_LOCK.lock().unwrap();
        let nvram = nvram_with(LibtpmsCallbacks {
            tpm_nvram_loaddata: Some(loaddata_found),
            ..LibtpmsCallbacks::empty()
        });
        assert_eq!(
            nvram.load(StateBlobKind::Permanent),
            Ok(NvramLoad::Data(vec![1, 2, 3]))
        );
    }

    #[test]
    fn load_success_without_buffer_stays_distinct_from_data() {
        let nvram = nvram_with(LibtpmsCallbacks {
            tpm_nvram_loaddata: Some(loaddata_success_null),
            ..LibtpmsCallbacks::empty()
        });
        assert_eq!(
            nvram.load(StateBlobKind::SaveState),
            Ok(NvramLoad::SuccessWithoutData)
        );
    }

    #[test]
    fn load_preserves_error_code_with_null_buffer() {
        let nvram = nvram_with(LibtpmsCallbacks {
            tpm_nvram_loaddata: Some(loaddata_error_null),
            ..LibtpmsCallbacks::empty()
        });
        assert_eq!(nvram.load(StateBlobKind::Permanent), Err(77));
    }

    #[test]
    fn load_frees_host_buffer_even_on_retry() {
        let nvram = nvram_with(LibtpmsCallbacks {
            tpm_nvram_loaddata: Some(loaddata_retry_with_buffer),
            ..LibtpmsCallbacks::empty()
        });
        assert_eq!(nvram.load(StateBlobKind::Permanent), Ok(NvramLoad::Missing));
    }

    #[test]
    fn load_frees_host_buffer_even_on_error() {
        let nvram = nvram_with(LibtpmsCallbacks {
            tpm_nvram_loaddata: Some(loaddata_error_with_buffer),
            ..LibtpmsCallbacks::empty()
        });
        assert_eq!(nvram.load(StateBlobKind::Permanent), Err(77));
    }

    #[test]
    fn store_without_callback_is_not_registered() {
        let nvram = nvram_with(LibtpmsCallbacks::empty());
        assert_eq!(
            nvram.store(StateBlobKind::Permanent, &[1]),
            Ok(NvramWrite::NotRegistered)
        );
    }

    #[test]
    fn store_passes_exact_arguments() {
        let _serial = TEST_LOCK.lock().unwrap();
        STORE_CALLS.lock().unwrap().clear();
        let nvram = nvram_with(LibtpmsCallbacks {
            tpm_nvram_storedata: Some(storedata_recording),
            ..LibtpmsCallbacks::empty()
        });
        assert_eq!(
            nvram.store(StateBlobKind::SaveState, &[9, 8, 7]),
            Ok(NvramWrite::Done)
        );
        assert_eq!(
            *STORE_CALLS.lock().unwrap(),
            [(vec![9, 8, 7], 0, "savestate".to_owned())]
        );
    }

    #[test]
    fn store_preserves_callback_error_code() {
        let nvram = nvram_with(LibtpmsCallbacks {
            tpm_nvram_storedata: Some(storedata_error),
            ..LibtpmsCallbacks::empty()
        });
        assert_eq!(nvram.store(StateBlobKind::Permanent, &[1]), Err(88));
    }

    #[test]
    fn delete_without_callback_is_not_registered() {
        let nvram = nvram_with(LibtpmsCallbacks::empty());
        assert_eq!(
            nvram.delete(StateBlobKind::Volatile, true),
            Ok(NvramWrite::NotRegistered)
        );
    }

    #[test]
    fn delete_passes_exact_arguments_and_converts_must_exist() {
        let _serial = TEST_LOCK.lock().unwrap();
        DELETE_CALLS.lock().unwrap().clear();
        let nvram = nvram_with(LibtpmsCallbacks {
            tpm_nvram_deletename: Some(deletename_recording),
            ..LibtpmsCallbacks::empty()
        });
        assert_eq!(
            nvram.delete(StateBlobKind::Volatile, true),
            Ok(NvramWrite::Done)
        );
        assert_eq!(
            nvram.delete(StateBlobKind::Permanent, false),
            Ok(NvramWrite::Done)
        );
        assert_eq!(
            *DELETE_CALLS.lock().unwrap(),
            [
                (0, "volatilestate".to_owned(), 1),
                (0, "permall".to_owned(), 0),
            ]
        );
    }

    #[test]
    fn delete_preserves_callback_error_code() {
        let nvram = nvram_with(LibtpmsCallbacks {
            tpm_nvram_deletename: Some(deletename_error),
            ..LibtpmsCallbacks::empty()
        });
        assert_eq!(nvram.delete(StateBlobKind::SaveState, false), Err(99));
    }

    #[test]
    fn probe_without_load_callback_reports_no_state() {
        let probe = nvram_with(LibtpmsCallbacks::empty()).probe_permanent();
        assert!(!probe.exists);
        assert!(!probe.has_load_callback);
    }

    #[test]
    fn probe_maps_retry_to_no_state_and_asks_for_permall() {
        let _serial = TEST_LOCK.lock().unwrap();
        LOAD_CALLS.lock().unwrap().clear();
        let probe = nvram_with(LibtpmsCallbacks {
            tpm_nvram_loaddata: Some(loaddata_retry),
            ..LibtpmsCallbacks::empty()
        })
        .probe_permanent();
        assert!(!probe.exists);
        assert!(probe.has_load_callback);
        assert_eq!(*LOAD_CALLS.lock().unwrap(), [(0, "permall".to_owned())]);
    }

    #[test]
    fn probe_maps_success_with_buffer_to_existing_state() {
        let _serial = TEST_LOCK.lock().unwrap();
        let probe = nvram_with(LibtpmsCallbacks {
            tpm_nvram_loaddata: Some(loaddata_found),
            ..LibtpmsCallbacks::empty()
        })
        .probe_permanent();
        assert!(probe.exists);
        assert!(probe.has_load_callback);
    }

    #[test]
    fn probe_maps_success_with_null_buffer_to_existing_state() {
        let probe = nvram_with(LibtpmsCallbacks {
            tpm_nvram_loaddata: Some(loaddata_success_null),
            ..LibtpmsCallbacks::empty()
        })
        .probe_permanent();
        assert!(probe.exists);
        assert!(probe.has_load_callback);
    }

    #[test]
    fn probe_maps_other_errors_to_existing_state() {
        let probe = nvram_with(LibtpmsCallbacks {
            tpm_nvram_loaddata: Some(loaddata_error_null),
            ..LibtpmsCallbacks::empty()
        })
        .probe_permanent();
        assert!(probe.exists);
        assert!(probe.has_load_callback);
    }
}
