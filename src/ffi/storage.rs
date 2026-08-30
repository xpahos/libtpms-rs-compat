use core::ffi::{CStr, c_uchar};
use core::ptr;

use crate::ffi::memory::MallocBuffer;
use crate::library::{
    StateBlobKind, Storage, StorageLoad, StorageProbe, TPM_FAIL, TPM_RETRY, TPM_SUCCESS,
};
use crate::types::{TpmBool, TpmResult};

const TPM_NUMBER: u32 = 0;

type NvramInit = unsafe extern "C" fn() -> TpmResult;
type NvramLoadData =
    unsafe extern "C" fn(*mut *mut c_uchar, *mut u32, u32, *const core::ffi::c_char) -> TpmResult;
type NvramStoreData =
    unsafe extern "C" fn(*const c_uchar, u32, u32, *const core::ffi::c_char) -> TpmResult;
type NvramDeleteName = unsafe extern "C" fn(u32, *const core::ffi::c_char, TpmBool) -> TpmResult;

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

pub(crate) struct CallbackStorage {
    init: Option<NvramInit>,
    loaddata: Option<NvramLoadData>,
    storedata: Option<NvramStoreData>,
    deletename: Option<NvramDeleteName>,
}

impl CallbackStorage {
    pub(crate) fn new(
        init: Option<NvramInit>,
        loaddata: Option<NvramLoadData>,
        storedata: Option<NvramStoreData>,
        deletename: Option<NvramDeleteName>,
    ) -> Self {
        Self {
            init,
            loaddata,
            storedata,
            deletename,
        }
    }
}

impl Storage for CallbackStorage {
    fn initialize(&self) -> Result<(), TpmResult> {
        let Some(init) = self.init else {
            return Ok(());
        };
        // SAFETY: TPMLIB_RegisterCallbacks copied a function pointer with
        // the exact C ABI signature, which must not unwind. The host must
        // keep its code loaded while the callback is registered.
        match unsafe { init() } {
            TPM_SUCCESS => Ok(()),
            code => Err(code),
        }
    }

    fn probe_permanent(&self) -> StorageProbe {
        let Some(loaddata) = self.loaddata else {
            return StorageProbe::Unsupported;
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
        match result {
            TPM_RETRY => StorageProbe::Missing,
            _ => StorageProbe::Present,
        }
    }

    fn load(&self, kind: StateBlobKind) -> Result<StorageLoad, TpmResult> {
        let Some(loaddata) = self.loaddata else {
            return Ok(StorageLoad::Unsupported);
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
                Some(buffer) => Ok(StorageLoad::Data(buffer.as_slice().to_vec())),
                None => Ok(StorageLoad::Empty),
            },
            TPM_RETRY => Ok(StorageLoad::Missing),
            code => Err(code),
        }
    }

    fn supports_store(&self) -> bool {
        self.storedata.is_some()
    }

    fn store(&self, kind: StateBlobKind, data: &[u8]) -> Result<(), TpmResult> {
        let Some(storedata) = self.storedata else {
            return Err(TPM_FAIL);
        };
        let length = u32::try_from(data.len()).map_err(|_| TPM_FAIL)?;
        // SAFETY: same registration and lifetime contract as `init`; the
        // data pointer stays valid for the duration of the call and the
        // host only reads `length` bytes from it.
        let result =
            unsafe { storedata(data.as_ptr(), length, TPM_NUMBER, state_name(kind).as_ptr()) };
        match result {
            TPM_SUCCESS => Ok(()),
            code => Err(code),
        }
    }

    fn delete(&self, kind: StateBlobKind, must_exist: bool) -> Result<(), TpmResult> {
        let Some(deletename) = self.deletename else {
            return Err(TPM_FAIL);
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
            TPM_SUCCESS => Ok(()),
            code => Err(code),
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

    fn storage_with(callbacks: crate::types::LibtpmsCallbacks) -> CallbackStorage {
        CallbackStorage::new(
            callbacks.tpm_nvram_init,
            callbacks.tpm_nvram_loaddata,
            callbacks.tpm_nvram_storedata,
            callbacks.tpm_nvram_deletename,
        )
    }

    #[test]
    fn state_name_upstream_parity() {
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
    fn missing_init_unsupported() {
        let storage = storage_with(crate::types::LibtpmsCallbacks::empty());
        assert_eq!(storage.initialize(), Ok(()));
    }

    #[test]
    fn init_callback_invocation() {
        let storage = storage_with(crate::types::LibtpmsCallbacks {
            tpm_nvram_init: Some(nvram_init_ok),
            ..crate::types::LibtpmsCallbacks::empty()
        });
        assert_eq!(storage.initialize(), Ok(()));
    }

    #[test]
    fn init_error_preservation() {
        let storage = storage_with(crate::types::LibtpmsCallbacks {
            tpm_nvram_init: Some(nvram_init_fail),
            ..crate::types::LibtpmsCallbacks::empty()
        });
        assert_eq!(storage.initialize(), Err(43));
    }

    #[test]
    fn missing_load_unsupported() {
        let storage = storage_with(crate::types::LibtpmsCallbacks::empty());
        assert_eq!(
            storage.load(StateBlobKind::Permanent),
            Ok(StorageLoad::Unsupported)
        );
    }

    #[test]
    fn retry_missing_classification() {
        let _serial = TEST_LOCK.lock().unwrap();
        LOAD_CALLS.lock().unwrap().clear();
        let storage = storage_with(crate::types::LibtpmsCallbacks {
            tpm_nvram_loaddata: Some(loaddata_retry),
            ..crate::types::LibtpmsCallbacks::empty()
        });
        assert_eq!(
            storage.load(StateBlobKind::Volatile),
            Ok(StorageLoad::Missing)
        );
        assert_eq!(
            *LOAD_CALLS.lock().unwrap(),
            [(0, "volatilestate".to_owned())]
        );
    }

    #[test]
    fn load_argument_passthrough() {
        let _serial = TEST_LOCK.lock().unwrap();
        LOAD_CALLS.lock().unwrap().clear();
        let storage = storage_with(crate::types::LibtpmsCallbacks {
            tpm_nvram_loaddata: Some(loaddata_retry),
            ..crate::types::LibtpmsCallbacks::empty()
        });
        for kind in [
            StateBlobKind::Permanent,
            StateBlobKind::Volatile,
            StateBlobKind::SaveState,
        ] {
            assert_eq!(storage.load(kind), Ok(StorageLoad::Missing));
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
    fn load_buffer_copy() {
        let _serial = TEST_LOCK.lock().unwrap();
        let storage = storage_with(crate::types::LibtpmsCallbacks {
            tpm_nvram_loaddata: Some(loaddata_found),
            ..crate::types::LibtpmsCallbacks::empty()
        });
        assert_eq!(
            storage.load(StateBlobKind::Permanent),
            Ok(StorageLoad::Data(vec![1, 2, 3]))
        );
    }

    #[test]
    fn null_load_empty_result() {
        let storage = storage_with(crate::types::LibtpmsCallbacks {
            tpm_nvram_loaddata: Some(loaddata_success_null),
            ..crate::types::LibtpmsCallbacks::empty()
        });
        assert_eq!(
            storage.load(StateBlobKind::SaveState),
            Ok(StorageLoad::Empty)
        );
    }

    #[test]
    fn load_error_preservation() {
        let storage = storage_with(crate::types::LibtpmsCallbacks {
            tpm_nvram_loaddata: Some(loaddata_error_null),
            ..crate::types::LibtpmsCallbacks::empty()
        });
        assert_eq!(storage.load(StateBlobKind::Permanent), Err(77));
    }

    #[test]
    fn retry_buffer_release() {
        let storage = storage_with(crate::types::LibtpmsCallbacks {
            tpm_nvram_loaddata: Some(loaddata_retry_with_buffer),
            ..crate::types::LibtpmsCallbacks::empty()
        });
        assert_eq!(
            storage.load(StateBlobKind::Permanent),
            Ok(StorageLoad::Missing)
        );
    }

    #[test]
    fn error_buffer_release() {
        let storage = storage_with(crate::types::LibtpmsCallbacks {
            tpm_nvram_loaddata: Some(loaddata_error_with_buffer),
            ..crate::types::LibtpmsCallbacks::empty()
        });
        assert_eq!(storage.load(StateBlobKind::Permanent), Err(77));
    }

    #[test]
    fn missing_store_unsupported() {
        let storage = storage_with(crate::types::LibtpmsCallbacks::empty());
        assert_eq!(storage.store(StateBlobKind::Permanent, &[1]), Err(TPM_FAIL));
        assert!(!storage.supports_store());
    }

    #[test]
    fn store_argument_passthrough() {
        let _serial = TEST_LOCK.lock().unwrap();
        STORE_CALLS.lock().unwrap().clear();
        let storage = storage_with(crate::types::LibtpmsCallbacks {
            tpm_nvram_storedata: Some(storedata_recording),
            ..crate::types::LibtpmsCallbacks::empty()
        });
        assert!(storage.supports_store());
        assert_eq!(storage.store(StateBlobKind::SaveState, &[9, 8, 7]), Ok(()));
        assert_eq!(
            *STORE_CALLS.lock().unwrap(),
            [(vec![9, 8, 7], 0, "savestate".to_owned())]
        );
    }

    #[test]
    fn store_error_preservation() {
        let storage = storage_with(crate::types::LibtpmsCallbacks {
            tpm_nvram_storedata: Some(storedata_error),
            ..crate::types::LibtpmsCallbacks::empty()
        });
        assert_eq!(storage.store(StateBlobKind::Permanent, &[1]), Err(88));
    }

    #[test]
    fn missing_delete_unsupported() {
        let storage = storage_with(crate::types::LibtpmsCallbacks::empty());
        assert_eq!(storage.delete(StateBlobKind::Volatile, true), Err(TPM_FAIL));
    }

    #[test]
    fn delete_argument_passthrough() {
        let _serial = TEST_LOCK.lock().unwrap();
        DELETE_CALLS.lock().unwrap().clear();
        let storage = storage_with(crate::types::LibtpmsCallbacks {
            tpm_nvram_deletename: Some(deletename_recording),
            ..crate::types::LibtpmsCallbacks::empty()
        });
        assert_eq!(storage.delete(StateBlobKind::Volatile, true), Ok(()));
        assert_eq!(storage.delete(StateBlobKind::Permanent, false), Ok(()));
        assert_eq!(
            *DELETE_CALLS.lock().unwrap(),
            [
                (0, "volatilestate".to_owned(), 1),
                (0, "permall".to_owned(), 0),
            ]
        );
    }

    #[test]
    fn delete_error_preservation() {
        let storage = storage_with(crate::types::LibtpmsCallbacks {
            tpm_nvram_deletename: Some(deletename_error),
            ..crate::types::LibtpmsCallbacks::empty()
        });
        assert_eq!(storage.delete(StateBlobKind::SaveState, false), Err(99));
    }

    #[test]
    fn missing_load_probe_unsupported() {
        let probe = storage_with(crate::types::LibtpmsCallbacks::empty()).probe_permanent();
        assert_eq!(probe, StorageProbe::Unsupported);
    }

    #[test]
    fn retry_probe_absence() {
        let _serial = TEST_LOCK.lock().unwrap();
        LOAD_CALLS.lock().unwrap().clear();
        let probe = storage_with(crate::types::LibtpmsCallbacks {
            tpm_nvram_loaddata: Some(loaddata_retry),
            ..crate::types::LibtpmsCallbacks::empty()
        })
        .probe_permanent();
        assert_eq!(probe, StorageProbe::Missing);
        assert_eq!(*LOAD_CALLS.lock().unwrap(), [(0, "permall".to_owned())]);
    }

    #[test]
    fn data_probe_presence() {
        let _serial = TEST_LOCK.lock().unwrap();
        let probe = storage_with(crate::types::LibtpmsCallbacks {
            tpm_nvram_loaddata: Some(loaddata_found),
            ..crate::types::LibtpmsCallbacks::empty()
        })
        .probe_permanent();
        assert_eq!(probe, StorageProbe::Present);
    }

    #[test]
    fn null_probe_presence() {
        let probe = storage_with(crate::types::LibtpmsCallbacks {
            tpm_nvram_loaddata: Some(loaddata_success_null),
            ..crate::types::LibtpmsCallbacks::empty()
        })
        .probe_permanent();
        assert_eq!(probe, StorageProbe::Present);
    }

    #[test]
    fn error_probe_presence() {
        let probe = storage_with(crate::types::LibtpmsCallbacks {
            tpm_nvram_loaddata: Some(loaddata_error_null),
            ..crate::types::LibtpmsCallbacks::empty()
        })
        .probe_permanent();
        assert_eq!(probe, StorageProbe::Present);
    }

    #[test]
    fn error_probe_buffer_release() {
        let probe = storage_with(crate::types::LibtpmsCallbacks {
            tpm_nvram_loaddata: Some(loaddata_error_with_buffer),
            ..crate::types::LibtpmsCallbacks::empty()
        })
        .probe_permanent();
        assert_eq!(probe, StorageProbe::Present);
    }
}
