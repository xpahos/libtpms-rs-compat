mod cached_state;
mod constants;
mod state;
#[cfg(feature = "tpm2")]
mod tpm2;

use core::ffi::{c_char, c_int, c_uchar, c_uint};

use crate::ffi_types::{
    LibtpmsCallbacks, TpmBool, TpmResult, TpmlibBlobType, TpmlibInfoFlags, TpmlibStateType,
    TpmlibTpmProperty, TpmlibTpmVersion,
};
pub use constants::{TPM_FAIL, TPM_SUCCESS};
use state::Library;

const TPM_LIBRARY_VERSION: u32 = 10 << 8 | 1;

pub fn get_version() -> u32 {
    TPM_LIBRARY_VERSION
}

pub fn choose_tpm_version(version: TpmlibTpmVersion) -> TpmResult {
    Library::global().choose_tpm_version(version)
}

pub fn main_init() -> TpmResult {
    Library::global().main_init()
}

pub fn terminate() {
    Library::global().terminate();
}

pub fn process(
    _respbuffer: *mut *mut c_uchar,
    _resp_size: *mut u32,
    _respbufsize: *mut u32,
    _command: *mut c_uchar,
    _command_size: u32,
) -> TpmResult {
    todo!("TPMLIB_Process is not implemented")
}

pub fn volatile_all_store(_buffer: *mut *mut c_uchar, _buflen: *mut u32) -> TpmResult {
    todo!("TPMLIB_VolatileAll_Store is not implemented")
}

pub fn cancel_command() -> TpmResult {
    todo!("TPMLIB_CancelCommand is not implemented")
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn get_tpm_property(prop: TpmlibTpmProperty, result: *mut c_int) -> TpmResult {
    if result.is_null() {
        return TPM_FAIL;
    }
    match Library::global().get_tpm_property(prop) {
        Some(value) => {
            // SAFETY: `result` is non-null and points to a caller-provided int.
            unsafe { *result = value };
            TPM_SUCCESS
        }
        None => TPM_FAIL,
    }
}

pub fn get_info(flags: TpmlibInfoFlags) -> *mut c_char {
    match Library::global().get_info(flags) {
        Some(json) => crate::ffi_support::malloc_c_string(&json),
        None => core::ptr::null_mut(),
    }
}

fn copy_callbacks(callbacks: *const LibtpmsCallbacks) -> LibtpmsCallbacks {
    // SAFETY: the caller guarantees `callbacks` points to a struct whose
    // first field declares how many bytes of it are valid.
    let declared = unsafe { (*callbacks).size_of_struct };
    let copy_len =
        usize::try_from(declared).map_or(0, |n| n.min(core::mem::size_of::<LibtpmsCallbacks>()));
    let mut stored = core::mem::MaybeUninit::<LibtpmsCallbacks>::zeroed();
    // SAFETY: `copy_len` bytes are valid to read per the size contract and
    // fit in `stored`; all-zero bytes are a valid LibtpmsCallbacks (0 size,
    // all callbacks None), so the partial overwrite leaves it valid.
    unsafe {
        core::ptr::copy_nonoverlapping(
            callbacks.cast::<u8>(),
            stored.as_mut_ptr().cast::<u8>(),
            copy_len,
        );
        stored.assume_init()
    }
}

pub fn register_callbacks(callbacks: *mut LibtpmsCallbacks) -> TpmResult {
    if callbacks.is_null() {
        return TPM_FAIL;
    }
    Library::global().register_callbacks(copy_callbacks(callbacks));
    TPM_SUCCESS
}

pub fn decode_blob(
    _data: *const c_char,
    _blob_type: TpmlibBlobType,
    _result: *mut *mut c_uchar,
    _result_len: *mut usize,
) -> TpmResult {
    todo!("TPMLIB_DecodeBlob is not implemented")
}

pub fn set_debug_fd(_fd: c_int) {
    todo!("TPMLIB_SetDebugFD is not implemented")
}

pub fn set_debug_level(_level: c_uint) {
    todo!("TPMLIB_SetDebugLevel is not implemented")
}

pub fn set_debug_prefix(_prefix: *const c_char) -> TpmResult {
    todo!("TPMLIB_SetDebugPrefix is not implemented")
}

pub fn set_buffer_size(_wanted_size: u32, _min_size: *mut u32, _max_size: *mut u32) -> u32 {
    todo!("TPMLIB_SetBufferSize is not implemented")
}

pub fn validate_state(_st: TpmlibStateType, _flags: c_uint) -> TpmResult {
    todo!("TPMLIB_ValidateState is not implemented")
}

pub fn set_state(_st: TpmlibStateType, _buffer: *const c_uchar, _buflen: u32) -> TpmResult {
    todo!("TPMLIB_SetState is not implemented")
}

pub fn get_state(_st: TpmlibStateType, _buffer: *mut *mut c_uchar, _buflen: *mut u32) -> TpmResult {
    todo!("TPMLIB_GetState is not implemented")
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn set_profile(profile: *const c_char) -> TpmResult {
    if profile.is_null() {
        return Library::global().set_profile(None);
    }
    // SAFETY: non-null was just checked; the ABI contract provides a
    // NUL-terminated string that stays valid for the call.
    let bytes = unsafe { core::ffi::CStr::from_ptr(profile) }.to_bytes();
    Library::global().set_profile(Some(bytes))
}

pub fn was_manufactured() -> TpmBool {
    TpmBool::from(Library::global().was_manufactured())
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn dummy_init() -> TpmResult {
        TPM_SUCCESS
    }

    fn full_table() -> LibtpmsCallbacks {
        LibtpmsCallbacks {
            size_of_struct: core::mem::size_of::<LibtpmsCallbacks>() as c_int,
            tpm_nvram_init: Some(dummy_init),
            tpm_io_init: Some(dummy_init),
            ..LibtpmsCallbacks::empty()
        }
    }

    #[test]
    fn full_size_table_round_trips() {
        let table = full_table();
        let stored = copy_callbacks(&table);
        assert_eq!(stored.size_of_struct, table.size_of_struct);
        assert!(stored.tpm_nvram_init.is_some());
        assert!(stored.tpm_io_init.is_some());
        assert!(stored.tpm_nvram_loaddata.is_none());
    }

    #[test]
    fn smaller_declared_size_truncates_copy() {
        let mut table = full_table();
        table.size_of_struct = core::mem::offset_of!(LibtpmsCallbacks, tpm_io_init) as c_int;
        let stored = copy_callbacks(&table);
        assert!(stored.tpm_nvram_init.is_some());
        assert!(stored.tpm_io_init.is_none(), "beyond declared size");
    }

    #[test]
    fn oversized_declared_size_is_capped_to_known_struct() {
        let mut table = full_table();
        table.size_of_struct = i32::MAX;
        let stored = copy_callbacks(&table);
        assert!(stored.tpm_nvram_init.is_some());
        assert!(stored.tpm_io_init.is_some());
    }

    #[test]
    fn negative_declared_size_copies_nothing() {
        let mut table = full_table();
        table.size_of_struct = -1;
        let stored = copy_callbacks(&table);
        assert_eq!(stored.size_of_struct, 0);
        assert!(stored.tpm_nvram_init.is_none());
    }

    #[test]
    fn null_pointer_fails_without_touching_state() {
        assert_eq!(register_callbacks(core::ptr::null_mut()), TPM_FAIL);
    }

    #[test]
    fn buffer_max_is_answered_before_version_dispatch() {
        let mut value: c_int = 0;
        assert_eq!(
            get_tpm_property(constants::TPMPROP_TPM_BUFFER_MAX, &mut value),
            TPM_SUCCESS
        );
        assert_eq!(value, 4096);
    }

    #[test]
    fn property_null_result_pointer_fails() {
        assert_eq!(
            get_tpm_property(constants::TPMPROP_TPM_BUFFER_MAX, core::ptr::null_mut()),
            TPM_FAIL
        );
    }
}
