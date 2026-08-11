use core::ffi::{c_char, c_int, c_uchar, c_uint};

use crate::ffi_types::{
    LibtpmsCallbacks, TpmBool, TpmResult, TpmlibBlobType, TpmlibInfoFlags, TpmlibStateType,
    TpmlibTpmProperty, TpmlibTpmVersion,
};
use crate::library::{self, TPM_FAIL, TPM_SUCCESS};

pub(crate) fn get_version() -> u32 {
    library::get_version()
}

pub(crate) fn choose_tpm_version(version: TpmlibTpmVersion) -> TpmResult {
    library::choose_tpm_version(version)
}

pub(crate) fn main_init() -> TpmResult {
    library::main_init()
}

pub(crate) fn terminate() {
    library::terminate();
}

pub(crate) unsafe fn process(
    _respbuffer: *mut *mut c_uchar,
    _resp_size: *mut u32,
    _respbufsize: *mut u32,
    _command: *mut c_uchar,
    _command_size: u32,
) -> TpmResult {
    todo!("TPMLIB_Process is not implemented")
}

pub(crate) unsafe fn volatile_all_store(
    _buffer: *mut *mut c_uchar,
    _buflen: *mut u32,
) -> TpmResult {
    todo!("TPMLIB_VolatileAll_Store is not implemented")
}

pub(crate) fn cancel_command() -> TpmResult {
    todo!("TPMLIB_CancelCommand is not implemented")
}

pub(crate) unsafe fn get_tpm_property(prop: TpmlibTpmProperty, result: *mut c_int) -> TpmResult {
    if result.is_null() {
        return TPM_FAIL;
    }
    match library::get_tpm_property(prop) {
        Some(value) => {
            // SAFETY: the C API contract requires `result` to point to a
            // writable int; the null case was rejected above.
            unsafe { result.write(value) };
            TPM_SUCCESS
        }
        None => TPM_FAIL,
    }
}

pub(crate) fn get_info(flags: TpmlibInfoFlags) -> *mut c_char {
    match library::get_info(flags) {
        Some(json) => crate::ffi_support::malloc_c_string(&json),
        None => core::ptr::null_mut(),
    }
}

unsafe fn copy_callbacks(callbacks: *const LibtpmsCallbacks) -> LibtpmsCallbacks {
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

pub(crate) unsafe fn register_callbacks(callbacks: *mut LibtpmsCallbacks) -> TpmResult {
    if callbacks.is_null() {
        return TPM_FAIL;
    }
    // SAFETY: forwarded from TPMLIB_RegisterCallbacks after the null check.
    library::register_callbacks(unsafe { copy_callbacks(callbacks) });
    TPM_SUCCESS
}

pub(crate) unsafe fn decode_blob(
    _data: *const c_char,
    _blob_type: TpmlibBlobType,
    _result: *mut *mut c_uchar,
    _result_len: *mut usize,
) -> TpmResult {
    todo!("TPMLIB_DecodeBlob is not implemented")
}

pub(crate) fn set_debug_fd(_fd: c_int) {
    todo!("TPMLIB_SetDebugFD is not implemented")
}

pub(crate) fn set_debug_level(_level: c_uint) {
    todo!("TPMLIB_SetDebugLevel is not implemented")
}

pub(crate) unsafe fn set_debug_prefix(_prefix: *const c_char) -> TpmResult {
    todo!("TPMLIB_SetDebugPrefix is not implemented")
}

pub(crate) unsafe fn set_buffer_size(
    _wanted_size: u32,
    _min_size: *mut u32,
    _max_size: *mut u32,
) -> u32 {
    todo!("TPMLIB_SetBufferSize is not implemented")
}

pub(crate) fn validate_state(_st: TpmlibStateType, _flags: c_uint) -> TpmResult {
    todo!("TPMLIB_ValidateState is not implemented")
}

pub(crate) unsafe fn set_state(
    _st: TpmlibStateType,
    _buffer: *const c_uchar,
    _buflen: u32,
) -> TpmResult {
    todo!("TPMLIB_SetState is not implemented")
}

pub(crate) unsafe fn get_state(
    _st: TpmlibStateType,
    _buffer: *mut *mut c_uchar,
    _buflen: *mut u32,
) -> TpmResult {
    todo!("TPMLIB_GetState is not implemented")
}

pub(crate) unsafe fn set_profile(profile: *const c_char) -> TpmResult {
    if profile.is_null() {
        return library::set_profile(None);
    }
    // SAFETY: the C API contract requires a non-null, NUL-terminated string
    // that remains valid for this call; the null case was handled above.
    let bytes = unsafe { core::ffi::CStr::from_ptr(profile) }.to_bytes();
    library::set_profile(Some(bytes))
}

pub(crate) fn was_manufactured() -> TpmBool {
    TpmBool::from(library::was_manufactured())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUFFER_MAX_PROPERTY: TpmlibTpmProperty = 2;

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
        // SAFETY: `table` is a live, full-size callback table.
        let stored = unsafe { copy_callbacks(&table) };
        assert_eq!(stored.size_of_struct, table.size_of_struct);
        assert!(stored.tpm_nvram_init.is_some());
        assert!(stored.tpm_io_init.is_some());
        assert!(stored.tpm_nvram_loaddata.is_none());
    }

    #[test]
    fn smaller_declared_size_truncates_copy() {
        let mut table = full_table();
        table.size_of_struct = core::mem::offset_of!(LibtpmsCallbacks, tpm_io_init) as c_int;
        // SAFETY: `table` has at least the number of live bytes it declares.
        let stored = unsafe { copy_callbacks(&table) };
        assert!(stored.tpm_nvram_init.is_some());
        assert!(stored.tpm_io_init.is_none(), "beyond declared size");
    }

    #[test]
    fn oversized_declared_size_is_capped_to_known_struct() {
        let mut table = full_table();
        table.size_of_struct = i32::MAX;
        // SAFETY: the implementation caps the read to the live table size.
        let stored = unsafe { copy_callbacks(&table) };
        assert!(stored.tpm_nvram_init.is_some());
        assert!(stored.tpm_io_init.is_some());
    }

    #[test]
    fn negative_declared_size_copies_nothing() {
        let mut table = full_table();
        table.size_of_struct = -1;
        // SAFETY: reading the first field of the live table is valid.
        let stored = unsafe { copy_callbacks(&table) };
        assert_eq!(stored.size_of_struct, 0);
        assert!(stored.tpm_nvram_init.is_none());
    }

    #[test]
    fn null_callbacks_pointer_fails_without_touching_state() {
        // SAFETY: NULL is explicitly accepted and rejected by the adapter.
        assert_eq!(
            unsafe { register_callbacks(core::ptr::null_mut()) },
            TPM_FAIL
        );
    }

    #[test]
    fn property_is_written_to_c_output_pointer() {
        let mut value: c_int = 0;
        // SAFETY: `value` is a live, writable c_int.
        assert_eq!(
            unsafe { get_tpm_property(BUFFER_MAX_PROPERTY, &mut value) },
            TPM_SUCCESS
        );
        assert_eq!(value, 4096);
    }

    #[test]
    fn null_property_output_pointer_fails() {
        // SAFETY: NULL is explicitly accepted and rejected by the adapter.
        assert_eq!(
            unsafe { get_tpm_property(BUFFER_MAX_PROPERTY, core::ptr::null_mut()) },
            TPM_FAIL
        );
    }
}
