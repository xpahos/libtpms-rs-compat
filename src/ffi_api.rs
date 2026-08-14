use core::ffi::{c_char, c_int, c_uchar, c_uint};

use crate::ffi_types::{
    LibtpmsCallbacks, TpmBool, TpmResult, TpmlibBlobType, TpmlibInfoFlags, TpmlibStateType,
    TpmlibTpmProperty, TpmlibTpmVersion,
};
#[cfg(feature = "tpm2")]
use crate::library::TPM_SIZE;
use crate::library::{self, TPM_FAIL, TPM_SUCCESS};

#[cfg(feature = "tpm2")]
const RESPONSE_BUFFER_SIZE: usize = library::TPM_BUFFER_MAX as usize;

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
    respbuffer: *mut *mut c_uchar,
    resp_size: *mut u32,
    respbufsize: *mut u32,
    command: *mut c_uchar,
    command_size: u32,
) -> TpmResult {
    if respbuffer.is_null() || resp_size.is_null() || respbufsize.is_null() {
        return TPM_FAIL;
    }
    if command.is_null() && command_size != 0 {
        return TPM_FAIL;
    }
    match library::prepare_process() {
        library::ProcessPreparation::Disabled => TPM_FAIL,
        #[cfg(feature = "tpm2")]
        library::ProcessPreparation::Tpm2(context) => {
            let prefix_len = library::CommandInput::required_prefix_len(command_size);
            let command_input = library::CommandInput::new(
                command_size,
                if prefix_len == 0 {
                    Vec::new()
                } else {
                    // SAFETY: `command` is non-null and points to at least
                    // `prefix_len <= command_size` readable bytes by the
                    // FFI contract.
                    unsafe { core::slice::from_raw_parts(command, prefix_len) }.to_vec()
                },
            );
            // SAFETY: the output pointers were null-checked above and
            // `*respbuffer` is null or caller-owned by the FFI contract.
            if let Err(code) = unsafe { ensure_response_buffer(respbuffer, respbufsize) } {
                return code;
            }
            match context.execute(&command_input) {
                // SAFETY: null-checked above; `ensure_response_buffer`
                // left `*respbuffer` with `*respbufsize` writable bytes.
                Ok(response) => unsafe {
                    copy_response(respbuffer, resp_size, respbufsize, &response)
                },
                Err(code) => code,
            }
        }
    }
}

/// # Safety
///
/// `respbuffer` and `respbufsize` must be non-null and writable, and
/// `*respbuffer` must be null or a caller-owned C-allocator allocation.
#[cfg(feature = "tpm2")]
unsafe fn ensure_response_buffer(
    respbuffer: *mut *mut c_uchar,
    respbufsize: *mut u32,
) -> Result<(), TpmResult> {
    // SAFETY: the pointers are valid per this function's contract, and
    // `*respbuffer` may be passed to realloc.
    unsafe {
        if (*respbufsize as usize) < RESPONSE_BUFFER_SIZE || (*respbuffer).is_null() {
            let grown = libc::realloc((*respbuffer).cast(), RESPONSE_BUFFER_SIZE);
            if grown.is_null() {
                return Err(TPM_SIZE);
            }
            *respbuffer = grown.cast();
            *respbufsize = RESPONSE_BUFFER_SIZE as u32;
        }
    }
    Ok(())
}

/// # Safety
///
/// All three pointers must be non-null and writable, and `*respbuffer`
/// must hold at least `*respbufsize` writable bytes.
#[cfg(feature = "tpm2")]
unsafe fn copy_response(
    respbuffer: *mut *mut c_uchar,
    resp_size: *mut u32,
    respbufsize: *mut u32,
    response: &[u8],
) -> TpmResult {
    // SAFETY: the pointers are valid per this function's contract and the
    // capacity check keeps the copy within `*respbuffer`.
    unsafe {
        if response.len() > *respbufsize as usize {
            return TPM_FAIL;
        }
        core::ptr::copy_nonoverlapping(response.as_ptr(), *respbuffer, response.len());
        *resp_size = response.len() as u32;
    }
    TPM_SUCCESS
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

pub(crate) fn set_debug_fd(fd: c_int) {
    crate::debug_logging::set_fd(fd);
}

pub(crate) fn set_debug_level(level: c_uint) {
    crate::debug_logging::set_level(level);
}

pub(crate) unsafe fn set_debug_prefix(prefix: *const c_char) -> TpmResult {
    if prefix.is_null() {
        return crate::debug_logging::set_prefix(None);
    }
    // SAFETY: the C API contract requires a non-null, NUL-terminated string
    // that remains valid for this call; the null case was handled above.
    crate::debug_logging::set_prefix(Some(unsafe { core::ffi::CStr::from_ptr(prefix) }))
}

pub(crate) unsafe fn set_buffer_size(
    wanted_size: u32,
    min_size: *mut u32,
    max_size: *mut u32,
) -> u32 {
    // SAFETY: forwarded from TPMLIB_SetBufferSize, whose contract allows both
    // output pointers to be null and otherwise requires them to be writable.
    unsafe { report_buffer_size(library::set_buffer_size(wanted_size), min_size, max_size) }
}

/// # Safety
///
/// `min_size` and `max_size` must each be null or point to a writable u32.
unsafe fn report_buffer_size(
    limits: Option<library::BufferSizeLimits>,
    min_size: *mut u32,
    max_size: *mut u32,
) -> u32 {
    let Some(limits) = limits else {
        return 0;
    };
    if !min_size.is_null() {
        // SAFETY: non-null implies writable per this function's contract.
        unsafe { min_size.write(limits.minimum) };
    }
    if !max_size.is_null() {
        // SAFETY: non-null implies writable per this function's contract.
        unsafe { max_size.write(limits.maximum) };
    }
    limits.current
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

pub(crate) fn tpm_io_hash_start() -> TpmResult {
    library::tis_hash_start()
}

pub(crate) unsafe fn tpm_io_hash_data(data: *const c_uchar, data_length: u32) -> TpmResult {
    if data.is_null() {
        if data_length != 0 {
            return TPM_FAIL;
        }
        return library::tis_hash_data(&[]);
    }
    // SAFETY: `data` is non-null and points to `data_length` readable bytes
    // by the FFI contract.
    let bytes = unsafe { core::slice::from_raw_parts(data, data_length as usize) };
    library::tis_hash_data(bytes)
}

pub(crate) fn tpm_io_hash_end() -> TpmResult {
    library::tis_hash_end()
}

pub(crate) unsafe fn tpm_io_tpm_established_get(tpm_established: *mut TpmBool) -> TpmResult {
    if tpm_established.is_null() {
        return TPM_FAIL;
    }
    match library::tis_established_get() {
        Ok(established) => {
            // SAFETY: the C API contract requires `tpm_established` to point
            // to a writable TPM_BOOL; the null case was rejected above.
            unsafe { tpm_established.write(TpmBool::from(established)) };
            TPM_SUCCESS
        }
        Err(code) => code,
    }
}

pub(crate) fn tpm_io_tpm_established_reset() -> TpmResult {
    library::tis_established_reset()
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
    fn tis_abi_signatures_are_exact() {
        let _: unsafe extern "C" fn() -> TpmResult = crate::tpm_tis_abi::TPM_IO_Hash_Start;
        let _: unsafe extern "C" fn(*const c_uchar, u32) -> TpmResult =
            crate::tpm_tis_abi::TPM_IO_Hash_Data;
        let _: unsafe extern "C" fn() -> TpmResult = crate::tpm_tis_abi::TPM_IO_Hash_End;
        let _: unsafe extern "C" fn(*mut TpmBool) -> TpmResult =
            crate::tpm_tis_abi::TPM_IO_TpmEstablished_Get;
        let _: unsafe extern "C" fn() -> TpmResult =
            crate::tpm_tis_abi::TPM_IO_TpmEstablished_Reset;
    }

    #[test]
    fn tis_null_established_output_pointer_fails_safely() {
        // SAFETY: NULL is explicitly accepted and rejected by the adapter.
        assert_eq!(
            unsafe { tpm_io_tpm_established_get(core::ptr::null_mut()) },
            TPM_FAIL
        );
        // SAFETY: same, through the exported wrapper and its panic guard.
        assert_eq!(
            unsafe { crate::tpm_tis_abi::TPM_IO_TpmEstablished_Get(core::ptr::null_mut()) },
            TPM_FAIL
        );
    }

    #[test]
    fn tis_null_hash_data_is_valid_only_for_zero_length() {
        // SAFETY: a null pointer with a nonzero length is rejected before any
        // dereference.
        unsafe {
            assert_eq!(tpm_io_hash_data(core::ptr::null(), 1), TPM_FAIL);
            assert_eq!(tpm_io_hash_data(core::ptr::null(), u32::MAX), TPM_FAIL);
            assert_eq!(
                crate::tpm_tis_abi::TPM_IO_Hash_Data(core::ptr::null(), 4),
                TPM_FAIL
            );
        }
        // SAFETY: a null pointer with zero length carries no bytes to read;
        // the result depends on the shared global library state, which other
        // tests may have initialized concurrently.
        let result = unsafe { tpm_io_hash_data(core::ptr::null(), 0) };
        assert!(result == TPM_FAIL || result == TPM_SUCCESS);
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

    const NO_LIMITS: Option<library::BufferSizeLimits> = None;
    const TPM2_LIMITS: Option<library::BufferSizeLimits> = Some(library::BufferSizeLimits {
        current: 3000,
        minimum: 2808,
        maximum: 4096,
    });

    #[test]
    fn buffer_size_limits_reach_both_c_output_pointers() {
        let mut min: u32 = 0xdead_beef;
        let mut max: u32 = 0xfeed_face;
        // SAFETY: both outputs are live, writable u32s.
        let current = unsafe { report_buffer_size(TPM2_LIMITS, &mut min, &mut max) };
        assert_eq!(current, 3000);
        assert_eq!(min, 2808);
        assert_eq!(max, 4096);
    }

    #[test]
    fn every_null_output_pointer_combination_is_safe() {
        let mut min: u32 = 0xdead_beef;
        let mut max: u32 = 0xfeed_face;
        // SAFETY: null is explicitly permitted for either output pointer, and
        // the non-null arguments reference live, writable u32s.
        unsafe {
            assert_eq!(
                report_buffer_size(TPM2_LIMITS, core::ptr::null_mut(), core::ptr::null_mut()),
                3000
            );
            assert_eq!(
                report_buffer_size(TPM2_LIMITS, &mut min, core::ptr::null_mut()),
                3000
            );
            assert_eq!(min, 2808);
            min = 0xdead_beef;
            assert_eq!(
                report_buffer_size(TPM2_LIMITS, core::ptr::null_mut(), &mut max),
                3000
            );
        }
        assert_eq!(min, 0xdead_beef, "a null minimum output is never written");
        assert_eq!(max, 4096);
    }

    #[test]
    fn a_disabled_implementation_answers_zero_and_writes_nothing() {
        let mut min: u32 = 0xdead_beef;
        let mut max: u32 = 0xfeed_face;
        // SAFETY: both outputs are live, writable u32s; null is permitted too.
        unsafe {
            assert_eq!(report_buffer_size(NO_LIMITS, &mut min, &mut max), 0);
            assert_eq!(
                report_buffer_size(NO_LIMITS, core::ptr::null_mut(), core::ptr::null_mut()),
                0
            );
        }
        assert_eq!(min, 0xdead_beef);
        assert_eq!(max, 0xfeed_face);
    }

    #[test]
    fn the_exported_set_buffer_size_never_panics_on_null_outputs() {
        let mut min: u32 = 0xdead_beef;
        let mut max: u32 = 0xfeed_face;
        // SAFETY: the wanted sizes below either query or request the
        // compile-time maximum, so the shared global library state other tests
        // observe cannot change; null outputs are explicitly permitted.
        let current = unsafe {
            for wanted_size in [0u32, 4096] {
                crate::tpm_library_abi::TPMLIB_SetBufferSize(
                    wanted_size,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                );
                crate::tpm_library_abi::TPMLIB_SetBufferSize(
                    wanted_size,
                    &mut min,
                    core::ptr::null_mut(),
                );
                crate::tpm_library_abi::TPMLIB_SetBufferSize(
                    wanted_size,
                    core::ptr::null_mut(),
                    &mut max,
                );
            }
            crate::tpm_library_abi::TPMLIB_SetBufferSize(0, &mut min, &mut max)
        };
        if current == 0 {
            assert_eq!(min, 0xdead_beef, "a disabled TPM writes no minimum");
            assert_eq!(max, 0xfeed_face, "a disabled TPM writes no maximum");
        } else {
            assert_eq!(current, 4096);
            assert_eq!(min, 2808);
            assert_eq!(max, 4096);
        }
    }

    #[test]
    fn debug_fd_and_level_reach_the_debug_configuration() {
        let _state = crate::debug_logging::test_support::DebugStateGuard::hold();
        set_debug_fd(21);
        set_debug_level(4);
        assert_eq!(crate::debug_logging::fd_and_level(), (21, 4));
    }

    #[test]
    fn debug_prefix_is_owned_replaced_and_cleared() {
        let _state = crate::debug_logging::test_support::DebugStateGuard::hold();
        let mut caller = b"first\0".to_vec();
        // SAFETY: `caller` is NUL-terminated and remains live for the call.
        assert_eq!(
            unsafe { set_debug_prefix(caller.as_ptr().cast()) },
            TPM_SUCCESS
        );
        caller[0] = b'X';
        assert_eq!(
            crate::debug_logging::prefix().as_deref(),
            Some(b"first".as_slice())
        );

        // SAFETY: the byte string is statically live and NUL-terminated.
        assert_eq!(unsafe { set_debug_prefix(c"second".as_ptr()) }, TPM_SUCCESS);
        assert_eq!(
            crate::debug_logging::prefix().as_deref(),
            Some(b"second".as_slice())
        );

        // SAFETY: NULL clears the prefix without being dereferenced.
        assert_eq!(unsafe { set_debug_prefix(core::ptr::null()) }, TPM_SUCCESS);
        assert_eq!(crate::debug_logging::prefix(), None);

        // SAFETY: the byte string is statically live and NUL-terminated.
        assert_eq!(unsafe { set_debug_prefix(c"".as_ptr()) }, TPM_SUCCESS);
        assert_eq!(
            crate::debug_logging::prefix().as_deref(),
            Some(b"".as_slice())
        );

        // SAFETY: restore the process-global setting for other tests.
        assert_eq!(unsafe { set_debug_prefix(core::ptr::null()) }, TPM_SUCCESS);
    }

    struct ProcessOutputs {
        respbuffer: *mut c_uchar,
        resp_size: u32,
        respbufsize: u32,
    }

    impl ProcessOutputs {
        fn new() -> Self {
            Self {
                respbuffer: core::ptr::null_mut(),
                resp_size: 0xdead_beef,
                respbufsize: 0,
            }
        }

        #[cfg(feature = "tpm2")]
        fn call(&mut self, command: &[u8]) -> TpmResult {
            // SAFETY: output pointers reference live fields and `command`
            // remains readable for the duration of the call.
            unsafe {
                process(
                    &mut self.respbuffer,
                    &mut self.resp_size,
                    &mut self.respbufsize,
                    command.as_ptr().cast_mut(),
                    command.len() as u32,
                )
            }
        }

        #[cfg(feature = "tpm2")]
        fn response(&self) -> &[u8] {
            assert!(!self.respbuffer.is_null());
            assert!(self.resp_size <= self.respbufsize);
            // SAFETY: `respbuffer` owns at least `respbufsize` bytes and the
            // assertions bound the returned slice to initialized response bytes.
            unsafe { core::slice::from_raw_parts(self.respbuffer, self.resp_size as usize) }
        }
    }

    impl Drop for ProcessOutputs {
        fn drop(&mut self) {
            // SAFETY: the pointer is null or was allocated through the C
            // allocator used by `process`.
            unsafe { libc::free(self.respbuffer.cast()) };
        }
    }

    const STARTUP_COMMAND: [u8; 12] = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
    ];
    #[cfg(feature = "tpm2")]
    const UNKNOWN_COMMAND: [u8; 10] = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x20, 0x00, 0x00, 0x00];
    #[cfg(feature = "tpm2")]
    const UNSUPPORTED_RESPONSE: [u8; 10] =
        [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x43];
    #[cfg(feature = "tpm2")]
    const INSUFFICIENT_RESPONSE: [u8; 10] =
        [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x9a];
    #[cfg(feature = "tpm2")]
    const COMMAND_SIZE_RESPONSE: [u8; 10] =
        [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x42];
    #[cfg(feature = "tpm2")]
    const BAD_TAG_RESPONSE: [u8; 10] = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x1e];

    #[test]
    fn process_rejects_null_output_pointers_without_touching_the_rest() {
        let mut command = STARTUP_COMMAND;
        let mut buffer: *mut c_uchar = core::ptr::null_mut();
        let mut resp_size: u32 = 0xdead_beef;
        let mut respbufsize: u32 = 0xfeed_face;
        // SAFETY: every non-null argument points to a live local; each call
        // intentionally tests one null output pointer.
        unsafe {
            assert_eq!(
                process(
                    core::ptr::null_mut(),
                    &mut resp_size,
                    &mut respbufsize,
                    command.as_mut_ptr(),
                    command.len() as u32,
                ),
                TPM_FAIL
            );
            assert_eq!(
                process(
                    &mut buffer,
                    core::ptr::null_mut(),
                    &mut respbufsize,
                    command.as_mut_ptr(),
                    command.len() as u32,
                ),
                TPM_FAIL
            );
            assert_eq!(
                process(
                    &mut buffer,
                    &mut resp_size,
                    core::ptr::null_mut(),
                    command.as_mut_ptr(),
                    command.len() as u32,
                ),
                TPM_FAIL
            );
        }
        assert!(buffer.is_null());
        assert_eq!(resp_size, 0xdead_beef);
        assert_eq!(respbufsize, 0xfeed_face);
    }

    #[test]
    fn process_rejects_a_null_command_with_nonzero_size_without_output_updates() {
        let mut outputs = ProcessOutputs::new();
        // SAFETY: output pointers reference live fields; the null command is
        // rejected before it can be dereferenced.
        let result = unsafe {
            process(
                &mut outputs.respbuffer,
                &mut outputs.resp_size,
                &mut outputs.respbufsize,
                core::ptr::null_mut(),
                STARTUP_COMMAND.len() as u32,
            )
        };
        assert_eq!(result, TPM_FAIL);
        assert!(outputs.respbuffer.is_null());
        assert_eq!(outputs.resp_size, 0xdead_beef);
        assert_eq!(outputs.respbufsize, 0);
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn process_end_to_end_follows_the_c_buffer_and_response_contract() {
        const TPMLIB_TPM_VERSION_2: crate::ffi_types::TpmlibTpmVersion = 1;
        const TPM_BUFFER_MAX: u32 = RESPONSE_BUFFER_SIZE as u32;

        let mut outputs = ProcessOutputs::new();
        assert_eq!(outputs.call(&STARTUP_COMMAND), TPM_FAIL);
        assert!(outputs.respbuffer.is_null());
        assert_eq!(outputs.resp_size, 0xdead_beef);
        assert_eq!(outputs.respbufsize, 0);

        assert_eq!(choose_tpm_version(TPMLIB_TPM_VERSION_2), TPM_SUCCESS);
        assert_eq!(outputs.call(&STARTUP_COMMAND), TPM_SUCCESS);
        assert!(!outputs.respbuffer.is_null());
        assert_eq!(outputs.respbufsize, TPM_BUFFER_MAX);
        assert_eq!(outputs.resp_size, 0);
        let grown_buffer = outputs.respbuffer;

        crate::library::stage_empty_permanent_state_for_tests();
        assert_eq!(main_init(), TPM_SUCCESS);

        assert_eq!(outputs.call(&UNKNOWN_COMMAND), TPM_SUCCESS);
        assert_eq!(
            outputs.respbuffer, grown_buffer,
            "a TPM_BUFFER_MAX-sized buffer is not reallocated"
        );
        assert_eq!(outputs.respbufsize, TPM_BUFFER_MAX);
        assert_eq!(outputs.response(), UNSUPPORTED_RESPONSE);

        assert_eq!(outputs.call(&[0x80, 0x01, 0x00]), TPM_SUCCESS);
        assert_eq!(outputs.response(), INSUFFICIENT_RESPONSE);

        // SAFETY: output pointers reference live fields and a null command is
        // valid when its size is zero.
        let result = unsafe {
            process(
                &mut outputs.respbuffer,
                &mut outputs.resp_size,
                &mut outputs.respbufsize,
                core::ptr::null_mut(),
                0,
            )
        };
        assert_eq!(result, TPM_SUCCESS);
        assert_eq!(outputs.response(), INSUFFICIENT_RESPONSE);

        let mut small = ProcessOutputs::new();
        small.respbuffer = crate::ffi_support::malloc_bytes(&[0u8; 16]);
        small.respbufsize = 16;
        assert_eq!(small.call(&UNKNOWN_COMMAND), TPM_SUCCESS);
        assert_eq!(small.respbufsize, TPM_BUFFER_MAX);
        assert_eq!(small.response(), UNSUPPORTED_RESPONSE);
        drop(small);

        let mut large = ProcessOutputs::new();
        large.respbuffer = crate::ffi_support::malloc_bytes(&[0u8; 2 * RESPONSE_BUFFER_SIZE]);
        large.respbufsize = 2 * TPM_BUFFER_MAX;
        let large_buffer = large.respbuffer;
        assert_eq!(large.call(&UNKNOWN_COMMAND), TPM_SUCCESS);
        assert_eq!(large.respbuffer, large_buffer);
        assert_eq!(large.respbufsize, 2 * TPM_BUFFER_MAX);
        assert_eq!(large.response(), UNSUPPORTED_RESPONSE);
        drop(large);

        let mut shared = ProcessOutputs::new();
        shared.respbuffer = crate::ffi_support::malloc_bytes(&UNKNOWN_COMMAND);
        shared.respbufsize = UNKNOWN_COMMAND.len() as u32;
        let shared_command = shared.respbuffer;
        // SAFETY: the command and response share one live allocation; the
        // implementation owns the command bytes before reallocating it.
        let result = unsafe {
            process(
                &mut shared.respbuffer,
                &mut shared.resp_size,
                &mut shared.respbufsize,
                shared_command,
                UNKNOWN_COMMAND.len() as u32,
            )
        };
        assert_eq!(result, TPM_SUCCESS);
        assert_eq!(shared.respbufsize, TPM_BUFFER_MAX);
        assert_eq!(shared.response(), UNSUPPORTED_RESPONSE);
        drop(shared);

        let mut shared = ProcessOutputs::new();
        let mut contents = [0u8; RESPONSE_BUFFER_SIZE];
        contents[..UNKNOWN_COMMAND.len()].copy_from_slice(&UNKNOWN_COMMAND);
        shared.respbuffer = crate::ffi_support::malloc_bytes(&contents);
        shared.respbufsize = TPM_BUFFER_MAX;
        let shared_command = shared.respbuffer;
        // SAFETY: the shared allocation contains the complete command and is
        // large enough for both request and response.
        let result = unsafe {
            process(
                &mut shared.respbuffer,
                &mut shared.resp_size,
                &mut shared.respbufsize,
                shared_command,
                UNKNOWN_COMMAND.len() as u32,
            )
        };
        assert_eq!(result, TPM_SUCCESS);
        assert_eq!(shared.respbuffer, shared_command, "reused in place");
        assert_eq!(shared.response(), UNSUPPORTED_RESPONSE);

        shared.respbufsize = 3;
        let shared_command = shared.respbuffer;
        // SAFETY: the first three bytes of the shared allocation are readable;
        // the call owns them before any possible reallocation.
        let result = unsafe {
            process(
                &mut shared.respbuffer,
                &mut shared.resp_size,
                &mut shared.respbufsize,
                shared_command,
                3,
            )
        };
        assert_eq!(result, TPM_SUCCESS);
        assert_eq!(shared.respbufsize, TPM_BUFFER_MAX);
        assert_eq!(shared.response(), INSUFFICIENT_RESPONSE);
        drop(shared);

        let mut outputs2 = ProcessOutputs::new();
        for (prefix, expected) in [
            (
                [0x80u8, 0x01, 0xff, 0xff, 0xff, 0xff],
                COMMAND_SIZE_RESPONSE,
            ),
            ([0x12u8, 0x34, 0xff, 0xff, 0xff, 0xff], BAD_TAG_RESPONSE),
        ] {
            // SAFETY: oversized requests inspect only the six-byte prefix,
            // which is fully backed by `prefix` for this call.
            let result = unsafe {
                process(
                    &mut outputs2.respbuffer,
                    &mut outputs2.resp_size,
                    &mut outputs2.respbufsize,
                    prefix.as_ptr().cast_mut(),
                    u32::MAX,
                )
            };
            assert_eq!(result, TPM_SUCCESS);
            assert_eq!(outputs2.response(), expected);
        }

        let mut shared = ProcessOutputs::new();
        shared.respbuffer = crate::ffi_support::malloc_bytes(&[0x80, 0x01, 0x00, 0x01, 0x00, 0x00]);
        shared.respbufsize = 6;
        let shared_command = shared.respbuffer;
        // SAFETY: oversized input requires only the six-byte prefix stored in
        // the live shared allocation before it may be reallocated.
        let result = unsafe {
            process(
                &mut shared.respbuffer,
                &mut shared.resp_size,
                &mut shared.respbufsize,
                shared_command,
                0x0001_0000,
            )
        };
        assert_eq!(result, TPM_SUCCESS);
        assert_eq!(shared.respbufsize, TPM_BUFFER_MAX);
        assert_eq!(shared.response(), COMMAND_SIZE_RESPONSE);
        drop(shared);

        let mut max_command = vec![0u8; RESPONSE_BUFFER_SIZE];
        max_command[..2].copy_from_slice(&[0x80, 0x01]);
        max_command[2..6].copy_from_slice(&(RESPONSE_BUFFER_SIZE as u32).to_be_bytes());
        max_command[6..10].copy_from_slice(&[0x20, 0x00, 0x00, 0x00]);
        assert_eq!(outputs2.call(&max_command), TPM_SUCCESS);
        assert_eq!(outputs2.response(), UNSUPPORTED_RESPONSE);

        let mut over_command = vec![0u8; RESPONSE_BUFFER_SIZE + 1];
        over_command[..2].copy_from_slice(&[0x80, 0x01]);
        over_command[2..6].copy_from_slice(&(RESPONSE_BUFFER_SIZE as u32 + 1).to_be_bytes());
        over_command[6..10].copy_from_slice(&[0x20, 0x00, 0x00, 0x00]);
        assert_eq!(outputs2.call(&over_command), TPM_SUCCESS);
        assert_eq!(outputs2.response(), COMMAND_SIZE_RESPONSE);
        drop(outputs2);

        terminate();
        assert_eq!(outputs.call(&STARTUP_COMMAND), TPM_SUCCESS);
        assert_eq!(outputs.resp_size, 0);
    }
}
