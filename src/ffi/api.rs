use core::ffi::{c_char, c_int, c_uchar, c_uint};

use std::sync::Arc;

use crate::ffi::platform::CallbackPlatform;
use crate::ffi::storage::CallbackStorage;
use crate::library::{
    self, EncodedBlobKind, ExternalServices, StateBlobKind, StateInput, StateOutput,
    StateValidationMask, TPM_FAIL, TPM_SIZE, TPM_SUCCESS,
};
use crate::types::{
    LibtpmsCallbacks, TpmBool, TpmResult, TpmlibBlobType, TpmlibInfoFlags, TpmlibStateType,
    TpmlibTpmProperty, TpmlibTpmVersion,
};

const BUFLEN_EMPTY_BUFFER: u32 = 0xffff_ffff;

const TPMLIB_BLOB_TYPE_INITSTATE: TpmlibBlobType = 0;

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
    #[cfg(feature = "tpm2")]
    {
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
        if !library::tpm2_selected() {
            return TPM_FAIL;
        }
        // SAFETY: the output pointers were null-checked above and
        // `*respbuffer` is null or caller-owned by the FFI contract.
        let prepared = match unsafe { PreparedResponseBuffer::for_outputs(respbuffer, respbufsize) }
        {
            Ok(prepared) => prepared,
            Err(code) => return code,
        };
        match library::process(&command_input) {
            // SAFETY: null-checked above; `publish` leaves `*respbuffer`
            // with at least `*respbufsize` writable bytes, and the command
            // bytes were copied before the old allocation can be freed.
            Ok(response) => unsafe {
                prepared.publish(respbuffer, respbufsize);
                copy_response(respbuffer, resp_size, respbufsize, &response)
            },
            Err(code) => code,
        }
    }
    #[cfg(not(feature = "tpm2"))]
    {
        let _ = (command, command_size);
        TPM_FAIL
    }
}

#[cfg(all(test, feature = "tpm2"))]
thread_local! {
    static RESPONSE_ALLOCATION_OVERRIDE: core::cell::RefCell<
        Option<Box<dyn FnMut() -> *mut c_uchar>>,
    > = const { core::cell::RefCell::new(None) };
}

#[cfg(feature = "tpm2")]
fn allocate_response_buffer() -> *mut c_uchar {
    #[cfg(test)]
    {
        let overridden =
            RESPONSE_ALLOCATION_OVERRIDE.with(|hook| hook.borrow_mut().as_mut().map(|hook| hook()));
        if let Some(replacement) = overridden {
            return replacement;
        }
    }
    // SAFETY: a plain C allocation of a nonzero constant size.
    unsafe { libc::malloc(RESPONSE_BUFFER_SIZE).cast() }
}

#[cfg(feature = "tpm2")]
struct PreparedResponseBuffer {
    replacement: *mut c_uchar,
}

#[cfg(feature = "tpm2")]
impl PreparedResponseBuffer {
    /// # Safety
    ///
    /// `respbuffer` and `respbufsize` must be non-null and readable, and
    /// `*respbuffer` must be null or a caller-owned C-allocator allocation
    /// holding at least `*respbufsize` bytes.
    unsafe fn for_outputs(
        respbuffer: *mut *mut c_uchar,
        respbufsize: *mut u32,
    ) -> Result<Self, TpmResult> {
        // SAFETY: the pointers are readable per this function's contract.
        let sufficient =
            unsafe { !(*respbuffer).is_null() && (*respbufsize as usize) >= RESPONSE_BUFFER_SIZE };
        if sufficient {
            return Ok(Self {
                replacement: core::ptr::null_mut(),
            });
        }
        let replacement = allocate_response_buffer();
        if replacement.is_null() {
            return Err(TPM_SIZE);
        }
        Ok(Self { replacement })
    }

    /// # Safety
    ///
    /// `respbuffer` and `respbufsize` must be non-null and writable,
    /// `*respbuffer` must be null or a caller-owned C-allocator allocation,
    /// and no live borrow may still alias that allocation.
    unsafe fn publish(mut self, respbuffer: *mut *mut c_uchar, respbufsize: *mut u32) {
        if self.replacement.is_null() {
            return;
        }
        // SAFETY: the displaced allocation is caller-owned and unaliased per
        // this function's contract; the replacement takes over its role.
        unsafe {
            libc::free((*respbuffer).cast());
            *respbuffer = self.replacement;
            *respbufsize = RESPONSE_BUFFER_SIZE as u32;
        }
        self.replacement = core::ptr::null_mut();
    }
}

#[cfg(feature = "tpm2")]
impl Drop for PreparedResponseBuffer {
    fn drop(&mut self) {
        if !self.replacement.is_null() {
            // SAFETY: an unpublished replacement is exclusively owned here.
            unsafe { libc::free(self.replacement.cast()) };
        }
    }
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

pub(crate) unsafe fn volatile_all_store(buffer: *mut *mut c_uchar, buflen: *mut u32) -> TpmResult {
    // SAFETY: forwarded from TPMLIB_VolatileAll_Store.
    unsafe {
        return_blob(buffer, buflen, || {
            library::volatile_all_store().map(StateOutput::Data)
        })
    }
}

/// # Safety
///
/// `buffer` and `buflen` must be null or point to writable output storage.
unsafe fn return_blob(
    buffer: *mut *mut c_uchar,
    buflen: *mut u32,
    create: impl FnOnce() -> Result<StateOutput, TpmResult>,
) -> TpmResult {
    if buffer.is_null() || buflen.is_null() {
        return TPM_FAIL;
    }
    // SAFETY: `buffer` was null-checked and is writable by the FFI contract.
    unsafe { buffer.write(core::ptr::null_mut()) };

    let (allocated, len) = match create() {
        Err(code) => return code,
        Ok(StateOutput::Empty) => (core::ptr::null_mut(), BUFLEN_EMPTY_BUFFER),
        Ok(StateOutput::Data(blob)) => {
            let Ok(len) = u32::try_from(blob.len()) else {
                return TPM_SIZE;
            };
            let allocated = crate::ffi::memory::malloc_bytes(&blob);
            if allocated.is_null() && !blob.is_empty() {
                return TPM_SIZE;
            }
            (allocated, len)
        }
    };

    // SAFETY: both outputs were null-checked and are writable by the FFI
    // contract. `allocated` is owned by the caller after this write.
    unsafe {
        buffer.write(allocated);
        buflen.write(len);
    }
    TPM_SUCCESS
}

pub(crate) fn cancel_command() -> TpmResult {
    library::cancel_command()
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
        Some(json) => crate::ffi::memory::malloc_c_string(&json),
        None => core::ptr::null_mut(),
    }
}

const CALLBACK_FIELD_ENDS: [usize; 8] = {
    const LAYOUT: LibtpmsCallbacks = LibtpmsCallbacks::empty();
    macro_rules! field_end {
        ($field:ident) => {
            core::mem::offset_of!(LibtpmsCallbacks, $field) + core::mem::size_of_val(&LAYOUT.$field)
        };
    }
    [
        field_end!(size_of_struct),
        field_end!(tpm_nvram_init),
        field_end!(tpm_nvram_loaddata),
        field_end!(tpm_nvram_storedata),
        field_end!(tpm_nvram_deletename),
        field_end!(tpm_io_init),
        field_end!(tpm_io_getlocality),
        field_end!(tpm_io_getphysicalpresence),
    ]
};

fn callbacks_copy_len(declared: c_int) -> usize {
    let capped =
        usize::try_from(declared).map_or(0, |n| n.min(core::mem::size_of::<LibtpmsCallbacks>()));
    CALLBACK_FIELD_ENDS
        .into_iter()
        .filter(|end| *end <= capped)
        .max()
        .unwrap_or(0)
}

/// # Safety
///
/// `callbacks` must be non-null and its `size_of_struct` field must be
/// readable. Only the prefix `callbacks_copy_len(size_of_struct)` selects has
/// to be readable for this call: the declared size is capped to the known
/// `LibtpmsCallbacks` layout and rounded down to a complete field, so a caller
/// declaring more than it owns - `i32::MAX` included - only has to back that
/// capped prefix. Each callback field completely inside that prefix must hold
/// either NULL, which reads back as `None`, or a function pointer matching
/// that field's C ABI signature. A non-NULL pointer must point to code with
/// that signature, must remain callable for as long as it stays registered,
/// and must not unwind across the C ABI boundary.
unsafe fn copy_callbacks(callbacks: *const LibtpmsCallbacks) -> LibtpmsCallbacks {
    // SAFETY: `size_of_struct` is readable per this function's contract; the
    // read is unaligned because a C caller owes Rust no alignment guarantee.
    let declared = unsafe { core::ptr::addr_of!((*callbacks).size_of_struct).read_unaligned() };
    let copy_len = callbacks_copy_len(declared);
    let mut stored = core::mem::MaybeUninit::<LibtpmsCallbacks>::zeroed();
    // SAFETY: `copy_len` is what `callbacks_copy_len` selected, which this
    // function's contract declares readable, and it is at most
    // `size_of::<LibtpmsCallbacks>()`, so it fits `stored`. All-zero bytes are
    // a valid LibtpmsCallbacks (0 size, all callbacks None) and `copy_len` ends
    // on a field boundary, so every field left untouched stays None instead of
    // holding a partial pointer.
    unsafe {
        core::ptr::copy_nonoverlapping(
            callbacks.cast::<u8>(),
            stored.as_mut_ptr().cast::<u8>(),
            copy_len,
        );
        stored.assume_init()
    }
}

fn split_callbacks(callbacks: LibtpmsCallbacks) -> (CallbackPlatform, CallbackStorage) {
    let LibtpmsCallbacks {
        size_of_struct: _,
        tpm_nvram_init,
        tpm_nvram_loaddata,
        tpm_nvram_storedata,
        tpm_nvram_deletename,
        tpm_io_init,
        tpm_io_getlocality,
        tpm_io_getphysicalpresence,
    } = callbacks;
    (
        CallbackPlatform::new(tpm_io_init, tpm_io_getlocality, tpm_io_getphysicalpresence),
        CallbackStorage::new(
            tpm_nvram_init,
            tpm_nvram_loaddata,
            tpm_nvram_storedata,
            tpm_nvram_deletename,
        ),
    )
}

pub(crate) unsafe fn register_callbacks(callbacks: *mut LibtpmsCallbacks) -> TpmResult {
    if callbacks.is_null() {
        return TPM_FAIL;
    }
    // SAFETY: forwarded from TPMLIB_RegisterCallbacks after the null check.
    let copied = unsafe { copy_callbacks(callbacks) };
    let (platform, storage) = split_callbacks(copied);
    library::register_external_services(ExternalServices::new(
        Arc::new(platform),
        Arc::new(storage),
    ));
    TPM_SUCCESS
}

pub(crate) unsafe fn decode_blob(
    data: *const c_char,
    blob_type: TpmlibBlobType,
    result: *mut *mut c_uchar,
    result_len: *mut usize,
) -> TpmResult {
    if result.is_null() || result_len.is_null() {
        return TPM_FAIL;
    }
    // SAFETY: both outputs were null-checked and are writable by the FFI
    // contract; publishing null/0 up front keeps every failure path below
    // from leaving a stale pointer or length behind.
    unsafe {
        result.write(core::ptr::null_mut());
        result_len.write(0);
    }
    if data.is_null() {
        return TPM_FAIL;
    }
    let Some(kind) = blob_kind(blob_type) else {
        return TPM_FAIL;
    };
    // SAFETY: forwarded from TPMLIB_DecodeBlob, whose contract requires a
    // NUL-terminated string that stays valid for this call; null was rejected
    // above. `decode_blob` reads the bytes before this call returns.
    let data = unsafe { core::ffi::CStr::from_ptr(data) }.to_bytes();
    let decoded = match library::decode_blob(kind, data) {
        Ok(decoded) => decoded,
        Err(code) => return code,
    };
    let allocated = crate::ffi::memory::malloc_bytes(&decoded);
    if allocated.is_null() {
        return TPM_FAIL;
    }
    // SAFETY: both outputs were null-checked above; `allocated` holds
    // `decoded.len()` bytes and its ownership transfers to the caller here.
    unsafe {
        result.write(allocated);
        result_len.write(decoded.len());
    }
    TPM_SUCCESS
}

fn blob_kind(blob_type: TpmlibBlobType) -> Option<EncodedBlobKind> {
    match blob_type {
        TPMLIB_BLOB_TYPE_INITSTATE => Some(EncodedBlobKind::InitState),
        _ => None,
    }
}

pub(crate) fn set_debug_fd(fd: c_int) {
    crate::ffi::debug::set_fd(fd);
}

pub(crate) fn set_debug_level(level: c_uint) {
    crate::ffi::debug::set_level(level);
}

pub(crate) unsafe fn set_debug_prefix(prefix: *const c_char) -> TpmResult {
    if prefix.is_null() {
        return crate::ffi::debug::set_prefix(None);
    }
    // SAFETY: the C API contract requires a non-null, NUL-terminated string
    // that remains valid for this call; the null case was handled above.
    // `set_prefix` copies the bytes before this call returns.
    crate::ffi::debug::set_prefix(Some(unsafe { core::ffi::CStr::from_ptr(prefix) }))
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

pub(crate) fn validate_state(st: TpmlibStateType, _flags: c_uint) -> TpmResult {
    library::validate_state(StateValidationMask::from_c(st))
}

pub(crate) unsafe fn set_state(
    st: TpmlibStateType,
    buffer: *const c_uchar,
    buflen: u32,
) -> TpmResult {
    let Some(kind) = StateBlobKind::from_c(st) else {
        return TPM_FAIL;
    };
    // SAFETY: forwarded from TPMLIB_SetState, whose contract allows a null
    // buffer and otherwise guarantees `buflen` readable bytes.
    library::set_state(kind, unsafe { copy_state_input(buffer, buflen) })
}

/// # Safety
///
/// `buffer` must be null or point to `buflen` readable bytes.
unsafe fn copy_state_input(buffer: *const c_uchar, buflen: u32) -> StateInput {
    if buffer.is_null() {
        return StateInput::Empty;
    }
    // SAFETY: `buffer` is non-null and points to `buflen` readable bytes per
    // this function's contract; the copy ends the caller's involvement.
    StateInput::Data(unsafe { core::slice::from_raw_parts(buffer, buflen as usize) }.to_vec())
}

pub(crate) unsafe fn get_state(
    st: TpmlibStateType,
    buffer: *mut *mut c_uchar,
    buflen: *mut u32,
) -> TpmResult {
    // SAFETY: forwarded from TPMLIB_GetState; `return_blob` rejects null
    // output pointers before it asks the library for any state.
    unsafe {
        return_blob(buffer, buflen, || {
            let kind = StateBlobKind::from_c(st).ok_or(TPM_FAIL)?;
            library::get_state(kind)
        })
    }
}

pub(crate) unsafe fn set_profile(profile: *const c_char) -> TpmResult {
    if profile.is_null() {
        return library::set_profile(None);
    }
    // SAFETY: the C API contract requires a non-null, NUL-terminated string
    // that remains valid for this call; the null case was handled above.
    // `set_profile` copies the bytes it keeps before this call returns.
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
    use crate::library::{Platform, Storage};

    const BUFFER_MAX_PROPERTY: TpmlibTpmProperty = 2;

    unsafe extern "C" fn dummy_init() -> TpmResult {
        TPM_SUCCESS
    }

    unsafe extern "C" fn dummy_loaddata(
        _data: *mut *mut c_uchar,
        _length: *mut u32,
        _tpm_number: u32,
        _name: *const c_char,
    ) -> TpmResult {
        TPM_SUCCESS
    }

    unsafe extern "C" fn dummy_storedata(
        _data: *const c_uchar,
        _length: u32,
        _tpm_number: u32,
        _name: *const c_char,
    ) -> TpmResult {
        TPM_SUCCESS
    }

    unsafe extern "C" fn dummy_deletename(
        _tpm_number: u32,
        _name: *const c_char,
        _must_exist: TpmBool,
    ) -> TpmResult {
        TPM_SUCCESS
    }

    unsafe extern "C" fn dummy_getlocality(
        _locality: *mut crate::types::TpmModifierIndicator,
        _tpm_number: u32,
    ) -> TpmResult {
        TPM_SUCCESS
    }

    unsafe extern "C" fn dummy_getphysicalpresence(
        _asserted: *mut TpmBool,
        _tpm_number: u32,
    ) -> TpmResult {
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

    fn every_callback_table() -> LibtpmsCallbacks {
        LibtpmsCallbacks {
            size_of_struct: core::mem::size_of::<LibtpmsCallbacks>() as c_int,
            tpm_nvram_init: Some(dummy_init),
            tpm_nvram_loaddata: Some(dummy_loaddata),
            tpm_nvram_storedata: Some(dummy_storedata),
            tpm_nvram_deletename: Some(dummy_deletename),
            tpm_io_init: Some(dummy_init),
            tpm_io_getlocality: Some(dummy_getlocality),
            tpm_io_getphysicalpresence: Some(dummy_getphysicalpresence),
        }
    }

    #[test]
    fn storage_callback_isolation() {
        let (platform, storage) = split_callbacks(every_callback_table());
        assert_eq!(storage.init(), Ok(library::StorageOperation::Done));
        assert!(storage.can_store());
        assert_eq!(
            storage.delete(StateBlobKind::Permanent, false),
            Ok(library::StorageOperation::Done)
        );
        assert_eq!(
            storage.load(StateBlobKind::Permanent),
            Ok(library::StorageLoad::Empty)
        );
        assert_eq!(platform.locality(), 0, "the dummy platform writes nothing");
    }

    #[test]
    fn platform_callback_isolation() {
        let (platform, storage) = split_callbacks(LibtpmsCallbacks {
            tpm_nvram_init: None,
            tpm_nvram_loaddata: None,
            tpm_nvram_storedata: None,
            tpm_nvram_deletename: None,
            ..every_callback_table()
        });
        assert_eq!(platform.initialize(), Ok(()));
        assert!(!platform.physical_presence());
        assert_eq!(storage.init(), Ok(library::StorageOperation::Unsupported));
        assert!(!storage.can_store());
        assert_eq!(
            storage.load(StateBlobKind::Permanent),
            Ok(library::StorageLoad::Unsupported)
        );
        assert_eq!(
            storage.delete(StateBlobKind::Permanent, false),
            Ok(library::StorageOperation::Unsupported)
        );
    }

    #[test]
    fn empty_table_absent_classification() {
        let (platform, storage) = split_callbacks(LibtpmsCallbacks::empty());
        assert_eq!(platform.initialize(), Ok(()));
        assert_eq!(platform.locality(), 0);
        assert!(!platform.physical_presence());
        assert_eq!(storage.init(), Ok(library::StorageOperation::Unsupported));
        assert!(!storage.can_store());
    }

    #[test]
    fn full_size_table_round_trip() {
        let table = full_table();
        // SAFETY: `table` is a live, full-size callback table.
        let stored = unsafe { copy_callbacks(&table) };
        assert_eq!(stored.size_of_struct, table.size_of_struct);
        assert!(stored.tpm_nvram_init.is_some());
        assert!(stored.tpm_io_init.is_some());
        assert!(stored.tpm_nvram_loaddata.is_none());
    }

    #[test]
    fn smaller_declared_size_copy_truncation() {
        let mut table = full_table();
        table.size_of_struct = core::mem::offset_of!(LibtpmsCallbacks, tpm_io_init) as c_int;
        // SAFETY: `table` has at least the number of live bytes it declares.
        let stored = unsafe { copy_callbacks(&table) };
        assert!(stored.tpm_nvram_init.is_some());
        assert!(stored.tpm_io_init.is_none(), "beyond declared size");
    }

    #[test]
    fn oversized_declared_size_known_struct_cap() {
        let mut table = full_table();
        table.size_of_struct = i32::MAX;
        // SAFETY: the implementation caps the read to the live table size.
        let stored = unsafe { copy_callbacks(&table) };
        assert!(stored.tpm_nvram_init.is_some());
        assert!(stored.tpm_io_init.is_some());
    }

    #[test]
    fn negative_declared_size_no_copy() {
        let mut table = full_table();
        table.size_of_struct = -1;
        // SAFETY: reading the first field of the live table is valid.
        let stored = unsafe { copy_callbacks(&table) };
        assert_eq!(stored.size_of_struct, 0);
        assert!(stored.tpm_nvram_init.is_none());
    }

    #[test]
    fn mid_callback_declared_size_field_boundary() {
        let full = core::mem::size_of::<LibtpmsCallbacks>() as c_int;
        let first_callback = core::mem::offset_of!(LibtpmsCallbacks, tpm_nvram_init) as c_int;
        for declared in [first_callback + 1, full - 1] {
            let mut table = full_table();
            table.size_of_struct = declared;
            // SAFETY: `table` has more live bytes than it declares.
            let stored = unsafe { copy_callbacks(&table) };
            assert_eq!(
                stored.size_of_struct, declared,
                "the size field itself always fits"
            );
            assert!(
                stored.tpm_io_getphysicalpresence.is_none(),
                "declared {declared}: no partially copied callback"
            );
        }

        let mut table = full_table();
        table.size_of_struct = first_callback + 1;
        // SAFETY: same live table, one byte into its first callback.
        let stored = unsafe { copy_callbacks(&table) };
        assert!(
            stored.tpm_nvram_init.is_none(),
            "a callback the declared size only half covers is dropped"
        );
    }

    #[test]
    fn declared_size_whole_field_copy() {
        let full = core::mem::size_of::<LibtpmsCallbacks>();
        for declared in 0..=(full as c_int + 8) {
            let copy_len = callbacks_copy_len(declared);
            assert!(copy_len <= full, "declared {declared} escaped the layout");
            assert!(
                copy_len <= usize::try_from(declared).unwrap_or(0),
                "declared {declared} read beyond what the caller promised"
            );
            assert!(
                copy_len == 0 || CALLBACK_FIELD_ENDS.contains(&copy_len),
                "declared {declared} stopped mid-field at {copy_len}"
            );
        }
        for declared in [-1, i32::MIN, i32::MIN + 1] {
            assert_eq!(callbacks_copy_len(declared), 0, "declared {declared}");
        }
        assert_eq!(callbacks_copy_len(i32::MAX), full);
    }

    #[test]
    fn misaligned_callback_table_read_safety() {
        let table = full_table();
        let mut unaligned = vec![0u8; core::mem::size_of::<LibtpmsCallbacks>() + 1];
        // SAFETY: `table` is a live struct and `unaligned` has room for its
        // bytes at offset one.
        unsafe {
            core::ptr::copy_nonoverlapping(
                core::ptr::from_ref(&table).cast::<u8>(),
                unaligned.as_mut_ptr().add(1),
                core::mem::size_of::<LibtpmsCallbacks>(),
            );
        }
        // SAFETY: the misaligned pointer is backed by a full table's worth of
        // live bytes; the implementation reads them without assuming alignment.
        let stored = unsafe { copy_callbacks(unaligned.as_ptr().add(1).cast()) };
        assert_eq!(stored.size_of_struct, table.size_of_struct);
    }

    #[test]
    fn tis_abi_signature_exactness() {
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
    fn tis_null_established_output_pointer_safe_failure() {
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
    fn tis_null_hash_data_zero_length_only() {
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
    fn null_callbacks_pointer_failure_state_preservation() {
        // SAFETY: NULL is explicitly accepted and rejected by the adapter.
        assert_eq!(
            unsafe { register_callbacks(core::ptr::null_mut()) },
            TPM_FAIL
        );
    }

    #[test]
    fn property_c_output_pointer_write() {
        let mut value: c_int = 0;
        // SAFETY: `value` is a live, writable c_int.
        assert_eq!(
            unsafe { get_tpm_property(BUFFER_MAX_PROPERTY, &mut value) },
            TPM_SUCCESS
        );
        assert_eq!(value, 4096);
    }

    #[test]
    fn null_property_output_pointer_failure() {
        // SAFETY: NULL is explicitly accepted and rejected by the adapter.
        assert_eq!(
            unsafe { get_tpm_property(BUFFER_MAX_PROPERTY, core::ptr::null_mut()) },
            TPM_FAIL
        );
    }

    const LEN_SENTINEL: u32 = 0xdead_beef;

    #[test]
    fn blob_output_null_pointer_rejection() {
        let called = core::cell::Cell::new(false);

        let mut buflen = LEN_SENTINEL;
        // SAFETY: `buffer` is null on purpose; `buflen` references a live
        // writable local.
        assert_eq!(
            unsafe {
                return_blob(core::ptr::null_mut(), &mut buflen, || {
                    called.set(true);
                    Ok(StateOutput::Data(vec![1]))
                })
            },
            TPM_FAIL
        );
        assert_eq!(buflen, LEN_SENTINEL);

        let mut buffer = core::ptr::dangling_mut::<c_uchar>();
        // SAFETY: `buflen` is null on purpose; `buffer` references a live
        // writable local.
        assert_eq!(
            unsafe {
                return_blob(&mut buffer, core::ptr::null_mut(), || {
                    called.set(true);
                    Ok(StateOutput::Data(vec![1]))
                })
            },
            TPM_FAIL
        );
        assert_eq!(buffer, core::ptr::dangling_mut::<c_uchar>());

        assert!(!called.get());
    }

    #[test]
    fn volatile_all_store_abi_signature_exactness() {
        let _: unsafe extern "C" fn(*mut *mut c_uchar, *mut u32) -> TpmResult =
            crate::tpm_library_abi::TPMLIB_VolatileAll_Store;
    }

    #[test]
    fn cancel_command_abi_signature_exactness() {
        let _: unsafe extern "C" fn() -> TpmResult = crate::tpm_library_abi::TPMLIB_CancelCommand;
    }

    static GLOBAL_LIBRARY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(all(feature = "tpm2", feature = "tpm1"))]
    #[test]
    fn exported_cancel_command_dispatch_matrix_coverage() {
        const TPMLIB_TPM_VERSION_1_2: crate::types::TpmlibTpmVersion = 0;
        const TPMLIB_TPM_VERSION_2: crate::types::TpmlibTpmVersion = 1;

        let _serial = GLOBAL_LIBRARY_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // SAFETY: the exported wrapper takes no arguments; every call below
        // goes through it so the test exercises the real C entry point.
        let cancel = || unsafe { crate::tpm_library_abi::TPMLIB_CancelCommand() };

        terminate();
        assert_eq!(choose_tpm_version(TPMLIB_TPM_VERSION_1_2), TPM_SUCCESS);
        assert_eq!(cancel(), TPM_FAIL, "TPM 1.2 has no cancel support");

        assert_eq!(choose_tpm_version(TPMLIB_TPM_VERSION_2), TPM_SUCCESS);
        assert_eq!(cancel(), TPM_SUCCESS, "before MainInit");

        crate::library::stage_empty_permanent_state_for_tests();
        assert_eq!(main_init(), TPM_SUCCESS);
        assert_eq!(cancel(), TPM_SUCCESS, "while TPM 2.0 is running");
        assert_eq!(cancel(), TPM_SUCCESS, "repeated requests stay successful");

        terminate();
        assert_eq!(cancel(), TPM_SUCCESS, "after Terminate");
        assert_eq!(
            cancel(),
            cancel_command(),
            "the adapter adds nothing to the library dispatch"
        );

        assert_eq!(choose_tpm_version(TPMLIB_TPM_VERSION_1_2), TPM_SUCCESS);
        assert_eq!(cancel(), TPM_FAIL);
    }

    #[cfg(not(feature = "tpm2"))]
    #[test]
    fn exported_cancel_command_no_tpm2_failure() {
        assert_eq!(
            cancel_command(),
            TPM_FAIL,
            "no build without tpm2 can select an implementation that cancels"
        );
        // SAFETY: the exported wrapper takes no arguments.
        assert_eq!(
            unsafe { crate::tpm_library_abi::TPMLIB_CancelCommand() },
            TPM_FAIL
        );
    }

    #[test]
    fn exported_cancel_command_panic_safety() {
        for round in 0..4 {
            let code = std::panic::catch_unwind(|| {
                // SAFETY: the exported wrapper takes no arguments and guards
                // every unwind before it can cross the C ABI.
                unsafe { crate::tpm_library_abi::TPMLIB_CancelCommand() }
            })
            .unwrap_or_else(|_| panic!("TPMLIB_CancelCommand unwound, round {round}"));
            assert!(
                code == TPM_SUCCESS || code == TPM_FAIL,
                "round {round}: {code}"
            );
        }
    }

    #[test]
    fn exported_volatile_all_store_null_pointer_rejection() {
        let mut buflen = LEN_SENTINEL;
        // SAFETY: `buffer` is null on purpose; `buflen` references a live
        // writable local.
        assert_eq!(
            unsafe {
                crate::tpm_library_abi::TPMLIB_VolatileAll_Store(core::ptr::null_mut(), &mut buflen)
            },
            TPM_FAIL
        );
        assert_eq!(buflen, LEN_SENTINEL);

        let mut buffer = core::ptr::dangling_mut::<c_uchar>();
        // SAFETY: `buflen` is null on purpose; `buffer` references a live
        // writable local.
        assert_eq!(
            unsafe {
                crate::tpm_library_abi::TPMLIB_VolatileAll_Store(&mut buffer, core::ptr::null_mut())
            },
            TPM_FAIL
        );
        assert_eq!(buffer, core::ptr::dangling_mut::<c_uchar>());
    }

    #[test]
    fn blob_output_error_preservation_no_allocation() {
        let mut buffer = core::ptr::dangling_mut::<c_uchar>();
        let mut buflen = 0xdead_beef;
        // SAFETY: both output pointers reference live writable locals.
        assert_eq!(
            unsafe { return_blob(&mut buffer, &mut buflen, || Err(0x1234)) },
            0x1234
        );
        assert!(buffer.is_null());
        assert_eq!(buflen, 0xdead_beef);
    }

    #[test]
    fn blob_output_c_allocation_transfer() {
        let expected = [1u8, 2, 3, 4];
        let mut buffer = core::ptr::null_mut();
        let mut buflen = 0u32;
        // SAFETY: both output pointers reference live writable locals.
        assert_eq!(
            unsafe {
                return_blob(&mut buffer, &mut buflen, || {
                    Ok(StateOutput::Data(expected.to_vec()))
                })
            },
            TPM_SUCCESS
        );
        assert_eq!(buflen, expected.len() as u32);
        assert!(!buffer.is_null());
        // SAFETY: success returned a C allocation containing `buflen` bytes.
        let actual = unsafe { core::slice::from_raw_parts(buffer, buflen as usize) };
        assert_eq!(actual, expected);
        // SAFETY: ownership of the C allocation was transferred to this test.
        unsafe { libc::free(buffer.cast()) };
    }

    #[test]
    fn blob_output_explicit_empty_wire_sentinel() {
        let mut buffer = core::ptr::dangling_mut::<c_uchar>();
        let mut buflen = 0u32;
        // SAFETY: both output pointers reference live writable locals.
        assert_eq!(
            unsafe { return_blob(&mut buffer, &mut buflen, || Ok(StateOutput::Empty)) },
            TPM_SUCCESS
        );
        assert!(buffer.is_null());
        assert_eq!(buflen, 0xffff_ffff);
        assert_eq!(buflen, BUFLEN_EMPTY_BUFFER);
    }

    #[test]
    fn blob_output_empty_blob_null_and_zero() {
        let mut buffer = core::ptr::dangling_mut::<c_uchar>();
        let mut buflen = 0xdead_beef;
        // SAFETY: both output pointers reference live writable locals.
        assert_eq!(
            unsafe {
                return_blob(&mut buffer, &mut buflen, || {
                    Ok(StateOutput::Data(Vec::new()))
                })
            },
            TPM_SUCCESS
        );
        assert!(buffer.is_null());
        assert_eq!(buflen, 0);
    }

    const PERMANENT_STATE: TpmlibStateType = 1;
    const VOLATILE_STATE: TpmlibStateType = 2;
    const SAVE_STATE: TpmlibStateType = 4;

    #[test]
    fn state_abi_signature_exactness() {
        let _: unsafe extern "C" fn(TpmlibStateType, *const c_uchar, u32) -> TpmResult =
            crate::tpm_library_abi::TPMLIB_SetState;
        let _: unsafe extern "C" fn(TpmlibStateType, *mut *mut c_uchar, *mut u32) -> TpmResult =
            crate::tpm_library_abi::TPMLIB_GetState;
    }

    #[test]
    fn validate_state_abi_signature_exactness() {
        let _: unsafe extern "C" fn(TpmlibStateType, c_uint) -> TpmResult =
            crate::tpm_library_abi::TPMLIB_ValidateState;
    }

    #[test]
    fn exported_validate_state_panic_safety() {
        for st in [
            0,
            PERMANENT_STATE,
            VOLATILE_STATE,
            SAVE_STATE,
            PERMANENT_STATE | VOLATILE_STATE,
            PERMANENT_STATE | SAVE_STATE,
            PERMANENT_STATE | VOLATILE_STATE | SAVE_STATE,
            8,
            8 | PERMANENT_STATE,
            -1,
            i32::MAX,
            i32::MIN,
        ] {
            for flags in [0u32, 1, 0xdead_beef, u32::MAX] {
                std::panic::catch_unwind(|| validate_state(st, flags))
                    .unwrap_or_else(|_| panic!("validate_state panicked, st {st} flags {flags}"));
                // SAFETY: the exported entry point takes no pointers, and its
                // guard must turn any panic into a return value.
                std::panic::catch_unwind(|| unsafe {
                    crate::tpm_library_abi::TPMLIB_ValidateState(st, flags)
                })
                .unwrap_or_else(|_| {
                    panic!("the exported TPMLIB_ValidateState panicked, st {st} flags {flags}")
                });
            }
        }
    }

    #[test]
    fn null_state_buffer_explicit_empty_any_length() {
        // SAFETY: a null buffer carries no bytes to read, so any length is
        // valid for this call.
        unsafe {
            for buflen in [0u32, 1, 4096, u32::MAX] {
                assert_eq!(
                    copy_state_input(core::ptr::null(), buflen),
                    StateInput::Empty,
                    "buflen {buflen}"
                );
            }
        }
    }

    #[test]
    fn non_null_zero_length_state_buffer_zero_length_blob() {
        let caller = [7u8; 4];
        // SAFETY: `caller` is live and no bytes are read at length zero.
        assert_eq!(
            unsafe { copy_state_input(caller.as_ptr(), 0) },
            StateInput::Data(Vec::new()),
            "distinct from the explicitly empty state"
        );
    }

    #[test]
    fn state_input_copy_before_library_access() {
        let mut caller = vec![1u8, 2, 3, 4];
        // SAFETY: `caller` is live and holds the four bytes announced.
        let input = unsafe { copy_state_input(caller.as_ptr(), caller.len() as u32) };
        caller.iter_mut().for_each(|byte| *byte = 0xff);
        drop(caller);
        assert_eq!(input, StateInput::Data(vec![1, 2, 3, 4]));
    }

    #[test]
    fn unknown_state_type_rejection_before_library() {
        for st in [0, 3, 5, 6, 7, -1, i32::MAX, i32::MIN] {
            // SAFETY: the state type is rejected before `buffer` is read.
            assert_eq!(
                unsafe { set_state(st, [1u8, 2].as_ptr(), 2) },
                TPM_FAIL,
                "TPMLIB_SetState st {st}"
            );
            // SAFETY: same, through the exported wrapper; a null buffer is
            // explicitly permitted.
            assert_eq!(
                unsafe { crate::tpm_library_abi::TPMLIB_SetState(st, core::ptr::null(), 0) },
                TPM_FAIL,
                "exported TPMLIB_SetState st {st}"
            );

            let mut buffer = core::ptr::dangling_mut::<c_uchar>();
            let mut buflen = LEN_SENTINEL;
            // SAFETY: both output pointers reference live writable locals.
            assert_eq!(
                unsafe { get_state(st, &mut buffer, &mut buflen) },
                TPM_FAIL,
                "TPMLIB_GetState st {st}"
            );
            assert!(buffer.is_null(), "the output pointer is always cleared");
            assert_eq!(buflen, LEN_SENTINEL, "no length is reported on failure");
        }
    }

    #[test]
    fn get_state_null_output_combination_rejection_before_library() {
        for st in [PERMANENT_STATE, VOLATILE_STATE, SAVE_STATE] {
            let mut buflen = LEN_SENTINEL;
            // SAFETY: `buffer` is null on purpose; `buflen` references a live
            // writable local.
            assert_eq!(
                unsafe { get_state(st, core::ptr::null_mut(), &mut buflen) },
                TPM_FAIL
            );
            assert_eq!(buflen, LEN_SENTINEL, "st {st}");

            let mut buffer = core::ptr::dangling_mut::<c_uchar>();
            // SAFETY: `buflen` is null on purpose; `buffer` references a live
            // writable local.
            assert_eq!(
                unsafe { get_state(st, &mut buffer, core::ptr::null_mut()) },
                TPM_FAIL
            );
            assert_eq!(buffer, core::ptr::dangling_mut::<c_uchar>(), "st {st}");

            // SAFETY: both output pointers are null on purpose, and the
            // exported wrapper must reject them rather than dereference.
            assert_eq!(
                unsafe {
                    crate::tpm_library_abi::TPMLIB_GetState(
                        st,
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                    )
                },
                TPM_FAIL
            );
        }
    }

    const NO_LIMITS: Option<library::BufferSizeLimits> = None;
    const TPM2_LIMITS: Option<library::BufferSizeLimits> = Some(library::BufferSizeLimits {
        current: 3000,
        minimum: 2808,
        maximum: 4096,
    });

    #[test]
    fn buffer_size_limit_output_pointer_propagation() {
        let mut min: u32 = 0xdead_beef;
        let mut max: u32 = 0xfeed_face;
        // SAFETY: both outputs are live, writable u32s.
        let current = unsafe { report_buffer_size(TPM2_LIMITS, &mut min, &mut max) };
        assert_eq!(current, 3000);
        assert_eq!(min, 2808);
        assert_eq!(max, 4096);
    }

    #[test]
    fn null_output_pointer_combination_safety() {
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
    fn disabled_implementation_zero_result_no_write() {
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
    fn exported_set_buffer_size_null_output_panic_safety() {
        let _serial = GLOBAL_LIBRARY_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut min: u32 = 0xdead_beef;
        let mut max: u32 = 0xfeed_face;
        // SAFETY: the global-library guard prevents version changes between
        // calls, and null output pointers are explicitly permitted.
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
    fn debug_fd_and_level_configuration_propagation() {
        let _state = crate::ffi::debug::test_support::DebugStateGuard::hold();
        set_debug_fd(21);
        set_debug_level(4);
        assert_eq!(crate::ffi::debug::fd_and_level(), (21, 4));
    }

    #[test]
    fn debug_prefix_ownership_replacement_and_clear() {
        let _state = crate::ffi::debug::test_support::DebugStateGuard::hold();
        let mut caller = b"first\0".to_vec();
        // SAFETY: `caller` is NUL-terminated and remains live for the call.
        assert_eq!(
            unsafe { set_debug_prefix(caller.as_ptr().cast()) },
            TPM_SUCCESS
        );
        caller[0] = b'X';
        assert_eq!(
            crate::ffi::debug::prefix().as_deref(),
            Some(b"first".as_slice())
        );

        // SAFETY: the byte string is statically live and NUL-terminated.
        assert_eq!(unsafe { set_debug_prefix(c"second".as_ptr()) }, TPM_SUCCESS);
        assert_eq!(
            crate::ffi::debug::prefix().as_deref(),
            Some(b"second".as_slice())
        );

        // SAFETY: NULL clears the prefix without being dereferenced.
        assert_eq!(unsafe { set_debug_prefix(core::ptr::null()) }, TPM_SUCCESS);
        assert_eq!(crate::ffi::debug::prefix(), None);

        // SAFETY: the byte string is statically live and NUL-terminated.
        assert_eq!(unsafe { set_debug_prefix(c"".as_ptr()) }, TPM_SUCCESS);
        assert_eq!(crate::ffi::debug::prefix().as_deref(), Some(b"".as_slice()));

        // SAFETY: restore the process-global setting for other tests.
        assert_eq!(unsafe { set_debug_prefix(core::ptr::null()) }, TPM_SUCCESS);
    }

    #[test]
    fn multi_kilobyte_debug_prefix_preservation() {
        let _state = crate::ffi::debug::test_support::DebugStateGuard::hold();
        let mut caller = vec![b'p'; 5000];
        caller.push(0);
        // SAFETY: `caller` is NUL-terminated and remains live for the call.
        assert_eq!(
            unsafe { set_debug_prefix(caller.as_ptr().cast()) },
            TPM_SUCCESS
        );
        assert_eq!(
            crate::ffi::debug::prefix().as_deref(),
            Some(&caller[..5000])
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
    fn process_null_output_pointer_rejection() {
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
    fn process_null_command_nonzero_size_rejection() {
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

    #[cfg(all(feature = "tpm2", feature = "tpm1"))]
    fn install_allocation_override(hook: Box<dyn FnMut() -> *mut c_uchar>) {
        RESPONSE_ALLOCATION_OVERRIDE.with(|slot| *slot.borrow_mut() = Some(hook));
    }

    #[cfg(all(feature = "tpm2", feature = "tpm1"))]
    fn clear_allocation_override() {
        RESPONSE_ALLOCATION_OVERRIDE.with(|slot| *slot.borrow_mut() = None);
    }

    #[cfg(all(feature = "tpm2", feature = "tpm1"))]
    #[test]
    fn version_switch_rollback() {
        use std::sync::mpsc::sync_channel;
        use std::time::Duration;

        const TPMLIB_TPM_VERSION_2: crate::types::TpmlibTpmVersion = 1;
        const WAIT: Duration = Duration::from_secs(30);

        let _serial = GLOBAL_LIBRARY_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        terminate();
        assert_eq!(choose_tpm_version(TPMLIB_TPM_VERSION_2), TPM_SUCCESS);

        let (entered_tx, entered_rx) = sync_channel(1);
        let (release_tx, release_rx) = sync_channel::<()>(1);
        let worker = std::thread::spawn(move || {
            let mut outputs = ProcessOutputs::new();
            outputs.respbuffer = crate::ffi::memory::malloc_bytes(&[0u8; 16]);
            outputs.respbufsize = 16;
            let original = outputs.respbuffer as usize;
            install_allocation_override(Box::new(move || {
                entered_tx
                    .send(())
                    .expect("the test observes the allocation");
                release_rx
                    .recv_timeout(WAIT)
                    .expect("timed out waiting for the version switch");
                // SAFETY: a plain C allocation of a nonzero constant size.
                unsafe { libc::malloc(RESPONSE_BUFFER_SIZE).cast() }
            }));
            let code = outputs.call(&STARTUP_COMMAND);
            clear_allocation_override();
            (
                code,
                outputs.respbuffer as usize == original,
                outputs.resp_size,
                outputs.respbufsize,
            )
        });

        entered_rx
            .recv_timeout(WAIT)
            .expect("timed out waiting for the allocation attempt");
        assert_eq!(
            choose_tpm_version(0),
            TPM_SUCCESS,
            "the selection can still switch before MainInit"
        );
        release_tx.send(()).expect("the worker resumes");

        let (code, pointer_unchanged, resp_size, respbufsize) =
            worker.join().expect("the worker never panics");
        assert_eq!(code, TPM_FAIL, "the switched selection rejects the command");
        assert!(pointer_unchanged, "the caller keeps its own allocation");
        assert_eq!(resp_size, 0xdead_beef, "the size stays untouched");
        assert_eq!(respbufsize, 16, "the capacity stays untouched");
    }

    #[cfg(all(feature = "tpm2", feature = "tpm1"))]
    #[test]
    fn sufficient_buffer_reuse() {
        const TPMLIB_TPM_VERSION_2: crate::types::TpmlibTpmVersion = 1;

        let _serial = GLOBAL_LIBRARY_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        terminate();
        assert_eq!(choose_tpm_version(TPMLIB_TPM_VERSION_2), TPM_SUCCESS);
        crate::library::stage_empty_permanent_state_for_tests();
        assert_eq!(main_init(), TPM_SUCCESS);

        let mut outputs = ProcessOutputs::new();
        outputs.respbuffer = crate::ffi::memory::malloc_bytes(&[0u8; RESPONSE_BUFFER_SIZE]);
        outputs.respbufsize = RESPONSE_BUFFER_SIZE as u32;
        let original = outputs.respbuffer;
        install_allocation_override(Box::new(|| {
            panic!("a sufficient response buffer must not trigger an allocation")
        }));
        let code = outputs.call(&UNKNOWN_COMMAND);
        clear_allocation_override();

        assert_eq!(code, TPM_SUCCESS);
        assert_eq!(outputs.respbuffer, original, "the buffer is reused");
        assert_eq!(outputs.respbufsize, RESPONSE_BUFFER_SIZE as u32);
        assert_eq!(outputs.response(), UNSUPPORTED_RESPONSE);

        terminate();
        assert_eq!(choose_tpm_version(0), TPM_SUCCESS);
    }

    #[cfg(all(feature = "tpm2", feature = "tpm1"))]
    #[test]
    fn allocation_failure_before_execution() {
        use std::sync::Mutex;

        struct MemoryStorage {
            permall: Arc<Mutex<Option<Vec<u8>>>>,
        }

        impl Storage for MemoryStorage {
            fn init(&self) -> Result<library::StorageOperation, TpmResult> {
                Ok(library::StorageOperation::Done)
            }

            fn probe_permanent(&self) -> library::StorageProbe {
                library::StorageProbe {
                    exists: self.permall.lock().unwrap().is_some(),
                    load_supported: true,
                }
            }

            fn load(&self, kind: StateBlobKind) -> Result<library::StorageLoad, TpmResult> {
                Ok(match (kind, self.permall.lock().unwrap().clone()) {
                    (StateBlobKind::Permanent, Some(blob)) => library::StorageLoad::Data(blob),
                    _ => library::StorageLoad::Missing,
                })
            }

            fn can_store(&self) -> bool {
                true
            }

            fn store(
                &self,
                kind: StateBlobKind,
                data: &[u8],
            ) -> Result<library::StorageOperation, TpmResult> {
                assert_eq!(kind, StateBlobKind::Permanent);
                *self.permall.lock().unwrap() = Some(data.to_vec());
                Ok(library::StorageOperation::Done)
            }

            fn delete(
                &self,
                _kind: StateBlobKind,
                _must_exist: bool,
            ) -> Result<library::StorageOperation, TpmResult> {
                Ok(library::StorageOperation::Done)
            }
        }

        const TPMLIB_TPM_VERSION_2: crate::types::TpmlibTpmVersion = 1;
        const STARTUP_SUCCESS: [u8; 10] =
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00];

        let _serial = GLOBAL_LIBRARY_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        terminate();
        assert_eq!(choose_tpm_version(TPMLIB_TPM_VERSION_2), TPM_SUCCESS);

        let permall: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
        crate::library::register_storage(Arc::new(MemoryStorage {
            permall: Arc::clone(&permall),
        }));
        assert_eq!(main_init(), TPM_SUCCESS, "a first boot manufactures");
        let manufactured = permall.lock().unwrap().clone();

        let mut outputs = ProcessOutputs::new();
        install_allocation_override(Box::new(|| core::ptr::null_mut()));
        assert_eq!(outputs.call(&STARTUP_COMMAND), TPM_SIZE);
        clear_allocation_override();
        assert!(outputs.respbuffer.is_null(), "no allocation is published");
        assert_eq!(outputs.resp_size, 0xdead_beef, "the size stays untouched");
        assert_eq!(outputs.respbufsize, 0, "the capacity stays untouched");
        assert_eq!(
            *permall.lock().unwrap(),
            manufactured,
            "the failed allocation committed nothing"
        );

        assert_eq!(
            outputs.call(&STARTUP_COMMAND),
            TPM_SUCCESS,
            "the retried command executes with a working allocation"
        );
        assert_eq!(
            outputs.response(),
            STARTUP_SUCCESS,
            "the failed allocation never reached the TPM: this is the first TPM2_Startup"
        );
        terminate();
        crate::library::register_external_services(ExternalServices::default());
        assert_eq!(choose_tpm_version(0), TPM_SUCCESS);
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn process_c_buffer_contract() {
        const TPMLIB_TPM_VERSION_2: crate::types::TpmlibTpmVersion = 1;
        const TPM_BUFFER_MAX: u32 = RESPONSE_BUFFER_SIZE as u32;

        let _serial = GLOBAL_LIBRARY_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

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
        small.respbuffer = crate::ffi::memory::malloc_bytes(&[0u8; 16]);
        small.respbufsize = 16;
        assert_eq!(small.call(&UNKNOWN_COMMAND), TPM_SUCCESS);
        assert_eq!(small.respbufsize, TPM_BUFFER_MAX);
        assert_eq!(small.response(), UNSUPPORTED_RESPONSE);
        drop(small);

        let mut large = ProcessOutputs::new();
        large.respbuffer = crate::ffi::memory::malloc_bytes(&[0u8; 2 * RESPONSE_BUFFER_SIZE]);
        large.respbufsize = 2 * TPM_BUFFER_MAX;
        let large_buffer = large.respbuffer;
        assert_eq!(large.call(&UNKNOWN_COMMAND), TPM_SUCCESS);
        assert_eq!(large.respbuffer, large_buffer);
        assert_eq!(large.respbufsize, 2 * TPM_BUFFER_MAX);
        assert_eq!(large.response(), UNSUPPORTED_RESPONSE);
        drop(large);

        let mut shared = ProcessOutputs::new();
        shared.respbuffer = crate::ffi::memory::malloc_bytes(&UNKNOWN_COMMAND);
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
        shared.respbuffer = crate::ffi::memory::malloc_bytes(&contents);
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
        shared.respbuffer = crate::ffi::memory::malloc_bytes(&[0x80, 0x01, 0x00, 0x01, 0x00, 0x00]);
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

    const INITSTATE_BLOB: &[u8] = b"-----BEGIN INITSTATE-----\nQUJD\n-----END INITSTATE-----\0";
    const BLOB_TYPE_INITSTATE: TpmlibBlobType = TPMLIB_BLOB_TYPE_INITSTATE;
    const PTR_SENTINEL: *mut c_uchar = core::ptr::dangling_mut::<c_uchar>();
    const SIZE_SENTINEL: usize = 0xdead_beef;

    struct DecodedBlob {
        result: *mut c_uchar,
        result_len: usize,
    }

    impl DecodedBlob {
        fn new() -> Self {
            Self {
                result: PTR_SENTINEL,
                result_len: SIZE_SENTINEL,
            }
        }

        fn call(&mut self, data: &[u8], blob_type: TpmlibBlobType) -> TpmResult {
            // SAFETY: `data` stays live and NUL-terminated for the call and
            // both output pointers reference live writable fields.
            unsafe {
                crate::tpm_library_abi::TPMLIB_DecodeBlob(
                    data.as_ptr().cast(),
                    blob_type,
                    &mut self.result,
                    &mut self.result_len,
                )
            }
        }

        fn decoded(&self) -> &[u8] {
            assert!(!self.result.is_null());
            // SAFETY: a successful call published a C allocation of exactly
            // `result_len` initialized bytes.
            unsafe { core::slice::from_raw_parts(self.result, self.result_len) }
        }

        fn assert_published_nothing(&self) {
            assert!(self.result.is_null(), "a failure published an allocation");
            assert_eq!(self.result_len, 0, "a failure published a length");
        }
    }

    impl Drop for DecodedBlob {
        fn drop(&mut self) {
            if self.result == PTR_SENTINEL {
                return;
            }
            // SAFETY: the pointer is null or the C-allocator allocation the
            // call transferred to us.
            unsafe { libc::free(self.result.cast()) };
        }
    }

    #[test]
    fn initstate_blob_type_sole_kind_mapping() {
        assert_eq!(
            blob_kind(TPMLIB_BLOB_TYPE_INITSTATE),
            Some(EncodedBlobKind::InitState)
        );
        assert_eq!(TPMLIB_BLOB_TYPE_INITSTATE, 0);
    }

    #[test]
    fn other_blob_type_no_kind_mapping() {
        for blob_type in [1, 2, 3, -1, -2, i32::MAX, i32::MIN] {
            assert_eq!(blob_kind(blob_type), None, "blob type {blob_type}");
        }
    }

    #[test]
    fn multi_hundred_kilobyte_blob_full_decode() {
        let payload: Vec<u8> = (0..200_000u32).map(|index| (index % 251) as u8).collect();
        let mut caller = Vec::new();
        caller.extend_from_slice(b"-----BEGIN INITSTATE-----\n");
        caller.extend_from_slice(base64_for_tests(&payload).as_bytes());
        caller.extend_from_slice(b"\n-----END INITSTATE-----\0");
        assert!(caller.len() > 64 * 1024);

        let mut blob = DecodedBlob::new();
        assert_eq!(blob.call(&caller, BLOB_TYPE_INITSTATE), TPM_SUCCESS);
        assert_eq!(blob.decoded(), payload);
    }

    fn base64_for_tests(data: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut encoded = Vec::new();
        for group in data.chunks(3) {
            let mut bits = 0u32;
            for (index, byte) in group.iter().enumerate() {
                bits |= u32::from(*byte) << (16 - 8 * index);
            }
            for index in 0..group.len() + 1 {
                encoded.push(ALPHABET[(bits >> (18 - 6 * index)) as usize & 0x3f]);
            }
            encoded.resize(encoded.len() + (3 - group.len()), b'=');
        }
        String::from_utf8(encoded).expect("the alphabet is ASCII")
    }

    #[test]
    fn decode_blob_abi_signature_exactness() {
        let _: unsafe extern "C" fn(
            *const c_char,
            TpmlibBlobType,
            *mut *mut c_uchar,
            *mut usize,
        ) -> TpmResult = crate::tpm_library_abi::TPMLIB_DecodeBlob;
    }

    #[test]
    fn valid_blob_decode_freeable_c_allocation() {
        let mut blob = DecodedBlob::new();
        assert_eq!(blob.call(INITSTATE_BLOB, BLOB_TYPE_INITSTATE), TPM_SUCCESS);
        assert_eq!(blob.decoded(), b"ABC");
        assert_ne!(blob.result, PTR_SENTINEL);

        let taken = core::mem::replace(&mut blob.result, PTR_SENTINEL);
        // SAFETY: `taken` is the C allocation the call handed us, with
        // `result_len` valid bytes and no other owner.
        let owned = unsafe { crate::ffi::memory::MallocBuffer::from_raw(taken, blob.result_len) };
        assert_eq!(owned.expect("a non-null allocation").as_slice(), b"ABC");
    }

    #[test]
    fn null_data_pointer_failure_no_allocation() {
        let mut result = PTR_SENTINEL;
        let mut result_len = SIZE_SENTINEL;
        // SAFETY: `data` is null on purpose; both outputs reference live
        // writable locals.
        assert_eq!(
            unsafe {
                crate::tpm_library_abi::TPMLIB_DecodeBlob(
                    core::ptr::null(),
                    BLOB_TYPE_INITSTATE,
                    &mut result,
                    &mut result_len,
                )
            },
            TPM_FAIL
        );
        assert!(result.is_null());
        assert_eq!(result_len, 0);
    }

    #[test]
    fn null_output_combination_failure_isolation() {
        let mut result = PTR_SENTINEL;
        let mut result_len = SIZE_SENTINEL;
        // SAFETY: `result` is null on purpose; `result_len` references a live
        // writable local.
        assert_eq!(
            unsafe {
                crate::tpm_library_abi::TPMLIB_DecodeBlob(
                    INITSTATE_BLOB.as_ptr().cast(),
                    BLOB_TYPE_INITSTATE,
                    core::ptr::null_mut(),
                    &mut result_len,
                )
            },
            TPM_FAIL
        );
        assert_eq!(result_len, SIZE_SENTINEL);

        // SAFETY: `result_len` is null on purpose; `result` references a live
        // writable local.
        assert_eq!(
            unsafe {
                crate::tpm_library_abi::TPMLIB_DecodeBlob(
                    INITSTATE_BLOB.as_ptr().cast(),
                    BLOB_TYPE_INITSTATE,
                    &mut result,
                    core::ptr::null_mut(),
                )
            },
            TPM_FAIL
        );
        assert_eq!(result, PTR_SENTINEL);

        // SAFETY: both outputs are null on purpose and `data` stays live.
        assert_eq!(
            unsafe {
                crate::tpm_library_abi::TPMLIB_DecodeBlob(
                    INITSTATE_BLOB.as_ptr().cast(),
                    BLOB_TYPE_INITSTATE,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                )
            },
            TPM_FAIL
        );

        // SAFETY: every pointer is null on purpose.
        assert_eq!(
            unsafe {
                crate::tpm_library_abi::TPMLIB_DecodeBlob(
                    core::ptr::null(),
                    BLOB_TYPE_INITSTATE,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                )
            },
            TPM_FAIL
        );
    }

    #[test]
    fn unknown_blob_type_failure_no_allocation() {
        for blob_type in [1, 2, -1, -2, i32::MAX, i32::MIN] {
            let mut blob = DecodedBlob::new();
            assert_eq!(
                blob.call(INITSTATE_BLOB, blob_type),
                TPM_FAIL,
                "blob type {blob_type}"
            );
            blob.assert_published_nothing();
        }
    }

    #[test]
    fn malformed_blob_failure_no_allocation() {
        for data in [
            b"\0".as_slice(),
            b"hello world\0",
            b"-----BEGIN INITSTATE-----\nQUJD\n\0",
            b"QUJD\n-----END INITSTATE-----\0",
            b"-----BEGIN INITSTATE-----\n-----END INITSTATE-----\0",
            b"-----BEGIN INITSTATE-----\nQ\n-----END INITSTATE-----\0",
            b"-----BEGIN INITSTATE-----\n====\n-----END INITSTATE-----\0",
        ] {
            let mut blob = DecodedBlob::new();
            assert_eq!(blob.call(data, BLOB_TYPE_INITSTATE), TPM_FAIL);
            blob.assert_published_nothing();
        }
    }

    #[test]
    fn exported_decode_blob_caller_c_string_boundary() {
        let mut blob = DecodedBlob::new();
        let trailing = [
            INITSTATE_BLOB,
            b"-----BEGIN INITSTATE-----\nRUZH\n-----END INITSTATE-----\0",
        ]
        .concat();
        assert_eq!(blob.call(&trailing, BLOB_TYPE_INITSTATE), TPM_SUCCESS);
        assert_eq!(blob.decoded(), b"ABC");

        let mut hidden = DecodedBlob::new();
        let after_terminator = [b"\0".as_slice(), INITSTATE_BLOB].concat();
        assert_eq!(
            hidden.call(&after_terminator, BLOB_TYPE_INITSTATE),
            TPM_FAIL
        );
        hidden.assert_published_nothing();
    }

    #[test]
    fn exported_decode_blob_panic_safety() {
        let corpus: Vec<Vec<u8>> = [
            b"\0".as_slice(),
            b"-----BEGIN INITSTATE-----\0",
            b"-----END INITSTATE-----\0",
            b"-----BEGIN INITSTATE-----\n\x80\xff=\n-----END INITSTATE-----\0",
            INITSTATE_BLOB,
        ]
        .iter()
        .map(|data| data.to_vec())
        .collect();
        for data in &corpus {
            for blob_type in [BLOB_TYPE_INITSTATE, 1, -1, i32::MIN] {
                let mut blob = DecodedBlob::new();
                let call = std::panic::AssertUnwindSafe(|| blob.call(data, blob_type));
                std::panic::catch_unwind(call)
                    .unwrap_or_else(|_| panic!("the exported TPMLIB_DecodeBlob panicked"));
            }
        }
    }
}
