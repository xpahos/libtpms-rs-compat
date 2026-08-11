use core::ffi::c_char;
use core::ptr;
use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::library::TPM_FAIL;

pub trait FfiPanicFallback {
    fn panic_fallback() -> Self;
}

impl FfiPanicFallback for u32 {
    fn panic_fallback() -> Self {
        TPM_FAIL
    }
}

impl FfiPanicFallback for u8 {
    fn panic_fallback() -> Self {
        0
    }
}

impl FfiPanicFallback for () {
    fn panic_fallback() -> Self {}
}

impl<T> FfiPanicFallback for *mut T {
    fn panic_fallback() -> Self {
        core::ptr::null_mut()
    }
}

impl<T> FfiPanicFallback for *const T {
    fn panic_fallback() -> Self {
        core::ptr::null()
    }
}

pub fn ffi_guard<R: FfiPanicFallback>(f: impl FnOnce() -> R) -> R {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| R::panic_fallback())
}

fn malloc_uninit(size: usize) -> *mut u8 {
    if size == 0 {
        return ptr::null_mut();
    }
    // SAFETY: plain allocation; a NULL result is handled by the callers.
    unsafe { libc::malloc(size) }.cast()
}

#[must_use]
pub fn malloc_bytes(data: &[u8]) -> *mut u8 {
    let out = malloc_uninit(data.len());
    if !out.is_null() {
        // SAFETY: `out` has room for `data.len()` bytes and the regions
        // cannot overlap.
        unsafe { ptr::copy_nonoverlapping(data.as_ptr(), out, data.len()) };
    }
    out
}

#[must_use]
pub fn malloc_c_string(value: &str) -> *mut c_char {
    let bytes = value.as_bytes();
    if bytes.contains(&0) {
        return ptr::null_mut();
    }
    let Some(size) = bytes.len().checked_add(1) else {
        return ptr::null_mut();
    };
    let out = malloc_uninit(size);
    if out.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `out` has `size` == len + 1 bytes: the copied string plus a
    // final NUL terminator; the regions cannot overlap.
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
        out.add(bytes.len()).write(0);
    }
    out.cast()
}

pub struct MallocBuffer {
    ptr: *mut u8,
    len: usize,
}

impl MallocBuffer {
    /// # Safety
    ///
    /// `ptr` must come from the C allocator with `len` valid bytes, and
    /// ownership must transfer to the returned guard.
    pub unsafe fn from_raw(ptr: *mut u8, len: usize) -> Option<Self> {
        (!ptr.is_null()).then_some(Self { ptr, len })
    }

    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: `from_raw`'s contract guarantees `len` valid bytes.
        unsafe { core::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl Drop for MallocBuffer {
    fn drop(&mut self) {
        // SAFETY: `from_raw`'s contract: C allocator, owned by this guard.
        unsafe { libc::free(self.ptr.cast()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::CStr;

    #[test]
    fn malloc_c_string_round_trips_and_is_freeable() {
        let ptr = malloc_c_string("{\"a\":1}");
        assert!(!ptr.is_null());
        // SAFETY: `ptr` is a valid NUL-terminated string we just allocated.
        let round_trip = unsafe { CStr::from_ptr(ptr) };
        assert_eq!(round_trip.to_str().unwrap(), "{\"a\":1}");
        // SAFETY: allocated with malloc; free() is the documented contract.
        unsafe { libc::free(ptr.cast()) };
    }

    #[test]
    fn malloc_c_string_rejects_interior_nul() {
        assert!(malloc_c_string("a\0b").is_null());
    }

    #[test]
    fn malloc_c_string_of_empty_str_is_empty_c_string() {
        let ptr = malloc_c_string("");
        assert!(!ptr.is_null());
        // SAFETY: `ptr` is a valid NUL-terminated string we just allocated.
        assert_eq!(unsafe { CStr::from_ptr(ptr) }.to_bytes(), b"");
        // SAFETY: allocated with malloc.
        unsafe { libc::free(ptr.cast()) };
    }

    #[test]
    fn malloc_bytes_round_trips_and_is_freeable() {
        let data = [1u8, 0, 255, 42];
        let ptr = malloc_bytes(&data);
        assert!(!ptr.is_null());
        // SAFETY: `ptr` holds `data.len()` initialized bytes.
        assert_eq!(
            unsafe { core::slice::from_raw_parts(ptr, data.len()) },
            data
        );
        // SAFETY: allocated with malloc.
        unsafe { libc::free(ptr.cast()) };
    }

    #[test]
    fn malloc_bytes_of_empty_slice_is_null() {
        assert!(malloc_bytes(&[]).is_null());
    }

    #[test]
    fn malloc_buffer_wraps_and_frees_host_allocation() {
        let data = [7u8, 8, 9];
        let raw = malloc_bytes(&data);
        // SAFETY: `raw` was malloc'ed with `data.len()` valid bytes.
        let buffer = unsafe { MallocBuffer::from_raw(raw, data.len()) }.unwrap();
        assert_eq!(buffer.as_slice(), data);
        drop(buffer);
    }

    #[test]
    fn malloc_buffer_of_null_is_none() {
        // SAFETY: NULL carries no ownership.
        assert!(unsafe { MallocBuffer::from_raw(core::ptr::null_mut(), 4) }.is_none());
    }
}
