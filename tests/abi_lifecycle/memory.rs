// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex
//
// License text: LICENSE.
// Upstream notices: LICENSES/libtpms-notices.txt.

use std::ffi::{CString, OsStr, c_char, c_int, c_uchar, c_uint, c_void};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::process::Command;
use std::ptr;
use std::sync::LazyLock;

use crate::harness::{TPM_FAIL, TPM_SUCCESS, TpmResult, library_path, symbol};

pub(crate) const TPM_SIZE: TpmResult = 23;
pub(crate) const TPM_ALLOC_MAX: u32 = 0x20000;
const DIAGNOSTICS_ENV: &str = "LIBTPMS_ABI_MEMORY_DIAGNOSTICS";

pub(crate) struct Memory {
    malloc: unsafe extern "C" fn(*mut *mut c_uchar, u32) -> TpmResult,
    realloc: unsafe extern "C" fn(*mut *mut c_uchar, u32) -> TpmResult,
    free: unsafe extern "C" fn(*mut c_uchar),
}

pub(crate) static MEMORY: LazyLock<Memory> = LazyLock::new(|| {
    let path = library_path();
    let display = path.display().to_string();
    let c_path = CString::new(display.clone()).expect("a path without NUL bytes");
    // SAFETY: plain dlopen of a shared library by path; the handle is never
    // closed, so the resolved functions stay valid for the whole process.
    let handle = unsafe { libc::dlopen(c_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen({display}) failed");
    // SAFETY: every type below matches the prototype in tpm_memory.h.
    unsafe {
        Memory {
            malloc: symbol(handle, &display, c"TPM_Malloc"),
            realloc: symbol(handle, &display, c"TPM_Realloc"),
            free: symbol(handle, &display, c"TPM_Free"),
        }
    }
});

pub(crate) fn malloc(buffer: &mut *mut c_uchar, size: u32) -> TpmResult {
    // SAFETY: `buffer` is a live, writable `unsigned char *`.
    unsafe { (MEMORY.malloc)(buffer, size) }
}

pub(crate) fn realloc(buffer: &mut *mut c_uchar, size: u32) -> TpmResult {
    // SAFETY: `buffer` is a live, writable `unsigned char *` holding NULL or
    // a C allocation owned by the caller.
    unsafe { (MEMORY.realloc)(buffer, size) }
}

pub(crate) fn free(buffer: *mut c_uchar) {
    // SAFETY: the callers pass NULL or a live allocation they give up.
    unsafe { (MEMORY.free)(buffer) }
}

pub(crate) fn fill(buffer: *mut c_uchar, len: u32, seed: u8) {
    for index in 0..len as usize {
        // SAFETY: the callers pass an allocation of at least `len` bytes.
        unsafe { buffer.add(index).write(seed.wrapping_add(index as u8)) };
    }
}

pub(crate) fn assert_filled(buffer: *const c_uchar, len: u32, seed: u8) {
    // SAFETY: the callers pass an allocation of at least `len` initialized
    // bytes.
    let bytes = unsafe { std::slice::from_raw_parts(buffer, len as usize) };
    for (index, byte) in bytes.iter().enumerate() {
        assert_eq!(*byte, seed.wrapping_add(index as u8), "byte {index}");
    }
}

fn foreign_pointer(slot: &mut u8) -> *mut c_uchar {
    ptr::from_mut(slot)
}

#[test]
fn memory_malloc_success_writable() {
    for size in [1, 64, 4096] {
        let mut buffer = ptr::null_mut();
        assert_eq!(malloc(&mut buffer, size), TPM_SUCCESS, "size {size}");
        assert!(!buffer.is_null(), "size {size}");
        fill(buffer, size, 0x31);
        assert_filled(buffer, size, 0x31);
        free(buffer);
    }
}

#[test]
fn memory_malloc_zero_size_rejection() {
    let mut buffer = ptr::null_mut();
    assert_eq!(malloc(&mut buffer, 0), TPM_FAIL);
    assert!(buffer.is_null());
}

#[test]
fn memory_malloc_non_null_initial_rejection() {
    let mut slot = 0x5a;
    let initial = foreign_pointer(&mut slot);
    for size in [1, 0, TPM_ALLOC_MAX, TPM_ALLOC_MAX + 1, u32::MAX] {
        let mut buffer = initial;
        assert_eq!(malloc(&mut buffer, size), TPM_FAIL, "size {size}");
        assert_eq!(buffer, initial, "size {size}");
    }
    assert_eq!(slot, 0x5a);
}

#[test]
fn memory_malloc_size_limit() {
    let mut buffer = ptr::null_mut();
    assert_eq!(malloc(&mut buffer, TPM_ALLOC_MAX), TPM_SUCCESS);
    assert!(!buffer.is_null());
    fill(buffer, TPM_ALLOC_MAX, 0x77);
    assert_filled(buffer, TPM_ALLOC_MAX, 0x77);
    free(buffer);

    for size in [TPM_ALLOC_MAX + 1, 0x8000_0000, u32::MAX] {
        let mut buffer = ptr::null_mut();
        assert_eq!(malloc(&mut buffer, size), TPM_SIZE, "size {size}");
        assert!(buffer.is_null(), "size {size}");
    }
}

#[test]
fn memory_realloc_from_null() {
    for size in [1, 32, TPM_ALLOC_MAX] {
        let mut buffer = ptr::null_mut();
        assert_eq!(realloc(&mut buffer, size), TPM_SUCCESS, "size {size}");
        assert!(!buffer.is_null(), "size {size}");
        fill(buffer, size, 0x11);
        assert_filled(buffer, size, 0x11);
        free(buffer);
    }
}

#[test]
fn memory_realloc_growth_and_shrinkage_preserve_contents() {
    let mut buffer = ptr::null_mut();
    assert_eq!(malloc(&mut buffer, 16), TPM_SUCCESS);
    fill(buffer, 16, 0xa0);

    assert_eq!(realloc(&mut buffer, 4096), TPM_SUCCESS);
    assert!(!buffer.is_null());
    assert_filled(buffer, 16, 0xa0);
    fill(buffer, 4096, 0x40);

    assert_eq!(realloc(&mut buffer, TPM_ALLOC_MAX), TPM_SUCCESS);
    assert_filled(buffer, 4096, 0x40);

    assert_eq!(realloc(&mut buffer, 8), TPM_SUCCESS);
    assert!(!buffer.is_null());
    assert_filled(buffer, 8, 0x40);

    assert_eq!(realloc(&mut buffer, 8), TPM_SUCCESS);
    assert_filled(buffer, 8, 0x40);
    free(buffer);
}

#[test]
fn memory_realloc_oversize_rejection_keeps_allocation() {
    let mut buffer = ptr::null_mut();
    assert_eq!(malloc(&mut buffer, 64), TPM_SUCCESS);
    fill(buffer, 64, 0xc3);
    let original = buffer;
    for size in [TPM_ALLOC_MAX + 1, 0x8000_0000, u32::MAX] {
        assert_eq!(realloc(&mut buffer, size), TPM_SIZE, "size {size}");
        assert_eq!(buffer, original, "size {size}");
        assert_filled(buffer, 64, 0xc3);
    }
    free(buffer);

    let mut empty = ptr::null_mut();
    assert_eq!(realloc(&mut empty, TPM_ALLOC_MAX + 1), TPM_SIZE);
    assert!(empty.is_null());
}

#[test]
fn memory_realloc_oversize_rejection_before_outer_pointer_use() {
    // SAFETY: the reference checks the size before it reads `*buffer`, so a
    // NULL outer pointer is well defined for oversized requests.
    let result = unsafe { (MEMORY.realloc)(ptr::null_mut(), TPM_ALLOC_MAX + 1) };
    assert_eq!(result, TPM_SIZE);
}

#[test]
fn memory_free_valid_and_null() {
    free(ptr::null_mut());
    let mut buffer = ptr::null_mut();
    assert_eq!(malloc(&mut buffer, 128), TPM_SUCCESS);
    fill(buffer, 128, 0x01);
    free(buffer);
    let mut buffer = ptr::null_mut();
    assert_eq!(realloc(&mut buffer, 128), TPM_SUCCESS);
    free(buffer);
}

#[test]
fn memory_free_releases_reference_allocation_to_libc() {
    let mut buffer = ptr::null_mut();
    assert_eq!(malloc(&mut buffer, 32), TPM_SUCCESS);
    // SAFETY: TPM_Malloc allocates with the C allocator, so libc free is a
    // valid release of the live allocation.
    unsafe { libc::free(buffer.cast::<c_void>()) };

    // SAFETY: plain C allocation handed to TPM_Realloc and TPM_Free, which
    // operate on the C allocator.
    let mut buffer = unsafe { libc::malloc(16) }.cast::<c_uchar>();
    assert!(!buffer.is_null());
    fill(buffer, 16, 0x99);
    assert_eq!(realloc(&mut buffer, 256), TPM_SUCCESS);
    assert_filled(buffer, 16, 0x99);
    free(buffer);
}

#[derive(Debug, Eq, PartialEq)]
enum ZeroRealloc {
    Allocated,
    Failed,
}

fn zero_realloc_from_null() -> ZeroRealloc {
    let mut buffer = ptr::null_mut();
    match realloc(&mut buffer, 0) {
        TPM_SUCCESS => {
            assert!(!buffer.is_null());
            free(buffer);
            ZeroRealloc::Allocated
        }
        TPM_SIZE => {
            assert!(buffer.is_null());
            ZeroRealloc::Failed
        }
        other => panic!("TPM_Realloc(NULL, 0) answered {other:#x}"),
    }
}

fn zero_realloc_of_allocation() -> ZeroRealloc {
    let mut buffer = ptr::null_mut();
    assert_eq!(malloc(&mut buffer, 16), TPM_SUCCESS);
    let original = buffer;
    match realloc(&mut buffer, 0) {
        TPM_SUCCESS => {
            assert!(!buffer.is_null());
            free(buffer);
            ZeroRealloc::Allocated
        }
        TPM_SIZE => {
            assert_eq!(buffer, original);
            ZeroRealloc::Failed
        }
        other => panic!("TPM_Realloc(p, 0) answered {other:#x}"),
    }
}

#[test]
fn memory_realloc_zero_size_platform_behavior() {
    let from_null = zero_realloc_from_null();
    let of_allocation = zero_realloc_of_allocation();
    if cfg!(target_os = "macos") {
        assert_eq!(from_null, ZeroRealloc::Allocated);
        assert_eq!(of_allocation, ZeroRealloc::Allocated);
    } else if cfg!(all(target_os = "linux", target_env = "gnu")) {
        assert_eq!(from_null, ZeroRealloc::Allocated);
        assert_eq!(of_allocation, ZeroRealloc::Failed);
    }
}

pub(crate) struct DebugLog {
    pub(crate) set_fd: unsafe extern "C" fn(c_int),
    pub(crate) set_level: unsafe extern "C" fn(c_uint),
    pub(crate) set_prefix: unsafe extern "C" fn(*const c_char) -> TpmResult,
}

pub(crate) fn debug_log() -> DebugLog {
    let path = library_path();
    let display = path.display().to_string();
    let c_path = CString::new(display.clone()).expect("a path without NUL bytes");
    // SAFETY: plain dlopen of the library MEMORY already holds open.
    let handle = unsafe { libc::dlopen(c_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen({display}) failed");
    // SAFETY: every type below matches the prototype in tpm_library.h.
    unsafe {
        DebugLog {
            set_fd: symbol(handle, &display, c"TPMLIB_SetDebugFD"),
            set_level: symbol(handle, &display, c"TPMLIB_SetDebugLevel"),
            set_prefix: symbol(handle, &display, c"TPMLIB_SetDebugPrefix"),
        }
    }
}

pub(crate) const FAKE_POINTER: usize = 0x1234;

fn diagnostics_child(log_path: &OsStr) {
    let _ = &*MEMORY;
    let log = debug_log();
    let file = File::create(log_path).expect("the debug log can be created");
    // SAFETY: the prefix is NUL-terminated and copied by the library; the
    // descriptor stays open until this child exits.
    unsafe {
        assert_eq!((log.set_prefix)(c"memtest: ".as_ptr()), TPM_SUCCESS);
        (log.set_fd)(file.as_raw_fd());
        (log.set_level)(1);
    }

    let mut buffer = ptr::without_provenance_mut(FAKE_POINTER);
    assert_eq!(malloc(&mut buffer, 16), TPM_FAIL);
    let mut buffer = ptr::null_mut();
    assert_eq!(malloc(&mut buffer, TPM_ALLOC_MAX + 1), TPM_SIZE);
    assert_eq!(malloc(&mut buffer, 0), TPM_FAIL);
    assert_eq!(realloc(&mut buffer, u32::MAX), TPM_SIZE);

    assert_eq!(malloc(&mut buffer, 16), TPM_SUCCESS);
    assert_eq!(realloc(&mut buffer, 32), TPM_SUCCESS);
    free(buffer);
    free(ptr::null_mut());

    let _ = zero_realloc_of_allocation();

    // SAFETY: disabling the debug log takes no pointers.
    unsafe { (log.set_level)(0) };
    assert_eq!(malloc(&mut ptr::null_mut(), 0), TPM_FAIL);
    // SAFETY: restores the library default descriptor before `file` closes.
    unsafe { (log.set_fd)(-1) };
}

#[test]
fn memory_debug_log_diagnostics_match_reference() {
    const CASE: &str = "memory::memory_debug_log_diagnostics_match_reference";
    if let Some(log_path) = std::env::var_os(DIAGNOSTICS_ENV) {
        diagnostics_child(&log_path);
        return;
    }
    let dir = std::env::temp_dir().join(format!("libtpms-memory-abi-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("the scratch directory can be created");
    let log_path = dir.join("debug.log");
    let exe = std::env::current_exe().expect("the test binary knows its own path");
    let output = Command::new(exe)
        .args(["--exact", CASE, "--nocapture", "--test-threads=1"])
        .env(DIAGNOSTICS_ENV, &log_path)
        .output()
        .expect("the diagnostics case can run in a child process");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains(&format!("test {CASE} ... ok")),
        "child failed ({}):\n{stdout}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !stdout.contains("TPM_Malloc") && !stdout.contains("TPM_Realloc"),
        "diagnostics leaked to stdout:\n{stdout}"
    );
    let log = std::fs::read_to_string(&log_path).expect("the child wrote its debug log");
    std::fs::remove_dir_all(&dir).expect("the scratch directory can be removed");

    let mut expected = format!(
        "memtest: TPM_Malloc: Error (fatal), *buffer {FAKE_POINTER:#x} should be NULL before malloc\n\
         memtest: TPM_Malloc: Error, size 131073 greater than maximum allowed\n\
         memtest: TPM_Malloc: Error (fatal), size is zero\n\
         memtest: TPM_Realloc: Error, size 4294967295 greater than maximum allowed\n"
    );
    if cfg!(all(target_os = "linux", target_env = "gnu")) {
        expected.push_str("memtest: TPM_Realloc: Error reallocating 0 bytes\n");
    }
    if cfg!(any(
        target_os = "macos",
        all(target_os = "linux", target_env = "gnu")
    )) {
        assert_eq!(log, expected);
    } else {
        assert!(log.starts_with(&expected), "debug log:\n{log}");
    }
}
