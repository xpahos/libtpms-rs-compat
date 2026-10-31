// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex
//
// License text: LICENSE.
// Upstream notices: LICENSES/libtpms-notices.txt.

use std::ffi::{CStr, CString, c_int, c_uchar, c_ulong, c_void};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr;

use crate::harness::{TPM_FAIL, TPM_SUCCESS, TpmResult};
use crate::memory::{
    FAKE_POINTER, MEMORY, TPM_ALLOC_MAX, TPM_SIZE, assert_filled, debug_log, fill, free, malloc,
};

const CHILD_ENV: &str = "LIBTPMS_ABI_MEMORY_OOM";
const SHIM_SOURCE: &str = include_str!("oom_shim.c");
const CASE: &str = "memory_oom::memory_allocation_failure_keeps_tpm_results";
const SUPPORTED: bool = cfg!(any(
    target_os = "macos",
    all(target_os = "linux", target_env = "gnu")
));
const PRELOAD_ENV: &str = if cfg!(target_os = "macos") {
    "DYLD_INSERT_LIBRARIES"
} else {
    "LD_PRELOAD"
};
const SHIM_FILE: &str = if cfg!(target_os = "macos") {
    "liboom_shim.dylib"
} else {
    "liboom_shim.so"
};
const MALLOC_FAILURE_SIZE: u32 = 12345;
const REALLOC_FAILURE_SIZE: u32 = 4096;
const LIVE_SIZE: u32 = 16;
const LIVE_SEED: u8 = 0x5c;

struct Shim {
    arm: unsafe extern "C" fn(),
    disarm: unsafe extern "C" fn(),
    refused: unsafe extern "C" fn() -> c_ulong,
}

impl Shim {
    fn load() -> Self {
        // SAFETY: each name is NUL-terminated and, when present, resolves to
        // the function of the matching type defined in oom_shim.c.
        unsafe {
            Self {
                arm: shim_symbol(c"libtpms_oom_arm"),
                disarm: shim_symbol(c"libtpms_oom_disarm"),
                refused: shim_symbol(c"libtpms_oom_refused"),
            }
        }
    }

    fn refused(&self) -> c_ulong {
        // SAFETY: the shim counter takes no arguments.
        unsafe { (self.refused)() }
    }

    fn failing<R>(&self, body: impl FnOnce() -> R) -> (R, c_ulong) {
        let before = self.refused();
        // SAFETY: arming only flips the shim flag; `body` performs no Rust
        // allocation while the allocator fails.
        unsafe { (self.arm)() };
        let result = body();
        // SAFETY: see above.
        unsafe { (self.disarm)() };
        (result, self.refused() - before)
    }
}

/// # Safety
///
/// `T` must be the function pointer type of the shim symbol `name`.
unsafe fn shim_symbol<T: Copy>(name: &CStr) -> T {
    assert_eq!(size_of::<T>(), size_of::<*mut c_void>());
    // SAFETY: `name` is NUL-terminated; RTLD_DEFAULT searches every image,
    // including the preloaded shim.
    let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
    assert!(
        !address.is_null(),
        "the allocation shim does not define {name:?}"
    );
    // SAFETY: the caller guarantees the symbol has type `T`.
    unsafe { std::mem::transmute_copy(&address) }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Call {
    rc: TpmResult,
    buffer: *mut c_uchar,
}

fn call_malloc(buffer: *mut c_uchar, size: u32) -> Call {
    let mut buffer = buffer;
    let rc = malloc(&mut buffer, size);
    Call { rc, buffer }
}

fn call_realloc(buffer: *mut c_uchar, size: u32) -> Call {
    let mut buffer = buffer;
    let rc = crate::memory::realloc(&mut buffer, size);
    Call { rc, buffer }
}

struct Calls {
    reuse: Call,
    malloc_oversize: Call,
    malloc_zero: Call,
    malloc_failure: (Call, c_ulong),
    realloc_oversize: Call,
    realloc_failure: (Call, c_ulong),
    realloc_null_failure: (Call, c_ulong),
}

fn failing_calls(shim: &Shim) -> Calls {
    let fake = ptr::without_provenance_mut(FAKE_POINTER);
    let mut live = ptr::null_mut();
    assert_eq!(malloc(&mut live, LIVE_SIZE), TPM_SUCCESS);
    fill(live, LIVE_SIZE, LIVE_SEED);

    let (reuse, _) = shim.failing(|| call_malloc(fake, 16));
    let (malloc_oversize, _) = shim.failing(|| call_malloc(ptr::null_mut(), TPM_ALLOC_MAX + 1));
    let (malloc_zero, _) = shim.failing(|| call_malloc(ptr::null_mut(), 0));
    let malloc_failure = shim.failing(|| call_malloc(ptr::null_mut(), MALLOC_FAILURE_SIZE));
    let (realloc_oversize, _) = shim.failing(|| call_realloc(live, u32::MAX));
    let realloc_failure = shim.failing(|| call_realloc(live, REALLOC_FAILURE_SIZE));
    let realloc_null_failure = shim.failing(|| call_realloc(ptr::null_mut(), 64));

    assert_filled(live, LIVE_SIZE, LIVE_SEED);
    let mut grown = live;
    assert_eq!(
        crate::memory::realloc(&mut grown, REALLOC_FAILURE_SIZE),
        TPM_SUCCESS
    );
    assert_filled(grown, LIVE_SIZE, LIVE_SEED);
    free(grown);

    Calls {
        reuse,
        malloc_oversize,
        malloc_zero,
        malloc_failure,
        realloc_oversize,
        realloc_failure,
        realloc_null_failure,
    }
    .checked(fake, live)
}

impl Calls {
    fn checked(self, fake: *mut c_uchar, live: *mut c_uchar) -> Self {
        let null = ptr::null_mut();
        assert_eq!(
            self.reuse,
            Call {
                rc: TPM_FAIL,
                buffer: fake
            }
        );
        assert_eq!(
            self.malloc_oversize,
            Call {
                rc: TPM_SIZE,
                buffer: null
            }
        );
        assert_eq!(
            self.malloc_zero,
            Call {
                rc: TPM_FAIL,
                buffer: null
            }
        );
        assert_eq!(
            self.malloc_failure.0,
            Call {
                rc: TPM_SIZE,
                buffer: null
            }
        );
        assert!(self.malloc_failure.1 > 0, "malloc was not refused");
        assert_eq!(
            self.realloc_oversize,
            Call {
                rc: TPM_SIZE,
                buffer: live
            }
        );
        assert_eq!(
            self.realloc_failure.0,
            Call {
                rc: TPM_SIZE,
                buffer: live
            }
        );
        assert!(self.realloc_failure.1 > 0, "realloc was not refused");
        assert_eq!(
            self.realloc_null_failure.0,
            Call {
                rc: TPM_SIZE,
                buffer: null
            }
        );
        assert!(
            self.realloc_null_failure.1 > 0,
            "realloc(NULL) was not refused"
        );
        self
    }
}

fn expected_log(prefix: &str) -> String {
    [
        format!(
            "TPM_Malloc: Error (fatal), *buffer {FAKE_POINTER:#x} should be NULL before malloc\n"
        ),
        format!(
            "TPM_Malloc: Error, size {} greater than maximum allowed\n",
            TPM_ALLOC_MAX + 1
        ),
        "TPM_Malloc: Error (fatal), size is zero\n".to_owned(),
        format!("TPM_Malloc: Error allocating {MALLOC_FAILURE_SIZE} bytes\n"),
        format!(
            "TPM_Realloc: Error, size {} greater than maximum allowed\n",
            u32::MAX
        ),
        format!("TPM_Realloc: Error reallocating {REALLOC_FAILURE_SIZE} bytes\n"),
        "TPM_Realloc: Error reallocating 64 bytes\n".to_owned(),
    ]
    .iter()
    .map(|line| format!("{prefix}{line}"))
    .collect()
}

fn logged_calls(shim: &Shim, dir: &Path, name: &str, prefix: Option<&str>) {
    let log = debug_log();
    let path = dir.join(format!("{name}.log"));
    let file = File::create(&path).expect("the debug log can be created");
    let c_prefix = prefix.map(|text| CString::new(text).expect("a prefix without NUL"));
    // SAFETY: the prefix is NULL or NUL-terminated and copied by the library;
    // `file` stays open until the descriptor is reset below.
    unsafe {
        assert_eq!(
            (log.set_prefix)(c_prefix.as_ref().map_or(ptr::null(), |text| text.as_ptr())),
            TPM_SUCCESS
        );
        (log.set_fd)(file.as_raw_fd());
        (log.set_level)(1);
    }
    failing_calls(shim);
    // SAFETY: disables logging before `file` closes.
    unsafe {
        (log.set_level)(0);
        (log.set_fd)(-1);
    }
    drop(file);
    let written = std::fs::read_to_string(&path).expect("the debug log can be read");
    assert_eq!(written, expected_log(prefix.unwrap_or("")), "{name}");
}

fn unwritable_log_calls(shim: &Shim, fd: c_int) {
    let log = debug_log();
    // SAFETY: an unwritable descriptor is a valid debug log setting; every
    // write to it fails.
    unsafe {
        assert_eq!((log.set_prefix)(c"memtest: ".as_ptr()), TPM_SUCCESS);
        (log.set_fd)(fd);
        (log.set_level)(1);
    }
    failing_calls(shim);
    // SAFETY: see above.
    unsafe {
        (log.set_level)(0);
        (log.set_fd)(-1);
        assert_eq!((log.set_prefix)(ptr::null()), TPM_SUCCESS);
    }
}

fn child(dir: &Path) {
    let shim = Shim::load();
    let _ = &*MEMORY;

    failing_calls(&shim);

    logged_calls(&shim, dir, "no-prefix", None);
    logged_calls(&shim, dir, "prefix", Some("memtest: "));
    logged_calls(
        &shim,
        dir,
        "long-prefix",
        Some(&format!("{}: ", "p".repeat(600))),
    );

    unwritable_log_calls(&shim, -1);
    let mut fds = [0 as c_int; 2];
    // SAFETY: `fds` is a live array of two ints as pipe() requires.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    // SAFETY: the read end is owned here and closed once, so writes to the
    // write end fail with EPIPE; Rust test binaries ignore SIGPIPE.
    assert_eq!(unsafe { libc::close(fds[0]) }, 0);
    unwritable_log_calls(&shim, fds[1]);
    // SAFETY: the write end is owned here and closed once.
    assert_eq!(unsafe { libc::close(fds[1]) }, 0);
}

fn build_shim(dir: &Path) -> PathBuf {
    let source = dir.join("oom_shim.c");
    std::fs::write(&source, SHIM_SOURCE).expect("the shim source can be written");
    let shim = dir.join(SHIM_FILE);
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let status = Command::new(&compiler)
        .args(["-shared", "-fPIC", "-O1", "-o"])
        .arg(&shim)
        .arg(&source)
        .status()
        .unwrap_or_else(|error| panic!("cannot run {compiler:?}: {error}"));
    assert!(status.success(), "the allocation shim does not compile");
    shim
}

#[test]
fn memory_allocation_failure_keeps_tpm_results() {
    if let Some(dir) = std::env::var_os(CHILD_ENV) {
        child(Path::new(&dir));
        return;
    }
    if !SUPPORTED {
        eprintln!("skipped: the allocation shim supports macOS and glibc only");
        return;
    }
    let dir =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("memory-oom-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("the scratch directory can be created");
    let shim = build_shim(&dir);
    let exe = std::env::current_exe().expect("the test binary knows its own path");
    let output = Command::new(exe)
        .args(["--exact", CASE, "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, &dir)
        .env(PRELOAD_ENV, &shim)
        .output()
        .expect("the allocation-failure case can run in a child process");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.code() == Some(0) && stdout.contains(&format!("test {CASE} ... ok")),
        "allocation-failure child did not finish normally ({}):\n--- stdout\n{stdout}\n--- stderr\n{stderr}",
        output.status
    );
    std::fs::remove_dir_all(&dir).expect("the scratch directory can be removed");
}
