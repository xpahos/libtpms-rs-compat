// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex
//
// License text: LICENSE.
// Upstream notices: LICENSES/libtpms-notices.txt.

use core::ffi::{CStr, c_int, c_uint};
use core::fmt;
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::ffi::CString;
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::library::{TPM_FAIL, TPM_SUCCESS};
use crate::types::TpmResult;

const MESSAGE_MAX: usize = 255;
const COMBINED_MAX: usize = 512;

static FD: AtomicI32 = AtomicI32::new(-1);
static LEVEL: AtomicU32 = AtomicU32::new(0);
static PREFIX: Mutex<Option<CString>> = Mutex::new(None);

fn prefix_lock() -> MutexGuard<'static, Option<CString>> {
    PREFIX.lock().unwrap_or_else(PoisonError::into_inner)
}

pub(crate) fn set_fd(fd: c_int) {
    let _prefix = prefix_lock();
    FD.store(fd, Ordering::Relaxed);
}

pub(crate) fn set_level(level: c_uint) {
    let _prefix = prefix_lock();
    LEVEL.store(level, Ordering::Relaxed);
}

pub(crate) fn set_prefix(prefix: Option<&CStr>) -> TpmResult {
    let mut current = prefix_lock();
    *current = None;

    let Some(prefix) = prefix else {
        return TPM_SUCCESS;
    };
    let bytes = prefix.to_bytes_with_nul();
    let mut owned = Vec::new();
    if owned.try_reserve_exact(bytes.len()).is_err() {
        return TPM_FAIL;
    }
    owned.extend_from_slice(bytes);
    *current = Some(CString::from_vec_with_nul(owned).expect("copied from CStr"));
    TPM_SUCCESS
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LogError {
    Disabled,
    Filtered,
    TooLong,
    Write,
}

fn enabled(fd: c_int, level: c_uint) -> bool {
    fd != 0 && level != 0
}

fn accepted_indent(message: &[u8], level: c_uint) -> Option<usize> {
    let indent = message.iter().take_while(|&&byte| byte == b' ').count();
    if indent == message.len() || indent >= level as usize {
        return None;
    }
    Some(indent)
}

struct MessageBuffer {
    bytes: [u8; MESSAGE_MAX],
    len: usize,
}

impl MessageBuffer {
    fn new() -> Self {
        Self {
            bytes: [0; MESSAGE_MAX],
            len: 0,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl fmt::Write for MessageBuffer {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(fmt::Error)?;
        let target = self.bytes.get_mut(self.len..end).ok_or(fmt::Error)?;
        target.copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

fn write_message(message: &[u8]) -> Result<usize, LogError> {
    let prefix = prefix_lock();
    let fd = FD.load(Ordering::Relaxed);
    let level = LEVEL.load(Ordering::Relaxed);
    if !enabled(fd, level) {
        return Err(LogError::Disabled);
    }
    let indent = accepted_indent(message, level).ok_or(LogError::Filtered)?;
    let prefix = prefix.as_deref().map_or(&[][..], CStr::to_bytes);
    let mut combined = [0u8; COMBINED_MAX];
    match combined.get_mut(..prefix.len() + message.len()) {
        Some(target) => {
            let (head, tail) = target.split_at_mut(prefix.len());
            head.copy_from_slice(prefix);
            tail.copy_from_slice(message);
            write_all(fd, target)?;
        }
        None => {
            write_all(fd, prefix)?;
            write_all(fd, message)?;
        }
    }
    Ok(indent)
}

pub(crate) fn log(message: fmt::Arguments<'_>) -> Result<usize, LogError> {
    if !enabled(FD.load(Ordering::Relaxed), LEVEL.load(Ordering::Relaxed)) {
        return Err(LogError::Disabled);
    }
    let mut buffer = MessageBuffer::new();
    fmt::write(&mut buffer, message).map_err(|_| LogError::TooLong)?;
    write_message(buffer.as_bytes())
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn log_bytes(message: &[u8]) -> Result<usize, LogError> {
    write_message(message)
}

fn write_all(fd: c_int, mut buffer: &[u8]) -> Result<(), LogError> {
    while !buffer.is_empty() {
        // SAFETY: `buffer` is a live slice of initialized bytes for the
        // given length; `write` does not retain the pointer or mutate
        // through it, and an invalid `fd` yields an error return, not UB.
        let written = unsafe { libc::write(fd, buffer.as_ptr().cast(), buffer.len()) };
        if written < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(LogError::Write);
        }
        if written == 0 {
            return Err(LogError::Write);
        }
        buffer = &buffer[written as usize..];
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn prefix() -> Option<Vec<u8>> {
    prefix_lock()
        .as_deref()
        .map(CStr::to_bytes)
        .map(<[u8]>::to_vec)
}

#[cfg(test)]
pub(crate) fn fd_and_level() -> (c_int, c_uint) {
    (FD.load(Ordering::Relaxed), LEVEL.load(Ordering::Relaxed))
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    pub(crate) struct DebugStateGuard {
        _serial: MutexGuard<'static, ()>,
        saved_fd: c_int,
        saved_level: c_uint,
        saved_prefix: Option<CString>,
    }

    impl DebugStateGuard {
        pub(crate) fn hold() -> Self {
            let serial = TEST_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
            let prefix = prefix_lock();
            Self {
                _serial: serial,
                saved_fd: FD.load(Ordering::Relaxed),
                saved_level: LEVEL.load(Ordering::Relaxed),
                saved_prefix: prefix.clone(),
            }
        }
    }

    impl Drop for DebugStateGuard {
        fn drop(&mut self) {
            let mut prefix = prefix_lock();
            FD.store(self.saved_fd, Ordering::Relaxed);
            LEVEL.store(self.saved_level, Ordering::Relaxed);
            *prefix = self.saved_prefix.take();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::DebugStateGuard;
    use super::*;

    struct Pipe {
        read_fd: c_int,
        write_fd: Option<c_int>,
    }

    impl Pipe {
        fn new() -> Self {
            let mut fds = [0 as c_int; 2];
            // SAFETY: `fds` is a live array of two ints as pipe() requires.
            let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
            assert_eq!(rc, 0, "pipe() failed");
            let pipe = Self {
                read_fd: fds[0],
                write_fd: Some(fds[1]),
            };
            // SAFETY: `read_fd` is a pipe descriptor owned by this struct;
            // O_NONBLOCK lets drain() stop at end of buffered data.
            let rc = unsafe { libc::fcntl(pipe.read_fd, libc::F_SETFL, libc::O_NONBLOCK) };
            assert_eq!(rc, 0, "fcntl() failed");
            pipe
        }

        fn write_fd(&self) -> c_int {
            self.write_fd.expect("write side already closed")
        }

        fn close_write(&mut self) -> c_int {
            let fd = self.write_fd.take().expect("write side already closed");
            // SAFETY: `fd` was owned by this helper until the take() above
            // and is closed exactly once, here.
            assert_eq!(unsafe { libc::close(fd) }, 0);
            fd
        }

        fn drain(&self) -> Vec<u8> {
            let mut out = Vec::new();
            let mut chunk = [0u8; 256];
            loop {
                // SAFETY: `chunk` is a live writable buffer of the given
                // length owned by this frame.
                let n = unsafe { libc::read(self.read_fd, chunk.as_mut_ptr().cast(), chunk.len()) };
                if n <= 0 {
                    break;
                }
                out.extend_from_slice(&chunk[..n as usize]);
            }
            out
        }
    }

    impl Drop for Pipe {
        fn drop(&mut self) {
            // SAFETY: `read_fd` is owned by this struct and closed exactly
            // once; the write side is closed only while still owned, so a
            // descriptor handed out by close_write() is never touched.
            unsafe {
                libc::close(self.read_fd);
                if let Some(write_fd) = self.write_fd.take() {
                    libc::close(write_fd);
                }
            }
        }
    }

    #[test]
    fn default_logging_disabled() {
        let _state = DebugStateGuard::hold();
        assert_eq!(fd_and_level(), (-1, 0));
        assert_eq!(prefix(), None);
        assert_eq!(log(format_args!("dropped")), Err(LogError::Disabled));
        assert_eq!(log_bytes(b"dropped"), Err(LogError::Disabled));
    }

    #[test]
    fn descriptor_level_storage_replacement() {
        let _state = DebugStateGuard::hold();
        set_fd(11);
        set_level(2);
        assert_eq!(fd_and_level(), (11, 2));
        set_fd(12);
        set_level(7);
        assert_eq!(fd_and_level(), (12, 7));
    }

    #[test]
    fn logging_descriptor_and_level_requirement() {
        let _state = DebugStateGuard::hold();
        let pipe = Pipe::new();

        set_fd(pipe.write_fd());
        set_level(0);
        assert_eq!(log(format_args!("no level")), Err(LogError::Disabled));

        set_fd(0);
        set_level(1);
        assert_eq!(log(format_args!("no descriptor")), Err(LogError::Disabled));

        set_fd(pipe.write_fd());
        assert_eq!(log(format_args!("on\n")), Ok(0));
        assert_eq!(pipe.drain(), b"on\n");

        set_level(0);
        assert_eq!(log(format_args!("off again")), Err(LogError::Disabled));
        assert_eq!(pipe.drain(), b"");
    }

    #[test]
    fn prefix_message_output_configured_descriptor() {
        let _state = DebugStateGuard::hold();
        let first = Pipe::new();
        let second = Pipe::new();

        set_fd(first.write_fd());
        set_level(1);
        assert_eq!(set_prefix(Some(c"tpm: ")), TPM_SUCCESS);
        assert_eq!(log(format_args!("message {}\n", 7)), Ok(0));
        assert_eq!(first.drain(), b"tpm: message 7\n");

        assert_eq!(set_prefix(Some(c"")), TPM_SUCCESS);
        assert_eq!(prefix().as_deref(), Some(b"".as_slice()));
        assert_eq!(log(format_args!("empty prefix\n")), Ok(0));
        assert_eq!(first.drain(), b"empty prefix\n");

        set_fd(second.write_fd());
        assert_eq!(set_prefix(None), TPM_SUCCESS);
        assert_eq!(prefix(), None);
        assert_eq!(log_bytes(b"raw\n"), Ok(0));
        assert_eq!(first.drain(), b"");
        assert_eq!(second.drain(), b"raw\n");

        // SAFETY: the descriptor is a live pipe write end owned by `second`
        // and the message is a live 7-byte buffer.
        let n = unsafe { libc::write(second.write_fd(), b"caller\n".as_ptr().cast(), 7) };
        assert_eq!(n, 7);
        assert_eq!(second.drain(), b"caller\n");
    }

    #[test]
    fn indentation_level_filtering() {
        let _state = DebugStateGuard::hold();
        let pipe = Pipe::new();
        set_fd(pipe.write_fd());

        set_level(1);
        assert_eq!(log(format_args!("visible\n")), Ok(0));
        assert_eq!(pipe.drain(), b"visible\n");
        assert_eq!(log(format_args!(" hidden\n")), Err(LogError::Filtered));
        assert_eq!(pipe.drain(), b"");

        set_level(2);
        assert_eq!(log(format_args!(" visible\n")), Ok(1));
        assert_eq!(pipe.drain(), b" visible\n");
        assert_eq!(log(format_args!("  hidden\n")), Err(LogError::Filtered));
        assert_eq!(pipe.drain(), b"");

        set_level(5);
        assert_eq!(log(format_args!("    deep\n")), Ok(4));
        assert_eq!(pipe.drain(), b"    deep\n");
    }

    #[test]
    fn empty_whitespace_message_rejection() {
        let _state = DebugStateGuard::hold();
        let pipe = Pipe::new();
        set_fd(pipe.write_fd());
        set_level(7);

        assert_eq!(log(format_args!("")), Err(LogError::Filtered));
        assert_eq!(log(format_args!("   ")), Err(LogError::Filtered));
        assert_eq!(log_bytes(b""), Err(LogError::Filtered));
        assert_eq!(log_bytes(b"   "), Err(LogError::Filtered));
        assert_eq!(pipe.drain(), b"");
    }

    #[test]
    fn log_and_log_bytes_filter_parity() {
        let _state = DebugStateGuard::hold();
        let pipe = Pipe::new();
        set_fd(pipe.write_fd());
        set_level(2);

        assert_eq!(log(format_args!(" one\n")), Ok(1));
        assert_eq!(log_bytes(b" one\n"), Ok(1));
        assert_eq!(pipe.drain(), b" one\n one\n");

        assert_eq!(log(format_args!("  two\n")), Err(LogError::Filtered));
        assert_eq!(log_bytes(b"  two\n"), Err(LogError::Filtered));
        assert_eq!(pipe.drain(), b"");
    }

    #[test]
    fn post_filter_prefix_addition() {
        let _state = DebugStateGuard::hold();
        let pipe = Pipe::new();
        set_fd(pipe.write_fd());
        set_level(1);
        assert_eq!(set_prefix(Some(c"tpm: ")), TPM_SUCCESS);

        assert_eq!(log(format_args!(" hidden\n")), Err(LogError::Filtered));
        assert_eq!(pipe.drain(), b"");

        assert_eq!(log(format_args!("shown\n")), Ok(0));
        assert_eq!(pipe.drain(), b"tpm: shown\n");
    }

    #[test]
    fn formatted_message_reference_buffer_limit() {
        let _state = DebugStateGuard::hold();
        let pipe = Pipe::new();
        set_fd(pipe.write_fd());
        set_level(1);
        assert_eq!(set_prefix(Some(c"tpm: ")), TPM_SUCCESS);

        let fits = "x".repeat(MESSAGE_MAX - 1);
        assert_eq!(log(format_args!("{fits}\n")), Ok(0));
        assert_eq!(pipe.drain(), format!("tpm: {fits}\n").into_bytes());

        assert_eq!(log(format_args!("{fits}x\n")), Err(LogError::TooLong));
        assert_eq!(
            log(format_args!("{}", "y".repeat(MESSAGE_MAX + 1))),
            Err(LogError::TooLong)
        );
        assert_eq!(pipe.drain(), b"");
    }

    #[test]
    fn long_prefix_separate_writes() {
        let _state = DebugStateGuard::hold();
        let pipe = Pipe::new();
        set_fd(pipe.write_fd());
        set_level(1);
        let long = CString::new("p".repeat(COMBINED_MAX)).unwrap();
        assert_eq!(set_prefix(Some(&long)), TPM_SUCCESS);

        assert_eq!(log(format_args!("size {}\n", 12345)), Ok(0));
        let mut expected = long.as_bytes().to_vec();
        expected.extend_from_slice(b"size 12345\n");
        assert_eq!(pipe.drain(), expected);
    }

    #[test]
    fn disabled_logging_formats_nothing() {
        struct Panics;
        impl fmt::Display for Panics {
            fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
                panic!("formatted while logging is disabled")
            }
        }
        let _state = DebugStateGuard::hold();
        set_fd(1);
        set_level(0);
        assert_eq!(log(format_args!("{}", Panics)), Err(LogError::Disabled));
    }

    #[test]
    fn closed_descriptor_failure_panic_safety() {
        let _state = DebugStateGuard::hold();
        let mut pipe = Pipe::new();
        let closed_fd = pipe.close_write();

        set_fd(closed_fd);
        set_level(1);
        assert_eq!(log(format_args!("gone")), Err(LogError::Write));
        assert_eq!(log_bytes(b"gone"), Err(LogError::Write));
        assert_eq!(pipe.drain(), b"");
    }

    #[test]
    fn invalid_descriptor_failure_panic_safety() {
        let _state = DebugStateGuard::hold();
        set_level(1);

        set_fd(-1);
        assert_eq!(log(format_args!("lost")), Err(LogError::Write));

        set_fd(c_int::MAX);
        assert_eq!(log_bytes(b"lost"), Err(LogError::Write));
    }

    #[test]
    fn poisoned_config_lock_recovery() {
        let _state = DebugStateGuard::hold();
        let poison = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _prefix = PREFIX.lock().unwrap();
            panic!("poison the debug configuration lock");
        }));
        assert!(poison.is_err());
        assert!(PREFIX.is_poisoned());

        set_fd(5);
        set_level(3);
        assert_eq!(set_prefix(Some(c"p")), TPM_SUCCESS);
        assert_eq!(fd_and_level(), (5, 3));
        assert_eq!(prefix().as_deref(), Some(b"p".as_slice()));

        set_fd(-1);
        assert_eq!(log(format_args!("recovered")), Err(LogError::Write));
    }
}
