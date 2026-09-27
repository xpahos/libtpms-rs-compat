use std::collections::BTreeMap;
use std::ffi::{CStr, CString, c_char, c_int, c_uchar, c_void};
use std::fmt::Write as _;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::path::PathBuf;
use std::process::Command;
use std::ptr;
use std::sync::{Mutex, MutexGuard, PoisonError};

use sha2::{Digest, Sha256};

pub type TpmResult = u32;

pub const TPM_SUCCESS: TpmResult = 0x0000_0000;
pub const TPM_FAIL: TpmResult = 0x0000_0009;
pub const TPM_RETRY: TpmResult = 0x0000_0800;
const TPM_SIZE: TpmResult = 0x0000_0011;

const TPMLIB_TPM_VERSION_2: c_int = 1;

const LIBRARY_ENV: &str = "LIBTPMS_ABI_LIBRARY";
const TRANSCRIPT_ENV: &str = "LIBTPMS_ABI_TRANSCRIPT_DIR";
const CASE_ENV: &str = "LIBTPMS_ABI_CASE";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Permanent,
    Volatile,
}

impl State {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "permanent" => Some(Self::Permanent),
            "volatile" => Some(Self::Volatile),
            _ => None,
        }
    }

    fn wire(self) -> c_int {
        match self {
            Self::Permanent => 1,
            Self::Volatile => 2,
        }
    }
}

#[repr(C)]
struct Callbacks {
    size_of_struct: c_int,
    tpm_nvram_init: Option<unsafe extern "C" fn() -> TpmResult>,
    tpm_nvram_loaddata:
        Option<unsafe extern "C" fn(*mut *mut c_uchar, *mut u32, u32, *const c_char) -> TpmResult>,
    tpm_nvram_storedata:
        Option<unsafe extern "C" fn(*const c_uchar, u32, u32, *const c_char) -> TpmResult>,
    tpm_nvram_deletename: Option<unsafe extern "C" fn(u32, *const c_char, c_uchar) -> TpmResult>,
    tpm_io_init: Option<unsafe extern "C" fn() -> TpmResult>,
    tpm_io_getlocality: Option<unsafe extern "C" fn(*mut u32, u32) -> TpmResult>,
    tpm_io_getphysicalpresence: Option<unsafe extern "C" fn(*mut c_uchar, u32) -> TpmResult>,
}

struct Host {
    nvram: BTreeMap<String, Vec<u8>>,
    io_init: TpmResult,
    nvram_init: TpmResult,
    load_failures: BTreeMap<String, TpmResult>,
    known: Vec<(String, Vec<u8>)>,
    log: Vec<String>,
}

impl Host {
    fn label(&self, bytes: &[u8]) -> String {
        self.known
            .iter()
            .find(|(_, blob)| blob == bytes)
            .map_or_else(|| "new".to_owned(), |(label, _)| label.clone())
    }

    fn callback(&mut self, line: String) {
        note(format!("  cb {line}"));
        self.log.push(line);
    }
}

static HOST: Mutex<Host> = Mutex::new(Host {
    nvram: BTreeMap::new(),
    io_init: TPM_SUCCESS,
    nvram_init: TPM_SUCCESS,
    load_failures: BTreeMap::new(),
    known: Vec::new(),
    log: Vec::new(),
});

static TRANSCRIPT: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn host() -> MutexGuard<'static, Host> {
    HOST.lock().unwrap_or_else(PoisonError::into_inner)
}

pub fn note(line: String) {
    TRANSCRIPT
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(line);
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn c_name(name: *const c_char) -> String {
    if name.is_null() {
        return "<null>".to_owned();
    }
    // SAFETY: libtpms passes a NUL-terminated state name.
    unsafe { CStr::from_ptr(name) }
        .to_string_lossy()
        .into_owned()
}

unsafe extern "C" fn nvram_init() -> TpmResult {
    let mut host = host();
    let result = host.nvram_init;
    host.callback(format!("tpm_nvram_init -> {result:#x}"));
    result
}

unsafe extern "C" fn nvram_loaddata(
    data: *mut *mut c_uchar,
    length: *mut u32,
    _tpm_number: u32,
    name: *const c_char,
) -> TpmResult {
    let name = c_name(name);
    // SAFETY: libtpms passes valid out-pointers.
    unsafe {
        *data = ptr::null_mut();
        *length = 0;
    }
    let mut host = host();
    if let Some(&failure) = host.load_failures.get(&name) {
        host.callback(format!("tpm_nvram_loaddata({name}) -> {failure:#x}"));
        return failure;
    }
    let Some(blob) = host.nvram.get(&name).cloned() else {
        host.callback(format!("tpm_nvram_loaddata({name}) -> {TPM_RETRY:#x}"));
        return TPM_RETRY;
    };
    // SAFETY: plain allocation; libtpms takes ownership and frees it.
    let buffer = unsafe { libc::malloc(blob.len().max(1)) }.cast::<c_uchar>();
    if buffer.is_null() {
        return TPM_SIZE;
    }
    // SAFETY: `buffer` holds at least `blob.len()` bytes and the out-pointers
    // are valid.
    unsafe {
        ptr::copy_nonoverlapping(blob.as_ptr(), buffer, blob.len());
        *data = buffer;
        *length = blob.len() as u32;
    }
    let content = host.label(&blob);
    host.callback(format!(
        "tpm_nvram_loaddata({name}) -> 0x0 len={} content={content}",
        blob.len()
    ));
    TPM_SUCCESS
}

unsafe extern "C" fn nvram_storedata(
    data: *const c_uchar,
    length: u32,
    _tpm_number: u32,
    name: *const c_char,
) -> TpmResult {
    let name = c_name(name);
    let bytes = if data.is_null() {
        Vec::new()
    } else {
        // SAFETY: libtpms passes `length` readable bytes.
        unsafe { std::slice::from_raw_parts(data, length as usize) }.to_vec()
    };
    let mut host = host();
    let content = host.label(&bytes);
    host.callback(format!(
        "tpm_nvram_storedata({name}) len={} content={content}",
        bytes.len()
    ));
    host.nvram.insert(name, bytes);
    TPM_SUCCESS
}

unsafe extern "C" fn nvram_deletename(
    _tpm_number: u32,
    name: *const c_char,
    must_exist: c_uchar,
) -> TpmResult {
    let name = c_name(name);
    let mut host = host();
    host.callback(format!(
        "tpm_nvram_deletename({name}) must_exist={}",
        u8::from(must_exist != 0)
    ));
    let existed = host.nvram.remove(&name).is_some();
    if !existed && must_exist != 0 {
        TPM_FAIL
    } else {
        TPM_SUCCESS
    }
}

unsafe extern "C" fn io_init() -> TpmResult {
    let mut host = host();
    let result = host.io_init;
    host.callback(format!("tpm_io_init -> {result:#x}"));
    result
}

unsafe extern "C" fn io_getlocality(locality: *mut u32, _tpm_number: u32) -> TpmResult {
    host().callback("tpm_io_getlocality".to_owned());
    // SAFETY: libtpms passes a valid out-pointer.
    unsafe { *locality = 0 };
    TPM_SUCCESS
}

unsafe extern "C" fn io_getphysicalpresence(present: *mut c_uchar, _tpm_number: u32) -> TpmResult {
    // SAFETY: libtpms passes a valid out-pointer.
    unsafe { *present = 0 };
    TPM_SUCCESS
}

pub type ProcessFn =
    unsafe extern "C" fn(*mut *mut c_uchar, *mut u32, *mut u32, *mut c_uchar, u32) -> TpmResult;
type BlobFn = unsafe extern "C" fn(*mut *mut c_uchar, *mut u32) -> TpmResult;

struct Symbols {
    get_version: unsafe extern "C" fn() -> u32,
    choose_tpm_version: unsafe extern "C" fn(c_int) -> TpmResult,
    main_init: unsafe extern "C" fn() -> TpmResult,
    terminate: unsafe extern "C" fn(),
    process: ProcessFn,
    volatile_all_store: BlobFn,
    register_callbacks: unsafe extern "C" fn(*mut Callbacks) -> TpmResult,
    set_state: unsafe extern "C" fn(c_int, *const c_uchar, u32) -> TpmResult,
    get_state: unsafe extern "C" fn(c_int, *mut *mut c_uchar, *mut u32) -> TpmResult,
    set_profile: unsafe extern "C" fn(*const c_char) -> TpmResult,
    was_manufactured: unsafe extern "C" fn() -> c_uchar,
    established_get: unsafe extern "C" fn(*mut c_uchar) -> TpmResult,
    established_reset: unsafe extern "C" fn() -> TpmResult,
    hash_start: unsafe extern "C" fn() -> TpmResult,
    hash_data: unsafe extern "C" fn(*const c_uchar, u32) -> TpmResult,
    hash_end: unsafe extern "C" fn() -> TpmResult,
}

/// # Safety
///
/// `T` must be the function pointer type of the exported symbol `name`.
unsafe fn symbol<T: Copy>(handle: *mut c_void, library: &str, name: &CStr) -> T {
    assert_eq!(size_of::<T>(), size_of::<*mut c_void>());
    // SAFETY: `handle` is a live dlopen handle and `name` is NUL-terminated.
    let address = unsafe { libc::dlsym(handle, name.as_ptr()) };
    assert!(!address.is_null(), "{library} does not export {name:?}");
    // SAFETY: the caller guarantees the symbol has type `T`.
    unsafe { std::mem::transmute_copy(&address) }
}

fn default_library() -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary knows its own path");
    let file = if cfg!(target_os = "macos") {
        "libtpms.dylib"
    } else {
        "libtpms.so"
    };
    exe.parent()
        .expect("the test binary lives in a directory")
        .join(file)
}

#[derive(Debug, Eq, PartialEq)]
pub struct ProcessReply {
    pub result: TpmResult,
    pub size: u32,
    pub capacity: u32,
    pub response: Option<Vec<u8>>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct StateReply {
    pub result: TpmResult,
    pub length: u32,
    pub blob: Option<Vec<u8>>,
}

struct CBuffer(*mut c_uchar);

impl Drop for CBuffer {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the library allocated the buffer with the C allocator
            // and handed its ownership to the caller.
            unsafe { libc::free(self.0.cast()) };
        }
    }
}

/// # Safety
///
/// `process` must follow the `TPMLIB_Process` prototype.
pub unsafe fn call_process(process: ProcessFn, command: &[u8]) -> Result<ProcessReply, String> {
    let mut command = command.to_vec();
    let mut buffer: *mut c_uchar = ptr::null_mut();
    let mut size: u32 = 0;
    let mut capacity: u32 = 0;
    // SAFETY: valid out-pointers, a NULL response buffer the callee may
    // allocate, and `command.len()` readable command bytes.
    let result = unsafe {
        process(
            &mut buffer,
            &mut size,
            &mut capacity,
            command.as_mut_ptr(),
            command.len() as u32,
        )
    };
    let owned = CBuffer(buffer);
    if result != TPM_SUCCESS {
        return Ok(ProcessReply {
            result,
            size,
            capacity,
            response: None,
        });
    }
    if owned.0.is_null() {
        if size != 0 {
            return Err(format!(
                "TPMLIB_Process succeeded with a NULL response buffer and resp_size {size}"
            ));
        }
        return Ok(ProcessReply {
            result,
            size,
            capacity,
            response: Some(Vec::new()),
        });
    }
    if size > capacity {
        return Err(format!(
            "TPMLIB_Process returned resp_size {size} in a respbufsize {capacity} buffer"
        ));
    }
    // SAFETY: the buffer is non-NULL and the library reports `size` valid
    // bytes within its `capacity`-byte allocation.
    let response = unsafe { std::slice::from_raw_parts(owned.0, size as usize) }.to_vec();
    Ok(ProcessReply {
        result,
        size,
        capacity,
        response: Some(response),
    })
}

fn state_reply(result: TpmResult, buffer: *mut c_uchar, length: u32) -> Result<StateReply, String> {
    let owned = CBuffer(buffer);
    if owned.0.is_null() {
        if result == TPM_SUCCESS && length != 0 {
            return Err(format!(
                "a successful state export returned a NULL buffer and length {length}"
            ));
        }
        return Ok(StateReply {
            result,
            length,
            blob: None,
        });
    }
    // SAFETY: the library returned `length` initialized bytes in a buffer
    // the caller owns.
    let blob = unsafe { std::slice::from_raw_parts(owned.0, length as usize) }.to_vec();
    Ok(StateReply {
        result,
        length,
        blob: Some(blob),
    })
}

pub struct Tpm {
    symbols: Symbols,
}

impl Tpm {
    fn load() -> Self {
        let path = std::env::var_os(LIBRARY_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(default_library);
        let bytes = std::fs::read(&path).unwrap_or_else(|error| {
            panic!(
                "cannot read the library under test {}: {error}",
                path.display()
            )
        });
        let display = path.display().to_string();
        let c_path = CString::new(display.clone()).expect("a path without NUL bytes");
        // SAFETY: plain dlopen of a shared library by path.
        let handle = unsafe { libc::dlopen(c_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if handle.is_null() {
            // SAFETY: dlerror returns NULL or a NUL-terminated message.
            let error = unsafe { libc::dlerror() };
            let message = if error.is_null() {
                "unknown error".to_owned()
            } else {
                // SAFETY: see above.
                unsafe { CStr::from_ptr(error) }
                    .to_string_lossy()
                    .into_owned()
            };
            panic!("dlopen({display}) failed: {message}");
        }
        // SAFETY: every type below matches the prototype in tpm_library.h
        // or tpm_tis.h.
        let symbols = unsafe {
            Symbols {
                get_version: symbol(handle, &display, c"TPMLIB_GetVersion"),
                choose_tpm_version: symbol(handle, &display, c"TPMLIB_ChooseTPMVersion"),
                main_init: symbol(handle, &display, c"TPMLIB_MainInit"),
                terminate: symbol(handle, &display, c"TPMLIB_Terminate"),
                process: symbol(handle, &display, c"TPMLIB_Process"),
                volatile_all_store: symbol(handle, &display, c"TPMLIB_VolatileAll_Store"),
                register_callbacks: symbol(handle, &display, c"TPMLIB_RegisterCallbacks"),
                set_state: symbol(handle, &display, c"TPMLIB_SetState"),
                get_state: symbol(handle, &display, c"TPMLIB_GetState"),
                set_profile: symbol(handle, &display, c"TPMLIB_SetProfile"),
                was_manufactured: symbol(handle, &display, c"TPMLIB_WasManufactured"),
                established_get: symbol(handle, &display, c"TPM_IO_TpmEstablished_Get"),
                established_reset: symbol(handle, &display, c"TPM_IO_TpmEstablished_Reset"),
                hash_start: symbol(handle, &display, c"TPM_IO_Hash_Start"),
                hash_data: symbol(handle, &display, c"TPM_IO_Hash_Data"),
                hash_end: symbol(handle, &display, c"TPM_IO_Hash_End"),
            }
        };
        // SAFETY: TPMLIB_GetVersion takes no arguments and has no preconditions.
        let version = unsafe { (symbols.get_version)() };
        note(format!(
            "# library {display} sha256={} TPMLIB_GetVersion={version:#010x}",
            hex(&Sha256::digest(&bytes))
        ));
        Self { symbols }
    }

    fn result(&self, call: &str, invoke: impl FnOnce() -> TpmResult) -> TpmResult {
        note(format!("> {call}"));
        let result = invoke();
        note(format!("< {result:#x}"));
        result
    }

    pub fn choose_tpm2(&self) -> TpmResult {
        // SAFETY: plain value argument.
        self.result("TPMLIB_ChooseTPMVersion(TPMLIB_TPM_VERSION_2)", || unsafe {
            (self.symbols.choose_tpm_version)(TPMLIB_TPM_VERSION_2)
        })
    }

    pub fn register_callbacks(&self) -> TpmResult {
        let mut callbacks = Callbacks {
            size_of_struct: size_of::<Callbacks>() as c_int,
            tpm_nvram_init: Some(nvram_init),
            tpm_nvram_loaddata: Some(nvram_loaddata),
            tpm_nvram_storedata: Some(nvram_storedata),
            tpm_nvram_deletename: Some(nvram_deletename),
            tpm_io_init: Some(io_init),
            tpm_io_getlocality: Some(io_getlocality),
            tpm_io_getphysicalpresence: Some(io_getphysicalpresence),
        };
        // SAFETY: the library copies the table; the callbacks are 'static.
        self.result("TPMLIB_RegisterCallbacks(all seven)", || unsafe {
            (self.symbols.register_callbacks)(&mut callbacks)
        })
    }

    pub fn main_init(&self) -> TpmResult {
        // SAFETY: TPMLIB_MainInit has no arguments.
        self.result("TPMLIB_MainInit()", || unsafe {
            (self.symbols.main_init)()
        })
    }

    pub fn terminate(&self) {
        note("> TPMLIB_Terminate()".to_owned());
        // SAFETY: TPMLIB_Terminate has no preconditions.
        unsafe { (self.symbols.terminate)() };
    }

    pub fn set_state(&self, kind: State, label: &str, blob: &[u8]) -> TpmResult {
        // SAFETY: `blob` holds `blob.len()` readable bytes for the call.
        self.result(
            &format!("TPMLIB_SetState({kind:?}, {label} len={})", blob.len()),
            || unsafe { (self.symbols.set_state)(kind.wire(), blob.as_ptr(), blob.len() as u32) },
        )
    }

    pub fn get_state(&self, kind: State) -> Result<StateReply, String> {
        note(format!("> TPMLIB_GetState({kind:?})"));
        let mut buffer: *mut c_uchar = ptr::null_mut();
        let mut length: u32 = 0;
        // SAFETY: valid out-pointers; the library hands over a malloc'ed buffer.
        let result = unsafe { (self.symbols.get_state)(kind.wire(), &mut buffer, &mut length) };
        let reply = state_reply(result, buffer, length);
        note_state_reply(&reply);
        reply
    }

    pub fn volatile_all_store(&self) -> Result<StateReply, String> {
        note("> TPMLIB_VolatileAll_Store()".to_owned());
        let mut buffer: *mut c_uchar = ptr::null_mut();
        let mut length: u32 = 0;
        // SAFETY: valid out-pointers; the library hands over a malloc'ed buffer.
        let result = unsafe { (self.symbols.volatile_all_store)(&mut buffer, &mut length) };
        let reply = state_reply(result, buffer, length);
        note_state_reply(&reply);
        reply
    }

    pub fn set_profile(&self, profile: &str) -> TpmResult {
        let c_profile = CString::new(profile).expect("a profile without NUL bytes");
        // SAFETY: a NUL-terminated profile string.
        self.result(&format!("TPMLIB_SetProfile({profile})"), || unsafe {
            (self.symbols.set_profile)(c_profile.as_ptr())
        })
    }

    pub fn process(&self, command: &[u8]) -> Result<ProcessReply, String> {
        note(format!("> TPMLIB_Process({})", hex(command)));
        // SAFETY: the symbol has the TPMLIB_Process prototype.
        let reply = unsafe { call_process(self.symbols.process, command) };
        match &reply {
            Ok(reply) => note(format!(
                "< {:#x} resp_size={} respbufsize={} {}",
                reply.result,
                reply.size,
                reply.capacity,
                reply.response.as_deref().map(hex).unwrap_or_default()
            )),
            Err(violation) => note(format!("< contract violation: {violation}")),
        }
        reply
    }

    pub fn was_manufactured(&self) -> u8 {
        note("> TPMLIB_WasManufactured()".to_owned());
        // SAFETY: no arguments.
        let manufactured = unsafe { (self.symbols.was_manufactured)() };
        note(format!("< {manufactured}"));
        manufactured
    }

    pub fn established_get(&self) -> (TpmResult, u8) {
        note("> TPM_IO_TpmEstablished_Get()".to_owned());
        let mut established: c_uchar = 0xee;
        // SAFETY: a valid out-pointer.
        let result = unsafe { (self.symbols.established_get)(&mut established) };
        note(format!("< {result:#x} established={established}"));
        (result, established)
    }

    pub fn established_reset(&self) -> TpmResult {
        // SAFETY: no arguments.
        self.result("TPM_IO_TpmEstablished_Reset()", || unsafe {
            (self.symbols.established_reset)()
        })
    }

    pub fn hash_start(&self) -> TpmResult {
        // SAFETY: no arguments.
        self.result("TPM_IO_Hash_Start()", || unsafe {
            (self.symbols.hash_start)()
        })
    }

    pub fn hash_data(&self, data: &[u8]) -> TpmResult {
        // SAFETY: `data` holds `data.len()` readable bytes.
        self.result(&format!("TPM_IO_Hash_Data({})", hex(data)), || unsafe {
            (self.symbols.hash_data)(data.as_ptr(), data.len() as u32)
        })
    }

    pub fn hash_end(&self) -> TpmResult {
        // SAFETY: no arguments.
        self.result("TPM_IO_Hash_End()", || unsafe { (self.symbols.hash_end)() })
    }
}

fn note_state_reply(reply: &Result<StateReply, String>) {
    match reply {
        Ok(StateReply {
            result,
            length,
            blob: Some(blob),
        }) => note(format!(
            "< {result:#x} length={length} sha256={}",
            hex(&Sha256::digest(blob))
        )),
        Ok(StateReply {
            result,
            length,
            blob: None,
        }) => note(format!("< {result:#x} length={length} no buffer")),
        Err(violation) => note(format!("< contract violation: {violation}")),
    }
}

pub mod host {
    use super::*;

    pub fn remember(label: &str, blob: &[u8]) {
        let mut host = host();
        if !host.known.iter().any(|(known, _)| known == label) {
            host.known.push((label.to_owned(), blob.to_vec()));
        }
    }

    pub fn put(name: &str, label: &str, blob: Vec<u8>) {
        note(format!("# nvram {name} := {label} len={}", blob.len()));
        host().nvram.insert(name.to_owned(), blob);
    }

    pub fn fail_loads(name: &str, result: TpmResult) {
        note(format!("# tpm_nvram_loaddata({name}) answers {result:#x}"));
        let mut host = host();
        if result == TPM_SUCCESS {
            host.load_failures.remove(name);
        } else {
            host.load_failures.insert(name.to_owned(), result);
        }
    }

    pub fn io_init_answers(result: TpmResult) {
        note(format!("# tpm_io_init answers {result:#x}"));
        host().io_init = result;
    }

    pub fn nvram_init_answers(result: TpmResult) {
        note(format!("# tpm_nvram_init answers {result:#x}"));
        host().nvram_init = result;
    }

    pub fn take_callbacks() -> Vec<String> {
        std::mem::take(&mut host().log)
    }
}

pub fn transcript_text() -> String {
    let mut text = TRANSCRIPT
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .join("\n");
    text.push('\n');
    text
}

fn write_transcript(case: &str, outcome: &str) {
    let Some(dir) = std::env::var_os(TRANSCRIPT_ENV) else {
        return;
    };
    let dir = PathBuf::from(dir);
    std::fs::create_dir_all(&dir).expect("the transcript directory can be created");
    let mut text = transcript_text();
    text.push_str(&format!("# outcome {outcome}\n"));
    std::fs::write(dir.join(format!("{case}.txt")), text).expect("the transcript can be written");
}

pub fn isolated(case: &str, body: impl FnOnce(&Tpm)) {
    if std::env::var(CASE_ENV).as_deref() == Ok(case) {
        let tpm = Tpm::load();
        let outcome = catch_unwind(AssertUnwindSafe(|| body(&tpm)));
        match outcome {
            Ok(()) => write_transcript(case, "passed"),
            Err(panic) => {
                write_transcript(case, "failed");
                eprintln!("--- transcript of {case}\n{}", transcript_text());
                resume_unwind(panic);
            }
        }
        return;
    }
    let exe = std::env::current_exe().expect("the test binary knows its own path");
    let output = Command::new(exe)
        .args(["--exact", case, "--nocapture", "--test-threads=1"])
        .env(CASE_ENV, case)
        .output()
        .expect("the case can run in a child process");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stdout.contains(&format!("test {case} ... ok")),
        "{case} failed in its child process ({}):\n--- stdout\n{stdout}\n--- stderr\n{stderr}",
        output.status
    );
}

pub struct Fixture {
    records: BTreeMap<String, Vec<u8>>,
}

impl Fixture {
    pub fn parse(magic: &[u8; 8], blob: &[u8]) -> Self {
        assert_eq!(&blob[..8], magic, "fixture magic");
        assert_eq!(u16::from_be_bytes([blob[8], blob[9]]), 1, "fixture version");
        let count = u16::from_be_bytes([blob[10], blob[11]]);
        let mut at = 12;
        let mut records = BTreeMap::new();
        for _ in 0..count {
            let name_len = usize::from(blob[at]);
            at += 1;
            let name = std::str::from_utf8(&blob[at..at + name_len])
                .expect("an ASCII record name")
                .to_owned();
            at += name_len;
            let len = u32::from_be_bytes(blob[at..at + 4].try_into().expect("four bytes")) as usize;
            at += 4;
            records.insert(name, blob[at..at + len].to_vec());
            at += len;
        }
        assert_eq!(at, blob.len(), "no trailing fixture bytes");
        Self { records }
    }

    #[track_caller]
    pub fn get(&self, name: &str) -> &[u8] {
        self.records
            .get(name)
            .unwrap_or_else(|| panic!("the fixture has no {name} record"))
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.records.keys().map(String::as_str)
    }
}
