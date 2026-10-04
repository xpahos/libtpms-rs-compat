use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::identity::{sha256_bytes, sha256_file};
use crate::scenario::Scenario;

pub const DUDECT_REPOSITORY: &str = "https://github.com/oreparaz/dudect";
pub const DUDECT_REVISION: &str = "dc269651fb2567e46755cfb2a13d3875592968b5";
pub const DUDECT_HEADER_SHA256: &str =
    "3fb3b2bd7f9e17ae34b7c92518c1311c67342c56facc80da925d85f121b649da";
pub const DUDECT_LICENSE_SHA256: &str =
    "ee7cd5d500ab72e03a6c8aefe69c6311d698c83e732b19d152a6fa38fd521720";
pub const WORKER_SOURCE: &str = include_str!("../c/worker.c");
pub const WORKER_CFLAGS: &[&str] = &["-std=c11", "-O2", "-g", "-Wall", "-Wextra", "-Werror"];

#[derive(Debug)]
pub enum WorkerError {
    UnsupportedTimer {
        arch: String,
    },
    MissingLibrary(PathBuf),
    UnusablePath(PathBuf),
    Fetch(String),
    Checksum {
        file: String,
        expected: String,
        actual: String,
    },
    Compile(String),
    Spawn(std::io::Error),
    Crashed {
        status: String,
        detail: String,
    },
    Reported(String),
    Protocol(String),
    Timeout {
        operation: String,
        bound: TimeoutBound,
        waited_ms: u64,
        partial: String,
        stderr_tail: String,
    },
    Io(std::io::Error),
}

impl fmt::Display for WorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedTimer { arch } => write!(
                f,
                "unsupported timer: dudect {DUDECT_REVISION} measures with mfence+rdtsc and only builds for x86/x86_64; this host is {arch}"
            ),
            Self::MissingLibrary(path) => {
                write!(f, "backend library does not exist: {}", path.display())
            }
            Self::UnusablePath(path) => write!(
                f,
                "path cannot be passed to the worker (whitespace or non-UTF-8): {}",
                path.display()
            ),
            Self::Fetch(detail) => write!(f, "dudect download failed: {detail}"),
            Self::Checksum {
                file,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "checksum mismatch for {file}: expected {expected}, got {actual}"
                )
            }
            Self::Compile(detail) => write!(f, "worker compilation failed: {detail}"),
            Self::Spawn(error) => write!(f, "cannot start worker: {error}"),
            Self::Crashed { status, detail } => {
                write!(f, "worker terminated unexpectedly ({status}): {detail}")
            }
            Self::Reported(detail) => write!(f, "worker reported an error: {detail}"),
            Self::Protocol(detail) => write!(f, "worker protocol violation: {detail}"),
            Self::Timeout {
                operation,
                bound,
                waited_ms,
                partial,
                ..
            } => write!(
                f,
                "worker timed out during {operation} ({bound:?}) after {waited_ms} ms; worker terminated; partial output {partial:?}"
            ),
            Self::Io(error) => write!(f, "worker I/O failed: {error}"),
        }
    }
}

impl std::error::Error for WorkerError {}

impl From<std::io::Error> for WorkerError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

pub fn check_timer_support(arch: &str) -> Result<(), WorkerError> {
    match arch {
        "x86_64" | "x86" => Ok(()),
        other => Err(WorkerError::UnsupportedTimer {
            arch: other.to_string(),
        }),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DudectSource {
    pub repository: String,
    pub revision: String,
    pub header: PathBuf,
    pub header_sha256: String,
    pub license: PathBuf,
    pub license_sha256: String,
    pub license_name: String,
    pub modified: bool,
}

fn verify_checksum(path: &Path, expected: &str) -> Result<(), WorkerError> {
    let actual = sha256_file(path)?;
    if actual != expected {
        return Err(WorkerError::Checksum {
            file: path.display().to_string(),
            expected: expected.to_string(),
            actual,
        });
    }
    Ok(())
}

fn download(url: &str, destination: &Path) -> Result<(), WorkerError> {
    let output = Command::new("curl")
        .args(["-fsSL", "--retry", "3", "-o"])
        .arg(destination)
        .arg(url)
        .output()
        .map_err(|e| WorkerError::Fetch(format!("cannot run curl: {e}")))?;
    if !output.status.success() {
        return Err(WorkerError::Fetch(format!(
            "{url}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

pub fn ensure_dudect(work: &Path) -> Result<DudectSource, WorkerError> {
    let dir = work.join("deps").join(format!("dudect-{DUDECT_REVISION}"));
    fs::create_dir_all(&dir)?;
    let files = [
        ("src/dudect.h", "dudect.h", DUDECT_HEADER_SHA256),
        ("LICENSE", "LICENSE", DUDECT_LICENSE_SHA256),
    ];
    for (remote, local, expected) in files {
        let path = dir.join(local);
        if path.exists() && verify_checksum(&path, expected).is_ok() {
            continue;
        }
        let partial = dir.join(format!("{local}.partial"));
        let url =
            format!("https://raw.githubusercontent.com/oreparaz/dudect/{DUDECT_REVISION}/{remote}");
        download(&url, &partial)?;
        if let Err(error) = verify_checksum(&partial, expected) {
            let _ = fs::remove_file(&partial);
            return Err(error);
        }
        fs::rename(&partial, &path)?;
    }
    let source = DudectSource {
        repository: DUDECT_REPOSITORY.into(),
        revision: DUDECT_REVISION.into(),
        header: dir.join("dudect.h"),
        header_sha256: DUDECT_HEADER_SHA256.into(),
        license: dir.join("LICENSE"),
        license_sha256: DUDECT_LICENSE_SHA256.into(),
        license_name:
            "MIT (LICENSE file); the header also carries an Unlicense public-domain dedication"
                .into(),
        modified: false,
    };
    fs::write(
        dir.join("SOURCE.json"),
        serde_json::to_vec_pretty(&source).unwrap(),
    )?;
    Ok(source)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerBinary {
    pub path: PathBuf,
    pub sha256: String,
    pub source_sha256: String,
    pub compiler: String,
    pub compiler_version: String,
    pub command: Vec<String>,
    pub dudect: Option<DudectSource>,
    pub override_note: Option<String>,
}

pub fn override_worker(path: &Path) -> Result<WorkerBinary, WorkerError> {
    if !path.is_file() {
        return Err(WorkerError::Compile(format!(
            "worker executable override {} does not exist",
            path.display()
        )));
    }
    Ok(WorkerBinary {
        path: path.to_path_buf(),
        sha256: sha256_file(path)?,
        source_sha256: String::new(),
        compiler: "override".into(),
        compiler_version: "not built by this tool".into(),
        command: Vec::new(),
        dudect: None,
        override_note: Some(
            "worker supplied with --worker-executable (test fixture); its results are not dudect evidence".into(),
        ),
    })
}

pub fn compiler_version(compiler: &str) -> String {
    Command::new(compiler)
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|text| text.lines().next().map(str::to_string))
        .unwrap_or_else(|| "unknown".into())
}

pub fn build_worker(work: &Path, libtpms_include: &Path) -> Result<WorkerBinary, WorkerError> {
    check_timer_support(std::env::consts::ARCH)?;
    let dudect = ensure_dudect(work)?;
    verify_checksum(&dudect.header, DUDECT_HEADER_SHA256)?;
    if !libtpms_include.join("libtpms/tpm_library.h").exists() {
        return Err(WorkerError::Compile(format!(
            "libtpms headers not found under {}",
            libtpms_include.display()
        )));
    }
    let compiler = std::env::var("CC").unwrap_or_else(|_| "cc".into());
    let compiler_version = compiler_version(&compiler);
    let build = work.join("build");
    fs::create_dir_all(&build)?;
    let source_path = build.join("worker.c");
    fs::write(&source_path, WORKER_SOURCE)?;
    let key_material = format!(
        "{}\n{}\n{}\n{:?}\n{}",
        sha256_bytes(WORKER_SOURCE.as_bytes()),
        DUDECT_HEADER_SHA256,
        compiler_version,
        WORKER_CFLAGS,
        sha256_file(&libtpms_include.join("libtpms/tpm_library.h"))?
    );
    let key = &sha256_bytes(key_material.as_bytes())[..16];
    let output = build.join(format!("tpms-timing-worker-{key}"));
    let header_dir = dudect.header.parent().unwrap().to_path_buf();
    let mut command: Vec<String> = vec![compiler.clone()];
    command.extend(WORKER_CFLAGS.iter().map(|s| s.to_string()));
    command.push(format!("-I{}", header_dir.display()));
    command.push(format!("-I{}", libtpms_include.display()));
    command.push("-o".into());
    command.push(output.display().to_string());
    command.push(source_path.display().to_string());
    if cfg!(target_os = "linux") {
        command.push("-ldl".into());
    }
    command.push("-lm".into());
    if !output.exists() {
        let result = Command::new(&command[0])
            .args(&command[1..])
            .output()
            .map_err(|e| WorkerError::Compile(format!("cannot run {compiler}: {e}")))?;
        if !result.status.success() {
            return Err(WorkerError::Compile(
                String::from_utf8_lossy(&result.stderr).into_owned(),
            ));
        }
    }
    Ok(WorkerBinary {
        sha256: sha256_file(&output)?,
        path: output,
        source_sha256: sha256_bytes(WORKER_SOURCE.as_bytes()),
        compiler,
        compiler_version,
        command,
        dudect: Some(dudect),
        override_note: None,
    })
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    clap::ValueEnum,
    PartialOrd,
    Ord,
)]
#[serde(rename_all = "kebab-case")]
pub enum BackendName {
    Rust,
    Reference,
}

impl BackendName {
    pub fn name(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::Reference => "reference",
        }
    }
}

impl fmt::Display for BackendName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum BackendSpec {
    Library { name: BackendName, path: PathBuf },
    Control { scenario: Scenario },
}

impl BackendSpec {
    pub fn label(&self) -> String {
        match self {
            Self::Library { name, .. } => name.name().to_string(),
            Self::Control { scenario } => scenario.name().to_string(),
        }
    }

    fn init_arguments(&self) -> Result<(String, String), WorkerError> {
        match self {
            Self::Library { path, .. } => {
                if !path.is_file() {
                    return Err(WorkerError::MissingLibrary(path.clone()));
                }
                let text = path
                    .to_str()
                    .filter(|s| !s.chars().any(char::is_whitespace))
                    .ok_or_else(|| WorkerError::UnusablePath(path.clone()))?;
                Ok(("tpm".into(), text.into()))
            }
            Self::Control { scenario } => match scenario {
                Scenario::ControlPositive => Ok(("control".into(), "positive".into())),
                Scenario::ControlNegative => Ok(("control".into(), "negative".into())),
                Scenario::EcdhP521 => Err(WorkerError::Protocol(
                    "ecdh-p521 needs a library backend".into(),
                )),
            },
        }
    }
}

pub type WorkerInfo = BTreeMap<String, String>;

pub const DEFAULT_OPERATION_TIMEOUT: Duration = Duration::from_secs(300);
pub const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TimeoutBound {
    OperationLimit,
    CampaignDeadline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Supervision {
    Bounded,
    Unbounded,
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub operation: Duration,
    pub shutdown: Duration,
    pub deadline: Option<Instant>,
}

impl Limits {
    pub fn new(operation: Duration) -> Self {
        Self {
            operation,
            shutdown: DEFAULT_SHUTDOWN_TIMEOUT.min(operation),
            deadline: None,
        }
    }

    fn bound(&self, limit: Duration) -> (Instant, TimeoutBound) {
        let operation = Instant::now() + limit;
        match self.deadline {
            Some(deadline) if deadline < operation => (deadline, TimeoutBound::CampaignDeadline),
            _ => (operation, TimeoutBound::OperationLimit),
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::new(DEFAULT_OPERATION_TIMEOUT)
    }
}

pub struct WorkerProcess {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    buffer: Vec<u8>,
    stderr_path: PathBuf,
    limits: Limits,
    supervision: Supervision,
    terminated: bool,
    failure_reported: bool,
    pub info: WorkerInfo,
}

pub const MAX_LINE_BYTES: usize = 64 << 20;
pub const DIAGNOSTIC_BYTES: usize = 512;

pub fn bounded_text(bytes: &[u8], limit: usize) -> String {
    let kept = &bytes[..bytes.len().min(limit)];
    let mut text = String::from_utf8_lossy(kept).into_owned();
    if bytes.len() > limit {
        text.push_str(&format!("... [{} more bytes]", bytes.len() - limit));
    }
    text
}
pub const SHUTDOWN_CAPTURE_BYTES: usize = 64 << 10;

fn describe_status(status: ExitStatus) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return format!("killed by signal {signal}");
        }
    }
    match status.code() {
        Some(code) => format!("exit code {code}"),
        None => "unknown status".into(),
    }
}

fn tail(path: &Path) -> String {
    let text = fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(5)..].join(" | ")
}

fn set_nonblocking(fd: RawFd) -> std::io::Result<()> {
    // SAFETY: fd is an open pipe descriptor owned by a live ChildStdin/ChildStdout; F_GETFL/F_SETFL only change its status flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: as above.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn wait_ready(
    fd: RawFd,
    events: libc::c_short,
    deadline: Option<Instant>,
) -> std::io::Result<bool> {
    loop {
        let timeout = match deadline {
            None => -1,
            Some(deadline) => {
                let now = Instant::now();
                if now >= deadline {
                    return Ok(false);
                }
                (deadline - now).as_millis().clamp(1, i32::MAX as u128) as libc::c_int
            }
        };
        let mut entry = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: entry is a valid pollfd for the duration of the call and nfds is 1.
        let rc = unsafe { libc::poll(&mut entry, 1, timeout) };
        if rc < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if rc > 0 {
            return Ok(true);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeasureReply {
    Samples {
        class: [Vec<u64>; 2],
        order: String,
        nv_stores_warmup: u64,
        nv_stores_measured: u64,
    },
    Mismatch {
        class: usize,
        tpmlib_rc: u32,
        response: Vec<u8>,
        nv_stores_measured: u64,
    },
}

impl WorkerProcess {
    pub fn spawn(
        worker: &Path,
        backend: &BackendSpec,
        cpu: Option<usize>,
        stderr_path: &Path,
        limits: Limits,
    ) -> Result<Self, WorkerError> {
        Self::spawn_supervised(
            worker,
            backend,
            cpu,
            stderr_path,
            limits,
            Supervision::Bounded,
        )
    }

    pub fn spawn_supervised(
        worker: &Path,
        backend: &BackendSpec,
        cpu: Option<usize>,
        stderr_path: &Path,
        limits: Limits,
        supervision: Supervision,
    ) -> Result<Self, WorkerError> {
        let (kind, argument) = backend.init_arguments()?;
        let stderr = fs::File::create(stderr_path)?;
        let mut child = Command::new(worker)
            .arg("serve")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr))
            .spawn()
            .map_err(WorkerError::Spawn)?;
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut process = Self {
            child,
            stdin,
            stdout,
            buffer: Vec::new(),
            stderr_path: stderr_path.to_path_buf(),
            limits,
            supervision,
            terminated: false,
            failure_reported: false,
            info: WorkerInfo::new(),
        };
        set_nonblocking(process.stdin.as_raw_fd())?;
        set_nonblocking(process.stdout.as_raw_fd())?;
        let (deadline, bound) = process.limits.bound(process.limits.operation);
        let ready = process.read_line("greeting", deadline, bound)?;
        if ready != "ready 1" {
            process.terminate("protocol violation in greeting");
            return Err(WorkerError::Protocol(format!(
                "unexpected greeting {ready:?}"
            )));
        }
        let cpu_text = cpu.map(|c| c as i64).unwrap_or(-1);
        let (deadline, bound) = process.limits.bound(process.limits.operation);
        process.send(
            "init",
            &format!("init {kind} {argument} {cpu_text}"),
            deadline,
            bound,
        )?;
        loop {
            let line = process.read_line("init", deadline, bound)?;
            if line == "ok" {
                break;
            }
            match line.strip_prefix("info ") {
                Some(rest) => {
                    let (key, value) = rest.split_once(' ').unwrap_or((rest, ""));
                    process.info.insert(key.to_string(), value.to_string());
                }
                None => {
                    process.terminate("protocol violation during init");
                    return Err(WorkerError::Protocol(format!(
                        "unexpected init line {line:?}"
                    )));
                }
            }
        }
        Ok(process)
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn set_deadline(&mut self, deadline: Option<Instant>) {
        self.limits.deadline = deadline;
    }

    fn effective(&self, deadline: Instant) -> Option<Instant> {
        match self.supervision {
            Supervision::Bounded => Some(deadline),
            Supervision::Unbounded => None,
        }
    }

    fn expired(&self, deadline: Instant) -> bool {
        self.effective(deadline)
            .is_some_and(|deadline| Instant::now() >= deadline)
    }

    fn note_failure<T>(&mut self, result: Result<T, WorkerError>) -> Result<T, WorkerError> {
        if result.is_err() {
            self.failure_reported = true;
        }
        result
    }

    fn terminate(&mut self, reason: &str) {
        if self.terminated {
            return;
        }
        self.terminated = true;
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
        }
        let status = self
            .child
            .wait()
            .map(describe_status)
            .unwrap_or_else(|e| e.to_string());
        if let Ok(mut log) = fs::OpenOptions::new().append(true).open(&self.stderr_path) {
            let _ = writeln!(log, "tpms-timing supervisor: {reason}; worker {status}");
        }
    }

    fn timeout(&mut self, operation: &str, bound: TimeoutBound, started: Instant) -> WorkerError {
        let partial = bounded_text(&self.buffer, 4096);
        let waited = started.elapsed();
        self.terminate(&format!(
            "{operation} exceeded its {bound:?} after {waited:?}; partial output {partial:?}"
        ));
        WorkerError::Timeout {
            operation: operation.into(),
            bound,
            waited_ms: waited.as_millis() as u64,
            partial,
            stderr_tail: tail(&self.stderr_path),
        }
    }

    fn exited(&mut self, operation: &str) -> WorkerError {
        let grace = Instant::now() + Duration::from_secs(1);
        let status = loop {
            match self.child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) if Instant::now() < grace => std::thread::sleep(Duration::from_millis(20)),
                _ => break None,
            }
        };
        let status = match status {
            Some(status) => {
                self.terminated = true;
                describe_status(status)
            }
            None => {
                self.terminate(&format!(
                    "{operation}: worker closed its pipes but kept running"
                ));
                "closed its pipes and was killed".into()
            }
        };
        WorkerError::Crashed {
            status: format!("{status} during {operation}"),
            detail: tail(&self.stderr_path),
        }
    }

    fn send(
        &mut self,
        operation: &str,
        line: &str,
        deadline: Instant,
        bound: TimeoutBound,
    ) -> Result<(), WorkerError> {
        if self.terminated {
            return Err(WorkerError::Protocol(format!(
                "{operation}: worker already terminated"
            )));
        }
        let started = Instant::now();
        let mut bytes = line.as_bytes().to_vec();
        bytes.push(b'\n');
        let mut written = 0;
        let fd = self.stdin.as_raw_fd();
        while written < bytes.len() {
            if self.expired(deadline) {
                return Err(self.timeout(&format!("{operation} (request write)"), bound, started));
            }
            match self.stdin.write(&bytes[written..]) {
                Ok(0) => return Err(self.exited(operation)),
                Ok(n) => written += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if !wait_ready(fd, libc::POLLOUT, self.effective(deadline))? {
                        return Err(self.timeout(
                            &format!("{operation} (request write)"),
                            bound,
                            started,
                        ));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                    return Err(self.exited(operation));
                }
                Err(e) => return Err(WorkerError::Io(e)),
            }
        }
        Ok(())
    }

    fn read_line(
        &mut self,
        operation: &str,
        deadline: Instant,
        bound: TimeoutBound,
    ) -> Result<String, WorkerError> {
        if self.terminated {
            return Err(WorkerError::Protocol(format!(
                "{operation}: worker already terminated"
            )));
        }
        let started = Instant::now();
        let fd = self.stdout.as_raw_fd();
        let mut chunk = [0u8; 8192];
        loop {
            if self.expired(deadline) {
                return Err(self.timeout(operation, bound, started));
            }
            if let Some(position) = self.buffer.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = self.buffer.drain(..=position).collect();
                let line = String::from_utf8_lossy(&line).trim_end().to_string();
                if let Some(detail) = line.strip_prefix("error ") {
                    self.terminate(&format!("worker reported error during {operation}"));
                    return Err(WorkerError::Reported(detail.to_string()));
                }
                return Ok(line);
            }
            match self.stdout.read(&mut chunk) {
                Ok(0) => return Err(self.exited(operation)),
                Ok(n) => {
                    self.buffer.extend_from_slice(&chunk[..n]);
                    if self.buffer.len() > MAX_LINE_BYTES {
                        let size = self.buffer.len();
                        self.terminate(&format!(
                            "{operation}: reply line exceeded {MAX_LINE_BYTES} bytes without a newline"
                        ));
                        return Err(WorkerError::Protocol(format!(
                            "{operation}: reply line of {size} bytes exceeds {MAX_LINE_BYTES}"
                        )));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if !wait_ready(fd, libc::POLLIN, self.effective(deadline))? {
                        return Err(self.timeout(operation, bound, started));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(WorkerError::Io(e)),
            }
        }
    }

    pub fn exec(&mut self, command: &[u8]) -> Result<(u32, Vec<u8>), WorkerError> {
        let result = self.exec_inner(command);
        self.note_failure(result)
    }

    fn exec_inner(&mut self, command: &[u8]) -> Result<(u32, Vec<u8>), WorkerError> {
        let (deadline, bound) = self.limits.bound(self.limits.operation);
        self.send(
            "exec",
            &format!("exec {}", hex::encode(command)),
            deadline,
            bound,
        )?;
        let line = self.read_line("exec", deadline, bound)?;
        let mut parts = line.split(' ');
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some("resp"), Some(rc), response, None) => {
                let rc = u32::from_str_radix(rc, 16)
                    .map_err(|_| WorkerError::Protocol(format!("bad rc in {line:?}")))?;
                let response = hex::decode(response.unwrap_or(""))
                    .map_err(|_| WorkerError::Protocol(format!("bad response in {line:?}")))?;
                Ok((rc, response))
            }
            _ => Err(WorkerError::Protocol(format!(
                "unexpected exec reply {line:?}"
            ))),
        }
    }

    pub fn measure(
        &mut self,
        rounds: usize,
        seed: u64,
        warmup: usize,
        commands: [&[u8]; 2],
        expected: [&[u8]; 2],
    ) -> Result<MeasureReply, WorkerError> {
        let result = self.measure_inner(rounds, seed, warmup, commands, expected);
        self.note_failure(result)
    }

    fn measure_inner(
        &mut self,
        rounds: usize,
        seed: u64,
        warmup: usize,
        commands: [&[u8]; 2],
        expected: [&[u8]; 2],
    ) -> Result<MeasureReply, WorkerError> {
        let (deadline, bound) = self.limits.bound(self.limits.operation);
        self.send(
            "measure",
            &format!(
                "measure {rounds} {seed:016x} {warmup} {} {} {} {}",
                hex::encode(commands[0]),
                hex::encode(expected[0]),
                hex::encode(commands[1]),
                hex::encode(expected[1])
            ),
            deadline,
            bound,
        )?;
        let begin = self.read_line("measure", deadline, bound)?;
        if begin != "measure-begin" {
            return Err(WorkerError::Protocol(format!("unexpected {begin:?}")));
        }
        let mut fields: BTreeMap<String, String> = BTreeMap::new();
        loop {
            let line = self.read_line("measure", deadline, bound)?;
            if line == "measure-end" {
                break;
            }
            let (key, value) = line.split_once(' ').unwrap_or((line.as_str(), ""));
            fields.insert(key.to_string(), value.to_string());
        }
        let number = |key: &str| -> Result<u64, WorkerError> {
            fields
                .get(key)
                .and_then(|v| v.parse().ok())
                .ok_or_else(|| WorkerError::Protocol(format!("missing {key}")))
        };
        let nv_stores_warmup = number("nvstores_warmup")?;
        let nv_stores_measured = number("nvstores_measured")?;
        if let Some(mismatch) = fields.get("mismatch") {
            let parts: Vec<&str> = mismatch.split(' ').collect();
            if parts.len() < 2 {
                return Err(WorkerError::Protocol(format!("bad mismatch {mismatch:?}")));
            }
            return Ok(MeasureReply::Mismatch {
                class: parts[0]
                    .parse()
                    .map_err(|_| WorkerError::Protocol("bad class".into()))?,
                tpmlib_rc: u32::from_str_radix(parts[1], 16)
                    .map_err(|_| WorkerError::Protocol("bad rc".into()))?,
                response: hex::decode(parts.get(2).copied().unwrap_or(""))
                    .map_err(|_| WorkerError::Protocol("bad response".into()))?,
                nv_stores_measured,
            });
        }
        let parse_ticks = |key: &str| -> Result<Vec<u64>, WorkerError> {
            let text = fields
                .get(key)
                .ok_or_else(|| WorkerError::Protocol(format!("missing {key}")))?;
            if text == "-" {
                return Ok(Vec::new());
            }
            text.split(',')
                .map(|v| {
                    v.parse::<i64>()
                        .ok()
                        .filter(|t| *t >= 0)
                        .map(|t| t as u64)
                        .ok_or_else(|| WorkerError::Protocol(format!("bad tick {v:?}")))
                })
                .collect()
        };
        let class = [parse_ticks("class0")?, parse_ticks("class1")?];
        if class[0].len() != rounds || class[1].len() != rounds {
            return Err(WorkerError::Protocol(
                "sample count differs from request".into(),
            ));
        }
        Ok(MeasureReply::Samples {
            class,
            order: fields.get("order").cloned().unwrap_or_default(),
            nv_stores_warmup,
            nv_stores_measured,
        })
    }

    pub fn close(mut self) -> Result<String, WorkerError> {
        if self.failure_reported {
            self.terminate("cleanup after a worker failure that was already reported");
            return Ok("terminated after an already reported failure".into());
        }
        if self.terminated {
            return Err(WorkerError::Protocol(
                "worker was terminated before shutdown".into(),
            ));
        }
        let (deadline, bound) = self.limits.bound(self.limits.shutdown);
        let started = Instant::now();
        self.send("shutdown", "quit", deadline, bound)?;
        let mut captured = std::mem::take(&mut self.buffer);
        captured.truncate(SHUTDOWN_CAPTURE_BYTES);
        let mut discarded = 0usize;
        let fd = self.stdout.as_raw_fd();
        let mut chunk = [0u8; 8192];
        loop {
            if self.expired(deadline) {
                self.buffer = captured;
                return Err(self.timeout("shutdown", bound, started));
            }
            match self.stdout.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    let room = SHUTDOWN_CAPTURE_BYTES.saturating_sub(captured.len()).min(n);
                    captured.extend_from_slice(&chunk[..room]);
                    discarded += n - room;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if !wait_ready(fd, libc::POLLIN, self.effective(deadline))? {
                        self.buffer = captured;
                        return Err(self.timeout("shutdown", bound, started));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(WorkerError::Io(e)),
            }
        }
        let status = loop {
            match self.child.try_wait()? {
                Some(status) => break status,
                None if !self.expired(deadline) => std::thread::sleep(Duration::from_millis(20)),
                None => {
                    self.buffer = captured;
                    return Err(self.timeout("shutdown (exit)", bound, started));
                }
            }
        };
        self.terminated = true;
        let description = describe_status(status);
        let output = String::from_utf8_lossy(&captured).into_owned();
        if !status.success() {
            if let Ok(mut log) = fs::OpenOptions::new().append(true).open(&self.stderr_path) {
                let _ = writeln!(
                    log,
                    "tpms-timing supervisor: worker {description} during shutdown"
                );
            }
            return Err(WorkerError::Crashed {
                status: format!("{description} during shutdown"),
                detail: tail(&self.stderr_path),
            });
        }
        if !output.lines().any(|line| line.trim_end() == "bye") {
            return Err(WorkerError::Protocol(format!(
                "worker exited with {description} without acknowledging shutdown; output {:?} ({discarded} further bytes discarded)",
                bounded_text(&captured, DIAGNOSTIC_BYTES)
            )));
        }
        Ok(description)
    }
}

impl Drop for WorkerProcess {
    fn drop(&mut self) {
        self.terminate("worker handle dropped");
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DudectPlan {
    pub backend: BackendSpec,
    pub cpu: Option<usize>,
    pub setup: Vec<Vec<u8>>,
    pub class_commands: [Vec<u8>; 2],
    pub expected: [Vec<u8>; 2],
    pub warmup: usize,
    pub batch: usize,
    pub budget: usize,
    pub time_limit_s: f64,
}

impl DudectPlan {
    pub fn render(&self) -> Result<String, WorkerError> {
        let (kind, argument) = self.backend.init_arguments()?;
        let mut out = format!("backend {kind} {argument}\n");
        out.push_str(&format!(
            "cpu {}\n",
            self.cpu.map(|c| c as i64).unwrap_or(-1)
        ));
        for command in &self.setup {
            out.push_str(&format!("setup {}\n", hex::encode(command)));
        }
        for class in 0..2 {
            out.push_str(&format!(
                "class{class} {}\n",
                hex::encode(&self.class_commands[class])
            ));
            out.push_str(&format!(
                "expect{class} {}\n",
                hex::encode(&self.expected[class])
            ));
        }
        out.push_str(&format!("warmup {}\n", self.warmup));
        out.push_str(&format!("batch {}\n", self.batch));
        out.push_str(&format!("budget {}\n", self.budget));
        out.push_str(&format!("time_limit_s {}\n", self.time_limit_s));
        Ok(out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DudectStatus {
    LeakageFound,
    BudgetExhausted,
    InsufficientMeasurements,
    TimeLimit,
    Interrupted,
    FunctionalFailure,
    SetupFailure,
    NvStoreDuringMeasurement,
    WorkerCrashed,
    WorkerTimeout,
    MalformedOutput,
}

impl DudectStatus {
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "leakage-found" => Self::LeakageFound,
            "budget-exhausted" => Self::BudgetExhausted,
            "insufficient-measurements" => Self::InsufficientMeasurements,
            "time-limit" => Self::TimeLimit,
            "interrupted" => Self::Interrupted,
            "functional-failure" => Self::FunctionalFailure,
            "setup-failure" => Self::SetupFailure,
            "nv-store-during-measurement" => Self::NvStoreDuringMeasurement,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DudectReportLine {
    pub measurements_millions: f64,
    pub max_t: Option<f64>,
    pub max_tau: Option<f64>,
    pub measurements_to_detect: Option<f64>,
    pub verdict: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DudectTest {
    pub index: usize,
    pub kind: String,
    pub n: [f64; 2],
    pub t: f64,
    pub eligible: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DudectOutcome {
    pub status: DudectStatus,
    pub detail: String,
    pub measurements: u64,
    pub batches: u64,
    pub nv_stores: u64,
    pub elapsed_s: f64,
    pub last_report: Option<DudectReportLine>,
    pub max_t_history: Vec<f64>,
    pub tests: Vec<DudectTest>,
    pub info: WorkerInfo,
    pub exit: String,
}

fn key_values(text: &str) -> BTreeMap<String, String> {
    text.split_whitespace()
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

pub fn parse_dudect_report(line: &str) -> Option<DudectReportLine> {
    let rest = line.strip_prefix("meas:")?;
    let (millions, rest) = rest.split_once(" M,")?;
    let measurements_millions = millions.trim().parse().ok()?;
    let rest = rest.trim();
    if let Some(after) = rest.strip_prefix("max t:") {
        let (t, after) = after.split_once(", max tau:")?;
        let (tau, after) = after.split_once(", (5/tau)^2:")?;
        let after = after.trim();
        let (needed, verdict) = after.split_once(char::is_whitespace).unwrap_or((after, ""));
        let needed = needed.trim_end_matches('.');
        Some(DudectReportLine {
            measurements_millions,
            max_t: t.trim().parse().ok(),
            max_tau: tau.trim().parse().ok(),
            measurements_to_detect: needed.trim().parse().ok(),
            verdict: verdict.trim().to_string(),
        })
    } else {
        Some(DudectReportLine {
            measurements_millions,
            max_t: None,
            max_tau: None,
            measurements_to_detect: None,
            verdict: rest.to_string(),
        })
    }
}

pub fn parse_dudect_output(stdout: &str, exit: &str) -> DudectOutcome {
    let mut outcome = DudectOutcome {
        status: DudectStatus::MalformedOutput,
        detail: String::new(),
        measurements: 0,
        batches: 0,
        nv_stores: 0,
        elapsed_s: 0.0,
        last_report: None,
        max_t_history: Vec::new(),
        tests: Vec::new(),
        info: WorkerInfo::new(),
        exit: exit.to_string(),
    };
    let mut result_seen = false;
    for line in stdout.lines() {
        if let Some(report) = parse_dudect_report(line) {
            if let Some(t) = report.max_t {
                outcome.max_t_history.push(t);
            }
            outcome.last_report = Some(report);
        } else if let Some(rest) = line.strip_prefix("tpms-timing info ") {
            let (key, value) = rest.split_once(' ').unwrap_or((rest, ""));
            outcome.info.insert(key.into(), value.into());
        } else if let Some(rest) = line.strip_prefix("tpms-timing test ") {
            let kv = key_values(rest);
            let get = |k: &str| {
                kv.get(k)
                    .and_then(|v| v.parse::<f64>().ok())
                    .unwrap_or(f64::NAN)
            };
            outcome.tests.push(DudectTest {
                index: get("index") as usize,
                kind: kv.get("kind").cloned().unwrap_or_default(),
                n: [get("n0"), get("n1")],
                t: get("t"),
                eligible: kv.get("eligible").map(|v| v == "yes").unwrap_or(false),
            });
        } else if let Some(rest) = line.strip_prefix("tpms-timing result ") {
            let kv = key_values(rest);
            let number = |k: &str| kv.get(k).and_then(|v| v.parse::<u64>().ok());
            match (
                kv.get("status").and_then(|s| DudectStatus::parse(s)),
                number("measurements"),
                number("batches"),
                number("nvstores"),
            ) {
                (Some(status), Some(measurements), Some(batches), Some(nv_stores)) => {
                    outcome.status = status;
                    outcome.measurements = measurements;
                    outcome.batches = batches;
                    outcome.nv_stores = nv_stores;
                    outcome.elapsed_s = kv
                        .get("elapsed_s")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0.0);
                    result_seen = true;
                }
                _ => {
                    outcome.status = DudectStatus::MalformedOutput;
                    outcome.detail = format!("unparseable result line: {line}");
                    return outcome;
                }
            }
        } else if let Some(rest) = line.strip_prefix("tpms-timing mismatch ") {
            outcome.detail = format!("mismatch {rest}");
        } else if let Some(rest) = line.strip_prefix("error ") {
            outcome.status = DudectStatus::WorkerCrashed;
            outcome.detail = format!("worker error: {rest}");
            return outcome;
        }
    }
    if !result_seen {
        outcome.status = if exit.starts_with("exit code 0") {
            DudectStatus::MalformedOutput
        } else {
            DudectStatus::WorkerCrashed
        };
        outcome.detail = format!("no result line; worker {exit}");
    } else if !exit.starts_with("exit code 0")
        && !matches!(
            outcome.status,
            DudectStatus::SetupFailure | DudectStatus::FunctionalFailure
        )
    {
        outcome.status = DudectStatus::WorkerCrashed;
        outcome.detail = format!("worker {exit} after its result line");
    }
    outcome
}

pub fn run_dudect(
    worker: &Path,
    plan: &DudectPlan,
    dir: &Path,
    wall_limit: Duration,
) -> Result<DudectOutcome, WorkerError> {
    crate::artifacts::create_new_dir(dir)?;
    let plan_path = dir.join("plan.txt");
    crate::artifacts::write_new(&plan_path, plan.render()?.as_bytes())?;
    let stdout_path = dir.join("dudect-stdout.log");
    let stderr_path = dir.join("dudect-stderr.log");
    let mut child = Command::new(worker)
        .arg("dudect")
        .arg(&plan_path)
        .stdin(Stdio::null())
        .stdout(Stdio::from(crate::artifacts::create_new_file(
            &stdout_path,
        )?))
        .stderr(Stdio::from(crate::artifacts::create_new_file(
            &stderr_path,
        )?))
        .spawn()
        .map_err(WorkerError::Spawn)?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if started.elapsed() > wall_limit {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let stdout = fs::read_to_string(&stdout_path)?;
    let mut outcome = match status {
        Some(status) => parse_dudect_output(&stdout, &describe_status(status)),
        None => {
            let mut outcome = parse_dudect_output(&stdout, "killed after wall-clock limit");
            outcome.status = DudectStatus::WorkerTimeout;
            outcome.detail = format!("worker exceeded the {:?} wall-clock limit", wall_limit);
            outcome
        }
    };
    if outcome.detail.is_empty() {
        outcome.detail = tail(&stderr_path);
    }
    crate::artifacts::write_new(
        &dir.join("outcome.json"),
        &serde_json::to_vec_pretty(&outcome).unwrap(),
    )?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_text_never_splits_characters_or_rejects_bytes() {
        assert_eq!(bounded_text(b"short", DIAGNOSTIC_BYTES), "short");
        assert_eq!(bounded_text(b"", DIAGNOSTIC_BYTES), "");
        let mut accent = vec![b'a'; 511];
        accent.extend_from_slice("é".as_bytes());
        let text = bounded_text(&accent, DIAGNOSTIC_BYTES);
        assert!(text.starts_with(&"a".repeat(511)));
        assert!(text.ends_with("\u{fffd}... [1 more bytes]"), "{text:?}");
        let mut invalid = vec![b'a'; 511];
        invalid.extend_from_slice(&[0xff, 0xfe, 0x80]);
        assert!(bounded_text(&invalid, DIAGNOSTIC_BYTES).ends_with("\u{fffd}... [2 more bytes]"));
        let mut wide = vec![b'a'; 510];
        wide.extend_from_slice("𝄞".as_bytes());
        assert!(bounded_text(&wide, DIAGNOSTIC_BYTES).ends_with("... [2 more bytes]"));
        let exact = "é".repeat(256);
        assert_eq!(bounded_text(exact.as_bytes(), DIAGNOSTIC_BYTES), exact);
    }

    #[test]
    fn unsupported_architectures_fail_explicitly() {
        assert!(check_timer_support("x86_64").is_ok());
        let error = check_timer_support("aarch64").unwrap_err();
        assert!(error.to_string().contains("unsupported timer"));
        assert!(error.to_string().contains("rdtsc"));
    }

    #[test]
    fn dudect_report_lines_parse() {
        let line = "meas:    0.02 M, max t:  +12.34, max tau: 8.70e-02, (5/tau)^2: 3.30e+03. Probably not constant time.";
        let report = parse_dudect_report(line).unwrap();
        assert_eq!(report.max_t, Some(12.34));
        assert_eq!(report.max_tau, Some(0.087));
        assert_eq!(report.measurements_to_detect, Some(3300.0));
        assert_eq!(report.verdict, "Probably not constant time.");
        let waiting =
            parse_dudect_report("meas:    0.00 M, not enough measurements (9990 still to go).")
                .unwrap();
        assert_eq!(waiting.max_t, None);
        assert!(waiting.verdict.starts_with("not enough"));
    }

    #[test]
    fn missing_result_line_is_not_a_success() {
        let partial = "tpms-timing info pid 1\nmeas:    0.02 M, max t:  +1.00, max tau: 1.00e-02, (5/tau)^2: 2.50e+05. For the moment, maybe constant time.\n";
        let crashed = parse_dudect_output(partial, "killed by signal 9");
        assert_eq!(crashed.status, DudectStatus::WorkerCrashed);
        let truncated = parse_dudect_output(partial, "exit code 0");
        assert_eq!(truncated.status, DudectStatus::MalformedOutput);
        let garbled = parse_dudect_output(
            "tpms-timing result status=leakage-found measurements=x\n",
            "exit code 0",
        );
        assert_eq!(garbled.status, DudectStatus::MalformedOutput);
        let unknown = parse_dudect_output(
            "tpms-timing result status=bogus measurements=1 batches=1 nvstores=0\n",
            "exit code 0",
        );
        assert_eq!(unknown.status, DudectStatus::MalformedOutput);
        let late_crash = parse_dudect_output(
            "tpms-timing result status=leakage-found measurements=2000 batches=2 nvstores=0 elapsed_s=1\n",
            "killed by signal 11",
        );
        assert_eq!(late_crash.status, DudectStatus::WorkerCrashed);
    }

    #[test]
    fn result_lines_parse() {
        let text = "tpms-timing info openssl_version OpenSSL 3.0.13 30 Jan 2024\ntpms-timing test index=0 kind=raw n0=12000 n1=11800 t=1.5 eligible=yes\ntpms-timing result status=budget-exhausted measurements=30000 batches=30 nvstores=0 mismatches=0 elapsed_s=12.5\n";
        let outcome = parse_dudect_output(text, "exit code 0");
        assert_eq!(outcome.status, DudectStatus::BudgetExhausted);
        assert_eq!(outcome.measurements, 30000);
        assert_eq!(outcome.tests.len(), 1);
        assert!(outcome.tests[0].eligible);
        assert_eq!(
            outcome.info["openssl_version"],
            "OpenSSL 3.0.13 30 Jan 2024"
        );
    }

    #[test]
    fn missing_library_is_reported_before_spawning() {
        let spec = BackendSpec::Library {
            name: BackendName::Rust,
            path: PathBuf::from("/nonexistent/libtpms.so"),
        };
        let error = WorkerProcess::spawn(
            Path::new("/bin/false"),
            &spec,
            None,
            Path::new("/dev/null"),
            Limits::default(),
        )
        .err()
        .unwrap();
        assert!(matches!(error, WorkerError::MissingLibrary(_)));
    }

    #[test]
    fn crashed_workers_are_reported_explicitly() {
        let dir = std::env::temp_dir().join(format!("tpms-timing-crash-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let script = dir.join("crash.sh");
        fs::write(&script, "#!/bin/sh\necho 'ready 1'\nkill -SEGV $$\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let spec = BackendSpec::Control {
            scenario: Scenario::ControlNegative,
        };
        let error = WorkerProcess::spawn(
            &script,
            &spec,
            None,
            &dir.join("stderr.log"),
            Limits::default(),
        )
        .err()
        .unwrap();
        match error {
            WorkerError::Crashed { status, .. } => assert!(status.contains("signal"), "{status}"),
            WorkerError::Io(_) => {}
            other => panic!("unexpected {other}"),
        }
        let plan = DudectPlan {
            backend: spec,
            cpu: None,
            setup: vec![],
            class_commands: [vec![1; 66], vec![2; 66]],
            expected: [vec![0; 16], vec![0; 16]],
            warmup: 1,
            batch: 100,
            budget: 1000,
            time_limit_s: 10.0,
        };
        let outcome =
            run_dudect(&script, &plan, &dir.join("run"), Duration::from_secs(10)).unwrap();
        assert_eq!(outcome.status, DudectStatus::WorkerCrashed);
        fs::remove_dir_all(&dir).unwrap();
    }
}
