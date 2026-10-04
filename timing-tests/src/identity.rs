use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 16];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

pub fn command_output(program: &str, args: &[&str], cwd: Option<&Path>) -> Option<String> {
    let mut command = Command::new(program);
    command.args(args);
    if let Some(dir) = cwd {
        command.current_dir(dir);
    }
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn git(repo: &Path, args: &[&str]) -> Option<String> {
    let mut full = vec!["-c", "safe.directory=*", "-C"];
    let repo_text = repo.to_str()?;
    full.push(repo_text);
    full.extend_from_slice(args);
    command_output("git", &full, None)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceIdentity {
    pub root: PathBuf,
    pub paths: Vec<String>,
    pub revision: Option<String>,
    pub dirty_files: Vec<String>,
    pub content_sha256: String,
    pub file_count: usize,
}

pub fn source_identity(root: &Path, paths: &[&str]) -> SourceIdentity {
    let mut args = vec!["ls-files", "-co", "--exclude-standard", "--"];
    args.extend_from_slice(paths);
    let listed = git(root, &args).unwrap_or_default();
    let mut files: Vec<String> = listed.lines().map(str::to_string).collect();
    files.sort();
    files.dedup();
    let mut hasher = Sha256::new();
    let mut count = 0;
    for file in &files {
        let path = root.join(file);
        if let Ok(digest) = sha256_file(&path) {
            hasher.update(file.as_bytes());
            hasher.update([0]);
            hasher.update(digest.as_bytes());
            hasher.update([b'\n']);
            count += 1;
        }
    }
    let mut status_args = vec!["status", "--porcelain", "--"];
    status_args.extend_from_slice(paths);
    SourceIdentity {
        root: root.to_path_buf(),
        paths: paths.iter().map(|p| p.to_string()).collect(),
        revision: git(root, &["rev-parse", "HEAD"]),
        dirty_files: git(root, &status_args)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect(),
        content_sha256: hex::encode(hasher.finalize()),
        file_count: count,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibraryIdentity {
    pub path: PathBuf,
    pub canonical_path: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub build_info: Option<serde_json::Value>,
}

pub fn library_identity(path: &Path) -> std::io::Result<LibraryIdentity> {
    let canonical = fs::canonicalize(path)?;
    let sidecar = PathBuf::from(format!("{}.build-info.json", path.display()));
    let build_info = fs::read(&sidecar)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok());
    Ok(LibraryIdentity {
        path: path.to_path_buf(),
        size: fs::metadata(&canonical)?.len(),
        sha256: sha256_file(&canonical)?,
        canonical_path: canonical,
        build_info,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostIdentity {
    pub arch: String,
    pub os: String,
    pub kernel: Option<String>,
    pub os_release: Option<String>,
    pub cpu_model: Option<String>,
    pub logical_cpus: Option<usize>,
    pub virtualization_indicators: Vec<String>,
    pub exploratory: bool,
}

pub fn host_identity() -> HostIdentity {
    let cpuinfo = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let cpu_model = cpuinfo
        .lines()
        .find(|l| l.starts_with("model name"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim().to_string())
        .or_else(|| command_output("sysctl", &["-n", "machdep.cpu.brand_string"], None));
    let mut indicators = Vec::new();
    if cpuinfo
        .lines()
        .any(|l| l.starts_with("flags") && l.split_whitespace().any(|f| f == "hypervisor"))
    {
        indicators.push("cpuinfo hypervisor flag".to_string());
    }
    if let Some(model) = &cpu_model
        && model.contains("VirtualApple")
    {
        indicators.push(format!(
            "cpu model {model:?} (Rosetta binary translation on Apple silicon)"
        ));
    }
    if Path::new("/.dockerenv").exists() {
        indicators.push("/.dockerenv present (container)".to_string());
    }
    if let Ok(version) = fs::read_to_string("/proc/version")
        && version.to_lowercase().contains("orbstack")
    {
        indicators.push("kernel built by OrbStack (Linux VM on macOS)".to_string());
    }
    let os_release = fs::read_to_string("/etc/os-release").ok().and_then(|text| {
        text.lines()
            .find(|l| l.starts_with("PRETTY_NAME="))
            .map(|l| {
                l.trim_start_matches("PRETTY_NAME=")
                    .trim_matches('"')
                    .to_string()
            })
    });
    HostIdentity {
        arch: std::env::consts::ARCH.into(),
        os: std::env::consts::OS.into(),
        kernel: command_output("uname", &["-srvm"], None),
        os_release,
        cpu_model,
        logical_cpus: std::thread::available_parallelism().ok().map(|n| n.get()),
        exploratory: !indicators.is_empty(),
        virtualization_indicators: indicators,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolIdentity {
    pub name: String,
    pub version: String,
    pub rustc: String,
    pub profile: String,
    pub opt_level: String,
    pub libafl: String,
    pub p521: String,
    pub executable: Option<PathBuf>,
    pub executable_sha256: Option<String>,
}

pub fn tool_identity() -> ToolIdentity {
    let executable = std::env::current_exe().ok();
    ToolIdentity {
        name: env!("CARGO_PKG_NAME").into(),
        version: env!("CARGO_PKG_VERSION").into(),
        rustc: env!("TPMS_TIMING_RUSTC").into(),
        profile: env!("TPMS_TIMING_PROFILE").into(),
        opt_level: env!("TPMS_TIMING_OPT_LEVEL").into(),
        libafl: env!("TPMS_TIMING_LIBAFL").into(),
        p521: env!("TPMS_TIMING_P521").into(),
        executable_sha256: executable.as_deref().and_then(|p| sha256_file(p).ok()),
        executable,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpensslObservation {
    pub backend: String,
    pub libcrypto_path: String,
    pub libcrypto_sha256: Option<String>,
    pub openssl_version: String,
}

pub fn observe_openssl(backend: &str, info: &crate::worker::WorkerInfo) -> OpensslObservation {
    let path = info
        .get("libcrypto_path")
        .cloned()
        .unwrap_or_else(|| "-".into());
    let sha = if path == "-" {
        None
    } else {
        sha256_file(Path::new(&path)).ok()
    };
    OpensslObservation {
        backend: backend.into(),
        libcrypto_sha256: sha,
        libcrypto_path: path,
        openssl_version: info
            .get("openssl_version")
            .cloned()
            .unwrap_or_else(|| "-".into()),
    }
}

pub fn check_openssl_consistency(observations: &[OpensslObservation]) -> Result<(), String> {
    for observation in observations {
        if observation.libcrypto_path == "-" || observation.libcrypto_sha256.is_none() {
            return Err(format!(
                "backend {} has no identifiable libcrypto loaded (path {:?})",
                observation.backend, observation.libcrypto_path
            ));
        }
    }
    if let Some(first) = observations.first() {
        for other in &observations[1..] {
            if other.libcrypto_sha256 != first.libcrypto_sha256
                || other.openssl_version != first.openssl_version
            {
                return Err(format!(
                    "OpenSSL mismatch: {} loads {} ({}, sha256 {:?}) but {} loads {} ({}, sha256 {:?})",
                    first.backend,
                    first.libcrypto_path,
                    first.openssl_version,
                    first.libcrypto_sha256,
                    other.backend,
                    other.libcrypto_path,
                    other.openssl_version,
                    other.libcrypto_sha256
                ));
            }
        }
    }
    Ok(())
}

pub const MEASUREMENT_BOUNDARIES: &[&str] = &[
    "search (serve mode): each sample is cpucycles() (dudect's mfence+rdtsc) immediately before and after one TPMLIB_Process call on a pre-copied command buffer; command copying, class ordering, response comparison and IPC are outside the bracket",
    "verification (dudect mode): dudect's own measure() loop timestamps consecutive do_one_computation() calls, so each sample covers one TPMLIB_Process call plus the loop step and a fixed-size copy of the response into a per-measurement slot; class assignment (dudect randombit) and command placement happen in prepare_inputs() before the timed loop",
    "outside every timed region: key derivation, candidate parsing and validation, TPM2_Startup, TPM2_LoadExternal of both objects, FlushContext, warm-up executions, response verification, NV-store accounting, logging and IPC",
    "both class objects stay loaded in the same TPM instance for the whole measurement; the classes differ only in the 4-byte object handle inside the otherwise identical ECDH_ZGen command",
    "outputs are verified against an independent p521-crate computation after every search batch and every dudect batch; a mismatch or non-success response aborts the measurement as a functional failure",
];

pub const EXCLUDED_PATHS: &[&str] = &[
    "first use of a freshly loaded key: each search evaluation and each dudect run executes warm-up commands before timing",
    "key generation (TPM2_Create/CreatePrimary) and key loading (LoadExternal/Load) are not measured",
    "ECDH_KeyGen, ZGen_2Phase and other ECC commands are not measured",
    "public-point validation of peers other than the single fixed peer point",
];
