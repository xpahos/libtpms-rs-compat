use std::path::Path;
use std::process::Command;

fn locked_version(lock: &str, name: &str) -> String {
    let marker = format!("name = \"{name}\"\nversion = \"");
    lock.find(&marker)
        .and_then(|start| {
            let rest = &lock[start + marker.len()..];
            rest.find('"').map(|end| rest[..end].to_string())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn main() {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let version = Command::new(rustc)
        .arg("-vV")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|text| text.lines().collect::<Vec<_>>().join("; "))
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=TPMS_TIMING_RUSTC={version}");
    let lock_path = Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("Cargo.lock");
    let lock = std::fs::read_to_string(&lock_path).unwrap_or_default();
    println!(
        "cargo:rustc-env=TPMS_TIMING_LIBAFL={}",
        locked_version(&lock, "libafl")
    );
    println!(
        "cargo:rustc-env=TPMS_TIMING_P521={}",
        locked_version(&lock, "p521")
    );
    println!(
        "cargo:rustc-env=TPMS_TIMING_PROFILE={}",
        std::env::var("PROFILE").unwrap_or_default()
    );
    println!(
        "cargo:rustc-env=TPMS_TIMING_OPT_LEVEL={}",
        std::env::var("OPT_LEVEL").unwrap_or_default()
    );
    println!("cargo:rerun-if-changed=Cargo.lock");
    println!("cargo:rerun-if-changed=build.rs");
}
