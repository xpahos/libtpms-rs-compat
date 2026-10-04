#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use tpms_timing_tests::scalar::{Scalar521, ScalarPair};
use tpms_timing_tests::scenario::{Scenario, SplitMix};
use tpms_timing_tests::search::{CandidateFile, CandidateKind, seeded_candidate};

pub const BIN: &str = env!("CARGO_BIN_EXE_tpms-timing-tests");

pub struct Sandbox {
    pub root: PathBuf,
    pub wrapper: PathBuf,
    pub state: PathBuf,
    pub out: PathBuf,
}

impl Sandbox {
    pub fn new(name: &str) -> Self {
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let wrapper = root.join("fake-worker.sh");
        fs::write(
            &wrapper,
            format!("#!/bin/sh\nexec '{BIN}' __fake-worker \"$@\"\n"),
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let state = root.join("state");
        fs::create_dir_all(&state).unwrap();
        let out = root.join("runs");
        Self {
            root,
            wrapper,
            state,
            out,
        }
    }

    pub fn modes(&self, modes: &[&str]) {
        fs::write(self.state.join("dudect-modes"), modes.join("\n")).unwrap();
        let _ = fs::remove_file(self.state.join("dudect-count"));
    }

    pub fn serve_mode(&self, mode: &str) {
        fs::write(self.state.join("serve-mode"), mode).unwrap();
    }

    pub fn run(&self, args: &[&str]) -> (i32, String) {
        let output = Command::new(BIN)
            .arg("--worker-executable")
            .arg(&self.wrapper)
            .args(args)
            .env("TPMS_TIMING_FAKE_STATE", &self.state)
            .output()
            .unwrap();
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    pub fn verify(&self, candidates: &[PathBuf], extra: &[&str]) -> (i32, String, PathBuf) {
        let before = self.run_dirs();
        let mut args: Vec<String> = vec![
            "verify".into(),
            "--out-dir".into(),
            self.out.display().to_string(),
        ];
        for candidate in candidates {
            args.push("--candidate".into());
            args.push(candidate.display().to_string());
        }
        let defaults = [
            "--budget",
            "30000",
            "--batch",
            "1000",
            "--repeats",
            "2",
            "--time-limit-s",
            "60",
        ];
        let mut merged: Vec<String> = Vec::new();
        let mut i = 0;
        while i < defaults.len() {
            if !extra.contains(&defaults[i]) {
                merged.push(defaults[i].into());
                merged.push(defaults[i + 1].into());
            }
            i += 2;
        }
        merged.extend(extra.iter().map(|s| s.to_string()));
        args.extend(merged);
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let (code, stderr) = self.run(&refs);
        let after: Vec<PathBuf> = self
            .run_dirs()
            .into_iter()
            .filter(|d| !before.contains(d))
            .collect();
        assert_eq!(after.len(), 1, "expected one new run directory: {stderr}");
        (code, stderr, after[0].clone())
    }

    pub fn run_dirs(&self) -> Vec<PathBuf> {
        let mut dirs: Vec<PathBuf> = fs::read_dir(&self.out)
            .map(|e| e.filter_map(|e| e.ok().map(|e| e.path())).collect())
            .unwrap_or_default();
        dirs.sort();
        dirs
    }
}

pub fn json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display())))
        .unwrap()
}

pub fn pair(seed: u64) -> ScalarPair {
    let mut rng = SplitMix::new(seed);
    ScalarPair {
        a: rng.scalar(),
        b: rng.scalar(),
    }
}

pub fn small_pair(a: u128, b: u128) -> ScalarPair {
    ScalarPair {
        a: Scalar521::from_u128(a).unwrap(),
        b: Scalar521::from_u128(b).unwrap(),
    }
}

pub fn candidate(id: &str, pair: ScalarPair, campaign: &str) -> CandidateFile {
    let mut c = seeded_candidate(Scenario::ControlPositive, "fixture", pair, 7);
    c.id = id.into();
    c.kind = CandidateKind::AdaptiveDiscovery;
    c.search_backend = Some("rust".into());
    c.search_run = Some(PathBuf::from(campaign));
    c
}

pub fn write_candidate(dir: &Path, file: &str, candidate: &CandidateFile) -> PathBuf {
    fs::create_dir_all(dir).unwrap();
    let path = dir.join(file);
    candidate.save(&path).unwrap();
    path
}
