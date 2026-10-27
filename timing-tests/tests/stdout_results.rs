mod common;

use std::fs;
use std::path::PathBuf;

use common::{Sandbox, json};
use tpms_timing_tests::{scenario::Scenario, verify::diagnostic_seeds};

fn probe_fixture(name: &str) -> Sandbox {
    let sandbox = Sandbox::new(name);
    // Only startup/probe is implemented. Known functional skips must never
    // send any other TPM command to this worker.
    fs::write(
        &sandbox.wrapper,
        r#"#!/bin/sh
echo 'ready 1'
while IFS= read -r line; do
    case "$line" in
        init\ *) echo "info session fixture-$$"; echo "info libcrypto_path $0"; echo ok ;;
        'exec 80010000000c000001440000') echo 'resp 00000000 80010000000a00000000' ;;
        quit) echo bye; exit 0 ;;
        *) echo 'err unexpected-command'; exit 2 ;;
    esac
done
"#,
    )
    .unwrap();
    sandbox
}

fn summary(stdout: &str, outcome: &str) -> serde_json::Value {
    let paths: Vec<_> = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("summary: "))
        .collect();
    assert_eq!(paths.len(), 1, "one final summary is required: {stdout}");
    let path = PathBuf::from(paths[0]);
    assert!(
        path.is_file(),
        "advertised summary must exist: {}",
        path.display()
    );
    let value = json(&path);
    assert_eq!(value["overall_outcome"], outcome);
    value
}

fn args<'a>(sandbox: &'a Sandbox, command: &'a str) -> Vec<&'a str> {
    vec![
        command,
        "--backend",
        "both",
        "--rust-lib",
        sandbox.wrapper.to_str().unwrap(),
        "--reference-lib",
        sandbox.wrapper.to_str().unwrap(),
        "--out-dir",
        sandbox.out.to_str().unwrap(),
    ]
}

#[test]
fn check_prints_an_existing_json_summary() {
    let sandbox = probe_fixture("check-stdout-summary");
    let mut args = args(&sandbox, "check");
    args.extend(["--scenario", "zgen-2phase-ecmqv-p256"]);
    let (code, stdout, stderr) = sandbox.run_with_stdout(&args);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    summary(&stdout, "completed");
    sandbox.assert_no_markdown(&sandbox.out);
}

#[test]
fn verify_stdout_preserves_each_backend_skip_reason_and_kind() {
    let sandbox = probe_fixture("verify-stdout-skips");
    let mut args = args(&sandbox, "verify");
    args.extend([
        "--scenario",
        "zgen-2phase-ecmqv-p256",
        "--seed-diagnostics",
        "1",
    ]);
    let (code, stdout, stderr) = sandbox.run_with_stdout(&args);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let report = summary(&stdout, "completed");
    let candidate = &report["verifications"][0]["results"]["results"][0];
    for (backend, issue) in candidate["skipped"].as_object().unwrap() {
        let line = stdout
            .lines()
            .find(|line| line.contains(backend) && line.contains("SKIP"))
            .unwrap_or_else(|| panic!("missing {backend} skip: {stdout}"));
        assert!(line.contains(issue["id"].as_str().unwrap()), "{line}");
        assert!(line.contains(issue["reason"].as_str().unwrap()), "{line}");
        assert!(line.contains("functional failure"), "{line}");
    }
    assert!(!stdout.contains("known timing issue"), "{stdout}");
}

#[test]
fn probe_failures_print_failed_results_for_every_run_command() {
    for command in ["search", "verify", "replay", "check"] {
        let sandbox = Sandbox::new(&format!("{command}-stdout-probe-failure"));
        fs::write(
            &sandbox.wrapper,
            "#!/bin/sh\necho 'ready 1'\nread line\necho 'err probe-fixture-failed'\nexit 2\n",
        )
        .unwrap();
        let scenario = Scenario::parse("auth-password").unwrap();
        let candidate = diagnostic_seeds(scenario, 1, 1).remove(0);
        let path = common::write_candidate(&sandbox.root, "candidate.json", &candidate);
        let mut args = args(&sandbox, command);
        if command == "replay" {
            args.extend(["--candidate", path.to_str().unwrap()]);
        } else {
            args.extend(["--scenario", "auth-password"]);
        }
        let (code, stdout, stderr) = sandbox.run_with_stdout(&args);
        assert_eq!(code, 4, "{command}: {stdout}\n{stderr}");
        assert!(
            stdout.contains("outcome Failed (exit 4)"),
            "{command}: {stdout}"
        );
        assert!(
            stdout.contains("probe-fixture-failed"),
            "{command}: {stdout}"
        );
        summary(&stdout, "failed");
    }
}
