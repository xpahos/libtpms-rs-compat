mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::*;

fn new_run(sandbox: &Sandbox, before: &[PathBuf]) -> PathBuf {
    let after: Vec<PathBuf> = sandbox
        .run_dirs()
        .into_iter()
        .filter(|d| !before.contains(d))
        .collect();
    assert_eq!(
        after.len(),
        1,
        "expected exactly one new run directory: {after:?}"
    );
    after[0].clone()
}

fn search(sandbox: &Sandbox) -> (i32, String, PathBuf) {
    let before = sandbox.run_dirs();
    let (code, stderr) = sandbox.run(&[
        "search",
        "--scenario",
        "control-positive",
        "--max-evaluations",
        "3",
        "--random-seed-pairs",
        "1",
        "--samples-per-class",
        "10",
        "--warmup",
        "0",
        "--out-dir",
        sandbox.out.to_str().unwrap(),
    ]);
    (code, stderr, new_run(sandbox, &before))
}

fn report(sandbox: &Sandbox, runs: &[&Path], name: &str) -> (serde_json::Value, String) {
    let out = sandbox.root.join(name);
    let mut args: Vec<String> = vec!["report".into()];
    args.extend(runs.iter().map(|r| r.display().to_string()));
    args.extend(["--output".into(), out.display().to_string()]);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (code, stderr) = sandbox.run(&refs);
    assert_eq!(code, 0, "report failed: {stderr}");
    (
        json(&out.join("report.json")),
        fs::read_to_string(out.join("report.md")).unwrap(),
    )
}

fn assert_run(run: &Path, state: &str, summary_outcome: &str) {
    assert_eq!(
        json(&run.join("run.json"))["state"],
        state,
        "{}",
        run.display()
    );
    let summary = json(&run.join("summary.json"));
    assert_eq!(
        summary["overall_outcome"],
        summary_outcome,
        "{}",
        run.display()
    );
}

#[test]
fn search_worker_exiting_nonzero_after_valid_work_fails_the_run() {
    let sandbox = Sandbox::new("search-exit9");
    sandbox.serve_mode("exit9-on-quit-after-measure");
    let (code, stderr, run) = search(&sandbox);
    assert_eq!(code, 4, "{stderr}");
    assert!(stderr.contains("exit code 9"), "{stderr}");
    assert_run(&run, "failed", "failed");
    let (report, markdown) = report(&sandbox, &[&run], "r");
    assert_eq!(report["overall_outcome"], "failed");
    assert!(markdown.contains("Overall outcome across all runs: **Failed**"));
}

#[test]
fn search_worker_killed_by_signal_during_shutdown_fails_the_run() {
    let sandbox = Sandbox::new("search-abort");
    sandbox.serve_mode("abort-on-quit-after-measure");
    let (code, stderr, run) = search(&sandbox);
    assert_eq!(code, 4, "{stderr}");
    assert!(stderr.contains("signal"), "{stderr}");
    assert_run(&run, "failed", "failed");
}

#[test]
fn search_with_normal_shutdown_completes() {
    let sandbox = Sandbox::new("search-normal");
    sandbox.serve_mode("normal");
    let (code, stderr, run) = search(&sandbox);
    assert_eq!(code, 0, "{stderr}");
    assert_run(&run, "completed", "completed");
}

#[test]
fn verify_worker_failing_at_shutdown_or_vanishing_fails_the_run() {
    for mode in [
        "exit9-on-quit-after-exec",
        "abort-on-quit-after-exec",
        "vanish-after-second-exec",
    ] {
        let sandbox = Sandbox::new(&format!("verify-{mode}"));
        sandbox.serve_mode(mode);
        sandbox.modes(&["signal", "signal"]);
        let file = write_candidate(
            &sandbox.root.join("c"),
            "c.json",
            &candidate("rust-e00001", pair(3), "campaign"),
        );
        let (code, stderr, run) = sandbox.verify(&[file], &[]);
        assert_eq!(code, 4, "{mode}: {stderr}");
        let results = json(&run.join("results.json"));
        assert_eq!(results["outcome"], "failed", "{mode}");
        assert_eq!(
            results["results"][0]["category"], "infrastructure-or-functional-failure",
            "{mode}"
        );
        assert_run(&run, "failed", "failed");
    }
}

#[test]
fn replay_worker_failing_at_shutdown_fails_the_run() {
    let sandbox = Sandbox::new("replay-exit9");
    sandbox.serve_mode("exit9-on-quit-after-exec");
    let file = write_candidate(
        &sandbox.root.join("c"),
        "c.json",
        &candidate("rust-e00001", pair(4), "campaign"),
    );
    let before = sandbox.run_dirs();
    let (code, stderr) = sandbox.run(&[
        "replay",
        "--candidate",
        file.to_str().unwrap(),
        "--batches",
        "1",
        "--samples-per-class",
        "10",
        "--out-dir",
        sandbox.out.to_str().unwrap(),
    ]);
    assert_eq!(code, 4, "{stderr}");
    let run = new_run(&sandbox, &before);
    assert_run(&run, "failed", "failed");
}

#[test]
fn verification_failing_at_probe_is_aggregated_in_any_order() {
    let sandbox = Sandbox::new("probe-failure");
    sandbox.serve_mode("normal");
    sandbox.modes(&["signal", "signal"]);
    let file = write_candidate(
        &sandbox.root.join("c"),
        "c.json",
        &candidate("rust-e00001", pair(6), "campaign"),
    );
    let (code, stderr, completed) = sandbox.verify(std::slice::from_ref(&file), &[]);
    assert_eq!(code, 0, "{stderr}");
    sandbox.serve_mode("exit9-on-quit");
    let (code, stderr, failed) = sandbox.verify(&[file], &[]);
    assert_eq!(code, 4, "{stderr}");
    assert!(
        !failed.join("results.json").exists(),
        "probe failure happens before results.json"
    );
    assert_run(&failed, "failed", "failed");
    let reason = json(&failed.join("run.json"))["detail"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(reason.contains("exit code 9"), "{reason}");

    let (alone, markdown) = report(&sandbox, &[&failed], "alone");
    assert_eq!(alone["overall_outcome"], "failed");
    assert_eq!(alone["overall_verification_outcome"], "failed");
    assert_eq!(
        alone["verifications_without_results"][0]["outcome"],
        "failed"
    );
    assert!(markdown.contains("Overall verification outcome: **Failed**"));
    assert!(markdown.contains("contributes **Failed**") && markdown.contains("exit code 9"));

    for (name, order) in [("cf", [&completed, &failed]), ("fc", [&failed, &completed])] {
        let (combined, markdown) = report(&sandbox, &[order[0], order[1]], name);
        assert_eq!(combined["overall_outcome"], "failed", "{name}");
        assert_eq!(combined["overall_verification_outcome"], "failed", "{name}");
        assert!(
            markdown.contains("Overall verification outcome: **Failed**"),
            "{name}"
        );
    }

    for (state, expected) in [("incomplete", "incomplete"), ("in-progress", "incomplete")] {
        let copy = sandbox.root.join(format!("copy-{state}"));
        fs::create_dir_all(&copy).unwrap();
        for entry in fs::read_dir(&failed).unwrap() {
            let entry = entry.unwrap();
            if entry.path().is_file() {
                fs::copy(entry.path(), copy.join(entry.file_name())).unwrap();
            }
        }
        let mut info = json(&copy.join("run.json"));
        info["state"] = state.into();
        info["run_id"] = format!("copy-{state}").into();
        fs::write(copy.join("run.json"), serde_json::to_vec(&info).unwrap()).unwrap();
        let (only, markdown) = report(&sandbox, &[&copy], &format!("r-{state}"));
        assert_eq!(only["overall_verification_outcome"], expected, "{state}");
        assert!(
            markdown.contains("Overall verification outcome: **Incomplete**"),
            "{state}"
        );
        let (with_completed, _) = report(&sandbox, &[&completed, &copy], &format!("rc-{state}"));
        assert_eq!(
            with_completed["overall_verification_outcome"], expected,
            "{state}"
        );
    }

    let corrupt = sandbox.root.join("copy-completed-without-results");
    fs::create_dir_all(&corrupt).unwrap();
    fs::copy(failed.join("run.json"), corrupt.join("run.json")).unwrap();
    fs::copy(failed.join("manifest.json"), corrupt.join("manifest.json")).unwrap();
    let mut info = json(&corrupt.join("run.json"));
    info["state"] = "completed".into();
    fs::write(corrupt.join("run.json"), serde_json::to_vec(&info).unwrap()).unwrap();
    let (code, stderr) = sandbox.run(&[
        "report",
        corrupt.to_str().unwrap(),
        "--output",
        sandbox.root.join("rx").to_str().unwrap(),
    ]);
    assert_eq!(
        code, 4,
        "a completed verify run without results.json is malformed: {stderr}"
    );
}

fn interrupted_checkpoint(name: &str, first: [&str; 2], expected: &str) {
    let sandbox = Sandbox::new(name);
    sandbox.serve_mode("normal");
    sandbox.modes(&[first[0], first[1], "block"]);
    let files = vec![
        write_candidate(
            &sandbox.root.join("a"),
            "c.json",
            &candidate("rust-e00001", pair(21), "campaign-a"),
        ),
        write_candidate(
            &sandbox.root.join("b"),
            "c.json",
            &candidate("rust-e00002", pair(22), "campaign-b"),
        ),
    ];
    let mut args: Vec<String> = vec![
        "--worker-executable".into(),
        sandbox.wrapper.display().to_string(),
        "verify".into(),
        "--out-dir".into(),
        sandbox.out.display().to_string(),
        "--budget".into(),
        "30000".into(),
        "--batch".into(),
        "1000".into(),
        "--repeats".into(),
        "2".into(),
    ];
    for file in &files {
        args.push("--candidate".into());
        args.push(file.display().to_string());
    }
    let mut child = Command::new(BIN)
        .args(&args)
        .env("TPMS_TIMING_FAKE_STATE", &sandbox.state)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let marker = sandbox.state.join("blocked.pid");
    let started = Instant::now();
    while !marker.exists() {
        assert!(
            started.elapsed() < Duration::from_secs(120),
            "second candidate never reached dudect"
        );
        assert!(
            child.try_wait().unwrap().is_none(),
            "verify exited before the second candidate blocked"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    child.kill().unwrap();
    child.wait().unwrap();
    let blocked: i32 = fs::read_to_string(&marker).unwrap().trim().parse().unwrap();
    // SAFETY: the pid was written by the fake dudect process that this test caused to block.
    unsafe {
        libc::kill(blocked, libc::SIGKILL);
    }
    let run = sandbox.run_dirs().pop().unwrap();
    assert_eq!(json(&run.join("run.json"))["state"], "in-progress");
    let results = json(&run.join("results.json"));
    assert_eq!(results["format"], "tpms-timing-verify-results/v2");
    assert_eq!(results["outcome"], expected);
    assert_eq!(results["all_candidates_processed"], false);
    assert_eq!(results["candidates_verified"], 1);
    let entries = results["results"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    let artifact = entries[0]["artifact"].as_str().unwrap();
    for record in entries[0]["runs"].as_array().unwrap() {
        let dir = PathBuf::from(record["directory"].as_str().unwrap());
        assert!(dir.starts_with(run.join("verify").join(artifact)));
        assert!(dir.join("dudect-stdout.log").is_file() && dir.join("outcome.json").is_file());
    }
    let (report, markdown) = report(&sandbox, &[&run], "report");
    assert_eq!(report["overall_verification_outcome"], expected);
    assert_eq!(report["verifications"][0]["outcome"], expected);
    assert_eq!(
        report["verifications"][0]["results"]["results"][0]["artifact"],
        artifact
    );
    let rendered = if expected == "failed" {
        "Failed"
    } else {
        "Incomplete"
    };
    assert!(
        markdown.contains(&format!("Overall verification outcome: **{rendered}**")),
        "{markdown}"
    );
}

#[test]
fn checkpoint_after_failed_candidate_reports_failed() {
    interrupted_checkpoint("checkpoint-failed", ["crash", "crash"], "failed");
}

#[test]
fn checkpoint_after_successful_candidate_reports_incomplete() {
    interrupted_checkpoint("checkpoint-success", ["signal", "signal"], "incomplete");
}

#[test]
fn continuous_valid_output_cannot_extend_the_operation_timeout() {
    let sandbox = Sandbox::new("flood-cli");
    let flood = sandbox.root.join("flood.sh");
    let pid_file = sandbox.root.join("flood.pid");
    fs::write(
        &flood,
        format!(
            "#!/bin/sh\n[ \"$1\" = warm ] && exit 0\necho $$ > '{}'\necho 'ready 1'\nread line\nexec yes 'info key value'\n",
            pid_file.display()
        ),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&flood, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let file = write_candidate(
        &sandbox.root.join("c"),
        "c.json",
        &candidate("rust-e00001", pair(31), "campaign"),
    );
    let warm = Command::new(&flood).arg("warm").status().unwrap();
    assert!(
        warm.success(),
        "warm-up execution of the flooding worker failed"
    );
    let started = Instant::now();
    let stderr_path = sandbox.root.join("flood-cli-stderr.log");
    let mut child = Command::new(BIN)
        .args([
            "--worker-executable",
            flood.to_str().unwrap(),
            "--operation-timeout-s",
            "3",
            "verify",
            "--candidate",
            file.to_str().unwrap(),
            "--out-dir",
            sandbox.out.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::from(fs::File::create(&stderr_path).unwrap()))
        .spawn()
        .unwrap();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() > Duration::from_secs(20) {
            child.kill().unwrap();
            child.wait().unwrap();
            if let Ok(text) = fs::read_to_string(&pid_file) {
                // SAFETY: the pid belongs to the flooding fake worker started by this test.
                unsafe {
                    libc::kill(text.trim().parse().unwrap(), libc::SIGKILL);
                }
            }
            panic!(
                "verify with a flooding worker was still running after 20 s; output extended the operation timeout"
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let elapsed = started.elapsed();
    let stderr = fs::read_to_string(&stderr_path).unwrap();
    assert_eq!(status.code(), Some(4), "{stderr}");
    assert!(
        elapsed < Duration::from_secs(10),
        "flooding worker kept the run alive for {elapsed:?}"
    );
    assert!(stderr.contains("timed out during init"), "{stderr}");
    let pid: i32 = fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    // SAFETY: signal 0 only checks whether the flooding worker still exists.
    let alive = unsafe { libc::kill(pid, 0) } == 0;
    assert!(!alive, "flooding worker {pid} is still alive");
    let run = sandbox.run_dirs().pop().unwrap();
    assert_eq!(json(&run.join("run.json"))["state"], "failed");
}

fn shutdown_output_case(name: &str, shutdown_output: &[u8]) -> (String, PathBuf, Sandbox) {
    let sandbox = Sandbox::new(name);
    let script = sandbox.root.join("worker.sh");
    let pid_file = sandbox.root.join("worker.pid");
    let octal: String = shutdown_output
        .iter()
        .map(|b| format!("\\{b:03o}"))
        .collect();
    fs::write(
        &script,
        format!(
            "#!/bin/sh\necho $$ > '{}'\necho 'ready 1'\nread line\necho ok\nread line\nprintf '{octal}'\nexit 0\n",
            pid_file.display()
        ),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let file = write_candidate(
        &sandbox.root.join("c"),
        "c.json",
        &candidate("rust-e00001", pair(41), "campaign"),
    );
    let output = Command::new(BIN)
        .args([
            "--worker-executable",
            script.to_str().unwrap(),
            "--operation-timeout-s",
            "20",
            "verify",
            "--candidate",
            file.to_str().unwrap(),
            "--out-dir",
            sandbox.out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(
        output.status.code(),
        Some(4),
        "{name}: expected exit 4, not a panic: {stderr}"
    );
    assert!(!stderr.contains("panicked"), "{name}: {stderr}");
    let pid: i32 = fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    // SAFETY: signal 0 only checks whether the controlled worker still exists.
    let alive = unsafe { libc::kill(pid, 0) } == 0;
    assert!(!alive, "{name}: worker {pid} was not reaped");
    let run = sandbox.run_dirs().pop().unwrap();
    let info = json(&run.join("run.json"));
    assert_eq!(info["state"], "failed", "{name}");
    let detail = info["detail"].as_str().unwrap().to_string();
    assert!(
        detail.contains("without acknowledging shutdown"),
        "{name}: {detail}"
    );
    assert_run(&run, "failed", "failed");
    let (report, markdown) = report(&sandbox, &[&run], "report");
    assert_eq!(report["overall_outcome"], "failed", "{name}");
    assert_eq!(report["overall_verification_outcome"], "failed", "{name}");
    assert!(
        markdown.contains("without acknowledging shutdown"),
        "{name}"
    );
    (detail, run, sandbox)
}

#[test]
fn shutdown_output_splitting_a_character_at_the_diagnostic_limit_fails_cleanly() {
    let mut bytes = vec![b'a'; 511];
    bytes.extend_from_slice("é".as_bytes());
    let (detail, _, _) = shutdown_output_case("utf8-boundary", &bytes);
    assert!(detail.contains(&"a".repeat(511)), "{detail}");
    assert!(detail.contains("[1 more bytes]"), "{detail}");
}

#[test]
fn invalid_utf8_shutdown_output_across_the_limit_fails_cleanly() {
    let mut bytes = vec![b'a'; 511];
    bytes.extend_from_slice(&[0xff, 0xfe, 0xc3]);
    let (detail, _, _) = shutdown_output_case("invalid-utf8", &bytes);
    assert!(detail.contains("[2 more bytes]"), "{detail}");
}

#[test]
fn short_shutdown_output_without_bye_fails_cleanly() {
    let (detail, _, _) = shutdown_output_case("short-output", "byebye é\n".as_bytes());
    assert!(detail.contains("byebye é"), "{detail}");
    assert!(!detail.contains("more bytes"), "{detail}");
}
