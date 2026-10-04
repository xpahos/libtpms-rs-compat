mod common;

use std::fs;

use common::*;

struct Case {
    name: &'static str,
    candidates: usize,
    serve: &'static str,
    modes: &'static [&'static str],
    args: &'static [&'static str],
    exit: i32,
    outcome: &'static str,
    state: &'static str,
}

fn check(case: &Case) {
    let sandbox = Sandbox::new(case.name);
    sandbox.serve_mode(case.serve);
    sandbox.modes(case.modes);
    let files: Vec<_> = (0..case.candidates)
        .map(|i| {
            write_candidate(
                &sandbox.root.join(format!("campaign-{i}")),
                "c.json",
                &candidate(&format!("rust-e{i:05}"), pair(100 + i as u64), "campaign"),
            )
        })
        .collect();
    let (code, stderr, run) = sandbox.verify(&files, case.args);
    assert_eq!(
        code, case.exit,
        "{}: exit code; stderr:\n{stderr}",
        case.name
    );
    let results = json(&run.join("results.json"));
    assert_eq!(
        results["format"], "tpms-timing-verify-results/v2",
        "{}",
        case.name
    );
    assert_eq!(
        results["outcome"], case.outcome,
        "{}: results outcome",
        case.name
    );
    let info = json(&run.join("run.json"));
    assert_eq!(info["state"], case.state, "{}: run state", case.name);
    let summary = fs::read_to_string(run.join("summary.md")).unwrap();
    let rendered = match case.outcome {
        "completed" => "Completed",
        "incomplete" => "Incomplete",
        _ => "Failed",
    };
    assert!(
        summary.contains(&format!("outcome {rendered}, exit {}", case.exit)),
        "{}: summary does not state the outcome:\n{summary}",
        case.name
    );
    if case.outcome != "completed" {
        assert_ne!(results["all_candidates_processed"].as_bool(), None);
        assert!(
            !summary.contains("Overall verification outcome: **Completed**"),
            "{}",
            case.name
        );
    }
    let report_dir = sandbox.root.join("report");
    let (report_code, report_stderr) = sandbox.run(&[
        "report",
        run.to_str().unwrap(),
        "--output",
        report_dir.to_str().unwrap(),
    ]);
    assert_eq!(
        report_code, 0,
        "{}: report failed: {report_stderr}",
        case.name
    );
    let report = json(&report_dir.join("report.json"));
    assert_eq!(
        report["overall_outcome"], case.outcome,
        "{}: regenerated report outcome",
        case.name
    );
    assert_eq!(
        report["verifications"][0]["outcome"], case.outcome,
        "{}",
        case.name
    );
}

macro_rules! case {
    ($test:ident, $($field:ident: $value:expr),* $(,)?) => {
        #[test]
        fn $test() {
            check(&Case { name: stringify!($test), $($field: $value),* });
        }
    };
}

case!(insufficient_measurements_small_budget, candidates: 1, serve: "normal", modes: &["auto", "auto"],
    args: &["--budget", "32", "--batch", "32", "--repeats", "2"], exit: 3, outcome: "incomplete", state: "incomplete");
case!(missing_required_repeat, candidates: 1, serve: "normal", modes: &["signal"],
    args: &["--repeats", "1"], exit: 3, outcome: "incomplete", state: "incomplete");
case!(mixed_repeat_outcomes, candidates: 1, serve: "normal", modes: &["signal", "nosignal"],
    args: &[], exit: 3, outcome: "incomplete", state: "incomplete");
case!(time_limit, candidates: 1, serve: "normal", modes: &["timelimit", "timelimit"],
    args: &[], exit: 3, outcome: "incomplete", state: "incomplete");
case!(interrupted_worker, candidates: 2, serve: "normal", modes: &["interrupted"],
    args: &[], exit: 3, outcome: "incomplete", state: "incomplete");
case!(worker_crash, candidates: 1, serve: "normal", modes: &["crash", "crash"],
    args: &[], exit: 4, outcome: "failed", state: "failed");
case!(malformed_output, candidates: 1, serve: "normal", modes: &["malformed", "malformed"],
    args: &[], exit: 4, outcome: "failed", state: "failed");
case!(functional_mismatch_in_check, candidates: 1, serve: "wrong-output", modes: &[],
    args: &[], exit: 4, outcome: "failed", state: "failed");
case!(functional_mismatch_in_dudect, candidates: 1, serve: "normal", modes: &["mismatch", "mismatch"],
    args: &[], exit: 4, outcome: "failed", state: "failed");
case!(success_then_incomplete, candidates: 2, serve: "normal", modes: &["signal", "signal", "insufficient", "insufficient"],
    args: &[], exit: 3, outcome: "incomplete", state: "incomplete");
case!(success_then_failure, candidates: 2, serve: "normal", modes: &["signal", "signal", "crash", "crash"],
    args: &[], exit: 4, outcome: "failed", state: "failed");
case!(failure_takes_precedence_over_incomplete, candidates: 2, serve: "normal", modes: &["insufficient", "insufficient", "malformed", "malformed"],
    args: &[], exit: 4, outcome: "failed", state: "failed");
case!(completed_reproducible_signal, candidates: 1, serve: "normal", modes: &["signal", "signal"],
    args: &[], exit: 0, outcome: "completed", state: "completed");
case!(completed_no_signal_sufficient_budget, candidates: 1, serve: "normal", modes: &["auto", "nosignal"],
    args: &["--budget", "30000", "--batch", "1000"], exit: 0, outcome: "completed", state: "completed");

#[test]
fn inconsistent_v2_artifacts_are_rejected_and_legacy_v1_is_not_promoted() {
    let sandbox = Sandbox::new("inconsistent");
    sandbox.serve_mode("normal");
    sandbox.modes(&["insufficient", "insufficient"]);
    let file = write_candidate(
        &sandbox.root.join("c"),
        "c.json",
        &candidate("rust-e00001", pair(5), "campaign"),
    );
    let (code, _, run) = sandbox.verify(&[file], &[]);
    assert_eq!(code, 3);

    let mut results = json(&run.join("results.json"));
    results["outcome"] = "completed".into();
    fs::write(
        run.join("results.json"),
        serde_json::to_vec(&results).unwrap(),
    )
    .unwrap();
    let mut info = json(&run.join("run.json"));
    info["state"] = "completed".into();
    fs::write(run.join("run.json"), serde_json::to_vec(&info).unwrap()).unwrap();
    let (code, stderr) = sandbox.run(&[
        "report",
        run.to_str().unwrap(),
        "--output",
        sandbox.root.join("r1").to_str().unwrap(),
    ]);
    assert_eq!(code, 4, "tampered v2 artifact must be rejected: {stderr}");
    assert!(stderr.contains("imply at least"), "{stderr}");

    results["format"] = "tpms-timing-verify-results/v1".into();
    results["completed"] = true.into();
    let object = results.as_object_mut().unwrap();
    for key in [
        "outcome",
        "outcome_detail",
        "outcome_contract",
        "all_candidates_processed",
        "candidates_requested",
    ] {
        object.remove(key);
    }
    for candidate in results["results"].as_array_mut().unwrap() {
        let object = candidate.as_object_mut().unwrap();
        for key in [
            "artifact",
            "content_sha256",
            "candidate_file",
            "provenance",
            "outcome",
        ] {
            object.remove(key);
        }
    }
    fs::write(
        run.join("results.json"),
        serde_json::to_vec(&results).unwrap(),
    )
    .unwrap();
    let out = sandbox.root.join("r2");
    let (code, stderr) = sandbox.run(&[
        "report",
        run.to_str().unwrap(),
        "--output",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{stderr}");
    let report = json(&out.join("report.json"));
    assert_eq!(report["overall_outcome"], "incomplete");
    assert!(
        report["verifications"][0]["legacy_inconsistency"]
            .as_str()
            .unwrap()
            .contains("not as successful verification")
    );
    let markdown = fs::read_to_string(out.join("report.md")).unwrap();
    assert!(markdown.contains("Inconsistent legacy artifact"));
}
