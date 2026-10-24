mod common;

use std::fs;
use std::path::Path;
use tpms_timing_tests::measure::{
    FixtureMeasurer, LoadOrder, LoadedPair, MeasureFailure, Measurer, RawBatch, no_effect,
};
use tpms_timing_tests::scalar::{Scalar521, ScalarPair, order_minus};
use tpms_timing_tests::scenario::{PreparedPair, Scenario};
use tpms_timing_tests::search::{HistoryEntry, run_campaign};
use tpms_timing_tests::selftest::fixture_config;
use tpms_timing_tests::worker::WorkerInfo;

struct ReferenceFixture(FixtureMeasurer, bool);
impl Measurer for ReferenceFixture {
    fn label(&self) -> String {
        "reference".into()
    }
    fn info(&self) -> WorkerInfo {
        [(
            "openssl_version".into(),
            "OpenSSL 3.0.13 30 Jan 2024".into(),
        )]
        .into()
    }
    fn load(&mut self, p: &PreparedPair, o: LoadOrder) -> Result<LoadedPair, MeasureFailure> {
        self.0.load(p, o)
    }
    fn measure(
        &mut self,
        p: &LoadedPair,
        n: usize,
        w: usize,
        s: u64,
    ) -> Result<RawBatch, MeasureFailure> {
        self.0.measure(p, n, w, s)
    }
    fn execute_once(&mut self, p: &LoadedPair) -> Result<[Vec<u8>; 2], MeasureFailure> {
        let mut responses = self.0.execute_once(p)?;
        if self.1 {
            responses[0][0] ^= 1;
        }
        Ok(responses)
    }
}
fn endpoints() -> ScalarPair {
    ScalarPair {
        a: Scalar521::from_u128(1).unwrap(),
        b: Scalar521::new(order_minus(1)).unwrap(),
    }
}
fn history(dir: &Path) -> Vec<HistoryEntry> {
    fs::read_to_string(dir.join("history.jsonl"))
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect()
}

#[test]
fn fuzzing_skips_only_known_endpoints_and_can_reenable_them() {
    let sandbox = common::Sandbox::new("known-search");
    for include in [false, true] {
        let mut config = fixture_config(7, true);
        config.scenario = Scenario::EcdhP521;
        config.max_evaluations = 26;
        config.random_seed_pairs = 0;
        config.disable_known_case_skips = include;
        let mut run = tpms_timing_tests::run::Run::create(
            &sandbox.root.join(format!("search-{include}")),
            "search",
            None,
        )
        .unwrap();
        run.write_json("manifest.json", &serde_json::json!({}))
            .unwrap();
        let dir = run.dir.join("search/reference");
        let result = run_campaign(
            ReferenceFixture(FixtureMeasurer::new("reference", no_effect), false),
            &config,
            &dir,
            &dir.join("corpus"),
            None,
        )
        .unwrap();
        let rows = history(&dir);
        let endpoint = rows
            .iter()
            .find(|r| {
                r.observation.input_hex
                    == hex::encode(
                        ScalarPair {
                            a: endpoints().b,
                            b: endpoints().a,
                        }
                        .to_bytes(),
                    )
            })
            .unwrap();
        assert_eq!(endpoint.observation.skipped.is_some(), !include);
        assert_eq!(endpoint.observation.batches.is_empty(), !include);
        assert!(!endpoint.decision.candidate);
        assert!(!endpoint.decision.seed_met_criteria);
        assert_eq!(result.summary.known_skips.len(), usize::from(!include));
        run.finish(tpms_timing_tests::run::RunState::Completed, None)
            .unwrap();
        let report = tpms_timing_tests::report::build_report(&[run.dir]).unwrap();
        let markdown = tpms_timing_tests::report::render_markdown(&report);
        assert_eq!(markdown.contains("**SKIP**"), !include);
        if !include {
            assert!(markdown.contains("s->Z == 0"));
        }
        assert!(
            rows.iter()
                .filter(|r| r.observation.skipped.is_none())
                .any(|r| !r.observation.batches.is_empty())
        );
    }
}

#[test]
fn fuzzing_skip_does_not_hide_a_functional_mismatch() {
    let sandbox = common::Sandbox::new("known-search-functional");
    let mut config = fixture_config(7, true);
    config.scenario = Scenario::EcdhP521;
    config.max_evaluations = 26;
    config.random_seed_pairs = 0;
    let result = run_campaign(
        ReferenceFixture(FixtureMeasurer::new("reference", no_effect), true),
        &config,
        &sandbox.root.join("search"),
        &sandbox.root.join("corpus"),
        None,
    )
    .unwrap();
    assert_eq!(result.summary.functional_failures, 1);
    assert!(result.summary.known_skips.is_empty());
    let rows = history(&sandbox.root.join("search"));
    let failed = rows
        .iter()
        .find(|r| r.observation.failure.is_some())
        .unwrap();
    assert!(matches!(
        failed.observation.failure,
        Some(MeasureFailure::Functional { class: Some(0), .. })
    ));
    assert!(!failed.decision.candidate);
    assert!(!failed.decision.seed_met_criteria);
}

#[test]
fn skipped_reference_preserves_incomplete_and_no_signal_rust_verdicts() {
    use tpms_timing_tests::verify::{
        BackendVerdict, Category, VerificationOutcome, candidate_outcome, categorize,
    };
    for (rust, category, outcome) in [
        (
            BackendVerdict::Inconclusive,
            Category::InconclusiveOrIncomplete,
            VerificationOutcome::Incomplete,
        ),
        (
            BackendVerdict::NoSignalWithinBudget,
            Category::SingleBackendNoSignalWithinBudget,
            VerificationOutcome::Completed,
        ),
    ] {
        let verdicts = [
            ("reference".into(), BackendVerdict::SkippedKnownIssue),
            ("rust".into(), rust),
        ]
        .into();
        assert_eq!(categorize(&verdicts, true), category);
        assert_eq!(candidate_outcome(categorize(&verdicts, true)), outcome);
        assert_eq!(
            categorize(&verdicts, false),
            Category::InfrastructureOrFunctionalFailure
        );
    }
}

#[test]
fn skip_is_scoped_to_curve_pair_backend_and_observed_openssl() {
    use tpms_timing_tests::known_issues::timing_skip;
    let info: WorkerInfo = [(
        "openssl_version".into(),
        "OpenSSL 3.0.13 30 Jan 2024".into(),
    )]
    .into();
    let pair = endpoints();
    for pair in [
        pair,
        ScalarPair {
            a: pair.b,
            b: pair.a,
        },
    ] {
        assert!(timing_skip(Scenario::EcdhP521, pair, "reference", &info).is_some());
        assert!(timing_skip(Scenario::EcdhP521, pair, "rust", &info).is_none());
        assert!(timing_skip(Scenario::ControlPositive, pair, "reference", &info).is_none());
        assert!(timing_skip(Scenario::EcdhP521, pair, "reference", &WorkerInfo::new()).is_none());
        for version in ["BoringSSL", "OpenSSL 3.0.14 4 Jun 2024"] {
            let other = [("openssl_version".into(), version.into())].into();
            assert!(timing_skip(Scenario::EcdhP521, pair, "reference", &other).is_none());
        }
    }
    let neighbor = ScalarPair {
        a: Scalar521::from_u128(2).unwrap(),
        b: pair.b,
    };
    assert!(timing_skip(Scenario::EcdhP521, neighbor, "reference", &info).is_none());
}

// Protocol fixture: fixed functional TPM responses; timed runs are synthetic signals.
fn install_endpoint_worker(sandbox: &common::Sandbox, wrong: bool) {
    let prepared = PreparedPair::prepare(Scenario::EcdhP521, endpoints());
    let mut script = format!(
        r#"#!/bin/sh
if [ "$1" = dudect ]; then
    echo run >> '{}'
    if [ -f '{}' ]; then exit 1; fi
    echo "tpms-timing info session fixture-$$"
    echo 'meas: 0.03 M, max t: 42.0, max tau: 0.01, (5/tau)^2: 250000. Probably not constant time.'
    echo 'tpms-timing result status=leakage-found measurements=30000 batches=30 nvstores=0 mismatches=0 elapsed_s=0.001'
    exit 0
fi
echo 'ready 1'
while IFS= read -r line; do
    case "$line" in
    init\ *)
        echo 'info openssl_version OpenSSL 3.0.13 30 Jan 2024'
        echo 'info libcrypto_path {}'
        echo "info session fixture-$$"
        echo ok ;;
    quit) echo bye; exit 0 ;;
    measure\ *)
        echo 'measure-begin'
        echo 'nvstores_warmup 0'
        echo 'nvstores_measured 0'
        echo 'order 0101'
        echo 'class0 100,101,102,103'
        echo 'class1 100,101,102,103'
        echo 'measure-end' ;;
"#,
        sandbox.state.join("timed-runs").display(),
        sandbox.state.join("fail-timing").display(),
        sandbox.wrapper.display()
    );
    for class in 0..2 {
        script.push_str(&format!(
            "    'exec {}') echo 'resp 00000000 80010000000e000000008000000{}' ;;\n",
            hex::encode(prepared.load_command(class).unwrap()),
            class
        ));
        script.push_str(&format!(
            "    'exec {}') echo 'resp 00000000 {}' ;;\n",
            hex::encode(prepared.measured_command(class, 0x8000_0000 + class as u32)),
            if wrong {
                "80010000000a00000101".into()
            } else {
                hex::encode(&prepared.classes[class].expected_response)
            }
        ));
    }
    script.push_str("    exec\\ *) echo 'resp 00000000 80010000000a00000000' ;;\n    *) exit 2 ;;\n    esac\ndone\n");
    fs::write(&sandbox.wrapper, script).unwrap();
}

#[test]
fn verify_reports_skip_without_measuring_and_override_really_runs() {
    for (name, backend, include, wrong, expected_skips, expected_runs, exit) in [
        ("known-verify", "reference", false, false, 1, 0, 0),
        ("known-override", "reference", true, false, 0, 2, 0),
        ("known-both", "both", false, false, 1, 2, 0),
        ("known-broken", "reference", false, true, 0, 0, 4),
        ("known-other-failure", "both", false, false, 1, 2, 4),
    ] {
        let sandbox = common::Sandbox::new(name);
        install_endpoint_worker(&sandbox, wrong);
        if name == "known-other-failure" {
            fs::write(sandbox.state.join("fail-timing"), "").unwrap();
        }
        let candidate = tpms_timing_tests::search::seeded_candidate(
            Scenario::EcdhP521,
            "renamed-case",
            endpoints(),
            7,
        );
        let file = common::write_candidate(&sandbox.root, "candidate.json", &candidate);
        let library = sandbox.wrapper.to_str().unwrap();
        let mut args = vec![
            "--operation-timeout-s",
            "2",
            "--backend",
            backend,
            "--reference-lib",
            library,
            "--rust-lib",
            library,
            "--seed-diagnostics",
            "0",
        ];
        if include {
            args.push("--disable-known-case-skips");
        }
        let (code, stderr, run) = sandbox.verify(std::slice::from_ref(&file), &args);
        assert_eq!(code, exit, "{name}: {stderr}");
        let result = common::json(&run.join("results.json"));
        let candidate = &result["results"][0];
        assert_eq!(
            candidate["skipped"].as_object().unwrap().len(),
            expected_skips
        );
        assert_eq!(candidate["runs"].as_array().unwrap().len(), expected_runs);
        let measured = fs::read_to_string(sandbox.state.join("timed-runs")).unwrap_or_default();
        assert_eq!(measured.lines().count(), expected_runs);
        if expected_skips > 0 {
            assert_eq!(candidate["verdicts"]["reference"], "skipped-known-issue");
            let summary = fs::read_to_string(run.join("summary.md")).unwrap();
            assert!(summary.contains("**SKIP**"));
            assert!(summary.contains("s->Z == 0"));
            assert!(stderr.contains("SKIP"));
        }
        if backend == "both" && exit == 0 {
            assert_eq!(candidate["verdicts"]["rust"], "reproducible-signal");
            assert_eq!(candidate["category"], "single-backend-reproducible-signal");
        }
        if exit == 4 {
            assert_eq!(
                candidate["category"],
                "infrastructure-or-functional-failure"
            );
        }
        assert_eq!(
            result["candidates_verified"],
            usize::from(expected_runs > 0)
        );
        if name == "known-verify" {
            for disable in [false, true] {
                let replay_out = sandbox.root.join(format!("replay-{disable}"));
                let mut args = vec![
                    "replay",
                    "--candidate",
                    file.to_str().unwrap(),
                    "--backend",
                    "reference",
                    "--reference-lib",
                    library,
                    "--out-dir",
                    replay_out.to_str().unwrap(),
                    "--operation-timeout-s",
                    "2",
                    "--samples-per-class",
                    "4",
                    "--batches",
                    "1",
                ];
                if disable {
                    args.push("--disable-known-case-skips");
                }
                let (code, stderr) = sandbox.run(&args);
                assert_eq!(code, 0, "{stderr}");
                assert_eq!(stderr.contains("SKIP"), !disable);
                let dir = fs::read_dir(replay_out)
                    .unwrap()
                    .next()
                    .unwrap()
                    .unwrap()
                    .path();
                let replay = common::json(&dir.join("replay.json"));
                assert_eq!(
                    replay["backends"]["reference"]["skipped"].is_object(),
                    !disable
                );
                assert_eq!(
                    replay["backends"]["reference"]["batches"]
                        .as_array()
                        .unwrap()
                        .len(),
                    usize::from(disable)
                );
            }
        }
        let report_dir = sandbox.root.join("regenerated");
        let (code, stderr) = sandbox.run(&[
            "report",
            run.to_str().unwrap(),
            "--output",
            report_dir.to_str().unwrap(),
        ]);
        assert_eq!(code, 0, "{stderr}");
        let regenerated = common::json(&report_dir.join("report.json"));
        assert_eq!(
            regenerated["verifications"][0]["results"]["results"][0]["skipped"],
            candidate["skipped"]
        );
    }
}
