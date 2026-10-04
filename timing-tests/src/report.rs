use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::run::{RunInfo, RunState, read_run_info, utc_now};
use crate::scenario::Scenario;
use crate::search::CampaignSummary;
use crate::verify::{
    CandidateResult, Category, VerificationOutcome, VerifyConfig, aggregate_outcome,
    candidate_outcome,
};

pub const VERIFY_RESULTS_FORMAT: &str = "tpms-timing-verify-results/v2";
pub const LEGACY_VERIFY_RESULTS_FORMAT: &str = "tpms-timing-verify-results/v1";
pub const REPORT_FORMAT: &str = "tpms-timing-report/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResults {
    pub format: String,
    pub scenario: Scenario,
    pub config: VerifyConfig,
    pub backends: Vec<String>,
    pub search_runs: Vec<PathBuf>,
    pub search_evaluations: BTreeMap<String, usize>,
    pub candidates_loaded: usize,
    #[serde(default)]
    pub candidates_requested: usize,
    pub candidates_verified: usize,
    pub adaptive_candidates: usize,
    pub seeded_diagnostics: usize,
    pub seeded_diagnostics_reason: Option<String>,
    #[serde(default)]
    pub all_candidates_processed: bool,
    #[serde(default = "incomplete")]
    pub outcome: VerificationOutcome,
    #[serde(default)]
    pub outcome_detail: String,
    #[serde(default)]
    pub outcome_contract: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed: Option<bool>,
    pub stop_reason: String,
    pub results: Vec<CandidateResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSummary {
    pub dir: PathBuf,
    pub info: RunInfo,
    pub exploratory: Option<bool>,
    pub virtualization_indicators: Vec<String>,
    pub host: Option<serde_json::Value>,
    pub openssl: Option<serde_json::Value>,
    pub libraries: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchSection {
    pub run_id: String,
    pub summary: CampaignSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifySection {
    pub run_id: String,
    pub state: RunState,
    pub outcome: VerificationOutcome,
    pub legacy_inconsistency: Option<String>,
    pub results: VerifyResults,
    pub counts: BTreeMap<Category, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub format: String,
    pub generated_utc: String,
    pub runs: Vec<RunSummary>,
    pub searches: Vec<SearchSection>,
    pub verifications: Vec<VerifySection>,
    pub self_tests: Vec<serde_json::Value>,
    pub replays: Vec<serde_json::Value>,
    pub overall_counts: BTreeMap<Category, usize>,
    pub overall_outcome: Option<VerificationOutcome>,
    pub overall_verification_outcome: Option<VerificationOutcome>,
    pub run_outcomes: Vec<RunOutcomeEntry>,
    pub verifications_without_results: Vec<RunOutcomeEntry>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunOutcomeEntry {
    pub run_id: String,
    pub command: String,
    pub state: RunState,
    pub outcome: VerificationOutcome,
    pub reason: Option<String>,
}

fn state_outcome(state: RunState) -> VerificationOutcome {
    match state {
        RunState::Completed => VerificationOutcome::Completed,
        RunState::Failed => VerificationOutcome::Failed,
        RunState::Incomplete | RunState::InProgress => VerificationOutcome::Incomplete,
    }
}

fn worst(
    current: Option<VerificationOutcome>,
    next: VerificationOutcome,
) -> Option<VerificationOutcome> {
    Some(current.map_or(next, |c| c.worst(next)))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let bytes = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("malformed {}: {e}", path.display()))
}

fn incomplete() -> VerificationOutcome {
    VerificationOutcome::Incomplete
}

pub fn reconcile_verify(
    info: &RunInfo,
    results: &mut VerifyResults,
) -> Result<(VerificationOutcome, Option<String>), String> {
    let state_outcome = match info.state {
        RunState::Completed => Some(VerificationOutcome::Completed),
        RunState::Incomplete => Some(VerificationOutcome::Incomplete),
        RunState::Failed => Some(VerificationOutcome::Failed),
        RunState::InProgress => None,
    };
    if results.format == VERIFY_RESULTS_FORMAT {
        for result in &results.results {
            if result.outcome != candidate_outcome(result.category) {
                return Err(format!(
                    "candidate {} records outcome {:?} but category {:?}",
                    result.artifact, result.outcome, result.category
                ));
            }
        }
        let (derived, _) = aggregate_outcome(&results.results, results.candidates_requested, None);
        if results.outcome < derived {
            return Err(format!(
                "results record outcome {:?} but the candidate results imply at least {derived:?}",
                results.outcome
            ));
        }
        return match state_outcome {
            Some(state) if state != results.outcome => Err(format!(
                "run state {:?} disagrees with recorded outcome {:?}",
                info.state, results.outcome
            )),
            Some(_) => Ok((results.outcome, None)),
            None => {
                let outcome = results.outcome.worst(VerificationOutcome::Incomplete);
                Ok((
                    outcome,
                    Some(format!(
                        "run never finished (state in-progress); checkpoint with {} of {} candidates reported as {outcome:?}",
                        results.candidates_verified, results.candidates_requested
                    )),
                ))
            }
        };
    }
    if results.format != LEGACY_VERIFY_RESULTS_FORMAT {
        return Err(format!(
            "unsupported verify results format {:?}; expected {VERIFY_RESULTS_FORMAT} or {LEGACY_VERIFY_RESULTS_FORMAT}",
            results.format
        ));
    }
    for result in &mut results.results {
        result.outcome = candidate_outcome(result.category);
        if result.artifact.is_empty() {
            result.artifact = format!("legacy:{}", result.id);
        }
    }
    let requested = if results.completed == Some(true) {
        results.candidates_verified
    } else {
        results.candidates_verified + 1
    };
    let (derived, detail) = aggregate_outcome(&results.results, requested, None);
    let derived = match info.state {
        RunState::Failed => VerificationOutcome::Failed,
        _ => derived,
    };
    results.outcome = derived;
    results.outcome_detail = detail;
    let note = (state_outcome != Some(derived)).then(|| {
        format!(
            "legacy {LEGACY_VERIFY_RESULTS_FORMAT} artifact: run.json says {:?} (completed flag {:?}) but its candidate outcomes imply {derived:?}; reported as {derived:?}, not as successful verification",
            info.state, results.completed
        )
    });
    Ok((derived, note))
}

pub fn count_categories(results: &[CandidateResult]) -> BTreeMap<Category, usize> {
    let mut counts = BTreeMap::new();
    for result in results {
        *counts.entry(result.category).or_insert(0) += 1;
    }
    counts
}

pub fn build_report(dirs: &[PathBuf]) -> Result<Report, String> {
    if dirs.is_empty() {
        return Err("no run directories given".into());
    }
    let mut report = Report {
        format: REPORT_FORMAT.into(),
        generated_utc: utc_now(),
        runs: Vec::new(),
        searches: Vec::new(),
        verifications: Vec::new(),
        self_tests: Vec::new(),
        replays: Vec::new(),
        overall_counts: BTreeMap::new(),
        overall_outcome: None,
        overall_verification_outcome: None,
        run_outcomes: Vec::new(),
        verifications_without_results: Vec::new(),
        notes: vec![
            "overall_outcome is the worst outcome over every supplied run (failed > incomplete > completed); overall_verification_outcome covers verify runs only, including runs that ended before writing results.json.".into(),
            "Search scores rank candidates only; they are not evidence of leakage.".into(),
            "Only dudect runs in fresh worker processes, repeated and agreeing, count as reproducible signals.".into(),
            "'No signal detected within budget' is not a constant-time or equivalence claim.".into(),
            "Absolute Rust and C execution times are not compared; each backend is judged on its own class-to-class timing dependence.".into(),
        ],
    };
    for dir in dirs {
        let info = read_run_info(dir)?;
        let manifest: Option<serde_json::Value> = if dir.join("manifest.json").exists() {
            Some(read_json(&dir.join("manifest.json"))?)
        } else if info.state == RunState::Completed {
            return Err(format!(
                "{}: completed run without manifest.json",
                dir.display()
            ));
        } else {
            None
        };
        report.runs.push(RunSummary {
            dir: dir.clone(),
            exploratory: manifest
                .as_ref()
                .and_then(|m| m.pointer("/host/exploratory"))
                .and_then(|v| v.as_bool()),
            virtualization_indicators: manifest
                .as_ref()
                .and_then(|m| m.pointer("/host/virtualization_indicators"))
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default(),
            host: manifest.as_ref().and_then(|m| m.get("host").cloned()),
            openssl: manifest.as_ref().and_then(|m| m.get("openssl").cloned()),
            libraries: manifest.as_ref().and_then(|m| m.get("backends").cloned()),
            info: info.clone(),
        });
        let mut run_outcome = state_outcome(info.state);
        match info.command.as_str() {
            "search" => {
                let search = dir.join("search");
                if info.state == RunState::Completed && !search.is_dir() {
                    return Err(format!(
                        "{}: completed search without search/",
                        dir.display()
                    ));
                }
                if search.is_dir() {
                    let mut backends: Vec<PathBuf> = fs::read_dir(&search)
                        .map_err(|e| e.to_string())?
                        .filter_map(|e| e.ok().map(|e| e.path()))
                        .filter(|p| p.is_dir())
                        .collect();
                    backends.sort();
                    for backend in backends {
                        let path = backend.join("summary.json");
                        if path.exists() || info.state == RunState::Completed {
                            report.searches.push(SearchSection {
                                run_id: info.run_id.clone(),
                                summary: read_json(&path)?,
                            });
                        }
                    }
                }
            }
            "verify" => {
                let path = dir.join("results.json");
                if !path.exists() && info.state == RunState::Completed {
                    return Err(format!(
                        "{}: verify run marked completed but results.json is missing",
                        dir.display()
                    ));
                }
                if path.exists() || info.state == RunState::Completed {
                    let mut results: VerifyResults = read_json(&path)?;
                    let (outcome, inconsistency) = reconcile_verify(&info, &mut results)
                        .map_err(|e| format!("{}: {e}", dir.display()))?;
                    if let Some(note) = &inconsistency {
                        report
                            .notes
                            .push(format!("verify run {}: {note}", info.run_id));
                    }
                    run_outcome = outcome;
                    report.overall_verification_outcome =
                        worst(report.overall_verification_outcome, outcome);
                    let counts = count_categories(&results.results);
                    for (category, count) in &counts {
                        *report.overall_counts.entry(*category).or_insert(0) += count;
                    }
                    report.verifications.push(VerifySection {
                        run_id: info.run_id.clone(),
                        state: info.state,
                        outcome,
                        legacy_inconsistency: inconsistency,
                        results,
                        counts,
                    });
                } else {
                    let entry = RunOutcomeEntry {
                        run_id: info.run_id.clone(),
                        command: info.command.clone(),
                        state: info.state,
                        outcome: run_outcome,
                        reason: info.detail.clone(),
                    };
                    report.notes.push(format!(
                        "verify run {} is {:?} and has no results.json; it contributes {:?} to the overall outcome (recorded reason: {})",
                        info.run_id,
                        info.state,
                        run_outcome,
                        info.detail.clone().unwrap_or_else(|| "none recorded".into())
                    ));
                    report.overall_verification_outcome =
                        worst(report.overall_verification_outcome, run_outcome);
                    report.verifications_without_results.push(entry);
                }
            }
            "self-test" => {
                let path = dir.join("selftest.json");
                if path.exists() || info.state == RunState::Completed {
                    report.self_tests.push(read_json(&path)?);
                }
            }
            "replay" => {
                let path = dir.join("replay.json");
                if path.exists() || info.state == RunState::Completed {
                    report.replays.push(read_json(&path)?);
                }
            }
            other => return Err(format!("{}: unknown run command {other:?}", dir.display())),
        }
        report.overall_outcome = worst(report.overall_outcome, run_outcome);
        report.run_outcomes.push(RunOutcomeEntry {
            run_id: info.run_id.clone(),
            command: info.command.clone(),
            state: info.state,
            outcome: run_outcome,
            reason: info.detail.clone(),
        });
        if info.state != RunState::Completed {
            report.notes.push(format!(
                "run {} ended as {:?}: {}",
                info.run_id,
                info.state,
                info.detail.clone().unwrap_or_default()
            ));
        }
    }
    let signal = [
        Category::ReproducibleSignalBoth,
        Category::ReproducibleSignalRustOnly,
        Category::ReproducibleSignalReferenceOnly,
        Category::SingleBackendReproducibleSignal,
    ];
    if signal
        .iter()
        .any(|c| report.overall_counts.get(c).copied().unwrap_or(0) > 0)
    {
        report.notes.push(
            "A reproducible signal is a class-to-class timing dependence for that scalar pair. Each class also loads a different public key and object name and returns a different shared point (handles alternate across repeats), so the dependence is not attributed to secret data alone without further analysis.".into(),
        );
    }
    if report.runs.iter().any(|r| r.exploratory == Some(true)) {
        report.notes.push(
            "At least one run executed on a virtualized or binary-translated host; its measurements are exploratory.".into(),
        );
    }
    Ok(report)
}

fn fmt_opt(value: Option<f64>) -> String {
    value
        .map(|v| format!("{v:.2}"))
        .unwrap_or_else(|| "-".into())
}

pub fn render_markdown(report: &Report) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# tpms-timing-tests report\n");
    let _ = writeln!(
        out,
        "Generated {} from saved artifacts (no measurements were rerun).\n",
        report.generated_utc
    );
    if let Some(outcome) = report.overall_outcome {
        let _ = writeln!(
            out,
            "Overall outcome across all runs: **{outcome:?}** (exit {}).\n",
            outcome.exit_code()
        );
    }
    if let Some(outcome) = report.overall_verification_outcome {
        let _ = writeln!(
            out,
            "Overall verification outcome: **{outcome:?}** (exit {}).\n",
            outcome.exit_code()
        );
    }
    if !report.verifications_without_results.is_empty() {
        let _ = writeln!(out, "Verification runs that ended without results.json:\n");
        for entry in &report.verifications_without_results {
            let _ = writeln!(
                out,
                "- `{}` ({:?}) contributes **{:?}**: {}",
                entry.run_id,
                entry.state,
                entry.outcome,
                entry
                    .reason
                    .clone()
                    .unwrap_or_else(|| "no reason recorded".into())
            );
        }
        let _ = writeln!(out);
    }
    let _ = writeln!(out, "## Runs\n");
    for run in &report.runs {
        let _ = writeln!(
            out,
            "- `{}` ({}, {:?}, outcome {:?}){}",
            run.info.run_id,
            run.info.command,
            run.info.state,
            report
                .run_outcomes
                .iter()
                .find(|o| o.run_id == run.info.run_id)
                .map(|o| o.outcome)
                .unwrap_or(VerificationOutcome::Incomplete),
            match run.exploratory {
                Some(true) => format!(
                    " — exploratory host: {}",
                    run.virtualization_indicators.join("; ")
                ),
                Some(false) => " — no virtualization indicators".into(),
                None => String::new(),
            }
        );
    }
    if !report.searches.is_empty() {
        let _ = writeln!(out, "\n## Adaptive searches\n");
        let _ = writeln!(
            out,
            "| run | backend | scenario | evaluations | feedback | candidates | best score | seeds meeting criteria | functional failures | stop |"
        );
        let _ = writeln!(out, "|---|---|---|---|---|---|---|---|---|---|");
        for s in &report.searches {
            let m = &s.summary;
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
                s.run_id,
                m.backend,
                m.scenario,
                m.evaluations,
                if m.timing_feedback { "on" } else { "off" },
                m.candidates.len(),
                fmt_opt(m.best_candidate_score),
                m.seeds_meeting_criteria.len(),
                m.functional_failures,
                m.stop_reason
            );
        }
    }
    for v in &report.verifications {
        let r = &v.results;
        let _ = writeln!(
            out,
            "\n## Verification `{}` (run state {:?}, outcome {:?}, exit {})\n",
            v.run_id,
            v.state,
            v.outcome,
            v.outcome.exit_code()
        );
        let _ = writeln!(out, "Outcome detail: {}\n", v.results.outcome_detail);
        if let Some(note) = &v.legacy_inconsistency {
            let _ = writeln!(out, "**Inconsistent legacy artifact:** {note}\n");
        }
        let _ = writeln!(
            out,
            "dudect budget {} measurements per run (batch {}), {} independent repeats per backend, time limit {} s per run, backends: {}.",
            r.config.budget,
            r.config.batch,
            r.config.repeats,
            r.config.time_limit_s,
            r.backends.join(", ")
        );
        let _ = writeln!(
            out,
            "Candidates: {} loaded from search ({} adaptive), {} verified, {} seeded diagnostics{}. Search evaluations examined: {}. Stop: {}.\n",
            r.candidates_loaded,
            r.adaptive_candidates,
            r.candidates_verified,
            r.seeded_diagnostics,
            r.seeded_diagnostics_reason
                .as_ref()
                .map(|x| format!(" ({x})"))
                .unwrap_or_default(),
            r.search_evaluations
                .iter()
                .map(|(k, v)| format!("{k} {v}"))
                .collect::<Vec<_>>()
                .join(", "),
            r.stop_reason
        );
        let _ = writeln!(
            out,
            "| artifact (label; provenance) | kind | search score | functional | runs (backend: status max t) | per-backend verdict | category | outcome |"
        );
        let _ = writeln!(out, "|---|---|---|---|---|---|---|---|");
        for c in &r.results {
            let runs = c
                .runs
                .iter()
                .map(|run| {
                    format!(
                        "{}#{}: {:?} {}",
                        run.backend,
                        run.repeat,
                        run.status,
                        fmt_opt(run.final_max_t)
                    )
                })
                .collect::<Vec<_>>()
                .join("<br>");
            let verdicts = c
                .verdicts
                .iter()
                .map(|(b, v)| format!("{b}: {v:?}"))
                .collect::<Vec<_>>()
                .join("<br>");
            let functional = if crate::verify::functional_ok(c) {
                match c.cross_backend_identical {
                    Some(true) => "ok, identical across backends".to_string(),
                    _ => "ok".to_string(),
                }
            } else {
                c.functional
                    .iter()
                    .filter(|f| !f.ok)
                    .map(|f| format!("{}: {}", f.backend, f.detail))
                    .collect::<Vec<_>>()
                    .join("; ")
            };
            let _ = writeln!(
                out,
                "| {} ({}; {} sources) | {:?} | {} | {} | {} | {} | {} | {:?} |",
                c.artifact,
                crate::artifacts::display_label(&c.id),
                c.provenance.len(),
                c.kind,
                fmt_opt(c.search_score),
                functional,
                runs,
                verdicts,
                c.category.describe(),
                c.outcome
            );
        }
    }
    if !report.verifications.is_empty() {
        let _ = writeln!(out, "\n## Outcome counts\n");
    }
    for category in [
        Category::ReproducibleSignalBoth,
        Category::ReproducibleSignalRustOnly,
        Category::ReproducibleSignalReferenceOnly,
        Category::NoSignalDetectedWithinBudget,
        Category::InconclusiveOrIncomplete,
        Category::InfrastructureOrFunctionalFailure,
        Category::SingleBackendReproducibleSignal,
        Category::SingleBackendNoSignalWithinBudget,
    ]
    .into_iter()
    .filter(|_| !report.verifications.is_empty())
    {
        let _ = writeln!(
            out,
            "- {}: {}",
            category.describe(),
            report.overall_counts.get(&category).copied().unwrap_or(0)
        );
    }
    if !report.self_tests.is_empty() {
        let _ = writeln!(out, "\n## Self-tests\n");
        for test in &report.self_tests {
            if let Some(checks) = test.get("checks").and_then(|c| c.as_array()) {
                for check in checks {
                    let _ = writeln!(
                        out,
                        "- {} — {}: {}",
                        check.get("name").and_then(|v| v.as_str()).unwrap_or("?"),
                        if check
                            .get("passed")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false)
                        {
                            "pass"
                        } else {
                            "FAIL"
                        },
                        check.get("detail").and_then(|v| v.as_str()).unwrap_or("")
                    );
                }
            }
        }
    }
    if !report.replays.is_empty() {
        let _ = writeln!(out, "\n## Replays\n");
        for replay in &report.replays {
            let _ = writeln!(
                out,
                "- {}",
                replay
                    .get("summary")
                    .and_then(|v| v.as_str())
                    .unwrap_or("(no summary)")
            );
        }
    }
    let _ = writeln!(out, "\n## Notes\n");
    for note in &report.notes {
        let _ = writeln!(out, "- {note}");
    }
    out
}

pub fn write_report(report: &Report, output: &Path) -> std::io::Result<()> {
    fs::create_dir_all(output)?;
    fs::write(
        output.join("report.json"),
        serde_json::to_vec_pretty(report).unwrap(),
    )?;
    fs::write(output.join("report.md"), render_markdown(report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::Run;

    fn temp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("tpms-timing-report-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn malformed_artifacts_fail_explicitly() {
        let base = temp("malformed");
        assert!(build_report(&[base.join("missing")]).is_err());
        let mut run = Run::create(&base, "verify", None).unwrap();
        run.write_json(
            "manifest.json",
            &serde_json::json!({"host": {"exploratory": true}}),
        )
        .unwrap();
        fs::write(run.dir.join("results.json"), b"{ not json").unwrap();
        run.finish(RunState::Completed, None).unwrap();
        let error = build_report(&[run.dir.clone()]).unwrap_err();
        assert!(error.contains("malformed"), "{error}");
        fs::write(run.dir.join("run.json"), b"[]").unwrap();
        assert!(
            build_report(&[run.dir.clone()])
                .unwrap_err()
                .contains("malformed")
        );
        let mut missing = Run::create(&base, "verify", Some("nomanifest")).unwrap();
        missing.finish(RunState::Completed, None).unwrap();
        assert!(
            build_report(&[missing.dir.clone()])
                .unwrap_err()
                .contains("manifest")
        );
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn interrupted_verification_is_reported_as_incomplete() {
        let base = temp("interrupted");
        let mut run = Run::create(&base, "verify", None).unwrap();
        run.write_json("manifest.json", &serde_json::json!({}))
            .unwrap();
        run.finish(RunState::Failed, Some("interrupted".into()))
            .unwrap();
        let report = build_report(&[run.dir.clone()]).unwrap();
        assert!(report.verifications.is_empty());
        assert!(report.notes.iter().any(|n| n.contains("incomplete")));
        assert!(report.overall_counts.is_empty());
        let in_progress = Run::create(&base, "verify", Some("live")).unwrap();
        let report = build_report(std::slice::from_ref(&in_progress.dir)).unwrap();
        assert!(report.notes.iter().any(|n| n.contains("InProgress")));
        fs::remove_dir_all(&base).unwrap();
    }
}
