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
pub struct CheckResultRow {
    #[serde(default = "default_checked")]
    pub functional_checked: bool,
    #[serde(default)]
    pub skipped: BTreeMap<String, crate::known_issues::KnownIssue>,
    pub scenario: String,
    #[serde(default)]
    pub seed: String,
    pub ok: bool,
}

fn default_checked() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
struct CheckFile {
    #[serde(default)]
    results: Vec<CheckResultRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckSection {
    pub run_id: String,
    pub state: RunState,
    pub outcome: VerificationOutcome,
    pub scenarios: Vec<String>,
    pub results: Vec<CheckResultRow>,
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
    #[serde(default)]
    pub checks: Vec<CheckSection>,
    #[serde(default)]
    pub scenarios: Vec<ScenarioRow>,
    pub overall_counts: BTreeMap<Category, usize>,
    pub overall_outcome: Option<VerificationOutcome>,
    pub overall_verification_outcome: Option<VerificationOutcome>,
    pub run_outcomes: Vec<RunOutcomeEntry>,
    #[serde(default)]
    pub run_scenarios: Vec<(Vec<String>, RunOutcomeEntry)>,
    pub verifications_without_results: Vec<RunOutcomeEntry>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BackendTally {
    pub reproducible_signal: usize,
    pub reproducible_signal_secret_only: usize,
    pub no_signal_within_budget: usize,
    pub skipped_known_issue: usize,
    pub inconclusive: usize,
    pub failure: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioRow {
    pub scenario: String,
    pub area: String,
    pub status: String,
    pub functional_check: Option<bool>,
    pub verified_candidates: usize,
    pub backends: BTreeMap<String, BackendTally>,
    pub outcome: Option<VerificationOutcome>,
    pub findings: Vec<String>,
    #[serde(default)]
    pub runs: Vec<RunOutcomeEntry>,
    #[serde(default)]
    pub problems: Vec<String>,
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
                        results.results.len(),
                        results.candidates_requested
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
        checks: Vec::new(),
        scenarios: Vec::new(),
        overall_counts: BTreeMap::new(),
        overall_outcome: None,
        overall_verification_outcome: None,
        run_outcomes: Vec::new(),
        run_scenarios: Vec::new(),
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
            "check" => {
                let path = dir.join("check.json");
                let results = if path.exists() {
                    read_json::<CheckFile>(&path)?.results
                } else if info.state == RunState::Completed {
                    return Err(format!(
                        "{}: check run marked completed but check.json is missing",
                        dir.display()
                    ));
                } else {
                    Vec::new()
                };
                report.checks.push(CheckSection {
                    run_id: info.run_id.clone(),
                    state: info.state,
                    outcome: run_outcome,
                    scenarios: info.scenarios.clone(),
                    results,
                });
            }
            other => return Err(format!("{}: unknown run command {other:?}", dir.display())),
        }
        report.overall_outcome = worst(report.overall_outcome, run_outcome);
        let entry = RunOutcomeEntry {
            run_id: info.run_id.clone(),
            command: info.command.clone(),
            state: info.state,
            outcome: run_outcome,
            reason: info.detail.clone(),
        };
        if !info.scenarios.is_empty() {
            report
                .run_scenarios
                .push((info.scenarios.clone(), entry.clone()));
        }
        report.run_outcomes.push(entry);
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
            "A reproducible signal is a class-to-class timing dependence for that input pair. Classes may also differ in public values (loaded public key, object name, handle, output, caller-chosen inputs); each finding lists its difference kind, public differences and confounders. Only secret-only pairs isolate a secret dependence; mixed, public-input, output-size and visible-outcome signals are not isolated to the secret and are not automatically harmless either.".into(),
        );
    }
    report.scenarios = scenario_rows(&report);
    if report.runs.iter().any(|r| r.exploratory == Some(true)) {
        report.notes.push(
            "At least one run executed on a virtualized or binary-translated host; its measurements are exploratory.".into(),
        );
    }
    Ok(report)
}

fn scenario_rows(report: &Report) -> Vec<ScenarioRow> {
    use crate::scenario::DifferenceKind;
    use crate::verify::BackendVerdict;
    let mut rows: BTreeMap<String, ScenarioRow> = BTreeMap::new();
    let row = |name: &str| -> ScenarioRow {
        let parsed = Scenario::parse(name).ok();
        ScenarioRow {
            scenario: name.to_string(),
            area: parsed
                .map(|s| s.area().name().to_string())
                .unwrap_or_default(),
            status: parsed
                .map(|s| {
                    if crate::scenario::matrix::implemented(s) {
                        "implemented"
                    } else {
                        "outstanding"
                    }
                })
                .unwrap_or("unknown")
                .to_string(),
            functional_check: None,
            verified_candidates: 0,
            backends: BTreeMap::new(),
            outcome: None,
            findings: Vec::new(),
            runs: Vec::new(),
            problems: Vec::new(),
        }
    };
    for (scenarios, entry) in &report.run_scenarios {
        for name in scenarios {
            if entry.command == "check" {
                let scenario_row = rows.entry(name.clone()).or_insert_with(|| row(name));
                scenario_row.runs.push(entry.clone());
                continue;
            }
            let scenario_row = rows.entry(name.clone()).or_insert_with(|| row(name));
            scenario_row.runs.push(entry.clone());
            scenario_row.outcome = worst(scenario_row.outcome, entry.outcome);
            if entry.outcome != VerificationOutcome::Completed {
                scenario_row.problems.push(format!(
                    "{} run `{}` ended as {:?} ({:?}): {}",
                    entry.command,
                    entry.run_id,
                    entry.state,
                    entry.outcome,
                    entry
                        .reason
                        .clone()
                        .unwrap_or_else(|| "no reason recorded".into())
                ));
            }
        }
    }
    for section in &report.checks {
        let listed: Vec<String> = if section.scenarios.is_empty() {
            let mut names: Vec<String> =
                section.results.iter().map(|r| r.scenario.clone()).collect();
            names.sort();
            names.dedup();
            names
        } else {
            section.scenarios.clone()
        };
        for name in listed {
            let entry = rows.entry(name.clone()).or_insert_with(|| row(&name));
            let own: Vec<&CheckResultRow> = section
                .results
                .iter()
                .filter(|r| r.scenario == name)
                .collect();
            if own.is_empty() {
                let outcome = if section.outcome == VerificationOutcome::Completed {
                    VerificationOutcome::Incomplete
                } else {
                    section.outcome
                };
                entry.outcome = worst(entry.outcome, outcome);
                entry.problems.push(format!(
                    "check run `{}` ({:?}) recorded no functional result for this scenario; it has no completion evidence",
                    section.run_id, section.state
                ));
                continue;
            }
            for result in &own {
                for (backend, issue) in &result.skipped {
                    entry
                        .backends
                        .entry(backend.clone())
                        .or_default()
                        .skipped_known_issue += 1;
                    entry
                        .problems
                        .push(format!("{backend}: SKIP {}: {}", issue.id, issue.reason));
                }
            }
            let checked: Vec<_> = own.iter().filter(|r| r.functional_checked).collect();
            if checked.is_empty() {
                continue;
            }
            let failed: Vec<_> = checked.into_iter().filter(|r| !r.ok).collect();
            let ok = failed.is_empty();
            entry.functional_check = Some(entry.functional_check.unwrap_or(true) && ok);
            if !ok {
                entry.outcome = worst(entry.outcome, VerificationOutcome::Failed);
                for row in failed {
                    entry.problems.push(format!(
                        "functional check failed in run `{}` for seed `{}`",
                        section.run_id, row.seed
                    ));
                }
            }
        }
    }
    for section in &report.verifications {
        let name = section.results.scenario.name();
        let entry = rows.entry(name.to_string()).or_insert_with(|| row(name));
        entry.outcome = worst(entry.outcome, section.outcome);
        for result in &section.results.results {
            if !result.runs.is_empty() {
                entry.verified_candidates += 1;
            }
            for (backend, verdict) in &result.verdicts {
                let tally = entry.backends.entry(backend.clone()).or_default();
                match verdict {
                    BackendVerdict::ReproducibleSignal => {
                        tally.reproducible_signal += 1;
                        // Classification as validated on the backend that produced
                        // this finding; only legacy results (no per-backend record)
                        // fall back to the top-level fields.
                        let (kind, public_differences, confounders) =
                            result.finding_context(backend);
                        if kind == DifferenceKind::SecretOnly {
                            tally.reproducible_signal_secret_only += 1;
                        }
                        let mut context = Vec::new();
                        if !public_differences.is_empty() {
                            context.push(format!(
                                "public differences: {}",
                                public_differences.join(", ")
                            ));
                        }
                        if !confounders.is_empty() {
                            context.push(format!("confounders: {}", confounders.join("; ")));
                        }
                        entry.findings.push(format!(
                            "{backend}: {} ({}) — {:?}: {}{}",
                            result.artifact,
                            crate::artifacts::display_label(&result.id),
                            kind,
                            kind.describe(),
                            if context.is_empty() {
                                String::new()
                            } else {
                                format!(" [{}]", context.join("; "))
                            }
                        ));
                    }
                    BackendVerdict::NoSignalWithinBudget => tally.no_signal_within_budget += 1,
                    BackendVerdict::SkippedKnownIssue => tally.skipped_known_issue += 1,
                    BackendVerdict::Inconclusive => tally.inconclusive += 1,
                    BackendVerdict::Failure => tally.failure += 1,
                }
            }
        }
    }
    rows.into_values().collect()
}

fn fmt_opt(value: Option<f64>) -> String {
    value
        .map(|v| format!("{v:.2}"))
        .unwrap_or_else(|| "-".into())
}

pub fn render_summary(report: &Report) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "tpms-timing-tests report");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Generated {} from saved artifacts (no measurements were rerun).",
        report.generated_utc
    );
    let _ = writeln!(out);
    if let Some(outcome) = report.overall_outcome {
        let _ = writeln!(
            out,
            "Overall outcome across all runs: {:?} (exit {}).",
            outcome,
            outcome.exit_code()
        );
    }
    if let Some(outcome) = report.overall_verification_outcome {
        let _ = writeln!(
            out,
            "Overall verification outcome: {:?} (exit {}).",
            outcome,
            outcome.exit_code()
        );
    }
    if !report.verifications_without_results.is_empty() {
        let _ = writeln!(
            out,
            "Verification runs that ended without results.json (never presented as passing):"
        );
        for entry in &report.verifications_without_results {
            let _ = writeln!(
                out,
                "  - {} ({:?}) contributes {:?}: {}",
                entry.run_id,
                entry.state,
                entry.outcome,
                entry
                    .reason
                    .clone()
                    .unwrap_or_else(|| "no reason recorded".into())
            );
        }
    }
    if !report.scenarios.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "Scenario outcomes");
        let _ = writeln!(
            out,
            "Per backend: S = reproducible signal (s = of which secret-only pairs), N = no signal within budget, K = known-case SKIP, I = inconclusive/incomplete, F = failure. A known-case SKIP is never evidence of no signal."
        );
        for row in &report.scenarios {
            let backends: Vec<String> = row
                .backends
                .iter()
                .map(|(b, t)| {
                    format!(
                        "{b}: S{} (s{}) N{} K{} I{} F{}",
                        t.reproducible_signal,
                        t.reproducible_signal_secret_only,
                        t.no_signal_within_budget,
                        t.skipped_known_issue,
                        t.inconclusive,
                        t.failure
                    )
                })
                .collect();
            let runs: Vec<String> = row
                .runs
                .iter()
                .map(|r| format!("{}:{:?}", r.command, r.outcome))
                .collect();
            let _ = writeln!(out);
            let _ = writeln!(out, "  scenario: {}", row.scenario);
            let _ = writeln!(out, "    area: {}", row.area);
            let _ = writeln!(
                out,
                "    functional check: {}",
                match row.functional_check {
                    Some(true) => "ok",
                    Some(false) => "FAILED",
                    None => "-",
                }
            );
            let _ = writeln!(out, "    verified candidates: {}", row.verified_candidates);
            let _ = writeln!(
                out,
                "    runs: {}",
                if runs.is_empty() {
                    "-".to_string()
                } else {
                    runs.join(", ")
                }
            );
            let _ = writeln!(
                out,
                "    backends: {}",
                if backends.is_empty() {
                    "-".to_string()
                } else {
                    backends.join("; ")
                }
            );
            let _ = writeln!(
                out,
                "    outcome: {}",
                row.outcome
                    .map(|o| format!("{o:?}"))
                    .unwrap_or_else(|| "-".into())
            );
        }
        let findings: Vec<&ScenarioRow> = report
            .scenarios
            .iter()
            .filter(|r| !r.findings.is_empty())
            .collect();
        let _ = writeln!(out);
        let _ = writeln!(out, "Findings (reproducible signals)");
        if findings.is_empty() {
            let _ = writeln!(out, "  None in the supplied runs.");
        } else {
            for row in findings {
                for finding in &row.findings {
                    let _ = writeln!(out, "  - {} {finding}", row.scenario);
                }
            }
        }
        let skipped: Vec<&ScenarioRow> = report
            .scenarios
            .iter()
            .filter(|r| r.backends.values().any(|t| t.skipped_known_issue > 0))
            .collect();
        let _ = writeln!(out);
        let _ = writeln!(out, "Known-case skips (with registered reasons)");
        if skipped.is_empty() {
            let _ = writeln!(out, "  None.");
        } else {
            for row in &skipped {
                let _ = writeln!(
                    out,
                    "  - SKIP {} (see verification details for the registered reason)",
                    row.scenario
                );
                for check in report
                    .checks
                    .iter()
                    .flat_map(|section| &section.results)
                    .filter(|check| check.scenario == row.scenario)
                {
                    for (backend, issue) in &check.skipped {
                        let _ = writeln!(
                            out,
                            "      {backend}: SKIP {:?} {}: {}",
                            issue.kind, issue.id, issue.reason
                        );
                    }
                }
            }
        }
        for (heading, wanted) in [
            ("Incomplete experiments", VerificationOutcome::Incomplete),
            (
                "Functional or infrastructure failures",
                VerificationOutcome::Failed,
            ),
        ] {
            let rows: Vec<&ScenarioRow> = report
                .scenarios
                .iter()
                .filter(|r| r.outcome == Some(wanted))
                .collect();
            let _ = writeln!(out);
            let _ = writeln!(out, "{heading}");
            if rows.is_empty() {
                let _ = writeln!(out, "  None.");
            } else {
                for row in &rows {
                    let _ = writeln!(out, "  - {}", row.scenario);
                    for problem in &row.problems {
                        let _ = writeln!(out, "      {problem}");
                    }
                    if !row.functional_check.unwrap_or(true) {
                        let _ = writeln!(out, "      functional check failed");
                    }
                }
            }
        }
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "Runs");
    for run in &report.runs {
        let _ = writeln!(
            out,
            "  - {} ({}, {:?}, outcome {:?}){}",
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
                    " - exploratory host: {}",
                    run.virtualization_indicators.join("; ")
                ),
                Some(false) => " - no virtualization indicators".to_string(),
                None => String::new(),
            }
        );
    }
    if !report.searches.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "Adaptive searches");
        for s in &report.searches {
            let m = &s.summary;
            let _ = writeln!(
                out,
                "  - run {} backend {} scenario {}: {} evaluations, timing feedback {}, {} candidates, best score {}, {} seeds meeting criteria, {} functional failures, stop: {}",
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
        let _ = writeln!(out);
        let _ = writeln!(out, "Known timing cases");
        for s in &report.searches {
            for entry in &s.summary.known_skips {
                if let Some(issue) = &entry.observation.skipped {
                    let _ = writeln!(
                        out,
                        "  - SKIP {} / {} / evaluation {}: {} - {}",
                        s.run_id,
                        s.summary.backend,
                        entry.observation.evaluation,
                        issue.id,
                        issue.reason
                    );
                }
            }
        }
    }
    for v in &report.verifications {
        let r = &v.results;
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "Verification {} (run state {:?}, outcome {:?}, exit {})",
            v.run_id,
            v.state,
            v.outcome,
            v.outcome.exit_code()
        );
        let _ = writeln!(out, "  outcome detail: {}", v.results.outcome_detail);
        if let Some(note) = &v.legacy_inconsistency {
            let _ = writeln!(out, "  inconsistent legacy artifact: {note}");
        }
        let _ = writeln!(
            out,
            "  dudect budget {} measurements per run (batch {}), {} independent repeats per backend, time limit {} s per run, backends: {}.",
            r.config.budget,
            r.config.batch,
            r.config.repeats,
            r.config.time_limit_s,
            r.backends.join(", ")
        );
        let _ = writeln!(
            out,
            "  candidates: {} loaded from search ({} adaptive), {} timing-verified, {} seeded diagnostics{}. Search evaluations examined: {}. Stop: {}.",
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
        let skipped = r.results.iter().map(|c| c.skipped.len()).sum::<usize>();
        let _ = writeln!(
            out,
            "  processed {} candidates; SKIP on {skipped} backend/candidate checks. Skipped timings are not no-signal evidence.",
            r.results.len()
        );
        for c in &r.results {
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "  candidate {} ({}; {} provenance sources)",
                c.artifact,
                crate::artifacts::display_label(&c.id),
                c.provenance.len()
            );
            let _ = writeln!(
                out,
                "    kind: {:?}, search score: {}, category: {} ({:?})",
                c.kind,
                fmt_opt(c.search_score),
                c.category.describe(),
                c.outcome
            );
            let functional = if c.functional.is_empty() {
                "not run (known functional failure skip)".to_string()
            } else if crate::verify::functional_ok(c) {
                match (c.cross_backend_identical, c.cross_backend_expected_divergence) {
                    (Some(true), _) => "ok, identical across backends".to_string(),
                    (Some(false), true) => {
                        "ok, nonidentical across backends as expected: the backends resolved different, independently validated contracts for this input"
                            .to_string()
                    }
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
            let _ = writeln!(out, "    functional: {functional}");
            for (backend, classification) in &c.per_backend {
                let _ = writeln!(
                    out,
                    "    classification {backend}: {:?} [public differences: {}; confounders: {}]",
                    classification
                        .difference
                        .map(|d| format!("{d:?}"))
                        .unwrap_or_else(|| "Unclassified".to_string()),
                    classification.public_differences.join(", "),
                    classification.confounders.join("; ")
                );
                if let Some(evidence) = &classification.rsaes_evidence {
                    let _ = writeln!(
                        out,
                        "    rsaes contract {backend}: {:?} (probe recorded independently)",
                        evidence.contract
                    );
                }
                if let Some(evidence) = &classification.sym_evidence {
                    let _ = writeln!(
                        out,
                        "    cfb chaining contract {backend}: {:?} (probe recorded independently)",
                        evidence.contract
                    );
                }
            }
            if c.per_backend.is_empty() {
                // Legacy result files without per-backend records keep their
                // combined classification visible instead of hiding it.
                let kind = c.finding_context("legacy");
                let _ = writeln!(
                    out,
                    "    classification: {:?} [public differences: {}; confounders: {}]",
                    kind.0,
                    kind.1.join(", "),
                    kind.2.join("; ")
                );
            }
            for run in &c.runs {
                let _ = writeln!(
                    out,
                    "    run {}#{}: {:?} {}",
                    run.backend,
                    run.repeat,
                    run.status,
                    fmt_opt(run.final_max_t)
                );
            }
            for (b, verdict) in &c.verdicts {
                match c.skipped.get(b) {
                    Some(issue) => {
                        let _ =
                            writeln!(out, "    verdict {b}: SKIP {} - {}", issue.id, issue.reason);
                    }
                    None => {
                        let _ = writeln!(out, "    verdict {b}: {verdict:?}");
                    }
                }
            }
        }
    }
    if !report.verifications.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "Outcome counts");
    }
    for category in [
        Category::KnownIssueSkipped,
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
            "  - {}: {}",
            category.describe(),
            report.overall_counts.get(&category).copied().unwrap_or(0)
        );
    }
    if !report.self_tests.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "Self-tests");
        for test in &report.self_tests {
            if let Some(checks) = test.get("checks").and_then(|c| c.as_array()) {
                for check in checks {
                    let _ = writeln!(
                        out,
                        "  - {} - {}: {}",
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
        let _ = writeln!(out);
        let _ = writeln!(out, "Replays (exploratory unless stated otherwise)");
        for replay in &report.replays {
            let _ = writeln!(
                out,
                "  - {}",
                replay
                    .get("summary")
                    .and_then(|v| v.as_str())
                    .unwrap_or("(no summary)")
            );
        }
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "Notes");
    for note in &report.notes {
        let _ = writeln!(out, "  - {note}");
    }
    out
}

pub fn write_report(report: &Report, output: &Path) -> std::io::Result<()> {
    fs::create_dir_all(output)?;
    fs::write(
        output.join("report.json"),
        serde_json::to_vec_pretty(report).unwrap(),
    )
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

    fn candidate(id: &str, verdicts: &[(&str, &str)], difference: &str) -> serde_json::Value {
        serde_json::json!({
            "artifact": id, "id": id, "kind": "adaptive-discovery", "search_backend": null,
            "search_score": null, "retention_reason": "", "functional": [],
            "cross_backend_identical": true, "runs": [{"repeat": 0, "backend": "rust", "load_order": "class-a-first",
            "directory": "", "status": "budget-exhausted", "verdict": "no-signal", "measurements": 0, "batches": 0,
            "final_max_t": null, "final_max_tau": null, "dudect_verdict_text": null, "session": null, "elapsed_s": 0.0,
            "detail": ""}],
            "verdicts": verdicts.iter().map(|(b, v)| (b.to_string(), serde_json::Value::String(v.to_string()))).collect::<serde_json::Map<_, _>>(),
            "category": "inconclusive-or-incomplete", "difference": difference,
        })
    }

    #[test]
    fn scenario_rows_keep_findings_skips_incomplete_and_failures_apart() {
        let results: VerifyResults = serde_json::from_value(serde_json::json!({
            "format": VERIFY_RESULTS_FORMAT, "scenario": "rsa-decrypt-2048-oaep-sha256",
            "config": {"budget": 1, "batch": 1, "repeats": 2, "warmup": 0, "time_limit_s": 1.0, "cpu": null,
                       "max_candidates": 1, "seed_diagnostics": 0, "include_seed_diagnostics": false},
            "backends": ["rust", "reference"], "search_runs": [], "search_evaluations": {},
            "candidates_loaded": 4, "candidates_verified": 4, "adaptive_candidates": 4, "seeded_diagnostics": 0,
            "seeded_diagnostics_reason": null, "stop_reason": "",
            "results": [
                candidate("secret", &[("rust", "reproducible-signal"), ("reference", "no-signal-within-budget")], "secret-only"),
                candidate("visible", &[("rust", "reproducible-signal"), ("reference", "reproducible-signal")], "visible-outcome"),
                candidate("skip", &[("rust", "no-signal-within-budget"), ("reference", "skipped-known-issue")], "secret-only"),
                candidate("open", &[("rust", "inconclusive"), ("reference", "failure")], "secret-only"),
            ],
        }))
        .unwrap();
        let mut report = Report {
            format: REPORT_FORMAT.into(),
            generated_utc: String::new(),
            runs: Vec::new(),
            searches: Vec::new(),
            verifications: vec![VerifySection {
                run_id: "v".into(),
                state: RunState::Incomplete,
                outcome: VerificationOutcome::Failed,
                legacy_inconsistency: None,
                counts: BTreeMap::new(),
                results,
            }],
            self_tests: Vec::new(),
            replays: Vec::new(),
            checks: vec![CheckSection {
                run_id: "c".into(),
                state: RunState::Failed,
                outcome: VerificationOutcome::Failed,
                scenarios: vec![
                    "mac-hmac-sha256".into(),
                    "rsa-decrypt-2048-oaep-sha256".into(),
                    "auth-password".into(),
                ],
                results: vec![
                    CheckResultRow {
                        functional_checked: true,
                        skipped: BTreeMap::new(),
                        scenario: "mac-hmac-sha256".into(),
                        seed: "same-message-different-key".into(),
                        ok: false,
                    },
                    CheckResultRow {
                        functional_checked: true,
                        skipped: BTreeMap::new(),
                        scenario: "rsa-decrypt-2048-oaep-sha256".into(),
                        seed: "valid-vs-valid".into(),
                        ok: true,
                    },
                    CheckResultRow {
                        functional_checked: true,
                        skipped: BTreeMap::new(),
                        scenario: "auth-password".into(),
                        seed: "s".into(),
                        ok: true,
                    },
                ],
            }],
            scenarios: Vec::new(),
            overall_counts: BTreeMap::new(),
            overall_outcome: None,
            overall_verification_outcome: None,
            run_outcomes: Vec::new(),
            run_scenarios: Vec::new(),
            verifications_without_results: Vec::new(),
            notes: Vec::new(),
        };
        report.scenarios = scenario_rows(&report);
        let row = |name: &str| {
            report
                .scenarios
                .iter()
                .find(|r| r.scenario == name)
                .unwrap()
        };
        let rsa = row("rsa-decrypt-2048-oaep-sha256");
        assert_eq!(rsa.backends["rust"].reproducible_signal, 2);
        assert_eq!(rsa.backends["rust"].reproducible_signal_secret_only, 1);
        assert_eq!(rsa.backends["reference"].skipped_known_issue, 1);
        assert_eq!(rsa.backends["reference"].no_signal_within_budget, 1);
        assert_eq!(rsa.backends["rust"].inconclusive, 1);
        assert_eq!(rsa.backends["reference"].failure, 1);
        assert_eq!(rsa.findings.len(), 3);
        assert!(
            rsa.findings
                .iter()
                .any(|f| f.contains("VisibleOutcome: classes return different response codes"))
        );
        assert_eq!(row("mac-hmac-sha256").functional_check, Some(false));
        assert_eq!(
            row("mac-hmac-sha256").outcome,
            Some(VerificationOutcome::Failed)
        );
        assert_eq!(row("auth-password").status, "implemented");
        let summary = render_summary(&report);
        for heading in [
            "Findings (reproducible signals)",
            "Known-case skips (with registered reasons)",
            "Incomplete experiments",
            "Functional or infrastructure failures",
        ] {
            assert!(summary.contains(heading), "{heading}");
        }
        assert!(summary.contains("functional check: FAILED"));
    }

    #[test]
    fn findings_render_their_confounders_and_legacy_results_stay_unclassified() {
        let mut mixed = candidate(
            "mixed",
            &[
                ("rust", "reproducible-signal"),
                ("reference", "no-signal-within-budget"),
            ],
            "mixed",
        );
        mixed["public_differences"] = serde_json::json!(["data"]);
        mixed["confounders"] = serde_json::json!([
            "the classes load different key objects: public key or unique field, object name and handle differ"
        ]);
        let mut legacy = candidate(
            "legacy",
            &[
                ("rust", "reproducible-signal"),
                ("reference", "reproducible-signal"),
            ],
            "secret-only",
        );
        legacy.as_object_mut().unwrap().remove("difference");
        let results: VerifyResults = serde_json::from_value(serde_json::json!({
            "format": VERIFY_RESULTS_FORMAT, "scenario": "ecdh-p521",
            "config": {"budget": 1, "batch": 1, "repeats": 2, "warmup": 0, "time_limit_s": 1.0, "cpu": null,
                       "max_candidates": 1, "seed_diagnostics": 0, "include_seed_diagnostics": false},
            "backends": ["rust", "reference"], "search_runs": [], "search_evaluations": {},
            "candidates_loaded": 2, "candidates_verified": 2, "adaptive_candidates": 2, "seeded_diagnostics": 0,
            "seeded_diagnostics_reason": null, "stop_reason": "", "results": [mixed, legacy],
        }))
        .unwrap();
        let mut report = build_report_from_parts(vec![VerifySection {
            run_id: "v".into(),
            state: RunState::Completed,
            outcome: VerificationOutcome::Completed,
            legacy_inconsistency: None,
            counts: BTreeMap::new(),
            results,
        }]);
        report.scenarios = scenario_rows(&report);
        let row = &report.scenarios[0];
        assert_eq!(row.backends["rust"].reproducible_signal, 2);
        assert_eq!(row.backends["rust"].reproducible_signal_secret_only, 0);
        let markdown = render_summary(&report);
        assert!(
            markdown.contains("Mixed: the secret component differs together with public values")
        );
        assert!(markdown.contains("public differences: data"));
        assert!(markdown.contains("confounders: the classes load different key objects"));
        assert!(markdown.contains("Unclassified: no difference classification recorded"));
        assert!(!markdown.contains("not a hidden leak"));
        assert!(!markdown.contains("are expected and are not"));
    }

    #[test]
    fn per_backend_classifications_render_separately_for_one_candidate() {
        // One candidate, two backends, two different validated classifications
        // (the RSAES explicit/implicit contract split): each finding must show
        // its own backend's classification, never the first backend's.
        let mut split = candidate(
            "split",
            &[
                ("rust", "reproducible-signal"),
                ("reference", "reproducible-signal"),
            ],
            "secret-only",
        );
        split.as_object_mut().unwrap().remove("difference");
        split["per_backend"] = serde_json::json!({
            "rust": {
                "difference": "mixed",
                "public_differences": ["ciphertext"],
                "confounders": [],
            },
            "reference": {
                "difference": "output-size",
                "public_differences": ["ciphertext"],
                "confounders": ["implicit rejection lengths"],
            },
        });
        let results: VerifyResults = serde_json::from_value(serde_json::json!({
            "format": VERIFY_RESULTS_FORMAT, "scenario": "rsa-decrypt-2048-rsaes",
            "config": {"budget": 1, "batch": 1, "repeats": 2, "warmup": 0, "time_limit_s": 1.0, "cpu": null,
                       "max_candidates": 1, "seed_diagnostics": 0, "include_seed_diagnostics": false},
            "backends": ["rust", "reference"], "search_runs": [], "search_evaluations": {},
            "candidates_loaded": 1, "candidates_verified": 1, "adaptive_candidates": 1, "seeded_diagnostics": 0,
            "seeded_diagnostics_reason": null, "stop_reason": "", "results": [split],
        }))
        .unwrap();
        let mut report = build_report_from_parts(vec![VerifySection {
            run_id: "v".into(),
            state: RunState::Completed,
            outcome: VerificationOutcome::Completed,
            legacy_inconsistency: None,
            counts: BTreeMap::new(),
            results,
        }]);
        report.scenarios = scenario_rows(&report);
        let row = &report.scenarios[0];
        // Both backends produced a reproducible signal, but neither is
        // secret-only under its own classification.
        assert_eq!(row.backends["rust"].reproducible_signal, 1);
        assert_eq!(row.backends["reference"].reproducible_signal, 1);
        assert_eq!(row.backends["rust"].reproducible_signal_secret_only, 0);
        assert_eq!(row.backends["reference"].reproducible_signal_secret_only, 0);
        let markdown = render_summary(&report);
        assert!(
            markdown.contains("rust: split (split) — Mixed"),
            "rust finding keeps its own classification: {markdown}"
        );
        assert!(
            markdown.contains("reference: split (split) — OutputSize"),
            "reference finding keeps its own classification: {markdown}"
        );
        assert!(markdown.contains("confounders: implicit rejection lengths"));
    }

    fn check_section(
        run_id: &str,
        state: RunState,
        outcome: VerificationOutcome,
        scenarios: &[&str],
        results: &[(&str, bool)],
    ) -> CheckSection {
        CheckSection {
            run_id: run_id.into(),
            state,
            outcome,
            scenarios: scenarios.iter().map(|s| s.to_string()).collect(),
            results: results
                .iter()
                .map(|(scenario, ok)| CheckResultRow {
                    functional_checked: true,
                    skipped: BTreeMap::new(),
                    scenario: (*scenario).into(),
                    seed: "boundary".into(),
                    ok: *ok,
                })
                .collect(),
        }
    }

    #[test]
    fn a_shared_check_failure_stays_with_the_scenario_that_failed() {
        let mut report = build_report_from_parts(Vec::new());
        report.checks = vec![check_section(
            "check-run",
            RunState::Failed,
            VerificationOutcome::Failed,
            &["ecdh-p256", "mac-hmac-sha256"],
            &[("ecdh-p256", false), ("mac-hmac-sha256", true)],
        )];
        report.run_scenarios = vec![
            (
                vec!["ecdh-p256".into(), "mac-hmac-sha256".into()],
                run_entry(
                    "check",
                    VerificationOutcome::Failed,
                    "1 of 2 scenarios failed",
                ),
            ),
            (
                vec!["mac-hmac-sha256".into()],
                run_entry("verify", VerificationOutcome::Completed, "ok"),
            ),
        ];
        report.scenarios = scenario_rows(&report);
        let find = |report: &Report, name: &str| {
            report
                .scenarios
                .iter()
                .find(|r| r.scenario == name)
                .cloned()
                .unwrap_or_else(|| panic!("{name} missing"))
        };
        let ecdh = find(&report, "ecdh-p256");
        let mac = find(&report, "mac-hmac-sha256");
        assert_eq!(ecdh.functional_check, Some(false));
        assert_eq!(ecdh.outcome, Some(VerificationOutcome::Failed));
        assert_eq!(mac.functional_check, Some(true));
        assert_eq!(mac.outcome, Some(VerificationOutcome::Completed));
        assert!(mac.problems.is_empty());
        assert_eq!(mac.runs.len(), 2);
        let markdown = render_summary(&report);
        assert!(markdown.contains("functional check failed in run `check-run`"));

        report.run_scenarios.push((
            vec!["mac-hmac-sha256".into()],
            run_entry("replay", VerificationOutcome::Failed, "replay mismatch"),
        ));
        report.scenarios = scenario_rows(&report);
        let mac = find(&report, "mac-hmac-sha256");
        assert_eq!(mac.outcome, Some(VerificationOutcome::Failed));
        assert_eq!(mac.functional_check, Some(true));
    }

    #[test]
    fn scenarios_without_check_evidence_never_look_successful() {
        let mut report = build_report_from_parts(Vec::new());
        report.checks = vec![check_section(
            "interrupted-check",
            RunState::Incomplete,
            VerificationOutcome::Incomplete,
            &["ecdh-p256", "mac-hmac-sha256", "drbg-getrandom"],
            &[("ecdh-p256", true)],
        )];
        report.run_scenarios = vec![(
            vec![
                "ecdh-p256".into(),
                "mac-hmac-sha256".into(),
                "drbg-getrandom".into(),
            ],
            run_entry("check", VerificationOutcome::Incomplete, "interrupted"),
        )];
        report.scenarios = scenario_rows(&report);
        let find = |name: &str| {
            report
                .scenarios
                .iter()
                .find(|r| r.scenario == name)
                .unwrap_or_else(|| panic!("{name} missing"))
        };
        assert_eq!(find("ecdh-p256").functional_check, Some(true));
        assert_eq!(find("ecdh-p256").outcome, None);
        for name in ["mac-hmac-sha256", "drbg-getrandom"] {
            assert_eq!(find(name).functional_check, None, "{name}");
            assert_eq!(
                find(name).outcome,
                Some(VerificationOutcome::Incomplete),
                "{name}"
            );
            assert!(
                find(name).problems[0].contains("no functional result"),
                "{}",
                find(name).problems[0]
            );
        }
        let markdown = render_summary(&report);
        assert!(markdown.contains("recorded no functional result for this scenario"));
    }

    fn report_with(
        verifications: Vec<VerifySection>,
        runs: Vec<(Vec<String>, RunOutcomeEntry)>,
    ) -> Report {
        let mut report = build_report_from_parts(verifications);
        report.run_scenarios = runs;
        report
    }

    fn run_entry(command: &str, outcome: VerificationOutcome, reason: &str) -> RunOutcomeEntry {
        RunOutcomeEntry {
            run_id: format!("{command}-run"),
            command: command.into(),
            state: match outcome {
                VerificationOutcome::Completed => RunState::Completed,
                VerificationOutcome::Incomplete => RunState::Incomplete,
                VerificationOutcome::Failed => RunState::Failed,
            },
            outcome,
            reason: Some(reason.into()),
        }
    }

    #[test]
    fn every_stage_feeds_its_scenario_outcome() {
        let mut report = report_with(
            Vec::new(),
            vec![
                (
                    vec!["ecdh-p256".into()],
                    run_entry("check", VerificationOutcome::Completed, "ok"),
                ),
                (
                    vec!["ecdh-p256".into()],
                    run_entry("search", VerificationOutcome::Failed, "worker crashed"),
                ),
                (
                    vec!["mac-hmac-sha256".into()],
                    run_entry("verify", VerificationOutcome::Completed, "ok"),
                ),
                (
                    vec!["mac-hmac-sha256".into()],
                    run_entry("replay", VerificationOutcome::Failed, "replay mismatch"),
                ),
                (
                    vec!["drbg-getrandom".into()],
                    run_entry("search", VerificationOutcome::Incomplete, "interrupted"),
                ),
                (
                    vec!["sym-aes128-cbc-encrypt".into()],
                    run_entry("verify", VerificationOutcome::Completed, "ok"),
                ),
            ],
        );
        report.scenarios = scenario_rows(&report);
        let row = |name: &str| {
            report
                .scenarios
                .iter()
                .find(|r| r.scenario == name)
                .unwrap_or_else(|| panic!("{name} missing"))
        };
        assert_eq!(row("ecdh-p256").outcome, Some(VerificationOutcome::Failed));
        assert_eq!(
            row("mac-hmac-sha256").outcome,
            Some(VerificationOutcome::Failed)
        );
        assert_eq!(
            row("drbg-getrandom").outcome,
            Some(VerificationOutcome::Incomplete)
        );
        assert_eq!(
            row("sym-aes128-cbc-encrypt").outcome,
            Some(VerificationOutcome::Completed)
        );
        assert_eq!(row("ecdh-p256").runs.len(), 2);
        let markdown = render_summary(&report);
        assert!(
            markdown.contains("search run `search-run` ended as Failed"),
            "{markdown}"
        );
        assert!(markdown.contains("replay run `replay-run` ended as Failed"));
        assert!(markdown.contains("search run `search-run` ended as Incomplete"));
        assert!(markdown.contains("check:Completed, search:Failed"));
    }

    fn build_report_from_parts(verifications: Vec<VerifySection>) -> Report {
        Report {
            format: REPORT_FORMAT.into(),
            generated_utc: String::new(),
            runs: Vec::new(),
            searches: Vec::new(),
            verifications,
            self_tests: Vec::new(),
            replays: Vec::new(),
            checks: Vec::new(),
            scenarios: Vec::new(),
            overall_counts: BTreeMap::new(),
            overall_outcome: None,
            overall_verification_outcome: None,
            run_outcomes: Vec::new(),
            run_scenarios: Vec::new(),
            verifications_without_results: Vec::new(),
            notes: Vec::new(),
        }
    }
}
