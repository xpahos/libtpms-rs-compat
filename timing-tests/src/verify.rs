use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::artifacts::{display_label, is_plain_label};
use crate::measure::{LoadOrder, Measurer, WorkerMeasurer};
use crate::scenario::{InputPair, PreparedPair, Scenario, diagnostic_order, scenario_seeds};
use crate::search::{CandidateFile, CandidateKind, Provenance, seeded_candidate};
use crate::tpm;
use crate::worker::{BackendSpec, DudectOutcome, DudectPlan, DudectStatus, Limits, run_dudect};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyConfig {
    #[serde(default, alias = "include_known_cases")]
    pub disable_known_case_skips: bool,
    pub budget: usize,
    pub batch: usize,
    pub repeats: usize,
    pub warmup: usize,
    pub time_limit_s: f64,
    pub cpu: Option<usize>,
    pub max_candidates: usize,
    pub seed_diagnostics: usize,
    pub include_seed_diagnostics: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunVerdict {
    Signal,
    NoSignal,
    Incomplete,
    Failure,
}

pub fn run_verdict(status: &DudectStatus) -> RunVerdict {
    match status {
        DudectStatus::LeakageFound => RunVerdict::Signal,
        DudectStatus::BudgetExhausted => RunVerdict::NoSignal,
        DudectStatus::InsufficientMeasurements
        | DudectStatus::TimeLimit
        | DudectStatus::Interrupted
        | DudectStatus::WorkerTimeout => RunVerdict::Incomplete,
        DudectStatus::FunctionalFailure
        | DudectStatus::SetupFailure
        | DudectStatus::NvStoreDuringMeasurement
        | DudectStatus::WorkerCrashed
        | DudectStatus::MalformedOutput => RunVerdict::Failure,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BackendVerdict {
    SkippedKnownIssue,
    ReproducibleSignal,
    NoSignalWithinBudget,
    Inconclusive,
    Failure,
}

pub fn backend_verdict(runs: &[RunVerdict], required_repeats: usize) -> BackendVerdict {
    if runs.contains(&RunVerdict::Failure) {
        return BackendVerdict::Failure;
    }
    if runs.len() < required_repeats.max(2) {
        return BackendVerdict::Inconclusive;
    }
    if runs.iter().all(|r| *r == RunVerdict::Signal) {
        return BackendVerdict::ReproducibleSignal;
    }
    if runs.iter().all(|r| *r == RunVerdict::NoSignal) {
        return BackendVerdict::NoSignalWithinBudget;
    }
    BackendVerdict::Inconclusive
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    KnownIssueSkipped,
    ReproducibleSignalBoth,
    ReproducibleSignalRustOnly,
    ReproducibleSignalReferenceOnly,
    NoSignalDetectedWithinBudget,
    InconclusiveOrIncomplete,
    InfrastructureOrFunctionalFailure,
    SingleBackendReproducibleSignal,
    SingleBackendNoSignalWithinBudget,
}

impl Category {
    pub fn describe(self) -> &'static str {
        match self {
            Self::KnownIssueSkipped => "SKIP known issue (see per-backend results)",
            Self::ReproducibleSignalBoth => "reproducible timing signal in both backends",
            Self::ReproducibleSignalRustOnly => "reproducible signal in the Rust library only",
            Self::ReproducibleSignalReferenceOnly => {
                "reproducible signal in the reference library only"
            }
            Self::NoSignalDetectedWithinBudget => {
                "no signal detected within the stated budget (not a constant-time claim)"
            }
            Self::InconclusiveOrIncomplete => "inconclusive or incomplete verification",
            Self::InfrastructureOrFunctionalFailure => "infrastructure or functional failure",
            Self::SingleBackendReproducibleSignal => {
                "reproducible signal (only one backend verified)"
            }
            Self::SingleBackendNoSignalWithinBudget => {
                "no signal within budget (only one backend verified)"
            }
        }
    }
}

pub fn categorize(verdicts: &BTreeMap<String, BackendVerdict>, functional_ok: bool) -> Category {
    if !functional_ok
        || verdicts.values().any(|v| *v == BackendVerdict::Failure)
        || verdicts.is_empty()
    {
        return Category::InfrastructureOrFunctionalFailure;
    }
    if verdicts
        .values()
        .any(|v| *v == BackendVerdict::SkippedKnownIssue)
    {
        let measured = verdicts
            .iter()
            .filter(|(_, v)| **v != BackendVerdict::SkippedKnownIssue)
            .map(|(backend, verdict)| (backend.clone(), *verdict))
            .collect::<BTreeMap<_, _>>();
        return if measured.is_empty() {
            Category::KnownIssueSkipped
        } else {
            categorize(&measured, functional_ok)
        };
    }
    let rust = verdicts.get("rust").copied();
    let reference = verdicts.get("reference").copied();
    use BackendVerdict::*;
    match (rust, reference) {
        (Some(ReproducibleSignal), Some(ReproducibleSignal)) => Category::ReproducibleSignalBoth,
        (Some(ReproducibleSignal), Some(NoSignalWithinBudget)) => {
            Category::ReproducibleSignalRustOnly
        }
        (Some(NoSignalWithinBudget), Some(ReproducibleSignal)) => {
            Category::ReproducibleSignalReferenceOnly
        }
        (Some(NoSignalWithinBudget), Some(NoSignalWithinBudget)) => {
            Category::NoSignalDetectedWithinBudget
        }
        (Some(_), Some(_)) => Category::InconclusiveOrIncomplete,
        _ => {
            let only = *verdicts.values().next().unwrap();
            match only {
                ReproducibleSignal if verdicts.len() == 1 => {
                    Category::SingleBackendReproducibleSignal
                }
                NoSignalWithinBudget if verdicts.len() == 1 => {
                    Category::SingleBackendNoSignalWithinBudget
                }
                _ => Category::InconclusiveOrIncomplete,
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRecord {
    pub repeat: usize,
    pub backend: String,
    pub load_order: LoadOrder,
    pub directory: PathBuf,
    pub status: DudectStatus,
    pub verdict: RunVerdict,
    pub measurements: u64,
    pub batches: u64,
    pub final_max_t: Option<f64>,
    pub final_max_tau: Option<f64>,
    pub dudect_verdict_text: Option<String>,
    pub session: Option<String>,
    pub elapsed_s: f64,
    pub detail: String,
}

impl RunRecord {
    pub fn from_outcome(
        repeat: usize,
        backend: &str,
        load_order: LoadOrder,
        directory: &Path,
        outcome: &DudectOutcome,
    ) -> Self {
        Self {
            repeat,
            backend: backend.into(),
            load_order,
            directory: directory.to_path_buf(),
            verdict: run_verdict(&outcome.status),
            status: outcome.status.clone(),
            measurements: outcome.measurements,
            batches: outcome.batches,
            final_max_t: outcome.last_report.as_ref().and_then(|r| r.max_t),
            final_max_tau: outcome.last_report.as_ref().and_then(|r| r.max_tau),
            dudect_verdict_text: outcome.last_report.as_ref().map(|r| r.verdict.clone()),
            session: outcome.info.get("session").cloned(),
            elapsed_s: outcome.elapsed_s,
            detail: outcome.detail.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionalCheck {
    #[serde(default)]
    pub validations: Vec<crate::measure::ValidationRecord>,
    #[serde(default)]
    pub worker_info: crate::worker::WorkerInfo,
    pub backend: String,
    pub ok: bool,
    pub detail: String,
    pub responses: Vec<String>,
    /// True when the failure came from backend expectation resolution (for example a
    /// failed or inconsistent RSAES capability probe), not from the measured response.
    #[serde(default)]
    pub backend_failure: bool,
    /// Resolved backend evidence recorded as provenance whenever the backend probed
    /// an RSAES contract for this check.
    #[serde(default)]
    pub rsaes_evidence: Option<crate::expectation::RsaesEvidence>,
}

/// A functional check together with the per-backend prepared pair it validated against.
/// The prepared pair carries the backend-resolved expectations that the caller must use
/// for any further measurement of this candidate on this backend.
pub struct PreparedCheck {
    pub check: FunctionalCheck,
    pub prepared: Result<PreparedPair, String>,
}

type ProbeOutcome = Result<
    (
        PreparedPair,
        [Vec<u8>; 2],
        Vec<crate::measure::ValidationRecord>,
    ),
    (bool, String),
>;

#[allow(clippy::too_many_arguments)]
pub fn functional_check_prepared(
    worker: &Path,
    backend: &BackendSpec,
    pair: impl Into<InputPair>,
    scenario: Scenario,
    stderr: &Path,
    limits: Limits,
) -> PreparedCheck {
    let label = backend.label();
    let pair = pair.into();
    let mut worker_info = crate::worker::WorkerInfo::new();
    let mut rsaes_evidence = None;
    let result = (|| -> ProbeOutcome {
        let mut measurer = WorkerMeasurer::start(worker, backend.clone(), None, stderr, limits)
            .map_err(|e| (true, e.to_string()))?;
        worker_info = measurer.info();
        let prepared = measurer.prepare(scenario, pair.clone()).map_err(|e| {
            (
                matches!(e, crate::measure::PrepareFailure::Backend(_)),
                e.to_string(),
            )
        })?;
        rsaes_evidence = prepared.metadata.rsaes_evidence.clone();
        let loaded = measurer
            .load(&prepared, LoadOrder::ClassAFirst)
            .map_err(|e| (false, e.to_string()))?;
        let responses = measurer.execute_once(&loaded);
        let validations = measurer.validation_records();
        let responses = responses.map_err(|e| (false, e.to_string()))?;
        measurer
            .close_checked()
            .map_err(|e| (false, e.to_string()))?;
        Ok((prepared, responses, validations))
    })();
    match result {
        Ok((prepared, responses, validations)) => {
            let failures: Vec<String> = (0..2)
                .filter_map(|c| {
                    prepared.classes[c]
                        .validate(&responses[c])
                        .err()
                        .map(|e| format!("class {c}: {e}"))
                })
                .collect();
            let mut check = FunctionalCheck {
                validations,
                worker_info,
                backend: label,
                ok: failures.is_empty(),
                detail: if failures.is_empty() {
                    "both classes matched the independently derived response (masked fields verified independently where randomized)".into()
                } else {
                    failures.join("; ")
                },
                responses: (0..2)
                    .map(|c| hex::encode(prepared.classes[c].masked(&responses[c])))
                    .collect(),
                backend_failure: false,
                rsaes_evidence,
            };
            if !check.ok {
                check.detail = format!("functional failure: {}", check.detail);
            }
            PreparedCheck {
                check,
                prepared: Ok(prepared),
            }
        }
        Err((backend_failure, detail)) => PreparedCheck {
            check: FunctionalCheck {
                validations: Vec::new(),
                worker_info,
                backend: label,
                ok: false,
                detail: if backend_failure {
                    format!("backend/infrastructure failure: {detail}")
                } else {
                    detail.clone()
                },
                responses: Vec::new(),
                backend_failure,
                rsaes_evidence,
            },
            prepared: Err(detail),
        },
    }
}

pub fn functional_check(
    worker: &Path,
    backend: &BackendSpec,
    pair: impl Into<InputPair>,
    scenario: Scenario,
    stderr: &Path,
    limits: Limits,
) -> FunctionalCheck {
    functional_check_prepared(worker, backend, pair, scenario, stderr, limits).check
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VerificationOutcome {
    Completed,
    #[default]
    Incomplete,
    Failed,
}

impl VerificationOutcome {
    pub fn exit_code(self) -> u8 {
        match self {
            Self::Completed => 0,
            Self::Incomplete => 3,
            Self::Failed => 4,
        }
    }

    pub fn worst(self, other: Self) -> Self {
        self.max(other)
    }
}

pub const OUTCOME_CONTRACT: &str = "completed (exit 0): every requested candidate was processed; each backend has a definite timing result or an explicit known-case SKIP (not a no-signal result); incomplete (exit 3): any candidate is inconclusive, has insufficient measurements, a time limit, an interruption, missing or mixed repeats, or not all candidates were processed; failed (exit 4): any functional or infrastructure failure, which takes precedence over incompleteness. A reproducible timing signal is a completed experiment, not a failure.";

pub fn candidate_outcome(category: Category) -> VerificationOutcome {
    match category {
        Category::KnownIssueSkipped
        | Category::ReproducibleSignalBoth
        | Category::ReproducibleSignalRustOnly
        | Category::ReproducibleSignalReferenceOnly
        | Category::NoSignalDetectedWithinBudget
        | Category::SingleBackendReproducibleSignal
        | Category::SingleBackendNoSignalWithinBudget => VerificationOutcome::Completed,
        Category::InconclusiveOrIncomplete => VerificationOutcome::Incomplete,
        Category::InfrastructureOrFunctionalFailure => VerificationOutcome::Failed,
    }
}

pub fn aggregate_outcome(
    results: &[CandidateResult],
    requested: usize,
    fatal: Option<&str>,
) -> (VerificationOutcome, String) {
    let mut outcome = VerificationOutcome::Completed;
    let mut reasons = Vec::new();
    for result in results {
        let candidate = candidate_outcome(result.category);
        if candidate != VerificationOutcome::Completed {
            reasons.push(format!(
                "{} ({}): {}",
                result.artifact,
                display_label(&result.id),
                result.category.describe()
            ));
        }
        outcome = outcome.worst(candidate);
    }
    if results.len() < requested {
        outcome = outcome.worst(VerificationOutcome::Incomplete);
        reasons.push(format!(
            "only {} of {requested} requested candidates were verified",
            results.len()
        ));
    }
    if let Some(fatal) = fatal {
        outcome = VerificationOutcome::Failed;
        reasons.push(format!("verification aborted: {fatal}"));
    }
    if requested == 0 {
        outcome = outcome.worst(VerificationOutcome::Incomplete);
        reasons.push("no candidate was available to verify".into());
    }
    let detail = if reasons.is_empty() {
        format!(
            "all {requested} candidates processed with a definite result or explicit known-case SKIP"
        )
    } else {
        reasons.join("; ")
    };
    (outcome, detail)
}

/// The classification metadata of one backend's own expectations:
/// difference kind, public differences and confounders exactly as validated on
/// that backend, never a different backend's view of the same pair.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BackendClassification {
    #[serde(default)]
    pub difference: Option<crate::scenario::DifferenceKind>,
    #[serde(default)]
    pub public_differences: Vec<String>,
    #[serde(default)]
    pub confounders: Vec<String>,
    /// Backend-resolved capability evidence (RSAES profile and CFB chaining
    /// contracts) as freshly probed while validating this classification.
    #[serde(default)]
    pub rsaes_evidence: Option<crate::expectation::RsaesEvidence>,
    #[serde(default)]
    pub sym_evidence: Option<crate::expectation::SymChainingEvidence>,
}

/// Agreement for the combined statement covers the classification triple only;
/// the evidence fields identify the backend build and are never compared.
impl PartialEq for BackendClassification {
    fn eq(&self, other: &Self) -> bool {
        self.difference == other.difference
            && self.public_differences == other.public_differences
            && self.confounders == other.confounders
    }
}
impl Eq for BackendClassification {}

impl BackendClassification {
    pub fn of(metadata: &crate::scenario::PublicMetadata) -> Self {
        Self {
            difference: Some(metadata.difference),
            public_differences: metadata.public_differences.clone(),
            confounders: metadata.confounders.clone(),
            rsaes_evidence: metadata.rsaes_evidence.clone(),
            sym_evidence: metadata.sym_evidence.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateResult {
    /// Per-backend validated classification, public differences and confounders;
    /// a combined result must never silently borrow one backend's view.
    #[serde(default)]
    pub per_backend: BTreeMap<String, BackendClassification>,
    #[serde(default)]
    pub skipped: BTreeMap<String, crate::known_issues::KnownIssue>,
    #[serde(default)]
    pub artifact: String,
    #[serde(default)]
    pub content_sha256: String,
    #[serde(default)]
    pub candidate_file: PathBuf,
    #[serde(default)]
    pub provenance: Vec<Provenance>,
    #[serde(default)]
    pub outcome: VerificationOutcome,
    pub id: String,
    pub kind: CandidateKind,
    pub search_backend: Option<String>,
    pub search_score: Option<f64>,
    pub retention_reason: String,
    pub functional: Vec<FunctionalCheck>,
    pub cross_backend_identical: Option<bool>,
    /// True when every backend resolved an independently validated RSAES contract and the
    /// resolved contracts differ: nonidentical cross-backend responses are then the
    /// expected, visible outcome and not a functional failure.
    #[serde(default)]
    pub cross_backend_expected_divergence: bool,
    pub runs: Vec<RunRecord>,
    pub verdicts: BTreeMap<String, BackendVerdict>,
    pub category: Category,
    #[serde(default)]
    pub difference: Option<crate::scenario::DifferenceKind>,
    #[serde(default)]
    pub public_differences: Vec<String>,
    #[serde(default)]
    pub confounders: Vec<String>,
    #[serde(default)]
    pub control_check: Option<String>,
}

impl CandidateResult {
    /// (difference kind, public differences, confounders) for a finding on one
    /// backend: the classification actually validated on that backend; legacy
    /// results without per-backend records fall back to the top-level fields.
    pub fn finding_context(
        &self,
        backend: &str,
    ) -> (crate::scenario::DifferenceKind, Vec<String>, Vec<String>) {
        match self.per_backend.get(backend) {
            Some(classification) => (
                classification.difference.unwrap_or_default(),
                classification.public_differences.clone(),
                classification.confounders.clone(),
            ),
            None => (
                self.difference.unwrap_or_default(),
                self.public_differences.clone(),
                self.confounders.clone(),
            ),
        }
    }
}

pub fn apply_control_expectation(scenario: Scenario, result: &mut CandidateResult) {
    let measured: Vec<(&String, &BackendVerdict)> = result
        .verdicts
        .iter()
        .filter(|(_, v)| **v != BackendVerdict::SkippedKnownIssue)
        .collect();
    let problem = match scenario {
        Scenario::TpmControlPositive => measured
            .iter()
            .find(|(_, v)| **v == BackendVerdict::NoSignalWithinBudget)
            .map(|(b, _)| format!("positive control not detected on {b} within the budget: the command-level pipeline did not show its sensitivity")),
        Scenario::TpmControlNegative => measured
            .iter()
            .find(|(_, v)| **v == BackendVerdict::ReproducibleSignal)
            .map(|(b, _)| format!("negative control produced a reproducible signal on {b}: identical commands must not differ")),
        _ => None,
    };
    if let Some(problem) = problem {
        result.control_check = Some(problem);
        result.category = Category::InfrastructureOrFunctionalFailure;
        result.outcome = VerificationOutcome::Failed;
    } else if scenario.is_tpm_control() {
        result.control_check = Some("control expectation met or not yet decidable".into());
    }
}

pub fn functional_ok(result: &CandidateResult) -> bool {
    result.functional.iter().all(|f| f.ok)
        && (result.cross_backend_expected_divergence
            || result.cross_backend_identical != Some(false))
}

pub fn classify(result: &mut CandidateResult, repeats: usize) {
    let mut by_backend: BTreeMap<String, Vec<RunVerdict>> = BTreeMap::new();
    for run in &result.runs {
        by_backend
            .entry(run.backend.clone())
            .or_default()
            .push(run.verdict);
    }
    for check in &result.functional {
        by_backend.entry(check.backend.clone()).or_default();
    }
    result.verdicts = by_backend
        .into_iter()
        .map(|(backend, runs)| (backend, backend_verdict(&runs, repeats)))
        .collect();
    for backend in result.skipped.keys() {
        result
            .verdicts
            .insert(backend.clone(), BackendVerdict::SkippedKnownIssue);
    }
    result.category = categorize(&result.verdicts, functional_ok(result));
    result.outcome = candidate_outcome(result.category);
}

pub fn load_candidates(
    search_runs: &[PathBuf],
    files: &[PathBuf],
) -> Result<(Vec<CandidateFile>, Vec<u64>), String> {
    let mut out = Vec::new();
    let mut seeds = Vec::new();
    for run in search_runs {
        let config: serde_json::Value = serde_json::from_slice(
            &fs::read(run.join("config.json")).map_err(|e| format!("{}: {e}", run.display()))?,
        )
        .map_err(|e| format!("malformed {}/config.json: {e}", run.display()))?;
        if let Some(seed) = config.pointer("/search/seed").and_then(|v| v.as_u64()) {
            seeds.push(seed);
        }
        let search = run.join("search");
        let backends = fs::read_dir(&search).map_err(|e| format!("{}: {e}", search.display()))?;
        for backend in backends {
            let backend_dir = backend.map_err(|e| e.to_string())?.path();
            for sub in ["candidates", "seed-signals"] {
                let dir = backend_dir.join(sub);
                if !dir.is_dir() {
                    continue;
                }
                let mut entries: Vec<PathBuf> = fs::read_dir(&dir)
                    .map_err(|e| e.to_string())?
                    .filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| p.extension().is_some_and(|x| x == "json"))
                    .collect();
                entries.sort();
                for path in entries {
                    out.push(CandidateFile::load(&path)?);
                }
            }
        }
    }
    for file in files {
        out.push(CandidateFile::load(file)?);
    }
    Ok((out, seeds))
}

pub fn union_candidates(
    candidates: Vec<CandidateFile>,
    limit: usize,
) -> Result<(Vec<CandidateFile>, usize), String> {
    let score = |c: &CandidateFile| {
        c.search_score
            .as_ref()
            .map(|s| s.ranking_value())
            .unwrap_or(0.0)
    };
    let mut ordered = candidates;
    ordered.sort_by(|a, b| {
        score(b)
            .partial_cmp(&score(a))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let mut unique: Vec<CandidateFile> = Vec::new();
    let mut index: BTreeMap<String, usize> = BTreeMap::new();
    for candidate in ordered {
        candidate.validate()?;
        let stem = candidate.artifact_stem()?;
        match index.get(&stem) {
            Some(position) => unique[*position].merge(&candidate)?,
            None => {
                index.insert(stem, unique.len());
                let mut primary = candidate.clone();
                if primary.provenance.is_empty() {
                    primary.provenance.push(candidate.own_provenance(None));
                }
                unique.push(primary);
            }
        }
    }
    let total = unique.len();
    unique.truncate(limit);
    Ok((unique, total))
}

pub type ArtifactNaming = fn(&CandidateFile) -> Result<String, String>;

pub fn content_naming(candidate: &CandidateFile) -> Result<String, String> {
    candidate.artifact_stem()
}

pub fn legacy_label_naming(candidate: &CandidateFile) -> Result<String, String> {
    Ok(candidate.id.clone())
}

pub fn artifact_names(
    candidates: &[CandidateFile],
    naming: ArtifactNaming,
) -> Result<Vec<String>, String> {
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    let mut names = Vec::new();
    for candidate in candidates {
        let name = naming(candidate)?;
        if !is_plain_label(&name) {
            return Err(format!(
                "artifact name {name:?} for candidate {} is not a plain file name",
                display_label(&candidate.id)
            ));
        }
        let content = candidate.content_sha256()?;
        if let Some(previous) = seen.insert(name.clone(), content.clone()) {
            return Err(format!(
                "artifact collision: candidates with content {previous} and {content} both map to {name:?}; nothing was written"
            ));
        }
        names.push(name);
    }
    Ok(names)
}

pub fn save_candidates(
    dir: &Path,
    candidates: &[CandidateFile],
    naming: ArtifactNaming,
) -> Result<Vec<(String, PathBuf)>, String> {
    let names = artifact_names(candidates, naming)?;
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    for name in &names {
        let path = dir.join(format!("{name}.json"));
        if path.exists() {
            return Err(format!(
                "artifact collision: {} already exists; nothing was written",
                path.display()
            ));
        }
    }
    let mut saved = Vec::new();
    for (candidate, name) in candidates.iter().zip(names) {
        let path = dir.join(format!("{name}.json"));
        candidate.save(&path).map_err(|e| e.to_string())?;
        saved.push((name, path));
    }
    Ok(saved)
}

pub fn diagnostic_seeds(
    scenario: Scenario,
    campaign_seed: u64,
    count: usize,
) -> Vec<CandidateFile> {
    let seeds = scenario_seeds(scenario, campaign_seed, 0);
    diagnostic_order(scenario)
        .iter()
        .filter_map(|name| seeds.iter().find(|s| s.name == *name))
        .take(count)
        .map(|seed| seeded_candidate(scenario, &seed.name, seed.pair.clone(), campaign_seed))
        .collect()
}

pub fn dudect_plan(
    backend: &BackendSpec,
    prepared: &PreparedPair,
    order: LoadOrder,
    config: &VerifyConfig,
) -> DudectPlan {
    let resolved = prepared.resolve(order);
    let setup = if prepared.has_tpm_state() {
        let mut setup = vec![tpm::startup_clear()];
        setup.extend(resolved.setup.iter().map(|s| s.command.clone()));
        setup
    } else {
        Vec::new()
    };
    let offset = usize::from(prepared.has_tpm_state());
    let mut setup_patches = vec![Vec::new(); offset];
    setup_patches.extend(resolved.setup.iter().map(|step| {
        step.patches
            .iter()
            .cloned()
            .map(|mut patch| {
                patch.setup_index += offset;
                patch
            })
            .collect()
    }));
    let patches = resolved.patches.clone().map(|list| {
        list.into_iter()
            .map(|mut p| {
                p.setup_index += offset;
                p
            })
            .collect()
    });
    DudectPlan {
        backend: backend.clone(),
        cpu: config.cpu,
        setup,
        setup_patches,
        class_commands: resolved.measured,
        expected: [
            prepared.classes[0].expected_response.clone(),
            prepared.classes[1].expected_response.clone(),
        ],
        masks: [
            prepared.classes[0].mask.clone(),
            prepared.classes[1].mask.clone(),
        ],
        posts: resolved.post,
        patches,
        warmup: config.warmup,
        batch: config.batch,
        budget: config.budget,
        time_limit_s: config.time_limit_s,
    }
}

pub fn session_is_fresh(
    session: Option<&str>,
    forbidden: &BTreeSet<String>,
    seen: &mut BTreeSet<String>,
) -> bool {
    match session {
        Some(session) => !forbidden.contains(session) && seen.insert(session.to_string()),
        None => false,
    }
}

pub struct VerifyTarget {
    pub spec: BackendSpec,
}

pub struct CandidateArtifact<'a> {
    pub candidate: &'a CandidateFile,
    pub name: &'a str,
    pub file: &'a Path,
}

#[allow(clippy::too_many_arguments)]
pub fn verify_candidate(
    worker: &Path,
    artifact: CandidateArtifact<'_>,
    targets: &[VerifyTarget],
    config: &VerifyConfig,
    dir: &Path,
    forbidden_sessions: &BTreeSet<String>,
    limits: Limits,
    progress: &mut dyn FnMut(&str),
) -> Result<CandidateResult, String> {
    let candidate = artifact.candidate;
    let pair = candidate.inputs()?;
    crate::artifacts::create_new_dir(dir).map_err(|e| e.to_string())?;
    // The pair must be reconstructible offline at all; the actual expectations
    // used below are resolved per backend by fresh probes, never by this pass.
    PreparedPair::try_prepare(candidate.scenario, pair.clone())?;
    let mut functional = Vec::new();
    let mut skipped = BTreeMap::new();
    let mut prepared_by_backend: BTreeMap<String, PreparedPair> = BTreeMap::new();
    for target in targets {
        if !config.disable_known_case_skips
            && let Some(issue) =
                crate::known_issues::functional_skip(candidate.scenario, &target.spec.label())
        {
            progress(&format!(
                "SKIP {} {} {}: {}",
                artifact.name,
                target.spec.label(),
                issue.id,
                issue.reason
            ));
            skipped.insert(target.spec.label(), issue);
            continue; // Do not fabricate a successful FunctionalCheck for an unexecuted command.
        }
        let label = target.spec.label();
        let outcome = functional_check_prepared(
            worker,
            &target.spec,
            pair.clone(),
            candidate.scenario,
            &dir.join(format!("functional-{}-stderr.log", label)),
            limits,
        );
        let check = outcome.check;
        if check.backend_failure {
            // A backend that could not resolve an independently validated contract is a
            // failure of the measurement infrastructure, not of this candidate input.
            progress(&format!(
                "backend failure {} on {}: {}",
                artifact.name, label, check.detail
            ));
            functional.push(check);
            continue;
        }
        if let Ok(prepared) = &outcome.prepared {
            prepared_by_backend.insert(label.clone(), prepared.clone());
        }
        progress(&format!(
            "functional check {} on {}: {}",
            artifact.name,
            label,
            if check.ok { "ok" } else { "FAILED" }
        ));
        if check.ok
            && !config.disable_known_case_skips
            && let Some(issue) = crate::known_issues::timing_skip(
                candidate.scenario,
                &pair,
                &target.spec.label(),
                &check.worker_info,
            )
        {
            progress(&format!(
                "SKIP {} {} {}: {}",
                artifact.name, label, issue.id, issue.reason
            ));
            skipped.insert(label, issue);
        }
        functional.push(check);
    }
    let cross = if functional.len() > 1 && functional.iter().all(|f| f.ok) {
        Some(
            functional
                .windows(2)
                .all(|w| w[0].responses == w[1].responses),
        )
    } else {
        None
    };
    // Only malformed RSAES padding with independently validated, different contracts on
    // every backend may legitimately answer the same pair differently.
    let prepared_metadata: Vec<&crate::scenario::PublicMetadata> =
        prepared_by_backend.values().map(|p| &p.metadata).collect();
    let expected_divergence =
        crate::expectation::expected_divergence(candidate.scenario, &prepared_metadata);
    let per_backend: BTreeMap<String, BackendClassification> = prepared_by_backend
        .iter()
        .map(|(backend, prepared)| {
            (
                backend.clone(),
                BackendClassification::of(&prepared.metadata),
            )
        })
        .collect();
    // The top-level classification is a combined statement only when every
    // backend's own validated classification agrees; a disagreement must stay
    // visible per backend instead of silently borrowing one backend's view.
    let agreed: Option<BackendClassification> = {
        let mut iter = per_backend.values();
        let first = iter.next();
        first
            .filter(|first| iter.all(|rest| rest == *first))
            .cloned()
    };
    let (difference, public_differences, confounders) = match agreed {
        Some(classification) => (
            classification.difference,
            classification.public_differences.clone(),
            classification.confounders.clone(),
        ),
        None => (None, Vec::new(), Vec::new()),
    };
    let mut result = CandidateResult {
        per_backend,
        skipped,
        artifact: artifact.name.to_string(),
        content_sha256: candidate.content_sha256()?,
        candidate_file: artifact.file.to_path_buf(),
        provenance: candidate.provenance.clone(),
        outcome: VerificationOutcome::Incomplete,
        id: candidate.id.clone(),
        kind: candidate.kind,
        search_backend: candidate.search_backend.clone(),
        search_score: candidate.search_score.as_ref().map(|s| s.ranking_value()),
        retention_reason: candidate.retention_reason.clone(),
        functional,
        cross_backend_identical: cross,
        cross_backend_expected_divergence: expected_divergence,
        runs: Vec::new(),
        verdicts: BTreeMap::new(),
        category: Category::InconclusiveOrIncomplete,
        difference,
        public_differences,
        confounders,
        control_check: None,
    };
    crate::artifacts::write_new(
        &dir.join("functional.json"),
        &serde_json::to_vec_pretty(&result.functional).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    if functional_ok(&result) {
        let mut sessions = BTreeSet::new();
        'repeats: for repeat in 0..config.repeats {
            let order = LoadOrder::from_bit(repeat % 2 == 1);
            for target in targets {
                let label = target.spec.label();
                if result.skipped.contains_key(&label) {
                    continue;
                }
                let run_dir = dir.join(&label).join(format!("run-{repeat}"));
                let Some(prepared) = prepared_by_backend.get(&label) else {
                    // Every non-skipped target with a passing functional check has a
                    // prepared pair; if it is missing the check never ran or failed.
                    return Err(format!(
                        "{label}: no backend-resolved expectations for a candidate whose functional check passed"
                    ));
                };
                let plan = dudect_plan(&target.spec, prepared, order, config);
                let wall = Duration::from_secs_f64(config.time_limit_s + 120.0);
                let outcome =
                    run_dudect(worker, &plan, &run_dir, wall).map_err(|e| e.to_string())?;
                let mut record = RunRecord::from_outcome(repeat, &label, order, &run_dir, &outcome);
                if record.verdict != RunVerdict::Failure
                    && !session_is_fresh(
                        record.session.as_deref(),
                        forbidden_sessions,
                        &mut sessions,
                    )
                {
                    record.verdict = RunVerdict::Failure;
                    record.detail = format!(
                        "worker session {:?} was missing or reused; fresh measurements are required",
                        record.session
                    );
                }
                progress(&format!(
                    "dudect {} {} repeat {}: {:?} after {} measurements, final max t {:?}",
                    artifact.name,
                    label,
                    repeat,
                    record.status,
                    record.measurements,
                    record.final_max_t
                ));
                let stop = record.status == DudectStatus::Interrupted;
                result.runs.push(record);
                if stop {
                    break 'repeats;
                }
            }
        }
    }
    classify(&mut result, config.repeats);
    apply_control_expectation(candidate.scenario, &mut result);
    crate::artifacts::write_new(
        &dir.join("result.json"),
        &serde_json::to_vec_pretty(&result).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result_with(runs: &[(&str, RunVerdict)], functional_ok: bool) -> CandidateResult {
        let mut result = CandidateResult {
            per_backend: BTreeMap::new(),
            skipped: BTreeMap::new(),
            artifact: "x".into(),
            content_sha256: String::new(),
            candidate_file: PathBuf::new(),
            provenance: Vec::new(),
            outcome: VerificationOutcome::Incomplete,
            id: "x".into(),
            kind: CandidateKind::AdaptiveDiscovery,
            search_backend: None,
            search_score: None,
            retention_reason: String::new(),
            functional: ["rust", "reference"]
                .iter()
                .map(|b| FunctionalCheck {
                    validations: Vec::new(),
                    worker_info: Default::default(),
                    backend: b.to_string(),
                    ok: functional_ok,
                    detail: String::new(),
                    responses: vec![],
                    backend_failure: false,
                    rsaes_evidence: None,
                })
                .collect(),
            cross_backend_identical: Some(true),
            cross_backend_expected_divergence: false,
            runs: runs
                .iter()
                .enumerate()
                .map(|(i, (backend, verdict))| RunRecord {
                    repeat: i,
                    backend: backend.to_string(),
                    load_order: LoadOrder::ClassAFirst,
                    directory: PathBuf::new(),
                    status: DudectStatus::LeakageFound,
                    verdict: *verdict,
                    measurements: 0,
                    batches: 0,
                    final_max_t: None,
                    final_max_tau: None,
                    dudect_verdict_text: None,
                    session: None,
                    elapsed_s: 0.0,
                    detail: String::new(),
                })
                .collect(),
            verdicts: BTreeMap::new(),
            category: Category::InconclusiveOrIncomplete,
            difference: None,
            public_differences: Vec::new(),
            confounders: Vec::new(),
            control_check: None,
        };
        classify(&mut result, 2);
        result
    }

    #[test]
    fn incomplete_runs_are_never_successful_verification() {
        for status in [
            DudectStatus::InsufficientMeasurements,
            DudectStatus::TimeLimit,
            DudectStatus::Interrupted,
            DudectStatus::WorkerTimeout,
        ] {
            assert_eq!(run_verdict(&status), RunVerdict::Incomplete);
        }
        assert_eq!(
            run_verdict(&DudectStatus::BudgetExhausted),
            RunVerdict::NoSignal
        );
        let r = result_with(
            &[
                ("rust", RunVerdict::Signal),
                ("reference", RunVerdict::Incomplete),
                ("rust", RunVerdict::Signal),
                ("reference", RunVerdict::NoSignal),
            ],
            true,
        );
        assert_eq!(r.verdicts["reference"], BackendVerdict::Inconclusive);
        assert_eq!(r.category, Category::InconclusiveOrIncomplete);
    }

    #[test]
    fn a_single_run_is_not_reproducible() {
        let r = result_with(
            &[
                ("rust", RunVerdict::Signal),
                ("reference", RunVerdict::NoSignal),
            ],
            true,
        );
        assert_eq!(r.verdicts["rust"], BackendVerdict::Inconclusive);
        assert_eq!(r.category, Category::InconclusiveOrIncomplete);
    }

    #[test]
    fn categories_follow_per_backend_verdicts() {
        use RunVerdict::*;
        let both = result_with(
            &[
                ("rust", Signal),
                ("reference", Signal),
                ("rust", Signal),
                ("reference", Signal),
            ],
            true,
        );
        assert_eq!(both.category, Category::ReproducibleSignalBoth);
        let rust = result_with(
            &[
                ("rust", Signal),
                ("reference", NoSignal),
                ("rust", Signal),
                ("reference", NoSignal),
            ],
            true,
        );
        assert_eq!(rust.category, Category::ReproducibleSignalRustOnly);
        let reference = result_with(
            &[
                ("rust", NoSignal),
                ("reference", Signal),
                ("rust", NoSignal),
                ("reference", Signal),
            ],
            true,
        );
        assert_eq!(
            reference.category,
            Category::ReproducibleSignalReferenceOnly
        );
        let none = result_with(
            &[
                ("rust", NoSignal),
                ("reference", NoSignal),
                ("rust", NoSignal),
                ("reference", NoSignal),
            ],
            true,
        );
        assert_eq!(none.category, Category::NoSignalDetectedWithinBudget);
        let mixed = result_with(
            &[
                ("rust", Signal),
                ("reference", NoSignal),
                ("rust", NoSignal),
                ("reference", NoSignal),
            ],
            true,
        );
        assert_eq!(mixed.category, Category::InconclusiveOrIncomplete);
    }

    #[test]
    fn functional_failures_and_errors_cannot_become_findings() {
        use RunVerdict::*;
        let failed = result_with(
            &[
                ("rust", Signal),
                ("reference", Signal),
                ("rust", Signal),
                ("reference", Signal),
            ],
            false,
        );
        assert_eq!(failed.category, Category::InfrastructureOrFunctionalFailure);
        let crashed = result_with(
            &[
                ("rust", Signal),
                ("reference", Failure),
                ("rust", Signal),
                ("reference", Signal),
            ],
            true,
        );
        assert_eq!(
            crashed.category,
            Category::InfrastructureOrFunctionalFailure
        );
        for status in [
            DudectStatus::FunctionalFailure,
            DudectStatus::SetupFailure,
            DudectStatus::WorkerCrashed,
            DudectStatus::MalformedOutput,
            DudectStatus::NvStoreDuringMeasurement,
        ] {
            assert_eq!(run_verdict(&status), RunVerdict::Failure);
        }
    }

    #[test]
    fn classifications_are_kept_per_backend_and_never_borrowed() {
        use crate::scenario::DifferenceKind;
        let mut result = result_with(&[], true);
        // Two backends validated different classifications for the same pair
        // (explicit vs implicit RSAES rejection, for example).
        let rust = BackendClassification {
            difference: Some(DifferenceKind::Mixed),
            public_differences: vec!["ciphertext".into()],
            confounders: Vec::new(),
            rsaes_evidence: None,
            sym_evidence: None,
        };
        let reference = BackendClassification {
            difference: Some(DifferenceKind::OutputSize),
            public_differences: vec!["ciphertext".into()],
            confounders: vec!["implicit rejection lengths".into()],
            rsaes_evidence: None,
            sym_evidence: None,
        };
        result.per_backend.insert("rust".into(), rust);
        result.per_backend.insert("reference".into(), reference);
        // The combined result must not silently borrow one backend's view.
        assert_eq!(result.difference, None);
        assert!(result.public_differences.is_empty());
        assert!(result.confounders.is_empty());
        // Each backend reads exactly its own validated classification.
        assert_eq!(result.finding_context("rust").0, DifferenceKind::Mixed);
        assert_eq!(result.finding_context("rust").1, vec!["ciphertext"]);
        assert_eq!(
            result.finding_context("reference").0,
            DifferenceKind::OutputSize
        );
        assert_eq!(
            result.finding_context("reference").2,
            vec!["implicit rejection lengths"]
        );
        // A backend with no per-backend record (legacy result) falls back to
        // the top-level fields.
        let (kind, _, _) = result.finding_context("other");
        assert_eq!(kind, DifferenceKind::Unclassified);
        // When every backend agrees, the combined record states the shared
        // classification instead of inventing one.
        let mut agreeing = result.clone();
        agreeing.per_backend.insert(
            "reference".into(),
            agreeing.per_backend.get("rust").cloned().unwrap(),
        );
        assert_eq!(
            agreeing
                .per_backend
                .values()
                .map(|c| c.difference)
                .collect::<Vec<_>>(),
            vec![Some(DifferenceKind::Mixed), Some(DifferenceKind::Mixed)]
        );
    }

    #[test]
    fn verification_plans_carry_no_search_measurements() {
        let seed = &crate::scenario::seeds(3, 1)[0];
        let mut candidate = seeded_candidate(Scenario::EcdhP521, "x", seed.pair.clone(), 3);
        candidate.search_raw = vec![crate::measure::RawBatch {
            seed: 0xdead_beef,
            order: "0101".into(),
            class0: vec![111_111, 222_222],
            class1: vec![333_333, 444_444],
            nv_stores_measured: 0,
        }];
        let prepared = PreparedPair::prepare(candidate.scenario, candidate.pair().unwrap());
        let config = VerifyConfig {
            disable_known_case_skips: false,
            budget: 20_000,
            batch: 1000,
            repeats: 2,
            warmup: 5,
            time_limit_s: 60.0,
            cpu: None,
            max_candidates: 1,
            seed_diagnostics: 0,
            include_seed_diagnostics: false,
        };
        let backend = BackendSpec::Control {
            scenario: Scenario::ControlPositive,
        };
        let plan = dudect_plan(&backend, &prepared, LoadOrder::ClassBFirst, &config);
        let text = plan.render().unwrap();
        for sample in ["111111", "222222", "333333", "444444", "deadbeef"] {
            assert!(!text.contains(sample), "plan leaks search sample {sample}");
        }
        let keys: BTreeSet<&str> = text.lines().filter_map(|l| l.split(' ').next()).collect();
        let allowed: BTreeSet<&str> = [
            "backend",
            "cpu",
            "setup",
            "class0",
            "class1",
            "expect0",
            "expect1",
            "warmup",
            "batch",
            "budget",
            "time_limit_s",
        ]
        .into_iter()
        .collect();
        assert!(keys.is_subset(&allowed), "{keys:?}");
        let ecdh = dudect_plan(
            &BackendSpec::Library {
                name: crate::worker::BackendName::Rust,
                path: PathBuf::from("/x"),
            },
            &prepared,
            LoadOrder::ClassBFirst,
            &config,
        );
        assert_eq!(ecdh.setup.len(), 3);
        assert_eq!(&ecdh.class_commands[0][10..14], &[0x80, 0, 0, 1]);
        assert_eq!(&ecdh.class_commands[1][10..14], &[0x80, 0, 0, 0]);
        assert_eq!(&ecdh.class_commands[0][14..], &ecdh.class_commands[1][14..]);
    }

    #[test]
    fn union_deduplicates_unordered_pairs() {
        let seed = &crate::scenario::seeds(5, 2)[0];
        let a = seeded_candidate(Scenario::EcdhP521, "a", seed.pair.clone(), 5);
        let swapped = seed.pair.reversed();
        let b = seeded_candidate(Scenario::EcdhP521, "b", swapped, 5);
        let other = seeded_candidate(
            Scenario::EcdhP521,
            "c",
            crate::scenario::seeds(5, 2)[1].pair.clone(),
            5,
        );
        let (unique, total) = union_candidates(vec![a, b, other], 10).unwrap();
        assert_eq!(unique[0].provenance.len() + unique[1].provenance.len(), 3);
        assert_eq!(total, 2);
        assert_eq!(unique.len(), 2);
    }

    #[test]
    fn tpm_controls_cannot_pass_on_functional_checks_alone() {
        use RunVerdict::*;
        let mut silent = result_with(
            &[
                ("rust", NoSignal),
                ("reference", NoSignal),
                ("rust", NoSignal),
                ("reference", NoSignal),
            ],
            true,
        );
        apply_control_expectation(Scenario::TpmControlPositive, &mut silent);
        assert_eq!(silent.outcome, VerificationOutcome::Failed);
        assert!(silent.control_check.unwrap().contains("not detected"));
        let mut detected = result_with(
            &[
                ("rust", Signal),
                ("reference", Signal),
                ("rust", Signal),
                ("reference", Signal),
            ],
            true,
        );
        apply_control_expectation(Scenario::TpmControlPositive, &mut detected);
        assert_eq!(detected.outcome, VerificationOutcome::Completed);
        let mut noisy = result_with(
            &[
                ("rust", Signal),
                ("reference", NoSignal),
                ("rust", Signal),
                ("reference", NoSignal),
            ],
            true,
        );
        apply_control_expectation(Scenario::TpmControlNegative, &mut noisy);
        assert_eq!(noisy.outcome, VerificationOutcome::Failed);
        let mut quiet = result_with(
            &[
                ("rust", NoSignal),
                ("reference", NoSignal),
                ("rust", NoSignal),
                ("reference", NoSignal),
            ],
            true,
        );
        apply_control_expectation(Scenario::TpmControlNegative, &mut quiet);
        assert_eq!(quiet.outcome, VerificationOutcome::Completed);
        let mut other = result_with(
            &[
                ("rust", NoSignal),
                ("reference", NoSignal),
                ("rust", NoSignal),
                ("reference", NoSignal),
            ],
            true,
        );
        apply_control_expectation(Scenario::EcdhP521, &mut other);
        assert!(other.control_check.is_none());
    }
}
