use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::artifacts::{display_label, is_plain_label};
use crate::measure::{LoadOrder, Measurer, WorkerMeasurer};
use crate::scalar::ScalarPair;
use crate::scenario::{PreparedPair, Scenario, boundary_seeds};
use crate::search::{CandidateFile, CandidateKind, Provenance, seeded_candidate};
use crate::tpm;
use crate::worker::{BackendSpec, DudectOutcome, DudectPlan, DudectStatus, Limits, run_dudect};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyConfig {
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
    pub backend: String,
    pub ok: bool,
    pub detail: String,
    pub responses: Vec<String>,
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

pub const OUTCOME_CONTRACT: &str = "completed (exit 0): every requested candidate was verified and each one is a reproducible signal or no signal within a sufficient dudect budget; incomplete (exit 3): any candidate is inconclusive, has insufficient measurements, a time limit, an interruption, missing or mixed repeats, or not all candidates were processed; failed (exit 4): any functional or infrastructure failure, which takes precedence over incompleteness. A reproducible timing signal is a completed experiment, not a failure.";

pub fn candidate_outcome(category: Category) -> VerificationOutcome {
    match category {
        Category::ReproducibleSignalBoth
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
        format!("all {requested} candidates verified with a definite result")
    } else {
        reasons.join("; ")
    };
    (outcome, detail)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateResult {
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
    pub runs: Vec<RunRecord>,
    pub verdicts: BTreeMap<String, BackendVerdict>,
    pub category: Category,
}

pub fn functional_ok(result: &CandidateResult) -> bool {
    result.functional.iter().all(|f| f.ok) && result.cross_backend_identical != Some(false)
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

pub const DIAGNOSTIC_SEED_ORDER: &[&str] = &[
    "small-1-vs-random",
    "leading-zero-9-bytes-vs-full-width",
    "order-minus-1-vs-random",
    "limb-2^64-minus-1-vs-2^64",
    "top-bit-2^520-vs-random",
    "leading-zero-1-bytes-vs-full-width",
    "small-2-vs-small-3",
    "order-minus-2-vs-order-minus-1",
];

pub fn diagnostic_seeds(
    scenario: Scenario,
    campaign_seed: u64,
    count: usize,
) -> Vec<CandidateFile> {
    let seeds = boundary_seeds(campaign_seed);
    DIAGNOSTIC_SEED_ORDER
        .iter()
        .filter_map(|name| seeds.iter().find(|s| s.name == *name))
        .take(count)
        .map(|seed| seeded_candidate(scenario, &seed.name, seed.pair, campaign_seed))
        .collect()
}

pub fn dudect_plan(
    backend: &BackendSpec,
    prepared: &PreparedPair,
    order: LoadOrder,
    config: &VerifyConfig,
) -> DudectPlan {
    let (setup, commands) = match prepared.scenario {
        Scenario::EcdhP521 => {
            let mut setup = vec![tpm::startup_clear()];
            let mut handles = [0u32; 2];
            for (slot, class) in order.classes().into_iter().enumerate() {
                setup.push(prepared.load_command(class).expect("ecdh loads objects"));
                handles[class] = tpm::FIRST_TRANSIENT_HANDLE + slot as u32;
            }
            (
                setup,
                [
                    prepared.measured_command(0, handles[0]),
                    prepared.measured_command(1, handles[1]),
                ],
            )
        }
        _ => (
            Vec::new(),
            [
                prepared.measured_command(0, 0),
                prepared.measured_command(1, 0),
            ],
        ),
    };
    DudectPlan {
        backend: backend.clone(),
        cpu: config.cpu,
        setup,
        class_commands: commands,
        expected: [
            prepared.classes[0].expected_response.clone(),
            prepared.classes[1].expected_response.clone(),
        ],
        warmup: config.warmup,
        batch: config.batch,
        budget: config.budget,
        time_limit_s: config.time_limit_s,
    }
}

pub fn functional_check(
    worker: &Path,
    backend: &BackendSpec,
    pair: ScalarPair,
    scenario: Scenario,
    stderr: &Path,
    limits: Limits,
) -> FunctionalCheck {
    let label = backend.label();
    let prepared = PreparedPair::prepare(scenario, pair);
    let result = (|| -> Result<[Vec<u8>; 2], String> {
        let mut measurer = WorkerMeasurer::start(worker, backend.clone(), None, stderr, limits)
            .map_err(|e| e.to_string())?;
        let loaded = measurer
            .load(&prepared, LoadOrder::ClassAFirst)
            .map_err(|e| e.to_string())?;
        let responses = measurer.execute_once(&loaded).map_err(|e| e.to_string())?;
        measurer.close_checked().map_err(|e| e.to_string())?;
        Ok(responses)
    })();
    match result {
        Ok(responses) => {
            let mismatched: Vec<usize> = (0..2)
                .filter(|c| responses[*c] != prepared.classes[*c].expected_response)
                .collect();
            FunctionalCheck {
                backend: label,
                ok: mismatched.is_empty(),
                detail: if mismatched.is_empty() {
                    "both classes returned TPM_RC_SUCCESS and the shared point computed independently with the p521 crate".into()
                } else {
                    format!(
                        "classes {mismatched:?} differ from the independently computed response"
                    )
                },
                responses: responses.iter().map(hex::encode).collect(),
            }
        }
        Err(detail) => FunctionalCheck {
            backend: label,
            ok: false,
            detail,
            responses: Vec::new(),
        },
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
    let pair = candidate.pair()?;
    crate::artifacts::create_new_dir(dir).map_err(|e| e.to_string())?;
    let prepared = PreparedPair::prepare(candidate.scenario, pair);
    let mut functional = Vec::new();
    for target in targets {
        let check = functional_check(
            worker,
            &target.spec,
            pair,
            candidate.scenario,
            &dir.join(format!("functional-{}-stderr.log", target.spec.label())),
            limits,
        );
        progress(&format!(
            "functional check {} on {}: {}",
            artifact.name,
            target.spec.label(),
            if check.ok { "ok" } else { "FAILED" }
        ));
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
    let mut result = CandidateResult {
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
        runs: Vec::new(),
        verdicts: BTreeMap::new(),
        category: Category::InconclusiveOrIncomplete,
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
                let run_dir = dir.join(&label).join(format!("run-{repeat}"));
                let plan = dudect_plan(&target.spec, &prepared, order, config);
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
                    backend: b.to_string(),
                    ok: functional_ok,
                    detail: String::new(),
                    responses: vec![],
                })
                .collect(),
            cross_backend_identical: Some(true),
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
    fn verification_plans_carry_no_search_measurements() {
        let seed = &crate::scenario::seeds(3, 1)[0];
        let mut candidate = seeded_candidate(Scenario::EcdhP521, "x", seed.pair, 3);
        candidate.search_raw = vec![crate::measure::RawBatch {
            seed: 0xdead_beef,
            order: "0101".into(),
            class0: vec![111_111, 222_222],
            class1: vec![333_333, 444_444],
            nv_stores_measured: 0,
        }];
        let prepared = PreparedPair::prepare(candidate.scenario, candidate.pair().unwrap());
        let config = VerifyConfig {
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
        let a = seeded_candidate(Scenario::EcdhP521, "a", seed.pair, 5);
        let swapped = ScalarPair {
            a: seed.pair.b,
            b: seed.pair.a,
        };
        let b = seeded_candidate(Scenario::EcdhP521, "b", swapped, 5);
        let other = seeded_candidate(
            Scenario::EcdhP521,
            "c",
            crate::scenario::seeds(5, 2)[1].pair,
            5,
        );
        let (unique, total) = union_candidates(vec![a, b, other], 10).unwrap();
        assert_eq!(unique[0].provenance.len() + unique[1].provenance.len(), 3);
        assert_eq!(total, 2);
        assert_eq!(unique.len(), 2);
    }
}
