use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use libafl::corpus::{Corpus, InMemoryCorpus, Testcase};
use libafl::feedbacks::ConstFeedback;
use libafl::inputs::{BytesInput, HasMutatorBytes};
use libafl::mutators::{
    BitFlipMutator, ByteInterestingMutator, ByteRandMutator, CrossoverReplaceMutator,
    HavocScheduledMutator, MutationResult, Mutator, QwordAddMutator,
};
use libafl::state::{HasCorpus, StdState};
use libafl_bolts::rands::StdRand;
use libafl_bolts::tuples::tuple_list;
use serde::{Deserialize, Serialize};

use crate::identity::{OpensslObservation, check_openssl_consistency};
use crate::measure::{
    FixtureMeasurer, LoadOrder, MeasureFailure, Measurer, WorkerMeasurer, no_effect,
    popcount_tail_effect,
};
use crate::scalar::{PAIR_BYTES, ScalarPair, order_minus};
use crate::scenario::{PreparedPair, Scenario, seeds};
use crate::search::{
    CandidateFile, CandidateKind, HistoryEntry, Origin, ScalarBoundaryMutator, SearchConfig,
    SearchError, SharedLog, ValidPairMutator, boundary_scalar, run_campaign, seeded_candidate,
};
use crate::stats::StatConfig;
use crate::verify::{
    BackendVerdict, CandidateArtifact, RunVerdict, VerifyConfig, VerifyTarget, backend_verdict,
    content_naming, dudect_plan, run_verdict, save_candidates, verify_candidate,
};
use crate::worker::{
    BackendSpec, DudectStatus, Limits, WorkerBinary, WorkerError, check_timer_support,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub name: String,
    pub kind: String,
    pub passed: bool,
    pub detail: String,
}

pub type Check = fn(&Path) -> Result<String, String>;

pub const DETERMINISTIC_CHECKS: &[(&str, Check)] = &[
    (
        "timing feedback retains improving candidates (fixture)",
        feedback_selects_candidates,
    ),
    (
        "disabled timing feedback selects nothing (fixture)",
        feedback_disabled_selects_nothing,
    ),
    (
        "noise-only fixture selects nothing",
        noise_only_selects_nothing,
    ),
    (
        "scalar mutations preserve width and range",
        mutations_preserve_validity,
    ),
    (
        "saved candidates round-trip and replay",
        candidates_round_trip,
    ),
    (
        "functional failures never become candidates",
        functional_failures_excluded,
    ),
    (
        "infrastructure failures abort the campaign",
        infrastructure_failures_abort,
    ),
    (
        "OpenSSL identity mismatches are rejected",
        openssl_mismatch_rejected,
    ),
    (
        "unsupported timers, missing libraries and crashed workers fail explicitly",
        explicit_worker_failures,
    ),
    (
        "incomplete verification is never reported as success",
        incomplete_not_success,
    ),
    (
        "verification plans contain no search samples",
        plans_have_no_search_samples,
    ),
    (
        "malformed and interrupted artifacts are handled explicitly",
        malformed_reports_rejected,
    ),
    (
        "every worker operation is bounded and timed-out workers are reaped",
        worker_deadlines_enforced,
    ),
    (
        "negative control: pre-fix blocking supervision hangs",
        unbounded_supervision_hangs,
    ),
    (
        "campaign deadline interrupts a worker blocked mid-measurement",
        campaign_deadline_interrupts_worker,
    ),
    (
        "unsuccessful worker termination is reported as a failure",
        worker_termination_is_checked,
    ),
];

pub fn fixture_config(seed: u64, feedback: bool) -> SearchConfig {
    SearchConfig {
        scenario: Scenario::ControlPositive,
        seed,
        max_evaluations: 240,
        max_duration_s: 600,
        samples_per_class: 40,
        warmup: 0,
        stats: StatConfig {
            min_improvement: 0.05,
            ..StatConfig::default()
        },
        max_candidates: 8,
        random_seed_pairs: 4,
        stage_max_iterations: 4,
        mutation_stack_pow: 2,
        timing_feedback: feedback,
    }
}

fn read_history(dir: &Path) -> Result<Vec<HistoryEntry>, String> {
    let text = fs::read_to_string(dir.join("history.jsonl")).map_err(|e| e.to_string())?;
    text.lines()
        .map(|l| serde_json::from_str(l).map_err(|e| e.to_string()))
        .collect()
}

fn fixture_campaign(
    dir: &Path,
    name: &str,
    config: &SearchConfig,
    measurer: FixtureMeasurer,
) -> Result<crate::search::CampaignOutput<FixtureMeasurer>, String> {
    let out = dir.join(name);
    let _ = fs::remove_dir_all(&out);
    run_campaign(measurer, config, &out, &out.join("corpus"), None).map_err(|e| e.to_string())
}

pub fn feedback_selects_candidates(dir: &Path) -> Result<String, String> {
    let config = fixture_config(11, true);
    let output = fixture_campaign(
        dir,
        "feedback-on",
        &config,
        FixtureMeasurer::new("fixture", popcount_tail_effect),
    )?;
    let summary = &output.summary;
    if output.candidates.is_empty() {
        return Err(format!(
            "no candidate retained in {} evaluations",
            summary.evaluations
        ));
    }
    for candidate in &output.candidates {
        if !matches!(candidate.origin, Origin::Mutation { .. }) {
            return Err(format!("candidate {} is not a mutation", candidate.id));
        }
        if !candidate.retention_reason.starts_with("retained") {
            return Err(format!(
                "candidate {} lacks a retention reason",
                candidate.id
            ));
        }
    }
    let scores: Vec<f64> = summary.score_trajectory.iter().map(|(_, s)| *s).collect();
    if scores.windows(2).any(|w| w[1] <= w[0]) {
        return Err(format!(
            "retained scores are not strictly improving: {scores:?}"
        ));
    }
    if summary.candidates.len() > config.max_candidates {
        return Err("candidate bound exceeded".into());
    }
    let history = read_history(&dir.join("feedback-on"))?;
    if history.len() != summary.evaluations {
        return Err(format!(
            "history has {} entries for {} evaluations",
            history.len(),
            summary.evaluations
        ));
    }
    Ok(format!(
        "{} candidates in {} evaluations, trajectory {:?}, best seed value {:?}",
        output.candidates.len(),
        summary.evaluations,
        scores
            .iter()
            .map(|s| (s * 100.0).round() / 100.0)
            .collect::<Vec<_>>(),
        summary
            .max_seed_ranking_value
            .map(|s| (s * 100.0).round() / 100.0)
    ))
}

pub fn feedback_disabled_selects_nothing(dir: &Path) -> Result<String, String> {
    let config = fixture_config(11, false);
    let output = fixture_campaign(
        dir,
        "feedback-off",
        &config,
        FixtureMeasurer::new("fixture", popcount_tail_effect),
    )?;
    if !output.candidates.is_empty() {
        return Err(format!(
            "{} candidates retained with feedback disabled",
            output.candidates.len()
        ));
    }
    let history = read_history(&dir.join("feedback-off"))?;
    if history
        .iter()
        .any(|h| h.decision.candidate || h.decision.seed_met_criteria)
    {
        return Err("a decision selected an input with feedback disabled".into());
    }
    if output.summary.evaluations != config.max_evaluations {
        return Err(format!(
            "expected the full budget of {} evaluations, ran {}",
            config.max_evaluations, output.summary.evaluations
        ));
    }
    Ok(format!(
        "0 candidates in {} evaluations; corpus holds only the {} seeds",
        output.summary.evaluations, output.summary.corpus_entries
    ))
}

pub fn noise_only_selects_nothing(dir: &Path) -> Result<String, String> {
    let config = fixture_config(11, true);
    let output = fixture_campaign(
        dir,
        "noise-only",
        &config,
        FixtureMeasurer::new("fixture", no_effect),
    )?;
    if !output.candidates.is_empty() || !output.summary.seeds_meeting_criteria.is_empty() {
        return Err(format!(
            "noise produced {} candidates and {} seeds meeting criteria",
            output.candidates.len(),
            output.summary.seeds_meeting_criteria.len()
        ));
    }
    Ok(format!(
        "0 candidates in {} evaluations",
        output.summary.evaluations
    ))
}

pub fn mutations_preserve_validity(_dir: &Path) -> Result<String, String> {
    let mut corpus = InMemoryCorpus::<BytesInput>::new();
    for seed in seeds(5, 4) {
        corpus
            .add(Testcase::new(BytesInput::new(seed.pair.to_bytes())))
            .map_err(|e| e.to_string())?;
    }
    let mut feedback = ConstFeedback::new(false);
    let mut objective = ConstFeedback::new(false);
    let mut state = StdState::new(
        StdRand::with_seed(99),
        corpus,
        InMemoryCorpus::<BytesInput>::new(),
        &mut feedback,
        &mut objective,
    )
    .map_err(|e| e.to_string())?;
    let log: SharedLog = Default::default();
    let mut mutator = ValidPairMutator::new(
        HavocScheduledMutator::with_max_stack_pow(
            tuple_list!(
                BitFlipMutator::new(),
                ByteRandMutator::new(),
                ByteInterestingMutator::new(),
                QwordAddMutator::new(),
                CrossoverReplaceMutator::new(),
                ScalarBoundaryMutator::new()
            ),
            3,
        ),
        log.clone(),
    );
    let mut mutated = 0;
    let mut input = BytesInput::new(seeds(5, 1)[0].pair.to_bytes());
    for round in 0..5000 {
        if round % 50 == 0 {
            let id = state.corpus().first().unwrap();
            *state.corpus_mut().current_mut() = Some(id);
        }
        let before = input.mutator_bytes().to_vec();
        match mutator
            .mutate(&mut state, &mut input)
            .map_err(|e| e.to_string())?
        {
            MutationResult::Mutated => {
                mutated += 1;
                let bytes = input.mutator_bytes();
                if bytes.len() != PAIR_BYTES {
                    return Err(format!("width changed to {}", bytes.len()));
                }
                ScalarPair::from_bytes(bytes)
                    .map_err(|e| format!("invalid mutation survived: {e}"))?;
            }
            MutationResult::Skipped => {
                if input.mutator_bytes() != before.as_slice() {
                    return Err("a skipped mutation left the input modified".into());
                }
            }
        }
    }
    let rejected = log.borrow().rejected_mutations;
    if rejected == 0 {
        return Err("no invalid mutation was generated, so rejection is untested".into());
    }
    let near_order = order_minus(1);
    let mut below_top = [0xffu8; 66];
    below_top[0] = 0;
    let toggled = boundary_scalar(5, 0, &below_top, &near_order);
    if crate::search::valid_scalar(&toggled) {
        return Err("setting the top byte of 0x00ff..ff should leave the valid range".into());
    }
    for op in 0..6 {
        for r in [0u64, 1, 7, 1 << 20, u64::MAX] {
            let out = boundary_scalar(
                op,
                r,
                &near_order,
                crate::scalar::Scalar521::from_u128(3).unwrap().bytes(),
            );
            if out.len() != 66 {
                return Err(format!("boundary op {op} changed width"));
            }
        }
    }
    Ok(format!(
        "{mutated} accepted mutations all valid; {rejected} invalid mutations rejected before measurement"
    ))
}

pub fn candidates_round_trip(dir: &Path) -> Result<String, String> {
    let config = fixture_config(23, true);
    let output = fixture_campaign(
        dir,
        "round-trip",
        &config,
        FixtureMeasurer::new("fixture", popcount_tail_effect),
    )?;
    let saved = output
        .candidates
        .first()
        .ok_or("fixture campaign produced no candidate")?;
    let path = dir
        .join("round-trip/candidates")
        .join(format!("{}.json", saved.artifact_stem()?));
    let loaded = CandidateFile::load(&path)?;
    if loaded.pair()? != saved.pair()?
        || loaded.search_raw != saved.search_raw
        || loaded.campaign_seed != config.seed
    {
        return Err("candidate changed across save/load".into());
    }
    if loaded.config_sha256.as_deref() != Some(config.sha256().as_str()) {
        return Err("candidate does not reference the configuration hash".into());
    }
    let mut measurer = FixtureMeasurer::new("fixture", popcount_tail_effect);
    let prepared = PreparedPair::prepare(loaded.scenario, loaded.pair()?);
    let pair = measurer
        .load(&prepared, LoadOrder::ClassAFirst)
        .map_err(|e| e.to_string())?;
    let responses = measurer.execute_once(&pair).map_err(|e| e.to_string())?;
    if responses[0] != prepared.classes[0].expected_response
        || responses[1] != prepared.classes[1].expected_response
    {
        return Err("replayed responses differ from the expected outputs".into());
    }
    let raw = measurer
        .measure(&pair, 40, 0, 1234)
        .map_err(|e| e.to_string())?;
    let stats = crate::stats::batch_stats(&raw.class0, &raw.class1, 0.9).ok_or("no stats")?;
    let search_sign = loaded.search_batches[0].t.signum();
    if stats.t.signum() != search_sign {
        return Err("replay disagrees with the saved search sign".into());
    }
    let mut corrupted = serde_json::to_value(&loaded).map_err(|e| e.to_string())?;
    corrupted["scalar_a"] = serde_json::Value::String(hex::encode(crate::scalar::ORDER));
    let bad = dir.join("round-trip/corrupted.json");
    fs::write(&bad, serde_json::to_vec(&corrupted).unwrap()).map_err(|e| e.to_string())?;
    if CandidateFile::load(&bad).is_ok() {
        return Err("a candidate with scalar >= n was accepted".into());
    }
    let mut legacy = serde_json::to_value(&loaded).map_err(|e| e.to_string())?;
    legacy["format"] = serde_json::Value::String(crate::search::LEGACY_CANDIDATE_FORMAT.into());
    legacy.as_object_mut().unwrap().remove("content_sha256");
    legacy.as_object_mut().unwrap().remove("provenance");
    let legacy_path = dir.join("round-trip/legacy-v1.json");
    fs::write(&legacy_path, serde_json::to_vec(&legacy).unwrap()).map_err(|e| e.to_string())?;
    let legacy_loaded = CandidateFile::load(&legacy_path)?;
    if legacy_loaded.pair()? != loaded.pair()? || legacy_loaded.provenance.len() != 1 {
        return Err("legacy v1 candidate did not load with its own provenance".into());
    }
    let mut tampered = serde_json::to_value(&loaded).map_err(|e| e.to_string())?;
    tampered["scalar_b"] = serde_json::Value::String(hex::encode(crate::scalar::order_minus(7)));
    let tampered_path = dir.join("round-trip/tampered.json");
    fs::write(&tampered_path, serde_json::to_vec(&tampered).unwrap()).map_err(|e| e.to_string())?;
    match CandidateFile::load(&tampered_path) {
        Err(e) if e.contains("content_sha256") => {}
        other => {
            return Err(format!(
                "tampered candidate not rejected: {:?}",
                other.map(|c| c.id)
            ));
        }
    }
    let mut future = serde_json::to_value(&loaded).map_err(|e| e.to_string())?;
    future["format"] = serde_json::Value::String("tpms-timing-candidate/v9".into());
    let future_path = dir.join("round-trip/future.json");
    fs::write(&future_path, serde_json::to_vec(&future).unwrap()).map_err(|e| e.to_string())?;
    match CandidateFile::load(&future_path) {
        Err(e) if e.contains("regenerate") && e.contains(crate::search::CANDIDATE_FORMAT) => {}
        other => {
            return Err(format!(
                "unsupported format not rejected actionably: {:?}",
                other.map(|c| c.id)
            ));
        }
    }
    Ok(format!(
        "{} round-tripped; replay t {:.2} has the saved sign",
        loaded.id, stats.t
    ))
}

fn odd_tail_is_functional_failure(pair: &PreparedPair) -> Option<MeasureFailure> {
    (pair.pair.a.bytes()[65] & 1 == 1).then(|| MeasureFailure::Functional {
        class: Some(0),
        detail: "fixture backend error".into(),
    })
}

pub fn functional_failures_excluded(dir: &Path) -> Result<String, String> {
    let config = fixture_config(31, true);
    let mut measurer = FixtureMeasurer::new("fixture", popcount_tail_effect);
    measurer.fail_when = Some(odd_tail_is_functional_failure);
    let output = fixture_campaign(dir, "functional", &config, measurer)?;
    if output.summary.functional_failures == 0 {
        return Err("the fixture never produced a functional failure".into());
    }
    for candidate in &output.candidates {
        if candidate.scalar_a[65] & 1 == 1 {
            return Err(format!("failing pair {} became a candidate", candidate.id));
        }
    }
    let history = read_history(&dir.join("functional"))?;
    let failing: Vec<_> = history
        .iter()
        .filter(|h| h.observation.failure.is_some())
        .collect();
    if failing
        .iter()
        .any(|h| h.decision.candidate || h.decision.seed_met_criteria)
    {
        return Err("a failed evaluation was selected".into());
    }
    if failing.iter().any(|h| !h.observation.batches.is_empty()) {
        return Err("a failed evaluation carries timing statistics".into());
    }
    Ok(format!(
        "{} functional failures recorded as objectives, {} candidates all from successful evaluations",
        failing.len(),
        output.candidates.len()
    ))
}

fn always_infrastructure(_pair: &PreparedPair) -> Option<MeasureFailure> {
    Some(MeasureFailure::Infrastructure {
        detail: "fixture worker died".into(),
    })
}

pub fn infrastructure_failures_abort(dir: &Path) -> Result<String, String> {
    let config = fixture_config(41, true);
    let mut measurer = FixtureMeasurer::new("fixture", popcount_tail_effect);
    measurer.fail_when = Some(always_infrastructure);
    let out = dir.join("infrastructure");
    match run_campaign(measurer, &config, &out, &out.join("corpus"), None) {
        Err(SearchError::Infrastructure(detail)) => Ok(format!("campaign aborted: {detail}")),
        Err(other) => Err(format!("unexpected error kind: {other}")),
        Ok(_) => Err("campaign completed despite infrastructure failure".into()),
    }
}

pub fn openssl_mismatch_rejected(_dir: &Path) -> Result<String, String> {
    let observation = |backend: &str, sha: Option<&str>, version: &str| OpensslObservation {
        backend: backend.into(),
        libcrypto_path: "/usr/lib/libcrypto.so.3".into(),
        libcrypto_sha256: sha.map(str::to_string),
        openssl_version: version.into(),
    };
    let same = [
        observation("rust", Some("aa"), "OpenSSL 3.0.13"),
        observation("reference", Some("aa"), "OpenSSL 3.0.13"),
    ];
    check_openssl_consistency(&same)?;
    let different = [
        observation("rust", Some("aa"), "OpenSSL 3.0.13"),
        observation("reference", Some("bb"), "OpenSSL 3.0.13"),
    ];
    let error = check_openssl_consistency(&different)
        .err()
        .ok_or("hash mismatch accepted")?;
    let version = [
        observation("rust", Some("aa"), "OpenSSL 3.0.13"),
        observation("reference", Some("aa"), "OpenSSL 3.3.0"),
    ];
    check_openssl_consistency(&version)
        .err()
        .ok_or("version mismatch accepted")?;
    let missing = [OpensslObservation {
        backend: "rust".into(),
        libcrypto_path: "-".into(),
        libcrypto_sha256: None,
        openssl_version: "-".into(),
    }];
    check_openssl_consistency(&missing)
        .err()
        .ok_or("missing libcrypto accepted")?;
    Ok(error)
}

pub fn explicit_worker_failures(dir: &Path) -> Result<String, String> {
    let timer = check_timer_support("aarch64")
        .err()
        .ok_or("aarch64 accepted")?;
    let spec = BackendSpec::Library {
        name: crate::worker::BackendName::Reference,
        path: dir.join("does-not-exist/libtpms.so"),
    };
    let missing = match crate::worker::WorkerProcess::spawn(
        Path::new("/bin/false"),
        &spec,
        None,
        &dir.join("missing.log"),
        crate::worker::Limits::default(),
    ) {
        Err(error @ WorkerError::MissingLibrary(_)) => error.to_string(),
        Err(other) => return Err(format!("unexpected error {other}")),
        Ok(_) => return Err("missing library accepted".into()),
    };
    let script = dir.join("crashing-worker.sh");
    fs::write(&script, "#!/bin/sh\necho 'ready 1'\nkill -SEGV $$\n").map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755))
            .map_err(|e| e.to_string())?;
    }
    let control = BackendSpec::Control {
        scenario: Scenario::ControlNegative,
    };
    let crashed = match crate::worker::WorkerProcess::spawn(
        &script,
        &control,
        None,
        &dir.join("crash.log"),
        crate::worker::Limits::default(),
    ) {
        Err(error @ (WorkerError::Crashed { .. } | WorkerError::Io(_))) => error.to_string(),
        Err(other) => return Err(format!("unexpected error {other}")),
        Ok(_) => return Err("crashing worker accepted".into()),
    };
    let pair = seeds(1, 1)[0].pair;
    let prepared = PreparedPair::prepare(Scenario::ControlNegative, pair);
    let plan = dudect_plan(
        &control,
        &prepared,
        LoadOrder::ClassAFirst,
        &small_verify_config(),
    );
    let outcome = crate::worker::run_dudect(
        &script,
        &plan,
        &dir.join("crash-dudect"),
        std::time::Duration::from_secs(20),
    )
    .map_err(|e| e.to_string())?;
    if outcome.status != DudectStatus::WorkerCrashed
        || run_verdict(&outcome.status) != RunVerdict::Failure
    {
        return Err(format!(
            "crashed dudect worker classified as {:?}",
            outcome.status
        ));
    }
    Ok(format!(
        "{timer}; {missing}; {crashed}; dudect: {:?}",
        outcome.status
    ))
}

fn small_verify_config() -> VerifyConfig {
    VerifyConfig {
        budget: 4000,
        batch: 500,
        repeats: 2,
        warmup: 2,
        time_limit_s: 30.0,
        cpu: None,
        max_candidates: 1,
        seed_diagnostics: 0,
        include_seed_diagnostics: false,
    }
}

pub fn incomplete_not_success(_dir: &Path) -> Result<String, String> {
    let incomplete = [
        DudectStatus::InsufficientMeasurements,
        DudectStatus::TimeLimit,
        DudectStatus::Interrupted,
        DudectStatus::WorkerTimeout,
    ];
    for status in &incomplete {
        if run_verdict(status) != RunVerdict::Incomplete {
            return Err(format!("{status:?} not classified as incomplete"));
        }
    }
    if backend_verdict(&[RunVerdict::Incomplete, RunVerdict::Incomplete], 2)
        != BackendVerdict::Inconclusive
    {
        return Err("two incomplete runs produced a verdict".into());
    }
    if backend_verdict(&[RunVerdict::NoSignal, RunVerdict::Incomplete], 2)
        != BackendVerdict::Inconclusive
    {
        return Err("partial budget treated as no-signal".into());
    }
    if backend_verdict(&[RunVerdict::Signal], 2) != BackendVerdict::Inconclusive {
        return Err("a single run treated as reproducible".into());
    }
    if backend_verdict(&[RunVerdict::Signal, RunVerdict::Signal], 2)
        != BackendVerdict::ReproducibleSignal
    {
        return Err("two agreeing runs not reproducible".into());
    }
    Ok(
        "budget/time-limit/interrupted runs map to incomplete; one run is never reproducible"
            .into(),
    )
}

pub fn plans_have_no_search_samples(_dir: &Path) -> Result<String, String> {
    let pair = seeds(3, 1)[0].pair;
    let mut candidate = seeded_candidate(Scenario::ControlPositive, "x", pair, 3);
    candidate.kind = CandidateKind::AdaptiveDiscovery;
    candidate.search_raw = vec![crate::measure::RawBatch {
        seed: 0x5ea2_c4ed,
        order: "01".into(),
        class0: vec![987_654_321, 987_654_322],
        class1: vec![123_456_789, 123_456_788],
        nv_stores_measured: 0,
    }];
    let prepared = PreparedPair::prepare(candidate.scenario, candidate.pair()?);
    let plan = dudect_plan(
        &BackendSpec::Control {
            scenario: Scenario::ControlPositive,
        },
        &prepared,
        LoadOrder::ClassAFirst,
        &small_verify_config(),
    );
    let text = plan.render().map_err(|e| e.to_string())?;
    for needle in ["987654321", "123456789", "5ea2c4ed"] {
        if text.contains(needle) {
            return Err(format!("plan contains search data {needle}"));
        }
    }
    let mut forbidden = BTreeSet::new();
    forbidden.insert("search-session".to_string());
    let mut seen = BTreeSet::new();
    if crate::verify::session_is_fresh(Some("search-session"), &forbidden, &mut seen) {
        return Err("a search session was accepted for verification".into());
    }
    if !crate::verify::session_is_fresh(Some("fresh-a"), &forbidden, &mut seen)
        || crate::verify::session_is_fresh(Some("fresh-a"), &forbidden, &mut seen)
        || crate::verify::session_is_fresh(None, &forbidden, &mut seen)
    {
        return Err("session freshness rules violated".into());
    }
    Ok("plans hold only commands, expected responses and budgets; reused or missing worker sessions are rejected".into())
}

pub fn malformed_reports_rejected(dir: &Path) -> Result<String, String> {
    use crate::run::{Run, RunState};
    let base = dir.join("reports");
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).map_err(|e| e.to_string())?;
    let mut run = Run::create(&base, "verify", Some("bad")).map_err(|e| e.to_string())?;
    run.write_json("manifest.json", &serde_json::json!({}))
        .map_err(|e| e.to_string())?;
    fs::write(run.dir.join("results.json"), b"{\"format\": 1").map_err(|e| e.to_string())?;
    run.finish(RunState::Completed, None)
        .map_err(|e| e.to_string())?;
    let malformed = crate::report::build_report(&[run.dir.clone()])
        .err()
        .ok_or("malformed results accepted")?;
    let mut interrupted = Run::create(&base, "verify", Some("int")).map_err(|e| e.to_string())?;
    interrupted
        .finish(RunState::Failed, Some("interrupted by signal".into()))
        .map_err(|e| e.to_string())?;
    let report = crate::report::build_report(&[interrupted.dir.clone()])?;
    if !report.overall_counts.is_empty() || !report.verifications.is_empty() {
        return Err("an interrupted run contributed verification results".into());
    }
    Ok(malformed)
}

pub fn run_deterministic(dir: &Path) -> Vec<CheckResult> {
    DETERMINISTIC_CHECKS
        .iter()
        .map(|(name, check)| {
            let scratch = dir.join(name.replace(|c: char| !c.is_ascii_alphanumeric(), "-"));
            let _ = fs::create_dir_all(&scratch);
            let outcome = check(&scratch);
            CheckResult {
                name: name.to_string(),
                kind: "deterministic".into(),
                passed: outcome.is_ok(),
                detail: outcome.unwrap_or_else(|e| e),
            }
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveParams {
    pub seed: u64,
    pub search_evaluations: usize,
    pub samples_per_class: usize,
    pub verify: VerifyConfig,
}

pub fn live_search_config(scenario: Scenario, params: &LiveParams, feedback: bool) -> SearchConfig {
    SearchConfig {
        scenario,
        seed: params.seed,
        max_evaluations: params.search_evaluations,
        max_duration_s: 1800,
        samples_per_class: params.samples_per_class,
        warmup: 5,
        stats: StatConfig::default(),
        max_candidates: 6,
        random_seed_pairs: 6,
        stage_max_iterations: 4,
        mutation_stack_pow: 2,
        timing_feedback: feedback,
    }
}

fn live_search(
    worker: &WorkerBinary,
    dir: &Path,
    name: &str,
    config: &SearchConfig,
    cpu: Option<usize>,
    limits: Limits,
) -> Result<crate::search::CampaignOutput<()>, String> {
    let out = dir.join("search").join(name);
    fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    let measurer = WorkerMeasurer::start(
        &worker.path,
        BackendSpec::Control {
            scenario: config.scenario,
        },
        cpu,
        &out.join("worker-stderr.log"),
        limits,
    )
    .map_err(|e| e.to_string())?;
    let output = run_campaign(measurer, config, &out, &out.join("corpus"), Some(dir))
        .map_err(|e| e.to_string())?;
    let crate::search::CampaignOutput {
        summary,
        candidates,
        measurer,
    } = output;
    measurer
        .close_checked()
        .map_err(|e| format!("worker shutdown failed: {e}"))?;
    if let Some(interrupted) = &summary.interrupted_operation {
        return Err(format!("search incomplete: {interrupted}"));
    }
    Ok(crate::search::CampaignOutput {
        summary,
        candidates,
        measurer: (),
    })
}

#[allow(clippy::too_many_arguments)]
fn live_verify(
    worker: &WorkerBinary,
    candidate: &CandidateFile,
    config: &VerifyConfig,
    dir: &Path,
    sessions: &BTreeSet<String>,
    limits: Limits,
    progress: &mut dyn FnMut(&str),
) -> Result<crate::verify::CandidateResult, String> {
    let saved = save_candidates(
        &dir.join("verify-candidates")
            .join(candidate.scenario.name()),
        std::slice::from_ref(candidate),
        content_naming,
    )?;
    let (name, file) = &saved[0];
    verify_candidate(
        &worker.path,
        CandidateArtifact {
            candidate,
            name,
            file,
        },
        &[VerifyTarget {
            spec: BackendSpec::Control {
                scenario: candidate.scenario,
            },
        }],
        config,
        &dir.join("verify").join(name),
        sessions,
        limits,
        progress,
    )
}

pub fn run_live(
    worker: &WorkerBinary,
    dir: &Path,
    params: &LiveParams,
    limits: Limits,
    positive: bool,
    negative: bool,
    progress: &mut dyn FnMut(&str),
) -> Vec<CheckResult> {
    let mut results = Vec::new();
    let push = |results: &mut Vec<CheckResult>, name: &str, outcome: Result<String, String>| {
        results.push(CheckResult {
            name: name.into(),
            kind: "live".into(),
            passed: outcome.is_ok(),
            detail: outcome.unwrap_or_else(|e| e),
        });
    };
    let mut pair_for_verification: Option<CandidateFile> = None;
    let mut search_sessions = BTreeSet::new();
    if positive {
        progress("live: positive-control search with timing feedback");
        let enabled = live_search(
            worker,
            dir,
            "control-positive-feedback-on",
            &live_search_config(Scenario::ControlPositive, params, true),
            params.verify.cpu,
            limits,
        );
        let outcome = enabled.map(|output| {
            if let Some(session) = output.summary.worker_info.get("session") {
                search_sessions.insert(session.clone());
            }
            let best = output.candidates.last().cloned();
            pair_for_verification = best.clone();
            (output.summary, best)
        });
        push(
            &mut results,
            "positive control: adaptive search discovers a difference",
            match &outcome {
                Ok((summary, Some(best))) => Ok(format!(
                    "{} candidates in {} evaluations; trajectory {:?}; best {} (score {:.2})",
                    summary.candidates.len(),
                    summary.evaluations,
                    summary
                        .score_trajectory
                        .iter()
                        .map(|(e, s)| (*e, (s * 100.0).round() / 100.0))
                        .collect::<Vec<_>>(),
                    best.id,
                    summary.best_candidate_score.unwrap_or(0.0)
                )),
                Ok((summary, None)) => Err(format!(
                    "no candidate in {} evaluations",
                    summary.evaluations
                )),
                Err(e) => Err(e.clone()),
            },
        );
        progress("live: positive-control search with timing feedback disabled");
        let disabled = live_search(
            worker,
            dir,
            "control-positive-feedback-off",
            &live_search_config(Scenario::ControlPositive, params, false),
            params.verify.cpu,
            limits,
        );
        push(
            &mut results,
            "positive control: disabled feedback retains nothing",
            match disabled {
                Ok(output) if output.candidates.is_empty() => Ok(format!(
                    "0 candidates in {} evaluations (max seed search value {:.2})",
                    output.summary.evaluations,
                    output.summary.max_seed_ranking_value.unwrap_or(0.0)
                )),
                Ok(output) => Err(format!("{} candidates retained", output.candidates.len())),
                Err(e) => Err(e),
            },
        );
    }
    let candidate = pair_for_verification.unwrap_or_else(|| {
        let seed = seeds(params.seed, 0)
            .into_iter()
            .find(|s| s.name == "small-1-vs-random")
            .unwrap();
        seeded_candidate(
            Scenario::ControlPositive,
            &seed.name,
            seed.pair,
            params.seed,
        )
    });
    if positive {
        progress(&format!(
            "live: dudect verification of positive control on {}",
            candidate.id
        ));
        let mut positive_candidate = candidate.clone();
        positive_candidate.scenario = Scenario::ControlPositive;
        let outcome = live_verify(
            worker,
            &positive_candidate,
            &params.verify,
            dir,
            &search_sessions,
            limits,
            progress,
        );
        push(
            &mut results,
            "positive control: independent dudect verification detects it",
            match outcome {
                Ok(r)
                    if r.verdicts
                        .values()
                        .all(|v| *v == BackendVerdict::ReproducibleSignal) =>
                {
                    Ok(format!(
                        "{:?}; runs: {}",
                        r.verdicts,
                        r.runs
                            .iter()
                            .map(|x| format!(
                                "{:?} max t {:?} after {}",
                                x.status, x.final_max_t, x.measurements
                            ))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                }
                Ok(r) => Err(format!(
                    "{:?}; runs {:?}",
                    r.verdicts,
                    r.runs
                        .iter()
                        .map(|x| (&x.status, x.final_max_t))
                        .collect::<Vec<_>>()
                )),
                Err(e) => Err(e),
            },
        );
    }
    if negative {
        progress(&format!(
            "live: dudect verification of negative control on {}",
            candidate.id
        ));
        let mut negative_candidate = candidate.clone();
        negative_candidate.scenario = Scenario::ControlNegative;
        negative_candidate.id = format!("{}-as-negative-control", candidate.id);
        let outcome = live_verify(
            worker,
            &negative_candidate,
            &params.verify,
            dir,
            &search_sessions,
            limits,
            progress,
        );
        push(
            &mut results,
            "negative control: no reproducible confirmed finding within budget",
            match outcome {
                Ok(r)
                    if r.verdicts.values().all(|v| {
                        matches!(
                            v,
                            BackendVerdict::NoSignalWithinBudget | BackendVerdict::Inconclusive
                        )
                    }) =>
                {
                    Ok(format!(
                        "{:?}; runs: {}",
                        r.verdicts,
                        r.runs
                            .iter()
                            .map(|x| format!(
                                "{:?} max t {:?} after {}",
                                x.status, x.final_max_t, x.measurements
                            ))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                }
                Ok(r) => Err(format!(
                    "{:?}; runs {:?}",
                    r.verdicts,
                    r.runs
                        .iter()
                        .map(|x| (&x.status, x.final_max_t))
                        .collect::<Vec<_>>()
                )),
                Err(e) => Err(e),
            },
        );
        progress("live: negative-control search with timing feedback (informational)");
        let search = live_search(
            worker,
            dir,
            "control-negative-feedback-on",
            &live_search_config(Scenario::ControlNegative, params, true),
            params.verify.cpu,
            limits,
        );
        push(
            &mut results,
            "negative control: search runs on the shared infrastructure",
            search.map(|output| {
                format!(
                    "{} search candidates in {} evaluations (search scores are ranking evidence only; not verified here)",
                    output.candidates.len(),
                    output.summary.evaluations
                )
            }),
        );
    }
    results
}

fn fake_script(dir: &Path, name: &str, body: &str) -> Result<std::path::PathBuf, String> {
    let path = dir.join(format!("{name}.sh"));
    let pid_file = dir.join(format!("{name}.pid"));
    let text = format!("#!/bin/sh\necho $$ > '{}'\n{body}\n", pid_file.display());
    fs::write(&path, text).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
    }
    Ok(path)
}

fn script_pid(dir: &Path, name: &str) -> Result<i32, String> {
    fs::read_to_string(dir.join(format!("{name}.pid")))
        .map_err(|e| format!("{name}: no pid file: {e}"))?
        .trim()
        .parse()
        .map_err(|e| format!("{name}: bad pid: {e}"))
}

fn reaped(pid: i32) -> bool {
    // SAFETY: signal 0 performs only an existence and permission check on pid.
    let rc = unsafe { libc::kill(pid, 0) };
    rc == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

const HANG: &str = "exec sleep 600";
const DEADLINE_LIMIT: std::time::Duration = std::time::Duration::from_secs(2);
const DEADLINE_MARGIN: std::time::Duration = std::time::Duration::from_secs(20);

pub fn worker_deadlines_enforced(dir: &Path) -> Result<String, String> {
    use crate::worker::{TimeoutBound, WorkerProcess};
    use std::time::Instant;
    let control = BackendSpec::Control {
        scenario: Scenario::ControlNegative,
    };
    let limits = Limits::new(DEADLINE_LIMIT);
    let init = "echo 'ready 1'\nread line\necho ok";
    let cases: [(&str, String, &str); 10] = [
        ("no-greeting", HANG.to_string(), "greeting"),
        (
            "hang-init",
            format!("echo 'ready 1'\nread line\n{HANG}"),
            "init",
        ),
        ("hang-command", format!("{init}\nread line\n{HANG}"), "exec"),
        (
            "hang-measure",
            format!("{init}\nread line\n{HANG}"),
            "measure",
        ),
        (
            "partial-line",
            format!("{init}\nread line\nprintf 'resp 00000000 80'\n{HANG}"),
            "exec",
        ),
        (
            "stop-reading",
            format!("{init}\n{HANG}"),
            "exec (request write)",
        ),
        (
            "ignore-shutdown",
            format!("{init}\nread line\n{HANG}"),
            "shutdown",
        ),
        (
            "continuous-lines",
            "echo 'ready 1'\nread line\nexec yes 'info key value'".to_string(),
            "init",
        ),
        (
            "continuous-bytes",
            format!("{init}\nread line\nwhile :; do printf xxxxxxxxxxxxxxxx; done"),
            "exec",
        ),
        (
            "continuous-shutdown",
            format!("{init}\nread line\nexec yes bye"),
            "shutdown",
        ),
    ];
    let mut summary = Vec::new();
    for (name, body, expected_operation) in cases {
        let script = fake_script(dir, name, &body)?;
        let stderr = dir.join(format!("{name}-stderr.log"));
        let started = Instant::now();
        let (tx, rx) = std::sync::mpsc::channel();
        let thread_script = script.clone();
        let thread_control = control.clone();
        let thread_stderr = stderr.clone();
        let case_name = name.to_string();
        let handle = std::thread::spawn(move || {
            let outcome: Result<(), WorkerError> = (|| {
                let mut process = WorkerProcess::spawn(
                    &thread_script,
                    &thread_control,
                    None,
                    &thread_stderr,
                    limits,
                )?;
                match case_name.as_str() {
                    "hang-command" | "partial-line" | "continuous-bytes" => {
                        process.exec(&[0u8; 66]).map(|_| ())
                    }
                    "stop-reading" => process.exec(&vec![0u8; 1 << 20]).map(|_| ()),
                    "hang-measure" => process
                        .measure(10, 1, 0, [&[0u8; 66], &[1u8; 66]], [&[0u8; 16], &[0u8; 16]])
                        .map(|_| ()),
                    "ignore-shutdown" | "continuous-shutdown" => process.close().map(|_| ()),
                    _ => Ok(()),
                }
            })();
            let _ = tx.send(outcome);
        });
        let outcome = match rx.recv_timeout(DEADLINE_MARGIN) {
            Ok(outcome) => {
                let _ = handle.join();
                outcome
            }
            Err(_) => {
                if let Ok(pid) = script_pid(dir, name) {
                    // SAFETY: pid belongs to the fake worker started by this check; killing it unblocks the supervising thread.
                    unsafe {
                        libc::kill(pid, libc::SIGKILL);
                    }
                }
                let _ = handle.join();
                return Err(format!(
                    "{name}: parent still blocked after {DEADLINE_MARGIN:?}; worker deadline not enforced"
                ));
            }
        };
        let elapsed = started.elapsed();
        match outcome {
            Err(WorkerError::Timeout {
                operation,
                bound,
                partial,
                ..
            }) => {
                if operation != expected_operation || bound != TimeoutBound::OperationLimit {
                    return Err(format!(
                        "{name}: timed out in {operation} ({bound:?}), expected {expected_operation}"
                    ));
                }
                if name == "partial-line" && partial != "resp 00000000 80" {
                    return Err(format!("{name}: partial output {partial:?} not preserved"));
                }
            }
            Err(other) => return Err(format!("{name}: unexpected error {other}")),
            Ok(()) => return Err(format!("{name}: completed although the worker hangs")),
        }
        let pid = script_pid(dir, name)?;
        if !reaped(pid) {
            return Err(format!("{name}: worker {pid} still exists after timeout"));
        }
        let log = fs::read_to_string(&stderr).unwrap_or_default();
        if !log.contains("tpms-timing supervisor:")
            || !log.contains(expected_operation.split(' ').next().unwrap())
        {
            return Err(format!(
                "{name}: diagnostics not saved in {}",
                stderr.display()
            ));
        }
        summary.push(format!(
            "{name}->{expected_operation} in {:.1}s",
            elapsed.as_secs_f64()
        ));
    }
    let normal = fake_script(
        dir,
        "normal",
        &format!("{init}\nread line\necho 'resp 00000000 aa'\nread line\necho bye\nexit 0"),
    )?;
    let started = Instant::now();
    let mut process = WorkerProcess::spawn(
        &normal,
        &control,
        None,
        &dir.join("normal-stderr.log"),
        limits,
    )
    .map_err(|e| format!("normal: {e}"))?;
    let reply = process
        .exec(&[1, 2, 3])
        .map_err(|e| format!("normal: {e}"))?;
    let status = process.close().map_err(|e| format!("normal: {e}"))?;
    if reply != (0, vec![0xaa]) || status != "exit code 0" {
        return Err(format!("normal worker: reply {reply:?}, status {status}"));
    }
    if !reaped(script_pid(dir, "normal")?) {
        return Err("normal worker not reaped".into());
    }
    summary.push(format!(
        "normal completed in {:.1}s",
        started.elapsed().as_secs_f64()
    ));
    Ok(summary.join("; "))
}

pub fn unbounded_supervision_hangs(dir: &Path) -> Result<String, String> {
    use crate::worker::{Supervision, WorkerProcess};
    let script = fake_script(dir, "negative-no-greeting", HANG)?;
    let stderr = dir.join("negative-stderr.log");
    let control = BackendSpec::Control {
        scenario: Scenario::ControlNegative,
    };
    let (tx, rx) = std::sync::mpsc::channel();
    let thread_script = script.clone();
    let handle = std::thread::spawn(move || {
        let result = WorkerProcess::spawn_supervised(
            &thread_script,
            &control,
            None,
            &stderr,
            Limits::new(DEADLINE_LIMIT),
            Supervision::Unbounded,
        );
        let _ = tx.send(result.is_ok());
    });
    let waited = std::time::Duration::from_secs(6);
    let outcome = rx.recv_timeout(waited);
    let pid = script_pid(dir, "negative-no-greeting")?;
    // SAFETY: pid was written by the fake worker script this check started; SIGKILL ends it so the blocked thread observes EOF.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    let _ = handle.join();
    match outcome {
        Ok(_) => Err("the previous blocking behaviour returned; the negative control did not reproduce the hang".into()),
        Err(_) => Ok(format!(
            "with the pre-fix blocking reads the parent was still waiting after {waited:?} (deadline {DEADLINE_LIMIT:?}); the bounded regression would fail"
        )),
    }
}

pub fn campaign_deadline_interrupts_worker(dir: &Path) -> Result<String, String> {
    use std::time::Instant;
    let script = fake_script(
        dir,
        "campaign-hang-measure",
        &format!("echo 'ready 1'\nread line\necho ok\nread line\n{HANG}"),
    )?;
    let out = dir.join("campaign");
    let measurer = WorkerMeasurer::start(
        &script,
        BackendSpec::Control {
            scenario: Scenario::ControlPositive,
        },
        None,
        &dir.join("campaign-stderr.log"),
        Limits::new(std::time::Duration::from_secs(120)),
    )
    .map_err(|e| e.to_string())?;
    let mut config = fixture_config(3, true);
    config.max_duration_s = 3;
    let started = Instant::now();
    let output = run_campaign(measurer, &config, &out, &out.join("corpus"), None)
        .map_err(|e| e.to_string())?;
    let elapsed = started.elapsed();
    if elapsed > DEADLINE_MARGIN {
        return Err(format!("campaign took {elapsed:?} with a 3 s budget"));
    }
    let interrupted = output
        .summary
        .interrupted_operation
        .clone()
        .ok_or("campaign did not record the interrupted operation")?;
    if !interrupted.contains("measure") {
        return Err(format!("unexpected interruption record {interrupted}"));
    }
    let history = read_history(&out)?;
    if !history.iter().any(|h| {
        h.decision
            .reason
            .starts_with("incomplete: campaign deadline")
    }) {
        return Err("history lacks the incomplete evaluation".into());
    }
    if !reaped(script_pid(dir, "campaign-hang-measure")?) {
        return Err("hung campaign worker was not reaped".into());
    }
    Ok(format!(
        "3 s campaign returned after {:.1}s although the worker never answered (operation limit 120 s): {interrupted}",
        elapsed.as_secs_f64()
    ))
}

pub fn worker_termination_is_checked(dir: &Path) -> Result<String, String> {
    use crate::worker::WorkerProcess;
    let control = BackendSpec::Control {
        scenario: Scenario::ControlNegative,
    };
    let limits = Limits::new(DEADLINE_LIMIT);
    let init = "echo 'ready 1'\nread line\necho ok";
    let reply = "read line\necho 'resp 00000000 aa'";
    let cases: [(&str, String, Option<&str>); 4] = [
        (
            "exit-nonzero",
            format!("{init}\n{reply}\nread line\necho bye\nexit 9"),
            Some("exit code 9"),
        ),
        (
            "signal-in-shutdown",
            format!("{init}\n{reply}\nread line\nkill -ABRT $$"),
            Some("signal"),
        ),
        (
            "exit-before-shutdown",
            format!("{init}\n{reply}\nexit 0"),
            Some(""),
        ),
        (
            "normal-shutdown",
            format!("{init}\n{reply}\nread line\necho bye\nexit 0"),
            None,
        ),
    ];
    let mut summary = Vec::new();
    for (name, body, expected) in cases {
        let script = fake_script(dir, name, &body)?;
        let mut process = WorkerProcess::spawn(
            &script,
            &control,
            None,
            &dir.join(format!("{name}-stderr.log")),
            limits,
        )
        .map_err(|e| format!("{name}: {e}"))?;
        let reply = process.exec(&[1]).map_err(|e| format!("{name}: {e}"))?;
        if reply != (0, vec![0xaa]) {
            return Err(format!("{name}: bad reply {reply:?}"));
        }
        let closed = process.close();
        match (expected, &closed) {
            (None, Ok(status)) if status == "exit code 0" => {}
            (Some(needle), Err(error)) if error.to_string().contains(needle) => {}
            _ => return Err(format!("{name}: close returned {closed:?}")),
        }
        if !reaped(script_pid(dir, name)?) {
            return Err(format!("{name}: worker not reaped"));
        }
        summary.push(format!(
            "{name}: {}",
            closed.unwrap_or_else(|e| e.to_string())
        ));
    }
    let script = fake_script(dir, "reported-failure", &format!("{init}\nexit 3"))?;
    let mut process = WorkerProcess::spawn(
        &script,
        &control,
        None,
        &dir.join("reported-failure-stderr.log"),
        limits,
    )
    .map_err(|e| e.to_string())?;
    let failure = process
        .exec(&[1])
        .err()
        .ok_or("exec on an exited worker succeeded")?;
    let cleanup = process
        .close()
        .map_err(|e| format!("cleanup after a reported failure must not fail again: {e}"))?;
    summary.push(format!(
        "reported failure ({failure}) then cleanup: {cleanup}"
    ));
    Ok(summary.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tpms-timing-selftest-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    macro_rules! check_test {
        ($name:ident, $check:path) => {
            #[test]
            fn $name() {
                let dir = scratch(stringify!($name));
                let outcome = $check(&dir);
                let _ = fs::remove_dir_all(&dir);
                assert!(outcome.is_ok(), "{}", outcome.unwrap_err());
            }
        };
    }

    check_test!(feedback_selects, feedback_selects_candidates);
    check_test!(feedback_disabled, feedback_disabled_selects_nothing);
    check_test!(noise_only, noise_only_selects_nothing);
    check_test!(mutation_validity, mutations_preserve_validity);
    check_test!(round_trip, candidates_round_trip);
    check_test!(functional_excluded, functional_failures_excluded);
    check_test!(infrastructure_abort, infrastructure_failures_abort);
    check_test!(openssl_mismatch, openssl_mismatch_rejected);
    check_test!(worker_failures, explicit_worker_failures);
    check_test!(incomplete, incomplete_not_success);
    check_test!(fresh_plans, plans_have_no_search_samples);
    check_test!(malformed_reports, malformed_reports_rejected);
    check_test!(worker_deadlines, worker_deadlines_enforced);
    check_test!(deadline_negative_control, unbounded_supervision_hangs);
    check_test!(campaign_deadline, campaign_deadline_interrupts_worker);
    check_test!(worker_termination, worker_termination_is_checked);

    #[test]
    fn every_deterministic_check_is_wired_into_cargo_test() {
        assert_eq!(DETERMINISTIC_CHECKS.len(), 16);
    }
}
