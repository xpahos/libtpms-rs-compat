use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::json;

use crate::identity::{
    EXCLUDED_PATHS, MEASUREMENT_BOUNDARIES, OpensslObservation, check_openssl_consistency,
    host_identity, library_identity, observe_openssl, sha256_file, source_identity, tool_identity,
};
use crate::measure::{LoadOrder, Measurer, WorkerMeasurer};
use crate::report::{VERIFY_RESULTS_FORMAT, VerifyResults, build_report, write_report};
use crate::run::{self, Run, RunState};
use crate::scenario::{PreparedPair, Scenario, peer_point};
use crate::search::{CandidateFile, CandidateKind, SearchConfig, run_campaign};
use crate::stats::{SEARCH_STATISTIC, StatConfig, batch_stats};
use crate::verify::{
    CandidateArtifact, OUTCOME_CONTRACT, VerificationOutcome as Outcome, VerifyConfig,
    VerifyTarget, aggregate_outcome, artifact_names, content_naming, diagnostic_seeds,
    load_candidates, save_candidates, union_candidates, verify_candidate,
};
use crate::worker::{
    BackendName, BackendSpec, Limits, WorkerBinary, WorkerInfo, build_worker, override_worker,
};
use crate::{selftest, tpm};

const LONG_ABOUT: &str = "\
Timing-fuzzing prototype for the TPM2_ECDH_ZGen command on NIST P-521, run through the public
libtpms ABI of two shared libraries: this repository's Rust library and the pinned C libtpms
reference. Each backend runs in its own worker process.

Pipeline:
  search   LibAFL mutates valid pairs of P-521 private scalars (66 bytes each, 1 <= d < n).
           A worker loads both keys with TPM2_LoadExternal outside timing, then times
           ECDH_ZGen for both classes in random interleaved order. A pair is kept only when
           repeated batches cross the configured Welch-t threshold with a consistent sign and
           beat the best score seen so far. Each backend is searched separately.
  verify   Takes the union of saved candidates (plus seeded boundary diagnostics when the search
           found nothing) and runs the original upstream dudect (oreparaz/dudect, pinned and
           checksum-verified) in a fresh worker process per backend and per repeat.
  replay   Re-runs one saved candidate: a functional check plus fresh search-style batches.
  report   Rebuilds report.json and report.md from saved artifacts without measuring.
  self-test
           Deterministic infrastructure checks, plus optional live positive and negative
           controls that use the same worker and dudect path.

Host requirements: the pinned dudect times with mfence+rdtsc and compiles only for x86/x86_64.
Measurement commands fail with an explicit 'unsupported timer' error on other architectures.
Measurements on virtualized or binary-translated hosts are labelled exploratory.

Example inside the x86_64 container (timing-tests/docker/run.sh):
  tpms-timing-tests self-test --live-controls positive,negative
  tpms-timing-tests search --backend rust --rust-lib $RUST_LIB --max-evaluations 120
  tpms-timing-tests search --backend reference --reference-lib $REF_LIB --max-evaluations 120
  tpms-timing-tests verify --rust-lib $RUST_LIB --reference-lib $REF_LIB \\
      --search-run target/timing-tests/runs/<rust-search> --search-run target/timing-tests/runs/<reference-search>
  tpms-timing-tests replay --rust-lib $RUST_LIB --reference-lib $REF_LIB --candidate <file.json>
  tpms-timing-tests report target/timing-tests/runs/<run> ...

Exit status (same contract in run.json, results.json, summary.md and report.json):
  0  completed: all requested work finished; every verified candidate is a reproducible
     signal or shows no signal within a sufficient dudect budget
  3  incomplete: inconclusive or mixed repeats, missing repeats, insufficient measurements,
     time limits, interruptions, unprocessed candidates, or a search whose campaign deadline
     cut a worker operation short
  4  failed: functional mismatch, worker crash or timeout, malformed output, OpenSSL identity
     mismatch, artifact collision or any other infrastructure error (wins over 3)
  2  command-line usage error
Every worker operation is bounded by --operation-timeout-s, measured from the start of the
operation and checked on every loop iteration, so continuous output cannot extend it; search
also passes its remaining campaign deadline into each worker request and kills/reaps a worker
that overruns it. A worker shutdown succeeds only when the worker answers 'bye' and exits with
status 0; any other exit, signal or crash makes the run fail.
report: overall_outcome is the worst outcome over every supplied run, including verify runs that
stopped before writing results.json; interrupted verify checkpoints keep their failed candidates.
Artifact file names derive from the scenario and scalar content; candidate ids are labels only.

Interpretation: search scores only rank candidates. A reproducible signal requires every
independent dudect repeat to cross dudect's own threshold. 'No signal detected within budget'
is never a constant-time or equivalence claim.";

#[derive(Parser)]
#[command(name = "tpms-timing-tests", version, about = "Adaptive timing search (LibAFL) and dudect verification for libtpms P-521 ECDH_ZGen", long_about = LONG_ABOUT)]
struct Cli {
    #[arg(
        long,
        global = true,
        help = "Repository root [default: parent of the tpms-timing-tests package]"
    )]
    repo: Option<PathBuf>,
    #[arg(
        long,
        global = true,
        help = "Work directory for downloads, worker builds and runs [default: <repo>/target/timing-tests]"
    )]
    work_dir: Option<PathBuf>,
    #[arg(
        long,
        global = true,
        default_value_t = 300.0,
        help = "Upper bound in seconds for every single worker operation (startup, request, measurement, shutdown); search additionally enforces its campaign deadline"
    )]
    operation_timeout_s: f64,
    #[arg(long, global = true, hide = true)]
    worker_executable: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Run deterministic infrastructure tests and optional live controls")]
    SelfTest(SelfTestArgs),
    #[command(about = "Run an adaptive LibAFL timing campaign for each selected backend")]
    Search(SearchArgs),
    #[command(
        about = "Independently verify saved candidates with upstream dudect in fresh worker processes"
    )]
    Verify(VerifyArgs),
    #[command(
        about = "Replay one saved candidate (functional check plus fresh search-style batches)"
    )]
    Replay(ReplayArgs),
    #[command(about = "Summarize completed run directories without re-measuring")]
    Report(ReportArgs),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum BackendChoice {
    Rust,
    Reference,
    Both,
}

#[derive(Args, Clone)]
struct BackendArgs {
    #[arg(
        long,
        value_enum,
        default_value = "both",
        help = "Backends to exercise"
    )]
    backend: BackendChoice,
    #[arg(long, help = "Path to the Rust libtpms shared library (libtpms.so)")]
    rust_lib: Option<PathBuf>,
    #[arg(
        long,
        help = "Path to the reference C libtpms shared library (libtpms.so)"
    )]
    reference_lib: Option<PathBuf>,
    #[arg(
        long,
        help = "Pin each worker to this CPU with sched_setaffinity (Linux only); whether it applied is recorded"
    )]
    cpu: Option<usize>,
    #[arg(
        long,
        help = "Directory containing libtpms/tpm_library.h [default: <repo>/libtpms/include]"
    )]
    libtpms_include: Option<PathBuf>,
}

#[derive(Args, Clone)]
struct OutputArgs {
    #[arg(
        long,
        help = "Directory receiving the run directory [default: <work-dir>/runs]"
    )]
    out_dir: Option<PathBuf>,
    #[arg(long, help = "Extra label embedded in the run directory name")]
    run_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum LiveControl {
    Positive,
    Negative,
    None,
}

#[derive(Args)]
struct SelfTestArgs {
    #[arg(
        long,
        value_enum,
        value_delimiter = ',',
        default_value = "none",
        help = "Live controls to run through the real worker and dudect"
    )]
    live_controls: Vec<LiveControl>,
    #[arg(long, default_value_t = 1)]
    seed: u64,
    #[arg(
        long,
        default_value_t = 400,
        help = "Evaluation budget of each live control search"
    )]
    search_evaluations: usize,
    #[arg(long, default_value_t = 60)]
    samples_per_class: usize,
    #[arg(
        long,
        default_value_t = 40_000,
        help = "dudect measurements per live control run"
    )]
    verify_budget: usize,
    #[arg(long, default_value_t = 1000)]
    verify_batch: usize,
    #[arg(long, default_value_t = 2)]
    verify_repeats: usize,
    #[arg(long, default_value_t = 300.0)]
    verify_time_limit_s: f64,
    #[arg(long)]
    cpu: Option<usize>,
    #[arg(long)]
    libtpms_include: Option<PathBuf>,
    #[command(flatten)]
    output: OutputArgs,
}

#[derive(Args)]
struct SearchArgs {
    #[command(flatten)]
    backends: BackendArgs,
    #[arg(long, value_enum, default_value = "ecdh-p521")]
    scenario: Scenario,
    #[arg(
        long,
        default_value_t = 1,
        help = "Campaign seed (seed corpus, LibAFL RNG, load order and batch order)"
    )]
    seed: u64,
    #[arg(
        long,
        default_value_t = 200,
        help = "Maximum timed evaluations per backend, including seeds"
    )]
    max_evaluations: usize,
    #[arg(
        long,
        default_value_t = 1800,
        help = "Maximum campaign duration per backend in seconds"
    )]
    max_duration_s: u64,
    #[arg(
        long,
        default_value_t = 100,
        help = "Timed executions per class in each search batch"
    )]
    samples_per_class: usize,
    #[arg(
        long,
        default_value_t = 10,
        help = "Untimed warm-up executions per class before the first batch"
    )]
    warmup: usize,
    #[arg(
        long,
        default_value_t = 4.5,
        help = "Search threshold on the cropped Welch |t|"
    )]
    t_threshold: f64,
    #[arg(
        long,
        default_value_t = 0.9,
        help = "Pooled percentile above which samples are cropped before the t-test"
    )]
    crop_percentile: f64,
    #[arg(
        long,
        default_value_t = 1,
        help = "Additional confirmation batches required before retention"
    )]
    confirm_batches: usize,
    #[arg(
        long,
        default_value_t = 0.1,
        help = "Relative improvement over the best known score required for retention"
    )]
    min_improvement: f64,
    #[arg(
        long,
        default_value_t = 8,
        help = "Maximum number of retained candidates per backend"
    )]
    max_candidates: usize,
    #[arg(
        long,
        default_value_t = 8,
        help = "Random seed pairs added to the boundary seeds"
    )]
    random_seed_pairs: usize,
    #[arg(
        long,
        default_value_t = 4,
        help = "Maximum mutations evaluated per scheduled corpus entry"
    )]
    stage_max_iterations: usize,
    #[arg(
        long,
        default_value_t = 2,
        help = "LibAFL havoc stack power (up to 2^n stacked mutations)"
    )]
    mutation_stack_pow: usize,
    #[arg(
        long,
        help = "Disable timing feedback (ablation: nothing is ever retained)"
    )]
    disable_timing_feedback: bool,
    #[arg(
        long,
        help = "Directory for the LibAFL on-disk corpus [default: <run>/search/<backend>/corpus]"
    )]
    corpus_dir: Option<PathBuf>,
    #[command(flatten)]
    output: OutputArgs,
}

#[derive(Args)]
struct VerifyArgs {
    #[command(flatten)]
    backends: BackendArgs,
    #[arg(
        long,
        help = "Completed search run directory (repeatable); the union of their candidates is verified"
    )]
    search_run: Vec<PathBuf>,
    #[arg(long, help = "Candidate JSON file (repeatable)")]
    candidate: Vec<PathBuf>,
    #[arg(
        long,
        value_enum,
        default_value = "ecdh-p521",
        help = "Scenario for seeded diagnostics"
    )]
    scenario: Scenario,
    #[arg(
        long,
        default_value_t = 1,
        help = "Campaign seed for seeded diagnostics when no search run supplies one"
    )]
    seed: u64,
    #[arg(
        long,
        default_value_t = 40_000,
        help = "dudect measurement budget per run"
    )]
    budget: usize,
    #[arg(
        long,
        default_value_t = 1000,
        help = "dudect measurements per dudect_main call"
    )]
    batch: usize,
    #[arg(
        long,
        default_value_t = 2,
        help = "Independent repeats per backend (at least 2 for a reproducible label)"
    )]
    repeats: usize,
    #[arg(
        long,
        default_value_t = 20,
        help = "Untimed warm-up executions per class before dudect starts"
    )]
    warmup: usize,
    #[arg(
        long,
        default_value_t = 900.0,
        help = "Wall-clock limit per dudect run in seconds"
    )]
    time_limit_s: f64,
    #[arg(
        long,
        default_value_t = 6,
        help = "Maximum number of candidates verified (highest search score first)"
    )]
    max_candidates: usize,
    #[arg(
        long,
        default_value_t = 4,
        help = "Boundary seed pairs verified when no adaptive candidate exists"
    )]
    seed_diagnostics: usize,
    #[arg(
        long,
        help = "Also verify seeded boundary diagnostics when adaptive candidates exist"
    )]
    include_seed_diagnostics: bool,
    #[command(flatten)]
    output: OutputArgs,
}

#[derive(Args)]
struct ReplayArgs {
    #[command(flatten)]
    backends: BackendArgs,
    #[arg(long, help = "Saved candidate JSON file")]
    candidate: PathBuf,
    #[arg(long, default_value_t = 100)]
    samples_per_class: usize,
    #[arg(long, default_value_t = 2)]
    batches: usize,
    #[arg(long, default_value_t = 10)]
    warmup: usize,
    #[arg(long, default_value_t = 1)]
    seed: u64,
    #[command(flatten)]
    output: OutputArgs,
}

#[derive(Args)]
struct ReportArgs {
    #[arg(required = true, help = "Run directories to summarize")]
    runs: Vec<PathBuf>,
    #[arg(
        long,
        help = "Output directory [default: <run>/report for one run, <work-dir>/reports/<timestamp> otherwise]"
    )]
    output: Option<PathBuf>,
}

struct Context {
    repo: PathBuf,
    work: PathBuf,
    worker_override: Option<PathBuf>,
    limits: Limits,
}

impl Context {
    fn new(cli: &Cli) -> Self {
        let repo = cli
            .repo
            .clone()
            .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join(".."));
        let repo = fs::canonicalize(&repo).unwrap_or(repo);
        let work = cli
            .work_dir
            .clone()
            .unwrap_or_else(|| repo.join("target/timing-tests"));
        let limits = Limits::new(Duration::from_secs_f64(cli.operation_timeout_s.max(0.001)));
        Self {
            repo,
            work,
            worker_override: cli.worker_executable.clone(),
            limits,
        }
    }

    fn out_dir(&self, output: &OutputArgs) -> PathBuf {
        output
            .out_dir
            .clone()
            .unwrap_or_else(|| self.work.join("runs"))
    }

    fn include(&self, explicit: &Option<PathBuf>) -> PathBuf {
        explicit
            .clone()
            .unwrap_or_else(|| self.repo.join("libtpms/include"))
    }

    fn worker(&self, include: &Option<PathBuf>) -> Result<WorkerBinary, String> {
        match &self.worker_override {
            Some(path) => override_worker(path).map_err(|e| e.to_string()),
            None => build_worker(&self.work, &self.include(include)).map_err(|e| e.to_string()),
        }
    }
}

fn resolve_backends(args: &BackendArgs) -> Result<Vec<BackendSpec>, String> {
    let mut out = Vec::new();
    let wanted = match args.backend {
        BackendChoice::Rust => vec![BackendName::Rust],
        BackendChoice::Reference => vec![BackendName::Reference],
        BackendChoice::Both => vec![BackendName::Rust, BackendName::Reference],
    };
    for name in wanted {
        let path = match name {
            BackendName::Rust => args.rust_lib.clone(),
            BackendName::Reference => args.reference_lib.clone(),
        }
        .ok_or_else(|| format!("--{}-lib is required for backend {name}", name.name()))?;
        if !path.is_file() {
            return Err(format!(
                "backend library does not exist: {}",
                path.display()
            ));
        }
        out.push(BackendSpec::Library { name, path });
    }
    Ok(out)
}

struct Probe {
    spec: BackendSpec,
    info: WorkerInfo,
    openssl: OpensslObservation,
}

fn probe(
    worker: &WorkerBinary,
    specs: &[BackendSpec],
    cpu: Option<usize>,
    dir: &Path,
    limits: Limits,
) -> Result<Vec<Probe>, String> {
    let mut probes = Vec::new();
    for spec in specs {
        let label = spec.label();
        let measurer = WorkerMeasurer::start(
            &worker.path,
            spec.clone(),
            cpu,
            &dir.join(format!("probe-{label}-stderr.log")),
            limits,
        )
        .map_err(|e| format!("{label}: {e}"))?;
        let info = measurer.info();
        measurer
            .close_checked()
            .map_err(|e| format!("{label}: {e}"))?;
        probes.push(Probe {
            openssl: observe_openssl(&label, &info),
            spec: spec.clone(),
            info,
        });
    }
    let library_observations: Vec<OpensslObservation> = probes
        .iter()
        .filter(|p| matches!(p.spec, BackendSpec::Library { .. }))
        .map(|p| p.openssl.clone())
        .collect();
    check_openssl_consistency(&library_observations)?;
    Ok(probes)
}

fn manifest(
    ctx: &Context,
    worker: Option<&WorkerBinary>,
    probes: &[Probe],
    scenario: Scenario,
) -> serde_json::Value {
    let backends: Vec<serde_json::Value> = probes
        .iter()
        .map(|p| {
            let library = match &p.spec {
                BackendSpec::Library { path, .. } => library_identity(path)
                    .map(|l| serde_json::to_value(l).unwrap())
                    .unwrap_or_else(|e| json!({"error": e.to_string()})),
                BackendSpec::Control { .. } => serde_json::Value::Null,
            };
            json!({
                "label": p.spec.label(),
                "spec": p.spec,
                "library": library,
                "worker_probe": p.info,
                "openssl": p.openssl,
            })
        })
        .collect();
    let observations: Vec<OpensslObservation> = probes
        .iter()
        .filter(|p| matches!(p.spec, BackendSpec::Library { .. }))
        .map(|p| p.openssl.clone())
        .collect();
    let root_lock = ctx.repo.join("Cargo.lock");
    json!({
        "format": "tpms-timing-manifest/v1",
        "tool": tool_identity(),
        "repository": source_identity(&ctx.repo, &["src", "Cargo.toml", "build.rs", "LICENSE"]),
        "repository_cargo_lock_sha256": sha256_file(&root_lock).ok(),
        "timing_package": source_identity(&ctx.repo, &["timing-tests"]),
        "libtpms_submodule": source_identity(&ctx.repo.join("libtpms"), &["."]),
        "host": host_identity(),
        "worker": worker,
        "backends": backends,
        "openssl": {
            "observations": observations,
            "consistent": check_openssl_consistency(&observations).is_ok(),
            "required": "all library backends must load the same libcrypto file (sha256) and report the same OpenSSL_version",
        },
        "timer": {
            "mechanism": "dudect cpucycles(): _mm_mfence() followed by __rdtsc(), unmodified upstream code",
            "per_backend": probes.iter().map(|p| json!({
                "backend": p.spec.label(),
                "ticks_per_ns": p.info.get("ticks_per_ns"),
                "granularity_ticks": p.info.get("timer_granularity_ticks"),
            })).collect::<Vec<_>>(),
        },
        "affinity": probes.iter().map(|p| json!({
            "backend": p.spec.label(),
            "requested": p.info.get("affinity_requested"),
            "applied": p.info.get("affinity_applied"),
            "detail": p.info.get("affinity_detail"),
        })).collect::<Vec<_>>(),
        "host_settings": "no host-wide power, frequency or scheduler settings were changed by this tool",
        "scenario": scenario_description(scenario),
        "measurement_boundaries": MEASUREMENT_BOUNDARIES,
        "excluded_paths": EXCLUDED_PATHS,
        "search_statistic": SEARCH_STATISTIC,
    })
}

fn scenario_description(scenario: Scenario) -> serde_json::Value {
    match scenario {
        Scenario::EcdhP521 => {
            let peer = peer_point();
            json!({
                "name": "ecdh-p521",
                "command": "TPM2_ECDH_ZGen (0x154), tag TPM_ST_SESSIONS, one password session (TPM_RS_PW, empty auth, continueSession), inPoint = fixed peer point",
                "command_bytes": tpm::zgen_command_len(),
                "response_bytes": 157,
                "key_loading": "TPM2_LoadExternal into TPM_RH_NULL: ECC NIST P-521, nameAlg SHA-256, attributes userWithAuth|noDA|decrypt, scheme/kdf/symmetric TPM_ALG_NULL, empty authValue",
                "profile": "default-v1 via TPMLIB_SetProfile, then TPMLIB_MainInit and TPM2_Startup(CLEAR)",
                "peer_point": peer,
                "expected_output": "shared point d*Q_peer computed independently with the p521 crate",
                "classes": "two private scalars loaded as two transient objects in one TPM instance; the measured commands differ only in the object handle",
                "varying_public_metadata": [
                    "public key and object name of each class",
                    "shared point returned by each class",
                    "transient handle / object slot (alternated across verification repeats)",
                ],
            })
        }
        _ => json!({
            "name": scenario.name(),
            "positive_control": "iterations = 20000 + 1000 * popcount(last 8 scalar bytes XOR a fixed hidden mask a53c960fe1782db4) of an LCG step guarded by an empty asm barrier; result returned and verified",
            "negative_control": "fixed 52000 iterations with a constant seed, ignoring the input; it only shows that the pipeline does not invent differences for identical work and is no proof of constant-time execution",
        }),
    }
}

fn finish_with_report(
    run: &mut Run,
    state: RunState,
    detail: Option<String>,
) -> Result<(), String> {
    run.finish(state, detail).map_err(|e| e.to_string())?;
    let report = build_report(std::slice::from_ref(&run.dir))?;
    write_report(&report, &run.dir).map_err(|e| e.to_string())?;
    let md = run.dir.join("report.md");
    let json_path = run.dir.join("report.json");
    fs::rename(&md, run.dir.join("summary.md")).map_err(|e| e.to_string())?;
    fs::rename(&json_path, run.dir.join("summary.json")).map_err(|e| e.to_string())?;
    Ok(())
}

fn say(message: &str) {
    eprintln!("[tpms-timing] {message}");
}

fn cmd_self_test(ctx: &Context, args: &SelfTestArgs) -> Result<Outcome, String> {
    let mut run = Run::create(
        &ctx.out_dir(&args.output),
        "self-test",
        args.output.run_name.as_deref(),
    )
    .map_err(|e| e.to_string())?;
    say(&format!("run directory {}", run.dir.display()));
    let mut checks = selftest::run_deterministic(&run.dir.join("deterministic"));
    for check in &checks {
        say(&format!(
            "{}: {}",
            if check.passed { "pass" } else { "FAIL" },
            check.name
        ));
    }
    let positive = args.live_controls.contains(&LiveControl::Positive);
    let negative = args.live_controls.contains(&LiveControl::Negative);
    let mut manifest_value = json!({"format": "tpms-timing-manifest/v1", "tool": tool_identity(), "host": host_identity(),
        "timing_package": source_identity(&ctx.repo, &["timing-tests"])});
    let params = selftest::LiveParams {
        seed: args.seed,
        search_evaluations: args.search_evaluations,
        samples_per_class: args.samples_per_class,
        verify: VerifyConfig {
            budget: args.verify_budget,
            batch: args.verify_batch,
            repeats: args.verify_repeats,
            warmup: 5,
            time_limit_s: args.verify_time_limit_s,
            cpu: args.cpu,
            max_candidates: 1,
            seed_diagnostics: 0,
            include_seed_diagnostics: false,
        },
    };
    run.write_json(
        "config.json",
        &json!({"live_controls": format!("{:?}", args.live_controls), "live": params}),
    )
    .map_err(|e| e.to_string())?;
    if positive || negative {
        match ctx.worker(&args.libtpms_include) {
            Err(error) => checks.push(selftest::CheckResult {
                name: "live controls".into(),
                kind: "live".into(),
                passed: false,
                detail: error,
            }),
            Ok(worker) => {
                let specs: Vec<BackendSpec> = [
                    (positive, Scenario::ControlPositive),
                    (negative, Scenario::ControlNegative),
                ]
                .into_iter()
                .filter(|(on, _)| *on)
                .map(|(_, scenario)| BackendSpec::Control { scenario })
                .collect();
                let probes =
                    probe(&worker, &specs, args.cpu, &run.dir, ctx.limits).unwrap_or_default();
                manifest_value = manifest(ctx, Some(&worker), &probes, Scenario::ControlPositive);
                let live = selftest::run_live(
                    &worker,
                    &run.dir,
                    &params,
                    ctx.limits,
                    positive,
                    negative,
                    &mut |m| say(m),
                );
                for check in &live {
                    say(&format!(
                        "{}: {} — {}",
                        if check.passed { "pass" } else { "FAIL" },
                        check.name,
                        check.detail
                    ));
                }
                checks.extend(live);
            }
        }
    }
    run.write_json("manifest.json", &manifest_value)
        .map_err(|e| e.to_string())?;
    let passed = checks.iter().all(|c| c.passed);
    run.write_json(
        "selftest.json",
        &json!({"passed": passed, "checks": checks}),
    )
    .map_err(|e| e.to_string())?;
    finish_with_report(
        &mut run,
        if passed {
            RunState::Completed
        } else {
            RunState::Failed
        },
        Some(format!("{} checks, all passed: {passed}", checks.len())),
    )?;
    say(&format!(
        "summary: {}",
        run.dir.join("summary.md").display()
    ));
    Ok(if passed {
        Outcome::Completed
    } else {
        Outcome::Failed
    })
}

fn cmd_search(ctx: &Context, args: &SearchArgs) -> Result<Outcome, String> {
    let specs = if args.scenario.is_control() {
        vec![BackendSpec::Control {
            scenario: args.scenario,
        }]
    } else {
        resolve_backends(&args.backends)?
    };
    let worker = ctx.worker(&args.backends.libtpms_include)?;
    let config = SearchConfig {
        scenario: args.scenario,
        seed: args.seed,
        max_evaluations: args.max_evaluations,
        max_duration_s: args.max_duration_s,
        samples_per_class: args.samples_per_class,
        warmup: args.warmup,
        stats: StatConfig {
            t_threshold: args.t_threshold,
            crop_percentile: args.crop_percentile,
            confirm_batches: args.confirm_batches,
            min_improvement: args.min_improvement,
        },
        max_candidates: args.max_candidates,
        random_seed_pairs: args.random_seed_pairs,
        stage_max_iterations: args.stage_max_iterations,
        mutation_stack_pow: args.mutation_stack_pow,
        timing_feedback: !args.disable_timing_feedback,
    };
    let mut run = Run::create(
        &ctx.out_dir(&args.output),
        "search",
        args.output.run_name.as_deref(),
    )
    .map_err(|e| e.to_string())?;
    say(&format!("run directory {}", run.dir.display()));
    run.write_json(
        "config.json",
        &json!({
            "search": config,
            "search_config_sha256": config.sha256(),
            "backends": specs,
            "cpu": args.backends.cpu,
            "corpus_dir": args.corpus_dir,
            "search_statistic": SEARCH_STATISTIC,
            "operation_timeout_s": ctx.limits.operation.as_secs_f64(),
            "worker_executable_override": ctx.worker_override,
        }),
    )
    .map_err(|e| e.to_string())?;
    let probes = match probe(&worker, &specs, args.backends.cpu, &run.dir, ctx.limits) {
        Ok(p) => p,
        Err(error) => {
            run.write_json(
                "manifest.json",
                &manifest(ctx, Some(&worker), &[], args.scenario),
            )
            .map_err(|e| e.to_string())?;
            finish_with_report(&mut run, RunState::Failed, Some(error.clone()))?;
            return Ok(Outcome::Failed);
        }
    };
    run.write_json(
        "manifest.json",
        &manifest(ctx, Some(&worker), &probes, args.scenario),
    )
    .map_err(|e| e.to_string())?;
    let mut failure = None;
    let mut incomplete = Vec::new();
    for spec in &specs {
        let label = spec.label();
        let dir = run.dir.join("search").join(&label);
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let corpus = args
            .corpus_dir
            .as_ref()
            .map(|c| c.join(&label))
            .unwrap_or_else(|| dir.join("corpus"));
        say(&format!(
            "searching {label}: up to {} evaluations / {} s",
            config.max_evaluations, config.max_duration_s
        ));
        let measurer = match WorkerMeasurer::start(
            &worker.path,
            spec.clone(),
            args.backends.cpu,
            &dir.join("worker-stderr.log"),
            ctx.limits,
        ) {
            Ok(m) => m,
            Err(e) => {
                failure = Some(format!("{label}: {e}"));
                break;
            }
        };
        match run_campaign(measurer, &config, &dir, &corpus, Some(&run.dir)) {
            Ok(output) => {
                let s = &output.summary;
                say(&format!(
                    "{label}: {} evaluations, {} candidates, best {:?}, {} seeds meeting criteria, {} functional failures, stop: {}",
                    s.evaluations,
                    s.candidates.len(),
                    s.best_candidate_score,
                    s.seeds_meeting_criteria.len(),
                    s.functional_failures,
                    s.stop_reason
                ));
                if let Some(interrupted) = &s.interrupted_operation {
                    incomplete.push(format!("{label}: {interrupted}"));
                }
                if let Err(error) = output.measurer.close_checked() {
                    failure = Some(format!("{label}: worker shutdown failed: {error}"));
                    break;
                }
            }
            Err(error) => {
                failure = Some(format!("{label}: {error}"));
                break;
            }
        }
    }
    let (state, outcome, detail) = match (&failure, incomplete.is_empty()) {
        (Some(f), _) => (RunState::Failed, Outcome::Failed, Some(f.clone())),
        (None, false) => (
            RunState::Incomplete,
            Outcome::Incomplete,
            Some(incomplete.join("; ")),
        ),
        (None, true) => (RunState::Completed, Outcome::Completed, None),
    };
    finish_with_report(&mut run, state, detail.clone())?;
    say(&format!(
        "summary: {}",
        run.dir.join("summary.md").display()
    ));
    if let Some(detail) = detail {
        say(&detail);
    }
    Ok(outcome)
}

fn search_summaries(runs: &[PathBuf]) -> Vec<serde_json::Value> {
    runs.iter()
        .filter_map(|run| fs::read_dir(run.join("search")).ok())
        .flat_map(|entries| entries.flatten())
        .filter_map(|entry| fs::read(entry.path().join("summary.json")).ok())
        .filter_map(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .collect()
}

fn search_sessions(runs: &[PathBuf]) -> BTreeSet<String> {
    search_summaries(runs)
        .iter()
        .filter_map(|v| v.pointer("/worker_info/session").and_then(|s| s.as_str()))
        .map(str::to_string)
        .collect()
}

fn search_evaluations(runs: &[PathBuf]) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    for value in search_summaries(runs) {
        let backend = value
            .get("backend")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string();
        let evaluations = value
            .get("evaluations")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        *out.entry(backend).or_insert(0) += evaluations;
    }
    out
}

fn checkpoint(results: &mut VerifyResults, requested: usize) {
    let (derived, detail) = aggregate_outcome(&results.results, requested, None);
    results.all_candidates_processed = results.candidates_verified == requested;
    results.outcome = derived.worst(Outcome::Incomplete);
    results.outcome_detail = format!(
        "checkpoint: {} of {requested} candidates verified, run not finished; {detail}",
        results.candidates_verified
    );
    results.stop_reason = "in progress".into();
}

fn cmd_verify(ctx: &Context, args: &VerifyArgs) -> Result<Outcome, String> {
    for run in &args.search_run {
        let info = run::read_run_info(run)?;
        if info.command != "search" || info.state != RunState::Completed {
            return Err(format!(
                "{} is not a completed search run ({} / {:?})",
                run.display(),
                info.command,
                info.state
            ));
        }
    }
    let (loaded, seeds) = load_candidates(&args.search_run, &args.candidate)?;
    let (mut candidates, loaded_unique) = union_candidates(loaded, args.max_candidates)?;
    let adaptive = candidates
        .iter()
        .filter(|c| c.kind == CandidateKind::AdaptiveDiscovery)
        .count();
    let scenario = candidates
        .first()
        .map(|c| c.scenario)
        .unwrap_or(args.scenario);
    if candidates.iter().any(|c| c.scenario != scenario) {
        return Err("candidates of different scenarios cannot be verified in one run".into());
    }
    let mut diagnostics_reason = None;
    if adaptive == 0 || args.include_seed_diagnostics {
        let seed = seeds.first().copied().unwrap_or(args.seed);
        let diagnostics = diagnostic_seeds(scenario, seed, args.seed_diagnostics);
        diagnostics_reason = Some(if adaptive == 0 {
            format!(
                "search produced no adaptive candidate; {} explicit boundary seed pairs (campaign seed {seed}) are verified as seeded diagnostics",
                diagnostics.len()
            )
        } else {
            format!(
                "--include-seed-diagnostics added {} boundary seed pairs",
                diagnostics.len()
            )
        });
        for diagnostic in diagnostics {
            let stem = diagnostic.artifact_stem()?;
            match candidates
                .iter_mut()
                .find(|c| c.artifact_stem().ok().as_deref() == Some(stem.as_str()))
            {
                Some(existing) => existing.merge(&diagnostic)?,
                None => candidates.push(diagnostic),
            }
        }
    }
    for candidate in &mut candidates {
        if candidate.provenance.is_empty() {
            let own = candidate.own_provenance(None);
            candidate.provenance.push(own);
        }
    }
    let names = artifact_names(&candidates, content_naming)?;
    let specs = if scenario.is_control() {
        vec![BackendSpec::Control { scenario }]
    } else {
        resolve_backends(&args.backends)?
    };
    let worker = ctx.worker(&args.backends.libtpms_include)?;
    let config = VerifyConfig {
        budget: args.budget,
        batch: args.batch,
        repeats: args.repeats,
        warmup: args.warmup,
        time_limit_s: args.time_limit_s,
        cpu: args.backends.cpu,
        max_candidates: args.max_candidates,
        seed_diagnostics: args.seed_diagnostics,
        include_seed_diagnostics: args.include_seed_diagnostics,
    };
    let mut run = Run::create(
        &ctx.out_dir(&args.output),
        "verify",
        args.output.run_name.as_deref(),
    )
    .map_err(|e| e.to_string())?;
    say(&format!("run directory {}", run.dir.display()));
    run.write_json("config.json", &json!({
        "verify": config,
        "backends": specs,
        "search_runs": args.search_run,
        "candidate_files": args.candidate,
        "scenario": scenario,
        "dudect_thresholds": {"moderate": 10, "bananas": 500, "enough_measurements_per_class": 10000},
        "operation_timeout_s": ctx.limits.operation.as_secs_f64(),
        "worker_executable_override": ctx.worker_override,
        "outcome_contract": OUTCOME_CONTRACT,
    }))
    .map_err(|e| e.to_string())?;
    let saved = save_candidates(&run.dir.join("candidates"), &candidates, content_naming)?;
    debug_assert_eq!(
        saved.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>(),
        names
    );
    let probes = match probe(&worker, &specs, args.backends.cpu, &run.dir, ctx.limits) {
        Ok(p) => p,
        Err(error) => {
            run.write_json(
                "manifest.json",
                &manifest(ctx, Some(&worker), &[], scenario),
            )
            .map_err(|e| e.to_string())?;
            finish_with_report(&mut run, RunState::Failed, Some(error.clone()))?;
            say(&format!("error: {error}"));
            return Ok(Outcome::Failed);
        }
    };
    run.write_json(
        "manifest.json",
        &manifest(ctx, Some(&worker), &probes, scenario),
    )
    .map_err(|e| e.to_string())?;
    let mut forbidden = search_sessions(&args.search_run);
    forbidden.extend(probes.iter().filter_map(|p| p.info.get("session").cloned()));
    let targets: Vec<VerifyTarget> = specs
        .iter()
        .map(|s| VerifyTarget { spec: s.clone() })
        .collect();
    let mut results = VerifyResults {
        format: VERIFY_RESULTS_FORMAT.into(),
        scenario,
        config: config.clone(),
        backends: specs.iter().map(BackendSpec::label).collect(),
        search_runs: args.search_run.clone(),
        search_evaluations: search_evaluations(&args.search_run),
        candidates_loaded: loaded_unique,
        candidates_requested: candidates.len(),
        candidates_verified: 0,
        adaptive_candidates: adaptive,
        seeded_diagnostics: candidates
            .iter()
            .filter(|c| c.kind == CandidateKind::SeededDiagnostic)
            .count(),
        seeded_diagnostics_reason: diagnostics_reason,
        all_candidates_processed: false,
        outcome: Outcome::Incomplete,
        outcome_detail: "in progress".into(),
        outcome_contract: OUTCOME_CONTRACT.into(),
        completed: None,
        stop_reason: "in progress".into(),
        results: Vec::new(),
    };
    say(&format!(
        "verifying {} candidates ({} adaptive) on {}",
        candidates.len(),
        adaptive,
        results.backends.join(", ")
    ));
    let mut fatal = None;
    let mut stop = None;
    for (candidate, (name, file)) in candidates.iter().zip(&saved) {
        match verify_candidate(
            &worker.path,
            CandidateArtifact {
                candidate,
                name,
                file,
            },
            &targets,
            &config,
            &run.dir.join("verify").join(name),
            &forbidden,
            ctx.limits,
            &mut |m| say(m),
        ) {
            Ok(result) => {
                say(&format!(
                    "{name}: {} ({:?})",
                    result.category.describe(),
                    result.outcome
                ));
                let interrupted = result
                    .runs
                    .iter()
                    .any(|r| r.status == crate::worker::DudectStatus::Interrupted);
                results.results.push(result);
                results.candidates_verified += 1;
                checkpoint(&mut results, candidates.len());
                run.write_json("results.json", &results)
                    .map_err(|e| e.to_string())?;
                if interrupted {
                    stop = Some(
                        "verification interrupted; remaining candidates were not processed"
                            .to_string(),
                    );
                    break;
                }
            }
            Err(error) => {
                fatal = Some(format!("{name}: {error}"));
                break;
            }
        }
    }
    results.all_candidates_processed = results.candidates_verified == candidates.len();
    let (outcome, detail) = aggregate_outcome(&results.results, candidates.len(), fatal.as_deref());
    results.outcome = outcome;
    results.outcome_detail = detail.clone();
    results.stop_reason = fatal.clone().or(stop).unwrap_or_else(|| {
        format!(
            "all {} candidates processed (bookkeeping only; see outcome)",
            candidates.len()
        )
    });
    run.write_json("results.json", &results)
        .map_err(|e| e.to_string())?;
    let state = match outcome {
        Outcome::Completed => RunState::Completed,
        Outcome::Incomplete => RunState::Incomplete,
        Outcome::Failed => RunState::Failed,
    };
    finish_with_report(&mut run, state, Some(detail.clone()))?;
    say(&format!(
        "verification outcome {outcome:?} (exit {}): {detail}",
        outcome.exit_code()
    ));
    say(&format!(
        "summary: {}",
        run.dir.join("summary.md").display()
    ));
    Ok(outcome)
}

fn cmd_replay(ctx: &Context, args: &ReplayArgs) -> Result<Outcome, String> {
    let candidate = CandidateFile::load(&args.candidate)?;
    let specs = if candidate.scenario.is_control() {
        vec![BackendSpec::Control {
            scenario: candidate.scenario,
        }]
    } else {
        resolve_backends(&args.backends)?
    };
    let worker = ctx.worker(&args.backends.libtpms_include)?;
    let mut run = Run::create(
        &ctx.out_dir(&args.output),
        "replay",
        args.output.run_name.as_deref(),
    )
    .map_err(|e| e.to_string())?;
    say(&format!("run directory {}", run.dir.display()));
    run.write_json(
        "config.json",
        &json!({
            "candidate_file": args.candidate,
            "samples_per_class": args.samples_per_class,
            "batches": args.batches,
            "warmup": args.warmup,
            "seed": args.seed,
            "backends": specs,
        }),
    )
    .map_err(|e| e.to_string())?;
    candidate
        .save(&run.dir.join("candidate.json"))
        .map_err(|e| e.to_string())?;
    let probes = match probe(&worker, &specs, args.backends.cpu, &run.dir, ctx.limits) {
        Ok(p) => p,
        Err(error) => {
            finish_with_report(&mut run, RunState::Failed, Some(error.clone())).ok();
            say(&format!("error: {error}"));
            return Ok(Outcome::Failed);
        }
    };
    run.write_json(
        "manifest.json",
        &manifest(ctx, Some(&worker), &probes, candidate.scenario),
    )
    .map_err(|e| e.to_string())?;
    let pair = candidate.pair()?;
    let prepared = PreparedPair::prepare(candidate.scenario, pair);
    let mut per_backend = BTreeMap::new();
    let mut responses_by_backend = Vec::new();
    let mut failure = None;
    for spec in &specs {
        let label = spec.label();
        let outcome = (|| -> Result<serde_json::Value, String> {
            let mut measurer = WorkerMeasurer::start(
                &worker.path,
                spec.clone(),
                args.backends.cpu,
                &run.dir.join(format!("replay-{label}-stderr.log")),
                ctx.limits,
            )
            .map_err(|e| e.to_string())?;
            let loaded = measurer
                .load(&prepared, LoadOrder::ClassAFirst)
                .map_err(|e| e.to_string())?;
            let responses = measurer.execute_once(&loaded).map_err(|e| e.to_string())?;
            let functional_ok =
                (0..2).all(|c| responses[c] == prepared.classes[c].expected_response);
            let mut batches = Vec::new();
            let mut rng = crate::scenario::SplitMix::new(args.seed);
            for index in 0..args.batches {
                let raw = measurer
                    .measure(
                        &loaded,
                        args.samples_per_class,
                        if index == 0 { args.warmup } else { 0 },
                        rng.next_u64(),
                    )
                    .map_err(|e| e.to_string())?;
                batches.push(json!({
                    "stats": batch_stats(&raw.class0, &raw.class1, 0.9),
                    "raw": raw,
                }));
            }
            measurer.close_checked().map_err(|e| e.to_string())?;
            responses_by_backend.push(responses.clone());
            Ok(json!({
                "functional_ok": functional_ok,
                "responses": responses.iter().map(hex::encode).collect::<Vec<_>>(),
                "batches": batches,
            }))
        })();
        match outcome {
            Ok(value) => {
                per_backend.insert(label, value);
            }
            Err(error) => {
                failure = Some(format!("{label}: {error}"));
                per_backend.insert(label, json!({"error": error}));
            }
        }
    }
    let identical = (responses_by_backend.len() > 1)
        .then(|| responses_by_backend.windows(2).all(|w| w[0] == w[1]));
    let t_summary: Vec<String> = per_backend
        .iter()
        .map(|(label, v)| {
            let ts: Vec<String> = v
                .get("batches")
                .and_then(|b| b.as_array())
                .map(|b| {
                    b.iter()
                        .filter_map(|x| x.pointer("/stats/t").and_then(|t| t.as_f64()))
                        .map(|t| format!("{t:.2}"))
                        .collect()
                })
                .unwrap_or_default();
            format!(
                "{label}: functional {} replay t [{}]",
                v.get("functional_ok")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(false),
                ts.join(", ")
            )
        })
        .collect();
    let summary = format!(
        "replayed {} ({:?}, search score {:?}); {}; cross-backend identical responses: {:?}. Replay batches are exploratory ranking evidence, not verification.",
        candidate.id,
        candidate.kind,
        candidate
            .search_score
            .as_ref()
            .map(|s| (s.ranking_value() * 100.0).round() / 100.0),
        t_summary.join("; "),
        identical
    );
    say(&summary);
    run.write_json(
        "replay.json",
        &json!({
            "candidate": candidate.id,
            "candidate_file": args.candidate,
            "candidate_file_sha256": sha256_file(&args.candidate).ok(),
            "artifact": candidate.artifact_stem()?,
            "content_sha256": candidate.content_sha256()?,
            "scenario": candidate.scenario,
            "scalar_a": hex::encode(pair.a.bytes()),
            "scalar_b": hex::encode(pair.b.bytes()),
            "measured_class_inputs": [hex::encode(prepared.pair.a.bytes()), hex::encode(prepared.pair.b.bytes())],
            "provenance": candidate.provenance,
            "search_batches": candidate.search_batches,
            "backends": per_backend,
            "cross_backend_identical": identical,
            "summary": summary,
        }),
    )
    .map_err(|e| e.to_string())?;
    let all_ok = failure.is_none()
        && identical != Some(false)
        && per_backend.values().all(|v| {
            v.get("functional_ok")
                .and_then(|x| x.as_bool())
                .unwrap_or(false)
        });
    let ok = failure.is_none() && all_ok;
    finish_with_report(
        &mut run,
        if ok {
            RunState::Completed
        } else {
            RunState::Failed
        },
        failure.clone().or((!all_ok)
            .then(|| "functional check failed or responses differ across backends".to_string())),
    )?;
    Ok(if ok {
        Outcome::Completed
    } else {
        Outcome::Failed
    })
}

fn cmd_report(ctx: &Context, args: &ReportArgs) -> Result<Outcome, String> {
    let report = build_report(&args.runs)?;
    let output = match (&args.output, args.runs.as_slice()) {
        (Some(output), _) => output.clone(),
        (None, [single]) => single.join("report"),
        (None, _) => ctx.work.join("reports").join(run::utc_now()),
    };
    write_report(&report, &output).map_err(|e| e.to_string())?;
    say(&format!(
        "report written to {} (report.json, report.md)",
        output.display()
    ));
    print!("{}", crate::report::render_markdown(&report));
    Ok(Outcome::Completed)
}

pub fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    if argv.get(1).map(String::as_str) == Some("__fake-worker") {
        return crate::fake_worker::run(&argv[2..]);
    }
    let cli = Cli::parse();
    let ctx = Context::new(&cli);
    let result = match &cli.command {
        Command::SelfTest(args) => cmd_self_test(&ctx, args),
        Command::Search(args) => cmd_search(&ctx, args),
        Command::Verify(args) => cmd_verify(&ctx, args),
        Command::Replay(args) => cmd_replay(&ctx, args),
        Command::Report(args) => cmd_report(&ctx, args),
    };
    match result {
        Ok(outcome) => {
            if outcome != Outcome::Completed {
                say(&format!(
                    "finished as {outcome:?} (exit {})",
                    outcome.exit_code()
                ));
            }
            ExitCode::from(outcome.exit_code())
        }
        Err(error) => {
            say(&format!("error: {error}"));
            ExitCode::from(Outcome::Failed.exit_code())
        }
    }
}
