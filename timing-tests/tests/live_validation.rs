use std::path::PathBuf;

use tpms_timing_tests::measure::{LoadOrder, LoadedPair, Measurer, WorkerMeasurer};
use tpms_timing_tests::scenario::{PreparedPair, Scenario, Validation, scenario_seeds};
use tpms_timing_tests::worker::{BackendName, BackendSpec, Limits, WorkerBinary, build_worker};

struct Live {
    worker: WorkerBinary,
    library: PathBuf,
    work: PathBuf,
}

fn live() -> Option<&'static Live> {
    static LIVE: std::sync::OnceLock<Option<Live>> = std::sync::OnceLock::new();
    LIVE.get_or_init(build_live).as_ref()
}

fn build_live() -> Option<Live> {
    let library = PathBuf::from(std::env::var_os("TPMS_TIMING_RUST_LIB")?);
    let work = PathBuf::from(
        std::env::var_os("TPMS_TIMING_WORK_DIR")
            .unwrap_or_else(|| std::ffi::OsString::from("../target/timing-tests")),
    );
    let include = PathBuf::from(
        std::env::var_os("TPMS_TIMING_INCLUDE")
            .unwrap_or_else(|| std::ffi::OsString::from("../libtpms/include")),
    );
    let worker = build_worker(&work, &include).expect("worker builds on the measurement host");
    Some(Live {
        worker,
        library,
        work,
    })
}

fn gate(live: &Live, prepared: &PreparedPair) -> Result<usize, String> {
    let backend = BackendSpec::Library {
        name: BackendName::Rust,
        path: live.library.clone(),
    };
    let stderr = live.work.join("live-gate-stderr.log");
    let mut measurer =
        WorkerMeasurer::start(&live.worker.path, backend, None, &stderr, Limits::default())
            .map_err(|e| e.to_string())?;
    let loaded = measurer
        .load(prepared, LoadOrder::ClassAFirst)
        .map_err(|e| e.to_string())?;
    let gated = tpms_timing_tests::search::functional_gate(&mut measurer, prepared, &loaded);
    let measured = match &gated {
        Ok(()) => {
            let raw = measurer
                .measure(&loaded, 8, 1, 0x1234)
                .map_err(|e| e.to_string())?;
            raw.class0.len()
        }
        Err(_) => 0,
    };
    measurer.close_checked().map_err(|e| e.to_string())?;
    gated.map(|()| measured).map_err(|e| e.to_string())
}

fn run(live: &Live, prepared: &PreparedPair) -> Result<(), String> {
    let backend = BackendSpec::Library {
        name: BackendName::Rust,
        path: live.library.clone(),
    };
    let stderr = live.work.join("live-validation-stderr.log");
    let mut measurer =
        WorkerMeasurer::start(&live.worker.path, backend, None, &stderr, Limits::default())
            .map_err(|e| e.to_string())?;
    let loaded = measurer
        .load(prepared, LoadOrder::ClassAFirst)
        .map_err(|e| e.to_string())?;
    let responses = measurer.execute_once(&loaded);
    let records = measurer.validation_records();
    let responses = responses.map_err(|e| e.to_string())?;
    measurer.close_checked().map_err(|e| e.to_string())?;
    for (class, (prep, response)) in prepared.classes.iter().zip(&responses).enumerate() {
        prep.validate(response)
            .map_err(|e| format!("class {class}: {e}"))?;
    }
    if records.is_empty() {
        return Err("no validation step ran".into());
    }
    Ok(())
}

fn start(live: &Live, label: &str) -> Result<WorkerMeasurer, String> {
    let backend = BackendSpec::Library {
        name: BackendName::Rust,
        path: live.library.clone(),
    };
    WorkerMeasurer::start(
        &live.worker.path,
        backend,
        None,
        &live.work.join(format!("live-{label}-stderr.log")),
        Limits::default(),
    )
    .map_err(|e| e.to_string())
}

fn measure_with(
    measurer: &mut WorkerMeasurer,
    prepared: &PreparedPair,
    warmup: usize,
) -> Result<usize, String> {
    let loaded = measurer
        .load(prepared, LoadOrder::ClassAFirst)
        .map_err(|e| e.to_string())?;
    tpms_timing_tests::search::functional_gate(measurer, prepared, &loaded)
        .map_err(|e| e.to_string())?;
    let raw = measurer
        .measure(&loaded, 8, warmup, 0x5eed)
        .map_err(|e| e.to_string())?;
    Ok(raw.class0.len())
}

fn attempt(measurer: &mut WorkerMeasurer, prepared: &PreparedPair) -> Result<usize, String> {
    let loaded = measurer
        .load(prepared, LoadOrder::ClassAFirst)
        .map_err(|e| e.to_string())?;
    tpms_timing_tests::search::functional_gate(measurer, prepared, &loaded)
        .map_err(|e| e.to_string())?;
    let raw = measurer
        .measure(&loaded, 8, 1, 0x5eed)
        .map_err(|e| e.to_string())?;
    Ok(raw.class0.len())
}

fn tamper_parameters(prepared: &mut PreparedPair, class: usize) {
    match prepared.classes[class]
        .validation
        .as_mut()
        .expect("salted sessions carry a derived-key validation")
    {
        Validation::SaltedSession(v) => {
            assert!(!v.expected_parameters.is_empty());
            let last = v.expected_parameters.len() - 1;
            v.expected_parameters[last] ^= 0x01;
        }
    }
}

fn tamper(prepared: &mut PreparedPair, class: usize) {
    match prepared.classes[class]
        .validation
        .as_mut()
        .expect("salted sessions carry a derived-key validation")
    {
        Validation::SaltedSession(v) => {
            assert!(
                !v.salt.is_empty(),
                "the valid class must carry a derived salt"
            );
            v.salt[0] ^= 0x01;
        }
    }
}

#[test]
fn derived_session_key_is_checked_against_the_real_library() {
    let Some(live) = live() else {
        eprintln!("skipped: set TPMS_TIMING_RUST_LIB to a libtpms shared library to run this test");
        return;
    };
    for name in ["kdf-salted-session-rsa2048", "kdf-salted-session-p256"] {
        let scenario = Scenario::parse(name).unwrap();
        let seed = scenario_seeds(scenario, 1, 0)
            .into_iter()
            .find(|s| s.name.starts_with("valid-vs-valid") || s.name == "small-1-vs-random")
            .expect("a seed whose classes both derive a valid salt");
        let good = PreparedPair::prepare(scenario, seed.pair.clone());
        run(live, &good).unwrap_or_else(|e| panic!("{name}: valid session rejected: {e}"));

        let mut wrong = PreparedPair::prepare(scenario, seed.pair.clone());
        tamper(&mut wrong, 0);
        let error = run(live, &wrong).expect_err(&format!(
            "{name}: a wrong derived salt must fail the functional check"
        ));
        assert!(
            error.contains("TPM_RC_AUTH_FAIL") || error.contains("response authorization HMAC"),
            "{name}: unexpected failure {error}"
        );

        let samples = gate(live, &good)
            .unwrap_or_else(|e| panic!("{name}: the search gate rejected a valid pair: {e}"));
        assert_eq!(
            samples, 8,
            "{name}: a valid pair proceeds to timing samples"
        );
        let error = gate(live, &wrong).expect_err(&format!(
            "{name}: the search gate must reject a wrong derived session key before measuring"
        ));
        assert!(
            error.contains("different salt or session key"),
            "{name}: search gate failure does not name the derived-key mismatch: {error}"
        );
        assert!(
            error.contains("different salt or session key"),
            "{name}: failure does not name the derived-key mismatch: {error}"
        );
    }
}

#[test]
fn a_worker_recovers_after_a_failed_salted_session_validation() {
    let Some(live) = live() else {
        eprintln!("skipped: set TPMS_TIMING_RUST_LIB to a libtpms shared library to run this test");
        return;
    };
    for name in ["kdf-salted-session-rsa2048", "kdf-salted-session-p256"] {
        let scenario = Scenario::parse(name).unwrap();
        let seed = scenario_seeds(scenario, 1, 0)
            .into_iter()
            .find(|s| s.name.starts_with("valid-vs-valid") || s.name == "small-1-vs-random")
            .expect("a seed whose classes both derive a valid salt");
        let valid = PreparedPair::prepare(scenario, seed.pair.clone());

        for (kind, break_it) in [
            ("wrong salt", tamper as fn(&mut PreparedPair, usize)),
            ("wrong expected parameters", tamper_parameters),
        ] {
            let mut measurer = start(live, "recovery").unwrap();
            let mut broken = PreparedPair::prepare(scenario, seed.pair.clone());
            break_it(&mut broken, 0);

            let error = attempt(&mut measurer, &broken)
                .expect_err(&format!("{name}/{kind}: the invalid pair must be rejected"));
            assert!(
                error.contains("functional failure"),
                "{name}/{kind}: {error}"
            );
            assert!(
                measurer.unrecovered().is_none(),
                "{name}/{kind}: the worker must be recovered, not poisoned: {:?}",
                measurer.unrecovered()
            );

            let samples = attempt(&mut measurer, &valid).unwrap_or_else(|e| {
                panic!("{name}/{kind}: a valid pair failed on the reused worker: {e}")
            });
            assert_eq!(samples, 8, "{name}/{kind}: timing samples after recovery");

            for round in 0..3 {
                let error = attempt(&mut measurer, &broken)
                    .expect_err(&format!("{name}/{kind}: round {round}"));
                assert!(error.contains("functional failure"), "{error}");
                assert!(measurer.unrecovered().is_none(), "round {round}");
            }
            let samples = attempt(&mut measurer, &valid).unwrap_or_else(|e| {
                panic!("{name}/{kind}: repeated failures accumulated state: {e}")
            });
            assert_eq!(samples, 8);

            measurer
                .close_checked()
                .unwrap_or_else(|e| panic!("{name}/{kind}: worker shutdown failed: {e}"));
        }
    }
}

fn break_cleanup(prepared: &mut PreparedPair, class: usize) {
    let post = prepared.layout.post[class]
        .as_mut()
        .expect("salted sessions flush the session they create");
    let last = post.expected.len() - 1;
    post.expected[last] ^= 0x01;
}

#[test]
fn a_worker_whose_cleanup_fails_is_never_reused() {
    let Some(live) = live() else {
        eprintln!("skipped: set TPMS_TIMING_RUST_LIB to a libtpms shared library to run this test");
        return;
    };
    let scenario = Scenario::parse("kdf-salted-session-p256").unwrap();
    let seed = scenario_seeds(scenario, 1, 0)
        .into_iter()
        .find(|s| s.name == "small-1-vs-random")
        .unwrap();
    let valid = PreparedPair::prepare(scenario, seed.pair.clone());

    let mut measurer = start(live, "cleanup-only").unwrap();
    let mut cleanup_broken = PreparedPair::prepare(scenario, seed.pair.clone());
    break_cleanup(&mut cleanup_broken, 0);
    let error = attempt(&mut measurer, &cleanup_broken).expect_err("cleanup failure must fail");
    assert!(error.contains("cleanup command failed"), "{error}");
    let reason = measurer
        .unrecovered()
        .expect("a worker whose cleanup failed must be marked unrecovered");
    assert!(reason.contains("cleanup command failed"), "{reason}");
    let error = attempt(&mut measurer, &valid)
        .expect_err("an unrecovered worker must not accept another candidate");
    assert!(error.contains("refusing to reuse"), "{error}");
    drop(measurer);

    let mut measurer = start(live, "both-broken").unwrap();
    let mut both = PreparedPair::prepare(scenario, seed.pair.clone());
    tamper(&mut both, 0);
    break_cleanup(&mut both, 0);
    let error = attempt(&mut measurer, &both).expect_err("both failures must be reported");
    assert!(
        error.contains("different salt or session key"),
        "the original validation failure must stay visible: {error}"
    );
    assert!(
        error.contains("could not be restored"),
        "the cleanup failure must be reported as additional context: {error}"
    );
    assert!(measurer.unrecovered().is_some());
    let error = attempt(&mut measurer, &valid).expect_err("no reuse after an unrecovered worker");
    assert!(error.contains("refusing to reuse"), "{error}");
}

fn loaded_for(
    measurer: &mut WorkerMeasurer,
    prepared: &PreparedPair,
) -> Result<LoadedPair, String> {
    let loaded = measurer
        .load(prepared, LoadOrder::ClassAFirst)
        .map_err(|e| e.to_string())?;
    tpms_timing_tests::search::functional_gate(measurer, prepared, &loaded)
        .map_err(|e| e.to_string())?;
    Ok(loaded)
}

fn break_measured_expectation(loaded: &mut LoadedPair, class: usize) {
    let len = loaded.expected[class].len();
    loaded.masks[class] = vec![0xff; len];
    loaded.expected[class][len - 1] ^= 0x01;
}

fn break_measured_cleanup(loaded: &mut LoadedPair, class: usize) {
    let (_, expected) = loaded.posts[class]
        .as_mut()
        .expect("salted sessions flush the session they create");
    let last = expected.len() - 1;
    expected[last] ^= 0x01;
}

#[test]
fn a_worker_recovers_after_a_measurement_stage_failure() {
    let Some(live) = live() else {
        eprintln!("skipped: set TPMS_TIMING_RUST_LIB to a libtpms shared library to run this test");
        return;
    };
    for name in ["kdf-salted-session-rsa2048", "kdf-salted-session-p256"] {
        let scenario = Scenario::parse(name).unwrap();
        let seed = scenario_seeds(scenario, 1, 0)
            .into_iter()
            .find(|s| s.name.starts_with("valid-vs-valid") || s.name == "small-1-vs-random")
            .expect("a seed whose classes both derive a valid salt");
        let valid = PreparedPair::prepare(scenario, seed.pair.clone());

        for warmup in [0usize, 2] {
            let label = format!("{name}/warmup {warmup}");
            let mut measurer = start(live, "measure-recovery").unwrap();

            let mut broken = loaded_for(&mut measurer, &valid).unwrap();
            break_measured_expectation(&mut broken, 1);
            let error = measurer
                .measure(&broken, 8, warmup, 0x5eed)
                .expect_err(&format!("{label}: the mismatching measurement must fail"));
            let text = error.to_string();
            assert!(
                text.contains("unexpected response"),
                "{label}: the original mismatch detail must survive cleanup: {text}"
            );
            assert!(
                text.contains("0200000000"),
                "{label}: the original response bytes must be reported: {text}"
            );
            assert!(
                !text.contains("cleanup command"),
                "{label}: a mismatch must stay distinguishable from a cleanup failure: {text}"
            );
            assert!(
                measurer.unrecovered().is_none(),
                "{label}: the worker must recover: {:?}",
                measurer.unrecovered()
            );

            let samples = measure_with(&mut measurer, &valid, warmup)
                .unwrap_or_else(|e| panic!("{label}: a valid pair failed after recovery: {e}"));
            assert_eq!(samples, 8, "{label}");

            for round in 0..3 {
                let mut broken = loaded_for(&mut measurer, &valid).unwrap();
                break_measured_expectation(&mut broken, 1);
                assert!(
                    measurer.measure(&broken, 8, warmup, 0x5eed).is_err(),
                    "{label}: round {round}"
                );
                assert!(measurer.unrecovered().is_none(), "{label}: round {round}");
            }
            let samples = measure_with(&mut measurer, &valid, warmup)
                .unwrap_or_else(|e| panic!("{label}: repeated failures accumulated state: {e}"));
            assert_eq!(samples, 8, "{label}");
            measurer.close_checked().unwrap();
        }
    }
}

#[test]
fn a_measurement_cleanup_failure_blocks_further_execution() {
    let Some(live) = live() else {
        eprintln!("skipped: set TPMS_TIMING_RUST_LIB to a libtpms shared library to run this test");
        return;
    };
    for name in ["kdf-salted-session-rsa2048", "kdf-salted-session-p256"] {
        let scenario = Scenario::parse(name).unwrap();
        let seed = scenario_seeds(scenario, 1, 0)
            .into_iter()
            .find(|s| s.name.starts_with("valid-vs-valid") || s.name == "small-1-vs-random")
            .unwrap();
        let valid = PreparedPair::prepare(scenario, seed.pair.clone());
        for warmup in [0usize, 2] {
            let label = format!("{name}/warmup {warmup}");
            let mut measurer = start(live, "measure-cleanup").unwrap();
            let mut broken = loaded_for(&mut measurer, &valid).unwrap();
            break_measured_cleanup(&mut broken, 0);
            let error = measurer
                .measure(&broken, 8, warmup, 0x5eed)
                .expect_err(&format!(
                    "{label}: a failing cleanup must fail the measurement"
                ));
            let text = error.to_string();
            assert!(
                text.contains("cleanup command"),
                "{label}: a cleanup failure must be named as such: {text}"
            );
            let reason = measurer
                .unrecovered()
                .unwrap_or_else(|| panic!("{label}: the worker must be blocked"));
            assert!(
                reason.contains("restored") || reason.contains("cleanup"),
                "{label}: {reason}"
            );
            let error = measure_with(&mut measurer, &valid, warmup)
                .expect_err("a blocked worker must not run another candidate");
            assert!(error.contains("refusing to reuse"), "{label}: {error}");
            drop(measurer);
        }
    }
}
