use tpms_timing_tests::scenario::{PreparedPair, Scenario, scenario_seeds};

#[test]
fn remaining_auth_families_are_registered_and_keep_semantic_outcomes() {
    for (name, rc) in [
        ("auth-hmac-sha256-none", 0x9a2),
        ("auth-hmac-sha1-aes128-cfb", 0x9a2),
        ("auth-hmac-sha512-xor", 0x9a2),
        ("integrity-import-rsa2048-outer", 0x3df),
        ("integrity-import-p256-inner", 0x3df),
        ("integrity-import-rsa2048-layered", 0x3df),
        ("integrity-rewrap-rsa2048-null", 0x1df),
    ] {
        let scenario = Scenario::parse(name).unwrap_or_else(|e| panic!("{name}: {e}"));
        let seeds = scenario_seeds(scenario, 3, 1);
        for seed in seeds {
            let prepared = PreparedPair::try_prepare(scenario, seed.pair.clone()).unwrap();
            let expected = [seed.pair.a, seed.pair.b]
                .map(|delta| if delta.iter().all(|b| *b == 0) { 0 } else { rc });
            assert_eq!(
                prepared.metadata.expected_response_codes, expected,
                "{name}"
            );
        }
    }
}

fn remaining(s: Scenario) -> bool {
    matches!(
        s,
        Scenario::HmacAuth(..)
            | Scenario::HmacAuthBound(..)
            | Scenario::HmacAuthSalted
            | Scenario::HmacAuthRequest(..)
            | Scenario::HmacAuthBoundSecret(..)
            | Scenario::HmacAuthSaltedSecret
            | Scenario::HmacAuthRequestSecret(..)
            | Scenario::Import(..)
            | Scenario::Duplicate(..)
            | Scenario::Rewrap(..)
    )
}

#[test]
fn live_remaining_auth_all_configs_both_load_orders_and_fresh_verify_workers() {
    use std::{fs, path::PathBuf};
    use tpms_timing_tests::{
        measure::{LoadOrder, Measurer, WorkerMeasurer},
        scenario::all_scenarios,
        verify::{VerifyConfig, dudect_plan},
        worker::{BackendName, BackendSpec, DudectStatus, Limits, build_worker, run_dudect},
    };
    let Some(library) = std::env::var_os("TPMS_TIMING_RUST_LIB") else {
        eprintln!("native remaining auth skipped: set TPMS_TIMING_RUST_LIB");
        return;
    };
    let work = PathBuf::from(
        std::env::var_os("TPMS_TIMING_WORK_DIR").unwrap_or_else(|| "../target/timing-tests".into()),
    );
    let include = PathBuf::from(
        std::env::var_os("TPMS_TIMING_INCLUDE").unwrap_or_else(|| "../libtpms/include".into()),
    );
    fs::create_dir_all(&work).unwrap();
    let worker = build_worker(&work, &include).unwrap();
    let backend = BackendSpec::Library {
        name: BackendName::Rust,
        path: library.into(),
    };
    let mut measurer = WorkerMeasurer::start(
        &worker.path,
        backend.clone(),
        None,
        &work.join("remaining-auth.log"),
        Limits::default(),
    )
    .unwrap();
    let filter = std::env::var("TPMS_TIMING_AUTH_FILTER").ok();
    let invocation = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    for scenario in all_scenarios()
        .into_iter()
        .filter(|s| remaining(*s))
        .filter(|s| filter.as_ref().is_none_or(|f| s.name().contains(f)))
    {
        eprintln!("native remaining auth: {scenario}");
        for seed in scenario_seeds(scenario, 17, 1) {
            let prepared = PreparedPair::prepare(scenario, seed.pair);
            for order in [LoadOrder::ClassAFirst, LoadOrder::ClassBFirst] {
                let label = format!("{scenario}/{} {order:?}", seed.name);
                let loaded = measurer
                    .load(&prepared, order)
                    .unwrap_or_else(|e| panic!("{label} setup: {e}"));
                let responses = measurer
                    .execute_once(&loaded)
                    .unwrap_or_else(|e| panic!("{label} execute: {e}"));
                for (class, response) in responses.iter().enumerate() {
                    prepared.classes[class]
                        .validate(response)
                        .unwrap_or_else(|e| panic!("{label} class{class} oracle: {e}"));
                    // Corrupt random/cryptographically checked bytes rather than only framing.
                    for index in [16, response.len() / 2, response.len().saturating_sub(1)] {
                        if response.len() <= 10 {
                            continue;
                        }
                        let mut bad = response.clone();
                        bad[index] ^= 1;
                        assert!(
                            prepared.classes[class].validate(&bad).is_err(),
                            "{label} accepted corruption at {index}"
                        );
                    }
                }
                let batch = measurer
                    .measure(&loaded, 8, 2, 17)
                    .unwrap_or_else(|e| panic!("{label} repeat beyond session capacity: {e}"));
                assert_eq!(batch.class0.len(), 8);
                assert_eq!(batch.class1.len(), 8);
                if seed.name.ends_with("vs-valid") || seed.name.ends_with("vs-baseline") {
                    let config = VerifyConfig {
                        disable_known_case_skips: true,
                        budget: 64,
                        batch: 32,
                        repeats: 1,
                        warmup: 2,
                        time_limit_s: 10.,
                        cpu: None,
                        max_candidates: 1,
                        seed_diagnostics: 0,
                        include_seed_diagnostics: false,
                    };
                    let plan = dudect_plan(&backend, &prepared, order, &config);

                    let outcome = run_dudect(
                        &worker.path,
                        &plan,
                        &work.join(format!(
                            "remaining-auth-{invocation}-{}-{}-{order:?}",
                            scenario.name(),
                            seed.name
                        )),
                        std::time::Duration::from_secs(30),
                    )
                    .unwrap();
                    assert!(
                        matches!(
                            outcome.status,
                            DudectStatus::LeakageFound
                                | DudectStatus::BudgetExhausted
                                | DudectStatus::InsufficientMeasurements
                        ),
                        "{label} fresh verify: {outcome:?}"
                    );
                    assert_eq!(outcome.measurements, 64, "{label}: measured budget");
                    assert_eq!(outcome.batches, 2, "{label}: completed batches");
                    assert_eq!(outcome.nv_stores, 0, "{label}: unexpected NV writes");
                }
            }
        }
    }
    measurer.close_checked().unwrap();
}

#[test]
fn live_auth_consumer_failure_refuses_same_worker_reuse() {
    use std::path::PathBuf;
    use tpms_timing_tests::{
        measure::{LoadOrder, Measurer, WorkerMeasurer},
        program::Program,
        worker::{BackendName, BackendSpec, Limits, build_worker},
    };
    let Some(library) = std::env::var_os("TPMS_TIMING_RUST_LIB") else {
        eprintln!("native auth consumer failure skipped: set TPMS_TIMING_RUST_LIB");
        return;
    };
    let work = PathBuf::from(
        std::env::var_os("TPMS_TIMING_WORK_DIR").unwrap_or_else(|| "../target/timing-tests".into()),
    );
    let include = PathBuf::from(
        std::env::var_os("TPMS_TIMING_INCLUDE").unwrap_or_else(|| "../libtpms/include".into()),
    );
    let worker = build_worker(&work, &include).unwrap();
    let backend = BackendSpec::Library {
        name: BackendName::Rust,
        path: library.into(),
    };
    for name in ["auth-hmac-sha256-none", "duplicate-null-supplied"] {
        let scenario = Scenario::parse(name).unwrap();
        let good = PreparedPair::prepare(
            scenario,
            scenario_seeds(scenario, 1, 0)
                .into_iter()
                .find(|s| s.pair.a == s.pair.b)
                .unwrap()
                .pair,
        );
        let mut bad = good.clone();
        for class in 0..2 {
            let mut program = Program::decode(&bad.layout.measured[class].command).unwrap();
            // A consumer error after real session allocation must never become a timing sample.
            program.steps.last_mut().unwrap().command[6..10]
                .copy_from_slice(&0xffff_ffffu32.to_be_bytes());
            let encoded = program.encode().unwrap();
            bad.layout.measured[class].command = encoded.bytes;
            bad.layout.measured[class].handles[0].0 =
                encoded.command_offsets[program.steps.len() - 1] + 10;
        }
        for warmup in [None, Some(0), Some(2)] {
            let mut measurer = WorkerMeasurer::start(
                &worker.path,
                backend.clone(),
                None,
                &work.join(format!("auth-consumer-failure-{name}-{warmup:?}.log")),
                Limits::default(),
            )
            .unwrap();
            let loaded = measurer.load(&bad, LoadOrder::ClassAFirst).unwrap();
            if let Some(warmup) = warmup {
                assert!(measurer.measure(&loaded, 8, warmup, 17).is_err());
            } else {
                assert!(measurer.execute_once(&loaded).is_err());
            }
            assert!(
                measurer.unrecovered().is_some(),
                "{name}: poisoned interpreter must reach supervisor"
            );
            assert!(
                measurer.load(&good, LoadOrder::ClassAFirst).is_err(),
                "{name}: same-worker recovery must be refused"
            );
            measurer.close_checked().unwrap();
        }
    }
}
