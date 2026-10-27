use tpms_timing_tests::measure::LoadOrder;
use tpms_timing_tests::scenario::{
    Area, DifferenceKind, PreparedPair, all_scenarios, scenario_seeds,
};

#[test]
fn integrity_boundaries_have_independent_outcomes_and_public_input_classification() {
    for scenario in all_scenarios().into_iter().filter(|s| {
        s.area() == Area::AuthenticationIntegrity
            && matches!(
                s,
                tpms_timing_tests::scenario::Scenario::PasswordAuth
                    | tpms_timing_tests::scenario::Scenario::SignTicket
                    | tpms_timing_tests::scenario::Scenario::ActivateCredential(_)
                    | tpms_timing_tests::scenario::Scenario::LoadIntegrity(_)
            )
    }) {
        let seeds = scenario_seeds(scenario, 17, 2);
        let mismatch = seeds
            .iter()
            .find(|s| s.name == "mismatch-first-byte-vs-last-byte")
            .unwrap_or_else(|| panic!("{scenario}: missing same-outcome mismatch boundary"));
        let prepared = PreparedPair::try_prepare(scenario, mismatch.pair.clone()).unwrap();
        assert_eq!(
            prepared.metadata.difference,
            DifferenceKind::PublicInput,
            "{scenario}"
        );
        let expected_error = match scenario {
            tpms_timing_tests::scenario::Scenario::PasswordAuth => 0x9a2,
            tpms_timing_tests::scenario::Scenario::SignTicket => 0x3e0,
            _ => 0x1df,
        };
        assert_eq!(
            prepared.metadata.expected_response_codes, [expected_error; 2],
            "{scenario}"
        );
        for order in [LoadOrder::ClassAFirst, LoadOrder::ClassBFirst] {
            let resolved = prepared.resolve(order);
            assert_eq!(resolved.measured[0].len(), resolved.measured[1].len());
        }
        let valid = seeds
            .iter()
            .find(|s| s.name == "valid-vs-mismatch-last-byte")
            .unwrap();
        let prepared = PreparedPair::try_prepare(scenario, valid.pair.clone()).unwrap();
        assert_eq!(
            prepared.metadata.expected_response_codes,
            [0, expected_error],
            "{scenario}"
        );
        assert_eq!(prepared.metadata.difference, DifferenceKind::VisibleOutcome);
    }
}

#[test]
fn successful_integrity_responses_reject_corrupted_results() {
    for scenario in all_scenarios().into_iter().filter(|s| {
        s.area() == Area::AuthenticationIntegrity
            && matches!(
                s,
                tpms_timing_tests::scenario::Scenario::PasswordAuth
                    | tpms_timing_tests::scenario::Scenario::SignTicket
                    | tpms_timing_tests::scenario::Scenario::ActivateCredential(_)
                    | tpms_timing_tests::scenario::Scenario::LoadIntegrity(_)
            )
    }) {
        let seed = scenario_seeds(scenario, 1, 0)
            .into_iter()
            .find(|s| s.name == "valid-vs-valid")
            .unwrap();
        let prepared = PreparedPair::prepare(scenario, seed.pair);
        let expected = &prepared.classes[0];
        expected.validate(&expected.expected_response).unwrap();
        let mut response = expected.expected_response.clone();
        // Corrupt child Name, signature bytes, MAC bytes or recovered credential.
        let at = if matches!(
            scenario,
            tpms_timing_tests::scenario::Scenario::LoadIntegrity(_)
                | tpms_timing_tests::scenario::Scenario::SignTicket
        ) {
            20
        } else {
            16
        };
        response[at] ^= 1;
        assert!(
            expected.validate(&response).is_err(),
            "{scenario}: corrupted successful result was accepted"
        );
    }
}

#[test]
fn live_integrity_boundaries_reuse_the_worker_and_reject_wrong_expectations() {
    use std::path::PathBuf;
    use tpms_timing_tests::measure::{Measurer, WorkerMeasurer};
    use tpms_timing_tests::worker::{BackendName, BackendSpec, Limits, build_worker};
    let Some(library) = std::env::var_os("TPMS_TIMING_RUST_LIB") else {
        eprintln!("skipped native integrity execution: set TPMS_TIMING_RUST_LIB");
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
    let mut measurer = WorkerMeasurer::start(
        &worker.path,
        backend,
        None,
        &work.join("integrity-live-stderr.log"),
        Limits::default(),
    )
    .unwrap();
    for scenario in all_scenarios().into_iter().filter(|s| {
        s.area() == Area::AuthenticationIntegrity
            && matches!(
                s,
                tpms_timing_tests::scenario::Scenario::PasswordAuth
                    | tpms_timing_tests::scenario::Scenario::SignTicket
                    | tpms_timing_tests::scenario::Scenario::ActivateCredential(_)
                    | tpms_timing_tests::scenario::Scenario::LoadIntegrity(_)
            )
    }) {
        for seed in scenario_seeds(scenario, 17, 1) {
            let prepared = PreparedPair::prepare(scenario, seed.pair);
            for order in [LoadOrder::ClassAFirst, LoadOrder::ClassBFirst] {
                let label = format!("{scenario}/{} {order:?}", seed.name);
                let loaded = measurer
                    .load(&prepared, order)
                    .unwrap_or_else(|e| panic!("{label}: setup: {e}"));
                tpms_timing_tests::search::functional_gate(&mut measurer, &prepared, &loaded)
                    .unwrap_or_else(|e| panic!("{label}: gate: {e}"));
                let batch = measurer
                    .measure(&loaded, 8, 2, 0x17)
                    .unwrap_or_else(|e| panic!("{label}: repeated measurement: {e}"));
                assert_eq!(batch.class0.len(), 8, "{label}");
                assert_eq!(batch.class1.len(), 8, "{label}");
                if seed.name == "valid-vs-valid" {
                    let mut wrong = prepared.clone();
                    let at = if matches!(
                        scenario,
                        tpms_timing_tests::scenario::Scenario::LoadIntegrity(_)
                            | tpms_timing_tests::scenario::Scenario::SignTicket
                    ) {
                        20
                    } else {
                        16
                    };
                    wrong.classes[0].expected_response[at] ^= 1;
                    let bad = measurer.load(&wrong, order).unwrap();
                    assert!(
                        tpms_timing_tests::search::functional_gate(&mut measurer, &wrong, &bad)
                            .is_err(),
                        "{label}: wrong independent result passed"
                    );
                    assert!(
                        measurer.unrecovered().is_none(),
                        "{label}: failed validation poisoned worker"
                    );
                    let loaded = measurer.load(&prepared, order).unwrap();
                    tpms_timing_tests::search::functional_gate(&mut measurer, &prepared, &loaded)
                        .unwrap();
                }
            }
        }
        if matches!(
            scenario,
            tpms_timing_tests::scenario::Scenario::LoadIntegrity(_)
        ) {
            for order in [LoadOrder::ClassAFirst, LoadOrder::ClassBFirst] {
                unexpected_load_success_is_cleaned_up(&mut measurer, scenario, order);
            }
        }
    }
    measurer.close_checked().unwrap();
}

fn unexpected_load_success_is_cleaned_up(
    measurer: &mut tpms_timing_tests::measure::WorkerMeasurer,
    scenario: tpms_timing_tests::scenario::Scenario,
    order: LoadOrder,
) {
    use tpms_timing_tests::measure::Measurer;
    let seeds = scenario_seeds(scenario, 1, 0);
    let invalid = seeds
        .iter()
        .find(|s| s.name == "mismatch-first-byte-vs-last-byte")
        .unwrap();
    let valid = seeds.iter().find(|s| s.name == "valid-vs-valid").unwrap();
    let valid = PreparedPair::prepare(scenario, valid.pair.clone());
    for stage in [None, Some(0), Some(2)] {
        let label = format!("{scenario}/{order:?}/unexpected-success stage {stage:?}");
        // Keep the invalid-input case's expected INTEGRITY response and cleanup
        // plan, but send a valid blob. This reproduces the state created if a
        // faulty backend accepts a corrupt HMAC without modifying that backend.
        let mut unexpected = PreparedPair::prepare(scenario, invalid.pair.clone());
        for measured in &mut unexpected.layout.measured {
            for patch in &mut measured.patches {
                patch.xor.fill(0);
            }
        }
        let loaded = measurer.load(&unexpected, order).unwrap();
        let error = if let Some(warmup) = stage {
            measurer
                .measure(&loaded, 8, warmup, 0x17)
                .expect_err(&format!("{label}: unexpected acceptance must fail"))
                .to_string()
        } else {
            tpms_timing_tests::search::functional_gate(measurer, &unexpected, &loaded)
                .expect_err(&format!("{label}: unexpected acceptance must fail"))
                .to_string()
        };
        assert!(
            error.contains("functional failure"),
            "{label}: original error lost: {error}"
        );
        assert!(
            error.contains("response"),
            "{label}: original response lost: {error}"
        );
        assert!(
            !error.contains("cleanup command failed"),
            "{label}: cleanup replaced the original failure: {error}"
        );
        assert!(
            measurer.unrecovered().is_none(),
            "{label}: worker marked unrecovered"
        );
        let loaded = measurer
            .load(&valid, order)
            .unwrap_or_else(|e| panic!("{label}: orphan child prevents setup reuse: {e}"));
        tpms_timing_tests::search::functional_gate(measurer, &valid, &loaded).unwrap_or_else(|e| {
            panic!("{label}: orphan child changes the next allocated handle: {e}")
        });
        let samples = measurer
            .measure(&loaded, 8, 2, 0x17)
            .unwrap_or_else(|e| panic!("{label}: measurement after recovery failed: {e}"));
        assert_eq!(samples.class0.len(), 8, "{label}");
        assert_eq!(samples.class1.len(), 8, "{label}");
    }
}
