use tpms_timing_tests::measure::{LoadOrder, Measurer, WorkerMeasurer};
use tpms_timing_tests::scenario::{
    Creates, InputPair, Patch, PreparedPair, Scenario, Step, StepRef,
};
use tpms_timing_tests::worker::{BackendName, BackendSpec, Limits, build_worker};
use tpms_timing_tests::{tpm, verify};

fn dependent_setup() -> PreparedPair {
    let mut pair = PreparedPair::prepare(
        Scenario::PasswordAuth,
        InputPair::new(vec![0; 32], vec![0; 32]),
    );
    let mut load = pair.layout.shared.remove(0);
    // LoadExternal's sensitive authValue starts at16; Name excludes this field.
    assert_eq!(&load.command[14..16], &32u16.to_be_bytes());
    load.command[16..48].fill(0);
    load.patches.push(Patch {
        at: 16,
        source: StepRef::Shared(0),
        from: 12,
        len: 32,
        xor: vec![0; 32],
    });
    let random = tpm::build_command(tpm::TPM_CC_GET_RANDOM, &[], &[], &32u16.to_be_bytes()).bytes;
    pair.layout.shared = vec![
        Step::new("fresh password", random).creates(Creates::Nothing),
        load,
    ];
    for step in &mut pair.layout.measured {
        assert_eq!(&step.command[25..27], &32u16.to_be_bytes());
        step.patches.push(Patch {
            at: 27,
            source: StepRef::Shared(0),
            from: 12,
            len: 32,
            xor: vec![0; 32],
        });
    }
    pair
}

#[test]
fn live_dependent_setup_uses_prior_response_in_measurement_and_fresh_dudect_worker() {
    use std::path::PathBuf;
    let Some(library) = std::env::var_os("TPMS_TIMING_RUST_LIB") else {
        return;
    };
    let work = PathBuf::from(std::env::var_os("TPMS_TIMING_WORK_DIR").expect("work directory"));
    let include =
        PathBuf::from(std::env::var_os("TPMS_TIMING_INCLUDE").expect("include directory"));
    let binary = build_worker(&work, &include).unwrap();
    let backend = BackendSpec::Library {
        name: BackendName::Rust,
        path: library.into(),
    };
    let pair = dependent_setup();
    let mut worker = WorkerMeasurer::start(
        &binary.path,
        backend.clone(),
        None,
        &work.join("setup-patches.log"),
        Limits::default(),
    )
    .unwrap();
    for order in [LoadOrder::ClassAFirst, LoadOrder::ClassBFirst] {
        let loaded = worker.load(&pair, order).unwrap();
        tpms_timing_tests::search::functional_gate(&mut worker, &pair, &loaded).unwrap();
        worker.measure(&loaded, 8, 2, 17).unwrap();
        let config = verify::VerifyConfig {
            disable_known_case_skips: false,
            budget: 64,
            batch: 32,
            repeats: 2,
            warmup: 2,
            time_limit_s: 5.0,
            cpu: None,
            max_candidates: 1,
            seed_diagnostics: 0,
            include_seed_diagnostics: false,
        };
        let plan = verify::dudect_plan(&backend, &pair, order, &config);
        let text = plan.render().unwrap();
        assert!(
            text.contains("setup-patch 2 16 1 12 32 "),
            "startup must offset both setup source and destination"
        );
        let path = work.join(format!("setup-patches-{order:?}.plan"));
        std::fs::write(&path, text).unwrap();
        let output = std::process::Command::new(&binary.path)
            .arg("dudect")
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("status=insufficient-measurements measurements=64 batches=2"),
            "{stdout}"
        );
    }
    worker.close_checked().unwrap();
}
