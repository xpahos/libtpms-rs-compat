use std::path::PathBuf;
use std::sync::Barrier;

use tpms_timing_tests::identity::sha256_file;
use tpms_timing_tests::scenario::Scenario;
use tpms_timing_tests::worker::{
    BackendSpec, DUDECT_REVISION, Limits, WorkerProcess, build_worker, ensure_dudect,
};

#[test]
fn live_concurrent_cold_cache_builds_start_every_returned_worker() {
    let Some(work) = std::env::var_os("TPMS_TIMING_WORK_DIR") else {
        eprintln!("native cache regression skipped: set TPMS_TIMING_WORK_DIR");
        return;
    };
    let work = PathBuf::from(work);
    let include = PathBuf::from(
        std::env::var_os("TPMS_TIMING_INCLUDE").unwrap_or_else(|| "../libtpms/include".into()),
    );
    let source = ensure_dudect(&work).unwrap();
    let cold = work.join(format!("concurrent-cold-cache-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&cold);
    let deps = cold.join("deps").join(format!("dudect-{DUDECT_REVISION}"));
    std::fs::create_dir_all(&deps).unwrap();
    // Use the verified pinned dependency, avoiding network availability in this race test.
    std::fs::copy(source.header, deps.join("dudect.h")).unwrap();
    std::fs::copy(source.license, deps.join("LICENSE")).unwrap();
    let barrier = Barrier::new(8);
    std::thread::scope(|scope| {
        let builds: Vec<_> = (0..8)
            .map(|index| {
                let barrier = &barrier;
                let cold = &cold;
                let include = &include;
                scope.spawn(move || {
                    barrier.wait();
                    let binary = build_worker(cold, include).unwrap();
                    let worker = WorkerProcess::spawn(
                        &binary.path,
                        &BackendSpec::Control {
                            scenario: Scenario::ControlNegative,
                        },
                        None,
                        &cold.join(format!("worker-{index}.log")),
                        Limits::default(),
                    )
                    .unwrap();
                    worker.close().unwrap();
                    assert_eq!(binary.sha256, sha256_file(&binary.path).unwrap());
                    binary
                })
            })
            .collect();
        let binaries: Vec<_> = builds
            .into_iter()
            .map(|build| build.join().unwrap())
            .collect();
        for binary in &binaries {
            assert_eq!(binary.path, binaries[0].path);
            assert_eq!(binary.sha256, binaries[0].sha256);
        }
    });
}
