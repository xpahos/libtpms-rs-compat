use num_bigint::BigUint;
use tpms_timing_tests::{
    oracle::{
        bytes::{from_be, to_fixed},
        ec::{Affine, CurveId},
        hash::HashAlg,
    },
    program::Program,
    scenario::{PreparedPair, Scenario, scenario_seeds},
    tpm,
};

fn point(curve: CurveId, p: &Affine) -> Vec<u8> {
    let (x, y) = curve.curve().encode(p);
    tpm::sized(&[tpm::sized(&x), tpm::sized(&y)].concat())
}
fn transcript(program: &Program, responses: &[Vec<u8>]) -> Vec<u8> {
    let mut p = b"TPTR\x01".to_vec();
    p.push(responses.len() as u8);
    for (step, response) in program.steps.iter().zip(responses) {
        tpm::put_u16(&mut p, response.len() as u16);
        tpm::put_u16(&mut p, step.slot);
        p.extend_from_slice(response);
        p.resize(p.len() + step.slot as usize - response.len(), 0);
    }
    tpm::success_response(&[], &p, 0)
}
fn params(command: &[u8]) -> &[u8] {
    let start = 18 + u32::from_be_bytes(command[14..18].try_into().unwrap()) as usize;
    &command[start..]
}
#[test]
fn ecdaa_independent_transcripts_accept_minimal_nonce_and_reject_each_significant_field() {
    for curve in CurveId::ALL {
        let s = Scenario::parse(&format!("ecdaa-commit-sign-{}", curve.name())).unwrap();
        let prepared = PreparedPair::prepare(s, scenario_seeds(s, 1, 0).remove(0).pair);
        let c = curve.curve();
        let d = from_be(&prepared.pair.a);
        let r = BigUint::from(13u32);
        let program = Program::decode(&prepared.layout.measured[0].command).unwrap();
        let cp = params(&program.steps[0].command);
        let (_, next) = tpm::read_2b(cp, 0).unwrap();
        let (s2, next) = tpm::read_2b(cp, next).unwrap();
        let (y2, _) = tpm::read_2b(cp, next).unwrap();
        let p2 = Affine {
            x: from_be(&HashAlg::Sha256.digest(&[s2])) % &c.p,
            y: from_be(y2),
        };
        assert!(c.on_curve(&p2));
        let mut commit = point(curve, &c.mul(&d, &p2).unwrap());
        commit.extend(point(curve, &c.mul(&r, &p2).unwrap()));
        commit.extend(point(curve, &c.mul_g(&r).unwrap()));
        commit.extend([0, 9]);
        let digest = tpm::read_2b(params(&program.steps[1].command), 0)
            .unwrap()
            .0;
        for nonce in [vec![1], to_fixed(&(&c.n - 1u32), c.order_bytes())] {
            let challenge = from_be(&HashAlg::Sha256.digest(&[&nonce, digest])) % &c.n;
            let s = (&r + challenge * &d) % &c.n;
            let mut signature = vec![0, 0x1a, 0, 0x0b];
            signature.extend(tpm::sized(&nonce));
            signature.extend(tpm::sized(&to_fixed(&s, c.order_bytes())));
            let good = [
                tpm::success_response(&[], &commit, 1),
                tpm::success_response(&[], &signature, 1),
            ];
            prepared.classes[0]
                .validate(&transcript(&program, &good))
                .unwrap();
            let width = 6 + 2 * c.bytes;
            for (step, index) in [
                (0, 14 + 6),
                (0, 14 + width + 6),
                (0, 14 + 2 * width + 6),
                (1, 14 + 1),
                (1, 14 + 3),
                (1, 14 + 6),
                (1, 14 + 8 + nonce.len()),
                (1, 14 + 4),
            ] {
                let mut bad = good.clone();
                bad[step][index] ^= 1;
                assert!(
                    prepared.classes[0]
                        .validate(&transcript(&program, &bad))
                        .is_err(),
                    "{curve:?} nonce{} step{step} byte{index}",
                    nonce.len()
                );
            }
            for step in 0..2 {
                let mut bad = good.clone();
                bad[step].pop();
                assert!(
                    prepared.classes[0]
                        .validate(&transcript(&program, &bad))
                        .is_err()
                );
            }
        }
    }
}
#[test]
fn ecc_catalog_covers_every_curve_hash_and_exchange_scheme() {
    for c in CurveId::ALL {
        for h in HashAlg::ALL {
            let s = Scenario::parse(&format!("ecc-decrypt-{}-{}", c.name(), h.name())).unwrap();
            for seed in scenario_seeds(s, 1, 1) {
                let p = PreparedPair::prepare(s, seed.pair);
                assert!(
                    p.metadata
                        .expected_response_codes
                        .iter()
                        .all(|rc| matches!(rc, 0 | 0x84))
                );
            }
        }
        for scheme in ["ecdh", "sm2", "ecmqv"] {
            let s = Scenario::parse(&format!("zgen-2phase-{scheme}-{}", c.name())).unwrap();
            let _ = PreparedPair::prepare(s, scenario_seeds(s, 1, 0).remove(0).pair);
        }
    }
}

fn native() -> Option<(
    std::path::PathBuf,
    tpms_timing_tests::worker::BackendSpec,
    std::path::PathBuf,
)> {
    use std::path::PathBuf;
    use tpms_timing_tests::worker::{BackendName, BackendSpec, build_worker};
    let library = std::env::var_os("TPMS_TIMING_RUST_LIB")?;
    let work = PathBuf::from(
        std::env::var_os("TPMS_TIMING_WORK_DIR").unwrap_or_else(|| "../target/timing-tests".into()),
    );
    let include = PathBuf::from(
        std::env::var_os("TPMS_TIMING_INCLUDE").unwrap_or_else(|| "../libtpms/include".into()),
    );
    std::fs::create_dir_all(&work).unwrap();
    let worker = build_worker(&work, &include).unwrap();
    let name = match std::env::var("TPMS_TIMING_BACKEND").as_deref() {
        Ok("reference") => BackendName::Reference,
        Ok("rust") | Err(_) => BackendName::Rust,
        Ok(other) => panic!("unknown TPMS_TIMING_BACKEND {other}"),
    };
    Some((
        worker.path,
        BackendSpec::Library {
            name,
            path: library.into(),
        },
        work,
    ))
}
#[test]
fn live_ecc_all_curves_hashes_both_load_orders_and_fresh_verify_workers() {
    use tpms_timing_tests::{
        measure::{LoadOrder, Measurer, WorkerMeasurer},
        scenario::{all_scenarios, catalog::ExchangeScheme},
        verify::{VerifyConfig, dudect_plan},
        worker::{DudectStatus, Limits, run_dudect},
    };
    let Some((worker, backend, work)) = native() else {
        eprintln!("native ECC skipped: set TPMS_TIMING_RUST_LIB");
        return;
    };
    let mut measurer = WorkerMeasurer::start(
        &worker,
        backend.clone(),
        None,
        &work.join("ecc-functional.log"),
        Limits::default(),
    )
    .unwrap();
    let filter = std::env::var("TPMS_TIMING_ECC_FILTER").ok();
    let invocation = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    for scenario in all_scenarios()
        .into_iter()
        .filter(|s| {
            matches!(
                s,
                Scenario::EccDecrypt(..)
                    | Scenario::Ecdaa(_)
                    | Scenario::Zgen(_, ExchangeScheme::Ecdh | ExchangeScheme::Sm2)
            )
        })
        .filter(|s| filter.as_ref().is_none_or(|f| s.name().contains(f)))
    {
        if let Some(issue) =
            tpms_timing_tests::known_issues::functional_skip(scenario, &backend.label())
        {
            eprintln!("native ECC SKIP {scenario}: {} {}", issue.id, issue.reason);
            continue;
        }
        eprintln!("native ECC: {scenario}");
        for (index, seed) in scenario_seeds(scenario, 17, 1).into_iter().enumerate() {
            let prepared = PreparedPair::prepare(scenario, seed.pair);
            for order in [LoadOrder::ClassAFirst, LoadOrder::ClassBFirst] {
                let label = format!("{scenario}/{} {order:?}", seed.name);
                let loaded = measurer
                    .load(&prepared, order)
                    .unwrap_or_else(|e| panic!("{label} load: {e}"));
                let responses = measurer
                    .execute_once(&loaded)
                    .unwrap_or_else(|e| panic!("{label} execute: {e}"));
                for (class, response) in responses.iter().enumerate() {
                    prepared.classes[class]
                        .validate(response)
                        .unwrap_or_else(|e| panic!("{label} class{class} oracle: {e}"));
                }
                // 132+ fresh producer/consumer pairs cross the 128-bit commit-array wrap.
                let rounds =
                    if index == 0 && matches!(scenario, Scenario::Ecdaa(_) | Scenario::Zgen(..)) {
                        66
                    } else {
                        4
                    };
                let batch = measurer
                    .measure(&loaded, rounds, 2, 17)
                    .unwrap_or_else(|e| panic!("{label} repeat: {e}"));
                assert_eq!(batch.class0.len(), rounds);
                assert_eq!(batch.class1.len(), rounds);
                if index == 0 {
                    let config = VerifyConfig {
                        disable_known_case_skips: false,
                        budget: 64,
                        batch: 32,
                        repeats: 1,
                        warmup: 2,
                        time_limit_s: 30.,
                        cpu: None,
                        max_candidates: 1,
                        seed_diagnostics: 0,
                        include_seed_diagnostics: false,
                    };
                    let plan = dudect_plan(&backend, &prepared, order, &config);
                    let outcome = run_dudect(
                        &worker,
                        &plan,
                        &work.join(format!("ecc-{invocation}-{scenario}-{order:?}")),
                        std::time::Duration::from_secs(60),
                    )
                    .unwrap();
                    assert!(
                        matches!(
                            outcome.status,
                            DudectStatus::LeakageFound
                                | DudectStatus::BudgetExhausted
                                | DudectStatus::InsufficientMeasurements
                        ),
                        "{label}: {outcome:?}"
                    );
                    assert_eq!(outcome.measurements, 64, "{label}");
                    assert_eq!(outcome.batches, 2);
                    assert_eq!(outcome.nv_stores, 0);
                }
            }
        }
    }
    measurer.close_checked().unwrap();
}
#[test]
fn live_ecc_consumer_errors_and_counter_corruption_refuse_worker_reuse() {
    use tpms_timing_tests::{
        measure::{LoadOrder, Measurer, WorkerMeasurer},
        program::Patch,
        worker::Limits,
    };
    let Some((worker, backend, work)) = native() else {
        return;
    };
    for name in CurveId::ALL.into_iter().flat_map(|curve| {
        [
            format!("ecdaa-commit-sign-{}", curve.name()),
            format!("zgen-2phase-ecdh-{}", curve.name()),
            format!("zgen-2phase-sm2-{}", curve.name()),
        ]
    }) {
        let scenario = Scenario::parse(&name).unwrap();
        let good = PreparedPair::prepare(scenario, scenario_seeds(scenario, 1, 0).remove(0).pair);
        for wrong_counter in [false, true] {
            for warmup in [None, Some(0), Some(2)] {
                let mut bad = good.clone();
                for class in 0..2 {
                    let mut p = Program::decode(&bad.layout.measured[class].command).unwrap();
                    if wrong_counter {
                        let Patch::Copy { xor, .. } = &mut p.steps[1].patches[0] else {
                            panic!()
                        };
                        xor[1] = 1;
                    } else {
                        // Successful producer, consumer rejected by TPM: corrupt the loaded handle.
                        p.steps[1].command[10..14].copy_from_slice(&0x80ffffffu32.to_be_bytes());
                        bad.layout.measured[class].handles.retain(|(at, _)| {
                            *at != Program::decode(&good.layout.measured[class].command)
                                .unwrap()
                                .encode()
                                .unwrap()
                                .command_offsets[1]
                                + 10
                        });
                    }
                    bad.layout.measured[class].command = p.encode().unwrap().bytes;
                }
                let mut m = WorkerMeasurer::start(
                    &worker,
                    backend.clone(),
                    None,
                    &work.join(format!("ecc-poison-{name}-{wrong_counter}-{warmup:?}.log")),
                    Limits::default(),
                )
                .unwrap();
                let loaded = m.load(&bad, LoadOrder::ClassAFirst).unwrap();
                if let Some(w) = warmup {
                    assert!(m.measure(&loaded, 4, w, 1).is_err());
                } else {
                    assert!(m.execute_once(&loaded).is_err());
                }
                assert!(m.unrecovered().is_some());
                assert!(m.load(&good, LoadOrder::ClassAFirst).is_err());
                m.close_checked().unwrap();
            }
        }
    }
}

#[test]
fn zgen_transcripts_check_actual_ephemeral_points_and_both_results() {
    use tpms_timing_tests::oracle::ecc::{sm2_associated_compat, sm2_associated_standard};
    for curve in CurveId::ALL {
        let c = curve.curve();
        let r = BigUint::from(13u32);
        let qe = c.mul_g(&r).unwrap();
        assert_ne!(
            sm2_associated_compat(c, &qe.x),
            sm2_associated_standard(c, &qe.x),
            "{curve:?}: standard SM2 deviation must stay explicit"
        );
        for scheme in ["ecdh", "sm2"] {
            let s = Scenario::parse(&format!("zgen-2phase-{scheme}-{}", curve.name())).unwrap();
            let prepared = PreparedPair::prepare(s, scenario_seeds(s, 1, 0).remove(0).pair);
            let d = from_be(&prepared.pair.a);
            let program = Program::decode(&prepared.layout.measured[0].command).unwrap();
            let mut ep = point(curve, &qe);
            ep.extend([0, 9]);
            let z1 = if scheme == "ecdh" {
                c.mul_g(&(&d * 5u32)).unwrap()
            } else {
                // Local-party equation, independently arranged from the peer-party oracle.
                let peer_static = c.mul_g(&BigUint::from(5u32)).unwrap();
                let peer_ephemeral = c.mul_g(&BigUint::from(11u32)).unwrap();
                let local_scalar = (&d + &r * sm2_associated_compat(c, &qe.x)) % &c.n;
                let peer = c
                    .mul_add(
                        &BigUint::from(1u32),
                        &peer_static,
                        &sm2_associated_compat(c, &peer_ephemeral.x),
                        &peer_ephemeral,
                    )
                    .unwrap();
                c.mul(&local_scalar, &peer).unwrap()
            };
            let mut z = point(curve, &z1);
            z.extend(if scheme == "ecdh" {
                point(curve, &c.mul_g(&(&r * 11u32)).unwrap())
            } else {
                vec![0, 4, 0, 0, 0, 0]
            });
            let good = [
                tpm::success_response(&[], &ep, 0),
                tpm::success_response(&[], &z, 1),
            ];
            prepared.classes[0]
                .validate(&transcript(&program, &good))
                .unwrap();
            for (step, start) in [(0, 10), (1, 14), (1, 14 + 6 + 2 * c.bytes)] {
                let mut bad = good.clone();
                if scheme == "sm2" && step == 1 && start > 14 {
                    bad[step][start + 5] = 1;
                } else {
                    bad[step][start..start + 6 + 2 * c.bytes].copy_from_slice(&point(curve, &c.g));
                }
                assert!(
                    prepared.classes[0]
                        .validate(&transcript(&program, &bad))
                        .is_err(),
                    "{scheme} {curve:?} step{step} at{start}"
                );
            }
            let mut bad = good.clone();
            bad[1][14] ^= 1;
            assert!(
                prepared.classes[0]
                    .validate(&transcript(&program, &bad))
                    .is_err()
            );
        }
    }
}
#[test]
fn live_ecc_known_failure_probes_are_isolated_and_original_worker_stays_usable() {
    use tpms_timing_tests::{
        measure::{LoadOrder, MeasureFailure, Measurer, WorkerMeasurer},
        worker::Limits,
    };
    let Some((worker, backend, work)) = native() else {
        return;
    };
    let mut m = WorkerMeasurer::start(
        &worker,
        backend.clone(),
        None,
        &work.join("ecc-known-failure-isolation.log"),
        Limits::default(),
    )
    .unwrap();
    for scenario in tpms_timing_tests::scenario::all_scenarios()
        .into_iter()
        .filter(|s| {
            tpms_timing_tests::known_issues::functional_skip(*s, &backend.label()).is_some()
        })
    {
        let Scenario::Zgen(curve, _) = scenario else {
            panic!("expected ECC known failure");
        };
        let bad = PreparedPair::prepare(scenario, scenario_seeds(scenario, 1, 0).remove(0).pair);
        let error = m.isolated_functional_probe(&bad).unwrap_err();
        assert!(
            matches!(error, MeasureFailure::Functional { .. }),
            "{curve:?}: {error}"
        );
        assert!(
            error.to_string().contains("80010000000a00000101"),
            "{scenario}: expected actual TPM failure-mode frame: {error}"
        );
        eprintln!("native ECC known failure {scenario}: {error}");
        assert!(m.unrecovered().is_none());
        let good_s = Scenario::parse(&format!("zgen-2phase-ecdh-{}", curve.name())).unwrap();
        let good = PreparedPair::prepare(good_s, scenario_seeds(good_s, 1, 0).remove(0).pair);
        let loaded = m.load(&good, LoadOrder::ClassAFirst).unwrap();
        let responses = m.execute_once(&loaded).unwrap();
        for (class, response) in responses.iter().enumerate() {
            good.classes[class].validate(response).unwrap();
        }
    }
    m.close_checked().unwrap();
}

#[test]
fn live_ecc_cli_check_and_replay_report_known_skips_and_opt_out_failures() {
    use tpms_timing_tests::{search::seeded_candidate, worker::BackendSpec};
    let Some((worker, backend, work)) = native() else {
        return;
    };
    let BackendSpec::Library { name, path } = backend else {
        panic!()
    };
    let invocation = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let scenario = Scenario::parse("zgen-2phase-ecmqv-p256").unwrap();
    let candidate = seeded_candidate(
        scenario,
        "fixture",
        scenario_seeds(scenario, 1, 0).remove(0).pair,
        1,
    );
    let candidate_path = work.join(format!("ecc-cli-candidate-{invocation}.json"));
    candidate.save(&candidate_path).unwrap();
    for command in ["check", "replay"] {
        for opt_out in [false, true] {
            let out = work.join(format!("ecc-cli-{invocation}-{command}-{opt_out}"));
            let mut cli = std::process::Command::new(env!("CARGO_BIN_EXE_tpms-timing-tests"));
            cli.arg("--worker-executable").arg(&worker);
            if opt_out {
                cli.arg("--disable-known-case-skips");
            }
            cli.arg(command)
                .arg("--backend")
                .arg(name.name())
                .arg(format!("--{}-lib", name.name()))
                .arg(&path)
                .arg("--out-dir")
                .arg(&out);
            if command == "check" {
                cli.args(["--scenario", scenario.name()]);
            } else {
                cli.arg("--candidate").arg(&candidate_path).args([
                    "--samples-per-class",
                    "4",
                    "--batches",
                    "1",
                    "--warmup",
                    "0",
                ]);
            }
            let output = cli.output().unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert_eq!(
                output.status.code(),
                Some(if opt_out { 4 } else { 0 }),
                "{command} opt_out{opt_out}: {stderr}"
            );
            let run = std::fs::read_dir(&out)
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path();
            let value: serde_json::Value = serde_json::from_slice(
                &std::fs::read(run.join(format!("{command}.json"))).unwrap(),
            )
            .unwrap();
            if !opt_out {
                // The skip result is a final result: it must state itself on
                // stdout, while stderr may only carry diagnostics.
                assert!(stdout.contains("SKIP"), "{command} stdout:\n{stdout}");
                if command == "check" {
                    for row in value["results"].as_array().unwrap() {
                        assert_eq!(row["functional_checked"], false);
                        assert_eq!(row["ok"], false);
                        assert!(row["checks"].as_array().unwrap().is_empty());
                        assert_eq!(row["skipped"][name.name()]["kind"], "functional-failure");
                    }
                } else {
                    let b = &value["backends"][name.name()];
                    assert!(b["functional_ok"].is_null());
                    assert_eq!(b["functional_checked"], false);
                    assert!(b["batches"].as_array().unwrap().is_empty());
                    assert_eq!(b["skipped"]["kind"], "functional-failure");
                }
            } else if command == "replay" {
                assert!(
                    value["backends"][name.name()]["batches"]
                        .as_array()
                        .unwrap()
                        .is_empty()
                );
            }
        }
    }
}
