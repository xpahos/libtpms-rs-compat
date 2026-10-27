use tpms_timing_tests::{
    oracle::drbg::{self, Input, RESEED_INTERVAL},
    scenario::{
        DifferenceKind, InputPair, PreparedPair, Scenario, all_scenarios, boundary_mutation,
        scenario_seeds, validate_input,
    },
};

fn controlled() -> impl Iterator<Item = Scenario> {
    all_scenarios()
        .into_iter()
        .filter(|s| matches!(s, Scenario::DrbgControlled { .. }))
}

struct Reader<'a>(&'a [u8]);
impl Reader<'_> {
    fn array<const N: usize>(&mut self) -> [u8; N] {
        let (head, tail) = self.0.split_at(N);
        self.0 = tail;
        head.try_into().unwrap()
    }
    fn u16(&mut self) -> u16 {
        u16::from_be_bytes(self.array())
    }
    fn u64(&mut self) -> u64 {
        u64::from_be_bytes(self.array())
    }
    fn last_value(&mut self) -> [u8; 16] {
        let words: [u8; 16] = self.array();
        let mut out = [0; 16];
        for (to, from) in out.chunks_exact_mut(4).zip(words.chunks_exact(4)) {
            to.copy_from_slice(&u32::from_be_bytes(from.try_into().unwrap()).to_le_bytes());
        }
        out
    }
}

#[test]
fn independent_oracle_matches_all_c_generated_vectors() {
    // Fixture layout is documented by src/library/tpm2/crypto/drbg_vectors.rs;
    // this reader deliberately does not import production DRBG implementation.
    let fixture = include_bytes!("../../src/library/tpm2/testdata/drbg_generate_vectors.bin");
    let mut reader = Reader(fixture);
    let entropy = std::array::from_fn(|i| (i as u8).wrapping_add(48) ^ 0x63);
    let mut checked = 0;
    for continuous in [false, true] {
        let mut input = Input {
            seed: reader.array(),
            counter: reader.u64(),
            last_value: reader.last_value(),
            entropy,
            continuous,
            requested: 0,
        };
        for step in 0..6 {
            input.requested = reader.u16();
            let output: [u8; 64] = reader.array();
            let expected_seed: [u8; 48] = reader.array();
            let expected_counter = reader.u64();
            let expected_last = reader.last_value();
            let actual = drbg::generate(&input).unwrap();
            assert_eq!(
                actual.bytes,
                output[..usize::from(input.requested)],
                "continuous={continuous}, step={step}"
            );
            assert_eq!(actual.seed, expected_seed);
            assert_eq!(actual.counter, expected_counter);
            assert_eq!(actual.last_value, expected_last);
            assert_eq!(actual.entropy_draws, 0);
            input.seed = expected_seed;
            input.counter = expected_counter;
            input.last_value = expected_last;
            checked += 1;
        }
    }
    for continuous in [false, true] {
        let seed = reader.array();
        let last_value = reader.last_value();
        for case in 0..4 {
            let input = Input {
                seed,
                counter: reader.u64(),
                requested: reader.u16(),
                last_value,
                entropy,
                continuous,
            };
            let draws = reader.array::<1>()[0];
            let output: [u8; 64] = reader.array();
            let expected_seed: [u8; 48] = reader.array();
            let expected_counter = reader.u64();
            let expected_last = reader.last_value();
            let actual = drbg::generate(&input).unwrap();
            assert_eq!(
                actual.bytes,
                output[..usize::from(input.requested)],
                "continuous={continuous}, boundary={case}"
            );
            assert_eq!(actual.seed, expected_seed);
            assert_eq!(actual.counter, expected_counter);
            assert_eq!(actual.last_value, expected_last);
            assert_eq!(actual.entropy_draws, u32::from(draws));
            checked += 1;
        }
    }
    assert!(reader.0.is_empty(), "stale fixture layout");
    assert_eq!(checked, 20);
}

#[test]
fn controlled_seed_matrix_exact_checks_and_classification() {
    let mut pairs = 0;
    for scenario in controlled() {
        let seeds = scenario_seeds(scenario, 17, 2);
        for seed in seeds {
            let prepared = PreparedPair::prepare(scenario, seed.pair);
            let expected = if seed.name.starts_with("same-") || seed.name == "last-value-prefix-0" {
                DifferenceKind::Identical
            } else if seed.name.starts_with("public-length") {
                DifferenceKind::OutputSize
            } else if seed.name.starts_with("public-") {
                DifferenceKind::PublicInput
            } else {
                DifferenceKind::SecretOnly
            };
            assert_eq!(
                prepared.metadata.difference, expected,
                "{scenario}/{}",
                seed.name
            );
            for class in &prepared.classes {
                assert!(class.mask.is_empty());
                class.validate(&class.expected_response).unwrap();
                // Every byte, including returned state and draw count, must be
                // covered by the exact gate, not merely the TPM framing.
                for index in 0..class.expected_response.len() {
                    let mut corrupt = class.expected_response.clone();
                    corrupt[index] ^= 1;
                    assert!(
                        class.validate(&corrupt).is_err(),
                        "unchecked response byte {index}"
                    );
                }
            }
            pairs += 1;
        }
    }
    assert_eq!(pairs, 140);
}

#[test]
fn controlled_mutations_preserve_valid_public_configuration() {
    for scenario in controlled() {
        for seed in scenario_seeds(scenario, 17, 0) {
            for op in 0..24 {
                let mutated =
                    boundary_mutation(scenario, op, 0x1234abcd, &seed.pair.a, &seed.pair.b);
                validate_input(scenario, &mutated).unwrap();
                assert_eq!(mutated[48..56], seed.pair.a[48..56]);
                assert_eq!(mutated[120..], seed.pair.a[120..]);
            }
        }
    }
}

#[test]
fn screening_diagnostics_keep_reported_pairs_and_matching_controls() {
    use tpms_timing_tests::{known_issues, scenario::diagnostic_order, worker::WorkerInfo};

    for scenario in controlled() {
        let Scenario::DrbgControlled { reseed, .. } = scenario else {
            unreachable!()
        };
        let seeds = scenario_seeds(scenario, 17, 0);
        let pair = |name: &str| {
            &seeds
                .iter()
                .find(|s| s.name == name)
                .unwrap_or_else(|| panic!("{scenario}: missing screening case {name}"))
                .pair
        };
        let (signal, aa, bb) = if reseed {
            ("key-zero-vs-ones", "same-zero-key", "same-ones-key")
        } else {
            (
                "secret-state-length-15",
                "same-zero-state-length-15",
                "same-ones-state-length-15",
            )
        };
        let signal = pair(signal);
        assert_eq!(pair(aa).a, signal.a);
        assert_eq!(pair(aa).b, signal.a);
        assert_eq!(pair(bb).a, signal.b);
        assert_eq!(pair(bb).b, signal.b);

        // A short verify run must include both matched controls and actual
        // secret-dependent cases, rather than spending its whole seed budget
        // on unrelated baseline states or public-length differences.
        let order = diagnostic_order(scenario);
        let defaults = &order[..4];
        assert!(defaults.iter().any(|s| s == aa));
        assert!(defaults.iter().any(|s| s == bb));
        let differences: Vec<_> = defaults
            .iter()
            .map(|name| {
                PreparedPair::prepare(scenario, pair(name).clone())
                    .metadata
                    .difference
            })
            .collect();
        assert_eq!(
            differences
                .iter()
                .filter(|d| **d == DifferenceKind::Identical)
                .count(),
            2
        );
        assert_eq!(
            differences
                .iter()
                .filter(|d| **d == DifferenceKind::SecretOnly)
                .count(),
            2
        );

        if !reseed {
            for (name, changed) in [
                ("secret-key-length-15", 0..32),
                ("secret-v-length-15", 32..48),
            ] {
                let p = pair(name);
                let a = Input::decode(&p.a).unwrap();
                let b = Input::decode(&p.b).unwrap();
                assert_eq!(a.requested, 15);
                assert_eq!(a.seed, [0; 48]);
                let mut expected = a.clone();
                expected.seed[changed].fill(0xff);
                assert_eq!(
                    b, expected,
                    "{scenario}/{name}: only the selected secret component may change"
                );
            }
        }
        let info: WorkerInfo = [(
            "openssl_version".into(),
            "OpenSSL 3.0.13 30 Jan 2024".into(),
        )]
        .into();
        for seed in seeds {
            for backend in ["rust", "reference"] {
                assert!(known_issues::functional_skip(scenario, backend).is_none());
                assert!(known_issues::timing_skip(scenario, &seed.pair, backend, &info).is_none());
            }
        }
    }
}

#[test]
fn malformed_payloads_and_continuous_failures_are_rejected() {
    let scenario = Scenario::DrbgControlled {
        reseed: false,
        continuous: true,
    };
    let payload = scenario_seeds(scenario, 1, 0).remove(0).pair.a;
    for width in [0, 122, 124] {
        assert!(Input::decode(&vec![0; width]).is_err());
    }
    for counter in [0, RESEED_INTERVAL + 8, u64::MAX] {
        let mut bad = payload.clone();
        bad[48..56].copy_from_slice(&counter.to_be_bytes());
        assert!(validate_input(scenario, &bad).is_err());
    }
    for (at, value) in [(120, 2), (120, 0), (121, 1), (122, 65)] {
        let mut bad = payload.clone();
        bad[at] = value;
        assert!(validate_input(scenario, &bad).is_err());
    }
    let mut bad = Input::decode(&payload).unwrap();
    bad.last_value = drbg::first_block(&bad.seed);
    assert!(validate_input(scenario, &bad.encode()).is_err());
}

#[test]
fn public_and_secret_mutations_are_not_misclassified() {
    let scenario = Scenario::DrbgControlled {
        reseed: true,
        continuous: false,
    };
    let a = scenario_seeds(scenario, 1, 0).remove(0).pair.a;
    let mut b = a.clone();
    b[0] ^= 1;
    b[55] ^= 1;
    let prepared = PreparedPair::prepare(scenario, InputPair::new(a.clone(), b));
    assert_eq!(prepared.metadata.difference, DifferenceKind::Mixed);
    let mut b = a.clone();
    b[56] ^= 1; // Last-value is inert when continuous test is off.
    let prepared = PreparedPair::prepare(scenario, InputPair::new(a, b));
    assert_eq!(prepared.metadata.difference, DifferenceKind::PublicInput);
    assert!(!prepared.metadata.confounders.is_empty());
}

#[test]
fn native_controlled_drbg_both_backends_reset_every_sample() {
    use std::{fs, path::PathBuf, time::Duration};
    use tpms_timing_tests::{
        measure::{LoadOrder, Measurer, WorkerMeasurer},
        verify::{VerifyConfig, dudect_plan},
        worker::{BackendName, BackendSpec, DudectStatus, Limits, build_worker, run_dudect},
    };
    let libraries: Vec<_> = [
        (BackendName::Rust, "TPMS_TIMING_DRBG_RUST_LIB"),
        (BackendName::Reference, "TPMS_TIMING_DRBG_REFERENCE_LIB"),
    ]
    .into_iter()
    .filter_map(|(name, variable)| {
        std::env::var_os(variable).map(|path| (name, PathBuf::from(path)))
    })
    .collect();
    if libraries.is_empty() {
        eprintln!(
            "native DRBG skipped: set TPMS_TIMING_DRBG_RUST_LIB and/or TPMS_TIMING_DRBG_REFERENCE_LIB to instrumented libraries"
        );
        return;
    }
    let work = PathBuf::from(
        std::env::var_os("TPMS_TIMING_WORK_DIR").unwrap_or_else(|| "../target/timing-tests".into()),
    );
    let include = PathBuf::from(
        std::env::var_os("TPMS_TIMING_INCLUDE").unwrap_or_else(|| "../libtpms/include".into()),
    );
    fs::create_dir_all(&work).unwrap();
    let worker = build_worker(&work, &include).unwrap();
    let invocation = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    for (name, library) in libraries {
        let backend = BackendSpec::Library {
            name,
            path: library,
        };
        let mut measurer = WorkerMeasurer::start(
            &worker.path,
            backend.clone(),
            None,
            &work.join(format!("drbg-{name}-{invocation}.log")),
            Limits::default(),
        )
        .unwrap();
        let mut pairs = 0;
        let mut samples = 0;
        let mut dudect_runs = 0;
        for scenario in controlled() {
            eprintln!("native controlled DRBG: {name}/{scenario}");
            for seed in scenario_seeds(scenario, 17, 1) {
                let prepared = PreparedPair::prepare(scenario, seed.pair);
                for order in [LoadOrder::ClassAFirst, LoadOrder::ClassBFirst] {
                    let label = format!("{name}/{scenario}/{} {order:?}", seed.name);
                    let loaded = measurer
                        .load(&prepared, order)
                        .unwrap_or_else(|e| panic!("{label} load: {e}"));
                    // Each call must restore the same input. A hidden continuing
                    // state stream fails exact comparison on the second call.
                    for _ in 0..2 {
                        let responses = measurer
                            .execute_once(&loaded)
                            .unwrap_or_else(|e| panic!("{label} execute: {e}"));
                        for (class, response) in responses.iter().enumerate() {
                            prepared.classes[class]
                                .validate(response)
                                .unwrap_or_else(|e| panic!("{label} oracle: {e}"));
                        }
                    }
                    let batch = measurer
                        .measure(&loaded, 8, 2, 17)
                        .unwrap_or_else(|e| panic!("{label} repeated measurement: {e}"));
                    assert_eq!(batch.class0.len(), 8, "{label}");
                    assert_eq!(batch.class1.len(), 8, "{label}");
                    samples += batch.class0.len() + batch.class1.len();
                    pairs += 1;
                    if matches!(
                        seed.name.as_str(),
                        "same-state"
                            | "same-zero-state-length-15"
                            | "same-ones-state-length-15"
                            | "same-zero-key"
                            | "same-ones-key"
                            | "secret-key-length-15"
                            | "secret-v-length-15"
                            | "secret-state-length-0"
                            | "secret-state-length-15"
                            | "secret-state-length-16"
                            | "secret-state-length-17"
                            | "secret-state-length-64"
                            | "entropy-zero-vs-ones"
                            | "last-value-prefix-15"
                            | "public-reseed-threshold-length-0"
                            | "public-reseed-threshold-length-16"
                    ) {
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
                                "drbg-{name}-{invocation}-{}-{}-{order:?}",
                                scenario.name(),
                                seed.name
                            )),
                            Duration::from_secs(30),
                        )
                        .unwrap_or_else(|e| panic!("{label} dudect: {e}"));
                        assert!(
                            matches!(
                                outcome.status,
                                DudectStatus::LeakageFound
                                    | DudectStatus::BudgetExhausted
                                    | DudectStatus::InsufficientMeasurements
                            ),
                            "{label} dudect functional validation: {outcome:?}"
                        );
                        assert_eq!(outcome.measurements, 64, "{label}");
                        assert_eq!(outcome.batches, 2, "{label}");
                        assert_eq!(outcome.nv_stores, 0, "{label}");
                        dudect_runs += 1;
                    }
                }
            }
        }
        measurer.close_checked().unwrap();
        assert_eq!(pairs, 272);
        assert_eq!(samples, 4352);
        assert_eq!(dudect_runs, 88);
        println!(
            "native controlled DRBG {name}: {pairs} pair/load-order checks; {samples} exact-checked timing samples; {dudect_runs} dudect runs ({} samples)",
            dudect_runs * 64
        );
    }
}

#[test]
fn boundary_mutation_leaves_invalid_intermediate_payloads_for_final_validation() {
    for scenario in controlled() {
        let pair = scenario_seeds(scenario, 4, 0).remove(0).pair;
        for (offset, value) in [(48, 0xff), (120, 2), (121, 1), (122, 65)] {
            let mut intermediate = pair.a.clone();
            intermediate[offset] = value;
            assert!(validate_input(scenario, &intermediate).is_err());
            for op in 0..24 {
                let changed = boundary_mutation(scenario, op, 17, &intermediate, &pair.b);
                assert_eq!(
                    changed, intermediate,
                    "{scenario}: invalid intermediate input must reach final validation unchanged"
                );
            }
        }
    }
}

#[test]
fn stacked_havoc_drbg_mutations_never_panic_or_admit_invalid_payloads() {
    use libafl::{
        corpus::{Corpus, InMemoryCorpus, Testcase},
        feedbacks::ConstFeedback,
        inputs::{BytesInput, HasMutatorBytes},
        mutators::{
            BitFlipMutator, ByteRandMutator, HavocScheduledMutator, MutationResult, Mutator,
        },
        state::{HasCorpus, StdState},
    };
    use libafl_bolts::{rands::StdRand, tuples::tuple_list};
    use tpms_timing_tests::{
        scenario::parse_pair,
        search::{ScalarBoundaryMutator, SharedLog, ValidPairMutator},
    };
    for scenario in controlled() {
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        for seed in scenario_seeds(scenario, 4, 2) {
            corpus
                .add(Testcase::new(BytesInput::new(seed.pair.to_bytes())))
                .unwrap();
        }
        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);
        let mut state = StdState::new(
            StdRand::with_seed(17),
            corpus,
            InMemoryCorpus::<BytesInput>::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();
        let id = state.corpus().first().unwrap();
        *state.corpus_mut().current_mut() = Some(id);
        let log: SharedLog = Default::default();
        let mut mutator = ValidPairMutator::for_scenario(
            HavocScheduledMutator::with_max_stack_pow(
                tuple_list!(
                    BitFlipMutator::new(),
                    ByteRandMutator::new(),
                    ScalarBoundaryMutator::for_scenario(scenario),
                    ScalarBoundaryMutator::for_scenario(scenario)
                ),
                2,
            ),
            log.clone(),
            scenario,
        );
        let mut input = BytesInput::new(scenario_seeds(scenario, 4, 0).remove(0).pair.to_bytes());
        let mut accepted = 0;
        for _ in 0..300 {
            if mutator.mutate(&mut state, &mut input).unwrap() == MutationResult::Mutated {
                accepted += 1;
                let pair = parse_pair(scenario, input.mutator_bytes()).unwrap();
                PreparedPair::try_prepare(scenario, pair).unwrap();
            }
        }
        assert!(accepted > 0, "{scenario}: all valid mutations were lost");
        assert!(
            log.borrow().rejected_mutations > 0,
            "{scenario}: malformed candidates were not exercised"
        );
    }
}
