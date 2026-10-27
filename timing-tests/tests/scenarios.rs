mod common;

use libafl::corpus::{Corpus, InMemoryCorpus, Testcase};
use libafl::feedbacks::ConstFeedback;
use libafl::inputs::{BytesInput, HasMutatorBytes};
use libafl::mutators::{
    BitFlipMutator, ByteRandMutator, HavocScheduledMutator, MutationResult, Mutator,
};
use libafl::state::{HasCorpus, StdState};
use libafl_bolts::rands::StdRand;
use libafl_bolts::tuples::tuple_list;
use tpms_timing_tests::measure::LoadOrder;
use tpms_timing_tests::scenario::matrix::{EXCLUSIONS, ExclusionKind, implemented};
use tpms_timing_tests::scenario::{
    Area, DifferenceKind, PreparedPair, Scenario, all_scenarios, input_width, parse_pair,
    scenario_seeds,
};
use tpms_timing_tests::search::{
    CandidateFile, ScalarBoundaryMutator, SharedLog, ValidPairMutator, seeded_candidate,
};
use tpms_timing_tests::verify::{VerifyConfig, diagnostic_seeds, dudect_plan};
use tpms_timing_tests::worker::{BackendName, BackendSpec};

fn implemented_scenarios() -> Vec<Scenario> {
    all_scenarios()
        .into_iter()
        .filter(|s| implemented(*s))
        .collect()
}

fn config() -> VerifyConfig {
    VerifyConfig {
        disable_known_case_skips: false,
        budget: 22_000,
        batch: 1000,
        repeats: 2,
        warmup: 5,
        time_limit_s: 60.0,
        cpu: None,
        max_candidates: 1,
        seed_diagnostics: 2,
        include_seed_diagnostics: true,
    }
}

#[test]
fn every_implemented_scenario_has_valid_seeds_that_prepare_in_both_load_orders() {
    for scenario in implemented_scenarios() {
        let seeds = scenario_seeds(scenario, 9, 2);
        assert!(seeds.len() >= 3, "{scenario}: too few seeds");
        assert!(
            seeds
                .iter()
                .any(|s| s.kind == tpms_timing_tests::scenario::SeedKind::Boundary),
            "{scenario}: no boundary seed"
        );
        for seed in &seeds {
            let bytes = seed.pair.to_bytes();
            assert_eq!(
                bytes.len(),
                2 * input_width(scenario),
                "{scenario} {}",
                seed.name
            );
            let pair = parse_pair(scenario, &bytes)
                .unwrap_or_else(|e| panic!("{scenario} {}: {e}", seed.name));
            let prepared = PreparedPair::try_prepare(scenario, pair)
                .unwrap_or_else(|e| panic!("{scenario} {}: {e}", seed.name));
            for class in 0..2 {
                let prep = &prepared.classes[class];
                assert!(
                    prep.mask.is_empty() || prep.mask.len() == prep.expected_response.len(),
                    "{scenario}: mask length"
                );
                assert!(
                    prep.matches(&prep.expected_response),
                    "{scenario}: expectation must match itself"
                );
                assert!(prep.expected_response.len() >= 10);
            }
            for order in [LoadOrder::ClassAFirst, LoadOrder::ClassBFirst] {
                let resolved = prepared.resolve(order);
                assert_eq!(
                    resolved.measured[0].len(),
                    resolved.measured[1].len(),
                    "{scenario}"
                );
            }
            if seed.pair.a == seed.pair.b && !scenario.is_control() {
                assert_eq!(
                    prepared.metadata.difference,
                    DifferenceKind::Identical,
                    "{scenario}"
                );
            }
        }
    }
}

#[test]
fn expected_responses_do_not_depend_on_load_order() {
    for scenario in implemented_scenarios() {
        let seed = &scenario_seeds(scenario, 3, 0)[0];
        let prepared = PreparedPair::prepare(scenario, seed.pair.clone());
        let a = prepared.resolve(LoadOrder::ClassAFirst);
        let b = prepared.resolve(LoadOrder::ClassBFirst);
        assert_eq!(a.setup.len(), b.setup.len(), "{scenario}");
        assert_eq!(
            a.post.iter().map(Option::is_some).collect::<Vec<_>>(),
            b.post.iter().map(Option::is_some).collect::<Vec<_>>()
        );
    }
}

#[test]
fn mutations_keep_every_scenario_input_valid() {
    for scenario in implemented_scenarios() {
        let width = input_width(scenario);
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
            log,
            scenario,
        );
        let mut input = BytesInput::new(scenario_seeds(scenario, 4, 1)[0].pair.to_bytes());
        let mut accepted = 0;
        for _ in 0..40 {
            if mutator.mutate(&mut state, &mut input).unwrap() == MutationResult::Mutated {
                accepted += 1;
                let bytes = input.mutator_bytes();
                assert_eq!(bytes.len(), 2 * width, "{scenario}");
                parse_pair(scenario, bytes)
                    .unwrap_or_else(|e| panic!("{scenario}: invalid mutation survived: {e}"));
                if accepted <= 5 {
                    let prepared =
                        PreparedPair::try_prepare(scenario, parse_pair(scenario, bytes).unwrap());
                    match prepared {
                        Ok(_) => {}
                        // SymPartial carries a per-class length selector; a mutation
                        // that changes one class's selector yields two measured
                        // commands of different length, which the harness refuses.
                        Err(e)
                            if matches!(scenario, Scenario::SymPartial(..))
                                && e.contains("the same length") => {}
                        Err(e) => {
                            panic!("{scenario}: mutated input does not prepare: {e}")
                        }
                    }
                }
            }
        }
        assert!(accepted > 0, "{scenario}: no mutation accepted");
    }
}

#[test]
fn dudect_plans_carry_setup_masks_cleanups_and_patches() {
    let spec = BackendSpec::Library {
        name: BackendName::Rust,
        path: std::env::current_exe().unwrap(),
    };
    for scenario in implemented_scenarios()
        .into_iter()
        .filter(|s| !s.is_control())
    {
        let seed = &scenario_seeds(scenario, 1, 0)[0];
        let prepared = PreparedPair::prepare(scenario, seed.pair.clone());
        let plan = dudect_plan(&spec, &prepared, LoadOrder::ClassBFirst, &config());
        assert_eq!(
            plan.setup[0],
            tpms_timing_tests::tpm::startup_clear(),
            "{scenario}"
        );
        let text = plan.render().unwrap();
        for class in 0..2 {
            if !prepared.classes[class].mask.is_empty() {
                assert!(text.contains(&format!("mask{class} ")), "{scenario}");
            }
            if prepared.layout.post[class].is_some() {
                assert!(
                    text.contains(&format!("post{class} "))
                        && text.contains(&format!("postexpect{class} ")),
                    "{scenario}"
                );
            }
        }
        assert!(
            !text.contains("search"),
            "{scenario}: plans never embed search samples"
        );
    }
}

#[test]
fn randomized_responses_are_checked_independently_beyond_the_mask() {
    for scenario in [
        Scenario::parse("ecsign-ecdsa-p256").unwrap(),
        Scenario::parse("ecsign-ecschnorr-bnp256").unwrap(),
        Scenario::parse("ecsign-sm2-sm2p256").unwrap(),
    ] {
        let prepared =
            PreparedPair::prepare(scenario, scenario_seeds(scenario, 1, 0)[0].pair.clone());
        let class = &prepared.classes[0];
        assert!(class.check.is_some(), "{scenario}");
        let forged = class.expected_response.clone();
        assert!(
            class.matches(&forged),
            "{scenario}: zero signature passes the mask"
        );
        assert!(
            class.validate(&forged).is_err(),
            "{scenario}: zero signature must fail the independent check"
        );
    }
    let keygen = Scenario::parse("keygen-primary-p256").unwrap();
    let prepared = PreparedPair::prepare(keygen, scenario_seeds(keygen, 1, 0)[0].pair.clone());
    assert!(
        prepared.classes[0]
            .validate(&prepared.classes[0].expected_response)
            .is_err()
    );
}

#[test]
fn padding_seeds_separate_same_outcome_pairs_from_visible_outcomes() {
    let scenario = Scenario::parse("rsa-decrypt-2048-oaep-sha256").unwrap();
    let seeds = scenario_seeds(scenario, 1, 0);
    let kind = |name: &str| {
        let seed = seeds.iter().find(|s| s.name == name).unwrap();
        PreparedPair::prepare(scenario, seed.pair.clone())
            .metadata
            .difference
    };
    assert_eq!(
        kind("bad-leading-byte-vs-bad-label-hash"),
        DifferenceKind::Mixed
    );
    assert_eq!(
        kind("valid-vs-bad-leading-byte"),
        DifferenceKind::VisibleOutcome
    );
    assert_eq!(kind("valid-vs-valid"), DifferenceKind::Mixed);
    let positive = Scenario::TpmControlPositive;
    let prepared = PreparedPair::prepare(positive, scenario_seeds(positive, 1, 0)[0].pair.clone());
    assert_eq!(
        prepared.metadata.difference,
        DifferenceKind::DifferentOperation
    );
}

#[test]
fn generic_candidates_round_trip_with_stable_content_identity() {
    let sandbox = common::Sandbox::new("generic-candidates");
    for name in [
        "sym-camellia256-ctr-decrypt",
        "rsa-decrypt-3072-raw",
        "ecdh-bnp638",
        "drbg-getrandom",
    ] {
        let scenario = Scenario::parse(name).unwrap();
        let seed = &scenario_seeds(scenario, 2, 0)[0];
        let candidate = seeded_candidate(scenario, &seed.name, seed.pair.clone(), 2);
        let file = common::write_candidate(&sandbox.root, &format!("{name}.json"), &candidate);
        let loaded = CandidateFile::load(&file).unwrap();
        assert_eq!(loaded.inputs().unwrap(), seed.pair);
        assert_eq!(
            loaded.content_sha256().unwrap(),
            candidate.content_sha256().unwrap()
        );
        let reversed = seeded_candidate(scenario, "reversed", seed.pair.reversed(), 2);
        assert_eq!(
            reversed.artifact_stem().unwrap(),
            candidate.artifact_stem().unwrap()
        );
        assert!(loaded.pair().is_err() || name == "never");
    }
    let diagnostics = diagnostic_seeds(Scenario::parse("ecdh-p256").unwrap(), 1, 3);
    assert_eq!(diagnostics.len(), 3);
}

#[test]
fn known_case_skips_never_reach_other_scenarios() {
    let info: tpms_timing_tests::worker::WorkerInfo = [(
        "openssl_version".into(),
        "OpenSSL 3.0.13 30 Jan 2024".into(),
    )]
    .into();
    for scenario in implemented_scenarios()
        .into_iter()
        .filter(|s| *s != Scenario::EcdhP521)
    {
        for seed in scenario_seeds(scenario, 1, 0) {
            assert!(
                tpms_timing_tests::known_issues::timing_skip(
                    scenario,
                    &seed.pair,
                    "reference",
                    &info
                )
                .is_none()
            );
        }
    }
}

#[test]
fn outstanding_scenarios_are_visible_and_refused() {
    let outstanding: Vec<Scenario> = all_scenarios()
        .into_iter()
        .filter(|s| !implemented(*s))
        .collect();
    for scenario in &outstanding {
        assert_eq!(scenario.area(), Area::AuthenticationIntegrity);
        assert!(
            PreparedPair::try_prepare(
                *scenario,
                tpms_timing_tests::scenario::InputPair::new(vec![1; 32], vec![2; 32])
            )
            .is_err()
        );
    }
    assert!(
        EXCLUSIONS.iter().any(
            |e| e.kind == ExclusionKind::Outstanding && e.area == Area::AuthenticationIntegrity
        )
    );
    let sandbox = common::Sandbox::new("outstanding");
    if let Some(scenario) = outstanding.first() {
        let (code, stderr) = sandbox.run(&[
            "search",
            "--scenario",
            scenario.name(),
            "--backend",
            "rust",
            "--rust-lib",
            "/nonexistent",
        ]);
        assert_eq!(code, 4, "{stderr}");
        assert!(stderr.contains("outstanding"), "{stderr}");
    }
}

#[test]
fn scenario_listing_and_selection_match_the_catalog() {
    let sandbox = common::Sandbox::new("listing");
    let output = std::process::Command::new(common::BIN)
        .args(["list-scenarios", "--implemented"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(text.lines().count(), implemented_scenarios().len());
    let output = std::process::Command::new(common::BIN)
        .args(["list-scenarios", "--area", "mac"])
        .output()
        .unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    let mac_area = implemented_scenarios()
        .into_iter()
        .filter(|s| s.area() == Area::Mac)
        .count();
    assert!(text.lines().all(|l| l.contains("\tmac\t")));
    assert_eq!(text.lines().count(), mac_area);
    let (code, stderr) = sandbox.run(&["search", "--scenario", "ecdh-p999"]);
    assert_eq!(code, 2, "{stderr}");
    let output = std::process::Command::new(common::BIN)
        .args(["list-scenarios", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
}

fn prepared(name: &str, a: Vec<u8>, b: Vec<u8>) -> PreparedPair {
    PreparedPair::prepare(
        Scenario::parse(name).unwrap(),
        tpms_timing_tests::scenario::InputPair::new(a, b),
    )
}

#[test]
fn difference_classification_follows_the_actual_pair() {
    let key = vec![0x13u8; 16];
    let other_key = vec![0x37u8; 16];
    let data = vec![0x00u8; 64];
    let other_data = vec![0xffu8; 64];
    let same_key = prepared(
        "sym-aes128-cbc-encrypt",
        [key.clone(), data.clone()].concat(),
        [key.clone(), other_data.clone()].concat(),
    );
    assert_eq!(same_key.metadata.difference, DifferenceKind::PublicInput);
    assert_eq!(
        same_key.metadata.public_differences,
        vec!["data".to_string()]
    );
    let other = prepared(
        "sym-aes128-cbc-encrypt",
        [key.clone(), data.clone()].concat(),
        [other_key.clone(), data.clone()].concat(),
    );
    assert_eq!(other.metadata.difference, DifferenceKind::Mixed);
    assert!(
        other
            .metadata
            .confounders
            .iter()
            .any(|c| c.contains("handle"))
    );
    let hmac_key = vec![0x21u8; 32];
    let message = vec![1u8; 64];
    let hmac = prepared(
        "mac-hmac-sha256",
        [hmac_key.clone(), message.clone()].concat(),
        [hmac_key, vec![2u8; 64]].concat(),
    );
    assert_eq!(hmac.metadata.difference, DifferenceKind::PublicInput);
    assert_ne!(hmac.metadata.difference, DifferenceKind::SecretOnly);
    let p521 = PreparedPair::prepare(Scenario::EcdhP521, common::small_pair(5, 9));
    assert_eq!(p521.metadata.difference, DifferenceKind::Mixed);
    assert!(
        p521.metadata
            .confounders
            .iter()
            .any(|c| c.contains("public key"))
    );
    assert!(
        p521.metadata
            .confounders
            .iter()
            .any(|c| c.contains("shared point"))
    );
    let sign = prepared("rsa-sign-2048-rsassa", vec![0; 32], vec![0xff; 32]);
    assert_eq!(sign.metadata.difference, DifferenceKind::PublicInput);
    let keygen = prepared("keygen-primary-p256", vec![0; 32], vec![1; 32]);
    assert_eq!(keygen.metadata.difference, DifferenceKind::Mixed);
    for scenario in implemented_scenarios() {
        for seed in scenario_seeds(scenario, 5, 1) {
            let prepared = PreparedPair::prepare(scenario, seed.pair.clone());
            if prepared.metadata.difference == DifferenceKind::SecretOnly {
                assert!(
                    prepared.metadata.public_differences.is_empty()
                        && prepared.metadata.confounders.is_empty(),
                    "{scenario} {}",
                    seed.name
                );
            }
            assert_ne!(
                prepared.metadata.difference,
                DifferenceKind::Unclassified,
                "{scenario}"
            );
        }
    }
}

#[test]
fn legacy_metadata_without_classification_gains_no_claim() {
    let legacy: tpms_timing_tests::scenario::PublicMetadata = serde_json::from_value(serde_json::json!({
        "varying_public_values": [], "bit_length": [1, 1], "leading_zero_bytes": [0, 0],
        "hamming_weight": [1, 1], "shared_x_leading_zero_bytes": [0, 0], "public_x_leading_zero_bytes": [0, 0]
    }))
    .unwrap();
    assert_eq!(legacy.difference, DifferenceKind::Unclassified);
    assert!(
        DifferenceKind::Unclassified
            .describe()
            .contains("not established")
    );
    for kind in [
        DifferenceKind::PublicInput,
        DifferenceKind::VisibleOutcome,
        DifferenceKind::OutputSize,
    ] {
        assert!(!kind.describe().contains("not a hidden leak"));
        assert!(!kind.describe().contains("expected"));
    }
}

fn keygen_response(kind: &str) -> (Scenario, Vec<u8>) {
    let scenario = Scenario::parse(&format!("keygen-primary-{kind}")).unwrap();
    let prepared = PreparedPair::prepare(scenario, scenario_seeds(scenario, 1, 0)[0].pair.clone());
    (scenario, prepared.classes[0].expected_response.clone())
}

fn fill(response: &mut [u8], pattern: &[u8], at: usize) {
    response[at..at + pattern.len()].copy_from_slice(pattern);
}

fn plausible(kind: &str) -> (Scenario, Vec<u8>) {
    let (scenario, mut response) = keygen_response(kind);
    let prepared = PreparedPair::prepare(scenario, scenario_seeds(scenario, 1, 0)[0].pair.clone());
    let base = tpms_timing_tests::tpm::success_parameters_at(1, 1);
    let public_len = u16::from_be_bytes(response[base..base + 2].try_into().unwrap()) as usize;
    let public_at = base + 2;
    let unique_len = match kind {
        "rsa2048" => 256,
        "p256" => 32,
        _ => 32,
    };
    let mut unique = vec![0u8; unique_len];
    match kind {
        "rsa2048" => {
            let modulus = tpms_timing_tests::oracle::rsa::RsaBits::B2048
                .key()
                .modulus();
            unique.copy_from_slice(&modulus);
            fill(&mut response, &unique, public_at + public_len - unique_len);
        }
        "p256" => {
            let c = tpms_timing_tests::oracle::ec::CurveId::NistP256.curve();
            let point = c.mul_g(&num_bigint::BigUint::from(7u32)).unwrap();
            let (x, y) = c.encode(&point);
            fill(
                &mut response,
                &x,
                public_at + public_len - 2 * unique_len - 2,
            );
            fill(&mut response, &y, public_at + public_len - unique_len);
        }
        _ => {
            unique
                .iter_mut()
                .enumerate()
                .for_each(|(i, b)| *b = i as u8 + 1);
            fill(&mut response, &unique, public_at + public_len - unique_len);
        }
    }
    let public = response[public_at..public_at + public_len].to_vec();
    let digest = tpms_timing_tests::oracle::hash::HashAlg::Sha256.digest(&[&public]);
    let name_at = response.len() - 5 - 34 + 2;
    fill(&mut response, &digest, name_at);
    let ticket_at = name_at - 2 - 2 - 64;
    fill(&mut response, &[0x5au8; 64], ticket_at);
    let _ = prepared;
    (scenario, response)
}

#[test]
fn create_primary_responses_are_parsed_strictly_and_never_panic() {
    for kind in ["p256", "rsa2048", "aes128", "hmac-sha256"] {
        let (scenario, response) = plausible(kind);
        let prepared =
            PreparedPair::prepare(scenario, scenario_seeds(scenario, 1, 0)[0].pair.clone());
        prepared.classes[0]
            .validate(&response)
            .unwrap_or_else(|e| panic!("{kind}: a plausible response must pass: {e}"));

        let base = tpms_timing_tests::tpm::success_parameters_at(1, 1);
        for (offset, label) in [(2usize, "type"), (4, "nameAlg")] {
            let mut bad = response.clone();
            fill(&mut bad, &[0xff, 0xff], base + offset);
            let error = prepared.classes[0]
                .validate(&bad)
                .expect_err(&format!("{kind}: 0xffff {label} must be rejected"));
            assert!(
                error.contains("differs from the independently derived expectation"),
                "{error}"
            );
        }
        for truncate in [1usize, 5, 40, 100] {
            if truncate >= response.len() {
                continue;
            }
            let short = response[..response.len() - truncate].to_vec();
            assert!(
                prepared.classes[0].validate(&short).is_err(),
                "{kind}: truncated response"
            );
        }
        let mut inconsistent = response.clone();
        fill(&mut inconsistent, &[0x7f, 0xff], base);
        assert!(
            prepared.classes[0].validate(&inconsistent).is_err(),
            "{kind}: nested length"
        );
        let mut bad_hash = response.clone();
        let at = bad_hash.len() - 5 - 34 - 2 - 64 - 4 - 2 - 32;
        bad_hash[at] ^= 0x01;
        assert!(
            prepared.classes[0].validate(&bad_hash).is_err(),
            "{kind}: creationHash"
        );
        let mut zero_ticket = response.clone();
        let ticket_at = zero_ticket.len() - 5 - 34 - 2 - 64;
        fill(&mut zero_ticket, &[0u8; 64], ticket_at);
        let error = prepared.classes[0]
            .validate(&zero_ticket)
            .expect_err("zero ticket");
        assert!(
            error.contains("creationTicket.digest is all zero"),
            "{error}"
        );
        let mut wrong_name = response.clone();
        let name_at = wrong_name.len() - 5 - 34 + 2;
        wrong_name[name_at] ^= 0x01;
        let error = prepared.classes[0]
            .validate(&wrong_name)
            .expect_err("wrong name");
        assert!(error.contains("name is not nameAlg"), "{error}");
    }
}

#[test]
fn create_primary_key_material_is_checked_independently() {
    let (scenario, response) = plausible("p256");
    let prepared = PreparedPair::prepare(scenario, scenario_seeds(scenario, 1, 0)[0].pair.clone());
    let base = tpms_timing_tests::tpm::success_parameters_at(1, 1);
    let public_len = u16::from_be_bytes(response[base..base + 2].try_into().unwrap()) as usize;
    let mut off_curve = response.clone();
    let y_at = base + 2 + public_len - 32;
    off_curve[y_at + 31] ^= 0x01;
    let public = off_curve[base + 2..base + 2 + public_len].to_vec();
    let digest = tpms_timing_tests::oracle::hash::HashAlg::Sha256.digest(&[&public]);
    let name_at = off_curve.len() - 5 - 34 + 2;
    fill(&mut off_curve, &digest, name_at);
    let error = prepared.classes[0]
        .validate(&off_curve)
        .expect_err("an off-curve generated point must be rejected");
    assert!(error.contains("not on the curve"), "{error}");

    let (scenario, response) = plausible("rsa2048");
    let prepared = PreparedPair::prepare(scenario, scenario_seeds(scenario, 1, 0)[0].pair.clone());
    let mut even = response.clone();
    let public_len = u16::from_be_bytes(even[base..base + 2].try_into().unwrap()) as usize;
    let last = base + 2 + public_len - 1;
    even[last] &= 0xfe;
    let public = even[base + 2..base + 2 + public_len].to_vec();
    let digest = tpms_timing_tests::oracle::hash::HashAlg::Sha256.digest(&[&public]);
    let name_at = even.len() - 5 - 34 + 2;
    fill(&mut even, &digest, name_at);
    let error = prepared.classes[0]
        .validate(&even)
        .expect_err("an even modulus must be rejected");
    assert!(error.contains("modulus is even"), "{error}");
}

#[allow(clippy::ptr_arg)]
fn wrong_response(_pair: &PreparedPair, _class: usize, response: &mut Vec<u8>) {
    response[0] ^= 0x01;
}

fn plausible_but_invalid_signature(pair: &PreparedPair, class: usize, response: &mut Vec<u8>) {
    *response = pair.classes[class].expected_response.clone();
    let mask = &pair.classes[class].mask;
    for (index, byte) in response.iter_mut().enumerate() {
        if mask.get(index).copied().unwrap_or(0xff) == 0 {
            *byte = 0x7f;
        }
    }
}

struct CampaignOutcome {
    history: Vec<tpms_timing_tests::search::HistoryEntry>,
    executions: usize,
    aborted: Option<String>,
}

impl CampaignOutcome {
    fn functional_failures(&self) -> usize {
        self.history
            .iter()
            .filter(|h| h.observation.failure.is_some())
            .count()
    }

    fn candidates(&self) -> usize {
        self.history.iter().filter(|h| h.decision.candidate).count()
    }

    fn measured(&self) -> usize {
        self.history
            .iter()
            .filter(|h| !h.observation.batches.is_empty())
            .count()
    }

    fn evaluated(&self) -> Vec<&tpms_timing_tests::search::HistoryEntry> {
        self.history
            .iter()
            .filter(|h| h.observation.invalid.is_none())
            .collect()
    }
}

fn campaign(
    scenario: Scenario,
    dir: &std::path::Path,
    evaluations: usize,
    corrupt: Option<fn(&PreparedPair, usize, &mut Vec<u8>)>,
) -> CampaignOutcome {
    let mut config = tpms_timing_tests::selftest::fixture_config(11, true);
    config.scenario = scenario;
    config.max_evaluations = evaluations;
    config.random_seed_pairs = 1;
    let mut measurer = tpms_timing_tests::measure::FixtureMeasurer::new(
        "rust",
        tpms_timing_tests::measure::no_effect,
    );
    measurer.corrupt_response = corrupt;
    let result =
        tpms_timing_tests::search::run_campaign(measurer, &config, dir, &dir.join("corpus"), None);
    let history: Vec<tpms_timing_tests::search::HistoryEntry> =
        std::fs::read_to_string(dir.join("history.jsonl"))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
    match result {
        Ok(output) => CampaignOutcome {
            history,
            executions: output.measurer.executions,
            aborted: None,
        },
        Err(error) => CampaignOutcome {
            history,
            executions: usize::MAX,
            aborted: Some(error.to_string()),
        },
    }
}

#[test]
fn search_validates_every_pair_before_measuring_it() {
    let sandbox = common::Sandbox::new("search-validation");
    let scenario = Scenario::parse("sym-aes128-cbc-encrypt").unwrap();

    let wrong = campaign(
        scenario,
        &sandbox.root.join("wrong"),
        15,
        Some(wrong_response),
    );
    assert!(
        wrong.functional_failures() > 0,
        "a response that fails independent validation must be a functional failure"
    );
    assert_eq!(wrong.measured(), 0, "no timing samples were collected");
    assert_eq!(wrong.candidates(), 0);
    if let Some(reason) = &wrong.aborted {
        assert!(
            reason.contains("corpus"),
            "an all-failing campaign may only abort because nothing entered the corpus: {reason}"
        );
    }
    for entry in wrong.evaluated() {
        assert!(entry.observation.failure.is_some());
        assert!(entry.observation.skipped.is_none());
        assert!(entry.observation.batches.is_empty());
        assert!(!entry.decision.candidate && !entry.decision.seed_met_criteria);
    }

    let good = campaign(scenario, &sandbox.root.join("good"), 15, None);
    assert_eq!(good.functional_failures(), 0);
    assert!(good.executions > 0 && good.executions != usize::MAX);
    assert_eq!(
        good.executions,
        good.evaluated().len(),
        "exactly one functional execution per evaluated pair"
    );
    assert!(
        good.evaluated()
            .iter()
            .all(|h| h.observation.functional_validated),
        "valid pairs are recorded as functionally validated"
    );
    assert!(
        good.measured() > 0,
        "valid pairs still reach timing measurements"
    );
    assert!(
        good.history.iter().any(|h| matches!(
            h.observation.origin,
            tpms_timing_tests::search::Origin::Mutation { .. }
        )),
        "mutated inputs are evaluated and validated too, not only boundary seeds"
    );
}

#[test]
fn search_rejects_randomized_responses_that_only_pass_the_mask() {
    let sandbox = common::Sandbox::new("search-masked-validation");
    let scenario = Scenario::parse("ecsign-ecdsa-p256").unwrap();
    let prepared = PreparedPair::prepare(scenario, scenario_seeds(scenario, 11, 0)[0].pair.clone());
    let mut forged = prepared.classes[0].expected_response.clone();
    plausible_but_invalid_signature(&prepared, 0, &mut forged);
    assert!(
        prepared.classes[0].matches(&forged),
        "the forgery must pass the byte mask"
    );
    assert!(
        prepared.classes[0].validate(&forged).is_err(),
        "the independent validator must reject it"
    );

    let masked = campaign(
        scenario,
        &sandbox.root.join("masked"),
        15,
        Some(plausible_but_invalid_signature),
    );
    assert!(
        masked.functional_failures() > 0,
        "search must reject responses that only pass the mask"
    );
    assert_eq!(masked.measured(), 0);
    assert_eq!(masked.candidates(), 0);
    assert!(
        masked
            .evaluated()
            .iter()
            .all(|h| h.observation.failure.is_some())
    );
}

#[test]
fn known_cases_are_validated_once_and_keep_their_skip_behaviour() {
    let sandbox = common::Sandbox::new("search-known-once");
    for disable in [false, true] {
        let mut config = tpms_timing_tests::selftest::fixture_config(7, true);
        config.scenario = Scenario::EcdhP521;
        config.max_evaluations = 26;
        config.random_seed_pairs = 0;
        config.disable_known_case_skips = disable;
        let dir = sandbox.root.join(format!("known-{disable}"));
        let mut measurer = tpms_timing_tests::measure::FixtureMeasurer::new(
            "reference",
            tpms_timing_tests::measure::no_effect,
        );
        measurer.label = "reference".into();
        measurer.info_extra = vec![(
            "openssl_version".into(),
            "OpenSSL 3.0.13 30 Jan 2024".into(),
        )];
        let output = tpms_timing_tests::search::run_campaign(
            measurer,
            &config,
            &dir,
            &dir.join("corpus"),
            None,
        )
        .unwrap();
        let history: Vec<tpms_timing_tests::search::HistoryEntry> =
            std::fs::read_to_string(dir.join("history.jsonl"))
                .unwrap()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect();
        let evaluated = history
            .iter()
            .filter(|h| h.observation.invalid.is_none())
            .count();
        assert_eq!(
            output.measurer.executions, evaluated,
            "each evaluated pair executes exactly once, skipped or not"
        );
        assert_eq!(output.summary.functional_failures, 0);
        let skipped: Vec<_> = history
            .iter()
            .filter(|h| h.observation.skipped.is_some())
            .collect();
        if disable {
            assert!(skipped.is_empty());
        } else {
            assert!(!skipped.is_empty(), "the registered case must still skip");
            for entry in skipped {
                assert!(entry.observation.functional_validated);
                assert!(entry.observation.batches.is_empty());
                assert!(entry.observation.failure.is_none());
            }
        }
    }
}
