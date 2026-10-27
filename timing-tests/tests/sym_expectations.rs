//! Regression tests for the confirmed backend contract on symmetric partial
//! inputs: for partial final CFB blocks the Rust port zeroes the unused ivOut
//! suffix while the OpenSSL-backed C reference retains the unused
//! encrypted-feedback suffix (issue 1), and partial-input classification
//! compares the data actually supplied to the TPM (issue 5).

use tpms_timing_tests::oracle::sym::{ChainingContract, SymKey, SymMode};
use tpms_timing_tests::scenario::{
    DifferenceKind, Direction, InputPair, PreparedPair, Scenario, scenario_seeds,
    sym_deterministic_key, sym_effective_input, sym_partial_cfb, sym_scenario_key,
};

const CFB: SymMode = SymMode::Cfb;

fn partial_cfb_scenarios() -> Vec<Scenario> {
    let mut out = Vec::new();
    for key in SymKey::ALL {
        for direction in [Direction::Encrypt, Direction::Decrypt] {
            out.push(Scenario::SymPartial(key, CFB, direction));
        }
    }
    out
}

/// Parses a successful EncryptDecrypt2 response and returns the byte range of
/// the ivOut: the TPM2B ivOut closes the parameter area.
fn parts(scenario: Scenario) -> (SymKey, SymMode, Direction) {
    match scenario {
        Scenario::SymPartial(key, mode, direction) => (key, mode, direction),
        _ => unreachable!("not a partial symmetric scenario"),
    }
}

fn iv_out_range(response: &[u8], block: usize) -> std::ops::Range<usize> {
    let parameter_size =
        u32::from_be_bytes(response[10..14].try_into().expect("response header")) as usize;
    let start = 14 + parameter_size - block;
    start..start + block
}

#[test]
fn all_partial_cfb_configurations_have_exact_per_contract_expectations() {
    let mut saw_partial = false;
    for scenario in partial_cfb_scenarios() {
        let block = sym_scenario_key(scenario).block();
        for seed in scenario_seeds(scenario, 3, 0) {
            let zero = PreparedPair::try_prepare_backend_chaining(
                scenario,
                seed.pair.clone(),
                ChainingContract::ZeroSuffix,
            )
            .expect("zero-suffix contract prepares");
            let retained = PreparedPair::try_prepare_backend_chaining(
                scenario,
                seed.pair.clone(),
                ChainingContract::RetainedSuffix,
            )
            .expect("retained-suffix contract prepares");
            // The measured command is contract-independent.
            assert_eq!(
                zero.measured_command(0, 0x8000_0001),
                retained.measured_command(0, 0x8000_0001),
                "{} {}",
                scenario.name(),
                seed.name
            );
            for class in [0, 1] {
                let (_, len, _) = sym_effective_input(scenario, seed.pair.class(class));
                let zero_response = &zero.classes[class].expected_response;
                let retained_response = &retained.classes[class].expected_response;
                assert_eq!(zero_response.len(), retained_response.len());
                let iv = iv_out_range(zero_response, block);
                // Exact outData validation, never masked.
                assert_eq!(&zero_response[..iv.start], &retained_response[..iv.start]);
                if len != 0 && !len.is_multiple_of(block) {
                    saw_partial = true;
                    // Bytes of the final block actually used by the data.
                    let used = (len - 1) % block + 1;
                    let zero_iv = zero_response[iv.clone()].to_vec();
                    let retained_iv = retained_response[iv.clone()].to_vec();
                    // The produced prefix is contract-independent.
                    assert_eq!(zero_iv[..used], retained_iv[..used]);
                    assert!(
                        zero_iv[used..].iter().all(|b| *b == 0),
                        "{} {} class {class}: the Rust port's zero-suffix chaining value",
                        scenario.name(),
                        seed.name
                    );
                    // The retained suffix is exactly E(previous ciphertext
                    // block), recomputed independently from the class secret —
                    // no masking of the differing bytes.
                    let (secret, _, data) = sym_effective_input(scenario, seed.pair.class(class));
                    let (key_spec, _, direction) = parts(scenario);
                    let previous_ct: Vec<u8> = if len < block {
                        // No complete block was consumed: the chaining value is
                        // derived directly from the fixed IV.
                        tpms_timing_tests::scenario::sym_fixed_iv(key_spec)
                    } else {
                        let previous_ct_start = len - used - block;
                        if direction == Direction::Decrypt {
                            data[previous_ct_start..len - used].to_vec()
                        } else {
                            zero_response[16 + previous_ct_start..16 + len - used].to_vec()
                        }
                    };
                    let keystream = key_spec.encrypt_block_copy(secret, &previous_ct);
                    assert_eq!(
                        retained_iv[used..],
                        keystream[used..],
                        "{} {} class {class}: the C reference's retained keystream suffix",
                        scenario.name(),
                        seed.name
                    );
                } else {
                    // Empty and aligned lengths: the contracts agree fully.
                    assert_eq!(zero_response, retained_response);
                }
            }
        }
    }
    assert!(
        saw_partial,
        "the boundary seeds must exercise partial lengths for every configuration"
    );
    assert_eq!(partial_cfb_scenarios().len(), 16);
}

#[test]
fn the_chaining_probe_pair_is_valid_and_contract_distinct_for_every_configuration() {
    for scenario in partial_cfb_scenarios() {
        let pair = tpms_timing_tests::scenario::sym_chaining_probe_pair(scenario)
            .unwrap_or_else(|e| panic!("{}: {e}", scenario.name()));
        // The probe must land on a partial final block.
        assert!(
            sym_partial_cfb(scenario, &pair.a),
            "{}: the probe length must be partial",
            scenario.name()
        );
        let zero = PreparedPair::try_prepare_backend_chaining(
            scenario,
            pair.clone(),
            ChainingContract::ZeroSuffix,
        )
        .unwrap();
        let retained = PreparedPair::try_prepare_backend_chaining(
            scenario,
            pair.clone(),
            ChainingContract::RetainedSuffix,
        )
        .unwrap();
        assert_ne!(
            zero.classes[0].expected_response,
            retained.classes[0].expected_response,
            "{}: the fixed probe must select a contract unambiguously",
            scenario.name()
        );
    }
}

#[test]
fn partial_input_classification_ignores_bytes_never_supplied_to_the_tpm() {
    let scenario = Scenario::parse("sym-partial-aes128-cfb-encrypt").unwrap();
    let key = sym_deterministic_key(sym_scenario_key(scenario));
    let width = tpms_timing_tests::scenario::input_width(scenario);
    let key_len = key.len();
    let data_area = width - key_len - 1;

    let classify = |a: Vec<u8>, b: Vec<u8>| {
        let scenario = Scenario::parse("sym-partial-aes128-cfb-encrypt").unwrap();
        PreparedPair::try_prepare(scenario, InputPair::new(a, b))
            .unwrap_or_else(|e| panic!("{e}"))
            .metadata
    };

    let base = {
        let mut input = Vec::new();
        input.extend_from_slice(&key);
        input.push(0); // selector 0: zero-length data
        input.resize(width, 0);
        input
    };

    // Zero-length data with a different unused tail: the measured commands are
    // identical, so this is an Identical pair, not PublicInput.
    {
        let mut b = base.clone();
        *b.last_mut().unwrap() = 0xed;
        let metadata = classify(base.clone(), b);
        assert_eq!(metadata.difference, DifferenceKind::Identical);
        assert!(metadata.public_differences.is_empty(), "{metadata:?}");
        assert!(metadata.confounders.is_empty(), "{metadata:?}");
    }
    // Equivalent selector encodings of the same length are identical commands.
    {
        let mut b = base.clone();
        b[key_len] = (data_area + 1) as u8; // (data_area + 1) % (data_area + 1) == 0
        let metadata = classify(base.clone(), b);
        assert_eq!(
            metadata.difference,
            DifferenceKind::Identical,
            "{metadata:?}"
        );
    }
    // Zero-length versus partial length: classes of different measured command
    // lengths are rejected by the layout check instead of being classified.
    {
        let mut b = base.clone();
        b[key_len] = 9;
        let error = PreparedPair::try_prepare(
            Scenario::parse("sym-partial-aes128-cfb-encrypt").unwrap(),
            InputPair::new(base.clone(), b),
        )
        .unwrap_err();
        assert!(
            error.contains("the two measured class commands must have the same length"),
            "{error}"
        );
    }
    // Partial lengths with equal transmitted data but differing unused tails:
    // identical commands.
    {
        let mut a = base.clone();
        a[key_len] = 9;
        let mut b = a.clone();
        *b.last_mut().unwrap() = 0x7e;
        let metadata = classify(a, b);
        assert_eq!(
            metadata.difference,
            DifferenceKind::Identical,
            "{metadata:?}"
        );
        assert!(
            !metadata
                .confounders
                .iter()
                .any(|c| c.contains("different key objects")),
            "bytes never reaching the TPM must not fabricate object differences"
        );
    }
    // An actual transmitted-data change at the same length is a public input.
    {
        let mut a = base.clone();
        a[key_len] = 9;
        let mut b = a.clone();
        b[key_len + 8] ^= 1;
        let metadata = classify(a, b);
        assert_eq!(metadata.difference, DifferenceKind::PublicInput);
    }
    // A key change with identical supplied data differences only in the secret.
    {
        let mut other_key = key.clone();
        other_key[0] ^= 1;
        let mut b = base.clone();
        b[..key_len].copy_from_slice(&other_key);
        let metadata = classify(base.clone(), b);
        // Secret-dependent key change with key confounders listed, and no
        // public command input difference.
        assert_eq!(metadata.difference, DifferenceKind::Mixed, "{metadata:?}");
        assert!(metadata.public_differences.is_empty(), "{metadata:?}");
        assert!(
            metadata
                .confounders
                .iter()
                .any(|c| c.contains("the classes load different key objects")),
            "{metadata:?}"
        );
    }
}

#[test]
fn partial_cfb_metadata_marks_only_genuinely_partial_lengths() {
    for scenario in partial_cfb_scenarios() {
        let key = sym_deterministic_key(sym_scenario_key(scenario));
        let width = tpms_timing_tests::scenario::input_width(scenario);
        let build = |selector: u8| {
            let mut input = key.clone();
            input.push(selector);
            input.resize(width, 0x3c);
            input
        };
        for (selector, partial) in [
            (0usize, false),
            (16, false),
            (32, false),
            (5, true),
            (21, true),
        ] {
            assert_eq!(
                sym_partial_cfb(scenario, &build(selector as u8)),
                partial,
                "{} selector {selector}",
                scenario.name()
            );
        }
    }
}

mod common;

/// A backend whose fixed CFB chaining probes cannot select an independently
/// validated contract must abort the campaign, never file an invalid candidate.
struct UnresolvableChaining(tpms_timing_tests::measure::FixtureMeasurer);

impl tpms_timing_tests::measure::Measurer for UnresolvableChaining {
    fn prepare(
        &mut self,
        _scenario: Scenario,
        _pair: InputPair,
    ) -> Result<PreparedPair, tpms_timing_tests::measure::PrepareFailure> {
        Err(tpms_timing_tests::measure::PrepareFailure::Backend(
            "CFB chaining probes did not uniquely match a known independent contract".into(),
        ))
    }
    fn label(&self) -> String {
        "reference".into()
    }
    fn info(&self) -> tpms_timing_tests::worker::WorkerInfo {
        [(
            "openssl_version".into(),
            "OpenSSL 3.0.13 30 Jan 2024".into(),
        )]
        .into()
    }
    fn load(
        &mut self,
        p: &PreparedPair,
        o: tpms_timing_tests::measure::LoadOrder,
    ) -> Result<tpms_timing_tests::measure::LoadedPair, tpms_timing_tests::measure::MeasureFailure>
    {
        self.0.load(p, o)
    }
    fn measure(
        &mut self,
        p: &tpms_timing_tests::measure::LoadedPair,
        n: usize,
        w: usize,
        s: u64,
    ) -> Result<tpms_timing_tests::measure::RawBatch, tpms_timing_tests::measure::MeasureFailure>
    {
        self.0.measure(p, n, w, s)
    }
    fn execute_once(
        &mut self,
        p: &tpms_timing_tests::measure::LoadedPair,
    ) -> Result<[Vec<u8>; 2], tpms_timing_tests::measure::MeasureFailure> {
        self.0.execute_once(p)
    }
}

#[test]
fn a_backend_that_cannot_resolve_its_cfb_chaining_contract_aborts_the_campaign() {
    let sandbox = common::Sandbox::new("sym-chaining-aborts");
    let mut config = tpms_timing_tests::selftest::fixture_config(7, true);
    config.scenario = Scenario::parse("sym-partial-aes128-cfb-encrypt").unwrap();
    config.max_evaluations = 5;
    config.random_seed_pairs = 0;
    let dir = sandbox.root.join("search");
    let measurer = UnresolvableChaining(tpms_timing_tests::measure::FixtureMeasurer::new(
        "reference",
        tpms_timing_tests::measure::no_effect,
    ));
    let history_path = dir.join("history.jsonl");
    let result = tpms_timing_tests::search::run_campaign(
        measurer,
        &config,
        &dir,
        &sandbox.root.join("corpus"),
        None,
    );
    let detail = match result {
        Err(tpms_timing_tests::search::SearchError::Infrastructure(detail)) => detail,
        Err(error) => panic!("expected an infrastructure abort, got: {error}"),
        Ok(_) => panic!("expected an infrastructure abort, campaign completed"),
    };
    assert!(detail.contains("backend expectation failure"), "{detail}");
    assert!(detail.contains("campaign aborted"), "{detail}");
    let rows: Vec<tpms_timing_tests::search::HistoryEntry> = std::fs::read_to_string(&history_path)
        .unwrap_or_else(|e| panic!("{}: {e}", history_path.display()))
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert!(
        rows.iter().any(|r| r
            .decision
            .reason
            .contains("backend/infrastructure failure during preparation")),
        "the abort must be recorded as history: {rows:?}"
    );
    assert!(
        rows.iter().all(|r| !r.decision.candidate),
        "a backend failure is never a candidate: {rows:?}"
    );
    assert!(
        rows.iter().all(|r| r.observation.invalid.is_none()),
        "a backend failure is never an invalid candidate: {rows:?}"
    );
}
