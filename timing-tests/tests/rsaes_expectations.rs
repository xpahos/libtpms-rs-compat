mod common;

use std::fs;

use tpms_timing_tests::expectation::RsaesProfile;
use tpms_timing_tests::measure::{
    FixtureMeasurer, LoadOrder, LoadedPair, MeasureFailure, Measurer, PrepareFailure, RawBatch,
    no_effect,
};
use tpms_timing_tests::oracle::rsa::RsaBits;
use tpms_timing_tests::scenario::{
    DifferenceKind, InputPair, PreparedPair, RsaPadding, RsaesSelectorSpace, Scenario,
    scenario_seeds,
};
use tpms_timing_tests::search::{HistoryEntry, SearchError, run_campaign};
use tpms_timing_tests::selftest::fixture_config;
use tpms_timing_tests::tpm::TPM_RC_VALUE;
use tpms_timing_tests::worker::WorkerInfo;

/// 1 + PADDED_MATERIAL input bytes; only deterministic material, no RNG.
fn selector_case(selector: u8) -> InputPair {
    let mut input = vec![selector];
    input.extend((0..48usize).map(|i| (i * 31 + 7) as u8));
    InputPair::new(input.clone(), input)
}

/// The same input bytes recorded under the original `selector % 5` semantics.
fn selector_case_legacy(selector: u8) -> InputPair {
    let mut input = vec![selector];
    input.extend((0..48usize).map(|i| (i * 31 + 7) as u8));
    InputPair::with_selector_space(input.clone(), input, RsaesSelectorSpace::LegacyMod5)
}

/// Versioned high-bit selector encodings of the separator-boundary kinds.
const SEPARATOR_BEFORE_MINIMUM: u8 = 0x85;
const SEPARATOR_AT_MINIMUM: u8 = 0x86;

/// Serializes a candidate for this input, optionally as it looked before the
/// versioned selector encoding existed (no `selector_encoding` field).
fn candidate_json(scenario: Scenario, selector: u8, legacy: bool) -> String {
    let candidate = tpms_timing_tests::search::seeded_candidate(
        scenario,
        "selector-encoding-case",
        selector_case(selector),
        3,
    );
    let mut value = serde_json::to_value(&candidate).unwrap();
    if legacy {
        value.as_object_mut().unwrap().remove("selector_encoding");
    }
    serde_json::to_string_pretty(&value).unwrap()
}

#[test]
fn legacy_selector_aliases_keep_their_recorded_meaning_and_replay_exactly() {
    // Selector bytes below 0x80 select kind = selector % 5, exactly as every
    // candidate recorded before the versioned encodings did. Every alias of a
    // kind must reproduce that kind's reconstructed command shape and expected
    // outcome: same response code, same response length contract, same
    // classification. Valid aliases additionally replay the exact expected
    // response bytes (the decoded message comes from input[1..]).
    let scenario = Scenario::parse("rsa-decrypt-1024-rsaes").unwrap();
    for (selector, kind) in [
        (0u8, 0u8),
        (5, 0),
        (10, 0),
        (15, 0),
        (20, 0),
        (1, 1),
        (6, 1),
        (11, 1),
        (2, 2),
        (17, 2),
        (3, 3),
        (13, 3),
        (4, 4),
        (9, 4),
    ] {
        assert_eq!(
            tpms_timing_tests::scenario::rsaes_selector_kind(
                selector,
                RsaesSelectorSpace::V2Tagged
            ),
            usize::from(kind),
            "selector {selector}"
        );
        for profile in [RsaesProfile::ExplicitValue, RsaesProfile::OpenSslImplicitV1] {
            let direct =
                PreparedPair::try_prepare_backend(scenario, selector_case(kind), profile).unwrap();
            let aliased =
                PreparedPair::try_prepare_backend(scenario, selector_case(selector), profile)
                    .unwrap_or_else(|e| panic!("selector {selector}: {e}"));
            assert_eq!(
                aliased.measured_command(0, 0x8000_0001).len(),
                direct.measured_command(0, 0x8000_0001).len(),
                "selector {selector} vs kind {kind}: reconstructed command shape"
            );
            assert_eq!(
                aliased.metadata.expected_response_codes, direct.metadata.expected_response_codes,
                "selector {selector} vs kind {kind} ({profile:?}): response codes"
            );
            if kind == 0 || profile == RsaesProfile::ExplicitValue {
                // Implicit-rejection synthetic messages legitimately depend on
                // the whole ciphertext, so malformed aliases only share the
                // code; lengths must match wherever the response carries the
                // independently derived plaintext or a bare error instead.
                assert_eq!(
                    aliased.metadata.expected_response_min_lengths,
                    direct.metadata.expected_response_min_lengths,
                    "selector {selector} vs kind {kind} ({profile:?}): response length contract"
                );
            }
            assert_eq!(
                aliased.metadata.difference, direct.metadata.difference,
                "selector {selector} vs kind {kind} ({profile:?}): classification"
            );
            if kind == 0 {
                // Valid padding: the decoded message is identical, so the
                // whole expected response must be identical, not just similar.
                assert_eq!(
                    aliased.classes[0].expected_response, direct.classes[0].expected_response,
                    "selector {selector} ({profile:?}): valid padding response"
                );
            }
            if profile == RsaesProfile::ExplicitValue {
                // The bare TPM_RC_VALUE error carries no payload, so even the
                // malformed aliases must reproduce the exact expected bytes.
                assert_eq!(
                    aliased.classes[0].expected_response, direct.classes[0].expected_response,
                    "selector {selector}: malformed padding error response"
                );
            }
        }
    }
}

#[test]
fn boundary_selectors_split_at_the_conforming_minimum_pad_length() {
    for bits in RsaBits::ALL {
        let scenario = Scenario::RsaDecrypt(bits, RsaPadding::Rsaes);
        for profile in [RsaesProfile::ExplicitValue, RsaesProfile::OpenSslImplicitV1] {
            let rejected = PreparedPair::try_prepare_backend(
                scenario,
                selector_case(SEPARATOR_BEFORE_MINIMUM),
                profile,
            )
            .expect("separator one byte before the minimum prepares");
            let expected_code = match profile {
                RsaesProfile::ExplicitValue => TPM_RC_VALUE,
                RsaesProfile::OpenSslImplicitV1 => 0,
            };
            assert_eq!(
                rejected.metadata.expected_response_codes, [expected_code; 2],
                "{bits:?} {profile:?}: malformed padding follows the backend contract"
            );
            let accepted = PreparedPair::try_prepare_backend(
                scenario,
                selector_case(SEPARATOR_AT_MINIMUM),
                profile,
            )
            .expect("separator at the minimum prepares");
            assert_eq!(
                accepted.metadata.expected_response_codes, [0u32; 2],
                "{bits:?} {profile:?}: the minimum-conforming separator is valid"
            );
            assert_eq!(
                accepted.metadata.expected_response_min_lengths,
                accepted.metadata.expected_response_lengths,
                "{bits:?} {profile:?}"
            );
        }
        // A valid input has the same expectation under both contracts; the malformed
        // separator is where the two independently validated contracts diverge.
        for selector in [0x00u8, SEPARATOR_AT_MINIMUM] {
            let explicit = PreparedPair::try_prepare_backend(
                scenario,
                selector_case(selector),
                RsaesProfile::ExplicitValue,
            )
            .unwrap();
            let implicit = PreparedPair::try_prepare_backend(
                scenario,
                selector_case(selector),
                RsaesProfile::OpenSslImplicitV1,
            )
            .unwrap();
            assert_eq!(
                explicit.classes[0].expected_response, implicit.classes[0].expected_response,
                "{bits:?} selector {selector:#04x}: valid inputs agree across contracts"
            );
        }
        let rejected_explicit = PreparedPair::try_prepare_backend(
            scenario,
            selector_case(SEPARATOR_BEFORE_MINIMUM),
            RsaesProfile::ExplicitValue,
        )
        .unwrap();
        let rejected_implicit = PreparedPair::try_prepare_backend(
            scenario,
            selector_case(SEPARATOR_BEFORE_MINIMUM),
            RsaesProfile::OpenSslImplicitV1,
        )
        .unwrap();
        assert_ne!(
            rejected_explicit.classes[0].expected_response,
            rejected_implicit.classes[0].expected_response,
            "{bits:?}: malformed padding is the contract split"
        );
    }
}

#[test]
fn versioned_selectors_live_in_a_tagged_high_bit_space() {
    // In the versioned encoding every byte below 0x80 keeps the legacy
    // `selector % 5` meaning, and only the two tagged bytes select the
    // separator-boundary kinds. The space is never inferred from the byte.
    for selector in 0u8..=0x7f {
        let kind = tpms_timing_tests::scenario::rsaes_selector_kind(
            selector,
            RsaesSelectorSpace::V2Tagged,
        );
        assert_eq!(kind, usize::from(selector % 5), "selector {selector:#04x}");
    }
    assert_eq!(
        tpms_timing_tests::scenario::rsaes_selector_kind(0x80, RsaesSelectorSpace::V2Tagged),
        6
    );
    assert_eq!(
        tpms_timing_tests::scenario::rsaes_selector_kind(0x83, RsaesSelectorSpace::V2Tagged),
        5
    );
    for (selector, kind) in [(0x81u8, 5usize), (0x85, 5), (0x87, 5), (0x86, 6), (0x84, 6)] {
        assert_eq!(
            tpms_timing_tests::scenario::rsaes_selector_kind(
                selector,
                RsaesSelectorSpace::V2Tagged
            ),
            kind,
            "selector {selector:#04x}"
        );
    }
    // The same bytes under the recorded legacy space keep the original
    // `selector % 5` semantics for all 256 values.
    for selector in [0x80u8, 0x84, 0x85, 0x86, 0xff] {
        assert_eq!(
            tpms_timing_tests::scenario::rsaes_selector_kind(
                selector,
                RsaesSelectorSpace::LegacyMod5
            ),
            usize::from(selector % 5),
            "selector {selector:#04x}"
        );
    }
}

#[test]
fn every_legacy_selector_value_keeps_its_mod_5_meaning() {
    // Candidates recorded before the versioned encoding used kind =
    // selector % 5 for every one of the 256 selector bytes, and every such
    // value must still reconstruct exactly the command and expected response
    // of its mod-5 kind (135 -> valid padding, 130 -> the standard valid
    // message, never the tagged separator boundaries).
    let scenario = Scenario::RsaDecrypt(RsaBits::B1024, RsaPadding::Rsaes);
    for selector in 0u8..=255 {
        let kind = tpms_timing_tests::scenario::rsaes_selector_kind(
            selector,
            RsaesSelectorSpace::LegacyMod5,
        );
        assert_eq!(kind, usize::from(selector % 5));
        assert_ne!(kind, 5, "no legacy byte ever selects kind 5");
        assert_ne!(kind, 6, "no legacy byte ever selects kind 6");
        // The class-0 command reconstructs with the exact shape of its mod-5
        // kind, and the expected outcomes follow that kind under every backend
        // contract. The padding seed material derives from the recorded bytes
        // (selector byte included, exactly as the legacy campaign generated
        // them), so aliased selectors keep their own ciphertext while the
        // decoded message — taken from the bytes after the selector — stays
        // byte-identical.
        let aliased = PreparedPair::try_prepare_backend(
            scenario,
            selector_case_legacy(selector),
            RsaesProfile::ExplicitValue,
        )
        .unwrap_or_else(|e| panic!("selector {selector}: {e}"));
        let aliased_implicit = PreparedPair::try_prepare_backend(
            scenario,
            selector_case_legacy(selector),
            RsaesProfile::OpenSslImplicitV1,
        )
        .unwrap();
        for (profile, aliased) in [
            (RsaesProfile::ExplicitValue, &aliased),
            (RsaesProfile::OpenSslImplicitV1, &aliased_implicit),
        ] {
            let plain = PreparedPair::try_prepare_backend(
                scenario,
                selector_case_legacy(kind as u8),
                profile,
            )
            .unwrap();
            assert_eq!(
                aliased.measured_command(0, 0x8000_0001).len(),
                plain.measured_command(0, 0x8000_0001).len(),
                "selector {selector} ({profile:?}): reconstructed command shape"
            );
            assert_eq!(
                aliased.metadata.expected_response_codes, plain.metadata.expected_response_codes,
                "selector {selector} ({profile:?}): response codes"
            );
            assert_eq!(
                aliased.metadata.difference, plain.metadata.difference,
                "selector {selector} ({profile:?}): classification"
            );
            if profile == RsaesProfile::ExplicitValue || kind == 0 {
                // The bare error and the valid decoded message respond
                // byte-identically for the kind, whatever the padding material.
                assert_eq!(
                    aliased.classes[0].expected_response, plain.classes[0].expected_response,
                    "selector {selector} ({profile:?}): expected response"
                );
            } else {
                // Implicit-rejection synthetic messages depend on the whole
                // ciphertext, so malformed aliases share the code — and the
                // exact synthetic answer of their own recorded bytes.
                assert_eq!(aliased.metadata.expected_response_codes, [0, 0]);
            }
        }
    }
}

#[test]
fn saved_candidates_dictate_their_recorded_selector_encoding() {
    let scenario = Scenario::RsaDecrypt(RsaBits::B1024, RsaPadding::Rsaes);
    let sandbox = common::Sandbox::new("rsaes-selector-encoding");
    // An old-format candidate: no selector-encoding field anywhere, selector
    // byte 135. It recorded kind = 135 % 5 = 0: valid padding. The versioned
    // space would answer TPM_RC_VALUE instead; it must never be inferred from
    // the high bit of the byte.
    let legacy = candidate_json(scenario, 135, true);
    let path = sandbox.root.join("legacy-candidate.json");
    fs::write(&path, legacy).unwrap();
    let loaded =
        tpms_timing_tests::search::CandidateFile::load(&path).expect("legacy candidate loads");
    assert_eq!(loaded.selector_encoding, RsaesSelectorSpace::LegacyMod5);
    let pair = loaded.inputs().unwrap();
    assert_eq!(pair.selector_space, RsaesSelectorSpace::LegacyMod5);
    let prepared = PreparedPair::try_prepare(scenario, pair).unwrap();
    assert_eq!(prepared.metadata.expected_response_codes, [0, 0]);
    // Under the recorded legacy space the same byte 135 yields the standard
    // valid message, byte-identical to selector 10.
    let plain = PreparedPair::try_prepare(scenario, selector_case_legacy(10)).unwrap();
    assert_eq!(
        prepared.classes[0].expected_response,
        plain.classes[0].expected_response
    );
    // Saving migrates nothing silently: bytes and encoding stay as recorded.
    loaded.save(&sandbox.root.join("resaved.json")).unwrap();
    let resaved =
        tpms_timing_tests::search::CandidateFile::load(&sandbox.root.join("resaved.json")).unwrap();
    assert_eq!(resaved.selector_encoding, RsaesSelectorSpace::LegacyMod5);
    assert_eq!(resaved.scalar_a, loaded.scalar_a);
    assert_eq!(resaved.scalar_b, loaded.scalar_b);
    assert!(
        serde_json::to_value(&resaved)
            .unwrap()
            .get("selector_encoding")
            .is_some(),
        "the explicit encoding must be recorded on every save"
    );

    // A current-format candidate: the tagged separator boundary back-reference
    // byte. The recorded encoding is the versioned space, so kind 5 survives
    // save, load and prepare unchanged.
    let tagged_bytes = candidate_json(scenario, SEPARATOR_BEFORE_MINIMUM, false);
    let tagged_path = sandbox.root.join("tagged-candidate.json");
    fs::write(&tagged_path, tagged_bytes).unwrap();
    let mut tagged = tpms_timing_tests::search::CandidateFile::load(&tagged_path).expect("loads");
    assert_eq!(tagged.selector_encoding, RsaesSelectorSpace::V2Tagged);
    let pair = tagged.inputs().unwrap();
    let prepared = PreparedPair::try_prepare(scenario, pair).unwrap();
    // The retained-suffix offline contract: malformed kind 5 under the default
    // explicit-view prepare is rejected with TPM_RC_VALUE.
    assert_eq!(
        prepared.metadata.expected_response_codes,
        [TPM_RC_VALUE, TPM_RC_VALUE]
    );
    // Identities of different recorded encodings never collide on merge.
    let mut merged = loaded.clone();
    assert!(merged.merge(&resaved).is_ok());
    tagged.scalar_a = loaded.scalar_a.clone();
    tagged.scalar_b = loaded.scalar_b.clone();
    assert!(
        merged.merge(&tagged).is_err(),
        "identical bytes with different recorded encodings must not merge"
    );
}

#[test]
fn the_separator_boundary_kinds_appear_as_campaign_seeds() {
    let scenario = Scenario::RsaDecrypt(RsaBits::B1024, RsaPadding::Rsaes);
    let mut selectors = Vec::new();
    for seed in scenario_seeds(scenario, 7, 1) {
        selectors.push((seed.name.clone(), seed.pair.a[0]));
    }
    for expected in [
        "missing-separator-vs-separator-before-minimum",
        "separator-before-minimum-vs-separator-at-minimum",
        "short-padding-vs-separator-at-minimum",
        "invalid-invalid-equal-implicit-length",
    ] {
        assert!(
            selectors.iter().any(|(n, _)| n == expected),
            "{selectors:?}"
        );
    }
    // Every seed selector byte lives in a declared space: legacy bytes select
    // kind = byte % 5, tagged high-bit bytes select the boundary kinds.
    for (name, selectors) in &selectors {
        for selector in [*selectors, seed_pair_b(name, scenario)] {
            if selector & 0x80 != 0 {
                assert!(
                    matches!(selector, SEPARATOR_BEFORE_MINIMUM | SEPARATOR_AT_MINIMUM),
                    "{name}: {selector:#04x} is not a versioned boundary selector"
                );
            } else {
                assert!(selector <= 4, "{name}: legacy selector {selector}");
            }
        }
    }
    assert!(
        selectors
            .iter()
            .any(|(n, s)| n.contains("separator-before-minimum") && *s == SEPARATOR_BEFORE_MINIMUM),
        "the separator boundary seeds use the versioned selector: {selectors:?}"
    );
}

fn seed_pair_b(name: &str, scenario: Scenario) -> u8 {
    scenario_seeds(scenario, 7, 1)
        .into_iter()
        .find(|s| s.name == name)
        .map(|s| s.pair.b[0])
        .unwrap_or(0)
}

#[test]
fn the_equal_length_malformed_pair_is_not_an_output_size_difference() {
    for bits in RsaBits::ALL {
        let scenario = Scenario::RsaDecrypt(bits, RsaPadding::Rsaes);
        let seed = scenario_seeds(scenario, 7, 0)
            .into_iter()
            .find(|s| s.name == "invalid-invalid-equal-implicit-length")
            .expect("the equal-length seed is part of the campaign");
        let prepared =
            PreparedPair::try_prepare_backend(scenario, seed.pair, RsaesProfile::OpenSslImplicitV1)
                .expect("equal-length malformed pair prepares under the implicit contract");
        let metadata = &prepared.metadata;
        assert_eq!(
            metadata.expected_response_codes[0], metadata.expected_response_codes[1],
            "{bits:?}: implicit rejection returns one outcome code"
        );
        assert_ne!(
            metadata.expected_response_codes[0], TPM_RC_VALUE,
            "{bits:?}: the implicit contract never surfaces TPM_RC_VALUE for malformed input"
        );
        assert_eq!(
            metadata.expected_response_min_lengths[0], metadata.expected_response_min_lengths[1],
            "{bits:?}: the seed was chosen for equal implicit-rejection lengths"
        );
        assert_ne!(metadata.difference, DifferenceKind::OutputSize, "{bits:?}");
        assert_ne!(
            prepared.classes[0].expected_response, prepared.classes[1].expected_response,
            "{bits:?}: equal lengths must not hide different synthetic plaintexts"
        );
    }
}

#[test]
fn other_malformed_seed_pairs_do_shrink_to_output_size_differences() {
    let scenario = Scenario::RsaDecrypt(RsaBits::B1024, RsaPadding::Rsaes);
    let mut found = 0usize;
    for seed in scenario_seeds(scenario, 7, 0) {
        if seed.pair.a == seed.pair.b {
            continue;
        }
        let Ok(prepared) =
            PreparedPair::try_prepare_backend(scenario, seed.pair, RsaesProfile::OpenSslImplicitV1)
        else {
            continue;
        };
        if prepared.metadata.difference == DifferenceKind::OutputSize {
            found += 1;
        }
    }
    assert!(
        found > 0,
        "at least one malformed seed pair must expose an output-size confounder"
    );
}

/// A backend whose fixed RSAES capability probes cannot select an independently
/// validated contract must abort the campaign, never file an invalid candidate.
struct UnresolvableBackend(FixtureMeasurer);

impl Measurer for UnresolvableBackend {
    fn prepare(
        &mut self,
        _scenario: Scenario,
        _pair: InputPair,
    ) -> Result<PreparedPair, PrepareFailure> {
        Err(PrepareFailure::Backend(
            "RSAES capability probes did not uniquely match a known independent contract".into(),
        ))
    }
    fn label(&self) -> String {
        "reference".into()
    }
    fn info(&self) -> WorkerInfo {
        [(
            "openssl_version".into(),
            "OpenSSL 3.0.13 30 Jan 2024".into(),
        )]
        .into()
    }
    fn load(&mut self, p: &PreparedPair, o: LoadOrder) -> Result<LoadedPair, MeasureFailure> {
        self.0.load(p, o)
    }
    fn measure(
        &mut self,
        p: &LoadedPair,
        n: usize,
        w: usize,
        s: u64,
    ) -> Result<RawBatch, MeasureFailure> {
        self.0.measure(p, n, w, s)
    }
    fn execute_once(&mut self, p: &LoadedPair) -> Result<[Vec<u8>; 2], MeasureFailure> {
        self.0.execute_once(p)
    }
}

#[test]
fn a_backend_that_cannot_resolve_its_rsaes_contract_aborts_the_campaign() {
    let sandbox = common::Sandbox::new("rsaes-backend-aborts");
    let mut config = fixture_config(7, true);
    config.scenario = Scenario::RsaDecrypt(RsaBits::B1024, RsaPadding::Rsaes);
    config.max_evaluations = 5;
    config.random_seed_pairs = 0;
    let dir = sandbox.root.join("search");
    let measurer = UnresolvableBackend(FixtureMeasurer::new("reference", no_effect));
    let history_path = dir.join("history.jsonl");
    let result = run_campaign(measurer, &config, &dir, &sandbox.root.join("corpus"), None);
    let detail = match result {
        Err(SearchError::Infrastructure(detail)) => detail,
        Err(error) => panic!("expected an infrastructure abort, got: {error}"),
        Ok(_) => panic!("expected an infrastructure abort, campaign completed"),
    };
    assert!(detail.contains("backend expectation failure"), "{detail}");
    assert!(detail.contains("campaign aborted"), "{detail}");
    let rows: Vec<HistoryEntry> = fs::read_to_string(&history_path)
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
