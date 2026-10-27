mod common;

use std::fs;
use std::path::PathBuf;

use common::Sandbox;
use tpms_timing_tests::scenario::{InputPair, RsaesSelectorSpace, Scenario};
use tpms_timing_tests::verify::{
    content_naming, diagnostic_seeds, load_candidates, save_candidates, union_candidates,
};

/// Serializes a candidate the way it looked before the versioned selector
/// encoding existed: no `selector_encoding` field anywhere.
fn legacy_json(candidate: &tpms_timing_tests::search::CandidateFile) -> Vec<u8> {
    let mut value = serde_json::to_value(candidate).unwrap();
    value.as_object_mut().unwrap().remove("selector_encoding");
    serde_json::to_vec_pretty(&value).unwrap()
}

/// A current-format candidate file on disk (the tool's own save format).
fn save(
    dir: &std::path::Path,
    name: &str,
    candidate: &tpms_timing_tests::search::CandidateFile,
) -> PathBuf {
    fs::create_dir_all(dir).unwrap();
    let path = dir.join(name);
    candidate.save(&path).unwrap();
    path
}

struct Case {
    legacy: tpms_timing_tests::search::CandidateFile,
    diagnostic: tpms_timing_tests::search::CandidateFile,
    path: PathBuf,
}

fn legacy_case(scenario: Scenario, sandbox: &Sandbox, campaign_seed: u64) -> Case {
    let diagnostics = diagnostic_seeds(scenario, campaign_seed, 4);
    assert!(!diagnostics.is_empty());
    let current = diagnostics[0].clone();
    // Save in the legacy format, then reload: the loaded candidate decodes
    // with legacy-mod5 and keeps the same identity as the current twin.
    let path = sandbox
        .root
        .join(format!("legacy-{}.json", scenario.name()));
    fs::write(&path, legacy_json(&current)).unwrap();
    let legacy = tpms_timing_tests::search::CandidateFile::load(&path).unwrap();
    assert_eq!(legacy.selector_encoding, RsaesSelectorSpace::LegacyMod5);
    assert_eq!(diagnostic_encoding(&current), RsaesSelectorSpace::V2Tagged);
    let _ = scenario;
    Case {
        legacy,
        diagnostic: current,
        path,
    }
}

fn diagnostic_encoding(candidate: &tpms_timing_tests::search::CandidateFile) -> RsaesSelectorSpace {
    candidate.selector_encoding
}

/// The verification merge exactly as `verify` performs it: the default
/// boundary diagnostic with the identical artifact stem merges into the loaded
/// candidate, proving legacy non-RSAES candidates verify alongside generated
/// diagnostics instead of failing before measurement.
fn verify_merges_current_diagnostics(case: &Case) {
    let stem = case.diagnostic.artifact_stem().unwrap();
    assert_eq!(
        case.legacy.artifact_stem().unwrap(),
        stem,
        "identical non-RSAES bytes keep one identity across encodings"
    );
    let mut merged = case.legacy.clone();
    merged.merge(&case.diagnostic).unwrap();
    assert!(
        merged
            .provenance
            .iter()
            .any(|p| p.label == case.diagnostic.id),
        "the diagnostic's provenance stays associated with the right candidate"
    );
    assert!(!merged.provenance.is_empty());
}

#[test]
fn legacy_ecc_candidates_verify_alongside_default_seed_diagnostics() {
    let sandbox = Sandbox::new("legacy-ecc-candidates");
    let case = legacy_case(Scenario::parse("ecdh-p521").unwrap(), &sandbox, 1);
    verify_merges_current_diagnostics(&case);
    // The whole union/dedup flow keeps exactly one candidate for these
    // bytes, whichever encoding recorded them.
    let (mut loaded, _) = load_candidates(&[], std::slice::from_ref(&case.path)).unwrap();
    loaded.push(case.diagnostic.clone());
    let (unique, total) = union_candidates(loaded, 10).unwrap();
    assert_eq!(total, 1, "legacy and current twins deduplicate");
    assert_eq!(unique.len(), 1);
    assert_eq!(
        unique[0].content_sha256().unwrap(),
        case.legacy.content_sha256().unwrap()
    );
}

#[test]
fn legacy_authentication_candidates_verify_alongside_default_seed_diagnostics() {
    let sandbox = Sandbox::new("legacy-auth-candidates");
    let scenario = Scenario::parse("auth-password").unwrap();
    let case = legacy_case(scenario, &sandbox, 1);
    verify_merges_current_diagnostics(&case);
    let (mut loaded, _) = load_candidates(&[], std::slice::from_ref(&case.path)).unwrap();
    loaded.push(case.diagnostic.clone());
    let (unique, total) = union_candidates(loaded, 10).unwrap();
    assert_eq!(total, 1);
    assert_eq!(unique.len(), 1);
}

#[test]
fn legacy_candidates_of_control_scenarios_verify_with_default_diagnostics() {
    // End-to-end through the fixture CLI: a pre-versioning control candidate
    // and the default seed diagnostics it duplicates merge during
    // verification and the run completes.
    let scenario = Scenario::ControlPositive;
    let sandbox = Sandbox::new("legacy-control-verify");
    sandbox.serve_mode("normal");
    let diagnostics = diagnostic_seeds(scenario, 1, 4);
    assert!(!diagnostics.is_empty());
    let path = sandbox.root.join("legacy-control.json");
    fs::write(&path, legacy_json(&diagnostics[0])).unwrap();
    let (code, stdout, stderr, run) = sandbox.verify(&[path], &[]);
    assert_eq!(code, 0, "stderr:\n{stderr}\nstdout:\n{stdout}");
    let results = common::json(&run.join("results.json"));
    assert_eq!(
        results["results"].as_array().unwrap().len(),
        diagnostics.len(),
        "merged legacy candidate plus the remaining default diagnostics"
    );
    assert_eq!(results["outcome"], "completed");
    sandbox.assert_no_markdown(&run);
}

fn rsaes_high_byte_pair(selector: u8, space: RsaesSelectorSpace) -> InputPair {
    let mut input = vec![selector];
    input.extend((0..48usize).map(|i| (i * 31 + 7) as u8));
    InputPair::with_selector_space(input.clone(), input, space)
}

#[test]
fn distinct_rsaes_encodings_never_collide_in_identity_or_artifacts() {
    // Identical RSAES byte 135 with the legacy encoding means valid padding
    // (135 % 5 = 0); with the versioned encoding it means the kind-5
    // separator boundary. They must keep separate identities, artifact names
    // and meanings through merging, loading, deduplication and saving.
    let scenario = Scenario::parse("rsa-decrypt-1024-rsaes").unwrap();
    let legacy = tpms_timing_tests::search::seeded_candidate(
        scenario,
        "high-selector-legacy",
        rsaes_high_byte_pair(135, RsaesSelectorSpace::LegacyMod5),
        1,
    );
    let v2 = tpms_timing_tests::search::seeded_candidate(
        scenario,
        "high-selector-v2",
        rsaes_high_byte_pair(135, RsaesSelectorSpace::V2Tagged),
        1,
    );
    assert_ne!(
        legacy.content_sha256().unwrap(),
        v2.content_sha256().unwrap()
    );
    assert_ne!(legacy.artifact_stem().unwrap(), v2.artifact_stem().unwrap());
    let mut merged = legacy.clone();
    let error = merged.merge(&v2).unwrap_err();
    assert!(
        error.contains("migrate"),
        "sensitive merge refusal must explain the migration: {error}"
    );
    // Same bytes recorded against themselves in the same encoding merge fine.
    assert!(merged.merge(&legacy).is_ok());

    let sandbox = Sandbox::new("rsaes-encoding-artifacts");
    let dir = sandbox.root.join("save");
    let saved = save_candidates(&dir, &[legacy.clone(), v2.clone()], content_naming).unwrap();
    assert_eq!(saved.len(), 2);
    let (paths, names): (Vec<PathBuf>, Vec<String>) =
        saved.into_iter().map(|(name, path)| (path, name)).unzip();
    assert_ne!(names[0], names[1]);
    for ((path, name), bytes) in paths.iter().zip(&names).zip([&legacy, &v2]) {
        let reloaded = tpms_timing_tests::search::CandidateFile::load(path).unwrap();
        assert_eq!(reloaded.id, bytes.id, "{name}: identity survives save/load");
        assert_eq!(
            reloaded.selector_encoding, bytes.selector_encoding,
            "{name}: encoding survives save/load"
        );
        assert_eq!(reloaded.scalar_a, bytes.scalar_a);
    }

    // Deduplication keeps both meanings; same-encoding duplicates collapse.
    let (mut loaded, _) = load_candidates(&[], &paths).unwrap();
    loaded.push(legacy.clone());
    loaded.push(v2.clone());
    let (unique, total) = union_candidates(loaded, 10).unwrap();
    assert_eq!(total, 2, "two meanings survive union deduplication");
    assert_eq!(unique.len(), 2);
}

#[test]
fn rsaes_encodings_save_load_replay_without_silent_reinterpretation() {
    let scenario = Scenario::parse("rsa-decrypt-1024-rsaes").unwrap();
    let sandbox = Sandbox::new("rsaes-encoding-replay");
    let legacy = tpms_timing_tests::search::seeded_candidate(
        scenario,
        "high-selector-legacy",
        rsaes_high_byte_pair(135, RsaesSelectorSpace::LegacyMod5),
        1,
    );
    let v2 = tpms_timing_tests::search::seeded_candidate(
        scenario,
        "high-selector-v2",
        rsaes_high_byte_pair(135, RsaesSelectorSpace::V2Tagged),
        1,
    );
    // The recorded semantics: legacy says valid padding, the versioned space
    // says the kind-5 separator boundary. Exactly as replay will prepare them.
    let legacy_prepared =
        tpms_timing_tests::scenario::PreparedPair::try_prepare(scenario, legacy.inputs().unwrap())
            .unwrap();
    let v2_prepared =
        tpms_timing_tests::scenario::PreparedPair::try_prepare(scenario, v2.inputs().unwrap())
            .unwrap();
    assert_eq!(legacy_prepared.metadata.expected_response_codes, [0, 0]);
    assert_eq!(
        v2_prepared.metadata.expected_response_codes,
        [
            tpms_timing_tests::tpm::TPM_RC_VALUE,
            tpms_timing_tests::tpm::TPM_RC_VALUE
        ]
    );

    let dir = sandbox.root.join("verified");
    let legacy_path = save(
        &dir,
        &format!("{}.json", legacy.artifact_stem().unwrap()),
        &legacy,
    );
    let v2_path = save(&dir, &format!("{}.json", v2.artifact_stem().unwrap()), &v2);
    // Reloading from disk keeps each recorded encoding, and preparing the
    // reloaded bytes reproduces exactly the semantics recorded at save time.
    for (path, codes) in [
        (&legacy_path, [0u32, 0]),
        (
            &v2_path,
            [
                tpms_timing_tests::tpm::TPM_RC_VALUE,
                tpms_timing_tests::tpm::TPM_RC_VALUE,
            ],
        ),
    ] {
        let reloaded = tpms_timing_tests::search::CandidateFile::load(path).unwrap();
        let prepared = tpms_timing_tests::scenario::PreparedPair::try_prepare(
            reloaded.scenario,
            reloaded.inputs().unwrap(),
        )
        .unwrap();
        assert_eq!(
            prepared.metadata.expected_response_codes,
            codes,
            "no silent reinterpretation of {}",
            path.display()
        );
    }
}

#[test]
fn run_commands_report_final_results_on_stdout_and_diagnostics_on_stderr() {
    // The verify/replay/check/self-test result lines are human-readable
    // results and must land on stdout; the run keeps its diagnostics and the
    // structured JSON artifact on their own channels.
    let scenario = Scenario::ControlPositive;
    let sandbox = Sandbox::new("stdout-separation");
    sandbox.serve_mode("normal");
    let diagnostics = diagnostic_seeds(scenario, 1, 1);
    let file = common::write_candidate(&sandbox.root.join("c"), "candidate.json", &diagnostics[0]);
    let (code, stdout, stderr, run) =
        sandbox.verify(std::slice::from_ref(&file), &["--seed-diagnostics", "0"]);
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stdout.contains("verification outcome Completed"),
        "{stdout}"
    );
    assert!(stdout.contains("verify "), "{stdout}");
    assert!(stdout.contains("summary: "), "{stdout}");
    assert!(
        !stderr.contains("verification outcome"),
        "results must not leak back into the diagnostic stream: {stderr}"
    );
    assert!(run.join("results.json").is_file());

    let (code, stdout, stderr) = sandbox.run_with_stdout(&[
        "replay",
        "--candidate",
        file.to_str().unwrap(),
        "--samples-per-class",
        "4",
        "--batches",
        "1",
        "--out-dir",
        sandbox.out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("replayed "), "{stdout}");
    assert!(stdout.contains("replay outcome Completed"), "{stdout}");
    assert!(
        stdout.contains("exploratory ranking evidence, not verification"),
        "{stdout}"
    );
    assert!(
        !stderr.contains("replayed "),
        "diagnostics stay on stderr: {stderr}"
    );

    let (code, stdout, stderr) =
        sandbox.run_with_stdout(&["self-test", "--out-dir", sandbox.out.to_str().unwrap()]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("self-test outcome Completed"), "{stdout}");
    assert!(stdout.contains("summary: "), "{stdout}");
    assert!(
        !stdout.contains("# "),
        "stream output must stay plain text, never document markup: {stdout}"
    );
    sandbox.assert_no_markdown(&sandbox.out);
}
