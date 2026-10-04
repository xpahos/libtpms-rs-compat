mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use common::*;
use tpms_timing_tests::scalar::ScalarPair;
use tpms_timing_tests::search::{CandidateFile, Orientation};
use tpms_timing_tests::verify::{
    ArtifactNaming, content_naming, legacy_label_naming, save_candidates, union_candidates,
};

fn plan_classes(plan: &std::path::Path) -> (String, String) {
    let text = fs::read_to_string(plan).unwrap();
    let get = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{key} ")))
            .unwrap()
            .to_string()
    };
    (get("class0"), get("class1"))
}

fn same_label_pair() -> (CandidateFile, CandidateFile) {
    (
        candidate("rust-e00001", pair(1), "campaign-a"),
        candidate("rust-e00001", pair(2), "campaign-b"),
    )
}

fn distinct_evidence(naming: ArtifactNaming) -> Result<(), String> {
    let (first, second) = same_label_pair();
    let (union, total) = union_candidates(vec![first.clone(), second.clone()], 10)?;
    if total != 2 || union.len() != 2 {
        return Err(format!("union kept {} of 2", union.len()));
    }
    let dir = std::env::temp_dir().join(format!(
        "tpms-collision-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = fs::remove_dir_all(&dir);
    let saved = save_candidates(&dir, &union, naming)?;
    let files: BTreeSet<PathBuf> = saved.iter().map(|(_, p)| p.clone()).collect();
    if files.len() != 2 {
        return Err("two candidates share one artifact file".into());
    }
    for (original, (_, path)) in [first, second].iter().zip(&saved) {
        let loaded = CandidateFile::load(path)?;
        if loaded.pair()? != original.pair()? {
            return Err(format!("{} holds the wrong scalar pair", path.display()));
        }
    }
    fs::remove_dir_all(&dir).ok();
    Ok(())
}

#[test]
fn union_and_save_keep_two_candidates_with_the_same_legacy_label() {
    distinct_evidence(content_naming).unwrap();
}

#[test]
fn negative_control_reintroducing_label_naming_fails_the_regression() {
    let error = distinct_evidence(legacy_label_naming).unwrap_err();
    assert!(error.contains("collision"), "{error}");
}

#[test]
fn negative_control_pre_fix_overwrite_loses_evidence() {
    let (first, second) = same_label_pair();
    let dir = std::env::temp_dir().join(format!("tpms-overwrite-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    for candidate in [&first, &second] {
        fs::write(
            dir.join(format!("{}.json", candidate.id)),
            serde_json::to_vec(candidate).unwrap(),
        )
        .unwrap();
    }
    let remaining = fs::read_dir(&dir).unwrap().count();
    assert_eq!(
        remaining, 1,
        "the pre-fix naming leaves a single file for two candidates"
    );
    let survivor = CandidateFile::load(&dir.join("rust-e00001.json")).unwrap();
    assert_ne!(
        survivor.pair().unwrap(),
        first.pair().unwrap(),
        "the first candidate's evidence was overwritten"
    );
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn verification_and_replay_use_each_candidates_own_pair() {
    let sandbox = Sandbox::new("collision-cli");
    sandbox.serve_mode("normal");
    sandbox.modes(&["signal", "signal", "nosignal", "nosignal"]);
    let (first, second) = same_label_pair();
    let files = vec![
        write_candidate(
            &sandbox.root.join("campaign-a/search/rust/candidates"),
            "rust-e00001.json",
            &first,
        ),
        write_candidate(
            &sandbox.root.join("campaign-b/search/rust/candidates"),
            "rust-e00001.json",
            &second,
        ),
    ];
    let (code, stderr, run) = sandbox.verify(&files, &[]);
    assert_eq!(code, 0, "{stderr}");
    let results = json(&run.join("results.json"));
    let entries = results["results"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    let artifacts: BTreeSet<&str> = entries
        .iter()
        .map(|e| e["artifact"].as_str().unwrap())
        .collect();
    assert_eq!(artifacts.len(), 2, "artifacts must differ");
    let mut log_dirs = BTreeSet::new();
    for (entry, original) in entries.iter().zip([&first, &second]) {
        assert_eq!(entry["id"], "rust-e00001");
        let file = PathBuf::from(entry["candidate_file"].as_str().unwrap());
        assert!(file.starts_with(run.join("candidates")));
        let saved = CandidateFile::load(&file).unwrap();
        assert_eq!(saved.pair().unwrap(), original.pair().unwrap());
        assert_eq!(entry["content_sha256"], saved.content_sha256().unwrap());
        assert_eq!(entry["provenance"].as_array().unwrap().len(), 1);
        for record in entry["runs"].as_array().unwrap() {
            let dir = PathBuf::from(record["directory"].as_str().unwrap());
            assert!(dir.starts_with(run.join("verify").join(entry["artifact"].as_str().unwrap())));
            assert!(
                log_dirs.insert(dir.clone()),
                "run directory reused: {}",
                dir.display()
            );
            assert!(dir.join("dudect-stdout.log").is_file());
            let (class0, class1) = plan_classes(&dir.join("plan.txt"));
            let pair = original.pair().unwrap();
            let expected: ScalarPair = pair;
            assert_eq!(class0, hex::encode(expected.a.bytes()));
            assert_eq!(class1, hex::encode(expected.b.bytes()));
        }
    }
    assert_eq!(log_dirs.len(), 4);
    for (entry, original) in entries.iter().zip([&first, &second]) {
        let file = entry["candidate_file"].as_str().unwrap();
        let (code, stderr) = sandbox.run(&[
            "replay",
            "--candidate",
            file,
            "--batches",
            "1",
            "--samples-per-class",
            "20",
            "--out-dir",
            sandbox.out.to_str().unwrap(),
        ]);
        assert_eq!(code, 0, "{stderr}");
        let replay_run = sandbox
            .run_dirs()
            .into_iter()
            .filter(|d| d.join("replay.json").exists())
            .find(|d| json(&d.join("replay.json"))["candidate_file"] == file)
            .unwrap();
        let replay = json(&replay_run.join("replay.json"));
        let pair = original.pair().unwrap();
        assert_eq!(replay["scalar_a"], hex::encode(pair.a.bytes()));
        assert_eq!(replay["scalar_b"], hex::encode(pair.b.bytes()));
        assert_eq!(replay["artifact"], entry["artifact"]);
    }
}

#[test]
fn identical_inputs_from_different_campaigns_merge_provenance() {
    let shared = pair(9);
    let reversed = ScalarPair {
        a: shared.b,
        b: shared.a,
    };
    let one = candidate("rust-e00004", shared, "campaign-a");
    let two = candidate("reference-e00017", shared, "campaign-b");
    let three = candidate("rust-e00002", reversed, "campaign-c");
    let other = candidate("rust-e00004", pair(10), "campaign-d");
    let (union, total) = union_candidates(vec![one.clone(), two, three, other], 10).unwrap();
    assert_eq!(total, 2);
    let merged = union
        .iter()
        .find(|c| c.pair().unwrap() == shared)
        .expect("the first-seen orientation is kept");
    assert_eq!(merged.provenance.len(), 3);
    let labels: Vec<&str> = merged.provenance.iter().map(|p| p.label.as_str()).collect();
    assert_eq!(labels, ["rust-e00004", "reference-e00017", "rust-e00002"]);
    let runs: BTreeSet<_> = merged
        .provenance
        .iter()
        .map(|p| p.search_run.clone().unwrap())
        .collect();
    assert_eq!(runs.len(), 3);
    assert_eq!(merged.provenance[2].orientation, Orientation::Reversed);
    assert_eq!(merged.provenance[0].orientation, Orientation::AsRecorded);

    let sandbox = Sandbox::new("merge-cli");
    sandbox.serve_mode("normal");
    sandbox.modes(&["signal", "signal", "signal", "signal"]);
    let files = vec![
        write_candidate(&sandbox.root.join("a"), "x.json", &one),
        write_candidate(
            &sandbox.root.join("b"),
            "x.json",
            &candidate("reference-e00017", shared, "campaign-b"),
        ),
        write_candidate(
            &sandbox.root.join("c"),
            "x.json",
            &candidate("rust-e00002", reversed, "campaign-c"),
        ),
    ];
    let (code, stderr, run) = sandbox.verify(&files, &[]);
    assert_eq!(code, 0, "{stderr}");
    let results = json(&run.join("results.json"));
    let entries = results["results"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["provenance"].as_array().unwrap().len(), 3);
    let sources: BTreeSet<&str> = entries[0]["provenance"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["source_file"].as_str().unwrap())
        .collect();
    assert_eq!(sources.len(), 3);
    let saved = CandidateFile::load(&PathBuf::from(
        entries[0]["candidate_file"].as_str().unwrap(),
    ))
    .unwrap();
    assert_eq!(
        saved.pair().unwrap(),
        shared,
        "class orientation follows the first contributing candidate"
    );
}

#[test]
fn unsafe_labels_never_become_paths() {
    let sandbox = Sandbox::new("unsafe-label");
    sandbox.serve_mode("normal");
    sandbox.modes(&["signal", "signal"]);
    let file = write_candidate(
        &sandbox.root.join("c"),
        "c.json",
        &candidate("../../../escape", pair(11), "campaign"),
    );
    let (code, stderr, run) = sandbox.verify(&[file], &[]);
    assert_eq!(code, 0, "{stderr}");
    assert!(!sandbox.root.join("escape").exists());
    let results = json(&run.join("results.json"));
    let artifact = results["results"][0]["artifact"].as_str().unwrap();
    assert!(artifact.starts_with("control-positive-") && !artifact.contains('/'));
    assert!(run.join("verify").join(artifact).is_dir());
}

#[test]
fn existing_evidence_is_never_overwritten() {
    let (first, _) = same_label_pair();
    let dir = std::env::temp_dir().join(format!("tpms-no-overwrite-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    save_candidates(&dir, std::slice::from_ref(&first), content_naming).unwrap();
    let error = save_candidates(&dir, std::slice::from_ref(&first), content_naming).unwrap_err();
    assert!(error.contains("already exists"), "{error}");
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn generated_seed_diagnostics_carry_provenance() {
    let sandbox = Sandbox::new("diagnostic-provenance");
    sandbox.serve_mode("normal");
    sandbox.modes(&["nosignal"; 8]);
    let (code, stderr, run) = sandbox.verify(
        &[],
        &["--scenario", "control-positive", "--seed-diagnostics", "2"],
    );
    assert_eq!(code, 0, "{stderr}");
    let results = json(&run.join("results.json"));
    let entries = results["results"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    for entry in entries {
        let provenance = entry["provenance"].as_array().unwrap();
        assert_eq!(provenance.len(), 1, "{entry}");
        assert_eq!(provenance[0]["label"], entry["id"]);
        assert_eq!(provenance[0]["kind"], "seeded-diagnostic");
        let saved = json(&PathBuf::from(entry["candidate_file"].as_str().unwrap()));
        assert_eq!(saved["provenance"], entry["provenance"]);
    }
}
