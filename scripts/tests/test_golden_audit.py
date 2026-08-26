import contextlib
import copy
import hashlib
import os
import importlib.util
import io
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path

GOLDEN_PATH = (
    Path(__file__).resolve().parent.parent / "golden_responses" / "golden.py"
)

spec = importlib.util.spec_from_file_location("golden", GOLDEN_PATH)
golden = importlib.util.module_from_spec(spec)
spec.loader.exec_module(golden)

golden_docker_output = golden.docker_output
golden_image_label = golden.image_label
golden_image_platform = golden.image_platform

SHIM = "scripts/golden_responses/entropy_shim.c"
SCENARIO_A = "scripts/golden_responses/scenarios/alpha.scenario"
SCENARIO_B = "scripts/golden_responses/scenarios/beta.scenario"


def baseline_manifest():
    return {
        "reference": {"docker_platform": "linux/arm64"},
        "families": {
            "alpha": {
                "magic": "AAORACLE",
                "scenario": SCENARIO_A,
                "fixture": "src/library/tpm2/testdata/golden_responses/create.bin",
                "reader": "src/library/tpm2/golden_responses/create.rs",
                "commands": ["TPM2_Create"],
            },
            "beta": {
                "magic": "BBORACLE",
                "scenario": SCENARIO_B,
                "fixture": "src/library/tpm2/testdata/golden_responses/create_loaded.bin",
                "reader": "src/library/tpm2/golden_responses/create_loaded.rs",
                "commands": ["TPM2_CreateLoaded"],
            },
        },
        "commands": {},
    }


def reader_source(magic, fixture):
    return (
        f'const MAGIC: &[u8; 8] = b"{magic}";\n\n'
        "static FIXTURE: Fixture = Fixture::new(\n"
        '    "label",\n'
        "    MAGIC,\n"
        f'    include_bytes!("../testdata/golden_responses/{fixture}"),\n'
        ");\n"
    )


def baseline_facts():
    return {
        "libtpms_commit": "a" * 40,
        "docker_from_name": "debian:12.11-slim",
        "docker_from_digest": "sha256:" + "c" * 64,
        "docker_snapshots": ["20250811T000000Z", "20250811T000000Z"],
        "docker_configure_flags": [
            "--with-tpm2",
            "--with-openssl",
            "--disable-shared",
            "--disable-use-openssl-functions",
        ],
        "docker_shim_compile_flags": ["-shared", "-fPIC"],
        "docker_packages": [("autoconf", "2.71-3"), ("build-essential", "12.9")],
        "docker_package_tokens": ["autoconf=2.71-3", "build-essential=12.9"],
        "docker_faketime": "@2026-01-01 00:00:00 x0.0",
        "docker_entropy_seed": "00000000c0ffee01",
        "docker_shim_referenced": True,
        "docker_ld_preload": [
            "/usr/local/lib/entropy_shim.so",
            "/usr/local/lib/libfaketime.so.1",
        ],
        "existing_files": {SHIM, SCENARIO_A, SCENARIO_B},
        "tracked_files": {SHIM, SCENARIO_A, SCENARIO_B},
        "tracked_replay_files": {
            "src/library/tpm2/testdata/golden_responses/create.bin",
            "src/library/tpm2/testdata/golden_responses/create_loaded.bin",
            "src/library/tpm2/golden_responses/create.rs",
            "src/library/tpm2/golden_responses/create_loaded.rs",
        },
        "reader_sources": {
            "src/library/tpm2/golden_responses/create.rs": reader_source(
                "AAORACLE", "create.bin"
            ),
            "src/library/tpm2/golden_responses/create_loaded.rs": reader_source(
                "BBORACLE", "create_loaded.bin"
            ),
        },
        "shim_monotonic_base": 1000000000000,
        "shim_monotonic_step": 0,
        "shim_clocks": ["CLOCK_MONOTONIC", "CLOCK_BOOTTIME"],
        "shim_symbols": {
            "RAND_bytes",
            "RAND_priv_bytes",
            "RAND_status",
            "clock_gettime",
            "golden_advance_monotonic_ms",
        },
        "shim_constants": set(golden.ENTROPY_ALGORITHMS["splitmix64"]),
        "submodule_dirt": {"libtpms": []},
        "image_checked": True,
        "image_tag": "libtpms-golden:test",
        "image_platform": "linux/arm64",
        "image_packages": {"autoconf": "2.71-3", "build-essential": "12.9"},
        **clean_entropy_facts(),
        **clean_clock_facts(),
    }


def clean_clock_facts():
    base = golden.CLOCK_BASE_NANOSECONDS
    first = base + golden.CLOCK_FIRST_ADVANCE_MS * 1_000_000
    second = base + (golden.CLOCK_FIRST_ADVANCE_MS + golden.CLOCK_SECOND_ADVANCE_MS) * 1_000_000
    wall = 1767225600 * 1_000_000_000
    readings = []
    for name in golden.MONOTONIC_CLOCK_IDS:
        readings += [
            f"{name}={base}",
            f"{name}_repeat={base}",
            f"{name}_first={first}",
            f"{name}_second={second}",
        ]
    readings += [
        f"CLOCK_REALTIME={wall}",
        f"CLOCK_REALTIME_repeat={wall}",
        f"CLOCK_REALTIME_first={wall}",
        f"CLOCK_REALTIME_second={wall}",
    ]
    probe = " ".join(readings)
    return {
        "clock_probe": probe,
        "clock_probe_restart": probe,
        "reproducibility": "cached",
    }


def clean_entropy_facts():
    vectors = golden.ENTROPY_VECTORS["splitmix64"]
    stream = " ".join([*vectors["outputs"], vectors["private"], vectors["status"]])
    return {
        "entropy_primary": stream,
        "entropy_restart": stream,
        "entropy_vector_seed": stream,
        "entropy_alternate": vectors["alternate_first"] + " a b c d e 1",
        "entropy_invalid_seed": None,
    }


def rendered(violations):
    return [violation.render() for violation in violations]


def structured_violations(manifest, facts):
    return (
        golden.validate_manifest_shape(manifest)
        + golden.validate_manifest_paths(manifest)
        + golden.validate_capture_environment(manifest, facts)
        + golden.validate_submodules(manifest, facts)
        + golden.validate_scenarios(manifest, facts)
        + golden.validate_readers(manifest, facts)
        + golden.validate_image(manifest, facts)
    )


def all_violations(manifest, facts):
    return [violation.render() for violation in structured_violations(manifest, facts)]


class GoldenManifestTest(unittest.TestCase):
    def assert_violation(self, manifest, facts, substring):
        self.assertEqual(all_violations(baseline_manifest(), baseline_facts()), [])
        violations = all_violations(manifest, facts)
        self.assertTrue(
            any(substring in violation for violation in violations),
            f"{substring!r} not found in {violations!r}",
        )

    def test_baseline_is_clean(self):
        self.assertEqual(all_violations(baseline_manifest(), baseline_facts()), [])

    def test_unknown_top_level_table(self):
        manifest = baseline_manifest()
        manifest["decoration"] = {}
        self.assert_violation(manifest, baseline_facts(), "unknown top-level table")

    def test_unknown_reference_field(self):
        manifest = baseline_manifest()
        manifest["reference"]["kernel"] = "6.1"
        self.assert_violation(manifest, baseline_facts(), "unknown [reference] field")

    def test_unknown_family_field(self):
        manifest = baseline_manifest()
        manifest["families"]["alpha"]["capture_mode"] = "legacy"
        self.assert_violation(manifest, baseline_facts(), "unknown field 'capture_mode'")

    def test_missing_family_field(self):
        manifest = baseline_manifest()
        del manifest["families"]["alpha"]["reader"]
        self.assert_violation(manifest, baseline_facts(), "missing 'reader'")

    def test_unknown_command_field(self):
        manifest = baseline_manifest()
        manifest["commands"]["Create"] = {"code": 0x153, "status": "todo", "note": "x"}
        self.assert_violation(manifest, baseline_facts(), "unknown field 'note'")

    def test_duplicate_scenario_assignment(self):
        manifest = baseline_manifest()
        manifest["families"]["beta"]["scenario"] = SCENARIO_A
        self.assert_violation(manifest, baseline_facts(), "duplicate scenario assignment")

    def test_scenario_outside_the_directory(self):
        manifest = baseline_manifest()
        manifest["families"]["alpha"]["scenario"] = "/etc/passwd"
        self.assert_violation(manifest, baseline_facts(), "must be a relative path")

    def test_missing_scenario_file(self):
        facts = baseline_facts()
        facts["existing_files"] = facts["existing_files"] - {SCENARIO_A}
        self.assert_violation(baseline_manifest(), facts, "does not exist")

    def test_untracked_scenario(self):
        facts = baseline_facts()
        facts["tracked_files"] = facts["tracked_files"] - {SCENARIO_A}
        self.assert_violation(baseline_manifest(), facts, "not tracked by git")

    def test_family_without_scenario(self):
        manifest = baseline_manifest()
        del manifest["families"]["alpha"]["scenario"]
        self.assert_violation(manifest, baseline_facts(), "missing 'scenario'")

    def test_unpinned_base_image(self):
        facts = baseline_facts()
        facts["docker_from_digest"] = None
        self.assert_violation(baseline_manifest(), facts, "pin its base image by digest")

    def test_missing_snapshot(self):
        facts = baseline_facts()
        facts["docker_snapshots"] = []
        self.assert_violation(baseline_manifest(), facts, "Debian snapshot")

    def test_openssl_functions_not_disabled(self):
        facts = baseline_facts()
        facts["docker_configure_flags"] = ["--with-tpm2"]
        self.assert_violation(baseline_manifest(), facts, "disable the OpenSSL key generation")

    def test_unfrozen_wall_clock(self):
        facts = baseline_facts()
        facts["docker_faketime"] = "@2026-01-01 00:00:00 i0.01"
        self.assert_violation(baseline_manifest(), facts, "freeze the wall clock")

    def test_shim_not_preloaded(self):
        facts = baseline_facts()
        facts["docker_ld_preload"] = ["/usr/local/lib/libfaketime.so.1"]
        self.assert_violation(baseline_manifest(), facts, "entropy shim is not preloaded")

    def test_shim_missing_symbol(self):
        facts = baseline_facts()
        facts["shim_symbols"] = facts["shim_symbols"] - {"RAND_priv_bytes"}
        self.assert_violation(baseline_manifest(), facts, "does not interpose RAND_priv_bytes")

    def test_shim_missing_advance_hook(self):
        facts = baseline_facts()
        facts["shim_symbols"] = facts["shim_symbols"] - {"golden_advance_monotonic_ms"}
        self.assert_violation(baseline_manifest(), facts, "golden_advance_monotonic_ms")

    def test_shim_advances_per_query(self):
        facts = baseline_facts()
        facts["shim_monotonic_step"] = 10000000
        self.assert_violation(baseline_manifest(), facts, "must not advance the monotonic clock")

    def test_shim_missing_algorithm_constant(self):
        facts = baseline_facts()
        facts["shim_constants"] = set(list(facts["shim_constants"])[:2])
        self.assert_violation(baseline_manifest(), facts, "does not implement splitmix64")

    def test_dirty_submodule(self):
        facts = baseline_facts()
        facts["submodule_dirt"]["libtpms"] = ["untracked file src/x.c"]
        self.assert_violation(baseline_manifest(), facts, "is dirty")

    def test_image_platform_mismatch(self):
        facts = baseline_facts()
        facts["image_platform"] = "linux/amd64"
        self.assert_violation(baseline_manifest(), facts, "platform")

    def test_missing_capture_image(self):
        facts = baseline_facts()
        facts["image_packages"] = None
        self.assert_violation(baseline_manifest(), facts, "no capture image")

    def test_entropy_stream_mismatch(self):
        facts = baseline_facts()
        facts["entropy_primary"] = "deadbeef a b c d e 1"
        facts["entropy_vector_seed"] = facts["entropy_primary"]
        self.assert_violation(baseline_manifest(), facts, "does not produce the splitmix64 vectors")

    def test_seed_without_effect(self):
        facts = baseline_facts()
        facts["entropy_alternate"] = facts["entropy_primary"]
        self.assert_violation(baseline_manifest(), facts, "same stream")

    def test_accepted_invalid_seed(self):
        facts = baseline_facts()
        facts["entropy_invalid_seed"] = "00 11 22 33 44 55 1"
        self.assert_violation(baseline_manifest(), facts, "non-hex GOLDEN_ENTROPY_SEED")

    def test_unversioned_package(self):
        facts = baseline_facts()
        facts["docker_packages"] = [("autoconf", None), ("build-essential", "12.9")]
        self.assert_violation(baseline_manifest(), facts, "without a pinned version")

    def test_empty_package_version(self):
        facts = baseline_facts()
        facts["docker_packages"] = [("autoconf", ""), ("build-essential", "12.9")]
        self.assert_violation(baseline_manifest(), facts, "empty version")

    def test_duplicate_package(self):
        facts = baseline_facts()
        facts["docker_packages"] = [
            ("autoconf", "2.71-3"),
            ("autoconf", "2.71-3"),
            ("build-essential", "12.9"),
        ]
        self.assert_violation(baseline_manifest(), facts, "declared more than once")

    def test_malformed_package_token(self):
        facts = baseline_facts()
        facts["docker_packages"] = [("--yes", "1"), ("build-essential", "12.9")]
        self.assert_violation(baseline_manifest(), facts, "malformed package token")

    def test_renamed_package_is_absent_from_the_image(self):
        facts = baseline_facts()
        facts["docker_packages"] = [("autoconf2", "2.71-3"), ("build-essential", "12.9")]
        self.assert_violation(baseline_manifest(), facts, "absent from the image")

    def test_installed_version_mismatch(self):
        facts = baseline_facts()
        facts["image_packages"]["autoconf"] = "9.9"
        self.assert_violation(baseline_manifest(), facts, "the Dockerfile pins")

    def test_package_parsing_splits_name_and_version(self):
        parsed = golden.parse_dockerfile(golden.DOCKERFILE.read_text("utf-8"))
        for name, version in parsed["docker_packages"]:
            self.assertNotIn("=", name)
            self.assertTrue(version)
        self.assertIn(("python3", "3.11.2-1+b1"), parsed["docker_packages"])

    def test_clock_base_mismatch(self):
        facts = baseline_facts()
        facts["clock_probe"] = facts["clock_probe"].replace(
            f"CLOCK_MONOTONIC={golden.CLOCK_BASE_NANOSECONDS}", "CLOCK_MONOTONIC=5", 1
        )
        self.assert_violation(baseline_manifest(), facts, "starts at 5")

    def test_clock_advances_without_a_request(self):
        facts = baseline_facts()
        facts["clock_probe"] = facts["clock_probe"].replace(
            f"CLOCK_MONOTONIC_repeat={golden.CLOCK_BASE_NANOSECONDS}",
            f"CLOCK_MONOTONIC_repeat={golden.CLOCK_BASE_NANOSECONDS + 1}",
            1,
        )
        self.assert_violation(baseline_manifest(), facts, "advanced without an explicit request")

    def test_clock_advance_multiplier(self):
        facts = baseline_facts()
        wrong = golden.CLOCK_BASE_NANOSECONDS + golden.CLOCK_FIRST_ADVANCE_MS * 500_000
        facts["clock_probe"] = facts["clock_probe"].replace(
            f"CLOCK_MONOTONIC_first={golden.CLOCK_BASE_NANOSECONDS + golden.CLOCK_FIRST_ADVANCE_MS * 1_000_000}",
            f"CLOCK_MONOTONIC_first={wrong}",
            1,
        )
        self.assert_violation(baseline_manifest(), facts, "after advancing")

    def test_wall_clock_not_frozen(self):
        facts = baseline_facts()
        wall = 1767225600 * 1_000_000_000
        facts["clock_probe"] = facts["clock_probe"].replace(
            f"CLOCK_REALTIME_repeat={wall}", f"CLOCK_REALTIME_repeat={wall + 1}", 1
        )
        self.assert_violation(baseline_manifest(), facts, "wall clock is not frozen")

    def test_wall_clock_disagrees_with_the_dockerfile(self):
        facts = baseline_facts()
        wall = 1767225600 * 1_000_000_000
        facts["clock_probe"] = facts["clock_probe"].replace(str(wall), str(wall + 10**9))
        self.assert_violation(baseline_manifest(), facts, "the Dockerfile pins")

    def test_clock_restart_mismatch(self):
        facts = baseline_facts()
        facts["clock_probe_restart"] = facts["clock_probe_restart"].replace(
            f"CLOCK_BOOTTIME={golden.CLOCK_BASE_NANOSECONDS}", "CLOCK_BOOTTIME=7", 1
        )
        self.assert_violation(baseline_manifest(), facts, "restart from the canonical base")

    def test_missing_clock_probe(self):
        facts = baseline_facts()
        facts["clock_probe"] = None
        self.assert_violation(baseline_manifest(), facts, "did not answer the probe")

    def test_reproducibility_probe_disagreement(self):
        facts = baseline_facts()
        facts["reproducibility"] = ["A x\nB y\n", "A x\nB z\n"]
        self.assert_violation(baseline_manifest(), facts, "did not record")

    def test_reproducibility_records_present_but_differing(self):
        facts = baseline_facts()
        lines = "\n".join(f"{name} aa" for name in golden.REPRODUCIBILITY_RECORDS)
        other = lines.replace("RANDOM_A aa", "RANDOM_A bb")
        facts["reproducibility"] = [lines + "\n", other + "\n"]
        self.assert_violation(baseline_manifest(), facts, "two fresh containers disagree")

    def test_reproducibility_empty_output(self):
        facts = baseline_facts()
        facts["reproducibility"] = ["", ""]
        self.assert_violation(baseline_manifest(), facts, "produced no output")


class GoldenContextTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.paths = golden.build_context(self.root)
        self.platform = "linux/arm64"
        self.identity = golden.context_identity(self.root, self.platform)

    def tearDown(self):
        self.directory.cleanup()

    def test_context_holds_the_dockerfile_and_tracked_inputs(self):
        self.assertIn("scripts/golden_responses/Dockerfile", self.paths)
        self.assertIn("scripts/golden_responses/entropy_shim.c", self.paths)
        self.assertIn("scripts/golden_responses/runner.c", self.paths)
        self.assertTrue(any(path.startswith("libtpms/src/") for path in self.paths))

    def test_context_excludes_the_manifest(self):
        self.assertNotIn("scripts/golden_responses/manifest.toml", self.paths)

    def test_context_excludes_ignored_submodule_artifacts(self):
        for path in self.paths:
            self.assertNotIn("autom4te.cache", path)
            self.assertFalse(path.endswith(".gch"))
            self.assertFalse(path.endswith("~"))
        self.assertNotIn("libtpms/configure", self.paths)
        self.assertNotIn("libtpms/aclocal.m4", self.paths)

    def test_ignored_submodule_artifact_does_not_change_the_context(self):
        artifact = golden.ROOT / "libtpms" / "config.log"
        self.assertFalse(artifact.exists())
        artifact.write_text("ambient host build artifact\n")
        try:
            with tempfile.TemporaryDirectory() as other:
                paths = golden.build_context(other)
                identity = golden.context_identity(other, self.platform)
        finally:
            artifact.unlink()
        self.assertEqual(paths, self.paths)
        self.assertEqual(identity, self.identity)

    def test_unrelated_untracked_file_does_not_enter_the_context(self):
        stray = golden.ROOT / "scripts" / "golden_responses" / "stray_note.txt"
        self.assertFalse(stray.exists())
        stray.write_text("scratch\n")
        try:
            with tempfile.TemporaryDirectory() as other:
                paths = golden.build_context(other)
                identity = golden.context_identity(other, self.platform)
        finally:
            stray.unlink()
        self.assertNotIn("scripts/golden_responses/stray_note.txt", paths)
        self.assertEqual(identity, self.identity)

    def test_changing_an_included_file_changes_the_identity(self):
        target = self.root / "scripts" / "golden_responses" / "runner.c"
        target.write_bytes(target.read_bytes() + b"\n")
        self.assertNotEqual(
            golden.context_identity(self.root, self.platform), self.identity
        )

    def test_every_context_file_contributes_to_the_identity(self):
        sample = self.paths[:: max(1, len(self.paths) // 12)] + [
            "scripts/golden_responses/Dockerfile",
            "scripts/golden_responses/entropy_shim.c",
            self.paths[-1],
        ]
        for path in sample:
            absolute = self.root / path
            original = absolute.read_bytes()
            absolute.write_bytes(original + b"\x00")
            mutated = golden.context_identity(self.root, self.platform)
            absolute.write_bytes(original)
            self.assertNotEqual(mutated, self.identity, path)
        self.assertEqual(golden.context_identity(self.root, self.platform), self.identity)

    def test_an_added_context_file_is_detected(self):
        (self.root / "smuggled.txt").write_text("not audited\n")
        self.assertIn("smuggled.txt", golden.context_paths(self.root))
        self.assertNotEqual(
            golden.context_identity(self.root, self.platform), self.identity
        )

    def test_the_mode_comes_from_the_stored_bits_not_from_access(self):
        target = Path(self.root) / "scripts" / "golden_responses" / "golden.py"
        before = golden.context_identity(self.root, self.platform)
        target.chmod(0o755)
        self.assertNotEqual(golden.context_identity(self.root, self.platform), before)
        target.chmod(0o644)
        self.assertEqual(golden.context_identity(self.root, self.platform), before)

    def test_a_group_only_execute_bit_still_counts_as_executable(self):
        target = Path(self.root) / "scripts" / "golden_responses" / "golden.py"
        target.chmod(0o755)
        executable = golden.context_identity(self.root, self.platform)
        target.chmod(0o654)
        self.assertEqual(golden.context_identity(self.root, self.platform), executable)
        target.chmod(0o644)

    def test_platform_participates_in_the_identity(self):
        self.assertNotEqual(
            golden.context_identity(self.root, "linux/amd64"), self.identity
        )

    def test_build_uses_the_generated_context(self):
        calls = []

        def fake_docker(arguments):
            calls.append(arguments)
            return None if arguments[0] == "image" else ""

        def fake_run(arguments, allow_empty=False, timeout=None):
            calls.append(arguments)
            return golden.DockerOutcome("ok")

        original = golden.docker_output
        original_run = golden.run_docker
        golden.docker_output = fake_docker
        golden.run_docker = fake_run
        try:
            golden.resolve_image(golden.load_manifest())
        finally:
            golden.docker_output = original
            golden.run_docker = original_run
        build = next(call for call in calls if call[0] == "build")
        context = build[-1]
        self.assertNotEqual(context, str(golden.ROOT))
        self.assertIn("golden-context-", context)
        self.assertIn("-f", build)
        self.assertIn("golden-context-", build[build.index("-f") + 1])



class GoldenEntropyContractTest(unittest.TestCase):
    def facts_with(self, **overrides):
        vectors = golden.ENTROPY_VECTORS["splitmix64"]
        stream = " ".join(
            [*vectors["outputs"], vectors["private"], vectors["status"]]
        )
        facts = {
            "image_checked": True,
            "entropy_primary": stream,
            "entropy_restart": stream,
            "entropy_vector_seed": stream,
            "entropy_alternate": vectors["alternate_first"] + " x x x x y 1",
            "entropy_invalid_seed": None,
        }
        facts.update(overrides)
        return facts

    def test_baseline_contract_is_clean(self):
        manifest = golden.load_manifest()
        self.assertEqual(
            golden.validate_entropy_behavior(manifest, self.facts_with()), []
        )

    def test_wrong_stream_fails(self):
        manifest = golden.load_manifest()
        broken = self.facts_with(
            entropy_primary="42d383507f956c628ef8893746e0885d a b c d e 1",
            entropy_vector_seed="42d383507f956c628ef8893746e0885d a b c d e 1",
        )
        violations = golden.validate_entropy_behavior(manifest, broken)
        self.assertTrue(any("does not produce the splitmix64 vectors" in v for v in rendered(violations)))

    def test_nondeterministic_restart_fails(self):
        manifest = golden.load_manifest()
        broken = self.facts_with(entropy_restart="something else")
        violations = golden.validate_entropy_behavior(manifest, broken)
        self.assertTrue(any("not deterministic across restarts" in v for v in rendered(violations)))

    def test_seed_without_effect_fails(self):
        manifest = golden.load_manifest()
        vectors = golden.ENTROPY_VECTORS["splitmix64"]
        stream = " ".join([*vectors["outputs"], vectors["private"], vectors["status"]])
        broken = self.facts_with(entropy_alternate=stream)
        violations = golden.validate_entropy_behavior(manifest, broken)
        self.assertTrue(any("expected" in v or "same stream" in v for v in rendered(violations)))

    def test_accepted_invalid_seed_fails(self):
        manifest = golden.load_manifest()
        broken = self.facts_with(entropy_invalid_seed="00 11 22 33 44 55 1")
        violations = golden.validate_entropy_behavior(manifest, broken)
        self.assertTrue(any("non-hex GOLDEN_ENTROPY_SEED" in v for v in rendered(violations)))

    def test_missing_probe_fails(self):
        manifest = golden.load_manifest()
        broken = self.facts_with(entropy_primary=None)
        violations = golden.validate_entropy_behavior(manifest, broken)
        self.assertTrue(any("did not answer" in v for v in rendered(violations)))




class GoldenFixtureCodecTest(unittest.TestCase):
    def setUp(self):
        self.codec = golden.load_packer()
        self.magic = b"TSTMAGIC"
        self.records = [("ALPHA", "aabb"), ("BETA", "ccdd")]
        self.blob = self.codec.pack(self.magic, self.records)

    def assert_rejected(self, blob, magic=None):
        with self.assertRaises(self.codec.FixtureFormatError):
            self.codec.unpack(magic or self.magic, blob)

    def test_round_trip(self):
        self.assertEqual(list(self.codec.unpack(self.magic, self.blob)), self.records)

    def test_unpack_returns_a_materialized_sequence(self):
        records = self.codec.unpack(self.magic, self.blob)
        self.assertNotIsInstance(records, types.GeneratorType)
        self.assertEqual(len(records), len(self.records))
        self.assertEqual(list(records), list(records))

    def test_a_truncated_header_raises_without_iteration(self):
        with self.assertRaises(self.codec.FixtureFormatError):
            self.codec.unpack(self.magic, self.blob[:10])

    def test_a_malformed_record_raises_without_iteration(self):
        broken = bytearray(self.blob)
        broken[13] = ord("a")
        with self.assertRaises(self.codec.FixtureFormatError):
            self.codec.unpack(self.magic, bytes(broken))

    def test_trailing_bytes_raise_without_iteration(self):
        with self.assertRaises(self.codec.FixtureFormatError):
            self.codec.unpack(self.magic, self.blob + b"\x00")

    def test_packing_is_deterministic(self):
        reversed_records = list(reversed(self.records))
        self.assertEqual(self.codec.pack(self.magic, reversed_records), self.blob)

    def test_empty_input(self):
        self.assert_rejected(b"")

    def test_partial_magic(self):
        self.assert_rejected(self.blob[:4])

    def test_wrong_magic(self):
        self.assert_rejected(self.blob, magic=b"OTHERMAG")

    def test_truncated_header(self):
        self.assert_rejected(self.blob[:10])

    def test_unsupported_version(self):
        broken = bytearray(self.blob)
        broken[8:10] = (99).to_bytes(2, "big")
        self.assert_rejected(bytes(broken))

    def test_every_truncation_is_controlled(self):
        for length in range(len(self.blob)):
            with self.assertRaises(
                self.codec.FixtureFormatError, msg=f"prefix of {length} bytes"
            ):
                self.codec.unpack(self.magic, self.blob[:length])

    def test_trailing_bytes(self):
        self.assert_rejected(self.blob + b"\x00")

    def test_record_count_beyond_the_payload(self):
        broken = bytearray(self.blob)
        broken[10:12] = (9).to_bytes(2, "big")
        self.assert_rejected(bytes(broken))

    def test_empty_record_name(self):
        broken = bytearray(self.blob)
        broken[12] = 0
        self.assert_rejected(bytes(broken))

    def test_non_ascii_record_name(self):
        broken = bytearray(self.blob)
        broken[13] = 0xFF
        self.assert_rejected(bytes(broken))

    def test_lower_case_record_name(self):
        broken = bytearray(self.blob)
        broken[13] = ord("a")
        self.assert_rejected(bytes(broken))

    def test_unsorted_records(self):
        blob = self.codec.pack(self.magic, self.records)
        unsorted = bytearray(blob)
        alpha = blob.index(b"ALPHA")
        unsorted[alpha : alpha + 5] = b"ZETA_"
        self.assert_rejected(bytes(unsorted))

    def test_duplicate_record_names(self):
        with self.assertRaises(self.codec.FixtureFormatError):
            self.codec.pack(self.magic, [("ALPHA", "aa"), ("ALPHA", "bb")])

    def test_odd_hex_payload(self):
        with self.assertRaises(self.codec.FixtureFormatError):
            self.codec.pack(self.magic, [("ALPHA", "aab")])

    def test_bad_listing_line(self):
        with self.assertRaises(self.codec.FixtureFormatError):
            list(self.codec.read_listing("ALPHA aa bb\n"))

    def test_committed_fixtures_decode(self):
        manifest = golden.load_manifest()
        for entry in manifest["families"].values():
            blob = (golden.ROOT / entry["fixture"]).read_bytes()
            records = self.codec.unpack(entry["magic"].encode("ascii"), blob)
            self.assertTrue(records)


class GoldenTransactionTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.fixtures = self.root / golden.FIXTURE_DIR
        self.fixtures.mkdir(parents=True)
        self.original_root = golden.ROOT
        golden.ROOT = self.root
        self.staged = []
        self.originals = {}
        for index in range(4):
            family = f"family{index}"
            path = self.fixtures / f"{family}.bin"
            path.write_bytes(f"original-{index}".encode("ascii"))
            self.originals[family] = path.read_bytes()
            self.staged.append(
                (
                    family,
                    {"fixture": golden.FIXTURE_DIR + f"{family}.bin", "magic": "TSTMAGIC"},
                    f"replacement-{index}".encode("ascii"),
                )
            )

    def tearDown(self):
        golden.ROOT = self.original_root
        self.directory.cleanup()

    def assert_originals_intact(self):
        for family, payload in self.originals.items():
            self.assertEqual((self.fixtures / f"{family}.bin").read_bytes(), payload)

    def assert_no_temporary_files(self):
        leftovers = [
            path.name
            for path in self.fixtures.iterdir()
            if ".staged" in path.name or ".backup" in path.name
        ]
        self.assertEqual(leftovers, [])

    @contextlib.contextmanager
    def captured_stderr(self):
        stream = io.StringIO()
        with contextlib.redirect_stderr(stream):
            yield stream

    def interrupt_and_capture(self, interruption=KeyboardInterrupt, **keywords):
        with self.captured_stderr() as stream:
            with self.assertRaises(interruption) as raised:
                golden.replace_fixtures(self.staged, **keywords)
        return raised.exception, stream.getvalue()

    def test_successful_replacement(self):
        written, failure = golden.replace_fixtures(self.staged)
        self.assertIsNone(failure)
        self.assertEqual(len(written), 4)
        for family, entry, _previous, blob in written:
            self.assertEqual((self.root / entry["fixture"]).read_bytes(), blob)
        self.assert_no_temporary_files()

    def test_failure_before_the_first_replacement(self):
        def hook(family, written):
            raise OSError("staging failed")

        written, failure = golden.replace_fixtures(self.staged, hook=hook)
        self.assertIsNone(written)
        self.assertEqual(failure["restored"], [])
        self.assert_originals_intact()
        self.assert_no_temporary_files()

    def test_failure_during_the_third_replacement_rolls_back(self):
        def hook(family, written):
            if written == 2:
                raise OSError("simulated failure")

        written, failure = golden.replace_fixtures(self.staged, hook=hook)
        self.assertIsNone(written)
        self.assertEqual(failure["restored"], ["family1", "family0"])
        self.assertEqual(failure["failed_restore"], [])
        self.assert_originals_intact()
        self.assert_no_temporary_files()

    def test_failure_on_the_last_replacement_rolls_back(self):
        def hook(family, written):
            if written == 3:
                raise OSError("simulated failure")

        written, failure = golden.replace_fixtures(self.staged, hook=hook)
        self.assertIsNone(written)
        self.assertEqual(len(failure["restored"]), 3)
        self.assert_originals_intact()

    def test_post_write_validation_failure_rolls_back(self):
        staged = list(self.staged)
        _family, entry, _blob = staged[1]
        corrupted = []

        def corrupting_replace(source, destination):
            os.replace(source, destination)
            if Path(destination).name == Path(entry["fixture"]).name and not corrupted:
                corrupted.append(destination)
                Path(destination).write_bytes(b"corrupted")

        written, failure = golden.replace_fixtures(staged, replace=corrupting_replace)
        self.assertIsNone(written)
        self.assertIsNotNone(failure)
        self.assert_originals_intact()
        self.assert_no_temporary_files()

    def test_interruption_immediately_after_the_replacement(self):
        interrupted = []

        def interrupting_replace(source, destination):
            os.replace(source, destination)
            if len(interrupted) < 2:
                interrupted.append(destination)
                return
            interrupted.append(destination)
            raise KeyboardInterrupt

        self.interrupt_and_capture(replace=interrupting_replace)
        self.assert_originals_intact()
        self.assert_no_temporary_files()

    def test_interruption_after_the_first_replacement(self):
        def interrupting_replace(source, destination):
            os.replace(source, destination)
            raise KeyboardInterrupt

        self.interrupt_and_capture(replace=interrupting_replace)
        self.assert_originals_intact()
        self.assert_no_temporary_files()

    def test_interruption_reports_a_successful_rollback(self):
        def interrupting_replace(source, destination):
            os.replace(source, destination)
            if Path(destination).name == "family2.bin":
                raise KeyboardInterrupt

        error, reported = self.interrupt_and_capture(replace=interrupting_replace)
        self.assertIsInstance(error, KeyboardInterrupt)
        self.assertIn("interrupted by KeyboardInterrupt", reported)
        self.assertIn("rolled back 3 fixture(s)", reported)
        self.assertIn("the repository is unchanged", reported)
        self.assertNotIn("ROLLBACK INCOMPLETE", reported)
        self.assert_originals_intact()
        self.assert_no_temporary_files()

    def test_system_exit_reports_a_successful_rollback(self):
        def hook(family, written):
            if written == 2:
                raise SystemExit(3)

        error, reported = self.interrupt_and_capture(SystemExit, hook=hook)
        self.assertEqual(error.code, 3)
        self.assertIn("interrupted by SystemExit (3)", reported)
        self.assertIn("rolled back 2 fixture(s)", reported)
        self.assert_originals_intact()

    def interrupt_with_a_failed_restore(self):
        original_chmod = golden.os.chmod

        def failing_chmod(path, mode, **keywords):
            if str(path).endswith(".backup") and not keywords:
                raise OSError("cannot restore")
            return original_chmod(path, mode, **keywords)

        def interrupting_replace(source, destination):
            os.replace(source, destination)
            if Path(destination).name == "family2.bin":
                raise KeyboardInterrupt

        golden.os.chmod = failing_chmod
        try:
            return self.interrupt_and_capture(replace=interrupting_replace)
        finally:
            golden.os.chmod = original_chmod

    def test_an_interrupted_failed_restore_still_raises_the_interruption(self):
        error, _reported = self.interrupt_with_a_failed_restore()
        self.assertIsInstance(error, KeyboardInterrupt)

    def test_an_interrupted_failed_restore_reports_the_incomplete_rollback(self):
        _error, reported = self.interrupt_with_a_failed_restore()
        self.assertIn("interrupted by KeyboardInterrupt", reported)
        self.assertIn("ROLLBACK INCOMPLETE", reported)
        self.assertNotIn("the repository is unchanged", reported)

    def test_an_interrupted_failed_restore_preserves_the_backup(self):
        _error, reported = self.interrupt_with_a_failed_restore()
        preserved = [
            line.split(" at ", 1)[1]
            for line in reported.splitlines()
            if "the original is preserved at " in line
        ]
        self.assertTrue(preserved)
        for path in preserved:
            self.assertTrue(Path(path).exists())
            self.assertIn(Path(path).read_bytes(), self.originals.values())

    def test_an_interrupted_failed_restore_prints_the_backup_path_to_stderr(self):
        _error, reported = self.interrupt_with_a_failed_restore()
        self.assertIn("the original is preserved at ", reported)
        leftovers = [
            path.name for path in self.fixtures.iterdir() if ".staged" in path.name
        ]
        self.assertEqual(leftovers, [])

    def test_replacement_failing_before_it_changes_anything(self):
        def failing_replace(source, destination):
            if Path(destination).name == "family2.bin":
                raise OSError("replacement refused")
            os.replace(source, destination)

        written, failure = golden.replace_fixtures(self.staged, replace=failing_replace)
        self.assertIsNone(written)
        self.assertEqual(failure["restored"], ["family2", "family1", "family0"])
        self.assert_originals_intact()
        self.assert_no_temporary_files()

    def test_incomplete_rollback_preserves_the_backup(self):
        original_chmod = golden.os.chmod

        def failing_chmod(path, mode, **keywords):
            if str(path).endswith(".backup") and not keywords:
                raise OSError("cannot restore")
            return original_chmod(path, mode, **keywords)

        def failing_replace(source, destination):
            if Path(destination).name == "family2.bin":
                raise OSError("replacement refused")
            os.replace(source, destination)

        golden.os.chmod = failing_chmod
        try:
            written, failure = golden.replace_fixtures(self.staged, replace=failing_replace)
        finally:
            golden.os.chmod = original_chmod
        self.assertIsNone(written)
        self.assertTrue(failure["failed_restore"])
        self.assertTrue(failure["preserved_backups"])
        for path in failure["preserved_backups"]:
            self.assertTrue(Path(path).exists())
            self.assertIn(Path(path).read_bytes(), self.originals.values())
        leftovers = [
            path.name for path in self.fixtures.iterdir() if ".staged" in path.name
        ]
        self.assertEqual(leftovers, [])

    def test_backup_copy_failure_leaves_nothing_behind(self):
        original_copy = golden.shutil.copy2

        def failing_copy(source, destination):
            if Path(source).name == "family1.bin":
                raise OSError("copy refused")
            return original_copy(source, destination)

        golden.shutil.copy2 = failing_copy
        try:
            written, failure = golden.replace_fixtures(self.staged)
        finally:
            golden.shutil.copy2 = original_copy
        self.assertIsNone(written)
        self.assert_originals_intact()
        self.assert_no_temporary_files()

    def test_staging_creation_failure_leaves_nothing_behind(self):
        original_mkstemp = golden.tempfile.mkstemp
        calls = []

        def failing_mkstemp(*arguments, **keywords):
            calls.append(keywords.get("suffix"))
            if calls.count(".staged") == 2:
                raise OSError("no space for the staging file")
            return original_mkstemp(*arguments, **keywords)

        golden.tempfile.mkstemp = failing_mkstemp
        try:
            written, failure = golden.replace_fixtures(self.staged)
        finally:
            golden.tempfile.mkstemp = original_mkstemp
        self.assertIsNone(written)
        self.assert_originals_intact()
        self.assert_no_temporary_files()

    def test_staging_write_failure_leaves_nothing_behind(self):
        original_fdopen = golden.os.fdopen
        calls = []

        def failing_fdopen(handle, mode):
            calls.append(handle)
            if len(calls) == 2:
                os.close(handle)
                raise OSError("write refused")
            return original_fdopen(handle, mode)

        golden.os.fdopen = failing_fdopen
        try:
            written, failure = golden.replace_fixtures(self.staged)
        finally:
            golden.os.fdopen = original_fdopen
        self.assertIsNone(written)
        self.assert_originals_intact()
        self.assert_no_temporary_files()

    def test_mode_change_failure_leaves_nothing_behind(self):
        original_chmod = golden.os.chmod
        calls = []

        def failing_chmod(path, mode, **keywords):
            if keywords:
                return original_chmod(path, mode, **keywords)
            calls.append(path)
            if len(calls) == 2:
                raise OSError("chmod refused")
            return original_chmod(path, mode)

        golden.os.chmod = failing_chmod
        try:
            written, failure = golden.replace_fixtures(self.staged)
        finally:
            golden.os.chmod = original_chmod
        self.assertIsNone(written)
        self.assert_originals_intact()
        self.assert_no_temporary_files()

    def test_every_replaceable_fixture_has_a_rollback_record(self):
        seen = []

        def recording_replace(source, destination):
            seen.append(Path(destination).name)
            os.replace(source, destination)
            raise KeyboardInterrupt

        self.interrupt_and_capture(replace=recording_replace)
        self.assertEqual(seen, ["family0.bin"])
        self.assert_originals_intact()

    def test_writes_outside_the_fixture_directory_are_refused(self):
        escaping = [("rogue", {"fixture": "../../../etc/passwd", "magic": "TSTMAGIC"}, b"x")]
        written, failure = golden.replace_fixtures(escaping)
        self.assertIsNone(written)
        self.assertIn("escapes the repository", failure["error"])

    def test_second_identical_replacement_changes_nothing(self):
        golden.replace_fixtures(self.staged)
        snapshot = {
            family: (self.fixtures / f"{family}.bin").read_bytes() for family in self.originals
        }
        golden.replace_fixtures(self.staged)
        for family, payload in snapshot.items():
            self.assertEqual((self.fixtures / f"{family}.bin").read_bytes(), payload)
        self.assert_no_temporary_files()

    def test_temporary_files_are_unique(self):
        names = []
        original_mkstemp = golden.tempfile.mkstemp

        def recording_mkstemp(*args, **kwargs):
            handle, path = original_mkstemp(*args, **kwargs)
            names.append(Path(path).name)
            return handle, path

        golden.tempfile.mkstemp = recording_mkstemp
        try:
            golden.replace_fixtures(self.staged)
        finally:
            golden.tempfile.mkstemp = original_mkstemp
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(all(name != "family0.bin.new" for name in names))

    def test_interruption_before_the_first_replacement(self):
        def hook(family, written):
            raise KeyboardInterrupt

        _error, reported = self.interrupt_and_capture(hook=hook)
        self.assertIn("rolled back 0 fixture(s)", reported)
        self.assert_originals_intact()
        self.assert_no_temporary_files()

    def test_interruption_after_two_replacements(self):
        def hook(family, written):
            if written == 2:
                raise KeyboardInterrupt

        self.interrupt_and_capture(hook=hook)
        self.assert_originals_intact()
        self.assert_no_temporary_files()

    def test_system_exit_is_reraised_after_rollback(self):
        def hook(family, written):
            if written == 1:
                raise SystemExit(3)

        self.interrupt_and_capture(SystemExit, hook=hook)
        self.assert_originals_intact()
        self.assert_no_temporary_files()

    def test_original_permissions_are_restored(self):
        target = self.fixtures / "family1.bin"
        target.chmod(0o640)

        def hook(family, written):
            if written == 2:
                raise OSError("simulated failure")

        golden.replace_fixtures(self.staged, hook=hook)
        self.assertEqual(target.stat().st_mode & 0o777, 0o640)
        self.assert_originals_intact()

    def test_rollback_removes_a_fixture_that_did_not_exist(self):
        fresh = ("family4", {"fixture": golden.FIXTURE_DIR + "family4.bin", "magic": "TSTMAGIC"}, b"new")
        staged = self.staged[:1] + [fresh] + self.staged[1:]

        def hook(family, written):
            if written == 3:
                raise OSError("simulated failure")

        golden.replace_fixtures(staged, hook=hook)
        self.assertFalse((self.fixtures / "family4.bin").exists())
        self.assert_originals_intact()
        self.assert_no_temporary_files()

    def test_no_backup_files_survive_a_successful_update(self):
        golden.replace_fixtures(self.staged)
        leftovers = [path.name for path in self.fixtures.iterdir() if ".backup" in path.name]
        self.assertEqual(leftovers, [])

    def test_previous_bytes_are_the_committed_contents(self):
        written, failure = golden.replace_fixtures(self.staged)
        self.assertIsNone(failure)
        for family, _entry, previous, _blob in written:
            self.assertEqual(previous, self.originals[family])

    def test_a_new_fixture_reports_no_previous_bytes(self):
        fresh = ("family4", {"fixture": golden.FIXTURE_DIR + "family4.bin", "magic": "TSTMAGIC"}, b"new")
        written, failure = golden.replace_fixtures([fresh])
        self.assertIsNone(failure)
        self.assertEqual(written[0][2], None)

    def test_cleanup_failure_after_the_commit_point_keeps_the_update(self):
        original_unlink = golden.os.unlink

        def failing_unlink(path, **keywords):
            if str(path).endswith(".backup"):
                raise OSError("cannot remove the backup")
            return original_unlink(path, **keywords)

        golden.os.unlink = failing_unlink
        try:
            written, failure = golden.replace_fixtures(self.staged)
        finally:
            golden.os.unlink = original_unlink
        self.assertIsNone(failure)
        self.assertEqual(len(written), 4)
        for family, entry, _previous, blob in written:
            self.assertEqual((self.root / entry["fixture"]).read_bytes(), blob)

    def test_nothing_is_replaced_before_every_staging_file_exists(self):
        seen = []
        original_mkstemp = golden.tempfile.mkstemp

        def recording_mkstemp(*arguments, **keywords):
            if keywords.get("suffix") == ".staged":
                seen.append(
                    [path.read_bytes() for path in sorted(self.fixtures.glob("family*.bin"))]
                )
            return original_mkstemp(*arguments, **keywords)

        golden.tempfile.mkstemp = recording_mkstemp
        try:
            golden.replace_fixtures(self.staged)
        finally:
            golden.tempfile.mkstemp = original_mkstemp
        untouched = [payload for _family, payload in sorted(self.originals.items())]
        for snapshot in seen:
            self.assertEqual(snapshot, untouched)

    def supported_special_bits(self):
        probe = self.fixtures / ".mode-probe"
        probe.write_bytes(b"")
        supported = []
        for bit in (stat.S_ISUID, stat.S_ISGID, stat.S_ISVTX):
            try:
                os.chmod(probe, 0o600 | bit)
            except OSError:
                continue
            if stat.S_IMODE(probe.stat().st_mode) == 0o600 | bit:
                supported.append(bit)
        probe.unlink()
        return supported

    def test_ordinary_permission_bits_survive_a_replacement(self):
        target = self.fixtures / "family1.bin"
        target.chmod(0o640)
        written, failure = golden.replace_fixtures(self.staged)
        self.assertIsNone(failure)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)
        self.assert_no_temporary_files()

    def test_supported_special_bits_survive_a_replacement(self):
        target = self.fixtures / "family1.bin"
        for bit in self.supported_special_bits():
            target.chmod(0o640 | bit)
            expected = stat.S_IMODE(target.stat().st_mode)
            self.assertEqual(expected, 0o640 | bit)
            written, failure = golden.replace_fixtures(self.staged)
            self.assertIsNone(failure)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), expected, oct(bit))
            self.assert_no_temporary_files()

    def test_supported_special_bits_are_restored(self):
        target = self.fixtures / "family1.bin"

        def hook(family, written):
            if written == 2:
                raise OSError("simulated failure")

        for bit in self.supported_special_bits():
            target.chmod(0o640 | bit)
            expected = stat.S_IMODE(target.stat().st_mode)
            written, failure = golden.replace_fixtures(self.staged, hook=hook)
            self.assertIsNone(written)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), expected, oct(bit))
            self.assert_originals_intact()
            self.assert_no_temporary_files()

    def test_the_recorded_mode_is_the_mode_the_filesystem_reports(self):
        target = self.fixtures / "family1.bin"
        target.chmod(0o2640)
        reported = stat.S_IMODE(target.stat().st_mode)
        prepared = golden.prepare_replacements(self.staged, set())
        recorded = next(
            record["mode"] for record in prepared if record["fixture"] == target
        )
        for record in prepared:
            record["staging"].unlink(missing_ok=True)
            if record["backup"] is not None:
                record["backup"].unlink(missing_ok=True)
        self.assertEqual(recorded, reported)

    def test_a_new_fixture_gets_the_default_mode(self):
        fresh = ("family4", {"fixture": golden.FIXTURE_DIR + "family4.bin", "magic": "TSTMAGIC"}, b"new")
        golden.replace_fixtures([fresh])
        created = self.fixtures / "family4.bin"
        self.assertEqual(stat.S_IMODE(created.stat().st_mode), golden.DEFAULT_FIXTURE_MODE)

    def test_validation_failure_on_the_last_fixture_rolls_all_of_them_back(self):
        def corrupting_replace(source, destination):
            os.replace(source, destination)
            if Path(destination).name == "family3.bin":
                Path(destination).write_bytes(b"corrupted")

        written, failure = golden.replace_fixtures(self.staged, replace=corrupting_replace)
        self.assertIsNone(written)
        self.assertEqual(len(failure["restored"]), 4)
        self.assert_originals_intact()
        self.assert_no_temporary_files()

    def test_a_failed_capture_never_reaches_the_staging_phase(self):
        created = []
        original_mkstemp = golden.tempfile.mkstemp

        def recording_mkstemp(*arguments, **keywords):
            created.append(keywords.get("suffix"))
            return original_mkstemp(*arguments, **keywords)

        golden.tempfile.mkstemp = recording_mkstemp
        try:
            written, failure = golden.replace_fixtures(
                [("rogue", {"fixture": "/etc/passwd.bin", "magic": "TSTMAGIC"}, b"x")]
            )
        finally:
            golden.tempfile.mkstemp = original_mkstemp
        self.assertIsNone(written)
        self.assertEqual(created, [])
        self.assertIn("must be a relative path", failure["error"])


class GoldenCommandLineTest(unittest.TestCase):
    def parse(self, arguments):
        return golden.build_parser().parse_args(arguments)

    def test_audit_takes_no_offline_flag(self):
        with self.assertRaises(SystemExit):
            self.parse(["audit", "--offline"])

    def test_verify_all_subcommand_is_gone(self):
        with self.assertRaises(SystemExit):
            self.parse(["verify-all"])

    def test_verify_accepts_all(self):
        arguments = self.parse(["verify", "--all"])
        self.assertTrue(arguments.all)

    def test_update_all_requires_confirmation(self):
        out, err = io.StringIO(), io.StringIO()
        arguments = self.parse(["update", "--all"])
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = golden.update(arguments)
        self.assertEqual(code, 1)
        self.assertIn("--confirm-reference-update", err.getvalue())

    def test_unknown_family_is_reported(self):
        manifest = golden.load_manifest()
        arguments = self.parse(["verify", "not-a-family"])
        chosen, error = golden.selected_families(manifest, arguments)
        self.assertIsNone(chosen)
        self.assertIn("not in the manifest", error)

    def test_family_and_all_are_mutually_exclusive(self):
        with self.assertRaises(SystemExit):
            self.parse(["verify", "create", "--all"])

    def test_dump_of_a_missing_record_is_reported(self):
        arguments = self.parse(["dump", "create-primary", "NOT_A_RECORD"])
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = golden.dump(arguments)
        self.assertEqual(code, 1)
        self.assertIn("NOT_A_RECORD", err.getvalue())

    def test_audit_makes_no_docker_calls(self):
        calls = []
        originals = (golden.docker_output, golden.image_label, golden.image_platform)

        def explode(*arguments, **keywords):
            calls.append(arguments)
            raise AssertionError("audit must not touch Docker")

        golden.docker_output = explode
        golden.image_label = explode
        golden.image_platform = explode
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                code = golden.run_audit()
        finally:
            golden.docker_output, golden.image_label, golden.image_platform = originals
        self.assertEqual(code, 0)
        self.assertEqual(calls, [])

    def test_verify_never_writes_fixtures(self):
        source = GOLDEN_PATH.read_text()
        start = source.index("def verify(args):")
        body = source[start : source.index("\n\n\n", start)]
        for forbidden in ("write_bytes", "replace_fixtures", "os.replace", "mkstemp"):
            self.assertNotIn(forbidden, body)


class GoldenMakefileTest(unittest.TestCase):
    def setUp(self):
        self.makefile = (golden.ROOT / "Makefile").read_text()

    def target_line(self, target):
        return next(
            line for line in self.makefile.splitlines() if line.startswith(f"{target}:")
        )

    def target_recipe(self, target):
        section = self.makefile[self.makefile.index(f"\n{target}:") + 1 :]
        return section.partition("\n\n")[0]

    def test_check_is_the_default_goal(self):
        line = next(
            line
            for line in self.makefile.splitlines()
            if line.startswith(".DEFAULT_GOAL")
        )
        self.assertEqual(line.partition(":=")[2].strip(), "check")

    def test_build_only_builds_the_selected_profile(self):
        self.assertEqual(self.target_line("build"), "build:")
        recipe = self.target_recipe("build")
        self.assertIn("$(CARGO) build $(CARGO_BUILD_FLAGS)", recipe)
        for forbidden in ("golden-audit", "generate-abi", "test-abi", "test-rust"):
            self.assertNotIn(forbidden, recipe)

    def test_check_runs_the_three_validation_stages(self):
        self.assertEqual(
            self.target_line("check").split(),
            ["check:", "golden-audit", "test-abi", "test-rust"],
        )

    def test_abi_tools_finish_before_the_abi_checks(self):
        self.assertEqual(
            self.target_line("test-abi").split(), ["test-abi:", "test-abi-tools"]
        )
        self.assertIn(
            "$(PYTHON) -m unittest discover -s scripts/tests",
            self.target_recipe("test-abi-tools"),
        )

    def test_rust_checks_and_tests_run_exactly_once(self):
        recipe = self.target_recipe("test-rust")
        self.assertIn("$(CARGO) check", recipe)
        self.assertIn("$(CARGO) test --all-features", recipe)
        self.assertEqual(self.makefile.count("$(CARGO) check"), 1)
        self.assertEqual(self.makefile.count("$(CARGO) test --all-features"), 1)

    def test_target_command_mapping(self):
        for target, command in (
            ("golden-audit", "$(GOLDEN) audit"),
            ("test-golden", "$(GOLDEN) verify --all"),
            ("update-golden", '$(GOLDEN) update "$(FAMILY)"'),
            ("update-golden-all", "$(GOLDEN) update --all --confirm-reference-update"),
        ):
            self.assertIn(command, self.target_recipe(target))

    def test_removed_public_targets_do_not_return(self):
        for target in (
            "all",
            "build-release",
            "ci",
            "cargo-check",
            "prepare-swtpm",
            "build-swtpm",
            "verify-swtpm-linkage",
        ):
            self.assertFalse(
                any(line.startswith(f"{target}:") for line in self.makefile.splitlines()),
                target,
            )

    def test_swtpm_build_linkage_and_tests_share_one_target(self):
        self.assertEqual(
            self.target_line("test-swtpm").split(),
            ["test-swtpm:", "$(SWTPM_CONFIGURE_STAMP)"],
        )
        recipe = self.target_recipe("test-swtpm")
        self.assertIn("$(MAKE) -C $(SWTPM_BUILD_DIR) -j$(JOBS)", recipe)
        self.assertIn("scripts/verify_tis_symbols.py", recipe)
        self.assertIn("$(MAKE) -C $(SWTPM_BUILD_DIR) check", recipe)
        self.assertNotIn("--no-print-directory", self.makefile)

    def test_update_targets_are_not_in_build_or_check_chains(self):
        for line in self.makefile.splitlines():
            if line.startswith(("build:", "check:")):
                self.assertNotIn("update-golden", line)

    def test_golden_audit_does_not_use_offline(self):
        self.assertNotIn("--offline", self.target_recipe("golden-audit"))


class GoldenMalformedManifestTest(unittest.TestCase):
    def run_audit(self, manifest):
        out, err = io.StringIO(), io.StringIO()
        facts = baseline_facts()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = golden.run_audit(manifest=manifest, facts=facts)
        return code, err.getvalue()

    def assert_rejected(self, manifest, substring):
        code, errors = self.run_audit(manifest)
        self.assertEqual(code, 1)
        self.assertIn(substring, errors)

    def test_a_manifest_that_is_not_a_table_is_one_violation(self):
        for manifest in ([1, 2], "text", 7, 1.5):
            code, errors = self.run_audit(manifest)
            self.assertEqual(code, 1, manifest)
            self.assertEqual(
                errors.strip().splitlines()[-1].strip(),
                "[manifest] the manifest is not a table",
            )

    def test_a_manifest_with_scalar_tables_is_rejected(self):
        for key in ("reference", "families", "commands"):
            manifest = golden.load_manifest()
            manifest[key] = 7
            code, errors = self.run_audit(manifest)
            self.assertEqual(code, 1, key)
            self.assertIn(f"[{key}] is missing or is not a table", errors)

    def test_invalid_toml_is_a_concise_error(self):
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        broken = Path(directory) / "manifest.toml"
        broken.write_text("[families\nmagic = ")
        original = golden.MANIFEST
        golden.MANIFEST = broken
        try:
            with self.assertRaises(golden.ManifestError) as raised:
                golden.load_manifest()
        finally:
            golden.MANIFEST = original
        self.assertIn("not valid TOML", str(raised.exception))

    def test_an_unreadable_manifest_is_a_concise_error(self):
        original = golden.MANIFEST
        golden.MANIFEST = Path("/nonexistent/manifest.toml")
        try:
            with self.assertRaises(golden.ManifestError) as raised:
                golden.load_manifest()
        finally:
            golden.MANIFEST = original
        self.assertIn("cannot be read", str(raised.exception))

    def test_the_cli_reports_a_manifest_error_without_a_traceback(self):
        original = golden.MANIFEST
        golden.MANIFEST = Path("/nonexistent/manifest.toml")
        argv = sys.argv
        sys.argv = ["golden.py", "audit"]
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as raised:
                golden.main()
        finally:
            golden.MANIFEST = original
            sys.argv = argv
        self.assertEqual(raised.exception.code, 1)
        self.assertIn("golden.py: manifest.toml cannot be read", err.getvalue())

    def test_missing_reader(self):
        manifest = golden.load_manifest()
        del manifest["families"]["create"]["reader"]
        self.assert_rejected(manifest, "missing 'reader'")

    def test_missing_magic(self):
        manifest = golden.load_manifest()
        del manifest["families"]["create"]["magic"]
        self.assert_rejected(manifest, "missing 'magic'")

    def test_non_ascii_magic(self):
        manifest = golden.load_manifest()
        manifest["families"]["create"]["magic"] = "CR\u00d6RACLE"
        self.assert_rejected(manifest, "must be ASCII")

    def test_short_magic(self):
        manifest = golden.load_manifest()
        manifest["families"]["create"]["magic"] = "SHORT"
        self.assert_rejected(manifest, "expected 8")

    def test_family_field_types(self):
        for field, value in (
            ("scenario", 7),
            ("fixture", ["a"]),
            ("reader", None),
            ("commands", "TPM2_Create"),
            ("magic", 8),
        ):
            manifest = golden.load_manifest()
            manifest["families"]["create"][field] = value
            code, errors = self.run_audit(manifest)
            self.assertEqual(code, 1, field)
            self.assertIn("create", errors)

    def test_command_field_types(self):
        for field, value in (("code", "0x153"), ("status", 1), ("family", 2), ("reason", 3)):
            manifest = golden.load_manifest()
            manifest["commands"]["Create"][field] = value
            code, errors = self.run_audit(manifest)
            self.assertEqual(code, 1, field)
            self.assertIn(f"commands.Create: {field}", errors)

    def test_the_committed_aliases_match_upstream(self):
        aliases = golden.parse_upstream_aliases()
        manifest = golden.load_manifest()
        declared = {
            entry["code"]: entry["alias"]
            for entry in manifest["commands"].values()
            if "alias" in entry
        }
        self.assertEqual(declared, aliases)

    def test_a_wrong_alias_is_rejected(self):
        manifest = golden.load_manifest()
        manifest["commands"]["HMAC"]["alias"] = "NOT_MAC"
        self.assert_rejected(manifest, "upstream names the alias MAC")

    def test_an_invented_alias_is_rejected(self):
        manifest = golden.load_manifest()
        manifest["commands"]["Create"]["alias"] = "Make"
        self.assert_rejected(manifest, "upstream declares no alias")

    def test_a_dropped_alias_is_rejected(self):
        manifest = golden.load_manifest()
        del manifest["commands"]["HMAC"]["alias"]
        self.assert_rejected(manifest, "upstream also names 0x0155 CC_MAC")

    def test_family_entry_is_not_a_table(self):
        manifest = golden.load_manifest()
        manifest["families"]["create"] = "not a table"
        self.assert_rejected(manifest, "the family is not a table")

    def test_missing_reference_platform(self):
        manifest = golden.load_manifest()
        manifest["reference"] = {}
        self.assert_rejected(manifest, "docker_platform")

    def test_duplicate_magic_across_fixtures(self):
        manifest = golden.load_manifest()
        manifest["families"]["nv-certify"]["magic"] = manifest["families"]["nv-commands"]["magic"]
        self.assert_rejected(manifest, "is already used by")

    def test_duplicate_magic_across_readers(self):
        manifest = golden.load_manifest()
        manifest["families"]["create"]["magic"] = manifest["families"]["pcr-event"]["magic"]
        self.assert_rejected(manifest, "is already used by")

    def test_committed_magic_values_are_unique(self):
        manifest = golden.load_manifest()
        magics = [entry["magic"] for entry in manifest["families"].values()]
        self.assertEqual(len(magics), len(set(magics)))

    def test_nv_fixtures_reject_each_other_magic(self):
        codec = golden.load_packer()
        manifest = golden.load_manifest()
        commands = manifest["families"]["nv-commands"]
        certify = manifest["families"]["nv-certify"]
        with self.assertRaises(codec.FixtureFormatError):
            codec.unpack(
                certify["magic"].encode("ascii"),
                (golden.ROOT / commands["fixture"]).read_bytes(),
            )
        with self.assertRaises(codec.FixtureFormatError):
            codec.unpack(
                commands["magic"].encode("ascii"),
                (golden.ROOT / certify["fixture"]).read_bytes(),
            )


class GoldenStructuredViolationTest(unittest.TestCase):
    def violations(self, manifest):
        return golden.audit_violations(manifest, baseline_facts())

    def test_a_violation_carries_a_code_and_a_family(self):
        manifest = golden.load_manifest()
        manifest["families"]["create"]["magic"] = manifest["families"]["pcr-event"]["magic"]
        matching = [v for v in self.violations(manifest) if v.code == "fixtures"]
        self.assertTrue(matching)
        self.assertEqual(matching[0].family, "pcr-event")
        self.assertIn("already used by create", matching[0].message)

    def test_rendering_happens_at_the_boundary(self):
        violation = golden.Violation("paths", "fixture is wrong", "create")
        self.assertEqual(violation.render(), "[paths] create: fixture is wrong")
        self.assertEqual(
            golden.Violation("manifest", "broken").render(), "[manifest] broken"
        )

    def test_stale_codes_are_exactly_the_two_migration_cases(self):
        self.assertEqual(
            set(golden.STALE_CODES), {"fixture-missing", "fixture-magic-mismatch"}
        )

    def test_a_missing_fixture_is_reported_by_code(self):
        manifest = golden.load_manifest()
        manifest["families"]["create"]["fixture"] = golden.FIXTURE_DIR + "absent.bin"
        codes = {v.code for v in self.violations(manifest) if v.family == "create"}
        self.assertIn("fixture-missing", codes)

    def test_a_wrong_magic_is_reported_by_code(self):
        manifest = golden.load_manifest()
        manifest["families"]["create"]["magic"] = "ZZORACLE"
        codes = {v.code for v in self.violations(manifest) if v.family == "create"}
        self.assertIn("fixture-magic-mismatch", codes)

    def test_only_the_selected_family_is_tolerated(self):
        stale = golden.Violation("fixture-missing", "gone", "create")
        self.assertTrue(golden.tolerated_stale(stale, {"create"}))
        self.assertFalse(golden.tolerated_stale(stale, {"pcr-event"}))
        other = golden.Violation("fixtures", "reader is gone", "create")
        self.assertFalse(golden.tolerated_stale(other, {"create"}))


class GoldenReaderContractTest(unittest.TestCase):
    def violations(self, mutate=None):
        manifest = golden.load_manifest()
        facts = golden.collect_facts(manifest)
        if mutate is not None:
            mutate(manifest, facts)
        return rendered(golden.validate_readers(manifest, facts))

    def test_the_committed_readers_satisfy_the_contract(self):
        self.assertEqual(self.violations(), [])

    def test_a_reader_that_includes_another_fixture_is_rejected(self):
        def mutate(manifest, _facts):
            manifest["families"]["create"]["reader"] = manifest["families"]["pcr-event"]["reader"]

        self.assertTrue(any("declares no Fixture::new" in v for v in self.violations(mutate)))

    def test_a_reader_without_the_declared_magic_is_rejected(self):
        def mutate(manifest, _facts):
            manifest["families"]["create"]["magic"] = "ZZORACLE"

        self.assertTrue(any("with CRORACLE" in v for v in self.violations(mutate)))

    def test_the_shared_nv_reader_declares_both_fixtures(self):
        manifest = golden.load_manifest()
        commands = manifest["families"]["nv-commands"]
        certify = manifest["families"]["nv-certify"]
        self.assertEqual(commands["reader"], certify["reader"])
        declarations, errors = golden.parse_reader_fixtures(
            commands["reader"], (golden.ROOT / commands["reader"]).read_text("utf-8")
        )
        self.assertEqual(errors, [])
        self.assertEqual(len(declarations), 2)
        self.assertEqual(
            {(entry["magic"], entry["fixture"]) for entry in declarations},
            {
                (commands["magic"], commands["fixture"]),
                (certify["magic"], certify["fixture"]),
            },
        )
        self.assertEqual(
            {entry["name"] for entry in declarations},
            {"COMMAND_FIXTURE", "CERTIFY_FIXTURE"},
        )

    def test_swapping_two_family_magics_is_rejected(self):
        def mutate(manifest, _facts):
            families = manifest["families"]
            families["create-primary"]["magic"], families["evict-control"]["magic"] = (
                families["evict-control"]["magic"],
                families["create-primary"]["magic"],
            )

        violations = self.violations(mutate)
        self.assertTrue(any("create-primary" in v and "CPORACLE" in v for v in violations))
        self.assertTrue(any("evict-control" in v and "ECORACLE" in v for v in violations))

    def test_the_swapped_magics_are_not_tolerated_as_stale(self):
        manifest = golden.load_manifest()
        families = manifest["families"]
        families["create-primary"]["magic"], families["evict-control"]["magic"] = (
            families["evict-control"]["magic"],
            families["create-primary"]["magic"],
        )
        facts = golden.collect_facts(manifest)
        allowed = {"create-primary", "evict-control"}
        remaining = [
            violation
            for violation in golden.audit_violations(manifest, facts)
            if not golden.tolerated_stale(violation, allowed)
        ]
        self.assertTrue(remaining)
        self.assertEqual({violation.code for violation in remaining}, {"replay"})

    def test_the_swapped_magics_fail_preflight_before_docker(self):
        manifest = golden.load_manifest()
        families = manifest["families"]
        families["create-primary"]["magic"], families["evict-control"]["magic"] = (
            families["evict-control"]["magic"],
            families["create-primary"]["magic"],
        )
        calls = []
        original = golden.run_docker
        golden.run_docker = lambda arguments, **keywords: calls.append(arguments)
        out, err = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = golden.preflight(
                    manifest, "update", allow_stale={"create-primary", "evict-control"}
                )
        finally:
            golden.run_docker = original
        self.assertEqual(code, 1)
        self.assertEqual(calls, [])
        self.assertIn("[replay]", err.getvalue())

    def test_a_magic_only_under_cfg_test_is_not_accepted(self):
        reader = golden.READER_DIR + "create.rs"
        source = (golden.ROOT / reader).read_text("utf-8")
        self.assertIn("#[cfg(test)]", source)
        head, tail = source.split("#[cfg(test)]", 1)
        planted = head + '#[cfg(test)]\nconst PLANTED: &[u8; 8] = b"ZZORACLE";\n' + tail

        def mutate(manifest, facts):
            manifest["families"]["create"]["magic"] = "ZZORACLE"
            facts["reader_sources"][reader] = planted

        self.assertTrue(any("with CRORACLE" in v for v in self.violations(mutate)))

    def test_a_magic_and_fixture_from_different_declarations_do_not_pair(self):
        reader = golden.READER_DIR + "nv.rs"

        def mutate(manifest, _facts):
            manifest["families"]["nv-certify"]["magic"] = manifest["families"]["nv-commands"]["magic"]

        violations = self.violations(mutate)
        self.assertTrue(
            any(
                reader in v and "nv_certify.bin with NCORACLE" in v and "NVORACLE" in v
                for v in violations
            ),
            violations,
        )

    def test_a_magic_declared_for_another_fixture_is_reported(self):
        def mutate(manifest, _facts):
            manifest["families"]["create"]["fixture"] = golden.FIXTURE_DIR + "absent.bin"

        violations = self.violations(mutate)
        self.assertTrue(any("not for" in v and "absent.bin" in v for v in violations), violations)

    def test_an_unparsable_declaration_is_rejected(self):
        reader = golden.READER_DIR + "create.rs"
        source = (golden.ROOT / reader).read_text("utf-8")

        def mutate(_manifest, facts):
            facts["reader_sources"][reader] = source.replace(
                "static FIXTURE: Fixture = Fixture::new(",
                "static FIXTURE: Fixture = Fixture::new(MAGIC, ",
                1,
            )

        self.assertTrue(any("unparsable Fixture::new" in v for v in self.violations(mutate)))

    def test_an_unresolved_magic_constant_is_rejected(self):
        reader = golden.READER_DIR + "create.rs"
        source = (golden.ROOT / reader).read_text("utf-8")

        def mutate(_manifest, facts):
            facts["reader_sources"][reader] = source.replace(
                'const MAGIC: &[u8; 8] = b"CRORACLE";', "", 1
            )

        self.assertTrue(any("is not an 8-byte literal" in v for v in self.violations(mutate)))

    def test_a_computed_payload_is_rejected(self):
        reader = golden.READER_DIR + "create.rs"
        source = (golden.ROOT / reader).read_text("utf-8")

        def mutate(_manifest, facts):
            facts["reader_sources"][reader] = source.replace(
                'include_bytes!("../testdata/golden_responses/create.bin")',
                "PAYLOAD",
                1,
            )

        self.assertTrue(any("is not an include_bytes! call" in v for v in self.violations(mutate)))

    def reader_variant(self, old, new):
        reader = golden.READER_DIR + "create.rs"
        source = (golden.ROOT / reader).read_text("utf-8")
        self.assertIn(old, source)
        return reader, source.replace(old, new, 1)

    def parse(self, source):
        return golden.parse_reader_fixtures(golden.READER_DIR + "create.rs", source)

    def violations_for(self, reader, source):
        def mutate(_manifest, facts):
            facts["reader_sources"][reader] = source

        return self.violations(mutate)

    def test_a_spaced_constructor_is_detected(self):
        reader, source = self.reader_variant(
            "Fixture = Fixture::new(", "Fixture = Fixture :: new("
        )
        declarations, errors = self.parse(source)
        self.assertEqual(declarations, [])
        self.assertTrue(any("unparsable Fixture::new" in error for error in errors), errors)
        self.assertTrue(
            any("unparsable Fixture::new" in v for v in self.violations_for(reader, source))
        )

    def test_a_widely_spaced_constructor_is_detected(self):
        reader, source = self.reader_variant(
            "Fixture = Fixture::new(", "Fixture = Fixture  ::  new("
        )
        self.assertTrue(
            any("unparsable Fixture::new" in v for v in self.violations_for(reader, source))
        )

    def test_a_constructor_split_across_lines_is_detected(self):
        reader, source = self.reader_variant(
            "Fixture = Fixture::new(", "Fixture = Fixture\n    ::new("
        )
        declarations, errors = self.parse(source)
        self.assertEqual(declarations, [])
        self.assertTrue(any("could be located" in error for error in errors), errors)
        self.assertTrue(
            any("could be located" in v for v in self.violations_for(reader, source))
        )

    def test_a_canonical_and_a_spaced_declaration_are_not_accepted(self):
        canonical = (
            "static FIXTURE: Fixture = Fixture::new(\n"
            '    "TPM2_Create",\n'
            "    MAGIC,\n"
            '    include_bytes!("../testdata/golden_responses/create.bin"),\n'
            ");"
        )
        spaced = (
            "const ACTIVE: Fixture = Fixture :: new(\n"
            '    "TPM2_Create",\n'
            "    MAGIC,\n"
            '    include_bytes!("../testdata/golden_responses/pcr_event.bin"),\n'
            ");"
        )
        reader, source = self.reader_variant(canonical, canonical + "\n\n" + spaced)
        declarations, errors = self.parse(source)
        self.assertEqual([entry["name"] for entry in declarations], ["FIXTURE"])
        self.assertTrue(errors)
        violations = self.violations_for(reader, source)
        self.assertTrue(any("unparsable Fixture::new" in v for v in violations), violations)

    def test_an_unused_canonical_declaration_cannot_bless_a_spaced_one(self):
        canonical = (
            "static FIXTURE: Fixture = Fixture::new(\n"
            '    "TPM2_Create",\n'
            "    MAGIC,\n"
            '    include_bytes!("../testdata/golden_responses/create.bin"),\n'
            ");"
        )
        active = (
            "const ACTIVE: Fixture = Fixture :: new(\n"
            '    "TPM2_Create",\n'
            "    MAGIC,\n"
            '    include_bytes!("../testdata/golden_responses/pcr_event.bin"),\n'
            ");"
        )
        reader, source = self.reader_variant(canonical, canonical + "\n\n" + active)
        source = source.replace("FIXTURE.get(name)", "ACTIVE.get(name)")
        declarations, _errors = self.parse(source)
        manifest = golden.load_manifest()
        entry = manifest["families"]["create"]
        matching = [
            declaration
            for declaration in declarations
            if declaration["magic"] == entry["magic"]
            and declaration["fixture"] == entry["fixture"]
        ]
        self.assertEqual(len(matching), 1)
        self.assertTrue(self.violations_for(reader, source))

    def test_a_spaced_constructor_on_a_test_only_constant_is_rejected(self):
        reader, source = self.reader_variant(
            "#[cfg(test)]",
            "#[cfg(test)]\nconst PLANTED: Fixture = Fixture :: new(\n"
            '    "planted",\n'
            "    MAGIC,\n"
            '    include_bytes!("../testdata/golden_responses/pcr_event.bin"),\n'
            ");\n",
        )
        declarations, errors = self.parse(source)
        self.assertEqual([entry["name"] for entry in declarations], ["FIXTURE"])
        self.assertTrue(any("unparsable Fixture::new" in error for error in errors), errors)
        self.assertTrue(
            any("unparsable Fixture::new" in v for v in self.violations_for(reader, source))
        )

    CANONICAL = (
        "static FIXTURE: Fixture = Fixture::new(\n"
        '    "TPM2_Create",\n'
        "    MAGIC,\n"
        '    include_bytes!("../testdata/golden_responses/create.bin"),\n'
        ");"
    )
    ACTIVE = (
        "const ACTIVE: Fixture = Fixture :: new(\n"
        '    "active fixture",\n'
        "    MAGIC,\n"
        '    include_bytes!("../testdata/golden_responses/pcr_event.bin"),\n'
        ");"
    )

    def test_a_string_containing_the_test_attribute_does_not_truncate(self):
        reader, source = self.reader_variant(
            self.CANONICAL,
            self.CANONICAL + '\n\nconst MARKER: &str = "#[cfg(test)]";\n\n' + self.ACTIVE,
        )
        declarations, errors = self.parse(source)
        self.assertEqual([entry["name"] for entry in declarations], ["FIXTURE"])
        self.assertTrue(any("unparsable Fixture::new" in error for error in errors), errors)
        self.assertTrue(
            any("unparsable Fixture::new" in v for v in self.violations_for(reader, source))
        )

    def test_a_hidden_active_declaration_is_not_blessed_by_a_canonical_one(self):
        reader, source = self.reader_variant(
            self.CANONICAL,
            self.CANONICAL + '\n\nconst MARKER: &str = "#[cfg(test)]";\n\n' + self.ACTIVE,
        )
        source = source.replace("FIXTURE.get(name)", "ACTIVE.get(name)")
        manifest = golden.load_manifest()
        entry = manifest["families"]["create"]
        declarations, _errors = self.parse(source)
        matching = [
            declaration
            for declaration in declarations
            if declaration["magic"] == entry["magic"]
            and declaration["fixture"] == entry["fixture"]
        ]
        self.assertEqual(len(matching), 1)
        self.assertTrue(self.violations_for(reader, source))

    def test_a_canonical_declaration_after_the_string_is_still_parsed(self):
        reader, source = self.reader_variant(
            self.CANONICAL,
            self.CANONICAL.replace("FIXTURE", "EARLIER").replace(
                "create.bin", "pcr_event.bin"
            )
            + '\n\nconst MARKER: &str = "#[cfg(test)]";\n\n'
            + self.CANONICAL,
        )
        declarations, errors = self.parse(source)
        self.assertEqual(errors, [])
        self.assertEqual([entry["name"] for entry in declarations], ["EARLIER", "FIXTURE"])
        self.assertEqual(self.violations_for(reader, source), [])

    def test_a_label_equal_to_the_constructor_is_not_a_constructor(self):
        reader, source = self.reader_variant('"TPM2_Create"', '"Fixture::new"')
        declarations, errors = self.parse(source)
        self.assertEqual([entry["name"] for entry in declarations], ["FIXTURE"])
        self.assertEqual(errors, [])
        self.assertEqual(self.violations_for(reader, source), [])

    def test_a_byte_string_constructor_is_not_a_constructor(self):
        reader, source = self.reader_variant(
            self.CANONICAL, self.CANONICAL + '\n\nconst NOISE: &[u8] = b"Fixture::new";'
        )
        declarations, errors = self.parse(source)
        self.assertEqual([entry["name"] for entry in declarations], ["FIXTURE"])
        self.assertEqual(errors, [])
        self.assertEqual(self.violations_for(reader, source), [])

    def test_a_raw_string_constructor_is_not_a_constructor(self):
        reader, source = self.reader_variant(
            self.CANONICAL,
            self.CANONICAL + '\n\nconst NOISE: &str = r#"Fixture :: new( #[cfg(test)]"#;',
        )
        declarations, errors = self.parse(source)
        self.assertEqual([entry["name"] for entry in declarations], ["FIXTURE"])
        self.assertEqual(errors, [])
        self.assertEqual(self.violations_for(reader, source), [])

    def test_a_commented_out_constructor_is_ignored(self):
        reader, source = self.reader_variant(
            self.CANONICAL,
            self.CANONICAL + "\n\n// const OLD: Fixture = Fixture::new(\n"
            "/* const OLDER: Fixture = Fixture :: new( */",
        )
        declarations, errors = self.parse(source)
        self.assertEqual([entry["name"] for entry in declarations], ["FIXTURE"])
        self.assertEqual(errors, [])
        self.assertEqual(self.violations_for(reader, source), [])

    def test_a_magic_constant_inside_a_raw_string_is_not_harvested(self):
        reader, source = self.reader_variant(
            'const MAGIC: &[u8; 8] = b"CRORACLE";',
            'const MAGIC: &[u8; 8] = b"CRORACLE";\n'
            'const DOC: &str = r#"\nconst PLANTED: &[u8; 8] = b"ZZORACLE";\n"#;',
        )
        declarations, errors = self.parse(source)
        self.assertEqual(errors, [])
        self.assertEqual([entry["magic"] for entry in declarations], ["CRORACLE"])

        def swap(manifest, facts):
            manifest["families"]["create"]["magic"] = "ZZORACLE"
            facts["reader_sources"][reader] = source.replace("MAGIC,", "PLANTED,", 1)

        self.assertTrue(any("is not an 8-byte literal" in v for v in self.violations(swap)))

    def test_an_unterminated_literal_fails_closed(self):
        reader, source = self.reader_variant('"TPM2_Create",', '"TPM2_Create,')
        declarations, errors = self.parse(source)
        self.assertEqual(declarations, [])
        self.assertEqual(errors, ["the source cannot be scanned: an unterminated string literal"])
        self.assertTrue(
            any("cannot be scanned" in v for v in self.violations_for(reader, source))
        )

    def test_an_unterminated_block_comment_fails_closed(self):
        reader, source = self.reader_variant(self.CANONICAL, "/* " + self.CANONICAL)
        declarations, errors = self.parse(source)
        self.assertEqual(declarations, [])
        self.assertEqual(
            errors, ["the source cannot be scanned: an unterminated block comment"]
        )
        self.assertTrue(
            any("cannot be scanned" in v for v in self.violations_for(reader, source))
        )

    def after_test_only_item(self, item):
        return self.reader_variant(self.CANONICAL, self.CANONICAL + item + self.ACTIVE)

    def test_a_test_only_constant_does_not_truncate_parsing(self):
        reader, source = self.after_test_only_item("\n\n#[cfg(test)]\nconst TEST_ONLY: u8 = 0;\n\n")
        declarations, errors = self.parse(source)
        self.assertEqual([entry["name"] for entry in declarations], ["FIXTURE"])
        self.assertTrue(any("unparsable Fixture::new" in error for error in errors), errors)
        self.assertTrue(
            any("unparsable Fixture::new" in v for v in self.violations_for(reader, source))
        )

    def test_a_test_only_function_does_not_truncate_parsing(self):
        reader, source = self.after_test_only_item("\n\n#[cfg(test)]\nfn helper() {}\n\n")
        self.assertTrue(
            any("unparsable Fixture::new" in v for v in self.violations_for(reader, source))
        )

    def test_a_test_only_static_does_not_truncate_parsing(self):
        reader, source = self.after_test_only_item("\n\n#[cfg(test)]\nstatic SEEN: u8 = 0;\n\n")
        self.assertTrue(
            any("unparsable Fixture::new" in v for v in self.violations_for(reader, source))
        )

    def test_a_test_only_module_that_is_not_tests_does_not_truncate_parsing(self):
        reader, source = self.after_test_only_item("\n\n#[cfg(test)]\nmod other { }\n\n")
        self.assertTrue(
            any("unparsable Fixture::new" in v for v in self.violations_for(reader, source))
        )

    def test_an_active_declaration_after_a_test_only_constant_is_visible(self):
        reader, source = self.reader_variant(
            self.CANONICAL,
            self.CANONICAL
            + "\n\n#[cfg(test)]\nconst TEST_ONLY: u8 = 0;\n\n"
            + self.ACTIVE.replace("Fixture :: new", "Fixture::new"),
        )
        source = source.replace("FIXTURE.get(name)", "ACTIVE.get(name)")
        declarations, errors = self.parse(source)
        self.assertEqual(errors, [])
        self.assertEqual([entry["name"] for entry in declarations], ["FIXTURE", "ACTIVE"])
        self.assertEqual(
            [entry["fixture"].split("/")[-1] for entry in declarations],
            ["create.bin", "pcr_event.bin"],
        )

    def test_a_production_constructor_after_the_test_module_is_parsed(self):
        reader = golden.READER_DIR + "create.rs"
        source = (golden.ROOT / reader).read_text("utf-8") + "\n" + self.ACTIVE.replace(
            "Fixture :: new", "Fixture::new"
        ).replace("ACTIVE", "AFTER")
        declarations, errors = self.parse(source)
        self.assertEqual(errors, [])
        self.assertEqual([entry["name"] for entry in declarations], ["FIXTURE", "AFTER"])

    def test_a_spaced_constructor_after_the_test_module_is_rejected(self):
        reader = golden.READER_DIR + "create.rs"
        source = (golden.ROOT / reader).read_text("utf-8") + "\n" + self.ACTIVE
        declarations, errors = self.parse(source)
        self.assertEqual([entry["name"] for entry in declarations], ["FIXTURE"])
        self.assertTrue(any("unparsable Fixture::new" in error for error in errors), errors)
        self.assertTrue(
            any("unparsable Fixture::new" in v for v in self.violations_for(reader, source))
        )

    def test_constructors_inside_the_test_module_are_ignored(self):
        reader, source = self.reader_variant(
            "#[cfg(test)]\nmod tests {",
            "#[cfg(test)]\nmod tests {\n"
            "    const PLANTED: Fixture = Fixture::new(\n"
            '        "planted",\n'
            "        MAGIC,\n"
            '        include_bytes!("../testdata/golden_responses/pcr_event.bin"),\n'
            "    );\n"
            "    const SPACED: Fixture = Fixture :: new();\n",
        )
        declarations, errors = self.parse(source)
        self.assertEqual([entry["name"] for entry in declarations], ["FIXTURE"])
        self.assertEqual(errors, [])
        self.assertEqual(self.violations_for(reader, source), [])

    def test_a_whitespace_separated_test_module_is_recognized(self):
        reader, source = self.reader_variant(
            "#[cfg(test)]\nmod tests {", "#[ cfg ( test ) ]\nmod\ntests\n{"
        )
        declarations, errors = self.parse(source)
        self.assertEqual([entry["name"] for entry in declarations], ["FIXTURE"])
        self.assertEqual(errors, [])
        self.assertEqual(self.violations_for(reader, source), [])

    def test_nested_modules_inside_the_test_module_are_balanced(self):
        reader, source = self.reader_variant(
            "#[cfg(test)]\nmod tests {",
            "#[cfg(test)]\nmod tests {\n"
            "    mod inner {\n"
            "        fn f() { if true { } }\n"
            "        const PLANTED: Fixture = Fixture :: new();\n"
            "    }\n",
        )
        declarations, errors = self.parse(source)
        self.assertEqual([entry["name"] for entry in declarations], ["FIXTURE"])
        self.assertEqual(errors, [])
        self.assertEqual(self.violations_for(reader, source), [])

    def test_braces_in_strings_and_comments_do_not_unbalance_the_test_module(self):
        reader, source = self.reader_variant(
            "#[cfg(test)]\nmod tests {",
            "#[cfg(test)]\nmod tests {\n"
            '    const A: &str = "}}}}";\n'
            '    const B: &[u8] = b"}}";\n'
            '    const C: &str = r#"} #[cfg(test)] mod tests {"#;\n'
            "    // }\n"
            "    /* } } */\n",
        )
        declarations, errors = self.parse(source)
        self.assertEqual([entry["name"] for entry in declarations], ["FIXTURE"])
        self.assertEqual(errors, [])
        self.assertEqual(self.violations_for(reader, source), [])

    def test_a_production_brace_string_does_not_start_a_test_module(self):
        reader, source = self.reader_variant(
            self.CANONICAL,
            self.CANONICAL + '\n\nconst B: &str = "} #[cfg(test)] mod tests {";\n',
        )
        declarations, errors = self.parse(source)
        self.assertEqual([entry["name"] for entry in declarations], ["FIXTURE"])
        self.assertEqual(errors, [])
        self.assertEqual(self.violations_for(reader, source), [])

    def test_an_unclosed_test_module_fails_closed(self):
        reader = golden.READER_DIR + "create.rs"
        source = (golden.ROOT / reader).read_text("utf-8").rstrip()[:-1]
        declarations, errors = self.parse(source)
        self.assertEqual(declarations, [])
        self.assertEqual(
            errors,
            ["the source cannot be scanned: an unbalanced #[cfg(test)] mod tests body"],
        )
        self.assertTrue(
            any("cannot be scanned" in v for v in self.violations_for(reader, source))
        )

    def test_a_bodyless_test_module_fails_closed(self):
        reader, source = self.reader_variant(
            "#[cfg(test)]\nmod tests {", "#[cfg(test)]\nmod tests;\n\nmod tests_inline {"
        )
        declarations, errors = self.parse(source)
        self.assertEqual(declarations, [])
        self.assertEqual(
            errors,
            ["the source cannot be scanned: a #[cfg(test)] mod tests item without a body"],
        )
        self.assertTrue(
            any("cannot be scanned" in v for v in self.violations_for(reader, source))
        )

    def test_the_real_test_module_boundary_is_recognized(self):
        reader = golden.READER_DIR + "create.rs"
        source = (golden.ROOT / reader).read_text("utf-8")
        masked, failure = golden.mask_rust_literals(source)
        self.assertIsNone(failure)
        boundary = golden.TEST_MODULE_ATTRIBUTE.search(masked)
        self.assertIsNotNone(boundary)
        self.assertEqual(
            source[boundary.start() : boundary.end()], "#[cfg(test)]"
        )
        self.assertIn("mod tests", source[boundary.end() : boundary.end() + 40])

    def test_lifetimes_are_not_mistaken_for_literals(self):
        masked, failure = golden.mask_rust_literals(
            "fn f<'a>(x: &'a str) -> &'static [u8] { b'x'; \"s\" }"
        )
        self.assertIsNone(failure)
        self.assertIn("&'a str", masked)
        self.assertIn("&'static", masked)
        self.assertNotIn("b'x'", masked)
        self.assertNotIn('"s"', masked)

    def test_the_constructor_pattern_ignores_whitespace(self):
        for spelling in ("Fixture::new", "Fixture ::new", "Fixture:: new", "Fixture  ::  new"):
            self.assertTrue(golden.FIXTURE_CONSTRUCTOR.search(spelling), spelling)
        for spelling in ("Fixtures::new", "Fixture::news", "Fixture:new"):
            self.assertIsNone(golden.FIXTURE_CONSTRUCTOR.search(spelling), spelling)

    def test_a_duplicate_declaration_is_ambiguous(self):
        reader = golden.READER_DIR + "create.rs"
        source = (golden.ROOT / reader).read_text("utf-8")
        declaration = (
            "static FIXTURE: Fixture = Fixture::new(\n"
            '    "TPM2_Create",\n'
            "    MAGIC,\n"
            '    include_bytes!("../testdata/golden_responses/create.bin"),\n'
            ");\n"
        )

        def mutate(_manifest, facts):
            self.assertIn(declaration, source)
            facts["reader_sources"][reader] = source.replace(
                declaration, declaration + "\n" + declaration.replace("FIXTURE", "SECOND"), 1
            )

        self.assertTrue(any("more than once" in v for v in self.violations(mutate)))

    def test_a_consistent_magic_migration_is_tolerated_as_stale(self):
        reader = golden.READER_DIR + "create.rs"
        manifest = golden.load_manifest()
        manifest["families"]["create"]["magic"] = "ZZORACLE"
        facts = golden.collect_facts(manifest)
        facts["reader_sources"][reader] = facts["reader_sources"][reader].replace(
            'const MAGIC: &[u8; 8] = b"CRORACLE";',
            'const MAGIC: &[u8; 8] = b"ZZORACLE";',
            1,
        )
        remaining = [
            violation
            for violation in golden.audit_violations(manifest, facts)
            if not golden.tolerated_stale(violation, {"create"})
        ]
        self.assertEqual(remaining, [])

    def test_two_families_may_not_share_a_fixture(self):
        def mutate(manifest, _facts):
            manifest["families"]["create"]["fixture"] = manifest["families"]["pcr-event"]["fixture"]

        self.assertTrue(any("is already used by" in v for v in self.violations(mutate)))

    def test_two_families_may_not_claim_one_command(self):
        def mutate(manifest, _facts):
            manifest["families"]["create"]["commands"] = list(
                manifest["families"]["pcr-event"]["commands"]
            )

        self.assertTrue(any("is already covered by" in v for v in self.violations(mutate)))

    def test_an_untracked_reader_is_rejected(self):
        def mutate(manifest, facts):
            facts["tracked_replay_files"] = facts["tracked_replay_files"] - {
                manifest["families"]["create"]["reader"]
            }

        self.assertTrue(any("is not tracked by git" in v for v in self.violations(mutate)))

    def test_an_untracked_fixture_is_rejected(self):
        def mutate(manifest, facts):
            facts["tracked_replay_files"] = facts["tracked_replay_files"] - {
                manifest["families"]["create"]["fixture"]
            }

        self.assertTrue(any("is not tracked by git" in v for v in self.violations(mutate)))

    def test_the_audit_rejects_a_swapped_reader(self):
        manifest = golden.load_manifest()
        manifest["families"]["create"]["reader"] = golden.READER_DIR + "pcr_event.rs"
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = golden.run_audit(manifest=manifest, facts=golden.collect_facts(manifest))
        self.assertEqual(code, 1)
        self.assertIn("declares no Fixture::new", err.getvalue())

    def test_every_committed_reader_declares_its_fixtures_as_static(self):
        for family, entry in sorted(golden.well_formed_families(golden.load_manifest()).items()):
            reader = entry["reader"]
            declarations, errors = golden.parse_reader_fixtures(
                reader, (golden.ROOT / reader).read_text("utf-8")
            )
            self.assertEqual(errors, [], family)
            self.assertEqual(
                sorted({declaration["kind"] for declaration in declarations}),
                ["static"],
                family,
            )

    def test_the_canonical_static_declaration_is_accepted(self):
        reader = golden.READER_DIR + "create.rs"
        source = (golden.ROOT / reader).read_text("utf-8")
        declarations, errors = golden.parse_reader_fixtures(reader, source)
        self.assertEqual(errors, [])
        self.assertEqual([entry["kind"] for entry in declarations], ["static"])
        self.assertEqual(self.violations_for(reader, source), [])

    def test_a_manifest_associated_const_fixture_is_rejected(self):
        reader, source = self.reader_variant(
            "static FIXTURE: Fixture = Fixture::new(",
            "const FIXTURE: Fixture = Fixture::new(",
        )
        declarations, errors = self.parse(source)
        self.assertEqual(errors, [])
        self.assertEqual([entry["kind"] for entry in declarations], ["const"])
        violations = self.violations_for(reader, source)
        self.assertTrue(any("must be static" in v for v in violations), violations)
        self.assertTrue(any("const Fixture" in v for v in violations), violations)
        self.assertTrue(any("FIXTURE" in v for v in violations), violations)

    def test_an_additional_active_const_fixture_stays_visible_to_the_audit(self):
        second = self.CANONICAL.replace("FIXTURE", "SECOND")
        reader, source = self.reader_variant(
            self.CANONICAL, self.CANONICAL + "\n\n" + second.replace("static", "const")
        )
        declarations, errors = self.parse(source)
        self.assertEqual(errors, [])
        self.assertEqual(
            [(entry["name"], entry["kind"]) for entry in declarations],
            [("FIXTURE", "static"), ("SECOND", "const")],
        )
        self.assertTrue(
            any("more than once" in v for v in self.violations_for(reader, source))
        )

    def test_an_unassociated_active_const_fixture_is_parsed_without_the_static_error(self):
        other = (
            self.CANONICAL.replace("FIXTURE", "OTHER")
            .replace("static", "const")
            .replace("create.bin", "pcr_event.bin")
        )
        reader, source = self.reader_variant(
            self.CANONICAL, self.CANONICAL + "\n\n" + other
        )
        declarations, errors = self.parse(source)
        self.assertEqual(errors, [])
        self.assertEqual(
            [(entry["name"], entry["kind"]) for entry in declarations],
            [("FIXTURE", "static"), ("OTHER", "const")],
        )
        self.assertEqual(self.violations_for(reader, source), [])

    def test_a_test_only_const_fixture_does_not_trigger_the_static_requirement(self):
        reader, source = self.reader_variant(
            "#[cfg(test)]\nmod tests {",
            "#[cfg(test)]\nmod tests {\n"
            "    const PLANTED: Fixture = Fixture::new(\n"
            '        "planted",\n'
            "        MAGIC,\n"
            '        include_bytes!("../testdata/golden_responses/create.bin"),\n'
            "    );\n",
        )
        declarations, errors = self.parse(source)
        self.assertEqual(errors, [])
        self.assertEqual([entry["name"] for entry in declarations], ["FIXTURE"])
        self.assertEqual(self.violations_for(reader, source), [])


class GoldenRunnerContractTest(unittest.TestCase):
    def setUp(self):
        self.source = (golden.HERE / "runner.c").read_text("utf-8")
        self.lines = self.source.splitlines()

    def test_every_main_init_result_is_captured(self):
        unassigned = [
            index + 1
            for index, line in enumerate(self.lines)
            if re.match(r"^\s*TPMLIB_MainInit\(\);", line)
        ]
        self.assertEqual(unassigned, [])

    def test_every_main_init_result_is_checked(self):
        for index, line in enumerate(self.lines):
            if "TPMLIB_MainInit()" not in line:
                continue
            self.assertRegex(line.strip(), r"^res = TPMLIB_MainInit\(\);$")
            self.assertRegex(self.lines[index + 1].strip(), r"^if \(res")

    def test_every_main_init_check_can_abort(self):
        for index, line in enumerate(self.lines):
            if "TPMLIB_MainInit()" not in line:
                continue
            window = " ".join(self.lines[index + 1 : index + 5])
            self.assertIn("die(", window)

    def test_the_failure_mode_result_is_a_named_constant(self):
        self.assertIn("#define FAILURE_MODE_RESULT 0x101", self.source)
        self.assertNotIn("0x101", self.source.replace("#define FAILURE_MODE_RESULT 0x101", ""))

    def test_patch_failure_code_requires_the_failure_mode_result(self):
        start = self.source.index('strncmp(p, "patch-failure-code ", 19)')
        end = self.source.index('strncmp(p, "locality ", 9)')
        body = self.source[start:end]
        self.assertIn("res = TPMLIB_MainInit();", body)
        self.assertIn("if (res != FAILURE_MODE_RESULT)", body)
        self.assertIn("patch-failure-code: MainInit answered", body)
        self.assertIn("lineno", body[body.index("MainInit answered") - 200 :])

    def test_the_runner_is_built_with_strict_warnings(self):
        dockerfile = golden.DOCKERFILE.read_text("utf-8")
        build = dockerfile[dockerfile.index("golden-runner") - 200 : dockerfile.index("golden-runner")]
        for flag in ("-Wall", "-Wextra", "-Werror"):
            self.assertIn(flag, build)


class GoldenDockerOutcomeTest(unittest.TestCase):
    def outcome(self, replacement, **keywords):
        original = golden.subprocess.run
        golden.subprocess.run = replacement
        try:
            return golden.run_docker(["run", "--rm", "image"], **keywords)
        finally:
            golden.subprocess.run = original

    def completed(self, returncode, stdout="", stderr=""):
        def replacement(*_arguments, **_keywords):
            return subprocess.CompletedProcess([], returncode, stdout, stderr)

        return replacement

    def test_a_missing_docker_binary_is_named(self):
        def replacement(*_arguments, **_keywords):
            raise FileNotFoundError("docker")

        outcome = self.outcome(replacement)
        self.assertEqual(outcome.status, "not-found")
        self.assertIn("not found on PATH", outcome.message)

    def test_a_timeout_is_named(self):
        def replacement(*_arguments, **_keywords):
            raise subprocess.TimeoutExpired("docker", 1)

        outcome = self.outcome(replacement, timeout=1)
        self.assertEqual(outcome.status, "timeout")
        self.assertIn("did not finish within 1s", outcome.message)

    def test_a_nonzero_exit_surfaces_stderr(self):
        outcome = self.outcome(self.completed(2, stderr="no such image: golden\n"))
        self.assertEqual(outcome.status, "failed")
        self.assertIn("exited 2", outcome.message)
        self.assertIn("no such image: golden", outcome.message)

    def test_empty_stdout_is_distinguished_from_success(self):
        outcome = self.outcome(self.completed(0, stdout="   \n", stderr="warning\n"))
        self.assertEqual(outcome.status, "empty")
        self.assertIn("produced no output", outcome.message)
        self.assertIn("warning", outcome.message)

    def test_empty_stdout_is_allowed_when_asked(self):
        outcome = self.outcome(self.completed(0, stdout=""), allow_empty=True)
        self.assertTrue(outcome.ok)

    def test_success_carries_the_output(self):
        outcome = self.outcome(self.completed(0, stdout="NAME 00\n"))
        self.assertTrue(outcome.ok)
        self.assertEqual(outcome.stdout, "NAME 00\n")

    def test_docker_output_hides_the_detail(self):
        original = golden.run_docker
        golden.run_docker = lambda arguments, **keywords: golden.DockerOutcome(
            "failed", message="boom"
        )
        try:
            self.assertIsNone(golden.docker_output(["image", "inspect", "x"]))
        finally:
            golden.run_docker = original

    def test_a_failed_capture_reports_the_reason(self):
        original = golden.run_docker
        golden.run_docker = lambda arguments, **keywords: golden.DockerOutcome(
            "failed", message="'docker run' exited 1:\nrunner: line 3: unknown op"
        )
        try:
            manifest = golden.load_manifest()
            entry = manifest["families"]["create"]
            blob, error = golden.capture_family(
                manifest, "create", entry, "tag", "linux/arm64"
            )
        finally:
            golden.run_docker = original
        self.assertIsNone(blob)
        self.assertIn("unknown op", error)

    def test_a_failed_build_reports_the_reason(self):
        original = golden.run_docker
        original_output = golden.docker_output
        golden.run_docker = lambda arguments, **keywords: golden.DockerOutcome(
            "not-found", message="docker was not found on PATH"
        )
        golden.docker_output = lambda arguments: None
        try:
            tag, error = golden.resolve_image(golden.load_manifest())
        finally:
            golden.run_docker = original
            golden.docker_output = original_output
        self.assertIsNone(tag)
        self.assertIn("not found on PATH", error)

    def test_stderr_tail_keeps_the_last_lines(self):
        self.assertEqual(golden.stderr_tail("a\nb\nc\n", lines=2), "b\nc")
        self.assertEqual(golden.stderr_tail("   \n"), "no stderr output")


class GoldenScenarioParserTest(unittest.TestCase):
    def errors(self, text):
        return golden.parse_scenario(text)[2]

    def test_every_committed_scenario_parses(self):
        manifest = golden.load_manifest()
        for entry in golden.well_formed_families(manifest).values():
            text = (golden.ROOT / entry["scenario"]).read_text("utf-8")
            self.assertEqual(self.errors(text), [], entry["scenario"])

    def test_the_parser_predicts_the_committed_records(self):
        packer = golden.load_packer()
        manifest = golden.load_manifest()
        for family, entry in golden.well_formed_families(manifest).items():
            records, _codes, _errors = golden.parse_scenario(
                (golden.ROOT / entry["scenario"]).read_text("utf-8")
            )
            committed = [
                name
                for name, _payload in packer.unpack(
                    entry["magic"].encode("ascii"),
                    (golden.ROOT / entry["fixture"]).read_bytes(),
                )
            ]
            self.assertEqual(sorted(records), sorted(committed), family)

    def test_the_op_table_matches_the_runner(self):
        source = (golden.HERE / "runner.c").read_text("utf-8")
        implemented = set(re.findall(r'strn?cmp\(p, "([a-z-]+) ?"', source))
        self.assertEqual(implemented, set(golden.SCENARIO_OPS))

    def test_the_runner_has_no_unused_ops(self):
        manifest = golden.load_manifest()
        used = set()
        scenarios = [entry["scenario"] for entry in manifest["families"].values()]
        scenarios.append("scripts/golden_responses/" + golden.REPRODUCIBILITY_SCENARIO)
        for scenario in scenarios:
            for line in (golden.ROOT / scenario).read_text("utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    used.add(line.split(" ")[0])
        self.assertEqual(used, set(golden.SCENARIO_OPS))

    def test_an_unknown_op_is_rejected(self):
        self.assertIn("unknown op 'teleport'", self.errors("teleport NOW")[0])

    def test_a_duplicate_record_name_is_rejected(self):
        text = "send A 80010000000a0000017c\nsend A 80010000000a0000017c\n"
        self.assertIn("duplicate record name A", self.errors(text)[0])

    def test_a_snapshot_collides_with_an_explicit_record(self):
        text = "snapshot X\npermall PERMALL_X\n"
        self.assertTrue(any("duplicate record name PERMALL_X" in e for e in self.errors(text)))

    def test_a_lower_case_label_is_rejected(self):
        self.assertIn("is not upper-case ASCII", self.errors("send lower 80010000000a0000017c")[0])

    def test_a_send_without_a_command_is_rejected(self):
        self.assertIn("needs a name and a command", self.errors("send ONLYNAME")[0])

    def test_odd_length_hex_is_rejected(self):
        self.assertIn("odd number of digits", self.errors("raw 80010000000a0000017")[0])

    def test_upper_case_hex_is_rejected(self):
        self.assertIn("not lower-case hexadecimal", self.errors("raw 80010000000A0000017C")[0])

    def test_a_missing_argument_is_rejected(self):
        self.assertIn("permall needs an argument", self.errors("permall")[0])

    def test_an_argument_to_a_niladic_op_is_rejected(self):
        self.assertIn("reboot takes no argument", self.errors("reboot now")[0])

    def test_a_non_numeric_advance_is_rejected(self):
        self.assertIn("needs a decimal argument", self.errors("advance later")[0])

    def test_a_non_boolean_fail_stores_is_rejected(self):
        self.assertIn("takes 0 or 1", self.errors("fail-stores yes")[0])

    def test_an_invalid_profile_is_rejected(self):
        self.assertIn("not valid JSON", self.errors('profile {"Name":')[0])

    def test_a_scalar_profile_is_rejected(self):
        self.assertIn("must be a JSON object", self.errors("profile 7")[0])

    def test_a_restore_without_a_checkpoint_is_rejected(self):
        self.assertIn("unknown checkpoint MISSING", self.errors("restore MISSING")[0])

    def test_a_checkpoint_satisfies_a_later_restore(self):
        self.assertEqual(self.errors("checkpoint SAVED\nrestore SAVED\n"), [])

    def test_a_snapshot_satisfies_a_later_restore(self):
        self.assertEqual(self.errors("snapshot SAVED\nrestore-permanent SAVED\n"), [])

    def test_comments_and_blank_lines_are_ignored(self):
        self.assertEqual(self.errors("# comment\n\n   \nreboot\n"), [])

    def test_command_codes_come_from_send_and_raw(self):
        _records, codes, errors = golden.parse_scenario(
            "send A 80010000000a0000017c\nraw 80010000000c000001440000\n"
        )
        self.assertEqual(errors, [])
        self.assertEqual(codes, [0x17C, 0x144])

    def test_a_malformed_packet_carries_no_command_code(self):
        _records, codes, errors = golden.parse_scenario("send A 800100000009000001\n")
        self.assertEqual(errors, [])
        self.assertEqual(codes, [])

    def test_version_records_a_row(self):
        records, _codes, errors = golden.parse_scenario("version\n")
        self.assertEqual((records, errors), (["VERSION"], []))

    def test_evict_control_covers_its_commands_through_raw(self):
        manifest = golden.load_manifest()
        entry = manifest["families"]["evict-control"]
        _records, codes, _errors = golden.parse_scenario(
            (golden.ROOT / entry["scenario"]).read_text("utf-8")
        )
        for _command, code in golden.scenario_command_codes(manifest, entry, "evict-control"):
            self.assertIn(code, codes)

    def test_an_uncovered_command_is_reported(self):
        manifest = golden.load_manifest()
        facts = golden.collect_facts(manifest)
        manifest["families"]["evict-control"]["commands"] = ["TPM2_PCR_Event"]
        manifest["commands"]["PCR_Event"]["family"] = "evict-control"
        violations = rendered(golden.validate_scenarios(manifest, facts))
        self.assertTrue(any("never runs TPM2_PCR_Event" in v for v in violations))

    def test_a_broken_scenario_fails_the_audit(self):
        manifest = golden.load_manifest()
        facts = golden.collect_facts(manifest)
        facts["scenario_sources"][manifest["families"]["create"]["scenario"]] = "teleport NOW\n"
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = golden.run_audit(manifest=manifest, facts=facts)
        self.assertEqual(code, 1)
        self.assertIn("unknown op 'teleport'", err.getvalue())


class GoldenSubmoduleScopeTest(unittest.TestCase):
    def test_only_context_submodules_are_checked(self):
        self.assertEqual(golden.CONTEXT_SUBMODULES, ("libtpms",))

    def test_dirty_libtpms_is_rejected(self):
        facts = baseline_facts()
        facts["submodule_dirt"] = {"libtpms": ["untracked file src/x.c"]}
        violations = golden.validate_submodules(golden.load_manifest(), facts)
        self.assertTrue(any("libtpms is dirty" in violation for violation in rendered(violations)))

    def test_dirty_swtpm_is_ignored(self):
        facts = baseline_facts()
        facts["submodule_dirt"] = {"libtpms": [], "swtpm": ["untracked file tests/x"]}
        self.assertEqual(golden.validate_submodules(golden.load_manifest(), facts), [])

    def test_no_swtpm_state_is_collected(self):
        manifest = golden.load_manifest()
        facts = golden.collect_facts(manifest)
        self.assertNotIn("swtpm_commit", facts)
        self.assertNotIn("swtpm", facts["submodule_dirt"])

    def test_context_carries_no_swtpm_files(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = golden.build_context(directory)
        self.assertFalse([path for path in paths if path.startswith("swtpm/")])


class GoldenPathContainmentTest(unittest.TestCase):
    def violation(self, field, value):
        directory, suffix = {
            "fixture": (golden.FIXTURE_DIR, ".bin"),
            "reader": (golden.READER_DIR, ".rs"),
            "scenario": (golden.SCENARIO_DIR, ".scenario"),
        }[field]
        violation = golden.path_violation("alpha", field, value, directory, suffix)
        return violation.render() if violation is not None else None

    def test_absolute_fixture_path(self):
        self.assertIn("relative", self.violation("fixture", "/etc/passwd.bin"))

    def test_absolute_reader_path(self):
        self.assertIn("relative", self.violation("reader", "/tmp/reader.rs"))

    def test_parent_traversal(self):
        self.assertIn("escapes", self.violation("fixture", "../../../etc/passwd.bin"))

    def test_unnormalized_path(self):
        self.assertIn(
            "not normalized",
            self.violation("fixture", golden.FIXTURE_DIR + "./create.bin"),
        )

    def test_fixture_outside_the_testdata_directory(self):
        self.assertIn("outside", self.violation("fixture", "src/library/create.bin"))

    def test_reader_outside_the_rust_directory(self):
        self.assertIn("outside", self.violation("reader", "src/library/create.rs"))

    def test_wrong_fixture_extension(self):
        self.assertIn(
            "does not end in .bin", self.violation("fixture", golden.FIXTURE_DIR + "create.txt")
        )

    def test_wrong_reader_extension(self):
        self.assertIn(
            "does not end in .rs", self.violation("reader", golden.READER_DIR + "create.bin")
        )

    def test_nested_path_is_rejected(self):
        self.assertIn(
            "nested", self.violation("fixture", golden.FIXTURE_DIR + "nested/create.bin")
        )

    def test_symlinked_parent_is_rejected(self):
        directory = tempfile.mkdtemp()
        original_root = golden.ROOT
        try:
            root = Path(directory)
            real = root / "outside"
            real.mkdir()
            link_parent = root / golden.FIXTURE_DIR
            link_parent.parent.mkdir(parents=True)
            os.symlink(real, link_parent)
            golden.ROOT = root
            self.assertIn(
                "resolves outside",
                self.violation("fixture", golden.FIXTURE_DIR + "create.bin"),
            )
        finally:
            golden.ROOT = original_root
            shutil.rmtree(directory, ignore_errors=True)

    def isolated_root(self):
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        root = Path(directory)
        (root / golden.FIXTURE_DIR).mkdir(parents=True)
        (root / golden.READER_DIR).mkdir(parents=True)
        (root / "outside").mkdir()
        original_root = golden.ROOT
        golden.ROOT = root
        self.addCleanup(setattr, golden, "ROOT", original_root)
        return root

    def test_a_symlinked_fixture_is_rejected(self):
        root = self.isolated_root()
        target = root / "outside" / "create.bin"
        target.write_bytes(b"x")
        os.symlink(target, root / golden.FIXTURE_DIR / "create.bin")
        self.assertIn(
            "is a symlink", self.violation("fixture", golden.FIXTURE_DIR + "create.bin")
        )

    def test_a_symlinked_reader_is_rejected(self):
        root = self.isolated_root()
        target = root / "outside" / "create.rs"
        target.write_text("")
        os.symlink(target, root / golden.READER_DIR / "create.rs")
        self.assertIn(
            "is a symlink", self.violation("reader", golden.READER_DIR + "create.rs")
        )

    def test_a_symlink_inside_the_directory_is_still_rejected(self):
        root = self.isolated_root()
        real = root / golden.FIXTURE_DIR / "real.bin"
        real.write_bytes(b"x")
        os.symlink(real, root / golden.FIXTURE_DIR / "create.bin")
        self.assertIn(
            "is a symlink", self.violation("fixture", golden.FIXTURE_DIR + "create.bin")
        )

    def test_a_regular_file_in_the_directory_is_accepted(self):
        root = self.isolated_root()
        (root / golden.FIXTURE_DIR / "create.bin").write_bytes(b"x")
        self.assertIsNone(self.violation("fixture", golden.FIXTURE_DIR + "create.bin"))

    def test_an_absent_path_in_the_directory_is_accepted(self):
        self.isolated_root()
        self.assertIsNone(self.violation("fixture", golden.FIXTURE_DIR + "create.bin"))

    def test_update_refuses_to_write_through_a_symlink(self):
        root = self.isolated_root()
        target = root / "outside" / "create.bin"
        target.write_bytes(b"original")
        os.symlink(target, root / golden.FIXTURE_DIR / "create.bin")
        entry = {"fixture": golden.FIXTURE_DIR + "create.bin", "magic": "TSTMAGIC"}
        written, failure = golden.replace_fixtures([("create", entry, b"new")])
        self.assertIsNone(written)
        self.assertIn("is a symlink", failure["error"])
        self.assertEqual(target.read_bytes(), b"original")

    def test_committed_paths_are_accepted(self):
        manifest = golden.load_manifest()
        self.assertEqual(golden.validate_manifest_paths(manifest), [])

    def test_audit_rejects_an_unsafe_fixture_path(self):
        manifest = golden.load_manifest()
        manifest["families"]["create"]["fixture"] = "../../../etc/passwd.bin"
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = golden.run_audit(manifest=manifest, facts=baseline_facts())
        self.assertEqual(code, 1)
        self.assertIn("escapes the repository", err.getvalue())

    def test_resolved_fixture_path_refuses_unsafe_entries(self):
        with self.assertRaises(ValueError):
            golden.resolved_fixture_path("alpha", {"fixture": "/etc/passwd"})


class GoldenStaleMigrationTest(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.original_docker = golden.docker_output
        self.original_resolve = golden.resolve_image
        self.original_facts = golden.collect_facts
        golden.docker_output = lambda arguments: self.calls.append(arguments) or ""
        golden.resolve_image = self.forbid
        golden.collect_facts = self.migrated_facts

    def tearDown(self):
        golden.docker_output = self.original_docker
        golden.resolve_image = self.original_resolve
        golden.collect_facts = self.original_facts

    def migrated_facts(self, manifest):
        facts = self.original_facts(manifest)
        reader = golden.READER_DIR + "nv.rs"
        if reader in facts["reader_sources"]:
            facts["reader_sources"][reader] = facts["reader_sources"][reader].replace(
                'const CERTIFY_MAGIC: &[u8; 8] = b"NCORACLE";',
                'const CERTIFY_MAGIC: &[u8; 8] = b"ZZORACLE";',
                1,
            )
        return facts

    def forbid(self, *arguments, **keywords):
        raise AssertionError("preflight must fail before Docker")

    def stale_manifest(self):
        manifest = golden.load_manifest()
        manifest["families"]["nv-certify"]["magic"] = "ZZORACLE"
        return manifest

    def preflight(self, manifest):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = golden.preflight(manifest, "update", allow_stale={"nv-certify"})
        return code, err.getvalue()

    def test_only_the_stale_fixture_violation_is_tolerated(self):
        code, _errors = self.preflight(self.stale_manifest())
        self.assertEqual(code, 0)
        self.assertEqual(self.calls, [])

    def test_duplicate_magic_still_fails(self):
        manifest = self.stale_manifest()
        manifest["families"]["nv-certify"]["magic"] = manifest["families"]["nv-commands"]["magic"]
        code, errors = self.preflight(manifest)
        self.assertEqual(code, 1)
        self.assertIn("already used by", errors)
        self.assertEqual(self.calls, [])

    def test_missing_reader_still_fails(self):
        manifest = self.stale_manifest()
        manifest["families"]["nv-certify"]["reader"] = golden.READER_DIR + "absent.rs"
        code, errors = self.preflight(manifest)
        self.assertEqual(code, 1)
        self.assertIn("reader", errors)
        self.assertEqual(self.calls, [])

    def test_unsafe_fixture_path_still_fails(self):
        manifest = self.stale_manifest()
        manifest["families"]["nv-certify"]["fixture"] = "../../../etc/passwd.bin"
        code, errors = self.preflight(manifest)
        self.assertEqual(code, 1)
        self.assertIn("escapes the repository", errors)
        self.assertEqual(self.calls, [])

    def test_malformed_metadata_still_fails(self):
        manifest = self.stale_manifest()
        manifest["families"]["nv-certify"]["commands"] = "TPM2_NV_Certify"
        code, errors = self.preflight(manifest)
        self.assertEqual(code, 1)
        self.assertIn("commands must be a list", errors)

    def test_another_family_failing_still_fails(self):
        manifest = self.stale_manifest()
        manifest["families"]["create"]["magic"] = "SHORT"
        code, errors = self.preflight(manifest)
        self.assertEqual(code, 1)
        self.assertIn("create", errors)
        self.assertEqual(self.calls, [])

    def test_stale_families_are_detected_exactly(self):
        self.assertEqual(golden.stale_fixture_families(self.stale_manifest()), {"nv-certify"})
        self.assertEqual(golden.stale_fixture_families(golden.load_manifest()), set())


class CommittedManifestCoverageTest(unittest.TestCase):
    def setUp(self):
        self.manifest = golden.load_manifest()
        self.commands = self.manifest["commands"]

    def test_every_upstream_command_is_resolved(self):
        upstream = dict(golden.parse_upstream())
        self.assertEqual(len(self.commands), len(upstream))
        self.assertEqual(
            sorted(entry["code"] for entry in self.commands.values()),
            sorted(upstream.values()),
        )

    def test_no_command_is_still_on_the_roadmap(self):
        pending = [
            name
            for name, entry in self.commands.items()
            if entry.get("status") == "todo"
        ]
        self.assertEqual(pending, [])

    def test_every_profile_disabled_command_is_waived_with_its_own_reason(self):
        disabled = {
            "FieldUpgradeStart": "CC_FieldUpgradeStart",
            "FieldUpgradeData": "CC_FieldUpgradeData",
            "FirmwareRead": "CC_FirmwareRead",
            "AC_GetCapability": "CC_AC_GetCapability",
            "AC_Send": "CC_AC_Send",
            "Policy_AC_SendSelect": "CC_Policy_AC_SendSelect",
            "NV_DefineSpace2": "CC_NV_DefineSpace2",
            "NV_ReadPublic2": "CC_NV_ReadPublic2",
            "SetCapability": "CC_SetCapability",
            "Vendor_TCG_Test": "CC_Vendor_TCG_Test",
        }
        reasons = set()
        for name, symbol in disabled.items():
            entry = self.commands[name]
            self.assertEqual(entry.get("status"), "waived", name)
            self.assertEqual(entry.get("family"), "disabled-commands", name)
            reason = entry.get("reason", "")
            self.assertIn(symbol + " to CC_NO", reason, name)
            reasons.add(reason)
        self.assertEqual(len(reasons), len(disabled), "each reason names its own symbol")

    def test_the_waived_set_equals_the_profile_disabled_set(self):
        waived = {
            name
            for name, entry in self.commands.items()
            if entry.get("status") == "waived"
        }
        self.assertEqual(waived, golden.parse_reference_disabled())
        self.assertIn("ACT_SetTimeout", waived)
        self.assertEqual(len(waived), 11)

    def test_certify_x509_is_implemented_and_covered(self):
        entry = self.commands["CertifyX509"]
        self.assertEqual(entry["code"], 0x0000_0197)
        self.assertEqual(entry.get("status"), "implemented")
        self.assertEqual(entry.get("family"), "certify-x509")
        family = self.manifest["families"]["certify-x509"]
        self.assertEqual(family["commands"], ["TPM2_CertifyX509"])


class ProfileWaiverAuditTest(unittest.TestCase):
    """The read-only audit itself, not just a manifest reader, enforces the
    profile-waiver invariant."""

    @classmethod
    def setUpClass(cls):
        cls.committed = golden.load_manifest()
        cls.facts = golden.collect_facts(cls.committed)
        cls.packer = golden.load_packer()

    def manifest(self):
        return copy.deepcopy(self.committed)

    def violations(self, manifest, registry=None):
        original = golden.parse_registry
        if registry is not None:
            golden.parse_registry = lambda: registry
        try:
            found, _summary = golden.collect_violations(manifest, self.facts, self.packer)
        finally:
            golden.parse_registry = original
        return [violation.render() for violation in found]

    def assert_rejects(self, manifest, substring, registry=None):
        self.assertEqual(self.violations(self.manifest()), [])
        rendered = self.violations(manifest, registry)
        self.assertTrue(
            any(substring in violation for violation in rendered),
            f"{substring!r} not found in {rendered!r}",
        )

    def test_the_committed_manifest_passes_the_audit(self):
        self.assertEqual(self.violations(self.manifest()), [])

    def test_an_enabled_command_may_not_be_waived(self):
        manifest = self.manifest()
        manifest["commands"]["CertifyX509"] = {
            "code": 0x0000_0197,
            "status": "waived",
            "family": "certify-x509",
            "reason": "CC_CertifyX509 is CC_NO",
        }
        self.assert_rejects(
            manifest,
            "CertifyX509: waived, but the pinned profile does not set CC_CertifyX509 to CC_NO",
        )

    def test_a_profile_disabled_command_may_not_be_implemented(self):
        manifest = self.manifest()
        manifest["commands"]["SetCapability"]["status"] = "implemented"
        self.assert_rejects(
            manifest,
            "SetCapability: the pinned profile sets CC_SetCapability to CC_NO",
        )

    def test_a_profile_disabled_command_may_not_be_todo(self):
        manifest = self.manifest()
        entry = manifest["commands"]["FirmwareRead"]
        entry["status"] = "todo"
        entry.pop("reason", None)
        entry.pop("family", None)
        self.assert_rejects(
            manifest,
            "FirmwareRead: the pinned profile sets CC_FirmwareRead to CC_NO",
        )

    def test_a_waiver_reason_must_name_its_own_symbol(self):
        manifest = self.manifest()
        manifest["commands"]["AC_Send"]["reason"] = (
            "The pinned libtpms v0.10.2 profile sets CC_AC_GetCapability to CC_NO."
        )
        self.assert_rejects(manifest, "AC_Send: the waiver reason does not name CC_AC_Send")

    def test_a_waiver_reason_must_name_cc_no(self):
        manifest = self.manifest()
        manifest["commands"]["NV_ReadPublic2"]["reason"] = (
            "The pinned libtpms v0.10.2 profile leaves CC_NV_ReadPublic2 out."
        )
        self.assert_rejects(
            manifest, "NV_ReadPublic2: the waiver reason does not name CC_NO"
        )

    def test_a_waived_command_may_not_be_registered(self):
        registry = dict(golden.parse_registry())
        registry[0x0000_019F] = "SET_CAPABILITY"
        self.assert_rejects(
            self.manifest(),
            "SetCapability: waived, but 0x019f is registered as TPM_CC_SET_CAPABILITY",
            registry=registry,
        )

    def test_a_waived_command_still_needs_a_reason(self):
        manifest = self.manifest()
        manifest["commands"]["AC_GetCapability"].pop("reason")
        self.assert_rejects(manifest, "AC_GetCapability: waived without a reason")


if __name__ == "__main__":
    unittest.main()
