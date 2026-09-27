import hashlib
import importlib.util
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

GOLDEN_PATH = Path(__file__).resolve().parent.parent / "golden_responses" / "golden.py"
spec = importlib.util.spec_from_file_location("golden", GOLDEN_PATH)
golden = importlib.util.module_from_spec(spec)
spec.loader.exec_module(golden)

class GoldenCompiledEntropyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = golden.load_manifest()
        cls.platform = cls.manifest["reference"]["docker_platform"]
        cls.tag, error = golden.resolve_image(cls.manifest)
        if error is not None:
            raise AssertionError(f'the capture image is required: {error}')
        cls.source = (golden.HERE / "entropy_shim.c").read_text()

    def compile_and_probe(self, source):
        directory = tempfile.mkdtemp(dir="/tmp", prefix="golden-shim-")
        try:
            Path(directory, "mutated.c").write_text(source)
            built = golden.docker_run_output(
                self.tag,
                self.platform,
                ["--entrypoint", "cc"],
                ["-shared", "-fPIC", "-O2", "-o", "/w/mutated.so", "/w/mutated.c"],
                mounts=((directory, "/w"),),
                allow_empty=True,
            )
            if built is None:
                self.fail("the mutated shim did not compile")
            facts = golden.collect_entropy_facts(
                self.manifest,
                self.tag,
                self.platform,
                "/w/mutated.so",
                mounts=((directory, "/w"),),
            )
            facts["image_checked"] = True
            return golden.validate_entropy_behavior(self.manifest, facts)
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    def assert_mutation_is_rejected(self, old, new):
        self.assertIn(old, self.source)
        violations = self.compile_and_probe(self.source.replace(old, new, 1))
        self.assertTrue(violations, f"mutating {old!r} was not detected")

    def test_unmutated_shim_satisfies_the_contract(self):
        self.assertEqual(self.compile_and_probe(self.source), [])

    def test_changed_shift_count_is_rejected(self):
        self.assert_mutation_is_rejected("mixed >> 30", "mixed >> 29")

    def test_changed_multiplier_is_rejected(self):
        self.assert_mutation_is_rejected(
            "UINT64_C(0xbf58476d1ce4e5b9)", "UINT64_C(0xbf58476d1ce4e5b7)"
        )

    def test_changed_state_increment_is_rejected(self):
        self.assert_mutation_is_rejected(
            "UINT64_C(0x9e3779b97f4a7c15)", "UINT64_C(0x9e3779b97f4a7c17)"
        )

    def test_changed_output_byte_order_is_rejected(self):
        self.assert_mutation_is_rejected(
            "buf[index] = (unsigned char)(word & 0xff);\n        word >>= 8;",
            "buf[index] = (unsigned char)((word >> 56) & 0xff);\n        word <<= 8;",
        )

    def test_changed_private_bytes_is_rejected(self):
        self.assert_mutation_is_rejected(
            "int RAND_priv_bytes(unsigned char *buf, int num)\n{\n    return RAND_bytes(buf, num);",
            "int RAND_priv_bytes(unsigned char *buf, int num)\n{\n    (void)buf;\n    (void)num;\n    return 1;",
        )

    def test_changed_seed_parsing_is_rejected(self):
        self.assert_mutation_is_rejected(
            'const char *seed_text = getenv("GOLDEN_ENTROPY_SEED");',
            'const char *seed_text = "00000000c0ffee01";',
        )


class GoldenCompiledClockTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = golden.load_manifest()
        cls.platform = cls.manifest["reference"]["docker_platform"]
        cls.tag, error = golden.resolve_image(cls.manifest)
        if error is not None:
            raise AssertionError(f"the capture image is required: {error}")
        cls.source = (golden.HERE / "entropy_shim.c").read_text()

    def probe(self, source):
        directory = tempfile.mkdtemp(dir="/tmp", prefix="golden-clock-")
        try:
            Path(directory, "mutated.c").write_text(source)
            built = golden.docker_run_output(
                self.tag,
                self.platform,
                ["--entrypoint", "cc"],
                ["-shared", "-fPIC", "-O2", "-o", "/w/mutated.so", "/w/mutated.c"],
                mounts=((directory, "/w"),),
                allow_empty=True,
            )
            if built is None:
                self.fail("the mutated shim did not compile")
            facts = golden.collect_clock_facts(
                self.manifest, self.tag, self.platform, "/w/mutated.so", ((directory, "/w"),)
            )
            facts["image_checked"] = True
            facts["docker_faketime"] = golden.parse_dockerfile(
                golden.DOCKERFILE.read_text("utf-8")
            )["docker_faketime"]
            return golden.validate_clock_behavior(self.manifest, facts)
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    def assert_mutation_is_rejected(self, old, new):
        self.assertIn(old, self.source)
        self.assertTrue(
            self.probe(self.source.replace(old, new, 1)),
            f"mutating {old!r} was not detected",
        )

    def test_unmutated_shim_satisfies_the_clock_contract(self):
        self.assertEqual(self.probe(self.source), [])

    def test_changed_monotonic_base_is_rejected(self):
        self.assert_mutation_is_rejected(
            "g_monotonic_nanoseconds = UINT64_C(1000000000000)",
            "g_monotonic_nanoseconds = UINT64_C(2000000000000)",
        )

    def test_changed_advance_multiplier_is_rejected(self):
        self.assert_mutation_is_rejected(
            "milliseconds * UINT64_C(1000000)", "milliseconds * UINT64_C(500000)"
        )

    def test_dropped_clock_id_is_rejected(self):
        self.assert_mutation_is_rejected(
            "|| clock_id == CLOCK_BOOTTIME", "|| clock_id == CLOCK_MONOTONIC"
        )

    def test_changed_seconds_field_is_rejected(self):
        self.assert_mutation_is_rejected(
            "result->tv_sec = (time_t)(now_nanoseconds / UINT64_C(1000000000));",
            "result->tv_sec = (time_t)(now_nanoseconds / UINT64_C(1000000000)) + 1;",
        )

    def test_changed_nanoseconds_field_is_rejected(self):
        self.assert_mutation_is_rejected(
            "result->tv_nsec = (long)(now_nanoseconds % UINT64_C(1000000000));",
            "result->tv_nsec = (long)(now_nanoseconds % UINT64_C(1000000000)) + 7;",
        )


class GoldenFreshContainerTest(unittest.TestCase):
    def test_two_fresh_containers_agree(self):
        manifest = golden.load_manifest()
        platform = manifest["reference"]["docker_platform"]
        tag, error = golden.resolve_image(manifest)
        self.assertIsNone(error)
        golden.VALIDATED_IMAGES.discard(tag)
        facts = golden.collect_reproducibility_facts(manifest, tag, platform)
        facts["image_checked"] = True
        facts["image_tag"] = tag
        self.assertIsInstance(facts["reproducibility"], list)
        self.assertEqual(golden.validate_reproducibility(manifest, facts), [])
        first, second = facts["reproducibility"]
        self.assertTrue(first.strip())
        self.assertEqual(first, second)


class GoldenImagePackageTest(unittest.TestCase):
    def test_pinned_versions_match_the_image(self):
        manifest = golden.load_manifest()
        tag, error = golden.resolve_image(manifest)
        self.assertIsNone(error)
        facts = golden.collect_facts(manifest)
        facts.update(golden.collect_image_facts(manifest, tag))
        self.assertEqual(golden.validate_image(manifest, facts), [])

    def test_wrong_installed_version_is_rejected(self):
        manifest = golden.load_manifest()
        tag, error = golden.resolve_image(manifest)
        self.assertIsNone(error)
        facts = golden.collect_facts(manifest)
        facts.update(golden.collect_image_facts(manifest, tag))
        facts["image_packages"]["python3"] = "9.9.9"
        violations = golden.validate_image(manifest, facts)
        self.assertTrue(any("python3" in violation.render() for violation in violations))


class GoldenCaseIsolationTest(unittest.TestCase):
    PARENT = (
        'profile {"Name":"default-v1"}\n'
        "send STARTUP 80010000000c000001440000\n"
        "snapshot READY\n"
    )

    def run_runner(self, text):
        manifest = golden.load_manifest()
        platform = manifest["reference"]["docker_platform"]
        tag, error = golden.resolve_image(manifest)
        self.assertIsNone(error)
        directory = tempfile.mkdtemp(dir="/tmp", prefix="golden-case-")
        try:
            Path(directory, "cases.scenario").write_text(text)
            command = ["run", "--rm"]
            if platform:
                command += ["--platform", platform]
            command += ["-v", f"{directory}:/w", tag, "/w/cases.scenario"]
            return golden.run_docker(command)
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    def run_scenario(self, text):
        outcome = self.run_runner(text)
        return outcome.stdout if outcome.ok else None

    def test_a_case_starts_in_a_fresh_process_and_the_parent_resumes(self):
        output = self.run_scenario(
            self.PARENT
            + "case isolated\n"
            + "get-state CASE_VOLATILE volatile\n"
            + "process CASE_GET_TEST_RESULT 80010000000a0000017c\n"
            + "callbacks CASE_CALLBACKS\n"
            + "end-case\n"
            + "send PARENT_GET_TEST_RESULT 80010000000a0000017c\n"
        )
        self.assertIsNotNone(output)
        records = dict(line.split() for line in output.splitlines())
        self.assertEqual(records["CASE_VOLATILE"], "0000080000")
        self.assertEqual(records["CASE_GET_TEST_RESULT"], "00000000")
        log = bytes.fromhex(records["CASE_CALLBACKS"])
        self.assertEqual(
            log[4:].decode("ascii").splitlines(),
            [
                "tpm_nvram_init -> 0x0",
                "tpm_nvram_loaddata(volatilestate) -> 0x800",
                "tpm_io_getlocality",
            ],
        )
        parent = bytes.fromhex(records["PARENT_GET_TEST_RESULT"])
        self.assertEqual((len(parent), parent[6:10]), (16, b"\x00\x00\x00\x00"))

    def test_a_failing_case_fails_the_capture(self):
        output = self.run_scenario(
            self.PARENT + "case broken\nnvram-put permall PERMALL_MISSING\nend-case\n"
        )
        self.assertIsNone(output)

    def test_blob_modifiers_apply_from_left_to_right(self):
        output = self.run_scenario(
            self.PARENT
            + "case edited\n"
            + "nvram-put volatilestate VOLATILE_READY@set=10:abcd@flip=12@sha1@drop=1\n"
            + "get-state CASE_INPUT volatile\n"
            + "end-case\n"
        )
        self.assertIsNotNone(output)
        records = dict(line.split() for line in output.splitlines())
        expected = bytearray.fromhex(records["VOLATILE_READY"])
        expected[10:12] = b"\xab\xcd"
        expected[12] ^= 0xFF
        expected[-20:] = hashlib.sha1(expected[:-20]).digest()
        del expected[-1]
        self.assertEqual(records["CASE_INPUT"], "0000000001" + expected.hex())

    def test_a_checkpoint_cannot_overwrite_a_recorded_snapshot(self):
        outcome = self.run_runner(
            'profile {"Name":"default-v1"}\n'
            "snapshot S\n"
            "send STARTUP 80010000000c000001440000\n"
            "checkpoint S\n"
            "case collision\n"
            "nvram-put volatilestate VOLATILE_S\n"
            "get-state CASE_INPUT volatile\n"
            "end-case\n"
        )
        self.assertEqual(outcome.status, "failed")
        self.assertIn("checkpoint S would overwrite the recorded snapshot S", outcome.stderr)
        self.assertNotIn("CASE_INPUT", outcome.stdout)

    def test_a_case_reads_the_recorded_snapshot_and_never_a_checkpoint(self):
        tail = (
            "send LATER_GET_TEST_RESULT 80010000000a0000017c\n"
            "checkpoint LATER\n"
            "case reads\n"
            "nvram-put volatilestate VOLATILE_{}\n"
            "get-state CASE_INPUT volatile\n"
            "end-case\n"
        )
        output = self.run_scenario(self.PARENT + tail.format("READY"))
        self.assertIsNotNone(output)
        records = dict(line.split() for line in output.splitlines())
        self.assertEqual(records["CASE_INPUT"], "0000000001" + records["VOLATILE_READY"])
        outcome = self.run_runner(self.PARENT + tail.format("LATER"))
        self.assertEqual(outcome.status, "failed")
        self.assertIn("no snapshot named 'LATER'", outcome.stderr)


class GoldenStaleMigrationTest(unittest.TestCase):
    FAMILY = "pcr-event"

    def isolated_repository(self):
        self.pinned_tag = golden.image_tag(golden.image_identity(golden.load_manifest()))
        directory = tempfile.mkdtemp(dir="/tmp", prefix="golden-repo-")
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        root = Path(directory)
        for tree in (
            "scripts",
            golden.READER_DIR.rstrip("/"),
            golden.FIXTURE_DIR.rstrip("/"),
        ):
            (root / tree).parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(
                golden.ROOT / tree,
                root / tree,
                ignore=shutil.ignore_patterns("__pycache__"),
            )
        for path in ("src/library/tpm2/command/core/registry.rs", "src/version.rs", "Makefile"):
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(golden.ROOT / path, root / path)
        (root / "libtpms").symlink_to(golden.ROOT / "libtpms")
        for arguments in (["init", "-q"], ["add", "-A"]):
            subprocess.run(["git", *arguments], cwd=root, check=True, capture_output=True)
        original = golden.ROOT
        golden.ROOT = root
        self.addCleanup(setattr, golden, "ROOT", original)
        return root

    def fixtures(self, root, manifest):
        return {
            family: (root / entry["fixture"]).read_bytes()
            for family, entry in manifest["families"].items()
            if (root / entry["fixture"]).is_file()
        }

    def test_update_regenerates_exactly_one_stale_fixture(self):
        manifest = golden.load_manifest()
        root = self.isolated_repository()
        before = self.fixtures(root, manifest)
        self.assertEqual(len(before), len(manifest["families"]))

        target = root / manifest["families"][self.FAMILY]["fixture"]
        target.unlink()
        self.assertEqual(golden.stale_fixture_families(manifest), {self.FAMILY})

        expected_tag = golden.image_tag(golden.image_identity(manifest))
        arguments = golden.build_parser().parse_args(["update", self.FAMILY])
        self.assertEqual(golden.update(arguments), 0)
        self.assertEqual(expected_tag, self.pinned_tag)

        after = self.fixtures(root, manifest)
        self.assertEqual(after, before)
        self.assertEqual(golden.stale_fixture_families(manifest), set())
        self.assertEqual(
            [path.name for path in target.parent.iterdir() if not path.name.endswith(".bin")],
            [],
        )

    def test_a_second_update_changes_nothing(self):
        manifest = golden.load_manifest()
        root = self.isolated_repository()
        arguments = golden.build_parser().parse_args(["update", self.FAMILY])
        self.assertEqual(golden.update(arguments), 0)
        before = self.fixtures(root, manifest)
        self.assertEqual(golden.update(arguments), 0)
        self.assertEqual(self.fixtures(root, manifest), before)


if __name__ == "__main__":
    unittest.main()
