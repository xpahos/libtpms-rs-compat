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
