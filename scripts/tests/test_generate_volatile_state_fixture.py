"""Tests for scripts/generate_volatile_state_fixture.py."""

import importlib.util
import pathlib
import shutil
import tempfile
import unittest

_SCRIPTS_DIR = pathlib.Path(__file__).resolve().parents[1]
_REPO_ROOT = _SCRIPTS_DIR.parent
_REAL_NVMARSHAL = _REPO_ROOT / "libtpms" / "src" / "tpm2" / "NVMarshal.c"
_REAL_VOLATILE = _REPO_ROOT / "libtpms" / "src" / "tpm2" / "Volatile.c"

_spec = importlib.util.spec_from_file_location(
    "generate_volatile_state_fixture",
    _SCRIPTS_DIR / "generate_volatile_state_fixture.py",
)
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)

_HAVE_VENDORED_TREE = _REAL_NVMARSHAL.is_file() and _REAL_VOLATILE.is_file()

# One shared full build of the fixtures (both oracles, cross-validated);
# computed lazily so import stays cheap and the compile cost is paid at
# most once per test run.
_BUILD_CACHE = {}


def _cached_build():
    if "fixtures" not in _BUILD_CACHE:
        fixtures, listing = gen.build_fixtures()
        _BUILD_CACHE["fixtures"] = fixtures
        _BUILD_CACHE["listing"] = listing
    return _BUILD_CACHE["fixtures"], _BUILD_CACHE["listing"]


class ExtractDefinesTest(unittest.TestCase):
    def test_extracts_every_listed_define_verbatim(self):
        source = "\n".join(
            f"#define {name} 0x{index:x}" for index, name in enumerate(gen.DEFINE_NAMES)
        )
        extracted = gen.extract_defines(source)
        for index, name in enumerate(gen.DEFINE_NAMES):
            self.assertIn(f"#define {name} 0x{index:x}", extracted)

    def test_missing_define_is_an_error_naming_the_symbol(self):
        with self.assertRaises(SystemExit) as caught:
            gen.extract_defines("#define SOMETHING_ELSE 1\n")
        self.assertIn("#define DRBG_STATE_MAGIC not found", str(caught.exception))

    def test_similarly_named_defines_do_not_match(self):
        # PCR_MAGIC must not match PCR_SAVE_MAGIC (and vice versa).
        source = "#define PCR_SAVE_MAGIC 0x1\n#define PCR_SAVE_VERSION 2\n"
        with self.assertRaises(SystemExit) as caught:
            gen.extract_defines(source)
        self.assertIn("MAGIC", str(caught.exception))

    @unittest.skipUnless(_HAVE_VENDORED_TREE, "libtpms submodule not present")
    def test_vendored_nvmarshal_carries_every_define(self):
        extracted = gen.extract_defines(_REAL_NVMARSHAL.read_text())
        # Spot-check the pinned values the Rust decoder hardcodes.
        self.assertIn("#define VOLATILE_STATE_VERSION 4", extracted)
        self.assertIn("#define VOLATILE_STATE_MAGIC 0x45637889", extracted)
        self.assertIn("#define SESSION_SLOT_MAGIC 0x3664aebc", extracted)
        self.assertIn("#define PCR_MAGIC 0xe95f0387", extracted)


class MarshallerFragmentsTest(unittest.TestCase):
    @unittest.skipUnless(_HAVE_VENDORED_TREE, "libtpms submodule not present")
    def test_vendored_sources_carry_every_required_fragment(self):
        gen.require_marshaller_fragments(
            _REAL_NVMARSHAL.read_text(), _REAL_VOLATILE.read_text()
        )

    def test_missing_nvmarshal_fragment_is_an_error_naming_it(self):
        volatile = "\n".join(
            fragment for name, fragment in gen.MARSHALLER_FRAGMENTS
            if name == "Volatile.c"
        )
        with self.assertRaises(SystemExit) as caught:
            gen.require_marshaller_fragments("/* nothing */", volatile)
        self.assertIn("VolatileState_Marshal", str(caught.exception))
        self.assertIn("NVMarshal.c", str(caught.exception))

    def test_missing_volatile_fragment_is_an_error_naming_it(self):
        nvmarshal = "\n".join(
            fragment for name, fragment in gen.MARSHALLER_FRAGMENTS
            if name == "NVMarshal.c"
        )
        with self.assertRaises(SystemExit) as caught:
            gen.require_marshaller_fragments(nvmarshal, "/* nothing */")
        self.assertIn("VolatileState_Save", str(caught.exception))
        self.assertIn("Volatile.c", str(caught.exception))


class FixtureListTest(unittest.TestCase):
    def test_every_declared_fixture_is_checked_in(self):
        for name in gen.FIXTURES:
            self.assertTrue(
                (gen.TESTDATA / name).is_file(),
                f"{name} missing from {gen.TESTDATA}",
            )

    def test_synthetic_fixtures_are_labeled_as_such(self):
        # No genuine v1..v3 writer exists in the pinned implementation;
        # the historical-layout fixtures must say they are synthetic.
        for version in (1, 2, 3):
            self.assertIn(f"volatile_state_v{version}_synthetic.bin", gen.FIXTURES)
        # The current-version fixtures are authentic marshaller outputs.
        self.assertIn("volatile_state_v4.bin", gen.FIXTURES)
        self.assertIn("volatile_state_v4_future.bin", gen.FIXTURES)


@unittest.skipUnless(_HAVE_VENDORED_TREE, "libtpms submodule not present")
class BuildFixturesTest(unittest.TestCase):
    """Full-build tests: both oracles compile, run, and cross-validate."""

    def test_checked_in_fixtures_match_regeneration(self):
        fixtures, _listing = _cached_build()
        self.assertEqual(sorted(fixtures), sorted(gen.FIXTURES))
        for name, data in fixtures.items():
            self.assertEqual(
                (gen.TESTDATA / name).read_bytes(),
                data,
                f"{name} is stale; rerun the generator",
            )

    def test_generation_is_deterministic(self):
        first, _ = _cached_build()
        second, _ = gen.build_fixtures()
        self.assertEqual(first, second)

    def test_v4_fixture_carries_the_save_frame(self):
        # The last 20 bytes are the SHA-1 over every preceding byte,
        # exactly the VolatileState_Save frame.
        import hashlib

        fixtures, _ = _cached_build()
        for name in ("volatile_state_v4.bin", "volatile_state_v4_future.bin"):
            blob = fixtures[name]
            self.assertEqual(
                blob[-20:],
                hashlib.sha1(blob[:-20]).digest(),
                f"{name}: digest must cover every preceding byte",
            )
        # The future variant differs only by the six forward bytes (and
        # the digest they change).
        self.assertEqual(
            len(fixtures["volatile_state_v4_future.bin"]),
            len(fixtures["volatile_state_v4.bin"]) + 6,
        )

    def test_upstream_marshalling_change_is_detected(self):
        # Reordering two marshal calls inside the vendored
        # VolatileState_Marshal path must fail cross-validation rather
        # than be silently absorbed into new fixture bytes.
        source = _REAL_NVMARSHAL.read_text()
        lastsys = "    written += UINT64_Marshal(&s_lastSystemTime, buffer, size);\n"
        lastrep = "    written += UINT64_Marshal(&s_lastReportedTime, buffer, size);\n"
        self.assertIn(lastsys + lastrep, source)
        patched = source.replace(lastsys + lastrep, lastrep + lastsys)
        with tempfile.TemporaryDirectory() as tmp:
            patched_path = pathlib.Path(tmp) / "NVMarshal.c"
            patched_path.write_text(patched)
            with self.assertRaises(SystemExit) as caught:
                gen.build_fixtures(nvmarshal_path=patched_path)
        self.assertIn("diverged", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
