import importlib.util
import pathlib
import sys
import tempfile
import unittest

_SCRIPTS_DIR = pathlib.Path(__file__).resolve().parents[1]
_REPO_ROOT = _SCRIPTS_DIR.parent
_REAL_EXEC_COMMAND = _REPO_ROOT / "libtpms" / "src" / "tpm2" / "ExecCommand.c"

_spec = importlib.util.spec_from_file_location(
    "generate_failure_locations_fixture",
    _SCRIPTS_DIR / "generate_failure_locations_fixture.py",
)
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)

_HAVE_VENDORED_TREE = _REAL_EXEC_COMMAND.is_file()


def _run_main(argv):
    saved_argv = sys.argv
    sys.argv = ["generate_failure_locations_fixture.py", *argv]
    try:
        return gen.main()
    finally:
        sys.argv = saved_argv


@unittest.skipUnless(_HAVE_VENDORED_TREE, "libtpms submodule not initialized")
class BuildFixtureTest(unittest.TestCase):
    def test_the_committed_fixture_is_current(self):
        self.assertEqual(gen.FIXTURE.read_text(), gen.build_fixture())

    def test_every_mapped_function_is_pinned(self):
        body = [
            line
            for line in gen.build_fixture().splitlines()
            if line and not line.startswith("#")
        ]
        functions = {line.split("\t")[2] for line in body}
        self.assertEqual(functions, gen.FUNCTIONS)

    def test_records_are_sorted_and_tab_separated(self):
        body = [
            line
            for line in gen.build_fixture().splitlines()
            if line and not line.startswith("#")
        ]
        self.assertEqual(body, sorted(body))
        for line in body:
            fields = line.split("\t")
            self.assertEqual(len(fields), 4, line)
            int(fields[1])

    def test_check_succeeds_for_the_committed_fixture(self):
        self.assertEqual(_run_main(["--check"]), 0)

    def test_check_fails_for_stale_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            stale = pathlib.Path(tmp) / "failure_locations.txt"
            stale.write_text(gen.build_fixture() + "libtpms/x.c\t1\tGone\tFAIL(X)\n")
            saved = gen.FIXTURE
            gen.FIXTURE = stale
            try:
                self.assertEqual(_run_main(["--check"]), 1)
            finally:
                gen.FIXTURE = saved

    def test_check_fails_for_a_missing_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            saved = gen.FIXTURE
            gen.FIXTURE = pathlib.Path(tmp) / "absent.txt"
            try:
                self.assertEqual(_run_main(["--check"]), 1)
            finally:
                gen.FIXTURE = saved


if __name__ == "__main__":
    unittest.main()
