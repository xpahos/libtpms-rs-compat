import importlib.util
import pathlib
import unittest

_SCRIPTS_DIR = pathlib.Path(__file__).resolve().parents[1]
_ORACLE_DIR = _SCRIPTS_DIR / "get_test_result_oracle"

_spec = importlib.util.spec_from_file_location(
    "convert_output",
    _ORACLE_DIR / "convert_output.py",
)
conv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(conv)

_SAMPLE = [
    "GTR_OK: outer=0 resp=80010000001000000000000000000000\n",
    "restore: set_perm=0 set_vol=0 main_init=257\n",
    "patched_fail_blocks=1\n",
    "PERMALL_BEFORE_FAILURE=aa\n",
    "PERMALL_FAILURE_ENTRY=bb\n",
    "VOLATILE_FAILURE_ENTRY=cc\n",
    "PERMALL_AFTER_QUERIES=dd\n",
    "VOLATILE_AFTER_QUERIES=ee\n",
]


class ConvertTest(unittest.TestCase):
    def test_responses_and_kept_state_records_pass_through_in_order(self):
        self.assertEqual(
            conv.convert(_SAMPLE),
            "GTR_OK 80010000001000000000000000000000\n"
            "PERMALL_FAILURE_ENTRY bb\n"
            "VOLATILE_FAILURE_ENTRY cc\n"
            "PERMALL_AFTER_QUERIES dd\n"
            "VOLATILE_AFTER_QUERIES ee\n",
        )

    def test_a_nonzero_process_result_is_rejected(self):
        lines = ["GTR_OK: outer=9 resp=80010000000a00000101\n", *_SAMPLE[1:]]
        with self.assertRaises(SystemExit):
            conv.convert(lines)

    def test_an_unrecognized_line_is_rejected(self):
        with self.assertRaises(SystemExit):
            conv.convert([*_SAMPLE, "something unexpected\n"])

    def test_a_missing_state_record_is_rejected(self):
        with self.assertRaises(SystemExit):
            conv.convert(_SAMPLE[:5])

    def test_duplicate_names_are_rejected(self):
        with self.assertRaises(SystemExit):
            conv.convert([_SAMPLE[0], *_SAMPLE])

    def test_the_tracked_listing_round_trips_through_the_regex_shapes(self):
        listing = (_ORACLE_DIR / "vectors.txt").read_text()
        names = [line.split(" ", 1)[0] for line in listing.splitlines()]
        self.assertEqual(len(names), len(set(names)))
        for name in conv.KEPT_STATES:
            self.assertIn(name, names)


if __name__ == "__main__":
    unittest.main()
