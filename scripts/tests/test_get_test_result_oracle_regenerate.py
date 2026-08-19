import importlib.util
import pathlib
import tempfile
import unittest

_SCRIPTS_DIR = pathlib.Path(__file__).resolve().parents[1]
_ORACLE_DIR = _SCRIPTS_DIR / "get_test_result_oracle"

_spec = importlib.util.spec_from_file_location(
    "regenerate",
    _ORACLE_DIR / "regenerate.py",
)
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)


def _mutate_last_hex_byte(payload):
    flipped = format(int(payload[-2:], 16) ^ 0x01, "02x")
    return payload[:-2] + flipped


class CompareListingsTest(unittest.TestCase):
    def setUp(self):
        self.tracked = gen.parse_listing(gen.LISTING)

    def test_the_tracked_listing_compares_equal_to_itself(self):
        self.assertEqual(gen.compare_listings(dict(self.tracked), self.tracked), [])

    def test_a_mutated_state_record_byte_is_rejected(self):
        for name in [
            "PERMALL_FAILURE_ENTRY",
            "VOLATILE_FAILURE_ENTRY",
            "PERMALL_AFTER_QUERIES",
            "VOLATILE_AFTER_QUERIES",
        ]:
            fresh = dict(self.tracked)
            fresh[name] = _mutate_last_hex_byte(fresh[name])
            errors = gen.compare_listings(fresh, self.tracked)
            self.assertEqual(len(errors), 1, name)
            self.assertIn(name, errors[0])

    def test_a_mutated_diagnostic_byte_inside_the_volatile_record_is_rejected(self):
        fresh = dict(self.tracked)
        payload = fresh["VOLATILE_FAILURE_ENTRY"]
        fail12 = self.tracked["FM_GTR_OK"][24:48]
        marker = "01000c" + fail12
        at = payload.index(marker) + len("01000c")
        mutated = payload[:at] + _mutate_last_hex_byte(payload[at : at + 8]) + payload[at + 8 :]
        fresh["VOLATILE_FAILURE_ENTRY"] = mutated
        errors = gen.compare_listings(fresh, self.tracked)
        self.assertEqual(len(errors), 1)
        self.assertIn("VOLATILE_FAILURE_ENTRY", errors[0])

    def test_a_mutated_response_record_is_rejected(self):
        fresh = dict(self.tracked)
        fresh["FM_GTR_OK"] = _mutate_last_hex_byte(fresh["FM_GTR_OK"])
        errors = gen.compare_listings(fresh, self.tracked)
        self.assertEqual(len(errors), 1)
        self.assertIn("FM_GTR_OK", errors[0])

    def test_record_name_drift_is_rejected(self):
        fresh = dict(self.tracked)
        payload = fresh.pop("GTR_OK")
        fresh["GTR_RENAMED"] = payload
        errors = gen.compare_listings(fresh, self.tracked)
        self.assertEqual(len(errors), 2)


class VerifyArtifactsTest(unittest.TestCase):
    def test_the_committed_artifacts_are_consistent(self):
        self.assertEqual(gen.verify_artifacts(), 0)

    def test_the_digest_table_matches_the_tracked_listing(self):
        self.assertEqual(
            gen.DIGESTS.read_text(),
            gen.digest_table(gen.parse_listing(gen.LISTING)),
        )

    def test_a_stale_digest_table_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            stale = pathlib.Path(tmp) / "digests.txt"
            stale.write_text(gen.DIGESTS.read_text() + "EXTRA 1 00\n")
            saved = gen.DIGESTS
            gen.DIGESTS = stale
            try:
                self.assertEqual(gen.verify_artifacts(), 1)
            finally:
                gen.DIGESTS = saved

    def test_a_missing_digest_table_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            saved = gen.DIGESTS
            gen.DIGESTS = pathlib.Path(tmp) / "absent.txt"
            try:
                self.assertEqual(gen.verify_artifacts(), 1)
            finally:
                gen.DIGESTS = saved

    def test_a_stale_listing_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            tracked = gen.parse_listing(gen.LISTING)
            tracked["GTR_OK"] = _mutate_last_hex_byte(tracked["GTR_OK"])
            stale = pathlib.Path(tmp) / "vectors.txt"
            stale.write_text(
                "".join(f"{name} {payload}\n" for name, payload in tracked.items())
            )
            saved_listing, saved_digests = gen.LISTING, gen.DIGESTS
            digests = pathlib.Path(tmp) / "digests.txt"
            digests.write_text(gen.digest_table(tracked))
            gen.LISTING, gen.DIGESTS = stale, digests
            try:
                self.assertEqual(gen.verify_artifacts(), 1)
            finally:
                gen.LISTING, gen.DIGESTS = saved_listing, saved_digests


if __name__ == "__main__":
    unittest.main()
