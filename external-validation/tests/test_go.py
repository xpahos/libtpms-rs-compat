"""Go test2json and gocheck collectors, on saved real upstream logs and fixtures."""
import gzip
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from validation import results as schema  # noqa: E402
from validation.collectors import gocheck, gotest  # noqa: E402

FIXTURES = ROOT / 'tests' / 'fixtures' / 'go'


def suite_for(name='go'):
    suite = schema.new_suite(name)
    suite['state'] = 'finished'
    suite['phases'] = [schema.phase_record('run', 'PASS')]
    return suite


def events_text(*events):
    return ''.join(json.dumps(e) + '\n' for e in events)


def run_events(name, *statuses, package='pass'):
    """Minimal event stream: `statuses` is [(test, action or None, outputs)]."""
    events = []
    for test, action, outputs in statuses:
        events.append({'Action': 'run', 'Test': test})
        events += [{'Action': 'output', 'Test': test, 'Output': o} for o in outputs]
        if action:
            events.append({'Action': action, 'Test': test, 'Elapsed': 0.01})
    if package:
        events.append({'Action': package, 'Elapsed': 1.0})
    return events_text(*events)


def collect(text, termination='completed', exit_code=0, name='go'):
    suite = suite_for(name)
    events, malformed = gotest.parse_events(text)
    tests, _ = gotest.collect(suite, events, termination=termination, exit_code=exit_code)
    return suite, tests, malformed


class RealLogTests(unittest.TestCase):
    """Saved verbose output from the pinned upstream suites (Rust backend)."""

    @classmethod
    def convert(cls, name):
        raw = gzip.open(FIXTURES / f'{name}.verbose.log.gz').read()
        with tempfile.TemporaryDirectory() as cache:
            env = dict(os.environ, GOCACHE=cache)
            return subprocess.run(['go', 'tool', 'test2json', '-t', '-p', name], input=raw,
                                  capture_output=True, check=True, env=env).stdout.decode()

    def test_google_parent_rollups_and_subtest_failure(self):
        suite, tests, malformed = collect(self.convert('google-go-tpm'), exit_code=1,
                                          name='google-go-tpm')
        schema.finalize_suite(suite)
        self.assertEqual(malformed, [])
        self.assertEqual(suite['issues'], [])
        self.assertEqual(suite['counts'], {'PASS': 273, 'FAIL': 1})
        groups = [t for t in suite['tests'] if t['kind'] == 'group']
        self.assertEqual(len(groups), 33)
        # 307 native results: 33 rollups + 274 leaves, none counted twice.
        self.assertEqual(len(suite['tests']), 307)
        failed = [t for t in suite['tests'] if t['status'] == 'FAIL']
        self.assertEqual({t['name'] for t in failed},
                         {'TestTestParms', 'TestTestParms/rsa3072_-_unsupported'})
        parent = next(t for t in failed if t['name'] == 'TestTestParms')
        self.assertFalse(parent['counted'])
        self.assertEqual(suite['status'], 'FAIL')

    def test_canonical_gocheck_reconciles_with_native_totals(self):
        suite, tests, _ = collect(self.convert('canonical-go-tpm2'), exit_code=1,
                                  name='canonical-go-tpm2')
        record = next(t for t in suite['tests'] if t['name'] == 'Test')
        record['kind'], record['counted'] = 'group', False
        gocheck.collect(suite, ''.join(tests['Test']['output']), parent='Test',
                        termination='completed')
        schema.finalize_suite(suite)
        self.assertEqual(suite['issues'], [])   # no totals mismatch
        self.assertEqual(suite['native_counts']['gocheck'],
                         {'passed': 579, 'failed': 7, 'missed': 7})
        cases = [t for t in suite['tests'] if t['id'].startswith('canonical-go-tpm2:gocheck/')]
        by_status = {}
        for case in cases:
            by_status.setdefault((case['kind'], case['status']), []).append(case['name'])
        self.assertEqual(len(by_status[('test', 'PASS')]), 579)
        self.assertEqual(len(by_status[('test', 'FAIL')]), 5)
        self.assertEqual(sorted(by_status[('fixture', 'FAIL')]),
                         ['pcrSuite.TearDownTest', 'startupSuite.TearDownTest'])
        self.assertEqual(sorted(by_status[('test', 'ERROR')]),
                         ['pcrSuite.TestPCRAllocation1', 'startupSuite.TestReset'])
        self.assertEqual(len(by_status[('test', 'NOT_RUN')]), 5)
        # The wrapper is neither counted nor treated as an unexplained failure.
        self.assertFalse(record['counted'])
        self.assertEqual(suite['fixture_counts'], {'FAIL': 2})
        self.assertEqual(suite['counts']['NOT_RUN'], 5)
        go_fail = [t['name'] for t in suite['tests'] if t['status'] == 'FAIL'
                   and t['counted'] and '/' not in t['id'].split(':', 1)[1]
                   and not t['id'].split(':', 1)[1].startswith('gocheck/')]
        self.assertEqual(go_fail, ['TestPCRRead'])
        self.assertFalse(suite['complete'])   # MISS: gocheck did not run 5 cases
        self.assertEqual(suite['status'], 'ERROR')


class EventTests(unittest.TestCase):
    def test_parent_and_children_are_not_double_counted(self):
        suite, *_ = collect(run_events('x', ('TestA/one', 'pass', []),
                                       ('TestA/two', 'skip', ['    a_test.go:9: no ECC\n']),
                                       ('TestA', 'pass', [])))
        schema.finalize_suite(suite)
        self.assertEqual(suite['counts'], {'PASS': 1, 'SKIPPED': 1})
        skipped = next(t for t in suite['tests'] if t['status'] == 'SKIPPED')
        self.assertEqual(skipped['parent_id'], 'go:TestA')
        self.assertEqual(skipped['reason'], 'a_test.go:9: no ECC')
        self.assertEqual(suite['status'], 'SKIPPED')

    def test_no_tests_to_run_is_incomplete(self):
        for output in ('testing: warning: no tests to run\n', 'ok x 0.1s [no tests to run]\n'):
            with self.subTest(output=output):
                text = events_text({'Action': 'output', 'Output': output},
                                   {'Action': 'pass', 'Elapsed': 0})
                suite, *_ = collect(text)
                schema.finalize_suite(suite)
                self.assertEqual(suite['status'], 'ERROR')
                self.assertFalse(suite['complete'])

    def test_malformed_duplicate_and_truncated_streams(self):
        suite, _, malformed = collect(run_events('x', ('TestA', 'pass', [])) + 'garbage\n')
        self.assertEqual(len(malformed), 1)
        text = events_text({'Action': 'run', 'Test': 'TestA'}, {'Action': 'pass', 'Test': 'TestA'},
                           {'Action': 'run', 'Test': 'TestA'}, {'Action': 'pass', 'Test': 'TestA'},
                           {'Action': 'pass'})
        suite, *_ = collect(text)
        self.assertIn('duplicate', [i['code'] for i in suite['issues']])
        suite, *_ = collect(run_events('x', ('TestA', 'pass', []), package=None))
        schema.finalize_suite(suite)
        self.assertIn('truncated', [i['code'] for i in suite['issues']])
        self.assertEqual(suite['status'], 'ERROR')

    def test_unfinished_test_after_timeout_or_crash(self):
        for termination, expected in (('timeout', 'TIMEOUT'), ('interrupted', 'INTERRUPTED'),
                                      ('completed', 'ERROR')):
            with self.subTest(termination=termination):
                suite, *_ = collect(run_events('x', ('TestA', 'pass', []), ('TestB', None, []),
                                               package=None), termination=termination,
                                    exit_code=2)
                statuses = {t['name']: t['status'] for t in suite['tests']}
                self.assertEqual(statuses, {'TestA': 'PASS', 'TestB': expected})

    def test_package_failure_outside_tests_and_exit_status(self):
        suite, *_ = collect(run_events('x', ('TestA', 'pass', []), package='fail'), exit_code=1)
        self.assertIn('package', [i['code'] for i in suite['issues']])
        suite, *_ = collect(run_events('x', ('TestA', 'fail', []), package='fail'), exit_code=0)
        self.assertIn('exit-status', [i['code'] for i in suite['issues']])


class GocheckTests(unittest.TestCase):
    def collect(self, text, termination='completed'):
        suite = suite_for('canonical')
        gocheck.collect(suite, text, parent='Test', termination=termination)
        return suite

    def test_empty_wrapper_and_missing_summary(self):
        suite = self.collect('OK: 0 passed\n')
        self.assertIn('no-tests', [i['code'] for i in suite['issues']])
        suite = self.collect('PASS: a_test.go:1: s.TestA\t0.1s\n')
        self.assertIn('gocheck', [i['code'] for i in suite['issues']])

    def test_skip_expected_failure_and_totals(self):
        suite = self.collect('PASS: a.go:1: s.TestA\t0.1s\nSKIP: a.go:2: s.TestB (no ECC)\n'
                             'FAIL EXPECTED: a.go:3: s.TestC\t0.1s\n'
                             'OK: 1 passed, 1 skipped, 1 expected failures\n')
        self.assertEqual(suite['issues'], [])
        statuses = {t['name']: (t['status'], t['reason']) for t in suite['tests']}
        self.assertEqual(statuses['s.TestB'], ('SKIPPED', 'no ECC'))
        self.assertEqual(statuses['s.TestC'][0], 'PASS')

    def test_totals_mismatch_and_duplicates_are_rejected(self):
        suite = self.collect('PASS: a.go:1: s.TestA\t0.1s\nOK: 2 passed\n')
        self.assertIn('gocheck-totals', [i['code'] for i in suite['issues']])
        suite = self.collect('PASS: a.go:1: s.TestA\t0.1s\nPASS: a.go:1: s.TestA\t0.1s\n'
                             'OK: 2 passed\n')
        self.assertIn('duplicate', [i['code'] for i in suite['issues']])

    def test_true_panic_is_a_failure(self):
        suite = self.collect('-' * 70 + '\nPANIC: a.go:1: s.TestA\n\n... Panic: boom\n'
                             + '-' * 70 + '\nOOPS: 0 passed, 1 PANICKED\n')
        self.assertEqual(suite['issues'], [])
        self.assertEqual(suite['tests'][0]['status'], 'FAIL')


if __name__ == '__main__':
    unittest.main()
