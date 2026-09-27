"""Unified schema: counting, aggregation, partial runs and backend comparison."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from validation import results as schema  # noqa: E402

KEY = {'image_id': 'sha256:img', 'harness_sha256': 'h', 'suites': ['s'], 'filter': '',
       'timeout': 1800}


def run_with(tests, backend='rust', *, key=KEY, phases=None, issues=None, state='finished'):
    run = schema.new_run('r', backend, {'comparison_key': dict(key)}, ['s'])
    suite = run['suites'][0]
    suite['state'] = state
    suite['phases'] = phases if phases is not None else [schema.phase_record('run', 'PASS')]
    suite['tests'] = tests
    suite['issues'] = issues or []
    run['state'] = 'finished'
    return run


def test(native, status, **kw):
    return schema.test_result('s', native, status, **kw)


class CountingTests(unittest.TestCase):
    def test_go_parent_rollup_is_not_counted_twice(self):
        run = schema.finalize_run(run_with([
            test('TestParms', 'FAIL', kind='group'),
            test('TestParms/a', 'PASS', parent='TestParms'),
            test('TestParms/b', 'FAIL', parent='TestParms')]))
        self.assertEqual(run['counts'], {'PASS': 1, 'FAIL': 1})
        self.assertEqual(run['status'], 'FAIL')

    def test_parent_failing_by_itself_stays_visible_once(self):
        run = schema.finalize_run(run_with([
            test('TestParms', 'FAIL', kind='group'),
            test('TestParms/a', 'PASS', parent='TestParms')]))
        self.assertEqual(run['counts'], {'PASS': 1, 'FAIL': 1})
        self.assertIn('outside its subtests', run['suites'][0]['tests'][0]['reason'])

    def test_fixtures_fail_the_suite_without_inflating_test_counts(self):
        run = schema.finalize_run(run_with([
            test('Test', 'FAIL', kind='group'),
            test('gocheck/a.TestX', 'PASS', parent='Test'),
            test('gocheck/a.TearDownTest#1', 'FAIL', parent='Test', kind='fixture')]))
        self.assertEqual(run['counts'], {'PASS': 1})
        self.assertEqual(run['fixture_counts'], {'FAIL': 1})
        self.assertEqual(run['status'], 'FAIL')

    def test_empty_result_is_never_success(self):
        run = schema.finalize_run(run_with([]))
        self.assertEqual(run['status'], 'ERROR')
        self.assertFalse(run['complete'])
        self.assertEqual(run['suites'][0]['issues'][0]['code'], 'no-tests')

    def test_error_issue_blocks_pass(self):
        run = schema.finalize_run(run_with([test('a', 'PASS')], issues=[
            schema.issue('exit-status', 'binary exited 0 despite failures')]))
        self.assertEqual(run['status'], 'ERROR')

    def test_skipped_and_not_run_are_unsuccessful(self):
        for status in ('SKIPPED', 'NOT_RUN'):
            with self.subTest(status=status):
                run = schema.finalize_run(run_with([test('a', 'PASS'), test('b', status)]))
                self.assertEqual(run['status'], status)
        self.assertFalse(schema.finalize_run(run_with([test('b', 'NOT_RUN')]))['complete'])

    def test_phase_termination_is_authoritative(self):
        for phase, expected in (('TIMEOUT', 'TIMEOUT'), ('INTERRUPTED', 'INTERRUPTED')):
            with self.subTest(phase=phase):
                run = schema.finalize_run(run_with(
                    [test('a', 'PASS')], phases=[schema.phase_record('run', phase)]))
                self.assertEqual(run['suites'][0]['status'], expected)
                self.assertFalse(run['complete'])

    def test_unfinished_runner_state_is_interpreted_on_load(self):
        run = run_with([test('a', 'PASS')], state='running')
        run['state'] = 'running'
        run['suites'].append(schema.new_suite('later'))
        loaded = schema.load_run(run)
        self.assertEqual([s['status'] for s in loaded['suites']], ['INTERRUPTED', 'NOT_RUN'])
        self.assertFalse(loaded['complete'])
        self.assertEqual(loaded['status'], 'INTERRUPTED')

    def test_prepare_only_is_not_a_validation(self):
        run = run_with([test('a', 'PASS')])
        run['metadata']['request'] = {'prepare_only': True}
        self.assertEqual(schema.finalize_run(run)['status'], 'NOT_RUN')

    def test_unknown_status_and_kind_are_rejected(self):
        with self.assertRaises(ValueError):
            schema.test_result('s', 'a', 'OK')
        with self.assertRaises(ValueError):
            schema.test_result('s', 'a', 'PASS', kind='suite')


class ComparisonTests(unittest.TestCase):
    def compare(self, ref_tests, rust_tests, **kw):
        return schema.compare_runs(run_with(ref_tests, 'reference', **kw.get('ref', {})),
                                   run_with(rust_tests, 'rust', **kw.get('rust', {})))

    def test_categories(self):
        comparison = self.compare(
            [test('both', 'PASS'), test('shared', 'FAIL'), test('regress', 'PASS'),
             test('improve', 'FAIL'), test('differ', 'FAIL'), test('only_ref', 'PASS')],
            [test('both', 'PASS'), test('shared', 'FAIL'), test('regress', 'FAIL'),
             test('improve', 'PASS'), test('differ', 'TIMEOUT'), test('only_rust', 'PASS')])
        ids = {c: [e['id'] for e in v] for c, v in comparison['tests'].items()}
        self.assertEqual(ids['both_pass'], ['s:both'])
        self.assertEqual(ids['shared_unsuccessful'], ['s:shared'])
        self.assertEqual(ids['regression'], ['s:regress'])
        self.assertEqual(ids['improvement'], ['s:improve'])
        self.assertEqual(ids['different_unsuccessful'], ['s:differ'])
        self.assertEqual(ids['missing_in_rust'], ['s:only_ref'])
        self.assertEqual(ids['missing_in_reference'], ['s:only_rust'])
        self.assertEqual(comparison['status'], 'INCOMPLETE')
        self.assertFalse(comparison['successful'])

    def test_matching_failures_are_equivalent_but_not_successful(self):
        comparison = self.compare([test('a', 'PASS'), test('b', 'FAIL')],
                                  [test('a', 'PASS'), test('b', 'FAIL')])
        self.assertEqual(comparison['status'], 'EQUIVALENT')
        self.assertFalse(comparison['successful'])
        self.assertIn('UNSUCCESSFUL', schema.render_comparison(comparison))

    def test_all_passing_equivalent_runs_are_successful(self):
        comparison = self.compare([test('a', 'PASS')], [test('a', 'PASS')])
        self.assertTrue(comparison['successful'])

    def test_incompatible_configuration_is_never_equivalent(self):
        other = dict(KEY, timeout=60)
        comparison = self.compare([test('a', 'PASS')], [test('a', 'PASS')],
                                  rust={'key': other})
        self.assertEqual(comparison['status'], 'INCOMPATIBLE')
        self.assertIn('timeout differs', comparison['compatibility_problems'][0])
        self.assertFalse(comparison['successful'])

    def test_incomplete_or_empty_runs_are_not_equivalent(self):
        comparison = self.compare([test('a', 'PASS')], [test('a', 'PASS')],
                                  rust={'phases': [schema.phase_record('run', 'TIMEOUT')]})
        self.assertEqual(comparison['status'], 'INCOMPLETE')
        self.assertEqual(self.compare([], [])['status'], 'INCOMPLETE')

    def test_same_status_with_different_diagnostics_is_reported(self):
        a = test('m', 'FAIL', details={'signature': {'exceptions': ['X: y']}})
        b = test('m', 'FAIL', details={'signature': {'exceptions': ['Z: w']}})
        comparison = self.compare([a], [b])
        self.assertEqual(comparison['status'], 'DIFFERENT')
        self.assertEqual(len(comparison['diagnostic_differences']), 1)

    def test_seeds_and_timings_are_not_diagnostic_differences(self):
        a = test('m', 'FAIL', duration=1.0, reason='seed 1',
                 details={'seeds': ['1'], 'signature': {'exceptions': ['X']}})
        b = test('m', 'FAIL', duration=9.0, reason='seed 2',
                 details={'seeds': ['2'], 'signature': {'exceptions': ['X']}})
        self.assertEqual(self.compare([a], [b])['status'], 'EQUIVALENT')

    def test_comparison_does_not_mutate_inputs(self):
        ref = run_with([test('a', 'PASS')], 'reference')
        before = copy.deepcopy(ref)
        schema.compare_runs(ref, run_with([test('a', 'PASS')]))
        self.assertEqual(ref, before)


if __name__ == '__main__':
    unittest.main()
