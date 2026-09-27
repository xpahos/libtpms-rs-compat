"""Automake selection, .trs/.log normalization and tpm2-tools transport evidence."""
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from validation import results as schema  # noqa: E402
from validation.adapters import automake  # noqa: E402
from validation.adapters.base import RunContext  # noqa: E402
from validation.environment import Phase, StepFailed  # noqa: E402

FIXTURES = ROOT / 'tests' / 'fixtures' / 'automake'
PASS = ':test-result: PASS example\n:global-test-result: PASS\n'
STARTED = 'creating simulator working dir: /tmp/tpm2_test_x\nStarting the simulator\n'
TABRMD = (STARTED + 'Starting tpm2-abrmd\n'
          'export TPM2TOOLS_TCTI="tabrmd:bus_type=session,bus_name=com.intel.tss2.Tabrmd42"\n')


class Fixture(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.build = self.root / 'build'
        self.run_root = self.root / 'run'
        self.suite_dir = self.run_root / 'rust' / 'suite'
        self.build.mkdir()
        self.suite_dir.mkdir(parents=True)

    def phase(self):
        return Phase(root=ROOT, cache=self.root, log=self.suite_dir / 'run.log', timeout=60,
                     jobs=1)

    def context(self, selected, termination='completed', exit_code=0):
        (self.suite_dir / 'selected.txt').write_text('\n'.join(selected) + '\n')
        return RunContext(phase=None, suite_dir=self.suite_dir, run_root=self.run_root,
                          library='/lib.so', backend='rust', started=time.time() - 5,
                          execution={'exit_code': exit_code, 'termination': termination},
                          termination=termination)

    def write(self, test, trs=None, log=None, age=0):
        base = self.build / Path(test).with_suffix('')
        base.parent.mkdir(parents=True, exist_ok=True)
        for suffix, content in (('.trs', trs), ('.log', log)):
            if content is not None:
                path = base.with_suffix(suffix)
                path.write_text(content)
                os.utime(path, (time.time() - age, time.time() - age))

    def collect(self, ctx, name='suite', required_tcti=None):
        suite = schema.new_suite(name)
        suite['state'] = 'finished'
        suite['phases'] = [schema.phase_record('run', 'PASS')]
        automake.collect(suite, ctx, build_dir=self.build, required_tcti=required_tcti)
        return suite


class SelectionTests(Fixture):
    def setUp(self):
        super().setUp()
        (self.build / 'Makefile').write_text(
            'TESTS_INTEGRATION = test/integration/sys-get-random.int '
            'test/integration/esys-nv.int\nDUPLICATED = test/a.sh test/a.sh\n'
            'all:\n\t@true\n')

    def test_selection_matches_basenames_and_clears_only_selected_evidence(self):
        self.write('test/integration/sys-get-random.int', 'old', 'old')
        simulator = self.build / 'test/integration/sys-get-random.int_simulator.log'
        simulator.write_text('old')
        self.write('test/integration/esys-nv.int', 'keep', 'keep')
        tests = automake.select(self.phase(), self.build, 'TESTS_INTEGRATION',
                                '^sys-get-random', self.suite_dir)
        self.assertEqual(tests, ['test/integration/sys-get-random.int'])
        self.assertEqual((self.suite_dir / 'selected.txt').read_text(),
                         'test/integration/sys-get-random.int\n')
        self.assertFalse((self.build / 'test/integration/sys-get-random.trs').exists())
        self.assertFalse(simulator.exists())
        self.assertTrue((self.build / 'test/integration/esys-nv.trs').exists())
        self.assertEqual(len((self.suite_dir / 'candidates.txt').read_text().split()), 2)

    def test_empty_invalid_and_duplicate_selections_are_rejected(self):
        for variable, expression, message in (
                ('TESTS_INTEGRATION', 'does-not-exist', 'selected no upstream tests'),
                ('TESTS_INTEGRATION', '[', 'invalid --filter'),
                ('UNDEFINED', '', 'lists no upstream tests'),
                ('DUPLICATED', '', 'duplicates')):
            with self.subTest(variable=variable, expression=expression):
                with self.assertRaisesRegex(StepFailed, message):
                    automake.select(self.phase(), self.build, variable, expression,
                                    self.suite_dir)


class RealEvidenceTests(Fixture):
    def test_tpm2_tss_pass_and_skip(self):
        shutil.copytree(FIXTURES / 'tpm2-tss', self.build, dirs_exist_ok=True)
        for path in self.build.rglob('*'):
            os.utime(path)   # fresh for this run
        suite = self.collect(self.context(['test/integration/sys-hmac.int',
                                           'test/integration/esys-act-set-timeout.int']),
                             'tpm2-tss')
        schema.finalize_suite(suite)
        statuses = {t['name']: (t['status'], t['native_status']) for t in suite['tests']}
        self.assertEqual(statuses, {'sys-hmac.int': ('PASS', 'PASS'),
                                    'esys-act-set-timeout.int': ('SKIPPED', 'SKIP')})
        skipped = suite['tests'][1]
        self.assertTrue(skipped['reason'])
        self.assertTrue((self.run_root / skipped['artifacts']['report']).exists())
        self.assertTrue((self.run_root / skipped['artifacts']['log']).exists())
        self.assertEqual(suite['native_counts'], {'PASS': 1, 'SKIP': 1})
        self.assertEqual(suite['status'], 'SKIPPED')

    def test_tpm2_tools_transport_from_upstream_helpers(self):
        shutil.copytree(FIXTURES / 'tpm2-tools', self.build, dirs_exist_ok=True)
        for path in self.build.rglob('*'):
            os.utime(path)
        suite = self.collect(self.context(['test/integration/tests/getrandom.sh',
                                           'test/integration/tests/X509certutil.sh']),
                             'tpm2-tools', required_tcti='tabrmd')
        schema.finalize_suite(suite)
        self.assertEqual({t['name']: t['details']['transport'] for t in suite['tests']},
                         {'getrandom.sh': 'tabrmd', 'X509certutil.sh': 'none'})
        self.assertEqual(suite['status'], 'PASS')


class NormalizationTests(Fixture):
    TEST = 'test/integration/example.int'

    def one(self, trs=None, log='upstream output\n', termination='completed', exit_code=0,
            age=0, required_tcti=None):
        self.write(self.TEST, trs, log, age)
        suite = self.collect(self.context([self.TEST], termination, exit_code),
                             required_tcti=required_tcti)
        schema.finalize_suite(suite)
        return suite, suite['tests'][0]

    def test_statuses(self):
        for trs, expected in ((PASS, 'PASS'),
                              (':test-result: SKIP x\n:global-test-result: SKIP\n', 'SKIPPED'),
                              (':test-result: FAIL x\n:global-test-result: FAIL\n', 'FAIL'),
                              (':test-result: XFAIL x\n:global-test-result: XFAIL\n', 'FAIL'),
                              (':test-result: ERROR x\n:global-test-result: ERROR\n', 'ERROR'),
                              (':global-test-result: PASS\n', 'ERROR')):
            with self.subTest(trs=trs):
                self.setUp()
                self.assertEqual(self.one(trs)[1]['status'], expected)

    def test_malformed_stale_and_missing_results(self):
        for kwargs, reason in (
                (dict(trs=PASS + ':global-test-result: PASS\n'), 'malformed'),
                (dict(trs=':test-result: MAYBE x\n:global-test-result: PASS\n'), 'malformed'),
                (dict(trs=PASS, age=3600), 'stale'),
                (dict(trs=None), 'no .trs')):
            with self.subTest(kwargs=kwargs):
                self.setUp()
                suite, test = self.one(**kwargs)
                self.assertEqual(test['status'], 'ERROR')
                self.assertIn(reason, test['reason'])
                self.assertEqual(suite['status'], 'ERROR')

    def test_timeout_and_interruption_keep_partial_evidence(self):
        for termination, log, expected in (('timeout', 'running\n', 'TIMEOUT'),
                                           ('interrupted', 'running\n', 'INTERRUPTED'),
                                           ('timeout', None, 'NOT_RUN')):
            with self.subTest(termination=termination, log=log):
                self.setUp()
                _, test = self.one(None, log, termination=termination)
                self.assertEqual(test['status'], expected)

    def test_make_failure_cannot_hide_behind_passing_tests(self):
        suite, test = self.one(PASS, exit_code=2)
        self.assertEqual(test['status'], 'PASS')
        self.assertEqual(suite['status'], 'ERROR')
        self.assertEqual(suite['issues'][0]['code'], 'make-check')

    def test_tools_transport_bypass_is_an_error(self):
        for log, transport in ((STARTED + 'not starting abrmd\n'
                                'export TPM2TOOLS_TCTI="mssim:host=localhost,port=4242"\n',
                                'direct'),
                               (TABRMD + 'export TPM2TOOLS_TCTI="mssim:port=4242"\n', 'direct'),
                               (STARTED + 'Starting tpm2-abrmd\n', 'startup-failed')):
            with self.subTest(log=log):
                self.setUp()
                suite, test = self.one(PASS, log, required_tcti='tabrmd')
                self.assertEqual(test['details']['transport'], transport)
                self.assertEqual(test['status'], 'ERROR')
                self.assertIn('not run through the tabrmd', test['reason'])

    def test_no_transport_requirement_for_tpm2_tss(self):
        _, test = self.one(PASS, 'not starting abrmd\n')
        self.assertNotIn('transport', test['details'])
        self.assertEqual(test['status'], 'PASS')

    def test_missing_selection_is_incomplete(self):
        suite = schema.new_suite('suite')
        suite['state'] = 'finished'
        ctx = self.context([])
        (self.suite_dir / 'selected.txt').unlink()
        ctx.error = 'preflight failed'
        automake.collect(suite, ctx, build_dir=self.build)
        schema.finalize_suite(suite)
        self.assertEqual(suite['issues'][0]['message'], 'preflight failed')
        self.assertFalse(suite['complete'])
        self.assertEqual(suite['status'], 'ERROR')


if __name__ == '__main__':
    unittest.main()
