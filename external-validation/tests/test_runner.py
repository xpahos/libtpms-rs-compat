"""Container runner: backend sequencing, isolation, timeouts, interruption, persistence.

Adapters and library builds are controlled fakes (tests/runner_hooks.py) that
run real child processes through the real phase/process supervision.
"""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from validation import results as schema  # noqa: E402


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    stat = Path(f'/proc/{pid}/stat')
    return stat.exists() and stat.read_text().rsplit(')', 1)[1].split()[0] != 'Z'


class RunnerFixture(unittest.TestCase):
    SUITES = ['tpm2-tss', 'google-go-tpm']

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.work = self.root / 'work'
        self.events = self.root / 'events'
        self.events.touch()
        self.run_id = 'test-run'
        self.run_dir = self.work / 'results' / self.run_id
        self.run_dir.mkdir(parents=True)

    def request(self, **overrides):
        request = {'run_id': self.run_id, 'backend': 'both', 'suites': self.SUITES,
                   'filter': '', 'timeout': 30, 'microsoft_test_timeout': 120, 'jobs': 1,
                   'prepare_only': False, 'image_id': 'sha256:fake', 'root': str(ROOT),
                   'work': str(self.work), 'repo': str(self.root), 'record_tools': False}
        request.update(overrides)
        path = self.run_dir / 'request.json'
        path.write_text(json.dumps(request))
        return path

    def plan(self, **plan):
        (self.root / 'plan.json').write_text(json.dumps(plan))

    def command(self, **overrides):
        return [sys.executable, '-m', 'validation.runner', '--request',
                str(self.request(**overrides)), '--hooks', 'tests.runner_hooks']

    def env(self):
        return dict(os.environ, PYTHONPATH=str(ROOT), FAKE_PLAN=str(self.root / 'plan.json'),
                    FAKE_EVENTS=str(self.events), PYTHONDONTWRITEBYTECODE='1')

    def run_runner(self, **overrides):
        return subprocess.run(self.command(**overrides), cwd=ROOT, env=self.env(),
                              capture_output=True, text=True, timeout=120)

    def results(self, backend):
        return schema.load_run(json.loads((self.run_dir / backend / 'results.json').read_text()))

    def suite(self, backend, name):
        return next(s for s in self.results(backend)['suites'] if s['name'] == name)

    def lines(self, kind):
        return [l.split() for l in self.events.read_text().splitlines() if l.startswith(kind + ' ')]

    def assert_all_dead(self):
        for kind in ('child', 'grandchild', 'daemon'):
            for words in self.lines(kind):
                deadline = time.monotonic() + 5
                while alive(int(words[1])) and time.monotonic() < deadline:
                    time.sleep(.05)
                self.assertFalse(alive(int(words[1])), f'{kind} {words[1]} survived')


class BackendTests(RunnerFixture):
    def test_both_backends_pass_with_equivalent_configuration_and_isolated_state(self):
        self.plan()
        result = self.run_runner()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # Shared preparation happens once; each backend then runs every suite.
        self.assertEqual([w[1] for w in self.lines('prepare')], self.SUITES)
        runs = self.lines('run')
        self.assertEqual([(w[1], w[2]) for w in runs],
                         [('reference', 'tpm2-tss'), ('reference', 'google-go-tpm'),
                          ('rust', 'tpm2-tss'), ('rust', 'google-go-tpm')])
        self.assertEqual({w[5] for w in runs}, {'fresh-state'})
        self.assertEqual(len({w[4] for w in runs}), 4)          # separate result dirs
        self.assertEqual(len({w[3] for w in runs}), 2)          # one library per backend
        reference, rust = self.results('reference'), self.results('rust')
        self.assertEqual(reference['metadata']['comparison_key'],
                         rust['metadata']['comparison_key'])
        self.assertNotEqual(reference['metadata']['library']['sha256'],
                            rust['metadata']['library']['sha256'])
        comparison = json.loads((self.run_dir / 'comparison.json').read_text())
        self.assertEqual((comparison['status'], comparison['successful']), ('EQUIVALENT', True))
        for path in ('metadata.json', 'runner.log', 'summary.txt', 'prepare/tpm2-tss.log',
                     'reference/summary.txt', 'rust/library-build.log',
                     'rust/tpm2-tss/console.log'):
            self.assertTrue((self.run_dir / path).exists(), path)
        prepare = self.suite('rust', 'tpm2-tss')['phases'][0]
        self.assertEqual((prepare['name'], prepare['shared']), ('prepare', True))

    def test_rust_runs_after_reference_library_build_failure(self):
        self.plan(library={'reference': 'fail'})
        result = self.run_runner()
        self.assertEqual(result.returncode, 1)
        reference = self.results('reference')
        self.assertEqual(reference['phases'][0]['status'], 'ERROR')
        self.assertEqual({s['status'] for s in reference['suites']}, {'NOT_RUN'})
        self.assertEqual(self.results('rust')['status'], 'PASS')
        comparison = json.loads((self.run_dir / 'comparison.json').read_text())
        self.assertEqual(comparison['status'], 'INCOMPLETE')
        self.assertIn('library-build: ERROR', (self.run_dir / 'summary.txt').read_text())

    def test_rust_runs_after_reference_test_and_setup_failures(self):
        self.plan(run={'reference/tpm2-tss': 'fail', 'reference/google-go-tpm': 'setup-fail'})
        result = self.run_runner()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.suite('reference', 'tpm2-tss')['status'], 'FAIL')
        setup = self.suite('reference', 'google-go-tpm')
        self.assertEqual(setup['status'], 'ERROR')
        self.assertIn('preflight failed', [i['message'] for i in setup['issues']])
        self.assertEqual(self.results('rust')['status'], 'PASS')
        comparison = json.loads((self.run_dir / 'comparison.json').read_text())
        self.assertEqual(comparison['counts']['improvement'], 1)

    def test_matching_failures_exit_nonzero(self):
        self.plan(run={'reference/tpm2-tss': 'fail', 'rust/tpm2-tss': 'fail'})
        result = self.run_runner()
        self.assertEqual(result.returncode, 1)
        comparison = json.loads((self.run_dir / 'comparison.json').read_text())
        self.assertEqual(comparison['status'], 'EQUIVALENT')
        self.assertFalse(comparison['successful'])

    def test_single_backend_and_prepare_failure_isolation(self):
        self.plan(prepare={'tpm2-tss': 'fail'})
        result = self.run_runner(backend='rust')
        self.assertEqual(result.returncode, 1)
        self.assertFalse((self.run_dir / 'reference').exists())
        failed = self.suite('rust', 'tpm2-tss')
        self.assertEqual((failed['status'], failed['phases'][0]['status']), ('ERROR', 'ERROR'))
        self.assertEqual(self.suite('rust', 'google-go-tpm')['status'], 'PASS')

    def test_prepare_only_is_not_a_validation(self):
        self.plan()
        result = self.run_runner(prepare_only=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.lines('library'), [])
        self.assertEqual(self.results('rust')['status'], 'NOT_RUN')

    def test_invalid_request_and_cache_lock(self):
        result = self.run_runner(backend='both-and-more')
        self.assertEqual(result.returncode, 2)
        self.plan()
        (self.work / 'cache').mkdir(parents=True, exist_ok=True)
        import fcntl
        with open(self.work / 'cache' / 'validation.lock', 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            result = self.run_runner()
        self.assertEqual(result.returncode, 2)
        self.assertIn('another validation run', result.stderr)


class TerminationTests(RunnerFixture):
    def wait_for(self, path, process):
        deadline = time.monotonic() + 60
        while not path.exists():
            if process.poll() is not None or time.monotonic() > deadline:
                self.fail(f'{path.name} never appeared: {process.communicate()}')
            time.sleep(.02)

    def test_phase_timeout_keeps_report_and_continues(self):
        self.plan(run={'rust/tpm2-tss': 'hang'})
        result = self.run_runner(backend='rust', timeout=3)
        self.assertEqual(result.returncode, 1)
        suite = self.suite('rust', 'tpm2-tss')
        self.assertEqual(suite['status'], 'TIMEOUT')
        self.assertEqual({t['name']: t['status'] for t in suite['tests']},
                         {'t1': 'PASS', 't2': 'TIMEOUT'})
        self.assertEqual(suite['phases'][-1]['execution']['termination'], 'timeout')
        self.assertEqual(self.suite('rust', 'google-go-tpm')['status'], 'PASS')
        self.assert_all_dead()

    def test_interruption_finalizes_partial_results(self):
        for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            with self.subTest(signal=number.name):
                self.setUp()
                self.plan(run={'reference/google-go-tpm': 'hang'})
                process = subprocess.Popen(self.command(), cwd=ROOT, env=self.env(),
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           text=True)
                self.addCleanup(lambda p=process: p.poll() is None and p.kill())
                self.wait_for(self.run_dir / 'hanging-reference-google-go-tpm', process)
                # Completed work was already persisted while the phase is running.
                live = json.loads((self.run_dir / 'reference' / 'results.json').read_text())
                self.assertEqual([s['state'] for s in live['suites']], ['finished', 'running'])
                process.send_signal(number)
                process.communicate(timeout=60)
                self.assertEqual(process.returncode, 128 + number)
                reference = self.results('reference')
                self.assertEqual([s['status'] for s in reference['suites']],
                                 ['PASS', 'INTERRUPTED'])
                interrupted = reference['suites'][1]
                self.assertEqual({t['name']: t['status'] for t in interrupted['tests']},
                                 {'t1': 'PASS', 't2': 'INTERRUPTED'})
                rust = self.results('rust')
                self.assertEqual([s['status'] for s in rust['suites']], ['NOT_RUN', 'NOT_RUN'])
                self.assertFalse(rust['complete'])
                self.assertEqual(self.lines('library')[-1][1], 'reference')
                comparison = json.loads((self.run_dir / 'comparison.json').read_text())
                self.assertEqual(comparison['status'], 'INCOMPLETE')
                self.assertTrue((self.run_dir / 'summary.txt').exists())
                metadata = json.loads((self.run_dir / 'metadata.json').read_text())
                self.assertEqual(metadata['interrupted_by'], number.name)
                self.assert_all_dead()

    def test_interruption_during_library_build(self):
        self.plan(library={'reference': 'hang'})
        process = subprocess.Popen(self.command(), cwd=ROOT, env=self.env(),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: process.poll() is None and process.kill())
        deadline = time.monotonic() + 60
        while not self.lines('library') and time.monotonic() < deadline:
            time.sleep(.05)
        time.sleep(.5)
        process.send_signal(signal.SIGTERM)
        process.communicate(timeout=60)
        self.assertEqual(process.returncode, 143)
        reference = self.results('reference')
        self.assertEqual(reference['phases'][0]['status'], 'INTERRUPTED')
        self.assertEqual(self.lines('run'), [])
        self.assertEqual(self.results('rust')['status'], 'NOT_RUN')

    def test_leaked_daemon_is_a_cleanup_failure(self):
        self.plan(run={'rust/tpm2-tss': 'leak'})
        result = self.run_runner(backend='rust')
        self.assertEqual(result.returncode, 1)
        suite = self.suite('rust', 'tpm2-tss')
        self.assertEqual(suite['status'], 'ERROR')
        cleanup = next(p for p in suite['phases'] if p['name'] == 'cleanup')
        self.assertIn('left descendants running', cleanup['reason'])
        run = next(p for p in suite['phases'] if p['name'] == 'run')
        self.assertTrue(run['execution']['cleanup_failed'])
        self.assert_all_dead()


if __name__ == '__main__':
    unittest.main()
