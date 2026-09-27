"""Host CLI: argument validation, Docker invocation, interruption and persistence.

A fake `docker` executable stands in for Docker. Its `run` executes the real
container runner (with test hooks) against the harness snapshot, so results are
really written by the runner and must survive the fake container's removal.
"""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from validation import harness  # noqa: E402

FAKE_DOCKER = textwrap.dedent(r'''
    #!/usr/bin/env python3
    import json, os, signal, subprocess, sys, time
    from pathlib import Path
    args = sys.argv[1:]
    state = Path(os.environ['FAKE_DOCKER_STATE'])
    with open(state / 'calls.jsonl', 'a') as calls:
        calls.write(json.dumps(args) + '\n')
    plan = json.loads((state / 'plan.json').read_text())
    if args[0] == 'build':
        sys.exit(plan.get('build', 0))
    if args[:2] == ['image', 'inspect']:
        print('sha256:' + 'f' * 64); sys.exit(0)
    if args[0] in ('stop', 'kill'):
        pid = state / f'{args[-1]}.pid'
        if pid.exists():
            os.kill(int(pid.read_text()), signal.SIGTERM if args[0] == 'stop' else signal.SIGKILL)
        sys.exit(0)
    assert args[0] == 'run', args
    name = args[args.index('--name') + 1]
    behavior = plan.get('run', 'runner')
    (state / f'{name}.pid').write_text(str(os.getpid()))
    if behavior == 'exit':
        sys.exit(plan.get('code', 23))
    mounts = dict(reversed(args[i + 1].split(':', 2)[:2])
                  for i, a in enumerate(args) if a == '-v')
    request_path = Path(args[-1].replace('/work', mounts['/work'], 1))
    request = json.loads(request_path.read_text())
    if behavior == 'die-partial':
        # The container is killed before the runner finalizes anything.
        run = {'schema_version': 1, 'run_id': request['run_id'], 'backend': 'rust',
               'metadata': {}, 'state': 'running', 'status': None, 'complete': False,
               'counts': {}, 'fixture_counts': {}, 'phases': [], 'issues': [],
               'suites': [{'name': 'tpm2-tss', 'revision': None, 'state': 'running',
                           'status': None, 'complete': False, 'selection': {},
                           'phases': [], 'executions': [], 'tests': [], 'counts': {},
                           'fixture_counts': {}, 'native_counts': {}, 'issues': [],
                           'artifacts': {}}]}
        out = request_path.parent / 'rust' / 'results.json'
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(run))
        sys.exit(137)
    # Execute the real runner as the container would, with paths mapped.
    request.update(root=mounts['/validation'], work=mounts['/work'], repo=mounts['/repo'],
                   record_tools=False)
    mapped = request_path.with_name('request.mapped.json')
    mapped.write_text(json.dumps(request))
    env = dict(os.environ, PYTHONPATH=mounts['/validation'])
    child = subprocess.Popen([sys.executable, '-m', 'validation.runner', '--request',
                              str(mapped), '--hooks', 'tests.runner_hooks'],
                             cwd=mounts['/validation'], env=env)
    signal.signal(signal.SIGTERM, lambda *_: child.send_signal(signal.SIGTERM))
    sys.exit(child.wait())
''').lstrip()


class CliFixture(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        docker = self.bin / 'docker'
        docker.write_text(FAKE_DOCKER)
        docker.chmod(0o755)
        self.state = self.root / 'state'
        self.state.mkdir()
        self.work = self.root / 'work'
        self.events = self.root / 'events'
        self.events.touch()
        self.plan()
        self.hooks_plan({})

    def plan(self, **plan):
        (self.state / 'plan.json').write_text(json.dumps(plan))

    def hooks_plan(self, plan):
        (self.root / 'hooks-plan.json').write_text(json.dumps(plan))

    def env(self):
        return dict(os.environ, PATH=f'{self.bin}:{os.environ["PATH"]}',
                    FAKE_DOCKER_STATE=str(self.state), EXTERNAL_VALIDATION_WORK_DIR=str(self.work),
                    FAKE_PLAN=str(self.root / 'hooks-plan.json'),
                    FAKE_EVENTS=str(self.events), PYTHONDONTWRITEBYTECODE='1')

    def cli(self, *args, **kwargs):
        return subprocess.run([sys.executable, str(ROOT / 'run.py'), *args], env=self.env(),
                              capture_output=True, text=True, timeout=180, **kwargs)

    def calls(self):
        path = self.state / 'calls.jsonl'
        return [json.loads(l) for l in path.read_text().splitlines()] if path.exists() else []

    def run_dirs(self):
        results = self.work / 'results'
        return sorted(p for p in results.iterdir() if p.is_dir()) if results.exists() else []


class ValidationTests(CliFixture):
    def test_invalid_arguments_are_rejected_before_docker(self):
        library = self.root / 'libtpms.so'
        library.write_text('x')
        for args, message in (
                (['run', 'unknown-suite'], 'unknown suite'),
                (['run', '--filter', 'Policy', 'all'], 'exactly one suite'),
                (['run', '--filter', 'Policy', 'tpm2-tss', 'tpm2-tools'], 'exactly one suite'),
                (['run', 'tpm2-tss', 'tpm2-tss'], 'once'),
                (['run', '--backend', 'swtpm'], 'unknown backend'),
                (['run', '--backend', 'both', '--library', str(library)], '--library'),
                (['run', '--backend', 'rust', '--library', str(library)], '--library'),
                (['run', '--library', str(self.root / 'missing.so')], 'does not exist'),
                (['run', '--timeout', '0'], 'positive integer'),
                (['run', '--microsoft-test-timeout', '1.5'], 'positive integer'),
                (['run', '--jobs', 'abc'], 'positive integer'),
                (['run', '--prepare-only', '--filter', 'x', 'tpm2-tss'], 'prepare-only'),
                (['frobnicate'], 'invalid choice')):
            with self.subTest(args=args):
                result = self.cli(*args)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(message, result.stderr)
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.run_dirs(), [])

    def test_help_needs_no_docker(self):
        result = self.cli('run', '--help')
        self.assertEqual(result.returncode, 0)
        self.assertIn('--backend', result.stdout)


class InvocationTests(CliFixture):
    def test_both_backends_through_docker_persist_results(self):
        result = self.cli('run', '--no-build-image', '--backend', 'both',
                          '--microsoft-test-timeout', '45', 'tpm2-tss')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        (run_dir,) = self.run_dirs()
        calls = self.calls()
        self.assertEqual([c[0] for c in calls], ['image', 'run'])
        run = calls[1]
        self.assertEqual(run[:3], ['run', '--rm', '--init'])
        self.assertIn(f'external-validation-{run_dir.name}', run)
        volumes = [run[i + 1] for i, a in enumerate(run) if a == '-v']
        self.assertIn(f'{ROOT.parent}:/repo:ro', volumes)
        self.assertIn(f'{run_dir / "harness"}:/validation:ro', volumes)
        self.assertIn(f'{self.work}:/work', volumes)
        self.assertNotIn('--privileged', run)
        self.assertIn('sha256:' + 'f' * 64, run)
        request = json.loads((run_dir / 'request.json').read_text())
        self.assertEqual((request['backend'], request['suites'], request['microsoft_test_timeout'],
                          request['timeout']), ('both', ['tpm2-tss'], 45, 1800))
        self.assertEqual(request['harness_sha256'], harness.digest(run_dir / 'harness'))
        # The fake container has exited and is gone; the evidence remains.
        for path in ('reference/results.json', 'rust/results.json', 'comparison.json',
                     'summary.txt', 'metadata.json', 'runner.log', 'harness/run.py'):
            self.assertTrue((run_dir / path).exists(), path)
        metadata = json.loads((run_dir / 'metadata.json').read_text())
        self.assertEqual(metadata['harness_sha256'], request['harness_sha256'])
        report = self.cli('report', str(run_dir))
        self.assertEqual(report.returncode, 0, report.stdout)
        self.assertIn('Comparison reference vs rust: EQUIVALENT', report.stdout)

    def test_container_status_is_preserved(self):
        self.plan(run='exit', code=23)
        result = self.cli('run', '--no-build-image', 'google-go-tpm')
        self.assertEqual(result.returncode, 23)
        (run_dir,) = self.run_dirs()
        self.assertIn('No results were persisted', (run_dir / 'summary.txt').read_text())

    def test_unsuccessful_validation_is_nonzero(self):
        self.hooks_plan({'run': {'rust/tpm2-tss': 'fail'}})
        result = self.cli('run', '--no-build-image', 'tpm2-tss')
        self.assertEqual(result.returncode, 1)
        (run_dir,) = self.run_dirs()
        self.assertIn('FAIL', (run_dir / 'summary.txt').read_text())

    def test_image_build_uses_the_snapshot_and_failure_stops_before_run(self):
        self.plan(build=1)
        result = self.cli('run', 'tpm2-tss')
        self.assertEqual(result.returncode, 2)
        (run_dir,) = self.run_dirs()
        self.assertEqual(self.calls()[0], ['build', '-t', 'libtpms-external-validation:local',
                                           str(run_dir / 'harness')])
        self.assertNotIn('run', [c[0] for c in self.calls()])

    def test_explicit_library_is_mounted_read_only(self):
        library = self.root / 'libtpms.so'
        library.write_text('x')
        self.cli('run', '--no-build-image', '--library', str(library), 'tpm2-tss')
        run = next(c for c in self.calls() if c[0] == 'run')
        self.assertIn(f'{library.resolve()}:/selected/libtpms.so:ro', run)
        (run_dir,) = self.run_dirs()
        self.assertEqual(json.loads((run_dir / 'request.json').read_text())['backend'],
                         'selected')

    def test_self_test_runs_inside_docker(self):
        self.plan(run='exit', code=0)
        result = self.cli('self-test', '--no-build-image', '--abi', 'none')
        self.assertEqual(result.returncode, 0, result.stderr)
        run = next(c for c in self.calls() if c[0] == 'run')
        self.assertEqual(run[run.index('-m') + 1], 'validation.selftest')
        self.assertIn('--abi', run)


class InterruptionTests(CliFixture):
    def test_interrupt_stops_the_container_and_keeps_partial_results(self):
        self.hooks_plan({'run': {'reference/google-go-tpm': 'hang'}})
        process = subprocess.Popen([sys.executable, str(ROOT / 'run.py'), 'run',
                                    '--no-build-image', '--backend', 'both', 'tpm2-tss',
                                    'google-go-tpm'],
                                   env=self.env(), stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: process.poll() is None and process.kill())
        deadline = time.monotonic() + 120
        while not list((self.work / 'results').glob('*/hanging-reference-google-go-tpm')) \
                if (self.work / 'results').exists() else True:
            if process.poll() is not None or time.monotonic() > deadline:
                self.fail(process.communicate())
            time.sleep(.05)
        process.send_signal(signal.SIGINT)
        stdout, stderr = process.communicate(timeout=120)
        self.assertEqual(process.returncode, 143, stdout + stderr)
        (run_dir,) = self.run_dirs()
        self.assertIn(['stop', '--time', '60', f'external-validation-{run_dir.name}'],
                      self.calls())
        reference = json.loads((run_dir / 'reference' / 'results.json').read_text())
        self.assertEqual([s['status'] for s in reference['suites']], ['PASS', 'INTERRUPTED'])
        self.assertTrue((run_dir / 'summary.txt').exists())

    def test_host_renders_results_left_by_a_killed_container(self):
        self.plan(run='die-partial')
        result = self.cli('run', '--no-build-image', 'tpm2-tss')
        self.assertEqual(result.returncode, 137)
        (run_dir,) = self.run_dirs()
        summary = (run_dir / 'summary.txt').read_text()
        self.assertIn('INTERRUPTED', summary)
        self.assertIn('incomplete', summary)


class ReportCompareTests(CliFixture):
    def make_run(self, *plans):
        created = []
        for plan in plans:
            self.hooks_plan(plan)
            before = set(self.run_dirs())
            self.cli('run', '--no-build-image', 'tpm2-tss')
            (new,) = set(self.run_dirs()) - before
            created.append(new)
        return created

    def test_compare_separate_runs(self):
        first, second = self.make_run({}, {'run': {'rust/tpm2-tss': 'fail'}})
        same = self.cli('compare', str(first / 'rust'), str(first / 'rust' / 'results.json'))
        self.assertEqual(same.returncode, 0, same.stdout + same.stderr)
        different = self.cli('compare', str(first), str(second), '--output',
                             str(self.root / 'comparison.json'))
        self.assertEqual(different.returncode, 1)
        comparison = json.loads((self.root / 'comparison.json').read_text())
        # Separate runs have different harness snapshots only if edited; the
        # image and pins match, so the outcome difference is what is reported.
        self.assertEqual(comparison['counts']['regression'], 1)
        failing = self.cli('report', str(second))
        self.assertEqual(failing.returncode, 1)
        self.assertIn('FAIL', failing.stdout)

    def test_report_of_missing_results(self):
        result = self.cli('report', str(self.root))
        self.assertEqual(result.returncode, 2)
        self.assertIn('no results.json', result.stderr)


if __name__ == '__main__':
    unittest.main()
