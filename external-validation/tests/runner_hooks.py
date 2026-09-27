"""Controlled adapters and library builds for runner tests (`--hooks`).

Behaviour comes from the JSON plan at $FAKE_PLAN; every notable action is
appended to $FAKE_EVENTS so tests can check ordering, isolation and cleanup.
"""
import hashlib
import json
import os
from pathlib import Path
import sys

from validation import results as schema
from validation.adapters.base import Adapter
from validation.environment import SUITES, StepFailed


def plan():
    return json.loads(Path(os.environ['FAKE_PLAN']).read_text())


def event(*words):
    with open(os.environ['FAKE_EVENTS'], 'a') as output:
        output.write(' '.join(map(str, words)) + '\n')


CHILD = r'''
import json, os, subprocess, sys, time
from pathlib import Path
behavior, events, marker = sys.argv[1], sys.argv[2], sys.argv[3]
def event(*words):
    open(events, 'a').write(' '.join(map(str, words)) + '\n')
event('child', os.getpid())
tests = {'t1': 'PASS', 't2': 'FAIL' if behavior == 'fail' else 'PASS'}
if behavior == 'hang':
    tests = {'t1': 'PASS'}
Path('report.json.tmp').write_text(json.dumps(tests))
os.replace('report.json.tmp', 'report.json')
if behavior == 'hang':
    grandchild = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(600)'])
    event('grandchild', grandchild.pid)
    Path(marker).write_text('hanging')
    time.sleep(600)
if behavior == 'leak':
    if os.fork() == 0:
        os.setsid()
        if os.fork() == 0:
            event('daemon', os.getpid())
            time.sleep(600)
        os._exit(0)
    time.sleep(.2)
sys.exit(1 if behavior == 'fail' else 0)
'''


class FakeAdapter(Adapter):
    def __init__(self, name):
        self.name = self.source = name

    def prepare(self, phase):
        event('prepare', self.name)
        phase.run([sys.executable, '-c', 'print("prepared")'], cwd=phase.cache)
        behavior = plan().get('prepare', {}).get(self.name, 'ok')
        if behavior == 'fail':
            raise StepFailed(f'{self.name} prepare failed')
        if behavior == 'hang':
            phase.run([sys.executable, '-c', 'import time; time.sleep(600)'], cwd=phase.cache)

    def run(self, ctx):
        behavior = plan().get('run', {}).get(f'{ctx.backend}/{self.name}', 'pass')
        state = ctx.suite_dir / 'tpm-state'
        # Fresh TPM state: nothing may exist from another backend or run.
        event('run', ctx.backend, self.name, ctx.library, ctx.suite_dir,
              'stale-state' if state.exists() else 'fresh-state')
        state.write_text(ctx.backend)
        if behavior == 'setup-fail':
            raise StepFailed('preflight failed')
        ctx.execution = ctx.phase.run(
            [sys.executable, '-c', CHILD, behavior, os.environ['FAKE_EVENTS'],
             str(ctx.run_root / f'hanging-{ctx.backend}-{self.name}')],
            cwd=ctx.suite_dir, log=ctx.suite_dir / 'console.log', check=False)
        return ctx.execution

    def collect(self, suite, ctx):
        event('collect', ctx.backend, self.name, ctx.termination)
        report = ctx.suite_dir / 'report.json'
        if not report.exists():
            suite['issues'].append(schema.issue('no-report', 'no report', incomplete=True))
            return
        for name, status in json.loads(report.read_text()).items():
            suite['tests'].append(schema.test_result(
                self.name, name, status, artifacts={'report': ctx.relative(report)}))
        running = {'timeout': 'TIMEOUT', 'interrupted': 'INTERRUPTED'}.get(ctx.termination)
        if running:
            suite['tests'].append(schema.test_result(self.name, 't2', running,
                                                     reason='stopped while running'))


ADAPTERS = {name: FakeAdapter(name) for name in SUITES}


def build_library(phase, backend, *, repo, cache, selected=None):
    event('library', backend)
    behavior = plan().get('library', {}).get(backend, 'ok')
    code = {'fail': 'raise SystemExit(3)', 'hang': 'import time; time.sleep(600)'}.get(
        behavior, 'print("built")')
    phase.run([sys.executable, '-c', code], cwd=cache)
    library = Path(cache) / 'builds' / backend / 'libtpms.so'
    library.parent.mkdir(parents=True, exist_ok=True)
    library.write_text(f'fake {backend} library')
    return {'path': str(library), 'sha256': hashlib.sha256(library.read_bytes()).hexdigest(),
            'identity': {'implementation': backend}}
