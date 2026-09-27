"""Container entry point: prepare suites once, run each backend, persist results.

    python3 -m validation.runner --request /work/results/<run-id>/request.json

Layout under <run>: runner.log, metadata.json, prepare/<suite>.log,
<backend>/{results.json,summary.txt,library-build.log,<suite>/...},
comparison.json and summary.txt (both backends).
"""
from __future__ import annotations

import argparse
import copy
import fcntl
import importlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time
import traceback

from . import harness, processes, results as schema
from .adapters.base import RunContext
from .environment import (SOURCES, SUITES, Interrupted, Phase, PhaseTimeout, StepFailed,
                          base_environment, write_json)

BACKEND_ORDER = {'both': ('reference', 'rust'), 'rust': ('rust',),
                 'reference': ('reference',), 'selected': ('selected',)}
PHASE_STATUS = {'completed': 'PASS', 'setup-failed': 'ERROR', 'timeout': 'TIMEOUT',
                'interrupted': 'INTERRUPTED'}
# Upstream checkouts each suite depends on (for the post-run integrity check).
SUITE_SOURCES = {'tpm2-tss': ('tpm2-tss',), 'tpm2-tools': ('tpm2-tss', 'tpm2-abrmd',
                                                           'tpm2-tools'),
                 'google-go-tpm': ('google-go-tpm',),
                 'canonical-go-tpm2': ('canonical-go-tpm2',),
                 'microsoft-tss': ('microsoft-tss',)}


class RequestError(ValueError):
    pass


def validate_request(request):
    """The container re-validates what the host already checked."""
    if request.get('jobs') is None:
        request['jobs'] = os.cpu_count() or 2   # resolved inside the container
    backend = request.get('backend')
    if backend not in BACKEND_ORDER:
        raise RequestError(f'unknown backend {backend!r}')
    suites = request.get('suites')
    if not suites or not isinstance(suites, list) or len(set(suites)) != len(suites) \
            or any(s not in SUITES for s in suites):
        raise RequestError(f'invalid suites {suites!r}')
    for key in ('timeout', 'microsoft_test_timeout', 'jobs'):
        value = request.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise RequestError(f'{key} must be a positive integer')
    if not isinstance(request.get('filter', ''), str):
        raise RequestError('filter must be a string')
    if request.get('filter') and len(suites) != 1:
        raise RequestError('--filter requires exactly one suite')
    if not isinstance(request.get('run_id'), str) or '/' in request['run_id']:
        raise RequestError('invalid run_id')
    return request


def comparison_key(request, harness_sha256):
    """Everything that must match before two backend results are comparable."""
    return {
        'image_id': request.get('image_id'),
        'harness_sha256': harness_sha256,
        'sources': {name: SOURCES[name][1] for name in sorted(SOURCES)},
        'suites': list(request['suites']),
        'filter': request.get('filter', ''),
        'timeout': request['timeout'],
        'microsoft_test_timeout': request['microsoft_test_timeout'],
        'jobs': request['jobs'],
        'prepare_only': bool(request.get('prepare_only')),
        'transport': {'bridge': 'bridge.py Microsoft simulator TCP over the public '
                                'libtpms ABI', 'tpm2-tools': 'tabrmd',
                      'ports': [2321, 2322]},
    }


def tool_versions():
    versions = {'python': platform.python_version(), 'kernel': platform.release()}
    for name, argv in (('go', ['go', 'version']), ('dotnet', ['dotnet', '--version']),
                       ('cargo', ['cargo', '--version']), ('rustc', ['rustc', '--version']),
                       ('gcc', ['gcc', '--version'])):
        try:
            output = subprocess.run(argv, capture_output=True, text=True, timeout=60)
            versions[name] = (output.stdout or output.stderr).splitlines()[0].strip()
        except (OSError, subprocess.SubprocessError, IndexError):
            versions[name] = None
    return versions


class Runner:
    def __init__(self, request, *, adapters, build_library):
        self.request = request
        self.adapters = adapters
        self.build_library = build_library
        self.root = Path(request.get('root', '/validation'))
        self.work = Path(request.get('work', '/work'))
        self.repo = Path(request.get('repo', '/repo'))
        self.cache = self.work / 'cache'
        self.run_dir = self.work / 'results' / request['run_id']
        self.signal = None
        self.log_file = open(self.run_dir / 'runner.log', 'a', buffering=1)
        self.backends = BACKEND_ORDER[request['backend']]
        self.runs = {}

    # -- plumbing
    def log(self, text):
        line = f'[{time.strftime("%H:%M:%S")}] {text}'
        print(line, flush=True)
        self.log_file.write(line + '\n')

    def on_signal(self, number, _frame):
        if self.signal is None:
            self.signal = number

    def relative(self, path):
        return str(Path(path).relative_to(self.run_dir))

    def snapshot(self, run):
        """In-progress view: finished suites are aggregated, others keep their state."""
        value = copy.deepcopy(run)
        for suite in value['suites']:
            if suite['state'] == 'finished':
                schema.finalize_suite(suite)
        return value

    def persist(self, backend, final=False):
        run = self.runs[backend]
        value = schema.finalize_run(run) if final else self.snapshot(run)
        write_json(self.run_dir / backend / 'results.json', value)
        if final:
            (self.run_dir / backend / 'summary.txt').write_text(schema.render_run(value))

    def persist_all(self):
        for backend in self.backends:
            self.persist(backend)

    def attempt(self, action):
        """Run a prepare/build action; return (status, reason, execution)."""
        try:
            action()
            return 'PASS', '', None
        except StepFailed as exc:
            return 'ERROR', str(exc), exc.execution
        except PhaseTimeout as exc:
            return 'TIMEOUT', f'phase exceeded {self.request["timeout"]}s', exc.execution
        except Interrupted as exc:
            self.note_interrupt(exc.execution)
            return 'INTERRUPTED', f'interrupted by {self.signal_name()}', exc.execution
        except Exception as exc:  # the harness itself failed: keep going, loudly
            self.log(traceback.format_exc())
            return 'ERROR', f'internal harness error: {exc!r}', None

    def note_interrupt(self, execution):
        if self.signal is None:
            name = (execution or {}).get('signal', 'SIGTERM')
            self.signal = getattr(signal, name, signal.SIGTERM)

    def signal_name(self):
        return signal.Signals(self.signal).name if self.signal else 'signal'

    def suite_record(self, backend, name):
        return next(s for s in self.runs[backend]['suites'] if s['name'] == name)

    # -- phases
    def prepare(self):
        statuses = {}
        for name in self.request['suites']:
            if self.signal:
                break
            log = self.run_dir / 'prepare' / f'{name}.log'
            self.log(f'{name}: prepare (log {self.relative(log)})')
            phase = Phase(root=self.root, cache=self.cache, log=log,
                          timeout=self.request['timeout'], jobs=self.request['jobs'])
            status, reason, execution = self.attempt(lambda: self.adapters[name].prepare(phase))
            statuses[name] = status
            self.log(f'{name}: prepare {status} {reason}'.rstrip())
            for backend in self.backends:
                self.suite_record(backend, name)['phases'].append(schema.phase_record(
                    'prepare', status, execution=execution, log=self.relative(log),
                    reason=reason, shared=len(self.backends) > 1))
            self.persist_all()
        return statuses

    def run_backend(self, backend, prepared):
        run = self.runs[backend]
        run['state'] = 'running'
        self.persist(backend)
        backend_dir = self.run_dir / backend
        log = backend_dir / 'library-build.log'
        self.log(f'{backend}: building library (log {self.relative(log)})')
        phase = Phase(root=self.root, cache=self.cache, log=log,
                      timeout=self.request['timeout'], jobs=self.request['jobs'])
        library = {}

        def build():
            library.update(self.build_library(phase, backend, repo=self.repo, cache=self.cache,
                                              selected=self.request.get('selected_library')))
        status, reason, execution = self.attempt(build)
        run['phases'].append(schema.phase_record('library-build', status, execution=execution,
                                                 log=self.relative(log), reason=reason))
        if library:
            library['host_path'] = self.request.get('library_host_path')
            run['metadata']['library'] = library
            self.log(f'{backend}: library {library["path"]} sha256 {library["sha256"]}')
        if status != 'PASS':
            self.log(f'{backend}: library build {status}: {reason}')
            for suite in run['suites']:
                suite['issues'].append(schema.issue('library', f'not run: library build '
                                                    f'{status.lower()}', incomplete=True))
            run['state'] = 'finished'
            self.persist(backend, final=True)
            return
        for name in self.request['suites']:
            if self.signal:
                break
            suite = self.suite_record(backend, name)
            if prepared.get(name) != 'PASS':
                suite['state'] = 'finished'
                suite['issues'].append(schema.issue('prepare', 'not run: preparation '
                                                    f'{(prepared.get(name) or "not done").lower()}',
                                                    incomplete=True))
                self.persist(backend)
                continue
            self.run_suite(backend, suite, library['path'])
        run['state'] = 'finished'
        if self.signal:
            run['issues'].append(schema.issue('interrupted', f'stopped by {self.signal_name()}',
                                              severity='warning', incomplete=True))
        self.persist(backend, final=True)

    def run_suite(self, backend, suite, library):
        name = suite['name']
        suite_dir = self.run_dir / backend / name
        suite_dir.mkdir(parents=True, exist_ok=True)
        suite['state'] = 'running'
        self.persist(backend)
        env = dict(base_environment(self.root, self.cache), LIBTPMS_LIBRARY=library)
        phase = Phase(root=self.root, cache=self.cache, log=suite_dir / 'run.log',
                      timeout=self.request['timeout'], jobs=self.request['jobs'], env=env)
        ctx = RunContext(phase=phase, suite_dir=suite_dir, run_root=self.run_dir,
                         library=library, backend=backend, filter=self.request.get('filter', ''),
                         microsoft_test_timeout=self.request['microsoft_test_timeout'],
                         jobs=self.request['jobs'], started=time.time())
        self.log(f'{backend}/{name}: run (log {self.relative(phase.log)})')
        adapter = self.adapters[name]
        try:
            adapter.run(ctx)
            ctx.termination = 'completed'
        except StepFailed as exc:
            ctx.termination, ctx.error = 'setup-failed', str(exc)
            ctx.execution = ctx.execution or exc.execution
        except PhaseTimeout as exc:
            ctx.termination = 'timeout'
            ctx.error = f'run phase exceeded {self.request["timeout"]}s'
            # The main execution was cut short inside phase.run; keep its evidence.
            ctx.execution = ctx.execution or exc.execution
        except Interrupted as exc:
            self.note_interrupt(exc.execution)
            ctx.termination, ctx.error = 'interrupted', f'interrupted by {self.signal_name()}'
            ctx.execution = ctx.execution or exc.execution
        except Exception as exc:
            self.log(traceback.format_exc())
            ctx.termination, ctx.error = 'setup-failed', f'internal harness error: {exc!r}'
        # Evidence is collected whatever ended the phase.
        try:
            adapter.collect(suite, ctx)
        except Exception as exc:
            self.log(traceback.format_exc())
            suite['issues'].append(schema.issue('collector', f'result collection failed: '
                                                f'{exc!r}', incomplete=True))
        if ctx.termination == 'setup-failed':
            suite['issues'].append(schema.issue('setup', ctx.error))
        suite['phases'].append(schema.phase_record(
            'run', PHASE_STATUS[ctx.termination], execution=ctx.execution,
            log=self.relative(phase.log), reason=ctx.error))
        # A command that exited normally but left descendants was already cleaned
        # up by run_process; it is still a failed cleanup.
        leaked = [e for e in phase.executions if e.get('cleanup_failed')]
        if leaked:
            suite['phases'].append(schema.phase_record(
                'cleanup', 'ERROR', log=self.relative(phase.log),
                reason=f'{len(leaked)} command(s) left descendants running; they were killed'))
        leftovers = processes.sweep(report=suite_dir / 'leftover-processes.txt') \
            if self.request.get('sweep', True) else []
        if leftovers:
            suite['phases'].append(schema.phase_record(
                'cleanup', 'ERROR', log=self.relative(suite_dir / 'leftover-processes.txt'),
                reason=f'{len(leftovers)} test process(es) outlived the phase and were killed'))
        for source in SUITE_SOURCES.get(name, ()):
            checkout = self.cache / 'sources' / source
            if (checkout / '.git').is_dir() and subprocess.run(
                    ['git', '-C', str(checkout), 'diff', '--quiet', 'HEAD', '--'],
                    capture_output=True).returncode != 0:
                suite['issues'].append(schema.issue('source-changed', f'upstream tracked '
                                                    f'sources changed: {source}'))
        suite['state'] = 'finished'
        view = schema.finalize_suite(copy.deepcopy(suite))
        self.log(f'{backend}/{name}: {view["status"]} '
                 f'{" ".join(f"{k}={v}" for k, v in view["counts"].items())}')
        self.persist(backend)

    # -- whole run
    def execute(self):
        for number in processes.SIGNALS:
            signal.signal(number, self.on_signal)
        processes.enable_subreaper()
        request = self.request
        harness_sha = harness.digest(self.root)
        issues = []
        if request.get('harness_sha256') and request['harness_sha256'] != harness_sha:
            issues.append(schema.issue('harness', 'the mounted harness does not match the '
                                       'snapshot recorded by the host'))
        metadata = {
            'request': {k: v for k, v in request.items() if k not in ('root', 'work', 'repo')},
            'image_id': request.get('image_id'),
            'harness_sha256': harness_sha,
            'sources': {name: {'url': url, 'revision': revision}
                        for name, (url, revision) in SOURCES.items()},
            'tools': tool_versions() if request.get('record_tools', True) else {},
            'started_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'comparison_key': comparison_key(request, harness_sha),
            'library': None,
        }
        write_json(self.run_dir / 'metadata.json', metadata)
        for backend in self.backends:
            self.runs[backend] = schema.new_run(request['run_id'], backend,
                                                copy.deepcopy(metadata), request['suites'])
            self.runs[backend]['issues'].extend(copy.deepcopy(issues))
        self.persist_all()
        self.log(f'run {request["run_id"]}: backends {", ".join(self.backends)}; suites '
                 f'{", ".join(request["suites"])}')
        prepared = self.prepare()
        if request.get('prepare_only'):
            for backend in self.backends:
                self.runs[backend]['state'] = 'finished'
                self.persist(backend, final=True)
            self.finish_metadata(metadata)
            ok = all(prepared.get(s) == 'PASS' for s in request['suites'])
            return self.exit_code(0 if ok else 1)
        for backend in self.backends:
            if self.signal:
                break
            self.run_backend(backend, prepared)
        for backend in self.backends:
            run = self.runs[backend]
            if run['state'] == 'pending':
                run['issues'].append(schema.issue('not-started', f'backend not started: '
                                                  f'{self.signal_name()}',
                                                  severity='warning', incomplete=True))
                run['state'] = 'finished'
            if run['state'] == 'running':
                run['state'] = 'finished'
            self.persist(backend, final=True)
        self.finish_metadata(metadata)
        finals = {b: schema.load_run(json.loads((self.run_dir / b / 'results.json').read_text()))
                  for b in self.backends}
        summary = ''.join(schema.render_run(finals[b]) for b in self.backends)
        if len(self.backends) == 2:
            comparison = schema.compare_runs(finals['reference'], finals['rust'])
            write_json(self.run_dir / 'comparison.json', comparison)
            summary += schema.render_comparison(comparison)
            ok = comparison['successful']
        else:
            ok = finals[self.backends[0]]['status'] == 'PASS' and \
                finals[self.backends[0]]['complete']
        (self.run_dir / 'summary.txt').write_text(summary)
        for line in summary.rstrip('\n').splitlines():
            self.log(line)
        return self.exit_code(0 if ok else 1)

    def finish_metadata(self, metadata):
        metadata['finished_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        metadata['libraries'] = {b: self.runs[b]['metadata'].get('library')
                                 for b in self.backends}
        metadata['interrupted_by'] = self.signal_name() if self.signal else None
        write_json(self.run_dir / 'metadata.json', metadata)

    def exit_code(self, code):
        return 128 + self.signal if self.signal else code


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--request', required=True, type=Path)
    parser.add_argument('--hooks', help='tests only: module providing ADAPTERS and '
                                        'build_library')
    args = parser.parse_args(argv)
    try:
        request = validate_request(json.loads(args.request.read_text()))
    except (OSError, ValueError) as exc:
        print(f'validation runner: invalid request: {exc}', file=sys.stderr)
        return 2
    if args.hooks:
        hooks = importlib.import_module(args.hooks)
        adapters, build_library = hooks.ADAPTERS, hooks.build_library
    else:
        from .adapters import ADAPTERS
        from .library import build
        adapters, build_library = ADAPTERS, build
    work = Path(request.get('work', '/work'))
    (work / 'cache').mkdir(parents=True, exist_ok=True)
    (work / 'results' / request['run_id']).mkdir(parents=True, exist_ok=True)
    lock = open(work / 'cache' / 'validation.lock', 'w')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print('validation runner: another validation run is using this cache', file=sys.stderr)
        return 2
    os.environ.setdefault('PYTHONDONTWRITEBYTECODE', '1')
    return Runner(request, adapters=adapters, build_library=build_library).execute()


if __name__ == '__main__':
    sys.exit(main())
