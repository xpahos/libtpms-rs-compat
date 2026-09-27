"""Framework tests inside the validation container (`run.py self-test`).

Runs every harness test once; the bridge ABI tests additionally load real
libraries (rust, reference or both), built with the same code as a run.
"""
from __future__ import annotations

import argparse
import fcntl
import os
from pathlib import Path
import subprocess
import sys

from .environment import Phase, StepFailed, PhaseTimeout, Interrupted
from .library import build

ABI_TESTS = ['-v', 'tests.test_bridge']


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--abi', choices=('rust', 'reference', 'both', 'none'), default='both')
    parser.add_argument('--results', required=True, type=Path)
    parser.add_argument('--timeout', type=int, default=1800)
    parser.add_argument('tests', nargs='*')
    args = parser.parse_args(argv)
    root, work = Path('/validation'), Path('/work')
    args.results.mkdir(parents=True, exist_ok=True)
    lock = open(work / 'cache' / 'validation.lock', 'w')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print('self-test: another validation run is using this cache', file=sys.stderr)
        return 2
    backends = {'both': ['rust', 'reference'], 'none': []}.get(args.abi, [args.abi])
    libraries, failed = {}, False
    for backend in backends:
        log = args.results / f'{backend}-library-build.log'
        print(f'self-test: building {backend} library (log {log})', flush=True)
        phase = Phase(root=root, cache=work / 'cache', log=log, timeout=args.timeout,
                      jobs=os.cpu_count() or 2)
        try:
            libraries[backend] = build(phase, backend, repo=Path('/repo'),
                                       cache=work / 'cache')['path']
        except (StepFailed, PhaseTimeout, Interrupted) as exc:
            print(f'self-test: {backend} library build failed: {exc}', file=sys.stderr)
            failed = True
    runs = [('all', ['-v', *args.tests] if args.tests else
             ['discover', '-v', '-s', 'tests', '-t', '.'],
             libraries.get('rust') or libraries.get('reference'))]
    if 'rust' in libraries and 'reference' in libraries:
        runs.append(('abi-reference', ABI_TESTS, libraries['reference']))
    for label, selection, library in runs:
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        env.pop('LIBTPMS_LIBRARY', None)
        if library:
            env['LIBTPMS_LIBRARY'] = library
        log = args.results / f'unittest-{label}.log'
        print(f'self-test: unittest {label} (library {library or "none"}; log {log})',
              flush=True)
        with open(log, 'w') as output:
            process = subprocess.Popen([sys.executable, '-m', 'unittest', *selection],
                                       cwd=root, env=env, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True)
            for line in process.stdout:
                output.write(line)
                sys.stdout.write(line)
            failed |= process.wait() != 0
    print(f'self-test: {"FAILED" if failed else "passed"}; logs in {args.results}')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
