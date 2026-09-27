"""Host command line: validate arguments, then run everything inside Docker.

    python3 external-validation/run.py run [--backend rust|reference|c|both] [SUITE ...]
    python3 external-validation/run.py report RESULTS_DIRECTORY
    python3 external-validation/run.py compare REFERENCE_RESULTS RUST_RESULTS
    python3 external-validation/run.py self-test

The host needs only Python and Docker. Results persist under the work
directory (default <repo>/target/external-validation, override with
EXTERNAL_VALIDATION_WORK_DIR) and survive container removal.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import time

from . import harness, results as schema
from .environment import SUITES, write_json

VALIDATION_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = VALIDATION_ROOT.parent
DEFAULT_IMAGE = 'libtpms-external-validation:local'
BACKENDS = {'rust': 'rust', 'reference': 'reference', 'c': 'reference', 'both': 'both'}
STOP_GRACE = 60   # seconds `docker stop` allows the runner to finalize


class UsageError(Exception):
    pass


def positive(value):
    try:
        number = int(value, 10)
    except (TypeError, ValueError):
        number = 0
    if str(value).strip() != str(number) or number <= 0:
        raise argparse.ArgumentTypeError(f'must be a positive integer, got {value!r}')
    return number


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise UsageError(message)


def build_parser():
    parser = Parser(prog='external-validation/run.py', description=__doc__,
                    formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest='command', required=True, parser_class=Parser)
    run = commands.add_parser('run', help='build and run upstream suites in Docker')
    run.add_argument('suites', nargs='*', metavar='SUITE',
                     help=f'{", ".join(SUITES)} or all (default)')
    run.add_argument('--backend', help='rust (default), reference (alias c), or both')
    run.add_argument('--library', type=Path,
                     help='use an existing Linux libtpms.so (single backend only)')
    run.add_argument('--filter', default='', help='suite-native test selection (one suite)')
    run.add_argument('--prepare-only', action='store_true',
                     help='fetch and compile suites without executing tests')
    run.add_argument('--timeout', type=positive, default=1800,
                     help='limit for each prepare/build/run phase in seconds (default 1800)')
    run.add_argument('--microsoft-test-timeout', type=positive, default=120,
                     help='limit for each Microsoft scenario process (default 120)')
    run.add_argument('--jobs', type=positive, help='parallel build jobs (default: CPUs)')
    run.add_argument('--image', default=DEFAULT_IMAGE)
    run.add_argument('--no-build-image', action='store_true',
                     help='reuse an already built environment image')
    report = commands.add_parser('report', help='render a persisted run')
    report.add_argument('directory', type=Path)
    compare = commands.add_parser('compare', help='compare two persisted backend results')
    compare.add_argument('reference', type=Path)
    compare.add_argument('rust', type=Path)
    compare.add_argument('--output', type=Path, help='also write the comparison JSON here')
    selftest = commands.add_parser('self-test', help='run the framework tests in Docker')
    selftest.add_argument('--abi', choices=('rust', 'reference', 'both', 'none'), default='both',
                          help='libraries for the bridge ABI tests (default both)')
    selftest.add_argument('--image', default=DEFAULT_IMAGE)
    selftest.add_argument('--no-build-image', action='store_true')
    selftest.add_argument('tests', nargs='*', help='optional unittest names')
    return parser


def resolve_run(args):
    """Validate every argument before Docker is touched; return the request."""
    suites = args.suites or ['all']
    if suites == ['all']:
        suites = list(SUITES)
    unknown = [s for s in suites if s not in SUITES]
    if unknown:
        raise UsageError(f'unknown suite: {unknown[0]} (choose from {", ".join(SUITES)} or all)')
    if 'all' in suites or len(set(suites)) != len(suites):
        raise UsageError('list each suite once, or use "all" alone')
    if args.filter and len(suites) != 1:
        raise UsageError('--filter requires exactly one suite')
    if args.backend is not None and args.backend not in BACKENDS:
        raise UsageError(f'unknown backend: {args.backend} (rust, reference, c, both)')
    library = None
    if args.library is not None:
        if args.backend is not None:
            # A single library cannot be both backends, nor silently relabelled.
            raise UsageError('--library selects its own backend; do not combine it with '
                             '--backend')
        if not args.library.is_file():
            raise UsageError(f'library does not exist: {args.library}')
        library = args.library.resolve()
        backend = 'selected'
    else:
        backend = BACKENDS[args.backend or 'rust']
    if args.prepare_only and args.filter:
        raise UsageError('--prepare-only runs no tests; --filter has no meaning')
    return {'backend': backend, 'suites': suites, 'filter': args.filter,
            'timeout': args.timeout, 'microsoft_test_timeout': args.microsoft_test_timeout,
            'jobs': args.jobs, 'prepare_only': bool(args.prepare_only),
            'library_host_path': str(library) if library else None,
            'selected_library': '/selected/libtpms.so' if library else None}


def work_directory():
    work = Path(os.environ.get('EXTERNAL_VALIDATION_WORK_DIR',
                               REPO_ROOT / 'target' / 'external-validation')).resolve()
    (work / 'cache').mkdir(parents=True, exist_ok=True)
    (work / 'results').mkdir(parents=True, exist_ok=True)
    return work


def new_run_directory(work, prefix=''):
    while True:
        run_id = prefix + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + \
            secrets.token_hex(3)
        directory = work / 'results' / run_id
        try:
            directory.mkdir()
            return run_id, directory
        except FileExistsError:
            continue


def snapshot(destination):
    shutil.copytree(VALIDATION_ROOT, destination, symlinks=True,
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '.pytest_cache'))
    return harness.digest(destination)


def docker(*args, **kwargs):
    return subprocess.run(['docker', *args], **kwargs)


def prepare_image(image, context, build, log):
    if build:
        print(f'Building image {image} (log {log})', flush=True)
        with open(log, 'wb') as output:
            result = docker('build', '-t', image, str(context), stdout=output,
                            stderr=subprocess.STDOUT)
        if result.returncode != 0:
            tail = Path(log).read_text(errors='replace').splitlines()[-20:]
            print('\n'.join(tail), file=sys.stderr)
            raise UsageError(f'docker build failed with status {result.returncode}; see {log}')
    inspected = docker('image', 'inspect', '--format', '{{.Id}}', image,
                       capture_output=True, text=True)
    if inspected.returncode != 0 or not inspected.stdout.strip():
        raise UsageError(f'image {image} is not available: {inspected.stderr.strip()}')
    return inspected.stdout.strip()


def run_container(name, docker_args, command):
    """Run the container, forwarding interruption as a bounded `docker stop`."""
    received = []

    def handler(number, _frame):
        received.append(number)

    previous = {n: signal.signal(n, handler) for n in (signal.SIGINT, signal.SIGTERM,
                                                      signal.SIGHUP)}
    stopping = False
    try:
        # Own session: a terminal Ctrl-C reaches only us; we decide how to stop.
        process = subprocess.Popen(['docker', 'run', '--rm', '--init', '--name', name,
                                    *docker_args, *command], start_new_session=True)
        while True:
            try:
                code = process.wait(timeout=0.5)
                break
            except subprocess.TimeoutExpired:
                pass
            if received and not stopping:
                stopping = True
                print(f'\nStopping container {name} (up to {STOP_GRACE}s to finalize '
                      'results)...', file=sys.stderr, flush=True)
                subprocess.Popen(['docker', 'stop', '--time', str(STOP_GRACE), name],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif len(received) > 1 and stopping:
                subprocess.run(['docker', 'kill', name], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
                received[:] = received[:1]
        return code, received[0] if received else None
    finally:
        for number, handler_ in previous.items():
            signal.signal(number, handler_)


def find_results(path):
    """Accept a run directory, a backend directory or a results.json file."""
    path = Path(path)
    if path.is_file():
        return {json.loads(path.read_text()).get('backend', path.parent.name): path}
    if (path / 'results.json').is_file():
        return {path.name: path / 'results.json'}
    found = {child.name: child / 'results.json' for child in sorted(path.iterdir())
             if (child / 'results.json').is_file()} if path.is_dir() else {}
    if not found:
        raise UsageError(f'no results.json under {path}')
    return found


def render_directory(directory):
    runs = {b: schema.load_run(json.loads(p.read_text()))
            for b, p in find_results(directory).items()}
    text = ''.join(schema.render_run(r) for r in runs.values())
    comparison = None
    if 'reference' in runs and 'rust' in runs:
        comparison = schema.compare_runs(runs['reference'], runs['rust'])
        text += schema.render_comparison(comparison)
        ok = comparison['successful']
    else:
        ok = all(r['status'] == 'PASS' and r['complete'] for r in runs.values())
    return text, ok, comparison


def command_run(args):
    request = resolve_run(args)
    if shutil.which('docker') is None:
        raise UsageError('Docker is required')
    work = work_directory()
    run_id, run_dir = new_run_directory(work)
    print(f'Results: {run_dir}', flush=True)
    # Preserve exactly the harness used by this run, even during active edits.
    harness_sha = snapshot(run_dir / 'harness')
    image_id = prepare_image(args.image, run_dir / 'harness', not args.no_build_image,
                             run_dir / 'image-build.log')
    request.update({'schema_version': schema.SCHEMA_VERSION, 'run_id': run_id,
                    'created_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                    'image': args.image, 'image_id': image_id, 'harness_sha256': harness_sha,
                    'repository': str(REPO_ROOT)})
    write_json(run_dir / 'request.json', request)
    mounts = ['-v', f'{REPO_ROOT}:/repo:ro', '-v', f'{work}:/work',
              '-v', f'{run_dir / "harness"}:/validation:ro']
    if request['library_host_path']:
        mounts += ['-v', f'{request["library_host_path"]}:/selected/libtpms.so:ro']
    env = ['-e', 'PYTHONDONTWRITEBYTECODE=1', '-e', 'PYTHONPATH=/validation',
           '-w', '/validation']
    code, received = run_container(
        f'external-validation-{run_id}', mounts + env,
        [image_id, 'python3', '-m', 'validation.runner', '--request',
         f'/work/results/{run_id}/request.json'])
    if not (run_dir / 'summary.txt').exists():
        # The container stopped before finalizing: render what was persisted.
        try:
            text, _, comparison = render_directory(run_dir)
        except (UsageError, ValueError, OSError) as exc:
            text, comparison = f'No results were persisted: {exc}\n', None
        if comparison is not None:
            write_json(run_dir / 'comparison.json', comparison)
        (run_dir / 'summary.txt').write_text(text)
        print(text, end='')
    print(f'Results: {run_dir}')
    if received and code == 0:
        return 128 + received
    return code


def command_report(args):
    text, ok, _ = render_directory(args.directory)
    print(text, end='')
    return 0 if ok else 1


def command_compare(args):
    left, right = find_results(args.reference), find_results(args.rust)
    if len(left) != 1 or len(right) != 1:
        raise UsageError('compare needs exactly one backend result on each side')
    reference = json.loads(next(iter(left.values())).read_text())
    rust = json.loads(next(iter(right.values())).read_text())
    comparison = schema.compare_runs(reference, rust)
    if args.output:
        write_json(args.output, comparison)
    print(schema.render_comparison(comparison), end='')
    return 0 if comparison['successful'] else 1


def command_self_test(args):
    if shutil.which('docker') is None:
        raise UsageError('Docker is required')
    work = work_directory()
    run_id, run_dir = new_run_directory(work, prefix='self-test-')
    print(f'Self-test results: {run_dir}', flush=True)
    snapshot(run_dir / 'harness')
    image_id = prepare_image(args.image, run_dir / 'harness', not args.no_build_image,
                             run_dir / 'image-build.log')
    code, received = run_container(
        f'external-validation-{run_id}',
        ['-v', f'{REPO_ROOT}:/repo:ro', '-v', f'{work}:/work',
         '-v', f'{run_dir / "harness"}:/validation:ro', '-e', 'PYTHONDONTWRITEBYTECODE=1',
         '-e', 'PYTHONPATH=/validation', '-w', '/validation'],
        [image_id, 'python3', '-m', 'validation.selftest', '--abi', args.abi,
         '--results', f'/work/results/{run_id}', *args.tests])
    print(f'Self-test results: {run_dir}')
    return 128 + received if received and code == 0 else code


def main(argv=None):
    try:
        args = build_parser().parse_args(argv)
        handler = {'run': command_run, 'report': command_report, 'compare': command_compare,
                   'self-test': command_self_test}[args.command]
        return handler(args)
    except UsageError as exc:
        print(f'external-validation: {exc}', file=sys.stderr)
        return 2
