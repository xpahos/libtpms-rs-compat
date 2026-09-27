"""Pinned sources, container paths and bounded phase execution."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import time

from . import processes

SUITES = ('tpm2-tss', 'tpm2-tools', 'google-go-tpm', 'canonical-go-tpm2', 'microsoft-tss')

# Every upstream checkout, including dependencies that are not suites.
SOURCES = {
    'tpm2-tss': ('https://github.com/tpm2-software/tpm2-tss.git',
                 'f097faf482dfb4966f96dc7ebe4354a86c9e05ab'),
    'tpm2-abrmd': ('https://github.com/tpm2-software/tpm2-abrmd.git',
                   '2928d8e95553395071c60ea235cbdaf1220ced35'),  # 3.0.0
    'tpm2-tools': ('https://github.com/tpm2-software/tpm2-tools.git',
                   '574eb683ea035317d1de440c7ac63bd7b25da6b9'),
    'google-go-tpm': ('https://github.com/google/go-tpm.git',
                      '9f0977c7f65a2d778e895ebeb35440b2a707eaf4'),
    'canonical-go-tpm2': ('https://github.com/canonical/go-tpm2.git',
                          '3a95914590b71c8914b4c4dc79e0de0f426f11b3'),
    'microsoft-tss': ('https://github.com/microsoft/TSS.MSR.git',
                      '52cb9f432318e8e95cdfeaf98b824ece89370744'),
}

COMMAND_PORT, PLATFORM_PORT = 2321, 2322
# Grace for a supervising child (Microsoft) to finalize after SIGTERM, as the
# former `timeout --kill-after=15` allowed.
PHASE_GRACE = 15


class StepFailed(Exception):
    """A preparation command failed; the execution evidence is attached."""

    def __init__(self, message, execution=None):
        super().__init__(message)
        self.execution = execution


class Interrupted(Exception):
    """A signal stopped the current phase; the runner finalizes partial results."""

    def __init__(self, execution=None):
        super().__init__('interrupted')
        self.execution = execution


class PhaseTimeout(Exception):
    def __init__(self, execution=None):
        super().__init__('phase timed out')
        self.execution = execution


def write_json(path, value):
    """Atomically replace a JSON file (readers never see a partial document)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f'.{path.name}.{os.getpid()}.tmp')
    with open(temporary, 'w') as output:
        json.dump(value, output, indent=2, sort_keys=False)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def base_environment(root, cache):
    """Environment shared by all upstream commands (formerly common.sh)."""
    env = dict(os.environ)
    install = Path(cache) / 'install'
    env['PATH'] = os.pathsep.join([str(Path(root) / 'bin'), str(install / 'bin'),
                                   str(install / 'sbin'), env.get('PATH', '')])
    for name, value in (('PKG_CONFIG_PATH', install / 'lib' / 'pkgconfig'),
                        ('LD_LIBRARY_PATH', install / 'lib')):
        env[name] = os.pathsep.join(filter(None, [str(value), env.get(name, '')]))
    env['TPM_COMMAND_PORT'], env['TPM_PLATFORM_PORT'] = str(COMMAND_PORT), str(PLATFORM_PORT)
    return env


class Phase:
    """One prepare or run phase: a shared deadline and one log for its commands."""

    def __init__(self, *, root, cache, log, timeout, jobs, env=None):
        self.root = Path(root)
        self.cache = Path(cache)
        self.log = Path(log)
        self.timeout = timeout
        self.jobs = jobs
        self.deadline = time.monotonic() + timeout
        self.env = env or base_environment(root, cache)
        self.executions = []
        self.log.parent.mkdir(parents=True, exist_ok=True)
        self.log.write_bytes(b'')

    def remaining(self):
        return self.deadline - time.monotonic()

    def note(self, text):
        with self.log.open('a') as output:
            output.write(text.rstrip('\n') + '\n')

    def run(self, argv, *, cwd, env=None, log=None, check=True, grace=5, limit=None):
        """Run one command within the phase deadline and record its evidence.

        `limit` bounds this step alone; exceeding it is a step failure, whereas
        exhausting the phase deadline is a phase timeout.
        """
        remaining = self.remaining()
        if remaining <= 0:
            raise PhaseTimeout()
        step_limited = limit is not None and limit < remaining
        if step_limited:
            remaining = limit
        target = Path(log) if log else self.log
        if log is None:
            self.note('$ ' + ' '.join(map(str, argv)) + f'    (cwd {cwd})')
        execution = processes.run_process(argv, cwd=cwd, env=env or self.env, log=target,
                                          timeout=remaining, grace=grace,
                                          append=log is None)
        execution['argv'] = [str(a) for a in argv]
        execution['log'] = str(target)
        self.executions.append(execution)
        if execution['termination'] == 'interrupted':
            raise Interrupted(execution)
        if execution['termination'] == 'timeout':
            if step_limited:
                raise StepFailed(f'{Path(str(argv[0])).name} did not finish within '
                                 f'{limit}s', execution)
            raise PhaseTimeout(execution)
        if check and execution['exit_code'] != 0:
            raise StepFailed(f'{Path(str(argv[0])).name} exited with status '
                             f'{execution["exit_code"]}', execution)
        return execution

    def capture(self, argv, *, cwd, env=None):
        """Run a short query command and return its output text."""
        output = self.log.with_name(self.log.name + '.capture')
        try:
            self.run(argv, cwd=cwd, env=env, log=output)
            return output.read_text(errors='replace')
        finally:
            output.unlink(missing_ok=True)


def fetch_source(phase, name):
    """Clone/fetch a pinned upstream checkout and refuse modified sources."""
    url, revision = SOURCES[name]
    if not re.fullmatch(r'[a-z0-9-]+', name) or not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise StepFailed(f'invalid pinned source: {name} {revision}')
    source = phase.cache / 'sources' / name
    cwd = phase.cache
    if not (source / '.git').is_dir():
        if source.exists():
            raise StepFailed(f'not a checkout: {source}')
        source.parent.mkdir(parents=True, exist_ok=True)
        phase.run(['git', 'clone', '--no-checkout', url, str(source)], cwd=cwd)
    else:
        assert_unmodified(phase, source)
        origin = phase.capture(['git', '-C', str(source), 'remote', 'get-url', 'origin'],
                               cwd=cwd).strip()
        if origin != url:
            raise StepFailed(f'unexpected source origin {origin} for {source}')
    # Autotools upstream derives package versions from reachable release tags.
    if phase.capture(['git', '-C', str(source), 'rev-parse', '--is-shallow-repository'],
                     cwd=cwd).strip() == 'true':
        phase.run(['git', '-C', str(source), 'fetch', '--unshallow', '--tags', 'origin'], cwd=cwd)
    present = phase.run(['git', '-C', str(source), 'cat-file', '-e', revision + '^{commit}'],
                        cwd=cwd, check=False)
    if present['exit_code'] != 0:
        phase.run(['git', '-C', str(source), 'fetch', 'origin', revision], cwd=cwd)
    phase.run(['git', '-C', str(source), 'checkout', '--detach', revision], cwd=cwd)
    head = phase.capture(['git', '-C', str(source), 'rev-parse', 'HEAD'], cwd=cwd).strip()
    if head != revision:
        raise StepFailed(f'{name} is at {head}, expected {revision}')
    return source


def assert_unmodified(phase, source):
    result = phase.run(['git', '-C', str(source), 'diff', '--quiet', 'HEAD', '--'],
                       cwd=phase.cache, check=False)
    if result['exit_code'] != 0:
        raise StepFailed(f'refusing modified upstream source: {source}')
