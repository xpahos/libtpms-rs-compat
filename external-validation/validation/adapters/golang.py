"""Google go-tpm and Canonical go-tpm2: compiled upstream Go test packages.

Each package runs as one native test binary under `go tool test2json`, keeping
the upstream simulator lifecycle: Google launches the bridge per test through
-tpm-sim-path; Canonical's TestMain launches `tpm2-simulator -m <port>` once and
its gocheck fixtures reset it between tests.
"""
from __future__ import annotations

from pathlib import Path
import shutil
import tempfile

from ..collectors import gocheck, gotest
from ..environment import COMMAND_PORT, PLATFORM_PORT, SOURCES, StepFailed, fetch_source
from .. import results as schema
from .base import Adapter


class GoPackage(Adapter):
    package = ''       # package directory relative to the checkout
    import_path = ''   # label for test2json events

    def binary(self, cache):
        return Path(cache) / 'builds' / self.name / 'tpm2.test'

    def prepare(self, phase):
        source = fetch_source(phase, self.name)
        build = phase.cache / 'builds' / self.name
        build.mkdir(parents=True, exist_ok=True)
        phase.run(['go', 'mod', 'download'], cwd=source)
        # Vet is separate from execution; recent Go versions reject upstream
        # formatting patterns, so compile the unchanged tests without it.
        phase.run(['go', 'test', '-c', '-mod=readonly', '-vet=off', '-p', str(phase.jobs),
                   '-o', str(self.binary(phase.cache)), './' + self.package if self.package
                   else '.'], cwd=source)
        (build / 'revision').write_text(SOURCES[self.name][1] + '\n')

    def arguments(self, ctx):
        raise NotImplementedError

    def run(self, ctx):
        phase = ctx.phase
        binary = self.binary(phase.cache)
        revision = binary.parent / 'revision'
        if not binary.exists() or not revision.exists() or \
                revision.read_text().strip() != SOURCES[self.name][1]:
            raise StepFailed(f'{self.name} is not prepared at the pinned revision')
        source = phase.cache / 'sources' / self.name
        env = dict(phase.env, LIBTPMS_LIBRARY=ctx.library)
        args = ['-test.v=test2json', '-test.timeout=60m', *self.arguments(ctx, env)]
        if ctx.filter:
            args.append(f'-test.run={ctx.filter}')
        (ctx.suite_dir / 'events.jsonl').unlink(missing_ok=True)
        try:
            ctx.execution = phase.run(
                ['go', 'tool', 'test2json', '-t', '-p', self.import_path, str(binary), *args],
                cwd=source / self.package, env=env, log=ctx.suite_dir / 'events.jsonl',
                check=False)
        finally:
            self.cleanup(ctx)
        return ctx.execution

    def cleanup(self, ctx):
        pass

    def collect(self, suite, ctx):
        path = ctx.suite_dir / 'events.jsonl'
        suite['selection'] = {'filter': ctx.filter, 'native': '-test.run'}
        if not path.exists():
            suite['issues'].append(schema.issue('no-events', ctx.error or 'the Go test binary '
                                                'did not run', incomplete=True))
            return
        events, malformed = gotest.parse_events(path.read_text(errors='replace'))
        console = ctx.suite_dir / 'console.log'
        console.write_text(gotest.console_text(events) + ''.join(
            f'[non-JSON line {m}]\n' for m in malformed))
        artifacts = {'log': ctx.relative(console), 'report': ctx.relative(path)}
        suite['artifacts'].update(artifacts)
        if malformed:
            suite['issues'].append(schema.issue('malformed', f'{len(malformed)} lines of the '
                                                'test2json stream are not JSON events',
                                                examples=malformed[:3]))
        execution = ctx.execution or {}
        tests, _ = gotest.collect(suite, events, termination=ctx.termination,
                                  exit_code=execution.get('exit_code'), artifacts=artifacts)
        self.collect_nested(suite, ctx, tests, artifacts)

    def collect_nested(self, suite, ctx, tests, artifacts):
        pass


class GoogleGoTpm(GoPackage):
    name = source = 'google-go-tpm'
    package = 'tpm2/test'
    import_path = 'github.com/google/go-tpm/tpm2/test'

    def arguments(self, ctx, env):
        # The explicit simulator path prevents the upstream embedded TPM fallback.
        return [f'-tpm-sim-path={ctx.phase.root / "bridge.py"}']


class CanonicalGoTpm2(GoPackage):
    name = source = 'canonical-go-tpm2'
    package = ''
    import_path = 'github.com/canonical/go-tpm2'
    wrapper = 'Test'   # func Test(t *testing.T) { check.TestingT(t) }

    def arguments(self, ctx, env):
        if PLATFORM_PORT != COMMAND_PORT + 1:
            raise StepFailed('canonical-go-tpm2 requires the platform port immediately '
                             'after the command port')
        bin_dir = ctx.phase.cache / 'builds' / self.name / 'bin'
        bin_dir.mkdir(parents=True, exist_ok=True)
        # Upstream TestMain launches this name itself with '-m <port>'. Keep that
        # lifecycle unchanged instead of starting a second simulator.
        link = bin_dir / 'tpm2-simulator'
        link.unlink(missing_ok=True)
        link.symlink_to(ctx.phase.root / 'bridge.py')
        runtime = Path(tempfile.mkdtemp(prefix='canonical-runtime.', dir=ctx.suite_dir))
        ctx.notes['runtime'] = runtime
        env['PATH'] = f'{bin_dir}:{env["PATH"]}'
        env['XDG_RUNTIME_DIR'] = str(runtime)
        return ['-check.v', '-use-mssim', f'-mssim-port={COMMAND_PORT}']

    def cleanup(self, ctx):
        runtime = ctx.notes.pop('runtime', None)
        if runtime:
            shutil.rmtree(runtime, ignore_errors=True)

    def collect_nested(self, suite, ctx, tests, artifacts):
        wrapper = tests.get(self.wrapper)
        if wrapper is None:
            if not ctx.filter and ctx.termination == 'completed':
                suite['issues'].append(schema.issue('gocheck', 'the gocheck wrapper Test did '
                                                    'not run', incomplete=True))
            return
        record = next(t for t in suite['tests'] if t['id'] == f'{self.name}:{self.wrapper}')
        # The wrapper only hosts gocheck; its cases are the tests.
        record['kind'], record['counted'] = 'group', False
        gocheck.collect(suite, ''.join(wrapper['output']), parent=self.wrapper,
                        termination=ctx.termination, artifacts=artifacts)
