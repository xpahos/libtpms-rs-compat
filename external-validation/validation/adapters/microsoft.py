"""Microsoft TSS.MSR Tpm2Tester: one process per scenario with a fresh bridge.

Selection, per-scenario supervision and HTML report semantics live in
microsoft_scenarios.py; this adapter builds the upstream assembly and runs that
supervisor as the suite's execution unit.
"""
from __future__ import annotations

import sys

from ..collectors import microsoft as collector
from ..environment import (COMMAND_PORT, PHASE_GRACE, PLATFORM_PORT, SOURCES, StepFailed,
                           fetch_source)
from .base import Adapter

PROJECT = 'Tpm2Tester/TestSuite/TestSuite.csproj'
# Upstream Tpm2Tester/Directory.Build.props relocates project output here.
ASSEMBLY = 'Tpm2Tester/bin/TestSuite/Release/net8.0/Tpm2TestSuite.dll'


class MicrosoftTss(Adapter):
    name = source = 'microsoft-tss'

    def prepare(self, phase):
        source = fetch_source(phase, self.name)
        # Global MSBuild properties retarget all three original projects. No
        # upstream project or test source is changed; keep its NuGet versions.
        # --disable-build-servers: persistent MSBuild/Roslyn servers would
        # outlive the phase (and be reported as leaked processes).
        phase.run(['dotnet', 'build', '--disable-build-servers', str(source / PROJECT),
                   '--configuration', 'Release',
                   '-p:TargetFramework=net8.0', '-p:TargetFrameworks=net8.0',
                   f'-maxcpucount:{phase.jobs}'], cwd=source)
        if not (source / ASSEMBLY).exists():
            raise StepFailed(f'the build did not produce {ASSEMBLY}')

    def run(self, ctx):
        phase = ctx.phase
        source = phase.cache / 'sources' / self.name
        if not (source / ASSEMBLY).exists():
            raise StepFailed('microsoft-tss is not prepared')
        if PLATFORM_PORT != COMMAND_PORT + 1:
            raise StepFailed('the Microsoft TCP transport requires adjacent ports')
        env = dict(phase.env, PYTHONPATH=str(phase.root))
        # The supervisor finalizes its partial summary on SIGTERM, so the phase
        # gives it PHASE_GRACE seconds before cleaning up its process tree.
        ctx.execution = phase.run(
            [sys.executable, '-m', 'validation.adapters.microsoft_scenarios', 'run',
             '--results', str(ctx.suite_dir / 'scenarios'),
             '--revision', SOURCES[self.name][1], '--source', str(source),
             '--filter', ctx.filter or '',
             '--scenario-timeout', str(ctx.microsoft_test_timeout),
             '--assembly', str(source / ASSEMBLY), '--library', ctx.library,
             '--port', str(COMMAND_PORT), '--platform-port', str(PLATFORM_PORT)],
            cwd=phase.root, env=env, log=ctx.suite_dir / 'supervisor.log', check=False,
            grace=PHASE_GRACE)
        return ctx.execution

    def collect(self, suite, ctx):
        suite['artifacts']['supervisor_log'] = ctx.relative(ctx.suite_dir / 'supervisor.log')
        summary = ctx.suite_dir / 'scenarios' / 'summary.json'
        if summary.exists():
            suite['artifacts']['summary'] = ctx.relative(summary)
        collector.collect(suite, summary, prefix=ctx.relative(ctx.suite_dir),
                          termination=ctx.termination)
