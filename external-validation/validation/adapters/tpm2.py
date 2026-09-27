"""tpm2-tss and tpm2-tools: unchanged upstream Automake integration tests.

tpm2-tools reaches the bridge through the pinned resource manager exactly as the
upstream helpers expect:
    tpm2-tools -> tabrmd TCTI -> tpm2-abrmd -> mssim TCTI -> bridge -> libtpms
"""
from __future__ import annotations

from pathlib import Path

from ..environment import SOURCES, StepFailed, assert_unmodified, fetch_source
from . import automake
from .base import Adapter

TSS_CONFIGURE = ['--enable-integration', '--with-integrationtcti=mssim',
                 '--disable-fapi', '--disable-policy', '--disable-unit',
                 '--disable-tcti-swtpm', '--disable-tcti-libtpms', '--disable-tcti-device',
                 '--disable-tcti-spi-ltt2go', '--disable-tcti-spidev',
                 '--disable-tcti-spi-ftdi', '--disable-tcti-i2c-ftdi']
# tpm2-tools tests may never be pre-pointed at a TCTI or an outside D-Bus.
TOOLS_UNSET = ('TPM2TOOLS_TCTI', 'TPM2TOOLS_TEST_TCTI', 'TPM2ABRMD_TCTI', 'TPM2_SIMPORT',
               'TCTI', 'TSS2_TCTI', 'DBUS_SESSION_BUS_ADDRESS', 'DBUS_SYSTEM_BUS_ADDRESS')


def marker(cache, name):
    return Path(cache) / 'builds' / name / '.validation-prepared'


def prepared(cache, name):
    path = marker(cache, name)
    return path.exists() and path.read_text().strip() == SOURCES[name][1]


def autotools(phase, name, configure, *, make_goals=((),), install=True):
    """bootstrap/configure/make/install one pinned checkout into the cache prefix."""
    source = fetch_source(phase, name)
    build = phase.cache / 'builds' / name
    prefix = phase.cache / 'install'
    phase.run(['./bootstrap'], cwd=source)
    assert_unmodified(phase, source)
    build.mkdir(parents=True, exist_ok=True)
    phase.run([str(source / 'configure'), f'--prefix={prefix}', f'--libdir={prefix}/lib',
               *configure], cwd=build)
    for goals in make_goals:
        phase.run(['make', f'-j{phase.jobs}', *goals], cwd=build)
    if install:
        phase.run(['make', 'install'], cwd=build)
    assert_unmodified(phase, source)
    marker(phase.cache, name).write_text(SOURCES[name][1] + '\n')


def prepare_tss(phase):
    # Upstream `all` recurses into make; combining it with check-programs
    # races the recursive library build against the outer check build.
    autotools(phase, 'tpm2-tss', TSS_CONFIGURE, make_goals=(('all',), ('check-programs',)))


def prepare_abrmd(phase):
    # System-bus policy and systemd units stay inside the private prefix; the
    # tests only ever use a per-test session bus.
    prefix = phase.cache / 'install'
    autotools(phase, 'tpm2-abrmd', ['--disable-unit', '--with-systemdsystemunitdir=no',
                                    f'--with-dbuspolicydir={prefix}/etc/dbus-1/system.d'])


class Tpm2Tss(Adapter):
    name = source = 'tpm2-tss'

    def prepare(self, phase):
        prepare_tss(phase)

    def build_dir(self, cache):
        return Path(cache) / 'builds' / 'tpm2-tss'

    def run(self, ctx):
        phase = ctx.phase
        if not prepared(phase.cache, 'tpm2-tss'):
            raise StepFailed('tpm2-tss is not prepared')
        build = self.build_dir(phase.cache)
        tests = automake.select(phase, build, 'TESTS_INTEGRATION', ctx.filter, ctx.suite_dir)
        # The upstream runner owns per-test simulator (bin/tpm_server) lifecycle.
        ctx.execution = automake.check(phase, build, tests, [],
                                       ctx.suite_dir / 'console.log')
        return ctx.execution

    def collect(self, suite, ctx):
        automake.collect(suite, ctx, build_dir=self.build_dir(ctx.phase.cache))
        suite['artifacts']['console'] = ctx.relative(ctx.suite_dir / 'console.log')


class Tpm2Tools(Adapter):
    name = source = 'tpm2-tools'

    def prepare(self, phase):
        # Build the pinned client stack and resource manager if this cache lacks them.
        if not prepared(phase.cache, 'tpm2-tss'):
            prepare_tss(phase)
        if not prepared(phase.cache, 'tpm2-abrmd'):
            prepare_abrmd(phase)
        autotools(phase, 'tpm2-tools', ['--enable-unit', '--disable-fapi',
                                        '--with-tpmsim=tpm_server'], install=True)

    def build_dir(self, cache):
        return Path(cache) / 'builds' / 'tpm2-tools'

    def run(self, ctx):
        phase = ctx.phase
        prefix = phase.cache / 'install'
        abrmd, tcti = prefix / 'sbin' / 'tpm2-abrmd', prefix / 'lib' / 'libtss2-tcti-tabrmd.so.0'
        build, source = self.build_dir(phase.cache), phase.cache / 'sources' / 'tpm2-tools'
        if not prepared(phase.cache, 'tpm2-tools'):
            raise StepFailed('tpm2-tools is not prepared')
        if not (abrmd.exists() and tcti.exists()):
            raise StepFailed('tpm2-abrmd is not prepared')
        # Only the upstream helpers may choose the TCTI; nothing may preselect mssim.
        env = automake.environment_without(phase.env, TOOLS_UNSET)
        # Record which daemon and client TCTI will run, and refuse a TSS mismatch.
        report = ctx.suite_dir / 'abrmd-environment.txt'
        report.write_text(f'daemon: {abrmd}\n'
                          + phase.capture([str(abrmd), '--version'], cwd=prefix, env=env)
                          + phase.capture(['sha256sum', str(abrmd), str(tcti)], cwd=prefix))
        foreign = automake.ldd_outside(phase, (abrmd, tcti), prefix, report)
        if foreign:
            raise StepFailed('; '.join(foreign))
        # Fail once, clearly, if the resource manager cannot start, instead of
        # letting every test report the same startup failure. One TPM round trip
        # through the upstream helpers' own start_up, under dbus-run-session
        # exactly like each upstream test.
        preflight = ctx.suite_dir / 'abrmd-preflight.log'
        preflight_env = dict(env, TPM2_ABRMD=str(abrmd), TPM2_SIM='tpm_server',
                             PATH=':'.join([str(build / 'tools'), str(build / 'tools' / 'misc'),
                                            str(source / 'test' / 'integration'), env['PATH']]))
        result = phase.run(['dbus-run-session', '--', 'bash', '-c',
                            'source helpers.sh; start_up; tpm2 getrandom --hex 16'],
                           cwd=build, env=preflight_env, log=preflight, check=False,
                           limit=60)
        text = preflight.read_text(errors='replace')
        if (result['exit_code'] != 0 or
                'export TPM2TOOLS_TCTI="tabrmd:bus_type=session,' not in text):
            raise StepFailed(f'tpm2-abrmd preflight failed (exit {result["exit_code"]}); '
                             f'see {ctx.relative(preflight)}')
        phase.note(f'tpm2-abrmd preflight passed; see {preflight}')
        tests = automake.select(phase, build, 'ALL_SYSTEM_TESTS', ctx.filter, ctx.suite_dir)
        # The upstream runner owns per-test D-Bus, bridge and resource-manager
        # startup/cleanup; every TPM-using test log must show the tabrmd TCTI.
        phase.env, saved = env, phase.env
        try:
            ctx.execution = automake.check(phase, build, tests,
                                           [f'TPM2_ABRMD={abrmd}', 'TPM2_SIM=tpm_server'],
                                           ctx.suite_dir / 'console.log')
        finally:
            phase.env = saved
        return ctx.execution

    def collect(self, suite, ctx):
        automake.collect(suite, ctx, build_dir=self.build_dir(ctx.phase.cache),
                         required_tcti='tabrmd')
        for name in ('console.log', 'abrmd-environment.txt', 'abrmd-preflight.log'):
            path = ctx.suite_dir / name
            if path.exists():
                suite['artifacts'][name.rsplit('.', 1)[0]] = ctx.relative(path)
        transports = {}
        for test in suite['tests']:
            transport = test['details'].get('transport')
            transports[transport] = transports.get(transport, 0) + 1
        suite['selection']['transports'] = transports
