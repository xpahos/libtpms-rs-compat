"""Normalize Automake `make check` evidence: selected list, .trs, .log, transport."""
from __future__ import annotations

from pathlib import Path
import re
import shutil

from .. import results as schema

# .trs :test-result: values -> normalized status. XFAIL is an expected
# failure: upstream tolerates it, but it is not a passing validation.
TRS_STATUS = {'PASS': 'PASS', 'SKIP': 'SKIPPED', 'FAIL': 'FAIL', 'XFAIL': 'FAIL',
              'XPASS': 'FAIL', 'ERROR': 'ERROR'}


def tools_transport(log, required):
    """How a tpm2-tools test reached the TPM, from the upstream helpers' output."""
    if not log.exists():
        return 'missing-log'
    text = log.read_text(errors='replace')
    if 'creating simulator working dir' not in text:
        return 'none'
    exported = re.findall(r'^export TPM2TOOLS_TCTI="([^"]*)"', text, re.M)
    if 'not starting abrmd' in text or any(not t.startswith(required + ':') for t in exported):
        return 'direct'
    return required if exported else 'startup-failed'


def parse_trs(path):
    """Return (global result, case results) or raise ValueError when malformed."""
    lines = path.read_text(errors='replace').splitlines()
    globals_ = [l.split(':', 2)[2].strip() for l in lines
                if l.startswith(':global-test-result:')]
    cases = [l.split(':', 2)[2].strip().split()[0] for l in lines
             if l.startswith(':test-result:') and l.split(':', 2)[2].strip()]
    if len(globals_) != 1:
        raise ValueError(f'{len(globals_)} :global-test-result: lines')
    unknown = [v for v in [globals_[0], *cases] if v not in TRS_STATUS]
    if unknown:
        raise ValueError(f'unknown result {unknown[0]!r}')
    return globals_[0], cases


def last_lines(path, count=3):
    if not path.exists():
        return ''
    lines = [l.strip() for l in path.read_text(errors='replace').splitlines() if l.strip()]
    return ' | '.join(lines[-count:])[:500]


def collect(suite, ctx, *, build_dir, required_tcti=None):
    """Normalize selected tests from .trs/.log evidence, even after a timeout."""
    name = suite['name']
    run_dir = ctx.suite_dir
    selected_file = run_dir / 'selected.txt'
    if not selected_file.exists():
        suite['issues'].append(schema.issue('no-selection', ctx.error or
                                            'no tests were selected', incomplete=True))
        return
    selected = selected_file.read_text().split()
    suite['selection'] = {'filter': ctx.filter, 'selected': selected,
                          'candidates': str(ctx.relative(run_dir / 'candidates.txt'))}
    termination = ctx.termination
    native = {}
    for test in selected:
        trs = build_dir / Path(test).with_suffix('.trs')
        log = build_dir / Path(test).with_suffix('.log')
        artifacts = {}
        for source in (trs, log, build_dir / (test + '_simulator.log')):
            if source.exists():
                destination = run_dir / 'tests' / source.relative_to(build_dir)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
                key = ('report' if source.suffix == '.trs' else
                       'simulator_log' if source.name.endswith('_simulator.log') else 'log')
                artifacts[key] = ctx.relative(destination)
        details, native_status = {}, None
        if trs.exists() and trs.stat().st_mtime < ctx.started - 1:
            status, reason = 'ERROR', 'stale .trs predates this run'
        elif trs.exists():
            try:
                native_status, cases = parse_trs(trs)
            except ValueError as exc:
                status, reason = 'ERROR', f'malformed .trs: {exc}'
            else:
                details['cases'] = cases
                details['signature'] = {'cases': cases}
                case_status = schema.worst(TRS_STATUS[c] for c in cases)
                status = schema.worst([TRS_STATUS[native_status]]
                                      + ([case_status] if case_status else []))
                reason = '' if status == 'PASS' else last_lines(log)
                if native_status == 'XFAIL' or 'XFAIL' in cases:
                    reason = 'expected failure (XFAIL) is not a pass; ' + reason
                if not cases:
                    status, reason = 'ERROR', '.trs lists no test cases'
        elif termination in ('timeout', 'interrupted'):
            if log.exists():
                status = 'TIMEOUT' if termination == 'timeout' else 'INTERRUPTED'
                reason = 'phase stopped while this test was running'
            else:
                status, reason = 'NOT_RUN', 'phase stopped before this test started'
        else:
            status, reason = 'ERROR', 'no .trs result for a selected test'
        native[native_status or 'MISSING'] = native.get(native_status or 'MISSING', 0) + 1
        if required_tcti:
            transport = tools_transport(log, required_tcti)
            details['transport'] = transport
            details.setdefault('signature', {})['transport'] = transport
            if transport not in (required_tcti, 'none') and status in ('PASS', 'SKIPPED'):
                status = 'ERROR'
                reason = (f'transport {transport}: not run through the {required_tcti} '
                          'resource manager')
        suite['tests'].append(schema.test_result(
            name, test, status, name=Path(test).name, native_status=native_status,
            reason=reason, details=details, execution='run', artifacts=artifacts))
    suite['native_counts'] = native
    execution = ctx.execution
    if execution and termination == 'completed':
        failures = [t for t in suite['tests'] if t['status'] != 'PASS']
        if execution['exit_code'] != 0 and not failures:
            suite['issues'].append(schema.issue(
                'make-check', f'make check exited {execution["exit_code"]} although every '
                'selected test passed'))
        if execution['exit_code'] == 0 and any(t['status'] in ('FAIL', 'ERROR')
                                              for t in failures):
            suite['issues'].append(schema.issue(
                'make-check', 'make check exited 0 despite failing tests', severity='warning'))
