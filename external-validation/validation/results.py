"""Versioned result schema, aggregation, console rendering and comparison.

A backend run is persisted as `results.json`:

    {schema_version, run_id, backend, metadata, state, status, complete,
     counts, fixture_counts, phases, issues, suites: [suite, ...]}

A suite keeps process evidence (`phases`, `executions`) separate from parsed
test evidence (`tests`), plus parser/infrastructure `issues`. Aggregates are
always derived here from that evidence, never taken from adapters.
"""
from __future__ import annotations

import copy

SCHEMA_VERSION = 1
STATUSES = ('PASS', 'FAIL', 'SKIPPED', 'ERROR', 'TIMEOUT', 'INTERRUPTED', 'NOT_RUN')
# Aggregation precedence: the first status present wins.
SEVERITY = ('ERROR', 'FAIL', 'TIMEOUT', 'INTERRUPTED', 'NOT_RUN', 'SKIPPED', 'PASS')
KINDS = ('test', 'group', 'fixture')
UNFINISHED = ('NOT_RUN', 'INTERRUPTED')


def worst(statuses):
    present = set(statuses)
    for status in SEVERITY:
        if status in present:
            return status
    return None


def issue(code, message, *, severity='error', path=None, incomplete=False, **details):
    entry = {'severity': severity, 'code': code, 'message': message}
    if path:
        entry['path'] = str(path)
    if incomplete:
        entry['incomplete'] = True
    if details:
        entry['details'] = details
    return entry


def test_result(suite, native_id, status, *, name=None, parent=None, kind='test',
                native_status=None, reason='', details=None, duration=None,
                execution=None, artifacts=None, counted=None):
    if status not in STATUSES:
        raise ValueError(f'unknown status {status!r}')
    if kind not in KINDS:
        raise ValueError(f'unknown kind {kind!r}')
    return {
        'id': f'{suite}:{native_id}',
        'name': name or native_id,
        'suite': suite,
        'parent_id': f'{suite}:{parent}' if parent else None,
        'kind': kind,
        'counted': (kind == 'test') if counted is None else counted,
        'status': status,
        'native_status': native_status,
        'reason': reason or '',
        'details': details or {},
        'duration_seconds': duration,
        'execution': execution,
        'artifacts': artifacts or {},
    }


def new_suite(name, revision=None):
    return {'name': name, 'revision': revision, 'state': 'pending', 'status': None,
            'complete': False, 'selection': {}, 'phases': [], 'executions': [],
            'tests': [], 'counts': {}, 'fixture_counts': {}, 'native_counts': {},
            'issues': [], 'artifacts': {}}


def phase_record(name, status, *, execution=None, log=None, reason='', shared=False):
    record = {'name': name, 'status': status, 'reason': reason, 'log': log,
              'shared': shared}
    if execution is not None:
        record['execution'] = {k: execution[k] for k in
                               ('exit_code', 'termination', 'duration_seconds',
                                'cleanup_failed', 'signal', 'child_exit_code')
                               if k in execution}
    return record


def new_run(run_id, backend, metadata, suites):
    return {'schema_version': SCHEMA_VERSION, 'run_id': run_id, 'backend': backend,
            'metadata': metadata, 'state': 'pending', 'status': None, 'complete': False,
            'counts': {}, 'fixture_counts': {}, 'phases': [], 'issues': [],
            'suites': [new_suite(name, metadata.get('sources', {}).get(name, {})
                                 .get('revision')) for name in suites]}


def _count(tests):
    counts = {}
    for test in tests:
        counts[test['status']] = counts.get(test['status'], 0) + 1
    return counts


def unexplained_group_failures(tests):
    """Groups whose own non-pass status is not explained by a child's."""
    children = {}
    for test in tests:
        if test['parent_id']:
            children.setdefault(test['parent_id'], []).append(test)
    return [t for t in tests if t['kind'] == 'group' and t['status'] != 'PASS'
            and not any(c['status'] != 'PASS' for c in children.get(t['id'], []))]


def finalize_suite(suite):
    """Derive status, completeness and counts from phases, tests and issues."""
    tests = suite['tests']
    if suite['state'] == 'running':
        # The runner stopped (signal or crash) before finishing this suite.
        suite['state'] = 'finished'
        suite['issues'].append(issue('interrupted', 'suite did not finish', severity='warning',
                                     incomplete=True))
        if not any(p['status'] == 'INTERRUPTED' for p in suite['phases']):
            suite['phases'].append(phase_record('run', 'INTERRUPTED',
                                                reason='runner stopped before completion'))
    for test in tests:
        if test['kind'] == 'group' and not test.get('explicit_count'):
            test['counted'] = False
    for group in unexplained_group_failures(tests):
        # A parent that failed by itself is a real result; count it once.
        group['counted'] = True
        group['reason'] = group['reason'] or 'failed outside its subtests'
    counted = [t for t in tests if t['counted']]
    suite['counts'] = _count(counted)
    suite['fixture_counts'] = _count([t for t in tests if t['kind'] == 'fixture'])
    if suite['state'] == 'pending':
        suite['status'], suite['complete'] = 'NOT_RUN', False
        return suite
    statuses = [p['status'] for p in suite['phases']]
    if 'INTERRUPTED' in statuses:
        status = 'INTERRUPTED'
    elif 'TIMEOUT' in statuses:
        status = 'TIMEOUT'
    else:
        considered = [t['status'] for t in tests if t['counted'] or t['kind'] == 'fixture']
        considered += [s for s in statuses if s != 'PASS']
        if any(i['severity'] == 'error' for i in suite['issues']):
            considered.append('ERROR')
        if not counted:
            considered.append('ERROR')
            if not any(i['code'] == 'no-tests' for i in suite['issues']):
                suite['issues'].append(issue('no-tests', 'no reported tests; an empty '
                                             'result is not a validation', incomplete=True))
        status = worst(considered) or 'ERROR'
    suite['status'] = status
    suite['complete'] = (status not in UNFINISHED + ('TIMEOUT',)
                         and not any(p['status'] in UNFINISHED + ('TIMEOUT',)
                                     for p in suite['phases'])
                         and not any(t['status'] in UNFINISHED for t in tests)
                         and not any(i.get('incomplete') for i in suite['issues']))
    if status == 'TIMEOUT':
        suite['complete'] = False
    return suite


def finalize_run(run):
    for suite in run['suites']:
        finalize_suite(suite)
    if run['state'] == 'running':
        run['state'] = 'finished'
        run['issues'].append(issue('interrupted', 'runner stopped before completion',
                                   severity='warning', incomplete=True))
    counts, fixtures = {}, {}
    for suite in run['suites']:
        for key, value in suite['counts'].items():
            counts[key] = counts.get(key, 0) + value
        for key, value in suite['fixture_counts'].items():
            fixtures[key] = fixtures.get(key, 0) + value
    run['counts'], run['fixture_counts'] = counts, fixtures
    considered = [s['status'] for s in run['suites']]
    considered += [p['status'] for p in run['phases'] if p['status'] != 'PASS']
    if any(i['severity'] == 'error' for i in run['issues']):
        considered.append('ERROR')
    if not run['suites']:
        considered.append('ERROR')
    run['status'] = worst(considered) or 'ERROR'
    prepare_only = run['metadata'].get('request', {}).get('prepare_only')
    if prepare_only:
        # Preparation success is never a validation result.
        run['status'] = 'NOT_RUN' if run['status'] == 'PASS' else run['status']
    run['complete'] = (run['state'] == 'finished' and not prepare_only
                       and all(s['complete'] for s in run['suites'])
                       and not any(i.get('incomplete') for i in run['issues'])
                       and not any(p['status'] != 'PASS' for p in run['phases']))
    return run


def load_run(value):
    """Finalize a persisted run, e.g. one left behind by a killed runner."""
    run = copy.deepcopy(value)
    if run.get('schema_version') != SCHEMA_VERSION:
        raise ValueError(f'unsupported schema_version {run.get("schema_version")!r}')
    return finalize_run(run)


# ------------------------------------------------------------------ rendering

def _counts_text(counts):
    return ' '.join(f'{s}={counts[s]}' for s in STATUSES if counts.get(s)) or 'no tests'


def render_run(run, limit=25):
    meta = run['metadata']
    library = meta.get('library') or {}
    lines = [f'Backend {run["backend"]}: {run["status"]}'
             f'{"" if run["complete"] else " (incomplete)"} -- {_counts_text(run["counts"])}']
    if run.get('fixture_counts'):
        lines[0] += f'; fixtures {_counts_text(run["fixture_counts"])}'
    if library.get('sha256'):
        lines.append(f'  library {library.get("path")} sha256 {library["sha256"][:16]}... '
                     f'{library.get("identity", "")}'.rstrip())
    for phase in run['phases']:
        if phase['status'] != 'PASS':
            lines.append(f'  {phase["name"]}: {phase["status"]} {phase.get("reason", "")}'
                         .rstrip() + (f' ({phase["log"]})' if phase.get('log') else ''))
    for item in run['issues']:
        lines.append(f'  issue [{item["code"]}] {item["message"]}')
    for suite in run['suites']:
        lines.append(f'  {suite["name"]:<18} {suite["status"]:<11} '
                     f'{"complete" if suite["complete"] else "INCOMPLETE":<10} '
                     f'{_counts_text(suite["counts"])}'
                     + (f'; fixtures {_counts_text(suite["fixture_counts"])}'
                        if suite['fixture_counts'] else ''))
        for phase in suite['phases']:
            if phase['status'] != 'PASS':
                lines.append(f'      {phase["name"]}: {phase["status"]} '
                             f'{phase.get("reason", "")}'.rstrip()
                             + (f' ({phase["log"]})' if phase.get('log') else ''))
        for item in suite['issues']:
            lines.append(f'      issue [{item["code"]}] {item["message"]}'
                         + (f' ({item["path"]})' if item.get('path') else ''))
        shown = [t for t in suite['tests'] if t['status'] != 'PASS'
                 and (t['counted'] or t['kind'] == 'fixture')]
        for test in shown[:limit]:
            reason = f' -- {test["reason"]}' if test['reason'] else ''
            kind = '' if test['kind'] == 'test' else f' [{test["kind"]}]'
            lines.append(f'      {test["status"]:<11} {test["name"]}{kind}{reason}'[:400])
        if len(shown) > limit:
            lines.append(f'      ... {len(shown) - limit} more unsuccessful; see results.json')
    return '\n'.join(lines) + '\n'


# ----------------------------------------------------------------- comparison

def _comparable(run):
    """Counted tests and fixtures by stable ID; duplicates are reported."""
    tests, duplicates = {}, []
    for suite in run['suites']:
        for test in suite['tests']:
            if not (test['counted'] or test['kind'] == 'fixture'):
                continue
            if test['id'] in tests:
                duplicates.append(test['id'])
            tests[test['id']] = test
    return tests, duplicates


def _signature(test):
    """Meaningful diagnostics; excludes timing, seeds, random values and raw logs."""
    return {'native_status': test.get('native_status'),
            **(test.get('details') or {}).get('signature', {})}


def compare_runs(reference, rust):
    reference, rust = load_run(reference), load_run(rust)
    problems = []
    key_ref = reference['metadata'].get('comparison_key')
    key_rust = rust['metadata'].get('comparison_key')
    if not key_ref or not key_rust:
        problems.append('comparison key missing')
    else:
        for field in sorted(set(key_ref) | set(key_rust)):
            if key_ref.get(field) != key_rust.get(field):
                problems.append(f'{field} differs: {key_ref.get(field)!r} != '
                                f'{key_rust.get(field)!r}')
    left, left_dup = _comparable(reference)
    right, right_dup = _comparable(rust)
    categories = {c: [] for c in ('both_pass', 'shared_unsuccessful', 'regression',
                                  'improvement', 'different_unsuccessful',
                                  'missing_in_reference', 'missing_in_rust')}
    diagnostic_differences = []
    for test_id in list(left) + [t for t in right if t not in left]:
        a, b = left.get(test_id), right.get(test_id)
        entry = {'id': test_id, 'kind': (a or b)['kind'],
                 'reference': a and a['status'], 'rust': b and b['status'],
                 'reference_reason': a and a['reason'], 'rust_reason': b and b['reason']}
        if a is None:
            categories['missing_in_reference'].append(entry)
        elif b is None:
            categories['missing_in_rust'].append(entry)
        elif a['status'] == 'PASS' and b['status'] == 'PASS':
            categories['both_pass'].append(entry)
        elif a['status'] == 'PASS':
            categories['regression'].append(entry)
        elif b['status'] == 'PASS':
            categories['improvement'].append(entry)
        elif a['status'] == b['status']:
            categories['shared_unsuccessful'].append(entry)
            if _signature(a) != _signature(b):
                entry['reference_signature'] = _signature(a)
                entry['rust_signature'] = _signature(b)
                diagnostic_differences.append(entry)
        else:
            categories['different_unsuccessful'].append(entry)
    suites = []
    for name in dict.fromkeys([s['name'] for s in reference['suites']]
                              + [s['name'] for s in rust['suites']]):
        a = next((s for s in reference['suites'] if s['name'] == name), None)
        b = next((s for s in rust['suites'] if s['name'] == name), None)
        suites.append({'name': name, 'reference': a and a['status'], 'rust': b and b['status'],
                       'reference_complete': bool(a and a['complete']),
                       'rust_complete': bool(b and b['complete'])})
    incomplete = []
    for label, run, dup in (('reference', reference, left_dup), ('rust', rust, right_dup)):
        if not run['complete']:
            incomplete.append(f'{label} run is incomplete')
        if dup:
            incomplete.append(f'{label} has duplicate test IDs: {", ".join(dup[:5])}')
        if not any(True for _ in (left if label == 'reference' else right)):
            incomplete.append(f'{label} has no comparable tests')
    if categories['missing_in_reference'] or categories['missing_in_rust']:
        incomplete.append('test sets differ')
    differences = any(categories[c] for c in ('regression', 'improvement',
                                              'different_unsuccessful'))
    if problems:
        status = 'INCOMPATIBLE'
    elif incomplete:
        status = 'INCOMPLETE'
    elif differences or diagnostic_differences:
        status = 'DIFFERENT'
    else:
        status = 'EQUIVALENT'
    both_pass = reference['status'] == 'PASS' and rust['status'] == 'PASS'
    return {
        'schema_version': SCHEMA_VERSION,
        'status': status,
        # Matching failures are not a successful validation.
        'successful': status == 'EQUIVALENT' and both_pass,
        'reference_status': reference['status'], 'rust_status': rust['status'],
        'compatibility_problems': problems, 'incomplete': incomplete,
        'counts': {c: len(v) for c, v in categories.items()},
        'diagnostic_differences': diagnostic_differences,
        'suites': suites, 'tests': categories,
    }


def render_comparison(comparison, limit=40):
    counts = comparison['counts']
    lines = [f'Comparison reference vs rust: {comparison["status"]} '
             f'(reference {comparison["reference_status"]}, rust {comparison["rust_status"]}; '
             f'validation {"successful" if comparison["successful"] else "UNSUCCESSFUL"})',
             '  ' + ', '.join(f'{k}={v}' for k, v in counts.items())]
    for problem in comparison['compatibility_problems']:
        lines.append(f'  incompatible: {problem}')
    for problem in comparison['incomplete']:
        lines.append(f'  incomplete: {problem}')
    lines.append(f'  {"suite":<18} {"reference":<12} {"rust":<12}')
    for suite in comparison['suites']:
        lines.append(f'  {suite["name"]:<18} {suite["reference"] or "MISSING":<12} '
                     f'{suite["rust"] or "MISSING":<12}')
    for category, title in (('regression', 'Regressions (reference PASS, rust not)'),
                            ('improvement', 'Improvements (rust PASS, reference not)'),
                            ('different_unsuccessful', 'Different unsuccessful outcomes'),
                            ('shared_unsuccessful', 'Shared unsuccessful outcomes'),
                            ('missing_in_reference', 'Missing from reference'),
                            ('missing_in_rust', 'Missing from rust')):
        entries = comparison['tests'][category]
        if not entries:
            continue
        lines.append(f'  {title}: {len(entries)}')
        for entry in entries[:limit]:
            lines.append(f'    {entry["id"]}: reference {entry["reference"] or "-"}, '
                         f'rust {entry["rust"] or "-"}')
        if len(entries) > limit:
            lines.append(f'    ... {len(entries) - limit} more; see comparison.json')
    if comparison['diagnostic_differences']:
        lines.append(f'  Same status, different diagnostics: '
                     f'{len(comparison["diagnostic_differences"])}')
        for entry in comparison['diagnostic_differences'][:limit]:
            lines.append(f'    {entry["id"]}: {entry["reference_signature"]} != '
                         f'{entry["rust_signature"]}')
    return '\n'.join(lines) + '\n'
