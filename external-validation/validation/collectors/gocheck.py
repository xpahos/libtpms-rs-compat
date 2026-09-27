"""gocheck (gopkg.in/check.v1) cases inside Canonical's single Go `Test` wrapper.

Counting follows gocheck's own Result accounting so the parsed cases reconcile
with its `OK:`/`OOPS:` line:
  * FAIL of a test or a fixture method increments FAILED;
  * PANIC of a test increments PANICKED, unless the test only reports that its
    fixture panicked ("Fixture has panicked"), which gocheck counts as MISSED;
  * PANIC of a fixture increments FIXTURE-PANICKED; MISS increments MISSED.
Fixture methods are reported as fixtures, never as additional tests.
"""
from __future__ import annotations

import re

from .. import results as schema

FIXTURES = ('SetUpSuite', 'TearDownSuite', 'SetUpTest', 'TearDownTest')
CASE = re.compile(r'^(PASS|FAIL EXPECTED|FAIL|PANIC|MISS|SKIP): (.+?:\d+): '
                  r'\(?\*?(\w+)\)?\.(\w+)(.*)$')
SEPARATOR = re.compile(r'^-{20,}$')
SUMMARY = re.compile(r'^(OK|OOPS): (\d+) passed((?:, \d+ [A-Za-z -]+?)*)(?:\s*$|\s+\[)')
FIXTURE_PANIC = 'Fixture has panicked (see related PANIC)'
FIELDS = {'skipped': 'skipped', 'expected failures': 'expected_failures', 'FAILED': 'failed',
          'PANICKED': 'panicked', 'FIXTURE-PANICKED': 'fixture_panicked', 'MISSED': 'missed'}


def parse(text):
    """Return (cases, summaries). Each case: label, location, suite, method, body."""
    cases, summaries, current = [], [], None
    for line in text.splitlines():
        stripped = line.rstrip()
        match = CASE.match(stripped)
        if match:
            label, location, suite, method, rest = match.groups()
            current = {'label': label, 'location': location, 'suite': suite,
                       'method': method, 'rest': rest.strip(), 'body': []}
            cases.append(current)
            continue
        summary = SUMMARY.match(stripped)
        if summary:
            counts = {'passed': int(summary.group(2))}
            for part in filter(None, summary.group(3).split(', ')):
                number, label = part.split(' ', 1)
                if label.strip() not in FIELDS:
                    counts.setdefault('unknown', []).append(part)
                else:
                    counts[FIELDS[label.strip()]] = int(number)
            summaries.append({'verdict': summary.group(1), 'counts': counts,
                              'line': stripped})
            current = None
            continue
        if SEPARATOR.match(stripped):
            current = None
        elif current is not None and current['label'] in ('FAIL', 'PANIC'):
            current['body'].append(stripped)
    return cases, summaries


def reason_of(case):
    checks = [l.strip() for l in case['body'] if l.strip().startswith('... ')
              and FIXTURE_PANIC not in l]
    return ' | '.join(checks[:2])[:500]


def collect(suite, text, *, parent, termination, execution='run', artifacts=None):
    """Append gocheck cases under `parent` (the Go wrapper) and reconcile totals."""
    name = suite['name']
    cases, summaries = parse(text)
    computed = dict.fromkeys(('passed', 'skipped', 'expected_failures', 'failed', 'panicked',
                              'fixture_panicked', 'missed'), 0)
    seen = set()
    for case in cases:
        fixture = case['method'] in FIXTURES
        native_id = f'gocheck/{case["suite"]}.{case["method"]}'
        label = case['label']
        fixture_caused = label == 'PANIC' and any(FIXTURE_PANIC in l for l in case['body'])
        if fixture:
            # Fixture calls repeat per test; keep each report, number repeats.
            occurrence = sum(1 for s in seen if s.startswith(native_id + '#')) + 1
            native_id = f'{native_id}#{occurrence}'
        elif native_id in seen:
            suite['issues'].append(schema.issue('duplicate', f'gocheck reported {native_id} '
                                                'more than once'))
            continue
        seen.add(native_id)
        if label == 'PASS':
            status, reason = 'PASS', ''
            computed['passed'] += not fixture
        elif label == 'FAIL EXPECTED':
            status, reason = 'PASS', 'expected failure (upstream ExpectFailure)'
            computed['expected_failures'] += 1
        elif label == 'SKIP':
            status, reason = 'SKIPPED', case['rest'].strip('() ')
            computed['skipped'] += 1
        elif label == 'MISS':
            status, reason = 'NOT_RUN', 'gocheck did not run it after a fixture failure'
            computed['missed'] += 1
        elif label == 'FAIL':
            status, reason = 'FAIL', reason_of(case)
            computed['failed'] += 1
        elif fixture_caused:
            status = 'ERROR'
            reason = 'its fixture failed (gocheck counts it as missed); ' + reason_of(case)
            computed['missed'] += 1
        else:
            status, reason = 'FAIL', 'panicked: ' + reason_of(case)
            computed['fixture_panicked' if fixture else 'panicked'] += 1
        native = label + (' (fixture panicked)' if fixture_caused else '')
        suite['tests'].append(schema.test_result(
            name, native_id, status, name=f'{case["suite"]}.{case["method"]}',
            parent=parent, kind='fixture' if fixture else 'test', native_status=native,
            reason=reason, details={'location': case['location']},
            execution=execution, artifacts=artifacts))
    suite['native_counts']['gocheck'] = summaries[-1]['counts'] if summaries else None
    if not summaries:
        if termination == 'completed':
            suite['issues'].append(schema.issue('gocheck', 'gocheck printed no OK/OOPS '
                                                'summary', incomplete=True))
        return cases
    if len(summaries) > 1:
        suite['issues'].append(schema.issue('gocheck', f'{len(summaries)} gocheck summaries'))
    native = summaries[-1]['counts']
    if native.get('unknown'):
        suite['issues'].append(schema.issue('gocheck', 'unrecognized gocheck totals: '
                                            + ', '.join(native['unknown'])))
    expected = {k: native.get(k, 0) for k in computed}
    if expected != computed:
        suite['issues'].append(schema.issue(
            'gocheck-totals', 'parsed gocheck cases do not reconcile with '
            f'"{summaries[-1]["line"]}"', native=expected, parsed=computed))
    if not sum(v for k, v in native.items() if k != 'unknown'):
        suite['issues'].append(schema.issue('no-tests', 'gocheck ran no cases',
                                            incomplete=True))
    return cases
