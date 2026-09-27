"""Normalize `go tool test2json` events for a compiled Go test binary.

Parent tests with subtests become groups: they are not counted on top of their
children, but a parent that fails by itself stays visible (see results.py).
"""
from __future__ import annotations

import json
import re

from .. import results as schema

ACTIONS = {'pass': 'PASS', 'fail': 'FAIL', 'skip': 'SKIPPED'}
NO_TESTS = ('testing: warning: no tests to run', '[no tests to run]')
FRAMING = re.compile(r'^\s*(=== (RUN|PAUSE|CONT|NAME)\s|--- (PASS|FAIL|SKIP):)')


def parse_events(text):
    """Return (events, malformed lines). Every line must be one JSON event."""
    events, malformed = [], []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except ValueError:
            malformed.append(f'{number}: {line[:200]}')
            continue
        if not isinstance(event, dict) or not isinstance(event.get('Action'), str):
            malformed.append(f'{number}: {line[:200]}')
            continue
        events.append(event)
    return events, malformed


def console_text(events):
    return ''.join(e.get('Output', '') for e in events if e['Action'] == 'output')


def aggregate(events):
    tests, package = {}, {'action': None, 'elapsed': None, 'output': []}
    for event in events:
        name, action = event.get('Test'), event['Action']
        if not name:
            if action in ACTIONS:
                package['action'], package['elapsed'] = action, event.get('Elapsed')
            elif action == 'output':
                package['output'].append(event.get('Output', ''))
            continue
        test = tests.setdefault(name, {'runs': 0, 'results': [], 'elapsed': None,
                                       'output': []})
        if action == 'run':
            test['runs'] += 1
        elif action in ACTIONS:
            test['results'].append(action)
            test['elapsed'] = event.get('Elapsed')
        elif action == 'output':
            test['output'].append(event.get('Output', ''))
    return tests, package


def message(lines, count=3):
    useful = [l.strip() for l in lines if l.strip() and not FRAMING.match(l)]
    return ' | '.join(useful[-count:])[:500]


def collect(suite, events, *, termination, exit_code, execution='run', artifacts=None):
    """Append normalized Go tests and issues to `suite`; return raw aggregates."""
    name = suite['name']
    tests, package = aggregate(events)
    children = {}
    for test in tests:
        if '/' in test:
            children.setdefault(test.rsplit('/', 1)[0], []).append(test)
    for test, data in tests.items():
        if data['runs'] != 1:
            suite['issues'].append(schema.issue(
                'duplicate' if data['runs'] > 1 else 'malformed',
                f'{test} has {data["runs"]} run events'))
        if len(data['results']) > 1:
            suite['issues'].append(schema.issue('duplicate', f'{test} has '
                                                f'{len(data["results"])} results'))
        if data['results']:
            status = ACTIONS[data['results'][-1]]
            reason = '' if status == 'PASS' else message(data['output'])
        elif termination in ('timeout', 'interrupted'):
            status = 'TIMEOUT' if termination == 'timeout' else 'INTERRUPTED'
            reason = 'phase stopped while this test was running'
        else:
            status = 'ERROR'
            reason = 'no result reported; the test binary stopped: ' + message(
                package['output'])
        parent = test.rsplit('/', 1)[0] if '/' in test and test.rsplit('/', 1)[0] in tests \
            else None
        suite['tests'].append(schema.test_result(
            name, test, status, parent=parent,
            kind='group' if test in children else 'test',
            native_status=data['results'][-1] if data['results'] else None,
            reason=reason, duration=data['elapsed'], execution=execution,
            artifacts=artifacts))
    output = ''.join(package['output']) + ''.join(
        ''.join(t['output']) for t in tests.values())
    if any(marker in output for marker in NO_TESTS):
        suite['issues'].append(schema.issue('no-tests', 'the Go test binary reported that '
                                            'no selected tests ran', incomplete=True))
    failed = any(t['results'][-1:] == ['fail'] for t in tests.values())
    if package['action'] is None:
        if termination == 'completed':
            suite['issues'].append(schema.issue('truncated', 'no package result; the test2json '
                                                'stream is truncated', incomplete=True))
    elif package['action'] == 'fail' and not failed:
        suite['issues'].append(schema.issue('package', 'package failed outside reported '
                                            'tests: ' + message(package['output'])))
    if termination == 'completed' and exit_code is not None:
        if exit_code == 0 and (failed or package['action'] == 'fail'):
            suite['issues'].append(schema.issue('exit-status', 'test binary exited 0 despite '
                                                'failures'))
        if exit_code != 0 and package['action'] == 'pass':
            suite['issues'].append(schema.issue('exit-status', f'test binary exited '
                                                f'{exit_code} although the package passed'))
    return tests, package
