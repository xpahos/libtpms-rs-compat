"""Normalize the Microsoft scenario supervisor's summary.json.

Each scenario is one test. LibTesterInfra and the upstream success/failure/abort
counters are evidence inside a scenario, never separate tests.
"""
from __future__ import annotations

import json

from .. import results as schema

# The supervisor persists these before finalizing; a killed supervisor leaves them.
UNFINISHED = {'PENDING': ('NOT_RUN', 'not started; the scenario supervisor stopped'),
              'RUNNING': ('INTERRUPTED', 'the scenario supervisor stopped before '
                                         'finalizing this scenario')}
DETAILS = ('counts', 'infrastructure_counts', 'report_title', 'report_error', 'exit_code',
           'timed_out', 'interrupted', 'exceptions', 'seeds', 'unsupported_opcodes',
           'error_responses', 'last_error_responses', 'skipped_messages', 'selected_by_upstream',
           'bridge_exit_code', 'timeout_seconds')


def collect(suite, summary_path, *, prefix, termination):
    """`prefix` turns supervisor paths (relative to the suite dir) into run paths."""
    name = suite['name']
    if not summary_path.exists():
        suite['issues'].append(schema.issue('no-summary', 'the scenario supervisor wrote no '
                                            'summary.json', incomplete=True))
        return
    try:
        summary = json.loads(summary_path.read_text())
    except ValueError as exc:
        suite['issues'].append(schema.issue('malformed', f'unreadable summary.json: {exc}',
                                            incomplete=True))
        return
    selection = summary.get('selection') or {}
    suite['selection'] = {k: selection.get(k) for k in
                          ('requested', 'default', 'expansions', 'duplicates_removed', 'order')
                          if k in selection}
    suite['native_counts'] = summary.get('counts', {})
    if summary.get('status') in ('INVALID_SELECTION', 'INTERRUPTED') and not \
            summary.get('scenarios'):
        suite['issues'].append(schema.issue('selection', summary.get('error', 'no scenarios'),
                                            incomplete=True))
        return
    if not summary.get('complete') and summary.get('status') == 'RUNNING':
        suite['issues'].append(schema.issue('supervisor', 'the scenario supervisor did not '
                                            'finalize its summary', incomplete=True))
    names = [s['name'] for s in summary.get('scenarios', [])]
    if len(set(names)) != len(names):
        suite['issues'].append(schema.issue('duplicate', 'duplicate scenarios in summary'))
    for scenario in summary.get('scenarios', []):
        native = scenario['status']
        status, reason = UNFINISHED.get(native, (native, scenario.get('reason', '')))
        if status not in schema.STATUSES:
            status, reason = 'ERROR', f'unknown scenario status {native!r}'
        details = {k: scenario[k] for k in DETAILS if k in scenario}
        details['signature'] = {
            'exceptions': scenario.get('exceptions', []),
            'unsupported_opcodes': sorted(set(scenario.get('unsupported_opcodes', []))),
            'counts': scenario.get('counts'),
            'report_error': scenario.get('report_error'),
        }
        artifacts = {key: f'{prefix}/{scenario[field]}'
                     for key, field in (('log', 'console_log'), ('bridge_log', 'bridge_log'),
                                        ('report', 'report')) if scenario.get(field)}
        execution = f'scenario:{scenario.get("directory", scenario["name"]).split("/")[-1]}'
        suite['tests'].append(schema.test_result(
            name, scenario['name'], status, native_status=native, reason=reason,
            details=details, duration=scenario.get('duration_seconds'),
            execution=execution, artifacts=artifacts))
        if 'duration_seconds' in scenario or scenario.get('exit_code') is not None:
            suite['executions'].append({
                'id': execution, 'exit_code': scenario.get('exit_code'),
                'timed_out': scenario.get('timed_out'),
                'interrupted': scenario.get('interrupted'),
                'duration_seconds': scenario.get('duration_seconds'),
                'bridge_exit_code': scenario.get('bridge_exit_code')})
