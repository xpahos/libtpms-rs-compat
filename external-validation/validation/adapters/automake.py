"""Unchanged Automake `make check` runs: selection, execution and evidence.

tpm2-tss and tpm2-tools own their simulator (and for tools: private D-Bus and
tpm2-abrmd) lifecycle through their upstream test harness; we only choose TESTS.
"""
from __future__ import annotations

import os
from pathlib import Path
import re

from ..collectors.automake import collect  # noqa: F401  (adapter API)
from ..environment import StepFailed

NAME = re.compile(r'[A-Za-z0-9_./-]+')


def select(phase, build_dir, variable, expression, run_dir):
    """List the Makefile's test variable, filter by basename, clear stale evidence."""
    try:
        pattern = re.compile(expression or '')
    except re.error as exc:
        raise StepFailed(f'invalid --filter regular expression: {exc}')
    fragment = run_dir / 'validation-list.mk'
    fragment.write_text('.PHONY: validation-list\nvalidation-list:\n'
                        f"\t@printf '%s\\n' $({variable})\n")
    listing = phase.capture(['make', '--no-print-directory', '-s', '-f', 'Makefile',
                             '-f', str(fragment), 'validation-list'], cwd=build_dir)
    fragment.unlink()
    candidates = listing.split()
    (run_dir / 'candidates.txt').write_text('\n'.join(candidates) + '\n')
    tests = [t for t in candidates if pattern.search(Path(t).name)]
    if not tests:
        raise StepFailed('--filter selected no upstream tests' if expression
                         else f'{variable} lists no upstream tests')
    if len(set(tests)) != len(tests) or any(not NAME.fullmatch(t) for t in tests):
        raise StepFailed('unexpected upstream test list (duplicates or unsafe names)')
    (run_dir / 'selected.txt').write_text('\n'.join(tests) + '\n')
    for test in tests:
        for suffix in ('.log', '.trs'):
            (build_dir / Path(test).with_suffix(suffix)).unlink(missing_ok=True)
        (build_dir / (test + '_simulator.log')).unlink(missing_ok=True)
    phase.note(f'Selected {len(tests)} upstream tests')
    return tests


def check(phase, build_dir, tests, make_args, log):
    return phase.run(['make', '-j1', 'check', *make_args, 'TESTS=' + ' '.join(tests)],
                     cwd=build_dir, log=log, check=False)


def environment_without(env, names):
    return {k: v for k, v in env.items() if k not in names}


def ldd_outside(phase, binaries, prefix, report):
    """Record linkage and list libtss2 libraries resolved outside the pinned prefix."""
    lines, foreign = [], []
    for binary in binaries:
        text = phase.capture(['ldd', str(binary)], cwd=prefix)
        lines += [f'ldd {binary}:', text]
        for match in re.finditer(r'^\s*(libtss2-\S+)\s+=>\s+(\S+)', text, re.M):
            if not match.group(2).startswith(str(prefix / 'lib') + os.sep):
                foreign.append(f'{binary} resolves {match.group(1)} outside the pinned '
                               f'TSS: {match.group(2)}')
    with open(report, 'a') as output:
        output.write('\n'.join(lines) + '\n')
    return foreign
