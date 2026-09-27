"""Bounded subprocess execution with ownership of the entire child tree.

Linux only (it reads /proc); every caller runs inside the validation container.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)


def _process_table():
    """Linux process identities, including start times to avoid PID reuse."""
    processes = {}
    for entry in Path('/proc').glob('[0-9]*'):
        try:
            text = (entry / 'stat').read_text()
            fields = text[text.rfind(')') + 2:].split()
            processes[int(entry.name)] = (int(fields[1]), fields[0], fields[19])
        except (OSError, ValueError, IndexError):
            continue
    return processes


def enable_subreaper():
    """Adopt double-forked descendants so that they can still be found and reaped."""
    if sys.platform.startswith('linux'):
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
            raise OSError(ctypes.get_errno(), 'cannot enable process subreaper')


def _reap(pids, deadline):
    """Collect exited adopted children; wait until `deadline` for the rest."""
    pending = set(pids)
    while pending:
        for pid in list(pending):
            try:
                if os.waitpid(pid, os.WNOHANG)[0] == pid:
                    pending.discard(pid)
            except ChildProcessError:
                pending.discard(pid)   # not our child (or already reaped)
        if not pending or time.monotonic() >= deadline:
            return
        time.sleep(.02)


def run_process(argv, *, cwd, env, log, timeout, grace=5, append=False):
    """Log a command and return evidence; timeouts/signals never abandon children.

    Termination is graceful first: the command's own process group gets SIGTERM
    and up to `grace` seconds to finish (a supervising child can then finalize
    its report), then every remaining descendant gets SIGTERM and SIGKILL.
    A normally exiting command which leaves running descendants is unsuccessful.
    SIGTERM, SIGINT and SIGHUP are recorded as an interrupted execution.
    """
    if timeout <= 0 or grace < 0:
        raise ValueError('timeout must be positive and grace must be nonnegative')
    enable_subreaper()
    started = time.monotonic()
    baseline = set(_process_table())
    owned = {}
    interrupted = []
    previous_handlers = {}
    process = None
    termination = 'completed'
    cleanup_failed = False
    log = Path(log)
    log.parent.mkdir(parents=True, exist_ok=True)

    def receive_signal(number, _frame):
        interrupted.append(number)

    def descendants():
        table = _process_table()
        parents = {process.pid}
        changed = True
        while changed:
            changed = False
            for pid, (parent, _state, identity) in table.items():
                if pid == process.pid:
                    continue
                if parent in parents or (parent == os.getpid() and pid not in baseline):
                    if pid not in parents:
                        parents.add(pid)
                        changed = True
                    owned.setdefault(pid, identity)
        return {pid for pid, identity in owned.items()
                if pid in table and table[pid][2] == identity and table[pid][1] != 'Z'}

    def signal_all(number, leader_only=False):
        try:
            os.killpg(process.pid, number)
        except ProcessLookupError:
            pass
        if leader_only:
            return
        for pid in descendants():
            try:
                os.kill(pid, number)
            except ProcessLookupError:
                pass

    def wait(seconds, leader_only=False):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if process.poll() is not None and (leader_only or not descendants()):
                return True
            time.sleep(.02)
        return False

    mode = 'ab' if append else 'wb'
    with log.open(mode, buffering=0) as output:
        try:
            if threading.current_thread() is threading.main_thread():
                for number in SIGNALS:
                    previous_handlers[number] = signal.signal(number, receive_signal)
            try:
                process = subprocess.Popen([str(arg) for arg in argv], cwd=cwd, env=env,
                                           stdout=output, stderr=subprocess.STDOUT,
                                           stdin=subprocess.DEVNULL, start_new_session=True)
            except OSError as exc:
                output.write(f'Cannot start command: {exc}\n'.encode())
                return {'exit_code': 127, 'termination': 'completed', 'cleanup_failed': False,
                        'duration_seconds': round(time.monotonic() - started, 3),
                        'error': f'cannot start command: {exc}'}
            while process.poll() is None:
                descendants()
                # As subreaper we adopt orphans; reap the exited ones now, or
                # their zombies would keep a supervised process group "alive".
                _reap(owned, deadline=0)
                if interrupted:
                    termination = 'interrupted'
                    break
                if time.monotonic() - started >= timeout:
                    termination = 'timeout'
                    break
                time.sleep(.02)
            if interrupted:
                termination = 'interrupted'
            if termination == 'completed':
                # Helpers (e.g. MSBuild worker nodes) may still be exiting on
                # their own; only descendants that outlive this window leak.
                wait(min(grace, 3))
            survivors = descendants()
            if termination != 'completed':
                signal_all(signal.SIGTERM, leader_only=True)
                wait(grace, leader_only=True)
            if termination != 'completed' or survivors:
                cleanup_failed = termination == 'completed' and bool(survivors)
                if cleanup_failed:
                    output.write(('Unreaped command descendants: ' +
                                  ', '.join(map(str, sorted(survivors))) + '\n').encode())
                signal_all(signal.SIGTERM)
                wait(min(grace, 2))
                signal_all(signal.SIGKILL)
            code = process.wait()
            # Reap adopted descendants, including ones already exited normally.
            # SIGKILL is asynchronous, so wait (bounded) until each is collected.
            descendants()
            _reap(owned, deadline=time.monotonic() + 5)
            result = {'exit_code': code, 'termination': termination,
                      'duration_seconds': round(time.monotonic() - started, 3),
                      'cleanup_failed': cleanup_failed}
            if termination == 'timeout':
                result['exit_code'] = 124
                result['child_exit_code'] = code
            elif termination == 'interrupted':
                result['exit_code'] = 128 + interrupted[0]
                result['signal'] = signal.Signals(interrupted[0]).name
                result['child_exit_code'] = code
            elif cleanup_failed and code == 0:
                result['exit_code'] = 1
            return result
        finally:
            if process is not None and process.poll() is None:
                signal_all(signal.SIGKILL)
                process.wait()
            for number, handler in previous_handlers.items():
                signal.signal(number, handler)


def sweep(report=None, grace=2):
    """Kill every process in this container except init and our own ancestry.

    The validation container runs nothing else, so any survivor after a phase is
    a leaked test service (daemonized D-Bus, resource manager or simulator).
    Returns the list of 'pid command' strings that had to be killed.
    """
    table = _process_table()
    keep = {1, os.getpid()}
    pid = os.getpid()
    while pid in table and table[pid][0] not in keep and table[pid][0] > 0:
        pid = table[pid][0]
        keep.add(pid)
    keep.add(table.get(os.getpid(), (0,))[0])

    def survivors():
        current = _process_table()
        return {p: identity for p, (_, state, identity) in current.items()
                if p not in keep and state != 'Z'}

    found = survivors()
    if not found:
        return []
    described = []
    for p in sorted(found):
        try:
            command = Path(f'/proc/{p}/cmdline').read_bytes().replace(b'\0', b' ').decode(
                errors='replace').strip()
        except OSError:
            command = '?'
        described.append(f'{p} {command}')
    for number in (signal.SIGTERM, signal.SIGKILL):
        for p, identity in survivors().items():
            if p in found and found[p] == identity:
                try:
                    os.kill(p, number)
                except ProcessLookupError:
                    pass
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline and any(p in found for p in survivors()):
            time.sleep(.05)
    _reap(found, deadline=time.monotonic() + grace)
    if report is not None:
        Path(report).write_text('\n'.join(described) + '\n')
    return described
