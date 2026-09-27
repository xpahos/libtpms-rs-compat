"""Exercise real process trees, including descendants that leave their session."""
import importlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('validation.processes'),
                             'Python process supervision must exist')
        self.processes = importlib.import_module('validation.processes')
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def run_process(self, code, timeout=3):
        return self.processes.run_process(
            [sys.executable, '-c', code], cwd=self.directory,
            env=os.environ.copy(), log=self.directory / 'console.log',
            timeout=timeout, grace=0.1)

    def assert_gone(self, path):
        pid = int(path.read_text())
        with self.assertRaises(ProcessLookupError, msg=f'child {pid} remains after cleanup'):
            os.kill(pid, 0)

    def test_nonzero_exit_preserves_output_and_status(self):
        result = self.run_process("print('evidence', flush=True); raise SystemExit(17)")
        self.assertEqual(result['exit_code'], 17)
        self.assertEqual(result['termination'], 'completed')
        self.assertIn('evidence', (self.directory / 'console.log').read_text())
        self.assertGreaterEqual(result['duration_seconds'], 0)

    def test_timeout_kills_and_reaps_detached_descendant(self):
        result = self.run_process("""
import os, signal, time
if os.fork() == 0:
    os.setsid()
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    open('descendant.pid', 'w').write(str(os.getpid()))
    while True: time.sleep(.1)
while True: time.sleep(.1)
""", timeout=0.3)
        self.assertEqual(result['termination'], 'timeout')
        self.assertNotEqual(result['exit_code'], 0)
        self.assert_gone(self.directory / 'descendant.pid')

    def test_successful_parent_with_leaked_child_is_not_success(self):
        result = self.run_process("""
import os, time
if os.fork() == 0:
    os.setsid()
    open('descendant.pid', 'w').write(str(os.getpid()))
    while True: time.sleep(.1)
time.sleep(.2)
""")
        self.assertNotEqual(result['exit_code'], 0)
        self.assertTrue(result['cleanup_failed'])
        self.assert_gone(self.directory / 'descendant.pid')

    def test_signal_interrupt_preserves_report_and_cleans_child(self):
        script = self.directory / 'supervisor.py'
        script.write_text('''
import json, os, sys
from pathlib import Path
from validation.processes import run_process
result = run_process([sys.executable, '-c', "import os,time; open('child.pid','w').write(str(os.getpid())); time.sleep(30)"], cwd=Path.cwd(), env=os.environ.copy(), log='child.log', timeout=30, grace=.1)
Path('execution.json').write_text(json.dumps(result))
''')
        supervisor = subprocess.Popen([sys.executable, str(script)], cwd=self.directory,
                                      env=dict(os.environ, PYTHONPATH=str(ROOT)))
        self.addCleanup(lambda: supervisor.poll() is None and supervisor.kill())
        deadline = time.monotonic() + 5
        while not (self.directory / 'child.pid').exists() and time.monotonic() < deadline:
            time.sleep(.02)
        self.assertTrue((self.directory / 'child.pid').exists())
        supervisor.send_signal(signal.SIGTERM)
        self.assertEqual(supervisor.wait(timeout=5), 0)
        result = json.loads((self.directory / 'execution.json').read_text())
        self.assertEqual(result['termination'], 'interrupted')
        self.assertEqual(result['exit_code'], 143)
        self.assert_gone(self.directory / 'child.pid')

    def test_leader_finalizes_before_its_descendants_are_killed(self):
        # Like the Microsoft supervisor: it owns a child in another session and
        # must still see that child alive while it finalizes after SIGTERM.
        result = self.processes.run_process([sys.executable, '-c', """
import os, signal, subprocess, sys, time
child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'],
                         start_new_session=True)
open('descendant.pid', 'w').write(str(child.pid))
def finalize(*_):
    open('final', 'w').write('child-alive' if child.poll() is None else 'child-dead')
    child.terminate(); child.wait(); sys.exit(0)
signal.signal(signal.SIGTERM, finalize)
while True: time.sleep(.05)
"""], cwd=self.directory, env=os.environ.copy(), log=self.directory / 'console.log',
            timeout=0.5, grace=5)
        self.assertEqual(result['termination'], 'timeout')
        self.assertEqual((self.directory / 'final').read_text(), 'child-alive')
        self.assert_gone(self.directory / 'descendant.pid')

    def test_sighup_is_an_interruption(self):
        script = self.directory / 'supervisor.py'
        script.write_text('''
import json, os, sys
from pathlib import Path
from validation.processes import run_process
result = run_process([sys.executable, '-c', "import os,time; open('child.pid','w').write(str(os.getpid())); time.sleep(30)"], cwd=Path.cwd(), env=os.environ.copy(), log='child.log', timeout=30, grace=.1)
Path('execution.json').write_text(json.dumps(result))
''')
        supervisor = subprocess.Popen([sys.executable, str(script)], cwd=self.directory,
                                      env=dict(os.environ, PYTHONPATH=str(ROOT)))
        self.addCleanup(lambda: supervisor.poll() is None and supervisor.kill())
        deadline = time.monotonic() + 5
        while not (self.directory / 'child.pid').exists() and time.monotonic() < deadline:
            time.sleep(.02)
        supervisor.send_signal(signal.SIGHUP)
        self.assertEqual(supervisor.wait(timeout=5), 0)
        result = json.loads((self.directory / 'execution.json').read_text())
        self.assertEqual((result['termination'], result['exit_code'], result['signal']),
                         ('interrupted', 129, 'SIGHUP'))
        self.assert_gone(self.directory / 'child.pid')

    def test_sweep_kills_escaped_daemons_but_not_our_ancestry(self):
        # A daemon that double-forked away from any supervised process tree.
        subprocess.run([sys.executable, '-c', """
import os, time
if os.fork() == 0:
    os.setsid()
    if os.fork() == 0:
        open('daemon.pid', 'w').write(str(os.getpid()))
        while True: time.sleep(.1)
"""], cwd=self.directory, check=True)
        deadline = time.monotonic() + 5
        while not (self.directory / 'daemon.pid').exists() and time.monotonic() < deadline:
            time.sleep(.02)
        report = self.directory / 'leftovers.txt'
        killed = self.processes.sweep(report=report)
        pid = int((self.directory / 'daemon.pid').read_text())
        self.assertTrue(any(line.startswith(f'{pid} ') for line in killed), killed)
        self.assertIn(str(pid), report.read_text())
        self.assert_gone(self.directory / 'daemon.pid')
        self.assertEqual(self.processes.sweep(), [])


if __name__ == '__main__':
    unittest.main()
