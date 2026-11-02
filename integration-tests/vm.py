"""Bounded QEMU/swtpm lifecycle, cancellation and evidence helpers (Python standard library only)."""
from __future__ import annotations

import base64
import binascii
import contextlib
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import signal
import socket
import subprocess
import time


# Synthetic timers require vpindex, synic and time; keep this supported profile fixed.
WINDOWS_CPU = 'host,hv_relaxed,hv_vapic,hv_spinlocks=0x1fff,hv_vpindex,hv_synic,hv_time,hv_stimer'
POWERSHELL = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
# The per-boot counter maintained by the Windows kernel; guest/windows-probe.ps1 uses the same value.
WINDOWS_BOOT_ID = ("(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\"
                   "Memory Management\\PrefetchParameters').BootId.ToString()")
HANDLED_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
SIGNATURE_SCHEME = 'rsassa-pkcs1-v1_5-sha256'
PUBLIC_KEY_ENCODING = 'x509-spki-der-base64'


class VMError(RuntimeError):
    pass


class Cancelled(BaseException):
    def __init__(self, signum: int):
        super().__init__(f'cancelled by {signal.Signals(signum).name}')
        self.signum = signum


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def source_hashes(*paths: Path) -> dict[str, str]:
    return {path.name: sha256(path) for path in paths}


def bundle_path(root: Path, value: str) -> Path:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise VMError(f'Bundle path must be relative: {value!r}')
    root = root.resolve()
    path = (root / value).resolve()
    if path == root or not path.is_relative_to(root) or not path.exists():
        raise VMError(f'Bundle path missing or escapes image: {value!r}')
    return path


def snapshot(root: Path) -> dict[str, str]:
    result = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise VMError(f'Bundle may not contain symlinks: {path}')
        if path.is_file():
            result[str(path.relative_to(root))] = sha256(path)
    return result


def atomic_json(path: Path, value: dict) -> None:
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def utc_now() -> str:
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def tool_version(command: list[str]) -> str:
    try:
        output = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return f'unavailable: {exc}'
    return (output.stdout or output.stderr).strip().splitlines()[0] if (output.stdout or output.stderr).strip() else ''


def preflight(swtpm: Path) -> dict[str, str]:
    if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'amd64'):
        raise VMError('Requires a Linux x86_64 host with KVM; no TCG fallback')
    if not os.access('/dev/kvm', os.R_OK | os.W_OK):
        raise VMError('/dev/kvm must be readable and writable')
    swtpm = Path(swtpm).resolve()
    if not swtpm.is_file() or not os.access(swtpm, os.X_OK):
        raise VMError(f'swtpm is not executable: {swtpm}')
    binaries = {name: shutil.which(name) for name in ('qemu-system-x86_64', 'qemu-img', 'openssl')}
    missing = [name for name, path in binaries.items() if not path]
    if missing:
        raise VMError(f'Required host tools are not on PATH: {", ".join(missing)}')
    return {**binaries, 'swtpm': str(swtpm), 'swtpm_sha256': sha256(swtpm)}


def freeze_library(source: Path, directory: Path, subdirectory: str = 'lib') -> dict[str, str]:
    """Copy the selected libtpms into this build/run; every swtpm start loads only this copy."""
    source = Path(source).expanduser()
    if not source.resolve().is_file():
        raise VMError(f'libtpms is not a file: {source}')
    private = directory / subdirectory
    private.mkdir(exist_ok=False)
    copy = private / 'libtpms.so.0'
    shutil.copyfile(source, copy)
    copy.chmod(0o500)
    with copy.open('rb') as stream:
        header = stream.read(20)
    if len(header) < 20 or header[:6] != b'\x7fELF\x02\x01' or header[18:20] != b'\x3e\x00':
        raise VMError('Selected libtpms must be a Linux x86_64 ELF library')
    return {'library_source': str(source.absolute()), 'library_source_resolved': str(source.resolve()),
            'library': str(copy.resolve()), 'library_sha256': sha256(copy)}


class _Lifecycle:
    def __init__(self):
        self.cleaning = False
        self.critical = 0
        self.pending: int | None = None
        self.signals: list[int] = []


LIFECYCLE = _Lifecycle()
OWNED: list['Process'] = []


def _handle_signal(signum, frame):
    LIFECYCLE.signals.append(signum)
    if LIFECYCLE.cleaning or LIFECYCLE.pending is not None:
        return
    if LIFECYCLE.critical:
        LIFECYCLE.pending = signum
        return
    LIFECYCLE.cleaning = True
    raise Cancelled(signum)


def install_signal_handlers() -> None:
    """SIGINT/SIGTERM/SIGHUP cancel once; later handled signals never interrupt cleanup."""
    for sig in HANDLED_SIGNALS:
        signal.signal(sig, _handle_signal)


def begin_cleanup() -> None:
    LIFECYCLE.cleaning = True


def cancellation_signal() -> int | None:
    return LIFECYCLE.signals[0] if LIFECYCLE.signals else None


@contextlib.contextmanager
def critical_section():
    """Defer cancellation while a child is spawned and registered for cleanup."""
    LIFECYCLE.critical += 1
    try:
        yield
    finally:
        LIFECYCLE.critical -= 1
        if not LIFECYCLE.critical and LIFECYCLE.pending is not None and not LIFECYCLE.cleaning:
            signum, LIFECYCLE.pending = LIFECYCLE.pending, None
            LIFECYCLE.cleaning = True
            raise Cancelled(signum)


def become_subreaper() -> None:
    """Orphaned descendants are reparented here, so cleanup can find and reap them."""
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise VMError(f'prctl(PR_SET_CHILD_SUBREAPER) failed: errno {ctypes.get_errno()}')


class Process:
    def __init__(self, command: list[str], directory: Path, name: str, env=None):
        self.name = name
        self.stopped = False
        self.stdout = (directory / f'{name}.stdout.log').open('ab')
        self.stderr = (directory / f'{name}.stderr.log').open('ab')
        try:
            with critical_section():
                self.process = subprocess.Popen(command, cwd=directory, env=env,
                                                stdout=self.stdout, stderr=self.stderr,
                                                start_new_session=True)
                OWNED.append(self)
        except BaseException:
            if not hasattr(self, 'process'):
                self.stdout.close()
                self.stderr.close()
            raise

    def check(self):
        code = self.process.poll()
        if code is not None:
            raise VMError(f'Process {self.name} exited with status {code}')

    def stop(self, timeout=10):
        if self.stopped:
            return
        # The group can outlive its leader (Packer can leave QEMU running), so
        # always signal and inspect the whole group, then escalate.
        with contextlib.suppress(ProcessLookupError):
            os.killpg(self.process.pid, signal.SIGTERM)
        deadline = time.monotonic() + timeout
        group_exists = True
        while time.monotonic() < deadline:
            self.process.poll()
            try:
                os.killpg(self.process.pid, 0)
            except ProcessLookupError:
                group_exists = False
                break
            time.sleep(0.05)
        if group_exists:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(self.process.pid, signal.SIGKILL)
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired as exc:
            raise VMError(f'{self.name} (pid {self.process.pid}) survived SIGKILL') from exc
        self.stopped = True
        self.stdout.close()
        self.stderr.close()
        with contextlib.suppress(ValueError):
            OWNED.remove(self)


def _children() -> list[int]:
    me, children = os.getpid(), []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / 'stat').read_text().rsplit(')', 1)[1].split()
        except (OSError, IndexError):
            continue
        if int(fields[1]) == me:
            children.append(int(entry.name))
    return children


def _reap(pids: set[int]) -> set[int]:
    for pid in list(pids):
        try:
            done, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            done = pid
        if done:
            pids.discard(pid)
    return pids


def stop_all_owned(timeout: float = 10) -> dict:
    """Stop every registered process group, then terminate and reap orphaned descendants."""
    report = {'stopped': [], 'orphans_terminated': [], 'errors': []}
    for child in reversed(list(OWNED)):
        try:
            child.stop(timeout)
            report['stopped'].append(child.name)
        except Exception as exc:
            report['errors'].append(f'{child.name}: {type(exc).__name__}: {exc}')
    if platform.system() != 'Linux':
        return report
    tracked = {child.process.pid for child in OWNED}
    deadline = time.monotonic() + timeout
    killed = False
    while True:
        orphans = set(_children()) - tracked
        if not orphans:
            break
        for pid in orphans:
            if pid not in report['orphans_terminated']:
                report['orphans_terminated'].append(pid)
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL if killed else signal.SIGTERM)
        _reap(orphans)
        if time.monotonic() >= deadline:
            if killed:
                report['errors'].append(f'orphaned descendants survived SIGKILL: {sorted(orphans)}')
                break
            killed, deadline = True, time.monotonic() + 5
        time.sleep(0.05)
    return report


def survivors(directory: Path) -> list[dict]:
    """Processes still running in, or naming, an owned work directory."""
    directory = directory.resolve()
    needle, found = os.fsencode(str(directory)), []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            cmdline = (entry / 'cmdline').read_bytes()
            cwd = Path(os.readlink(entry / 'cwd'))
        except OSError:
            continue
        if needle in cmdline or cwd == directory or cwd.is_relative_to(directory):
            found.append({'pid': int(entry.name), 'cmdline': cmdline.replace(b'\0', b' ').decode(errors='replace').strip()})
    return found


def finish_cleanup(directory: Path, timeout: float = 10) -> dict:
    """Bounded, signal-safe final cleanup; always returns a report instead of raising."""
    begin_cleanup()
    try:
        report = stop_all_owned(timeout)
    except Exception as exc:
        report = {'stopped': [], 'orphans_terminated': [], 'errors': [f'{type(exc).__name__}: {exc}']}
    try:
        report['survivors'] = survivors(directory) if platform.system() == 'Linux' else []
    except Exception as exc:
        report['survivors'] = []
        report['errors'].append(f'survivor scan failed: {type(exc).__name__}: {exc}')
    if report['survivors']:
        report['errors'].append('owned processes remain after cleanup')
    report['status'] = 'ERROR' if report['errors'] else 'OK'
    return report


class Swtpm:
    def __init__(self, swtpm: Path, library: Path, state: Path, socket_path: Path, workdir: Path,
                 library_sha256: str):
        self.binary, self.library = Path(swtpm).resolve(), Path(library).resolve()
        self.state, self.socket, self.workdir = Path(state).resolve(), Path(socket_path).resolve(), Path(workdir).resolve()
        self.library_sha256 = library_sha256
        self.child = None
        self.starts: list[dict] = []
        self.select_library(library, library_sha256)

    def select_library(self, library: Path, library_sha256: str):
        """Point later starts at another frozen copy; only allowed while swtpm is stopped."""
        if self.child is not None:
            raise VMError('Cannot switch libtpms while swtpm is running')
        library = Path(library)
        if library.name != 'libtpms.so.0' or library.is_symlink():
            raise VMError(f'swtpm must load a frozen private libtpms.so.0 copy, not {library}')
        self.library, self.library_sha256 = library.resolve(), library_sha256

    def start(self, timeout=30):
        if len(os.fsencode(self.socket)) > 103:
            raise VMError(f'Unix socket path too long; use a shorter checkout path: {self.socket}')
        self.state.mkdir(parents=True, exist_ok=True)
        self.socket.unlink(missing_ok=True)
        env = {key: value for key, value in os.environ.items() if not key.startswith('LD_')}
        env['LD_LIBRARY_PATH'] = str(self.library.parent)
        self.child = Process([str(self.binary), 'socket', '--tpm2', '--tpmstate', f'dir={self.state}',
                              '--ctrl', f'type=unixio,path={self.socket}', '--flags', 'not-need-init'],
                             self.workdir, 'swtpm', env)
        deadline = time.monotonic() + timeout
        try:
            while time.monotonic() < deadline:
                self.child.check()
                if self.socket.exists():
                    self.starts.append(self.verify_library())
                    return
                time.sleep(0.05)
            raise VMError('Timed out waiting for swtpm socket')
        except BaseException:
            self.stop()
            raise

    def verify_library(self) -> dict:
        expected = self.library.stat()
        pid = self.child.process.pid
        maps = Path(f'/proc/{pid}/maps').read_text()
        loaded = None
        for line in maps.splitlines():
            fields = line.split(maxsplit=5)
            if len(fields) < 6:
                continue
            major, minor = (int(part, 16) for part in fields[3].split(':'))
            same = (int(fields[4]) == expected.st_ino and
                    os.makedev(major, minor) == expected.st_dev)
            if same:
                loaded = fields[5]
            mapped_name = Path(fields[5].removesuffix(' (deleted)')).name
            if (mapped_name == 'libtpms.so' or mapped_name.startswith('libtpms.so.')) and not same:
                raise VMError(f'swtpm loaded an unexpected libtpms: {fields[5]}')
        if loaded is None:
            raise VMError('The frozen libtpms copy was not found in swtpm /proc/PID/maps')
        digest = sha256(self.library)
        if digest != self.library_sha256:
            raise VMError(f'Frozen libtpms copy changed: {digest} != {self.library_sha256}')
        return {'pid': pid, 'started_at': utc_now(), 'library': str(self.library), 'mapped_library': loaded,
                'inode': expected.st_ino, 'sha256': digest}

    def stop(self):
        if self.child is not None:
            child, self.child = self.child, None
            child.stop()


class JSONConnection:
    """One synchronous QMP/QGA stream; every operation has a fixed deadline."""
    def __init__(self, sock: socket.socket, timeout: float):
        self.socket, self.timeout, self.buffer = sock, timeout, b''

    @classmethod
    def connect(cls, path: Path, timeout: float):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect(str(path))
        except BaseException:
            sock.close()
            raise
        return cls(sock, timeout)

    def close(self):
        self.socket.close()

    def read(self, deadline: float):
        while b'\n' not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise VMError('Protocol response timed out')
            self.socket.settimeout(remaining)
            try:
                data = self.socket.recv(65536)
            except TimeoutError as exc:
                raise VMError('Protocol response timed out') from exc
            if not data:
                raise VMError('Protocol connection closed')
            self.buffer += data
            if len(self.buffer) > 16 * 1024 * 1024:
                raise VMError('Protocol response exceeds 16 MiB')
        line, self.buffer = self.buffer.split(b'\n', 1)
        return line

    def send(self, command: str, arguments=None):
        request = {'execute': command}
        if arguments is not None:
            request['arguments'] = arguments
        self.socket.settimeout(self.timeout)
        self.socket.sendall(json.dumps(request).encode() + b'\n')

    def execute(self, command: str, arguments=None):
        started, timeout = time.monotonic(), self.timeout
        deadline = started + timeout
        try:
            self.send(command, arguments)
            while True:
                try:
                    response = json.loads(self.read(deadline))
                except (ValueError, UnicodeDecodeError) as exc:
                    raise VMError('Invalid JSON protocol response') from exc
                if 'event' in response:
                    continue
                if 'error' in response:
                    raise VMError(str(response['error']))
                if 'return' not in response:
                    raise VMError('missing return value')
                return response['return']
        except (VMError, OSError) as exc:
            elapsed = time.monotonic() - started
            raise VMError(f'{command} failed after {elapsed:.3f}s (timeout {timeout:.3f}s): {exc}') from exc

    def sync(self):
        token = secrets.randbits(48)
        request = {'execute': 'guest-sync-delimited', 'arguments': {'id': token}}
        self.socket.settimeout(self.timeout)
        self.socket.sendall(b'\xff' + json.dumps(request).encode() + b'\n')
        deadline = time.monotonic() + self.timeout
        while True:
            line = self.read(deadline)
            if b'\xff' not in line:
                continue
            try:
                value = json.loads(line.rsplit(b'\xff', 1)[1])
            except ValueError:
                continue
            if value.get('return') == token:
                return


def guest_exec(agent: JSONConnection, executable: str, arguments: list[str], timeout: float,
               input_data: bytes | None = None) -> dict:
    deadline = time.monotonic() + timeout
    # Windows can take over 10 seconds to launch the first PowerShell process.
    agent.timeout = min(30, timeout)
    request = {'path': executable, 'arg': arguments, 'capture-output': True}
    if input_data is not None:
        request['input-data'] = base64.b64encode(input_data).decode('ascii')
    started = agent.execute('guest-exec', request)
    while time.monotonic() < deadline:
        agent.timeout = min(10, max(0.001, deadline - time.monotonic()))
        status = agent.execute('guest-exec-status', {'pid': started['pid']})
        if status.get('exited'):
            return status
        time.sleep(min(0.2, max(0, deadline - time.monotonic())))
    raise VMError(f'Guest command timed out: {executable}')


def decoded_output(status: dict, stream: str = 'out-data') -> str:
    try:
        return base64.b64decode(status.get(stream, ''), validate=True).decode('utf-8-sig').strip()
    except (ValueError, UnicodeDecodeError) as exc:
        raise VMError('Invalid guest command output encoding') from exc


def command_output(status: dict) -> str:
    if status.get('exitcode') != 0 or status.get('signal') or status.get('out-truncated') or status.get('err-truncated'):
        raise VMError(f'Guest command failed: exit {status.get("exitcode")}, stdout {decoded_output(status)!r}, '
                      f'stderr {decoded_output(status, "err-data")!r}')
    return decoded_output(status)


def probe_result(status: dict, action: str) -> dict:
    output = command_output(status)
    try:
        result = json.loads(output)
    except ValueError as exc:
        raise VMError(f'Guest probe did not return JSON: {output!r}') from exc
    if not isinstance(result, dict) or result.get('status') != 'PASS':
        raise VMError(f'Guest probe failed: {result}')
    if result.get('action') != action:
        raise VMError(f'Guest probe answered action {result.get("action")!r}, expected {action!r}')
    return result


def _strict_b64(value, field: str, limit: int) -> bytes:
    if not isinstance(value, str) or not value or len(value) > limit * 2:
        raise VMError(f'Probe field {field} is missing or oversized')
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise VMError(f'Probe field {field} is not strict base64') from exc
    if not data or len(data) > limit:
        raise VMError(f'Probe field {field} has an invalid length')
    return data


def _openssl(openssl: str, arguments: list[str], log, stdin: bytes | None = None) -> subprocess.CompletedProcess:
    completed = subprocess.run([openssl, *arguments], input=stdin, capture_output=True, timeout=30, check=False)
    log.write(b'$ openssl ' + ' '.join(arguments).encode() + b'\n' + completed.stdout + completed.stderr +
              f'[exit {completed.returncode}]\n'.encode())
    return completed


def verify_signature_evidence(result: dict, challenge: str, evidence: Path, openssl: str) -> dict:
    """Verify a probe's signature over the host challenge with host OpenSSL, independent of guest PASS."""
    if result.get('challenge') != challenge:
        raise VMError('Probe challenge does not match the host-generated challenge')
    if result.get('signature_scheme') != SIGNATURE_SCHEME:
        raise VMError(f'Unexpected signature scheme: {result.get("signature_scheme")!r}')
    if result.get('public_key_encoding') != PUBLIC_KEY_ENCODING:
        raise VMError(f'Unexpected public key encoding: {result.get("public_key_encoding")!r}')
    public = _strict_b64(result.get('public_key'), 'public_key', 4096)
    signature = _strict_b64(result.get('signature'), 'signature', 2048)
    (evidence / 'challenge.bin').write_bytes(bytes.fromhex(challenge))
    (evidence / 'signature.bin').write_bytes(signature)
    (evidence / 'public.der').write_bytes(public)
    with (evidence / 'openssl.log').open('wb') as log:
        canonical = _openssl(openssl, ['pkey', '-pubin', '-inform', 'DER', '-outform', 'DER'], log, public)
        if canonical.returncode or canonical.stdout != public:
            raise VMError('Public key is not a canonical DER SubjectPublicKeyInfo')
        text = _openssl(openssl, ['pkey', '-pubin', '-inform', 'DER', '-noout', '-text_pub'], log, public)
        match = re.match(rb'(?:RSA )?Public-Key: \((\d+) bit\)\s*\nModulus:', text.stdout)
        if text.returncode or not match:
            raise VMError('Public key is not an RSA key')
        bits = int(match.group(1))
        if bits < 2048:
            raise VMError(f'RSA key is too small: {bits} bits')
        converted = _openssl(openssl, ['pkey', '-pubin', '-inform', 'DER', '-in', str(evidence / 'public.der'),
                                       '-out', str(evidence / 'public.pem')], log)
        if converted.returncode:
            raise VMError('Could not convert the public key to PEM')
        verified = _openssl(openssl, ['dgst', '-sha256', '-verify', str(evidence / 'public.pem'),
                                      '-signature', str(evidence / 'signature.bin'), str(evidence / 'challenge.bin')], log)
        if verified.returncode or verified.stdout.strip() != b'Verified OK':
            raise VMError('Host OpenSSL rejected the probe signature')
    return {'signature_verified': True, 'key_bits': bits,
            'key_fingerprint_sha256': hashlib.sha256(public).hexdigest(),
            'public_key': result['public_key']}


class VM:
    def __init__(self, directory: Path, manifest: dict, binaries: dict, timeout: float):
        self.directory, self.manifest, self.binaries, self.timeout = directory, manifest, binaries, timeout
        self.qemu = self.qmp = self.agent = None
        self.swtpm = Swtpm(Path(binaries['swtpm']), Path(binaries['library']), directory / 'tpm-state',
                           directory / 'tpm.sock', directory, binaries['library_sha256'])

    def start(self):
        self.swtpm.start(min(30, self.timeout))
        for name in ('qmp.sock', 'qga.sock'):
            (self.directory / name).unlink(missing_ok=True)
        m = self.manifest
        command = [self.binaries['qemu-system-x86_64'], '-enable-kvm', '-machine', 'q35', '-cpu', m['cpu'],
                   '-m', str(m['memory_mb']), '-smp', str(m['cpus']), '-display', 'none',
                   '-drive', 'if=pflash,format=raw,readonly=on,file=firmware.fd',
                   '-drive', 'if=pflash,format=raw,file=efivars.fd',
                   '-drive', 'if=virtio,format=qcow2,file=disk.qcow2',
                   '-chardev', 'socket,id=chrtpm,path=tpm.sock', '-tpmdev', 'emulator,id=tpm0,chardev=chrtpm',
                   '-device', 'tpm-crb,tpmdev=tpm0', '-device', 'virtio-serial-pci',
                   '-chardev', 'socket,path=qga.sock,server=on,wait=off,id=qga0',
                   '-device', 'virtserialport,chardev=qga0,name=org.qemu.guest_agent.0',
                   '-qmp', 'unix:qmp.sock,server=on,wait=off', '-serial', 'file:serial.log',
                   '-netdev', 'user,id=n0', '-device', 'virtio-net-pci,netdev=n0']
        self.qemu = Process(command, self.directory, 'qemu')
        deadline = time.monotonic() + self.timeout
        last_error = None
        while time.monotonic() < deadline:
            self.qemu.check()
            self.swtpm.child.check()
            try:
                self.qmp = JSONConnection.connect(self.directory / 'qmp.sock', min(5, self.timeout))
                greeting = json.loads(self.qmp.read(time.monotonic() + min(5, self.timeout)))
                if 'QMP' not in greeting:
                    raise VMError('Missing QMP greeting')
                self.qmp.execute('qmp_capabilities')
                if self.qmp.execute('query-status').get('status') != 'running':
                    raise VMError('QEMU is not running')
                self.wait_agent(deadline)
                return
            except (OSError, VMError, ValueError) as exc:
                last_error = exc
                if self.qmp:
                    self.qmp.close()
                    self.qmp = None
                time.sleep(0.2)
        raise VMError(f'VM boot timed out: {last_error}')

    def wait_agent(self, deadline: float):
        last_error = None
        while time.monotonic() < deadline:
            self.qemu.check()
            if self.agent:
                self.agent.close()
                self.agent = None
            try:
                self.agent = JSONConnection.connect(self.directory / 'qga.sock', min(5, max(.001, deadline - time.monotonic())))
                self.agent.sync()
                self.agent.execute('guest-ping')
                return
            except (OSError, VMError) as exc:
                last_error = exc
                time.sleep(.2)
        raise VMError(f'QEMU guest agent readiness timed out: {last_error}')

    def boot_id(self):
        if self.manifest['guest'] == 'linux':
            executable, arguments = '/bin/cat', ['/proc/sys/kernel/random/boot_id']
        else:
            executable, arguments = POWERSHELL, ['-NoProfile', '-NonInteractive', '-Command', WINDOWS_BOOT_ID]
        identity = command_output(guest_exec(self.agent, executable, arguments, self.timeout))
        if not identity:
            raise VMError('Guest boot identity is empty')
        return identity

    def stage_probe(self, payload: bytes) -> str:
        """Install this run's probe in the overlay and verify its on-disk hash."""
        expected = hashlib.sha256(payload).hexdigest()
        if self.manifest['guest'] == 'linux':
            executable = '/usr/bin/python3'
            script = (
                "import hashlib,pathlib,sys; "
                "p=pathlib.Path('/usr/local/libexec/libtpms-integration-probe'); "
                "p.parent.mkdir(parents=True,exist_ok=True); "
                "p.write_bytes(sys.stdin.buffer.read()); p.chmod(0o755); "
                "print(hashlib.sha256(p.read_bytes()).hexdigest())"
            )
            arguments, stdin = ['-c', script], payload
        else:
            executable = POWERSHELL
            script = (
                "$ErrorActionPreference='Stop'; "
                r"$p='C:\libtpms-integration\probe.ps1'; "
                "[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($p)) | Out-Null; "
                "[IO.File]::WriteAllBytes($p,[Convert]::FromBase64String([Console]::In.ReadToEnd())); "
                "(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()"
            )
            arguments = ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script]
            # ASCII base64 avoids Windows stdin text-encoding transformations.
            stdin = base64.b64encode(payload)
        status = guest_exec(self.agent, executable, arguments, self.timeout, input_data=stdin)
        atomic_json(self.directory / 'probe-stage.json', {'expected_sha256': expected, 'command': status})
        observed = command_output(status)
        if observed != expected:
            raise VMError(f'Staged guest probe SHA-256 mismatch: expected {expected}, got {observed!r}')
        return expected

    def select_library(self, library: Path, library_sha256: str):
        """Cold library switch: QEMU and swtpm must both be stopped, and nothing may still run in the work tree."""
        if self.qemu is not None or self.swtpm.child is not None:
            raise VMError('Cannot switch libtpms while QEMU or swtpm is running')
        remaining = survivors(self.directory) if platform.system() == 'Linux' else []
        if remaining:
            raise VMError(f'Processes still use the work tree before the library switch: {remaining}')
        self.swtpm.select_library(library, library_sha256)
        return remaining

    def probe(self, action: str, extra: list[str], record: Path) -> dict:
        if self.manifest['guest'] == 'linux':
            executable, arguments = '/usr/local/libexec/libtpms-integration-probe', [action, *extra]
        else:
            executable = POWERSHELL
            arguments = ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File',
                         'C:\\libtpms-integration\\probe.ps1', action, *extra]
        status = guest_exec(self.agent, executable, arguments, self.timeout)
        atomic_json(record, status)
        return probe_result(status, action)

    def shutdown(self):
        self.agent.timeout = min(10, self.timeout)
        self.agent.send('guest-shutdown', {'mode': 'powerdown'})
        try:
            code = self.qemu.process.wait(timeout=self.timeout)
        except subprocess.TimeoutExpired as exc:
            raise VMError('Guest powerdown timed out') from exc
        if code != 0:
            raise VMError(f'QEMU shutdown exited with status {code}')
        self.stop()

    def reboot(self, previous_boot: str):
        self.agent.send('guest-shutdown', {'mode': 'reboot'})
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            try:
                self.wait_agent(deadline)
                identity = self.boot_id()
                if identity != previous_boot:
                    return identity
            except (OSError, VMError):
                # The old agent can answer ping just before the guest goes down.
                pass
            time.sleep(min(.5, max(0, deadline - time.monotonic())))
        raise VMError('Warm reboot did not change guest boot identity')

    def failure_diagnostics(self):
        """Best effort QMP evidence, with a three-second bound per operation."""
        result = {}
        connection = None
        try:
            # A failed command may have left a late reply on the old stream.
            if self.qmp:
                self.qmp.close()
                self.qmp = None
            if self.qemu is None or self.qemu.process.poll() is not None:
                raise VMError('QEMU is not running')
            connection = JSONConnection.connect(self.directory / 'qmp.sock', 3)
            connection.timeout = 3
            greeting = json.loads(connection.read(time.monotonic() + 3))
            if 'QMP' not in greeting:
                raise VMError('Missing QMP greeting for failure diagnostics')
            connection.execute('qmp_capabilities')
            result['qmp_status'] = connection.execute('query-status')
            screenshot = self.directory / 'failure.ppm'
            connection.execute('screendump', {'filename': str(screenshot)})
            if not screenshot.is_file():
                raise VMError('QMP screendump did not produce failure.ppm')
            result['screenshot'] = screenshot.name
        except Exception as exc:
            result['diagnostics_error'] = f'{type(exc).__name__}: {exc}'
        finally:
            if connection:
                connection.close()
        return result

    def stop(self):
        for connection in (self.agent, self.qmp):
            if connection:
                connection.close()
        self.agent = self.qmp = None
        try:
            if self.qemu:
                qemu, self.qemu = self.qemu, None
                qemu.stop()
        finally:
            self.swtpm.stop()
