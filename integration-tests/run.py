#!/usr/bin/env python3
"""Launch an immutable image bundle and test TPM persistence across warm and cold boots, or across a
libtpms round trip (initial library -> transition library -> initial library) on one working state."""
from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
from pathlib import Path
import platform
import secrets
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent
RUNNER_SOURCES = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in ('run.py', 'vm.py')}

from vm import (LIFECYCLE, VM, Cancelled, VMError, WINDOWS_CPU, atomic_json, become_subreaper,  # noqa: E402
                begin_cleanup, bundle_path, cancellation_signal, finish_cleanup, install_signal_handlers,
                freeze_library, preflight, sha256, snapshot, tool_version, utc_now, verify_signature_evidence)

FAULTS = ('signature', 'challenge', 'malformed', 'key')
ROUND_TRIP_FAULTS = ('secondary-key', 'nv-value')
PHASES = (('initial', 'library'), ('transition', 'transition_library'), ('final', 'library'))
NV_INDEX = '0x1500020'


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError('must be a positive integer')
    return number


def non_negative(value):
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError('must be zero or a positive integer')
    return number


def load_manifest(image):
    manifest_bytes = (image / 'manifest.json').read_bytes()
    manifest = json.loads(manifest_bytes)
    if not isinstance(manifest, dict) or manifest.get('schema_version') != 2:
        raise VMError('Expected bundle manifest schema_version 2 (rebuild older bundles with build.py)')
    if manifest.get('guest') not in ('linux', 'windows'):
        raise VMError('Manifest guest must be linux or windows')
    allowed_cpus = (WINDOWS_CPU,) if manifest['guest'] == 'windows' else ('host',)
    if manifest.get('machine') != 'q35' or manifest.get('cpu') not in allowed_cpus:
        raise VMError('Bundle must use q35 and the supported CPU profile for its guest')
    for field in ('memory_mb', 'cpus'):
        if type(manifest.get(field)) is not int or manifest[field] < 1:
            raise VMError(f'Manifest {field} must be a positive integer')
    if not isinstance(manifest.get('guest_os'), dict):
        raise VMError('Manifest lacks the guest OS identity recorded at build time')
    paths = {key: bundle_path(image, manifest.get(key)) for key in ('disk', 'firmware', 'variables', 'tpm_state')}
    for key, path in paths.items():
        if not (path.is_dir() if key == 'tpm_state' else path.is_file()):
            raise VMError(f'Invalid bundle {key}: {path}')
    if not any(paths['tpm_state'].iterdir()):
        raise VMError('Bundle TPM state must not be empty')
    return manifest, manifest_bytes, paths


def identity_key(guest: str, os_identity: dict) -> dict:
    fields = ('id', 'version_id') if guest == 'linux' else ('edition_id', 'current_build')
    return {field: os_identity.get(field) for field in fields}


def inject_fault(kind: str, result: dict, challenge: str, evidence, openssl: str) -> None:
    """Tamper with guest evidence before host verification (manual negative checks only)."""
    if kind == 'signature':
        signature = bytearray(base64.b64decode(result['signature']))
        signature[-1] ^= 1
        result['signature'] = base64.b64encode(bytes(signature)).decode()
    elif kind == 'challenge':
        result['challenge'] = secrets.token_hex(32)
    elif kind == 'malformed':
        result['signature'] = 'not base64!'
    elif kind == 'key':
        key = evidence / 'injected-key.pem'
        (evidence / 'injected-challenge.bin').write_bytes(bytes.fromhex(challenge))
        subprocess.run([openssl, 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', str(key)],
                       check=True, capture_output=True, timeout=60)
        public = subprocess.run([openssl, 'pkey', '-in', str(key), '-pubout', '-outform', 'DER'],
                                check=True, capture_output=True, timeout=30).stdout
        signature = subprocess.run([openssl, 'dgst', '-sha256', '-sign', str(key), str(evidence / 'injected-challenge.bin')],
                                   check=True, capture_output=True, timeout=30).stdout
        result['public_key'] = base64.b64encode(public).decode()
        result['signature'] = base64.b64encode(signature).decode()


def working_state(directory: Path) -> dict:
    """Identity of the per-run disk overlay, EFI variables and TPM state shared by every phase."""
    paths = [directory / 'disk.qcow2', directory / 'efivars.fd', *sorted((directory / 'tpm-state').rglob('*'))]
    return {str(path.relative_to(directory)): {'inode': path.stat().st_ino, 'sha256': sha256(path)}
            for path in paths if path.is_file()}


class Runner:
    def __init__(self, args, directory: Path, result: dict):
        self.args, self.directory, self.result = args, directory, result
        self.machine = None
        self.boot = None
        self.pins = {}
        self.phase = None
        self.nv_expected = None
        self.sequence = 0

    def save(self):
        if self.machine:
            self.result['swtpm_starts'] = self.machine.swtpm.starts
        atomic_json(self.directory / 'result.json', self.result)

    def guest_call(self, kind: str, action: str, arguments: list[str], entry: dict, cycle: int | None = None):
        self.sequence += 1
        label = f'{self.sequence:02d}-{kind}-{action}'
        evidence = self.directory / 'evidence' / label
        evidence.mkdir(parents=True)
        entry = {'kind': kind, 'action': action, **entry, 'expected_boot_id': self.boot,
                 'evidence': str(evidence.relative_to(self.directory))}
        if cycle is not None:
            entry['cycle'] = cycle
        if self.phase is not None:
            entry['phase'] = self.phase['number']
            self.phase['probes'].append(label)
        self.result['probes'].append(entry)
        guest = self.machine.probe(action, arguments, evidence / 'guest-exec.json')
        (evidence / 'probe.json').write_text(json.dumps(guest, indent=2) + '\n')
        entry['guest_boot_id'] = guest.get('boot_id')
        if guest.get('boot_id') != self.boot:
            raise VMError(f'Probe boot ID {guest.get("boot_id")!r} does not match the tested boot {self.boot!r}')
        return label, evidence, entry, guest

    def check_nv(self, entry: dict, observed, expected: str, label: str, field: str = 'nv'):
        check = {'probe': label, 'phase': entry.get('phase'), 'field': field, 'expected': expected,
                 'observed': observed, 'matched': observed == expected}
        entry[field] = check
        self.result['nv']['checks'].append(check)
        if not check['matched']:
            raise VMError(f'TPM NV readback {observed!r} does not match the host-expected value {expected!r}')

    def run_probe(self, kind: str, action: str, cycle: int | None = None, role: str = 'primary',
                  extra: tuple = ()) -> dict:
        challenge = secrets.token_hex(32)
        label, evidence, entry, guest = self.guest_call(kind, action, [challenge, *extra],
                                                        {'key_role': role, 'challenge': challenge}, cycle)
        fault = self.args.inject_fault
        if (fault in FAULTS and (fault != 'key' or role in self.pins)
                and not self.result['fault_injection']['applied']):
            inject_fault(fault, guest, challenge, evidence, self.binaries['openssl'])
            self.result['fault_injection'].update(applied=True, probe=label)
        if guest.get('key_role') != role:
            raise VMError(f'Probe answered for key role {guest.get("key_role")!r}, expected {role!r}')
        verified = verify_signature_evidence(guest, challenge, evidence, self.binaries['openssl'])
        guest_key_id = guest.get('key_handle') or guest.get('key_name')
        entry.update(signature_verified=True, key_fingerprint_sha256=verified['key_fingerprint_sha256'],
                     guest_key_id=guest_key_id)
        if action in ('setup', 'create-secondary'):
            if role in self.pins:
                raise VMError(f'The {role} key was already pinned')
            for other, pin in self.pins.items():
                if verified['public_key'] == pin['public_key'] or guest_key_id == pin['guest_key_id']:
                    raise VMError(f'The {role} key is not distinct from the {other} key')
            self.pins[role] = {**verified, 'guest_key_id': guest_key_id}
            pinned = {'fingerprint_sha256': verified['key_fingerprint_sha256'], 'bits': verified['key_bits'],
                      'encoding': 'x509-spki-der-base64', 'public_key': verified['public_key'],
                      'guest_key_id': guest_key_id, 'pinned_by': label}
            if role == 'primary':
                self.result['pinned_key'] = pinned
            if self.phase is not None:
                self.result['pinned_keys'][role] = {**pinned, 'created_in_phase': self.phase['number'],
                                                    'created_with_library_sha256': self.phase['library_sha256']}
        elif role not in self.pins:
            raise VMError(f'The {role} key was never pinned')
        elif verified['public_key'] != self.pins[role]['public_key']:
            raise VMError(f'TPM {role} public key changed from the key pinned during setup')
        elif guest_key_id != self.pins[role]['guest_key_id']:
            raise VMError(f'TPM {role} key moved from {self.pins[role]["guest_key_id"]!r} to {guest_key_id!r}')
        if self.nv_expected is not None and role == 'primary':
            self.check_nv(entry, guest.get('nv_value'), self.nv_expected, label)
        return entry

    def update_nv(self, value: str) -> dict:
        label, evidence, entry, guest = self.guest_call(self.phase['name'], 'update-nv', [value], {'nv_written': value})
        if guest.get('nv_index') != NV_INDEX:
            raise VMError(f'NV update touched {guest.get("nv_index")!r}, expected {NV_INDEX}')
        self.check_nv(entry, guest.get('nv_previous'), self.nv_expected, label, 'nv_previous')
        self.check_nv(entry, guest.get('nv_value'), value, label, 'nv_readback')
        self.nv_expected = value
        entry['nv_write_verified'] = True
        return entry

    def new_boot(self, kind: str, identity: str, cycle: int | None = None):
        previous = [boot['id'] for boot in self.result['boots']]
        if identity in previous:
            raise VMError(f'{kind} boot reused an earlier boot identity {identity!r}')
        self.boot = identity
        boot = {'kind': kind, 'id': identity}
        if cycle is not None:
            boot['cycle'] = cycle
        if self.phase is not None:
            boot['phase'] = self.phase['number']
            self.phase['boot_id'] = identity
        self.result['boots'].append(boot)

    def first_boot(self, manifest: dict, probe_payload: bytes):
        result, directory = self.result, self.directory
        self.machine.start()
        self.record_start()
        self.machine.stage_probe(probe_payload)
        result['probe']['staged'] = True
        self.new_boot('initial', self.machine.boot_id())
        identity = self.machine.probe('identity', [], directory / 'guest-identity-exec.json')
        result['guest_os'] = identity.get('os')
        if identity.get('boot_id') != self.boot:
            raise VMError('Identity probe boot ID does not match the tested boot')
        if not isinstance(result['guest_os'], dict):
            raise VMError('Identity probe returned no OS identity')
        expected = identity_key(manifest['guest'], manifest['guest_os'])
        observed = identity_key(manifest['guest'], result['guest_os'])
        if None in expected.values() or expected != observed:
            raise VMError(f'Guest OS identity {observed} does not match the image manifest {expected}')
        if manifest['guest'] == 'windows':
            result['provisioning_access'] = identity.get('provisioning_access')
            if not isinstance(result['provisioning_access'], dict) or result['provisioning_access'].get('exposed') is not False:
                raise VMError(f'Image still exposes provisioning WinRM access: {result["provisioning_access"]}')

    def record_start(self):
        """Tie the latest swtpm start to the running phase and prove it mapped that phase's frozen copy."""
        starts = self.machine.swtpm.starts
        if self.phase is None:
            return
        start = starts[-1]
        start.update(phase=self.phase['number'], library_role=self.phase['library_role'])
        self.phase['swtpm_starts'].append(len(starts) - 1)
        if start['sha256'] != self.phase['library_sha256'] or start['library'] != self.phase['library_copy']:
            raise VMError(f'Phase {self.phase["number"]} swtpm loaded {start["library"]} ({start["sha256"]}), '
                          f'expected {self.phase["library_copy"]} ({self.phase["library_sha256"]})')
        if Path(start['mapped_library']).resolve() != Path(self.phase['library_copy']):
            raise VMError(f'Phase {self.phase["number"]} swtpm mapped {start["mapped_library"]}')

    def persistence(self, manifest: dict, probe_payload: bytes):
        args, result = self.args, self.result
        self.first_boot(manifest, probe_payload)
        self.run_probe('initial', 'setup')
        self.save()
        if args.warm_reboots:
            for cycle in range(1, args.warm_reboots + 1):
                self.new_boot('warm', self.machine.reboot(self.boot), cycle)
                self.run_probe('warm', 'verify', cycle)
                result['restarts']['warm_completed'] = cycle
                self.save()
        for cycle in range(1, args.cycles + 1):
            self.machine.shutdown()  # Stops QEMU and swtpm; retains overlay, vars, and TPM state.
            self.machine.start()
            self.new_boot('cold', self.machine.boot_id(), cycle)
            self.run_probe('cold', 'verify', cycle)
            result['restarts']['cold_completed'] = cycle
            self.save()
        self.machine.shutdown()

    def begin_phase(self, number: int):
        phase = self.result['phases'][number - 1]
        phase.update(status='RUNNING', started_at=utc_now())
        self.phase = phase
        phase['working_state_before'] = working_state(self.directory)
        if number > 1:
            previous = self.result['phases'][number - 2]
            if phase['working_state_before'] != previous['working_state_after']:
                raise VMError(f'Working state changed between phase {number - 1} and phase {number}')
            phase['processes_before_library_switch'] = self.machine.select_library(
                Path(phase['library_copy']), phase['library_sha256'])
        self.save()

    def end_phase(self):
        self.machine.shutdown()  # QEMU and swtpm both exit before the next library is selected.
        phase = self.phase
        phase['working_state_after'] = working_state(self.directory)
        phase.update(status='PASS', finished_at=utc_now())
        self.phase = None
        self.save()

    def cold_phase_boot(self, number: int):
        self.machine.start()
        self.record_start()
        self.new_boot('cold', self.machine.boot_id(), number - 1)

    def round_trip(self, manifest: dict, probe_payload: bytes):
        result, linux = self.result, manifest['guest'] == 'linux'
        fault = self.args.inject_fault
        initial_nv = secrets.token_hex(32) if linux else None
        updated_nv = secrets.token_hex(32) if linux else None
        if linux:
            while updated_nv == initial_nv:
                updated_nv = secrets.token_hex(32)
            result['nv'].update(initial_value=initial_nv, updated_value=updated_nv)

        self.begin_phase(1)
        self.first_boot(manifest, probe_payload)
        self.nv_expected = initial_nv
        self.run_probe('initial', 'setup', extra=(initial_nv,) if linux else ())
        self.run_probe('initial', 'verify')
        self.end_phase()

        self.begin_phase(2)
        self.cold_phase_boot(2)
        self.run_probe('transition', 'verify')
        self.run_probe('transition', 'create-secondary', role='secondary')
        if linux:
            self.update_nv(updated_nv)
        self.run_probe('transition', 'verify')
        self.run_probe('transition', 'verify-secondary', role='secondary')
        result['restarts']['cold_completed'] = 1
        self.end_phase()

        self.begin_phase(3)
        self.cold_phase_boot(3)
        if fault == 'secondary-key':
            label = self.guest_call('final', 'remove-secondary', [], {'fault': True})[0]
            result['fault_injection'].update(applied=True, probe=label)
        elif fault == 'nv-value':
            label = self.guest_call('final', 'update-nv', [secrets.token_hex(32)], {'fault': True})[0]
            result['fault_injection'].update(applied=True, probe=label)
        self.save()
        self.run_probe('final', 'verify')
        self.run_probe('final', 'verify-secondary', role='secondary')
        result['restarts']['cold_completed'] = 2
        self.end_phase()

        boots = [boot['id'] for boot in result['boots']]
        if len(boots) != 3 or len(set(boots)) != 3:
            raise VMError(f'Expected three distinct boot IDs, got {boots}')
        starts = self.machine.swtpm.starts
        sequence = [start['sha256'] for start in starts]
        expected = [phase['library_sha256'] for phase in result['phases']]
        if sequence != expected:
            raise VMError(f'swtpm library sequence {sequence} does not match the requested {expected}')
        if starts[0]['inode'] != starts[2]['inode'] or starts[0]['inode'] == starts[1]['inode']:
            raise VMError('The final phase did not reuse the exact initial frozen library copy')
        if set(self.pins) != {'primary', 'secondary'}:
            raise VMError(f'Expected primary and secondary pinned keys, got {sorted(self.pins)}')
        if linux and result['nv']['checks'][-1]['expected'] != updated_nv:
            raise VMError('The final NV check did not verify the transition-phase value')
        result['library_sequence_verified'] = True

    def execute(self):
        args, result, directory = self.args, self.result, self.directory
        self.binaries = binaries = preflight(args.swtpm)
        binaries.update(freeze_library(args.library, directory))
        result['library'] = {'source_path': binaries['library_source'],
                             'source_resolved': binaries['library_source_resolved'],
                             'private_copy': binaries['library'], 'sha256': binaries['library_sha256']}
        if args.transition_library:
            transition = freeze_library(args.transition_library, directory, 'lib-transition')
            result['transition_library'] = {'source_path': transition['library_source'],
                                            'source_resolved': transition['library_source_resolved'],
                                            'private_copy': transition['library'],
                                            'sha256': transition['library_sha256']}
            if transition['library_sha256'] == binaries['library_sha256']:
                raise VMError('--library and --transition-library have identical SHA-256; nothing would change')
            for phase in result['phases']:
                library = result[phase['library_role']]
                phase.update(library_sha256=library['sha256'], library_copy=library['private_copy'])
        result['swtpm'] = {'path': binaries['swtpm'], 'sha256': binaries['swtpm_sha256']}
        result['host'].update(openssl=tool_version([binaries['openssl'], 'version']),
                              qemu=tool_version([binaries['qemu-system-x86_64'], '--version']))
        image = args.image.resolve()
        manifest, manifest_bytes, paths = load_manifest(image)
        (directory / 'image-manifest.json').write_bytes(manifest_bytes)
        result['image'].update(manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(), guest=manifest['guest'],
                               build_id=manifest.get('build_id'), library_sha256=manifest.get('library_sha256'),
                               guest_os=manifest['guest_os'])
        if args.transition_library:
            if manifest['guest'] == 'linux':
                result['nv'] = {'covered': True, 'index': NV_INDEX, 'checks': []}
            else:
                result['nv'] = {'covered': False, 'reason': 'raw TPM NV is exercised on Linux guests only'}
                if args.inject_fault == 'nv-value':
                    raise VMError('--inject-fault nv-value needs a Linux guest')
        probe_name = 'linux-probe.py' if manifest['guest'] == 'linux' else 'windows-probe.ps1'
        probe_payload = (ROOT / 'guest' / probe_name).read_bytes()
        result['probe'] = {'name': probe_name, 'sha256': hashlib.sha256(probe_payload).hexdigest(), 'staged': False}
        original = snapshot(image)
        self.original = original
        atomic_json(directory / 'base-hashes.json', original)
        shutil.copy2(paths['firmware'], directory / 'firmware.fd')
        shutil.copy2(paths['variables'], directory / 'efivars.fd')
        shutil.copytree(paths['tpm_state'], directory / 'tpm-state')
        with (directory / 'qemu-img.stdout.log').open('wb') as stdout, (directory / 'qemu-img.stderr.log').open('wb') as stderr:
            info = subprocess.run([binaries['qemu-img'], 'info', '-U', '--output=json', str(paths['disk'])],
                                  capture_output=True, check=True, timeout=args.timeout)
            stdout.write(info.stdout)
            stderr.write(info.stderr)
            disk = json.loads(info.stdout)
            if disk.get('format') != 'qcow2' or disk.get('backing-filename'):
                raise VMError('Image must be a standalone qcow2 disk without a backing file')
            subprocess.run([binaries['qemu-img'], 'create', '-f', 'qcow2', '-F', 'qcow2',
                            '-b', str(paths['disk']), str(directory / 'disk.qcow2')],
                           stdout=stdout, stderr=stderr, check=True, timeout=args.timeout)
        self.machine = VM(directory, manifest, binaries, args.timeout)
        if args.transition_library:
            self.round_trip(manifest, probe_payload)
        else:
            self.persistence(manifest, probe_payload)
        result['checks_completed'] = True


def run(args) -> int:
    run_root = ROOT / 'img' / 'runs'
    image = args.image.resolve()
    if run_root.resolve().is_relative_to(image):
        raise VMError('Image bundle cannot contain the runs directory')
    directory = run_root / (datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + secrets.token_hex(3))
    directory.mkdir(parents=True)
    print(f'Run artifacts: {directory}', flush=True)
    result = {
        'schema_version': 2, 'status': 'RUNNING', 'started_at': utc_now(), 'run_directory': str(directory),
        'host': {'node': platform.node(), 'kernel': platform.release()},
        'runner_sources': RUNNER_SOURCES, 'image': {'path': str(image)},
        'timeout_seconds_per_operation': args.timeout,
        'scenario': {'name': 'library-round-trip' if args.transition_library else 'single-library-persistence'},
        'restarts': {'warm_requested': args.warm_reboots, 'warm_completed': 0,
                     'cold_requested': args.cycles, 'cold_completed': 0},
        'fault_injection': {'kind': args.inject_fault, 'applied': False} if args.inject_fault else None,
        'checks_completed': False, 'boots': [], 'probes': [],
        'artifacts': {'library_copy': 'lib/libtpms.so.0', 'image_manifest': 'image-manifest.json',
                      'base_hashes': 'base-hashes.json',
                      'probe_stage': 'probe-stage.json', 'guest_identity': 'guest-identity-exec.json',
                      'evidence': 'evidence/', 'logs': ['qemu.stdout.log', 'qemu.stderr.log', 'swtpm.stdout.log',
                                                        'swtpm.stderr.log', 'serial.log', 'qemu-img.stderr.log']},
    }
    if args.transition_library:
        result['scenario'].update(phases=len(PHASES), cold_transitions=len(PHASES) - 1,
                                  library_order=[role for _, role in PHASES])
        result['phases'] = [{'number': number, 'name': name, 'library_role': role, 'status': 'NOT_STARTED',
                             'boot_id': None, 'swtpm_starts': [], 'probes': []}
                            for number, (name, role) in enumerate(PHASES, 1)]
        result['pinned_keys'] = {}
        result['library_sequence_verified'] = False
        result['artifacts']['transition_library_copy'] = 'lib-transition/libtpms.so.0'
    runner = Runner(args, directory, result)
    try:
        runner.execute()
    except Cancelled as exc:
        result['error'] = str(exc)
    except Exception as exc:
        result['error'] = f'{type(exc).__name__}: {exc}'
    finally:
        begin_cleanup()
        try:
            if runner.machine and not result['checks_completed']:
                result['diagnostics'] = runner.machine.failure_diagnostics()
                if result['diagnostics'].get('screenshot'):
                    result['artifacts']['failure_screenshot'] = result['diagnostics']['screenshot']
        except Exception as exc:
            result['diagnostics'] = {'diagnostics_error': f'{type(exc).__name__}: {exc}'}
        cleanup_errors = []
        try:
            if runner.machine:
                runner.machine.stop()
        except Exception as exc:
            cleanup_errors.append(f'VM stop: {type(exc).__name__}: {exc}')
        if runner.machine:
            result['swtpm_starts'] = runner.machine.swtpm.starts
        result['cleanup'] = finish_cleanup(directory)
        result['cleanup']['errors'][:0] = cleanup_errors
        if cleanup_errors:
            result['cleanup']['status'] = 'ERROR'
        original = getattr(runner, 'original', None)
        if original is not None:
            try:
                result['base_unchanged'] = original == snapshot(image)
            except Exception as exc:
                result['base_unchanged'] = False
                result['base_error'] = f'{type(exc).__name__}: {exc}'
        else:
            result['base_unchanged'] = None
        signum = cancellation_signal()
        for phase in result.get('phases', []):
            if phase['status'] == 'RUNNING':
                phase.update(status='CANCELLED' if signum is not None else 'FAIL', finished_at=utc_now())
        if signum is not None:
            result['status'] = 'CANCELLED'
            result['cancel_signals'] = [int(sig) for sig in LIFECYCLE.signals]
        elif (result['checks_completed'] and result['cleanup']['status'] == 'OK' and result['base_unchanged'] is True
              and not result['fault_injection'] and 'error' not in result
              and all(phase['status'] == 'PASS' for phase in result.get('phases', []))):
            result['status'] = 'PASS'
        else:
            result['status'] = 'FAIL'
            if result['fault_injection'] and 'error' not in result:
                result['error'] = 'Fault injection was requested; an injected run can never pass'
        result['finished_at'] = utc_now()
        result['exit_status'] = 0 if result['status'] == 'PASS' else (128 + signum if signum is not None else 1)
        atomic_json(directory / 'result.json', result)
    print(json.dumps({key: result.get(key) for key in ('status', 'error', 'run_directory', 'exit_status')}, indent=2))
    return result['exit_status']


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter, epilog='''
Requires Linux x86_64, /dev/kvm, qemu-system-x86_64, qemu-img, openssl and a bundle
produced by build.py. Each run works on its own qcow2 overlay and copies of the EFI
variables and TPM state; the base bundle is hashed before and after. The current
guest probe is uploaded through QEMU Guest Agent and its SHA-256 checked in the guest.
Every signature is verified on the host with OpenSSL against the host challenge, and
the public key pinned at setup must be returned unchanged after every restart.

--transition-library runs the library round trip instead: exactly three phases on one
working overlay, EFI variable store and TPM state, separated by two cold transitions
in which QEMU and swtpm both exit before swtpm restarts on the other library.
  phase 1 (--library):            create the primary key; Linux defines the NV index and
                                  writes a host-generated value
  phase 2 (--transition-library): verify the primary key and NV value, create a distinct
                                  secondary key, and on Linux overwrite the NV value
  phase 3 (--library again):      verify both keys and, on Linux, the phase 2 NV value
Both libraries are frozen before the first boot; phase 3 loads the very copy phase 1
loaded, and every swtpm start is checked against /proc/PID/maps and the copy's hash.
Implementations are identified only by the supplied paths and their hashes. Windows
uses two non-exportable Microsoft Platform Crypto Provider keys and has no raw TPM NV
coverage. Warm reboots and --cycles do not apply and are rejected; identical library
hashes are rejected before any VM starts. Verification never creates or repairs state,
so --inject-fault secondary-key (remove the secondary key) or nv-value (Linux: write an
unexpected NV value) before the phase 3 checks must make the run fail.

--timeout bounds each single operation: one boot until the guest agent answers, one
guest command, or one guest shutdown. It is not a limit for the whole run.

SIGINT, SIGTERM and SIGHUP cancel the run once; further signals are ignored while
owned QEMU/swtpm processes are stopped (SIGTERM, then SIGKILL) and result.json is
written. SIGKILL or host failure cannot be cleaned up. Results are retained under
integration-tests/img/runs/<id>/result.json; exit status 0 means PASS.''')
    parser.add_argument('--image', type=Path, required=True, help='image bundle directory containing manifest.json')
    parser.add_argument('--swtpm', type=Path, required=True, help='swtpm executable to run')
    parser.add_argument('--library', type=Path, required=True, help='exact Linux x86_64 libtpms shared object to load')
    parser.add_argument('--transition-library', type=Path,
                        help='libtpms for the middle phase of the round trip; --library runs the first and last phase')
    parser.add_argument('--cycles', type=positive, help='cold QEMU+swtpm restart cycles (default: 1)')
    parser.add_argument('--warm-reboots', type=non_negative,
                        help='guest-initiated reboots before the cold cycles (default: 1)')
    parser.add_argument('--timeout', type=positive, default=600,
                        help='seconds per boot, guest command or shutdown (default: 600)')
    parser.add_argument('--inject-fault', choices=FAULTS + ROUND_TRIP_FAULTS,
                        help='manual negative check: tamper with guest evidence before host verification, or (round '
                             'trip only) damage the transition-phase state before phase 3; never passes')
    args = parser.parse_args()
    if args.transition_library:
        explicit = [flag for flag, value in (('--cycles', args.cycles), ('--warm-reboots', args.warm_reboots))
                    if value is not None]
        if explicit:
            parser.error(f'{" and ".join(explicit)} cannot be combined with --transition-library')
        args.cycles, args.warm_reboots = len(PHASES) - 1, 0
    else:
        if args.inject_fault in ROUND_TRIP_FAULTS:
            parser.error(f'--inject-fault {args.inject_fault} needs --transition-library')
        args.cycles = 1 if args.cycles is None else args.cycles
        args.warm_reboots = 1 if args.warm_reboots is None else args.warm_reboots
    install_signal_handlers()
    try:
        if platform.system() == 'Linux':
            become_subreaper()
        return run(args)
    except Cancelled as exc:
        print(f'CANCELLED: {exc}', file=sys.stderr)
        finish_cleanup(ROOT / 'img' / 'runs')
        return 128 + exc.signum
    except Exception as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        finish_cleanup(ROOT / 'img' / 'runs')
        return 1


if __name__ == '__main__':
    sys.exit(main())
