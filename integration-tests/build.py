#!/usr/bin/env python3
"""Build an ISO-based guest bundle on Linux x86_64/KVM; see --help for inputs."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import urllib.request

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent
IMG = ROOT / 'img'
WRAPPER_SOURCES = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in ('build.py', 'vm.py')}

from vm import (Cancelled, Process, Swtpm, VMError, WINDOWS_CPU, atomic_json, become_subreaper,  # noqa: E402
                begin_cleanup, cancellation_signal, finish_cleanup, freeze_library, install_signal_handlers, preflight, sha256,
                tool_version, utc_now)

BUILD_INPUT_DIRECTORIES = ('packer', 'guest')
BUILD_INTERRUPTION_GRACE = 30


def checksum(value: str) -> str:
    value = value.removeprefix('sha256:').lower()
    if not re.fullmatch('[0-9a-f]{64}', value):
        raise ValueError('A SHA-256 digest (64 hex digits) is required')
    return value


def cache_iso(source: str, expected: str, cache: Path) -> Path:
    expected = checksum(expected)
    cache.mkdir(parents=True, exist_ok=True)
    destination = cache / (expected + '.iso')
    if destination.exists():
        if sha256(destination) != expected:
            raise VMError(f'Cached ISO checksum mismatch: {destination}; remove it and retry')
        return destination
    with tempfile.NamedTemporaryFile(dir=cache, suffix='.part', delete=False) as stream:
        temporary = Path(stream.name)
        try:
            if source.startswith('https://'):
                with urllib.request.urlopen(source, timeout=60) as response:
                    if not response.url.startswith('https://'):
                        raise VMError('ISO download redirected to an insecure URL')
                    shutil.copyfileobj(response, stream, 1024 * 1024)
            else:
                with Path(source).expanduser().open('rb') as original:
                    shutil.copyfileobj(original, stream, 1024 * 1024)
            stream.flush()
            if sha256(temporary) != expected:
                raise VMError(f'ISO checksum mismatch: {source}')
            temporary.replace(destination)
        finally:
            temporary.unlink(missing_ok=True)
    return destination


def snapshot_inputs(destination: Path) -> dict[str, str]:
    """Copy the Packer templates, provisioning files and probes this build consumes; return their hashes."""
    hashes = {}
    for directory in BUILD_INPUT_DIRECTORIES:
        for source in sorted((ROOT / directory).rglob('*')):
            if source.is_symlink():
                raise VMError(f'Build inputs may not contain symlinks: {source}')
            if not source.is_file():
                continue
            relative = source.relative_to(ROOT)
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            target.chmod(0o400)
            hashes[str(relative)] = sha256(target)
    return hashes


def snapshot_file(source: Path, destination: Path) -> str:
    """Copy a firmware input once; the build and its provenance use only the read-only copy."""
    shutil.copyfile(source, destination)
    destination.chmod(0o400)
    return sha256(destination)


def normalize_driver_tree(root: Path):
    """Make our extracted copy writable for Packer's CD staging step."""
    if root.is_symlink():
        raise VMError(f'Staged driver tree may not be a symlink: {root}')
    root.chmod(0o700)
    for directory, directories, files in os.walk(root):
        for name in directories + files:
            path = Path(directory) / name
            if path.is_symlink():
                raise VMError(f'Staged driver tree may not contain symlinks: {path}')
            path.chmod(0o700 if path.is_dir() else 0o600)


def run_logged(command: list[str], work: Path, name: str, env: dict, timeout: float, grace: float = 10):
    child = Process(command, work, name, env)
    try:
        try:
            code = child.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise VMError(f'{name} exceeded {timeout}s; see {work}') from error
        if code:
            raise VMError(f'{name} exited with status {code}; see {work / (name + ".stdout.log")}')
    finally:
        child.stop(grace)


def load_identity(path: Path, guest: str) -> dict:
    if not path.is_file():
        raise VMError('Packer did not download the guest identity report')
    try:
        identity = json.loads(path.read_text(encoding='utf-8-sig'))
    except ValueError as exc:
        raise VMError('Guest identity report is not JSON') from exc
    os_identity = identity.get('os') if isinstance(identity, dict) else None
    if identity.get('status') != 'PASS' or not isinstance(os_identity, dict) or os_identity.get('family') != guest:
        raise VMError(f'Invalid guest identity report: {identity}')
    required = ('id', 'version_id') if guest == 'linux' else ('edition_id', 'current_build', 'caption')
    if any(not os_identity.get(field) for field in required):
        raise VMError(f'Guest identity lacks {required}: {os_identity}')
    return os_identity


def arguments():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''All generated files remain under integration-tests/img. Each build works in
img/builds/<id>: Packer inputs are copied to inputs/ and hashed, the bundle is staged
in bundle/, and it is moved to img/images/<name> only after success. A failed build
keeps its logs and result.json (status FAIL/CANCELLED) and does not reserve the name.

Image builds use the selected library; use the C reference library for a baseline
image. The test runner independently selects the library under test. Base images
contain no probe keys or NV data.

Validated Windows baseline: Windows 11 Pro 24H2 (26100) from the ISO with SHA-256
b56b911bf18a2ceaeb3904d87e7c770bdf92d3099599d61ac2497b91bf190b11, installed with
--windows-image-name "Windows 11 Pro" and a setup key file. Other editions or
versions can be selected but have not been validated. Keys are read from a file,
are never written to provenance, and do not activate Windows.

Example (run from the repository root on Linux):
  python3 integration-tests/build.py linux --iso /path/ubuntu-server.iso \\
    --sha256 <trusted-sha256> --firmware-code /usr/share/OVMF/OVMF_CODE_4M.fd \\
    --firmware-vars /usr/share/OVMF/OVMF_VARS_4M.fd \\
    --library /usr/lib/x86_64-linux-gnu/libtpms.so.0

Windows additionally requires --virtio-iso, --virtio-sha256 and --windows-image-name,
plus Secure Boot firmware with Microsoft-enrolled variables, e.g. OVMF_CODE_4M.ms.fd
and OVMF_VARS_4M.ms.fd on Ubuntu. Provisioning WinRM is disabled before the image is
published; tests use QEMU Guest Agent only.

SIGINT, SIGTERM and SIGHUP cancel the build once; further signals are ignored while
Packer, QEMU and swtpm are stopped and result.json is written. SIGKILL or host
failure cannot be cleaned up.''')
    parser.add_argument('guest', choices=('linux', 'windows'))
    parser.add_argument('--iso', required=True, help='local ISO or HTTPS URL')
    parser.add_argument('--sha256', required=True, type=checksum)
    parser.add_argument('--virtio-iso', help='local VirtIO driver ISO or HTTPS URL (Windows)')
    parser.add_argument('--virtio-sha256', type=checksum)
    parser.add_argument('--windows-image-name', help='install.wim image name, e.g. "Windows 11 Pro" (Windows)')
    parser.add_argument('--windows-product-key-file', type=Path,
                        help='optional file with a setup key for media that requires one')
    parser.add_argument('--firmware-code', required=True, type=Path)
    parser.add_argument('--firmware-vars', required=True, type=Path)
    parser.add_argument('--library', required=True, type=Path)
    parser.add_argument('--swtpm', type=Path, default=Path(shutil.which('swtpm') or '/usr/bin/swtpm'))
    parser.add_argument('--packer', default='packer')
    parser.add_argument('--name', help='unique image directory name (letters, numbers, dot, dash, underscore)')
    parser.add_argument('--cpus', type=int, default=2)
    parser.add_argument('--memory', type=int, help='MiB, default 4096 for Linux, 8192 for Windows')
    parser.add_argument('--timeout', type=int, default=7200, help='Packer build timeout in seconds (default: 7200)')
    args = parser.parse_args()
    if args.guest == 'windows' and not (args.virtio_iso and args.virtio_sha256 and args.windows_image_name):
        parser.error('Windows requires --virtio-iso, --virtio-sha256 and --windows-image-name')
    if args.guest == 'linux' and (args.windows_image_name or args.windows_product_key_file):
        parser.error('Windows options are not valid for a Linux build')
    if args.name and not re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9_.-]{0,40}', args.name):
        parser.error('--name must be 1-41 safe filename characters')
    if args.memory is None:
        args.memory = 4096 if args.guest == 'linux' else 8192
    if min(args.cpus, args.memory, args.timeout) <= 0:
        parser.error('--cpus, --memory and --timeout must be positive')
    return args


def build(args, work: Path, report: dict):
    binaries = preflight(args.swtpm)
    packer = shutil.which(args.packer)
    if not packer or not shutil.which('xorriso'):
        raise VMError('Install packer and xorriso on the Linux build host')
    packer = str(Path(packer).resolve())
    for firmware in (args.firmware_code, args.firmware_vars):
        if not firmware.is_file():
            raise VMError(f'Firmware file not found: {firmware}')
    image = IMG / 'images' / report['name']
    if image.exists():
        raise VMError(f'Image already exists: {image}')
    staging = work / 'bundle'
    staging.mkdir()
    firmware_code = snapshot_file(args.firmware_code, staging / 'firmware.fd')
    vars_template = snapshot_file(args.firmware_vars, work / 'initial-vars.fd')
    binaries.update(freeze_library(args.library, work))
    inputs = snapshot_inputs(work / 'inputs')
    environment = dict(os.environ)
    for key, subdir in [('PACKER_CACHE_DIR', 'packer'), ('PACKER_PLUGIN_PATH', 'plugins'), ('TMPDIR', 'tmp')]:
        path = IMG / 'cache' / subdir
        path.mkdir(parents=True, exist_ok=True)
        environment[key] = str(path)
    cpu_model = WINDOWS_CPU if args.guest == 'windows' else 'host'
    provenance = {
        'build_wrapper': WRAPPER_SOURCES, 'build_inputs': inputs,
        'installation_iso_sha256': args.sha256,
        'firmware_code': {'source_path': str(args.firmware_code.absolute()), 'snapshot': 'bundle/firmware.fd',
                          'bundle_path': 'firmware.fd', 'sha256': firmware_code},
        'initial_efivars_template': {'source_path': str(args.firmware_vars.absolute()), 'snapshot': 'initial-vars.fd',
                                     'sha256': vars_template},
        'library': {'source_path': binaries['library_source'], 'source_resolved': binaries['library_source_resolved'],
                    'private_copy': 'lib/libtpms.so.0', 'sha256': binaries['library_sha256']},
        'swtpm': {'path': binaries['swtpm'], 'sha256': binaries['swtpm_sha256']},
        'tools': {'packer': tool_version([packer, 'version']),
                  'qemu': tool_version([binaries['qemu-system-x86_64'], '--version']),
                  'xorriso': tool_version(['xorriso', '-version'])},
        'parameters': {'guest': args.guest, 'machine': 'q35', 'cpu': cpu_model, 'cpus': args.cpus,
                       'memory_mb': args.memory, 'packer_timeout_seconds': args.timeout},
        'host': {'node': platform.node(), 'kernel': platform.release()},
    }
    report['provenance'] = provenance
    tpm = Swtpm(args.swtpm, binaries['library'], staging / 'tpm-state', work / 'tpm.sock', work,
                binaries['library_sha256'])
    config = work / 'variables.pkrvars.json'
    report['_config'] = config
    iso = cache_iso(args.iso, args.sha256, IMG / 'cache' / 'iso')
    identity_path = work / 'guest-identity.json'
    password = 'TpM!' + secrets.token_hex(16)
    variables = {'iso_url': str(iso), 'iso_checksum': 'sha256:' + args.sha256,
                 'output_directory': str(work / 'output'),
                 'efi_firmware_code': str(staging / 'firmware.fd'),
                 'efi_firmware_vars': str(work / 'initial-vars.fd'),
                 'tpm_socket': str(tpm.socket), 'cpus': args.cpus, 'memory': args.memory,
                 'machine_type': 'q35', 'qemu_binary': binaries['qemu-system-x86_64'],
                 'identity_output': str(identity_path), 'password': password}
    if args.guest == 'linux':
        hashed = subprocess.run([binaries['openssl'], 'passwd', '-6', '-stdin'], input=password + '\n',
                                text=True, capture_output=True, check=True, timeout=10).stdout.strip()
        variables['password_hash'] = hashed
    else:
        variables['cpu_model'] = cpu_model
        provenance['parameters'].update(windows_image_name=args.windows_image_name,
                                        windows_setup_key_supplied=bool(args.windows_product_key_file))
        if args.windows_product_key_file:
            key = args.windows_product_key_file.read_text().strip().upper()
            if not re.fullmatch(r'[A-Z0-9]{5}(?:-[A-Z0-9]{5}){4}', key):
                raise VMError('Windows product key file must contain one 25-character key')
            variables['windows_product_key'] = key
        virtio = cache_iso(args.virtio_iso, args.virtio_sha256, IMG / 'cache' / 'iso')
        provenance['virtio_iso_sha256'] = args.virtio_sha256
        drivers = work / 'drivers'
        target = drivers / '$WinPEDriver$' / 'viostor'
        target.parent.mkdir(parents=True)
        run_logged(['xorriso', '-osirrox', 'on', '-indev', str(virtio), '-extract',
                    '/viostor/w11/amd64', str(target)], work, 'extract-drivers', environment, 120)
        normalize_driver_tree(drivers)
        variables.update(virtio_iso_url=str(virtio), virtio_iso_checksum='sha256:' + args.virtio_sha256,
                         virtio_driver_directory=str(drivers), windows_image_name=args.windows_image_name)
    atomic_json(config, variables)
    config.chmod(0o600)
    template = work / 'inputs' / 'packer' / (args.guest + '.pkr.hcl')
    run_logged([packer, 'init', str(template)], work, 'packer-init', environment, 300)
    run_logged([packer, 'validate', '-var-file=' + str(config), str(template)],
               work, 'packer-validate', environment, 60)
    tpm.start()
    print(f'Building {args.guest}; logs: {work}', flush=True)
    run_logged([packer, 'build', '-color=false', '-var-file=' + str(config), str(template)],
               work, 'packer-build', environment, args.timeout, BUILD_INTERRUPTION_GRACE)
    tpm.stop()
    config.unlink()
    report['swtpm_starts'] = tpm.starts
    for path, expected in ((staging / 'firmware.fd', firmware_code), (work / 'initial-vars.fd', vars_template)):
        if sha256(path) != expected:
            raise VMError(f'Firmware snapshot changed during the build: {path}')
    for file in ('disk.qcow2', 'efivars.fd'):
        source = work / 'output' / file
        if not source.is_file():
            raise VMError(f'Packer did not produce {file}')
        source.replace(staging / file)
    guest_os = load_identity(identity_path, args.guest)
    report['guest_os'] = guest_os
    manifest = {'schema_version': 2, 'build_id': report['build_id'], 'guest': args.guest,
                'disk': 'disk.qcow2', 'firmware': 'firmware.fd', 'variables': 'efivars.fd', 'tpm_state': 'tpm-state',
                'machine': 'q35', 'cpu': cpu_model, 'cpus': args.cpus, 'memory_mb': args.memory,
                'library_sha256': binaries['library_sha256'], 'iso_sha256': args.sha256,
                'created_at': utc_now(), 'firmware_sha256': firmware_code,
                'initial_efivars_template_sha256': vars_template,
                'final_efivars_sha256': sha256(staging / 'efivars.fd'), 'guest_os': guest_os, 'provenance': provenance}
    if args.guest == 'windows':
        manifest.update(windows_image_name=args.windows_image_name, virtio_sha256=args.virtio_sha256)
    atomic_json(staging / 'manifest.json', manifest)
    report['manifest_sha256'] = sha256(staging / 'manifest.json')
    report['checks_completed'] = True


def publish(work: Path, report: dict) -> None:
    image = IMG / 'images' / report['name']
    if image.exists():
        raise VMError(f'Image appeared during the build: {image}')
    image.parent.mkdir(parents=True, exist_ok=True)
    os.rename(work / 'bundle', image)
    report['published'] = str(image)

def main():
    install_signal_handlers()
    try:
        args = arguments()
        if platform.system() == 'Linux':
            become_subreaper()
        build_id = secrets.token_hex(4)
        work = IMG / 'builds' / build_id
        work.mkdir(parents=True)
        os.umask(0o077)
    except Cancelled as exc:
        return 128 + exc.signum
    report = {'schema_version': 2, 'status': 'RUNNING', 'build_id': build_id, 'guest': args.guest,
              'name': args.name or f'{args.guest}-{build_id}', 'started_at': utc_now(), 'work_directory': str(work),
              'published': None, 'checks_completed': False,
              'artifacts': {'inputs': 'inputs/', 'staging_bundle': 'bundle/', 'library_copy': 'lib/libtpms.so.0',
                            'initial_efivars_template': 'initial-vars.fd', 'guest_identity': 'guest-identity.json',
                            'logs': ['packer-init.stdout.log', 'packer-validate.stdout.log', 'packer-build.stdout.log',
                                     'packer-build.stderr.log', 'swtpm.stderr.log']}}
    try:
        build(args, work, report)
    except Cancelled as exc:
        report['error'] = str(exc)
    except Exception as exc:
        report['error'] = f'{type(exc).__name__}: {exc}'
    finally:
        begin_cleanup()
        report['cleanup'] = finish_cleanup(work, BUILD_INTERRUPTION_GRACE)
        config = report.pop('_config', None)
        try:
            if config is not None:
                config.unlink(missing_ok=True)
        except OSError as exc:
            report['cleanup']['errors'].append(f'could not remove Packer variables file: {exc}')
            report['cleanup']['status'] = 'ERROR'
        signum = cancellation_signal()
        if signum is not None:
            report['status'] = 'CANCELLED'
        elif report['checks_completed'] and report['cleanup']['status'] == 'OK' and 'error' not in report:
            try:
                publish(work, report)
                report['status'] = 'PASS'
            except Exception as exc:
                report['error'] = f'publish failed: {type(exc).__name__}: {exc}'
                report['status'] = 'FAIL'
        else:
            report['status'] = 'FAIL'
        if report['published'] is None and (work / 'bundle').exists():
            report['staging_bundle_unpublished'] = True
        report['finished_at'] = utc_now()
        report['exit_status'] = 0 if report['status'] == 'PASS' else (128 + signum if signum is not None else 1)
        atomic_json(work / 'result.json', report)
    if report['status'] == 'PASS':
        print(f'Image ready: {report["published"]}', flush=True)
        return 0
    print(f'Build {report["status"]}: {report.get("error") or report["cleanup"]["errors"]}; see {work}/result.json',
          file=sys.stderr)
    return report['exit_status']


if __name__ == '__main__':
    sys.exit(main())
