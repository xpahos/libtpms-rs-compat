#!/usr/bin/env python3
"""TPM2 NV and persistent signing-key probe, run as root inside a disposable guest.

Usage: probe setup <64 hex challenge> [<64 hex NV value>]
       probe verify|create-secondary|verify-secondary <64 hex challenge>
       probe update-nv <64 hex NV value>   or   probe remove-secondary   or   probe identity
Output is one JSON object. Signing actions return the persistent key's public part as
base64 DER X.509 SubjectPublicKeyInfo and a raw RSASSA-PKCS1-v1_5 SHA-256 signature
over the challenge bytes, so the host can verify both independently. Actions that read
the NV index report the raw readback as nv_value for the host to compare.
Only setup and create-secondary create TPM objects; nothing else creates or repairs state.
remove-secondary evicts the secondary key and exists for negative checks only.
"""

import base64
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile


STATE = Path('/var/lib/libtpms-integration')
NV = '0x1500020'
NV_SIZE = 32
KEYS = {'primary': ('0x81010020', 'public.der'), 'secondary': ('0x81010021', 'secondary.der')}


def command(*args):
    result = subprocess.run(args, capture_output=True, timeout=60, check=False,
                            env={**os.environ, 'TPM2TOOLS_TCTI': 'device:/dev/tpmrm0'})
    if result.returncode:
        raise RuntimeError(f'{args[0]} failed: {result.stderr.decode(errors="replace")}')
    return result.stdout


def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def identity():
    release = {}
    for line in Path('/etc/os-release').read_text().splitlines():
        key, separator, value = line.partition('=')
        if separator:
            release[key] = value.strip().strip('"')
    media = Path('/var/log/installer/media-info')
    return {'status': 'PASS', 'action': 'identity', 'boot_id': boot_id(),
            'os': {'family': 'linux', 'id': release.get('ID'), 'version_id': release.get('VERSION_ID'),
                   'version': release.get('VERSION'), 'pretty_name': release.get('PRETTY_NAME'),
                   'kernel_release': os.uname().release, 'kernel_version': os.uname().version,
                   'installer_media': media.read_text().strip() if media.exists() else None}}


def hex_argument(value, name):
    if not isinstance(value, str) or len(value) != 2 * NV_SIZE:
        raise ValueError(f'expected {name} as {NV_SIZE} bytes of hex')
    return bytes.fromhex(value)


def persistent_handles():
    output = command('tpm2_getcap', 'handles-persistent').decode()
    return {line.strip().lstrip('-').strip().lower() for line in output.splitlines() if line.strip()}


def read_nv(tmp):
    command('tpm2_nvread', NV, '-C', 'o', '-s', str(NV_SIZE), '-o', str(tmp / 'nv'))
    return (tmp / 'nv').read_bytes()


def create_key(handle):
    with tempfile.TemporaryDirectory() as directory:
        parent, public, private, key = [str(Path(directory) / n) for n in ('parent', 'public', 'private', 'key')]
        command('tpm2_createprimary', '-C', 'o', '-G', 'rsa', '-c', parent)
        command('tpm2_create', '-C', parent, '-G', 'rsa2048:rsassa-sha256',
                '-a', 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign',
                '-u', public, '-r', private)
        command('tpm2_load', '-C', parent, '-u', public, '-r', private, '-c', key)
        command('tpm2_evictcontrol', '-C', 'o', '-c', key, handle)


def sign(role, action, challenge, check_nv):
    data = bytes.fromhex(challenge)
    handle, pinned = KEYS[role]
    result = {'status': 'PASS', 'action': action, 'challenge': challenge, 'boot_id': boot_id(), 'key_role': role}
    with tempfile.TemporaryDirectory() as directory:
        tmp = Path(directory)
        if check_nv:
            nv = read_nv(tmp)
            if nv != (STATE / 'sentinel').read_bytes():
                raise RuntimeError('TPM NV sentinel changed')
            result.update(nv_index=NV, nv_verified=True, nv_value=nv.hex())
        command('tpm2_readpublic', '-c', handle, '-f', 'der', '-o', str(tmp / 'public.der'))
        public = (STATE / pinned).read_bytes()
        if (tmp / 'public.der').read_bytes() != public:
            raise RuntimeError(f'TPM {role} persistent key changed')
        (tmp / 'challenge').write_bytes(data)
        command('tpm2_sign', '-c', handle, '-g', 'sha256', '-s', 'rsassa', '-f', 'plain',
                '-o', str(tmp / 'signature'), str(tmp / 'challenge'))
        signature = (tmp / 'signature').read_bytes()
    result.update(key_handle=handle, public_key_encoding='x509-spki-der-base64',
                  public_key=base64.b64encode(public).decode(),
                  signature_scheme='rsassa-pkcs1-v1_5-sha256', signature=base64.b64encode(signature).decode())
    return result


def update_nv(value):
    if not STATE.is_dir():
        raise RuntimeError('Probe state is missing; refusing to define a new NV index')
    with tempfile.TemporaryDirectory() as directory:
        tmp = Path(directory)
        previous = read_nv(tmp)
        (tmp / 'value').write_bytes(value)
        command('tpm2_nvwrite', NV, '-C', 'o', '-i', str(tmp / 'value'))
        readback = read_nv(tmp)
    if readback != value:
        raise RuntimeError('TPM NV readback does not match the written value')
    (STATE / 'sentinel').write_bytes(value)
    return {'status': 'PASS', 'action': 'update-nv', 'boot_id': boot_id(), 'nv_index': NV,
            'nv_previous': previous.hex(), 'nv_value': readback.hex()}


def remove_secondary():
    handle = KEYS['secondary'][0]
    if handle not in persistent_handles():
        raise RuntimeError(f'Secondary key {handle} is not persistent')
    command('tpm2_evictcontrol', '-C', 'o', '-c', handle)
    return {'status': 'PASS', 'action': 'remove-secondary', 'boot_id': boot_id(), 'key_handle': handle}


def probe(action, *arguments):
    if action == 'update-nv' and len(arguments) == 1:
        return update_nv(hex_argument(arguments[0], 'the NV value'))
    if action == 'remove-secondary' and not arguments:
        return remove_secondary()
    signing = ('setup', 'verify', 'create-secondary', 'verify-secondary')
    if action not in signing or not 1 <= len(arguments) <= (2 if action == 'setup' else 1):
        raise ValueError('expected setup|verify|create-secondary|verify-secondary and a 32-byte hex challenge')
    challenge = arguments[0]
    hex_argument(challenge, 'the challenge')
    if action == 'setup':
        initial = hex_argument(arguments[1], 'the NV value') if len(arguments) == 2 else secrets.token_bytes(NV_SIZE)
        STATE.mkdir(mode=0o700)  # Refuse a base image containing an earlier test's state.
        (STATE / 'sentinel').write_bytes(initial)
        command('tpm2_nvdefine', NV, '-C', 'o', '-s', str(NV_SIZE), '-a', 'ownerread|ownerwrite')
        command('tpm2_nvwrite', NV, '-C', 'o', '-i', str(STATE / 'sentinel'))
        create_key(KEYS['primary'][0])
        command('tpm2_readpublic', '-c', KEYS['primary'][0], '-f', 'der', '-o', str(STATE / KEYS['primary'][1]))
    elif action == 'create-secondary':
        handle, pinned = KEYS['secondary']
        if not (STATE / KEYS['primary'][1]).is_file():
            raise RuntimeError('Primary key state is missing; run setup first')
        if (STATE / pinned).exists() or handle in persistent_handles():
            raise RuntimeError(f'Secondary key {handle} already exists')
        create_key(handle)
        command('tpm2_readpublic', '-c', handle, '-f', 'der', '-o', str(STATE / pinned))
    role = 'secondary' if action.endswith('-secondary') else 'primary'
    return sign(role, action, challenge, check_nv=role == 'primary')


if __name__ == '__main__':
    try:
        arguments = sys.argv[1:]
        print(json.dumps(identity() if arguments == ['identity'] else probe(*arguments)))
    except Exception as error:
        print(json.dumps({'status': 'FAIL', 'error': f'{type(error).__name__}: {error}'}))
        sys.exit(1)
