"""Build the selected libtpms backend and record its identity."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import tarfile

from .environment import StepFailed

BACKENDS = ('rust', 'reference', 'selected')


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as source:
        for block in iter(lambda: source.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def sha256_tree(paths, base):
    """Content hash of the files that were actually compiled."""
    digest = hashlib.sha256()
    for path in sorted(p for root in paths for p in
                       ([root] if root.is_file() else root.rglob('*')) if p.is_file()):
        digest.update(str(path.relative_to(base)).encode() + b'\0')
        digest.update(path.read_bytes() + b'\0')
    return digest.hexdigest()


def git(phase, repository, *args):
    # The checkout is mounted read-only and owned by the host user.
    return phase.capture(['git', '-c', f'safe.directory={repository}', '-C', str(repository),
                          *args], cwd=repository).strip()


def build(phase, backend, *, repo, cache, selected=None):
    """Return {'path', 'sha256', 'identity', ...} for the library under test."""
    repo, cache = Path(repo), Path(cache)
    if backend == 'rust':
        source = cache / 'builds' / 'rust-source'
        source.mkdir(parents=True, exist_ok=True)
        shutil.rmtree(source / 'src', ignore_errors=True)
        shutil.copytree(repo / 'src', source / 'src')
        shutil.copy2(repo / 'Cargo.toml', source / 'Cargo.toml')
        if (repo / 'Cargo.lock').exists():
            shutil.copy2(repo / 'Cargo.lock', source / 'Cargo.lock')
        else:
            (source / 'Cargo.lock').unlink(missing_ok=True)
        phase.run(['cargo', 'build', '--release', '--manifest-path',
                   str(source / 'Cargo.toml')], cwd=source)
        target = Path(phase.env.get('CARGO_TARGET_DIR', source / 'target'))
        library = target / 'release' / 'libtpms.so'
        identity = {
            'implementation': 'rust',
            'revision': git(phase, repo, 'rev-parse', 'HEAD'),
            'dirty': bool(git(phase, repo, 'status', '--porcelain', '--',
                              'src', 'Cargo.toml', 'Cargo.lock')),
            'source_sha256': sha256_tree([source / 'src', source / 'Cargo.toml']
                                         + ([source / 'Cargo.lock']
                                            if (source / 'Cargo.lock').exists() else []),
                                         source),
        }
    elif backend == 'reference':
        checkout = repo / 'libtpms'
        source = cache / 'builds' / 'reference-source'
        build_dir = cache / 'builds' / 'reference'
        archive = cache / 'builds' / 'reference-source.tar'
        shutil.rmtree(source, ignore_errors=True)
        source.mkdir(parents=True)
        build_dir.mkdir(parents=True, exist_ok=True)
        phase.run(['git', '-c', f'safe.directory={checkout}', '-C', str(checkout),
                   'archive', '--format=tar', '-o', str(archive), 'HEAD'], cwd=checkout)
        with tarfile.open(archive) as bundle:
            bundle.extractall(source)
        archive.unlink()
        env = dict(phase.env, NOCONFIGURE='1')
        phase.run(['./autogen.sh'], cwd=source, env=env)
        phase.run([str(source / 'configure'), '--with-tpm2', '--with-openssl',
                   '--enable-shared', '--disable-static'], cwd=build_dir)
        phase.run(['make', f'-j{phase.jobs}'], cwd=build_dir)
        library = build_dir / 'src' / '.libs' / 'libtpms.so'
        identity = {
            'implementation': 'reference C libtpms',
            'revision': git(phase, checkout, 'rev-parse', 'HEAD'),
            # git archive builds HEAD; uncommitted changes are not compiled.
            'dirty_worktree_not_built': bool(git(phase, checkout, 'status', '--porcelain')),
        }
    elif backend == 'selected':
        library = Path(selected or '/selected/libtpms.so')
        identity = {'implementation': 'explicitly selected shared library'}
    else:
        raise StepFailed(f'unknown backend {backend!r}')
    if not library.is_file():
        raise StepFailed(f'library was not produced: {library}')
    return {'path': str(library), 'sha256': sha256_file(library), 'identity': identity,
            'size': os.path.getsize(library)}
