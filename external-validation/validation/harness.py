"""Content identity of the harness snapshot used by a run."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

IGNORED_DIRECTORIES = {'__pycache__', '.pytest_cache'}


def files(root):
    root = Path(root)
    for directory, subdirectories, names in os.walk(root):
        subdirectories[:] = sorted(d for d in subdirectories if d not in IGNORED_DIRECTORIES)
        for name in sorted(names):
            if not name.endswith('.pyc'):
                yield Path(directory, name)


def digest(root):
    """SHA-256 over relative paths, modes and contents (symlinks by target)."""
    root = Path(root)
    hasher = hashlib.sha256()
    for path in sorted(files(root)):
        relative = path.relative_to(root).as_posix()
        hasher.update(relative.encode() + b'\0')
        if path.is_symlink():
            hasher.update(b'L' + os.readlink(path).encode() + b'\0')
            continue
        hasher.update(b'X' if path.stat().st_mode & 0o111 else b'F')
        hasher.update(path.read_bytes() + b'\0')
    return hasher.hexdigest()
