"""Adapter contract shared by the five upstream suites.

An adapter prepares dependencies (backend independent, run once), executes the
native execution unit(s) against one library, and collects evidence into a
suite record. The runner owns phases, deadlines, persistence and cleanup.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class RunContext:
    phase: object            # environment.Phase for this suite's run phase
    suite_dir: Path          # <run>/<backend>/<suite>
    run_root: Path           # <run>, the base of every persisted relative path
    library: str             # absolute path of the library under test
    backend: str
    filter: str = ''
    microsoft_test_timeout: int = 120
    jobs: int = 2
    started: float = 0.0     # wall clock at run start, for stale-evidence checks
    execution: dict = None   # main native execution, once it exists
    termination: str = None  # completed | timeout | interrupted | setup-failed
    error: str = ''          # setup failure before/around the main execution
    notes: dict = field(default_factory=dict)

    def relative(self, path):
        return str(Path(path).relative_to(self.run_root))


class Adapter:
    name = ''
    source = ''              # pinned upstream checkout under test

    def prepare(self, phase):
        raise NotImplementedError

    def run(self, ctx):
        """Start the native execution unit(s); return the main execution evidence."""
        raise NotImplementedError

    def collect(self, suite, ctx):
        """Fill suite tests/issues/selection from whatever evidence exists."""
        raise NotImplementedError
