#!/usr/bin/env python3
"""External TPM validation launcher; see `run.py --help` and README.md."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from validation.cli import main  # noqa: E402

if __name__ == '__main__':
    sys.exit(main())
