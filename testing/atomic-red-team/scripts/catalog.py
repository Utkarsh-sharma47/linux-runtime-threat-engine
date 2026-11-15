#!/usr/bin/env python3
"""Read-only catalog of Linux Atomic Red Team tests with a conservative risk triage.

The implementation lives in `runtime_engine.atomic.catalog` (also used by
`runtime-engine atomic`); this script keeps the lab's existing command line.

Usage:
  catalog.py build [--atomics DIR] [--markdown FILE] [--json FILE]
  catalog.py show --guid GUID [--json]
  catalog.py list [--risk A|B|C] [--technique T1059.004]
"""

from runtime_engine.atomic.catalog import *  # noqa: F403
from runtime_engine.atomic.catalog import main

if __name__ == "__main__":
    raise SystemExit(main())
