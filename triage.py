#!/usr/bin/env python3
"""CLI entry point: `python triage.py <command>` (or `triage <command>` after `pip install -e .`)."""
import sys

from jamtriage.cli import main

if __name__ == "__main__":
    sys.exit(main())
