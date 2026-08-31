#!/usr/bin/env python3
"""Compatibility launcher for the packaged capability-only worker endpoint."""

from bpe.worker_cli import main

if __name__ == "__main__":
    raise SystemExit(main())
