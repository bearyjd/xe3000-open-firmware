#!/usr/bin/env python3
"""CLI: redact a raw text tree into harvest/redacted (stdlib only)."""
import sys

from recon.redact import main

if __name__ == "__main__":
    sys.exit(main())
