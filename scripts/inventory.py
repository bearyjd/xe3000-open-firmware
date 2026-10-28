#!/usr/bin/env python3
"""CLI: build Phase 2 ground-truth inventories under findings/raw/ground-truth (counts only on stdout)."""
import sys

from recon.inventory import main

if __name__ == "__main__":
    sys.exit(main())
