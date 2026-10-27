#!/usr/bin/env python3
"""CLI: render docs/findings/*.md from findings/raw/<run-id>/."""
import sys

from recon.report import main

if __name__ == "__main__":
    sys.exit(main())
