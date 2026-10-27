#!/usr/bin/env python3
"""CLI (inside the unpack container): unpack a stock firmware image or rootfs tar into a redacted tree."""
import sys

from recon.unpack import main

if __name__ == "__main__":
    sys.exit(main())
