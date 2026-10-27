#!/usr/bin/env python3
"""Host wrapper: gitleaks pre-flight (stdlib only). Runs gitleaks via $PODMAN with the pinned image."""
import sys

from recon.preflight import main

if __name__ == "__main__":
    sys.exit(main())
