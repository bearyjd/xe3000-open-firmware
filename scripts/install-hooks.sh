#!/usr/bin/env bash
set -eu
cd "$(git rev-parse --show-toplevel)"
chmod +x hooks/pre-commit
git config core.hooksPath hooks
echo "hooks installed (core.hooksPath=hooks)"
