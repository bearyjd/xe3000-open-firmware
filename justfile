# Recon engine tasks. All Python runs in a container; only stdlib-only wrappers run on the host.
# On this host: PODMAN="distrobox-host-exec podman" just <recipe>
set positional-arguments

PODMAN := env_var_or_default('PODMAN', 'podman')
ROOT   := justfile_directory()
IMAGE  := 'localhost/xe3000-open-firmware-recon:0.1'
UNPACK_IMAGE := 'localhost/xe3000-open-firmware-unpack:0.1'

# Applied to every container run: no capabilities, no privilege escalation, bounded pids, read-only rootfs.
hardening := "--cap-drop=ALL --security-opt no-new-privileges --pids-limit 256 --read-only --tmpfs /tmp"

default:
    @just --list

build:
    {{PODMAN}} build -t {{IMAGE}} -f "{{ROOT}}/containers/recon.Containerfile" "{{ROOT}}/containers"

# Offline test suite (FakeClient only; no API calls, no .env, no network).
test: build
    {{PODMAN}} run --rm {{hardening}} --network=none -e COVERAGE_FILE=/tmp/.coverage \
      -v "{{ROOT}}/scripts:/work/scripts:ro,z" -v "{{ROOT}}/tests:/work/tests:ro,z" -v "{{ROOT}}/hooks:/work/hooks:ro,z" \
      -v "{{ROOT}}/containers:/work/containers:ro,z" -v "{{ROOT}}/justfile:/work/justfile:ro,z" \
      -v "{{ROOT}}/.github:/work/.github:ro,z" -v "{{ROOT}}/.gitleaks-baseline.json:/work/.gitleaks-baseline.json:ro,z" \
      -v "{{ROOT}}/docs:/work/docs:ro,z" -v "{{ROOT}}/README.md:/work/README.md:ro,z" \
      {{IMAGE}} pytest -c tests/pytest.ini -p no:cacheprovider --cov=recon --cov-report=term-missing

# Host wrapper (stdlib only): gitleaks pre-flight over harvest/redacted and unpacked; writes the stamp.
preflight:
    mkdir -p "{{ROOT}}/harvest/redacted" "{{ROOT}}/unpacked" "{{ROOT}}/cache"
    PODMAN="{{PODMAN}}" python3 "{{ROOT}}/scripts/preflight.py" --root "{{ROOT}}"

# Redact a raw text tree into harvest/redacted. Raw is mounted read-only into THIS container only, never analyze's.
redact SRC: build
    ROOT={{quote(ROOT)}} PODMAN={{quote(PODMAN)}} IMAGE={{quote(IMAGE)}} HARDENING={{quote(hardening)}} \
      bash "{{ROOT}}/scripts/redact-container.sh" "$1" harvest/redacted redaction-report.json

# Redact unblob output into unpacked/ (the engine also re-redacts unpacked text in memory as defence in depth).
redact-unpacked SRC: build
    ROOT={{quote(ROOT)}} PODMAN={{quote(PODMAN)}} IMAGE={{quote(IMAGE)}} HARDENING={{quote(hardening)}} \
      bash "{{ROOT}}/scripts/redact-container.sh" "$1" unpacked unpacked-redaction-report.json

# Create the (empty, mode 0600) known-secret canary file and print how to use it. Never overwrites.
canary-init:
    python3 "{{ROOT}}/scripts/recon/canary.py" --init

# Estimate only: counts tokens (free API call), prints worst-case cost, sends nothing.
dry-run RUN_ID *ARGS: build
    ROOT={{quote(ROOT)}} PODMAN={{quote(PODMAN)}} IMAGE={{quote(IMAGE)}} HARDENING={{quote(hardening)}} \
      bash "{{ROOT}}/scripts/analyze-container.sh" "$@" --dry-run

analyze RUN_ID *ARGS: build
    ROOT={{quote(ROOT)}} PODMAN={{quote(PODMAN)}} IMAGE={{quote(IMAGE)}} HARDENING={{quote(hardening)}} \
      bash "{{ROOT}}/scripts/analyze-container.sh" "$@"

# Firmware unpack image (pinned unblob + extractors; separate from the recon image).
build-unpack:
    {{PODMAN}} build -t {{UNPACK_IMAGE}} -f "{{ROOT}}/containers/unpack.Containerfile" "{{ROOT}}/containers"

# Unpack a stock image or rootfs tar: just unpack path/to/image NAME. Staging in build/unpack/NAME, redacted output in unpacked/NAME.
unpack INPUT NAME: build-unpack
    ROOT={{quote(ROOT)}} PODMAN={{quote(PODMAN)}} UNPACK_IMAGE={{quote(UNPACK_IMAGE)}} HARDENING={{quote(hardening)}} \
      bash "{{ROOT}}/scripts/unpack.sh" "$1" "$2"

# Real-tool end to end test (synthetic squashfs + FIT/DTB through unblob); the recon image lacks these tools, so `test` skips it.
test-unpack: build-unpack
    {{PODMAN}} run --rm {{hardening}} --network=none \
      -v "{{ROOT}}/scripts:/work/scripts:ro,z" -v "{{ROOT}}/tests:/work/tests:ro,z" \
      {{UNPACK_IMAGE}} pytest -c tests/pytest.ini -p no:cacheprovider --noconftest tests/test_unpack_e2e.py
