# Base: python:3.12-slim pinned by digest. Analysis + test image. Code, tests and data are mounted at run time (see justfile);
# the repo root is never mounted and never part of the build context (context = containers/).
# The gitleaks binary is copied from the pinned official image (same digest as containers/gitleaks.image)
# so the independence tests can run it without nested podman.
FROM docker.io/zricethezav/gitleaks@sha256:b109bc5f8f76a38196a3e413704fc5b9e3c32360bce4e4b603bd6f45b3721dbb AS gitleaks

FROM docker.io/library/python@sha256:6d2b0577e6d1632f077331de8e4780535f54839d163ded7abb4b7dd37b5d37ac

RUN apt-get update \
 && apt-get install -y --no-install-recommends git bash \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    anthropic==2.3.0 \
    python-dotenv==1.2.4 \
    jsonschema==4.26.0 \
    pytest==9.1.1 \
    pytest-cov==7.1.0

COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks

# Rootless podman maps container root to the invoking host user, so bind-mounted dirs stay writable.
WORKDIR /work
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/work/scripts \
    RECON_ROOT=/work \
    RECON_GITLEAKS_BIN=/usr/local/bin/gitleaks
