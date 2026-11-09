# Decompilation image: pinned radare2 (release .deb, sha256-verified, same digest as GitHub's published asset) plus
# gcc for the synthetic-ELF test. Same python base digest as the other images. It only ever runs on a network-less,
# hardened container (see scripts/decompile.sh): firmware binaries are parsed and disassembled, never executed.
FROM docker.io/library/python@sha256:6d2b0577e6d1632f077331de8e4780535f54839d163ded7abb4b7dd37b5d37ac

RUN apt-get update \
 && apt-get install -y --no-install-recommends bash gcc libc6-dev curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

ARG R2_URL=https://github.com/radareorg/radare2/releases/download/6.2.4/radare2_6.2.4_amd64.deb
ARG R2_SHA256=7019eedc0e0e87d1f53d6b8f5fc62b898567679c5efdce7fbfc557c9e7655e90
RUN curl -fsSL -o /tmp/r2.deb "$R2_URL" \
 && echo "$R2_SHA256  /tmp/r2.deb" | sha256sum -c - \
 && apt-get update && apt-get install -y --no-install-recommends /tmp/r2.deb \
 && rm -rf /tmp/r2.deb /var/lib/apt/lists/*

RUN pip install --no-cache-dir pytest==9.1.1

WORKDIR /work
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/work/scripts \
    RECON_ROOT=/work
