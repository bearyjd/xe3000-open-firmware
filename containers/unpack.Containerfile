# Firmware unpack image: pinned unblob plus the extraction tools it shells out to, and the engine code for the
# safe-extraction wrapper. Same python base digest as recon.Containerfile. It only ever runs on a network-less,
# hardened container (see scripts/unpack.sh): nothing from a firmware image is executed, it is only parsed/extracted.
FROM docker.io/library/python@sha256:6d2b0577e6d1632f077331de8e4780535f54839d163ded7abb4b7dd37b5d37ac

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash libmagic1 squashfs-tools e2fsprogs lz4 lzop zstd xz-utils bzip2 gzip p7zip-full unar cpio \
      device-tree-compiler mtd-utils erofs-utils lziprecover partclone android-sdk-libsparse-utils curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# sasquatch (squashfs extractor unblob needs): pinned release .deb, sha256-verified before install.
ARG SASQUATCH_URL=https://github.com/onekey-sec/sasquatch/releases/download/sasquatch-v4.5.1-6/sasquatch_1.0_amd64.deb
ARG SASQUATCH_SHA256=efbc92bd27594e01211e1b582f105a463a0017360a0746a93de3f283906ade95
RUN curl -fsSL -o /tmp/sasquatch.deb "$SASQUATCH_URL" \
 && echo "$SASQUATCH_SHA256  /tmp/sasquatch.deb" | sha256sum -c - \
 && apt-get update && apt-get install -y --no-install-recommends /tmp/sasquatch.deb \
 && rm -rf /tmp/sasquatch.deb /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    unblob==26.6.4 \
    pytest==9.1.1 \
    pytest-cov==7.1.0

WORKDIR /work
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/work/scripts \
    RECON_ROOT=/work
