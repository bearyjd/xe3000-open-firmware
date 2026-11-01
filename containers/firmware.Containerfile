FROM docker.io/library/debian@sha256:13cb01d584d2c23f475c088c168a48f9a08f033a10460572fbfd10912ec5ba7c
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential clang flex bison g++ gawk gcc-multilib g++-multilib gettext git \
    libncurses-dev libssl-dev python3 python3-setuptools rsync swig unzip zlib1g-dev \
    file wget curl ca-certificates patch xz-utils zstd time \
    && rm -r /var/lib/apt/lists/* \
    && useradd --uid 1000 --create-home builder
USER builder
WORKDIR /work
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC
