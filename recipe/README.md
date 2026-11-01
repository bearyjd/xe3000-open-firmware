# GL-XE3000 upstream source baseline

This recipe prepares OpenWrt `v25.12.6` at the full commit in `upstream.json`. Its five feed references match that commit's `feeds.conf.default` byte for byte. The seed selects only the MediaTek Filogic GL-XE3000 target. Package selection remains the upstream baseline; the recipe adds no experimental MHI patch, PCIe boot argument, or placeholder MCU support.

Preparation requires a standalone local Git repository containing the exact pinned commit; the offline helper never fetches it. A fresh project checkout has no `build/openwrt` source repository. If a suitable local source already exists, pass it with `--source`. Otherwise, these optional online bootstrap commands obtain upstream source in a **new** path; preserve any existing dirty `build/openwrt` experiments:

```sh
git clone --no-checkout https://git.openwrt.org/openwrt/openwrt.git build/upstream-source
git -C build/upstream-source checkout --detach 64900e756efa667774214f9c6b17c113222e01f7
```

If that commit is absent, explicitly fetch it with `git -C build/upstream-source fetch origin 64900e756efa667774214f9c6b17c113222e01f7` before checkout. Clone/fetch require network access; preparation and verification below are offline. From the project directory:

```sh
python3 scripts/prepare_firmware.py --source build/upstream-source --out build/firmware-v25.12.6
python3 scripts/prepare_firmware.py --source build/upstream-source --out build/firmware-v25.12.6 --verify
```

The default object source is the existing `build/openwrt` repository. `--source` can select another local repository. A dirty source checkout is allowed: preparation reads committed objects and creates a new local clone with independent object files, checks out the exact commit detached, and writes the three-line seed to `checkout/.config`. It never copies dirty tracked files or untracked experiments, modifies the original repository, fetches, invokes feeds, or runs make. Existing destinations and path aliases are refused. Only standalone Git repositories are accepted; worktree/common-directory indirection, alternate object stores, and per-worktree configuration are refused in both source and prepared checkout before any Git command. Source Git configuration is restricted to ordinary repository metadata; includes, partial clones, promisors, and external helpers are refused before any object lookup. Object integrity is checked with strict Git fsck, and hooks and lazy fetching are disabled.

`manifest.json` sits outside the checkout and records the upstream commit, tag label, feed pins, commit-derived `source_date_epoch`, and hashes of the recipe and seed. Its state is `prepared-unconfigured`, with `production_ready=false` and `firmware_build_complete=false`. Verification checks this metadata, object integrity, the exact source commit/feed file/seed, detached HEAD, and absence of unexpected generated files. It compares every tracked regular file and symlink directly against its pinned Git blob hash and expected executable mode, independently of index flags or cached file timestamps. This establishes a source baseline; it does not establish a firmware image, runtime support, or a reproducible build.

## Subsequent build stages

The upstream [README](https://git.openwrt.org/openwrt/openwrt.git/tree/README.md?id=64900e756efa667774214f9c6b17c113222e01f7) describes feeds update/install, configuration, and make. Before those stages, record the build host or container image digest, host package versions and dependencies, compiler environment, full source/feed pins, and `SOURCE_DATE_EPOCH` from the preparation manifest.

A later build stage must explicitly obtain each feed at its recorded full commit, run `./scripts/feeds update -a` and `./scripts/feeds install -a`, and verify each resulting feed HEAD against the recipe before proceeding. Record the resolved configuration after `make defconfig`, its hash, the complete build command and environment, build logs, and the final artifact hashes. Configuration expansion and feed installation change the prepared tree; keep their evidence in a separate build-stage record rather than changing the source-preparation manifest to claim a completed build.

Successful compilation requires inspection of the resulting device profile, image metadata, package inventory, and SHA-256 hashes. Reproducibility requires a separate clean build under the recorded environment and comparison of output hashes. Hardware behavior and production readiness require additional evidence beyond this source preparation.

## Recorded configure and compile

The [public r3 verification summary](../docs/evidence/firmware-r3.json) records successful compilation and image inspection with independent local approval. Reproducibility and hardware acceptance remain open.

`scripts/build_firmware.py` implements these stages in a **new** destination. It verifies the original baseline, prepares an independent object copy, and preserves the baseline manifest. Configuration records an allowlisted environment, commit-derived `SOURCE_DATE_EPOCH`, OS/kernel, tool versions, package inventory, commands and logs. All five feeds must have the pinned HEAD, origin, detached state and unchanged committed bytes before installation and after each later stage. The one upstream-generated `feeds/base -> ../package` link is accepted exactly. The resolved configuration must select only GL-XE3000; its hash and a complete snapshot of configured source/generated inputs are recorded before compilation.

Both `make defconfig` and compilation receive `SOURCE_DATE_EPOCH=<manifest value>` as an explicit command-line assignment, also recorded in their command arguments. Exporting the environment variable alone is insufficient: upstream `include/toplevel.mk` assigns it from `scripts/get_source_date_epoch.sh`, which prioritizes the release's `version.date` over the commit timestamp. Command-line precedence preserves the manifest epoch without changing source or configuration.

Build the dedicated environment (apt package versions are recorded, but apt repositories are not snapshot-pinned):

```sh
podman build -f containers/firmware.Containerfile -t localhost/xe3000-firmware containers
image_id=$(podman image inspect --format '{{.Id}}' localhost/xe3000-firmware)
mkdir -p build/firmware-stages
```

Use the same immutable image ID for both commands. This example mounts only build code, the recipe, the read-only baseline, and a writable directory for new stages:

```sh
podman run --rm --hostname xe3000-firmware-builder --userns=keep-id --read-only --tmpfs /tmp \
  --cap-drop=all --security-opt=no-new-privileges --pids-limit=1024 \
  -v "$PWD/scripts:/work/scripts:ro" -v "$PWD/recipe:/work/recipe:ro" \
  -v "$PWD/build/firmware-v25.12.6:/work/build/firmware-v25.12.6:ro" \
  -v "$PWD/build/firmware-stages:/work/build/stages:rw" \
  "$image_id" python3 scripts/build_firmware.py --root /work \
  --baseline /work/build/firmware-v25.12.6 --out /work/build/stages/run-1 \
  --configure --environment-id "$image_id"

podman run --rm --hostname xe3000-firmware-builder --userns=keep-id --read-only --tmpfs /tmp \
  --cap-drop=all --security-opt=no-new-privileges --pids-limit=1024 \
  -v "$PWD/scripts:/work/scripts:ro" -v "$PWD/recipe:/work/recipe:ro" \
  -v "$PWD/build/firmware-v25.12.6:/work/build/firmware-v25.12.6:ro" \
  -v "$PWD/build/firmware-stages:/work/build/stages:rw" \
  "$image_id" python3 scripts/build_firmware.py --root /work \
  --baseline /work/build/firmware-v25.12.6 --out /work/build/stages/run-1 \
  --compile --jobs 2 --environment-id "$image_id"
```

The CLI supports Debian (`dpkg-query`) and RPM hosts; the container above supplies the reviewed dependencies. Compilation bounds jobs to 1–64 and refuses changed environment identity, tools/packages, recipe, config, source, feeds or configured inputs, including added makefiles. Use a recorded read-only copy of the build scripts when running long stages. HTTPS-only Git access and disabled credential helpers prevent ambient Git configuration from influencing downloads.

`build-record.json`, `configured-inputs.json`, `logs/`, and extracted `image-metadata.json` remain outside the checkout. A zero make exit alone does not complete the build: inspection checks image hashes/sizes, GL-XE3000 profile and embedded sysupgrade identity, tar members/board, package inventory, and config/feed/version buildinfo. Only then does status become `compiled-inspected` with `firmware_build_complete=true`; `production_ready` and `reproducible` remain false. Partial outputs or any failure leave a terminal `failed` record; retain it for diagnosis and start with a new destination. Failed stages cannot resume or overwrite their logs. No stage contacts a router or flashes any image.
