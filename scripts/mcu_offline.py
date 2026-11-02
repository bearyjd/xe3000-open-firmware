#!/usr/bin/env python3
"""Build the MCU candidate against verified, real native OpenWrt libraries.

Offline only: acquire the exact inputs listed in source.json separately.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import tarfile
import difflib
import copy
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CANDIDATE = ROOT / "recipe/candidates/mcu"
DEFAULT_OUTPUT = ROOT / "build/mcu-offline-20261101"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def artifacts(prefix):
    return {str(p.relative_to(prefix)): ("link:" + os.readlink(p) if p.is_symlink() else digest(p))
            for p in sorted(prefix.rglob("*")) if p.is_file() or p.is_symlink()}


def verify(checkout, manifest):
    package = checkout / "feeds/packages/utils/gl-puli-mcu"
    actual = {str(p.relative_to(package)): digest(p)
              for p in sorted(package.rglob("*")) if p.is_file()}
    if actual != manifest["files"]:
        raise ValueError("Pinned MCU package file set/hash mismatch")
    for archive in manifest["archives"]:
        recipe_path = checkout / archive["recipe"]
        if digest(recipe_path) != archive["recipe_sha256"]:
            raise ValueError("Pinned dependency recipe hash mismatch")
        recipe = recipe_path.read_text()
        if archive["sha256"] not in recipe:
            raise ValueError("Archive hash absent from pinned dependency recipe")
        if digest(checkout / "dl" / archive["name"]) != archive["sha256"]:
            raise ValueError("Archive hash mismatch: " + archive["name"])
    return package


def build(checkout, output, cmake, patch_count):
    manifest = json.loads((CANDIDATE / "source.json").read_text())
    if output.parent != ROOT / "build" or not output.name.startswith("mcu-offline-"):
        raise ValueError("Output must be a dedicated build/mcu-offline-* directory")
    if any(p.is_symlink() for p in [output, *output.parents]):
        raise ValueError("Output aliases are forbidden")
    if checkout == output or checkout in output.parents or output in checkout.parents:
        raise ValueError("Output overlaps input checkout")
    owner = output / ".mcu-offline-owner"
    if output.exists() and (not owner.is_file() or owner.read_text() != "mcu-offline-v1\n"):
        raise ValueError("Existing output is not owned by the MCU fixture builder")
    if owner.exists() and (owner.is_symlink() or owner.stat().st_nlink != 1):
        raise ValueError("Invalid owner marker")
    for path in output.rglob("*") if output.exists() else ():
        if path.is_symlink():
            if not path.resolve().is_relative_to(output):
                raise ValueError("Output link escapes fixture")
        elif path.is_file() and path.stat().st_nlink != 1:
            raise ValueError("Output hardlinks forbidden")
    package = verify(checkout, manifest)
    output.mkdir(parents=True, exist_ok=True)
    owner.write_text("mcu-offline-v1\n")
    # A failed or interrupted rebuild must never advertise a usable fixture.
    (output / "fixture.json").unlink(missing_ok=True)
    if any(p.is_symlink() for name in ("package", "model-1", "model-2")
           for p in [output / name, *(output / name).rglob("*")]):
        raise ValueError("Unexpected source/build symlink")
    prefix = output / "prefix"
    env = {"PATH": "/usr/bin:/bin", "HOME": str(output), "LANG": "C",
           "GIT_CEILING_DIRECTORIES": str(output)}
    env.update(CC="/usr/bin/gcc", CXX="/usr/bin/g++",
               PKG_CONFIG_PATH=str(prefix / "lib/pkgconfig"),
               PKG_CONFIG_LIBDIR=str(prefix / "lib/pkgconfig"),
               LD_LIBRARY_PATH=str(prefix / "lib"))
    commands = []
    with (output / "build.log").open("a") as log:
        def run(args, cwd=None):
            args = list(map(str, args))
            commands.append(args)
            subprocess.run(args, env=env, stdout=log, stderr=subprocess.STDOUT, check=True, cwd=cwd)

        def configure(source, dest, flags=()):
            run([cmake, "-S", source, "-B", dest,
                 "-DCMAKE_C_COMPILER=/usr/bin/gcc", "-DCMAKE_CXX_COMPILER=/usr/bin/g++",
                 "-DCMAKE_INSTALL_PREFIX=" + str(prefix),
                 "-DCMAKE_POLICY_VERSION_MINIMUM=3.5",
                 "-DCMAKE_INSTALL_LIBDIR=lib", "-DCMAKE_PREFIX_PATH=" + str(prefix),
                 "-DCMAKE_INSTALL_RPATH=" + str(prefix / "lib"), *flags])
            run([cmake, "--build", dest, "--parallel", "2"])

        marker = output / "dependencies.json"
        if not marker.exists():
            for index, archive in enumerate(manifest["archives"]):
                source = output / ("dependency-" + str(index))
                if source.is_symlink():
                    raise ValueError("Dependency source aliases forbidden")
                if source.exists():
                    shutil.rmtree(source)
                source.mkdir()
                archive_path = checkout / "dl" / archive["name"]
                # Decode zstd through the system tool; inspect records before extraction.
                if archive_path.suffix == ".zst":
                    decoded = output / "archive.tar"
                    with decoded.open("wb") as stream:
                        subprocess.run(["/usr/bin/zstd", "-dc", str(archive_path)],
                                       stdout=stream, check=True, env=env)
                    archive_path = decoded
                with tarfile.open(archive_path) as tar:
                    members = tar.getmembers()
                    if len(members) > 20000 or sum(m.size for m in members) > 100_000_000:
                        raise ValueError("Archive exceeds extraction cap")
                    for entry in members:
                        member = copy.copy(entry)
                        parts = Path(member.name).parts
                        test_link = (index == 0 and member.issym() and len(parts) == 3 and
                                     parts[1] == "tests" and parts[2].endswith(".test") and
                                     member.linkname == "test_basic.test")
                        if (member.name.startswith("/") or ".." in parts or
                                not (member.isfile() or member.isdir() or test_link)):
                            raise ValueError("Unsafe archive member")
                        if len(parts) > 1:
                            if test_link:
                                dest = source / Path(*parts[1:])
                                dest.parent.mkdir(parents=True, exist_ok=True)
                                dest.write_bytes(tar.extractfile(member).read())
                            else:
                                member.name = str(Path(*parts[1:]))
                                tar.extract(member, source, filter="data")
                flags = ["-DBUILD_TESTING=OFF", "-DBUILD_LUA=OFF", "-DBUILD_EXAMPLES=OFF"]
                if index == 0:
                    flags += ["-DBUILD_SHARED_LIBS=ON"]
                if index == 2:
                    # ubusd makes its compiled default directory even when given -s.
                    # Keep this native-test-only change out of the MCU package patches.
                    f = source / "CMakeLists.txt"
                    original = f.read_text()
                    changed = original.replace('/var/run/ubus/ubus.sock', str(output / "ubus/ubus.sock"))
                    if original == changed:
                        raise ValueError("Expected ubus socket default not found")
                    f.write_text(changed)
                    acl = source / "ubusd_acl.c"
                    acl_original = acl.read_text()
                    acl_changed = acl_original.replace("if (st.st_uid || st.st_gid)",
                                                       "if (st.st_uid != getuid() || st.st_gid != getgid())")
                    if acl_original == acl_changed:
                        raise ValueError("Expected ACL owner check not found")
                    acl.write_text(acl_changed)
                    native_patch = ''.join(difflib.unified_diff(original.splitlines(True), changed.splitlines(True), fromfile="a/CMakeLists.txt", tofile="b/CMakeLists.txt"))
                    native_patch += ''.join(difflib.unified_diff(acl_original.splitlines(True), acl_changed.splitlines(True), fromfile="a/ubusd_acl.c", tofile="b/ubusd_acl.c"))
                    (output / "ubus-native-only.patch").write_text(native_patch)
                dest = output / ("dependency-build-" + str(index))
                configure(source, dest, flags)
                run([cmake, "--install", dest])
            (output / "dependency-commands.json").write_text(json.dumps(commands, indent=2) + "\n")
            marker.write_text(json.dumps({"archives": manifest["archives"], "artifacts": artifacts(prefix)}, indent=2) + "\n")
        elif json.loads(marker.read_text()) != {"archives": manifest["archives"], "artifacts": artifacts(prefix)}:
            raise ValueError("Dependency marker differs; use a fresh output directory")
        copied = output / "package"
        if copied.exists():
            shutil.rmtree(copied)
        shutil.copytree(package, copied)
        patches = sorted((CANDIDATE / "patches").glob("*.patch"))[:patch_count]
        for patch in patches:
            run(["/usr/bin/git", "apply", patch], cwd=copied)
        for model in (1, 2):
            dest = output / ("model-" + str(model))
            if dest.exists():
                shutil.rmtree(dest)
            configure(copied / "src", dest,
                      ["-DCMAKE_C_FLAGS=-DGL_TARGET=" + str(model) + " -I" + str(prefix / "include"),
                       "-DCMAKE_EXE_LINKER_FLAGS=-L" + str(prefix / "lib")])
        versions = {str(tool): subprocess.check_output([str(tool), "--version"], text=True, env=env).splitlines()[0]
                    for tool in [cmake, "/usr/bin/gcc", "make", "tar", "pkg-config"]}
        licenses = {}
        for directory in [copied, *(output / ("dependency-" + str(i)) for i in range(3))]:
            for f in sorted(directory.rglob("*")):
                if f.is_file() and f.name.upper() in ("COPYING", "COPYRIGHT", "LICENSE", "LICENSE.TXT"):
                    licenses[str(f.relative_to(output))] = digest(f)
        evidence = {"licenses": licenses, "inputs": manifest, "patches": {p.name: digest(p) for p in patches},
                    "native_dependency_patch_sha256": digest(output / "ubus-native-only.patch"),
                    "dependency_commands": json.loads((output / "dependency-commands.json").read_text()),
                    "commands_this_run": commands, "versions": versions,
                    "package_after_build": {str(p.relative_to(package)): digest(p)
                                            for p in sorted(package.rglob("*")) if p.is_file()}}
        verify(checkout, manifest)
        (output / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
        (output / "fixture.json").write_text(json.dumps({"patch_count": len(patches),
                                                       "source_manifest_sha256": digest(CANDIDATE / "source.json"),
                                                       "binaries": {str(p.relative_to(output)): digest(p) for p in [output / "model-1/gl-puli-mcu", output / "model-2/gl-puli-mcu"]},
                                                       "dependency_marker_sha256": digest(marker),
                                                       "patches": {p.name: digest(p) for p in patches}}))
    print("Native fixture ready:", output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--cmake", type=Path)
    parser.add_argument("--patch-count", type=int, default=99)
    args = parser.parse_args()
    checkout = args.checkout.resolve()
    cmake = (args.cmake or checkout / "staging_dir/host/bin/cmake").resolve()
    build(checkout, args.output.absolute(), cmake, args.patch_count)


if __name__ == "__main__":
    main()
