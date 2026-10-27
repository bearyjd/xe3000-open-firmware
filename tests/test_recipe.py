"""Static and sandboxed tests for the build recipe (recipe/). Nothing here touches the network, a router or a modem."""
import os
import re
import shutil
import subprocess
import textwrap

import pytest

from conftest import REPO

RECIPE = REPO / "recipe"
PREPARE = RECIPE / "prepare.sh"
SIM = RECIPE / "files" / "usr" / "sbin" / "xe3000-sim-select"
UCI_DEFAULTS = RECIPE / "files" / "etc" / "uci-defaults" / "90-xe3000-defaults"
KERNEL_PATCHES = sorted((RECIPE / "patches" / "kernel").glob("*.patch"))
TREE_PATCHES = sorted((RECIPE / "patches" / "tree").glob("*.patch"))
RUNBOOK = REPO / "docs" / "runbooks" / "flash-and-rollback.md"
LIB = RECIPE / "lib.sh"
SHELL_SCRIPTS = [PREPARE, SIM, UCI_DEFAULTS, RECIPE / "container-build.sh", LIB]
BOOTARGS = 'bootargs = "console=ttyS0,115200n8 root=PARTLABEL=rootfs rootwait";'
DTSI = "target/linux/mediatek/dts/mt7981a-glinet-gl-x3000-xe3000-common.dtsi"

# Flashing/modem tools only (the build image legitimately installs rsync for OpenWrt's prerequisite check).
FORBIDDEN_FLASH = re.compile(r"\b(sysupgrade|fw_setenv|flash_erase|flashcp|mtd\s+write|reboot|microcom|minicom|atinout|"
                             r"socat|comgt|gcom|picocom)\b|dd\s+of=", re.I)
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
FORBIDDEN = re.compile(
    r"\b(sysupgrade|fw_setenv|flash_erase|flashcp|mtd\s+write|reboot|mkfs\S*|ssh|scp|rsync|microcom|minicom|"
    r"atinout|socat|comgt|gcom|picocom)\b|dd\s+of=|>\s*/dev/(tty|cdc|mhi|wwan)",
    re.I,
)


def _code_lines(path):
    return [l for l in path.read_text().splitlines() if l.strip() and not l.lstrip().startswith("#")]


def _pins():
    out = {}
    for line in (RECIPE / "pins.env").read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip().strip('"')
    return out


def test_recipe_layout_exists():
    for rel in ("pins.env", "prepare.sh", "Containerfile", "container-build.sh", "config/xe3000.config",
                "files/usr/sbin/xe3000-sim-select", "files/etc/uci-defaults/90-xe3000-defaults",
                "feeds/xe3000/gl-puli-mcu/Makefile"):
        assert (RECIPE / rel).is_file(), rel
    assert RUNBOOK.is_file()
    assert KERNEL_PATCHES and TREE_PATCHES


def test_pins_are_a_25_12_tag_with_full_commit():
    pins = _pins()
    assert re.fullmatch(r"v25\.12\.\d+", pins["OPENWRT_TAG"])
    assert re.fullmatch(r"[0-9a-f]{40}", pins["OPENWRT_COMMIT"])
    assert pins["OPENWRT_REPO"].startswith("https://github.com/openwrt/openwrt")


def test_kernel_patch_adds_mhi_id_in_openwrt_layout():
    (patch,) = KERNEL_PATCHES
    assert re.fullmatch(r"\d{3}-.+\.patch", patch.name)
    text = patch.read_text()
    assert "--- a/drivers/bus/mhi/host/pci_generic.c" in text
    assert "+++ b/drivers/bus/mhi/host/pci_generic.c" in text
    added = [l for l in text.splitlines() if l.startswith("+") and not l.startswith("+++")]
    body = "\n".join(added)
    assert "PCI_DEVICE_SUB(PCI_VENDOR_ID_QCOM, 0x0308, PCI_VENDOR_ID_QCOM, 0x5201)" in body
    assert "Signed-off-by:" in text
    assert not [l for l in text.splitlines() if l.startswith("-") and not l.startswith("---")]  # additive only


def test_tree_patch_sets_pcie_port_pm_off_in_bootargs():
    (patch,) = TREE_PATCHES
    text = patch.read_text()
    assert f"+++ b/{DTSI}" in text
    plus = [l for l in text.splitlines() if l.startswith("+") and not l.startswith("+++")]
    assert len(plus) == 1 and "pcie_port_pm=off" in plus[0]
    assert "console=ttyS0,115200n8" in plus[0] and "root=PARTLABEL=rootfs" in plus[0]


def test_config_selects_only_xe3000_and_gl_puli_mcu():
    cfg = (RECIPE / "config" / "xe3000.config").read_text().splitlines()
    for need in ("CONFIG_TARGET_mediatek=y", "CONFIG_TARGET_mediatek_filogic=y",
                 "CONFIG_TARGET_mediatek_filogic_DEVICE_glinet_gl-xe3000=y",
                 "CONFIG_PACKAGE_gl-puli-mcu=y", "CONFIG_PACKAGE_kmod-mhi-pci-generic=y"):
        assert need in cfg, need
    devices = [l for l in cfg if re.match(r"CONFIG_TARGET_\w+_DEVICE_.*=y", l)]
    assert devices == ["CONFIG_TARGET_mediatek_filogic_DEVICE_glinet_gl-xe3000=y"]


def test_gl_puli_mcu_feed_is_a_stub_without_vendor_code():
    mk = (RECIPE / "feeds" / "xe3000" / "gl-puli-mcu" / "Makefile").read_text()
    assert "PKG_NAME:=gl-puli-mcu" in mk and "GPL-2.0" in mk
    assert not list((RECIPE / "feeds").rglob("*.bin")) and not list((RECIPE / "feeds").rglob("*.ko"))


# ---- SIM-select helper: prints, never sends -------------------------------------------------------------------

def _sim(*args):
    return subprocess.run(["sh", str(SIM), *args], capture_output=True, text=True, timeout=10)


@pytest.mark.parametrize("slot", ["1", "2"])
def test_sim_select_prints_at_sequence(slot):
    r = _sim(slot)
    assert r.returncode == 0, r.stderr
    lines = r.stdout.splitlines()
    assert any(l == f"AT+QUIMSLOT={slot}" for l in lines)
    assert all(l.startswith(("AT", "#")) for l in lines if l.strip())


@pytest.mark.parametrize("bad", [[], ["0"], ["3"], ["a"], ["1", "2"], ["1;reboot"], ["--send"]])
def test_sim_select_rejects_bad_args(bad):
    r = _sim(*bad)
    assert r.returncode == 2 and not r.stdout.strip()
    assert "usage" in r.stderr.lower()


def test_sim_select_banner_says_nothing_is_sent():
    assert "NOT SENT" in _sim("1").stdout


def test_sim_select_has_no_way_to_send():
    code = "\n".join(_code_lines(SIM))
    assert not FORBIDDEN.search(code)
    assert "/dev/" not in code and "ttyUSB" not in code and "mhi" not in code.lower()


# ---- uci-defaults ---------------------------------------------------------------------------------------------

def test_uci_defaults_idempotent_and_non_secret():
    text = UCI_DEFAULTS.read_text()
    assert text.startswith("#!/bin/sh\n")
    assert text.rstrip().endswith("exit 0")
    assert "uci commit" in text
    low = text.lower()
    for bad in ("password", "psk", "key", "wireless", "firewall", "network.lan"):
        assert bad not in low, bad
    assert not IPV4.search(text)


# ---- static safety across the whole recipe --------------------------------------------------------------------

def test_recipe_scripts_never_flash_ssh_or_touch_the_modem():
    for path in SHELL_SCRIPTS:
        assert path.is_file(), path
        hit = FORBIDDEN.search("\n".join(_code_lines(path)))
        assert not hit, f"{path.name}: {hit and hit.group(0)}"


def test_no_ipv4_addresses_or_proprietary_blobs_in_recipe_and_runbook():
    files = [p for p in RECIPE.rglob("*") if p.is_file()] + [RUNBOOK]
    for p in files:
        assert not IPV4.search(p.read_text()), p
        assert p.suffix not in {".bin", ".ko", ".img", ".fip"}, p


@pytest.mark.parametrize("path", SHELL_SCRIPTS, ids=lambda p: p.name)
def test_scripts_parse(path):
    shell = "sh" if path in (SIM, UCI_DEFAULTS) else "bash"
    assert subprocess.run([shell, "-n", str(path)], capture_output=True).returncode == 0


@pytest.mark.parametrize("path", SHELL_SCRIPTS, ids=lambda p: p.name)
def test_scripts_use_strict_mode(path):
    assert re.search(r"^set -(eu|euo pipefail|u)\b", path.read_text(), re.M) or path == UCI_DEFAULTS


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck not installed (CI job covers it)")
@pytest.mark.parametrize("path", SHELL_SCRIPTS, ids=lambda p: p.name)
def test_shellcheck_clean(path):
    shell = "sh" if path in (SIM, UCI_DEFAULTS) else "bash"
    r = subprocess.run(["shellcheck", "-s", shell, str(path)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout


def test_ci_shellchecks_the_recipe():
    wf = (REPO / ".github" / "workflows" / "ci.yml").read_text()
    assert "recipe/prepare.sh" in wf and "xe3000-sim-select" in wf and "90-xe3000-defaults" in wf


def test_shell_scripts_are_executable():
    for path in (PREPARE, SIM, RECIPE / "container-build.sh"):
        assert os.access(path, os.X_OK), path


# ---- prepare.sh against a local fixture repo (no network) -----------------------------------------------------

def _git(cwd, *args):
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid", "GIT_CONFIG_GLOBAL": "/dev/null"}
    return subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture
def upstream(tmp_path):
    repo = tmp_path / "upstream"
    dts = repo / DTSI
    dts.parent.mkdir(parents=True)
    dts.write_text(textwrap.dedent(f"""\
        // SPDX-License-Identifier: GPL-2.0-or-later OR MIT

        #include "mt7981.dtsi"
        #include <dt-bindings/gpio/gpio.h>

        / {{
        \tchosen {{
        \t\t{BOOTARGS}
        \t}};

        \taliases {{
        \t\tlabel-mac-device = &gmac0;
        \t}};
        }};
        """))
    (repo / "target/linux/generic/pending-6.12").mkdir(parents=True)
    (repo / "target/linux/generic/pending-6.12/.keep").write_text("")
    (repo / "feeds.conf.default").write_text("src-git packages https://example.invalid/packages.git\n")
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "fixture")
    _git(repo, "tag", "v25.12.99")
    return repo, _git(repo, "rev-parse", "HEAD")


def _prepare(tmp_path, upstream_repo, commit, *args):
    env = {**os.environ, "BUILD_DIR": str(tmp_path / "build"), "OPENWRT_REPO": str(upstream_repo),
           "OPENWRT_TAG": "v25.12.99", "OPENWRT_COMMIT": commit, "GIT_CONFIG_GLOBAL": "/dev/null"}
    return subprocess.run(["bash", str(PREPARE), *args], env=env, capture_output=True, text=True, timeout=120)


def test_prepare_print_plan_is_offline_and_mentions_pins():
    env = {**os.environ, "BUILD_DIR": "/nonexistent-for-test"}
    r = subprocess.run(["bash", str(PREPARE), "--print-plan"], env=env, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    pins = _pins()
    assert pins["OPENWRT_TAG"] in r.stdout and pins["OPENWRT_COMMIT"] in r.stdout
    assert "pcie_port_pm=off" in r.stdout and "0x5201" in r.stdout
    assert not os.path.exists("/nonexistent-for-test")


def test_prepare_applies_patches_overlay_and_config(tmp_path, upstream):
    repo, commit = upstream
    r = _prepare(tmp_path, repo, commit)
    assert r.returncode == 0, r.stdout + r.stderr
    dest = tmp_path / "build" / "openwrt"
    dts = (dest / DTSI).read_text()
    assert "pcie_port_pm=off" in dts and "console=ttyS0,115200n8" in dts
    assert (dest / "target/linux/generic/pending-6.12" / KERNEL_PATCHES[0].name).is_file()
    assert (dest / "files/usr/sbin/xe3000-sim-select").is_file()
    assert os.access(dest / "files/usr/sbin/xe3000-sim-select", os.X_OK)
    assert (dest / "files/etc/uci-defaults/90-xe3000-defaults").is_file()
    assert (dest / "package/xe3000/gl-puli-mcu/Makefile").is_file()
    cfg = (dest / ".config").read_text()
    assert "CONFIG_TARGET_mediatek_filogic_DEVICE_glinet_gl-xe3000=y" in cfg
    assert _git(dest, "rev-parse", "HEAD") == commit


def test_prepare_aborts_when_tag_commit_differs_from_pin(tmp_path, upstream):
    repo, _ = upstream
    r = _prepare(tmp_path, repo, "0" * 40)
    assert r.returncode != 0
    assert "does not match" in (r.stdout + r.stderr)


def test_prepare_leaves_no_tree_after_failed_commit_pin(tmp_path, upstream):
    repo, _ = upstream
    r = _prepare(tmp_path, repo, "0" * 40)
    assert r.returncode != 0
    assert not (tmp_path / "build" / "openwrt").exists()
    leftovers = [p.name for p in (tmp_path / "build").iterdir()] if (tmp_path / "build").exists() else []
    assert leftovers == []


def test_prepare_leaves_no_tree_after_failed_patch(tmp_path, upstream):
    repo, _ = upstream
    dts = repo / DTSI
    dts.write_text(dts.read_text().replace("root=PARTLABEL=rootfs", "root=PARTLABEL=other"))
    _git(repo, "commit", "-q", "-am", "diverge")
    _git(repo, "tag", "-f", "v25.12.99")
    commit = _git(repo, "rev-parse", "HEAD")
    r = _prepare(tmp_path, repo, commit)
    assert r.returncode != 0
    assert not (tmp_path / "build" / "openwrt").exists()
    assert list((tmp_path / "build").iterdir()) == []


def test_prepare_writes_stamp_with_pinned_commit(tmp_path, upstream):
    repo, commit = upstream
    assert _prepare(tmp_path, repo, commit).returncode == 0
    stamp = tmp_path / "build" / "openwrt" / ".xe3000-prepared"
    assert stamp.read_text().strip() == commit


def _build_sandbox(tmp_path, commit_in_pins):
    root = tmp_path / "sandbox"
    (root / "recipe").mkdir(parents=True)
    shutil.copy(RECIPE / "container-build.sh", root / "recipe" / "container-build.sh")
    if LIB.is_file():
        shutil.copy(LIB, root / "recipe" / "lib.sh")
    (root / "recipe" / "pins.env").write_text(
        f"OPENWRT_REPO=https://example.invalid/openwrt.git\nOPENWRT_TAG=v25.12.99\nOPENWRT_COMMIT={commit_in_pins}\n")
    tree = root / "build" / "openwrt"
    tree.mkdir(parents=True)
    _git(tree, "init", "-q", "-b", "main")
    (tree / "f").write_text("x")
    _git(tree, "add", "-A")
    _git(tree, "commit", "-q", "-m", "x")
    return root, tree, _git(tree, "rev-parse", "HEAD")


def _seal(root, tree):
    """Record the input manifest exactly as prepare.sh does (via the shared library)."""
    r = subprocess.run(["bash", "-c", f'. "{root}/recipe/lib.sh" && xe3000_write_manifest "{tree}"'],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def _run_build(root):
    env = {**os.environ, "PODMAN": "echo"}
    return subprocess.run(["bash", str(root / "recipe" / "container-build.sh"), "feeds"], env=env,
                          capture_output=True, text=True, timeout=30)


def test_container_build_rejects_tree_without_stamp(tmp_path):
    root, _, head = _build_sandbox(tmp_path, "a" * 40)
    r = _run_build(root)
    assert r.returncode != 0 and "prepare" in r.stderr


def test_container_build_rejects_stamp_not_matching_head_or_pin(tmp_path):
    root, tree, head = _build_sandbox(tmp_path, "a" * 40)
    (tree / ".xe3000-prepared").write_text(head + "\n")
    assert _run_build(root).returncode != 0  # HEAD is not the pinned commit
    root3, tree3, head3 = _build_sandbox(tmp_path / "three", "c" * 40)
    (root3 / "recipe" / "pins.env").write_text(
        f"OPENWRT_REPO=x\nOPENWRT_TAG=t\nOPENWRT_COMMIT={head3}\n")
    (tree3 / ".xe3000-prepared").write_text("d" * 40 + "\n")
    assert _run_build(root3).returncode != 0  # stamp differs from HEAD


def test_container_build_accepts_verified_tree(tmp_path):
    root, tree, head = _build_sandbox(tmp_path, "a" * 40)
    (root / "recipe" / "pins.env").write_text(f"OPENWRT_REPO=x\nOPENWRT_TAG=t\nOPENWRT_COMMIT={head}\n")
    (tree / ".xe3000-prepared").write_text(head + "\n")
    _seal(root, tree)
    r = _run_build(root)
    assert r.returncode == 0, r.stderr


def test_runbook_specifies_sysupgrade_image_not_factory():
    text = RUNBOOK.read_text().lower()
    assert "sysupgrade.bin" in text
    assert "openwrt `factory` image" not in text
    for banned in ("factory", "preloader", "fip"):
        assert banned in text  # named only in the explicit exclusion
    assert "do not upload" in text or "never upload" in text


def test_prepare_refuses_existing_destination(tmp_path, upstream):
    repo, commit = upstream
    assert _prepare(tmp_path, repo, commit).returncode == 0
    r = _prepare(tmp_path, repo, commit)
    assert r.returncode != 0 and "exists" in (r.stdout + r.stderr)


def test_prepare_refuses_build_dir_outside_repo_build(tmp_path):
    env = {**os.environ}
    env.pop("BUILD_DIR", None)
    r = subprocess.run(["bash", str(PREPARE), "--dest", str(tmp_path / "elsewhere")], env=env,
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 2 and "build" in r.stderr


def test_prepare_rejects_unknown_args():
    r = subprocess.run(["bash", str(PREPARE), "--flash"], capture_output=True, text=True, timeout=30)
    assert r.returncode == 2 and "usage" in r.stderr.lower()


# ---- container, justfile, runbook -----------------------------------------------------------------------------

def test_containerfile_pinned_nonroot_and_inert():
    text = (RECIPE / "Containerfile").read_text()
    assert re.search(r"^FROM docker\.io/library/debian@sha256:[0-9a-f]{64}$", text, re.M)
    assert re.search(r"^USER (?!root)\S+", text, re.M)
    assert "build-essential" in text and "libncurses-dev" in text
    assert "ENTRYPOINT" not in text and "CMD [\"sh\"" not in text
    assert not FORBIDDEN_FLASH.search("\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#")))


def test_container_build_script_is_hardened_and_scoped():
    body = (RECIPE / "container-build.sh").read_text()
    assert "--cap-drop=ALL" in body and "--security-opt no-new-privileges" in body and "--pids-limit" in body
    assert "--privileged" not in body and "--device" not in body
    assert "build:/home/build/work" in body and ".env" not in body
    assert "harvest" not in body and "unpacked" not in body


def test_justfile_has_recipe_targets_and_suite_mounts_recipe():
    text = (REPO / "justfile").read_text()
    for name in ("recipe-image", "recipe-prepare", "recipe-build"):
        assert re.search(rf"^{name}\b", text, re.M), name
    assert "recipe:/work/recipe:ro" in text


def test_runbook_covers_recovery_backup_and_is_document_only():
    text = RUNBOOK.read_text()
    low = text.lower()
    for needle in ("u-boot", "web recovery", "emmc", "backup", "bootloader", "untouched", "rollback", "sha256"):
        assert needle in low, needle
    assert "document only" in low
    assert "not been executed" in low
    assert not re.search(r"\bof=/dev/", text)
    assert "fw_setenv" not in text.replace("Never run `fw_setenv`", "")


def _backup_section():
    text = RUNBOOK.read_text()
    start = text.index("## 2.")
    return text[start:text.index("## 3.")]


def test_runbook_backup_checks_pipeline_status_not_just_checksums():
    sec = _backup_section().lower()
    assert "pipefail" in sec or "pipestatus" in sec


def test_runbook_backup_verifies_byte_count_against_device_size():
    sec = _backup_section().lower()
    assert "byte count" in sec or "wc -c" in sec
    assert "blockdev --getsize64" in sec or "/sys/class/block" in sec


def test_runbook_backup_does_not_trust_matching_checksums_alone():
    sec = _backup_section().lower()
    assert "truncated" in sec


# ---- overlay hygiene: nothing secret-bearing or untracked may enter the build ----------------------------------

def _recipe_copy(tmp_path):
    root = tmp_path / "repocopy"
    shutil.copytree(RECIPE, root / "recipe", ignore=shutil.ignore_patterns("__pycache__"))
    return root


def _prepare_copy(root, tmp_path, upstream_repo, commit):
    env = {**os.environ, "BUILD_DIR": str(tmp_path / "build"), "OPENWRT_REPO": str(upstream_repo),
           "OPENWRT_TAG": "v25.12.99", "OPENWRT_COMMIT": commit, "GIT_CONFIG_GLOBAL": "/dev/null"}
    return subprocess.run(["bash", str(root / "recipe" / "prepare.sh")], env=env, capture_output=True, text=True,
                          timeout=120)


def _plant(root, rel, content="x\n"):
    path = root / "recipe" / "files" / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


SECRET_NAMES = [".env", ".env.local", "etc/dropbear/dropbear_rsa_host_key", "etc/shadow", "root/.ssh/id_ed25519",
                "etc/ssl/private/site.pem", "etc/ssl/site.key", "etc/config/vpn.p12", "etc/wireguard/wg0.conf.secret"]


@pytest.mark.parametrize("rel", SECRET_NAMES)
def test_prepare_refuses_secret_named_overlay_files(tmp_path, upstream, rel):
    repo, commit = upstream
    root = _recipe_copy(tmp_path)
    _plant(root, rel)
    r = _prepare_copy(root, tmp_path, repo, commit)
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "build" / "openwrt").exists()
    assert "overlay" in r.stderr.lower()


def test_prepare_refuses_private_key_content_in_any_overlay_file(tmp_path, upstream):
    repo, commit = upstream
    root = _recipe_copy(tmp_path)
    marker = "-----BEGIN " + "OPENSSH PRIVATE" + " KEY-----"
    _plant(root, "etc/config/innocent", marker + "\n")
    r = _prepare_copy(root, tmp_path, repo, commit)
    assert r.returncode != 0
    assert not (tmp_path / "build" / "openwrt").exists()
    assert "overlay" in r.stderr.lower()


def test_prepare_refuses_symlinks_in_overlay(tmp_path, upstream):
    repo, commit = upstream
    root = _recipe_copy(tmp_path)
    link = root / "recipe" / "files" / "etc" / "leak"
    link.symlink_to("/etc/hostname")
    r = _prepare_copy(root, tmp_path, repo, commit)
    assert r.returncode != 0
    assert not (tmp_path / "build" / "openwrt").exists()


def test_prepare_refuses_untracked_overlay_files_in_a_git_checkout(tmp_path, upstream):
    repo, commit = upstream
    root = _recipe_copy(tmp_path)
    _git(root, "init", "-q", "-b", "main")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "tracked")
    _plant(root, "etc/config/untracked-extra", "harmless\n")
    r = _prepare_copy(root, tmp_path, repo, commit)
    assert r.returncode != 0
    assert not (tmp_path / "build" / "openwrt").exists()
    assert "untracked" in r.stderr.lower()


def test_prepare_copies_clean_tracked_overlay_in_a_git_checkout(tmp_path, upstream):
    repo, commit = upstream
    root = _recipe_copy(tmp_path)
    _git(root, "init", "-q", "-b", "main")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "tracked")
    r = _prepare_copy(root, tmp_path, repo, commit)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (tmp_path / "build" / "openwrt" / "files" / "usr/sbin/xe3000-sim-select").is_file()


# ---- runbook honesty about recovery ----------------------------------------------------------------------------

def test_runbook_does_not_promise_guaranteed_recovery():
    low = RUNBOOK.read_text().lower()
    assert "always available" not in low
    assert "is always" not in low


def test_runbook_states_documented_uboot_defect_and_cites_upstream():
    text = RUNBOOK.read_text()
    low = text.lower()
    assert "defect" in low and "mt2500" in low
    assert "no guarantee" in low or "cannot be guaranteed" in low or "may not" in low
    assert re.search(r"https://openwrt\.org/toh/\S+", text)


def test_runbook_requires_verified_full_backup_before_any_flash():
    low = RUNBOOK.read_text().lower()
    assert "full emmc" in low or "full mtd" in low
    assert re.search(r"(do not|never) flash[^.\n]*(until|without)[^.\n]*(verified|backup)", low)


# ---- round 2: committed-only inputs, credential content, input manifest ------------------------------------------

def _commit_all(root):
    _git(root, "init", "-q", "-b", "main")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "tracked")


def _fake_credentials():
    """Credential-shaped lines assembled at runtime so no secret-looking literal sits in the repo."""
    word = "hunter" + "2hunter2"
    return {
        "uci-option": "config wifi-iface\n\toption " + "ke" + "y '" + word + "'\n",
        "uci-set": "uci set wireless.default_radio0." + "ps" + "k='" + word + "'\n",
        "shell-assign": "WIFI_" + "PASS" + "WORD=" + word + "\n",
        "token": "api_" + "tok" + "en: " + word + "\n",
        "ghp": "x=gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8\n",
    }


@pytest.mark.parametrize("kind", sorted(_fake_credentials()))
def test_prepare_refuses_credential_content_even_in_committed_overlay_file(tmp_path, upstream, kind):
    repo, commit = upstream
    root = _recipe_copy(tmp_path)
    sim = root / "recipe" / "files" / "usr" / "sbin" / "xe3000-sim-select"
    sim.write_text(sim.read_text() + _fake_credentials()[kind])
    _commit_all(root)
    r = _prepare_copy(root, tmp_path, repo, commit)
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "build" / "openwrt").exists()
    assert "credential" in r.stderr.lower()


def test_prepare_refuses_modified_tracked_overlay_file(tmp_path, upstream):
    repo, commit = upstream
    root = _recipe_copy(tmp_path)
    _commit_all(root)
    sim = root / "recipe" / "files" / "usr" / "sbin" / "xe3000-sim-select"
    sim.write_text(sim.read_text() + "# harmless local edit\n")
    r = _prepare_copy(root, tmp_path, repo, commit)
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "build" / "openwrt").exists()
    assert "uncommitted" in r.stderr.lower()


def test_prepare_refuses_staged_but_uncommitted_overlay_change(tmp_path, upstream):
    repo, commit = upstream
    root = _recipe_copy(tmp_path)
    _commit_all(root)
    (root / "recipe" / "files" / "etc" / "staged-extra").write_text("harmless\n")
    _git(root, "add", "-A")
    r = _prepare_copy(root, tmp_path, repo, commit)
    assert r.returncode != 0 and "uncommitted" in r.stderr.lower()


def _plant_feed(root, rel, content="x\n"):
    path = root / "recipe" / "feeds" / "xe3000" / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


@pytest.mark.parametrize("rel", [".env", "gl-puli-mcu/.env", "gl-puli-mcu/files/deploy.key", "gl-puli-mcu/id_ed25519"])
def test_prepare_refuses_secret_named_package_inputs(tmp_path, upstream, rel):
    repo, commit = upstream
    root = _recipe_copy(tmp_path)
    _plant_feed(root, rel)
    r = _prepare_copy(root, tmp_path, repo, commit)
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "build" / "openwrt").exists()
    assert "package" in r.stderr.lower()


def test_prepare_refuses_credential_content_in_package_inputs(tmp_path, upstream):
    repo, commit = upstream
    root = _recipe_copy(tmp_path)
    _plant_feed(root, "gl-puli-mcu/files/net.conf", _fake_credentials()["shell-assign"])
    _commit_all(root)
    r = _prepare_copy(root, tmp_path, repo, commit)
    assert r.returncode != 0
    assert not (tmp_path / "build" / "openwrt").exists()
    assert "credential" in r.stderr.lower()


def test_prepare_refuses_symlinks_in_package_inputs(tmp_path, upstream):
    repo, commit = upstream
    root = _recipe_copy(tmp_path)
    link = root / "recipe" / "feeds" / "xe3000" / "gl-puli-mcu" / "leak"
    link.symlink_to("/etc/hostname")
    r = _prepare_copy(root, tmp_path, repo, commit)
    assert r.returncode != 0
    assert not (tmp_path / "build" / "openwrt").exists()


def test_prepare_refuses_untracked_or_ignored_package_inputs_in_a_git_checkout(tmp_path, upstream):
    repo, commit = upstream
    root = _recipe_copy(tmp_path)
    _commit_all(root)
    _plant_feed(root, "gl-puli-mcu/extra.c", "int main(void){return 0;}\n")
    r = _prepare_copy(root, tmp_path, repo, commit)
    assert r.returncode != 0 and "untracked" in r.stderr.lower()
    assert not (tmp_path / "build" / "openwrt").exists()


def test_prepare_refuses_modified_tracked_package_input(tmp_path, upstream):
    repo, commit = upstream
    root = _recipe_copy(tmp_path)
    _commit_all(root)
    mk = root / "recipe" / "feeds" / "xe3000" / "gl-puli-mcu" / "Makefile"
    mk.write_text(mk.read_text() + "# local edit\n")
    r = _prepare_copy(root, tmp_path, repo, commit)
    assert r.returncode != 0 and "uncommitted" in r.stderr.lower()


def test_prepare_writes_input_manifest_and_container_build_accepts_the_prepared_tree(tmp_path, upstream):
    repo, commit = upstream
    root = _recipe_copy(tmp_path)
    (root / "recipe" / "pins.env").write_text(
        f"OPENWRT_REPO={repo}\nOPENWRT_TAG=v25.12.99\nOPENWRT_COMMIT={commit}\n")
    shutil.copy(RECIPE / "container-build.sh", root / "recipe" / "container-build.sh")
    env = {**os.environ, "BUILD_DIR": str(root / "build"), "GIT_CONFIG_GLOBAL": "/dev/null"}
    r = subprocess.run(["bash", str(root / "recipe" / "prepare.sh")], env=env, capture_output=True, text=True,
                       timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    tree = root / "build" / "openwrt"
    manifest = (tree / ".xe3000-manifest").read_text()
    assert "files/usr/sbin/xe3000-sim-select" in manifest and "package/xe3000/gl-puli-mcu/Makefile" in manifest
    assert _run_build(root).returncode == 0


def _prepared(tmp_path, upstream):
    repo, commit = upstream
    root = _recipe_copy(tmp_path)
    (root / "recipe" / "pins.env").write_text(
        f"OPENWRT_REPO={repo}\nOPENWRT_TAG=v25.12.99\nOPENWRT_COMMIT={commit}\n")
    env = {**os.environ, "BUILD_DIR": str(root / "build"), "GIT_CONFIG_GLOBAL": "/dev/null"}
    r = subprocess.run(["bash", str(root / "recipe" / "prepare.sh")], env=env, capture_output=True, text=True,
                       timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    return root, root / "build" / "openwrt"


def test_container_build_rejects_overlay_file_added_after_prepare(tmp_path, upstream):
    root, tree = _prepared(tmp_path, upstream)
    wireless = tree / "files" / "etc" / "config" / "wireless"
    wireless.parent.mkdir(parents=True, exist_ok=True)
    wireless.write_text("config wifi-iface\n")
    r = _run_build(root)
    assert r.returncode != 0 and "prepared inputs" in r.stderr


def test_container_build_rejects_modified_config_and_package_after_prepare(tmp_path, upstream):
    root, tree = _prepared(tmp_path, upstream)
    mk = tree / "package" / "xe3000" / "gl-puli-mcu" / "Makefile"
    mk.write_text(mk.read_text() + "# changed\n")
    assert _run_build(root).returncode != 0


def test_container_build_rejects_removed_patch_after_prepare(tmp_path, upstream):
    root, tree = _prepared(tmp_path, upstream)
    (tree / "target/linux/generic/pending-6.12" / KERNEL_PATCHES[0].name).unlink()
    assert _run_build(root).returncode != 0


def test_container_build_rejects_reverted_tree_patch_after_prepare(tmp_path, upstream):
    root, tree = _prepared(tmp_path, upstream)
    _git(tree, "checkout", "--", DTSI)
    assert _run_build(root).returncode != 0


def test_container_build_rejects_seed_config_dropped_after_prepare(tmp_path, upstream):
    root, tree = _prepared(tmp_path, upstream)
    (tree / ".config").write_text("# emptied\n")
    assert _run_build(root).returncode != 0


def test_container_build_rejects_missing_manifest(tmp_path, upstream):
    root, tree = _prepared(tmp_path, upstream)
    (tree / ".xe3000-manifest").unlink()
    assert _run_build(root).returncode != 0


def test_container_build_rescans_credentials_even_if_manifest_matches(tmp_path, upstream):
    root, tree = _prepared(tmp_path, upstream)
    wireless = tree / "files" / "etc" / "config" / "wireless"
    wireless.parent.mkdir(parents=True, exist_ok=True)
    wireless.write_text(_fake_credentials()["uci-option"])
    _seal(root, tree)  # attacker also refreshes the manifest: the credential rescan must still refuse
    r = _run_build(root)
    assert r.returncode != 0 and "credential" in r.stderr.lower()


def test_container_build_rejects_symlink_in_prepared_inputs(tmp_path, upstream):
    root, tree = _prepared(tmp_path, upstream)
    (tree / "files" / "etc" / "leak").symlink_to("/etc/hostname")
    _seal(root, tree)
    assert _run_build(root).returncode != 0
