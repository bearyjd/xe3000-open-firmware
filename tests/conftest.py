from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from fakes import FakeClient

class Lazy:
    """Module proxy resolved on first attribute access, so a missing module fails its tests, not collection."""

    def __init__(self, name: str) -> None:
        self._name = name

    def __getattr__(self, attr):
        import importlib
        return getattr(importlib.import_module(self._name), attr)


REPO = Path(__file__).resolve().parent.parent
GITLEAKS_TOML = REPO / "containers" / "gitleaks.toml"
CFG = {"gitleaks_bin": os.environ.get("RECON_GITLEAKS_BIN") or shutil.which("gitleaks")}


def pytest_collection_modifyitems(config, items):
    has_podman = shutil.which("podman") is not None
    has_gitleaks = bool(CFG["gitleaks_bin"]) or has_podman
    for item in items:
        if "requires_podman" in item.keywords and not has_podman:
            item.add_marker(pytest.mark.skip(reason="no podman in this environment"))
        if "requires_gitleaks" in item.keywords and not has_gitleaks:
            item.add_marker(pytest.mark.skip(reason="no gitleaks binary or podman"))


@pytest.fixture
def root(tmp_path) -> Path:
    base = tmp_path / "repo"
    for sub in ("harvest/raw", "harvest/redacted", "unpacked", "cache", "findings/raw", "containers"):
        (base / sub).mkdir(parents=True)
    for name in ("gitleaks.toml", "gitleaks.image", "recon-allowlist.txt"):
        if (REPO / "containers" / name).exists():
            shutil.copy(REPO / "containers" / name, base / "containers" / name)
    return base


def _write(base: Path, rel: str, text: str) -> None:
    path = base / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


@pytest.fixture
def fixture_tree(root) -> Path:
    """Synthetic redacted-zone tree: configs, init/hotplug scripts, DTS, dmesg, lsmod."""
    red = root / "harvest" / "redacted"
    _write(red, "etc/config/network", "config interface 'wan'\n\toption proto 'dhcp'\n\toption device 'eth1'\n")
    _write(red, "etc/init.d/modem",
           "#!/bin/sh /etc/rc.common\nSTART=99\nstart() {\n  echo 'AT+CFUN=1' > /dev/ttyUSB2\n"
           "  insmod mhi_wwan_ctrl\n  echo 12 > /sys/class/gpio/export\n  ubus call modem get_info\n}\n")
    _write(red, "etc/hotplug.d/iface/10-modem", "#!/bin/sh\n[ \"$ACTION\" = ifup ] && logger modem up\n")
    _write(red, "sys/board.dts", "fan {\n\tgpios = <&tlmm 7 0>;\n\tcompatible = \"gpio-fan\";\n};\n")
    _write(red, "var/dmesg.txt", "[    1.0] mhi_wwan_ctrl: probe ok\n[    2.0] gpio-fan: registered\n")
    _write(red, "proc/lsmod.txt", "Module Size Used by\nmhi_wwan_ctrl 20480 1\nmhi 94208 2 mhi_wwan_ctrl\n")
    return red


def write_stamp_for(root: Path) -> None:
    from recon import preflight
    dirs = [root / "harvest" / "redacted", root / "unpacked"]
    preflight.write_stamp(root, preflight.tree_hash(dirs, root))


@pytest.fixture
def stamp():
    """Callable: write a valid pre-flight stamp for the current default input tree."""
    return write_stamp_for


@pytest.fixture
def stamped(root, fixture_tree):
    write_stamp_for(root)
    return root


@pytest.fixture
def fake_client() -> FakeClient:
    return FakeClient()
