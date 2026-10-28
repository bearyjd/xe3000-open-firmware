"""The exclusion lists exist three times (recon/names.py, harvest.sh, collect.sh). Fuzz them against each other."""
import os
import random
import subprocess
from pathlib import Path

import pytest

from conftest import REPO
from recon import redact

COLLECT = REPO / "scripts" / "remote" / "collect.sh"
HARVEST = REPO / "scripts" / "harvest.sh"

POOL = [
    "etc", "config", "private", "dropbear", "ssh", "ssl", "root", ".ssh", "sys", "class", "proc", "wireguard", "init.d",
    "id_rsa", "id_dsa", "id_ecdsa.pub", "id_ed25519", "ssh_host_rsa_key", "my_host_key", "board_serial", "serial",
    "serial_number", "Serial1", "wg0.conf", "wgvpn.conf", "wg.conf", "wgx.cfg", "vpn.wg", "chap-secrets",
    "pap-secrets", "ipsec.secrets", "shadow", "shadow-", "gshadow", "htpasswd", "userpass.txt", "wpa_psk.conf",
    "auth-user-pass", "a.pem", "b.key", "c.psk", "d.secrets", "e.auth", "glmodem", "network", "led", "fan",
    "cpuinfo", "dmesg", "10-modem", "gl_modem", "notes.txt", "keyboard", "pem", "keys", "publickey", "wifi",
]


def _names(count=3000):
    rng = random.Random(1234)
    out = set()
    while len(out) < count:
        out.add("/".join(rng.choice(POOL) for _ in range(rng.randint(1, 4))))
    return sorted(out)


NAMES = _names()


def _shell(argv, names, env=None):
    p = subprocess.run(argv, input="\n".join(names) + "\n", capture_output=True, text=True, timeout=300,
                       env={"PATH": os.environ["PATH"], **(env or {})})
    assert p.returncode == 0, p.stderr
    return set(p.stdout.splitlines())


def test_collect_sh_exclusions_imply_python_exclusions():
    script = f'. "{COLLECT}"; while IFS= read -r n; do if is_excluded "/$n"; then printf "%s\\n" "$n"; fi; done'
    shell_excluded = _shell(["sh", "-c", script], NAMES, {"COLLECT_NO_MAIN": "1"})
    assert shell_excluded, "the fuzz set must hit the exclusion list"
    missed = sorted(n for n in shell_excluded if not redact._is_excluded(Path(n)))
    assert missed == []


def test_harvest_sh_exclusions_equal_python_exclusions():
    script = (f'source "{HARVEST}"; while IFS= read -r n; do if name_excluded "$n"; then printf "%s\\n" "$n"; fi; done')
    shell_excluded = _shell(["bash", "-c", script], NAMES)
    python_excluded = {n for n in NAMES if redact._is_excluded(Path(n))}
    assert shell_excluded == python_excluded, sorted(shell_excluded ^ python_excluded)[:20]


@pytest.mark.parametrize("name", ["etc/ssh/ssh_host_rsa_key", "root/.ssh/id_rsa", "sys/board_serial", "etc/config/wg0.conf",
                                  "etc/private/x", "etc/vpn/c.wg", "etc/ssh/my_host_key_old"])
def test_review_examples_are_excluded_by_all_three(name):
    assert redact._is_excluded(Path(name))
    script = f'. "{COLLECT}"; is_excluded "/{name}"'
    assert subprocess.run(["sh", "-c", script], env={"PATH": os.environ["PATH"], "COLLECT_NO_MAIN": "1"}).returncode == 0
    script = f'source "{HARVEST}"; name_excluded "{name}"'
    assert subprocess.run(["bash", "-c", script], env={"PATH": os.environ["PATH"]}).returncode == 0
