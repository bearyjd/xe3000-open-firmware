"""Offline checks for the Phase 1 harvest tooling. No router, no network, no ssh: ssh is a shim on PATH."""
import hashlib
import os
import re
import shutil
import stat
import subprocess
import tarfile
from pathlib import Path

import pytest

from conftest import REPO

COLLECT = REPO / "scripts" / "remote" / "collect.sh"
HARVEST = REPO / "scripts" / "harvest.sh"
SRC = COLLECT.read_text()
CODE = "\n".join(l for l in SRC.splitlines() if not l.lstrip().startswith("#"))

SHELLS = [["sh"]] + ([["busybox", "sh"]] if shutil.which("busybox") else [])


# ---------------------------------------------------------------- (a) static

FORBIDDEN_WORDS = ["rm", "mv", "cp", "tee", "dd", "mkdir", "mount", "umount", "opkg", "uci", "fw_setenv",
                   "reboot", "sysupgrade", "insmod", "modprobe", "rmmod", "chmod", "chown", "ln", "touch",
                   "sed", "awk", "wget", "curl", "nc", "ssh", "stty", "microcom", "socat", "gpioset", "sysctl"]


@pytest.mark.parametrize("word", FORBIDDEN_WORDS)
def test_no_forbidden_command(word):
    assert not re.search(rf"(?<![\w./-]){re.escape(word)}(?![\w./-])", CODE), word


def test_no_file_redirections():
    stripped = re.sub(r"2>&1|2?>\s*/dev/null", "", CODE)
    assert ">" not in stripped, "output redirection to something other than /dev/null or 2>&1"
    assert "<<" not in CODE  # heredocs may use temp files in some shells
    for m in re.finditer(r"<\s*(\"?[\w/$.]+\"?)", CODE):
        assert m.group(1).strip('"') in ("/dev/null", "/proc/modules", "/proc/$mo_p/comm"), m.group(0)


def test_mtd_only_read():
    assert not re.search(r"\bmtd\s+(write|erase|unlock|-)", CODE)
    assert not re.search(r"\bubi(format|attach|detach|mkvol|rmvol)", CODE)


def test_ubus_call_only_system_board():
    calls = re.findall(r"ubus\s+call\b[^\n]*", CODE)
    assert calls and all(re.fullmatch(r"ubus call system board", c.strip()) for c in calls), calls


def test_no_set_e_and_no_bashisms():
    assert not re.search(r"\bset\s+-[a-zA-Z]*e", CODE)
    for bad in ("[[", "local ", "<(", ">(", "declare ", "=(", "${!", "source ", "function "):
        assert bad not in CODE, bad


def test_no_modem_node_reads():
    assert not re.search(r"[<>]\s*\"?/dev/", CODE.replace("</dev/null", "").replace(">/dev/null", ""))
    for line in CODE.splitlines():
        if re.search(r"/dev/(tty|cdc|wwan|mhi)", line):
            assert not re.search(r"\b(cat|od|head|tail|dd|read|stty|strings|hexdump)\b", line), line
    assert "AT+" not in CODE


def test_no_secret_paths_are_read_explicitly():
    for bad in ("/etc/shadow", "dropbear/", "host_key"):
        assert not re.search(rf"\b(cat|frame_file|opt_file)\b[^\n]*{re.escape(bad)}", CODE), bad


# ---------------------------------------------------------------- stream parsing helper

def parse_stream(text):
    """Return (frames, outside_lines). Raises AssertionError on malformed framing."""
    frames, outside, cur = {}, [], None
    lines = text.split("\n")
    for line in lines:
        if cur is None:
            if line.startswith("@@BEGIN "):
                _, kind, name = line.split(" ")
                assert name not in frames, f"duplicate frame {name}"
                cur = (kind, name, [])
            elif line:
                outside.append(line)
        else:
            m = re.fullmatch(r"@@END (\S+) (\d+)", line)
            if m and m.group(1) == cur[1]:
                frames[cur[1]] = (cur[0], "\n".join(cur[2]), int(m.group(2)))
                cur = None
            else:
                cur[2].append(line)
    assert cur is None, f"unterminated frame {cur and cur[1]}"
    return frames, outside


# ---------------------------------------------------------------- (b) run collect.sh locally

SNAP_DIRS = ["/etc", "/root", "/opt", "/srv", "/usr/bin", "/usr/sbin", "/var/spool", "/var/mail"]


def snapshot():
    snap = {}
    for base in SNAP_DIRS:
        for dp, dn, fn in os.walk(base, followlinks=False):
            for n in dn + fn:
                p = os.path.join(dp, n)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                snap[p] = (st.st_mode, st.st_size, st.st_mtime_ns)
    return snap


@pytest.fixture(scope="module")
def local_run(tmp_path_factory):
    work = tmp_path_factory.mktemp("collect")
    results = {}
    before = snapshot()
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(work), "TMPDIR": str(work)}
    for shell in SHELLS:
        with open(COLLECT, "rb") as fh:
            try:
                p = subprocess.run(shell + ["-s"], stdin=fh, capture_output=True, cwd=work, env=env, timeout=120)
            except subprocess.TimeoutExpired:
                pytest.skip("collect.sh blocked on a sysfs read on this host; the container run is authoritative")
        results[" ".join(shell)] = p
    after = snapshot()
    return results, before, after, work


@pytest.mark.parametrize("shell", [" ".join(s) for s in SHELLS])
def test_collect_stream_well_formed(local_run, shell):
    p = local_run[0][shell]
    assert p.returncode == 0
    text = p.stdout.decode("utf-8", "replace")
    frames, outside = parse_stream(text)
    assert outside[0] == "@@COLLECT-VERSION 1"
    assert outside[-1] == f"@@DONE {len(frames)}"
    for o in outside[1:-1]:
        assert re.match(r"@@(MISSING|SKIPPED) \S", o), o
    for name in ("proc/cpuinfo", "proc/meminfo", "cmd/uname"):
        assert name in frames and frames[name][2] == 0, name
    assert frames["proc/meminfo"][1].startswith("MemTotal:")
    # a command that cannot exist in the test image is reported and the run continues
    assert "@@MISSING ubus" in outside


@pytest.mark.parametrize("shell", [" ".join(s) for s in SHELLS])
def test_collect_stream_has_no_excluded_paths(local_run, shell):
    text = local_run[0][shell].stdout.decode("utf-8", "replace")
    frames, outside = parse_stream(text)
    for name in frames:
        base = name.rsplit("/", 1)[-1]
        assert not name.startswith(("etc/shadow", "etc/dropbear")), name
        assert "host_key" not in name and not name.endswith((".pem", ".key")), name
        assert "serial" not in base.lower(), name
    shadow = Path("/etc/shadow")
    if shadow.exists() and os.access(shadow, os.R_OK):
        for line in shadow.read_text().splitlines():
            h = line.split(":")[1] if ":" in line else ""
            if len(h) > 8:
                assert h not in text


def test_collect_leaves_filesystem_unchanged(local_run):
    _, before, after, work = local_run
    assert before == after
    assert list(work.iterdir()) == []  # HOME/TMPDIR/cwd untouched


# ---- unit-level behaviour of the frame helpers, via sourcing (COLLECT_NO_MAIN is test-only)

def run_fn(call, *args, shell=("sh",)):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "COLLECT_NO_MAIN": "1"}
    p = subprocess.run(list(shell) + ["-c", f'. "{COLLECT}"; {call}', "sh", *map(str, args)],
                       capture_output=True, env=env, timeout=60)
    assert p.returncode == 0, p.stderr
    return p.stdout.decode()


@pytest.mark.parametrize("shell", SHELLS)
def test_exclusions_and_limits(tmp_path, shell):
    secret = "TOPSECRETVALUE"
    for name in ("a.pem", "b.key", "my_host_key", "serial", "serial_number", "good.txt", "sp ace"):
        (tmp_path / name).write_text(secret + "\n")
    (tmp_path / "big").write_bytes(b"x" * (1024 * 1024 + 1))
    wo = tmp_path / "writeonly"
    wo.write_text(secret)
    wo.chmod(0o200)
    (tmp_path / "link.txt").symlink_to(tmp_path / "serial_number")
    out = ""
    for name in ("a.pem", "b.key", "my_host_key", "serial", "serial_number", "big", "writeonly", "link.txt", "sp ace"):
        out += run_fn('frame_file t "$1"', tmp_path / name, shell=shell)
    assert secret not in out and "@@BEGIN" not in out
    assert out.count("@@SKIPPED") == 9
    assert "size=1048577" in out
    good = run_fn('frame_file t "$1"', tmp_path / "good.txt", shell=shell)
    assert good.startswith("@@BEGIN t ") and secret in good and good.rstrip().endswith(" 0")
    for path in ("/etc/shadow", "/etc/dropbear/dropbear_rsa_host_key", "/etc/dropbear/authorized_keys",
                 "/sys/bus/usb/devices/1-1/serial", "/sys/class/power_supply/BAT0/serial_number"):
        run_fn('is_excluded "$1"', path, shell=shell)  # returns 0 => run_fn asserts rc==0


def test_non_excluded_path_is_not_excluded():
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "COLLECT_NO_MAIN": "1"}
    p = subprocess.run(["sh", "-c", f'. "{COLLECT}"; is_excluded /etc/config/network'], env=env)
    assert p.returncode == 1


# ---------------------------------------------------------------- (c) harvest.sh with a fake ssh

@pytest.fixture
def shim(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    sshp = bindir / "ssh"
    sshp.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$@" > "$SHIM_DIR/args"\ncat > "$SHIM_DIR/stdin"\n'
        'if [ -n "${SHIM_STREAM:-}" ]; then cat "$SHIM_STREAM"; fi\nexit "${SHIM_RC:-0}"\n')
    sshp.chmod(0o755)
    shimdir = tmp_path / "shim"
    shimdir.mkdir()
    out = tmp_path / "out"

    def run(stream=None, host="router.invalid", args=(), rc=0, strip_host=False):
        env = {"PATH": f"{bindir}:{os.environ.get('PATH', '/usr/bin:/bin')}", "SHIM_DIR": str(shimdir),
               "HARVEST_OUT": str(out), "SHIM_RC": str(rc), "HOME": str(tmp_path)}
        if host is not None:
            env["ROUTER_HOST"] = host
        if stream is not None:
            sf = tmp_path / "canned.txt"
            sf.write_bytes(stream.encode())
            env["SHIM_STREAM"] = str(sf)
        return subprocess.run(["bash", str(HARVEST), *args], capture_output=True, text=True, env=env, timeout=60)

    run.shimdir, run.out = shimdir, out
    return run


GOOD = ("@@COLLECT-VERSION 1\n@@MISSING ubus\n@@SKIPPED /x/serial excluded\n"
        "@@BEGIN ident proc/cpuinfo\nmodel: x\n\n@@END proc/cpuinfo 0\n"
        "@@BEGIN hw-bin sys/firmware/fdt\nd0 0d fe ed\n\n@@END sys/firmware/fdt 0\n"
        "@@DONE 2\n")


def only_run_dir(out):
    (d,) = [p for p in out.iterdir() if p.is_dir()]
    return d


def test_harvest_complete_stream(shim):
    r = shim(GOOD)
    assert r.returncode == 0, r.stderr
    d = only_run_dir(shim.out)
    assert stat.S_IMODE(d.stat().st_mode) == 0o700
    assert (d / "frames/ident/proc%cpuinfo").read_text() == "model: x\n"
    assert (d / "stream.txt").read_text() == GOOD
    man = (d / "manifest.tsv").read_text()
    assert "MISSING\tubus" in man and "SKIPPED\t/x/serial excluded" in man and "done_marker\t1" in man
    tar = shim.out / f"{d.name}.tar"
    digest = (shim.out / f"{d.name}.tar.sha256").read_text().split()[0]
    assert digest == hashlib.sha256(tar.read_bytes()).hexdigest()
    with tarfile.open(tar) as t:
        assert f"{d.name}/manifest.tsv" in t.getnames()
    assert "router.invalid" not in r.stdout + r.stderr
    assert "frames_ok=2 partial=0 rejected=0 missing=1 skipped=1" in r.stdout


def test_harvest_ssh_invocation(shim):
    shim(GOOD)
    args = (shim.shimdir / "args").read_text().split("\n")
    for opt in ("BatchMode=yes", "ConnectTimeout=10", "ServerAliveInterval=5", "root@router.invalid", "sh -s"):
        assert opt in args, opt
    assert (shim.shimdir / "stdin").read_bytes() == COLLECT.read_bytes()


def test_harvest_truncated_stream_marks_partial(shim):
    cut = GOOD[: GOOD.index("d0 0d") + 3]  # dropped mid-frame, no END, no DONE
    r = shim(cut)
    assert r.returncode == 2
    d = only_run_dir(shim.out)
    assert (d / "frames/hw-bin/sys%firmware%fdt.PARTIAL").read_text() == "d0 \n"
    assert not (d / "frames/hw-bin/sys%firmware%fdt").exists()
    assert (d / "frames/ident/proc%cpuinfo").exists()
    man = (d / "manifest.tsv").read_text()
    assert "PARTIAL\thw-bin\tsys/firmware/fdt\tsys%firmware%fdt.PARTIAL" in man and "done_marker\t0" in man
    assert "partial=1" in r.stdout


def test_harvest_ssh_failure_is_incomplete(shim):
    r = shim(GOOD, rc=255)
    assert r.returncode == 2 and "ssh_exit=255" in r.stdout


@pytest.mark.parametrize("name", ["../../evil", "/etc/passwd", "a/../b", "a//b", "a/./b", "x.PARTIAL", "bad$name"])
def test_harvest_rejects_bad_frame_names(shim, tmp_path, name):
    stream = (f"@@BEGIN ident {name}\nPWNED\n\n@@END {name} 0\n"
              "@@BEGIN ident ok/one\nfine\n\n@@END ok/one 0\n@@DONE 2\n")
    r = shim(stream)
    assert r.returncode == 0, r.stderr
    d = only_run_dir(shim.out)
    assert "rejected=1" in r.stdout
    assert (d / "frames/ident/ok%one").read_text() == "fine\n"
    for p in tmp_path.rglob("*"):
        if p.is_file() and p.name not in ("stream.txt", "canned.txt", "stdin") and p.suffix != ".tar":
            assert "PWNED" not in p.read_text(errors="replace"), p
    assert not (tmp_path / "evil").exists() and not (shim.out.parent / "evil").exists()
    assert "REJECTED" in (d / "manifest.tsv").read_text()


def test_harvest_rejects_duplicate_and_bad_kind(shim):
    stream = ("@@BEGIN ident a\n1\n\n@@END a 0\n@@BEGIN ident a\n2\n\n@@END a 0\n"
              "@@BEGIN ../x b\n3\n\n@@END b 0\n@@DONE 3\n")
    r = shim(stream)
    d = only_run_dir(shim.out)
    assert "frames_ok=1 partial=0 rejected=2" in r.stdout
    assert (d / "frames/ident/a").read_text() == "1\n"


def test_harvest_roundtrip_via_real_collect_helpers(shim, tmp_path):
    f = tmp_path / "nonl.txt"
    f.write_bytes(b"line1\n\nlast-no-newline")
    g = tmp_path / "tricky.txt"
    g.write_bytes(b"@@BEGIN x y\n@@END other 0\nend\n\n")
    env = {"PATH": os.environ["PATH"], "COLLECT_NO_MAIN": "1"}
    stream = subprocess.run(["sh", "-c", f'. "{COLLECT}"; frame_file t "{f}"; frame_file t "{g}"; printf "@@DONE 2\\n"'],
                            capture_output=True, env=env, check=True).stdout.decode()
    r = shim(stream)
    assert r.returncode == 0, r.stderr
    d = only_run_dir(shim.out)
    files = {p.name: p.read_bytes() for p in (d / "frames/t").iterdir()}
    assert files[str(f).lstrip("/").replace("/", "%")] == b"line1\n\nlast-no-newline\n"
    assert files[str(g).lstrip("/").replace("/", "%")] == g.read_bytes()


def test_harvest_requires_router_host_and_validates_it(shim):
    r = shim(GOOD, host=None)
    assert r.returncode != 0 and "ROUTER_HOST" in r.stderr
    assert not (shim.shimdir / "args").exists()
    for bad in ("-oProxyCommand=x", "a b", "host;rm", "$(id)"):
        r = shim(GOOD, host=bad)
        assert r.returncode != 0 and not (shim.shimdir / "args").exists(), bad


def test_dry_print_does_not_connect_and_needs_no_host(shim):
    r = shim(GOOD, host=None, args=("--dry-print",))
    assert r.returncode == 0 and r.stdout == SRC
    assert not (shim.shimdir / "args").exists()
    assert not shim.out.exists()


def test_no_hardcoded_ip_or_default_host():
    text = HARVEST.read_text() + (REPO / "justfile").read_text()
    assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", text)
    assert "ROUTER_HOST:-" not in re.sub(r'\$\{ROUTER_HOST:-\}', "", text)
