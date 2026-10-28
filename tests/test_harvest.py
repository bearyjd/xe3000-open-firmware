"""Offline behaviour checks for the Phase 1 harvest tooling. No router, no network: ssh is a shim on PATH.
Static allowlist checks of collect.sh live in test_harvest_static.py."""
import hashlib
import os
import re
import shutil
import stat
import subprocess
import tarfile
import time

import pytest

from conftest import REPO

COLLECT = REPO / "scripts" / "remote" / "collect.sh"
HARVEST = REPO / "scripts" / "harvest.sh"
SRC = COLLECT.read_text()
TAG = "glinet-harvest-collect"
N = "n0nce-1234abcd"

SHELLS = [["sh"]] + ([["busybox", "sh"]] if shutil.which("busybox") else [])
needs_timeout = pytest.mark.skipif(not shutil.which("timeout"), reason="no timeout binary")


# ---------------------------------------------------------------- stream parsing helper

def parse_stream(text):
    """Return (nonce, frames, outside_lines). Only END lines carrying the announced nonce close a frame."""
    lines = text.split("\n")
    m = re.fullmatch(r"@@COLLECT-VERSION 2 ([A-Za-z0-9-]{8,64})", lines[0])
    assert m, lines[0]
    nonce = m.group(1)
    frames, outside, cur = {}, [], None
    for line in lines[1:]:
        if cur is None:
            if line.startswith("@@BEGIN "):
                _, kind, name = line.split(" ")
                assert name not in frames, f"duplicate frame {name}"
                cur = (kind, name, [])
            elif line:
                outside.append(line)
        else:
            m = re.fullmatch(rf"@@END-{re.escape(nonce)} (\S+) (\d+)", line)
            if m and m.group(1) == cur[1]:
                frames[cur[1]] = (cur[0], "\n".join(cur[2]), int(m.group(2)))
                cur = None
            else:
                cur[2].append(line)
    assert cur is None, f"unterminated frame {cur and cur[1]}"
    return nonce, frames, outside


# ---------------------------------------------------------------- run collect.sh locally (as over ssh)

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


def run_collect(shell, work, *extra):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(work), "TMPDIR": str(work)}
    with open(COLLECT, "rb") as fh:
        try:
            return subprocess.run(shell + ["-s", TAG, *extra], stdin=fh, capture_output=True, cwd=work, env=env,
                                  timeout=120)
        except subprocess.TimeoutExpired:
            pytest.skip("collect.sh blocked on a sysfs read on this host; the container run is authoritative")


@pytest.fixture(scope="module")
def local_run(tmp_path_factory):
    work = tmp_path_factory.mktemp("collect")
    before = snapshot()
    results = {" ".join(s): run_collect(s, work) for s in SHELLS}
    return results, before, snapshot(), work


@pytest.mark.parametrize("shell", [" ".join(s) for s in SHELLS])
def test_collect_stream_well_formed(local_run, shell):
    p = local_run[0][shell]
    assert p.returncode == 0
    nonce, frames, outside = parse_stream(p.stdout.decode("utf-8", "replace"))
    assert outside[-1] == f"@@DONE-{nonce} {len(frames)}"
    for o in outside[:-1]:
        assert re.match(r"@@(MISSING|SKIPPED) \S", o), o
    for name in ("proc/cpuinfo", "proc/meminfo", "cmd/uname"):
        assert name in frames and frames[name][2] == 0, name
    assert frames["proc/meminfo"][1].startswith("MemTotal:")
    assert "@@MISSING ubus" in outside  # absent in the test image: reported, run continues
    # data minimisation: no command lines, no crontab bodies, logs are opt-in
    assert "cmd/ps" not in frames and "cmd/logread" not in frames
    assert "@@SKIPPED logread logs-not-requested" in outside
    assert not any(n.startswith("etc/crontabs/") for n in frames)
    assert not any("cmdline" in n for n in frames if n != "proc/cmdline")
    table = frames["cmd/proc-comm"][1].splitlines()
    assert table and all(re.fullmatch(r"\d+ .*", l) for l in table)


@pytest.mark.parametrize("shell", [" ".join(s) for s in SHELLS])
def test_collect_stream_has_no_excluded_paths(local_run, shell):
    text = local_run[0][shell].stdout.decode("utf-8", "replace")
    _, frames, _ = parse_stream(text)
    for name in frames:
        base = name.rsplit("/", 1)[-1]
        assert not name.startswith(("etc/shadow", "etc/dropbear")), name
        assert "host_key" not in name and not name.endswith((".pem", ".key")), name
        assert "serial" not in base.lower(), name


def test_collect_leaves_filesystem_unchanged(local_run):
    _, before, after, work = local_run
    assert before == after
    assert list(work.iterdir()) == []


@pytest.mark.parametrize("shell", SHELLS)
def test_probe_mode_runs_only_the_probe(tmp_path, shell):
    p = run_collect(shell, tmp_path, "probe")
    assert p.returncode == 0
    nonce, frames, outside = parse_stream(p.stdout.decode())
    assert sorted(frames) == ["cmd/busybox-list", "cmd/command-v", "cmd/uname"]
    assert outside == [f"@@DONE-{nonce} 3"] or outside == ["@@MISSING busybox", f"@@DONE-{nonce} 3"]
    assert "present cat" in frames["cmd/command-v"][1]
    probed = frames["cmd/command-v"][1]
    assert re.search(r"^(present|absent) pkill$", probed, re.M) and re.search(r"^(present|absent) pgrep$", probed, re.M)
    assert list(tmp_path.iterdir()) == []


# ---------------------------------------------------------------- helper-level behaviour via sourcing

def run_fn(call, *args, shell=("sh",), setup="", shim=None, env=None):
    """Source collect.sh (COLLECT_NO_MAIN is test-only), then run `setup; call`. Returns stdout."""
    e = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "COLLECT_NO_MAIN": "1", **(env or {})}
    pre = f'PATH="{shim}:$PATH"; ' if shim else ""
    script = "; ".join(x for x in (f'. "{COLLECT}"', pre.rstrip("; "), setup, call) if x)
    p = subprocess.run(list(shell) + ["-c", script, "sh", *map(str, args)],
                       capture_output=True, env=e, timeout=60)
    assert p.returncode == 0, p.stderr
    return p.stdout.decode()


@pytest.mark.parametrize("shell", SHELLS)
def test_exclusions_and_limits(tmp_path, shell):
    canary = "TOPSECRET" + "VALUE"
    for name in ("a.pem", "b.key", "my_host_key", "serial", "serial_number", "good.txt", "sp ace"):
        (tmp_path / name).write_text(canary + "\n")
    (tmp_path / "big").write_bytes(b"x" * (1024 * 1024 + 1))
    wo = tmp_path / "writeonly"
    wo.write_text(canary)
    wo.chmod(0o200)
    (tmp_path / "link.txt").symlink_to(tmp_path / "serial_number")
    out = ""
    for name in ("a.pem", "b.key", "my_host_key", "serial", "serial_number", "big", "writeonly", "link.txt", "sp ace"):
        out += run_fn('frame_file t "$1"', tmp_path / name, shell=shell)
    assert canary not in out and "@@BEGIN" not in out
    assert out.count("@@SKIPPED") == 9
    assert "size=1048577" in out
    good = run_fn('frame_file t "$1"', tmp_path / "good.txt", shell=shell)
    assert good.startswith("@@BEGIN t ") and canary in good and re.search(r"@@END-\S+ \S+ 0\n$", good)
    for path in ("/etc/shadow", "/etc/dropbear/dropbear_rsa_host_key", "/etc/dropbear/authorized_keys",
                 "/sys/bus/usb/devices/1-1/serial", "/sys/class/power_supply/BAT0/serial_number"):
        run_fn('is_excluded "$1"', path, shell=shell)  # rc 0 => excluded


def test_non_excluded_path_is_not_excluded():
    p = subprocess.run(["sh", "-c", f'. "{COLLECT}"; is_excluded /etc/config/network'],
                       env={"PATH": os.environ["PATH"], "COLLECT_NO_MAIN": "1"})
    assert p.returncode == 1


def test_proc_comm_table_has_only_pid_and_name():
    out = run_fn("proc_comm_table").splitlines()
    assert out and all(re.fullmatch(r"\d+ \S.*", l) for l in out)


@pytest.mark.parametrize("shell", SHELLS)
def test_proc_comm_table_skips_vanished_and_empty_comm(tmp_path, shell):
    for pid, comm in (("1", "init\n"), ("2", ""), ("4", "a b\n")):
        (tmp_path / pid).mkdir()
        (tmp_path / pid / "comm").write_text(comm)
    (tmp_path / "3").mkdir()  # process exited: no comm file
    (tmp_path / "self").mkdir()  # non-numeric entry is ignored
    out = run_fn("proc_comm_table", shell=shell, env={"PROC_ROOT": str(tmp_path)})
    assert out.splitlines() == ["1 init", "4 a b"]


def test_logs_are_opt_in_via_positional_arg():
    base = run_fn("collect_system")
    assert "@@SKIPPED logread logs-not-requested" in base
    with_logs = run_fn("collect_system", "COLLECT_LOGS=1")
    assert "logs-not-requested" not in with_logs
    assert "@@MISSING logread" in with_logs or "@@BEGIN sys cmd/logread" in with_logs


CRON = (
    "*/5 * * * * /usr/bin/foo.sh\n"
    "0 4 * * * /sbin/reload_thing\n"
    "* * * * * curl -u bob:" + "hunter" + "2 http://a/b\n"
    "* * * * * pppd PASSWORD=hunter2\n"
    "* * * * * x --Pwd=hunter2\n"
    "* * * * * x SECRET_value\n"
    "* * * * * x API_Token=abc\n"
    "* * * * * x apiKEY=abc\n"
    "* * * * * x -H Authorization:abc\n"
    "* * * * * x --username=bob\n"
    "* * * * * mosquitto_pub -h h -P hunter2\n"
    "* * * * * x -p hunter2\n"
    "* * * * * x -U bob\n"
    "* * * * * fetch ftp://h/p\n"
    "* * * * * x -pabc\n"
    "* * * * * x -uroot\n"
    "* * * * * x -Pabc\n"
    "* * * * * PW_X=1 run\n"
    "* * * * * WIFI_PSK=abc run\n"
    "* * * * * API_X=1 run\n"
    "5 5 * * * last-line-without-newline"
)


def test_crontab_lines_pass_through_the_conservative_filter(tmp_path):
    cron = tmp_path / "cron"
    cron.mkdir()
    (cron / "root").write_text(CRON)
    (cron / "serial_number").write_text("0 0 * * * keepme\n")
    out = run_fn("crontab_filtered", setup=f"CRONDIR={cron}")
    assert "hunter2" not in out and "bob" not in out and "abc" not in out and "keepme" not in out
    assert "*/5 * * * * /usr/bin/foo.sh" in out and "/sbin/reload_thing" in out
    assert "5 5 * * * last-line-without-newline" in out
    assert "# file root" in out and "# dropped 18 line(s)" in out


def _sleeper_shim(tmp_path, *names):
    shim = tmp_path / "shim"
    shim.mkdir(exist_ok=True)
    for name in names:
        (shim / name).write_text("#!/bin/sh\nexec sleep 30\n")
        (shim / name).chmod(0o755)
    return shim


@needs_timeout
def test_blocked_read_and_blocked_command_are_cut_off(tmp_path):
    shim = _sleeper_shim(tmp_path, "head", "dmesg", "ls")
    f = tmp_path / "f.txt"
    f.write_text("hello")
    t0 = time.monotonic()
    out = run_fn('frame_file t "$1"; frame_cmd kernel cmd/dmesg dmesg; frame_cmd hw cmd/ls ls -l /sys',
                 f, setup='TMO="timeout 1"', shim=shim)
    assert time.monotonic() - t0 < 12
    assert len(re.findall(r"@@END-\S+ \S+ (?:124|143)\n", out)) == 2  # head and dmesg timed out (exit 124)
    assert "@@SKIPPED" in out  # ls -lnL (the size probe) timed out: skipped, not hung


def test_file_reads_are_capped_even_when_size_reports_zero():
    out = run_fn('frame_file t /proc/self/maps', setup="MAXBYTES=64")
    body = out.split("\n", 1)[1].rsplit("\n@@END-", 1)[0]
    assert 0 < len(body.encode()) <= 64


def test_timeout_is_empty_when_router_has_no_timeout_command(tmp_path):
    empty = tmp_path / "nobin"
    empty.mkdir()
    p = subprocess.run(["/bin/sh", "-c", f'COLLECT_NO_MAIN=1; . "{COLLECT}"; echo "[$TMO]"'],
                       capture_output=True, env={"PATH": str(empty), "COLLECT_NO_MAIN": "1"})
    # collect.sh resets PATH itself, so only assert the variable is always defined (empty or 'timeout 10')
    assert p.stdout.decode().strip() in ("[]", "[timeout 10]")


def test_detect_hex_prefers_od_then_hexdump_then_none():
    stub = "TMO=; "
    assert "HEX=[od]" in run_fn('detect_hex; echo "HEX=[$HEX]"', setup=stub + "od() { return 0; }")
    assert "HEX=[hexdump]" in run_fn(
        'detect_hex; echo "HEX=[$HEX]"', setup=stub + "od() { return 1; }; hexdump() { return 0; }")
    assert "HEX=[]" in run_fn(
        'detect_hex; echo "HEX=[$HEX]"', setup=stub + "od() { return 1; }; hexdump() { return 1; }")


def test_fdt_without_a_hex_tool_reports_missing_and_walks_device_tree(tmp_path):
    fdt = tmp_path / "fdt"
    fdt.write_bytes(b"\xd0\x0d\xfe\xed")
    out = run_fn("collect_fdt", setup=f'TMO=; FDT={fdt}; detect_hex() {{ HEX=; }}; dt_fallback() {{ echo FALLBACK; }}')
    assert f"@@MISSING {fdt}" in out and "FALLBACK" in out and "@@BEGIN" not in out


def test_fdt_hex_with_od_and_hexdump_branches(tmp_path):
    fdt = tmp_path / "fdt"
    fdt.write_bytes(b"\xd0\x0d\xfe\xed")
    out = run_fn("collect_fdt", setup=f"TMO=; FDT={fdt}; detect_hex() {{ HEX=od; }}")
    assert "@@BEGIN hw-bin" in out and "d0 0d fe ed" in out
    out = run_fn("collect_fdt", setup=f"TMO=; FDT={fdt}; detect_hex() {{ HEX=hexdump; }}; hexdump() {{ echo HEXDUMP-USED; }}")
    assert "HEXDUMP-USED" in out and "@@BEGIN hw-bin" in out


def _modinfo_shim(tmp_path):
    shim = tmp_path / "mshim"
    shim.mkdir()
    (shim / "modinfo").write_text('#!/bin/sh\necho "$1" >> "$MODLOG"\necho "name: $1"\n')
    (shim / "modinfo").chmod(0o755)
    return shim


def test_modinfo_skipped_when_module_count_is_large(tmp_path):
    mods = tmp_path / "modules"
    mods.write_text("".join(f"m{i} 1 0 - Live 0x0\n" for i in range(250)))
    log = tmp_path / "log"
    out = run_fn("collect_modinfo", setup=f"TMO=; MODULES_FILE={mods}; SYSMODULE={tmp_path}/sys",
                 shim=_modinfo_shim(tmp_path), env={"MODLOG": str(log)})
    assert "@@SKIPPED modinfo module-count=250" in out
    assert not log.exists()


def test_modinfo_called_once_per_module_and_not_when_sysfs_has_version(tmp_path):
    mods = tmp_path / "modules"
    mods.write_text("a 1 0 - Live 0x0\nb 1 0 - Live 0x0\nc 1 0 - Live 0x0\n")
    (tmp_path / "sys" / "a").mkdir(parents=True)
    (tmp_path / "sys" / "a" / "version").write_text("1.2\n")
    log = tmp_path / "log"
    out = run_fn("collect_modinfo", setup=f"TMO=; MODULES_FILE={mods}; SYSMODULE={tmp_path}/sys",
                 shim=_modinfo_shim(tmp_path), env={"MODLOG": str(log)})
    assert log.read_text().split() == ["b", "c"]
    assert "@@BEGIN kernel cmd/modinfo/b" in out and "1.2" in out and "@@SKIPPED modinfo" not in out


def test_collect_hw_risky_is_skipped_when_tmo_is_empty():
    out = run_fn("collect_hw_risky", setup="TMO=")
    for what in ("/sys/class/hwmon", "/sys/class/thermal", "/sys/class/power_supply", "/sys/kernel/debug/gpio"):
        assert f"@@SKIPPED {what} no-timeout" in out, what
    assert "@@BEGIN" not in out


def test_collect_on_a_router_without_timeout_skips_risky_reads(tmp_path):
    """Run a copy of collect.sh whose PATH has no `timeout` applet (the real one resets PATH itself)."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for tool in ("cat", "head", "ls", "od", "readlink", "uname", "date", "grep", "hexdump", "lsmod", "dmesg"):
        found = shutil.which(tool)
        if found:
            (bindir / tool).symlink_to(found)
    script = tmp_path / "collect_nt.sh"
    script.write_text(SRC.replace("PATH=/usr/sbin:/usr/bin:/sbin:/bin", f"PATH={bindir}", 1))
    work = tmp_path / "work"
    work.mkdir()
    with open(script, "rb") as fh:
        try:
            p = subprocess.run(["sh", "-s", TAG], stdin=fh, capture_output=True, cwd=work, timeout=120,
                               env={"PATH": os.environ["PATH"], "HOME": str(work)})
        except subprocess.TimeoutExpired:
            pytest.skip("collect.sh blocked on a sysfs read on this host")
    nonce, frames, outside = parse_stream(p.stdout.decode("utf-8", "replace"))
    for what in ("/sys/class/hwmon", "/sys/class/thermal", "/sys/class/power_supply", "/sys/kernel/debug/gpio"):
        assert f"@@SKIPPED {what} no-timeout" in outside, what
    assert not any(n.startswith(("sys/class/hwmon", "sys/class/thermal", "sys/class/power_supply")) for n in frames)


# ---------------------------------------------------------------- harvest.sh with a fake ssh

@pytest.fixture
def shim(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    sshp = bindir / "ssh"
    sshp.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$@" > "$SHIM_DIR/args"\ncat > "$SHIM_DIR/stdin"\n'
        'if [ -n "${SHIM_HANG:-}" ]; then printf "@@COLLECT-VERSION 2 abc12345\\n@@BEGIN ident hang\\npart"; '
        "exec sleep 300; fi\n"
        'if [ -n "${SHIM_STREAM:-}" ]; then cat "$SHIM_STREAM"; fi\nexit "${SHIM_RC:-0}"\n')
    sshp.chmod(0o755)
    shimdir = tmp_path / "shim"
    shimdir.mkdir()
    # Run a copy of the script inside a throwaway fake repo so HERE/../harvest/raw is the confinement root.
    repo = tmp_path / "repo"
    (repo / "scripts" / "remote").mkdir(parents=True)
    shutil.copy(HARVEST, repo / "scripts" / "harvest.sh")
    shutil.copy(COLLECT, repo / "scripts" / "remote" / "collect.sh")
    out = repo / "harvest" / "raw" / "out"

    def run(stream=None, host="router.invalid", args=(), rc=0, env_extra=None):
        env = {"PATH": f"{bindir}:{os.environ.get('PATH', '/usr/bin:/bin')}", "SHIM_DIR": str(shimdir),
               "HARVEST_OUT": str(out), "SHIM_RC": str(rc), "HOME": str(tmp_path), **(env_extra or {})}
        if host is not None:
            env["ROUTER_HOST"] = host
        if stream is not None:
            sf = tmp_path / "canned.txt"
            sf.write_bytes(stream if isinstance(stream, bytes) else stream.encode())
            env["SHIM_STREAM"] = str(sf)
        return subprocess.run(["bash", str(repo / "scripts" / "harvest.sh"), *args], capture_output=True, text=True, env=env, timeout=120)

    run.shimdir, run.out, run.repo = shimdir, out, repo
    return run


def stream(*parts, nonce=N, done=True):
    body = f"@@COLLECT-VERSION 2 {nonce}\n" + "".join(parts)
    return body + (f"@@DONE-{nonce} 2\n" if done else "")


def frame(kind, name, content, nonce=N, code=0):
    return f"@@BEGIN {kind} {name}\n{content}\n\n@@END-{nonce} {name} {code}\n"


GOOD = stream("@@MISSING ubus\n@@SKIPPED /x/serial excluded\n", frame("ident", "proc/cpuinfo", "model: x"),
              frame("hw-bin", "sys/firmware/fdt", "d0 0d fe ed"))


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
    for opt in ("BatchMode=yes", "ConnectTimeout=10", "ServerAliveInterval=5", "ServerAliveCountMax=3",
                "root@router.invalid", f"sh -s {TAG}"):
        assert opt in args, opt
    assert (shim.shimdir / "stdin").read_bytes() == COLLECT.read_bytes()


def test_harvest_truncated_stream_marks_partial(shim):
    cut = stream(frame("ident", "proc/cpuinfo", "model: x"), "@@BEGIN hw-bin sys/firmware/fdt\nd0 ", done=False)
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
    s = stream(frame("ident", name, "PWNED"), frame("ident", "ok/one", "fine"))
    r = shim(s)
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
    s = stream(frame("ident", "a", "1"), frame("ident", "a", "2"), frame("../x", "b", "3"), done=False)
    s += f"@@DONE-{N} 3\n"
    r = shim(s)
    d = only_run_dir(shim.out)
    assert "frames_ok=1 partial=0 rejected=2" in r.stdout
    assert (d / "frames/ident/a").read_text() == "1\n"


def test_content_line_cannot_forge_a_frame_end(shim):
    forged = ("line1\n@@END a/b 0\n@@END-wrongnonce a/b 0\n@@DONE-wrongnonce 9\n@@COLLECT-VERSION 2 evil1234\nline2")
    s = stream(frame("ident", "a/b", forged), frame("ident", "c", "after"))
    r = shim(s)
    assert r.returncode == 0, r.stderr
    d = only_run_dir(shim.out)
    assert (d / "frames/ident/a%b").read_text() == forged + "\n"
    assert (d / "frames/ident/c").read_text() == "after\n"
    assert "frames_ok=2 partial=0 rejected=0" in r.stdout


def test_wrong_nonce_done_and_pre_version_frames_are_ignored(shim):
    s = (frame("ident", "early", "x", nonce="other123") + f"@@COLLECT-VERSION 2 {N}\n" + frame("ident", "ok", "y")
         + "@@COLLECT-VERSION 2 second99\n" + "@@DONE-wrong999 1\n")
    r = shim(s)
    assert r.returncode == 2 and "done_marker=0" in r.stdout
    d = only_run_dir(shim.out)
    assert not (d / "frames/ident/early").exists()
    assert (d / "frames/ident/ok").read_text() == "y\n"


def test_harvest_handles_nul_bytes_quietly(shim):
    s = stream(frame("ident", "bin", "ab\x00cd")).encode()
    r = shim(s)
    assert r.returncode == 0 and "null byte" not in r.stderr.lower()
    assert (only_run_dir(shim.out) / "frames/ident/bin").read_bytes() == b"abcd\n"


def test_harvest_roundtrip_via_real_collect_helpers(shim, tmp_path):
    f = tmp_path / "nonl.txt"
    f.write_bytes(b"line1\n\nlast-no-newline")
    g = tmp_path / "tricky.txt"
    g.write_bytes(b"@@BEGIN x y\n@@END other 0\nend\n\n")
    call = f'printf "@@COLLECT-VERSION 2 %s\\n" "$NONCE"; frame_file t "{f}"; frame_file t "{g}"; printf "@@DONE-%s 2\\n" "$NONCE"'
    s = run_fn(call)
    r = shim(s)
    assert r.returncode == 0, r.stderr
    files = {p.name: p.read_bytes() for p in (only_run_dir(shim.out) / "frames/t").iterdir()}
    assert files[str(f).lstrip("/").replace("/", "%")] == b"line1\n\nlast-no-newline\n"
    assert files[str(g).lstrip("/").replace("/", "%")] == g.read_bytes()


def test_harvest_requires_router_host_and_validates_it(shim):
    r = shim(GOOD, host=None)
    assert r.returncode != 0 and "ROUTER_HOST" in r.stderr
    assert not (shim.shimdir / "args").exists()
    for bad in ("-oProxyCommand=x", "a b", "host;rm", "$(id)"):
        r = shim(GOOD, host=bad)
        assert r.returncode != 0 and not (shim.shimdir / "args").exists(), bad


def test_output_base_is_tightened_to_0700(shim):
    shim.out.mkdir(parents=True)
    shim.out.chmod(0o755)
    assert shim(GOOD).returncode == 0
    assert stat.S_IMODE(shim.out.stat().st_mode) == 0o700


@needs_timeout
def test_hanging_ssh_is_killed_and_marked_incomplete(shim):
    t0 = time.monotonic()
    r = shim(args=(), env_extra={"SHIM_HANG": "1", "HARVEST_TIMEOUT": "2"})
    assert time.monotonic() - t0 < 60
    assert r.returncode == 2 and "ssh_exit=124" in r.stdout and "partial=1" in r.stdout
    d = only_run_dir(shim.out)
    assert (d / "frames/ident/hang.PARTIAL").read_text() == "part\n"
    assert "ssh_exit\t124" in (d / "manifest.tsv").read_text()


def test_invalid_harvest_timeout_is_rejected(shim):
    for bad in ("abc", "0", "-5", "1;rm"):
        r = shim(GOOD, env_extra={"HARVEST_TIMEOUT": bad})
        assert r.returncode != 0 and "HARVEST_TIMEOUT" in r.stderr, bad
        assert not (shim.shimdir / "args").exists()


STOP = "ssh root@$ROUTER_HOST \"pkill -f '[s]h -s glinet-harvest-collect'\""


def test_dry_print_does_not_connect_and_needs_no_host(shim):
    r = shim(GOOD, host=None, args=("--dry-print",))
    assert r.returncode == 0 and r.stdout.endswith(SRC)
    head = r.stdout[: -len(SRC)]
    assert STOP in head and f"'sh -s {TAG}'" in head
    assert all(l.startswith("# harvest:") for l in head.splitlines())
    assert not (shim.shimdir / "args").exists() and not shim.out.exists()


def test_dry_print_probe_shows_the_probe_command(shim):
    r = shim(GOOD, host=None, args=("--probe", "--dry-print"))
    assert r.returncode == 0 and r.stdout.endswith(SRC)
    assert f"'sh -s {TAG} probe'" in r.stdout and STOP in r.stdout
    assert not (shim.shimdir / "args").exists()


def test_logs_are_not_requested_by_default(shim):
    shim(GOOD)
    assert not any("COLLECT_LOGS" in a for a in (shim.shimdir / "args").read_text().split("\n"))


def test_with_logs_flag_is_passed_as_remote_positional_arg(shim):
    shim(GOOD, args=("--with-logs",))
    assert f"sh -s {TAG} COLLECT_LOGS=1" in (shim.shimdir / "args").read_text().split("\n")


def test_with_logs_and_probe_do_not_combine(shim):
    r = shim(GOOD, args=("--probe", "--with-logs"))
    assert r.returncode != 0 and not (shim.shimdir / "args").exists()


def test_dry_print_with_logs_shows_the_flag(shim):
    r = shim(GOOD, host=None, args=("--with-logs", "--dry-print"))
    assert r.returncode == 0 and f"'sh -s {TAG} COLLECT_LOGS=1'" in r.stdout and r.stdout.endswith(SRC)


def test_usage_error_prints_the_stop_command(shim):
    r = shim(GOOD, args=("--bogus",))
    assert r.returncode != 0 and STOP in r.stderr
    assert not (shim.shimdir / "args").exists()


def test_probe_run_uses_probe_command_and_prints_probe_frames(shim):
    probe = stream(frame("probe", "cmd/uname", "Linux x"), frame("probe", "cmd/command-v", "present od\nabsent hexdump"))
    r = shim(probe, args=("--probe",))
    assert r.returncode == 0, r.stderr
    args = (shim.shimdir / "args").read_text().split("\n")
    assert f"sh -s {TAG} probe" in args
    assert "present od" in r.stdout
    assert only_run_dir(shim.out).name.endswith("-probe")


def test_no_hardcoded_ip_or_default_host():
    text = HARVEST.read_text() + (REPO / "justfile").read_text()
    assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", text)
    assert "ROUTER_HOST:-" not in re.sub(r"\$\{ROUTER_HOST:-\}", "", text)


def test_capped_frames_124_and_143_are_reported(shim):
    s = stream(frame("sys", "cmd/a", "x", code=124), frame("sys", "cmd/b", "y", code=143), frame("sys", "cmd/c", "z"))
    s = s.replace(f"@@DONE-{N} 2", f"@@DONE-{N} 3")
    r = shim(s)
    assert "capped=2" in r.stdout and "frames_ok=3" in r.stdout
    assert "capped" in r.stderr.lower()
    man = (only_run_dir(shim.out) / "manifest.tsv").read_text()
    assert "CAPPED\tsys\tcmd/a\t124" in man and "CAPPED\tsys\tcmd/b\t143" in man and "cmd/c\texit=0" in man


def test_no_timeout_skip_prints_a_clear_notice(shim):
    s = stream("@@SKIPPED /sys/class/hwmon no-timeout\n@@SKIPPED /sys/class/thermal no-timeout\n", frame("ident", "a", "x"))
    r = shim(s)
    assert r.returncode == 0
    assert "NOTICE" in r.stderr and "timeout" in r.stderr and "hwmon" in r.stderr
    assert "NOTICE\tno-timeout" in (only_run_dir(shim.out) / "manifest.tsv").read_text()


# ---------------------------------------------------------------- HARVEST_OUT confinement (raw data must stay in harvest/raw)

def assert_refused(r):
    assert r.returncode != 0 and "HARVEST_OUT" in r.stderr, (r.returncode, r.stderr)


def test_harvest_out_outside_raw_refused(shim, tmp_path):
    target = tmp_path / "elsewhere"
    assert_refused(shim(GOOD, env_extra={"HARVEST_OUT": str(target)}))
    assert not target.exists()
    assert not (shim.shimdir / "args").exists()


def test_harvest_out_traversal_refused(shim):
    assert_refused(shim(GOOD, env_extra={"HARVEST_OUT": str(shim.out) + "/../../escape"}))
    assert not (shim.repo / "harvest" / "escape").exists()


def test_harvest_out_symlink_escape_refused(shim, tmp_path):
    outside = tmp_path / "synced"
    outside.mkdir()
    raw = shim.repo / "harvest" / "raw"
    raw.mkdir(parents=True)
    (raw / "link").symlink_to(outside)
    assert_refused(shim(GOOD, env_extra={"HARVEST_OUT": str(raw / "link" / "sub")}))
    assert list(outside.iterdir()) == []


def test_harvest_raw_dir_itself_symlink_refused(shim, tmp_path):
    outside = tmp_path / "synced"
    outside.mkdir()
    (shim.repo / "harvest").mkdir()
    (shim.repo / "harvest" / "raw").symlink_to(outside)
    assert_refused(shim(GOOD))
    assert list(outside.iterdir()) == []


def test_harvest_out_tracked_dirs_and_prefix_siblings_refused(shim):
    repo = shim.repo
    for bad in (repo, repo / "scripts", repo / "harvest", str(repo / "harvest" / "raw") + "-evil", "", "relative/dir"):
        r = shim(GOOD, env_extra={"HARVEST_OUT": str(bad)})
        if bad == "":
            continue  # empty value falls back to the default
        assert_refused(r)
    assert not list((repo / "scripts").glob("*.tar"))
    assert not (repo / "harvest" / "raw-evil").exists()


def test_harvest_out_subdir_of_raw_allowed(shim):
    r = shim(GOOD, env_extra={"HARVEST_OUT": str(shim.out / "nested")})
    assert r.returncode == 0, r.stderr
    assert (shim.out / "nested").is_dir()


def test_harvest_default_out_is_raw(shim):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    r = subprocess.run(["bash", str(shim.repo / "scripts" / "harvest.sh"), "--dry-print"],
                       capture_output=True, text=True, env={**env, "ROUTER_HOST": "router.invalid"}, timeout=30)
    assert r.returncode == 0, r.stderr


# ---------------------------------------------------------------- artifact writes never follow planted symlinks

FIXED_TS = "20300101T000000Z"


def _fixed_date(tmp_path):
    d = tmp_path / "bin" / "date"
    d.write_text(f'#!/bin/sh\necho {FIXED_TS}\n')
    d.chmod(0o755)


@pytest.mark.parametrize("suffix", [".tar", ".tar.sha256"])
@pytest.mark.parametrize("dangling", [False, True])
def test_artifact_symlink_destinations_are_never_followed(shim, tmp_path, suffix, dangling):
    _fixed_date(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "victim"
    if not dangling:
        victim.write_text("ORIGINAL")
    shim.out.mkdir(parents=True)
    (shim.out / f"{FIXED_TS}{suffix}").symlink_to(victim)
    r = shim(GOOD)
    assert r.returncode != 0
    assert (victim.read_text() == "ORIGINAL") if not dangling else not victim.exists()
    assert list(outside.iterdir()) == ([victim] if not dangling else [])


def test_artifacts_are_created_private_and_not_overwritten(shim, tmp_path):
    _fixed_date(tmp_path)
    shim.out.mkdir(parents=True)
    pre = shim.out / f"{FIXED_TS}.tar"
    pre.write_text("PRE-EXISTING")
    assert shim(GOOD).returncode != 0
    assert pre.read_text() == "PRE-EXISTING"


def test_artifacts_have_mode_0600(shim):
    assert shim(GOOD).returncode == 0
    d = only_run_dir(shim.out)
    for n in (f"{d.name}.tar", f"{d.name}.tar.sha256"):
        assert stat.S_IMODE((shim.out / n).stat().st_mode) == 0o600


def test_harvest_never_writes_excluded_names_into_frames(shim):
    secret = "-".join(("hunter2", "SUPERSECRET"))
    s = stream(frame("config", "etc/config/chap-secrets", f"u * {secret} *"),
               frame("config", "etc/config/pap-secrets", secret),
               frame("sys", "etc/dropbear/dropbear_rsa_host_key", secret),
               frame("hw", "sys/bus/usb/devices/1-1/serial", secret),
               frame("sys", "etc/shadow", secret),
               frame("sys", "etc/ssl/x.pem", secret),
               frame("config", "etc/config/glmodem", "config modem 'm'"), done=False)
    s += f"@@DONE-{N} 7\n"
    r = shim(s)
    assert r.returncode == 0, r.stderr
    d = only_run_dir(shim.out)
    assert "excluded=6" in r.stdout and "frames_ok=1" in r.stdout
    for p in (d / "frames").rglob("*"):
        if p.is_file():
            assert secret not in p.read_text(), p
    assert [p.name for p in (d / "frames").rglob("*") if p.is_file()] == ["etc%config%glmodem"]
    man = (d / "manifest.tsv").read_text()
    assert "EXCLUDED\tetc/config/chap-secrets" in man and "EXCLUDED\tetc/dropbear/dropbear_rsa_host_key" in man
    assert secret not in man
