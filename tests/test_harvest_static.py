"""Static ALLOWLIST analysis of scripts/remote/collect.sh.

Anything that is not explicitly allowed fails: every external command invocation must match an exact allowed
form, every frame_cmd/frame_fn call is pinned, redirections are limited to exact forms, and /dev/ may only appear
as /dev/null or as the modem-node globs that are only ever stat-ed. Adding a command means editing this file.
"""
import re

import pytest

from conftest import REPO

COLLECT = REPO / "scripts" / "remote" / "collect.sh"
HARVEST = REPO / "scripts" / "harvest.sh"
SRC = COLLECT.read_text()

PH = "\x01"

# Redirections that are allowed (exact forms only; /dev/null must be followed by a non-name character).
REDIR_OK = [
    r"2>&1",
    r"2?>\s*/dev/null(?![\w./*-])",
    r"<\s*/dev/null(?![\w./*-])",
    r'<\s*"\$MODULES_FILE"',
    r'<\s*"/proc/\$mo_p/comm"',
    r'<\s*"/proc/\$pt_p/comm"',
    r'<\s*"\$ct_f"',
]

DEV_OK = {"/dev/null", "/dev/ttyUSB*", "/dev/ttyACM*", "/dev/cdc-wdm*", "/dev/wwan*", "/dev/mhi*"}

# External commands, exact form at command position (after stripping $TMO and allowed redirections).
ALLOWED_EXTERNAL = {
    "cat /proc/sys/kernel/random/uuid",
    "date +%s",
    'readlink -f "$ff_p"',
    'ls -lnL "$ff_p"',
    'od -An -v -tx1 "$ff_p"',
    "od -An -tx1 /dev/null",
    """hexdump -v -e '16/1 "%02x " "\\n"' "$ff_p\"""",
    """hexdump -v -e '16/1 "%02x " "\\n"' /dev/null""",
    'head -c "$MAXBYTES" "$ff_p"',
    'cat "$ff_p"',
    'ls -l "$mp_d"',
    'readlink "$mo_f"',
    "busybox --list",
    "grep -E '^(od|hexdump|timeout|head|readlink|ls|netstat|logread|lsmod|modinfo|dmesg)$'",
}

# Shell builtins in their allowed forms (fullmatch).
BUILTIN_OK = [
    r"\[ .+ \]",
    r"return( \d+)?",
    r"continue|break|:",
    r"printf .+",
    r"read -r \w+( \w+)?",
    r"set -- \$ff_l",
    r"shift( \d+)?",
    r"export PATH LC_ALL",
    r"command -v (\"\$1\"|\"\$pc_c\"|[a-z]+)",
]

EXPECTED_FRAME_CMD = sorted([
    "frame_cmd config cmd/ls-config ls -l /etc/config",
    'frame_cmd hw "${hp_d#/}/driver.link" readlink "$hp_d/driver"',
    "frame_cmd hw cmd/ls-gpio ls -l /sys/class/gpio",
    "frame_cmd hw cmd/ls-leds ls -l /sys/class/leds",
    "frame_cmd hw cmd/ls-pci ls -l /sys/bus/pci/devices",
    "frame_cmd hw cmd/ls-usb ls -l /sys/bus/usb/devices",
    "frame_cmd ident cmd/uname uname -a",
    'frame_cmd kernel "cmd/modinfo/$km_m" modinfo "$km_m"',
    "frame_cmd kernel cmd/dmesg dmesg",
    "frame_cmd kernel cmd/ls-lib-modules ls -lR /lib/modules",
    "frame_cmd kernel cmd/lsmod lsmod",
    "frame_cmd probe cmd/uname uname -a",
    'frame_cmd sys "cmd/ls${cs_d}" ls -l "$cs_d"',
    "frame_cmd sys cmd/logread logread",
    "frame_cmd sys cmd/ls-init ls -l /etc/init.d /etc/rc.d",
    "frame_cmd sys cmd/netstat netstat -lntup",
    "frame_cmd sys cmd/ls-crontabs ls -l /etc/crontabs",
    "frame_cmd sys cmd/ubus-call-system-board ubus call system board",
    "frame_cmd sys cmd/ubus-list ubus -v list",
])

EXPECTED_FRAME_FN = sorted([
    "frame_fn modem cmd/modem-owners modem_owners",
    "frame_fn modem cmd/modem-ports modem_ports",
    "frame_fn sys cmd/crontabs-filtered crontab_filtered",
    "frame_fn sys cmd/proc-comm proc_comm_table",
    "frame_fn probe cmd/busybox-list probe_busybox",
    "frame_fn probe cmd/command-v probe_commands",
])

FORBIDDEN_WORDS = [
    "rm", "mv", "cp", "tee", "dd", "mkdir", "mount", "umount", "opkg", "uci", "fw_setenv", "reboot", "poweroff",
    "halt", "sysupgrade", "insmod", "modprobe", "rmmod", "chmod", "chown", "ln", "touch", "sed", "awk", "wget",
    "curl", "nc", "ssh", "stty", "microcom", "socat", "gpioset", "sysctl", "kill", "killall", "pkill", "ifdown",
    "ifup", "ps", "wifi", "iwpriv", "firstboot", "jffs2reset", "eval", "exec", "trap",
]


def logical_lines(src):
    src = src.replace("\\\n", " ")
    return [l for l in src.splitlines() if l.strip() and not l.lstrip().startswith("#")]


def _strip_redirs(text):
    for pat in REDIR_OK:
        text = re.sub(pat, "", text)
    return text


def _protect(line, store):
    def rep(m):
        store.append(m.group(0))
        return f"{PH}{len(store) - 1}{PH}"

    return re.sub(r"'[^']*'|\"(?:[^\"\\]|\\.)*\"", rep, line)


def _restore(text, store):
    return re.sub(PH + r"(\d+)" + PH, lambda m: store[int(m.group(1))], text)


def segments(lines):
    """Yield normalized command segments (restored text) from logical lines."""
    for line in lines:
        store = []
        t = _protect(_strip_redirs(line), store)
        t = re.sub(r"^\s*case\s+\S+\s+in\b\s*", "", t)
        t = re.sub(r"^\s*\w+\(\)\s*\{?\s*", "", t)  # function definition
        t = re.sub(r"^\s*[^\s()]+\)\s*", "", t)  # case label
        t = re.sub(r"\$\(\([^()]*\)\)", "X", t)
        subs = []
        while True:
            m = re.search(r"\$\(([^()]*)\)", t)
            if not m:
                break
            subs.append(m.group(1))
            t = t[: m.start()] + "X" + t[m.end():]
        for piece in [t] + subs:
            for seg in re.split(r";|&&|\|\||\|", piece):
                seg = re.sub(r"\s+", " ", seg).strip()
                seg = re.sub(r"^(?:(?:if|elif|while|until|then|do|else|!|\{)(?:\s+|$))+", "", seg)
                seg = re.sub(r"^\$TMO(?:\s+|$)", "", seg)
                seg = re.sub(r"^(?:\w+=\S*\s*)+", "", seg)
                if seg:
                    yield _restore(seg, store)


def analyze(src):
    problems = []
    lines = logical_lines(src)
    code = "\n".join(lines)
    if "`" in code:
        problems.append("backtick command substitution")
    left = _strip_redirs(code)
    if re.search(r"[<>]", left):
        problems.append("redirection other than the exact allowed forms")
    for tok in re.findall(r"/dev/[^\s\"';)|&<>]*", code):
        if tok not in DEV_OK:
            problems.append(f"/dev path not allowed: {tok}")
    for word in FORBIDDEN_WORDS:
        if re.search(rf"(?<![\w./$-]){re.escape(word)}(?![\w./-])", code):
            problems.append(f"forbidden word: {word}")
    if re.search(r"(?<!/proc/)cmdline|/proc/[^\s\"']*/cmdline", code):
        problems.append("per-process command lines must never be collected")
    if "/etc/crontabs/" in code:
        problems.append("crontab contents must only be read through crontab_filtered")
    if re.search(r"\bset\s+-[a-zA-Z]*e", code):
        problems.append("set -e")
    funcs = set(re.findall(r"^\s*(\w+)\(\)", code, re.M))
    cmds, fns = [], []
    for seg in segments(lines):
        first = seg.split()[0]
        if first in ("for", "in", "fi", "done", "esac", "}", ";;"):
            continue
        if seg in ('"$@"', '"$3"'):
            continue
        if first in funcs:
            if first == "frame_cmd":
                cmds.append(seg)
            elif first == "frame_fn":
                fns.append(seg)
            continue
        if any(re.fullmatch(p, seg) for p in BUILTIN_OK):
            continue
        if seg in ALLOWED_EXTERNAL:
            continue
        problems.append(f"command not allowed: {seg}")
    if sorted(cmds) != EXPECTED_FRAME_CMD:
        problems.append(f"frame_cmd list differs: {sorted(set(cmds) ^ set(EXPECTED_FRAME_CMD))}")
    if sorted(fns) != EXPECTED_FRAME_FN:
        problems.append(f"frame_fn list differs: {sorted(set(fns) ^ set(EXPECTED_FRAME_FN))}")
    return problems


def test_collect_passes_the_allowlist():
    assert analyze(SRC) == []


MUTATIONS = [
    "/bin/rm x",
    "ubus -S call network.interface down",
    'd=/dev/ttyUSB2\ncat "$d"',
    "dmesg -c",
    "logread -f",
    "echo x >/dev/null.x",
    "frame_cmd sys cmd/x ubus -S call network.interface down",
    "frame_cmd kernel cmd/dmesg-c dmesg -c",
    "frame_cmd sys cmd/lf logread -f",
    "frame_cmd sys cmd/send ubus send x",
    "$CMD x",
    "FOO=1 rm x",
    "eval x",
    "x=`id`",
    "x=$(ifdown wan)",
    "set -e",
    "cat /etc/shadow",
    'cat "$d" >/tmp/x',
    'cat "$d" > /dev/ttyUSB2',
    "read -r x < /dev/ttyUSB2",
    "kill 1",
    "wifi down",
    "reboot",
    "frame_fn sys cmd/x something",
    "ps w",
    "frame_cmd sys cmd/ps ps w",
    'cat "/proc/$p/cmdline"',
    "frame_file sys /proc/1/cmdline",
    "frame_cmd sys cmd/cron cat /etc/crontabs/root",
    "frame_file sys /etc/crontabs/root",
]


@pytest.mark.parametrize("mutation", MUTATIONS)
def test_mutation_is_rejected(mutation):
    assert analyze(SRC + "\n" + mutation + "\n"), mutation


def test_mutation_inside_a_function_body_is_rejected():
    assert analyze(SRC.replace("  return 0\n}\n\n# Owners", "  return 0\n  dmesg -c\n}\n\n# Owners", 1))


def test_no_bashisms_and_no_local_state():
    code = "\n".join(logical_lines(SRC))
    for bad in ("[[", "local ", "<(", ">(", "<<", "declare ", "=(", "${!", "source ", "function "):
        assert bad not in code, bad


def test_reads_are_capped_and_timeboxed():
    assert 'TMO="timeout 10"' in SRC and "command -v timeout" in SRC
    body = SRC.split("frame_cmd() {", 1)[1].split("\n}\n", 1)[0]
    assert '$TMO "$@"' in body
    assert 'head -c "$MAXBYTES"' in SRC
    assert re.search(r"^export .*LC_ALL", SRC, re.M)


def test_frames_are_nonce_authenticated():
    assert "/proc/sys/kernel/random/uuid" in SRC
    assert "@@END-%s" in SRC and "@@DONE-%s" in SRC and "@@COLLECT-VERSION 2 %s" in SRC


def test_tag_and_stop_command_documented():
    assert "glinet-harvest-collect" in SRC
    text = HARVEST.read_text()
    assert "pkill -f 'sh -s glinet-harvest-collect'" in text
    assert "ServerAliveCountMax=3" in text and "timeout -k 10" in text
    assert re.search(r"^export LC_ALL=C", text, re.M)


def test_no_per_process_cmdline_and_no_ps():
    code = "\n".join(logical_lines(SRC))
    assert not re.search(r"(?<!/proc/)cmdline", code), "only the kernel /proc/cmdline may be read"
    assert not re.search(r"/proc/[^\s\"']*/cmdline", code)
    assert not re.search(r"\bps\b", code)


def test_crontabs_only_through_the_filter_and_logs_are_opt_in():
    code = "\n".join(logical_lines(SRC))
    assert "/etc/crontabs/" not in code and not re.search(r"\bcat\b[^\n]*crontab", code)
    flt = code.split("crontab_filtered() {", 1)[1].split("\n}\n", 1)[0]
    for needle in ("Pp][Aa][Ss][Ss", "Pp][Ww][Dd", "Ss][Ee][Cc][Rr][Ee][Tt", "Tt][Oo][Kk][Ee][Nn", "Kk][Ee][Yy",
                   "Aa][Uu][Tt][Hh", "Uu][Ss][Ee][Rr", '"-u "', '"-p "', "://"):
        assert needle in flt, needle
    assert re.search(r'if \[ -n "\$COLLECT_LOGS" \]; then\n\s+frame_cmd sys cmd/logread logread', code)
    assert "COLLECT_LOGS=1) COLLECT_LOGS=1" in code
