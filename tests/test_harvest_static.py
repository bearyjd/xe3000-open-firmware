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

# External commands: exact form at command position -> (functions they may appear in, must be prefixed by $TMO).
# None stands for the top level of the script.
HEXFMT = """'16/1 "%02x " "\\n"'"""
ALLOWED_EXTERNAL = {
    "cat /proc/sys/kernel/random/uuid": ({None}, False),
    "date +%s": ({None}, False),
    'readlink -f "$cn_p"': ({"canon_safe"}, True),
    'ls -lnL "$ff_p"': ({"frame_file"}, True),
    'od -An -v -tx1 "$ff_p"': ({"frame_file"}, True),
    f'hexdump -v -e {HEXFMT} "$ff_p"': ({"frame_file"}, True),
    'head -c "$MAXBYTES" "$ff_p"': ({"frame_file"}, True),
    'cat "$ff_p"': ({"frame_file"}, True),
    "od -An -tx1 /dev/null": ({"detect_hex"}, True),
    f"hexdump -v -e {HEXFMT} /dev/null": ({"detect_hex"}, True),
    'ls -l "$mp_d"': ({"modem_ports"}, True),
    'readlink "$mo_f"': ({"modem_owners"}, True),
    "busybox --list": ({"probe_busybox"}, False),
    "grep -E '^(od|hexdump|timeout|head|readlink|ls|netstat|logread|lsmod|modinfo|dmesg)$'": ({"probe_busybox"}, False),
}

# Assignments whose value is pinned (raw text after the '=').
PINNED_ASSIGN = {
    "TMO": {"timeout 10", ""},
    "ff_p": {"$2"},
    "PATH": {"/usr/sbin:/usr/bin:/sbin:/bin"},
    "FDT": {"/sys/firmware/fdt"},
    "MODULES_FILE": {"/proc/modules"},
    "SYSMODULE": {"/sys/module"},
    "CRONDIR": {"/etc/crontabs"},
    "HEX": {"od", "hexdump", ""},
}

# Literal absolute paths in `for ... in` lists may only live under these.
LIST_PREFIXES = ("/proc/", "/sys/", "/etc/", "/lib/modules")

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

EXPECTED_FILE_CALLS = sorted([
    'frame_file "$1" "$2" "$3"',
    "frame_file hw /sys/kernel/debug/gpio",
    'frame_file hw-bin "$FDT" hex',
    'frame_file ident "$ci_f"',
    'opt_file config "$cc_f"',
    'opt_file hw "$hh_a"',
    'opt_file hw "$hl_d/$hl_a"',
    'opt_file hw "$hp_d/$hp_a"',
    'opt_file hw "$hs_a"',
    'opt_file hw "$ht_d/$ht_a"',
    'opt_file hw "$hu_d/$hu_a"',
    'opt_file hw-dt "$dt_p" hex',
    "opt_file ident /etc/glversion",
    "opt_file ident /etc/openwrt_release",
    'opt_file kernel "$SYSMODULE/$km_m/$km_a"',
    'opt_file kernel "$km_a"',
    'opt_file sys "$cs_f"',
    'opt_file sys "$cs_f"',
    'opt_file sys "$cs_f"',
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
    "curl", "nc", "ssh", "stty", "microcom", "socat", "gpioset", "sysctl", "kill", "killall", "ifdown",
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

    return re.sub(r"'[^']*'|\"(?:[^\"\\]|\\.)*\"|\\.", rep, line)


def _restore(text, store):
    return re.sub(PH + r"(\d+)" + PH, lambda m: store[int(m.group(1))], text)


class Seg:
    def __init__(self, text, tmo, func, assigns, line):
        self.text, self.tmo, self.func, self.assigns, self.line = text, tmo, func, assigns, line


def _balanced_subs(text):
    """Contents of every outermost $(...) in text (paren-balanced, so nested substitutions stay inside their parent;
    an unbalanced one runs to the end). $(( is arithmetic: skipped, but substitutions inside it are still found.
    Backtick bodies are returned as well."""
    out, i = [], 0
    while i < len(text):
        if text.startswith("$((", i):
            i += 3
        elif text.startswith("$(", i):
            depth, j = 1, i + 2
            while j < len(text) and depth:
                depth += (text[j] == "(") - (text[j] == ")")
                j += 1
            out.append(text[i + 2: j - 1 if depth == 0 else j])
            i = j
        else:
            i += 1
    return out + re.findall(r"`([^`]*)`", text)


def _segs(text, func, line, top):
    """Yield Seg objects for one logical line; command substitutions are analysed recursively, including the ones
    inside double-quoted strings."""
    store = []
    t = _protect(_strip_redirs(text), store)
    if top:
        t = re.sub(r"^\s*case\s+\S+\s+in\b\s*", "", t)
        t = re.sub(r"^\s*\w+\(\)\s*\{?\s*", "", t)  # function definition
        t = re.sub(r"^\s*[^\s()]+\)\s*", "", t)  # case label
    t = re.sub(r"\$\(\([^()]*\)\)", "X", t)
    subs = []
    while True:
        m = re.search(r"\$\(([^()]*)\)", t)
        if not m:
            break
        subs.append(_restore(m.group(1), store))
        t = t[: m.start()] + "X" + t[m.end():]
    for item in store:
        if item.startswith('"'):
            subs.extend(_balanced_subs(item))
    for piece in re.split(r";|&&|\|\||\|", t):
        seg = re.sub(r"\s+", " ", piece).strip()
        seg = re.sub(r"^(?:(?:if|elif|while|until|then|do|else|!|\{)(?:\s+|$))+", "", seg)
        tmo = bool(re.match(r"^\$TMO(?:\s+|$)", seg))
        seg = re.sub(r"^\$TMO(?:\s+|$)", "", seg)
        assigns = []
        while True:
            m = re.match(r"^(\w+)=(\S*)\s*", seg)
            if not m:
                break
            val = _restore(m.group(2), store)
            if len(val) >= 2 and val[0] == val[-1] == '"':
                val = val[1:-1]  # quoted literal (SC2209); pinned value must still match exactly
            assigns.append((m.group(1), val))
            seg = seg[m.end():]
        seg = _restore(seg, store)
        if assigns or seg:
            yield Seg(seg, tmo, func, assigns, line)
    for sub in subs:
        yield from _segs(sub, func, line, False)


def iter_segments(lines):
    func = None
    for line in lines:
        m = re.match(r"^(\w+)\(\)", line)
        if m:
            func = m.group(1)
        yield from _segs(line, func, line, True)
        if line.strip() == "}":
            func = None


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
    cmds, fns, files = [], [], []
    for sg in iter_segments(lines):
        for name, val in sg.assigns:
            if name in PINNED_ASSIGN and val not in PINNED_ASSIGN[name]:
                problems.append(f"assignment not allowed: {name}={val}")
            if name == "TMO" and "command -v timeout" not in sg.line:
                problems.append("TMO may only be assigned on its defining line")
            if name == "ff_p" and sg.func != "frame_file":
                problems.append("ff_p may only be assigned inside frame_file")
        seg = sg.text
        if not seg:
            continue
        first = seg.split()[0]
        if first == "for":
            for w in seg.split():
                if w.startswith("/") and not (w.startswith(LIST_PREFIXES) or w in DEV_OK):
                    problems.append(f"path not allowed in loop list: {w}")
            continue
        if first in ("in", "fi", "done", "esac", "}", ";;"):
            continue
        if seg == '"$@"':
            if not (sg.func == "frame_cmd" and sg.tmo):
                problems.append('"$@" is only allowed as `$TMO "$@"` inside frame_cmd')
            continue
        if seg == '"$3"':
            if sg.func != "frame_fn":
                problems.append('"$3" is only allowed inside frame_fn')
            continue
        if first in funcs:
            {"frame_cmd": cmds, "frame_fn": fns, "frame_file": files, "opt_file": files}.get(first, []).append(seg)
            continue
        if any(re.fullmatch(p, seg) for p in BUILTIN_OK):
            continue
        if seg in ALLOWED_EXTERNAL:
            allowed_funcs, needs_tmo = ALLOWED_EXTERNAL[seg]
            if sg.func not in allowed_funcs:
                problems.append(f"command not allowed here ({sg.func}): {seg}")
            elif needs_tmo and not sg.tmo:
                problems.append(f"command must be prefixed by $TMO: {seg}")
            continue
        problems.append(f"command not allowed: {seg}")
    if sorted(cmds) != EXPECTED_FRAME_CMD:
        problems.append(f"frame_cmd list differs: {sorted(set(cmds) ^ set(EXPECTED_FRAME_CMD))}")
    if sorted(fns) != EXPECTED_FRAME_FN:
        problems.append(f"frame_fn list differs: {sorted(set(fns) ^ set(EXPECTED_FRAME_FN))}")
    if sorted(files) != EXPECTED_FILE_CALLS:
        problems.append(f"frame_file/opt_file calls differ: {sorted(set(files) ^ set(EXPECTED_FILE_CALLS))}")
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
    '[ -n "$(ubus call network.interface.wan down)" ]',
    "ff_p=$(printf '/%s/ttyUSB2' dev)\ncat \"$ff_p\"",
    "TMO='ubus call x'\n$TMO",
    "TMO=",
    "frame_file sys /sys/class/gpio/export",
    "opt_file sys /sys/class/gpio/unexport",
    '"$@"',
    '"$3"',
    "for x in /home/*; do frame_file sys \"$x\"; done",
    "pkill -f x",
    "pgrep x",
    'x=$(readlink "$mo_f")',
    "ps w",
    "frame_cmd sys cmd/ps ps w",
    'cat "/proc/$p/cmdline"',
    "frame_file sys /proc/1/cmdline",
    "frame_cmd sys cmd/cron cat /etc/crontabs/root",
    "frame_file sys /etc/crontabs/root",
    # nested / doubly nested command substitutions inside double quotes (outer command position must be checked)
    'printf "%s" "$(ubus call network.interface.wan down $(printf x))"',
    'x="$(ubus call network.interface.wan down $(printf x))"',
    'printf "%s" "$(printf "%s" "$(ifdown wan)")"',
    'printf "%s" "$(printf "%s" "$(printf "%s" "$(reboot)")")"',
    'printf "%s" "$(printf x; dmesg -c)"',
    'printf "%s" "$(printf $(printf x) | kill 1)"',
    'printf "%s" "`ifdown wan`"',
    'printf "%s" "`printf $(ifdown wan)`"',
    'printf "%s" "$(( $(ifdown wan) + 1 ))"',
]


@pytest.mark.parametrize("mutation", MUTATIONS)
def test_mutation_is_rejected(mutation):
    """The mutation must introduce at least one NEW problem on top of whatever the unmutated file has."""
    base = set(analyze(SRC))
    assert set(analyze(SRC + "\n" + mutation + "\n")) - base, mutation


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


STOP_OK = "pkill -f '[s]h -s glinet-harvest-collect'"
STOP_BAD = "pkill -f 'sh -s glinet-harvest-collect'"


def test_tag_and_stop_command_documented():
    assert "glinet-harvest-collect" in SRC
    text = HARVEST.read_text()
    assert STOP_OK in text and STOP_OK in SRC  # bracket form: the pkill never matches its own ssh shell
    assert STOP_BAD not in text and STOP_BAD not in SRC
    assert "ServerAliveCountMax=3" in text and "timeout -k 10" in text
    assert re.search(r"^export LC_ALL=C", text, re.M)


def test_prp_uses_the_bracket_stop_command():
    prp = REPO / "docs" / "prp" / "0001-probes.md"
    if not prp.exists():
        pytest.skip("docs/ is not mounted in the test container")
    text = prp.read_text()
    assert STOP_BAD not in text
    if "glinet-harvest-collect" in text:
        assert STOP_OK in text


def test_without_timeout_the_risky_sysfs_reads_are_skipped():
    assert 'if [ -z "$TMO" ]; then' in SRC
    for what in ("/sys/class/hwmon", "/sys/class/thermal", "/sys/class/power_supply", "/sys/kernel/debug/gpio"):
        assert f"skipped {what} no-timeout" in SRC, what


def test_timeout_exit_codes_documented_for_busybox_and_coreutils():
    assert "143" in SRC and "124" in SRC


def test_modem_owner_readlink_is_timeboxed():
    assert 'mo_t=$($TMO readlink "$mo_f"' in SRC


def test_probe_checks_for_pkill_and_pgrep_with_command_v_only():
    body = SRC.split("probe_commands() {", 1)[1].split("\n}\n", 1)[0]
    assert "pkill pgrep" in body and "command -v" in body


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
