"""Phase 2 rootfs inventories: deterministic, offline, counts-only logging."""
import json
import os

import pytest

from conftest import Lazy

inventory = Lazy("recon.inventory")

LUA = (
    "--[[\n    @object-name: fan\n--]]\nlocal M = {}\n"
    "--[[\n    @method-name: set_test\n    @in-example:  {\\\"jsonrpc\\\":\\\"2.0\\\",\\\"params\\\":[\\\"\\\",\\\"fan\\\",\\\"set_test\\\",{}]}\n--]]\n"
    "M.set_test = function(params)\n  utils.writefile('/sys/class/thermal/cooling_device0/cur_state', '0')\nend\n"
    "M.get_status = function(params)\n  return {}\nend\nreturn M\n"
)
ACL = json.dumps({"gl-fan": {"description": "fan", "read": {"ubus": {"fan": ["get_status"]}},
                              "write": {"ubus": {"fan": ["set_test"], "modem": ["*"]}}}}, indent=1)
INITD = "#!/bin/sh /etc/rc.common\nUSE_PROCD=1\nSTART=95\nSTOP=10\nstart_service() {\n  echo 'AT+CFUN=1' > /dev/ttyUSB2\n}\n"
TEXTS = {
    "rootfs/etc/init.d/gl_modem": INITD,
    "rootfs/etc/init.d/early": "START=5\nstart() {\n  insmod mhi_wwan_ctrl\n  echo 12 > /sys/class/gpio/export\n"
                               "  echo out > /sys/class/gpio/gpio12/direction\n  echo 1 > /sys/class/gpio/gpio12/value\n}\n",
    "rootfs/etc/init.d/nostart": "start() {\n  true\n}\n",
    "rootfs/usr/lib/oui-httpd/rpc/fan": LUA,
    "rootfs/usr/share/acl.d/gl-fan.json": ACL,
    "rootfs/usr/lib/lua/oui/ubus.lua": 'local r = ubus:call("system", "board", {})\n',
    "rootfs/usr/bin/helper.sh": "ubus call network.interface.wan status\nmodprobe -q gl_fan_drv\n",
    "rootfs/etc/modules.d/30-wifi": "mt7915e\n# comment\nmt76-connac-lib\n",
    "rootfs/www/js/app.js_extract": 'a.call("modem","get_info");b(["call","sim","get_status"]);',
}


def at_names(inv):
    return set(inv["at-commands"])


def test_at_commands_from_text_with_file_and_line():
    inv = inventory.build(TEXTS)
    assert "AT+CFUN" in at_names(inv)
    hit = inv["at-commands"]["AT+CFUN"][0]
    assert hit["file"] == "rootfs/etc/init.d/gl_modem" and hit["line"] == 6 and hit["via"] == "text"


def test_at_commands_from_binary_strings():
    binaries = {"rootfs/usr/sbin/modem_tool": b"\x7fELF\x00\x00AT+QCFG=\"x\"\x00junk\x00ATI\x00AT^SYSCONFIG?\x00\x01"}
    inv = inventory.build({}, binaries=binaries)
    assert {"AT+QCFG", "AT^SYSCONFIG"} <= at_names(inv)
    assert "ATI" not in at_names(inv)  # short bare commands are noise in binaries
    assert inv["at-commands"]["AT+QCFG"][0]["via"] == "strings"


def test_printable_strings():
    assert inventory.printable_strings(b"\x00ab\x00abcdef\x01gh1234\x00", min_len=4) == ["abcdef", "gh1234"]


def test_rpc_methods_from_all_sources():
    methods = {(m["object"], m["method"]): m for m in inventory.build(TEXTS)["rpc-methods"]["methods"]}
    sources = {m["source"] for m in inventory.build(TEXTS)["rpc-methods"]["methods"]
               if (m["object"], m["method"]) == ("fan", "set_test")}
    assert {"lua-doc", "lua-table", "example", "acl"} <= sources
    assert ("fan", "get_status") in methods  # table entry without a doc header
    acl = [m for m in inventory.build(TEXTS)["rpc-methods"]["methods"] if m["source"] == "acl"]
    assert {(m["object"], m["method"], m["access"]) for m in acl} == {
        ("fan", "get_status", "read"), ("fan", "set_test", "write"), ("modem", "*", "write")}
    assert ("system", "board") in methods and ("network.interface.wan", "status") in methods
    assert ("modem", "get_info") in methods and ("sim", "get_status") in methods


def test_ubus_object_names():
    objs = inventory.build(TEXTS)["rpc-methods"]["objects"]
    assert {"fan", "modem", "system", "network.interface.wan", "sim"} <= set(objs)


def test_invalid_acl_json_is_reported_not_swallowed():
    inv = inventory.build({"rootfs/usr/share/acl.d/bad.json": "{not json"})
    assert inv["rpc-methods"]["parse_errors"] == ["rootfs/usr/share/acl.d/bad.json"]


def test_gpios_and_sysfs_writes():
    gp = inventory.build(TEXTS)["gpios"]
    assert "12" in gp["numbers"] and gp["numbers"]["12"][0]["file"] == "rootfs/etc/init.d/early"
    writes = {(w["gpio"], w["attr"], w["value"]) for w in gp["sysfs_writes"]}
    assert (12, "direction", "out") in writes and (12, "value", "1") in writes


def test_kernel_modules_from_text_modules_d_and_paths():
    inv = inventory.build(TEXTS, paths=["rootfs/lib/modules/5.4.0/gl_extra-drv.ko", "rootfs/etc/hosts"])
    mods = set(inv["kernel-modules"])
    assert {"mhi_wwan_ctrl", "gl_fan_drv", "mt7915e", "mt76_connac_lib", "gl_extra_drv"} <= mods
    assert "comment" not in mods and "hosts" not in mods


def test_initd_order_sorted_by_start_then_stop_reversed():
    order = inventory.build(TEXTS)["initd-order"]
    assert [e["name"] for e in order["start"]] == ["early", "gl_modem"]
    assert order["start"][1] == {"name": "gl_modem", "start": 95, "stop": 10, "procd": True,
                                 "file": "rootfs/etc/init.d/gl_modem"}
    assert [e["name"] for e in order["stop"]] == ["gl_modem"]
    assert order["unordered"] == ["nostart"]


def test_load_tree_skips_secrets_symlinks_and_oversize(tmp_path):
    root = tmp_path / "rootfs"
    (root / "etc" / "dropbear").mkdir(parents=True)
    (root / "usr" / "sbin").mkdir(parents=True)
    (root / "lib" / "modules").mkdir(parents=True)
    (root / "etc" / "init.d").mkdir(parents=True)
    (root / "etc" / "init.d" / "a").write_text("START=1\n")
    (root / "etc" / "shadow").write_text("root:x:0\n")
    (root / "etc" / "dropbear" / "dropbear_rsa_host_key").write_bytes(b"AT+LEAK\x00")
    (root / "etc" / "server.pem").write_text("AT+PEM\n")
    (root / "etc" / "link").symlink_to(root / "etc" / "shadow")
    (root / "usr" / "sbin" / "tool").write_bytes(b"\x7fELF\x00AT+REAL=1\x00")
    (root / "lib" / "modules" / "x.ko").write_bytes(b"\x7fELF\x00")
    big = root / "etc" / "big.txt"
    big.write_text("x" * (inventory.MAX_TEXT_BYTES + 1))
    tree = inventory.load_tree(root)
    assert set(tree.texts) == {"etc/init.d/a"}
    assert set(tree.binaries) == {"usr/sbin/tool", "lib/modules/x.ko"}
    assert "lib/modules/x.ko" in tree.paths
    assert not any("shadow" in n or "dropbear" in n or ".pem" in n or n.endswith("link") for n in
                   [*tree.texts, *tree.binaries, *tree.paths])
    assert "etc/big.txt" in tree.skipped_oversize


def test_write_all_returns_counts_only(tmp_path):
    inv = inventory.build(TEXTS)
    counts = inventory.write_all(inv, tmp_path / "gt")
    assert set(p.name for p in (tmp_path / "gt").iterdir()) == {
        "at-commands.json", "rpc-methods.json", "gpios.json", "kernel-modules.json", "initd-order.json"}
    assert all(isinstance(v, int) for v in counts.values()) and counts["at-commands"] >= 1
    assert json.loads((tmp_path / "gt" / "at-commands.json").read_text())["AT+CFUN"]


def _repo(tmp_path):
    root = tmp_path / "repo"
    for sub in ("harvest/raw", "harvest/redacted", "unpacked/stock/rootfs/etc/init.d"):
        (root / sub).mkdir(parents=True)
    (root / "unpacked/stock/rootfs/etc/init.d/gl_modem").write_text(INITD)
    return root


def test_main_logs_counts_only_and_writes_under_findings_raw(tmp_path, capsys):
    root = _repo(tmp_path)
    assert inventory.main(["--root", str(root), "--tree", "unpacked/stock/rootfs"]) == 0
    out = capsys.readouterr().out
    assert "at-commands: 1" in out and "AT+CFUN" not in out and "gl_modem" not in out
    assert (root / "findings/raw/ground-truth/at-commands.json").exists()


@pytest.mark.parametrize("tree", ["harvest/raw", "../elsewhere"])
def test_main_refuses_raw_and_outside_trees(tmp_path, capsys, tree):
    root = _repo(tmp_path)
    assert inventory.main(["--root", str(root), "--tree", tree]) == 2
    assert "refused" in capsys.readouterr().err
    assert not (root / "findings/raw/ground-truth").exists()


def test_main_accepts_the_build_staging_tree_for_binary_strings(tmp_path, capsys):
    root = _repo(tmp_path)
    sbin = root / "build/unpack/stock/rootfs/usr/sbin"
    sbin.mkdir(parents=True)
    (sbin / "modem_tool").write_bytes(b"\x7fELF\x00AT+QCFG=1\x00")
    assert inventory.main(["--root", str(root), "--tree", "build/unpack/stock/rootfs"]) == 0
    assert "at-commands: 1" in capsys.readouterr().out
    doc = json.loads((root / "findings/raw/ground-truth/at-commands.json").read_text())
    assert doc["AT+QCFG"][0]["file"] == "build/unpack/stock/rootfs/usr/sbin/modem_tool"


def _raw_symlinked_build(tmp_path):
    root = _repo(tmp_path)
    (root / "harvest/raw/etc/init.d").mkdir(parents=True)
    (root / "harvest/raw/etc/init.d/x").write_text("echo AT+RAWLEAK\n")
    (root / "build").symlink_to(root / "harvest/raw")
    return root


@pytest.mark.parametrize("tree", ["build", "harvest/raw", "build/etc"])
def test_main_refuses_raw_even_when_build_is_a_symlink_to_it(tmp_path, capsys, tree):
    root = _raw_symlinked_build(tmp_path)
    assert inventory.main(["--root", str(root), "--tree", tree]) == 2
    assert "refused" in capsys.readouterr().err
    assert not (root / "findings/raw/ground-truth").exists()


def test_main_accepts_only_build_unpack_not_all_of_build(tmp_path, capsys):
    root = _repo(tmp_path)
    (root / "build/other").mkdir(parents=True)
    (root / "build/other/f").write_bytes(b"AT+NOPE\x00")
    assert inventory.main(["--root", str(root), "--tree", "build/other"]) == 2
    assert not (root / "findings/raw/ground-truth").exists()


def test_main_refuses_build_unpack_symlinked_outside_build(tmp_path, capsys):
    root = _repo(tmp_path)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "f").write_bytes(b"AT+NOPE\x00")
    (root / "build").mkdir()
    (root / "build/unpack").symlink_to(outside)
    assert inventory.main(["--root", str(root), "--tree", "build/unpack"]) == 2
    assert not (root / "findings/raw/ground-truth").exists()


def test_main_does_not_read_a_hardlink_into_harvest_raw(tmp_path, capsys):
    root = _repo(tmp_path)
    raw = root / "harvest/raw/etc/init.d"
    raw.mkdir(parents=True)
    (raw / "m").write_text("echo AT+RAWLEAK\n")
    os.link(raw / "m", root / "unpacked/stock/rootfs/etc/init.d/m")
    rc = inventory.main(["--root", str(root), "--tree", "unpacked/stock/rootfs"])
    written = root / "findings/raw/ground-truth/at-commands.json"
    leaked = written.exists() and "AT+RAWLEAK" in written.read_text()
    assert not leaked
    assert rc in (0, 2)
    assert "AT+RAWLEAK" not in capsys.readouterr().out
