"""External PTY/private-ubus seam; no substitute parser, headers, or ubus."""
import json
import os
from pathlib import Path
import pty
import pwd
import hashlib
import subprocess
import tempfile
import time

import pytest
from conftest import Lazy

mcu = Lazy('mcu_offline')

FIXTURE = Path(os.environ.get("MCU_NATIVE_FIXTURE", str(
    Path(__file__).resolve().parents[1] / "build/mcu-offline-20261101")))


class Daemon:
    def __init__(self, model):
        self.temp = tempfile.TemporaryDirectory(prefix="mcu-")
        self.socket = Path(self.temp.name) / "bus.sock"
        self.master, self.slave = pty.openpty()
        self.env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LD_LIBRARY_PATH": str(FIXTURE / "prefix/lib")}
        acl = Path(self.temp.name) / "acl"
        acl.mkdir()
        (acl / "battery.json").write_text(json.dumps({"user": pwd.getpwuid(os.getuid()).pw_name,
            "publish": ["battery"], "access": {"battery": {"methods": ["info"]}}}))
        self.log = tempfile.TemporaryFile()
        self.bus = subprocess.Popen([str(FIXTURE / "prefix/sbin/ubusd"), "-s", str(self.socket), "-A", str(acl)],
                                    env=self.env, stdout=self.log, stderr=self.log)
        for _ in range(100):
            if self.socket.exists():
                break
            time.sleep(.01)
        self.process = subprocess.Popen([str(FIXTURE / f"model-{model}/gl-puli-mcu"),
                                         "-d", os.ttyname(self.slave), "-s", str(self.socket)],
                                        env=self.env, stdout=self.log, stderr=self.log)

    def status(self):
        result = subprocess.run([str(FIXTURE / "prefix/bin/ubus"), "-s", str(self.socket),
                                 "call", "battery", "info"], env=self.env, capture_output=True,
                                text=True, timeout=2)
        if result.returncode:
            return None
        return json.loads(result.stdout)

    def expect(self, expected, timeout=1):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            actual = self.status()
            if actual == expected:
                return
            time.sleep(.01)
        self.log.seek(0)
        assert actual == expected, self.log.read().decode(errors="replace")

    def send(self, data):
        os.write(self.master, data)

    def close(self):
        for proc in (self.process, self.bus):
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
        os.close(self.master)
        os.close(self.slave)
        self.log.close()
        self.temp.cleanup()


@pytest.fixture
def daemon(request):
    if not (FIXTURE / "fixture.json").is_file():
        if "MCU_NATIVE_FIXTURE" in os.environ:
            pytest.fail("Explicit MCU_NATIVE_FIXTURE is missing its verified native fixture")
        pytest.skip("Verified native MCU fixture missing; run scripts/mcu_offline.py --checkout PINNED_CHECKOUT")
    artifacts, digest, CANDIDATE = mcu.artifacts, mcu.digest, mcu.CANDIDATE
    fixture = json.loads((FIXTURE / "fixture.json").read_text())
    assert fixture["source_manifest_sha256"] == digest(CANDIDATE / "source.json")
    patches = sorted((CANDIDATE / "patches").glob("*.patch"))
    assert fixture["patches"] == {p.name: digest(p) for p in patches}, "Stale candidate fixture"
    assert fixture["dependency_marker_sha256"] == digest(FIXTURE / "dependencies.json")
    assert json.loads((FIXTURE / "dependencies.json").read_text())["artifacts"] == artifacts(FIXTURE / "prefix")
    assert fixture["binaries"] == {str(p.relative_to(FIXTURE)): digest(p) for p in
                                  [FIXTURE / "model-1/gl-puli-mcu", FIXTURE / "model-2/gl-puli-mcu"]}
    instance = Daemon(getattr(request, "param", 2))
    try:
        yield instance
    finally:
        instance.close()


VALID = b'{"code":0,"capacity":73,"temp":28,"chg_state":1,"charge_cycle":42}\n'
STATUS = {"soc": 73, "temperature": 28, "charging": 1, "cycles": 42}


def test_startup_and_status(daemon):
    daemon.expect({"error": 1})
    daemon.send(VALID)
    daemon.expect(STATUS)


def test_reject_out_of_range_soc(daemon):
    daemon.expect({"error": 1})
    daemon.send(VALID.replace(b'"capacity":73', b'"capacity":256'))
    time.sleep(.05)
    daemon.expect({"error": 1})


@pytest.mark.parametrize("bad", [
    VALID.replace(b'"capacity":73', b'"capacity":-1'),
    VALID.replace(b'"chg_state":1', b'"chg_state":2'),
    VALID.replace(b'"charge_cycle":42', b'"charge_cycle":65536'),
    VALID.replace(b'"charge_cycle":42', b'"charge_cycle":-1'),
    VALID.replace(b'"temp":28', b'"temp":2147483648'),
    VALID.replace(b'"temp":28', b'"temp":-2147483649'),
    VALID.replace(b'"temp":28', b'"temp":999999999999999999999999'),
    VALID.replace(b'"code":0,', b'"code":0x'),
    VALID.replace(b'}\n', b'garbage\n'),
    VALID.replace(b'}\n', b'\n'),
    VALID.replace(b'}\n', b'}extra\n'),
    VALID.replace(b'73,', b'73x'),
    VALID.replace(b'28,', b'28.5,'),
    VALID.replace(b'}\n', b'}\x00junk\n'),
])
def test_invalid_frame_is_atomic(daemon, bad):
    daemon.expect({"error": 1})
    daemon.send(VALID)
    daemon.expect(STATUS)
    daemon.send(bad)
    time.sleep(.04)
    daemon.expect(STATUS)


@pytest.mark.parametrize("wire, expected", [
    (VALID.replace(b'73', b'0').replace(b':28', b':-2147483648').replace(b':42', b':0'),
     {"soc": 0, "temperature": -2147483648, "charging": 1, "cycles": 0}),
    (VALID.replace(b'73', b'100').replace(b':28', b':2147483647').replace(b':42', b':65535').replace(b'"chg_state":1', b'"chg_state":0'),
     {"soc": 100, "temperature": 2147483647, "charging": 0, "cycles": 65535}),
])
def test_numeric_boundaries(daemon, wire, expected):
    daemon.expect({"error": 1})
    daemon.send(wire)
    daemon.expect(expected)


def test_fragmented_coalesced_crlf_and_oversized_recovery(daemon):
    daemon.expect({"error": 1})
    daemon.send(VALID[:25])
    time.sleep(.04)
    daemon.expect({"error": 1})
    daemon.send(VALID[25:].replace(b'\n', b'\r\n'))
    daemon.expect(STATUS)
    daemon.send(b'x' * 8192 + b'\n' + VALID.replace(b'73', b'55') + VALID.replace(b'73', b'19'))
    daemon.expect(dict(STATUS, soc=19))


def test_stale_and_malformed_does_not_refresh(daemon):
    daemon.expect({"error": 1})
    daemon.send(VALID)
    daemon.expect(STATUS)
    time.sleep(8)
    daemon.send(VALID.replace(b'"charge_cycle":42', b'"charge_cycle":-1'))
    time.sleep(2.15)
    daemon.expect({"error": 1})
    daemon.send(VALID)
    daemon.expect(STATUS)


@pytest.mark.parametrize("daemon", [1], indirect=True)
def test_xe300_regression_and_cross_model(daemon):
    daemon.expect({"error": 1})
    daemon.send(VALID)
    time.sleep(.04)
    daemon.expect({"error": 1})
    daemon.send(b'{OK},88,275,0,65535\n')
    daemon.expect({"soc": 88, "temperature": 27.5, "charging": 0, "cycles": 65535})
    daemon.send(b'{OK},88,275,0,65536\n')
    time.sleep(.04)
    daemon.expect({"soc": 88, "temperature": 27.5, "charging": 0, "cycles": 65535})


def test_xe3000_rejects_xe300(daemon):
    daemon.expect({"error": 1})
    daemon.send(b'{OK},88,275,0,65535\n')
    time.sleep(.04)
    daemon.expect({"error": 1})


@pytest.mark.parametrize("kind", ["source", "unowned", "symlink", "hardlink-owner"])
def test_builder_refuses_unsafe_output_before_touching_inputs(tmp_path, monkeypatch, kind):
    import importlib
    root = tmp_path / "repo"
    (root / "build").mkdir(parents=True)
    source = tmp_path / "accepted"
    source.mkdir()
    sentinel = source / "package"
    sentinel.write_text("accepted baseline")
    monkeypatch.setattr(importlib.import_module("mcu_offline"), "ROOT", root)
    output = root / "build/mcu-offline-test"
    if kind == "source":
        output = source
    elif kind == "symlink":
        output.symlink_to(source, target_is_directory=True)
    else:
        output.mkdir()
        if kind == "hardlink-owner":
            sentinel.write_text("mcu-offline-v1\n")
            os.link(sentinel, output / ".mcu-offline-owner")
    with pytest.raises(ValueError):
        mcu.build(source, output, Path("/usr/bin/false"), 99)
    assert sentinel.read_text() == ("mcu-offline-v1\n" if kind == "hardlink-owner" else "accepted baseline")


def test_builder_never_implicitly_inherits_subprocess_environment():
    # Architectural safety contract: every native tool launch must choose its env.
    # This includes special paths (e.g. decompression), not only the build wrapper.
    import ast
    tree = ast.parse(Path(mcu.__file__).read_text())
    launches = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"
                and node.func.attr in ("run", "check_output", "Popen")]
    assert launches
    for launch in launches:
        assert any(keyword.arg == "env" and not (
            isinstance(keyword.value, ast.Constant) and keyword.value.value is None)
            for keyword in launch.keywords), f"Inherited environment at line {launch.lineno}"
