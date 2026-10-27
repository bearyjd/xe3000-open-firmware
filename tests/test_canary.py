"""L2: known-secret canaries. The value is never printed, only file and line."""
import base64
import json
import os
import stat
import urllib.parse

import pytest

from conftest import Lazy

canary = Lazy("recon.canary")

# assembled at runtime; nothing secret-looking is committed
VALUE = "Gx4Ts9" + "Lm2Qe7!z"
RAW_CANARY = "plant-" + "ed pass/phrase+1"


def write_canary(tmp_path, *values, mode=0o600):
    f = tmp_path / "canaries"
    f.write_text("# my secrets\n\n" + "\n".join(values) + "\n")
    f.chmod(mode)
    return f


def forms(secret):
    b = secret.encode()
    out = {
        "exact": secret, "lower": secret.lower(), "upper": secret.upper(),
        "url": urllib.parse.quote(secret, safe=""), "urlplus": urllib.parse.quote_plus(secret),
        "hex": b.hex(), "HEX": b.hex().upper(),
        "b64": base64.b64encode(b).decode(), "b64url": base64.urlsafe_b64encode(b).decode().rstrip("="),
        "b64-in-middle-1": base64.b64encode(b"x" + b + b"y").decode(),
        "b64-in-middle-2": base64.b64encode(b"xy" + b + b"z").decode(),
        "b64-in-middle-0": base64.b64encode(b + b"xyz").decode(),
    }
    return out


@pytest.mark.parametrize("form", sorted(forms(RAW_CANARY)))
def test_scan_finds_every_common_transform(form):
    text = f"line one\nprefix {forms(RAW_CANARY)[form]} suffix\nline three\n"
    hits = canary.scan({"redacted/etc/x": text}, [RAW_CANARY])
    assert hits == [("redacted/etc/x", 2)], form


def test_scan_reports_multiple_files_and_lines_only():
    files = {"redacted/a": f"x\n{RAW_CANARY}\n", "unpacked/b": f"{RAW_CANARY}\n\n{RAW_CANARY}\n", "redacted/c": "clean\n"}
    assert canary.scan(files, [RAW_CANARY]) == [("redacted/a", 2), ("unpacked/b", 1), ("unpacked/b", 3)]


def test_scan_clean_and_empty():
    assert canary.scan({"a": "nothing here\n"}, [RAW_CANARY]) == []
    assert canary.scan({"a": RAW_CANARY}, []) == []


def test_load_reads_values_skips_comments(tmp_path):
    f = write_canary(tmp_path, RAW_CANARY, VALUE)
    assert canary.load_canaries(f) == (RAW_CANARY, VALUE)


def test_load_missing_returns_none(tmp_path):
    assert canary.load_canaries(tmp_path / "absent") is None


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o660])
def test_load_refuses_group_or_world_readable(tmp_path, mode):
    f = write_canary(tmp_path, RAW_CANARY, mode=mode)
    with pytest.raises(canary.CanaryError, match="0600") as ei:
        canary.load_canaries(f)
    assert RAW_CANARY not in str(ei.value)


def test_load_refuses_too_short_values_without_echoing_them(tmp_path):
    f = write_canary(tmp_path, "abc")
    with pytest.raises(canary.CanaryError) as ei:
        canary.load_canaries(f)
    assert "abc" not in str(ei.value) and "line 3" in str(ei.value).lower()


def test_default_path_and_env_override(monkeypatch, tmp_path):
    monkeypatch.delenv("RECON_CANARY_FILE", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    assert canary.default_path() == tmp_path / ".config" / "xe3000-open-firmware" / "canaries"
    monkeypatch.setenv("RECON_CANARY_FILE", str(tmp_path / "other"))
    assert canary.default_path() == tmp_path / "other"


def test_init_creates_empty_0600_file_once(tmp_path):
    f = tmp_path / "d" / "canaries"
    assert canary.init_file(f) is True
    assert f.read_text() == "" or f.read_text().startswith("#")
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    f.write_text("keep-" + "me-please\n")
    assert canary.init_file(f) is False and "keep-me-please" in f.read_text()


def test_real_harvest_markers(tmp_path):
    assert canary.has_real_harvest_marker(["redacted/.recon-redacted"])
    assert canary.has_real_harvest_marker(["redacted/etc/glversion"])
    assert not canary.has_real_harvest_marker(["redacted/etc/init.d/modem"])


# ---- analyze integration ----

def _cli(root, client, *extra, run_id="r1", canary_env=None):
    from recon import cli
    return cli.main(["--root", str(root), "--run-id", run_id, "--allow-extra", "**", *extra],
                    client_factory=lambda: client)


def test_analyze_aborts_on_canary_in_any_input_file(stamped, tmp_path, monkeypatch, capsys):
    from fakes import FakeClient
    (stamped / "harvest" / "redacted" / "etc" / "config" / "network").write_text(f"a\nb\n{RAW_CANARY}\n")
    from conftest import write_stamp_for
    write_stamp_for(stamped)
    monkeypatch.setenv("RECON_CANARY_FILE", str(write_canary(tmp_path, RAW_CANARY)))
    client = FakeClient()
    assert _cli(stamped, client) == 2
    seen = capsys.readouterr()
    assert "redacted/etc/config/network:3" in seen.err
    assert RAW_CANARY not in seen.out + seen.err
    assert client.count_calls == [] and client.create_calls == []
    assert not (stamped / "findings" / "raw" / "r1").exists()


@pytest.mark.parametrize("form", ["url", "hex", "b64", "lower"])
def test_analyze_aborts_on_encoded_canary_even_in_denied_files(root, stamp, tmp_path, monkeypatch, capsys, form):
    from fakes import FakeClient
    (root / "harvest" / "redacted" / "ps").write_text("ok\n" + forms(RAW_CANARY)[form] + "\n")  # not on the allowlist
    stamp(root)
    monkeypatch.setenv("RECON_CANARY_FILE", str(write_canary(tmp_path, RAW_CANARY)))
    client = FakeClient()
    from recon import cli
    assert cli.main(["--root", str(root), "--run-id", "r1"], client_factory=lambda: client) == 2
    err = capsys.readouterr().err
    assert "redacted/ps:2" in err and forms(RAW_CANARY)[form] not in err
    assert client.create_calls == []


def test_missing_canary_file_with_real_harvest_marker_is_refused(stamped, stamp, tmp_path, monkeypatch, capsys):
    from fakes import FakeClient
    (stamped / "harvest" / "redacted" / ".recon-redacted").write_text("marker\n")
    stamp(stamped)
    monkeypatch.setenv("RECON_CANARY_FILE", str(tmp_path / "absent"))
    client = FakeClient()
    assert _cli(stamped, client) == 2
    assert "--no-canary" in capsys.readouterr().err and client.count_calls == []
    assert _cli(stamped, client, "--no-canary", "--dry-run", "--max-usd", "5") == 0


def test_missing_canary_file_without_marker_is_fine_for_fixtures(stamped, tmp_path, monkeypatch):
    from fakes import FakeClient
    monkeypatch.setenv("RECON_CANARY_FILE", str(tmp_path / "absent"))
    assert _cli(stamped, FakeClient(), "--dry-run", "--max-usd", "5") == 0


def test_clean_inputs_pass_with_a_canary_file(stamped, tmp_path, monkeypatch):
    from fakes import FakeClient
    monkeypatch.setenv("RECON_CANARY_FILE", str(write_canary(tmp_path, RAW_CANARY)))
    assert _cli(stamped, FakeClient(), "--dry-run", "--max-usd", "5") == 0


def test_bad_permissions_on_canary_file_refuse_the_run(stamped, tmp_path, monkeypatch, capsys):
    from fakes import FakeClient
    monkeypatch.setenv("RECON_CANARY_FILE", str(write_canary(tmp_path, RAW_CANARY, mode=0o644)))
    assert _cli(stamped, FakeClient()) == 2
    err = capsys.readouterr().err
    assert "0600" in err and RAW_CANARY not in err


# ---- pre-flight integration ----

def test_preflight_aborts_on_canary_and_writes_no_stamp(root, fixture_tree, tmp_path, monkeypatch, capsys):
    import subprocess
    from conftest import GITLEAKS_TOML
    from recon import preflight
    (fixture_tree / "etc" / "config" / "network").write_text(f"x\n{forms(RAW_CANARY)['b64']}\n")
    monkeypatch.setenv("RECON_CANARY_FILE", str(write_canary(tmp_path, RAW_CANARY)))
    monkeypatch.delenv("RECON_GITLEAKS_BIN", raising=False)
    monkeypatch.setenv("PODMAN", "podman")
    monkeypatch.setattr(preflight, "_default_runner",
                        lambda: (lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "[]", "")))
    rc = preflight.main(["--root", str(root), "--config", str(GITLEAKS_TOML),
                         "--image-file", str(root / "containers" / "gitleaks.image")])
    out = capsys.readouterr()
    assert rc == 1 and "redacted/etc/config/network:2" in out.out + out.err
    assert forms(RAW_CANARY)["b64"] not in out.out + out.err and RAW_CANARY not in out.out + out.err
    assert not (root / "cache" / "preflight").exists() or not list((root / "cache" / "preflight").glob("*.ok"))


def test_preflight_missing_canary_with_marker_needs_flag(root, fixture_tree, tmp_path, monkeypatch, capsys):
    import subprocess
    from conftest import GITLEAKS_TOML
    from recon import preflight
    (fixture_tree / ".recon-redacted").write_text("m\n")
    monkeypatch.setenv("RECON_CANARY_FILE", str(tmp_path / "absent"))
    monkeypatch.delenv("RECON_GITLEAKS_BIN", raising=False)
    monkeypatch.setenv("PODMAN", "podman")
    monkeypatch.setattr(preflight, "_default_runner",
                        lambda: (lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "[]", "")))
    args = ["--root", str(root), "--config", str(GITLEAKS_TOML), "--image-file", str(root / "containers" / "gitleaks.image")]
    assert preflight.main(args) == 2
    assert "--no-canary" in capsys.readouterr().err
    assert preflight.main([*args, "--no-canary"]) == 0


def test_scan_finds_percent_encoded_every_char_and_json_escaped_forms():
    import json as _json
    secret = RAW_CANARY
    full_pct = "".join(f"%{b:02X}" for b in secret.encode())
    full_pct_lower = full_pct.lower()
    json_escaped = _json.dumps("a\"b" + secret + "c\\d")[1:-1]
    unicode_escaped = "".join(f"\\u{ord(c):04x}" for c in secret)
    for form in (full_pct, full_pct_lower, json_escaped, unicode_escaped):
        assert canary.scan({"f": f"x {form} y\n"}, [secret]) == [("f", 1)], form


def test_scan_finds_a_canary_that_contains_quotes_in_its_json_form():
    quoted = 'pa"ss' + "wd-12"
    import json as _json
    assert canary.scan({"f": _json.dumps({"k": quoted})}, [quoted]) == [("f", 1)]


def test_readme_documents_short_pin_limit():
    from conftest import REPO
    readme = (REPO / "README.md").read_text().lower()
    assert "4-digit" in readme and "pin" in readme and "canar" in readme
