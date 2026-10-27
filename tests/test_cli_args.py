import pytest

from fakes import FakeClient
from recon import cli


@pytest.mark.parametrize("flag", ["--max-usd", "--max-input-tokens", "--max-tokens"])
@pytest.mark.parametrize("bad", ["nan", "inf", "-inf", "0", "-1", "abc", "1e999"])
def test_bad_numeric_flags_are_rejected(root, flag, bad, capsys):
    client = FakeClient()
    with pytest.raises(SystemExit) as ei:
        cli.main(["--root", str(root), "--run-id", "x", flag, bad], client_factory=lambda: client)
    assert ei.value.code == 2 and client.count_calls == []


@pytest.mark.parametrize("env,bad", [("RECON_MAX_USD", "nan"), ("RECON_MAX_USD", "-3"), ("RECON_MAX_USD", "inf"),
                                     ("RECON_MAX_INPUT_TOKENS", "0")])
def test_bad_env_defaults_are_rejected(root, monkeypatch, env, bad):
    monkeypatch.setenv(env, bad)
    with pytest.raises(SystemExit) as ei:
        cli.main(["--root", str(root), "--run-id", "x"], client_factory=FakeClient)
    assert ei.value.code == 2


def test_good_values_accepted(root, monkeypatch):
    monkeypatch.setenv("RECON_MAX_USD", "0.5")
    args = cli.build_parser().parse_args(["--run-id", "x", "--max-input-tokens", "10", "--max-tokens", "5"])
    assert args.max_usd == 0.5 and args.max_input_tokens == 10 and args.max_tokens == 5
