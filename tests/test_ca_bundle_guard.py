"""CA-bundle duplicate guard, using synthetic PEM blocks (the guard never parses X.509)."""
import base64
import sys

import pytest

from conftest import REPO

sys.path.insert(0, str(REPO / 'scripts'))
import ca_bundle_guard as guard  # noqa: E402
import firmware as fw  # noqa: E402


def pem(seed: int) -> bytes:
    der = bytes([seed]) * 48
    return b'-----BEGIN CERTIFICATE-----\n' + base64.b64encode(der) + b'\n-----END CERTIFICATE-----\n'


def stage(tmp_path, crts, bundle):
    root = tmp_path / 'checkout/build_dir/target-x/ca-certificates-1'
    (root / 'mozilla').mkdir(parents=True)
    for name, seed in crts.items():
        (root / 'mozilla' / name).write_bytes(pem(seed))
    certs = root / 'ipkg-all/ca-bundle/etc/ssl/certs'
    certs.mkdir(parents=True)
    (certs / 'ca-certificates.crt').write_bytes(b''.join(pem(s) for s in bundle))
    return tmp_path / 'checkout'


def test_clean_single_run_passes(tmp_path):
    checkout = stage(tmp_path, {'a.crt': 1, 'b.crt': 2}, [1, 2])
    result = guard.check(checkout)
    assert result[0]['bundle_unique'] == 2 and result[0]['crt_files'] == 2


def test_no_ca_package_dir_is_not_an_error(tmp_path):
    (tmp_path / 'checkout/build_dir').mkdir(parents=True)
    assert guard.check(tmp_path / 'checkout') == []


def test_rerun_duplicate_crt_files_and_bundle_refused(tmp_path):
    checkout = stage(tmp_path, {'a.crt': 1, 'a_2.crt': 1, 'b.crt': 2, 'b_2.crt': 2}, [1, 1, 2, 2])
    with pytest.raises(fw.FirmwareError, match='duplicates'):
        guard.check(checkout)


def test_bundle_duplicate_alone_refused(tmp_path):
    checkout = stage(tmp_path, {'a.crt': 1, 'b.crt': 2}, [1, 2, 2])
    with pytest.raises(fw.FirmwareError, match='duplicates'):
        guard.check(checkout)


def test_bundle_differing_from_crt_set_refused(tmp_path):
    checkout = stage(tmp_path, {'a.crt': 1, 'b.crt': 2}, [1, 3])
    with pytest.raises(fw.FirmwareError, match='duplicates'):
        guard.check(checkout)


def test_empty_bundle_refused(tmp_path):
    checkout = stage(tmp_path, {'a.crt': 1}, [])
    with pytest.raises(fw.FirmwareError, match='no certificates'):
        guard.check(checkout)


def test_invalid_base64_refused(tmp_path):
    checkout = stage(tmp_path, {'a.crt': 1}, [1])
    bundle = checkout / 'build_dir/target-x/ca-certificates-1/ipkg-all/ca-bundle/etc/ssl/certs/ca-certificates.crt'
    bundle.write_bytes(b'-----BEGIN CERTIFICATE-----\n!!!notb64\n-----END CERTIFICATE-----\n')
    with pytest.raises(fw.FirmwareError, match='base64'):
        guard.check(checkout)


def test_guard_never_modifies_outputs(tmp_path):
    checkout = stage(tmp_path, {'a.crt': 1, 'a_2.crt': 1}, [1, 1])
    before = {p: p.read_bytes() for p in checkout.rglob('*') if p.is_file()}
    with pytest.raises(fw.FirmwareError):
        guard.check(checkout)
    assert before == {p: p.read_bytes() for p in checkout.rglob('*') if p.is_file()}


def test_duplicate_crt_files_with_clean_bundle_refused(tmp_path):
    checkout = stage(tmp_path, {'a.crt': 1, 'a_2.crt': 1}, [1])
    with pytest.raises(fw.FirmwareError, match='duplicates'):
        guard.check(checkout)


def test_missing_bundle_gives_specific_error(tmp_path):
    checkout = stage(tmp_path, {'a.crt': 1}, [1])
    (checkout / 'build_dir/target-x/ca-certificates-1/ipkg-all/ca-bundle/etc/ssl/certs/ca-certificates.crt').unlink()
    with pytest.raises(fw.FirmwareError, match='CA bundle missing'):
        guard.check(checkout)


def test_missing_sources_not_reported_as_duplicates(tmp_path):
    checkout = stage(tmp_path, {}, [1])
    with pytest.raises(fw.FirmwareError, match='sources missing'):
        guard.check(checkout)
