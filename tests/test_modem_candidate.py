"""Real public kernel sources, real git apply, and fail-closed offline boundaries."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

import pytest

from conftest import Lazy, REPO

modem = Lazy('check_modem_candidate')
ARTIFACTS = REPO / 'recipe/candidates/modem'
PCI = 'drivers/bus/mhi/host/pci_generic.c'
MBIM = 'drivers/net/wwan/mhi_wwan_mbim.c'


def test_public_cli_entrypoint():
    result = subprocess.run([sys.executable, str(REPO / 'scripts/check_modem_candidate.py'), '--help'], capture_output=True)
    assert result.returncode == 0, result.stderr.decode()
    assert b'--kernel-source' in result.stdout


@pytest.fixture
def candidate(tmp_path, monkeypatch):
    # Public exact source subset: tests replace only the full-archive digest.
    archive = tmp_path / 'sources.tar.xz'
    shutil.copyfile(ARTIFACTS / 'tests/linux-6.12.112-public-sources.txz', archive)
    kernel = tmp_path / 'kernel'
    with tarfile.open(archive) as tf:
        for rel in (PCI, MBIM):
            path = kernel / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(tf.extractfile('linux-6.12.112/' + rel).read())
    monkeypatch.setattr('check_modem_candidate.KERNEL_ARCHIVE_SHA256', hashlib.sha256(archive.read_bytes()).hexdigest())
    return kernel, archive, tmp_path / 'candidate'


def test_real_apply_preserves_sources_and_records_profile_change(candidate):
    kernel, archive, out = candidate
    before = {rel: (kernel / rel).read_bytes() for rel in (PCI, MBIM)}
    modem.prepare(kernel, archive, out)
    record = json.loads((out / 'proposal.json').read_text())
    assert record['before_profile'] == 'mhi_qcom_sdx65_info'
    assert record['after_profile'] == 'mhi_quectel_rm5xx_info'
    assert record['mbim_channel'] == 'IP_HW0_MBIM'
    assert record['profile_diff']['sideband_wake'] == {'before': 'false', 'after': 'true'}
    assert record['profile_diff']['config']['after'] == '&modem_quectel_em1xx_config'
    assert record['patch_application']['check_exit_code'] == 0
    assert record['patch_application']['apply_exit_code'] == 0
    assert record['defconfig_verified'] is False
    assert record['firmware_build_complete'] is False
    assert record['hardware_verified'] is False
    patched = (out / 'kernel' / PCI).read_bytes()
    assert patched != before[PCI]
    for rel, original in before.items():
        assert (kernel / rel).read_bytes() == original
        assert (kernel / rel).stat().st_ino != (out / 'kernel' / rel).stat().st_ino


@pytest.mark.parametrize('rel', [PCI, MBIM])
@pytest.mark.parametrize('damage', ['corrupt', 'truncate'])
def test_corrupted_or_truncated_source_refused_before_output(candidate, rel, damage):
    kernel, archive, out = candidate
    path = kernel / rel
    data = path.read_bytes()
    path.write_bytes(data[:-20] if damage == 'truncate' else data.replace(b'static', b'broken', 1))
    with pytest.raises(modem.CandidateError, match='source hash'):
        modem.prepare(kernel, archive, out)
    assert not out.exists()


def test_archive_corruption_refused_before_output(candidate):
    kernel, archive, out = candidate
    archive.write_bytes(archive.read_bytes()[:-20])
    with pytest.raises(modem.CandidateError, match='archive hash'):
        modem.prepare(kernel, archive, out)
    assert not out.exists()


def test_already_patched_source_refused(candidate):
    kernel, archive, out = candidate
    modem.prepare(kernel, archive, out)
    with pytest.raises(modem.CandidateError, match='source hash'):
        modem.prepare(out / 'kernel', archive, out.parent / 'second')
    assert not (out.parent / 'second').exists()


@pytest.mark.parametrize('kind', ['existing', 'symlink', 'parent_symlink', 'source_alias', 'private', 'traversal'])
def test_unsafe_output_refused_before_side_effects(candidate, kind):
    kernel, archive, out = candidate
    if kind == 'existing':
        out.mkdir()
        (out / 'keep').write_text('keep')
    elif kind == 'symlink':
        out.symlink_to(kernel, target_is_directory=True)
    elif kind == 'parent_symlink':
        alias = out.parent / 'alias'
        alias.symlink_to(kernel, target_is_directory=True)
        out = alias / 'new'
    elif kind == 'source_alias':
        out = kernel / 'new'
    elif kind == 'private':
        out = out.parent / 'harvest/raw/candidate'
    else:
        out = out / '../new'
    before = sorted(str(p.relative_to(kernel)) for p in kernel.rglob('*'))
    with pytest.raises(modem.CandidateError):
        modem.prepare(kernel, archive, out)
    assert sorted(str(p.relative_to(kernel)) for p in kernel.rglob('*')) == before


@pytest.mark.parametrize('kind', ['symlink_file', 'symlink_parent', 'hardlink_file', 'private'])
def test_source_alias_and_private_paths_refused(candidate, kind):
    kernel, archive, out = candidate
    path = kernel / PCI
    if kind == 'symlink_file':
        original = path.with_suffix('.original')
        path.rename(original)
        path.symlink_to(original)
    elif kind == 'symlink_parent':
        original = path.parent.with_name('original')
        path.parent.rename(original)
        path.parent.symlink_to(original, target_is_directory=True)
    elif kind == 'hardlink_file':
        os.link(path, path.with_suffix('.linked'))
    else:
        kernel = out.parent / 'harvest/raw/kernel'
    with pytest.raises(modem.CandidateError):
        modem.prepare(kernel, archive, out)
    assert not out.exists()


def test_wrong_public_patch_hash_refused(candidate, monkeypatch, tmp_path):
    kernel, archive, out = candidate
    artifacts = tmp_path / 'artifacts'
    shutil.copytree(ARTIFACTS, artifacts)
    patch = artifacts / 'gl-x3000-quectel-pci-id.patch'
    patch.write_bytes(patch.read_bytes().replace(b'mhi_quectel_rm5xx_info', b'mhi_qcom_sdx65_info'))
    monkeypatch.setattr('check_modem_candidate.ARTIFACTS', artifacts)
    with pytest.raises(modem.CandidateError, match='patch hash'):
        modem.prepare(kernel, archive, out)
    assert not out.exists()


@pytest.mark.parametrize('filename', ['candidate.config', 'provenance.json', 'README.md'])
def test_candidate_artifact_damage_refused_before_output(candidate, monkeypatch, tmp_path, filename):
    kernel, archive, out = candidate
    artifacts = tmp_path / 'artifacts'
    shutil.copytree(ARTIFACTS, artifacts)
    path = artifacts / filename
    path.write_bytes(path.read_bytes() + b'CORRUPT')
    monkeypatch.setattr('check_modem_candidate.ARTIFACTS', artifacts)
    with pytest.raises(modem.CandidateError):
        modem.prepare(kernel, archive, out)
    assert not out.exists()


@pytest.mark.parametrize('damage', ['duplicate_member', 'wrong_member', 'missing_member'])
def test_pristine_archive_member_contract(candidate, monkeypatch, damage):
    kernel, archive, out = candidate
    with tarfile.open(archive, 'w:xz') as tf:
        rels = [PCI] if damage == 'missing_member' else [PCI, MBIM]
        if damage == 'duplicate_member':
            rels.append(PCI)
        for rel in rels:
            data = (kernel / rel).read_bytes()
            if damage == 'wrong_member' and rel == MBIM:
                data = b'X' + data[1:]
            item = tarfile.TarInfo('linux-6.12.112/' + rel)
            item.size = len(data)
            tf.addfile(item, io.BytesIO(data))
    monkeypatch.setattr('check_modem_candidate.KERNEL_ARCHIVE_SHA256', hashlib.sha256(archive.read_bytes()).hexdigest())
    with pytest.raises(modem.CandidateError, match='pristine archive'):
        modem.prepare(kernel, archive, out)
    assert not out.exists()


def test_cli_success_records_only_offline_proposal(candidate, capsys):
    kernel, archive, out = candidate
    assert modem.main(['--kernel-source', str(kernel), '--kernel-archive', str(archive), '--out', str(out)]) == 0
    assert 'unverified' in capsys.readouterr().out
    assert (out / 'proposal.json').is_file()


def test_git_ignores_host_path_and_loader_configuration(candidate, monkeypatch, tmp_path):
    kernel, archive, out = candidate
    tools = tmp_path / 'host-bin'
    tools.mkdir()
    marker = tmp_path / 'untrusted-git-ran'
    fake = tools / 'git'
    fake.write_text('#!/bin/sh\ntouch "' + str(marker) + '"\nexit 0\n')
    fake.chmod(0o755)
    monkeypatch.setenv('PATH', str(tools) + ':/usr/bin:/bin')
    monkeypatch.setenv('LD_PRELOAD', '/invalid/host-preload.so')
    monkeypatch.setenv('LD_LIBRARY_PATH', '/invalid/host-library-path')
    modem.prepare(kernel, archive, out)
    assert not marker.exists()
    record = json.loads((out / 'proposal.json').read_text())
    assert 'host-preload' not in record['patch_application']['check_detail']


def test_git_ignores_ancestor_repository_configuration(candidate):
    kernel, archive, out = candidate
    gitdir = out.parent / '.git'
    gitdir.mkdir()
    (gitdir / 'HEAD').write_text('ref: refs/heads/main\n')
    (gitdir / 'objects').mkdir()
    (gitdir / 'refs').mkdir()
    (gitdir / 'config').write_text('this is an invalid Git config\n')
    modem.prepare(kernel, archive, out)
    record = json.loads((out / 'proposal.json').read_text())
    assert 'Checking patch drivers/bus/mhi/host/pci_generic.c' in record['patch_application']['check_detail']


@pytest.mark.parametrize('damage', ['wrong_profile', 'match_after_generic', 'wrong_mbim_channel'])
def test_semantic_check_rejects_wrong_binding(candidate, damage):
    kernel, archive, out = candidate
    modem.prepare(kernel, archive, out)
    pci = (out / 'kernel' / PCI).read_text()
    mbim = (kernel / MBIM).read_text()
    if damage == 'wrong_profile':
        pci = pci.replace('0x5201),\n\t\t.driver_data = (kernel_ulong_t) &mhi_quectel_rm5xx_info',
                          '0x5201),\n\t\t.driver_data = (kernel_ulong_t) &mhi_qcom_sdx65_info')
    elif damage == 'match_after_generic':
        first = pci.index('\t{ PCI_DEVICE_SUB(PCI_VENDOR_ID_QCOM, 0x0308, PCI_VENDOR_ID_QCOM, 0x5201)')
        end = pci.index('},', first) + 2
        entry = pci[first:end]
        pci = pci[:first] + pci[end:]
        index = pci.index('&mhi_qcom_sdx65_info },') + len('&mhi_qcom_sdx65_info },')
        pci = pci[:index] + '\n' + entry + pci[index:]
    else:
        mbim = mbim.replace('IP_HW0_MBIM', 'IP_HW0_QMI')
    with pytest.raises(modem.CandidateError):
        modem.inspect_profiles(pci, mbim)


def test_cli_failure_is_content_free(candidate, capsys):
    kernel, archive, out = candidate
    (kernel / PCI).write_text('DO-NOT-ECHO-THIS-CONTENT')
    assert modem.main(['--kernel-source', str(kernel), '--kernel-archive', str(archive), '--out', str(out)]) == 1
    captured = capsys.readouterr()
    assert 'DO-NOT-ECHO' not in captured.out + captured.err
    assert 'source hash' in captured.err
