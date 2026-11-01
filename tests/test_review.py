"""Public review preparation contract; scanner is replaced only at subprocess boundary."""
import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from conftest import Lazy
from recon import canary, preflight

review = Lazy('recon.review')


def hit(file='/scan/etc%config%network', start=2, end=3, rule='synthetic-key'):
    return {'File': file, 'StartLine': start, 'EndLine': end, 'RuleID': rule,
            'Secret': 'NEVER_PERSIST_SECRET', 'Match': 'NEVER_PERSIST_MATCH'}


class Scanner:
    def __init__(self, reports=None):
        self.reports = list(reports or [])
        self.calls = []

    def __call__(self, cmd, **kwargs):
        self.calls.append(cmd)
        assert '--redact' in cmd and '--network=none' in cmd
        assert kwargs == {'capture_output': True, 'text': True, 'check': False}
        code, data = self.reports.pop(0) if self.reports else (0, [])
        stdout = data if isinstance(data, str) else json.dumps(data)
        return subprocess.CompletedProcess(cmd, code, stdout, 'NEVER_PERSIST_STDERR')


def invoke(root, out, scanner):
    return review.main(['--root', str(root), '--out', str(out)], runner=scanner,
                       sanitizer=canary.Sanitizer(()),
                       canary_check=lambda files, **kw: [])


def seed(root):
    (root / 'harvest/redacted/etc%config%network').write_bytes(b'head\r\nsecret one\r\nsecret two\r\ntail')
    (root / 'unpacked/x').write_bytes(b'one\nsecret without newline')
    (root / 'harvest/raw/private').write_text('RAW_MUST_NEVER_COPY')


def test_copy_redact_provenance_and_default_stamp(root, tmp_path, capsys):
    seed(root)
    original = {p: p.read_bytes() for d in preflight.default_inputs(root) for p in d.rglob('*') if p.is_file()}
    scanner = Scanner([(7, [hit(), hit(start=3, end=3)]),
                       (7, [hit('/scan/x', 2, 2)])])
    out = tmp_path / 'review'
    assert invoke(root, out, scanner) == 0
    assert (out / 'harvest/redacted/etc%config%network').read_bytes() == (
        b'head\r\n# <REDACTED:scanner-review>\r\n# <REDACTED:scanner-review>\r\ntail')
    assert (out / 'unpacked/x').read_bytes() == b'one\n# <REDACTED:scanner-review>'
    assert all(p.read_bytes() == data for p, data in original.items())
    for name in ('gitleaks.toml', 'gitleaks.image', 'recon-allowlist.txt'):
        assert (out / 'containers' / name).read_bytes() == (root / 'containers' / name).read_bytes()
        assert (out / 'containers' / name).stat().st_ino != (root / 'containers' / name).stat().st_ino
    assert not (out / 'harvest/raw').exists()
    assert {f.name for d in preflight.default_inputs(out) for f in __import__('recon.paths', fromlist=['list_input_files']).list_input_files(d, out)} == {
        'redacted/etc%config%network', 'unpacked/x'}
    evidence = json.loads((out / 'review.json').read_text())
    assert evidence['status'] == 'complete' and evidence['method'] == 'scanner-guided post-redaction'
    assert evidence['context_loss'] is True
    row = next(r for r in evidence['files'] if r['file'] == 'redacted/etc%config%network')
    assert row['source_sha256'] == row['copy_sha256'] == hashlib.sha256(next(iter(original.values()))).hexdigest()
    assert row['output_sha256'] == hashlib.sha256((out / 'harvest/redacted/etc%config%network').read_bytes()).hexdigest()
    assert preflight.has_stamp(out, preflight.default_inputs(out))
    (out / 'unpacked/x').write_text('changed')
    assert not preflight.has_stamp(out, preflight.default_inputs(out))
    serialized = (out / 'review.json').read_text() + ''.join(capsys.readouterr())
    assert 'NEVER_PERSIST' not in serialized
    assert len(scanner.calls) == 4


@pytest.mark.parametrize('bad', [
    hit('/scanx/etc%config%network'), hit('/scan/../x'), hit('/scan//x'), hit('/scan/./x'),
    hit('etc%config%network'), hit('/etc%config%network'), hit('/scan/missing'),
    hit(start=True), hit(start=0), hit(start=3, end=2), hit(end=5),
    hit(end='3'), hit(rule=[]), {'File': '/scan/x'},
])
def test_malformed_finding_fails_closed(root, tmp_path, bad, capsys):
    seed(root)
    out = tmp_path / 'review'
    assert invoke(root, out, Scanner([(7, [bad])])) == 2
    assert not list(out.rglob('*.ok'))
    assert json.loads((out / 'review.json').read_text())['status'] == 'failed'
    assert 'NEVER_PERSIST' not in ''.join(capsys.readouterr()) + (out / 'review.json').read_text()


@pytest.mark.parametrize('response', [(1, 'NEVER_PERSIST'), (7, []), (7, {}), (7, 'broken'), (0, [hit()]), (0, {})])
def test_scanner_failures_and_exit_zero_lies(root, tmp_path, response):
    seed(root)
    out = tmp_path / 'review'
    assert invoke(root, out, Scanner([response])) == 2
    assert not list(out.rglob('*.ok'))


def test_remaining_rescan_hit_refuses(root, tmp_path):
    seed(root)
    out = tmp_path / 'review'
    scanner = Scanner([(7, [hit()]), (0, []), (7, [hit()])])
    assert invoke(root, out, scanner) == 2
    assert not list(out.rglob('*.ok'))
    assert json.loads((out / 'review.json').read_text())['status'] == 'failed'


@pytest.mark.parametrize('kind', ['existing', 'overlap', 'contains', 'raw', 'file-symlink', 'dir-symlink', 'hardlink', 'policy-link', 'out-parent-link', 'source-root-link'])
def test_unsafe_paths_never_scan(root, tmp_path, kind):
    seed(root)
    out = tmp_path / 'review'
    if kind == 'existing': out.mkdir()
    if kind == 'overlap': out = root / 'harvest/redacted/new'
    if kind == 'contains': out = root.parent
    if kind == 'raw': out = root / 'harvest/raw/new'
    if kind == 'file-symlink': (root / 'unpacked/link').symlink_to(root / 'harvest/redacted/etc%config%network')
    if kind == 'dir-symlink': (root / 'unpacked/link').symlink_to(root / 'harvest/redacted', target_is_directory=True)
    if kind == 'hardlink': os.link(root / 'unpacked/x', root / 'unpacked/other')
    if kind == 'policy-link':
        (root / 'containers/gitleaks.toml').unlink()
        (root / 'containers/gitleaks.toml').symlink_to(root / 'unpacked/x')
    if kind == 'out-parent-link':
        (tmp_path / 'alias').symlink_to(tmp_path, target_is_directory=True)
        out = tmp_path / 'alias/review'
    if kind == 'source-root-link':
        (tmp_path / 'alias').symlink_to(root, target_is_directory=True)
        root = tmp_path / 'alias'
    scanner = Scanner()
    assert invoke(root, out, scanner) == 2
    assert not scanner.calls


def test_normal_canary_gate_refuses_and_preserves_original(root, tmp_path):
    seed(root)
    canary_file = tmp_path / 'canaries'
    canary_file.write_text('secret one\n')
    canary_file.chmod(0o600)
    out = tmp_path / 'review'
    assert review.main(['--root', str(root), '--out', str(out)], runner=Scanner(),
                       sanitizer=canary.Sanitizer.from_file(canary_file),
                       canary_check=lambda files, **kw: canary.check(files, path=canary_file, **kw)) == 2
    assert not list(out.rglob('*.ok'))
    assert b'secret one' in (root / 'harvest/redacted/etc%config%network').read_bytes()


@pytest.mark.requires_podman
def test_pinned_scanner_prepares_synthetic_multiline_tree(root, tmp_path):
    """Real pinned scanner integration; no real harvest or API use."""
    original = b'head\r\n-----BEGIN ' + b'PRIVATE ' + b'KEY-----\r\n' + b'A' * 48 + b'\r\n-----END ' + b'PRIVATE ' + b'KEY-----\r\ntail'
    path = root / 'harvest/redacted/synthetic.txt'
    path.write_bytes(original)
    out = tmp_path / 'review'
    canary_file = tmp_path / 'canaries'
    canary_file.write_text('')
    canary_file.chmod(0o600)
    assert review.main(['--root', str(root), '--out', str(out)],
                       sanitizer=canary.Sanitizer.from_file(canary_file),
                       canary_check=lambda files, **kw: canary.check(files, path=canary_file, **kw)) == 0
    assert path.read_bytes() == original
    assert (out / 'harvest/redacted/synthetic.txt').read_bytes() == (
        b'head\r\n' + b'# <REDACTED:scanner-review>\r\n' * 3 + b'tail')
    assert preflight.has_stamp(out, preflight.default_inputs(out))


@pytest.mark.parametrize('rel', ['known-name-secret/config', 'known-name-secret/.env'])
def test_known_canary_filename_refused_before_copy(root, tmp_path, rel, capsys):
    source = root / 'unpacked' / rel
    source.parent.mkdir(parents=True)
    source.write_text('ordinary harmless contents\n')
    canary_file = tmp_path / 'canaries'
    canary_file.write_text('known-name-secret\n')
    canary_file.chmod(0o600)
    scanner = Scanner()
    out = tmp_path / 'review'
    assert review.main(['--root', str(root), '--out', str(out)], runner=scanner,
                       sanitizer=canary.Sanitizer.from_file(canary_file),
                       canary_check=lambda files, **kw: canary.check(files, path=canary_file, **kw)) == 2
    assert not scanner.calls
    assert not list(out.rglob('*.ok'))
    assert not out.exists()
    assert source.read_text() == 'ordinary harmless contents\n'
    assert 'known-name-secret' not in ''.join(capsys.readouterr())


def test_excluded_sources_never_opened_and_exclusions_recorded(root, tmp_path, monkeypatch):
    excluded = ['.env', '.env.local', 'etc/id_ed25519', 'private/ordinary', 'etc%ssl%private%x']
    forbidden = set()
    for rel in excluded:
        path = root / 'unpacked' / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('BYTES_MUST_NOT_BE_OPENED')
        forbidden.add(path)
    raw = root / 'harvest/raw/raw-file'
    raw.write_text('RAW_MUST_NOT_BE_OPENED')
    forbidden.add(raw)
    (root / 'unpacked/ordinary').write_text('safe evidence')
    original_open = os.open
    opened = []

    def guarded_open(path, flags, mode=0o777, *, dir_fd=None):
        full = Path(path)
        if not full.is_absolute() and dir_fd is not None:
            full = Path(os.readlink(f'/proc/self/fd/{dir_fd}')) / full
        assert full not in forbidden, 'excluded source was opened'
        opened.append(full)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, 'open', guarded_open)
    out = tmp_path / 'review'
    assert invoke(root, out, Scanner()) == 0
    assert (out / 'unpacked/ordinary').read_text() == 'safe evidence'
    assert all(not (out / 'unpacked' / rel).exists() for rel in excluded)
    assert not (out / 'harvest/raw').exists()
    data = json.loads((out / 'review.json').read_text())
    assert {row['file'] for row in data['exclusions']} == {'unpacked/' + rel for rel in excluded}
    assert all(row['reason'] == 'excluded source name' for row in data['exclusions'])
    for name in ('gitleaks.toml', 'gitleaks.image', 'recon-allowlist.txt'):
        assert root / 'containers' / name in opened
        assert (out / 'containers' / name).read_bytes() == (root / 'containers' / name).read_bytes()
