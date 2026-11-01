"""Prepared-root launch contract through public shell and just entry points; fake containers only."""
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from conftest import REPO
from recon import canary, review
from test_review import Scanner


@pytest.fixture
def launch(root, tmp_path):
    source = root
    (source / 'scripts/recon').mkdir(parents=True)
    for name in ('__init__.py', 'review.py', 'canary.py', 'preflight.py', 'paths.py', 'names.py'):
        shutil.copy(REPO / 'scripts/recon' / name, source / 'scripts/recon' / name)
    for name in ('prepare_review.py', 'analyze-container.sh'):
        shutil.copy(REPO / 'scripts' / name, source / 'scripts' / name)
    shutil.copy(REPO / 'justfile', source / 'justfile')
    (source / '.env').write_text('ANTHROPIC_API_KEY=synthetic-only\nLLM_MODEL=model-a\nLLM_MODEL_CHEAP=model-b\nOTHER=hidden\nexport ANTHROPIC_API_KEY=wrong\n')
    (source / 'unpacked/ordinary').write_text('ordinary synthetic evidence\n')
    out = tmp_path / 'review tree'
    review.prepare(source, out, runner=Scanner(), sanitizer=canary.Sanitizer(()), canary_check=lambda files, **kw: [])
    tools = tmp_path / 'tools'
    tools.mkdir()
    for name in ('grep', 'mktemp'):
        real = shutil.which(name)
        tool = tools / name
        tool.write_text('#!/bin/sh\nprintf %s\\n ' + name + ' >> "$ACCESS_LOG"\nexec ' + real + ' "$@"\n')
        tool.chmod(0o755)
    podman = tools / 'podman'
    podman.write_text('''#!/usr/bin/env python3
import json, os, pathlib, stat, sys
args = sys.argv[1:]
record = {'args': args}
if '--env-file' in args:
    p = pathlib.Path(args[args.index('--env-file') + 1])
    record.update(env=p.read_text(), envpath=str(p), mode=stat.S_IMODE(p.stat().st_mode))
with open(os.environ['FAKE_LOG'], 'a') as f:
    f.write(json.dumps(record) + '\\n')
''')
    podman.chmod(0o755)
    log, access = tmp_path / 'containers.jsonl', tmp_path / 'access'
    env = {**os.environ, 'ROOT': str(out), 'RECON_SOURCE_ROOT': str(source), 'PODMAN': str(podman),
           'IMAGE': 'synthetic-image', 'HARDENING': '--read-only', 'FAKE_LOG': str(log),
           'ACCESS_LOG': str(access), 'PATH': str(tools) + ':' + os.environ['PATH'],
           'RECON_CANARY_FILE': str(tmp_path / 'absent-canaries')}
    return source, out, env, log, access


def shell_launch(launch):
    source, out, env, log, access = launch
    return subprocess.run(['bash', str(source / 'scripts/analyze-container.sh'), 'run-one', '--dry-run'],
                          env=env, capture_output=True, text=True)


def assert_review_mounts(record, source, out):
    args = record['args']
    assert f'{source}/scripts:/work/scripts:ro,z' in args
    for rel, mode in [('containers', 'ro,z'), ('harvest/redacted', 'ro,z'), ('unpacked', 'ro,z'),
                      ('cache/preflight', 'ro,z'), ('cache/responses', 'z'), ('findings/raw', 'z')]:
        assert f'{out}/{rel}:/work/{rel}:{mode}' in args
    mounts = [args[i + 1] for i, value in enumerate(args) if value == '-v']
    assert not any('harvest/raw' in m or m.startswith(str(source) + ':/') for m in mounts)
    assert all(not m.startswith(str(source) + '/') or m.startswith(str(source) + '/scripts:') for m in mounts)
    assert record['env'] == 'ANTHROPIC_API_KEY=synthetic-only\nLLM_MODEL=model-a\nLLM_MODEL_CHEAP=model-b\n'
    assert record['mode'] == 0o600 and not Path(record['envpath']).exists()
    assert not (out / '.env').exists()


def test_prepared_root_launch_uses_source_scripts_and_filtered_credentials(launch):
    source, out, env, log, access = launch
    result = shell_launch(launch)
    assert result.returncode == 0, result.stderr
    assert_review_mounts(json.loads(log.read_text()), source, out)


@pytest.mark.parametrize('tamper', ['missing', 'failed', 'source-policy', 'review-policy', 'tree', 'stamp', 'alias', 'raw', 'overlap'])
def test_invalid_review_refused_before_credentials_tempfile_or_container(launch, tamper):
    source, out, env, log, access = launch
    if tamper == 'missing': (out / 'review.json').unlink()
    if tamper == 'failed':
        data = json.loads((out / 'review.json').read_text())
        data['status'] = 'failed'
        (out / 'review.json').write_text(json.dumps(data))
    if tamper == 'source-policy': (source / 'containers/recon-allowlist.txt').write_text('changed')
    if tamper == 'review-policy': (out / 'containers/gitleaks.toml').write_text('changed')
    if tamper == 'tree': (out / 'unpacked/ordinary').write_text('changed')
    if tamper == 'stamp': next((out / 'cache/preflight').glob('*.ok')).unlink()
    if tamper == 'alias':
        alias = out.parent / 'alias'
        alias.symlink_to(out, target_is_directory=True)
        env['ROOT'] = str(alias)
    if tamper == 'raw':
        raw = source / 'harvest/raw/review'
        shutil.copytree(out, raw)
        env['ROOT'] = str(raw)
    if tamper == 'overlap': env['ROOT'] = str(source)
    result = shell_launch(launch)
    assert result.returncode != 0
    assert not log.exists() and not access.exists()
    assert 'synthetic-only' not in result.stdout + result.stderr


@pytest.mark.skipif(shutil.which('just') is None, reason='requires host just binary; exercised in CI hook-tests')
def test_just_analyze_review_public_recipe_quotes_root_and_preserves_arguments(launch):
    source, out, env, log, access = launch
    result = subprocess.run(['just', '--justfile', str(source / 'justfile'), 'analyze-review',
                             str(out), 'run with spaces', '--topic', 'boot'], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    records = [json.loads(line) for line in log.read_text().splitlines()]
    assert records[0]['args'][0] == 'build'
    assert_review_mounts(records[-1], source, out)
    assert records[-1]['args'][-4:] == ['--run-id', 'run with spaces', '--topic', 'boot']


@pytest.mark.parametrize('injected', ['.env', 'private/credential', 'unexpected'])
def test_verifier_inventory_refusal_precedes_all_input_reads(launch, monkeypatch, injected):
    source, out, env, log, access = launch
    added = out / 'unpacked' / injected
    added.parent.mkdir(parents=True, exist_ok=True)
    added.write_text('SYNTHETIC_BYTES_MUST_NOT_BE_OPENED')
    original_open = os.open

    def guarded_open(path, flags, mode=0o777, *, dir_fd=None):
        full = Path(path)
        if not full.is_absolute() and dir_fd is not None:
            full = Path(os.readlink(f'/proc/self/fd/{dir_fd}')) / full
        if full.is_relative_to(out / 'unpacked') and full.is_file():
            pytest.fail('candidate input bytes opened before inventory refusal')
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, 'open', guarded_open)
    with pytest.raises(review.ReviewError):
        review.verify_review_root(out, source, canary_check=lambda files, **kw: [])
    result = shell_launch(launch)
    assert result.returncode != 0 and not log.exists() and not access.exists()


@pytest.mark.parametrize('mounted', ['findings/raw', 'cache/responses', 'cache/preflight', 'containers', 'unpacked', 'harvest/redacted'])
def test_mounted_candidate_symlink_refused_before_credentials_or_container(launch, mounted):
    source, out, env, log, access = launch
    path = out / mounted
    if path.exists():
        shutil.rmtree(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(source / 'harvest/raw', target_is_directory=True)
    result = shell_launch(launch)
    assert result.returncode != 0
    assert not log.exists() and not access.exists()


@pytest.mark.parametrize('parent', ['findings', 'cache'])
def test_mount_parent_alias_refused_before_credentials_or_container(launch, parent):
    source, out, env, log, access = launch
    path = out / parent
    if path.exists():
        shutil.rmtree(path)
    path.symlink_to(source / 'harvest/raw', target_is_directory=True)
    result = shell_launch(launch)
    assert result.returncode != 0
    assert not log.exists() and not access.exists()


def test_verifier_canary_name_gate_precedes_input_reads(launch, monkeypatch):
    source, out, env, log, access = launch
    (out / 'unpacked/known-name-secret').write_text('ordinary contents')
    canary_file = out.parent / 'test-canaries'
    canary_file.write_text('known-name-secret\n')
    canary_file.chmod(0o600)
    original_open = os.open

    def guarded_open(path, flags, mode=0o777, *, dir_fd=None):
        full = Path(path)
        if not full.is_absolute() and dir_fd is not None:
            full = Path(os.readlink(f'/proc/self/fd/{dir_fd}')) / full
        if full.is_relative_to(out / 'unpacked') and full.is_file():
            pytest.fail('candidate bytes opened before filename canary gate')
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, 'open', guarded_open)
    with pytest.raises(review.ReviewError, match='known-secret canary'):
        review.verify_review_root(out, source, canary_check=lambda files, **kw: canary.check(files, path=canary_file, **kw))
