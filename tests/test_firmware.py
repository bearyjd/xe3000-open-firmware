"""Public source preparation/verification using real temporary Git objects only."""
import json
from pathlib import Path
import subprocess

import pytest

from conftest import Lazy, REPO

firmware = Lazy('firmware')
SEED = ('CONFIG_TARGET_mediatek=y\nCONFIG_TARGET_mediatek_filogic=y\n'
        'CONFIG_TARGET_mediatek_filogic_DEVICE_glinet_gl-xe3000=y\n')
FEEDS = [{'name': name, 'url': f'https://git.openwrt.org/feed/{name}.git', 'commit': str(i) * 40}
         for i, name in enumerate(('packages', 'luci', 'routing', 'telephony', 'video'), 1)]


def git(directory, *args):
    return subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null', '-C', str(directory), *args], stderr=subprocess.DEVNULL).decode().strip()


@pytest.fixture
def setup(tmp_path):
    project = tmp_path / 'project'
    source = project / 'build/source'
    source.mkdir(parents=True)
    git(source, 'init', '-q')
    git(source, 'config', 'user.name', 'Fixture')
    git(source, 'config', 'user.email', 'fixture@example.invalid')
    feedtext = ''.join(f"src-git {r['name']} {r['url']}^{r['commit']}\n" for r in FEEDS)
    (source / 'feeds.conf.default').write_text(feedtext)
    (source / 'README.md').write_text('Pristine upstream baseline\n')
    (source / '.gitignore').write_text('.config\n')
    (source / 'README.link').symlink_to('README.md')
    (source / 'build.sh').write_text('#!/bin/sh\nexit 0\n')
    (source / 'build.sh').chmod(0o755)
    target = source / 'target/linux/mediatek/image/filogic.mk'
    target.parent.mkdir(parents=True)
    target.write_text('define Device/glinet_gl-xe3000\nendef\nTARGET_DEVICES += glinet_gl-xe3000\n')
    dts = source / 'target/linux/mediatek/dts/mt7981a-glinet-gl-xe3000.dts'
    dts.parent.mkdir()
    dts.write_text('/dts-v1/;\n')
    git(source, 'add', '.')
    git(source, 'commit', '-qm', 'fixture baseline')
    sha = git(source, 'rev-parse', 'HEAD')
    (source / 'README.md').write_text('DIRTY EXPERIMENT\n')
    (source / 'untracked-experiment').write_text('MUST NOT COPY\n')
    recipe = project / 'recipe'
    recipe.mkdir()
    data = {'schema_version': 1, 'upstream': {'url': 'https://git.openwrt.org/openwrt/openwrt.git',
            'commit': sha, 'tag': 'fixture-baseline'}, 'feeds': json.loads(json.dumps(FEEDS))}
    (recipe / 'upstream.json').write_text(json.dumps(data))
    (recipe / 'xe3000.config').write_text(SEED)
    return project, source, project / 'build/prepared', data


def invoke(setup, *extra):
    project, source, out, _ = setup
    return firmware.main(['--root', str(project), '--source', str(source), '--out', str(out), *extra])


def test_object_only_independent_checkout_and_verify(setup):
    project, source, out, data = setup
    before = git(source, 'status', '--porcelain')
    assert invoke(setup) == 0
    checkout = out / 'checkout'
    assert (checkout / 'README.md').read_text() == 'Pristine upstream baseline\n'
    assert not (checkout / 'untracked-experiment').exists()
    assert (checkout / '.config').read_text() == SEED
    assert git(checkout, 'rev-parse', 'HEAD') == data['upstream']['commit']
    assert git(checkout, 'rev-parse', '--abbrev-ref', 'HEAD') == 'HEAD'
    assert git(source, 'status', '--porcelain') == before
    assert (source / 'README.md').read_text() == 'DIRTY EXPERIMENT\n'
    manifest = json.loads((out / 'manifest.json').read_text())
    assert manifest['status'] == 'prepared-unconfigured'
    assert manifest['production_ready'] is False and manifest['firmware_build_complete'] is False
    assert manifest['source_commit'] == data['upstream']['commit'] and manifest['feeds'] == FEEDS
    assert manifest['source_date_epoch'] == int(git(source, 'show', '-s', '--format=%ct', data['upstream']['commit']))
    source_object = next((source / '.git/objects').glob('??/*'))
    copied_object = checkout / '.git/objects' / source_object.relative_to(source / '.git/objects')
    assert source_object.stat().st_ino != copied_object.stat().st_ino
    assert invoke(setup, '--verify') == 0


@pytest.mark.parametrize('bad', ['unknown-commit', 'unpinned', 'feed-mismatch', 'seed', 'existing', 'nonempty', 'raw', 'alias', 'source-alias', 'outside', 'overlap'])
def test_refuses_invalid_preparation_without_source_mutation(setup, bad):
    project, source, out, data = setup
    before = git(source, 'status', '--porcelain')
    if bad == 'unknown-commit': data['upstream']['commit'] = '0' * 40
    if bad == 'unpinned': data['feeds'][0] = {**data['feeds'][0], 'commit': 'main'}
    if bad == 'feed-mismatch': data['feeds'][0] = {**data['feeds'][0], 'commit': 'f' * 40}
    if bad == 'seed': (project / 'recipe/xe3000.config').write_text(SEED + 'CONFIG_EXPERIMENT=y\n')
    if bad in ('existing', 'nonempty'): out.mkdir()
    if bad == 'nonempty': (out / 'keep').write_text('untouched')
    if bad == 'outside': out = project / 'not-build'
    if bad == 'raw': out = project / 'build/harvest/raw/new'
    if bad == 'alias':
        (project / 'build/link').symlink_to(project / 'build', target_is_directory=True)
        out = project / 'build/link/new'
    if bad == 'source-alias':
        alias = project / 'build/source-alias'
        alias.symlink_to(source, target_is_directory=True)
        source = alias
    if bad == 'overlap': out = source / 'nested'
    (project / 'recipe/upstream.json').write_text(json.dumps(data))
    assert firmware.main(['--root', str(project), '--source', str(source), '--out', str(out)]) == 2
    assert git(source, 'status', '--porcelain') == before


@pytest.mark.parametrize('tamper', ['tracked', 'seed', 'head', 'feeds', 'untracked', 'manifest'])
def test_verify_refuses_modified_destination(setup, tamper):
    project, source, out, data = setup
    assert invoke(setup) == 0
    checkout = out / 'checkout'
    if tamper == 'tracked': (checkout / 'README.md').write_text('changed')
    if tamper == 'seed': (checkout / '.config').write_text(SEED + 'CONFIG_EXPERIMENT=y\n')
    if tamper == 'feeds': (checkout / 'feeds.conf.default').write_text('changed')
    if tamper == 'untracked': (checkout / 'experiment').write_text('changed')
    if tamper == 'head': git(checkout, 'symbolic-ref', 'HEAD', 'refs/heads/master')
    if tamper == 'manifest':
        manifest = json.loads((out / 'manifest.json').read_text())
        manifest['production_ready'] = True
        (out / 'manifest.json').write_text(json.dumps(manifest))
    assert invoke(setup, '--verify') == 2


def test_preparation_disables_inherited_hooks(setup, monkeypatch, tmp_path):
    hooks = tmp_path / 'inherited-hooks'
    hooks.mkdir()
    marker = tmp_path / 'hook-ran'
    hook = hooks / 'post-checkout'
    hook.write_text('#!/bin/sh\ntouch "' + str(marker) + '"\n')
    hook.chmod(0o755)
    monkeypatch.setenv('GIT_CONFIG_COUNT', '1')
    monkeypatch.setenv('GIT_CONFIG_KEY_0', 'core.hooksPath')
    monkeypatch.setenv('GIT_CONFIG_VALUE_0', str(hooks))
    assert invoke(setup) == 0
    assert not marker.exists()


@pytest.mark.parametrize('flag', ['--assume-unchanged', '--skip-worktree'])
def test_verify_reads_tracked_bytes_despite_index_flags_and_preserved_stat(setup, flag):
    import os
    project, source, out, _ = setup
    assert invoke(setup) == 0
    path = out / 'checkout/README.md'
    info = path.stat()
    size = len(path.read_bytes())
    git(out / 'checkout', 'update-index', flag, 'README.md')
    path.write_bytes(b'X' * size)
    os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
    assert invoke(setup, '--verify') == 2


def test_source_promisor_refused_without_fetch_helper_or_object_mutation(setup, tmp_path):
    project, source, out, _ = setup
    companion = tmp_path / 'companion.git'
    git(source, 'clone', '--bare', '--no-hardlinks', str(source), str(companion))
    blob = git(source, 'rev-parse', 'HEAD:feeds.conf.default')
    object_path = source / '.git/objects' / blob[:2] / blob[2:]
    object_path.unlink()
    marker = tmp_path / 'helper-ran'
    git(source, 'config', 'remote.evil.url', str(companion))
    git(source, 'config', 'remote.evil.promisor', 'true')
    git(source, 'config', 'remote.evil.uploadpack', f'touch {marker}; git-upload-pack')
    assert invoke(setup) == 2
    assert not marker.exists() and not object_path.exists()
    assert not out.exists()


def test_tracked_config_symlink_cannot_overwrite_external_file(setup, tmp_path):
    project, source, out, data = setup
    victim = tmp_path / 'external-victim'
    victim.write_text('ORIGINAL VICTIM')
    (source / '.config').symlink_to(victim)
    git(source, 'add', '-f', '.config')
    git(source, 'commit', '-qm', 'config symlink')
    data['upstream']['commit'] = git(source, 'rev-parse', 'HEAD')
    (project / 'recipe/upstream.json').write_text(json.dumps(data))
    assert invoke(setup) == 2
    assert victim.read_text() == 'ORIGINAL VICTIM'


def test_counterfeit_loose_blob_refused_before_checkout(setup):
    import zlib
    project, source, out, _ = setup
    blob = git(source, 'rev-parse', 'HEAD:README.md')
    object_path = source / '.git/objects' / blob[:2] / blob[2:]
    counterfeit = b'COUNTERFEIT UPSTREAM SOURCE\n'
    object_path.chmod(0o600)
    object_path.write_bytes(zlib.compress(b'blob ' + str(len(counterfeit)).encode() + b'\0' + counterfeit))
    assert invoke(setup) == 2
    assert not out.exists()


def test_source_include_refused_without_reading_included_env_or_running_git(setup, monkeypatch, tmp_path):
    import io
    project, source, out, _ = setup
    included = tmp_path / '.env'
    included.write_text('SYNTHETIC_FILE_MUST_NOT_BE_READ')
    with (source / '.git/config').open('a') as handle:
        handle.write(f'\n[include]\n\tpath = {included}\n')
    real_open = io.open

    def guarded_open(path, *args, **kwargs):
        assert Path(path) != included, 'Git include content was read'
        return real_open(path, *args, **kwargs)

    def no_git_before_rejection(*args, **kwargs):
        pytest.fail('Git process started before unsafe source settings were refused')

    monkeypatch.setattr(io, 'open', guarded_open)
    monkeypatch.setattr(subprocess, 'run', no_git_before_rejection)
    assert invoke(setup) == 2
    assert not out.exists()


def test_checked_in_recipe_records_expected_baseline_and_exact_target_seed():
    data = json.loads((REPO / 'recipe/upstream.json').read_text())
    assert data['upstream']['commit'] == '64900e756efa667774214f9c6b17c113222e01f7'
    assert data['upstream']['tag'] == 'v25.12.6'
    assert [feed['name'] for feed in data['feeds']] == [feed['name'] for feed in FEEDS]
    assert all(len(feed['commit']) == 40 and all(c in '0123456789abcdef' for c in feed['commit']) for feed in data['feeds'])
    assert (REPO / 'recipe/xe3000.config').read_text() == SEED


@pytest.mark.parametrize('tamper', ['executable', 'symlink-mode', 'symlink-target'])
def test_verify_checks_tracked_modes_and_symlink_targets_without_following(setup, tamper, tmp_path):
    project, source, out, _ = setup
    assert invoke(setup) == 0
    checkout = out / 'checkout'
    if tamper == 'executable': (checkout / 'build.sh').chmod(0o644)
    if tamper == 'symlink-mode':
        (checkout / 'README.link').unlink()
        (checkout / 'README.link').write_text('README.md')
    if tamper == 'symlink-target':
        victim = tmp_path / 'victim'
        victim.write_text('UNCHANGED')
        (checkout / 'README.link').unlink()
        (checkout / 'README.link').symlink_to(victim)
    assert invoke(setup, '--verify') == 2
    if tamper == 'symlink-target': assert victim.read_text() == 'UNCHANGED'


def test_indented_unsafe_section_cannot_hide_in_configparser_continuation(setup, monkeypatch):
    project, source, out, _ = setup
    with (source / '.git/config').open('a') as handle:
        handle.write('    [extensions]\n    partialClone = evil\n')
    def no_git_before_rejection(*args, **kwargs):
        pytest.fail('unsafe config grammar reached Git process')
    monkeypatch.setattr(subprocess, 'run', no_git_before_rejection)
    assert invoke(setup) == 2


def test_verify_refuses_extra_file_even_when_added_to_mutable_index(setup):
    project, source, out, _ = setup
    assert invoke(setup) == 0
    checkout = out / 'checkout'
    (checkout / 'staged-experiment').write_text('not upstream')
    git(checkout, 'add', 'staged-experiment')
    assert invoke(setup, '--verify') == 2


@pytest.mark.parametrize('alias', ['commondir', 'gitdir', 'config.worktree', 'objects/info/alternates', 'objects/info/http-alternates'])
@pytest.mark.parametrize('phase', ['prepare', 'verify'])
def test_git_metadata_indirection_refused_before_external_config_or_git(setup, monkeypatch, tmp_path, alias, phase):
    import io
    project, source, out, _ = setup
    companion = tmp_path / 'companion.git'
    git(source, 'clone', '--bare', '--no-hardlinks', str(source), str(companion))
    external = tmp_path / '.env'
    external.write_text('# SYNTHETIC EXTERNAL FILE MUST NOT BE READ\n')
    git(companion, 'config', 'fsck.skipList', str(external))
    if phase == 'verify':
        assert invoke(setup) == 0
    directory = source if phase == 'prepare' else out / 'checkout'
    alias_file = directory / '.git' / alias
    alias_file.parent.mkdir(parents=True, exist_ok=True)
    alias_file.write_text(str(companion) + '\n')
    real_open = io.open

    def guarded_open(path, *args, **kwargs):
        assert Path(path) not in (external, companion / 'config'), 'external Git metadata was read'
        return real_open(path, *args, **kwargs)

    def no_git_before_rejection(*args, **kwargs):
        pytest.fail('Git process started before metadata indirection rejection')

    monkeypatch.setattr(io, 'open', guarded_open)
    monkeypatch.setattr(subprocess, 'run', no_git_before_rejection)
    assert invoke(setup, *(['--verify'] if phase == 'verify' else [])) == 2
