"""Offline upstream source-baseline preparation. This does not configure or build firmware."""
from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

UPSTREAM = 'https://git.openwrt.org/openwrt/openwrt.git'
FEED_NAMES = ('packages', 'luci', 'routing', 'telephony', 'video')
SEED = (b'CONFIG_TARGET_mediatek=y\nCONFIG_TARGET_mediatek_filogic=y\n'
        b'CONFIG_TARGET_mediatek_filogic_DEVICE_glinet_gl-xe3000=y\n')
PROFILE = 'target/linux/mediatek/image/filogic.mk'
DTS = 'target/linux/mediatek/dts/mt7981a-glinet-gl-xe3000.dts'
# A fixed local configuration prevents copied/user-added Git filters or includes.
GIT_CONFIG = (f'[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n'
              f'\tlogallrefupdates = true\n[remote "origin"]\n\turl = {UPSTREAM}\n'
              '\tfetch = +refs/heads/*:refs/remotes/origin/*\n').encode()


class FirmwareError(RuntimeError):
    """Content-free refusal."""


def _path(path: Path) -> Path:
    if '..' in Path(path).parts:
        raise FirmwareError('parent traversal refused')
    path = Path(os.path.abspath(path))
    if any(a == 'harvest' and b == 'raw' for a, b in zip(path.parts, path.parts[1:])):
        raise FirmwareError('raw path refused')
    for candidate in reversed((path, *path.parents)):
        try:
            mode = candidate.lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode) or (candidate != path and not stat.S_ISDIR(mode)):
            raise FirmwareError('path alias refused')
    return path


def _file(path: Path) -> bytes:
    path = _path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise FirmwareError('non-regular or linked file refused')
    return path.read_bytes()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git(directory: Path, *args: str, allowed=(0,)) -> subprocess.CompletedProcess:
    env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_TERMINAL_PROMPT='0',
               GIT_NO_REPLACE_OBJECTS='1', GIT_GRAFT_FILE='/dev/null', GIT_NO_LAZY_FETCH='1')
    result = subprocess.run(['git', '--no-optional-locks', '-c', 'core.hooksPath=/dev/null',
                             '-c', 'core.fsmonitor=false', '-c', 'core.attributesFile=/dev/null',
                             '-c', 'protocol.allow=never', '-c', 'protocol.file.allow=always',
                             '-C', str(directory), *args], capture_output=True, env=env)
    if result.returncode not in allowed:
        raise FirmwareError('Git operation refused')
    return result


def _metadata_safe(directory: Path) -> None:
    gitdir = _path(directory / '.git')
    if not gitdir.is_dir():
        raise FirmwareError('Git metadata directory refused')
    indirect = ('commondir', 'gitdir', 'config.worktree',
                'objects/info/alternates', 'objects/info/http-alternates')
    if any(os.path.lexists(gitdir / name) for name in indirect):
        raise FirmwareError('standalone Git metadata required')
    for base, dirs, files in os.walk(gitdir, followlinks=False):
        for name in (*dirs, *files):
            mode = (Path(base) / name).lstat().st_mode
            if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                raise FirmwareError('Git metadata alias or special file refused')


def _source_settings(source: Path) -> None:
    # Parse only this physical file with stdlib. No Git setup, includes, helpers,
    # object lookup, or lazy fetch may occur before this allowlist passes.
    parser = configparser.RawConfigParser(strict=True, allow_no_value=True, delimiters=('=',))
    try:
        text = _file(source / '.git/config').decode()
        if any(line[:1].isspace() and line.lstrip().startswith('[') for line in text.splitlines()):
            raise FirmwareError('ambiguous Git configuration refused')
        parser.read_string(text)
    except (configparser.Error, UnicodeError):
        raise FirmwareError('source Git configuration refused') from None
    if parser.defaults():
        raise FirmwareError('source Git configuration refused')
    for section in parser.sections():
        lowered = section.lower()
        if lowered == 'core':
            allowed = {'repositoryformatversion', 'filemode', 'bare', 'logallrefupdates',
                       'ignorecase', 'precomposeunicode', 'symlinks'}
        elif lowered == 'user':
            allowed = {'name', 'email'}
        elif re.fullmatch(r'remote "[A-Za-z0-9_.-]+"', section):
            allowed = {'url', 'fetch'}
            url = parser.get(section, 'url', fallback='')
            if not url or not re.fullmatch(r'https://[A-Za-z0-9._/-]+', url):
                raise FirmwareError('source remote configuration refused')
        elif re.fullmatch(r'branch "[A-Za-z0-9_./-]+"', section):
            allowed = {'remote', 'merge', 'rebase'}
        else:
            raise FirmwareError('source Git configuration refused')
        if any(value is not None and '\n' in value for value in parser[section].values()):
            raise FirmwareError('multiline Git configuration refused')
        if not set(parser[section]) <= allowed:
            raise FirmwareError('source Git configuration refused')
    if parser.get('core', 'repositoryformatversion', fallback='0') != '0':
        raise FirmwareError('source object format refused')


def _integrity(directory: Path, pin: str) -> None:
    _git(directory, 'fsck', '--strict', '--no-reflogs', '--no-dangling', pin)


def _tracked_bytes(checkout: Path, pin: str) -> None:
    # Compare worktree bytes directly with commit blob IDs. The mutable index,
    # stat cache, assume-unchanged/skip-worktree flags and filters are irrelevant.
    rows = list(filter(None, _git(checkout, 'ls-tree', '-rz', pin).stdout.split(b'\0')))
    expected_names = {os.fsdecode(row.split(b'\t', 1)[1]) for row in rows}
    expected_dirs = {parent.as_posix() for name in expected_names for parent in Path(name).parents
                     if parent != Path('.')}
    found, found_dirs = set(), set()
    for base, dirs, files in os.walk(checkout, followlinks=False):
        if Path(base) == checkout:
            dirs.remove('.git')
        for name in (*dirs, *files):
            path = Path(base) / name
            rel = path.relative_to(checkout).as_posix()
            if stat.S_ISDIR(path.lstat().st_mode):
                found_dirs.add(rel)
            else:
                found.add(rel)
    if found != expected_names | {'.config'} or found_dirs != expected_dirs:
        raise FirmwareError('unexpected checkout entries')
    for row in rows:
        header, name = row.split(b'\t', 1)
        mode, kind, expected = header.split()
        rel = Path(os.fsdecode(name))
        if rel.is_absolute() or any(part in (b'', b'.', b'..') for part in name.split(b'/')):
            raise FirmwareError('tracked source path refused')
        path = _path(checkout / rel.parent) / rel.name
        info = path.lstat()
        if mode == b'120000' and kind == b'blob':
            if not stat.S_ISLNK(info.st_mode):
                raise FirmwareError('tracked symlink changed')
            content = os.fsencode(os.readlink(path))
        elif mode in (b'100644', b'100755') and kind == b'blob':
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_mode & 0o111 != (0o111 if mode == b'100755' else 0)):
                raise FirmwareError('tracked source mode changed')
            content = _file(path)
        else:
            raise FirmwareError('unsupported tracked source mode')
        digest = hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest().encode()
        if digest != expected:
            raise FirmwareError('tracked source content changed')


def _recipe(path: Path) -> tuple[dict, bytes, bytes, bytes]:
    raw = _file(path)
    data = json.loads(raw)
    if not isinstance(data, dict) or set(data) != {'schema_version', 'upstream', 'feeds'} or data['schema_version'] != 1:
        raise FirmwareError('recipe schema refused')
    upstream, feeds = data['upstream'], data['feeds']
    if (not isinstance(upstream, dict) or set(upstream) != {'url', 'commit', 'tag'}
            or upstream['url'] != UPSTREAM or not isinstance(upstream['commit'], str)
            or not re.fullmatch('[0-9a-f]{40}', upstream['commit'])
            or not isinstance(upstream['tag'], str) or not re.fullmatch('[A-Za-z0-9_.-]{1,80}', upstream['tag'])):
        raise FirmwareError('upstream pin refused')
    if not isinstance(feeds, list) or len(feeds) != len(FEED_NAMES):
        raise FirmwareError('feed pins refused')
    for name, row in zip(FEED_NAMES, feeds):
        if (not isinstance(row, dict) or set(row) != {'name', 'url', 'commit'} or row['name'] != name
                or not isinstance(row['commit'], str) or not re.fullmatch('[0-9a-f]{40}', row['commit'])
                or not isinstance(row['url'], str) or not re.fullmatch(r'https://[A-Za-z0-9./_-]+\.git', row['url'])):
            raise FirmwareError('feed pins refused')
    expected = ''.join(f"src-git {row['name']} {row['url']}^{row['commit']}\n" for row in feeds).encode()
    seed = _file(path.parent / 'xe3000.config')
    if seed != SEED:
        raise FirmwareError('target seed refused')
    return data, raw, seed, expected


def _objects(directory: Path, data: dict, expected_feeds: bytes) -> int:
    pin = data['upstream']['commit']
    if _git(directory, 'cat-file', '-t', pin).stdout.strip() != b'commit':
        raise FirmwareError('source commit missing')
    if _git(directory, 'show', f'{pin}:feeds.conf.default').stdout != expected_feeds:
        raise FirmwareError('upstream feed pins differ from recipe')
    profile = _git(directory, 'show', f'{pin}:{PROFILE}').stdout
    if b'define Device/glinet_gl-xe3000\n' not in profile:
        raise FirmwareError('upstream device profile missing')
    _git(directory, 'cat-file', '-e', f'{pin}:{DTS}')
    epoch = _git(directory, 'show', '-s', '--format=%ct', pin).stdout.strip()
    if not epoch.isdigit():
        raise FirmwareError('source timestamp refused')
    return int(epoch)


def _manifest(data: dict, recipe: bytes, seed: bytes, epoch: int) -> dict:
    return {'schema_version': 1, 'status': 'prepared-unconfigured', 'production_ready': False,
            'firmware_build_complete': False, 'source_url': data['upstream']['url'],
            'source_commit': data['upstream']['commit'], 'tag_label': data['upstream']['tag'],
            'feeds': data['feeds'], 'source_date_epoch': epoch, 'seed_sha256': _sha(seed),
            'recipe_sha256': _sha(recipe)}


def _locations(root: Path, source: Path, out: Path) -> tuple[Path, Path, Path]:
    root, source, out = _path(root), _path(source), _path(out)
    build = _path(root / 'build')
    if (not root.is_dir() or out == build or not out.is_relative_to(build)
            or out == source or out.is_relative_to(source) or source.is_relative_to(out)):
        raise FirmwareError('destination must be independent under project build')
    return root, source, out


def prepare(root: Path, source: Path, out: Path, recipe: Path) -> Path:
    root, source, out = _locations(root, source, out)
    recipe = _path(recipe)
    if out.exists() or not source.is_dir() or not _path(source / '.git').is_dir():
        raise FirmwareError('source or new destination refused')
    _metadata_safe(source)
    _source_settings(source)
    data, raw, seed, expected = _recipe(recipe)
    pin = data['upstream']['commit']
    _integrity(source, pin)
    if _git(source, 'ls-tree', '-z', pin, '--', '.config').stdout:
        raise FirmwareError('upstream tracks target config')
    epoch = _objects(source, data, expected)
    out.parent.mkdir(parents=True, exist_ok=True)
    _path(out.parent)
    out.mkdir()
    try:
        checkout = out / 'checkout'
        _git(root, 'clone', '--local', '--no-hardlinks', '--no-checkout', '--', str(source), str(checkout))
        (checkout / '.git/config').write_bytes(GIT_CONFIG)
        _git(checkout, 'checkout', '--detach', data['upstream']['commit'])
        fd = os.open(checkout / '.config', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(seed)
        (out / 'manifest.json').write_text(json.dumps(_manifest(data, raw, seed, epoch), indent=2, sort_keys=True) + '\n')
        verify(root, source, out, recipe)
    except Exception:
        # A partial stage is retained for inspection but never claims preparation succeeded.
        (out / 'manifest.json').write_text(json.dumps({'status': 'failed', 'production_ready': False,
                                                     'firmware_build_complete': False}) + '\n')
        raise FirmwareError('source preparation failed') from None
    return out


def verify(root: Path, source: Path, out: Path, recipe: Path) -> Path:
    root, source, out = _locations(root, source, out)
    data, raw, seed, expected = _recipe(_path(recipe))
    checkout = _path(out / 'checkout')
    _metadata_safe(checkout)
    if _file(checkout / '.git/config') != GIT_CONFIG or (checkout / '.git/objects/info/alternates').exists():
        raise FirmwareError('checkout Git settings changed')
    _integrity(checkout, data['upstream']['commit'])
    if _git(checkout, 'rev-parse', 'HEAD').stdout.strip().decode() != data['upstream']['commit']:
        raise FirmwareError('checkout commit changed')
    if _git(checkout, 'symbolic-ref', '-q', 'HEAD', allowed=(0, 1)).returncode != 1:
        raise FirmwareError('checkout must remain detached')
    epoch = _objects(checkout, data, expected)
    if _file(checkout / 'feeds.conf.default') != expected or _file(checkout / '.config') != seed:
        raise FirmwareError('checkout feeds or target seed changed')
    _tracked_bytes(checkout, data['upstream']['commit'])
    manifest = json.loads(_file(out / 'manifest.json'))
    if manifest != _manifest(data, raw, seed, epoch):
        raise FirmwareError('source preparation manifest changed')
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('.'))
    parser.add_argument('--source', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--recipe', type=Path)
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args(argv)
    try:
        root = _path(args.root)
        action = verify if args.verify else prepare
        action(root, args.source or root / 'build/openwrt', args.out, args.recipe or root / 'recipe/upstream.json')
    except (FirmwareError, OSError, ValueError, TypeError, KeyError, UnicodeError):
        print('firmware: refused; no verified source preparation', file=sys.stderr)
        return 2
    print('firmware: source prepared and verified; unconfigured, firmware build incomplete')
    return 0
