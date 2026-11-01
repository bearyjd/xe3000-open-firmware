"""Recorded OpenWrt configure/compile stages in an independent workspace."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
from pathlib import Path
import subprocess
import sys
import tarfile

import firmware as fw

TARGET = 'CONFIG_TARGET_mediatek_filogic_DEVICE_glinet_gl-xe3000=y'


def save(out, record):
    fw._path(out / 'build-record.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')


def environment(out, epoch):
    return {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(out / 'home'),
            'TMPDIR': str(out / 'tmp'), 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
            'TZ': 'UTC', 'SHELL': '/bin/sh', 'SOURCE_DATE_EPOCH': str(epoch),
            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
            'GIT_TERMINAL_PROMPT': '0', 'GIT_NO_REPLACE_OBJECTS': '1',
            'GIT_NO_LAZY_FETCH': '1', 'GIT_ALLOW_PROTOCOL': 'https', 'GIT_CONFIG_COUNT': '5',
            'GIT_CONFIG_KEY_0': 'core.hooksPath', 'GIT_CONFIG_VALUE_0': '/dev/null',
            'GIT_CONFIG_KEY_1': 'core.fsmonitor', 'GIT_CONFIG_VALUE_1': 'false',
            'GIT_CONFIG_KEY_2': 'core.attributesFile', 'GIT_CONFIG_VALUE_2': '/dev/null',
            'GIT_CONFIG_KEY_3': 'credential.helper', 'GIT_CONFIG_VALUE_3': '',
            'GIT_CONFIG_KEY_4': 'protocol.allow', 'GIT_CONFIG_VALUE_4': 'never'}


def tracked(repo, pin, *, exact=False):
    """Compare bytes/modes against commit objects, independent of index caches."""
    expected = set()
    for row in fw._git(repo, 'ls-tree', '-rz', pin).stdout.split(b'\0'):
        if not row:
            continue
        header, name = row.split(b'\t', 1)
        mode, kind, digest = header.split()
        rel = Path(os.fsdecode(name))
        path = fw._path(repo / rel.parent) / rel.name
        expected.add(rel.as_posix())
        info = path.lstat()
        if mode == b'120000' and stat.S_ISLNK(info.st_mode):
            raw = os.fsencode(os.readlink(path))
        elif mode in (b'100644', b'100755') and stat.S_ISREG(info.st_mode):
            if info.st_mode & 0o111 != (0o111 if mode == b'100755' else 0):
                raise fw.FirmwareError('tracked executable mode changed')
            raw = fw._file(path)
        else:
            raise fw.FirmwareError('tracked entry refused')
        if kind != b'blob' or hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest().encode() != digest:
            raise fw.FirmwareError('tracked bytes changed')
    if exact:
        found = set()
        for base, dirs, files in os.walk(repo, followlinks=False):
            if Path(base) == repo:
                dirs.remove('.git')
            for name in (*dirs, *files):
                path = Path(base) / name
                if not path.is_dir() or path.is_symlink():
                    found.add(path.relative_to(repo).as_posix())
        if found != expected:
            raise fw.FirmwareError('unexpected feed files')


def run(out, record, name, argv):
    record['commands'].append({'name': name, 'argv': argv})
    save(out, record)
    log = fw._path(out / 'logs' / (name + '.log'))
    with log.open('xb') as handle:
        result = subprocess.run(argv, cwd=out / 'checkout', env=record['environment'],
                                stdout=handle, stderr=subprocess.STDOUT)
    record['commands'][-1]['returncode'] = result.returncode
    save(out, record)
    if result.returncode:
        raise fw.FirmwareError('build command failed')


def heads(out, data):
    actual = {}
    feeds = fw._path(out / 'checkout/feeds')
    base = feeds / 'base'
    if os.path.lexists(base) and (not base.is_symlink() or os.readlink(base) != '../package'):
        raise fw.FirmwareError('base feed alias refused')
    if {p.name for p in feeds.iterdir() if p.is_dir() and not p.name.endswith('.tmp') and p.name != 'base'} != set(fw.FEED_NAMES):
        raise fw.FirmwareError('unexpected feed directories')
    for row in data['feeds']:
        repo = fw._path(feeds / row['name'])
        fw._metadata_safe(repo)
        fw._source_settings(repo)
        actual[row['name']] = fw._git(repo, 'rev-parse', 'HEAD').stdout.decode().strip()
        if actual[row['name']] != row['commit']:
            raise fw.FirmwareError('feed pin mismatch')
        if (fw._git(repo, 'symbolic-ref', '-q', 'HEAD', allowed=(0, 1)).returncode != 1
                or fw._git(repo, 'config', '--get', 'remote.origin.url').stdout.decode().strip() != row['url']):
            raise fw.FirmwareError('feed origin or detached HEAD mismatch')
        fw._integrity(repo, row['commit'])
        tracked(repo, row['commit'], exact=True)
    return actual


def config(out):
    raw = fw._file(out / 'checkout/.config')
    lines = raw.decode().splitlines()
    targets = [line for line in lines if line.startswith('CONFIG_TARGET_') and line.endswith('=y')
               and '_DEVICE_' in line]
    if (targets != [TARGET] or 'CONFIG_TARGET_mediatek=y' not in lines
            or 'CONFIG_TARGET_mediatek_filogic=y' not in lines):
        raise fw.FirmwareError('resolved target mismatch')
    return fw._sha(raw)


def inputs(checkout):
    result = {}
    for base, dirs, files in os.walk(checkout, followlinks=False):
        if '.git' in dirs:
            rel = (Path(base) / '.git').relative_to(checkout).as_posix()
            if rel not in {'.git', *(f'feeds/{name}/.git' for name in fw.FEED_NAMES)}:
                raise fw.FirmwareError('unexpected nested Git metadata')
            dirs.remove('.git')
        for name in (*dirs, *files):
            path = Path(base) / name
            info = path.lstat()
            rel = path.relative_to(checkout).as_posix()
            if stat.S_ISLNK(info.st_mode):
                result[rel] = ['symlink', os.readlink(path)]
            elif stat.S_ISREG(info.st_mode):
                result[rel] = [info.st_mode & 0o777, fw._sha(fw._file(path))]
            elif not stat.S_ISDIR(info.st_mode):
                raise fw.FirmwareError('special build input refused')
    return result


def host_info(env):
    tools = {}
    for tool in ('git', 'make', 'gcc', 'g++', 'python3', 'ld'):
        result = subprocess.run([tool, '--version'], env=env, capture_output=True, check=True)
        tools[tool] = result.stdout.decode().splitlines()[0]
    inventory = (['dpkg-query', '-W', '-f=${Package}\t${Version}\n']
                 if shutil.which('dpkg-query', path=env['PATH'])
                 else ['rpm', '-qa', '--qf', '%{NAME}\t%{VERSION}-%{RELEASE}\n'])
    packages = subprocess.run(inventory, env=env, capture_output=True, check=True)
    return {'os_release': Path('/etc/os-release').read_text(), 'uname': list(os.uname()),
            'tools': tools, 'packages': sorted(packages.stdout.decode().splitlines())}


def configure(root, baseline, out, recipe, environment_id):
    fw._locations(root, baseline, out)
    # verify's source argument is only a separation guard; it never reads it.
    fw.verify(root, root / 'build/openwrt', baseline, recipe)
    fw.prepare(root, baseline / 'checkout', out, recipe)
    record = {'schema_version': 1, 'status': 'configuring', 'firmware_build_complete': False,
              'production_ready': False, 'reproducible': False, 'commands': [],
              'baseline': str(baseline), 'environment_id': environment_id,
              'recipe': str(recipe),
              'preparation_manifest_sha256': fw._sha(fw._file(out / 'manifest.json'))}
    try:
        manifest = json.loads(fw._file(out / 'manifest.json'))
        record['environment'] = environment(out, manifest['source_date_epoch'])
        for name in ('logs', 'home', 'tmp'):
            (out / name).mkdir()
        record.update(host_info(record['environment']))
        data, *_ = fw._recipe(recipe)
        run(out, record, 'feeds-update', ['./scripts/feeds', 'update', '-a'])
        record['feed_heads'] = heads(out, data)
        run(out, record, 'feeds-install', ['./scripts/feeds', 'install', '-a'])
        record['feed_heads'] = heads(out, data)
        run(out, record, 'defconfig', ['make', 'defconfig',
                                      'SOURCE_DATE_EPOCH=' + record['environment']['SOURCE_DATE_EPOCH']])
        record['config_sha256'] = config(out)
        snapshot = json.dumps(inputs(out / 'checkout'), sort_keys=True).encode()
        (out / 'configured-inputs.json').write_bytes(snapshot)
        record['configured_inputs_sha256'] = fw._sha(snapshot)
        record['status'] = 'configured'
        save(out, record)
    except BaseException:
        record['status'] = 'failed'
        save(out, record)
        raise


def inspect(out, record, data, epoch):
    directory = fw._path(out / 'checkout/bin/targets/mediatek/filogic')
    metadata = json.loads(fw._file(directory / 'profiles.json'))
    profile = metadata['profiles']['glinet_gl-xe3000']
    if (metadata['target'] != 'mediatek/filogic'
            or metadata['version_number'] != data['upstream']['tag'].removeprefix('v')
            or not metadata['version_code'] or metadata['source_date_epoch'] != epoch
            or profile['supported_devices'] != ['glinet,gl-xe3000']
            or not profile['device_packages']):
        raise fw.FirmwareError('image metadata mismatch')
    images = profile['images']
    if not {'factory', 'sysupgrade'} <= {row['type'] for row in images}:
        raise fw.FirmwareError('expected device images missing')
    names = set()
    for image in images:
        name = image['name']
        if (not isinstance(name, str) or Path(name).name != name or 'glinet_gl-xe3000' not in name
                or name in names):
            raise fw.FirmwareError('image name refused')
        names.add(name)
        raw = fw._file(directory / name)
        if not raw or fw._sha(raw) != image['sha256'] or len(raw) != image['size']:
            raise fw.FirmwareError('image hash or size mismatch')
    inventories = list(directory.glob('*.manifest'))
    if len(inventories) != 1:
        raise fw.FirmwareError('unique package manifest required')
    inventory = fw._file(inventories[0]).decode().splitlines()
    if not inventory or any(' - ' not in line for line in inventory):
        raise fw.FirmwareError('package inventory refused')
    installed = {line.split(' - ', 1)[0] for line in inventory}
    if not {name for name in profile['device_packages'] if not name.startswith('-')} <= installed:
        raise fw.FirmwareError('profile packages missing from inventory')
    for name in ('config.buildinfo', 'feeds.buildinfo', 'version.buildinfo'):
        if not fw._file(directory / name):
            raise fw.FirmwareError('build metadata missing')
    if fw._file(directory / 'version.buildinfo').decode().strip() != metadata['version_code']:
        raise fw.FirmwareError('image revision differs from buildinfo')
    expected_feeds = fw._recipe(Path(record['recipe']))[3]
    if fw._file(directory / 'feeds.buildinfo') != expected_feeds:
        raise fw.FirmwareError('image feed buildinfo mismatch')
    buildconfig = fw._file(directory / 'config.buildinfo').decode().splitlines()
    resolved = set(fw._file(out / 'checkout/.config').decode().splitlines())
    if TARGET not in buildconfig or any(line.startswith('CONFIG_') and line not in resolved for line in buildconfig):
        raise fw.FirmwareError('image config buildinfo mismatch')
    sysupgrade = next(row for row in images if row['type'] == 'sysupgrade')
    image = directory / sysupgrade['name']
    with tarfile.open(image, 'r:') as archive:
        prefix = 'sysupgrade-glinet_gl-xe3000/'
        for name in ('CONTROL', 'kernel', 'root'):
            member = archive.getmember(prefix + name)
            if not member.isfile() or not member.size:
                raise fw.FirmwareError('sysupgrade container content refused')
        if archive.extractfile(prefix + 'CONTROL').read() != b'BOARD=glinet_gl-xe3000\n':
            raise fw.FirmwareError('sysupgrade container board mismatch')
    tool = fw._path(out / 'checkout/staging_dir/host/bin/fwtool')
    fw._file(tool)
    extracted = fw._path(out / 'image-metadata.json')
    if os.path.lexists(extracted):
        raise fw.FirmwareError('metadata output must be new')
    run(out, record, 'image-metadata', [str(tool), '-i', str(extracted), str(image)])
    embedded = json.loads(fw._file(extracted))
    if (embedded['supported_devices'] != ['glinet,gl-xe3000'] or embedded['version'] != {
            'dist': 'OpenWrt', 'version': metadata['version_number'],
            'revision': metadata['version_code'], 'target': 'mediatek/filogic', 'board': 'glinet_gl-xe3000'}):
        raise fw.FirmwareError('embedded firmware metadata mismatch')
    artifacts = []
    for path in sorted(directory.iterdir()):
        if path.is_dir() and not path.is_symlink():
            continue
        raw = fw._file(path)
        artifacts.append({'path': path.relative_to(out / 'checkout').as_posix(),
                          'sha256': fw._sha(raw), 'size': len(raw)})
    return {'artifacts': artifacts, 'images': images, 'profile': profile,
            'image_metadata': metadata, 'embedded_metadata': embedded, 'package_inventory': inventory}


def compile_stage(root, baseline, out, recipe, environment_id, jobs):
    fw._locations(root, baseline, out)
    record = json.loads(fw._file(out / 'build-record.json'))
    if record['status'] != 'configured':
        raise fw.FirmwareError('configured stage required')
    try:
        if record['production_ready'] is not False or record['reproducible'] is not False:
            raise fw.FirmwareError('invalid readiness claim')
        record['status'] = 'compiling'
        save(out, record)
        data, recipe_raw, seed, _ = fw._recipe(recipe)
        manifest = fw._file(out / 'manifest.json')
        prepared = json.loads(manifest)
        if (record['environment_id'] != environment_id or record['baseline'] != str(baseline)
                or record['preparation_manifest_sha256'] != fw._sha(manifest)
                or prepared != fw._manifest(data, recipe_raw, seed, prepared['source_date_epoch'])
                or record['environment'] != environment(out, prepared['source_date_epoch'])
                or record['config_sha256'] != config(out)):
            raise fw.FirmwareError('configured inputs changed')
        if not 1 <= jobs <= 64:
            raise fw.FirmwareError('jobs outside bounded range')
        checkout = fw._path(out / 'checkout')
        if any(record[key] != value for key, value in host_info(record['environment']).items()):
            raise fw.FirmwareError('build environment changed')
        snapshot = fw._file(out / 'configured-inputs.json')
        if (fw._sha(snapshot) != record['configured_inputs_sha256']
                or json.loads(snapshot) != inputs(checkout)):
            raise fw.FirmwareError('configured build inputs changed')
        fw._metadata_safe(checkout)
        if fw._file(checkout / '.git/config') != fw.GIT_CONFIG:
            raise fw.FirmwareError('source Git settings changed')
        if fw._git(checkout, 'rev-parse', 'HEAD').stdout.decode().strip() != data['upstream']['commit']:
            raise fw.FirmwareError('source HEAD changed')
        tracked(checkout, data['upstream']['commit'])
        record['feed_heads'] = heads(out, data)
        if (checkout / 'bin').exists():
            raise fw.FirmwareError('preexisting output refused')
        run(out, record, 'compile', ['make', f'-j{jobs}', 'V=s',
                                    'SOURCE_DATE_EPOCH=' + record['environment']['SOURCE_DATE_EPOCH']])
        tracked(checkout, data['upstream']['commit'])
        record['feed_heads'] = heads(out, data)
        if record['config_sha256'] != config(out):
            raise fw.FirmwareError('configuration changed during compile')
        record.update(inspect(out, record, data, prepared['source_date_epoch']))
        record['status'] = 'compiled-inspected'
        record['firmware_build_complete'] = True
        save(out, record)
    except BaseException:
        record['status'] = 'failed'
        record['firmware_build_complete'] = False
        record['production_ready'] = False
        record['reproducible'] = False
        save(out, record)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('.'))
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--recipe', type=Path)
    parser.add_argument('--environment-id', default='unidentified-host')
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument('--configure', action='store_true')
    actions.add_argument('--compile', action='store_true')
    parser.add_argument('--jobs', type=int, default=2)
    args = parser.parse_args(argv)
    try:
        root, baseline, out = map(fw._path, (args.root, args.baseline, args.out))
        recipe = args.recipe or root / 'recipe/upstream.json'
        if args.configure:
            configure(root, baseline, out, recipe, args.environment_id)
        else:
            compile_stage(root, baseline, out, recipe, args.environment_id, args.jobs)
    except (fw.FirmwareError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError):
        print('firmware build: refused or failed; inspect stage record and logs', file=sys.stderr)
        return 2
    print('firmware build: configured' if args.configure else 'firmware build: compiled and inspected; hardware acceptance pending')
    return 0


if __name__ == '__main__':
    sys.exit(main())
