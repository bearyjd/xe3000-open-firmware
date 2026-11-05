"""Public build CLI with synthetic local Git feeds and real make processes."""
import hashlib
import json
import os
import shutil
from pathlib import Path
import subprocess

import pytest

from conftest import REPO
from test_firmware import setup, git

pytestmark = pytest.mark.skipif(any(shutil.which(tool) is None for tool in ('make', 'gcc', 'g++', 'ld')),
                                reason='build-process tests require host build tools')


@pytest.fixture
def build_case(setup):
    project, source, baseline, data = setup
    feeds = project / 'local-feeds'
    feeds.mkdir()
    for row in data['feeds']:
        repo = feeds / row['name']
        repo.mkdir()
        git(repo, 'init', '-q')
        git(repo, 'config', 'user.name', 'Fixture')
        git(repo, 'config', 'user.email', 'fixture@example.invalid')
        (repo / 'README').write_text('pinned feed\n')
        git(repo, 'add', '.')
        git(repo, 'commit', '-qm', 'feed')
        git(repo, 'remote', 'add', 'origin', row['url'])
        row['commit'] = git(repo, 'rev-parse', 'HEAD')
    (source / 'feeds.conf.default').write_text(''.join(
        f"src-git {r['name']} {r['url']}^{r['commit']}\n" for r in data['feeds']))
    (source / 'package').mkdir()
    (source / 'package/README').write_text('base package fixture\n')
    script = source / 'scripts/feeds'
    script.parent.mkdir()
    script.write_text('#!/usr/bin/python3\nimport pathlib,subprocess,sys,shutil\n'
                      f'local=pathlib.Path({str(feeds)!r})\n'
                      'if sys.argv[1]=="update":\n'
                      ' pathlib.Path("feeds").mkdir()\n'
                      ' pathlib.Path("feeds/base").symlink_to("../package")\n'
                      ' for repo in local.iterdir():\n'
                      '  dest="feeds/"+repo.name\n'
                      '  shutil.copytree(repo,dest)\n'
                      '  subprocess.run(["git","-C",dest,"checkout","--detach","-q"],check=True)\n'
                      'print("feed stage",sys.argv[1])\n')
    script.chmod(0o755)
    (source / 'fixture-epoch.mk').write_text('SOURCE_DATE_EPOCH := 1\n')
    (source / 'Makefile').write_text('.DEFAULT_GOAL := all\ninclude fixture-epoch.mk\n'
                                    'defconfig:\n\t@echo CONFIG_PACKAGE_fixture=y >> .config\n'
                                    '\t@echo $(SOURCE_DATE_EPOCH) > effective-defconfig-epoch\n'
                                    'all:\n\t@echo $(SOURCE_DATE_EPOCH) > effective-compile-epoch\n'
                                    '\t@echo compiled\n\t@python3 scripts/emit-images\n')
    (source / 'scripts/emit-images').write_text('import pathlib,json,hashlib,subprocess,tarfile,io\n'
        f'if not pathlib.Path({str(project / "emit-images")!r}).exists(): raise SystemExit(0)\n'
        'out=pathlib.Path("bin/targets/mediatek/filogic"); out.mkdir(parents=True)\n'
        'images=[]\n'
        'for kind in ("sysupgrade","factory"):\n'
        ' name="openwrt-glinet_gl-xe3000-"+kind+".bin"\n'
        ' if kind=="sysupgrade":\n'
        '  with tarfile.open(out/name,"w") as archive:\n'
        '   for member,raw in (("CONTROL",b"BOARD=glinet_gl-xe3000\\n"),("kernel",b"kernel-fixture"),("root",b"root-fixture")):\n'
        '    info=tarfile.TarInfo("sysupgrade-glinet_gl-xe3000/"+member); info.size=len(raw); archive.addfile(info,io.BytesIO(raw))\n'
        ' else: (out/name).write_bytes(b"factory-image")\n'
        ' raw=(out/name).read_bytes()\n'
        ' images.append({"name":name,"type":kind,"size":len(raw),"sha256":hashlib.sha256(raw).hexdigest()})\n'
        'epoch=int(subprocess.check_output(["git","show","-s","--format=%ct","HEAD"]))\n'
        'meta={"target":"mediatek/filogic","version_number":"fixture-baseline","version_code":"r1-fixture",'
        '"source_date_epoch":epoch,"profiles":{"glinet_gl-xe3000":{"images":images,"supported_devices":["glinet,gl-xe3000"],"device_packages":["fixture"]}}}\n'
        f'if pathlib.Path({str(project / "wrong-image-hash")!r}).exists(): images[0]["sha256"]="0"*64\n'
        '(out/"profiles.json").write_text(json.dumps(meta))\n'
        '(out/"openwrt.manifest").write_text("fixture - 1.0\\n")\n'
        '(out/"config.buildinfo").write_bytes(pathlib.Path(".config").read_bytes())\n'
        '(out/"feeds.buildinfo").write_bytes(pathlib.Path("feeds.conf.default").read_bytes())\n'
        '(out/"version.buildinfo").write_text("r1-fixture\\n")\n'
        'embedded={"supported_devices":["glinet,gl-xe3000"],"version":{"dist":"OpenWrt","version":"fixture-baseline","revision":"r1-fixture","target":"mediatek/filogic","board":"glinet_gl-xe3000"}}\n'
        f'if pathlib.Path({str(project / "wrong-board")!r}).exists(): embedded["version"]["board"]="wrong-board"\n'
        'tool=pathlib.Path("staging_dir/host/bin/fwtool");tool.parent.mkdir(parents=True)\n'
        'tool.write_text("#!/usr/bin/python3\\nimport pathlib,sys\\npathlib.Path(sys.argv[2]).write_text("+repr(json.dumps(embedded))+")\\n")\n'
        'tool.chmod(0o755)\n'
        f'if pathlib.Path({str(project / "ca-dup")!r}).exists():\n'
        ' import base64\n'
        ' pem=lambda n:b"-----BEGIN CERTIFICATE-----\\n"+base64.b64encode(bytes([n])*48)+b"\\n-----END CERTIFICATE-----\\n"\n'
        ' ca=pathlib.Path("build_dir/target-x/ca-certificates-1"); (ca/"mozilla").mkdir(parents=True)\n'
        ' (ca/"mozilla/a.crt").write_bytes(pem(1)); (ca/"mozilla/a_2.crt").write_bytes(pem(1))\n'
        ' certs=ca/"ipkg-all/ca-bundle/etc/ssl/certs"; certs.mkdir(parents=True)\n'
        ' (certs/"ca-certificates.crt").write_bytes(pem(1)+pem(1))\n'
        f'if pathlib.Path({str(project / "compile-fail")!r}).exists(): raise SystemExit(7)\n'
        f'if pathlib.Path({str(project / "missing-package")!r}).exists(): (out/"openwrt.manifest").write_text("unrelated - 1\\n")\n')
    git(source, 'add', 'feeds.conf.default', 'scripts', 'Makefile', 'fixture-epoch.mk', 'package')
    git(source, 'commit', '-qm', 'synthetic build tools')
    data['upstream']['commit'] = git(source, 'rev-parse', 'HEAD')
    (project / 'recipe/upstream.json').write_text(json.dumps(data))
    subprocess.run(['python3', str(REPO / 'scripts/prepare_firmware.py'), '--root', str(project),
                    '--source', str(source), '--out', str(baseline)], check=True, capture_output=True)
    return project, baseline, project / 'build/stages/run', data


def invoke(case, *args, extra_env=None):
    project, baseline, out, _ = case
    env = dict(os.environ, SECRET_TOKEN='must-not-record', **(extra_env or {}))
    return subprocess.run(['python3', str(REPO / 'scripts/build_firmware.py'), '--root', str(project),
                           '--baseline', str(baseline), '--out', str(out), *args],
                          env=env, capture_output=True, text=True)


def record(case):
    return json.loads((case[2] / 'build-record.json').read_text())


def test_configure_records_environment_pins_and_resolved_config(build_case):
    _, baseline, out, data = build_case
    before = (baseline / 'manifest.json').read_bytes()
    result = invoke(build_case, '--configure', '--environment-id', 'sha256:' + 'a' * 64)
    assert result.returncode == 0, result.stderr
    r = record(build_case)
    assert r['status'] == 'configured'
    assert not r['firmware_build_complete'] and not r['production_ready'] and not r['reproducible']
    assert r['feed_heads'] == {row['name']: row['commit'] for row in data['feeds']}
    assert r['config_sha256'] == hashlib.sha256((out / 'checkout/.config').read_bytes()).hexdigest()
    assert r['environment']['SOURCE_DATE_EPOCH'] == str(json.loads(before)['source_date_epoch'])
    assert r['environment_id'] == 'sha256:' + 'a' * 64
    assert r['os_release'] and r['tools']['make'] and r['packages']
    assert 'must-not-record' not in json.dumps(r)
    assert (baseline / 'manifest.json').read_bytes() == before
    assert (out / 'logs/feeds-update.log').exists()
    assert (out / 'logs/feeds-install.log').exists()
    assert (out / 'logs/defconfig.log').exists()
    assert os.readlink(out / 'checkout/feeds/base') == '../package'


def test_make_command_line_epoch_overrides_upstream_make_assignment(build_case):
    project, baseline, out, _ = build_case
    (project / 'emit-images').touch()
    expected = str(json.loads((baseline / 'manifest.json').read_text())['source_date_epoch'])
    assert expected != '1'
    assert invoke(build_case, '--configure').returncode == 0
    assert (out / 'checkout/effective-defconfig-epoch').read_text().strip() == expected
    assert invoke(build_case, '--compile', '--jobs', '2').returncode == 0
    assert (out / 'checkout/effective-compile-epoch').read_text().strip() == expected
    commands = {row['name']: row['argv'] for row in record(build_case)['commands']}
    assert commands['defconfig'] == ['make', 'defconfig', 'SOURCE_DATE_EPOCH=' + expected]
    assert commands['compile'] == ['make', '-j2', 'V=s', 'SOURCE_DATE_EPOCH=' + expected]


def test_same_head_dirty_feed_refused_before_install(build_case):
    project, baseline, out, data = build_case
    # Change committed feed-update behavior, then prepare a fresh verified baseline.
    source = project / 'build/source'
    script = source / 'scripts/feeds'
    script.write_text(script.read_text() + '\nif sys.argv[1]=="update": pathlib.Path("feeds/packages/README").write_text("changed")\n')
    git(source, 'add', 'scripts/feeds')
    git(source, 'commit', '-qm', 'dirty feed fixture')
    data['upstream']['commit'] = git(source, 'rev-parse', 'HEAD')
    (project / 'recipe/upstream.json').write_text(json.dumps(data))
    new_baseline = project / 'build/dirty-feed-baseline'
    subprocess.run(['python3', str(REPO / 'scripts/prepare_firmware.py'), '--root', str(project),
                    '--source', str(source), '--out', str(new_baseline)], check=True, capture_output=True)
    case = project, new_baseline, out, data
    assert invoke(case, '--configure').returncode == 2
    assert record(case)['status'] == 'failed'
    assert not (out / 'logs/feeds-install.log').exists()


def test_compile_without_images_fails_closed(build_case):
    assert invoke(build_case, '--configure', '--environment-id', 'fixture-image').returncode == 0
    result = invoke(build_case, '--compile', '--jobs', '2', '--environment-id', 'fixture-image')
    assert result.returncode == 2
    r = record(build_case)
    assert r['status'] == 'failed'
    assert not r['firmware_build_complete']
    assert (build_case[2] / 'logs/compile.log').read_text() == 'compiled\n'


def test_success_inspects_metadata_inventory_and_image_hashes(build_case):
    project, _, out, _ = build_case
    (project / 'emit-images').touch()
    assert invoke(build_case, '--configure', '--environment-id', 'fixture-image').returncode == 0
    result = invoke(build_case, '--compile', '--jobs', '2', '--environment-id', 'fixture-image')
    assert result.returncode == 0, result.stderr
    r = record(build_case)
    assert r['status'] == 'compiled-inspected' and r['firmware_build_complete']
    assert not r['production_ready'] and not r['reproducible']
    artifacts = r['artifacts']
    assert {'factory', 'sysupgrade'} == {row['type'] for row in r['images']}
    for item in artifacts:
        assert item['sha256'] == hashlib.sha256((out / 'checkout' / item['path']).read_bytes()).hexdigest()
    assert r['package_inventory'] == ['fixture - 1.0']
    assert r['profile']['supported_devices'] == ['glinet,gl-xe3000']


def test_compile_refuses_untracked_make_override(build_case):
    assert invoke(build_case, '--configure').returncode == 0
    checkout = build_case[2] / 'checkout'
    (checkout / 'GNUmakefile').write_text('all:\n\t@touch injected-command-ran\n')
    assert invoke(build_case, '--compile').returncode == 2
    assert not (checkout / 'injected-command-ran').exists()
    assert record(build_case)['status'] == 'failed'


def test_compile_refuses_changed_tool_environment(build_case):
    assert invoke(build_case, '--configure').returncode == 0
    r = record(build_case)
    r['tools']['gcc'] = 'different compiler'
    (build_case[2] / 'build-record.json').write_text(json.dumps(r))
    assert invoke(build_case, '--compile').returncode == 2
    assert not (build_case[2] / 'logs/compile.log').exists()


def test_snapshot_does_not_ignore_injected_nested_git_directory(build_case):
    assert invoke(build_case, '--configure').returncode == 0
    extra = build_case[2] / 'checkout/package/.git'
    extra.mkdir(parents=True)
    (extra / 'Makefile').write_text('injected build input\n')
    assert invoke(build_case, '--compile').returncode == 2
    assert not (build_case[2] / 'logs/compile.log').exists()


def test_wrong_embedded_image_board_fails_despite_matching_profile_hash(build_case):
    project, _, _, _ = build_case
    (project / 'emit-images').touch()
    (project / 'wrong-board').touch()
    assert invoke(build_case, '--configure').returncode == 0
    assert invoke(build_case, '--compile').returncode == 2
    assert not record(build_case)['firmware_build_complete']


def test_metadata_output_alias_is_refused_before_overwrite(build_case):
    project, _, out, _ = build_case
    (project / 'emit-images').touch()
    assert invoke(build_case, '--configure').returncode == 0
    protected = project / 'keep'
    protected.write_text('unchanged')
    (out / 'image-metadata.json').symlink_to(protected)
    assert invoke(build_case, '--compile').returncode == 2
    assert protected.read_text() == 'unchanged'


@pytest.mark.parametrize('failure', ['compile-fail', 'wrong-image-hash', 'missing-package'])
def test_partial_or_invalid_artifacts_never_claim_completion(build_case, failure):
    project, _, out, _ = build_case
    (project / 'emit-images').touch()
    (project / failure).touch()
    assert invoke(build_case, '--configure').returncode == 0
    assert invoke(build_case, '--compile').returncode == 2
    assert (out / 'checkout/bin/targets/mediatek/filogic/profiles.json').exists()
    r = record(build_case)
    assert r['status'] == 'failed' and not r['firmware_build_complete']
    assert not r['production_ready'] and not r['reproducible']
    if failure == 'compile-fail': assert r['commands'][-1]['returncode'] == 2
    log = (out / 'logs/compile.log').read_bytes()
    assert invoke(build_case, '--compile').returncode == 2
    assert (out / 'logs/compile.log').read_bytes() == log


@pytest.mark.parametrize('tamper', ['recipe', 'config', 'feed-head', 'feed-bytes', 'source-bytes',
                                   'base-alias', 'readiness', 'jobs', 'environment-id'])
def test_compile_input_refusals_run_no_make(build_case, tamper):
    assert invoke(build_case, '--configure').returncode == 0
    project, _, out, data = build_case
    checkout = out / 'checkout'
    extra = []
    if tamper == 'recipe':
        data['upstream']['tag'] = 'changed'
        (project / 'recipe/upstream.json').write_text(json.dumps(data))
    if tamper == 'config': (checkout / '.config').write_text('CONFIG_TARGET_wrong=y\n')
    if tamper == 'feed-head': git(checkout / 'feeds/packages', 'symbolic-ref', 'HEAD', 'refs/heads/main')
    if tamper == 'feed-bytes': (checkout / 'feeds/packages/README').write_text('changed\n')
    if tamper == 'source-bytes': (checkout / 'Makefile').write_text('all:\n\t@exit 0\n')
    if tamper == 'base-alias':
        (checkout / 'feeds/base').unlink()
        (checkout / 'feeds/base').symlink_to('../../../../prepared/checkout/package')
    if tamper == 'readiness':
        r = record(build_case); r['production_ready'] = True
        (out / 'build-record.json').write_text(json.dumps(r))
    if tamper == 'jobs': extra = ['--jobs', '65']
    if tamper == 'environment-id': extra = ['--environment-id', 'different-image']
    assert invoke(build_case, '--compile', *extra).returncode == 2
    r = record(build_case)
    assert r['status'] == 'failed' and not r['firmware_build_complete'] and not r['production_ready']
    assert not (out / 'logs/compile.log').exists()
    assert invoke(build_case, '--compile', *extra).returncode == 2


@pytest.mark.parametrize('bad', ['existing', 'overlap', 'alias', 'outside'])
def test_configure_rejects_existing_and_aliased_destinations(build_case, bad):
    project, baseline, out, data = build_case
    before = (baseline / 'manifest.json').read_bytes()
    if bad == 'existing': out.mkdir(parents=True)
    if bad == 'overlap': out = baseline / 'nested'
    if bad == 'outside': out = project / 'outside'
    if bad == 'alias':
        alias = project / 'build/link'; alias.symlink_to(project / 'build')
        out = alias / 'run'
    assert invoke((project, baseline, out, data), '--configure').returncode == 2
    assert (baseline / 'manifest.json').read_bytes() == before


def test_duplicate_ca_bundle_fails_compile_and_marks_record_failed(build_case):
    project = build_case[0]
    (project / 'emit-images').write_text('')
    (project / 'ca-dup').write_text('')
    assert invoke(build_case, '--configure').returncode == 0
    result = invoke(build_case, '--compile')
    assert result.returncode != 0
    r = record(build_case)
    assert r['status'] == 'failed' and not r['firmware_build_complete'] and 'ca_bundle_guard' not in r
