"""Prepare an isolated, public-only MHI source proposal. No network or hardware I/O."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile

ARTIFACTS = Path(__file__).resolve().parent.parent / 'recipe/candidates/modem'
PINNED_ARCHIVE_SHA256 = '164dc9d1f6c93c61a15e1f071c48379b467f2b17c469cce7223471968208ed03'
KERNEL_ARCHIVE_SHA256 = PINNED_ARCHIVE_SHA256
PATCH_COMMIT = '8cc71da72ac6dcc651c93e6a4c10351d56006fd8'
PATCH_SHA256 = '0b52a04aa0e514888687e0e0bc115b351422ad14e32cd8a07678661a7b7fd399'
PCI = 'drivers/bus/mhi/host/pci_generic.c'
MBIM = 'drivers/net/wwan/mhi_wwan_mbim.c'
SOURCE_HASHES = {
    PCI: '76c4e4a67278c27b7e3796e4534813a78e683df687d212eb2ff05247b805a375',
    MBIM: '126960b96fb524fb3d806533865c9d0294a3b27e474dcf4a1b5d9b6081d5ebb3',
}


class CandidateError(RuntimeError):
    """Content-free offline refusal."""


def safe_path(path: Path) -> Path:
    path = Path(path)
    if '..' in path.parts:
        raise CandidateError('parent traversal refused')
    path = Path(os.path.abspath(path))
    private = {'.env', '.ssh', '.gnupg', '.aws', '.git', 'private', 'secrets'}
    if (private.intersection(path.parts) or path.name.startswith('.env.')
            or path.suffix in {'.pem', '.key', '.p12'} or any(
            a == 'harvest' and b == 'raw' for a, b in zip(path.parts, path.parts[1:]))):
        raise CandidateError('private path refused')
    for part in (*reversed(path.parents), path):
        try:
            mode = part.lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode) or (part != path and not stat.S_ISDIR(mode)):
            raise CandidateError('path alias refused')
    return path


def regular(path: Path) -> Path:
    path = safe_path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise CandidateError('non-regular or linked input refused')
    return path


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hashed_file(path: Path, expected: str, label: str, max_size=None) -> bytes:
    path = regular(path)
    if max_size is not None and path.stat().st_size > max_size:
        raise CandidateError(f'{label} size refused')
    data = path.read_bytes()
    if sha(data) != expected:
        raise CandidateError(f'{label} hash mismatch')
    return data


def candidate_artifacts() -> dict:
    manifest_bytes = regular(ARTIFACTS / 'provenance.json').read_bytes()
    try:
        manifest = json.loads(manifest_bytes)
        if not (manifest['schema_version'] == 1
                and manifest['patch']['commit'] == PATCH_COMMIT
                and manifest['patch']['sha256'] == PATCH_SHA256
                and manifest['kernel']['version'] == '6.12.112'
                and manifest['kernel']['archive_sha256'] == PINNED_ARCHIVE_SHA256
                and manifest['kernel']['source_sha256'] == SOURCE_HASHES):
            raise CandidateError('candidate provenance contract mismatch')
        artifacts = {name: hashed_file(ARTIFACTS / name, manifest['artifact_sha256'][name],
                                      'candidate artifact', 64 * 1024)
                     for name in ('candidate.config', 'README.md')}
    except (KeyError, TypeError, ValueError):
        raise CandidateError('candidate provenance contract mismatch') from None
    artifacts['provenance.json'] = manifest_bytes
    return artifacts


def block(text: str, name: str) -> str:
    # Restricted inspection of the pinned source; never an arbitrary C evaluator.
    matches = re.findall(r'\b' + re.escape(name) + r'(?:\[\])?\s*=\s*\{(.*?)\n\};', text, re.S)
    if len(matches) != 1:
        raise CandidateError('source declaration contract mismatch')
    return matches[0]


def fields(text: str, name: str) -> dict:
    return dict(re.findall(r'\.(\w+)\s*=\s*([^,\n]+)', block(text, name)))


def matched_profile(pci: str) -> str:
    entries = re.findall(
        r'\{\s*PCI_DEVICE(_SUB)?\(([^)]+)\),\s*'
        r'\.driver_data\s*=\s*\(kernel_ulong_t\)\s*&([a-zA-Z0-9_]+)\s*\}',
        re.sub(r'/\*.*?\*/', '', block(pci, 'mhi_pci_id_table'), flags=re.S))
    for subsystem, args, profile in entries:
        values = [v.strip() for v in args.split(',')]
        if values[:2] != ['PCI_VENDOR_ID_QCOM', '0x0308']:
            continue
        if not subsystem or values[2:] == ['PCI_VENDOR_ID_QCOM', '0x5201']:
            return profile
    raise CandidateError('PCI match contract mismatch')


def inspect_profiles(pci: str, mbim: str) -> dict:
    selected = matched_profile(pci)
    if selected != 'mhi_quectel_rm5xx_info':
        raise CandidateError('Quectel PCI match must precede generic fallback')
    before = fields(pci, 'mhi_qcom_sdx65_info')
    after = fields(pci, selected)
    controller = after.get('config', '').removeprefix('&')
    channels = fields(pci, controller).get('ch_cfg', '')
    channel_body = block(pci, channels)
    for direction, channel_id in [('UL', 100), ('DL', 101)]:
        if not re.search(r'MHI_CHANNEL_CONFIG_HW_' + direction + r'\(' + str(channel_id)
                         + r',\s*"IP_HW0_MBIM"\s*,', channel_body):
            raise CandidateError('Quectel MBIM channel contract mismatch')
    if not re.search(r'\.chan\s*=\s*"IP_HW0_MBIM"', block(mbim, 'mhi_mbim_id_table')):
        raise CandidateError('MBIM consumer channel contract mismatch')
    driver = fields(mbim, 'mhi_mbim_driver')
    if driver.get('id_table') != 'mhi_mbim_id_table' or '"mhi_wwan_mbim"' not in block(mbim, 'mhi_mbim_driver'):
        raise CandidateError('MBIM consumer driver contract mismatch')
    return {
        'after_profile': selected,
        'mbim_channel': 'IP_HW0_MBIM',
        'profile_diff': {key: {'before': before.get(key), 'after': after.get(key)}
                         for key in sorted(before.keys() | after.keys()) if before.get(key) != after.get(key)},
        'inspection_scope': 'restricted pinned-source declarations; no C compilation or runtime binding claim',
    }


def apply_patch(kernel: Path, patch: bytes, check: bool) -> dict:
    env = dict(PATH='/usr/bin:/bin', HOME=str(kernel), TMPDIR='/tmp', LANG='C', TZ='UTC',
               GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_TERMINAL_PROMPT='0',
               GIT_CEILING_DIRECTORIES=str(kernel.parent), GIT_DISCOVERY_ACROSS_FILESYSTEM='0')
    command = ['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.attributesFile=/dev/null',
               '-c', 'core.fsmonitor=false', 'apply', '--verbose', '--whitespace=error']
    if check:
        command.append('--check')
    result = subprocess.run(command, cwd=kernel, input=patch, capture_output=True, env=env)
    if result.returncode:
        raise CandidateError('patch application refused')
    return {'exit_code': result.returncode, 'detail': result.stderr.decode('utf-8', 'replace').strip()}


def prepare(kernel_source: Path, kernel_archive: Path, out: Path) -> Path:
    kernel_source, kernel_archive, out = map(safe_path, (kernel_source, kernel_archive, out))
    if out.exists():
        raise CandidateError('existing output refused')
    if kernel_source in out.parents or out in kernel_source.parents or out == kernel_source:
        raise CandidateError('source/output overlap refused')
    if out == kernel_archive or out in kernel_archive.parents:
        raise CandidateError('archive/output overlap refused')
    archive = regular(kernel_archive)
    with archive.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != KERNEL_ARCHIVE_SHA256:
            raise CandidateError('archive hash mismatch')
    sources = {rel: hashed_file(kernel_source / rel, digest, 'source', 1024 * 1024)
               for rel, digest in SOURCE_HASHES.items()}
    members = {'linux-6.12.112/' + rel: rel for rel in SOURCE_HASHES}
    found = set()
    with tarfile.open(archive, 'r:xz') as tf:
        for item in tf:
            if item.name not in members:
                continue
            rel = members[item.name]
            if rel in found or not item.isfile() or item.size != len(sources[rel]):
                raise CandidateError('pristine archive member contract mismatch')
            stream = tf.extractfile(item)
            if stream is None or stream.read() != sources[rel]:
                raise CandidateError('pristine archive/source mismatch')
            found.add(rel)
    if found != SOURCE_HASHES.keys():
        raise CandidateError('pristine archive incomplete')
    patch = hashed_file(ARTIFACTS / 'gl-x3000-quectel-pci-id.patch', PATCH_SHA256, 'patch', 8192)
    artifacts = candidate_artifacts()
    before = matched_profile(sources[PCI].decode())
    if before != 'mhi_qcom_sdx65_info':
        raise CandidateError('pristine PCI fallback mismatch')
    # All input validation precedes the first mutation. Copy only two public files.
    out.mkdir(parents=True, exist_ok=False)
    kernel = out / 'kernel'
    for rel, data in sources.items():
        destination = kernel / rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    check_result = apply_patch(kernel, patch, True)
    apply_result = apply_patch(kernel, patch, False)
    report = inspect_profiles((kernel / PCI).read_text(), (kernel / MBIM).read_text())
    report.update(schema_version=1, before_profile=before,
                  patch_sha256=PATCH_SHA256, kernel_archive_sha256=KERNEL_ARCHIVE_SHA256,
                  source_sha256=SOURCE_HASHES, patched_pci_sha256=sha((kernel / PCI).read_bytes()),
                  patch_application={'check_exit_code': check_result['exit_code'],
                                     'apply_exit_code': apply_result['exit_code'],
                                     'check_detail': check_result['detail'], 'apply_detail': apply_result['detail']},
                  defconfig_verified=False, firmware_build_complete=False, hardware_verified=False,
                  protocol_mode_verified=False, production_ready=False,
                  power_management_change_included=False)
    for filename, data in artifacts.items():
        (out / filename).write_bytes(data)
    (out / 'gl-x3000-quectel-pci-id.patch').write_bytes(patch)
    (out / 'proposal.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel-source', type=Path, required=True,
                        help='verified, unmodified Linux 6.12.112 source root')
    parser.add_argument('--kernel-archive', type=Path, required=True,
                        help='pinned pristine linux-6.12.112.tar.xz')
    parser.add_argument('--out', type=Path, required=True, help='new isolated output directory')
    args = parser.parse_args(argv)
    try:
        prepare(args.kernel_source, args.kernel_archive, args.out)
    except (CandidateError, OSError, tarfile.TarError, UnicodeError):
        # Preserve actionable trusted reasons without printing input content or paths.
        exc = sys.exc_info()[1]
        reason = str(exc) if isinstance(exc, CandidateError) else 'invalid offline input'
        print('modem candidate refused: ' + reason, file=sys.stderr)
        return 1
    print('Offline MHI source proposal prepared; defconfig, firmware and hardware unverified.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
