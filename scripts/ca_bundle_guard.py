"""Read-only post-build guard: the CA bundle must not contain duplicate certificates.

OpenWrt's ca-certificates parser does not clean its output directory, so a resumed or
re-run build leaves extra CRT files and a larger bundle (see
docs/prp/reproducibility-plan.md). This guard only reads; it never rewrites outputs.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
from pathlib import Path

import firmware as fw

BLOCK = re.compile(rb'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', re.DOTALL)
BUNDLE_PARTS = ('ipkg-all', 'ca-bundle', 'etc', 'ssl', 'certs', 'ca-certificates.crt')


def _der_digests(raw: bytes) -> list[str]:
    digests = []
    for body in BLOCK.findall(raw):
        try:
            der = base64.b64decode(b''.join(body.split()), validate=True)
        except binascii.Error as exc:
            raise fw.FirmwareError('CA bundle certificate block is not valid base64') from exc
        if not der:
            raise fw.FirmwareError('CA bundle certificate block is empty')
        digests.append(hashlib.sha256(der).hexdigest())
    return digests


def _summarize(directory: Path) -> dict:
    crt_files = sorted((directory / 'mozilla').glob('*.crt'))
    if not crt_files:
        raise fw.FirmwareError('CA certificate sources missing: ' + directory.name + '/mozilla')
    bundle_path = directory.joinpath(*BUNDLE_PARTS)
    if not bundle_path.is_file():
        raise fw.FirmwareError('CA bundle missing: ' + directory.name)
    bundle = _der_digests(fw._file(bundle_path))
    parsed = [d for crt in crt_files for d in _der_digests(fw._file(crt))]
    return {'directory': directory.name, 'sets_equal': set(bundle) == set(parsed),
            'crt_files': len(crt_files),
            'bundle_blocks': len(bundle), 'bundle_unique': len(set(bundle)),
            'crt_blocks': len(parsed), 'crt_unique': len(set(parsed))}


def check(checkout: Path) -> list[dict]:
    """Return one summary per ca-certificates build dir; raise on any duplicate."""
    roots = sorted(Path(checkout, 'build_dir').glob('target-*/ca-certificates-*'))
    summaries = [_summarize(root) for root in roots if root.is_dir()]
    for s in summaries:
        if not s['bundle_blocks']:
            raise fw.FirmwareError('CA bundle contains no certificates')
        if (s['bundle_blocks'] != s['bundle_unique'] or s['crt_blocks'] != s['crt_unique']
                or s['crt_files'] != s['crt_unique'] or not s['sets_equal']):
            raise fw.FirmwareError(
                'CA bundle duplicates detected (resumed or re-run parser); '
                'accepted artifacts require one uninterrupted build: ' + repr(s))
    return summaries
