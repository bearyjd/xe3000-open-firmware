"""Offline eMMC layout rebuild check from a local backup. Never touches a router.

Parses the saved GPT, checks it against the recorded partition map, rebuilds a sparse
disk image from the backup copies at their start sectors and reads every region back.
It proves offsets and sizes are consistent, not that a restore would boot.
No GUIDs, hashes of identity partitions or contents are written to the report.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
import zlib
from pathlib import Path

SECTOR = 512
DISK_SECTORS = 15269888
HEAD_FILE = 'mmcblk0-first4096.bin'
HEAD_SECTORS = 4096
# name -> (start sector, sector count) recorded from sysfs and the saved GPT.
EXPECTED = {
    'log': (4096, 4096), 'u-boot-env': (8192, 1024), 'factory': (9216, 4096),
    'fip': (13312, 4096), 'custom': (17408, 4096), 'kernel': (21504, 65536),
    'rootfs': (87040, DISK_SECTORS - 87040),
}
BACKED_UP = {'u-boot-env': 'mmcblk0p2.bin', 'factory': 'mmcblk0p3.bin',
             'fip': 'mmcblk0p4.bin', 'custom': 'mmcblk0p5.bin'}


class LayoutError(Exception):
    """The backup or its partition table is inconsistent."""


def parse_gpt(head: bytes) -> dict[str, tuple[int, int]]:
    if len(head) < 34 * SECTOR or head[SECTOR:SECTOR + 8] != b'EFI PART':
        raise LayoutError('GPT header missing')
    size, crc = struct.unpack('<II', head[SECTOR + 12:SECTOR + 20])
    header = bytearray(head[SECTOR:SECTOR + size])
    header[16:20] = b'\0\0\0\0'
    if size < 92 or zlib.crc32(bytes(header)) != crc:
        raise LayoutError('GPT header CRC mismatch')
    lba, count, entry_size, entries_crc = struct.unpack('<QIII', head[SECTOR + 72:SECTOR + 92])
    raw = head[lba * SECTOR:lba * SECTOR + count * entry_size]
    if len(raw) != count * entry_size or zlib.crc32(raw) != entries_crc:
        raise LayoutError('GPT entry table CRC mismatch')
    entries = {}
    for i in range(count):
        row = raw[i * entry_size:(i + 1) * entry_size]
        if row[:16] == b'\0' * 16:
            continue
        first, last = struct.unpack('<QQ', row[32:48])
        name = row[56:128].decode('utf-16le').rstrip('\0')
        if name in entries or last < first:
            raise LayoutError('GPT entry invalid or duplicated: ' + name)
        entries[name] = (first, last - first + 1)
    return entries


def check_layout(entries: dict[str, tuple[int, int]]) -> None:
    if entries != EXPECTED:
        raise LayoutError('GPT differs from recorded partition map')


def verify_manifest(backup: Path) -> dict[str, bytes]:
    """Return file contents after checking every file against SHA256SUMS."""
    listed = {}
    for line in (backup / 'SHA256SUMS').read_text().splitlines():
        digest, name = line.split(None, 1)
        listed[name.strip().lstrip('*')] = digest
    wanted = {HEAD_FILE, *BACKED_UP.values()}
    if not wanted <= set(listed):
        raise LayoutError('manifest lacks required files')
    data = {}
    for name in sorted(wanted):
        raw = (backup / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != listed[name]:
            raise LayoutError('hash mismatch: ' + name)
        data[name] = raw
    return data


def regions(data: dict[str, bytes]) -> dict[str, tuple[int, bytes]]:
    out = {'first-4096-sectors': (0, data[HEAD_FILE])}
    for part, fname in BACKED_UP.items():
        start, count = EXPECTED[part]
        if len(data[fname]) != count * SECTOR:
            raise LayoutError('copy size differs from partition size: ' + part)
        out[part] = (start, data[fname])
    if len(data[HEAD_FILE]) != HEAD_SECTORS * SECTOR:
        raise LayoutError('first-4096-sector copy has the wrong size')
    return out


def rebuild(backup: Path, out_image: Path) -> dict:
    data = verify_manifest(backup)
    check_layout(parse_gpt(data[HEAD_FILE]))
    placed = regions(data)
    fd = os.open(out_image, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as image:
        image.truncate(DISK_SECTORS * SECTOR)
        for start, raw in placed.values():
            image.seek(start * SECTOR)
            image.write(raw)
    results = {}
    with out_image.open('rb') as image:
        for name, (start, raw) in placed.items():
            image.seek(start * SECTOR)
            results[name] = image.read(len(raw)) == raw
    if not all(results.values()):
        raise LayoutError('read-back mismatch: ' + ', '.join(k for k, v in results.items() if not v))
    return {'disk_bytes': out_image.stat().st_size, 'gpt_matches_recorded_map': True,
            'regions_verified': sorted(results), 'untested': ['log', 'kernel', 'rootfs', 'rootfs_data',
            'boot partitions', 'bootability']}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backup', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True, help='new sparse image path')
    args = parser.parse_args(argv)
    try:
        report = rebuild(args.backup, args.out)
    except (LayoutError, OSError, ValueError) as exc:
        sys.stderr.write(f'layout rebuild failed: {exc}\n')
        return 1
    sys.stdout.write(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
