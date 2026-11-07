"""Layout rebuild check against a synthetic GPT and backup built at runtime."""
import hashlib
import struct
import sys
import zlib

import pytest

from conftest import REPO

sys.path.insert(0, str(REPO / 'scripts'))
import layout_rebuild as lr  # noqa: E402

SECTOR = lr.SECTOR


def gpt_head(layout, *, corrupt_header=False, corrupt_entries=False):
    head = bytearray(lr.HEAD_SECTORS * SECTOR)
    head[510:512] = b'\x55\xaa'
    table = bytearray(128 * 128)
    for i, (name, (start, count)) in enumerate(layout.items()):
        row = bytearray(128)
        row[0:16] = bytes([1]) * 16
        row[16:32] = bytes([i + 1]) * 16
        row[32:48] = struct.pack('<QQ', start, start + count - 1)
        row[56:56 + 2 * len(name)] = name.encode('utf-16le')
        table[i * 128:(i + 1) * 128] = row
    ecrc = zlib.crc32(bytes(table)) ^ (1 if corrupt_entries else 0)
    header = bytearray(92)
    header[0:8] = b'EFI PART'
    struct.pack_into('<IIII', header, 8, 0x10000, 92, 0, 0)
    struct.pack_into('<QQQQ', header, 24, 1, 1, 34, lr.DISK_SECTORS - 1)
    struct.pack_into('<QIII', header, 72, 2, 128, 128, ecrc)
    struct.pack_into('<I', header, 16, zlib.crc32(bytes(header)) ^ (1 if corrupt_header else 0))
    head[SECTOR:SECTOR + 92] = header
    head[2 * SECTOR:2 * SECTOR + len(table)] = table
    return bytes(head)


def make_backup(path, layout=None, **gpt_kw):
    layout = layout or lr.EXPECTED
    files = {lr.HEAD_FILE: gpt_head(layout, **gpt_kw)}
    for part, fname in lr.BACKED_UP.items():
        count = lr.EXPECTED[part][1]
        files[fname] = bytes([sorted(lr.BACKED_UP).index(part) + 7]) * (count * SECTOR)
    path.mkdir()
    for name, raw in files.items():
        (path / name).write_bytes(raw)
    (path / 'SHA256SUMS').write_text(''.join(
        f'{hashlib.sha256(raw).hexdigest()}  {name}\n' for name, raw in files.items()))
    return path


def test_rebuild_places_every_region_at_its_start_sector(tmp_path):
    backup = make_backup(tmp_path / 'b')
    report = lr.rebuild(backup, tmp_path / 'disk.img')
    image = (tmp_path / 'disk.img').read_bytes()
    assert report['disk_bytes'] == lr.DISK_SECTORS * SECTOR == len(image)
    for part, fname in lr.BACKED_UP.items():
        start = lr.EXPECTED[part][0] * SECTOR
        assert image[start:start + 64] == (backup / fname).read_bytes()[:64]
    assert report['gpt_matches_recorded_map'] and 'bootability' in report['untested']


def test_report_contains_no_hashes_or_guids(tmp_path):
    backup = make_backup(tmp_path / 'b')
    text = repr(lr.rebuild(backup, tmp_path / 'disk.img'))
    assert not any(hashlib.sha256(p.read_bytes()).hexdigest() in text for p in backup.glob('*.bin'))


@pytest.mark.parametrize('kw, msg', [({'corrupt_header': True}, 'header CRC'),
                                     ({'corrupt_entries': True}, 'entry table CRC')])
def test_corrupt_gpt_refused(tmp_path, kw, msg):
    with pytest.raises(lr.LayoutError, match=msg):
        lr.rebuild(make_backup(tmp_path / 'b', **kw), tmp_path / 'd.img')


def test_moved_partition_refused(tmp_path):
    moved = dict(lr.EXPECTED, fip=(13313, 4096))
    with pytest.raises(lr.LayoutError, match='differs from recorded'):
        lr.rebuild(make_backup(tmp_path / 'b', moved), tmp_path / 'd.img')


def test_recorded_map_is_disjoint_and_ends_at_the_disk_end():
    spans = sorted(lr.EXPECTED.values())
    assert all(a + n <= b for (a, n), (b, _) in zip(spans, spans[1:]))
    assert spans[-1][0] + spans[-1][1] == lr.DISK_SECTORS


def test_manifest_hash_mismatch_refused(tmp_path):
    backup = make_backup(tmp_path / 'b')
    (backup / 'mmcblk0p4.bin').write_bytes(b'x' * (4096 * SECTOR))
    with pytest.raises(lr.LayoutError, match='hash mismatch'):
        lr.rebuild(backup, tmp_path / 'd.img')


def test_wrong_size_copy_refused(tmp_path):
    backup = make_backup(tmp_path / 'b')
    short = b'y' * 1024
    (backup / 'mmcblk0p5.bin').write_bytes(short)
    lines = [line for line in (backup / 'SHA256SUMS').read_text().splitlines() if 'p5' not in line]
    lines.append(f'{hashlib.sha256(short).hexdigest()}  mmcblk0p5.bin')
    (backup / 'SHA256SUMS').write_text('\n'.join(lines) + '\n')
    with pytest.raises(lr.LayoutError, match='copy size'):
        lr.rebuild(backup, tmp_path / 'd.img')


def test_existing_output_never_overwritten(tmp_path):
    backup = make_backup(tmp_path / 'b')
    existing = tmp_path / 'd.img'
    existing.write_bytes(b'keep')
    with pytest.raises(FileExistsError):
        lr.rebuild(backup, existing)
    assert existing.read_bytes() == b'keep'


def test_cli_returns_nonzero_without_traceback(tmp_path, capsys):
    assert lr.main(['--backup', str(tmp_path / 'missing'), '--out', str(tmp_path / 'd.img')]) == 1
    assert 'layout rebuild failed' in capsys.readouterr().err


def test_read_back_catches_regions_that_clobber_each_other(tmp_path, monkeypatch):
    backup = make_backup(tmp_path / 'b')
    real = lr.regions

    def overlapping(data):
        placed = dict(real(data))
        placed['fip'] = (placed['u-boot-env'][0], placed['fip'][1])
        return placed
    monkeypatch.setattr(lr, 'regions', overlapping)
    with pytest.raises(lr.LayoutError, match='read-back mismatch'):
        lr.rebuild(backup, tmp_path / 'd.img')
