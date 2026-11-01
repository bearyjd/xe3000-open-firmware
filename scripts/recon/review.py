"""Prepare an independent scanner-guided review tree. No API client or dotenv loading."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys

from recon import canary, names, preflight

ZONES = (Path('harvest/redacted'), Path('unpacked'))
POLICIES = ('gitleaks.toml', 'gitleaks.image', 'recon-allowlist.txt')
MARKER = b'# <REDACTED:scanner-review>'


class ReviewError(RuntimeError):
    """A refusal with a fixed, content-free message."""


def _absolute(path: Path) -> Path:
    # Reject aliases rather than silently resolving them before validation.
    if '..' in Path(path).parts:
        raise ReviewError('parent traversal refused')
    path = Path(os.path.abspath(path))
    if any(a == 'harvest' and b == 'raw' for a, b in zip(path.parts, path.parts[1:])):
        raise ReviewError('raw path refused')
    _safe_components(path)
    return path


def _safe_components(path: Path) -> None:
    for item in reversed((path, *path.parents)):
        try:
            mode = item.lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            raise ReviewError('symlink path refused')
        if item != path and not stat.S_ISDIR(mode):
            raise ReviewError('non-directory ancestor refused')


def _read(path: Path) -> bytes:
    """Open every component without following links, including parent directories."""
    descriptor = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        with os.fdopen(fd, 'rb') as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ReviewError('non-regular file or hardlink refused')
            return handle.read()
    finally:
        os.close(descriptor)


def _files(directory: Path) -> list[Path]:
    _safe_components(directory)
    if not directory.exists():
        return []
    if not stat.S_ISDIR(directory.lstat().st_mode):
        raise ReviewError('input directory refused')
    files = []
    for base, dirs, names in os.walk(directory, followlinks=False):
        for name in sorted([*dirs, *names]):
            path = Path(base) / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise ReviewError('source symlink refused')
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ReviewError('non-regular file or hardlink refused')
            files.append(path)
    return sorted(files)


def _excluded(rel: Path) -> bool:
    # Shared credential exclusions stay canonical. Dotenv files are never input
    # to this local preparer, including flattened harvest spellings.
    decoded = names.decode(rel.parts)
    return names.is_excluded(rel.parts) or any(
        part.lower() == '.env' or part.lower().startswith('.env.')
        for part in (*rel.parts, *(decoded or ())))


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _lines(data: bytes) -> list[bytes]:
    # Gitleaks counts LF-delimited lines; bytes.splitlines also splits vertical tabs.
    lines = data.split(b'\n')
    return [line + b'\n' for line in lines[:-1]] + ([lines[-1]] if lines[-1] else [])


def _report(proc, directory: Path) -> list[dict]:
    """Drop all scanner fields except validated relative file/rule/line coordinates."""
    if type(proc.returncode) is not int or proc.returncode not in (0, preflight.LEAK_EXIT_CODE):
        raise ReviewError('scanner failed')
    try:
        rows = json.loads(proc.stdout) if proc.stdout.strip() else []
    except (ValueError, TypeError, AttributeError):
        raise ReviewError('unreadable scanner report') from None
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ReviewError('invalid scanner report')
    if (proc.returncode == 0 and rows) or (proc.returncode == preflight.LEAK_EXIT_CODE and not rows):
        raise ReviewError('scanner exit/report disagreement')
    result = []
    for row in rows:
        name, start, end, rule = (row.get(key) for key in ('File', 'StartLine', 'EndLine', 'RuleID'))
        prefix = preflight.CONTAINER_SCAN_DIR + '/'
        if not isinstance(name, str) or not name.startswith(prefix):
            raise ReviewError('scanner path refused')
        rel = name[len(prefix):]
        if (not rel or '\\' in rel or any(ord(c) < 32 for c in rel)
                or any(part in ('', '.', '..') for part in rel.split('/'))):
            raise ReviewError('scanner path refused')
        path = directory / rel
        _safe_components(path)
        if not path.is_file():
            raise ReviewError('scanner file refused')
        lines = _lines(_read(path))
        if (type(start) is not int or type(end) is not int
                or not 1 <= start <= end <= len(lines)):
            raise ReviewError('scanner coordinates refused')
        if not isinstance(rule, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', rule):
            raise ReviewError('scanner rule refused')
        result.append({'file': directory.name + '/' + rel, 'start_line': start,
                       'end_line': end, 'rule': rule})
    return result


def _redact(directory: Path, hits: list[dict]) -> None:
    by_file = {}
    for hit in hits:
        rel = hit['file'].split('/', 1)[1]
        by_file.setdefault(rel, set()).update(range(hit['start_line'], hit['end_line'] + 1))
    for rel, numbers in by_file.items():
        path = directory / rel
        lines = _lines(_read(path))
        for number in numbers:
            line = lines[number - 1]
            ending = b'\r\n' if line.endswith(b'\r\n') else (b'\n' if line.endswith(b'\n') else b'')
            lines[number - 1] = MARKER + ending
        path.write_bytes(b''.join(lines))


def _evidence(out: Path, evidence: dict, sanitizer: canary.Sanitizer) -> None:
    (out / 'review.json').write_text(json.dumps(sanitizer.obj(evidence), indent=2, sort_keys=True) + '\n')


def prepare(root: Path, out: Path, *, runner=None, sanitizer=None, canary_check=None) -> Path:
    """Public test seam: replace only scanner subprocess and canary boundaries."""
    runner = runner if runner is not None else subprocess.run
    sanitizer = sanitizer if sanitizer is not None else canary.Sanitizer.from_file()
    canary_check = canary_check if canary_check is not None else canary.check
    root, out = _absolute(root), _absolute(out)
    if not root.is_dir() or out.exists():
        raise ReviewError('source or destination refused')
    raw = root / 'harvest/raw'
    if out == raw or out.is_relative_to(raw) or root.is_relative_to(out):
        raise ReviewError('overlapping or raw destination refused')
    for zone in ZONES:
        source = root / zone
        if out == source or out.is_relative_to(source) or source.is_relative_to(out):
            raise ReviewError('overlapping destination refused')
    # Gate names before reading any input bytes, including files later excluded.
    sources = [(zone, path.relative_to(root / zone), path)
               for zone in ZONES for path in _files(root / zone)]
    displaynames = {zone.name + '/' + rel.as_posix(): zone.name + '/' + rel.as_posix()
                    for zone, rel, _path in sources}
    if canary_check(displaynames, skip=False):
        raise ReviewError('known-secret canary found in source name')
    exclusions = [{'file': zone.name + '/' + rel.as_posix(), 'reason': 'excluded source name'}
                  for zone, rel, _path in sources if _excluded(rel)]
    # Excluded names are data omissions, never exemptions from scanner rules.
    inputs = [(zone, rel, _read(path)) for zone, rel, path in sources if not _excluded(rel)]
    policies = {name: _read(root / 'containers' / name) for name in POLICIES}
    try:
        image = policies['gitleaks.image'].decode().strip()
    except UnicodeError:
        raise ReviewError('invalid pinned image') from None
    if not re.fullmatch(r'[^\s]+@sha256:[0-9a-f]{64}', image):
        raise ReviewError('invalid pinned image')
    podman = shlex.split(os.environ.get(preflight.PODMAN_ENV, 'podman'))
    if not podman:
        raise ReviewError('missing container scanner')
    out.parent.mkdir(parents=True, exist_ok=True)
    _safe_components(out.parent)
    out.mkdir(mode=0o700)
    evidence = {'status': 'incomplete', 'method': 'scanner-guided post-redaction',
                'context_loss': True, 'files': [], 'findings': [], 'exclusions': exclusions,
                'policy_sha256': {name: _sha(data) for name, data in policies.items()}}
    try:
        for zone in ZONES:
            (out / zone).mkdir(parents=True)
        (out / 'containers').mkdir()
        for name, data in policies.items():
            (out / 'containers' / name).write_bytes(data)
        for zone, rel, data in inputs:
            path = out / zone / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            evidence['files'].append({'file': zone.name + '/' + rel.as_posix(),
                                      'source_sha256': _sha(data), 'copy_sha256': _sha(_read(path))})
        _evidence(out, evidence, sanitizer)
        config = out / preflight.DEFAULT_CONFIG_REL
        for zone in ZONES:
            directory = out / zone
            cmd = preflight.build_command(directory, config, podman=podman, image=image, gitleaks_bin=None)
            proc = runner(cmd, capture_output=True, text=True, check=False)
            hits = _report(proc, directory)
            evidence['findings'].extend(hits)
            _redact(directory, hits)
        texts = {zone.name + '/' + path.relative_to(out / zone).as_posix(): _read(path).decode('utf-8', errors='replace')
                 for zone in ZONES for path in _files(out / zone)}
        if canary_check(texts, skip=False):
            raise ReviewError('known-secret canary found')
        # The unchanged final preflight writes its normal exact-tree stamp. The wrapper
        # also rejects malformed clean reports, which the legacy preflight ignores.
        def final_runner(cmd, **kwargs):
            proc = runner(cmd, **kwargs)
            mount = cmd[cmd.index('-v') + 1]
            directory = Path(mount.removesuffix(':/scan:ro,z'))
            if _report(proc, directory):
                raise ReviewError('scanner findings remain after review redaction')
            return proc
        result = preflight.run_preflight(preflight.default_inputs(out), out, config=config,
                                         podman=podman, image=image, gitleaks_bin=None, runner=final_runner)
        for row in evidence['files']:
            label, rel = row['file'].split('/', 1)
            zone = ZONES[0] if label == 'redacted' else ZONES[1]
            row['output_sha256'] = _sha(_read(out / zone / rel))
        if not result.stamp or not preflight.has_stamp(out, preflight.default_inputs(out)):
            raise ReviewError('final preflight did not attest the review tree')
        evidence.update(status='complete', tree_sha256=result.tree_hash, stamp=result.stamp.relative_to(out).as_posix())
        _evidence(out, evidence, sanitizer)
        return out
    except Exception:
        # A staged tree is diagnostic only; failed preparation never leaves completion evidence.
        for stamp in (out / preflight.STAMP_DIR).glob('*.ok'):
            stamp.unlink()
        evidence['status'] = 'failed'
        evidence.pop('stamp', None)
        _evidence(out, evidence, sanitizer)
        raise ReviewError('review preparation failed; no valid completion or stamp') from None


def verify_review_root(root: Path, source_root: Path, *, canary_check=None) -> Path:
    """Verify completed review metadata/policies/tree before credentials or network use."""
    root, source_root = _absolute(root), _absolute(source_root)
    if (root == source_root or source_root.is_relative_to(root)
            or any(root.is_relative_to(source_root / zone) for zone in ZONES)):
        raise ReviewError('review/source overlap refused')
    # Validate every host path mounted by analyze-container.sh, including writable
    # outputs which may not have been created by preparation yet.
    for rel in (*ZONES, Path('containers'), Path('cache/preflight'), Path('cache/responses'), Path('findings/raw')):
        mounted = root / rel
        _safe_components(mounted)
        if mounted.exists() and not mounted.is_dir():
            raise ReviewError('mounted review path is not an independent directory')
    _safe_components(source_root / 'scripts')
    if not (source_root / 'scripts').is_dir():
        raise ReviewError('trusted scripts missing')
    data = json.loads(_read(root / 'review.json'))
    digest_re = re.compile(r'[a-f0-9]{64}')
    def digest(value):
        return isinstance(value, str) and digest_re.fullmatch(value) is not None
    def relative(value):
        return (isinstance(value, str) and bool(value) and '\\' not in value
                and not any(ord(c) < 32 for c in value)
                and all(part not in ('', '.', '..') for part in value.split('/')))
    if (not isinstance(data, dict) or data.get('status') != 'complete'
            or data.get('method') != 'scanner-guided post-redaction' or data.get('context_loss') is not True
            or not digest(data.get('tree_sha256'))):
        raise ReviewError('review completion metadata refused')
    hashes = data.get('policy_sha256')
    if not isinstance(hashes, dict) or set(hashes) != set(POLICIES):
        raise ReviewError('review policy metadata refused')
    for name, expected in hashes.items():
        if (not digest(expected) or _sha(_read(root / 'containers' / name)) != expected
                or _sha(_read(source_root / 'containers' / name)) != expected):
            raise ReviewError('review policies differ from approved source')
    files = data.get('files')
    if not isinstance(files, list):
        raise ReviewError('review file metadata refused')
    inventory = {zone.name + '/' + path.relative_to(root / zone).as_posix(): path
                 for zone in ZONES for path in _files(root / zone)}
    check_names = canary_check if canary_check is not None else canary.check
    if check_names({name: name for name in inventory}, skip=False):
        raise ReviewError('known-secret canary found in review name')
    if any(_excluded(Path(name.split('/', 1)[1])) for name in inventory):
        raise ReviewError('excluded review input name refused')
    seen = set()
    for row in files:
        if (not isinstance(row, dict) or set(row) != {'file', 'source_sha256', 'copy_sha256', 'output_sha256'}
                or not relative(row['file']) or row['file'] in seen
                or not all(digest(row[key]) for key in ('source_sha256', 'copy_sha256', 'output_sha256'))
                or row['source_sha256'] != row['copy_sha256'] or row['file'] not in inventory):
            raise ReviewError('review file metadata refused')
        seen.add(row['file'])
    if seen != set(inventory):
        raise ReviewError('review file set changed')
    # Only the validated inventory may be opened, after all name/set checks pass.
    actual = {name: _sha(_read(path)) for name, path in inventory.items()}
    if any(actual[row['file']] != row['output_sha256'] for row in files):
        raise ReviewError('review input content changed')
    exclusions, findings = data.get('exclusions'), data.get('findings')
    if not isinstance(exclusions, list) or not isinstance(findings, list):
        raise ReviewError('review finding metadata refused')
    for row in exclusions:
        if (not isinstance(row, dict) or set(row) != {'file', 'reason'} or not relative(row['file'])
                or row['reason'] != 'excluded source name'):
            raise ReviewError('review exclusion metadata refused')
    for row in findings:
        if (not isinstance(row, dict) or set(row) != {'file', 'start_line', 'end_line', 'rule'}
                or row['file'] not in actual or type(row['start_line']) is not int
                or type(row['end_line']) is not int or not 1 <= row['start_line'] <= row['end_line']
                or not isinstance(row['rule'], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', row['rule'])):
            raise ReviewError('review finding metadata refused')
    tree_digest = preflight.tree_hash(preflight.default_inputs(root), root)
    stamp = data.get('stamp')
    if (tree_digest != data['tree_sha256'] or not relative(stamp)
            or not re.fullmatch(r'cache/preflight/[a-f0-9]{64}\.ok', stamp)
            or not preflight.has_stamp(root, preflight.default_inputs(root))):
        raise ReviewError('review tree or stamp changed')
    ctx = preflight.stamp_context(root)
    if json.loads(_read(root / stamp)) != {'tree_sha256': tree_digest, **ctx}:
        raise ReviewError('review stamp metadata refused')
    return root


def main(argv=None, *, runner=None, sanitizer=None, canary_check=None) -> int:
    parser = argparse.ArgumentParser(description='Create a new independent scanner-guided review root.')
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--verify', action='store_true', help='verify completion before review analysis')
    parser.add_argument('--source-root', type=Path)
    args = parser.parse_args(argv)
    if args.verify and (args.source_root is None or args.out is not None):
        parser.error('--verify requires --source-root and excludes --out')
    if not args.verify and (args.out is None or args.source_root is not None):
        parser.error('preparation requires --out and excludes --source-root')
    try:
        if args.verify:
            verify_review_root(args.root, args.source_root, canary_check=canary_check)
            return 0
        prepare(args.root, args.out, runner=runner, sanitizer=sanitizer, canary_check=canary_check)
    except (ReviewError, OSError, ValueError, TypeError, KeyError, canary.CanaryError):
        print('prepare-review: refused; no valid completion or stamp', file=sys.stderr)
        return 2
    print('prepare-review: complete; review.json records provenance and context loss')
    return 0
