"""Content-addressed result cache: cache/<sha256(chunk + PROMPT_VERSION + model + SCHEMA_VERSION)>.json."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from recon.scrub import scrub


def cache_key(chunk_text: str, prompt_version: str, model: str, schema_version: str, *,
              schema_hash: str = "", prompt_hash: str = "", max_tokens: int = 0) -> str:
    h = hashlib.sha256()
    for part in (chunk_text, prompt_version, model, schema_version, schema_hash, prompt_hash, str(max_tokens)):
        h.update(part.encode())
        h.update(b"\0")
    return h.hexdigest()


class Cache:
    def __init__(self, directory: Path) -> None:
        self._dir = Path(directory)

    def get(self, key: str) -> dict | None:
        path = self._dir / f"{key}.json"
        try:
            value = json.loads(path.read_text())
        except (OSError, ValueError):
            return None
        return value if isinstance(value, dict) else None

    def put(self, key: str, value: dict) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)
        (self._dir / f"{key}.json").write_text(scrub(json.dumps(value, sort_keys=True)))
