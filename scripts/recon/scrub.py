"""Remove API-key material from any text before it is displayed, logged, cached or stored."""
from __future__ import annotations

import os
import re

KEY_RE = re.compile(r"sk-ant-[A-Za-z0-9_\-]*")
KEY_ENV = "ANTHROPIC_API_KEY"
MIN_ENV_SECRET_LEN = 8
MASK = "<REDACTED:key>"


def scrub(text: str) -> str:
    """Mask sk-ant- patterns and the literal value of $ANTHROPIC_API_KEY (never printed itself)."""
    out = KEY_RE.sub(MASK, str(text))
    env_value = os.environ.get(KEY_ENV, "")
    if len(env_value) >= MIN_ENV_SECRET_LEN:
        out = out.replace(env_value, MASK)
    return out
