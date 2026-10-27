"""Offline stand-ins for the model client. No network, no key."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable

from recon.client import ModelResponse, Usage


def response(findings, *, stop="end_turn", in_tok=100, out_tok=50) -> ModelResponse:
    return ModelResponse(json.dumps({"findings": findings}), stop, Usage(in_tok, out_tok, 0, 0))


@dataclass
class FakeClient:
    """Wrapper-level fake. `script` maps (call index) -> ModelResponse or raises when callable."""
    script: Callable[[int, list], object] = lambda i, messages: response([])
    tokens: int = 1000
    create_calls: list = field(default_factory=list)
    count_calls: list = field(default_factory=list)
    text_calls: list = field(default_factory=list)
    batches: dict = field(default_factory=dict)

    def count_tokens(self, model, system, messages):
        self.count_calls.append((model, tuple(system), messages))
        return self.tokens

    def create(self, model, system, messages, max_tokens):
        idx = len(self.create_calls)
        self.create_calls.append((model, tuple(system), messages, max_tokens))
        out = self.script(idx, messages)
        if isinstance(out, BaseException):
            raise out
        return out

    def create_text(self, model, system, messages, max_tokens):
        self.text_calls.append((model, tuple(system), messages, max_tokens))
        return ModelResponse("# Gap report\n", "end_turn", Usage(10, 5, 0, 0))

    def batch_create(self, model, items, max_tokens):
        self.batches["b1"] = {cid: self.script(i, messages) for i, (cid, _s, messages) in enumerate(items)}
        return "b1"

    def batch_status(self, batch_id):
        return "ended"

    def batch_results(self, batch_id):
        return self.batches[batch_id]
