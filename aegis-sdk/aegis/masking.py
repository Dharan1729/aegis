"""Removes the fields a policy says must be masked from a tool's output.

Structured output (dicts, lists, pydantic models, and strings that hold
JSON) is masked key by key, at any depth, matching key names without regard
to case. Anything else cannot be masked reliably: masking free text would
mean guessing where a value is. `mask()` reports that instead of guessing,
and the caller decides (by default, the guard withholds the output).
"""

import json
from dataclasses import dataclass
from typing import Any

MASK = "[MASKED]"


@dataclass
class MaskResult:
    value: Any
    ok: bool  # False: the output had a shape we cannot mask
    masked_keys: int = 0


def _walk(value: Any, fields: set[str], counter: list[int]) -> Any:
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if isinstance(key, str) and key.lower() in fields:
                out[key] = MASK
                counter[0] += 1
            else:
                out[key] = _walk(item, fields, counter)
        return out
    if isinstance(value, list | tuple):
        return type(value)(_walk(item, fields, counter) for item in value)
    return value


def _is_plain(value: Any) -> bool:
    return value is None or isinstance(value, bool | int | float)


def mask(value: Any, fields: list[str]) -> MaskResult:
    """Returns `value` with every key named in `fields` replaced by
    "[MASKED]". With no fields, returns `value` untouched."""
    if not fields:
        return MaskResult(value=value, ok=True)
    wanted = {f.lower() for f in fields}
    counter = [0]

    if hasattr(value, "model_dump") and callable(value.model_dump):  # pydantic v2 model
        value = value.model_dump()
    if isinstance(value, dict | list | tuple):
        return MaskResult(value=_walk(value, wanted, counter), ok=True, masked_keys=counter[0])
    if _is_plain(value):
        return MaskResult(value=value, ok=True)
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except ValueError:
            return MaskResult(value=value, ok=False)
        if _is_plain(parsed) or isinstance(parsed, str):
            # A JSON scalar is a bare value, and a bare value has no keys to
            # tell us whether it is one of the masked fields.
            return MaskResult(value=value, ok=False)
        masked = _walk(parsed, wanted, counter)
        return MaskResult(value=json.dumps(masked), ok=True, masked_keys=counter[0])
    return MaskResult(value=value, ok=False)
