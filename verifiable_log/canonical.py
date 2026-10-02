"""Canonical JSON used for every log entry.

The byte representation is deterministic for semantically equal values.  JSON
objects are rejected if they contain duplicate keys, and object members are
sorted by UTF-16 code unit, matching the deterministic ordering used by
RFC 8785.
"""

from __future__ import annotations

import json
from typing import Any


def _reject_non_finite(value: str):
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def dumps(value: Any) -> bytes:
    text = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=False,
        default=None,
    )
    return text.encode("utf-8")


def loads(data: bytes) -> Any:
    if data.startswith(b"\xef\xbb\xbf"):
        raise ValueError("UTF-8 BOM is not allowed")
    text = data.decode("utf-8", errors="strict")
    return json.loads(
        text,
        parse_constant=_reject_non_finite,
        object_pairs_hook=_reject_duplicates,
    )


def dumps_canonical(value: Any) -> bytes:
    """Return normalized UTF-8 JSON bytes.

    Python's ``sort_keys`` orders by Unicode scalar values.  Canonical JSON
    orders strings by UTF-16 code units, so perform that ordering explicitly.
    """

    return dumps(_canonicalize(value))


def canonicalize(value: Any) -> bytes:
    return dumps_canonical(value)


def _canonicalize(value: Any) -> Any:
    # Round-trip through the strict parser so duplicate-key rejection is
    # applied both to externally supplied bytes and to values already decoded
    # by callers.
    normalized_text = json.dumps(value, ensure_ascii=False, allow_nan=False)
    value = json.loads(
        normalized_text,
        parse_constant=_reject_non_finite,
        object_pairs_hook=_reject_duplicates,
    )
    if isinstance(value, dict):
        ordered = sorted(value.items(), key=lambda item: item[0].encode("utf-16-be"))
        return {key: _canonicalize(child) for key, child in ordered}
    if isinstance(value, list):
        return [_canonicalize(child) for child in value]
    return value
