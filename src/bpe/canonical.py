"""Canonical JSON and content hashing helpers."""

from __future__ import annotations

import hashlib
import json
import math
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel


class CanonicalJSONError(ValueError):
    """Input cannot be parsed or serialized as strict canonical JSON."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalJSONError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite_constant(value: str) -> None:
    raise CanonicalJSONError(f"non-finite JSON number: {value}")


def _parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise CanonicalJSONError(f"non-finite JSON number: {value}")
    return parsed


def strict_json_loads(raw: str | bytes | bytearray) -> Any:
    """Parse RFC-style JSON while rejecting duplicate keys and non-finite numbers."""

    try:
        return json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite_constant,
            parse_float=_parse_finite_float,
        )
    except CanonicalJSONError:
        raise
    except (UnicodeError, ValueError, OverflowError, RecursionError) as exc:
        raise CanonicalJSONError(f"invalid JSON: {exc}") from exc


def canonical_data(value: BaseModel | Any) -> Any:
    """Return JSON-compatible data with no representation-only Pydantic values."""

    if isinstance(value, BaseModel):
        return canonical_data(value.model_dump(mode="json", by_alias=True, exclude_none=False))
    if isinstance(value, dict):
        return {str(key): canonical_data(child) for key, child in value.items()}
    if isinstance(value, (tuple, list)):
        return [canonical_data(child) for child in value]
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    return value


def canonical_json_bytes(value: BaseModel | Any) -> bytes:
    """Serialize a value deterministically for hashes and replay artifacts."""

    try:
        return (
            json.dumps(
                canonical_data(value),
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
    except CanonicalJSONError:
        raise
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError) as exc:
        raise CanonicalJSONError(f"cannot encode canonical JSON: {exc}") from exc


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_json(value: BaseModel | Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size
