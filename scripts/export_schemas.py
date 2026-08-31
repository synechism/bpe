"""Regenerate committed JSON Schemas from the strict Pydantic models."""

from __future__ import annotations

import json
from pathlib import Path

from bpe.schemas import JSON_SCHEMAS


def main() -> None:
    output = Path("schemas")
    output.mkdir(parents=True, exist_ok=True)
    for filename, model_type in sorted(JSON_SCHEMAS.items()):
        content = json.dumps(model_type.model_json_schema(), indent=2, sort_keys=True) + "\n"
        (output / filename).write_text(content, encoding="utf-8")


if __name__ == "__main__":
    main()
