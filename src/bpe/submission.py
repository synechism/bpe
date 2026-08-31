"""Strict extraction of the one candidate C translation unit."""

from __future__ import annotations

import re


class SubmissionError(ValueError):
    """The model response does not satisfy the candidate-source contract."""


_FENCE = re.compile(r"\A\s*```(?:c|C)\s*\n(?P<source>.*?)\n```\s*\Z", re.DOTALL)


def extract_c_source(raw: bytes, *, max_bytes: int = 65536, allow_fence: bool = True) -> bytes:
    """Extract plain C or exactly one isolated C fence without repairing content."""

    if len(raw) > max_bytes:
        raise SubmissionError(f"response is {len(raw)} bytes; limit is {max_bytes}")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise SubmissionError("response is not valid UTF-8") from exc
    if "\x00" in text:
        raise SubmissionError("response contains a NUL byte")

    if "```" not in text:
        if not text.strip():
            raise SubmissionError("response is empty")
        return raw

    if not allow_fence:
        raise SubmissionError("Markdown fences are disabled for this task")
    if text.count("```") != 2:
        raise SubmissionError("response must contain exactly one Markdown fence")
    match = _FENCE.fullmatch(text)
    if not match:
        raise SubmissionError(
            "response must contain exactly one C fence and only whitespace outside it"
        )
    source = match.group("source")
    if not source.strip():
        raise SubmissionError("C fence is empty")
    return source.encode("utf-8")
