"""Bounded one-frame subprocess endpoint for the capability-only worker protocol."""

from __future__ import annotations

import os
import sys
from typing import BinaryIO, cast

from bpe.canonical import CanonicalJSONError, canonical_json_bytes, strict_json_loads
from bpe.worker_protocol import (
    MAX_WORKER_RESPONSE_BYTES,
    WorkerErrorResponse,
    WorkerProtocolError,
    WorkerProtocolErrorCode,
    WorkerResponse,
    handle_worker_request,
    validate_worker_response,
)

MAX_REQUEST_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = MAX_WORKER_RESPONSE_BYTES
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 4096

EXIT_OK = 0
EXIT_PROTOCOL_ERROR = 2
EXIT_INTERNAL_ERROR = 3
EXIT_IO_ERROR = 4


class _FrameFailure(ValueError):
    def __init__(self, code: WorkerProtocolErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _transport_error(
    code: WorkerProtocolErrorCode,
    message: str,
) -> WorkerErrorResponse:
    return WorkerErrorResponse(
        schema_version="bpe.worker-response.v1",
        request_id=None,
        request_sha256=None,
        status="error",
        error=WorkerProtocolError(code=code, message=message),
    )


def _read_frame(stdin: BinaryIO) -> object | None:
    raw = stdin.readline(MAX_REQUEST_BYTES + 2)
    if raw == b"":
        return None
    if len(raw) > MAX_REQUEST_BYTES + 1:
        raise _FrameFailure(
            WorkerProtocolErrorCode.FRAME_TOO_LARGE,
            "request frame exceeds the 16384-byte limit",
        )
    if not raw.endswith(b"\n"):
        code = (
            WorkerProtocolErrorCode.FRAME_TOO_LARGE
            if len(raw) > MAX_REQUEST_BYTES
            else WorkerProtocolErrorCode.INVALID_FRAME
        )
        message = (
            "request frame exceeds the 16384-byte limit"
            if code is WorkerProtocolErrorCode.FRAME_TOO_LARGE
            else "request frame must end with one LF byte"
        )
        raise _FrameFailure(code, message)

    payload = raw[:-1]
    if len(payload) > MAX_REQUEST_BYTES:
        raise _FrameFailure(
            WorkerProtocolErrorCode.FRAME_TOO_LARGE,
            "request frame exceeds the 16384-byte limit",
        )
    if not payload or payload.endswith(b"\r"):
        raise _FrameFailure(
            WorkerProtocolErrorCode.INVALID_FRAME,
            "request frame must contain JSON followed by one LF byte",
        )
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise _FrameFailure(
            WorkerProtocolErrorCode.INVALID_ENCODING,
            "request frame must be strict UTF-8",
        ) from exc
    try:
        value = cast(object, strict_json_loads(text))
    except CanonicalJSONError as exc:
        raise _FrameFailure(
            WorkerProtocolErrorCode.INVALID_JSON,
            "request frame is not strict JSON",
        ) from exc
    _validate_json_complexity(value)
    return value


def _validate_json_complexity(value: object) -> None:
    stack: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if depth > MAX_JSON_DEPTH or nodes > MAX_JSON_NODES:
            raise _FrameFailure(
                WorkerProtocolErrorCode.INVALID_JSON,
                "request JSON exceeds the structural complexity limit",
            )
        if isinstance(current, dict):
            for key, child in current.items():
                _validate_json_string(key)
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
        elif isinstance(current, str):
            _validate_json_string(current)


def _validate_json_string(value: str) -> None:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise _FrameFailure(
            WorkerProtocolErrorCode.INVALID_JSON,
            "request JSON strings must contain only Unicode scalar values",
        )


def _encode_response(response: WorkerResponse) -> bytes:
    validated = validate_worker_response(response.model_dump(mode="python"))
    raw = canonical_json_bytes(validated)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("worker response exceeds the fixed transport limit")
    return raw


def _write_response(stdout: BinaryIO, response: WorkerResponse) -> bool:
    raw = _encode_response(response)
    try:
        written = stdout.write(raw)
        if written != len(raw):
            _quarantine_failed_output(stdout)
            return False
        stdout.flush()
    except Exception:
        _quarantine_failed_output(stdout)
        return False
    return True


def _quarantine_failed_output(stdout: BinaryIO) -> None:
    """Prevent interpreter shutdown from retrying a failed buffered write."""

    try:
        output_fd = stdout.fileno()
        null_fd = os.open(os.devnull, os.O_WRONLY)
        if null_fd != output_fd:
            try:
                os.dup2(null_fd, output_fd)
            finally:
                os.close(null_fd)
    except Exception:
        # Cleanup must not replace the stable I/O-failure exit with a traceback.
        pass


def serve_one(stdin: BinaryIO, stdout: BinaryIO) -> int:
    """Consume at most one LF-terminated frame and emit at most one response."""

    try:
        value = _read_frame(stdin)
    except _FrameFailure as exc:
        response = _transport_error(exc.code, exc.message)
        try:
            written = _write_response(stdout, response)
        except Exception:
            return EXIT_INTERNAL_ERROR
        return EXIT_PROTOCOL_ERROR if written else EXIT_IO_ERROR
    except Exception:
        response = _transport_error(
            WorkerProtocolErrorCode.INTERNAL_ERROR,
            "worker transport failed before dispatch",
        )
        try:
            written = _write_response(stdout, response)
        except Exception:
            return EXIT_INTERNAL_ERROR
        return EXIT_INTERNAL_ERROR if written else EXIT_IO_ERROR

    if value is None:
        return EXIT_OK

    try:
        worker_response: WorkerResponse = handle_worker_request(value)
    except Exception:
        worker_response = _transport_error(
            WorkerProtocolErrorCode.INTERNAL_ERROR,
            "worker request handling failed",
        )
        result = EXIT_INTERNAL_ERROR
    else:
        result = EXIT_OK

    try:
        written = _write_response(stdout, worker_response)
    except Exception:
        fallback = _transport_error(
            WorkerProtocolErrorCode.INTERNAL_ERROR,
            "worker response serialization failed",
        )
        try:
            written = _write_response(stdout, fallback)
        except Exception:
            return EXIT_INTERNAL_ERROR
        result = EXIT_INTERNAL_ERROR
    return result if written else EXIT_IO_ERROR


def main() -> int:
    stdin = getattr(sys.stdin, "buffer", None)
    stdout = getattr(sys.stdout, "buffer", None)
    if stdin is None or stdout is None:
        return EXIT_IO_ERROR
    return serve_one(stdin, stdout)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "EXIT_INTERNAL_ERROR",
    "EXIT_IO_ERROR",
    "EXIT_OK",
    "EXIT_PROTOCOL_ERROR",
    "MAX_JSON_DEPTH",
    "MAX_JSON_NODES",
    "MAX_REQUEST_BYTES",
    "MAX_RESPONSE_BYTES",
    "main",
    "serve_one",
]
