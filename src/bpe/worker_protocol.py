"""Closed Phase 0 protocol for querying worker capabilities.

The protocol intentionally has no candidate-execution request.  Adding one is a
versioned protocol change, not an extension point on these models.
"""

from __future__ import annotations

import subprocess
from collections.abc import Mapping
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    RootModel,
    TypeAdapter,
    ValidationError,
    field_validator,
)

from bpe.canonical import (
    CanonicalJSONError,
    canonical_json_bytes,
    sha256_json,
    strict_json_loads,
)
from bpe.capabilities import WorkerCapabilities, probe_capabilities
from bpe.models import Sha256, StableId

_MAX_ERROR_MESSAGE_LENGTH = 512
MAX_WORKER_RESPONSE_BYTES = 32 * 1024


class _ProtocolModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        allow_inf_nan=False,
        revalidate_instances="always",
        strict=True,
    )


class WorkerProtocolErrorCode(StrEnum):
    """Stable machine-readable failures exposed by the Phase 0 endpoint."""

    INVALID_REQUEST = "invalid_request"
    UNSUPPORTED_METHOD = "unsupported_method"
    CAPABILITY_PROBE_FAILED = "capability_probe_failed"
    INVALID_ENCODING = "invalid_encoding"
    INVALID_FRAME = "invalid_frame"
    INVALID_JSON = "invalid_json"
    FRAME_TOO_LARGE = "frame_too_large"
    INTERNAL_ERROR = "internal_error"


class CapabilitiesRequest(_ProtocolModel):
    """The only request admitted by the Phase 0 worker protocol."""

    schema_version: Literal["bpe.worker-request.v1"]
    request_id: StableId
    method: Literal["capabilities"]


class _UnknownMethodRequest(_ProtocolModel):
    """Otherwise-valid v1 envelope carrying an unsupported method name."""

    schema_version: Literal["bpe.worker-request.v1"]
    request_id: StableId
    method: StableId


class WorkerProtocolError(_ProtocolModel):
    code: WorkerProtocolErrorCode
    message: str = Field(min_length=1, max_length=_MAX_ERROR_MESSAGE_LENGTH)

    @field_validator("code", mode="before")
    @classmethod
    def parse_known_code(cls, value: object) -> WorkerProtocolErrorCode:
        if isinstance(value, WorkerProtocolErrorCode):
            return value
        if isinstance(value, str):
            try:
                return WorkerProtocolErrorCode(value)
            except ValueError as exc:
                raise ValueError("unknown worker protocol error code") from exc
        raise ValueError("worker protocol error code must be a string")

    @field_validator("message")
    @classmethod
    def message_must_be_single_line(cls, value: str) -> str:
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("message must not contain control characters")
        return value


class CapabilitiesSuccessResponse(_ProtocolModel):
    schema_version: Literal["bpe.worker-response.v1"]
    request_id: StableId
    request_sha256: Sha256
    status: Literal["success"]
    capabilities: WorkerCapabilities


class WorkerErrorResponse(_ProtocolModel):
    schema_version: Literal["bpe.worker-response.v1"]
    request_id: StableId | None
    request_sha256: Sha256 | None
    status: Literal["error"]
    error: WorkerProtocolError


WorkerResponse = Annotated[
    CapabilitiesSuccessResponse | WorkerErrorResponse,
    Field(discriminator="status"),
]


class WorkerResponseEnvelope(RootModel[WorkerResponse]):
    """Schema-export wrapper for the discriminated response union."""

    model_config = ConfigDict(frozen=True, strict=True)


class WorkerProtocolViolation(ValueError):
    """A worker process or response violated the host acceptance contract."""

_REQUEST_ID_ADAPTER: TypeAdapter[StableId] = TypeAdapter(StableId)
_RESPONSE_ADAPTER: TypeAdapter[WorkerResponse] = TypeAdapter(WorkerResponse)


def validate_worker_response(value: object) -> WorkerResponse:
    """Validate an untrusted response using the required status discriminator."""

    return _RESPONSE_ADAPTER.validate_python(value, strict=True)


def validate_correlated_worker_response(
    request: CapabilitiesRequest,
    value: object,
) -> WorkerResponse:
    """Validate an untrusted response and require exact request correlation."""

    frozen_request = CapabilitiesRequest.model_validate(
        request.model_dump(mode="python"),
        strict=True,
    )
    response = validate_worker_response(value)
    if (
        response.request_id != frozen_request.request_id
        or response.request_sha256 != sha256_json(frozen_request)
    ):
        raise WorkerProtocolViolation(
            "worker response does not bind the outstanding request"
        )
    return response


def validate_worker_subprocess_result(
    request: CapabilitiesRequest,
    result: subprocess.CompletedProcess[bytes],
) -> CapabilitiesSuccessResponse:
    """Validate the complete raw host-side result of one capability request.

    Object-level response validation is intentionally insufficient here: parsing
    first can erase duplicate keys, extra frames, and noncanonical representations.
    This is the host acceptance boundary and therefore returns success only.
    """

    if result.returncode != 0:
        raise WorkerProtocolViolation("worker process did not exit successfully")
    if result.stderr != b"":
        raise WorkerProtocolViolation("worker process produced unexpected stderr")
    if not isinstance(result.stdout, bytes):
        raise WorkerProtocolViolation("worker stdout must be captured as bytes")

    raw = result.stdout
    if not raw:
        raise WorkerProtocolViolation("worker process produced no response")
    if len(raw) > MAX_WORKER_RESPONSE_BYTES:
        raise WorkerProtocolViolation("worker response exceeds the fixed byte limit")
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise WorkerProtocolViolation("worker stdout must contain exactly one response frame")

    try:
        value = strict_json_loads(raw)
        response = validate_correlated_worker_response(request, value)
        canonical = canonical_json_bytes(response)
    except (CanonicalJSONError, ValidationError) as exc:
        raise WorkerProtocolViolation("worker response is not strict protocol JSON") from exc

    if canonical != raw:
        raise WorkerProtocolViolation("worker response is not canonical protocol JSON")
    if not isinstance(response, CapabilitiesSuccessResponse):
        raise WorkerProtocolViolation("worker returned an error response")
    return response


def handle_worker_request(
    value: object,
    *,
    capabilities: WorkerCapabilities | None = None,
) -> WorkerResponse:
    """Validate one request and return a correlated, non-reflective response.

    ``capabilities`` is injectable for callers that already performed a probe and
    for deterministic tests.  It is revalidated before it crosses the protocol
    boundary so Pydantic's unsafe construction helpers cannot manufacture
    execution claims.
    """

    request_id = _safe_request_id(value)
    request_sha256 = _safe_request_sha256(value)
    try:
        request = CapabilitiesRequest.model_validate(value, strict=True)
    except ValidationError:
        if _has_unsupported_method(value):
            return _error_response(
                request_id,
                request_sha256,
                WorkerProtocolErrorCode.UNSUPPORTED_METHOD,
                "only the capabilities method is available in Phase 0",
            )
        return _error_response(
            request_id,
            request_sha256,
            WorkerProtocolErrorCode.INVALID_REQUEST,
            "request does not match the Phase 0 capability protocol",
        )

    # A validated request is always canonicalizable.  Recomputing from the
    # validated model is a defensive fallback for unusual Mapping implementations.
    request_sha256 = request_sha256 or sha256_json(request)

    try:
        observed = capabilities if capabilities is not None else probe_capabilities()
        validated = WorkerCapabilities.model_validate(
            observed.model_dump(mode="python"),
            strict=True,
        )
    # The protocol boundary must turn probe failures into a closed error envelope;
    # it must not leak platform-specific exceptions or their messages to clients.
    except Exception:
        return _error_response(
            request.request_id,
            request_sha256,
            WorkerProtocolErrorCode.CAPABILITY_PROBE_FAILED,
            "the worker capability probe did not produce a valid snapshot",
        )

    return CapabilitiesSuccessResponse(
        schema_version="bpe.worker-response.v1",
        request_id=request.request_id,
        request_sha256=request_sha256,
        status="success",
        capabilities=validated,
    )


def _safe_request_id(value: object) -> StableId | None:
    if not isinstance(value, Mapping):
        return None
    try:
        return _REQUEST_ID_ADAPTER.validate_python(value.get("request_id"), strict=True)
    except ValidationError:
        return None


def _has_unsupported_method(value: object) -> bool:
    try:
        request = _UnknownMethodRequest.model_validate(value, strict=True)
    except ValidationError:
        return False
    return request.method != "capabilities"


def _safe_request_sha256(value: object) -> Sha256 | None:
    try:
        return sha256_json(value)
    except CanonicalJSONError:
        return None


def _error_response(
    request_id: StableId | None,
    request_sha256: Sha256 | None,
    code: WorkerProtocolErrorCode,
    message: str,
) -> WorkerErrorResponse:
    return WorkerErrorResponse(
        schema_version="bpe.worker-response.v1",
        request_id=request_id,
        request_sha256=request_sha256,
        status="error",
        error=WorkerProtocolError(code=code, message=message),
    )


__all__ = [
    "MAX_WORKER_RESPONSE_BYTES",
    "CapabilitiesRequest",
    "CapabilitiesSuccessResponse",
    "WorkerErrorResponse",
    "WorkerProtocolError",
    "WorkerProtocolErrorCode",
    "WorkerProtocolViolation",
    "WorkerResponse",
    "WorkerResponseEnvelope",
    "handle_worker_request",
    "validate_correlated_worker_response",
    "validate_worker_response",
    "validate_worker_subprocess_result",
]
