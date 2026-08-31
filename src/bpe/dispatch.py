"""Signed, one-shot dispatch admission without candidate execution.

This module is a Phase 1A control-plane primitive.  It authenticates a short-lived
authorization, binds it to exact prepared-job and execution-profile identities, and
atomically consumes it in a durable ledger.  It never launches a process and every receipt
is structurally non-authoritative.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import secrets
import sqlite3
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from bpe.canonical import canonical_json_bytes, sha256_bytes, sha256_json
from bpe.job import EvaluationJobManifest, JobBlobRef, LoadedEvaluationJob, LoadedJobBlob
from bpe.models import EnvironmentFingerprint, Isolation, Sha256, StableId

MAX_AUTHORIZATION_LIFETIME_SECONDS = 15 * 60
DISPATCH_SIGNING_DOMAIN = b"BPE\x00dispatch-authorization\x00v1\x00"

_BASE64URL_PATTERN = r"^[A-Za-z0-9_-]+$"
_BASE64URL = re.compile(_BASE64URL_PATTERN)
_PUBLIC_KEY_BASE64URL_PATTERN = r"^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$"
_SIGNATURE_BASE64URL_PATTERN = r"^[A-Za-z0-9_-]{85}[AQgw]$"
_PUBLIC_KEY_BYTES = 32
_SIGNATURE_BYTES = 64
_LEDGER_APPLICATION_ID = 0x42504531
_LEDGER_USER_VERSION = 1

_CREATE_LEDGER_TABLE = """
CREATE TABLE dispatch_claims (
    authorization_id TEXT PRIMARY KEY,
    authorization_sha256 TEXT NOT NULL UNIQUE,
    payload_sha256 TEXT NOT NULL,
    signature_key_id TEXT NOT NULL,
    trust_store_id TEXT NOT NULL,
    trust_store_sha256 TEXT NOT NULL,
    dispatch_nonce TEXT NOT NULL UNIQUE,
    claim_id TEXT NOT NULL UNIQUE,
    claim_nonce TEXT NOT NULL UNIQUE,
    claimed_at_unix INTEGER NOT NULL,
    receipt_sha256 TEXT NOT NULL UNIQUE,
    job_manifest_sha256 TEXT NOT NULL,
    binding_sha256 TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    policy_sha256 TEXT NOT NULL,
    retry_index INTEGER NOT NULL,
    retry_of_authorization_id TEXT UNIQUE,
    retry_of_claim_sha256 TEXT UNIQUE,
    UNIQUE(authorization_id, receipt_sha256),
    FOREIGN KEY(retry_of_authorization_id, retry_of_claim_sha256)
        REFERENCES dispatch_claims(authorization_id, receipt_sha256),
    CHECK(length(authorization_sha256) = 64),
    CHECK(length(payload_sha256) = 64),
    CHECK(length(trust_store_sha256) = 64),
    CHECK(length(dispatch_nonce) = 64),
    CHECK(length(claim_id) = 64),
    CHECK(length(claim_nonce) = 64),
    CHECK(length(receipt_sha256) = 64),
    CHECK(length(job_manifest_sha256) = 64),
    CHECK(length(binding_sha256) = 64),
    CHECK(length(policy_sha256) = 64),
    CHECK(claimed_at_unix >= 0),
    CHECK(retry_index >= 0),
    CHECK(retry_of_claim_sha256 IS NULL OR length(retry_of_claim_sha256) = 64),
    CHECK(
        (retry_index = 0 AND retry_of_authorization_id IS NULL
            AND retry_of_claim_sha256 IS NULL)
        OR
        (retry_index > 0 AND retry_of_authorization_id IS NOT NULL
            AND retry_of_claim_sha256 IS NOT NULL)
    )
) WITHOUT ROWID
"""

_CREATE_LEDGER_STATE = """
CREATE TABLE dispatch_state (
    singleton INTEGER PRIMARY KEY,
    clock_high_water_unix INTEGER NOT NULL,
    CHECK(singleton = 1),
    CHECK(clock_high_water_unix >= 0)
) WITHOUT ROWID
"""


class DispatchAdmissionError(ValueError):
    """A dispatch authorization or claim failed closed."""


class DispatchAuthorizationError(DispatchAdmissionError):
    """A signed authorization is invalid, untrusted, stale, or misbound."""


class DispatchExpectationError(DispatchAdmissionError):
    """Trusted local job/profile inputs cannot form a dispatch expectation."""


class DispatchLedgerError(DispatchAdmissionError):
    """The durable one-shot claim ledger is unavailable or unsafe."""


class DispatchAlreadyClaimed(DispatchLedgerError):
    """An authorization ID or signed envelope was already consumed."""


class _DispatchModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        allow_inf_nan=False,
        revalidate_instances="always",
        strict=True,
    )


class ExecutionResourceProfile(_DispatchModel):
    """Typed process and filesystem ceilings; no opaque command or environment surface."""

    schema_version: Literal["bpe.execution-resource-profile.v1"]
    profile_id: StableId
    wall_timeout_ms: Annotated[int, Field(ge=100, le=600_000)]
    cpu_time_seconds: Annotated[int, Field(ge=1, le=600)]
    memory_bytes: Annotated[int, Field(ge=64 * 1024 * 1024, le=64 * 1024**3)]
    swap_bytes: Literal[0]
    pids_max: Annotated[int, Field(ge=1, le=4096)]
    open_files_max: Annotated[int, Field(ge=8, le=65_536)]
    file_size_bytes: Annotated[int, Field(ge=1024, le=1024**3)]
    stack_bytes: Annotated[int, Field(ge=64 * 1024, le=64 * 1024**2)]
    stdout_bytes: Annotated[int, Field(ge=0, le=16 * 1024**2)]
    stderr_bytes: Annotated[int, Field(ge=0, le=16 * 1024**2)]
    tmpfs_bytes: Annotated[int, Field(ge=1024**2, le=16 * 1024**3)]
    tmpfs_inodes: Annotated[int, Field(ge=16, le=1_000_000)]
    network_enabled: Literal[False]
    core_dumps_enabled: Literal[False]

    @model_validator(mode="after")
    def limits_are_coherent(self) -> Self:
        if self.cpu_time_seconds * 1000 > self.wall_timeout_ms:
            raise ValueError("CPU time cannot exceed the whole wall-clock limit")
        if self.stack_bytes > self.memory_bytes:
            raise ValueError("stack limit cannot exceed the memory limit")
        if self.file_size_bytes > self.tmpfs_bytes:
            raise ValueError("one file cannot exceed the entire tmpfs limit")
        return self


class SnapshotComponents(_DispatchModel):
    """External snapshot resources that Firecracker does not authenticate as one unit."""

    vm_state_sha256: Sha256
    memory_sha256: Sha256
    kernel_image_sha256: Sha256
    kernel_config_sha256: Sha256
    kernel_btf_sha256: Sha256
    rootfs_sha256: Sha256
    block_device_config_sha256: Sha256
    vsock_config_sha256: Sha256


class ExecutionProfile(_DispatchModel):
    """Declarative microVM identity for admission; execution remains disabled in v1."""

    schema_version: Literal["bpe.execution-profile.v1"]
    profile_id: StableId
    worker_pool_audience: StableId
    environment: EnvironmentFingerprint
    environment_sha256: Sha256
    resources: ExecutionResourceProfile
    resource_profile_sha256: Sha256
    firecracker_version: Annotated[str, Field(min_length=1, max_length=128)]
    firecracker_sha256: Sha256
    jailer_sha256: Sha256
    guest_agent_sha256: Sha256
    seccomp_policy_sha256: Sha256
    jailer_config_sha256: Sha256
    snapshot: SnapshotComponents
    snapshot_components_sha256: Sha256
    host_kernel_release: Annotated[str, Field(min_length=1, max_length=256)]
    host_kernel_sha256: Sha256
    host_architecture: StableId
    vcpu_count: Literal[1]
    smt_enabled: Literal[False]
    cpu_vendor: StableId
    cpu_model: Annotated[str, Field(min_length=1, max_length=256)]
    cpu_template: StableId | None = None
    cpu_features: Annotated[tuple[StableId, ...], Field(min_length=1, max_length=256)]
    snapshot_compatibility_profile: StableId
    execution_implemented: Literal[False]
    authoritative_ready: Literal[False]

    @field_validator("cpu_features", mode="before")
    @classmethod
    def cpu_features_accept_json_arrays(cls, value: object) -> object:
        if isinstance(value, list):
            return tuple(value)
        return value

    @model_validator(mode="after")
    def profile_is_cross_bound_and_nonexecuting(self) -> Self:
        if self.environment.isolation != Isolation.MICROVM:
            raise ValueError("execution profile v1 requires a microVM environment")
        if self.environment.snapshot_sha256 is None:
            raise ValueError("execution profile environment lacks a snapshot identity")
        if self.environment_sha256 != sha256_json(self.environment):
            raise ValueError("execution profile environment digest is inconsistent")
        if self.resource_profile_sha256 != sha256_json(self.resources):
            raise ValueError("execution profile resource digest is inconsistent")
        if self.environment.resource_limits_sha256 != self.resource_profile_sha256:
            raise ValueError("environment does not bind the typed resource profile")
        if self.snapshot_components_sha256 != sha256_json(self.snapshot):
            raise ValueError("execution profile snapshot-component digest is inconsistent")
        if self.environment.snapshot_sha256 != self.snapshot_components_sha256:
            raise ValueError("environment snapshot digest does not bind its components")
        if (
            self.snapshot.kernel_image_sha256 != self.environment.kernel_image_sha256
            or self.snapshot.kernel_config_sha256
            != self.environment.kernel_config_sha256
            or self.snapshot.kernel_btf_sha256 != self.environment.kernel_btf_sha256
            or self.snapshot.rootfs_sha256 != self.environment.rootfs_sha256
        ):
            raise ValueError("execution profile snapshot differs from its environment")
        if self.host_architecture != self.environment.architecture:
            raise ValueError("execution profile host architecture differs from environment")
        if tuple(sorted(set(self.cpu_features))) != self.cpu_features:
            raise ValueError("CPU features must be unique and sorted")
        return self


DispatchPurpose = Literal[
    "training",
    "development",
    "calibration",
    "validation",
    "sealed_eval",
    "benchmark",
]


class DispatchAuthorizationPayload(_DispatchModel):
    """Short-lived one-shot authority, signed by an external control plane."""

    schema_version: Literal["bpe.dispatch-authorization-payload.v1"]
    authorization_id: StableId
    dispatch_nonce: Sha256
    job_manifest_sha256: Sha256
    request_sha256: Sha256
    experiment_sha256: Sha256
    environment_sha256: Sha256
    execution_profile_sha256: Sha256
    resource_profile_sha256: Sha256
    purpose: DispatchPurpose
    worker_pool_audience: StableId
    policy_id: StableId
    policy_sha256: Sha256
    issued_at_unix: Annotated[int, Field(ge=0)]
    not_before_unix: Annotated[int, Field(ge=0)]
    expires_at_unix: Annotated[int, Field(ge=0)]
    retry_index: Annotated[int, Field(ge=0, le=16)] = 0
    retry_of_authorization_id: StableId | None = None
    retry_of_claim_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def time_and_retry_lineage_are_closed(self) -> Self:
        if not self.issued_at_unix <= self.not_before_unix < self.expires_at_unix:
            raise ValueError("authorization times must be ordered")
        if self.expires_at_unix - self.issued_at_unix > MAX_AUTHORIZATION_LIFETIME_SECONDS:
            raise ValueError("authorization validity exceeds the fixed lifetime")
        if self.dispatch_nonce == "0" * 64:
            raise ValueError("dispatch nonce cannot use the all-zero placeholder")
        parent_values = (
            self.retry_of_authorization_id,
            self.retry_of_claim_sha256,
        )
        if (
            self.retry_index == 0
            and any(value is not None for value in parent_values)
        ) or (
            self.retry_index > 0
            and any(value is None for value in parent_values)
        ):
            raise ValueError("retry index, parent authorization, and parent claim must agree")
        if self.retry_of_authorization_id == self.authorization_id:
            raise ValueError("an authorization cannot name itself as its retry parent")
        if self.retry_of_claim_sha256 == "0" * 64:
            raise ValueError("retry parent claim cannot use the all-zero placeholder")
        return self


class SignedDispatchAuthorization(_DispatchModel):
    schema_version: Literal["bpe.signed-dispatch-authorization.v1"]
    algorithm: Literal["Ed25519"]
    key_id: StableId
    payload: DispatchAuthorizationPayload
    payload_sha256: Sha256
    signature_base64url: Annotated[
        str,
        Field(min_length=86, max_length=86, pattern=_SIGNATURE_BASE64URL_PATTERN),
    ]

    @field_validator("signature_base64url")
    @classmethod
    def signature_is_unpadded_base64url(cls, value: str) -> str:
        _decode_base64url(value, expected_bytes=_SIGNATURE_BYTES, label="signature")
        return value

    @model_validator(mode="after")
    def payload_digest_is_exact(self) -> Self:
        if self.payload_sha256 != sha256_json(self.payload):
            raise ValueError("signed authorization payload digest is inconsistent")
        return self


class DispatchTrustKey(_DispatchModel):
    key_id: StableId
    algorithm: Literal["Ed25519"]
    public_key_base64url: Annotated[
        str,
        Field(min_length=43, max_length=43, pattern=_PUBLIC_KEY_BASE64URL_PATTERN),
    ]
    valid_from_unix: Annotated[int, Field(ge=0)]
    valid_until_unix: Annotated[int, Field(ge=0)]
    revoked: bool = False

    @field_validator("public_key_base64url")
    @classmethod
    def public_key_is_unpadded_base64url(cls, value: str) -> str:
        _decode_base64url(value, expected_bytes=_PUBLIC_KEY_BYTES, label="public key")
        return value

    @model_validator(mode="after")
    def key_interval_is_nonempty(self) -> Self:
        if self.valid_from_unix >= self.valid_until_unix:
            raise ValueError("dispatch trust-key validity interval is empty")
        return self


class DispatchTrustStore(_DispatchModel):
    """Trusted local configuration; the store must be authenticated out of band."""

    schema_version: Literal["bpe.dispatch-trust-store.v1"]
    trust_store_id: StableId
    keys: Annotated[tuple[DispatchTrustKey, ...], Field(min_length=1, max_length=64)]

    @field_validator("keys", mode="before")
    @classmethod
    def keys_accept_json_arrays(cls, value: object) -> object:
        if isinstance(value, list):
            return tuple(value)
        return value

    @model_validator(mode="after")
    def key_identities_are_unique(self) -> Self:
        identifiers = [key.key_id for key in self.keys]
        public_keys = [key.public_key_base64url for key in self.keys]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("dispatch trust-store key IDs must be unique")
        if len(public_keys) != len(set(public_keys)):
            raise ValueError("dispatch trust-store public keys must be unique")
        return self


@dataclass(frozen=True)
class DispatchExpectation:
    job_manifest_sha256: str
    request_sha256: str
    experiment_sha256: str
    environment_sha256: str
    execution_profile_sha256: str
    resource_profile_sha256: str
    purpose: DispatchPurpose
    worker_pool_audience: str
    policy_id: str
    policy_sha256: str


@dataclass(frozen=True)
class VerifiedDispatchAuthorization:
    authorization: SignedDispatchAuthorization
    authorization_sha256: str
    payload_sha256: str
    trust_store_id: str
    trust_store_sha256: str
    verified_at_unix: int


def _current_unix_time() -> int:
    """Read the worker wall clock used for authorization validity decisions."""

    return time.time_ns() // 1_000_000_000


def _new_claim_nonce() -> str:
    """Generate an unpredictable worker-side nonce for a committed claim receipt."""

    return secrets.token_hex(32)


def _dispatch_binding_sha256(payload: DispatchAuthorizationPayload) -> str:
    """Hash fields that every authorization in one retry lineage must preserve."""

    return sha256_json(
        {
            "schema_version": "bpe.dispatch-binding.v1",
            "job_manifest_sha256": payload.job_manifest_sha256,
            "request_sha256": payload.request_sha256,
            "experiment_sha256": payload.experiment_sha256,
            "environment_sha256": payload.environment_sha256,
            "execution_profile_sha256": payload.execution_profile_sha256,
            "resource_profile_sha256": payload.resource_profile_sha256,
            "purpose": payload.purpose,
            "worker_pool_audience": payload.worker_pool_audience,
            "policy_id": payload.policy_id,
            "policy_sha256": payload.policy_sha256,
        }
    )


class DispatchAdmissionReceipt(_DispatchModel):
    schema_version: Literal["bpe.dispatch-admission-receipt.v1"]
    status: Literal["claimed_not_executed"]
    authorization_id: StableId
    authorization_sha256: Sha256
    authorization_payload_sha256: Sha256
    signature_key_id: StableId
    trust_store_id: StableId
    trust_store_sha256: Sha256
    claim_id: Sha256
    claim_nonce: Sha256
    claimed_at_unix: Annotated[int, Field(ge=0)]
    dispatch_nonce: Sha256
    job_manifest_sha256: Sha256
    request_sha256: Sha256
    experiment_sha256: Sha256
    environment_sha256: Sha256
    execution_profile_sha256: Sha256
    resource_profile_sha256: Sha256
    purpose: DispatchPurpose
    worker_pool_audience: StableId
    policy_id: StableId
    policy_sha256: Sha256
    retry_index: Annotated[int, Field(ge=0, le=16)]
    retry_of_authorization_id: StableId | None
    retry_of_claim_sha256: Sha256 | None
    signature_verified: Literal[True]
    execution_started: Literal[False]
    authoritative: Literal[False]

    @model_validator(mode="after")
    def claim_identity_is_nonplaceholder(self) -> Self:
        if (
            self.claim_id == "0" * 64
            or self.claim_nonce == "0" * 64
            or self.dispatch_nonce == "0" * 64
        ):
            raise ValueError("dispatch claim identities cannot use all-zero placeholders")
        parent_values = (
            self.retry_of_authorization_id,
            self.retry_of_claim_sha256,
        )
        if (
            self.retry_index == 0
            and any(value is not None for value in parent_values)
        ) or (
            self.retry_index > 0
            and any(value is None for value in parent_values)
        ):
            raise ValueError("dispatch receipt retry lineage is inconsistent")
        return self


def _decode_base64url(value: str, *, expected_bytes: int, label: str) -> bytes:
    if not _BASE64URL.fullmatch(value) or "=" in value:
        raise ValueError(f"{label} must be unpadded base64url")
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(
            (value + padding).encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError(f"{label} must be unpadded base64url") from exc
    if len(decoded) != expected_bytes:
        raise ValueError(f"{label} has the wrong decoded length")
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != value:
        raise ValueError(f"{label} is not canonical base64url")
    return decoded


def dispatch_authorization_signing_bytes(
    payload: DispatchAuthorizationPayload,
) -> bytes:
    """Return the only bytes an external control plane may sign for payload v1."""

    frozen = DispatchAuthorizationPayload.model_validate(
        payload.model_dump(mode="python"),
        strict=True,
    )
    return DISPATCH_SIGNING_DOMAIN + canonical_json_bytes(frozen)


def _validate_expectation(expectation: DispatchExpectation) -> None:
    probe = DispatchAuthorizationPayload(
        schema_version="bpe.dispatch-authorization-payload.v1",
        authorization_id="expectation-probe",
        dispatch_nonce="1" * 64,
        job_manifest_sha256=expectation.job_manifest_sha256,
        request_sha256=expectation.request_sha256,
        experiment_sha256=expectation.experiment_sha256,
        environment_sha256=expectation.environment_sha256,
        execution_profile_sha256=expectation.execution_profile_sha256,
        resource_profile_sha256=expectation.resource_profile_sha256,
        purpose=expectation.purpose,
        worker_pool_audience=expectation.worker_pool_audience,
        policy_id=expectation.policy_id,
        policy_sha256=expectation.policy_sha256,
        issued_at_unix=0,
        not_before_unix=0,
        expires_at_unix=1,
    )
    del probe


def dispatch_expectation_for(
    loaded: LoadedEvaluationJob,
    profile: ExecutionProfile,
    *,
    expected_job_manifest_sha256: str,
    purpose: DispatchPurpose,
    worker_pool_audience: str,
    policy_id: str,
    policy_sha256: str,
) -> DispatchExpectation:
    """Derive content bindings from an anchored job and trusted local worker policy."""

    if not isinstance(loaded, LoadedEvaluationJob):
        raise DispatchExpectationError("dispatch requires a loaded evaluation job")
    try:
        manifest = EvaluationJobManifest.model_validate(
            loaded.manifest.model_dump(mode="python"),
            strict=True,
        )
        frozen_profile = ExecutionProfile.model_validate(
            profile.model_dump(mode="python"),
            strict=True,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise DispatchExpectationError("dispatch job or profile is invalid") from exc
    if loaded.anchored is not True:
        raise DispatchExpectationError("dispatch job is not anchored by an expected digest")
    if (
        loaded.manifest_sha256 != expected_job_manifest_sha256
        or loaded.manifest_sha256 != sha256_json(manifest)
    ):
        raise DispatchExpectationError("dispatch job anchor differs from its manifest")
    expected_blobs = {
        (reference.sha256, reference.size_bytes) for reference in manifest.blobs
    }
    loaded_blobs: set[tuple[str, int]] = set()
    loaded_byte_total = 0
    try:
        for blob in loaded.blobs:
            if not isinstance(blob, LoadedJobBlob) or type(blob.content) is not bytes:
                raise ValueError("loaded job blob has an invalid runtime type")
            reference = JobBlobRef.model_validate(
                blob.reference.model_dump(mode="python"),
                strict=True,
            )
            identity = (reference.sha256, reference.size_bytes)
            if (
                identity not in expected_blobs
                or identity in loaded_blobs
                or len(blob.content) != reference.size_bytes
                or sha256_bytes(blob.content) != reference.sha256
            ):
                raise ValueError("loaded job blob identity or content differs")
            loaded_blobs.add(identity)
            loaded_byte_total += len(blob.content)
    except (AttributeError, TypeError, ValueError) as exc:
        raise DispatchExpectationError("dispatch loaded-job blob set is invalid") from exc
    if (
        loaded_blobs != expected_blobs
        or loaded_byte_total != manifest.total_blob_bytes
    ):
        raise DispatchExpectationError("dispatch loaded-job blob set is incomplete")
    if (
        frozen_profile.environment != manifest.environment
        or frozen_profile.environment_sha256 != manifest.environment_sha256
    ):
        raise DispatchExpectationError(
            "dispatch execution profile differs from the anchored job environment"
        )
    if frozen_profile.worker_pool_audience != worker_pool_audience:
        raise DispatchExpectationError(
            "dispatch execution profile differs from the trusted worker audience"
        )
    if (
        frozen_profile.resources.wall_timeout_ms
        > manifest.plan.whole_attempt_timeout_seconds * 1000
    ):
        raise DispatchExpectationError(
            "dispatch resource timeout exceeds the anchored evaluation plan"
        )
    expectation = DispatchExpectation(
        job_manifest_sha256=loaded.manifest_sha256,
        request_sha256=manifest.request_sha256,
        experiment_sha256=manifest.experiment_sha256,
        environment_sha256=manifest.environment_sha256,
        execution_profile_sha256=sha256_json(frozen_profile),
        resource_profile_sha256=frozen_profile.resource_profile_sha256,
        purpose=purpose,
        worker_pool_audience=worker_pool_audience,
        policy_id=policy_id,
        policy_sha256=policy_sha256,
    )
    try:
        _validate_expectation(expectation)
    except (TypeError, ValueError) as exc:
        raise DispatchExpectationError("trusted dispatch policy inputs are invalid") from exc
    return expectation


def _verify_dispatch_authorization(
    authorization: SignedDispatchAuthorization,
    trust_store: DispatchTrustStore,
    expectation: DispatchExpectation,
    *,
    now_unix: int,
    enforce_validity: bool,
) -> VerifiedDispatchAuthorization:
    """Authenticate and bind one authorization, optionally enforcing its time window."""

    if type(now_unix) is not int or now_unix < 0:
        raise DispatchAuthorizationError("verification time must be a nonnegative integer")
    try:
        frozen_authorization = SignedDispatchAuthorization.model_validate(
            authorization.model_dump(mode="python"),
            strict=True,
        )
        frozen_store = DispatchTrustStore.model_validate(
            trust_store.model_dump(mode="python"),
            strict=True,
        )
        _validate_expectation(expectation)
    except (AttributeError, TypeError, ValueError) as exc:
        raise DispatchAuthorizationError("dispatch authorization inputs are invalid") from exc

    payload = frozen_authorization.payload
    expected_bindings = (
        expectation.job_manifest_sha256,
        expectation.request_sha256,
        expectation.experiment_sha256,
        expectation.environment_sha256,
        expectation.execution_profile_sha256,
        expectation.resource_profile_sha256,
        expectation.purpose,
        expectation.worker_pool_audience,
        expectation.policy_id,
        expectation.policy_sha256,
    )
    actual_bindings = (
        payload.job_manifest_sha256,
        payload.request_sha256,
        payload.experiment_sha256,
        payload.environment_sha256,
        payload.execution_profile_sha256,
        payload.resource_profile_sha256,
        payload.purpose,
        payload.worker_pool_audience,
        payload.policy_id,
        payload.policy_sha256,
    )
    if actual_bindings != expected_bindings:
        raise DispatchAuthorizationError("dispatch authorization bindings differ")
    if enforce_validity and not (
        payload.not_before_unix <= now_unix < payload.expires_at_unix
    ):
        raise DispatchAuthorizationError("dispatch authorization is outside its validity window")

    matching_keys = [
        key for key in frozen_store.keys if key.key_id == frozen_authorization.key_id
    ]
    if len(matching_keys) != 1:
        raise DispatchAuthorizationError("dispatch signing key is not trusted")
    key = matching_keys[0]
    if key.revoked:
        raise DispatchAuthorizationError("dispatch signing key is revoked")
    if not (
        key.valid_from_unix <= payload.issued_at_unix
        and payload.expires_at_unix <= key.valid_until_unix
    ):
        raise DispatchAuthorizationError(
            "dispatch authorization is outside the signing key validity window"
        )

    try:
        public_key = Ed25519PublicKey.from_public_bytes(
            _decode_base64url(
                key.public_key_base64url,
                expected_bytes=_PUBLIC_KEY_BYTES,
                label="public key",
            )
        )
        signature = _decode_base64url(
            frozen_authorization.signature_base64url,
            expected_bytes=_SIGNATURE_BYTES,
            label="signature",
        )
        public_key.verify(signature, dispatch_authorization_signing_bytes(payload))
    except (InvalidSignature, ValueError) as exc:
        raise DispatchAuthorizationError(
            "dispatch authorization signature is invalid"
        ) from exc

    return VerifiedDispatchAuthorization(
        authorization=frozen_authorization,
        authorization_sha256=sha256_json(frozen_authorization),
        payload_sha256=sha256_json(payload),
        trust_store_id=frozen_store.trust_store_id,
        trust_store_sha256=sha256_json(frozen_store),
        verified_at_unix=now_unix,
    )


def verify_dispatch_authorization(
    authorization: SignedDispatchAuthorization,
    trust_store: DispatchTrustStore,
    expectation: DispatchExpectation,
    *,
    now_unix: int,
) -> VerifiedDispatchAuthorization:
    """Authenticate and exactly bind one currently valid authorization."""

    return _verify_dispatch_authorization(
        authorization,
        trust_store,
        expectation,
        now_unix=now_unix,
        enforce_validity=True,
    )


class DispatchClaimLedger:
    """SQLite-backed durable uniqueness boundary for one-shot authorizations."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._prepare_database_path()
        try:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                objects = connection.execute(
                    "SELECT type, name FROM sqlite_schema"
                ).fetchall()
                if not objects:
                    connection.execute(_CREATE_LEDGER_TABLE)
                    connection.execute(_CREATE_LEDGER_STATE)
                    connection.execute(
                        "INSERT INTO dispatch_state (singleton, clock_high_water_unix) "
                        "VALUES (1, 0)"
                    )
                    connection.execute(f"PRAGMA application_id={_LEDGER_APPLICATION_ID}")
                    connection.execute(f"PRAGMA user_version={_LEDGER_USER_VERSION}")
                connection.execute("COMMIT")
                self._validate_schema(connection)
            finally:
                connection.close()
        except DispatchLedgerError:
            raise
        except sqlite3.Error as exc:
            raise DispatchLedgerError("cannot initialize dispatch claim ledger") from exc

    def _prepare_database_path(self) -> None:
        if not self.path.is_absolute() or self.path.name in {"", ".", ".."}:
            raise DispatchLedgerError("dispatch claim ledger path must be absolute")
        parent = self.path.parent
        try:
            parent_stat = parent.lstat()
            resolved_parent = parent.resolve(strict=True)
        except OSError as exc:
            raise DispatchLedgerError("cannot inspect dispatch ledger parent") from exc
        if (
            resolved_parent != parent
            or stat.S_ISLNK(parent_stat.st_mode)
            or not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_uid != os.geteuid()
            or parent_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise DispatchLedgerError(
                "dispatch ledger parent must be caller-owned, private, and non-symlinked"
            )
        for ancestor in parent.parents:
            try:
                ancestor_stat = ancestor.lstat()
            except OSError as exc:
                raise DispatchLedgerError(
                    "cannot inspect a dispatch ledger ancestor"
                ) from exc
            writable_by_others = ancestor_stat.st_mode & (
                stat.S_IWGRP | stat.S_IWOTH
            )
            if (
                stat.S_ISLNK(ancestor_stat.st_mode)
                or not stat.S_ISDIR(ancestor_stat.st_mode)
                or ancestor_stat.st_uid not in {0, os.geteuid()}
                or (writable_by_others and not ancestor_stat.st_mode & stat.S_ISVTX)
            ):
                raise DispatchLedgerError(
                    "dispatch ledger ancestors must be trusted and rename-safe"
                )

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        for name in ("O_NOFOLLOW", "O_CLOEXEC"):
            if not hasattr(os, name):
                raise DispatchLedgerError("secure dispatch ledger creation is unavailable")
            flags |= getattr(os, name)
        created = False
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except FileExistsError:
            descriptor = -1
        except OSError as exc:
            raise DispatchLedgerError("cannot create dispatch claim ledger") from exc
        else:
            created = True
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

        try:
            database_stat = self.path.lstat()
        except OSError as exc:
            raise DispatchLedgerError("cannot inspect dispatch claim ledger") from exc
        if (
            stat.S_ISLNK(database_stat.st_mode)
            or not stat.S_ISREG(database_stat.st_mode)
            or database_stat.st_uid != os.geteuid()
            or database_stat.st_nlink != 1
            or database_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise DispatchLedgerError(
                "dispatch claim ledger must be caller-owned, private, and regular"
            )
        if created:
            try:
                parent_fd = os.open(
                    parent,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                )
                try:
                    os.fsync(parent_fd)
                finally:
                    os.close(parent_fd)
            except OSError as exc:
                raise DispatchLedgerError("cannot durably create dispatch ledger") from exc

    def _connect(self) -> sqlite3.Connection:
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                self.path,
                timeout=5.0,
                isolation_level=None,
            )
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=EXTRA")
            settings = (
                connection.execute("PRAGMA busy_timeout").fetchone(),
                connection.execute("PRAGMA foreign_keys").fetchone(),
                connection.execute("PRAGMA trusted_schema").fetchone(),
                connection.execute("PRAGMA journal_mode").fetchone(),
                connection.execute("PRAGMA synchronous").fetchone(),
            )
            if settings != ((5000,), (1,), (0,), ("delete",), (3,)):
                raise DispatchLedgerError(
                    "dispatch ledger safety settings were not applied"
                )
            return connection
        except DispatchLedgerError:
            if connection is not None:
                connection.close()
            raise
        except sqlite3.Error as exc:
            if connection is not None:
                connection.close()
            raise DispatchLedgerError("cannot open dispatch claim ledger") from exc

    def _validate_schema(self, connection: sqlite3.Connection) -> None:
        try:
            integrity_check = connection.execute("PRAGMA integrity_check").fetchall()
            foreign_key_check = connection.execute("PRAGMA foreign_key_check").fetchall()
            application_id = connection.execute("PRAGMA application_id").fetchone()
            user_version = connection.execute("PRAGMA user_version").fetchone()
            objects = connection.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_schema "
                "ORDER BY type, name"
            ).fetchall()
            table_sql = connection.execute(
                "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?",
                ("dispatch_claims",),
            ).fetchone()
            state_sql = connection.execute(
                "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?",
                ("dispatch_state",),
            ).fetchone()
            columns = connection.execute("PRAGMA table_info(dispatch_claims)").fetchall()
            state_columns = connection.execute(
                "PRAGMA table_info(dispatch_state)"
            ).fetchall()
            state_rows = connection.execute(
                "SELECT singleton, clock_high_water_unix FROM dispatch_state"
            ).fetchall()
            index_rows = connection.execute("PRAGMA index_list(dispatch_claims)").fetchall()
            state_index_rows = connection.execute(
                "PRAGMA index_list(dispatch_state)"
            ).fetchall()
            indexed_columns = {
                tuple(
                    row[2]
                    for row in connection.execute(
                        f'PRAGMA index_info("{index_row[1]}")'
                    ).fetchall()
                )
                for index_row in index_rows
                if index_row[2] == 1
            }
            state_indexed_columns = {
                tuple(
                    row[2]
                    for row in connection.execute(
                        f'PRAGMA index_info("{index_row[1]}")'
                    ).fetchall()
                )
                for index_row in state_index_rows
                if index_row[2] == 1
            }
            foreign_keys = connection.execute(
                "PRAGMA foreign_key_list(dispatch_claims)"
            ).fetchall()
        except sqlite3.Error as exc:
            raise DispatchLedgerError("dispatch claim ledger schema is not trusted") from exc

        expected_columns = (
            (0, "authorization_id", "TEXT", 1, None, 1),
            (1, "authorization_sha256", "TEXT", 1, None, 0),
            (2, "payload_sha256", "TEXT", 1, None, 0),
            (3, "signature_key_id", "TEXT", 1, None, 0),
            (4, "trust_store_id", "TEXT", 1, None, 0),
            (5, "trust_store_sha256", "TEXT", 1, None, 0),
            (6, "dispatch_nonce", "TEXT", 1, None, 0),
            (7, "claim_id", "TEXT", 1, None, 0),
            (8, "claim_nonce", "TEXT", 1, None, 0),
            (9, "claimed_at_unix", "INTEGER", 1, None, 0),
            (10, "receipt_sha256", "TEXT", 1, None, 0),
            (11, "job_manifest_sha256", "TEXT", 1, None, 0),
            (12, "binding_sha256", "TEXT", 1, None, 0),
            (13, "policy_id", "TEXT", 1, None, 0),
            (14, "policy_sha256", "TEXT", 1, None, 0),
            (15, "retry_index", "INTEGER", 1, None, 0),
            (16, "retry_of_authorization_id", "TEXT", 0, None, 0),
            (17, "retry_of_claim_sha256", "TEXT", 0, None, 0),
        )
        expected_unique_columns = {
            ("authorization_id",),
            ("authorization_id", "receipt_sha256"),
            ("authorization_sha256",),
            ("dispatch_nonce",),
            ("claim_id",),
            ("claim_nonce",),
            ("receipt_sha256",),
            ("retry_of_authorization_id",),
            ("retry_of_claim_sha256",),
        }
        valid_foreign_key = (
            len(foreign_keys) == 2
            and len({row[0] for row in foreign_keys}) == 1
            and {row[1] for row in foreign_keys} == {0, 1}
            and all(row[2] == "dispatch_claims" for row in foreign_keys)
            and {(row[3], row[4]) for row in foreign_keys}
            == {
                ("retry_of_authorization_id", "authorization_id"),
                ("retry_of_claim_sha256", "receipt_sha256"),
            }
        )
        normalized_table_sql = (
            " ".join(table_sql[0].split())
            if table_sql is not None and isinstance(table_sql[0], str)
            else None
        )
        expected_table_sql = " ".join(_CREATE_LEDGER_TABLE.split())
        normalized_state_sql = (
            " ".join(state_sql[0].split())
            if state_sql is not None and isinstance(state_sql[0], str)
            else None
        )
        expected_state_sql = " ".join(_CREATE_LEDGER_STATE.split())
        expected_state_columns = (
            (0, "singleton", "INTEGER", 1, None, 1),
            (1, "clock_high_water_unix", "INTEGER", 1, None, 0),
        )
        table_objects = {
            row[1]: " ".join(row[3].split())
            for row in objects
            if row[0] == "table" and isinstance(row[3], str)
        }
        autoindexes_are_exact = all(
            row[0] == "index"
            and row[2] in {"dispatch_claims", "dispatch_state"}
            and row[1].startswith(f"sqlite_autoindex_{row[2]}_")
            and row[3] is None
            for row in objects
            if row[0] != "table"
        )
        schema_index_names = {row[1] for row in objects if row[0] == "index"}
        expected_schema_index_names = {
            row[1] for row in (*index_rows, *state_index_rows) if row[3] == "u"
        }
        if (
            integrity_check != [("ok",)]
            or foreign_key_check
            or application_id != (_LEDGER_APPLICATION_ID,)
            or user_version != (_LEDGER_USER_VERSION,)
            or table_objects
            != {
                "dispatch_claims": expected_table_sql,
                "dispatch_state": expected_state_sql,
            }
            or not autoindexes_are_exact
            or schema_index_names != expected_schema_index_names
            or normalized_table_sql != expected_table_sql
            or normalized_state_sql != expected_state_sql
            or tuple(columns) != expected_columns
            or tuple(state_columns) != expected_state_columns
            or len(state_rows) != 1
            or state_rows[0][0] != 1
            or type(state_rows[0][1]) is not int
            or state_rows[0][1] < 0
            or indexed_columns != expected_unique_columns
            or len(index_rows) != len(expected_unique_columns)
            or state_indexed_columns != {("singleton",)}
            or len(state_index_rows) != 1
            or not valid_foreign_key
        ):
            raise DispatchLedgerError("dispatch claim ledger schema is not trusted")

    def claim_authorization(
        self,
        authorization: SignedDispatchAuthorization,
        trust_store: DispatchTrustStore,
        expectation: DispatchExpectation,
        *,
        claim_id: str,
    ) -> DispatchAdmissionReceipt:
        """Reverify and claim one authorization using the worker's wall clock."""

        verification_time = _current_unix_time()
        self._advance_clock(verification_time)
        verified = verify_dispatch_authorization(
            authorization,
            trust_store,
            expectation,
            now_unix=verification_time,
        )
        payload = verified.authorization.payload
        binding_sha256 = _dispatch_binding_sha256(payload)

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            claimed_at_unix = _current_unix_time()
            if type(claimed_at_unix) is not int or claimed_at_unix < 0:
                connection.execute("ROLLBACK")
                raise DispatchLedgerError("worker clock returned an invalid Unix time")
            clock_row = connection.execute(
                "SELECT clock_high_water_unix FROM dispatch_state WHERE singleton = 1"
            ).fetchone()
            if (
                clock_row is None
                or type(clock_row[0]) is not int
                or claimed_at_unix < clock_row[0]
            ):
                connection.execute("ROLLBACK")
                raise DispatchLedgerError("worker clock moved behind its durable high-water mark")
            connection.execute(
                "UPDATE dispatch_state SET clock_high_water_unix = ? WHERE singleton = 1",
                (claimed_at_unix,),
            )
            if (
                not payload.not_before_unix
                <= claimed_at_unix
                < payload.expires_at_unix
            ):
                connection.execute("COMMIT")
                raise DispatchLedgerError(
                    "authorization is outside its validity window at durable claim"
                )
            try:
                claim_nonce = _new_claim_nonce()
                receipt = DispatchAdmissionReceipt(
                    schema_version="bpe.dispatch-admission-receipt.v1",
                    status="claimed_not_executed",
                    authorization_id=payload.authorization_id,
                    authorization_sha256=verified.authorization_sha256,
                    authorization_payload_sha256=verified.payload_sha256,
                    signature_key_id=verified.authorization.key_id,
                    trust_store_id=verified.trust_store_id,
                    trust_store_sha256=verified.trust_store_sha256,
                    claim_id=claim_id,
                    claim_nonce=claim_nonce,
                    claimed_at_unix=claimed_at_unix,
                    dispatch_nonce=payload.dispatch_nonce,
                    job_manifest_sha256=payload.job_manifest_sha256,
                    request_sha256=payload.request_sha256,
                    experiment_sha256=payload.experiment_sha256,
                    environment_sha256=payload.environment_sha256,
                    execution_profile_sha256=payload.execution_profile_sha256,
                    resource_profile_sha256=payload.resource_profile_sha256,
                    purpose=payload.purpose,
                    worker_pool_audience=payload.worker_pool_audience,
                    policy_id=payload.policy_id,
                    policy_sha256=payload.policy_sha256,
                    retry_index=payload.retry_index,
                    retry_of_authorization_id=payload.retry_of_authorization_id,
                    retry_of_claim_sha256=payload.retry_of_claim_sha256,
                    signature_verified=True,
                    execution_started=False,
                    authoritative=False,
                )
            except ValueError as exc:
                connection.execute("COMMIT")
                raise DispatchLedgerError("dispatch claim identity is invalid") from exc
            receipt_sha256 = sha256_json(receipt)
            conflict = connection.execute(
                """
                SELECT 1 FROM dispatch_claims
                WHERE authorization_id = ?
                   OR authorization_sha256 = ?
                   OR dispatch_nonce = ?
                   OR claim_id = ?
                   OR claim_nonce = ?
                   OR receipt_sha256 = ?
                   OR (? IS NOT NULL AND retry_of_authorization_id = ?)
                   OR (? IS NOT NULL AND retry_of_claim_sha256 = ?)
                LIMIT 1
                """,
                (
                    receipt.authorization_id,
                    receipt.authorization_sha256,
                    receipt.dispatch_nonce,
                    receipt.claim_id,
                    receipt.claim_nonce,
                    receipt_sha256,
                    receipt.retry_of_authorization_id,
                    receipt.retry_of_authorization_id,
                    receipt.retry_of_claim_sha256,
                    receipt.retry_of_claim_sha256,
                ),
            ).fetchone()
            if conflict is not None:
                connection.execute("COMMIT")
                raise DispatchAlreadyClaimed(
                    "dispatch authorization, nonce, claim, or retry parent was already consumed"
                )
            if receipt.retry_of_authorization_id is not None:
                parent = connection.execute(
                    "SELECT retry_index, binding_sha256, claimed_at_unix, receipt_sha256 "
                    "FROM dispatch_claims "
                    "WHERE authorization_id = ?",
                    (receipt.retry_of_authorization_id,),
                ).fetchone()
                if (
                    parent is None
                    or parent[0] != receipt.retry_index - 1
                    or parent[1] != binding_sha256
                    or payload.issued_at_unix < parent[2]
                    or payload.retry_of_claim_sha256 != parent[3]
                ):
                    connection.execute("COMMIT")
                    raise DispatchLedgerError(
                        "dispatch retry parent or claim receipt is missing, misbound, "
                        "predates its claim, or has the wrong index"
                    )
            connection.execute(
                """
                INSERT INTO dispatch_claims (
                    authorization_id,
                    authorization_sha256,
                    payload_sha256,
                    signature_key_id,
                    trust_store_id,
                    trust_store_sha256,
                    dispatch_nonce,
                    claim_id,
                    claim_nonce,
                    claimed_at_unix,
                    receipt_sha256,
                    job_manifest_sha256,
                    binding_sha256,
                    policy_id,
                    policy_sha256,
                    retry_index,
                    retry_of_authorization_id,
                    retry_of_claim_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.authorization_id,
                    receipt.authorization_sha256,
                    receipt.authorization_payload_sha256,
                    receipt.signature_key_id,
                    receipt.trust_store_id,
                    receipt.trust_store_sha256,
                    receipt.dispatch_nonce,
                    receipt.claim_id,
                    receipt.claim_nonce,
                    receipt.claimed_at_unix,
                    receipt_sha256,
                    receipt.job_manifest_sha256,
                    binding_sha256,
                    receipt.policy_id,
                    receipt.policy_sha256,
                    receipt.retry_index,
                    receipt.retry_of_authorization_id,
                    receipt.retry_of_claim_sha256,
                ),
            )
            connection.execute("COMMIT")
        except sqlite3.IntegrityError as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise DispatchLedgerError("dispatch claim violated ledger integrity") from exc
        except (DispatchAlreadyClaimed, DispatchLedgerError):
            raise
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise DispatchLedgerError("cannot commit dispatch authorization claim") from exc
        finally:
            connection.close()
        return receipt

    def verify_committed_receipt(self, receipt: DispatchAdmissionReceipt) -> str:
        """Return the digest of an exact receipt already committed to this ledger."""

        try:
            frozen_receipt = DispatchAdmissionReceipt.model_validate(
                receipt.model_dump(mode="python"),
                strict=True,
            )
            receipt_sha256 = sha256_json(frozen_receipt)
        except (AttributeError, TypeError, ValueError) as exc:
            raise DispatchLedgerError("dispatch admission receipt is invalid") from exc

        binding_sha256 = sha256_json(
            {
                "schema_version": "bpe.dispatch-binding.v1",
                "job_manifest_sha256": frozen_receipt.job_manifest_sha256,
                "request_sha256": frozen_receipt.request_sha256,
                "experiment_sha256": frozen_receipt.experiment_sha256,
                "environment_sha256": frozen_receipt.environment_sha256,
                "execution_profile_sha256": frozen_receipt.execution_profile_sha256,
                "resource_profile_sha256": frozen_receipt.resource_profile_sha256,
                "purpose": frozen_receipt.purpose,
                "worker_pool_audience": frozen_receipt.worker_pool_audience,
                "policy_id": frozen_receipt.policy_id,
                "policy_sha256": frozen_receipt.policy_sha256,
            }
        )
        expected_row = (
            frozen_receipt.authorization_id,
            frozen_receipt.authorization_sha256,
            frozen_receipt.authorization_payload_sha256,
            frozen_receipt.signature_key_id,
            frozen_receipt.trust_store_id,
            frozen_receipt.trust_store_sha256,
            frozen_receipt.dispatch_nonce,
            frozen_receipt.claim_id,
            frozen_receipt.claim_nonce,
            frozen_receipt.claimed_at_unix,
            receipt_sha256,
            frozen_receipt.job_manifest_sha256,
            binding_sha256,
            frozen_receipt.policy_id,
            frozen_receipt.policy_sha256,
            frozen_receipt.retry_index,
            frozen_receipt.retry_of_authorization_id,
            frozen_receipt.retry_of_claim_sha256,
        )

        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                f"{self.path.as_uri()}?mode=ro",
                timeout=5.0,
                isolation_level=None,
                uri=True,
            )
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA query_only=ON")
            self._validate_schema(connection)
            row = connection.execute(
                """
                SELECT
                    authorization_id,
                    authorization_sha256,
                    payload_sha256,
                    signature_key_id,
                    trust_store_id,
                    trust_store_sha256,
                    dispatch_nonce,
                    claim_id,
                    claim_nonce,
                    claimed_at_unix,
                    receipt_sha256,
                    job_manifest_sha256,
                    binding_sha256,
                    policy_id,
                    policy_sha256,
                    retry_index,
                    retry_of_authorization_id,
                    retry_of_claim_sha256
                FROM dispatch_claims
                WHERE authorization_id = ?
                """,
                (frozen_receipt.authorization_id,),
            ).fetchone()
        except DispatchLedgerError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise DispatchLedgerError("cannot verify committed dispatch receipt") from exc
        finally:
            if connection is not None:
                connection.close()

        if row != expected_row:
            raise DispatchLedgerError(
                "dispatch admission receipt is not committed in this ledger"
            )
        return receipt_sha256

    def _advance_clock(self, observed_unix: int) -> None:
        if type(observed_unix) is not int or observed_unix < 0:
            raise DispatchLedgerError("worker clock returned an invalid Unix time")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT clock_high_water_unix FROM dispatch_state WHERE singleton = 1"
            ).fetchone()
            if row is None or type(row[0]) is not int or observed_unix < row[0]:
                connection.execute("ROLLBACK")
                raise DispatchLedgerError(
                    "worker clock moved behind its durable high-water mark"
                )
            connection.execute(
                "UPDATE dispatch_state SET clock_high_water_unix = ? WHERE singleton = 1",
                (observed_unix,),
            )
            connection.execute("COMMIT")
        except DispatchLedgerError:
            raise
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise DispatchLedgerError("cannot update dispatch clock high-water mark") from exc
        finally:
            connection.close()

    def claim_count(self) -> int:
        connection = self._connect()
        try:
            row = connection.execute("SELECT COUNT(*) FROM dispatch_claims").fetchone()
        except sqlite3.Error as exc:
            raise DispatchLedgerError("cannot inspect dispatch claim ledger") from exc
        finally:
            connection.close()
        if row is None or type(row[0]) is not int:
            raise DispatchLedgerError("dispatch claim ledger returned an invalid count")
        return row[0]


def admit_dispatch(
    authorization: SignedDispatchAuthorization,
    trust_store: DispatchTrustStore,
    expectation: DispatchExpectation,
    *,
    ledger_path: Path,
    claim_id: str,
) -> DispatchAdmissionReceipt:
    """Verify first, then durably consume one authorization without executing anything."""

    verification_time = _current_unix_time()
    _verify_dispatch_authorization(
        authorization,
        trust_store,
        expectation,
        now_unix=verification_time,
        enforce_validity=False,
    )
    ledger = DispatchClaimLedger(ledger_path)
    ledger._advance_clock(verification_time)
    return ledger.claim_authorization(
        authorization,
        trust_store,
        expectation,
        claim_id=claim_id,
    )


JSON_SCHEMAS: dict[str, type[BaseModel]] = {
    "execution-resource-profile-v1.json": ExecutionResourceProfile,
    "execution-profile-v1.json": ExecutionProfile,
    "dispatch-authorization-payload-v1.json": DispatchAuthorizationPayload,
    "signed-dispatch-authorization-v1.json": SignedDispatchAuthorization,
    "dispatch-trust-store-v1.json": DispatchTrustStore,
    "dispatch-admission-receipt-v1.json": DispatchAdmissionReceipt,
}


__all__ = [
    "DISPATCH_SIGNING_DOMAIN",
    "JSON_SCHEMAS",
    "MAX_AUTHORIZATION_LIFETIME_SECONDS",
    "DispatchAdmissionError",
    "DispatchAdmissionReceipt",
    "DispatchAlreadyClaimed",
    "DispatchAuthorizationError",
    "DispatchAuthorizationPayload",
    "DispatchClaimLedger",
    "DispatchExpectation",
    "DispatchExpectationError",
    "DispatchLedgerError",
    "DispatchPurpose",
    "DispatchTrustKey",
    "DispatchTrustStore",
    "ExecutionProfile",
    "ExecutionResourceProfile",
    "SignedDispatchAuthorization",
    "SnapshotComponents",
    "VerifiedDispatchAuthorization",
    "admit_dispatch",
    "dispatch_authorization_signing_bytes",
    "dispatch_expectation_for",
    "verify_dispatch_authorization",
]
