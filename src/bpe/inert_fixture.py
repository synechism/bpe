"""Signed one-shot admission for the fixed no-exec supervisor fixture.

This module is deliberately process-free.  It authenticates and durably consumes a
short-lived intent that may later authorize exactly one built-in native fixture state
machine.  It accepts no job, candidate, launcher/executable/root path, command, argv,
environment, or executable input and does not import the Linux runtime boundary.  Its
receipt is evidence only: a future runtime must reverify the original intent and atomically
consume a separate launch attempt before creating either the pinned launcher or its fixture
child.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import secrets
import sqlite3
import stat
import sys
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal, Self

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from bpe.canonical import canonical_json_bytes, sha256_json
from bpe.dispatch import ExecutionResourceProfile
from bpe.models import Sha256, StableId

INERT_FIXTURE_INTENT_SIGNING_DOMAIN = b"BPE\x00inert-fixture-intent\x00v1\x00"
MAX_INERT_FIXTURE_INTENT_LIFETIME_SECONDS = 15 * 60

_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_STABLE_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/@:+-]{0,127}$")
_PUBLIC_KEY_BASE64URL_PATTERN = r"^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$"
_SIGNATURE_BASE64URL_PATTERN = r"^[A-Za-z0-9_-]{85}[AQgw]$"
_PUBLIC_KEY_BYTES = 32
_SIGNATURE_BYTES = 64
_LEDGER_APPLICATION_ID = 0x42504532
_LEDGER_USER_VERSION = 2

_CREATE_INTENT_RESERVATIONS = """
CREATE TABLE inert_fixture_intent_reservations (
    intent_sha256 TEXT PRIMARY KEY,
    intent_id TEXT NOT NULL UNIQUE,
    payload_sha256 TEXT NOT NULL,
    signature_key_id TEXT NOT NULL,
    trust_store_id TEXT NOT NULL,
    trust_store_sha256 TEXT NOT NULL,
    worker_instance_id TEXT NOT NULL,
    claim_ledger_id TEXT NOT NULL,
    launch_ledger_id TEXT NOT NULL,
    intent_nonce TEXT NOT NULL UNIQUE,
    policy_sha256 TEXT NOT NULL,
    binding_sha256 TEXT NOT NULL,
    reserved_at_unix INTEGER NOT NULL,
    UNIQUE(
        intent_sha256,
        intent_id,
        payload_sha256,
        signature_key_id,
        trust_store_id,
        trust_store_sha256,
        worker_instance_id,
        claim_ledger_id,
        launch_ledger_id,
        intent_nonce,
        policy_sha256,
        binding_sha256,
        reserved_at_unix
    ),
    CHECK(length(intent_sha256) = 64),
    CHECK(length(payload_sha256) = 64),
    CHECK(length(trust_store_sha256) = 64),
    CHECK(length(intent_nonce) = 64),
    CHECK(length(policy_sha256) = 64),
    CHECK(length(binding_sha256) = 64),
    CHECK(reserved_at_unix >= 0)
) WITHOUT ROWID
"""

_CREATE_INTENT_CLAIMS = """
CREATE TABLE inert_fixture_intent_claims (
    intent_id TEXT PRIMARY KEY,
    intent_sha256 TEXT NOT NULL UNIQUE,
    payload_sha256 TEXT NOT NULL,
    signature_key_id TEXT NOT NULL,
    trust_store_id TEXT NOT NULL,
    trust_store_sha256 TEXT NOT NULL,
    worker_instance_id TEXT NOT NULL,
    claim_ledger_id TEXT NOT NULL,
    launch_ledger_id TEXT NOT NULL,
    intent_nonce TEXT NOT NULL UNIQUE,
    claim_id TEXT NOT NULL UNIQUE,
    claim_nonce TEXT NOT NULL UNIQUE,
    claimed_at_unix INTEGER NOT NULL,
    receipt_sha256 TEXT NOT NULL UNIQUE,
    receipt_json BLOB NOT NULL,
    policy_id TEXT NOT NULL,
    policy_sha256 TEXT NOT NULL,
    worker_pool_audience TEXT NOT NULL,
    delegated_root_id TEXT NOT NULL,
    launcher_artifact_id TEXT NOT NULL,
    launcher_artifact_sha256 TEXT NOT NULL,
    launcher_seccomp_policy_id TEXT NOT NULL,
    launcher_seccomp_policy_sha256 TEXT NOT NULL,
    fixture_protocol_id TEXT NOT NULL,
    resource_profile_id TEXT NOT NULL,
    resource_profile_sha256 TEXT NOT NULL,
    binding_sha256 TEXT NOT NULL,
    UNIQUE(intent_id, receipt_sha256),
    FOREIGN KEY (
        intent_sha256,
        intent_id,
        payload_sha256,
        signature_key_id,
        trust_store_id,
        trust_store_sha256,
        worker_instance_id,
        claim_ledger_id,
        launch_ledger_id,
        intent_nonce,
        policy_sha256,
        binding_sha256,
        claimed_at_unix
    ) REFERENCES inert_fixture_intent_reservations (
        intent_sha256,
        intent_id,
        payload_sha256,
        signature_key_id,
        trust_store_id,
        trust_store_sha256,
        worker_instance_id,
        claim_ledger_id,
        launch_ledger_id,
        intent_nonce,
        policy_sha256,
        binding_sha256,
        reserved_at_unix
    ),
    CHECK(length(intent_sha256) = 64),
    CHECK(length(payload_sha256) = 64),
    CHECK(length(trust_store_sha256) = 64),
    CHECK(length(intent_nonce) = 64),
    CHECK(length(claim_id) = 64),
    CHECK(length(claim_nonce) = 64),
    CHECK(length(receipt_sha256) = 64),
    CHECK(typeof(receipt_json) = 'blob'),
    CHECK(length(receipt_json) BETWEEN 1 AND 32768),
    CHECK(length(policy_sha256) = 64),
    CHECK(length(launcher_artifact_sha256) = 64),
    CHECK(length(launcher_seccomp_policy_sha256) = 64),
    CHECK(length(resource_profile_sha256) = 64),
    CHECK(length(binding_sha256) = 64),
    CHECK(claimed_at_unix >= 0)
) WITHOUT ROWID
"""

_CREATE_INTENT_STATE = """
CREATE TABLE inert_fixture_intent_state (
    singleton INTEGER PRIMARY KEY,
    worker_instance_id TEXT NOT NULL,
    claim_ledger_id TEXT NOT NULL,
    clock_high_water_unix INTEGER NOT NULL,
    CHECK(singleton = 1),
    CHECK(length(worker_instance_id) BETWEEN 1 AND 128),
    CHECK(length(claim_ledger_id) BETWEEN 1 AND 128),
    CHECK(clock_high_water_unix >= 0)
) WITHOUT ROWID
"""


class InertFixtureIntentError(ValueError):
    """An inert-fixture policy, signature, expectation, or claim failed closed."""


class InertFixtureAuthorizationError(InertFixtureIntentError):
    """The signed intent is invalid, untrusted, stale, or misbound."""


class InertFixtureExpectationError(InertFixtureIntentError):
    """Trusted local policy inputs cannot form an intent expectation."""


class InertFixtureLedgerError(InertFixtureIntentError):
    """The durable fixture-intent claim ledger is unavailable or unsafe."""


class InertFixtureIntentAlreadyClaimed(InertFixtureLedgerError):
    """An intent identity or signed envelope was already consumed."""


class _InertFixtureModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        allow_inf_nan=False,
        revalidate_instances="always",
        strict=True,
    )


class InertFixturePolicy(_InertFixtureModel):
    """Closed policy for one built-in no-exec native supervisor fixture."""

    schema_version: Literal["bpe.inert-fixture-policy.v1"]
    policy_id: StableId
    worker_pool_audience: StableId
    worker_instance_id: StableId
    claim_ledger_id: StableId
    launch_ledger_id: StableId
    claim_scope: Literal["single-configured-worker-ledger-v1"]
    delegated_root_id: StableId
    host_platform: Literal["linux"]
    host_architecture: Literal["x86_64"]
    purpose: Literal["inert_fixture_qualification"]
    operation: Literal["qualify-clone3-inert-noexec-v1"]
    launcher_kind: Literal["spawned-one-shot-executable-v1"]
    launcher_artifact_id: StableId
    launcher_artifact_sha256: Sha256
    launcher_seccomp_policy_id: StableId
    launcher_seccomp_policy_sha256: Sha256
    launcher_protocol_version: Literal["bpe.clone3-inert-launcher-protocol.v1"]
    launcher_launch_method: Literal["fixed-one-shot-executable-v1"]
    launcher_fd_layout: Literal["stdio-null-control-3-cgroup-4-v1"]
    launcher_argv_environment: Literal["argc-one-empty-environment-v1"]
    ipc_method: Literal["unix-seqpacket-fixed-frame-v1"]
    fixture_kind: Literal["builtin-noexec-fixed-v1"]
    fixture_protocol_id: Literal["bpe.clone3-inert-fixture-protocol.v1"]
    process_creation_method: Literal["clone3-into-cgroup-pidfd-v1"]
    pidfd_signal_method: Literal["pidfd-send-signal-v1"]
    wait_method: Literal["waitid-p-pidfd-v1"]
    deadline_method: Literal["clock-monotonic-absolute-v1"]
    cleanup_method: Literal["cgroup-kill-events-rmdir-v1"]
    resources: ExecutionResourceProfile
    resource_profile_sha256: Sha256
    fixture_timeout_ms: Annotated[int, Field(ge=5000, le=30_000)]
    cleanup_timeout_ms: Literal[5000]
    total_timeout_ms: Annotated[int, Field(ge=10_000, le=35_000)]
    maximum_claims: Literal[1]
    maximum_launch_attempts: Literal[1]
    retry_permitted: Literal[False]
    launcher_process_permitted: Literal[True]
    fixture_child_process_permitted: Literal[True]
    fixture_child_exec_permitted: Literal[False]
    external_fixture_executable_permitted: Literal[False]
    candidate_access_permitted: Literal[False]
    evaluation_job_access_permitted: Literal[False]
    authoritative_ready: Literal[False]

    @field_validator(
        "launcher_process_permitted",
        "fixture_child_process_permitted",
        mode="before",
    )
    @classmethod
    def fixture_scope_must_be_boolean_true(cls, value: object) -> object:
        if value is not True:
            raise ValueError("the policy must explicitly permit only the fixed fixture protocol")
        return value

    @field_validator(
        "retry_permitted",
        "fixture_child_exec_permitted",
        "external_fixture_executable_permitted",
        "candidate_access_permitted",
        "evaluation_job_access_permitted",
        "authoritative_ready",
        mode="before",
    )
    @classmethod
    def broader_authority_must_be_boolean_false(cls, value: object) -> object:
        if value is not False:
            raise ValueError("the inert-fixture policy cannot grant broader execution authority")
        return value

    @model_validator(mode="after")
    def artifacts_resources_and_time_are_exact(self) -> Self:
        if (
            self.launcher_artifact_sha256 == "0" * 64
            or self.launcher_seccomp_policy_sha256 == "0" * 64
        ):
            raise ValueError("launcher artifact and seccomp digests cannot be placeholders")
        if self.resource_profile_sha256 != sha256_json(self.resources):
            raise ValueError("the inert-fixture resource-profile digest is inconsistent")
        if self.fixture_timeout_ms > self.resources.wall_timeout_ms:
            raise ValueError("fixture deadline exceeds the resource profile wall deadline")
        if self.resources.pids_max < 2:
            raise ValueError("the fixed descendant-cleanup fixture requires at least two PIDs")
        if self.total_timeout_ms != self.fixture_timeout_ms + self.cleanup_timeout_ms:
            raise ValueError("total timeout must exactly include fixture and cleanup deadlines")
        if self.claim_ledger_id == self.launch_ledger_id:
            raise ValueError("claim and launch ledgers must have distinct identities")
        return self


class InertFixtureIntentPayload(_InertFixtureModel):
    """Short-lived authority for exactly one fixed built-in fixture claim."""

    schema_version: Literal["bpe.inert-fixture-intent-payload.v1"]
    intent_id: StableId
    intent_nonce: Sha256
    purpose: Literal["inert_fixture_qualification"]
    operation: Literal["qualify-clone3-inert-noexec-v1"]
    policy_id: StableId
    policy_sha256: Sha256
    worker_pool_audience: StableId
    worker_instance_id: StableId
    claim_ledger_id: StableId
    launch_ledger_id: StableId
    claim_scope: Literal["single-configured-worker-ledger-v1"]
    delegated_root_id: StableId
    launcher_kind: Literal["spawned-one-shot-executable-v1"]
    launcher_artifact_id: StableId
    launcher_artifact_sha256: Sha256
    launcher_seccomp_policy_id: StableId
    launcher_seccomp_policy_sha256: Sha256
    launcher_protocol_version: Literal["bpe.clone3-inert-launcher-protocol.v1"]
    launcher_launch_method: Literal["fixed-one-shot-executable-v1"]
    fixture_kind: Literal["builtin-noexec-fixed-v1"]
    fixture_protocol_id: Literal["bpe.clone3-inert-fixture-protocol.v1"]
    resource_profile_id: StableId
    resource_profile_sha256: Sha256
    fixture_timeout_ms: Annotated[int, Field(ge=5000, le=30_000)]
    cleanup_timeout_ms: Literal[5000]
    total_timeout_ms: Annotated[int, Field(ge=10_000, le=35_000)]
    issued_at_unix: Annotated[int, Field(ge=0)]
    not_before_unix: Annotated[int, Field(ge=0)]
    expires_at_unix: Annotated[int, Field(ge=0)]
    maximum_claims: Literal[1]
    maximum_launch_attempts: Literal[1]
    retry_permitted: Literal[False]
    launcher_process_permitted: Literal[True]
    fixture_child_process_permitted: Literal[True]
    fixture_child_exec_permitted: Literal[False]
    external_fixture_executable_permitted: Literal[False]
    candidate_access_permitted: Literal[False]
    evaluation_job_access_permitted: Literal[False]
    authoritative_ready: Literal[False]

    @field_validator(
        "launcher_process_permitted",
        "fixture_child_process_permitted",
        mode="before",
    )
    @classmethod
    def fixture_scope_must_be_boolean_true(cls, value: object) -> object:
        if value is not True:
            raise ValueError("the intent must explicitly permit only the inert fixture")
        return value

    @field_validator(
        "retry_permitted",
        "fixture_child_exec_permitted",
        "external_fixture_executable_permitted",
        "candidate_access_permitted",
        "evaluation_job_access_permitted",
        "authoritative_ready",
        mode="before",
    )
    @classmethod
    def broader_authority_must_be_boolean_false(cls, value: object) -> object:
        if value is not False:
            raise ValueError("the inert-fixture intent cannot grant broader execution authority")
        return value

    @model_validator(mode="after")
    def identity_and_time_are_closed(self) -> Self:
        if self.intent_nonce == "0" * 64:
            raise ValueError("fixture intent nonce cannot use the all-zero placeholder")
        if (
            self.launcher_artifact_sha256 == "0" * 64
            or self.launcher_seccomp_policy_sha256 == "0" * 64
            or self.policy_sha256 == "0" * 64
        ):
            raise ValueError("fixture intent artifact digests cannot be placeholders")
        if not self.issued_at_unix <= self.not_before_unix < self.expires_at_unix:
            raise ValueError("fixture intent times must be ordered")
        if (
            self.expires_at_unix - self.issued_at_unix
            > MAX_INERT_FIXTURE_INTENT_LIFETIME_SECONDS
        ):
            raise ValueError("fixture intent validity exceeds the fixed lifetime")
        if self.total_timeout_ms != self.fixture_timeout_ms + self.cleanup_timeout_ms:
            raise ValueError("intent total timeout does not include both fixed deadlines")
        if self.claim_ledger_id == self.launch_ledger_id:
            raise ValueError("intent claim and launch ledgers must be distinct")
        return self


class SignedInertFixtureIntent(_InertFixtureModel):
    schema_version: Literal["bpe.signed-inert-fixture-intent.v1"]
    algorithm: Literal["Ed25519"]
    key_id: StableId
    payload: InertFixtureIntentPayload
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
            raise ValueError("signed fixture intent payload digest is inconsistent")
        return self


class InertFixtureIntentTrustKey(_InertFixtureModel):
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
            raise ValueError("fixture-intent trust-key validity interval is empty")
        return self


class InertFixtureIntentTrustStore(_InertFixtureModel):
    """Role-specific trusted configuration, authenticated out of band."""

    schema_version: Literal["bpe.inert-fixture-intent-trust-store.v1"]
    trust_store_id: StableId
    keys: Annotated[tuple[InertFixtureIntentTrustKey, ...], Field(min_length=1, max_length=64)]

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
            raise ValueError("fixture-intent trust-store key IDs must be unique")
        if len(public_keys) != len(set(public_keys)):
            raise ValueError("fixture-intent trust-store public keys must be unique")
        return self


@dataclass(frozen=True)
class InertFixtureIntentExpectation:
    policy: InertFixturePolicy
    claim_ledger_path: Path
    purpose: Literal["inert_fixture_qualification"]
    operation: Literal["qualify-clone3-inert-noexec-v1"]
    policy_id: str
    policy_sha256: str
    worker_pool_audience: str
    worker_instance_id: str
    claim_ledger_id: str
    launch_ledger_id: str
    claim_scope: Literal["single-configured-worker-ledger-v1"]
    delegated_root_id: str
    launcher_kind: Literal["spawned-one-shot-executable-v1"]
    launcher_artifact_id: str
    launcher_artifact_sha256: str
    launcher_seccomp_policy_id: str
    launcher_seccomp_policy_sha256: str
    launcher_protocol_version: Literal["bpe.clone3-inert-launcher-protocol.v1"]
    launcher_launch_method: Literal["fixed-one-shot-executable-v1"]
    fixture_kind: Literal["builtin-noexec-fixed-v1"]
    fixture_protocol_id: Literal["bpe.clone3-inert-fixture-protocol.v1"]
    resource_profile_id: str
    resource_profile_sha256: str
    fixture_timeout_ms: int
    cleanup_timeout_ms: Literal[5000]
    total_timeout_ms: int


@dataclass(frozen=True)
class VerifiedInertFixtureIntent:
    intent: SignedInertFixtureIntent
    intent_sha256: str
    payload_sha256: str
    trust_store_id: str
    trust_store_sha256: str
    verified_at_unix: int


class InertFixtureIntentClaimReceipt(_InertFixtureModel):
    schema_version: Literal["bpe.inert-fixture-intent-claim-receipt.v1"]
    status: Literal["claimed_not_started"]
    intent_id: StableId
    intent_sha256: Sha256
    intent_payload_sha256: Sha256
    signature_key_id: StableId
    trust_store_id: StableId
    trust_store_sha256: Sha256
    claim_id: Sha256
    claim_nonce: Sha256
    claimed_at_unix: Annotated[int, Field(ge=0)]
    intent_nonce: Sha256
    intent_issued_at_unix: Annotated[int, Field(ge=0)]
    intent_not_before_unix: Annotated[int, Field(ge=0)]
    intent_expires_at_unix: Annotated[int, Field(ge=0)]
    purpose: Literal["inert_fixture_qualification"]
    operation: Literal["qualify-clone3-inert-noexec-v1"]
    policy_id: StableId
    policy_sha256: Sha256
    worker_pool_audience: StableId
    worker_instance_id: StableId
    claim_ledger_id: StableId
    launch_ledger_id: StableId
    claim_scope: Literal["single-configured-worker-ledger-v1"]
    delegated_root_id: StableId
    launcher_kind: Literal["spawned-one-shot-executable-v1"]
    launcher_artifact_id: StableId
    launcher_artifact_sha256: Sha256
    launcher_seccomp_policy_id: StableId
    launcher_seccomp_policy_sha256: Sha256
    launcher_protocol_version: Literal["bpe.clone3-inert-launcher-protocol.v1"]
    launcher_launch_method: Literal["fixed-one-shot-executable-v1"]
    fixture_kind: Literal["builtin-noexec-fixed-v1"]
    fixture_protocol_id: Literal["bpe.clone3-inert-fixture-protocol.v1"]
    resource_profile_id: StableId
    resource_profile_sha256: Sha256
    fixture_timeout_ms: Annotated[int, Field(ge=5000, le=30_000)]
    cleanup_timeout_ms: Literal[5000]
    total_timeout_ms: Annotated[int, Field(ge=10_000, le=35_000)]
    maximum_claims: Literal[1]
    maximum_launch_attempts: Literal[1]
    retry_permitted: Literal[False]
    signature_verified: Literal[True]
    one_shot_claim_committed: Literal[True]
    signed_launcher_process_permitted: Literal[True]
    signed_fixture_child_process_permitted: Literal[True]
    signed_fixture_child_exec_permitted: Literal[False]
    signed_external_fixture_executable_permitted: Literal[False]
    signed_candidate_access_permitted: Literal[False]
    signed_evaluation_job_access_permitted: Literal[False]
    signed_authoritative_ready: Literal[False]
    separate_launch_ledger_required: Literal[True]
    launch_authorized: Literal[False]
    launch_attempt_consumed: Literal[False]
    launcher_artifact_accessed: Literal[False]
    launcher_process_created: Literal[False]
    fixture_child_process_created: Literal[False]
    fixture_child_exec_attempted: Literal[False]
    process_created: Literal[False]
    execution_started: Literal[False]
    external_fixture_executable_accessed: Literal[False]
    candidate_bytes_accessed: Literal[False]
    evaluation_job_accessed: Literal[False]
    authoritative: Literal[False]

    @field_validator(
        "signature_verified",
        "one_shot_claim_committed",
        "signed_launcher_process_permitted",
        "signed_fixture_child_process_permitted",
        "separate_launch_ledger_required",
        mode="before",
    )
    @classmethod
    def positive_claims_must_be_boolean_true(cls, value: object) -> object:
        if value is not True:
            raise ValueError("fixture claim evidence must be boolean true")
        return value

    @field_validator(
        "retry_permitted",
        "signed_fixture_child_exec_permitted",
        "signed_external_fixture_executable_permitted",
        "signed_candidate_access_permitted",
        "signed_evaluation_job_access_permitted",
        "signed_authoritative_ready",
        "launch_authorized",
        "launch_attempt_consumed",
        "launcher_artifact_accessed",
        "launcher_process_created",
        "fixture_child_process_created",
        "fixture_child_exec_attempted",
        "process_created",
        "execution_started",
        "external_fixture_executable_accessed",
        "candidate_bytes_accessed",
        "evaluation_job_accessed",
        "authoritative",
        mode="before",
    )
    @classmethod
    def nonclaims_must_be_boolean_false(cls, value: object) -> object:
        if value is not False:
            raise ValueError("fixture intent admission cannot claim execution or authority")
        return value

    @model_validator(mode="after")
    def claim_identities_are_nonplaceholder(self) -> Self:
        if (
            self.claim_id == "0" * 64
            or self.claim_nonce == "0" * 64
            or self.intent_nonce == "0" * 64
        ):
            raise ValueError("fixture claim identities cannot use all-zero placeholders")
        if any(
            digest == "0" * 64
            for digest in (
                self.intent_sha256,
                self.intent_payload_sha256,
                self.trust_store_sha256,
                self.policy_sha256,
                self.launcher_artifact_sha256,
                self.launcher_seccomp_policy_sha256,
                self.resource_profile_sha256,
            )
        ):
            raise ValueError("fixture claim digests cannot use all-zero placeholders")
        if not (
            self.intent_issued_at_unix
            <= self.intent_not_before_unix
            <= self.claimed_at_unix
            < self.intent_expires_at_unix
        ):
            raise ValueError("fixture claim time is outside the signed intent interval")
        if (
            self.intent_expires_at_unix - self.intent_issued_at_unix
            > MAX_INERT_FIXTURE_INTENT_LIFETIME_SECONDS
        ):
            raise ValueError("fixture claim intent interval exceeds the fixed lifetime")
        if self.total_timeout_ms != self.fixture_timeout_ms + self.cleanup_timeout_ms:
            raise ValueError("fixture claim total timeout is inconsistent")
        if self.claim_ledger_id == self.launch_ledger_id:
            raise ValueError("fixture claim and launch ledgers must be distinct")
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


def _current_unix_time() -> int:
    return time.time_ns() // 1_000_000_000


def _new_claim_nonce() -> str:
    return secrets.token_hex(32)


def _rollback_sqlite_after_error(connection: sqlite3.Connection) -> None:
    """Best-effort rollback that cannot replace the bounded primary failure."""

    with suppress(sqlite3.Error):
        if connection.in_transaction:
            connection.execute("ROLLBACK")


def _close_sqlite_connection(
    connection: sqlite3.Connection,
    *,
    error_message: str,
) -> None:
    """Close without masking an active failure; bound a standalone close failure."""

    active_error = sys.exception()
    try:
        connection.close()
    except sqlite3.Error as exc:
        if active_error is None:
            raise InertFixtureLedgerError(error_message) from exc


def inert_fixture_intent_signing_bytes(payload: InertFixtureIntentPayload) -> bytes:
    """Return the only bytes the fixture-intent signing role may sign."""

    if type(payload) is not InertFixtureIntentPayload:
        raise ValueError("fixture-intent signing requires its dedicated payload type")
    frozen = InertFixtureIntentPayload.model_validate(
        payload.model_dump(mode="python"),
        strict=True,
    )
    return INERT_FIXTURE_INTENT_SIGNING_DOMAIN + canonical_json_bytes(frozen)


def _validate_expectation(expectation: InertFixtureIntentExpectation) -> None:
    if type(expectation) is not InertFixtureIntentExpectation:
        raise InertFixtureExpectationError("fixture-intent expectation has the wrong type")
    try:
        if (
            type(expectation.claim_ledger_path) is not type(Path())
            or not expectation.claim_ledger_path.is_absolute()
            or expectation.claim_ledger_path.resolve(strict=True)
            != expectation.claim_ledger_path
        ):
            raise ValueError("fixture-intent expectation has an unsafe claim-ledger path")
        if type(expectation.policy) is not InertFixturePolicy:
            raise TypeError("fixture-intent expectation has the wrong policy type")
        frozen_policy = InertFixturePolicy.model_validate(
            expectation.policy.model_dump(mode="python"),
            strict=True,
        )
        policy_bindings = (
            frozen_policy.purpose,
            frozen_policy.operation,
            frozen_policy.policy_id,
            sha256_json(frozen_policy),
            frozen_policy.worker_pool_audience,
            frozen_policy.worker_instance_id,
            frozen_policy.claim_ledger_id,
            frozen_policy.launch_ledger_id,
            frozen_policy.claim_scope,
            frozen_policy.delegated_root_id,
            frozen_policy.launcher_kind,
            frozen_policy.launcher_artifact_id,
            frozen_policy.launcher_artifact_sha256,
            frozen_policy.launcher_seccomp_policy_id,
            frozen_policy.launcher_seccomp_policy_sha256,
            frozen_policy.launcher_protocol_version,
            frozen_policy.launcher_launch_method,
            frozen_policy.fixture_kind,
            frozen_policy.fixture_protocol_id,
            frozen_policy.resources.profile_id,
            frozen_policy.resource_profile_sha256,
            frozen_policy.fixture_timeout_ms,
            frozen_policy.cleanup_timeout_ms,
            frozen_policy.total_timeout_ms,
        )
        expectation_bindings = (
            expectation.purpose,
            expectation.operation,
            expectation.policy_id,
            expectation.policy_sha256,
            expectation.worker_pool_audience,
            expectation.worker_instance_id,
            expectation.claim_ledger_id,
            expectation.launch_ledger_id,
            expectation.claim_scope,
            expectation.delegated_root_id,
            expectation.launcher_kind,
            expectation.launcher_artifact_id,
            expectation.launcher_artifact_sha256,
            expectation.launcher_seccomp_policy_id,
            expectation.launcher_seccomp_policy_sha256,
            expectation.launcher_protocol_version,
            expectation.launcher_launch_method,
            expectation.fixture_kind,
            expectation.fixture_protocol_id,
            expectation.resource_profile_id,
            expectation.resource_profile_sha256,
            expectation.fixture_timeout_ms,
            expectation.cleanup_timeout_ms,
            expectation.total_timeout_ms,
        )
        if expectation_bindings != policy_bindings:
            raise ValueError("fixture-intent expectation differs from its policy preimage")
        probe = InertFixtureIntentPayload(
            schema_version="bpe.inert-fixture-intent-payload.v1",
            intent_id="expectation-probe",
            intent_nonce="1" * 64,
            purpose=expectation.purpose,
            operation=expectation.operation,
            policy_id=expectation.policy_id,
            policy_sha256=expectation.policy_sha256,
            worker_pool_audience=expectation.worker_pool_audience,
            worker_instance_id=expectation.worker_instance_id,
            claim_ledger_id=expectation.claim_ledger_id,
            launch_ledger_id=expectation.launch_ledger_id,
            claim_scope=expectation.claim_scope,
            delegated_root_id=expectation.delegated_root_id,
            launcher_kind=expectation.launcher_kind,
            launcher_artifact_id=expectation.launcher_artifact_id,
            launcher_artifact_sha256=expectation.launcher_artifact_sha256,
            launcher_seccomp_policy_id=expectation.launcher_seccomp_policy_id,
            launcher_seccomp_policy_sha256=expectation.launcher_seccomp_policy_sha256,
            launcher_protocol_version=expectation.launcher_protocol_version,
            launcher_launch_method=expectation.launcher_launch_method,
            fixture_kind=expectation.fixture_kind,
            fixture_protocol_id=expectation.fixture_protocol_id,
            resource_profile_id=expectation.resource_profile_id,
            resource_profile_sha256=expectation.resource_profile_sha256,
            fixture_timeout_ms=expectation.fixture_timeout_ms,
            cleanup_timeout_ms=expectation.cleanup_timeout_ms,
            total_timeout_ms=expectation.total_timeout_ms,
            issued_at_unix=0,
            not_before_unix=0,
            expires_at_unix=1,
            maximum_claims=1,
            maximum_launch_attempts=1,
            retry_permitted=False,
            launcher_process_permitted=True,
            fixture_child_process_permitted=True,
            fixture_child_exec_permitted=False,
            external_fixture_executable_permitted=False,
            candidate_access_permitted=False,
            evaluation_job_access_permitted=False,
            authoritative_ready=False,
        )
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as exc:
        raise InertFixtureExpectationError(
            "trusted fixture-intent expectation inputs are invalid"
        ) from exc
    del probe


def inert_fixture_intent_expectation_for(
    policy: InertFixturePolicy,
    *,
    expected_policy_sha256: str,
    expected_worker_pool_audience: str,
    expected_worker_instance_id: str,
    expected_claim_ledger_id: str,
    expected_claim_ledger_path: Path,
    expected_launch_ledger_id: str,
    expected_delegated_root_id: str,
    expected_launcher_artifact_id: str,
    expected_launcher_artifact_sha256: str,
    expected_launcher_seccomp_policy_id: str,
    expected_launcher_seccomp_policy_sha256: str,
) -> InertFixtureIntentExpectation:
    """Derive intent bindings from an exactly anchored trusted local policy."""

    if type(policy) is not InertFixturePolicy:
        raise InertFixtureExpectationError("fixture intent requires its dedicated policy type")
    try:
        frozen_policy = InertFixturePolicy.model_validate(
            policy.model_dump(mode="python"),
            strict=True,
        )
        policy_sha256 = sha256_json(frozen_policy)
    except (AttributeError, TypeError, ValueError) as exc:
        raise InertFixtureExpectationError("fixture-intent policy is invalid") from exc
    if policy_sha256 != expected_policy_sha256:
        raise InertFixtureExpectationError("fixture-intent policy differs from its trusted anchor")
    expected_local_bindings = (
        expected_worker_pool_audience,
        expected_worker_instance_id,
        expected_claim_ledger_id,
        expected_launch_ledger_id,
        expected_delegated_root_id,
        expected_launcher_artifact_id,
        expected_launcher_artifact_sha256,
        expected_launcher_seccomp_policy_id,
        expected_launcher_seccomp_policy_sha256,
    )
    actual_local_bindings = (
        frozen_policy.worker_pool_audience,
        frozen_policy.worker_instance_id,
        frozen_policy.claim_ledger_id,
        frozen_policy.launch_ledger_id,
        frozen_policy.delegated_root_id,
        frozen_policy.launcher_artifact_id,
        frozen_policy.launcher_artifact_sha256,
        frozen_policy.launcher_seccomp_policy_id,
        frozen_policy.launcher_seccomp_policy_sha256,
    )
    if actual_local_bindings != expected_local_bindings:
        raise InertFixtureExpectationError(
            "fixture-intent policy differs from trusted local launcher or worker bindings"
        )

    expectation = InertFixtureIntentExpectation(
        policy=frozen_policy,
        claim_ledger_path=expected_claim_ledger_path,
        purpose=frozen_policy.purpose,
        operation=frozen_policy.operation,
        policy_id=frozen_policy.policy_id,
        policy_sha256=policy_sha256,
        worker_pool_audience=frozen_policy.worker_pool_audience,
        worker_instance_id=frozen_policy.worker_instance_id,
        claim_ledger_id=frozen_policy.claim_ledger_id,
        launch_ledger_id=frozen_policy.launch_ledger_id,
        claim_scope=frozen_policy.claim_scope,
        delegated_root_id=frozen_policy.delegated_root_id,
        launcher_kind=frozen_policy.launcher_kind,
        launcher_artifact_id=frozen_policy.launcher_artifact_id,
        launcher_artifact_sha256=frozen_policy.launcher_artifact_sha256,
        launcher_seccomp_policy_id=frozen_policy.launcher_seccomp_policy_id,
        launcher_seccomp_policy_sha256=frozen_policy.launcher_seccomp_policy_sha256,
        launcher_protocol_version=frozen_policy.launcher_protocol_version,
        launcher_launch_method=frozen_policy.launcher_launch_method,
        fixture_kind=frozen_policy.fixture_kind,
        fixture_protocol_id=frozen_policy.fixture_protocol_id,
        resource_profile_id=frozen_policy.resources.profile_id,
        resource_profile_sha256=frozen_policy.resource_profile_sha256,
        fixture_timeout_ms=frozen_policy.fixture_timeout_ms,
        cleanup_timeout_ms=frozen_policy.cleanup_timeout_ms,
        total_timeout_ms=frozen_policy.total_timeout_ms,
    )
    _validate_expectation(expectation)
    return expectation


def _inert_fixture_binding_sha256(
    subject: InertFixtureIntentPayload | InertFixtureIntentClaimReceipt,
) -> str:
    return sha256_json(
        {
            "schema_version": "bpe.inert-fixture-binding.v1",
            "purpose": subject.purpose,
            "operation": subject.operation,
            "policy_id": subject.policy_id,
            "policy_sha256": subject.policy_sha256,
            "worker_pool_audience": subject.worker_pool_audience,
            "worker_instance_id": subject.worker_instance_id,
            "claim_ledger_id": subject.claim_ledger_id,
            "launch_ledger_id": subject.launch_ledger_id,
            "claim_scope": subject.claim_scope,
            "delegated_root_id": subject.delegated_root_id,
            "launcher_kind": subject.launcher_kind,
            "launcher_artifact_id": subject.launcher_artifact_id,
            "launcher_artifact_sha256": subject.launcher_artifact_sha256,
            "launcher_seccomp_policy_id": subject.launcher_seccomp_policy_id,
            "launcher_seccomp_policy_sha256": subject.launcher_seccomp_policy_sha256,
            "launcher_protocol_version": subject.launcher_protocol_version,
            "launcher_launch_method": subject.launcher_launch_method,
            "fixture_kind": subject.fixture_kind,
            "fixture_protocol_id": subject.fixture_protocol_id,
            "resource_profile_id": subject.resource_profile_id,
            "resource_profile_sha256": subject.resource_profile_sha256,
            "fixture_timeout_ms": subject.fixture_timeout_ms,
            "cleanup_timeout_ms": subject.cleanup_timeout_ms,
            "total_timeout_ms": subject.total_timeout_ms,
            "maximum_claims": subject.maximum_claims,
            "maximum_launch_attempts": subject.maximum_launch_attempts,
            "retry_permitted": subject.retry_permitted,
        }
    )


def _receipt_mirrors_authenticated_payload(
    receipt: InertFixtureIntentClaimReceipt,
    payload: InertFixtureIntentPayload,
) -> bool:
    payload_fields = (
        payload.intent_id,
        payload.intent_nonce,
        payload.issued_at_unix,
        payload.not_before_unix,
        payload.expires_at_unix,
        payload.purpose,
        payload.operation,
        payload.policy_id,
        payload.policy_sha256,
        payload.worker_pool_audience,
        payload.worker_instance_id,
        payload.claim_ledger_id,
        payload.launch_ledger_id,
        payload.claim_scope,
        payload.delegated_root_id,
        payload.launcher_kind,
        payload.launcher_artifact_id,
        payload.launcher_artifact_sha256,
        payload.launcher_seccomp_policy_id,
        payload.launcher_seccomp_policy_sha256,
        payload.launcher_protocol_version,
        payload.launcher_launch_method,
        payload.fixture_kind,
        payload.fixture_protocol_id,
        payload.resource_profile_id,
        payload.resource_profile_sha256,
        payload.fixture_timeout_ms,
        payload.cleanup_timeout_ms,
        payload.total_timeout_ms,
        payload.maximum_claims,
        payload.maximum_launch_attempts,
        payload.retry_permitted,
        payload.launcher_process_permitted,
        payload.fixture_child_process_permitted,
        payload.fixture_child_exec_permitted,
        payload.external_fixture_executable_permitted,
        payload.candidate_access_permitted,
        payload.evaluation_job_access_permitted,
        payload.authoritative_ready,
    )
    receipt_fields = (
        receipt.intent_id,
        receipt.intent_nonce,
        receipt.intent_issued_at_unix,
        receipt.intent_not_before_unix,
        receipt.intent_expires_at_unix,
        receipt.purpose,
        receipt.operation,
        receipt.policy_id,
        receipt.policy_sha256,
        receipt.worker_pool_audience,
        receipt.worker_instance_id,
        receipt.claim_ledger_id,
        receipt.launch_ledger_id,
        receipt.claim_scope,
        receipt.delegated_root_id,
        receipt.launcher_kind,
        receipt.launcher_artifact_id,
        receipt.launcher_artifact_sha256,
        receipt.launcher_seccomp_policy_id,
        receipt.launcher_seccomp_policy_sha256,
        receipt.launcher_protocol_version,
        receipt.launcher_launch_method,
        receipt.fixture_kind,
        receipt.fixture_protocol_id,
        receipt.resource_profile_id,
        receipt.resource_profile_sha256,
        receipt.fixture_timeout_ms,
        receipt.cleanup_timeout_ms,
        receipt.total_timeout_ms,
        receipt.maximum_claims,
        receipt.maximum_launch_attempts,
        receipt.retry_permitted,
        receipt.signed_launcher_process_permitted,
        receipt.signed_fixture_child_process_permitted,
        receipt.signed_fixture_child_exec_permitted,
        receipt.signed_external_fixture_executable_permitted,
        receipt.signed_candidate_access_permitted,
        receipt.signed_evaluation_job_access_permitted,
        receipt.signed_authoritative_ready,
    )
    return receipt_fields == payload_fields


def _verify_inert_fixture_intent(
    intent: SignedInertFixtureIntent,
    trust_store: InertFixtureIntentTrustStore,
    expectation: InertFixtureIntentExpectation,
    *,
    now_unix: int,
    enforce_validity: bool,
) -> VerifiedInertFixtureIntent:
    if type(now_unix) is not int or now_unix < 0:
        raise InertFixtureAuthorizationError(
            "fixture-intent verification time must be a nonnegative integer"
        )
    if type(intent) is not SignedInertFixtureIntent:
        raise InertFixtureAuthorizationError("fixture intent has the wrong signed-envelope type")
    if type(trust_store) is not InertFixtureIntentTrustStore:
        raise InertFixtureAuthorizationError("fixture intent has the wrong trust-store role")
    try:
        frozen_intent = SignedInertFixtureIntent.model_validate(
            intent.model_dump(mode="python"),
            strict=True,
        )
        frozen_store = InertFixtureIntentTrustStore.model_validate(
            trust_store.model_dump(mode="python"),
            strict=True,
        )
        _validate_expectation(expectation)
    except (AttributeError, InertFixtureExpectationError, TypeError, ValueError) as exc:
        raise InertFixtureAuthorizationError("fixture-intent inputs are invalid") from exc

    payload = frozen_intent.payload
    expected_bindings = (
        expectation.purpose,
        expectation.operation,
        expectation.policy_id,
        expectation.policy_sha256,
        expectation.worker_pool_audience,
        expectation.worker_instance_id,
        expectation.claim_ledger_id,
        expectation.launch_ledger_id,
        expectation.claim_scope,
        expectation.delegated_root_id,
        expectation.launcher_kind,
        expectation.launcher_artifact_id,
        expectation.launcher_artifact_sha256,
        expectation.launcher_seccomp_policy_id,
        expectation.launcher_seccomp_policy_sha256,
        expectation.launcher_protocol_version,
        expectation.launcher_launch_method,
        expectation.fixture_kind,
        expectation.fixture_protocol_id,
        expectation.resource_profile_id,
        expectation.resource_profile_sha256,
        expectation.fixture_timeout_ms,
        expectation.cleanup_timeout_ms,
        expectation.total_timeout_ms,
    )
    actual_bindings = (
        payload.purpose,
        payload.operation,
        payload.policy_id,
        payload.policy_sha256,
        payload.worker_pool_audience,
        payload.worker_instance_id,
        payload.claim_ledger_id,
        payload.launch_ledger_id,
        payload.claim_scope,
        payload.delegated_root_id,
        payload.launcher_kind,
        payload.launcher_artifact_id,
        payload.launcher_artifact_sha256,
        payload.launcher_seccomp_policy_id,
        payload.launcher_seccomp_policy_sha256,
        payload.launcher_protocol_version,
        payload.launcher_launch_method,
        payload.fixture_kind,
        payload.fixture_protocol_id,
        payload.resource_profile_id,
        payload.resource_profile_sha256,
        payload.fixture_timeout_ms,
        payload.cleanup_timeout_ms,
        payload.total_timeout_ms,
    )
    if actual_bindings != expected_bindings:
        raise InertFixtureAuthorizationError("fixture-intent bindings differ")
    if enforce_validity and not (
        payload.not_before_unix <= now_unix < payload.expires_at_unix
    ):
        raise InertFixtureAuthorizationError("fixture intent is outside its validity window")

    matching_keys = [key for key in frozen_store.keys if key.key_id == frozen_intent.key_id]
    if len(matching_keys) != 1:
        raise InertFixtureAuthorizationError("fixture-intent signing key is not trusted")
    key = matching_keys[0]
    if key.revoked:
        raise InertFixtureAuthorizationError("fixture-intent signing key is revoked")
    if not (
        key.valid_from_unix <= payload.issued_at_unix
        and payload.expires_at_unix <= key.valid_until_unix
    ):
        raise InertFixtureAuthorizationError(
            "fixture intent is outside the signing key validity window"
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
            frozen_intent.signature_base64url,
            expected_bytes=_SIGNATURE_BYTES,
            label="signature",
        )
        public_key.verify(signature, inert_fixture_intent_signing_bytes(payload))
    except (InvalidSignature, UnsupportedAlgorithm, ValueError) as exc:
        raise InertFixtureAuthorizationError("fixture-intent signature is invalid") from exc

    return VerifiedInertFixtureIntent(
        intent=frozen_intent,
        intent_sha256=sha256_json(frozen_intent),
        payload_sha256=sha256_json(payload),
        trust_store_id=frozen_store.trust_store_id,
        trust_store_sha256=sha256_json(frozen_store),
        verified_at_unix=now_unix,
    )


def verify_inert_fixture_intent(
    intent: SignedInertFixtureIntent,
    trust_store: InertFixtureIntentTrustStore,
    expectation: InertFixtureIntentExpectation,
    *,
    now_unix: int,
) -> VerifiedInertFixtureIntent:
    """Authenticate and exactly bind one currently valid fixture intent."""

    return _verify_inert_fixture_intent(
        intent,
        trust_store,
        expectation,
        now_unix=now_unix,
        enforce_validity=True,
    )


class InertFixtureIntentLedger:
    """Independent durable one-shot ledger for fixed fixture intents."""

    path: Path
    ledger_id: str
    worker_instance_id: str

    def __init__(self, path: Path, *, ledger_id: str, worker_instance_id: str) -> None:
        self._configure_identity(
            path,
            ledger_id=ledger_id,
            worker_instance_id=worker_instance_id,
        )
        self._validate_database_parent()
        self._validate_database_file()
        self._initialize_or_validate(require_empty=False)

    @classmethod
    def provision(
        cls,
        path: Path,
        *,
        ledger_id: str,
        worker_instance_id: str,
    ) -> InertFixtureIntentLedger:
        """Create one new configured ledger; never open or replace an existing path."""

        instance = cls.__new__(cls)
        instance._configure_identity(
            path,
            ledger_id=ledger_id,
            worker_instance_id=worker_instance_id,
        )
        instance._validate_database_parent()
        instance._create_database_file()
        instance._initialize_or_validate(require_empty=True)
        return instance

    def _configure_identity(
        self,
        path: Path,
        *,
        ledger_id: str,
        worker_instance_id: str,
    ) -> None:
        if type(path) is not type(Path()):
            raise InertFixtureLedgerError("fixture-intent ledger path must be a Path")
        try:
            encoded_path = os.fsencode(path)
        except UnicodeError as exc:
            raise InertFixtureLedgerError(
                "fixture-intent ledger path is not filesystem-encodable"
            ) from exc
        if b"\x00" in encoded_path:
            raise InertFixtureLedgerError("fixture-intent ledger path contains a NUL byte")
        if type(ledger_id) is not str or not _STABLE_ID.fullmatch(ledger_id):
            raise InertFixtureLedgerError("fixture-intent ledger ID is invalid")
        if (
            type(worker_instance_id) is not str
            or not _STABLE_ID.fullmatch(worker_instance_id)
        ):
            raise InertFixtureLedgerError("fixture-intent worker instance ID is invalid")
        self.path = Path(os.fspath(path))
        self.ledger_id = ledger_id
        self.worker_instance_id = worker_instance_id

    def _initialize_or_validate(self, *, require_empty: bool) -> None:
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                objects = connection.execute(
                    "SELECT type, name FROM sqlite_schema"
                ).fetchall()
                if require_empty:
                    if objects:
                        raise InertFixtureLedgerError(
                            "new fixture-intent ledger is not empty"
                        )
                    connection.execute(_CREATE_INTENT_RESERVATIONS)
                    connection.execute(_CREATE_INTENT_CLAIMS)
                    connection.execute(_CREATE_INTENT_STATE)
                    connection.execute(
                        "INSERT INTO inert_fixture_intent_state "
                        "(singleton, worker_instance_id, claim_ledger_id, "
                        "clock_high_water_unix) VALUES (1, ?, ?, 0)",
                        (self.worker_instance_id, self.ledger_id),
                    )
                    connection.execute(f"PRAGMA application_id={_LEDGER_APPLICATION_ID}")
                    connection.execute(f"PRAGMA user_version={_LEDGER_USER_VERSION}")
                elif not objects:
                    raise InertFixtureLedgerError(
                        "fixture-intent ledger is unprovisioned or empty"
                    )
                connection.execute("COMMIT")
                connection.execute("BEGIN")
                self._validate_schema(connection)
                connection.execute("COMMIT")
            except BaseException:
                _rollback_sqlite_after_error(connection)
                raise
            finally:
                _close_sqlite_connection(
                    connection,
                    error_message="cannot close fixture-intent claim ledger",
                )
        except InertFixtureLedgerError:
            raise
        except sqlite3.Error as exc:
            raise InertFixtureLedgerError(
                "cannot initialize fixture-intent claim ledger"
            ) from exc

    def _validate_database_parent(self) -> None:
        if not self.path.is_absolute() or self.path.name in {"", ".", ".."}:
            raise InertFixtureLedgerError("fixture-intent ledger path must be absolute")
        parent = self.path.parent
        try:
            parent_stat = parent.lstat()
            resolved_parent = parent.resolve(strict=True)
        except (OSError, RuntimeError, ValueError) as exc:
            raise InertFixtureLedgerError(
                "cannot inspect fixture-intent ledger parent"
            ) from exc
        if (
            resolved_parent != parent
            or stat.S_ISLNK(parent_stat.st_mode)
            or not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_uid != os.geteuid()
            or parent_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise InertFixtureLedgerError(
                "fixture-intent ledger parent must be caller-owned, private, and non-symlinked"
            )
        for ancestor in parent.parents:
            try:
                ancestor_stat = ancestor.lstat()
            except OSError as exc:
                raise InertFixtureLedgerError(
                    "cannot inspect a fixture-intent ledger ancestor"
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
                raise InertFixtureLedgerError(
                    "fixture-intent ledger ancestors must be trusted and rename-safe"
                )

    def _create_database_file(self) -> None:
        parent = self.path.parent
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        for name in ("O_NOFOLLOW", "O_CLOEXEC"):
            if not hasattr(os, name):
                raise InertFixtureLedgerError(
                    "secure fixture-intent ledger creation is unavailable"
                )
            flags |= getattr(os, name)
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except FileExistsError as exc:
            raise InertFixtureLedgerError(
                "fixture-intent ledger path is already provisioned"
            ) from exc
        except OSError as exc:
            raise InertFixtureLedgerError(
                "cannot create fixture-intent claim ledger"
            ) from exc
        try:
            os.fsync(descriptor)
        except OSError as exc:
            with suppress(OSError):
                os.close(descriptor)
            raise InertFixtureLedgerError(
                "cannot durably create fixture-intent ledger file"
            ) from exc
        try:
            os.close(descriptor)
        except OSError as exc:
            raise InertFixtureLedgerError(
                "cannot close new fixture-intent ledger file"
            ) from exc

        self._validate_database_file()
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
            raise InertFixtureLedgerError(
                "cannot durably create fixture-intent ledger"
            ) from exc

    def _validate_database_file(self) -> None:
        try:
            database_stat = self.path.lstat()
        except OSError as exc:
            raise InertFixtureLedgerError(
                "cannot inspect fixture-intent claim ledger"
            ) from exc
        if (
            stat.S_ISLNK(database_stat.st_mode)
            or not stat.S_ISREG(database_stat.st_mode)
            or database_stat.st_uid != os.geteuid()
            or database_stat.st_nlink != 1
            or stat.S_IMODE(database_stat.st_mode) != 0o600
        ):
            raise InertFixtureLedgerError(
                "fixture-intent ledger must be caller-owned, mode 0600, and regular"
            )

    def _connect(self) -> sqlite3.Connection:
        connection: sqlite3.Connection | None = None
        try:
            self._validate_database_parent()
            self._validate_database_file()
            connection = sqlite3.connect(
                f"{self.path.as_uri()}?mode=rw",
                timeout=5.0,
                isolation_level=None,
                uri=True,
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
                raise InertFixtureLedgerError(
                    "fixture-intent ledger safety settings were not applied"
                )
            return connection
        except InertFixtureLedgerError:
            if connection is not None:
                with suppress(sqlite3.Error):
                    connection.close()
            raise
        except sqlite3.Error as exc:
            if connection is not None:
                with suppress(sqlite3.Error):
                    connection.close()
            raise InertFixtureLedgerError(
                "cannot open fixture-intent claim ledger"
            ) from exc

    def _validate_schema(self, connection: sqlite3.Connection) -> None:
        if not connection.in_transaction:
            raise InertFixtureLedgerError(
                "fixture-intent schema validation requires one database snapshot"
            )
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
                ("inert_fixture_intent_claims",),
            ).fetchone()
            reservation_sql = connection.execute(
                "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?",
                ("inert_fixture_intent_reservations",),
            ).fetchone()
            state_sql = connection.execute(
                "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?",
                ("inert_fixture_intent_state",),
            ).fetchone()
            columns = connection.execute(
                "PRAGMA table_info(inert_fixture_intent_claims)"
            ).fetchall()
            reservation_columns = connection.execute(
                "PRAGMA table_info(inert_fixture_intent_reservations)"
            ).fetchall()
            state_columns = connection.execute(
                "PRAGMA table_info(inert_fixture_intent_state)"
            ).fetchall()
            state_rows = connection.execute(
                "SELECT singleton, worker_instance_id, claim_ledger_id, "
                "clock_high_water_unix "
                "FROM inert_fixture_intent_state"
            ).fetchall()
            maximum_claimed_at = connection.execute(
                "SELECT MAX(claimed_at_unix) FROM inert_fixture_intent_claims"
            ).fetchone()
            maximum_reserved_at = connection.execute(
                "SELECT MAX(reserved_at_unix) FROM inert_fixture_intent_reservations"
            ).fetchone()
            index_rows = connection.execute(
                "PRAGMA index_list(inert_fixture_intent_claims)"
            ).fetchall()
            reservation_index_rows = connection.execute(
                "PRAGMA index_list(inert_fixture_intent_reservations)"
            ).fetchall()
            state_index_rows = connection.execute(
                "PRAGMA index_list(inert_fixture_intent_state)"
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
            reservation_indexed_columns = {
                tuple(
                    row[2]
                    for row in connection.execute(
                        f'PRAGMA index_info("{index_row[1]}")'
                    ).fetchall()
                )
                for index_row in reservation_index_rows
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
                "PRAGMA foreign_key_list(inert_fixture_intent_claims)"
            ).fetchall()
            reservation_foreign_keys = connection.execute(
                "PRAGMA foreign_key_list(inert_fixture_intent_reservations)"
            ).fetchall()
        except sqlite3.Error as exc:
            raise InertFixtureLedgerError(
                "fixture-intent claim ledger schema is not trusted"
            ) from exc

        expected_columns = (
            (0, "intent_id", "TEXT", 1, None, 1),
            (1, "intent_sha256", "TEXT", 1, None, 0),
            (2, "payload_sha256", "TEXT", 1, None, 0),
            (3, "signature_key_id", "TEXT", 1, None, 0),
            (4, "trust_store_id", "TEXT", 1, None, 0),
            (5, "trust_store_sha256", "TEXT", 1, None, 0),
            (6, "worker_instance_id", "TEXT", 1, None, 0),
            (7, "claim_ledger_id", "TEXT", 1, None, 0),
            (8, "launch_ledger_id", "TEXT", 1, None, 0),
            (9, "intent_nonce", "TEXT", 1, None, 0),
            (10, "claim_id", "TEXT", 1, None, 0),
            (11, "claim_nonce", "TEXT", 1, None, 0),
            (12, "claimed_at_unix", "INTEGER", 1, None, 0),
            (13, "receipt_sha256", "TEXT", 1, None, 0),
            (14, "receipt_json", "BLOB", 1, None, 0),
            (15, "policy_id", "TEXT", 1, None, 0),
            (16, "policy_sha256", "TEXT", 1, None, 0),
            (17, "worker_pool_audience", "TEXT", 1, None, 0),
            (18, "delegated_root_id", "TEXT", 1, None, 0),
            (19, "launcher_artifact_id", "TEXT", 1, None, 0),
            (20, "launcher_artifact_sha256", "TEXT", 1, None, 0),
            (21, "launcher_seccomp_policy_id", "TEXT", 1, None, 0),
            (22, "launcher_seccomp_policy_sha256", "TEXT", 1, None, 0),
            (23, "fixture_protocol_id", "TEXT", 1, None, 0),
            (24, "resource_profile_id", "TEXT", 1, None, 0),
            (25, "resource_profile_sha256", "TEXT", 1, None, 0),
            (26, "binding_sha256", "TEXT", 1, None, 0),
        )
        expected_reservation_columns = (
            (0, "intent_sha256", "TEXT", 1, None, 1),
            (1, "intent_id", "TEXT", 1, None, 0),
            (2, "payload_sha256", "TEXT", 1, None, 0),
            (3, "signature_key_id", "TEXT", 1, None, 0),
            (4, "trust_store_id", "TEXT", 1, None, 0),
            (5, "trust_store_sha256", "TEXT", 1, None, 0),
            (6, "worker_instance_id", "TEXT", 1, None, 0),
            (7, "claim_ledger_id", "TEXT", 1, None, 0),
            (8, "launch_ledger_id", "TEXT", 1, None, 0),
            (9, "intent_nonce", "TEXT", 1, None, 0),
            (10, "policy_sha256", "TEXT", 1, None, 0),
            (11, "binding_sha256", "TEXT", 1, None, 0),
            (12, "reserved_at_unix", "INTEGER", 1, None, 0),
        )
        expected_unique_columns = {
            ("intent_id",),
            ("intent_id", "receipt_sha256"),
            ("intent_sha256",),
            ("intent_nonce",),
            ("claim_id",),
            ("claim_nonce",),
            ("receipt_sha256",),
        }
        expected_reservation_unique_columns = {
            ("intent_sha256",),
            ("intent_id",),
            ("intent_nonce",),
            (
                "intent_sha256",
                "intent_id",
                "payload_sha256",
                "signature_key_id",
                "trust_store_id",
                "trust_store_sha256",
                "worker_instance_id",
                "claim_ledger_id",
                "launch_ledger_id",
                "intent_nonce",
                "policy_sha256",
                "binding_sha256",
                "reserved_at_unix",
            ),
        }
        normalized_table_sql = (
            " ".join(table_sql[0].split())
            if table_sql is not None and isinstance(table_sql[0], str)
            else None
        )
        expected_table_sql = " ".join(_CREATE_INTENT_CLAIMS.split())
        normalized_reservation_sql = (
            " ".join(reservation_sql[0].split())
            if reservation_sql is not None and isinstance(reservation_sql[0], str)
            else None
        )
        expected_reservation_sql = " ".join(_CREATE_INTENT_RESERVATIONS.split())
        normalized_state_sql = (
            " ".join(state_sql[0].split())
            if state_sql is not None and isinstance(state_sql[0], str)
            else None
        )
        expected_state_sql = " ".join(_CREATE_INTENT_STATE.split())
        expected_state_columns = (
            (0, "singleton", "INTEGER", 1, None, 1),
            (1, "worker_instance_id", "TEXT", 1, None, 0),
            (2, "claim_ledger_id", "TEXT", 1, None, 0),
            (3, "clock_high_water_unix", "INTEGER", 1, None, 0),
        )
        table_objects = {
            row[1]: " ".join(row[3].split())
            for row in objects
            if row[0] == "table" and isinstance(row[3], str)
        }
        autoindexes_are_exact = all(
            row[0] == "index"
            and row[2]
            in {
                "inert_fixture_intent_claims",
                "inert_fixture_intent_reservations",
                "inert_fixture_intent_state",
            }
            and row[1].startswith(f"sqlite_autoindex_{row[2]}_")
            and row[3] is None
            for row in objects
            if row[0] != "table"
        )
        schema_index_names = {row[1] for row in objects if row[0] == "index"}
        expected_schema_index_names = {
            row[1]
            for row in (*index_rows, *reservation_index_rows, *state_index_rows)
            if row[3] == "u"
        }
        expected_foreign_key_columns = {
            ("intent_sha256", "intent_sha256"),
            ("intent_id", "intent_id"),
            ("payload_sha256", "payload_sha256"),
            ("signature_key_id", "signature_key_id"),
            ("trust_store_id", "trust_store_id"),
            ("trust_store_sha256", "trust_store_sha256"),
            ("worker_instance_id", "worker_instance_id"),
            ("claim_ledger_id", "claim_ledger_id"),
            ("launch_ledger_id", "launch_ledger_id"),
            ("intent_nonce", "intent_nonce"),
            ("policy_sha256", "policy_sha256"),
            ("binding_sha256", "binding_sha256"),
            ("claimed_at_unix", "reserved_at_unix"),
        }
        foreign_key_columns = {(row[3], row[4]) for row in foreign_keys}
        if (
            integrity_check != [("ok",)]
            or foreign_key_check
            or reservation_foreign_keys
            or len(foreign_keys) != len(expected_foreign_key_columns)
            or foreign_key_columns != expected_foreign_key_columns
            or any(
                row[2] != "inert_fixture_intent_reservations"
                or row[5:] != ("NO ACTION", "NO ACTION", "NONE")
                for row in foreign_keys
            )
            or application_id != (_LEDGER_APPLICATION_ID,)
            or user_version != (_LEDGER_USER_VERSION,)
            or table_objects
            != {
                "inert_fixture_intent_claims": expected_table_sql,
                "inert_fixture_intent_reservations": expected_reservation_sql,
                "inert_fixture_intent_state": expected_state_sql,
            }
            or not autoindexes_are_exact
            or schema_index_names != expected_schema_index_names
            or normalized_table_sql != expected_table_sql
            or normalized_reservation_sql != expected_reservation_sql
            or normalized_state_sql != expected_state_sql
            or tuple(columns) != expected_columns
            or tuple(reservation_columns) != expected_reservation_columns
            or tuple(state_columns) != expected_state_columns
            or len(state_rows) != 1
            or state_rows[0][0] != 1
            or state_rows[0][1] != self.worker_instance_id
            or state_rows[0][2] != self.ledger_id
            or type(state_rows[0][3]) is not int
            or state_rows[0][3] < 0
            or maximum_claimed_at is None
            or len(maximum_claimed_at) != 1
            or (
                maximum_claimed_at[0] is not None
                and (
                    type(maximum_claimed_at[0]) is not int
                    or state_rows[0][3] < maximum_claimed_at[0]
                )
            )
            or maximum_reserved_at is None
            or len(maximum_reserved_at) != 1
            or (
                maximum_reserved_at[0] is not None
                and (
                    type(maximum_reserved_at[0]) is not int
                    or state_rows[0][3] < maximum_reserved_at[0]
                )
            )
            or indexed_columns != expected_unique_columns
            or len(index_rows) != len(expected_unique_columns)
            or reservation_indexed_columns
            != expected_reservation_unique_columns
            or len(reservation_index_rows)
            != len(expected_reservation_unique_columns)
            or state_indexed_columns != {("singleton",)}
            or len(state_index_rows) != 1
        ):
            raise InertFixtureLedgerError(
                "fixture-intent claim ledger schema is not trusted"
            )

    def claim_intent(
        self,
        intent: SignedInertFixtureIntent,
        trust_store: InertFixtureIntentTrustStore,
        expectation: InertFixtureIntentExpectation,
        *,
        claim_id: str,
    ) -> InertFixtureIntentClaimReceipt:
        """Reverify and durably consume one intent without starting a process."""

        verification_time = _current_unix_time()
        verified = verify_inert_fixture_intent(
            intent,
            trust_store,
            expectation,
            now_unix=verification_time,
        )
        payload = verified.intent.payload
        if (
            payload.worker_instance_id != self.worker_instance_id
            or payload.claim_ledger_id != self.ledger_id
            or expectation.claim_ledger_path != self.path
        ):
            raise InertFixtureLedgerError(
                "fixture intent is bound to a different worker or claim ledger"
            )
        binding_sha256 = _inert_fixture_binding_sha256(payload)

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_schema(connection)
            claimed_at_unix = _current_unix_time()
            if type(claimed_at_unix) is not int or claimed_at_unix < 0:
                raise InertFixtureLedgerError("worker clock returned an invalid Unix time")
            clock_row = connection.execute(
                "SELECT clock_high_water_unix FROM inert_fixture_intent_state "
                "WHERE singleton = 1"
            ).fetchone()
            if (
                clock_row is None
                or type(clock_row[0]) is not int
                or claimed_at_unix < verification_time
                or claimed_at_unix < clock_row[0]
            ):
                raise InertFixtureLedgerError(
                    "worker clock moved behind its durable fixture-intent high-water mark"
                )
            connection.execute(
                "UPDATE inert_fixture_intent_state SET clock_high_water_unix = ? "
                "WHERE singleton = 1",
                (claimed_at_unix,),
            )
            if not (
                payload.not_before_unix
                <= claimed_at_unix
                < payload.expires_at_unix
            ):
                connection.execute("COMMIT")
                raise InertFixtureLedgerError(
                    "fixture intent is outside its validity window at durable claim"
                )

            reservation_identity = (
                verified.intent_sha256,
                payload.intent_id,
                verified.payload_sha256,
                verified.intent.key_id,
                verified.trust_store_id,
                verified.trust_store_sha256,
                self.worker_instance_id,
                self.ledger_id,
                payload.launch_ledger_id,
                payload.intent_nonce,
                payload.policy_sha256,
                binding_sha256,
            )
            existing_reservation = connection.execute(
                """
                SELECT intent_sha256, intent_id, payload_sha256, signature_key_id,
                       trust_store_id, trust_store_sha256, worker_instance_id,
                       claim_ledger_id, launch_ledger_id, intent_nonce, policy_sha256,
                       binding_sha256, reserved_at_unix
                FROM inert_fixture_intent_reservations
                WHERE intent_sha256 = ?
                """,
                (verified.intent_sha256,),
            ).fetchone()
            if existing_reservation is not None:
                if (
                    existing_reservation[:-1] != reservation_identity
                    or type(existing_reservation[-1]) is not int
                    or not (
                        payload.not_before_unix
                        <= existing_reservation[-1]
                        < payload.expires_at_unix
                    )
                ):
                    raise InertFixtureLedgerError(
                        "fixture-intent reservation differs from authenticated inputs"
                    )
                connection.execute("COMMIT")
                raise InertFixtureIntentAlreadyClaimed(
                    "fixture intent was already consumed by a terminal reservation"
                )
            signed_identity_conflict = connection.execute(
                """
                SELECT 1 FROM inert_fixture_intent_reservations
                WHERE intent_id = ? OR intent_nonce = ?
                LIMIT 1
                """,
                (payload.intent_id, payload.intent_nonce),
            ).fetchone()
            if signed_identity_conflict is not None:
                connection.execute("COMMIT")
                raise InertFixtureIntentAlreadyClaimed(
                    "fixture intent signed identity was already consumed"
                )
            connection.execute(
                """
                INSERT INTO inert_fixture_intent_reservations (
                    intent_sha256, intent_id, payload_sha256, signature_key_id,
                    trust_store_id, trust_store_sha256, worker_instance_id,
                    claim_ledger_id, launch_ledger_id, intent_nonce, policy_sha256,
                    binding_sha256, reserved_at_unix
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (*reservation_identity, claimed_at_unix),
            )
            if (
                type(claim_id) is not str
                or not _SHA256_HEX.fullmatch(claim_id)
                or claim_id == "0" * 64
            ):
                connection.execute("COMMIT")
                raise InertFixtureIntentAlreadyClaimed(
                    "fixture intent was already consumed: claim ID must be a nonzero "
                    "lowercase SHA-256 value"
                )
            caller_conflict = connection.execute(
                "SELECT 1 FROM inert_fixture_intent_claims WHERE claim_id = ? LIMIT 1",
                (claim_id,),
            ).fetchone()
            if caller_conflict is not None:
                connection.execute("COMMIT")
                raise InertFixtureIntentAlreadyClaimed(
                    "fixture intent was already consumed by an identity collision"
                )
            try:
                receipt = InertFixtureIntentClaimReceipt(
                    schema_version="bpe.inert-fixture-intent-claim-receipt.v1",
                    status="claimed_not_started",
                    intent_id=payload.intent_id,
                    intent_sha256=verified.intent_sha256,
                    intent_payload_sha256=verified.payload_sha256,
                    signature_key_id=verified.intent.key_id,
                    trust_store_id=verified.trust_store_id,
                    trust_store_sha256=verified.trust_store_sha256,
                    claim_id=claim_id,
                    claim_nonce=_new_claim_nonce(),
                    claimed_at_unix=claimed_at_unix,
                    intent_nonce=payload.intent_nonce,
                    intent_issued_at_unix=payload.issued_at_unix,
                    intent_not_before_unix=payload.not_before_unix,
                    intent_expires_at_unix=payload.expires_at_unix,
                    purpose=payload.purpose,
                    operation=payload.operation,
                    policy_id=payload.policy_id,
                    policy_sha256=payload.policy_sha256,
                    worker_pool_audience=payload.worker_pool_audience,
                    worker_instance_id=payload.worker_instance_id,
                    claim_ledger_id=payload.claim_ledger_id,
                    launch_ledger_id=payload.launch_ledger_id,
                    claim_scope=payload.claim_scope,
                    delegated_root_id=payload.delegated_root_id,
                    launcher_kind=payload.launcher_kind,
                    launcher_artifact_id=payload.launcher_artifact_id,
                    launcher_artifact_sha256=payload.launcher_artifact_sha256,
                    launcher_seccomp_policy_id=payload.launcher_seccomp_policy_id,
                    launcher_seccomp_policy_sha256=(
                        payload.launcher_seccomp_policy_sha256
                    ),
                    launcher_protocol_version=payload.launcher_protocol_version,
                    launcher_launch_method=payload.launcher_launch_method,
                    fixture_kind=payload.fixture_kind,
                    fixture_protocol_id=payload.fixture_protocol_id,
                    resource_profile_id=payload.resource_profile_id,
                    resource_profile_sha256=payload.resource_profile_sha256,
                    fixture_timeout_ms=payload.fixture_timeout_ms,
                    cleanup_timeout_ms=payload.cleanup_timeout_ms,
                    total_timeout_ms=payload.total_timeout_ms,
                    maximum_claims=payload.maximum_claims,
                    maximum_launch_attempts=payload.maximum_launch_attempts,
                    retry_permitted=False,
                    signature_verified=True,
                    one_shot_claim_committed=True,
                    signed_launcher_process_permitted=True,
                    signed_fixture_child_process_permitted=True,
                    signed_fixture_child_exec_permitted=False,
                    signed_external_fixture_executable_permitted=False,
                    signed_candidate_access_permitted=False,
                    signed_evaluation_job_access_permitted=False,
                    signed_authoritative_ready=False,
                    separate_launch_ledger_required=True,
                    launch_authorized=False,
                    launch_attempt_consumed=False,
                    launcher_artifact_accessed=False,
                    launcher_process_created=False,
                    fixture_child_process_created=False,
                    fixture_child_exec_attempted=False,
                    process_created=False,
                    execution_started=False,
                    external_fixture_executable_accessed=False,
                    candidate_bytes_accessed=False,
                    evaluation_job_accessed=False,
                    authoritative=False,
                )
                receipt_sha256 = sha256_json(receipt)
                receipt_json = canonical_json_bytes(receipt)
                if not 1 <= len(receipt_json) <= 32_768:
                    raise ValueError("receipt exceeds its fixed storage bound")
            except Exception as exc:
                connection.execute("COMMIT")
                raise InertFixtureIntentAlreadyClaimed(
                    "fixture intent was already consumed before receipt construction"
                ) from exc
            conflict = connection.execute(
                """
                SELECT 1 FROM inert_fixture_intent_claims
                WHERE claim_nonce = ? OR receipt_sha256 = ?
                LIMIT 1
                """,
                (
                    receipt.claim_nonce,
                    receipt_sha256,
                ),
            ).fetchone()
            if conflict is not None:
                connection.execute("COMMIT")
                raise InertFixtureIntentAlreadyClaimed(
                    "fixture intent was already consumed by a receipt collision"
                )
            try:
                connection.execute(
                    """
                    INSERT INTO inert_fixture_intent_claims (
                        intent_id,
                        intent_sha256,
                        payload_sha256,
                        signature_key_id,
                        trust_store_id,
                        trust_store_sha256,
                        worker_instance_id,
                        claim_ledger_id,
                        launch_ledger_id,
                        intent_nonce,
                        claim_id,
                        claim_nonce,
                        claimed_at_unix,
                        receipt_sha256,
                        receipt_json,
                        policy_id,
                        policy_sha256,
                        worker_pool_audience,
                        delegated_root_id,
                        launcher_artifact_id,
                        launcher_artifact_sha256,
                        launcher_seccomp_policy_id,
                        launcher_seccomp_policy_sha256,
                        fixture_protocol_id,
                        resource_profile_id,
                        resource_profile_sha256,
                        binding_sha256
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    (
                        receipt.intent_id,
                        receipt.intent_sha256,
                        receipt.intent_payload_sha256,
                        receipt.signature_key_id,
                        receipt.trust_store_id,
                        receipt.trust_store_sha256,
                        receipt.worker_instance_id,
                        receipt.claim_ledger_id,
                        receipt.launch_ledger_id,
                        receipt.intent_nonce,
                        receipt.claim_id,
                        receipt.claim_nonce,
                        receipt.claimed_at_unix,
                        receipt_sha256,
                        sqlite3.Binary(receipt_json),
                        receipt.policy_id,
                        receipt.policy_sha256,
                        receipt.worker_pool_audience,
                        receipt.delegated_root_id,
                        receipt.launcher_artifact_id,
                        receipt.launcher_artifact_sha256,
                        receipt.launcher_seccomp_policy_id,
                        receipt.launcher_seccomp_policy_sha256,
                        receipt.fixture_protocol_id,
                        receipt.resource_profile_id,
                        receipt.resource_profile_sha256,
                        binding_sha256,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                connection.execute("COMMIT")
                raise InertFixtureIntentAlreadyClaimed(
                    "fixture intent was already consumed by a durable collision"
                ) from exc
            connection.execute("COMMIT")
        except sqlite3.IntegrityError as exc:
            _rollback_sqlite_after_error(connection)
            raise InertFixtureLedgerError(
                "fixture-intent claim violated ledger integrity"
            ) from exc
        except (InertFixtureIntentAlreadyClaimed, InertFixtureLedgerError):
            _rollback_sqlite_after_error(connection)
            raise
        except sqlite3.Error as exc:
            _rollback_sqlite_after_error(connection)
            raise InertFixtureLedgerError(
                "cannot commit fixture-intent claim"
            ) from exc
        finally:
            _close_sqlite_connection(
                connection,
                error_message="cannot close fixture-intent claim ledger",
            )
        return receipt

    def verify_committed_receipt(
        self,
        receipt: InertFixtureIntentClaimReceipt,
    ) -> str:
        """Return the digest of an exact receipt committed in this ledger."""

        if type(receipt) is not InertFixtureIntentClaimReceipt:
            raise InertFixtureLedgerError(
                "fixture-intent claim receipt has the wrong type"
            )
        try:
            frozen_receipt = InertFixtureIntentClaimReceipt.model_validate(
                receipt.model_dump(mode="python"),
                strict=True,
            )
            receipt_sha256 = sha256_json(frozen_receipt)
        except (AttributeError, TypeError, ValueError) as exc:
            raise InertFixtureLedgerError(
                "fixture-intent claim receipt is invalid"
            ) from exc
        if (
            frozen_receipt.worker_instance_id != self.worker_instance_id
            or frozen_receipt.claim_ledger_id != self.ledger_id
        ):
            raise InertFixtureLedgerError(
                "fixture-intent receipt is bound to a different worker or ledger"
            )

        binding_sha256 = _inert_fixture_binding_sha256(frozen_receipt)
        receipt_json = canonical_json_bytes(frozen_receipt)
        expected_row = (
            frozen_receipt.intent_id,
            frozen_receipt.intent_sha256,
            frozen_receipt.intent_payload_sha256,
            frozen_receipt.signature_key_id,
            frozen_receipt.trust_store_id,
            frozen_receipt.trust_store_sha256,
            frozen_receipt.worker_instance_id,
            frozen_receipt.claim_ledger_id,
            frozen_receipt.launch_ledger_id,
            frozen_receipt.intent_nonce,
            frozen_receipt.claim_id,
            frozen_receipt.claim_nonce,
            frozen_receipt.claimed_at_unix,
            receipt_sha256,
            receipt_json,
            frozen_receipt.policy_id,
            frozen_receipt.policy_sha256,
            frozen_receipt.worker_pool_audience,
            frozen_receipt.delegated_root_id,
            frozen_receipt.launcher_artifact_id,
            frozen_receipt.launcher_artifact_sha256,
            frozen_receipt.launcher_seccomp_policy_id,
            frozen_receipt.launcher_seccomp_policy_sha256,
            frozen_receipt.fixture_protocol_id,
            frozen_receipt.resource_profile_id,
            frozen_receipt.resource_profile_sha256,
            binding_sha256,
        )

        connection: sqlite3.Connection | None = None
        try:
            self._validate_database_parent()
            self._validate_database_file()
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
            connection.execute("BEGIN")
            self._validate_schema(connection)
            row = connection.execute(
                """
                SELECT
                    intent_id,
                    intent_sha256,
                    payload_sha256,
                    signature_key_id,
                    trust_store_id,
                    trust_store_sha256,
                    worker_instance_id,
                    claim_ledger_id,
                    launch_ledger_id,
                    intent_nonce,
                    claim_id,
                    claim_nonce,
                    claimed_at_unix,
                    receipt_sha256,
                    receipt_json,
                    policy_id,
                    policy_sha256,
                    worker_pool_audience,
                    delegated_root_id,
                    launcher_artifact_id,
                    launcher_artifact_sha256,
                    launcher_seccomp_policy_id,
                    launcher_seccomp_policy_sha256,
                    fixture_protocol_id,
                    resource_profile_id,
                    resource_profile_sha256,
                    binding_sha256
                FROM inert_fixture_intent_claims
                WHERE intent_id = ?
                """,
                (frozen_receipt.intent_id,),
            ).fetchone()
            connection.execute("COMMIT")
        except InertFixtureLedgerError:
            if connection is not None:
                _rollback_sqlite_after_error(connection)
            raise
        except (OSError, sqlite3.Error) as exc:
            if connection is not None:
                _rollback_sqlite_after_error(connection)
            raise InertFixtureLedgerError(
                "cannot verify committed fixture-intent receipt"
            ) from exc
        finally:
            if connection is not None:
                _close_sqlite_connection(
                    connection,
                    error_message="cannot close fixture-intent claim ledger",
                )

        if row != expected_row:
            raise InertFixtureLedgerError(
                "fixture-intent claim receipt is not committed in this ledger"
            )
        return receipt_sha256

    def recover_committed_receipt(
        self,
        intent: SignedInertFixtureIntent,
        trust_store: InertFixtureIntentTrustStore,
        expectation: InertFixtureIntentExpectation,
    ) -> InertFixtureIntentClaimReceipt:
        """Recover prelaunch evidence after an ambiguous or interrupted commit."""

        verified = _verify_inert_fixture_intent(
            intent,
            trust_store,
            expectation,
            now_unix=_current_unix_time(),
            enforce_validity=False,
        )
        if (
            verified.intent.payload.worker_instance_id != self.worker_instance_id
            or verified.intent.payload.claim_ledger_id != self.ledger_id
            or expectation.claim_ledger_path != self.path
        ):
            raise InertFixtureLedgerError(
                "fixture intent is bound to a different worker or claim ledger"
            )
        payload = verified.intent.payload
        reservation_identity = (
            verified.intent_sha256,
            payload.intent_id,
            verified.payload_sha256,
            verified.intent.key_id,
            verified.trust_store_id,
            verified.trust_store_sha256,
            self.worker_instance_id,
            self.ledger_id,
            payload.launch_ledger_id,
            payload.intent_nonce,
            payload.policy_sha256,
            _inert_fixture_binding_sha256(payload),
        )
        connection: sqlite3.Connection | None = None
        try:
            self._validate_database_parent()
            self._validate_database_file()
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
            connection.execute("BEGIN")
            self._validate_schema(connection)
            row = connection.execute(
                """
                SELECT r.intent_sha256, r.intent_id, r.payload_sha256,
                       r.signature_key_id, r.trust_store_id, r.trust_store_sha256,
                       r.worker_instance_id, r.claim_ledger_id, r.launch_ledger_id,
                       r.intent_nonce, r.policy_sha256, r.binding_sha256,
                       r.reserved_at_unix, c.receipt_json, c.receipt_sha256
                FROM inert_fixture_intent_reservations AS r
                LEFT JOIN inert_fixture_intent_claims AS c
                  ON c.intent_sha256 = r.intent_sha256
                WHERE r.intent_sha256 = ?
                """,
                (verified.intent_sha256,),
            ).fetchone()
            connection.execute("COMMIT")
        except InertFixtureLedgerError:
            if connection is not None:
                _rollback_sqlite_after_error(connection)
            raise
        except (OSError, sqlite3.Error) as exc:
            if connection is not None:
                _rollback_sqlite_after_error(connection)
            raise InertFixtureLedgerError(
                "cannot recover committed fixture-intent receipt"
            ) from exc
        finally:
            if connection is not None:
                _close_sqlite_connection(
                    connection,
                    error_message="cannot close fixture-intent claim ledger",
                )

        if row is None:
            raise InertFixtureLedgerError(
                "no recoverable receipt is committed for this fixture intent"
            )
        if (
            len(row) != 15
            or row[:12] != reservation_identity
            or type(row[12]) is not int
            or not payload.not_before_unix <= row[12] < payload.expires_at_unix
        ):
            raise InertFixtureLedgerError(
                "fixture-intent reservation differs from the authenticated intent"
            )
        if row[13:] == (None, None):
            raise InertFixtureIntentAlreadyClaimed(
                "fixture intent was terminally consumed without a recoverable receipt"
            )
        if type(row[13]) is not bytes or type(row[14]) is not str:
            raise InertFixtureLedgerError(
                "committed fixture-intent reservation has incomplete receipt evidence"
            )
        receipt_json, stored_receipt_sha256 = row[13], row[14]
        try:
            recovered = InertFixtureIntentClaimReceipt.model_validate_json(
                receipt_json,
                strict=True,
            )
            recovered_json = canonical_json_bytes(recovered)
            recovered_sha256 = sha256_json(recovered)
        except (TypeError, ValueError) as exc:
            raise InertFixtureLedgerError(
                "committed fixture-intent receipt bytes are invalid"
            ) from exc
        if (
            recovered_json != receipt_json
            or recovered_sha256 != stored_receipt_sha256
            or recovered.intent_id != verified.intent.payload.intent_id
            or recovered.intent_sha256 != verified.intent_sha256
            or recovered.intent_payload_sha256 != verified.payload_sha256
            or recovered.signature_key_id != verified.intent.key_id
            or recovered.trust_store_id != verified.trust_store_id
            or recovered.trust_store_sha256 != verified.trust_store_sha256
            or not _receipt_mirrors_authenticated_payload(
                recovered,
                verified.intent.payload,
            )
            or _inert_fixture_binding_sha256(recovered)
            != _inert_fixture_binding_sha256(verified.intent.payload)
        ):
            raise InertFixtureLedgerError(
                "committed fixture-intent receipt differs from the authenticated intent"
            )
        if self.verify_committed_receipt(recovered) != recovered_sha256:
            raise InertFixtureLedgerError(
                "recovered fixture-intent receipt failed exact ledger verification"
            )
        return recovered

    def claim_count(self) -> int:
        """Count terminally consumed intent reservations, including tombstones."""

        connection = self._connect()
        try:
            connection.execute("BEGIN")
            self._validate_schema(connection)
            row = connection.execute(
                "SELECT COUNT(*) FROM inert_fixture_intent_reservations"
            ).fetchone()
            connection.execute("COMMIT")
        except InertFixtureLedgerError:
            _rollback_sqlite_after_error(connection)
            raise
        except sqlite3.Error as exc:
            _rollback_sqlite_after_error(connection)
            raise InertFixtureLedgerError(
                "cannot inspect fixture-intent claim ledger"
            ) from exc
        finally:
            _close_sqlite_connection(
                connection,
                error_message="cannot close fixture-intent claim ledger",
            )
        if row is None or type(row[0]) is not int:
            raise InertFixtureLedgerError(
                "fixture-intent claim ledger returned an invalid count"
            )
        return row[0]


def admit_inert_fixture_intent(
    intent: SignedInertFixtureIntent,
    trust_store: InertFixtureIntentTrustStore,
    expectation: InertFixtureIntentExpectation,
    *,
    ledger: InertFixtureIntentLedger,
    claim_id: str,
) -> InertFixtureIntentClaimReceipt:
    """Verify first, then durably consume one intent without launching anything."""

    verification_time = _current_unix_time()
    _verify_inert_fixture_intent(
        intent,
        trust_store,
        expectation,
        now_unix=verification_time,
        enforce_validity=True,
    )
    if type(ledger) is not InertFixtureIntentLedger:
        raise InertFixtureLedgerError(
            "fixture admission requires its configured claim-ledger type"
        )
    if (
        ledger.path != expectation.claim_ledger_path
        or ledger.ledger_id != expectation.claim_ledger_id
        or ledger.worker_instance_id != expectation.worker_instance_id
    ):
        raise InertFixtureLedgerError(
            "fixture admission received a different configured claim ledger"
        )
    return ledger.claim_intent(
        intent,
        trust_store,
        expectation,
        claim_id=claim_id,
    )


JSON_SCHEMAS: dict[str, type[BaseModel]] = {
    "inert-fixture-policy-v1.json": InertFixturePolicy,
    "inert-fixture-intent-payload-v1.json": InertFixtureIntentPayload,
    "signed-inert-fixture-intent-v1.json": SignedInertFixtureIntent,
    "inert-fixture-intent-trust-store-v1.json": InertFixtureIntentTrustStore,
    "inert-fixture-intent-claim-receipt-v1.json": InertFixtureIntentClaimReceipt,
}


__all__ = [
    "INERT_FIXTURE_INTENT_SIGNING_DOMAIN",
    "JSON_SCHEMAS",
    "MAX_INERT_FIXTURE_INTENT_LIFETIME_SECONDS",
    "InertFixtureAuthorizationError",
    "InertFixtureExpectationError",
    "InertFixtureIntentAlreadyClaimed",
    "InertFixtureIntentClaimReceipt",
    "InertFixtureIntentError",
    "InertFixtureIntentExpectation",
    "InertFixtureIntentLedger",
    "InertFixtureIntentPayload",
    "InertFixtureIntentTrustKey",
    "InertFixtureIntentTrustStore",
    "InertFixtureLedgerError",
    "InertFixturePolicy",
    "SignedInertFixtureIntent",
    "VerifiedInertFixtureIntent",
    "admit_inert_fixture_intent",
    "inert_fixture_intent_expectation_for",
    "inert_fixture_intent_signing_bytes",
    "verify_inert_fixture_intent",
]
