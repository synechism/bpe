"""Process-free one-shot launch-attempt admission for the fixed inert fixture.

This module consumes a launch attempt; it does not authorize or perform a launch.  The
original signed intent, its complete trusted expectation, and the exact committed claim
receipt remain mandatory inputs.  No launcher path, executable, command, argv, environment,
job, candidate, cgroup descriptor, or native runtime surface is accepted here.
"""

from __future__ import annotations

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

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from bpe.canonical import canonical_json_bytes, sha256_json
from bpe.inert_fixture import (
    InertFixtureIntentClaimReceipt,
    InertFixtureIntentError,
    InertFixtureIntentExpectation,
    InertFixtureIntentLedger,
    InertFixtureIntentTrustStore,
    SignedInertFixtureIntent,
    inert_fixture_intent_expectation_for,
    verify_inert_fixture_intent,
)
from bpe.models import Sha256, StableId

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_STABLE_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/@:+-]{0,127}$")
_LEDGER_APPLICATION_ID = 0x42504533
_LEDGER_USER_VERSION = 2

_CREATE_LAUNCH_RESERVATIONS = """
CREATE TABLE inert_fixture_launch_reservations (
    claim_receipt_sha256 TEXT PRIMARY KEY,
    intent_id TEXT NOT NULL UNIQUE,
    intent_sha256 TEXT NOT NULL UNIQUE,
    payload_sha256 TEXT NOT NULL,
    intent_nonce TEXT NOT NULL UNIQUE,
    claim_id TEXT NOT NULL UNIQUE,
    claim_nonce TEXT NOT NULL UNIQUE,
    claimed_at_unix INTEGER NOT NULL,
    trust_store_sha256 TEXT NOT NULL,
    worker_instance_id TEXT NOT NULL,
    claim_ledger_id TEXT NOT NULL,
    launch_ledger_id TEXT NOT NULL,
    policy_sha256 TEXT NOT NULL,
    binding_sha256 TEXT NOT NULL,
    reserved_at_unix INTEGER NOT NULL,
    UNIQUE(
        claim_receipt_sha256,
        intent_id,
        intent_sha256,
        payload_sha256,
        intent_nonce,
        claim_id,
        claim_nonce,
        claimed_at_unix,
        trust_store_sha256,
        worker_instance_id,
        claim_ledger_id,
        launch_ledger_id,
        policy_sha256,
        binding_sha256,
        reserved_at_unix
    ),
    CHECK(length(claim_receipt_sha256) = 64),
    CHECK(length(intent_sha256) = 64),
    CHECK(length(payload_sha256) = 64),
    CHECK(length(intent_nonce) = 64),
    CHECK(length(claim_id) = 64),
    CHECK(length(claim_nonce) = 64),
    CHECK(length(trust_store_sha256) = 64),
    CHECK(length(policy_sha256) = 64),
    CHECK(length(binding_sha256) = 64),
    CHECK(claimed_at_unix >= 0),
    CHECK(reserved_at_unix >= claimed_at_unix)
) WITHOUT ROWID
"""

_CREATE_LAUNCH_ATTEMPTS = """
CREATE TABLE inert_fixture_launch_attempts (
    intent_id TEXT PRIMARY KEY,
    intent_sha256 TEXT NOT NULL UNIQUE,
    payload_sha256 TEXT NOT NULL,
    intent_nonce TEXT NOT NULL UNIQUE,
    claim_receipt_sha256 TEXT NOT NULL UNIQUE,
    claim_id TEXT NOT NULL UNIQUE,
    claim_nonce TEXT NOT NULL UNIQUE,
    claimed_at_unix INTEGER NOT NULL,
    trust_store_sha256 TEXT NOT NULL,
    worker_instance_id TEXT NOT NULL,
    claim_ledger_id TEXT NOT NULL,
    launch_ledger_id TEXT NOT NULL,
    launch_attempt_id TEXT NOT NULL UNIQUE,
    launch_attempt_nonce TEXT NOT NULL UNIQUE,
    consumed_at_unix INTEGER NOT NULL,
    receipt_sha256 TEXT NOT NULL UNIQUE,
    receipt_json BLOB NOT NULL,
    policy_sha256 TEXT NOT NULL,
    binding_sha256 TEXT NOT NULL,
    UNIQUE(intent_id, claim_receipt_sha256),
    FOREIGN KEY (
        claim_receipt_sha256,
        intent_id,
        intent_sha256,
        payload_sha256,
        intent_nonce,
        claim_id,
        claim_nonce,
        claimed_at_unix,
        trust_store_sha256,
        worker_instance_id,
        claim_ledger_id,
        launch_ledger_id,
        policy_sha256,
        binding_sha256,
        consumed_at_unix
    ) REFERENCES inert_fixture_launch_reservations (
        claim_receipt_sha256,
        intent_id,
        intent_sha256,
        payload_sha256,
        intent_nonce,
        claim_id,
        claim_nonce,
        claimed_at_unix,
        trust_store_sha256,
        worker_instance_id,
        claim_ledger_id,
        launch_ledger_id,
        policy_sha256,
        binding_sha256,
        reserved_at_unix
    ),
    CHECK(length(intent_sha256) = 64),
    CHECK(length(payload_sha256) = 64),
    CHECK(length(intent_nonce) = 64),
    CHECK(length(claim_receipt_sha256) = 64),
    CHECK(length(claim_id) = 64),
    CHECK(length(claim_nonce) = 64),
    CHECK(length(trust_store_sha256) = 64),
    CHECK(length(launch_attempt_id) = 64),
    CHECK(length(launch_attempt_nonce) = 64),
    CHECK(length(receipt_sha256) = 64),
    CHECK(typeof(receipt_json) = 'blob'),
    CHECK(length(receipt_json) BETWEEN 1 AND 32768),
    CHECK(length(policy_sha256) = 64),
    CHECK(length(binding_sha256) = 64),
    CHECK(claimed_at_unix >= 0),
    CHECK(consumed_at_unix >= claimed_at_unix)
) WITHOUT ROWID
"""

_CREATE_LAUNCH_STATE = """
CREATE TABLE inert_fixture_launch_state (
    singleton INTEGER PRIMARY KEY,
    worker_instance_id TEXT NOT NULL,
    claim_ledger_id TEXT NOT NULL,
    launch_ledger_id TEXT NOT NULL,
    clock_high_water_unix INTEGER NOT NULL,
    CHECK(singleton = 1),
    CHECK(length(worker_instance_id) BETWEEN 1 AND 128),
    CHECK(length(claim_ledger_id) BETWEEN 1 AND 128),
    CHECK(length(launch_ledger_id) BETWEEN 1 AND 128),
    CHECK(claim_ledger_id != launch_ledger_id),
    CHECK(clock_high_water_unix >= 0)
) WITHOUT ROWID
"""


class InertFixtureLaunchError(ValueError):
    """A fixed-fixture launch-attempt input or durable consumption failed closed."""


class InertFixtureLaunchAuthorizationError(InertFixtureLaunchError):
    """The original intent, claim, trust role, or local binding is invalid."""


class InertFixtureLaunchExpectationError(InertFixtureLaunchError):
    """Trusted local launch-attempt inputs cannot form an exact expectation."""


class InertFixtureLaunchLedgerError(InertFixtureLaunchError):
    """The independent durable launch-attempt ledger is unavailable or unsafe."""


class InertFixtureLaunchAttemptAlreadyConsumed(InertFixtureLaunchLedgerError):
    """The intent, claim, or launch-attempt identity was already consumed."""


class _InertLaunchModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        allow_inf_nan=False,
        revalidate_instances="always",
        strict=True,
    )


@dataclass(frozen=True)
class InertFixtureLaunchExpectation:
    """Trusted local launch bindings retaining the complete intent expectation."""

    intent_expectation: InertFixtureIntentExpectation
    launch_ledger_path: Path
    worker_instance_id: str
    claim_ledger_id: str
    launch_ledger_id: str


@dataclass(frozen=True)
class VerifiedInertFixtureLaunchAttempt:
    intent: SignedInertFixtureIntent
    claim_receipt: InertFixtureIntentClaimReceipt
    intent_sha256: str
    payload_sha256: str
    trust_store_id: str
    trust_store_sha256: str
    claim_receipt_sha256: str
    verified_at_unix: int


class InertFixtureLaunchAttemptReceipt(_InertLaunchModel):
    """Exact evidence that one launch attempt was consumed and no process was started."""

    schema_version: Literal["bpe.inert-fixture-launch-attempt-receipt.v1"]
    status: Literal["launch_attempt_consumed_not_started"]
    claim_receipt: InertFixtureIntentClaimReceipt
    claim_receipt_sha256: Sha256
    launch_attempt_id: Sha256
    launch_attempt_nonce: Sha256
    launch_attempt_consumed_at_unix: Annotated[int, Field(ge=0)]
    worker_instance_id: StableId
    claim_ledger_id: StableId
    launch_ledger_id: StableId
    original_intent_reauthenticated: Literal[True]
    exact_claim_receipt_committed: Literal[True]
    serialized_worker_clock_verified: Literal[True]
    separate_launch_ledger_used: Literal[True]
    launch_attempt_consumed: Literal[True]
    retry_permitted: Literal[False]
    launch_authorized: Literal[False]
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
        "original_intent_reauthenticated",
        "exact_claim_receipt_committed",
        "serialized_worker_clock_verified",
        "separate_launch_ledger_used",
        "launch_attempt_consumed",
        mode="before",
    )
    @classmethod
    def evidence_claims_must_be_boolean_true(cls, value: object) -> object:
        if value is not True:
            raise ValueError("launch-attempt evidence claims must be boolean true")
        return value

    @field_validator(
        "retry_permitted",
        "launch_authorized",
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
            raise ValueError(
                "launch-attempt admission cannot claim launch, execution, or authority"
            )
        return value

    @model_validator(mode="after")
    def claim_and_attempt_are_exact(self) -> Self:
        if type(self.claim_receipt) is not InertFixtureIntentClaimReceipt:
            raise ValueError("launch-attempt evidence requires the dedicated claim receipt type")
        if self.claim_receipt_sha256 != sha256_json(self.claim_receipt):
            raise ValueError("launch-attempt claim-receipt digest is inconsistent")
        if self.launch_attempt_id == "0" * 64 or self.launch_attempt_nonce == "0" * 64:
            raise ValueError("launch-attempt identities cannot use all-zero placeholders")
        if (
            self.worker_instance_id,
            self.claim_ledger_id,
            self.launch_ledger_id,
        ) != (
            self.claim_receipt.worker_instance_id,
            self.claim_receipt.claim_ledger_id,
            self.claim_receipt.launch_ledger_id,
        ):
            raise ValueError("launch-attempt evidence differs from the committed claim identity")
        if self.claim_ledger_id == self.launch_ledger_id:
            raise ValueError("claim and launch ledgers must have distinct identities")
        if not (
            self.claim_receipt.claimed_at_unix
            <= self.launch_attempt_consumed_at_unix
            < self.claim_receipt.intent_expires_at_unix
        ):
            raise ValueError("launch attempt is outside the authenticated claim interval")
        return self


def _current_unix_time() -> int:
    return time.time_ns() // 1_000_000_000


def _new_launch_attempt_nonce() -> str:
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
    active_error = sys.exception()
    try:
        connection.close()
    except sqlite3.Error as exc:
        if active_error is None:
            raise InertFixtureLaunchLedgerError(error_message) from exc


def _normalized_intent_expectation(
    expectation: InertFixtureIntentExpectation,
) -> InertFixtureIntentExpectation:
    if type(expectation) is not InertFixtureIntentExpectation:
        raise InertFixtureLaunchExpectationError(
            "launch attempt requires the complete dedicated intent expectation"
        )
    try:
        normalized = inert_fixture_intent_expectation_for(
            expectation.policy,
            expected_policy_sha256=expectation.policy_sha256,
            expected_worker_pool_audience=expectation.worker_pool_audience,
            expected_worker_instance_id=expectation.worker_instance_id,
            expected_claim_ledger_id=expectation.claim_ledger_id,
            expected_claim_ledger_path=expectation.claim_ledger_path,
            expected_launch_ledger_id=expectation.launch_ledger_id,
            expected_delegated_root_id=expectation.delegated_root_id,
            expected_launcher_artifact_id=expectation.launcher_artifact_id,
            expected_launcher_artifact_sha256=expectation.launcher_artifact_sha256,
            expected_launcher_seccomp_policy_id=expectation.launcher_seccomp_policy_id,
            expected_launcher_seccomp_policy_sha256=(
                expectation.launcher_seccomp_policy_sha256
            ),
        )
    except (AttributeError, InertFixtureIntentError, OSError, TypeError, ValueError) as exc:
        raise InertFixtureLaunchExpectationError(
            "launch-attempt intent expectation is invalid"
        ) from exc
    if normalized != expectation:
        raise InertFixtureLaunchExpectationError(
            "launch-attempt intent expectation differs from its complete policy"
        )
    return normalized


def _validate_launch_ledger_path(path: Path) -> Path:
    if type(path) is not type(Path()):
        raise InertFixtureLaunchExpectationError("launch-ledger path must be an exact Path")
    try:
        encoded = os.fsencode(path)
        if b"\x00" in encoded:
            raise ValueError("NUL")
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise ValueError("noncanonical")
    except (OSError, RuntimeError, TypeError, UnicodeError, ValueError) as exc:
        raise InertFixtureLaunchExpectationError(
            "launch-ledger path must be existing, absolute, and canonical"
        ) from exc
    return Path(os.fspath(path))


def _validate_launch_expectation(
    expectation: InertFixtureLaunchExpectation,
) -> InertFixtureLaunchExpectation:
    if type(expectation) is not InertFixtureLaunchExpectation:
        raise InertFixtureLaunchExpectationError("launch expectation has the wrong type")
    intent_expectation = _normalized_intent_expectation(expectation.intent_expectation)
    launch_path = _validate_launch_ledger_path(expectation.launch_ledger_path)
    if launch_path == intent_expectation.claim_ledger_path:
        raise InertFixtureLaunchExpectationError(
            "claim and launch ledgers must use distinct canonical paths"
        )
    identity = (
        expectation.worker_instance_id,
        expectation.claim_ledger_id,
        expectation.launch_ledger_id,
    )
    if any(type(value) is not str or not _STABLE_ID.fullmatch(value) for value in identity):
        raise InertFixtureLaunchExpectationError("launch expectation identity is invalid")
    if identity != (
        intent_expectation.worker_instance_id,
        intent_expectation.claim_ledger_id,
        intent_expectation.launch_ledger_id,
    ):
        raise InertFixtureLaunchExpectationError(
            "launch expectation differs from the complete intent expectation"
        )
    if expectation.claim_ledger_id == expectation.launch_ledger_id:
        raise InertFixtureLaunchExpectationError(
            "claim and launch ledgers must have distinct identities"
        )
    return InertFixtureLaunchExpectation(
        intent_expectation=intent_expectation,
        launch_ledger_path=launch_path,
        worker_instance_id=expectation.worker_instance_id,
        claim_ledger_id=expectation.claim_ledger_id,
        launch_ledger_id=expectation.launch_ledger_id,
    )


def inert_fixture_launch_expectation_for(
    intent_expectation: InertFixtureIntentExpectation,
    *,
    expected_launch_ledger_path: Path,
    expected_worker_instance_id: str,
    expected_claim_ledger_id: str,
    expected_launch_ledger_id: str,
) -> InertFixtureLaunchExpectation:
    """Retain the full trusted intent expectation and anchor the launch-ledger path."""

    expectation = InertFixtureLaunchExpectation(
        intent_expectation=_normalized_intent_expectation(intent_expectation),
        launch_ledger_path=expected_launch_ledger_path,
        worker_instance_id=expected_worker_instance_id,
        claim_ledger_id=expected_claim_ledger_id,
        launch_ledger_id=expected_launch_ledger_id,
    )
    return _validate_launch_expectation(expectation)


def _normalize_claim_receipt(
    receipt: InertFixtureIntentClaimReceipt,
) -> InertFixtureIntentClaimReceipt:
    if type(receipt) is not InertFixtureIntentClaimReceipt:
        raise InertFixtureLaunchAuthorizationError(
            "launch attempt requires the dedicated claim receipt type"
        )
    try:
        return InertFixtureIntentClaimReceipt.model_validate(
            receipt.model_dump(mode="python"),
            strict=True,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise InertFixtureLaunchAuthorizationError(
            "launch-attempt claim receipt is invalid"
        ) from exc


def _authenticate_launch_inputs(
    intent: SignedInertFixtureIntent,
    trust_store: InertFixtureIntentTrustStore,
    expectation: InertFixtureLaunchExpectation,
    claim_receipt: InertFixtureIntentClaimReceipt,
    claim_ledger: InertFixtureIntentLedger,
    *,
    now_unix: int,
    enforce_validity: bool,
) -> VerifiedInertFixtureLaunchAttempt:
    if type(now_unix) is not int or now_unix < 0:
        raise InertFixtureLaunchAuthorizationError(
            "launch-attempt verification time must be a nonnegative integer"
        )
    if type(intent) is not SignedInertFixtureIntent:
        raise InertFixtureLaunchAuthorizationError("launch attempt has the wrong intent type")
    if type(trust_store) is not InertFixtureIntentTrustStore:
        raise InertFixtureLaunchAuthorizationError(
            "launch attempt has the wrong intent trust-store role"
        )
    if type(claim_ledger) is not InertFixtureIntentLedger:
        raise InertFixtureLaunchAuthorizationError(
            "launch attempt requires the configured intent-claim ledger"
        )
    try:
        frozen_expectation = _validate_launch_expectation(expectation)
        frozen_claim = _normalize_claim_receipt(claim_receipt)
        frozen_intent = SignedInertFixtureIntent.model_validate(
            intent.model_dump(mode="python"),
            strict=True,
        )
        frozen_store = InertFixtureIntentTrustStore.model_validate(
            trust_store.model_dump(mode="python"),
            strict=True,
        )
    except (AttributeError, InertFixtureLaunchError, TypeError, ValueError) as exc:
        if isinstance(exc, InertFixtureLaunchAuthorizationError):
            raise
        raise InertFixtureLaunchAuthorizationError(
            "launch-attempt authentication inputs are invalid"
        ) from exc

    intent_expectation = frozen_expectation.intent_expectation
    if (
        claim_ledger.path != intent_expectation.claim_ledger_path
        or claim_ledger.ledger_id != frozen_expectation.claim_ledger_id
        or claim_ledger.worker_instance_id != frozen_expectation.worker_instance_id
    ):
        raise InertFixtureLaunchAuthorizationError(
            "launch attempt received a different configured claim ledger"
        )

    try:
        if enforce_validity:
            verified_intent = verify_inert_fixture_intent(
                frozen_intent,
                frozen_store,
                intent_expectation,
                now_unix=now_unix,
            )
        recovered_claim = claim_ledger.recover_committed_receipt(
            frozen_intent,
            frozen_store,
            intent_expectation,
        )
    except InertFixtureIntentError as exc:
        raise InertFixtureLaunchAuthorizationError(
            "launch attempt failed original intent or committed-claim authentication"
        ) from exc

    if recovered_claim != frozen_claim:
        raise InertFixtureLaunchAuthorizationError(
            "launch attempt requires the exact authenticated committed claim receipt"
        )
    payload = frozen_intent.payload
    if (
        payload.worker_instance_id,
        payload.claim_ledger_id,
        payload.launch_ledger_id,
    ) != (
        frozen_expectation.worker_instance_id,
        frozen_expectation.claim_ledger_id,
        frozen_expectation.launch_ledger_id,
    ):
        raise InertFixtureLaunchAuthorizationError(
            "launch-attempt worker or ledger binding differs"
        )
    if enforce_validity and now_unix < frozen_claim.claimed_at_unix:
        raise InertFixtureLaunchAuthorizationError(
            "launch-attempt clock is earlier than the committed claim"
        )

    intent_sha256 = sha256_json(frozen_intent)
    payload_sha256 = sha256_json(payload)
    trust_store_sha256 = sha256_json(frozen_store)
    if enforce_validity:
        if (
            verified_intent.intent_sha256 != intent_sha256
            or verified_intent.payload_sha256 != payload_sha256
            or verified_intent.trust_store_sha256 != trust_store_sha256
        ):
            raise InertFixtureLaunchAuthorizationError(
                "launch-attempt intent verification provenance differs"
            )
        trust_store_id = verified_intent.trust_store_id
    else:
        trust_store_id = frozen_store.trust_store_id
    return VerifiedInertFixtureLaunchAttempt(
        intent=frozen_intent,
        claim_receipt=frozen_claim,
        intent_sha256=intent_sha256,
        payload_sha256=payload_sha256,
        trust_store_id=trust_store_id,
        trust_store_sha256=trust_store_sha256,
        claim_receipt_sha256=sha256_json(frozen_claim),
        verified_at_unix=now_unix,
    )


def verify_inert_fixture_launch_attempt(
    intent: SignedInertFixtureIntent,
    trust_store: InertFixtureIntentTrustStore,
    expectation: InertFixtureLaunchExpectation,
    claim_receipt: InertFixtureIntentClaimReceipt,
    claim_ledger: InertFixtureIntentLedger,
    *,
    now_unix: int,
) -> VerifiedInertFixtureLaunchAttempt:
    """Reauthenticate a currently valid intent and its exact committed claim."""

    return _authenticate_launch_inputs(
        intent,
        trust_store,
        expectation,
        claim_receipt,
        claim_ledger,
        now_unix=now_unix,
        enforce_validity=True,
    )


def _launch_binding_sha256(
    claim_receipt: InertFixtureIntentClaimReceipt,
    *,
    claim_receipt_sha256: str,
    worker_instance_id: str,
    claim_ledger_id: str,
    launch_ledger_id: str,
) -> str:
    return sha256_json(
        {
            "schema_version": "bpe.inert-fixture-launch-binding.v1",
            "intent_id": claim_receipt.intent_id,
            "intent_sha256": claim_receipt.intent_sha256,
            "intent_nonce": claim_receipt.intent_nonce,
            "claim_receipt_sha256": claim_receipt_sha256,
            "claim_id": claim_receipt.claim_id,
            "claim_nonce": claim_receipt.claim_nonce,
            "policy_sha256": claim_receipt.policy_sha256,
            "worker_instance_id": worker_instance_id,
            "claim_ledger_id": claim_ledger_id,
            "launch_ledger_id": launch_ledger_id,
            "maximum_launch_attempts": claim_receipt.maximum_launch_attempts,
            "retry_permitted": claim_receipt.retry_permitted,
        }
    )


class InertFixtureLaunchLedger:
    """Independent durable one-shot ledger for fixed-fixture launch attempts."""

    path: Path
    ledger_id: str
    worker_instance_id: str
    claim_ledger_id: str

    def __init__(
        self,
        path: Path,
        *,
        ledger_id: str,
        worker_instance_id: str,
        claim_ledger_id: str,
    ) -> None:
        self._configure_identity(
            path,
            ledger_id=ledger_id,
            worker_instance_id=worker_instance_id,
            claim_ledger_id=claim_ledger_id,
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
        claim_ledger_id: str,
    ) -> InertFixtureLaunchLedger:
        """Create one new configured launch ledger without replacing an existing path."""

        instance = cls.__new__(cls)
        instance._configure_identity(
            path,
            ledger_id=ledger_id,
            worker_instance_id=worker_instance_id,
            claim_ledger_id=claim_ledger_id,
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
        claim_ledger_id: str,
    ) -> None:
        if type(path) is not type(Path()):
            raise InertFixtureLaunchLedgerError("launch-attempt ledger path must be a Path")
        try:
            encoded_path = os.fsencode(path)
        except UnicodeError as exc:
            raise InertFixtureLaunchLedgerError(
                "launch-attempt ledger path is not filesystem-encodable"
            ) from exc
        if b"\x00" in encoded_path:
            raise InertFixtureLaunchLedgerError(
                "launch-attempt ledger path contains a NUL byte"
            )
        identities = (ledger_id, worker_instance_id, claim_ledger_id)
        if any(type(value) is not str or not _STABLE_ID.fullmatch(value) for value in identities):
            raise InertFixtureLaunchLedgerError("launch-attempt ledger identity is invalid")
        if ledger_id == claim_ledger_id:
            raise InertFixtureLaunchLedgerError(
                "claim and launch ledgers must have distinct identities"
            )
        self.path = Path(os.fspath(path))
        self.ledger_id = ledger_id
        self.worker_instance_id = worker_instance_id
        self.claim_ledger_id = claim_ledger_id

    def _initialize_or_validate(self, *, require_empty: bool) -> None:
        connection = self._connect()
        try:
            try:
                connection.execute("BEGIN IMMEDIATE")
                objects = connection.execute("SELECT type, name FROM sqlite_schema").fetchall()
                if require_empty:
                    if objects:
                        raise InertFixtureLaunchLedgerError(
                            "new launch-attempt ledger is not empty"
                        )
                    connection.execute(_CREATE_LAUNCH_RESERVATIONS)
                    connection.execute(_CREATE_LAUNCH_ATTEMPTS)
                    connection.execute(_CREATE_LAUNCH_STATE)
                    connection.execute(
                        "INSERT INTO inert_fixture_launch_state "
                        "(singleton, worker_instance_id, claim_ledger_id, launch_ledger_id, "
                        "clock_high_water_unix) VALUES (1, ?, ?, ?, 0)",
                        (self.worker_instance_id, self.claim_ledger_id, self.ledger_id),
                    )
                    connection.execute(f"PRAGMA application_id={_LEDGER_APPLICATION_ID}")
                    connection.execute(f"PRAGMA user_version={_LEDGER_USER_VERSION}")
                elif not objects:
                    raise InertFixtureLaunchLedgerError(
                        "launch-attempt ledger is unprovisioned or empty"
                    )
                connection.execute("COMMIT")
                connection.execute("BEGIN")
                self._validate_schema(connection)
                connection.execute("COMMIT")
            except BaseException:
                _rollback_sqlite_after_error(connection)
                raise
        except InertFixtureLaunchLedgerError:
            raise
        except sqlite3.Error as exc:
            raise InertFixtureLaunchLedgerError(
                "cannot initialize launch-attempt ledger"
            ) from exc
        finally:
            _close_sqlite_connection(
                connection,
                error_message="cannot close launch-attempt ledger",
            )

    def _validate_database_parent(self) -> None:
        if not self.path.is_absolute() or self.path.name in {"", ".", ".."}:
            raise InertFixtureLaunchLedgerError("launch-attempt ledger path must be absolute")
        parent = self.path.parent
        try:
            parent_stat = parent.lstat()
            resolved_parent = parent.resolve(strict=True)
        except (OSError, RuntimeError, ValueError) as exc:
            raise InertFixtureLaunchLedgerError(
                "cannot inspect launch-attempt ledger parent"
            ) from exc
        if (
            resolved_parent != parent
            or stat.S_ISLNK(parent_stat.st_mode)
            or not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_uid != os.geteuid()
            or parent_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise InertFixtureLaunchLedgerError(
                "launch-attempt ledger parent must be caller-owned, private, and non-symlinked"
            )
        for ancestor in parent.parents:
            try:
                ancestor_stat = ancestor.lstat()
            except OSError as exc:
                raise InertFixtureLaunchLedgerError(
                    "cannot inspect a launch-attempt ledger ancestor"
                ) from exc
            writable_by_others = ancestor_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            if (
                stat.S_ISLNK(ancestor_stat.st_mode)
                or not stat.S_ISDIR(ancestor_stat.st_mode)
                or ancestor_stat.st_uid not in {0, os.geteuid()}
                or (writable_by_others and not ancestor_stat.st_mode & stat.S_ISVTX)
            ):
                raise InertFixtureLaunchLedgerError(
                    "launch-attempt ledger ancestors must be trusted and rename-safe"
                )

    def _create_database_file(self) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        for name in ("O_NOFOLLOW", "O_CLOEXEC"):
            if not hasattr(os, name):
                raise InertFixtureLaunchLedgerError(
                    "secure launch-attempt ledger creation is unavailable"
                )
            flags |= getattr(os, name)
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except FileExistsError as exc:
            raise InertFixtureLaunchLedgerError(
                "launch-attempt ledger path is already provisioned"
            ) from exc
        except OSError as exc:
            raise InertFixtureLaunchLedgerError(
                "cannot create launch-attempt ledger"
            ) from exc
        try:
            os.fsync(descriptor)
        except OSError as exc:
            with suppress(OSError):
                os.close(descriptor)
            raise InertFixtureLaunchLedgerError(
                "cannot durably create launch-attempt ledger file"
            ) from exc
        try:
            os.close(descriptor)
        except OSError as exc:
            raise InertFixtureLaunchLedgerError(
                "cannot close new launch-attempt ledger file"
            ) from exc
        self._validate_database_file()
        try:
            parent_fd = os.open(
                self.path.parent,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        except OSError as exc:
            raise InertFixtureLaunchLedgerError(
                "cannot durably create launch-attempt ledger"
            ) from exc

    def _validate_database_file(self) -> None:
        try:
            database_stat = self.path.lstat()
        except OSError as exc:
            raise InertFixtureLaunchLedgerError(
                "cannot inspect launch-attempt ledger"
            ) from exc
        if (
            stat.S_ISLNK(database_stat.st_mode)
            or not stat.S_ISREG(database_stat.st_mode)
            or database_stat.st_uid != os.geteuid()
            or database_stat.st_nlink != 1
            or stat.S_IMODE(database_stat.st_mode) != 0o600
        ):
            raise InertFixtureLaunchLedgerError(
                "launch-attempt ledger must be caller-owned, mode 0600, and regular"
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
                raise InertFixtureLaunchLedgerError(
                    "launch-attempt ledger safety settings were not applied"
                )
            return connection
        except InertFixtureLaunchLedgerError:
            if connection is not None:
                with suppress(sqlite3.Error):
                    connection.close()
            raise
        except sqlite3.Error as exc:
            if connection is not None:
                with suppress(sqlite3.Error):
                    connection.close()
            raise InertFixtureLaunchLedgerError(
                "cannot open launch-attempt ledger"
            ) from exc

    def _validate_schema(self, connection: sqlite3.Connection) -> None:
        if not connection.in_transaction:
            raise InertFixtureLaunchLedgerError(
                "launch-attempt schema validation requires one database snapshot"
            )
        try:
            integrity_check = connection.execute("PRAGMA integrity_check").fetchall()
            foreign_key_check = connection.execute("PRAGMA foreign_key_check").fetchall()
            application_id = connection.execute("PRAGMA application_id").fetchone()
            user_version = connection.execute("PRAGMA user_version").fetchone()
            objects = connection.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name"
            ).fetchall()
            table_sql = connection.execute(
                "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?",
                ("inert_fixture_launch_attempts",),
            ).fetchone()
            reservation_sql = connection.execute(
                "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?",
                ("inert_fixture_launch_reservations",),
            ).fetchone()
            state_sql = connection.execute(
                "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?",
                ("inert_fixture_launch_state",),
            ).fetchone()
            columns = connection.execute(
                "PRAGMA table_info(inert_fixture_launch_attempts)"
            ).fetchall()
            reservation_columns = connection.execute(
                "PRAGMA table_info(inert_fixture_launch_reservations)"
            ).fetchall()
            state_columns = connection.execute(
                "PRAGMA table_info(inert_fixture_launch_state)"
            ).fetchall()
            state_rows = connection.execute(
                "SELECT singleton, worker_instance_id, claim_ledger_id, launch_ledger_id, "
                "clock_high_water_unix FROM inert_fixture_launch_state"
            ).fetchall()
            maximum_consumed_at = connection.execute(
                "SELECT MAX(consumed_at_unix) FROM inert_fixture_launch_attempts"
            ).fetchone()
            maximum_reserved_at = connection.execute(
                "SELECT MAX(reserved_at_unix) FROM inert_fixture_launch_reservations"
            ).fetchone()
            index_rows = connection.execute(
                "PRAGMA index_list(inert_fixture_launch_attempts)"
            ).fetchall()
            reservation_index_rows = connection.execute(
                "PRAGMA index_list(inert_fixture_launch_reservations)"
            ).fetchall()
            state_index_rows = connection.execute(
                "PRAGMA index_list(inert_fixture_launch_state)"
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
                "PRAGMA foreign_key_list(inert_fixture_launch_attempts)"
            ).fetchall()
            reservation_foreign_keys = connection.execute(
                "PRAGMA foreign_key_list(inert_fixture_launch_reservations)"
            ).fetchall()
        except sqlite3.Error as exc:
            raise InertFixtureLaunchLedgerError(
                "launch-attempt ledger schema is not trusted"
            ) from exc

        expected_columns = (
            (0, "intent_id", "TEXT", 1, None, 1),
            (1, "intent_sha256", "TEXT", 1, None, 0),
            (2, "payload_sha256", "TEXT", 1, None, 0),
            (3, "intent_nonce", "TEXT", 1, None, 0),
            (4, "claim_receipt_sha256", "TEXT", 1, None, 0),
            (5, "claim_id", "TEXT", 1, None, 0),
            (6, "claim_nonce", "TEXT", 1, None, 0),
            (7, "claimed_at_unix", "INTEGER", 1, None, 0),
            (8, "trust_store_sha256", "TEXT", 1, None, 0),
            (9, "worker_instance_id", "TEXT", 1, None, 0),
            (10, "claim_ledger_id", "TEXT", 1, None, 0),
            (11, "launch_ledger_id", "TEXT", 1, None, 0),
            (12, "launch_attempt_id", "TEXT", 1, None, 0),
            (13, "launch_attempt_nonce", "TEXT", 1, None, 0),
            (14, "consumed_at_unix", "INTEGER", 1, None, 0),
            (15, "receipt_sha256", "TEXT", 1, None, 0),
            (16, "receipt_json", "BLOB", 1, None, 0),
            (17, "policy_sha256", "TEXT", 1, None, 0),
            (18, "binding_sha256", "TEXT", 1, None, 0),
        )
        expected_reservation_columns = (
            (0, "claim_receipt_sha256", "TEXT", 1, None, 1),
            (1, "intent_id", "TEXT", 1, None, 0),
            (2, "intent_sha256", "TEXT", 1, None, 0),
            (3, "payload_sha256", "TEXT", 1, None, 0),
            (4, "intent_nonce", "TEXT", 1, None, 0),
            (5, "claim_id", "TEXT", 1, None, 0),
            (6, "claim_nonce", "TEXT", 1, None, 0),
            (7, "claimed_at_unix", "INTEGER", 1, None, 0),
            (8, "trust_store_sha256", "TEXT", 1, None, 0),
            (9, "worker_instance_id", "TEXT", 1, None, 0),
            (10, "claim_ledger_id", "TEXT", 1, None, 0),
            (11, "launch_ledger_id", "TEXT", 1, None, 0),
            (12, "policy_sha256", "TEXT", 1, None, 0),
            (13, "binding_sha256", "TEXT", 1, None, 0),
            (14, "reserved_at_unix", "INTEGER", 1, None, 0),
        )
        expected_state_columns = (
            (0, "singleton", "INTEGER", 1, None, 1),
            (1, "worker_instance_id", "TEXT", 1, None, 0),
            (2, "claim_ledger_id", "TEXT", 1, None, 0),
            (3, "launch_ledger_id", "TEXT", 1, None, 0),
            (4, "clock_high_water_unix", "INTEGER", 1, None, 0),
        )
        expected_unique_columns = {
            ("intent_id",),
            ("intent_id", "claim_receipt_sha256"),
            ("intent_sha256",),
            ("intent_nonce",),
            ("claim_receipt_sha256",),
            ("claim_id",),
            ("claim_nonce",),
            ("launch_attempt_id",),
            ("launch_attempt_nonce",),
            ("receipt_sha256",),
        }
        expected_reservation_unique_columns = {
            ("claim_receipt_sha256",),
            ("intent_id",),
            ("intent_sha256",),
            ("intent_nonce",),
            ("claim_id",),
            ("claim_nonce",),
            (
                "claim_receipt_sha256",
                "intent_id",
                "intent_sha256",
                "payload_sha256",
                "intent_nonce",
                "claim_id",
                "claim_nonce",
                "claimed_at_unix",
                "trust_store_sha256",
                "worker_instance_id",
                "claim_ledger_id",
                "launch_ledger_id",
                "policy_sha256",
                "binding_sha256",
                "reserved_at_unix",
            ),
        }
        expected_table_sql = " ".join(_CREATE_LAUNCH_ATTEMPTS.split())
        normalized_reservation_sql = (
            " ".join(reservation_sql[0].split())
            if reservation_sql is not None and isinstance(reservation_sql[0], str)
            else None
        )
        expected_reservation_sql = " ".join(_CREATE_LAUNCH_RESERVATIONS.split())
        expected_state_sql = " ".join(_CREATE_LAUNCH_STATE.split())
        normalized_table_sql = (
            " ".join(table_sql[0].split())
            if table_sql is not None and isinstance(table_sql[0], str)
            else None
        )
        normalized_state_sql = (
            " ".join(state_sql[0].split())
            if state_sql is not None and isinstance(state_sql[0], str)
            else None
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
                "inert_fixture_launch_attempts",
                "inert_fixture_launch_reservations",
                "inert_fixture_launch_state",
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
            ("claim_receipt_sha256", "claim_receipt_sha256"),
            ("intent_id", "intent_id"),
            ("intent_sha256", "intent_sha256"),
            ("payload_sha256", "payload_sha256"),
            ("intent_nonce", "intent_nonce"),
            ("claim_id", "claim_id"),
            ("claim_nonce", "claim_nonce"),
            ("claimed_at_unix", "claimed_at_unix"),
            ("trust_store_sha256", "trust_store_sha256"),
            ("worker_instance_id", "worker_instance_id"),
            ("claim_ledger_id", "claim_ledger_id"),
            ("launch_ledger_id", "launch_ledger_id"),
            ("policy_sha256", "policy_sha256"),
            ("binding_sha256", "binding_sha256"),
            ("consumed_at_unix", "reserved_at_unix"),
        }
        foreign_key_columns = {(row[3], row[4]) for row in foreign_keys}
        if (
            integrity_check != [("ok",)]
            or foreign_key_check
            or reservation_foreign_keys
            or len(foreign_keys) != len(expected_foreign_key_columns)
            or foreign_key_columns != expected_foreign_key_columns
            or any(
                row[2] != "inert_fixture_launch_reservations"
                or row[5:] != ("NO ACTION", "NO ACTION", "NONE")
                for row in foreign_keys
            )
            or application_id != (_LEDGER_APPLICATION_ID,)
            or user_version != (_LEDGER_USER_VERSION,)
            or table_objects
            != {
                "inert_fixture_launch_attempts": expected_table_sql,
                "inert_fixture_launch_reservations": expected_reservation_sql,
                "inert_fixture_launch_state": expected_state_sql,
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
            or state_rows[0][2] != self.claim_ledger_id
            or state_rows[0][3] != self.ledger_id
            or type(state_rows[0][4]) is not int
            or state_rows[0][4] < 0
            or maximum_consumed_at is None
            or len(maximum_consumed_at) != 1
            or (
                maximum_consumed_at[0] is not None
                and (
                    type(maximum_consumed_at[0]) is not int
                    or state_rows[0][4] < maximum_consumed_at[0]
                )
            )
            or maximum_reserved_at is None
            or len(maximum_reserved_at) != 1
            or (
                maximum_reserved_at[0] is not None
                and (
                    type(maximum_reserved_at[0]) is not int
                    or state_rows[0][4] < maximum_reserved_at[0]
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
            raise InertFixtureLaunchLedgerError(
                "launch-attempt ledger schema is not trusted"
            )

    def consume_launch_attempt(
        self,
        intent: SignedInertFixtureIntent,
        trust_store: InertFixtureIntentTrustStore,
        expectation: InertFixtureLaunchExpectation,
        claim_receipt: InertFixtureIntentClaimReceipt,
        claim_ledger: InertFixtureIntentLedger,
        *,
        launch_attempt_id: str,
    ) -> InertFixtureLaunchAttemptReceipt:
        """Reauthenticate and atomically consume one attempt without starting a process."""

        verification_time = _current_unix_time()
        verified = _authenticate_launch_inputs(
            intent,
            trust_store,
            expectation,
            claim_receipt,
            claim_ledger,
            now_unix=verification_time,
            enforce_validity=True,
        )
        frozen_expectation = _validate_launch_expectation(expectation)
        if (
            self.path != frozen_expectation.launch_ledger_path
            or self.ledger_id != frozen_expectation.launch_ledger_id
            or self.worker_instance_id != frozen_expectation.worker_instance_id
            or self.claim_ledger_id != frozen_expectation.claim_ledger_id
        ):
            raise InertFixtureLaunchLedgerError(
                "launch attempt is bound to a different configured launch ledger"
            )
        claim = verified.claim_receipt
        binding_sha256 = _launch_binding_sha256(
            claim,
            claim_receipt_sha256=verified.claim_receipt_sha256,
            worker_instance_id=self.worker_instance_id,
            claim_ledger_id=self.claim_ledger_id,
            launch_ledger_id=self.ledger_id,
        )

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_schema(connection)
            consumed_at_unix = _current_unix_time()
            if type(consumed_at_unix) is not int or consumed_at_unix < 0:
                raise InertFixtureLaunchLedgerError(
                    "worker clock returned an invalid Unix time"
                )
            clock_row = connection.execute(
                "SELECT clock_high_water_unix FROM inert_fixture_launch_state "
                "WHERE singleton = 1"
            ).fetchone()
            if (
                clock_row is None
                or type(clock_row[0]) is not int
                or consumed_at_unix < verification_time
                or consumed_at_unix < verified.claim_receipt.claimed_at_unix
                or consumed_at_unix < clock_row[0]
            ):
                raise InertFixtureLaunchLedgerError(
                    "worker clock moved behind the claim or durable launch high-water mark"
                )
            connection.execute(
                "UPDATE inert_fixture_launch_state SET clock_high_water_unix = ? "
                "WHERE singleton = 1",
                (consumed_at_unix,),
            )
            if consumed_at_unix >= verified.claim_receipt.intent_expires_at_unix:
                connection.execute("COMMIT")
                raise InertFixtureLaunchLedgerError(
                    "fixture intent expired before durable launch-attempt consumption"
                )

            reservation_identity = (
                verified.claim_receipt_sha256,
                claim.intent_id,
                verified.intent_sha256,
                verified.payload_sha256,
                claim.intent_nonce,
                claim.claim_id,
                claim.claim_nonce,
                claim.claimed_at_unix,
                verified.trust_store_sha256,
                self.worker_instance_id,
                self.claim_ledger_id,
                self.ledger_id,
                claim.policy_sha256,
                binding_sha256,
            )
            existing_reservation = connection.execute(
                """
                SELECT claim_receipt_sha256, intent_id, intent_sha256,
                       payload_sha256, intent_nonce, claim_id, claim_nonce,
                       claimed_at_unix, trust_store_sha256, worker_instance_id,
                       claim_ledger_id, launch_ledger_id, policy_sha256,
                       binding_sha256, reserved_at_unix
                FROM inert_fixture_launch_reservations
                WHERE claim_receipt_sha256 = ?
                """,
                (verified.claim_receipt_sha256,),
            ).fetchone()
            if existing_reservation is not None:
                if (
                    existing_reservation[:-1] != reservation_identity
                    or type(existing_reservation[-1]) is not int
                    or not (
                        claim.claimed_at_unix
                        <= existing_reservation[-1]
                        < claim.intent_expires_at_unix
                    )
                ):
                    raise InertFixtureLaunchLedgerError(
                        "launch reservation differs from authenticated inputs"
                    )
                connection.execute("COMMIT")
                raise InertFixtureLaunchAttemptAlreadyConsumed(
                    "launch attempt was already consumed by a terminal reservation"
                )
            committed_identity_conflict = connection.execute(
                """
                SELECT 1 FROM inert_fixture_launch_reservations
                WHERE intent_id = ?
                   OR intent_sha256 = ?
                   OR intent_nonce = ?
                   OR claim_id = ?
                   OR claim_nonce = ?
                LIMIT 1
                """,
                (
                    claim.intent_id,
                    verified.intent_sha256,
                    claim.intent_nonce,
                    claim.claim_id,
                    claim.claim_nonce,
                ),
            ).fetchone()
            if committed_identity_conflict is not None:
                connection.execute("COMMIT")
                raise InertFixtureLaunchAttemptAlreadyConsumed(
                    "launch claim or intent identity was already consumed"
                )
            connection.execute(
                """
                INSERT INTO inert_fixture_launch_reservations (
                    claim_receipt_sha256, intent_id, intent_sha256, payload_sha256,
                    intent_nonce, claim_id, claim_nonce, claimed_at_unix,
                    trust_store_sha256, worker_instance_id, claim_ledger_id,
                    launch_ledger_id, policy_sha256, binding_sha256,
                    reserved_at_unix
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (*reservation_identity, consumed_at_unix),
            )
            if (
                type(launch_attempt_id) is not str
                or not _SHA256_HEX.fullmatch(launch_attempt_id)
                or launch_attempt_id == "0" * 64
            ):
                connection.execute("COMMIT")
                raise InertFixtureLaunchAttemptAlreadyConsumed(
                    "launch attempt was already consumed: attempt ID must be a nonzero "
                    "lowercase SHA-256 value"
                )
            caller_conflict = connection.execute(
                "SELECT 1 FROM inert_fixture_launch_attempts "
                "WHERE launch_attempt_id = ? LIMIT 1",
                (launch_attempt_id,),
            ).fetchone()
            if caller_conflict is not None:
                connection.execute("COMMIT")
                raise InertFixtureLaunchAttemptAlreadyConsumed(
                    "launch attempt was already consumed by an identity collision"
                )
            try:
                receipt = InertFixtureLaunchAttemptReceipt(
                    schema_version="bpe.inert-fixture-launch-attempt-receipt.v1",
                    status="launch_attempt_consumed_not_started",
                    claim_receipt=verified.claim_receipt,
                    claim_receipt_sha256=verified.claim_receipt_sha256,
                    launch_attempt_id=launch_attempt_id,
                    launch_attempt_nonce=_new_launch_attempt_nonce(),
                    launch_attempt_consumed_at_unix=consumed_at_unix,
                    worker_instance_id=self.worker_instance_id,
                    claim_ledger_id=self.claim_ledger_id,
                    launch_ledger_id=self.ledger_id,
                    original_intent_reauthenticated=True,
                    exact_claim_receipt_committed=True,
                    serialized_worker_clock_verified=True,
                    separate_launch_ledger_used=True,
                    launch_attempt_consumed=True,
                    retry_permitted=False,
                    launch_authorized=False,
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
                raise InertFixtureLaunchAttemptAlreadyConsumed(
                    "launch attempt was already consumed before receipt construction"
                ) from exc
            conflict = connection.execute(
                """
                SELECT 1 FROM inert_fixture_launch_attempts
                WHERE launch_attempt_nonce = ? OR receipt_sha256 = ?
                LIMIT 1
                """,
                (
                    receipt.launch_attempt_nonce,
                    receipt_sha256,
                ),
            ).fetchone()
            if conflict is not None:
                connection.execute("COMMIT")
                raise InertFixtureLaunchAttemptAlreadyConsumed(
                    "launch attempt was already consumed by a receipt collision"
                )
            try:
                connection.execute(
                    """
                    INSERT INTO inert_fixture_launch_attempts (
                        intent_id,
                        intent_sha256,
                        payload_sha256,
                        intent_nonce,
                        claim_receipt_sha256,
                        claim_id,
                        claim_nonce,
                        claimed_at_unix,
                        trust_store_sha256,
                        worker_instance_id,
                        claim_ledger_id,
                        launch_ledger_id,
                        launch_attempt_id,
                        launch_attempt_nonce,
                        consumed_at_unix,
                        receipt_sha256,
                        receipt_json,
                        policy_sha256,
                        binding_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        claim.intent_id,
                        verified.intent_sha256,
                        verified.payload_sha256,
                        claim.intent_nonce,
                        verified.claim_receipt_sha256,
                        claim.claim_id,
                        claim.claim_nonce,
                        claim.claimed_at_unix,
                        verified.trust_store_sha256,
                        self.worker_instance_id,
                        self.claim_ledger_id,
                        self.ledger_id,
                        receipt.launch_attempt_id,
                        receipt.launch_attempt_nonce,
                        consumed_at_unix,
                        receipt_sha256,
                        sqlite3.Binary(receipt_json),
                        claim.policy_sha256,
                        binding_sha256,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                connection.execute("COMMIT")
                raise InertFixtureLaunchAttemptAlreadyConsumed(
                    "launch attempt was already consumed by a durable collision"
                ) from exc
            connection.execute("COMMIT")
        except sqlite3.IntegrityError as exc:
            _rollback_sqlite_after_error(connection)
            raise InertFixtureLaunchLedgerError(
                "launch-attempt consumption violated ledger integrity"
            ) from exc
        except (InertFixtureLaunchAttemptAlreadyConsumed, InertFixtureLaunchLedgerError):
            _rollback_sqlite_after_error(connection)
            raise
        except sqlite3.Error as exc:
            _rollback_sqlite_after_error(connection)
            raise InertFixtureLaunchLedgerError(
                "cannot commit launch-attempt consumption"
            ) from exc
        finally:
            _close_sqlite_connection(
                connection,
                error_message="cannot close launch-attempt ledger",
            )
        return receipt

    def verify_committed_receipt(self, receipt: InertFixtureLaunchAttemptReceipt) -> str:
        """Return the digest of an exact launch-attempt receipt in this ledger."""

        if type(receipt) is not InertFixtureLaunchAttemptReceipt:
            raise InertFixtureLaunchLedgerError("launch-attempt receipt has the wrong type")
        try:
            frozen = InertFixtureLaunchAttemptReceipt.model_validate(
                receipt.model_dump(mode="python"),
                strict=True,
            )
            receipt_sha256 = sha256_json(frozen)
        except (AttributeError, TypeError, ValueError) as exc:
            raise InertFixtureLaunchLedgerError("launch-attempt receipt is invalid") from exc
        if (
            frozen.worker_instance_id != self.worker_instance_id
            or frozen.claim_ledger_id != self.claim_ledger_id
            or frozen.launch_ledger_id != self.ledger_id
        ):
            raise InertFixtureLaunchLedgerError(
                "launch-attempt receipt is bound to another ledger"
            )
        claim = frozen.claim_receipt
        binding_sha256 = _launch_binding_sha256(
            claim,
            claim_receipt_sha256=frozen.claim_receipt_sha256,
            worker_instance_id=frozen.worker_instance_id,
            claim_ledger_id=frozen.claim_ledger_id,
            launch_ledger_id=frozen.launch_ledger_id,
        )
        expected_row = (
            claim.intent_id,
            claim.intent_sha256,
            claim.intent_payload_sha256,
            claim.intent_nonce,
            frozen.claim_receipt_sha256,
            claim.claim_id,
            claim.claim_nonce,
            claim.claimed_at_unix,
            claim.trust_store_sha256,
            frozen.worker_instance_id,
            frozen.claim_ledger_id,
            frozen.launch_ledger_id,
            frozen.launch_attempt_id,
            frozen.launch_attempt_nonce,
            frozen.launch_attempt_consumed_at_unix,
            receipt_sha256,
            canonical_json_bytes(frozen),
            claim.policy_sha256,
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
                SELECT intent_id, intent_sha256, payload_sha256, intent_nonce,
                       claim_receipt_sha256, claim_id, claim_nonce, claimed_at_unix,
                       trust_store_sha256, worker_instance_id, claim_ledger_id,
                       launch_ledger_id, launch_attempt_id, launch_attempt_nonce,
                       consumed_at_unix, receipt_sha256, receipt_json, policy_sha256,
                       binding_sha256
                FROM inert_fixture_launch_attempts
                WHERE intent_id = ?
                """,
                (claim.intent_id,),
            ).fetchone()
            connection.execute("COMMIT")
        except InertFixtureLaunchLedgerError:
            if connection is not None:
                _rollback_sqlite_after_error(connection)
            raise
        except (OSError, sqlite3.Error) as exc:
            if connection is not None:
                _rollback_sqlite_after_error(connection)
            raise InertFixtureLaunchLedgerError(
                "cannot verify committed launch-attempt receipt"
            ) from exc
        finally:
            if connection is not None:
                _close_sqlite_connection(
                    connection,
                    error_message="cannot close launch-attempt ledger",
                )
        if row != expected_row:
            raise InertFixtureLaunchLedgerError(
                "launch-attempt receipt is not committed in this ledger"
            )
        return receipt_sha256

    def recover_committed_receipt(
        self,
        intent: SignedInertFixtureIntent,
        trust_store: InertFixtureIntentTrustStore,
        expectation: InertFixtureLaunchExpectation,
        claim_receipt: InertFixtureIntentClaimReceipt,
        claim_ledger: InertFixtureIntentLedger,
    ) -> InertFixtureLaunchAttemptReceipt:
        """Recover exact non-launching evidence after an ambiguous commit."""

        verified = _authenticate_launch_inputs(
            intent,
            trust_store,
            expectation,
            claim_receipt,
            claim_ledger,
            now_unix=_current_unix_time(),
            enforce_validity=False,
        )
        frozen_expectation = _validate_launch_expectation(expectation)
        if (
            self.path != frozen_expectation.launch_ledger_path
            or self.ledger_id != frozen_expectation.launch_ledger_id
            or self.worker_instance_id != frozen_expectation.worker_instance_id
            or self.claim_ledger_id != frozen_expectation.claim_ledger_id
        ):
            raise InertFixtureLaunchLedgerError(
                "launch attempt is bound to a different configured launch ledger"
            )
        claim = verified.claim_receipt
        binding_sha256 = _launch_binding_sha256(
            claim,
            claim_receipt_sha256=verified.claim_receipt_sha256,
            worker_instance_id=self.worker_instance_id,
            claim_ledger_id=self.claim_ledger_id,
            launch_ledger_id=self.ledger_id,
        )
        reservation_identity = (
            verified.claim_receipt_sha256,
            claim.intent_id,
            verified.intent_sha256,
            verified.payload_sha256,
            claim.intent_nonce,
            claim.claim_id,
            claim.claim_nonce,
            claim.claimed_at_unix,
            verified.trust_store_sha256,
            self.worker_instance_id,
            self.claim_ledger_id,
            self.ledger_id,
            claim.policy_sha256,
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
                SELECT r.claim_receipt_sha256, r.intent_id, r.intent_sha256,
                       r.payload_sha256, r.intent_nonce, r.claim_id, r.claim_nonce,
                       r.claimed_at_unix, r.trust_store_sha256, r.worker_instance_id,
                       r.claim_ledger_id, r.launch_ledger_id, r.policy_sha256,
                       r.binding_sha256, r.reserved_at_unix,
                       a.receipt_json, a.receipt_sha256
                FROM inert_fixture_launch_reservations AS r
                LEFT JOIN inert_fixture_launch_attempts AS a
                  ON a.claim_receipt_sha256 = r.claim_receipt_sha256
                WHERE r.claim_receipt_sha256 = ?
                """,
                (verified.claim_receipt_sha256,),
            ).fetchone()
            connection.execute("COMMIT")
        except InertFixtureLaunchLedgerError:
            if connection is not None:
                _rollback_sqlite_after_error(connection)
            raise
        except (OSError, sqlite3.Error) as exc:
            if connection is not None:
                _rollback_sqlite_after_error(connection)
            raise InertFixtureLaunchLedgerError(
                "cannot recover committed launch-attempt receipt"
            ) from exc
        finally:
            if connection is not None:
                _close_sqlite_connection(
                    connection,
                    error_message="cannot close launch-attempt ledger",
                )
        if row is None:
            raise InertFixtureLaunchLedgerError(
                "no recoverable launch-attempt receipt is committed"
            )
        if (
            len(row) != 17
            or row[:14] != reservation_identity
            or type(row[14]) is not int
            or not claim.claimed_at_unix <= row[14] < claim.intent_expires_at_unix
        ):
            raise InertFixtureLaunchLedgerError(
                "launch reservation differs from authenticated inputs"
            )
        if row[15:] == (None, None):
            raise InertFixtureLaunchAttemptAlreadyConsumed(
                "launch attempt was terminally consumed without a recoverable receipt"
            )
        if type(row[15]) is not bytes or type(row[16]) is not str:
            raise InertFixtureLaunchLedgerError(
                "committed launch reservation has incomplete receipt evidence"
            )
        receipt_json, stored_receipt_sha256 = row[15], row[16]
        try:
            recovered = InertFixtureLaunchAttemptReceipt.model_validate_json(
                receipt_json,
                strict=True,
            )
            recovered_json = canonical_json_bytes(recovered)
            recovered_sha256 = sha256_json(recovered)
        except (TypeError, ValueError) as exc:
            raise InertFixtureLaunchLedgerError(
                "committed launch-attempt receipt bytes are invalid"
            ) from exc
        if (
            recovered_json != receipt_json
            or recovered_sha256 != stored_receipt_sha256
            or recovered.claim_receipt != verified.claim_receipt
            or recovered.claim_receipt_sha256 != verified.claim_receipt_sha256
            or recovered.worker_instance_id != frozen_expectation.worker_instance_id
            or recovered.claim_ledger_id != frozen_expectation.claim_ledger_id
            or recovered.launch_ledger_id != frozen_expectation.launch_ledger_id
        ):
            raise InertFixtureLaunchLedgerError(
                "committed launch-attempt receipt differs from authenticated inputs"
            )
        if self.verify_committed_receipt(recovered) != recovered_sha256:
            raise InertFixtureLaunchLedgerError(
                "recovered launch-attempt receipt failed exact ledger verification"
            )
        return recovered

    def attempt_count(self) -> int:
        """Count terminally consumed launch reservations, including tombstones."""

        connection = self._connect()
        try:
            connection.execute("BEGIN")
            self._validate_schema(connection)
            row = connection.execute(
                "SELECT COUNT(*) FROM inert_fixture_launch_reservations"
            ).fetchone()
            connection.execute("COMMIT")
        except InertFixtureLaunchLedgerError:
            _rollback_sqlite_after_error(connection)
            raise
        except sqlite3.Error as exc:
            _rollback_sqlite_after_error(connection)
            raise InertFixtureLaunchLedgerError(
                "cannot inspect launch-attempt ledger"
            ) from exc
        finally:
            _close_sqlite_connection(
                connection,
                error_message="cannot close launch-attempt ledger",
            )
        if row is None or type(row[0]) is not int:
            raise InertFixtureLaunchLedgerError(
                "launch-attempt ledger returned an invalid count"
            )
        return row[0]


def admit_inert_fixture_launch_attempt(
    intent: SignedInertFixtureIntent,
    trust_store: InertFixtureIntentTrustStore,
    expectation: InertFixtureLaunchExpectation,
    claim_receipt: InertFixtureIntentClaimReceipt,
    claim_ledger: InertFixtureIntentLedger,
    *,
    launch_ledger: InertFixtureLaunchLedger,
    launch_attempt_id: str,
) -> InertFixtureLaunchAttemptReceipt:
    """Reauthenticate, then consume one attempt without authorizing or starting a process."""

    verification_time = _current_unix_time()
    _authenticate_launch_inputs(
        intent,
        trust_store,
        expectation,
        claim_receipt,
        claim_ledger,
        now_unix=verification_time,
        enforce_validity=True,
    )
    if type(launch_ledger) is not InertFixtureLaunchLedger:
        raise InertFixtureLaunchLedgerError(
            "launch admission requires its configured launch-ledger type"
        )
    frozen_expectation = _validate_launch_expectation(expectation)
    if (
        launch_ledger.path != frozen_expectation.launch_ledger_path
        or launch_ledger.ledger_id != frozen_expectation.launch_ledger_id
        or launch_ledger.worker_instance_id != frozen_expectation.worker_instance_id
        or launch_ledger.claim_ledger_id != frozen_expectation.claim_ledger_id
    ):
        raise InertFixtureLaunchLedgerError(
            "launch admission received a different configured launch ledger"
        )
    return launch_ledger.consume_launch_attempt(
        intent,
        trust_store,
        frozen_expectation,
        claim_receipt,
        claim_ledger,
        launch_attempt_id=launch_attempt_id,
    )


JSON_SCHEMAS: dict[str, type[BaseModel]] = {
    "inert-fixture-launch-attempt-receipt-v1.json": InertFixtureLaunchAttemptReceipt,
}


__all__ = [
    "JSON_SCHEMAS",
    "InertFixtureLaunchAttemptAlreadyConsumed",
    "InertFixtureLaunchAttemptReceipt",
    "InertFixtureLaunchAuthorizationError",
    "InertFixtureLaunchError",
    "InertFixtureLaunchExpectation",
    "InertFixtureLaunchExpectationError",
    "InertFixtureLaunchLedger",
    "InertFixtureLaunchLedgerError",
    "VerifiedInertFixtureLaunchAttempt",
    "admit_inert_fixture_launch_attempt",
    "inert_fixture_launch_expectation_for",
    "verify_inert_fixture_launch_attempt",
]
