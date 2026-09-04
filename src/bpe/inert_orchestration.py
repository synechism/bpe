"""Atomic execution boundary for the fixed Linux inert fixture.

The public entry point reauthenticates the original signed intent and committed claim,
preflights and stages the immutable launcher, prepares a dedicated single-threaded
subreaper, and only then consumes the one-shot launch attempt.  A cgroup leaf or process
is never created before that durable consumption succeeds.

Normally returned post-consumption outcomes are content-addressed, replayable, unsigned
diagnostic evidence.  They are not durable finalization evidence: an abrupt controller
death after launch-attempt consumption can leave only the launch-ledger tombstone.  A
separate result-attestor role and finalization ledger remain required before these
observations can become authenticated results.
"""

from __future__ import annotations

import array
import ctypes
import errno
import fcntl
import os
import platform
import resource
import select
import signal
import socket
import stat
import struct
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from bpe.canonical import (
    CanonicalJSONError,
    canonical_json_bytes,
    sha256_bytes,
    sha256_json,
    strict_json_loads,
)
from bpe.cgroup import (
    LinuxCgroupError,
    LinuxCgroupV2QualificationPolicy,
    LinuxCgroupV2RetainedLeaf,
    retain_linux_cgroup_v2_leaf,
)
from bpe.inert_artifact import (
    LinuxInertLauncherArtifact,
    LinuxInertLauncherArtifactPreflightReceipt,
    preflight_inert_launcher_artifact,
)
from bpe.inert_fixture import (
    InertFixtureIntentClaimReceipt,
    InertFixtureIntentLedger,
    InertFixtureIntentTrustStore,
    InertFixturePolicy,
    SignedInertFixtureIntent,
)
from bpe.inert_launch import (
    InertFixtureLaunchAttemptAlreadyConsumed,
    InertFixtureLaunchAttemptReceipt,
    InertFixtureLaunchExpectation,
    InertFixtureLaunchLedger,
    admit_inert_fixture_launch_attempt,
    verify_inert_fixture_launch_attempt,
)
from bpe.inert_native_protocol import (
    ACHIEVED_RESULT_MASK,
    LINUX_MAX_PID,
    PROTOCOL_FRAME_SIZE,
    PROTOCOL_MAX_FRAMES,
    InertNativeProtocolViolation,
    InertNativeSocketRecord,
    parse_inert_native_transcript,
)
from bpe.models import Sha256

LINUX_INERT_FIXTURE_ORCHESTRATION_RESULT_DOMAIN = (
    b"BPE\x00linux-inert-fixture-orchestration-result\x00v1\x00"
)
LINUX_INERT_FIXTURE_NATIVE_OBSERVATION_DOMAIN = (
    b"BPE\x00linux-inert-fixture-native-observation\x00v1\x00"
)
MAX_LINUX_INERT_FIXTURE_ORCHESTRATION_RESULT_BYTES = 64 * 1024

_LAUNCHER_ARGV0 = "bpe-inert-fixture-launcher"
_EXEC_DESCRIPTOR_MINIMUM = 16
_SOURCE_DESCRIPTOR_MINIMUM = 32
_MINIMUM_NOFILE_LIMIT = 64
_SOCK_CLOEXEC_LINUX = 0o2000000
_MSG_CMSG_CLOEXEC = getattr(socket, "MSG_CMSG_CLOEXEC", 0)
_MSG_EOR = getattr(socket, "MSG_EOR", 0)
_SO_PASSCRED_LINUX = getattr(socket, "SO_PASSCRED", 16)
_SCM_CREDENTIALS_LINUX = getattr(socket, "SCM_CREDENTIALS", 2)
_SCM_RIGHTS_ITEM_SIZE = array.array("i").itemsize
_UCRED = struct.Struct("=iII")
_CONTROL_ANCILLARY_SIZE = socket.CMSG_SPACE(
    253 * _SCM_RIGHTS_ITEM_SIZE
) + socket.CMSG_SPACE(_UCRED.size)
_WAIT_POLL_SECONDS = 0.01
_PR_SET_CHILD_SUBREAPER = 36
_PR_GET_CHILD_SUBREAPER = 37
_SIGACTION_STORAGE_WORDS = 32

_FRAME_HEX = Annotated[
    str,
    Field(
        min_length=0,
        max_length=(PROTOCOL_FRAME_SIZE + 1) * 2,
        pattern=r"^(?:[0-9a-f]{2})*$",
    ),
]
_PID = Annotated[int, Field(ge=1, le=LINUX_MAX_PID)]
_RETURN_CODE = Annotated[int, Field(ge=-255, le=255)]
_COMPONENT_REASON = Annotated[
    str,
    Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]{0,63}$"),
]

NativeStageName = Literal[
    "startup",
    "descriptor_validation",
    "cgroup_validation",
    "fixture_setup",
    "clone3",
    "child_ready",
    "pidfd_signal",
    "cgroup_kill",
    "child_observation",
    "child_reap",
    "cleanup",
    "protocol",
]
NativeReasonName = Literal[
    "none",
    "bad_argc",
    "bad_argv",
    "nonempty_environment",
    "bad_descriptor_layout",
    "bad_stdio",
    "bad_control_socket",
    "bad_cgroup_descriptor",
    "cgroup_not_empty",
    "protocol_input",
    "peer_closed",
    "resource_exhausted",
    "clone3_unavailable",
    "clone3_rejected",
    "pidfd_unavailable",
    "child_setup_failed",
    "pidfd_signal_failed",
    "cgroup_kill_failed",
    "child_observation_failed",
    "child_reap_failed",
    "timeout",
    "cleanup_incomplete",
    "io_failure",
    "internal",
]
OrchestrationFailureStage = Literal[
    "attempt_finalization",
    "cgroup_retention",
    "cgroup_handoff",
    "launcher_setup",
    "launcher_spawn",
    "transcript_collection",
    "launcher_wait",
    "transcript_validation",
    "cleanup",
]
OrchestrationFailureReason = Literal[
    "attempt_consumption_ambiguous",
    "attempt_receipt_verification_failed",
    "deadline_exceeded",
    "cgroup_retention_failed",
    "cgroup_handoff_failed",
    "launcher_setup_failed",
    "launcher_spawn_failed",
    "transcript_collection_failed",
    "control_protocol_failed",
    "launcher_wait_failed",
    "native_transcript_rejected",
    "cleanup_incomplete",
    "unexpected_error",
]


class LinuxInertFixtureOrchestrationError(ValueError):
    """A process-free orchestration precondition failed before attempt consumption."""


class LinuxInertFixtureOrchestrationPreflightError(
    LinuxInertFixtureOrchestrationError
):
    """Trusted policy or dedicated-controller host state is unsafe."""


class LinuxInertFixtureTerminalConsumptionError(
    LinuxInertFixtureOrchestrationError
):
    """Attempt consumption may be durable but cannot yield trustworthy evidence.

    This exception is itself not a receipt.  It is a local fail-closed signal that the
    caller must treat the attempt as terminal because retry safety cannot be proven.
    """

    launch_attempt_may_be_consumed: Literal[True] = True
    retry_permitted: Literal[False] = False


class _OrchestrationModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        allow_inf_nan=False,
        revalidate_instances="always",
        strict=True,
    )


class LinuxInertFixtureNativeSocketRecord(_OrchestrationModel):
    """One bounded native socket record, including trust-relevant recvmsg metadata."""

    payload_hex: _FRAME_HEX
    message_truncated: bool
    control_truncated: bool
    sender_credentials_present: bool
    sender_pid: Annotated[int, Field(ge=-(1 << 31), le=(1 << 31) - 1)] | None
    sender_uid: Annotated[int, Field(ge=0, le=(1 << 32) - 1)] | None
    sender_gid: Annotated[int, Field(ge=0, le=(1 << 32) - 1)] | None
    unexpected_ancillary_present: bool

    @field_validator(
        "message_truncated",
        "control_truncated",
        "sender_credentials_present",
        "unexpected_ancillary_present",
        mode="before",
    )
    @classmethod
    def metadata_must_be_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("native record metadata must be boolean")
        return value

    @model_validator(mode="after")
    def sender_credentials_are_exact(self) -> Self:
        values = (self.sender_pid, self.sender_uid, self.sender_gid)
        if any(value is None for value in values) != all(
            value is None for value in values
        ):
            raise ValueError("sender credential values must be all present or all absent")
        values_present = self.sender_pid is not None
        if values_present and not self.sender_credentials_present:
            raise ValueError("sender credential values require ancillary presence")
        if (
            self.sender_credentials_present
            and not values_present
            and not self.unexpected_ancillary_present
        ):
            raise ValueError(
                "unparsed sender credentials require unexpected ancillary evidence"
            )
        return self

    def as_protocol_record(
        self,
        *,
        expected_sender_credentials: tuple[int, int, int],
    ) -> InertNativeSocketRecord:
        credentials_are_exact = (
            self.sender_credentials_present
            and (self.sender_pid, self.sender_uid, self.sender_gid)
            == expected_sender_credentials
        )
        return InertNativeSocketRecord(
            payload=bytes.fromhex(self.payload_hex),
            message_truncated=self.message_truncated,
            control_truncated=self.control_truncated,
            ancillary_present=(
                self.unexpected_ancillary_present
                or not credentials_are_exact
            ),
        )


def _native_observation_sha256(fields: dict[str, object]) -> str:
    if "observation_sha256" in fields:
        raise ValueError("native observation preimage contains its own digest")
    return sha256_bytes(
        LINUX_INERT_FIXTURE_NATIVE_OBSERVATION_DOMAIN
        + canonical_json_bytes(fields)
    )


class LinuxInertFixtureNativeObservation(_OrchestrationModel):
    """Raw bounded launcher observation plus a parser-derived projection."""

    observation_sha256: Sha256
    launcher_pid: _PID
    expected_sender_uid: Annotated[int, Field(ge=0, le=(1 << 32) - 1)]
    expected_sender_gid: Annotated[int, Field(ge=0, le=(1 << 32) - 1)]
    launcher_returncode: _RETURN_CODE | None
    eof_observed: bool
    records: Annotated[
        tuple[LinuxInertFixtureNativeSocketRecord, ...],
        Field(max_length=PROTOCOL_MAX_FRAMES),
    ]
    transcript_replay: Literal["accepted", "rejected", "not_replayable"]
    transcript_succeeded: bool | None
    launcher_exit_code: Annotated[int, Field(ge=0, le=255)] | None
    fixture_child_pid: _PID | None
    achieved_result_mask: Annotated[int, Field(ge=0, le=ACHIEVED_RESULT_MASK)] | None
    elapsed_ns: Annotated[int, Field(ge=1)] | None
    failure_stage: NativeStageName | None
    failure_reason: NativeReasonName | None
    failure_errno: Annotated[int, Field(ge=0, le=4095)] | None

    @field_validator("records", mode="before")
    @classmethod
    def record_arrays_are_tuples(cls, value: object) -> object:
        if isinstance(value, list):
            return tuple(value)
        return value

    @field_validator("eof_observed", "transcript_succeeded", mode="before")
    @classmethod
    def booleans_are_exact(cls, value: object) -> object:
        if value is not None and type(value) is not bool:
            raise ValueError("native observation booleans must be exact")
        return value

    @model_validator(mode="after")
    def raw_observation_replays_exactly(self) -> Self:
        raw_fields = self.model_dump(
            mode="python",
            exclude={
                "observation_sha256",
                "transcript_replay",
                "transcript_succeeded",
                "launcher_exit_code",
                "fixture_child_pid",
                "achieved_result_mask",
                "elapsed_ns",
                "failure_stage",
                "failure_reason",
                "failure_errno",
            },
        )
        if self.observation_sha256 != _native_observation_sha256(raw_fields):
            raise ValueError("native observation digest is inconsistent")

        projection = (
            self.transcript_succeeded,
            self.launcher_exit_code,
            self.fixture_child_pid,
            self.achieved_result_mask,
            self.elapsed_ns,
            self.failure_stage,
            self.failure_reason,
            self.failure_errno,
        )
        if self.launcher_returncode is None:
            if self.transcript_replay != "not_replayable" or any(
                value is not None for value in projection
            ):
                raise ValueError("an unreaped launcher cannot claim transcript replay")
            return self

        try:
            expected_sender_credentials = (
                self.launcher_pid,
                self.expected_sender_uid,
                self.expected_sender_gid,
            )
            transcript = parse_inert_native_transcript(
                tuple(
                    record.as_protocol_record(
                        expected_sender_credentials=expected_sender_credentials,
                    )
                    for record in self.records
                ),
                returncode=self.launcher_returncode,
                eof_observed=self.eof_observed,
                expected_launcher_pid=self.launcher_pid,
            )
        except InertNativeProtocolViolation:
            if self.transcript_replay != "rejected" or any(
                value is not None for value in projection
            ):
                raise ValueError(
                    "rejected native replay contains a derived projection"
                ) from None
            return self

        expected_projection = (
            transcript.succeeded,
            int(transcript.launcher_exit_code),
            transcript.child_pid,
            transcript.achieved_result_mask,
            transcript.elapsed_ns,
            (
                transcript.failure_stage.name.lower()
                if transcript.failure_stage is not None
                else None
            ),
            (
                transcript.failure_reason.name.lower()
                if transcript.failure_reason is not None
                else None
            ),
            transcript.failure_errno,
        )
        if self.transcript_replay != "accepted" or projection != expected_projection:
            raise ValueError("accepted native replay projection is inconsistent")
        return self


class LinuxInertFixtureCleanupEvidence(_OrchestrationModel):
    """Terminal local cleanup facts; no field authenticates them externally."""

    status: Literal["completed", "not_required", "incomplete"]
    launcher_waited_exact: bool
    launcher_reaped: bool
    launcher_termination_attempted: bool
    launcher_termination_signal_sent: bool
    launcher_termination_errno: Annotated[int, Field(ge=0, le=4095)] | None
    control_socket_finalized: bool
    staging_descriptors_finalized: bool
    artifact_executable_fd_finalized: bool
    leaf_handoff_fd_finalized: bool
    cgroup_cleanup_attempted: bool
    cgroup_cleanup_completed: bool
    cgroup_cleanup_duration_ms: Annotated[int, Field(ge=0, le=5000)] | None
    cgroup_cleanup_failure_reason: _COMPONENT_REASON | None
    cgroup_retention_cleanup_uncertain: bool
    adopted_descendants_reaped: Annotated[int, Field(ge=0, le=4096)]
    no_children_remaining: bool
    subreaper_restored: bool
    artifact_handle_closed: bool

    @field_validator(
        "launcher_waited_exact",
        "launcher_reaped",
        "launcher_termination_attempted",
        "launcher_termination_signal_sent",
        "control_socket_finalized",
        "staging_descriptors_finalized",
        "artifact_executable_fd_finalized",
        "leaf_handoff_fd_finalized",
        "cgroup_cleanup_attempted",
        "cgroup_cleanup_completed",
        "cgroup_retention_cleanup_uncertain",
        "no_children_remaining",
        "subreaper_restored",
        "artifact_handle_closed",
        mode="before",
    )
    @classmethod
    def cleanup_facts_are_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("cleanup facts must be boolean")
        return value

    @model_validator(mode="after")
    def cleanup_state_is_exact(self) -> Self:
        if self.launcher_waited_exact != self.launcher_reaped:
            raise ValueError("exact launcher wait and reaping facts must agree")
        if self.launcher_termination_signal_sent and not self.launcher_termination_attempted:
            raise ValueError("a launcher signal requires a termination attempt")
        if self.launcher_termination_errno is not None and (
            not self.launcher_termination_attempted
            or self.launcher_termination_signal_sent
        ):
            raise ValueError("launcher termination errno evidence is inconsistent")
        if (
            not self.launcher_termination_attempted
            and self.launcher_termination_errno is not None
        ):
            raise ValueError("launcher termination errno requires an attempt")
        if self.cgroup_cleanup_completed:
            if (
                not self.cgroup_cleanup_attempted
                or self.cgroup_cleanup_duration_ms is None
                or self.cgroup_cleanup_failure_reason is not None
            ):
                raise ValueError("successful cgroup cleanup evidence is inconsistent")
        elif self.cgroup_cleanup_duration_ms is not None:
            raise ValueError("incomplete cgroup cleanup cannot claim a duration")
        if (
            self.cgroup_cleanup_attempted
            and not self.cgroup_cleanup_completed
            and self.cgroup_cleanup_failure_reason is None
        ):
            raise ValueError("failed cgroup cleanup requires a failure reason")
        if self.cgroup_cleanup_failure_reason is not None and not self.cgroup_cleanup_attempted:
            raise ValueError("cgroup cleanup failure requires an attempted cleanup")
        if self.cgroup_retention_cleanup_uncertain and self.cgroup_cleanup_attempted:
            raise ValueError("retention rollback uncertainty cannot claim handle cleanup")
        if self.subreaper_restored and not self.no_children_remaining:
            raise ValueError("subreaper restoration requires an empty child set")

        common_complete = (
            self.control_socket_finalized
            and self.staging_descriptors_finalized
            and self.artifact_executable_fd_finalized
            and self.leaf_handoff_fd_finalized
            and self.no_children_remaining
            and self.subreaper_restored
            and self.artifact_handle_closed
            and not self.cgroup_retention_cleanup_uncertain
        )
        if self.status == "not_required":
            if (
                self.launcher_waited_exact
                or self.launcher_reaped
                or self.cgroup_cleanup_attempted
                or self.cgroup_cleanup_completed
                or self.cgroup_retention_cleanup_uncertain
                or not common_complete
            ):
                raise ValueError("not-required cleanup evidence is inconsistent")
        elif self.status == "completed":
            if not self.cgroup_cleanup_completed or not common_complete:
                raise ValueError("completed cleanup evidence is incomplete")
        elif common_complete and (
            self.cgroup_cleanup_completed or not self.cgroup_cleanup_attempted
        ):
            raise ValueError("complete cleanup facts cannot be labeled incomplete")
        return self


def _orchestration_result_id(fields: dict[str, object]) -> str:
    if "result_id" in fields:
        raise ValueError("orchestration result preimage contains its own identity")
    return sha256_bytes(
        LINUX_INERT_FIXTURE_ORCHESTRATION_RESULT_DOMAIN
        + canonical_json_bytes(fields)
    )


class LinuxInertFixtureOrchestrationResult(_OrchestrationModel):
    """Normally returned terminal observation after one attempt was consumed."""

    schema_version: Literal["bpe.linux-inert-fixture-orchestration-result.v1"]
    status: Literal["fixture_orchestration_terminal_unsigned"]
    result_id: Sha256
    terminal_outcome: Literal[
        "fixture_succeeded",
        "launcher_failed",
        "orchestrator_failed",
    ]
    inert_fixture_policy: InertFixturePolicy
    inert_fixture_policy_sha256: Sha256
    cgroup_policy: LinuxCgroupV2QualificationPolicy
    cgroup_policy_sha256: Sha256
    artifact_preflight_receipt: LinuxInertLauncherArtifactPreflightReceipt
    artifact_preflight_receipt_sha256: Sha256
    launch_attempt_receipt: InertFixtureLaunchAttemptReceipt
    launch_attempt_receipt_sha256: Sha256
    retained_leaf_created: bool
    qualification_nonce: Sha256 | None
    delegated_root_device: Annotated[int, Field(ge=0)] | None
    delegated_root_inode: Annotated[int, Field(ge=1)] | None
    leaf_device: Annotated[int, Field(ge=0)] | None
    leaf_inode: Annotated[int, Field(ge=1)] | None
    leaf_handoff_completed: bool
    launcher_process_created: bool
    launcher_exec_observed: bool
    fixture_child_process_observed: bool
    native_observation: LinuxInertFixtureNativeObservation | None
    orchestration_failure_stage: OrchestrationFailureStage | None
    orchestration_failure_reason: OrchestrationFailureReason | None
    orchestration_failure_component_reason: _COMPONENT_REASON | None
    orchestration_failure_errno: Annotated[int, Field(ge=0, le=4095)] | None
    cleanup_deadline_observed: bool
    total_deadline_observed: bool
    cleanup: LinuxInertFixtureCleanupEvidence
    artifact_preflight_completed: Literal[True]
    launch_attempt_consumed: Literal[True]
    retry_permitted: Literal[False]
    fixture_child_exec_performed: Literal[False]
    external_fixture_executable_accessed: Literal[False]
    candidate_bytes_accessed: Literal[False]
    evaluation_job_accessed: Literal[False]
    execution_authorized: Literal[False]
    authenticity: Literal["unsigned"]
    durable: Literal[False]
    result_attested: Literal[False]
    finalization_ledger_committed: Literal[False]
    freshness_authenticated: Literal[False]
    authoritative: Literal[False]
    official_grading_eligible: Literal[False]

    @field_validator(
        "retained_leaf_created",
        "leaf_handoff_completed",
        "launcher_process_created",
        "launcher_exec_observed",
        "fixture_child_process_observed",
        "cleanup_deadline_observed",
        "total_deadline_observed",
        mode="before",
    )
    @classmethod
    def observed_facts_are_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("orchestration facts must be boolean")
        return value

    @field_validator("artifact_preflight_completed", "launch_attempt_consumed", mode="before")
    @classmethod
    def required_facts_are_true(cls, value: object) -> object:
        if value is not True:
            raise ValueError("orchestration preflight and consumption facts must be true")
        return value

    @field_validator(
        "retry_permitted",
        "fixture_child_exec_performed",
        "external_fixture_executable_accessed",
        "candidate_bytes_accessed",
        "evaluation_job_accessed",
        "execution_authorized",
        "durable",
        "result_attested",
        "finalization_ledger_committed",
        "freshness_authenticated",
        "authoritative",
        "official_grading_eligible",
        mode="before",
    )
    @classmethod
    def boundary_nonclaims_are_false(cls, value: object) -> object:
        if value is not False:
            raise ValueError("unsigned orchestration cannot claim retry, authority, or grading")
        return value

    @model_validator(mode="after")
    def bindings_outcome_and_cleanup_are_exact(self) -> Self:
        if type(self.inert_fixture_policy) is not InertFixturePolicy:
            raise ValueError("orchestration requires the dedicated inert-fixture policy")
        if type(self.cgroup_policy) is not LinuxCgroupV2QualificationPolicy:
            raise ValueError("orchestration requires the dedicated cgroup policy")
        if type(self.artifact_preflight_receipt) is not LinuxInertLauncherArtifactPreflightReceipt:
            raise ValueError("orchestration requires the dedicated artifact receipt")
        if type(self.launch_attempt_receipt) is not InertFixtureLaunchAttemptReceipt:
            raise ValueError("orchestration requires the dedicated launch receipt")
        if self.inert_fixture_policy_sha256 != sha256_json(self.inert_fixture_policy):
            raise ValueError("inert-fixture policy digest is inconsistent")
        if self.cgroup_policy_sha256 != sha256_json(self.cgroup_policy):
            raise ValueError("cgroup policy digest is inconsistent")
        if self.artifact_preflight_receipt_sha256 != sha256_json(
            self.artifact_preflight_receipt
        ):
            raise ValueError("artifact-preflight receipt digest is inconsistent")
        if self.launch_attempt_receipt_sha256 != sha256_json(
            self.launch_attempt_receipt
        ):
            raise ValueError("launch-attempt receipt digest is inconsistent")

        policy = self.inert_fixture_policy
        cgroup_policy = self.cgroup_policy
        artifact = self.artifact_preflight_receipt
        attempt = self.launch_attempt_receipt
        claim = attempt.claim_receipt
        if (
            claim.policy_id != policy.policy_id
            or claim.policy_sha256 != self.inert_fixture_policy_sha256
            or claim.worker_pool_audience != policy.worker_pool_audience
            or claim.worker_instance_id != policy.worker_instance_id
            or claim.claim_ledger_id != policy.claim_ledger_id
            or claim.launch_ledger_id != policy.launch_ledger_id
            or claim.delegated_root_id != policy.delegated_root_id
            or claim.launcher_artifact_id != policy.launcher_artifact_id
            or claim.launcher_artifact_sha256 != policy.launcher_artifact_sha256
            or claim.launcher_seccomp_policy_id != policy.launcher_seccomp_policy_id
            or claim.launcher_seccomp_policy_sha256
            != policy.launcher_seccomp_policy_sha256
            or claim.launcher_protocol_version != policy.launcher_protocol_version
            or claim.launcher_launch_method != policy.launcher_launch_method
            or claim.fixture_kind != policy.fixture_kind
            or claim.fixture_protocol_id != policy.fixture_protocol_id
            or claim.resource_profile_id != policy.resources.profile_id
            or claim.resource_profile_sha256 != policy.resource_profile_sha256
            or claim.fixture_timeout_ms != policy.fixture_timeout_ms
            or claim.cleanup_timeout_ms != policy.cleanup_timeout_ms
            or claim.total_timeout_ms != policy.total_timeout_ms
        ):
            raise ValueError("launch-attempt receipt differs from the exact fixture policy")
        if (
            artifact.policy_id != policy.policy_id
            or artifact.policy_sha256 != self.inert_fixture_policy_sha256
            or artifact.worker_pool_audience != policy.worker_pool_audience
            or artifact.worker_instance_id != policy.worker_instance_id
            or artifact.claim_ledger_id != policy.claim_ledger_id
            or artifact.launch_ledger_id != policy.launch_ledger_id
            or artifact.delegated_root_id != policy.delegated_root_id
            or artifact.launcher_artifact_id != policy.launcher_artifact_id
            or artifact.launcher_artifact_sha256 != policy.launcher_artifact_sha256
            or artifact.launcher_seccomp_policy_id != policy.launcher_seccomp_policy_id
            or artifact.launcher_seccomp_policy_sha256
            != policy.launcher_seccomp_policy_sha256
            or artifact.launcher_protocol_version != policy.launcher_protocol_version
            or artifact.launcher_launch_method != policy.launcher_launch_method
        ):
            raise ValueError("artifact receipt differs from the exact fixture policy")
        if (
            cgroup_policy.worker_pool_audience != policy.worker_pool_audience
            or cgroup_policy.delegated_root_id != policy.delegated_root_id
            or cgroup_policy.cleanup_timeout_ms != policy.cleanup_timeout_ms
        ):
            raise ValueError("cgroup policy differs from the fixture deployment binding")

        leaf_identity = (
            self.qualification_nonce,
            self.delegated_root_device,
            self.delegated_root_inode,
            self.leaf_device,
            self.leaf_inode,
        )
        if self.retained_leaf_created != all(value is not None for value in leaf_identity):
            raise ValueError("retained leaf identity is incomplete")
        if self.retained_leaf_created and (
            self.delegated_root_device != self.leaf_device
            or self.delegated_root_inode == self.leaf_inode
        ):
            raise ValueError("retained root and leaf identities are structurally invalid")
        if self.leaf_handoff_completed and not self.retained_leaf_created:
            raise ValueError("leaf handoff requires a retained leaf")
        if self.native_observation is not None and not self.launcher_process_created:
            raise ValueError("native observation requires a launcher process")
        if self.launcher_process_created and (
            not self.retained_leaf_created or not self.leaf_handoff_completed
        ):
            raise ValueError("launcher process requires retained cgroup handoff")

        replay_accepted = (
            self.native_observation is not None
            and self.native_observation.transcript_replay == "accepted"
        )
        child_observed = (
            replay_accepted
            and self.native_observation is not None
            and self.native_observation.fixture_child_pid is not None
        )
        if self.launcher_exec_observed != replay_accepted:
            raise ValueError("launcher exec observation differs from native replay")
        if self.fixture_child_process_observed != child_observed:
            raise ValueError("fixture-child observation differs from native replay")

        cleanup = self.cleanup
        if self.retained_leaf_created:
            if not cleanup.cgroup_cleanup_attempted:
                raise ValueError("retained leaf requires a terminal cleanup attempt")
            if cleanup.cgroup_retention_cleanup_uncertain:
                raise ValueError("retained leaf cannot claim uncertain retention rollback")
        elif (
            cleanup.cgroup_cleanup_attempted
            or cleanup.cgroup_cleanup_completed
            or cleanup.cgroup_cleanup_duration_ms is not None
            or cleanup.cgroup_cleanup_failure_reason is not None
        ):
            raise ValueError("absent retained leaf cannot claim handle cleanup")
        if cleanup.cgroup_retention_cleanup_uncertain and self.retained_leaf_created:
            raise ValueError("retention rollback uncertainty requires no returned leaf")
        if cleanup.status == "not_required" and (
            self.retained_leaf_created
            or self.launcher_process_created
            or cleanup.cgroup_retention_cleanup_uncertain
        ):
            raise ValueError("not-required cleanup requires no retained resources")
        if self.cleanup_deadline_observed and not self.total_deadline_observed:
            raise ValueError("cleanup deadline cannot outlive the total deadline")
        retention_cleanup_uncertain = (
            self.orchestration_failure_stage == "cgroup_retention"
            and self.orchestration_failure_reason == "cgroup_retention_failed"
            and self.orchestration_failure_component_reason == "cleanup_incomplete"
        )
        if cleanup.cgroup_retention_cleanup_uncertain != retention_cleanup_uncertain:
            raise ValueError("retention rollback uncertainty must be represented exactly")
        if retention_cleanup_uncertain and cleanup.status != "incomplete":
            raise ValueError("uncertain retention rollback requires incomplete cleanup")
        if self.launcher_process_created:
            if cleanup.status == "not_required":
                raise ValueError("a launcher process always requires cleanup")
            if cleanup.status == "completed" and not cleanup.launcher_reaped:
                raise ValueError("completed process cleanup requires an exact launcher reap")
            if self.native_observation is not None:
                returncode_observed = self.native_observation.launcher_returncode is not None
                if returncode_observed != cleanup.launcher_reaped:
                    raise ValueError("launcher return code differs from exact reap evidence")
        elif (
            cleanup.launcher_waited_exact
            or cleanup.launcher_reaped
            or cleanup.launcher_termination_attempted
            or cleanup.launcher_termination_signal_sent
            or cleanup.launcher_termination_errno is not None
            or cleanup.adopted_descendants_reaped != 0
        ):
            raise ValueError("absent launcher cannot claim process cleanup")
        if (
            self.orchestration_failure_stage == "launcher_wait"
            and self.orchestration_failure_reason == "launcher_wait_failed"
            and cleanup.launcher_reaped
        ):
            raise ValueError("launcher wait failure cannot claim an exact reap")

        cleanup_complete = cleanup.status in {"completed", "not_required"}
        if self.launcher_process_created:
            cleanup_complete = cleanup_complete and cleanup.launcher_reaped
        if self.retained_leaf_created:
            cleanup_complete = cleanup_complete and cleanup.cgroup_cleanup_completed

        native_succeeded = (
            replay_accepted
            and self.native_observation is not None
            and self.native_observation.transcript_succeeded is True
        )
        native_failed = (
            replay_accepted
            and self.native_observation is not None
            and self.native_observation.transcript_succeeded is False
        )
        if self.terminal_outcome == "fixture_succeeded":
            if (
                not native_succeeded
                or not cleanup_complete
                or not self.retained_leaf_created
                or not self.leaf_handoff_completed
                or not self.launcher_process_created
                or not self.cleanup_deadline_observed
                or not self.total_deadline_observed
                or self.orchestration_failure_stage is not None
                or self.orchestration_failure_reason is not None
            ):
                raise ValueError("fixture success requires exact replay and complete cleanup")
        elif self.terminal_outcome == "launcher_failed":
            if (
                not native_failed
                or not cleanup_complete
                or not self.retained_leaf_created
                or not self.leaf_handoff_completed
                or not self.launcher_process_created
                or not self.cleanup_deadline_observed
                or not self.total_deadline_observed
                or self.orchestration_failure_stage is not None
                or self.orchestration_failure_reason is not None
            ):
                raise ValueError("launcher failure requires exact replay and complete cleanup")
        elif (
            self.orchestration_failure_stage is None
            or self.orchestration_failure_reason is None
        ):
            raise ValueError("orchestrator failure requires a closed stage and reason")

        if (self.orchestration_failure_stage is None) != (
            self.orchestration_failure_reason is None
        ):
            raise ValueError("orchestration failure stage and reason must be paired")
        if (self.orchestration_failure_stage is None) != (
            self.orchestration_failure_component_reason is None
        ):
            raise ValueError("orchestration component reason must be paired with a failure")
        if (
            self.orchestration_failure_errno is not None
            and self.orchestration_failure_stage is None
        ):
            raise ValueError("orchestration errno requires a failure")

        allowed_reasons: dict[OrchestrationFailureStage, frozenset[str]] = {
            "attempt_finalization": frozenset(
                {"attempt_consumption_ambiguous", "attempt_receipt_verification_failed"}
            ),
            "cgroup_retention": frozenset(
                {"cgroup_retention_failed", "unexpected_error"}
            ),
            "cgroup_handoff": frozenset(
                {"cgroup_handoff_failed", "deadline_exceeded"}
            ),
            "launcher_setup": frozenset(
                {"launcher_setup_failed", "deadline_exceeded", "unexpected_error"}
            ),
            "launcher_spawn": frozenset({"launcher_spawn_failed"}),
            "transcript_collection": frozenset(
                {
                    "deadline_exceeded",
                    "transcript_collection_failed",
                    "control_protocol_failed",
                }
            ),
            "launcher_wait": frozenset(
                {"launcher_wait_failed", "deadline_exceeded", "unexpected_error"}
            ),
            "transcript_validation": frozenset(
                {"native_transcript_rejected", "unexpected_error"}
            ),
            "cleanup": frozenset({"cleanup_incomplete", "deadline_exceeded"}),
        }
        stage = self.orchestration_failure_stage
        reason = self.orchestration_failure_reason
        if stage is not None and reason not in allowed_reasons[stage]:
            raise ValueError("orchestration failure stage and reason are incompatible")
        if stage in {"attempt_finalization", "cgroup_retention"} and (
            self.retained_leaf_created or self.launcher_process_created
        ):
            raise ValueError("early orchestration failure cannot claim created resources")
        if stage == "cgroup_handoff" and (
            not self.retained_leaf_created
            or self.leaf_handoff_completed
            or self.launcher_process_created
        ):
            raise ValueError("cgroup handoff failure has impossible lifecycle facts")
        if stage in {"launcher_setup", "launcher_spawn"} and (
            not self.retained_leaf_created
            or not self.leaf_handoff_completed
            or self.launcher_process_created
        ):
            raise ValueError("launcher creation failure has impossible lifecycle facts")
        if stage in {
            "transcript_collection",
            "launcher_wait",
            "transcript_validation",
        } and not self.launcher_process_created:
            raise ValueError("post-spawn failure requires a launcher process")
        if (
            stage == "transcript_validation"
            and reason == "native_transcript_rejected"
            and (
                self.native_observation is None
                or self.native_observation.transcript_replay != "rejected"
            )
        ):
            raise ValueError("native transcript rejection requires rejected replay")
        if stage == "transcript_collection" and replay_accepted:
            raise ValueError("transcript collection failure cannot claim accepted replay")
        if stage == "cleanup" and (
            not self.retained_leaf_created
            or not self.leaf_handoff_completed
            or not self.launcher_process_created
            or not replay_accepted
        ):
            raise ValueError("cleanup failure requires the completed launch lifecycle")
        if (
            stage == "cleanup"
            and reason == "cleanup_incomplete"
            and cleanup.status != "incomplete"
        ):
            raise ValueError("cleanup-incomplete failure requires incomplete cleanup facts")
        if (
            stage == "cleanup"
            and reason == "deadline_exceeded"
            and self.cleanup_deadline_observed
            and self.total_deadline_observed
        ):
            raise ValueError("deadline failure requires an observed deadline overrun")

        fields = self.model_dump(mode="python", exclude={"result_id"})
        if self.result_id != _orchestration_result_id(fields):
            raise ValueError("orchestration result identity is inconsistent")
        if len(canonical_json_bytes(self)) > MAX_LINUX_INERT_FIXTURE_ORCHESTRATION_RESULT_BYTES:
            raise ValueError("orchestration result exceeds its fixed byte bound")
        return self


@dataclass(slots=True)
class _HostGuard:
    libc: Any
    original_sigchld_action: Any
    active: bool = True

    def restore(self) -> None:
        if not self.active:
            return
        active_error: BaseException | None = None
        try:
            _set_child_subreaper(self.libc, enabled=False)
        except BaseException as exc:
            active_error = exc
        try:
            _restore_sigchld_action(self.libc, self.original_sigchld_action)
        except BaseException as exc:
            if active_error is None:
                active_error = exc
            else:
                active_error.add_note("exact SIGCHLD action restoration also failed")
        if active_error is not None:
            raise active_error
        self.active = False


@dataclass(frozen=True, slots=True)
class _CollectionObservation:
    records: tuple[LinuxInertFixtureNativeSocketRecord, ...]
    eof_observed: bool
    failure_reason: OrchestrationFailureReason | None
    failure_component_reason: str | None
    failure_errno: int | None
    received_descriptors_finalized: bool


@dataclass(frozen=True, slots=True)
class _WaitObservation:
    returncode: int | None
    launcher_reaped: bool
    termination_attempted: bool
    termination_signal_sent: bool
    termination_errno: int | None
    wait_errno: int | None
    cleanup_deadline_ns: int
    exit_deadline_exceeded: bool


@dataclass(slots=True)
class _CleanupWindow:
    deadline_ns: int | None = None


@dataclass(frozen=True, slots=True)
class _NativeRun:
    pid: int | None
    expected_sender_uid: int
    expected_sender_gid: int
    returncode: int | None
    records: tuple[LinuxInertFixtureNativeSocketRecord, ...]
    eof_observed: bool
    failure_stage: OrchestrationFailureStage | None
    failure_reason: OrchestrationFailureReason | None
    failure_component_reason: str | None
    failure_errno: int | None
    launcher_waited_exact: bool
    launcher_reaped: bool
    control_socket_finalized: bool
    staging_descriptors_finalized: bool
    launcher_termination_attempted: bool = False
    launcher_termination_signal_sent: bool = False
    launcher_termination_errno: int | None = None
    cleanup_deadline_ns: int | None = None


@dataclass(slots=True)
class _ResultState:
    primary_stage: OrchestrationFailureStage | None = None
    primary_reason: OrchestrationFailureReason | None = None
    primary_component_reason: str | None = None
    primary_errno: int | None = None
    retained_leaf_created: bool = False
    qualification_nonce: str | None = None
    root_identity: tuple[int, int] | None = None
    leaf_identity: tuple[int, int] | None = None
    leaf_handoff_completed: bool = False
    native_run: _NativeRun | None = None
    native_observation: LinuxInertFixtureNativeObservation | None = None
    artifact_exec_finalized: bool = True
    leaf_fd_finalized: bool = True
    cgroup_cleanup_attempted: bool = False
    cgroup_cleanup_completed: bool = False
    cgroup_cleanup_duration_ms: int | None = None
    cgroup_cleanup_failure_reason: str | None = None
    cgroup_retention_cleanup_uncertain: bool = False
    adopted_descendants_reaped: int = 0
    no_children_remaining: bool = False
    subreaper_restored: bool = False
    artifact_handle_closed: bool = False
    cleanup_deadline_observed: bool = True
    total_deadline_observed: bool = True

    def fail(
        self,
        stage: OrchestrationFailureStage,
        reason: OrchestrationFailureReason,
        *,
        component_reason: str | None = None,
        error_number: int | None = None,
    ) -> None:
        if self.primary_stage is None:
            self.primary_stage = stage
            self.primary_reason = reason
            self.primary_component_reason = component_reason
            self.primary_errno = _bounded_errno(error_number)


def _current_unix_time() -> int:
    return time.time_ns() // 1_000_000_000


def _bounded_errno(value: int | None) -> int | None:
    if type(value) is int and 0 <= value <= 4095:
        return value
    return None


def _exception_errno(exc: BaseException) -> int | None:
    current: BaseException | None = exc
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, OSError):
            return _bounded_errno(current.errno)
        cause = current.__cause__
        current = cause if isinstance(cause, BaseException) else None
    return None


def _freeze_policies(
    expectation: InertFixtureLaunchExpectation,
    cgroup_policy: LinuxCgroupV2QualificationPolicy,
) -> tuple[InertFixturePolicy, LinuxCgroupV2QualificationPolicy]:
    if type(expectation) is not InertFixtureLaunchExpectation:
        raise LinuxInertFixtureOrchestrationPreflightError(
            "orchestration requires the exact launch expectation"
        )
    if type(cgroup_policy) is not LinuxCgroupV2QualificationPolicy:
        raise LinuxInertFixtureOrchestrationPreflightError(
            "orchestration requires the exact cgroup policy type"
        )
    try:
        policy = InertFixturePolicy.model_validate(
            expectation.intent_expectation.policy.model_dump(mode="python"),
            strict=True,
        )
        frozen_cgroup = LinuxCgroupV2QualificationPolicy.model_validate(
            cgroup_policy.model_dump(mode="python"),
            strict=True,
        )
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise LinuxInertFixtureOrchestrationPreflightError(
            "orchestration policy inputs are invalid"
        ) from exc
    if (
        policy.worker_pool_audience != frozen_cgroup.worker_pool_audience
        or policy.delegated_root_id != frozen_cgroup.delegated_root_id
        or policy.cleanup_timeout_ms != frozen_cgroup.cleanup_timeout_ms
    ):
        raise LinuxInertFixtureOrchestrationPreflightError(
            "cgroup policy differs from the signed fixture deployment binding"
        )
    return policy, frozen_cgroup


def _preflight_launch_ledger(
    expectation: InertFixtureLaunchExpectation,
    launch_ledger: InertFixtureLaunchLedger,
) -> None:
    if type(launch_ledger) is not InertFixtureLaunchLedger:
        raise LinuxInertFixtureOrchestrationPreflightError(
            "orchestration requires the exact launch-ledger type"
        )
    if (
        type(launch_ledger.path) is not type(Path())
        or type(launch_ledger.ledger_id) is not str
        or type(launch_ledger.worker_instance_id) is not str
        or type(launch_ledger.claim_ledger_id) is not str
        or launch_ledger.path != expectation.launch_ledger_path
        or launch_ledger.ledger_id != expectation.launch_ledger_id
        or launch_ledger.worker_instance_id != expectation.worker_instance_id
        or launch_ledger.claim_ledger_id != expectation.claim_ledger_id
    ):
        raise LinuxInertFixtureOrchestrationPreflightError(
            "orchestration received a different configured launch ledger"
        )


def _load_libc() -> Any:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl.restype = ctypes.c_int
        libc.sigaction.restype = ctypes.c_int
    except (AttributeError, OSError) as exc:
        raise LinuxInertFixtureOrchestrationPreflightError(
            "the dedicated Linux subreaper interface is unavailable"
        ) from exc
    return libc


def _capture_sigchld_action(libc: Any) -> Any:
    """Capture the libc sigaction bytes without assuming a libc struct layout."""

    action = (ctypes.c_ulong * _SIGACTION_STORAGE_WORDS)()
    ctypes.set_errno(0)
    result = int(
        libc.sigaction(
            ctypes.c_int(signal.SIGCHLD),
            ctypes.c_void_p(),
            ctypes.byref(action),
        )
    )
    if result != 0:
        error_number = ctypes.get_errno() or errno.EIO
        raise OSError(error_number, os.strerror(error_number))
    return action


def _restore_sigchld_action(libc: Any, action: Any) -> None:
    ctypes.set_errno(0)
    result = int(
        libc.sigaction(
            ctypes.c_int(signal.SIGCHLD),
            ctypes.byref(action),
            ctypes.c_void_p(),
        )
    )
    if result != 0:
        error_number = ctypes.get_errno() or errno.EIO
        raise OSError(error_number, os.strerror(error_number))
    if signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL:
        raise OSError(errno.EIO, "SIGCHLD handler was not restored exactly")


def _get_child_subreaper(libc: Any) -> int:
    value = ctypes.c_int(-1)
    ctypes.set_errno(0)
    result = int(
        libc.prctl(
            ctypes.c_int(_PR_GET_CHILD_SUBREAPER),
            ctypes.byref(value),
            ctypes.c_ulong(0),
            ctypes.c_ulong(0),
            ctypes.c_ulong(0),
        )
    )
    if result != 0 or value.value not in {0, 1}:
        error_number = ctypes.get_errno() or errno.EIO
        raise OSError(error_number, os.strerror(error_number))
    return value.value


def _set_child_subreaper(libc: Any, *, enabled: bool) -> None:
    ctypes.set_errno(0)
    result = int(
        libc.prctl(
            ctypes.c_int(_PR_SET_CHILD_SUBREAPER),
            ctypes.c_ulong(1 if enabled else 0),
            ctypes.c_ulong(0),
            ctypes.c_ulong(0),
            ctypes.c_ulong(0),
        )
    )
    if result != 0:
        error_number = ctypes.get_errno() or errno.EIO
        raise OSError(error_number, os.strerror(error_number))
    if _get_child_subreaper(libc) != (1 if enabled else 0):
        raise OSError(errno.EIO, "child-subreaper state did not change exactly")


def _read_children_file() -> bytes:
    path = f"/proc/self/task/{os.getpid()}/children"
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError(errno.EPERM, "children state is not a procfs regular file")
        content = os.read(descriptor, 4097)
        if len(content) > 4096 or os.read(descriptor, 1):
            raise OSError(errno.EOVERFLOW, "children state exceeds its fixed bound")
        return content
    finally:
        os.close(descriptor)


def _prepare_host_guard() -> _HostGuard:
    if (
        sys.platform != "linux"
        or platform.machine() != "x86_64"
        or ctypes.sizeof(ctypes.c_void_p) != 8
        or ctypes.sizeof(ctypes.c_long) != 8
    ):
        raise LinuxInertFixtureOrchestrationPreflightError(
            "orchestration requires native Linux x86-64"
        )
    required = (
        "POSIX_SPAWN_DUP2",
        "kill",
        "posix_spawn",
        "waitpid",
        "waitstatus_to_exitcode",
    )
    if any(not hasattr(os, name) for name in required):
        raise LinuxInertFixtureOrchestrationPreflightError(
            "the fixed posix_spawn and wait interfaces are unavailable"
        )
    if _MSG_CMSG_CLOEXEC == 0:
        raise LinuxInertFixtureOrchestrationPreflightError(
            "atomic CLOEXEC control-message receipt is unavailable"
        )
    if threading.current_thread() is not threading.main_thread():
        raise LinuxInertFixtureOrchestrationPreflightError(
            "orchestration must run in the dedicated main thread"
        )
    try:
        soft_nofile, _hard_nofile = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft_nofile < _MINIMUM_NOFILE_LIMIT:
            raise LinuxInertFixtureOrchestrationPreflightError(
                "orchestration requires at least 64 process descriptors"
            )
        task_ids = {
            entry
            for entry in os.listdir("/proc/self/task")
            if entry.isascii() and entry.isdecimal()
        }
        if task_ids != {str(os.getpid())}:
            raise LinuxInertFixtureOrchestrationPreflightError(
                "orchestration requires a dedicated single-threaded process"
            )
        if _read_children_file().strip():
            raise LinuxInertFixtureOrchestrationPreflightError(
                "orchestration requires a process with no pre-existing children"
            )
        if signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL:
            raise LinuxInertFixtureOrchestrationPreflightError(
                "orchestration requires the default SIGCHLD disposition"
            )
        ambient_descriptors = tuple(
            sorted(
                int(entry)
                for entry in os.listdir("/proc/self/fd")
                if entry.isascii() and entry.isdecimal() and int(entry) >= 3
            )
        )
        for descriptor in ambient_descriptors:
            try:
                if os.get_inheritable(descriptor):
                    raise LinuxInertFixtureOrchestrationPreflightError(
                        "all ambient descriptors must be non-inheritable"
                    )
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise
        if ambient_descriptors and ambient_descriptors[-1] >= _SOURCE_DESCRIPTOR_MINIMUM:
            raise LinuxInertFixtureOrchestrationPreflightError(
                "ambient descriptor layout leaves no fixed staging reserve"
            )
        libc = _load_libc()
        if _get_child_subreaper(libc) != 0:
            raise LinuxInertFixtureOrchestrationPreflightError(
                "orchestration requires an initially non-subreaper process"
            )
        original_sigchld_action = _capture_sigchld_action(libc)
        try:
            # A SIG_DFL handler can still carry SA_NOCLDWAIT. Reinstalling the
            # default action clears that flag before any child exists, guaranteeing
            # zombie retention until our exact wait and preventing PID-reuse kills.
            if signal.signal(signal.SIGCHLD, signal.SIG_DFL) is not signal.SIG_DFL:
                raise LinuxInertFixtureOrchestrationPreflightError(
                    "SIGCHLD changed during dedicated host preparation"
                )
            _set_child_subreaper(libc, enabled=True)
        except BaseException as exc:
            try:
                if _get_child_subreaper(libc) == 1:
                    _set_child_subreaper(libc, enabled=False)
            except BaseException:
                exc.add_note("child-subreaper rollback also failed")
            try:
                _restore_sigchld_action(libc, original_sigchld_action)
            except BaseException:
                exc.add_note("exact SIGCHLD action rollback also failed")
            raise
    except LinuxInertFixtureOrchestrationPreflightError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise LinuxInertFixtureOrchestrationPreflightError(
            "dedicated orchestration process state could not be established"
        ) from exc
    return _HostGuard(
        libc=libc,
        original_sigchld_action=original_sigchld_action,
    )


def _close_descriptor(descriptor: int) -> bool:
    if descriptor < 0:
        return True
    try:
        os.close(descriptor)
    except OSError:
        return False
    return True


def _finalize_descriptor(descriptor: int) -> bool:
    """Make one conservative close attempt without interrupting later cleanup."""

    try:
        return _close_descriptor(descriptor)
    except BaseException:
        return False


def _finalize_socket(control: socket.socket) -> bool:
    """Close one owned socket while preserving independent cleanup progress."""

    try:
        control.close()
    except BaseException:
        return False
    return True


def _stage_executable_descriptor(artifact: LinuxInertLauncherArtifact) -> int:
    direct = artifact.duplicate_executable_fd()
    staged = -1
    try:
        staged = int(
            fcntl.fcntl(direct, fcntl.F_DUPFD_CLOEXEC, _EXEC_DESCRIPTOR_MINIMUM)
        )
        if os.get_inheritable(staged):
            raise OSError(errno.EPERM, "staged executable descriptor is inheritable")
        closing_direct, direct = direct, -1
        if not _finalize_descriptor(closing_direct):
            raise OSError(errno.EIO, "artifact descriptor closure was indeterminate")
        retained, staged = staged, -1
        return retained
    finally:
        if staged >= 0:
            closing_staged, staged = staged, -1
            _finalize_descriptor(closing_staged)
        if direct >= 0:
            closing_direct, direct = direct, -1
            _finalize_descriptor(closing_direct)


def _duplicate_sources(
    descriptors: tuple[int, int, int, int, int],
    *,
    owned: list[int],
) -> tuple[int, ...]:
    """Duplicate spawn sources while leaving every acquired fd in caller custody."""

    if owned:
        raise AssertionError("spawn source ownership must begin empty")
    minimum = _SOURCE_DESCRIPTOR_MINIMUM
    for descriptor in descriptors:
        duplicate = int(fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, minimum))
        owned.append(duplicate)
        if os.get_inheritable(duplicate):
            raise OSError(errno.EPERM, "staged source descriptor is inheritable")
        minimum = duplicate + 1
    return tuple(owned)


def _close_received_rights(ancillary: list[tuple[int, int, bytes]]) -> bool:
    completed = True
    for level, message_type, message_data in ancillary:
        if level != socket.SOL_SOCKET or message_type != socket.SCM_RIGHTS:
            continue
        usable = len(message_data) - len(message_data) % _SCM_RIGHTS_ITEM_SIZE
        descriptors = array.array("i")
        descriptors.frombytes(message_data[:usable])
        for descriptor in descriptors:
            completed = _finalize_descriptor(descriptor) and completed
    return completed


def _inspect_control_ancillary(
    ancillary: list[tuple[int, int, bytes]],
    *,
    expected_sender_credentials: tuple[int, int, int],
) -> tuple[bool, int | None, int | None, int | None, bool, bool]:
    """Parse one kernel ucred and classify every other control item."""

    credentials_present = False
    sender_pid: int | None = None
    sender_uid: int | None = None
    sender_gid: int | None = None
    unexpected_ancillary_present = False
    for level, message_type, message_data in ancillary:
        if level == socket.SOL_SOCKET and message_type == socket.SCM_RIGHTS:
            unexpected_ancillary_present = True
            continue
        if (
            level == socket.SOL_SOCKET
            and message_type == _SCM_CREDENTIALS_LINUX
            and not credentials_present
        ):
            credentials_present = True
            if len(message_data) != _UCRED.size:
                unexpected_ancillary_present = True
                continue
            sender_pid, sender_uid, sender_gid = _UCRED.unpack(message_data)
            continue
        unexpected_ancillary_present = True
    credentials_verified = (
        credentials_present
        and (sender_pid, sender_uid, sender_gid) == expected_sender_credentials
    )
    return (
        credentials_present,
        sender_pid,
        sender_uid,
        sender_gid,
        credentials_verified,
        unexpected_ancillary_present,
    )


def _enable_control_credentials(control: socket.socket) -> None:
    control.setsockopt(socket.SOL_SOCKET, _SO_PASSCRED_LINUX, 1)
    if control.getsockopt(socket.SOL_SOCKET, _SO_PASSCRED_LINUX) != 1:
        raise OSError(errno.EIO, "SO_PASSCRED was not enabled exactly")


def _control_return_flags_valid(flags: int) -> bool:
    """Accept only the fixed CLOEXEC echo and normal record-boundary metadata."""

    return flags >= 0 and flags & ~(_MSG_CMSG_CLOEXEC | _MSG_EOR) == 0


def _control_peer_hup_observed(control: socket.socket) -> bool:
    """Confirm that an empty seqpacket receive represents read-side closure."""

    descriptor = control.fileno()
    if descriptor < 0:
        raise OSError(errno.EBADF, os.strerror(errno.EBADF))
    poller = select.poll()
    poller.register(
        descriptor,
        select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL,
    )
    observed = 0
    for observed_descriptor, events in poller.poll(0):
        if observed_descriptor != descriptor:
            raise OSError(errno.EIO, "control poll returned an unrelated descriptor")
        observed |= events
    if observed & (select.POLLERR | select.POLLNVAL):
        raise OSError(errno.EIO, "control poll reported an invalid socket state")
    return bool(observed & select.POLLHUP)


def _collect_records(
    control: socket.socket,
    deadline_ns: int,
    *,
    expected_sender_credentials: tuple[int, int, int],
) -> _CollectionObservation:
    records: list[LinuxInertFixtureNativeSocketRecord] = []
    received_descriptors_finalized = True
    while True:
        remaining_ns = deadline_ns - time.monotonic_ns()
        if remaining_ns <= 0:
            return _CollectionObservation(
                records=tuple(records),
                eof_observed=False,
                failure_reason="deadline_exceeded",
                failure_component_reason="fixture_deadline",
                failure_errno=None,
                received_descriptors_finalized=received_descriptors_finalized,
            )
        control.settimeout(remaining_ns / 1_000_000_000)
        try:
            payload, ancillary, flags, _address = control.recvmsg(
                PROTOCOL_FRAME_SIZE + 1,
                _CONTROL_ANCILLARY_SIZE,
                _MSG_CMSG_CLOEXEC,
            )
        except TimeoutError:
            return _CollectionObservation(
                records=tuple(records),
                eof_observed=False,
                failure_reason="deadline_exceeded",
                failure_component_reason="fixture_deadline",
                failure_errno=None,
                received_descriptors_finalized=received_descriptors_finalized,
            )
        except OSError as exc:
            return _CollectionObservation(
                records=tuple(records),
                eof_observed=False,
                failure_reason="transcript_collection_failed",
                failure_component_reason="recvmsg_failed",
                failure_errno=_bounded_errno(exc.errno),
                received_descriptors_finalized=received_descriptors_finalized,
            )

        try:
            received_ns = time.monotonic_ns()
        finally:
            # recvmsg installs SCM_RIGHTS descriptors before returning.  No
            # post-receive interruption may bypass their one bounded close pass.
            rights_closed = _close_received_rights(ancillary)
            received_descriptors_finalized = (
                rights_closed and received_descriptors_finalized
            )
        (
            sender_credentials_present,
            sender_pid,
            sender_uid,
            sender_gid,
            sender_credentials_verified,
            unexpected_ancillary_present,
        ) = _inspect_control_ancillary(
            ancillary,
            expected_sender_credentials=expected_sender_credentials,
        )
        return_flags_valid = _control_return_flags_valid(flags)
        if payload == b"" and not ancillary and return_flags_valid:
            try:
                peer_hup_observed = _control_peer_hup_observed(control)
            except OSError as exc:
                return _CollectionObservation(
                    records=tuple(records),
                    eof_observed=False,
                    failure_reason="transcript_collection_failed",
                    failure_component_reason="peer_hup_poll_failed",
                    failure_errno=_bounded_errno(exc.errno),
                    received_descriptors_finalized=received_descriptors_finalized,
                )
            if peer_hup_observed:
                if received_ns >= deadline_ns:
                    return _CollectionObservation(
                        records=tuple(records),
                        eof_observed=False,
                        failure_reason="deadline_exceeded",
                        failure_component_reason="fixture_deadline",
                        failure_errno=None,
                        received_descriptors_finalized=received_descriptors_finalized,
                    )
                return _CollectionObservation(
                    records=tuple(records),
                    eof_observed=True,
                    failure_reason=None,
                    failure_component_reason=None,
                    failure_errno=None,
                    received_descriptors_finalized=received_descriptors_finalized,
                )

        record = LinuxInertFixtureNativeSocketRecord(
            payload_hex=payload.hex(),
            message_truncated=bool(flags & socket.MSG_TRUNC),
            control_truncated=bool(flags & socket.MSG_CTRUNC),
            sender_credentials_present=sender_credentials_present,
            sender_pid=sender_pid,
            sender_uid=sender_uid,
            sender_gid=sender_gid,
            unexpected_ancillary_present=unexpected_ancillary_present,
        )
        record_overflow = len(records) >= PROTOCOL_MAX_FRAMES
        if not record_overflow:
            records.append(record)
        if (
            not return_flags_valid
            or not sender_credentials_verified
            or unexpected_ancillary_present
            or not rights_closed
            or len(payload) != PROTOCOL_FRAME_SIZE
            or record_overflow
        ):
            return _CollectionObservation(
                records=tuple(records),
                eof_observed=False,
                failure_reason="control_protocol_failed",
                failure_component_reason=(
                    "ancillary_descriptor_close_failed"
                    if not rights_closed
                    else "invalid_control_record"
                ),
                failure_errno=None,
                received_descriptors_finalized=received_descriptors_finalized,
            )
        if received_ns >= deadline_ns:
            return _CollectionObservation(
                records=tuple(records),
                eof_observed=False,
                failure_reason="deadline_exceeded",
                failure_component_reason="fixture_deadline",
                failure_errno=None,
                received_descriptors_finalized=received_descriptors_finalized,
            )


def _signal_launcher(pid: int) -> tuple[bool, int | None]:
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return False, None
    except OSError as exc:
        return False, _bounded_errno(exc.errno)
    return True, None


def _wait_launcher(
    pid: int,
    *,
    exit_deadline_ns: int,
    overall_deadline_ns: int,
    cleanup_timeout_ms: int,
    terminate_first: bool,
    cleanup_window: _CleanupWindow | None = None,
) -> _WaitObservation:
    termination_attempted = False
    termination_signal_sent = False
    termination_errno: int | None = None
    active_cleanup_window = cleanup_window or _CleanupWindow()

    def ensure_cleanup_deadline() -> int:
        if active_cleanup_window.deadline_ns is None:
            active_cleanup_window.deadline_ns = min(
                overall_deadline_ns,
                time.monotonic_ns() + cleanup_timeout_ms * 1_000_000,
            )
        return active_cleanup_window.deadline_ns

    def terminate() -> None:
        nonlocal termination_attempted, termination_signal_sent, termination_errno
        ensure_cleanup_deadline()
        termination_attempted = True
        termination_signal_sent, termination_errno = _signal_launcher(pid)

    while True:
        try:
            waited_pid, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return _WaitObservation(
                returncode=None,
                launcher_reaped=False,
                termination_attempted=termination_attempted,
                termination_signal_sent=termination_signal_sent,
                termination_errno=termination_errno,
                wait_errno=errno.ECHILD,
                cleanup_deadline_ns=ensure_cleanup_deadline(),
                exit_deadline_exceeded=time.monotonic_ns() >= exit_deadline_ns,
            )
        except OSError as exc:
            if exc.errno == errno.EINTR:
                continue
            return _WaitObservation(
                returncode=None,
                launcher_reaped=False,
                termination_attempted=termination_attempted,
                termination_signal_sent=termination_signal_sent,
                termination_errno=termination_errno,
                wait_errno=_bounded_errno(exc.errno),
                cleanup_deadline_ns=ensure_cleanup_deadline(),
                exit_deadline_exceeded=time.monotonic_ns() >= exit_deadline_ns,
            )
        if waited_pid == pid:
            observed_ns = time.monotonic_ns()
            return _WaitObservation(
                returncode=os.waitstatus_to_exitcode(status),
                launcher_reaped=True,
                termination_attempted=termination_attempted,
                termination_signal_sent=termination_signal_sent,
                termination_errno=termination_errno,
                wait_errno=None,
                cleanup_deadline_ns=ensure_cleanup_deadline(),
                exit_deadline_exceeded=observed_ns >= exit_deadline_ns,
            )
        if waited_pid not in {0, pid}:
            return _WaitObservation(
                returncode=None,
                launcher_reaped=False,
                termination_attempted=termination_attempted,
                termination_signal_sent=termination_signal_sent,
                termination_errno=termination_errno,
                wait_errno=errno.ECHILD,
                cleanup_deadline_ns=ensure_cleanup_deadline(),
                exit_deadline_exceeded=time.monotonic_ns() >= exit_deadline_ns,
            )
        now_ns = time.monotonic_ns()
        if not termination_attempted and (
            terminate_first or now_ns >= exit_deadline_ns
        ):
            terminate()
        active_deadline_ns = (
            active_cleanup_window.deadline_ns
            if active_cleanup_window.deadline_ns is not None
            else min(exit_deadline_ns, overall_deadline_ns)
        )
        if now_ns >= active_deadline_ns:
            return _WaitObservation(
                returncode=None,
                launcher_reaped=False,
                termination_attempted=termination_attempted,
                termination_signal_sent=termination_signal_sent,
                termination_errno=termination_errno,
                wait_errno=errno.ETIMEDOUT,
                cleanup_deadline_ns=ensure_cleanup_deadline(),
                exit_deadline_exceeded=True,
            )
        remaining_seconds = max(
            0.0,
            (active_deadline_ns - now_ns) / 1_000_000_000,
        )
        time.sleep(min(_WAIT_POLL_SECONDS, remaining_seconds))


def _wait_launcher_resilient(
    pid: int,
    *,
    exit_deadline_ns: int,
    overall_deadline_ns: int,
    cleanup_timeout_ms: int,
    terminate_first: bool,
    cleanup_window: _CleanupWindow,
) -> tuple[_WaitObservation | None, bool, int | None]:
    """Force one bounded termination/reap pass after an inexact first wait."""

    first_wait: _WaitObservation | None = None
    try:
        initial_wait = _wait_launcher(
            pid,
            exit_deadline_ns=exit_deadline_ns,
            overall_deadline_ns=overall_deadline_ns,
            cleanup_timeout_ms=cleanup_timeout_ms,
            terminate_first=terminate_first,
            cleanup_window=cleanup_window,
        )
    except BaseException as first_error:
        recovery_errno = _exception_errno(first_error)
    else:
        if initial_wait.launcher_reaped:
            return initial_wait, False, None
        if initial_wait.wait_errno == errno.ECHILD:
            # Child ownership is already lost.  Its numeric PID can be reused, so a
            # second pass must never signal that PID in an attempt to recover.
            return initial_wait, False, None
        first_wait = initial_wait
        recovery_errno = initial_wait.wait_errno

    if cleanup_window.deadline_ns is None:
        try:
            cleanup_window.deadline_ns = min(
                overall_deadline_ns,
                time.monotonic_ns() + cleanup_timeout_ms * 1_000_000,
            )
        except BaseException as clock_error:
            cleanup_window.deadline_ns = overall_deadline_ns
            recovery_errno = _exception_errno(clock_error) or recovery_errno
    try:
        cleanup_wait = _wait_launcher(
            pid,
            exit_deadline_ns=exit_deadline_ns,
            overall_deadline_ns=overall_deadline_ns,
            cleanup_timeout_ms=cleanup_timeout_ms,
            terminate_first=True,
            cleanup_window=cleanup_window,
        )
    except BaseException as cleanup_error:
        return (
            first_wait,
            True,
            _exception_errno(cleanup_error) or recovery_errno,
        )
    if first_wait is None:
        return cleanup_wait, True, recovery_errno

    termination_signal_sent = (
        first_wait.termination_signal_sent or cleanup_wait.termination_signal_sent
    )
    return (
        _WaitObservation(
            returncode=cleanup_wait.returncode,
            launcher_reaped=cleanup_wait.launcher_reaped,
            termination_attempted=(
                first_wait.termination_attempted
                or cleanup_wait.termination_attempted
            ),
            termination_signal_sent=termination_signal_sent,
            termination_errno=(
                None
                if termination_signal_sent
                else cleanup_wait.termination_errno or first_wait.termination_errno
            ),
            wait_errno=cleanup_wait.wait_errno,
            cleanup_deadline_ns=cleanup_wait.cleanup_deadline_ns,
            exit_deadline_exceeded=(
                first_wait.exit_deadline_exceeded
                or cleanup_wait.exit_deadline_exceeded
            ),
        ),
        True,
        recovery_errno,
    )


def _spawn_and_collect(
    launcher_fd: int,
    leaf_fd: int,
    *,
    fixture_deadline_ns: int,
    overall_deadline_ns: int,
    cleanup_timeout_ms: int,
) -> _NativeRun:
    expected_sender_uid = os.getuid()
    expected_sender_gid = os.getgid()
    stdin_fd = -1
    stdout_fd = -1
    stderr_fd = -1
    source_descriptors: list[int] = []
    parent_control: socket.socket | None = None
    child_control: socket.socket | None = None
    pid: int | None = None
    returncode: int | None = None
    launcher_reaped = False
    termination_attempted = False
    termination_signal_sent = False
    termination_errno: int | None = None
    wait_attempted = False
    cleanup_window = _CleanupWindow()
    cleanup_deadline_ns: int | None = None
    records: tuple[LinuxInertFixtureNativeSocketRecord, ...] = ()
    eof_observed = False
    stage: OrchestrationFailureStage | None = None
    reason: OrchestrationFailureReason | None = None
    component_reason: str | None = None
    failure_errno: int | None = None
    staging_finalized = True
    control_finalized = True
    phase: Literal["setup", "spawn", "post_spawn"] = "setup"
    try:
        if time.monotonic_ns() >= fixture_deadline_ns:
            stage = "launcher_setup"
            reason = "deadline_exceeded"
            component_reason = "fixture_deadline"
        else:
            stdin_fd = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
            stdout_fd = os.open("/dev/null", os.O_WRONLY | os.O_CLOEXEC)
            stderr_fd = os.open("/dev/null", os.O_WRONLY | os.O_CLOEXEC)
            parent_control, child_control = socket.socketpair(
                socket.AF_UNIX,
                socket.SOCK_SEQPACKET
                | getattr(socket, "SOCK_CLOEXEC", _SOCK_CLOEXEC_LINUX),
            )
            if sys.platform == "linux":
                _enable_control_credentials(parent_control)
            sources = _duplicate_sources(
                (stdin_fd, stdout_fd, stderr_fd, child_control.fileno(), leaf_fd),
                owned=source_descriptors,
            )
            file_actions = tuple(
                (os.POSIX_SPAWN_DUP2, source, target)
                for target, source in enumerate(sources)
            )
            signal_defaults = tuple(
                item
                for item in signal.valid_signals()
                if item not in {signal.SIGKILL, signal.SIGSTOP}
            )
            phase = "spawn"
            pid = os.posix_spawn(
                f"/proc/self/fd/{launcher_fd}",
                [_LAUNCHER_ARGV0],
                {},
                file_actions=file_actions,
                setsigmask=(),
                setsigdef=signal_defaults,
            )
            phase = "post_spawn"

        if pid is not None:
            closing_child_control, child_control = child_control, None
            if closing_child_control is None:  # pragma: no cover - setup invariant
                raise AssertionError("spawned launcher has no child control socket")
            if not _finalize_socket(closing_child_control):
                staging_finalized = False

            closing_fds = (stdin_fd, stdout_fd, stderr_fd)
            stdin_fd = stdout_fd = stderr_fd = -1
            for descriptor in closing_fds:
                if not _finalize_descriptor(descriptor):
                    staging_finalized = False
            closing_sources, source_descriptors = source_descriptors, []
            for descriptor in closing_sources:
                if not _finalize_descriptor(descriptor):
                    staging_finalized = False

            if parent_control is None:  # pragma: no cover - setup invariant
                raise AssertionError("spawned launcher has no parent control socket")
            collection = _collect_records(
                parent_control,
                fixture_deadline_ns,
                expected_sender_credentials=(
                    pid,
                    expected_sender_uid,
                    expected_sender_gid,
                ),
            )
            records = collection.records
            eof_observed = collection.eof_observed
            staging_finalized = (
                collection.received_descriptors_finalized and staging_finalized
            )
            if collection.failure_reason is not None:
                stage = "transcript_collection"
                reason = collection.failure_reason
                component_reason = collection.failure_component_reason
                failure_errno = collection.failure_errno

            closing_parent_control, parent_control = parent_control, None
            if not _finalize_socket(closing_parent_control):
                control_finalized = False

            wait_attempted = True
            wait, wait_recovery_attempted, wait_recovery_errno = (
                _wait_launcher_resilient(
                    pid,
                    exit_deadline_ns=fixture_deadline_ns,
                    overall_deadline_ns=overall_deadline_ns,
                    cleanup_timeout_ms=cleanup_timeout_ms,
                    terminate_first=reason is not None,
                    cleanup_window=cleanup_window,
                )
            )
            cleanup_deadline_ns = cleanup_window.deadline_ns
            if wait is None:
                if stage is None:
                    stage = "launcher_wait"
                    reason = "launcher_wait_failed"
                    component_reason = "exact_wait_exception"
                    failure_errno = wait_recovery_errno
            else:
                returncode = wait.returncode
                launcher_reaped = wait.launcher_reaped
                termination_attempted = wait.termination_attempted
                termination_signal_sent = wait.termination_signal_sent
                termination_errno = wait.termination_errno
                cleanup_deadline_ns = wait.cleanup_deadline_ns
                wait_errno = wait.wait_errno
                if not launcher_reaped and stage is None:
                    stage = "launcher_wait"
                    reason = "launcher_wait_failed"
                    component_reason = "exact_wait_incomplete"
                    failure_errno = wait_errno
                elif wait.exit_deadline_exceeded and stage is None:
                    stage = "launcher_wait"
                    reason = "deadline_exceeded"
                    component_reason = "launcher_exit_deadline"
                    failure_errno = termination_errno
                elif wait_recovery_attempted and stage is None:
                    stage = "launcher_wait"
                    reason = "unexpected_error"
                    component_reason = "exact_wait_recovered"
                    failure_errno = wait_recovery_errno
                elif termination_attempted and stage is None:
                    stage = "launcher_wait"
                    reason = "deadline_exceeded"
                    component_reason = "launcher_exit_deadline"
                    failure_errno = termination_errno
    except OSError as exc:
        if pid is None and stage is None:
            if phase == "spawn":
                stage = "launcher_spawn"
                reason = "launcher_spawn_failed"
                component_reason = "posix_spawn_failed"
            else:
                stage = "launcher_setup"
                reason = "launcher_setup_failed"
                component_reason = "launcher_setup_io_failed"
        elif stage is None:
            stage = "transcript_validation"
            reason = "unexpected_error"
            component_reason = "post_spawn_io_failed"
        failure_errno = failure_errno or _bounded_errno(exc.errno)
    except BaseException as exc:
        if stage is None:
            if pid is None:
                stage = "launcher_setup"
                reason = "launcher_setup_failed"
                component_reason = "launcher_setup_exception"
            else:
                stage = "transcript_validation"
                reason = "unexpected_error"
                component_reason = "post_spawn_exception"
        failure_errno = failure_errno or _exception_errno(exc)
    finally:
        if pid is not None and not launcher_reaped and not wait_attempted:
            wait_attempted = True
            wait, wait_recovery_attempted, wait_recovery_errno = (
                _wait_launcher_resilient(
                    pid,
                    exit_deadline_ns=fixture_deadline_ns,
                    overall_deadline_ns=overall_deadline_ns,
                    cleanup_timeout_ms=cleanup_timeout_ms,
                    terminate_first=True,
                    cleanup_window=cleanup_window,
                )
            )
            cleanup_deadline_ns = cleanup_window.deadline_ns
            if wait is None:
                if stage is None:
                    stage = "launcher_wait"
                    reason = "launcher_wait_failed"
                    component_reason = "exact_wait_exception"
                    failure_errno = wait_recovery_errno
            else:
                returncode = wait.returncode
                launcher_reaped = wait.launcher_reaped
                termination_attempted = wait.termination_attempted
                termination_signal_sent = wait.termination_signal_sent
                termination_errno = wait.termination_errno
                cleanup_deadline_ns = wait.cleanup_deadline_ns
                wait_errno = wait.wait_errno
                if not launcher_reaped and stage is None:
                    stage = "launcher_wait"
                    reason = "launcher_wait_failed"
                    component_reason = "exact_wait_incomplete"
                    failure_errno = wait_errno
                elif wait_recovery_attempted and stage is None:
                    stage = "launcher_wait"
                    reason = "unexpected_error"
                    component_reason = "exact_wait_recovered"
                    failure_errno = wait_recovery_errno

        if parent_control is not None:
            closing_parent_control, parent_control = parent_control, None
            if not _finalize_socket(closing_parent_control):
                control_finalized = False
        if child_control is not None:
            closing_child_control, child_control = child_control, None
            if not _finalize_socket(closing_child_control):
                staging_finalized = False
        closing_sources, source_descriptors = source_descriptors, []
        for descriptor in closing_sources:
            if not _finalize_descriptor(descriptor):
                staging_finalized = False
        closing_fds = (stdin_fd, stdout_fd, stderr_fd)
        stdin_fd = stdout_fd = stderr_fd = -1
        for descriptor in closing_fds:
            if descriptor >= 0 and not _finalize_descriptor(descriptor):
                staging_finalized = False

    return _NativeRun(
        pid=pid,
        expected_sender_uid=expected_sender_uid,
        expected_sender_gid=expected_sender_gid,
        returncode=returncode,
        records=records,
        eof_observed=eof_observed,
        failure_stage=stage,
        failure_reason=reason,
        failure_component_reason=component_reason,
        failure_errno=failure_errno,
        launcher_waited_exact=launcher_reaped,
        launcher_reaped=launcher_reaped,
        control_socket_finalized=control_finalized,
        staging_descriptors_finalized=staging_finalized,
        launcher_termination_attempted=termination_attempted,
        launcher_termination_signal_sent=termination_signal_sent,
        launcher_termination_errno=termination_errno,
        cleanup_deadline_ns=cleanup_deadline_ns,
    )


def _build_native_observation(run: _NativeRun) -> LinuxInertFixtureNativeObservation | None:
    if run.pid is None:
        return None
    raw_fields: dict[str, object] = {
        "launcher_pid": run.pid,
        "expected_sender_uid": run.expected_sender_uid,
        "expected_sender_gid": run.expected_sender_gid,
        "launcher_returncode": run.returncode,
        "eof_observed": run.eof_observed,
        "records": run.records,
    }
    replay: Literal["accepted", "rejected", "not_replayable"]
    projection: dict[str, object]
    if run.returncode is None:
        replay = "not_replayable"
        projection = {
            "transcript_succeeded": None,
            "launcher_exit_code": None,
            "fixture_child_pid": None,
            "achieved_result_mask": None,
            "elapsed_ns": None,
            "failure_stage": None,
            "failure_reason": None,
            "failure_errno": None,
        }
    else:
        try:
            expected_sender_credentials = (
                run.pid,
                run.expected_sender_uid,
                run.expected_sender_gid,
            )
            transcript = parse_inert_native_transcript(
                tuple(
                    record.as_protocol_record(
                        expected_sender_credentials=expected_sender_credentials,
                    )
                    for record in run.records
                ),
                returncode=run.returncode,
                eof_observed=run.eof_observed,
                expected_launcher_pid=run.pid,
            )
        except InertNativeProtocolViolation:
            replay = "rejected"
            projection = {
                "transcript_succeeded": None,
                "launcher_exit_code": None,
                "fixture_child_pid": None,
                "achieved_result_mask": None,
                "elapsed_ns": None,
                "failure_stage": None,
                "failure_reason": None,
                "failure_errno": None,
            }
        else:
            replay = "accepted"
            projection = {
                "transcript_succeeded": transcript.succeeded,
                "launcher_exit_code": int(transcript.launcher_exit_code),
                "fixture_child_pid": transcript.child_pid,
                "achieved_result_mask": transcript.achieved_result_mask,
                "elapsed_ns": transcript.elapsed_ns,
                "failure_stage": (
                    transcript.failure_stage.name.lower()
                    if transcript.failure_stage is not None
                    else None
                ),
                "failure_reason": (
                    transcript.failure_reason.name.lower()
                    if transcript.failure_reason is not None
                    else None
                ),
                "failure_errno": transcript.failure_errno,
            }
    return LinuxInertFixtureNativeObservation.model_validate(
        {
            **raw_fields,
            "observation_sha256": _native_observation_sha256(raw_fields),
            "transcript_replay": replay,
            **projection,
        },
        strict=True,
    )


def _reap_adopted_descendants(deadline_ns: int) -> tuple[int, bool, int | None]:
    reaped = 0
    while True:
        try:
            pid, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return reaped, True, None
        except OSError as exc:
            if exc.errno == errno.EINTR:
                continue
            return reaped, False, _bounded_errno(exc.errno)
        if pid > 0:
            reaped += 1
            if reaped > 4096:
                return 4096, False, errno.EOVERFLOW
            continue
        if time.monotonic_ns() >= deadline_ns:
            return reaped, False, errno.ETIMEDOUT
        remaining_seconds = max(
            0.0,
            (deadline_ns - time.monotonic_ns()) / 1_000_000_000,
        )
        time.sleep(min(_WAIT_POLL_SECONDS, remaining_seconds))


def _cleanup_status(state: _ResultState) -> Literal["completed", "not_required", "incomplete"]:
    run = state.native_run
    common = (
        state.artifact_exec_finalized
        and state.leaf_fd_finalized
        and state.no_children_remaining
        and state.subreaper_restored
        and state.artifact_handle_closed
        and not state.cgroup_retention_cleanup_uncertain
        and (run is None or run.control_socket_finalized)
        and (run is None or run.staging_descriptors_finalized)
        and (run is None or run.pid is None or run.launcher_reaped)
    )
    if not state.retained_leaf_created and (run is None or run.pid is None) and common:
        return "not_required"
    if state.retained_leaf_created and state.cgroup_cleanup_completed and common:
        return "completed"
    return "incomplete"


def _build_cleanup(state: _ResultState) -> LinuxInertFixtureCleanupEvidence:
    run = state.native_run
    return LinuxInertFixtureCleanupEvidence(
        status=_cleanup_status(state),
        launcher_waited_exact=run.launcher_waited_exact if run is not None else False,
        launcher_reaped=run.launcher_reaped if run is not None else False,
        launcher_termination_attempted=(
            run.launcher_termination_attempted if run is not None else False
        ),
        launcher_termination_signal_sent=(
            run.launcher_termination_signal_sent if run is not None else False
        ),
        launcher_termination_errno=(
            run.launcher_termination_errno if run is not None else None
        ),
        control_socket_finalized=run.control_socket_finalized if run is not None else True,
        staging_descriptors_finalized=(
            run.staging_descriptors_finalized if run is not None else True
        ),
        artifact_executable_fd_finalized=state.artifact_exec_finalized,
        leaf_handoff_fd_finalized=state.leaf_fd_finalized,
        cgroup_cleanup_attempted=state.cgroup_cleanup_attempted,
        cgroup_cleanup_completed=state.cgroup_cleanup_completed,
        cgroup_cleanup_duration_ms=state.cgroup_cleanup_duration_ms,
        cgroup_cleanup_failure_reason=state.cgroup_cleanup_failure_reason,
        cgroup_retention_cleanup_uncertain=(
            state.cgroup_retention_cleanup_uncertain
        ),
        adopted_descendants_reaped=state.adopted_descendants_reaped,
        no_children_remaining=state.no_children_remaining,
        subreaper_restored=state.subreaper_restored,
        artifact_handle_closed=state.artifact_handle_closed,
    )


def _build_result(
    *,
    policy: InertFixturePolicy,
    cgroup_policy: LinuxCgroupV2QualificationPolicy,
    artifact_receipt: LinuxInertLauncherArtifactPreflightReceipt,
    attempt_receipt: InertFixtureLaunchAttemptReceipt,
    attempt_receipt_sha256: str,
    state: _ResultState,
) -> LinuxInertFixtureOrchestrationResult:
    cleanup = _build_cleanup(state)
    observation = state.native_observation
    native_success = (
        observation is not None
        and observation.transcript_replay == "accepted"
        and observation.transcript_succeeded is True
    )
    native_failure = (
        observation is not None
        and observation.transcript_replay == "accepted"
        and observation.transcript_succeeded is False
    )
    if (
        state.primary_stage is None
        and cleanup.status != "incomplete"
        and state.total_deadline_observed
        and native_success
    ):
        terminal_outcome: Literal[
            "fixture_succeeded", "launcher_failed", "orchestrator_failed"
        ] = "fixture_succeeded"
    elif (
        state.primary_stage is None
        and cleanup.status != "incomplete"
        and state.total_deadline_observed
        and native_failure
    ):
        terminal_outcome = "launcher_failed"
    else:
        terminal_outcome = "orchestrator_failed"
        if state.primary_stage is None:
            if not state.total_deadline_observed:
                state.fail(
                    "cleanup",
                    "deadline_exceeded",
                    component_reason="total_deadline",
                )
            else:
                state.fail(
                    "cleanup",
                    "cleanup_incomplete",
                    component_reason="local_cleanup_incomplete",
                )

    root_device, root_inode = state.root_identity or (None, None)
    leaf_device, leaf_inode = state.leaf_identity or (None, None)
    fields: dict[str, object] = {
        "schema_version": "bpe.linux-inert-fixture-orchestration-result.v1",
        "status": "fixture_orchestration_terminal_unsigned",
        "terminal_outcome": terminal_outcome,
        "inert_fixture_policy": policy,
        "inert_fixture_policy_sha256": sha256_json(policy),
        "cgroup_policy": cgroup_policy,
        "cgroup_policy_sha256": sha256_json(cgroup_policy),
        "artifact_preflight_receipt": artifact_receipt,
        "artifact_preflight_receipt_sha256": sha256_json(artifact_receipt),
        "launch_attempt_receipt": attempt_receipt,
        "launch_attempt_receipt_sha256": attempt_receipt_sha256,
        "retained_leaf_created": state.retained_leaf_created,
        "qualification_nonce": state.qualification_nonce,
        "delegated_root_device": root_device,
        "delegated_root_inode": root_inode,
        "leaf_device": leaf_device,
        "leaf_inode": leaf_inode,
        "leaf_handoff_completed": state.leaf_handoff_completed,
        "launcher_process_created": (
            state.native_run is not None and state.native_run.pid is not None
        ),
        "launcher_exec_observed": (
            observation is not None and observation.transcript_replay == "accepted"
        ),
        "fixture_child_process_observed": (
            observation is not None
            and observation.transcript_replay == "accepted"
            and observation.fixture_child_pid is not None
        ),
        "native_observation": observation,
        "orchestration_failure_stage": state.primary_stage,
        "orchestration_failure_reason": state.primary_reason,
        "orchestration_failure_component_reason": state.primary_component_reason,
        "orchestration_failure_errno": state.primary_errno,
        "cleanup_deadline_observed": state.cleanup_deadline_observed,
        "total_deadline_observed": state.total_deadline_observed,
        "cleanup": cleanup,
        "artifact_preflight_completed": True,
        "launch_attempt_consumed": True,
        "retry_permitted": False,
        "fixture_child_exec_performed": False,
        "external_fixture_executable_accessed": False,
        "candidate_bytes_accessed": False,
        "evaluation_job_accessed": False,
        "execution_authorized": False,
        "authenticity": "unsigned",
        "durable": False,
        "result_attested": False,
        "finalization_ledger_committed": False,
        "freshness_authenticated": False,
        "authoritative": False,
        "official_grading_eligible": False,
    }
    return LinuxInertFixtureOrchestrationResult.model_validate(
        {**fields, "result_id": _orchestration_result_id(fields)},
        strict=True,
    )


def _remaining_cleanup_timeout_ms(deadline_ns: int, maximum_ms: int) -> int:
    remaining_ns = deadline_ns - time.monotonic_ns()
    if remaining_ns <= 0:
        return 1
    whole_ms = remaining_ns // 1_000_000
    return max(1, min(maximum_ms, whole_ms))


def _finalize_artifact_handle(
    artifact: LinuxInertLauncherArtifact,
    state: _ResultState,
) -> None:
    try:
        artifact.close()
        state.artifact_handle_closed = artifact.closed
    except BaseException as exc:
        state.artifact_handle_closed = False
        state.fail(
            "cleanup",
            "cleanup_incomplete",
            component_reason="artifact_handle_close_failed",
            error_number=_exception_errno(exc),
        )
    if not state.artifact_handle_closed:
        state.fail(
            "cleanup",
            "cleanup_incomplete",
            component_reason="artifact_handle_close_failed",
        )


def _finish_result_before_deadline(
    *,
    policy: InertFixturePolicy,
    cgroup_policy: LinuxCgroupV2QualificationPolicy,
    artifact_receipt: LinuxInertLauncherArtifactPreflightReceipt,
    attempt_receipt: InertFixtureLaunchAttemptReceipt,
    attempt_receipt_sha256: str,
    state: _ResultState,
    cleanup_deadline_ns: int,
    overall_deadline_ns: int,
) -> LinuxInertFixtureOrchestrationResult:
    now_ns = time.monotonic_ns()
    state.cleanup_deadline_observed = now_ns < cleanup_deadline_ns
    state.total_deadline_observed = now_ns < overall_deadline_ns
    if not state.cleanup_deadline_observed:
        state.fail(
            "cleanup",
            "deadline_exceeded",
            component_reason="cleanup_deadline",
        )
    elif not state.total_deadline_observed:
        state.fail(
            "cleanup",
            "deadline_exceeded",
            component_reason="total_deadline",
        )
    result = _build_result(
        policy=policy,
        cgroup_policy=cgroup_policy,
        artifact_receipt=artifact_receipt,
        attempt_receipt=attempt_receipt,
        attempt_receipt_sha256=attempt_receipt_sha256,
        state=state,
    )
    completed_ns = time.monotonic_ns()
    if (
        state.cleanup_deadline_observed
        and completed_ns >= cleanup_deadline_ns
    ) or (state.total_deadline_observed and completed_ns >= overall_deadline_ns):
        state.cleanup_deadline_observed = completed_ns < cleanup_deadline_ns
        state.total_deadline_observed = completed_ns < overall_deadline_ns
        if not state.cleanup_deadline_observed:
            state.fail(
                "cleanup",
                "deadline_exceeded",
                component_reason="cleanup_deadline",
            )
        else:
            state.fail(
                "cleanup",
                "deadline_exceeded",
                component_reason="total_deadline",
            )
        result = _build_result(
            policy=policy,
            cgroup_policy=cgroup_policy,
            artifact_receipt=artifact_receipt,
            attempt_receipt=attempt_receipt,
            attempt_receipt_sha256=attempt_receipt_sha256,
            state=state,
        )
    return result


def _orchestrate_consumed_attempt(
    *,
    policy: InertFixturePolicy,
    cgroup_policy: LinuxCgroupV2QualificationPolicy,
    artifact: LinuxInertLauncherArtifact,
    artifact_receipt: LinuxInertLauncherArtifactPreflightReceipt,
    staged_executable_fd: int,
    attempt_receipt: InertFixtureLaunchAttemptReceipt,
    attempt_receipt_sha256: str,
    host_guard: _HostGuard,
    delegated_root_fd: int,
    started_ns: int,
) -> LinuxInertFixtureOrchestrationResult:
    state = _ResultState()
    retained: LinuxCgroupV2RetainedLeaf | None = None
    leaf_fd = -1
    active_executable_fd = staged_executable_fd
    fixture_deadline_ns = started_ns + policy.fixture_timeout_ms * 1_000_000
    overall_deadline_ns = started_ns + policy.total_timeout_ms * 1_000_000
    cleanup_deadline_ns: int | None = None
    try:
        try:
            retained = retain_linux_cgroup_v2_leaf(
                cgroup_policy,
                policy.resources,
                delegated_root_fd=delegated_root_fd,
            )
            state.retained_leaf_created = True
            state.qualification_nonce = retained.qualification_nonce
            state.root_identity = retained.root_identity
            state.leaf_identity = retained.leaf_identity
        except LinuxCgroupError as exc:
            state.cgroup_retention_cleanup_uncertain = exc.reason == "cleanup_incomplete"
            state.fail(
                "cgroup_retention",
                "cgroup_retention_failed",
                component_reason=exc.reason,
                error_number=_exception_errno(exc),
            )
        except BaseException as exc:
            state.fail(
                "cgroup_retention",
                "unexpected_error",
                component_reason="unexpected_cgroup_exception",
                error_number=_exception_errno(exc),
            )

        if retained is not None:
            try:
                if time.monotonic_ns() >= fixture_deadline_ns:
                    state.fail(
                        "cgroup_handoff",
                        "deadline_exceeded",
                        component_reason="fixture_deadline",
                    )
                else:
                    leaf_fd = retained.duplicate_leaf_fd()
                    state.leaf_handoff_completed = True
            except LinuxCgroupError as exc:
                state.fail(
                    "cgroup_handoff",
                    "cgroup_handoff_failed",
                    component_reason=exc.reason,
                    error_number=_exception_errno(exc),
                )
            except BaseException as exc:
                state.fail(
                    "cgroup_handoff",
                    "cgroup_handoff_failed",
                    component_reason="leaf_descriptor_handoff_failed",
                    error_number=_exception_errno(exc),
                )

        if state.primary_stage is None and leaf_fd >= 0:
            run = _spawn_and_collect(
                active_executable_fd,
                leaf_fd,
                fixture_deadline_ns=fixture_deadline_ns,
                overall_deadline_ns=overall_deadline_ns,
                cleanup_timeout_ms=policy.cleanup_timeout_ms,
            )
            state.native_run = run
            cleanup_deadline_ns = run.cleanup_deadline_ns
            if run.failure_stage is not None and run.failure_reason is not None:
                state.fail(
                    run.failure_stage,
                    run.failure_reason,
                    component_reason=run.failure_component_reason,
                    error_number=run.failure_errno,
                )
            try:
                state.native_observation = _build_native_observation(run)
            except BaseException as exc:
                state.fail(
                    "transcript_validation",
                    "unexpected_error",
                    component_reason="native_observation_build_failed",
                    error_number=_exception_errno(exc),
                )
            if state.primary_stage is None and (
                state.native_observation is None
                or state.native_observation.transcript_replay != "accepted"
            ):
                state.fail(
                    "transcript_validation",
                    "native_transcript_rejected",
                    component_reason="native_replay_rejected",
                )
    except BaseException as exc:
        if state.native_run is not None and state.native_run.pid is not None:
            state.fail(
                "transcript_validation",
                "unexpected_error",
                component_reason="unexpected_post_spawn_exception",
                error_number=_exception_errno(exc),
            )
        elif state.retained_leaf_created and state.leaf_handoff_completed:
            state.fail(
                "launcher_setup",
                "unexpected_error",
                component_reason="unexpected_launcher_setup_exception",
                error_number=_exception_errno(exc),
            )
        elif state.retained_leaf_created:
            state.fail(
                "cgroup_handoff",
                "cgroup_handoff_failed",
                component_reason="unexpected_cgroup_handoff_exception",
                error_number=_exception_errno(exc),
            )
        else:
            state.fail(
                "cgroup_retention",
                "unexpected_error",
                component_reason="unexpected_cgroup_exception",
                error_number=_exception_errno(exc),
            )
    finally:
        if cleanup_deadline_ns is None:
            try:
                cleanup_deadline_ns = min(
                    overall_deadline_ns,
                    time.monotonic_ns() + policy.cleanup_timeout_ms * 1_000_000,
                )
            except BaseException as exc:
                cleanup_deadline_ns = overall_deadline_ns
                state.fail(
                    "cleanup",
                    "cleanup_incomplete",
                    component_reason="cleanup_clock_failed",
                    error_number=_exception_errno(exc),
                )
        if leaf_fd >= 0:
            closing_leaf_fd, leaf_fd = leaf_fd, -1
            state.leaf_fd_finalized = _finalize_descriptor(closing_leaf_fd)
        if active_executable_fd >= 0:
            closing_executable_fd, active_executable_fd = active_executable_fd, -1
            state.artifact_exec_finalized = _finalize_descriptor(
                closing_executable_fd
            )

        if retained is not None:
            state.cgroup_cleanup_attempted = True
            try:
                cleanup_timeout_ms = _remaining_cleanup_timeout_ms(
                    cleanup_deadline_ns,
                    policy.cleanup_timeout_ms,
                )
                state.cgroup_cleanup_duration_ms = retained.cleanup_with_timeout_ms(
                    cleanup_timeout_ms
                )
                state.cgroup_cleanup_completed = True
            except LinuxCgroupError as exc:
                state.cgroup_cleanup_failure_reason = exc.reason
            except BaseException:
                state.cgroup_cleanup_failure_reason = "unexpected_error"

        launcher_disposition_exact = (
            state.native_run is None
            or state.native_run.pid is None
            or state.native_run.launcher_reaped
        )
        if launcher_disposition_exact:
            try:
                (
                    state.adopted_descendants_reaped,
                    state.no_children_remaining,
                    reap_errno,
                ) = _reap_adopted_descendants(cleanup_deadline_ns)
                if not state.no_children_remaining:
                    state.fail(
                        "cleanup",
                        "cleanup_incomplete",
                        component_reason="adopted_descendant_reap_incomplete",
                        error_number=reap_errno,
                    )
            except BaseException as exc:
                state.fail(
                    "cleanup",
                    "cleanup_incomplete",
                    component_reason="adopted_descendant_reap_failed",
                    error_number=_exception_errno(exc),
                )
        else:
            state.no_children_remaining = False
            state.fail(
                "cleanup",
                "cleanup_incomplete",
                component_reason="launcher_disposition_unresolved",
            )

        _finalize_artifact_handle(artifact, state)

        if state.no_children_remaining:
            try:
                host_guard.restore()
                state.subreaper_restored = not host_guard.active
            except BaseException as exc:
                state.fail(
                    "cleanup",
                    "cleanup_incomplete",
                    component_reason="subreaper_restore_failed",
                    error_number=_exception_errno(exc),
                )

        if not state.artifact_exec_finalized:
            state.fail(
                "cleanup",
                "cleanup_incomplete",
                component_reason="artifact_descriptor_close_failed",
            )
        if not state.leaf_fd_finalized:
            state.fail(
                "cleanup",
                "cleanup_incomplete",
                component_reason="leaf_descriptor_close_failed",
            )
        if state.cgroup_cleanup_attempted and not state.cgroup_cleanup_completed:
            state.fail(
                "cleanup",
                "cleanup_incomplete",
                component_reason=state.cgroup_cleanup_failure_reason or "cgroup_cleanup_failed",
            )

    return _finish_result_before_deadline(
        policy=policy,
        cgroup_policy=cgroup_policy,
        artifact_receipt=artifact_receipt,
        attempt_receipt=attempt_receipt,
        attempt_receipt_sha256=attempt_receipt_sha256,
        state=state,
        cleanup_deadline_ns=cleanup_deadline_ns,
        overall_deadline_ns=overall_deadline_ns,
    )


def _release_prelaunch_resources(
    artifact: LinuxInertLauncherArtifact,
    staged_executable_fd: int,
    host_guard: _HostGuard | None,
    active_error: BaseException,
) -> None:
    if staged_executable_fd >= 0 and not _finalize_descriptor(staged_executable_fd):
        active_error.add_note("staged launcher descriptor closure also failed")
    if host_guard is not None and host_guard.active:
        try:
            host_guard.restore()
        except BaseException:
            active_error.add_note("dedicated subreaper restoration also failed")
    try:
        artifact.close()
    except BaseException:
        active_error.add_note("sealed launcher artifact closure also failed")


def _terminal_consumption_error(
    message: str,
    *,
    active_error: BaseException,
    recovery_error: BaseException | None = None,
) -> LinuxInertFixtureTerminalConsumptionError:
    terminal = LinuxInertFixtureTerminalConsumptionError(message)
    terminal.add_note(
        "the launch attempt is terminal and must not be retried because durable "
        "consumption safety could not be established"
    )
    terminal.add_note(f"triggering failure type: {type(active_error).__name__}")
    if recovery_error is not None:
        terminal.add_note(
            f"receipt recovery also failed ({type(recovery_error).__name__})"
        )
    return terminal


def _start_post_consumption_clock(
    artifact: LinuxInertLauncherArtifact,
    staged_executable_fd: int,
    host_guard: _HostGuard,
    active_error: BaseException | None,
) -> int:
    try:
        return time.monotonic_ns()
    except BaseException as clock_error:
        terminal = _terminal_consumption_error(
            "post-consumption monotonic clock could not be established",
            active_error=active_error or clock_error,
            recovery_error=clock_error,
        )
        _release_prelaunch_resources(
            artifact,
            staged_executable_fd,
            host_guard,
            terminal,
        )
        raise terminal from clock_error


def _finalize_consumed_without_launch(
    *,
    policy: InertFixturePolicy,
    cgroup_policy: LinuxCgroupV2QualificationPolicy,
    artifact: LinuxInertLauncherArtifact,
    artifact_receipt: LinuxInertLauncherArtifactPreflightReceipt,
    staged_executable_fd: int,
    attempt_receipt: InertFixtureLaunchAttemptReceipt,
    attempt_receipt_sha256: str,
    host_guard: _HostGuard,
    started_ns: int,
    failure_reason: Literal[
        "attempt_consumption_ambiguous",
        "attempt_receipt_verification_failed",
    ],
) -> LinuxInertFixtureOrchestrationResult:
    state = _ResultState()
    overall_deadline_ns = started_ns + policy.total_timeout_ms * 1_000_000
    cleanup_deadline_ns = min(
        overall_deadline_ns,
        started_ns + policy.cleanup_timeout_ms * 1_000_000,
    )
    state.fail(
        "attempt_finalization",
        failure_reason,
        component_reason=(
            "recovered_after_ambiguous_consumption"
            if failure_reason == "attempt_consumption_ambiguous"
            else "recovered_after_receipt_verification_failure"
        ),
    )
    if staged_executable_fd >= 0:
        state.artifact_exec_finalized = _finalize_descriptor(staged_executable_fd)
    try:
        (
            state.adopted_descendants_reaped,
            state.no_children_remaining,
            reap_errno,
        ) = _reap_adopted_descendants(cleanup_deadline_ns)
        if not state.no_children_remaining:
            state.fail(
                "cleanup",
                "cleanup_incomplete",
                component_reason="unexpected_prelaunch_child",
                error_number=reap_errno,
            )
    except BaseException as exc:
        state.fail(
            "cleanup",
            "cleanup_incomplete",
            component_reason="prelaunch_child_audit_failed",
            error_number=_exception_errno(exc),
        )
    _finalize_artifact_handle(artifact, state)
    if state.no_children_remaining:
        try:
            host_guard.restore()
            state.subreaper_restored = not host_guard.active
        except BaseException as exc:
            state.fail(
                "cleanup",
                "cleanup_incomplete",
                component_reason="subreaper_restore_failed",
                error_number=_exception_errno(exc),
            )
    if not state.artifact_exec_finalized:
        state.fail(
            "cleanup",
            "cleanup_incomplete",
            component_reason="artifact_descriptor_close_failed",
        )
    return _finish_result_before_deadline(
        policy=policy,
        cgroup_policy=cgroup_policy,
        artifact_receipt=artifact_receipt,
        attempt_receipt=attempt_receipt,
        attempt_receipt_sha256=attempt_receipt_sha256,
        state=state,
        cleanup_deadline_ns=cleanup_deadline_ns,
        overall_deadline_ns=overall_deadline_ns,
    )


def orchestrate_linux_inert_fixture(
    intent: SignedInertFixtureIntent,
    trust_store: InertFixtureIntentTrustStore,
    expectation: InertFixtureLaunchExpectation,
    claim_receipt: InertFixtureIntentClaimReceipt,
    claim_ledger: InertFixtureIntentLedger,
    cgroup_policy: LinuxCgroupV2QualificationPolicy,
    *,
    launch_ledger: InertFixtureLaunchLedger,
    launch_attempt_id: str,
    launcher_artifact_fd: int,
    delegated_root_fd: int,
) -> LinuxInertFixtureOrchestrationResult:
    """Run the one fixed fixture after exact preflight and one-shot consumption.

    The caller retains ownership of ``launcher_artifact_fd`` and
    ``delegated_root_fd``.  No path, command, caller-selected argv/environment,
    candidate, evaluation job, external fixture, or process callback is accepted.
    A failure before durable attempt consumption raises and creates no cgroup/process.
    A normally handled failure after consumption returns an unsigned terminal
    observation with retry fixed false.
    """

    policy, frozen_cgroup_policy = _freeze_policies(expectation, cgroup_policy)
    verify_inert_fixture_launch_attempt(
        intent,
        trust_store,
        expectation,
        claim_receipt,
        claim_ledger,
        now_unix=_current_unix_time(),
    )
    _preflight_launch_ledger(expectation, launch_ledger)
    artifact = preflight_inert_launcher_artifact(
        expectation,
        launcher_artifact_fd=launcher_artifact_fd,
    )
    staged_executable_fd = -1
    host_guard: _HostGuard | None = None
    try:
        artifact_receipt = artifact.receipt
        staged_executable_fd = _stage_executable_descriptor(artifact)
        host_guard = _prepare_host_guard()
    except BaseException as exc:
        _release_prelaunch_resources(
            artifact,
            staged_executable_fd,
            host_guard,
            exc,
        )
        raise

    try:
        attempt_receipt = admit_inert_fixture_launch_attempt(
            intent,
            trust_store,
            expectation,
            claim_receipt,
            claim_ledger,
            launch_ledger=launch_ledger,
            launch_attempt_id=launch_attempt_id,
        )
    except InertFixtureLaunchAttemptAlreadyConsumed as exc:
        _release_prelaunch_resources(
            artifact,
            staged_executable_fd,
            host_guard,
            exc,
        )
        raise
    except BaseException as exc:
        try:
            recovered_receipt = launch_ledger.recover_committed_receipt(
                intent,
                trust_store,
                expectation,
                claim_receipt,
                claim_ledger,
            )
        except BaseException as recovery_error:
            terminal = _terminal_consumption_error(
                "launch-attempt consumption is ambiguous and no receipt was recovered",
                active_error=exc,
                recovery_error=recovery_error,
            )
            _release_prelaunch_resources(
                artifact,
                staged_executable_fd,
                host_guard,
                terminal,
            )
            raise terminal from exc
        if host_guard is None:  # pragma: no cover - construction invariant
            raise AssertionError("receipt recovery has no active host guard") from exc
        started_ns = _start_post_consumption_clock(
            artifact,
            staged_executable_fd,
            host_guard,
            exc,
        )
        try:
            return _finalize_consumed_without_launch(
                policy=policy,
                cgroup_policy=frozen_cgroup_policy,
                artifact=artifact,
                artifact_receipt=artifact_receipt,
                staged_executable_fd=staged_executable_fd,
                attempt_receipt=recovered_receipt,
                attempt_receipt_sha256=sha256_json(recovered_receipt),
                host_guard=host_guard,
                started_ns=started_ns,
                failure_reason="attempt_consumption_ambiguous",
            )
        except BaseException as finalization_error:
            terminal = _terminal_consumption_error(
                "recovered launch-attempt consumption could not be finalized",
                active_error=finalization_error,
            )
            raise terminal from finalization_error

    if host_guard is None:  # pragma: no cover - construction invariant
        raise AssertionError("orchestration consumed an attempt without a host guard")
    try:
        attempt_receipt_sha256 = launch_ledger.verify_committed_receipt(
            attempt_receipt
        )
    except BaseException as exc:
        try:
            recovered_receipt = launch_ledger.recover_committed_receipt(
                intent,
                trust_store,
                expectation,
                claim_receipt,
                claim_ledger,
            )
            if recovered_receipt != attempt_receipt:
                raise ValueError("recovered receipt differs from the consumed receipt")
        except BaseException as recovery_error:
            terminal = _terminal_consumption_error(
                "consumed launch-attempt receipt could not be verified or recovered",
                active_error=exc,
                recovery_error=recovery_error,
            )
            _release_prelaunch_resources(
                artifact,
                staged_executable_fd,
                host_guard,
                terminal,
            )
            raise terminal from exc
        started_ns = _start_post_consumption_clock(
            artifact,
            staged_executable_fd,
            host_guard,
            exc,
        )
        try:
            return _finalize_consumed_without_launch(
                policy=policy,
                cgroup_policy=frozen_cgroup_policy,
                artifact=artifact,
                artifact_receipt=artifact_receipt,
                staged_executable_fd=staged_executable_fd,
                attempt_receipt=recovered_receipt,
                attempt_receipt_sha256=sha256_json(recovered_receipt),
                host_guard=host_guard,
                started_ns=started_ns,
                failure_reason="attempt_receipt_verification_failed",
            )
        except BaseException as finalization_error:
            terminal = _terminal_consumption_error(
                "recovered launch-attempt receipt could not be finalized",
                active_error=finalization_error,
            )
            raise terminal from finalization_error

    started_ns = _start_post_consumption_clock(
        artifact,
        staged_executable_fd,
        host_guard,
        None,
    )
    try:
        return _orchestrate_consumed_attempt(
            policy=policy,
            cgroup_policy=frozen_cgroup_policy,
            artifact=artifact,
            artifact_receipt=artifact_receipt,
            staged_executable_fd=staged_executable_fd,
            attempt_receipt=attempt_receipt,
            attempt_receipt_sha256=attempt_receipt_sha256,
            host_guard=host_guard,
            delegated_root_fd=delegated_root_fd,
            started_ns=started_ns,
        )
    except BaseException as exc:
        terminal = _terminal_consumption_error(
            "post-consumption orchestration could not produce terminal evidence",
            active_error=exc,
        )
        raise terminal from exc


def validate_linux_inert_fixture_orchestration_result(
    result: LinuxInertFixtureOrchestrationResult,
) -> LinuxInertFixtureOrchestrationResult:
    """Strictly freeze and replay one already parsed orchestration result."""

    if type(result) is not LinuxInertFixtureOrchestrationResult:
        raise LinuxInertFixtureOrchestrationError(
            "orchestration result has the wrong dedicated type"
        )
    try:
        return LinuxInertFixtureOrchestrationResult.model_validate(
            result.model_dump(mode="python"),
            strict=True,
        )
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise LinuxInertFixtureOrchestrationError(
            "orchestration result is invalid"
        ) from exc


def canonical_linux_inert_fixture_orchestration_result_bytes(
    result: LinuxInertFixtureOrchestrationResult,
) -> bytes:
    """Return canonical bounded bytes after strict replay validation."""

    raw = canonical_json_bytes(
        validate_linux_inert_fixture_orchestration_result(result)
    )
    if len(raw) > MAX_LINUX_INERT_FIXTURE_ORCHESTRATION_RESULT_BYTES:
        raise LinuxInertFixtureOrchestrationError(
            "orchestration result exceeds its fixed byte bound"
        )
    return raw


def validate_linux_inert_fixture_orchestration_result_bytes(
    raw: bytes,
) -> LinuxInertFixtureOrchestrationResult:
    """Reject noncanonical, duplicated-key, oversized, or invalid result bytes."""

    if (
        type(raw) is not bytes
        or not 1
        <= len(raw)
        <= MAX_LINUX_INERT_FIXTURE_ORCHESTRATION_RESULT_BYTES
    ):
        raise LinuxInertFixtureOrchestrationError(
            "orchestration result bytes are absent or oversized"
        )
    try:
        parsed = strict_json_loads(raw)
        result = LinuxInertFixtureOrchestrationResult.model_validate(
            parsed,
            strict=True,
        )
        if raw != canonical_json_bytes(result):
            raise ValueError("orchestration result bytes are not canonical")
    except (CanonicalJSONError, TypeError, ValidationError, ValueError) as exc:
        raise LinuxInertFixtureOrchestrationError(
            "orchestration result bytes are invalid"
        ) from exc
    return result


JSON_SCHEMAS: dict[str, type[BaseModel]] = {
    "linux-inert-fixture-orchestration-result-v1.json": (
        LinuxInertFixtureOrchestrationResult
    ),
}


__all__ = [
    "JSON_SCHEMAS",
    "LINUX_INERT_FIXTURE_NATIVE_OBSERVATION_DOMAIN",
    "LINUX_INERT_FIXTURE_ORCHESTRATION_RESULT_DOMAIN",
    "MAX_LINUX_INERT_FIXTURE_ORCHESTRATION_RESULT_BYTES",
    "LinuxInertFixtureCleanupEvidence",
    "LinuxInertFixtureNativeObservation",
    "LinuxInertFixtureNativeSocketRecord",
    "LinuxInertFixtureOrchestrationError",
    "LinuxInertFixtureOrchestrationPreflightError",
    "LinuxInertFixtureOrchestrationResult",
    "canonical_linux_inert_fixture_orchestration_result_bytes",
    "orchestrate_linux_inert_fixture",
    "validate_linux_inert_fixture_orchestration_result",
    "validate_linux_inert_fixture_orchestration_result_bytes",
]
