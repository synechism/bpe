"""Native Linux gate for cgroup-v2 qualification and production orchestration.

Run only as PID 1 in a disposable privileged cgroup namespace.  The script creates an
empty sibling delegation root while keeping itself in a separate manager cgroup.  It
first preserves the nonexecution qualification boundary, then gives the production
orchestrator one signed, one-shot authority to run only the built-in no-exec fixture.
It never accepts or launches a candidate or an external fixture.
"""

from __future__ import annotations

import base64
import json
import os
import platform
import re
import secrets
import stat
import sys
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bpe.canonical import canonical_data, sha256_json
from bpe.cgroup import LinuxCgroupV2QualificationPolicy, qualify_linux_cgroup_v2
from bpe.dispatch import ExecutionResourceProfile
from bpe.inert_artifact import FIXED_SECCOMP_POLICY_ID, FIXED_SECCOMP_POLICY_SHA256
from bpe.inert_fixture import (
    InertFixtureIntentLedger,
    InertFixtureIntentPayload,
    InertFixtureIntentTrustKey,
    InertFixtureIntentTrustStore,
    InertFixturePolicy,
    SignedInertFixtureIntent,
    inert_fixture_intent_expectation_for,
    inert_fixture_intent_signing_bytes,
)
from bpe.inert_launch import (
    InertFixtureLaunchLedger,
    inert_fixture_launch_expectation_for,
)
from bpe.inert_orchestration import (
    LinuxInertFixtureOrchestrationResult,
    canonical_linux_inert_fixture_orchestration_result_bytes,
    orchestrate_linux_inert_fixture,
    validate_linux_inert_fixture_orchestration_result_bytes,
)

_LAUNCHER = Path("/launcher")
_PROBE = Path("/probe.py")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


def _write_control(path: Path, value: str) -> None:
    path.write_text(value + "\n", encoding="ascii")


def _base64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _descriptor_identity(descriptor: int) -> tuple[int, int, int, int, int, int]:
    metadata = os.fstat(descriptor)
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
    )


def _require_no_child_cgroups(delegate: Path, *, phase: str) -> None:
    children = tuple(sorted(entry.name for entry in delegate.iterdir() if entry.is_dir()))
    if children:
        raise RuntimeError(f"{phase} left child cgroups behind: {children}")


def _fixture_policy(
    cgroup_policy: LinuxCgroupV2QualificationPolicy,
    profile: ExecutionResourceProfile,
    *,
    launcher_sha256: str,
) -> InertFixturePolicy:
    return InertFixturePolicy(
        schema_version="bpe.inert-fixture-policy.v1",
        policy_id="native-production-orchestration-policy-v1",
        worker_pool_audience=cgroup_policy.worker_pool_audience,
        worker_instance_id="native-production-orchestration-worker-001",
        claim_ledger_id="native-production-orchestration-claims-v1",
        launch_ledger_id="native-production-orchestration-launches-v1",
        claim_scope="single-configured-worker-ledger-v1",
        delegated_root_id=cgroup_policy.delegated_root_id,
        host_platform="linux",
        host_architecture="x86_64",
        purpose="inert_fixture_qualification",
        operation="qualify-clone3-inert-noexec-v1",
        launcher_kind="spawned-one-shot-executable-v1",
        launcher_artifact_id="native-production-launcher-amd64-v1",
        launcher_artifact_sha256=launcher_sha256,
        launcher_seccomp_policy_id=FIXED_SECCOMP_POLICY_ID,
        launcher_seccomp_policy_sha256=FIXED_SECCOMP_POLICY_SHA256,
        launcher_protocol_version="bpe.clone3-inert-launcher-protocol.v1",
        launcher_launch_method="fixed-one-shot-executable-v1",
        launcher_fd_layout="stdio-null-control-3-cgroup-4-v1",
        launcher_argv_environment="argc-one-empty-environment-v1",
        ipc_method="unix-seqpacket-fixed-frame-v1",
        fixture_kind="builtin-noexec-fixed-v1",
        fixture_protocol_id="bpe.clone3-inert-fixture-protocol.v1",
        process_creation_method="clone3-into-cgroup-pidfd-v1",
        pidfd_signal_method="pidfd-send-signal-v1",
        wait_method="waitid-p-pidfd-v1",
        deadline_method="clock-monotonic-absolute-v1",
        cleanup_method="cgroup-kill-events-rmdir-v1",
        resources=profile,
        resource_profile_sha256=sha256_json(profile),
        fixture_timeout_ms=5000,
        cleanup_timeout_ms=5000,
        total_timeout_ms=10_000,
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


def _fixture_payload(
    policy: InertFixturePolicy,
    *,
    now_unix: int,
) -> InertFixtureIntentPayload:
    return InertFixtureIntentPayload(
        schema_version="bpe.inert-fixture-intent-payload.v1",
        intent_id="native-production-orchestration-intent-001",
        intent_nonce=secrets.token_hex(32),
        purpose=policy.purpose,
        operation=policy.operation,
        policy_id=policy.policy_id,
        policy_sha256=sha256_json(policy),
        worker_pool_audience=policy.worker_pool_audience,
        worker_instance_id=policy.worker_instance_id,
        claim_ledger_id=policy.claim_ledger_id,
        launch_ledger_id=policy.launch_ledger_id,
        claim_scope=policy.claim_scope,
        delegated_root_id=policy.delegated_root_id,
        launcher_kind=policy.launcher_kind,
        launcher_artifact_id=policy.launcher_artifact_id,
        launcher_artifact_sha256=policy.launcher_artifact_sha256,
        launcher_seccomp_policy_id=policy.launcher_seccomp_policy_id,
        launcher_seccomp_policy_sha256=policy.launcher_seccomp_policy_sha256,
        launcher_protocol_version=policy.launcher_protocol_version,
        launcher_launch_method=policy.launcher_launch_method,
        fixture_kind=policy.fixture_kind,
        fixture_protocol_id=policy.fixture_protocol_id,
        resource_profile_id=policy.resources.profile_id,
        resource_profile_sha256=policy.resource_profile_sha256,
        fixture_timeout_ms=policy.fixture_timeout_ms,
        cleanup_timeout_ms=policy.cleanup_timeout_ms,
        total_timeout_ms=policy.total_timeout_ms,
        issued_at_unix=now_unix - 1,
        not_before_unix=now_unix - 1,
        expires_at_unix=now_unix + 300,
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


def _require_private_ledger(path: Path) -> None:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise RuntimeError("production orchestration ledger is not private")


def _require_success_result(result: LinuxInertFixtureOrchestrationResult) -> None:
    native = result.native_observation
    cleanup = result.cleanup
    if (
        result.terminal_outcome != "fixture_succeeded"
        or not result.retained_leaf_created
        or not result.leaf_handoff_completed
        or not result.launcher_process_created
        or not result.launcher_exec_observed
        or not result.fixture_child_process_observed
        or not result.cleanup_deadline_observed
        or not result.total_deadline_observed
        or result.orchestration_failure_stage is not None
        or result.orchestration_failure_reason is not None
        or result.orchestration_failure_component_reason is not None
        or result.orchestration_failure_errno is not None
        or native is None
        or native.transcript_replay != "accepted"
        or native.transcript_succeeded is not True
        or native.launcher_returncode != 0
        or not native.eof_observed
        or native.fixture_child_pid is None
        or cleanup.status != "completed"
        or not cleanup.launcher_waited_exact
        or not cleanup.launcher_reaped
        or cleanup.launcher_termination_attempted
        or cleanup.launcher_termination_signal_sent
        or cleanup.launcher_termination_errno is not None
        or not cleanup.control_socket_finalized
        or not cleanup.staging_descriptors_finalized
        or not cleanup.artifact_executable_fd_finalized
        or not cleanup.leaf_handoff_fd_finalized
        or not cleanup.cgroup_cleanup_attempted
        or not cleanup.cgroup_cleanup_completed
        or cleanup.cgroup_cleanup_duration_ms is None
        or cleanup.cgroup_cleanup_failure_reason is not None
        or cleanup.cgroup_retention_cleanup_uncertain
        or cleanup.adopted_descendants_reaped != 0
        or not cleanup.no_children_remaining
        or not cleanup.subreaper_restored
        or not cleanup.artifact_handle_closed
        or result.retry_permitted
        or result.durable
        or result.authoritative
        or result.official_grading_eligible
    ):
        raise RuntimeError("production orchestration did not return exact fixture success")


def _run_production_orchestration(
    cgroup_policy: LinuxCgroupV2QualificationPolicy,
    profile: ExecutionResourceProfile,
    *,
    launcher_sha256: str,
    launcher_fd: int,
    delegated_root_fd: int,
) -> LinuxInertFixtureOrchestrationResult:
    with tempfile.TemporaryDirectory(
        prefix="bpe-production-orchestration-",
        dir="/tmp",
    ) as raw_private_root:
        private_root = Path(raw_private_root).resolve(strict=True)
        root_metadata = private_root.stat()
        if (
            root_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(root_metadata.st_mode) != 0o700
        ):
            raise RuntimeError("production orchestration state root is not private")

        policy = _fixture_policy(
            cgroup_policy,
            profile,
            launcher_sha256=launcher_sha256,
        )
        claim_ledger = InertFixtureIntentLedger.provision(
            private_root / "claims.sqlite3",
            ledger_id=policy.claim_ledger_id,
            worker_instance_id=policy.worker_instance_id,
        )
        launch_ledger = InertFixtureLaunchLedger.provision(
            private_root / "launches.sqlite3",
            ledger_id=policy.launch_ledger_id,
            worker_instance_id=policy.worker_instance_id,
            claim_ledger_id=policy.claim_ledger_id,
        )
        _require_private_ledger(claim_ledger.path)
        _require_private_ledger(launch_ledger.path)

        intent_expectation = inert_fixture_intent_expectation_for(
            policy,
            expected_policy_sha256=sha256_json(policy),
            expected_worker_pool_audience=policy.worker_pool_audience,
            expected_worker_instance_id=policy.worker_instance_id,
            expected_claim_ledger_id=policy.claim_ledger_id,
            expected_claim_ledger_path=claim_ledger.path,
            expected_launch_ledger_id=policy.launch_ledger_id,
            expected_delegated_root_id=policy.delegated_root_id,
            expected_launcher_artifact_id=policy.launcher_artifact_id,
            expected_launcher_artifact_sha256=policy.launcher_artifact_sha256,
            expected_launcher_seccomp_policy_id=policy.launcher_seccomp_policy_id,
            expected_launcher_seccomp_policy_sha256=(
                policy.launcher_seccomp_policy_sha256
            ),
        )

        now_unix = time.time_ns() // 1_000_000_000
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        payload = _fixture_payload(policy, now_unix=now_unix)
        key_id = "native-production-orchestration-key-1"
        intent = SignedInertFixtureIntent(
            schema_version="bpe.signed-inert-fixture-intent.v1",
            algorithm="Ed25519",
            key_id=key_id,
            payload=payload,
            payload_sha256=sha256_json(payload),
            signature_base64url=_base64url(
                private_key.sign(inert_fixture_intent_signing_bytes(payload))
            ),
        )
        trust_store = InertFixtureIntentTrustStore(
            schema_version="bpe.inert-fixture-intent-trust-store.v1",
            trust_store_id="native-production-orchestration-trust-v1",
            keys=(
                InertFixtureIntentTrustKey(
                    key_id=key_id,
                    algorithm="Ed25519",
                    public_key_base64url=_base64url(public_key),
                    valid_from_unix=now_unix - 60,
                    valid_until_unix=now_unix + 600,
                ),
            ),
        )
        claim_receipt = claim_ledger.claim_intent(
            intent,
            trust_store,
            intent_expectation,
            claim_id=secrets.token_hex(32),
        )
        launch_expectation = inert_fixture_launch_expectation_for(
            intent_expectation,
            expected_launch_ledger_path=launch_ledger.path,
            expected_worker_instance_id=policy.worker_instance_id,
            expected_claim_ledger_id=policy.claim_ledger_id,
            expected_launch_ledger_id=policy.launch_ledger_id,
        )

        result = orchestrate_linux_inert_fixture(
            intent,
            trust_store,
            launch_expectation,
            claim_receipt,
            claim_ledger,
            cgroup_policy,
            launch_ledger=launch_ledger,
            launch_attempt_id=secrets.token_hex(32),
            launcher_artifact_fd=launcher_fd,
            delegated_root_fd=delegated_root_fd,
        )
        _require_success_result(result)
        if claim_ledger.claim_count() != 1 or launch_ledger.attempt_count() != 1:
            raise RuntimeError("production orchestration did not consume exactly one attempt")
        if claim_ledger.verify_committed_receipt(claim_receipt) != sha256_json(
            claim_receipt
        ):
            raise RuntimeError("production orchestration claim receipt is not durable")
        if (
            launch_ledger.verify_committed_receipt(result.launch_attempt_receipt)
            != result.launch_attempt_receipt_sha256
        ):
            raise RuntimeError("production orchestration launch receipt is not durable")
        if (
            launch_ledger.recover_committed_receipt(
                intent,
                trust_store,
                launch_expectation,
                claim_receipt,
                claim_ledger,
            )
            != result.launch_attempt_receipt
        ):
            raise RuntimeError("production orchestration launch receipt did not recover exactly")

        result_bytes = canonical_linux_inert_fixture_orchestration_result_bytes(result)
        replayed = validate_linux_inert_fixture_orchestration_result_bytes(result_bytes)
        if (
            replayed != result
            or canonical_linux_inert_fixture_orchestration_result_bytes(replayed)
            != result_bytes
        ):
            raise RuntimeError("production orchestration result did not replay exactly")
        return result


def main() -> None:
    if sys.platform != "linux" or os.getpid() != 1 or os.geteuid() != 0:
        raise RuntimeError("native cgroup probe requires Linux PID 1 with effective UID 0")

    launcher_sha256 = os.environ.get("BPE_LAUNCHER_SHA256", "")
    if not _SHA256_PATTERN.fullmatch(launcher_sha256):
        raise RuntimeError("native cgroup probe requires a lowercase launcher SHA-256")
    if Path(__file__).resolve() != _PROBE or not _LAUNCHER.is_file():
        raise RuntimeError("native cgroup probe inputs are not at their fixed mount targets")

    native_architecture = platform.machine()
    if native_architecture != "x86_64":
        raise RuntimeError("native cgroup probe requires x86_64")

    root = Path("/sys/fs/cgroup")
    suffix = secrets.token_hex(8)
    manager = root / f"bpe-native-manager-{suffix}"
    delegate = root / f"bpe-native-delegate-{suffix}"
    manager.mkdir()
    _write_control(manager / "cgroup.procs", str(os.getpid()))
    _write_control(root / "cgroup.subtree_control", "+cpu +memory +pids")
    delegate.mkdir()
    _write_control(delegate / "cgroup.subtree_control", "+cpu +memory +pids")
    # The container has no systemd manager.  This installs the exact kernel xattr
    # convention that production checks; systemd provisioning is a separate deployment
    # obligation and the report never treats the marker as proof of provenance.
    os.setxattr(delegate, b"user.delegate", b"1")

    policy = LinuxCgroupV2QualificationPolicy(
        schema_version="bpe.linux-cgroup-v2-qualification-policy.v1",
        policy_id="native-empty-cgroup-qualification-v1",
        worker_pool_audience="native-probe-workers",
        delegated_root_id="disposable-container-delegate",
        host_platform="linux",
        host_architecture="x86_64",
        filesystem="cgroup2-v2",
        delegation_method="systemd-user.delegate-xattr-v1",
        delegated_owner="current-euid",
        delegated_root_group_other_writable=False,
        root_cgroup_type="domain",
        root_empty_required=True,
        root_without_children_required=True,
        required_controllers=("cpu", "memory", "pids"),
        subtree_control_exact=True,
        component_open_method="openat2-v1",
        resolve_beneath=True,
        resolve_no_xdev=True,
        resolve_no_symlinks=True,
        resolve_no_magiclinks=True,
        openat2_eagain_retries=3,
        leaf_name_method="random-256-bit-v1",
        memory_limit_method="memory.max-v1",
        swap_limit_method="memory.swap.max-zero-v1",
        pids_limit_method="pids.max-v1",
        cpu_limit_method="cpu.max-one-cpu-equivalent-bandwidth-v1",
        cpu_quota_us=100_000,
        cpu_period_us=100_000,
        cpu_burst_us=0,
        base_page_size_bytes=4096,
        oom_group_method="memory.oom.group-v1",
        leaf_max_depth=0,
        leaf_max_descendants=0,
        cleanup_method="cgroup.kill-events-rmdir-v1",
        cleanup_timeout_ms=5000,
        process_creation_probed=False,
        execution_permitted=False,
        candidate_access_permitted=False,
        resource_profile_fully_enforced=False,
        authoritative_ready=False,
    )
    profile = ExecutionResourceProfile(
        schema_version="bpe.execution-resource-profile.v1",
        profile_id="native-empty-cgroup-resources-v1",
        wall_timeout_ms=30_000,
        cpu_time_seconds=20,
        memory_bytes=256 * 1024 * 1024,
        swap_bytes=0,
        pids_max=32,
        open_files_max=64,
        file_size_bytes=16 * 1024 * 1024,
        stack_bytes=8 * 1024 * 1024,
        stdout_bytes=256 * 1024,
        stderr_bytes=256 * 1024,
        tmpfs_bytes=64 * 1024 * 1024,
        tmpfs_inodes=4096,
        network_enabled=False,
        core_dumps_enabled=False,
    )

    delegate_fd = -1
    launcher_fd = -1
    try:
        delegate_fd = os.open(delegate, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        launcher_fd = os.open(_LAUNCHER, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        delegate_identity = _descriptor_identity(delegate_fd)
        launcher_identity = _descriptor_identity(launcher_fd)
        report = qualify_linux_cgroup_v2(policy, profile, delegated_root_fd=delegate_fd)
        if _descriptor_identity(delegate_fd) != delegate_identity:
            raise RuntimeError("qualification changed the caller-owned delegated-root fd")
        _require_no_child_cgroups(delegate, phase="empty-leaf qualification")
        if (
            report.execution_started
            or report.clone3_qualified
            or report.limits_exercised
            or not report.cgroup_kill_empty_write_verified
            or not report.leaf_name_removed
        ):
            raise RuntimeError(
                "native qualification report crossed its nonexecution boundary"
            )
        orchestration_result = _run_production_orchestration(
            policy,
            profile,
            launcher_sha256=launcher_sha256,
            launcher_fd=launcher_fd,
            delegated_root_fd=delegate_fd,
        )
        if (
            _descriptor_identity(delegate_fd) != delegate_identity
            or _descriptor_identity(launcher_fd) != launcher_identity
            or os.get_inheritable(delegate_fd)
            or os.get_inheritable(launcher_fd)
        ):
            raise RuntimeError("production orchestration changed a caller-owned descriptor")
        _require_no_child_cgroups(delegate, phase="production orchestration")
    finally:
        if launcher_fd >= 0:
            os.close(launcher_fd)
        if delegate_fd >= 0:
            os.close(delegate_fd)

    _require_no_child_cgroups(delegate, phase="final qualification audit")
    delegate.rmdir()
    print(
        json.dumps(
            {
                "native_architecture": native_architecture,
                "orchestration_result": canonical_data(orchestration_result),
                "report": canonical_data(report),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
