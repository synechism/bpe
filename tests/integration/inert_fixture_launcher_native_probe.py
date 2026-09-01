"""Privileged live-cgroup gate for the fixed native inert-fixture launcher.

Run this script only as PID 1 in a disposable privileged container with a private
cgroup namespace.  It deliberately stays separate from production orchestration:
its only inputs are the pinned launcher artifact and fresh cgroup-v2 leaves created
inside that disposable namespace.
"""

from __future__ import annotations

import argparse
import array
import contextlib
import ctypes
import errno
import fcntl
import hashlib
import importlib.metadata
import os
import platform
import re
import secrets
import signal
import socket
import stat
import struct
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Literal, cast

import bpe
import bpe.inert_native_qualification as native_qualification
from bpe.canonical import canonical_json_bytes, sha256_bytes, sha256_json, strict_json_loads
from bpe.dispatch import ExecutionResourceProfile
from bpe.inert_artifact import (
    F_GET_SEALS_LINUX,
    FIXED_SECCOMP_POLICY_ID,
    FIXED_SECCOMP_POLICY_SHA256,
    MAX_LAUNCHER_ARTIFACT_BYTES,
    LinuxInertLauncherArtifact,
    preflight_inert_launcher_artifact,
)
from bpe.inert_fixture import InertFixturePolicy, inert_fixture_intent_expectation_for
from bpe.inert_launch import (
    InertFixtureLaunchExpectation,
    inert_fixture_launch_expectation_for,
)
from bpe.inert_native_protocol import (
    ACHIEVED_RESULT_MASK,
    PROTOCOL_FRAME_SIZE,
    PROTOCOL_MAX_FRAMES,
    InertNativeProtocolViolation,
    InertNativeSocketRecord,
    NativeExitCode,
    NativeFrameType,
    NativeReason,
    NativeStage,
    parse_inert_native_transcript,
)
from bpe.inert_native_qualification import (
    MAX_NATIVE_QUALIFICATION_BUILT_WHEEL_BYTES,
    MAX_NATIVE_QUALIFICATION_PROVENANCE_BYTES,
    MAX_NATIVE_QUALIFICATION_REPORT_BYTES,
    MAX_NATIVE_QUALIFICATION_RUNTIME_DISTRIBUTIONS,
    MAX_NATIVE_QUALIFICATION_RUNTIME_FILES,
    MAX_NATIVE_QUALIFICATION_RUNTIME_TOTAL_BYTES,
    MAX_NATIVE_QUALIFICATION_SOURCE_FILE_BYTES,
    MAX_NATIVE_QUALIFICATION_SOURCE_TOTAL_BYTES,
    MAX_NATIVE_QUALIFICATION_TRACKED_TREE_FILES,
    MAX_NATIVE_QUALIFICATION_TRACKED_TREE_MANIFEST_BYTES,
    MAX_NATIVE_QUALIFICATION_TRACKED_TREE_TOTAL_BYTES,
    NATIVE_QUALIFICATION_BPE_DISTRIBUTION_VERSION,
    NATIVE_QUALIFICATION_BPE_SOURCE_PATHS,
    NATIVE_QUALIFICATION_BUILT_WHEEL_PATH,
    NATIVE_QUALIFICATION_CASE_SET_ID,
    NATIVE_QUALIFICATION_CASE_SET_SHA256,
    NATIVE_QUALIFICATION_CASES,
    NATIVE_QUALIFICATION_FAULT_PROFILE_ID,
    NATIVE_QUALIFICATION_INVOCATION_DOMAIN,
    NATIVE_QUALIFICATION_OUTER_SECCOMP_CONTRACT_SHA256,
    NATIVE_QUALIFICATION_OUTER_SECCOMP_INSTRUCTIONS,
    NATIVE_QUALIFICATION_PARSER_ID,
    NATIVE_QUALIFICATION_RUNTIME_INSTALLER_PATHS,
    NATIVE_QUALIFICATION_SOURCE_PATHS,
    NATIVE_QUALIFICATION_WHEEL_DIST_INFO_PATHS,
    LinuxInertLauncherNativeQualificationReport,
    NativeQualificationArtifact,
    NativeQualificationArtifactDuplicate,
    NativeQualificationBuildTools,
    NativeQualificationCase,
    NativeQualificationCaseCleanup,
    NativeQualificationContainer,
    NativeQualificationContainerInvocation,
    NativeQualificationFinalization,
    NativeQualificationHost,
    NativeQualificationMountBinding,
    NativeQualificationNamespaceIdentity,
    NativeQualificationRuntimeDistribution,
    NativeQualificationSourceManifest,
    NativeQualificationSourceRun,
    NativeQualificationUpstreamWorkflowRun,
    build_inert_native_qualification_case,
    canonical_inert_native_qualification_report_bytes,
    inert_native_qualification_id,
    native_qualification_commit_bpe_tree_manifest_sha256,
    native_qualification_context_sha256,
    native_qualification_github_context_bytes,
    native_qualification_runtime_dependency_manifest_sha256,
    validate_inert_native_qualification_report_bytes,
)

_LAUNCHER_ARGV0 = "bpe-inert-fixture-launcher"
_CASE_TIMEOUT_SECONDS = 45.0
_EXTRA_DESCRIPTOR = 257
_SOURCE_DESCRIPTOR_MINIMUM = 512
_ARTIFACT_DESCRIPTOR_MINIMUM = 1024
_QUALIFICATION_OUTPUT_DIRECTORY = Path("/qualification-output")
_QUALIFICATION_OUTPUT_NAME = "native-launcher-qualification-report.json"
_RUNTIME_ROOT = Path("/runtime")
_DEPENDENCY_ROOT = Path("/dependencies")
_BUILT_WHEEL_PATH = Path(NATIVE_QUALIFICATION_BUILT_WHEEL_PATH)
_SOURCE_ROOT = Path("/qualification-source")
_PROVENANCE_PATH = Path("/qualification-provenance/context.json")
_TRACKED_TREE_MANIFEST_PATH = Path(
    "/qualification-provenance/tracked-tree-content-manifest.json"
)
_MAX_PROVENANCE_BYTES = MAX_NATIVE_QUALIFICATION_PROVENANCE_BYTES
_MAX_TRACKED_TREE_MANIFEST_BYTES = MAX_NATIVE_QUALIFICATION_TRACKED_TREE_MANIFEST_BYTES
_MAX_TRACKED_TREE_FILES = MAX_NATIVE_QUALIFICATION_TRACKED_TREE_FILES
_MAX_SOURCE_FILE_BYTES = MAX_NATIVE_QUALIFICATION_SOURCE_FILE_BYTES
_MAX_SOURCE_TOTAL_BYTES = MAX_NATIVE_QUALIFICATION_SOURCE_TOTAL_BYTES
_MAX_RUNTIME_DISTRIBUTIONS = MAX_NATIVE_QUALIFICATION_RUNTIME_DISTRIBUTIONS
_MAX_RUNTIME_FILES = MAX_NATIVE_QUALIFICATION_RUNTIME_FILES
_MAX_RUNTIME_TOTAL_BYTES = MAX_NATIVE_QUALIFICATION_RUNTIME_TOTAL_BYTES
_RENAMEAT2_SYSCALL_X86_64 = 316
_RENAME_NOREPLACE = 1
_CGROUP2_SUPER_MAGIC = 0x63677270
_SOCK_CLOEXEC_LINUX = 0o2000000
_MSG_CMSG_CLOEXEC = getattr(socket, "MSG_CMSG_CLOEXEC", 0)
_SCM_RIGHTS_ITEM_SIZE = array.array("i").itemsize
# Linux rejects SCM_RIGHTS messages containing more than SCM_MAX_FD descriptors.
_CONTROL_ANCILLARY_SIZE = socket.CMSG_SPACE(253 * _SCM_RIGHTS_ITEM_SIZE)

_PR_GET_SECCOMP = 21
_PR_SET_NO_NEW_PRIVS = 38
_PR_GET_NO_NEW_PRIVS = 39
_SECCOMP_SET_MODE_FILTER = 1
_SECCOMP_MODE_FILTER = 2
_SYS_SECCOMP_X86_64 = 317
_SYS_PIDFD_SEND_SIGNAL_X86_64 = 424
_AUDIT_ARCH_X86_64 = 0xC000003E
_X32_SYSCALL_BIT = 0x40000000

_BPF_LD_W_ABS = 0x20
_BPF_JMP_JEQ_K = 0x15
_BPF_JMP_JGE_K = 0x35
_BPF_RET_K = 0x06
_SECCOMP_RET_KILL_PROCESS = 0x80000000
_SECCOMP_RET_ERRNO = 0x00050000
_SECCOMP_RET_ALLOW = 0x7FFF0000

# This evaluator-only inherited filter denies both the launcher's normal SIGSTOP and
# emergency SIGKILL pidfd calls.  The x32 ABI shares AUDIT_ARCH_X86_64, so reject its
# tagged syscall range rather than silently permitting an ABI-bypass variant.
_PIDFD_DENIAL_FILTER = (
    (_BPF_LD_W_ABS, 0, 0, 4),
    (_BPF_JMP_JEQ_K, 1, 0, _AUDIT_ARCH_X86_64),
    (_BPF_RET_K, 0, 0, _SECCOMP_RET_KILL_PROCESS),
    (_BPF_LD_W_ABS, 0, 0, 0),
    (_BPF_JMP_JGE_K, 0, 1, _X32_SYSCALL_BIT),
    (_BPF_RET_K, 0, 0, _SECCOMP_RET_KILL_PROCESS),
    (_BPF_JMP_JEQ_K, 0, 1, _SYS_PIDFD_SEND_SIGNAL_X86_64),
    (_BPF_RET_K, 0, 0, _SECCOMP_RET_ERRNO | errno.EPERM),
    (_BPF_RET_K, 0, 0, _SECCOMP_RET_ALLOW),
)


class _SockFilter(ctypes.Structure):
    _fields_ = (
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    )


class _SockFprog(ctypes.Structure):
    _fields_ = (
        ("length", ctypes.c_ushort),
        ("filter", ctypes.POINTER(_SockFilter)),
    )


class _StatFs(ctypes.Structure):
    _fields_ = (
        ("f_type", ctypes.c_long),
        ("f_bsize", ctypes.c_long),
        ("f_blocks", ctypes.c_ulonglong),
        ("f_bfree", ctypes.c_ulonglong),
        ("f_bavail", ctypes.c_ulonglong),
        ("f_files", ctypes.c_ulonglong),
        ("f_ffree", ctypes.c_ulonglong),
        ("f_fsid", ctypes.c_int * 2),
        ("f_namelen", ctypes.c_long),
        ("f_frsize", ctypes.c_long),
        ("f_flags", ctypes.c_long),
        ("f_spare", ctypes.c_long * 4),
    )


_LIBC = ctypes.CDLL(None, use_errno=True)


@dataclass(frozen=True, slots=True)
class _LaunchResult:
    pid: int
    returncode: int
    records: tuple[InertNativeSocketRecord, ...]
    eof_observed: bool


@dataclass(frozen=True, slots=True)
class _DuplicateSeal:
    sha256: str
    size_bytes: int
    device: int
    inode: int
    mode: int
    nlink: int
    seals: int
    readonly_verified: bool
    cloexec_verified: bool
    identity_verified: bool


@dataclass(frozen=True, slots=True)
class _CaseObservation:
    case_name: str
    result: _LaunchResult
    parser_outcome: Literal["accepted", "rejected"]
    parser_value: object | None
    parser_rejection: Literal["empty_transcript", "eof_not_observed"] | None
    duplicate: _DuplicateSeal
    strict_cleanup_complete: bool


@dataclass(frozen=True, slots=True)
class _SourceFileSnapshot:
    path: str
    git_blob_sha1: str
    sha256: str
    size_bytes: int
    identity: tuple[int, int, int, int, int, int, int, int, int]


@dataclass(frozen=True, slots=True)
class _SourceClosure:
    manifest: NativeQualificationSourceManifest
    files: tuple[_SourceFileSnapshot, ...]

    @property
    def total_bytes(self) -> int:
        return sum(item.size_bytes for item in self.files)


@dataclass(frozen=True, slots=True)
class _RuntimeEvidence:
    distributions: tuple[NativeQualificationRuntimeDistribution, ...]
    manifest_sha256: str
    bpe_tree_sha256: str
    total_bytes: int
    dependency_tree_sha256: str
    dependency_tree_size_bytes: int
    runtime_tree_sha256: str
    runtime_tree_size_bytes: int


@dataclass(frozen=True, slots=True)
class _ManagerFinalization:
    probe_restored_to_root: bool
    manager_empty: bool
    manager_removed: bool


@dataclass(frozen=True, slots=True)
class _Provenance:
    git_commit: str
    github_sha: str
    github_run_id: int
    github_run_attempt: int
    github_repository: Literal["synechism/bpe"]
    github_job: Literal["native-qualification"]
    github_event: Literal["workflow_run"]
    github_ref: Literal["refs/heads/main"]
    github_actor_category: Literal["unverified"]
    upstream_workflow_name: Literal["CI"]
    upstream_workflow_id: int
    upstream_workflow_path: Literal[".github/workflows/ci.yml"]
    upstream_run_id: int
    upstream_run_attempt: int
    upstream_event: Literal["push"]
    upstream_head_branch: Literal["main"]
    upstream_head_repository_full_name: Literal["synechism/bpe"]
    upstream_head_sha: str
    upstream_conclusion: Literal["success"]
    built_wheel_sha256: str
    runner_architecture: str
    docker_server_architecture: str
    docker_server_version: str
    image_reference: str
    image_manifest_sha256: str
    image_platform_sha256: str
    image_config_sha256: str
    runtime_name: str
    runtime_version: str
    runtime_id: str
    compiler_identity: str
    linker_identity: str
    libc_identity: str
    binutils_identity: str
    launcher_build_id_sha1: str


_PROVENANCE_KEYS = frozenset(_Provenance.__dataclass_fields__)


@dataclass(frozen=True, slots=True)
class _ArtifactSeal:
    identity: tuple[int, int, int, int, int, int, int, int, int]
    sha256: str


def _write_control(path: Path, value: str) -> None:
    path.write_text(value + "\n", encoding="ascii")


def _read_nonempty_lines(path: Path) -> tuple[str, ...]:
    return tuple(line for line in path.read_text(encoding="ascii").splitlines() if line)


def _require_private_namespace(root: Path) -> None:
    if sys.platform != "linux" or platform.machine() != "x86_64":
        raise RuntimeError("native launcher probe requires Linux x86-64")
    if os.getpid() != 1 or os.geteuid() != 0:
        raise RuntimeError(
            "native launcher probe requires effective UID 0 as PID 1 in a container"
        )
    if Path("/proc/self/cgroup").read_text(encoding="ascii") != "0::/\n":
        raise RuntimeError("native launcher probe requires a private cgroup namespace root")
    task_ids = {entry.name for entry in Path("/proc/self/task").iterdir()}
    if task_ids != {"1"}:
        raise RuntimeError("native launcher probe must be single-threaded before fork")
    if not (root / "cgroup.controllers").is_file():
        raise RuntimeError("native launcher probe requires a writable cgroup-v2 mount")
    if _read_nonempty_lines(root / "cgroup.procs") != ("1",):
        raise RuntimeError("private cgroup root must initially contain only probe PID 1")


def _duplicate_source(descriptor: int) -> int:
    return int(
        fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, _SOURCE_DESCRIPTOR_MINIMUM)
    )


def _duplicate_sources(
    descriptors: tuple[int, int, int, int, int],
) -> tuple[int, int, int, int, int]:
    duplicates: list[int] = []
    try:
        for descriptor in descriptors:
            duplicates.append(_duplicate_source(descriptor))
        return (
            duplicates[0],
            duplicates[1],
            duplicates[2],
            duplicates[3],
            duplicates[4],
        )
    except BaseException:
        for descriptor in duplicates:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        raise


def _pidfd_denial_program() -> _SockFprog:
    if (
        ctypes.sizeof(ctypes.c_void_p) != 8
        or ctypes.sizeof(_SockFilter) != 8
        or ctypes.sizeof(_SockFprog) != 16
        or _PIDFD_DENIAL_FILTER != NATIVE_QUALIFICATION_OUTER_SECCOMP_INSTRUCTIONS
    ):
        raise RuntimeError("unexpected x86-64 seccomp structure or contract")
    filters = (_SockFilter * len(_PIDFD_DENIAL_FILTER))(
        *(_SockFilter(*instruction) for instruction in _PIDFD_DENIAL_FILTER)
    )
    # ctypes retains the pointed-to array through the structure's ownership graph.
    return _SockFprog(len(_PIDFD_DENIAL_FILTER), filters)


def _call_prctl(option: int, argument: int = 0) -> int:
    try:
        prctl = _LIBC.prctl
    except AttributeError as exc:  # pragma: no cover - Linux probe invariant
        raise OSError(errno.ENOSYS, "prctl is unavailable") from exc
    prctl.argtypes = (
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    )
    prctl.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = int(prctl(option, argument, 0, 0, 0))
    if result < 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))
    return result


def _call_seccomp(program: _SockFprog) -> int:
    syscall = _LIBC.syscall
    syscall.restype = ctypes.c_long
    ctypes.set_errno(0)
    result = int(
        syscall(
            ctypes.c_long(_SYS_SECCOMP_X86_64),
            ctypes.c_uint(_SECCOMP_SET_MODE_FILTER),
            ctypes.c_uint(0),
            ctypes.byref(program),
        )
    )
    if result < 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))
    return result


def _install_pidfd_denial_filter() -> None:
    if _call_prctl(_PR_SET_NO_NEW_PRIVS, 1) != 0:
        raise RuntimeError("PR_SET_NO_NEW_PRIVS returned an impossible result")
    if _call_prctl(_PR_GET_NO_NEW_PRIVS) != 1:
        raise RuntimeError("no-new-privs was not enabled exactly")
    if _call_seccomp(_pidfd_denial_program()) != 0:
        raise RuntimeError("seccomp filter installation returned an impossible result")
    if _call_prctl(_PR_GET_SECCOMP) != _SECCOMP_MODE_FILTER:
        raise RuntimeError("seccomp filter mode was not observed exactly")


def _sha256_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(descriptor, 1024 * 1024, offset)
        if not chunk:
            return digest.hexdigest()
        digest.update(chunk)
        offset += len(chunk)


def _read_bounded_descriptor(descriptor: int, *, maximum_bytes: int, label: str) -> bytes:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or not 0 <= metadata.st_size <= maximum_bytes:
        raise RuntimeError(f"{label} is not a bounded regular file")
    chunks: list[bytes] = []
    offset = 0
    while offset < metadata.st_size:
        chunk = os.pread(descriptor, min(1024 * 1024, metadata.st_size - offset), offset)
        if not chunk:
            raise RuntimeError(f"{label} changed during its bounded read")
        chunks.append(chunk)
        offset += len(chunk)
    if os.pread(descriptor, 1, offset):
        raise RuntimeError(f"{label} grew during its bounded read")
    if _artifact_identity(os.fstat(descriptor)) != _artifact_identity(metadata):
        raise RuntimeError(f"{label} metadata changed during its bounded read")
    return b"".join(chunks)


def _read_bounded_path(path: Path, *, maximum_bytes: int, label: str) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        return _read_bounded_descriptor(
            descriptor,
            maximum_bytes=maximum_bytes,
            label=label,
        )
    finally:
        os.close(descriptor)


def _read_bounded_stream_path(path: Path, *, maximum_bytes: int, label: str) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(4096, maximum_bytes + 1 - total))
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                raise RuntimeError(f"{label} exceeds its byte bound")
    finally:
        os.close(descriptor)


def _require_lower_hex(value: object, *, digits: int, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != digits
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise RuntimeError(f"{label} is not an exact lowercase hexadecimal identity")
    return value


def _require_bounded_text(value: object, *, label: str, maximum: int = 512) -> str:
    if type(value) is not str or not 1 <= len(value) <= maximum or "\x00" in value:
        raise RuntimeError(f"{label} is not bounded text")
    return value


def _git_blob_sha1(content: bytes) -> str:
    header = f"blob {len(content)}\0".encode("ascii")
    return hashlib.sha1(header + content, usedforsecurity=False).hexdigest()


def _load_provenance(path: Path) -> _Provenance:
    raw = _read_bounded_path(path, maximum_bytes=_MAX_PROVENANCE_BYTES, label="provenance")
    parsed = strict_json_loads(raw)
    if type(parsed) is not dict or set(parsed) != _PROVENANCE_KEYS:
        raise RuntimeError("native qualification provenance has the wrong closed field set")
    if canonical_json_bytes(parsed) != raw:
        raise RuntimeError("native qualification provenance is not canonical JSON")

    git_commit = _require_lower_hex(parsed["git_commit"], digits=40, label="git commit")
    github_sha = _require_lower_hex(parsed["github_sha"], digits=40, label="GitHub SHA")
    run_id = parsed["github_run_id"]
    run_attempt = parsed["github_run_attempt"]
    if type(run_id) is not int or run_id < 1:
        raise RuntimeError("GitHub run ID is invalid")
    if type(run_attempt) is not int or not 1 <= run_attempt <= 1000:
        raise RuntimeError("GitHub run attempt is invalid")
    repository = parsed["github_repository"]
    if repository != "synechism/bpe" or type(repository) is not str:
        raise RuntimeError("GitHub repository is invalid")
    job = parsed["github_job"]
    if job != "native-qualification" or type(job) is not str:
        raise RuntimeError("GitHub job is invalid")
    event = parsed["github_event"]
    reference = parsed["github_ref"]
    if event != "workflow_run" or type(event) is not str:
        raise RuntimeError("GitHub event is invalid")
    if reference != "refs/heads/main" or type(reference) is not str:
        raise RuntimeError("GitHub ref is invalid")
    actor = parsed["github_actor_category"]
    if actor != "unverified" or type(actor) is not str:
        raise RuntimeError("GitHub actor category is invalid")

    upstream_workflow_name = parsed["upstream_workflow_name"]
    upstream_workflow_id = parsed["upstream_workflow_id"]
    upstream_workflow_path = parsed["upstream_workflow_path"]
    upstream_run_id = parsed["upstream_run_id"]
    upstream_run_attempt = parsed["upstream_run_attempt"]
    upstream_event = parsed["upstream_event"]
    upstream_head_branch = parsed["upstream_head_branch"]
    upstream_head_repository = parsed["upstream_head_repository_full_name"]
    upstream_head_sha = _require_lower_hex(
        parsed["upstream_head_sha"], digits=40, label="upstream head SHA"
    )
    upstream_conclusion = parsed["upstream_conclusion"]
    if upstream_workflow_name != "CI" or type(upstream_workflow_name) is not str:
        raise RuntimeError("upstream workflow name is invalid")
    if type(upstream_workflow_id) is not int or upstream_workflow_id < 1:
        raise RuntimeError("upstream workflow ID is invalid")
    if (
        upstream_workflow_path != ".github/workflows/ci.yml"
        or type(upstream_workflow_path) is not str
    ):
        raise RuntimeError("upstream workflow path is invalid")
    if type(upstream_run_id) is not int or upstream_run_id < 1:
        raise RuntimeError("upstream run ID is invalid")
    if type(upstream_run_attempt) is not int or not 1 <= upstream_run_attempt <= 1000:
        raise RuntimeError("upstream run attempt is invalid")
    if upstream_event != "push" or type(upstream_event) is not str:
        raise RuntimeError("upstream event is invalid")
    if upstream_head_branch != "main" or type(upstream_head_branch) is not str:
        raise RuntimeError("upstream head branch is invalid")
    if (
        upstream_head_repository != "synechism/bpe"
        or type(upstream_head_repository) is not str
    ):
        raise RuntimeError("upstream head repository is invalid")
    if upstream_conclusion != "success" or type(upstream_conclusion) is not str:
        raise RuntimeError("upstream conclusion is invalid")

    return _Provenance(
        git_commit=git_commit,
        github_sha=github_sha,
        github_run_id=run_id,
        github_run_attempt=run_attempt,
        github_repository=repository,
        github_job=job,
        github_event=event,
        github_ref=reference,
        github_actor_category=actor,
        upstream_workflow_name=upstream_workflow_name,
        upstream_workflow_id=upstream_workflow_id,
        upstream_workflow_path=upstream_workflow_path,
        upstream_run_id=upstream_run_id,
        upstream_run_attempt=upstream_run_attempt,
        upstream_event=upstream_event,
        upstream_head_branch=upstream_head_branch,
        upstream_head_repository_full_name=upstream_head_repository,
        upstream_head_sha=upstream_head_sha,
        upstream_conclusion=upstream_conclusion,
        built_wheel_sha256=_require_lower_hex(
            parsed["built_wheel_sha256"], digits=64, label="built wheel digest"
        ),
        runner_architecture=_require_bounded_text(
            parsed["runner_architecture"], label="runner architecture"
        ),
        docker_server_architecture=_require_bounded_text(
            parsed["docker_server_architecture"], label="Docker server architecture"
        ),
        docker_server_version=_require_bounded_text(
            parsed["docker_server_version"], label="Docker server version"
        ),
        image_reference=_require_bounded_text(
            parsed["image_reference"], label="container image reference"
        ),
        image_manifest_sha256=_require_lower_hex(
            parsed["image_manifest_sha256"], digits=64, label="image manifest digest"
        ),
        image_platform_sha256=_require_lower_hex(
            parsed["image_platform_sha256"], digits=64, label="image platform digest"
        ),
        image_config_sha256=_require_lower_hex(
            parsed["image_config_sha256"], digits=64, label="image config digest"
        ),
        runtime_name=_require_bounded_text(parsed["runtime_name"], label="runtime name"),
        runtime_version=_require_bounded_text(
            parsed["runtime_version"], label="runtime version"
        ),
        runtime_id=_require_bounded_text(parsed["runtime_id"], label="runtime ID"),
        compiler_identity=_require_bounded_text(
            parsed["compiler_identity"], label="compiler identity"
        ),
        linker_identity=_require_bounded_text(
            parsed["linker_identity"], label="linker identity"
        ),
        libc_identity=_require_bounded_text(parsed["libc_identity"], label="libc identity"),
        binutils_identity=_require_bounded_text(
            parsed["binutils_identity"], label="binutils identity"
        ),
        launcher_build_id_sha1=_require_lower_hex(
            parsed["launcher_build_id_sha1"], digits=40, label="launcher build ID"
        ),
    )


def _require_trusted_workflow_run(provenance: _Provenance) -> None:
    if (
        provenance.github_repository != "synechism/bpe"
        or provenance.github_event != "workflow_run"
        or provenance.github_ref != "refs/heads/main"
        or provenance.github_job != "native-qualification"
        or provenance.github_sha != provenance.git_commit
        or provenance.upstream_workflow_name != "CI"
        or provenance.upstream_workflow_path != ".github/workflows/ci.yml"
        or provenance.upstream_event != "push"
        or provenance.upstream_head_branch != "main"
        or provenance.upstream_head_repository_full_name != "synechism/bpe"
        or provenance.upstream_head_sha != provenance.git_commit
        or provenance.upstream_conclusion != "success"
    ):
        raise RuntimeError(
            "native qualification report emission is restricted to trusted workflow runs"
        )


def _expected_source_directories() -> frozenset[str]:
    result = {""}
    for raw_path in NATIVE_QUALIFICATION_SOURCE_PATHS:
        path = Path(raw_path)
        result.update(
            parent.as_posix() if parent.as_posix() != "." else ""
            for parent in path.parents
        )
    return frozenset(result)


def _enumerate_source_tree(root: Path) -> tuple[frozenset[str], frozenset[str]]:
    directories: set[str] = {""}
    files: set[str] = set()
    for directory, child_directories, child_files in os.walk(root, followlinks=False):
        base = Path(directory)
        relative_base = base.relative_to(root)
        relative_label = "" if relative_base == Path(".") else relative_base.as_posix()
        directories.add(relative_label)
        for name in (*child_directories, *child_files):
            child = base / name
            metadata = child.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise RuntimeError("native qualification source tree contains a symlink")
        for name in child_directories:
            child = base / name
            if not stat.S_ISDIR(child.stat().st_mode):
                raise RuntimeError("native qualification source tree contains a non-directory")
        for name in child_files:
            child = base / name
            if not stat.S_ISREG(child.stat().st_mode):
                raise RuntimeError("native qualification source tree contains a non-file")
            files.add((relative_base / name).as_posix())
    return frozenset(directories), frozenset(files)


def _snapshot_source_tree(root: Path) -> _SourceClosure:
    root_metadata = root.lstat()
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        raise RuntimeError("native qualification source root is unsafe")
    directories, files = _enumerate_source_tree(root)
    if directories != _expected_source_directories() or files != frozenset(
        NATIVE_QUALIFICATION_SOURCE_PATHS
    ):
        raise RuntimeError("native qualification source tree is not exactly closed")

    snapshots: list[_SourceFileSnapshot] = []
    total_bytes = 0
    for raw_path in NATIVE_QUALIFICATION_SOURCE_PATHS:
        path = root / raw_path
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(descriptor)
            content = _read_bounded_descriptor(
                descriptor,
                maximum_bytes=_MAX_SOURCE_FILE_BYTES,
                label=f"source file {raw_path}",
            )
            total_bytes += len(content)
            if total_bytes > _MAX_SOURCE_TOTAL_BYTES:
                raise RuntimeError("native qualification source closure exceeds its byte bound")
            snapshots.append(
                _SourceFileSnapshot(
                    path=raw_path,
                    git_blob_sha1=_git_blob_sha1(content),
                    sha256=sha256_bytes(content),
                    size_bytes=len(content),
                    identity=_artifact_identity(metadata),
                )
            )
        finally:
            os.close(descriptor)
    manifest = native_qualification.build_inert_native_qualification_source_manifest(
        tuple((snapshot.sha256, snapshot.size_bytes) for snapshot in snapshots)
    )
    return _SourceClosure(manifest=manifest, files=tuple(snapshots))


def _require_source_tree_unchanged(root: Path, closure: _SourceClosure) -> None:
    repeated = _snapshot_source_tree(root)
    if repeated != closure:
        raise RuntimeError("native qualification source closure changed during the probe")


def _load_tracked_tree_manifest(
    path: Path,
    source: _SourceClosure,
) -> tuple[str, int, int]:
    raw = _read_bounded_path(
        path,
        maximum_bytes=_MAX_TRACKED_TREE_MANIFEST_BYTES,
        label="tracked-tree manifest",
    )
    parsed = strict_json_loads(raw)
    if type(parsed) is not dict or set(parsed) != {"schema_version", "files"}:
        raise RuntimeError("tracked-tree manifest has the wrong field set")
    if parsed["schema_version"] != "bpe.git-commit-blob-content-manifest.v1":
        raise RuntimeError("tracked-tree manifest has the wrong schema")
    entries = parsed["files"]
    if type(entries) is not list or not 1 <= len(entries) <= _MAX_TRACKED_TREE_FILES:
        raise RuntimeError("tracked-tree manifest has an unsafe file count")
    normalized: list[tuple[str, str, str, str, int]] = []
    for entry in entries:
        if type(entry) is not dict or set(entry) != {
            "path",
            "mode",
            "git_blob_sha1",
            "sha256",
            "size_bytes",
        }:
            raise RuntimeError("tracked-tree manifest contains a malformed entry")
        entry_path = entry["path"]
        mode = entry["mode"]
        git_blob_sha1 = entry["git_blob_sha1"]
        digest = entry["sha256"]
        size_bytes = entry["size_bytes"]
        if (
            type(entry_path) is not str
            or not entry_path
            or entry_path.startswith("/")
            or "\\" in entry_path
            or Path(entry_path).as_posix() != entry_path
            or any(part in {"", ".", ".."} for part in Path(entry_path).parts)
        ):
            raise RuntimeError("tracked-tree manifest contains an unsafe path")
        if mode not in {"100644", "100755"} or type(mode) is not str:
            raise RuntimeError("tracked-tree manifest contains a non-regular blob mode")
        normalized.append(
            (
                entry_path,
                mode,
                _require_lower_hex(
                    git_blob_sha1,
                    digits=40,
                    label="tracked Git blob identity",
                ),
                _require_lower_hex(digest, digits=64, label="tracked file digest"),
                size_bytes,
            )
        )
        if type(size_bytes) is not int or size_bytes < 0:
            raise RuntimeError("tracked-tree manifest contains an unsafe size")
    if normalized != sorted(normalized) or len({item[0] for item in normalized}) != len(
        normalized
    ):
        raise RuntimeError("tracked-tree manifest paths are not sorted and unique")
    if canonical_json_bytes(parsed) != raw:
        raise RuntimeError("tracked-tree manifest is not canonical JSON")
    by_path = {item[0]: (item[2], item[3], item[4]) for item in normalized}
    for snapshot in source.files:
        if by_path.get(snapshot.path) != (
            snapshot.git_blob_sha1,
            snapshot.sha256,
            snapshot.size_bytes,
        ):
            raise RuntimeError("tracked-tree and critical-source manifests are not cross-bound")
    total_bytes = sum(item[4] for item in normalized)
    if not 1 <= total_bytes <= MAX_NATIVE_QUALIFICATION_TRACKED_TREE_TOTAL_BYTES:
        raise RuntimeError("tracked-tree manifest describes an unsafe source-tree size")
    return sha256_bytes(raw), len(raw), total_bytes


def _is_beneath(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _require_runtime_bpe_tree(
    package_root: Path,
    source: _SourceClosure,
) -> None:
    """Require an exact byte-for-byte installed projection of committed ``src/bpe``."""

    package_metadata = package_root.lstat()
    if not stat.S_ISDIR(package_metadata.st_mode) or stat.S_ISLNK(
        package_metadata.st_mode
    ):
        raise RuntimeError("the installed BPE package root is unsafe")
    directories, files = _enumerate_source_tree(package_root)
    expected_files = {
        path.removeprefix("src/bpe/"): next(
            item for item in source.files if item.path == path
        )
        for path in NATIVE_QUALIFICATION_BPE_SOURCE_PATHS
    }
    expected_directories = {""}
    for relative in expected_files:
        expected_directories.update(
            parent.as_posix() if parent.as_posix() != "." else ""
            for parent in Path(relative).parents
        )
    if files != frozenset(expected_files) or directories != frozenset(
        expected_directories
    ):
        raise RuntimeError("the installed BPE package tree is not exactly closed")
    for relative, snapshot in expected_files.items():
        content = _read_bounded_path(
            package_root / relative,
            maximum_bytes=_MAX_SOURCE_FILE_BYTES,
            label=f"runtime BPE file {relative}",
        )
        if len(content) != snapshot.size_bytes or sha256_bytes(content) != snapshot.sha256:
            raise RuntimeError("the installed BPE package differs from committed source")


def _require_runtime_import_roots(runtime_root: Path, source: _SourceClosure) -> None:
    resolved_root = runtime_root.resolve(strict=True)
    loaded: list[tuple[str, Path]] = []
    for name, module in sorted(sys.modules.items()):
        if name != "bpe" and not name.startswith("bpe."):
            continue
        raw_path = getattr(module, "__file__", None)
        if raw_path is None:
            continue
        path = Path(raw_path).resolve(strict=True)
        if not _is_beneath(path, resolved_root):
            raise RuntimeError(f"imported BPE module {name} did not resolve beneath /runtime")
        loaded.append((name, path))
    if not loaded or Path(bpe.__file__).resolve(strict=True).parent != resolved_root / "bpe":
        raise RuntimeError("the installed BPE package did not resolve beneath /runtime")

    _require_runtime_bpe_tree(resolved_root / "bpe", source)

    distribution = importlib.metadata.distribution("bpe")
    distribution_root = Path(distribution.locate_file("")).resolve(strict=True)
    if not _is_beneath(distribution_root, resolved_root):
        raise RuntimeError("BPE distribution metadata did not resolve beneath /runtime")


def _tree_manifest_sha256(files: list[dict[str, object]]) -> str:
    return sha256_json(
        {
            "schema_version": "bpe.python-installed-tree-content-manifest.v1",
            "files": files,
        }
    )


def _expected_wheel_paths() -> frozenset[str]:
    return frozenset(
        path.removeprefix("src/") for path in NATIVE_QUALIFICATION_BPE_SOURCE_PATHS
    ) | frozenset(NATIVE_QUALIFICATION_WHEEL_DIST_INFO_PATHS)


def _expected_runtime_root_paths() -> frozenset[str]:
    return _expected_wheel_paths() | frozenset(
        NATIVE_QUALIFICATION_RUNTIME_INSTALLER_PATHS
    )


def _root_tree_evidence(
    root: Path,
    *,
    label: str,
) -> tuple[str, int, frozenset[str]]:
    resolved_root = root.resolve(strict=True)
    files: list[dict[str, object]] = []
    total_bytes = 0
    for directory, child_directories, child_files in os.walk(
        resolved_root,
        followlinks=False,
    ):
        base = Path(directory)
        for name in (*child_directories, *child_files):
            metadata = (base / name).lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise RuntimeError(f"{label} contains a symlink")
        for name in child_files:
            path = base / name
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                raise RuntimeError(f"{label} contains a non-regular file")
            content = _read_bounded_path(
                path,
                maximum_bytes=64 * 1024 * 1024,
                label=f"{label} file",
            )
            total_bytes += len(content)
            if len(files) >= _MAX_RUNTIME_FILES or total_bytes > _MAX_RUNTIME_TOTAL_BYTES:
                raise RuntimeError(f"{label} exceeds its work bound")
            files.append(
                {
                    "path": path.relative_to(resolved_root).as_posix(),
                    "sha256": sha256_bytes(content),
                    "size_bytes": len(content),
                }
            )
    files.sort(key=lambda item: cast(str, item["path"]))
    if not files:
        raise RuntimeError(f"{label} is empty")
    return (
        _tree_manifest_sha256(files),
        total_bytes,
        frozenset(cast(str, item["path"]) for item in files),
    )


def _wheel_bpe_tree_sha256(path: Path) -> str:
    files: list[dict[str, object]] = []
    total_bytes = 0
    seen: set[str] = set()
    expected_wheel_paths = _expected_wheel_paths()
    expected_bpe_paths = frozenset(
        source_path.removeprefix("src/")
        for source_path in NATIVE_QUALIFICATION_BPE_SOURCE_PATHS
    )
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            member = PurePosixPath(info.filename)
            if (
                member.is_absolute()
                or member.as_posix() != info.filename
                or any(part in {"", ".", ".."} for part in member.parts)
            ):
                raise RuntimeError("built wheel contains an unsafe member path")
            if info.filename in seen:
                raise RuntimeError("built wheel contains duplicate members")
            seen.add(info.filename)
            mode = (info.external_attr >> 16) & 0xFFFF
            if (
                info.is_dir()
                or info.filename not in expected_wheel_paths
                or stat.S_ISLNK(mode)
                or stat.S_IFMT(mode) not in {0, stat.S_IFREG}
                or info.flag_bits & 0x1
            ):
                raise RuntimeError("built wheel layout is not exactly closed")
            if info.file_size > _MAX_RUNTIME_TOTAL_BYTES - total_bytes:
                raise RuntimeError("built wheel content exceeds its byte bound")
            content = archive.read(info)
            if len(content) != info.file_size:
                raise RuntimeError("built wheel member changed during read")
            total_bytes += len(content)
            if info.filename in expected_bpe_paths:
                files.append(
                    {
                        "path": info.filename,
                        "sha256": sha256_bytes(content),
                        "size_bytes": len(content),
                    }
                )
    if seen != expected_wheel_paths:
        raise RuntimeError("built wheel layout is not exactly closed")
    files.sort(key=lambda item: cast(str, item["path"]))
    return _tree_manifest_sha256(files)


def _runtime_root_evidence(root: Path) -> tuple[str, int]:
    directories, files = _enumerate_source_tree(root)
    expected_files = _expected_runtime_root_paths()
    expected_directories = {""}
    for relative in expected_files:
        expected_directories.update(
            parent.as_posix() if parent.as_posix() != "." else ""
            for parent in Path(relative).parents
        )
    if files != expected_files or directories != frozenset(expected_directories):
        raise RuntimeError("runtime root is not the exact installed-wheel projection")
    digest, total_bytes, digested_files = _root_tree_evidence(
        root,
        label="runtime tree",
    )
    if digested_files != expected_files:
        raise RuntimeError("runtime root changed during exact-tree evidence collection")
    return digest, total_bytes


def _runtime_dependency_evidence(
    runtime_root: Path,
    dependency_root: Path,
) -> _RuntimeEvidence:
    roots = (runtime_root.resolve(strict=True), dependency_root.resolve(strict=True))
    distributions: list[NativeQualificationRuntimeDistribution] = []
    file_count = 0
    total_bytes = 0
    seen: set[tuple[str, str, str]] = set()
    dependency_files: set[str] = set()
    for root_label, root in (("runtime", roots[0]), ("dependencies", roots[1])):
        found = tuple(importlib.metadata.distributions(path=[str(root)]))
        if len(found) > _MAX_RUNTIME_DISTRIBUTIONS:
            raise RuntimeError("runtime dependency distribution count exceeds its bound")
        if root_label == "runtime" and len(found) != 1:
            raise RuntimeError("runtime root must contain one exact BPE distribution")
        for distribution in found:
            name = distribution.metadata.get("Name")
            version = distribution.version
            if not name or not version:
                raise RuntimeError("runtime dependency has incomplete distribution metadata")
            normalized_name = re.sub(r"[-_.]+", "-", name).lower()
            identity = (root_label, normalized_name, version)
            if identity in seen:
                raise RuntimeError("runtime dependency distribution identity is duplicated")
            if root_label == "dependencies" and normalized_name == "bpe":
                raise RuntimeError("dependency tree must not contain a shadow BPE distribution")
            if root_label == "runtime" and (
                normalized_name != "bpe"
                or version != NATIVE_QUALIFICATION_BPE_DISTRIBUTION_VERSION
            ):
                raise RuntimeError("runtime root contains the wrong BPE distribution")
            seen.add(identity)
            files: list[dict[str, object]] = []
            seen_files: set[str] = set()
            for entry in distribution.files or ():
                candidate = Path(distribution.locate_file(entry))
                try:
                    resolved = candidate.resolve(strict=True)
                except FileNotFoundError:
                    continue
                if not _is_beneath(resolved, root):
                    continue
                candidate_metadata = candidate.lstat()
                if stat.S_ISLNK(candidate_metadata.st_mode):
                    raise RuntimeError("runtime dependency contains a symlink")
                metadata = resolved.lstat()
                if not stat.S_ISREG(metadata.st_mode):
                    raise RuntimeError("runtime dependency contains a non-regular file")
                relative = resolved.relative_to(root).as_posix()
                if normalized_name == "bpe" and root_label == "runtime":
                    parts = PurePosixPath(relative).parts
                    if not parts or parts[0] != "bpe":
                        continue
                if relative in seen_files:
                    raise RuntimeError("runtime dependency contains duplicate file evidence")
                seen_files.add(relative)
                if root_label == "dependencies":
                    if relative in dependency_files:
                        raise RuntimeError(
                            "dependency file is claimed by multiple distributions"
                        )
                    dependency_files.add(relative)
                content = _read_bounded_path(
                    resolved,
                    maximum_bytes=64 * 1024 * 1024,
                    label=f"runtime dependency file {relative}",
                )
                file_count += 1
                total_bytes += len(content)
                if (
                    file_count > _MAX_RUNTIME_FILES
                    or total_bytes > _MAX_RUNTIME_TOTAL_BYTES
                ):
                    raise RuntimeError("runtime dependency manifest exceeds its work bound")
                files.append(
                    {
                        "path": relative,
                        "sha256": sha256_bytes(content),
                        "size_bytes": len(content),
                    }
                )
            files.sort(key=lambda item: cast(str, item["path"]))
            if not files:
                raise RuntimeError("runtime dependency has no bounded files")
            distributions.append(
                NativeQualificationRuntimeDistribution(
                    root=cast(Literal["runtime", "dependencies"], root_label),
                    normalized_name=normalized_name,
                    version=version,
                    aggregate_scope=(
                        "package-tree"
                        if root_label == "runtime" and normalized_name == "bpe"
                        else "distribution-files"
                    ),
                    file_count=len(files),
                    total_bytes=sum(cast(int, item["size_bytes"]) for item in files),
                    aggregate_tree_sha256=_tree_manifest_sha256(files),
                )
            )
    distributions.sort(
        key=lambda item: (item.root, item.normalized_name, item.version)
    )
    frozen = tuple(distributions)
    bpe_distributions = tuple(
        item
        for item in frozen
        if item.root == "runtime" and item.normalized_name == "bpe"
    )
    if len(bpe_distributions) != 1:
        raise RuntimeError("runtime must contain exactly one installed BPE distribution")
    manifest_sha256 = native_qualification_runtime_dependency_manifest_sha256(
        frozen
    )
    (
        dependency_tree_sha256,
        dependency_tree_size_bytes,
        dependency_tree_files,
    ) = _root_tree_evidence(
        dependency_root,
        label="dependency tree",
    )
    if dependency_tree_files != dependency_files or dependency_tree_size_bytes != sum(
        item.total_bytes for item in frozen if item.root == "dependencies"
    ):
        raise RuntimeError(
            "dependency root contains files outside the recorded distributions"
        )
    runtime_tree_sha256, runtime_tree_size_bytes = _runtime_root_evidence(
        runtime_root
    )
    return _RuntimeEvidence(
        distributions=frozen,
        manifest_sha256=manifest_sha256,
        bpe_tree_sha256=bpe_distributions[0].aggregate_tree_sha256,
        total_bytes=sum(item.total_bytes for item in frozen),
        dependency_tree_sha256=dependency_tree_sha256,
        dependency_tree_size_bytes=dependency_tree_size_bytes,
        runtime_tree_sha256=runtime_tree_sha256,
        runtime_tree_size_bytes=runtime_tree_size_bytes,
    )


def _require_readonly_mount(path: Path, *, label: str) -> None:
    if os.statvfs(path).f_flag & getattr(os, "ST_RDONLY", 1) == 0:
        raise RuntimeError(f"{label} is not mounted read-only")


def _require_readwrite_mount(path: Path, *, label: str) -> None:
    if os.statvfs(path).f_flag & getattr(os, "ST_RDONLY", 1):
        raise RuntimeError(f"{label} is unexpectedly mounted read-only")


def _require_built_wheel(wheel: Path, expected_sha256: str) -> tuple[int, str]:
    metadata = wheel.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError("built wheel input is not a regular file")
    content = _read_bounded_path(
        wheel,
        maximum_bytes=MAX_NATIVE_QUALIFICATION_BUILT_WHEEL_BYTES,
        label="built wheel",
    )
    if sha256_bytes(content) != expected_sha256:
        raise RuntimeError("built wheel differs from CI provenance")
    return len(content), _wheel_bpe_tree_sha256(wheel)


def _elf_build_id_sha1(descriptor: int) -> str:
    header = os.pread(descriptor, 64, 0)
    if len(header) != 64 or header[:16] != b"\x7fELF\x02\x01\x01" + b"\x00" * 9:
        raise RuntimeError("launcher is not the fixed ELF64 little-endian ABI")
    section_offset = struct.unpack_from("<Q", header, 0x28)[0]
    section_size = struct.unpack_from("<H", header, 0x3A)[0]
    section_count = struct.unpack_from("<H", header, 0x3C)[0]
    metadata = os.fstat(descriptor)
    if (
        section_size != 64
        or not 1 <= section_count <= 4096
        or section_offset > metadata.st_size
        or section_count * section_size > metadata.st_size - section_offset
    ):
        raise RuntimeError("launcher section table is not bounded")
    build_ids: list[str] = []
    for index in range(section_count):
        section = os.pread(descriptor, section_size, section_offset + index * section_size)
        if len(section) != section_size or struct.unpack_from("<I", section, 4)[0] != 7:
            continue
        note_offset = struct.unpack_from("<Q", section, 0x18)[0]
        note_size = struct.unpack_from("<Q", section, 0x20)[0]
        if note_offset > metadata.st_size or note_size > metadata.st_size - note_offset:
            raise RuntimeError("launcher note section is out of bounds")
        notes = os.pread(descriptor, note_size, note_offset)
        if len(notes) != note_size:
            raise RuntimeError("launcher note section changed during read")
        cursor = 0
        while cursor < len(notes):
            if len(notes) - cursor < 12:
                raise RuntimeError("launcher note section has a truncated header")
            name_size, description_size, note_type = struct.unpack_from("<III", notes, cursor)
            cursor += 12
            padded_name = (name_size + 3) & ~3
            padded_description = (description_size + 3) & ~3
            if padded_name + padded_description > len(notes) - cursor:
                raise RuntimeError("launcher note section has a truncated value")
            name = notes[cursor : cursor + name_size]
            cursor += padded_name
            description = notes[cursor : cursor + description_size]
            cursor += padded_description
            if note_type == 3 and name == b"GNU\x00":
                if description_size != 20:
                    raise RuntimeError("launcher GNU build ID is not SHA-1")
                build_ids.append(description.hex())
    if len(build_ids) != 1:
        raise RuntimeError("launcher must contain exactly one GNU SHA-1 build ID")
    return build_ids[0]


def _namespace_identity(name: str) -> NativeQualificationNamespaceIdentity:
    path = Path("/proc/self/ns") / name
    if not stat.S_ISLNK(path.lstat().st_mode):
        raise RuntimeError(f"{name} namespace identity is not a namespace link")
    metadata = path.stat()
    return NativeQualificationNamespaceIdentity(device=metadata.st_dev, inode=metadata.st_ino)


def _cgroup_filesystem_magic(root: Path) -> int:
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        result = _StatFs()
        fstatfs = _LIBC.fstatfs
        fstatfs.argtypes = (ctypes.c_int, ctypes.POINTER(_StatFs))
        fstatfs.restype = ctypes.c_int
        ctypes.set_errno(0)
        if fstatfs(descriptor, ctypes.byref(result)) != 0:
            error_number = ctypes.get_errno()
            raise OSError(error_number, os.strerror(error_number))
        return int(result.f_type)
    finally:
        os.close(descriptor)


def _require_privileged_container() -> None:
    fields: dict[str, str] = {}
    for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            fields[key] = value.strip()
    effective = int(fields.get("CapEff", "0"), 16)
    bounding = int(fields.get("CapBnd", "0"), 16)
    required = (1 << 21) | (1 << 24)  # CAP_SYS_ADMIN | CAP_SYS_RESOURCE
    if os.geteuid() != 0 or effective & required != required or effective != bounding:
        raise RuntimeError("native qualification did not observe a privileged container")


def _require_network_namespace_isolated() -> None:
    interfaces = {entry.name for entry in Path("/sys/class/net").iterdir()}
    if interfaces != {"lo"}:
        raise RuntimeError("native qualification network namespace is not loopback-only")


def _build_host(root: Path, provenance: _Provenance) -> NativeQualificationHost:
    if (
        provenance.runner_architecture != "x86_64"
        or provenance.docker_server_architecture != "x86_64"
        or platform.machine() != "x86_64"
    ):
        raise RuntimeError("native qualification architecture is not exact x86-64")
    proc_version = _read_bounded_stream_path(
        Path("/proc/version"),
        maximum_bytes=4096,
        label="kernel version",
    )
    boot_id = _read_bounded_stream_path(
        Path("/proc/sys/kernel/random/boot_id"),
        maximum_bytes=128,
        label="kernel boot ID",
    )
    page_size = os.sysconf("SC_PAGE_SIZE")
    filesystem_magic = _cgroup_filesystem_magic(root)
    if page_size != 4096 or filesystem_magic != _CGROUP2_SUPER_MAGIC:
        raise RuntimeError("native qualification host page or cgroup ABI is unsupported")
    return NativeQualificationHost(
        runner_architecture="x86_64",
        docker_server_architecture="x86_64",
        container_architecture="x86_64",
        emulation_detected=False,
        kernel_release=platform.release(),
        kernel_version=proc_version.decode("utf-8").strip(),
        proc_version_sha256=sha256_bytes(proc_version),
        boot_id_sha256=sha256_bytes(boot_id),
        base_page_size_bytes=4096,
        cgroup_v2_filesystem_magic=filesystem_magic,
        pid_namespace=_namespace_identity("pid"),
        mount_namespace=_namespace_identity("mnt"),
        user_namespace=_namespace_identity("user"),
        cgroup_namespace=_namespace_identity("cgroup"),
    )


def _artifact_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int, int, int, int]:
    # Deliberately exclude atime: reading the artifact to hash it may advance atime.
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _seal_artifact(descriptor: int, *, expected_sha256: str) -> _ArtifactSeal:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o022:
        raise RuntimeError("native launcher artifact must be a non-writable regular file")
    if metadata.st_mode & 0o111 == 0:
        raise RuntimeError("native launcher artifact is not executable")
    if not 64 <= metadata.st_size <= MAX_LAUNCHER_ARTIFACT_BYTES:
        raise RuntimeError("native launcher artifact has an unsafe size")
    if fcntl.fcntl(descriptor, fcntl.F_GETFD) & fcntl.FD_CLOEXEC == 0:
        raise RuntimeError("pinned native launcher descriptor must be close-on-exec")
    sha256 = _sha256_descriptor(descriptor)
    if sha256 != expected_sha256:
        raise RuntimeError("native launcher artifact differs from the external digest")
    return _ArtifactSeal(
        identity=_artifact_identity(os.fstat(descriptor)),
        sha256=sha256,
    )


def _require_artifact_unchanged(descriptor: int, seal: _ArtifactSeal) -> None:
    if _artifact_identity(os.fstat(descriptor)) != seal.identity:
        raise RuntimeError("pinned native launcher inode metadata changed during the gate")
    if _sha256_descriptor(descriptor) != seal.sha256:
        raise RuntimeError("pinned native launcher bytes changed during the gate")
    if _artifact_identity(os.fstat(descriptor)) != seal.identity:
        raise RuntimeError("pinned native launcher inode changed while it was hashed")


def _copy_exact_artifact(source_fd: int, destination_fd: int, *, size: int) -> None:
    offset = 0
    while offset < size:
        chunk = os.pread(source_fd, min(1024 * 1024, size - offset), offset)
        if not chunk:
            raise RuntimeError("native launcher source changed during private staging")
        written = 0
        while written < len(chunk):
            count = os.write(destination_fd, chunk[written:])
            if count <= 0:
                raise RuntimeError("short write while privately staging native launcher")
            written += count
        offset += len(chunk)
    if os.pread(source_fd, 1, size):
        raise RuntimeError("native launcher source grew during private staging")


def _stage_root_owned_artifact(
    source_fd: int,
    source_seal: _ArtifactSeal,
    private_root: Path,
) -> tuple[int, _ArtifactSeal]:
    staged_path = private_root / "launcher"
    staged_fd = os.open(
        staged_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        _copy_exact_artifact(
            source_fd,
            staged_fd,
            size=source_seal.identity[6],
        )
        os.fchmod(staged_fd, 0o500)
        os.fsync(staged_fd)
    finally:
        os.close(staged_fd)
    _require_artifact_unchanged(source_fd, source_seal)
    descriptor = os.open(
        staged_path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o500
            or metadata.st_nlink != 1
        ):
            raise RuntimeError("privately staged launcher ownership or mode is unsafe")
        staged_seal = _seal_artifact(
            descriptor,
            expected_sha256=source_seal.sha256,
        )
        return descriptor, staged_seal
    except BaseException:
        os.close(descriptor)
        raise


def _resource_profile() -> ExecutionResourceProfile:
    return ExecutionResourceProfile(
        schema_version="bpe.execution-resource-profile.v1",
        profile_id="native-probe-resource-profile-v1",
        wall_timeout_ms=10_000,
        cpu_time_seconds=5,
        memory_bytes=256 * 1024 * 1024,
        swap_bytes=0,
        pids_max=16,
        open_files_max=32,
        file_size_bytes=4 * 1024 * 1024,
        stack_bytes=4 * 1024 * 1024,
        stdout_bytes=64 * 1024,
        stderr_bytes=64 * 1024,
        tmpfs_bytes=16 * 1024 * 1024,
        tmpfs_inodes=1024,
        network_enabled=False,
        core_dumps_enabled=False,
    )


def _launch_expectation(
    private_root: Path,
    artifact_sha256: str,
) -> InertFixtureLaunchExpectation:
    claim_path = private_root / "claims.sqlite3"
    launch_path = private_root / "launches.sqlite3"
    claim_path.touch(mode=0o600)
    launch_path.touch(mode=0o600)
    resources = _resource_profile()
    policy = InertFixturePolicy(
        schema_version="bpe.inert-fixture-policy.v1",
        policy_id="native-probe-inert-fixture-policy-v1",
        worker_pool_audience="native-probe-workers",
        worker_instance_id="native-probe-worker-001",
        claim_ledger_id="native-probe-claim-ledger-v1",
        launch_ledger_id="native-probe-launch-ledger-v1",
        claim_scope="single-configured-worker-ledger-v1",
        delegated_root_id="native-probe-cgroup-root-v1",
        host_platform="linux",
        host_architecture="x86_64",
        purpose="inert_fixture_qualification",
        operation="qualify-clone3-inert-noexec-v1",
        launcher_kind="spawned-one-shot-executable-v1",
        launcher_artifact_id="native-probe-launcher-amd64-v1",
        launcher_artifact_sha256=artifact_sha256,
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
        resources=resources,
        resource_profile_sha256=sha256_json(resources),
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
    intent_expectation = inert_fixture_intent_expectation_for(
        policy,
        expected_policy_sha256=sha256_json(policy),
        expected_worker_pool_audience=policy.worker_pool_audience,
        expected_worker_instance_id=policy.worker_instance_id,
        expected_claim_ledger_id=policy.claim_ledger_id,
        expected_claim_ledger_path=claim_path,
        expected_launch_ledger_id=policy.launch_ledger_id,
        expected_delegated_root_id=policy.delegated_root_id,
        expected_launcher_artifact_id=policy.launcher_artifact_id,
        expected_launcher_artifact_sha256=policy.launcher_artifact_sha256,
        expected_launcher_seccomp_policy_id=policy.launcher_seccomp_policy_id,
        expected_launcher_seccomp_policy_sha256=(
            policy.launcher_seccomp_policy_sha256
        ),
    )
    return inert_fixture_launch_expectation_for(
        intent_expectation,
        expected_launch_ledger_path=launch_path,
        expected_worker_instance_id=policy.worker_instance_id,
        expected_claim_ledger_id=policy.claim_ledger_id,
        expected_launch_ledger_id=policy.launch_ledger_id,
    )


def _require_preflight_receipt_binding(
    artifact: LinuxInertLauncherArtifact,
    staged_seal: _ArtifactSeal,
) -> None:
    receipt = artifact.receipt
    identity = staged_seal.identity
    if (
        receipt.launcher_artifact_sha256 != staged_seal.sha256
        or receipt.launcher_seccomp_policy_id != FIXED_SECCOMP_POLICY_ID
        or receipt.launcher_seccomp_policy_sha256 != FIXED_SECCOMP_POLICY_SHA256
        or receipt.source_device != identity[0]
        or receipt.source_inode != identity[1]
        or receipt.source_mode != identity[2]
        or receipt.source_nlink != identity[3]
        or receipt.source_uid != identity[4]
        or receipt.source_gid != identity[5]
        or receipt.source_size_bytes != identity[6]
        or receipt.source_mtime_ns != identity[7]
        or receipt.source_ctime_ns != identity[8]
        or receipt.sealed_copy_sha256 != staged_seal.sha256
        or receipt.launch_attempt_consumed
        or receipt.process_created
        or receipt.execution_started
        or receipt.authoritative
    ):
        raise RuntimeError("production artifact preflight receipt is not exactly bound")


def _require_descriptor_closed(descriptor: int, *, label: str) -> None:
    try:
        os.fstat(descriptor)
    except OSError as exc:
        if exc.errno == errno.EBADF:
            return
        raise
    raise RuntimeError(f"{label} remained open")


def _close_exact(descriptor: int, *, label: str) -> None:
    os.close(descriptor)
    _require_descriptor_closed(descriptor, label=label)


def _duplicate_sealed_launcher(
    artifact: LinuxInertLauncherArtifact,
    *,
    expected_sha256: str,
) -> tuple[int, _DuplicateSeal]:
    direct_fd = artifact.duplicate_executable_fd()
    launcher_fd = -1
    try:
        direct_identity = _artifact_identity(os.fstat(direct_fd))
        launcher_fd = int(
            fcntl.fcntl(
                direct_fd,
                fcntl.F_DUPFD_CLOEXEC,
                _ARTIFACT_DESCRIPTOR_MINIMUM,
            )
        )
    finally:
        _close_exact(direct_fd, label="direct sealed launcher duplicate")
    try:
        metadata = os.fstat(launcher_fd)
        identity = _artifact_identity(metadata)
        seals = int(fcntl.fcntl(launcher_fd, F_GET_SEALS_LINUX))
        readonly = fcntl.fcntl(launcher_fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
        cloexec = bool(fcntl.fcntl(launcher_fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
        identity_verified = identity == direct_identity
        if (
            _sha256_descriptor(launcher_fd) != expected_sha256
            or seals != artifact.receipt.sealed_copy_seals
            or not readonly
            or not cloexec
            or not identity_verified
        ):
            raise RuntimeError("sealed launcher handoff descriptor is not exact")
        return launcher_fd, _DuplicateSeal(
            sha256=expected_sha256,
            size_bytes=metadata.st_size,
            device=metadata.st_dev,
            inode=metadata.st_ino,
            mode=metadata.st_mode,
            nlink=metadata.st_nlink,
            seals=seals,
            readonly_verified=readonly,
            cloexec_verified=cloexec,
            identity_verified=identity_verified,
        )
    except BaseException:
        _close_exact(launcher_fd, label="failed sealed launcher duplicate")
        raise


def _close_child_descriptors_except(keep: frozenset[int]) -> None:
    # The probe is single-threaded at fork.  Materialize the procfs directory before
    # closing so its transient enumeration fd cannot make the final table inexact.
    descriptors = tuple(
        int(name) for name in os.listdir("/proc/self/fd") if name.isascii() and name.isdigit()
    )
    for descriptor in descriptors:
        if descriptor not in keep:
            with contextlib.suppress(OSError):
                os.close(descriptor)


def _child_exec(
    launcher_fd: int,
    sources: tuple[int, int, int, int, int],
    *,
    deny_pidfd_send_signal: bool,
    retain_extra_descriptor: bool,
) -> None:
    try:
        signal.pthread_sigmask(signal.SIG_SETMASK, ())
        for signal_number in signal.valid_signals():
            if signal_number not in {signal.SIGKILL, signal.SIGSTOP}:
                signal.signal(signal_number, signal.SIG_DFL)
        for target, source in enumerate(sources):
            os.dup2(source, target, inheritable=True)
        keep = {0, 1, 2, 3, 4}
        if retain_extra_descriptor:
            os.dup2(sources[0], _EXTRA_DESCRIPTOR, inheritable=True)
            keep.add(_EXTRA_DESCRIPTOR)
        keep.add(launcher_fd)
        _close_child_descriptors_except(frozenset(keep))
        if deny_pidfd_send_signal:
            _install_pidfd_denial_filter()
        os.execve(launcher_fd, [_LAUNCHER_ARGV0], {})
    except BaseException:
        os._exit(127)


def _collect_records(control: socket.socket, deadline: float) -> tuple[
    tuple[InertNativeSocketRecord, ...], bool
]:
    records: list[InertNativeSocketRecord] = []
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("timed out draining native launcher control socket")
        control.settimeout(remaining)
        try:
            payload, ancillary, flags, _address = control.recvmsg(
                PROTOCOL_FRAME_SIZE + 1,
                _CONTROL_ANCILLARY_SIZE,
                _MSG_CMSG_CLOEXEC,
            )
        except TimeoutError as exc:
            raise RuntimeError(
                "timed out draining native launcher control socket"
            ) from exc

        ancillary_present = bool(ancillary)
        for level, message_type, message_data in ancillary:
            if level != socket.SOL_SOCKET or message_type != socket.SCM_RIGHTS:
                continue
            usable_size = len(message_data) - len(message_data) % _SCM_RIGHTS_ITEM_SIZE
            received_descriptors = array.array("i")
            received_descriptors.frombytes(message_data[:usable_size])
            for descriptor in received_descriptors:
                with contextlib.suppress(OSError):
                    os.close(descriptor)

        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            raise RuntimeError("native launcher control message was truncated")
        if ancillary_present:
            raise RuntimeError("native launcher sent forbidden ancillary data")
        if payload == b"":
            return tuple(records), True
        if len(records) >= PROTOCOL_MAX_FRAMES:
            raise RuntimeError("native launcher transcript exceeded the frame bound")
        records.append(
            InertNativeSocketRecord(
                payload=payload,
                message_truncated=False,
                control_truncated=False,
                ancillary_present=False,
            )
        )


def _wait_exact_child(pid: int, deadline: float) -> int:
    while True:
        waited_pid, status = os.waitpid(pid, os.WNOHANG)
        if waited_pid == pid:
            return os.waitstatus_to_exitcode(status)
        if time.monotonic() >= deadline:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            raise RuntimeError("timed out waiting for native launcher exit")
        time.sleep(0.01)


def _spawn_and_collect(
    launcher_fd: int,
    leaf: Path,
    *,
    deny_pidfd_send_signal: bool = False,
    prequeue_input: bool = False,
    close_peer: bool = False,
    retain_extra_descriptor: bool = False,
) -> _LaunchResult:
    stdin_fd = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
    stdout_fd = os.open("/dev/null", os.O_WRONLY | os.O_CLOEXEC)
    stderr_fd = os.open("/dev/null", os.O_WRONLY | os.O_CLOEXEC)
    leaf_fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    parent_control, child_control = socket.socketpair(
        socket.AF_UNIX,
        socket.SOCK_SEQPACKET | _SOCK_CLOEXEC_LINUX,
    )
    original_descriptors = (stdin_fd, stdout_fd, stderr_fd, child_control.fileno(), leaf_fd)
    sources: tuple[int, int, int, int, int] | None = None
    pid: int | None = None
    waited = False
    deadline = time.monotonic() + _CASE_TIMEOUT_SECONDS
    try:
        sources = _duplicate_sources(original_descriptors)

        child_control.close()
        for descriptor in (stdin_fd, stdout_fd, stderr_fd, leaf_fd):
            os.close(descriptor)

        if prequeue_input and parent_control.send(b"x") != 1:
            raise RuntimeError("failed to queue native inbound-control adversary")
        if close_peer:
            parent_control.close()

        pid = os.fork()
        if pid == 0:
            _child_exec(
                launcher_fd,
                sources,
                deny_pidfd_send_signal=deny_pidfd_send_signal,
                retain_extra_descriptor=retain_extra_descriptor,
            )

        for descriptor in sources:
            os.close(descriptor)
        sources = None

        records: tuple[InertNativeSocketRecord, ...] = ()
        eof_observed = False
        if not close_peer:
            records, eof_observed = _collect_records(parent_control, deadline)
            parent_control.close()
        returncode = _wait_exact_child(pid, deadline)
        waited = True
        return _LaunchResult(
            pid=pid,
            returncode=returncode,
            records=records,
            eof_observed=eof_observed,
        )
    finally:
        if sources is not None:
            for descriptor in sources:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
        for descriptor in original_descriptors:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        with contextlib.suppress(OSError):
            parent_control.close()
        with contextlib.suppress(OSError):
            child_control.close()
        if pid is not None and pid > 0 and not waited:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
            with contextlib.suppress(ChildProcessError):
                os.waitpid(pid, 0)


def _assert_no_reparented_child() -> None:
    try:
        child_pid, _status = os.waitpid(-1, os.WNOHANG)
    except ChildProcessError:
        return
    if child_pid == 0:
        raise RuntimeError("a live child remained after the launcher exited")
    raise RuntimeError(f"an unreaped launcher descendant remained as PID {child_pid}")


def _require_empty_leaf(leaf: Path) -> None:
    if _read_nonempty_lines(leaf / "cgroup.procs"):
        raise RuntimeError("native launcher left a process in its cgroup leaf")
    events = dict(
        line.split(" ", 1) for line in _read_nonempty_lines(leaf / "cgroup.events")
    )
    if events.get("populated") != "0":
        raise RuntimeError("native launcher left its cgroup leaf populated")


def _cleanup_leaf(leaf: Path) -> None:
    if not leaf.exists():
        return
    with contextlib.suppress(OSError):
        _write_control(leaf / "cgroup.kill", "1")
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            if not _read_nonempty_lines(leaf / "cgroup.procs"):
                break
        except OSError:
            break
        time.sleep(0.01)
    with contextlib.suppress(OSError):
        leaf.rmdir()


def _fresh_leaf(root: Path, suffix: str, case: str) -> Path:
    leaf = root / f"bpe-native-launcher-{case}-{suffix}"
    leaf.mkdir()
    try:
        if (leaf / "cgroup.type").read_text(encoding="ascii") != "domain\n":
            raise RuntimeError("native launcher probe requires a domain cgroup leaf")
        _require_empty_leaf(leaf)
        return leaf
    except BaseException:
        _cleanup_leaf(leaf)
        raise


def _run_success(launcher_fd: int, leaf: Path) -> _LaunchResult:
    result = _spawn_and_collect(launcher_fd, leaf)
    if not result.records:
        raise RuntimeError(
            "native launcher emitted no success transcript; "
            f"returncode={result.returncode}, eof={result.eof_observed}"
        )
    transcript = parse_inert_native_transcript(
        result.records,
        returncode=result.returncode,
        eof_observed=result.eof_observed,
        expected_launcher_pid=result.pid,
    )
    if (
        not transcript.succeeded
        or transcript.launcher_exit_code is not NativeExitCode.OK
        or transcript.achieved_result_mask != ACHIEVED_RESULT_MASK
        or transcript.achieved_result_mask != 0x1FF
        or transcript.child_pid is None
    ):
        raise RuntimeError("native launcher did not produce the exact success evidence")
    return result


def _run_extra_descriptor(launcher_fd: int, leaf: Path) -> _LaunchResult:
    result = _spawn_and_collect(launcher_fd, leaf, retain_extra_descriptor=True)
    if not result.records:
        raise RuntimeError(
            "native launcher emitted no extra-descriptor failure transcript; "
            f"returncode={result.returncode}, eof={result.eof_observed}"
        )
    transcript = parse_inert_native_transcript(
        result.records,
        returncode=result.returncode,
        eof_observed=result.eof_observed,
        expected_launcher_pid=result.pid,
    )
    if (
        transcript.succeeded
        or transcript.failure_reason is not NativeReason.BAD_DESCRIPTOR_LAYOUT
        or transcript.failure_stage is not NativeStage.DESCRIPTOR_VALIDATION
        or transcript.achieved_result_mask != 0
    ):
        raise RuntimeError("native launcher did not reject the unexpected high descriptor")
    return result


def _run_inbound_control(launcher_fd: int, leaf: Path) -> _LaunchResult:
    result = _spawn_and_collect(launcher_fd, leaf, prequeue_input=True)
    if (
        result.returncode != int(NativeExitCode.STARTUP)
        or result.records
        or not result.eof_observed
    ):
        raise RuntimeError("native launcher did not fail closed on inbound control data")
    try:
        parse_inert_native_transcript(
            result.records,
            returncode=result.returncode,
            eof_observed=result.eof_observed,
            expected_launcher_pid=result.pid,
        )
    except InertNativeProtocolViolation:
        pass
    else:
        raise RuntimeError("empty inbound-control failure was accepted as transcript evidence")
    return result


def _run_closed_peer(launcher_fd: int, leaf: Path) -> _LaunchResult:
    result = _spawn_and_collect(launcher_fd, leaf, close_peer=True)
    if result.returncode != int(NativeExitCode.PROTOCOL) or result.records:
        raise RuntimeError("native launcher did not fail closed when its peer was absent")
    try:
        parse_inert_native_transcript(
            result.records,
            returncode=result.returncode,
            eof_observed=False,
            expected_launcher_pid=result.pid,
        )
    except InertNativeProtocolViolation:
        pass
    else:
        raise RuntimeError("peer-close failure was accepted as transcript evidence")
    return result


def _run_emergency_cgroup_kill(launcher_fd: int, leaf: Path) -> _LaunchResult:
    result = _spawn_and_collect(
        launcher_fd,
        leaf,
        deny_pidfd_send_signal=True,
    )
    if not result.records:
        raise RuntimeError(
            "native launcher emitted no emergency-cleanup transcript; "
            f"returncode={result.returncode}, eof={result.eof_observed}"
        )
    transcript = parse_inert_native_transcript(
        result.records,
        returncode=result.returncode,
        eof_observed=result.eof_observed,
        expected_launcher_pid=result.pid,
    )
    if (
        transcript.succeeded
        or transcript.launcher_exit_code is not NativeExitCode.KERNEL
        or tuple(frame.frame_type for frame in transcript.frames)
        != (
            NativeFrameType.HELLO,
            NativeFrameType.CHILD_READY,
            NativeFrameType.ERROR,
        )
        or transcript.child_pid is None
        or transcript.failure_stage is not NativeStage.PIDFD_SIGNAL
        or transcript.failure_reason is not NativeReason.PIDFD_SIGNAL_FAILED
        or transcript.failure_errno != errno.EPERM
        or transcript.achieved_result_mask != 0x1C3
    ):
        raise RuntimeError(
            "native launcher did not produce the exact emergency-cleanup outcome evidence"
        )
    return result


def _run_case(
    root: Path,
    suffix: str,
    launcher_fd: int,
    duplicate: _DuplicateSeal,
    case: str,
) -> _CaseObservation:
    leaf = _fresh_leaf(root, suffix, case)
    try:
        if case == "success":
            result = _run_success(launcher_fd, leaf)
        elif case == "extra-fd":
            result = _run_extra_descriptor(launcher_fd, leaf)
        elif case == "inbound":
            result = _run_inbound_control(launcher_fd, leaf)
        elif case == "peer-close":
            result = _run_closed_peer(launcher_fd, leaf)
        elif case == "emergency-cgroup-kill":
            result = _run_emergency_cgroup_kill(launcher_fd, leaf)
        else:  # pragma: no cover - fixed caller cases
            raise RuntimeError(f"unknown native launcher probe case: {case}")

        try:
            parser_value = parse_inert_native_transcript(
                result.records,
                returncode=result.returncode,
                eof_observed=result.eof_observed,
                expected_launcher_pid=result.pid,
            )
        except InertNativeProtocolViolation:
            parser_outcome: Literal["accepted", "rejected"] = "rejected"
            parser_rejection: Literal["empty_transcript", "eof_not_observed"] | None
            if case == "inbound":
                parser_rejection = "empty_transcript"
            elif case == "peer-close":
                parser_rejection = "eof_not_observed"
            else:
                raise RuntimeError("an accepted native case failed parser replay") from None
            parsed: object | None = None
        else:
            if case in {"inbound", "peer-close"}:
                raise RuntimeError("a rejected native case passed parser replay")
            parser_outcome = "accepted"
            parser_rejection = None
            parsed = parser_value

        _require_empty_leaf(leaf)
        _assert_no_reparented_child()
        leaf.rmdir()
        if leaf.exists():
            raise RuntimeError("native launcher leaf still exists after exact removal")
        return _CaseObservation(
            case_name=case,
            result=result,
            parser_outcome=parser_outcome,
            parser_value=parsed,
            parser_rejection=parser_rejection,
            duplicate=duplicate,
            strict_cleanup_complete=True,
        )
    except BaseException:
        _cleanup_leaf(leaf)
        raise


def _finish_manager_cgroup(
    root: Path,
    manager: Path,
    *,
    moved_to_manager: bool,
    strict: bool,
) -> _ManagerFinalization | None:
    if not strict:
        if moved_to_manager:
            with contextlib.suppress(OSError):
                _write_control(root / "cgroup.procs", str(os.getpid()))
        _cleanup_leaf(manager)
        return None
    try:
        if not moved_to_manager:
            raise RuntimeError("probe never entered the native launcher manager cgroup")
        _write_control(root / "cgroup.procs", str(os.getpid()))
        if _read_nonempty_lines(root / "cgroup.procs") != ("1",):
            raise RuntimeError("probe PID was not restored to the cgroup namespace root")
        _require_empty_leaf(manager)
        manager.rmdir()
        if manager.exists():
            raise RuntimeError("native launcher manager cgroup still exists after removal")
        return _ManagerFinalization(
            probe_restored_to_root=True,
            manager_empty=True,
            manager_removed=True,
        )
    except BaseException:
        with contextlib.suppress(OSError):
            _write_control(root / "cgroup.procs", str(os.getpid()))
        _cleanup_leaf(manager)
        raise


def _require_exact_mode(path: Path, *, expected: int, label: str) -> None:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != expected:
        raise RuntimeError(f"{label} does not have mode {expected:#o}")


def _require_fixed_mounts(launcher: Path) -> None:
    readonly_paths = (
        (_PROVENANCE_PATH, "provenance context", 0o444),
        (_TRACKED_TREE_MANIFEST_PATH, "tracked-tree manifest", 0o444),
        (_BUILT_WHEEL_PATH, "built wheel", 0o444),
        (Path("/probe.py"), "probe source", 0o444),
        (launcher, "native launcher", 0o555),
        (_DEPENDENCY_ROOT, "dependency tree", 0o555),
        (_SOURCE_ROOT, "critical source tree", 0o555),
    )
    for path, label, mode in readonly_paths:
        _require_readonly_mount(path, label=label)
        _require_exact_mode(path, expected=mode, label=label)
    _require_readwrite_mount(_QUALIFICATION_OUTPUT_DIRECTORY, label="qualification output")
    _require_exact_mode(
        _QUALIFICATION_OUTPUT_DIRECTORY,
        expected=0o700,
        label="qualification output",
    )


def _build_invocation(
    provenance: _Provenance,
    *,
    context_sha256: str,
    context_size_bytes: int,
    tracked_tree_manifest_sha256: str,
    tracked_tree_manifest_size_bytes: int,
    wheel_size_bytes: int,
    source: _SourceClosure,
    runtime: _RuntimeEvidence,
    launcher: _ArtifactSeal,
) -> NativeQualificationContainerInvocation:
    source_by_path = {item.path: item for item in source.files}
    probe = source_by_path["tests/integration/inert_fixture_launcher_native_probe.py"]
    bindings = (
        NativeQualificationMountBinding(
            purpose="provenance-context",
            target_path="/qualification-provenance/context.json",
            target_kind="file",
            source_sha256=context_sha256,
            source_size_bytes=context_size_bytes,
            readonly=True,
            target_mode=0o444,
        ),
        NativeQualificationMountBinding(
            purpose="tracked-tree-manifest",
            target_path=(
                "/qualification-provenance/tracked-tree-content-manifest.json"
            ),
            target_kind="file",
            source_sha256=tracked_tree_manifest_sha256,
            source_size_bytes=tracked_tree_manifest_size_bytes,
            readonly=True,
            target_mode=0o444,
        ),
        NativeQualificationMountBinding(
            purpose="built-wheel",
            target_path=NATIVE_QUALIFICATION_BUILT_WHEEL_PATH,
            target_kind="file",
            source_sha256=provenance.built_wheel_sha256,
            source_size_bytes=wheel_size_bytes,
            readonly=True,
            target_mode=0o444,
        ),
        NativeQualificationMountBinding(
            purpose="probe",
            target_path="/probe.py",
            target_kind="file",
            source_sha256=probe.sha256,
            source_size_bytes=probe.size_bytes,
            readonly=True,
            target_mode=0o444,
        ),
        NativeQualificationMountBinding(
            purpose="launcher",
            target_path="/launcher",
            target_kind="file",
            source_sha256=launcher.sha256,
            source_size_bytes=launcher.identity[6],
            readonly=True,
            target_mode=0o555,
        ),
        NativeQualificationMountBinding(
            purpose="dependency-tree",
            target_path="/dependencies",
            target_kind="directory",
            source_sha256=runtime.dependency_tree_sha256,
            source_size_bytes=runtime.dependency_tree_size_bytes,
            readonly=True,
            target_mode=0o555,
        ),
        NativeQualificationMountBinding(
            purpose="source-tree",
            target_path="/qualification-source",
            target_kind="directory",
            source_sha256=source.manifest.manifest_sha256,
            source_size_bytes=source.total_bytes,
            readonly=True,
            target_mode=0o555,
        ),
        NativeQualificationMountBinding(
            purpose="qualification-output",
            target_path="/qualification-output",
            target_kind="directory",
            source_sha256=None,
            source_size_bytes=None,
            readonly=False,
            target_mode=0o700,
        ),
    )
    fields: dict[str, object] = {
        "schema_version": "bpe.linux-inert-launcher-native-invocation.v1",
        "image_reference": provenance.image_reference,
        "image_manifest_sha256": provenance.image_manifest_sha256,
        "image_platform_sha256": provenance.image_platform_sha256,
        "image_config_sha256": provenance.image_config_sha256,
        "platform": "linux/amd64",
        "command_contract": "python-no-site-pid1-sealed-fd-exec-v1",
        "privileged_configured": True,
        "pid_namespace_mode": "container-default-private",
        "mount_namespace_mode": "container-default-private",
        "user_namespace_mode": "daemon-default-recorded-only",
        "cgroup_namespace_mode": "private",
        "network_mode": "none",
        "mount_bindings": bindings,
        "distribution_mount_readonly": True,
        "launcher_mount_readonly": True,
        "probe_mount_readonly": True,
        "dependencies_mount_readonly": True,
        "qualification_output_mount": "dedicated-readwrite-output-v1",
        "qualification_output_mount_readwrite": True,
    }
    fields["invocation_sha256"] = sha256_bytes(
        NATIVE_QUALIFICATION_INVOCATION_DOMAIN + canonical_json_bytes(fields)
    )
    return NativeQualificationContainerInvocation.model_validate(fields, strict=True)


def _build_source_run(
    provenance: _Provenance,
    *,
    provenance_sha256: str,
    provenance_size_bytes: int,
    source: _SourceClosure,
    tracked_tree_sha256: str,
    tracked_tree_manifest_size_bytes: int,
    tracked_tree_total_bytes: int,
    wheel_size_bytes: int,
    wheel_bpe_tree_sha256: str,
) -> NativeQualificationSourceRun:
    source_by_path = {item.path: item for item in source.files}
    workflow = source_by_path[".github/workflows/native-qualification.yml"]
    probe = source_by_path["tests/integration/inert_fixture_launcher_native_probe.py"]
    upstream = NativeQualificationUpstreamWorkflowRun(
        workflow_name=provenance.upstream_workflow_name,
        workflow_id=provenance.upstream_workflow_id,
        workflow_path=provenance.upstream_workflow_path,
        run_id=provenance.upstream_run_id,
        run_attempt=provenance.upstream_run_attempt,
        event=provenance.upstream_event,
        head_branch=provenance.upstream_head_branch,
        head_repository_full_name=(
            provenance.upstream_head_repository_full_name
        ),
        head_sha=provenance.upstream_head_sha,
        conclusion=provenance.upstream_conclusion,
    )
    return NativeQualificationSourceRun(
        repository=f"github.com/{provenance.github_repository}",
        git_commit=provenance.git_commit,
        github_context_file_sha256=provenance_sha256,
        github_context_file_size_bytes=provenance_size_bytes,
        source_manifest=source.manifest,
        source_manifest_total_bytes=source.total_bytes,
        tracked_tree_manifest_method=(
            "git-commit-blob-canonical-content-manifest-v1"
        ),
        tracked_tree_content_manifest_sha256=tracked_tree_sha256,
        tracked_tree_manifest_file_size_bytes=tracked_tree_manifest_size_bytes,
        tracked_tree_total_bytes=tracked_tree_total_bytes,
        tracked_tree_matches_git_commit=True,
        commit_bpe_tree_manifest_method=(
            "git-src-bpe-to-installed-bpe-tree-content-manifest-v1"
        ),
        commit_bpe_tree_manifest_sha256=(
            native_qualification_commit_bpe_tree_manifest_sha256(source.manifest)
        ),
        built_wheel_bpe_tree_manifest_method=(
            "closed-wheel-bpe-tree-content-manifest-v1"
        ),
        built_wheel_bpe_tree_manifest_sha256=wheel_bpe_tree_sha256,
        built_wheel_size_bytes=wheel_size_bytes,
        probe_source_size_bytes=probe.size_bytes,
        workflow_path=".github/workflows/native-qualification.yml",
        workflow_sha256=workflow.sha256,
        github_repository=provenance.github_repository,
        github_sha=provenance.github_sha,
        github_run_id=provenance.github_run_id,
        github_run_attempt=provenance.github_run_attempt,
        github_job=provenance.github_job,
        github_event=provenance.github_event,
        github_ref="refs/heads/main",
        github_actor_category=provenance.github_actor_category,
        upstream_workflow_run=upstream,
        context_source="github-actions-workflow-run-environment-v1",
        ci_context_authenticated=False,
        built_wheel_sha256=provenance.built_wheel_sha256,
    )


def _build_container(
    provenance: _Provenance,
    *,
    invocation: NativeQualificationContainerInvocation,
    runtime: _RuntimeEvidence,
    source: _SourceClosure,
) -> NativeQualificationContainer:
    source_by_path = {item.path: item for item in source.files}
    return NativeQualificationContainer(
        invocation=invocation,
        docker_server_version=provenance.docker_server_version,
        runtime_name=provenance.runtime_name,
        runtime_version=provenance.runtime_version,
        runtime_id=provenance.runtime_id,
        runtime_dependency_manifest_method=(
            "python-distribution-summary-tree-digest-v1"
        ),
        runtime_dependency_manifest_sha256=runtime.manifest_sha256,
        runtime_distributions=runtime.distributions,
        dependency_root_tree_manifest_method=(
            "canonical-relative-path-content-manifest-v1"
        ),
        dependency_root_tree_sha256=runtime.dependency_tree_sha256,
        dependency_root_total_bytes=runtime.dependency_tree_size_bytes,
        runtime_distribution_wheel_sha256=provenance.built_wheel_sha256,
        runtime_bpe_tree_manifest_method="installed-bpe-tree-content-manifest-v1",
        runtime_bpe_tree_manifest_sha256=runtime.bpe_tree_sha256,
        runtime_bpe_tree_matches_built_wheel=True,
        runtime_root_tree_manifest_method=(
            "canonical-relative-path-content-manifest-v1"
        ),
        runtime_root_tree_completeness_method=(
            "recursive-lstat-exact-wheel-projection-v1"
        ),
        runtime_root_tree_sha256=runtime.runtime_tree_sha256,
        runtime_root_total_bytes=runtime.runtime_tree_size_bytes,
        runtime_probe_source_sha256=source_by_path[
            "tests/integration/inert_fixture_launcher_native_probe.py"
        ].sha256,
        runtime_lockfile_sha256=source_by_path["uv.lock"].sha256,
        observed_invocation_sha256=invocation.invocation_sha256,
        pid_one_observed=True,
        effective_uid_zero_observed=True,
        privileged_observed=True,
        pid_namespace_private_observed=True,
        mount_namespace_private_observed=True,
        user_namespace_identity_recorded=True,
        user_namespace_private_qualified=False,
        cgroup_namespace_private_observed=True,
        network_namespace_isolated_observed=True,
        single_threaded_before_fork=True,
        cgroup_root_initially_only_pid_one=True,
        fault_profile_id=NATIVE_QUALIFICATION_FAULT_PROFILE_ID,
        outer_seccomp_instruction_contract_sha256=(
            NATIVE_QUALIFICATION_OUTER_SECCOMP_CONTRACT_SHA256
        ),
    )


def _build_artifact_evidence(
    provenance: _Provenance,
    *,
    receipt: Any,
    source: _SourceClosure,
    observations: tuple[_CaseObservation, ...],
) -> NativeQualificationArtifact:
    source_by_path = {item.path: item for item in source.files}
    duplicates = tuple(
        NativeQualificationArtifactDuplicate(
            case_name=cast(Any, observation.case_name),
            duplicate_sha256=observation.duplicate.sha256,
            duplicate_size_bytes=observation.duplicate.size_bytes,
            duplicate_device=observation.duplicate.device,
            duplicate_inode=observation.duplicate.inode,
            duplicate_mode=observation.duplicate.mode,
            duplicate_nlink=cast(Any, observation.duplicate.nlink),
            duplicate_seals=cast(Any, observation.duplicate.seals),
            duplicate_readonly_verified=observation.duplicate.readonly_verified,
            duplicate_cloexec_verified=observation.duplicate.cloexec_verified,
            duplicate_identity_verified=observation.duplicate.identity_verified,
            executed_from_duplicate=True,
        )
        for observation in observations
    )
    return NativeQualificationArtifact(
        launcher_artifact_id=receipt.launcher_artifact_id,
        launcher_sha256=receipt.launcher_artifact_sha256,
        launcher_source_sha256=source_by_path[
            "worker/linux/inert_fixture_launcher/launcher.c"
        ].sha256,
        launcher_size_bytes=receipt.sealed_copy_size_bytes,
        launcher_build_id_sha1=provenance.launcher_build_id_sha1,
        build_tools=NativeQualificationBuildTools(
            compiler_identity=provenance.compiler_identity,
            linker_identity=provenance.linker_identity,
            libc_identity=provenance.libc_identity,
            binutils_identity=provenance.binutils_identity,
        ),
        seccomp_policy_id=FIXED_SECCOMP_POLICY_ID,
        seccomp_policy_sha256=FIXED_SECCOMP_POLICY_SHA256,
        preflight_receipt=receipt,
        preflight_id=receipt.preflight_id,
        sealed_copy_sha256=receipt.sealed_copy_sha256,
        sealed_copy_seals=cast(Any, receipt.sealed_copy_seals),
        sealed_copy_readonly_verified=True,
        sealed_copy_cloexec_verified=True,
        sealed_copy_identity_verified=True,
        source_artifact_unchanged_after_preflight=True,
        case_duplicates=duplicates,
    )


def _build_case_evidence(
    observations: tuple[_CaseObservation, ...],
) -> tuple[NativeQualificationCase, ...]:
    cases: list[NativeQualificationCase] = []
    for observation in observations:
        cleanup = NativeQualificationCaseCleanup(
            cleanup_method="exact-wait-empty-rmdir-v1",
            launcher_waited_exact=True,
            no_reparented_child_observed=True,
            leaf_cgroup_procs_empty=True,
            leaf_populated_zero=True,
            leaf_removed=True,
            evaluator_fallback_cleanup_used=False,
        )
        built = build_inert_native_qualification_case(
            case_name=cast(Any, observation.case_name),
            launcher_pid=observation.result.pid,
            returncode=observation.result.returncode,
            eof_observed=observation.result.eof_observed,
            records=observation.result.records,
            cleanup=cleanup,
        )
        reconstructed = tuple(record.to_native_record() for record in built.records)
        if (
            reconstructed != observation.result.records
            or built.parser_outcome != observation.parser_outcome
            or built.parser_rejection != observation.parser_rejection
            or not observation.strict_cleanup_complete
        ):
            raise RuntimeError("native qualification case builder changed captured evidence")
        cases.append(built)
    return tuple(cases)


def _build_report(
    *,
    provenance: _Provenance,
    source_run: NativeQualificationSourceRun,
    host: NativeQualificationHost,
    container: NativeQualificationContainer,
    artifact: NativeQualificationArtifact,
    cases: tuple[NativeQualificationCase, ...],
    manager: _ManagerFinalization,
) -> LinuxInertLauncherNativeQualificationReport:
    context_sha256 = native_qualification_context_sha256(
        git_commit=source_run.git_commit,
        source_manifest_sha256=source_run.source_manifest.manifest_sha256,
        tracked_tree_content_manifest_sha256=(
            source_run.tracked_tree_content_manifest_sha256
        ),
        tracked_tree_matches_git_commit=source_run.tracked_tree_matches_git_commit,
        built_wheel_sha256=source_run.built_wheel_sha256,
        runtime_dependency_manifest_sha256=container.runtime_dependency_manifest_sha256,
        runtime_root_tree_sha256=container.runtime_root_tree_sha256,
        runtime_root_total_bytes=container.runtime_root_total_bytes,
        runtime_root_tree_completeness_method=(
            container.runtime_root_tree_completeness_method
        ),
        launcher_sha256=artifact.launcher_sha256,
        workflow_sha256=source_run.workflow_sha256,
        github_repository=provenance.github_repository,
        github_sha=provenance.github_sha,
        github_run_id=provenance.github_run_id,
        github_run_attempt=provenance.github_run_attempt,
        github_job=provenance.github_job,
        github_event=provenance.github_event,
        github_ref="refs/heads/main",
        github_actor_category=provenance.github_actor_category,
        upstream_workflow_run=source_run.upstream_workflow_run,
        container_invocation_sha256=container.invocation.invocation_sha256,
    )
    fields: dict[str, object] = {
        "schema_version": (
            "bpe.linux-inert-launcher-native-qualification-report.v1"
        ),
        "status": "native_probe_passed_unsigned",
        "qualification_nonce": secrets.token_bytes(32).hex(),
        "qualification_nonce_method": "secrets-token-bytes-256-bit-v1",
        "qualification_nonce_purpose": "run-correlation-only",
        "parser_contract_id": NATIVE_QUALIFICATION_PARSER_ID,
        "case_set_id": NATIVE_QUALIFICATION_CASE_SET_ID,
        "case_set_sha256": NATIVE_QUALIFICATION_CASE_SET_SHA256,
        "context_sha256": context_sha256,
        "source_run": source_run,
        "host": host,
        "container": container,
        "artifact": artifact,
        "cases": cases,
        "finalization": NativeQualificationFinalization(
            probe_restored_to_cgroup_namespace_root=manager.probe_restored_to_root,
            manager_cgroup_empty=manager.manager_empty,
            manager_cgroup_removed=manager.manager_removed,
            every_launcher_duplicate_closed=True,
            retained_artifact_closed=True,
            source_artifact_descriptor_closed=True,
        ),
        "preflight_before_process_creation_verified": True,
        "launcher_execution_started": True,
        "fixture_execution_started": True,
        "launcher_process_count": 5,
        "fixture_child_process_count": 2,
        "execution_scope": "evaluator-only-native-qualification",
        "production_launch_admission_used": False,
        "production_launch_attempts_consumed": 0,
        "authenticity": "unsigned",
        "durable": False,
        "sigstore_attested": False,
        "worm_archived": False,
        "provenance_authenticated": False,
        "externally_anchored": False,
        "freshness_authenticated": False,
        "authoritative": False,
        "execution_authorized": False,
        "fixture_child_exec_performed": False,
        "candidate_bytes_accessed": False,
        "evaluation_job_bytes_accessed": False,
        "resource_pressure_qualified": False,
        "descendant_tree_cleanup_qualified": False,
        "filesystem_isolation_qualified": False,
        "network_isolation_qualified": False,
        "signed_deadlines_qualified": False,
        "signed_output_limits_qualified": False,
        "production_orchestration_qualified": False,
        "official_grading_qualified": False,
    }
    fields["qualification_id"] = inert_native_qualification_id(fields)
    return LinuxInertLauncherNativeQualificationReport.model_validate(fields, strict=True)


def _rename_without_replacement(
    directory_descriptor: int,
    temporary_name: str,
    final_name: str,
) -> None:
    if sys.platform != "linux" or platform.machine() != "x86_64":
        raise RuntimeError("atomic qualification publication requires Linux x86-64")
    syscall = _LIBC.syscall
    syscall.restype = ctypes.c_long
    ctypes.set_errno(0)
    result = int(
        syscall(
            _RENAMEAT2_SYSCALL_X86_64,
            directory_descriptor,
            temporary_name.encode("ascii"),
            directory_descriptor,
            final_name.encode("ascii"),
            _RENAME_NOREPLACE,
        )
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _publish_qualified_report(raw: bytes) -> None:
    if validate_inert_native_qualification_report_bytes(raw) is None:  # pragma: no cover
        raise RuntimeError("native qualification report validation returned no report")
    output = _QUALIFICATION_OUTPUT_DIRECTORY
    directory_descriptor = os.open(
        output,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    temporary_name = f".{_QUALIFICATION_OUTPUT_NAME}.{secrets.token_hex(16)}.tmp"
    temporary_descriptor = -1
    try:
        if os.listdir(directory_descriptor):
            raise RuntimeError("qualification output directory is not empty")
        temporary_descriptor = os.open(
            temporary_name,
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_descriptor,
        )
        written = 0
        while written < len(raw):
            count = os.write(temporary_descriptor, raw[written:])
            if count <= 0:
                raise RuntimeError("short write while publishing qualification report")
            written += count
        os.fchmod(temporary_descriptor, 0o600)
        os.fsync(temporary_descriptor)
        if stat.S_IMODE(os.fstat(temporary_descriptor).st_mode) != 0o600:
            raise RuntimeError("qualification report temporary mode is not 0600")
        repeated = os.pread(temporary_descriptor, len(raw) + 1, 0)
        if repeated != raw:
            raise RuntimeError("qualification report changed before publication")
        validate_inert_native_qualification_report_bytes(repeated)
        _close_exact(
            temporary_descriptor,
            label="qualification report temporary descriptor",
        )
        temporary_descriptor = -1
        os.fsync(directory_descriptor)
    except BaseException:
        if temporary_descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(temporary_descriptor)
        with contextlib.suppress(OSError):
            os.unlink(temporary_name, dir_fd=directory_descriptor)
        with contextlib.suppress(OSError):
            os.close(directory_descriptor)
        raise

    try:
        _rename_without_replacement(
            directory_descriptor,
            temporary_name,
            _QUALIFICATION_OUTPUT_NAME,
        )
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary_name, dir_fd=directory_descriptor)
        with contextlib.suppress(OSError):
            os.close(directory_descriptor)
        raise
    # Deliberately perform no fallible work after no-replace publication.  The
    # descriptor is reclaimed at process exit.  This unsigned report makes no
    # directory-fsync durability claim.


def _collect_qualified_report_bytes(
    *,
    launcher: Path,
    expected_sha256: str,
) -> bytes:
    if (
        len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
    ):
        raise RuntimeError("native launcher probe requires a lowercase SHA-256 anchor")
    if launcher != Path("/launcher") or Path(__file__).resolve() != Path("/probe.py"):
        raise RuntimeError("native qualification inputs are not at their fixed mount targets")
    if os.execve not in os.supports_fd:
        raise RuntimeError("native launcher probe requires fd-capable os.execve")

    provenance_raw = _read_bounded_path(
        _PROVENANCE_PATH,
        maximum_bytes=_MAX_PROVENANCE_BYTES,
        label="provenance context",
    )
    provenance = _load_provenance(_PROVENANCE_PATH)
    _require_trusted_workflow_run(provenance)
    _require_fixed_mounts(launcher)
    if tuple(_QUALIFICATION_OUTPUT_DIRECTORY.iterdir()):
        raise RuntimeError("qualification output directory must start empty")

    root = Path("/sys/fs/cgroup")
    _require_private_namespace(root)
    _require_privileged_container()
    _require_network_namespace_isolated()

    source = _snapshot_source_tree(_SOURCE_ROOT)
    (
        tracked_tree_sha256,
        tracked_tree_manifest_size_bytes,
        tracked_tree_total_bytes,
    ) = _load_tracked_tree_manifest(_TRACKED_TREE_MANIFEST_PATH, source)
    wheel_size_bytes, wheel_bpe_tree_sha256 = _require_built_wheel(
        _BUILT_WHEEL_PATH,
        provenance.built_wheel_sha256,
    )
    _require_runtime_import_roots(_RUNTIME_ROOT, source)
    runtime = _runtime_dependency_evidence(_RUNTIME_ROOT, _DEPENDENCY_ROOT)
    if runtime.bpe_tree_sha256 != wheel_bpe_tree_sha256:
        raise RuntimeError("installed BPE tree differs from the built wheel")
    probe_snapshot = {
        item.path: item for item in source.files
    }["tests/integration/inert_fixture_launcher_native_probe.py"]
    if sha256_bytes(
        _read_bounded_path(
            Path("/probe.py"),
            maximum_bytes=_MAX_SOURCE_FILE_BYTES,
            label="mounted probe source",
        )
    ) != probe_snapshot.sha256:
        raise RuntimeError("executed probe differs from the critical source closure")

    provenance_sha256 = sha256_bytes(provenance_raw)
    provenance_size_bytes = len(provenance_raw)
    host = _build_host(root, provenance)

    source_fd = os.open(
        launcher,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    artifact: LinuxInertLauncherArtifact | None = None
    artifact_receipt: Any | None = None
    source_seal: _ArtifactSeal | None = None
    observations: tuple[_CaseObservation, ...] = ()
    manager_finalization: _ManagerFinalization | None = None
    try:
        source_seal = _seal_artifact(
            source_fd,
            expected_sha256=expected_sha256,
        )
        if _elf_build_id_sha1(source_fd) != provenance.launcher_build_id_sha1:
            raise RuntimeError("launcher build ID differs from CI provenance")
        with tempfile.TemporaryDirectory(prefix="bpe-native-probe-") as temp_directory:
            private_root = Path(temp_directory)
            if (
                private_root.stat().st_uid != 0
                or stat.S_IMODE(private_root.stat().st_mode) != 0o700
            ):
                raise RuntimeError("native probe private artifact root is unsafe")
            staged_fd, staged_seal = _stage_root_owned_artifact(
                source_fd,
                source_seal,
                private_root,
            )
            try:
                expectation = _launch_expectation(private_root, source_seal.sha256)
                artifact = preflight_inert_launcher_artifact(
                    expectation,
                    launcher_artifact_fd=staged_fd,
                )
            finally:
                _close_exact(staged_fd, label="privately staged launcher descriptor")
            _require_preflight_receipt_binding(artifact, staged_seal)
            artifact_receipt = artifact.receipt
            _require_artifact_unchanged(source_fd, source_seal)
            _close_exact(source_fd, label="source launcher artifact descriptor")
            source_fd = -1

            suffix = secrets.token_hex(8)
            manager = root / f"bpe-native-launcher-manager-{suffix}"
            manager.mkdir()
            moved_to_manager = False
            primary_error: BaseException | None = None
            captured: list[_CaseObservation] = []
            try:
                _write_control(manager / "cgroup.procs", str(os.getpid()))
                moved_to_manager = True
                if _read_nonempty_lines(root / "cgroup.procs"):
                    raise RuntimeError(
                        "private cgroup root was not empty after manager migration"
                    )
                for case in NATIVE_QUALIFICATION_CASES:
                    launcher_fd, duplicate = _duplicate_sealed_launcher(
                        artifact,
                        expected_sha256=source_seal.sha256,
                    )
                    try:
                        captured.append(
                            _run_case(
                                root,
                                suffix,
                                launcher_fd,
                                duplicate,
                                case,
                            )
                        )
                    finally:
                        _close_exact(
                            launcher_fd,
                            label=f"{case} sealed launcher duplicate",
                        )
            except BaseException as exc:
                primary_error = exc
                raise
            finally:
                finalized = _finish_manager_cgroup(
                    root,
                    manager,
                    moved_to_manager=moved_to_manager,
                    strict=primary_error is None,
                )
                if finalized is not None:
                    manager_finalization = finalized
            observations = tuple(captured)
            artifact.close()
            if not artifact.closed:
                raise RuntimeError("retained sealed launcher artifact remained open")
    finally:
        if artifact is not None and not artifact.closed:
            artifact.close()
        if source_fd >= 0:
            _close_exact(source_fd, label="failed source launcher artifact descriptor")

    if (
        artifact is None
        or not artifact.closed
        or artifact_receipt is None
        or source_seal is None
        or manager_finalization is None
        or len(observations) != len(NATIVE_QUALIFICATION_CASES)
    ):
        raise RuntimeError("native qualification finalization evidence is incomplete")
    _assert_no_reparented_child()
    if _read_nonempty_lines(root / "cgroup.procs") != ("1",):
        raise RuntimeError("probe was not finally isolated at the cgroup namespace root")

    _require_source_tree_unchanged(_SOURCE_ROOT, source)
    repeated_tracked = _load_tracked_tree_manifest(_TRACKED_TREE_MANIFEST_PATH, source)
    if repeated_tracked != (
        tracked_tree_sha256,
        tracked_tree_manifest_size_bytes,
        tracked_tree_total_bytes,
    ):
        raise RuntimeError("tracked-tree manifest changed during qualification")
    if _read_bounded_path(
        _PROVENANCE_PATH,
        maximum_bytes=_MAX_PROVENANCE_BYTES,
        label="provenance context",
    ) != provenance_raw:
        raise RuntimeError("provenance context changed during qualification")
    if _require_built_wheel(
        _BUILT_WHEEL_PATH,
        provenance.built_wheel_sha256,
    ) != (wheel_size_bytes, wheel_bpe_tree_sha256):
        raise RuntimeError("built wheel changed during qualification")
    _require_runtime_import_roots(_RUNTIME_ROOT, source)
    if _runtime_dependency_evidence(_RUNTIME_ROOT, _DEPENDENCY_ROOT) != runtime:
        raise RuntimeError("runtime dependency evidence changed during qualification")
    mounted_launcher = _read_bounded_path(
        launcher,
        maximum_bytes=MAX_LAUNCHER_ARTIFACT_BYTES,
        label="mounted launcher",
    )
    if sha256_bytes(mounted_launcher) != source_seal.sha256:
        raise RuntimeError("mounted launcher changed during qualification")

    invocation = _build_invocation(
        provenance,
        context_sha256=provenance_sha256,
        context_size_bytes=provenance_size_bytes,
        tracked_tree_manifest_sha256=tracked_tree_sha256,
        tracked_tree_manifest_size_bytes=tracked_tree_manifest_size_bytes,
        wheel_size_bytes=wheel_size_bytes,
        source=source,
        runtime=runtime,
        launcher=source_seal,
    )
    source_run = _build_source_run(
        provenance,
        provenance_sha256=provenance_sha256,
        provenance_size_bytes=provenance_size_bytes,
        source=source,
        tracked_tree_sha256=tracked_tree_sha256,
        tracked_tree_manifest_size_bytes=tracked_tree_manifest_size_bytes,
        tracked_tree_total_bytes=tracked_tree_total_bytes,
        wheel_size_bytes=wheel_size_bytes,
        wheel_bpe_tree_sha256=wheel_bpe_tree_sha256,
    )
    container = _build_container(
        provenance,
        invocation=invocation,
        runtime=runtime,
        source=source,
    )
    artifact_evidence = _build_artifact_evidence(
        provenance,
        receipt=artifact_receipt,
        source=source,
        observations=observations,
    )
    if native_qualification_github_context_bytes(
        source_run,
        host,
        container,
        artifact_evidence,
    ) != provenance_raw:
        raise RuntimeError("canonical report fields differ from the provenance context")
    cases = _build_case_evidence(observations)
    report = _build_report(
        provenance=provenance,
        source_run=source_run,
        host=host,
        container=container,
        artifact=artifact_evidence,
        cases=cases,
        manager=manager_finalization,
    )
    raw = canonical_inert_native_qualification_report_bytes(report)
    if len(raw) > MAX_NATIVE_QUALIFICATION_REPORT_BYTES:
        raise RuntimeError("native qualification report exceeds its byte bound")
    validated = validate_inert_native_qualification_report_bytes(raw)
    if validated != report:
        raise RuntimeError("native qualification report changed during validation")
    return raw


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--launcher", required=True, type=Path)
    parser.add_argument("--launcher-sha256", required=True)
    arguments = parser.parse_args()
    raw = _collect_qualified_report_bytes(
        launcher=arguments.launcher,
        expected_sha256=arguments.launcher_sha256,
    )
    _publish_qualified_report(raw)


if __name__ == "__main__":
    main()
