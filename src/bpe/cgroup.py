"""Fail-closed cgroup-v2 qualification without process or candidate execution.

This module qualifies one pre-opened, empty, systemd-delegated cgroup-v2 root by
creating a temporary empty leaf, applying a narrow subset of an execution resource
profile, verifying kernel readback, and removing the leaf through the same cleanup
path a later supervisor must use.  It can also retain that configured leaf for a
later supervisor while keeping cleanup ownership.  It deliberately has no process-
launch surface and grants no execution authority.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import os
import platform
import secrets
import select
import stat
import sys
import threading
import time
from contextlib import suppress
from dataclasses import dataclass
from typing import Annotated, Any, Literal, NoReturn, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from bpe.canonical import canonical_json_bytes, sha256_bytes, sha256_json
from bpe.dispatch import ExecutionResourceProfile
from bpe.models import Sha256, StableId

OPENAT2_SYSCALL_X86_64 = 437
O_PATH_LINUX = 0o10000000

RESOLVE_NO_XDEV = 0x01
RESOLVE_NO_MAGICLINKS = 0x02
RESOLVE_NO_SYMLINKS = 0x04
RESOLVE_BENEATH = 0x08
STRICT_RESOLVE_FLAGS = (
    RESOLVE_NO_XDEV
    | RESOLVE_NO_MAGICLINKS
    | RESOLVE_NO_SYMLINKS
    | RESOLVE_BENEATH
)

CGROUP2_SUPER_MAGIC = 0x63677270
CGROUP_QUALIFICATION_DOMAIN = b"BPE\x00cgroup-v2-qualification\x00v1\x00"
SYSTEMD_DELEGATION_XATTR = b"user.delegate"
SYSTEMD_DELEGATION_VALUE = b"1"
REQUIRED_CONTROLLERS: tuple[Literal["cpu"], Literal["memory"], Literal["pids"]] = (
    "cpu",
    "memory",
    "pids",
)
CPU_MAX_VALUE = "100000 100000"
MAX_CONTROL_BYTES = 4096
MAX_ROOT_ENTRIES = 1024
LEAF_PREFIX = "bpe-q-"


class _OpenHow(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    ]


CgroupFailureReason = Literal[
    "unsupported_platform",
    "unsupported_architecture",
    "unsupported_page_size",
    "openat2_unavailable",
    "openat2_abi_incompatible",
    "invalid_inputs",
    "unsafe_delegate",
    "not_cgroup_v2",
    "delegation_unverified",
    "delegate_busy",
    "controllers_unavailable",
    "controller_state_mismatch",
    "creation_conflict",
    "configuration_rejected",
    "readback_mismatch",
    "cgroup_changed",
    "cleanup_timeout",
    "cleanup_incomplete",
    "resource_exhausted",
    "io_failure",
]


class LinuxCgroupError(ValueError):
    """A bounded, path-free cgroup-v2 qualification failure."""

    reason: CgroupFailureReason

    def __init__(self, reason: CgroupFailureReason, message: str) -> None:
        self.reason = reason
        super().__init__(message)


class LinuxCgroupUnavailable(LinuxCgroupError):
    """The host cannot provide the exact cgroup-v2 qualification contract."""


class LinuxCgroupRejected(LinuxCgroupError):
    """The policy, profile, delegated root, or controller state failed closed."""


class LinuxCgroupLifecycleError(LinuxCgroupError):
    """Leaf creation, configuration, verification, or cleanup failed."""


class _CgroupModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        allow_inf_nan=False,
        revalidate_instances="always",
        strict=True,
    )


class LinuxCgroupV2QualificationPolicy(_CgroupModel):
    """Literal, non-authorizing policy for an empty cgroup-v2 lifecycle probe."""

    schema_version: Literal["bpe.linux-cgroup-v2-qualification-policy.v1"]
    policy_id: StableId
    worker_pool_audience: StableId
    delegated_root_id: StableId
    host_platform: Literal["linux"]
    host_architecture: Literal["x86_64"]
    filesystem: Literal["cgroup2-v2"]
    delegation_method: Literal["systemd-user.delegate-xattr-v1"]
    delegated_owner: Literal["current-euid"]
    delegated_root_group_other_writable: Literal[False]
    root_cgroup_type: Literal["domain"]
    root_empty_required: Literal[True]
    root_without_children_required: Literal[True]
    required_controllers: tuple[Literal["cpu"], Literal["memory"], Literal["pids"]]
    subtree_control_exact: Literal[True]
    component_open_method: Literal["openat2-v1"]
    resolve_beneath: Literal[True]
    resolve_no_xdev: Literal[True]
    resolve_no_symlinks: Literal[True]
    resolve_no_magiclinks: Literal[True]
    openat2_eagain_retries: Literal[3]
    leaf_name_method: Literal["random-256-bit-v1"]
    memory_limit_method: Literal["memory.max-v1"]
    swap_limit_method: Literal["memory.swap.max-zero-v1"]
    pids_limit_method: Literal["pids.max-v1"]
    cpu_limit_method: Literal["cpu.max-one-cpu-equivalent-bandwidth-v1"]
    cpu_quota_us: Literal[100000]
    cpu_period_us: Literal[100000]
    cpu_burst_us: Literal[0]
    base_page_size_bytes: Literal[4096]
    oom_group_method: Literal["memory.oom.group-v1"]
    leaf_max_depth: Literal[0]
    leaf_max_descendants: Literal[0]
    cleanup_method: Literal["cgroup.kill-events-rmdir-v1"]
    cleanup_timeout_ms: Literal[5000]
    process_creation_probed: Literal[False]
    execution_permitted: Literal[False]
    candidate_access_permitted: Literal[False]
    resource_profile_fully_enforced: Literal[False]
    authoritative_ready: Literal[False]

    @field_validator(
        "root_empty_required",
        "root_without_children_required",
        "subtree_control_exact",
        "resolve_beneath",
        "resolve_no_xdev",
        "resolve_no_symlinks",
        "resolve_no_magiclinks",
        mode="before",
    )
    @classmethod
    def true_controls_must_be_boolean_true(cls, value: object) -> object:
        if value is not True:
            raise ValueError("cgroup qualification safety controls must be boolean true")
        return value

    @field_validator(
        "delegated_root_group_other_writable",
        "process_creation_probed",
        "execution_permitted",
        "candidate_access_permitted",
        "resource_profile_fully_enforced",
        "authoritative_ready",
        mode="before",
    )
    @classmethod
    def false_claims_must_be_boolean_false(cls, value: object) -> object:
        if value is not False:
            raise ValueError("cgroup qualification cannot authorize execution or authority")
        return value

    @field_validator("required_controllers", mode="before")
    @classmethod
    def controller_arrays_are_tuples(cls, value: object) -> object:
        if isinstance(value, list):
            return tuple(value)
        return value

    @model_validator(mode="after")
    def controller_contract_is_exact(self) -> Self:
        if self.required_controllers != REQUIRED_CONTROLLERS:
            raise ValueError("cgroup qualification requires exact cpu, memory, and pids controls")
        return self


def _qualification_id(report_fields: dict[str, object]) -> str:
    if "qualification_id" in report_fields:
        raise ValueError("qualification identity input cannot contain its own digest")
    return sha256_bytes(
        CGROUP_QUALIFICATION_DOMAIN + canonical_json_bytes(report_fields)
    )


class LinuxCgroupV2QualificationReport(_CgroupModel):
    """Self-reported proof of an empty cgroup lifecycle, never launch authority."""

    schema_version: Literal["bpe.linux-cgroup-v2-qualification-report.v1"]
    status: Literal["qualified_without_execution"]
    qualification_id: Sha256
    qualification_nonce: Sha256
    policy_id: StableId
    policy_sha256: Sha256
    resource_profile_id: StableId
    resource_profile_sha256: Sha256
    worker_pool_audience: StableId
    delegated_root_id: StableId
    filesystem: Literal["cgroup2-v2"]
    filesystem_magic_verified: Literal[True]
    delegation_marker_verified: Literal[True]
    delegated_owner_verified: Literal[True]
    delegated_root_empty_verified: Literal[True]
    delegated_root_without_children_verified: Literal[True]
    required_controllers: tuple[Literal["cpu"], Literal["memory"], Literal["pids"]]
    required_controllers_available: Literal[True]
    subtree_control_exact_verified: Literal[True]
    leaf_cgroup_type: Literal["domain"]
    memory_max_bytes: Annotated[int, Field(ge=64 * 1024 * 1024, le=64 * 1024**3)]
    memory_swap_max_bytes: Literal[0]
    pids_max: Annotated[int, Field(ge=1, le=4096)]
    cpu_quota_us: Literal[100000]
    cpu_period_us: Literal[100000]
    cpu_burst_us: Literal[0]
    base_page_size_bytes: Literal[4096]
    memory_oom_group: Literal[True]
    leaf_max_depth: Literal[0]
    leaf_max_descendants: Literal[0]
    controller_readback_verified: Literal[True]
    cgroup_kill_interface_verified: Literal[True]
    cgroup_kill_empty_write_verified: Literal[True]
    populated_zero_before_cleanup: Literal[True]
    populated_zero_after_kill: Literal[True]
    leaf_identity_verified_before_removal: Literal[True]
    leaf_name_removed: Literal[True]
    dying_descendants_reclaimed: Literal[False]
    cleanup_duration_ms: Annotated[int, Field(ge=0, le=5000)]
    process_creation_probed: Literal[False]
    clone3_qualified: Literal[False]
    pidfd_qualified: Literal[False]
    process_created: Literal[False]
    execution_started: Literal[False]
    candidate_bytes_accessed: Literal[False]
    limits_exercised: Literal[False]
    wall_timeout_enforced: Literal[False]
    cpu_time_enforced: Literal[False]
    output_limits_enforced: Literal[False]
    filesystem_isolation_enforced: Literal[False]
    network_isolation_enforced: Literal[False]
    resource_profile_fully_enforced: Literal[False]
    execution_authorized: Literal[False]
    authoritative: Literal[False]

    @field_validator(
        "filesystem_magic_verified",
        "delegation_marker_verified",
        "delegated_owner_verified",
        "delegated_root_empty_verified",
        "delegated_root_without_children_verified",
        "required_controllers_available",
        "subtree_control_exact_verified",
        "memory_oom_group",
        "controller_readback_verified",
        "cgroup_kill_interface_verified",
        "cgroup_kill_empty_write_verified",
        "populated_zero_before_cleanup",
        "populated_zero_after_kill",
        "leaf_identity_verified_before_removal",
        "leaf_name_removed",
        mode="before",
    )
    @classmethod
    def true_claims_must_be_boolean_true(cls, value: object) -> object:
        if value is not True:
            raise ValueError("successful cgroup qualification claims must be boolean true")
        return value

    @field_validator(
        "process_creation_probed",
        "clone3_qualified",
        "pidfd_qualified",
        "process_created",
        "execution_started",
        "candidate_bytes_accessed",
        "limits_exercised",
        "dying_descendants_reclaimed",
        "wall_timeout_enforced",
        "cpu_time_enforced",
        "output_limits_enforced",
        "filesystem_isolation_enforced",
        "network_isolation_enforced",
        "resource_profile_fully_enforced",
        "execution_authorized",
        "authoritative",
        mode="before",
    )
    @classmethod
    def false_claims_must_be_boolean_false(cls, value: object) -> object:
        if value is not False:
            raise ValueError("cgroup qualification cannot claim execution or full isolation")
        return value

    @field_validator("required_controllers", mode="before")
    @classmethod
    def controller_arrays_are_tuples(cls, value: object) -> object:
        if isinstance(value, list):
            return tuple(value)
        return value

    @model_validator(mode="after")
    def identity_and_controller_contract_are_exact(self) -> Self:
        expected = _qualification_id(
            self.model_dump(mode="python", exclude={"qualification_id"})
        )
        if self.qualification_id != expected:
            raise ValueError("cgroup qualification identity is inconsistent")
        if self.required_controllers != REQUIRED_CONTROLLERS:
            raise ValueError("cgroup qualification controller set is inconsistent")
        return self


@dataclass(frozen=True)
class _QualifiedLeaf:
    name: str
    nonce: str
    descriptor: int
    identity: tuple[int, int]
    populated_zero_before_cleanup: bool


@dataclass
class _CleanupProgress:
    leaf_removed: bool = False


def _require_linux_x86_64() -> None:
    """Refuse before model, libc, or descriptor inspection on unsupported hosts."""

    if sys.platform != "linux":
        raise LinuxCgroupUnavailable(
            "unsupported_platform",
            "cgroup-v2 qualification requires Linux",
        )
    if platform.machine() != "x86_64" or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise LinuxCgroupUnavailable(
            "unsupported_architecture",
            "cgroup-v2 qualification requires the pinned x86_64 ABI",
        )
    if (
        ctypes.sizeof(_OpenHow) != 24
        or _OpenHow.flags.offset != 0
        or _OpenHow.mode.offset != 8
        or _OpenHow.resolve.offset != 16
    ):
        raise LinuxCgroupUnavailable(
            "openat2_abi_incompatible",
            "the openat2 ABI layout is incompatible",
        )
    required_flags = ("O_PATH", "O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK")
    if (
        any(not hasattr(os, name) for name in required_flags)
        or getattr(os, "O_PATH", None) != O_PATH_LINUX
        or not hasattr(fcntl, "F_DUPFD_CLOEXEC")
    ):
        raise LinuxCgroupUnavailable(
            "openat2_abi_incompatible",
            "required Linux descriptor flags are unavailable",
        )


def _load_libc() -> Any:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.syscall.restype = ctypes.c_long
    except (AttributeError, OSError) as exc:
        raise LinuxCgroupUnavailable(
            "openat2_unavailable",
            "the Linux syscall interface is unavailable",
        ) from exc
    return libc


def _validate_component_name(name: str, *, allow_dot: bool = False) -> bytes:
    if type(name) is not str or "\x00" in name or "/" in name:
        raise LinuxCgroupRejected(
            "unsafe_delegate",
            "a cgroup component name is invalid",
        )
    if name in {"", ".."} or (name == "." and not allow_dot):
        raise LinuxCgroupRejected(
            "unsafe_delegate",
            "a cgroup component name is invalid",
        )
    try:
        return name.encode("ascii")
    except UnicodeEncodeError as exc:
        raise LinuxCgroupRejected(
            "unsafe_delegate",
            "a cgroup component name is invalid",
        ) from exc


def _openat2(
    libc: Any,
    *,
    parent_fd: int,
    name: str,
    flags: int,
    retries: int,
    allow_dot: bool = False,
) -> int:
    encoded = _validate_component_name(name, allow_dot=allow_dot)
    how = _OpenHow(flags=flags, mode=0, resolve=STRICT_RESOLVE_FLAGS)
    retryable_failures = 0
    while True:
        ctypes.set_errno(0)
        result = libc.syscall(
            ctypes.c_long(OPENAT2_SYSCALL_X86_64),
            ctypes.c_int(parent_fd),
            ctypes.c_char_p(encoded),
            ctypes.byref(how),
            ctypes.c_size_t(ctypes.sizeof(how)),
        )
        if result >= 0:
            descriptor = int(result)
            try:
                os.set_inheritable(descriptor, False)
            except BaseException:
                with suppress(OSError):
                    os.close(descriptor)
                raise
            return descriptor
        error = ctypes.get_errno()
        if error in {errno.EINTR, errno.EAGAIN} and retryable_failures < retries:
            retryable_failures += 1
            continue
        raise OSError(error, os.strerror(error))


def _probe_openat2(libc: Any, root_fd: int, *, retries: int) -> None:
    descriptor = -1
    try:
        descriptor = _openat2(
            libc,
            parent_fd=root_fd,
            name=".",
            flags=O_PATH_LINUX | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            retries=retries,
            allow_dot=True,
        )
    except OSError as exc:
        if exc.errno in {errno.ENOSYS, errno.EPERM}:
            raise LinuxCgroupUnavailable(
                "openat2_unavailable",
                "the exact openat2 contract is unavailable",
            ) from exc
        if exc.errno in {errno.EINVAL, errno.E2BIG}:
            raise LinuxCgroupUnavailable(
                "openat2_abi_incompatible",
                "the exact openat2 contract is unavailable",
            ) from exc
        _raise_open_error(exc)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _raise_open_error(exc: OSError, *, lifecycle: bool = False) -> NoReturn:
    if exc.errno in {errno.ENOSYS, errno.EPERM}:
        raise LinuxCgroupUnavailable(
            "openat2_unavailable",
            "the exact openat2 contract became unavailable",
        ) from exc
    if exc.errno in {errno.EINVAL, errno.E2BIG}:
        raise LinuxCgroupUnavailable(
            "openat2_abi_incompatible",
            "the exact openat2 ABI became unavailable",
        ) from exc
    if exc.errno in {errno.ELOOP, errno.EXDEV, errno.ENOTDIR}:
        raise LinuxCgroupRejected(
            "unsafe_delegate",
            "a cgroup component escaped its descriptor boundary",
        ) from exc
    if exc.errno in {errno.EMFILE, errno.ENFILE, errno.ENOMEM, errno.ENOSPC}:
        raise LinuxCgroupLifecycleError(
            "resource_exhausted",
            "worker resources were exhausted during cgroup qualification",
        ) from exc
    if lifecycle:
        raise LinuxCgroupLifecycleError(
            "io_failure",
            "a cgroup lifecycle operation failed",
        ) from exc
    raise LinuxCgroupRejected(
        "unsafe_delegate",
        "the delegated cgroup root is incomplete or inaccessible",
    ) from exc


def _duplicate_delegate_fd(descriptor: int) -> tuple[int, os.stat_result]:
    if type(descriptor) is not int or descriptor < 0:
        raise LinuxCgroupRejected(
            "unsafe_delegate",
            "the delegated cgroup descriptor is invalid",
        )
    duplicate = -1
    try:
        duplicate = fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, 3)
        flags = fcntl.fcntl(duplicate, fcntl.F_GETFL)
        opened = os.fstat(duplicate)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or flags & O_PATH_LINUX
            or os.get_inheritable(duplicate)
            or opened.st_uid != os.geteuid()
            or opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise OSError(errno.EPERM, "delegated root metadata is unsafe")
        return duplicate, opened
    except (OSError, OverflowError) as exc:
        if duplicate >= 0:
            with suppress(OSError):
                os.close(duplicate)
        raise LinuxCgroupRejected(
            "unsafe_delegate",
            "the delegated cgroup descriptor is unsafe",
        ) from exc


def _reopen_delegate_root(
    libc: Any,
    *,
    pinned_fd: int,
    pinned_stat: os.stat_result,
    retries: int,
) -> tuple[int, os.stat_result]:
    """Create an independent directory description instead of sharing caller offset."""

    descriptor = -1
    try:
        try:
            descriptor = _openat2(
                libc,
                parent_fd=pinned_fd,
                name=".",
                flags=os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                retries=retries,
                allow_dot=True,
            )
        except OSError as exc:
            _raise_open_error(exc)
        flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or flags & O_PATH_LINUX
            or os.get_inheritable(descriptor)
            or (opened.st_dev, opened.st_ino) != (pinned_stat.st_dev, pinned_stat.st_ino)
            or opened.st_uid != os.geteuid()
            or opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise OSError(errno.EPERM, "reopened delegated root metadata is unsafe")
        retained = descriptor
        descriptor = -1
        return retained, opened
    except LinuxCgroupError:
        raise
    except OSError as exc:
        raise LinuxCgroupRejected(
            "unsafe_delegate",
            "the delegated cgroup root could not be independently reopened",
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _require_cgroup2_filesystem(libc: Any, descriptor: int) -> None:
    try:
        buffer = (ctypes.c_ubyte * 256)()
        libc.fstatfs.argtypes = (ctypes.c_int, ctypes.c_void_p)
        libc.fstatfs.restype = ctypes.c_int
        ctypes.set_errno(0)
        if libc.fstatfs(ctypes.c_int(descriptor), ctypes.byref(buffer)) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        filesystem_type = ctypes.c_long.from_buffer(buffer).value
    except (AttributeError, OSError) as exc:
        raise LinuxCgroupRejected(
            "not_cgroup_v2",
            "the delegated descriptor filesystem cannot be verified",
        ) from exc
    if filesystem_type != CGROUP2_SUPER_MAGIC:
        raise LinuxCgroupRejected(
            "not_cgroup_v2",
            "the delegated descriptor is not a cgroup-v2 filesystem",
        )


def _require_systemd_delegation_marker(libc: Any, descriptor: int) -> None:
    try:
        buffer = (ctypes.c_ubyte * 16)()
        libc.fgetxattr.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
        )
        libc.fgetxattr.restype = ctypes.c_ssize_t
        ctypes.set_errno(0)
        size = libc.fgetxattr(
            ctypes.c_int(descriptor),
            ctypes.c_char_p(SYSTEMD_DELEGATION_XATTR),
            ctypes.byref(buffer),
            ctypes.c_size_t(len(buffer)),
        )
        if size < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        value = bytes(buffer[:size])
    except (AttributeError, OSError) as exc:
        raise LinuxCgroupRejected(
            "delegation_unverified",
            "the systemd cgroup delegation marker is unavailable",
        ) from exc
    if value != SYSTEMD_DELEGATION_VALUE:
        raise LinuxCgroupRejected(
            "delegation_unverified",
            "the systemd cgroup delegation marker is invalid",
        )


def _open_component(
    libc: Any,
    *,
    parent_fd: int,
    parent_device: int,
    name: str,
    flags: int,
    directory: bool,
    retries: int,
    lifecycle: bool = False,
) -> int:
    descriptor = -1
    try:
        descriptor = _openat2(
            libc,
            parent_fd=parent_fd,
            name=name,
            flags=flags | os.O_NOFOLLOW | os.O_CLOEXEC,
            retries=retries,
        )
        metadata = os.fstat(descriptor)
        expected_kind = stat.S_ISDIR if directory else stat.S_ISREG
        if (
            not expected_kind(metadata.st_mode)
            or metadata.st_dev != parent_device
            or os.get_inheritable(descriptor)
        ):
            raise OSError(errno.EPERM, "cgroup component metadata is unsafe")
        retained = descriptor
        descriptor = -1
        return retained
    except OSError as exc:
        _raise_open_error(exc, lifecycle=lifecycle)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_fd_bounded(descriptor: int, *, maximum: int = MAX_CONTROL_BYTES) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(1024, maximum + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum:
            raise LinuxCgroupRejected(
                "controller_state_mismatch",
                "a cgroup control value exceeds its fixed bound",
            )


def _decode_control(content: bytes) -> str:
    try:
        value = content.decode("ascii")
    except UnicodeDecodeError as exc:
        raise LinuxCgroupRejected(
            "controller_state_mismatch",
            "a cgroup control value is not canonical ASCII",
        ) from exc
    if "\x00" in value or "\r" in value:
        raise LinuxCgroupRejected(
            "controller_state_mismatch",
            "a cgroup control value is malformed",
        )
    if value.endswith("\n"):
        value = value[:-1]
    if "\n" in value:
        raise LinuxCgroupRejected(
            "controller_state_mismatch",
            "a single-value cgroup control has multiple lines",
        )
    return value


def _read_control(
    libc: Any,
    *,
    parent_fd: int,
    parent_device: int,
    name: str,
    retries: int,
    lifecycle: bool = False,
) -> bytes:
    descriptor = -1
    try:
        descriptor = _open_component(
            libc,
            parent_fd=parent_fd,
            parent_device=parent_device,
            name=name,
            flags=os.O_RDONLY | os.O_NONBLOCK,
            directory=False,
            retries=retries,
            lifecycle=lifecycle,
        )
        return _read_fd_bounded(descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _write_control(
    libc: Any,
    *,
    parent_fd: int,
    parent_device: int,
    name: str,
    value: str,
    retries: int,
) -> None:
    if not value or len(value) > 128 or "\x00" in value or "\n" in value or "\r" in value:
        raise LinuxCgroupLifecycleError(
            "configuration_rejected",
            "an internal cgroup control value is invalid",
        )
    try:
        encoded = value.encode("ascii") + b"\n"
    except UnicodeEncodeError as exc:
        raise LinuxCgroupLifecycleError(
            "configuration_rejected",
            "an internal cgroup control value is invalid",
        ) from exc
    descriptor = -1
    try:
        descriptor = _open_component(
            libc,
            parent_fd=parent_fd,
            parent_device=parent_device,
            name=name,
            flags=os.O_WRONLY,
            directory=False,
            retries=retries,
            lifecycle=True,
        )
        written = os.write(descriptor, encoded)
        if written != len(encoded):
            raise LinuxCgroupLifecycleError(
                "configuration_rejected",
                "a cgroup control write was incomplete",
            )
    except LinuxCgroupError:
        raise
    except OSError as exc:
        if exc.errno in {errno.EACCES, errno.EPERM, errno.EROFS, errno.EBUSY, errno.EINVAL}:
            raise LinuxCgroupLifecycleError(
                "configuration_rejected",
                "the kernel rejected a cgroup control value",
            ) from exc
        if exc.errno in {errno.EMFILE, errno.ENFILE, errno.ENOMEM, errno.ENOSPC}:
            raise LinuxCgroupLifecycleError(
                "resource_exhausted",
                "worker resources were exhausted during cgroup configuration",
            ) from exc
        raise LinuxCgroupLifecycleError(
            "io_failure",
            "a cgroup control write failed",
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _parse_token_set(content: bytes) -> tuple[str, ...]:
    value = _decode_control(content)
    if not value:
        return ()
    tokens = value.split(" ")
    if (
        any(not token or len(token) > 32 for token in tokens)
        or any(
            not token.isascii()
            or any(character != "_" and not ("a" <= character <= "z") for character in token)
            for token in tokens
        )
        or len(tokens) != len(set(tokens))
    ):
        raise LinuxCgroupRejected(
            "controller_state_mismatch",
            "a cgroup controller set is malformed",
        )
    return tuple(sorted(tokens))


def _parse_events(content: bytes) -> dict[str, int]:
    try:
        value = content.decode("ascii")
    except UnicodeDecodeError as exc:
        raise LinuxCgroupRejected(
            "controller_state_mismatch",
            "cgroup events are not canonical ASCII",
        ) from exc
    if not value.endswith("\n") or "\x00" in value or "\r" in value:
        raise LinuxCgroupRejected(
            "controller_state_mismatch",
            "cgroup events are malformed",
        )
    result: dict[str, int] = {}
    lines = value[:-1].split("\n")
    if not lines or len(lines) > 64:
        raise LinuxCgroupRejected(
            "controller_state_mismatch",
            "cgroup events have an invalid field count",
        )
    for line in lines:
        parts = line.split(" ")
        if len(parts) != 2:
            raise LinuxCgroupRejected(
                "controller_state_mismatch",
                "cgroup events have an invalid field",
            )
        key, encoded_value = parts
        if (
            not key
            or len(key) > 64
            or not key.isascii()
            or any(
                character not in "._" and not ("a" <= character <= "z")
                for character in key
            )
            or key in result
            or not encoded_value.isascii()
            or not encoded_value.isdecimal()
            or (len(encoded_value) > 1 and encoded_value.startswith("0"))
        ):
            raise LinuxCgroupRejected(
                "controller_state_mismatch",
                "cgroup events have a noncanonical field",
            )
        parsed = int(encoded_value)
        if parsed > 2**63 - 1:
            raise LinuxCgroupRejected(
                "controller_state_mismatch",
                "cgroup events exceed the fixed integer bound",
            )
        result[key] = parsed
    return result


def _read_events(
    libc: Any,
    *,
    cgroup_fd: int,
    cgroup_device: int,
    retries: int,
    lifecycle: bool = False,
) -> dict[str, int]:
    return _parse_events(
        _read_control(
            libc,
            parent_fd=cgroup_fd,
            parent_device=cgroup_device,
            name="cgroup.events",
            retries=retries,
            lifecycle=lifecycle,
        )
    )


def _list_child_cgroups(descriptor: int) -> tuple[tuple[str, tuple[int, int]], ...]:
    children: list[tuple[str, tuple[int, int]]] = []
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        with os.scandir(descriptor) as entries:
            for index, entry in enumerate(entries, start=1):
                if index > MAX_ROOT_ENTRIES:
                    raise LinuxCgroupRejected(
                        "delegate_busy",
                        "the delegated cgroup root exceeds its entry bound",
                    )
                if entry.is_symlink():
                    raise LinuxCgroupRejected(
                        "unsafe_delegate",
                        "the delegated cgroup root contains an unsafe entry",
                    )
                if entry.is_dir(follow_symlinks=False):
                    metadata = entry.stat(follow_symlinks=False)
                    children.append((entry.name, (metadata.st_dev, metadata.st_ino)))
    except LinuxCgroupError:
        raise
    except OSError as exc:
        raise LinuxCgroupRejected(
            "unsafe_delegate",
            "the delegated cgroup root cannot be enumerated",
        ) from exc
    finally:
        with suppress(OSError):
            os.lseek(descriptor, 0, os.SEEK_SET)
    return tuple(children)


def _require_empty_domain_root(
    libc: Any,
    *,
    root_fd: int,
    root_device: int,
    retries: int,
) -> None:
    try:
        cgroup_type = _decode_control(
            _read_control(
                libc,
                parent_fd=root_fd,
                parent_device=root_device,
                name="cgroup.type",
                retries=retries,
            )
        )
        controllers = _parse_token_set(
            _read_control(
                libc,
                parent_fd=root_fd,
                parent_device=root_device,
                name="cgroup.controllers",
                retries=retries,
            )
        )
        enabled = _parse_token_set(
            _read_control(
                libc,
                parent_fd=root_fd,
                parent_device=root_device,
                name="cgroup.subtree_control",
                retries=retries,
            )
        )
        events = _read_events(
            libc,
            cgroup_fd=root_fd,
            cgroup_device=root_device,
            retries=retries,
        )
        processes = _decode_control(
            _read_control(
                libc,
                parent_fd=root_fd,
                parent_device=root_device,
                name="cgroup.procs",
                retries=retries,
            )
        )
        threads = _decode_control(
            _read_control(
                libc,
                parent_fd=root_fd,
                parent_device=root_device,
                name="cgroup.threads",
                retries=retries,
            )
        )
    except LinuxCgroupUnavailable:
        raise
    except LinuxCgroupError as exc:
        raise LinuxCgroupRejected(
            "controllers_unavailable",
            "required delegated cgroup controls are unavailable",
        ) from exc

    if cgroup_type != "domain":
        raise LinuxCgroupRejected(
            "controller_state_mismatch",
            "the delegated cgroup root is not an unthreaded domain",
        )
    if not set(REQUIRED_CONTROLLERS).issubset(controllers):
        raise LinuxCgroupRejected(
            "controllers_unavailable",
            "required cgroup controllers are not delegated",
        )
    if enabled != REQUIRED_CONTROLLERS:
        raise LinuxCgroupRejected(
            "controller_state_mismatch",
            "the delegated subtree controller set is not exact",
        )
    if events.get("populated") != 0 or events.get("frozen", 0) != 0:
        raise LinuxCgroupRejected(
            "delegate_busy",
            "the delegated cgroup root is populated or frozen",
        )
    if processes or threads or _list_child_cgroups(root_fd):
        raise LinuxCgroupRejected(
            "delegate_busy",
            "the delegated cgroup root is not empty and exclusive",
        )


def _new_qualification_nonce() -> str:
    return secrets.token_hex(32)


def _create_leaf(
    libc: Any,
    *,
    root_fd: int,
    root_device: int,
    retries: int,
) -> _QualifiedLeaf:
    nonce = _new_qualification_nonce()
    if len(nonce) != 64 or nonce == "0" * 64:
        raise LinuxCgroupLifecycleError(
            "resource_exhausted",
            "a secure cgroup qualification nonce is unavailable",
        )
    try:
        bytes.fromhex(nonce)
    except ValueError as exc:
        raise LinuxCgroupLifecycleError(
            "resource_exhausted",
            "a secure cgroup qualification nonce is unavailable",
        ) from exc
    if any(character not in "0123456789abcdef" for character in nonce):
        raise LinuxCgroupLifecycleError(
            "resource_exhausted",
            "a secure cgroup qualification nonce is unavailable",
        )
    name = LEAF_PREFIX + nonce
    try:
        os.mkdir(name, mode=0o700, dir_fd=root_fd)
    except FileExistsError as exc:
        raise LinuxCgroupLifecycleError(
            "creation_conflict",
            "the random cgroup qualification leaf already exists",
        ) from exc
    except OSError as exc:
        if exc.errno in {errno.EACCES, errno.EPERM, errno.EROFS}:
            raise LinuxCgroupRejected(
                "delegation_unverified",
                "the delegated cgroup root does not permit child creation",
            ) from exc
        if exc.errno in {errno.ENOSPC, errno.ENOMEM, errno.EMFILE, errno.ENFILE}:
            raise LinuxCgroupLifecycleError(
                "resource_exhausted",
                "worker resources were exhausted while creating a cgroup leaf",
            ) from exc
        raise LinuxCgroupLifecycleError(
            "io_failure",
            "the cgroup qualification leaf could not be created",
        ) from exc

    descriptor = -1
    try:
        descriptor = _open_component(
            libc,
            parent_fd=root_fd,
            parent_device=root_device,
            name=name,
            flags=os.O_RDONLY | os.O_DIRECTORY,
            directory=True,
            retries=retries,
            lifecycle=True,
        )
        metadata = os.fstat(descriptor)
        if (
            metadata.st_uid != os.geteuid()
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise LinuxCgroupLifecycleError(
                "cgroup_changed",
                "the cgroup qualification leaf metadata is unsafe",
            )
        leaf = _QualifiedLeaf(
            name=name,
            nonce=nonce,
            descriptor=descriptor,
            identity=(metadata.st_dev, metadata.st_ino),
            populated_zero_before_cleanup=False,
        )
        descriptor = -1
        return leaf
    except BaseException:
        close_error: OSError | None = None
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as exc:
                close_error = exc
        try:
            os.rmdir(name, dir_fd=root_fd)
        except OSError as cleanup_exc:
            raise LinuxCgroupLifecycleError(
                "cleanup_incomplete",
                "a failed cgroup leaf creation could not be rolled back",
            ) from cleanup_exc
        if close_error is not None:
            raise LinuxCgroupLifecycleError(
                "cleanup_incomplete",
                "a failed cgroup leaf descriptor could not be closed",
            ) from close_error
        raise


def _require_exclusive_leaf(
    libc: Any,
    *,
    root_fd: int,
    root_device: int,
    leaf: _QualifiedLeaf,
    retries: int,
) -> None:
    try:
        children = _list_child_cgroups(root_fd)
        cgroup_type = _decode_control(
            _read_control(
                libc,
                parent_fd=root_fd,
                parent_device=root_device,
                name="cgroup.type",
                retries=retries,
                lifecycle=True,
            )
        )
        controllers = _parse_token_set(
            _read_control(
                libc,
                parent_fd=root_fd,
                parent_device=root_device,
                name="cgroup.controllers",
                retries=retries,
                lifecycle=True,
            )
        )
        events = _read_events(
            libc,
            cgroup_fd=root_fd,
            cgroup_device=root_device,
            retries=retries,
            lifecycle=True,
        )
        processes = _decode_control(
            _read_control(
                libc,
                parent_fd=root_fd,
                parent_device=root_device,
                name="cgroup.procs",
                retries=retries,
                lifecycle=True,
            )
        )
        threads = _decode_control(
            _read_control(
                libc,
                parent_fd=root_fd,
                parent_device=root_device,
                name="cgroup.threads",
                retries=retries,
                lifecycle=True,
            )
        )
        enabled = _parse_token_set(
            _read_control(
                libc,
                parent_fd=root_fd,
                parent_device=root_device,
                name="cgroup.subtree_control",
                retries=retries,
                lifecycle=True,
            )
        )
    except LinuxCgroupUnavailable:
        raise
    except LinuxCgroupError as exc:
        raise LinuxCgroupLifecycleError(
            "cgroup_changed",
            "the delegated cgroup root changed during qualification",
        ) from exc
    if (
        children != ((leaf.name, leaf.identity),)
        or cgroup_type != "domain"
        or not set(REQUIRED_CONTROLLERS).issubset(controllers)
        or events.get("populated") != 0
        or events.get("frozen", 0) != 0
        or processes
        or threads
        or enabled != REQUIRED_CONTROLLERS
    ):
        raise LinuxCgroupLifecycleError(
            "cgroup_changed",
            "the delegated cgroup root changed during qualification",
        )


def _require_leaf_empty(
    libc: Any,
    *,
    leaf_fd: int,
    leaf_device: int,
    retries: int,
    lifecycle: bool = True,
) -> None:
    try:
        cgroup_type = _decode_control(
            _read_control(
                libc,
                parent_fd=leaf_fd,
                parent_device=leaf_device,
                name="cgroup.type",
                retries=retries,
                lifecycle=lifecycle,
            )
        )
        events = _read_events(
            libc,
            cgroup_fd=leaf_fd,
            cgroup_device=leaf_device,
            retries=retries,
            lifecycle=lifecycle,
        )
        processes = _decode_control(
            _read_control(
                libc,
                parent_fd=leaf_fd,
                parent_device=leaf_device,
                name="cgroup.procs",
                retries=retries,
                lifecycle=lifecycle,
            )
        )
        threads = _decode_control(
            _read_control(
                libc,
                parent_fd=leaf_fd,
                parent_device=leaf_device,
                name="cgroup.threads",
                retries=retries,
                lifecycle=lifecycle,
            )
        )
        subtree_control = _parse_token_set(
            _read_control(
                libc,
                parent_fd=leaf_fd,
                parent_device=leaf_device,
                name="cgroup.subtree_control",
                retries=retries,
                lifecycle=lifecycle,
            )
        )
        children = _list_child_cgroups(leaf_fd)
    except LinuxCgroupUnavailable:
        raise
    except LinuxCgroupError as exc:
        raise LinuxCgroupLifecycleError(
            "cgroup_changed",
            "the cgroup qualification leaf changed unexpectedly",
        ) from exc
    if (
        cgroup_type != "domain"
        or events.get("populated") != 0
        or events.get("frozen", 0) != 0
        or processes
        or threads
        or subtree_control
        or children
    ):
        raise LinuxCgroupLifecycleError(
            "cgroup_changed",
            "the cgroup qualification leaf is not an empty domain",
        )


def _expected_leaf_controls(
    profile: ExecutionResourceProfile,
) -> tuple[tuple[str, str], ...]:
    """Return the exact version-1 leaf controls in their fixed audit order."""

    return (
        ("cgroup.max.depth", "0"),
        ("cgroup.max.descendants", "0"),
        ("pids.max", str(profile.pids_max)),
        ("memory.swap.max", "0"),
        ("memory.max", str(profile.memory_bytes)),
        ("memory.oom.group", "1"),
        ("cpu.max", CPU_MAX_VALUE),
        ("cpu.max.burst", "0"),
    )


def _require_leaf_control_readback(
    libc: Any,
    *,
    leaf: _QualifiedLeaf,
    profile: ExecutionResourceProfile,
    retries: int,
) -> None:
    """Read, but never repair, every configured leaf control."""

    for name, expected in _expected_leaf_controls(profile):
        observed = _decode_control(
            _read_control(
                libc,
                parent_fd=leaf.descriptor,
                parent_device=leaf.identity[0],
                name=name,
                retries=retries,
                lifecycle=True,
            )
        )
        if observed != expected:
            raise LinuxCgroupLifecycleError(
                "readback_mismatch",
                "a configured cgroup control did not read back exactly",
            )


def _probe_write_control(
    libc: Any,
    *,
    parent_fd: int,
    parent_device: int,
    name: str,
    retries: int,
) -> None:
    descriptor = -1
    try:
        descriptor = _open_component(
            libc,
            parent_fd=parent_fd,
            parent_device=parent_device,
            name=name,
            flags=os.O_WRONLY,
            directory=False,
            retries=retries,
            lifecycle=True,
        )
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _configure_leaf(
    libc: Any,
    *,
    root_fd: int,
    root_device: int,
    leaf: _QualifiedLeaf,
    profile: ExecutionResourceProfile,
    retries: int,
) -> _QualifiedLeaf:
    _require_exclusive_leaf(
        libc,
        root_fd=root_fd,
        root_device=root_device,
        leaf=leaf,
        retries=retries,
    )
    _require_leaf_empty(
        libc,
        leaf_fd=leaf.descriptor,
        leaf_device=leaf.identity[0],
        retries=retries,
    )
    _probe_write_control(
        libc,
        parent_fd=leaf.descriptor,
        parent_device=leaf.identity[0],
        name="cgroup.kill",
        retries=retries,
    )

    controls = _expected_leaf_controls(profile)
    for name, value in controls:
        _write_control(
            libc,
            parent_fd=leaf.descriptor,
            parent_device=leaf.identity[0],
            name=name,
            value=value,
            retries=retries,
        )
    _require_leaf_control_readback(
        libc,
        leaf=leaf,
        profile=profile,
        retries=retries,
    )

    _require_exclusive_leaf(
        libc,
        root_fd=root_fd,
        root_device=root_device,
        leaf=leaf,
        retries=retries,
    )
    _require_leaf_empty(
        libc,
        leaf_fd=leaf.descriptor,
        leaf_device=leaf.identity[0],
        retries=retries,
    )
    return _QualifiedLeaf(
        name=leaf.name,
        nonce=leaf.nonce,
        descriptor=leaf.descriptor,
        identity=leaf.identity,
        populated_zero_before_cleanup=True,
    )


def _open_events_fd(
    libc: Any,
    *,
    leaf: _QualifiedLeaf,
    retries: int,
) -> int:
    return _open_component(
        libc,
        parent_fd=leaf.descriptor,
        parent_device=leaf.identity[0],
        name="cgroup.events",
        flags=os.O_RDONLY | os.O_NONBLOCK,
        directory=False,
        retries=retries,
        lifecycle=True,
    )


def _read_events_fd(descriptor: int) -> dict[str, int]:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        return _parse_events(_read_fd_bounded(descriptor))
    except LinuxCgroupError as exc:
        raise LinuxCgroupLifecycleError(
            "cgroup_changed",
            "cgroup event state is invalid",
        ) from exc
    except OSError as exc:
        raise LinuxCgroupLifecycleError(
            "io_failure",
            "cgroup event state could not be reread",
        ) from exc


def _events_populated(events: dict[str, int]) -> int:
    populated = events.get("populated")
    if populated not in {0, 1}:
        raise LinuxCgroupLifecycleError(
            "cgroup_changed",
            "cgroup population state is invalid",
        )
    return populated


def _wait_populated_zero(
    events_fd: int,
    *,
    deadline_ns: int,
) -> None:
    poller = select.poll()
    poller.register(events_fd, select.POLLPRI | select.POLLERR)
    while True:
        if _events_populated(_read_events_fd(events_fd)) == 0:
            return
        now = time.monotonic_ns()
        if now >= deadline_ns:
            raise LinuxCgroupLifecycleError(
                "cleanup_timeout",
                "the cgroup qualification leaf did not become empty",
            )
        remaining_ms = max(1, (deadline_ns - now + 999_999) // 1_000_000)
        try:
            poller.poll(remaining_ms)
        except OSError as exc:
            if exc.errno == errno.EINTR:
                continue
            raise LinuxCgroupLifecycleError(
                "io_failure",
                "cgroup population notification failed",
            ) from exc


def _require_leaf_identity(
    libc: Any,
    *,
    root_fd: int,
    root_device: int,
    leaf: _QualifiedLeaf,
    retries: int,
) -> None:
    reopened = -1
    try:
        reopened = _open_component(
            libc,
            parent_fd=root_fd,
            parent_device=root_device,
            name=leaf.name,
            flags=os.O_RDONLY | os.O_DIRECTORY,
            directory=True,
            retries=retries,
            lifecycle=True,
        )
        metadata = os.fstat(reopened)
        retained = os.fstat(leaf.descriptor)
        if (
            (metadata.st_dev, metadata.st_ino) != leaf.identity
            or (retained.st_dev, retained.st_ino) != leaf.identity
        ):
            raise LinuxCgroupLifecycleError(
                "cgroup_changed",
                "the cgroup qualification leaf identity changed",
            )
    finally:
        if reopened >= 0:
            os.close(reopened)


def _remove_empty_leaf(
    libc: Any,
    *,
    root_fd: int,
    root_device: int,
    leaf: _QualifiedLeaf,
    events_fd: int,
    retries: int,
    deadline_ns: int,
) -> None:
    while True:
        _wait_populated_zero(events_fd, deadline_ns=deadline_ns)
        _require_leaf_identity(
            libc,
            root_fd=root_fd,
            root_device=root_device,
            leaf=leaf,
            retries=retries,
        )
        if _list_child_cgroups(root_fd) != ((leaf.name, leaf.identity),):
            raise LinuxCgroupLifecycleError(
                "cgroup_changed",
                "the delegated cgroup root changed before leaf removal",
            )
        try:
            os.rmdir(leaf.name, dir_fd=root_fd)
            break
        except OSError as exc:
            if exc.errno in {errno.EBUSY, errno.ENOTEMPTY}:
                now = time.monotonic_ns()
                if now >= deadline_ns:
                    raise LinuxCgroupLifecycleError(
                        "cleanup_timeout",
                        "the cgroup qualification leaf could not be removed",
                    ) from exc
                _write_control(
                    libc,
                    parent_fd=leaf.descriptor,
                    parent_device=leaf.identity[0],
                    name="cgroup.kill",
                    value="1",
                    retries=retries,
                )
                retry_poller = select.poll()
                retry_poller.register(events_fd, select.POLLPRI | select.POLLERR)
                remaining_ms = max(1, (deadline_ns - now + 999_999) // 1_000_000)
                retry_poller.poll(min(10, remaining_ms))
                continue
            if exc.errno == errno.ENOENT:
                raise LinuxCgroupLifecycleError(
                    "cgroup_changed",
                    "the cgroup qualification leaf disappeared unexpectedly",
                ) from exc
            raise LinuxCgroupLifecycleError(
                "io_failure",
                "the cgroup qualification leaf could not be removed",
            ) from exc
    try:
        os.stat(leaf.name, dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise LinuxCgroupLifecycleError(
            "io_failure",
            "leaf removal could not be verified",
        ) from exc
    raise LinuxCgroupLifecycleError(
        "cgroup_changed",
        "the removed cgroup leaf name was reused",
    )


def _cleanup_leaf_once(
    libc: Any,
    *,
    root_fd: int,
    root_device: int,
    leaf: _QualifiedLeaf,
    retries: int,
    timeout_ms: int,
    require_prequalified_empty: bool,
    progress: _CleanupProgress,
) -> int:
    started_ns = time.monotonic_ns()
    deadline_ns = started_ns + timeout_ms * 1_000_000
    events_fd = -1
    events_close_error: BaseException | None = None
    kill_error: LinuxCgroupError | None = None
    populated_before = False
    try:
        events_fd = _open_events_fd(libc, leaf=leaf, retries=retries)
        populated_before = _events_populated(_read_events_fd(events_fd)) != 0
        try:
            _write_control(
                libc,
                parent_fd=leaf.descriptor,
                parent_device=leaf.identity[0],
                name="cgroup.kill",
                value="1",
                retries=retries,
            )
        except LinuxCgroupError as exc:
            kill_error = exc
        _wait_populated_zero(events_fd, deadline_ns=deadline_ns)
        _remove_empty_leaf(
            libc,
            root_fd=root_fd,
            root_device=root_device,
            leaf=leaf,
            events_fd=events_fd,
            retries=retries,
            deadline_ns=deadline_ns,
        )
        progress.leaf_removed = True
    finally:
        if events_fd >= 0:
            closing_events_fd, events_fd = events_fd, -1
            try:
                os.close(closing_events_fd)
            except BaseException as exc:
                events_close_error = exc

    try:
        _require_empty_domain_root(
            libc,
            root_fd=root_fd,
            root_device=root_device,
            retries=retries,
        )
    except LinuxCgroupError as exc:
        raise LinuxCgroupLifecycleError(
            "cgroup_changed",
            "the delegated root did not return to its empty state",
        ) from exc
    elapsed_ns = time.monotonic_ns() - started_ns
    if elapsed_ns < 0:
        raise LinuxCgroupLifecycleError(
            "io_failure",
            "the monotonic cleanup clock moved backwards",
        )
    elapsed_ms = (elapsed_ns + 999_999) // 1_000_000
    if elapsed_ms > timeout_ms:
        raise LinuxCgroupLifecycleError(
            "cleanup_timeout",
            "cgroup cleanup exceeded its fixed deadline",
        )
    if kill_error is not None:
        raise LinuxCgroupLifecycleError(
            "io_failure",
            "the cgroup.kill write was not accepted",
        ) from kill_error
    if events_close_error is not None:
        raise LinuxCgroupLifecycleError(
            "io_failure",
            "the cgroup events descriptor could not be closed",
        ) from events_close_error
    if require_prequalified_empty and (
        populated_before or not leaf.populated_zero_before_cleanup
    ):
        raise LinuxCgroupLifecycleError(
            "cgroup_changed",
            "the qualification leaf was populated before cleanup",
        )
    return elapsed_ms


def _fallback_remove_empty_leaf(
    *,
    root_fd: int,
    leaf: _QualifiedLeaf,
) -> None:
    """Remove only the exact empty probe leaf when event observation is unavailable."""

    try:
        named = os.stat(leaf.name, dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise LinuxCgroupLifecycleError(
            "cleanup_incomplete",
            "cgroup qualification cleanup could not inspect the residual leaf",
        ) from exc
    try:
        retained = os.fstat(leaf.descriptor)
    except OSError as exc:
        raise LinuxCgroupLifecycleError(
            "cleanup_incomplete",
            "cgroup qualification cleanup lost the retained leaf identity",
        ) from exc
    if (
        not stat.S_ISDIR(named.st_mode)
        or (named.st_dev, named.st_ino) != leaf.identity
        or (retained.st_dev, retained.st_ino) != leaf.identity
    ):
        raise LinuxCgroupLifecycleError(
            "cleanup_incomplete",
            "cgroup qualification cleanup refused an identity-mismatched leaf",
        )
    try:
        os.rmdir(leaf.name, dir_fd=root_fd)
    except OSError as exc:
        raise LinuxCgroupLifecycleError(
            "cleanup_incomplete",
            "cgroup qualification cleanup left a residual leaf",
        ) from exc
    try:
        os.stat(leaf.name, dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise LinuxCgroupLifecycleError(
            "cleanup_incomplete",
            "cgroup qualification fallback removal could not be verified",
        ) from exc
    raise LinuxCgroupLifecycleError(
        "cleanup_incomplete",
        "cgroup qualification fallback leaf name was reused",
    )


def _cleanup_leaf(
    libc: Any,
    *,
    root_fd: int,
    root_device: int,
    leaf: _QualifiedLeaf,
    retries: int,
    timeout_ms: int,
    require_prequalified_empty: bool,
) -> int:
    progress = _CleanupProgress()
    try:
        return _cleanup_leaf_once(
            libc,
            root_fd=root_fd,
            root_device=root_device,
            leaf=leaf,
            retries=retries,
            timeout_ms=timeout_ms,
            require_prequalified_empty=require_prequalified_empty,
            progress=progress,
        )
    except BaseException:
        if progress.leaf_removed:
            raise
        try:
            _fallback_remove_empty_leaf(root_fd=root_fd, leaf=leaf)
        except BaseException as cleanup_exc:
            raise LinuxCgroupLifecycleError(
                "cleanup_incomplete",
                "cgroup qualification cleanup could not remove the exact leaf",
            ) from cleanup_exc
        raise


def _require_root_unchanged(
    libc: Any,
    *,
    root_fd: int,
    initial: os.stat_result,
) -> None:
    try:
        current = os.fstat(root_fd)
    except OSError as exc:
        raise LinuxCgroupLifecycleError(
            "cgroup_changed",
            "the delegated cgroup root identity became unavailable",
        ) from exc
    if (
        (current.st_dev, current.st_ino) != (initial.st_dev, initial.st_ino)
        or current.st_uid != os.geteuid()
        or current.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise LinuxCgroupLifecycleError(
            "cgroup_changed",
            "the delegated cgroup root metadata changed",
        )
    _require_cgroup2_filesystem(libc, root_fd)
    _require_systemd_delegation_marker(libc, root_fd)


def _freeze_qualification_inputs(
    policy: LinuxCgroupV2QualificationPolicy,
    resource_profile: ExecutionResourceProfile,
) -> tuple[LinuxCgroupV2QualificationPolicy, ExecutionResourceProfile]:
    try:
        frozen_policy = LinuxCgroupV2QualificationPolicy.model_validate(
            policy.model_dump(mode="python"),
            strict=True,
        )
        frozen_profile = ExecutionResourceProfile.model_validate(
            resource_profile.model_dump(mode="python"),
            strict=True,
        )
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise LinuxCgroupRejected(
            "invalid_inputs",
            "cgroup qualification policy or resource profile is invalid",
        ) from exc

    try:
        page_size = os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError) as exc:
        raise LinuxCgroupUnavailable(
            "unsupported_page_size",
            "the host base page size cannot be established",
        ) from exc
    if type(page_size) is not int or page_size != frozen_policy.base_page_size_bytes:
        raise LinuxCgroupUnavailable(
            "unsupported_page_size",
            "cgroup qualification requires a 4096-byte base page size",
        )
    if frozen_profile.memory_bytes % page_size != 0:
        raise LinuxCgroupRejected(
            "invalid_inputs",
            "the resource-profile memory limit is not base-page aligned",
        )
    return frozen_policy, frozen_profile


class LinuxCgroupV2RetainedLeaf:
    """A non-authorizing owner of one configured cgroup leaf and its cleanup.

    ``duplicate_leaf_fd()`` returns a caller-owned CLOEXEC descriptor after
    immediately revalidating the retained root, leaf name, and leaf identity.  The
    caller must close every duplicate before ``cleanup()`` or
    ``cleanup_with_timeout_ms()``.  An unclosed duplicate can retain a removed,
    dying kernel cgroup object and is never evidence that the object was reclaimed.
    """

    __slots__ = (
        "_cleanup_duration_ms",
        "_finished",
        "_leaf",
        "_libc",
        "_lock",
        "_policy",
        "_policy_sha256",
        "_resource_profile",
        "_resource_profile_sha256",
        "_root_fd",
        "_root_stat",
        "_terminal_error",
    )

    _cleanup_duration_ms: int | None
    _finished: bool
    _leaf: _QualifiedLeaf
    _libc: Any
    _lock: threading.Lock
    _policy: LinuxCgroupV2QualificationPolicy
    _policy_sha256: str
    _resource_profile: ExecutionResourceProfile
    _resource_profile_sha256: str
    _root_fd: int
    _root_stat: os.stat_result
    _terminal_error: BaseException | None

    def __init__(self) -> None:
        raise TypeError("retained cgroup leaves must be created by the qualification API")

    @classmethod
    def _create(
        cls,
        *,
        libc: Any,
        policy: LinuxCgroupV2QualificationPolicy,
        resource_profile: ExecutionResourceProfile,
        policy_sha256: str,
        resource_profile_sha256: str,
        root_fd: int,
        root_stat: os.stat_result,
        leaf: _QualifiedLeaf,
    ) -> Self:
        retained = cls.__new__(cls)
        retained._libc = libc
        retained._policy = policy
        retained._resource_profile = resource_profile
        retained._policy_sha256 = policy_sha256
        retained._resource_profile_sha256 = resource_profile_sha256
        retained._root_fd = root_fd
        retained._root_stat = root_stat
        retained._leaf = leaf
        retained._lock = threading.Lock()
        retained._finished = False
        retained._cleanup_duration_ms = None
        retained._terminal_error = None
        return retained

    @property
    def qualification_nonce(self) -> str:
        """Return the random leaf binding without exposing its filesystem name."""

        return self._leaf.nonce

    @property
    def root_identity(self) -> tuple[int, int]:
        """Return the retained delegated-root device and inode identity."""

        return self._root_stat.st_dev, self._root_stat.st_ino

    @property
    def leaf_identity(self) -> tuple[int, int]:
        """Return the configured leaf's device and inode identity."""

        return self._leaf.identity

    @property
    def active(self) -> bool:
        """Whether the handle still owns live descriptors and cleanup responsibility."""

        with self._lock:
            return not self._finished

    @property
    def cleanup_completed(self) -> bool:
        """Whether name cleanup and the final root audit, not object reclaim, succeeded."""

        with self._lock:
            return self._finished and self._terminal_error is None

    @property
    def cleanup_error(self) -> BaseException | None:
        """Return the terminal cleanup failure, if cleanup was attempted and failed."""

        with self._lock:
            return self._terminal_error

    def _require_active_identity(self) -> None:
        if self._finished:
            raise LinuxCgroupLifecycleError(
                "cgroup_changed",
                "the retained cgroup leaf is no longer active",
            )
        try:
            root_metadata = os.fstat(self._root_fd)
            leaf_metadata = os.fstat(self._leaf.descriptor)
            root_inheritable = os.get_inheritable(self._root_fd)
            leaf_inheritable = os.get_inheritable(self._leaf.descriptor)
        except OSError as exc:
            raise LinuxCgroupLifecycleError(
                "cgroup_changed",
                "a retained cgroup descriptor identity became unavailable",
            ) from exc
        if (
            (root_metadata.st_dev, root_metadata.st_ino) != self.root_identity
            or not stat.S_ISDIR(root_metadata.st_mode)
            or root_metadata.st_uid != os.geteuid()
            or root_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or (leaf_metadata.st_dev, leaf_metadata.st_ino) != self.leaf_identity
            or not stat.S_ISDIR(leaf_metadata.st_mode)
            or leaf_metadata.st_uid != os.geteuid()
            or leaf_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or root_inheritable
            or leaf_inheritable
        ):
            raise LinuxCgroupLifecycleError(
                "cgroup_changed",
                "a retained cgroup descriptor identity changed",
            )

    def _require_named_leaf_binding(self) -> None:
        try:
            _require_root_unchanged(
                self._libc,
                root_fd=self._root_fd,
                initial=self._root_stat,
            )
            children = _list_child_cgroups(self._root_fd)
        except LinuxCgroupUnavailable:
            raise
        except LinuxCgroupError as exc:
            raise LinuxCgroupLifecycleError(
                "cgroup_changed",
                "the retained delegated root changed before leaf handoff",
            ) from exc
        if children != ((self._leaf.name, self._leaf.identity),):
            raise LinuxCgroupLifecycleError(
                "cgroup_changed",
                "the retained cgroup leaf name or identity changed before handoff",
            )
        try:
            _require_leaf_identity(
                self._libc,
                root_fd=self._root_fd,
                root_device=self._root_stat.st_dev,
                leaf=self._leaf,
                retries=self._policy.openat2_eagain_retries,
            )
        except LinuxCgroupError:
            raise
        except OSError as exc:
            raise LinuxCgroupLifecycleError(
                "io_failure",
                "the retained cgroup leaf identity could not be revalidated",
            ) from exc

    def _require_safe_handoff_state(self) -> None:
        """Revalidate the complete read-only handoff contract under the handle lock."""

        self._require_named_leaf_binding()
        try:
            _require_exclusive_leaf(
                self._libc,
                root_fd=self._root_fd,
                root_device=self._root_stat.st_dev,
                leaf=self._leaf,
                retries=self._policy.openat2_eagain_retries,
            )
            _require_leaf_empty(
                self._libc,
                leaf_fd=self._leaf.descriptor,
                leaf_device=self._leaf.identity[0],
                retries=self._policy.openat2_eagain_retries,
            )
            _require_leaf_control_readback(
                self._libc,
                leaf=self._leaf,
                profile=self._resource_profile,
                retries=self._policy.openat2_eagain_retries,
            )
        except LinuxCgroupUnavailable:
            raise
        except LinuxCgroupError as exc:
            raise LinuxCgroupLifecycleError(
                "cgroup_changed",
                "the retained cgroup state changed before leaf handoff",
            ) from exc

    def duplicate_leaf_fd(self) -> int:
        """Revalidate state and return a caller-owned CLOEXEC leaf descriptor."""

        with self._lock:
            self._require_active_identity()
            self._require_safe_handoff_state()
            descriptor = -1
            try:
                descriptor = fcntl.fcntl(
                    self._leaf.descriptor,
                    fcntl.F_DUPFD_CLOEXEC,
                    3,
                )
                metadata = os.fstat(descriptor)
                if (
                    (metadata.st_dev, metadata.st_ino) != self._leaf.identity
                    or os.get_inheritable(descriptor)
                ):
                    raise OSError(errno.EPERM, "duplicated leaf metadata is unsafe")
                retained = descriptor
                descriptor = -1
                return retained
            except OSError as exc:
                if exc.errno in {errno.EMFILE, errno.ENFILE, errno.ENOMEM, errno.ENOSPC}:
                    raise LinuxCgroupLifecycleError(
                        "resource_exhausted",
                        "worker resources were exhausted while duplicating the cgroup leaf",
                    ) from exc
                raise LinuxCgroupLifecycleError(
                    "cgroup_changed",
                    "the retained cgroup leaf descriptor could not be duplicated",
                ) from exc
            finally:
                if descriptor >= 0:
                    with suppress(OSError):
                        os.close(descriptor)

    def _cleanup(
        self,
        *,
        require_prequalified_empty: bool,
        timeout_ms: int,
    ) -> int:
        with self._lock:
            if self._finished:
                if self._terminal_error is not None:
                    raise self._terminal_error
                if self._cleanup_duration_ms is None:
                    raise AssertionError("successful retained cleanup has no duration")
                return self._cleanup_duration_ms

            self._finished = True
            operation_error: BaseException | None = None
            cleanup_duration_ms: int | None = None
            try:
                cleanup_duration_ms = _cleanup_leaf(
                    self._libc,
                    root_fd=self._root_fd,
                    root_device=self._root_stat.st_dev,
                    leaf=self._leaf,
                    retries=self._policy.openat2_eagain_retries,
                    timeout_ms=timeout_ms,
                    require_prequalified_empty=require_prequalified_empty,
                )
                _require_root_unchanged(
                    self._libc,
                    root_fd=self._root_fd,
                    initial=self._root_stat,
                )
            except LinuxCgroupError as exc:
                operation_error = exc
            except OSError as exc:
                wrapped = LinuxCgroupLifecycleError(
                    "io_failure",
                    "an unexpected retained cgroup cleanup I/O operation failed",
                )
                wrapped.__cause__ = exc
                operation_error = wrapped
            except BaseException as exc:
                operation_error = exc

            close_error: BaseException | None = None
            for descriptor in (self._leaf.descriptor, self._root_fd):
                try:
                    os.close(descriptor)
                except BaseException as exc:
                    close_error = close_error or exc
            self._root_fd = -1

            if close_error is not None:
                if operation_error is not None:
                    operation_error.add_note(
                        "one or more cgroup qualification descriptors also failed to close"
                    )
                else:
                    wrapped = LinuxCgroupLifecycleError(
                        "io_failure",
                        "cgroup qualification descriptors could not be closed",
                    )
                    wrapped.__cause__ = close_error
                    operation_error = wrapped

            self._cleanup_duration_ms = cleanup_duration_ms
            self._terminal_error = operation_error
            if operation_error is not None:
                raise operation_error
            if cleanup_duration_ms is None:
                raise AssertionError("retained cleanup completed without a duration")
            return cleanup_duration_ms

    def cleanup(self) -> int:
        """Kill occupants, wait boundedly, remove the exact leaf, and re-audit the root.

        The operation is terminal and idempotent.  Repeated calls return the first
        duration after success or re-raise the exact first cleanup failure.
        """

        return self._cleanup(
            require_prequalified_empty=False,
            timeout_ms=self._policy.cleanup_timeout_ms,
        )

    def cleanup_with_timeout_ms(self, timeout_ms: int) -> int:
        """Clean the live leaf within a caller-selected, policy-bounded timeout.

        This is the same terminal, idempotent operation as :meth:`cleanup`, but it
        lets an orchestrator spend only the time remaining in a larger shared
        deadline.  The timeout must be an exact built-in integer from one
        millisecond through the policy's cleanup bound.  Invalid input does not
        consume the retained handle.
        """

        if type(timeout_ms) is not int:
            raise LinuxCgroupRejected(
                "invalid_inputs",
                "the retained cleanup timeout must be an exact integer",
            )
        if not 1 <= timeout_ms <= self._policy.cleanup_timeout_ms:
            raise LinuxCgroupRejected(
                "invalid_inputs",
                "the retained cleanup timeout is outside the policy bound",
            )
        return self._cleanup(
            require_prequalified_empty=False,
            timeout_ms=timeout_ms,
        )

    def __enter__(self) -> Self:
        with self._lock:
            self._require_active_identity()
        return self

    def __exit__(
        self,
        _exception_type: type[BaseException] | None,
        exception: BaseException | None,
        _traceback: object,
    ) -> Literal[False]:
        try:
            self.cleanup()
        except BaseException as cleanup_error:
            if exception is None:
                raise
            cleanup_reason: str
            if isinstance(cleanup_error, LinuxCgroupError):
                cleanup_reason = cleanup_error.reason
            else:
                cleanup_reason = "unexpected_error"
            exception.add_note(
                f"retained cgroup cleanup also failed ({cleanup_reason}); "
                "the retained handle exposes cleanup_error"
            )
        return False


def retain_linux_cgroup_v2_leaf(
    policy: LinuxCgroupV2QualificationPolicy,
    resource_profile: ExecutionResourceProfile,
    *,
    delegated_root_fd: int,
) -> LinuxCgroupV2RetainedLeaf:
    """Validate a delegated root and retain one configured, process-free leaf.

    This function neither creates a process nor authorizes a later launch.  The
    returned handle exclusively owns its internal descriptors and cleanup duty.
    """

    _require_linux_x86_64()
    frozen_policy, frozen_profile = _freeze_qualification_inputs(policy, resource_profile)
    policy_sha256 = sha256_json(frozen_policy)
    resource_profile_sha256 = sha256_json(frozen_profile)
    libc = _load_libc()
    pinned_root_fd = -1
    root_fd = -1
    leaf: _QualifiedLeaf | None = None
    active_error: BaseException | None = None
    try:
        pinned_root_fd, pinned_root_stat = _duplicate_delegate_fd(delegated_root_fd)
        _probe_openat2(
            libc,
            pinned_root_fd,
            retries=frozen_policy.openat2_eagain_retries,
        )
        root_fd, root_stat = _reopen_delegate_root(
            libc,
            pinned_fd=pinned_root_fd,
            pinned_stat=pinned_root_stat,
            retries=frozen_policy.openat2_eagain_retries,
        )
        closing_pinned_fd = pinned_root_fd
        pinned_root_fd = -1
        os.close(closing_pinned_fd)
        _require_cgroup2_filesystem(libc, root_fd)
        _require_systemd_delegation_marker(libc, root_fd)
        _require_empty_domain_root(
            libc,
            root_fd=root_fd,
            root_device=root_stat.st_dev,
            retries=frozen_policy.openat2_eagain_retries,
        )
        leaf = _create_leaf(
            libc,
            root_fd=root_fd,
            root_device=root_stat.st_dev,
            retries=frozen_policy.openat2_eagain_retries,
        )
        try:
            leaf = _configure_leaf(
                libc,
                root_fd=root_fd,
                root_device=root_stat.st_dev,
                leaf=leaf,
                profile=frozen_profile,
                retries=frozen_policy.openat2_eagain_retries,
            )
            _require_root_unchanged(libc, root_fd=root_fd, initial=root_stat)
            retained = LinuxCgroupV2RetainedLeaf._create(
                libc=libc,
                policy=frozen_policy,
                resource_profile=frozen_profile,
                policy_sha256=policy_sha256,
                resource_profile_sha256=resource_profile_sha256,
                root_fd=root_fd,
                root_stat=root_stat,
                leaf=leaf,
            )
        except BaseException as exc:
            try:
                _cleanup_leaf(
                    libc,
                    root_fd=root_fd,
                    root_device=root_stat.st_dev,
                    leaf=leaf,
                    retries=frozen_policy.openat2_eagain_retries,
                    timeout_ms=frozen_policy.cleanup_timeout_ms,
                    require_prequalified_empty=False,
                )
                _require_root_unchanged(libc, root_fd=root_fd, initial=root_stat)
            except BaseException as cleanup_exc:
                raise cleanup_exc from exc
            raise

        root_fd = -1
        leaf = None
        return retained
    except LinuxCgroupError as exc:
        active_error = exc
        raise
    except OSError as exc:
        wrapped = LinuxCgroupLifecycleError(
            "io_failure",
            "an unexpected cgroup qualification I/O operation failed",
        )
        active_error = wrapped
        raise wrapped from exc
    except BaseException as exc:
        active_error = exc
        raise
    finally:
        close_error: OSError | None = None
        if leaf is not None:
            try:
                os.close(leaf.descriptor)
            except OSError as exc:
                close_error = exc
        if root_fd >= 0:
            try:
                os.close(root_fd)
            except OSError as exc:
                close_error = close_error or exc
        if pinned_root_fd >= 0:
            try:
                os.close(pinned_root_fd)
            except OSError as exc:
                close_error = close_error or exc
        if close_error is not None:
            if active_error is not None:
                active_error.add_note(
                    "one or more cgroup qualification descriptors also failed to close"
                )
            else:
                raise LinuxCgroupLifecycleError(
                    "io_failure",
                    "cgroup qualification descriptors could not be closed",
                ) from close_error


def qualify_linux_cgroup_v2(
    policy: LinuxCgroupV2QualificationPolicy,
    resource_profile: ExecutionResourceProfile,
    *,
    delegated_root_fd: int,
) -> LinuxCgroupV2QualificationReport:
    """Qualify and remove one empty cgroup-v2 leaf without launching a process."""

    retained = retain_linux_cgroup_v2_leaf(
        policy,
        resource_profile,
        delegated_root_fd=delegated_root_fd,
    )
    cleanup_duration_ms = retained._cleanup(
        require_prequalified_empty=True,
        timeout_ms=retained._policy.cleanup_timeout_ms,
    )
    frozen_policy = retained._policy
    frozen_profile = retained._resource_profile
    report_fields: dict[str, object] = {
        "schema_version": "bpe.linux-cgroup-v2-qualification-report.v1",
        "status": "qualified_without_execution",
        "qualification_nonce": retained.qualification_nonce,
        "policy_id": frozen_policy.policy_id,
        "policy_sha256": retained._policy_sha256,
        "resource_profile_id": frozen_profile.profile_id,
        "resource_profile_sha256": retained._resource_profile_sha256,
        "worker_pool_audience": frozen_policy.worker_pool_audience,
        "delegated_root_id": frozen_policy.delegated_root_id,
        "filesystem": "cgroup2-v2",
        "filesystem_magic_verified": True,
        "delegation_marker_verified": True,
        "delegated_owner_verified": True,
        "delegated_root_empty_verified": True,
        "delegated_root_without_children_verified": True,
        "required_controllers": REQUIRED_CONTROLLERS,
        "required_controllers_available": True,
        "subtree_control_exact_verified": True,
        "leaf_cgroup_type": "domain",
        "memory_max_bytes": frozen_profile.memory_bytes,
        "memory_swap_max_bytes": 0,
        "pids_max": frozen_profile.pids_max,
        "cpu_quota_us": frozen_policy.cpu_quota_us,
        "cpu_period_us": frozen_policy.cpu_period_us,
        "cpu_burst_us": frozen_policy.cpu_burst_us,
        "base_page_size_bytes": frozen_policy.base_page_size_bytes,
        "memory_oom_group": True,
        "leaf_max_depth": frozen_policy.leaf_max_depth,
        "leaf_max_descendants": frozen_policy.leaf_max_descendants,
        "controller_readback_verified": True,
        "cgroup_kill_interface_verified": True,
        "cgroup_kill_empty_write_verified": True,
        "populated_zero_before_cleanup": True,
        "populated_zero_after_kill": True,
        "leaf_identity_verified_before_removal": True,
        "leaf_name_removed": True,
        "dying_descendants_reclaimed": False,
        "cleanup_duration_ms": cleanup_duration_ms,
        "process_creation_probed": False,
        "clone3_qualified": False,
        "pidfd_qualified": False,
        "process_created": False,
        "execution_started": False,
        "candidate_bytes_accessed": False,
        "limits_exercised": False,
        "wall_timeout_enforced": False,
        "cpu_time_enforced": False,
        "output_limits_enforced": False,
        "filesystem_isolation_enforced": False,
        "network_isolation_enforced": False,
        "resource_profile_fully_enforced": False,
        "execution_authorized": False,
        "authoritative": False,
    }
    return LinuxCgroupV2QualificationReport.model_validate(
        {
            **report_fields,
            "qualification_id": _qualification_id(report_fields),
        },
        strict=True,
    )


JSON_SCHEMAS: dict[str, type[BaseModel]] = {
    "linux-cgroup-v2-qualification-policy-v1.json": LinuxCgroupV2QualificationPolicy,
    "linux-cgroup-v2-qualification-report-v1.json": LinuxCgroupV2QualificationReport,
}


__all__ = [
    "CGROUP_QUALIFICATION_DOMAIN",
    "JSON_SCHEMAS",
    "LinuxCgroupError",
    "LinuxCgroupLifecycleError",
    "LinuxCgroupRejected",
    "LinuxCgroupUnavailable",
    "LinuxCgroupV2QualificationPolicy",
    "LinuxCgroupV2QualificationReport",
    "LinuxCgroupV2RetainedLeaf",
    "qualify_linux_cgroup_v2",
    "retain_linux_cgroup_v2_leaf",
]
