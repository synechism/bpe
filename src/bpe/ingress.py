"""Linux-only, non-executing ingress for one durably claimed evaluation job.

The public boundary accepts pinned directory descriptors, never caller-selected paths.
It resolves every untrusted source component with ``openat2(2)``, seals the anchored
bytes in memory, copies them into a private worker tree, and publishes the complete
tree with ``renameat2(RENAME_NOREPLACE)``.  It does not compile or execute candidate
code and cannot produce authoritative grading evidence.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import os
import platform
import stat
import sys
from contextlib import suppress
from dataclasses import dataclass
from typing import Annotated, Any, Literal, NoReturn, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from bpe.canonical import CanonicalJSONError, canonical_json_bytes, sha256_bytes, sha256_json
from bpe.dispatch import DispatchAdmissionReceipt, DispatchClaimLedger, DispatchLedgerError
from bpe.job import (
    MAX_JOB_BLOBS,
    MAX_JOB_MANIFEST_BYTES,
    MAX_JOB_TOTAL_BLOB_BYTES,
    JobBundleError,
    LoadedEvaluationJob,
    _atomic_write_at,
    _create_staging_directory,
    _discard_staged_bundle,
    _load_evaluation_job_from_root,
    _open_component,
)
from bpe.models import Sha256, StableId

OPENAT2_SYSCALL_X86_64 = 437
RENAMEAT2_SYSCALL_X86_64 = 316
RENAME_NOREPLACE = 1
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

PROC_SUPER_MAGIC = 0x9FA0
INGRESS_OBJECT_DOMAIN = b"BPE\x00linux-job-ingress-object\x00v1\x00"


class _OpenHow(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    ]


IngressFailureReason = Literal[
    "unsupported_platform",
    "unsupported_architecture",
    "openat2_unavailable",
    "openat2_abi_incompatible",
    "renameat2_unavailable",
    "trusted_procfs_unavailable",
    "invalid_claim",
    "uncommitted_claim",
    "policy_mismatch",
    "unsafe_source_root",
    "unsafe_source_resolution",
    "source_missing",
    "source_unreadable",
    "source_changed",
    "invalid_bundle",
    "unsafe_destination",
    "destination_conflict",
    "resource_exhausted",
    "io_failure",
]


class LinuxIngressError(ValueError):
    """A bounded, path-free Linux ingress failure."""

    reason: IngressFailureReason

    def __init__(self, reason: IngressFailureReason, message: str) -> None:
        self.reason = reason
        super().__init__(message)


class LinuxIngressUnavailable(LinuxIngressError):
    """The host cannot provide the exact required Linux syscall contract."""


class LinuxIngressRejected(LinuxIngressError):
    """The claim, policy, source, or existing object failed closed."""


class LinuxIngressStorageError(LinuxIngressError):
    """Private worker-store staging or durable publication failed."""


class _IngressModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        allow_inf_nan=False,
        revalidate_instances="always",
        strict=True,
    )


class LinuxJobIngressPolicy(_IngressModel):
    """Signed policy for the only supported spool-to-worker copy strategy."""

    schema_version: Literal["bpe.linux-job-ingress-policy.v1"]
    policy_id: StableId
    worker_pool_audience: StableId
    source_root_id: StableId
    worker_root_id: StableId
    host_platform: Literal["linux"]
    host_architecture: Literal["x86_64"]
    source_layout: Literal["sha256-job-directory-v1"]
    source_open_method: Literal["openat2-v1"]
    regular_file_open_method: Literal["openat2-opath-procfd-reopen-v1"]
    trusted_procfs_required: Literal[True]
    resolve_beneath: Literal[True]
    resolve_no_xdev: Literal[True]
    resolve_no_symlinks: Literal[True]
    resolve_no_magiclinks: Literal[True]
    openat2_eagain_retries: Literal[3]
    max_manifest_bytes: Literal[262144]
    max_blobs: Literal[256]
    max_blob_bytes: Literal[16777216]
    max_total_blob_bytes: Literal[134217728]
    copy_method: Literal["verified-bounded-byte-copy-v1"]
    publish_method: Literal["renameat2-noreplace-v1"]
    worker_directory_mode: Literal["0700"]
    worker_file_mode: Literal["0600"]
    execution_permitted: Literal[False]
    authoritative_ready: Literal[False]

    @field_validator(
        "trusted_procfs_required",
        "resolve_beneath",
        "resolve_no_xdev",
        "resolve_no_symlinks",
        "resolve_no_magiclinks",
        mode="before",
    )
    @classmethod
    def true_controls_must_be_boolean_true(cls, value: object) -> object:
        if value is not True:
            raise ValueError("Linux ingress safety controls must be boolean true")
        return value

    @field_validator("execution_permitted", "authoritative_ready", mode="before")
    @classmethod
    def false_claims_must_be_boolean_false(cls, value: object) -> object:
        if value is not False:
            raise ValueError("Linux ingress cannot permit execution or authority")
        return value


def _worker_object_id(
    *,
    dispatch_claim_receipt_sha256: str,
    job_manifest_sha256: str,
    ingress_policy_sha256: str,
) -> str:
    return sha256_bytes(
        INGRESS_OBJECT_DOMAIN
        + bytes.fromhex(dispatch_claim_receipt_sha256)
        + bytes.fromhex(job_manifest_sha256)
        + bytes.fromhex(ingress_policy_sha256)
    )


class LinuxJobIngressReceipt(_IngressModel):
    """Deterministic evidence that a claimed job was copied, not executed."""

    schema_version: Literal["bpe.linux-job-ingress-receipt.v1"]
    status: Literal["ingressed_not_executed"]
    worker_object_id: Sha256
    dispatch_claim_receipt_sha256: Sha256
    authorization_id: StableId
    authorization_sha256: Sha256
    claim_id: Sha256
    claim_nonce: Sha256
    dispatch_nonce: Sha256
    job_manifest_sha256: Sha256
    ingress_policy_id: StableId
    ingress_policy_sha256: Sha256
    worker_pool_audience: StableId
    source_root_id: StableId
    worker_root_id: StableId
    source_open_method: Literal["openat2-v1"]
    regular_file_open_method: Literal["openat2-opath-procfd-reopen-v1"]
    resolve_beneath: Literal[True]
    resolve_no_xdev: Literal[True]
    resolve_no_symlinks: Literal[True]
    resolve_no_magiclinks: Literal[True]
    copy_method: Literal["verified-bounded-byte-copy-v1"]
    publish_method: Literal["renameat2-noreplace-v1"]
    manifest_size_bytes: Annotated[int, Field(ge=1, le=MAX_JOB_MANIFEST_BYTES)]
    blob_count: Annotated[int, Field(ge=1, le=MAX_JOB_BLOBS)]
    total_blob_bytes: Annotated[int, Field(ge=1, le=MAX_JOB_TOTAL_BLOB_BYTES)]
    source_verified: Literal[True]
    worker_copy_verified: Literal[True]
    published_without_replacement: Literal[True]
    execution_started: Literal[False]
    authoritative: Literal[False]

    @field_validator(
        "resolve_beneath",
        "resolve_no_xdev",
        "resolve_no_symlinks",
        "resolve_no_magiclinks",
        "source_verified",
        "worker_copy_verified",
        "published_without_replacement",
        mode="before",
    )
    @classmethod
    def true_claims_must_be_boolean_true(cls, value: object) -> object:
        if value is not True:
            raise ValueError("Linux ingress verification claims must be boolean true")
        return value

    @field_validator("execution_started", "authoritative", mode="before")
    @classmethod
    def false_claims_must_be_boolean_false(cls, value: object) -> object:
        if value is not False:
            raise ValueError("Linux ingress cannot claim execution or authority")
        return value

    @model_validator(mode="after")
    def object_identity_is_cross_bound(self) -> Self:
        expected = _worker_object_id(
            dispatch_claim_receipt_sha256=self.dispatch_claim_receipt_sha256,
            job_manifest_sha256=self.job_manifest_sha256,
            ingress_policy_sha256=self.ingress_policy_sha256,
        )
        if self.worker_object_id != expected:
            raise ValueError("worker object identity is inconsistent")
        return self


@dataclass
class SealedJobIngress:
    """Opaque retained worker object plus immutable bytes; close after handoff."""

    receipt: LinuxJobIngressReceipt
    job: LoadedEvaluationJob
    _root_fd: int

    def fileno(self) -> int:
        if self._root_fd < 0:
            raise ValueError("sealed job ingress is closed")
        return self._root_fd

    @property
    def closed(self) -> bool:
        return self._root_fd < 0

    def close(self) -> None:
        if self._root_fd >= 0:
            os.close(self._root_fd)
            self._root_fd = -1

    def __enter__(self) -> Self:
        if self.closed:
            raise ValueError("sealed job ingress is closed")
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def _require_linux_x86_64() -> None:
    if sys.platform != "linux":
        raise LinuxIngressUnavailable(
            "unsupported_platform",
            "Linux job ingress requires Linux",
        )
    if platform.machine() != "x86_64" or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise LinuxIngressUnavailable(
            "unsupported_architecture",
            "Linux job ingress requires the pinned x86_64 ABI",
        )
    if (
        ctypes.sizeof(_OpenHow) != 24
        or _OpenHow.flags.offset != 0
        or _OpenHow.mode.offset != 8
        or _OpenHow.resolve.offset != 16
    ):
        raise LinuxIngressUnavailable(
            "openat2_abi_incompatible",
            "the openat2 ABI layout is incompatible",
        )
    required = (
        "O_PATH",
        "O_DIRECTORY",
        "O_NOFOLLOW",
        "O_CLOEXEC",
        "O_NONBLOCK",
    )
    if (
        any(not hasattr(os, name) for name in required)
        or getattr(os, "O_PATH", None) != O_PATH_LINUX
        or not hasattr(fcntl, "F_DUPFD_CLOEXEC")
    ):
        raise LinuxIngressUnavailable(
            "openat2_abi_incompatible",
            "required Linux descriptor flags are unavailable",
        )


def _load_libc() -> Any:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.syscall.restype = ctypes.c_long
    except (AttributeError, OSError) as exc:
        raise LinuxIngressUnavailable(
            "openat2_unavailable",
            "the Linux syscall interface is unavailable",
        ) from exc
    return libc


def _validate_component_name(name: str, *, allow_dot: bool = False) -> bytes:
    if type(name) is not str or "\x00" in name or "/" in name:
        raise LinuxIngressRejected(
            "unsafe_source_resolution",
            "an ingress source component is invalid",
        )
    if name in {"", ".."} or (name == "." and not allow_dot):
        raise LinuxIngressRejected(
            "unsafe_source_resolution",
            "an ingress source component is invalid",
        )
    try:
        encoded = name.encode("ascii")
    except UnicodeEncodeError as exc:
        raise LinuxIngressRejected(
            "unsafe_source_resolution",
            "an ingress source component is invalid",
        ) from exc
    return encoded


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


def _probe_openat2(libc: Any, source_root_fd: int, *, retries: int) -> None:
    descriptor = -1
    try:
        descriptor = _openat2(
            libc,
            parent_fd=source_root_fd,
            name=".",
            flags=(
                O_PATH_LINUX
                | os.O_DIRECTORY
                | os.O_NOFOLLOW
                | os.O_CLOEXEC
            ),
            retries=retries,
            allow_dot=True,
        )
    except OSError as exc:
        if exc.errno in {errno.ENOSYS, errno.EPERM}:
            reason: IngressFailureReason = "openat2_unavailable"
        elif exc.errno in {errno.EINVAL, errno.E2BIG}:
            reason = "openat2_abi_incompatible"
        elif exc.errno == errno.EAGAIN:
            reason = "source_changed"
        else:
            reason = "openat2_unavailable"
        raise LinuxIngressUnavailable(reason, "the exact openat2 contract is unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _open_trusted_procfd(libc: Any) -> int:
    descriptor = -1
    try:
        descriptor = os.open(
            "/proc/self/fd",
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
        )
        opened = os.fstat(descriptor)
        if not stat.S_ISDIR(opened.st_mode):
            raise OSError(errno.ENOTDIR, "procfd is not a directory")
        buffer = (ctypes.c_ubyte * 256)()
        libc.fstatfs.argtypes = (ctypes.c_int, ctypes.c_void_p)
        libc.fstatfs.restype = ctypes.c_int
        ctypes.set_errno(0)
        if libc.fstatfs(ctypes.c_int(descriptor), ctypes.byref(buffer)) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        filesystem_type = ctypes.c_long.from_buffer(buffer).value
        if filesystem_type != PROC_SUPER_MAGIC:
            raise OSError(errno.ENODEV, "procfd is not backed by procfs")
        os.set_inheritable(descriptor, False)
        return descriptor
    except (AttributeError, OSError) as exc:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        raise LinuxIngressUnavailable(
            "trusted_procfs_unavailable",
            "trusted procfs descriptor reopening is unavailable",
        ) from exc


def _raise_source_open_error(exc: OSError) -> NoReturn:
    if exc.errno in {errno.ENOSYS, errno.EPERM}:
        raise LinuxIngressUnavailable(
            "openat2_unavailable",
            "the exact openat2 contract became unavailable",
        ) from exc
    if exc.errno in {errno.EINVAL, errno.E2BIG}:
        raise LinuxIngressUnavailable(
            "openat2_abi_incompatible",
            "the exact openat2 ABI became unavailable",
        ) from exc
    if exc.errno in {errno.ELOOP, errno.EXDEV, errno.ENOTDIR}:
        raise LinuxIngressRejected(
            "unsafe_source_resolution",
            "an ingress source component escaped its resolution boundary",
        ) from exc
    if exc.errno == errno.ENOENT:
        raise LinuxIngressRejected(
            "source_missing",
            "the claimed ingress source is missing",
        ) from exc
    if exc.errno in {errno.EACCES, errno.EROFS}:
        raise LinuxIngressRejected(
            "source_unreadable",
            "the claimed ingress source is not readable",
        ) from exc
    if exc.errno in {errno.EAGAIN, errno.ESTALE}:
        raise LinuxIngressRejected(
            "source_changed",
            "the claimed ingress source changed during resolution",
        ) from exc
    if exc.errno in {errno.EMFILE, errno.ENFILE, errno.ENOMEM}:
        raise LinuxIngressStorageError(
            "resource_exhausted",
            "worker resources were exhausted during source ingress",
        ) from exc
    raise LinuxIngressStorageError(
        "io_failure",
        "an ingress source operation failed",
    ) from exc


class _StrictSourceOpener:
    def __init__(
        self,
        libc: Any,
        procfd: int,
        *,
        retries: int,
        forbidden_directory_identities: frozenset[tuple[int, int]],
    ) -> None:
        self._libc = libc
        self._procfd = procfd
        self._retries = retries
        self._forbidden_directory_identities = forbidden_directory_identities

    def __call__(
        self,
        name: str,
        *,
        parent_fd: int,
        root_device: int,
        directory: bool,
        label: str,
    ) -> int:
        del label
        path_fd = -1
        read_fd = -1
        try:
            flags = O_PATH_LINUX | os.O_NOFOLLOW | os.O_CLOEXEC
            if directory:
                flags |= os.O_DIRECTORY
            path_fd = _openat2(
                self._libc,
                parent_fd=parent_fd,
                name=name,
                flags=flags,
                retries=self._retries,
            )
            pinned = os.fstat(path_fd)
            expected_kind = stat.S_ISDIR if directory else stat.S_ISREG
            if directory and (pinned.st_dev, pinned.st_ino) in (
                self._forbidden_directory_identities
            ):
                raise LinuxIngressStorageError(
                    "unsafe_destination",
                    "the worker root aliases the claimed source tree",
                )
            if (
                not expected_kind(pinned.st_mode)
                or pinned.st_dev != root_device
                or (not directory and pinned.st_nlink != 1)
            ):
                raise LinuxIngressRejected(
                    "unsafe_source_resolution",
                    "an ingress source component has an unsafe type or identity",
                )

            reopen_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
            if directory:
                reopen_flags |= os.O_DIRECTORY
            read_fd = os.open(str(path_fd), reopen_flags, dir_fd=self._procfd)
            os.set_inheritable(read_fd, False)
            reopened = os.fstat(read_fd)
            if (
                (reopened.st_dev, reopened.st_ino)
                != (pinned.st_dev, pinned.st_ino)
                or not expected_kind(reopened.st_mode)
                or reopened.st_dev != root_device
                or (not directory and reopened.st_nlink != 1)
            ):
                raise LinuxIngressRejected(
                    "source_changed",
                    "an ingress source component changed while it was pinned",
                )
            return read_fd
        except LinuxIngressError:
            raise
        except OSError as exc:
            _raise_source_open_error(exc)
        finally:
            if path_fd >= 0:
                os.close(path_fd)
            if read_fd >= 0 and sys.exc_info()[0] is not None:
                os.close(read_fd)


def _duplicate_directory_fd(descriptor: int, *, source: bool) -> tuple[int, os.stat_result]:
    if type(descriptor) is not int or descriptor < 0:
        error_type = LinuxIngressRejected if source else LinuxIngressStorageError
        reason: IngressFailureReason = "unsafe_source_root" if source else "unsafe_destination"
        raise error_type(reason, "an ingress root descriptor is invalid")
    duplicate = -1
    try:
        duplicate = fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, 3)
        flags = fcntl.fcntl(duplicate, fcntl.F_GETFL)
        opened = os.fstat(duplicate)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or flags & O_PATH_LINUX
            or os.get_inheritable(duplicate)
        ):
            raise OSError(errno.EBADF, "root descriptor is not a readable directory")
        if source:
            if (
                opened.st_uid not in {0, os.geteuid()}
                or opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            ):
                raise OSError(errno.EPERM, "source root is not trusted")
        elif opened.st_uid != os.geteuid() or stat.S_IMODE(opened.st_mode) != 0o700:
            raise OSError(errno.EPERM, "worker root is not private")
        return duplicate, opened
    except OSError as exc:
        if duplicate >= 0:
            with suppress(OSError):
                os.close(duplicate)
        if source:
            raise LinuxIngressRejected(
                "unsafe_source_root",
                "the ingress source root descriptor is unsafe",
            ) from exc
        raise LinuxIngressStorageError(
            "unsafe_destination",
            "the worker-store root descriptor is unsafe",
        ) from exc


def _directory_is_ancestor(
    ancestor: os.stat_result,
    descendant_fd: int,
    *,
    max_depth: int = 1024,
) -> bool:
    """Conservatively compare pinned roots without recovering caller-visible paths."""

    current_fd = -1
    try:
        current_fd = fcntl.fcntl(descendant_fd, fcntl.F_DUPFD_CLOEXEC, 3)
        for _ in range(max_depth):
            current = os.fstat(current_fd)
            if (current.st_dev, current.st_ino) == (ancestor.st_dev, ancestor.st_ino):
                return True
            parent_fd = -1
            try:
                parent_fd = os.open(
                    "..",
                    O_PATH_LINUX | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=current_fd,
                )
                os.set_inheritable(parent_fd, False)
                parent = os.fstat(parent_fd)
                previous_fd = current_fd
                current_fd = parent_fd
                parent_fd = -1
                os.close(previous_fd)
            finally:
                if parent_fd >= 0:
                    os.close(parent_fd)
            if (parent.st_dev, parent.st_ino) == (current.st_dev, current.st_ino):
                return False
        raise OSError(errno.ELOOP, "directory ancestry exceeds the ingress limit")
    finally:
        if current_fd >= 0:
            os.close(current_fd)


def _require_disjoint_roots(
    *,
    source_fd: int,
    source_stat: os.stat_result,
    worker_fd: int,
    worker_stat: os.stat_result,
) -> None:
    try:
        overlaps = _directory_is_ancestor(source_stat, worker_fd) or _directory_is_ancestor(
            worker_stat,
            source_fd,
        )
    except OSError as exc:
        raise LinuxIngressStorageError(
            "unsafe_destination",
            "source and worker root isolation cannot be established",
        ) from exc
    if overlaps:
        raise LinuxIngressStorageError(
            "unsafe_destination",
            "source and worker roots must be disjoint",
        )


def _open_source_job(
    opener: _StrictSourceOpener,
    *,
    source_root_fd: int,
    source_root_device: int,
    manifest_sha256: str,
) -> tuple[int, LoadedEvaluationJob]:
    digest_root_fd = -1
    job_fd = -1
    try:
        digest_root_fd = opener(
            "sha256",
            parent_fd=source_root_fd,
            root_device=source_root_device,
            directory=True,
            label="source digest namespace",
        )
        job_fd = opener(
            manifest_sha256,
            parent_fd=digest_root_fd,
            root_device=source_root_device,
            directory=True,
            label="claimed source job",
        )
        loaded = _load_evaluation_job_from_root(
            root_fd=job_fd,
            root_device=source_root_device,
            expected_manifest_sha256=manifest_sha256,
            component_opener=opener,
        )
        retained = job_fd
        job_fd = -1
        return retained, loaded
    except LinuxIngressError:
        raise
    except JobBundleError as exc:
        raise LinuxIngressRejected(
            "invalid_bundle",
            "the claimed evaluation job bundle is invalid",
        ) from exc
    finally:
        if job_fd >= 0:
            os.close(job_fd)
        if digest_root_fd >= 0:
            os.close(digest_root_fd)


def _same_loaded_job(left: LoadedEvaluationJob, right: LoadedEvaluationJob) -> bool:
    return left == right and left.anchored is True and right.anchored is True


def _validate_worker_tree(
    root_fd: int,
    *,
    root_device: int,
    loaded: LoadedEvaluationJob,
) -> None:
    expected_uid = os.geteuid()
    root_stat = os.fstat(root_fd)
    if (
        not stat.S_ISDIR(root_stat.st_mode)
        or root_stat.st_dev != root_device
        or root_stat.st_uid != expected_uid
        or stat.S_IMODE(root_stat.st_mode) != 0o700
    ):
        raise JobBundleError("worker object root metadata is unsafe")

    directories = ((root_fd, "blobs"),)
    opened_directories: list[int] = []
    try:
        for parent_fd, name in directories:
            descriptor = _open_component(
                name,
                parent_fd=parent_fd,
                root_device=root_device,
                directory=True,
                label="worker object directory",
            )
            opened_directories.append(descriptor)
            metadata = os.fstat(descriptor)
            if metadata.st_uid != expected_uid or stat.S_IMODE(metadata.st_mode) != 0o700:
                raise JobBundleError("worker object directory metadata is unsafe")
        sha256_fd = _open_component(
            "sha256",
            parent_fd=opened_directories[0],
            root_device=root_device,
            directory=True,
            label="worker object digest directory",
        )
        opened_directories.append(sha256_fd)
        sha_metadata = os.fstat(sha256_fd)
        if sha_metadata.st_uid != expected_uid or stat.S_IMODE(sha_metadata.st_mode) != 0o700:
            raise JobBundleError("worker object digest directory metadata is unsafe")

        for parent_fd, name in (
            (root_fd, "manifest.json"),
            *((sha256_fd, blob.reference.sha256) for blob in loaded.blobs),
        ):
            metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_dev != root_device
                or metadata.st_uid != expected_uid
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise JobBundleError("worker object file metadata is unsafe")
    finally:
        for descriptor in reversed(opened_directories):
            os.close(descriptor)


def _build_receipt(
    claim: DispatchAdmissionReceipt,
    policy: LinuxJobIngressPolicy,
    loaded: LoadedEvaluationJob,
    *,
    claim_receipt_sha256: str,
    policy_sha256: str,
) -> LinuxJobIngressReceipt:
    manifest_bytes = canonical_json_bytes(loaded.manifest)
    return LinuxJobIngressReceipt(
        schema_version="bpe.linux-job-ingress-receipt.v1",
        status="ingressed_not_executed",
        worker_object_id=_worker_object_id(
            dispatch_claim_receipt_sha256=claim_receipt_sha256,
            job_manifest_sha256=claim.job_manifest_sha256,
            ingress_policy_sha256=policy_sha256,
        ),
        dispatch_claim_receipt_sha256=claim_receipt_sha256,
        authorization_id=claim.authorization_id,
        authorization_sha256=claim.authorization_sha256,
        claim_id=claim.claim_id,
        claim_nonce=claim.claim_nonce,
        dispatch_nonce=claim.dispatch_nonce,
        job_manifest_sha256=claim.job_manifest_sha256,
        ingress_policy_id=policy.policy_id,
        ingress_policy_sha256=policy_sha256,
        worker_pool_audience=claim.worker_pool_audience,
        source_root_id=policy.source_root_id,
        worker_root_id=policy.worker_root_id,
        source_open_method=policy.source_open_method,
        regular_file_open_method=policy.regular_file_open_method,
        resolve_beneath=policy.resolve_beneath,
        resolve_no_xdev=policy.resolve_no_xdev,
        resolve_no_symlinks=policy.resolve_no_symlinks,
        resolve_no_magiclinks=policy.resolve_no_magiclinks,
        copy_method=policy.copy_method,
        publish_method=policy.publish_method,
        manifest_size_bytes=len(manifest_bytes),
        blob_count=len(loaded.blobs),
        total_blob_bytes=sum(len(blob.content) for blob in loaded.blobs),
        source_verified=True,
        worker_copy_verified=True,
        published_without_replacement=True,
        execution_started=False,
        authoritative=False,
    )


def _open_existing_worker_object(
    *,
    worker_root_fd: int,
    worker_root_device: int,
    worker_object_id: str,
    source: LoadedEvaluationJob,
) -> tuple[int, LoadedEvaluationJob]:
    target_fd = -1
    try:
        target_fd = _open_component(
            worker_object_id,
            parent_fd=worker_root_fd,
            root_device=worker_root_device,
            directory=True,
            label="existing worker object",
        )
        loaded = _load_evaluation_job_from_root(
            root_fd=target_fd,
            root_device=worker_root_device,
            expected_manifest_sha256=source.manifest_sha256,
        )
        _validate_worker_tree(
            target_fd,
            root_device=worker_root_device,
            loaded=loaded,
        )
        if not _same_loaded_job(source, loaded):
            raise JobBundleError("existing worker object differs from the source")
        retained = target_fd
        target_fd = -1
        return retained, loaded
    except (JobBundleError, OSError) as exc:
        raise LinuxIngressRejected(
            "destination_conflict",
            "the deterministic worker object target conflicts",
        ) from exc
    finally:
        if target_fd >= 0:
            os.close(target_fd)


def _rename_stage_without_replacement(
    libc: Any,
    *,
    worker_root_fd: int,
    staged_name: str,
    worker_object_id: str,
) -> None:
    ctypes.set_errno(0)
    result = libc.syscall(
        ctypes.c_long(RENAMEAT2_SYSCALL_X86_64),
        ctypes.c_int(worker_root_fd),
        ctypes.c_char_p(staged_name.encode("ascii")),
        ctypes.c_int(worker_root_fd),
        ctypes.c_char_p(worker_object_id.encode("ascii")),
        ctypes.c_uint(RENAME_NOREPLACE),
    )
    if result >= 0:
        return
    error = ctypes.get_errno()
    raise OSError(error, os.strerror(error))


def _stage_and_publish(
    libc: Any,
    *,
    worker_root_fd: int,
    worker_root_device: int,
    worker_object_id: str,
    source: LoadedEvaluationJob,
) -> tuple[int, LoadedEvaluationJob]:
    staged_name: str | None = None
    staged_fd = -1
    blobs_fd = -1
    sha256_fd = -1
    try:
        staged_name, staged_fd = _create_staging_directory(
            parent_fd=worker_root_fd,
            parent_device=worker_root_device,
        )
        os.mkdir("blobs", mode=0o700, dir_fd=staged_fd)
        blobs_fd = _open_component(
            "blobs",
            parent_fd=staged_fd,
            root_device=worker_root_device,
            directory=True,
            label="staged worker blob parent",
        )
        os.fchmod(blobs_fd, 0o700)
        os.mkdir("sha256", mode=0o700, dir_fd=blobs_fd)
        sha256_fd = _open_component(
            "sha256",
            parent_fd=blobs_fd,
            root_device=worker_root_device,
            directory=True,
            label="staged worker digest store",
        )
        os.fchmod(sha256_fd, 0o700)
        for blob in source.blobs:
            _atomic_write_at(sha256_fd, blob.reference.sha256, blob.content)
        manifest_bytes = canonical_json_bytes(source.manifest)
        _atomic_write_at(staged_fd, "manifest.json", manifest_bytes)
        os.fsync(sha256_fd)
        os.fsync(blobs_fd)
        os.fsync(staged_fd)
        os.close(sha256_fd)
        sha256_fd = -1
        os.close(blobs_fd)
        blobs_fd = -1

        staged = _load_evaluation_job_from_root(
            root_fd=staged_fd,
            root_device=worker_root_device,
            expected_manifest_sha256=source.manifest_sha256,
        )
        _validate_worker_tree(
            staged_fd,
            root_device=worker_root_device,
            loaded=staged,
        )
        if not _same_loaded_job(source, staged):
            raise JobBundleError("staged worker object differs from sealed source bytes")

        try:
            _rename_stage_without_replacement(
                libc,
                worker_root_fd=worker_root_fd,
                staged_name=staged_name,
                worker_object_id=worker_object_id,
            )
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                existing_fd, existing = _open_existing_worker_object(
                    worker_root_fd=worker_root_fd,
                    worker_root_device=worker_root_device,
                    worker_object_id=worker_object_id,
                    source=source,
                )
                try:
                    # A prior attempt may have completed renameat2 but failed before
                    # synchronizing the parent.  Recovery repeats that durability edge
                    # before returning the same deterministic receipt.
                    os.fsync(worker_root_fd)
                except OSError:
                    os.close(existing_fd)
                    raise
                return existing_fd, existing
            if exc.errno in {errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP}:
                raise LinuxIngressUnavailable(
                    "renameat2_unavailable",
                    "atomic no-replacement publication is unavailable",
                ) from exc
            if exc.errno in {errno.ENOSPC, errno.EDQUOT, errno.EMFILE, errno.ENFILE, errno.ENOMEM}:
                raise LinuxIngressStorageError(
                    "resource_exhausted",
                    "worker resources were exhausted during publication",
                ) from exc
            if exc.errno == errno.EXDEV:
                raise LinuxIngressStorageError(
                    "unsafe_destination",
                    "worker publication crossed a filesystem boundary",
                ) from exc
            raise LinuxIngressStorageError(
                "io_failure",
                "atomic worker-object publication failed",
            ) from exc

        staged_name = None
        os.fsync(worker_root_fd)
        published = _load_evaluation_job_from_root(
            root_fd=staged_fd,
            root_device=worker_root_device,
            expected_manifest_sha256=source.manifest_sha256,
        )
        _validate_worker_tree(
            staged_fd,
            root_device=worker_root_device,
            loaded=published,
        )
        if not _same_loaded_job(source, published):
            raise JobBundleError("published worker object differs from sealed source bytes")
        retained = staged_fd
        staged_fd = -1
        return retained, published
    except LinuxIngressError:
        raise
    except (CanonicalJSONError, JobBundleError, OSError) as exc:
        if isinstance(exc, OSError) and exc.errno in {
            errno.ENOSPC,
            errno.EDQUOT,
            errno.EMFILE,
            errno.ENFILE,
            errno.ENOMEM,
        }:
            raise LinuxIngressStorageError(
                "resource_exhausted",
                "worker resources were exhausted during job ingress",
            ) from exc
        raise LinuxIngressStorageError(
            "io_failure",
            "worker object staging or verification failed",
        ) from exc
    finally:
        if sha256_fd >= 0:
            os.close(sha256_fd)
        if blobs_fd >= 0:
            os.close(blobs_fd)
        if staged_name is not None and staged_fd >= 0:
            _discard_staged_bundle(
                parent_fd=worker_root_fd,
                parent_device=worker_root_device,
                staged_fd=staged_fd,
                staged_name=staged_name,
                blob_names=tuple(blob.reference.sha256 for blob in source.blobs),
            )
        if staged_fd >= 0:
            os.close(staged_fd)


def ingress_claimed_evaluation_job(
    claim: DispatchAdmissionReceipt,
    policy: LinuxJobIngressPolicy,
    *,
    ledger: DispatchClaimLedger,
    source_spool_fd: int,
    worker_store_fd: int,
) -> SealedJobIngress:
    """Copy one exact committed claim into a sealed, non-executing worker object."""

    # Refuse unsupported hosts before loading libc, touching the ledger, or inspecting
    # caller-supplied descriptors.  There is deliberately no portable fallback.
    _require_linux_x86_64()
    try:
        frozen_claim = DispatchAdmissionReceipt.model_validate(
            claim.model_dump(mode="python"),
            strict=True,
        )
        frozen_policy = LinuxJobIngressPolicy.model_validate(
            policy.model_dump(mode="python"),
            strict=True,
        )
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise LinuxIngressRejected(
            "invalid_claim",
            "Linux ingress claim or policy is invalid",
        ) from exc
    policy_sha256 = sha256_json(frozen_policy)
    if (
        frozen_claim.policy_id != frozen_policy.policy_id
        or frozen_claim.policy_sha256 != policy_sha256
        or frozen_claim.worker_pool_audience != frozen_policy.worker_pool_audience
    ):
        raise LinuxIngressRejected(
            "policy_mismatch",
            "the committed dispatch claim does not bind the ingress policy",
        )
    if type(ledger) is not DispatchClaimLedger:
        raise LinuxIngressRejected(
            "uncommitted_claim",
            "a trusted dispatch claim ledger is required",
        )
    try:
        claim_receipt_sha256 = ledger.verify_committed_receipt(frozen_claim)
    except DispatchLedgerError as exc:
        raise LinuxIngressRejected(
            "uncommitted_claim",
            "the exact dispatch claim receipt is not committed",
        ) from exc

    libc = _load_libc()
    source_fd = -1
    worker_fd = -1
    source_job_fd = -1
    procfd = -1
    retained_fd = -1
    try:
        source_fd, source_stat = _duplicate_directory_fd(source_spool_fd, source=True)
        worker_fd, worker_stat = _duplicate_directory_fd(worker_store_fd, source=False)
        _require_disjoint_roots(
            source_fd=source_fd,
            source_stat=source_stat,
            worker_fd=worker_fd,
            worker_stat=worker_stat,
        )
        _probe_openat2(
            libc,
            source_fd,
            retries=frozen_policy.openat2_eagain_retries,
        )
        procfd = _open_trusted_procfd(libc)
        opener = _StrictSourceOpener(
            libc,
            procfd,
            retries=frozen_policy.openat2_eagain_retries,
            forbidden_directory_identities=frozenset(
                {(worker_stat.st_dev, worker_stat.st_ino)}
            ),
        )
        source_job_fd, source = _open_source_job(
            opener,
            source_root_fd=source_fd,
            source_root_device=source_stat.st_dev,
            manifest_sha256=frozen_claim.job_manifest_sha256,
        )
        receipt = _build_receipt(
            frozen_claim,
            frozen_policy,
            source,
            claim_receipt_sha256=claim_receipt_sha256,
            policy_sha256=policy_sha256,
        )
        retained_fd, worker_copy = _stage_and_publish(
            libc,
            worker_root_fd=worker_fd,
            worker_root_device=worker_stat.st_dev,
            worker_object_id=receipt.worker_object_id,
            source=source,
        )
        result = SealedJobIngress(
            receipt=receipt,
            job=worker_copy,
            _root_fd=retained_fd,
        )
        retained_fd = -1
        return result
    finally:
        if retained_fd >= 0:
            os.close(retained_fd)
        if source_job_fd >= 0:
            os.close(source_job_fd)
        if procfd >= 0:
            os.close(procfd)
        if worker_fd >= 0:
            os.close(worker_fd)
        if source_fd >= 0:
            os.close(source_fd)


JSON_SCHEMAS: dict[str, type[BaseModel]] = {
    "linux-job-ingress-policy-v1.json": LinuxJobIngressPolicy,
    "linux-job-ingress-receipt-v1.json": LinuxJobIngressReceipt,
}


__all__ = [
    "INGRESS_OBJECT_DOMAIN",
    "JSON_SCHEMAS",
    "LinuxIngressError",
    "LinuxIngressRejected",
    "LinuxIngressStorageError",
    "LinuxIngressUnavailable",
    "LinuxJobIngressPolicy",
    "LinuxJobIngressReceipt",
    "SealedJobIngress",
    "ingress_claimed_evaluation_job",
]
