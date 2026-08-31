"""Fail-closed immutable preflight for the fixed Linux inert-fixture launcher.

The public boundary accepts an exact caller-supplied descriptor, never a launcher path.
It copies the authenticated bytes into an executable ``memfd``, applies the complete
Linux write/size/execute seal set, and retains only a read-only descriptor suitable for
a later ``execveat(AT_EMPTY_PATH)`` handoff.  It does not create a process, consume a
launch attempt, or grant launch authority.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import os
import platform
import stat
import struct
import sys
import threading
from contextlib import suppress
from dataclasses import dataclass
from typing import Annotated, Any, Literal, NoReturn, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from bpe.canonical import canonical_json_bytes, sha256_bytes
from bpe.inert_launch import (
    InertFixtureLaunchExpectation,
    InertFixtureLaunchExpectationError,
    inert_fixture_launch_expectation_for,
)
from bpe.models import Sha256, StableId

MEMFD_CREATE_SYSCALL_X86_64 = 319
MFD_CLOEXEC = 0x0001
MFD_ALLOW_SEALING = 0x0002
MFD_EXEC = 0x0010

F_ADD_SEALS_LINUX = 1033
F_GET_SEALS_LINUX = 1034
F_SEAL_SEAL = 0x0001
F_SEAL_SHRINK = 0x0002
F_SEAL_GROW = 0x0004
F_SEAL_WRITE = 0x0008
F_SEAL_FUTURE_WRITE = 0x0010
F_SEAL_EXEC = 0x0020
REQUIRED_EXEC_SEALS = (
    F_SEAL_SEAL
    | F_SEAL_SHRINK
    | F_SEAL_GROW
    | F_SEAL_WRITE
    | F_SEAL_FUTURE_WRITE
    | F_SEAL_EXEC
)

PROC_SUPER_MAGIC = 0x9FA0
O_PATH_LINUX = 0o10000000
MAX_LAUNCHER_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_LINUX_DESCRIPTOR = (1 << 31) - 1
ARTIFACT_READ_CHUNK_BYTES = 128 * 1024
SEALED_EXECUTABLE_MODE = stat.S_IFREG | 0o500
PREFLIGHT_ID_DOMAIN = b"BPE\x00inert-launcher-artifact-preflight\x00v1\x00"

FIXED_SECCOMP_POLICY_ID = "bpe.inert-fixture-launcher-seccomp.v1"
FIXED_SECCOMP_POLICY_SHA256 = (
    "3ac1f4557845704da77f6778c886f3dd65b8ccb97d5060781cb88ee264195ddd"
)

ELF_HEADER_SIZE = 64
ELF_PROGRAM_HEADER_SIZE = 56
ELFCLASS64 = 2
ELFDATA2LSB = 1
ELFOSABI_LINUX = 3
ET_DYN = 3
EM_X86_64 = 62
PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PF_X = 0x1
PF_W = 0x2
PF_R = 0x4
DT_NULL = 0
DT_NEEDED = 1
DT_RPATH = 15
DT_FLAGS = 30
DT_RUNPATH = 29
DT_FLAGS_1 = 0x6FFFFFFB
DF_BIND_NOW = 0x8
DF_1_NOW = 0x1
DF_1_PIE = 0x08000000
UINT64_MAX = (1 << 64) - 1


ArtifactFailureReason = Literal[
    "unsupported_platform",
    "unsupported_architecture",
    "memfd_unavailable",
    "sealing_unavailable",
    "trusted_procfs_unavailable",
    "invalid_expectation",
    "invalid_source_descriptor",
    "unsafe_source_artifact",
    "artifact_too_large",
    "source_changed",
    "artifact_digest_mismatch",
    "invalid_elf",
    "seccomp_identity_mismatch",
    "resource_exhausted",
    "io_failure",
    "sealed_artifact_changed",
    "sealed_artifact_closed",
]


class LinuxInertLauncherArtifactError(ValueError):
    """A bounded, path-free launcher-artifact preflight failure."""

    reason: ArtifactFailureReason

    def __init__(self, reason: ArtifactFailureReason, message: str) -> None:
        self.reason = reason
        super().__init__(message)


class LinuxInertLauncherArtifactUnavailable(LinuxInertLauncherArtifactError):
    """The host cannot provide the exact immutable executable-descriptor contract."""


class LinuxInertLauncherArtifactRejected(LinuxInertLauncherArtifactError):
    """The expectation or supplied artifact failed the fixed preflight contract."""


class LinuxInertLauncherArtifactLifecycleError(LinuxInertLauncherArtifactError):
    """Sealed-copy creation, retention, or handoff failed closed."""


class _ArtifactModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        allow_inf_nan=False,
        revalidate_instances="always",
        strict=True,
    )


@dataclass(frozen=True)
class _StatBinding:
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    nlink: int
    size: int
    mtime_ns: int
    ctime_ns: int

    @classmethod
    def from_stat(cls, metadata: os.stat_result) -> Self:
        return cls(
            device=metadata.st_dev,
            inode=metadata.st_ino,
            mode=metadata.st_mode,
            uid=metadata.st_uid,
            gid=metadata.st_gid,
            nlink=metadata.st_nlink,
            size=metadata.st_size,
            mtime_ns=metadata.st_mtime_ns,
            ctime_ns=metadata.st_ctime_ns,
        )


@dataclass(frozen=True)
class _ElfSegment:
    segment_type: int
    flags: int
    file_offset: int
    virtual_address: int
    file_size: int
    memory_size: int
    alignment: int

    @property
    def file_end(self) -> int:
        return self.file_offset + self.file_size

    @property
    def virtual_end(self) -> int:
        return self.virtual_address + self.memory_size


def _preflight_id(fields: dict[str, object]) -> str:
    if "preflight_id" in fields:
        raise ValueError("preflight identity input cannot contain its own digest")
    return sha256_bytes(PREFLIGHT_ID_DOMAIN + canonical_json_bytes(fields))


class LinuxInertLauncherArtifactPreflightReceipt(_ArtifactModel):
    """Evidence that fixed bytes were sealed and retained, never launch authority."""

    schema_version: Literal["bpe.linux-inert-launcher-artifact-preflight-receipt.v1"]
    status: Literal["artifact_preflighted_not_launched"]
    preflight_id: Sha256
    policy_id: StableId
    policy_sha256: Sha256
    worker_pool_audience: StableId
    worker_instance_id: StableId
    claim_ledger_id: StableId
    launch_ledger_id: StableId
    delegated_root_id: StableId
    launcher_artifact_id: StableId
    launcher_artifact_sha256: Sha256
    launcher_seccomp_policy_id: StableId
    launcher_seccomp_policy_sha256: Sha256
    host_platform: Literal["linux"]
    host_architecture: Literal["x86_64"]
    launcher_protocol_version: Literal["bpe.clone3-inert-launcher-protocol.v1"]
    launcher_launch_method: Literal["fixed-one-shot-executable-v1"]
    launcher_fd_layout: Literal["stdio-null-control-3-cgroup-4-v1"]
    launcher_argv_environment: Literal["argc-one-empty-environment-v1"]
    source_method: Literal["exact-caller-supplied-readable-fd-v1"]
    source_device: Annotated[int, Field(ge=0)]
    source_inode: Annotated[int, Field(ge=1)]
    source_mode: Annotated[int, Field(ge=0, le=0o177777)]
    source_uid: Annotated[int, Field(ge=0)]
    source_gid: Annotated[int, Field(ge=0)]
    source_nlink: Literal[1]
    source_size_bytes: Annotated[int, Field(ge=ELF_HEADER_SIZE, le=MAX_LAUNCHER_ARTIFACT_BYTES)]
    source_mtime_ns: Annotated[int, Field(ge=0)]
    source_ctime_ns: Annotated[int, Field(ge=0)]
    source_regular_file_verified: Literal[True]
    source_owner_trusted: Literal[True]
    source_not_group_other_writable: Literal[True]
    source_stable_during_read: Literal[True]
    artifact_digest_verified: Literal[True]
    elf_contract: Literal["elf64-le-x86_64-static-pie-v1"]
    elf_contract_verified: Literal[True]
    embedded_seccomp_markers_verified: Literal[True]
    sealed_copy_method: Literal["memfd-exec-complete-seals-procfd-readonly-v1"]
    sealed_copy_sha256: Sha256
    sealed_copy_size_bytes: Annotated[
        int,
        Field(ge=ELF_HEADER_SIZE, le=MAX_LAUNCHER_ARTIFACT_BYTES),
    ]
    sealed_copy_mode: Annotated[int, Field(ge=0, le=0o177777)]
    sealed_copy_nlink: Literal[0]
    sealed_copy_seals: Literal[63]
    sealed_copy_verified: Literal[True]
    executable_fd_retained_at_preflight: Literal[True]
    launch_attempt_consumed: Literal[False]
    launch_authorized: Literal[False]
    launcher_process_created: Literal[False]
    fixture_child_process_created: Literal[False]
    process_created: Literal[False]
    execution_started: Literal[False]
    authoritative: Literal[False]

    @field_validator(
        "source_regular_file_verified",
        "source_owner_trusted",
        "source_not_group_other_writable",
        "source_stable_during_read",
        "artifact_digest_verified",
        "elf_contract_verified",
        "embedded_seccomp_markers_verified",
        "sealed_copy_verified",
        "executable_fd_retained_at_preflight",
        mode="before",
    )
    @classmethod
    def verification_claims_must_be_boolean_true(cls, value: object) -> object:
        if value is not True:
            raise ValueError("artifact-preflight verification claims must be boolean true")
        return value

    @field_validator(
        "launch_attempt_consumed",
        "launch_authorized",
        "launcher_process_created",
        "fixture_child_process_created",
        "process_created",
        "execution_started",
        "authoritative",
        mode="before",
    )
    @classmethod
    def authority_nonclaims_must_be_boolean_false(cls, value: object) -> object:
        if value is not False:
            raise ValueError("artifact preflight cannot claim launch or execution authority")
        return value

    @model_validator(mode="after")
    def artifact_and_receipt_bindings_are_exact(self) -> Self:
        if not stat.S_ISREG(self.source_mode):
            raise ValueError("artifact preflight source mode is not regular")
        source_permissions = stat.S_IMODE(self.source_mode)
        if (
            not source_permissions & stat.S_IXUSR
            or source_permissions & (stat.S_IWGRP | stat.S_IWOTH)
            or source_permissions & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
        ):
            raise ValueError("artifact preflight source mode is unsafe")
        if self.launcher_seccomp_policy_id != FIXED_SECCOMP_POLICY_ID:
            raise ValueError("artifact preflight seccomp policy ID is not fixed")
        if self.launcher_seccomp_policy_sha256 != FIXED_SECCOMP_POLICY_SHA256:
            raise ValueError("artifact preflight seccomp policy digest is not fixed")
        if self.claim_ledger_id == self.launch_ledger_id:
            raise ValueError("artifact preflight ledger identities must be distinct")
        if (
            self.sealed_copy_sha256 != self.launcher_artifact_sha256
            or self.sealed_copy_size_bytes != self.source_size_bytes
            or self.sealed_copy_mode != SEALED_EXECUTABLE_MODE
            or self.sealed_copy_seals != REQUIRED_EXEC_SEALS
        ):
            raise ValueError("sealed launcher copy differs from the verified source")
        fields = self.model_dump(mode="python", exclude={"preflight_id"})
        if self.preflight_id != _preflight_id(fields):
            raise ValueError("artifact preflight identity is inconsistent")
        return self


def _require_linux_x86_64() -> None:
    if sys.platform != "linux":
        raise LinuxInertLauncherArtifactUnavailable(
            "unsupported_platform",
            "launcher artifact preflight requires Linux",
        )
    if (
        platform.machine() != "x86_64"
        or ctypes.sizeof(ctypes.c_void_p) != 8
        or ctypes.sizeof(ctypes.c_long) != 8
    ):
        raise LinuxInertLauncherArtifactUnavailable(
            "unsupported_architecture",
            "launcher artifact preflight requires the pinned x86_64 ABI",
        )
    required_os_members = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "pread")
    if (
        any(not hasattr(os, member) for member in required_os_members)
        or not hasattr(fcntl, "F_DUPFD_CLOEXEC")
    ):
        raise LinuxInertLauncherArtifactUnavailable(
            "unsupported_architecture",
            "required Linux descriptor operations are unavailable",
        )


def _load_libc() -> Any:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.syscall.restype = ctypes.c_long
    except (AttributeError, OSError) as exc:
        raise LinuxInertLauncherArtifactUnavailable(
            "memfd_unavailable",
            "the Linux syscall interface is unavailable",
        ) from exc
    return libc


def _normalize_expectation(
    expectation: InertFixtureLaunchExpectation,
) -> InertFixtureLaunchExpectation:
    if type(expectation) is not InertFixtureLaunchExpectation:
        raise LinuxInertLauncherArtifactRejected(
            "invalid_expectation",
            "artifact preflight requires the complete launch expectation",
        )
    try:
        frozen = inert_fixture_launch_expectation_for(
            expectation.intent_expectation,
            expected_launch_ledger_path=expectation.launch_ledger_path,
            expected_worker_instance_id=expectation.worker_instance_id,
            expected_claim_ledger_id=expectation.claim_ledger_id,
            expected_launch_ledger_id=expectation.launch_ledger_id,
        )
    except (
        AttributeError,
        InertFixtureLaunchExpectationError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        raise LinuxInertLauncherArtifactRejected(
            "invalid_expectation",
            "the configured launch expectation is invalid",
        ) from exc
    if frozen != expectation:
        raise LinuxInertLauncherArtifactRejected(
            "invalid_expectation",
            "the configured launch expectation is not exact",
        )
    intent_expectation = frozen.intent_expectation
    if (
        intent_expectation.launcher_seccomp_policy_id != FIXED_SECCOMP_POLICY_ID
        or intent_expectation.launcher_seccomp_policy_sha256
        != FIXED_SECCOMP_POLICY_SHA256
    ):
        raise LinuxInertLauncherArtifactRejected(
            "seccomp_identity_mismatch",
            "the configured launcher seccomp identity is not the fixed native policy",
        )
    return frozen


def _raise_descriptor_failure(exc: OSError, *, sealed: bool = False) -> NoReturn:
    if exc.errno in {errno.EMFILE, errno.ENFILE, errno.ENOMEM, errno.ENOSPC}:
        raise LinuxInertLauncherArtifactLifecycleError(
            "resource_exhausted",
            "worker resources were exhausted during artifact preflight",
        ) from exc
    if sealed:
        raise LinuxInertLauncherArtifactLifecycleError(
            "sealed_artifact_changed",
            "the sealed launcher descriptor became unavailable",
        ) from exc
    raise LinuxInertLauncherArtifactRejected(
        "invalid_source_descriptor",
        "the launcher source descriptor is invalid",
    ) from exc


def _source_binding(metadata: os.stat_result, flags: int, inheritable: bool) -> _StatBinding:
    binding = _StatBinding.from_stat(metadata)
    permissions = stat.S_IMODE(binding.mode)
    if (
        not stat.S_ISREG(binding.mode)
        or binding.uid not in {0, os.geteuid()}
        or binding.nlink != 1
        or binding.inode < 1
        or binding.device < 0
        or binding.size < ELF_HEADER_SIZE
        or binding.mtime_ns < 0
        or binding.ctime_ns < 0
        or not permissions & stat.S_IXUSR
        or permissions & (stat.S_IWGRP | stat.S_IWOTH)
        or permissions & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
        or flags & os.O_ACCMODE != os.O_RDONLY
        or flags & O_PATH_LINUX
        or inheritable
    ):
        raise LinuxInertLauncherArtifactRejected(
            "unsafe_source_artifact",
            "the launcher source descriptor is not a trusted executable regular file",
        )
    if binding.size > MAX_LAUNCHER_ARTIFACT_BYTES:
        raise LinuxInertLauncherArtifactRejected(
            "artifact_too_large",
            "the launcher artifact exceeds the fixed byte limit",
        )
    return binding


def _duplicate_source_fd(descriptor: int) -> tuple[int, _StatBinding]:
    if (
        type(descriptor) is not int
        or descriptor < 0
        or descriptor > MAX_LINUX_DESCRIPTOR
    ):
        raise LinuxInertLauncherArtifactRejected(
            "invalid_source_descriptor",
            "the launcher source descriptor is invalid",
        )
    duplicate = -1
    try:
        duplicate = fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, 3)
        metadata = os.fstat(duplicate)
        flags = fcntl.fcntl(duplicate, fcntl.F_GETFL)
        binding = _source_binding(metadata, flags, os.get_inheritable(duplicate))
        return duplicate, binding
    except LinuxInertLauncherArtifactError:
        raise
    except OSError as exc:
        _raise_descriptor_failure(exc)
    finally:
        if duplicate >= 0 and sys.exception() is not None:
            with suppress(OSError):
                os.close(duplicate)


def _read_stable_source(descriptor: int, initial: _StatBinding) -> bytes:
    chunks: list[bytes] = []
    offset = 0
    try:
        initial_flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        initial_inheritable = os.get_inheritable(descriptor)
        try:
            observed_initial = _source_binding(
                os.fstat(descriptor),
                initial_flags,
                initial_inheritable,
            )
        except LinuxInertLauncherArtifactRejected as exc:
            raise LinuxInertLauncherArtifactRejected(
                "source_changed",
                "the launcher artifact changed before it could be read",
            ) from exc
        if observed_initial != initial:
            raise LinuxInertLauncherArtifactRejected(
                "source_changed",
                "the launcher artifact changed before it could be read",
            )
        while offset < initial.size:
            requested = min(ARTIFACT_READ_CHUNK_BYTES, initial.size - offset)
            chunk = os.pread(descriptor, requested, offset)
            if not chunk:
                raise LinuxInertLauncherArtifactRejected(
                    "source_changed",
                    "the launcher artifact changed while it was read",
                )
            chunks.append(chunk)
            offset += len(chunk)
        if os.pread(descriptor, 1, initial.size):
            raise LinuxInertLauncherArtifactRejected(
                "source_changed",
                "the launcher artifact changed while it was read",
            )
        final_metadata = os.fstat(descriptor)
        final_flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        final_inheritable = os.get_inheritable(descriptor)
        try:
            final = _source_binding(
                final_metadata,
                final_flags,
                final_inheritable,
            )
        except LinuxInertLauncherArtifactRejected as exc:
            raise LinuxInertLauncherArtifactRejected(
                "source_changed",
                "the launcher artifact metadata or flags changed while it was read",
            ) from exc
    except LinuxInertLauncherArtifactError:
        raise
    except OSError as exc:
        if exc.errno in {errno.EMFILE, errno.ENFILE, errno.ENOMEM, errno.ENOSPC}:
            raise LinuxInertLauncherArtifactLifecycleError(
                "resource_exhausted",
                "worker resources were exhausted while reading the launcher",
            ) from exc
        raise LinuxInertLauncherArtifactLifecycleError(
            "io_failure",
            "the launcher artifact could not be read",
        ) from exc
    if (
        final != initial
        or final_flags != initial_flags
        or final_inheritable != initial_inheritable
    ):
        raise LinuxInertLauncherArtifactRejected(
            "source_changed",
            "the launcher artifact metadata changed while it was read",
        )
    content = b"".join(chunks)
    if len(content) != initial.size:
        raise LinuxInertLauncherArtifactRejected(
            "source_changed",
            "the launcher artifact size changed while it was read",
        )
    return content


def _validate_elf64_static_pie(content: bytes) -> None:
    def reject() -> NoReturn:
        raise LinuxInertLauncherArtifactRejected(
            "invalid_elf",
            "the launcher artifact is not the fixed ELF64 static-PIE shape",
        )

    if len(content) < ELF_HEADER_SIZE:
        reject()
    if (
        content[:4] != b"\x7fELF"
        or content[4] != ELFCLASS64
        or content[5] != ELFDATA2LSB
        or content[6] != 1
        or content[7] != ELFOSABI_LINUX
        or content[8] != 0
        or any(content[9:16])
    ):
        reject()
    try:
        (
            elf_type,
            machine,
            version,
            entry,
            program_offset,
            _section_offset,
            flags,
            header_size,
            program_entry_size,
            program_count,
            _section_entry_size,
            _section_count,
            _section_names,
        ) = struct.unpack_from("<HHIQQQIHHHHHH", content, 16)
    except struct.error:
        reject()
    if (
        elf_type != ET_DYN
        or machine != EM_X86_64
        or version != 1
        or entry == 0
        or flags != 0
        or header_size != ELF_HEADER_SIZE
        or program_offset != ELF_HEADER_SIZE
        or program_entry_size != ELF_PROGRAM_HEADER_SIZE
        or not 1 <= program_count <= 128
        or program_offset + program_count * program_entry_size > len(content)
    ):
        reject()

    load_segments: list[_ElfSegment] = []
    dynamic_segment: _ElfSegment | None = None
    stack_segment: _ElfSegment | None = None
    relro_segment: _ElfSegment | None = None
    for index in range(program_count):
        offset = program_offset + index * program_entry_size
        try:
            (
                segment_type,
                segment_flags,
                file_offset,
                virtual_address,
                _physical_address,
                file_size,
                memory_size,
                alignment,
            ) = struct.unpack_from("<IIQQQQQQ", content, offset)
        except struct.error:
            reject()
        if segment_type != PT_NULL and (
            segment_flags & ~(PF_R | PF_W | PF_X)
            or file_size > memory_size
            or file_offset > len(content)
            or file_size > len(content) - file_offset
            or memory_size > UINT64_MAX - virtual_address
            or (alignment not in {0, 1} and alignment & (alignment - 1))
            or (
                alignment not in {0, 1}
                and file_offset % alignment != virtual_address % alignment
            )
        ):
            reject()
        segment = _ElfSegment(
            segment_type=segment_type,
            flags=segment_flags,
            file_offset=file_offset,
            virtual_address=virtual_address,
            file_size=file_size,
            memory_size=memory_size,
            alignment=alignment,
        )
        if segment_type == PT_INTERP:
            reject()
        if segment_type == PT_LOAD:
            if (
                not segment_flags & PF_R
                or (segment_flags & PF_W and segment_flags & PF_X)
                or file_size == 0
                or memory_size == 0
            ):
                reject()
            if load_segments:
                previous = load_segments[-1]
                if (
                    file_offset < previous.file_end
                    or virtual_address < previous.virtual_end
                ):
                    reject()
            load_segments.append(segment)
        elif segment_type == PT_DYNAMIC:
            if (
                dynamic_segment is not None
                or segment_flags != PF_R | PF_W
                or file_size == 0
                or file_size != memory_size
                or file_size % 16
            ):
                reject()
            dynamic_segment = segment
        elif segment_type == PT_GNU_STACK:
            if stack_segment is not None or segment_flags != PF_R | PF_W:
                reject()
            stack_segment = segment
        elif segment_type == PT_GNU_RELRO:
            if (
                relro_segment is not None
                or segment_flags != PF_R
                or file_size == 0
                or file_size != memory_size
            ):
                reject()
            relro_segment = segment

    if (
        not load_segments
        or dynamic_segment is None
        or stack_segment is None
        or relro_segment is None
    ):
        reject()

    program_table_end = program_offset + program_count * program_entry_size
    if not any(
        segment.file_offset == 0 and segment.file_end >= program_table_end
        for segment in load_segments
    ):
        reject()

    if not any(
        segment.flags & PF_X
        and segment.virtual_address <= entry
        and entry < segment.virtual_address + segment.file_size
        for segment in load_segments
    ):
        reject()

    def is_exactly_mapped(segment: _ElfSegment) -> bool:
        return any(
            load.file_offset <= segment.file_offset
            and segment.file_end <= load.file_end
            and load.virtual_address <= segment.virtual_address
            and segment.virtual_end <= load.virtual_end
            and segment.file_offset - load.file_offset
            == segment.virtual_address - load.virtual_address
            and not segment.flags & ~load.flags
            for load in load_segments
        )

    if not is_exactly_mapped(dynamic_segment) or not is_exactly_mapped(
        relro_segment
    ):
        reject()

    saw_dynamic_null = False
    saw_bind_now = False
    saw_pie_now = False
    for offset in range(
        dynamic_segment.file_offset,
        dynamic_segment.file_end,
        16,
    ):
        try:
            tag, value = struct.unpack_from("<qQ", content, offset)
        except struct.error:
            reject()
        if tag in {DT_NEEDED, DT_RPATH, DT_RUNPATH}:
            reject()
        if tag == DT_FLAGS:
            if saw_bind_now or value & DF_BIND_NOW != DF_BIND_NOW:
                reject()
            saw_bind_now = True
        elif tag == DT_FLAGS_1:
            required_flags = DF_1_NOW | DF_1_PIE
            if saw_pie_now or value & required_flags != required_flags:
                reject()
            saw_pie_now = True
        if tag == DT_NULL:
            saw_dynamic_null = True
            break
    if not (saw_dynamic_null and saw_bind_now and saw_pie_now):
        reject()


def _require_embedded_seccomp_identity(
    content: bytes,
    *,
    policy_id: str,
    policy_sha256: str,
) -> None:
    try:
        id_marker = policy_id.encode("ascii") + b"\x00"
        digest_marker = policy_sha256.encode("ascii") + b"\x00"
    except UnicodeEncodeError as exc:
        raise LinuxInertLauncherArtifactRejected(
            "seccomp_identity_mismatch",
            "the launcher seccomp identity is not canonical ASCII",
        ) from exc
    id_offset = content.find(id_marker)
    digest_offset = content.find(digest_marker)
    if (
        id_offset < 0
        or digest_offset < 0
        or content.find(id_marker, id_offset + 1) >= 0
        or content.find(digest_marker, digest_offset + 1) >= 0
    ):
        raise LinuxInertLauncherArtifactRejected(
            "seccomp_identity_mismatch",
            "the launcher does not uniquely embed the fixed seccomp identity",
        )
    loaded_ranges: list[tuple[int, int]] = []
    try:
        program_offset = struct.unpack_from("<Q", content, 32)[0]
        program_entry_size = struct.unpack_from("<H", content, 54)[0]
        program_count = struct.unpack_from("<H", content, 56)[0]
        for index in range(program_count):
            offset = program_offset + index * program_entry_size
            segment_type, _flags, file_offset = struct.unpack_from("<IIQ", content, offset)
            file_size = struct.unpack_from("<Q", content, offset + 32)[0]
            if segment_type == PT_LOAD:
                loaded_ranges.append((file_offset, file_offset + file_size))
    except (IndexError, struct.error) as exc:
        raise LinuxInertLauncherArtifactRejected(
            "seccomp_identity_mismatch",
            "the launcher seccomp identity cannot be located in loaded bytes",
        ) from exc
    if not all(
        any(
            start <= marker_offset and marker_offset + marker_size <= end
            for start, end in loaded_ranges
        )
        for marker_offset, marker_size in (
            (id_offset, len(id_marker)),
            (digest_offset, len(digest_marker)),
        )
    ):
        raise LinuxInertLauncherArtifactRejected(
            "seccomp_identity_mismatch",
            "the fixed launcher seccomp identity is not in a loadable segment",
        )


def _memfd_create(libc: Any) -> int:
    ctypes.set_errno(0)
    result = libc.syscall(
        ctypes.c_long(MEMFD_CREATE_SYSCALL_X86_64),
        ctypes.c_char_p(b"bpe-inert-fixture-launcher"),
        ctypes.c_uint(MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_EXEC),
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
    exc = OSError(error, os.strerror(error))
    if error in {errno.ENOSYS, errno.EINVAL, errno.EPERM, errno.EACCES}:
        raise LinuxInertLauncherArtifactUnavailable(
            "memfd_unavailable",
            "executable sealing-enabled memfd creation is unavailable",
        ) from exc
    _raise_descriptor_failure(exc, sealed=True)


def _open_trusted_procfd(libc: Any) -> int:
    descriptor = -1
    try:
        descriptor = os.open(
            "/proc/self/fd",
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode) or os.get_inheritable(descriptor):
            raise OSError(errno.ENOTDIR, "procfd is not a non-inheritable directory")
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
        return descriptor
    except (AttributeError, OSError) as exc:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        if isinstance(exc, OSError) and exc.errno in {
            errno.EMFILE,
            errno.ENFILE,
            errno.ENOMEM,
            errno.ENOSPC,
        }:
            _raise_descriptor_failure(exc)
        raise LinuxInertLauncherArtifactUnavailable(
            "trusted_procfs_unavailable",
            "trusted procfs descriptor reopening is unavailable",
        ) from exc


def _hash_descriptor(descriptor: int, size: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        chunk = os.pread(descriptor, min(ARTIFACT_READ_CHUNK_BYTES, size - offset), offset)
        if not chunk:
            raise OSError(errno.EIO, "short sealed artifact read")
        digest.update(chunk)
        offset += len(chunk)
    if os.pread(descriptor, 1, size):
        raise OSError(errno.EIO, "sealed artifact grew")
    return digest.hexdigest()


def _validate_sealed_exec_fd(
    descriptor: int,
    expected: _StatBinding,
    expected_sha256: str,
    *,
    rehash: bool,
) -> None:
    try:
        metadata = os.fstat(descriptor)
        binding = _StatBinding.from_stat(metadata)
        flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        seals = fcntl.fcntl(descriptor, F_GET_SEALS_LINUX)
        if (
            binding != expected
            or binding.mode != SEALED_EXECUTABLE_MODE
            or binding.nlink != 0
            or flags & os.O_ACCMODE != os.O_RDONLY
            or flags & O_PATH_LINUX
            or os.get_inheritable(descriptor)
            or seals != REQUIRED_EXEC_SEALS
            or (rehash and _hash_descriptor(descriptor, binding.size) != expected_sha256)
        ):
            raise OSError(errno.EPERM, "sealed launcher descriptor changed")
    except OSError as exc:
        _raise_descriptor_failure(exc, sealed=True)


def _create_sealed_exec_copy(
    libc: Any,
    content: bytes,
    expected_sha256: str,
) -> tuple[int, _StatBinding]:
    writable_fd = -1
    procfd = -1
    exec_fd = -1
    try:
        writable_fd = _memfd_create(libc)
        view = memoryview(content)
        written = 0
        while written < len(view):
            count = os.write(writable_fd, view[written:])
            if count <= 0:
                raise OSError(errno.EIO, "short memfd write")
            written += count
        os.fchmod(writable_fd, 0o500)
        os.fsync(writable_fd)
        try:
            fcntl.fcntl(writable_fd, F_ADD_SEALS_LINUX, REQUIRED_EXEC_SEALS)
            seals = fcntl.fcntl(writable_fd, F_GET_SEALS_LINUX)
        except OSError as exc:
            if exc.errno in {
                errno.EINVAL,
                errno.ENOTTY,
                errno.EOPNOTSUPP,
                errno.EPERM,
            }:
                raise LinuxInertLauncherArtifactUnavailable(
                    "sealing_unavailable",
                    "the complete executable memfd seal contract is unavailable",
                ) from exc
            _raise_descriptor_failure(exc, sealed=True)
        if seals != REQUIRED_EXEC_SEALS:
            raise LinuxInertLauncherArtifactUnavailable(
                "sealing_unavailable",
                "the complete executable memfd seal contract is unavailable",
            )

        procfd = _open_trusted_procfd(libc)
        exec_fd = os.open(
            str(writable_fd),
            os.O_RDONLY | os.O_CLOEXEC,
            dir_fd=procfd,
        )
        os.set_inheritable(exec_fd, False)
        writable_metadata = os.fstat(writable_fd)
        exec_metadata = os.fstat(exec_fd)
        if (
            (exec_metadata.st_dev, exec_metadata.st_ino)
            != (writable_metadata.st_dev, writable_metadata.st_ino)
            or not stat.S_ISREG(exec_metadata.st_mode)
            or stat.S_IMODE(exec_metadata.st_mode) != 0o500
            or exec_metadata.st_nlink != 0
            or exec_metadata.st_size != len(content)
        ):
            raise OSError(errno.EPERM, "read-only memfd reopen changed identity")

        closing_writable_fd = writable_fd
        writable_fd = -1
        os.close(closing_writable_fd)
        binding = _StatBinding.from_stat(os.fstat(exec_fd))
        _validate_sealed_exec_fd(
            exec_fd,
            binding,
            expected_sha256,
            rehash=True,
        )
        retained = exec_fd
        exec_fd = -1
        return retained, binding
    except LinuxInertLauncherArtifactError:
        raise
    except OSError as exc:
        _raise_descriptor_failure(exc, sealed=True)
    finally:
        for descriptor in (exec_fd, procfd, writable_fd):
            if descriptor >= 0:
                with suppress(OSError):
                    os.close(descriptor)


def _build_receipt(
    expectation: InertFixtureLaunchExpectation,
    source: _StatBinding,
    sealed: _StatBinding,
) -> LinuxInertLauncherArtifactPreflightReceipt:
    intent_expectation = expectation.intent_expectation
    fields: dict[str, object] = {
        "schema_version": "bpe.linux-inert-launcher-artifact-preflight-receipt.v1",
        "status": "artifact_preflighted_not_launched",
        "policy_id": intent_expectation.policy_id,
        "policy_sha256": intent_expectation.policy_sha256,
        "worker_pool_audience": intent_expectation.worker_pool_audience,
        "worker_instance_id": intent_expectation.worker_instance_id,
        "claim_ledger_id": intent_expectation.claim_ledger_id,
        "launch_ledger_id": intent_expectation.launch_ledger_id,
        "delegated_root_id": intent_expectation.delegated_root_id,
        "launcher_artifact_id": intent_expectation.launcher_artifact_id,
        "launcher_artifact_sha256": intent_expectation.launcher_artifact_sha256,
        "launcher_seccomp_policy_id": intent_expectation.launcher_seccomp_policy_id,
        "launcher_seccomp_policy_sha256": (
            intent_expectation.launcher_seccomp_policy_sha256
        ),
        "host_platform": "linux",
        "host_architecture": "x86_64",
        "launcher_protocol_version": intent_expectation.launcher_protocol_version,
        "launcher_launch_method": intent_expectation.launcher_launch_method,
        "launcher_fd_layout": intent_expectation.policy.launcher_fd_layout,
        "launcher_argv_environment": (
            intent_expectation.policy.launcher_argv_environment
        ),
        "source_method": "exact-caller-supplied-readable-fd-v1",
        "source_device": source.device,
        "source_inode": source.inode,
        "source_mode": source.mode,
        "source_uid": source.uid,
        "source_gid": source.gid,
        "source_nlink": source.nlink,
        "source_size_bytes": source.size,
        "source_mtime_ns": source.mtime_ns,
        "source_ctime_ns": source.ctime_ns,
        "source_regular_file_verified": True,
        "source_owner_trusted": True,
        "source_not_group_other_writable": True,
        "source_stable_during_read": True,
        "artifact_digest_verified": True,
        "elf_contract": "elf64-le-x86_64-static-pie-v1",
        "elf_contract_verified": True,
        "embedded_seccomp_markers_verified": True,
        "sealed_copy_method": "memfd-exec-complete-seals-procfd-readonly-v1",
        "sealed_copy_sha256": intent_expectation.launcher_artifact_sha256,
        "sealed_copy_size_bytes": sealed.size,
        "sealed_copy_mode": sealed.mode,
        "sealed_copy_nlink": sealed.nlink,
        "sealed_copy_seals": REQUIRED_EXEC_SEALS,
        "sealed_copy_verified": True,
        "executable_fd_retained_at_preflight": True,
        "launch_attempt_consumed": False,
        "launch_authorized": False,
        "launcher_process_created": False,
        "fixture_child_process_created": False,
        "process_created": False,
        "execution_started": False,
        "authoritative": False,
    }
    try:
        return LinuxInertLauncherArtifactPreflightReceipt.model_validate(
            {**fields, "preflight_id": _preflight_id(fields)},
            strict=True,
        )
    except ValueError as exc:
        raise LinuxInertLauncherArtifactLifecycleError(
            "io_failure",
            "verified launcher metadata could not form a preflight receipt",
        ) from exc


class LinuxInertLauncherArtifact:
    """Opaque owner of one sealed read-only launcher descriptor."""

    __slots__ = ("_binding", "_exec_fd", "_lock", "_receipt")

    _binding: _StatBinding
    _exec_fd: int
    _lock: threading.Lock
    _receipt: LinuxInertLauncherArtifactPreflightReceipt

    def __init__(self) -> None:
        raise TypeError("sealed launcher artifacts must be created by the preflight API")

    @property
    def receipt(self) -> LinuxInertLauncherArtifactPreflightReceipt:
        return self._receipt

    @classmethod
    def _create(
        cls,
        *,
        receipt: LinuxInertLauncherArtifactPreflightReceipt,
        descriptor: int,
        binding: _StatBinding,
    ) -> Self:
        artifact = cls.__new__(cls)
        artifact._receipt = receipt
        artifact._exec_fd = descriptor
        artifact._binding = binding
        artifact._lock = threading.Lock()
        return artifact

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._exec_fd < 0

    def duplicate_executable_fd(self) -> int:
        """Revalidate and return a caller-owned CLOEXEC fd for later execveat."""

        with self._lock:
            if self._exec_fd < 0:
                raise LinuxInertLauncherArtifactLifecycleError(
                    "sealed_artifact_closed",
                    "the sealed launcher artifact is closed",
                )
            _validate_sealed_exec_fd(
                self._exec_fd,
                self._binding,
                self.receipt.launcher_artifact_sha256,
                rehash=False,
            )
            descriptor = -1
            try:
                descriptor = fcntl.fcntl(
                    self._exec_fd,
                    fcntl.F_DUPFD_CLOEXEC,
                    3,
                )
                _validate_sealed_exec_fd(
                    descriptor,
                    self._binding,
                    self.receipt.launcher_artifact_sha256,
                    rehash=False,
                )
                retained = descriptor
                descriptor = -1
                return retained
            except LinuxInertLauncherArtifactError:
                raise
            except OSError as exc:
                _raise_descriptor_failure(exc, sealed=True)
            finally:
                if descriptor >= 0:
                    with suppress(OSError):
                        os.close(descriptor)

    def close(self) -> None:
        with self._lock:
            if self._exec_fd >= 0:
                descriptor = self._exec_fd
                self._exec_fd = -1
                try:
                    os.close(descriptor)
                except OSError as exc:
                    raise LinuxInertLauncherArtifactLifecycleError(
                        "sealed_artifact_changed",
                        "the sealed launcher descriptor could not be closed",
                    ) from exc

    def __enter__(self) -> Self:
        if self.closed:
            raise LinuxInertLauncherArtifactLifecycleError(
                "sealed_artifact_closed",
                "the sealed launcher artifact is closed",
            )
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __del__(self) -> None:
        """Best-effort leak containment; callers still must close deterministically."""

        descriptor = getattr(self, "_exec_fd", -1)
        if descriptor >= 0:
            self._exec_fd = -1
            with suppress(OSError):
                os.close(descriptor)


def preflight_inert_launcher_artifact(
    expectation: InertFixtureLaunchExpectation,
    *,
    launcher_artifact_fd: int,
) -> LinuxInertLauncherArtifact:
    """Authenticate, seal, and retain the fixed launcher without starting a process."""

    source_fd = -1
    sealed_fd = -1
    try:
        _require_linux_x86_64()
        frozen_expectation = _normalize_expectation(expectation)
        libc = _load_libc()
        source_fd, source_binding = _duplicate_source_fd(launcher_artifact_fd)
        content = _read_stable_source(source_fd, source_binding)
        expected_sha256 = frozen_expectation.intent_expectation.launcher_artifact_sha256
        if hashlib.sha256(content).hexdigest() != expected_sha256:
            raise LinuxInertLauncherArtifactRejected(
                "artifact_digest_mismatch",
                "the launcher artifact digest differs from its trusted expectation",
            )
        _validate_elf64_static_pie(content)
        _require_embedded_seccomp_identity(
            content,
            policy_id=(
                frozen_expectation.intent_expectation.launcher_seccomp_policy_id
            ),
            policy_sha256=(
                frozen_expectation.intent_expectation.launcher_seccomp_policy_sha256
            ),
        )
        sealed_fd, sealed_binding = _create_sealed_exec_copy(
            libc,
            content,
            expected_sha256,
        )
        receipt = _build_receipt(
            frozen_expectation,
            source_binding,
            sealed_binding,
        )
        result = LinuxInertLauncherArtifact._create(
            receipt=receipt,
            descriptor=sealed_fd,
            binding=sealed_binding,
        )
        sealed_fd = -1
        return result
    except MemoryError as exc:
        raise LinuxInertLauncherArtifactLifecycleError(
            "resource_exhausted",
            "worker memory was exhausted during launcher artifact preflight",
        ) from exc
    finally:
        if sealed_fd >= 0:
            with suppress(OSError):
                os.close(sealed_fd)
        if source_fd >= 0:
            with suppress(OSError):
                os.close(source_fd)


JSON_SCHEMAS: dict[str, type[BaseModel]] = {
    "linux-inert-launcher-artifact-preflight-receipt-v1.json": (
        LinuxInertLauncherArtifactPreflightReceipt
    ),
}


__all__ = [
    "FIXED_SECCOMP_POLICY_ID",
    "FIXED_SECCOMP_POLICY_SHA256",
    "JSON_SCHEMAS",
    "MAX_LAUNCHER_ARTIFACT_BYTES",
    "PREFLIGHT_ID_DOMAIN",
    "LinuxInertLauncherArtifact",
    "LinuxInertLauncherArtifactError",
    "LinuxInertLauncherArtifactLifecycleError",
    "LinuxInertLauncherArtifactPreflightReceipt",
    "LinuxInertLauncherArtifactRejected",
    "LinuxInertLauncherArtifactUnavailable",
    "preflight_inert_launcher_artifact",
]
