"""Pure parser for the fixed, one-way inert-fixture native transcript.

The parser is deliberately process-free.  It accepts only bounded records already
received from a ``SOCK_SEQPACKET`` socket and validates the complete launcher
transcript plus process exit code.  A parsed transcript is local diagnostic
evidence; it is neither signed nor authorizing.
"""

from __future__ import annotations

import struct
from collections.abc import Sequence
from dataclasses import dataclass
from enum import IntEnum, IntFlag

PROTOCOL_MAGIC = b"BPEIFX1\x00"
PROTOCOL_VERSION = 1
PROTOCOL_FRAME_SIZE = 64
PROTOCOL_PAYLOAD_SIZE = 40
PROTOCOL_MAX_FRAMES = 8
PROTOCOL_MAX_ERRNO = 4095

# Linux's maximum pid_max is 2^22, and pid_max itself is the wrap point rather
# than an allocatable PID.
LINUX_MAX_PID = (1 << 22) - 1
CLONE_PIDFD = 0x00001000
CLONE_INTO_CGROUP = 0x200000000
REQUIRED_CLONE_FLAGS = CLONE_PIDFD | CLONE_INTO_CGROUP
CLD_KILLED = 2
CLD_STOPPED = 5
SIGKILL = 9
SIGSTOP = 19

_FRAME_STRUCT = struct.Struct(">8sHHIQIIIIQQ8s")
if _FRAME_STRUCT.size != PROTOCOL_FRAME_SIZE:  # pragma: no cover - import invariant
    raise RuntimeError("inert native frame layout has an invalid size")


class NativeFrameType(IntEnum):
    HELLO = 1
    CHILD_READY = 2
    CHILD_SIGNALED = 3
    CHILD_OBSERVED = 4
    FINAL = 5
    ERROR = 6


class NativeStatus(IntEnum):
    OK = 0
    FAILED = 1


class NativeStage(IntEnum):
    STARTUP = 1
    DESCRIPTOR_VALIDATION = 2
    CGROUP_VALIDATION = 3
    FIXTURE_SETUP = 4
    CLONE3 = 5
    CHILD_READY = 6
    PIDFD_SIGNAL = 7
    CGROUP_KILL = 8
    CHILD_OBSERVATION = 9
    CHILD_REAP = 10
    CLEANUP = 11
    PROTOCOL = 12


class NativeReason(IntEnum):
    NONE = 0
    BAD_ARGC = 1
    BAD_ARGV = 2
    NONEMPTY_ENVIRONMENT = 3
    BAD_DESCRIPTOR_LAYOUT = 4
    BAD_STDIO = 5
    BAD_CONTROL_SOCKET = 6
    BAD_CGROUP_DESCRIPTOR = 7
    CGROUP_NOT_EMPTY = 8
    PROTOCOL_INPUT = 9
    PEER_CLOSED = 10
    RESOURCE_EXHAUSTED = 11
    CLONE3_UNAVAILABLE = 12
    CLONE3_REJECTED = 13
    PIDFD_UNAVAILABLE = 14
    CHILD_SETUP_FAILED = 15
    PIDFD_SIGNAL_FAILED = 16
    CGROUP_KILL_FAILED = 17
    CHILD_OBSERVATION_FAILED = 18
    CHILD_REAP_FAILED = 19
    TIMEOUT = 20
    CLEANUP_INCOMPLETE = 21
    IO_FAILURE = 22
    INTERNAL = 23


class NativeExitCode(IntEnum):
    OK = 0
    STARTUP = 64
    PROTOCOL = 65
    KERNEL = 66
    TIMEOUT = 67
    CLEANUP = 68
    INTERNAL = 69


class NativeResultFlag(IntFlag):
    CLONE3_INTO_CGROUP = 1 << 0
    PIDFD_CREATED = 1 << 1
    PIDFD_STOP_SENT = 1 << 2
    PIDFD_STOP_OBSERVED = 1 << 3
    LIVE_CGROUP_KILL = 1 << 4
    PIDFD_EXIT_OBSERVED = 1 << 5
    CHILD_REAPED = 1 << 6
    CGROUP_EMPTY = 1 << 7
    BUILTIN_NOEXEC = 1 << 8


ACHIEVED_RESULT_MASK = int(
    NativeResultFlag.CLONE3_INTO_CGROUP
    | NativeResultFlag.PIDFD_CREATED
    | NativeResultFlag.PIDFD_STOP_SENT
    | NativeResultFlag.PIDFD_STOP_OBSERVED
    | NativeResultFlag.LIVE_CGROUP_KILL
    | NativeResultFlag.PIDFD_EXIT_OBSERVED
    | NativeResultFlag.CHILD_REAPED
    | NativeResultFlag.CGROUP_EMPTY
    | NativeResultFlag.BUILTIN_NOEXEC
)


class InertNativeProtocolViolation(ValueError):
    """A native record, transcript, or exit status violated the fixed protocol."""


@dataclass(frozen=True, slots=True)
class InertNativeSocketRecord:
    """One bounded ``recvmsg`` result and its trust-relevant metadata."""

    payload: bytes
    message_truncated: bool = False
    control_truncated: bool = False
    ancillary_present: bool = False


@dataclass(frozen=True, slots=True)
class InertNativeFrame:
    frame_type: NativeFrameType
    sequence: int
    status: NativeStatus
    stage: NativeStage
    reason: NativeReason
    system_errno: int
    value0: int
    value1: int


@dataclass(frozen=True, slots=True)
class InertNativeTranscript:
    """A completely validated but unsigned and nonauthoritative transcript."""

    succeeded: bool
    frames: tuple[InertNativeFrame, ...]
    launcher_exit_code: NativeExitCode
    launcher_pid: int
    child_pid: int | None
    achieved_result_mask: int
    elapsed_ns: int | None
    failure_stage: NativeStage | None
    failure_reason: NativeReason | None
    failure_errno: int | None


_SUCCESS_TYPES = (
    NativeFrameType.HELLO,
    NativeFrameType.CHILD_READY,
    NativeFrameType.CHILD_SIGNALED,
    NativeFrameType.CHILD_OBSERVED,
    NativeFrameType.FINAL,
)
_SUCCESS_STAGES = (
    NativeStage.STARTUP,
    NativeStage.CHILD_READY,
    NativeStage.PIDFD_SIGNAL,
    NativeStage.CHILD_OBSERVATION,
    NativeStage.CLEANUP,
)
def _masks(*values: int) -> frozenset[int]:
    return frozenset(values)


# Exact ERROR states reachable from launcher.c.  The key is the number of already
# emitted success frames plus the terminal reason/stage; the value is the complete
# set of masks possible after bounded emergency cleanup.  This intentionally rejects
# merely plausible combinations: a transcript is evidence only when it matches the
# compiled state machine, including cleanup-added REAPED/EMPTY bits.
_ERROR_GRAMMAR: dict[
    tuple[int, NativeReason, NativeStage], frozenset[int]
] = {
    (0, NativeReason.BAD_DESCRIPTOR_LAYOUT, NativeStage.DESCRIPTOR_VALIDATION): _masks(
        0x000
    ),
    (0, NativeReason.BAD_CGROUP_DESCRIPTOR, NativeStage.DESCRIPTOR_VALIDATION): _masks(
        0x000
    ),
    (0, NativeReason.BAD_CGROUP_DESCRIPTOR, NativeStage.CGROUP_VALIDATION): _masks(
        0x000
    ),
    (0, NativeReason.CGROUP_NOT_EMPTY, NativeStage.CGROUP_VALIDATION): _masks(0x000),
    (0, NativeReason.INTERNAL, NativeStage.STARTUP): _masks(0x000),
    (0, NativeReason.IO_FAILURE, NativeStage.PROTOCOL): _masks(0x000),
    (0, NativeReason.CLEANUP_INCOMPLETE, NativeStage.CLEANUP): _masks(0x000),
    (1, NativeReason.INTERNAL, NativeStage.FIXTURE_SETUP): _masks(0x000),
    (1, NativeReason.RESOURCE_EXHAUSTED, NativeStage.FIXTURE_SETUP): _masks(0x000),
    (1, NativeReason.RESOURCE_EXHAUSTED, NativeStage.CLONE3): _masks(0x000),
    (1, NativeReason.CLONE3_UNAVAILABLE, NativeStage.CLONE3): _masks(0x000),
    (1, NativeReason.CLONE3_REJECTED, NativeStage.CLONE3): _masks(0x000),
    (1, NativeReason.PIDFD_UNAVAILABLE, NativeStage.CLONE3): _masks(0x0C1),
    (1, NativeReason.CHILD_SETUP_FAILED, NativeStage.CHILD_READY): _masks(0x0C3),
    (1, NativeReason.CHILD_OBSERVATION_FAILED, NativeStage.CHILD_READY): _masks(
        0x0C3
    ),
    (1, NativeReason.TIMEOUT, NativeStage.CHILD_READY): _masks(0x0C3),
    (1, NativeReason.PROTOCOL_INPUT, NativeStage.PROTOCOL): _masks(
        0x000, 0x0C3, 0x1C3
    ),
    (1, NativeReason.IO_FAILURE, NativeStage.FIXTURE_SETUP): _masks(0x000, 0x0C3),
    (1, NativeReason.IO_FAILURE, NativeStage.CHILD_READY): _masks(0x0C3, 0x1C3),
    (1, NativeReason.IO_FAILURE, NativeStage.PROTOCOL): _masks(0x1C3),
    (1, NativeReason.CLEANUP_INCOMPLETE, NativeStage.CLEANUP): _masks(
        0x000,
        0x001,
        0x041,
        0x081,
        0x0C1,
        0x003,
        0x043,
        0x083,
        0x0C3,
        0x103,
        0x143,
        0x183,
        0x1C3,
    ),
    (2, NativeReason.PIDFD_SIGNAL_FAILED, NativeStage.PIDFD_SIGNAL): _masks(0x1C3),
    (2, NativeReason.CHILD_OBSERVATION_FAILED, NativeStage.PIDFD_SIGNAL): _masks(
        0x1C7, 0x1CF
    ),
    (2, NativeReason.TIMEOUT, NativeStage.PIDFD_SIGNAL): _masks(0x1C7),
    (2, NativeReason.PROTOCOL_INPUT, NativeStage.PROTOCOL): _masks(0x1C7, 0x1CF),
    (2, NativeReason.IO_FAILURE, NativeStage.PIDFD_SIGNAL): _masks(0x1C7, 0x1CF),
    (2, NativeReason.IO_FAILURE, NativeStage.PROTOCOL): _masks(0x1CF),
    (2, NativeReason.CLEANUP_INCOMPLETE, NativeStage.CLEANUP): _masks(
        0x103,
        0x143,
        0x183,
        0x1C3,
        0x107,
        0x147,
        0x187,
        0x1C7,
        0x10F,
        0x14F,
        0x18F,
        0x1CF,
    ),
    (3, NativeReason.CGROUP_KILL_FAILED, NativeStage.CGROUP_KILL): _masks(0x1CF),
    (
        3,
        NativeReason.CHILD_OBSERVATION_FAILED,
        NativeStage.CHILD_OBSERVATION,
    ): _masks(0x1DF),
    (3, NativeReason.TIMEOUT, NativeStage.CHILD_OBSERVATION): _masks(0x1DF),
    (3, NativeReason.PROTOCOL_INPUT, NativeStage.PROTOCOL): _masks(
        0x1CF, 0x1DF, 0x1FF
    ),
    (3, NativeReason.IO_FAILURE, NativeStage.CGROUP_KILL): _masks(0x1CF),
    (3, NativeReason.IO_FAILURE, NativeStage.CHILD_OBSERVATION): _masks(
        0x1DF, 0x1FF
    ),
    (3, NativeReason.IO_FAILURE, NativeStage.PROTOCOL): _masks(0x1FF),
    (3, NativeReason.CLEANUP_INCOMPLETE, NativeStage.CLEANUP): _masks(
        0x10F,
        0x14F,
        0x18F,
        0x1CF,
        0x11F,
        0x15F,
        0x19F,
        0x1DF,
        0x1BF,
        0x1FF,
    ),
    (4, NativeReason.CHILD_REAP_FAILED, NativeStage.CHILD_REAP): _masks(0x1FF),
    (4, NativeReason.INTERNAL, NativeStage.CLEANUP): _masks(0x1FF),
    (4, NativeReason.PROTOCOL_INPUT, NativeStage.PROTOCOL): _masks(0x1FF),
    (4, NativeReason.IO_FAILURE, NativeStage.CLEANUP): _masks(0x1FF),
    (4, NativeReason.CLEANUP_INCOMPLETE, NativeStage.CLEANUP): _masks(
        0x1BF, 0x1FF
    ),
}

_ZERO_ERRNO_ERROR_KEYS = frozenset(
    key
    for key in _ERROR_GRAMMAR
    if key[1]
    in {
        NativeReason.CGROUP_NOT_EMPTY,
        NativeReason.PROTOCOL_INPUT,
        NativeReason.TIMEOUT,
    }
) | frozenset(
    {
        (
            1,
            NativeReason.CHILD_OBSERVATION_FAILED,
            NativeStage.CHILD_READY,
        ),
        (4, NativeReason.INTERNAL, NativeStage.CLEANUP),
    }
)

_ZERO_ERRNO_ERROR_STATES = frozenset(
    {
        (
            2,
            NativeReason.CHILD_OBSERVATION_FAILED,
            NativeStage.PIDFD_SIGNAL,
            0x1CF,
        ),
    }
)

# Linux x86-64 errno values used by launcher.c's clone3 classification.  These
# cannot come from Python's host ``errno`` module because transcript validation also
# runs on non-Linux development hosts.
_LINUX_ENOSYS = 38
_LINUX_CLONE_RESOURCE_ERRNOS = frozenset({11, 12, 23, 24})
_LINUX_CLASSIFIED_CLONE_ERRNOS = _LINUX_CLONE_RESOURCE_ERRNOS | {_LINUX_ENOSYS}

_NONZERO_ERRNO_ERROR_STATES = frozenset(
    {
        (0, NativeReason.IO_FAILURE, NativeStage.PROTOCOL, 0x000),
        (1, NativeReason.IO_FAILURE, NativeStage.PROTOCOL, 0x1C3),
        (2, NativeReason.IO_FAILURE, NativeStage.PROTOCOL, 0x1CF),
        (3, NativeReason.IO_FAILURE, NativeStage.PROTOCOL, 0x1FF),
        (1, NativeReason.IO_FAILURE, NativeStage.FIXTURE_SETUP, 0x000),
        (1, NativeReason.IO_FAILURE, NativeStage.FIXTURE_SETUP, 0x0C3),
        (1, NativeReason.IO_FAILURE, NativeStage.CHILD_READY, 0x1C3),
        (2, NativeReason.IO_FAILURE, NativeStage.PIDFD_SIGNAL, 0x1C7),
        (3, NativeReason.IO_FAILURE, NativeStage.CGROUP_KILL, 0x1CF),
        (3, NativeReason.IO_FAILURE, NativeStage.CHILD_OBSERVATION, 0x1FF),
        (4, NativeReason.IO_FAILURE, NativeStage.CLEANUP, 0x1FF),
        (1, NativeReason.RESOURCE_EXHAUSTED, NativeStage.FIXTURE_SETUP, 0x000),
        (3, NativeReason.CGROUP_KILL_FAILED, NativeStage.CGROUP_KILL, 0x1CF),
        (0, NativeReason.CLEANUP_INCOMPLETE, NativeStage.CLEANUP, 0x000),
        (1, NativeReason.CLEANUP_INCOMPLETE, NativeStage.CLEANUP, 0x000),
        (1, NativeReason.CLEANUP_INCOMPLETE, NativeStage.CLEANUP, 0x0C1),
        (1, NativeReason.CLEANUP_INCOMPLETE, NativeStage.CLEANUP, 0x0C3),
        (1, NativeReason.CLEANUP_INCOMPLETE, NativeStage.CLEANUP, 0x1C3),
        (2, NativeReason.CLEANUP_INCOMPLETE, NativeStage.CLEANUP, 0x1C3),
        (2, NativeReason.CLEANUP_INCOMPLETE, NativeStage.CLEANUP, 0x1C7),
        (2, NativeReason.CLEANUP_INCOMPLETE, NativeStage.CLEANUP, 0x1CF),
        (3, NativeReason.CLEANUP_INCOMPLETE, NativeStage.CLEANUP, 0x1CF),
        (3, NativeReason.CLEANUP_INCOMPLETE, NativeStage.CLEANUP, 0x1DF),
        (3, NativeReason.CLEANUP_INCOMPLETE, NativeStage.CLEANUP, 0x1FF),
        (4, NativeReason.CLEANUP_INCOMPLETE, NativeStage.CLEANUP, 0x1FF),
    }
)


def _exit_code_for_reason(reason: NativeReason) -> NativeExitCode:
    if NativeReason.BAD_ARGC <= reason <= NativeReason.CGROUP_NOT_EMPTY:
        return NativeExitCode.STARTUP
    if NativeReason.PROTOCOL_INPUT <= reason <= NativeReason.PEER_CLOSED:
        return NativeExitCode.PROTOCOL
    if NativeReason.RESOURCE_EXHAUSTED <= reason <= NativeReason.CHILD_REAP_FAILED:
        return NativeExitCode.KERNEL
    if reason is NativeReason.TIMEOUT:
        return NativeExitCode.TIMEOUT
    if reason is NativeReason.CLEANUP_INCOMPLETE:
        return NativeExitCode.CLEANUP
    if reason is NativeReason.IO_FAILURE:
        return NativeExitCode.KERNEL
    if reason is NativeReason.INTERNAL:
        return NativeExitCode.INTERNAL
    raise InertNativeProtocolViolation("native error frame has no failure reason")


def _decode_record(record: InertNativeSocketRecord) -> InertNativeFrame:
    if type(record.payload) is not bytes:
        raise InertNativeProtocolViolation("native record payload must be bytes")
    if (
        type(record.message_truncated) is not bool
        or type(record.control_truncated) is not bool
        or type(record.ancillary_present) is not bool
    ):
        raise InertNativeProtocolViolation("native record metadata must be boolean")
    if record.message_truncated or record.control_truncated:
        raise InertNativeProtocolViolation("native record was truncated")
    if record.ancillary_present:
        raise InertNativeProtocolViolation("native record carried ancillary data")
    if len(record.payload) != PROTOCOL_FRAME_SIZE:
        raise InertNativeProtocolViolation("native record has an invalid size")

    (
        magic,
        version,
        frame_type_raw,
        payload_size,
        sequence,
        status_raw,
        stage_raw,
        reason_raw,
        system_errno,
        value0,
        value1,
        reserved,
    ) = _FRAME_STRUCT.unpack(record.payload)

    if magic != PROTOCOL_MAGIC:
        raise InertNativeProtocolViolation("native record has invalid magic")
    if version != PROTOCOL_VERSION:
        raise InertNativeProtocolViolation("native record has an invalid version")
    if payload_size != PROTOCOL_PAYLOAD_SIZE:
        raise InertNativeProtocolViolation("native record has an invalid payload size")
    if reserved != b"\x00" * 8:
        raise InertNativeProtocolViolation("native record has nonzero reserved bytes")
    if system_errno > PROTOCOL_MAX_ERRNO:
        raise InertNativeProtocolViolation("native record errno exceeds the fixed bound")

    try:
        frame_type = NativeFrameType(frame_type_raw)
        status = NativeStatus(status_raw)
        stage = NativeStage(stage_raw)
        reason = NativeReason(reason_raw)
    except ValueError as exc:
        raise InertNativeProtocolViolation("native record contains an unknown enum") from exc

    return InertNativeFrame(
        frame_type=frame_type,
        sequence=sequence,
        status=status,
        stage=stage,
        reason=reason,
        system_errno=system_errno,
        value0=value0,
        value1=value1,
    )


def _validate_success_frame(frame: InertNativeFrame, index: int) -> None:
    if frame.frame_type is not _SUCCESS_TYPES[index]:
        raise InertNativeProtocolViolation("native success frames are out of order")
    if frame.status is not NativeStatus.OK:
        raise InertNativeProtocolViolation("native success frame has failure status")
    if frame.stage is not _SUCCESS_STAGES[index]:
        raise InertNativeProtocolViolation("native success frame has the wrong stage")
    if frame.reason is not NativeReason.NONE or frame.system_errno != 0:
        raise InertNativeProtocolViolation("native success frame contains failure fields")

    if index == 0:
        if not 1 <= frame.value0 <= LINUX_MAX_PID or frame.value1 != 0:
            raise InertNativeProtocolViolation("native hello frame has invalid values")
    elif index == 1:
        if not 1 <= frame.value0 <= LINUX_MAX_PID:
            raise InertNativeProtocolViolation("native child-ready frame has an invalid pid")
        if frame.value1 != REQUIRED_CLONE_FLAGS:
            raise InertNativeProtocolViolation(
                "native child-ready frame has invalid clone3 flags"
            )
    elif index == 2:
        if frame.value0 != CLD_STOPPED or frame.value1 != SIGSTOP:
            raise InertNativeProtocolViolation("native child-signaled frame is invalid")
    elif index == 3:
        if frame.value0 != CLD_KILLED or frame.value1 != SIGKILL:
            raise InertNativeProtocolViolation("native child-observed frame is invalid")
    elif frame.value0 != ACHIEVED_RESULT_MASK or frame.value1 == 0:
        raise InertNativeProtocolViolation("native final frame is invalid")


def _validate_error_frame(
    frame: InertNativeFrame,
    *,
    prefix_length: int,
    returncode: int,
) -> NativeExitCode:
    if frame.status is not NativeStatus.FAILED:
        raise InertNativeProtocolViolation("native error frame has success status")
    if frame.reason is NativeReason.NONE:
        raise InertNativeProtocolViolation("native error frame has no failure reason")
    if frame.value0 & ~ACHIEVED_RESULT_MASK:
        raise InertNativeProtocolViolation("native error frame has unknown result flags")
    if frame.value1 != 0:
        raise InertNativeProtocolViolation("native error frame has a nonzero reserved value")
    grammar_key = (prefix_length, frame.reason, frame.stage)
    allowed_masks = _ERROR_GRAMMAR.get(grammar_key)
    if allowed_masks is None:
        raise InertNativeProtocolViolation(
            "native error reason and stage are impossible after its success prefix"
        )
    if frame.value0 not in allowed_masks:
        raise InertNativeProtocolViolation(
            "native error mask is impossible for its prefix, reason, and stage"
        )
    if grammar_key in _ZERO_ERRNO_ERROR_KEYS and frame.system_errno != 0:
        raise InertNativeProtocolViolation(
            "native error errno is impossible for its prefix, reason, and stage"
        )
    error_state = (*grammar_key, frame.value0)
    if error_state in _ZERO_ERRNO_ERROR_STATES and frame.system_errno != 0:
        raise InertNativeProtocolViolation(
            "native error errno is impossible for its exact achieved state"
        )
    if (
        frame.reason is NativeReason.CLONE3_UNAVAILABLE
        and frame.system_errno != _LINUX_ENOSYS
    ):
        raise InertNativeProtocolViolation("native clone3-unavailable errno is impossible")
    if (
        frame.reason is NativeReason.RESOURCE_EXHAUSTED
        and frame.stage is NativeStage.CLONE3
        and frame.system_errno not in _LINUX_CLONE_RESOURCE_ERRNOS
    ):
        raise InertNativeProtocolViolation("native clone3 resource errno is impossible")
    if frame.reason is NativeReason.CLONE3_REJECTED and (
        frame.system_errno == 0
        or frame.system_errno in _LINUX_CLASSIFIED_CLONE_ERRNOS
    ):
        raise InertNativeProtocolViolation("native clone3-rejected errno is impossible")
    if (
        frame.reason is NativeReason.PIDFD_SIGNAL_FAILED
        and frame.system_errno == 0
    ):
        raise InertNativeProtocolViolation("native pidfd-signal errno is impossible")
    if error_state in _NONZERO_ERRNO_ERROR_STATES and frame.system_errno == 0:
        raise InertNativeProtocolViolation(
            "native I/O failure is missing its required Linux errno"
        )

    expected_exit = _exit_code_for_reason(frame.reason)
    if returncode != int(expected_exit):
        raise InertNativeProtocolViolation("native error exit code does not match its reason")
    return expected_exit


def parse_inert_native_transcript(
    records: Sequence[InertNativeSocketRecord],
    *,
    returncode: int,
    eof_observed: bool,
    expected_launcher_pid: int,
) -> InertNativeTranscript:
    """Validate an entire bounded transcript and its exact launcher exit status.

    The caller must translate each ``recvmsg`` result into an
    :class:`InertNativeSocketRecord`, including the truncation and ancillary-data
    flags.  Passing payload bytes alone would erase protocol-relevant socket state.
    ``eof_observed`` must attest that the collector drained the socket through peer
    closure, and ``expected_launcher_pid`` must be the exact spawned process whose
    return code was collected.
    """

    if isinstance(records, (bytes, bytearray, memoryview)):
        raise InertNativeProtocolViolation("native transcript must contain records")
    if type(returncode) is not int:
        raise InertNativeProtocolViolation("native launcher return code must be an integer")
    if type(eof_observed) is not bool or not eof_observed:
        raise InertNativeProtocolViolation(
            "native transcript must include an observed socket EOF"
        )
    if (
        type(expected_launcher_pid) is not int
        or not 1 <= expected_launcher_pid <= LINUX_MAX_PID
    ):
        raise InertNativeProtocolViolation("expected native launcher pid is invalid")

    count = len(records)
    if count == 0:
        raise InertNativeProtocolViolation("native transcript is empty")
    if count > PROTOCOL_MAX_FRAMES:
        raise InertNativeProtocolViolation("native transcript exceeds the frame bound")

    frames: list[InertNativeFrame] = []
    for index in range(count):
        record = records[index]
        if type(record) is not InertNativeSocketRecord:
            raise InertNativeProtocolViolation("native transcript contains an invalid record")
        frame = _decode_record(record)
        if frame.sequence != index:
            raise InertNativeProtocolViolation("native frame sequence is not contiguous")
        frames.append(frame)

    launcher_pid = expected_launcher_pid
    child_pid: int | None = None
    for index, frame in enumerate(frames):
        if frame.frame_type is NativeFrameType.ERROR:
            if index >= len(_SUCCESS_TYPES):
                raise InertNativeProtocolViolation("native error frame followed a final frame")
            if index != len(frames) - 1:
                raise InertNativeProtocolViolation("native error frame is not terminal")
            exit_code = _validate_error_frame(
                frame,
                prefix_length=index,
                returncode=returncode,
            )
            return InertNativeTranscript(
                succeeded=False,
                frames=tuple(frames),
                launcher_exit_code=exit_code,
                launcher_pid=launcher_pid,
                child_pid=child_pid,
                achieved_result_mask=frame.value0,
                elapsed_ns=None,
                failure_stage=frame.stage,
                failure_reason=frame.reason,
                failure_errno=frame.system_errno,
            )
        if index >= len(_SUCCESS_TYPES):
            raise InertNativeProtocolViolation("native transcript continued after success")
        _validate_success_frame(frame, index)
        if index == 0:
            if frame.value0 != expected_launcher_pid:
                raise InertNativeProtocolViolation(
                    "native hello pid does not match the spawned launcher"
                )
        elif index == 1:
            child_pid = frame.value0
            if child_pid == launcher_pid:
                raise InertNativeProtocolViolation(
                    "native child pid must differ from the launcher pid"
                )

    if len(frames) != len(_SUCCESS_TYPES):
        raise InertNativeProtocolViolation("native success transcript is incomplete")
    if returncode != int(NativeExitCode.OK):
        raise InertNativeProtocolViolation("native success transcript has a nonzero exit code")

    final = frames[-1]
    return InertNativeTranscript(
        succeeded=True,
        frames=tuple(frames),
        launcher_exit_code=NativeExitCode.OK,
        launcher_pid=launcher_pid,
        child_pid=child_pid,
        achieved_result_mask=final.value0,
        elapsed_ns=final.value1,
        failure_stage=None,
        failure_reason=None,
        failure_errno=None,
    )
