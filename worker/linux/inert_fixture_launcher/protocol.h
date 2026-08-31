#ifndef BPE_INERT_FIXTURE_PROTOCOL_H
#define BPE_INERT_FIXTURE_PROTOCOL_H

#include <stdint.h>

/*
 * The launcher protocol is deliberately one-way.  The authorized parent receives
 * fixed-size records on inherited SOCK_SEQPACKET descriptor 3.  The launcher never
 * accepts a request, path, argv element, environment entry, candidate byte, or other
 * runtime input.
 */
#define BPE_INERT_PROTOCOL_MAGIC "BPEIFX1\0"
#define BPE_INERT_PROTOCOL_MAGIC_SIZE 8U
#define BPE_INERT_PROTOCOL_VERSION 1U
#define BPE_INERT_PROTOCOL_FRAME_SIZE 64U
#define BPE_INERT_PROTOCOL_PAYLOAD_SIZE 40U
#define BPE_INERT_PROTOCOL_MAX_FRAMES 8U
#define BPE_INERT_MAX_ERRNO 4095U
#define BPE_INERT_ACHIEVED_MASK UINT64_C(0x1ff)

#define BPE_INERT_CONTROL_FD 3
#define BPE_INERT_CGROUP_FD 4

/* These are launcher emergency ceilings, not caller-selected or signed policy values. */
#define BPE_INERT_EMERGENCY_RUNTIME_MS 30000U
#define BPE_INERT_EMERGENCY_CLEANUP_MS 5000U

enum bpe_inert_frame_type {
    BPE_INERT_FRAME_HELLO = 1,
    BPE_INERT_FRAME_CHILD_READY = 2,
    BPE_INERT_FRAME_CHILD_SIGNALED = 3,
    BPE_INERT_FRAME_CHILD_OBSERVED = 4,
    BPE_INERT_FRAME_FINAL = 5,
    BPE_INERT_FRAME_ERROR = 6,
};

enum bpe_inert_status {
    BPE_INERT_STATUS_OK = 0,
    BPE_INERT_STATUS_FAILED = 1,
};

enum bpe_inert_stage {
    BPE_INERT_STAGE_STARTUP = 1,
    BPE_INERT_STAGE_DESCRIPTOR_VALIDATION = 2,
    BPE_INERT_STAGE_CGROUP_VALIDATION = 3,
    BPE_INERT_STAGE_FIXTURE_SETUP = 4,
    BPE_INERT_STAGE_CLONE3 = 5,
    BPE_INERT_STAGE_CHILD_READY = 6,
    BPE_INERT_STAGE_PIDFD_SIGNAL = 7,
    BPE_INERT_STAGE_CGROUP_KILL = 8,
    BPE_INERT_STAGE_CHILD_OBSERVATION = 9,
    BPE_INERT_STAGE_CHILD_REAP = 10,
    BPE_INERT_STAGE_CLEANUP = 11,
    BPE_INERT_STAGE_PROTOCOL = 12,
};

enum bpe_inert_reason {
    BPE_INERT_REASON_NONE = 0,
    BPE_INERT_REASON_BAD_ARGC = 1,
    BPE_INERT_REASON_BAD_ARGV = 2,
    BPE_INERT_REASON_NONEMPTY_ENVIRONMENT = 3,
    BPE_INERT_REASON_BAD_DESCRIPTOR_LAYOUT = 4,
    BPE_INERT_REASON_BAD_STDIO = 5,
    BPE_INERT_REASON_BAD_CONTROL_SOCKET = 6,
    BPE_INERT_REASON_BAD_CGROUP_DESCRIPTOR = 7,
    BPE_INERT_REASON_CGROUP_NOT_EMPTY = 8,
    BPE_INERT_REASON_PROTOCOL_INPUT = 9,
    BPE_INERT_REASON_PEER_CLOSED = 10,
    BPE_INERT_REASON_RESOURCE_EXHAUSTED = 11,
    BPE_INERT_REASON_CLONE3_UNAVAILABLE = 12,
    BPE_INERT_REASON_CLONE3_REJECTED = 13,
    BPE_INERT_REASON_PIDFD_UNAVAILABLE = 14,
    BPE_INERT_REASON_CHILD_SETUP_FAILED = 15,
    BPE_INERT_REASON_PIDFD_SIGNAL_FAILED = 16,
    BPE_INERT_REASON_CGROUP_KILL_FAILED = 17,
    BPE_INERT_REASON_CHILD_OBSERVATION_FAILED = 18,
    BPE_INERT_REASON_CHILD_REAP_FAILED = 19,
    BPE_INERT_REASON_TIMEOUT = 20,
    BPE_INERT_REASON_CLEANUP_INCOMPLETE = 21,
    BPE_INERT_REASON_IO_FAILURE = 22,
    BPE_INERT_REASON_INTERNAL = 23,
};

enum bpe_inert_exit_code {
    BPE_INERT_EXIT_OK = 0,
    BPE_INERT_EXIT_STARTUP = 64,
    BPE_INERT_EXIT_PROTOCOL = 65,
    BPE_INERT_EXIT_KERNEL = 66,
    BPE_INERT_EXIT_TIMEOUT = 67,
    BPE_INERT_EXIT_CLEANUP = 68,
    BPE_INERT_EXIT_INTERNAL = 69,
};

/*
 * ERROR is terminal.  value0 is the achieved-result mask, value1 is exactly zero,
 * and errno is either zero or in [1, BPE_INERT_MAX_ERRNO].  The stable exit map is:
 *
 *   reasons 1..8   -> STARTUP (64)
 *   reasons 9..10  -> PROTOCOL (65)
 *   reasons 11..19 -> KERNEL (66)
 *   reason 20      -> TIMEOUT (67)
 *   reason 21      -> CLEANUP (68)
 *   reason 22      -> KERNEL (66)
 *   reason 23      -> INTERNAL (69)
 *
 * CHILD_OBSERVATION_FAILED may use CHILD_READY, PIDFD_SIGNAL, or CHILD_OBSERVATION.
 * TIMEOUT may use CHILD_READY, PIDFD_SIGNAL, or CHILD_OBSERVATION.
 * CLEANUP_INCOMPLETE uses CLEANUP and overrides an earlier diagnostic reason whenever
 * bounded emergency reap/empty cleanup or owned-descriptor closure is incomplete.
 * IO_FAILURE uses the stage of the failed fixed I/O operation.  The parent parser
 * additionally constrains every prefix/reason/stage to the exact reachable achieved
 * masks; independent field plausibility is not sufficient protocol evidence.
 * PROTOCOL_INPUT, CGROUP_NOT_EMPTY, TIMEOUT, CHILD_OBSERVATION_FAILED at CHILD_READY,
 * CHILD_OBSERVATION_FAILED at PIDFD_SIGNAL with achieved mask 0x1cf, and INTERNAL at
 * CLEANUP deterministically carry errno zero.
 * CLONE3_UNAVAILABLE carries Linux ENOSYS (38); RESOURCE_EXHAUSTED at CLONE3 carries
 * one of EAGAIN (11), ENOMEM (12), ENFILE (23), or EMFILE (24); CLONE3_REJECTED
 * carries a different nonzero Linux errno; and PIDFD_SIGNAL_FAILED is nonzero.
 * Error states produced solely by a failed send, poll, close, fixed pipe creation,
 * pidfd signal, or cgroup.kill write also carry a nonzero errno.
 * CLEANUP_INCOMPLETE masks proving emergency reap plus empty-cgroup cleanup completed
 * likewise require a nonzero owned-descriptor close errno.
 */

enum bpe_inert_result_flag {
    BPE_INERT_RESULT_CLONE3_INTO_CGROUP = UINT64_C(1) << 0,
    BPE_INERT_RESULT_PIDFD_CREATED = UINT64_C(1) << 1,
    BPE_INERT_RESULT_PIDFD_STOP_SENT = UINT64_C(1) << 2,
    BPE_INERT_RESULT_PIDFD_STOP_OBSERVED = UINT64_C(1) << 3,
    BPE_INERT_RESULT_LIVE_CGROUP_KILL = UINT64_C(1) << 4,
    BPE_INERT_RESULT_PIDFD_EXIT_OBSERVED = UINT64_C(1) << 5,
    BPE_INERT_RESULT_CHILD_REAPED = UINT64_C(1) << 6,
    BPE_INERT_RESULT_CGROUP_EMPTY = UINT64_C(1) << 7,
    BPE_INERT_RESULT_BUILTIN_NOEXEC = UINT64_C(1) << 8,
};

/* Wire offsets.  Integers use network byte order and every reserved byte is zero. */
#define BPE_INERT_WIRE_MAGIC_OFFSET 0U
#define BPE_INERT_WIRE_VERSION_OFFSET 8U
#define BPE_INERT_WIRE_TYPE_OFFSET 10U
#define BPE_INERT_WIRE_PAYLOAD_LENGTH_OFFSET 12U
#define BPE_INERT_WIRE_SEQUENCE_OFFSET 16U
#define BPE_INERT_WIRE_STATUS_OFFSET 24U
#define BPE_INERT_WIRE_STAGE_OFFSET 28U
#define BPE_INERT_WIRE_REASON_OFFSET 32U
#define BPE_INERT_WIRE_ERRNO_OFFSET 36U
#define BPE_INERT_WIRE_VALUE0_OFFSET 40U
#define BPE_INERT_WIRE_VALUE1_OFFSET 48U
#define BPE_INERT_WIRE_RESERVED_OFFSET 56U

/* The Python decoder mirrors this ABI; fail compilation on any local drift. */
_Static_assert(BPE_INERT_PROTOCOL_MAGIC_SIZE == 8U, "protocol magic size drift");
_Static_assert(BPE_INERT_PROTOCOL_VERSION == 1U, "protocol version drift");
_Static_assert(BPE_INERT_PROTOCOL_FRAME_SIZE == 64U, "protocol frame size drift");
_Static_assert(BPE_INERT_PROTOCOL_PAYLOAD_SIZE == 40U, "protocol payload size drift");
_Static_assert(BPE_INERT_PROTOCOL_MAX_FRAMES == 8U, "protocol frame bound drift");
_Static_assert(BPE_INERT_MAX_ERRNO == 4095U, "protocol errno bound drift");
_Static_assert(BPE_INERT_WIRE_MAGIC_OFFSET == 0U, "magic offset drift");
_Static_assert(BPE_INERT_WIRE_VERSION_OFFSET == 8U, "version offset drift");
_Static_assert(BPE_INERT_WIRE_TYPE_OFFSET == 10U, "type offset drift");
_Static_assert(BPE_INERT_WIRE_PAYLOAD_LENGTH_OFFSET == 12U, "length offset drift");
_Static_assert(BPE_INERT_WIRE_SEQUENCE_OFFSET == 16U, "sequence offset drift");
_Static_assert(BPE_INERT_WIRE_STATUS_OFFSET == 24U, "status offset drift");
_Static_assert(BPE_INERT_WIRE_STAGE_OFFSET == 28U, "stage offset drift");
_Static_assert(BPE_INERT_WIRE_REASON_OFFSET == 32U, "reason offset drift");
_Static_assert(BPE_INERT_WIRE_ERRNO_OFFSET == 36U, "errno offset drift");
_Static_assert(BPE_INERT_WIRE_VALUE0_OFFSET == 40U, "value0 offset drift");
_Static_assert(BPE_INERT_WIRE_VALUE1_OFFSET == 48U, "value1 offset drift");
_Static_assert(BPE_INERT_WIRE_RESERVED_OFFSET == 56U, "reserved offset drift");
_Static_assert(BPE_INERT_WIRE_RESERVED_OFFSET + 8U == BPE_INERT_PROTOCOL_FRAME_SIZE,
               "protocol wire fields do not fill one frame");
_Static_assert(BPE_INERT_FRAME_HELLO == 1 && BPE_INERT_FRAME_CHILD_READY == 2 &&
                   BPE_INERT_FRAME_CHILD_SIGNALED == 3 &&
                   BPE_INERT_FRAME_CHILD_OBSERVED == 4 && BPE_INERT_FRAME_FINAL == 5 &&
                   BPE_INERT_FRAME_ERROR == 6,
               "frame enum drift");
_Static_assert(BPE_INERT_STATUS_OK == 0 && BPE_INERT_STATUS_FAILED == 1,
               "status enum drift");
_Static_assert(BPE_INERT_STAGE_STARTUP == 1 && BPE_INERT_STAGE_DESCRIPTOR_VALIDATION == 2 &&
                   BPE_INERT_STAGE_CGROUP_VALIDATION == 3 &&
                   BPE_INERT_STAGE_FIXTURE_SETUP == 4 && BPE_INERT_STAGE_CLONE3 == 5 &&
                   BPE_INERT_STAGE_CHILD_READY == 6 && BPE_INERT_STAGE_PIDFD_SIGNAL == 7 &&
                   BPE_INERT_STAGE_CGROUP_KILL == 8 &&
                   BPE_INERT_STAGE_CHILD_OBSERVATION == 9 &&
                   BPE_INERT_STAGE_CHILD_REAP == 10 && BPE_INERT_STAGE_CLEANUP == 11 &&
                   BPE_INERT_STAGE_PROTOCOL == 12,
               "stage enum drift");
_Static_assert(BPE_INERT_REASON_NONE == 0 && BPE_INERT_REASON_BAD_ARGC == 1 &&
                   BPE_INERT_REASON_BAD_ARGV == 2 &&
                   BPE_INERT_REASON_NONEMPTY_ENVIRONMENT == 3 &&
                   BPE_INERT_REASON_BAD_DESCRIPTOR_LAYOUT == 4 &&
                   BPE_INERT_REASON_BAD_STDIO == 5 &&
                   BPE_INERT_REASON_BAD_CONTROL_SOCKET == 6 &&
                   BPE_INERT_REASON_BAD_CGROUP_DESCRIPTOR == 7 &&
                   BPE_INERT_REASON_CGROUP_NOT_EMPTY == 8 &&
                   BPE_INERT_REASON_PROTOCOL_INPUT == 9 &&
                   BPE_INERT_REASON_PEER_CLOSED == 10 &&
                   BPE_INERT_REASON_RESOURCE_EXHAUSTED == 11 &&
                   BPE_INERT_REASON_CLONE3_UNAVAILABLE == 12 &&
                   BPE_INERT_REASON_CLONE3_REJECTED == 13 &&
                   BPE_INERT_REASON_PIDFD_UNAVAILABLE == 14 &&
                   BPE_INERT_REASON_CHILD_SETUP_FAILED == 15 &&
                   BPE_INERT_REASON_PIDFD_SIGNAL_FAILED == 16 &&
                   BPE_INERT_REASON_CGROUP_KILL_FAILED == 17 &&
                   BPE_INERT_REASON_CHILD_OBSERVATION_FAILED == 18 &&
                   BPE_INERT_REASON_CHILD_REAP_FAILED == 19 &&
                   BPE_INERT_REASON_TIMEOUT == 20 &&
                   BPE_INERT_REASON_CLEANUP_INCOMPLETE == 21 &&
                   BPE_INERT_REASON_IO_FAILURE == 22 && BPE_INERT_REASON_INTERNAL == 23,
               "reason enum drift");
_Static_assert(BPE_INERT_EXIT_OK == 0 && BPE_INERT_EXIT_STARTUP == 64 &&
                   BPE_INERT_EXIT_PROTOCOL == 65 && BPE_INERT_EXIT_KERNEL == 66 &&
                   BPE_INERT_EXIT_TIMEOUT == 67 && BPE_INERT_EXIT_CLEANUP == 68 &&
                   BPE_INERT_EXIT_INTERNAL == 69,
               "exit enum drift");
_Static_assert(BPE_INERT_RESULT_CLONE3_INTO_CGROUP == (UINT64_C(1) << 0) &&
                   BPE_INERT_RESULT_PIDFD_CREATED == (UINT64_C(1) << 1) &&
                   BPE_INERT_RESULT_PIDFD_STOP_SENT == (UINT64_C(1) << 2) &&
                   BPE_INERT_RESULT_PIDFD_STOP_OBSERVED == (UINT64_C(1) << 3) &&
                   BPE_INERT_RESULT_LIVE_CGROUP_KILL == (UINT64_C(1) << 4) &&
                   BPE_INERT_RESULT_PIDFD_EXIT_OBSERVED == (UINT64_C(1) << 5) &&
                   BPE_INERT_RESULT_CHILD_REAPED == (UINT64_C(1) << 6) &&
                   BPE_INERT_RESULT_CGROUP_EMPTY == (UINT64_C(1) << 7) &&
                   BPE_INERT_RESULT_BUILTIN_NOEXEC == (UINT64_C(1) << 8) &&
                   BPE_INERT_ACHIEVED_MASK == UINT64_C(0x1ff),
               "result flag drift");

#endif
