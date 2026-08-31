#define _GNU_SOURCE

#include "wire.h"

#include <linux/sched.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/wait.h>

_Static_assert(CLONE_PIDFD == UINT64_C(0x1000), "CLONE_PIDFD ABI drift");
_Static_assert(CLONE_INTO_CGROUP == UINT64_C(0x200000000),
               "CLONE_INTO_CGROUP ABI drift");
_Static_assert(CLD_KILLED == 2 && CLD_STOPPED == 5, "CLD code ABI drift");
_Static_assert(SIGKILL == 9 && SIGSTOP == 19, "signal ABI drift");

static int bpe_hex_nibble(char value) {
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    return -1;
}

int main(void) {
    uint8_t actual[5U * BPE_INERT_PROTOCOL_FRAME_SIZE];
    uint8_t expected[sizeof(actual)];
    size_t index;
    static const char expected_hex[] =
        "4250454946583100000100010000002800000000000000000000000000000001"
        "000000000000000000000000000004d200000000000000000000000000000000"
        "4250454946583100000100020000002800000000000000010000000000000006"
        "000000000000000000000000000004d300000002000010000000000000000000"
        "4250454946583100000100030000002800000000000000020000000000000007"
        "0000000000000000000000000000000500000000000000130000000000000000"
        "4250454946583100000100040000002800000000000000030000000000000009"
        "0000000000000000000000000000000200000000000000090000000000000000"
        "425045494658310000010005000000280000000000000004000000000000000b"
        "000000000000000000000000000001ff000000003ade68b10000000000000000";

    _Static_assert(sizeof(expected_hex) == 2U * sizeof(actual) + 1U,
                   "golden protocol vector has an unexpected length");
    for (index = 0U; index < sizeof(expected); index++) {
        int high = bpe_hex_nibble(expected_hex[2U * index]);
        int low = bpe_hex_nibble(expected_hex[2U * index + 1U]);
        if (high < 0 || low < 0) {
            return 1;
        }
        expected[index] = (uint8_t)((unsigned int)high << 4) | (uint8_t)low;
    }

    bpe_inert_encode_frame(actual + 0U * BPE_INERT_PROTOCOL_FRAME_SIZE,
                           BPE_INERT_FRAME_HELLO, 0U, BPE_INERT_STATUS_OK,
                           BPE_INERT_STAGE_STARTUP, BPE_INERT_REASON_NONE, 0U, 1234U,
                           0U);
    bpe_inert_encode_frame(actual + 1U * BPE_INERT_PROTOCOL_FRAME_SIZE,
                           BPE_INERT_FRAME_CHILD_READY, 1U, BPE_INERT_STATUS_OK,
                           BPE_INERT_STAGE_CHILD_READY, BPE_INERT_REASON_NONE, 0U,
                           1235U, CLONE_PIDFD | CLONE_INTO_CGROUP);
    bpe_inert_encode_frame(actual + 2U * BPE_INERT_PROTOCOL_FRAME_SIZE,
                           BPE_INERT_FRAME_CHILD_SIGNALED, 2U, BPE_INERT_STATUS_OK,
                           BPE_INERT_STAGE_PIDFD_SIGNAL, BPE_INERT_REASON_NONE, 0U,
                           CLD_STOPPED, SIGSTOP);
    bpe_inert_encode_frame(actual + 3U * BPE_INERT_PROTOCOL_FRAME_SIZE,
                           BPE_INERT_FRAME_CHILD_OBSERVED, 3U, BPE_INERT_STATUS_OK,
                           BPE_INERT_STAGE_CHILD_OBSERVATION, BPE_INERT_REASON_NONE, 0U,
                           CLD_KILLED, SIGKILL);
    bpe_inert_encode_frame(actual + 4U * BPE_INERT_PROTOCOL_FRAME_SIZE,
                           BPE_INERT_FRAME_FINAL, 4U, BPE_INERT_STATUS_OK,
                           BPE_INERT_STAGE_CLEANUP, BPE_INERT_REASON_NONE, 0U,
                           BPE_INERT_ACHIEVED_MASK, UINT64_C(987654321));

    return memcmp(actual, expected, sizeof(actual)) == 0 ? 0 : 1;
}
