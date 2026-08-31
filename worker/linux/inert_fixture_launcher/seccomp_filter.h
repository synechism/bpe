#ifndef BPE_INERT_FIXTURE_SECCOMP_FILTER_H
#define BPE_INERT_FIXTURE_SECCOMP_FILTER_H

#include "seccomp_policy.h"

#include <limits.h>
#include <stdint.h>

#define BPE_FILTER_INSTRUCTION(instruction_code, jump_true, jump_false, argument) \
    {                                                                           \
        .code = (uint16_t)(instruction_code), .jt = (uint8_t)(jump_true),       \
        .jf = (uint8_t)(jump_false), .k = (uint32_t)(argument),                 \
    },

/* Both the installed filter and digest dumper consume this exact array definition. */
static const struct sock_filter bpe_inert_seccomp_filter[] = {
    BPE_INERT_SECCOMP_FILTER(BPE_FILTER_INSTRUCTION)
};

#undef BPE_FILTER_INSTRUCTION

_Static_assert(sizeof(bpe_inert_seccomp_filter) /
                       sizeof(bpe_inert_seccomp_filter[0]) <=
                   USHRT_MAX,
               "seccomp filter exceeds sock_fprog length field");

#endif
