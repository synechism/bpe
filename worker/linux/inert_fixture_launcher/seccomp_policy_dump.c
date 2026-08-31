#include "seccomp_filter.h"

#include <stdint.h>
#include <stdio.h>

int main(void) {
    size_t index;
    for (index = 0U;
         index < sizeof(bpe_inert_seccomp_filter) /
                     sizeof(bpe_inert_seccomp_filter[0]);
         index++) {
        const struct sock_filter instruction = bpe_inert_seccomp_filter[index];
        const uint8_t canonical[8] = {
            (uint8_t)(instruction.code >> 8),
            (uint8_t)instruction.code,
            instruction.jt,
            instruction.jf,
            (uint8_t)(instruction.k >> 24),
            (uint8_t)(instruction.k >> 16),
            (uint8_t)(instruction.k >> 8),
            (uint8_t)instruction.k,
        };
        if (fwrite(canonical, sizeof(canonical), 1U, stdout) != 1U) {
            return 1;
        }
    }
    return fflush(stdout) == 0 ? 0 : 1;
}
