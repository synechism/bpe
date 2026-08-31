#ifndef BPE_INERT_FIXTURE_WIRE_H
#define BPE_INERT_FIXTURE_WIRE_H

#include "protocol.h"

#include <stdint.h>
#include <string.h>

static inline void bpe_inert_put_be16(uint8_t *output, uint16_t value) {
    output[0] = (uint8_t)(value >> 8);
    output[1] = (uint8_t)value;
}

static inline void bpe_inert_put_be32(uint8_t *output, uint32_t value) {
    output[0] = (uint8_t)(value >> 24);
    output[1] = (uint8_t)(value >> 16);
    output[2] = (uint8_t)(value >> 8);
    output[3] = (uint8_t)value;
}

static inline void bpe_inert_put_be64(uint8_t *output, uint64_t value) {
    output[0] = (uint8_t)(value >> 56);
    output[1] = (uint8_t)(value >> 48);
    output[2] = (uint8_t)(value >> 40);
    output[3] = (uint8_t)(value >> 32);
    output[4] = (uint8_t)(value >> 24);
    output[5] = (uint8_t)(value >> 16);
    output[6] = (uint8_t)(value >> 8);
    output[7] = (uint8_t)value;
}

static inline void bpe_inert_encode_frame(uint8_t output[BPE_INERT_PROTOCOL_FRAME_SIZE],
                                          uint16_t type, uint64_t sequence,
                                          uint32_t status, uint32_t stage,
                                          uint32_t reason, uint32_t error_number,
                                          uint64_t value0, uint64_t value1) {
    memset(output, 0, BPE_INERT_PROTOCOL_FRAME_SIZE);
    memcpy(output + BPE_INERT_WIRE_MAGIC_OFFSET, BPE_INERT_PROTOCOL_MAGIC,
           BPE_INERT_PROTOCOL_MAGIC_SIZE);
    bpe_inert_put_be16(output + BPE_INERT_WIRE_VERSION_OFFSET,
                       BPE_INERT_PROTOCOL_VERSION);
    bpe_inert_put_be16(output + BPE_INERT_WIRE_TYPE_OFFSET, type);
    bpe_inert_put_be32(output + BPE_INERT_WIRE_PAYLOAD_LENGTH_OFFSET,
                       BPE_INERT_PROTOCOL_PAYLOAD_SIZE);
    bpe_inert_put_be64(output + BPE_INERT_WIRE_SEQUENCE_OFFSET, sequence);
    bpe_inert_put_be32(output + BPE_INERT_WIRE_STATUS_OFFSET, status);
    bpe_inert_put_be32(output + BPE_INERT_WIRE_STAGE_OFFSET, stage);
    bpe_inert_put_be32(output + BPE_INERT_WIRE_REASON_OFFSET, reason);
    bpe_inert_put_be32(output + BPE_INERT_WIRE_ERRNO_OFFSET, error_number);
    bpe_inert_put_be64(output + BPE_INERT_WIRE_VALUE0_OFFSET, value0);
    bpe_inert_put_be64(output + BPE_INERT_WIRE_VALUE1_OFFSET, value1);
}

#endif
