#ifndef HASH_AVX2_C_H
#define HASH_AVX2_C_H

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "sha256_avx2.h"
#include "ripemd160_avx2.h"

#define SHA256_DIGEST_SIZE 32
#define RIPEMD160_DIGEST_SIZE 20

/**
 * Compute SHA256 on 8 inputs in parallel using AVX2.
 *
 * @param inputs   Array of 8 pointers to input buffers.
 * @param lengths  Array of 8 lengths for each input buffer.
 * @param outputs  Output array [8][SHA256_DIGEST_SIZE] to receive digests.
 * @return 0 on success, -1 on allocation error.
 */
int sha256_8x(const uint8_t *inputs[8], const size_t lengths[8],
             uint8_t outputs[8][SHA256_DIGEST_SIZE]);

/**
 * Compute RIPEMD160 on 8 inputs in parallel using AVX2.
 *
 * @param inputs   Array of 8 pointers to input buffers.
 * @param lengths  Array of 8 lengths for each input buffer.
 * @param outputs  Output array [8][RIPEMD160_DIGEST_SIZE] to receive digests.
 * @return 0 on success, -1 on allocation error.
 */
int ripemd160_8x(const uint8_t *inputs[8], const size_t lengths[8],
                 uint8_t outputs[8][RIPEMD160_DIGEST_SIZE]);

#endif // HASH_AVX2_C_H
