#include "Hash.h"
#include <stdlib.h>
#include <string.h>

int sha256_8x(const uint8_t *inputs[8], const size_t lengths[8],
              uint8_t outputs[8][SHA256_DIGEST_SIZE]) {
    void *aligned[8];
    // The block size for SHA-256 is 64 bytes. 128 extra bytes is safe.
    const size_t SHA256_BLOCK_SIZE = 64;
    const size_t SAFETY_PAD        = 128;

    // Allocate buffers and copy in, leaving padding space
    for (int i = 0; i < 8; ++i) {
        size_t alloc_size = lengths[i] + SAFETY_PAD;
        if (posix_memalign(&aligned[i], 32, alloc_size) != 0) {
            // Cleanup on failure
            for (int j = 0; j < i; ++j) free(aligned[j]);
            return -1;
        }
        // Copy the message
        memcpy(aligned[i], inputs[i], lengths[i]);
        // Zero out the tail (for safety and padding)
        memset((uint8_t *)aligned[i] + lengths[i], 0, alloc_size - lengths[i]);
    }

    // Now call the AVX2-based 8-way SHA-256 function
    // which can safely read/write final blocks:
    sha256avx2_8B(
        (uint8_t*)aligned[0], (uint8_t*)aligned[1],
        (uint8_t*)aligned[2], (uint8_t*)aligned[3],
        (uint8_t*)aligned[4], (uint8_t*)aligned[5],
        (uint8_t*)aligned[6], (uint8_t*)aligned[7],
        lengths[0], lengths[1],
        lengths[2], lengths[3],
        lengths[4], lengths[5],
        lengths[6], lengths[7],
        outputs[0], outputs[1],
        outputs[2], outputs[3],
        outputs[4], outputs[5],
        outputs[6], outputs[7]
    );

    // Free
    for (int i = 0; i < 8; ++i) {
        free(aligned[i]);
    }
    return 0;
}

int ripemd160_8x(const uint8_t *inputs[8], const size_t lengths[8],
                 uint8_t outputs[8][RIPEMD160_DIGEST_SIZE])
{
    void *aligned[8];
    // 64-byte block + some extra. 128 is usually safe.
    const size_t RIPEMD160_BLOCK_SIZE = 64;
    const size_t SAFETY_PAD           = 128;

    for (int i = 0; i < 8; ++i) {
        size_t alloc_size = lengths[i] + SAFETY_PAD;
        if (posix_memalign(&aligned[i], 32, alloc_size) != 0) {
            for (int j = 0; j < i; ++j) {
                free(aligned[j]);
            }
            return -1;
        }
        // Copy the actual data
        memcpy(aligned[i], inputs[i], lengths[i]);
        // Zero out the rest so the AVX2 code sees valid data for padding
        memset((uint8_t*)aligned[i] + lengths[i], 0, alloc_size - lengths[i]);
    }

    // Now call the 8x RIPEMD-160 function
    ripemd160avx2_32(
        (uint8_t*)aligned[0], (uint8_t*)aligned[1],
        (uint8_t*)aligned[2], (uint8_t*)aligned[3],
        (uint8_t*)aligned[4], (uint8_t*)aligned[5],
        (uint8_t*)aligned[6], (uint8_t*)aligned[7],
        lengths[0], lengths[1],
        lengths[2], lengths[3],
        lengths[4], lengths[5],
        lengths[6], lengths[7],
        outputs[0], outputs[1],
        outputs[2], outputs[3],
        outputs[4], outputs[5],
        outputs[6], outputs[7]
    );

    for (int i = 0; i < 8; ++i) {
        free(aligned[i]);
    }
    return 0;
}

