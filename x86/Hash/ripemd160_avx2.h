#ifndef RIPEMD160_AVX2_H
#define RIPEMD160_AVX2_H

#include <immintrin.h>
#include <stdint.h>

// Initialize RIPEMD-160 state
void ripemd160_avx2_initialize(__m256i *state);

// Transform AVX2
void ripemd160_avx2_transform(__m256i *state, uint8_t *blocks[8]);

// Hashing functions
void ripemd160avx2_32(
    unsigned char *i0, unsigned char *i1, unsigned char *i2, unsigned char *i3,
    unsigned char *i4, unsigned char *i5, unsigned char *i6, unsigned char *i7,
    size_t len0, size_t len1, size_t len2, size_t len3,
    size_t len4, size_t len5, size_t len6, size_t len7,
    unsigned char *d0, unsigned char *d1, unsigned char *d2, unsigned char *d3,
    unsigned char *d4, unsigned char *d5, unsigned char *d6, unsigned char *d7);

#endif  // RIPEMD160_AVX2_H
