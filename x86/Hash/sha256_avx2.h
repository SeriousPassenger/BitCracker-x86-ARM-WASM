#ifndef SHA256_AVX2_H
#define SHA256_AVX2_H

#include <immintrin.h>
#include <stdint.h>

// Initialize SHA-256 state with initial hash values
void sha256_avx2_initialize(__m256i* s);

// Transform function processes one block for each message
void sha256_avx2_transform(__m256i* state, const uint8_t* data[8]);

// Main function to compute SHA-256 hash for 8 messages of arbitrary size
void sha256avx2_8B(
    const uint8_t* data0, const uint8_t* data1, const uint8_t* data2, const uint8_t* data3,
    const uint8_t* data4, const uint8_t* data5, const uint8_t* data6, const uint8_t* data7,
    size_t len0, size_t len1, size_t len2, size_t len3,
    size_t len4, size_t len5, size_t len6, size_t len7,
    unsigned char* hash0, unsigned char* hash1, unsigned char* hash2, unsigned char* hash3,
    unsigned char* hash4, unsigned char* hash5, unsigned char* hash6, unsigned char* hash7);

#endif // SHA256_AVX2_H

