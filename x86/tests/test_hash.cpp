#include <cstdio>
#include <cstring>
#include <stdint.h>
#include "../Hash/Hash.h"

static void to_hex(const uint8_t* digest, size_t len, char* out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        out[i*2] = hex[(digest[i] >> 4) & 0xF];
        out[i*2 + 1] = hex[digest[i] & 0xF];
    }
    out[len*2] = '\0';
}

int main() {
    const char* messages[8] = {"", "abc", "hello world", "BitCrack",
                                "test", "1234567890", "OpenAI", "foo bar"};
    const char* sha_expect[8] = {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        "dd8a07f4f180cdd21a22edef65e6a23820aa1c6e65b119cffa31fda567512a4f",
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "c775e7b757ede630cd0aa1113bd102661ab38829ca52a6422ab782862f268646",
        "8b7d1a3187ab355dc31bc683aaa71ab5ed217940c12196a9cd5f4ca984babfa4",
        "fbc1a9f858ea9e177916964bd88c3d37b91a1e84412765e29950777f265c4b75"};
    const char* ripemd_expect[8] = {
        "9c1185a5c5e9fc54612808977ee8f548b2258d31",
        "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
        "98c615784ccb5fe5936fbc0cbe9dfdb408d92f0f",
        "604012d06a8331ea7ebfe563d0b74f7f2930a955",
        "5e52fee47e6b070565f74372468cdc699de89107",
        "9d752daa3fb4df29837088e1e5a1acf74932e074",
        "303e5cdaf4970c8ae7572a9a7864ef341ca9c14d",
        "daba326b8e276af34297f879f6234bcef2528efa"};

    const uint8_t* inputs[8];
    size_t lengths[8];
    for (int i = 0; i < 8; ++i) {
        inputs[i] = (const uint8_t*)messages[i];
        lengths[i] = strlen(messages[i]);
    }

    uint8_t sha_out[8][SHA256_DIGEST_SIZE];
    uint8_t rip_out[8][RIPEMD160_DIGEST_SIZE];

    if (sha256_8x(inputs, lengths, sha_out) != 0) {
        printf("sha256_8x failed\n");
        return 1;
    }
    if (ripemd160_8x(inputs, lengths, rip_out) != 0) {
        printf("ripemd160_8x failed\n");
        return 1;
    }

    char hexbuf[65];
    for (int i = 0; i < 8; ++i) {
        to_hex(sha_out[i], SHA256_DIGEST_SIZE, hexbuf);
        if (strcmp(hexbuf, sha_expect[i]) != 0) {
            printf("SHA256 mismatch %d: %s != %s\n", i, hexbuf, sha_expect[i]);
            return 1;
        }
    }

    char hexbuf2[41];
    for (int i = 0; i < 8; ++i) {
        to_hex(rip_out[i], RIPEMD160_DIGEST_SIZE, hexbuf2);
        if (strcmp(hexbuf2, ripemd_expect[i]) != 0) {
            printf("RIPEMD160 mismatch %d: %s != %s\n", i, hexbuf2, ripemd_expect[i]);
            return 1;
        }
    }

    printf("All AVX2 hash tests passed\n");
    return 0;
}
