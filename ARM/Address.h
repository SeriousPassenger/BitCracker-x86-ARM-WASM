#pragma once

#include "include/Point.h"
#include <array>
#include <vector>

#define HEXSTR_BYTES (RIPEMD160_DIGEST_SIZE * 2 + 1) /* 41 */

/*---------------------------------------------------------------
    A light container for the two encodings
  --------------------------------------------------------------*/
struct SerializedPubKey {
  std::array<unsigned char, 65> uncompressed; // 0x04 || X || Y
  std::array<unsigned char, 33> compressed;   // 0x02/0x03 || X

  /* optional convenience accessors */
  std::vector<unsigned char> uncompressed_vec() const {
    return {uncompressed.begin(), uncompressed.end()};
  }

  std::vector<unsigned char> compressed_vec() const {
    return {compressed.begin(), compressed.end()};
  }
};

namespace Address {
// Non-template specific function for Point type
SerializedPubKey serialize_pubkey(const Point &p);

std::string pubkey_to_hash160_hex(const uint8_t *pubkey, const size_t length);

std::string encodeP2PKH_Mainnet(const std::string &h160_hex);
} // namespace Address
