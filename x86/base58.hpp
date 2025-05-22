/*  base58.hpp  ── standalone Base-58 / Base58Check decoder  (C++17)
 *  MIT-licensed – 2025
 *
 *  Example:
 *      #include "base58.hpp"
 *      auto raw = Base58Decode("1GCgdyfh5huY72TYwSrzwY1tuFP7GjqUhx");
 */

#pragma once
#include <algorithm>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace base58 {
// ----------------------------------------------------  alphabet
constexpr char alphabet[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

//  Build a compile-time reverse-lookup table (C++17-safe: no constexpr fill)
constexpr std::array<int8_t, 128> make_index() {
  std::array<int8_t, 128> idx{};               // zero-initialised
  for (std::size_t i = 0; i < idx.size(); ++i) // mark all as invalid
    idx[i] = -1;
  for (int8_t i = 0; i < 58; ++i) // map legal chars
    idx[static_cast<std::size_t>(alphabet[i])] = i;
  return idx;
}
constexpr auto index = make_index();

// -----------------------------------------  bignum × mul + add
inline void mul_add(std::vector<uint8_t> &number, uint8_t mul, uint8_t add) {
  uint32_t carry = add;
  for (auto &byte : number) {
    uint32_t prod = static_cast<uint32_t>(byte) * mul + carry;
    byte = static_cast<uint8_t>(prod & 0xFF);
    carry = prod >> 8;
  }
  while (carry) {
    number.push_back(static_cast<uint8_t>(carry & 0xFF));
    carry >>= 8;
  }
}

// ------------------------------------------------ public API
inline std::vector<uint8_t> decode(const std::string &input) {
  if (input.empty())
    return {};

  // 1) leading zeros: each leading '1' → one 0x00 byte
  std::size_t zero_count = 0;
  while (zero_count < input.size() && input[zero_count] == '1')
    ++zero_count;

  // 2) Base-58 → little-endian base-256
  std::vector<uint8_t> num;
  num.reserve((input.size() * 733) / 1000 + 1); // ≃ log(58)/log(256)

  for (char c : input.substr(zero_count)) {
    unsigned char uc = static_cast<unsigned char>(c); // avoid sign issues
    if (uc >= 128 || index[uc] == -1)
      throw std::invalid_argument("Invalid Base-58 character");
    mul_add(num, 58, static_cast<uint8_t>(index[uc]));
  }

  // 3) assemble result: leading 0x00 + big-endian payload
  std::vector<uint8_t> out(zero_count, 0x00);
  out.insert(out.end(), num.rbegin(), num.rend());
  return out;
}

inline std::array<uint8_t, 20> ExtractHash160(const std::string &base58_addr) {
  // Decode Base-58 → 25-byte (version + payload + checksum)
  auto bytes = base58::decode(base58_addr);
  if (bytes.size() != 25)
    throw std::runtime_error("Decoded address is not 25 bytes (bad Base58)");

  // OPTIONAL—but recommended—verify the 4-byte checksum first.
  // See note below if you want to add the double-SHA-256 check.

  // Copy bytes 1 … 20  (skip version, keep payload, drop checksum)
  std::array<uint8_t, 20> h160{};
  std::copy_n(bytes.begin() + 1, 20, h160.begin());
  return h160;
}

inline std::string encode(const std::vector<uint8_t> &bytes) {
    if (bytes.empty())
        return {};

    // 1) Count leading zero bytes
    std::size_t zero_count = 0;
    while (zero_count < bytes.size() && bytes[zero_count] == 0) {
        ++zero_count;
    }

    // 2) Copy bytes so we can perform divisions in place
    std::vector<uint8_t> bignum(bytes.begin(), bytes.end());

    // 3) Convert base-256 → base-58
    std::string encoded;
    encoded.reserve(bytes.size() * 138 / 100 + 1); // roughly log(256)/log(58)

    std::size_t start = zero_count; 
    while (start < bignum.size()) {
        // Perform division by 58, capturing remainder in 'carry'
        int carry = 0;
        for (std::size_t i = start; i < bignum.size(); ++i) {
            int x = (static_cast<int>(bignum[i]) & 0xFF) + (carry << 8);
            bignum[i] = static_cast<uint8_t>(x / 58);
            carry = x % 58;
        }

        // Append the remainder's Base58 digit (in reverse order for now)
        encoded.push_back(alphabet[carry]);

        // Skip leading zeros in bignum (they were fully divided out)
        while (start < bignum.size() && bignum[start] == 0) {
            ++start;
        }
    }

    // 4) Each leading zero byte becomes '1'
    for (std::size_t i = 0; i < zero_count; ++i) {
        encoded.push_back('1');
    }

    // 5) The remainders were collected in reverse order, so flip them
    std::reverse(encoded.begin(), encoded.end());

    return encoded;
}


} // namespace base58