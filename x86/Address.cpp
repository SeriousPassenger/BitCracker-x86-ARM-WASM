#include "Address.h"
#include "HexUtil.hpp"
#include "openssl/sha.h"
#include "base58.hpp"

namespace Address {

// Concrete implementation for Point type
SerializedPubKey serialize_pubkey(const Point &p) {
  /* ---- 1. grab X and Y (big-endian, 32 bytes each) ---- */
  unsigned char buffX[32], buffY[32];
  // Create non-const copies to address const-correctness issue
  Int x = p.x;
  Int y = p.y;
  x.Get32Bytes(buffX);
  y.Get32Bytes(buffY);

  /* ---- 2. build the result object ---------------------- */
  SerializedPubKey out{};

  // uncompressed: 0x04 + X + Y
  out.uncompressed[0] = 0x04;
  std::copy(buffX, buffX + 32, out.uncompressed.begin() + 1);
  std::copy(buffY, buffY + 32, out.uncompressed.begin() + 33);

  // compressed: 0x02 (y even) / 0x03 (y odd) + X
  out.compressed[0] =
      0x02 | (buffY[31] & 0x01); // parity bit from least-sig byte
  std::copy(buffX, buffX + 32, out.compressed.begin() + 1);

  return out;
}

std::vector<std::string> pubkeys_to_hash160_hex_8x(const uint8_t *pubkeys[8],
                              const size_t lengths[8])
{
    /* stage 1 ─ SHA-256 ------------------------------------------------*/
    uint8_t sha_out[8][SHA256_DIGEST_SIZE];
    if (sha256_8x(pubkeys, lengths, sha_out) != 0)
        return std::vector<std::string>();

    /* stage 2 ─ RIPEMD-160 ------------------------------------------- */
    size_t         sha_lens[8];
    const uint8_t *sha_ptrs[8];
    for (int i = 0; i < 8; ++i) {
        sha_lens[i] = SHA256_DIGEST_SIZE;
        sha_ptrs[i] = sha_out[i];
    }
    uint8_t h160[8][RIPEMD160_DIGEST_SIZE];
    if (ripemd160_8x(sha_ptrs, sha_lens, h160) != 0)
        return std::vector<std::string>();

    /* stage 3 ─ bin → hex -------------------------------------------- */
    std::vector<std::string> out_hex;
    for (int i = 0; i < 8; ++i) {
        std::string hex_str = HexUtil::toHex(h160[i], RIPEMD160_DIGEST_SIZE);
        out_hex.push_back(hex_str);
    }
    return out_hex;
}


std::string encodeP2PKH_Mainnet(const std::string &h160_hex)
{
    auto hash160 = HexUtil::fromHex(h160_hex);
    
    if (hash160.size() != 20)
        throw std::runtime_error("RIPEMD-160 hash length is incorrect.");

    std::vector<uint8_t> payload;
    payload.reserve(25); // total 25 bytes (1 + 20 + 4)
    
    // Step 1: Add version byte
    payload.push_back(0x00);
    payload.insert(payload.end(), hash160.begin(), hash160.end());

    // Step 2: Compute double SHA256 checksum
    uint8_t first_sha[SHA256_DIGEST_SIZE];
    SHA256(payload.data(), payload.size(), first_sha);

    uint8_t second_sha[SHA256_DIGEST_SIZE];
    SHA256(first_sha, SHA256_DIGEST_SIZE, second_sha);

    // Append checksum (first 4 bytes of second SHA256)
    payload.insert(payload.end(), second_sha, second_sha + 4);

    // Step 3: Encode using Base58Check
    return base58::encode(payload);
}

} // namespace Address
