// Simple inline utility functions for string and hex conversions.
#pragma once

#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <cstdint>

namespace HexUtil {
    inline std::string toHex(unsigned char* data, size_t length) {
        std::stringstream ss;
        ss << std::hex << std::uppercase;
        for (size_t i = 0; i < length; ++i) {
            ss << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
        }
        return ss.str();
    }

   inline std::vector<uint8_t> fromHex(const std::string& hex) {
    auto hexchar_to_int = [](char c) -> uint8_t {
        if ('0' <= c && c <= '9') return c - '0';
        if ('a' <= c && c <= 'f') return c - 'a' + 10;
        if ('A' <= c && c <= 'F') return c - 'A' + 10;
        throw std::invalid_argument("Invalid hex character");
    };

    if (hex.length() % 2 != 0) {
        throw std::invalid_argument("Hex string length must be even");
    }

    std::vector<uint8_t> bytes;
    bytes.reserve(hex.length() / 2);

    for (size_t i = 0; i < hex.length(); i += 2) {
        uint8_t high = hexchar_to_int(hex[i]);
        uint8_t low = hexchar_to_int(hex[i + 1]);
        bytes.push_back((high << 4) | low);
    }

    return bytes;
}
}
