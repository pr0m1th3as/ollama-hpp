#ifndef SHA256_HPP
#define SHA256_HPP
// tiny_sha256.hpp — header-only SHA-256 (C++11)
//
// Usage:
//   #include "tiny_sha256.hpp"
//   std::string h1 = sha256("hello");          // big-endian hex (standard)
//   std::string h2 = sha256("hello", true);    // little-endian hex per 32-bit word
//
// Public API:
//   inline std::string sha256(const std::string& s, bool little_endian=false);

#include <array>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace hash
{

    inline std::string sha256(const std::string& s, bool little_endian = false) {
        // --- helpers (C++11 lambdas) ---
        const auto ROTR = [](uint32_t x, uint32_t n) -> uint32_t {
            return (x >> n) | (x << (32u - n));
        };
        const auto Ch = [](uint32_t x, uint32_t y, uint32_t z) -> uint32_t {
            return (x & y) ^ (~x & z);
        };
        const auto Maj = [](uint32_t x, uint32_t y, uint32_t z) -> uint32_t {
            return (x & y) ^ (x & z) ^ (y & z);
        };
        const auto bigSigma0 = [&](uint32_t x) -> uint32_t {
            return ROTR(x, 2u) ^ ROTR(x, 13u) ^ ROTR(x, 22u);
        };
        const auto bigSigma1 = [&](uint32_t x) -> uint32_t {
            return ROTR(x, 6u) ^ ROTR(x, 11u) ^ ROTR(x, 25u);
        };
        const auto smallSigma0 = [&](uint32_t x) -> uint32_t {
            return ROTR(x, 7u) ^ ROTR(x, 18u) ^ (x >> 3u);
        };
        const auto smallSigma1 = [&](uint32_t x) -> uint32_t {
            return ROTR(x, 17u) ^ ROTR(x, 19u) ^ (x >> 10u);
        };

        static const uint32_t K[64] = {
            0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
            0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
            0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
            0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
            0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
            0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
            0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
            0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
        };

        // Initial hash values (H0..H7)
        std::array<uint32_t, 8> H = {{
            0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
            0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
        }};

        // --- Preprocessing (padding) ---
        std::vector<uint8_t> data(s.begin(), s.end());
        data.push_back(0x80u); // append '1' bit

        while ((data.size() % 64u) != 56u) data.push_back(0x00u);

        const uint64_t bitlen = static_cast<uint64_t>(s.size()) * 8u;
        for (int i = 7; i >= 0; --i)
            data.push_back(static_cast<uint8_t>((bitlen >> (8*i)) & 0xFFu));

        // --- Process 512-bit chunks ---
        for (size_t offset = 0; offset < data.size(); offset += 64) {
            uint32_t w[64];

            for (int i = 0; i < 16; ++i) {
                const size_t j = offset + static_cast<size_t>(i) * 4u;
                w[i] = (static_cast<uint32_t>(data[j])   << 24)
                    | (static_cast<uint32_t>(data[j+1]) << 16)
                    | (static_cast<uint32_t>(data[j+2]) << 8)
                    |  static_cast<uint32_t>(data[j+3]);
            }
            for (int i = 16; i < 64; ++i)
                w[i] = smallSigma1(w[i-2]) + w[i-7] + smallSigma0(w[i-15]) + w[i-16];

            uint32_t a = H[0], b = H[1], c = H[2], d = H[3];
            uint32_t e = H[4], f = H[5], g = H[6], h = H[7];

            for (int i = 0; i < 64; ++i) {
                const uint32_t T1 = h + bigSigma1(e) + Ch(e, f, g) + K[i] + w[i];
                const uint32_t T2 = bigSigma0(a) + Maj(a, b, c);
                h = g; g = f; f = e;
                e = d + T1;
                d = c; c = b; b = a;
                a = T1 + T2;
            }

            H[0] += a; H[1] += b; H[2] += c; H[3] += d;
            H[4] += e; H[5] += f; H[6] += g; H[7] += h;
        }

        // --- Produce digest bytes (big-endian words) ---
        std::array<uint8_t, 32> digest;
        for (std::size_t i = 0; i < H.size(); ++i) {
            digest[4*i + 0] = static_cast<uint8_t>((H[i] >> 24) & 0xFFu);
            digest[4*i + 1] = static_cast<uint8_t>((H[i] >> 16) & 0xFFu);
            digest[4*i + 2] = static_cast<uint8_t>((H[i] >>  8) & 0xFFu);
            digest[4*i + 3] = static_cast<uint8_t>((H[i]      ) & 0xFFu);
        }

        // If requested, output little-endian per 32-bit word:
        // i.e., reverse the byte order within each 4-byte word, not the word order.
        if (little_endian) {
            for (int i = 0; i < 8; ++i) {
                uint8_t& b0 = digest[4*i + 0];
                uint8_t& b1 = digest[4*i + 1];
                uint8_t& b2 = digest[4*i + 2];
                uint8_t& b3 = digest[4*i + 3];
                std::swap(b0, b3);
                std::swap(b1, b2);
            }
        }

        // Hex encode
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (uint8_t b : digest) oss << std::setw(2) << static_cast<unsigned>(b);
        return oss.str();
    }

}

#endif
