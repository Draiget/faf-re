#include "MD5.h"
#include <array>
#include <algorithm>

namespace gpg
{
    /**
     * Load 16 little-endian 32-bit words from an unaligned 64-byte buffer.
     */
    static inline void load_block_le(const void* src, uint32_t(&M)[16]) {
        // Avoid unaligned access: memcpy to local words
        std::memcpy(M, src, 64);
        // Host is little-endian on x86; if you ever port to BE, byteswap here.
    }

    bool MD5Digest::operator!=(MD5Digest* rhs) const
    {
        // Keep exact pointer-parameter semantics as in the original binary.
        return rhs->vals[0] != vals[0]
            || rhs->vals[1] != vals[1]
            || rhs->vals[2] != vals[2]
            || rhs->vals[3] != vals[3];
    }

    msvc8::string MD5Digest::ToString() const
    {
        static constexpr char HEX[] = "0123456789abcdef";
        msvc8::string out;
        out.resize(32); // reserve exactly 32 characters

        // Iterate raw bytes in memory order (matches original ToString)
        auto b = reinterpret_cast<const uint8_t*>(vals);
        for (size_t i = 0; i < 16; ++i) {
            uint8_t v = b[i];
            out[2 * i + 0] = HEX[v >> 4];
            out[2 * i + 1] = HEX[v & 0xF];
        }
        return out;
    }

    void MD5Context::Reset()
    {
        pos = 0;
        size = 0;
        digest.vals[0] = 0x67452301u;
        digest.vals[1] = 0xEFCDAB89u;
        digest.vals[2] = 0x98BADCFEu;
        digest.vals[3] = 0x10325476u;
        // block content can remain undefined until used; we clear on padding path.
    }

    void MD5Context::Update(std::string s)
    {
        // Original passed size+1 to include trailing '\0'
        const char* p = s.c_str();
        Update(p, s.size() + 1);
    }

    void MD5Context::Update(const void* ptr, size_t len)
    {
        // Accumulate total byte count
        size += static_cast<int64_t>(len);

        auto src = static_cast<const uint8_t*>(ptr);

        // If we have a partial block, fill it first
        if (pos != 0) {
            size_t need = 64u - pos;
            if (need > len) need = len;

            std::memcpy(&block.vals[pos], src, need);
            pos += need;
            src += need;
            len -= need;

            if (pos == 64u) {
                ProcessBlock(digest, block.vals);
                pos = 0;
            }
        }

        // Process full 64-byte blocks directly from input
        while (len >= 64u) {
            ProcessBlock(digest, src);
            src += 64;
            len -= 64;
        }

        // Stash remainder into the working block
        if (len) {
            std::memcpy(&block.vals[0], src, len);
            pos = len;
        }
    }

    MD5Digest MD5Context::Digest() const
    {
        // Work on a copy of the running state to keep context immutable
        MD5Digest out = digest;

        // Local shadow of the block to apply padding
        MD5Block tmp = block;

        // Append 0x80 at current position
        tmp.vals[pos] = 0x80;

        if (63u - pos < 8u) {
            // Not enough space for length -> zero to end, process,
            // then process an all-zero block with only the bit length set.
            if (pos + 1u <= 63u) {
                std::memset(&tmp.vals[pos + 1u], 0, 63u - pos);
            }
            ProcessBlock(out, tmp.vals);

            // second block: all zeros except length at the tail
            std::memset(&tmp, 0, sizeof(MD5Block));
            tmp.size = static_cast<int64_t>(size) * 8ll;
            ProcessBlock(out, &tmp.vals[0]);
        } else {
            // Enough room: zero-fill until the last 8 bytes,
            // write bit length there, process once.
            const uint32_t zeroCount = (63u - pos - 8u);
            if (zeroCount) {
                std::memset(&tmp.vals[pos + 1u], 0, zeroCount);
            }
            tmp.size = static_cast<int64_t>(size) * 8ll;
            ProcessBlock(out, tmp.vals);
        }

        return out;
    }

    void MD5Context::ProcessBlock(gpg::MD5Digest& out, const void* src) {
        // Standard MD5 round constants
        static constexpr uint32_t K[64] = {
            0xd76aa478u,0xe8c7b756u,0x242070dBu,0xc1bdceeeu,0xf57c0fafu,0x4787c62Au,0xa8304613u,0xfd469501u,
            0x698098d8u,0x8b44f7afu,0xffff5bb1u,0x895cd7beu,0x6b901122u,0xfd987193u,0xa679438eu,0x49b40821u,
            0xf61e2562u,0xc040b340u,0x265e5a51u,0xe9b6c7aau,0xd62f105du,0x02441453u,0xd8a1e681u,0xe7d3fbc8u,
            0x21e1cde6u,0xc33707d6u,0xf4d50d87u,0x455a14edu,0xa9e3e905u,0xfcefa3f8u,0x676f02d9u,0x8d2a4c8au,
            0xfffa3942u,0x8771f681u,0x6d9d6122u,0xfde5380cu,0xa4beea44u,0x4bdecfau, 0xf6bb4b60u,0xbebfbc70u,
            0x289b7ec6u,0xeaA127FAu,0xd4ef3085u,0x04881d05u,0xd9d4d039u,0xe6db99e5u,0x1fa27cf8u,0xc4ac5665u,
            0xf4292244u,0x432aff97u,0xab9423a7u,0xfc93a039u,0x655b59c3u,0x8f0ccc92u,0xffeff47du,0x85845dd1u,
            0x6fa87e4fu,0xfe2ce6e0u,0xa3014314u,0x4e0811a1u,0xf7537e82u,0xbd3af235u,0x2ad7d2bbu,0xeb86d391u
        };
        static constexpr uint32_t S[64] = {
            7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
            5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
            4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
            6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
        };

        uint32_t M[16];
        load_block_le(src, M);

        uint32_t a = out.vals[0];
        uint32_t b = out.vals[1];
        uint32_t c = out.vals[2];
        uint32_t d = out.vals[3];

        auto F = [](uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); };
        auto G = [](uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); };
        auto H = [](uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; };
        auto I = [](uint32_t x, uint32_t y, uint32_t z) { return y ^ (x | ~z); };

        // Round 1
        auto step = [](uint32_t f, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t m, uint32_t k, uint32_t s) {
            return b + std::rotl(a + f + m + k, s);
            };

        // 64 steps with index permutations per RFC 1321
        for (uint32_t i = 0; i < 16; ++i) {
            uint32_t f = F(b, c, d);
            uint32_t t = step(f, a, b, c, d, M[i], K[i], S[i]);
            a = d; d = c; c = b; b = t;
        }
        for (uint32_t i = 16; i < 32; ++i) {
            uint32_t gidx = (5u * i + 1u) & 15u;
            uint32_t f = G(b, c, d);
            uint32_t t = step(f, a, b, c, d, M[gidx], K[i], S[i]);
            a = d; d = c; c = b; b = t;
        }
        for (uint32_t i = 32; i < 48; ++i) {
            uint32_t hidx = (3u * i + 5u) & 15u;
            uint32_t f = H(b, c, d);
            uint32_t t = step(f, a, b, c, d, M[hidx], K[i], S[i]);
            a = d; d = c; c = b; b = t;
        }
        for (uint32_t i = 48; i < 64; ++i) {
            uint32_t iidx = (7u * i) & 15u;
            uint32_t f = I(b, c, d);
            uint32_t t = step(f, a, b, c, d, M[iidx], K[i], S[i]);
            a = d; d = c; c = b; b = t;
        }

        out.vals[0] += a;
        out.vals[1] += b;
        out.vals[2] += c;
        out.vals[3] += d;
    }
}
