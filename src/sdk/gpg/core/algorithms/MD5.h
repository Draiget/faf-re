#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <bit>

#include "legacy/containers/String.h" // msvc8::string

namespace gpg
{
    struct MD5Digest
    {
        /**
         * Raw 128-bit digest as 4 little-endian 32-bit words.
         */
        uint32_t vals[4];

        /**
         * Address: 0x0073B100
         * Compare with another digest (pointer semantics to match original ABI).
         */
        bool operator!=(MD5Digest* rhs) const;

        /**
         * Address: 0x008E5910
         * Convert digest to 32-character lowercase hexadecimal string.
         */
        [[nodiscard]] msvc8::string ToString() const;
    };

    struct MD5Block
    {
        /**
         * 56 data bytes of the MD5 64-byte block (last 8 for length).
         */
        uint8_t vals[56];
        /**
         * Bit length (little-endian) stored in the last 8 bytes of a block.
         */
        int64_t size;
    };

    struct MD5Context
    {
        /**
         * Current digest state (A,B,C,D).
         */
        MD5Digest digest;
        /**
         * Current working 64-byte block buffer.
         */
        MD5Block block;
        /**
         * Current position inside block [0..63].
         */
        uint32_t pos;

        // Keep MSVC8 x86 layout stable: int64 aligned at 8 bytes -> add explicit pad.
        uint32_t pad_; // unused, ensures offsetof(size) == 88 on x86 MSVC8

        /**
         * Total number of bytes fed into the context.
         */
        int64_t size;

        /**
         * Address: 0x004A48B0
         * Update with a std::string; includes the trailing '\0' like original code.
         */
        void Update(std::string s);

        /**
         * Address: 0x008E4F40
         * Reset context to MD5 initial vector.
         */
        void Reset();

        /**
         * Address: 0x008E4F70
         * Round function F (choice) used in round 1.
         */
        [[nodiscard]]
        static int RoundFunc1(const int b, const int c, const int d) {
            return (b & c) | (d & ~b);
        }

        /**
         * Address: 0x008E4F80
         * One step of round 1.
         */
        int Round1(const int v, const int a, int b, const int c, const int d, const int h, const char s) const {
            return b + rol32i(v + a + RoundFunc1(b, c, d) + h, static_cast<int>(s));
        }

        /**
         * Address: 0x008E4FB0
         * Round function G used in round 2.
         */
        int RoundFunc2(const int b, const int c, const int d) const {
            return (b & d) | (c & ~d);
        }

        /**
         * Address: 0x008E4FC0
         * One step of round 2.
         */
        int Round2(const int v, const int a, int b, const int c, const int d, const int h, const char s) const {
            return b + rol32i(v + a + RoundFunc2(b, c, d) + h, static_cast<int>(s));
        }

        /**
         * Address: 0x008E4FF0
         * Round function H used in round 3.
         */
        int RoundFunc3(const int b, const int c, const int d) const {
            return b ^ c ^ d;
        }

        /**
         * Address: 0x008E5000
         * One step of round 3.
         */
        int Round3(const int v, const int a, int b, const int c, const int d, const int h, const char s) const {
            return b + rol32i(v + a + RoundFunc3(b, c, d) + h, static_cast<int>(s));
        }

        /**
         * Address: 0x008E5020
         * Round function I used in round 4.
         */
        int RoundFunc4(const int b, const int c, const int d) const {
            return c ^ (b | ~d);
        }

        /**
         * Address: 0x008E5030
         * One step of round 4.
         */
        int Round4(const int v, const int a, int b, const int c, const int d, const int h, const char s) const {
            return b + rol32i(v + a + RoundFunc4(b, c, d) + h, static_cast<int>(s));
        }

        /**
         * Address: 0x008E5050
         * Process one 64-byte block pointed by src; updates 'out' state in place.
         */
        static void ProcessBlock(MD5Digest& out, const void* src);

        /**
         * Address: 0x008E5790
         * Finalize into a digest without mutating the context (uses a copy).
         */
        MD5Digest Digest() const;

        /**
         * Address: 0x008E5870
         * Update with a raw memory buffer.
         */
        void Update(const void* ptr, size_t len);

    private:
        /**
         * Portable 32-bit left rotate for signed int parameters.
         */
        static int rol32i(const int x, const int s) noexcept {
            const uint32_t u = static_cast<uint32_t>(x);
            const uint32_t n = static_cast<uint32_t>(s) & 31u;
            return static_cast<int>((u << n) | (u >> ((32u - n) & 31u)));
        }
    };

    /**
     * Address: 0x008E3EA0
     * Hash a single 32-bit value with salt (implementation elsewhere).
     */
    unsigned int HashDword/*guess*/(unsigned int dat, unsigned int salt);

    /**
     * Address: 0x008E3EC0
     * Hash an arbitrary byte buffer with salt (implementation elsewhere).
     */
    unsigned int HashBytes(const void* dat, size_t size, unsigned int salt);

    /**
     * Address: 0x008E3F40
     * Hash a std::string with salt (implementation elsewhere).
     */
    unsigned int Hash(const std::string& dat, unsigned int salt);

    // --- Layout checks (x86/MSVC8 expectations) ---
    static_assert(sizeof(MD5Digest) == 16, "MD5Digest must be 16 bytes");
    static_assert(offsetof(MD5Block, size) == 56, "MD5Block.size must be at +56");
    static_assert(sizeof(MD5Block) == 64, "MD5Block must be 64 bytes");
    static_assert(offsetof(MD5Context, digest) == 0, "MD5Context.digest offset");
    static_assert(offsetof(MD5Context, block) == 16, "MD5Context.block offset");
    static_assert(offsetof(MD5Context, pos) == 80, "MD5Context.pos offset");
    static_assert(offsetof(MD5Context, size) == 88, "MD5Context.size offset");
}
