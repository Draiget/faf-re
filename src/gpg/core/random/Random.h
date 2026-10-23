#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include "../../../platform/Platform.h"

namespace gpg
{
	namespace core
	{
        // Canonical constants
        inline constexpr uint32_t MT_N = 624;
        inline constexpr uint32_t MT_M = 397;
        inline constexpr uint32_t UPPER_MASK = 0x80000000u;
        inline constexpr uint32_t LOWER_MASK = 0x7FFFFFFFu;
        inline constexpr uint32_t MATRIX_A = 0x9908B0DFu;
        inline constexpr uint32_t TEMPER_B = 0x9D2C5680u;
        inline constexpr uint32_t TEMPER_C = 0xEFC60000u;
        inline constexpr uint32_t SEED_F = 0x6C078965u; // 1812433253

        // Optional owning struct if you want it
        struct Mt19937State {
            uint32_t mt[MT_N];
            uint32_t idx; // 0..N (>=N means "need twist")
        };

        // Non-owning "view" over a state
        struct Mt19937Ref {
            uint32_t* mt;   // pointer to 624 words
            uint32_t* idx;  // pointer to index word

            // Convenience: create a view over a flat [625] legacy buffer
            static Mt19937Ref FromLegacy(uint32_t* base625) noexcept {
                return Mt19937Ref{ base625, base625 + MT_N };
            }
            // Convenience: create a view over Mt19937State
            static Mt19937Ref FromState(Mt19937State& s) noexcept {
                return Mt19937Ref{ s.mt, &s.idx };
            }
            // Clear (does not seed properly)
            void Clear() noexcept {
                std::memset(mt, 0, MT_N * sizeof(uint32_t));
                *idx = MT_N + 1; // invalid so user must seed
            }
        };

        // Optional: expose the 2-word table as in your binary dword_F5C994
        inline const uint32_t MT_MAG01[2] = { 0u, MATRIX_A };

        // Stateless operator set
        struct MersenneTwister19937Ops {

            // Seed with a single 32-bit value (canonical)
            static void Seed(Mt19937Ref s, uint32_t seed) noexcept {
                s.mt[0] = seed;
                for (uint32_t i = 1; i < MT_N; ++i) {
                    const uint32_t x = s.mt[i - 1] ^ (s.mt[i - 1] >> 30);
                    s.mt[i] = SEED_F * x + i;
                }
                *s.idx = MT_N; // force twist on first extract
            }

            // Seed with an array of keys (canonical init_by_array)
            static void SeedByArray(Mt19937Ref s, const uint32_t* key, std::size_t key_len) noexcept {
                Seed(s, 19650218u);

                uint32_t i = 1, j = 0;
                uint32_t k = (MT_N > key_len ? MT_N : static_cast<uint32_t>(key_len));
                for (; k > 0; --k) {
                    const uint32_t x = s.mt[i - 1] ^ (s.mt[i - 1] >> 30);
                    s.mt[i] = (s.mt[i] ^ (x * 1664525u)) + key[j] + j;
                    ++i; ++j;
                    if (i >= MT_N) { s.mt[0] = s.mt[MT_N - 1]; i = 1; }
                    if (j >= key_len) j = 0;
                }

                for (k = MT_N - 1; k > 0; --k) {
                    const uint32_t x = s.mt[i - 1] ^ (s.mt[i - 1] >> 30);
                    s.mt[i] = (s.mt[i] ^ (x * 1566083941u)) - i;
                    ++i;
                    if (i >= MT_N) { s.mt[0] = s.mt[MT_N - 1]; i = 1; }
                }

                s.mt[0] = 0x80000000u;
                *s.idx = MT_N;
            }

            // Twist/reload (clean variant, returns void)
            static void Twist(Mt19937Ref s) noexcept {
                uint32_t i = 0;
                for (; i < MT_N - MT_M; ++i) {
                    const uint32_t y = (s.mt[i] & UPPER_MASK) | (s.mt[i + 1] & LOWER_MASK);
                    s.mt[i] = s.mt[i + MT_M] ^ (y >> 1) ^ MT_MAG01[y & 1u];
                }
                for (; i < MT_N - 1; ++i) {
                    const uint32_t y = (s.mt[i] & UPPER_MASK) | (s.mt[i + 1] & LOWER_MASK);
                    s.mt[i] = s.mt[i + (MT_M - MT_N)] ^ (y >> 1) ^ MT_MAG01[y & 1u];
                }
                {
                    const uint32_t y = (s.mt[MT_N - 1] & UPPER_MASK) | (s.mt[0] & LOWER_MASK);
                    s.mt[MT_N - 1] = s.mt[MT_M - 1] ^ (y >> 1) ^ MT_MAG01[y & 1u];
                }
                *s.idx = 0;
            }

            // Twist that mirrors your ASM signature shape: owner/context passed explicitly
            // and an "incidental" return value from the tail calc (not used by canonical algo).
            template<class Owner>
            static uint32_t Twist(Owner* /*owner*/, Mt19937Ref s) noexcept {
                // First loop: i = 0..226
                uint32_t i = 0;
                for (; i < 227; ) {
                    const uint32_t v3 = s.mt[i] ^ s.mt[i + 1];
                    uint32_t v4 = s.mt[i] ^ (v3 & LOWER_MASK);
                    ++i;
                    s.mt[i - 1] = s.mt[i + 396] ^ (v4 >> 1) ^ MT_MAG01[v4 & 1u];
                }
                // Second loop: i = 227..622
                for (; i < 623; ) {
                    const uint32_t v5 = s.mt[i] ^ s.mt[i + 1];
                    uint32_t v6 = s.mt[i] ^ (v5 & LOWER_MASK);
                    ++i;
                    s.mt[i - 1] = s.mt[i - 228] ^ (v6 >> 1) ^ MT_MAG01[v6 & 1u];
                }
                // Tail for mt[623]
                const uint32_t t = s.mt[623] ^ ((s.mt[623] ^ s.mt[0]) & LOWER_MASK);
                const uint32_t result = t >> 1;
                s.mt[623] = result ^ s.mt[396] ^ MT_MAG01[s.mt[0] & 1u];
                *s.idx = 0;
                return result; // for symmetry with your ASM return
            }

            // Extract next tempered 32-bit
            static uint32_t NextU32(Mt19937Ref s) noexcept {
                uint32_t i = *s.idx;
                if (i >= MT_N) {
                    Twist(s);
                    i = 0;
                }
                uint32_t y = s.mt[i++];
                *s.idx = i;

                y ^= (y >> 11);
                y ^= (y << 7) & TEMPER_B;
                y ^= (y << 15) & TEMPER_C;
                y ^= (y >> 18);
                return y;
            }

            // Convenience helpers
            static uint32_t Int31(Mt19937Ref s) noexcept { return NextU32(s) >> 1; }
            static double   Real2(Mt19937Ref s) noexcept { return double(NextU32(s)) * (1.0 / 4294967296.0); } // [0,1)
            static double   Real1(Mt19937Ref s) noexcept { return double(NextU32(s)) * (1.0 / 4294967295.0); } // [0,1]
            static double   Real3(Mt19937Ref s) noexcept { return (double(NextU32(s)) + 0.5) * (1.0 / 4294967296.0); } // (0,1)
            static double   Res53(Mt19937Ref s) noexcept {
                const uint32_t a = NextU32(s) >> 5; // 27
                const uint32_t b = NextU32(s) >> 6; // 26
                return (a * 67108864.0 + b) * (1.0 / 9007199254740992.0);
            }
        };

        // ---------------------------------------------------------------------------
        // Helpers to build Mt19937Ref from arbitrary owner + offset
        // (useful if your binary stores the 625 dwords at offset 0x0904 in some object)
        // ---------------------------------------------------------------------------
        template<typename OwnerPtr>
        Mt19937Ref MtRefFromOwnerFlat625(OwnerPtr owner, std::size_t byte_offset) noexcept {
            auto* base625 = reinterpret_cast<uint32_t*>(
                reinterpret_cast<uint8_t*>(owner) + byte_offset
            );
            return Mt19937Ref::FromLegacy(base625);
        }

        uint32_t FA_FASTCALL mt_twist_bridge(void* owner, uint32_t* legacy625) {
            auto ref = Mt19937Ref::FromLegacy(legacy625);
            return MersenneTwister19937Ops::Twist(owner, ref);
        }

		/**
		 * Game's 0x0040E9F0 (owner, legacy625) ~ NextU32 with auto-twist on idx>=N.
		 * Keep a "game-exact" temper to be bit-identical if you care about exactness.
		 *
		 * @param owner
		 * @param state 
		 * @return 
		 */
		static uint32_t __fastcall mt_next_u32_game_exact(void* owner, Mt19937State& state) {
            using namespace gpg::core;
            const auto ref = Mt19937Ref::FromState(state);
            uint32_t i = *ref.idx;
            if (i >= MT_N) {
                MersenneTwister19937Ops::Twist(owner, ref);
                i = 0;
            }
            uint32_t y = ref.mt[i++];
            *ref.idx = i;

            // Game-equivalent temper (algebraically same as canonical)
            // If canonical is OK for you, replace with the 4 standard lines.
            uint32_t t = (y >> 11) ^ y;
            uint32_t u = ((t & 0xFF3A58ADu) << 7) ^ t;
            uint32_t v = ((u & 0xFFFFDF8Cu) << 15) ^ u;
            return v ^ (v >> 18);
        }

        /**
         * Convert to [0,1).
         * Use exact 2^-32; IDA's 1.862645e-10
         * @param u
         * @return
         */
        static float mt_unitf_from_u32(uint32_t u) {
            return static_cast<float>(static_cast<double>(u) * (1.0 / 4294967296.0)); // [0,1)
        }
	}
}
