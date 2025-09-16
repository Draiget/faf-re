#pragma once

#include "Angle.h"
#include <cmath>
#include "platform/Platform.h"

// --- Feature switches ---
#ifndef MOHO_USE_SSE2
	#if defined(__SSE2__) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2) || defined(_M_X64)
		#define MOHO_USE_SSE2 1
	#else
		#define MOHO_USE_SSE2 0
	#endif
#endif

// Optional: allow dp_ps on SSE4.1 for dot; we don't strictly need it in the chosen kernel.
#ifndef MOHO_USE_SSE41
	#if defined(__SSE4_1__) || defined(_M_IX86_FP) || defined(_M_X64)
	#define MOHO_USE_SSE41 0
	#endif
#endif

namespace moho
{
    /**
     * 4D vector (also used as a SIMD row). Aligned for fast loads/stores.
     */
    struct alignas(16) Vector4f
	{
        float x{}, y{}, z{}, w{};

#if MOHO_USE_SSE2
        // Aligned load/store
        MOHO_FORCEINLINE __m128 load() const { return _mm_load_ps(&x); }
        MOHO_FORCEINLINE void store(__m128 v) { _mm_store_ps(&x, v); }

        /** Compile-time splat: Lane is template immediate -> valid for _mm_shuffle_ps. */
        template<int Lane>
        static MOHO_FORCEINLINE __m128 splat(__m128 v) {
            static_assert(Lane >= 0 && Lane <= 3, "Lane out of range");
            return _mm_shuffle_ps(v, v, _MM_SHUFFLE(Lane, Lane, Lane, Lane));
        }

        /** Runtime splat wrapper: dispatches to compile-time variants (keeps imm8 constant). */
        static MOHO_FORCEINLINE __m128 splat_lane(__m128 v, int i) {
            switch (i & 3) {
            case 0: return splat<0>(v);
            case 1: return splat<1>(v);
            case 2: return splat<2>(v);
            default: return splat<3>(v);
            }
        }
#endif

        /** Convert a quaternion (x,y,z,w) to Euler XYZ (roll, pitch, yaw), radians. */
        [[nodiscard]] Angle quaternion_to_euler() const;
	};
}
