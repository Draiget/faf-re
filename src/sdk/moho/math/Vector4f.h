#pragma once

#include "Angle.h"
#include "platform/Platform.h"
#include "legacy/containers/String.h"
#include <cstdint>
#include <cmath>

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
   * 4D vector (also used as a SIMD row).
   *
   * Binary-layout note:
   * This type is stored inline in ABI-facing engine objects (for example Entity).
   * Keep default x86-style 4-byte alignment to preserve recovered offsets.
   */
  struct Vector4f
  {
    float x{}, y{}, z{}, w{};

    Vector4f() noexcept = default;

    /**
     * Address: 0x0046FAB0 (FUN_0046FAB0, Moho::Vector4f::Vector4f)
     *
     * float,float,float,float
     *
     * What it does:
     * Initializes all four scalar lanes in-order.
     */
    Vector4f(float xValue, float yValue, float zValue, float wValue) noexcept;

    /**
     * Address: 0x0046FAE0 (FUN_0046FAE0, Moho::Vector4f::operator[])
     *
     * What it does:
     * Returns one scalar lane by unchecked index.
     */
    [[nodiscard]] float operator[](std::uint32_t index) const noexcept;

    /**
     * Address: 0x0046FAF0 (FUN_0046FAF0, Moho::Vector4f::X)
     *
     * What it does:
     * Returns x lane.
     */
    [[nodiscard]] float X() const noexcept;

    /**
     * Address: 0x0046FB00 (FUN_0046FB00, Moho::Vector4f::Y)
     *
     * What it does:
     * Returns y lane.
     */
    [[nodiscard]] float Y() const noexcept;

    /**
     * Address: 0x0046FB10 (FUN_0046FB10, Moho::Vector4f::Z)
     *
     * What it does:
     * Returns z lane.
     */
    [[nodiscard]] float Z() const noexcept;

    /**
     * Address: 0x0046FB20 (FUN_0046FB20, Moho::Vector4f::operator=)
     *
     * What it does:
     * Copies all four scalar lanes from rhs.
     */
    Vector4f& operator=(const Vector4f& rhs) noexcept;

    /**
     * Address: 0x0046FB40 (FUN_0046FB40, Moho::Vector4f::operator*=)
     *
     * What it does:
     * Multiplies all scalar lanes by one uniform scalar.
     */
    Vector4f& operator*=(float scalar) noexcept;

#if MOHO_USE_SSE2
    // Unaligned load/store keeps ABI alignment at 4 bytes.
    MOHO_FORCEINLINE __m128 load() const
    {
      return _mm_loadu_ps(&x);
    }
    MOHO_FORCEINLINE void store(__m128 v)
    {
      _mm_storeu_ps(&x, v);
    }

    /** Compile-time splat: Lane is template immediate -> valid for _mm_shuffle_ps. */
    template <int Lane>
    static MOHO_FORCEINLINE __m128 splat(__m128 v)
    {
      static_assert(Lane >= 0 && Lane <= 3, "Lane out of range");
      return _mm_shuffle_ps(v, v, _MM_SHUFFLE(Lane, Lane, Lane, Lane));
    }

    /** Runtime splat wrapper: dispatches to compile-time variants (keeps imm8 constant). */
    static MOHO_FORCEINLINE __m128 splat_lane(__m128 v, int i)
    {
      switch (i & 3) {
      case 0:
        return splat<0>(v);
      case 1:
        return splat<1>(v);
      case 2:
        return splat<2>(v);
      default:
        return splat<3>(v);
      }
    }
#endif

    /** Convert a quaternion (x,y,z,w) to Euler XYZ (roll, pitch, yaw), radians. */
    [[nodiscard]] Angle quaternion_to_euler() const;
  };

  static_assert(sizeof(Vector4f) == 0x10, "Vector4f size must be 0x10");
  static_assert(alignof(Vector4f) == 0x4, "Vector4f alignment must be 4");

  /**
   * Address: 0x004ECED0 (FUN_004ECED0, Moho::ToString)
   *
   * What it does:
   * Formats one `Vector4f` lane set as `x=%f,y=%f,z=%f,w=%f`.
   */
  [[nodiscard]] msvc8::string ToString(const Vector4f& value);
} // namespace moho
