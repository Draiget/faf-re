#pragma once

// MMX intrinsics for x64 builds.
//
// The Sofdec movie code keeps the binary's MMX instruction sequences as
// intrinsics. MSVC declares the __m64 type on x64 but none of its operations
// (they are guarded by _M_IX86 in <mmintrin.h>/<xmmintrin.h>), so these are
// exact portable versions of the ones that code uses, following the
// instruction definitions: per-lane wraparound or saturation, shift counts
// past the lane width giving zero (logical) or a sign fill (arithmetic), and
// rounding averages. Nothing here is compiled on x86, where the real
// intrinsics are used.

#if defined(_M_X64)

#include <mmintrin.h>

#include <cstdint>

namespace mmx_on_x64
{
  [[nodiscard]] inline __m64 FromU64(const std::uint64_t value) noexcept
  {
    __m64 result;
    result.m64_u64 = value;
    return result;
  }

  [[nodiscard]] inline std::uint8_t SaturateToU8(const std::int16_t value) noexcept
  {
    return value < 0 ? 0 : (value > 255 ? 255 : static_cast<std::uint8_t>(value));
  }
} // namespace mmx_on_x64

inline void _m_empty() noexcept {}
inline void _mm_empty() noexcept {}

inline __m64 _mm_setzero_si64() noexcept
{
  return mmx_on_x64::FromU64(0);
}

inline int _mm_cvtsi64_si32(const __m64 a) noexcept
{
  return a.m64_i32[0];
}

inline __m64 _m_por(const __m64 a, const __m64 b) noexcept
{
  return mmx_on_x64::FromU64(a.m64_u64 | b.m64_u64);
}

inline __m64 _m_paddw(const __m64 a, const __m64 b) noexcept
{
  __m64 r;
  for (int i = 0; i < 4; ++i) {
    r.m64_u16[i] = static_cast<std::uint16_t>(a.m64_u16[i] + b.m64_u16[i]);
  }
  return r;
}

inline __m64 _mm_add_pi16(const __m64 a, const __m64 b) noexcept
{
  return _m_paddw(a, b);
}

inline __m64 _m_paddusw(const __m64 a, const __m64 b) noexcept
{
  __m64 r;
  for (int i = 0; i < 4; ++i) {
    const unsigned sum = static_cast<unsigned>(a.m64_u16[i]) + b.m64_u16[i];
    r.m64_u16[i] = static_cast<std::uint16_t>(sum > 0xFFFFu ? 0xFFFFu : sum);
  }
  return r;
}

inline __m64 _m_pmullw(const __m64 a, const __m64 b) noexcept
{
  __m64 r;
  for (int i = 0; i < 4; ++i) {
    const std::int32_t product = static_cast<std::int32_t>(a.m64_i16[i]) * b.m64_i16[i];
    r.m64_u16[i] = static_cast<std::uint16_t>(product & 0xFFFF);
  }
  return r;
}

inline __m64 _m_pavgw(const __m64 a, const __m64 b) noexcept
{
  __m64 r;
  for (int i = 0; i < 4; ++i) {
    r.m64_u16[i] = static_cast<std::uint16_t>((static_cast<unsigned>(a.m64_u16[i]) + b.m64_u16[i] + 1u) >> 1);
  }
  return r;
}

inline __m64 _m_pavgb(const __m64 a, const __m64 b) noexcept
{
  __m64 r;
  for (int i = 0; i < 8; ++i) {
    r.m64_u8[i] = static_cast<std::uint8_t>((static_cast<unsigned>(a.m64_u8[i]) + b.m64_u8[i] + 1u) >> 1);
  }
  return r;
}

inline __m64 _m_punpcklbw(const __m64 a, const __m64 b) noexcept
{
  __m64 r;
  for (int i = 0; i < 4; ++i) {
    r.m64_u8[2 * i] = a.m64_u8[i];
    r.m64_u8[2 * i + 1] = b.m64_u8[i];
  }
  return r;
}

inline __m64 _m_punpckhbw(const __m64 a, const __m64 b) noexcept
{
  __m64 r;
  for (int i = 0; i < 4; ++i) {
    r.m64_u8[2 * i] = a.m64_u8[4 + i];
    r.m64_u8[2 * i + 1] = b.m64_u8[4 + i];
  }
  return r;
}

inline __m64 _m_packuswb(const __m64 a, const __m64 b) noexcept
{
  __m64 r;
  for (int i = 0; i < 4; ++i) {
    r.m64_u8[i] = mmx_on_x64::SaturateToU8(a.m64_i16[i]);
    r.m64_u8[4 + i] = mmx_on_x64::SaturateToU8(b.m64_i16[i]);
  }
  return r;
}

inline __m64 _mm_packs_pu16(const __m64 a, const __m64 b) noexcept
{
  return _m_packuswb(a, b);
}

inline __m64 _m_psllqi(const __m64 a, const int count) noexcept
{
  return mmx_on_x64::FromU64(static_cast<unsigned>(count) > 63u ? 0u : a.m64_u64 << count);
}

inline __m64 _m_psrlqi(const __m64 a, const int count) noexcept
{
  return mmx_on_x64::FromU64(static_cast<unsigned>(count) > 63u ? 0u : a.m64_u64 >> count);
}

inline __m64 _m_psrlwi(const __m64 a, const int count) noexcept
{
  __m64 r;
  for (int i = 0; i < 4; ++i) {
    r.m64_u16[i] = static_cast<unsigned>(count) > 15u ? 0u : static_cast<std::uint16_t>(a.m64_u16[i] >> count);
  }
  return r;
}

inline __m64 _m_psrawi(const __m64 a, const int count) noexcept
{
  const int shift = static_cast<unsigned>(count) > 15u ? 15 : count;
  __m64 r;
  for (int i = 0; i < 4; ++i) {
    r.m64_i16[i] = static_cast<std::int16_t>(a.m64_i16[i] >> shift);
  }
  return r;
}

inline __m64 _mm_srai_pi16(const __m64 a, const int count) noexcept
{
  return _m_psrawi(a, count);
}

#endif // _M_X64
