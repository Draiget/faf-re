#pragma once

#include <bit>
#include <cstdint>

namespace gpg::gal
{
  /**
   * Engine addition (issue #317): D3DXFloat32To16Array's float -> float16 conversion, without D3DX.
   *
   * d3dx9_43's rule, matched on all 2^32 inputs on x64 and x86 (tmp/claude/half/half_model2.cpp,
   * 2026-11-06): the result is rounded to nearest, and a remainder exactly halfway, or below it by up to
   * 2^(shift - 14) in the subnormal range, rounds down. Values past the float16 range, infinities and NaNs
   * give +/-infinity; values below half the smallest subnormal give +/-0.
   */
  [[nodiscard]] inline std::uint16_t FloatToHalf(const float value) noexcept
  {
    const std::uint32_t bits = std::bit_cast<std::uint32_t>(value);
    const std::uint32_t sign = (bits >> 16U) & 0x8000U;
    const std::int32_t exponent = static_cast<std::int32_t>((bits >> 23U) & 0xFFU) - 127 + 15;
    if (exponent >= 31) {
      return static_cast<std::uint16_t>(sign | 0x7C00U);
    }
    if (exponent < -10) {
      return static_cast<std::uint16_t>(sign);
    }

    std::uint32_t mantissa = bits & 0x007FFFFFU;
    std::uint32_t shift = 13U;
    std::uint32_t half = static_cast<std::uint32_t>(exponent) << 10U;
    if (exponent <= 0) {
      mantissa |= 0x00800000U;
      shift = static_cast<std::uint32_t>(14 - exponent);
      half = 0U;
    }
    half |= mantissa >> shift;
    const std::uint32_t rest = mantissa & ((1U << shift) - 1U);
    const std::uint32_t middle = 1U << (shift - 1U);
    if (rest > middle + (middle >> 13U)) {
      ++half;
    }
    return static_cast<std::uint16_t>(sign | half);
  }
} // namespace gpg::gal
