#pragma once

#include <cmath>
#include <cstdint>
#include <cstring>

namespace msvc8
{
  /**
   * A value on the x87 register stack under the simulation's 24-bit precision
   * control (`_controlfp(_PC_24, _MCW_PC)`): every arithmetic result is rounded
   * to a 24-bit significand, as a float is, but keeps the register's wide
   * exponent. An intermediate past the float range - the product of two large
   * lanes, or of two tiny ones - neither overflows nor goes denormal until it
   * is stored; `static_cast<float>` is that store (`fstp dword`), the second
   * rounding, into the float range.
   *
   * The shipped engine's Wild Magic was compiled for x87 with /fp:precise, so a
   * port of its code computes each expression in this type and converts at
   * every point the binary stores to a float: each named variable, each
   * Vector3 temporary, each argument and result of `Math<float>::FAbs` and
   * `Math<float>::Sqrt` (e.g. `IntrSegment3Sphere3<float>::Find` 0x00A471C0
   * stores fA0, fA1 and fDiscr, and compares `fQM*fQP` against 0 on the stack).
   * The `Vector3` operators the binary calls out of line (operator+ 0x00428DB0,
   * scalar * vector 0x005006F0) are SSE and stay plain float arithmetic.
   *
   * Held in a double: each operation is formed in double precision and then
   * rounded to 24 bits. For + - * / and sqrt of 24-bit operands that is one
   * rounding of the exact result (53 >= 2 * 24 + 2). The double's exponent
   * covers any product of up to six float lanes; past that the x87 register
   * (down to 2^-16382) still has range where this type goes denormal.
   */
  class X87Float
  {
  public:
    constexpr X87Float() noexcept = default;

    /// `fld dword`: exact.
    constexpr X87Float(const float value) noexcept // NOLINT(google-explicit-constructor)
      : mValue(value)
    {}

    /// `fstp dword`: rounds into the float range (overflow to inf, denormals).
    [[nodiscard]] explicit operator float() const noexcept { return static_cast<float>(mValue); }

    friend X87Float operator+(const X87Float lhs, const X87Float rhs) noexcept { return Round(lhs.mValue + rhs.mValue); }
    friend X87Float operator-(const X87Float lhs, const X87Float rhs) noexcept { return Round(lhs.mValue - rhs.mValue); }
    friend X87Float operator*(const X87Float lhs, const X87Float rhs) noexcept { return Round(lhs.mValue * rhs.mValue); }
    friend X87Float operator/(const X87Float lhs, const X87Float rhs) noexcept { return Round(lhs.mValue / rhs.mValue); }
    /// `fchs`: exact.
    friend X87Float operator-(const X87Float value) noexcept { return Raw(-value.mValue); }

    friend bool operator<(const X87Float lhs, const X87Float rhs) noexcept { return lhs.mValue < rhs.mValue; }
    friend bool operator>(const X87Float lhs, const X87Float rhs) noexcept { return lhs.mValue > rhs.mValue; }
    friend bool operator<=(const X87Float lhs, const X87Float rhs) noexcept { return lhs.mValue <= rhs.mValue; }
    friend bool operator>=(const X87Float lhs, const X87Float rhs) noexcept { return lhs.mValue >= rhs.mValue; }
    friend bool operator==(const X87Float lhs, const X87Float rhs) noexcept { return lhs.mValue == rhs.mValue; }
    friend bool operator!=(const X87Float lhs, const X87Float rhs) noexcept { return lhs.mValue != rhs.mValue; }

    /// `fabs`: exact, and clears the sign of a NaN too.
    [[nodiscard]] friend X87Float Abs(const X87Float value) noexcept { return Raw(std::fabs(value.mValue)); }

    /// `fild dword`: exact (an int has at most 31 significant bits, and the
    /// load does not round).
    [[nodiscard]] static X87Float FromInt(const std::int32_t value) noexcept { return Raw(static_cast<double>(value)); }

  private:
    [[nodiscard]] static X87Float Raw(const double value) noexcept
    {
      X87Float result;
      result.mValue = value;
      return result;
    }

    /// Round to a 24-bit significand, ties to even, keeping the exponent.
    [[nodiscard]] static X87Float Round(double value) noexcept
    {
      std::uint64_t bits;
      std::memcpy(&bits, &value, sizeof(bits));
      const std::uint64_t exponent = (bits >> 52) & 0x7FFu;
      if (exponent == 0x7FFu) {
        return Raw(value); // inf, NaN
      }
      if (exponent == 0) {
        if (value == 0.0) {
          return Raw(value);
        }
        // A double denormal (below 2^-1022): scale up, round, scale back. Both
        // scalings are exact.
        return Raw(Round(value * 0x1p600).mValue * 0x1p-600);
      }
      constexpr std::uint64_t kDropped = (std::uint64_t{1} << 29) - 1u; // 52 - 23 fraction bits
      constexpr std::uint64_t kHalf = std::uint64_t{1} << 28;
      constexpr std::uint64_t kLsb = std::uint64_t{1} << 29;
      const std::uint64_t low = bits & kDropped;
      bits &= ~kDropped;
      if (low > kHalf || (low == kHalf && (bits & kLsb) != 0)) {
        bits += kLsb; // a carry into the exponent is the correct rounding
      }
      std::memcpy(&value, &bits, sizeof(value));
      return Raw(value);
    }

    double mValue = 0.0;
  };

  /// `Math<float>::FAbs` as the binary inlines it: the argument is stored to a
  /// float, `fabs`, and the result stored again.
  [[nodiscard]] inline float FAbsX87(const X87Float value) noexcept
  {
    return static_cast<float>(Abs(X87Float(static_cast<float>(value))));
  }
} // namespace msvc8
