#pragma once

#include <cmath>
#include <cstdint>
#include <type_traits>

namespace msvc8
{
  /**
   * `factor * word` exactly as the shipped engine forms it from a Mersenne
   * Twister word under 24-bit x87 precision control (e.g. CRandomStream::FRand,
   * 0x0051B5C0): `fild` loads the word exactly - a word at or above 2^31 loads
   * negative, and the `fadd 2^32` correcting it rounds to single - then the
   * multiply rounds the exact product to single once. A double multiply rounds
   * twice (53 bits, then 24) and can land one float away.
   */
  [[nodiscard]] float MulTwisterWord(float factor, std::uint32_t word) noexcept;

  /**
   * Single-precision transcendentals as the 2007 toolchain produced them.
   *
   * With intrinsics on, MSVC8 expanded the engine's float trig to the x87
   * transcendental instructions: `sinf` is `fld; fsin` (0x005734E0), `cosf` is
   * `fld; fcos` (0x005734D0), the float `atan2` is `fld; fld; fpatan`
   * (0x004E9DF0). A modern CRT computes these in software, and differently on
   * x86 and x64 (1 ulp apart on about 0.1% of inputs), which is enough to
   * split a lockstep simulation between the two builds. These functions run
   * the same x87 instructions on both architectures - the x87 unit is
   * available in 64-bit mode - so x86, x64 and the shipped binary produce the
   * same bits. fsin/fcos/fptan/fpatan ignore the precision-control field, so a
   * thread's `_PC_24` setting does not change them.
   */
  [[nodiscard]] float sinf(float x) noexcept;
  [[nodiscard]] float cosf(float x) noexcept;
  [[nodiscard]] float tanf(float x) noexcept;
  [[nodiscard]] float atanf(float x) noexcept;
  [[nodiscard]] float atan2f(float y, float x) noexcept;

  /**
   * The remaining float functions go through the CRT's double routine and
   * round once, which is what the x86 CRT's own float overloads do; x64's CRT
   * has separate float implementations that disagree with them. The double
   * routines of the two CRTs differ in the last bit for some inputs, but
   * rounding to float hides that (0 of 1,000,000 sampled inputs differed).
   */
  [[nodiscard]] float asinf(float x) noexcept;
  [[nodiscard]] float acosf(float x) noexcept;
  [[nodiscard]] float expf(float x) noexcept;
  [[nodiscard]] float logf(float x) noexcept;
  [[nodiscard]] float powf(float x, float y) noexcept;

  /**
   * Drop-in spellings for `std::sin` and friends with the same overload
   * resolution: a `float` argument takes the functions above, anything else
   * (double, mixed or integral arguments) forwards to `std::` unchanged, so
   * replacing `std::sin(` with `msvc8::sin(` changes only the float overloads.
   */
  [[nodiscard]] inline float sin(const float x) noexcept { return sinf(x); }
  [[nodiscard]] inline float cos(const float x) noexcept { return cosf(x); }
  [[nodiscard]] inline float tan(const float x) noexcept { return tanf(x); }
  [[nodiscard]] inline float atan(const float x) noexcept { return atanf(x); }
  [[nodiscard]] inline float asin(const float x) noexcept { return asinf(x); }
  [[nodiscard]] inline float acos(const float x) noexcept { return acosf(x); }
  [[nodiscard]] inline float exp(const float x) noexcept { return expf(x); }
  [[nodiscard]] inline float log(const float x) noexcept { return logf(x); }
  [[nodiscard]] inline float atan2(const float y, const float x) noexcept { return atan2f(y, x); }
  [[nodiscard]] inline float pow(const float x, const float y) noexcept { return powf(x, y); }

  template <class T, std::enable_if_t<!std::is_same_v<T, float>, int> = 0>
  [[nodiscard]] inline auto sin(const T x) noexcept { return std::sin(x); }
  template <class T, std::enable_if_t<!std::is_same_v<T, float>, int> = 0>
  [[nodiscard]] inline auto cos(const T x) noexcept { return std::cos(x); }
  template <class T, std::enable_if_t<!std::is_same_v<T, float>, int> = 0>
  [[nodiscard]] inline auto tan(const T x) noexcept { return std::tan(x); }
  template <class T, std::enable_if_t<!std::is_same_v<T, float>, int> = 0>
  [[nodiscard]] inline auto atan(const T x) noexcept { return std::atan(x); }
  template <class T, std::enable_if_t<!std::is_same_v<T, float>, int> = 0>
  [[nodiscard]] inline auto asin(const T x) noexcept { return std::asin(x); }
  template <class T, std::enable_if_t<!std::is_same_v<T, float>, int> = 0>
  [[nodiscard]] inline auto acos(const T x) noexcept { return std::acos(x); }
  template <class T, std::enable_if_t<!std::is_same_v<T, float>, int> = 0>
  [[nodiscard]] inline auto exp(const T x) noexcept { return std::exp(x); }
  template <class T, std::enable_if_t<!std::is_same_v<T, float>, int> = 0>
  [[nodiscard]] inline auto log(const T x) noexcept { return std::log(x); }
  template <class Y, class X, std::enable_if_t<!(std::is_same_v<Y, float> && std::is_same_v<X, float>), int> = 0>
  [[nodiscard]] inline auto atan2(const Y y, const X x) noexcept { return std::atan2(y, x); }
  template <class B, class E, std::enable_if_t<!(std::is_same_v<B, float> && std::is_same_v<E, float>), int> = 0>
  [[nodiscard]] inline auto pow(const B base, const E exponent) noexcept { return std::pow(base, exponent); }
} // namespace msvc8
