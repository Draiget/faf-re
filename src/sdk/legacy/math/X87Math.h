#pragma once

#include <cmath>
#include <cstdint>
#include <type_traits>

namespace msvc8
{
  /**
   * Inlined block from FUN_006BDEE0: float-to-cell conversion uses the
   * caller's x87 rounding mode and preserves FISTP's invalid-input result.
   */
  [[nodiscard]] std::int32_t RoundToInt(float value) noexcept;
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
   * Vector length clamp exactly as the 2007 toolchain computed it.
   *
   * The shipped engine clamps a vector by forming the squared length in SSE,
   * then switching to x87: `fld lenSq; fsqrt; fdivr maxLen` leaves the scale
   * `maxLen / sqrt(lenSq)` in extended precision (64-bit mantissa), and the
   * per-component multiplies consume that extended scale and store each
   * component to float once (FUN_005D1E70, func_VecLimitLengthTo:
   * 0x005D1ECF..0x005D1EEC; the same inlined shape recurs throughout
   * CAiPathSpline::Generate, e.g. 0x005B39FD..0x005B3A24). A pure-float
   * `scale = max / sqrtf(lenSq)` rounds the scale to 24 bits before the
   * multiplies, so each component can land one ulp away from the engine's
   * single rounding - enough to drift a lockstep simulation's path nodes.
   */
  void ScaleVectorByMaxLengthX87(float& x, float& y, float& z, float maxLength) noexcept;

  /**
   * `dest[i] = source[i] * (length / sqrt(lengthSq))` exactly as
   * func_VecSetLengthS (FUN_005B1C90) forms it at 0x005B1CCF..0x005B1CF7:
   * `fsqrt` of the float squared length, `fdivr length`, and the scale stays
   * on the x87 stack - 24-bit mantissa but extended exponent - across the
   * three multiplies, each stored to float once. QuatToAxisAndAngle
   * (FUN_006C1070, 0x006C10EF..0x006C1117) is the same chain with length 1
   * (`fld1; fdivrp`). A float scale overflows or goes denormal when the
   * length and the vector are far apart in magnitude (difffuzz found
   * 1/1,000,000 ordinary-range inputs, and every denormal output, off).
   * `dest` may alias `source`.
   */
  void ScaleVectorToLengthX87(float* destLanes, const float* sourceLanes, float lengthSq, float targetLength) noexcept;

  /**
   * `dest[i] = source[i] * scale` with each product formed on the x87 stack
   * and stored once: under 24-bit precision control that rounds the mantissa
   * first and the float exponent range second, which differs from one SSE
   * multiply only when the product is denormal (QuatFromAxisAngleVector
   * 0x00697393..0x006973AD, EulerRollToQuat 0x0057077E..0x00570796).
   */
  void ScaleVectorX87(float* destLanes, const float* sourceLanes, float scale) noexcept;

  /**
   * The MSVC8 CRT's `fmod` (`_CIfmod`, 0x00A8E06A, x87 table dispatch): a
   * zero dividend returns +0 for a finite non-zero divisor, where the modern
   * CRT keeps the dividend's sign (`fmod(-0, y) == -0`). Every other
   * finite input matched in 1,000,000 difffuzz samples.
   */
  [[nodiscard]] double fmod(double x, double y) noexcept;

  /**
   * `(a + b) * 0.5f` and `fabs(a - b) * 0.5f` as the 2007 build formed them
   * on the x87 stack: `fld a; fadd b; fmul 0.5` (CAimManipulator::SetFiringArc
   * 0x00630CB9..0x00630CBF / 0x00630D01..0x00630D24, CBuilderArmManipulator::
   * SetAimingArc 0x00636499..0x0063649F / 0x006364E1..0x00636504). Under
   * 24-bit precision control the sum rounds its mantissa to single but keeps
   * the extended exponent, so it cannot overflow to infinity before the
   * halving brings it back into float range. A float sum does overflow for
   * `|a + b| > FLT_MAX`. These form the sum in double (one float rounding of a
   * double sum of two floats is the single rounding, and halving is exact),
   * so they give the same bits on x86 and x64.
   *
   * `HalfSumX87` returns the value still on the x87 stack, unrounded: the
   * callers feed it straight into an inlined `_CIfmod`
   * (`moho::NormalizeAngleSignedRadiansX87`), and a half below float
   * precision (`-2^-150`) must reach the fmod as non-zero. `HalfAbsDifferenceX87`
   * returns the float its `fstp` stores.
   */
  [[nodiscard]] double HalfSumX87(float a, float b) noexcept;
  [[nodiscard]] float HalfAbsDifferenceX87(float minuend, float subtrahend) noexcept;

  /**
   * `dest = source * sqrt(|target|^2 / sourceLengthSq)` exactly as
   * func_VecSetLengthTo (FUN_0069A360) forms it at 0x0069A3A5..0x0069A3D3:
   * the target's squared length `(x*x + y*y) + z*z`, the division and the
   * `fsqrt` all run on the x87 stack, so neither `|target|^2` nor the ratio
   * rounds to the float exponent range. In float, a short source (|s| ~ 1e-18
   * against |t| ~ 100) overflowed the ratio and returned infinities where the
   * engine returns a vector of length |t|.
   */
  void ScaleVectorToLengthOfX87(float* destLanes, const float* sourceLanes, const float* targetLanes, float sourceLengthSq) noexcept;

  // Terrain interpolation uses the simulation's 24-bit x87 arithmetic.
  // Inlined block from FUN_0044FB90; preserve the original operation order.
  [[nodiscard]] float BilinearHeight(float h00, float h01, float h10, float h11, float fracX, float fracZ) noexcept;

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
  // First angle is stored as float; the second stays in x87 through subtraction.
  [[nodiscard]] float Atan2Difference(float firstY, float firstX, float secondY, float secondX) noexcept;
  // Inlined `fsin`/`fcos` results stay unrounded on the x87 stack and only
  // their product rounds, under 24-bit precision control (FUN_00695180's fall
  // axis): sin(sinArg) * cos(cosArg) and cos(firstArg) * cos(secondArg).
  // `fpatan` result added to `addend` before any rounding (CAimManipulator's
  // heading lane, 0x00630AB2..0x00630AB7): round24(atan2(y, x) + addend).
  [[nodiscard]] float Atan2Plus(float y, float x, float addend) noexcept;
  [[nodiscard]] float SinTimesCos(float sinArg, float cosArg) noexcept;
  // `fld arg; fsin; fmul factor; fstp`: the sine stays unrounded and only the
  // product rounds (CUnitMotion::HandleDivingAndSurfacing, 0x006C337A..0x006C3380).
  [[nodiscard]] float SinTimes(float sinArg, float factor) noexcept;
  /**
   * Moho::SLERP's spherical blend exactly as FUN_004EBC00 runs it at
   * 0x004EBD95..0x004EBDF2, entirely on the x87 stack:
   *   inv = 1 / fsin(angle)
   *   w1  = fsin(angle * oneMinusT) * inv,  w2 = fsin(angle * t) * inv
   *   out[i] = q1[i] * w1 + rhs[i] * w2      (one float store per lane)
   * Under the simulation's 24-bit precision control each step rounds its
   * mantissa but keeps the extended exponent, so neither the weights nor the
   * lane products flush to denormal before the final store. Storing them as
   * floats in between (the former SinReciprocal/SinTimes split) differed from
   * retail on denormal-range `t` and lanes (difffuzz).
   */
  void SlerpSphericalBlend(
    float* outLanes, const float* q1Lanes, const float* rhsLanes, float angle, float oneMinusT, float t
  ) noexcept;

  /**
   * MSVC8's /Oi intrinsic expansions of `exp`, `log` and `log10`, as the
   * engine's Lua math library inlines them (math_exp 0x00919D5D..0x00919D76,
   * math_log 0x00919CFD..0x00919D06, math_log10 0x00919D2D..0x00919D36).
   * `fyl2x`/`f2xm1` ignore precision control, but the `fmul`/`fadd` steps of
   * the exp sequence round under the simulation's 24-bit control, so these
   * are not the correctly rounded functions and must not go through a CRT.
   */
  [[nodiscard]] float IntrinsicExp(float x) noexcept;
  [[nodiscard]] float IntrinsicLn(float x) noexcept;
  [[nodiscard]] float IntrinsicLog10(float x) noexcept;
  /**
   * `log(x) / log(base)` with both /Oi `log` intrinsics inlined (`fldln2;
   * fxch; fyl2x` twice, then `fdivp`), as RATE_GameRateToSpeed forms it at
   * 0x0055AE19..0x0055AE2E: neither logarithm rounds before the divide, only
   * the quotient does. Rounding `IntrinsicLn(x)` to float first can land one
   * float away.
   */
  [[nodiscard]] float IntrinsicLnQuotient(float x, double base) noexcept;
  [[nodiscard]] float CosTimesCos(float firstArg, float secondArg) noexcept;

  /**
   * Except for the legacy-dispatched acos overload below, these float
   * functions go through the host CRT's double routine and
   * round once, which is what the x86 CRT's own float overloads do; x64's CRT
   * has separate float implementations that disagree with them. The double
   * routines of the two CRTs differ in the last bit for some inputs, but
   * rounding to float hides that (0 of 1,000,000 sampled inputs differed).
   */
  [[nodiscard]] float asinf(float x) noexcept;
  [[nodiscard]] float acosf(float x) noexcept;
  // Legacy CRT dispatch: the engine's /sse2 option selects the SSE lane;
  // simulation otherwise uses x87 arithmetic with single precision control.
  [[nodiscard]] double acos(double x) noexcept;
  [[nodiscard]] float expf(float x) noexcept;
  [[nodiscard]] float logf(float x) noexcept;
  [[nodiscard]] float powf(float x, float y) noexcept;

  /**
   * Drop-in spellings for `std::sin` and friends with the same overload
   * resolution: a `float` argument takes the functions above, anything else
   * (double, mixed or integral arguments) forwards to `std::` unchanged.
   * The explicit double acos overload also preserves legacy CRT dispatch.
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
  template <class T, std::enable_if_t<!std::is_same_v<T, float> && !std::is_same_v<T, double>, int> = 0>
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
