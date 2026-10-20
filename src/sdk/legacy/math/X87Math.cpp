#include "legacy/math/X87Math.h"

#include <bit>
#include <cmath>
#include <xmmintrin.h>

extern "C" int global_mode_sse2;

#if defined(_M_X64)
// legacy/math/X87Math64.asm: the same instruction sequences for 64-bit code,
// which has no inline assembly.
extern "C" float __cdecl msvc8_x87_sinf(float x);
extern "C" float __cdecl msvc8_x87_cosf(float x);
extern "C" float __cdecl msvc8_x87_tanf(float x);
extern "C" float __cdecl msvc8_x87_atan2f(float y, float x);
extern "C" double __cdecl msvc8_x87_acos(double x);
extern "C" double __cdecl msvc8_x87_asin(double x);
extern "C" double __cdecl msvc8_x87_pow(double x, double y);
extern "C" unsigned int __cdecl msvc8_x87_control_word();
extern "C" float __cdecl msvc8_x87_atan2_difference(float firstY, float firstX, float secondY, float secondX);
extern "C" float __cdecl msvc8_x87_atan2_plus(float y, float x, float addend);
extern "C" float __cdecl msvc8_x87_sin_times_cos(float sinArg, float cosArg);
extern "C" float __cdecl msvc8_x87_sin_times(float sinArg, float factor);
extern "C" void __cdecl msvc8_x87_slerp_spherical_blend(
  float* outLanes, const float* q1Lanes, const float* rhsLanes, float angle, float oneMinusT, float t
);
extern "C" float __cdecl msvc8_x87_intrinsic_exp(float x);
extern "C" float __cdecl msvc8_x87_intrinsic_ln(float x);
extern "C" float __cdecl msvc8_x87_intrinsic_log10(float x);
extern "C" float __cdecl msvc8_x87_intrinsic_ln_quotient(float x, double base);
extern "C" float __cdecl msvc8_x87_scaled_ln_quotient(float numerator, float denominator, float scale);
extern "C" float __cdecl msvc8_x87_cos_times_cos(float firstArg, float secondArg);
extern "C" float __cdecl msvc8_x87_bilinear_height(float h00, float h01, float h10, float h11, float fracX, float fracZ);
extern "C" std::int32_t __cdecl msvc8_x87_round_to_int(float value);
extern "C" void __cdecl msvc8_x87_scale_vector_max_length(float* x, float* y, float* z, float maxLength, float lengthSq);
extern "C" void __cdecl msvc8_x87_scale_vector_to_length(
  float* destLanes, const float* sourceLanes, float lengthSq, float length
);
extern "C" void __cdecl msvc8_x87_scale_vector(float* destLanes, const float* sourceLanes, float scale);
extern "C" float __cdecl msvc8_x87_box_radius_on_axis(const float* boxLanes, const float* axisLanes);
extern "C" void __cdecl msvc8_x87_scale_vector_to_length_of(
  float* destLanes, const float* sourceLanes, const float* targetLanes, float sourceLengthSq
);
extern "C" float __cdecl msvc8_x87_vector_length_zyx(const float* lanes);
#endif

namespace msvc8
{
  namespace
  {
    [[nodiscard]] unsigned int CurrentControlWord() noexcept
    {
#if defined(_M_IX86)
      unsigned short hardwareControlWord;
      __asm { fnstcw hardwareControlWord }
      return hardwareControlWord;
#else
      return msvc8_x87_control_word();
#endif
    }

    /**
     * The `_CI*` entries' shared prologue (`_CIacos` 0x00A8DCD0, `_CIasin`
     * 0x00A8DE20, `_CIpow` 0x00A8E0E0): the SSE2 body runs only with
     * `global_mode_sse2` set, MXCSR masks at their default and the x87 control
     * word's low byte at 0x7F. The game clears `global_mode_sse2` through
     * _set_SSE2_enable(0), so in game every entry takes its x87 body.
     */
    [[nodiscard]] bool TakesSse2Lane(const unsigned int controlWord) noexcept
    {
      return global_mode_sse2 != 0 && (_mm_getcsr() & 0x1F80u) == 0x1F80u && (controlWord & 0x7Fu) == 0x7Fu;
    }

    /**
     * Rounds the exact product `a * b` to float once, for operands whose
     * product needs more than double's 53 bits (a 31-bit integer times a
     * float). The exact product is `product + residual`; `fma` recovers the
     * part the double multiply rounded off.
     */
    [[nodiscard]] float RoundExactProductToFloat(const double a, const double b) noexcept
    {
      const double product = a * b;
      const double residual = std::fma(a, b, -product);

      float rounded = static_cast<float>(product);
      if (residual != 0.0 && static_cast<double>(rounded) != product) {
        // Rounding `product` to float matches rounding the exact value unless
        // `product` sits exactly halfway between two floats; there the
        // residual, not round-half-even, picks the side.
        const float other = std::nextafter(rounded, product > static_cast<double>(rounded) ? HUGE_VALF : -HUGE_VALF);
        const double midpoint = (static_cast<double>(rounded) + static_cast<double>(other)) * 0.5;
        if (product == midpoint && ((residual > 0.0) == (other > rounded))) {
          rounded = other;
        }
      }
      return rounded;
    }

    /**
     * An x87 `fmul` under _PC_24 followed by `fstp dword`: the exact product
     * rounds to a 24-bit mantissa with the extended exponent range, then the
     * store rounds once more if that lands below FLT_MIN.
     */
    [[nodiscard]] float RoundProductX87(const double a, const double b) noexcept
    {
      const double product = a * b;
      if (product != 0.0 && std::fabs(product) < 0x1p-126) {
        // Scaling by 2^172 (exact) moves every such product (>= 2^-298) into
        // float's normal range, where float rounding is the 24-bit rounding.
        const float mantissa = RoundExactProductToFloat(a * 0x1p172, b);
        return static_cast<float>(static_cast<double>(mantissa) * 0x1p-172);
      }
      return RoundExactProductToFloat(a, b);
    }
  } // namespace

  std::int32_t RoundToInt(const float value) noexcept
  {
#if defined(_M_IX86)
    std::int32_t result;
    __asm {
      fld value
      fistp result
    }
    return result;
#else
    return msvc8_x87_round_to_int(value);
#endif
  }

  void ScaleVectorByMaxLengthX87(float& x, float& y, float& z, const float maxLength) noexcept
  {
    // FUN_005D1E70 shape: squared length formed from the float components,
    // then `fld lenSq; fsqrt; fdivr maxLength` keeps the scale in extended
    // precision while each component multiplies against it and stores once.
    const float lengthSq = (x * x) + (y * y) + (z * z);
    if ((maxLength * maxLength) >= lengthSq) {
      return;
    }
    float* const px = &x;
    float* const py = &y;
    float* const pz = &z;
#if defined(_M_IX86)
    __asm {
      mov eax, px
      mov edx, py
      mov ecx, pz
      fld lengthSq
      fsqrt
      fdivr maxLength
      fld dword ptr [eax]
      fmul st(0), st(1)
      fstp dword ptr [eax]
      fld dword ptr [edx]
      fmul st(0), st(1)
      fstp dword ptr [edx]
      fmul dword ptr [ecx]
      fstp dword ptr [ecx]
      // 0x005D1EE8..0x005D1EEC: `fmul; fstp` consumes the scale itself. A
      // trailing `fstp st(0)` here popped an empty stack - a masked invalid
      // (stack underflow) that left x87 TOP rotated by one (difffuzz).
    }
#else
    // The x64 routine runs the same block under the simulation's PC24 and
    // starts from this same float `lengthSq`.
    msvc8_x87_scale_vector_max_length(px, py, pz, maxLength, lengthSq);
#endif
  }

  void ScaleVectorToLengthX87(
    float* const destLanes, const float* const sourceLanes, const float lengthSq, const float targetLength
  ) noexcept
  {
#if defined(_M_IX86)
    // 0x005B1CCF..0x005B1CF7: fld lenSq; fsqrt (FUN_0040EAF0); fdivr length;
    // x*scale, scale*y, scale*z, one float store each.
    __asm {
      mov eax, destLanes
      mov ecx, sourceLanes
      fld lengthSq
      fsqrt
      fdivr targetLength
      fld dword ptr [ecx]
      fmul st(0), st(1)
      fstp dword ptr [eax]
      fld st(0)
      fmul dword ptr [ecx + 4]
      fstp dword ptr [eax + 4]
      fmul dword ptr [ecx + 8]
      fstp dword ptr [eax + 8]
    }
#else
    msvc8_x87_scale_vector_to_length(destLanes, sourceLanes, lengthSq, targetLength);
#endif
  }

  void ScaleVectorX87(float* const destLanes, const float* const sourceLanes, const float scale) noexcept
  {
#if defined(_M_IX86)
    __asm {
      mov eax, destLanes
      mov ecx, sourceLanes
      fld scale
      fld dword ptr [ecx]
      fmul st(0), st(1)
      fstp dword ptr [eax]
      fld dword ptr [ecx + 4]
      fmul st(0), st(1)
      fstp dword ptr [eax + 4]
      fmul dword ptr [ecx + 8]
      fstp dword ptr [eax + 8]
    }
#else
    msvc8_x87_scale_vector(destLanes, sourceLanes, scale);
#endif
  }

  float BoxRadiusOnAxisX87(const float* const boxLanes, const float* const axisLanes) noexcept
  {
#if defined(_M_IX86)
    float radius;
    __asm {
      mov eax, boxLanes
      mov ecx, axisLanes
      fld dword ptr [eax + 28h]
      fld dword ptr [ecx + 4]
      fmul st(1), st
      fld dword ptr [eax + 2Ch]
      fld dword ptr [ecx + 8]
      fmul st(1), st
      fxch st(3)
      faddp st(1), st
      fld dword ptr [eax + 24h]
      fld dword ptr [ecx]
      fmul st(1), st
      fxch st(2)
      faddp st(1), st
      fabs
      fmul dword ptr [eax + 38h]
      fld dword ptr [eax + 1Ch]
      fmul st, st(3)
      fld dword ptr [eax + 20h]
      fmul st, st(5)
      faddp st(1), st
      fld dword ptr [eax + 18h]
      fmul st, st(3)
      faddp st(1), st
      fabs
      fmul dword ptr [eax + 34h]
      faddp st(1), st
      fld dword ptr [eax + 10h]
      fmulp st(3), st
      fld dword ptr [eax + 14h]
      fmulp st(4), st
      fxch st(2)
      faddp st(3), st
      fmul dword ptr [eax + 0Ch]
      faddp st(2), st
      fxch st(1)
      fabs
      fmul dword ptr [eax + 30h]
      faddp st(1), st
      fstp radius
    }
    return radius;
#else
    return msvc8_x87_box_radius_on_axis(boxLanes, axisLanes);
#endif
  }

  double fmod(const double x, const double y) noexcept
  {
    // _CIfmod (0x00A8E06A -> 0x00AA83B0 table dispatch) answers a zero
    // dividend with +0; the host CRT returns the dividend's -0.
    if (x == 0.0 && y != 0.0 && std::isfinite(y)) {
      return 0.0;
    }
    return std::fmod(x, y);
  }

  /**
   * Address: 0x00A8DA05 (frexp)
   */
  double frexp(const double x, int* const exponent) noexcept
  {
    if (!std::isfinite(x)) {
      // 0x00A8DA5A `or dword ptr [edi], -1`, then _except1 hands back the
      // x87 indefinite for an infinity (0x00A8DA8E) or _handle_qnan1 the NaN.
      *exponent = -1;
      return std::isnan(x) ? x : std::bit_cast<double>(0xFFF8000000000000ull);
    }
    if (x == 0.0) {
      // _decomp 0x00A99F08: `fldz; fcom x` and the equal branch returns the
      // +0 it loaded, so frexp(-0) is +0 (the host CRT keeps -0).
      *exponent = 0;
      return 0.0;
    }
    return std::frexp(x, exponent);
  }

  float MultiplyX87(const float a, const float b) noexcept
  {
    return RoundProductX87(static_cast<double>(a), static_cast<double>(b));
  }

  float MultiplyIntegerX87(const std::int32_t integer, const float factor) noexcept
  {
    return RoundProductX87(static_cast<double>(integer), static_cast<double>(factor));
  }

  double HalfSumX87(const float a, const float b) noexcept
  {
    // `fadd` rounds the sum to a 24-bit mantissa without the float exponent
    // limits, and `fmul 0.5` is exact. A sum below 2^-125 is a multiple of
    // 2^-149 that fits 24 bits, so it is already exact; anything larger rounds
    // like a float once scaled into range (|sum| <= 2 * FLT_MAX).
    const double half = (static_cast<double>(a) + static_cast<double>(b)) * 0.5;
    if (std::fabs(half) < 0x1p-126) {
      return half;
    }
    return static_cast<double>(static_cast<float>(half));
  }

  float HalfAbsDifferenceX87(const float minuend, const float subtrahend) noexcept
  {
    return static_cast<float>(std::fabs(static_cast<double>(minuend) - static_cast<double>(subtrahend)) * 0.5);
  }

  void ScaleVectorToLengthOfX87(
    float* const destLanes, const float* const sourceLanes, const float* const targetLanes, const float sourceLengthSq
  ) noexcept
  {
#if defined(_M_IX86)
    // 0x0069A3A5..0x0069A3D3: ((tx*tx + ty*ty) + tz*tz) / srcLenSq, fsqrt,
    // then sx*scale, scale*sy, scale*sz with one float store each.
    __asm {
      mov eax, destLanes
      mov ecx, sourceLanes
      mov edx, targetLanes
      fld dword ptr [edx]
      fmul st(0), st(0)
      fld dword ptr [edx + 4]
      fmul st(0), st(0)
      faddp st(1), st(0)
      fld dword ptr [edx + 8]
      fmul st(0), st(0)
      faddp st(1), st(0)
      fdiv sourceLengthSq
      fsqrt
      fld dword ptr [ecx]
      fmul st(0), st(1)
      fstp dword ptr [eax]
      fld st(0)
      fmul dword ptr [ecx + 4]
      fstp dword ptr [eax + 4]
      fmul dword ptr [ecx + 8]
      fstp dword ptr [eax + 8]
    }
#else
    msvc8_x87_scale_vector_to_length_of(destLanes, sourceLanes, targetLanes, sourceLengthSq);
#endif
  }

  float BilinearHeight(const float h00, const float h01, const float h10, const float h11, const float fracX, const float fracZ) noexcept
  {
#if defined(_M_IX86)
    float result;
    // Keep both rows on the x87 stack; arithmetic follows the active precision
    // control, which the original simulation thread sets to 24 bits.
    __asm {
      fld h01
      fld h00
      fsub st(1), st(0)
      fld fracZ
      fmul st(2), st(0)
      fxch st(2)
      faddp st(1), st(0)
      fld h11
      fld h10
      fsub st(1), st(0)
      fxch st(1)
      fmulp st(3), st(0)
      faddp st(2), st(0)
      fsub st(1), st(0)
      fxch st(1)
      fmul fracX
      faddp st(1), st(0)
      fstp result
    }
    return result;
#else
    return msvc8_x87_bilinear_height(h00, h01, h10, h11, fracX, fracZ);
#endif
  }

  float MulTwisterWord(const float factor, const std::uint32_t word) noexcept
  {
    const double wordValue =
      word < 0x80000000u ? static_cast<double>(word) : static_cast<double>(static_cast<float>(word));
    return RoundExactProductToFloat(static_cast<double>(factor), wordValue);
  }

  /**
   * Address: 0x005734E0 (sinf; `fld [esp+4]; fsin; ret`)
   */
  float sinf(const float x) noexcept
  {
#if defined(_M_IX86)
    float result;
    __asm {
      fld x
      fsin
      fstp result
    }
    return result;
#else
    return msvc8_x87_sinf(x);
#endif
  }

  /**
   * Address: 0x005734D0 (cosf; `fld [esp+4]; fcos; ret`)
   */
  float cosf(const float x) noexcept
  {
#if defined(_M_IX86)
    float result;
    __asm {
      fld x
      fcos
      fstp result
    }
    return result;
#else
    return msvc8_x87_cosf(x);
#endif
  }

  float tanf(const float x) noexcept
  {
#if defined(_M_IX86)
    float result;
    __asm {
      fld x
      fptan          // pushes tan(x), then 1.0
      fstp st(0)     // drop the 1.0
      fstp result
    }
    return result;
#else
    return msvc8_x87_tanf(x);
#endif
  }

  /**
   * Address: 0x004E9DF0 (float atan2; `fld y; fld x; fpatan`)
   */
  float atan2f(const float y, const float x) noexcept
  {
#if defined(_M_IX86)
    float result;
    __asm {
      fld y
      fld x
      fpatan         // atan(st1 / st0) with the quadrant of (x, y)
      fstp result
    }
    return result;
#else
    return msvc8_x87_atan2f(y, x);
#endif
  }

  float atanf(const float x) noexcept
  {
    return atan2f(x, 1.0f);
  }

  float Atan2Difference(const float firstY, const float firstX, const float secondY, const float secondX) noexcept
  {
#if defined(_M_IX86)
    const float firstAngle = atan2f(firstY, firstX);
    float result;
    // The original float atan2 returns an unspilled x87 result. Round only
    // the first angle before subtracting the second (CalcWingedOrientation).
    __asm {
      fld secondY
      fld secondX
      fpatan
      fsubr firstAngle
      fstp result
    }
    return result;
#else
    return msvc8_x87_atan2_difference(firstY, firstX, secondY, secondX);
#endif
  }

  float Atan2Plus(const float y, const float x, const float addend) noexcept
  {
#if defined(_M_IX86)
    float result;
    __asm {
      fld y
      fld x
      fpatan
      fadd addend
      fstp result
    }
    return result;
#else
    return msvc8_x87_atan2_plus(y, x, addend);
#endif
  }

  float SinTimesCos(const float sinArg, const float cosArg) noexcept
  {
#if defined(_M_IX86)
    float result;
    // Simulation thread runs with 24-bit precision control; fsin/fcos ignore
    // it, so only the fmul rounds (0x00695397..0x006953B1).
    __asm {
      fld cosArg
      fcos
      fld sinArg
      fsin
      fmulp st(1), st(0)
      fstp result
    }
    return result;
#else
    return msvc8_x87_sin_times_cos(sinArg, cosArg);
#endif
  }

  float SinTimes(const float sinArg, const float factor) noexcept
  {
#if defined(_M_IX86)
    float result;
    __asm {
      fld sinArg
      fsin
      fmul factor
      fstp result
    }
    return result;
#else
    return msvc8_x87_sin_times(sinArg, factor);
#endif
  }

  void SlerpSphericalBlend(
    float* const outLanes, const float* const q1Lanes, const float* const rhsLanes, const float angle,
    const float oneMinusT, const float t
  ) noexcept
  {
#if defined(_M_IX86)
    // Instruction for instruction 0x004EBD95..0x004EBDF2 (edi = q1, the
    // stack copy at [esp+20h] = rhs, ebx = out).
    __asm {
      mov eax, outLanes
      mov ecx, q1Lanes
      mov edx, rhsLanes
      fld angle
      fld st(0)
      fsin
      fld1
      fdivrp st(1), st(0)     ; inv, a
      fld st(1)
      fmul oneMinusT
      fsin
      fmul st(0), st(1)       ; w1, inv, a
      fld t
      fmulp st(3), st(0)      ; w1, inv, a*t
      fxch st(2)
      fsin
      fmulp st(1), st(0)      ; w2, w1
      fld dword ptr [ecx]
      fmul st(0), st(2)
      fld dword ptr [edx]
      fmul st(0), st(2)
      faddp st(1), st(0)
      fstp dword ptr [eax]
      fld dword ptr [ecx + 4]
      fmul st(0), st(2)
      fld dword ptr [edx + 4]
      fmul st(0), st(2)
      faddp st(1), st(0)
      fstp dword ptr [eax + 4]
      fld dword ptr [ecx + 8]
      fmul st(0), st(2)
      fld dword ptr [edx + 8]
      fmul st(0), st(2)
      faddp st(1), st(0)
      fstp dword ptr [eax + 8]
      fld dword ptr [ecx + 12]
      fmulp st(2), st(0)      ; w2, q1z*w1
      fmul dword ptr [edx + 12]
      faddp st(1), st(0)
      fstp dword ptr [eax + 12]
    }
#else
    msvc8_x87_slerp_spherical_blend(outLanes, q1Lanes, rhsLanes, angle, oneMinusT, t);
#endif
  }

  float IntrinsicExp(const float x) noexcept
  {
#if defined(_M_IX86)
    float result;
    __asm {
      fld x
      fldl2e
      fmulp st(1), st(0)
      fld st(0)
      frndint
      fxch st(1)
      fsub st(0), st(1)
      f2xm1
      fld1
      faddp st(1), st(0)
      fscale
      fstp st(1)
      fstp result
    }
    return result;
#else
    return msvc8_x87_intrinsic_exp(x);
#endif
  }

  float IntrinsicLn(const float x) noexcept
  {
#if defined(_M_IX86)
    float result;
    __asm {
      fld x
      fldln2
      fxch st(1)
      fyl2x
      fstp result
    }
    return result;
#else
    return msvc8_x87_intrinsic_ln(x);
#endif
  }

  float IntrinsicLog10(const float x) noexcept
  {
#if defined(_M_IX86)
    float result;
    __asm {
      fld x
      fldlg2
      fxch st(1)
      fyl2x
      fstp result
    }
    return result;
#else
    return msvc8_x87_intrinsic_log10(x);
#endif
  }

  float IntrinsicLnQuotient(const float x, const double base) noexcept
  {
#if defined(_M_IX86)
    float result;
    __asm {
      fld x
      fldln2
      fxch st(1)
      fyl2x
      fld base
      fldln2
      fxch st(1)
      fyl2x
      fdivp st(1), st(0)
      fstp result
    }
    return result;
#else
    return msvc8_x87_intrinsic_ln_quotient(x, base);
#endif
  }

  float ScaledLnQuotient(const float numerator, const float denominator, const float scale) noexcept
  {
#if defined(_M_IX86)
    float result;
    __asm {
      fld numerator
      fdiv denominator
      fldln2
      fxch st(1)
      fyl2x
      fmul scale
      fstp result
    }
    return result;
#else
    return msvc8_x87_scaled_ln_quotient(numerator, denominator, scale);
#endif
  }

  float CosTimesCos(const float firstArg, const float secondArg) noexcept
  {
#if defined(_M_IX86)
    float result;
    __asm {
      fld secondArg
      fcos
      fld firstArg
      fcos
      fmulp st(1), st(0)
      fstp result
    }
    return result;
#else
    return msvc8_x87_cos_times_cos(firstArg, secondArg);
#endif
  }

  float asinf(const float x) noexcept
  {
    return static_cast<float>(std::asin(static_cast<double>(x)));
  }

  float acosf(const float x) noexcept
  {
    return static_cast<float>(acos(static_cast<double>(x)));
  }

  double acos(const double x) noexcept
  {
    if (TakesSse2Lane(CurrentControlWord()) || !(x >= -1.0 && x <= 1.0)) {
      return std::acos(x);
    }

#if defined(_M_IX86)
    double result;
    // Original CRT valid-domain lane: (1+x)*(1-x), sqrt, then atan2.
    // Each arithmetic instruction uses the caller's x87 precision control.
    __asm {
      fld x
      fld1
      fadd st(0), st(1)
      fld1
      fsub st(0), st(2)
      fmulp st(1), st(0)
      fsqrt
      fxch st(1)
      fpatan
      fstp result
    }
    return result;
#else
    return msvc8_x87_acos(x);
#endif
  }

  /**
   * Address: 0x00A8DE20 (_CIasin)
   */
  double asin(const double x) noexcept
  {
    const unsigned int controlWord = CurrentControlWord();
    // NaN, infinities and |x| > 1 take the CRT's errno lane; the host CRT
    // returns the same NaN.
    if (TakesSse2Lane(controlWord) || !(x >= -1.0 && x <= 1.0)) {
      return std::asin(x);
    }

#if defined(_M_IX86)
    double result;
    // 0x00AA7BD5: the body runs with (caller CW & precision) | 0x7F.
    const unsigned short bodyControlWord = static_cast<unsigned short>((controlWord & 0x300u) | 0x7Fu);
    const unsigned short savedControlWord = static_cast<unsigned short>(controlWord);
    // 0x00A8DE93..0x00A8DE9F: (1 + x) * (1 - x), fsqrt, fpatan. |x| == 1
    // loads pi/2 at 0x00A8DED9 instead, which fpatan(+-1, 0) also gives.
    // The result leaves through the qword spill at 0x00AA7B80 (the game's
    // sticky inexact flag always takes it), hence the double store.
    __asm {
      fldcw bodyControlWord
      fld x
      fld1
      fadd st(0), st(1)
      fld1
      fsub st(0), st(2)
      fmulp st(1), st(0)
      fsqrt
      fpatan
      fstp result
      fldcw savedControlWord
    }
    return result;
#else
    return msvc8_x87_asin(x);
#endif
  }

  // 0x00A8E18A..0x00A8E194 + 0x00AA7BC0: `fyl2x` then 2^t through
  // frndint/f2xm1/fscale, under (caller CW & precision) | 0x7F.
  static double PowPositiveBase(unsigned int controlWord, double x, double y) noexcept;

  double pow(const double x, const double y) noexcept
  {
    const unsigned int controlWord = CurrentControlWord();
    if (TakesSse2Lane(controlWord)) {
      return std::pow(x, y);
    }
    // Zero, infinite and NaN operands, and a negative base with a fractional
    // exponent (the domain-error lane), are left to the host CRT.
    if (!std::isfinite(x) || !std::isfinite(y) || x == 0.0) {
      return std::pow(x, y);
    }
    if (x < 0.0) {
      // 0x00A8E2DD: classify the exponent (0x00A8E302: integer, then whether
      // y * 0.5 is too), run the positive lane on -x and negate for odd y.
      if (y != std::floor(y)) {
        return std::pow(x, y);
      }
      const bool oddExponent = (y * 0.5) != std::floor(y * 0.5);
      const double magnitude = PowPositiveBase(controlWord, -x, y);
      return oddExponent ? -magnitude : magnitude;
    }
    return PowPositiveBase(controlWord, x, y);
  }

  static double PowPositiveBase(const unsigned int controlWord, const double x, const double y) noexcept
  {
#if defined(_M_IX86)
    double result;
    // 0x00AA7BD5: the body runs with (caller CW & precision) | 0x7F.
    const unsigned short bodyControlWord = static_cast<unsigned short>((controlWord & 0x300u) | 0x7Fu);
    const unsigned short savedControlWord = static_cast<unsigned short>(controlWord);
    __asm {
      fldcw bodyControlWord
      fld y
      fld x
      fyl2x
      fld st(0)
      frndint
      fsubr st(1), st(0)
      fxch st(1)
      fchs
      f2xm1
      fld1
      faddp st(1), st(0)
      fscale
      fstp st(1)
      fstp result
      fldcw savedControlWord
    }
    return result;
#else
    return msvc8_x87_pow(x, y);
#endif
  }

  float expf(const float x) noexcept
  {
    return static_cast<float>(std::exp(static_cast<double>(x)));
  }

  float logf(const float x) noexcept
  {
    return static_cast<float>(std::log(static_cast<double>(x)));
  }

  float powf(const float x, const float y) noexcept
  {
    return static_cast<float>(std::pow(static_cast<double>(x), static_cast<double>(y)));
  }

  float VectorLengthZYXX87(const float* const lanes) noexcept
  {
#if defined(_M_IX86)
    // `length` is a MASM operator, so the result slot is `vectorLength`.
    float vectorLength;
    // 0x006A2846..0x006A2861: z*z, y*y, sum, x*x, sum, fsqrt, one store.
    __asm {
      mov eax, lanes
      fld dword ptr [eax + 8]
      fmul st(0), st(0)
      fld dword ptr [eax + 4]
      fmul st(0), st(0)
      faddp st(1), st(0)
      fld dword ptr [eax]
      fmul st(0), st(0)
      faddp st(1), st(0)
      fsqrt
      fstp vectorLength
    }
    return vectorLength;
#else
    return msvc8_x87_vector_length_zyx(lanes);
#endif
  }
} // namespace msvc8
