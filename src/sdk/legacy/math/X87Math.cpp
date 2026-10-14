#include "legacy/math/X87Math.h"

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
extern "C" unsigned int __cdecl msvc8_x87_control_word();
extern "C" float __cdecl msvc8_x87_atan2_difference(float firstY, float firstX, float secondY, float secondX);
extern "C" float __cdecl msvc8_x87_bilinear_height(float h00, float h01, float h10, float h11, float fracX, float fracZ);
extern "C" std::int32_t __cdecl msvc8_x87_round_to_int(float value);
extern "C" void __cdecl msvc8_x87_scale_vector_max_length(float* x, float* y, float* z, float maxLength);
#endif

namespace msvc8
{
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
      fstp st(0)
    }
#else
    msvc8_x87_scale_vector_max_length(px, py, pz, maxLength);
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
    const double product = static_cast<double>(factor) * wordValue;
    // The exact product is product + residual; fma recovers the part the
    // double multiply rounded off.
    const double residual = std::fma(static_cast<double>(factor), wordValue, -product);

    float rounded = static_cast<float>(product);
    if (residual != 0.0 && static_cast<double>(rounded) != product) {
      // Rounding `product` to float matches rounding the exact value unless
      // `product` sits exactly halfway between two floats; there the residual,
      // not round-half-even, picks the side.
      const float other = std::nextafter(
        rounded, product > static_cast<double>(rounded) ? HUGE_VALF : -HUGE_VALF
      );
      const double midpoint = (static_cast<double>(rounded) + static_cast<double>(other)) * 0.5;
      if (product == midpoint && ((residual > 0.0) == (other > rounded))) {
        rounded = other;
      }
    }
    return rounded;
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
    unsigned int controlWord;
#if defined(_M_IX86)
    unsigned short hardwareControlWord;
    __asm { fnstcw hardwareControlWord }
    controlWord = hardwareControlWord;
#else
    controlWord = msvc8_x87_control_word();
#endif
    if ((global_mode_sse2 != 0 && (_mm_getcsr() & 0x1F80u) == 0x1F80u
         && (controlWord & 0x7Fu) == 0x7Fu)
        || !(x >= -1.0 && x <= 1.0)) {
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
} // namespace msvc8
