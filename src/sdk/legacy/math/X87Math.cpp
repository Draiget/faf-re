#include "legacy/math/X87Math.h"

#include <cmath>

#if defined(_M_X64)
// legacy/math/X87Math64.asm: the same instruction sequences for 64-bit code,
// which has no inline assembly.
extern "C" float __cdecl msvc8_x87_sinf(float x);
extern "C" float __cdecl msvc8_x87_cosf(float x);
extern "C" float __cdecl msvc8_x87_tanf(float x);
extern "C" float __cdecl msvc8_x87_atan2f(float y, float x);
#endif

namespace msvc8
{
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

  float asinf(const float x) noexcept
  {
    return static_cast<float>(std::asin(static_cast<double>(x)));
  }

  float acosf(const float x) noexcept
  {
    return static_cast<float>(std::acos(static_cast<double>(x)));
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
