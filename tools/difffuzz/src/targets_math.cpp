// Math leaf targets: retail VA vs the recovered function compiled from src.
//
// Pattern per target (see README.md "Adding a target"):
//   gen    - fills the input words (floats as raw bits)
//   retail - unpacks the inputs, calls the retail:: thunk, packs every output
//            word (written lanes, return value, in-place inputs after the call)
//   ours   - the same, calling the recovered moho:: / msvc8:: / Wm3:: function
// Output buffers are pre-filled with kCanary so "did not write a lane" is
// compared too.

#include "fuzz.h"
#include "retail_thunks.h"

#include "legacy/math/X87Math.h"
#include "moho/math/QuaternionMath.h"
#include "moho/math/Vector3f.h"
#include "sdk_mirror.h"

#include <cmath>
#include <cstring>

// Defined with external linkage in QuaternionMath.cpp but not declared in its
// header (no caller outside that file needs them). The top-level `const` on
// the pointer parameters is spelled out because MSVC mangles it for a
// definition that has no prior declaration.
namespace moho
{
  Wm3::Vector3f* QuaternionExtractYAxisColumn(Wm3::Vector3f* const outAxis, const Wm3::Quaternionf* const quaternion) noexcept;
  Wm3::Vector3f* RotateVectorByConjugateQuaternionLanes(
    const float* const quaternionLanes, Wm3::Vector3f* const outVector, const Wm3::Vector3f* const sourceVector
  );
} // namespace moho

namespace difffuzz
{
  namespace
  {
    using Vec = Wm3::Vector3f;
    using Quat = Wm3::Quaternionf;
    using u32 = std::uint32_t;

    static_assert(sizeof(Vec) == 12 && sizeof(Quat) == 16);

    [[nodiscard]] float F(const u32* in, const int i) noexcept { return FromBits(in[i]); }
    void Put(u32* out, const int i, const float f) noexcept { out[i] = Bits(f); }
    void PutBlock(u32* out, const int i, const void* p, const int words) noexcept { std::memcpy(out + i, p, words * 4); }
    template <class T>
    void Load(T& obj, const u32* in, const int i) noexcept
    {
      std::memcpy(static_cast<void*>(&obj), in + i, sizeof(T));
    }
    template <class T>
    void Canary(T& obj) noexcept
    {
      std::memset(static_cast<void*>(&obj), 0xCD, sizeof(T));
    }
    void PutF(u32* out, const int i, float* src, const int n) noexcept
    {
      for (int k = 0; k < n; ++k) {
        out[i + k] = Bits(src[k]);
      }
    }

    // ---- sqrt helpers 0x00452FC0 / 0x0040EAF0 (inlined as std::sqrt(float))
    void GenScalar(Rng& rng, u32* in) { in[0] = Bits(rng.Chance(30) ? std::fabs(GenFloat(rng)) : GenFloat(rng)); }
    void SqrtRetail(const u32* in, u32* out) { Put(out, 0, retail::Sqrtf(F(in, 0))); }
    void SqrtBRetail(const u32* in, u32* out) { Put(out, 0, retail::SqrtfB(F(in, 0))); }
    void SqrtOurs(const u32* in, u32* out) { Put(out, 0, std::sqrt(F(in, 0))); }

    void FabsRetail(const u32* in, u32* out) { Put(out, 0, retail::Fabsf(F(in, 0))); }
    void FabsOurs(const u32* in, u32* out) { Put(out, 0, std::fabs(F(in, 0))); }

    void GenTrig(Rng& rng, u32* in)
    {
      in[0] = Bits(rng.Chance(70) ? GenAngle(rng) : GenFloat(rng));
      in[1] = Bits(rng.Chance(50) ? GenPlain(rng, 10.0f) : GenFloat(rng));
    }
    void SinRetail(const u32* in, u32* out) { Put(out, 0, retail::Sinf(F(in, 0))); }
    void SinOurs(const u32* in, u32* out) { Put(out, 0, msvc8::sinf(F(in, 0))); }
    void CosRetail(const u32* in, u32* out) { Put(out, 0, retail::Cosf(F(in, 0))); }
    void CosOurs(const u32* in, u32* out) { Put(out, 0, msvc8::cosf(F(in, 0))); }
    void Atan2Retail(const u32* in, u32* out) { Put(out, 0, retail::Atan2f(F(in, 0), F(in, 1))); }
    void Atan2Ours(const u32* in, u32* out) { Put(out, 0, msvc8::atan2f(F(in, 0), F(in, 1))); }

    // ---- acos 0x00A8DCD0 (double in/out; SLERP feeds it a widened float dot)
    void GenAcos(Rng& rng, u32* in)
    {
      double d;
      const u32 mode = rng.Below(100);
      if (mode < 50) {
        d = static_cast<double>(static_cast<float>(rng.Range(-1.0, 1.0)));
      } else if (mode < 70) {
        d = static_cast<double>(FromBits(0x3F800000u - rng.Below(4096))); // just below 1
      } else if (mode < 85) {
        d = rng.Range(-1.0, 1.0); // full double
      } else {
        d = static_cast<double>(GenFloat(rng));
        if (!(d >= -1.0 && d <= 1.0)) {
          d = 0.5; // out-of-domain needs the CRT error path (errno -> imports)
        }
      }
      std::memcpy(in, &d, 8);
    }
    void AcosRetail(const u32* in, u32* out)
    {
      double d;
      std::memcpy(&d, in, 8);
      const double r = retail::Acos(d);
      std::memcpy(out, &r, 8);
    }
    void AcosOurs(const u32* in, u32* out)
    {
      double d;
      std::memcpy(&d, in, 8);
      const double r = msvc8::acos(d);
      std::memcpy(out, &r, 8);
    }

    // ---- fmod 0x00A8E06A (_CIfmod), as NormalizeAngleSignedRadians uses it:
    // a float angle widened to double, modulo the double 2*pi constant.
    void GenFmod(Rng& rng, u32* in)
    {
      double x = static_cast<double>(rng.Chance(70) ? GenPlain(rng, 100.0f) : GenFloat(rng));
      if (!std::isfinite(x)) {
        x = -0.0; // inf/NaN take the CRT error path (errno -> imports)
      }
      const double y = rng.Chance(80) ? static_cast<double>(6.2831855f) : static_cast<double>(GenPlain(rng, 10.0f));
      std::memcpy(in, &x, 8);
      std::memcpy(in + 2, &y, 8);
    }
    void FmodRetail(const u32* in, u32* out)
    {
      double x, y;
      std::memcpy(&x, in, 8);
      std::memcpy(&y, in + 2, 8);
      const double r = retail::Fmod(x, y);
      std::memcpy(out, &r, 8);
    }
    void FmodOurs(const u32* in, u32* out)
    {
      double x, y;
      std::memcpy(&x, in, 8);
      std::memcpy(&y, in + 2, 8);
      const double r = msvc8::fmod(x, y);
      std::memcpy(out, &r, 8);
    }

    // ---- pow 0x00A8E0E0 (_CIpow) as Lua math.pow uses it (0x00919CB0) -------
    void GenPow(Rng& rng, u32* in)
    {
      float x = rng.Chance(70) ? GenPlain(rng, 100.0f) : GenFloat(rng);
      if (!std::isfinite(x)) {
        x = 2.0f;
      }
      if (x < 0.0f && rng.Chance(70)) {
        x = -x;
      }
      const std::uint32_t pick = rng.Below(4);
      const float y = pick == 0 ? 2.0f
        : pick == 1 ? static_cast<float>(rng.Below(7))
        : pick == 2 ? 0.5f
        : GenPlain(rng, 4.0f);
      // Stay inside the domain: a negative base with a fractional exponent, or
      // a zero base with a negative one, takes the CRT error path (errno).
      if (x < 0.0f && y != std::floor(y)) {
        x = -x;
      }
      if (x == 0.0f) {
        x = 1.5f;
      }
      std::memcpy(in, &x, 4);
      std::memcpy(in + 1, &y, 4);
    }
    void PowRetail(const u32* in, u32* out)
    {
      float x, y, r;
      std::memcpy(&x, in, 4);
      std::memcpy(&y, in + 1, 4);
      retail::PowF(x, y, &r);
      std::memcpy(out, &r, 4);
    }
    void PowOurs(const u32* in, u32* out)
    {
      float x, y;
      std::memcpy(&x, in, 4);
      std::memcpy(&y, in + 1, 4);
      const float r = static_cast<float>(msvc8::pow(static_cast<double>(x), static_cast<double>(y)));
      std::memcpy(out, &r, 4);
    }

    // ---- Lua math library (src\lua\LuaObject.cpp math_*) -----------------
    // Retail: every math_X takes a float from luaL_checknumber in st(0), runs
    // an inline x87 sequence or a CRT entry, and stores the result with
    // `fstp dword` before lua_pushnumber. "Ours" mirrors the exact expression
    // of each math_X (that TU does not compile standalone); keep in sync.
    constexpr u32 kRetailAsin = 0x00A8DE20;   // _CIasin
    constexpr u32 kRetailAcos = 0x00A8DCD0;   // _CIacos
    constexpr u32 kRetailFmod = 0x00A8E06A;   // _CIfmod
    constexpr u32 kRetailCeil = 0x00A840A0;   // ceil
    constexpr u32 kRetailFloor = 0x00A8DF30;  // floor
    constexpr u32 kRetailTan = 0x00919A40;    // fld; fptan; fstp st(0)
    constexpr u32 kRetailLog10 = 0x00919980;  // fld; fldlg2; fxch; fyl2x
    constexpr u32 kRetailExp = 0x009199D0;    // the /Oi exp expansion
    constexpr u32 kRetailLn = 0x0040EAD0;     // fld; fldln2; fxch; fyl2x
    constexpr u32 kRetailDegrees = 0x00D46340; // 57.29578f
    constexpr u32 kRetailRadians = 0x00D46344; // 0.017453292f

    // Any float, NaN and inf included: the inline x87 lanes have no error path.
    void GenLuaAny(Rng& rng, u32* in)
    {
      const u32 mode = rng.Below(100);
      in[0] = Bits(mode < 40 ? GenPlain(rng, 10.0f) : mode < 50 ? GenAngle(rng) : GenFloat(rng));
    }
    // [-1, 1]: asin/acos outside it take the CRT's errno path (trapped import).
    void GenLuaUnit(Rng& rng, u32* in)
    {
      float x;
      const u32 mode = rng.Below(100);
      if (mode < 50) {
        x = static_cast<float>(rng.Range(-1.0, 1.0));
      } else if (mode < 65) {
        x = FromBits(0x3F800000u - rng.Below(4096));
      } else if (mode < 75) {
        x = rng.Chance(50) ? 1.0f : 0.0f;
      } else {
        x = GenFloat(rng);
        if (!(std::fabs(x) <= 1.0f)) {
          x = static_cast<float>(rng.Range(0.0, 1.0)) * FromBits(0x3F800000u - (rng.Below(64) << 23));
        }
      }
      in[0] = Bits(rng.Chance(50) ? x : -x);
    }
    // Finite or infinite, never NaN: ceil/floor/ldexp send NaN to the CRT's
    // error handler.
    void GenLuaNotNan(Rng& rng, u32* in)
    {
      GenLuaAny(rng, in);
      if (std::isnan(FromBits(in[0]))) {
        in[0] = Bits(-0.0f);
      }
    }
    void GenLuaFinite(Rng& rng, u32* in)
    {
      GenLuaAny(rng, in);
      if (!std::isfinite(FromBits(in[0]))) {
        in[0] = Bits(rng.Chance(50) ? 0.0f : -0.0f);
      }
    }

    void LuaAbsRetail(const u32* in, u32* out) { Put(out, 0, retail::Fabsf(F(in, 0))); } // math_abs: inline fabs
    void LuaAbsOurs(const u32* in, u32* out)
    {
      Put(out, 0, static_cast<float>(std::fabs(static_cast<double>(F(in, 0)))));
    }
    void LuaTanRetail(const u32* in, u32* out) { Put(out, 0, retail::UnaryFloatLeaf(kRetailTan, F(in, 0))); }
    void LuaTanOurs(const u32* in, u32* out) { Put(out, 0, msvc8::tanf(F(in, 0))); }
    // math_atan: `fld1; fpatan` == the float atan2 leaf with x = 1.
    void LuaAtanRetail(const u32* in, u32* out) { Put(out, 0, retail::Atan2f(F(in, 0), 1.0f)); }
    void LuaAtanOurs(const u32* in, u32* out) { Put(out, 0, msvc8::atanf(F(in, 0))); }
    void LuaSqrtRetail(const u32* in, u32* out) { Put(out, 0, retail::Sqrtf(F(in, 0))); } // math_sqrt: inline fsqrt
    void LuaSqrtOurs(const u32* in, u32* out)
    {
      Put(out, 0, static_cast<float>(std::sqrt(static_cast<double>(F(in, 0)))));
    }
    void LuaLogRetail(const u32* in, u32* out) { Put(out, 0, retail::UnaryFloatLeaf(kRetailLn, F(in, 0))); }
    void LuaLogOurs(const u32* in, u32* out) { Put(out, 0, msvc8::IntrinsicLn(F(in, 0))); }
    void LuaLog10Retail(const u32* in, u32* out) { Put(out, 0, retail::UnaryFloatLeaf(kRetailLog10, F(in, 0))); }
    void LuaLog10Ours(const u32* in, u32* out) { Put(out, 0, msvc8::IntrinsicLog10(F(in, 0))); }
    void LuaExpRetail(const u32* in, u32* out) { Put(out, 0, retail::UnaryFloatLeaf(kRetailExp, F(in, 0))); }
    void LuaExpOurs(const u32* in, u32* out) { Put(out, 0, msvc8::IntrinsicExp(F(in, 0))); }
    void LuaDegRetail(const u32* in, u32* out) { Put(out, 0, retail::MulImageConstant(F(in, 0), kRetailDegrees)); }
    void LuaDegOurs(const u32* in, u32* out) { Put(out, 0, msvc8::MultiplyX87(F(in, 0), 57.29578f)); }
    void LuaRadRetail(const u32* in, u32* out) { Put(out, 0, retail::MulImageConstant(F(in, 0), kRetailRadians)); }
    void LuaRadOurs(const u32* in, u32* out) { Put(out, 0, msvc8::MultiplyX87(F(in, 0), 0.017453292f)); }

    void LuaAsinRetail(const u32* in, u32* out)
    {
      float r;
      retail::CrtStackUnaryF(kRetailAsin, F(in, 0), &r);
      Put(out, 0, r);
    }
    void LuaAsinOurs(const u32* in, u32* out)
    {
      Put(out, 0, static_cast<float>(msvc8::asin(static_cast<double>(F(in, 0)))));
    }
    void LuaAcosRetail(const u32* in, u32* out)
    {
      float r;
      retail::CrtStackUnaryF(kRetailAcos, F(in, 0), &r);
      Put(out, 0, r);
    }
    void LuaAcosOurs(const u32* in, u32* out)
    {
      Put(out, 0, static_cast<float>(msvc8::acos(static_cast<double>(F(in, 0)))));
    }
    void LuaCeilRetail(const u32* in, u32* out)
    {
      float r;
      retail::CrtDoubleArgF(kRetailCeil, F(in, 0), &r);
      Put(out, 0, r);
    }
    void LuaCeilOurs(const u32* in, u32* out)
    {
      Put(out, 0, static_cast<float>(std::ceil(static_cast<double>(F(in, 0))))); // LuaCeilBridge
    }
    void LuaFloorRetail(const u32* in, u32* out)
    {
      float r;
      retail::CrtDoubleArgF(kRetailFloor, F(in, 0), &r);
      Put(out, 0, r);
    }
    void LuaFloorOurs(const u32* in, u32* out)
    {
      Put(out, 0, static_cast<float>(std::floor(static_cast<double>(F(in, 0)))));
    }

    // math.mod: finite operands, non-zero divisor (anything else is the
    // CRT's errno path).
    void GenLuaMod(Rng& rng, u32* in)
    {
      float x = rng.Chance(70) ? GenPlain(rng, 1000.0f) : GenFloat(rng);
      if (!std::isfinite(x)) {
        x = rng.Chance(50) ? 0.0f : -0.0f;
      }
      float y = rng.Chance(60) ? GenPlain(rng, 20.0f) : GenFloat(rng);
      if (!std::isfinite(y) || y == 0.0f) {
        y = 360.0f;
      }
      if (rng.Chance(10)) {
        const float multiple = y * static_cast<float>(static_cast<int>(rng.Below(9)) - 4);
        if (std::isfinite(multiple)) {
          x = multiple;
        }
      }
      in[0] = Bits(x);
      in[1] = Bits(y);
    }
    void LuaModRetail(const u32* in, u32* out)
    {
      float r;
      retail::CrtStackBinaryF(kRetailFmod, F(in, 0), F(in, 1), &r);
      Put(out, 0, r);
    }
    void LuaModOurs(const u32* in, u32* out)
    {
      Put(out, 0, static_cast<float>(msvc8::fmod(static_cast<double>(F(in, 0)), static_cast<double>(F(in, 1)))));
    }

    void LuaFrexpRetail(const u32* in, u32* out)
    {
      float mantissa = FromBits(kCanary);
      int exponent = 0x7EADBEEF;
      retail::FrexpF(F(in, 0), &mantissa, &exponent);
      Put(out, 0, mantissa);
      Put(out, 1, static_cast<float>(exponent)); // cvtsi2ss (0x00919E1D)
    }
    void LuaFrexpOurs(const u32* in, u32* out)
    {
      int exponent = 0;
      const float mantissa = static_cast<float>(msvc8::frexp(static_cast<double>(F(in, 0)), &exponent));
      Put(out, 0, mantissa);
      Put(out, 1, static_cast<float>(exponent));
    }

    // math.ldexp(x, n): n is truncated by _ftol2; keep |exponent(x) + n|
    // inside double's normal range (beyond it the CRT raises through errno).
    void GenLuaLdexp(Rng& rng, u32* in)
    {
      GenLuaNotNan(rng, in); // an infinity returns itself (class 1/2, 0x00A8DB43)
      const u32 mode = rng.Below(100);
      float n;
      if (mode < 50) {
        n = static_cast<float>(static_cast<int>(rng.Below(81)) - 40);
      } else if (mode < 80) {
        n = static_cast<float>(rng.Range(-800.0, 800.0));
      } else {
        n = static_cast<float>(static_cast<int>(rng.Below(321)) - 160) + (rng.Chance(50) ? 0.5f : -0.75f);
      }
      in[1] = Bits(n);
    }
    void LuaLdexpRetail(const u32* in, u32* out)
    {
      float r;
      retail::LdexpF(F(in, 0), F(in, 1), &r);
      Put(out, 0, r);
    }
    void LuaLdexpOurs(const u32* in, u32* out)
    {
      const int exponent = static_cast<int>(F(in, 1));
      Put(out, 0, static_cast<float>(std::ldexp(static_cast<double>(F(in, 0)), exponent)));
    }

    // math.random: in[0] = rand() value, in[1] = argument count (0..2),
    // in[2]/in[3] = the integer arguments (already through _ftol2).
    int GenRandomInt(Rng& rng)
    {
      const u32 mode = rng.Below(100);
      if (mode < 40) {
        return static_cast<int>(rng.Below(200)) - 20;
      }
      if (mode < 60) {
        return static_cast<int>(rng.Below(1u << 20));
      }
      if (mode < 80) {
        return static_cast<int>(rng.U32() >> 1);
      }
      return static_cast<int>(rng.U32());
    }
    constexpr float kLuaRandomScale = 3.0518509447574615e-05f;

    // A span whose exact product with the sample has the 55-bit pattern
    // [24 bits, last one even][1][28 zeros][01 or 10]: a double multiply
    // rounds it onto a float tie and round-half-even then picks the wrong
    // side. Needs an odd sample mantissa m: span = c * m^-1 (mod 2^32).
    bool GenRandomTie(Rng& rng, u32* in)
    {
      for (int attempt = 0; attempt < 64; ++attempt) {
        const u32 randValue = 1u + rng.Below(0x7FFEu);
        const float sample = static_cast<float>(static_cast<int>(randValue)) * kLuaRandomScale;
        const u32 mantissa = (Bits(sample) & 0x007FFFFFu) | 0x00800000u;
        if ((mantissa & 1u) == 0) {
          continue;
        }
        u32 inverse = mantissa; // Newton: each step doubles the correct low bits
        for (int i = 0; i < 5; ++i) {
          inverse *= 2u - mantissa * inverse;
        }
        const u32 span = ((1u << 30) + (rng.Chance(50) ? 1u : 2u)) * inverse;
        if (span < (1u << 29) || span >= (1u << 31)) {
          continue;
        }
        in[0] = randValue;
        if (rng.Chance(50)) {
          in[1] = 1;
          in[2] = span;
          in[3] = 0;
        } else {
          in[1] = 2;
          in[2] = 0u - rng.Below(1000); // lower; upper - lower + 1 == span
          in[3] = in[2] + span - 1u;
        }
        return true;
      }
      return false;
    }
    void GenLuaRandom(Rng& rng, u32* in)
    {
      if (rng.Chance(10) && GenRandomTie(rng, in)) {
        return;
      }
      in[0] = rng.Chance(5) ? 0x7FFFu - rng.Below(3) : rng.Below(0x8000u);
      const u32 argumentCount = rng.Below(3);
      int a = GenRandomInt(rng);
      int b = GenRandomInt(rng);
      if (argumentCount == 1 && a < 1) {
        a = 1 - a / 2; // an upper bound below 1 raises luaL_argerror
      }
      if (argumentCount == 2 && a > b) {
        const int t = a; // lower > upper raises luaL_argerror
        a = b;
        b = t;
      }
      in[1] = argumentCount;
      in[2] = static_cast<u32>(a);
      in[3] = static_cast<u32>(b);
    }
    void LuaRandomRetail(const u32* in, u32* out)
    {
      const float sample = retail::RandomSample(static_cast<int>(in[0]));
      float r = sample;
      if (in[1] == 1) {
        retail::RandomPickUpTo(static_cast<int>(in[2]), sample, &r);
      } else if (in[1] == 2) {
        const int count = static_cast<int>(in[3] - in[2] + 1u); // sub esi, ebx; add esi, 1
        retail::RandomPickRange(count, sample, static_cast<int>(in[2]), &r);
      }
      Put(out, 0, r);
    }
    // math_random (LuaObject.cpp): sample, then the one- or two-argument lane.
    void LuaRandomOurs(const u32* in, u32* out)
    {
      const float sample = static_cast<float>(static_cast<int>(in[0]) % 0x7FFF) * kLuaRandomScale;
      float r = sample;
      if (in[1] == 1) {
        const int upper = static_cast<int>(in[2]);
        const float scaled = msvc8::MultiplyIntegerX87(upper, sample);
        const float picked = std::floor(scaled);
        r = picked + 1.0f;
      } else if (in[1] == 2) {
        const int lower = static_cast<int>(in[2]);
        const int upper = static_cast<int>(in[3]);
        const auto span =
          static_cast<std::int32_t>(static_cast<std::uint32_t>(upper) - static_cast<std::uint32_t>(lower) + 1u);
        const float scaled = msvc8::MultiplyIntegerX87(span, sample);
        const float picked = std::floor(scaled);
        r = static_cast<float>(static_cast<double>(picked) + static_cast<double>(lower));
      }
      Put(out, 0, r);
    }

    void LuaSeedRetail(const u32* in, u32* out) { out[0] = retail::RandomSeedWord(F(in, 0)); }
    void LuaSeedOurs(const u32* in, u32* out)
    {
      out[0] = static_cast<unsigned int>(static_cast<std::int64_t>(F(in, 0)));
    }

    // ---- Wm3::Vector3<float>::Normalize 0x00452AF0 --------------------------
    void GenV3(Rng& rng, u32* in)
    {
      float v[3];
      GenVec3(rng, v);
      PutF(in, 0, v, 3);
    }
    void NormalizeRetail(const u32* in, u32* out)
    {
      Vec v;
      Load(v, in, 0);
      const float len = retail::Wm3Normalize(&v);
      PutBlock(out, 0, &v, 3);
      Put(out, 3, len);
    }
    void NormalizeOurs(const u32* in, u32* out)
    {
      Vec v;
      Load(v, in, 0);
      const float len = Vec::Normalize(&v);
      PutBlock(out, 0, &v, 3);
      Put(out, 3, len);
    }

    // ---- NormalizeVectorInto 0x0044F7E0 --------------------------------------
    void NormIntoRetail(const u32* in, u32* out)
    {
      Vec src, dst;
      Load(src, in, 0);
      Canary(dst);
      out[3] = retail::NormalizeVectorInto(&dst, &src) == &dst;
      PutBlock(out, 0, &dst, 3);
      PutBlock(out, 4, &src, 3);
    }
    void NormIntoOurs(const u32* in, u32* out)
    {
      Vec src, dst;
      Load(src, in, 0);
      Canary(dst);
      out[3] = moho::NormalizeVectorInto(&dst, src) == &dst;
      PutBlock(out, 0, &dst, 3);
      PutBlock(out, 4, &src, 3);
    }

    // ---- QuatCrossAdd 0x0044F880 ---------------------------------------------
    void GenCrossAdd(Rng& rng, u32* in)
    {
      float v1[3], v2[3], fb[3];
      GenVecPair(rng, v1, v2);
      const u32 mode = rng.Below(100);
      if (mode < 40) {
        fb[0] = 1.0f, fb[1] = 0.0f, fb[2] = 0.0f;
      } else if (mode < 80) {
        fb[0] = 0.0f, fb[1] = 1.0f, fb[2] = 0.0f;
      } else {
        GenVec3(rng, fb);
      }
      PutF(in, 0, v1, 3);
      PutF(in, 3, v2, 3);
      PutF(in, 6, fb, 3);
    }
    void CrossAddRetail(const u32* in, u32* out)
    {
      Vec v1, v2, fb;
      Quat q;
      Load(v1, in, 0);
      Load(v2, in, 3);
      Load(fb, in, 6);
      Canary(q);
      out[4] = retail::QuatCrossAdd(&q, &v1, &v2, &fb) == &q;
      PutBlock(out, 0, &q, 4);
    }
    void CrossAddOurs(const u32* in, u32* out)
    {
      Vec v1, v2, fb;
      Quat q;
      Load(v1, in, 0);
      Load(v2, in, 3);
      Load(fb, in, 6);
      Canary(q);
      out[4] = moho::QuatCrossAdd(&q, v1, v2, fb) == &q;
      PutBlock(out, 0, &q, 4);
    }

    // ---- QuatFromVecRot 0x0069AA50 -------------------------------------------
    void GenFromVecRot(Rng& rng, u32* in)
    {
      float q[4], r[3];
      GenQuat(rng, q);
      const u32 mode = rng.Below(100);
      if (mode < 30) {
        // +- the quaternion's own forward axis (third matrix column), nudged.
        const double w = q[0], x = q[1], y = q[2], z = q[3];
        const double f[3] = {2 * (x * z + w * y), 2 * (y * z - w * x), 1 - 2 * (x * x + y * y)};
        const double s = rng.Chance(50) ? 1.0 : -1.0;
        for (int i = 0; i < 3; ++i) {
          r[i] = static_cast<float>(s * f[i] + (rng.Chance(50) ? 0.0 : 1e-6 * rng.Range(-1, 1)));
        }
      } else {
        GenVec3(rng, r);
      }
      PutF(in, 0, q, 4);
      PutF(in, 4, r, 3);
      in[7] = Bits(GenAngle(rng));
    }
    void FromVecRotRetail(const u32* in, u32* out)
    {
      Quat q;
      Vec r;
      Load(q, in, 0);
      Load(r, in, 4);
      retail::QuatFromVecRot(&q, &r, F(in, 7));
      PutBlock(out, 0, &q, 4);
      PutBlock(out, 4, &r, 3);
    }
    void FromVecRotOurs(const u32* in, u32* out)
    {
      Quat q;
      Vec r;
      Load(q, in, 0);
      Load(r, in, 4);
      moho::QuatFromVecRot(&q, &r, F(in, 7));
      PutBlock(out, 0, &q, 4);
      PutBlock(out, 4, &r, 3);
    }

    // ---- RotateQuatByAngle 0x004EB740 ----------------------------------------
    void GenRotate(Rng& rng, u32* in)
    {
      float q[4];
      GenQuat(rng, q);
      PutF(in, 0, q, 4);
      in[4] = Bits(GenAngle(rng));
    }
    void RotateRetail(const u32* in, u32* out)
    {
      Quat q;
      Load(q, in, 0);
      out[4] = static_cast<u32>(retail::RotateQuatByAngle(&q, F(in, 4)));
      PutBlock(out, 0, &q, 4);
    }
    void RotateOurs(const u32* in, u32* out)
    {
      Quat q;
      Load(q, in, 0);
      out[4] = moho::RotateQuatByAngle(&q, F(in, 4)) ? 1u : 0u;
      PutBlock(out, 0, &q, 4);
    }

    // ---- SLERP 0x004EBC00 / QuatLERP 0x004EBA80 ------------------------------
    void GenInterp(Rng& rng, u32* in)
    {
      float a[4], b[4];
      GenQuatPair(rng, a, b);
      PutF(in, 0, a, 4);
      PutF(in, 4, b, 4);
      in[8] = Bits(GenT(rng));
    }
    // in[0..3] = first register operand (eax), in[4..7] = second (ecx).
    void SlerpRetail(const u32* in, u32* out)
    {
      Quat a, b, o;
      Load(a, in, 0);
      Load(b, in, 4);
      Canary(o);
      out[4] = retail::Slerp(&a, &b, &o, F(in, 8)) == &o;
      PutBlock(out, 0, &o, 4);
    }
    void SlerpOurs(const u32* in, u32* out)
    {
      Quat a, b, o;
      Load(a, in, 0);
      Load(b, in, 4);
      Canary(o);
      out[4] = moho::SLERP(&a, &b, &o, F(in, 8)) == &o;
      PutBlock(out, 0, &o, 4);
    }
    void LerpRetail(const u32* in, u32* out)
    {
      Quat a, b, o;
      Load(a, in, 0);
      Load(b, in, 4);
      Canary(o);
      out[4] = retail::QuatLerp(&a, &b, &o, F(in, 8)) == &o;
      PutBlock(out, 0, &o, 4);
    }
    void LerpOurs(const u32* in, u32* out)
    {
      Quat a, b, o;
      Load(a, in, 0);
      Load(b, in, 4);
      Canary(o);
      out[4] = moho::QuatLERP(&a, &b, &o, F(in, 8)) == &o;
      PutBlock(out, 0, &o, 4);
    }

    // ---- MultQuadVec 0x00452D40 / QuatToMatrix 0x00452FD0 --------------------
    void GenQuatVec(Rng& rng, u32* in)
    {
      float v[3], q[4];
      GenVec3(rng, v);
      GenQuat(rng, q);
      PutF(in, 0, v, 3);
      PutF(in, 3, q, 4);
    }
    void MultRetail(const u32* in, u32* out)
    {
      Vec v, d;
      Quat q;
      Load(v, in, 0);
      Load(q, in, 3);
      Canary(d);
      out[3] = retail::MultQuadVec(&d, &v, &q) == &d;
      PutBlock(out, 0, &d, 3);
    }
    void MultOurs(const u32* in, u32* out)
    {
      Vec v, d;
      Quat q;
      Load(v, in, 0);
      Load(q, in, 3);
      Canary(d);
      out[3] = moho::MultQuadVec(&d, &v, &q) == &d;
      PutBlock(out, 0, &d, 3);
    }
    void GenQ(Rng& rng, u32* in)
    {
      float q[4];
      GenQuat(rng, q);
      PutF(in, 0, q, 4);
    }
    void ToMatrixRetail(const u32* in, u32* out)
    {
      Quat q;
      Vec rows[3];
      Load(q, in, 0);
      Canary(rows);
      out[9] = retail::QuatToMatrix(&q, rows) == rows;
      PutBlock(out, 0, rows, 9);
    }
    void ToMatrixOurs(const u32* in, u32* out)
    {
      Quat q;
      Vec rows[3];
      Load(q, in, 0);
      Canary(rows);
      out[9] = moho::QuatToMatrix(&q, rows) == rows;
      PutBlock(out, 0, rows, 9);
    }

    // ---- VecSetLengthTo 0x0069A360 / VecSetLength 0x005B1C90 -----------------
    void GenTwoVec(Rng& rng, u32* in)
    {
      float a[3], b[3];
      GenVec3(rng, a);
      GenVec3(rng, b);
      PutF(in, 0, a, 3);
      PutF(in, 3, b, 3);
    }
    // in[0..2] = target-length vector, in[3..5] = source direction.
    void SetLengthToRetail(const u32* in, u32* out)
    {
      Vec t, s, d;
      Load(t, in, 0);
      Load(s, in, 3);
      Canary(d);
      out[3] = retail::VecSetLengthTo(&d, &t, &s) == &d;
      PutBlock(out, 0, &d, 3);
    }
    void SetLengthToOurs(const u32* in, u32* out)
    {
      Vec t, s, d;
      Load(t, in, 0);
      Load(s, in, 3);
      Canary(d);
      out[3] = moho::VecSetLengthTo(&d, &t, &s) == &d;
      PutBlock(out, 0, &d, 3);
    }
    void GenVecLen(Rng& rng, u32* in)
    {
      float v[3];
      GenVec3(rng, v);
      PutF(in, 0, v, 3);
      in[3] = Bits(rng.Chance(60) ? static_cast<float>(rng.Range(0.0, 50.0)) : GenFloat(rng));
    }
    void SetLengthRetail(const u32* in, u32* out)
    {
      Vec v;
      Load(v, in, 0);
      out[3] = static_cast<u32>(retail::VecSetLength(&v, F(in, 3)));
      PutBlock(out, 0, &v, 3);
    }
    void SetLengthOurs(const u32* in, u32* out)
    {
      Vec v;
      Load(v, in, 0);
      out[3] = moho::VecSetLength(&v, F(in, 3)) ? 1u : 0u;
      PutBlock(out, 0, &v, 3);
    }

    // ---- NormalizeQuatInPlace 0x004EDAA0 / QuatsNearEqual 0x004EDED0 ---------
    void NormQuatRetail(const u32* in, u32* out)
    {
      Quat q;
      Load(q, in, 0);
      retail::NormalizeQuatInPlace(&q);
      PutBlock(out, 0, &q, 4);
    }
    void NormQuatOurs(const u32* in, u32* out)
    {
      Quat q;
      Load(q, in, 0);
      moho::NormalizeQuatInPlace(&q);
      PutBlock(out, 0, &q, 4);
    }
    void GenNear(Rng& rng, u32* in)
    {
      float a[4], b[4];
      GenQuat(rng, a);
      for (int i = 0; i < 4; ++i) {
        // Straddle the 1e-6 tolerance: +-1e-6 +- a few ulps, or a random gap.
        const u32 mode = rng.Below(100);
        if (mode < 40) {
          b[i] = a[i];
        } else if (mode < 80) {
          const float d = FromBits(0x358637BDu + rng.Below(9) - 4);
          b[i] = a[i] + (rng.Chance(50) ? d : -d);
        } else {
          b[i] = rng.Chance(50) ? GenFloat(rng) : a[i] + GenPlain(rng, 1e-5f);
        }
      }
      PutF(in, 0, a, 4);
      PutF(in, 4, b, 4);
    }
    void NearRetail(const u32* in, u32* out)
    {
      Quat a, b;
      Load(a, in, 0);
      Load(b, in, 4);
      out[0] = static_cast<u32>(retail::QuatsNearEqual(&a, &b));
    }
    void NearOurs(const u32* in, u32* out)
    {
      Quat a, b;
      Load(a, in, 0);
      Load(b, in, 4);
      out[0] = moho::QuatsNearEqual(a, b) ? 1u : 0u;
    }

    // ---- second wave ---------------------------------------------------------
    void GenRows(Rng& rng, u32* in)
    {
      float m[9];
      const u32 mode = rng.Below(100);
      if (mode < 25) {
        for (float& v : m) {
          v = GenFloat(rng);
        }
      } else {
        float q[4];
        GenQuat(rng, q);
        const double w = q[0], x = q[1], y = q[2], z = q[3];
        const double r[9] = {1 - 2 * (y * y + z * z), 2 * (x * y - w * z), 2 * (x * z + w * y),
                             2 * (x * y + w * z), 1 - 2 * (x * x + z * z), 2 * (y * z - w * x),
                             2 * (x * z - w * y), 2 * (y * z + w * x), 1 - 2 * (x * x + y * y)};
        for (int i = 0; i < 9; ++i) {
          m[i] = static_cast<float>(r[i] + (mode < 50 ? 1e-4 * rng.Range(-1, 1) : 0.0));
        }
      }
      PutF(in, 0, m, 9);
    }
    void GenRowsPair(Rng& rng, u32* in)
    {
      GenRows(rng, in);
      GenRows(rng, in + 9);
    }

    void DistRetail(const u32* in, u32* out)
    {
      Vec a, b;
      Load(a, in, 0);
      Load(b, in, 3);
      Put(out, 0, retail::DistanceSquared3D(&a, &b));
    }
    void DistOurs(const u32* in, u32* out)
    {
      Vec a, b;
      Load(a, in, 0);
      Load(b, in, 3);
      Put(out, 0, moho::DistanceSquared3D(a, b));
    }
    void ReflectRetail(const u32* in, u32* out)
    {
      Vec i, n, d;
      Load(i, in, 0);
      Load(n, in, 3);
      Canary(d);
      out[3] = retail::ReflectAcrossNormal(&d, &i, &n) == &d;
      PutBlock(out, 0, &d, 3);
    }
    void ReflectOurs(const u32* in, u32* out)
    {
      Vec i, n, d;
      Load(i, in, 0);
      Load(n, in, 3);
      Canary(d);
      out[3] = moho::ReflectVector3fAcrossNormal(&d, &i, &n) == &d;
      PutBlock(out, 0, &d, 3);
    }
    void UnitRetail(const u32* in, u32* out)
    {
      Vec v;
      Load(v, in, 0);
      out[0] = static_cast<u32>(retail::IsUnitLength(&v));
    }
    void UnitOurs(const u32* in, u32* out)
    {
      Vec v;
      Load(v, in, 0);
      out[0] = moho::IsUnitLengthVector3f(v) ? 1u : 0u;
    }
    void AxisRetail(const u32* in, u32* out)
    {
      Vec v;
      Load(v, in, 0);
      out[0] = static_cast<u32>(retail::LargestAxis(&v));
    }
    void AxisOurs(const u32* in, u32* out)
    {
      Vec v;
      Load(v, in, 0);
      out[0] = static_cast<u32>(moho::VEC_LargestAxis(v));
    }
    void GenVecScalar(Rng& rng, u32* in)
    {
      float v[3];
      GenVec3(rng, v);
      PutF(in, 0, v, 3);
      in[3] = Bits(rng.Chance(20) ? (rng.Chance(50) ? 0.0f : -0.0f) : GenFloat(rng));
    }
    void RecipRetail(const u32* in, u32* out)
    {
      Vec v;
      Load(v, in, 0);
      out[3] = retail::ScaleByReciprocalOrSetMax(&v, F(in, 3)) == &v;
      PutBlock(out, 0, &v, 3);
    }
    void RecipOurs(const u32* in, u32* out)
    {
      Vec v;
      Load(v, in, 0);
      out[3] = moho::VecScaleByReciprocalOrSetMax(&v, F(in, 3)) == &v;
      PutBlock(out, 0, &v, 3);
    }
    void HeadingRetail(const u32* in, u32* out)
    {
      Vec v;
      Load(v, in, 0);
      Put(out, 0, retail::HeadingFromXZ(&v));
    }
    void HeadingOurs(const u32* in, u32* out)
    {
      Vec v;
      Load(v, in, 0);
      Put(out, 0, moho::VEC_HeadingFromXZ(&v));
    }
    void YAxisRetail(const u32* in, u32* out)
    {
      Quat q;
      Vec o;
      Load(q, in, 0);
      Canary(o);
      out[3] = retail::ExtractYAxisColumn(&o, &q) == &o;
      PutBlock(out, 0, &o, 3);
    }
    void YAxisOurs(const u32* in, u32* out)
    {
      Quat q;
      Vec o;
      Load(q, in, 0);
      Canary(o);
      out[3] = moho::QuaternionExtractYAxisColumn(&o, &q) == &o;
      PutBlock(out, 0, &o, 3);
    }
    void ConjRetail(const u32* in, u32* out)
    {
      Vec v, o;
      Quat q;
      Load(v, in, 0);
      Load(q, in, 3);
      Canary(o);
      out[3] = retail::RotateByConjugate(&q, &o, &v) == &o;
      PutBlock(out, 0, &o, 3);
    }
    void ConjOurs(const u32* in, u32* out)
    {
      Vec v, o;
      Quat q;
      Load(v, in, 0);
      Load(q, in, 3);
      Canary(o);
      out[3] = moho::RotateVectorByConjugateQuaternionLanes(&q.w, &o, &v) == &o;
      PutBlock(out, 0, &o, 3);
    }
    void AxisAngleRetail(const u32* in, u32* out)
    {
      Vec v;
      Quat q;
      Load(v, in, 0);
      Canary(q);
      out[4] = retail::QuatFromAxisAngleVector(&q, &v) == &q;
      PutBlock(out, 0, &q, 4);
    }
    void AxisAngleOurs(const u32* in, u32* out)
    {
      Vec v;
      Quat q;
      Load(v, in, 0);
      Canary(q);
      out[4] = moho::QuatFromAxisAngleVector(&q, v) == &q;
      PutBlock(out, 0, &q, 4);
    }
    void GenAxisRoll(Rng& rng, u32* in)
    {
      float v[3];
      GenVec3(rng, v);
      PutF(in, 0, v, 3);
      in[3] = Bits(GenAngle(rng));
    }
    void RollRetail(const u32* in, u32* out)
    {
      Vec a;
      Quat q;
      Load(a, in, 0);
      Canary(q);
      out[4] = retail::EulerRollToQuat(&a, &q, F(in, 3)) == &q;
      PutBlock(out, 0, &q, 4);
    }
    void RollOurs(const u32* in, u32* out)
    {
      Vec a;
      Quat q;
      Load(a, in, 0);
      Canary(q);
      out[4] = moho::EulerRollToQuat(&a, &q, F(in, 3)) == &q;
      PutBlock(out, 0, &q, 4);
    }
    void LimitRetail(const u32* in, u32* out)
    {
      Vec v;
      Load(v, in, 0);
      out[3] = static_cast<u32>(retail::VecLimitLengthTo(&v, F(in, 3)));
      PutBlock(out, 0, &v, 3);
    }
    void LimitOurs(const u32* in, u32* out)
    {
      Vec v;
      Load(v, in, 0);
      out[3] = moho::VecLimitLengthTo(&v, F(in, 3)) ? 1u : 0u;
      PutBlock(out, 0, &v, 3);
    }
    void M2QRetail(const u32* in, u32* out)
    {
      Vec rows[3];
      Quat q;
      Load(rows, in, 0);
      Canary(q);
      retail::MatrixToQuat(rows, &q);
      PutBlock(out, 0, &q, 4);
    }
    void M2QOurs(const u32* in, u32* out)
    {
      Vec rows[3];
      Quat q;
      Load(rows, in, 0);
      Canary(q);
      (void)moho::MatrixToQuat(rows, &q);
      PutBlock(out, 0, &q, 4);
    }
    void M2QCRetail(const u32* in, u32* out)
    {
      Vec rows[3];
      Quat q;
      Load(rows, in, 0);
      Canary(q);
      retail::MatrixRowsToQuatCanonical(rows, &q);
      PutBlock(out, 0, &q, 4);
    }
    void M2QCOurs(const u32* in, u32* out)
    {
      Vec rows[3];
      Quat q;
      Load(rows, in, 0);
      Canary(q);
      (void)moho::MatrixRowsToQuatCanonical(rows, &q);
      PutBlock(out, 0, &q, 4);
    }
    void ToAxisRetail(const u32* in, u32* out)
    {
      Quat q;
      Vec axis;
      float angle;
      Load(q, in, 0);
      Canary(axis);
      Canary(angle);
      retail::QuatToAxisAndAngle(&q, &axis, &angle);
      PutBlock(out, 0, &axis, 3);
      Put(out, 3, angle);
    }
    void ToAxisOurs(const u32* in, u32* out)
    {
      Quat q;
      Vec axis;
      float angle;
      Load(q, in, 0);
      Canary(axis);
      Canary(angle);
      moho::QuatToAxisAndAngle(q, &axis, &angle);
      PutBlock(out, 0, &axis, 3);
      Put(out, 3, angle);
    }
    void GenTilt(Rng& rng, u32* in)
    {
      float a[3], b[3];
      GenVecPair(rng, a, b);
      PutF(in, 0, a, 3);
      PutF(in, 3, b, 3);
    }
    // in[0..2] = target normal, in[3..5] = current up.
    void TiltRetail(const u32* in, u32* out)
    {
      Vec n, up;
      Quat q;
      Load(n, in, 0);
      Load(up, in, 3);
      Canary(q);
      out[4] = retail::TiltShortestArcDelta(&n, &q, &up) == &q;
      PutBlock(out, 0, &q, 4);
    }
    void TiltOurs(const u32* in, u32* out)
    {
      Vec n, up;
      Quat q;
      Load(n, in, 0);
      Load(up, in, 3);
      Canary(q);
      out[4] = moho::BuildTiltShortestArcDelta(n, &q, up) == &q;
      PutBlock(out, 0, &q, 4);
    }
    void GenFiniteAngle(Rng& rng, u32* in)
    {
      float a = rng.Chance(80) ? GenPlain(rng, 100.0f) : GenFloat(rng);
      if (!std::isfinite(a)) {
        a = 0.0f; // inf/NaN take fmod's CRT error path (errno -> imports)
      }
      in[0] = Bits(a);
    }
    void NormAngleRetail(const u32* in, u32* out) { Put(out, 0, retail::NormalizeAngle(F(in, 0))); }
    void NormAngleOurs(const u32* in, u32* out) { Put(out, 0, moho::NormalizeAngleSignedRadians(F(in, 0))); }
    void Mul3Retail(const u32* in, u32* out)
    {
      Vec a[3], b[3], r[3];
      Load(a, in, 0);
      Load(b, in, 9);
      Canary(r);
      out[9] = retail::Multiply3x3(r, a, b) == r;
      PutBlock(out, 0, r, 9);
    }
    void Mul3Ours(const u32* in, u32* out)
    {
      Vec a[3], b[3], r[3];
      Load(a, in, 0);
      Load(b, in, 9);
      Canary(r);
      out[9] = moho::Multiply3x3RowMatrices(r, a, b) == r;
      PutBlock(out, 0, r, 9);
    }
    void GenHpr(Rng& rng, u32* in)
    {
      for (int i = 0; i < 3; ++i) {
        in[i] = Bits(GenAngle(rng));
      }
    }
    void HprRetail(const u32* in, u32* out)
    {
      Vec r[3];
      Canary(r);
      out[9] = retail::EulerHPRToMatrix(r, F(in, 0), F(in, 1), F(in, 2)) == r;
      PutBlock(out, 0, r, 9);
    }
    void HprOurs(const u32* in, u32* out)
    {
      Vec r[3];
      Canary(r);
      out[9] = moho::BuildRotationMatrixFromEulerHPR(r, F(in, 0), F(in, 1), F(in, 2)) == r;
      PutBlock(out, 0, r, 9);
    }
    // in[0..3] = goal, in[4..7] = current, in[8] = step.
    void BlendRetail(const u32* in, u32* out)
    {
      Quat g, c, o;
      u32 flag = kCanary;
      Load(g, in, 0);
      Load(c, in, 4);
      Canary(o);
      out[5] = retail::BlendOrientation(&g, &c, F(in, 8), &flag, &o) == &o;
      PutBlock(out, 0, &o, 4);
      out[4] = flag;
    }
    void BlendOurs(const u32* in, u32* out)
    {
      Quat g, c, o;
      u32 flag = kCanary;
      Load(g, in, 0);
      Load(c, in, 4);
      Canary(o);
      out[5] = moho::BlendOrientationDeltaByMaxAngle(g, c, F(in, 8), reinterpret_cast<bool*>(&flag), &o) == &o;
      PutBlock(out, 0, &o, 4);
      out[4] = flag;
    }

    // ---- third wave: manipulator angle lanes ---------------------------------
    // Every value that reaches `_CIfmod` must stay finite: a NaN/inf takes the
    // CRT's errno path, which calls a trapped import.

    // A finite float: mostly ordinary angles, sometimes any finite float
    // (including +-FLT_MAX neighbours, where an x87 sum keeps its exponent).
    float GenFiniteArcValue(Rng& rng)
    {
      const std::uint32_t mode = rng.Below(100);
      if (mode < 50) {
        const float a = GenAngle(rng);
        return std::isfinite(a) ? a : 0.0f;
      }
      if (mode < 70) {
        return GenPlain(rng, 20.0f);
      }
      if (mode < 80) {
        const float big = FromBits(0x7F7FFFFFu - rng.Below(0x00800000u));
        return rng.Chance(50) ? big : -big;
      }
      float f = GenFloat(rng);
      return std::isfinite(f) ? f : 0.0f;
    }
    void GenArc(Rng& rng, u32* in)
    {
      for (int i = 0; i < 6; ++i) {
        in[i] = Bits(GenFiniteArcValue(rng));
      }
    }
    void FiringArcRetail(const u32* in, u32* out)
    {
      alignas(16) unsigned char self[0x100];
      std::memset(self, 0xCD, sizeof(self));
      retail::SetFiringArc(self, F(in, 0), F(in, 1), F(in, 2), F(in, 3), F(in, 4), F(in, 5));
      PutBlock(out, 0, self + 0xC8, 6);
    }
    void FiringArcOurs(const u32* in, u32* out)
    {
      mirror::AimArcLanes lanes;
      Canary(lanes);
      mirror::AimSetFiringArc(lanes, {F(in, 0), F(in, 1), F(in, 2), F(in, 3), F(in, 4), F(in, 5)});
      PutBlock(out, 0, &lanes, 6);
    }
    void AimingArcRetail(const u32* in, u32* out)
    {
      alignas(16) unsigned char self[0x100];
      std::memset(self, 0xCD, sizeof(self));
      retail::SetAimingArc(self, F(in, 0), F(in, 1), F(in, 2), F(in, 3), F(in, 4), F(in, 5));
      PutBlock(out, 0, self + 0x98, 6);
    }
    void AimingArcOurs(const u32* in, u32* out)
    {
      mirror::BuilderArmArcLanes lanes;
      Canary(lanes);
      mirror::BuilderArmSetAimingArc(lanes, F(in, 0), F(in, 1), F(in, 2), F(in, 3), F(in, 4), F(in, 5));
      PutBlock(out, 0, &lanes, 6);
    }

    // in: target[3] center halfArc slew current tolerance headingOffset
    float GenModerate(Rng& rng)
    {
      // Finite and below 1e6: a huge pitch centre leaves fsin/fcos's operand
      // range (|x| >= 2^63) and the resulting NaN would reach `_CIfmod`.
      const float a = rng.Chance(85) ? GenAngle(rng) : GenPlain(rng, 1000.0f);
      return (std::isfinite(a) && std::fabs(a) < 1.0e6f) ? a : GenPlain(rng, 10.0f);
    }
    void GenTrack(Rng& rng, u32* in)
    {
      float v[3];
      do {
        GenVec3(rng, v);
        // COORDS_Pitch squares the lanes: keep them where |v|^2 neither
        // overflows nor underflows to 0 (0/0 -> NaN would reach `_CIfmod`).
        for (float& c : v) {
          if (!std::isfinite(c) || std::fabs(c) > 1.0e15f || (c != 0.0f && std::fabs(c) < 1.0e-6f)) {
            c = GenPlain(rng, 10.0f);
          }
        }
      } while (v[0] == 0.0f && v[1] == 0.0f && v[2] == 0.0f);
      in[0] = Bits(v[0]);
      in[1] = Bits(v[1]);
      in[2] = Bits(v[2]);
      in[3] = Bits(GenModerate(rng)); // center
      // half arc: below and above the 3.1405928 clamp gate, and its ulp neighbours
      const std::uint32_t arcMode = rng.Below(100);
      float arc = GenPlain(rng, 3.2f);
      if (arcMode < 15) {
        arc = FromBits(Bits(3.1405928f) + rng.Below(5) - 2);
      } else if (arcMode < 30) {
        arc = GenPlain(rng, 0.5f);
      }
      in[4] = Bits(arc);
      // slew: around the 1e-5 motion epsilon, small, large, zero, negative
      const std::uint32_t slewMode = rng.Below(100);
      float slew = GenPlain(rng, 0.5f);
      if (slewMode < 25) {
        slew = static_cast<float>(rng.Range(0.0, 2.0e-5));
      } else if (slewMode < 35) {
        slew = static_cast<float>(rng.Range(0.0, 2.0e-3));
      } else if (slewMode < 45) {
        slew = GenPlain(rng, 10.0f);
      } else if (slewMode < 50) {
        slew = 0.0f;
      }
      in[5] = Bits(slew);
      in[6] = Bits(GenModerate(rng)); // current lane
      in[7] = Bits(static_cast<float>(rng.Range(0.0, 0.5))); // tolerance (CAim)
      in[8] = Bits(rng.Chance(50) ? 0.0f : GenPlain(rng, 3.1415927f)); // heading offset (CAim)
    }
    constexpr int kTrackHeading = 0x01 | 0x04;
    constexpr int kTrackPitch = 0x02 | 0x04;
    template <int Flags>
    void BuilderTrackRetail(const u32* in, u32* out)
    {
      alignas(16) unsigned char self[0x120];
      std::memset(self, 0, sizeof(self));
      const Vec target{F(in, 0), F(in, 1), F(in, 2)};
      std::memcpy(self + (Flags & 1 ? 0x88 : 0x8C), in + 6, 4);
      out[0] = static_cast<u32>(retail::BuilderArmUpdateTrackingAxis(self, &target, F(in, 3), F(in, 4), F(in, 5), Flags));
      PutBlock(out, 1, self + 0x88, 2);
    }
    template <int Flags>
    void BuilderTrackOurs(const u32* in, u32* out)
    {
      mirror::TrackLanes lanes{};
      const Vec target{F(in, 0), F(in, 1), F(in, 2)};
      (Flags & 1 ? lanes.mHeading : lanes.mPitch) = F(in, 6);
      out[0] = mirror::BuilderArmUpdateTrackingAxis(lanes, target, F(in, 3), F(in, 4), F(in, 5), Flags);
      Put(out, 1, lanes.mHeading);
      Put(out, 2, lanes.mPitch);
    }
    template <int Flags>
    void AimTrackRetail(const u32* in, u32* out)
    {
      alignas(16) unsigned char self[0x120];
      std::memset(self, 0, sizeof(self)); // +0xAC weapon blueprint = null
      const Vec target{F(in, 0), F(in, 1), F(in, 2)};
      std::memcpy(self + (Flags & 1 ? 0xB8 : 0xBC), in + 6, 4);
      std::memcpy(self + 0x10C, in + 8, 4);
      out[0] = static_cast<u32>(retail::AimCheckTracking(self, &target, F(in, 3), F(in, 4), F(in, 5), F(in, 7), Flags));
      PutBlock(out, 1, self + 0xB8, 2);
    }
    template <int Flags>
    void AimTrackOurs(const u32* in, u32* out)
    {
      mirror::TrackLanes lanes{};
      const Vec target{F(in, 0), F(in, 1), F(in, 2)};
      (Flags & 1 ? lanes.mHeading : lanes.mPitch) = F(in, 6);
      lanes.mHeadingOffset = F(in, 8);
      out[0] = mirror::AimCheckTracking(lanes, target, F(in, 3), F(in, 4), F(in, 5), F(in, 7), Flags);
      Put(out, 1, lanes.mHeading);
      Put(out, 2, lanes.mPitch);
    }

    void GenWrap(Rng& rng, u32* in)
    {
      float v = rng.Chance(70) ? GenPlain(rng, 100.0f) : GenFloat(rng);
      if (!std::isfinite(v)) {
        v = 0.0f;
      }
      if (rng.Chance(10)) {
        v = rng.Chance(50) ? 0.0f : -0.0f;
      }
      float r = rng.Chance(70) ? GenPlain(rng, 30.0f) : GenFloat(rng);
      if (!std::isfinite(r) || r == 0.0f) {
        r = 1.0f; // callers keep the range non-zero (0x0063FAB7, 0x0064005D)
      }
      if (rng.Chance(10)) {
        const float multiple = r * static_cast<float>(static_cast<int>(rng.Below(9)) - 4); // +-0 remainders
        if (std::isfinite(multiple)) {
          v = multiple;
        }
      }
      in[0] = Bits(v);
      in[1] = Bits(r);
    }
    void WrapRetail(const u32* in, u32* out) { Put(out, 0, retail::WrapPositiveModulo(F(in, 0), F(in, 1))); }
    void WrapOurs(const u32* in, u32* out) { Put(out, 0, mirror::WrapPositiveModulo(F(in, 0), F(in, 1))); }

    const Target kTargets[] = {
      {"sqrtf", 0x00452FC0, "std::sqrt(float) (inlined by every caller)", 1, 1, "x", "r", GenScalar, SqrtRetail, SqrtOurs},
      {"sqrtf_b", 0x0040EAF0, "std::sqrtf (VecSetLength)", 1, 1, "x", "r", GenScalar, SqrtBRetail, SqrtOurs},
      {"fabsf", 0x0040DAB0, "std::fabs(float) (QuatsNearEqual)", 1, 1, "x", "r", GenScalar, FabsRetail, FabsOurs},
      {"sinf", 0x005734E0, "legacy/math/X87Math.cpp msvc8::sinf", 2, 1, "x _", "r", GenTrig, SinRetail, SinOurs},
      {"cosf", 0x005734D0, "legacy/math/X87Math.cpp msvc8::cosf", 2, 1, "x _", "r", GenTrig, CosRetail, CosOurs},
      {"atan2f", 0x004E9DF0, "legacy/math/X87Math.cpp msvc8::atan2f", 2, 1, "y x", "r", GenTrig, Atan2Retail, Atan2Ours},
      {"acos", 0x00A8DCD0, "legacy/math/X87Math.cpp msvc8::acos(double)", 2, 2, "x(f64)", "r(f64)", GenAcos, AcosRetail, AcosOurs},
      {"pow", 0x00A8E0E0, "legacy/math/X87Math.cpp msvc8::pow (Lua math.pow)", 2, 1, "x y", "r", GenPow, PowRetail, PowOurs},
      {"fmod", 0x00A8E06A, "legacy/math/X87Math.cpp msvc8::fmod", 4, 2, "x(f64) y(f64)", "r(f64)", GenFmod, FmodRetail, FmodOurs},
      {"Wm3Normalize", 0x00452AF0, "Wm3Vector3.h Vector3::Normalize(Vector3*)", 3, 4, "v[3]", "v[3] len", GenV3, NormalizeRetail, NormalizeOurs},
      {"NormalizeVectorInto", 0x0044F7E0, "moho/math/Vector3f.cpp NormalizeVectorInto", 3, 7, "src[3]", "dest[3] ret src[3]", GenV3, NormIntoRetail, NormIntoOurs},
      {"QuatCrossAdd", 0x0044F880, "moho/sim/Sim.cpp QuatCrossAdd (mirrored)", 9, 5, "v1[3] v2[3] fallback[3]", "q[4] ret", GenCrossAdd, CrossAddRetail, CrossAddOurs},
      {"QuatFromVecRot", 0x0069AA50, "moho/math/QuaternionMath.cpp QuatFromVecRot", 8, 7, "q[4] ref[3] rads", "q[4] ref[3]", GenFromVecRot, FromVecRotRetail, FromVecRotOurs},
      {"RotateQuatByAngle", 0x004EB740, "moho/math/QuaternionMath.cpp RotateQuatByAngle", 5, 5, "q[4] rads", "q[4] ret", GenRotate, RotateRetail, RotateOurs},
      {"SLERP", 0x004EBC00, "moho/math/QuaternionMath.cpp SLERP", 9, 5, "q2(eax)[4] q1(ecx)[4] t", "out[4] ret", GenInterp, SlerpRetail, SlerpOurs},
      {"QuatLERP", 0x004EBA80, "moho/math/QuaternionMath.cpp QuatLERP", 9, 5, "q1(eax)[4] q2(ecx)[4] t", "out[4] ret", GenInterp, LerpRetail, LerpOurs},
      {"MultQuadVec", 0x00452D40, "moho/math/QuaternionMath.cpp MultQuadVec", 7, 4, "v[3] q[4]", "dest[3] ret", GenQuatVec, MultRetail, MultOurs},
      {"QuatToMatrix", 0x00452FD0, "moho/math/QuaternionMath.cpp QuatToMatrix", 4, 10, "q[4]", "rows[9] ret", GenQ, ToMatrixRetail, ToMatrixOurs},
      {"VecSetLengthTo", 0x0069A360, "moho/math/Vector3f.cpp VecSetLengthTo", 6, 4, "target[3] src[3]", "dest[3] ret", GenTwoVec, SetLengthToRetail, SetLengthToOurs},
      {"VecSetLength", 0x005B1C90, "moho/math/Vector3f.cpp VecSetLength", 4, 4, "v[3] len", "v[3] ret", GenVecLen, SetLengthRetail, SetLengthOurs},
      {"NormalizeQuatInPlace", 0x004EDAA0, "moho/math/QuaternionMath.cpp NormalizeQuatInPlace", 4, 4, "q[4]", "q[4]", GenQ, NormQuatRetail, NormQuatOurs},
      {"QuatsNearEqual", 0x004EDED0, "moho/math/QuaternionMath.cpp QuatsNearEqual", 8, 1, "a(edi)[4] b(esi)[4]", "ret", GenNear, NearRetail, NearOurs},
      // second wave
      {"DistanceSquared3D", 0x004CC960, "moho/math/Vector3f.cpp DistanceSquared3D", 6, 1, "from[3] to[3]", "r", GenTwoVec, DistRetail, DistOurs},
      {"ReflectVector3fAcrossNormal", 0x0069A230, "moho/math/Vector3f.cpp ReflectVector3fAcrossNormal", 6, 4, "incident[3] normal[3]", "dest[3] ret", GenTwoVec, ReflectRetail, ReflectOurs},
      {"IsUnitLengthVector3f", 0x0069A1D0, "moho/math/Vector3f.cpp IsUnitLengthVector3f", 3, 1, "v[3]", "ret", GenV3, UnitRetail, UnitOurs},
      {"VEC_LargestAxis", 0x005382E0, "moho/math/Vector3f.cpp VEC_LargestAxis", 3, 1, "v[3]", "ret", GenV3, AxisRetail, AxisOurs},
      {"VecScaleByReciprocalOrSetMax", 0x004ED810, "moho/math/Vector3f.cpp VecScaleByReciprocalOrSetMax", 4, 4, "v[3] divisor", "v[3] ret", GenVecScalar, RecipRetail, RecipOurs},
      {"VEC_HeadingFromXZ", 0x00565A10, "moho/math/Vector3f.cpp VEC_HeadingFromXZ", 3, 1, "v[3]", "r", GenV3, HeadingRetail, HeadingOurs},
      {"QuaternionExtractYAxisColumn", 0x00694AF0, "moho/math/QuaternionMath.cpp QuaternionExtractYAxisColumn", 4, 4, "q[4]", "out[3] ret", GenQ, YAxisRetail, YAxisOurs},
      {"RotateVectorByConjugateQuat", 0x0062FBA0, "moho/math/QuaternionMath.cpp RotateVectorByConjugateQuaternionLanes", 7, 4, "v[3] q[4]", "out[3] ret", GenQuatVec, ConjRetail, ConjOurs},
      {"QuatFromAxisAngleVector", 0x00697360, "moho/math/QuaternionMath.cpp QuatFromAxisAngleVector", 3, 5, "axisAngle[3]", "q[4] ret", GenV3, AxisAngleRetail, AxisAngleOurs},
      {"EulerRollToQuat", 0x00570750, "moho/math/Vector3f.cpp EulerRollToQuat", 4, 5, "axis[3] roll", "q[4] ret", GenAxisRoll, RollRetail, RollOurs},
      {"VecLimitLengthTo", 0x005D1E70, "moho/math/Vector3f.cpp VecLimitLengthTo", 4, 4, "v[3] max", "v[3] ret", GenVecLen, LimitRetail, LimitOurs},
      {"MatrixToQuat", 0x004EB3F0, "moho/math/QuaternionMath.cpp MatrixToQuat", 9, 4, "rows[9]", "q[4]", GenRows, M2QRetail, M2QOurs},
      {"MatrixRowsToQuatCanonical", 0x004F0CB0, "moho/math/QuaternionMath.cpp MatrixRowsToQuatCanonical", 9, 4, "rows[9]", "q[4]", GenRows, M2QCRetail, M2QCOurs},
      {"QuatToAxisAndAngle", 0x006C1070, "moho/math/QuaternionMath.cpp QuatToAxisAndAngle", 4, 4, "q[4]", "axis[3] angle", GenQ, ToAxisRetail, ToAxisOurs},
      {"BuildTiltShortestArcDelta", 0x0050CB50, "moho/math/QuaternionMath.cpp BuildTiltShortestArcDelta", 6, 5, "targetNormal[3] currentUp[3]", "q[4] ret", GenTilt, TiltRetail, TiltOurs},
      {"NormalizeAngleSignedRadians", 0x0062FB50, "moho/math/QuaternionMath.cpp NormalizeAngleSignedRadians", 1, 1, "rads", "r", GenFiniteAngle, NormAngleRetail, NormAngleOurs},
      {"Multiply3x3RowMatrices", 0x006D2680, "moho/math/QuaternionMath.cpp Multiply3x3RowMatrices", 18, 10, "a[9] b[9]", "r[9] ret", GenRowsPair, Mul3Retail, Mul3Ours},
      {"BuildRotationMatrixFromEulerHPR", 0x006D1E30, "moho/math/QuaternionMath.cpp BuildRotationMatrixFromEulerHPR", 3, 10, "h p r", "rows[9] ret", GenHpr, HprRetail, HprOurs},
      {"BlendOrientationDeltaByMaxAngle", 0x004EB830, "moho/math/QuaternionMath.cpp BlendOrientationDeltaByMaxAngle", 9, 6, "goal[4] current[4] step", "out[4] noStep ret", GenInterp, BlendRetail, BlendOurs},
      // third wave
      {"CAimManipulator::SetFiringArc", 0x00630CB0, "moho/ai/CAimManipulator.cpp SetFiringArc (mirrored)", 6, 6, "minH maxH hSlew minP maxP pSlew", "this+C8[6]", GenArc, FiringArcRetail, FiringArcOurs},
      {"CBuilderArmManipulator::SetAimingArc", 0x00636490, "moho/ai/CBuilderArmManipulator.cpp SetAimingArc (mirrored)", 6, 6, "minH maxH hSlew minP maxP pSlew", "this+98[6]", GenArc, AimingArcRetail, AimingArcOurs},
      {"BuilderArmTrackHeading", 0x00636220, "moho/ai/CBuilderArmManipulator.cpp UpdateTrackingAxis (mirrored, flags 5)", 9, 3, "target[3] center halfArc slew heading _ _", "ret heading pitch", GenTrack, BuilderTrackRetail<kTrackHeading>, BuilderTrackOurs<kTrackHeading>},
      {"BuilderArmTrackPitch", 0x00636220, "moho/ai/CBuilderArmManipulator.cpp UpdateTrackingAxis (mirrored, flags 6)", 9, 3, "target[3] center halfArc slew pitch _ _", "ret heading pitch", GenTrack, BuilderTrackRetail<kTrackPitch>, BuilderTrackOurs<kTrackPitch>},
      {"AimCheckTrackingHeading", 0x006309F0, "moho/ai/CAimManipulator.cpp CheckTracking (mirrored, flags 5)", 9, 3, "target[3] center range slew heading tol offset", "ret heading pitch", GenTrack, AimTrackRetail<kTrackHeading>, AimTrackOurs<kTrackHeading>},
      {"AimCheckTrackingPitch", 0x006309F0, "moho/ai/CAimManipulator.cpp CheckTracking (mirrored, flags 6)", 9, 3, "target[3] center range slew pitch tol offset", "ret heading pitch", GenTrack, AimTrackRetail<kTrackPitch>, AimTrackOurs<kTrackPitch>},
      {"WrapPositiveModulo", 0x00422940, "moho/animation/CAnimTexture.cpp WrapPositiveModulo (mirrored)", 2, 1, "value range", "r", GenWrap, WrapRetail, WrapOurs},
      // Lua math library, one row per `math.*` entry (--filter lua_).
      {"lua_abs", 0x00919A50, "lua/LuaObject.cpp math_abs (inline fabs; retail leaf 0x0040DAB0)", 1, 1, "x", "r", GenLuaAny, LuaAbsRetail, LuaAbsOurs},
      {"lua_sin", 0x00919A80, "lua/LuaObject.cpp math_sin -> msvc8::sinf (retail leaf 0x005734E0)", 2, 1, "x _", "r", GenTrig, SinRetail, SinOurs},
      {"lua_cos", 0x00919AB0, "lua/LuaObject.cpp math_cos -> msvc8::cosf (retail leaf 0x005734D0)", 2, 1, "x _", "r", GenTrig, CosRetail, CosOurs},
      {"lua_tan", 0x00919AE0, "lua/LuaObject.cpp math_tan -> msvc8::tanf (retail leaf 0x00919A40)", 1, 1, "x", "r", GenLuaAny, LuaTanRetail, LuaTanOurs},
      {"lua_asin", 0x00A8DE20, "lua/LuaObject.cpp math_asin (_CIasin)", 1, 1, "x", "r", GenLuaUnit, LuaAsinRetail, LuaAsinOurs},
      {"lua_acos", 0x00A8DCD0, "lua/LuaObject.cpp math_acos -> msvc8::acos (_CIacos)", 1, 1, "x", "r", GenLuaUnit, LuaAcosRetail, LuaAcosOurs},
      {"lua_atan", 0x00919B70, "lua/LuaObject.cpp math_atan -> msvc8::atanf (fld1; fpatan via leaf 0x004E9DF0)", 1, 1, "x", "r", GenLuaAny, LuaAtanRetail, LuaAtanOurs},
      {"lua_atan2", 0x00919BA0, "lua/LuaObject.cpp math_atan2 -> msvc8::atan2f (retail leaf 0x004E9DF0)", 2, 1, "y x", "r", GenTrig, Atan2Retail, Atan2Ours},
      {"lua_ceil", 0x00A840A0, "lua/LuaObject.cpp math_ceil (CRT ceil)", 1, 1, "x", "r", GenLuaNotNan, LuaCeilRetail, LuaCeilOurs},
      {"lua_floor", 0x00A8DF30, "lua/LuaObject.cpp math_floor (CRT floor)", 1, 1, "x", "r", GenLuaNotNan, LuaFloorRetail, LuaFloorOurs},
      {"lua_mod", 0x00A8E06A, "lua/LuaObject.cpp math_mod -> msvc8::fmod (_CIfmod)", 2, 1, "x y", "r", GenLuaMod, LuaModRetail, LuaModOurs},
      {"lua_frexp", 0x00A8DA05, "lua/LuaObject.cpp math_frexp (CRT frexp)", 1, 2, "x", "mantissa exponent", GenLuaFinite, LuaFrexpRetail, LuaFrexpOurs},
      {"lua_ldexp", 0x00A8DADF, "lua/LuaObject.cpp math_ldexp (_ftol2 + CRT ldexp)", 2, 1, "x n", "r", GenLuaLdexp, LuaLdexpRetail, LuaLdexpOurs},
      {"lua_sqrt", 0x00919C80, "lua/LuaObject.cpp math_sqrt (inline fsqrt; retail leaf 0x00452FC0)", 1, 1, "x", "r", GenLuaAny, LuaSqrtRetail, LuaSqrtOurs},
      {"lua_pow", 0x00A8E0E0, "lua/LuaObject.cpp math_pow -> msvc8::pow (_CIpow)", 2, 1, "x y", "r", GenPow, PowRetail, PowOurs},
      {"lua_log", 0x00919CF0, "lua/LuaObject.cpp math_log -> msvc8::IntrinsicLn (retail leaf 0x0040EAD0)", 1, 1, "x", "r", GenLuaAny, LuaLogRetail, LuaLogOurs},
      {"lua_log10", 0x00919D20, "lua/LuaObject.cpp math_log10 -> msvc8::IntrinsicLog10 (retail leaf 0x00919980)", 1, 1, "x", "r", GenLuaAny, LuaLog10Retail, LuaLog10Ours},
      {"lua_exp", 0x00919D50, "lua/LuaObject.cpp math_exp -> msvc8::IntrinsicExp (retail leaf 0x009199D0)", 1, 1, "x", "r", GenLuaAny, LuaExpRetail, LuaExpOurs},
      {"lua_deg", 0x00919D90, "lua/LuaObject.cpp math_deg (fmul dword [0x00D46340])", 1, 1, "x", "r", GenLuaAny, LuaDegRetail, LuaDegOurs},
      {"lua_rad", 0x00919DC0, "lua/LuaObject.cpp math_rad (fmul dword [0x00D46344])", 1, 1, "x", "r", GenLuaAny, LuaRadRetail, LuaRadOurs},
      {"lua_random", 0x00919F90, "lua/LuaObject.cpp math_random arithmetic (retail floor 0x00A8DF30)", 4, 1, "rand argc a b", "r", GenLuaRandom, LuaRandomRetail, LuaRandomOurs},
      {"lua_randomseed", 0x0091A0D0, "lua/LuaObject.cpp math_randomseed seed conversion", 1, 1, "x", "seed", GenLuaAny, LuaSeedRetail, LuaSeedOurs},
    };
  } // namespace

  const Target* MathTargets(int& count)
  {
    count = static_cast<int>(sizeof(kTargets) / sizeof(kTargets[0]));
    return kTargets;
  }
} // namespace difffuzz
