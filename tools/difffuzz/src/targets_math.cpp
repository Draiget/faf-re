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
#include "moho/collision/CColPrimitiveBase.h"
#include "moho/math/QuaternionMath.h"
#include "moho/math/Vector3f.h"
#include "sdk_mirror.h"

#include <cmath>
#include <cstring>

// DIFFFUZZ_ENGINE_LINKED (faf_math_dump): a row whose engine function lives in a
// TU the standalone build does not compile calls the engine's own definition
// there, and the sdk_mirror.cpp copy here. ENGINE_OR_MIRROR names the one this
// build calls; the golden file holds retail's outputs, so a stale mirror is
// caught in difffuzz and the engine's definition in faf_math_dump.
#include "moho/math/GridPos.h"
#include "moho/math/Wm3AxisAlignedBox3FafExtras.h"
#include "moho/math/Wm3Queries.h"
#include "moho/math/Wm3Segment3FafExtras.h"

#include "moho/math/Vector2f.h"

#if defined(DIFFFUZZ_ENGINE_LINKED)
#include "gpg/core/algorithms/Cluster.h"
#include "gpg/core/containers/Rect2.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/math/MathReflection.h"
#include "moho/render/camera/VTransform.h"
#include "moho/sim/CRandomStream.h"
#include "moho/sim/STIMap.h"
namespace moho
{
  gpg::Rect2i* COORDS_ToGridRect(gpg::Rect2i* result, const SCoordsVec2& centerXZ, int sizeX, int sizeZ); // Entity.h
} // namespace moho
#define ENGINE_OR_MIRROR(engine, mirrored) engine
#else
#define ENGINE_OR_MIRROR(engine, mirrored) mirrored
#endif

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
          // One draw per statement: cl and clang order the operands of `*` differently.
          const float unit = static_cast<float>(rng.Range(0.0, 1.0));
          x = unit * FromBits(0x3F800000u - (rng.Below(64) << 23));
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
        const float whole = static_cast<float>(static_cast<int>(rng.Below(321)) - 160); // one draw per statement
        n = whole + (rng.Chance(50) ? 0.5f : -0.75f);
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
      out[0] = static_cast<unsigned int>(msvc8::TruncateToInt64(F(in, 0))); // math_randomseed
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
          r[i] = DerivedFloat(s * f[i] + (rng.Chance(50) ? 0.0 : 1e-6 * rng.Range(-1, 1)));
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
          m[i] = DerivedFloat(r[i] + (mode < 50 ? 1e-4 * rng.Range(-1, 1) : 0.0));
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

    // ---- fourth wave: callers of the inline X87Math helpers ----------------

    // A float k ulps from `value` (k in -3..3), or `value` itself.
    [[nodiscard]] float NearFloat(Rng& rng, const double value)
    {
      const u32 bits = Bits(static_cast<float>(value));
      return FromBits(bits + rng.Below(7) - 3u);
    }

    // RATE_GameRateToSpeed 0x0055AE10: floor(10 * log10(rate)). Rates around
    // 10^(k/10), where the step changes, and ordinary ones.
    void GenRate(Rng& rng, u32* in)
    {
      const u32 mode = rng.Below(100);
      if (mode < 40) {
        const int step = static_cast<int>(rng.Below(61)) - 30;
        double rate = 1.0;
        for (int i = 0; i < (step < 0 ? -step : step); ++i) {
          rate = step < 0 ? rate / 1.2589254117941673 : rate * 1.2589254117941673; // 10^0.1
        }
        in[0] = Bits(NearFloat(rng, rate));
      } else if (mode < 75) {
        in[0] = Bits(static_cast<float>(rng.Range(0.0, 100.0)));
      } else {
        in[0] = Bits(GenFloat(rng));
      }
    }
    void RateRetail(const u32* in, u32* out) { out[0] = static_cast<u32>(retail::RateGameRateToSpeed(F(in, 0))); }
    // The engine keeps RATE_GameRateToSpeed in SimDriver.cpp's anonymous
    // namespace, so both builds run the mirror over the engine's helpers.
    void RateOurs(const u32* in, u32* out) { out[0] = static_cast<u32>(mirror::RATE_GameRateToSpeed(F(in, 0))); }

    // HaStar::Cluster::QuantizeEdgeCost 0x0092D8B0: ceil(ln(a / b) * 6) in
    // 0..31. Ratios around exp(k/6), where the bucket changes, and ordinary ones.
    void GenEdgeCost(Rng& rng, u32* in)
    {
      const u32 mode = rng.Below(100);
      if (mode < 45) {
        const float distance = static_cast<float>(rng.Range(0.5, 40.0));
        const int bucket = static_cast<int>(rng.Below(34));
        double ratio = 1.0;
        for (int i = 0; i < bucket; ++i) {
          ratio *= 1.1813604128656459; // e^(1/6)
        }
        in[0] = Bits(NearFloat(rng, distance * ratio));
        in[1] = Bits(distance);
      } else if (mode < 75) {
        const float distance = static_cast<float>(rng.Range(0.0, 50.0));
        in[0] = Bits(static_cast<float>(rng.Range(0.0, 500.0)));
        in[1] = Bits(distance);
      } else {
        in[0] = Bits(GenFloat(rng));
        in[1] = Bits(GenFloat(rng));
      }
    }
    void EdgeCostRetail(const u32* in, u32* out) { Put(out, 0, retail::QuantizeEdgeCost(F(in, 0), F(in, 1))); }
    void EdgeCostOurs(const u32* in, u32* out)
    {
      Put(out, 0, ENGINE_OR_MIRROR(gpg::HaStar::Cluster::QuantizeEdgeCost, mirror::QuantizeEdgeCost)(F(in, 0), F(in, 1)));
    }

    // COORDS_ToGridRect 0x0050AFA0: in = center x, z, then sizeX, sizeZ as
    // ints. Centers on half cells (fistp's round-half-even), map-sized and raw.
    [[nodiscard]] int GenFootprintSize(Rng& rng)
    {
      const u32 mode = rng.Below(100);
      if (mode < 70) {
        return static_cast<int>(rng.Below(16));
      }
      if (mode < 90) {
        return static_cast<int>(rng.Below(201)) - 100;
      }
      return static_cast<int>(rng.U32());
    }
    [[nodiscard]] float GenGridCoordinate(Rng& rng)
    {
      const u32 mode = rng.Below(100);
      if (mode < 40) {
        return static_cast<float>(rng.Below(8193)) * 0.5f; // half cells up to 4096
      }
      if (mode < 70) {
        const float halfCell = static_cast<float>(rng.Below(8193)) * 0.5f;
        return NearFloat(rng, halfCell);
      }
      if (mode < 85) {
        return static_cast<float>(rng.Range(-100.0, 4200.0));
      }
      return GenFloat(rng);
    }
    void GenGridRect(Rng& rng, u32* in)
    {
      in[0] = Bits(GenGridCoordinate(rng));
      in[1] = Bits(GenGridCoordinate(rng));
      in[2] = static_cast<u32>(GenFootprintSize(rng));
      in[3] = static_cast<u32>(GenFootprintSize(rng));
    }
    void GridRectRetail(const u32* in, u32* out)
    {
      int rect[4];
      Canary(rect);
      out[4] = retail::CoordsToGridRect(rect, in, static_cast<int>(in[2]), static_cast<int>(in[3])) == rect;
      PutBlock(out, 0, rect, 4);
    }
    void GridRectOurs(const u32* in, u32* out)
    {
#if defined(DIFFFUZZ_ENGINE_LINKED)
      gpg::Rect2i rect;
      Canary(rect);
      moho::SCoordsVec2 center;
      center.x = F(in, 0);
      center.z = F(in, 1);
      out[4] = moho::COORDS_ToGridRect(&rect, center, static_cast<int>(in[2]), static_cast<int>(in[3])) == &rect;
      PutBlock(out, 0, &rect, 4);
#else
      int rect[4];
      Canary(rect);
      mirror::COORDS_ToGridRect(rect, F(in, 0), F(in, 1), static_cast<int>(in[2]), static_cast<int>(in[3]));
      out[4] = 1;
      PutBlock(out, 0, rect, 4);
#endif
    }

    // ProjectBoxOntoAxis 0x00475550 (the box-box separating-axis interval): box
    // = Center[3], Axis[3][3], Extent[3]; then the axis, which the SAT forms as
    // cross products of box axes (near-degenerate ones have denormal products).
    void GenBoxAxis(Rng& rng, u32* in)
    {
      float center[3], axis[3];
      GenVec3(rng, center);
      PutF(in, 0, center, 3);
      float q[4];
      GenQuat(rng, q);
      const double w = q[0], x = q[1], y = q[2], z = q[3];
      const double rows[9] = {1 - 2 * (y * y + z * z), 2 * (x * y - w * z), 2 * (x * z + w * y),
                              2 * (x * y + w * z), 1 - 2 * (x * x + z * z), 2 * (y * z - w * x),
                              2 * (x * z - w * y), 2 * (y * z + w * x), 1 - 2 * (x * x + y * y)};
      for (int i = 0; i < 9; ++i) {
        in[3 + i] = Bits(DerivedFloat(rows[i]));
      }
      for (int i = 0; i < 3; ++i) {
        in[12 + i] = Bits(rng.Chance(75) ? static_cast<float>(rng.Range(0.0, 20.0)) : GenFloat(rng));
      }
      GenVec3(rng, axis);
      PutF(in, 15, axis, 3);
    }
    void BoxAxisRetail(const u32* in, u32* out)
    {
      float range[2];
      Canary(range);
      retail::ProjectBoxOntoAxis(in, in + 15, &range[0], &range[1]);
      PutBlock(out, 0, range, 2);
    }
    void BoxAxisOurs(const u32* in, u32* out)
    {
      float box[15], axis[3], range[2];
      std::memcpy(box, in, sizeof(box));
      std::memcpy(axis, in + 15, sizeof(axis));
      Canary(range);
      mirror::ProjectBoxOntoAxis(box, axis, &range[0], &range[1]);
      PutBlock(out, 0, range, 2);
    }

    // MatrixColumnsToQuatCanonical 0x004F0AE0: the transpose, then the fuzzed
    // MatrixRowsToQuatCanonical (0x004F0CB0).
    void ColumnsToQuatRetail(const u32* in, u32* out)
    {
      Vec columns[3];
      Quat q;
      Load(columns, in, 0);
      Canary(q);
      out[4] = retail::MatrixColumnsToQuat(columns, &q) == &q;
      PutBlock(out, 0, &q, 4);
    }
    void ColumnsToQuatOurs(const u32* in, u32* out)
    {
      Vec columns[3];
      Quat q;
      Load(columns, in, 0);
      Canary(q);
      out[4] = moho::MatrixColumnsToQuatCanonical(columns, &q) == &q;
      PutBlock(out, 0, &q, 4);
    }

    // Moho::IsValid_Vector3f 0x005657F0: no lane is NaN (infinities pass).
    void ValidRetail(const u32* in, u32* out)
    {
      Vec v;
      Load(v, in, 0);
      out[0] = static_cast<u32>(retail::IsValidVector3f(&v));
    }
    void ValidOurs(const u32* in, u32* out)
    {
      Vec v;
      Load(v, in, 0);
      out[0] = moho::IsValidVector3f(v) ? 1u : 0u;
    }

    // VAxes3::VAxes3(const Quaternionf&) 0x004EC590 (QuatForwardAxis's
    // basis) and VMatrix4::Set(quat, vec) 0x004EE980: the same rotation block.
    void AxesRetail(const u32* in, u32* out)
    {
      Quat q;
      float axes[9];
      Load(q, in, 0);
      Canary(axes);
      retail::VAxes3FromQuat(axes, &q);
      PutBlock(out, 0, axes, 9);
    }
    void AxesOurs(const u32* in, u32* out)
    {
      Quat q;
      Load(q, in, 0);
#if defined(DIFFFUZZ_ENGINE_LINKED)
      const moho::VAxes3 axes(q);
      PutBlock(out, 0, &axes.vX, 3);
      PutBlock(out, 3, &axes.vY, 3);
      PutBlock(out, 6, &axes.vZ, 3);
#else
      float axes[9];
      Canary(axes);
      mirror::VAxes3FromQuat(axes, q);
      PutBlock(out, 0, axes, 9);
#endif
    }
    void MatrixSetRetail(const u32* in, u32* out)
    {
      Vec v;
      Quat q;
      float rows[16];
      Load(v, in, 0);
      Load(q, in, 3);
      Canary(rows);
      retail::VMatrix4Set(rows, &q, &v);
      PutBlock(out, 0, rows, 16);
    }
    void MatrixSetOurs(const u32* in, u32* out)
    {
      Vec v;
      Quat q;
      Load(v, in, 0);
      Load(q, in, 3);
#if defined(DIFFFUZZ_ENGINE_LINKED)
      moho::VMatrix4 matrix;
      Canary(matrix);
      matrix.Set(q, v);
      PutBlock(out, 0, &matrix, 16);
#else
      float rows[16];
      Canary(rows);
      mirror::VMatrix4Set(rows, q, v);
      PutBlock(out, 0, rows, 16);
#endif
    }

    // FloorSecondsToTicks 0x0066D1D0: floor(seconds * 10) as frndint plus
    // the -1 borrow. Whole and near-whole tenths, ordinary and raw seconds.
    void GenSeconds(Rng& rng, u32* in)
    {
      const u32 mode = rng.Below(100);
      if (mode < 45) {
        const double tenths = static_cast<double>(static_cast<int>(rng.Below(20001)) - 1000) / 10.0;
        in[0] = Bits(NearFloat(rng, tenths));
      } else if (mode < 75) {
        in[0] = Bits(static_cast<float>(rng.Range(-10.0, 600.0)));
      } else {
        in[0] = Bits(GenFloat(rng));
      }
    }
    void SecondsRetail(const u32* in, u32* out) { out[0] = static_cast<u32>(retail::FloorSecondsToTicks(F(in, 0))); }
    void SecondsOurs(const u32* in, u32* out) { out[0] = static_cast<u32>(moho::FloorSecondsToTicks(F(in, 0))); }

    // GridPos::GridPos(Vec3f*, int) 0x00506E20: floor(x / size), floor(z / size)
    // through the float reciprocal. in = world x, y, z, then the grid size.
    void GenGridPos(Rng& rng, u32* in)
    {
      for (int i = 0; i < 3; ++i) {
        in[i] = Bits(GenGridCoordinate(rng));
      }
      const u32 mode = rng.Below(100);
      int size;
      if (mode < 70) {
        size = 1 << rng.Below(7); // 1..64
      } else if (mode < 90) {
        size = static_cast<int>(rng.Below(200)) - 50;
      } else {
        size = static_cast<int>(rng.U32());
      }
      in[3] = static_cast<u32>(size);
    }
    void GridPosRetail(const u32* in, u32* out)
    {
      Vec world;
      int cell[2];
      Load(world, in, 0);
      Canary(cell);
      out[2] = retail::GridPosFromWorld(cell, &world, static_cast<int>(in[3])) == cell;
      PutBlock(out, 0, cell, 2);
    }
    void GridPosOurs(const u32* in, u32* out)
    {
      Vec world;
      Load(world, in, 0);
      const moho::GridPos cell(&world, static_cast<int>(in[3]));
      out[0] = static_cast<u32>(cell.x);
      out[1] = static_cast<u32>(cell.z);
      out[2] = 1;
    }

    // Segment3f(start, end) 0x004FE130 (MakeSegment3fFromEndpoints): origin,
    // direction, extent. in[0..2] = start, in[3..5] = end.
    void SegmentRetail(const u32* in, u32* out)
    {
      Vec start, end;
      float segment[7];
      Load(start, in, 0);
      Load(end, in, 3);
      Canary(segment);
      out[7] = retail::SegmentFromEndpoints(segment, &start, &end) == segment;
      PutBlock(out, 0, segment, 7);
    }
    void SegmentOurs(const u32* in, u32* out)
    {
      Vec start, end;
      Load(start, in, 0);
      Load(end, in, 3);
      const Wm3::Segment3f segment = Wm3::MakeSegment3fFromEndpoints(start, end);
      PutBlock(out, 0, &segment.Origin, 3);
      PutBlock(out, 3, &segment.Direction, 3);
      Put(out, 6, segment.Extent);
      out[7] = 1;
    }

    // AxisAlignedBox3f(const Box3f&) 0x004FE2D0 (AxisAlignedBoundsFromBox):
    // the box's eight vertices fitted, then Min and Max.
    void GenBox(Rng& rng, u32* in)
    {
      GenBoxAxis(rng, in); // the box's 15 lanes; the trailing axis is not read
    }
    void BoundsRetail(const u32* in, u32* out)
    {
      float bounds[6];
      Canary(bounds);
      out[6] = retail::AlignedBoundsFromBox(bounds, in) == bounds;
      PutBlock(out, 0, bounds, 6);
    }
    void BoundsOurs(const u32* in, u32* out)
    {
      Wm3::Box3f box;
      std::memcpy(&box.Center, in, 12);
      std::memcpy(&box.Axis[0], in + 3, 12);
      std::memcpy(&box.Axis[1], in + 6, 12);
      std::memcpy(&box.Axis[2], in + 9, 12);
      std::memcpy(box.Extent, in + 12, 12);
#if defined(DIFFFUZZ_ENGINE_LINKED)
      const Wm3::AxisAlignedBox3f bounds = moho::AxisAlignedBoundsFromBox(box);
      PutBlock(out, 0, &bounds.Min, 3);
      PutBlock(out, 3, &bounds.Max, 3);
#else
      float bounds[6];
      mirror::AxisAlignedBoundsFromBox(box, bounds, bounds + 3);
      PutBlock(out, 0, bounds, 6);
#endif
      out[6] = 1;
    }

    // ---- fifth wave: the collision primitives (Wild Magic queries) ----------
    //
    // CColPrimitive<Box3f> (vftable 0x00E0D50C) is {vptr, Box3f mShape at +04,
    // mLocalCenter at +40}; CColPrimitive<Sphere3f> (0x00E0D480) is {vptr,
    // Sphere3f at +04, mLocalCenter at +14}. The tested virtuals read mShape
    // only. Inputs: a box is Center[3] Axis[3][3] Extent[3], a sphere
    // Center[3] Radius.
    constexpr u32 kBoxPrimitiveVftable = 0x00E0D50Cu;
    constexpr u32 kSpherePrimitiveVftable = 0x00E0D480u;

    // A box as the sim places one: a unit rotation's rows, extents up to 20, a
    // map-range centre. One in ten is GenBoxAxis's raw box (any quaternion,
    // GenVec3 centre, GenFloat extents).
    void GenRotatedBox(Rng& rng, u32* in);
    void GenCollisionBox(Rng& rng, u32* in)
    {
      if (rng.Chance(10)) {
        u32 raw[18];
        GenBoxAxis(rng, raw);
        std::memcpy(in, raw, 15 * 4);
        return;
      }
      GenRotatedBox(rng, in);
    }
    void GenRotatedBox(Rng& rng, u32* in)
    {
      for (int i = 0; i < 3; ++i) {
        in[i] = Bits(static_cast<float>(rng.Range(-50.0, 1050.0)));
      }
      double q[4];
      double norm = 0.0;
      for (double& lane : q) {
        lane = rng.Range(-1.0, 1.0);
        norm += lane * lane;
      }
      norm = norm > 1e-12 ? std::sqrt(norm) : 1.0;
      const double w = q[0] / norm, x = q[1] / norm, y = q[2] / norm, z = q[3] / norm;
      const double rows[9] = {1 - 2 * (y * y + z * z), 2 * (x * y - w * z), 2 * (x * z + w * y),
                              2 * (x * y + w * z), 1 - 2 * (x * x + z * z), 2 * (y * z - w * x),
                              2 * (x * z - w * y), 2 * (y * z + w * x), 1 - 2 * (x * x + y * y)};
      for (int i = 0; i < 9; ++i) {
        in[3 + i] = Bits(DerivedFloat(rows[i]));
      }
      for (int i = 0; i < 3; ++i) {
        in[12 + i] = Bits(rng.Chance(5) ? 0.0f : static_cast<float>(rng.Range(0.05, 20.0)));
      }
    }

    // A point within `reach` of `center` on each lane (so about half the
    // queries hit), or one in ten a GenVec3 point.
    void GenPointNear(Rng& rng, const u32* center, const double reach, u32* out)
    {
      if (rng.Chance(10)) {
        float v[3];
        GenVec3(rng, v);
        PutF(out, 0, v, 3);
        return;
      }
      for (int i = 0; i < 3; ++i) {
        out[i] = Bits(DerivedFloat(static_cast<double>(F(center, i)) + rng.Range(-reach, reach)));
      }
    }

    [[nodiscard]] double BoxReach(const u32* box)
    {
      double reach = 2.0;
      for (int i = 0; i < 3; ++i) {
        const double extent = F(box, 12 + i);
        reach += std::isfinite(extent) ? std::fmin(std::fabs(extent), 1.0e6) : 0.0;
      }
      return reach;
    }

    [[nodiscard]] float GenRadius(Rng& rng)
    {
      const u32 mode = rng.Below(100);
      if (mode < 80) {
        return static_cast<float>(rng.Range(0.0, 10.0));
      }
      if (mode < 88) {
        return 0.0f;
      }
      return GenFloat(rng);
    }

    void GenCollisionSphere(Rng& rng, u32* in)
    {
      if (rng.Chance(10)) {
        float v[3];
        GenVec3(rng, v);
        PutF(in, 0, v, 3);
      } else {
        for (int i = 0; i < 3; ++i) {
          in[i] = Bits(static_cast<float>(rng.Range(-50.0, 1050.0)));
        }
      }
      in[3] = Bits(GenRadius(rng));
    }

    // A sphere around `center`, within `reach` of it.
    void GenSphereNear(Rng& rng, const u32* center, const double reach, u32* out)
    {
      GenPointNear(rng, center, reach, out);
      out[3] = Bits(GenRadius(rng));
    }

    void GenBoxLine(Rng& rng, u32* in) // box[15] start[3] end[3]
    {
      GenCollisionBox(rng, in);
      const double reach = BoxReach(in) * 1.5;
      GenPointNear(rng, in, reach, in + 15);
      GenPointNear(rng, in, reach, in + 18);
    }
    void GenBoxSphere(Rng& rng, u32* in) // box[15] sphere[4]
    {
      GenCollisionBox(rng, in);
      GenSphereNear(rng, in, BoxReach(in) + 5.0, in + 15);
    }
    void GenBoxBox(Rng& rng, u32* in) // box[15] box[15]
    {
      GenCollisionBox(rng, in);
      GenCollisionBox(rng, in + 15);
      if (rng.Chance(90)) { // move the second box next to the first
        GenPointNear(rng, in, BoxReach(in) + BoxReach(in + 15), in + 15);
      }
    }
    void GenBoxPoint(Rng& rng, u32* in) // box[15] point[3]
    {
      GenCollisionBox(rng, in);
      GenPointNear(rng, in, BoxReach(in), in + 15);
    }
    void GenSphereLine(Rng& rng, u32* in) // sphere[4] start[3] end[3]
    {
      GenCollisionSphere(rng, in);
      const double reach = 12.0;
      GenPointNear(rng, in, reach, in + 4);
      GenPointNear(rng, in, reach, in + 7);
    }
    void GenSphereBox(Rng& rng, u32* in) // sphere[4] box[15]
    {
      // A rotation's box and finite sphere lanes. With an infinite, NaN or
      // overflowing lane IntrBox3Sphere3<float>::Find can take its "moving
      // away" result after Test and report a contact point from coordinates it
      // never set (Wm3Queries.cpp, FindBox3Sphere3): retail's are the caller's
      // stack. The simulation's boxes come from unit quaternions and blueprint
      // sizes, its spheres from positions and radii.
      GenCollisionSphere(rng, in);
      GenRotatedBox(rng, in + 4);
      if (rng.Chance(90)) {
        GenPointNear(rng, in, BoxReach(in + 4) + 10.0, in + 4);
      }
      for (int i = 0; i < 19; ++i) {
        if (!std::isfinite(F(in, i))) {
          in[i] = 0;
        }
      }
    }
    void GenSphereSphere(Rng& rng, u32* in) // sphere[4] sphere[4]
    {
      GenCollisionSphere(rng, in);
      GenSphereNear(rng, in, 20.0, in + 4);
    }
    void GenSpherePoint(Rng& rng, u32* in) // sphere[4] point[3]
    {
      GenCollisionSphere(rng, in);
      GenPointNear(rng, in, 12.0, in + 4);
    }

    // The primitive as retail lays it out: vptr, the shape, mLocalCenter (set
    // to the shape's centre, as the constructors do).
    struct BoxPrimitiveImage
    {
      u32 vftable;
      u32 shape[15];
      u32 localCenter[3];
    };
    struct SpherePrimitiveImage
    {
      u32 vftable;
      u32 shape[4];
      u32 localCenter[3];
    };
    static_assert(sizeof(BoxPrimitiveImage) == 0x4C && sizeof(SpherePrimitiveImage) == 0x20);

    [[nodiscard]] BoxPrimitiveImage RetailBox(const u32* in)
    {
      BoxPrimitiveImage self;
      self.vftable = kBoxPrimitiveVftable;
      std::memcpy(self.shape, in, sizeof(self.shape));
      std::memcpy(self.localCenter, in, sizeof(self.localCenter));
      return self;
    }
    [[nodiscard]] SpherePrimitiveImage RetailSphere(const u32* in)
    {
      SpherePrimitiveImage self;
      self.vftable = kSpherePrimitiveVftable;
      std::memcpy(self.shape, in, sizeof(self.shape));
      std::memcpy(self.localCenter, in, sizeof(self.localCenter));
      return self;
    }

    [[nodiscard]] Wm3::Box3f LoadBox(const u32* in)
    {
      Wm3::Box3f box;
      std::memcpy(&box.Center, in, 12);
      std::memcpy(&box.Axis[0], in + 3, 12);
      std::memcpy(&box.Axis[1], in + 6, 12);
      std::memcpy(&box.Axis[2], in + 9, 12);
      std::memcpy(box.Extent, in + 12, 12);
      return box;
    }
    [[nodiscard]] Wm3::Sphere3f LoadSphere(const u32* in)
    {
      Wm3::Sphere3f sphere;
      std::memcpy(&sphere.Center, in, 12);
      std::memcpy(&sphere.Radius, in + 3, 4);
      return sphere;
    }
    [[nodiscard]] moho::CColPrimitive<Wm3::Box3f> OurBox(const u32* in) { return moho::CColPrimitive<Wm3::Box3f>(LoadBox(in)); }
    [[nodiscard]] moho::CColPrimitive<Wm3::Sphere3f> OurSphere(const u32* in)
    {
      const Wm3::Sphere3f sphere = LoadSphere(in);
      return moho::CColPrimitive<Wm3::Sphere3f>(sphere.Center, sphere.Radius);
    }

    // Outputs. A line hit: ret, direction[3], position[3], distance (the
    // result's +04..+1C; +00, the source entity, is the caller's). A shape
    // hit: ret, direction[3], depth (+08..+14). Retail fills an x86-layout
    // buffer; ours the engine struct, whose pointer lanes are 8 bytes on x64.
    void CollideLineRetail(const unsigned va, const void* self, const u32* line, u32* out)
    {
      Vec start, end;
      u32 result[8];
      Load(start, line, 0);
      Load(end, line, 3);
      Canary(result);
      out[0] = static_cast<u32>(retail::ThisCallBool3(va, self, &start, &end, result));
      PutBlock(out, 1, result + 1, 7);
    }
    template <class Primitive>
    void CollideLineOurs(const Primitive& self, const u32* line, u32* out)
    {
      Vec start, end;
      moho::CollisionSegmentResult result;
      Load(start, line, 0);
      Load(end, line, 3);
      Canary(result);
      out[0] = self.CollideLine(&start, &end, &result) ? 1u : 0u;
      PutBlock(out, 1, &result.direction, 3);
      PutBlock(out, 4, &result.position, 3);
      Put(out, 7, result.distanceFromLineStart);
    }
    void CollideShapeRetail(const unsigned va, const void* self, const void* shape, u32* out)
    {
      u32 result[6];
      Canary(result);
      out[0] = static_cast<u32>(retail::ThisCallBool2(va, self, shape, result));
      PutBlock(out, 1, result + 2, 4);
    }
    void PutShapeResult(const bool hit, const moho::CollisionResult& result, u32* out)
    {
      out[0] = hit ? 1u : 0u;
      PutBlock(out, 1, &result.direction, 3);
      Put(out, 4, result.penetrationDepth);
    }

    void BoxLineRetail(const u32* in, u32* out)
    {
      const BoxPrimitiveImage self = RetailBox(in);
      CollideLineRetail(0x004FF2D0u, &self, in + 15, out);
    }
    void BoxLineOurs(const u32* in, u32* out) { CollideLineOurs(OurBox(in), in + 15, out); }

    void SphereLineRetail(const u32* in, u32* out)
    {
      const SpherePrimitiveImage self = RetailSphere(in);
      CollideLineRetail(0x004FE9D0u, &self, in + 4, out);
    }
    void SphereLineOurs(const u32* in, u32* out) { CollideLineOurs(OurSphere(in), in + 4, out); }

    void BoxSphereRetail(const u32* in, u32* out)
    {
      const BoxPrimitiveImage self = RetailBox(in);
      u32 sphere[4];
      std::memcpy(sphere, in + 15, sizeof(sphere));
      CollideShapeRetail(0x004FF150u, &self, sphere, out);
    }
    void BoxSphereOurs(const u32* in, u32* out)
    {
      const Wm3::Sphere3f sphere = LoadSphere(in + 15);
      moho::CollisionResult result;
      Canary(result);
      PutShapeResult(OurBox(in).CollideSphere(&sphere, &result), result, out);
    }

    void BoxBoxRetail(const u32* in, u32* out)
    {
      const BoxPrimitiveImage self = RetailBox(in);
      u32 box[15];
      std::memcpy(box, in + 15, sizeof(box));
      CollideShapeRetail(0x004FF260u, &self, box, out);
    }
    void BoxBoxOurs(const u32* in, u32* out)
    {
      const Wm3::Box3f box = LoadBox(in + 15);
      moho::CollisionResult result;
      Canary(result);
      PutShapeResult(OurBox(in).CollideBox(&box, &result), result, out);
    }

    void SphereBoxRetail(const u32* in, u32* out)
    {
      const SpherePrimitiveImage self = RetailSphere(in);
      u32 box[15];
      std::memcpy(box, in + 4, sizeof(box));
      CollideShapeRetail(0x004FE860u, &self, box, out);
    }
    void SphereBoxOurs(const u32* in, u32* out)
    {
      const Wm3::Box3f box = LoadBox(in + 4);
      moho::CollisionResult result;
      Canary(result);
      PutShapeResult(OurSphere(in).CollideBox(&box, &result), result, out);
    }

    void SphereSphereRetail(const u32* in, u32* out)
    {
      const SpherePrimitiveImage self = RetailSphere(in);
      u32 sphere[4];
      std::memcpy(sphere, in + 4, sizeof(sphere));
      CollideShapeRetail(0x004FE7A0u, &self, sphere, out);
    }
    void SphereSphereOurs(const u32* in, u32* out)
    {
      const Wm3::Sphere3f sphere = LoadSphere(in + 4);
      moho::CollisionResult result;
      Canary(result);
      PutShapeResult(OurSphere(in).CollideSphere(&sphere, &result), result, out);
    }

    void BoxPointRetail(const u32* in, u32* out)
    {
      const BoxPrimitiveImage self = RetailBox(in);
      Vec point;
      Load(point, in, 15);
      out[0] = static_cast<u32>(retail::ThisCallBool1(0x004FF450u, &self, &point));
    }
    void BoxPointOurs(const u32* in, u32* out)
    {
      Vec point;
      Load(point, in, 15);
      out[0] = OurBox(in).PointInShape(&point) ? 1u : 0u;
    }

    void SpherePointRetail(const u32* in, u32* out)
    {
      const SpherePrimitiveImage self = RetailSphere(in);
      Vec point;
      Load(point, in, 4);
      out[0] = static_cast<u32>(retail::ThisCallBool1(0x004FEB60u, &self, &point));
    }
    void SpherePointOurs(const u32* in, u32* out)
    {
      Vec point;
      Load(point, in, 4);
      out[0] = OurSphere(in).PointInShape(&point) ? 1u : 0u;
    }

    // ---- the Wild Magic queries themselves (src/moho/math/Wm3Queries.cpp) ---
    //
    // Retail's query objects are built by their constructors in a canary-filled
    // buffer: DistVector3Segment3<float> {..., m_kClosestPoint1 +1C, &vector
    // +34, &segment +38}; IntrBox2Box2<float> {..., &box0 +0C, &box1 +10}.
    // IntrBox3Sphere3<float>::Find has no row of its own: on its "moving away"
    // result it reports a hit built from intersection coordinates it never
    // set, which read other locals' slots and the caller's stack
    // (Wm3Queries.cpp); the simulation's path is ColSphere::CollideBox.
    struct QueryImage
    {
      u32 words[32];
    };

    [[nodiscard]] QueryImage CanaryQuery()
    {
      QueryImage query;
      Canary(query);
      return query;
    }

    // DistVector3Segment3<float>::GetSquared 0x00A484F0 (Projectile's homing
    // hit): point[3] origin[3] direction[3] extent.
    void GenPointSegment(Rng& rng, u32* in)
    {
      if (rng.Chance(10)) {
        for (int i = 0; i < 10; ++i) {
          in[i] = Bits(GenFloat(rng));
        }
        return;
      }
      for (int i = 0; i < 3; ++i) {
        in[3 + i] = Bits(static_cast<float>(rng.Range(-50.0, 1050.0)));
      }
      float direction[3];
      GenUnitVec3(rng, direction);
      PutF(in, 6, direction, 3);
      in[9] = Bits(rng.Chance(5) ? 0.0f : static_cast<float>(rng.Range(0.0, 30.0)));
      GenPointNear(rng, in + 3, 40.0, in);
    }
    void PointSegmentRetail(const u32* in, u32* out)
    {
      u32 point[3], segment[7];
      std::memcpy(point, in, sizeof(point));
      std::memcpy(segment, in + 3, sizeof(segment));
      QueryImage query = CanaryQuery();
      retail::ThisCallBool2(0x00A48030u, &query, point, segment);
      Put(out, 0, retail::ThisCallFloat0(0x00A484F0u, &query));
      PutBlock(out, 1, &query.words[7], 3);
    }
    void PointSegmentOurs(const u32* in, u32* out)
    {
      Vec point, closest;
      Wm3::Segment3f segment;
      Load(point, in, 0);
      Load(segment.Origin, in, 3);
      Load(segment.Direction, in, 6);
      std::memcpy(&segment.Extent, in + 9, 4);
      Put(out, 0, Wm3::SquaredDistanceVector3Segment3(point, segment, closest));
      PutBlock(out, 1, &closest, 3);
    }

    // IntrBox2Box2<float>::Test 0x00A47D40 (CAiSteeringImpl's unit boxes): a
    // box is Center[2] Axis[2][2] Extent[2].
    void GenSteeringBox(Rng& rng, u32* out, const u32* nearCenter)
    {
      if (rng.Chance(10)) {
        for (int i = 0; i < 8; ++i) {
          out[i] = Bits(GenFloat(rng));
        }
        return;
      }
      for (int i = 0; i < 2; ++i) {
        out[i] = nearCenter ? Bits(DerivedFloat(static_cast<double>(F(nearCenter, i)) + rng.Range(-12.0, 12.0)))
                      : Bits(static_cast<float>(rng.Range(-50.0, 1050.0)));
      }
      // A unit heading from a normalised random vector: sqrt is correctly rounded
      // on every platform, where cos/sin of the CRT may differ by an ulp.
      const double hx = rng.Range(-1.0, 1.0);
      const double hy = rng.Range(-1.0, 1.0);
      const double length = std::sqrt(hx * hx + hy * hy);
      const float cosine = length > 1e-9 ? static_cast<float>(hx / length) : 1.0f;
      const float sine = length > 1e-9 ? static_cast<float>(hy / length) : 0.0f;
      out[2] = Bits(cosine);
      out[3] = Bits(sine);
      out[4] = Bits(-sine);
      out[5] = Bits(cosine);
      out[6] = Bits(static_cast<float>(rng.Range(0.0, 6.0)));
      out[7] = Bits(static_cast<float>(rng.Range(0.0, 6.0)));
    }
    void GenBox2Pair(Rng& rng, u32* in)
    {
      GenSteeringBox(rng, in, nullptr);
      GenSteeringBox(rng, in + 8, in);
    }
    void Box2PairRetail(const u32* in, u32* out)
    {
      u32 box0[8], box1[8];
      std::memcpy(box0, in, sizeof(box0));
      std::memcpy(box1, in + 8, sizeof(box1));
      QueryImage query = CanaryQuery();
      retail::ThisCallBool2(0x00A47BF0u, &query, box0, box1);
      out[0] = static_cast<u32>(retail::ThisCallBool0(0x00A47D40u, &query));
    }
    void Box2PairOurs(const u32* in, u32* out)
    {
      Wm3::Box2f box0, box1;
      std::memcpy(&box0.Center, in, 8);
      std::memcpy(&box0.Axis[0], in + 2, 8);
      std::memcpy(&box0.Axis[1], in + 4, 8);
      std::memcpy(box0.Extent, in + 6, 8);
      std::memcpy(&box1.Center, in + 8, 8);
      std::memcpy(&box1.Axis[0], in + 10, 8);
      std::memcpy(&box1.Axis[1], in + 12, 8);
      std::memcpy(box1.Extent, in + 14, 8);
      out[0] = Wm3::TestBox2Box2(box0, box1) ? 1u : 0u;
    }

    // ---- sixth wave: terrain, random stream, transform inverse, Vector2f, ray
    // slab clip, bone rotation and the inlined X87Math sites ------------------

    // CHeightField::GetElevation 0x0044FB90: in = x, z, width, height (1..8
    // each), then 64 samples packed two to a word. A field is {data, width,
    // height} at +0/+4/+8.
    constexpr int kFieldSampleWords = 32;
    [[nodiscard]] float GenFieldCoordinate(Rng& rng, const int size)
    {
      const u32 mode = rng.Below(100);
      if (mode < 55) {
        return static_cast<float>(rng.Range(-2.0, size + 2.0));
      }
      if (mode < 75) {
        return NearFloat(rng, static_cast<double>(static_cast<int>(rng.Below(static_cast<u32>(size) + 3)) - 1));
      }
      if (mode < 85) {
        return NearFloat(rng, static_cast<double>(static_cast<int>(rng.Below(static_cast<u32>(size) + 3)) - 1) + 0.5);
      }
      return GenFloat(rng);
    }
    void GenHeightField(Rng& rng, u32* in)
    {
      const int width = 1 + static_cast<int>(rng.Below(8));
      const int height = 1 + static_cast<int>(rng.Below(8));
      in[0] = Bits(GenFieldCoordinate(rng, width));
      in[1] = Bits(GenFieldCoordinate(rng, height));
      in[2] = static_cast<u32>(width);
      in[3] = static_cast<u32>(height);
      const u32 mode = rng.Below(100);
      for (int i = 0; i < kFieldSampleWords; ++i) {
        // Whole fields of one level, of the extremes, or random words.
        in[4 + i] = mode < 10 ? 0u : mode < 20 ? 0xFFFFFFFFu : mode < 30 ? 0x40004000u : rng.U32();
      }
    }
    void HeightFieldRetail(const u32* in, u32* out)
    {
      struct
      {
        const void* data;
        int width;
        int height;
      } field{in + 4, static_cast<int>(in[2]), static_cast<int>(in[3])};
      Put(out, 0, retail::HeightFieldElevation(&field, F(in, 0), F(in, 1)));
    }
    void HeightFieldOurs(const u32* in, u32* out)
    {
      const int width = static_cast<int>(in[2]);
      const int height = static_cast<int>(in[3]);
#if defined(DIFFFUZZ_ENGINE_LINKED)
      moho::CHeightField field(width - 1, height - 1); // InitField(width, height)
      std::memcpy(field.data, in + 4, static_cast<std::size_t>(width * height) * 2);
      Put(out, 0, field.GetElevation(F(in, 0), F(in, 1)));
#else
      std::uint16_t samples[kFieldSampleWords * 2];
      std::memcpy(samples, in + 4, sizeof(samples));
      Put(out, 0, mirror::HeightFieldElevation(samples, width, height, F(in, 0), F(in, 1)));
#endif
    }

    // CRandomStream::FRand(lower, upper) 0x0051B5C0: in = state seed, k, lower,
    // upper. Both sides fill the 624 state words from the seed the same way; k
    // = 624 makes IRand twist the block first (ShuffleState 0x0040EBB0). out =
    // the draw, k after, and the xor of the state words after.
    constexpr int kTwisterWords = 624;
    void FillTwisterState(const u32 seed, u32* state)
    {
      for (u32 i = 0; i < static_cast<u32>(kTwisterWords); ++i) {
        u32 z = seed + 0x9E3779B9u * (i + 1u);
        z = (z ^ (z >> 16)) * 0x85EBCA6Bu;
        z = (z ^ (z >> 13)) * 0xC2B2AE35u;
        state[i] = z ^ (z >> 16);
      }
    }
    [[nodiscard]] u32 XorWords(const u32* words, const int n)
    {
      u32 x = 0;
      for (int i = 0; i < n; ++i) {
        x ^= words[i];
      }
      return x;
    }
    void GenRandomRange(Rng& rng, u32* in)
    {
      in[0] = rng.U32();
      const u32 kMode = rng.Below(100);
      in[1] = kMode < 30 ? 624u : kMode < 40 ? 623u : rng.Below(624);
      float lower, upper;
      const u32 mode = rng.Below(100);
      if (mode < 35) {
        upper = static_cast<float>(rng.Range(0.0, 50.0)); // FRand(-h, h)
        lower = -upper;
      } else if (mode < 55) {
        lower = 0.0f;
        upper = rng.Chance(50) ? 1.0f : static_cast<float>(rng.Range(0.0, 10.0));
      } else if (mode < 85) {
        lower = GenPlain(rng, 1000.0f);
        upper = GenPlain(rng, 1000.0f);
      } else {
        lower = GenFloat(rng);
        upper = GenFloat(rng);
      }
      in[2] = Bits(lower);
      in[3] = Bits(upper);
    }
    void RandomRangeRetail(const u32* in, u32* out)
    {
      static u32 stream[0x9CC / 4]; // twister state, k at +9C0h, the gaussian cache
      FillTwisterState(in[0], stream);
      stream[kTwisterWords] = in[1];
      Put(out, 0, retail::RandomStreamFRand(stream, F(in, 2), F(in, 3)));
      out[1] = stream[kTwisterWords];
      out[2] = XorWords(stream, kTwisterWords);
    }
    void RandomRangeOurs(const u32* in, u32* out)
    {
#if defined(DIFFFUZZ_ENGINE_LINKED)
      static moho::CRandomStream stream;
      FillTwisterState(in[0], stream.twister.state);
      stream.twister.k = in[1];
      Put(out, 0, stream.FRand(F(in, 2), F(in, 3)));
      out[1] = stream.twister.k;
      out[2] = XorWords(stream.twister.state, kTwisterWords);
#else
      static u32 state[kTwisterWords];
      FillTwisterState(in[0], state);
      u32 k = in[1];
      Put(out, 0, mirror::RandomStreamFRand(state, k, F(in, 2), F(in, 3)));
      out[1] = k;
      out[2] = XorWords(state, kTwisterWords);
#endif
    }

    // VTransform::Inverse 0x0046FBF0: orient[4] (w, x, y, z), pos[3]; the
    // conjugate, and the negated position rotated by it (MultQuadVec).
    void GenTransform(Rng& rng, u32* in)
    {
      float q[4], v[3];
      GenQuat(rng, q);
      GenVec3(rng, v);
      PutF(in, 0, q, 4);
      PutF(in, 4, v, 3);
    }
    void InverseRetail(const u32* in, u32* out)
    {
      float transform[7], inverted[7];
      std::memcpy(transform, in, sizeof(transform));
      Canary(inverted);
      out[7] = retail::VTransformInverse(inverted, transform) == inverted;
      PutBlock(out, 0, inverted, 7);
    }
    void InverseOurs(const u32* in, u32* out)
    {
#if defined(DIFFFUZZ_ENGINE_LINKED)
      moho::VTransform transform;
      std::memcpy(&transform.orient_, in, 16);
      std::memcpy(&transform.pos_, in + 4, 12);
      const moho::VTransform inverted = transform.Inverse();
      PutBlock(out, 0, &inverted.orient_, 4);
      PutBlock(out, 4, &inverted.pos_, 3);
#else
      float transform[7], inverted[7];
      std::memcpy(transform, in, sizeof(transform));
      mirror::VTransformInverse(transform, inverted);
      PutBlock(out, 0, inverted, 7);
#endif
      out[7] = 1;
    }

    // Distance2D 0x004CC8F0, DistanceSquared2D 0x004CC930 and
    // IsValid_Vector2f 0x005657B0: from[2] to[2].
    void GenVec2Pair(Rng& rng, u32* in)
    {
      for (int i = 0; i < 4; ++i) {
        in[i] = Bits(rng.Chance(70) ? GenPlain(rng, 1000.0f) : GenFloat(rng));
      }
    }
    void Distance2DRetail(const u32* in, u32* out) { Put(out, 0, retail::Distance2D(in, in + 2)); }
    void Distance2DOurs(const u32* in, u32* out)
    {
      Wm3::Vector2f from, to;
      std::memcpy(&from, in, 8);
      std::memcpy(&to, in + 2, 8);
      Put(out, 0, moho::Distance2D(from, to));
    }
    void DistanceSquared2DRetail(const u32* in, u32* out) { Put(out, 0, retail::DistanceSquared2D(in, in + 2)); }
    void DistanceSquared2DOurs(const u32* in, u32* out)
    {
      Wm3::Vector2f from, to;
      std::memcpy(&from, in, 8);
      std::memcpy(&to, in + 2, 8);
      Put(out, 0, moho::DistanceSquared2D(from, to));
    }
    void Valid2Retail(const u32* in, u32* out) { out[0] = static_cast<u32>(retail::IsValidVector2f(in)); }
    void Valid2Ours(const u32* in, u32* out)
    {
      Wm3::Vector2f v;
      std::memcpy(&v, in, 8);
      out[0] = moho::IsValidVector2f(v) ? 1u : 0u;
    }

    // RayBoxSlabClip 0x00473DF0: state = origin[3] dir[3] tEnter tExit, box =
    // min[3] max[3]. Direction lanes include zeros and values around the
    // FLT_MIN cut-off (0x00E4F7A8) below which an axis is skipped.
    void GenRaySlab(Rng& rng, u32* in)
    {
      float box[6];
      for (int i = 0; i < 3; ++i) {
        const float a = GenPlain(rng, 100.0f);
        const float b = GenPlain(rng, 100.0f);
        box[i] = a < b ? a : b;
        box[3 + i] = a < b ? b : a;
      }
      if (rng.Chance(10)) {
        for (float& lane : box) {
          lane = GenFloat(rng);
        }
      }
      for (int i = 0; i < 3; ++i) {
        in[i] = Bits(rng.Chance(85) ? GenPlain(rng, 150.0f) : GenFloat(rng));
      }
      float direction[3];
      GenUnitVec3(rng, direction);
      for (float& lane : direction) {
        const u32 mode = rng.Below(100);
        if (mode < 8) {
          lane = rng.Chance(50) ? 0.0f : -0.0f;
        } else if (mode < 16) {
          // One draw per statement: cl and clang order the operands of `*` differently.
          const float magnitude = FromBits(0x00800000u + rng.Below(5) - 2u);
          lane = rng.Chance(50) ? magnitude : -magnitude;
        } else if (mode < 24) {
          lane = GenFloat(rng);
        }
      }
      PutF(in, 3, direction, 3);
      in[6] = Bits(rng.Chance(70) ? 0.0f : GenPlain(rng, 10.0f));
      in[7] = Bits(rng.Chance(70) ? 3.4028235e38f : GenPlain(rng, 500.0f));
      PutF(in, 8, box, 6);
    }
    void RaySlabRetail(const u32* in, u32* out)
    {
      u32 state[8], box[6];
      std::memcpy(state, in, sizeof(state));
      std::memcpy(box, in + 8, sizeof(box));
      out[8] = static_cast<u32>(retail::RayBoxSlabClip(state, box));
      PutBlock(out, 0, state, 8);
    }
    void RaySlabOurs(const u32* in, u32* out)
    {
      moho::RaySlabState state;
      Wm3::AxisAlignedBox3f box;
      std::memcpy(&state, in, sizeof(state));
      std::memcpy(&box.Min, in + 8, 12);
      std::memcpy(&box.Max, in + 11, 12);
      out[8] = moho::RayBoxSlabClip(state, box) ? 1u : 0u;
      PutBlock(out, 0, &state, 8);
    }

    // CAniPoseBone::Rotate 0x0054BC00: orient = orient * rotation (MultiplyQuat),
    // then CAniPose::MarkBoneDirty (0x0054B990), which returns at once for a
    // bone whose dirty byte (+1Ch of its 4Ch-byte pose record) is already set.
    void BoneRotateRetail(const u32* in, u32* out)
    {
      alignas(4) unsigned char poseBones[0x4C] = {};
      poseBones[0x1C] = 1;
      u32 pose[0x30 / 4] = {};
      pose[0x28 / 4] = static_cast<u32>(reinterpret_cast<std::uintptr_t>(poseBones));
      pose[0x2C / 4] = static_cast<u32>(reinterpret_cast<std::uintptr_t>(poseBones + sizeof(poseBones)));
      u32 bone[0x44 / 4] = {};
      std::memcpy(&bone[0x20 / 4], in, 16);
      bone[0x3C / 4] = 0; // the bone's index in the pose
      bone[0x40 / 4] = static_cast<u32>(reinterpret_cast<std::uintptr_t>(pose));
      retail::AniPoseBoneRotate(bone, in + 4);
      PutBlock(out, 0, &bone[0x20 / 4], 4);
    }
    void BoneRotateOurs(const u32* in, u32* out)
    {
      Quat orient, rotation;
      Load(orient, in, 0);
      Load(rotation, in, 4);
      const Quat rotated = moho::MultiplyQuat(orient, rotation); // CAniPoseBone::Rotate
      PutBlock(out, 0, &rotated, 4);
    }
    void GenBoneRotate(Rng& rng, u32* in)
    {
      float q1[4], q2[4];
      GenQuatPair(rng, q1, q2);
      PutF(in, 0, q1, 4);
      PutF(in, 4, q2, 4);
    }

    // MotorFallDown::Update's fall axis 0x006952A9..0x006953B1: direction,
    // elevation (fall angle - pi/2, so [-pi/2, 0]) -> axis[3].
    void GenFallAxis(Rng& rng, u32* in)
    {
      in[0] = Bits(rng.Chance(80) ? GenAngle(rng) : GenFloat(rng));
      const u32 mode = rng.Below(100);
      in[1] = Bits(mode < 70 ? static_cast<float>(rng.Range(-1.5707964, 0.0))
                   : mode < 80 ? NearFloat(rng, rng.Chance(50) ? 0.0 : -1.5707963267948966)
                               : GenFloat(rng));
    }
    void FallAxisRetail(const u32* in, u32* out)
    {
      float axis[3];
      Canary(axis);
      retail::FallAxis(F(in, 0), F(in, 1), axis);
      PutBlock(out, 0, axis, 3);
    }
    void FallAxisOurs(const u32* in, u32* out)
    {
      const float direction = F(in, 0);
      const float elevation = F(in, 1);
      Put(out, 0, msvc8::SinTimesCos(direction, elevation));
      Put(out, 1, -msvc8::sin(elevation));
      Put(out, 2, msvc8::CosTimesCos(direction, elevation));
    }

    // CUnitMotion::CalcWingedOrientation 0x006BDAF2..0x006BDB31 (and the
    // formation and weapon headings): atan2(y1, x1) stored, minus atan2(y2, x2).
    void GenAtan2Pair(Rng& rng, u32* in)
    {
      for (int i = 0; i < 4; ++i) {
        in[i] = Bits(rng.Chance(80) ? GenPlain(rng, rng.Chance(50) ? 1.0f : 1000.0f) : GenFloat(rng));
      }
    }
    void Atan2DiffRetail(const u32* in, u32* out)
    {
      Put(out, 0, retail::Atan2DifferenceSite(F(in, 0), F(in, 1), F(in, 2), F(in, 3)));
    }
    void Atan2DiffOurs(const u32* in, u32* out)
    {
      Put(out, 0, msvc8::Atan2Difference(F(in, 0), F(in, 1), F(in, 2), F(in, 3)));
    }

    // CUnitMotion::HandleDivingAndSurfacing 0x006C336C..0x006C3380: the depth
    // phase is |depth / limit|, folded to 1 - phase above 0.5, so <= 0.5.
    void GenDivePhase(Rng& rng, u32* in)
    {
      const u32 mode = rng.Below(100);
      in[0] = Bits(mode < 70 ? static_cast<float>(rng.Range(0.0, 0.5))
                   : mode < 80 ? NearFloat(rng, rng.Chance(50) ? 0.5 : 0.0)
                               : GenFloat(rng));
      in[1] = Bits(rng.Chance(85) ? static_cast<float>(rng.Range(0.0, 10.0)) : GenFloat(rng));
    }
    void DiveRetail(const u32* in, u32* out) { Put(out, 0, retail::DiveCurveSpeed(F(in, 0), F(in, 1))); }
    void DiveOurs(const u32* in, u32* out)
    {
      constexpr float kPi = 3.1415927f; // CUnitMotion.cpp HandleDivingAndSurfacing
      Put(out, 0, msvc8::SinOfProductTimes(F(in, 0), kPi, F(in, 1)));
    }

    // cfunc_ProjectileGetCurrentSpeedL 0x006A2846..0x006A2861: |velocity|.
    void VelocityRetail(const u32* in, u32* out) { Put(out, 0, retail::VelocityLength(in)); }
    void VelocityOurs(const u32* in, u32* out)
    {
      float lanes[3];
      std::memcpy(lanes, in, sizeof(lanes));
      Put(out, 0, msvc8::VectorLengthZYXX87(lanes));
    }

    // The Lua table code's number keys: cvttss2si (lua_getn 0x0090AD62).
    void KeyRetail(const u32* in, u32* out) { out[0] = static_cast<u32>(retail::TruncateFloatKey(F(in, 0))); }
    void KeyOurs(const u32* in, u32* out) { out[0] = static_cast<u32>(msvc8::TruncateToInt(F(in, 0))); }
    void GenFloatKey(Rng& rng, u32* in)
    {
      const u32 mode = rng.Below(100);
      if (mode < 40) {
        in[0] = Bits(static_cast<float>(static_cast<int>(rng.Below(2001)) - 1000));
      } else if (mode < 55) {
        in[0] = Bits(NearFloat(rng, rng.Chance(50) ? 2147483648.0 : -2147483648.0));
      } else {
        GenLuaAny(rng, in);
      }
    }

    // 0x00425110: frndint, +1 when above (cmova; a NaN adds nothing), fistp.
    // Near-integers, near-halves (frndint's ties), the int range's edges and
    // raw bits (NaN, infinities, denormals).
    void CeilRetail(const u32* in, u32* out) { out[0] = static_cast<u32>(retail::CeilFloatToInt(F(in, 0))); }
    void CeilOurs(const u32* in, u32* out) { out[0] = static_cast<u32>(msvc8::CeilToIntX87(F(in, 0))); }
    void GenCeilInput(Rng& rng, u32* in)
    {
      const u32 mode = rng.Below(100);
      if (mode < 35) {
        in[0] = Bits(NearFloat(rng, static_cast<double>(static_cast<int>(rng.Below(20001)) - 10000)));
      } else if (mode < 50) {
        in[0] = Bits(NearFloat(rng, static_cast<double>(static_cast<int>(rng.Below(2001)) - 1000) + 0.5));
      } else if (mode < 65) {
        in[0] = Bits(NearFloat(rng, rng.Chance(50) ? 2147483648.0 : -2147483648.0));
      } else {
        in[0] = Bits(GenFloat(rng));
      }
    }

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
      {"lua_randomseed", 0x0091A0D0, "lua/LuaObject.cpp math_randomseed seed conversion", 1, 1, "x", "seed", GenLuaAny, LuaSeedRetail, LuaSeedOurs, true},
      // Fourth wave: retail callers of the inline X87Math helpers. New rows go
      // at the end: a row's stream comes from its index (main.cpp, dump_main.cpp).
      {"RATE_GameRateToSpeed", 0x0055AE10, "moho/sim/SimDriver.cpp RATE_GameRateToSpeed (mirrored; IntrinsicLnQuotient, RoundToInt)", 1, 1, "rate", "speed(int)", GenRate, RateRetail, RateOurs, true},
      {"QuantizeEdgeCost", 0x0092D8B0, "gpg/core/algorithms/Cluster.cpp Cluster::QuantizeEdgeCost (ScaledLnQuotient)", 2, 1, "a b", "bucket", GenEdgeCost, EdgeCostRetail, EdgeCostOurs},
      {"COORDS_ToGridRect", 0x0050AFA0, "moho/entity/Entity.cpp COORDS_ToGridRect (RoundToInt)", 4, 5, "x z sizeX(int) sizeZ(int)", "x0 z0 x1 z1 ret", GenGridRect, GridRectRetail, GridRectOurs, true},
      {"ProjectBoxOntoAxis", 0x00475550, "moho/collision/CColPrimitiveBase.cpp ProjectBoxOntoAxis (mirrored; BoxRadiusOnAxisX87)", 18, 2, "center[3] axes[9] extent[3] axis[3]", "min max", GenBoxAxis, BoxAxisRetail, BoxAxisOurs},
      {"MatrixColumnsToQuatCanonical", 0x004F0AE0, "moho/math/QuaternionMath.cpp MatrixColumnsToQuatCanonical", 9, 5, "columns[9]", "q[4] ret", GenRows, ColumnsToQuatRetail, ColumnsToQuatOurs},
      {"IsValidVector3f", 0x005657F0, "moho/math/Vector3f.cpp IsValidVector3f", 3, 1, "v[3]", "ret", GenV3, ValidRetail, ValidOurs},
      {"VAxes3", 0x004EC590, "moho/math/MathReflection.cpp VAxes3::VAxes3(quat) (mirrored; QuatForwardAxis's basis)", 4, 9, "q[4]", "vX[3] vY[3] vZ[3]", GenQ, AxesRetail, AxesOurs},
      {"VMatrix4::Set", 0x004EE980, "moho/math/MathReflection.cpp VMatrix4::Set(quat, vec) (mirrored)", 7, 16, "v[3] q[4]", "r[16]", GenQuatVec, MatrixSetRetail, MatrixSetOurs},
      {"FloorSecondsToTicks", 0x0066D1D0, "moho/math/GridPos.cpp FloorSecondsToTicks", 1, 1, "seconds", "ticks(int)", GenSeconds, SecondsRetail, SecondsOurs, true},
      {"GridPos", 0x00506E20, "moho/math/GridPos.cpp GridPos::GridPos(Vec3f*, int)", 4, 3, "world[3] size(int)", "x z ret", GenGridPos, GridPosRetail, GridPosOurs, true},
      {"MakeSegment3fFromEndpoints", 0x004FE130, "moho/math/Wm3Segment3FafExtras.cpp MakeSegment3fFromEndpoints", 6, 8, "start[3] end[3]", "origin[3] dir[3] extent ret", GenTwoVec, SegmentRetail, SegmentOurs},
      {"AxisAlignedBoundsFromBox", 0x004FE2D0, "moho/math/Wm3AxisAlignedBox3FafExtras.cpp AxisAlignedBoundsFromBox", 15, 7, "center[3] axes[9] extent[3]", "min[3] max[3] ret", GenBox, BoundsRetail, BoundsOurs},
      // fifth wave: the collision primitives (IntrSegment3Box3f, DistVector3Box3f, InBox, IntrSegment3Sphere3f, IntrBox3Sphere3f, the box-box SAT)
      {"ColBox::CollideLine", 0x004FF2D0, "moho/collision/CColPrimitiveBase.cpp CColPrimitive<Box3f>::CollideLine (IntrSegment3Box3f)", 21, 8, "box[15] start[3] end[3]", "ret dir[3] pos[3] dist", GenBoxLine, BoxLineRetail, BoxLineOurs},
      {"ColBox::CollideSphere", 0x004FF150, "moho/collision/CColPrimitiveBase.cpp CColPrimitive<Box3f>::CollideSphere (DistVector3Box3f)", 19, 5, "box[15] sphere[4]", "ret dir[3] depth", GenBoxSphere, BoxSphereRetail, BoxSphereOurs},
      {"ColBox::CollideBox", 0x004FF260, "moho/collision/CColPrimitiveBase.cpp CColPrimitive<Box3f>::CollideBox (box-box SAT 0x00474830)", 30, 5, "box[15] other[15]", "ret dir[3] depth", GenBoxBox, BoxBoxRetail, BoxBoxOurs},
      {"ColBox::PointInShape", 0x004FF450, "moho/collision/CColPrimitiveBase.cpp CColPrimitive<Box3f>::PointInShape (InBox)", 18, 1, "box[15] point[3]", "ret", GenBoxPoint, BoxPointRetail, BoxPointOurs},
      {"ColSphere::CollideLine", 0x004FE9D0, "moho/collision/CColPrimitiveBase.cpp CColPrimitive<Sphere3f>::CollideLine (IntrSegment3Sphere3f)", 10, 8, "sphere[4] start[3] end[3]", "ret dir[3] pos[3] dist", GenSphereLine, SphereLineRetail, SphereLineOurs},
      {"ColSphere::CollideBox", 0x004FE860, "moho/collision/CColPrimitiveBase.cpp CColPrimitive<Sphere3f>::CollideBox (IntrBox3Sphere3f)", 19, 5, "sphere[4] box[15]", "ret dir[3] depth", GenSphereBox, SphereBoxRetail, SphereBoxOurs},
      {"ColSphere::CollideSphere", 0x004FE7A0, "moho/collision/CColPrimitiveBase.cpp CColPrimitive<Sphere3f>::CollideSphere", 8, 5, "sphere[4] other[4]", "ret dir[3] depth", GenSphereSphere, SphereSphereRetail, SphereSphereOurs},
      {"ColSphere::PointInShape", 0x004FEB60, "moho/collision/CColPrimitiveBase.cpp CColPrimitive<Sphere3f>::PointInShape", 7, 1, "sphere[4] point[3]", "ret", GenSpherePoint, SpherePointRetail, SpherePointOurs},
      {"Wm3::SquaredDistanceVector3Segment3", 0x00A484F0, "moho/math/Wm3Queries.cpp SquaredDistanceVector3Segment3 (DistVector3Segment3<float>::GetSquared)", 10, 4, "point[3] origin[3] dir[3] extent", "sqr closest[3]", GenPointSegment, PointSegmentRetail, PointSegmentOurs},
      {"Wm3::TestBox2Box2", 0x00A47D40, "moho/math/Wm3Queries.cpp TestBox2Box2 (IntrBox2Box2<float>::Test)", 16, 1, "box0[8] box1[8]", "ret", GenBox2Pair, Box2PairRetail, Box2PairOurs},
      // sixth wave
      {"CHeightField::GetElevation", 0x0044FB90, "moho/sim/STIMap.cpp CHeightField::GetElevation (BilinearHeight)", 4 + kFieldSampleWords, 1, "x z width(int) height(int) samples[64](u16)", "r", GenHeightField, HeightFieldRetail, HeightFieldOurs},
      {"CRandomStream::FRand(lower,upper)", 0x0051B5C0, "moho/sim/CRandomStream.cpp CRandomStream::FRand(lower, upper) (TwisterWordInRange)", 4, 3, "seed(u32) k(u32) lower upper", "r k(u32) xorState(u32)", GenRandomRange, RandomRangeRetail, RandomRangeOurs},
      {"VTransform::Inverse", 0x0046FBF0, "moho/render/camera/VTransform.cpp VTransform::Inverse (ConjugateQuat, MultQuadVec)", 7, 8, "orient[4] pos[3]", "orient[4] pos[3] ret", GenTransform, InverseRetail, InverseOurs},
      {"Distance2D", 0x004CC8F0, "moho/math/Vector2f.cpp Distance2D", 4, 1, "from[2] to[2]", "r", GenVec2Pair, Distance2DRetail, Distance2DOurs},
      {"DistanceSquared2D", 0x004CC930, "moho/math/Vector2f.cpp DistanceSquared2D", 4, 1, "from[2] to[2]", "r", GenVec2Pair, DistanceSquared2DRetail, DistanceSquared2DOurs},
      {"IsValidVector2f", 0x005657B0, "moho/math/Vector2f.cpp IsValidVector2f", 2, 1, "v[2]", "ret", GenVec2Pair, Valid2Retail, Valid2Ours},
      {"RayBoxSlabClip", 0x00473DF0, "moho/math/Wm3AxisAlignedBox3FafExtras.cpp RayBoxSlabClip", 14, 9, "origin[3] dir[3] tEnter tExit min[3] max[3]", "state[8] ret", GenRaySlab, RaySlabRetail, RaySlabOurs},
      {"CAniPoseBone::Rotate", 0x0054BC00, "moho/animation/CAniPose.cpp CAniPoseBone::Rotate (MultiplyQuat)", 8, 4, "orient[4] rotation[4]", "orient[4]", GenBoneRotate, BoneRotateRetail, BoneRotateOurs},
      {"MotorFallDown::FallAxis", 0x006952A9, "moho/entity/MotorFallDown.cpp (SinTimesCos, -sin, CosTimesCos; site 0x006952A9..0x006953B1)", 2, 3, "direction elevation", "axis[3]", GenFallAxis, FallAxisRetail, FallAxisOurs},
      {"Atan2Difference", 0x006BDAF2, "legacy/math/X87Math.cpp msvc8::Atan2Difference (site 0x006BDAF2..0x006BDB31, leaf 0x004E9DF0)", 4, 1, "y1 x1 y2 x2", "r", GenAtan2Pair, Atan2DiffRetail, Atan2DiffOurs},
      {"CUnitMotion::DiveCurveSpeed", 0x006C336C, "moho/unit/CUnitMotion.cpp msvc8::SinOfProductTimes(phase, pi, base) (site 0x006C336C..0x006C3380)", 2, 1, "phase base", "r", GenDivePhase, DiveRetail, DiveOurs},
      {"VectorLengthZYXX87", 0x006A2846, "legacy/math/X87Math.cpp msvc8::VectorLengthZYXX87 (site 0x006A2846..0x006A2861)", 3, 1, "v[3]", "r", GenV3, VelocityRetail, VelocityOurs},
      {"TruncateToInt", 0x0090AD62, "legacy/math/X87Math.h msvc8::TruncateToInt (cvttss2si, lua_getn 0x0090AD62)", 1, 1, "key", "int", GenFloatKey, KeyRetail, KeyOurs, true},
      // seventh wave
      {"CeilToIntX87", 0x00425110, "legacy/math/X87Math.cpp msvc8::CeilToIntX87 (frndint, cmova +1, fistp)", 1, 1, "value", "int", GenCeilInput, CeilRetail, CeilOurs, true},
    };
  } // namespace

  const Target* MathTargets(int& count)
  {
    count = static_cast<int>(sizeof(kTargets) / sizeof(kTargets[0]));
    return kTargets;
  }
} // namespace difffuzz
