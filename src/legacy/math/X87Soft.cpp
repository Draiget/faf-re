// Engine addition (#262): the x87 routines of legacy/math/X87Routines.h in software, bit for bit
// what the x87 unit stores (the model is in X87Soft.h). Written from the instruction sequences of
// legacy/math/X87Math64.S: each routine below is that block, instruction by instruction, with the
// register stack kept in named values. Three layers:
//
//   Ext       an x87 register: 64-bit significand, extended exponent, the x87's classes and NaN
//             rules. Every operation forms the exact result in 128 bits and rounds once.
//   Fast      a double standing for a value with at most 24 significant bits: each operation
//             rounds to odd at 53 bits (the error-free transforms give the exact error's sign),
//             then to 24 bits on the double's bit pattern. Round-to-odd at p + 2 bits or more
//             followed by round-to-nearest at p equals rounding the exact value once
//             (Boldo-Melquiond), so this is exact while every value stays in the double's normal
//             range; an operation that leaves it marks the run, and the routine is redone on Ext.
//             The hot arithmetic routines (terrain height, vector lengths, the box test) take it.
//   kernels   fsin/fcos/fptan/fpatan/fyl2x/f2xm1 in double-double (about 106 bits), rounded to
//             64 bits as the hardware's result.
//
// Pure functions of their arguments: no state, no use of the thread's floating-point mode beyond
// round-to-nearest (the game never changes it). Needs unsigned __int128 (clang on every target).

#include "legacy/math/X87Soft.h"

#include "legacy/math/X87Routines.h"

#include <bit>
#include <cmath>
#include <cstdint>

namespace fa::x87
{
  namespace
  {
    using u64 = std::uint64_t;
    using u128 = unsigned __int128;
    using i128 = __int128;

    // --- The register model -----------------------------------------------------------------

    enum class Class : std::uint8_t
    {
      Zero,
      Finite,
      Infinity,
      NaN,
    };

    /// An x87 register. Finite: value = sig * 2^(exp - 63), sig with bit 63 set (an extended
    /// denormal has exp == kMinExp and bit 63 clear). NaN: sig is the payload with bit 63 set,
    /// bit 62 the quiet bit.
    struct Ext
    {
      u64 sig = 0;
      std::int32_t exp = 0;
      bool negative = false;
      Class cls = Class::Zero;
    };

    constexpr std::int32_t kMinExp = -16382;
    constexpr std::int32_t kMaxExp = 16383;
    constexpr u64 kIntegerBit = 0x8000000000000000ull;
    constexpr u64 kQuietBit = 0x4000000000000000ull;

    /// The precision-control widths the routines use.
    enum Precision : int
    {
      P24 = 24,
      P53 = 53,
      P64 = 64,
    };

    [[nodiscard]] constexpr Ext Zero(
      const bool negative
    ) noexcept
    {
      return Ext{0, 0, negative, Class::Zero};
    }

    [[nodiscard]] constexpr Ext Infinity(
      const bool negative
    ) noexcept
    {
      return Ext{kIntegerBit, kMaxExp + 1, negative, Class::Infinity};
    }

    /// The real indefinite: what an invalid operation leaves (0xFFC00000 once stored as a float).
    [[nodiscard]] constexpr Ext Indefinite() noexcept
    {
      return Ext{kIntegerBit | kQuietBit, kMaxExp + 1, true, Class::NaN};
    }

    [[nodiscard]] constexpr Ext Finite(
      const bool negative,
      const std::int32_t exp,
      const u64 sig
    ) noexcept
    {
      return Ext{sig, exp, negative, Class::Finite};
    }

    [[nodiscard]] constexpr Ext Negate(
      Ext a
    ) noexcept
    {
      a.negative = !a.negative;
      return a;
    }

    [[nodiscard]] constexpr Ext Abs(
      Ext a
    ) noexcept
    {
      a.negative = false;
      return a;
    }

    [[nodiscard]] constexpr Ext Quiet(
      Ext a
    ) noexcept
    {
      a.sig |= kQuietBit;
      return a;
    }

    [[nodiscard]] constexpr bool IsSignaling(
      const Ext& a
    ) noexcept
    {
      return a.cls == Class::NaN && (a.sig & kQuietBit) == 0;
    }

    /// The x87's choice between two NaN operands (at least one is a NaN; Intel SDM vol. 1,
    /// table 4-7): a NaN against a non-NaN is that NaN; a quiet NaN against a signalling one is
    /// the quiet one; of two of the same kind, the larger significand, and on a tie the positive
    /// one. The result is quiet. Only a memory operand of an arithmetic instruction can still be
    /// signalling (fld quiets what it loads), so the indefinite an invalid operation made beats a
    /// signalling NaN in memory.
    [[nodiscard]] constexpr Ext PropagateNaN(
      const Ext a,
      const Ext b
    ) noexcept
    {
      if (a.cls != Class::NaN) {
        return Quiet(b);
      }
      if (b.cls != Class::NaN) {
        return Quiet(a);
      }
      if (IsSignaling(a) != IsSignaling(b)) {
        return Quiet(IsSignaling(a) ? b : a);
      }
      if (a.sig != b.sig) {
        return Quiet(a.sig > b.sig ? a : b);
      }
      return Quiet(a.negative ? b : a);
    }

    // --- Rounding -------------------------------------------------------------------------------

    [[nodiscard]] constexpr int CountLeadingZeros(
      const u128 m
    ) noexcept
    {
      const u64 high = static_cast<u64>(m >> 64);
      return high != 0 ? std::countl_zero(high) : 64 + std::countl_zero(static_cast<u64>(m));
    }

    /// m >> shift, with every bit shifted out ORed into the lowest one ("jamming").
    [[nodiscard]] constexpr u128 ShiftRightJam(
      const u128 m,
      const int shift
    ) noexcept
    {
      if (shift <= 0) {
        return m;
      }
      if (shift >= 128) {
        return m != 0 ? 1 : 0;
      }
      return (m >> shift) | ((m << (128 - shift)) != 0 ? 1 : 0);
    }

    /// Rounds m (bit 127 the leading position) to its top `bits` bits, nearest-even; `sticky`
    /// stands for nonzero bits below m. Returns true when rounding up carried out of bit 127
    /// (m is then 2^127, one binade up).
    [[nodiscard]] constexpr bool RoundTopBits(
      u128& m,
      const int bits,
      const bool sticky
    ) noexcept
    {
      const u128 unit = static_cast<u128>(1) << (128 - bits);
      const u128 half = unit >> 1;
      const u128 rest = m & (unit - 1);
      m -= rest;
      const bool up = rest > half || (rest == half && (sticky || (m & unit) != 0));
      if (!up) {
        return false;
      }
      m += unit;
      if (m == 0) {
        m = static_cast<u128>(1) << 127;
        return true;
      }
      return false;
    }

    /// The register value sign * m * 2^(exp - 127) (plus a sticky remainder below m), rounded to
    /// `bits` significant bits within the extended exponent range: an arithmetic result under
    /// precision control. Below 2^kMinExp it becomes an extended denormal, rounded at the same
    /// bit positions; past the range, infinity.
    [[nodiscard]] Ext Round(
      const bool negative,
      std::int32_t exp,
      u128 m,
      const bool sticky,
      const int bits
    ) noexcept
    {
      if (m == 0) {
        return Zero(negative);
      }
      const int leading = CountLeadingZeros(m);
      m <<= leading;
      exp -= leading;
      if (exp < kMinExp) {
        m = ShiftRightJam(m, kMinExp - exp); // shifted-out bits jam into the lowest, far below
        exp = kMinExp;
      }
      if (RoundTopBits(m, bits, sticky)) {
        ++exp;
      }
      if (exp > kMaxExp) {
        return Infinity(negative);
      }
      const u64 sig = static_cast<u64>(m >> 64);
      if (sig == 0) {
        return Zero(negative);
      }
      return Finite(negative, exp, sig);
    }

    // --- Loads and stores ----------------------------------------------------------------------

    /// A float or double register value, exact; a NaN keeps its quiet bit as it is in memory.
    [[nodiscard]] Ext FromBinary(
      const u64 bits,
      const int mantissaBits,
      const int exponentBits
    ) noexcept
    {
      const int bias = (1 << (exponentBits - 1)) - 1;
      const bool negative = ((bits >> (mantissaBits + exponentBits)) & 1) != 0;
      const auto biased = static_cast<std::int32_t>((bits >> mantissaBits) & ((1u << exponentBits) - 1));
      const u64 fraction = bits & ((static_cast<u64>(1) << mantissaBits) - 1);
      if (biased == (1 << exponentBits) - 1) {
        if (fraction == 0) {
          return Infinity(negative);
        }
        return Ext{kIntegerBit | (fraction << (63 - mantissaBits)), kMaxExp + 1, negative, Class::NaN};
      }
      if (biased == 0) {
        if (fraction == 0) {
          return Zero(negative);
        }
        const int leading = std::countl_zero(fraction);
        return Finite(negative, 1 - bias - (leading - (63 - mantissaBits)), fraction << leading);
      }
      return Finite(negative, biased - bias, kIntegerBit | (fraction << (63 - mantissaBits)));
    }

    /// fld m32 / m64: exact; a signalling NaN is quieted.
    [[nodiscard]] Ext Load(
      const float value
    ) noexcept
    {
      Ext a = FromBinary(std::bit_cast<std::uint32_t>(value), 23, 8);
      return a.cls == Class::NaN ? Quiet(a) : a;
    }

    [[nodiscard]] Ext Load(
      const double value
    ) noexcept
    {
      Ext a = FromBinary(std::bit_cast<u64>(value), 52, 11);
      return a.cls == Class::NaN ? Quiet(a) : a;
    }

    /// A memory operand of an arithmetic instruction (fmul m32, fadd m32, fdivr m32, ...): read
    /// as it is, so a signalling NaN stays signalling for the NaN rules.
    [[nodiscard]] Ext Operand(
      const float value
    ) noexcept
    {
      return FromBinary(std::bit_cast<std::uint32_t>(value), 23, 8);
    }

    /// fild m32: exact.
    [[nodiscard]] Ext LoadInteger(
      const std::int32_t value
    ) noexcept
    {
      if (value == 0) {
        return Zero(false);
      }
      const bool negative = value < 0;
      const u64 magnitude = negative ? static_cast<u64>(-static_cast<std::int64_t>(value)) : static_cast<u64>(value);
      const int leading = std::countl_zero(magnitude);
      return Finite(negative, 63 - leading, magnitude << leading);
    }

    /// fstp m32 / m64: one rounding to the format, with its denormals and overflow to infinity.
    [[nodiscard]] u64 ToBinary(
      const Ext& a,
      const int mantissaBits,
      const int exponentBits
    ) noexcept
    {
      const int bias = (1 << (exponentBits - 1)) - 1;
      const u64 signBit = static_cast<u64>(a.negative ? 1 : 0) << (mantissaBits + exponentBits);
      const u64 allOnes = static_cast<u64>((1u << exponentBits) - 1) << mantissaBits;
      const u64 fractionMask = (static_cast<u64>(1) << mantissaBits) - 1;
      switch (a.cls) {
      case Class::Zero:
        return signBit;
      case Class::Infinity:
        return signBit | allOnes;
      case Class::NaN:
        return signBit | allOnes | ((a.sig >> (63 - mantissaBits)) & fractionMask) |
          (static_cast<u64>(1) << (mantissaBits - 1));
      case Class::Finite:
        break;
      }
      const int significandBits = mantissaBits + 1;
      const std::int32_t minExp = 1 - bias;
      u128 m = static_cast<u128>(a.sig) << 64;
      std::int32_t exp = a.exp;
      if ((a.sig & kIntegerBit) == 0) {
        const int leading = std::countl_zero(a.sig);
        m <<= leading;
        exp -= leading;
      }
      if (exp < minExp) {
        m = ShiftRightJam(m, minExp - exp);
        exp = minExp;
      }
      if (RoundTopBits(m, significandBits, false)) {
        ++exp;
      }
      if (exp > bias) {
        return signBit | allOnes;
      }
      const u64 field = static_cast<u64>(m >> (128 - significandBits));
      if ((field >> mantissaBits) == 0) {
        return signBit | field; // denormal (or zero after rounding)
      }
      return signBit | (static_cast<u64>(exp + bias) << mantissaBits) | (field & fractionMask);
    }

    [[nodiscard]] float StoreFloat(
      const Ext& a
    ) noexcept
    {
      return std::bit_cast<float>(static_cast<std::uint32_t>(ToBinary(a, 23, 8)));
    }

    [[nodiscard]] double StoreDouble(
      const Ext& a
    ) noexcept
    {
      return std::bit_cast<double>(ToBinary(a, 52, 11));
    }

    /// frndint under round-to-nearest: the nearest integer, ties to even; exact.
    [[nodiscard]] Ext RoundToInteger(
      const Ext& a
    ) noexcept
    {
      if (a.cls == Class::NaN) {
        return Quiet(a);
      }
      if (a.cls != Class::Finite || a.exp >= 63) {
        return a;
      }
      if (a.exp < -1) {
        return Zero(a.negative);
      }
      u128 m = static_cast<u128>(a.sig) << 64;
      std::int32_t exp = a.exp;
      if (a.exp == -1) {
        // [0.5, 1): one integer bit above the leading one.
        m >>= 1;
        exp = 0;
      }
      if (RoundTopBits(m, exp + 1, false)) {
        ++exp;
      }
      const u64 sig = static_cast<u64>(m >> 64);
      if (sig == 0) {
        return Zero(a.negative);
      }
      const int leading = std::countl_zero(sig);
      return Finite(a.negative, exp - leading, sig << leading);
    }

    // --- Arithmetic under precision control --------------------------------------------------

    [[nodiscard]] Ext Add(
      const Ext& a,
      const Ext& b,
      const int bits
    ) noexcept
    {
      if (a.cls == Class::NaN || b.cls == Class::NaN) {
        return PropagateNaN(a, b);
      }
      if (a.cls == Class::Infinity) {
        return (b.cls == Class::Infinity && b.negative != a.negative) ? Indefinite() : a;
      }
      if (b.cls == Class::Infinity) {
        return b;
      }
      if (a.cls == Class::Zero && b.cls == Class::Zero) {
        return Zero(a.negative && b.negative);
      }
      if (a.cls == Class::Zero) {
        return Round(b.negative, b.exp, static_cast<u128>(b.sig) << 64, false, bits);
      }
      if (b.cls == Class::Zero) {
        return Round(a.negative, a.exp, static_cast<u128>(a.sig) << 64, false, bits);
      }
      // value = M * 2^(exp - 126): the integer bit at 126 leaves room for a carry.
      const Ext& big = a.exp >= b.exp ? a : b;
      const Ext& small = a.exp >= b.exp ? b : a;
      const u128 bigM = static_cast<u128>(big.sig) << 63;
      const u128 smallM = ShiftRightJam(static_cast<u128>(small.sig) << 63, big.exp - small.exp);
      if (big.negative == small.negative) {
        return Round(big.negative, big.exp + 1, bigM + smallM, false, bits);
      }
      if (bigM == smallM) {
        return Zero(false);
      }
      if (bigM > smallM) {
        return Round(big.negative, big.exp + 1, bigM - smallM, false, bits);
      }
      return Round(small.negative, big.exp + 1, smallM - bigM, false, bits);
    }

    [[nodiscard]] Ext Sub(
      const Ext& a,
      const Ext& b,
      const int bits
    ) noexcept
    {
      if (a.cls == Class::NaN || b.cls == Class::NaN) {
        return PropagateNaN(a, b);
      }
      return Add(a, Negate(b), bits);
    }

    [[nodiscard]] Ext Mul(
      const Ext& a,
      const Ext& b,
      const int bits
    ) noexcept
    {
      if (a.cls == Class::NaN || b.cls == Class::NaN) {
        return PropagateNaN(a, b);
      }
      const bool negative = a.negative != b.negative;
      if (a.cls == Class::Infinity || b.cls == Class::Infinity) {
        return (a.cls == Class::Zero || b.cls == Class::Zero) ? Indefinite() : Infinity(negative);
      }
      if (a.cls == Class::Zero || b.cls == Class::Zero) {
        return Zero(negative);
      }
      return Round(negative, a.exp + b.exp + 1, static_cast<u128>(a.sig) * b.sig, false, bits);
    }

    [[nodiscard]] Ext Div(
      const Ext& a,
      const Ext& b,
      const int bits
    ) noexcept
    {
      if (a.cls == Class::NaN || b.cls == Class::NaN) {
        return PropagateNaN(a, b);
      }
      const bool negative = a.negative != b.negative;
      if (a.cls == Class::Infinity) {
        return b.cls == Class::Infinity ? Indefinite() : Infinity(negative);
      }
      if (b.cls == Class::Infinity) {
        return Zero(negative);
      }
      if (b.cls == Class::Zero) {
        return a.cls == Class::Zero ? Indefinite() : Infinity(negative);
      }
      if (a.cls == Class::Zero) {
        return Zero(negative);
      }
      // a / b = (A * 2^64 / B) * 2^(ea - eb - 64); then quotient bits until there are 67.
      const u128 numerator = static_cast<u128>(a.sig) << 64;
      u128 quotient = numerator / b.sig;
      u128 remainder = numerator % b.sig;
      std::int32_t exp = a.exp - b.exp - 64 + 127;
      while ((quotient >> 66) == 0) {
        quotient <<= 1;
        remainder <<= 1;
        if (remainder >= b.sig) {
          remainder -= b.sig;
          quotient |= 1;
        }
        --exp;
      }
      return Round(negative, exp, quotient, remainder != 0, bits);
    }

    /// floor(sqrt(n)) for n < 2^127.
    [[nodiscard]] u64 IntegerSqrt(
      const u128 n
    ) noexcept
    {
      auto root = static_cast<u64>(std::sqrt(static_cast<double>(n)));
      if (root != 0) {
        root = static_cast<u64>((static_cast<u128>(root) + n / root) >> 1);
      }
      while (static_cast<u128>(root) * root > n) {
        --root;
      }
      while (static_cast<u128>(root + 1) * (root + 1) <= n) {
        ++root;
      }
      return root;
    }

    [[nodiscard]] Ext Sqrt(
      const Ext& a,
      const int bits
    ) noexcept
    {
      if (a.cls == Class::NaN) {
        return Quiet(a);
      }
      if (a.cls == Class::Zero) {
        return a;
      }
      if (a.negative) {
        return Indefinite();
      }
      if (a.cls == Class::Infinity) {
        return a;
      }
      u64 sig = a.sig;
      std::int32_t exp = a.exp;
      if ((sig & kIntegerBit) == 0) {
        const int leading = std::countl_zero(sig);
        sig <<= leading;
        exp -= leading;
      }
      // a = sig * 2^(exp - 63) = N * 2^(exp - 63 - shift), with that exponent even and N < 2^127.
      const int shift = ((exp - 63 - 62) & 1) == 0 ? 62 : 63;
      const u128 n = static_cast<u128>(sig) << shift;
      u128 root = IntegerSqrt(n);
      u128 remainder = n - root * root;
      // Three more root bits, digit by digit.
      for (int i = 0; i < 3; ++i) {
        const u128 trial = (root << 2) + 1;
        remainder <<= 2;
        root <<= 1;
        if (remainder >= trial) {
          remainder -= trial;
          root |= 1;
        }
      }
      const std::int32_t halfExp = (exp - 63 - shift) / 2 - 3;
      return Round(false, halfExp + 127, root, remainder != 0, bits);
    }

    /// fscale: a * 2^trunc(b), exact apart from the range's edges.
    [[nodiscard]] Ext Scale(
      const Ext& a,
      const Ext& b
    ) noexcept
    {
      if (a.cls == Class::NaN || b.cls == Class::NaN) {
        return PropagateNaN(a, b);
      }
      if (b.cls == Class::Infinity) {
        if (a.cls == Class::Zero) {
          return b.negative ? a : Indefinite();
        }
        if (a.cls == Class::Infinity) {
          return b.negative ? Indefinite() : a;
        }
        return b.negative ? Zero(a.negative) : Infinity(a.negative);
      }
      if (a.cls != Class::Finite || b.cls == Class::Zero) {
        return a;
      }
      // trunc(b), clamped far beyond where the result over- or underflows.
      std::int32_t n = 0;
      if (b.exp >= 0) {
        n = b.exp >= 20 ? (1 << 20) : static_cast<std::int32_t>(b.sig >> (63 - b.exp));
        if (b.negative) {
          n = -n;
        }
      }
      return Round(a.negative, a.exp + n, static_cast<u128>(a.sig) << 64, false, P64);
    }

    // --- Double-double arithmetic for the kernels --------------------------------------------

    /// hi + lo with |lo| <= ulp(hi) / 2: about 106 significant bits.
    struct DoubleDouble
    {
      double hi = 0.0;
      double lo = 0.0;
    };

    [[nodiscard]] DoubleDouble TwoSum(
      const double a,
      const double b
    ) noexcept
    {
      const double s = a + b;
      const double bb = s - a;
      return {s, (a - (s - bb)) + (b - bb)};
    }

    [[nodiscard]] DoubleDouble QuickTwoSum(
      const double a,
      const double b
    ) noexcept
    {
      const double s = a + b;
      return {s, b - (s - a)};
    }

    [[nodiscard]] DoubleDouble TwoProduct(
      const double a,
      const double b
    ) noexcept
    {
      const double p = a * b;
      return {p, std::fma(a, b, -p)};
    }

    [[nodiscard]] DoubleDouble operator+(
      const DoubleDouble a,
      const DoubleDouble b
    ) noexcept
    {
      DoubleDouble s = TwoSum(a.hi, b.hi);
      const DoubleDouble t = TwoSum(a.lo, b.lo);
      s.lo += t.hi;
      s = QuickTwoSum(s.hi, s.lo);
      s.lo += t.lo;
      return QuickTwoSum(s.hi, s.lo);
    }

    [[nodiscard]] DoubleDouble operator-(
      const DoubleDouble a
    ) noexcept
    {
      return {-a.hi, -a.lo};
    }

    [[nodiscard]] DoubleDouble operator-(
      const DoubleDouble a,
      const DoubleDouble b
    ) noexcept
    {
      return a + (-b);
    }

    [[nodiscard]] DoubleDouble operator*(
      const DoubleDouble a,
      const DoubleDouble b
    ) noexcept
    {
      DoubleDouble p = TwoProduct(a.hi, b.hi);
      p.lo += a.hi * b.lo + a.lo * b.hi;
      return QuickTwoSum(p.hi, p.lo);
    }

    [[nodiscard]] DoubleDouble operator*(
      const DoubleDouble a,
      const double b
    ) noexcept
    {
      DoubleDouble p = TwoProduct(a.hi, b);
      p.lo += a.lo * b;
      return QuickTwoSum(p.hi, p.lo);
    }

    [[nodiscard]] DoubleDouble operator/(
      const DoubleDouble a,
      const DoubleDouble b
    ) noexcept
    {
      const double q1 = a.hi / b.hi;
      DoubleDouble r = a - b * q1;
      const double q2 = r.hi / b.hi;
      r = r - b * q2;
      const double q3 = r.hi / b.hi;
      return QuickTwoSum(q1, q2) + DoubleDouble{q3, 0.0};
    }

    [[nodiscard]] DoubleDouble Sqrt(
      const DoubleDouble a
    ) noexcept
    {
      if (a.hi <= 0.0) {
        return {0.0, 0.0};
      }
      const double root = std::sqrt(a.hi);
      const DoubleDouble square = TwoProduct(root, root);
      const double correction = ((a.hi - square.hi) - square.lo + a.lo) / (2.0 * root);
      return QuickTwoSum(root, correction);
    }

    constexpr DoubleDouble kLn2{0x1.62e42fefa39efp-1, 0x1.abc9e3b39803fp-56};
    constexpr DoubleDouble kLog2E{0x1.71547652b82fep+0, 0x1.777d0ffda0d24p-56};

    // The x87 constant loads, each the real constant rounded to 64 bits (fldln2, fldlg2, fldl2e).
    constexpr Ext kFldLn2 = Finite(false, -1, 0xB17217F7D1CF79ACull);
    constexpr Ext kFldLg2 = Finite(false, -2, 0x9A209A84FBCFF799ull);
    constexpr Ext kFldL2e = Finite(false, 0, 0xB8AA3B295C17F0BCull);
    constexpr Ext kFld1 = Finite(false, 0, kIntegerBit);
    // RN64(pi), RN64(pi/2), RN64(pi/4), RN64(3pi/4): fpatan's exact special values.
    constexpr Ext kPi64 = Finite(false, 1, 0xC90FDAA22168C235ull);
    constexpr Ext kHalfPi64 = Finite(false, 0, 0xC90FDAA22168C235ull);
    constexpr Ext kQuarterPi64 = Finite(false, -1, 0xC90FDAA22168C235ull);
    constexpr Ext kThreeQuarterPi64 = Finite(false, 1, 0x96CBE3F9990E91A8ull);
    // Intel's 66-bit pi used by fsin/fcos/fptan's reduction: pi truncated after 64 fraction bits,
    // here in units of 2^-64 (pi/2 is the same integer in units of 2^-65).
    constexpr u128 kPi66 = (static_cast<u128>(0x3) << 64) | 0x243F6A8885A308D3ull;
    // The same 66-bit pi exactly as hi + lo, and half of it: fpatan's quadrant terms.
    constexpr DoubleDouble kPi66Exact{
      static_cast<double>(static_cast<u64>(kPi66 >> 13)) * 0x1p-51,
      static_cast<double>(static_cast<u64>(kPi66 & 0x1FFF)) * 0x1p-64
    };
    constexpr DoubleDouble kHalfPi66Exact{kPi66Exact.hi * 0.5, kPi66Exact.lo * 0.5};

    /// A finite register exactly as hi + lo (64 significant bits fit in two doubles).
    [[nodiscard]] DoubleDouble ToDoubleDouble(
      const Ext& a
    ) noexcept
    {
      const double hi = std::ldexp(static_cast<double>(a.sig >> 11), a.exp - 52);
      const double lo = std::ldexp(static_cast<double>(a.sig & 0x7FF), a.exp - 63);
      const DoubleDouble value = QuickTwoSum(hi, lo);
      return a.negative ? -value : value;
    }

    /// hi + lo rounded once to a 64-bit significand (what the instruction leaves in the register).
    [[nodiscard]] Ext RoundTo64(
      const DoubleDouble value
    ) noexcept
    {
      if (value.hi == 0.0) {
        return Zero(std::signbit(value.hi));
      }
      const bool negative = value.hi < 0.0;
      int hiExp = 0;
      const double hiFraction = std::frexp(std::fabs(value.hi), &hiExp); // [0.5, 1)
      const auto hiSig = static_cast<u64>(std::ldexp(hiFraction, 53));   // 53 bits
      u128 m = static_cast<u128>(hiSig) << 75;                           // bit 127 = 2^(hiExp - 1)
      if (value.lo != 0.0) {
        int loExp = 0;
        const double loFraction = std::frexp(std::fabs(value.lo), &loExp);
        const auto loSig = static_cast<u64>(std::ldexp(loFraction, 53));
        // lo = loSig * 2^(loExp - 53); m's unit is 2^(hiExp - 1 - 127).
        const int shift = (loExp - 53) - (hiExp - 128);
        const u128 loM = shift >= 0 ? static_cast<u128>(loSig) << shift : ShiftRightJam(loSig, -shift);
        if ((value.lo < 0.0) == negative) {
          m += loM;
        } else {
          m -= loM;
        }
      }
      return Round(negative, hiExp - 1, m, false, P64);
    }

    // Series coefficients, 1/k as double-double, built once.
    struct Reciprocals
    {
      DoubleDouble of[64];

      Reciprocals() noexcept
      {
        for (int k = 1; k < 64; ++k) {
          of[k] = DoubleDouble{1.0, 0.0} / DoubleDouble{static_cast<double>(k), 0.0};
        }
      }
    };

    [[nodiscard]] const Reciprocals& Inverse() noexcept
    {
      static const Reciprocals table;
      return table;
    }

    constexpr int kTrigTerms = 16;

    /// The Taylor coefficients the kernels' Horner steps take, as double-double, built once:
    /// (-1)^k / (2k+1)! for sin, (-1)^k / (2k)! for cos, (-1)^k / (2k+1) for arctan, 1 / (k+1)!
    /// for expm1.
    struct SeriesCoefficients
    {
      DoubleDouble sine[kTrigTerms + 1];
      DoubleDouble cosine[kTrigTerms + 1];
      DoubleDouble arctangent[64];
      DoubleDouble exponential[32];

      SeriesCoefficients() noexcept
      {
        const Reciprocals& inv = Inverse();
        DoubleDouble factorial{1.0, 0.0}; // 1 / n! as n grows
        for (int n = 0; n <= 2 * kTrigTerms + 1; ++n) {
          if (n > 0) {
            factorial = factorial * inv.of[n];
          }
          const int k = n / 2;
          const DoubleDouble signedTerm = (k % 2 == 0) ? factorial : -factorial;
          if ((n % 2) == 0) {
            cosine[k] = signedTerm;
          } else {
            sine[k] = signedTerm;
          }
        }
        for (int k = 0; k < 64 && 2 * k + 1 < 64; ++k) {
          arctangent[k] = (k % 2 == 0) ? inv.of[2 * k + 1] : -inv.of[2 * k + 1];
        }
        DoubleDouble expTerm{1.0, 0.0};
        for (int k = 0; k < 32; ++k) {
          expTerm = expTerm * inv.of[k + 1];
          exponential[k] = expTerm; // 1 / (k+1)!
        }
      }
    };

    [[nodiscard]] const SeriesCoefficients& Coefficients() noexcept
    {
      static const SeriesCoefficients table;
      return table;
    }

    /// sin(r) and cos(r) for |r| <= pi/4: Taylor series to 2^-110, Horner in r^2.
    void SinCos(
      const DoubleDouble r,
      DoubleDouble* sine,
      DoubleDouble* cosine
    ) noexcept
    {
      const SeriesCoefficients& c = Coefficients();
      const DoubleDouble r2 = r * r;
      if (sine != nullptr) {
        DoubleDouble p = c.sine[kTrigTerms];
        for (int k = kTrigTerms - 1; k >= 0; --k) {
          p = c.sine[k] + r2 * p;
        }
        *sine = r * p;
      }
      if (cosine != nullptr) {
        DoubleDouble p = c.cosine[kTrigTerms];
        for (int k = kTrigTerms - 1; k >= 0; --k) {
          p = c.cosine[k] + r2 * p;
        }
        *cosine = p;
      }
    }

    /// fsin/fcos/fptan's argument reduction: x = k * (pi66 / 2) + r, k the nearest integer, done
    /// exactly in 128-bit fixed point. |x| < 2^63 (the instructions' range).
    struct Reduced
    {
      DoubleDouble r;
      unsigned quadrant = 0;
    };

    [[nodiscard]] Reduced Reduce(
      const Ext& x
    ) noexcept
    {
      if (x.exp < -1) { // |x| < 1/2 < pi66/4
        return {ToDoubleDouble(x), 0};
      }
      // |x| in units of 2^-65 (exact: x's last bit weighs 2^(exp - 63) >= 2^-64).
      const u128 units = static_cast<u128>(x.sig) << (x.exp + 2);
      u128 k = units / kPi66;
      i128 rest = static_cast<i128>(units % kPi66);
      if (2 * rest > static_cast<i128>(kPi66)) { // kPi66 is odd: no ties
        ++k;
        rest -= static_cast<i128>(kPi66);
      }
      if (x.negative) {
        rest = -rest;
        k = static_cast<u128>(-static_cast<i128>(k));
      }
      // rest * 2^-65 exactly as hi + lo (|rest| < 2^65).
      const auto hi = static_cast<double>(rest);
      const auto lo = static_cast<double>(rest - static_cast<i128>(hi));
      return {QuickTwoSum(std::ldexp(hi, -65), std::ldexp(lo, -65)), static_cast<unsigned>(k & 3)};
    }

    /// arctan(z) for 0 <= z <= 1: two half-angle steps to |z| <= tan(pi/16), then the series.
    [[nodiscard]] DoubleDouble Atan(
      DoubleDouble z
    ) noexcept
    {
      const DoubleDouble one{1.0, 0.0};
      for (int i = 0; i < 2; ++i) {
        z = z / (one + Sqrt(one + z * z));
      }
      const SeriesCoefficients& c = Coefficients();
      const DoubleDouble w = z * z;
      constexpr int kTerms = 24;
      DoubleDouble s = c.arctangent[kTerms];
      for (int k = kTerms - 1; k >= 0; --k) {
        s = c.arctangent[k] + w * s;
      }
      return z * s * 4.0;
    }

    // --- The transcendental instructions -------------------------------------------------------

    /// fsin / fcos / fptan's shared cases. Returns false when the instruction leaves the register
    /// alone (|x| >= 2^63: C2 set) or the result is decided without the kernel (`out` holds it).
    [[nodiscard]] bool TrigSpecial(
      const Ext& x,
      Ext& out,
      const bool cosine
    ) noexcept
    {
      switch (x.cls) {
      case Class::NaN:
        out = Quiet(x);
        return true;
      case Class::Infinity:
        out = Indefinite();
        return true;
      case Class::Zero:
        out = cosine ? kFld1 : x;
        return true;
      case Class::Finite:
        break;
      }
      return false;
    }

    [[nodiscard]] Ext Fsin(
      const Ext& x
    ) noexcept
    {
      Ext out;
      if (TrigSpecial(x, out, false)) {
        return out;
      }
      if (x.exp >= 63) {
        return x; // out of range: unchanged
      }
      const Reduced reduced = Reduce(x);
      DoubleDouble value;
      if ((reduced.quadrant & 1) == 0) {
        SinCos(reduced.r, &value, nullptr);
      } else {
        SinCos(reduced.r, nullptr, &value);
      }
      return RoundTo64((reduced.quadrant & 2) != 0 ? -value : value);
    }

    [[nodiscard]] Ext Fcos(
      const Ext& x
    ) noexcept
    {
      Ext out;
      if (TrigSpecial(x, out, true)) {
        return out;
      }
      if (x.exp >= 63) {
        return x;
      }
      const Reduced reduced = Reduce(x);
      DoubleDouble value;
      if ((reduced.quadrant & 1) == 0) {
        SinCos(reduced.r, nullptr, &value);
      } else {
        SinCos(reduced.r, &value, nullptr);
      }
      const bool negate = reduced.quadrant == 1 || reduced.quadrant == 2;
      return RoundTo64(negate ? -value : value);
    }

    /// fptan. Returns false when |x| >= 2^63: nothing is pushed and ST0 is left as it was.
    [[nodiscard]] bool Fptan(
      const Ext& x,
      Ext& tangent
    ) noexcept
    {
      if (TrigSpecial(x, tangent, false)) {
        return true;
      }
      if (x.exp >= 63) {
        return false;
      }
      const Reduced reduced = Reduce(x);
      DoubleDouble sine;
      DoubleDouble cosine;
      SinCos(reduced.r, &sine, &cosine);
      // tan(r + k pi/2): tan r for even k, -1/tan r for odd k.
      tangent = RoundTo64((reduced.quadrant & 1) == 0 ? sine / cosine : -(cosine / sine));
      return true;
    }

    /// fpatan: arctan(y / x) in the quadrant of (x, y), with Intel's values for zeros and
    /// infinities (no invalid case).
    [[nodiscard]] Ext Fpatan(
      const Ext& y,
      const Ext& x
    ) noexcept
    {
      if (y.cls == Class::NaN || x.cls == Class::NaN) {
        return PropagateNaN(y, x);
      }
      const auto withSign = [](Ext value, const bool negative) {
        value.negative = negative;
        return value;
      };
      if (y.cls == Class::Zero) {
        return x.negative ? withSign(kPi64, y.negative) : Zero(y.negative);
      }
      if (y.cls == Class::Infinity) {
        if (x.cls == Class::Infinity) {
          return withSign(x.negative ? kThreeQuarterPi64 : kQuarterPi64, y.negative);
        }
        return withSign(kHalfPi64, y.negative);
      }
      if (x.cls == Class::Zero) {
        return withSign(kHalfPi64, y.negative);
      }
      if (x.cls == Class::Infinity) {
        return x.negative ? withSign(kPi64, y.negative) : Zero(y.negative);
      }
      // The quadrant terms are the 66-bit pi fsin reduces with, as the hardware's results show:
      // acos of tiny inputs, pi/2 - x stored as a double, rounds the hardware's way only so.
      const DoubleDouble ay = ToDoubleDouble(Abs(y));
      const DoubleDouble ax = ToDoubleDouble(Abs(x));
      DoubleDouble angle;
      if (ay.hi < ax.hi || (ay.hi == ax.hi && ay.lo <= ax.lo)) {
        angle = Atan(ay / ax);
      } else {
        angle = kHalfPi66Exact - Atan(ax / ay);
      }
      if (x.negative) {
        angle = kPi66Exact - angle;
      }
      return RoundTo64(y.negative ? -angle : angle);
    }

    /// fyl2x: y * log2(x) as one operation, with Intel's values for the special operands.
    [[nodiscard]] Ext Fyl2x(
      const Ext& y,
      const Ext& x
    ) noexcept
    {
      if (y.cls == Class::NaN || x.cls == Class::NaN) {
        return PropagateNaN(y, x);
      }
      if (x.negative && x.cls != Class::Zero) {
        return Indefinite();
      }
      if (x.cls == Class::Zero) { // log2(0) = -inf: 0 * inf is invalid
        return y.cls == Class::Zero ? Indefinite() : Infinity(!y.negative);
      }
      if (x.cls == Class::Infinity) {
        return y.cls == Class::Zero ? Indefinite() : Infinity(y.negative);
      }
      std::int32_t exp = x.exp;
      u64 sig = x.sig;
      if ((sig & kIntegerBit) == 0) {
        const int leading = std::countl_zero(sig);
        sig <<= leading;
        exp -= leading;
      }
      if (sig == kIntegerBit) {
        // x = 2^exp: log2 is exact, and y * exp rounds once.
        if (y.cls == Class::Infinity) {
          return exp == 0 ? Indefinite() : Infinity(y.negative != (exp < 0));
        }
        return Mul(y, LoadInteger(exp), P64);
      }
      const bool logNegative = exp < 0;
      if (y.cls == Class::Infinity) {
        return Infinity(y.negative != logNegative);
      }
      if (y.cls == Class::Zero) {
        return Zero(y.negative != logNegative);
      }
      // x = m * 2^e with m in [sqrt(1/2), sqrt(2)); log2(m) = 2 log2(e) atanh((m - 1) / (m + 1)).
      constexpr u64 kSqrt2Sig = 0xB504F333F9DE6484ull;
      std::int32_t e = exp;
      Ext m = Finite(false, 0, sig);
      if (sig > kSqrt2Sig) {
        m.exp = -1;
        ++e;
      }
      const DoubleDouble one{1.0, 0.0};
      const DoubleDouble mm = ToDoubleDouble(m);
      const DoubleDouble s = (mm - one) / (mm + one);
      const DoubleDouble w = s * s;
      const Reciprocals& inv = Inverse();
      constexpr int kTerms = 22;
      DoubleDouble series = inv.of[2 * kTerms + 1];
      for (int k = kTerms - 1; k >= 0; --k) {
        series = inv.of[2 * k + 1] + w * series;
      }
      const DoubleDouble log2m = s * series * kLog2E * 2.0;
      const DoubleDouble log2x = DoubleDouble{static_cast<double>(e), 0.0} + log2m;
      return RoundTo64(ToDoubleDouble(y) * log2x);
    }

    /// f2xm1: 2^x - 1 for |x| <= 1 (outside it the instruction is undefined; the limits are kept).
    [[nodiscard]] Ext F2xm1(
      const Ext& x
    ) noexcept
    {
      switch (x.cls) {
      case Class::NaN:
        return Quiet(x);
      case Class::Zero:
        return x;
      case Class::Infinity:
        return x.negative ? Negate(kFld1) : x;
      case Class::Finite:
        break;
      }
      if (x.sig == kIntegerBit && x.exp == 0) { // +-1: 1 or -1/2
        return x.negative ? Finite(true, -1, kIntegerBit) : kFld1;
      }
      // expm1(t), t = x ln 2: t (1 + t/2! + t^2/3! + ...), Horner in t.
      const DoubleDouble t = ToDoubleDouble(x) * kLn2;
      const SeriesCoefficients& c = Coefficients();
      constexpr int kTerms = 27;
      DoubleDouble sum = c.exponential[kTerms];
      for (int k = kTerms - 1; k >= 0; --k) {
        sum = c.exponential[k] + t * sum;
      }
      return RoundTo64(t * sum);
    }

    // --- The arithmetic the routines run on ---------------------------------------------------

    /// The routines' arithmetic on the exact register model, at _PC_24.
    struct ExactArithmetic
    {
      using Value = Ext;

      [[nodiscard]] static Value Load(
        const float v
      ) noexcept
      {
        return x87::Load(v);
      }
      [[nodiscard]] static Value Operand(
        const float v
      ) noexcept
      {
        return x87::Operand(v);
      }
      [[nodiscard]] static Value LoadInteger(
        const std::int32_t v
      ) noexcept
      {
        return x87::LoadInteger(v);
      }
      [[nodiscard]] Value Add(
        const Value& a,
        const Value& b
      ) noexcept
      {
        return x87::Add(a, b, P24);
      }
      [[nodiscard]] Value Sub(
        const Value& a,
        const Value& b
      ) noexcept
      {
        return x87::Sub(a, b, P24);
      }
      [[nodiscard]] Value Mul(
        const Value& a,
        const Value& b
      ) noexcept
      {
        return x87::Mul(a, b, P24);
      }
      [[nodiscard]] Value Div(
        const Value& a,
        const Value& b
      ) noexcept
      {
        return x87::Div(a, b, P24);
      }
      [[nodiscard]] Value Sqrt(
        const Value& a
      ) noexcept
      {
        return x87::Sqrt(a, P24);
      }
      [[nodiscard]] static Value Abs(
        const Value& a
      ) noexcept
      {
        return x87::Abs(a);
      }
      [[nodiscard]] static float Store(
        const Value& a
      ) noexcept
      {
        return StoreFloat(a);
      }
      [[nodiscard]] static constexpr bool Valid() noexcept
      {
        return true;
      }
    };

    /// The same at _PC_24 on doubles (see the top of the file). Valid() is false once any
    /// operation left the double's normal range or met a NaN, infinity or zero divisor; the
    /// caller then redoes the routine on ExactArithmetic.
    struct FastArithmetic
    {
      using Value = double;

      bool ok = true;

      [[nodiscard]] static Value Load(
        const float v
      ) noexcept
      {
        return v;
      }
      [[nodiscard]] static Value Operand(
        const float v
      ) noexcept
      {
        return v;
      }
      [[nodiscard]] static Value LoadInteger(
        const std::int32_t v
      ) noexcept
      {
        return v;
      }

      /// r, the double nearest the exact result, and the sign of (exact - r) in `error`: the
      /// exact result rounded to 24 bits.
      [[nodiscard]] Value Finish(
        const double r,
        const double error
      ) noexcept
      {
        u64 bits = std::bit_cast<u64>(r);
        const u64 biased = (bits >> 52) & 0x7FF;
        if (biased < 0x080 || biased > 0x77F) { // outside [2^-895, 2^896]
          if (r == 0.0 && error == 0.0) {
            return r;
          }
          ok = false;
          return r;
        }
        if (error != 0.0 && (bits & 1) == 0) { // round to odd at 53 bits
          bits = ((error > 0.0) == (r > 0.0)) ? bits + 1 : bits - 1;
        }
        bits += 0x0FFFFFFFull + ((bits >> 29) & 1); // then to nearest-even at 24 bits
        bits &= ~0x1FFFFFFFull;
        return std::bit_cast<double>(bits);
      }

      [[nodiscard]] Value Add(
        const Value a,
        const Value b
      ) noexcept
      {
        const double r = a + b;
        const double bb = r - a;
        return Finish(r, (a - (r - bb)) + (b - bb));
      }

      [[nodiscard]] Value Sub(
        const Value a,
        const Value b
      ) noexcept
      {
        return Add(a, -b);
      }

      [[nodiscard]] Value Mul(
        const Value a,
        const Value b
      ) noexcept
      {
        const double r = a * b;
        return Finish(r, std::fma(a, b, -r));
      }

      [[nodiscard]] Value Div(
        const Value a,
        const Value b
      ) noexcept
      {
        if (b == 0.0) {
          ok = false;
          return 0.0;
        }
        const double r = a / b;
        const double remainder = std::fma(-r, b, a); // a - r b, exact
        return Finish(r, b > 0.0 ? remainder : -remainder);
      }

      [[nodiscard]] Value Sqrt(
        const Value a
      ) noexcept
      {
        if (a < 0.0) {
          ok = false;
          return 0.0;
        }
        const double r = std::sqrt(a);
        return Finish(r, std::fma(-r, r, a));
      }

      [[nodiscard]] static Value Abs(
        const Value a
      ) noexcept
      {
        return std::fabs(a);
      }
      [[nodiscard]] static float Store(
        const Value a
      ) noexcept
      {
        return static_cast<float>(a);
      }
      [[nodiscard]] bool Valid() const noexcept
      {
        return ok;
      }
    };

    // --- The routines, as X87Math64.S runs them -------------------------------------------------
    // Comments name the asm's stack as it stands after each step. Every arithmetic step is one
    // rounding at _PC_24; additions and multiplications keep the asm's operand pairs, which is
    // what fixes the rounding (the operations themselves are commutative).

    template <class A>
    [[nodiscard]] typename A::Value BilinearBody(
      A& ar,
      const float h00,
      const float h01,
      const float h10,
      const float h11,
      const float fx,
      const float fz
    ) noexcept
    {
      using V = typename A::Value;
      const V nearRow =
        ar.Add(A::Load(h00), ar.Mul(ar.Sub(A::Load(h01), A::Load(h00)), A::Load(fz))); // h00 + (h01-h00)fz
      const V farRow =
        ar.Add(A::Load(h10), ar.Mul(A::Load(fz), ar.Sub(A::Load(h11), A::Load(h10)))); // h10 + fz(h11-h10)
      return ar.Add(nearRow, ar.Mul(ar.Sub(farRow, nearRow), A::Operand(fx)));         // a + (b-a)fx
    }

    template <class A>
    [[nodiscard]] float BilinearT(
      const float h00,
      const float h01,
      const float h10,
      const float h11,
      const float fx,
      const float fz
    ) noexcept
    {
      A ar;
      const auto result = BilinearBody(ar, h00, h01, h10, h11, fx, fz);
      return ar.Valid() ? A::Store(result) : BilinearT<ExactArithmetic>(h00, h01, h10, h11, fx, fz);
    }

    template <class A>
    [[nodiscard]] float SubtractBilinearT(
      const float top,
      const float h00,
      const float h01,
      const float h10,
      const float h11,
      const float fx,
      const float fz
    ) noexcept
    {
      A ar;
      const auto height = BilinearBody(ar, h00, h01, h10, h11, fx, fz);
      const auto result = ar.Sub(A::Operand(top), height); // fsubr m32
      return ar.Valid() ? A::Store(result) : SubtractBilinearT<ExactArithmetic>(top, h00, h01, h10, h11, fx, fz);
    }

    template <class A>
    [[nodiscard]] float TwisterWordInRangeT(
      const float lower,
      const float upper,
      const std::uint32_t word
    ) noexcept
    {
      using V = typename A::Value;
      A ar;
      V w = A::LoadInteger(static_cast<std::int32_t>(word)); // fild: exact
      if (static_cast<std::int32_t>(word) < 0) {
        w = ar.Add(w, A::Load(0x1p32f)); // fadd 2^32
      }
      const V range = ar.Sub(A::Load(upper), A::Load(lower));
      const V scaled = ar.Mul(ar.Mul(range, w), A::Load(0x1p-32f));
      const V result = ar.Add(A::Load(lower), scaled);
      return ar.Valid() ? A::Store(result) : TwisterWordInRangeT<ExactArithmetic>(lower, upper, word);
    }

    template <class A>
    [[nodiscard]] bool ScaleVectorMaxLengthT(
      float* const x,
      float* const y,
      float* const z,
      const float maxLength,
      const float lengthSq
    ) noexcept
    {
      using V = typename A::Value;
      A ar;
      const V scale = ar.Div(A::Operand(maxLength), ar.Sqrt(A::Load(lengthSq))); // fsqrt; fdivr m32
      const V nx = ar.Mul(A::Load(*x), scale);
      const V ny = ar.Mul(A::Load(*y), scale);
      const V nz = ar.Mul(scale, A::Operand(*z)); // fmul m32
      if (!ar.Valid()) {
        return false;
      }
      *x = A::Store(nx);
      *y = A::Store(ny);
      *z = A::Store(nz);
      return true;
    }

    template <class A>
    [[nodiscard]] bool ScaleVectorToLengthT(
      float* const dest,
      const float* const source,
      const float lengthSq,
      const float length
    ) noexcept
    {
      using V = typename A::Value;
      A ar;
      const V scale = ar.Div(A::Operand(length), ar.Sqrt(A::Load(lengthSq)));
      const float s0 = source[0];
      const float s1 = source[1];
      const float s2 = source[2];
      const V d0 = ar.Mul(A::Load(s0), scale);
      const V d1 = ar.Mul(scale, A::Operand(s1));
      const V d2 = ar.Mul(scale, A::Operand(s2));
      if (!ar.Valid()) {
        return false;
      }
      // The asm stores dest[0] before it reads source[1]: the same when they don't overlap,
      // and source[i] is read before dest[i] is written either way.
      dest[0] = A::Store(d0);
      dest[1] = A::Store(d1);
      dest[2] = A::Store(d2);
      return true;
    }

    template <class A>
    [[nodiscard]] bool ScaleVectorT(
      float* const dest,
      const float* const source,
      const float scaleValue
    ) noexcept
    {
      using V = typename A::Value;
      A ar;
      const V scale = A::Load(scaleValue);
      const V d0 = ar.Mul(A::Load(source[0]), scale);
      const V d1 = ar.Mul(A::Load(source[1]), scale);
      const V d2 = ar.Mul(scale, A::Operand(source[2]));
      if (!ar.Valid()) {
        return false;
      }
      dest[0] = A::Store(d0);
      dest[1] = A::Store(d1);
      dest[2] = A::Store(d2);
      return true;
    }

    template <class A>
    [[nodiscard]] bool ScaleVectorToLengthOfT(
      float* const dest,
      const float* const source,
      const float* const target,
      const float sourceLengthSq
    ) noexcept
    {
      using V = typename A::Value;
      A ar;
      const V t0 = A::Load(target[0]);
      const V t1 = A::Load(target[1]);
      const V t2 = A::Load(target[2]);
      const V sum = ar.Add(ar.Add(ar.Mul(t0, t0), ar.Mul(t1, t1)), ar.Mul(t2, t2));
      const V scale = ar.Sqrt(ar.Div(sum, A::Operand(sourceLengthSq)));
      const V d0 = ar.Mul(A::Load(source[0]), scale);
      const V d1 = ar.Mul(scale, A::Operand(source[1]));
      const V d2 = ar.Mul(scale, A::Operand(source[2]));
      if (!ar.Valid()) {
        return false;
      }
      dest[0] = A::Store(d0);
      dest[1] = A::Store(d1);
      dest[2] = A::Store(d2);
      return true;
    }

    template <class A>
    [[nodiscard]] float BoxRadiusOnAxisT(
      const float* const box,
      const float* const axis
    ) noexcept
    {
      using V = typename A::Value;
      A ar;
      // box: center 0x00, axis0 0x0C, axis1 0x18, axis2 0x24, extents 0x30 (float lanes 0..14).
      const V a0 = A::Load(axis[0]);
      const V a1 = A::Load(axis[1]);
      const V a2 = A::Load(axis[2]);
      // Third axis: (B28*a1 + B2C*a2) + B24*a0, |.| * extent2.
      const V p1 = ar.Mul(A::Load(box[10]), a1);
      const V p2 = ar.Mul(A::Load(box[11]), a2);
      const V d2 = ar.Add(ar.Add(p2, p1), ar.Mul(A::Load(box[9]), a0));
      const V r2 = ar.Mul(A::Abs(d2), A::Operand(box[14]));
      // Second axis: (B1C*a1 + B20*a2) + B18*a0, |.| * extent1.
      const V q12 = ar.Add(ar.Mul(A::Load(box[7]), a1), ar.Mul(A::Load(box[8]), a2));
      const V d1 = ar.Add(q12, ar.Mul(A::Load(box[6]), a0));
      const V r1 = ar.Mul(A::Abs(d1), A::Operand(box[13]));
      const V acc = ar.Add(r2, r1);
      // First axis: (a2*B14 + a1*B10) + a0*B0C, |.| * extent0.
      const V u12 = ar.Add(ar.Mul(a2, A::Load(box[5])), ar.Mul(a1, A::Load(box[4])));
      const V d0 = ar.Add(u12, ar.Mul(a0, A::Operand(box[3])));
      const V r0 = ar.Mul(A::Abs(d0), A::Operand(box[12]));
      const V result = ar.Add(acc, r0);
      return ar.Valid() ? A::Store(result) : BoxRadiusOnAxisT<ExactArithmetic>(box, axis);
    }

    template <class A>
    [[nodiscard]] float VectorLengthZYXT(
      const float* const lanes
    ) noexcept
    {
      using V = typename A::Value;
      A ar;
      const V z = A::Load(lanes[2]);
      const V y = A::Load(lanes[1]);
      const V x = A::Load(lanes[0]);
      const V result = ar.Sqrt(ar.Add(ar.Add(ar.Mul(z, z), ar.Mul(y, y)), ar.Mul(x, x)));
      return ar.Valid() ? A::Store(result) : VectorLengthZYXT<ExactArithmetic>(lanes);
    }

    // The routines with transcendental instructions run on the exact model only.

    [[nodiscard]] Ext AcosAsinRadicand(
      const Ext& x
    ) noexcept
    {
      // fld1; fadd st0, st1 -> 1 + x;  fld1; fsub st0, st2 -> 1 - x;  fmulp;  fsqrt
      const Ext onePlus = Add(kFld1, x, P24);
      const Ext oneMinus = Sub(kFld1, x, P24);
      return Sqrt(Mul(onePlus, oneMinus, P24), P24);
    }

    /// The exp/pow tail: n = frndint(t); 2^(t - n) via f2xm1 and 1 + ., scaled by n.
    [[nodiscard]] Ext TwoToThe(
      const Ext& t,
      const bool fromPow
    ) noexcept
    {
      const Ext n = RoundToInteger(t);
      Ext fraction;
      if (fromPow) {
        fraction = Negate(Sub(n, t, P24)); // fsubr st1, st0 (n - t); fxch; fchs
      } else {
        fraction = Sub(t, n, P24); // fsub st0, st1
      }
      const Ext power = Add(F2xm1(fraction), kFld1, P24); // f2xm1; fld1; faddp
      return Scale(power, n);                             // fscale; fstp st1
    }
  } // namespace

  // --- The routines ------------------------------------------------------------------------------

  namespace
  {
    /**
     * Ziv's fast path for fsin/fcos stored to a float. The double kernels below are within 2^-50 of
     * the function relative to it (Taylor terms far past 2^-60, a few rounding errors of 2^-53), and
     * the hardware's 64-bit result within 2^-63: when the double lies farther than 2^-46 of itself
     * from every point halfway between two floats, both round to the same float. Otherwise (about
     * one call in 2^22) the exact model decides. Denormal results always take the exact model.
     */
    [[nodiscard]] bool FloatIfFarFromTie(
      const double v,
      float& out
    ) noexcept
    {
      const double magnitude = std::fabs(v);
      if (!(magnitude >= 0x1p-126 && magnitude < 0x1p127)) {
        return false;
      }
      const float f = static_cast<float>(v);
      const double tolerance = magnitude * 0x1p-46;
      const double above = (static_cast<double>(f) + static_cast<double>(std::nextafter(f, HUGE_VALF))) * 0.5;
      const double below = (static_cast<double>(f) + static_cast<double>(std::nextafter(f, -HUGE_VALF))) * 0.5;
      if (std::fabs(v - above) <= tolerance || std::fabs(v - below) <= tolerance) {
        return false;
      }
      out = f;
      return true;
    }

    /// sin and cos of hi + lo (|hi| <= pi/4, |lo| <= 2^-53 |hi|) in double, Taylor to r^19 / r^18.
    [[nodiscard]] double FastSin(
      const double hi,
      const double lo
    ) noexcept
    {
      const double r2 = hi * hi;
      const double tail = -1.0 / 6 +
        r2 *
          (1.0 / 120 +
           r2 *
             (-1.0 / 5040 +
              r2 *
                (1.0 / 362880 +
                 r2 *
                   (-1.0 / 39916800 +
                    r2 *
                      (1.0 / 6227020800.0 +
                       r2 *
                         (-1.0 / 1307674368000.0 +
                          r2 * (1.0 / 355687428096000.0 + r2 * (-1.0 / 121645100408832000.0))))))));
      return hi + (hi * r2 * tail + lo * (1.0 - 0.5 * r2));
    }

    [[nodiscard]] double FastCos(
      const double hi,
      const double lo
    ) noexcept
    {
      const double r2 = hi * hi;
      const double tail = 1.0 / 24 +
        r2 *
          (-1.0 / 720 +
           r2 *
             (1.0 / 40320 +
              r2 *
                (-1.0 / 3628800 +
                 r2 *
                   (1.0 / 479001600 +
                    r2 *
                      (-1.0 / 87178291200.0 +
                       r2 *
                         (1.0 / 20922789888000.0 +
                          r2 * (-1.0 / 6402373705728000.0 + r2 * (1.0 / 2432902008176640000.0))))))));
      return 1.0 + (-0.5 * r2 + (r2 * r2 * tail - hi * lo));
    }

    /// fsin (or fcos) of a float, stored to a float, through the fast path when it decides.
    [[nodiscard]] bool FastTrig(
      const float x,
      const bool cosine,
      float& out
    ) noexcept
    {
      if (!(std::fabs(x) < 0x1p63f) || x == 0.0f) {
        return false;
      }
      const Reduced reduced = Reduce(Load(x));
      const bool swap = (reduced.quadrant & 1) != 0;
      const bool useCos = cosine != swap;
      double v = useCos ? FastCos(reduced.r.hi, reduced.r.lo) : FastSin(reduced.r.hi, reduced.r.lo);
      const bool negate = cosine ? (reduced.quadrant == 1 || reduced.quadrant == 2) : (reduced.quadrant & 2) != 0;
      if (negate) {
        v = -v;
      }
      return FloatIfFarFromTie(v, out);
    }
  } // namespace

  float Sinf(
    const float x
  ) noexcept
  {
    float fast;
    if (FastTrig(x, false, fast)) {
      return fast;
    }
    return StoreFloat(Fsin(Load(x)));
  }

  float Cosf(
    const float x
  ) noexcept
  {
    float fast;
    if (FastTrig(x, true, fast)) {
      return fast;
    }
    return StoreFloat(Fcos(Load(x)));
  }

  float Tanf(
    const float x
  ) noexcept
  {
    Ext tangent;
    if (!Fptan(Load(x), tangent)) {
      // Out of range: nothing pushed, so `fstp st(0)` pops x and the `fstp m32` stores from an
      // empty register - the stack underflow's masked response, the indefinite.
      return StoreFloat(Indefinite());
    }
    return StoreFloat(tangent);
  }

  float Atan2f(
    const float y,
    const float x
  ) noexcept
  {
    return StoreFloat(Fpatan(Load(y), Load(x)));
  }

  double Acos(
    const double x
  ) noexcept
  {
    const Ext value = Load(x);
    return StoreDouble(Fpatan(AcosAsinRadicand(value), value)); // fxch: atan(s / x)
  }

  double Asin(
    const double x
  ) noexcept
  {
    const Ext value = Load(x);
    return StoreDouble(Fpatan(value, AcosAsinRadicand(value))); // atan(x / s)
  }

  double Pow(
    const double x,
    const double y
  ) noexcept
  {
    const Ext t = Fyl2x(Load(y), Load(x)); // fld y; fld x; fyl2x
    return StoreDouble(TwoToThe(t, true));
  }

  unsigned int ControlWord() noexcept
  {
    // A Windows x64 thread's control word: 53-bit precision, round to nearest, exceptions masked.
    return 0x027Fu;
  }

  float Atan2Difference(
    const float firstY,
    const float firstX,
    const float secondY,
    const float secondX
  ) noexcept
  {
    const float first = StoreFloat(Fpatan(Load(firstY), Load(firstX))); // fstp m32
    const Ext second = Fpatan(Load(secondY), Load(secondX));
    return StoreFloat(Sub(Operand(first), second, P24)); // fsubr m32: first - second
  }

  float Atan2Plus(
    const float y,
    const float x,
    const float addend
  ) noexcept
  {
    return StoreFloat(Add(Fpatan(Load(y), Load(x)), Operand(addend), P24)); // fadd m32
  }

  float SinTimesCos(
    const float sinArg,
    const float cosArg
  ) noexcept
  {
    const Ext c = Fcos(Load(cosArg));
    const Ext s = Fsin(Load(sinArg));
    return StoreFloat(Mul(c, s, P24));
  }

  float SinOfProductTimes(
    const float a,
    const float b,
    const float factor
  ) noexcept
  {
    const Ext product = Mul(Load(a), Operand(b), P24);           // fmul m32
    return StoreFloat(Mul(Fsin(product), Operand(factor), P24)); // fmul m32
  }

  float TwisterWordInRange(
    const float lower,
    const float upper,
    const std::uint32_t word
  ) noexcept
  {
    return TwisterWordInRangeT<FastArithmetic>(lower, upper, word);
  }

  void SlerpSphericalBlend(
    float* const outLanes,
    const float* const q1Lanes,
    const float* const rhsLanes,
    const float angle,
    const float oneMinusT,
    const float t
  ) noexcept
  {
    const Ext a = Load(angle);
    const Ext inverseSine = Div(kFld1, Fsin(a), P24);                            // fld1; fdivrp
    const Ext w1 = Mul(Fsin(Mul(a, Operand(oneMinusT), P24)), inverseSine, P24); // sin(A(1-t)) * inv
    const Ext w2 = Mul(inverseSine, Fsin(Mul(a, Load(t), P24)), P24);            // inv * sin(At)
    for (int lane = 0; lane < 3; ++lane) {
      const Ext q = Mul(Load(q1Lanes[lane]), w1, P24);
      const Ext r = Mul(Load(rhsLanes[lane]), w2, P24);
      outLanes[lane] = StoreFloat(Add(q, r, P24));
    }
    const Ext q = Mul(w1, Load(q1Lanes[3]), P24);     // fmulp st2, st0
    const Ext r = Mul(w2, Operand(rhsLanes[3]), P24); // fmul m32
    outLanes[3] = StoreFloat(Add(q, r, P24));
  }

  float IntrinsicExp(
    const float x
  ) noexcept
  {
    const Ext t = Mul(Load(x), kFldL2e, P24); // fldl2e; fmulp
    return StoreFloat(TwoToThe(t, false));
  }

  float IntrinsicLn(
    const float x
  ) noexcept
  {
    return StoreFloat(Fyl2x(kFldLn2, Load(x)));
  }

  float IntrinsicLog10(
    const float x
  ) noexcept
  {
    return StoreFloat(Fyl2x(kFldLg2, Load(x)));
  }

  float IntrinsicLnQuotient(
    const float x,
    const double base
  ) noexcept
  {
    const Ext numerator = Fyl2x(kFldLn2, Load(x));
    const Ext denominator = Fyl2x(kFldLn2, Load(base));
    return StoreFloat(Div(numerator, denominator, P24)); // fdivp st1, st0
  }

  float ScaledLnQuotient(
    const float numerator,
    const float denominator,
    const float scale
  ) noexcept
  {
    const Ext quotient = Div(Load(numerator), Operand(denominator), P24);  // fdiv m32
    return StoreFloat(Mul(Fyl2x(kFldLn2, quotient), Operand(scale), P24)); // fmul m32
  }

  float CosTimesCos(
    const float firstArg,
    const float secondArg
  ) noexcept
  {
    const Ext second = Fcos(Load(secondArg));
    const Ext first = Fcos(Load(firstArg));
    return StoreFloat(Mul(second, first, P24));
  }

  float BilinearHeight(
    const float h00,
    const float h01,
    const float h10,
    const float h11,
    const float fracX,
    const float fracZ
  ) noexcept
  {
    return BilinearT<FastArithmetic>(h00, h01, h10, h11, fracX, fracZ);
  }

  float SubtractBilinearHeight(
    const float top,
    const float h00,
    const float h01,
    const float h10,
    const float h11,
    const float fracX,
    const float fracZ
  ) noexcept
  {
    return SubtractBilinearT<FastArithmetic>(top, h00, h01, h10, h11, fracX, fracZ);
  }

  std::int32_t RoundToInt(
    const float value
  ) noexcept
  {
    // fld; fistp: nearest-even, the integer indefinite outside int32 (and for NaN).
    const float nearest = std::nearbyint(value);
    if (!(nearest >= -0x1p31f && nearest < 0x1p31f)) {
      return static_cast<std::int32_t>(0x80000000u);
    }
    return static_cast<std::int32_t>(nearest);
  }

  void ScaleVectorMaxLength(
    float* const x,
    float* const y,
    float* const z,
    const float maxLength,
    const float lengthSq
  ) noexcept
  {
    if (!ScaleVectorMaxLengthT<FastArithmetic>(x, y, z, maxLength, lengthSq)) {
      (void)ScaleVectorMaxLengthT<ExactArithmetic>(x, y, z, maxLength, lengthSq);
    }
  }

  void ScaleVectorToLength(
    float* const destLanes,
    const float* const sourceLanes,
    const float lengthSq,
    const float length
  ) noexcept
  {
    if (!ScaleVectorToLengthT<FastArithmetic>(destLanes, sourceLanes, lengthSq, length)) {
      (void)ScaleVectorToLengthT<ExactArithmetic>(destLanes, sourceLanes, lengthSq, length);
    }
  }

  void ScaleVector(
    float* const destLanes,
    const float* const sourceLanes,
    const float scale
  ) noexcept
  {
    if (!ScaleVectorT<FastArithmetic>(destLanes, sourceLanes, scale)) {
      (void)ScaleVectorT<ExactArithmetic>(destLanes, sourceLanes, scale);
    }
  }

  float BoxRadiusOnAxis(
    const float* const boxLanes,
    const float* const axisLanes
  ) noexcept
  {
    return BoxRadiusOnAxisT<FastArithmetic>(boxLanes, axisLanes);
  }

  void ScaleVectorToLengthOf(
    float* const destLanes,
    const float* const sourceLanes,
    const float* const targetLanes,
    const float sourceLengthSq
  ) noexcept
  {
    if (!ScaleVectorToLengthOfT<FastArithmetic>(destLanes, sourceLanes, targetLanes, sourceLengthSq)) {
      (void)ScaleVectorToLengthOfT<ExactArithmetic>(destLanes, sourceLanes, targetLanes, sourceLengthSq);
    }
  }

  float VectorLengthZYX(
    const float* const lanes
  ) noexcept
  {
    return VectorLengthZYXT<FastArithmetic>(lanes);
  }

  namespace testing
  {
    float SinfExact(
      const float x
    ) noexcept
    {
      return StoreFloat(Fsin(Load(x)));
    }

    float CosfExact(
      const float x
    ) noexcept
    {
      return StoreFloat(Fcos(Load(x)));
    }

    float BilinearHeightExact(
      const float h00,
      const float h01,
      const float h10,
      const float h11,
      const float fracX,
      const float fracZ
    ) noexcept
    {
      return BilinearT<ExactArithmetic>(h00, h01, h10, h11, fracX, fracZ);
    }

    float BoxRadiusOnAxisExact(
      const float* const boxLanes,
      const float* const axisLanes
    ) noexcept
    {
      return BoxRadiusOnAxisT<ExactArithmetic>(boxLanes, axisLanes);
    }

    float VectorLengthZYXExact(
      const float* const lanes
    ) noexcept
    {
      return VectorLengthZYXT<ExactArithmetic>(lanes);
    }

    void ScaleVectorToLengthOfExact(
      float* const destLanes,
      const float* const sourceLanes,
      const float* const targetLanes,
      const float sourceLengthSq
    ) noexcept
    {
      (void)ScaleVectorToLengthOfT<ExactArithmetic>(destLanes, sourceLanes, targetLanes, sourceLengthSq);
    }

    float TwisterWordInRangeExact(
      const float lower,
      const float upper,
      const std::uint32_t word
    ) noexcept
    {
      return TwisterWordInRangeT<ExactArithmetic>(lower, upper, word);
    }
  } // namespace testing
} // namespace fa::x87

#if FAF_SOFT_X87
// The routines' C names, for legacy/math/X87Math.cpp (legacy/math/X87Routines.h).
extern "C" float __cdecl msvc8_x87_sinf(
  const float x
)
{
  return fa::x87::Sinf(x);
}
extern "C" float __cdecl msvc8_x87_cosf(
  const float x
)
{
  return fa::x87::Cosf(x);
}
extern "C" float __cdecl msvc8_x87_tanf(
  const float x
)
{
  return fa::x87::Tanf(x);
}
extern "C" float __cdecl msvc8_x87_atan2f(
  const float y,
  const float x
)
{
  return fa::x87::Atan2f(y, x);
}
extern "C" double __cdecl msvc8_x87_acos(
  const double x
)
{
  return fa::x87::Acos(x);
}
extern "C" double __cdecl msvc8_x87_asin(
  const double x
)
{
  return fa::x87::Asin(x);
}
extern "C" double __cdecl msvc8_x87_pow(
  const double x,
  const double y
)
{
  return fa::x87::Pow(x, y);
}
extern "C" unsigned int __cdecl msvc8_x87_control_word()
{
  return fa::x87::ControlWord();
}
extern "C" float __cdecl msvc8_x87_atan2_difference(
  const float firstY,
  const float firstX,
  const float secondY,
  const float secondX
)
{
  return fa::x87::Atan2Difference(firstY, firstX, secondY, secondX);
}
extern "C" float __cdecl msvc8_x87_atan2_plus(
  const float y,
  const float x,
  const float addend
)
{
  return fa::x87::Atan2Plus(y, x, addend);
}
extern "C" float __cdecl msvc8_x87_sin_times_cos(
  const float sinArg,
  const float cosArg
)
{
  return fa::x87::SinTimesCos(sinArg, cosArg);
}
extern "C" float __cdecl msvc8_x87_sin_of_product_times(
  const float a,
  const float b,
  const float factor
)
{
  return fa::x87::SinOfProductTimes(a, b, factor);
}
extern "C" float __cdecl msvc8_x87_twister_word_in_range(
  const float lower,
  const float upper,
  const std::uint32_t word
)
{
  return fa::x87::TwisterWordInRange(lower, upper, word);
}
extern "C" void __cdecl msvc8_x87_slerp_spherical_blend(
  float* const outLanes,
  const float* const q1Lanes,
  const float* const rhsLanes,
  const float angle,
  const float oneMinusT,
  const float t
)
{
  fa::x87::SlerpSphericalBlend(outLanes, q1Lanes, rhsLanes, angle, oneMinusT, t);
}
extern "C" float __cdecl msvc8_x87_intrinsic_exp(
  const float x
)
{
  return fa::x87::IntrinsicExp(x);
}
extern "C" float __cdecl msvc8_x87_intrinsic_ln(
  const float x
)
{
  return fa::x87::IntrinsicLn(x);
}
extern "C" float __cdecl msvc8_x87_intrinsic_log10(
  const float x
)
{
  return fa::x87::IntrinsicLog10(x);
}
extern "C" float __cdecl msvc8_x87_intrinsic_ln_quotient(
  const float x,
  const double base
)
{
  return fa::x87::IntrinsicLnQuotient(x, base);
}
extern "C" float __cdecl msvc8_x87_scaled_ln_quotient(
  const float numerator,
  const float denominator,
  const float scale
)
{
  return fa::x87::ScaledLnQuotient(numerator, denominator, scale);
}
extern "C" float __cdecl msvc8_x87_cos_times_cos(
  const float firstArg,
  const float secondArg
)
{
  return fa::x87::CosTimesCos(firstArg, secondArg);
}
extern "C" float __cdecl msvc8_x87_bilinear_height(
  const float h00,
  const float h01,
  const float h10,
  const float h11,
  const float fracX,
  const float fracZ
)
{
  return fa::x87::BilinearHeight(h00, h01, h10, h11, fracX, fracZ);
}
extern "C" float __cdecl msvc8_x87_subtract_bilinear_height(
  const float top,
  const float h00,
  const float h01,
  const float h10,
  const float h11,
  const float fracX,
  const float fracZ
)
{
  return fa::x87::SubtractBilinearHeight(top, h00, h01, h10, h11, fracX, fracZ);
}
extern "C" std::int32_t __cdecl msvc8_x87_round_to_int(
  const float value
)
{
  return fa::x87::RoundToInt(value);
}
extern "C" void __cdecl msvc8_x87_scale_vector_max_length(
  float* const x,
  float* const y,
  float* const z,
  const float maxLength,
  const float lengthSq
)
{
  fa::x87::ScaleVectorMaxLength(x, y, z, maxLength, lengthSq);
}
extern "C" void __cdecl msvc8_x87_scale_vector_to_length(
  float* const destLanes,
  const float* const sourceLanes,
  const float lengthSq,
  const float length
)
{
  fa::x87::ScaleVectorToLength(destLanes, sourceLanes, lengthSq, length);
}
extern "C" void __cdecl msvc8_x87_scale_vector(
  float* const destLanes,
  const float* const sourceLanes,
  const float scale
)
{
  fa::x87::ScaleVector(destLanes, sourceLanes, scale);
}
extern "C" float __cdecl msvc8_x87_box_radius_on_axis(
  const float* const boxLanes,
  const float* const axisLanes
)
{
  return fa::x87::BoxRadiusOnAxis(boxLanes, axisLanes);
}
extern "C" void __cdecl msvc8_x87_scale_vector_to_length_of(
  float* const destLanes,
  const float* const sourceLanes,
  const float* const targetLanes,
  const float sourceLengthSq
)
{
  fa::x87::ScaleVectorToLengthOf(destLanes, sourceLanes, targetLanes, sourceLengthSq);
}
extern "C" float __cdecl msvc8_x87_vector_length_zyx(
  const float* const lanes
)
{
  return fa::x87::VectorLengthZYX(lanes);
}
#endif
