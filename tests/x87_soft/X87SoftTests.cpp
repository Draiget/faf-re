// Engine addition (#262): the software x87 (legacy/math/X87Soft.cpp) on any target. The x87 unit
// itself is the reference in tools/x87-oracle/X87Oracle.cpp (x86-64); these check what needs none:
// the double fast path equals the exact model wherever it is taken, the x87's special values,
// and results the x87 is known to give.

#include "legacy/math/X87Soft.h"

#include <gtest/gtest.h>

#include <bit>
#include <cmath>
#include <cstdint>
#include <limits>

namespace
{
  std::uint32_t Bits(
    const float v
  )
  {
    return std::bit_cast<std::uint32_t>(v);
  }
  std::uint64_t Bits(
    const double v
  )
  {
    return std::bit_cast<std::uint64_t>(v);
  }
  float FromBits(
    const std::uint32_t b
  )
  {
    return std::bit_cast<float>(b);
  }

  /// Random floats: any bit pattern, or values in the game's ranges, or near powers of two.
  class Inputs
  {
  public:
    float Next()
    {
      std::uint64_t z = (mState += 0x9E3779B97F4A7C15ull);
      z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
      z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
      z ^= z >> 31;
      switch (z & 3) {
      case 0:
        return FromBits(static_cast<std::uint32_t>(z >> 32));
      case 1:
        return (static_cast<float>(z >> 40) * 0x1p-24f - 0.5f) * 2048.0f;
      case 2:
        return (static_cast<float>(z >> 40) * 0x1p-24f - 0.5f) * 4.0f;
      default: {
        const auto base = Bits(std::ldexp(1.0f, static_cast<int>((z >> 8) % 80) - 40));
        return FromBits(base + static_cast<std::uint32_t>(static_cast<std::int32_t>((z >> 40) & 7) - 4));
      }
      }
    }

  private:
    std::uint64_t mState = 12345;
  };

  constexpr std::uint32_t kIndefinite = 0xFFC00000u;
} // namespace

// The double fast path rounds to odd and then to 24 bits; it must equal the exact model.
TEST(
  X87Soft,
  FastPathMatchesExactModel
)
{
  Inputs in;
  for (int i = 0; i < 2'000'000; ++i) {
    const float h[6] = {in.Next(), in.Next(), in.Next(), in.Next(), in.Next(), in.Next()};
    ASSERT_EQ(
      Bits(fa::x87::BilinearHeight(h[0], h[1], h[2], h[3], h[4], h[5])),
      Bits(fa::x87::testing::BilinearHeightExact(h[0], h[1], h[2], h[3], h[4], h[5]))
    ) << std::hex
      << Bits(h[0]) << " " << Bits(h[1]) << " " << Bits(h[2]) << " " << Bits(h[3]) << " " << Bits(h[4]) << " "
      << Bits(h[5]);

    const float lanes[3] = {h[0], h[1], h[2]};
    ASSERT_EQ(Bits(fa::x87::VectorLengthZYX(lanes)), Bits(fa::x87::testing::VectorLengthZYXExact(lanes)))
      << std::hex << Bits(h[0]) << " " << Bits(h[1]) << " " << Bits(h[2]);

    float box[15];
    for (float& lane : box) {
      lane = in.Next();
    }
    ASSERT_EQ(Bits(fa::x87::BoxRadiusOnAxis(box, lanes)), Bits(fa::x87::testing::BoxRadiusOnAxisExact(box, lanes)));

    const float target[3] = {h[3], h[4], h[5]};
    float fast[3];
    float exact[3];
    const float lengthSq = in.Next();
    fa::x87::ScaleVectorToLengthOf(fast, lanes, target, lengthSq);
    fa::x87::testing::ScaleVectorToLengthOfExact(exact, lanes, target, lengthSq);
    for (int lane = 0; lane < 3; ++lane) {
      ASSERT_EQ(Bits(fast[lane]), Bits(exact[lane]));
    }

    const auto word = static_cast<std::uint32_t>(Bits(h[3]) * 2654435761u);
    ASSERT_EQ(
      Bits(fa::x87::TwisterWordInRange(h[0], h[1], word)),
      Bits(fa::x87::testing::TwisterWordInRangeExact(h[0], h[1], word))
    );
  }
}

// sinf/cosf's double fast path must give the exact model's float whenever it answers.
TEST(
  X87Soft,
  TrigFastPathMatchesExactModel
)
{
  Inputs in;
  for (int i = 0; i < 4'000'000; ++i) {
    const float x = in.Next();
    ASSERT_EQ(Bits(fa::x87::Sinf(x)), Bits(fa::x87::testing::SinfExact(x))) << std::hex << Bits(x);
    ASSERT_EQ(Bits(fa::x87::Cosf(x)), Bits(fa::x87::testing::CosfExact(x))) << std::hex << Bits(x);
  }
}

// fistp: nearest-even, the integer indefinite outside int32 and for NaN.
TEST(
  X87Soft,
  RoundToInt
)
{
  EXPECT_EQ(fa::x87::RoundToInt(2.5f), 2);
  EXPECT_EQ(fa::x87::RoundToInt(3.5f), 4);
  EXPECT_EQ(fa::x87::RoundToInt(-2.5f), -2);
  EXPECT_EQ(fa::x87::RoundToInt(2147483520.0f), 2147483520);
  EXPECT_EQ(fa::x87::RoundToInt(2147483648.0f), static_cast<std::int32_t>(0x80000000u));
  EXPECT_EQ(fa::x87::RoundToInt(-2147483648.0f), static_cast<std::int32_t>(0x80000000u));
  EXPECT_EQ(fa::x87::RoundToInt(std::numeric_limits<float>::quiet_NaN()), static_cast<std::int32_t>(0x80000000u));
}

// The trigonometric instructions' special operands and range.
TEST(
  X87Soft,
  TrigonometrySpecialValues
)
{
  EXPECT_EQ(Bits(fa::x87::Sinf(0.0f)), 0u);
  EXPECT_EQ(Bits(fa::x87::Sinf(-0.0f)), 0x80000000u);
  EXPECT_EQ(fa::x87::Cosf(0.0f), 1.0f);
  EXPECT_EQ(Bits(fa::x87::Sinf(std::numeric_limits<float>::infinity())), kIndefinite);
  // |x| >= 2^63: out of range, the operand comes back unchanged (fsin), the indefinite (fptan).
  EXPECT_EQ(fa::x87::Sinf(0x1p63f), 0x1p63f);
  EXPECT_EQ(fa::x87::Cosf(-0x1p70f), -0x1p70f);
  EXPECT_EQ(Bits(fa::x87::Tanf(0x1p63f)), kIndefinite);
  // Exact in float.
  EXPECT_EQ(fa::x87::Sinf(0x1p-30f), 0x1p-30f);
  EXPECT_EQ(fa::x87::Cosf(0x1p-30f), 1.0f);
}

// fpatan's table (no invalid case) and its ordinary values.
TEST(
  X87Soft,
  Atan2SpecialValues
)
{
  constexpr float kInf = std::numeric_limits<float>::infinity();
  EXPECT_EQ(Bits(fa::x87::Atan2f(0.0f, 1.0f)), 0u);
  EXPECT_EQ(Bits(fa::x87::Atan2f(-0.0f, 1.0f)), 0x80000000u);
  EXPECT_EQ(fa::x87::Atan2f(0.0f, -0.0f), static_cast<float>(M_PI));
  EXPECT_EQ(fa::x87::Atan2f(1.0f, 0.0f), static_cast<float>(M_PI_2));
  EXPECT_EQ(fa::x87::Atan2f(kInf, kInf), static_cast<float>(M_PI_4));
  EXPECT_EQ(fa::x87::Atan2f(-kInf, -kInf), static_cast<float>(-3.0 * M_PI_4));
  EXPECT_EQ(fa::x87::Atan2f(1.0f, 1.0f), static_cast<float>(M_PI_4));
  EXPECT_EQ(fa::x87::Atan2f(1.0f, -1.0f), static_cast<float>(3.0 * M_PI_4));
}

// The logarithm and exponential lanes on exact cases.
TEST(
  X87Soft,
  LogExpExactCases
)
{
  EXPECT_EQ(Bits(fa::x87::IntrinsicLn(1.0f)), 0u);
  EXPECT_EQ(fa::x87::IntrinsicLog10(1.0f), 0.0f);
  EXPECT_EQ(fa::x87::IntrinsicExp(0.0f), 1.0f);
  EXPECT_EQ(Bits(fa::x87::IntrinsicLn(-1.0f)), kIndefinite);
  EXPECT_EQ(fa::x87::IntrinsicLn(0.0f), -std::numeric_limits<float>::infinity());
  EXPECT_EQ(fa::x87::Pow(2.0, 10.0), 1024.0);
  EXPECT_EQ(fa::x87::Pow(3.0, 2.0), 9.0);
  EXPECT_EQ(fa::x87::IntrinsicLog10(100.0f), 2.0f);
}

// Known results of the retail game's x87 code (legacy/math/X87Math.h, tests/sim_math).
TEST(
  X87Soft,
  KnownRetailResults
)
{
  // math.asin(0x3F052EAA) through _CIasin's x87 body at _PC_24.
  EXPECT_EQ(Bits(static_cast<float>(fa::x87::Asin(static_cast<double>(FromBits(0x3F052EAAu))))), 0x3F0C1118u);
  // VectorLengthZYX of a tiny vector keeps the extended exponent until the store.
  const float tiny[3] = {1e-25f, 1e-25f, 1e-25f};
  EXPECT_EQ(Bits(fa::x87::VectorLengthZYX(tiny)), Bits(fa::x87::testing::VectorLengthZYXExact(tiny)));
}

// Every result matches across a sweep of ordinary angles to well within a float's ulp, a check
// of the kernels' arithmetic independent of the hardware.
TEST(
  X87Soft,
  KernelsAgreeWithDoubleMath
)
{
  for (int i = -4000; i <= 4000; ++i) {
    const float x = static_cast<float>(i) * 0.00731f;
    EXPECT_NEAR(fa::x87::Sinf(x), std::sin(static_cast<double>(x)), 1e-6) << x;
    EXPECT_NEAR(fa::x87::Cosf(x), std::cos(static_cast<double>(x)), 1e-6) << x;
    EXPECT_NEAR(fa::x87::Atan2f(x, 1.5f), std::atan2(static_cast<double>(x), 1.5), 1e-6) << x;
    if (x > 0.0f) {
      EXPECT_NEAR(fa::x87::IntrinsicLn(x), std::log(static_cast<double>(x)), 1e-6) << x;
    }
    if (std::fabs(x) < 20.0f) {
      const double e = std::exp(static_cast<double>(x));
      EXPECT_NEAR(fa::x87::IntrinsicExp(x), e, e * 1e-6) << x;
    }
  }
}
