// The math library (luaopen_math 0x0091A110, registration array 0x00D46278). Results are
// single-precision floats; exact comparisons are used where the value is exact in a float, near
// ones for the transcendental functions.

#include <cmath>
#include <string>
#include <gtest/gtest.h>

#include "LuaTestSupport.h"

namespace
{
  using faf_lua_tests::Contains;

  class LuaMathLib : public faf_lua_tests::LuaFixture
  {
  };

  TEST_F(LuaMathLib, RoundingAndSign)
  {
    EXPECT_EQ(Num("return math.floor(3.7)"), 3.0);
    EXPECT_EQ(Num("return math.floor(-3.5)"), -4.0);
    EXPECT_EQ(Num("return math.ceil(3.2)"), 4.0);
    EXPECT_EQ(Num("return math.ceil(-3.5)"), -3.0);
    EXPECT_EQ(Num("return math.abs(-3)"), 3.0);
    EXPECT_EQ(Num("return math.abs(2.5)"), 2.5);
    EXPECT_EQ(Num("return math.mod(7, 3)"), 1.0);
    EXPECT_EQ(Num("return math.mod(-7, 3)"), -1.0); // fmod keeps the dividend's sign
    EXPECT_EQ(Num("return math.mod(7.5, 2)"), 1.5);
    EXPECT_TRUE(Contains(ErrorOf("return math.floor('x')"), "bad argument #1 to `floor' (number expected, got string)"));
  }

  TEST_F(LuaMathLib, MinMax)
  {
    EXPECT_EQ(Num("return math.max(1, 5, 3)"), 5.0);
    EXPECT_EQ(Num("return math.min(4, -2, 8)"), -2.0);
    EXPECT_EQ(Num("return math.max(7)"), 7.0);
    EXPECT_TRUE(Contains(ErrorOf("return math.max()"), "bad argument #1 to `max' (number expected, got no value)"));
    EXPECT_TRUE(Contains(ErrorOf("return math.min(1, {})"), "bad argument #2 to `min'"));
  }

  TEST_F(LuaMathLib, PowersAndLogs)
  {
    EXPECT_EQ(Num("return math.sqrt(16)"), 4.0);
    EXPECT_EQ(Num("return math.pow(2, 10)"), 1024.0);
    EXPECT_EQ(Num("return math.pow(9, 0.5)"), 3.0);
    EXPECT_EQ(Num("return math.exp(0)"), 1.0);
    EXPECT_EQ(Num("return math.log(1)"), 0.0);
    EXPECT_EQ(Num("return math.log10(1000)"), 3.0);
    EXPECT_NEAR(Num("return math.exp(1)"), 2.718281828, 1e-6);
    EXPECT_NEAR(Num("return math.log(10)"), 2.302585093, 1e-6);
    EXPECT_EQ(Num("local m, e = math.frexp(8) return m"), 0.5);
    EXPECT_EQ(Num("local m, e = math.frexp(8) return e"), 4.0);
    EXPECT_EQ(Num("return math.ldexp(0.5, 4)"), 8.0);
    EXPECT_EQ(Num("return math.ldexp(3, -1)"), 1.5);
    EXPECT_TRUE(Bool("local x = math.sqrt(-1) return x ~= x")); // NaN
  }

  TEST_F(LuaMathLib, Trigonometry)
  {
    EXPECT_EQ(Num("return math.pi"), static_cast<double>(3.14159265358979f));
    EXPECT_EQ(Num("return math.sin(0)"), 0.0);
    EXPECT_EQ(Num("return math.cos(0)"), 1.0);
    EXPECT_EQ(Num("return math.tan(0)"), 0.0);
    EXPECT_NEAR(Num("return math.sin(math.pi / 2)"), 1.0, 1e-6);
    EXPECT_NEAR(Num("return math.cos(math.pi)"), -1.0, 1e-6);
    EXPECT_NEAR(Num("return math.asin(1)"), 1.5707963, 1e-6);
    EXPECT_NEAR(Num("return math.acos(0)"), 1.5707963, 1e-6);
    EXPECT_NEAR(Num("return math.atan(1)"), 0.7853982, 1e-6);
    EXPECT_NEAR(Num("return math.atan2(1, -1)"), 2.3561945, 1e-6);
    EXPECT_NEAR(Num("return math.atan2(-1, 0)"), -1.5707963, 1e-6);
    EXPECT_NEAR(Num("return math.deg(math.pi)"), 180.0, 1e-4);
    EXPECT_NEAR(Num("return math.rad(180)"), 3.1415927, 1e-6);
    EXPECT_EQ(Num("return math.deg(0)"), 0.0);
  }

  // math_random (0x00919F90): no argument gives [0,1), one gives an integer in [1,u], two give
  // [l,u]; one sample is drawn per call whatever the form, and randomseed restarts the sequence.
  TEST_F(LuaMathLib, RandomRangesAndSeeding)
  {
    EXPECT_TRUE(Bool(R"(
      math.randomseed(1234)
      for i = 1, 2000 do
        local r = math.random()
        if r < 0 or r >= 1 then return false end
        local a = math.random(10)
        if a < 1 or a > 10 or math.floor(a) ~= a then return false end
        local b = math.random(-3, 3)
        if b < -3 or b > 3 or math.floor(b) ~= b then return false end
      end
      return true)"));
    EXPECT_TRUE(Bool("local seen = {} math.randomseed(7) for i = 1, 500 do seen[math.random(4)] = true end return seen[1] and seen[2] and seen[3] and seen[4]"));
    EXPECT_TRUE(Bool(R"(
      math.randomseed(42)
      local a = {math.random(1000), math.random(), math.random(5, 9)}
      math.randomseed(42)
      local b = {math.random(1000), math.random(), math.random(5, 9)}
      return a[1] == b[1] and a[2] == b[2] and a[3] == b[3])"));
    EXPECT_EQ(Num("return math.random(5, 5)"), 5.0);
    EXPECT_TRUE(Contains(ErrorOf("return math.random(0)"), "interval is empty"));
    EXPECT_TRUE(Contains(ErrorOf("return math.random(3, 1)"), "interval is empty"));
    EXPECT_TRUE(Contains(ErrorOf("return math.random(1, 2, 3)"), "wrong number of arguments"));
  }

  // luaopen_math puts __pow into the globals, not into math; nothing in the VM calls it here
  // (`^` is xor, see LuaLanguage.BitOperatorsTruncateToThirtyTwoBits), but scripts can.
  TEST_F(LuaMathLib, GlobalPowIsMathPow)
  {
    EXPECT_EQ(Str("return type(__pow)"), "cfunction");
    EXPECT_EQ(Num("return __pow(3, 2)"), 9.0);
    EXPECT_TRUE(Run("return math.__pow").IsNil());
  }
} // namespace
