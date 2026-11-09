// The language as the game's scripts see it, run through the engine's parser and VM: numbers and
// their text, arithmetic, the fork's bit operators, concatenation, comparison, logic, tables,
// closures, varargs, multiple results, control flow, errors through pcall, tail calls and the depth
// limits. Expected values come from the Lua 5.0 reference manual; where the fork differs the test
// says so and cites the retail instructions.

#include <cmath>
#include <string>
#include <gtest/gtest.h>

#include "LuaTestSupport.h"

namespace
{
  using faf_lua_tests::Contains;

  class LuaLanguage : public faf_lua_tests::LuaFixture
  {
  };

  // ---------------------------------------------------------------------------------------------
  // Numbers

  // lua_Number is a 4-byte float in this fork (TObject is 8 bytes; luaV_tostring 0x009291A0 loads
  // the value with `fld dword ptr`), so a literal is rounded to single precision.
  TEST_F(LuaLanguage, NumbersAreSinglePrecision)
  {
    EXPECT_EQ(Num("return 0.1"), static_cast<double>(0.1f));
    EXPECT_EQ(Num("return 16777217"), 16777216.0);
    EXPECT_TRUE(Bool("return 16777216 + 1 == 16777216"));
    EXPECT_EQ(Num("return 1e10"), 1e10);
    EXPECT_EQ(Num("return .5"), 0.5);
    EXPECT_EQ(Num("return 5e-1"), 0.5);
    EXPECT_EQ(Num("return 2E+2"), 200.0);
  }

  // tostring is sprintf("%.14g") of the float widened to double (luaV_tostring, 0x009291A0).
  TEST_F(LuaLanguage, NumberTextIsFourteenDigitsOfTheFloat)
  {
    EXPECT_EQ(Str("return tostring(10)"), "10");
    EXPECT_EQ(Str("return tostring(-0.5)"), "-0.5");
    EXPECT_EQ(Str("return tostring(0.1)"), "0.10000000149012");
    EXPECT_EQ(Str("return tostring(1/3)"), "0.33333334326744");
    EXPECT_EQ(Str("return tostring(123456789)"), "123456792");
    EXPECT_EQ(Str("return tostring(1e10)"), "10000000000");
    EXPECT_EQ(Str("return tostring(0.001)"), "0.0010000000474975");
    EXPECT_EQ(Str("return tostring(0.25)"), "0.25");
  }

  TEST_F(LuaLanguage, ArithmeticAndPrecedence)
  {
    EXPECT_EQ(Num("return 7 - 2 * 3"), 1.0);
    EXPECT_EQ(Num("return (7 - 2) * 3"), 15.0);
    EXPECT_EQ(Num("return 7 / 2"), 3.5);
    EXPECT_EQ(Num("return -(-3)"), 3.0);
    EXPECT_EQ(Num("return - 2 * - 3"), 6.0);
    EXPECT_EQ(Num("return 10 - 4 - 3"), 3.0); // left associative
    EXPECT_EQ(Num("return 12 / 2 / 3"), 2.0);
    EXPECT_EQ(Num("local a, b = 3, 4 return a * a + b * b"), 25.0);
    EXPECT_TRUE(Bool("return 1/0 > 1e30 and -1/0 < -1e30"));
    EXPECT_TRUE(Bool("local nan = 0/0 return nan ~= nan"));
  }

  // Unary minus still converts a numeric string (luaV_execute 0x00929C60 calls luaO_str2d,
  // 0x0091A5D0, for it), as stock 5.0 does.
  TEST_F(LuaLanguage, UnaryMinusConvertsNumericStrings)
  {
    EXPECT_EQ(Num("return -'2'"), -2.0);
    EXPECT_EQ(Num("return -' 2.5 '"), -2.5);
    EXPECT_TRUE(Contains(ErrorOf("return -'abc'"), "perform arithmetic on"));
  }

  // Suspected bug: numeric strings are read with the current C runtime's strtod, which takes hex
  // and inf/nan spellings. Retail luaO_str2d (0x0091A5D0) calls the MSVC8 CRT's strtod
  // (0x00A8E474 -> 0x00A8E359 -> __strgtold12-like scanner 0x00A98C3E), whose scanner compares
  // only '+', '-', 'E' and 'e' (0x00A98D4C..0x00A98D6C) - no 'x' or 'i'/'n' - so in retail
  // tonumber('0x10'), tonumber('inf') and tonumber('nan') are nil and -'0x10' is an error. Here
  // they are 16, inf and a NaN. Disabled until the parse follows the retail CRT.
  TEST_F(LuaLanguage, DISABLED_NumericStringsReadLikeTheRetailCrt)
  {
    EXPECT_TRUE(Run("return tonumber('0x10')").IsNil());
    EXPECT_TRUE(Run("return tonumber('inf')").IsNil());
    EXPECT_TRUE(Run("return tonumber('nan')").IsNil());
    EXPECT_TRUE(Contains(ErrorOf("return -'0x10'"), "perform arithmetic on"));
  }

  // Fork: the binary operators do not convert strings. Stock 5.0's Arith calls luaV_tonumber
  // (0x00929150 here); retail luaV_execute (0x00929C60) never calls it - its arithmetic fallback is
  // luaT_gettmbyobj / callTMres / luaG_aritherror only.
  TEST_F(LuaLanguage, BinaryArithmeticDoesNotConvertStrings)
  {
    EXPECT_TRUE(Contains(ErrorOf("return '10' + 1"), "perform arithmetic on"));
    EXPECT_TRUE(Contains(ErrorOf("return 2 * '3'"), "perform arithmetic on"));
    EXPECT_TRUE(Contains(ErrorOf("return {} - 1"), "perform arithmetic on"));
    EXPECT_TRUE(Contains(ErrorOf("local x return x / 2"), "attempt to perform arithmetic on local `x' (a nil value)"));
  }

  // Fork: a value with no name gets "<operation> expected but got <type>" where stock 5.0 says
  // "attempt to <operation> a <type> value"; a named one keeps the stock wording. Both format
  // strings are in retail luaG_typeerror (0x009133A0): 0x00D459B0 and 0x00D4598C.
  TEST_F(LuaLanguage, TypeErrorWording)
  {
    EXPECT_TRUE(Contains(ErrorOf("return {} .. 'a'"), "concatenate expected but got table"));
    EXPECT_TRUE(Contains(ErrorOf("return ({}) - 1"), "perform arithmetic on expected but got table"));
    EXPECT_TRUE(Contains(ErrorOf("local t = {} return t .. 'a'"), "attempt to concatenate local `t' (a table value)"));
    EXPECT_TRUE(Contains(ErrorOf("gt = {} return gt.missing()"), "attempt to call field `missing' (a nil value)"));
  }

  // Fork: every type has a metatable (lua_open gives each tag its own empty default table), and
  // indexing a value that is not a table falls back to that metatable when it has no __index -
  // luaV_getnotable (0x00929370) calls luaT_getmetatable (0x009284A0) and indexes the result. So
  // reading a field of nil or of a number gives nil instead of an error. Calling nil still fails.
  TEST_F(LuaLanguage, IndexingNonTablesReadsTheirDefaultMetatable)
  {
    EXPECT_TRUE(Run("local x return x.y").IsNil());
    EXPECT_TRUE(Run("local x = 5 return x.y").IsNil());
    EXPECT_TRUE(Run("local x = true return x[1]").IsNil());
    EXPECT_TRUE(Run("gt = {} return gt.a.b.c").IsNil());
    EXPECT_TRUE(Contains(ErrorOf("local x x()"), "attempt to call local `x' (a nil value)"));
  }

  // Fork: values of different types order by type tag instead of raising - luaV_lessthan
  // (0x009296F0) answers `setl` on the two tags (nil 0 < boolean 1 < number 3 < string 4 <
  // table 5) before looking at the values.
  TEST_F(LuaLanguage, MixedTypesOrderByTag)
  {
    EXPECT_TRUE(Bool("return 1 < '2'"));
    EXPECT_TRUE(Bool("return 100 < 'a'"));
    EXPECT_FALSE(Bool("return '1' < 2"));
    EXPECT_TRUE(Bool("return nil <= 1"));
    EXPECT_TRUE(Bool("return false < 0"));
    EXPECT_FALSE(Bool("return {} < 1"));
    EXPECT_TRUE(Bool("return 'z' < {}"));
    EXPECT_TRUE(Bool("return 'x' >= 5"));
  }

  // Fork: `&`, `|`, `<<`, `>>` and `^` work on the 32-bit truncation of their operands and give the
  // result back unsigned. Retail luaV_execute has one handler per operator - `and edx, eax` at
  // 0x0092A88D, `or` at 0x0092AA11, `shl` at 0x0092AB78, `shr` at 0x0092ACDF, `xor` at 0x0092AE46 -
  // and a negative result gets 2^32 added (`fadd [0xE4F710]`, 0x0092A89F). The parser lowers a
  // binary operator to opcode `OPR + OP_ADD` (codebinop 0x00911380, `add edx, 0Ch`), so `^`
  // (OPR_POW, the fifth after OPR_BAND) lands on the xor handler: `^` is not a power here.
  TEST_F(LuaLanguage, BitOperatorsTruncateToThirtyTwoBits)
  {
    EXPECT_EQ(Num("return 12 & 10"), 8.0);
    EXPECT_EQ(Num("return 12 | 3"), 15.0);
    EXPECT_EQ(Num("return 1 << 10"), 1024.0);
    EXPECT_EQ(Num("return 1024 >> 3"), 128.0);
    EXPECT_EQ(Num("return 6 ^ 3"), 5.0);
    EXPECT_EQ(Num("return 2 ^ 10"), 8.0);
    EXPECT_EQ(Num("return 7.9 & 3.9"), 3.0);
    EXPECT_EQ(Num("return -1 >> 0"), 4294967296.0); // 0xFFFFFFFF as a float rounds up to 2^32
    EXPECT_EQ(Num("return -1 >> 28"), 15.0);
    EXPECT_EQ(Num("return 0xFF00 | 0x00FF"), 65535.0);
    EXPECT_TRUE(Contains(ErrorOf("return 'a' | 1"), "perform arithmetic on"));
  }

  // ---------------------------------------------------------------------------------------------
  // Strings and concatenation

  TEST_F(LuaLanguage, ConcatenationConvertsNumbers)
  {
    EXPECT_EQ(Str("return 1 .. 2"), "12");
    EXPECT_EQ(Str("return 'x' .. 1.5"), "x1.5");
    EXPECT_EQ(Str("return 0.1 .. ''"), "0.10000000149012");
    EXPECT_EQ(Str("return 'a' .. 'b' .. 'c' .. 'd'"), "abcd");
    EXPECT_EQ(Str("return 'a' .. 1 + 2"), "a3"); // + binds tighter than ..
    EXPECT_EQ(Str("local s = '' for i = 1, 5 do s = s .. i end return s"), "12345");
    EXPECT_TRUE(Contains(ErrorOf("return 'a' .. {}"), "concatenate expected but got table"));
    EXPECT_TRUE(Contains(ErrorOf("return 'a' .. nil"), "concatenate expected but got nil"));
    EXPECT_TRUE(Contains(ErrorOf("return true .. 'a'"), "concatenate expected but got boolean"));
  }

  TEST_F(LuaLanguage, StringsHoldAnyByte)
  {
    EXPECT_EQ(Num("return string.len('a\\0b')"), 3.0);
    EXPECT_EQ(Str("return 'a\\0b' .. 'c'"), std::string("a\0bc", 4));
    EXPECT_TRUE(Bool("return 'a\\0b' ~= 'a\\0c'"));
    EXPECT_TRUE(Bool("return 'a\\0b' < 'a\\0c'"));
  }

  // ---------------------------------------------------------------------------------------------
  // Comparison and logic

  TEST_F(LuaLanguage, Comparison)
  {
    EXPECT_TRUE(Bool("return 1 < 2 and 2 <= 2 and 3 > 2 and 3 >= 3"));
    EXPECT_TRUE(Bool("return 1 == 1.0"));
    EXPECT_TRUE(Bool("return 'abc' < 'abd' and 'ab' < 'abc' and '' < 'a'"));
    EXPECT_TRUE(Bool("return 'Z' < 'a'"));
    EXPECT_FALSE(Bool("return '1' == 1"));
    EXPECT_FALSE(Bool("return {} == {}"));
    EXPECT_TRUE(Bool("local t = {} return t == t"));
    EXPECT_FALSE(Bool("return nil == false"));
    EXPECT_TRUE(Bool("return 1 ~= 2"));
    EXPECT_TRUE(Bool("return print == print"));
    EXPECT_TRUE(Contains(ErrorOf("return {} < {}"), "attempt to compare two table values"));
  }

  TEST_F(LuaLanguage, LogicalOperatorsReturnOperands)
  {
    EXPECT_TRUE(Run("return nil and 1").IsNil());
    EXPECT_EQ(Str("return false or 'x'"), "x");
    EXPECT_EQ(Num("return 1 and 2"), 2.0);
    EXPECT_EQ(Num("return nil or false or 3"), 3.0);
    EXPECT_FALSE(Bool("return nil and nil or false"));
    EXPECT_TRUE(Bool("return not nil"));
    EXPECT_FALSE(Bool("return not 0")); // 0 is true
    EXPECT_FALSE(Bool("return not ''"));
    EXPECT_EQ(Num("local x = 5 return x > 3 and 10 or 20"), 10.0);
    EXPECT_EQ(Num("local x = 1 return x > 3 and 10 or 20"), 20.0);
    // The right operand is not evaluated when the left decides.
    EXPECT_EQ(Num("local n = 0 local function f() n = n + 1 return true end local _ = true or f() local _ = false and f() return n"), 0.0);
  }

  // ---------------------------------------------------------------------------------------------
  // Tables

  TEST_F(LuaLanguage, TableConstructors)
  {
    EXPECT_EQ(Num("local t = {10, 20, 30} return t[1] + t[2] + t[3]"), 60.0);
    EXPECT_EQ(Num("local t = {x = 1, ['y z'] = 2, [10] = 3} return t.x + t['y z'] + t[10]"), 6.0);
    EXPECT_EQ(Num("local t = {1, 2, 3,} return table.getn(t)"), 3.0);
    EXPECT_EQ(Num("local t = {1, 2; x = 'a'; 3} return t[3]"), 3.0);
    EXPECT_EQ(Str("local t = {a = {b = {c = 'deep'}}} return t.a.b.c"), "deep");
    EXPECT_TRUE(Run("local t = {} return t.missing").IsNil());
    // [k] = v and positional items mix; a positional item wins its slot when written later.
    EXPECT_EQ(Str("local t = {[1] = 'keyed', 'positional'} return t[1]"), "positional");
  }

  // More items than one SETLIST flush carries (LFIELDS_PER_FLUSH), and a call in the last
  // position expanding to all its results (SETLISTO).
  TEST_F(LuaLanguage, LargeConstructorsAndOpenCalls)
  {
    std::string items;
    for (int i = 1; i <= 100; ++i) {
      items += std::to_string(i) + ",";
    }
    EXPECT_EQ(Num("local t = {" + items + "} local s = 0 for i = 1, 100 do s = s + t[i] end return s"), 5050.0);
    EXPECT_EQ(Num("local t = {" + items + "} return table.getn(t)"), 100.0);
    EXPECT_EQ(Num("local function f() return 1, 2, 3 end local t = {f()} return table.getn(t)"), 3.0);
    EXPECT_EQ(Num("local function f() return 1, 2, 3 end local t = {f(), f()} return table.getn(t)"), 4.0);
    EXPECT_EQ(Num("local function f() return 1, 2, 3 end local t = {(f())} return table.getn(t)"), 1.0);
  }

  TEST_F(LuaLanguage, TableKeys)
  {
    EXPECT_EQ(Str("local t = {} t[1] = 'num' return t[1.0]"), "num");
    EXPECT_TRUE(Run("local t = {} t[1] = 'num' return t['1']").IsNil());
    EXPECT_EQ(Str("local t = {} t[0.5] = 'half' t[-3] = 'neg' return t[0.5] .. t[-3]"), "halfneg");
    EXPECT_EQ(Str("local k = {} local t = {} t[k] = 'obj' return t[k]"), "obj");
    EXPECT_EQ(Str("local t = {} t[true] = 'yes' return t[true]"), "yes");
    EXPECT_EQ(Str("local f = function() end local t = {[f] = 'fn'} return t[f]"), "fn");
    EXPECT_TRUE(Contains(ErrorOf("local t = {} t[nil] = 1"), "table index is nil"));
    EXPECT_TRUE(Contains(ErrorOf("local t = {} t[0/0] = 1"), "table index is NaN"));
    // Reading a nil key is allowed and gives nil.
    EXPECT_TRUE(Run("local t = {} return t[nil]").IsNil());
  }

  TEST_F(LuaLanguage, TablesGrowAndShrink)
  {
    // Array part grown one by one, a hash part beside it, then emptied again.
    EXPECT_EQ(Num(R"(
      local t = {}
      for i = 1, 1000 do t[i] = i end
      for i = 1, 1000 do t['k' .. i] = i end
      local sum = 0
      for i = 1, 1000 do sum = sum + t[i] + t['k' .. i] end
      for i = 1, 1000 do t[i] = nil t['k' .. i] = nil end
      return sum + (next(t) == nil and 0 or 1))"), 1001000.0);
  }

  // ---------------------------------------------------------------------------------------------
  // Functions

  TEST_F(LuaLanguage, ClosuresKeepTheirUpvalues)
  {
    EXPECT_EQ(Num(R"(
      local function counter()
        local n = 0
        return function() n = n + 1 return n end
      end
      local a, b = counter(), counter()
      a() a() b()
      return a() * 10 + b())"), 32.0);
    // Two closures over the same local share it.
    EXPECT_EQ(Num(R"(
      local function pair()
        local v = 0
        return function(x) v = x end, function() return v end
      end
      local set, get = pair()
      set(42)
      return get())"), 42.0);
    // A local declared in the loop body is a new variable each time round, closed by the
    // body's OP_CLOSE.
    EXPECT_EQ(Str(R"(
      local fns = {}
      local i = 1
      while i <= 3 do
        local j = i
        fns[i] = function() return j end
        i = i + 1
      end
      return fns[1]() .. fns[2]() .. fns[3]())"), "123");
    // Nested three levels deep.
    EXPECT_EQ(Num("local a = 1 local function f() local b = 2 return function() return function() return a + b end end end return f()()()"), 3.0);
  }

  TEST_F(LuaLanguage, RecursionAndLocalFunctions)
  {
    EXPECT_EQ(Num("local function fact(n) if n <= 1 then return 1 end return n * fact(n - 1) end return fact(10)"), 3628800.0);
    EXPECT_EQ(Num("local function fib(n) if n < 2 then return n end return fib(n - 1) + fib(n - 2) end return fib(20)"), 6765.0);
    EXPECT_EQ(Num("local t = {} function t.f(x) return x * 2 end function t:g(x) return self.f(x) + 1 end return t:g(5)"), 11.0);
    EXPECT_EQ(Str("local s = 'abc' return s:upper()"), "ABC");
  }

  // 5.0 varargs: `...` collects the extra arguments into the local table `arg`, with `n`.
  TEST_F(LuaLanguage, VarargsGoIntoArg)
  {
    EXPECT_EQ(Num("local function f(...) return arg.n end return f(1, nil, 3)"), 3.0);
    EXPECT_EQ(Num("local function f(...) return arg[3] end return f(1, nil, 3)"), 3.0);
    EXPECT_EQ(Num("local function f(...) return arg.n end return f()"), 0.0);
    EXPECT_EQ(Str("local function f(a, ...) return a .. arg.n end return f('x', 1, 2)"), "x2");
    EXPECT_EQ(Num("local function sum(...) local s = 0 for i = 1, arg.n do s = s + arg[i] end return s end return sum(1, 2, 3, 4)"), 10.0);
    EXPECT_EQ(Num("local function pass(...) return unpack(arg) end local a, b, c = pass(4, 5, 6) return a + b + c"), 15.0);
  }

  TEST_F(LuaLanguage, MultipleResultsAndAdjustment)
  {
    EXPECT_TRUE(Run("local a, b, c = (function() return 1, 2 end)() return c").IsNil());
    EXPECT_EQ(Num("local function f() return 1, 2 end local a, b = f(), 10 return b"), 10.0);
    EXPECT_TRUE(Run("local function f() return 1, 2 end local a, b = (f()) return b").IsNil());
    EXPECT_EQ(Num("local a, b = 1 return a"), 1.0);
    EXPECT_TRUE(Run("local a, b = 1 return b").IsNil());
    EXPECT_EQ(Num("local a, b = 1, 2, 3 return b"), 2.0);
    EXPECT_EQ(Num("local a, b = 1, 2 a, b = b, a return a * 10 + b"), 21.0);
    EXPECT_EQ(Num("local function f() return 1, 2, 3 end local function g() return f() end local x, y, z = g() return z"), 3.0);
    EXPECT_EQ(Num("local t = {} local i = 1 i, t[i] = i + 1, 20 return t[1]"), 20.0); // index evaluated before assignment
  }

  // ---------------------------------------------------------------------------------------------
  // Control flow

  TEST_F(LuaLanguage, NumericFor)
  {
    EXPECT_EQ(Num("local s = 0 for i = 1, 10 do s = s + i end return s"), 55.0);
    EXPECT_EQ(Num("local s = 0 for i = 10, 1, -2 do s = s + i end return s"), 30.0);
    EXPECT_EQ(Num("local n = 0 for i = 1, 0 do n = n + 1 end return n"), 0.0);
    EXPECT_EQ(Num("local n = 0 for i = 0, 1, 0.25 do n = n + 1 end return n"), 5.0);
    EXPECT_EQ(Num("local s = 0 for i = 1, 3 do for j = 1, 3 do s = s + i * j end end return s"), 36.0);
    EXPECT_EQ(Num("local s = 0 for i = 1, '3' do s = s + i end return s"), 6.0); // the limit converts
    EXPECT_TRUE(Contains(ErrorOf("for i = 1, {} do end"), "`for' limit must be a number"));
    // fornum pre-subtracts the step with OP_SUB before the first OP_FORLOOP (5.0 lparser.c), so a
    // bad start or step value fails as arithmetic - and, as binary arithmetic takes no strings
    // here, so does a numeric-string step.
    EXPECT_TRUE(Contains(ErrorOf("for i = {}, 2 do end"), "perform arithmetic on"));
    EXPECT_TRUE(Contains(ErrorOf("for i = 1, 2, {} do end"), "perform arithmetic on"));
    EXPECT_TRUE(Contains(ErrorOf("for i = 1, 2, '1' do end"), "perform arithmetic on"));
  }

  TEST_F(LuaLanguage, GenericFor)
  {
    EXPECT_EQ(Num("local s = 0 for i, v in ipairs({5, 6, 7}) do s = s + i * v end return s"), 38.0);
    EXPECT_EQ(Num("local s = 0 for k, v in pairs({a = 1, b = 2, c = 3}) do s = s + v end return s"), 6.0);
    // 5.0's `for k, v in t` is shorthand for `in next, t`.
    EXPECT_EQ(Num("local s = 0 for k, v in {4, 5, 6} do s = s + v end return s"), 15.0);
    // A hand-written iterator.
    EXPECT_EQ(Str(R"(
      local function range(n)
        return function(state, i) if i < n then return i + 1 end end, nil, 0
      end
      local out = ''
      for i in range(4) do out = out .. i end
      return out)"), "1234");
    EXPECT_TRUE(Contains(ErrorOf("for x in 5 do end"), "loop over"));
  }

  TEST_F(LuaLanguage, WhileRepeatAndBreak)
  {
    EXPECT_EQ(Num("local i, s = 0, 0 while i < 5 do i = i + 1 s = s + i end return s"), 15.0);
    EXPECT_EQ(Num("local i = 0 repeat i = i + 1 until i >= 7 return i"), 7.0);
    EXPECT_EQ(Num("local i = 10 repeat i = i + 1 until true return i"), 11.0); // body runs once
    EXPECT_EQ(Num("local i = 0 while true do i = i + 1 if i == 4 then break end end return i"), 4.0);
    EXPECT_EQ(Num("local n = 0 for i = 1, 10 do for j = 1, 10 do if j > 2 then break end n = n + 1 end end return n"), 20.0);
    EXPECT_EQ(Num("local i = 0 repeat i = i + 1 if i == 3 then break end until false return i"), 3.0);
  }

  // Fork: `continue` is a keyword (the token table at 0x00D45C0C lists "continue" after "break";
  // statement 0x0091DD60 parses it like break).
  TEST_F(LuaLanguage, ContinueSkipsToTheNextIteration)
  {
    EXPECT_EQ(Num("local s = 0 for i = 1, 10 do if math.mod(i, 2) == 0 then continue end s = s + i end return s"), 25.0);
    EXPECT_EQ(Num("local s, i = 0, 0 while i < 10 do i = i + 1 if i > 5 then continue end s = s + i end return s"), 15.0);
    EXPECT_EQ(Num("local s = 0 for _, v in ipairs({1, 2, 3, 4}) do if v == 2 then continue end s = s + v end return s"), 8.0);
  }

  TEST_F(LuaLanguage, IfElseifElse)
  {
    const char* const classify = "local function c(x) if x < 0 then return 'neg' elseif x == 0 then return 'zero' elseif x < 10 then return 'small' else return 'big' end end ";
    EXPECT_EQ(Str(std::string(classify) + "return c(-1)"), "neg");
    EXPECT_EQ(Str(std::string(classify) + "return c(0)"), "zero");
    EXPECT_EQ(Str(std::string(classify) + "return c(5)"), "small");
    EXPECT_EQ(Str(std::string(classify) + "return c(50)"), "big");
    EXPECT_EQ(Num("local x do local x = 5 end return x == nil and 1 or 0"), 1.0); // do-block scope
  }

  // ---------------------------------------------------------------------------------------------
  // Errors

  TEST_F(LuaLanguage, PcallAndErrorWithValues)
  {
    using faf_lua_tests::FirstLine;
    EXPECT_EQ(FirstLine(Str("local ok, e = pcall(error, 'msg') return tostring(ok) .. ' ' .. e")), "false msg");
    // A position is added for a Lua caller, in the fork's "chunk(line): " form (luaL_where 0x0090DB80).
    EXPECT_EQ(FirstLine(Str("local ok, e = pcall(function() error('boom') end) return e")), "test(1): boom");
    EXPECT_EQ(FirstLine(Str("local ok, e = pcall(function() error('boom', 0) end) return e")), "boom");
    EXPECT_EQ(FirstLine(Str("local function inner() error('lvl2', 2) end\nlocal ok, e = pcall(function()\ninner()\nend) return e")), "test(3): lvl2");
    EXPECT_EQ(Str("local ok, a, b = pcall(function(x, y) return x + y, x * y end, 3, 4) return tostring(ok) .. a .. b"), "true712");
    EXPECT_FALSE(Bool("return pcall(function() local x = nil; x() end)"));
    // Errors raised by the VM carry the position too (addinfo 0x00912F30, "%s(%d): %s").
    EXPECT_EQ(FirstLine(Str("local ok, e = pcall(function()\nlocal f = nil\nreturn f()\nend) return e")), "test(3): attempt to call local `f' (a nil value)");
    // Nested pcall: the inner error does not escape.
    EXPECT_EQ(FirstLine(Str("local ok, v = pcall(function() local ok2, e2 = pcall(error, 'in') return 'out:' .. e2 end) return v")), "out:in");
  }

  // Fork: the message of a raised error has the stack traceback appended - luaG_errormsg calls the
  // global `_TRACEBACK` (installed by luaopen_debug, 0x009124C0) with it.
  TEST_F(LuaLanguage, ErrorsCarryATraceback)
  {
    const std::string message = Str("local function deep() error('where') end\nlocal ok, e = pcall(function() deep() end) return e");
    EXPECT_TRUE(Contains(message, "test(1): where\nstack traceback:")) << message;
    EXPECT_TRUE(Contains(message, "in function `error'")) << message;
    EXPECT_TRUE(Contains(message, "in function `pcall'")) << message;
    // Without _TRACEBACK the message stays as raised.
    EXPECT_EQ(Str("_TRACEBACK = nil local ok, e = pcall(error, 'bare') return e"), "bare");
  }

  // Fork: lua_isstring (0x0090C800) is true for strings only (`cmp eax, 4`), not for numbers, so
  // error() adds no position to a number and passes it on as it is.
  TEST_F(LuaLanguage, ErrorWithANumberGetsNoPosition)
  {
    EXPECT_EQ(Str("local ok, e = pcall(function() error(42) end) return e"), "42");
  }

  TEST_F(LuaLanguage, ErrorMessagesNameTheVariable)
  {
    const std::string callGlobal = ErrorOf("nofunc()");
    EXPECT_TRUE(Contains(callGlobal, "attempt to call")) << callGlobal;
    EXPECT_TRUE(Contains(callGlobal, "nofunc")) << callGlobal;
    const std::string callLocal = ErrorOf("local fn\nreturn fn()");
    EXPECT_EQ(faf_lua_tests::FirstLine(callLocal), "test(2): attempt to call local `fn' (a nil value)");
    const std::string callUpvalue = ErrorOf("local up local function f() return up() end return f()");
    // Fork wording: "upval", not 5.0's "upvalue" (getobjname 0x00912D50, `mov eax, 0D45544h ; "upval"`).
    EXPECT_TRUE(Contains(callUpvalue, "attempt to call upval `up' (a nil value)")) << callUpvalue;
    const std::string callField = ErrorOf("local t = {} t.method()");
    EXPECT_TRUE(Contains(callField, "method")) << callField;
  }

  TEST_F(LuaLanguage, TailCallsDoNotGrowTheStack)
  {
    EXPECT_EQ(Str("local function loop(n) if n == 0 then return 'done' end return loop(n - 1) end return loop(100000)"), "done");
    EXPECT_EQ(Num(R"(
      local isEven, isOdd
      function isEven(n) if n == 0 then return 1 end return isOdd(n - 1) end
      function isOdd(n) if n == 0 then return 0 end return isEven(n - 1) end
      return isEven(50001))"), 0.0);
  }

  // Unbounded recursion stops at the call-info limit with "stack overflow" (luaD_growCI,
  // 0x00914240), and the state is usable afterwards - a second overflow reports the same.
  TEST_F(LuaLanguage, DeepRecursionOverflowsCleanly)
  {
    const std::string chunk = "local function f(n) return 1 + f(n + 1) end local ok, e = pcall(f, 1) return tostring(ok) .. ' ' .. e";
    const std::string first = Str(chunk);
    EXPECT_TRUE(Contains(first, "false")) << first;
    EXPECT_TRUE(Contains(first, "stack overflow")) << first;
    const std::string second = Str(chunk);
    EXPECT_TRUE(Contains(second, "stack overflow")) << second;
    EXPECT_EQ(Num("local function d(n) if n == 0 then return 0 end return 1 + d(n - 1) end return d(1000)"), 1000.0);
  }

  // Recursion through C (here a metamethod called from the VM through luaD_call) stops at the
  // C-call limit with "C stack overflow" (luaD_call 0x00914430), and the count is put back.
  TEST_F(LuaLanguage, CStackOverflowIsCaughtAndRecovers)
  {
    const std::string chunk = R"(
      local t = setmetatable({}, {})
      getmetatable(t).__index = function(self, k) return self[k] end
      local ok, e = pcall(function() return t.x end)
      return tostring(ok) .. ' ' .. e)";
    const std::string first = Str(chunk);
    EXPECT_TRUE(Contains(first, "false")) << first;
    EXPECT_TRUE(Contains(first, "stack overflow")) << first;
    const std::string second = Str(chunk);
    EXPECT_TRUE(Contains(second, "stack overflow")) << second;
    EXPECT_EQ(Num("return 1 + 1"), 2.0);
  }

  TEST_F(LuaLanguage, GlobalsAndEnvironments)
  {
    EXPECT_EQ(Num("gx = 5 return gx + _G.gx"), 10.0);
    EXPECT_TRUE(Run("return undefined_global_name").IsNil());
    EXPECT_EQ(Str(R"(
      local function f() return marker end
      setfenv(f, {marker = 'own env'})
      return f())"), "own env");
    EXPECT_EQ(Str(R"(
      marker = 'global'
      local env = setmetatable({}, {__index = _G})
      local chunk = loadstring('marker = "inside" return marker')
      setfenv(chunk, env)
      local inside = chunk()
      return inside .. '/' .. marker)"), "inside/global");
  }
} // namespace
