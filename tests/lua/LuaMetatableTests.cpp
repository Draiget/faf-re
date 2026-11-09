// Metatables and every tag method the fork dispatches. The event names are the eighteen of retail
// luaT_eventname (0x00D47508): __index, __newindex, __mode, __eq, __add, __sub, __mul, __div,
// __band, __bor, __bshl, __bshr, __pow, __unm, __lt, __le, __concat, __call. The VM numbers its
// fifth bit operator (xor, which `^` compiles to) after __bshr, so `^` asks for "__pow".

#include <string>
#include <gtest/gtest.h>

#include "LuaTestSupport.h"

namespace
{
  using faf_lua_tests::Contains;

  class LuaMetatable : public faf_lua_tests::LuaFixture
  {
  };

  TEST_F(LuaMetatable, IndexThroughTableAndFunction)
  {
    EXPECT_EQ(Num("local base = {x = 7} local t = setmetatable({}, {__index = base}) return t.x"), 7.0);
    EXPECT_EQ(Str("local t = setmetatable({}, {__index = function(self, k) return 'got ' .. k end}) return t.name"), "got name");
    // A present key never reaches __index; rawget bypasses it.
    EXPECT_EQ(Num("local t = setmetatable({x = 1}, {__index = function() return 99 end}) return t.x"), 1.0);
    EXPECT_TRUE(Run("local t = setmetatable({}, {__index = function() return 99 end}) return rawget(t, 'x')").IsNil());
    // Inheritance chain three deep.
    EXPECT_EQ(Str(R"(
      local A = {who = 'A'}
      local B = setmetatable({}, {__index = A})
      local C = setmetatable({}, {__index = B})
      return C.who)"), "A");
    // __index receives the original table.
    EXPECT_TRUE(Bool("local t t = setmetatable({}, {__index = function(self) return self == t end}) return t.anything"));
  }

  TEST_F(LuaMetatable, NewindexThroughTableAndFunction)
  {
    EXPECT_EQ(Num(R"(
      local store = {}
      local t = setmetatable({}, {__newindex = store})
      t.a = 5
      return store.a + (rawget(t, 'a') == nil and 0 or 100))"), 5.0);
    EXPECT_EQ(Str(R"(
      local log = ''
      local t = setmetatable({}, {__newindex = function(self, k, v) log = log .. k .. '=' .. v rawset(self, k, v) end})
      t.a = 1
      t.a = 2 -- present now: no call
      t.b = 3
      return log .. ';' .. t.a)"), "a=1b=3;2");
    EXPECT_EQ(Num("local t = setmetatable({}, {__newindex = function() error('no') end}) rawset(t, 'k', 4) return t.k"), 4.0);
  }

  TEST_F(LuaMetatable, CallMakesTablesCallable)
  {
    EXPECT_EQ(Num("local t = setmetatable({base = 10}, {__call = function(self, a, b) return self.base + a + b end}) return t(1, 2)"), 13.0);
    EXPECT_EQ(Num("local t = setmetatable({}, {__call = function(self, ...) return arg.n end}) return t(1, 2, 3)"), 3.0);
    EXPECT_TRUE(Contains(ErrorOf("local t = {} t()"), "attempt to call local `t' (a table value)"));
  }

  TEST_F(LuaMetatable, ArithmeticTagMethods)
  {
    const std::string vec = R"(
      local V = {}
      V.__add = function(a, b) return 'add' end
      V.__sub = function(a, b) return 'sub' end
      V.__mul = function(a, b) return 'mul' end
      V.__div = function(a, b) return 'div' end
      V.__unm = function(a) return 'unm' end
      local v = setmetatable({}, V)
    )";
    EXPECT_EQ(Str(vec + "return v + 1"), "add");
    EXPECT_EQ(Str(vec + "return v + v"), "add");
    EXPECT_EQ(Str(vec + "return v - v"), "sub");
    EXPECT_EQ(Str(vec + "return v * 2"), "mul");
    EXPECT_EQ(Str(vec + "return v / 2"), "div");
    EXPECT_EQ(Str(vec + "return -v"), "unm");
    EXPECT_EQ(Str(vec + "return v + {}"), "add");
    // The operands arrive in source order.
    EXPECT_EQ(Num("local m = {__sub = function(a, b) return a.v - b end} local x = setmetatable({v = 10}, m) return x - 3"), 7.0);
    // Strings have no __add in their metatable (the string table).
    EXPECT_TRUE(Contains(ErrorOf("return 'a' + 'b'"), "perform arithmetic on"));
  }

  // Fork: only the left operand's tag method is consulted when the left operand is not a table or
  // userdata. luaT_gettmbyobj (0x00928450) hands back the type's default metatable slot itself for
  // every other tag (`lea eax, [ecx+eax*8+0D4h]`), which is never nil, so the right operand's
  // method is not looked at and the operation fails.
  TEST_F(LuaMetatable, LeftNonTableOperandHidesTheRightTagMethod)
  {
    const std::string vec = "local v = setmetatable({}, {__add = function() return 'add' end, __mul = function() return 'mul' end, __concat = function() return 'cat' end, __bor = function() return 'bor' end}) ";
    EXPECT_TRUE(Contains(ErrorOf(vec + "return 1 + v"), "attempt to perform arithmetic on local `v' (a table value)"));
    EXPECT_TRUE(Contains(ErrorOf(vec + "return 2 * v"), "perform arithmetic on"));
    EXPECT_TRUE(Contains(ErrorOf(vec + "return 1 | v"), "perform arithmetic on"));
    EXPECT_TRUE(Contains(ErrorOf(vec + "return 'x' .. v"), "attempt to concatenate local `v' (a table value)"));
    EXPECT_EQ(Str(vec + "return v .. 'x'"), "cat");
  }

  TEST_F(LuaMetatable, BitTagMethods)
  {
    const std::string bits = R"(
      local B = {
        __band = function() return 'band' end, __bor = function() return 'bor' end,
        __bshl = function() return 'bshl' end, __bshr = function() return 'bshr' end,
        __pow = function() return 'xor' end,
      }
      local b = setmetatable({}, B)
    )";
    EXPECT_EQ(Str(bits + "return b & 1"), "band");
    EXPECT_EQ(Str(bits + "return b | 1"), "bor");
    EXPECT_EQ(Str(bits + "return b << 2"), "bshl");
    EXPECT_EQ(Str(bits + "return b >> 2"), "bshr");
    EXPECT_EQ(Str(bits + "return b ^ 3"), "xor");
  }

  TEST_F(LuaMetatable, ConcatTagMethod)
  {
    const std::string cat = "local C = {__concat = function(a, b) return (type(a) == 'table' and 'T' or a) .. '+' .. (type(b) == 'table' and 'T' or b) end} local c = setmetatable({}, C) ";
    EXPECT_EQ(Str(cat + "return c .. 'x'"), "T+x");
    EXPECT_EQ(Str(cat + "return c .. 1"), "T+1");
    EXPECT_EQ(Str(cat + "return c .. c"), "T+T");
    EXPECT_EQ(Str(cat + "return c .. 'a' .. 'b'"), "T+ab"); // the right-hand strings join first
  }

  // __eq runs only for two tables (or two userdata) that are not the same object and whose
  // metamethods agree (5.0 luaV_equalval / get_compTM); ~= is its negation.
  TEST_F(LuaMetatable, EqualityTagMethod)
  {
    const std::string eq = "local calls = 0 local E = {__eq = function(a, b) calls = calls + 1 return a.id == b.id end} ";
    EXPECT_TRUE(Bool(eq + "local a, b = setmetatable({id = 1}, E), setmetatable({id = 1}, E) return a == b"));
    EXPECT_TRUE(Bool(eq + "local a, b = setmetatable({id = 1}, E), setmetatable({id = 2}, E) return a ~= b"));
    EXPECT_EQ(Num(eq + "local a = setmetatable({id = 1}, E) local _ = (a == a) return calls"), 0.0); // same object: no call
    EXPECT_FALSE(Bool(eq + "local a = setmetatable({id = 1}, E) return a == 1")); // different types: no call
    EXPECT_FALSE(Bool(eq + "local a = setmetatable({id = 1}, E) local b = setmetatable({id = 1}, {__eq = function() return true end}) return a == b"));
    EXPECT_TRUE(Bool(eq + "local a = setmetatable({id = 1}, E) local b = setmetatable({id = 1}, {__eq = E.__eq}) return a == b"));
    EXPECT_FALSE(Bool(eq + "local a, b = setmetatable({id = 1}, E), {id = 1} return a == b"));
  }

  TEST_F(LuaMetatable, OrderTagMethods)
  {
    const std::string ord = R"(
      local O = {}
      O.__lt = function(a, b) return a.v < b.v end
      O.__le = function(a, b) return a.v <= b.v end
      local function n(v) return setmetatable({v = v}, O) end
    )";
    EXPECT_TRUE(Bool(ord + "return n(1) < n(2)"));
    EXPECT_FALSE(Bool(ord + "return n(2) < n(1)"));
    EXPECT_TRUE(Bool(ord + "return n(2) > n(1)"));
    EXPECT_TRUE(Bool(ord + "return n(2) <= n(2)"));
    EXPECT_TRUE(Bool(ord + "return n(3) >= n(2)"));
    // Without __le, a <= b is not (b < a).
    EXPECT_TRUE(Bool("local O = {__lt = function(a, b) return a.v < b.v end} local a, b = setmetatable({v = 1}, O), setmetatable({v = 1}, O) return a <= b"));
    EXPECT_FALSE(Bool("local O = {__lt = function(a, b) return a.v < b.v end} local a, b = setmetatable({v = 2}, O), setmetatable({v = 1}, O) return a <= b"));
    // Different types never reach the method: they order by tag (LuaLanguage.MixedTypesOrderByTag).
    EXPECT_FALSE(Bool(ord + "return n(1) < 2"));
    EXPECT_TRUE(Bool(ord + "return 2 < n(1)"));
    // No method at all.
    EXPECT_TRUE(Contains(ErrorOf("return setmetatable({}, {}) < setmetatable({}, {})"), "attempt to compare two table values"));
  }

  TEST_F(LuaMetatable, TostringAndProtectedMetatables)
  {
    EXPECT_EQ(Str("local t = setmetatable({}, {__tostring = function() return 'custom' end}) return tostring(t)"), "custom");
    EXPECT_EQ(Str("local t = setmetatable({}, {__metatable = 'locked'}) return getmetatable(t)"), "locked");
    EXPECT_TRUE(Contains(ErrorOf("local t = setmetatable({}, {__metatable = 'locked'}) setmetatable(t, {})"), "cannot change a protected metatable"));
    EXPECT_TRUE(Bool("local mt = {} local t = setmetatable({}, mt) return getmetatable(t) == mt"));
    EXPECT_TRUE(Bool("local mt = {} local t = setmetatable({}, mt) setmetatable(t, nil) return getmetatable(t) ~= mt"));
    EXPECT_TRUE(Contains(ErrorOf("setmetatable({}, 5)"), "bad argument #2"));
  }

  // Fork: luaopen_string (0x00926EF0) makes the string table the default metatable of every
  // string, and luaV_getnotable (0x00929370) indexes through the metatable itself when it has no
  // __index - so string methods resolve.
  TEST_F(LuaMetatable, StringsIndexTheStringTable)
  {
    EXPECT_EQ(Str("local s = 'abc' return s:upper()"), "ABC");
    EXPECT_EQ(Str("return ('hello'):sub(2, 3)"), "el");
    EXPECT_EQ(Num("return ('abc'):len()"), 3.0);
    EXPECT_TRUE(Bool("return ('x').upper == string.upper"));
    EXPECT_TRUE(Bool("return getmetatable('x') == string"));
  }

  // Fork: lua_getmetatable (0x0090D180) always pushes a table and returns 1 - a value without a
  // metatable of its own answers its type's shared default, one per type.
  TEST_F(LuaMetatable, EveryValueHasAMetatable)
  {
    EXPECT_EQ(Str("return type(getmetatable({}))"), "table");
    EXPECT_TRUE(Bool("return getmetatable({}) == getmetatable({})"));
    EXPECT_TRUE(Bool("return getmetatable(1) == getmetatable(2)"));
    EXPECT_TRUE(Bool("return getmetatable(nil) ~= nil and getmetatable(nil) ~= getmetatable(1)"));
    EXPECT_TRUE(Bool("return getmetatable(print) == getmetatable(type)"));
  }

  TEST_F(LuaMetatable, RawAccessIgnoresTagMethods)
  {
    EXPECT_TRUE(Bool(R"(
      local hit = false
      local t = setmetatable({}, {__index = function() hit = true end, __newindex = function() hit = true end})
      rawset(t, 'a', 1)
      local v = rawget(t, 'a')
      local w = rawget(t, 'missing')
      return v == 1 and w == nil and not hit)"));
    EXPECT_TRUE(Bool("local E = {__eq = function() return true end} return not rawequal(setmetatable({}, E), setmetatable({}, E))"));
    EXPECT_TRUE(Bool("local E = {__eq = function() return true end} return setmetatable({}, E) == setmetatable({}, E)"));
  }
} // namespace
