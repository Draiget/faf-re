// The table library: the eight 5.0 functions (registration array 0x00D47418) and the four FAF
// adds through its hot-patched opener (0x0128C1DE, rows at 0x0129366C): getsize, empty, unpack,
// clone. Lengths follow 5.0's luaL_getn (0x0090E090): the `n` field, then the weak sizes table,
// then a count from 1 up to the first nil.

#include <string>
#include <gtest/gtest.h>

#include "LuaTestSupport.h"

namespace
{
  using faf_lua_tests::Contains;

  class LuaTableLib : public faf_lua_tests::LuaFixture
  {
  };

  TEST_F(LuaTableLib, GetnAndSetn)
  {
    EXPECT_EQ(Num("return table.getn({})"), 0.0);
    EXPECT_EQ(Num("return table.getn({1, 2, 3})"), 3.0);
    EXPECT_EQ(Num("return table.getn({1, 2, nil, 4})"), 2.0); // counts up to the first nil
    EXPECT_EQ(Num("return table.getn({n = 5})"), 5.0);         // n wins
    EXPECT_EQ(Num("return table.getn({1, 2, 3, n = 1})"), 1.0);
    EXPECT_EQ(Num("local t = {1, 2, 3} table.setn(t, 10) return table.getn(t)"), 10.0); // sizes table
    EXPECT_TRUE(Run("local t = {1, 2, 3} table.setn(t, 10) return rawget(t, 'n')").IsNil()); // the table is left alone
    EXPECT_EQ(Num("local t = {n = 2} table.setn(t, 7) return t.n"), 7.0);                // n is updated
    EXPECT_TRUE(Contains(ErrorOf("table.getn(5)"), "bad argument #1 to `getn' (table expected, got number)"));
  }

  TEST_F(LuaTableLib, Insert)
  {
    EXPECT_EQ(Str("local t = {} table.insert(t, 'a') table.insert(t, 'b') return t[1] .. t[2] .. table.getn(t)"), "ab2");
    EXPECT_EQ(Str("local t = {'a', 'c'} table.insert(t, 2, 'b') return t[1] .. t[2] .. t[3] .. table.getn(t)"), "abc3");
    EXPECT_EQ(Str("local t = {'b'} table.insert(t, 1, 'a') return t[1] .. t[2]"), "ab");
    // Past the end grows n to the position.
    EXPECT_EQ(Str("local t = {'a'} table.insert(t, 5, 'e') return table.getn(t) .. t[5] .. tostring(t[3])"), "5enil");
    // Insert keeps the sizes table up to date, so a hole does not shorten the count.
    EXPECT_EQ(Num("local t = {} for i = 1, 5 do table.insert(t, i) end t[3] = nil return table.getn(t)"), 5.0);
    EXPECT_EQ(Num("local t = {n = 0} table.insert(t, 'x') return t.n"), 1.0);
    EXPECT_TRUE(Contains(ErrorOf("table.insert(nil, 1)"), "bad argument #1 to `insert'"));
  }

  TEST_F(LuaTableLib, Remove)
  {
    EXPECT_EQ(Str("local t = {'a', 'b', 'c'} local r = table.remove(t) return r .. table.getn(t) .. tostring(t[3])"), "c2nil");
    EXPECT_EQ(Str("local t = {'a', 'b', 'c'} local r = table.remove(t, 1) return r .. t[1] .. t[2] .. table.getn(t)"), "abc2");
    EXPECT_EQ(Str("local t = {'a', 'b', 'c'} local r = table.remove(t, 2) return r .. t[1] .. t[2] .. tostring(t[3])"), "bacnil");
    EXPECT_TRUE(Run("return table.remove({})").IsNil());
    EXPECT_EQ(Num("local t = {} local n = 0 for i = 1, 20 do table.insert(t, i) end while table.remove(t) do n = n + 1 end return n"), 20.0);
  }

  TEST_F(LuaTableLib, Sort)
  {
    // table.concat takes strings only here, so the lists are joined in Lua.
    const std::string kJoin = "local function join(t) local s = '' for i = 1, table.getn(t) do s = s .. (i > 1 and ',' or '') .. tostring(t[i]) end return s end ";
    EXPECT_EQ(Str(kJoin + "local t = {5, 2, 8, 1, 9, 3} table.sort(t) return join(t)"), "1,2,3,5,8,9");
    EXPECT_EQ(Str(kJoin + "local t = {'pear', 'apple', 'fig'} table.sort(t) return join(t)"), "apple,fig,pear");
    EXPECT_EQ(Str(kJoin + "local t = {5, 2, 8, 1} table.sort(t, function(a, b) return a > b end) return join(t)"), "8,5,2,1");
    EXPECT_EQ(Str(kJoin + "local t = {} table.sort(t) return join(t)"), "");
    EXPECT_EQ(Str(kJoin + "local t = {1} table.sort(t) return join(t)"), "1");
    EXPECT_EQ(Str(kJoin + "local t = {2, 1} table.sort(t) return join(t)"), "1,2");
    // A larger reverse-ordered and a constant input both come out sorted.
    EXPECT_TRUE(Bool(R"(
      local t = {}
      for i = 1, 500 do t[i] = 501 - i end
      table.sort(t)
      for i = 1, 500 do if t[i] ~= i then return false end end
      local c = {}
      for i = 1, 100 do c[i] = 7 end
      table.sort(c)
      return c[1] == 7 and c[100] == 7)"));
    // Sorting records by a field through a C++-visible Lua comparator.
    EXPECT_EQ(Str(R"(
      local people = {{name = 'b', age = 30}, {name = 'a', age = 20}, {name = 'c', age = 25}}
      table.sort(people, function(x, y) return x.age < y.age end)
      return people[1].name .. people[2].name .. people[3].name)"), "acb");
    // A comparator that is always true walks off the range.
    EXPECT_TRUE(Contains(ErrorOf("local t = {} for i = 1, 20 do t[i] = i end table.sort(t, function() return true end)"), "invalid order function for sorting"));
    // Mixed types order by tag (LuaLanguage.MixedTypesOrderByTag): numbers before strings.
    EXPECT_EQ(Str(kJoin + "local t = {'b', 2, 'a', 1} table.sort(t) return join(t)"), "1,2,a,b");
    EXPECT_TRUE(Contains(ErrorOf("table.sort({{}, {}})"), "attempt to compare two table values"));
  }

  TEST_F(LuaTableLib, ConcatForeachForeachi)
  {
    EXPECT_EQ(Str("return table.concat({'1', '2', '3'}, ', ')"), "1, 2, 3");
    // Fork: numbers are refused - the check is lua_isstring, true for strings only in this build
    // (0x0090C800, `cmp eax, 4`).
    EXPECT_TRUE(Contains(ErrorOf("return table.concat({1, 2, 3})"), "table contains non-strings"));
    EXPECT_EQ(Str("return table.concat({'a', 'b', 'c'})"), "abc");
    EXPECT_EQ(Str("return table.concat({'a', 'b', 'c', 'd'}, '-', 2, 3)"), "b-c");
    EXPECT_EQ(Str("return table.concat({})"), "");
    EXPECT_TRUE(Contains(ErrorOf("return table.concat({1, {}, 3})"), "table contains non-strings"));
    EXPECT_EQ(Str("local out = '' table.foreachi({'x', 'y', 'z'}, function(i, v) out = out .. i .. v end) return out"), "1x2y3z");
    EXPECT_EQ(Num("return table.foreachi({5, 6, 7}, function(i, v) if v == 6 then return i * 100 end end)"), 200.0);
    EXPECT_EQ(Num("local s = 0 table.foreach({a = 1, b = 2, c = 3}, function(k, v) s = s + v end) return s"), 6.0);
    EXPECT_EQ(Str("return table.foreach({only = 'v'}, function(k, v) return k .. v end)"), "onlyv");
    EXPECT_TRUE(Run("return table.foreach({}, function() return 1 end)").IsNil());
  }

  // FAF table.getsize (0x0128BF5A): the non-nil values of the array and hash parts.
  TEST_F(LuaTableLib, FafGetsize)
  {
    EXPECT_EQ(Num("return table.getsize({})"), 0.0);
    EXPECT_EQ(Num("return table.getsize({1, 2, 3, a = 1, b = 2})"), 5.0);
    EXPECT_EQ(Num("local t = {} for i = 1, 10 do t['k' .. i] = i end t.k3 = nil return table.getsize(t)"), 9.0);
    EXPECT_EQ(Num("return table.getsize({1, nil, 3})"), 2.0);
    EXPECT_EQ(Num("return table.getsize(5)"), 0.0);
    EXPECT_EQ(Num("return table.getsize()"), 0.0);
  }

  // FAF table.empty (0x0128BFD1).
  TEST_F(LuaTableLib, FafEmpty)
  {
    EXPECT_TRUE(Bool("return table.empty({})"));
    EXPECT_FALSE(Bool("return table.empty({1})"));
    EXPECT_FALSE(Bool("return table.empty({a = 1, b = 2})"));
    EXPECT_TRUE(Bool("local t = {1, 2} t[1] = nil t[2] = nil return table.empty(t)"));
    EXPECT_TRUE(Bool("return table.empty(nil)"));
    EXPECT_TRUE(Bool("return table.empty('x')"));
  }

  // FAF table.unpack (0x0128C055): t[i]..t[j], i defaulting to 1 and j to lua_getn.
  TEST_F(LuaTableLib, FafUnpack)
  {
    EXPECT_EQ(Num("local a, b, c = table.unpack({1, 2, 3}) return a + b + c"), 6.0);
    EXPECT_EQ(Num("local a, b = table.unpack({1, 2, 3}, 2) return a * 10 + b"), 23.0);
    EXPECT_EQ(Num("local a, b = table.unpack({1, 2, 3}, 2, 2) return b == nil and a or -1"), 2.0);
    EXPECT_TRUE(Run("return table.unpack({1, 2, 3}, 3, 2)").IsNil());
    EXPECT_EQ(Num("local a, b = table.unpack({1, 2}, 0) return b"), 1.0); // t[0] is nil, then t[1]
  }

  // FAF table.clone (0x0128C0F1): a deep copy that keeps shared and cyclic sub-tables shared,
  // leaves the metatable behind and returns non-tables as they are.
  TEST_F(LuaTableLib, FafClone)
  {
    EXPECT_TRUE(Bool(R"(
      local inner = {x = 1}
      local t = {inner = inner, list = {1, 2, 3}, s = 'str'}
      local c = table.clone(t)
      return c ~= t and c.inner ~= inner and c.inner.x == 1 and c.list[3] == 3 and c.s == 'str')"));
    EXPECT_TRUE(Bool("local t = {} t.self = t local c = table.clone(t) return c.self == c"));
    EXPECT_TRUE(Bool("local s = {} local t = {a = s, b = s} local c = table.clone(t) return c.a == c.b and c.a ~= s"));
    EXPECT_TRUE(Bool("local t = setmetatable({}, {}) return getmetatable(table.clone(t)) == getmetatable({})"));
    EXPECT_TRUE(Bool("local k = {} local t = {[k] = 1} local c = table.clone(t) return c[k] == 1")); // keys are shared
    EXPECT_EQ(Num("return table.clone(5)"), 5.0);
    EXPECT_EQ(Str("return table.clone('s')"), "s");
    EXPECT_TRUE(Bool("local t = {1, 2} local c = table.clone(t) c[1] = 9 return t[1] == 1"));
  }
} // namespace
