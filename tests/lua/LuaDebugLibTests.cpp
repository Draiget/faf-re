// The debug library (luaopen_debug 0x009124C0): getinfo, getlocal/setlocal, getupvalue/setupvalue,
// traceback, hooks, and the fork's listcode/listk/listlocals.

#include <string>
#include <gtest/gtest.h>

#include "LuaTestSupport.h"

namespace
{
  using faf_lua_tests::Contains;

  class LuaDebugLib : public faf_lua_tests::LuaFixture
  {
  };

  TEST_F(LuaDebugLib, GetinfoDescribesFunctionsAndLevels)
  {
    EXPECT_EQ(Str("return debug.getinfo(1, 'S').what"), "main");
    EXPECT_EQ(Str("return debug.getinfo(1, 'S').source"), "=test");
    EXPECT_EQ(Str("return debug.getinfo(1, 'S').short_src"), "test");
    EXPECT_EQ(Num("\n\nreturn debug.getinfo(1, 'l').currentline"), 3.0);
    EXPECT_EQ(Str("local function f() return debug.getinfo(1, 'S').what end local r = f() return r"), "Lua");
    EXPECT_EQ(Num("\nlocal function f()\nend\nreturn debug.getinfo(f, 'S').linedefined"), 2.0);
    EXPECT_EQ(Str("return debug.getinfo(print, 'S').what"), "C");
    EXPECT_EQ(Num("local a, b = 1, 2 local function f() return a + b end return debug.getinfo(f, 'u').nups"), 2.0);
    EXPECT_TRUE(Bool("local function f() end return debug.getinfo(f, 'f').func == f"));
    EXPECT_EQ(Str("function named_fn() return debug.getinfo(1, 'n').name end local r = named_fn() return r"), "named_fn");
    EXPECT_EQ(Str("function named_fn2() return debug.getinfo(1, 'n').namewhat end local r = named_fn2() return r"), "global");
    EXPECT_EQ(Str("local t = {} function t.m() return debug.getinfo(1, 'n').namewhat end local r = t.m() return r"), "field");
    EXPECT_TRUE(Run("return debug.getinfo(100)").IsNil());
    EXPECT_TRUE(Contains(ErrorOf("return debug.getinfo('x')"), "function or level expected"));
    // A tail call leaves a "tail" record in the caller's place.
    EXPECT_EQ(Str("local function g() return debug.getinfo(2, 'S').what end local function f() return g() end local r = f() return r"), "tail");
  }

  TEST_F(LuaDebugLib, LocalsAndUpvalues)
  {
    EXPECT_EQ(Str("local a, b = 10, 'x' local n, v = debug.getlocal(1, 2) return n .. v"), "bx");
    EXPECT_EQ(Str("local a = 10 local n, v = debug.getlocal(1, 1) return n .. v"), "a10");
    EXPECT_TRUE(Run("local a = 1 return debug.getlocal(1, 50)").IsNil());
    EXPECT_EQ(Num("local a = 1 debug.setlocal(1, 1, 99) return a"), 99.0);
    EXPECT_EQ(Str("local up = 5 local function f() return up end local n, v = debug.getupvalue(f, 1) return n .. v"), "up5");
    EXPECT_EQ(Num("local up = 5 local function f() return up end debug.setupvalue(f, 1, 6) return f()"), 6.0);
    EXPECT_TRUE(Run("local function f() end return debug.getupvalue(f, 1)").IsNil());
    EXPECT_TRUE(Contains(ErrorOf("debug.getlocal(100, 1)"), "level out of range"));
  }

  TEST_F(LuaDebugLib, Traceback)
  {
    const std::string plain = Str("return debug.traceback()");
    EXPECT_TRUE(Contains(plain, "stack traceback:")) << plain;
    const std::string withMessage = Str("local function inner() return debug.traceback('msg') end local r = inner() return r");
    EXPECT_EQ(withMessage.rfind("msg", 0), 0u) << withMessage;
    EXPECT_TRUE(Contains(withMessage, "stack traceback:")) << withMessage;
    EXPECT_TRUE(Contains(withMessage, "test(")) << withMessage;
    EXPECT_TRUE(Contains(Str("return _TRACEBACK('via global')"), "via global"));
  }

  TEST_F(LuaDebugLib, LineAndCountHooks)
  {
    EXPECT_TRUE(Bool(R"(
      local lines = {}
      debug.sethook(function(event, line) lines[table.getn(lines) + 1] = line end, 'l')
      local x = 1
      x = x + 1
      debug.sethook()
      return table.getn(lines) >= 2)"));
    EXPECT_TRUE(Bool(R"(
      local f = function() end
      debug.sethook(f, 'l')
      local h, mask, count = debug.gethook()
      debug.sethook()
      local h2 = debug.gethook()
      return h == f and mask == 'l' and count == 0 and h2 == nil)"));
    EXPECT_TRUE(Bool(R"(
      local counts = 0
      debug.sethook(function(event) if event == 'count' then counts = counts + 1 end end, '', 10)
      for i = 1, 200 do end
      debug.sethook()
      return counts > 5)"));
    EXPECT_TRUE(Bool(R"(
      local calls = 0
      local function target() end
      debug.sethook(function(event) if event == 'call' then calls = calls + 1 end end, 'c')
      target() target() target()
      debug.sethook()
      return calls >= 3)"));
    EXPECT_EQ(Num("return 1 + 1"), 2.0); // nothing left hooked
  }

  // Fork: debug.listcode / listk / listlocals (0x00911FC0, 0x009120B0, 0x00912130).
  TEST_F(LuaDebugLib, ForkListings)
  {
    EXPECT_EQ(Num("return debug.listcode(function(a, b) return a + b end).numparams"), 2.0);
    EXPECT_TRUE(Bool("return debug.listcode(function(a, b) return a + b end).maxstack >= 2"));
    EXPECT_TRUE(Bool(R"(
      local code = debug.listcode(function(a, b) return a + b end)
      local sawAdd, sawReturn = false, false
      for i = 1, table.getn(code) do
        if string.find(code[i], 'ADD', 1, true) then sawAdd = true end
        if string.find(code[i], 'RETURN', 1, true) then sawReturn = true end
      end
      return sawAdd and sawReturn)"));
    EXPECT_TRUE(Bool(R"(
      local k = debug.listk(function() return 'k1', 42 end)
      local sawString, sawNumber = false, false
      for i = 1, table.getn(k) do
        if k[i] == 'k1' then sawString = true end
        if k[i] == 42 then sawNumber = true end
      end
      return sawString and sawNumber)"));
    EXPECT_EQ(Str("local a, b = debug.listlocals(function(x, y) local z = 1 return z end, 1) return a .. b"), "xy");
    EXPECT_TRUE(Contains(ErrorOf("debug.listcode(print)"), "Lua function expected"));
  }
} // namespace
