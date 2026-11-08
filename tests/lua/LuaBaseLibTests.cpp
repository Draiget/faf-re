// The base library as the game opens it (luaopen_base 0x0090FD90, registration array in
// LuaObjectAuxLib.inl): type, tonumber, tostring, assert, error, pcall, unpack, the raw
// functions, next/pairs/ipairs, environments, loadstring, gcinfo, _G and _VERSION.

#include <string>
#include <gtest/gtest.h>

#include "LuaTestSupport.h"

namespace
{
  using faf_lua_tests::Contains;

  class LuaBaseLib : public faf_lua_tests::LuaFixture
  {
  };

  // Fork: C functions have their own tag and type name. type() reads global_State::typenames
  // (luaB_type 0x0090F270), and retail luaT_typenames (0x00D474D8) has "cfunction" at tag 6.
  TEST_F(LuaBaseLib, TypeNames)
  {
    EXPECT_EQ(Str("return type(nil)"), "nil");
    EXPECT_EQ(Str("return type(true)"), "boolean");
    EXPECT_EQ(Str("return type(1)"), "number");
    EXPECT_EQ(Str("return type('')"), "string");
    EXPECT_EQ(Str("return type({})"), "table");
    EXPECT_EQ(Str("return type(function() end)"), "function");
    EXPECT_EQ(Str("return type(print)"), "cfunction");
    EXPECT_EQ(Str("return type(coroutine.create(function() end))"), "thread");
    EXPECT_EQ(Str("return type(newproxy())"), "userdata");
    EXPECT_TRUE(Contains(ErrorOf("return type()"), "bad argument #1 to `type' (value expected)"));
  }

  TEST_F(LuaBaseLib, Tonumber)
  {
    EXPECT_EQ(Num("return tonumber('10')"), 10.0);
    EXPECT_EQ(Num("return tonumber('  10  ')"), 10.0);
    EXPECT_EQ(Num("return tonumber(' -7.5 ')"), -7.5);
    EXPECT_EQ(Num("return tonumber('1e2')"), 100.0);
    EXPECT_EQ(Num("return tonumber(42)"), 42.0);
    EXPECT_TRUE(Run("return tonumber('10x')").IsNil());
    EXPECT_TRUE(Run("return tonumber('')").IsNil());
    EXPECT_TRUE(Run("return tonumber('abc')").IsNil());
    EXPECT_TRUE(Run("return tonumber({})").IsNil());
    EXPECT_TRUE(Run("return tonumber(nil)").IsNil());
    // Other bases go through strtoul.
    EXPECT_EQ(Num("return tonumber('ff', 16)"), 255.0);
    EXPECT_EQ(Num("return tonumber('FF', 16)"), 255.0);
    EXPECT_EQ(Num("return tonumber('zz', 36)"), 1295.0);
    EXPECT_EQ(Num("return tonumber('777', 8)"), 511.0);
    EXPECT_EQ(Num("return tonumber(' 11 ', 2)"), 3.0);
    EXPECT_TRUE(Run("return tonumber('8', 8)").IsNil());
    EXPECT_TRUE(Run("return tonumber('12', 2)").IsNil());
    EXPECT_TRUE(Contains(ErrorOf("return tonumber('1', 1)"), "base out of range"));
    EXPECT_TRUE(Contains(ErrorOf("return tonumber('1', 37)"), "base out of range"));
  }

  TEST_F(LuaBaseLib, Tostring)
  {
    EXPECT_EQ(Str("return tostring(nil)"), "nil");
    EXPECT_EQ(Str("return tostring(true) .. tostring(false)"), "truefalse");
    EXPECT_EQ(Str("return tostring(12)"), "12");
    EXPECT_EQ(Str("return tostring('s')"), "s");
    EXPECT_EQ(Str("return string.sub(tostring({}), 1, 7)"), "table: ");
    EXPECT_EQ(Str("return string.sub(tostring(function() end), 1, 10)"), "function: ");
    EXPECT_EQ(Str("return string.sub(tostring(print), 1, 11)"), "cfunction: ");
    EXPECT_EQ(Str("return string.sub(tostring(coroutine.create(function() end)), 1, 8)"), "thread: ");
    EXPECT_TRUE(Bool("local t = {} return tostring(t) == tostring(t)"));
    EXPECT_TRUE(Bool("return tostring({}) ~= tostring({})"));
  }

  TEST_F(LuaBaseLib, AssertReturnsItsFirstArgument)
  {
    EXPECT_EQ(Num("return assert(5, 'unused')"), 5.0);
    EXPECT_EQ(Num("local a, b = assert(1, 2) return b == nil and 1 or 0"), 1.0); // only the first comes back
    EXPECT_EQ(faf_lua_tests::FirstLine(Str("local ok, e = pcall(assert, false, 'custom') return e")), "custom");
    EXPECT_EQ(faf_lua_tests::FirstLine(Str("local ok, e = pcall(assert, nil) return e")), "assertion failed!");
    EXPECT_TRUE(Contains(Str("local ok, e = pcall(function() assert(false) end) return e"), "assertion failed!"));
  }

  TEST_F(LuaBaseLib, UnpackAndRawFunctions)
  {
    EXPECT_EQ(Num("local a, b, c = unpack({1, 2, 3}) return a + b + c"), 6.0);
    EXPECT_TRUE(Run("return unpack({})").IsNil());
    EXPECT_EQ(Num("local t = {1, 2, 3, n = 2} local a, b, c = unpack(t) return c == nil and b or -1"), 2.0); // n wins
    EXPECT_TRUE(Bool("local t = {} return rawequal(t, t) and not rawequal(t, {}) and rawequal(1, 1) and not rawequal('1', 1)"));
    EXPECT_EQ(Num("local t = {} return rawget(rawset(t, 'k', 9), 'k')"), 9.0); // rawset returns the table
    EXPECT_TRUE(Contains(ErrorOf("rawset({}, nil, 1)"), "table index is nil"));
    EXPECT_TRUE(Contains(ErrorOf("rawget(1, 1)"), "bad argument #1 to `rawget' (table expected, got number)"));
  }

  TEST_F(LuaBaseLib, NextPairsIpairs)
  {
    EXPECT_TRUE(Run("return next({})").IsNil());
    EXPECT_EQ(Num("local k, v = next({7}) return k * 10 + v"), 17.0);
    EXPECT_EQ(Num(R"(
      local t = {10, 20, 30, a = 1, b = 2}
      local count, sum = 0, 0
      local k, v = next(t)
      while k do count = count + 1 sum = sum + v k, v = next(t, k) end
      return count * 1000 + sum)"), 5063.0);
    // ipairs stops at the first nil.
    EXPECT_EQ(Num("local n = 0 for i, v in ipairs({1, 2, nil, 4}) do n = n + 1 end return n"), 2.0);
    // pairs returns next, the table and nil.
    EXPECT_TRUE(Bool("local f, t, k = pairs({}) return f == next and type(t) == 'table' and k == nil"));
    // Clearing fields while traversing is allowed.
    EXPECT_EQ(Num(R"(
      local t = {}
      for i = 1, 50 do t['k' .. i] = i end
      for k in pairs(t) do t[k] = nil end
      return next(t) == nil and 1 or 0)"), 1.0);
    EXPECT_TRUE(Contains(ErrorOf("next({}, 'missing')"), "invalid key for `next'"));
    EXPECT_TRUE(Contains(ErrorOf("for k in pairs(nil) do end"), "bad argument #1 to `pairs'"));
  }

  TEST_F(LuaBaseLib, EnvironmentFunctions)
  {
    EXPECT_TRUE(Bool("return getfenv(0) == _G and getfenv(1) == _G"));
    EXPECT_TRUE(Bool("local function f() end return getfenv(f) == _G"));
    EXPECT_EQ(Num("local function f() return x end setfenv(f, {x = 3}) return f()"), 3.0);
    EXPECT_TRUE(Bool("local gf = getfenv local function f() local r = gf(1) return r end local e = {} setfenv(f, e) return f() == e"));
    EXPECT_TRUE(Contains(ErrorOf("setfenv(1, 2)"), "bad argument #2"));
    EXPECT_TRUE(Contains(ErrorOf("getfenv(-1)"), "level must be non-negative"));
    EXPECT_TRUE(Contains(ErrorOf("getfenv(50)"), "invalid level"));
    // A `__fenv` field protects an environment from setfenv.
    EXPECT_TRUE(Contains(ErrorOf("local function f() end setfenv(f, {__fenv = true}) setfenv(f, {})"), "cannot change a protected environment"));
    // ... and getfenv answers that field instead of the table.
    EXPECT_EQ(Str("local function f() end setfenv(f, {__fenv = 'hidden'}) return getfenv(f)"), "hidden");
  }

  TEST_F(LuaBaseLib, LoadstringCompilesChunks)
  {
    EXPECT_EQ(Num("local f = loadstring('return 6 * 7') return f()"), 42.0);
    EXPECT_EQ(Num("local f = loadstring('local a = 5 return a + 1') return f()"), 6.0);
    EXPECT_EQ(Num("loadstring('newglobal = 11')() return newglobal"), 11.0);
    EXPECT_TRUE(Bool("local f, e = loadstring('(') return f == nil and type(e) == 'string'"));
  }

  TEST_F(LuaBaseLib, GlobalsVersionAndGcinfo)
  {
    EXPECT_TRUE(Bool("return _G._G == _G"));
    EXPECT_EQ(Str("return _VERSION"), "Lua 5.0.1");
    EXPECT_TRUE(Bool("local count, threshold = gcinfo() return type(count) == 'number' and type(threshold) == 'number' and count > 0"));
    EXPECT_TRUE(Run("return collectgarbage()").IsNil());
    EXPECT_TRUE(Bool("return type(LOG) == 'cfunction' and type(_ALERT) == 'cfunction' and type(_TRACEBACK) == 'cfunction'"));
  }

  // States opened with LIB_BASE get the engine's mounted-file loaders instead of the stock ones.
  TEST_F(LuaBaseLib, GameStatesHaveNoIoOrOs)
  {
    EXPECT_TRUE(Run("return io").IsNil());
    EXPECT_TRUE(Run("return os").IsNil());
    EXPECT_TRUE(Run("return loadlib").IsNil());
  }

  // A state opened with LIB_OSIO (the start-up state) also gets io, os and loadlib. Only calls
  // that touch nothing outside the process: a temporary file, clocks and dates.
  class LuaBaseLibOsio : public ::testing::Test
  {
  protected:
    LuaPlus::LuaState state{LuaPlus::LuaState::LIB_OSIO};

    bool Check(const char* const source)
    {
      lua_State* const L = state.GetCState();
      const int top = lua_gettop(L);
      bool result = false;
      if (luaL_loadbuffer(L, source, std::char_traits<char>::length(source), "=osio") != 0 || LuaCallProtected(L, 0, 1) != 0) {
        ADD_FAILURE() << lua_tostring(L, -1) << "\nin: " << source;
      } else {
        result = lua_toboolean(L, -1) != 0;
      }
      lua_settop(L, top);
      return result;
    }
  };

  TEST_F(LuaBaseLibOsio, OpensIoOsAndLoadlib)
  {
    EXPECT_TRUE(Check("return type(io) == 'table' and type(io.open) == 'cfunction' and type(os.time) == 'cfunction' and type(loadlib) == 'cfunction'"));
    EXPECT_TRUE(Check("return os.difftime(10, 4) == 6 and type(os.clock()) == 'number' and type(os.time()) == 'number'"));
    EXPECT_TRUE(Check("return os.date('!%Y-%m-%d %H:%M:%S', 0) == '1970-01-01 00:00:00'"));
    EXPECT_TRUE(Check("local t = os.date('!*t', 86400 + 3600) return t.year == 1970 and t.month == 1 and t.day == 2 and t.hour == 1 and t.min == 0 and t.isdst == false"));
    EXPECT_TRUE(Check("return os.time({year = 2000, month = 1, day = 2, hour = 12}) - os.time({year = 2000, month = 1, day = 1, hour = 12}) == 86400"));
    EXPECT_TRUE(Check("local ok, e = pcall(os.time, {year = 2000}) return not ok and string.find(e, 'missing in date table', 1, true) ~= nil"));
    EXPECT_TRUE(Check("local r, e = os.remove('faf_lua_tests_no_such_file.tmp') return r == nil and type(e) == 'string'"));
    EXPECT_TRUE(Check("local f, e = io.open('faf_lua_tests_no_such_dir/x.txt', 'r') return f == nil and type(e) == 'string'"));
  }

  TEST_F(LuaBaseLibOsio, TemporaryFileReadWriteSeek)
  {
    EXPECT_TRUE(Check(R"(
      local f = io.tmpfile()
      if f == nil then return false end
      f:write('line1\n', 42, '\n', 'line3')
      f:seek('set')
      local a = f:read('*l')
      local n = f:read('*n')
      f:read('*l')
      local rest = f:read('*a')
      local size = f:seek('end')
      f:seek('set', 2)
      local two = f:read(3)
      local lines = 0
      f:seek('set')
      for l in f:lines() do lines = lines + 1 end
      local atEnd = f:read('*l')
      f:close()
      local closedOk = pcall(f.read, f)
      return a == 'line1' and n == 42 and rest == 'line3' and size == 14 and two == 'ne1' and lines == 3
         and atEnd == nil and not closedOk)"));
  }
} // namespace
