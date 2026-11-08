// Shared fixture for faf_lua_tests: a root Lua state opened the way the game opens its states
// (LuaState::Init with LIB_BASE: base, coroutine, table with FAF's additions, serialize, string,
// math, debug), and helpers that compile and run a chunk and read its first result back.
//
// Every chunk is named "=test", so a position in an error reads "test(<line>): ". That spelling is
// the fork's, not stock Lua's "test:<line>:": luaL_where (0x0090DB80) pushes "%s(%d): " and addinfo
// (0x00912F30) "%s(%d): %s".
#pragma once

#include <string>
#include <gtest/gtest.h>

#include "lua/LuaObject.h"
#include "lua/LuaPrimitives.h"

namespace faf_lua_tests
{
  class LuaFixture : public ::testing::Test
  {
  protected:
    LuaPlus::LuaState state{LuaPlus::LuaState::LIB_BASE};

    [[nodiscard]] lua_State* L() const { return state.GetCState(); }

    /** Compiles and runs `source`, returning its first result (nil when it returns nothing). A load or run error fails the test. */
    LuaPlus::LuaObject Run(const std::string& source);

    /** Runs `source` and returns its first result, which must be a string. */
    std::string Str(const std::string& source);

    /** Runs `source` and returns its first result, which must be a number. */
    double Num(const std::string& source);

    /** Runs `source` and returns its first result, which must be a boolean. */
    bool Bool(const std::string& source);

    /** The message `source` fails with, from loading or from running it. Empty, and a test failure, when it succeeds. */
    std::string ErrorOf(const std::string& source);

    /** Only compiles `source`: 0 when it loads, else the status, with the message in `message`. */
    int Load(const std::string& source, std::string* message = nullptr);
  };

  /**
   * An error message up to its first line break. luaopen_debug installs `_TRACEBACK`, and
   * luaG_errormsg passes every message through it (LuaObjectVm.inl), so a raised string arrives
   * with "\nstack traceback:..." appended.
   */
  [[nodiscard]] inline std::string FirstLine(const std::string& text)
  {
    return text.substr(0, text.find('\n'));
  }

  /** True when `text` contains `part`. */
  [[nodiscard]] inline bool Contains(const std::string& text, const std::string& part)
  {
    return text.find(part) != std::string::npos;
  }
} // namespace faf_lua_tests
