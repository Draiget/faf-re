// The Lua debugger's breakpoint list and state hooks (src/moho/misc/ScrDebugHooks.cpp, ScrBreakpoint.cpp), as the
// debug window drives them: add (sorted, no duplicates), enable one or all, remove one or all, enumerate per source
// file (only while any breakpoint is enabled), the "enabled:line:name" text form, and hooking a Lua state with no
// debug window open, which leaves the script running. With no preferences loaded the list is saved into in-memory
// defaults, so no file is touched.

#include "LuaTestSupport.h"

#include "moho/misc/ScrBreakpoint.h"
#include "moho/misc/ScrDebugHooks.h"

#include <gtest/gtest.h>

#include <set>

namespace
{
  std::set<int> LinesOf(
    const char* const source
  )
  {
    fa::vector<moho::ScrBreakpoint> found;
    moho::SCR_EnumerateBreakpoints(fa::string(source), found);
    std::set<int> lines;
    for (const moho::ScrBreakpoint& breakpoint : found) {
      lines.insert(breakpoint.line);
    }
    return lines;
  }
} // namespace

// SCR_AddBreakpoint (0x004B4A30) keeps one entry per (file, line); SCR_EnumerateBreakpoints (0x004B4D20) lists one
// file's while any breakpoint is enabled.
TEST(
  ScrDebugHooks,
  BreakpointsAreAddedOncePerLineAndListedPerFile
)
{
  moho::SCR_RemoveAllBreakpoints();
  moho::SCR_AddBreakpoint(moho::ScrBreakpoint(fa::string("/lua/a.lua"), 10));
  moho::SCR_AddBreakpoint(moho::ScrBreakpoint(fa::string("/lua/a.lua"), 5));
  moho::SCR_AddBreakpoint(moho::ScrBreakpoint(fa::string("/lua/a.lua"), 10));
  moho::SCR_AddBreakpoint(moho::ScrBreakpoint(fa::string("/lua/b.lua"), 7));

  EXPECT_EQ(LinesOf("/lua/a.lua"), (std::set<int>{5, 10}));
  EXPECT_EQ(LinesOf("/lua/b.lua"), (std::set<int>{7}));
  EXPECT_TRUE(LinesOf("/lua/c.lua").empty());
  moho::SCR_RemoveAllBreakpoints();
}

// SCR_EnableBreakpoint (0x004B4AC0) and SCR_EnableAllBreakpoints (0x004B4B50): with none enabled the enumeration is
// empty; enabling any brings the file's whole list back, disabled entries included.
TEST(
  ScrDebugHooks,
  NothingIsListedWhileEveryBreakpointIsDisabled
)
{
  moho::SCR_RemoveAllBreakpoints();
  const moho::ScrBreakpoint first(fa::string("/lua/a.lua"), 3);
  const moho::ScrBreakpoint second(fa::string("/lua/a.lua"), 4);
  moho::SCR_AddBreakpoint(first);
  moho::SCR_AddBreakpoint(second);

  moho::SCR_EnableBreakpoint(first, false);
  EXPECT_EQ(LinesOf("/lua/a.lua"), (std::set<int>{3, 4}));

  moho::SCR_EnableAllBreakpoints(false);
  EXPECT_TRUE(LinesOf("/lua/a.lua").empty());

  moho::SCR_EnableBreakpoint(second, true);
  EXPECT_EQ(LinesOf("/lua/a.lua"), (std::set<int>{3, 4}));

  moho::SCR_EnableAllBreakpoints(true);
  moho::SCR_RemoveBreakpoint(first);
  EXPECT_EQ(LinesOf("/lua/a.lua"), (std::set<int>{4}));
  moho::SCR_RemoveBreakpoint(first); // gone already: nothing happens
  EXPECT_EQ(LinesOf("/lua/a.lua"), (std::set<int>{4}));

  moho::SCR_RemoveAllBreakpoints();
  EXPECT_TRUE(LinesOf("/lua/a.lua").empty());
}

// ScrBreakpoint::AsString (0x004B03A0) writes "enabled:line:name"; FromString (0x004B0240) reads exactly three
// ':'-separated fields and leaves the breakpoint as it was otherwise.
TEST(
  ScrDebugHooks,
  BreakpointTextRoundTrips
)
{
  moho::ScrBreakpoint written(fa::string("/lua/sim/unit.lua"), 42);
  written.enabled = false;
  EXPECT_STREQ(written.AsString().c_str(), "disabled:42:/lua/sim/unit.lua");

  moho::ScrBreakpoint read;
  read.FromString(written.AsString());
  EXPECT_FALSE(read.enabled);
  EXPECT_EQ(read.line, 42);
  EXPECT_STREQ(read.name.c_str(), "/lua/sim/unit.lua");

  read.FromString(fa::string("enabled:7:/x.lua"));
  EXPECT_TRUE(read.enabled);
  EXPECT_EQ(read.line, 7);
  EXPECT_STREQ(read.name.c_str(), "/x.lua");

  read.FromString(fa::string("enabled:9")); // two fields: unchanged
  EXPECT_EQ(read.line, 7);
  EXPECT_STREQ(read.name.c_str(), "/x.lua");

  const moho::ScrBreakpoint blank;
  EXPECT_FALSE(blank.enabled);
  EXPECT_EQ(blank.line, -1);
}

// SCR_HookState (0x004B49B0) installs the debug hook; with no debug window open the hook removes itself
// (DebugLuaHook, 0x004B5B10) and the script runs on. SCR_UnhookState (0x004B49D0) drops the state again.
using faf_lua_tests::LuaFixture;

TEST_F(
  LuaFixture,
  HookedStateRunsWithoutADebugWindow
)
{
  ASSERT_FALSE(moho::SCR_IsDebugWindowActive());
  moho::SCR_AddBreakpoint(moho::ScrBreakpoint(fa::string("=chunk"), 1));
  moho::SCR_HookState(&state);
  EXPECT_DOUBLE_EQ(Num("local total = 0\nfor i = 1, 10 do total = total + i end\nreturn total"), 55.0);
  moho::SCR_UnhookState(&state);
  EXPECT_DOUBLE_EQ(Num("return 6 * 7"), 42.0);
  moho::SCR_RemoveAllBreakpoints();
}
