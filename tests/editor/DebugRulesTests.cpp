// The Script Editor's debugger's rules (src/editor/EdDebugRules.cpp): which chunk is which file, and where a step
// stops.

#include "editor/EdLuaDebugger.h"

#include <gtest/gtest.h>

using faf::editor::EdStepMode;
using faf::editor::ShouldPause;
using faf::editor::SourceIsFile;

namespace
{
  TEST(
    DebugRules,
    AChunkIsAFileByItsName
  )
  {
    EXPECT_TRUE(SourceIsFile("@/maps/scmp_009/SCMP_009_script.lua", "scmp_009_script.lua")) << "case aside";
    EXPECT_TRUE(SourceIsFile("@c:\\maps\\x\\x_script.lua", "x_script.lua")) << "either slash";
    EXPECT_TRUE(SourceIsFile("x_script.lua", "x_script.lua"));
    EXPECT_FALSE(SourceIsFile("@/maps/x/my_x_script.lua", "x_script.lua")) << "the whole name, not its end";
    EXPECT_FALSE(SourceIsFile("@/lua/sim/ScenarioUtilities.lua", "x_script.lua"));
    EXPECT_FALSE(SourceIsFile("@/maps/x/x_script.lua", ""));
  }

  TEST(
    DebugRules,
    WhereAStepStops
  )
  {
    // Running: only at breakpoints.
    EXPECT_FALSE(ShouldPause(EdStepMode::Run, 3, 0, false));
    EXPECT_TRUE(ShouldPause(EdStepMode::Run, 3, 0, true));
    // Into: the next line anywhere.
    EXPECT_TRUE(ShouldPause(EdStepMode::Into, 5, 3, false));
    // Over: not inside a call made from the line (deeper), the next line here or after a return.
    EXPECT_FALSE(ShouldPause(EdStepMode::Over, 4, 3, false));
    EXPECT_TRUE(ShouldPause(EdStepMode::Over, 3, 3, false));
    EXPECT_TRUE(ShouldPause(EdStepMode::Over, 2, 3, false));
    EXPECT_TRUE(ShouldPause(EdStepMode::Over, 4, 3, true)) << "a breakpoint inside the call still stops";
    // Out: only above where the step began.
    EXPECT_FALSE(ShouldPause(EdStepMode::Out, 3, 3, false));
    EXPECT_TRUE(ShouldPause(EdStepMode::Out, 2, 3, false));
  }
} // namespace
