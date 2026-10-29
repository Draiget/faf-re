// Engine addition (dedicated-server plan WPL.4, WPR.11): WLD_LoadScenarioInfo,
// the engine's scenario-file loader, moved unchanged out of CWldSession.cpp:
// the lobby's launch builder (LaunchInfoBuilder.cpp) and the game server use it
// without a user world.

#include "legacy/containers/String.h"
#include "lua/LuaObject.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/sim/CWldSession.h"
namespace moho
{
  /**
   * Address: 0x0088BD40 (FUN_0088BD40)
   */
  LuaPlus::LuaObject WLD_LoadScenarioInfo(const msvc8::string& scenarioFile, LuaPlus::LuaState* const state)
  {
    if (state == nullptr) {
      return {};
    }

    LuaPlus::LuaObject scenarioEnv(state);
    if (FILE_GetFileInfo(scenarioFile.c_str(), nullptr, false)) {
      // Both scripts run with `scenarioEnv` as their globals table, so the
      // scenario file's top-level `ScenarioInfo = {...}` lands in it rather
      // than in _G. This is the engine's own loader (VFS resolution + hook
      // concatenation + setfenv); routing it through the Lua-level `doscript`
      // binding instead loses the C++ error propagation the caller relies on.
      scenarioEnv.AssignNewTable(state, 0, 0);
      (void)SCR_LuaDoScript(state, "/lua/dataInit.lua", &scenarioEnv);
      (void)SCR_LuaDoScript(state, scenarioFile.c_str(), &scenarioEnv);
    }

    if (scenarioEnv.IsNil()) {
      return scenarioEnv;
    }

    return scenarioEnv["ScenarioInfo"];
  }

} // namespace moho
