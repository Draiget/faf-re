// Engine addition, server mode (plan WPR.12): see ReplayLuaState.h.

#include "headless/ReplayLuaState.h"

#include "lua/LuaObject.h"

namespace faf::headless
{
  LuaPlus::LuaState* ReplayLuaState()
  {
    static LuaPlus::LuaState sState(LuaPlus::LuaState::LIB_BASE);
    return &sState;
  }
} // namespace faf::headless
