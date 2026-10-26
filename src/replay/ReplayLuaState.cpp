// Engine addition, server mode (plan WPR.12): see ReplayLuaState.h.

#include "replay/ReplayLuaState.h"

#include "lua/LuaObject.h"

#if !FAF_REPLAY_SIM_ONLY
#include "moho/ui/UiRuntimeTypes.h"
#endif

namespace faf::replay
{
  LuaPlus::LuaState* ReplayLuaState()
  {
#if FAF_REPLAY_SIM_ONLY
    static LuaPlus::LuaState sState(LuaPlus::LuaState::LIB_BASE);
    return &sState;
#else
    return moho::USER_GetLuaState();
#endif
  }
} // namespace faf::replay
