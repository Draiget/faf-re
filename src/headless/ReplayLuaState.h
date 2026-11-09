#pragma once

namespace LuaPlus
{
  class LuaState;
} // namespace LuaPlus

// Engine addition, server mode (plan WPR.12): the Lua state headless decodes sync packets
// and launch configs into. headless links only the simulation's objects and has no user
// Lua state, so it keeps a plain one of its own (base library only: the sync and config
// values are plain Lua data).

namespace faf::headless
{
  [[nodiscard]] LuaPlus::LuaState* ReplayLuaState();
} // namespace faf::headless
