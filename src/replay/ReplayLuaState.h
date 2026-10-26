#pragma once

namespace LuaPlus
{
  class LuaState;
} // namespace LuaPlus

// Engine addition, server mode (plan WPR.12): the Lua state faf-replay decodes sync packets
// and launch configs into. faf-replay links only the simulation's objects and has no user
// Lua state, so it keeps a plain one of its own (base library only: the sync and config
// values are plain Lua data). `faf-replay-full`, which links the client too, uses the user
// state as faf-replay did before (`USER_GetLuaState`).

namespace faf::replay
{
  [[nodiscard]] LuaPlus::LuaState* ReplayLuaState();
} // namespace faf::replay
