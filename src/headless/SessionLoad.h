#pragma once

#include <initializer_list>
#include <string>
#include <string_view>

#include "lua/LuaObject.h"

namespace moho
{
  class CWldMap;
  class RRuleGameRules;
  class STIMap;
  struct SSyncData;
  struct SWldGameData;
  struct SWldSessionInfo;
} // namespace moho

// Engine addition, server mode: the world session's loading steps that the sim needs, for what runs
// a sim with no world session: headless, and the dedicated server (plan WP1.2).

namespace faf::headless
{
  /**
   * `WLD_DoPreload`, `WLD_DoLoading`: the session loader builds rules, session Lua state and map on
   * its worker thread. False, with `error` set, if the map doesn't load.
   */
  [[nodiscard]] bool LoadSessionScenario(moho::SWldSessionInfo& sessionInfo, moho::SWldGameData& gameData, std::string& error);

  /**
   * The launch info, completed as `WLD_DoLoading` completes it from the world session. Returns the
   * map it now holds.
   */
  moho::STIMap* CompleteSessionLaunchInfo(moho::SWldSessionInfo& sessionInfo, moho::RRuleGameRules& rules, moho::CWldMap& map, LuaPlus::LuaState& sessionState);

  /** Whether a packet's encoded `Sync` holds `text`. Leaves the packet's stream at its start. */
  [[nodiscard]] bool SyncBytesContain(moho::SSyncData& packet, std::string_view text);

  /** Decodes a packet's `Sync` into `sync` if its bytes hold one of `names`, as most beats need no decoding. */
  [[nodiscard]] bool ReadSyncNaming(moho::SSyncData& packet, LuaPlus::LuaState* state, std::initializer_list<std::string_view> names, LuaPlus::LuaObject& sync);

  /** Whether a packet's `Sync` says the game has ended. Decodes it only if its bytes name that. */
  [[nodiscard]] bool SyncSaysGameEnded(moho::SSyncData& packet, LuaPlus::LuaState* state);
} // namespace faf::headless
