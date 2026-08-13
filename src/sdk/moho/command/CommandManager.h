#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/Map.h"
#include "moho/command/CmdDefs.h"

namespace moho
{
  struct UserCommandIssueHelper;

  /**
   * The session-wide command manager, reached through
   * `CWldSession::mCommandManager` (+0x3FC).
   *
   * Layout evidence: `sub_8B6C50` loads the manager out of
   * `sWldSession+0x3FC`, then looks commands up in the ordered map at
   * `+0x0CB4` whose head sits at `+0x0CB8` (0x008B6CE9 / 0x008B6CF8) and whose
   * nodes carry the helper pointer at node `+0x10` (0x008B6D06) - the standard
   * MSVC8 `map` shape. `CWldSession::DoBeat` and the right-click dispatcher
   * read the same map at the same offset.
   *
   * Everything before the map is still unmapped, so it stays one padding run
   * rather than a guess.
   */
  struct CommandManager
  {
    std::uint8_t pad_0000_0CB4[0xCB4];

    /// Live commands by id. Entries are owned by the manager.
    msvc8::map<CmdId, UserCommandIssueHelper*> mCommands; // +0x0CB4
  };

  static_assert(offsetof(CommandManager, mCommands) == 0x0CB4, "CommandManager::mCommands offset must be 0x0CB4");
  static_assert(sizeof(CommandManager) == 0x0CC0, "CommandManager size must be 0x0CC0");
} // namespace moho
