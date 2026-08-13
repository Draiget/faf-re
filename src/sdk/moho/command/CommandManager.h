#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/Map.h"
#include "legacy/containers/Vector.h"
#include "moho/command/CmdDefs.h"
#include "moho/sim/IdPool.h"

namespace moho
{
  struct SSTICommandConstantData;
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
   * Everything below the map is the command-id pool: `IdPool` is exactly
   * 0xCB0 bytes and the source byte the recycler stamps ids with sits right
   * after it, which is how the issue path reaches them.
   */
  struct CommandManager
  {
    /// Recycling pool the manager draws command ids from.
    IdPool mIdPool;              // +0x0000
    /// Command-source byte; ids whose source matches are recycled locally.
    std::uint8_t mSourceId;      // +0x0CB0
    std::uint8_t pad_0CB1_0CB4[0x03];

    /// Live commands by id. Entries are owned by the manager.
    msvc8::map<CmdId, UserCommandIssueHelper*> mCommands; // +0x0CB4
  };

  static_assert(offsetof(CommandManager, mSourceId) == 0x0CB0, "CommandManager::mSourceId offset must be 0x0CB0");
  static_assert(offsetof(CommandManager, mCommands) == 0x0CB4, "CommandManager::mCommands offset must be 0x0CB4");
  static_assert(sizeof(CommandManager) == 0x0CC0, "CommandManager size must be 0x0CC0");

  /**
   * Address: 0x008B5A70 (FUN_008B5A70, struct_CommandManager::FindDataFor)
   *
   * What it does:
   * Returns the live helper for one command id, constructing and inserting one
   * when the manager does not have it yet and marking a reused helper's
   * variable data dirty.
   */
  [[nodiscard]] UserCommandIssueHelper* FindOrCreateCommandIssueHelper(
    CommandManager& commandManager,
    const SSTICommandConstantData& constantData,
    std::uint8_t deleteWhenDue,
    std::int32_t dueSeqNo
  );

  /**
   * Address: 0x008B5C20 (FUN_008B5C20, struct_CommandManager::DeleteCommands)
   *
   * What it does:
   * Deletes the command-issue helper for each supplied id and recycles the ids
   * that belong to this manager's source byte.
   */
  void DeleteCommandIssueHelpers(CommandManager& commandManager, const msvc8::vector<CmdId>& commandIds) noexcept;

  /**
   * Address: 0x008B5CF0 (FUN_008B5CF0)
   *
   * What it does:
   * Advances every command-issue helper to `beat`, then ticks the manager's
   * id-pool recycle history.
   */
  void AdvanceCommandIssueHelpersToBeat(CommandManager& commandManager, std::int32_t beat) noexcept;
} // namespace moho
