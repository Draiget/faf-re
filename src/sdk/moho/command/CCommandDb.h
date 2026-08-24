#pragma once

#include <cstdint>

#include "legacy/containers/Map.h"
#include "legacy/containers/Vector.h"
#include "moho/command/CmdDefs.h"
#include "moho/sim/IdPool.h"
#include "moho/unit/CUnitCommand.h"

namespace moho
{
  class Sim;
}

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{

  class CCommandDb
  {
  public:
    /**
     * Address: 0x006E09C0 (FUN_006E09C0, ??0CommandDatabase@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes one command DB with its owning Sim and container/id-pool lanes.
     *
     * Sentinel allocation (0x006E2840, FUN_006E2840, sub_6E2840):
     * The binary buys the command map's header/sentinel node through a raw
     * node allocator (isNil=0 by default), then this constructor's own body
     * patches isNil=1 and self-links left/parent/right before zeroing
     * `_Mysize` - the same split-allocator shape as
     * `AllocateAllUnitsTreeNode`/`InitializeAllUnitsTreeHeadLane` in
     * EntityDb.cpp. Here the split is fused inside `commands`'s own default
     * construction: `msvc8::map`'s shared `detail::rb_tree` default
     * constructor (legacy/containers/RbTree.h) calls `rb_tree::buy_head()`,
     * which performs the identical alloc + self-link + isNil=1/color=black
     * sequence, so no separate call is needed in this constructor's body.
     *
     * `pendingReleasedCmdIds` (binary's `this->vec`):
     * Declared at +0x0CC0, immediately after `pool`'s 0x0CB0-byte `IdPool`
     * span, closing the struct out exactly at the asserted 0xCD0 size.
     * `msvc8::vector<CmdId>`'s default constructor already zeroes
     * `_Myfirst`/`_Mylast`/`_Myend`, matching the binary's explicit
     * zero-stores.
     */
    explicit CCommandDb(Sim* sim);

    /**
     * Address: 0x006E0A70 (FUN_006E0A70, ??1CommandDatabase@Moho@@QAE@@Z)
     *
     * What it does:
     * Validates destruction preconditions for command ownership, emits a fatal
     * diagnostic dump when commands remain, and releases command-db runtime
     * map/id-pool storage lanes.
     */
    ~CCommandDb();

    Sim* sim;                                     // +0x0000
    /**
     * Command id -> owned command lookup.
     *
     * The binary's node is the standard `msvc8::map` shape `{left,parent,right,
     * key@0x0C, CUnitCommand*@0x10, color@0x14, isnil@0x15}` (0x18 bytes), and
     * the container itself is the shipped 12-byte `{proxy,_Myhead,_Mysize}`
     * triplet ending at +0x0F with the id pool starting at +0x10. The RB-tree
     * mechanics (insert/erase/traversal) for this exact instantiation are
     * address-cited on `legacy/containers/RbTree.h`'s canonical
     * `detail::rb_tree` members (`insert_unique` FUN_006E15B0, `insert_at`
     * FUN_006E1D60, `buy_node` FUN_006E23F0, `rotate_left`/`rotate_right`
     * FUN_006E1F20/FUN_006E1FD0, `erase_range` FUN_006E22D0, `destroy_subtree`
     * FUN_006E2990, `~rb_tree` FUN_006E0A70) rather than on a bespoke tree
     * reimplementation in CCommandDb.cpp.
     */
    msvc8::map<CmdId, CUnitCommand*> commands;    // +0x0004
    IdPool pool;                                  // +0x0010
    msvc8::vector<CmdId> pendingReleasedCmdIds;   // +0x0CC0

    /**
     * Address: 0x006E1430 (FUN_006E1430, Moho::CCommandDB::MemberDeserialize)
     *
     * What it does:
     * Reads owned `CUnitCommand` pointer lanes from archive, assigns recovered
     * command ids from the id-pool, and inserts each command into the command map.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x006E0DB0 (FUN_006E0DB0, Moho::CommandDatabase::AddIssueData)
     *
     * What it does:
     * Resolves a command id for `issueData`, constructs one `CUnitCommand`,
     * inserts it into the command database map, and returns the new command.
     */
    [[nodiscard]] CUnitCommand* AddIssueData(SSTICommandIssueData issueData);

    /**
     * Address: 0x006E13A0 (FUN_006E13A0, Moho::CCommandDB::MemberSerialize)
     *
     * What it does:
     * Serializes each command-db entry as an owned tracked `CUnitCommand`
     * pointer and emits the terminating null pointer lane.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x006E0F50 (FUN_006E0F50)
     *
     * What it does:
     * Publishes per-command sync event deltas into `syncData`, swaps pending
     * released command-id lanes into the outgoing packet, then advances id-pool
     * recycle state for the next beat.
     */
    void PublishSyncData(SSyncData* syncData, bool forceRefresh);
  };

  static_assert(offsetof(CCommandDb, sim) == 0x0000, "CCommandDb::sim offset must be 0x0000");
  static_assert(offsetof(CCommandDb, commands) == 0x0004, "CCommandDb::commands offset must be 0x0004");
  static_assert(offsetof(CCommandDb, pool) == 0x0010, "CCommandDb::pool offset must be 0x0010");
  static_assert(
    offsetof(CCommandDb, pendingReleasedCmdIds) == 0x0CC0,
    "CCommandDb::pendingReleasedCmdIds offset must be 0x0CC0"
  );
  static_assert(sizeof(CCommandDb) == 0xCD0, "CCommandDb size must be 0xCD0");
} // namespace moho
