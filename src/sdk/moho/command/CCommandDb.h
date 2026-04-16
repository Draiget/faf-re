#pragma once

#include <cstdint>

#include "legacy/containers/Map.h"
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

    Sim* sim;
    msvc8::map<CmdId, CUnitCommand> commands;
    // Legacy map node/proxy bookkeeping occupies +0x14..+0x1F in the binary layout.
    std::uint8_t pad_0014[0x0C];
    IdPool pool;

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

  static_assert(sizeof(CCommandDb) == 0xCD0, "CCommandDb size must be 0xCD0");
} // namespace moho
