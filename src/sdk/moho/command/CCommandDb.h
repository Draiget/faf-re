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

    Sim* sim;
    msvc8::map<CmdId, CUnitCommand> commands;
    // Legacy map node/proxy bookkeeping occupies +0x14..+0x1F in the binary layout.
    std::uint8_t pad_0014[0x0C];
    IdPool pool;

    void MemberDeserialize(gpg::ReadArchive* archive);
    void MemberSerialize(gpg::WriteArchive* archive) const;
  };

  static_assert(sizeof(CCommandDb) == 0xCD0, "CCommandDb size must be 0xCD0");
} // namespace moho
