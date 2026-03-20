#pragma once

#include <cstdint>

#include "legacy/containers/Map.h"
#include "moho/command/CmdDefs.h"
#include "moho/sim/IdPool.h"
#include "moho/unit/CUnitCommand.h"

namespace moho
{
  class Sim;

  class CCommandDb
  {
  public:
    Sim* sim;
    msvc8::map<CmdId, CUnitCommand> commands;
    // Legacy map node/proxy bookkeeping occupies +0x14..+0x1F in the binary layout.
    std::uint8_t pad_0014[0x0C];
    IdPool pool;
  };

  static_assert(sizeof(CCommandDb) == 0xCD0, "CCommandDb size must be 0xCD0");
} // namespace moho
