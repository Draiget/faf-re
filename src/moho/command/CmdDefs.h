#pragma once
#include <cstdint>

namespace moho
{
  using CmdId = int32_t;

  // A player's slot in the command stream (`CMDST_SetCommandSource`); one byte
  // on the wire, 0xFF for none.
  using CommandSourceId = uint32_t;
} // namespace moho
