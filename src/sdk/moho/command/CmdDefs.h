#pragma once
#include <cstdint>

namespace moho
{
  typedef int32_t CmdId;

  // A player's slot in the command stream (`CMDST_SetCommandSource`); one byte
  // on the wire, 0xFF for none.
  using CommandSourceId = uint32_t;
}
