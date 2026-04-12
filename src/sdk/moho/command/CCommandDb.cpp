#include "moho/command/CCommandDb.h"

namespace moho
{
  /**
   * Address: 0x006E09C0 (FUN_006E09C0, ??0CommandDatabase@Moho@@QAE@@Z)
   *
   * What it does:
   * Initializes one command database with its owning Sim and empty
   * container/id-pool lanes.
   */
  CCommandDb::CCommandDb(Sim* const sim)
    : sim(sim)
    , commands()
    , pool()
  {
  }
} // namespace moho
