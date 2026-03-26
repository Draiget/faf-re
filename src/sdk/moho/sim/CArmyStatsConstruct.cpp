#include "moho/sim/CArmyStatsConstruct.h"

#include "moho/sim/CArmyStats.h"

namespace moho
{
  /**
   * Address: 0x0070F560 (FUN_0070F560, gpg::SerConstructHelper_CArmyStats::Init)
   *
   * IDA signature:
   * void (__cdecl *__thiscall sub_70F560(void (__cdecl **this)(void *)))(...);
   */
  void CArmyStatsConstruct::RegisterConstructFunction()
  {
    gpg::RType* const type = CArmyStats::StaticGetClass();
    GPG_ASSERT(type->serConstructFunc_ == nullptr);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }
} // namespace moho
