#include "moho/sim/CArmyStatsSerializer.h"

#include "moho/sim/CArmyStats.h"

namespace moho
{
  /**
   * Address: 0x0070F5E0 (FUN_0070F5E0, gpg::SerSaveLoadHelper_CArmyStats::Init)
   *
   * IDA signature:
   * void (__cdecl *__thiscall sub_70F5E0(void (__cdecl **this)(...)))(...);
   */
  void CArmyStatsSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CArmyStats::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho
