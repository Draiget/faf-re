#include "moho/sim/CArmyStatItemSerializer.h"

#include "moho/sim/CArmyStats.h"

namespace moho
{
  /**
   * Address: 0x0070EEE0 (FUN_0070EEE0, gpg::SerSaveLoadHelper_CArmyStatItem::Init)
   *
   * IDA signature:
   * void (__cdecl *__thiscall sub_70EEE0(void (__cdecl **this)(...)))(...);
   */
  void CArmyStatItemSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CArmyStatItem::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho
