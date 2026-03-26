#include "moho/sim/SimArmySerializer.h"

#include "moho/sim/SimArmy.h"

namespace moho
{
  /**
   * Address: 0x00701610 (FUN_00701610, gpg::SerSaveLoadHelper_SimArmy::Init)
   *
   * IDA signature:
   * void (__cdecl *__thiscall sub_701610(void (__cdecl **this)(...)))(...);
   */
  void SimArmySerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = SimArmy::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho
