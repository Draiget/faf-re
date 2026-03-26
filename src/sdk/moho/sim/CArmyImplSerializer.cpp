#include "moho/sim/CArmyImplSerializer.h"

#include "moho/sim/CArmyImpl.h"

namespace moho
{
  /**
   * Address: 0x00701DD0 (FUN_00701DD0, gpg::SerSaveLoadHelper_CArmyImpl::Init)
   *
   * IDA signature:
   * void (__cdecl *__thiscall sub_701DD0(void (__cdecl **this)(...)))(...);
   */
  void CArmyImplSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CArmyImpl::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho
