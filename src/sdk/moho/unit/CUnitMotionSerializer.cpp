#include "moho/unit/CUnitMotionSerializer.h"

#include "moho/unit/CUnitMotion.h"

namespace moho
{
  /**
   * Address: 0x006BA870 (FUN_006BA870, gpg::SerSaveLoadHelper_CUnitMotion::Init)
   *
   * IDA signature:
   * void (__cdecl *__thiscall sub_6BA870(void (__cdecl **this)(...)))(...);
   */
  void CUnitMotionSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CUnitMotion::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho
