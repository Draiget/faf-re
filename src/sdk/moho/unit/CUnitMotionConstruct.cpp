#include "moho/unit/CUnitMotionConstruct.h"

#include "moho/unit/CUnitMotion.h"

namespace moho
{
  /**
   * Address: 0x006BA7F0 (FUN_006BA7F0, gpg::SerConstructHelper_CUnitMotion::Init)
   *
   * IDA signature:
   * void (__cdecl *__thiscall sub_6BA7F0(void (__cdecl **this)(void *)))(...);
   */
  void CUnitMotionConstruct::RegisterConstructFunction()
  {
    gpg::RType* const type = CUnitMotion::StaticGetClass();
    GPG_ASSERT(type->serConstructFunc_ == nullptr);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }
} // namespace moho
