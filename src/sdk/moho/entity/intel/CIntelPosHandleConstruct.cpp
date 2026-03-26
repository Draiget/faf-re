#include "moho/entity/intel/CIntelPosHandleConstruct.h"

#include "moho/entity/intel/CIntelPosHandle.h"

namespace moho
{
  /**
   * Address: 0x0076FA80 (FUN_0076FA80, gpg::SerConstructHelper_CIntelPosHandle::Init)
   *
   * What it does:
   * Lazily resolves CIntelPosHandle RTTI and installs construct/delete callbacks
   * from this helper into the type descriptor.
   */
  void CIntelPosHandleConstruct::RegisterConstructFunction()
  {
    gpg::RType* const type = CIntelPosHandle::StaticGetClass();
    GPG_ASSERT(type->serConstructFunc_ == nullptr);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }
} // namespace moho
