#include "moho/entity/intel/CIntelCounterHandleConstruct.h"

#include "moho/entity/intel/CIntelCounterHandle.h"

namespace moho
{
  /**
   * Address: 0x0076FBA0 (FUN_0076FBA0, gpg::SerConstructHelper_CIntelCounterHandle::Init)
   *
   * What it does:
   * Lazily resolves CIntelCounterHandle RTTI and installs construct/delete
   * callbacks from this helper into the type descriptor.
   */
  void CIntelCounterHandleConstruct::RegisterConstructFunction()
  {
    gpg::RType* const type = CIntelCounterHandle::StaticGetClass();
    GPG_ASSERT(type->serConstructFunc_ == nullptr);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }
} // namespace moho
