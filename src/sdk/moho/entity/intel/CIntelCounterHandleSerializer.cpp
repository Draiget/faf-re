#include "moho/entity/intel/CIntelCounterHandleSerializer.h"

#include "moho/entity/intel/CIntelCounterHandle.h"

namespace moho
{
  /**
   * Address: 0x0076FC20 (FUN_0076FC20, gpg::SerSaveLoadHelper_CIntelCounterHandle::Init)
   *
   * What it does:
   * Lazily resolves CIntelCounterHandle RTTI and installs load/save callbacks
   * from this helper into the type descriptor.
   */
  void CIntelCounterHandleSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CIntelCounterHandle::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho
