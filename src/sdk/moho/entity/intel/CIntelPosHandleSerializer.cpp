#include "moho/entity/intel/CIntelPosHandleSerializer.h"

#include "moho/entity/intel/CIntelPosHandle.h"

namespace moho
{
  /**
   * Address: 0x0076FB00 (FUN_0076FB00, gpg::SerSaveLoadHelper_CIntelPosHandle::Init)
   *
   * What it does:
   * Lazily resolves CIntelPosHandle RTTI and installs load/save callbacks
   * from this helper into the type descriptor.
   */
  void CIntelPosHandleSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CIntelPosHandle::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho
