#include "moho/render/CDecalHandleSerializer.h"

#include "moho/render/CDecalHandle.h"

namespace moho
{
  /**
   * Address: 0x0077ABC0 (FUN_0077ABC0, gpg::SerSaveLoadHelper_CDecalHandle::Init)
   */
  void CDecalHandleSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CDecalHandle::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho
