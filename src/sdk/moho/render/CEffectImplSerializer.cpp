#include "moho/render/CEffectImplSerializer.h"

#include "moho/render/CEffectImpl.h"

namespace moho
{
  /**
   * Address: 0x0065A2C0 (FUN_0065A2C0, gpg::SerSaveLoadHelper_CEffectImpl::Init)
   */
  void CEffectImplSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CEffectImpl::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho

