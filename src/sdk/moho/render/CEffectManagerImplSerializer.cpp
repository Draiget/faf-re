#include "moho/render/CEffectManagerImplSerializer.h"

#include "moho/render/CEffectManagerImpl.h"

namespace moho
{
  /**
   * Address: 0x0066C160 (FUN_0066C160, gpg::SerSaveLoadHelper_CEffectManagerImpl::Init)
   *
   * IDA signature:
   * void (__cdecl *__thiscall gpg::SerSaveLoadHelper_CEffectManagerImpl::Init(
   *   void (__cdecl **this)(gpg::WriteArchive *, void *obj, int version, const gpg::RRef *a5)))
   * (gpg::ReadArchive *arch, void *obj, int cont, gpg::RRef *res);
   */
  void CEffectManagerImplSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CEffectManagerImpl::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho

