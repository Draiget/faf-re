#include "moho/render/CEffectManagerImplSaveConstruct.h"

#include "moho/render/CEffectManagerImpl.h"

namespace moho
{
  /**
   * Address: 0x0066C060 (FUN_0066C060, gpg::SerSaveConstructHelper_CEffectManagerImpl::Init)
   *
   * IDA signature:
   * gpg::RType *__thiscall gpg::SerSaveConstructHelper_CEffectManagerImpl::Init(
   *   void (__cdecl **this)(gpg::WriteArchive *, void *, int version, int, gpg::SerConstructResult *));
   */
  void CEffectManagerImplSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* const type = CEffectManagerImpl::StaticGetClass();
    GPG_ASSERT(type->serSaveConstructArgsFunc_ == nullptr);
    type->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }
} // namespace moho

