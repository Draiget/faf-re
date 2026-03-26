#include "moho/render/CEffectManagerImplConstruct.h"

#include "moho/render/CEffectManagerImpl.h"

namespace moho
{
  /**
   * Address: 0x0066C0E0 (FUN_0066C0E0, gpg::SerConstructHelper_CEffectManagerImpl::Init)
   *
   * IDA signature:
   * int __thiscall gpg::SerConstructHelper_CEffectManagerImpl::Init(void (__cdecl **this)(void *));
   */
  void CEffectManagerImplConstruct::RegisterConstructFunction()
  {
    gpg::RType* const type = CEffectManagerImpl::StaticGetClass();
    GPG_ASSERT(type->serConstructFunc_ == nullptr);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }
} // namespace moho

