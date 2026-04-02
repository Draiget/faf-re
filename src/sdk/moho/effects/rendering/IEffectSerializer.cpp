#include "moho/effects/rendering/IEffectSerializer.h"

#include "moho/effects/rendering/IEffect.h"

namespace moho
{
  /**
   * Address: 0x007712D0 (FUN_007712D0, gpg::SerSaveLoadHelper_IEffect::Init)
   *
   * IDA signature:
   * void (__cdecl *__thiscall gpg::SerSaveLoadHelper_IEffect::Init(_DWORD *this))
   * (gpg::ReadArchive *, int, int, gpg::RRef *);
   */
  void IEffectSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = IEffect::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho

