#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E36BC4
   * COL: 0x00E900F4
   */
  class IEffectSerializer
  {
  public:
    /**
     * Address: 0x007712D0 (FUN_007712D0, gpg::SerSaveLoadHelper_IEffect::Init)
     *
     * IDA signature:
     * void (__cdecl *__thiscall gpg::SerSaveLoadHelper_IEffect::Init(_DWORD *this))
     * (gpg::ReadArchive *, int, int, gpg::RRef *);
     *
     * What it does:
     * Binds load/save serializer callbacks into `IEffect` RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(offsetof(IEffectSerializer, mHelperNext) == 0x04, "IEffectSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(IEffectSerializer, mHelperPrev) == 0x08, "IEffectSerializer::mHelperPrev offset must be 0x08");
  static_assert(
    offsetof(IEffectSerializer, mLoadCallback) == 0x0C, "IEffectSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(IEffectSerializer, mSaveCallback) == 0x10, "IEffectSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(IEffectSerializer) == 0x14, "IEffectSerializer size must be 0x14");
} // namespace moho

