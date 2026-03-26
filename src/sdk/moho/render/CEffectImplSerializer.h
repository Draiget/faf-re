#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
}

namespace moho
{
  class CEffectImplSerializer
  {
  public:
    /**
     * Address: 0x0065A2C0 (FUN_0065A2C0, gpg::SerSaveLoadHelper_CEffectImpl::Init)
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CEffectImplSerializer, mHelperNext) == 0x04, "CEffectImplSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CEffectImplSerializer, mHelperPrev) == 0x08, "CEffectImplSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CEffectImplSerializer, mLoadCallback) == 0x0C, "CEffectImplSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CEffectImplSerializer, mSaveCallback) == 0x10, "CEffectImplSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CEffectImplSerializer) == 0x14, "CEffectImplSerializer size must be 0x14");
} // namespace moho

