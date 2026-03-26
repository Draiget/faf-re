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
   * VFTABLE: 0x00E25E80
   * COL: 0x00E7EB44
   */
  class CEffectManagerImplSerializer
  {
  public:
    /**
     * Address: 0x0066C160 (FUN_0066C160, gpg::SerSaveLoadHelper_CEffectManagerImpl::Init)
     *
     * IDA signature:
     * void (__cdecl *__thiscall gpg::SerSaveLoadHelper_CEffectManagerImpl::Init(
     *   void (__cdecl **this)(gpg::WriteArchive *, void *obj, int version, const gpg::RRef *a5)))
     * (gpg::ReadArchive *arch, void *obj, int cont, gpg::RRef *res);
     *
     * What it does:
     * Binds load/save serializer callbacks into `CEffectManagerImpl` RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CEffectManagerImplSerializer, mHelperNext) == 0x04,
    "CEffectManagerImplSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CEffectManagerImplSerializer, mHelperPrev) == 0x08,
    "CEffectManagerImplSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CEffectManagerImplSerializer, mLoadCallback) == 0x0C,
    "CEffectManagerImplSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CEffectManagerImplSerializer, mSaveCallback) == 0x10,
    "CEffectManagerImplSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CEffectManagerImplSerializer) == 0x14, "CEffectManagerImplSerializer size must be 0x14");
} // namespace moho

