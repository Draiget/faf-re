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
   * VFTABLE: 0x00E25E60
   * COL: 0x00E7EC9C
   */
  class CEffectManagerImplSaveConstruct
  {
  public:
    /**
     * Address: 0x0066C060 (FUN_0066C060, gpg::SerSaveConstructHelper_CEffectManagerImpl::Init)
     *
     * IDA signature:
     * gpg::RType *__thiscall gpg::SerSaveConstructHelper_CEffectManagerImpl::Init(
     *   void (__cdecl **this)(gpg::WriteArchive *, void *, int version, int, gpg::SerConstructResult *));
     *
     * What it does:
     * Binds save-construct-args callback into `CEffectManagerImpl` RTTI.
     */
    virtual void RegisterSaveConstructArgsFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback;
  };

  static_assert(
    offsetof(CEffectManagerImplSaveConstruct, mHelperNext) == 0x04,
    "CEffectManagerImplSaveConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CEffectManagerImplSaveConstruct, mHelperPrev) == 0x08,
    "CEffectManagerImplSaveConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CEffectManagerImplSaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "CEffectManagerImplSaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(
    sizeof(CEffectManagerImplSaveConstruct) == 0x10, "CEffectManagerImplSaveConstruct size must be 0x10"
  );
} // namespace moho

