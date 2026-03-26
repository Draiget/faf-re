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
   * VFTABLE: 0x00E25E70
   * COL: 0x00E7EBF0
   */
  class CEffectManagerImplConstruct
  {
  public:
    /**
     * Address: 0x0066C0E0 (FUN_0066C0E0, gpg::SerConstructHelper_CEffectManagerImpl::Init)
     *
     * IDA signature:
     * int __thiscall gpg::SerConstructHelper_CEffectManagerImpl::Init(void (__cdecl **this)(void *));
     *
     * What it does:
     * Binds construct/delete callbacks into `CEffectManagerImpl` RTTI.
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(
    offsetof(CEffectManagerImplConstruct, mHelperNext) == 0x04,
    "CEffectManagerImplConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CEffectManagerImplConstruct, mHelperPrev) == 0x08,
    "CEffectManagerImplConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CEffectManagerImplConstruct, mConstructCallback) == 0x0C,
    "CEffectManagerImplConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CEffectManagerImplConstruct, mDeleteCallback) == 0x10,
    "CEffectManagerImplConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(CEffectManagerImplConstruct) == 0x14, "CEffectManagerImplConstruct size must be 0x14");
} // namespace moho

