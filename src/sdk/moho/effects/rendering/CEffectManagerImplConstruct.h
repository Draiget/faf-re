#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E25E70
   * COL: 0x00E7EBF0
   */
  class CEffectManagerImplConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD45C0 (FUN_00BD45C0, register_CEffectManagerImplConstruct)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list) and binds
     * the construct/delete callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7CEffectManagerImplConstruct@Moho@@6B@` -- no eager `Init()` call
     * exists here. The trailing `atexit` push is the compiler registering the
     * destructor.
     */
    CEffectManagerImplConstruct();

    /**
     * Address: 0x00BFC030 (FUN_00BFC030, dynamic atexit destructor for `gCEffectManagerImplConstruct`)
     *
     * What it does:
     * Unlinks this helper node from the serializer-helper list (the
     * `TDatListItem` base destructor). The compiler registers it with
     * `atexit` from the global's dynamic initializer (0x00BD45C0).
     * `FUN_0066BAE0` and `FUN_0066BB10` are
     * unreferenced out-of-line copies of the same body.
     */
    ~CEffectManagerImplConstruct();

    /**
     * Address: 0x0066C0E0 (FUN_0066C0E0, gpg::SerConstructHelper_CEffectManagerImpl::Init)
     *
     * IDA signature:
     * int __thiscall gpg::SerConstructHelper_CEffectManagerImpl::Init(void (__cdecl **this)(void *));
     *
     * What it does:
     * Binds construct/delete callbacks into `CEffectManagerImpl` RTTI.
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback; // +0x0C
    gpg::RType::delete_func_t mDeleteCallback;        // +0x10
  };

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
