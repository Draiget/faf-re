#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E25E60
   * COL: 0x00E7EC9C
   */
  class CEffectManagerImplSaveConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD4590 (FUN_00BD4590, register_CEffectManagerImplSaveConstruct)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list) and
     * binds the save-construct-args callback field. Confirmed from raw
     * disassembly: calls `gpg::SerHelperBase::SerHelperBase()` directly,
     * then installs `??_7CEffectManagerImplSaveConstruct@Moho@@6B@` -- no
     * eager `Init()` call exists here. Its atexit target is the plain
     * (unmangled) free function `cleanup_CEffectManagerImplSaveConstruct`,
     * already correctly named from a prior recovery pass, so it stays an
     * explicit `std::atexit` registration rather than becoming an implicit
     * destructor (see `ReconBlipSerializer` for the same variant).
     */
    CEffectManagerImplSaveConstruct();

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
    void Init() override;

  public:
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback; // +0x0C
  };

  static_assert(
    offsetof(CEffectManagerImplSaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "CEffectManagerImplSaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(sizeof(CEffectManagerImplSaveConstruct) == 0x10, "CEffectManagerImplSaveConstruct size must be 0x10");
} // namespace moho
