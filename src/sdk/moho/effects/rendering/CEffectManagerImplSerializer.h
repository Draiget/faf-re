#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E25E80
   * COL: 0x00E7EB44
   */
  class CEffectManagerImplSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD4600 (FUN_00BD4600, register_CEffectManagerImplSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list) and binds
     * the load/save callback fields. Confirmed from raw disassembly: calls
     * `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7CEffectManagerImplSerializer@Moho@@6B@` -- no eager `Init()` call
     * exists here. The trailing `atexit` push is the compiler registering the
     * destructor.
     */
    CEffectManagerImplSerializer();

    /**
     * Address: 0x00BFC060 (FUN_00BFC060, dynamic atexit destructor for `gCEffectManagerImplSerializer`)
     *
     * What it does:
     * Unlinks this helper node from the serializer-helper list (the
     * `TDatListItem` base destructor). The compiler registers it with
     * `atexit` from the global's dynamic initializer (0x00BD4600).
     * `FUN_0066BC20` and `FUN_0066BC50` are
     * unreferenced out-of-line copies of the same body.
     */
    ~CEffectManagerImplSerializer();

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
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

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
