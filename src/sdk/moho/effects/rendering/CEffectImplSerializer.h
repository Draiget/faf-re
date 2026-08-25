#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E23E3C
   */
  class CEffectImplSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD40E0 (FUN_00BD40E0, register_CEffectImplSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list) and
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7CEffectImplSerializer@Moho@@6B@` -- no eager `Init()` call exists
     * here. Its atexit target is the plain (unmangled) free function
     * `cleanup_CEffectImplSerializer`, already correctly named from a prior
     * recovery pass, so it stays an explicit `std::atexit` registration
     * rather than becoming an implicit destructor (see `ReconBlipSerializer`
     * for the same variant).
     */
    CEffectImplSerializer();

    /**
     * Address: 0x006598A0 (FUN_006598A0, Moho::CEffectImplSerializer::Deserialize)
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006598B0 (FUN_006598B0, Moho::CEffectImplSerializer::Serialize)
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0065A2C0 (FUN_0065A2C0, gpg::SerSaveLoadHelper_CEffectImpl::Init)
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(CEffectImplSerializer, mLoadCallback) == 0x0C, "CEffectImplSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CEffectImplSerializer, mSaveCallback) == 0x10, "CEffectImplSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CEffectImplSerializer) == 0x14, "CEffectImplSerializer size must be 0x14");
} // namespace moho
