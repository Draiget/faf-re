#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CEffectImplTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x006597F0 (FUN_006597F0, Moho::CEffectImplTypeInfo::dtr)
     */
    ~CEffectImplTypeInfo() override;

    /**
     * Address: 0x006597E0 (FUN_006597E0, Moho::CEffectImplTypeInfo::GetName)
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x006597B0 (FUN_006597B0, Moho::CEffectImplTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x0065A750 (FUN_0065A750, Moho::CEffectImplTypeInfo::AddBase_IEffect)
     */
    static void AddBase_IEffect(gpg::RType* typeInfo);
  };

  static_assert(sizeof(CEffectImplTypeInfo) == 0x64, "CEffectImplTypeInfo size must be 0x64");

  /**
   * Address: 0x00659750 (FUN_00659750, register_CEffectImplTypeInfo_00)
   *
   * What it does:
   * Constructs/preregisters startup RTTI metadata for `moho::CEffectImpl`.
   */
  gpg::RType* register_CEffectImplTypeInfo_00();

  /**
   * Address: 0x00BFB9C0 (FUN_00BFB9C0, cleanup_CEffectImplTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `CEffectImplTypeInfo` reflection storage.
   */
  void cleanup_CEffectImplTypeInfo();

  /**
   * Address: 0x00BD40C0 (FUN_00BD40C0, register_CEffectImplTypeInfo_AtExit)
   *
   * What it does:
   * Registers `CEffectImpl` RTTI bootstrap and installs process-exit cleanup.
   */
  int register_CEffectImplTypeInfo_AtExit();
} // namespace moho
