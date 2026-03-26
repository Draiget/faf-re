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
} // namespace moho

