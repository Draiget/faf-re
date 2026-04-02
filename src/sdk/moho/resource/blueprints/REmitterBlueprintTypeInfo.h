#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class REmitterBlueprintTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0050F460 (FUN_0050F460, Moho::REmitterBlueprintTypeInfo::REmitterBlueprintTypeInfo)
     */
    REmitterBlueprintTypeInfo();

    /**
     * Address: 0x0050F520 (FUN_0050F520, Moho::REmitterBlueprintTypeInfo::dtr)
     */
    ~REmitterBlueprintTypeInfo() override;

    /**
     * Address: 0x0050F510 (FUN_0050F510, Moho::REmitterBlueprintTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0050F4C0 (FUN_0050F4C0, Moho::REmitterBlueprintTypeInfo::Init)
     */
    void Init() override;

    /**
     * Address: 0x0050F5C0 (FUN_0050F5C0, Moho::REmitterBlueprintTypeInfo::AddFields)
     */
    static void AddFields(gpg::RType* typeInfo);
  };

  /**
   * Address: 0x00BC8090 (FUN_00BC8090, register_REmitterBlueprintTypeInfo)
   */
  void register_REmitterBlueprintTypeInfo();

  static_assert(sizeof(REmitterBlueprintTypeInfo) == 0x64, "REmitterBlueprintTypeInfo size must be 0x64");
} // namespace moho

