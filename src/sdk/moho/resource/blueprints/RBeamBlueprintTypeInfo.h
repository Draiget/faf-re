#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class RBeamBlueprintTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0050FA30 (FUN_0050FA30, Moho::RBeamBlueprintTypeInfo::RBeamBlueprintTypeInfo)
     */
    RBeamBlueprintTypeInfo();

    /**
     * Address: 0x0050FAF0 (FUN_0050FAF0, Moho::RBeamBlueprintTypeInfo::dtr)
     */
    ~RBeamBlueprintTypeInfo() override;

    /**
     * Address: 0x0050FAE0 (FUN_0050FAE0, Moho::RBeamBlueprintTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0050FA90 (FUN_0050FA90, Moho::RBeamBlueprintTypeInfo::Init)
     */
    void Init() override;

    /**
     * Address: 0x0050FB90 (FUN_0050FB90, Moho::RBeamBlueprintTypeInfo::AddFields)
     */
    static void AddFields(gpg::RType* typeInfo);
  };

  /**
   * Address: 0x00BC80B0 (FUN_00BC80B0, register_RBeamBlueprintTypeInfo)
   */
  void register_RBeamBlueprintTypeInfo();

  static_assert(sizeof(RBeamBlueprintTypeInfo) == 0x64, "RBeamBlueprintTypeInfo size must be 0x64");
} // namespace moho
