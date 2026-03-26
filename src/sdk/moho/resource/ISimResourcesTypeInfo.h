#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E17224
   * COL: 0x00E6B598
   */
  class ISimResourcesTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00546F80 (FUN_00546F80, Moho::ISimResourcesTypeInfo::dtr)
     * Slot: 2
     */
    ~ISimResourcesTypeInfo() override;

    /**
     * Address: 0x00546F70 (FUN_00546F70, Moho::ISimResourcesTypeInfo::GetName)
     * Slot: 3
     *
     * What it does:
     * Returns reflection type-name literal for `ISimResources`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00546F50 (FUN_00546F50, Moho::ISimResourcesTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Initializes `ISimResources` reflection metadata and registers
     * `IResources` as base metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x005488F0 (FUN_005488F0, Moho::ISimResourcesTypeInfo::AddBase_IResources)
     *
     * What it does:
     * Registers `IResources` as reflection base metadata at offset `0`.
     */
    static void AddBase_IResources(gpg::RType* typeInfo);
  };

  static_assert(sizeof(ISimResourcesTypeInfo) == 0x64, "ISimResourcesTypeInfo size must be 0x64");
} // namespace moho
