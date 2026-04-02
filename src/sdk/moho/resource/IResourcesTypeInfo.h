#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E171F4
   * COL: 0x00E6B5E8
   */
  class IResourcesTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00546D30 (FUN_00546D30, Moho::IResourcesTypeInfo::IResourcesTypeInfo)
     *
     * What it does:
     * Initializes base reflection state and preregisters RTTI ownership for
     * `IResources`.
     */
    IResourcesTypeInfo();

    /**
     * Address: 0x00546DC0 (FUN_00546DC0, Moho::IResourcesTypeInfo::dtr)
     * Slot: 2
     */
    ~IResourcesTypeInfo() override;

    /**
     * Address: 0x00546DB0 (FUN_00546DB0, Moho::IResourcesTypeInfo::GetName)
     * Slot: 3
     *
     * What it does:
     * Returns reflection type-name literal for `IResources`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00546D90 (FUN_00546D90, Moho::IResourcesTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Initializes reflection metadata for `IResources` (`sizeof = 0x04`).
     */
    void Init() override;
  };

  /**
   * Address: 0x00BC97B0 (FUN_00BC97B0, register_IResourcesTypeInfo)
   *
   * What it does:
   * Constructs startup-owned `IResourcesTypeInfo` storage and registers
   * process-exit teardown.
   */
  void register_IResourcesTypeInfo();

  static_assert(sizeof(IResourcesTypeInfo) == 0x64, "IResourcesTypeInfo size must be 0x64");
} // namespace moho
