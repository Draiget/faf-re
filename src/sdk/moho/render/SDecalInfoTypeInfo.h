#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * Reflection type descriptor for the world decal descriptor `moho::SDecalInfo`.
   */
  class SDecalInfoTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00778CD0 (FUN_00778CD0, construct-and-preregister worker)
     *
     * What it does:
     * Preregisters `SDecalInfo` RTTI so lookup resolves to this type helper.
     */
    SDecalInfoTypeInfo();

    /**
     * Address: 0x00778D60 (FUN_00778D60, scalar deleting thunk)
     * Slot: 2
     */
    ~SDecalInfoTypeInfo() override;

    /**
     * Address: 0x00778D50 (FUN_00778D50)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type name literal for SDecalInfo.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00778D30 (FUN_00778D30)
     * Slot: 9
     *
     * What it does:
     * Writes `size_` for SDecalInfo, then performs base-init/finalization.
     */
    void Init() override;
  };

  static_assert(sizeof(SDecalInfoTypeInfo) == 0x64, "SDecalInfoTypeInfo size must be 0x64");

  /**
   * Address: 0x00BDD800 (FUN_00BDD800, register_SDecalInfoTypeInfo)
   *
   * What it does:
   * Registers the `SDecalInfo` type-info object and installs process-exit cleanup.
   */
  int register_SDecalInfoTypeInfo();
} // namespace moho
