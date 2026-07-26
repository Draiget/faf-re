#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * Reflection type descriptor for the transport pickup-candidate entry `moho::SPickUpInfo`.
   */
  class SPickUpInfoTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x006246D0 (FUN_006246D0, construct-and-preregister worker)
     *
     * What it does:
     * Preregisters `SPickUpInfo` RTTI so lookup resolves to this type helper.
     */
    SPickUpInfoTypeInfo();

    /**
     * Address: 0x00624760 (FUN_00624760, scalar deleting thunk)
     * Slot: 2
     */
    ~SPickUpInfoTypeInfo() override;

    /**
     * Address: 0x00624750 (FUN_00624750)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type name literal for SPickUpInfo.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00624730 (FUN_00624730)
     * Slot: 9
     *
     * What it does:
     * Writes `size_` for SPickUpInfo, then performs base-init/finalization.
     */
    void Init() override;
  };

  static_assert(sizeof(SPickUpInfoTypeInfo) == 0x64, "SPickUpInfoTypeInfo size must be 0x64");

  /**
   * Address: 0x00BD1C30 (FUN_00BD1C30, register_SPickUpInfoTypeInfo)
   *
   * What it does:
   * Registers the `SPickUpInfo` type-info object and installs process-exit cleanup.
   */
  int register_SPickUpInfoTypeInfo();
} // namespace moho
