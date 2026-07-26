#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * Reflection type descriptor for the formation offset-slot descriptor `moho::SOffsetInfo`.
   */
  class SOffsetInfoTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x005663C0 (FUN_005663C0, construct-and-preregister worker)
     *
     * What it does:
     * Preregisters `SOffsetInfo` RTTI so lookup resolves to this type helper.
     */
    SOffsetInfoTypeInfo();

    /**
     * Address: 0x00566450 (FUN_00566450, scalar deleting thunk)
     * Slot: 2
     */
    ~SOffsetInfoTypeInfo() override;

    /**
     * Address: 0x00566440 (FUN_00566440)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type name literal for SOffsetInfo.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00566420 (FUN_00566420)
     * Slot: 9
     *
     * What it does:
     * Writes `size_` for SOffsetInfo, then performs base-init/finalization.
     */
    void Init() override;
  };

  static_assert(sizeof(SOffsetInfoTypeInfo) == 0x64, "SOffsetInfoTypeInfo size must be 0x64");

  /**
   * Address: 0x00BCAB00 (FUN_00BCAB00, register_SOffsetInfoTypeInfo)
   *
   * What it does:
   * Registers the `SOffsetInfo` type-info object and installs process-exit cleanup.
   */
  int register_SOffsetInfoTypeInfo();
} // namespace moho
