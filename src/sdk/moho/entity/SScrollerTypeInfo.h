#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * Reflection type descriptor for the texture-scroll lane descriptor `moho::SScroller`.
   */
  class SScrollerTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00777330 (FUN_00777330, construct-and-preregister worker)
     *
     * What it does:
     * Preregisters `SScroller` RTTI so lookup resolves to this type helper.
     */
    SScrollerTypeInfo();

    /**
     * Address: 0x007773C0 (FUN_007773C0, scalar deleting thunk)
     * Slot: 2
     */
    ~SScrollerTypeInfo() override;

    /**
     * Address: 0x007773B0 (FUN_007773B0)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type name literal for SScroller.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00777390 (FUN_00777390)
     * Slot: 9
     *
     * What it does:
     * Writes `size_` for SScroller, then performs base-init/finalization.
     */
    void Init() override;
  };

  static_assert(sizeof(SScrollerTypeInfo) == 0x64, "SScrollerTypeInfo size must be 0x64");

  /**
   * Address: 0x00BDD6D0 (FUN_00BDD6D0, register_SScrollerTypeInfo)
   *
   * What it does:
   * Registers the `SScroller` type-info object and installs process-exit cleanup.
   */
  int register_SScrollerTypeInfo();
} // namespace moho
