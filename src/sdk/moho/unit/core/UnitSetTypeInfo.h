#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E2D7BC
   * COL: 0x00E870C0
   */
  class UnitSetTypeInfo final : public gpg::RType
  {
  public:
    /**
       * Address: 0x006D28C0 (FUN_006D28C0)
     *
     * What it does:
     * Constructs/preregisters RTTI metadata for `EntitySetTemplate<Unit>`.
     */
    UnitSetTypeInfo();

    /**
     * Address: 0x006D2950 (FUN_006D2950, sub_6D2950)
     *
     * What it does:
     * Releases reflected base/field vectors for `UnitSetTypeInfo`.
     */
    ~UnitSetTypeInfo() override;

    /**
     * Address: 0x006D2940 (FUN_006D2940, sub_6D2940)
     *
     * What it does:
     * Returns `"UnitSet"` as the reflection type-name.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006D2920 (FUN_006D2920, sub_6D2920)
     *
     * What it does:
     * Sets size/version metadata, adds `EntitySetBase` as base, and finalizes type setup.
     */
    void Init() override;

  private:
    static void AddBase_EntitySetBaseVariant2(gpg::RType* typeInfo);
  };

  static_assert(sizeof(UnitSetTypeInfo) == 0x64, "UnitSetTypeInfo size must be 0x64");

  /**
   * Address: 0x00BFE3F0 (FUN_00BFE3F0, sub_BFE3F0)
   *
   * What it does:
   * Tears down the global `UnitSetTypeInfo` storage at process exit.
   */
  void cleanup_UnitSetTypeInfo();

  /**
   * Address: 0x00BD8460 (FUN_00BD8460, sub_BD8460)
   *
   * What it does:
   * Constructs global `UnitSetTypeInfo` and registers exit cleanup.
   */
  int register_UnitSetTypeInfo();
} // namespace moho
