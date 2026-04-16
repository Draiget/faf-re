#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E2D7FC
   * COL: 0x00E86FC4
   */
  class WeakUnitSetTypeInfo final : public gpg::RType
  {
  public:
    /**
       * Address: 0x006D2B10 (FUN_006D2B10)
     *
     * What it does:
     * Constructs/preregisters RTTI metadata for `WeakEntitySetTemplate<Unit>`.
     */
    WeakUnitSetTypeInfo();

    /**
     * Address: 0x006D2BA0 (FUN_006D2BA0, sub_6D2BA0)
     *
     * What it does:
     * Releases reflected base/field vectors for `WeakUnitSetTypeInfo`.
     */
    ~WeakUnitSetTypeInfo() override;

    /**
     * Address: 0x006D2B90 (FUN_006D2B90, sub_6D2B90)
     *
     * What it does:
     * Returns `"WeakUnitSet"` as the reflection type-name.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006D2B70 (FUN_006D2B70, sub_6D2B70)
     *
     * What it does:
     * Sets size/version metadata, adds `EntitySetTemplate<Unit>` as base, and finalizes type setup.
     */
    void Init() override;

  private:
    static void AddBase_UnitSet(gpg::RType* typeInfo);
  };

  static_assert(sizeof(WeakUnitSetTypeInfo) == 0x64, "WeakUnitSetTypeInfo size must be 0x64");

  /**
   * Address: 0x00BFE480 (FUN_00BFE480, sub_BFE480)
   *
   * What it does:
   * Tears down global `WeakUnitSetTypeInfo` storage at process exit.
   */
  void cleanup_WeakUnitSetTypeInfo();

  /**
   * Address: 0x00BD84C0 (FUN_00BD84C0, sub_BD84C0)
   *
   * What it does:
   * Constructs global `WeakUnitSetTypeInfo` and registers exit cleanup.
   */
  int register_WeakUnitSetTypeInfo();
} // namespace moho
