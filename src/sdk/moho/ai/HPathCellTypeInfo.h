#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * Reflection type descriptor for the path-graph cell handle `moho::HPathCell`.
   */
  class HPathCellTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00762E40 (FUN_00762E40, construct-and-preregister worker)
     *
     * What it does:
     * Preregisters `HPathCell` RTTI so lookup resolves to this type helper.
     */
    HPathCellTypeInfo();

    /**
     * Address: 0x00762ED0 (FUN_00762ED0, scalar deleting thunk)
     * Slot: 2
     */
    ~HPathCellTypeInfo() override;

    /**
     * Address: 0x00762EC0 (FUN_00762EC0)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type name literal for HPathCell.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00762EA0 (FUN_00762EA0)
     * Slot: 9
     *
     * What it does:
     * Writes `size_` for HPathCell, then performs base-init/finalization.
     */
    void Init() override;
  };

  static_assert(sizeof(HPathCellTypeInfo) == 0x64, "HPathCellTypeInfo size must be 0x64");

  /**
   * Address: 0x00BDC610 (FUN_00BDC610, register_HPathCellTypeInfo)
   *
   * What it does:
   * Registers the `HPathCell` type-info object and installs process-exit cleanup.
   */
  int register_HPathCellTypeInfo();
} // namespace moho
