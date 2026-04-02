#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1B7CC
   * COL:  0x00E70DE0
   */
  class CAiBuilderImplTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0059FBB0 (FUN_0059FBB0, ctor)
     *
     * What it does:
     * Preregisters `CAiBuilderImpl` RTTI so lookup resolves to this type
     * helper.
     */
    CAiBuilderImplTypeInfo();

    /**
     * Address: 0x0059FC40 (FUN_0059FC40, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~CAiBuilderImplTypeInfo() override;

    /**
     * Address: 0x0059FC30 (FUN_0059FC30, ?GetName@CAiBuilderImplTypeInfo@Moho@@UBEPBDXZ)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0059FC10 (FUN_0059FC10, ?Init@CAiBuilderImplTypeInfo@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  static_assert(sizeof(CAiBuilderImplTypeInfo) == 0x64, "CAiBuilderImplTypeInfo size must be 0x64");

  /**
   * Address: 0x00BCC2C0 (FUN_00BCC2C0, register_CAiBuilderImplTypeInfo)
   *
   * What it does:
   * Constructs startup-owned `CAiBuilderImplTypeInfo` storage and installs
   * process-exit cleanup.
   */
  void register_CAiBuilderImplTypeInfo();

  /**
   * Address: 0x005A1F50 (FUN_005A1F50)
   *
   * What it does:
   * Constructs/preregisters reflection metadata for
   * `std::map<unsigned int,Moho::RUnitBlueprint const *>`.
   */
  [[nodiscard]] gpg::RType* preregister_CAiBuilderRebuildMapTypeInfo();

  /**
   * Address: 0x00BCC360 (FUN_00BCC360)
   *
   * What it does:
   * Preregisters builder rebuild-map RTTI and installs process-exit cleanup.
   */
  int register_CAiBuilderRebuildMapTypeInfo();

  /**
   * Address: 0x00BCC380 (FUN_00BCC380)
   *
   * What it does:
   * Installs process-exit cleanup for one startup-owned AI-builder stats slot.
   */
  int register_CAiBuilderStartupStatsCleanupPrimary();

  /**
   * Address: 0x00BCC3F0 (FUN_00BCC3F0)
   *
   * What it does:
   * Installs process-exit cleanup for a second startup-owned AI-builder stats
   * slot.
   */
  int register_CAiBuilderStartupStatsCleanupSecondary();
} // namespace moho
