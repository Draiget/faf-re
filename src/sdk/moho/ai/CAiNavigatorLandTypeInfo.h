#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1C0C0
   * COL:  0x00E716C4
   */
  class CAiNavigatorLandTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005A4560 (FUN_005A4560, ctor)
     *
     * What it does:
     * Preregisters `CAiNavigatorLand` RTTI so lookup resolves to this type
     * helper.
     */
    CAiNavigatorLandTypeInfo();

    /**
     * Address: 0x005A45F0 (FUN_005A45F0, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~CAiNavigatorLandTypeInfo() override;

    /**
     * Address: 0x005A45E0 (FUN_005A45E0, ?GetName@CAiNavigatorLandTypeInfo@Moho@@UBEPBDXZ)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005A45C0 (FUN_005A45C0, ?Init@CAiNavigatorLandTypeInfo@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  static_assert(sizeof(CAiNavigatorLandTypeInfo) == 0x64, "CAiNavigatorLandTypeInfo size must be 0x64");

  /**
   * Address: 0x00BCC780 (FUN_00BCC780)
   *
   * What it does:
   * Constructs startup-owned `CAiNavigatorLandTypeInfo` storage and installs
   * process-exit cleanup.
   */
  int register_CAiNavigatorLandTypeInfo();
} // namespace moho
