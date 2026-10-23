#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1C078
   * COL:  0x00E7180C
   */
  class CAiNavigatorImplTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005A3880 (FUN_005A3880, ctor)
     *
     * What it does:
     * Preregisters `CAiNavigatorImpl` RTTI so lookup resolves to this type
     * helper.
     */
    CAiNavigatorImplTypeInfo();

    /**
     * Address: 0x005A3930 (FUN_005A3930, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~CAiNavigatorImplTypeInfo() override;

    /**
     * Address: 0x005A3920 (FUN_005A3920, ?GetName@CAiNavigatorImplTypeInfo@Moho@@UBEPBDXZ)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005A38E0 (FUN_005A38E0, ?Init@CAiNavigatorImplTypeInfo@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  static_assert(sizeof(CAiNavigatorImplTypeInfo) == 0x64, "CAiNavigatorImplTypeInfo size must be 0x64");

  /**
   * Address: 0x00BCC700 (FUN_00BCC700, register_CAiNavigatorImplTypeInfo)
   *
   * What it does:
   * Constructs startup-owned `CAiNavigatorImplTypeInfo` storage and installs
   * process-exit cleanup.
   */
  void register_CAiNavigatorImplTypeInfo();
} // namespace moho

