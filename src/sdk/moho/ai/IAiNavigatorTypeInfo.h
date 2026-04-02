#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1C038
   * COL:  0x00E71908
   */
  class IAiNavigatorTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005A3190 (FUN_005A3190, ctor)
     *
     * What it does:
     * Preregisters `IAiNavigator` RTTI so lookup resolves to this type helper.
     */
    IAiNavigatorTypeInfo();

    /**
     * Address: 0x005A3220 (FUN_005A3220, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~IAiNavigatorTypeInfo() override;

    /**
     * Address: 0x005A3210 (FUN_005A3210, ?GetName@IAiNavigatorTypeInfo@Moho@@UBEPBDXZ)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005A31F0 (FUN_005A31F0, ?Init@IAiNavigatorTypeInfo@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  static_assert(sizeof(IAiNavigatorTypeInfo) == 0x64, "IAiNavigatorTypeInfo size must be 0x64");

  /**
   * Address: 0x00BCC6A0 (FUN_00BCC6A0)
   *
   * What it does:
   * Constructs startup-owned `IAiNavigatorTypeInfo` storage and installs
   * process-exit cleanup.
   */
  int register_IAiNavigatorTypeInfo();
} // namespace moho

