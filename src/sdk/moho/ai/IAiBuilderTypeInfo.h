#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1B70C
   * COL:  0x00E70ECC
   */
  class IAiBuilderTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0059ED90 (FUN_0059ED90, ctor)
     *
     * What it does:
     * Preregisters `IAiBuilder` RTTI so lookup resolves to this type helper.
     */
    IAiBuilderTypeInfo();

    /**
     * Address: 0x0059EE20 (FUN_0059EE20, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~IAiBuilderTypeInfo() override;

    /**
     * Address: 0x0059EE10 (FUN_0059EE10, ?GetName@IAiBuilderTypeInfo@Moho@@UBEPBDXZ)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0059EDF0 (FUN_0059EDF0, ?Init@IAiBuilderTypeInfo@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  static_assert(sizeof(IAiBuilderTypeInfo) == 0x64, "IAiBuilderTypeInfo size must be 0x64");

  /**
   * Address: 0x00BCC2A0 (FUN_00BCC2A0)
   *
   * What it does:
   * Constructs startup-owned `IAiBuilderTypeInfo` storage and installs
   * process-exit cleanup.
   */
  int register_IAiBuilderTypeInfo();
} // namespace moho
