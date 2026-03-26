#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E20C60
   * COL: 0x00E7A024
   */
  class CUnitScriptTaskTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00622DE0 (FUN_00622DE0, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~CUnitScriptTaskTypeInfo() override;

    /**
     * Address: 0x00622DD0 (FUN_00622DD0, ?GetName@CUnitScriptTaskTypeInfo@Moho@@UBEPBDXZ)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00622D80 (FUN_00622D80, ?Init@CUnitScriptTaskTypeInfo@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  static_assert(sizeof(CUnitScriptTaskTypeInfo) == 0x64, "CUnitScriptTaskTypeInfo size must be 0x64");
} // namespace moho

