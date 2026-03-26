#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E19914
   * COL:  0x00E6E9C0
   */
  class CAiBrainTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00579BB0 (FUN_00579BB0, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~CAiBrainTypeInfo() override;

    /**
     * Address: 0x00579BA0 (FUN_00579BA0, ?GetName@CAiBrainTypeInfo@Moho@@UBEPBDXZ)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00579B80 (FUN_00579B80, ?Init@CAiBrainTypeInfo@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  static_assert(sizeof(CAiBrainTypeInfo) == 0x64, "CAiBrainTypeInfo size must be 0x64");
} // namespace moho
