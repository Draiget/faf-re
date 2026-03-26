#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1DE08
   * COL:  0x00E7493C
   */
  class CAiSiloBuildImplTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005CF700 (FUN_005CF700, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~CAiSiloBuildImplTypeInfo() override;

    /**
     * Address: 0x005CF6F0 (FUN_005CF6F0, ?GetName@CAiSiloBuildImplTypeInfo@Moho@@UBEPBDXZ)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005CF6D0 (FUN_005CF6D0, ?Init@CAiSiloBuildImplTypeInfo@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  static_assert(sizeof(CAiSiloBuildImplTypeInfo) == 0x64, "CAiSiloBuildImplTypeInfo size must be 0x64");
} // namespace moho
