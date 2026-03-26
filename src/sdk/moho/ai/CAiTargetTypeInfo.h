#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1ED24
   * COL:  0x00E762B8
   */
  class CAiTargetTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005E2570 (FUN_005E2570, scalar deleting thunk)
     */
    ~CAiTargetTypeInfo() override;

    /**
     * Address: 0x005E2560 (FUN_005E2560)
     *
     * What it does:
     * Returns the reflection type name literal for CAiTarget.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005E2540 (FUN_005E2540)
     *
     * What it does:
     * Writes `size_` for CAiTarget, then performs base-init/finalization.
     */
    void Init() override;
  };

  static_assert(sizeof(CAiTargetTypeInfo) == 0x64, "CAiTargetTypeInfo size must be 0x64");
} // namespace moho
