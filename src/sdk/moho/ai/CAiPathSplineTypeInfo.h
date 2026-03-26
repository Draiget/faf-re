#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CAiPathSpline;

  /**
   * VFTABLE: 0x00E1C8AC
   * COL:  0x00E72740
   */
  class CAiPathSplineTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005B23F0 (FUN_005B23F0, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~CAiPathSplineTypeInfo() override;

    /**
     * Address: 0x005B23E0 (FUN_005B23E0, ?GetName@CAiPathSplineTypeInfo@Moho@@UBEPBDXZ)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005B23A0 (FUN_005B23A0, ?Init@CAiPathSplineTypeInfo@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  static_assert(sizeof(CAiPathSplineTypeInfo) == 0x64, "CAiPathSplineTypeInfo size must be 0x64");
} // namespace moho
