#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1C3DC
   * COL:  0x00E720F0
   */
  class CAiPathFinderTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005AAB60 (FUN_005AAB60, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~CAiPathFinderTypeInfo() override;

    /**
     * Address: 0x005AAB50 (FUN_005AAB50, ?GetName@CAiPathFinderTypeInfo@Moho@@UBEPBDXZ)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005AAB00 (FUN_005AAB00, ?Init@CAiPathFinderTypeInfo@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  static_assert(sizeof(CAiPathFinderTypeInfo) == 0x64, "CAiPathFinderTypeInfo size must be 0x64");
} // namespace moho
