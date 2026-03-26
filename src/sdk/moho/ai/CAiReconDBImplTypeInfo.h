#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1DAE4
   * COL:  0x00E73CE8
   */
  class CAiReconDBImplTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005C2860 (FUN_005C2860, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~CAiReconDBImplTypeInfo() override;

    /**
     * Address: 0x005C2850 (FUN_005C2850)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005C2810 (FUN_005C2810)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  static_assert(sizeof(CAiReconDBImplTypeInfo) == 0x64, "CAiReconDBImplTypeInfo size must be 0x64");
} // namespace moho
