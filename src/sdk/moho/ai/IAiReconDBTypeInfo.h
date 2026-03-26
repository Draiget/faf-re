#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1DAB4
   * COL:  0x00E73D38
   */
  class IAiReconDBTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005C2700 (FUN_005C2700, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~IAiReconDBTypeInfo() override;

    /**
     * Address: 0x005C26F0 (FUN_005C26F0)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005C26D0 (FUN_005C26D0)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  static_assert(sizeof(IAiReconDBTypeInfo) == 0x64, "IAiReconDBTypeInfo size must be 0x64");
} // namespace moho
