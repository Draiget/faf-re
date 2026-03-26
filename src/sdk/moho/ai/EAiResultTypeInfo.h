#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E20240
   * COL:  0x00E78BF0
   */
  class EAiResultTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x00608C00 (FUN_00608C00, scalar deleting thunk)
     */
    ~EAiResultTypeInfo() override;

    /**
     * Address: 0x00608BF0 (FUN_00608BF0)
     *
     * What it does:
     * Returns the reflection type name literal for EAiResult.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00608BD0 (FUN_00608BD0)
     *
     * What it does:
     * Writes enum width and finalizes metadata.
     */
    void Init() override;
  };

  static_assert(sizeof(EAiResultTypeInfo) == 0x78, "EAiResultTypeInfo size must be 0x78");
} // namespace moho
