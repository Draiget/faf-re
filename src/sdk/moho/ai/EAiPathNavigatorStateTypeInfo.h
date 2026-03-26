#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1C674
   * COL:  0x00E72584
   */
  class EAiPathNavigatorStateTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x005AD2D0 (FUN_005AD2D0, scalar deleting thunk)
     */
    ~EAiPathNavigatorStateTypeInfo() override;

    /**
     * Address: 0x005AD2C0 (FUN_005AD2C0)
     *
     * What it does:
     * Returns the reflection type name literal for EAiPathNavigatorState.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005AD2A0 (FUN_005AD2A0)
     *
     * What it does:
     * Writes enum width and finalizes metadata.
     */
    void Init() override;
  };

  static_assert(sizeof(EAiPathNavigatorStateTypeInfo) == 0x78, "EAiPathNavigatorStateTypeInfo size must be 0x78");
} // namespace moho
