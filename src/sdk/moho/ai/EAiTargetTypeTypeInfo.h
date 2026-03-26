#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1ECE4
   * COL:  0x00E763B4
   */
  class EAiTargetTypeTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x005E2400 (FUN_005E2400, scalar deleting thunk)
     */
    ~EAiTargetTypeTypeInfo() override;

    /**
     * Address: 0x005E23F0 (FUN_005E23F0)
     *
     * What it does:
     * Returns the reflection type name literal for EAiTargetType.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005E23D0 (FUN_005E23D0)
     *
     * What it does:
     * Writes enum width, registers enum values, then finalizes metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x005E2430 (FUN_005E2430)
     *
     * What it does:
     * Registers `EAiTargetType` enum option names/values.
     */
    void AddEnums();
  };

  static_assert(sizeof(EAiTargetTypeTypeInfo) == 0x78, "EAiTargetTypeTypeInfo size must be 0x78");
} // namespace moho
