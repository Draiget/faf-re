#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1BFC8
   * COL:  0x00E71A54
   */
  class EAiNavigatorEventTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x005A30B0 (FUN_005A30B0, scalar deleting thunk)
     */
    ~EAiNavigatorEventTypeInfo() override;

    /**
     * Address: 0x005A30A0 (FUN_005A30A0)
     *
     * What it does:
     * Returns the reflection type name literal for EAiNavigatorEvent.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005A3080 (FUN_005A3080)
     *
     * What it does:
     * Writes enum width, registers enum values, then finalizes metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x005A30E0 (FUN_005A30E0)
     *
     * What it does:
     * Registers EAiNavigatorEvent enum option names/values.
     */
    void AddEnums();
  };

  static_assert(sizeof(EAiNavigatorEventTypeInfo) == 0x78, "EAiNavigatorEventTypeInfo size must be 0x78");
} // namespace moho
