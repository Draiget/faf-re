#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1E890
   * COL:  0x00E75E94
   */
  class EAiAttackerEventTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x005D5A30 (FUN_005D5A30, scalar deleting thunk)
     */
    ~EAiAttackerEventTypeInfo() override;

    /**
     * Address: 0x005D5A20 (FUN_005D5A20)
     *
     * What it does:
     * Returns the reflection type name literal for EAiAttackerEvent.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005D5A00 (FUN_005D5A00)
     *
     * What it does:
     * Writes enum width, registers enum values, then finalizes metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x005D5A60 (FUN_005D5A60)
     *
     * What it does:
     * Registers EAiAttackerEvent enum option names/values.
     */
    void AddEnums();
  };

  static_assert(sizeof(EAiAttackerEventTypeInfo) == 0x78, "EAiAttackerEventTypeInfo size must be 0x78");
} // namespace moho
