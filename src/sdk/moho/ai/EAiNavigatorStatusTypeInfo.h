#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1BFD4
   * COL:  0x00E71A88
   */
  class EAiNavigatorStatusTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x005A2F40 (FUN_005A2F40, scalar deleting thunk)
     */
    ~EAiNavigatorStatusTypeInfo() override;

    /**
     * Address: 0x005A2F30 (FUN_005A2F30)
     *
     * What it does:
     * Returns the reflection type name literal for EAiNavigatorStatus.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005A2F10 (FUN_005A2F10)
     *
     * What it does:
     * Writes enum width, registers enum values, then finalizes metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x005A2F70 (FUN_005A2F70)
     *
     * What it does:
     * Registers EAiNavigatorStatus enum option names/values.
     */
    void AddEnums();
  };

  static_assert(sizeof(EAiNavigatorStatusTypeInfo) == 0x78, "EAiNavigatorStatusTypeInfo size must be 0x78");
} // namespace moho
