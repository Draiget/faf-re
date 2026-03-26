#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1F18C
   * COL:  0x00E76CC0
   */
  class EAiTransportEventTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x005E3DA0 (FUN_005E3DA0, scalar deleting thunk)
     */
    ~EAiTransportEventTypeInfo() override;

    /**
     * Address: 0x005E3D90 (FUN_005E3D90)
     *
     * What it does:
     * Returns the reflection type name literal for EAiTransportEvent.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005E3D70 (FUN_005E3D70)
     *
     * What it does:
     * Writes enum width, registers enum values, then finalizes metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x005E3DD0 (FUN_005E3DD0)
     *
     * What it does:
     * Registers EAiTransportEvent enum option names/values.
     */
    void AddEnums();
  };

  static_assert(sizeof(EAiTransportEventTypeInfo) == 0x78, "EAiTransportEventTypeInfo size must be 0x78");
} // namespace moho
