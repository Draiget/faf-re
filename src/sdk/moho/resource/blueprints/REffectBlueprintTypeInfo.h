#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E0EBA0
   * COL: 0x00E68420
   *
   * Source hints:
   * - c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\reflection.cpp
   */
  class REffectBlueprintTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0050F0C0 (FUN_0050F0C0, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~REffectBlueprintTypeInfo() override;

    /**
     * Address: 0x0050F0B0 (FUN_0050F0B0)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0050F080 (FUN_0050F080)
     * Slot: 9
     *
     * What it does:
     * Sets `REffectBlueprint` size, registers `RObject` base metadata, and
     * publishes base effect-blueprint fields.
     */
    void Init() override;
  };

  static_assert(sizeof(REffectBlueprintTypeInfo) == 0x64, "REffectBlueprintTypeInfo size must be 0x64");
} // namespace moho
