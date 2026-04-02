#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E0EBBC
   * COL: 0x00E683D0
   *
   * Source hints:
   * - c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\reflection.cpp
   */
  class RTrailBlueprintTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0050F1D0 (FUN_0050F1D0, Moho::RTrailBlueprintTypeInfo::RTrailBlueprintTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `RTrailBlueprint`.
     */
    RTrailBlueprintTypeInfo();

    /**
     * Address: 0x0050F290 (FUN_0050F290, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~RTrailBlueprintTypeInfo() override;

    /**
     * Address: 0x0050F280 (FUN_0050F280)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0050F230 (FUN_0050F230)
     * Slot: 9
     *
     * What it does:
     * Sets `RTrailBlueprint` size, binds lifetime/new/delete hooks, registers
     * `REffectBlueprint` base metadata, and publishes trail-specific fields.
     */
    void Init() override;

    /**
     * Address: 0x0050F330 (FUN_0050F330, Moho::RTrailBlueprintTypeInfo::AddFields)
     *
     * What it does:
     * Publishes the reflected trail-blueprint fields and descriptions in the
     * original binary order.
     */
    static void AddFields(gpg::RType* typeInfo);
  };

  /**
   * Address: 0x00BC8070 (FUN_00BC8070, register_RTrailBlueprintTypeInfo)
   *
   * What it does:
   * Materializes and startup-registers `RTrailBlueprintTypeInfo`.
   */
  void register_RTrailBlueprintTypeInfo();

  static_assert(sizeof(RTrailBlueprintTypeInfo) == 0x64, "RTrailBlueprintTypeInfo size must be 0x64");
} // namespace moho
