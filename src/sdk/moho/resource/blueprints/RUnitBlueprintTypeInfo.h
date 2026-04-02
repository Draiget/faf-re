#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E0EB84
   * COL: 0x00E683A0
   */
  class RUnitBlueprintTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00522940 (FUN_00522940, Moho::RUnitBlueprintTypeInfo::RUnitBlueprintTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `RUnitBlueprint`.
     */
    RUnitBlueprintTypeInfo();

    /**
     * Address: 0x00BF36F0 (FUN_00BF36F0, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~RUnitBlueprintTypeInfo() override;

    /**
     * Address: 0x005229D0 (FUN_005229D0)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005229A0 (FUN_005229A0)
     * Slot: 9
     *
     * What it does:
     * Sets `RUnitBlueprint` size, registers `REntityBlueprint` base metadata,
     * and publishes unit-blueprint section fields.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00525820 (FUN_00525820)
     *
     * What it does:
     * Adds `REntityBlueprint` as the reflected base class lane.
     */
    static void AddBaseREntityBlueprint(gpg::RType* typeInfo);

    /**
     * Address: 0x00522A80 (FUN_00522A80)
     *
     * What it does:
     * Registers unit-blueprint section field descriptors and descriptions.
     */
    static void AddFields(gpg::RType* typeInfo);
  };

  /**
   * Address: 0x00BC8C10 (FUN_00BC8C10, register_RUnitBlueprintTypeInfo)
   *
   * What it does:
   * Materializes and startup-registers `RUnitBlueprintTypeInfo`.
   */
  void register_RUnitBlueprintTypeInfo();

  static_assert(sizeof(RUnitBlueprintTypeInfo) == 0x64, "RUnitBlueprintTypeInfo size must be 0x64");
} // namespace moho

