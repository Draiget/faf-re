#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E0EB30
   * COL: 0x00E683B8
   */
  class RProjectileBlueprintTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0051C260 (FUN_0051C260, Moho::RProjectileBlueprintTypeInfo::RProjectileBlueprintTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `RProjectileBlueprint`.
     */
    RProjectileBlueprintTypeInfo();

    /**
     * Address: 0x00BF2EF0 (FUN_00BF2EF0, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~RProjectileBlueprintTypeInfo() override;

    /**
     * Address: 0x0051C2F0 (FUN_0051C2F0)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0051C2C0 (FUN_0051C2C0)
     * Slot: 9
     *
     * What it does:
     * Sets `RProjectileBlueprint` size, registers `REntityBlueprint` base
     * metadata, and publishes projectile-blueprint fields.
     */
    void Init() override;

  private:
    /**
     * Address: 0x0051CD60 (FUN_0051CD60)
     *
     * What it does:
     * Adds `REntityBlueprint` as the reflected base class lane.
     */
    static void AddBaseREntityBlueprint(gpg::RType* typeInfo);

    /**
     * Address: 0x0051C3A0 (FUN_0051C3A0)
     *
     * What it does:
     * Registers projectile-blueprint field descriptors and descriptions.
     */
    static void AddFields(gpg::RType* typeInfo);
  };

  /**
   * Address: 0x00BC86B0 (FUN_00BC86B0, register_RProjectileBlueprintTypeInfo)
   *
   * What it does:
   * Materializes and startup-registers `RProjectileBlueprintTypeInfo`.
   */
  int register_RProjectileBlueprintTypeInfo();

  static_assert(sizeof(RProjectileBlueprintTypeInfo) == 0x64, "RProjectileBlueprintTypeInfo size must be 0x64");
} // namespace moho
