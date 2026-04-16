#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  struct REntityBlueprint;

  /**
   * VFTABLE: 0x00E0F610
   * COL: 0x00E68674
   */
  class REntityBlueprintTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00512730 (FUN_00512730, Moho::REntityBlueprintTypeInfo::REntityBlueprintTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `REntityBlueprint`.
     */
    REntityBlueprintTypeInfo();

    /**
     * Address: 0x005127D0 (FUN_005127D0, Moho::REntityBlueprintTypeInfo::dtr)
     * Slot: 2
     */
    ~REntityBlueprintTypeInfo() override;

    /**
     * Address: 0x005127C0 (FUN_005127C0, Moho::REntityBlueprintTypeInfo::GetName)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00512790 (FUN_00512790, Moho::REntityBlueprintTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Sets `REntityBlueprint` size, registers `RBlueprint` base metadata,
     * and publishes entity-blueprint field descriptors.
     */
    void Init() override;

  private:
    /**
     * Address: 0x005131D0 (FUN_005131D0, Moho::REntityBlueprintTypeInfo::AddBase_RBlueprint)
     *
     * What it does:
     * Adds `RBlueprint` as the reflected base class lane.
     */
    static void AddBaseRBlueprint(gpg::RType* typeInfo);

    /**
     * Address: 0x00512870 (FUN_00512870, Moho::REntityBlueprintTypeInfo::AddFields)
     *
     * What it does:
     * Registers `REntityBlueprint` field descriptors and descriptions.
     */
    static void AddFields(gpg::RType* typeInfo);

    /**
     * Address: 0x005132B0 (FUN_005132B0, gpg::RType::AddField_ECollisionShape_0xA8CollisionShape)
     *
     * What it does:
     * Appends the `CollisionShape` reflected field entry (`+0xA8`).
     */
    static gpg::RField* AddFieldCollisionShape(gpg::RType* typeInfo);
  };

  /**
   * Address: 0x00BC8290 (FUN_00BC8290, register_REntityBlueprintTypeInfo)
   *
   * What it does:
   * Materializes and startup-registers `REntityBlueprintTypeInfo`.
   */
  void register_REntityBlueprintTypeInfo();

  /**
   * Address: 0x00BC8340 (FUN_00BC8340, register_EFootprintFlagsTypeInfo)
   *
   * What it does:
   * Materializes and startup-registers the reflected `EFootprintFlags` enum
   * descriptor, then installs its exit-time cleanup.
   */
  int register_EFootprintFlagsTypeInfo();

  /**
   * Address: 0x00BC82B0 (FUN_00BC82B0, register_RStringVectorTypeInfo)
   *
   * What it does:
   * Materializes and startup-registers the reflected `vector<string>`
   * descriptor, then installs its exit-time cleanup.
   */
  int register_RStringVectorTypeInfo();

  static_assert(sizeof(REntityBlueprintTypeInfo) == 0x64, "REntityBlueprintTypeInfo size must be 0x64");
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x00555040 (FUN_00555040, gpg::RRef_REntityBlueprint)
   *
   * What it does:
   * Builds a typed reflection reference for `REntityBlueprint*`, upgrading to
   * the dynamic derived type and applying base-offset adjustment when needed.
   */
  gpg::RRef* RRef_REntityBlueprint(gpg::RRef* outRef, moho::REntityBlueprint* value);

  /**
   * Address: 0x0060C290 (FUN_0060C290, func_RRRefREntityBlueprint)
   *
   * What it does:
   * Builds one temporary `RRef_REntityBlueprint` and copies `(mObj,mType)`
   * into caller-owned output storage.
   */
  gpg::RRef* PackRRef_REntityBlueprint(gpg::RRef* outRef, moho::REntityBlueprint* value);
} // namespace gpg
