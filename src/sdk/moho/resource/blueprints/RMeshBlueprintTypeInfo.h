#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E0EAF4
   * COL: 0x00E68388
   */
  class RMeshBlueprintTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005186B0 (FUN_005186B0, Moho::RMeshBlueprintTypeInfo::RMeshBlueprintTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for `RMeshBlueprint`.
     */
    RMeshBlueprintTypeInfo();

    /**
     * Address: 0x00BF2C60 (FUN_00BF2C60, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~RMeshBlueprintTypeInfo() override;

    /**
     * Address: 0x00518740 (FUN_00518740)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00518710 (FUN_00518710)
     * Slot: 9
     *
     * What it does:
     * Sets `RMeshBlueprint` size, registers `RBlueprint` base metadata, and
     * publishes mesh-blueprint fields.
     */
    void Init() override;

  private:
    /**
     * Address: 0x0051A2D0 (FUN_0051A2D0)
     *
     * What it does:
     * Adds `RBlueprint` as the reflected base class lane.
     */
    static void AddBaseRBlueprint(gpg::RType* typeInfo);

    /**
     * Address: 0x005187F0 (FUN_005187F0)
     *
     * What it does:
     * Registers mesh-blueprint field descriptors and descriptions.
     */
    static void AddFields(gpg::RType* typeInfo);

    /**
     * Address: 0x0051A330 (FUN_0051A330, gpg::RType::AddField_vector_RMeshBlueprintLOD_0x60LODs)
     *
     * What it does:
     * Appends the `LODs` reflected field entry (`+0x60`).
     */
    static gpg::RField* AddFieldLods(gpg::RType* typeInfo);
  };

  /**
   * Address: 0x00BC8530 (FUN_00BC8530, register_RMeshBlueprintTypeInfo)
   *
   * What it does:
   * Materializes and startup-registers `RMeshBlueprintTypeInfo`.
   */
  int register_RMeshBlueprintTypeInfo();

  static_assert(sizeof(RMeshBlueprintTypeInfo) == 0x64, "RMeshBlueprintTypeInfo size must be 0x64");
} // namespace moho
