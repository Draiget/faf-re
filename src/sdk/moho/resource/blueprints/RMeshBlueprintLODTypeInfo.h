#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/Vector.h"

namespace moho
{
  struct RMeshBlueprintLOD;

  /**
   * Address: 0x005195B0 (FUN_005195B0)
   *
   * What it does:
   * Releases a `msvc8::vector<RMeshBlueprintLOD>`'s backing storage: destroys
   * each live LOD element (tearing down its seven legacy string lanes via
   * `FUN_00519800`), frees the storage block, and nulls the container
   * pointer lanes. Used by `RMeshBlueprint::~RMeshBlueprint()`
   * (`FUN_00528410`) and the blueprint construct deletion lane.
   */
  void ClearAndFreeMeshBlueprintLodVectorStorage(msvc8::vector<RMeshBlueprintLOD>* storage);

  /**
   * VFTABLE: 0x00E0FE1C
   * COL: 0x00E692FC
   */
  class RMeshBlueprintLODTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00518460 (FUN_00518460, Moho::RMeshBlueprintLODTypeInfo::RMeshBlueprintLODTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `RMeshBlueprintLOD`.
     */
    RMeshBlueprintLODTypeInfo();

    /**
     * Address: 0x005184F0 (FUN_005184F0, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~RMeshBlueprintLODTypeInfo() override;

    /**
     * Address: 0x005184E0 (FUN_005184E0)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005184C0 (FUN_005184C0)
     * Slot: 9
     *
     * What it does:
     * Sets `RMeshBlueprintLOD` size, initializes base reflection state,
     * publishes LOD field descriptors, and finalizes the descriptor.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00518590 (FUN_00518590, Moho::RMeshBlueprintLODTypeInfo::AddFields)
     *
     * What it does:
     * Publishes reflected LOD field metadata with version/descriptions.
     */
    static void AddFields(gpg::RType* typeInfo);
  };

  /**
   * Address: 0x00BC8510 (FUN_00BC8510)
   *
   * What it does:
   * Materializes and startup-registers `RMeshBlueprintLODTypeInfo`, then
   * installs process-exit cleanup.
   */
  int register_RMeshBlueprintLODTypeInfo();

  /**
   * Address: 0x0051A6D0 (FUN_0051A6D0)
   *
   * What it does:
   * Constructs/preregisters RTTI for `msvc8::vector<RMeshBlueprintLOD>`.
   */
  [[nodiscard]] gpg::RType* preregister_VectorRMeshBlueprintLODType();

  /**
   * Address: 0x00BC85C0 (FUN_00BC85C0)
   *
   * What it does:
   * Registers `vector<RMeshBlueprintLOD>` reflection and installs process-exit
   * teardown.
   */
  int register_VectorRMeshBlueprintLODTypeAtexit();

  static_assert(sizeof(RMeshBlueprintLODTypeInfo) == 0x64, "RMeshBlueprintLODTypeInfo size must be 0x64");
} // namespace moho

