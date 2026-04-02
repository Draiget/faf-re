#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitCallTeleport;

  class CUnitCallTeleportTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00601090 (FUN_00601090)
     *
     * What it does:
     * Preregisters RTTI metadata for `CUnitCallTeleport`.
     */
    CUnitCallTeleportTypeInfo();

    /**
     * Address: 0x00601140 (FUN_00601140, scalar deleting destructor thunk)
     */
    ~CUnitCallTeleportTypeInfo() override;

    /**
     * Address: 0x00601130 (FUN_00601130)
     *
     * What it does:
     * Returns the reflected type name literal for `CUnitCallTeleport`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006010F0 (FUN_006010F0)
     *
     * What it does:
     * Sets reflected size/callbacks and binds `CCommandTask` as base type.
     */
    void Init() override;

    /**
     * Address: 0x00602EA0 (FUN_00602EA0, AddBase_CCommandTask)
     */
    static void __stdcall AddBase_CCommandTask(gpg::RType* typeInfo);

    /**
     * Address: 0x006029A0 (FUN_006029A0)
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x00602A50 (FUN_00602A50)
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x00602A30 (FUN_00602A30)
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x00602AD0 (FUN_00602AD0)
     */
    static void Destruct(void* objectStorage);
  };

  /**
   * Address: 0x00BF96E0 (FUN_00BF96E0, cleanup_CUnitCallTeleportTypeInfo)
   *
   * What it does:
   * Releases reflected base/field buffers of the global type-info owner.
   */
  void cleanup_CUnitCallTeleportTypeInfo();

  /**
   * Address: 0x00BCFD00 (FUN_00BCFD00, register_CUnitCallTeleportTypeInfo)
   *
   * What it does:
   * Constructs the global type-info owner and schedules process-exit cleanup.
   */
  int register_CUnitCallTeleportTypeInfo();

  static_assert(sizeof(CUnitCallTeleportTypeInfo) == 0x64, "CUnitCallTeleportTypeInfo size must be 0x64");
} // namespace moho

