#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitCallAirStagingPlatform;

  class CUnitCallAirStagingPlatformTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00601AC0 (FUN_00601AC0)
     *
     * What it does:
     * Preregisters RTTI metadata for `CUnitCallAirStagingPlatform`.
     */
    CUnitCallAirStagingPlatformTypeInfo();

    /**
     * Address: 0x00601B70 (FUN_00601B70, scalar deleting destructor thunk)
     */
    ~CUnitCallAirStagingPlatformTypeInfo() override;

    /**
     * Address: 0x00601B60 (FUN_00601B60)
     *
     * What it does:
     * Returns the reflected type name literal for
     * `CUnitCallAirStagingPlatform`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00601B20 (FUN_00601B20)
     *
     * What it does:
     * Sets reflected size/callbacks and binds `CCommandTask` as base type.
     */
    void Init() override;

    /**
     * Address: 0x00602F20 (FUN_00602F20, AddBase_CCommandTask)
     */
    static void __stdcall AddBase_CCommandTask(gpg::RType* typeInfo);

    /**
     * Address: 0x00602AE0 (FUN_00602AE0)
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x00602B90 (FUN_00602B90)
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x00602B70 (FUN_00602B70)
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x00602C10 (FUN_00602C10)
     */
    static void Destruct(void* objectStorage);
  };

  /**
   * Address: 0x00BF9770 (FUN_00BF9770, cleanup_CUnitCallAirStagingPlatformTypeInfo)
   *
   * What it does:
   * Releases reflected base/field buffers of the global type-info owner.
   */
  void cleanup_CUnitCallAirStagingPlatformTypeInfo();

  /**
   * Address: 0x00BCFD60 (FUN_00BCFD60, register_CUnitCallAirStagingPlatformTypeInfo)
   *
   * What it does:
   * Constructs the global type-info owner and schedules process-exit cleanup.
   */
  int register_CUnitCallAirStagingPlatformTypeInfo();

  static_assert(
    sizeof(CUnitCallAirStagingPlatformTypeInfo) == 0x64, "CUnitCallAirStagingPlatformTypeInfo size must be 0x64"
  );
} // namespace moho

