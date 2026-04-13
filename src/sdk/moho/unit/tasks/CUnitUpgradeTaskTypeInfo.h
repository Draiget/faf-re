#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitUpgradeTask;

  class CUnitUpgradeTaskTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x005F8680 (FUN_005F8680, sub_5F8680)
     *
     * What it does:
     * Preregisters `CUnitUpgradeTask` RTTI into the reflection lookup table.
     */
    CUnitUpgradeTaskTypeInfo();

    /**
     * Address: 0x005F8730 (FUN_005F8730, Moho::CUnitUpgradeTaskTypeInfo::dtr)
     */
    ~CUnitUpgradeTaskTypeInfo() override;

    /**
     * Address: 0x005F8720 (FUN_005F8720, Moho::CUnitUpgradeTaskTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005F86E0 (FUN_005F86E0, Moho::CUnitUpgradeTaskTypeInfo::Init)
     */
    void Init() override;

    /**
     * Address: 0x005FD140 (FUN_005FD140, Moho::CUnitUpgradeTaskTypeInfo::AddBase_CCommandTask)
     */
    static void __stdcall AddBase_CCommandTask(gpg::RType* typeInfo);

    /**
     * Address: 0x005FC240 (FUN_005FC240, Moho::CUnitUpgradeTaskTypeInfo::NewRef)
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x005FC2E0 (FUN_005FC2E0, Moho::CUnitUpgradeTaskTypeInfo::CtrRef)
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x005FC2C0 (FUN_005FC2C0, Moho::CUnitUpgradeTaskTypeInfo::Delete)
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x005FC350 (FUN_005FC350, Moho::CUnitUpgradeTaskTypeInfo::Destruct)
     */
    static void Destruct(void* objectStorage);
  };

  /**
   * Address: 0x00BF9360 (FUN_00BF9360)
   *
   * What it does:
   * Releases reflected base/field buffers for global `CUnitUpgradeTaskTypeInfo`
   * storage.
   */
  void cleanup_CUnitUpgradeTaskTypeInfo();

  /**
   * Address: 0x00BCF8D0 (FUN_00BCF8D0, sub_BCF8D0)
   *
   * What it does:
   * Constructs the startup-owned `CUnitUpgradeTaskTypeInfo` instance and
   * schedules process-exit cleanup.
   */
  int register_CUnitUpgradeTaskTypeInfo();

  static_assert(sizeof(CUnitUpgradeTaskTypeInfo) == 0x64, "CUnitUpgradeTaskTypeInfo size must be 0x64");
} // namespace moho

