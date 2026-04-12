#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitRepairTask;

  /**
   * VFTABLE: 0x00E1FA9C
   */
  class CUnitRepairTaskTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x005F9000 (FUN_005F9000, ??0CUnitRepairTaskTypeInfo@Moho@@QAE@@Z)
     *
     * What it does:
     * Preregisters `CUnitRepairTask` RTTI into the reflection lookup table.
     */
    CUnitRepairTaskTypeInfo();

    /**
     * Address: 0x005F90C0 (FUN_005F90C0, scalar deleting thunk)
     */
    ~CUnitRepairTaskTypeInfo() override;

    /**
     * Address: 0x005F90B0 (FUN_005F90B0)
     *
     * What it does:
     * Returns the reflected type name literal for `CUnitRepairTask`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005F9060 (FUN_005F9060)
     *
     * What it does:
     * Sets the reflected size (0x9C) and wires base / allocator callbacks.
     */
    void Init() override;

    static void AddBase_CCommandTask(gpg::RType* typeInfo);
    static void AddBase_Listener_ECommandEvent(gpg::RType* typeInfo);
    static gpg::RRef NewRef();
    static gpg::RRef CtrRef(void* objectStorage);
    static void Delete(void* objectStorage);
    static void Destruct(void* objectStorage);
  };

  /**
   * Address: 0x00BCF930 (FUN_00BCF930, register_CUnitRepairTaskTypeInfo)
   *
   * What it does:
   * Constructs the global type-info owner and schedules process-exit cleanup.
   */
  int register_CUnitRepairTaskTypeInfo();

  static_assert(sizeof(CUnitRepairTaskTypeInfo) == 0x64, "CUnitRepairTaskTypeInfo size must be 0x64");
} // namespace moho
