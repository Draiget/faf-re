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

    /**
     * Address: 0x005FD340 (FUN_005FD340, Moho::CUnitRepairTaskTypeInfo::AddBase_CCommandTask)
     *
     * What it does:
     * Registers `CCommandTask` as the primary reflection base at offset 0.
     */
    static void __stdcall AddBase_CCommandTask(gpg::RType* typeInfo);

    /**
     * Address: 0x005FD3A0 (FUN_005FD3A0, Moho::CUnitRepairTaskTypeInfo::AddBase_Listener_ECommandEvent)
     *
     * What it does:
     * Registers `Listener<ECommandEvent>` as the secondary reflection base at
     * offset `0x34`.
     */
    static void __stdcall AddBase_Listener_ECommandEvent(gpg::RType* typeInfo);

    /**
     * Address: 0x005FC360 (FUN_005FC360, Moho::CUnitRepairTaskTypeInfo::NewRef)
     *
     * What it does:
     * Allocates one repair-task reflection object and returns its typed
     * reflection reference.
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x005FC400 (FUN_005FC400, Moho::CUnitRepairTaskTypeInfo::CtrRef)
     *
     * What it does:
     * Placement-constructs one repair-task reflection object in caller-provided
     * storage and returns its typed reflection reference.
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x005FC3E0 (FUN_005FC3E0, Moho::CUnitRepairTaskTypeInfo::Delete)
     *
     * What it does:
     * Deletes one heap-owned repair-task reflection object through the deleting
     * destructor lane.
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x005FC470 (FUN_005FC470, Moho::CUnitRepairTaskTypeInfo::Destruct)
     *
     * What it does:
     * Runs the non-deleting destructor lane for one repair-task reflection
     * object.
     */
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
