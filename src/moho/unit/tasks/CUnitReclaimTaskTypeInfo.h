#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitReclaimTaskTypeInfo final : public gpg::RType
  {
  public:
    /**
     * What it does:
     * Returns the reflected type name literal for `CUnitReclaimTask`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0061EDA0 (FUN_0061EDA0, Moho::CUnitReclaimTaskTypeInfo::Init)
     *
     * What it does:
     * Sets reclaim-task reflected size/callback lanes, registers reflected base
     * slices, and finalizes type-info initialization.
     */
    void Init() override;

    /**
     * Address: 0x00620460 (FUN_00620460, callback shard)
     *
     * What it does:
     * Assigns all lifecycle callbacks (`NewRef`, `CtrRef`, delete, destruct)
     * to one reclaim-task type descriptor.
     */
    static gpg::RType* AssignAllLifecycleCallbacks(gpg::RType* typeInfo);

    /**
     * Address: 0x00620520 (FUN_00620520, callback shard)
     *
     * What it does:
     * Assigns constructor-lane callbacks (`NewRef`, `CtrRef`) to one reclaim-task
     * type descriptor.
     */
    static gpg::RType* AssignCtorCallbacks(gpg::RType* typeInfo);

    /**
     * Address: 0x00620530 (FUN_00620530, callback shard)
     *
     * What it does:
     * Assigns destructor-lane callbacks (delete + in-place destruct) to one
     * reclaim-task type descriptor.
     */
    static gpg::RType* AssignDtorCallbacks(gpg::RType* typeInfo);

    /**
     * Address: 0x00620680 (FUN_00620680, Moho::CUnitReclaimTaskTypeInfo::AddBase_CCommandTask)
     */
    static void __stdcall AddBase_CCommandTask(gpg::RType* typeInfo);

    /**
     * Address: 0x006206E0 (FUN_006206E0, Moho::CUnitReclaimTaskTypeInfo::AddBase_Listener_ECommandEvent)
     */
    static void __stdcall AddBase_Listener_ECommandEvent(gpg::RType* typeInfo);

    /**
     * Address: 0x00620560 (FUN_00620560, Moho::CUnitReclaimTaskTypeInfo::NewRef)
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x00620600 (FUN_00620600, Moho::CUnitReclaimTaskTypeInfo::CtrRef)
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x006205E0 (FUN_006205E0, Moho::CUnitReclaimTaskTypeInfo::Delete)
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x00620670 (FUN_00620670, Moho::CUnitReclaimTaskTypeInfo::Destruct)
     */
    static void Destruct(void* objectStorage);
  };

  static_assert(sizeof(CUnitReclaimTaskTypeInfo) == 0x64, "CUnitReclaimTaskTypeInfo size must be 0x64");
} // namespace moho
