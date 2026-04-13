#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitAttackTargetTask;

  /**
   * VFTABLE: 0x00E1F678
   */
  class CUnitAttackTargetTaskTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x005F2510 (FUN_005F2510, ??0CUnitAttackTargetTaskTypeInfo@Moho@@QAE@@Z)
     *
     * What it does:
     * Preregisters `CUnitAttackTargetTask` RTTI into the reflection lookup table.
     */
    CUnitAttackTargetTaskTypeInfo();

    /**
     * Address: 0x005F25D0 (FUN_005F25D0, scalar deleting thunk)
     */
    ~CUnitAttackTargetTaskTypeInfo() override;

    /**
     * Address: 0x005F25C0 (FUN_005F25C0)
     *
     * What it does:
     * Returns the reflected type name literal for `CUnitAttackTargetTask`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005F2570 (FUN_005F2570)
     *
     * What it does:
     * Sets the reflected size (0x90) and wires base / allocator callbacks.
     */
    void Init() override;

    /**
     * Address: 0x005F4760 (FUN_005F4760, Moho::CUnitAttackTargetTaskTypeInfo::AddBase_CCommandTask)
     *
     * What it does:
     * Registers `CCommandTask` as the primary reflection base.
     */
    static void AddBase_CCommandTask(gpg::RType* typeInfo);

    /**
     * Address: 0x005F47C0 (FUN_005F47C0, Moho::CUnitAttackTargetTaskTypeInfo::AddBase_Listener_EAiAttackerEvent)
     *
     * What it does:
     * Registers `Listener<EAiAttackerEvent>` as a secondary reflection base at
     * offset `0x34`.
     */
    static void AddBase_Listener_EAiAttackerEvent(gpg::RType* typeInfo);

    /**
     * Address: 0x005F4820 (FUN_005F4820, Moho::CUnitAttackTargetTaskTypeInfo::AddBase_Listener_ECommandEvent)
     *
     * What it does:
     * Registers `Listener<ECommandEvent>` as a secondary reflection base at
     * offset `0x44`.
     */
    static void AddBase_Listener_ECommandEvent(gpg::RType* typeInfo);

    /**
     * Address: 0x005F4640 (FUN_005F4640, Moho::CUnitAttackTargetTaskTypeInfo::NewRef)
     *
     * What it does:
     * Allocates one `CUnitAttackTargetTask` and returns typed reflection
     * reference for it.
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x005F46E0 (FUN_005F46E0, Moho::CUnitAttackTargetTaskTypeInfo::CtrRef)
     *
     * What it does:
     * Placement-constructs one `CUnitAttackTargetTask` in caller-provided
     * storage and returns typed reflection reference for it.
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x005F46C0 (FUN_005F46C0, Moho::CUnitAttackTargetTaskTypeInfo::Delete)
     *
     * What it does:
     * Deletes one heap-owned `CUnitAttackTargetTask`.
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x005F4750 (FUN_005F4750, Moho::CUnitAttackTargetTaskTypeInfo::Destruct)
     *
     * What it does:
     * Runs in-place destructor for one `CUnitAttackTargetTask` without
     * deallocating storage.
     */
    static void Destruct(void* objectStorage);
  };

  /**
   * Address: 0x00BCF4A0 (FUN_00BCF4A0, register_CUnitAttackTargetTaskTypeInfo)
   *
   * What it does:
   * Constructs the global type-info owner and schedules process-exit cleanup.
   */
  int register_CUnitAttackTargetTaskTypeInfo();

  static_assert(sizeof(CUnitAttackTargetTaskTypeInfo) == 0x64, "CUnitAttackTargetTaskTypeInfo size must be 0x64");
} // namespace moho
