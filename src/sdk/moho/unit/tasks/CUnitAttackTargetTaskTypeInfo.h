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

    static void AddBase_CCommandTask(gpg::RType* typeInfo);
    static void AddBase_Listener_EAiAttackerEvent(gpg::RType* typeInfo);
    static void AddBase_Listener_ECommandEvent(gpg::RType* typeInfo);
    static gpg::RRef NewRef();
    static gpg::RRef CtrRef(void* objectStorage);
    static void Delete(void* objectStorage);
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
