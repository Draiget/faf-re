#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitAssistMoveTask;

  /**
   * VFTABLE: 0x00E1F508
   */
  class CUnitAssistMoveTaskTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x005F09A0 (FUN_005F09A0, ??0CUnitAssistMoveTaskTypeInfo@Moho@@QAE@@Z)
     *
     * What it does:
     * Preregisters `CUnitAssistMoveTask` RTTI into the reflection lookup table.
     */
    CUnitAssistMoveTaskTypeInfo();

    /**
     * Address: 0x005F0A50 (FUN_005F0A50, scalar deleting thunk)
     */
    ~CUnitAssistMoveTaskTypeInfo() override;

    /**
     * Address: 0x005F0A40 (FUN_005F0A40)
     *
     * What it does:
     * Returns the reflected type name literal for `CUnitAssistMoveTask`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005F0A00 (FUN_005F0A00)
     *
     * What it does:
     * Sets the reflected size and wires base / allocator callbacks.
     */
    void Init() override;

    static void AddBase_CCommandTask(gpg::RType* typeInfo);
    static gpg::RRef NewRef();
    static gpg::RRef CtrRef(void* objectStorage);
    static void Delete(void* objectStorage);
    static void Destruct(void* objectStorage);
  };

  /**
   * Address: 0x00BCF250 (FUN_00BCF250, register_CUnitAssistMoveTaskTypeInfo)
   *
   * What it does:
   * Constructs the global type-info owner and schedules process-exit cleanup.
   */
  int register_CUnitAssistMoveTaskTypeInfo();

  static_assert(sizeof(CUnitAssistMoveTaskTypeInfo) == 0x64, "CUnitAssistMoveTaskTypeInfo size must be 0x64");
} // namespace moho
