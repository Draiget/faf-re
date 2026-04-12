#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitMobileBuildTask;

  /**
   * VFTABLE: 0x00E1F9FC
   */
  class CUnitMobileBuildTaskTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x005F68A0 (FUN_005F68A0, ??0CUnitMobileBuildTaskTypeInfo@Moho@@QAE@@Z)
     *
     * What it does:
     * Preregisters `CUnitMobileBuildTask` RTTI into the reflection lookup table.
     */
    CUnitMobileBuildTaskTypeInfo();

    /**
     * Address: 0x005F6960 (FUN_005F6960, scalar deleting thunk)
     */
    ~CUnitMobileBuildTaskTypeInfo() override;

    /**
     * Address: 0x005F6950 (FUN_005F6950)
     *
     * What it does:
     * Returns the reflected type name literal for `CUnitMobileBuildTask`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005F6900 (FUN_005F6900)
     *
     * What it does:
     * Sets the reflected size (0xE8) and wires base / allocator callbacks.
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
   * Address: 0x00BCF870 (FUN_00BCF870, register_CUnitMobileBuildTaskTypeInfo)
   *
   * What it does:
   * Constructs the global type-info owner and schedules process-exit cleanup.
   */
  int register_CUnitMobileBuildTaskTypeInfo();

  static_assert(sizeof(CUnitMobileBuildTaskTypeInfo) == 0x64, "CUnitMobileBuildTaskTypeInfo size must be 0x64");
} // namespace moho
