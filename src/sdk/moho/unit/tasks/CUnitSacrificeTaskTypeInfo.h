#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitSacrificeTask;

  /**
   * VFTABLE: 0x00E1FB3C
   */
  class CUnitSacrificeTaskTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x005FAF60 (FUN_005FAF60, ??0CUnitSacrificeTaskTypeInfo@Moho@@QAE@@Z)
     *
     * What it does:
     * Preregisters `CUnitSacrificeTask` RTTI into the reflection lookup table.
     */
    CUnitSacrificeTaskTypeInfo();

    /**
     * Address: 0x005FB020 (FUN_005FB020, scalar deleting thunk)
     */
    ~CUnitSacrificeTaskTypeInfo() override;

    /**
     * Address: 0x005FB010 (FUN_005FB010)
     *
     * What it does:
     * Returns the reflected type name literal for `CUnitSacrificeTask`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005FAFC0 (FUN_005FAFC0)
     *
     * What it does:
     * Sets the reflected size (0x4C) and wires base / allocator callbacks.
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
   * Address: 0x00BCF9F0 (FUN_00BCF9F0, register_CUnitSacrificeTaskTypeInfo)
   *
   * What it does:
   * Constructs the global type-info owner and schedules process-exit cleanup.
   */
  int register_CUnitSacrificeTaskTypeInfo();

  static_assert(sizeof(CUnitSacrificeTaskTypeInfo) == 0x64, "CUnitSacrificeTaskTypeInfo size must be 0x64");
} // namespace moho
