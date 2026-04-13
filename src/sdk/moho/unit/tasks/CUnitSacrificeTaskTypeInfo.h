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

    /**
     * Address: 0x005FD4A0 (FUN_005FD4A0, Moho::CUnitSacrificeTaskTypeInfo::AddBase_CCommandTask)
     */
    static void __stdcall AddBase_CCommandTask(gpg::RType* typeInfo);

    /**
     * Address: 0x005FD500 (FUN_005FD500, Moho::CUnitSacrificeTaskTypeInfo::AddBase_Listener_ECommandEvent)
     */
    static void __stdcall AddBase_Listener_ECommandEvent(gpg::RType* typeInfo);

    /**
     * Address: 0x005FC5A0 (FUN_005FC5A0, Moho::CUnitSacrificeTaskTypeInfo::NewRef)
     *
     * What it does:
     * Allocates and initializes one `CUnitSacrificeTask` for reflection use,
     * then returns its typed reflection reference.
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x005FC660 (FUN_005FC660, Moho::CUnitSacrificeTaskTypeInfo::CtrRef)
     *
     * What it does:
     * Constructs one `CUnitSacrificeTask` in caller-provided storage and
     * returns its typed reflection reference.
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x005FC640 (FUN_005FC640, Moho::CUnitSacrificeTaskTypeInfo::Delete)
     *
     * What it does:
     * Deletes a `CUnitSacrificeTask` through its deleting-destructor path.
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x005FC700 (FUN_005FC700, Moho::CUnitSacrificeTaskTypeInfo::Destruct)
     *
     * What it does:
     * Runs the non-deleting `CUnitSacrificeTask` destructor body on placement
     * storage.
     */
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
