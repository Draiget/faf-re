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

    /**
     * Address: 0x005FC120 (FUN_005FC120, Moho::CUnitMobileBuildTaskTypeInfo::NewRef)
     *
     * What it does:
     * Allocates one `CUnitMobileBuildTask` and returns its typed reflection
     * reference.
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x005FC1C0 (FUN_005FC1C0, Moho::CUnitMobileBuildTaskTypeInfo::CtrRef)
     *
     * What it does:
     * Constructs one `CUnitMobileBuildTask` in caller-provided storage and
     * returns its typed reflection reference.
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x005FC1A0 (FUN_005FC1A0, Moho::CUnitMobileBuildTaskTypeInfo::Delete)
     *
     * What it does:
     * Deletes one heap-owned `CUnitMobileBuildTask`.
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x005FC230 (FUN_005FC230, Moho::CUnitMobileBuildTaskTypeInfo::Destruct)
     *
     * What it does:
     * Runs the non-deleting `CUnitMobileBuildTask` destructor body on
     * placement storage.
     */
    static void Destruct(void* objectStorage);

    /**
     * Address: 0x005FCF00 (FUN_005FCF00, Moho::CUnitMobileBuildTaskTypeInfo::AddBase_CCommandTask)
     *
     * What it does:
     * Registers `CCommandTask` as the primary reflection base.
     */
    static void __stdcall AddBase_CCommandTask(gpg::RType* typeInfo);

    /**
     * Address: 0x005FCF60 (FUN_005FCF60, Moho::CUnitMobileBuildTaskTypeInfo::AddBase_Listener_ECommandEvent)
     *
     * What it does:
     * Registers `Listener<ECommandEvent>` as the secondary reflection base at
     * offset `0x34`.
     */
    static void __stdcall AddBase_Listener_ECommandEvent(gpg::RType* typeInfo);
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
