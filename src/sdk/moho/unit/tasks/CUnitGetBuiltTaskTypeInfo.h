#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitGetBuiltTask;

  /**
   * VFTABLE: 0x00E202CC
   */
  class CUnitGetBuiltTaskTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0060A5A0 (FUN_0060A5A0)
     * Mangled: ?0CUnitGetBuiltTaskTypeInfo@Moho@@QAE@@Z
     *
     * What it does:
     * Preregisters `CUnitGetBuiltTask` RTTI into the reflection lookup table.
     */
    CUnitGetBuiltTaskTypeInfo();

    /**
     * Address: 0x0060A650 (FUN_0060A650, scalar deleting thunk)
     */
    ~CUnitGetBuiltTaskTypeInfo() override;

    /**
     * Address: 0x0060A640 (FUN_0060A640)
     *
     * What it does:
     * Returns the reflected type name literal for `CUnitGetBuiltTask`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0060A600 (FUN_0060A600)
     *
     * What it does:
     * Sets the reflected size (0x30) and wires base / allocator callbacks.
     */
    void Init() override;

    /**
     * Address: 0x0060C430 (FUN_0060C430, Moho::CUnitGetBuiltTaskTypeInfo::AddBase_CCommandTask)
     */
    static void __stdcall AddBase_CCommandTask(gpg::RType* typeInfo);

    /**
     * Address: 0x0060BE20 (FUN_0060BE20, Moho::CUnitGetBuiltTaskTypeInfo::NewRef)
     *
     * What it does:
     * Allocates one `CUnitGetBuiltTask` and returns a reflection reference to
     * the constructed object.
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x0060BEC0 (FUN_0060BEC0, Moho::CUnitGetBuiltTaskTypeInfo::CtrRef)
     *
     * What it does:
     * Constructs one `CUnitGetBuiltTask` in caller-provided storage and
     * returns a reflection reference to it.
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x0060BEA0 (FUN_0060BEA0, Moho::CUnitGetBuiltTaskTypeInfo::Delete)
     *
     * What it does:
     * Deletes a `CUnitGetBuiltTask` through its deleting-destructor path.
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x0060BF40 (FUN_0060BF40, Moho::CUnitGetBuiltTaskTypeInfo::Destruct)
     *
     * What it does:
     * Runs the non-deleting `CUnitGetBuiltTask` destructor body on placement
     * storage.
     */
    static void Destruct(void* objectStorage);
  };

  /**
   * Address: 0x00BD05D0 (FUN_00BD05D0, register_CUnitGetBuiltTaskTypeInfo)
   *
   * What it does:
   * Constructs the global type-info owner and schedules process-exit cleanup.
   */
  int register_CUnitGetBuiltTaskTypeInfo();

  static_assert(sizeof(CUnitGetBuiltTaskTypeInfo) == 0x64, "CUnitGetBuiltTaskTypeInfo size must be 0x64");
} // namespace moho
