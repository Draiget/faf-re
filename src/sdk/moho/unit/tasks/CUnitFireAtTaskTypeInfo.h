#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitFireAtTask;

  /**
   * VFTABLE: 0x00E20364
   */
  class CUnitFireAtTaskTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0060AFA0 (FUN_0060AFA0)
     */
    CUnitFireAtTaskTypeInfo();

    /**
     * Address: 0x0060B050 (FUN_0060B050, scalar deleting thunk)
     */
    ~CUnitFireAtTaskTypeInfo() override;

    /**
     * Address: 0x0060B040 (FUN_0060B040)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0060B000 (FUN_0060B000)
     */
    void Init() override;

    /**
     * Address: 0x0060C720 (FUN_0060C720, Moho::CUnitFireAtTaskTypeInfo::AddBase_CCommandTask)
     */
    static void __stdcall AddBase_CCommandTask(gpg::RType* typeInfo);

    /**
     * Address: 0x0060C0B0 (FUN_0060C0B0, Moho::CUnitFireAtTaskTypeInfo::NewRef)
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x0060C170 (FUN_0060C170, Moho::CUnitFireAtTaskTypeInfo::CtrRef)
     *
     * What it does:
     * Placement-constructs one fire-at-task runtime lane in caller storage and
     * returns typed reflection reference.
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x0060C150 (FUN_0060C150, Moho::CUnitFireAtTaskTypeInfo::Delete)
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x0060C200 (FUN_0060C200, Moho::CUnitFireAtTaskTypeInfo::Destruct)
     */
    static void Destruct(void* objectStorage);
  };

  int register_CUnitFireAtTaskTypeInfo();

  static_assert(sizeof(CUnitFireAtTaskTypeInfo) == 0x64, "CUnitFireAtTaskTypeInfo size must be 0x64");
} // namespace moho

