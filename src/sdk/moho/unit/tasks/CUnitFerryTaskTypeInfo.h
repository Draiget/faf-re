#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitFerryTask;

  /**
   * VFTABLE: 0x00E203EC
   */
  class CUnitFerryTaskTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0060DB00 (FUN_0060DB00)
     *
     * What it does:
     * Preregisters `CUnitFerryTask` RTTI into the reflection lookup table.
     */
    CUnitFerryTaskTypeInfo();

    /**
     * Address: 0x0060DBB0 (FUN_0060DBB0, scalar deleting thunk)
     */
    ~CUnitFerryTaskTypeInfo() override;

    /**
     * Address: 0x0060DBA0 (FUN_0060DBA0, Moho::CUnitFerryTaskTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0060DB60 (FUN_0060DB60, Moho::CUnitFerryTaskTypeInfo::Init)
     */
    void Init() override;

    /**
     * Address: 0x006104B0 (FUN_006104B0, Moho::CUnitFerryTaskTypeInfo::AddBase_CCommandTask)
     */
    static void __stdcall AddBase_CCommandTask(gpg::RType* typeInfo);

    /**
     * Address: 0x006101B0 (FUN_006101B0, Moho::CUnitFerryTaskTypeInfo::NewRef)
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x00610280 (FUN_00610280, Moho::CUnitFerryTaskTypeInfo::CtrRef)
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x00610260 (FUN_00610260, Moho::CUnitFerryTaskTypeInfo::Delete)
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x00610330 (FUN_00610330, Moho::CUnitFerryTaskTypeInfo::Destruct)
     */
    static void Destruct(void* objectStorage);
  };

  int register_CUnitFerryTaskTypeInfo();

  static_assert(sizeof(CUnitFerryTaskTypeInfo) == 0x64, "CUnitFerryTaskTypeInfo size must be 0x64");
} // namespace moho

