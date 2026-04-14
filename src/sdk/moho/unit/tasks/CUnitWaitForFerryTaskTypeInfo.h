#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitWaitForFerryTask;

  /**
   * VFTABLE: 0x00E20438
   */
  class CUnitWaitForFerryTaskTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0060F830 (FUN_0060F830)
     */
    CUnitWaitForFerryTaskTypeInfo();

    /**
     * Address: 0x0060F8E0 (FUN_0060F8E0, scalar deleting thunk)
     */
    ~CUnitWaitForFerryTaskTypeInfo() override;

    /**
     * Address: 0x0060F8D0 (FUN_0060F8D0)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0060F890 (FUN_0060F890)
     */
    void Init() override;

    /**
     * Address: 0x00610530 (FUN_00610530, Moho::CUnitWaitForFerryTaskTypeInfo::AddBase_CCommandTask)
     */
    static void __stdcall AddBase_CCommandTask(gpg::RType* typeInfo);

    /**
     * Address: 0x00610340 (FUN_00610340, Moho::CUnitWaitForFerryTaskTypeInfo::NewRef)
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x00610400 (FUN_00610400, Moho::CUnitWaitForFerryTaskTypeInfo::CtrRef)
     *
     * What it does:
     * Placement-constructs one wait-for-ferry task runtime lane in caller
     * storage and returns typed reflection reference.
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x006103E0 (FUN_006103E0, Moho::CUnitWaitForFerryTaskTypeInfo::Delete)
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x006104A0 (FUN_006104A0, Moho::CUnitWaitForFerryTaskTypeInfo::Destruct)
     */
    static void Destruct(void* objectStorage);
  };

  int register_CUnitWaitForFerryTaskTypeInfo();

  static_assert(sizeof(CUnitWaitForFerryTaskTypeInfo) == 0x64, "CUnitWaitForFerryTaskTypeInfo size must be 0x64");
} // namespace moho

