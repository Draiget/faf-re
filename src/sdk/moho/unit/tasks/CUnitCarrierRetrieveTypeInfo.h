#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitCarrierRetrieve;

  /**
   * VFTABLE: 0x00E20050
   */
  class CUnitCarrierRetrieveTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00606240 (FUN_00606240)
     */
    CUnitCarrierRetrieveTypeInfo();

    /**
     * Address: 0x006062F0 (FUN_006062F0, scalar deleting thunk)
     */
    ~CUnitCarrierRetrieveTypeInfo() override;

    /**
     * Address: 0x006062E0 (FUN_006062E0)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006062A0 (FUN_006062A0)
     */
    void Init() override;

    /**
     * Address: 0x00607E20 (FUN_00607E20, Moho::CUnitCarrierRetrieveTypeInfo::AddBase_CCommandTask)
     */
    static void __stdcall AddBase_CCommandTask(gpg::RType* typeInfo);

    /**
     * Address: 0x006079E0 (FUN_006079E0, Moho::CUnitCarrierRetrieveTypeInfo::NewRef)
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x00607AA0 (FUN_00607AA0, Moho::CUnitCarrierRetrieveTypeInfo::CtrRef)
     *
     * What it does:
     * Placement-constructs one carrier-retrieve task runtime lane in caller
     * storage and returns typed reflection reference.
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x00607A80 (FUN_00607A80, Moho::CUnitCarrierRetrieveTypeInfo::Delete)
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x00607B40 (FUN_00607B40, Moho::CUnitCarrierRetrieveTypeInfo::Destruct)
     */
    static void Destruct(void* objectStorage);
  };

  int register_CUnitCarrierRetrieveTypeInfo();

  static_assert(sizeof(CUnitCarrierRetrieveTypeInfo) == 0x64, "CUnitCarrierRetrieveTypeInfo size must be 0x64");
} // namespace moho

