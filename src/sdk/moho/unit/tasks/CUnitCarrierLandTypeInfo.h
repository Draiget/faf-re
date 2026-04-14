#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitCarrierLand;

  /**
   * VFTABLE: 0x00E2009C
   */
  class CUnitCarrierLandTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00606B70 (FUN_00606B70)
     */
    CUnitCarrierLandTypeInfo();

    /**
     * Address: 0x00606C20 (FUN_00606C20, scalar deleting thunk)
     */
    ~CUnitCarrierLandTypeInfo() override;

    /**
     * Address: 0x00606C10 (FUN_00606C10)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00606BD0 (FUN_00606BD0)
     */
    void Init() override;

    /**
     * Address: 0x00607EA0 (FUN_00607EA0, Moho::CUnitCarrierLandTypeInfo::AddBase_CCommandTask)
     */
    static void __stdcall AddBase_CCommandTask(gpg::RType* typeInfo);

    /**
     * Address: 0x00607B50 (FUN_00607B50, Moho::CUnitCarrierLandTypeInfo::NewRef)
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x00607C30 (FUN_00607C30, Moho::CUnitCarrierLandTypeInfo::CtrRef)
     *
     * What it does:
     * Placement-constructs one carrier-land task runtime lane in caller
     * storage and returns typed reflection reference.
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x00607C10 (FUN_00607C10, Moho::CUnitCarrierLandTypeInfo::Delete)
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x00607CF0 (FUN_00607CF0, Moho::CUnitCarrierLandTypeInfo::Destruct)
     */
    static void Destruct(void* objectStorage);
  };

  int register_CUnitCarrierLandTypeInfo();

  static_assert(sizeof(CUnitCarrierLandTypeInfo) == 0x64, "CUnitCarrierLandTypeInfo size must be 0x64");
} // namespace moho

