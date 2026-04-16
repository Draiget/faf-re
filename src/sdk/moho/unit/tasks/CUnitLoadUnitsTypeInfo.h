#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitLoadUnits;

  /**
   * VFTABLE: 0x00E20E3C
   * COL: 0x00E7A3FC
   */
  class CUnitLoadUnitsTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00624F40 (FUN_00624F40, scalar deleting destructor thunk)
     */
    ~CUnitLoadUnitsTypeInfo() override;

    /**
     * Address: 0x00624F30 (FUN_00624F30, Moho::CUnitLoadUnitsTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflected type name literal for `CUnitLoadUnits`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00624EF0 (FUN_00624EF0, Moho::CUnitLoadUnitsTypeInfo::Init)
     *
     * What it does:
     * Sets reflected size/callback lanes, registers `CCommandTask` as the base
     * slice, and finalizes initialization.
     */
    void Init() override;

    /**
     * Address: 0x00627F50 (FUN_00627F50, Moho::CUnitLoadUnitsTypeInfo::AddBase_CCommandTask)
     */
    static void __stdcall AddBase_CCommandTask(gpg::RType* typeInfo);

    /**
     * Address: 0x00627C20 (FUN_00627C20, Moho::CUnitLoadUnitsTypeInfo::NewRef)
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x00627CC0 (FUN_00627CC0, Moho::CUnitLoadUnitsTypeInfo::CtrRef)
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x00627CA0 (FUN_00627CA0, Moho::CUnitLoadUnitsTypeInfo::Delete)
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x00627D30 (FUN_00627D30, Moho::CUnitLoadUnitsTypeInfo::Destruct)
     */
    static void Destruct(void* objectStorage);
  };

  static_assert(sizeof(CUnitLoadUnitsTypeInfo) == 0x64, "CUnitLoadUnitsTypeInfo size must be 0x64");
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x00628C00 (FUN_00628C00, gpg::RRef_CUnitLoadUnits)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitLoadUnits*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitLoadUnits(gpg::RRef* outRef, moho::CUnitLoadUnits* value);
} // namespace gpg

