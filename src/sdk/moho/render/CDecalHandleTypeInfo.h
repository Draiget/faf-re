#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E37308
   * COL: 0x00E916C4
   *
   * Source hints:
   * - c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\reflection.cpp
   */
  class CDecalHandleTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00779EF0 (FUN_00779EF0, Moho::CDecalHandleTypeInfo::dtr)
     * Slot: 2
     */
    ~CDecalHandleTypeInfo() override;

    /**
     * Address: 0x00779EE0 (FUN_00779EE0, Moho::CDecalHandleTypeInfo::GetName)
     * Slot: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00779EA0 (FUN_00779EA0, Moho::CDecalHandleTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Sets `CDecalHandle` size metadata and hook function pointers for
     * reflection construction/destruction lanes, then finalizes the type.
     */
    void Init() override;

  private:
    /**
     * Address: 0x0077D8B0 (FUN_0077D8B0, Moho::CDecalHandleTypeInfo::AddBase_CScriptObject)
     *
     * What it does:
     * Registers `CScriptObject` as base metadata at subobject offset `0`.
     */
    static void AddBase_CScriptObject(gpg::RType* typeInfo);
  };

  static_assert(sizeof(CDecalHandleTypeInfo) == 0x64, "CDecalHandleTypeInfo size must be 0x64");
} // namespace moho
