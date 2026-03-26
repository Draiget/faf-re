#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E3CAB0
   * COL: 0x00E965BC
   *
   * Source hints:
   * - c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\reflection.cpp
   */
  class CPathDebuggerTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x007B5DB0 (FUN_007B5DB0, Moho::CPathDebuggerTypeInfo::dtr)
     * Slot: 2
     */
    ~CPathDebuggerTypeInfo() override;

    /**
     * Address: 0x007B5DA0 (FUN_007B5DA0, Moho::CPathDebuggerTypeInfo::GetName)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type-name literal for `CPathDebugger`.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x007B5D70 (FUN_007B5D70, Moho::CPathDebuggerTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Initializes reflection metadata for `CPathDebugger`
     * (`sizeof = 0x34`) and registers the `CScriptObject` base.
     */
    void Init() override;

  private:
    /**
     * Address: 0x007B6260 (FUN_007B6260, Moho::CPathDebuggerTypeInfo::AddBase_CScriptObject)
     *
     * What it does:
     * Registers `CScriptObject` as base metadata at subobject offset `0`.
     */
    static void AddBase_CScriptObject(gpg::RType* typeInfo);
  };

  static_assert(sizeof(CPathDebuggerTypeInfo) == 0x64, "CPathDebuggerTypeInfo size must be 0x64");
} // namespace moho
