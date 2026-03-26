#pragma once

#include "moho/lua/CScrLuaBinderFwd.h"
#include "moho/script/CScriptObject.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E3CA9C
   * COL: 0x00E9660C
   */
  class CPathDebugger : public CScriptObject
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x007B5C90 (FUN_007B5C90)
     *
     * LuaObject const &
     *
     * What it does:
     * Constructs CScriptObject base state, installs CPathDebugger vftable,
     * and binds the provided Lua object.
     */
    explicit CPathDebugger(const LuaPlus::LuaObject& luaObject);

    /**
     * Address: 0x007B5C50 (FUN_007B5C50, Moho::CPathDebugger::GetClass)
     * Slot: 0
     *
     * What it does:
     * Returns cached reflection descriptor for `CPathDebugger`.
     */
    [[nodiscard]]
    gpg::RType* GetClass() const override;

    /**
     * Address: 0x007B5C70 (FUN_007B5C70, Moho::CPathDebugger::GetDerivedObjectRef)
     * Slot: 1
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x007B5CE0 (FUN_007B5CE0, Moho::CPathDebugger::dtr)
     * Slot: 2
     */
    ~CPathDebugger() override;
  };

  /**
   * VFTABLE: 0x00E3CAE8
   * COL: 0x00E96520
   */
  using CPathDebuggerDestroy_LuaFuncDef = ::moho::CScrLuaBinder;

  static_assert(sizeof(CPathDebugger) == 0x34, "CPathDebugger size must be 0x34");
} // namespace moho
