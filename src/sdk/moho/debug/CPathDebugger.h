#pragma once

#include "moho/lua/CScrLuaBinderFwd.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/script/CScriptObject.h"

struct lua_State;

namespace LuaPlus
{
  class LuaState;
}

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

  template <>
  class CScrLuaMetatableFactory<CPathDebugger> final : public CScrLuaObjectFactory
  {
  public:
    [[nodiscard]]
    static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<CPathDebugger>) == 0x08,
    "CScrLuaMetatableFactory<CPathDebugger> size must be 0x08"
  );

  /**
   * VFTABLE: 0x00E3CAE8
   * COL: 0x00E96520
   */
  using CPathDebuggerDestroy_LuaFuncDef = ::moho::CScrLuaBinder;
  using CCreatePathDebugger_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x007B5F90 (FUN_007B5F90, cfunc__c_CreatePathDebugger)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc__c_CreatePathDebuggerL`.
   */
  int cfunc__c_CreatePathDebugger(lua_State* luaContext);

  /**
   * Address: 0x007B5FB0 (FUN_007B5FB0, func__c_CreatePathDebugger_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder metadata for `_c_CreatePathDebugger`.
   */
  CScrLuaInitForm* func__c_CreatePathDebugger_LuaFuncDef();

  /**
   * Address: 0x007B6010 (FUN_007B6010, cfunc__c_CreatePathDebuggerL)
   *
   * What it does:
   * Validates `(luaobj, spec)` argument shape, creates one `CPathDebugger`
   * script object from the first argument, and pushes its Lua object.
   */
  int cfunc__c_CreatePathDebuggerL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007B5E60 (FUN_007B5E60, cfunc_CPathDebuggerDestroy)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CPathDebuggerDestroyL`.
   */
  int cfunc_CPathDebuggerDestroy(lua_State* luaContext);

  /**
   * Address: 0x007B5E80 (FUN_007B5E80, func_CPathDebuggerDestroy_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CPathDebugger:Destroy`.
   */
  CScrLuaInitForm* func_CPathDebuggerDestroy_LuaFuncDef();

  /**
   * Address: 0x007B5EE0 (FUN_007B5EE0, cfunc_CPathDebuggerDestroyL)
   *
   * What it does:
   * Validates one `CPathDebugger` argument from Lua, resolves object ownership,
   * and deletes the script object when it is still alive.
   */
  int cfunc_CPathDebuggerDestroyL(LuaPlus::LuaState* state);

  static_assert(sizeof(CPathDebugger) == 0x34, "CPathDebugger size must be 0x34");
} // namespace moho
