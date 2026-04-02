#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/Vector.h"
#include "lua/LuaObject.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/serialization/PrefetchHandleBase.h"

namespace moho
{
  class CPrefetchSet
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x004A5290 (FUN_004A5290, Moho::CPrefetchset::Update)
     *
     * What it does:
     * Rebuilds the prefetch-handle vector from one Lua table grouped by
     * prefetch-kind keys.
     */
    void Update(LuaPlus::LuaObject prefetchTable, LuaPlus::LuaState* state);

    /**
     * Address: 0x004A59D0 (FUN_004A59D0 call chain via sub_4A6340)
     *
     * What it does:
     * Clears all currently tracked prefetch handles.
     */
    void Reset();

    [[nodiscard]] static gpg::RType* StaticGetClass();

  public:
    msvc8::vector<PrefetchHandleBase> mHandles; // +0x00
  };

  static_assert(offsetof(CPrefetchSet, mHandles) == 0x00, "CPrefetchSet::mHandles offset must be 0x00");
  static_assert(sizeof(CPrefetchSet) == 0x10, "CPrefetchSet size must be 0x10");

  template <>
  class CScrLuaMetatableFactory<CPrefetchSet> final : public CScrLuaObjectFactory
  {
  public:
    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x004A5FC0 (FUN_004A5FC0, Moho::CScrLuaMetatableFactory<Moho::CPrefetchSet>::Create)
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(sizeof(CScrLuaMetatableFactory<CPrefetchSet>) == 0x08, "CScrLuaMetatableFactory<CPrefetchSet> size must be 0x08");

  /**
   * Address: 0x004A7D20 (FUN_004A7D20, func_CreatePrefetchSet)
   *
   * What it does:
   * Creates one Lua userdata wrapper around a newly allocated `CPrefetchSet`.
   */
  LuaPlus::LuaObject func_CreatePrefetchSet(LuaPlus::LuaState* state);

  /**
   * Address: 0x004A7DD0 (FUN_004A7DD0, func_GetCObj_CPrefetchSet)
   * Address: 0x004A8660 (FUN_004A8660, gpg::RRef::TryUpcast_CPrefetchSet)
   *
   * What it does:
   * Resolves native `CPrefetchSet*` from one Lua object or table `_c_object` lane.
   */
  CPrefetchSet* func_GetCObj_CPrefetchSet(LuaPlus::LuaObject object);

  /**
   * Address: 0x004A5700 (FUN_004A5700, cfunc_CreatePrefetchSet)
   */
  int cfunc_CreatePrefetchSet(lua_State* luaContext);

  /**
   * Address: 0x004A5780 (FUN_004A5780, cfunc_CreatePrefetchSetL)
   */
  int cfunc_CreatePrefetchSetL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004A5720 (FUN_004A5720, func_CreatePrefetchSet_LuaFuncDef)
   */
  CScrLuaInitForm* func_CreatePrefetchSet_LuaFuncDef();

  /**
   * Address: 0x004A5810 (FUN_004A5810, cfunc_CPrefetchSetUpdate)
   */
  int cfunc_CPrefetchSetUpdate(lua_State* luaContext);

  /**
   * Address: 0x004A5890 (FUN_004A5890, cfunc_CPrefetchSetUpdateL)
   */
  int cfunc_CPrefetchSetUpdateL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004A5830 (FUN_004A5830, func_CPrefetchSetUpdate_LuaFuncDef)
   */
  CScrLuaInitForm* func_CPrefetchSetUpdate_LuaFuncDef();

  /**
   * Address: 0x004A5950 (FUN_004A5950, cfunc_CPrefetchSetReset)
   */
  int cfunc_CPrefetchSetReset(lua_State* luaContext);

  /**
   * Address: 0x004A59D0 (FUN_004A59D0, cfunc_CPrefetchSetResetL)
   */
  int cfunc_CPrefetchSetResetL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004A5970 (FUN_004A5970, func_CPrefetchSetReset_LuaFuncDef)
   */
  CScrLuaInitForm* func_CPrefetchSetReset_LuaFuncDef();
} // namespace moho
