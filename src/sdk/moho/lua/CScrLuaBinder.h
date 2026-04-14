#pragma once

#include <cstddef>

#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"

namespace moho
{
  class CScrLuaBinder : public CScrLuaInitForm
  {
  public:
    using LuaFunction = int(__cdecl*)(lua_State*);

    /**
     * Address: 0x10015970 (FUN_10015970)
     *
     * CScrLuaInitFormSet &, char const *, int (__cdecl *)(lua_State *),
     * CScrLuaObjectFactory *, char const *, char const *
     *
     * IDA signature:
     * Moho::CScrLuaBinder *__thiscall Moho::CScrLuaBinder::CScrLuaBinder(
     *     Moho::CScrLuaBinder *this,
     *     struct Moho::CScrLuaInitFormSet *a2,
     *     const char *a3,
     *     int (__cdecl *a4)(struct lua_State *),
     *     struct Moho::CScrLuaObjectFactory *a5,
     *     const char *a6,
     *     const char *a7)
     *
     * What it does:
     * Builds a function binder init-form, wiring Lua C function and optional destination object factory.
     */
    CScrLuaBinder(
      CScrLuaInitFormSet& set,
      const char* name,
      LuaFunction function,
      CScrLuaObjectFactory* ownerFactory,
      const char* groupName,
      const char* docString
    );

    /**
     * Address: 0x100159C0 (FUN_100159C0)
     *
     * CScrLuaBinder &, CScrLuaBinder const &
     *
     * What it does:
     * Copy-constructs binder metadata and all trailing binder fields.
     */
    CScrLuaBinder(const CScrLuaBinder& other);

    /**
     * Address: 0x100BEE80 (FUN_100BEE80)
     * Address: 0x004CD3A0 (FUN_004CD3A0, Moho::CScrLuaBinder::Run)
     *
     * LuaState *
     *
     * What it does:
     * Registers a Lua C function either on globals or on a factory-provided object table.
     */
    void Run(LuaPlus::LuaState* state) override;

  public:
    LuaFunction mFunction;               // +0x14
    CScrLuaObjectFactory* mOwnerFactory; // +0x18
    void* mUnknown1C;                    // +0x1C (copied by ctor/operator paths; semantic use unresolved)
    void* mUnknown20;                    // +0x20 (copied by ctor/operator paths; semantic use unresolved)
  };
  static_assert(offsetof(CScrLuaBinder, mFunction) == 0x14, "CScrLuaBinder::mFunction offset must be 0x14");
  static_assert(offsetof(CScrLuaBinder, mOwnerFactory) == 0x18, "CScrLuaBinder::mOwnerFactory offset must be 0x18");
  static_assert(offsetof(CScrLuaBinder, mUnknown1C) == 0x1C, "CScrLuaBinder::mUnknown1C offset must be 0x1C");
  static_assert(offsetof(CScrLuaBinder, mUnknown20) == 0x20, "CScrLuaBinder::mUnknown20 offset must be 0x20");
  static_assert(sizeof(CScrLuaBinder) == 0x24, "CScrLuaBinder size must be 0x24");
} // namespace moho
