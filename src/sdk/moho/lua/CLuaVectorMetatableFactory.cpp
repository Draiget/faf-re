#include "moho/lua/CLuaVectorMetatableFactory.h"

namespace
{
  constexpr const char* kVectorExpectedError = "Vector expected";
  constexpr const char* kVectorKeyExpectedError = "'x', 'y', or 'z' expected";

  /**
   * Address: 0x100C1070 (FUN_100C1070, sub_100C1070, MohoEngine.dll)
   * Address: 0x004CF930 (FUN_004CF930, sub_4CF930, ForgedAlliance.exe mirror)
   *
   * What it does:
   * Metamethod for vector tables (`__index`):
   * validates `x`/`y`/`z` key and forwards to `lua_rawgeti`.
   */
  int cfunc_LuaVectorIndex(lua_State* const state)
  {
    if (lua_type(state, 1) != LUA_TTABLE) {
      luaL_argerror(state, 1, kVectorExpectedError);
    }

    const char* const key = lua_tostring(state, 2);
    if (!key) {
      luaL_argerror(state, 2, kVectorKeyExpectedError);
    }

    const int luaIndex = static_cast<int>(key[0]) - 'w';
    if ((static_cast<unsigned int>(static_cast<int>(key[0]) - 'x') > 2U) || key[1] != '\0') {
      luaL_argerror(state, 2, kVectorKeyExpectedError);
    }

    lua_rawgeti(state, 1, luaIndex);
    return 1;
  }

  /**
   * Address: 0x100C1100 (FUN_100C1100, sub_100C1100, MohoEngine.dll)
   * Address: 0x004CF9C0 (FUN_004CF9C0, sub_4CF9C0, ForgedAlliance.exe mirror)
   *
   * What it does:
   * Metamethod for vector tables (`__newindex`):
   * validates `x`/`y`/`z` key and forwards to `lua_rawseti`.
   */
  int cfunc_LuaVectorNewIndex(lua_State* const state)
  {
    if (lua_type(state, 1) != LUA_TTABLE) {
      luaL_argerror(state, 1, kVectorExpectedError);
    }

    const char* const key = lua_tostring(state, 2);
    if (!key) {
      luaL_argerror(state, 2, kVectorKeyExpectedError);
    }

    const int luaIndex = static_cast<int>(key[0]) - 'w';
    if ((static_cast<unsigned int>(static_cast<int>(key[0]) - 'x') > 2U) || key[1] != '\0') {
      luaL_argerror(state, 2, kVectorKeyExpectedError);
    }

    lua_rawseti(state, 1, luaIndex);
    return 0;
  }
} // namespace

namespace moho
{
  CLuaVectorMetatableFactory CLuaVectorMetatableFactory::sInstance{};
}

/**
 * Address: 0x100C1210 (startup init chunk, MohoEngine.dll)
 */
moho::CLuaVectorMetatableFactory::CLuaVectorMetatableFactory()
  : CScrLuaObjectFactory(CScrLuaObjectFactory::AllocateFactoryObjectIndex())
{}

moho::CLuaVectorMetatableFactory& moho::CLuaVectorMetatableFactory::Instance()
{
  return sInstance;
}

/**
 * Address: 0x100C1180 (FUN_100C1180, sub_100C1180, MohoEngine.dll)
 * Address: 0x004CFA40 (FUN_004CFA40, sub_4CFA40, ForgedAlliance.exe mirror)
 */
LuaPlus::LuaObject moho::CLuaVectorMetatableFactory::Create(LuaPlus::LuaState* const state)
{
  LuaPlus::LuaObject metatable;
  metatable.AssignNewTable(state, 0, 0);
  metatable.Register("__index", cfunc_LuaVectorIndex, 0);
  metatable.Register("__newindex", cfunc_LuaVectorNewIndex, 0);
  return metatable;
}
