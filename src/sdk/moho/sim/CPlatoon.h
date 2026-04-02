#pragma once

namespace LuaPlus
{
  class LuaState;
} // namespace LuaPlus
struct lua_State;

namespace gpg
{
  class RType;
} // namespace gpg

namespace moho
{
  class CScrLuaInitForm;

  /**
   * Recovered minimal polymorphic base for platoon pointers used by
   * army serialization and reflection helper paths.
   *
   * Full gameplay layout/method surface is still pending dedicated recovery.
   */
  class CPlatoon
  {
  public:
    inline static gpg::RType* sType = nullptr;
    virtual ~CPlatoon() = default;
  };

  /**
   * Address: 0x00BDAE70 (FUN_00BDAE70, register_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef)
   *
   * What it does:
   * Forwards startup registration to `func_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef();

  /**
   * Address: 0x0072CC00 (FUN_0072CC00, cfunc_CPlatoonCanConsiderFormingPlatoon)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonCanConsiderFormingPlatoonL`.
   */
  int cfunc_CPlatoonCanConsiderFormingPlatoon(lua_State* luaContext);

  /**
   * Address: 0x0072CC80 (FUN_0072CC80, cfunc_CPlatoonCanConsiderFormingPlatoonL)
   *
   * What it does:
   * Validates one `CPlatoon` method call and returns whether arg#3 matches
   * the first element of arg#2 case-insensitively.
   */
  int cfunc_CPlatoonCanConsiderFormingPlatoonL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0072CC20 (FUN_0072CC20, func_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:CanConsiderFormingPlatoon()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef();
} // namespace moho
