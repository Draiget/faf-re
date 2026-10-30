#pragma once

struct lua_State;

namespace moho
{
  /// A C function as Lua calls it (`lua_CFunction`).
  using LuaCFunctionPtr = int (*)(lua_State*);

  /**
   * Engine addition, not in the binary: a check the calling thread's Lua runs before each C
   * function it calls (with that function) and before each garbage collection (with null).
   * A sim phase that keeps worker jobs running next to Lua uses it to finish them before Lua can
   * reach engine state the jobs read. Pure Lua never reaches it.
   */
  using LuaCallGate = void (*)(LuaCFunctionPtr function);

  /// Sets this thread's gate (null removes it).
  void LUA_SetCallGate(LuaCallGate gate) noexcept;

  /**
   * True for the C functions of the Lua libraries (base, coroutine, string, table with FAF's
   * additions, math): they read and write only Lua values, never engine objects.
   */
  [[nodiscard]] bool LUA_IsLibraryCFunction(LuaCFunctionPtr function) noexcept;
} // namespace moho
