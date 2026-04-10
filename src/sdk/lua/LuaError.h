#pragma once

#include <stdexcept>

#include "lua/LuaPrimitives.h"

namespace lua
{
  /**
   * VFTABLE: `lua_Error::`vftable''
   * COL: from callers at `luaD_growCI`, `luaD_call`, `luaM_realloc`.
   *
   * C++ exception thrown by the Lua runtime when an error condition occurs.
   * Wraps the Lua error message and stores the originating `lua_State*` and
   * numeric error code.
   */
  class lua_Error : public std::runtime_error
  {
  public:
    /**
     * Address: 0x009140D0 (FUN_009140D0)
     * Mangled: ??0lua_Error@lua@@Z_0
     *
     * lua_State*, int, const char*
     *
     * What it does:
     * Constructs a `lua_Error` from an error message string, stores the
     * originating `lua_State` and numeric error code.  Inherits message
     * storage from `std::runtime_error`.
     */
    lua_Error(lua_State* lua_state, int errcode, const char* err);

    lua_State* L;   // originating lua state
    int code;       // numeric lua error code (e.g. LUA_ERRMEM, LUA_ERRRUN)
  };
} // namespace lua
