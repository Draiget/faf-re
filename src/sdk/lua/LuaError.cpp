#include "lua/LuaError.h"

/**
 * Address: 0x009140D0 (FUN_009140D0)
 * Mangled: ??0lua_Error@lua@@Z_0
 *
 * What it does:
 * Constructs a `lua_Error` by forwarding `err` to `std::runtime_error`, then
 * stores `lua_state` in `L` and `errcode` in `code`.  The vtable is set by
 * the usual C++ construction sequence.
 */
lua::lua_Error::lua_Error(lua_State* const lua_state, const int errcode, const char* const err)
  : std::runtime_error(err), L(lua_state), code(errcode)
{
}
