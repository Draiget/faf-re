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

/**
 * Address: 0x009132A0 (FUN_009132A0, lua_RuntimeError::dtr)
 *
 * What it does:
 * Implements the recovered Lua runtime-error destruction lane by delegating
 * to normal `std::runtime_error` teardown.
 */
lua::lua_Error::~lua_Error() = default;

/**
 * Address: 0x00919900 (FUN_00919900)
 * Mangled: ??0lua_SyntaxError@@QAE@@Z
 *
 * What it does:
 * Copies the base Lua error state into a syntax-error exception object and
 * leaves the derived syntax-error vtable installed.
 */
lua_SyntaxError::lua_SyntaxError(const lua::lua_Error& error)
  : lua::lua_Error(error)
{
}

/**
 * Address: 0x009188A0 (FUN_009188A0)
 * Mangled: lua_SyntaxError::dtr
 *
 * What it does:
 * Implements the recovered `lua_SyntaxError` virtual destruction lane. The
 * original binary path is a scalar-deleting destructor; in source form this
 * is represented as the class destructor.
 */
lua_SyntaxError::~lua_SyntaxError() = default;

/**
 * Address: 0x0091A1F0 (FUN_0091A1F0, lua_MemError::dtr)
 * Mangled: lua_MemError::dtr
 *
 * What it does:
 * Implements the recovered `lua_MemError` virtual destruction lane. The
 * original binary path is a scalar-deleting destructor; in source form this
 * is represented as the class destructor.
 */
lua_MemError::~lua_MemError() = default;
