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
 * Address: 0x009137B0 (FUN_009137B0, lua_Error::lua_Error)
 * Mangled: ??0lua_Error@@QAE@@Z
 *
 * What it does:
 * Copy-constructs one Lua error payload and preserves the source state's
 * `code` and `L` fields.
 */
lua::lua_Error::lua_Error(const lua::lua_Error& error)
  : std::runtime_error(error), L(error.L), code(error.code)
{
}

/**
 * What it does:
 * Implements base Lua error destruction by delegating to normal
 * `std::runtime_error` teardown.
 */
lua::lua_Error::~lua_Error() = default;

/**
 * Address: 0x009137E0 (FUN_009137E0, lua_RuntimeError::lua_RuntimeError)
 * Mangled: ??0lua_RuntimeError@@QAE@@Z
 *
 * What it does:
 * Copy-constructs one runtime-error lane from an existing Lua error payload.
 */
lua_RuntimeError::lua_RuntimeError(const lua::lua_Error& error)
  : lua::lua_Error(error)
{
}

/**
 * Address: 0x00913170 (FUN_00913170, non-deleting dtor lane)
 * Address: 0x009132A0 (FUN_009132A0, deleting dtor lane)
 * Mangled: lua_RuntimeError::dtr
 *
 * What it does:
 * Implements the recovered `lua_RuntimeError` virtual destruction lanes.
 */
lua_RuntimeError::~lua_RuntimeError() = default;

/**
 * Address: 0x00914780 (FUN_00914780, lua_ErrorError::lua_ErrorError)
 * Mangled: ??0lua_ErrorError@@QAE@@Z
 *
 * What it does:
 * Copy-constructs one error-error lane from an existing Lua error payload.
 */
lua_ErrorError::lua_ErrorError(const lua::lua_Error& error)
  : lua::lua_Error(error)
{
}

/**
 * Address: 0x009141B0 (FUN_009141B0, non-deleting dtor lane)
 * Address: 0x009141F0 (FUN_009141F0, deleting dtor lane)
 * Mangled: lua_ErrorError::dtr
 *
 * What it does:
 * Implements the recovered `lua_ErrorError` virtual destruction lanes.
 */
lua_ErrorError::~lua_ErrorError() = default;

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
 * Address: 0x009182D0 (FUN_009182D0, non-deleting dtor lane)
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
 * Address: 0x0091A380 (FUN_0091A380, lua_MemError::lua_MemError)
 * Mangled: ??0lua_MemError@@QAE@@Z
 *
 * What it does:
 * Copy-constructs one memory-error lane from an existing Lua error payload.
 */
lua_MemError::lua_MemError(const lua::lua_Error& error)
  : lua::lua_Error(error)
{
}

/**
 * Address: 0x0091A1B0 (FUN_0091A1B0, non-deleting dtor lane)
 * Address: 0x0091A1F0 (FUN_0091A1F0, lua_MemError::dtr)
 * Mangled: lua_MemError::dtr
 *
 * What it does:
 * Implements the recovered `lua_MemError` virtual destruction lane. The
 * original binary path is a scalar-deleting destructor; in source form this
 * is represented as the class destructor.
 */
lua_MemError::~lua_MemError() = default;
