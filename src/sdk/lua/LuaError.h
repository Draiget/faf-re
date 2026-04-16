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

    /**
     * Address: 0x009137B0 (FUN_009137B0, lua_Error::lua_Error)
     * Mangled: ??0lua_Error@@QAE@@Z
     *
     * What it does:
     * Copy-constructs one Lua error payload, preserving the source runtime
     * error text plus `L` and `code` lanes.
     */
    lua_Error(const lua_Error& error);

    /**
     * What it does:
     * Destroys one base Lua error payload by delegating to the inherited
     * `std::runtime_error` destruction lane.
     */
    ~lua_Error() override;

    lua_State* L;   // originating lua state
    int code;       // numeric lua error code (e.g. LUA_ERRMEM, LUA_ERRRUN)
  };

  static_assert(sizeof(lua_Error) == 0x30, "lua::lua_Error size must be 0x30");
} // namespace lua

/**
 * VFTABLE: `lua_MemError::`vftable''
 *
 * Specialized Lua memory-allocation exception lane used by `luaM_realloc`
 * throw paths.
 */
class lua_MemError : public lua::lua_Error
{
public:
  /**
   * Address: 0x0091A380 (FUN_0091A380, lua_MemError::lua_MemError)
   * Mangled: ??0lua_MemError@@QAE@@Z
   *
   * What it does:
   * Copy-constructs one memory-error lane from an existing Lua error payload
   * and installs the derived `lua_MemError` vtable.
   */
  lua_MemError(const lua::lua_Error& error);

  /**
   * Address: 0x0091A1B0 (FUN_0091A1B0, non-deleting dtor lane)
   * Address: 0x0091A1F0 (FUN_0091A1F0)
   * Mangled: lua_MemError::dtr
   *
   * What it does:
   * Destroys one `lua_MemError` object and releases exception storage through
   * the usual C++ virtual-destruction path.
  */
  ~lua_MemError() override;
};

static_assert(sizeof(lua_MemError) == 0x30, "lua_MemError size must be 0x30");

/**
 * VFTABLE: `lua_RuntimeError::`vftable''
 *
 * Runtime-error exception lane used by Lua protected-call failure paths.
 */
class lua_RuntimeError : public lua::lua_Error
{
public:
  /**
   * Address: 0x009137E0 (FUN_009137E0, lua_RuntimeError::lua_RuntimeError)
   * Mangled: ??0lua_RuntimeError@@QAE@@Z
   *
   * What it does:
   * Copy-constructs one runtime-error lane from an existing Lua error payload
   * and installs the derived `lua_RuntimeError` vtable.
   */
  lua_RuntimeError(const lua::lua_Error& error);

  /**
   * Address: 0x00913170 (FUN_00913170, non-deleting dtor lane)
   * Address: 0x009132A0 (FUN_009132A0, deleting dtor lane)
   * Mangled: lua_RuntimeError::dtr
   *
   * What it does:
   * Destroys one `lua_RuntimeError` object and releases exception storage
   * through the normal scalar-deleting destructor path.
   */
  ~lua_RuntimeError() override;
};

static_assert(sizeof(lua_RuntimeError) == 0x30, "lua_RuntimeError size must be 0x30");

/**
 * VFTABLE: `lua_ErrorError::`vftable''
 *
 * Secondary error lane used when Lua error handling itself faults.
 */
class lua_ErrorError : public lua::lua_Error
{
public:
  /**
   * Address: 0x00914780 (FUN_00914780, lua_ErrorError::lua_ErrorError)
   * Mangled: ??0lua_ErrorError@@QAE@@Z
   *
   * What it does:
   * Copy-constructs one error-error lane from an existing Lua error payload
   * and installs the derived `lua_ErrorError` vtable.
   */
  lua_ErrorError(const lua::lua_Error& error);

  /**
   * Address: 0x009141B0 (FUN_009141B0, non-deleting dtor lane)
   * Address: 0x009141F0 (FUN_009141F0, deleting dtor lane)
   * Mangled: lua_ErrorError::dtr
   *
   * What it does:
   * Destroys one `lua_ErrorError` object and releases exception storage
   * through the normal scalar-deleting destructor path.
   */
  ~lua_ErrorError() override;
};

static_assert(sizeof(lua_ErrorError) == 0x30, "lua_ErrorError size must be 0x30");

/**
 * VFTABLE: `lua_SyntaxError::`vftable''
 *
 * Syntax-error exception lane used by Lua parser and compile-time error
 * recovery paths.
 */
class lua_SyntaxError : public lua::lua_Error
{
public:
  /**
   * Address: 0x00919900 (FUN_00919900)
   * Mangled: ??0lua_SyntaxError@@QAE@@Z
   *
   * What it does:
   * Copies an existing Lua error payload into a syntax-error exception object
   * and installs the derived vtable.
   */
  lua_SyntaxError(const lua::lua_Error& error);

  /**
   * Address: 0x009182D0 (FUN_009182D0, non-deleting dtor lane)
   * Address: 0x009188A0 (FUN_009188A0)
   * Mangled: lua_SyntaxError::dtr
   *
   * What it does:
   * Destroys one `lua_SyntaxError` object and releases exception storage
   * through the normal scalar-deleting destructor path.
   */
  ~lua_SyntaxError() override;
};

static_assert(sizeof(lua_SyntaxError) == 0x30, "lua_SyntaxError size must be 0x30");
