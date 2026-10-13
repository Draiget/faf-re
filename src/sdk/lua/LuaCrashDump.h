#ifndef LUA_LUACRASHDUMP_H
#define LUA_LUACRASHDUMP_H

#include <cstdio>

struct lua_State;

namespace lua
{

  /**
   * Crash-path Lua diagnostics (deviation from the 2007 binary, documented:
   * new engine functionality; nothing here runs outside a crash handler).
   *
   * A global registry of live VMs is maintained by lua_open/lua_close and
   * refreshed per-execution by luaV_execute (thread-active flag). On a crash
   * the handler dumps, per VM:
   *   - the CallInfo chain: function, source chunk, current line
   *     (exact on the running frame: luaV_execute keeps `ci->pc` live),
   *     C-function and suspended frames marked as such;
   *   - top-of-stack values with type tags;
   *   - when a frame is inside table code, the suspect table's header and
   *     nodes, flagging the two stray-write signatures FADeepProbe #3 found:
   *     nil-key/non-nil-value nodes, and keys unreachable from luaH_get.
   */
  void RegisterLuaVm(lua_State* state);
  void UnregisterLuaVm(lua_State* state);

  /**
   * Attaches a diagnostics-only display name ("UI", "Sim", "Lobby", ...) to
   * one registered root VM. The name lives in the crash-dump registry only -
   * never in lua_State, never serialized, invisible to the simulation.
   */
  void NameLuaVm(lua_State* state, const char* name);

  /**
   * Records one Lua error message (already traceback-formatted - callers
   * pass lua_Error::what()) into a bounded ring the crash report prints.
   * The record carries the VM name, so "which script kept failing" is
   * answerable from the report alone.
   */
  void RecordLuaError(lua_State* state, const char* message);

  /** Marks `state` as the VM running on the current thread (crash handler). */
  void SetThreadActiveLuaVm(lua_State* state);

  /** Crash-report section writer: dumps every registered VM. */
  void WriteLuaCrashSection(std::FILE* sink, const void* faultAddress, const void* accessTarget);

  /**
   * Extra annotation when the faulting address or AV target belongs to a
   * registered VM's stack or a table being dumped. Best-effort; quiet.
   */
  void AnnotateLuaAddress(std::FILE* sink, const void* address);

} // namespace lua

#endif // LUA_LUACRASHDUMP_H
