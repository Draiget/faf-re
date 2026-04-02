#pragma once

#include <cstdint>

#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"

struct lua_State;
struct lua_Debug;

namespace LuaPlus
{
  class LuaState;
} // namespace LuaPlus

namespace moho
{
  class ScrActivation;
  class ScrBreakpoint;
  class ScrWatch;

  /**
   * Address: 0x004B49B0 (FUN_004B49B0, Moho::SCR_HookState)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Binds one Lua state to the script debug hook callback when a debug window
   * runtime is active.
   */
  void SCR_HookState(LuaPlus::LuaState* state);

  /**
   * Address: 0x004B49D0 (FUN_004B49D0, Moho::SCR_UnhookState)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Removes one Lua state from script debug hook dispatch and clears the Lua
   * hook callback.
   */
  void SCR_UnhookState(LuaPlus::LuaState* state);

  /**
   * Address: 0x004B4A30 (FUN_004B4A30, Moho::SCR_AddBreakpoint)
   *
   * Moho::ScrBreakpoint const &
   *
   * What it does:
   * Inserts one breakpoint in sorted unique order and persists preferences
   * after successful insertion.
   */
  void SCR_AddBreakpoint(const ScrBreakpoint& breakpoint);

  /**
   * Address: 0x004B4AC0 (FUN_004B4AC0, Moho::SCR_EnableBreakpoint)
   *
   * Moho::ScrBreakpoint const &,bool
   *
   * What it does:
   * Updates one existing breakpoint enabled lane and persists preferences.
   */
  void SCR_EnableBreakpoint(const ScrBreakpoint& breakpoint, bool enabled);

  /**
   * Address: 0x004B4B50 (FUN_004B4B50, Moho::SCR_EnableAllBreakpoints)
   *
   * bool
   *
   * What it does:
   * Applies one enabled lane to every global breakpoint and persists
   * preferences.
   */
  void SCR_EnableAllBreakpoints(bool enabled);

  /**
   * Address: 0x004B4BF0 (FUN_004B4BF0, Moho::SCR_RemoveBreakpoint)
   *
   * Moho::ScrBreakpoint const &
   *
   * What it does:
   * Removes one matching global breakpoint and persists preferences.
   */
  void SCR_RemoveBreakpoint(const ScrBreakpoint& breakpoint);

  /**
   * Address: 0x004B4C80 (FUN_004B4C80, Moho::SCR_RemoveAllBreakpoints)
   *
   * What it does:
   * Clears all global breakpoints, refreshes enabled-state cache, and persists
   * preferences.
   */
  void SCR_RemoveAllBreakpoints();

  /**
   * Address: 0x004B4D20 (FUN_004B4D20, Moho::SCR_EnumerateBreakpoints)
   *
   * std::string const &,std::vector<Moho::ScrBreakpoint> &
   *
   * What it does:
   * Enumerates breakpoints matching one mounted source path into output storage.
   */
  void SCR_EnumerateBreakpoints(const msvc8::string& sourcePath, msvc8::vector<ScrBreakpoint>& outBreakpoints);

  /**
   * Address: 0x004B4DF0 (FUN_004B4DF0, Moho::SCR_EnumerateCallStack)
   *
   * std::vector<Moho::ScrActivation> &
   *
   * What it does:
   * Enumerates call-stack activation frames for the currently paused script state.
   */
  void SCR_EnumerateCallStack(msvc8::vector<ScrActivation>& outActivations);

  /**
   * Address: 0x004B5140 (FUN_004B5140, Moho::SCR_EnumerateLocals)
   *
   * int,std::vector<Moho::ScrWatch> &
   *
   * What it does:
   * Enumerates locals and closure upvalues from one Lua stack level.
   */
  void SCR_EnumerateLocals(int level, msvc8::vector<ScrWatch>& outWatches);

  /**
   * Address: 0x004B5470 (FUN_004B5470, Moho::SCR_EnumerateGlobals)
   *
   * std::vector<Moho::ScrWatch> &
   *
   * What it does:
   * Enumerates global Lua table entries for the currently paused script state.
   */
  void SCR_EnumerateGlobals(msvc8::vector<ScrWatch>& outWatches);

  /**
   * Address: 0x004B5690 (FUN_004B5690, Moho::SCR_DebugStep)
   *
   * What it does:
   * Resumes the oldest paused script thread and schedules one single-step stop
   * for that thread root state.
   */
  void SCR_DebugStep();

  /**
   * Address: 0x004B5790 (FUN_004B5790, Moho::SCR_DebugResume)
   *
   * What it does:
   * Resumes the oldest paused script thread without scheduling a step stop.
   */
  void SCR_DebugResume();

  /**
   * Address: 0x004B5840 (FUN_004B5840, Moho::SCR_LoadBreakpoints)
   *
   * What it does:
   * Loads persisted breakpoint entries from user preferences and rebuilds the
   * in-memory sorted breakpoint list.
   */
  void SCR_LoadBreakpoints();

  /**
   * Address: 0x004B59B0 (FUN_004B59B0, Moho::SCR_SaveBreakpoints)
   *
   * What it does:
   * Serializes the in-memory breakpoint list and stores it to user
   * preferences.
   */
  void SCR_SaveBreakpoints();

  /**
   * Address: 0x004B5C70 (FUN_004B5C70, Moho::DebugLuaHook)
   *
   * lua_State *,lua_Debug *
   *
   * What it does:
   * Handles Lua line-hook notifications, checking queued single-step roots and
   * explicit file/line breakpoints before pausing the current script thread.
   */
  void DebugLuaHook(lua_State* state, lua_Debug* debugFrame);

  /**
   * Returns whether the script debug window runtime is currently active.
   */
  [[nodiscard]] bool SCR_IsDebugWindowActive();

  /**
   * Updates script debug window runtime ownership used by pause/resume flows.
   */
  void SCR_SetDebugWindowRuntime(void* debugWindow, std::uint32_t ownerThreadId);
} // namespace moho
