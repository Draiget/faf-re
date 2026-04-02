#include "moho/misc/ScrDebugHooks.h"

#include <cstddef>
#include <cstring>
#include <string_view>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <boost/thread/mutex.hpp>

#include "legacy/containers/Vector.h"
#include "lua/LuaObject.h"
#include "lua/LuaTableIterator.h"
#include "moho/misc/CVirtualFileSystem.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/PausedThread.h"
#include "moho/misc/ScrActivation.h"
#include "moho/misc/ScrBreakpoint.h"
#include "moho/misc/ScrPauseEvent.h"
#include "moho/misc/ScrWatch.h"
#include "moho/misc/StartupHelpers.h"

class wxEvent;
class wxEvtHandler
{
public:
  void AddPendingEvent(wxEvent& event);
};

namespace
{
  struct LuaHookBinding
  {
    lua_State* cState = nullptr;
    LuaPlus::LuaState* wrapperState = nullptr;
  };

  struct ScrDebugRuntime
  {
    void* debugWindow = nullptr;
    std::uint32_t debugWindowOwnerThreadId = 0;

    boost::mutex hookBindingMutex;
    boost::mutex singleStepMutex;
    boost::mutex breakpointMutex;
    boost::mutex pausedQueueMutex;

    msvc8::list<LuaHookBinding> hookBindings;
    msvc8::list<LuaPlus::LuaState*> singleStepRootStates;
    msvc8::list<moho::ScrBreakpoint> breakpoints;
    msvc8::list<moho::PausedThread*> pausedThreads;

    bool hasPendingSingleStepRoots = false;
    bool hasEnabledBreakpoints = false;
  };

  [[nodiscard]] ScrDebugRuntime& GetScrDebugRuntime()
  {
    static ScrDebugRuntime runtime{};
    return runtime;
  }

  constexpr char kBreakpointPreferenceKey[] = "Options.Debug.Breakpoints";
  constexpr char kDebugGetInfoMask[] = "Sln";
  constexpr char kCallStackInfoMask[] = "lnS";
  constexpr char kFunctionInfoMask[] = "f";

  [[nodiscard]] int CompareBreakpointKey(
    const moho::ScrBreakpoint& lhs,
    const moho::ScrBreakpoint& rhs
  ) noexcept
  {
    if (lhs.line < rhs.line) {
      return -1;
    }
    if (lhs.line > rhs.line) {
      return 1;
    }

    const std::string_view lhsName = lhs.name.view();
    const std::string_view rhsName = rhs.name.view();
    if (lhsName < rhsName) {
      return -1;
    }
    if (lhsName > rhsName) {
      return 1;
    }
    return 0;
  }

  [[nodiscard]] msvc8::list<moho::ScrBreakpoint>::iterator FindBreakpointExact(
    ScrDebugRuntime& runtime,
    const moho::ScrBreakpoint& key
  )
  {
    for (auto it = runtime.breakpoints.begin(); it != runtime.breakpoints.end(); ++it) {
      if (CompareBreakpointKey(*it, key) == 0) {
        return it;
      }
    }
    return runtime.breakpoints.end();
  }

  [[nodiscard]] bool InsertBreakpointSortedUnique(
    ScrDebugRuntime& runtime,
    const moho::ScrBreakpoint& breakpoint
  )
  {
    auto insertPosition = runtime.breakpoints.end();
    for (auto it = runtime.breakpoints.begin(); it != runtime.breakpoints.end(); ++it) {
      const int order = CompareBreakpointKey(breakpoint, *it);
      if (order == 0) {
        return false;
      }
      if (order < 0) {
        insertPosition = it;
        break;
      }
    }

    runtime.breakpoints.insert(insertPosition, breakpoint);
    return true;
  }

  /**
   * Address: 0x004B49F0 (FUN_004B49F0)
   *
   * What it does:
   * Rebuilds the cached "has enabled breakpoints" flag from global breakpoint
   * entries.
   */
  void RefreshAnyEnabledBreakpointsFlag(ScrDebugRuntime& runtime)
  {
    runtime.hasEnabledBreakpoints = false;
    for (const moho::ScrBreakpoint& breakpoint : runtime.breakpoints) {
      if (breakpoint.enabled) {
        runtime.hasEnabledBreakpoints = true;
        return;
      }
    }
  }

  void SaveBreakpointsUnlocked(ScrDebugRuntime& runtime)
  {
    moho::IUserPrefs* const preferences = moho::USER_GetPreferences();
    if (preferences == nullptr) {
      return;
    }

    msvc8::vector<msvc8::string> serializedBreakpoints;
    for (const moho::ScrBreakpoint& breakpoint : runtime.breakpoints) {
      serializedBreakpoints.push_back(breakpoint.AsString());
    }

    preferences->SetStringArr(msvc8::string(kBreakpointPreferenceKey), serializedBreakpoints);
  }

  [[nodiscard]] msvc8::string ToMountedSourcePath(const char* sourcePath)
  {
    msvc8::string mountedPath;
    if (sourcePath == nullptr) {
      return mountedPath;
    }

    if (moho::CVirtualFileSystem* const vfs = moho::DISK_GetVFS(); vfs != nullptr) {
      vfs->ToMountedPath(&mountedPath, sourcePath);
      return mountedPath;
    }

    mountedPath.assign(sourcePath, std::strlen(sourcePath));
    return mountedPath;
  }

  void PostPauseEventToDebugWindow(
    void* const debugWindow,
    moho::ScrPauseEvent& pauseEvent
  )
  {
    if (debugWindow == nullptr) {
      return;
    }

    auto* const eventHandler = reinterpret_cast<wxEvtHandler*>(debugWindow);
    eventHandler->AddPendingEvent(reinterpret_cast<wxEvent&>(pauseEvent));
  }

  [[nodiscard]] moho::PausedThread* PopPausedThreadUnlocked(ScrDebugRuntime& runtime)
  {
    if (runtime.pausedThreads.empty()) {
      return nullptr;
    }

    const auto first = runtime.pausedThreads.begin();
    moho::PausedThread* const pausedThread = *first;
    runtime.pausedThreads.erase(first);
    return pausedThread;
  }

  [[nodiscard]] LuaPlus::LuaState* GetFrontPausedLuaStateUnlocked(ScrDebugRuntime& runtime)
  {
    if (runtime.pausedThreads.empty()) {
      return nullptr;
    }

    moho::PausedThread* const pausedThread = runtime.pausedThreads.front();
    if (pausedThread == nullptr) {
      return nullptr;
    }

    return reinterpret_cast<LuaPlus::LuaState*>(pausedThread->GetPauseContextA());
  }

  void BindLuaStateForHook(ScrDebugRuntime& runtime, LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return;
    }

    for (LuaHookBinding& binding : runtime.hookBindings) {
      if (binding.cState == state->m_state) {
        binding.wrapperState = state;
        return;
      }
    }

    runtime.hookBindings.push_back(LuaHookBinding{state->m_state, state});
  }

  void UnbindLuaStateForHook(ScrDebugRuntime& runtime, LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return;
    }

    for (auto it = runtime.hookBindings.begin(); it != runtime.hookBindings.end(); ++it) {
      if (it->cState == state->m_state) {
        runtime.hookBindings.erase(it);
        return;
      }
    }
  }

  [[nodiscard]] LuaPlus::LuaState* FindLuaStateForHook(
    ScrDebugRuntime& runtime,
    lua_State* const cState
  )
  {
    for (const LuaHookBinding& binding : runtime.hookBindings) {
      if (binding.cState == cState) {
        return binding.wrapperState;
      }
    }
    return nullptr;
  }

  bool ConsumeSingleStepRootState(ScrDebugRuntime& runtime, LuaPlus::LuaState* const rootState)
  {
    boost::mutex::scoped_lock lock(runtime.singleStepMutex);

    if (rootState == nullptr || runtime.singleStepRootStates.empty()) {
      runtime.hasPendingSingleStepRoots = !runtime.singleStepRootStates.empty();
      return false;
    }

    for (auto it = runtime.singleStepRootStates.begin(); it != runtime.singleStepRootStates.end(); ++it) {
      if (*it == rootState) {
        runtime.singleStepRootStates.erase(it);
        runtime.hasPendingSingleStepRoots = !runtime.singleStepRootStates.empty();
        return true;
      }
    }

    runtime.hasPendingSingleStepRoots = !runtime.singleStepRootStates.empty();
    return false;
  }

  void QueueSingleStepRootState(ScrDebugRuntime& runtime, LuaPlus::LuaState* const rootState)
  {
    if (rootState == nullptr) {
      return;
    }

    boost::mutex::scoped_lock lock(runtime.singleStepMutex);
    for (LuaPlus::LuaState* const queuedRootState : runtime.singleStepRootStates) {
      if (queuedRootState == rootState) {
        runtime.hasPendingSingleStepRoots = true;
        return;
      }
    }

    runtime.singleStepRootStates.push_back(rootState);
    runtime.hasPendingSingleStepRoots = true;
  }

  /**
   * Address: 0x004B5B10 (FUN_004B5B10)
   *
   * LuaPlus::LuaState *,msvc8::string const &,int,lua_Debug *
   *
   * What it does:
   * Posts one pause event to the debug window, enqueues one paused-thread
   * bridge object, then blocks until resumed.
   */
  void PauseLuaThreadAtSource(
    LuaPlus::LuaState* const luaState,
    const msvc8::string& mountedSource,
    const int sourceLine,
    lua_Debug* const debugFrame
  )
  {
    ScrDebugRuntime& runtime = GetScrDebugRuntime();
    moho::PausedThread* pausedThread = nullptr;

    {
      boost::mutex::scoped_lock lock(runtime.pausedQueueMutex);

      moho::ScrPauseEvent pauseEvent(mountedSource, sourceLine);
      PostPauseEventToDebugWindow(runtime.debugWindow, pauseEvent);

      const std::uint32_t currentThreadId = ::GetCurrentThreadId();
      if (runtime.debugWindowOwnerThreadId == 0U) {
        runtime.debugWindowOwnerThreadId = currentThreadId;
      }

      const int pauseContextA = reinterpret_cast<int>(luaState);
      const int pauseContextB = reinterpret_cast<int>(debugFrame);
      if (currentThreadId == runtime.debugWindowOwnerThreadId) {
        pausedThread = new moho::PausedMainThread(pauseContextA, pauseContextB);
      } else {
        pausedThread = new moho::PausedChildThread(currentThreadId, pauseContextA, pauseContextB);
      }

      if (pausedThread != nullptr) {
        runtime.pausedThreads.push_back(pausedThread);
      }
    }

    if (pausedThread != nullptr) {
      (void)pausedThread->WaitUntilResumedAndDelete();
    }
  }
} // namespace

/**
 * Address: 0x004B49B0 (FUN_004B49B0, Moho::SCR_HookState)
 *
 * LuaPlus::LuaState *
 *
 * What it does:
 * Binds one Lua state to the script debug hook callback when a debug window
 * runtime is active.
 */
void moho::SCR_HookState(LuaPlus::LuaState* const state)
{
  if (state == nullptr || state->m_state == nullptr) {
    return;
  }

  ScrDebugRuntime& runtime = GetScrDebugRuntime();
  {
    boost::mutex::scoped_lock lock(runtime.hookBindingMutex);
    BindLuaStateForHook(runtime, state);
  }

  if (SCR_IsDebugWindowActive()) {
    lua_sethook(state->m_state, DebugLuaHook, LUA_MASKLINE, 0);
  }
}

/**
 * Address: 0x004B49D0 (FUN_004B49D0, Moho::SCR_UnhookState)
 *
 * LuaPlus::LuaState *
 *
 * What it does:
 * Removes one Lua state from script debug hook dispatch and clears the Lua
 * hook callback.
 */
void moho::SCR_UnhookState(LuaPlus::LuaState* const state)
{
  if (state == nullptr || state->m_state == nullptr) {
    return;
  }

  ScrDebugRuntime& runtime = GetScrDebugRuntime();
  {
    boost::mutex::scoped_lock lock(runtime.hookBindingMutex);
    UnbindLuaStateForHook(runtime, state);
  }

  lua_sethook(state->m_state, nullptr, 0, 0);
}

/**
 * Address: 0x004B4A30 (FUN_004B4A30, Moho::SCR_AddBreakpoint)
 *
 * Moho::ScrBreakpoint const &
 *
 * What it does:
 * Inserts one breakpoint in sorted unique order and persists preferences
 * after successful insertion.
 */
void moho::SCR_AddBreakpoint(const ScrBreakpoint& breakpoint)
{
  ScrDebugRuntime& runtime = GetScrDebugRuntime();
  boost::mutex::scoped_lock lock(runtime.breakpointMutex);

  if (InsertBreakpointSortedUnique(runtime, breakpoint)) {
    RefreshAnyEnabledBreakpointsFlag(runtime);
    SaveBreakpointsUnlocked(runtime);
  }
}

/**
 * Address: 0x004B4AC0 (FUN_004B4AC0, Moho::SCR_EnableBreakpoint)
 *
 * Moho::ScrBreakpoint const &,bool
 *
 * What it does:
 * Updates one existing breakpoint enabled lane and persists preferences.
 */
void moho::SCR_EnableBreakpoint(const ScrBreakpoint& breakpoint, const bool enabled)
{
  ScrDebugRuntime& runtime = GetScrDebugRuntime();
  boost::mutex::scoped_lock lock(runtime.breakpointMutex);

  const auto it = FindBreakpointExact(runtime, breakpoint);
  if (it != runtime.breakpoints.end()) {
    it->enabled = enabled;
    RefreshAnyEnabledBreakpointsFlag(runtime);
    SaveBreakpointsUnlocked(runtime);
  }
}

/**
 * Address: 0x004B4B50 (FUN_004B4B50, Moho::SCR_EnableAllBreakpoints)
 *
 * bool
 *
 * What it does:
 * Applies one enabled lane to every global breakpoint and persists
 * preferences.
 */
void moho::SCR_EnableAllBreakpoints(const bool enabled)
{
  ScrDebugRuntime& runtime = GetScrDebugRuntime();
  boost::mutex::scoped_lock lock(runtime.breakpointMutex);

  for (ScrBreakpoint& breakpoint : runtime.breakpoints) {
    breakpoint.enabled = enabled;
  }
  RefreshAnyEnabledBreakpointsFlag(runtime);
  SaveBreakpointsUnlocked(runtime);
}

/**
 * Address: 0x004B4BF0 (FUN_004B4BF0, Moho::SCR_RemoveBreakpoint)
 *
 * Moho::ScrBreakpoint const &
 *
 * What it does:
 * Removes one matching global breakpoint and persists preferences.
 */
void moho::SCR_RemoveBreakpoint(const ScrBreakpoint& breakpoint)
{
  ScrDebugRuntime& runtime = GetScrDebugRuntime();
  boost::mutex::scoped_lock lock(runtime.breakpointMutex);

  const auto it = FindBreakpointExact(runtime, breakpoint);
  if (it != runtime.breakpoints.end()) {
    runtime.breakpoints.erase(it);
    RefreshAnyEnabledBreakpointsFlag(runtime);
    SaveBreakpointsUnlocked(runtime);
  }
}

/**
 * Address: 0x004B4C80 (FUN_004B4C80, Moho::SCR_RemoveAllBreakpoints)
 *
 * What it does:
 * Clears all global breakpoints, refreshes enabled-state cache, and persists
 * preferences.
 */
void moho::SCR_RemoveAllBreakpoints()
{
  ScrDebugRuntime& runtime = GetScrDebugRuntime();
  boost::mutex::scoped_lock lock(runtime.breakpointMutex);

  runtime.breakpoints.clear();
  RefreshAnyEnabledBreakpointsFlag(runtime);
  SaveBreakpointsUnlocked(runtime);
}

/**
 * Address: 0x004B4D20 (FUN_004B4D20, Moho::SCR_EnumerateBreakpoints)
 *
 * std::string const &,std::vector<Moho::ScrBreakpoint> &
 *
 * What it does:
 * Enumerates breakpoints matching one mounted source path into output storage.
 */
void moho::SCR_EnumerateBreakpoints(
  const msvc8::string& sourcePath,
  msvc8::vector<ScrBreakpoint>& outBreakpoints
)
{
  outBreakpoints.clear();

  ScrDebugRuntime& runtime = GetScrDebugRuntime();
  boost::mutex::scoped_lock lock(runtime.breakpointMutex);
  if (!runtime.hasEnabledBreakpoints) {
    return;
  }

  const std::string_view sourcePathView = sourcePath.view();
  for (const ScrBreakpoint& breakpoint : runtime.breakpoints) {
    if (sourcePathView == breakpoint.name.view()) {
      outBreakpoints.push_back(breakpoint);
    }
  }
}

/**
 * Address: 0x004B4DF0 (FUN_004B4DF0, Moho::SCR_EnumerateCallStack)
 *
 * std::vector<Moho::ScrActivation> &
 *
 * What it does:
 * Enumerates call-stack activation frames for the currently paused script state.
 */
void moho::SCR_EnumerateCallStack(msvc8::vector<ScrActivation>& outActivations)
{
  outActivations.clear();

  ScrDebugRuntime& runtime = GetScrDebugRuntime();
  boost::mutex::scoped_lock lock(runtime.pausedQueueMutex);

  LuaPlus::LuaState* const pausedLuaState = GetFrontPausedLuaStateUnlocked(runtime);
  if (pausedLuaState == nullptr || pausedLuaState->m_state == nullptr) {
    return;
  }

  lua_Debug debugFrame{};
  for (int level = 0; lua_getstack(pausedLuaState->m_state, level, &debugFrame) != 0; ++level) {
    lua_getinfo(pausedLuaState->m_state, kCallStackInfoMask, &debugFrame);

    const char* source = debugFrame.source != nullptr ? debugFrame.source : "";
    if (source[0] == '@') {
      ++source;
    }

    const msvc8::string mountedSource = ToMountedSourcePath(source);
    const msvc8::string activationName(debugFrame.name != nullptr ? debugFrame.name : "");
    outActivations.push_back(ScrActivation(mountedSource, activationName, debugFrame.currentline));
  }
}

/**
 * Address: 0x004B5140 (FUN_004B5140, Moho::SCR_EnumerateLocals)
 *
 * int,std::vector<Moho::ScrWatch> &
 *
 * What it does:
 * Enumerates locals and closure upvalues from one Lua stack level.
 */
void moho::SCR_EnumerateLocals(const int level, msvc8::vector<ScrWatch>& outWatches)
{
  outWatches.clear();

  ScrDebugRuntime& runtime = GetScrDebugRuntime();
  boost::mutex::scoped_lock lock(runtime.pausedQueueMutex);

  LuaPlus::LuaState* const pausedLuaState = GetFrontPausedLuaStateUnlocked(runtime);
  if (pausedLuaState == nullptr || pausedLuaState->m_state == nullptr) {
    return;
  }

  lua_Debug debugFrame{};
  if (lua_getstack(pausedLuaState->m_state, level, &debugFrame) == 0) {
    return;
  }

  int index = 1;
  for (const char* localName = lua_getlocal(pausedLuaState->m_state, &debugFrame, index);
       localName != nullptr;
       localName = lua_getlocal(pausedLuaState->m_state, &debugFrame, index)) {
    ++index;

    const msvc8::string watchName(localName);
    const LuaPlus::LuaObject watchValue(pausedLuaState, -1);
    outWatches.push_back(ScrWatch(watchName, watchValue));
  }

  lua_getinfo(pausedLuaState->m_state, kFunctionInfoMask, &debugFrame);

  index = 1;
  for (const char* upvalueName = lua_getupvalue(pausedLuaState->m_state, -1, index);
       upvalueName != nullptr;
       upvalueName = lua_getupvalue(pausedLuaState->m_state, -1, index)) {
    ++index;

    const msvc8::string watchName(upvalueName);
    const LuaPlus::LuaObject watchValue(pausedLuaState, -1);
    outWatches.push_back(ScrWatch(watchName, watchValue));

    lua_settop(pausedLuaState->m_state, -2);
  }

  lua_settop(pausedLuaState->m_state, -2);
}

/**
 * Address: 0x004B5470 (FUN_004B5470, Moho::SCR_EnumerateGlobals)
 *
 * std::vector<Moho::ScrWatch> &
 *
 * What it does:
 * Enumerates global Lua table entries for the currently paused script state.
 */
void moho::SCR_EnumerateGlobals(msvc8::vector<ScrWatch>& outWatches)
{
  outWatches.clear();

  ScrDebugRuntime& runtime = GetScrDebugRuntime();
  boost::mutex::scoped_lock lock(runtime.pausedQueueMutex);

  LuaPlus::LuaState* const pausedLuaState = GetFrontPausedLuaStateUnlocked(runtime);
  if (pausedLuaState == nullptr || pausedLuaState->m_state == nullptr) {
    return;
  }

  const LuaPlus::LuaObject globals = pausedLuaState->GetGlobals();
  if (globals.IsNil()) {
    return;
  }

  LuaPlus::LuaTableIterator iterator(globals, true);
  while (!iterator.m_isDone) {
    const char* const keyName = iterator.m_keyObj.GetString();
    const msvc8::string watchName(keyName != nullptr ? keyName : "");
    outWatches.push_back(ScrWatch(watchName, iterator.m_valueObj));
    iterator.Next();
  }
}

/**
 * Address: 0x004B5690 (FUN_004B5690, Moho::SCR_DebugStep)
 *
 * What it does:
 * Resumes the oldest paused script thread and schedules one single-step stop
 * for that thread root state.
 */
void moho::SCR_DebugStep()
{
  ScrDebugRuntime& runtime = GetScrDebugRuntime();
  boost::mutex::scoped_lock queueLock(runtime.pausedQueueMutex);

  PausedThread* const pausedThread = PopPausedThreadUnlocked(runtime);
  if (pausedThread == nullptr) {
    return;
  }

  LuaPlus::LuaState* const pausedState = reinterpret_cast<LuaPlus::LuaState*>(pausedThread->GetPauseContextA());
  if (pausedState != nullptr && pausedState->m_rootState != nullptr) {
    QueueSingleStepRootState(runtime, pausedState->m_rootState);
  }

  (void)pausedThread->Resume();
}

/**
 * Address: 0x004B5790 (FUN_004B5790, Moho::SCR_DebugResume)
 *
 * What it does:
 * Resumes the oldest paused script thread without scheduling a step stop.
 */
void moho::SCR_DebugResume()
{
  ScrDebugRuntime& runtime = GetScrDebugRuntime();
  boost::mutex::scoped_lock queueLock(runtime.pausedQueueMutex);

  PausedThread* const pausedThread = PopPausedThreadUnlocked(runtime);
  if (pausedThread == nullptr) {
    return;
  }

  (void)pausedThread->Resume();
}

/**
 * Address: 0x004B5840 (FUN_004B5840, Moho::SCR_LoadBreakpoints)
 *
 * What it does:
 * Loads persisted breakpoint entries from user preferences and rebuilds the
 * in-memory sorted breakpoint list.
 */
void moho::SCR_LoadBreakpoints()
{
  ScrDebugRuntime& runtime = GetScrDebugRuntime();
  boost::mutex::scoped_lock lock(runtime.breakpointMutex);

  runtime.breakpoints.clear();
  runtime.hasEnabledBreakpoints = false;

  IUserPrefs* const preferences = USER_GetPreferences();
  if (preferences == nullptr) {
    return;
  }

  const msvc8::vector<msvc8::string> fallback;
  const msvc8::vector<msvc8::string> serializedBreakpoints =
    preferences->GetStringArr(msvc8::string(kBreakpointPreferenceKey), fallback);

  const msvc8::string emptyName("");
  for (const msvc8::string& serializedBreakpoint : serializedBreakpoints) {
    ScrBreakpoint breakpoint(emptyName, -1);
    breakpoint.enabled = false;
    breakpoint.FromString(serializedBreakpoint);
    (void)InsertBreakpointSortedUnique(runtime, breakpoint);
  }

  RefreshAnyEnabledBreakpointsFlag(runtime);
}

/**
 * Address: 0x004B59B0 (FUN_004B59B0, Moho::SCR_SaveBreakpoints)
 *
 * What it does:
 * Serializes the in-memory breakpoint list and stores it to user
 * preferences.
 */
void moho::SCR_SaveBreakpoints()
{
  ScrDebugRuntime& runtime = GetScrDebugRuntime();
  boost::mutex::scoped_lock lock(runtime.breakpointMutex);
  SaveBreakpointsUnlocked(runtime);
}

/**
 * Address: 0x004B5C70 (FUN_004B5C70, Moho::DebugLuaHook)
 *
 * lua_State *,lua_Debug *
 *
 * What it does:
 * Handles Lua line-hook notifications, checking queued single-step roots and
 * explicit file/line breakpoints before pausing the current script thread.
 */
void moho::DebugLuaHook(lua_State* const state, lua_Debug* const debugFrame)
{
  ScrDebugRuntime& runtime = GetScrDebugRuntime();

  LuaPlus::LuaState* luaState = nullptr;
  {
    boost::mutex::scoped_lock lock(runtime.hookBindingMutex);
    luaState = FindLuaStateForHook(runtime, state);
  }
  if (luaState == nullptr) {
    return;
  }

  if (!SCR_IsDebugWindowActive()) {
    lua_sethook(luaState->m_state, nullptr, 0, 0);
    return;
  }

  if (debugFrame == nullptr || luaState->m_state == nullptr) {
    return;
  }

  lua_getinfo(luaState->m_state, kDebugGetInfoMask, debugFrame);
  const char* source = debugFrame->source;
  if (source == nullptr || std::strlen(source) <= 1U) {
    return;
  }
  if (*source == '@') {
    ++source;
  }

  const int currentLine = debugFrame->currentline;

  if (ConsumeSingleStepRootState(runtime, luaState->m_rootState)) {
    const msvc8::string mountedSource = ToMountedSourcePath(source);
    PauseLuaThreadAtSource(luaState, mountedSource, currentLine, debugFrame);
    return;
  }

  bool shouldPauseForBreakpoint = false;
  msvc8::string mountedSource;
  {
    boost::mutex::scoped_lock lock(runtime.breakpointMutex);
    if (runtime.hasEnabledBreakpoints) {
      mountedSource = ToMountedSourcePath(source);
      const ScrBreakpoint breakpointKey(mountedSource, currentLine);
      const auto hitIt = FindBreakpointExact(runtime, breakpointKey);
      shouldPauseForBreakpoint = (hitIt != runtime.breakpoints.end() && hitIt->enabled);
    }
  }

  if (shouldPauseForBreakpoint) {
    PauseLuaThreadAtSource(luaState, mountedSource, currentLine, debugFrame);
  }
}

bool moho::SCR_IsDebugWindowActive()
{
  return GetScrDebugRuntime().debugWindow != nullptr;
}

void moho::SCR_SetDebugWindowRuntime(void* const debugWindow, const std::uint32_t ownerThreadId)
{
  ScrDebugRuntime& runtime = GetScrDebugRuntime();
  runtime.debugWindow = debugWindow;
  runtime.debugWindowOwnerThreadId = ownerThreadId;
}
