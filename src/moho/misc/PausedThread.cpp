#include "moho/misc/PausedThread.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include "moho/app/WxRuntimeTypes.h"

namespace moho
{
  PausedThread::~PausedThread() = default;
} // namespace moho

/**
 * Address: 0x004B4570 (FUN_004B4570, sub_4B4570)
 *
 * LuaPlus::LuaState*,lua_Debug*
 *
 * What it does:
 * Captures current thread id, stores Lua state/debug-frame pointers, and allocates one
 * auto-reset resume event.
 */
moho::PausedMainThread::PausedMainThread(LuaPlus::LuaState* const luaState, lua_Debug* const debugFrame)
  : mResumeEvent(nullptr)
  , mThreadId(::GetCurrentThreadId())
  , mLuaState(luaState)
  , mDebugFrame(debugFrame)
{
  mResumeEvent = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
}

/**
 * Address: 0x004B45A0 (FUN_004B45A0, sub_4B45A0)
 * Address: 0x004B4670 (FUN_004B4670, deleting-dtor thunk)
 *
 * What it does:
 * Closes the resume event lane and tears down the paused-thread object.
 */
moho::PausedMainThread::~PausedMainThread()
{
  (void)::CloseHandle(static_cast<HANDLE>(mResumeEvent));
  mResumeEvent = nullptr;
}

/**
 * Address: 0x004B45C0 (FUN_004B45C0, sub_4B45C0)
 */
std::uint32_t moho::PausedMainThread::GetThreadId() const
{
  return mThreadId;
}

/**
 * Address: 0x004B45D0 (FUN_004B45D0, sub_4B45D0)
 */
LuaPlus::LuaState* moho::PausedMainThread::GetLuaState() const
{
  return mLuaState;
}

/**
 * Address: 0x004B45E0 (FUN_004B45E0, sub_4B45E0)
 */
lua_Debug* moho::PausedMainThread::GetDebugFrame() const
{
  return mDebugFrame;
}

/**
 * Address: 0x004B45F0 (FUN_004B45F0, sub_4B45F0)
 *
 * What it does:
 * Pumps wx pending/idle work until resumed, then self-deletes.
 */
std::uintptr_t moho::PausedMainThread::WaitUntilResumedAndDelete()
{
  bool processIdle = true;
  while (::WaitForSingleObject(static_cast<HANDLE>(mResumeEvent), 0) != WAIT_OBJECT_0) {
    if (wxTheApp != nullptr && wxTheApp->Pending()) {
      wxTheApp->Dispatch();
      processIdle = true;
      continue;
    }

    if (processIdle && wxTheApp != nullptr) {
      processIdle = wxTheApp->ProcessIdle();
    }
  }

  const std::uintptr_t deletedAddress = reinterpret_cast<std::uintptr_t>(this);
  delete this;
  return deletedAddress;
}

/**
 * Address: 0x004B4660 (FUN_004B4660, sub_4B4660)
 */
bool moho::PausedMainThread::Resume()
{
  return ::SetEvent(static_cast<HANDLE>(mResumeEvent)) != FALSE;
}

/**
 * Address: 0x004B46A0 (FUN_004B46A0, sub_4B46A0)
 *
 * std::uint32_t,LuaPlus::LuaState*,lua_Debug*
 *
 * What it does:
 * Stores paused thread id and Lua state/debug-frame pointers and allocates one auto-reset
 * resume event.
 */
moho::PausedChildThread::PausedChildThread(
  const std::uint32_t pausedThreadId, LuaPlus::LuaState* const luaState, lua_Debug* const debugFrame
)
  : mResumeEvent(nullptr)
  , mThreadId(pausedThreadId)
  , mLuaState(luaState)
  , mDebugFrame(debugFrame)
{
  mResumeEvent = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
}

/**
 * Address: 0x004B46D0 (FUN_004B46D0, sub_4B46D0)
 * Address: 0x004B4750 (FUN_004B4750, deleting-dtor thunk)
 *
 * What it does:
 * Closes the resume event lane and tears down the paused-thread object.
 */
moho::PausedChildThread::~PausedChildThread()
{
  (void)::CloseHandle(static_cast<HANDLE>(mResumeEvent));
  mResumeEvent = nullptr;
}

/**
 * Address: 0x004B46F0 (FUN_004B46F0, sub_4B46F0)
 */
std::uint32_t moho::PausedChildThread::GetThreadId() const
{
  return mThreadId;
}

/**
 * Address: 0x004B4700 (FUN_004B4700, sub_4B4700)
 */
LuaPlus::LuaState* moho::PausedChildThread::GetLuaState() const
{
  return mLuaState;
}

/**
 * Address: 0x004B4710 (FUN_004B4710, sub_4B4710)
 */
lua_Debug* moho::PausedChildThread::GetDebugFrame() const
{
  return mDebugFrame;
}

/**
 * Address: 0x004B4720 (FUN_004B4720, sub_4B4720)
 *
 * What it does:
 * Blocks until resumed, then self-deletes.
 */
std::uintptr_t moho::PausedChildThread::WaitUntilResumedAndDelete()
{
  (void)::WaitForSingleObject(static_cast<HANDLE>(mResumeEvent), INFINITE);
  const std::uintptr_t deletedAddress = reinterpret_cast<std::uintptr_t>(this);
  delete this;
  return deletedAddress;
}

/**
 * Address: 0x004B4740 (FUN_004B4740, sub_4B4740)
 */
bool moho::PausedChildThread::Resume()
{
  return ::SetEvent(static_cast<HANDLE>(mResumeEvent)) != FALSE;
}
