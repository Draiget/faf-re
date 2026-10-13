#pragma once

#include <cstddef>
#include <cstdint>

namespace LuaPlus { class LuaState; }
struct lua_Debug;

namespace moho
{
  /**
   * Abstract paused-thread bridge queued by script debug pause handlers.
   *
   * Layout evidence:
   * - `PausedMainThread` ctor (`FUN_004B4570`) writes fields at `+0x04..+0x10`.
   * - `PausedChildThread` ctor (`FUN_004B46A0`) writes the same lanes.
   */
  class PausedThread
  {
  public:
    virtual ~PausedThread() = 0;
    [[nodiscard]] virtual std::uint32_t GetThreadId() const = 0;
    [[nodiscard]] virtual LuaPlus::LuaState* GetLuaState() const = 0;
    [[nodiscard]] virtual lua_Debug* GetDebugFrame() const = 0;
    [[nodiscard]] virtual std::uintptr_t WaitUntilResumedAndDelete() = 0;
    [[nodiscard]] virtual bool Resume() = 0;
  };

  /**
   * Paused-thread implementation for the engine main thread.
   */
  class PausedMainThread final : public PausedThread
  {
  public:
    /**
     * Address: 0x004B4570 (FUN_004B4570, sub_4B4570)
     *
     * LuaPlus::LuaState*,lua_Debug*
     *
     * What it does:
     * Captures current thread id, stores Lua state/debug-frame pointers, and allocates one
     * auto-reset resume event.
     */
    PausedMainThread(LuaPlus::LuaState* luaState, lua_Debug* debugFrame);

    /**
     * Address: 0x004B45A0 (FUN_004B45A0, sub_4B45A0)
     * Address: 0x004B4670 (FUN_004B4670, deleting-dtor thunk)
     *
     * What it does:
     * Closes the resume event lane and tears down the paused-thread object.
     */
    ~PausedMainThread() override;

    /**
     * Address: 0x004B45C0 (FUN_004B45C0, sub_4B45C0)
     */
    [[nodiscard]] std::uint32_t GetThreadId() const override;

    /**
     * Address: 0x004B45D0 (FUN_004B45D0, sub_4B45D0)
     */
    [[nodiscard]] LuaPlus::LuaState* GetLuaState() const override;

    /**
     * Address: 0x004B45E0 (FUN_004B45E0, sub_4B45E0)
     */
    [[nodiscard]] lua_Debug* GetDebugFrame() const override;

    /**
     * Address: 0x004B45F0 (FUN_004B45F0, sub_4B45F0)
     *
     * What it does:
     * Pumps wx pending/idle work until resumed, then self-deletes.
     */
    [[nodiscard]] std::uintptr_t WaitUntilResumedAndDelete() override;

    /**
     * Address: 0x004B4660 (FUN_004B4660, sub_4B4660)
     */
    [[nodiscard]] bool Resume() override;

  public:
    void* mResumeEvent;          // +0x04
    std::uint32_t mThreadId;     // +0x08
    LuaPlus::LuaState* mLuaState;          // +0x0C
    lua_Debug* mDebugFrame;          // +0x10
  };

  /**
   * Paused-thread implementation for non-main script threads.
   */
  class PausedChildThread final : public PausedThread
  {
  public:
    /**
     * Address: 0x004B46A0 (FUN_004B46A0, sub_4B46A0)
     *
     * std::uint32_t,LuaPlus::LuaState*,lua_Debug*
     *
     * What it does:
     * Stores paused thread id and Lua state/debug-frame pointers and allocates one auto-reset
     * resume event.
     */
    PausedChildThread(std::uint32_t pausedThreadId, LuaPlus::LuaState* luaState, lua_Debug* debugFrame);

    /**
     * Address: 0x004B46D0 (FUN_004B46D0, sub_4B46D0)
     * Address: 0x004B4750 (FUN_004B4750, deleting-dtor thunk)
     *
     * What it does:
     * Closes the resume event lane and tears down the paused-thread object.
     */
    ~PausedChildThread() override;

    /**
     * Address: 0x004B46F0 (FUN_004B46F0, sub_4B46F0)
     */
    [[nodiscard]] std::uint32_t GetThreadId() const override;

    /**
     * Address: 0x004B4700 (FUN_004B4700, sub_4B4700)
     */
    [[nodiscard]] LuaPlus::LuaState* GetLuaState() const override;

    /**
     * Address: 0x004B4710 (FUN_004B4710, sub_4B4710)
     */
    [[nodiscard]] lua_Debug* GetDebugFrame() const override;

    /**
     * Address: 0x004B4720 (FUN_004B4720, sub_4B4720)
     *
     * What it does:
     * Blocks until resumed, then self-deletes.
     */
    [[nodiscard]] std::uintptr_t WaitUntilResumedAndDelete() override;

    /**
     * Address: 0x004B4740 (FUN_004B4740, sub_4B4740)
     */
    [[nodiscard]] bool Resume() override;

  public:
    void* mResumeEvent;          // +0x04
    std::uint32_t mThreadId;     // +0x08
    LuaPlus::LuaState* mLuaState;          // +0x0C
    lua_Debug* mDebugFrame;          // +0x10
  };

#if INTPTR_MAX == INT32_MAX
  static_assert(sizeof(PausedThread) == 0x04, "PausedThread size must be 0x04");

  static_assert(offsetof(PausedMainThread, mResumeEvent) == 0x04, "PausedMainThread::mResumeEvent offset must be 0x04");
  static_assert(offsetof(PausedMainThread, mThreadId) == 0x08, "PausedMainThread::mThreadId offset must be 0x08");
  static_assert(offsetof(PausedMainThread, mLuaState) == 0x0C, "PausedMainThread::mLuaState offset must be 0x0C");
  static_assert(offsetof(PausedMainThread, mDebugFrame) == 0x10, "PausedMainThread::mDebugFrame offset must be 0x10");
  static_assert(sizeof(PausedMainThread) == 0x14, "PausedMainThread size must be 0x14");

  static_assert(offsetof(PausedChildThread, mResumeEvent) == 0x04, "PausedChildThread::mResumeEvent offset must be 0x04");
  static_assert(offsetof(PausedChildThread, mThreadId) == 0x08, "PausedChildThread::mThreadId offset must be 0x08");
  static_assert(offsetof(PausedChildThread, mLuaState) == 0x0C, "PausedChildThread::mLuaState offset must be 0x0C");
  static_assert(offsetof(PausedChildThread, mDebugFrame) == 0x10, "PausedChildThread::mDebugFrame offset must be 0x10");
  static_assert(sizeof(PausedChildThread) == 0x14, "PausedChildThread size must be 0x14");
#else
  static_assert(sizeof(PausedThread) == 0x08, "PausedThread native size must be 0x08");
  static_assert(sizeof(PausedMainThread) == 0x28, "PausedMainThread native size must be 0x28");
  static_assert(sizeof(PausedChildThread) == 0x28, "PausedChildThread native size must be 0x28");
  static_assert(offsetof(PausedMainThread, mLuaState) == 0x18, "PausedMainThread native Lua pointer offset");
  static_assert(offsetof(PausedMainThread, mDebugFrame) == 0x20, "PausedMainThread native debug pointer offset");
  static_assert(offsetof(PausedChildThread, mLuaState) == 0x18, "PausedChildThread native Lua pointer offset");
  static_assert(offsetof(PausedChildThread, mDebugFrame) == 0x20, "PausedChildThread native debug pointer offset");
#endif
} // namespace moho
