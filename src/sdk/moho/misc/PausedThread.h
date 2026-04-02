#pragma once

#include <cstddef>
#include <cstdint>

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
    [[nodiscard]] virtual int GetPauseContextA() const = 0;
    [[nodiscard]] virtual int GetPauseContextB() const = 0;
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
     * int,int
     *
     * What it does:
     * Captures current thread id, stores pause context lanes, and allocates one
     * auto-reset resume event.
     */
    PausedMainThread(int pauseContextA, int pauseContextB);

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
    [[nodiscard]] int GetPauseContextA() const override;

    /**
     * Address: 0x004B45E0 (FUN_004B45E0, sub_4B45E0)
     */
    [[nodiscard]] int GetPauseContextB() const override;

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
    int mPauseContextA;          // +0x0C
    int mPauseContextB;          // +0x10
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
     * int,int,int
     *
     * What it does:
     * Stores paused thread id/context lanes and allocates one auto-reset
     * resume event.
     */
    PausedChildThread(std::uint32_t pausedThreadId, int pauseContextA, int pauseContextB);

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
    [[nodiscard]] int GetPauseContextA() const override;

    /**
     * Address: 0x004B4710 (FUN_004B4710, sub_4B4710)
     */
    [[nodiscard]] int GetPauseContextB() const override;

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
    int mPauseContextA;          // +0x0C
    int mPauseContextB;          // +0x10
  };

  static_assert(sizeof(PausedThread) == 0x04, "PausedThread size must be 0x04");

  static_assert(offsetof(PausedMainThread, mResumeEvent) == 0x04, "PausedMainThread::mResumeEvent offset must be 0x04");
  static_assert(offsetof(PausedMainThread, mThreadId) == 0x08, "PausedMainThread::mThreadId offset must be 0x08");
  static_assert(offsetof(PausedMainThread, mPauseContextA) == 0x0C, "PausedMainThread::mPauseContextA offset must be 0x0C");
  static_assert(offsetof(PausedMainThread, mPauseContextB) == 0x10, "PausedMainThread::mPauseContextB offset must be 0x10");
  static_assert(sizeof(PausedMainThread) == 0x14, "PausedMainThread size must be 0x14");

  static_assert(offsetof(PausedChildThread, mResumeEvent) == 0x04, "PausedChildThread::mResumeEvent offset must be 0x04");
  static_assert(offsetof(PausedChildThread, mThreadId) == 0x08, "PausedChildThread::mThreadId offset must be 0x08");
  static_assert(offsetof(PausedChildThread, mPauseContextA) == 0x0C, "PausedChildThread::mPauseContextA offset must be 0x0C");
  static_assert(offsetof(PausedChildThread, mPauseContextB) == 0x10, "PausedChildThread::mPauseContextB offset must be 0x10");
  static_assert(sizeof(PausedChildThread) == 0x14, "PausedChildThread size must be 0x14");
} // namespace moho
