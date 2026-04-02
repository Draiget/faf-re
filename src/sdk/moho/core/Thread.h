#pragma once

#include <memory>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "boost/function.h"
#include "wm3/AABB.h"
#include <winsock2.h>
#include <Windows.h>

namespace moho
{
  /**
   * Exact mask used by FA (MSVC8 era): THREAD_ALL_ACCESS
   */
  constexpr DWORD kThreadAccessFa = STANDARD_RIGHTS_REQUIRED // 0x000F0000
    | SYNCHRONIZE                                            // 0x00100000
    | 0x000003FF;                                            // thread-specific rights bits [0..9]

  /**
   * Address: 0x00413AA0 (FUN_00413AA0)
   *
   * What it does:
   * Captures the current thread id as the process main-thread lane used by
   * thread-invoke helpers.
   */
  void THREAD_InitInvoke();

  /**
   * Address: 0x00413AB0 (FUN_00413AB0)
   *
   * What it does:
   * Returns true when called from the thread captured by
   * `THREAD_InitInvoke()`.
   */
  bool THREAD_IsMainThread();

  /**
   * Address: 0x00413AD0 (FUN_00413AD0)
   *
   * What it does:
   * Returns the cached main-thread id lane.
   */
  uint32_t THREAD_GetMainThreadId();

  /**
   * Address: 0x00413B70 (FUN_00413B70)
   *
   * boost::function<void(),std::allocator<void>>,uint32_t
   *
   * What it does:
   * Clones one callback and queues it as an APC to the resolved target thread.
   */
  void THREAD_InvokeAsync(boost::function<void(), std::allocator<void>> fn, uint32_t threadId);

  /**
   * Address: 0x00413C50 (FUN_00413C50)
   *
   * boost::function<void(),std::allocator<void>>,uint32_t
   *
   * What it does:
   * Queues one callback as APC and blocks until the callback signals
   * completion.
   */
  void THREAD_InvokeWait(boost::function<void(), std::allocator<void>> fn, uint32_t threadId);

  /**
   * Address: 0x004141A0 (FUN_004141A0)
   *
   * What it does:
   * Pins the current thread to one processor selected from the current process
   * affinity mask.
   */
  void THREAD_SetAffinity(bool preferLowest) noexcept;

  /**
   * Small payload that will live in a 32-byte box.
   * Must fit into 32 bytes to mimic the observed allocation size.
   */
  struct InvokePayload
  {
    boost::function<void()> fn;
  };
  static_assert(sizeof(InvokePayload) <= 32, "InvokePayload must fit into 32 bytes (box size)");

  /**
   * Minimal wait context mirroring sub_104DB6C0/7F0/790 trio.
   */
  struct WaitCtx
  {
    HANDLE evt{nullptr};

    /**
     * Initialize context (asm passes '2'; ignored here, kept for parity).
     */
    void begin(int /*mode*/) noexcept
    {
      // Auto-reset, initially non-signaled
      evt = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
    }

    /**
     * Alertable wait until signaled by the APC side.
     */
    void block() noexcept
    {
      if (!evt)
        return;
      ::WaitForSingleObjectEx(evt, INFINITE, TRUE);
    }

    /**
     * Signal completion from APC.
     */
    void signal() noexcept
    {
      if (evt)
        ::SetEvent(evt);
    }

    /**
     * Cleanup.
     */
    void end() noexcept
    {
      if (evt) {
        ::CloseHandle(evt);
        evt = nullptr;
      }
    }
  };

  /**
   * Address: 0x00413AE0 (FUN_00413AE0)
   *
   * What it does:
   * APC thunk that runs one queued callback payload, signals optional waiting
   * context, and releases heap payload storage.
   */
  VOID CALLBACK pfnAPC(ULONG_PTR dwData);

  /**
   * Resolve TID like the binary: given threadId or global, else current.
   */
  DWORD ResolveTid(std::uint32_t threadId) noexcept;
} // namespace moho
