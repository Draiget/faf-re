#pragma once

#include <memory>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <functional>
#include "Wm3AxisAlignedBox3.h"
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
  void THREAD_InvokeAsync(std::function<void()> fn, uint32_t threadId);

  /**
   * Address: 0x004141A0 (FUN_004141A0)
   *
   * What it does:
   * Pins the current thread to one processor selected from the current process
   * affinity mask.
   */
  void THREAD_SetAffinity(bool preferLowest) noexcept;

  /**
   * What THREAD_InvokeAsync queues: the callback, in one allocation. The binary queues an 8-byte pair of a 32-byte
   * `boost::function` box and a waiter that only a synchronous invoke sets; nothing in the engine invokes
   * synchronously.
   */
  struct InvokePayload
  {
    std::function<void()> fn;
  };

  /**
   * Address: 0x00413AE0 (FUN_00413AE0)
   *
   * What it does:
   * APC thunk that runs one queued callback payload and frees it.
   */
  VOID CALLBACK pfnAPC(ULONG_PTR dwData);

  /**
   * Resolve TID like the binary: given threadId or global, else current.
   */
  DWORD ResolveTid(std::uint32_t threadId) noexcept;
} // namespace moho
