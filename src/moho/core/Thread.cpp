#include "Thread.h"

#include "platform/Platform.h"

#include <memory>
#include <new>
using namespace moho;

namespace
{
  std::uint32_t dwThreadId = 0;
}

/**
 * Address: 0x00413AA0 (FUN_00413AA0)
 *
 * What it does:
 * Captures the current thread id as the process main-thread lane.
 */
void moho::THREAD_InitInvoke()
{
  dwThreadId = GetCurrentThreadId();
}

/**
 * Address: 0x00413AD0 (FUN_00413AD0)
 *
 * What it does:
 * Returns the cached main-thread id lane.
 */
uint32_t moho::THREAD_GetMainThreadId()
{
  return dwThreadId;
}

/**
 * Address: 0x00413B70 (FUN_00413B70)
 *
 * boost::function<void(),std::allocator<void>>,uint32_t
 *
 * What it does:
 * Queues one callback as APC on the resolved target thread.
 */
void moho::THREAD_InvokeAsync(
  std::function<void()> fn,
  const uint32_t threadId
)
{
  const DWORD tid = ResolveTid(threadId);
  const HANDLE hThread = ::OpenThread(kThreadAccessFa, FALSE, tid);
  if (!hThread) {
    return;
  }

  auto* const payload = new (std::nothrow) InvokePayload{std::move(fn)};
  if (payload != nullptr && ::QueueUserAPC(&pfnAPC, hThread, reinterpret_cast<ULONG_PTR>(payload)) == 0) {
    delete payload; // never queued, so pfnAPC won't free it
  }
  ::CloseHandle(hThread);
}

/**
 * Address: 0x004141A0 (FUN_004141A0)
 *
 * What it does:
 * Selects one cpu from the process affinity mask and pins the current thread.
 */
void moho::THREAD_SetAffinity(
  const bool preferLowest
) noexcept
{
  DWORD_PTR procMask = 0;
  DWORD_PTR sysMask = 0;

  // Query process and system affinity masks
  if (!::GetProcessAffinityMask(::GetCurrentProcess(), &procMask, &sysMask)) {
    return; // keep current affinity on failure
  }

  if (procMask == 0) {
    return; // nothing to choose
  }

  constexpr unsigned bitCount = sizeof(procMask) * 8U;
  DWORD_PTR chosen = 0;

  if (preferLowest) {
    // Scan from LSB to MSB
    for (unsigned b = 0; b < bitCount; ++b) {
      const DWORD_PTR bit = (static_cast<DWORD_PTR>(1) << b);
      if (procMask & bit) {
        chosen = bit;
        break;
      }
    }
  } else {
    // Scan from MSB to LSB
    for (int b = static_cast<int>(bitCount) - 1; b >= 0; --b) {
      const DWORD_PTR bit = (static_cast<DWORD_PTR>(1) << b);
      if (procMask & bit) {
        chosen = bit;
        break;
      }
    }
  }

  if (chosen != 0) {
    // Bind current thread to the chosen CPU; return value is previous mask (ignored)
    (void)::SetThreadAffinityMask(::GetCurrentThread(), chosen);
  }
}

/**
 * Address: 0x00413AE0 (FUN_00413AE0)
 *
 * What it does:
 * Runs one APC callback payload and frees transport storage.
 */
void __stdcall moho::pfnAPC(
  const ULONG_PTR dwData
)
{
  const std::unique_ptr<InvokePayload> payload(reinterpret_cast<InvokePayload*>(dwData));
  if (payload && payload->fn) {
    payload->fn();
  }
}

DWORD moho::ResolveTid(
  const std::uint32_t threadId
) noexcept
{
  if (threadId) {
    return threadId;
  }
  if (dwThreadId) {
    return dwThreadId;
  }
  return ::GetCurrentThreadId();
}
