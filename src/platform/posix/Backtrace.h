#pragma once

// Engine addition (Android port): the calling thread's return addresses, for the crash
// diagnostics and moho::PLAT_GetCallStack on POSIX. Linux and macOS take backtrace(3) and
// backtrace_symbols_fd(3) from their C library; bionic declares them only from Android 13
// (API level 33), so Android walks the stack with the unwinder's _Unwind_Backtrace
// (platform/posix/Backtrace.cpp), which every C++ runtime with exceptions has.

#if FAFRE_PLATFORM_POSIX

#if !FAFRE_PLATFORM_ANDROID
#include <execinfo.h>
#endif

namespace platform::posix
{
#if FAFRE_PLATFORM_ANDROID
  /**
   * Up to `maxFrames` return addresses of the calling thread, the innermost first, as
   * backtrace(3): frame 0 is an address in the function that called Backtrace.
   */
  [[nodiscard]] int Backtrace(void** frames, int maxFrames) noexcept;

  /**
   * One line per frame on `fd`, as backtrace_symbols_fd(3): the module, the nearest symbol
   * and its offset where dladdr finds them, and the address. Allocates nothing.
   */
  void BacktraceSymbolsFd(void* const* frames, int count, int fd) noexcept;
#else
  // Inlined, so that frame 0 stays in the caller, as with backtrace(3) itself.
  [[nodiscard, gnu::always_inline]] inline int Backtrace(
    void** const frames,
    const int maxFrames
  ) noexcept
  {
    return ::backtrace(frames, maxFrames);
  }

  [[gnu::always_inline]] inline void BacktraceSymbolsFd(
    void* const* const frames,
    const int count,
    const int fd
  ) noexcept
  {
    ::backtrace_symbols_fd(frames, count, fd);
  }
#endif
} // namespace platform::posix

#endif // FAFRE_PLATFORM_POSIX
