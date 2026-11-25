// Engine addition (Android port): platform/posix/Backtrace.h on the unwinder's
// _Unwind_Backtrace, for bionic, which declares backtrace(3) from API level 33 only.

#if FAFRE_PLATFORM_ANDROID

#include "platform/posix/Backtrace.h"

#include <cstdint>
#include <cstdio>

#include <dlfcn.h>
#include <unistd.h>
#include <unwind.h>

namespace
{
  struct BacktraceState
  {
    void** frames;
    int maxFrames;
    int count;
    int skip;
  };

  _Unwind_Reason_Code CollectFrame(
    _Unwind_Context* const context,
    void* const raw
  )
  {
    auto* const state = static_cast<BacktraceState*>(raw);
    const std::uintptr_t ip = _Unwind_GetIP(context);
    if (ip == 0) {
      return _URC_END_OF_STACK;
    }
    if (state->skip > 0) {
      --state->skip;
      return _URC_NO_REASON;
    }
    if (state->count >= state->maxFrames) {
      return _URC_END_OF_STACK;
    }
    state->frames[state->count++] = reinterpret_cast<void*>(ip);
    return _URC_NO_REASON;
  }

  void WriteAll(
    const int fd,
    const char* const text,
    const int length
  )
  {
    int written = 0;
    while (written < length) {
      const ssize_t put = ::write(fd, text + written, static_cast<std::size_t>(length - written));
      if (put <= 0) {
        return;
      }
      written += static_cast<int>(put);
    }
  }
} // namespace

int platform::posix::Backtrace(
  void** const frames,
  const int maxFrames
) noexcept
{
  if (frames == nullptr || maxFrames <= 0) {
    return 0;
  }
  // The first frame the unwinder reports is this function's own; backtrace(3) starts at
  // its caller.
  BacktraceState state{frames, maxFrames, 0, 1};
  (void)_Unwind_Backtrace(&CollectFrame, &state);
  return state.count;
}

void platform::posix::BacktraceSymbolsFd(
  void* const* const frames,
  const int count,
  const int fd
) noexcept
{
  if (frames == nullptr) {
    return;
  }
  for (int index = 0; index < count; ++index) {
    char line[512];
    int length = 0;
    Dl_info info{};
    if (::dladdr(frames[index], &info) != 0 && info.dli_fname != nullptr) {
      if (info.dli_sname != nullptr) {
        const auto offset =
          reinterpret_cast<std::uintptr_t>(frames[index]) - reinterpret_cast<std::uintptr_t>(info.dli_saddr);
        length = std::snprintf(
          line,
          sizeof(line),
          "%s(%s+0x%zx)[%p]\n",
          info.dli_fname,
          info.dli_sname,
          static_cast<std::size_t>(offset),
          frames[index]
        );
      } else {
        const auto offset =
          reinterpret_cast<std::uintptr_t>(frames[index]) - reinterpret_cast<std::uintptr_t>(info.dli_fbase);
        length = std::snprintf(
          line, sizeof(line), "%s(+0x%zx)[%p]\n", info.dli_fname, static_cast<std::size_t>(offset), frames[index]
        );
      }
    } else {
      length = std::snprintf(line, sizeof(line), "[%p]\n", frames[index]);
    }
    if (length > 0) {
      WriteAll(fd, line, length < static_cast<int>(sizeof(line)) ? length : static_cast<int>(sizeof(line)) - 1);
    }
  }
}

#endif // FAFRE_PLATFORM_ANDROID
