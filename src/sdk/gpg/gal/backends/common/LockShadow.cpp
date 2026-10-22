// FAF addition, not in the shipped binary: see LockShadow.h.

#include "LockShadow.h"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <cstring>

#include "gpg/core/utils/Logging.h"

namespace gpg::gal::backend
{
  namespace
  {
    constexpr std::size_t kGuardBytes = 256U;
    constexpr std::uint8_t kGuardFill = 0xA5U;
    constexpr int kMaxReports = 32;

    std::atomic<int> sReports{0};
    std::atomic<std::uint64_t> sTotalBytes{0};

    [[nodiscard]] bool BreakRequested() noexcept
    {
      static const bool requested = [] {
        const char* const value = std::getenv("FAF_GAL_LOCK_BREAK");
        return value != nullptr && value[0] == '1';
      }();
      return requested;
    }

    /** The engine frames that made the lock, as module+offset, for `ln` in a debugger. */
    void LogCallers()
    {
      void* frames[10]{};
      const USHORT count = ::RtlCaptureStackBackTrace(2U, 10U, frames, nullptr);
      char line[512]{};
      std::size_t used = 0U;
      for (USHORT index = 0U; index < count && used + 40U < sizeof(line); ++index) {
        HMODULE module = nullptr;
        char name[MAX_PATH]{};
        std::uintptr_t offset = reinterpret_cast<std::uintptr_t>(frames[index]);
        if (::GetModuleHandleExA(
              GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
              static_cast<LPCSTR>(frames[index]),
              &module
            ) != FALSE &&
            ::GetModuleFileNameA(module, name, MAX_PATH) != 0U) {
          offset -= reinterpret_cast<std::uintptr_t>(module);
        } else {
          std::strcpy(name, "?");
        }
        const char* const base = std::max(std::strrchr(name, '\\'), std::strrchr(name, '/'));
        used += static_cast<std::size_t>(std::snprintf(
          line + used, sizeof(line) - used, " %s+0x%zX", (base != nullptr) ? base + 1 : name, static_cast<std::size_t>(offset)
        ));
      }
      gpg::Warnf("  called from%s", line);
    }

    /** Logs (up to kMaxReports times a run) and breaks when asked to. */
    template <class... Args>
    void Report(const char* const format, Args... args)
    {
      if (sReports.fetch_add(1) < kMaxReports) {
        gpg::Warnf(format, args...);
        LogCallers();
      }
      if (BreakRequested() && ::IsDebuggerPresent() != FALSE) {
        ::DebugBreak();
      }
    }
  } // namespace

  LockShadow::~LockShadow()
  {
    sTotalBytes.fetch_sub(mBytes.capacity());
  }

  std::uint64_t LockShadow::TotalBytes() noexcept
  {
    return sTotalBytes.load();
  }

  void LockShadow::Account(const std::size_t previousCapacity) noexcept
  {
    sTotalBytes.fetch_add(mBytes.capacity());
    sTotalBytes.fetch_sub(previousCapacity);
  }

  void LockShadow::Reset(const std::uint32_t byteWidth)
  {
    const std::size_t previous = mBytes.capacity();
    mByteWidth = byteWidth;
    mMappedEnd = byteWidth;
    mBytes.assign(static_cast<std::size_t>(byteWidth) + kGuardBytes, 0U);
    Account(previous);
    Arm(byteWidth);
  }

  void LockShadow::Arm(const std::size_t from)
  {
    mGuardStart = from;
    std::memset(mBytes.data() + from, kGuardFill, mBytes.size() - from);
  }

  std::uint8_t* LockShadow::Map(const std::uint32_t offset, const std::uint32_t size, const char* const kind)
  {
    std::uint32_t end = (size == 0U) ? mByteWidth : offset + size;
    if (size != 0U && (end < offset || end > mByteWidth)) {
      Report(
        "gal: %s lock past the end: offset %u size %u, buffer %u bytes - the part past the end is not drawn",
        (kind != nullptr) ? kind : "buffer", offset, size, mByteWidth
      );
      end = std::max(end, offset);
      if (static_cast<std::size_t>(end) + kGuardBytes > mBytes.size()) {
        const std::size_t previous = mBytes.capacity();
        mBytes.resize(static_cast<std::size_t>(end) + kGuardBytes, 0U);
        Account(previous);
      }
    }
    mMappedEnd = std::max(end, mByteWidth);
    if (mGuardStart != mMappedEnd) {
      Arm(mMappedEnd);
    }
    return mBytes.data() + offset;
  }

  void LockShadow::CheckGuard(const char* const kind)
  {
    const std::uint8_t* const guard = mBytes.data() + mGuardStart;
    const std::size_t length = mBytes.size() - mGuardStart;
    std::size_t dirty = length;
    while (dirty > 0U && guard[dirty - 1U] == kGuardFill) {
      --dirty;
    }
    if (dirty == 0U) {
      return;
    }
    Report(
      "gal: %s written past its end: %zu bytes beyond the %u locked (buffer %u bytes)",
      (kind != nullptr) ? kind : "buffer", dirty, mMappedEnd, mByteWidth
    );
    Arm(mGuardStart);
  }
} // namespace gpg::gal::backend
