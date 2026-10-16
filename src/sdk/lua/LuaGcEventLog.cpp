#include "lua/LuaGcEventLog.h"

#include <Windows.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <mutex>

#include "gpg/core/utils/Logging.h"

namespace
{
  /// One live global_State. The engine runs a handful of VMs at a time (user
  /// UI, sim, lobby, and short-lived ones such as blueprint loading), so a
  /// small fixed table scanned linearly is enough.
  struct GcEventLogEntry
  {
    std::atomic<const global_State*> state{nullptr};
    std::uint32_t index = 0;
    std::atomic<std::uint64_t> reallocs{0};
  };

  constexpr std::size_t kMaxTrackedStates = 64;

  struct GcEventLog
  {
    std::array<GcEventLogEntry, kMaxTrackedStates> entries{};
    std::mutex registration;
    std::uint32_t nextIndex = 0;
  };

  GcEventLog& TheGcEventLog()
  {
    static GcEventLog log;
    return log;
  }

  [[nodiscard]] GcEventLogEntry* FindEntry(const global_State* const globalState) noexcept
  {
    for (GcEventLogEntry& entry : TheGcEventLog().entries) {
      if (entry.state.load(std::memory_order_acquire) == globalState) {
        return &entry;
      }
    }
    return nullptr;
  }
} // namespace

bool lua::GcEventLogEnabled() noexcept
{
  static const bool enabled = [] {
    char value[4] = {};
    const DWORD written = ::GetEnvironmentVariableA("FAF_LUAGC_LOG", value, static_cast<DWORD>(sizeof(value)));
    return written == 1u && value[0] == '1';
  }();
  return enabled;
}

void lua::GcEventLogRegisterState(const global_State* const globalState) noexcept
{
  if (!GcEventLogEnabled() || globalState == nullptr) {
    return;
  }
  GcEventLog& log = TheGcEventLog();
  const std::lock_guard<std::mutex> lock(log.registration);
  const std::uint32_t index = log.nextIndex++;
  for (GcEventLogEntry& entry : log.entries) {
    if (entry.state.load(std::memory_order_relaxed) == nullptr) {
      entry.index = index;
      entry.reallocs.store(0, std::memory_order_relaxed);
      entry.state.store(globalState, std::memory_order_release);
      return;
    }
  }
  gpg::Warnf("[LUAGC] more than %u live Lua VMs; state %u is not tracked",
             static_cast<unsigned>(kMaxTrackedStates), static_cast<unsigned>(index));
}

void lua::GcEventLogUnregisterState(const global_State* const globalState) noexcept
{
  if (!GcEventLogEnabled() || globalState == nullptr) {
    return;
  }
  const std::lock_guard<std::mutex> lock(TheGcEventLog().registration);
  if (GcEventLogEntry* const entry = FindEntry(globalState)) {
    entry->state.store(nullptr, std::memory_order_release);
  }
}

void lua::GcEventLogCountRealloc(const global_State* const globalState) noexcept
{
  if (!GcEventLogEnabled()) {
    return;
  }
  if (GcEventLogEntry* const entry = FindEntry(globalState)) {
    entry->reallocs.fetch_add(1, std::memory_order_relaxed);
  }
}

void lua::GcEventLogCollection(
  const global_State* const globalState, const std::size_t nblocks, const std::size_t threshold
) noexcept
{
  if (!GcEventLogEnabled()) {
    return;
  }
  const GcEventLogEntry* const entry = FindEntry(globalState);
  if (entry == nullptr) {
    return;
  }
  gpg::Logf(
    "[LUAGC] state=%u allocs=%llu nblocks=%llu threshold=%llu",
    static_cast<unsigned>(entry->index),
    static_cast<unsigned long long>(entry->reallocs.load(std::memory_order_relaxed)),
    static_cast<unsigned long long>(nblocks),
    static_cast<unsigned long long>(threshold)
  );
}
