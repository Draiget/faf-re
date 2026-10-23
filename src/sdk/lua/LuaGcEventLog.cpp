#include "lua/LuaGcEventLog.h"

#include <Windows.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <mutex>

#include "gpg/core/utils/Logging.h"
#include "moho/sim/SimThreadRole.h"

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

namespace
{
  bool GcTimingEnabled() noexcept
  {
    static const bool enabled = [] {
      char value[4] = {};
      const DWORD written = ::GetEnvironmentVariableA("FAF_LUAGC_TIMING", value, static_cast<DWORD>(sizeof(value)));
      return written == 1u && value[0] == '1';
    }();
    return enabled;
  }

  /// Totals over every timed collection (sim thread only, so no locking).
  struct GcTimingTotals
  {
    unsigned collections = 0;
    long long phaseTicks[lua::GcTimer::kPhaseCount]{};
  };

  GcTimingTotals gGcTimingTotals;

  [[nodiscard]] long long QpcNow() noexcept
  {
    LARGE_INTEGER now{};
    ::QueryPerformanceCounter(&now);
    return now.QuadPart;
  }

  [[nodiscard]] double QpcToMs(const long long ticks) noexcept
  {
    static const double msPerTick = [] {
      LARGE_INTEGER frequency{};
      ::QueryPerformanceFrequency(&frequency);
      return 1000.0 / static_cast<double>(frequency.QuadPart);
    }();
    return static_cast<double>(ticks) * msPerTick;
  }
} // namespace

namespace
{
  thread_local lua::GcTimer* tCurrentGcTimer = nullptr;
}

lua::GcTimer::GcTimer(const global_State* const globalState, const std::size_t nblocks) noexcept
{
  (void)globalState;
  if (GcTimingEnabled() && moho::IsSimThread()) {
    mBlocks = nblocks;
    mLast = QpcNow();
    tCurrentGcTimer = this;
  }
}

lua::GcTimer* lua::GcTimer::Current() noexcept
{
  return tCurrentGcTimer;
}

long long lua::GcTimer::Now() noexcept
{
  return QpcNow();
}

void lua::GcTimer::NoteSweep(
  const long long classifyTicks, const long long clearTicks, const long long replayTicks, const std::size_t live,
  const std::size_t dead
) noexcept
{
  mSweepTicks[0] += classifyTicks;
  mSweepTicks[1] += clearTicks;
  mSweepTicks[2] += replayTicks;
  mLive += live;
  mDead += dead;
  mSweepNoted = true;
}

void lua::GcTimer::Detail(const char* const name, const long long ticks) noexcept
{
  for (int slot = 0; slot < 8; ++slot) {
    if (mDetailNames[slot] == nullptr || mDetailNames[slot] == name) {
      mDetailNames[slot] = name;
      mDetailTicks[slot] += ticks;
      return;
    }
  }
}

void lua::GcTimer::Lap(const EPhase phase) noexcept
{
  if (mLast == 0) {
    return;
  }
  const long long now = QpcNow();
  mPhaseTicks[phase] += now - mLast;
  mLast = now;
}

lua::GcTimer::~GcTimer()
{
  if (mLast == 0) {
    return;
  }
  if (tCurrentGcTimer == this) {
    tCurrentGcTimer = nullptr;
  }
  if (mDetailNames[0] != nullptr) {
    char text[512];
    int length = 0;
    for (int slot = 0; slot < 8 && mDetailNames[slot] != nullptr; ++slot) {
      length += std::snprintf(
        text + length, sizeof(text) - static_cast<std::size_t>(length), " %s=%.3f", mDetailNames[slot],
        QpcToMs(mDetailTicks[slot])
      );
    }
    gpg::Logf("[LUAGC-T]   detail:%s", text);
  }
  if (mSweepNoted) {
    gpg::Logf(
      "[LUAGC-T] parallel sweep: classify=%.3f reset=%.3f replay=%.3f live=%llu dead=%llu",
      QpcToMs(mSweepTicks[0]),
      QpcToMs(mSweepTicks[1]),
      QpcToMs(mSweepTicks[2]),
      static_cast<unsigned long long>(mLive),
      static_cast<unsigned long long>(mDead)
    );
  }
  GcTimingTotals& totals = gGcTimingTotals;
  ++totals.collections;
  for (int phase = 0; phase < kPhaseCount; ++phase) {
    totals.phaseTicks[phase] += mPhaseTicks[phase];
  }
  gpg::Logf(
    "[LUAGC-T] n=%u nblocks=%llu mark=%.3f sweep=%.3f final=%.3f total mark=%.1f sweep=%.1f final=%.1f",
    totals.collections,
    static_cast<unsigned long long>(mBlocks),
    QpcToMs(mPhaseTicks[kMark]),
    QpcToMs(mPhaseTicks[kSweep]),
    QpcToMs(mPhaseTicks[kFinalize]),
    QpcToMs(totals.phaseTicks[kMark]),
    QpcToMs(totals.phaseTicks[kSweep]),
    QpcToMs(totals.phaseTicks[kFinalize])
  );
}
