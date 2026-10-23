#pragma once

#include <cstddef>

struct global_State;

namespace lua
{
  /**
   * x64 port test mode (not in the binary; plan 4.1a, verification V12).
   *
   * With `FAF_LUAGC_LOG=1` every full collection of every Lua VM logs
   *
   *   [LUAGC] state=<n> allocs=<count> nblocks=<accounted> threshold=<value>
   *
   * where `n` is the order in which the VM's global_State was created and
   * `allocs` the number of `luaM_realloc` calls made on it so far. Lua starts
   * a collection when `nblocks` reaches `GCthreshold`, and `nblocks` counts
   * real allocation sizes, so comparing the sim VM's lines between an x86 and
   * an x64 run of the same replay shows whether collections run at the same
   * point of the allocation sequence on both builds. The per-VM counters live
   * in a side table keyed by the global_State, so no Lua layout changes.
   *
   * Without the variable every entry point is one cached flag test.
   */
  [[nodiscard]] bool GcEventLogEnabled() noexcept;

  /** f_luaopen: a new global_State takes the next creation index. */
  void GcEventLogRegisterState(const global_State* globalState) noexcept;

  /** close_state: the global_State is about to be freed. */
  void GcEventLogUnregisterState(const global_State* globalState) noexcept;

  /** luaM_realloc: one more allocator call on this global_State. */
  void GcEventLogCountRealloc(const global_State* globalState) noexcept;

  /** luaC_collectgarbage, before the collection runs. */
  void GcEventLogCollection(const global_State* globalState, std::size_t nblocks, std::size_t threshold) noexcept;

  /**
   * Engine addition, measurement only: with `FAF_LUAGC_TIMING=1` every collection the sim thread
   * runs logs the wall time of its phases,
   *
   *   [LUAGC-T] n=<count> nblocks=<accounted> mark=<ms> sweep=<ms> final=<ms> total mark=<ms> sweep=<ms> final=<ms>
   *
   * (`final` is checkSizes plus the finalizers; the totals are since the process started). It is
   * how `lua_ParallelMark` and `lua_ParallelSweep` are measured. Without the variable a timer is
   * one cached flag test.
   */
  class GcTimer
  {
  public:
    enum EPhase : int
    {
      kMark = 0,
      kSweep,
      kFinalize,
      kPhaseCount
    };

    GcTimer(const global_State* globalState, std::size_t nblocks) noexcept;
    ~GcTimer();
    GcTimer(const GcTimer&) = delete;
    GcTimer& operator=(const GcTimer&) = delete;

    /** Charges the time since the previous lap (or the start) to `phase`. */
    void Lap(EPhase phase) noexcept;

    /** The timer of the collection running on this thread, if it is being timed. */
    [[nodiscard]] static GcTimer* Current() noexcept;

    /** QueryPerformanceCounter now. */
    [[nodiscard]] static long long Now() noexcept;

    /** Parallel sweep detail: its classify, mark-reset and serial replay times, live and dead objects. */
    void NoteSweep(long long classifyTicks, long long clearTicks, long long replayTicks, std::size_t live, std::size_t dead) noexcept;

    /** Adds `ticks` to the named sub-phase (a string literal) of this collection. */
    void Detail(const char* name, long long ticks) noexcept;

  private:
    std::size_t mBlocks = 0;
    long long mLast = 0;                   // QueryPerformanceCounter ticks; 0: not timing
    long long mPhaseTicks[kPhaseCount]{};
    long long mSweepTicks[3]{};            // NoteSweep: classify, clear, replay
    std::size_t mLive = 0;
    std::size_t mDead = 0;
    bool mSweepNoted = false;
    const char* mDetailNames[8]{};
    long long mDetailTicks[8]{};
  };
} // namespace lua
