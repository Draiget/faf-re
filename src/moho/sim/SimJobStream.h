#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>

namespace moho
{
  /**
   * Engine addition, not recovered from the binary: an ordered stream of small sim jobs.
   *
   * CSimWorkerPool runs one batch whose items are all known up front. Some sim work only becomes
   * known one item at a time while the sim thread keeps going (a unit's pose update, queued when
   * its MotionTick reaches it). The stream takes those items one by one: `Enqueue` hands an item
   * to the sim workers and returns at once, the workers take items in queue order, and the sim
   * thread waits for an item only where its serial code would read what the item writes
   * (`Finish`, `FinishAll`).
   *
   * Contract, the same as CSimWorkerPool's: an item writes only state its own owner holds and reads
   * nothing another sim step changes before the item is finished; whatever it would read that can
   * change is copied into the item when it is queued. It must not call Lua, draw from the sim RNG,
   * create or destroy entities, or copy `WeakPtr`s / `LuaObject`s. Under that contract the result
   * is the serial result for any worker count and any timing.
   *
   * The stream holds the pool's async dispatch while it is open, so a CSimWorkerPool::Run on the
   * sim thread in the meantime runs serially. `Close` releases it; the next `Enqueue` opens the
   * stream again.
   *
   * Thread use: Enqueue, Finish, FinishAll and Close only on the sim thread.
   */
  class CSimJobStream
  {
  public:
    using JobFunction = void (*)(void* context);

    /// Returned by Enqueue when the job already ran on the calling thread.
    static constexpr std::int32_t kRanInline = -1;

    [[nodiscard]] static CSimJobStream& Get();

    CSimJobStream(const CSimJobStream&) = delete;
    CSimJobStream& operator=(const CSimJobStream&) = delete;
    ~CSimJobStream();

    /**
     * Queues `fn(context)` for the workers and returns its ticket, or runs it now and returns
     * kRanInline when the stream can't use workers (sim_Workers 0, a call from a worker, the pool's
     * async dispatch taken by someone else, or the stream full).
     */
    std::int32_t Enqueue(JobFunction fn, void* context);

    /**
     * Returns once job `ticket` has run: runs it here if no worker has taken it yet, else waits.
     * A ticket from before the last Close returns at once (Close finished it).
     */
    void Finish(std::int32_t ticket);

    /// Finishes every queued job, in queue order; the stream stays open.
    void FinishAll();

    /// Finishes every queued job and releases the workers and the pool's async dispatch.
    void Close();

    /// True while jobs may be pending (between the first Enqueue that used the workers and Close).
    [[nodiscard]] bool IsOpen() const noexcept;

    /// Totals since start, counted on the sim thread; jobs the workers ran = queued - stolen.
    struct SStats
    {
      std::uint64_t mQueued = 0;    // jobs handed to the stream
      std::uint64_t mStolen = 0;    // jobs the sim thread ran itself in Finish / FinishAll
      std::uint64_t mWaited = 0;    // jobs the sim thread waited for while a worker ran them
      std::uint64_t mWaitMicroseconds = 0; // time spent in those waits
      std::uint64_t mWakeCalls = 0; // Enqueues that woke a sleeping worker (a system call)
      std::uint64_t mOpens = 0;     // Open calls (one pool StartAsync / FinishAsync pair each)
    };
    [[nodiscard]] const SStats& Stats() const noexcept;

  private:
    CSimJobStream();

    struct Impl;
    std::unique_ptr<Impl> mImpl;
  };
} // namespace moho
