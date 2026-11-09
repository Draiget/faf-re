#include "moho/sim/SimJobStream.h"

#include <atomic>
#include <exception>
#include <mutex>
#include <vector>

#include <Windows.h>
#include <immintrin.h>

#include "gpg/core/profiling/Profiler.h"
#include "moho/console/CConCommand.h"
#include "moho/sim/SimThreadRole.h"
#include "moho/sim/SimWorkerPool.h"

namespace moho
{
  bool sim_JobStreamPrefetch = true;
  TConVar<bool> gTConVar_sim_JobStreamPrefetch(
    "sim_JobStreamPrefetch",
    "Queueing a sim stream job loads the next slots for writing ahead of time; same jobs, same "
    "results. Read when the stream opens.",
    &sim_JobStreamPrefetch
  );

  int sim_JobStreamPublishBatch = 4;
  TConVar<int> gTConVar_sim_JobStreamPublishBatch(
    "sim_JobStreamPublishBatch",
    "Sim stream jobs are shown to the workers this many at a time (1 = each one at once); a wait "
    "or a close shows the rest first. Same jobs, same results. Read when the stream opens.",
    &sim_JobStreamPublishBatch
  );

  namespace
  {
    // Jobs the stream holds before it closes and opens again (a beat queues one per moving unit).
    constexpr std::uint32_t kCapacity = 1u << 16;

    // Rounds an idle worker spins before it sleeps; a beat queues a job every few microseconds, and
    // waking a sleeper is a system call on the sim thread.
    constexpr unsigned int kSpinRounds = 16384u;

    constexpr std::size_t kCacheLine = 64u;

    enum : std::uint8_t
    {
      kQueued = 0,
      kRunning = 1,
      kDone = 2,
    };

    // One cache line per slot: the sim thread writes the next slot while a worker runs this one.
    struct alignas(kCacheLine) Slot
    {
      CSimJobStream::JobFunction fn = nullptr;
      void* context = nullptr;
      std::atomic<std::uint8_t> state{kDone};
    };

    void SpinFor(const std::int64_t ticks)
    {
      LARGE_INTEGER start{};
      LARGE_INTEGER now{};
      ::QueryPerformanceCounter(&start);
      do {
        _mm_pause();
        ::QueryPerformanceCounter(&now);
      } while (now.QuadPart - start.QuadPart < ticks);
    }
  } // namespace

  struct CSimJobStream::Impl
  {
    std::vector<Slot> slots = std::vector<Slot>(kCapacity);

    // Written by the sim thread only.
    bool open = false;
    std::uint32_t epoch = 0; // bumped by every Open; a ticket is (epoch << 16) | index
    std::uint32_t finishedPrefix = 0; // every job below this index is done
    std::int64_t workerDelayTicks = 0; // sim_WorkerJobDelayUs, read when the stream opens
    std::uint32_t written = 0; // slots filled; `published` trails it by less than `publishBatch`
    std::uint32_t publishBatch = 1; // sim_JobStreamPublishBatch, read when the stream opens
    bool prefetchSlots = false; // sim_JobStreamPrefetch, read when the stream opens

    // Separate lines: the sim thread writes `published`, the workers fight over `next`.
    alignas(kCacheLine) std::atomic<std::uint32_t> published{0}; // jobs the workers may take
    std::atomic<bool> closing{false};
    alignas(kCacheLine) std::atomic<std::uint32_t> next{0}; // next job a worker claims
    // A worker about to sleep counts itself in `sleepers`, then looks at `published` once more; the
    // sim thread stores `published`, then looks at `sleepers` (all seq_cst). One of the two sees
    // the other, so a job is never left with every worker asleep. `signal` is what they sleep on,
    // bumped only when someone sleeps.
    alignas(kCacheLine) std::atomic<std::uint32_t> signal{0};
    std::atomic<unsigned int> sleepers{0};

    std::mutex errorMutex;
    std::exception_ptr firstError;

    SStats stats; // sim thread only
    std::int64_t qpcFrequency = [] {
      LARGE_INTEGER frequency{};
      ::QueryPerformanceFrequency(&frequency);
      return frequency.QuadPart;
    }();

    /// Runs job `index` unless another thread took it first; true when this call ran it.
    bool RunSlot(const std::uint32_t index)
    {
      Slot& slot = slots[index];
      std::uint8_t expected = kQueued;
      if (!slot.state.compare_exchange_strong(expected, kRunning, std::memory_order_acq_rel)) {
        return false;
      }
      try {
        slot.fn(slot.context);
      } catch (...) {
        const std::lock_guard<std::mutex> lock(errorMutex);
        if (!firstError) {
          firstError = std::current_exception();
        }
      }
      slot.state.store(kDone, std::memory_order_release);
      return true;
    }

    void WorkerLoop()
    {
      unsigned int idleRounds = 0;
      for (;;) {
        std::uint32_t index = next.load(std::memory_order_acquire);
        if (index < published.load(std::memory_order_acquire)) {
          idleRounds = 0;
          if (workerDelayTicks > 0) {
            SpinFor(workerDelayTicks);
          }
          if (next.compare_exchange_weak(index, index + 1u, std::memory_order_acq_rel)) {
            FAF_PROFILE_ZONE_NAMED("SimStream Job");
            (void)RunSlot(index);
          }
          continue;
        }
        if (closing.load(std::memory_order_acquire)) {
          return;
        }
        if (++idleRounds < kSpinRounds) {
          _mm_pause();
          continue;
        }
        idleRounds = 0;
        const std::uint32_t seenSignal = signal.load(std::memory_order_seq_cst);
        sleepers.fetch_add(1u, std::memory_order_seq_cst);
        if (next.load(std::memory_order_seq_cst) < published.load(std::memory_order_seq_cst) ||
            closing.load(std::memory_order_seq_cst)) {
          sleepers.fetch_sub(1u, std::memory_order_seq_cst);
          continue;
        }
        signal.wait(seenSignal, std::memory_order_seq_cst);
        sleepers.fetch_sub(1u, std::memory_order_seq_cst);
      }
    }

    static void DrainEntry(void* const context, std::size_t, std::size_t)
    {
      // CSimWorkerPool's dispatcher also runs chunks (at StartAsync's serial fallback and at
      // FinishAsync); only workers wait for jobs here.
      if (IsSimWorkerThread()) {
        static_cast<Impl*>(context)->WorkerLoop();
      }
    }

    /// Shows the workers every filled slot.
    void PublishWritten()
    {
      if (published.load(std::memory_order_relaxed) == written) {
        return;
      }
      published.store(written, std::memory_order_seq_cst);
      WakeSleepers(false);
    }

    /// After a store to `published` or `closing`: wakes sleeping workers, if there are any.
    void WakeSleepers(const bool all)
    {
      if (sleepers.load(std::memory_order_seq_cst) == 0u) {
        return;
      }
      ++stats.mWakeCalls;
      signal.fetch_add(1u, std::memory_order_seq_cst);
      if (all) {
        signal.notify_all();
      } else {
        signal.notify_one();
      }
    }

    bool Open()
    {
      CSimWorkerPool& pool = CSimWorkerPool::Get();
      workerDelayTicks = 0;
      if (sim_WorkerJobDelayUs > 0) {
        LARGE_INTEGER frequency{};
        ::QueryPerformanceFrequency(&frequency);
        workerDelayTicks = frequency.QuadPart * sim_WorkerJobDelayUs / 1000000;
      }
      publishBatch = sim_JobStreamPublishBatch > 1 ? static_cast<std::uint32_t>(sim_JobStreamPublishBatch) : 1u;
      prefetchSlots = sim_JobStreamPrefetch;
      closing.store(false, std::memory_order_relaxed);
      published.store(0u, std::memory_order_relaxed);
      next.store(0u, std::memory_order_relaxed);
      written = 0;
      finishedPrefix = 0;
      // One chunk per worker plus one the dispatcher returns from at once, so the pool never takes
      // its serial path (count <= grain) for a pool of one worker.
      if (!pool.StartAsync(static_cast<std::size_t>(pool.WorkerCount()) + 1u, 1u, &DrainEntry, this)) {
        return false;
      }
      open = true;
      epoch = (epoch + 1u) & 0x7FFFu;
      ++stats.mOpens;
      return true;
    }

    void Finish(const std::uint32_t index)
    {
      Slot& slot = slots[index];
      if (slot.state.load(std::memory_order_acquire) == kDone) {
        return;
      }
      // A slot no worker can see yet runs here; the ones before it go to the workers first.
      PublishWritten();
      if (RunSlot(index)) {
        ++stats.mStolen;
        return; // no worker had taken it: ran here, as the serial code would have
      }
      FAF_PROFILE_ZONE_NAMED("SimStream Wait");
      LARGE_INTEGER start{};
      LARGE_INTEGER end{};
      ::QueryPerformanceCounter(&start);
      while (slot.state.load(std::memory_order_acquire) != kDone) {
        _mm_pause();
      }
      ::QueryPerformanceCounter(&end);
      ++stats.mWaited;
      stats.mWaitMicroseconds += static_cast<std::uint64_t>((end.QuadPart - start.QuadPart) * 1000000 / qpcFrequency);
    }

    void FinishAll()
    {
      PublishWritten();
      const std::uint32_t end = written;
      for (std::uint32_t index = finishedPrefix; index < end; ++index) {
        Finish(index);
      }
      finishedPrefix = end;
    }

    void Close()
    {
      if (!open) {
        return;
      }
      FinishAll();
      closing.store(true, std::memory_order_seq_cst);
      WakeSleepers(true);
      open = false;
      CSimWorkerPool::Get().FinishAsync();

      std::exception_ptr error;
      {
        const std::lock_guard<std::mutex> lock(errorMutex);
        error = firstError;
        firstError = nullptr;
      }
      if (error) {
        std::rethrow_exception(error);
      }
    }
  };

  CSimJobStream::CSimJobStream()
    : mImpl(std::make_unique<Impl>())
  {
  }

  CSimJobStream::~CSimJobStream() = default;

  CSimJobStream& CSimJobStream::Get()
  {
    static CSimJobStream sStream;
    return sStream;
  }

  std::int32_t CSimJobStream::Enqueue(const JobFunction fn, void* const context)
  {
    Impl& impl = *mImpl;
    if (IsSimWorkerThread() || !CSimWorkerPool::ParallelEnabled()) {
      fn(context);
      return kRanInline;
    }
    if (impl.open && impl.written == kCapacity) {
      impl.Close();
    }
    if (!impl.open && !impl.Open()) {
      fn(context);
      return kRanInline;
    }

    const std::uint32_t index = impl.written;
    if (impl.prefetchSlots && index + 2u < kCapacity) {
      // The slot two ahead was last written by the worker that ran it: fetch it for writing now.
      __builtin_prefetch(&impl.slots[index + 2u], 1);
    }
    Slot& slot = impl.slots[index];
    slot.fn = fn;
    slot.context = context;
    slot.state.store(kQueued, std::memory_order_relaxed);
    impl.written = index + 1u;
    if (impl.written - impl.published.load(std::memory_order_relaxed) >= impl.publishBatch) {
      impl.published.store(impl.written, std::memory_order_seq_cst);
      impl.WakeSleepers(false);
    }
    ++impl.stats.mQueued;
    return static_cast<std::int32_t>((impl.epoch << 16) | index);
  }

  void CSimJobStream::Finish(const std::int32_t ticket)
  {
    Impl& impl = *mImpl;
    // A ticket from before the last Close is done: Close finished every job.
    if (ticket < 0 || !impl.open || (static_cast<std::uint32_t>(ticket) >> 16) != impl.epoch) {
      return;
    }
    impl.Finish(static_cast<std::uint32_t>(ticket) & 0xFFFFu);
  }

  void CSimJobStream::FinishAll()
  {
    if (mImpl->open) {
      mImpl->FinishAll();
    }
  }

  void CSimJobStream::Close()
  {
    mImpl->Close();
  }

  bool CSimJobStream::IsOpen() const noexcept
  {
    return mImpl->open;
  }

  const CSimJobStream::SStats& CSimJobStream::Stats() const noexcept
  {
    return mImpl->stats;
  }
} // namespace moho
