#include "moho/sim/SimWorkerPool.h"
#include "gpg/core/profiling/Profiler.h"

#include <algorithm>
#include <atomic>
#include <bit>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <mutex>
#include <thread>
#include <vector>

#include <Windows.h>
#include <xmmintrin.h>

#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "moho/console/CConCommand.h"
#include "moho/core/ThreadPlacement.h"
#include "moho/misc/StartupHelpers.h"

namespace moho
{
  namespace
  {
    // MXCSR bits 0-5 are sticky exception *flags* (status, not control); a job inherits only the
    // control half: exception masks, rounding, flush-to-zero, denormals-are-zero.
    constexpr std::uint32_t kMxcsrControlMask = 0xFFC0u;

    // More workers than usable CPUs only adds contention.
    constexpr unsigned int kMaxWorkers = 64u;

    // True on a thread while it is inside CSimWorkerPool::Run as the dispatcher, so a job body that
    // calls Run again takes the serial path instead of deadlocking on its own dispatch.
    thread_local bool tIsDispatchingSimJob = false;

    [[nodiscard]] unsigned int UsableCpuCount() noexcept
    {
      DWORD_PTR processMask = 0;
      DWORD_PTR systemMask = 0;
      if (::GetProcessAffinityMask(::GetCurrentProcess(), &processMask, &systemMask) && processMask != 0) {
        return static_cast<unsigned int>(std::popcount(static_cast<std::uintptr_t>(processMask)));
      }
      return std::max(1u, std::thread::hardware_concurrency());
    }

    /// `/simworkers N` on the command line, otherwise 0: serial until a parallel phase is asked for.
    [[nodiscard]] int CommandLineWorkerCount()
    {
      msvc8::vector<msvc8::string> args;
      if (CFG_GetArgOption("/simworkers", 1u, &args) && !args.empty()) {
        return static_cast<int>(std::max(0L, std::strtol(args[0].c_str(), nullptr, 10)));
      }
      return 0;
    }

    /// Clamps a requested worker count to [0, min(usable CPUs, kMaxWorkers)].
    [[nodiscard]] unsigned int ClampWorkerCount(const int requested)
    {
      if (requested <= 0) {
        return 0u;
      }
      return std::min({static_cast<unsigned int>(requested), UsableCpuCount(), kMaxWorkers});
    }
  } // namespace

  int sim_Workers = -1;

  bool sim_ParallelRecon = true;

  TConVar<bool> gTConVar_sim_ParallelRecon(
    "sim_ParallelRecon",
    "Refresh each army's recon blips on sim workers (when sim_Workers > 0).",
    &sim_ParallelRecon
  );

  bool sim_ParallelSync = true;

  TConVar<bool> gTConVar_sim_ParallelSync(
    "sim_ParallelSync",
    "Copy the sync packet's unit updates on sim workers (when sim_Workers > 0).",
    &sim_ParallelSync
  );

  int sim_WorkerJobDelayUs = 0;

  TConVar<int> gTConVar_sim_WorkerJobDelayUs(
    "sim_WorkerJobDelayUs",
    "Debug: microseconds a sim worker waits before each chunk it takes (0 = none). Stress test for "
    "parallel phases; results are identical with any value.",
    &sim_WorkerJobDelayUs
  );

  TConVar<int> gTConVar_sim_Workers(
    "sim_Workers",
    "Worker threads for parallel sim phases; 0 runs every phase serially. Results are identical "
    "either way.",
    &sim_Workers
  );

  SFpuControlState SFpuControlState::Capture() noexcept
  {
    SFpuControlState state{};
#if defined(_M_IX86)
    std::uint16_t controlWord = 0;
    __asm fnstcw controlWord
    state.mX87ControlWord = controlWord;
#endif
    state.mMxcsr = _mm_getcsr() & kMxcsrControlMask;
    return state;
  }

  void SFpuControlState::Apply() const noexcept
  {
#if defined(_M_IX86)
    std::uint16_t controlWord = static_cast<std::uint16_t>(mX87ControlWord);
    __asm fldcw controlWord
#endif
    _mm_setcsr((_mm_getcsr() & ~kMxcsrControlMask) | (mMxcsr & kMxcsrControlMask));
  }

  struct CSimWorkerPool::Impl
  {
    unsigned int workerCount = 0;
    std::vector<std::thread> threads;

    std::mutex dispatchMutex; // one dispatcher at a time

    std::mutex mutex; // guards everything below except the atomics
    std::condition_variable wake;
    std::condition_variable done;
    std::uint64_t generation = 0;
    bool stopping = false;
    unsigned int activeWorkers = 0; // workers currently inside a job

    // The current job. Written under `mutex` before `generation` is bumped; a worker registers
    // under `mutex` too, so its reads happen-after the dispatcher's writes.
    RangeFunction fn = nullptr;
    void* context = nullptr;
    std::size_t count = 0;
    std::size_t grain = 1;
    std::size_t chunkCount = 0;
    SFpuControlState fpu{};
    std::int64_t workerDelayTicks = 0; // sim_WorkerJobDelayUs in QueryPerformanceCounter ticks
    std::atomic<std::size_t> nextChunk{0};
    std::atomic<std::size_t> chunksLeft{0};

    std::mutex errorMutex;
    std::exception_ptr firstError;

    void RunChunks()
    {
      const bool delayed = workerDelayTicks > 0 && IsSimWorkerThread();
      for (;;) {
        if (delayed) {
          LARGE_INTEGER start{};
          LARGE_INTEGER now{};
          ::QueryPerformanceCounter(&start);
          do {
            _mm_pause();
            ::QueryPerformanceCounter(&now);
          } while (now.QuadPart - start.QuadPart < workerDelayTicks);
        }
        const std::size_t chunk = nextChunk.fetch_add(1u, std::memory_order_relaxed);
        if (chunk >= chunkCount) {
          return;
        }

        const std::size_t begin = chunk * grain;
        const std::size_t end = std::min(count, begin + grain);
        try {
          FAF_PROFILE_ZONE_NAMED("SimWorker Task");
          fn(context, begin, end);
        } catch (...) {
          const std::lock_guard<std::mutex> errorLock(errorMutex);
          if (!firstError) {
            firstError = std::current_exception();
          }
        }

        if (chunksLeft.fetch_sub(1u, std::memory_order_acq_rel) == 1u) {
          const std::lock_guard<std::mutex> lock(mutex);
          done.notify_all();
        }
      }
    }

    void WorkerMain(const unsigned int index, std::uint64_t seenGeneration)
    {
      tIsSimWorkerThread = true;
      char name[32];
      std::snprintf(name, sizeof(name), "SimWorker %u", index);
      gpg::SetThreadName(0xFFFFFFFFu, name);
      PlaceCurrentThread(EThreadRole::SimWorker, index);

      // `seenGeneration` is the generation current when this thread was started, so a pool that
      // was resized wakes it only for jobs dispatched after that.
      for (;;) {
        SFpuControlState jobFpu{};
        {
          std::unique_lock<std::mutex> lock(mutex);
          wake.wait(lock, [&] { return stopping || generation != seenGeneration; });
          if (stopping) {
            return;
          }
          seenGeneration = generation;
          ++activeWorkers;
          jobFpu = fpu;
        }

        jobFpu.Apply();
#if MOHO_SIM_AFFINITY_CHECKS
        if (!(SFpuControlState::Capture() == jobFpu)) {
          gpg::HandleAssertFailure("sim worker failed to adopt the dispatcher's FPU control state", __LINE__, __FILE__);
        }
#endif
        RunChunks();

        const std::lock_guard<std::mutex> lock(mutex);
        if (--activeWorkers == 0u) {
          done.notify_all();
        }
      }
    }

    void Start()
    {
      threads.reserve(workerCount);
      std::uint64_t startGeneration = 0;
      {
        const std::lock_guard<std::mutex> lock(mutex);
        startGeneration = generation;
      }
      for (unsigned int index = 0; index < workerCount; ++index) {
        threads.emplace_back([this, index, startGeneration] { WorkerMain(index, startGeneration); });
      }
      gpg::Logf("SimWorkerPool: started %u worker threads", workerCount);
    }

    void Stop()
    {
      {
        const std::lock_guard<std::mutex> lock(mutex);
        stopping = true;
      }
      wake.notify_all();
      for (std::thread& thread : threads) {
        if (thread.joinable()) {
          thread.join();
        }
      }
      threads.clear();
      stopping = false;
    }
  };

  CSimWorkerPool::CSimWorkerPool()
    : mImpl(std::make_unique<Impl>())
  {
    if (sim_Workers < 0) {
      sim_Workers = CommandLineWorkerCount();
    }
    mImpl->workerCount = ClampWorkerCount(sim_Workers);
  }

  CSimWorkerPool::~CSimWorkerPool()
  {
    mImpl->Stop();
  }

  bool CSimWorkerPool::ParallelEnabled()
  {
    if (sim_Workers < 0) {
      sim_Workers = CommandLineWorkerCount();
    }
    return sim_Workers > 0;
  }

  CSimWorkerPool& CSimWorkerPool::Get()
  {
    static CSimWorkerPool sPool;
    return sPool;
  }

  unsigned int CSimWorkerPool::WorkerCount() const noexcept
  {
    return mImpl->workerCount;
  }

  void CSimWorkerPool::Run(const std::size_t count, std::size_t grain, const RangeFunction fn, void* const context)
  {
    if (count == 0u || fn == nullptr) {
      return;
    }
    if (grain == 0u) {
      grain = 1u;
    }

    Impl& impl = *mImpl;

    // `sim_Workers` changed since the last dispatch: retire the old threads (none is inside a job,
    // dispatches are serialized and this one has not started), new ones start below on demand.
    if (!IsSimWorkerThread() && !tIsDispatchingSimJob) {
      if (sim_Workers < 0) {
        sim_Workers = CommandLineWorkerCount();
      }
      const unsigned int wanted = ClampWorkerCount(sim_Workers);
      if (wanted != impl.workerCount) {
        const std::lock_guard<std::mutex> dispatchLock(impl.dispatchMutex);
        impl.Stop();
        impl.workerCount = wanted;
      }
    }

    // Serial path: no workers, a single chunk, a call from a worker, or a nested call from inside a
    // job on the dispatching thread. It walks the same chunk boundaries as the parallel path, so a
    // body that accumulates per chunk sees identical partitions either way.
    if (impl.workerCount == 0u || count <= grain || IsSimWorkerThread() || tIsDispatchingSimJob) {
      for (std::size_t begin = 0; begin < count; begin += grain) {
        fn(context, begin, std::min(count, begin + grain));
      }
      return;
    }

    const std::lock_guard<std::mutex> dispatchLock(impl.dispatchMutex);
    if (impl.threads.empty()) {
      impl.Start();
    }

    {
      std::unique_lock<std::mutex> lock(impl.mutex);
      // A worker that woke late for the previous job may still be registered. Let it leave before
      // the job fields are overwritten.
      impl.done.wait(lock, [&] { return impl.activeWorkers == 0u; });

      impl.fn = fn;
      impl.context = context;
      impl.count = count;
      impl.grain = grain;
      impl.chunkCount = (count + grain - 1u) / grain;
      impl.fpu = SFpuControlState::Capture();
      impl.workerDelayTicks = 0;
      if (sim_WorkerJobDelayUs > 0) {
        LARGE_INTEGER frequency{};
        ::QueryPerformanceFrequency(&frequency);
        impl.workerDelayTicks = frequency.QuadPart * sim_WorkerJobDelayUs / 1000000;
      }
      impl.nextChunk.store(0u, std::memory_order_relaxed);
      impl.chunksLeft.store(impl.chunkCount, std::memory_order_relaxed);
      impl.firstError = nullptr;
      ++impl.generation;
    }
    impl.wake.notify_all();

    tIsDispatchingSimJob = true;
    impl.RunChunks();
    tIsDispatchingSimJob = false;

    {
      std::unique_lock<std::mutex> lock(impl.mutex);
      // Every chunk finished, and no worker still holds a pointer into this job (the caller's
      // context dies when we return).
      impl.done.wait(lock, [&] {
        return impl.chunksLeft.load(std::memory_order_acquire) == 0u && impl.activeWorkers == 0u;
      });
    }

    if (impl.firstError) {
      std::rethrow_exception(impl.firstError);
    }
  }
} // namespace moho
