#include "moho/sim/SimWorkerPool.h"

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
#include "moho/misc/StartupHelpers.h"

namespace moho
{
  namespace
  {
    // MXCSR bits 0-5 are sticky exception *flags* (status, not control); a job inherits only the
    // control half: exception masks, rounding, flush-to-zero, denormals-are-zero.
    constexpr std::uint32_t kMxcsrControlMask = 0xFFC0u;

    // Sim and main threads keep one CPU each; beyond eight workers the sim's parallel phases are
    // too short for more threads to pay off.
    constexpr unsigned int kReservedCpus = 2u;
    constexpr unsigned int kMaxDefaultWorkers = 8u;

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

    /// `/simworkers N` wins; otherwise usable CPUs minus the Sim and main threads, capped.
    [[nodiscard]] unsigned int ResolveWorkerCount()
    {
      msvc8::vector<msvc8::string> args;
      if (CFG_GetArgOption("/simworkers", 1u, &args) && !args.empty()) {
        return static_cast<unsigned int>(std::max(0L, std::strtol(args[0].c_str(), nullptr, 10)));
      }
      const unsigned int cpus = UsableCpuCount();
      return cpus > kReservedCpus ? std::min(cpus - kReservedCpus, kMaxDefaultWorkers) : 0u;
    }
  } // namespace

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
    std::atomic<std::size_t> nextChunk{0};
    std::atomic<std::size_t> chunksLeft{0};

    std::mutex errorMutex;
    std::exception_ptr firstError;

    void RunChunks()
    {
      for (;;) {
        const std::size_t chunk = nextChunk.fetch_add(1u, std::memory_order_relaxed);
        if (chunk >= chunkCount) {
          return;
        }

        const std::size_t begin = chunk * grain;
        const std::size_t end = std::min(count, begin + grain);
        try {
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

    void WorkerMain(const unsigned int index)
    {
      tIsSimWorkerThread = true;
      char name[32];
      std::snprintf(name, sizeof(name), "SimWorker %u", index);
      gpg::SetThreadName(0xFFFFFFFFu, name);

      std::uint64_t seenGeneration = 0;
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
      for (unsigned int index = 0; index < workerCount; ++index) {
        threads.emplace_back([this, index] { WorkerMain(index); });
      }
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
    }
  };

  CSimWorkerPool::CSimWorkerPool()
    : mImpl(std::make_unique<Impl>())
  {
    mImpl->workerCount = ResolveWorkerCount();
  }

  CSimWorkerPool::~CSimWorkerPool()
  {
    mImpl->Stop();
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
