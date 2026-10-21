#include "moho/app/UserWorkerPool.h"
#include "moho/core/ThreadPlacement.h"

#include <algorithm>
#include <atomic>
#include <bit>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <mutex>
#include <thread>
#include <vector>

#include <Windows.h>

#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "moho/console/CConCommand.h"
#include "moho/sim/SimWorkerPool.h"

namespace moho
{
  namespace
  {
    constexpr unsigned int kMaxUserWorkers = 32u;
    constexpr unsigned int kDefaultUserWorkers = 6u;

    // Set on pool workers, and on the dispatcher while it runs chunks, so a nested dispatch runs
    // serially instead of waiting on itself.
    thread_local bool tInsideUserJob = false;

    [[nodiscard]] unsigned int UsableCpuCount() noexcept
    {
      DWORD_PTR processMask = 0;
      DWORD_PTR systemMask = 0;
      if (::GetProcessAffinityMask(::GetCurrentProcess(), &processMask, &systemMask) && processMask != 0) {
        return static_cast<unsigned int>(std::popcount(static_cast<std::uintptr_t>(processMask)));
      }
      return std::max(1u, std::thread::hardware_concurrency());
    }
  } // namespace

  int user_Workers = -1;

  TConVar<int> gTConVar_user_Workers(
    "user_Workers",
    "Worker threads for parallel main-thread work (strategic icons, culling...): -1 = automatic, "
    "0 = everything on the main thread. Rendering only; never affects the simulation.",
    &user_Workers
  );

  struct CUserWorkerPool::Impl
  {
    unsigned int workerCount = 0;
    std::vector<std::thread> threads;

    std::mutex mutex; // guards everything below except the atomics
    std::condition_variable wake;
    std::condition_variable done;
    std::uint64_t generation = 0;
    bool stopping = false;
    unsigned int activeWorkers = 0;

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
        try {
          fn(context, begin, std::min(count, begin + grain));
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
      tInsideUserJob = true;
      char name[32];
      std::snprintf(name, sizeof(name), "UserWorker %u", index);
      gpg::SetThreadName(0xFFFFFFFFu, name);
      PlaceCurrentThread(EThreadRole::UserWorker, index);

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
        RunChunks();

        const std::lock_guard<std::mutex> lock(mutex);
        if (--activeWorkers == 0u) {
          done.notify_all();
        }
      }
    }

    void Start()
    {
      std::uint64_t startGeneration = 0;
      {
        const std::lock_guard<std::mutex> lock(mutex);
        startGeneration = generation;
      }
      threads.reserve(workerCount);
      for (unsigned int index = 0; index < workerCount; ++index) {
        threads.emplace_back([this, index, startGeneration] { WorkerMain(index, startGeneration); });
      }
      gpg::Logf("UserWorkerPool: started %u worker threads", workerCount);
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

  CUserWorkerPool::CUserWorkerPool()
    : mImpl(std::make_unique<Impl>())
  {}

  CUserWorkerPool::~CUserWorkerPool()
  {
    mImpl->Stop();
  }

  CUserWorkerPool& CUserWorkerPool::Get()
  {
    static CUserWorkerPool sPool;
    return sPool;
  }

  unsigned int CUserWorkerPool::ConfiguredWorkerCount()
  {
    if (user_Workers == 0) {
      return 0u;
    }
    const unsigned int cpus = UsableCpuCount();
    if (user_Workers < 0) {
      return cpus > 2u ? std::min(cpus - 2u, kDefaultUserWorkers) : 0u;
    }
    return std::min({static_cast<unsigned int>(user_Workers), cpus, kMaxUserWorkers});
  }

  void CUserWorkerPool::Run(const std::size_t count, std::size_t grain, const RangeFunction fn, void* const context)
  {
    if (count == 0u || fn == nullptr) {
      return;
    }
    if (grain == 0u) {
      grain = 1u;
    }

    Impl& impl = *mImpl;
    if (!tInsideUserJob) {
      const unsigned int wanted = ConfiguredWorkerCount();
      if (wanted != impl.workerCount) {
        impl.Stop();
        impl.workerCount = wanted;
      }
    }

    // Serial path: the same chunk boundaries as the parallel one.
    if (impl.workerCount == 0u || count <= grain || tInsideUserJob) {
      for (std::size_t begin = 0; begin < count; begin += grain) {
        fn(context, begin, std::min(count, begin + grain));
      }
      return;
    }

    if (impl.threads.empty()) {
      impl.Start();
    }

    {
      std::unique_lock<std::mutex> lock(impl.mutex);
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

    tInsideUserJob = true;
    impl.RunChunks();
    tInsideUserJob = false;

    {
      std::unique_lock<std::mutex> lock(impl.mutex);
      impl.done.wait(lock, [&] {
        return impl.chunksLeft.load(std::memory_order_acquire) == 0u && impl.activeWorkers == 0u;
      });
    }

    if (impl.firstError) {
      std::rethrow_exception(impl.firstError);
    }
  }
} // namespace moho
