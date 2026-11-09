#pragma once

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

#include "moho/sim/SimWorkerPool.h"

// Engine addition, server mode (plan WPR.35): a batch of jobs that run while the sim goes on, for the
// part of a view's beat that reads only what the view keeps. CSimWorkerPool's batches block the sim
// thread, and its workers have pose jobs to run during the next tick, so these threads are their own.
//
// The sim thread never takes a job itself, even while it waits: what it allocates and frees decides
// the addresses later sim objects get, and this work must not touch that.

namespace faf::remote
{
  class CViewJobs
  {
  public:
    explicit CViewJobs(unsigned int threads);
    ~CViewJobs();

    CViewJobs(const CViewJobs&) = delete;
    CViewJobs& operator=(const CViewJobs&) = delete;

    /** Starts `job(0)` .. `job(count - 1)` and returns. The last batch must have been waited for. */
    void Start(std::size_t count, std::function<void(std::size_t)> job);
    /** Returns when the batch is over. */
    void Wait();

  private:
    void ThreadMain();

    std::mutex mMutex;
    std::condition_variable mWake;
    std::condition_variable mDone;
    std::function<void(std::size_t)> mJob;
    std::size_t mCount = 0;
    std::size_t mNext = 0;
    std::size_t mFinished = 0;
    moho::SFpuControlState mFpu{};
    bool mStopping = false;
    std::vector<std::thread> mThreads;
  };
} // namespace faf::remote
