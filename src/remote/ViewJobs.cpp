#include "remote/ViewJobs.h"

#include <utility>

#include "moho/sim/SimThreadRole.h"

// Engine addition, server mode: see ViewJobs.h.

namespace faf::remote
{
  CViewJobs::CViewJobs(const unsigned int threads)
  {
    mThreads.reserve(threads);
    for (unsigned int index = 0; index < threads; ++index) {
      mThreads.emplace_back([this] { ThreadMain(); });
    }
  }

  CViewJobs::~CViewJobs()
  {
    {
      const std::lock_guard<std::mutex> lock(mMutex);
      mStopping = true;
    }
    mWake.notify_all();
    for (std::thread& thread : mThreads) {
      thread.join();
    }
  }

  void CViewJobs::Start(const std::size_t count, std::function<void(std::size_t)> job)
  {
    {
      const std::lock_guard<std::mutex> lock(mMutex);
      mJob = std::move(job);
      mCount = count;
      mNext = 0u;
      mFinished = 0u;
      mFpu = moho::SFpuControlState::Capture();
    }
    mWake.notify_all();
  }

  void CViewJobs::Wait()
  {
    std::unique_lock<std::mutex> lock(mMutex);
    mDone.wait(lock, [this] { return mFinished == mCount; });
  }

  void CViewJobs::ThreadMain()
  {
    moho::tIsSimWorkerThread = true; // the same rules as the sim's workers: no Lua, no nested batches
    std::unique_lock<std::mutex> lock(mMutex);
    for (;;) {
      mWake.wait(lock, [this] { return mStopping || mNext < mCount; });
      if (mStopping) {
        return;
      }
      const std::size_t index = mNext++;
      const moho::SFpuControlState fpu = mFpu;
      lock.unlock();
      fpu.Apply();
      mJob(index);
      lock.lock();
      if (++mFinished == mCount) {
        mDone.notify_all();
      }
    }
  }
} // namespace faf::remote
