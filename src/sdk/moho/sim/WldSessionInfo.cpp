#include "WldSessionInfo.h"

#include <climits>
#include <cstring>
#include <new>

#include "boost/thread.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/RRuleGameRules.h"

namespace moho
{
  namespace
  {
    struct ScopedLoadControlLock
    {
      explicit ScopedLoadControlLock(gpg::core::Mutex& lock)
        : mLock(lock)
      {
        mLock.lock();
      }

      ~ScopedLoadControlLock()
      {
        mLock.unlock();
      }

      ScopedLoadControlLock(const ScopedLoadControlLock&) = delete;
      ScopedLoadControlLock& operator=(const ScopedLoadControlLock&) = delete;

    private:
      gpg::core::Mutex& mLock;
    };

    void CloseHandleIfValid(void*& handle)
    {
      if (!handle) {
        return;
      }

      CloseHandle(static_cast<HANDLE>(handle));
      handle = nullptr;
    }
  } // namespace

  /**
   * Address: 0x00412DC0 (FUN_00412DC0)
   *
   * What it does:
   * Copy-constructs background-task-aborted exception state.
   */
  XBackgroundTaskAborted::XBackgroundTaskAborted(const XBackgroundTaskAborted& other) noexcept
    : std::exception(other)
  {}

  /**
   * Address: 0x00412DE0 (FUN_00412DE0)
   *
   * What it does:
   * Destroys background-task-aborted exception instance.
   */
  XBackgroundTaskAborted::~XBackgroundTaskAborted() noexcept = default;

  SWldScenarioLoadWakeSet::SWldScenarioLoadWakeSet()
    : mWakeEvent(CreateEventW(nullptr, FALSE, FALSE, nullptr))
    , mQueueSemaphore(CreateSemaphoreW(nullptr, 0, LONG_MAX, nullptr))
    , mCountersMutex(CreateMutexW(nullptr, FALSE, nullptr))
    , mGoneCount(0)
    , mBlockedCount(0)
    , mWaitingCount(0)
  {}

  SWldScenarioLoadWakeSet::~SWldScenarioLoadWakeSet()
  {
    CloseHandleIfValid(mWakeEvent);
    CloseHandleIfValid(mQueueSemaphore);
    CloseHandleIfValid(mCountersMutex);
  }

  void SWldScenarioLoadWakeSet::SignalOne() const
  {
    if (!mWakeEvent) {
      return;
    }

    SetEvent(static_cast<HANDLE>(mWakeEvent));
  }

  void SWldScenarioLoadWakeSet::WaitOne() const
  {
    if (!mWakeEvent) {
      return;
    }

    WaitForSingleObject(static_cast<HANDLE>(mWakeEvent), INFINITE);
  }

  void SWldScenarioLoadCallbackStorage::Bind(const WldScenarioLoadEntryFn entryPoint, SWldScenarioInfo* const scenario)
  {
    mDispatchOwner = nullptr;
    mReserved04 = 0;
    mEntryPoint = entryPoint;
    mScenario = scenario;
    std::memset(mReserved10, 0, sizeof(mReserved10));

    if (mEntryPoint && mScenario) {
      mDispatchOwner = mScenario;
    }
  }

  void SWldScenarioLoadCallbackStorage::Invoke(CWaitHandleSet** const waitSet) const
  {
    if (!mEntryPoint || !mScenario) {
      return;
    }

    mEntryPoint(mScenario, waitSet);
  }

  /**
   * Address: 0x00412B90 (FUN_00412b90)
   */
  SWldScenarioLoadControl::SWldScenarioLoadControl(
    const char* const workerName, SWldScenarioInfo* const owner, const WldScenarioLoadEntryFn entryPoint
  )
    : mMutex()
    , mThreadName(workerName ? workerName : "")
    , mCallback{}
    , mState(EWldScenarioLoadControlState::kNotStarted)
    , mProgressToken(0)
    , mPauseRequested(false)
    , mStopRequested(false)
    , pad_52{}
    , mWakeSet()
    , mDisposeAfterWorkerExit(false)
    , pad_6D{}
  {
    mMutex.init_critical_section();
    mCallback.Bind(entryPoint, owner);
  }

  /**
   * Address: 0x00412F00 path (FUN_00412f00)
   */
  SWldScenarioLoadControl::~SWldScenarioLoadControl()
  {
    mCallback.Bind(nullptr, nullptr);
    mThreadName = "";
  }

  /**
   * Address: 0x00413110 (FUN_00413110)
   */
  void SWldScenarioLoadControl::RequestPause()
  {
    ScopedLoadControlLock lock(mMutex);
    if (!mPauseRequested) {
      mPauseRequested = true;
    }
  }

  /**
   * Address: 0x004131A0 (FUN_004131a0)
   */
  void SWldScenarioLoadControl::RequestStop()
  {
    ScopedLoadControlLock lock(mMutex);
    if (mStopRequested) {
      return;
    }

    mStopRequested = true;
    if (mState == EWldScenarioLoadControlState::kPaused) {
      mWakeSet.SignalOne();
    } else if (mState == EWldScenarioLoadControlState::kNotStarted ||
               mState == EWldScenarioLoadControlState::kCompleted) {
      mState = EWldScenarioLoadControlState::kReadyForDestroy;
    }
  }

  /**
   * Address: 0x00412FA0 (FUN_00412fa0)
   */
  void SWldScenarioLoadControl::StartOrResume(SWldScenarioLoadTask& ownerTask)
  {
    ScopedLoadControlLock lock(mMutex);
    if (mPauseRequested) {
      mPauseRequested = false;
    }

    if (mState == EWldScenarioLoadControlState::kNotStarted) {
      mState = EWldScenarioLoadControlState::kRunning;

      boost::thread* worker = nullptr;
      if (mCallback.mEntryPoint && mCallback.mScenario) {
        worker = new (std::nothrow) boost::thread([this]() {
          RunWorkerThread();
        });
      }

      boost::thread* const previousWorker = ownerTask.mWorkerThread;
      ownerTask.mWorkerThread = worker;
      if (previousWorker) {
        delete previousWorker;
      }
    } else if (mState == EWldScenarioLoadControlState::kPaused) {
      mState = EWldScenarioLoadControlState::kRunning;
      mWakeSet.SignalOne();
    }
  }

  /**
   * Address: 0x004132B0 (FUN_004132b0)
   */
  void SWldScenarioLoadControl::RunWorkerThread()
  {
    bool disposeAfterExit = false;
    try {
      CWaitHandleSet* waitSet = nullptr;
      mCallback.Invoke(&waitSet);

      {
        ScopedLoadControlLock lock(mMutex);
        mPauseRequested = false;
        mState =
          mStopRequested ? EWldScenarioLoadControlState::kReadyForDestroy : EWldScenarioLoadControlState::kCompleted;
        disposeAfterExit = mDisposeAfterWorkerExit;
      }
    } catch (...) {
      gpg::Warnf("CWldSessionLoaderImpl worker raised an exception; marking scenario as failed.");

      {
        ScopedLoadControlLock lock(mMutex);
        mPauseRequested = false;
        mState = EWldScenarioLoadControlState::kReadyForDestroy;
        disposeAfterExit = mDisposeAfterWorkerExit;
      }
    }

    mWakeSet.SignalOne();
    if (!disposeAfterExit) {
      ScopedLoadControlLock lock(mMutex);
      disposeAfterExit = mDisposeAfterWorkerExit;
    }
    if (disposeAfterExit) {
      delete this;
    }
  }

  /**
   * Address: 0x00412C70 (FUN_00412C70, func_UpdateLoadingProgress)
   *
   * What it does:
   * Updates progress token, blocks while pause is requested, and throws
   * `XBackgroundTaskAborted` when stop is requested.
   */
  void SWldScenarioLoadControl::UpdateLoadingProgress()
  {
    mMutex.lock();
    mProgressToken = 0;

    if (mStopRequested) {
      mMutex.unlock();
      throw XBackgroundTaskAborted{};
    }

    while (mPauseRequested) {
      if (mState != EWldScenarioLoadControlState::kPaused) {
        gpg::Logf("Background task \"%s\" paused.", mThreadName.c_str());
        mState = EWldScenarioLoadControlState::kPaused;
      }

      mMutex.unlock();
      mWakeSet.WaitOne();
      mMutex.lock();

      if (mStopRequested) {
        mMutex.unlock();
        throw XBackgroundTaskAborted{};
      }
    }

    if (mState != EWldScenarioLoadControlState::kRunning) {
      gpg::Logf("Background task \"%s\" resumed.", mThreadName.c_str());
      mState = EWldScenarioLoadControlState::kRunning;
    }

    mMutex.unlock();
  }

  /**
   * Address: 0x00885460 (FUN_00885460)
   */
  SWldScenarioLoadTask* SWldScenarioLoadTask::Create(
    const char* const workerName, SWldScenarioInfo* const owner, const WldScenarioLoadEntryFn entryPoint
  )
  {
    auto* const task = new (std::nothrow) SWldScenarioLoadTask{};
    if (!task) {
      return nullptr;
    }

    task->mControl = new (std::nothrow) SWldScenarioLoadControl(workerName, owner, entryPoint);
    task->mWorkerThread = nullptr;
    return task;
  }

  /**
   * Address: 0x008866A0 (FUN_008866a0)
   */
  void SWldScenarioLoadTask::AssignWithRelease(SWldScenarioLoadTask*& slot, SWldScenarioLoadTask* const replacement)
  {
    SWldScenarioLoadTask* const previous = slot;
    slot = replacement;
    if (!previous) {
      return;
    }

    previous->ReleaseOwnedResources();
    delete previous;
  }

  /**
   * Address: 0x00412E00 (FUN_00412e00)
   */
  void SWldScenarioLoadTask::ReleaseOwnedResources()
  {
    SWldScenarioLoadControl* control = mControl;
    bool destroyControlNow = false;

    if (control) {
      {
        ScopedLoadControlLock lock(control->mMutex);
        switch (control->mState) {
        case EWldScenarioLoadControlState::kNotStarted:
        case EWldScenarioLoadControlState::kReadyForDestroy:
        case EWldScenarioLoadControlState::kCompleted:
          destroyControlNow = true;
          break;
        case EWldScenarioLoadControlState::kPaused:
        case EWldScenarioLoadControlState::kRunning:
          control->mStopRequested = true;
          control->mWakeSet.SignalOne();
          control->mDisposeAfterWorkerExit = true;
          break;
        default:
          break;
        }
      }

      if (destroyControlNow) {
        delete control;
        control = nullptr;
      }
    }

    mControl = nullptr;
    if (mWorkerThread) {
      delete mWorkerThread;
      mWorkerThread = nullptr;
    }
  }

  /**
   * Address: 0x00413270 (FUN_00413270)
   *
   * What it does:
   * Starts/resumes the worker and joins one active worker thread.
   */
  void SWldScenarioLoadTask::StartOrResumeAndJoin()
  {
    if (mControl != nullptr) {
      mControl->StartOrResume(*this);
    }

    if (mWorkerThread != nullptr) {
      mWorkerThread->join();

      boost::thread* const worker = mWorkerThread;
      mWorkerThread = nullptr;
      delete worker;
    }
  }

  /**
   * Address: 0x00885530 (FUN_00885530, ??0struct_ScenarioInfo@@QAE@@Z)
   */
  SWldScenarioInfo::SWldScenarioInfo(const char* const mapName, const msvc8::string& gameMods)
  {
    mMapName = gpg::STR_ToLower(mapName ? mapName : "");
    mGameMods = gameMods;
    mUnloadRequested = false;
    mLoaded = false;
    mLoadFlags = 0;
    mLoadTask = nullptr;
    mWldMap = nullptr;
    mState = nullptr;
    mGameRules = nullptr;
  }

  /**
   * Address: 0x008857A0 (FUN_008857A0, sub_8857A0)
   */
  void SWldScenarioInfo::ResetAndUnlink()
  {
    if (mGameRules) {
      delete mGameRules;
      mGameRules = nullptr;
    }

    if (mState) {
      delete mState;
      mState = nullptr;
    }

    if (mWldMap) {
      delete mWldMap;
      mWldMap = nullptr;
    }

    if (mLoadTask) {
      mLoadTask->ReleaseOwnedResources();
      delete mLoadTask;
      mLoadTask = nullptr;
    }

    mGameMods = "";
    mMapName = "";
    ListUnlink();
  }
} // namespace moho
