#pragma once

#include <cstddef>
#include <cstdint>
#include <exception>

#include "boost/shared_ptr.h"
#include "gpg/core/utils/Sync.h"
#include "legacy/containers/String.h"
#include "moho/containers/TDatList.h"

namespace LuaPlus
{
  class LuaState;
}

namespace boost
{
  class thread;
}

namespace moho
{
  class CWldMap;
  class CWaitHandleSet;
  class IClientManager;
  class LaunchInfoBase;
  class RRuleGameRules;
  struct SWldScenarioInfo;

  /**
   * Address evidence:
   * - ctor use at 0x00893160 (FUN_00893160, CWldSession::CWldSession)
   *
   * What it does:
   * Session bootstrap payload passed into world-session creation.
   */
  struct SWldSessionInfo
  {
    msvc8::string mMapName;                        // 0x00
    boost::shared_ptr<LaunchInfoBase> mLaunchInfo; // 0x1C
    bool mIsBeingRecorded;                         // 0x24
    bool mIsReplay;                                // 0x25
    bool mIsMultiplayer;                           // 0x26
    std::uint8_t pad_27{};                         // 0x27
    IClientManager* mClientManager;                // 0x28
    std::uint32_t mSourceId;                       // 0x2C
  };

  static_assert(sizeof(SWldSessionInfo) == 0x30, "SWldSessionInfo size must be 0x30");
  static_assert(offsetof(SWldSessionInfo, mMapName) == 0x00, "SWldSessionInfo::mMapName offset must be 0x00");
  static_assert(offsetof(SWldSessionInfo, mLaunchInfo) == 0x1C, "SWldSessionInfo::mLaunchInfo offset must be 0x1C");
  static_assert(
    offsetof(SWldSessionInfo, mIsBeingRecorded) == 0x24, "SWldSessionInfo::mIsBeingRecorded offset must be 0x24"
  );
  static_assert(offsetof(SWldSessionInfo, mIsReplay) == 0x25, "SWldSessionInfo::mIsReplay offset must be 0x25");
  static_assert(
    offsetof(SWldSessionInfo, mIsMultiplayer) == 0x26, "SWldSessionInfo::mIsMultiplayer offset must be 0x26"
  );
  static_assert(
    offsetof(SWldSessionInfo, mClientManager) == 0x28, "SWldSessionInfo::mClientManager offset must be 0x28"
  );
  static_assert(offsetof(SWldSessionInfo, mSourceId) == 0x2C, "SWldSessionInfo::mSourceId offset must be 0x2C");

  /**
   * Address evidence:
   * - extracted by CWldSessionLoaderImpl path at 0x00886170 (FUN_00886170)
   *
   * What it does:
   * Transient loaded game objects transferred into CWldSession creation.
   */
  struct SWldGameData
  {
    LuaPlus::LuaState* mState;  // 0x00
    RRuleGameRules* mGameRules; // 0x04
    CWldMap* mWldMap;           // 0x08
  };

  static_assert(sizeof(SWldGameData) == 0x0C, "SWldGameData size must be 0x0C");
  static_assert(offsetof(SWldGameData, mState) == 0x00, "SWldGameData::mState offset must be 0x00");
  static_assert(offsetof(SWldGameData, mGameRules) == 0x04, "SWldGameData::mGameRules offset must be 0x04");
  static_assert(offsetof(SWldGameData, mWldMap) == 0x08, "SWldGameData::mWldMap offset must be 0x08");

  enum class EWldScenarioLoadControlState : std::uint32_t
  {
    kNotStarted = 0,
    kPaused = 1,
    kRunning = 2,
    kReadyForDestroy = 3,
    kCompleted = 4,
  };

  /**
   * VFTABLE: 0x00E00A94
   * COL: 0x00E5D738
   */
  class XBackgroundTaskAborted : public std::exception
  {
  public:
    XBackgroundTaskAborted() noexcept = default;

    /**
     * Address: 0x00412DC0 (FUN_00412DC0)
     *
     * What it does:
     * Copy-constructs background-task-aborted exception state.
     */
    XBackgroundTaskAborted(const XBackgroundTaskAborted& other) noexcept;

    /**
     * Address: 0x00412DE0 (FUN_00412DE0)
     *
     * What it does:
     * Destroys background-task-aborted exception instance.
     */
    ~XBackgroundTaskAborted() noexcept override;
  };

  using WldScenarioLoadEntryFn = void (*)(SWldScenarioInfo*, CWaitHandleSet**);

  /**
   * Address evidence:
   * - ctor/dtor helper usage at 0x00412B90 / 0x00412F00 path.
   * - signal path at 0x00412FA0 / 0x004131A0.
   *
   * What it does:
   * Legacy wake/signal primitive block embedded inside scenario load control.
   */
  struct SWldScenarioLoadWakeSet
  {
    void* mWakeEvent;            // 0x00
    void* mQueueSemaphore;       // 0x04
    void* mCountersMutex;        // 0x08
    std::uint32_t mGoneCount;    // 0x0C
    std::uint32_t mBlockedCount; // 0x10
    std::uint32_t mWaitingCount; // 0x14

    SWldScenarioLoadWakeSet();
    ~SWldScenarioLoadWakeSet();

    void SignalOne() const;
    void WaitOne() const;
  };

  static_assert(sizeof(SWldScenarioLoadWakeSet) == 0x18, "SWldScenarioLoadWakeSet size must be 0x18");
  static_assert(
    offsetof(SWldScenarioLoadWakeSet, mWakeEvent) == 0x00, "SWldScenarioLoadWakeSet::mWakeEvent offset must be 0x00"
  );
  static_assert(
    offsetof(SWldScenarioLoadWakeSet, mQueueSemaphore) == 0x04,
    "SWldScenarioLoadWakeSet::mQueueSemaphore offset must be 0x04"
  );
  static_assert(
    offsetof(SWldScenarioLoadWakeSet, mCountersMutex) == 0x08,
    "SWldScenarioLoadWakeSet::mCountersMutex offset must be 0x08"
  );

  /**
   * Address evidence:
   * - callback object placement at 0x00412B90 (+0x28..+0x47)
   * - bind helper at 0x008868A0.
   *
   * What it does:
   * Stores loader worker entry callback and bound scenario owner.
   */
  struct SWldScenarioLoadCallbackStorage
  {
    void* mDispatchOwner;               // 0x00
    std::uint32_t mReserved04;          // 0x04
    WldScenarioLoadEntryFn mEntryPoint; // 0x08
    SWldScenarioInfo* mScenario;        // 0x0C
    std::uint8_t mReserved10[0x14];     // 0x10

    void Bind(WldScenarioLoadEntryFn entryPoint, SWldScenarioInfo* scenario);
    void Invoke(CWaitHandleSet** waitSet) const;
  };

  static_assert(sizeof(SWldScenarioLoadCallbackStorage) == 0x24, "SWldScenarioLoadCallbackStorage size must be 0x24");
  static_assert(
    offsetof(SWldScenarioLoadCallbackStorage, mEntryPoint) == 0x08,
    "SWldScenarioLoadCallbackStorage::mEntryPoint offset must be 0x08"
  );
  static_assert(
    offsetof(SWldScenarioLoadCallbackStorage, mScenario) == 0x0C,
    "SWldScenarioLoadCallbackStorage::mScenario offset must be 0x0C"
  );

  struct SWldScenarioLoadTask;

  /**
   * Address evidence:
   * - ctor alloc/construct at 0x00412B90 (FUN_00412b90, alloc size 0x70).
   * - scheduler helpers at 0x00412FA0 / 0x00413110 / 0x004131A0.
   *
   * What it does:
   * Per-scenario async load control object: thread state, stop/pause flags,
   * wake primitives, and bound worker callback payload.
   */
  struct SWldScenarioLoadControl
  {
    gpg::core::Mutex mMutex;                   // 0x00
    msvc8::string mThreadName;                 // 0x08
    SWldScenarioLoadCallbackStorage mCallback; // 0x24
    EWldScenarioLoadControlState mState;       // 0x48
    std::uint32_t mProgressToken;              // 0x4C
    bool mPauseRequested;                      // 0x50
    bool mStopRequested;                       // 0x51
    std::uint8_t pad_52[2];                    // 0x52
    SWldScenarioLoadWakeSet mWakeSet;          // 0x54
    bool mDisposeAfterWorkerExit;              // 0x6C
    std::uint8_t pad_6D[3];                    // 0x6D

    /**
     * Address: 0x00412B90 (FUN_00412b90)
     */
    SWldScenarioLoadControl(const char* workerName, SWldScenarioInfo* owner, WldScenarioLoadEntryFn entryPoint);

    /**
     * Address: 0x00412F00 path (FUN_00412f00)
     */
    ~SWldScenarioLoadControl();

    /**
     * Address: 0x00413110 (FUN_00413110)
     */
    void RequestPause();

    /**
     * Address: 0x004131A0 (FUN_004131a0)
     */
    void RequestStop();

    /**
     * Address: 0x00412FA0 (FUN_00412fa0)
     */
    void StartOrResume(SWldScenarioLoadTask& ownerTask);

    /**
     * Address: 0x004132B0 (FUN_004132b0)
     */
    void RunWorkerThread();

    /**
     * Address: 0x00412C70 (FUN_00412C70, func_UpdateLoadingProgress)
     *
     * What it does:
     * Updates loader progress state, waits while pause is requested, and throws
     * `XBackgroundTaskAborted` when stop is requested.
     */
    void UpdateLoadingProgress();
  };

  static_assert(sizeof(SWldScenarioLoadControl) == 0x70, "SWldScenarioLoadControl size must be 0x70");
  static_assert(
    offsetof(SWldScenarioLoadControl, mThreadName) == 0x08, "SWldScenarioLoadControl::mThreadName offset must be 0x08"
  );
  static_assert(
    offsetof(SWldScenarioLoadControl, mCallback) == 0x24, "SWldScenarioLoadControl::mCallback offset must be 0x24"
  );
  static_assert(
    offsetof(SWldScenarioLoadControl, mState) == 0x48, "SWldScenarioLoadControl::mState offset must be 0x48"
  );
  static_assert(
    offsetof(SWldScenarioLoadControl, mWakeSet) == 0x54, "SWldScenarioLoadControl::mWakeSet offset must be 0x54"
  );
  static_assert(
    offsetof(SWldScenarioLoadControl, mDisposeAfterWorkerExit) == 0x6C,
    "SWldScenarioLoadControl::mDisposeAfterWorkerExit offset must be 0x6C"
  );

  /**
   * Address evidence:
   * - used at 0x00885B61 / 0x00885D2E / 0x0088572D (control acquire/release path)
   * - worker pointer used at 0x00885732..0x00885754
   *
   * What it does:
   * Runtime async-load task pair attached to SWldScenarioInfo.
   */
  struct SWldScenarioLoadTask
  {
    SWldScenarioLoadControl* mControl; // 0x00
    boost::thread* mWorkerThread;      // 0x04

    /**
     * Address: 0x00885460 (FUN_00885460)
     */
    static SWldScenarioLoadTask*
    Create(const char* workerName, SWldScenarioInfo* owner, WldScenarioLoadEntryFn entryPoint);

    /**
     * Address: 0x008866A0 (FUN_008866a0)
     */
    static void AssignWithRelease(SWldScenarioLoadTask*& slot, SWldScenarioLoadTask* replacement);

    /**
     * Address: 0x00412E00 (FUN_00412e00)
     */
    void ReleaseOwnedResources();

    /**
     * Address: 0x00413270 (FUN_00413270)
     *
     * What it does:
     * Starts/resumes the worker and joins one active thread instance.
     */
    void StartOrResumeAndJoin();
  };

  static_assert(sizeof(SWldScenarioLoadTask) == 0x08, "SWldScenarioLoadTask size must be 0x08");
  static_assert(offsetof(SWldScenarioLoadTask, mControl) == 0x00, "SWldScenarioLoadTask::mControl offset must be 0x00");
  static_assert(
    offsetof(SWldScenarioLoadTask, mWorkerThread) == 0x04, "SWldScenarioLoadTask::mWorkerThread offset must be 0x04"
  );

  /**
   * Address evidence:
   * - ctor at 0x00885530 (FUN_00885530, alloc size 0x54)
   * - cleanup path at 0x008857A0 (FUN_008857A0)
   *
   * What it does:
   * Per-scenario loader entry tracked by CWldSessionLoaderImpl intrusive list.
   */
  struct SWldScenarioInfo : TDatListItem<SWldScenarioInfo, void>
  {
    msvc8::string mMapName;  // 0x08
    msvc8::string mGameMods; // 0x24
    union
    {
      bool mUnloadRequested; // 0x40
      bool mRequested;       // 0x40 (compat alias)
    };
    bool mLoaded;                    // 0x41
    std::uint16_t mLoadFlags{};      // 0x42
    SWldScenarioLoadTask* mLoadTask; // 0x44
    CWldMap* mWldMap;                // 0x48
    LuaPlus::LuaState* mState;       // 0x4C
    RRuleGameRules* mGameRules;      // 0x50

    /**
     * Address: 0x00885530 (FUN_00885530, ??0struct_ScenarioInfo@@QAE@@Z)
     *
     * What it does:
     * Initializes list links, lower-cases map name, copies game-mods, and clears runtime owners.
     */
    SWldScenarioInfo(const char* mapName, const msvc8::string& gameMods);

    /**
     * Address: 0x008857A0 (FUN_008857A0, sub_8857A0)
     *
     * What it does:
     * Releases owned runtime objects (rules/lua/map/load-task) and unlinks this node.
     */
    void ResetAndUnlink();
  };

  static_assert(sizeof(SWldScenarioInfo) == 0x54, "SWldScenarioInfo size must be 0x54");
  static_assert(offsetof(SWldScenarioInfo, mMapName) == 0x08, "SWldScenarioInfo::mMapName offset must be 0x08");
  static_assert(offsetof(SWldScenarioInfo, mGameMods) == 0x24, "SWldScenarioInfo::mGameMods offset must be 0x24");
  static_assert(
    offsetof(SWldScenarioInfo, mUnloadRequested) == 0x40, "SWldScenarioInfo::mUnloadRequested offset must be 0x40"
  );
  static_assert(offsetof(SWldScenarioInfo, mLoaded) == 0x41, "SWldScenarioInfo::mLoaded offset must be 0x41");
  static_assert(offsetof(SWldScenarioInfo, mLoadTask) == 0x44, "SWldScenarioInfo::mLoadTask offset must be 0x44");
  static_assert(offsetof(SWldScenarioInfo, mWldMap) == 0x48, "SWldScenarioInfo::mWldMap offset must be 0x48");
  static_assert(offsetof(SWldScenarioInfo, mState) == 0x4C, "SWldScenarioInfo::mState offset must be 0x4C");
  static_assert(offsetof(SWldScenarioInfo, mGameRules) == 0x50, "SWldScenarioInfo::mGameRules offset must be 0x50");

  // Compatibility aliases while names stabilize across recovery passes.
  using SGameData = SWldGameData;
  using SScenarioInfo = SWldScenarioInfo;
} // namespace moho
