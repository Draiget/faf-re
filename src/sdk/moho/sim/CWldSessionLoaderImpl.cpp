#include "CWldSessionLoaderImpl.h"

#include <cstring>

#include "boost/thread.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "lua/LuaObject.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/RRuleGameRules.h"

namespace moho
{
  namespace
  {
    bool IsInterlockedLoadingEnabled()
    {
#if defined(_WIN32)
      const char* const cmdLine = GetCommandLineA();
      return cmdLine && std::strstr(cmdLine, "/interlocked") != nullptr;
#else
      return false;
#endif
    }

    /**
     * Address: 0x00885DE0 (FUN_00885DE0, func_WorldSessionUserLoad)
     *
     * What it does:
     * Scenario content loading worker callback. Full source lift is still pending;
     * this placeholder keeps typed loader scheduling/control semantics intact.
     */
    void WorldSessionUserLoad(SWldScenarioInfo* const scenario, CWaitHandleSet** const /*waitSet*/)
    {
      if (!scenario) {
        return;
      }
    }
  } // namespace

  /**
   * Address: 0x008855B0 init path (FUN_008855B0, func_GetWldSessionLoader)
   */
  CWldSessionLoaderImpl::CWldSessionLoaderImpl()
    : mCreated(false)
    , mLoaded(false)
    , mFinalized(false)
    , mPad07(0)
    , mScenarioHead{}
    , mGameData(nullptr)
    , mActiveLoadScenario(nullptr)
  {}

  /**
   * Address: 0x00885660 (FUN_00885660, ??1CWldSessionLoaderImpl@Moho@@QAE@@Z_0)
   */
  CWldSessionLoaderImpl::~CWldSessionLoaderImpl()
  {
    Finalize();
    mScenarioHead.ListUnlink();
  }

  /**
   * Address: 0x00885890 (FUN_00885890)
   */
  void CWldSessionLoaderImpl::SetCreated()
  {
    mLoaded = false;
    mCreated = true;
  }

  /**
   * Address: 0x00886200 (FUN_00886200, func_GetScenarioInfo)
   */
  SWldScenarioInfo*
  CWldSessionLoaderImpl::FindOrCreateScenarioInfo(const char* const mapName, const msvc8::string& gameMods)
  {
    const msvc8::string loweredMap = gpg::STR_ToLower(mapName ? mapName : "");

    for (auto* node = mScenarioHead.mNext; node != &mScenarioHead; node = node->mNext) {
      auto* const scenario = static_cast<SWldScenarioInfo*>(node);
      if (scenario->mMapName == loweredMap && scenario->mGameMods == gameMods && !scenario->mUnloadRequested) {
        return scenario;
      }
    }

    auto* const created = new SWldScenarioInfo(loweredMap.c_str(), gameMods);
    created->ListLinkAfter(&mScenarioHead);
    return created;
  }

  /**
   * Address: 0x008858A0 (FUN_008858A0)
   */
  SWldScenarioInfo* CWldSessionLoaderImpl::GetScenarioInfo(
    const char* const mapName, msvc8::string* const gameMods, const bool setGameData
  )
  {
    SetCreated();

    const msvc8::string requestedMods = gameMods ? *gameMods : msvc8::string{};
    SWldScenarioInfo* result = FindOrCreateScenarioInfo(mapName, requestedMods);
    result->ListLinkAfter(&mScenarioHead);

    if (setGameData) {
      mGameData = result;
      return result;
    }

    if (mGameData) {
      mGameData->ListLinkAfter(&mScenarioHead);
      result = mGameData;
    }

    return result;
  }

  /**
   * Address: 0x00885920 (FUN_00885920)
   */
  SWldScenarioInfo* CWldSessionLoaderImpl::CreateScenarioInfo(const char* const mapName, msvc8::string* const gameMods)
  {
    SetCreated();

    const msvc8::string requestedMods = gameMods ? *gameMods : msvc8::string{};
    SWldScenarioInfo* const scenario = FindOrCreateScenarioInfo(mapName, requestedMods);
    mGameData = scenario;
    scenario->ListLinkAfter(&mScenarioHead);
    mLoaded = true;
    return scenario;
  }

  /**
   * Address: 0x00885970 (FUN_00885970)
   */
  bool CWldSessionLoaderImpl::IsLoaded()
  {
    if (!mCreated || !mGameData || !mGameData->mLoaded) {
      return false;
    }

    auto* const head = &mScenarioHead;
    auto* node = head->mNext;
    if (node == head) {
      return true;
    }

    while (mGameData == static_cast<SWldScenarioInfo*>(node)) {
      node = node->mNext;
      if (node == head) {
        return true;
      }
    }

    return false;
  }

  /**
   * Address: 0x00886170 (FUN_00886170, func_MoveGameData)
   */
  SWldGameData* CWldSessionLoaderImpl::MoveGameData(SWldScenarioInfo* const source, SWldGameData* const outData)
  {
    if (!outData) {
      return nullptr;
    }

    outData->mState = nullptr;
    outData->mGameRules = nullptr;
    outData->mWldMap = nullptr;

    if (!source) {
      return outData;
    }

    LuaPlus::LuaState* const movedState = source->mState;
    source->mState = nullptr;
    if (outData->mState && outData->mState != movedState) {
      delete outData->mState;
    }
    outData->mState = movedState;

    RRuleGameRules* const movedRules = source->mGameRules;
    source->mGameRules = nullptr;
    if (outData->mGameRules && outData->mGameRules != movedRules) {
      delete outData->mGameRules;
    }
    outData->mGameRules = movedRules;

    CWldMap* const movedMap = source->mWldMap;
    source->mWldMap = nullptr;
    if (outData->mWldMap && outData->mWldMap != movedMap) {
      delete outData->mWldMap;
    }
    outData->mWldMap = movedMap;
    return outData;
  }

  /**
   * Address: 0x008859B0 (FUN_008859B0)
   */
  SWldGameData* CWldSessionLoaderImpl::LoadGameData(SWldGameData* const outData)
  {
    SWldGameData* const result = MoveGameData(mGameData, outData);
    if (mGameData) {
      mGameData->ResetAndUnlink();
      delete mGameData;
    }

    mGameData = nullptr;
    mCreated = false;
    return result;
  }

  /**
   * Address: 0x00885AD0 (FUN_00885AD0)
   */
  void CWldSessionLoaderImpl::Update()
  {
    if (!mCreated) {
      for (auto* node = mScenarioHead.mNext; node != &mScenarioHead;) {
        auto* const scenario = static_cast<SWldScenarioInfo*>(node);
        node = node->mNext;

        bool shouldDelete = (scenario->mLoadTask == nullptr);
        if (!shouldDelete) {
          scenario->mUnloadRequested = true;

          SWldScenarioLoadControl* const control = scenario->mLoadTask->mControl;
          if (!control) {
            shouldDelete = true;
          } else {
            control->RequestStop();
            shouldDelete = control->mState == EWldScenarioLoadControlState::kReadyForDestroy;
          }
        }

        if (!shouldDelete) {
          continue;
        }

        scenario->ResetAndUnlink();
        delete scenario;
        if (mActiveLoadScenario == scenario) {
          mActiveLoadScenario = nullptr;
        }
        if (mGameData == scenario) {
          mGameData = nullptr;
        }
      }
      return;
    }

    if (mActiveLoadScenario && mActiveLoadScenario->mLoadTask && mActiveLoadScenario->mLoadTask->mControl) {
      if (mActiveLoadScenario->mLoadTask->mControl->mState != EWldScenarioLoadControlState::kRunning) {
        mActiveLoadScenario = nullptr;
      }
    }

    int scenarioCount = 0;
    bool canStartLoad = true;

    for (auto* node = mScenarioHead.mNext; node != &mScenarioHead;) {
      auto* const scenario = static_cast<SWldScenarioInfo*>(node);
      node = node->mNext;

      if (scenario != mGameData && (scenarioCount >= 3 || mLoaded)) {
        scenario->mUnloadRequested = true;
      }

      if (scenario->mUnloadRequested) {
        if (scenario->mLoadTask && scenario->mLoadTask->mControl) {
          scenario->mLoadTask->mControl->RequestStop();
          if (scenario->mLoadTask->mControl->mState == EWldScenarioLoadControlState::kReadyForDestroy) {
            scenario->ResetAndUnlink();
            delete scenario;
            if (scenario == mActiveLoadScenario) {
              mActiveLoadScenario = nullptr;
            }
          }
        } else {
          scenario->ResetAndUnlink();
          delete scenario;
          if (scenario == mActiveLoadScenario) {
            mActiveLoadScenario = nullptr;
          }
        }
        continue;
      }

      if (canStartLoad && !scenario->mLoaded) {
        if (mActiveLoadScenario && mActiveLoadScenario != scenario) {
          if (mActiveLoadScenario->mLoadTask && mActiveLoadScenario->mLoadTask->mControl) {
            mActiveLoadScenario->mLoadTask->mControl->RequestPause();
          }
          return;
        }

        if (!IsInterlockedLoadingEnabled()) {
          if (!scenario->mLoadTask) {
            const msvc8::string workerName = gpg::STR_Printf("Map loader %s", scenario->mMapName.c_str());
            SWldScenarioLoadTask* const createdTask =
              SWldScenarioLoadTask::Create(workerName.c_str(), scenario, &WorldSessionUserLoad);
            SWldScenarioLoadTask::AssignWithRelease(scenario->mLoadTask, createdTask);
          }

          if (scenario->mLoadTask && scenario->mLoadTask->mControl) {
            SWldScenarioLoadControl* const control = scenario->mLoadTask->mControl;
            switch (control->mState) {
            case EWldScenarioLoadControlState::kNotStarted:
            case EWldScenarioLoadControlState::kPaused:
              mActiveLoadScenario = scenario;
              control->StartOrResume(*scenario->mLoadTask);
              [[fallthrough]];
            case EWldScenarioLoadControlState::kRunning:
              ++scenarioCount;
              canStartLoad = false;
              continue;
            case EWldScenarioLoadControlState::kReadyForDestroy:
              gpg::HandleAssertFailure(
                "Reached the supposably unreachable.", 320, "c:\\work\\rts\\main\\code\\src\\user\\SessionLoader.cpp"
              );
              break;
            case EWldScenarioLoadControlState::kCompleted:
              scenario->mLoaded = true;
              break;
            default:
              break;
            }
          }
        } else {
          CWaitHandleSet* waitSet = nullptr;
          WorldSessionUserLoad(scenario, &waitSet);
          scenario->mLoaded = true;
        }
      }

      ++scenarioCount;
    }
  }

  /**
   * Address: 0x008856E0 (FUN_008856E0)
   */
  void CWldSessionLoaderImpl::Finalize()
  {
    if (mFinalized) {
      return;
    }

    for (auto* node = mScenarioHead.mNext; node != &mScenarioHead; node = node->mNext) {
      auto* const scenario = static_cast<SWldScenarioInfo*>(node);
      if (!scenario->mLoadTask || !scenario->mLoadTask->mControl) {
        continue;
      }

      scenario->mLoadTask->mControl->RequestStop();
    }

    while (mScenarioHead.mNext != &mScenarioHead) {
      auto* const scenario = static_cast<SWldScenarioInfo*>(mScenarioHead.mNext);

      if (scenario->mLoadTask && scenario->mLoadTask->mControl) {
        scenario->mLoadTask->mControl->StartOrResume(*scenario->mLoadTask);
      }
      if (scenario->mLoadTask && scenario->mLoadTask->mWorkerThread) {
        scenario->mLoadTask->mWorkerThread->join();
        delete scenario->mLoadTask->mWorkerThread;
        scenario->mLoadTask->mWorkerThread = nullptr;
      }

      if (scenario == mActiveLoadScenario) {
        mActiveLoadScenario = nullptr;
      }
      if (scenario == mGameData) {
        mGameData = nullptr;
      }

      scenario->ResetAndUnlink();
      delete scenario;
    }

    mFinalized = true;
  }

  /**
   * Address: 0x008855B0 (FUN_008855B0, func_GetWldSessionLoader)
   */
  CWldSessionLoaderImpl* GetWldSessionLoader()
  {
    static CWldSessionLoaderImpl sWldSessionLoader{};
    return &sWldSessionLoader;
  }
} // namespace moho
