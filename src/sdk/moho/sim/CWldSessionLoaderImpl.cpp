#include "CWldSessionLoaderImpl.h"

#include <cfloat>
#include <cstring>
#include <new>

#include "boost/thread.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "lua/LuaObject.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/misc/ScrDebugHooks.h"
#include "moho/sim/CBackgroundTaskControl.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/RRuleGameRules.h"

namespace moho
{
  /**
   * Address: 0x00885450 (FUN_00885450, ??1IWldSessionLoader@Moho@@QAE@@Z)
   *
   * What it does:
   * Base virtual destructor lane for world-session loader ownership.
   */
  IWldSessionLoader::~IWldSessionLoader() = default;

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
     * Address: 0x00412C70 (FUN_00412C70, func_UpdateLoadingProgress)
     *
     * What it does:
     * Advances the loader's progress through its control handle. A load with no
     * control attached simply has nothing to report to. This is also the abort
     * point - the control throws `XBackgroundTaskAborted` when a stop has been
     * requested, which unwinds the worker out of the load.
     */
    void AdvanceLoadingProgress(CBackgroundTaskControl* const loadControl)
    {
      if (loadControl != nullptr && loadControl->mHandle != nullptr) {
        loadControl->mHandle->UpdateLoadingProgress();
      }
    }

    /**
     * What it does:
     * Runs one named Lua init-form set against a state. The binary reaches
     * `scr_CoreInits` / `scr_UserInits` directly; the sets are registered by
     * name here, and a missing set means nothing was linked into it.
     */
    void RunLuaInitFormSet(const char* const setName, LuaPlus::LuaState* const state)
    {
      if (CScrLuaInitFormSet* const set = SCR_FindLuaInitFormSet(setName); set != nullptr) {
        set->RunInits(state);
      }
    }

    /**
     * Address: 0x00885DE0 (FUN_00885DE0, func_WorldSessionUserLoad)
     *
     * IDA signature:
     * void __usercall func_WorldSessionUserLoad(struct_ScenarioInfo *this@<ecx>,
     *                                           Moho::CWaitHandleSet **a2);
     *
     * What it does:
     * The scenario load worker - everything a skirmish needs before a session
     * can be built. On the loader's worker thread it builds the game rules from
     * the scenario's mod list, stands up a fresh Lua state and runs the core
     * and user init-form sets against it, exports the rules into that state,
     * runs `/lua/SessionInit.lua`, and finally loads the map. Each stage bumps
     * the loading-progress control, which is also the abort check: the control
     * throws `XBackgroundTaskAborted` out of here when the load is cancelled.
     *
     * This was an empty placeholder, so `SWldScenarioInfo` came back with null
     * rules, state and map. `WLD_DoLoading` reads exactly that to decide the
     * scenario failed, which is why a skirmish reported
     * "map %s failed.  aborting session." the moment the frame machine was
     * fixed enough to consult it.
     *
     * IDA types the second parameter `CWaitHandleSet**`; it is the
     * background-task control the worker threads through the load, which is the
     * same word seen without the one-pointer struct around it.
     */
    void WorldSessionUserLoad(SWldScenarioInfo* const scenario, CBackgroundTaskControl* const loadControl)
    {
      if (scenario == nullptr) {
        return;
      }

      // Loader threads run with the same reduced x87 precision the sim uses, so
      // map geometry loaded here rounds identically to the way it is simulated.
      (void)::_controlfp(_PC_24, _MCW_PC);

      {
        const std::string marker(" World Session Load 1", 21u);
        (void)marker;
      }

      RRuleGameRules* const createdRules = RRuleGameRules::Create(scenario->mGameMods, loadControl);
      if (RRuleGameRules* const previousRules = scenario->mGameRules;
          createdRules != previousRules && previousRules != nullptr) {
        delete previousRules;
      }
      scenario->mGameRules = createdRules;
      AdvanceLoadingProgress(loadControl);

      {
        const std::string marker(" World Session Load 2", 21u);
        (void)marker;
      }

      auto* const createdState = new LuaPlus::LuaState(LuaPlus::LuaState::LIB_BASE);
      if (LuaPlus::LuaState* const previousState = scenario->mState;
          createdState != previousState && previousState != nullptr) {
        delete previousState;
      }
      scenario->mState = createdState;

      {
        const std::string marker(" World Session Load 3", 21u);
        (void)marker;
      }

      // The session's Lua state gets the same two binding sets the front end
      // gets, in the same order: engine core bindings first, then user ones.
      RunLuaInitFormSet("Core", scenario->mState);
      RunLuaInitFormSet("User", scenario->mState);

      if (SCR_IsDebugWindowActive()) {
        lua_sethook(scenario->mState->m_state, DebugLuaHook, LUA_MASKLINE, 0);
      }
      AdvanceLoadingProgress(loadControl);

      {
        const std::string marker(" World Session Load 4", 21u);
        (void)marker;
      }

      scenario->mGameRules->ExportToLuaState(scenario->mState);
      AdvanceLoadingProgress(loadControl);

      {
        const std::string marker(" World Session Load 5", 21u);
        (void)marker;
      }

      (void)SCR_LuaDoScript(scenario->mState, "/lua/SessionInit.lua", nullptr);
      AdvanceLoadingProgress(loadControl);

      {
        const std::string marker(" World Session Load 6", 21u);
        (void)marker;
      }

      msvc8::auto_ptr<CWldMap> loadedMap(new CWldMap());
      if (loadedMap->MapLoad(scenario->mMapName.c_str(), scenario->mState, false, *loadControl)) {
        CWldMap* const acceptedMap = loadedMap.release();
        if (CWldMap* const previousMap = scenario->mWldMap;
            acceptedMap != previousMap && previousMap != nullptr) {
          delete previousMap;
        }
        scenario->mWldMap = acceptedMap;
      }

      {
        const std::string marker(" World Session Load 7", 21u);
        (void)marker;
      }
    }

    /**
     * Address: 0x00885640 (FUN_00885640, sub_885640)
     *
     * What it does:
     * Unlinks one intrusive list-item lane from its current neighbors and
     * re-initializes it as a self-linked sentinel node.
     */
    [[nodiscard]] TDatListItem<SWldScenarioInfo, void>* ResetScenarioListHead(
      TDatListItem<SWldScenarioInfo, void>& listItem
    ) noexcept
    {
      listItem.mNext->mPrev = listItem.mPrev;
      listItem.mPrev->mNext = listItem.mNext;
      listItem.mPrev = &listItem;
      listItem.mNext = &listItem;
      return &listItem;
    }
  } // namespace

  /**
   * Address: 0x008855B0 (FUN_008855B0) init path (FUN_008855B0, func_GetWldSessionLoader)
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
    (void)ResetScenarioListHead(mScenarioHead);
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
    // When no scenario has populated the game data yet, release any handles the
    // caller was already carrying in `outData` before zeroing the slot. The
    // binary SEH path (address 0x00885A20) performs the same teardown order.
    if (mGameData == nullptr && outData != nullptr) {
      ReleaseWldGameDataHandles(outData);
    }

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
              // The binary falls straight through into the completed case, so the
              // assert fires once and the scenario is then marked loaded. That
              // mark is what stops Update reconsidering it: with a `break` here
              // the state never moves and a load that aborted reopens the assert
              // dialog on every single frame for the rest of the session.
              gpg::HandleAssertFailure(
                "Reached the supposably unreachable.", 320, "c:\\work\\rts\\main\\code\\src\\user\\SessionLoader.cpp"
              );
              [[fallthrough]];
            case EWldScenarioLoadControlState::kCompleted:
              scenario->mLoaded = true;
              break;
            default:
              break;
            }
          }
        } else {
          // No load control on this path, so nothing is watching progress.
          CBackgroundTaskControl loadControl{nullptr};
          WorldSessionUserLoad(scenario, &loadControl);
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
    * Alias of FUN_008855B0 (non-canonical helper lane).
   */
  CWldSessionLoaderImpl* GetWldSessionLoader()
  {
    static CWldSessionLoaderImpl sWldSessionLoader{};
    return &sWldSessionLoader;
  }

  /**
   * Address: 0x00885630 (FUN_00885630, sub_885630)
   *
   * What it does:
   * Rebinds the loader singleton storage to base `IWldSessionLoader` vtable
   * lane and returns the same singleton-address as interface pointer.
   */
  [[maybe_unused]] IWldSessionLoader* ResetWldSessionLoaderSingletonToInterfaceVtable() noexcept
  {
    IWldSessionLoader* const loader = static_cast<IWldSessionLoader*>(GetWldSessionLoader());
    return ::new (loader) IWldSessionLoader();
  }
} // namespace moho
