#include "CWldSessionLoaderImpl.h"
#include "platform/X87Precision.h"

#include <atomic>
#include <cfloat>
#include <chrono>
#include <cstring>
#include <exception>
#include <new>
#include <optional>
#include <thread>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "lua/LuaObject.h"
#include "moho/console/CConCommand.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/ScriptChunkCache.h"
#include "moho/misc/ScrDebugHooks.h"
#include "moho/sim/CBackgroundTaskControl.h"
#include "moho/sim/CVFSImpl.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/misc/CZipFile.h"
#include "moho/sim/Sim.h"
#include "lua/LuaCrashDump.h"
#include "lua/LuaIncrementalGc.h"

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
    bool wld_LoadMapEarly = true;
    TConVar<bool> gTConVar_wld_LoadMapEarly(
      "wld_LoadMapEarly",
      "Load the map on a helper thread while the rules are built (1, the default), or after SessionInit.lua as the "
      "binary does (0). The same map either way.",
      &wld_LoadMapEarly
    );

    bool wld_StartSimEarly = true;
    TConVar<bool> gTConVar_wld_StartSimEarly(
      "wld_StartSimEarly",
      "With wld_LoadMapEarly, build the sim's Lua state as soon as the rules are built and start a single-player "
      "game's or a replay's sim then (1, the default), or build it after the session's copy of the rules and start "
      "the sim once the whole load is done, as the binary does (0). The same sim either way.",
      &wld_StartSimEarly
    );

    /// The scenario whose rules and map are ready for its sim (wld_StartSimEarly); one load runs at a time.
    std::atomic<const SWldScenarioInfo*> gEarlySimScenario{nullptr};

    /// Set while a load began before the app has its UI frames (WLD_HoldSessionScripts).
    std::atomic<bool> gSessionScriptsHeld{false};

    /// Set while a load began before the app has its graphics device (WLD_HoldDeviceUse), and the
    /// thread that holds it, which never waits for itself.
    std::atomic<bool> gDeviceUseHeld{false};
    std::atomic<std::thread::id> gDeviceUseHolder{};

    bool IsInterlockedLoadingEnabled()
    {
#if FAFRE_PLATFORM_WINDOWS
      const char* const cmdLine = GetCommandLineA();
      return cmdLine && std::strstr(cmdLine, "/interlocked") != nullptr;
#else
      return false;
#endif
    }

    /**
     * Null-guard head of 0x00412C70 (`func_UpdateLoadingProgress`). NOT a
     * separate binary function and deliberately carries no `Address:` block -
     * the binary has one function there, whose body is owned by
     * `SWldScenarioLoadControl::UpdateLoadingProgress` in
     * moho/sim/WldSessionInfo.cpp. The recovered source splits the `mHandle`
     * null test off from the locking body; this is the test.
     *
     * What it does:
     * Advances the loader's progress through its control handle. A load with no
     * control attached simply has nothing to report to. This is also the abort
     * point - the control throws `XBackgroundTaskAborted` when a stop has been
     * requested, which unwinds the worker out of the load.
     */
    void AdvanceLoadingProgress(
      CBackgroundTaskControl* const loadControl
    )
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
    void RunLuaInitFormSet(
      const char* const setName,
      LuaPlus::LuaState* const state
    )
    {
      if (CScrLuaInitFormSet* const set = SCR_FindLuaInitFormSet(setName); set != nullptr) {
        set->RunInits(state);
      }
    }

    bool gSessionKeepsBlueprints = true;

    /**
     * Steps 2 and 3 of the session load: the session's own Lua state, with the same two binding
     * sets the front end gets, in the same order: engine core bindings first, then user ones.
     */
    void CreateSessionLuaState(
      SWldScenarioInfo* const scenario,
      CBackgroundTaskControl* const loadControl
    )
    {
      {
        const std::string marker(" World Session Load 2", 21u);
        (void)marker;
      }

      auto* const createdState = new LuaPlus::LuaState(
        LuaPlus::LuaState::LIB_BASE, static_cast<int>(moho::lua_incremental::ELuaVmRole::SessionUi)
      );
      if (
        LuaPlus::LuaState* const previousState = scenario->mState;
        createdState != previousState && previousState != nullptr
      ) {
        delete previousState;
      }
      scenario->mState = createdState;
      lua::NameLuaVm(createdState->m_state, "Lobby"); // diagnostics label only

      {
        const std::string marker(" World Session Load 3", 21u);
        (void)marker;
      }

      RunLuaInitFormSet("Core", scenario->mState);
      RunLuaInitFormSet("User", scenario->mState);

      if (SCR_IsDebugWindowActive()) {
        lua_sethook(scenario->mState->m_state, DebugLuaHook, LUA_MASKLINE, 0);
      }
      AdvanceLoadingProgress(loadControl);
    }

    /**
     * Engine addition (`wld_LoadMapEarly`): the map load on a helper thread while the rules are
     * built. It reads only the map file and runs `/lua/TerrainTypes.lua` in a table of its own in
     * the session's Lua state, which nothing else uses until the rules are done, so the session's
     * state is created first and the load joins the helper before anything else uses that state.
     * An exception the helper throws (a cancelled load) is thrown again on the loader thread.
     */
    class EarlyMapLoad
    {
    public:
      EarlyMapLoad(
        SWldScenarioInfo* const scenario,
        CBackgroundTaskControl* const loadControl
      )
        : mMap(new CWldMap())
      {
        mThread = std::thread([this, scenario, loadControl] {
          gpg::SetThreadName(0xFFFFFFFFu, "Map load");
          platform::SetX87PrecisionControl(_PC_24); // as the loader thread, see WorldSessionUserLoad
          try {
            mLoaded = mMap->MapLoad(scenario->mMapName.c_str(), scenario->mState, false, *loadControl);
          } catch (...) {
            mError = std::current_exception();
          }
        });
      }

      ~EarlyMapLoad()
      {
        if (mThread.joinable()) {
          mThread.join();
        }
      }

      EarlyMapLoad(const EarlyMapLoad&) = delete;
      EarlyMapLoad& operator=(const EarlyMapLoad&) = delete;

      /** Waits for the helper; the map when it loaded, else null. */
      [[nodiscard]] CWldMap* Finish()
      {
        mThread.join();
        if (mError) {
          std::rethrow_exception(mError);
        }
        return mLoaded ? mMap.release() : nullptr;
      }

    private:
      fa::auto_ptr<CWldMap> mMap;
      std::thread mThread;
      std::exception_ptr mError;
      bool mLoaded = false;
    };

    /// The scenario takes the loaded map, dropping one it had.
    void AcceptMap(
      SWldScenarioInfo* const scenario,
      CWldMap* const acceptedMap
    )
    {
      if (CWldMap* const previousMap = scenario->mWldMap; acceptedMap != previousMap && previousMap != nullptr) {
        delete previousMap;
      }
      scenario->mWldMap = acceptedMap;
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
    void WorldSessionUserLoad(
      SWldScenarioInfo* const scenario,
      CBackgroundTaskControl* const loadControl
    )
    {
      if (scenario == nullptr) {
        return;
      }

      // Loader threads run with the same reduced x87 precision the sim uses, so
      // map geometry loaded here rounds identically to the way it is simulated.
      platform::SetX87PrecisionControl(_PC_24);
      gEarlySimScenario.store(nullptr, std::memory_order_release); // a scenario at a freed one's address is not ready

      // Engine addition: the load compiles each script and blueprint, which the script cache answers
      // when the source is unchanged. Its archives stay open through the load task's
      // CZipFileReadScope (SWldScenarioLoadControl::RunWorkerThread, res_ZipKeepOpen), and its hook
      // lookups come from lua_HookProbeCache's listings.
      const ScriptChunkCacheBatch scriptChunks;

      {
        const std::string marker(" World Session Load 1", 21u);
        (void)marker;
      }

      // Engine addition (wld_LoadMapEarly): the session's state first, and the map loading in it
      // on a helper thread while the rules are built.
      std::optional<EarlyMapLoad> earlyMap;
      if (wld_LoadMapEarly) {
        CreateSessionLuaState(scenario, loadControl);
        earlyMap.emplace(scenario, loadControl);
      }

      // Engine addition (RULE_SetKeepBetweenSessions): the last session's rules when the editor keeps them.
      RRuleGameRules* const createdRules = RULE_TakeOrCreate(scenario->mGameMods, loadControl);
      if (
        RRuleGameRules* const previousRules = scenario->mGameRules;
        createdRules != previousRules && previousRules != nullptr
      ) {
        delete previousRules;
      }
      scenario->mGameRules = createdRules;
      AdvanceLoadingProgress(loadControl);

      CWldMap* loadedEarly = nullptr;
      if (earlyMap) {
        loadedEarly = earlyMap->Finish();
      } else {
        CreateSessionLuaState(scenario, loadControl);
      }

      {
        const std::string marker(" World Session Load 4", 21u);
        (void)marker;
      }

      // Engine addition (wld_StartSimEarly): with the rules and the map in hand, the map is the
      // scenario's now and the sim's copy of the rules goes first, so a session can start its sim
      // (WLD_GetEarlySimInputs) while the session's copy and SessionInit.lua run here.
      const bool startSimEarly = wld_StartSimEarly && loadedEarly != nullptr;
      if (startSimEarly) {
        AcceptMap(scenario, loadedEarly);
        RULE_DeferScriptBlueprintRelease(scenario->mGameRules); // freed below, after the session's export
        SIM_PrepareLuaState(scenario->mGameRules);
        gEarlySimScenario.store(scenario, std::memory_order_release);
        SIM_FinishPreparingLuaState(); // the session's export below would take the rules' lock first
      }

      if (gSessionKeepsBlueprints) {
        const SCR_CopySharedTablesScope sharedTables;
        scenario->mGameRules->ExportToLuaState(scenario->mState);
      }
      // Engine addition: with the session's copy done (or skipped), the sim's own copy of the rules
      // starts on a helper thread, alongside SessionInit.lua and the map load below.
      if (!startSimEarly) {
        SIM_PrepareLuaState(scenario->mGameRules);
      }
      AdvanceLoadingProgress(loadControl);

      {
        const std::string marker(" World Session Load 5", 21u);
        (void)marker;
      }

      // Engine addition (wld_EarlyCommandLineSession): SessionInit.lua loads UserSync.lua, whose imports
      // call GetFrame(0). Without the UI frames it stops there, and the session has no OnSync and no world
      // view. A load begun before the frames waits for them here, and the map goes on loading.
      while (gSessionScriptsHeld.load(std::memory_order_acquire)) {
        AdvanceLoadingProgress(loadControl); // the abort point, for a game that quits while it waits
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }

      (void)SCR_LuaDoScript(scenario->mState, "/lua/SessionInit.lua", nullptr);
      AdvanceLoadingProgress(loadControl);

      {
        const std::string marker(" World Session Load 6", 21u);
        (void)marker;
      }

      if (startSimEarly) {
        RULE_ReleaseDeferredScriptBlueprints(scenario->mGameRules); // the session and the sim both have their copy
      } else {
        fa::auto_ptr<CWldMap> loadedMap(earlyMap ? loadedEarly : new CWldMap());
        if (
          earlyMap ? loadedEarly != nullptr
                   : loadedMap->MapLoad(scenario->mMapName.c_str(), scenario->mState, false, *loadControl)
        ) {
          AcceptMap(scenario, loadedMap.release());
        }
      }

      {
        const std::string marker(" World Session Load 7", 21u);
        (void)marker;
      }
    }

  } // namespace

  void WLD_SetSessionKeepsBlueprints(
    const bool keep
  ) noexcept
  {
    gSessionKeepsBlueprints = keep;
  }

  void WLD_HoldSessionScripts(
    const bool hold
  ) noexcept
  {
    gSessionScriptsHeld.store(hold, std::memory_order_release);
  }

  void WLD_HoldDeviceUse(
    const bool hold
  ) noexcept
  {
    gDeviceUseHolder.store(std::this_thread::get_id(), std::memory_order_relaxed);
    gDeviceUseHeld.store(hold, std::memory_order_release);
  }

  void WLD_WaitForDeviceUse() noexcept
  {
    while (gDeviceUseHeld.load(std::memory_order_acquire) &&
           gDeviceUseHolder.load(std::memory_order_relaxed) != std::this_thread::get_id()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
  }

  bool WLD_GetEarlySimInputs(
    const SWldScenarioInfo* const scenario,
    RRuleGameRules** const outRules,
    CWldMap** const outMap
  ) noexcept
  {
    if (scenario == nullptr || gEarlySimScenario.load(std::memory_order_acquire) != scenario) {
      return false;
    }
    *outRules = scenario->mGameRules;
    *outMap = scenario->mWldMap;
    return *outRules != nullptr && *outMap != nullptr;
  }

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
  SWldScenarioInfo* CWldSessionLoaderImpl::FindOrCreateScenarioInfo(
    const char* const mapName,
    const fa::string& gameMods
  )
  {
    const fa::string loweredMap = gpg::STR_ToLower(mapName ? mapName : "");

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
    const char* const mapName,
    fa::string* const gameMods,
    const bool setGameData
  )
  {
    SetCreated();

    const fa::string requestedMods = gameMods ? *gameMods : fa::string{};
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
  SWldScenarioInfo* CWldSessionLoaderImpl::CreateScenarioInfo(
    const char* const mapName,
    fa::string* const gameMods
  )
  {
    SetCreated();

    const fa::string requestedMods = gameMods ? *gameMods : fa::string{};
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
  SWldGameData* CWldSessionLoaderImpl::MoveGameData(
    SWldScenarioInfo* const source,
    SWldGameData* const outData
  )
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
  SWldGameData* CWldSessionLoaderImpl::LoadGameData(
    SWldGameData* const outData
  )
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
            const fa::string workerName = gpg::STR_Printf("Map loader %s", scenario->mMapName.c_str());
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

  // 0x00885630 used to live here as
  // ResetWldSessionLoaderSingletonToInterfaceVtable, placement-new-ing an
  // IWldSessionLoader over the singleton to "rebind the vtable lane". The
  // binary body is two instructions -- install the base vftable pointer,
  // return the object -- which is simply what MSVC emits for the abstract
  // base's constructor. It is now cited on IWldSessionLoader::IWldSessionLoader
  // in the header, where the derived loader's constructor invokes it. The
  // helper had no callers, and with the interface's virtuals correctly pure it
  // could not compile anyway: an abstract class cannot be constructed.
} // namespace moho
