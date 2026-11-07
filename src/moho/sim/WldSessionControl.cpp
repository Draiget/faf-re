#include <mutex>

#include "moho/net/CClientManagerImpl.h"
#include "moho/net/CRejoinFeed.h"
#include "moho/sim/CWldSessionPrivate.h"

#include <chrono>

#include "moho/render/GpuPathSettings.h"
#include "moho/render/SkyDome.h"
#include "moho/sim/CWldSessionLoaderImpl.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/STIMap.h"

namespace moho
{
namespace
{
    [[nodiscard]] IWldUIProvider* ResolveWldUIProvider() noexcept
    {
      if (sWldUIProvider == nullptr) {
        return nullptr;
      }

      return dynamic_cast<IWldUIProvider*>(sWldUIProvider);
    }
}


    // gActiveWldSession: moho/sim/WldSessionState.cpp (WldSessionState.h).

    /**
     * The world session's simulation driver (`sSimDriver`, 0x010C4F50), a
     * `boost::scoped_ptr`. Its out-of-line members are LTCG copies specialised
     * on this global, none of them referenced:
     * Address: 0x0088E8B0 (FUN_0088E8B0, `reset`: new value stored first, old
     *   one deleted through vtable slot 0, no self-test)
     * Address: 0x0088E8F0 (FUN_0088E8F0, `operator unspecified_bool_type`: 0 when
     *   set, -1 - the null data-member pointer - when empty)
     * Address: 0x0088E9F0 (FUN_0088E9F0, `swap`: three plain stores)
     * Address: 0x00C07EB0 (FUN_00C07EB0, atexit destructor: delete through slot 0)
     * `get` is WLD_GetDriver (0x0088D330); 0x0088E8D0 and 0x0088E8E0 are its ICF
     * twins.
     */
    boost::scoped_ptr<ISTIDriver> sSimDriver;
namespace
{

    // Engine addition (replay timeline): a new sim on its way behind the running session.
    enum class EReplaySimSwap
    {
      None,
      WaitingForSync,
      WaitingForReady,
      Holding,
    };
    EReplaySimSwap sReplaySimSwap = EReplaySimSwap::None;
    // The new sim's beats until the move's target: the session and what it draws stay as they are.
    std::vector<SSyncData*> sReplayHeldBeats;
    int sReplaySwapRate = 0;
    std::int32_t sReplaySwapFocus = -1;
    std::chrono::steady_clock::time_point sReplaySwapStart{};

    // ---- Crash-report "Sim" section (new diagnostics functionality) ----
    //
    // Everything a crash report reader asks first: what map, live or replay,
    // which beat, and whether the sim had already desynced. Reads only the
    // two globals above plus Sim::sInstance; guarded so a teardown-time crash
    // still prints the rest.
    void WriteSimCrashSectionAdapter(std::FILE* const sink, const gpg::diag::CrashSectionInfo& info)
    {
      (void)info;
      const auto line = [sink](const char* const format, ...) {
        va_list args;
        va_start(args, format);
        (void)std::vfprintf(sink, format, args);
        va_end(args);
        (void)std::fputc('\n', sink);
        (void)std::fflush(sink);
      };

      if (CWldSession* const session = gActiveWldSession) {
        line("session   : active");
        line("map       : %s", session->mMapName.c_str());
        line("replay    : %s", session->IsReplay ? "yes" : "no");
      } else {
        line("session   : none (menu/lobby/teardown)");
      }

      if (const auto* const simDriver = dynamic_cast<const CSimDriver*>(sSimDriver.get())) {
        line("driver    : state=%d dispatchBeat=%d nextIssueBeat=%d",
             static_cast<int>(simDriver->DiagDriverState()), simDriver->DiagDispatchBeat(),
             simDriver->DiagNextIssueBeat());
      } else if (sSimDriver.get() != nullptr) {
        line("driver    : not the lockstep driver (loopback or a server session's)");
      } else {
        line("driver    : none");
      }

      if (Sim* const sim = Sim::sInstance) {
        line("sim       : beat=%u tick=%u gameEnded=%d gameOver=%d", sim->mCurBeat, sim->mCurTick,
             sim->mGameEnded ? 1 : 0, sim->mGameOver ? 1 : 0);
        line("desync    : %s (%u record(s))", sim->mIsDesyncFree ? "free" : "DESYNCED",
             static_cast<unsigned>(sim->mDesyncs.size()));
      } else {
        line("sim       : none");
      }
    }

    const bool sSimCrashSectionRegistered =
      (gpg::diag::AddCrashSection("Sim", &WriteSimCrashSectionAdapter, /*priority=*/100), true);

    /**
     * The next session's launch description (0x010C4F58), a `std::auto_ptr`.
     * Address: 0x0088E900 (FUN_0088E900, its `operator=(auto_ptr&)` specialised
     *   on this global: release the source, delete the old value when it
     *   differs, return the global) - WLD_BeginSession's assignment.
     */
    fa::auto_ptr<SWldSessionInfo> gPendingWldSessionInfo;

    [[nodiscard]] std::intptr_t DispatchSessionListenerAttachAndReturnLastResult(
      WldTeardownCallbackVector* const callbacks
    )
    {
      if (callbacks == nullptr) {
        return 0;
      }

      // The binary's return register still holds `_Myfirst` when the callback
      // list is empty, and otherwise whatever the last slot-0 call left in eax.
      // The attach hook is `void`, so the seed is the only defined value here
      // and no caller reads the result for anything but its truthiness.
      std::intptr_t result = reinterpret_cast<std::intptr_t>(callbacks->data());

      const std::size_t callbackCount = callbacks->size();
      for (std::size_t i = 0; i < callbackCount; ++i) {
        ISessionListener* const listener = (*callbacks)[i];
        listener->AttachToSessionListenerLane(gActiveWldSession);
      }

      return result;
    }

    /**
     * Address: 0x008698B0 (FUN_008698B0, func_DoTeardownCallbacks)
     *
     * What it does:
     * Detaches every registered session listener from the current active world
     * session. This is the teardown half of the pair: the binary dispatches
     * `(*(*v4 + 4))(v4, Moho::sWldSession)` - **vtable slot 1**,
     * `ISessionListener::DetachFromSessionListenerLane` - where the
     * creation-time pass at FUN_00869870 dispatches slot 0.
     */
    [[nodiscard]] std::intptr_t DoTeardownCallbacks(WldTeardownCallbackVector* const callbacks)
    {
      if (callbacks == nullptr) {
        return 0;
      }

      std::intptr_t result = reinterpret_cast<std::intptr_t>(callbacks->data());

      const std::size_t callbackCount = callbacks->size();
      for (std::size_t i = 0; i < callbackCount; ++i) {
        ISessionListener* const listener = (*callbacks)[i];
        listener->DetachFromSessionListenerLane(gActiveWldSession);
      }

      return result;
    }
    /**
     * Address: 0x0088BEE0 (FUN_0088BEE0, Moho::func_DoPreload)
     *
     * IDA signature:
     * void func_DoPreload();
     *
     * What it does:
     * Drives the world-session `Preload` frame action: tears down any active
     * world-session runtime, saves user preferences, restarts the in-game UI
     * lane on the active Lua state, opens the world UI provider's loading
     * dialog, asks the session loader to prefetch the pending session's
     * scenario, installs the no-op `IClientMgrUIInterface` bootstrap on the
     * pending session's client manager, and transitions the world-frame
     * dispatch lane to `Loading`. The bracketing ` DoPreload 1` / ` DoPreload
     * 2` `std::string` temporaries match the binary's profiler-marker shape
     * (built and immediately destroyed with no consumer in the retail body).
     */
    void WLD_DoPreload()
    {
      // ` DoPreload 1` bracket marker: the retail binary constructs one
      // 12-byte `std::string` literal here purely as a profiler/log marker
      // and discards it immediately. Preserved 1:1 to keep observable
      // string-allocation side effects (operator new/delete pair when the
      // SSO threshold would be exceeded) identical to the binary.
      {
        const std::string marker(" DoPreload 1", 12u);
        (void)marker;
      }

      WLD_Teardown();
      USER_SavePreferences();

      LuaPlus::LuaState* const state = USER_GetLuaState();
      (void)UI_StartGameUI(state);

      if (IWldUIProvider* const wldUIProvider = ResolveWldUIProvider(); wldUIProvider != nullptr) {
        wldUIProvider->StartLoadingDialog();
      }

      CWldSessionLoaderImpl* const loader = GetWldSessionLoader();
      SWldSessionInfo* const pendingSession = gPendingWldSessionInfo.get();
      if (loader != nullptr && pendingSession != nullptr) {
        LaunchInfoBase* const launchInfo = pendingSession->mLaunchInfo.get();
        if (launchInfo != nullptr) {
          // Slot 2 of the loader's vtable (0x0088BF71 `call [edx+8]` with the
          // map name and &mGameMods pushed): `CreateScenarioInfo`, which is
          // 0x00885920 in ??_7CWldSessionLoaderImpl (0x00E49FC4) and returns
          // with `ret 8`. It marks the load as requested (`mLoaded`), so
          // `Update` unloads any other prefetched scenario. This called
          // `GetScenarioInfo` (slot 1, the Lua PrefetchSession path) instead,
          // which clears that mark: a launch whose mods differ from the last
          // prefetch (the autolobby prefetches with none) kept the stale
          // scenario, `IsLoaded` never became true, and the client sat in the
          // loading screen while the others waited for it.
          (void)loader->CreateScenarioInfo(pendingSession->mMapName.raw_data_unsafe(), &launchInfo->mGameMods);
        }
      }

      if (pendingSession != nullptr && pendingSession->mClientManager != nullptr) {
        pendingSession->mClientManager->SetUIInterface(&sCWldUiInterface);
      }

      gWldFrameAction = EWldFrameAction::Loading;
      WLD_HoldSessionScripts(false); // engine addition (wld_EarlyCommandLineSession): the UI frames exist now

      // ` DoPreload 2` bracket marker (paired with the opening marker
      // above): same profiler/log-string discard pattern.
      {
        const std::string marker(" DoPreload 2", 12u);
        (void)marker;
      }
    }

    /**
     * Engine addition: the issue-thread pacing for a new session's driver. A replay gets the
     * replay lead; a session with exactly one client - the local human - and no network connector
     * (a single-player skirmish or campaign) gets the local lead; anything with a connector or more
     * clients (players or observers of a live game) keeps the original pacing.
     */
    [[nodiscard]] ESimSessionPacing SelectSessionPacing(
      const bool isReplay, const bool isMultiplayer, IClientManager* const clientManager
    )
    {
      if (isReplay) {
        return ESimSessionPacing::Replay;
      }
      if (isMultiplayer || clientManager == nullptr || clientManager->GetConnector() != nullptr ||
          clientManager->NumberOfClients() != 1u || clientManager->GetLocalClient() == nullptr) {
        return ESimSessionPacing::Network;
      }
      return ESimSessionPacing::Local;
    }

    [[nodiscard]] ESimSessionPacing SelectSessionPacing(const CWldSession& session, IClientManager* const clientManager)
    {
      return SelectSessionPacing(session.IsReplay != 0, session.IsMultiplayer != 0, clientManager);
    }

    /**
     * Engine addition (`wld_StartSimEarly`): a single-player game's or a replay's sim driver, created
     * as soon as the load has the rules and the map (`WLD_GetEarlySimInputs`) rather than once the
     * whole load is done, for `WLD_DoLoading` to hand to the session it builds then. The driver gets
     * what it gets there, in the same order: the game version, the replay sink, the launch info's
     * rules, map and language, the single-player clone of the launch info (made before the sim takes
     * the map out of it), and the props.
     */
    struct SEarlySimStart
    {
      ISTIDriver* driver = nullptr;
      boost::shared_ptr<LaunchInfoBase> launchClone;
      std::string language; // the launch info's, checked against the session's once that exists
    };
    SEarlySimStart sEarlySim;

    /** Shuts down and deletes a driver started early that no session took (a load given up). */
    void DropEarlySim()
    {
      if (ISTIDriver* const driver = sEarlySim.driver; driver != nullptr) {
        driver->ShutDown();
        while (driver->HasSyncData()) {
          SSyncData* syncData = nullptr;
          driver->GetSyncData(syncData);
          (void)fa::auto_ptr<SSyncData>(syncData);
        }
        delete driver;
      }
      sEarlySim = SEarlySimStart{};
    }

    /**
     * Starts the sim of the session `WLD_DoLoading` waits for once its load has the rules and the
     * map, when the session has no network: a single-player game or a replay. Otherwise, or when the
     * user interface has no language to give it, the sim starts when the load is done, as before.
     * The language is the user interface's `__language`: the session's comes from the same
     * userInit.lua and preferences in its SessionInit.lua, which is still running.
     */
    void StartSimEarly(SWldSessionInfo* const sessionInfo, CWldSessionLoaderImpl* const loader)
    {
      RRuleGameRules* rules = nullptr;
      CWldMap* map = nullptr;
      if (sEarlySim.driver != nullptr || sessionInfo == nullptr || sessionInfo->mLaunchInfo.get() == nullptr ||
          !WLD_GetEarlySimInputs(loader->mGameData, &rules, &map) || map->mTerrainRes == nullptr ||
          SelectSessionPacing(sessionInfo->mIsReplay, sessionInfo->mIsMultiplayer, sessionInfo->mClientManager) ==
            ESimSessionPacing::Network) {
        return;
      }
      const LuaPlus::LuaObject userLanguage = USER_GetLuaState()->GetGlobal("__language");
      const char* const language = userLanguage.ToString();
      if (language == nullptr) {
        return;
      }
      sEarlySim.language = language;

      FAF_BeginSession(sessionInfo->mIsReplay);
      fa::auto_ptr<gpg::Stream> replayStream(nullptr);
      if (sessionInfo->mIsBeingRecorded) {
        const fa::string defaultReplayName = Loc(USER_GetLuaState(), "<LOC Engine0030>LastGame");
        replayStream = VCR_CreateReplay(sessionInfo, defaultReplayName.c_str());
        if (replayStream.get() == nullptr) {
          sessionInfo->mIsBeingRecorded = false;
        }
      }

      STIMap* const launchMap = new STIMap(map->mTerrainRes->mMap);
      LaunchInfoBase* const launchInfo = sessionInfo->mLaunchInfo.get();
      launchInfo->mGameRules = rules;
      if (launchMap != launchInfo->mMap && launchInfo->mMap != nullptr) {
        delete launchInfo->mMap;
      }
      launchInfo->mMap = launchMap;
      launchInfo->mLanguage.assign_owned(language);

      if (!sessionInfo->mIsMultiplayer && !sessionInfo->mIsReplay) {
        boost::SharedPtrRaw<void> createdLaunchInfo{};
        launchInfo->Create(createdLaunchInfo);
        boost::SharedPtrRaw<LaunchInfoBase> createdTyped{};
        createdTyped.px = static_cast<LaunchInfoBase*>(createdLaunchInfo.px);
        createdTyped.pi = createdLaunchInfo.pi;
        sEarlySim.launchClone = boost::SharedPtrFromRawRetained(createdTyped);
        createdLaunchInfo.release();
      }

      if (LaunchInfoNew* const newLaunchInfo = launchInfo->GetNew(); newLaunchInfo != nullptr) {
        newLaunchInfo->mProps = map->mProps;
      }

      IClientManager* const clientManager = sessionInfo->mClientManager;
      sessionInfo->mClientManager = nullptr;
      // Engine addition (issue #275), as WLD_DoLoading: does nothing unless a save came with this
      // client's seat (a rejoin is a network session, which never starts early).
      REJOIN_PrepareRestore(*sessionInfo);
      REPLAY_PrepareSession(*sessionInfo); // engine addition (replay timeline)
      SIM_SetSessionPacing(SelectSessionPacing(sessionInfo->mIsReplay, sessionInfo->mIsMultiplayer, clientManager));
      ISTIDriver* driver = SIM_CreateDriver(
        static_cast<CClientManagerImpl*>(clientManager),
        replayStream.release(),
        sessionInfo->mLaunchInfo,
        sessionInfo->mSourceId
      );
#if FAF_SERVER_MODE
      driver = faf::remote::client::WrapForLoopback(
        driver, *rules, launchMap->GetBounds3D(), sessionInfo->mIsMultiplayer
      );
#endif
      sEarlySim.driver = driver;
    }

    /**
     * Engine addition (issue #275): what the screen of a client taking its seat back
     * says this frame. Outside a rejoin there is no feed and it does nothing. Past the
     * loading screen, the "loading" stage is only the first beat waiting for the sim,
     * and it needs the cover as much as catching up does.
     */
    void UpdateRejoinScreen(IClientManager* const clientManager, const bool loadingScreenUp)
    {
      auto* const manager = static_cast<CClientManagerImpl*>(clientManager);
      if (manager == nullptr || manager->mRejoinFeed == nullptr) {
        return;
      }

      SRejoinStatus status{};
      {
        std::scoped_lock lock(manager->mLock);
        status = manager->mRejoinFeed->Status();
      }
      if (status.stage == ERejoinStage::Loading) {
        UI_UpdateRejoinScreen(loadingScreenUp ? "loading" : "catchingUp", loadingScreenUp ? -1.0f : 0.0f);
      } else if (status.stage == ERejoinStage::CatchingUp) {
        UI_UpdateRejoinScreen("catchingUp", status.progress);
      } else {
        UI_UpdateRejoinScreen("", -1.0f);
      }
    }

    /**
     * Address: 0x0088C000 (FUN_0088C000, func_DoLoading)
     *
     * IDA signature:
     * void __cdecl func_DoLoading(bool *outContinue);
     *
     * What it does:
     * Drives the world-session `Loading` frame action. Every frame it beats the
     * client manager; once the loader reports the scenario in hand it takes
     * ownership of the loaded Lua state / game rules / map, builds the session,
     * gives the launch info its own copy of the playable map and the player's
     * language, opens the replay sink when the session is recorded, creates the
     * sim driver, and hands the frame machine on to `Initialize`.
     *
     * This transition is the whole point of the function. Until it was
     * recovered, `Loading` fell through to `CreateSession` - a state that in
     * the binary only exists for an explicit restart request - and
     * `WLD_CreateSessionInfo` bounced straight back to `Preload`, so a skirmish
     * cycled Preload -> Loading -> CreateSession forever, restarting the
     * in-game UI and reopening the loading movie on every lap.
     *
     * The bracketing ` DoLoading N` `std::string` temporaries are the binary's
     * profiler markers: built and immediately discarded, kept for the identical
     * allocation side effects.
     */
    void WLD_DoLoading(bool* const outContinue)
    {
      {
        const std::string marker(" DoLoading 1", 12u);
        (void)marker;
      }

      SWldSessionInfo* const sessionInfo = gPendingWldSessionInfo.get();
      if (sessionInfo != nullptr && sessionInfo->mClientManager != nullptr) {
        sessionInfo->mClientManager->DoBeat();
        UpdateRejoinScreen(sessionInfo->mClientManager, true);
      }

      CWldSessionLoaderImpl* const loader = GetWldSessionLoader();
      if (loader == nullptr) {
        return;
      }
      if (!loader->IsLoaded()) {
        StartSimEarly(sessionInfo, loader); // engine addition (wld_StartSimEarly)
        return;
      }

      {
        const std::string marker(" DoLoading 2", 12u);
        (void)marker;
      }

      SWldGameData gameData{};
      (void)loader->LoadGameData(&gameData);

      if (gameData.mGameRules == nullptr) {
        DropEarlySim();
        gpg::Warnf("map %s failed.  aborting session.", sessionInfo->mMapName.c_str());
        if (gWldFrameAction != EWldFrameAction::Inactive) {
          gWldFrameAction = EWldFrameAction::Exit;
        }
        if (outContinue != nullptr) {
          *outContinue = true;
        }
        ReleaseWldGameDataHandles(&gameData);
        return;
      }

      // Engine addition (wld_StartSimEarly): a sim started early (StartSimEarly) has had everything
      // up to its driver below; the session is built as before and takes that driver.
      const bool simStartedEarly = sEarlySim.driver != nullptr;

      // Engine addition: fix the FAF game version - and with it the engine
      // patches the sim applies - before the replay sink records it and before
      // the driver creates the sim.
      if (!simStartedEarly) {
        FAF_BeginSession(sessionInfo->mIsReplay);
      }

      // The replay sink, when this session records one. A sink that cannot be
      // opened is not fatal - the session simply stops being a recorded one.
      fa::auto_ptr<gpg::Stream> replayStream(nullptr);
      if (sessionInfo->mIsBeingRecorded && !simStartedEarly) {
        const fa::string defaultReplayName = Loc(USER_GetLuaState(), "<LOC Engine0030>LastGame");
        replayStream = VCR_CreateReplay(sessionInfo, defaultReplayName.c_str());
        if (replayStream.get() == nullptr) {
          sessionInfo->mIsBeingRecorded = false;
        }
      }

      {
        const std::string marker(" DoLoading 3");
        (void)marker;
      }

      fa::auto_ptr<LuaPlus::LuaState> stateOwner(gameData.mState);
      fa::auto_ptr<RRuleGameRules> rulesOwner(gameData.mGameRules);
      fa::auto_ptr<CWldMap> mapOwner(gameData.mWldMap);
      gameData = SWldGameData{};
      CWldSession* const wldSession = WLD_CreateSession(stateOwner, rulesOwner, mapOwner, *sessionInfo);
      ISTIDriver* driver = nullptr;
      if (simStartedEarly) {
        const char* const sessionLanguage = wldSession->mState->GetGlobal("__language").ToString();
        if (sessionLanguage == nullptr || sEarlySim.language != sessionLanguage) {
          gpg::Warnf("wld_StartSimEarly: the sim started with language '%s', the session's is '%s'",
                     sEarlySim.language.c_str(), sessionLanguage != nullptr ? sessionLanguage : "");
        }
        if (sEarlySim.launchClone) {
          wldSession->mLaunchInfo = sEarlySim.launchClone;
        }
        driver = sEarlySim.driver;
        sEarlySim = SEarlySimStart{};
      } else {
        // The launch info keeps its own copy of the playable map so a restart can
        // rebuild the session without the terrain resource still being alive.
        auto* const playableMap =
          wldSession->mWldMap->mTerrainRes->mMap;
        STIMap* const launchMap = new STIMap(playableMap);

        LaunchInfoBase* const launchInfo = sessionInfo->mLaunchInfo.get();
        launchInfo->mGameRules = wldSession->mRules;
        if (launchMap != launchInfo->mMap && launchInfo->mMap != nullptr) {
          delete launchInfo->mMap;
        }
        launchInfo->mMap = launchMap;

        launchInfo->mLanguage.assign_owned(wldSession->mState->GetGlobal("__language").ToString());

        if (!wldSession->IsMultiplayer && !wldSession->IsReplay) {
          // Single player: the session takes a shared owner on a fresh clone of
          // the launch info, which is what a mid-game save serializes.
          boost::SharedPtrRaw<void> createdLaunchInfo{};
          launchInfo->Create(createdLaunchInfo);

          boost::SharedPtrRaw<LaunchInfoBase> createdTyped{};
          createdTyped.px = static_cast<LaunchInfoBase*>(createdLaunchInfo.px);
          createdTyped.pi = createdLaunchInfo.pi;
          wldSession->mLaunchInfo = boost::SharedPtrFromRawRetained(createdTyped);
          createdLaunchInfo.release();
        }

        {
          const std::string marker(" DoLoading 4");
          (void)marker;
        }

        if (LaunchInfoNew* const newLaunchInfo = launchInfo->GetNew(); newLaunchInfo != nullptr) {
          newLaunchInfo->mProps = wldSession->mWldMap->mProps;
        }

        {
          const std::string marker(" DoLoading 5");
          (void)marker;
        }

#if FAF_SERVER_MODE
        // Engine addition, server mode (plan WP2.8): a server session's client has no sim. Its driver makes every
        // beat from the server's views (remote/client/NetworkSimDriver.h); no rejoin restore, replay timeline,
        // recording (the server keeps the replay) or sim pacing.
        const bool serverSession = faf::remote::client::HasServerLaunch();
#else
        constexpr bool serverSession = false;
#endif
        // Ownership of both the client manager and the replay sink moves into the
        // driver; the session info gives its client manager up here.
        IClientManager* const clientManager = sessionInfo->mClientManager;
        sessionInfo->mClientManager = nullptr;
        if (serverSession) {
#if FAF_SERVER_MODE
          // The client's own map heights, as loaded: the server's terrain edits go on a copy of them.
          const CHeightField* heights = nullptr;
          if (wldSession->mWldMap != nullptr && wldSession->mWldMap->mTerrainRes != nullptr && wldSession->mWldMap->mTerrainRes->mMap != nullptr) {
            heights = wldSession->mWldMap->mTerrainRes->mMap->mHeightField.get();
          }
          driver = faf::remote::client::CreateServerSessionDriver(*wldSession->mRules, *sessionInfo->mLaunchInfo, heights);
#endif
        } else {
        // Engine addition (issue #275): does nothing unless a save came with this client's seat.
        REJOIN_PrepareRestore(*sessionInfo);
        REPLAY_PrepareSession(*sessionInfo); // engine addition (replay timeline)
        // Engine addition: replays and single-player sessions get a beat lead (`sim_ReplayLead`,
        // `sim_LocalLead`); a session with any network connector keeps the original pacing.
        SIM_SetSessionPacing(SelectSessionPacing(*wldSession, clientManager));
        // 0x0088C364..0x0088C37C: the inlined `scoped_ptr::reset` - the new
        // driver is stored first, then the previous one is deleted.
        driver = SIM_CreateDriver(
          static_cast<CClientManagerImpl*>(clientManager),
          replayStream.release(),
          sessionInfo->mLaunchInfo,
          sessionInfo->mSourceId
        );
#if FAF_SERVER_MODE
        // Engine addition, server mode: `/loopback` runs the session through the remote
        // driver, the lockstep driver standing in for its server (replays and single-player
        // sessions only). Without it, unchanged.
        driver = faf::remote::client::WrapForLoopback(
          driver, *wldSession->mRules, launchMap->GetBounds3D(), wldSession->IsMultiplayer != 0
        );
#endif
        }
      }
      sSimDriver.reset(driver);

      gWldFrameAction = EWldFrameAction::Initialize;
      if (outContinue != nullptr) {
        *outContinue = true;
      }

      {
        const std::string marker(" DoLoading 6");
        (void)marker;
      }

      ReleaseWldGameDataHandles(&gameData);
    }

    /**
     * Engine addition (replay timeline): replaces the sim behind the running session with one at
     * the replay's keyframe or start. It is `WLD_DoLoading`'s part from the session info on; the
     * session's map, rules, UI and camera stay. What the old sim published stays until the new one
     * reaches the target, so that is what the screen shows until then.
     */
    [[nodiscard]] bool StartReplaySim(CWldSession& session)
    {
      sReplaySwapRate = sSimDriver->GetClientManager()->GetSimRateRequested();
      sReplaySwapFocus = session.FocusArmy;
      sReplaySwapStart = std::chrono::steady_clock::now();

      // Its last syncs only say that everything is gone, and they go with the driver.
      sSimDriver->ShutDown();
      sSimDriver.reset();

      fa::auto_ptr<SWldSessionInfo> sessionInfo = REPLAY_CreateRestartSession();
      if (sessionInfo.get() == nullptr) {
        return false;
      }

      STIMap* const launchMap = REPLAY_CloneStartMap();
      LaunchInfoBase* const launchInfo = sessionInfo->mLaunchInfo.get();
      launchInfo->mGameRules = session.mRules;
      launchInfo->mMap = launchMap;
      launchInfo->mLanguage.assign_owned(session.mState->GetGlobal("__language").ToString());
      if (LaunchInfoNew* const newLaunchInfo = launchInfo->GetNew(); newLaunchInfo != nullptr) {
        newLaunchInfo->mProps = session.mWldMap->mProps;
      }

      IClientManager* const clientManager = sessionInfo->mClientManager;
      sessionInfo->mClientManager = nullptr;
      clientManager->SetUIInterface(&sCWldUiInterface);
      REPLAY_PrepareSession(*sessionInfo);
      SIM_SetSessionPacing(SelectSessionPacing(session, clientManager));
      ISTIDriver* driver = SIM_CreateDriver(
        static_cast<CClientManagerImpl*>(clientManager),
        nullptr,
        sessionInfo->mLaunchInfo,
        sessionInfo->mSourceId
      );
#if FAF_SERVER_MODE
      driver = faf::remote::client::WrapForLoopback(
        driver, *session.mRules, launchMap->GetBounds3D(), session.IsMultiplayer != 0
      );
#endif
      sSimDriver.reset(driver);
      gpg::Logf(
        "Replay timeline: the old sim went in %.2f s",
        std::chrono::duration<double>(std::chrono::steady_clock::now() - sReplaySwapStart).count()
      );
      return true;
    }

    /**
     * Engine addition (replay timeline): one frame of a sim swap: the steps of `WLD_DoInitializing`
     * and `WLD_DoPostInitializing` without their UI, then the new sim's beats are held until the
     * target, and applied in one frame. True while the session has no beats to take.
     */
    [[nodiscard]] bool StepReplaySimSwap(CWldSession& session)
    {
      constexpr double kNewSimLimitSeconds = 300.0;

      if (sReplaySimSwap == EReplaySimSwap::None) {
        if (!REPLAY_RestartWanted()) {
          return false;
        }
        sReplaySimSwap = EReplaySimSwap::WaitingForSync;
        if (!StartReplaySim(session)) {
          gWldFrameAction = EWldFrameAction::Exit;
          return true;
        }
      }

      ISTIDriver* const simDriver = sSimDriver.get();
      if (simDriver == nullptr) {
        return true;
      }
      simDriver->Dispatch();

      if (sReplaySimSwap == EReplaySimSwap::WaitingForSync) {
        if (!simDriver->HasSyncData()) {
          const std::chrono::duration<double> waited = std::chrono::steady_clock::now() - sReplaySwapStart;
          if (waited.count() > kNewSimLimitSeconds) {
            gpg::Warnf("Replay timeline: the new sim gave nothing in %.0f s, leaving the replay", waited.count());
            gWldFrameAction = EWldFrameAction::Exit;
          }
          return true;
        }

        SSyncData* syncData = nullptr;
        simDriver->GetSyncData(syncData);
        // The new sim doesn't know whose view this is yet; the UI must not see a change for one beat.
        syncData->mFocusArmy = sReplaySwapFocus;
        sReplayHeldBeats.push_back(syncData);
        REPLAY_NoteHeldTick(syncData->mCurTick);
        gpg::Logf(
          "Replay timeline: the new sim's first sync after %.2f s",
          std::chrono::duration<double>(std::chrono::steady_clock::now() - sReplaySwapStart).count()
        );

        if (CClientManagerImpl* const clientManager = simDriver->GetClientManager(); clientManager != nullptr) {
          clientManager->Cleanup();
          clientManager->SetSimRate(sReplaySwapRate);
        }
        simDriver->SetArmyIndex(sReplaySwapFocus);
        sReplaySimSwap = EReplaySimSwap::WaitingForReady;
      }

      if (sReplaySimSwap == EReplaySimSwap::WaitingForReady) {
        CClientManagerImpl* const clientManager = simDriver->GetClientManager();
        if (clientManager != nullptr && !clientManager->IsEveryoneReady()) {
          return true;
        }
        simDriver->DecrementOutstandingRequestsAndSignal();
        sReplaySimSwap = EReplaySimSwap::Holding;
      }

      simDriver->SetGeomCams(CAM_GetAllCameras());
      bool gameOver = false;
      while (!gameOver && !REPLAY_HoldIsDone(sReplayHeldBeats.size()) && simDriver->HasSyncData()) {
        SSyncData* syncData = nullptr;
        simDriver->GetSyncData(syncData);
        sReplayHeldBeats.push_back(syncData);
        REPLAY_NoteHeldTick(syncData->mCurTick);
        gameOver = syncData->mGameOver;
      }
      if (!gameOver && !REPLAY_HoldIsDone(sReplayHeldBeats.size())) {
        return true;
      }

      const auto applyStart = std::chrono::steady_clock::now();
      session.ResetForNewReplaySim();
      for (SSyncData* const held : sReplayHeldBeats) {
        session.DoBeat(fa::auto_ptr<SSyncData>(held));
      }
      gpg::Logf(
        "Replay timeline: %d held beats applied in %.2f s", static_cast<int>(sReplayHeldBeats.size()),
        std::chrono::duration<double>(std::chrono::steady_clock::now() - applyStart).count()
      );
      sReplayHeldBeats.clear();
      sReplaySimSwap = EReplaySimSwap::None;
      REPLAY_SimRestarted(session);
      return false;
    }

    /**
     * Address: 0x0088C3F0 (FUN_0088C3F0, func_DoInitializing)
     *
     * What it does:
     * Waits for the sim to publish its first sync data, then performs the whole
     * loading-to-playing handover: starts the game Lua UI, takes down the
     * loading dialog, builds the in-game interface, drops the now-consumed
     * session info, runs the loader's teardown callbacks, and finally tells the
     * client manager that this client has finished loading.
     */
    void WLD_DoInitializing(bool* const outContinue)
    {
      ISTIDriver* const simDriver = sSimDriver.get();
      if (simDriver == nullptr) {
        if (outContinue != nullptr) {
          *outContinue = false;
        }
        gWldFrameAction = EWldFrameAction::Exit;
        return;
      }

      // Engine addition: once per session, while the loading screen waits for the sim's first
      // sync, build the GPU-driven render paths the first frame of play would otherwise build
      // (REN_PrepareGpuPaths); the main thread is idle here for the seconds the sim takes to start.
      if (static const CWldSession* sPreparedFor = nullptr; ren_PrepareDuringLoading && sPreparedFor != gActiveWldSession) {
        sPreparedFor = gActiveWldSession;
        const auto prepareStart = std::chrono::steady_clock::now();
        const int paths = REN_PrepareGpuPaths();
        // The map's sky dome textures and buffers, which its first draw otherwise creates.
        if (IWldTerrainRes* const terrainRes = REN_GetTerrainRes(); terrainRes != nullptr) {
          terrainRes->GetSkyDome().CreateRenderAbility();
        }
        gpg::Logf("Render: %d GPU-driven paths and the sky dome prepared during loading in %.1f ms", paths,
          std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - prepareStart).count());
      }

      simDriver->Dispatch();
      if (!simDriver->HasSyncData()) {
        return;
      }

      CWldSession* const session = gActiveWldSession;
      if (session != nullptr && session->mState != nullptr) {
        (void)UI_StartGameUI(session->mState);
      }

      // Apply the first sync payload. This has to happen before
      // `CreateGameInterface` below: the packet carries the initial armies and
      // entities, and the in-game UI reads them as it builds.
      if (session != nullptr) {
        SSyncData* syncData = nullptr;
        simDriver->GetSyncData(syncData);
        session->DoBeat(fa::auto_ptr<SSyncData>(syncData));
      }

      IWldUIProvider* const wldUIProvider = ResolveWldUIProvider();
      if (wldUIProvider != nullptr) {
        wldUIProvider->StopLoadingDialog();
      }

      if (wldUIProvider != nullptr) {
        // Not in the binary: an exception out of the UI's Lua
        // `CreateGameInterface` used to skip `clientManager->Cleanup()` below
        // and leave the session stuck in Waiting forever, so it is reported
        // and the session start carries on. Costs nothing unless it throws.
        try {
          wldUIProvider->CreateGameInterface(gPendingWldSessionInfo != nullptr && gPendingWldSessionInfo->mIsReplay);
        } catch (const std::exception& ex) {
          char probe[512];
          sprintf_s(probe, "[INITDIAG] CreateGameInterface THREW std::exception: %.400s\n", ex.what());
          ::OutputDebugStringA(probe);
        } catch (...) {
          ::OutputDebugStringA("[INITDIAG] CreateGameInterface THREW non-std exception\n");
        }
      }

      // The session info existed only to carry launch parameters into the
      // session; the session owns everything it needed by now.
      gPendingWldSessionInfo.reset();

      (void)WLD_DispatchOnTeardownCallbacksCoreFromGlobalList();

      // Declare this client ready. `CClientManagerImpl::Cleanup` is the only
      // writer of `mWeAreReady`, which `DoBeat` needs before it will ever set
      // `mEveryoneIsReady` - so without this the session sits in Waiting
      // forever showing "waiting for other players", local game or not.
      // Engine addition (wld_ReadyAfterFirstFrame): not until the first frame of the interface just
      // built has been drawn (WLD_DoPostInitializing); the binary declared it here.
      if (wld_ReadyAfterFirstFrame != 0) {
        gReadyAfterFirstFrame = true;
      } else if (CClientManagerImpl* const clientManager = simDriver->GetClientManager(); clientManager != nullptr) {
        clientManager->Cleanup();
      }

      if (outContinue != nullptr) {
        *outContinue = false;
      }
      gWldFrameAction = EWldFrameAction::PostInitialize;
    }

    /**
     * Address: 0x0088BFD0 (FUN_0088BFD0)
     *
     * What it does:
     * Signals one trailing post-init sim-driver lane, transitions world-frame
     * dispatch to `Playing`, and notifies the active world-UI provider through
     * `OnStart` when present.
     */
    [[maybe_unused]] int WLD_EnterPlayingAndNotifyUIProvider()
    {
      int dispatchResult = 0;
      if (ISTIDriver* const simDriver = sSimDriver.get(); simDriver != nullptr) {
        simDriver->DecrementOutstandingRequestsAndSignal();
      }

      gWldFrameAction = EWldFrameAction::Playing;

      if (IWldUIProvider* const wldUIProvider = ResolveWldUIProvider(); wldUIProvider != nullptr) {
        wldUIProvider->OnStart();
      }

      return dispatchResult;
    }

    /**
     * Address: 0x0088C6D0 (FUN_0088C6D0, func_DoPostInitializing)
     *
     * What it does:
     * Dispatches post-init sim/network work, transitions to playing once every
     * client is ready, and toggles waiting-dialog UI lanes during the handoff.
     */
    void WLD_DoPostInitializing(bool* const outContinue)
    {
      if (outContinue != nullptr) {
        *outContinue = false;
      }

      ISTIDriver* const simDriver = sSimDriver.get();
      if (simDriver == nullptr) {
        gWldFrameAction = EWldFrameAction::Exit;
        return;
      }

      simDriver->Dispatch();
      CClientManagerImpl* const clientManager = simDriver->GetClientManager();

      // Engine addition: the frame that built the game interface has been drawn, with the UI's
      // first update (`OnFirstUpdate`) and the world's first render, which take a few hundred ms
      // more. Ready now, so the session's shared start (wld_PreciseSharedStart) is when the last
      // player can show its first tick, not that long before it. Checked next frame, once the
      // issue thread has counted it, so a lone player does not see the waiting dialog flash.
      if (gReadyAfterFirstFrame) {
        gReadyAfterFirstFrame = false;
        if (clientManager != nullptr) {
          clientManager->Cleanup();
        }
        return;
      }

      if (clientManager != nullptr && clientManager->IsEveryoneReady()) {
        simDriver->DecrementOutstandingRequestsAndSignal();
        gWldFrameAction = EWldFrameAction::Playing;
        if (outContinue != nullptr) {
          *outContinue = true;
        }
        if (IWldUIProvider* const wldUIProvider = ResolveWldUIProvider(); wldUIProvider != nullptr) {
          wldUIProvider->OnStart();
        }
      } else {
        if (IWldUIProvider* const wldUIProvider = ResolveWldUIProvider(); wldUIProvider != nullptr) {
          wldUIProvider->StartWaitingDialog();
        }
        gWldFrameAction = EWldFrameAction::Waiting;
      }
    }

    /**
     * Address: 0x0088C750 (FUN_0088C750, func_DoWaiting)
     *
     * What it does:
     * Dispatches waiting-state sim/network work, transitions to playing when
     * all peers are ready, and fires waiting-dialog stop/start UI callbacks.
     */
    void WLD_DoWaiting(bool* const outContinue)
    {
      if (outContinue != nullptr) {
        *outContinue = false;
      }

      ISTIDriver* const simDriver = sSimDriver.get();
      if (simDriver == nullptr) {
        gWldFrameAction = EWldFrameAction::Exit;
        return;
      }

      REJOIN_MainFrame(*simDriver);
      simDriver->Dispatch();
      CClientManagerImpl* const clientManager = simDriver->GetClientManager();
      if (clientManager != nullptr && clientManager->IsEveryoneReady()) {
        if (IWldUIProvider* const wldUIProvider = ResolveWldUIProvider(); wldUIProvider != nullptr) {
          wldUIProvider->StopWaitingDialog();
        }

        simDriver->DecrementOutstandingRequestsAndSignal();
        gWldFrameAction = EWldFrameAction::Playing;

        if (IWldUIProvider* const wldUIProvider = ResolveWldUIProvider(); wldUIProvider != nullptr) {
          wldUIProvider->OnStart();
        }

        if (outContinue != nullptr) {
          *outContinue = true;
        }
      } else {
        UpdateRejoinScreen(clientManager, false);
        (void)UI_UpdateDisconnectDialogCallback();
      }
    }

    /**
     * Address: 0x0088C7C0 (FUN_0088C7C0, func_DoPlayingAction)
     *
     * What it does:
     * Dispatches one sim-driver tick, hands the current world camera set to
     * the sim driver, runs one world-session frame, fires the trailing
     * sim-driver post-frame slot, and pumps the disconnect dialog callback.
     */
    void WLD_DoPlayingAction(const float deltaSeconds)
    {
      // Engine addition (replay timeline): a new sim behind this session, and keyframes.
      CWldSession* const replaySession = WLD_GetActiveSession();
      const bool simSwapping = replaySession != nullptr && StepReplaySimSwap(*replaySession);

      if (ISTIDriver* const simDriver = sSimDriver.get(); simDriver != nullptr && !simSwapping) {
        REJOIN_MainFrame(*simDriver);
        simDriver->Dispatch();

        if (replaySession != nullptr) {
          REPLAY_MainFrame(*simDriver, *replaySession);
        }

        // Snapshot every active GeomCamera and forward to the sim driver so
        // visibility/projection state matches the upcoming session frame.
        const fa::vector<GeomCamera3> cameras = CAM_GetAllCameras();
        simDriver->SetGeomCams(cameras);
      }

      if (CWldSession* const activeSession = WLD_GetActiveSession(); activeSession != nullptr) {
        activeSession->SessionFrame(deltaSeconds);
      }

      if (ISTIDriver* const simDriver = sSimDriver.get(); simDriver != nullptr) {
        // Trailing sim-driver post-frame slot (Func1 in IDA): currently
        // a NoOp until full ISTIDriver vtable slot ownership is recovered.
        simDriver->NoOp();
        UpdateRejoinScreen(simDriver->GetClientManager(), false);
      }

      (void)UI_UpdateDisconnectDialogCallback();
    }

    /**
     * Address: 0x0088C9D0 (FUN_0088C9D0, func_CreateSWldSessionInfo)
     *
     * What it does:
     * Drives the world-session `CreateSession` frame action, which only an
     * explicit restart request (`RestartSession`) sets: builds a fresh session
     * info from the active session - its map, its launch info, whether it is
     * recorded - gives it a local client named after the session's own command
     * source, and begins it, which schedules `Preload`.
     *
     * This only set `Preload`. `WLD_DoInitializing` has already released the
     * pending session info, so `Preload` tore the session down, opened the
     * loading screen and prefetched nothing, and `Loading` waited for a
     * scenario that was never requested: a restart hung in the loading screen.
     */
    void WLD_CreateSessionInfo()
    {
      // Engine addition: the binary reads the active session unchecked;
      // without one there is nothing to restart, so leave to the front end.
      const CWldSession* const session = gActiveWldSession;
      if (session == nullptr) {
        gWldFrameAction = EWldFrameAction::Exit;
        return;
      }

      fa::auto_ptr<SWldSessionInfo> sessionInfo(new SWldSessionInfo());
      sessionInfo->mMapName = session->mMapName;
      sessionInfo->mLaunchInfo = session->mLaunchInfo;
      sessionInfo->mIsBeingRecorded = session->IsBeingRecorded;
      sessionInfo->mIsReplay = false;
      sessionInfo->mIsMultiplayer = false;
      sessionInfo->mClientManager = nullptr;
      sessionInfo->mSourceId = 0xFFu;

      const SSTICommandSource& localSource = session->cmdSources[static_cast<std::size_t>(session->ourCmdSource)];
      SetupSinglePlayerCommandSourceLane(*sessionInfo, localSource.mName.c_str());
      WLD_BeginSession(sessionInfo);
    }
}


  /**
   * Address: 0x0088BD20 (FUN_0088BD20, ?WLD_SetUIProvider@Moho@@YAXPAVIWldUIProvider@1@@Z)
   *
   * What it does:
   * Replaces the process-global world-UI provider ownership lane, deleting the
   * previous provider when it differs from the new one.
   */
  void WLD_SetUIProvider(IWldUIProvider* const provider)
  {
    if (sWldUIProvider != provider && sWldUIProvider != nullptr) {
      delete sWldUIProvider;
    }

    sWldUIProvider = provider;
  }

  // WLD_GetFrameAction, WLD_SetFrameAction: moho/sim/WldSessionState.cpp.

  /**
   * Address: 0x0088BE80 (FUN_0088BE80, ?WLD_IsSessionActive@Moho@@YA_NXZ)
   *
   * What it does:
   * Returns whether world-frame dispatch is currently active.
   */
  bool WLD_IsSessionActive()
  {
    return gWldFrameAction != EWldFrameAction::Inactive;
  }

  /**
   * Address: 0x0088BE90 (FUN_0088BE90, world-frame playing-state probe)
   *
   * What it does:
   * Returns whether world-frame dispatch is currently in the `Playing` state.
   */
  bool WLD_IsSessionPlaying()
  {
    return gWldFrameAction == EWldFrameAction::Playing;
  }

  /**
   * Address: 0x0088BEA0 (FUN_0088BEA0, ?WLD_RequestEndSession@Moho@@YAXXZ)
   *
   * What it does:
   * Requests world-session exit when frame dispatch is currently active.
   */
  void WLD_RequestEndSession()
  {
    if (gWldFrameAction != EWldFrameAction::Inactive) {
      gWldFrameAction = EWldFrameAction::Exit;
    }
  }

  /**
   * Address: 0x0088E6D0 (FUN_0088E6D0)
   *
   * What it does:
   * Console-command callback for `wld_ClientDebugDump`: when a sim driver is
   * active (`sSimDriver`, 0x010C4F50), asks it for its client manager
   * (`ISTIDriver` slot 3) and runs that manager's `Debug` dump (slot 25,
   * tail call, no null test). Registered by the `gCConFunc_wld_ClientDebugDump`
   * initializer 0x00BE7510 (instruction 0x00BE7530 stores the callback
   * address in the command object's slot at 0x00F5B770).
   */
  void CON_WLD_ClientDebugDump(const fa::vector<fa::string>& args)
  {
    (void)args;

    if (ISTIDriver* const simDriver = sSimDriver.get()) {
      simDriver->GetClientManager()->Debug();
    }
  }

  /**
   * Address: 0x0088E6F0 (FUN_0088E6F0)
   *
   * What it does:
   * Console-command callback that requests world-session exit when frame
   * dispatch is currently active.
   */
  void CON_WLD_RequestEndSession(const fa::vector<fa::string>& args)
  {
    (void)args;

    if (gWldFrameAction != EWldFrameAction::Inactive) {
      gWldFrameAction = EWldFrameAction::Exit;
    }
  }

  /**
   * Address: 0x0088BEC0 (FUN_0088BEC0, ?WLD_RequestRestartSession@Moho@@YAXXZ)
   *
   * What it does:
   * Requests world-session recreation when frame dispatch is active and the
   * active session carries restart launch info.
   */
  void WLD_RequestRestartSession()
  {
    if (gWldFrameAction == EWldFrameAction::Inactive) {
      return;
    }

    CWldSession* const activeSession = WLD_GetActiveSession();
    if (activeSession != nullptr && activeSession->mLaunchInfo) {
      gWldFrameAction = EWldFrameAction::CreateSession;
    }
  }

  /**
   * Address: 0x0088C9C0 (FUN_0088C9C0)
   *
   * What it does:
   * Tears down the current world session and then enters the front-end flow.
   */
  [[nodiscard]] bool WLD_TeardownAndStartFrontEnd()
  {
    WLD_Teardown();
    return UI_StartFrontEnd();
  }

  /**
   * Address: 0x0088CAE0 (FUN_0088CAE0, ?WLD_Frame@Moho@@YA_NM@Z)
   */
  bool WLD_Frame(const float deltaSeconds)
  {
    if (CWldSessionLoaderImpl* const loader = GetWldSessionLoader(); loader != nullptr) {
      loader->Update();
    }

    for (;;) {
      bool continueDispatch = false;
      switch (gWldFrameAction) {
        case EWldFrameAction::Inactive:
          if (CWldSessionLoaderImpl* const loader = GetWldSessionLoader(); loader != nullptr) {
            loader->SetCreated();
          }
          return true;
        case EWldFrameAction::Preload:
          WLD_DoPreload();
          return true;
        case EWldFrameAction::Loading:
          WLD_DoLoading(&continueDispatch);
          break;
        case EWldFrameAction::Initialize:
          WLD_DoInitializing(&continueDispatch);
          break;
        case EWldFrameAction::PostInitialize:
          WLD_DoPostInitializing(&continueDispatch);
          break;
        case EWldFrameAction::Waiting:
          WLD_DoWaiting(&continueDispatch);
          break;
        case EWldFrameAction::Playing:
          WLD_DoPlayingAction(deltaSeconds);
          return true;
        case EWldFrameAction::CreateSession:
          WLD_CreateSessionInfo();
          return true;
        case EWldFrameAction::Exit:
          (void)WLD_TeardownAndStartFrontEnd();
          return true;
        default:
          return true;
      }

      if (continueDispatch) {
        continue;
      }

      return true;
    }
  }

  /**
   * Address: 0x00869810 (FUN_00869810, func_WldSessionLoader_GetOnTeardownCallbacks)
   * Address: 0x00C07650 (FUN_00C07650, atexit destructor of the session-listener registry)
   * Address: 0x00869A80 (FUN_00869A80, unreferenced copy of that atexit destructor)
   *
   * What it does:
   * Returns the process-global session-listener registry, a function-local
   * static constructed on first use.
   *
   * Every registrant (`SelectionListener`, `PauseListener`,
   * `IdleUnitSelector`) registers from its own translation unit's static
   * initialiser. A namespace-scope vector would be constructed in
   * static-initialisation order and could null the lanes those `push_back`s
   * already filled; the function-local static is constructed exactly when the
   * first registrant needs it, as in the binary.
   */
  WldTeardownCallbackVector* WLD_GetOnTeardownCallbacks()
  {
    static WldTeardownCallbackVector sCallbacks;
    return &sCallbacks;
  }

  /**
   * Address: 0x008699A0 (FUN_008699A0)
   *
   * What it does:
   * Resolves the process-global session-listener registry and attaches every
   * listener in it to the freshly created world session (vtable slot 0).
   */
  std::int32_t WLD_DispatchOnTeardownCallbacksCoreFromGlobalList()
  {
    WldTeardownCallbackVector* const callbacks = WLD_GetOnTeardownCallbacks();
    return static_cast<std::int32_t>(DispatchSessionListenerAttachAndReturnLastResult(callbacks));
  }

  /**
   * Address: 0x008699B0 (FUN_008699B0)
   *
   * What it does:
   * Resolves the process-global teardown-callback vector and runs the normal
   * teardown callback dispatch entry point.
   */
  [[nodiscard]] std::intptr_t WLD_RunTeardownCallbacksFromGlobalList()
  {
    WldTeardownCallbackVector* const callbacks = WLD_GetOnTeardownCallbacks();
    return DoTeardownCallbacks(callbacks);
  }

  /**
   * Address: 0x00869950 (FUN_00869950)
   *
   * What it does:
   * Appends one teardown-callback pointer to the process-global callback
   * vector and returns that vector.
   */
  WldTeardownCallbackVector* WLD_AddOnTeardownCallback(IWldTeardownCallback* const callback)
  {
    WldTeardownCallbackVector* const callbacks = WLD_GetOnTeardownCallbacks();
    if (callbacks == nullptr) {
      return nullptr;
    }

    callbacks->push_back(callback);
    return callbacks;
  }

  /**
   * Address: 0x0088C860 (FUN_0088C860, ?WLD_Teardown@Moho@@YAXXZ)
   *
   * What it does:
   * Shuts the driver down and hands the session every sync packet it still
   * holds, then silences sound, runs the teardown callbacks, destroys the game
   * interface and its provider, clears the particle buckets, drops the UI Lua
   * state, deletes the session and finally releases the driver.
   *
   * The drain matters: packets the sim produced after the session's last beat
   * carry entity deletions and command releases the session would otherwise
   * never apply before it is destroyed.
   */
  bool WLD_IsReplaySimSwapping()
  {
    return sReplaySimSwap != EReplaySimSwap::None;
  }

  void WLD_Teardown()
  {
    DropEarlySim(); // engine addition (wld_StartSimEarly): a load given up before its session
    REPLAY_OnTeardown(); // engine addition (replay timeline)
    sReplaySimSwap = EReplaySimSwap::None;
    for (SSyncData* const held : sReplayHeldBeats) {
      delete held;
    }
    sReplayHeldBeats.clear();
    if (sSimDriver) {
      sSimDriver->ShutDown();
      CWldSession* const session = gActiveWldSession;
      while (sSimDriver->HasSyncData()) {
        SSyncData* syncData = nullptr;
        sSimDriver->GetSyncData(syncData);
        session->DoBeat(fa::auto_ptr<SSyncData>(syncData));
      }
    }

    USER_GetSound()->StopAllSounds();
    (void)DoTeardownCallbacks(WLD_GetOnTeardownCallbacks());

    if (sWldUIProvider != nullptr) {
      sWldUIProvider->DestroyGameInterface();
      delete sWldUIProvider;
      sWldUIProvider = nullptr;
    }

    sWorldParticles.ClearRenderBuckets();
    (void)g_UIManager->SetNewLuaState(nullptr);

    delete gActiveWldSession;
    gActiveWldSession = nullptr;
    gWldFrameAction = EWldFrameAction::Inactive;
    sSimDriver.reset();
  }


  /**
   * Address: 0x00897220 (FUN_00897220, ?WLD_CreateSession@Moho@@YAPAVCWldSession@1@AAV?$auto_ptr@VLuaState@LuaPlus@@@std@@AAV?$auto_ptr@VRRuleGameRules@Moho@@@4@AAV?$auto_ptr@VCWldMap@Moho@@@4@AAUSWldSessionInfo@1@@Z)
   *
   * What it does:
   * Allocates one world-session object, constructs it from transferred
   * auto_ptr lanes, and updates the global active-session pointer.
   */
  CWldSession* WLD_CreateSession(
    fa::auto_ptr<LuaPlus::LuaState>& state,
    fa::auto_ptr<RRuleGameRules>& gameRules,
    fa::auto_ptr<CWldMap>& wldMap,
    SWldSessionInfo& sessionInfo
  )
  {
    void* const sessionStorage = ::operator new(sizeof(CWldSession), std::nothrow);
    if (sessionStorage == nullptr) {
      gActiveWldSession = nullptr;
      return nullptr;
    }

    CWldSession* session = nullptr;
    try {
      session = new (sessionStorage) CWldSession(state, gameRules, wldMap, sessionInfo);
    } catch (...) {
      ::operator delete(sessionStorage);
      throw;
    }

    gActiveWldSession = session;
    return session;
  }

  /**
   * Address: 0x008972D0 (FUN_008972D0)
   *
   * What it does:
   * Runs one deleting teardown path for `CWldSession` and returns the original
   * pointer lane.
   */
  CWldSession* DeleteWldSessionAndReturn(CWldSession* const session) noexcept
  {
    session->~CWldSession();
    ::operator delete(session);
    return session;
  }

  /**
   * Address: 0x008972A0 (FUN_008972A0, ?WLD_DestroySession@Moho@@YAXXZ)
   *
   * What it does:
   * Destroys the active world-session object when present and clears the
   * process-global active-session pointer.
   */
  void WLD_DestroySession()
  {
    CWldSession* const activeSession = gActiveWldSession;
    if (activeSession != nullptr) {
      (void)DeleteWldSessionAndReturn(activeSession);
    }

    gActiveWldSession = nullptr;
  }

  // WLD_GetSession: moho/sim/WldSessionState.cpp.

  /**
   * Address: 0x0088D060 (FUN_0088D060, ?WLD_BeginSession@Moho@@YAXV?$auto_ptr@USWldSessionInfo@Moho@@@std@@@Z)
   *
   * What it does:
   * Replaces pending world-session bootstrap info and schedules preload.
   */
  void WLD_BeginSession(fa::auto_ptr<SWldSessionInfo> sessionInfo)
  {
    gPendingWldSessionInfo = sessionInfo;
    gWldFrameAction = EWldFrameAction::Preload;
  }

  void WLD_StartPendingSessionLoad()
  {
    CWldSessionLoaderImpl* const loader = GetWldSessionLoader();
    SWldSessionInfo* const pendingSession = gPendingWldSessionInfo.get();
    if (loader == nullptr || pendingSession == nullptr || pendingSession->mLaunchInfo.get() == nullptr) {
      return;
    }
    (void)loader->CreateScenarioInfo(
      pendingSession->mMapName.raw_data_unsafe(), &pendingSession->mLaunchInfo.get()->mGameMods
    );
    WLD_HoldSessionScripts(true);
    WLD_HoldDeviceUse(true); // CScApp::Init lets it go once CreateDevice returns
    loader->Update();
  }

  /**
   * Address: 0x0088D0B0 (FUN_0088D0B0, ?WLD_GetSimRate@Moho@@YAMXZ)
   */
  float WLD_GetSimRate()
  {
    extern float wld_SkewRateAdjustBase;
    extern float wld_SkewRateAdjustMax;

    ISTIDriver* const simDriver = sSimDriver.get();
    if (simDriver == nullptr) {
      return 1.0f;
    }

    CClientManagerImpl* const clientManager = simDriver->GetClientManager();
    if (clientManager == nullptr) {
      return 1.0f;
    }

    // 0x0088D0DA..0x0088D0EB: `fild rate; fmul 0.1f` (float 0x3DCCCCCD at
    // 0x00E4F714), then the CRT pow with the double 10.0 base.
    float requestedSimScale =
      static_cast<float>(std::pow(10.0, static_cast<double>(clientManager->GetSimRate() * 0.1f)));

    // Engine addition (sim_ReplayLead / sim_LocalLead): the display clock follows the sim's measured speed
    // rather than the rate step it rounds down to (up to 26% slower), with a little headroom so the
    // display, not the sim, is the one that waits. Never faster than the requested speed.
    if (const float measuredScale = SIM_GetLeadSimSpeedEstimate(); measuredScale > 0.0f) {
      constexpr float kReplayClockHeadroom = 1.05f;
      const float requestedOnly =
        static_cast<float>(std::pow(10.0, static_cast<double>(clientManager->GetSimRateRequested() * 0.1f)));
      requestedSimScale = std::min(requestedOnly, std::max(requestedSimScale, measuredScale * kReplayClockHeadroom));
    }

    const float skewRateMin = 1.0f / wld_SkewRateAdjustMax;
    const float skewRateSample =
      static_cast<float>(std::pow(static_cast<double>(wld_SkewRateAdjustBase), -simDriver->GetSimSpeed()));
    const float clampedSkewRate = std::max(skewRateMin, std::min(wld_SkewRateAdjustMax, skewRateSample));
    return clampedSkewRate * requestedSimScale;
  }

  /**
   * Address: 0x0088D170 (FUN_0088D170, session sim-rate permission probe)
   *
   * What it does:
   * Returns whether the active session context may issue local sim-rate
   * changes (`replay`, focused local army, or non-multiplayer).
   */
  bool WLD_CanAdjustSimRate()
  {
    CWldSession* const activeSession = WLD_GetActiveSession();
    if (activeSession == nullptr) {
      return false;
    }

    if (activeSession->IsReplay) {
      return true;
    }

    const int focusArmy = activeSession->FocusArmy;
    if (focusArmy >= 0 && activeSession->userArmies[static_cast<std::size_t>(focusArmy)] != nullptr) {
      return true;
    }

    return !activeSession->IsMultiplayer;
  }

  /**
   * Address: 0x0088D1B0 (FUN_0088D1B0, ?WLD_IncreaseSimRate@Moho@@YAXXZ)
   *
   * What it does:
   * Raises requested sim rate by one step (up to +50) for authorized local
   * session contexts.
   */
  void WLD_IncreaseSimRate()
  {
    ISTIDriver* const simDriver = sSimDriver.get();
    if (simDriver == nullptr || !WLD_CanAdjustSimRate()) {
      return;
    }

    CClientManagerImpl* const clientManager = simDriver->GetClientManager();
    const int requestedSimRate = clientManager->GetSimRateRequested();
    if (requestedSimRate < 50) {
      clientManager->SetSimRate(requestedSimRate + 1);
    }
  }

  /**
   * Address: 0x0088D220 (FUN_0088D220, ?WLD_ResetSimRate@Moho@@YAXXZ)
   *
   * What it does:
   * Resets requested sim rate back to neutral (`0`) for authorized local
   * session contexts.
   */
  void WLD_ResetSimRate()
  {
    ISTIDriver* const simDriver = sSimDriver.get();
    if (simDriver == nullptr || !WLD_CanAdjustSimRate()) {
      return;
    }

    CClientManagerImpl* const clientManager = simDriver->GetClientManager();
    if (clientManager->GetSimRateRequested() != 0) {
      clientManager->SetSimRate(0);
    }
  }

  /**
   * Address: 0x0088D280 (FUN_0088D280, ?WLD_DecreaseSimRate@Moho@@YAXXZ)
   *
   * What it does:
   * Lowers requested sim rate by one step (down to `-10`) for authorized
   * local session contexts.
   */
  void WLD_DecreaseSimRate()
  {
    ISTIDriver* const simDriver = sSimDriver.get();
    if (simDriver == nullptr || !WLD_CanAdjustSimRate()) {
      return;
    }

    CClientManagerImpl* const clientManager = simDriver->GetClientManager();
    const int requestedSimRate = clientManager->GetSimRateRequested();
    if (requestedSimRate > -10) {
      clientManager->SetSimRate(requestedSimRate - 1);
    }
  }

  /**
   * Address: 0x0088D2F0 (FUN_0088D2F0, ?WLD_SetGameSpeed@Moho@@YAXH@Z)
   *
   * What it does:
   * Sets one requested sim-rate lane after clamping the provided game-speed
   * value to the legacy `[-10, 10]` bounds.
   */
  void WLD_SetGameSpeed(int gameSpeed)
  {
    ISTIDriver* const simDriver = sSimDriver.get();
    if (simDriver == nullptr) {
      return;
    }

    CClientManagerImpl* const clientManager = simDriver->GetClientManager();
    int clampedGameSpeed = gameSpeed;
    if (gameSpeed >= 10) {
      clampedGameSpeed = 10;
    }

    if (clampedGameSpeed < -10) {
      clampedGameSpeed = -10;
    }

    clientManager->SetSimRate(clampedGameSpeed);
  }

  // WLD_GetDriver and WLD_GetActiveSession: moho/sim/WldSessionState.cpp; the
  // driver is this file's sSimDriver, handed over through the hook below.
}

namespace
{
  // Engine addition (dedicated-server plan WPL.4): WLD_GetDriver's
  // `sSimDriver.get()` (WldSessionState.cpp), set before main.
  moho::ISTIDriver* SessionSimDriver()
  {
    return moho::sSimDriver.get();
  }

  [[maybe_unused]] const bool gSessionSimDriverSet = (moho::sSessionSimDriver = &SessionSimDriver, true);
}

