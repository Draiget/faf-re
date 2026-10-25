#include "replay/ReplayRunner.h"

#include <Windows.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>

#include "gpg/core/algorithms/MD5.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/misc/SessionStartup.h"
#include "moho/net/CClientManagerImpl.h"
#include "moho/net/IClientMgrUIInterface.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/CWldSessionLoaderImpl.h"
#include "moho/sim/FafGameVersion.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimDebugCommandRegistrations.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/WldSessionInfo.h"
#include "moho/ui/UiRuntimeTypes.h"

namespace faf::replay
{
  namespace
  {
    using Clock = std::chrono::steady_clock;

    [[nodiscard]] double SecondsSince(const Clock::time_point start)
    {
      return std::chrono::duration<double>(Clock::now() - start).count();
    }

    // The game logs every recorded checksum that differs from the sim's as
    // "Checksum for beat N mismatched: <sim> (sim) != <recorded> (<player>)." (Sim::VerifyChecksum).
    class ChecksumLogWatch final : public gpg::LogTarget
    {
    public:
      explicit ChecksumLogWatch(std::string label)
        : gpg::LogTarget(true)
        , mLabel(std::move(label))
      {}

      void OnMessage(
        const gpg::LogSeverity level,
        const msvc8::string& message,
        const msvc8::vector<msvc8::string>& context,
        const int previousDepth
      ) override
      {
        (void)level;
        (void)context;
        (void)previousDepth;
        if (std::strstr(message.c_str(), "Checksum for beat ") != nullptr
            && std::strstr(message.c_str(), " mismatched: ") != nullptr) {
          mMismatches.fetch_add(1, std::memory_order_relaxed);
          std::printf("[%s] DESYNC-LINE %s\n", mLabel.c_str(), message.c_str());
          std::fflush(stdout);
        }
      }

      [[nodiscard]] int Mismatches() const noexcept { return mMismatches.load(std::memory_order_relaxed); }

    private:
      std::string mLabel;
      std::atomic<int> mMismatches{0};
    };

    ChecksumLogWatch* gChecksumWatch = nullptr;

    // The world session's client-manager callbacks (chat, disconnects, speed changes) have no
    // one to tell here; the client manager calls some of them without a null check.
    class ReplayClientEvents final : public moho::IClientMgrUIInterface
    {};

    ReplayClientEvents gReplayClientEvents;

    [[nodiscard]] bool IsZero(const gpg::MD5Digest& digest) noexcept
    {
      return (digest.vals[0] | digest.vals[1] | digest.vals[2] | digest.vals[3]) == 0u;
    }

    /** Whether this beat's Lua `Sync` table says the game ended, as the UI's `OnSync` sees it. */
    [[nodiscard]] bool SyncSaysGameEnded(moho::SSyncData& packet, LuaPlus::LuaState* const state)
    {
      if (packet.mStream == nullptr || state == nullptr) {
        return false;
      }
      gpg::BinaryReader syncReader(packet.mStream);
      LuaPlus::LuaObject currentSync;
      currentSync.SCR_FromByteStream(currentSync, state, &syncReader);
      if (currentSync.IsNil()) {
        return false;
      }
      const LuaPlus::LuaObject gameEnded = currentSync["GameEnded"];
      return !gameEnded.IsNil() && (!gameEnded.IsBoolean() || gameEnded.GetBoolean());
    }

    /**
     * The world session's loading steps that the sim needs (`WLD_DoPreload`, `WLD_DoLoading`):
     * the session loader builds rules, session Lua state and map on its worker thread.
     */
    [[nodiscard]] bool LoadScenario(moho::SWldSessionInfo& sessionInfo, moho::SWldGameData& gameData, std::string& error)
    {
      moho::CWldSessionLoaderImpl* const loader = moho::GetWldSessionLoader();
      moho::LaunchInfoBase* const launchInfo = sessionInfo.mLaunchInfo.get();
      if (loader == nullptr || launchInfo == nullptr) {
        error = "no session loader or launch info";
        return false;
      }

      (void)loader->GetScenarioInfo(sessionInfo.mMapName.raw_data_unsafe(), &launchInfo->mGameMods, true);
      while (true) {
        // `WLD_DoLoading` beats the client manager every frame while the map loads.
        if (sessionInfo.mClientManager != nullptr) {
          sessionInfo.mClientManager->DoBeat();
        }
        loader->Update();
        if (loader->IsLoaded()) {
          break;
        }
        ::Sleep(5);
      }

      (void)loader->LoadGameData(&gameData);
      if (gameData.mGameRules == nullptr || gameData.mWldMap == nullptr || gameData.mState == nullptr) {
        error = "map " + std::string(sessionInfo.mMapName.c_str()) + " failed to load";
        return false;
      }
      return true;
    }
  } // namespace

  void InstallChecksumWatch(const std::string& label)
  {
    if (gChecksumWatch == nullptr) {
      gChecksumWatch = new ChecksumLogWatch(label);
    }
  }

  int ChecksumMismatchCount() noexcept
  {
    return gChecksumWatch != nullptr ? gChecksumWatch->Mismatches() : 0;
  }

  SReplayResult RunReplay(const SReplayOptions& options)
  {
    SReplayResult result{};
    const Clock::time_point loadStart = Clock::now();
    const char* const label = options.label.c_str();

    msvc8::auto_ptr<moho::SWldSessionInfo> sessionInfo = moho::VCR_SetupReplaySession(options.replayPath.c_str());
    if (sessionInfo.get() == nullptr) {
      result.error = "cannot open the replay, or its game version is not supported";
      return result;
    }

    moho::LaunchInfoBase* const launchInfo = sessionInfo->mLaunchInfo.get();
    const int armyCount = static_cast<int>(launchInfo->mArmyLaunchInfo.size());
    if (options.focusArmy < -1 || options.focusArmy >= armyCount) {
      result.error = "focus army out of range (the replay has " + std::to_string(armyCount) + " armies)";
      return result;
    }

    if (sessionInfo->mClientManager != nullptr) {
      sessionInfo->mClientManager->SetUIInterface(&gReplayClientEvents);
    }

    moho::SWldGameData gameData{};
    if (!LoadScenario(*sessionInfo, gameData, result.error)) {
      moho::ReleaseWldGameDataHandles(&gameData);
      return result;
    }

    // `WLD_DoLoading`: the game version (and with it the engine patches) is fixed before the
    // driver creates the sim.
    moho::FAF_BeginSession(sessionInfo->mIsReplay);

    // The session keeps these for the whole game; so does this run.
    std::unique_ptr<LuaPlus::LuaState> sessionState(gameData.mState);
    std::unique_ptr<moho::RRuleGameRules> rules(gameData.mGameRules);
    std::unique_ptr<moho::CWldMap> wldMap(gameData.mWldMap);
    gameData = moho::SWldGameData{};

    // The launch info, completed as `WLD_DoLoading` completes it from the world session.
    moho::STIMap* const launchMap = new moho::STIMap(wldMap->mTerrainRes->mMap);
    launchInfo->mGameRules = rules.get();
    if (launchInfo->mMap != nullptr && launchInfo->mMap != launchMap) {
      delete launchInfo->mMap;
    }
    launchInfo->mMap = launchMap;
    launchInfo->mLanguage.assign_owned(sessionState->GetGlobal("__language").ToString());
    if (moho::LaunchInfoNew* const newLaunchInfo = launchInfo->GetNew(); newLaunchInfo != nullptr) {
      newLaunchInfo->mProps = wldMap->mProps;
    }

    // The focus army: the sim and the driver both start from the launch info's original
    // source, which a lockstep client sets to its own army (CLobby::LaunchGame) and a replay
    // viewer to -1.
    launchInfo->mCommandSources.mOriginalSource = options.focusArmy;

    if (options.checksumPeriod > 0) {
      moho::gSimConVar_sim_ChecksumPeriod.mDefaultValue = options.checksumPeriod;
    }
    // A replay's lead, with no clock: the sim runs as fast as this thread takes its beats.
    moho::sim_LeadOnSchedule = 0;
    if (options.replayLead >= 0) {
      moho::sim_ReplayLead = options.replayLead;
    }

    moho::IClientManager* const clientManager = sessionInfo->mClientManager;
    sessionInfo->mClientManager = nullptr;
    moho::SIM_SetSessionPacing(moho::ESimSessionPacing::Replay);
    std::unique_ptr<moho::ISTIDriver> driver(moho::SIM_CreateDriver(
      static_cast<moho::CClientManagerImpl*>(clientManager), nullptr, sessionInfo->mLaunchInfo, sessionInfo->mSourceId
    ));
    auto* const simDriver = static_cast<moho::CSimDriver*>(driver.get());
    result.loadSeconds = SecondsSince(loadStart);
    std::printf("[%s] loaded in %.1fs: %d armies, focus %d\n", label, result.loadSeconds, armyCount, options.focusArmy);
    std::fflush(stdout);

    std::FILE* digestFile = nullptr;
    if (!options.digestPath.empty() && fopen_s(&digestFile, options.digestPath.c_str(), "w") != 0) {
      digestFile = nullptr;
      result.error = "cannot write " + options.digestPath;
      return result;
    }

    LuaPlus::LuaState* const syncState = moho::USER_GetLuaState();
    const Clock::time_point playStart = Clock::now();
    const double timeLimit = 60.0 * options.timeoutMinutes;
    double lastReport = 0.0;
    bool ready = false;
    const HANDLE syncAvailable = driver->GetSyncDataAvailableEvent();

    while (!result.gameOver) {
      const double elapsed = SecondsSince(playStart);
      if (elapsed > timeLimit) {
        result.timedOut = true;
        break;
      }
      if (simDriver->DiagDriverState() == moho::EDriverState::Failed) {
        result.crashed = true;
        result.error = "the sim driver failed";
        break;
      }

      driver->Dispatch();
      if (!driver->HasSyncData()) {
        // `WLD_DoPostInitializing` / `WLD_DoWaiting`: the first beat is out and this client
        // is ready; once every client is, the issue thread may run.
        if (result.started && !ready) {
          if (moho::CClientManagerImpl* const manager = driver->GetClientManager();
              manager != nullptr && manager->IsEveryoneReady()) {
            driver->DecrementOutstandingRequestsAndSignal();
            ready = true;
          }
        }
        (void)::WaitForSingleObject(syncAvailable, 50);
        continue;
      }

      while (driver->HasSyncData()) {
        moho::SSyncData* rawPacket = nullptr;
        driver->GetSyncData(rawPacket);
        std::unique_ptr<moho::SSyncData> packet(rawPacket);
        if (!packet) {
          continue;
        }

        ++result.beats;
        result.lastBeat = packet->mCurBeat;
        result.desyncReports += static_cast<int>(packet->mDesyncs.size());

        if (digestFile != nullptr) {
          const moho::Sim* const sim = simDriver->GetSimForReplayCheck();
          if (sim != nullptr && packet->mCurBeat >= 0) {
            const gpg::MD5Digest& digest = sim->mSimHashes[static_cast<std::uint32_t>(packet->mCurBeat) & 0x7Fu];
            if (!IsZero(digest)) {
              std::fprintf(digestFile, "%d %s\n", packet->mCurBeat, digest.ToString().c_str());
              ++result.digestsWritten;
            }
          }
        }

        if (!result.gameEnded && SyncSaysGameEnded(*packet, syncState)) {
          result.gameEnded = true;
          std::printf("[%s] GAME-ENDED beat %d\n", label, packet->mCurBeat);
          std::fflush(stdout);
        }
        if (packet->mGameOver) {
          result.gameOver = true;
        }

        if (!result.started) {
          // `WLD_DoInitializing`: the first beat is applied, then this client declares itself
          // ready.
          result.started = true;
          if (moho::CClientManagerImpl* const manager = driver->GetClientManager(); manager != nullptr) {
            manager->Cleanup();
          }
        }
      }

      if (elapsed - lastReport >= 30.0) {
        lastReport = elapsed;
        const int gameSeconds = result.lastBeat > 0 ? result.lastBeat / 10 : 0;
        std::printf(
          "[%s] beat %d game time %02d:%02d:%02d after %.0fs\n",
          label,
          result.lastBeat,
          gameSeconds / 3600,
          (gameSeconds / 60) % 60,
          gameSeconds % 60,
          elapsed
        );
        std::fflush(stdout);
      }
    }

    result.playSeconds = SecondsSince(playStart);
    result.mismatches = ChecksumMismatchCount();
    if (digestFile != nullptr) {
      std::fclose(digestFile);
    }
    // The driver, sim and session objects are left to the process exit: the caller ends the
    // process once the verdict is out, as nothing after it is observed.
    (void)driver.release();
    (void)sessionState.release();
    (void)rules.release();
    (void)wldMap.release();
    return result;
  }
} // namespace faf::replay
