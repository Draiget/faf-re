#include "headless/ReplayRunner.h"
#include "headless/ReplayLuaState.h"
#include "headless/ReplaySyncWriters.h"

#if FAF_SERVER_MODE
#include "remote/client/LoopbackLink.h"
#endif

#include <Windows.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <map>
#include <type_traits>
#include <memory>

#include "gpg/core/algorithms/MD5.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "lua/LuaTableIterator.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/misc/SessionStartup.h"
#include "moho/render/CDecalTypes.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/net/CClientManagerImpl.h"
#include "moho/net/IClientMgrUIInterface.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/CWldSessionLoaderImpl.h"
#include "moho/sim/FafGameVersion.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/sim/SSTIArmyConstantData.h"
#include "moho/sim/SSTIArmyVariableData.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimDebugCommandRegistrations.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/WldSessionInfo.h"
#include "moho/unit/core/Unit.h"
#include "headless/ReplayBoneStats.h"
#include "headless/ReplayFpuReport.h"
#if FAF_SERVER_MODE
// The wire format and the remote client (src/remote), built only with FAF_SERVER_MODE:
// --wire-stats, --loopback and --command-check (docs/SWITCHES.md, "headless").
#include "headless/ReplayCommandCheck.h"
#include "headless/ReplayChangeSetCheck.h"
#include "headless/ReplayOracleCheck.h"
#include "headless/ReplayViewFrameStats.h"
#include "headless/ReplayViewPacketCheck.h"
#include "headless/ReplayWireStats.h"
#include "remote/ContentTables.h"
#endif

namespace faf::headless
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

    /** When and how often one top-level `Sync` key was present. */
    struct SSyncKeySeen
    {
      int beats = 0;
      int firstBeat = -1;
      int lastBeat = -1;
    };

    /**
     * Decodes this beat's Lua `Sync` table as the UI's `DoBeat` does, and reports whether it
     * says the game ended. With `keys` set, every top-level key is counted.
     */
    [[nodiscard]] bool InspectSync(
      moho::SSyncData& packet, LuaPlus::LuaState* const state, std::map<std::string, SSyncKeySeen>* const keys
    )
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
      if (keys != nullptr) {
        for (LuaPlus::LuaTableIterator it(currentSync, 1); !it.m_isDone; it.Next()) {
          const LuaPlus::LuaObject key = it.GetKey();
          const char* const text = key.IsString() ? key.GetString() : key.ToString();
          SSyncKeySeen& seen = (*keys)[text != nullptr ? text : "?"];
          if (seen.firstBeat < 0) {
            seen.firstBeat = packet.mCurBeat;
          }
          seen.lastBeat = packet.mCurBeat;
          ++seen.beats;
        }
      }
      const LuaPlus::LuaObject gameEnded = currentSync["GameEnded"];
      return !gameEnded.IsNil() && (!gameEnded.IsBoolean() || gameEnded.GetBoolean());
    }

    /**
     * A digest of what the sim published in one beat, independent of `sim_ChecksumPeriod` and
     * never touching the sim's checksum context: creations, every entity and unit update,
     * deletions, every army's economy, and the Lua `Sync` bytes. Desync reports are left out
     * (they depend on the checksum period by design). 64-bit FNV-1a, field by field.
     */
    class CStateDigest
    {
    public:
      template <typename T>
      void Add(const T& value) noexcept
      {
        static_assert(std::is_arithmetic_v<T> || std::is_enum_v<T>);
        Bytes(&value, sizeof(value));
      }

      void Bytes(const void* const data, const std::size_t size) noexcept
      {
        const auto* const bytes = static_cast<const unsigned char*>(data);
        for (std::size_t i = 0; i < size; ++i) {
          mHash ^= bytes[i];
          mHash *= 0x100000001B3ull;
        }
      }

      void Text(const char* const text) noexcept { Bytes(text, text != nullptr ? std::strlen(text) + 1u : 0u); }

      [[nodiscard]] std::uint64_t Value() const noexcept { return mHash; }

    private:
      std::uint64_t mHash = 0xCBF29CE484222325ull;
    };

    void AddTransform(CStateDigest& digest, const moho::VTransform& transform) noexcept
    {
      digest.Add(transform.orient_.x);
      digest.Add(transform.orient_.y);
      digest.Add(transform.orient_.z);
      digest.Add(transform.orient_.w);
      digest.Add(transform.pos_.x);
      digest.Add(transform.pos_.y);
      digest.Add(transform.pos_.z);
    }

    [[nodiscard]] std::uint64_t DigestPublishedState(const moho::SSyncData& packet)
    {
      CStateDigest digest;
      digest.Add(packet.mCurBeat);
      digest.Add(packet.mCurTick);
      for (const moho::SCreateEntityParams& params : packet.mNewEntities) {
        digest.Add(params.mEntityId);
        digest.Text(params.mBlueprint != nullptr ? params.mBlueprint->mBlueprintId.c_str() : nullptr);
      }
      for (const moho::SCreateUnitParams& params : packet.mNewUnits) {
        digest.Add(params.mEntityId);
        digest.Text(params.mBlueprint != nullptr ? params.mBlueprint->mBlueprintId.c_str() : nullptr);
      }
      for (const moho::SEntityVariableUpdateEntry& update : packet.mEntityUpdates) {
        const moho::SSTIEntityVariableData& data = update.mVariableData;
        digest.Add(update.mEntityId);
        digest.Add(data.mScale.x);
        digest.Add(data.mScale.y);
        digest.Add(data.mScale.z);
        digest.Add(data.mHealth);
        digest.Add(data.mMaxHealth);
        digest.Add(data.mIsBeingBuilt);
        digest.Add(data.mIsDead);
        digest.Add(data.mDestroyedByKill);
        AddTransform(digest, data.mCurTransform);
        AddTransform(digest, data.mLastTransform);
        digest.Add(data.mCurImpactValue);
        digest.Add(data.mFractionComplete);
        digest.Add(data.mAttachmentParentRef);
        digest.Add(data.mVisibilityHidden);
        digest.Add(data.mVisibilityMode);
        digest.Add(data.mLayerMask);
      }
      for (const moho::SUnitVariableUpdateEntry& update : packet.mUnitUpdates) {
        const moho::SSTIUnitVariableData& data = update.mVariableData;
        digest.Add(update.mEntityId);
        digest.Add(update.mReconFlags);
        digest.Add(data.mCreator);
        digest.Add(data.mAutoMode);
        digest.Add(data.mIsBusy);
        digest.Add(data.mFuelRatio);
        digest.Add(data.mShieldRatio);
        digest.Add(data.mStunTicks);
        digest.Add(data.mIsPaused);
        digest.Add(data.mJobType);
        digest.Add(data.mFireState);
        digest.Add(data.mWorkProgress);
        digest.Add(data.mTacticalSiloBuildCount);
        digest.Add(data.mNukeSiloBuildCount);
        digest.Add(data.mTacticalSiloStorageCount);
        digest.Add(data.mNukeSiloStorageCount);
        digest.Add(data.mProduced.ENERGY);
        digest.Add(data.mProduced.MASS);
        digest.Add(data.mResourcesSpent.ENERGY);
        digest.Add(data.mResourcesSpent.MASS);
        digest.Add(data.mMaintainenceCost.ENERGY);
        digest.Add(data.mMaintainenceCost.MASS);
        digest.Add(data.mFocusUnit);
        digest.Add(data.mGuardedUnit);
        digest.Add(data.mTargetBlip);
        digest.Add(data.mScriptbits);
        digest.Add(data.mUnitStates);
      }
      for (const moho::EntId id : packet.mEraseIds) {
        digest.Add(id);
      }
      for (const moho::EntId id : packet.mDeleteIds) {
        digest.Add(id);
      }
      for (const moho::SSTIArmyVariableData& army : packet.mArmyUpdates) {
        const moho::SEconTotals& economy = army.mEconomyTotals;
        for (const auto* pair : {&economy.mStored, &economy.mIncome, &economy.mReclaimed, &economy.mLastUseRequested,
                                 &economy.mLastUseActual}) {
          digest.Add(pair->ENERGY);
          digest.Add(pair->MASS);
        }
        digest.Add(economy.mMaxStorage.ENERGY);
        digest.Add(economy.mMaxStorage.MASS);
      }
      // The Lua `Sync` bytes, read whole and rewound for the decode that follows.
      if (packet.mStream != nullptr) {
        char buffer[4096];
        for (;;) {
          const std::size_t read = packet.mStream->Read(buffer, sizeof(buffer));
          if (read == 0) {
            break;
          }
          digest.Bytes(buffer, read);
        }
        (void)packet.mStream->VirtSeek(gpg::Stream::ModeReceive, gpg::Stream::OriginBegin, 0);
      }
      return digest.Value();
    }

    /** The Lua `Sync` payload's size in bytes, leaving the stream at its start. */
    [[nodiscard]] std::uint64_t SyncStreamBytes(const moho::SSyncData& packet)
    {
      if (packet.mStream == nullptr) {
        return 0;
      }
      const std::uint64_t end = packet.mStream->VirtSeek(gpg::Stream::ModeReceive, gpg::Stream::OriginEnd, 0);
      (void)packet.mStream->VirtSeek(gpg::Stream::ModeReceive, gpg::Stream::OriginBegin, 0);
      return end;
    }

    constexpr const char* kLaneSizesHeader =
      "beat,new_entities,new_units,entity_updates,unit_updates,delete_ids,erase_ids,army_updates,new_grids,"
      "command_new,command_updates,command_removed,command_released,decals_add,decals_remove,cam_shakes,"
      "cam_follows,pose_updates,audio_requests,playable_rects,print_lines,extra_unit_data,desyncs,"
      "entity_update_bytes,unit_update_bytes,army_update_bytes,lua_sync_bytes\n";

    /** One CSV row of per-lane element counts and the in-memory bytes of the big lanes (M0.2). */
    void WriteLaneSizes(std::FILE* const file, const moho::SSyncData& packet)
    {
      std::fprintf(
        file,
        "%d,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%llu\n",
        packet.mCurBeat, packet.mNewEntities.size(), packet.mNewUnits.size(), packet.mEntityUpdates.size(),
        packet.mUnitUpdates.size(), packet.mDeleteIds.size(), packet.mEraseIds.size(), packet.mArmyUpdates.size(),
        packet.mNewGrids.size(), packet.mPublishedCommandDescriptors.size(), packet.mPublishedCommandPackets.size(),
        packet.mPendingCommandEventRemovals.size(), packet.mPendingReleasedCommandIds.size(), packet.mAddDecals.size(),
        packet.mRemoveDecals.size(), packet.mCamShakeParams.size(), packet.mFollowCameras.size(),
        packet.mPoseUpdates.size(), static_cast<std::size_t>(packet.mAudioRequests.end() - packet.mAudioRequests.begin()),
        packet.mPlayableRectUpdates.size(), packet.mPrintField.size(), packet.mSyncExtraUnitData.size(),
        packet.mDesyncs.size(), packet.mEntityUpdates.size() * sizeof(moho::SEntityVariableUpdateEntry),
        packet.mUnitUpdates.size() * sizeof(moho::SUnitVariableUpdateEntry),
        packet.mArmyUpdates.size() * sizeof(moho::SSTIArmyVariableData),
        static_cast<unsigned long long>(SyncStreamBytes(packet))
      );
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

    // Plan WPL.16: the blueprints in the order the rules loaded them (their ordinals), to
    // compare between platforms.
    if (!options.blueprintOrderPath.empty()) {
      std::FILE* orderFile = nullptr;
      if (fopen_s(&orderFile, options.blueprintOrderPath.c_str(), "w") != 0 || orderFile == nullptr) {
        result.error = "cannot write " + options.blueprintOrderPath;
        return result;
      }
      int ordinal = 0;
      for (; const moho::RBlueprint* const blueprint = rules->GetBlueprintFromOrdinal(ordinal); ++ordinal) {
        std::fprintf(orderFile, "%d %s\n", ordinal, blueprint->mBlueprintId.c_str());
      }
      std::fclose(orderFile);
      std::printf("[%s] blueprint order: %d blueprints written to %s\n", label, ordinal, options.blueprintOrderPath.c_str());
    }

#if FAF_SERVER_MODE
    // The wire format's content tables (plan WP7.2), as a server or client builds them at load.
    const faf::remote::wire::SContentTables tables = faf::remote::BuildContentTables(*rules);
    {
      std::printf(
        "[%s] content: %u blueprints, %u meshes, hash %016llx\n",
        label,
        tables.blueprints.Size(),
        tables.meshes.Size(),
        static_cast<unsigned long long>(tables.Hash())
      );
    }
#endif
    gameData = moho::SWldGameData{};

    // The launch info, completed as `WLD_DoLoading` completes it from the world session.
    moho::STIMap* const launchMap = new moho::STIMap(wldMap->mTerrainRes->mMap);
    const Wm3::AxisAlignedBox3f mapBounds = launchMap->GetBounds3D(); // the sim takes the map
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
    if (!options.luaPairsPath.empty()) {
      moho::sim_LuaPairsDumpPath = options.luaPairsPath.c_str();
    }

    // `--sync-writers`: the Sync write recorder goes in before the sim (and its scripts) exist.
    CSyncWriters syncWriters;
    const bool attributeSyncWrites = !options.syncWritersPath.empty();
    if (attributeSyncWrites) {
      syncWriters.Enable();
    }

#if FAF_SERVER_MODE
    // `--command-check`: watches the sim's decoder from its first message.
    std::unique_ptr<CReplayCommandCheck> commandCheck;
    if (options.commandCheck) {
      commandCheck = std::make_unique<CReplayCommandCheck>(*rules);
      commandCheck->Install();
    }

    // `--oracle-check`: after every `Sim::Sync`, on the sim's thread.
    std::unique_ptr<CReplayOracleCheck> oracleCheck;
    if (options.oracleCheck) {
      oracleCheck = std::make_unique<CReplayOracleCheck>(options.oracleDigestsPath);
      if (!oracleCheck->IsOpen()) {
        result.error = "cannot write " + options.oracleDigestsPath;
        return result;
      }
      oracleCheck->Install();
    }

    // `--changeset-check`: the sync walk's observer too, so not with `--oracle-check`.
    std::unique_ptr<CReplayChangeSetCheck> changeSetCheck;
    if (options.changeSetCheck) {
      changeSetCheck = std::make_unique<CReplayChangeSetCheck>();
      changeSetCheck->Install();
    }

    // `--view-packets`: the sync walk's observer as well.
    std::unique_ptr<CReplayViewPacketCheck> viewPackets;
    if (!options.viewPacketsPath.empty()) {
      viewPackets = std::make_unique<CReplayViewPacketCheck>(options.viewPacketsArmy, options.viewPacketsPath);
      if (!viewPackets->IsOpen()) {
        result.error = "cannot write " + options.viewPacketsPath;
        return result;
      }
      viewPackets->Install();
    }

    // `--view-frames`: the sync walk's observer as well.
    std::unique_ptr<CReplayViewFrameStats> viewFrames;
    if (!options.viewFramesPath.empty()) {
      viewFrames = std::make_unique<CReplayViewFrameStats>(
        options.viewFramesPath, tables, mapBounds.Max.x - mapBounds.Min.x, mapBounds.Max.z - mapBounds.Min.z
      );
      if (!viewFrames->IsOpen()) {
        result.error = "cannot write " + options.viewFramesPath;
        return result;
      }
      viewFrames->Install();
    }
#endif

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
    std::FILE* stateDigestFile = nullptr;
    std::FILE* laneSizesFile = nullptr;
    if (!options.laneSizesPath.empty()) {
      if (fopen_s(&laneSizesFile, options.laneSizesPath.c_str(), "w") != 0) {
        laneSizesFile = nullptr;
        result.error = "cannot write " + options.laneSizesPath;
        return result;
      }
      std::fputs(kLaneSizesHeader, laneSizesFile);
    }
    if (!options.stateDigestPath.empty() && fopen_s(&stateDigestFile, options.stateDigestPath.c_str(), "w") != 0) {
      stateDigestFile = nullptr;
      result.error = "cannot write " + options.stateDigestPath;
      return result;
    }
    if (!options.digestPath.empty() && fopen_s(&digestFile, options.digestPath.c_str(), "w") != 0) {
      digestFile = nullptr;
      result.error = "cannot write " + options.digestPath;
      return result;
    }

    std::unique_ptr<CReplayBoneStats> boneStats;
    if (!options.boneStatsPath.empty()) {
      boneStats = std::make_unique<CReplayBoneStats>(options.boneStatsPath);
      if (!boneStats->IsOpen()) {
        result.error = "cannot write " + options.boneStatsPath;
        return result;
      }
    }
#if FAF_SERVER_MODE
    std::unique_ptr<CReplayWireStats> wireStats;
    if (!options.wireStatsPath.empty()) {
      wireStats = std::make_unique<CReplayWireStats>(
        options.wireStatsPath, tables, mapBounds.Max.x - mapBounds.Min.x, mapBounds.Max.z - mapBounds.Min.z
      );
      if (!wireStats->IsOpen()) {
        result.error = "cannot write " + options.wireStatsPath;
        return result;
      }
    }

    // `--loopback`: every packet through the wire format and the client's rebuild, after the
    // consumers above have seen the sim's own packet.
    std::unique_ptr<faf::remote::client::CLoopbackLink> loopback;
    // The remote client's client manager, answering from the roster the link sends (WP11.4).
    std::unique_ptr<faf::remote::client::CRemoteClientManager> rosterFacade;
    if (options.loopback) {
      faf::remote::client::SLoopbackOptions loopbackOptions{};
      loopbackOptions.deadReckoningTolerance = static_cast<std::uint32_t>(options.loopbackDeadReckoning);
      loopbackOptions.orientationTolerance = static_cast<std::uint32_t>(options.loopbackTurnTolerance);
      loopback = std::make_unique<faf::remote::client::CLoopbackLink>(
        *rules,
        faf::remote::client::MakeLoopbackCodec(
          mapBounds.Max.x - mapBounds.Min.x, mapBounds.Max.z - mapBounds.Min.z, loopbackOptions
        ),
        loopbackOptions
      );
    }
#endif

    LuaPlus::LuaState* const syncState = ReplayLuaState();
    std::map<std::string, SSyncKeySeen> syncKeys;
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

        if (laneSizesFile != nullptr) {
          WriteLaneSizes(laneSizesFile, *packet);
        }
        if (stateDigestFile != nullptr) {
          std::fprintf(
            stateDigestFile, "%d %016llx\n", packet->mCurBeat,
            static_cast<unsigned long long>(DigestPublishedState(*packet))
          );
        }
        const bool syncSaysEnded =
          InspectSync(*packet, syncState, options.syncKeysPath.empty() ? nullptr : &syncKeys);
        if (!result.gameEnded && syncSaysEnded) {
          result.gameEnded = true;
          std::printf("[%s] GAME-ENDED beat %d\n", label, packet->mCurBeat);
          std::fflush(stdout);
        }
#if FAF_SERVER_MODE
        if (wireStats) {
          wireStats->OnPacket(*packet);
        }
#endif
        if (options.fpuReport && result.fpuReport.empty() && packet->mCurBeat >= 1) {
          result.fpuReport = ReportThreadFloatingPointState(40, 25);
        }
        if (boneStats) {
          boneStats->OnPacket(*packet);
        }
        if (packet->mGameOver) {
          result.gameOver = true;
        }
#if FAF_SERVER_MODE
        if (loopback) {
          if (moho::CClientManagerImpl* const standIn = driver->GetClientManager(); standIn != nullptr) {
            loopback->SetServerSimRate(standIn->GetSimRate());
          }
          loopback->Pass(*packet);
          if (moho::CClientManagerImpl* const standIn = driver->GetClientManager(); standIn != nullptr) {
            if (!rosterFacade) {
              rosterFacade = std::make_unique<faf::remote::client::CRemoteClientManager>(nullptr, standIn);
            }
            loopback->PassRoster(*standIn, *rosterFacade);
          }
        }
#endif

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

#if FAF_SERVER_MODE
    // The sim's thread keeps running beats after a time limit ends the loop; the sync-walk
    // observers are read (and destroyed) below, so none of them may be called from here on.
    moho::Sim::SetSyncObserver(nullptr);
#endif
    result.playSeconds = SecondsSince(playStart);
    result.mismatches = ChecksumMismatchCount();
    if (digestFile != nullptr) {
      std::fclose(digestFile);
    }
    if (stateDigestFile != nullptr) {
      std::fclose(stateDigestFile);
    }
    if (laneSizesFile != nullptr) {
      std::fclose(laneSizesFile);
    }
    if (boneStats) {
      result.boneSummary = boneStats->Finish();
    }
    if (attributeSyncWrites) {
      result.syncWritersSummary = syncWriters.Write(options.syncWritersPath);
    }
#if FAF_SERVER_MODE
    if (wireStats) {
      result.wireSummary = wireStats->Summary();
    }
    if (loopback) {
      result.loopbackSummary = loopback->Summary("end");
      result.loopbackFailures = loopback->CheckFailures();
    }
    if (commandCheck) {
      result.commandSummary = commandCheck->Summary();
      result.commandFailures = commandCheck->Failures();
    }
    if (oracleCheck) {
      result.oracleSummary = oracleCheck->Summary();
      result.oracleFailures = oracleCheck->Failures();
    }
    if (changeSetCheck) {
      result.changeSetSummary = changeSetCheck->Summary();
      result.changeSetFailures = changeSetCheck->Failures();
    }
    if (viewPackets) {
      result.viewPacketsSummary = viewPackets->Summary();
    }
    if (viewFrames) {
      result.viewFramesSummary = viewFrames->Summary();
      result.viewFramesFailures = viewFrames->Failures();
    }
#endif
    if (!options.syncKeysPath.empty()) {
      std::FILE* keysFile = nullptr;
      if (fopen_s(&keysFile, options.syncKeysPath.c_str(), "w") == 0 && keysFile != nullptr) {
        std::fprintf(keysFile, "# key beats-present first-beat last-beat (of %d beats)\n", result.beats);
        for (const auto& [key, seen] : syncKeys) {
          std::fprintf(keysFile, "%s %d %d %d\n", key.c_str(), seen.beats, seen.firstBeat, seen.lastBeat);
        }
        std::fclose(keysFile);
      }
    }
    // The driver, sim and session objects are left to the process exit: the caller ends the
    // process once the verdict is out, as nothing after it is observed.
    (void)driver.release();
    (void)sessionState.release();
    (void)rules.release();
    (void)wldMap.release();
    return result;
  }
} // namespace faf::headless
