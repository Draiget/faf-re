#include "headless/ReplayRunner.h"
#include "headless/SessionLoad.h"
#include "headless/ReplayLuaState.h"
#include "headless/ReplaySyncWriters.h"

#if FAF_SERVER_MODE
#include "remote/client/LoopbackLink.h"
#endif

#include <Windows.h>
#if defined(_WIN32)
#include <Psapi.h>
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <map>
#include <string_view>
#include <type_traits>
#include <memory>

#include "gpg/core/algorithms/MD5.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "lua/LuaTableIterator.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/misc/CSaveGameRequestImpl.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/misc/SessionStartup.h"
#include "moho/render/CDecalTypes.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/net/CClientManagerImpl.h"
#include "moho/net/IClientMgrUIInterface.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/CWldSessionLoaderImpl.h"
#include "moho/sim/DesyncRecorder.h"
#include "moho/sim/FafGameVersion.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/sim/SSTIArmyConstantData.h"
#include "moho/sim/SSTIArmyVariableData.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimDebugCommandRegistrations.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/SimKeyframe.h"
#include "moho/sim/WldSessionInfo.h"
#include "moho/unit/core/Unit.h"
#include "headless/ReplayBoneStats.h"
#if FAF_SERVER_MODE
#include "headless/ReplaySeats.h"
#endif
#if FAF_HEADLESS_NET
#include "headless/ReplayTargetAudit.h"
#include "remote/net/UdpSocket.h"
#include "server/ServerNet.h"
#include "server/ServerViews.h"
#endif
#include "headless/ReplayFpuReport.h"
#include "headless/ReplayKeyframes.h"
#if FAF_SERVER_MODE
// The wire format and the remote client (src/remote), built only with FAF_SERVER_MODE:
// --wire-stats, --loopback and --command-check (docs/SWITCHES.md, "headless").
#include "headless/ReplayCommandCheck.h"
#include "headless/ReplayChangeSetCheck.h"
#include "headless/ReplayOracleCheck.h"
#include "headless/ReplayInboundCheck.h"
#include "headless/ReplayViewBench.h"
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

    /** This process's private bytes (Linux: resident), in MB. */
    [[nodiscard]] double ProcessMegabytes()
    {
#if defined(_WIN32)
      PROCESS_MEMORY_COUNTERS_EX counters{};
      counters.cb = sizeof(counters);
      if (::K32GetProcessMemoryInfo(
            ::GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters), sizeof(counters)
          )) {
        return static_cast<double>(counters.PrivateUsage) / 1048576.0;
      }
      return 0.0;
#else
      long pages = 0;
      long resident = 0;
      std::FILE* const statm = std::fopen("/proc/self/statm", "r");
      if (statm != nullptr) {
        if (std::fscanf(statm, "%ld %ld", &pages, &resident) != 2) {
          resident = 0;
        }
        std::fclose(statm);
      }
      return static_cast<double>(resident) * 4096.0 / 1048576.0;
#endif
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
        const fa::string& message,
        const fa::vector<fa::string>& context,
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

    /** Whether this beat's Lua `Sync` bytes contain `text` (read whole and rewound). */

    /**
     * Decodes this beat's Lua `Sync` table as the UI's `DoBeat` does, and reports whether it
     * says the game ended. With `keys` set, every top-level key is counted. A table that cannot
     * name the key is not decoded: the garbage of a whole game's decoding is tens of megabytes.
     */
    [[nodiscard]] bool InspectSync(
      moho::SSyncData& packet, LuaPlus::LuaState* const state, std::map<std::string, SSyncKeySeen>* const keys
    )
    {
      if (packet.mStream == nullptr || state == nullptr) {
        return false;
      }
      if (keys == nullptr && !SyncBytesContain(packet, "GameEnded")) {
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
        for (const moho::CmdId id : data.mCommands) {
          digest.Add(id);
        }
        for (const moho::CmdId id : data.mBuildQueue) {
          digest.Add(id);
        }
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

    // `--resume-from`: the keyframe's header says how far into the stream the session starts.
    boost::shared_ptr<std::FILE> keyframeFile;
    moho::SSimKeyframeHeader keyframeHeader{};
    if (!options.resumeFrom.empty()) {
      std::FILE* rawFile = nullptr;
      if (fopen_s(&rawFile, options.resumeFrom.c_str(), "rb") != 0 || rawFile == nullptr) {
        result.error = "cannot read " + options.resumeFrom;
        return result;
      }
      keyframeFile = boost::shared_ptr<std::FILE>(rawFile, moho::SFileStarCloser{});
      if (!moho::SIM_ReadKeyframeHeader(rawFile, keyframeHeader)) {
        result.error = options.resumeFrom + " is not a keyframe";
        return result;
      }
    }
    const int skipBeats = keyframeFile.get() != nullptr ? static_cast<int>(keyframeHeader.beat) - 1 : 0;
    if (keyframeFile.get() == nullptr) {
      moho::gSimBeatOrigin.store(0); // an earlier session in this process may have been restored
    }

    const bool liveRejoin = !options.rejoinPeers.empty();
    const bool rejoinRehearsal = options.rejoinSource >= 0 && !liveRejoin;
    std::unique_ptr<gpg::Stream> rejoinRecording;
    fa::auto_ptr<moho::SWldSessionInfo> sessionInfo;
    if (liveRejoin) {
      // Issue #275: as `CScApp` does for /rejoin, without a window to wait in.
      fa::string reason;
      bool failed = !moho::REJOIN_BeginSetup(
        options.rejoinPeers.c_str(), options.rejoinSource, static_cast<unsigned short>(options.rejoinPort), &reason
      );
      while (!failed && sessionInfo.get() == nullptr) {
        fa::auto_ptr<moho::SWldSessionInfo> polled = moho::REJOIN_PollSetup(&reason, &failed);
        if (polled.get() != nullptr) {
          sessionInfo = polled;
        } else if (!failed) {
          ::Sleep(20);
        }
      }
      if (failed) {
        result.error = std::string("the rejoin was refused: ") + reason.c_str();
        return result;
      }
    } else {
      sessionInfo = moho::VCR_SetupReplaySession(
        options.replayPath.c_str(), nullptr, rejoinRehearsal || options.seats ? &rejoinRecording : nullptr, skipBeats
      );
    }
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

    // Issue #275: this client's view of a live game, as `CLobby::LaunchGame` sets it up.
    if (rejoinRehearsal) {
      if (static_cast<std::size_t>(options.rejoinSource) >= launchInfo->mCommandSources.mSrcs.size()) {
        result.error = "--rejoin-source out of range";
        return result;
      }
      if (options.focusArmy < 0
          || !launchInfo->mArmyLaunchInfo[static_cast<std::size_t>(options.focusArmy)].mUnitSources.Contains(
            static_cast<unsigned int>(options.rejoinSource)
          )) {
        result.error = "--rejoin-source needs --focus on an army of that source";
        return result;
      }
      sessionInfo->mSourceId = static_cast<std::uint32_t>(options.rejoinSource);
      sessionInfo->mClientManager = moho::REJOIN_CreateRehearsalManager(
        *launchInfo, std::move(rejoinRecording), options.rejoinSource, options.rejoinBeat, skipBeats
      );
    }

#if FAF_SERVER_MODE
    // `--seats`: outlives the driver, whose manager calls it.
    std::unique_ptr<CReplaySeatFeed> seatFeed;
    if (options.seats) {
      if (skipBeats > 0 || options.rejoinSource >= 0 || liveRejoin) {
        result.error = "--seats plays a replay from its start, and not as a rejoin";
        return result;
      }
      moho::SIM_SetIssueWhilePaused(true);
      moho::CClientManagerImpl* seatManager = nullptr;
      seatFeed = std::make_unique<CReplaySeatFeed>(*launchInfo, std::move(rejoinRecording), seatManager);
      sessionInfo->mClientManager = seatManager;
    }
#endif
#if !FAF_HEADLESS_NET
    if (!options.seatsListen.empty()) {
      result.error = "--seats-listen needs the Linux build";
      return result;
    }
#endif
#if FAF_HEADLESS_NET
    // `--seats-listen`: the players' network on those seats. Nobody is waited for or put out: this
    // measures the load, and the recording goes on whoever is there.
    std::unique_ptr<faf::server::CServerNet> seatNet;
    if (seatFeed && !options.seatsListen.empty()) {
      faf::server::SServerNetConfig netConfig;
      if (!faf::remote::net::ParseEndpoint(options.seatsListen, netConfig.listen)) {
        result.error = "--seats-listen takes <ip:port>";
        return result;
      }
      netConfig.joinSeconds = 1.0e9;
      netConfig.reconnectSeconds = 1.0e9;
      netConfig.holdViewsForJoin = !options.targetAudit;
      seatNet = std::make_unique<faf::server::CServerNet>(netConfig);
      for (faf::remote::CServerClient* const seat : seatFeed->Seats()) {
        seatNet->AddSeat(seat->GetIndex(), seat->GetNickname().c_str(), "seat-" + std::to_string(seat->GetIndex()), *seat);
      }
      std::string netError;
      if (!seatNet->Start(netError)) {
        result.error = netError;
        return result;
      }
    }
#endif

    if (sessionInfo->mClientManager != nullptr) {
      sessionInfo->mClientManager->SetUIInterface(&gReplayClientEvents);
    }

    // Issue #217: a dump this run writes (`/desyncdumpbeat`) names the map and game mods, and
    // says it came from a replay, as a game's CWldSession would tell the recorder.
    moho::CDesyncRecorder::SetSessionInfo(
      sessionInfo->mMapName.c_str(), launchInfo->mGameMods.c_str(), true, sessionInfo->mIsMultiplayer
    );

    moho::SWldGameData gameData{};
    if (!LoadSessionScenario(*sessionInfo, gameData, result.error)) {
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
    moho::STIMap* const launchMap = CompleteSessionLaunchInfo(*sessionInfo, *rules, *wldMap, *sessionState);
    [[maybe_unused]] const Wm3::AxisAlignedBox3f mapBounds = launchMap->GetBounds3D(); // the sim takes the map

    // The focus army: the sim and the driver both start from the launch info's original
    // source, which a lockstep client sets to its own army (CLobby::LaunchGame) and a replay
    // viewer to -1.
    if (!liveRejoin) {
      launchInfo->mCommandSources.mOriginalSource = options.focusArmy;
    } else {
      moho::REJOIN_PrepareRestore(*sessionInfo);
    }

    // `--resume-from`: the same launch info, as `CSavedGame::CreateSinglePlayerSessionInfo` builds
    // a saved game's; the sim comes from the archive behind the header.
    if (keyframeFile.get() != nullptr) {
      boost::shared_ptr<moho::LaunchInfoLoad> loadInfo;
      (void)boost::ConstructSharedLaunchInfoLoadFromRaw(&loadInfo, new moho::LaunchInfoLoad());
      loadInfo->mGameRules = launchInfo->mGameRules;
      loadInfo->mMap = launchInfo->mMap;
      launchInfo->mMap = nullptr;
      loadInfo->mGameMods = launchInfo->mGameMods;
      loadInfo->mScenarioInfo = launchInfo->mScenarioInfo;
      loadInfo->mArmyLaunchInfo = launchInfo->mArmyLaunchInfo;
      loadInfo->mCommandSources = launchInfo->mCommandSources;
      loadInfo->mLanguage = launchInfo->mLanguage;
      loadInfo->mCheatsEnabled = launchInfo->mCheatsEnabled;
      loadInfo->mReadArchive = gpg::CreateBinaryReadArchive(keyframeFile);
      std::printf("[%s] resuming from beat %u, tick %u\n", label, keyframeHeader.beat, keyframeHeader.tick);
      std::fflush(stdout);
      moho::SIM_BeginKeyframeRestore(keyframeHeader);
      if (rejoinRehearsal) {
        // As REJOIN_PrepareRestore: this session's clients count in the game's own beats.
        moho::gSimBeatOrigin.store(0);
      }
      sessionInfo->mLaunchInfo = boost::static_pointer_cast<moho::LaunchInfoBase>(loadInfo);
    }

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
      viewPackets = std::make_unique<CReplayViewPacketCheck>(
        options.viewPacketsArmy, options.viewPacketsPath, options.viewPacketsEntriesPath,
        static_cast<std::uint32_t>(options.viewPacketsEntriesEvery)
      );
      if (!viewPackets->IsOpen()) {
        result.error = "cannot write " + options.viewPacketsPath
          + (options.viewPacketsEntriesPath.empty() ? "" : " or " + options.viewPacketsEntriesPath);
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
      if (options.viewIds) {
        viewFrames->EnableIdMaps();
      }
      viewFrames->SetParallel(options.parallelViews);
      if (options.spy) {
        viewFrames->EnableSpy();
      }
      viewFrames->SetChannel(
        static_cast<std::uint32_t>(options.viewLossPercent), static_cast<std::uint32_t>(options.viewAckDelay)
      );
      viewFrames->Install();
    }
    // `--view-bench`: the server's view work alone, timed (also a sync-walk observer).
    std::unique_ptr<CReplayViewBench> viewBench;
    std::FILE* viewDumpFile = nullptr; // left open: the sim may run on past this function's end
    if (!options.viewBenchPath.empty()) {
      viewBench = std::make_unique<CReplayViewBench>(
        options.viewBenchPath, tables, mapBounds.Max.x - mapBounds.Min.x, mapBounds.Max.z - mapBounds.Min.z, options.viewBenchCheck
      );
      if (!viewBench->IsOpen()) {
        result.error = "cannot write " + options.viewBenchPath;
        return result;
      }
      viewBench->SetParallel(options.parallelViews);
      viewBench->EnablePipeline(static_cast<unsigned int>(options.viewPipelineThreads));
      if (options.viewTeams) {
        viewBench->EnableTeamViews();
      }
      if (options.viewTables) {
        viewBench->EnableBenchTables();
        if (options.statsEvery > 0) {
          viewBench->SetStatsEveryBeats(static_cast<std::uint32_t>(options.statsEvery));
        }
      }
      if (!options.viewDumpPath.empty()) {
        viewDumpFile = std::fopen(options.viewDumpPath.c_str(), "wb");
        viewBench->SetViewDump(viewDumpFile);
      }
      if (options.luaRouting) {
        viewBench->EnableLuaRouting(options.luaRoutingDump);
        if (options.spy) {
          viewBench->EnableLuaSpy();
        }
        if (options.luaMoveBeat >= 0) {
          viewBench->AddLuaMove(options.luaMoveBeat, static_cast<std::size_t>(options.luaMoveView), options.luaMoveArmy);
        }
        if (options.luaResyncBeat >= 0) {
          viewBench->AddLuaResync(options.luaResyncBeat, static_cast<std::size_t>(options.luaResyncView));
        }
      }
      viewBench->Install();
    }
    // `--inbound-check`: the decoder's messages through view ids and back (with --view-ids).
    std::unique_ptr<CReplayInboundCheck> inboundCheck;
    if (options.inboundCheck && viewFrames) {
      inboundCheck = std::make_unique<CReplayInboundCheck>(*rules, *viewFrames);
      inboundCheck->Install();
    }
#endif

#if FAF_HEADLESS_NET
    std::unique_ptr<faf::server::CServerViews> seatViews;
    if (seatNet) {
      std::map<std::size_t, std::int32_t> players;
      const auto& armies = launchInfo->mArmyLaunchInfo;
      for (faf::remote::CServerClient* const seat : seatFeed->Seats()) {
        std::int32_t playerArmy = -1;
        for (std::size_t army = 0; army < armies.size(); ++army) {
          if (armies[army].mUnitSources.Contains(static_cast<unsigned int>(seat->GetIndex()))) {
            players[army] = seat->GetIndex();
            playerArmy = static_cast<std::int32_t>(army);
            break;
          }
        }
        seatNet->QueueView(
          seat->GetIndex(), faf::server::MakeGameInfo(mapBounds.Max.x - mapBounds.Min.x, mapBounds.Max.z - mapBounds.Min.z, playerArmy, static_cast<std::uint32_t>(seat->GetIndex()))
        );
      }
      seatViews = std::make_unique<faf::server::CServerViews>(
        tables, *rules, mapBounds.Max.x - mapBounds.Min.x, mapBounds.Max.z - mapBounds.Min.z, *seatNet, std::move(players),
        static_cast<unsigned int>(std::max(options.viewPipelineThreads, 1)), options.viewTeams
      );
      seatViews->Install();
    }
    std::unique_ptr<CReplayTargetAudit> targetAudit;
    if (seatViews && options.targetAudit) {
      targetAudit = std::make_unique<CReplayTargetAudit>(*rules, *seatViews);
      targetAudit->Install();
    }
#endif

    moho::IClientManager* const clientManager = sessionInfo->mClientManager;
    sessionInfo->mClientManager = nullptr;
    moho::SIM_SetSessionPacing(rejoinRehearsal || liveRejoin ? moho::ESimSessionPacing::Network : moho::ESimSessionPacing::Replay);
    std::unique_ptr<moho::ISTIDriver> driver(moho::SIM_CreateDriver(
      static_cast<moho::CClientManagerImpl*>(clientManager), nullptr, sessionInfo->mLaunchInfo, sessionInfo->mSourceId
    ));
    auto* const simDriver = static_cast<moho::CSimDriver*>(driver.get());
#if FAF_HEADLESS_NET
    // Ahead of the driver going away, on every way out: the network's thread touches its seats.
    struct SStopSeatNet
    {
      faf::server::CServerNet* net;
      ~SStopSeatNet()
      {
        if (net != nullptr) {
          net->Stop();
        }
      }
    } const stopSeatNet{seatNet.get()};
#endif
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

    // `--keyframe-every`: the sim saved between beats, as a saved game is.
    std::unique_ptr<CReplayKeyframes> keyframes;
    if (options.keyframeEvery > 0) {
      keyframes = std::make_unique<CReplayKeyframes>(
        options.keyframeDir, options.keyframeEvery, options.keyframeKeep || options.keyframePrepare, options.label, options.keyframeIndex
      );
    }

    if (keyframes) {
      keyframes->SetPreparing(options.keyframePrepare);
      if (options.keyframeFirst > 0) {
        keyframes->SetFirstBeat(options.keyframeFirst);
      }
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
    bool releasedScriptBlueprints = false;
    std::map<std::string, SSyncKeySeen> syncKeys;
    const Clock::time_point playStart = Clock::now();
    const double timeLimit = 60.0 * options.timeoutMinutes;
    double lastReport = 0.0;
    bool ready = false;
    const HANDLE syncAvailable = driver->GetSyncDataAvailableEvent();
    const double pacePeriod = options.paceMs / 1000.0;
    double nextPacedBeat = 0.0; // seconds of play: when the next beat may leave the queue
    int lateBeats = 0;
    double lateSeconds = 0.0;

    bool stopped = false;
    while (!result.gameOver && !stopped) {
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

      if (liveRejoin) {
        moho::REJOIN_MainFrame(*driver);
      }
      driver->Dispatch();
      // `--pace`: the issue thread tops up only past the last beat taken from the queue, so holding
      // the next one back holds the sim too.
      if (pacePeriod > 0.0 && ready) {
        const double waitSeconds = nextPacedBeat - SecondsSince(playStart);
        if (waitSeconds > 0.0) {
          ::Sleep(std::max(1, static_cast<int>(waitSeconds * 1000.0)));
          continue;
        }
      }
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
        if (packet->mCurBeat == options.focusSwitchBeat) {
          simDriver->SetPendingFocusArmyRaw(options.focusSwitchArmy);
        }
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
        // The first packet means the sim exists and has its copy of the blueprints.
        if (rules && !options.keepClientData && !releasedScriptBlueprints) {
          static_cast<moho::RRuleGameRulesImpl*>(rules.get())->ReleaseScriptBlueprints();
          releasedScriptBlueprints = true;
        }
        if (!options.syncDumpPath.empty() && packet->mStream != nullptr) {
          static bool sStarted = false;
          std::FILE* const dump = std::fopen(options.syncDumpPath.c_str(), sStarted ? "ab" : "wb");
          sStarted = true;
          if (dump != nullptr) {
            std::string bytes;
            char buffer[4096];
            for (std::size_t read = packet->mStream->Read(buffer, sizeof(buffer)); read != 0u; read = packet->mStream->Read(buffer, sizeof(buffer))) {
              bytes.append(buffer, read);
            }
            (void)packet->mStream->VirtSeek(gpg::Stream::ModeReceive, gpg::Stream::OriginBegin, 0);
            const std::uint32_t head[2] = {static_cast<std::uint32_t>(packet->mCurBeat), static_cast<std::uint32_t>(bytes.size())};
            std::fwrite(head, sizeof(head), 1u, dump);
            std::fwrite(bytes.data(), 1u, bytes.size(), dump);
            std::fclose(dump);
          }
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
        if (keyframes && !packet->mGameOver) {
          keyframes->OnBeat(*driver, simDriver->GetSimForReplayCheck(), packet->mCurBeat);
        }
        if (packet->mGameOver) {
          result.gameOver = true;
        }
#if FAF_SERVER_MODE
#if FAF_HEADLESS_NET
        if (seatNet) {
          seatNet->NoteBeat(packet->mCurBeat);
          for (const std::string& line : seatNet->TakeNews()) {
            std::printf("[%s] beat %d: %s\n", label, packet->mCurBeat, line.c_str());
            std::fflush(stdout);
          }
        }
#endif
        // With every source gone before its end, a recording has nobody left to end the game.
        if (seatFeed && packet->mCurBeat > seatFeed->LastBeat() + 1) {
          stopped = true;
        }
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

        // The sim's thread keeps running beats after the game-over packet. Packets it queued
        // meanwhile are not part of the game, and how many there are depends on thread timing.
        if (result.gameOver) {
          break;
        }

        if (options.stopAfter && options.stopAfter(packet->mCurBeat)) {
          stopped = true;
          break;
        }

        if (pacePeriod > 0.0 && ready) {
          // A game that lost time doesn't get it back: the next beat is one period from here.
          const double now = SecondsSince(playStart);
          const double late = now - nextPacedBeat;
          if (late > 0.002 && nextPacedBeat > 0.0) {
            ++lateBeats;
            lateSeconds += late;
          }
          nextPacedBeat = (late > 0.002 ? now : nextPacedBeat) + pacePeriod;
          break;
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

    // A session about to go first finishes the keyframe it asked for: the request reports to `keyframes`.
    const Clock::time_point tearDownStart = Clock::now();
    while (options.tearDown && keyframes && keyframes->Pending() && SecondsSince(tearDownStart) < 120.0) {
      driver->Dispatch();
      while (driver->HasSyncData()) {
        moho::SSyncData* rawPacket = nullptr;
        driver->GetSyncData(rawPacket);
        delete rawPacket;
      }
      (void)::WaitForSingleObject(syncAvailable, 50);
    }
    result.mismatches = ChecksumMismatchCount();
#if FAF_SERVER_MODE
    if (seatFeed) {
      std::printf("[%s] %s\n", label, seatFeed->Report().c_str());
      std::fflush(stdout);
    }
#endif
#if FAF_HEADLESS_NET
    if (seatNet) {
      std::printf(
        "[%s] seat network: %.1f MB sent, %.1f KB/s, %llu view lanes failed\n", label, static_cast<double>(seatNet->BytesSent()) / 1048576.0,
        static_cast<double>(seatNet->BytesSent()) / 1024.0 / std::max(SecondsSince(playStart), 1.0),
        static_cast<unsigned long long>(seatViews ? seatViews->Failures() : 0u)
      );
      if (seatViews) {
        std::printf("[%s] %s\n[%s] %s\n", label, seatViews->LaneReport().c_str(), label, seatNet->Intake().Report().c_str());
      }
      if (targetAudit) {
        std::printf("[%s] %s\n", label, targetAudit->Summary().c_str());
      }
      std::fflush(stdout);
    }
#endif
    if (pacePeriod > 0.0) {
      std::printf("[%s] pace %d ms: %d of %d beats late, %.1f s lost\n", label, options.paceMs, lateBeats, result.beats, lateSeconds);
      std::fflush(stdout);
    }
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
    if (keyframes) {
      result.keyframeSummary = keyframes->Summary();
      result.keyframeFailures = keyframes->Failures();
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
    if (viewBench) {
      // Lua routing lives in the sim's Lua from here on, and the bench holds it: the sim can't run
      // on past this function, as it otherwise does until the process exits.
      if (options.luaRouting && !options.tearDown) {
        driver->ShutDown();
      }
      (void)viewBench->FinishViews();
      result.viewBenchSummary = viewBench->Summary();
      result.viewBenchFailures = viewBench->Failures();
    }
    if (inboundCheck) {
      result.inboundSummary = inboundCheck->Summary();
      result.inboundFailures = inboundCheck->Failures();
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
    // `WLD_Teardown`: the driver stops and gives up the packets it holds, the session's objects
    // go, then the driver with the sim.
    if (options.tearDown) {
      if (keyframes && keyframes->Pending()) {
        result.error = "a keyframe was still being saved after two minutes";
      } else {
        driver->ShutDown();
        while (driver->HasSyncData()) {
          moho::SSyncData* rawPacket = nullptr;
          driver->GetSyncData(rawPacket);
          delete rawPacket;
        }
        sessionState.reset();
        rules.reset();
        wldMap.reset();
        driver.reset();
        result.tearDownSeconds = SecondsSince(tearDownStart);
        return result;
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

  SReplayResult RunSeekPlan(const SReplayOptions& options, const std::vector<int>& plan)
  {
    const char* const label = options.label.c_str();
    std::map<int, std::string> keyframes;
    std::size_t step = 0;
    Clock::time_point seekStart = Clock::now();

    SReplayOptions run = options;
    run.tearDown = true;
    run.keyframeKeep = true;
    run.keyframeIndex = &keyframes;
    run.stopAfter = [&](const int beat) {
      if (step >= plan.size() || beat < plan[step]) {
        return false;
      }
      std::printf("[%s] seek %zu: at beat %d, %.2fs after it was asked for\n", label, step, beat, SecondsSince(seekStart));
      std::fflush(stdout);
      ++step;
      seekStart = Clock::now();
      if (step >= plan.size()) {
        return false;
      }
      if (plan[step] <= beat) {
        return true;
      }
      const auto after = keyframes.upper_bound(plan[step]);
      return after != keyframes.begin() && std::prev(after)->first > beat;
    };

    SReplayResult total{};
    total.started = true;
    for (int session = 0;; ++session) {
      if (!options.digestPath.empty()) {
        run.digestPath = options.digestPath + "." + std::to_string(session);
      }
      if (!options.stateDigestPath.empty()) {
        run.stateDigestPath = options.stateDigestPath + "." + std::to_string(session);
      }
      if (!options.laneSizesPath.empty()) {
        run.laneSizesPath = options.laneSizesPath + "." + std::to_string(session);
      }

      const SReplayResult result = RunReplay(run);
      std::printf(
        "[%s] seek session %d: up to beat %d, %d beats, load %.2fs, play %.1fs, teardown %.2fs, process %.0f MB\n",
        label, session, result.lastBeat, result.beats, result.loadSeconds, result.playSeconds, result.tearDownSeconds,
        ProcessMegabytes()
      );
      if (!result.keyframeSummary.empty()) {
        std::printf("[%s] %s\n", label, result.keyframeSummary.c_str());
      }
      std::fflush(stdout);

      total.started = total.started && result.started;
      total.gameOver = result.gameOver;
      total.gameEnded = result.gameEnded;
      total.timedOut = total.timedOut || result.timedOut;
      total.crashed = total.crashed || result.crashed;
      total.beats += result.beats;
      total.lastBeat = result.lastBeat;
      total.mismatches = result.mismatches;
      total.desyncReports += result.desyncReports;
      total.digestsWritten += result.digestsWritten;
      total.loadSeconds += result.loadSeconds;
      total.playSeconds += result.playSeconds;
      total.tearDownSeconds += result.tearDownSeconds;
      total.keyframeFailures += result.keyframeFailures;
      if (!result.error.empty() || result.timedOut || result.crashed || result.gameOver) {
        total.error = result.error;
        break;
      }

      const auto after = keyframes.upper_bound(plan[step]);
      run.resumeFrom = after != keyframes.begin() ? std::prev(after)->second : std::string{};
      seekStart = Clock::now();
      std::printf(
        "[%s] seek %zu: from beat %d to beat %d, by %s\n", label, step, result.lastBeat, plan[step],
        run.resumeFrom.empty() ? "the replay's start" : run.resumeFrom.c_str()
      );
      std::fflush(stdout);
    }
    if (step < plan.size()) {
      std::printf("[%s] seek: the game ended with %zu of %zu moves left\n", label, plan.size() - step, plan.size());
    }
    return total;
  }
} // namespace faf::headless
