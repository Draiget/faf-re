#include "ProbeRebuild.h"

#include <cstdio>
#include <fstream>
#include <sstream>
#include <vector>

#include "gpg/core/containers/String.h"
#include "headless/ReplayLuaState.h"
#include "headless/SessionLoad.h"
#include "lua/LuaObject.h"
#include "legacy/math/X87Math.h"
#include "moho/app/IWinApp.h"
#include "moho/app/WinApp.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/misc/StartupHelpers.h"
#include "gpg/core/streams/BinaryReader.h"
#include "moho/net/CMessage.h"
#include "moho/net/CMessageStream.h"
#include "moho/net/ELobbyMsg.h"
#include "moho/net/LaunchInfoBuilder.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/CWldSessionLoaderImpl.h"
#include "moho/sim/FafGameVersion.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/WldSessionInfo.h"
#include "remote/ContentTables.h"
#include "remote/FrameBuilder.h"
#include "remote/ViewLanes.h"
#include "remote/client/SyncRebuilder.h"
#include "remote/client/ViewMerge.h"
#include "remote/wire/ArmyLane.h"
#include "remote/wire/BitStream.h"

// Plan WP11 step 1: see ProbeRebuild.h.

namespace faf::probe
{
  namespace
  {
    /** The engine's common services, as the server starts them (its `CServerApp`). */
    class CProbeApp final : public moho::IWinApp
    {
    public:
      CProbeApp()
        : moho::IWinApp("SupCom", "SupremeCommander")
      {}
      bool Init() override { return AppInitCommonServices(); }
      void Main() override {}
      void Destroy() override {}
    };
  } // namespace

  struct CProbeRebuild::SState
  {
    CProbeApp app;
    std::unique_ptr<moho::RRuleGameRules> rules;
    std::unique_ptr<moho::CWldMap> map;
    std::unique_ptr<LuaPlus::LuaState> sessionState;
    std::unique_ptr<remote::client::CSyncRebuilder> rebuilder;
    remote::client::CViewFrameMerger merger;
    remote::wire::SFrameCodec codec{};
    std::uint64_t mergeFailures = 0;
    // Plan WP11 step 2: the army and grid lanes as the client holds them.
    std::vector<remote::wire::SArmyRecord> armies;
    bool haveArmies = false;
    std::vector<remote::wire::SGridSlot> grids;
    std::uint64_t armyLanes = 0;
    std::uint64_t armyFailures = 0;
    std::uint64_t gridLanes = 0;
    std::uint64_t gridFailures = 0;
    std::uint64_t gridSlotsSeen = 0;
    std::uint64_t frames = 0;
    std::uint64_t applied = 0;
    std::uint64_t blueprints = 0;
  };

  CProbeRebuild::CProbeRebuild() = default;
  CProbeRebuild::~CProbeRebuild() = default;

  bool CProbeRebuild::Start(std::string& error)
  {
    if (mState) {
      return true;
    }
    // `WinMain` / `CScApp::Init` without a window, as the server does.
    moho::APP_InitializeIdentity();
    moho::PLAT_Init();
    (void)SetSse2Mode(0);
    mState = std::make_unique<SState>();
    if (!mState->app.Init()) {
      error = "the engine's services didn't start";
      return false;
    }
    moho::USER_LoadPreferences(fa::string("Game.prefs"));
    return true;
  }

  bool CProbeRebuild::OnLaunchInfo(const std::span<const std::uint8_t> configuration, const int uid, std::string& error)
  {
    if (!mState || mState->rules) {
      return true; // not asked to rebuild from it, or the rules are loaded already (a reconnect sends it again)
    }
    // As `CLobby::OnScriptData` reads script data: the lobby's Lua byte form.
    LuaPlus::LuaState* const state = faf::headless::ReplayLuaState();
    LuaPlus::LuaObject config;
    try {
      moho::CMessage message(moho::ELobbyMsg::LOBMSG_DirectScriptData);
      (void)message.Append(reinterpret_cast<const char*>(configuration.data()), configuration.size());
      moho::CMessageStream stream(&message, moho::CMessageStream::Access::kReadOnly);
      const gpg::BinaryReader reader{&stream};
      LuaPlus::LuaObject codec = state->GetGlobals();
      codec.SCR_FromByteStream(config, state, &reader);
    } catch (const std::exception& exception) {
      error = std::string("the launch info doesn't read: ") + exception.what();
      return false;
    }
    if (!config.IsTable()) {
      error = "the launch info isn't a table";
      return false;
    }
    // A client with no sim needs only the rules from it: the server's own observer entry (uid 0) is left out.
    LuaPlus::LuaObject noObservers;
    noObservers.AssignNewTable(state, 0, 0u);
    config.SetObject("Observers", noObservers);
    return LoadRules(config, uid, error);
  }

  bool CProbeRebuild::Load(const std::string& matchPath, const int uid, std::string& error)
  {
    if (!Start(error)) {
      return false;
    }

    // The match, as the server reads it (`MatchConfig`, `MatchSeed`); a client will get it from the server (WPR.55).
    LuaPlus::LuaState* const state = faf::headless::ReplayLuaState();
    std::ifstream file(matchPath, std::ios::binary);
    std::stringstream text;
    text << file.rdbuf();
    if (!file || !moho::SCR_LuaDoString(text.str().c_str(), state)) {
      error = "cannot run " + matchPath;
      return false;
    }
    LuaPlus::LuaObject config = state->GetGlobal("MatchConfig");
    if (!config.IsTable()) {
      error = matchPath + " sets no MatchConfig";
      return false;
    }
    return LoadRules(config, uid, error);
  }

  bool CProbeRebuild::LoadRules(LuaPlus::LuaObject& config, const int uid, std::string& error)
  {
    LuaPlus::LuaState* const state = faf::headless::ReplayLuaState();
    // As the player this probe is: `BuildLaunchInfo` wants the local player in the match.
    moho::CLaunchRoster roster(uid, fa::string("probe"), {});
    // The seed is the sim's; a client with no sim needs none.
    moho::SLaunchBuild build = moho::BuildLaunchInfo(config, roster, 1, true, state);
    if (build.failure != nullptr) {
      error = std::string("the match can't launch: ") + build.failure;
      return false;
    }
    moho::SWldSessionInfo sessionInfo{}; // value-initialised: `LoadSessionScenario` beats a non-null client manager
    sessionInfo.mClientManager = nullptr;
    sessionInfo.mMapName = build.mapName;
    sessionInfo.mLaunchInfo = boost::static_pointer_cast<moho::LaunchInfoBase>(build.launchInfo);
    moho::SWldGameData gameData{};
    if (!faf::headless::LoadSessionScenario(sessionInfo, gameData, error)) {
      return false;
    }
    moho::FAF_BeginSession(false);
    mState->sessionState.reset(gameData.mState);
    mState->rules.reset(gameData.mGameRules);
    mState->map.reset(gameData.mWldMap);
    gameData = moho::SWldGameData{};
    return true;
  }

  void CProbeRebuild::OnGameInfo(const float mapSizeX, const float mapSizeZ, const std::int32_t army)
  {
    if (!mState || !mState->rules || mState->rebuilder) {
      return;
    }
    mState->merger.SetArmy(army);
    mState->codec = remote::MakeViewCodec(mapSizeX, mapSizeZ);
    // The client's own tables from its own rules, as the server builds its (WP7.2: both sides build them at load).
    const remote::wire::SContentTables tables = remote::BuildContentTables(*mState->rules);
    std::vector<const moho::REntityBlueprint*> blueprints = remote::client::ResolveBlueprints(*mState->rules, tables);
    for (const moho::REntityBlueprint* const blueprint : blueprints) {
      mState->blueprints += blueprint != nullptr ? 1u : 0u;
    }
    mState->rebuilder = std::make_unique<remote::client::CSyncRebuilder>(
      remote::MakeViewCodec(mapSizeX, mapSizeZ), std::move(blueprints), remote::client::ResolveMeshes(*mState->rules, tables)
    );
    mState->rebuilder->SetRules(mState->rules.get());
  }

  void CProbeRebuild::OnView(
    const std::span<const std::uint8_t> own, const std::span<const std::uint8_t> team, const std::span<const std::uint8_t> armies,
    const std::span<const std::uint8_t> grids
  )
  {
    if (!mState || !mState->rebuilder) {
      return;
    }
    // Army lane: every army's record, each against the one this client holds.
    if (!armies.empty()) {
      ++mState->armyLanes;
      remote::wire::BitReader reader(armies);
      std::vector<remote::wire::SArmyRecord> decoded;
      if (remote::wire::DecodeArmyLane(reader, mState->haveArmies ? &mState->armies : nullptr, decoded)) {
        mState->armies = std::move(decoded);
        mState->haveArmies = true;
      } else {
        ++mState->armyFailures;
      }
    }
    // Grid lane: the view's intel grids, each a delta against the copy this client holds.
    if (!grids.empty()) {
      ++mState->gridLanes;
      remote::wire::BitReader reader(grids);
      if (remote::wire::DecodeGridLane(reader, mState->grids)) {
        mState->gridSlotsSeen += mState->grids.size();
      } else {
        ++mState->gridFailures;
      }
    }
    ++mState->frames;
    remote::wire::SViewFrame merged;
    if (!mState->merger.Decode(own, team, mState->codec, merged)) {
      ++mState->mergeFailures;
      return;
    }
    // A fresh packet each beat: a client with no sim has nothing else to start from.
    moho::SSyncData packet{};
    mState->applied += mState->rebuilder->ApplyFrame(std::move(merged), own.size() + team.size(), packet) ? 1u : 0u;
  }

  bool CProbeRebuild::HasRules() const noexcept
  {
    return mState && mState->rules;
  }

  void CProbeRebuild::Report(const int uid) const
  {
    if (!mState || !mState->rebuilder) {
      std::printf("probe %d: rebuild: never started (no rules or no game info)\n", uid);
      return;
    }
    const remote::client::SRebuildStats& s = mState->rebuilder->Stats();
    std::string slots;
    for (const remote::wire::SGridSlot& slot : mState->grids) {
      slots += " army " + std::to_string(slot.army) + (slot.kind == 0 ? " vision " : " water ") + std::to_string(slot.bits.width) + "x" +
               std::to_string(slot.bits.height);
    }
    std::printf(
      "probe %d: rebuild: army lanes %llu (%llu failed), %zu armies held; grid lanes %llu (%llu failed), %zu grids held:%s\n", uid,
      static_cast<unsigned long long>(mState->armyLanes), static_cast<unsigned long long>(mState->armyFailures), mState->armies.size(),
      static_cast<unsigned long long>(mState->gridLanes), static_cast<unsigned long long>(mState->gridFailures), mState->grids.size(), slots.c_str()
    );
    // What the last frame held: how many of its records the rebuild could create at all.
    std::uint64_t records = 0;
    std::uint64_t units = 0;
    std::uint64_t orphaned = 0;
    std::uint64_t armyless = 0;
    if (const remote::wire::SViewFrame* const shown = mState->rebuilder->Baseline(); shown != nullptr) {
      for (const remote::wire::SEntityRecord& record : shown->entities) {
        ++records;
        units += record.isUnit ? 1u : 0u;
        orphaned += (record.flags & remote::kEntityFlagOrphaned) != 0u ? 1u : 0u;
        armyless += record.army == 0xFFu ? 1u : 0u;
      }
    }
    std::printf(
      "probe %d: rebuild: last frame %llu records: %llu units, %llu orphaned, %llu with no army; %llu views failed to decode, %llu own blips left out\n", uid,
      static_cast<unsigned long long>(records), static_cast<unsigned long long>(units), static_cast<unsigned long long>(orphaned),
      static_cast<unsigned long long>(armyless), static_cast<unsigned long long>(mState->mergeFailures),
      static_cast<unsigned long long>(mState->merger.BlipsLeftOut())
    );
    std::printf(
      "probe %d: rebuild: %llu frames, %llu applied, %llu failed to decode; %llu blueprints known; created %llu, updates %llu, erased %llu, "
      "deleted %llu; no blueprint %llu, unknown table ids %llu, unit changes without an update %llu, unit updates %llu\n",
      uid, static_cast<unsigned long long>(mState->frames), static_cast<unsigned long long>(mState->applied),
      static_cast<unsigned long long>(s.decodeFailures), static_cast<unsigned long long>(mState->blueprints),
      static_cast<unsigned long long>(s.created), static_cast<unsigned long long>(s.entityUpdates), static_cast<unsigned long long>(s.erased),
      static_cast<unsigned long long>(s.deleted), static_cast<unsigned long long>(s.noBlueprint), static_cast<unsigned long long>(s.unknownTableIds),
      static_cast<unsigned long long>(s.unitChangesWithoutUpdate), static_cast<unsigned long long>(s.unitUpdates)
    );
  }
} // namespace faf::probe
