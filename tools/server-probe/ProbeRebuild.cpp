#include "ProbeRebuild.h"

#include <cstdio>
#include <fstream>
#include <print>
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
#include "moho/sim/STIMap.h"
#include "moho/sim/WldSessionInfo.h"
#include "remote/ContentTables.h"
#include "remote/FrameBuilder.h"
#include "remote/ViewLanes.h"
#include "remote/client/ServerViewClient.h"
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
      bool Init() override
      {
        return AppInitCommonServices();
      }
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
    std::unique_ptr<remote::client::CServerViewClient> client;
    bool seeded = false;
    std::uint64_t tablesBad = 0;
    std::string gameMods; // the launch's `GameMods`, in its byte form
  };

  CProbeRebuild::CProbeRebuild() = default;
  CProbeRebuild::~CProbeRebuild() = default;

  std::expected<void, std::string> CProbeRebuild::Start()
  {
    if (mState) {
      return {};
    }
    // `WinMain` / `CScApp::Init` without a window, as the server does.
    moho::APP_InitializeIdentity();
    moho::PLAT_Init();
    (void)SetSse2Mode(0);
    mState = std::make_unique<SState>();
    if (!mState->app.Init()) {
      return std::unexpected("the engine's services didn't start");
    }
    moho::USER_LoadPreferences(fa::string("Game.prefs"));
    return {};
  }

  std::expected<void, std::string> CProbeRebuild::OnLaunchInfo(
    const std::span<const std::uint8_t> configuration,
    const int uid
  )
  {
    if (!mState || mState->rules) {
      return {}; // not asked to rebuild from it, or the rules are loaded already (a reconnect sends it again)
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
      return std::unexpected(std::string("the launch info doesn't read: ") + exception.what());
    }
    if (!config.IsTable()) {
      return std::unexpected("the launch info isn't a table");
    }
    // A client with no sim needs only the rules from it: the server's own observer entry (uid 0) is left out.
    LuaPlus::LuaObject noObservers;
    noObservers.AssignNewTable(state, 0, 0u);
    config.SetObject("Observers", noObservers);
    return LoadRules(config, uid);
  }

  std::expected<void, std::string> CProbeRebuild::Load(
    const std::string& matchPath,
    const int uid
  )
  {
    if (auto started = Start(); !started) {
      return started;
    }

    // The match, as the server reads it (`MatchConfig`, `MatchSeed`); a client will get it from the server (WPR.55).
    LuaPlus::LuaState* const state = faf::headless::ReplayLuaState();
    std::ifstream file(matchPath, std::ios::binary);
    std::stringstream text;
    text << file.rdbuf();
    if (!file || !moho::SCR_LuaDoString(text.str().c_str(), state)) {
      return std::unexpected("cannot run " + matchPath);
    }
    LuaPlus::LuaObject config = state->GetGlobal("MatchConfig");
    if (!config.IsTable()) {
      return std::unexpected(matchPath + " sets no MatchConfig");
    }
    return LoadRules(config, uid);
  }

  std::expected<void, std::string> CProbeRebuild::LoadRules(
    LuaPlus::LuaObject& config,
    const int uid
  )
  {
    LuaPlus::LuaState* const state = faf::headless::ReplayLuaState();
    // As the player this probe is: `BuildLaunchInfo` wants the local player in the match.
    moho::CLaunchRoster roster(uid, fa::string("probe"), {});
    // The seed is the sim's; a client with no sim needs none.
    moho::SLaunchBuild build = moho::BuildLaunchInfo(config, roster, 1, true, state);
    if (build.failure != nullptr) {
      return std::unexpected(std::string("the match can't launch: ") + build.failure);
    }
    moho::SWldSessionInfo sessionInfo{}; // value-initialised: `LoadSessionScenario` beats a non-null client manager
    sessionInfo.mClientManager = nullptr;
    sessionInfo.mMapName = build.mapName;
    sessionInfo.mLaunchInfo = std::static_pointer_cast<moho::LaunchInfoBase>(build.launchInfo);
    moho::SWldGameData gameData{};
    if (auto loaded = faf::headless::LoadSessionScenario(sessionInfo, gameData); !loaded) {
      return loaded;
    }
    moho::FAF_BeginSession(false);
    mState->sessionState.reset(gameData.mState);
    mState->rules.reset(gameData.mGameRules);
    mState->map.reset(gameData.mWldMap);
    mState->gameMods.assign(build.launchInfo->mGameMods.c_str(), build.launchInfo->mGameMods.size());
    gameData = moho::SWldGameData{};
    return {};
  }

  bool CProbeRebuild::Content(
    remote::SContentReport& out
  ) const
  {
    if (!mState || !mState->rules) {
      return false;
    }
    out = remote::MakeContentReport(*mState->rules, mState->gameMods);
    return true;
  }

  void CProbeRebuild::OnGameInfo(
    const float mapSizeX,
    const float mapSizeZ,
    const std::int32_t army
  )
  {
    if (!mState || !mState->rules || mState->client) {
      return;
    }
    remote::client::SServerGameInfo info;
    info.mapSizeX = mapSizeX;
    info.mapSizeZ = mapSizeZ;
    info.army = army;
    mState->client = std::make_unique<remote::client::CServerViewClient>(*mState->rules, info);
    if (mHostEffects) {
      // Plan WP9.3: the game client's hosting, with one camera that sees everything: no frustum plane, and a viewport
      // that puts every point at depth 0, inside every LOD cutoff.
      moho::GeomCamera3 everywhere;
      everywhere.solid2 = moho::CGeomSolid3{};
      everywhere.viewport = moho::VMatrix4{};
      remote::client::SEffectHostWorld world;
      world.cameras = [everywhere](fa::vector<moho::GeomCamera3>& out) {
        out.clear();
        out.push_back(everywhere);
      };
      moho::CWldMap* const map = mState->map.get();
      world.map = [map]() -> moho::STIMap* {
        return map != nullptr && map->mTerrainRes != nullptr ? map->mTerrainRes->mMap : nullptr;
      };
      mState->client->HostEffects(*mState->rules, std::move(world));
    }
    // The heights as this client loaded the map: the server's terrain edits go on a copy, as in the game client.
    if (
      mState->map && mState->map->mTerrainRes != nullptr && mState->map->mTerrainRes->mMap != nullptr &&
      mState->map->mTerrainRes->mMap->mHeightField
    ) {
      mState->client->SeedTerrain(*mState->map->mTerrainRes->mMap->mHeightField);
      mState->seeded = true;
    }
  }

  void CProbeRebuild::OnTables(
    const std::span<const std::uint8_t> message
  )
  {
    if (!mState || !mState->client) {
      return;
    }
    remote::client::STablesMessage tables;
    if (!remote::client::ReadTablesMessage(message, tables) || !mState->client->ApplyTables(tables)) {
      ++mState->tablesBad;
    }
  }

  void CProbeRebuild::OnView(
    const std::span<const std::uint8_t> own,
    const std::span<const std::uint8_t> team,
    const std::span<const std::uint8_t> armies,
    const std::span<const std::uint8_t> grids,
    const std::span<const std::uint8_t> poses,
    const bool hasPoses,
    const std::span<const std::uint8_t> effects,
    const std::span<const std::uint8_t> commands
  )
  {
    if (!mState || !mState->client) {
      return;
    }
    remote::client::SViewMessage view;
    view.own = own;
    view.team = team;
    view.armies = armies;
    view.grids = grids;
    view.poses = poses;
    view.hasPoses = hasPoses;
    view.effects = effects;   // plan WP9.3: applied as the game client applies them, with its rules' blueprints
    view.commands = commands; // plan WP5.14: into the packet's command lists, blueprints from its rules
    // A fresh packet each beat: a client with no sim has nothing else to start from.
    moho::SSyncData packet{};
    (void)mState->client->Apply(view, packet);
  }

  bool CProbeRebuild::HasRules() const noexcept
  {
    return mState && mState->rules;
  }

  void CProbeRebuild::Report(
    const int uid
  ) const
  {
    if (!mState || !mState->client) {
      std::println("probe {}: rebuild: never started (no rules or no game info)", uid);
      return;
    }
    const remote::client::CServerViewClient& client = *mState->client;
    const remote::client::SServerViewStats& v = client.Stats();
    const remote::client::SRebuildStats& s = client.RebuildStats();
    {
      // Plan WP5.14: the command-records lane as the game client's view client applied it.
      const remote::wire::SCommandLaneCounts& c = client.Commands().Counts();
      std::println(
        "probe {}: rebuild: commands: {} lanes ({} didn't decode), {} descriptors ({} naming a blueprint not held), {} "
        "updates, {} removals, {} releases; dropped {} updates and {} removals of commands not sent; {} held at the "
        "end",
        uid,
        static_cast<unsigned long long>(c.lanes),
        static_cast<unsigned long long>(c.failures),
        static_cast<unsigned long long>(c.descriptors),
        static_cast<unsigned long long>(client.Commands().UnknownBlueprints()),
        static_cast<unsigned long long>(c.updates),
        static_cast<unsigned long long>(c.removals),
        static_cast<unsigned long long>(c.releases),
        static_cast<unsigned long long>(c.droppedUpdates),
        static_cast<unsigned long long>(c.droppedRemovals),
        client.Commands().Receiver().Held()
      );
    }
    {
      // Plan WP9.3: the effects lane as the game client's view client applied it.
      using remote::client::EEffectSkip;
      const remote::client::SEffectApplyCounts& e = client.Effects().Total();
      std::println(
        "probe {}: rebuild: effects: {} ops, {} applied ({} created, {} replacing one held, {} setters, {} lights, {} "
        "destroyed by script), dropped {} with their entity, {} at a whole view, {} aged out; skipped: entity not held "
        "{}, unknown effect {}, name not sent {}, blueprint not held {}; {} lanes didn't decode; {} held at the end",
        uid,
        static_cast<unsigned long long>(e.ops),
        static_cast<unsigned long long>(e.applied),
        static_cast<unsigned long long>(e.created),
        static_cast<unsigned long long>(e.replaced),
        static_cast<unsigned long long>(e.setters),
        static_cast<unsigned long long>(e.lights),
        static_cast<unsigned long long>(e.destroyedByScript),
        static_cast<unsigned long long>(e.droppedWithEntity),
        static_cast<unsigned long long>(e.droppedWhole),
        static_cast<unsigned long long>(e.agedOut),
        static_cast<unsigned long long>(e.skipped[static_cast<std::size_t>(EEffectSkip::EntityNotHeld)]),
        static_cast<unsigned long long>(e.skipped[static_cast<std::size_t>(EEffectSkip::UnknownEffect)]),
        static_cast<unsigned long long>(e.skipped[static_cast<std::size_t>(EEffectSkip::UnknownName)]),
        static_cast<unsigned long long>(e.skipped[static_cast<std::size_t>(EEffectSkip::UnknownBlueprint)]),
        static_cast<unsigned long long>(e.badLanes),
        client.Effects().Live()
      );
      if (const remote::client::CClientEffects* const hosted = client.Hosted(); hosted != nullptr) {
        // Plan WP9.3: what the hosted effects drew under the camera that sees everything.
        const remote::client::SHostedEffectCounts& h = hosted->Counts();
        std::println(
          "probe {}: rebuild: hosted effects: {} beats, {} made ({} not), {} ended by themselves, {} alive at the end "
          "(most {}), {} entities followed (most {}); drawn: {} particles ({} beats with any, most {} in one), {} "
          "trail segments, {} beams, {} lights",
          uid,
          static_cast<unsigned long long>(h.beats),
          static_cast<unsigned long long>(h.created),
          static_cast<unsigned long long>(h.createFailed),
          static_cast<unsigned long long>(h.endedByThemselves),
          hosted->Alive(),
          static_cast<unsigned long long>(h.mostAlive),
          hosted->Targets(),
          static_cast<unsigned long long>(h.mostTargets),
          static_cast<unsigned long long>(h.particles),
          static_cast<unsigned long long>(h.beatsDrawing),
          static_cast<unsigned long long>(h.mostParticles),
          static_cast<unsigned long long>(h.trails),
          static_cast<unsigned long long>(h.beams),
          static_cast<unsigned long long>(h.lights)
        );
      }
    }
    std::string slots;
    for (const remote::wire::SGridSlot& slot : client.Grids()) {
      slots += " army " + std::to_string(slot.army) + (slot.kind == 0 ? " vision " : " water ") +
        std::to_string(slot.bits.width) + "x" + std::to_string(slot.bits.height);
    }
    std::println(
      "probe {}: rebuild: army lanes {} ({} failed), {} armies held; grid lanes {} ({} failed), {} grids held:{}",
      uid,
      static_cast<unsigned long long>(v.armyLanes),
      static_cast<unsigned long long>(v.armyFailures),
      client.Armies().size(),
      static_cast<unsigned long long>(v.gridLanes),
      static_cast<unsigned long long>(v.gridFailures),
      client.Grids().size(),
      slots
    );
    std::uint64_t records = 0;
    std::uint64_t units = 0;
    std::uint64_t orphaned = 0;
    if (const remote::wire::SViewFrame* const shown = client.Shown(); shown != nullptr) {
      for (const remote::wire::SEntityRecord& record : shown->entities) {
        ++records;
        units += record.isUnit ? 1u : 0u;
        orphaned += (record.flags & remote::kEntityFlagOrphaned) != 0u ? 1u : 0u;
      }
    }
    std::println(
      "probe {}: rebuild: last frame {} records: {} units, {} orphaned; {} own blips left out",
      uid,
      static_cast<unsigned long long>(records),
      static_cast<unsigned long long>(units),
      static_cast<unsigned long long>(orphaned),
      static_cast<unsigned long long>(client.BlipsLeftOut())
    );
    std::println(
      "probe {}: rebuild: {} frames, {} applied, {} failed; {} blueprints known; created {}, updates {}, erased {}, "
      "deleted {}; no blueprint {}, unknown table ids {}, unit updates {}",
      uid,
      static_cast<unsigned long long>(v.views),
      static_cast<unsigned long long>(v.applied),
      static_cast<unsigned long long>(v.frameFailures),
      static_cast<unsigned long long>(v.blueprintsKnown),
      static_cast<unsigned long long>(s.created),
      static_cast<unsigned long long>(s.entityUpdates),
      static_cast<unsigned long long>(s.erased),
      static_cast<unsigned long long>(s.deleted),
      static_cast<unsigned long long>(s.noBlueprint),
      static_cast<unsigned long long>(s.unknownTableIds),
      static_cast<unsigned long long>(s.unitUpdates)
    );
    const remote::wire::CSessionTableReaders& tables = client.Tables();
    std::println(
      "probe {}: rebuild: session tables {} records ({} bad, {} resets): {} sounds, {} names, {} deposits, {} terrain "
      "edits ({}); unit stat items applied {}",
      uid,
      static_cast<unsigned long long>(v.tableRecords),
      static_cast<unsigned long long>(v.tableFailures + mState->tablesBad),
      static_cast<unsigned long long>(v.tableResets),
      tables.Sounds().Size(),
      tables.Names().Size(),
      tables.Deposits().size(),
      static_cast<unsigned long long>(s.terrainEdits),
      mState->seeded ? "applied to the map's heights" : "counted, no heights",
      static_cast<unsigned long long>(s.statsApplied)
    );
    std::println(
      "probe {}: rebuild: poses: {} lanes ({} bad, {} KB), {} poses made, {} unit-beats with bones, {} bones applied, "
      "{} bad, {} without a mesh",
      uid,
      static_cast<unsigned long long>(v.poseLanes),
      static_cast<unsigned long long>(v.poseFailures),
      static_cast<unsigned long long>(v.poseBytes / 1024u),
      static_cast<unsigned long long>(s.posesMade),
      static_cast<unsigned long long>(s.poseBeats),
      static_cast<unsigned long long>(s.poseBonesApplied),
      static_cast<unsigned long long>(s.poseBonesBad),
      static_cast<unsigned long long>(s.posesWithoutMesh)
    );
  }
} // namespace faf::probe
