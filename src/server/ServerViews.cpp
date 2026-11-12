#include "server/ServerViews.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string_view>
#include <utility>
#include <vector>

#include "gpg/core/utils/Logging.h"
#include "moho/sim/Sim.h"
#include "remote/net/Datagram.h"
#include "remote/net/GameLinks.h"
#include "remote/SyncRouting.h"
#include "remote/VisibilityOracle.h"
#include "remote/wire/BitStream.h"
#include "remote/wire/LuaSyncLane.h"
#include "server/EffectOpRecorder.h"
#include "server/LobbyScriptData.h"
#include "server/ServerNet.h"

namespace faf::server
{
  namespace
  {
    void WriteLane(
      remote::net::ByteWriter& writer,
      const remote::wire::BitWriter& lane
    )
    {
      const auto bytes = lane.Bytes();
      writer.Varint(bytes.size());
      writer.Bytes(bytes.data(), bytes.size());
    }
  } // namespace

  std::vector<std::uint8_t> MakeGameInfo(
    const float mapSizeX,
    const float mapSizeZ,
    const std::int32_t army,
    const std::uint32_t source
  )
  {
    std::vector<std::uint8_t> message(1u + 2u * sizeof(float) + sizeof(army) + sizeof(source));
    message[0] = static_cast<std::uint8_t>(remote::net::ESeatMessage::GameInfo);
    std::uint8_t* out = message.data() + 1;
    const float sizes[2] = {mapSizeX, mapSizeZ};
    std::memcpy(out, sizes, sizeof(sizes));
    out += sizeof(sizes);
    std::memcpy(out, &army, sizeof(army));
    out += sizeof(army);
    std::memcpy(out, &source, sizeof(source));
    return message;
  }

  CServerViews::CServerViews(
    const remote::wire::SContentTables& tables,
    moho::RRuleGameRules& rules,
    const float mapSizeX,
    const float mapSizeZ,
    CServerNet& net,
    std::map<std::size_t, std::int32_t> players,
    const unsigned int threads,
    const bool teams
  )
    : CViewLanes(tables, mapSizeX, mapSizeZ)
    , mRules(rules)
    , mNet(net)
    , mPlayers(std::move(players))
  {
    EnableIdMaps();
    SkipCivilianViews();
    for (const auto& [army, uid] : mPlayers) {
      if (army < 32u) {
        mViewMask |= std::uint32_t{1} << army;
      }
      mNet.Intake().SetArmy(uid, static_cast<std::int32_t>(army));
    }
    SetViewArmies(mViewMask);
    mPlayerViews = mViewMask;
    EnableHeldFrames(false);
    SetParallel(true);
    EnablePipeline(threads);
    if (teams) {
      EnableTeamViews();
    }
    EnableLuaRouting({});
    SendLuaSeparately(); // `LuaSync` (OnLuaRouterMade)
    EnableSessionTables(mSessionTables);
    EnablePoses();
  }

  CServerViews::~CServerViews()
  {
    Uninstall();
    if (mEffects) {
      moho::gEffectOpHook = nullptr; // enabled but never installed
    }
  }

  void CServerViews::Install()
  {
    moho::Sim::SetSyncObserver(this);
    mInstalled = true;
  }

  void CServerViews::EnableEffectOps(
    const bool route
  )
  {
    if (mEffects) {
      return;
    }
    if (route) {
      mEffectRoutes = std::make_unique<CEffectRoutes>();
    }
    for (const auto& [army, uid] : mPlayers) {
      mEffectReceivers.try_emplace(army);
    }
    mEffects = std::make_unique<CEffectOpRecorder>();
    mEffects->Attach();
    moho::gEffectOpHook = &CEffectOpRecorder::Hook;
  }

  void CServerViews::Uninstall()
  {
    if (!mInstalled) {
      return;
    }
    mInstalled = false;
    (void)FinishViews();
    UninstallRouting();
    moho::Sim::SetSyncObserver(nullptr);
    if (mEffects) {
      moho::gEffectOpHook = nullptr;
      mEffects->Detach();
    }
  }

  std::string CServerViews::EffectReport() const
  {
    if (!mEffects) {
      return {};
    }
    const CEffectOpEncoder& encoder = mEffects->Encoder();
    std::uint64_t namesSent = 0;
    for (const auto& [army, receiver] : mEffectReceivers) {
      namesSent += receiver.names.NamesSent() + receiver.route.Names().NamesSent();
    }
    char line[512];
    std::snprintf(
      line,
      sizeof(line),
      "effects lane: %llu ops in %llu of %llu beats, %.1f KB of ops (%.1f bytes a beat, the most %u), %llu KB to "
      "the %zu players with %llu names; %llu destroys a client derives left out, %llu SetFloat coalesced, %llu ops "
      "on effects never seen created dropped, %zu blueprint and %zu texture names",
      static_cast<unsigned long long>(mEffectOpsTaken),
      static_cast<unsigned long long>(mEffectBeatsWithOps),
      static_cast<unsigned long long>(mEffectBeats),
      static_cast<double>(mEffectOpBytes) / 1024.0,
      mEffectBeats != 0u ? static_cast<double>(mEffectOpBytes) / static_cast<double>(mEffectBeats) : 0.0,
      mEffectMaxBeatBytes,
      static_cast<unsigned long long>(mEffectBytes.load(std::memory_order_relaxed) / 1024u),
      mEffectReceivers.size(),
      static_cast<unsigned long long>(namesSent),
      static_cast<unsigned long long>(encoder.DerivedDestroys()),
      static_cast<unsigned long long>(encoder.Coalesced()),
      static_cast<unsigned long long>(encoder.DroppedTotal()),
      encoder.BlueprintNames(),
      encoder.TextureNames()
    );
    std::string report = line;
    if (!mEffectRoutes) {
      return report + "\neffects routing: off (--effect-ops-all), every player gets every op";
    }
    // Plan WP9.2: what each player's view was sent of them.
    for (const auto& [army, receiver] : mEffectReceivers) {
      const CEffectViewRoute& route = receiver.route;
      std::snprintf(
        line,
        sizeof(line),
        "\neffects routing, army index %zu: %llu ops (%llu KB), %llu lights; %llu creates held at their beat, %llu "
        "effects sent whole later, %llu dropped with their entity; entities as the client's ids %llu, held under none "
        "%llu; %zu effects its client holds at the end",
        army,
        static_cast<unsigned long long>(route.OpsSent()),
        static_cast<unsigned long long>(receiver.bytes / 1024u),
        static_cast<unsigned long long>(route.Lights()),
        static_cast<unsigned long long>(route.Held()),
        static_cast<unsigned long long>(route.Released()),
        static_cast<unsigned long long>(route.Withdrawn()),
        static_cast<unsigned long long>(route.Translated()),
        static_cast<unsigned long long>(route.Untranslated()),
        mEffectRoutes->HeldBy(army)
      );
      report += line;
    }
    std::snprintf(
      line,
      sizeof(line),
      "\neffects routing: %llu effects ended without reaching a player (summed over the players), %zu live at the "
      "end (%zu kept, %.1f KB), %llu creates past the cap not kept",
      static_cast<unsigned long long>(mEffectRoutes->Dropped()),
      mEffectRoutes->Live(),
      mEffectRoutes->Kept(),
      static_cast<double>(mEffectRoutes->KeptBytes()) / 1024.0,
      static_cast<unsigned long long>(mEffectRoutes->NotKept())
    );
    return report + line;
  }

  void CServerViews::OnBeatStarting()
  {
    CViewLanes::OnBeatStarting();

    for (const std::int32_t uid : mNet.TakeGone()) {
      for (const auto& [army, player] : mPlayers) {
        if (player == uid && army < 32u) {
          mViewMask &= ~(std::uint32_t{1} << army);
          SetViewArmies(mViewMask);
        }
      }
    }
    // Plan WP14.1: a returning player's client holds nothing, so this beat's view goes to them whole, and its Lua
    // lane gets what loading a saved game sends for the UI's state (WP6.8, `OnLuaRouterBeat`).
    for (const std::int32_t uid : mNet.TakeReturned()) {
      for (const auto& [army, player] : mPlayers) {
        if (player == uid) {
          RequestFresh(army);
          mLuaResyncs.push_back(army);
        }
      }
    }

    mNet.Intake().Drain(&mRules, [this](const std::int32_t army) -> const remote::CViewIdMap* {
      return army >= 0 && static_cast<std::size_t>(army) < ViewCount() ? &IdMap(army) : nullptr;
    }, [this](const std::int32_t army, const std::uint32_t id) {
      return army >= 0 && ViewHoldsEntity(static_cast<std::size_t>(army), id);
    }, [this](const std::int32_t uid, std::vector<std::uint8_t> message) {
      mNet.QueueView(uid, std::move(message));
    });
  }

  void CServerViews::OnLanesEncoded(
    const std::size_t army,
    const SLanes& lanes
  )
  {
    const auto player = mPlayers.find(army);
    if (player == mPlayers.end()) {
      return;
    }
    static const remote::wire::BitWriter noFrame;
    const remote::wire::BitWriter& teamFrame = lanes.team != nullptr ? *lanes.team : noFrame;
    mFrameBytes.fetch_add(lanes.frame.Bytes().size() + teamFrame.Bytes().size(), std::memory_order_relaxed);
    mArmyBytes.fetch_add(lanes.armies.Bytes().size(), std::memory_order_relaxed);
    mGridBytes.fetch_add(lanes.grids.Bytes().size(), std::memory_order_relaxed);
    std::vector<std::uint8_t> message;
    message.reserve(
      30u + lanes.frame.Bytes().size() + teamFrame.Bytes().size() + lanes.armies.Bytes().size() +
      lanes.grids.Bytes().size() + (lanes.poses != nullptr ? lanes.poses->Bytes().size() : 0u)
    );
    remote::net::ByteWriter writer(message);
    writer.Byte(static_cast<std::uint8_t>(remote::net::ESeatMessage::View));
    writer.Varint(ViewBeat());
    writer.Varint(HeldCount(static_cast<std::int32_t>(army)));
    writer.Varint(lanes.teamEntities);
    WriteLane(writer, lanes.frame);
    WriteLane(writer, teamFrame);
    WriteLane(writer, lanes.armies);
    WriteLane(writer, lanes.grids);
    WriteLane(writer, noFrame); // the Lua lane goes as `LuaSync`, once the beat's `Sync` is routed (OnLuaRouterMade)
    if (lanes.poses != nullptr) {
      // Plan WP8.1: the sixth lane, the units' bones (a client reads it when the message goes on past the Lua lane).
      mPoseBytes.fetch_add(lanes.poses->Bytes().size(), std::memory_order_relaxed);
      WriteLane(writer, *lanes.poses);
      // Plan WP9.1 step 3: the seventh, the beat's effect ops (remote/wire/EffectLane.h). It needs the pose lane before
      // it, which the server always sends; a client that doesn't know it skips it.
      if (const auto receiver = mEffectReceivers.find(army); mEffects && receiver != mEffectReceivers.end()) {
        std::vector<std::uint8_t>& lane = receiver->second.lane;
        if (mEffectRoutes) {
          // Plan WP9.2: the effects whose place this client holds (its frame and its team's, as just encoded); plan
          // WP9.3: their entities by the ids this client holds them under (its view's id map, read on its own job).
          const remote::CViewIdMap& ids = IdMap(static_cast<std::int32_t>(army));
          receiver->second.route.Write(
            mEffectBeat, *mEffectRoutes, army, lanes.fresh, [this, army](const std::int32_t entity, const bool orLeft) {
            return ViewHoldsEntityNow(army, static_cast<std::uint32_t>(entity), orLeft);
          }, lane, [&ids](const std::int32_t entity, std::int32_t& clientId) {
            std::uint32_t viewId = 0;
            if (!ids.EntityToHeldView(static_cast<std::uint32_t>(entity), viewId)) {
              return false;
            }
            clientId = static_cast<std::int32_t>(viewId);
            return true;
          }
          );
        } else {
          if (lanes.fresh) {
            receiver->second.names.Reset(); // its client holds nothing: the names its ops need go again
          }
          receiver->second.names.Write(mEffectBeat, lane);
        }
        receiver->second.bytes += lane.size();
        writer.Varint(lane.size());
        writer.Bytes(lane.data(), lane.size());
        mEffectBytes.fetch_add(lane.size(), std::memory_order_relaxed);
        mEffectLanes.fetch_add(lane.empty() ? 0u : 1u, std::memory_order_relaxed);
      }
    }
    mNet.QueueView(player->second, std::move(message), lanes.fresh);
    if (lanes.check) {
      std::vector<std::uint8_t> check;
      remote::net::ByteWriter checkWriter(check);
      checkWriter.Byte(static_cast<std::uint8_t>(remote::net::ESeatMessage::ViewCheck));
      checkWriter.Varint(ViewBeat());
      std::uint8_t hashes[2 * sizeof(std::uint64_t)];
      std::memcpy(hashes, &lanes.frameHash, sizeof(std::uint64_t));
      std::memcpy(hashes + sizeof(std::uint64_t), &lanes.teamHash, sizeof(std::uint64_t));
      checkWriter.Bytes(hashes, sizeof(hashes));
      mNet.QueueView(player->second, std::move(check));
    }
  }

  void CServerViews::OnViewFrames(
    moho::Sim& sim
  )
  {
    // #178: the frames' headers carry the game speed and the server's clock for the clients' beat clocks.
    SetFrameClock(
      mFrameSimRate.load(std::memory_order_relaxed),
      static_cast<std::uint32_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - mStart).count()
      )
    );
    // Plan WP9.1 step 3: the beat's effect ops, for its views' effects lanes. Ops the sim makes from here on (the next
    // beat's, while these views are built) go into the next beat's.
    if (mEffects) {
      // Plan WP9.5: a beat the sim didn't tick (paused) goes as the unticked lane, so clients hold their effects too.
      mEffectBeat = mEffects->EndBeat(sim.mAdvancedThisTick);
      ++mEffectBeats;
      mEffectBeatsWithOps += mEffectBeat.opCount != 0u ? 1u : 0u;
      mEffectOpsTaken += mEffectBeat.opCount;
      mEffectOpBytes += mEffectBeat.ops.size();
      mEffectMaxBeatBytes = std::max(mEffectMaxBeatBytes, static_cast<std::uint32_t>(mEffectBeat.ops.size()));
      if (mEffectRoutes) {
        // Plan WP9.2: the live effects and the beat's lights, with the sight of each player's army as the sim has it
        // now (the frames' own test for a point, `ViewCanSeePoint`). A player watching everything sees every point.
        std::uint32_t watching = 0u;
        for (const auto& [army, uid] : mPlayers) {
          if (army < 32u && WatchesEverything(army)) {
            watching |= std::uint32_t{1} << army;
          }
        }
        mEffectRoutes->TakeBeat(mEffectBeat, mPlayerViews, watching, [this, &sim](const std::array<float, 3>& at) {
          std::uint32_t views = 0u;
          const Wm3::Vec3f point(at[0], at[1], at[2]);
          for (const auto& [army, uid] : mPlayers) {
            if (army < 32u && remote::ViewCanSeePoint(sim, static_cast<std::int32_t>(army), point, false)) {
              views |= std::uint32_t{1} << army;
            }
          }
          return views;
        }, [this, &sim](const std::int32_t entity, CEffectRoutes::SBlips& blips) {
          // Another army's unit: those who draw its blip (a unit is published to its own army only), and which blip.
          return remote::ViewsShowingUnitBlips(sim, mPlayerViews, static_cast<std::uint32_t>(entity), &blips);
        });
      }
    }
    // The builders are done with the beat (they interned what the frames name); its views go out after this.
    if (mSessionTables.HasPending()) {
      remote::wire::BitWriter record;
      mSessionTables.WritePending(record);
      std::vector<std::uint8_t> message;
      message.reserve(8u + record.Bytes().size());
      remote::net::ByteWriter writer(message);
      writer.Byte(static_cast<std::uint8_t>(remote::net::ESeatMessage::SessionTables));
      writer.Varint(ViewBeat());
      writer.Byte(0u); // no reset
      writer.Bytes(record.Bytes().data(), record.Bytes().size());
      mTableBytes.fetch_add(message.size(), std::memory_order_relaxed);
      mTableRecords.fetch_add(1u, std::memory_order_relaxed);
      for (const auto& [army, uid] : mPlayers) {
        mNet.QueueView(uid, message);
      }
    }
    CViewLanes::OnViewFrames(sim);
  }

  void CServerViews::OnLuaRouterBeat(
    moho::Sim& sim,
    remote::CSyncRouter& router
  )
  {
    (void)sim;
    // The same beat's `Sync` (`CSyncRouter::OnSyncTable` applies the request before it routes the table).
    for (const std::size_t view : mLuaResyncs) {
      if (view < router.ViewCount()) {
        router.RequestResync(view);
        if (const auto player = mPlayers.find(view); player != mPlayers.end()) {
          gpg::Logf("views: uid %d is back; the UI's state goes to them again (army index %zu)", player->second, view);
        }
      }
    }
    mLuaResyncs.clear();
  }

  void CServerViews::OnLuaRouterMade(
    remote::CSyncRouter& router
  )
  {
    // On the sim's thread, at the end of `Sim::Sync` (SimTick.cpp), after the beat's views were encoded: the same
    // beat's `Sync` for each player, in the order queued after that beat's view unless the views' pipeline is late.
    if (mObserverViews) {
      router.SetSourceGoneHandler([this, &router](const std::size_t view) {
        if (WatchEverything(view)) {
          router.MoveView(view, -1); // its `Sync` as focus -1's, with `NoteFocusArmyChanged`
          if (const auto player = mPlayers.find(view); player != mPlayers.end()) {
            gpg::Logf(
              "views: the player of army index %zu (uid %d) has left every army; they watch everything from now on",
              view,
              player->second
            );
          }
        }
      });
    }
    router.SetPayloadObserver([this, &router](moho::Sim& sim) {
      const auto beat = static_cast<std::uint64_t>(sim.mCurBeat);
      // Plan WP15.4: the sim's own timeouts are unlimited (the server keeps them), so its `TimeoutsRemaining` reads -1.
      // FAF's pause button takes the count from the first paused beat (UserSync.lua OnPause, tabs.lua): from then on
      // each player's `Sync` carries what the pausing player has left after this pause, as the server counts it.
      const std::int32_t pausedBy = sim.mPausedByCommandSource;
      if (pausedBy != mPausedSeen) {
        mPausedSeen = pausedBy;
        mPauseShown.reset();
        if (pausedBy >= 0 && mPauseBook) {
          const auto source = static_cast<std::uint32_t>(pausedBy);
          const int seen = ++mPausesSeen[source];
          const std::optional<int> granted = mPauseBook->Granted(source);
          if (granted && *granted >= 0) {
            mPauseShown = std::max(*granted - seen, 0);
          }
          gpg::Logf(
            "server views: beat %d paused by source %d: granted %d, seen %d, shown %d",
            static_cast<int>(sim.mCurBeat),
            static_cast<int>(pausedBy),
            granted ? *granted : -99,
            seen,
            mPauseShown ? *mPauseShown : -99
          );
        }
      }
      static constexpr std::string_view kTimeoutsKey = "TimeoutsRemaining";
      std::vector<std::uint8_t> rewritten;
      for (const auto& [army, uid] : mPlayers) {
        if (army >= router.ViewCount()) {
          continue;
        }
        std::span<const std::uint8_t> payload = router.Payload(army);
        if (
          mPauseShown &&
          std::search(payload.begin(), payload.end(), kTimeoutsKey.begin(), kTimeoutsKey.end()) != payload.end() &&
          SetTableNumber(payload, kTimeoutsKey, static_cast<float>(*mPauseShown), rewritten)
        ) {
          payload = rewritten;
        }
        remote::wire::BitWriter lane;
        if (!remote::wire::EncodeLuaSyncLane(payload, router.Prints(army), lane)) {
          continue;
        }
        mLuaBytes.fetch_add(lane.Bytes().size(), std::memory_order_relaxed);
        std::vector<std::uint8_t> message;
        message.reserve(12u + lane.Bytes().size());
        remote::net::ByteWriter writer(message);
        writer.Byte(static_cast<std::uint8_t>(remote::net::ESeatMessage::LuaSync));
        writer.Varint(beat);
        writer.Varint(lane.Bytes().size());
        writer.Bytes(lane.Bytes().data(), lane.Bytes().size());
        mNet.QueueView(uid, std::move(message));
      }
    });
  }

  std::string CServerViews::LaneReport() const
  {
    const auto megabytes = [](const std::atomic<std::uint64_t>& bytes) {
      return std::to_string(bytes.load(std::memory_order_relaxed) / (1024u * 1024u));
    };
    return "views so far: entities " + megabytes(mFrameBytes) + " MB, armies " + megabytes(mArmyBytes) + " MB, grids " +
      megabytes(mGridBytes) + " MB, Lua " + megabytes(mLuaBytes) + " MB, poses " + megabytes(mPoseBytes) +
      (mEffects ? " MB, effects " + megabytes(mEffectBytes) : std::string()) + " MB, session tables " +
      std::to_string(mTableRecords.load(std::memory_order_relaxed)) + " records of " +
      std::to_string(mTableBytes.load(std::memory_order_relaxed) / 1024u) + " KB to each player";
  }

  void CServerViews::OnViewsFinished()
  {
    for (const auto& [army, uid] : mPlayers) {
      mFailures += TakeClientFailures(army);
    }
  }
} // namespace faf::server
