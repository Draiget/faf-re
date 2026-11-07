#include "server/ServerViews.h"

#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

#include "moho/sim/Sim.h"
#include "remote/net/Datagram.h"
#include "remote/net/GameLinks.h"
#include "remote/SyncRouting.h"
#include "remote/wire/BitStream.h"
#include "remote/wire/LuaSyncLane.h"
#include "server/ServerNet.h"

namespace faf::server
{
  namespace
  {
    void WriteLane(remote::net::ByteWriter& writer, const remote::wire::BitWriter& lane)
    {
      const auto bytes = lane.Bytes();
      writer.Varint(bytes.size());
      writer.Bytes(bytes.data(), bytes.size());
    }
  } // namespace

  std::vector<std::uint8_t> MakeGameInfo(const float mapSizeX, const float mapSizeZ, const std::int32_t army, const std::uint32_t source)
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
    const remote::wire::SContentTables& tables, moho::RRuleGameRules& rules, const float mapSizeX, const float mapSizeZ, CServerNet& net,
    std::map<std::size_t, std::int32_t> players, const unsigned int threads, const bool teams
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
    EnableHeldFrames(false);
    SetParallel(true);
    EnablePipeline(threads);
    if (teams) {
      EnableTeamViews();
    }
    EnableLuaRouting({});
    SendLuaSeparately(); // `LuaSync` (OnLuaRouterMade)
    EnableSessionTables(mSessionTables);
  }

  CServerViews::~CServerViews()
  {
    Uninstall();
  }

  void CServerViews::Install()
  {
    moho::Sim::SetSyncObserver(this);
    mInstalled = true;
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
    // Plan WP14.1: a returning player's client holds nothing, so this beat's view goes to them whole.
    for (const std::int32_t uid : mNet.TakeReturned()) {
      for (const auto& [army, player] : mPlayers) {
        if (player == uid) {
          RequestFresh(army);
        }
      }
    }

    mNet.Intake().Drain(
      &mRules,
      [this](const std::int32_t army) -> const remote::CViewIdMap* {
        return army >= 0 && static_cast<std::size_t>(army) < ViewCount() ? &IdMap(army) : nullptr;
      },
      [this](const std::int32_t army, const std::uint32_t id) { return army >= 0 && ViewHoldsEntity(static_cast<std::size_t>(army), id); },
      [this](const std::int32_t uid, std::vector<std::uint8_t> message) { mNet.QueueView(uid, std::move(message)); }
    );
  }

  void CServerViews::OnLanesEncoded(const std::size_t army, const SLanes& lanes)
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
    message.reserve(24u + lanes.frame.Bytes().size() + teamFrame.Bytes().size() + lanes.armies.Bytes().size() + lanes.grids.Bytes().size() + lanes.lua.Bytes().size());
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

  void CServerViews::OnViewFrames(moho::Sim& sim)
  {
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

  void CServerViews::OnLuaRouterMade(remote::CSyncRouter& router)
  {
    // On the sim's thread, at the end of `Sim::Sync` (SimTick.cpp), after the beat's views were encoded: the same
    // beat's `Sync` for each player, in the order queued after that beat's view unless the views' pipeline is late.
    router.SetPayloadObserver([this, &router](moho::Sim& sim) {
      const auto beat = static_cast<std::uint64_t>(sim.mCurBeat);
      for (const auto& [army, uid] : mPlayers) {
        if (army >= router.ViewCount()) {
          continue;
        }
        remote::wire::BitWriter lane;
        if (!remote::wire::EncodeLuaSyncLane(router.Payload(army), router.Prints(army), lane)) {
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
    return "views so far: entities " + megabytes(mFrameBytes) + " MB, armies " + megabytes(mArmyBytes) + " MB, grids " + megabytes(mGridBytes) + " MB, Lua " + megabytes(mLuaBytes) + " MB, session tables "
         + std::to_string(mTableRecords.load(std::memory_order_relaxed)) + " records of "
         + std::to_string(mTableBytes.load(std::memory_order_relaxed) / 1024u) + " KB to each player";
  }

  void CServerViews::OnViewsFinished()
  {
    for (const auto& [army, uid] : mPlayers) {
      mFailures += TakeClientFailures(army);
    }
  }
} // namespace faf::server
