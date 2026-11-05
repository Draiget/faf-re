#include "server/ServerViews.h"

#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

#include "moho/sim/Sim.h"
#include "remote/net/Datagram.h"
#include "remote/net/GameLinks.h"
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
    mLuaBytes.fetch_add(lanes.lua.Bytes().size(), std::memory_order_relaxed);
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
    WriteLane(writer, lanes.lua);
    mNet.QueueView(player->second, std::move(message));
  }

  std::string CServerViews::LaneReport() const
  {
    const auto megabytes = [](const std::atomic<std::uint64_t>& bytes) {
      return std::to_string(bytes.load(std::memory_order_relaxed) / (1024u * 1024u));
    };
    return "views so far: entities " + megabytes(mFrameBytes) + " MB, armies " + megabytes(mArmyBytes) + " MB, grids " + megabytes(mGridBytes) + " MB, Lua " + megabytes(mLuaBytes) + " MB";
  }

  void CServerViews::OnViewsFinished()
  {
    for (const auto& [army, uid] : mPlayers) {
      mFailures += TakeClientFailures(army);
    }
  }
} // namespace faf::server
