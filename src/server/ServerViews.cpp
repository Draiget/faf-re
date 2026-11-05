#include "server/ServerViews.h"

#include <cstdint>
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

  CServerViews::CServerViews(
    const remote::wire::SContentTables& tables, const float mapSizeX, const float mapSizeZ, CServerNet& net, std::map<std::size_t, std::int32_t> players,
    const unsigned int threads
  )
    : CViewLanes(tables, mapSizeX, mapSizeZ)
    , mNet(net)
    , mPlayers(std::move(players))
  {
    EnableIdMaps();
    SkipCivilianViews();
    std::uint32_t views = 0u;
    for (const auto& [army, uid] : mPlayers) {
      if (army < 32u) {
        views |= std::uint32_t{1} << army;
      }
    }
    SetViewArmies(views);
    EnableHeldFrames(false);
    SetParallel(true);
    EnablePipeline(threads);
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

  void CServerViews::OnLanesEncoded(const std::size_t army, const SLanes& lanes)
  {
    const auto player = mPlayers.find(army);
    if (player == mPlayers.end()) {
      return;
    }
    std::vector<std::uint8_t> message;
    message.reserve(16u + lanes.frame.Bytes().size() + lanes.armies.Bytes().size() + lanes.grids.Bytes().size() + lanes.lua.Bytes().size());
    remote::net::ByteWriter writer(message);
    writer.Byte(static_cast<std::uint8_t>(remote::net::ESeatMessage::View));
    writer.Varint(ViewBeat());
    writer.Varint(HeldCount(static_cast<std::int32_t>(army)));
    WriteLane(writer, lanes.frame);
    WriteLane(writer, lanes.armies);
    WriteLane(writer, lanes.grids);
    WriteLane(writer, lanes.lua);
    mNet.QueueView(player->second, std::move(message));
  }

  void CServerViews::OnViewsFinished()
  {
    for (const auto& [army, uid] : mPlayers) {
      mFailures += TakeClientFailures(army);
    }
  }
} // namespace faf::server
