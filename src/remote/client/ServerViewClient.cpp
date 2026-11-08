#include "remote/client/ServerViewClient.h"

#include <cstring>
#include <utility>

#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SimDriver.h"
#include "remote/ContentTables.h"
#include "remote/ViewLanes.h"
#include "remote/net/Datagram.h"
#include "remote/net/GameLinks.h"
#include "remote/wire/BitStream.h"

// Engine addition, server mode: see ServerViewClient.h.

namespace faf::remote::client
{
  bool ReadGameInfo(const std::span<const std::uint8_t> message, SServerGameInfo& out)
  {
    constexpr std::size_t kSize = 1u + 2u * sizeof(float) + 2u * sizeof(std::int32_t);
    if (message.size() != kSize || message[0] != static_cast<std::uint8_t>(net::ESeatMessage::GameInfo)) {
      return false;
    }
    std::size_t at = 1;
    std::memcpy(&out.mapSizeX, message.data() + at, sizeof(float));
    at += sizeof(float);
    std::memcpy(&out.mapSizeZ, message.data() + at, sizeof(float));
    at += sizeof(float);
    std::memcpy(&out.army, message.data() + at, sizeof(std::int32_t));
    at += sizeof(std::int32_t);
    std::memcpy(&out.source, message.data() + at, sizeof(std::uint32_t));
    return true;
  }

  bool ReadViewMessage(const std::span<const std::uint8_t> message, SViewMessage& out)
  {
    if (message.empty() || message[0] != static_cast<std::uint8_t>(net::ESeatMessage::View)) {
      return false;
    }
    net::ByteReader reader(message.data() + 1, message.size() - 1u);
    out.beat = static_cast<std::uint32_t>(reader.Varint());
    out.ownEntities = reader.Varint();
    out.teamEntities = reader.Varint();
    std::span<const std::uint8_t>* const lanes[] = {&out.own, &out.team, &out.armies, &out.grids, &out.lua};
    for (std::span<const std::uint8_t>* const lane : lanes) {
      const std::uint64_t size = reader.Varint();
      const std::uint8_t* const bytes = reader.Bytes(static_cast<std::size_t>(size));
      if (!reader.Ok()) {
        return false;
      }
      *lane = std::span<const std::uint8_t>(bytes, static_cast<std::size_t>(size));
    }
    // Plan WP8.1: a server that sends poses adds them as a sixth lane.
    out.poses = {};
    if (!reader.AtEnd()) {
      const std::uint64_t size = reader.Varint();
      const std::uint8_t* const bytes = reader.Bytes(static_cast<std::size_t>(size));
      if (!reader.Ok()) {
        return false;
      }
      out.poses = std::span<const std::uint8_t>(bytes, static_cast<std::size_t>(size));
      out.hasPoses = true;
    }
    return reader.AtEnd();
  }

  bool ReadTablesMessage(const std::span<const std::uint8_t> message, STablesMessage& out)
  {
    if (message.empty() || message[0] != static_cast<std::uint8_t>(net::ESeatMessage::SessionTables)) {
      return false;
    }
    net::ByteReader reader(message.data() + 1, message.size() - 1u);
    out.beat = static_cast<std::uint32_t>(reader.Varint());
    const std::uint8_t flags = reader.Byte();
    if (!reader.Ok() || flags > 1u) {
      return false;
    }
    out.reset = flags == 1u;
    const std::size_t at = message.size() - reader.Remaining();
    out.record = message.subspan(at);
    return !out.reset || out.record.empty();
  }

  CServerViewClient::CServerViewClient(moho::RRuleGameRules& rules, const SServerGameInfo& info)
    : mInfo(info)
    , mCodec(MakeViewCodec(info.mapSizeX, info.mapSizeZ))
  {
    // The client's own tables from its own rules, as the server builds its (WP7.2: both sides build them at load).
    const wire::SContentTables tables = BuildContentTables(rules);
    std::vector<const moho::REntityBlueprint*> blueprints = ResolveBlueprints(rules, tables);
    for (const moho::REntityBlueprint* const blueprint : blueprints) {
      mStats.blueprintsKnown += blueprint != nullptr ? 1u : 0u;
    }
    mRebuilder = std::make_unique<CSyncRebuilder>(mCodec, std::move(blueprints), ResolveMeshes(rules, tables));
    mRebuilder->SetRules(&rules);
    mRebuilder->SetNoSim();
    mTables = std::make_unique<wire::CSessionTableReaders>();
    mRebuilder->SetSessionTables(mTables.get());
    mMerger.SetArmy(info.army);
  }

  bool CServerViewClient::ApplyTables(const STablesMessage& tables)
  {
    if (tables.reset) {
      // Every record follows from the first, before the next view. The ids come out as before (the server's never
      // change); deposits past those applied are added (`CSyncRebuilder::ApplyDeposits` counts them); the terrain
      // edits are applied again in order, which leaves the heights the last of them left.
      ++mStats.tableResets;
      mTables = std::make_unique<wire::CSessionTableReaders>();
      mRebuilder->SetSessionTables(mTables.get());
      return true;
    }
    ++mStats.tableRecords;
    wire::BitReader reader(tables.record);
    if (!mTables->Read(reader)) {
      ++mStats.tableFailures;
      return false;
    }
    return true;
  }

  bool CServerViewClient::Apply(const SViewMessage& view, moho::SSyncData& packet)
  {
    ++mStats.views;
    // Army lane: every army's record, each against the one this client holds.
    if (!view.armies.empty()) {
      ++mStats.armyLanes;
      wire::BitReader reader(view.armies);
      std::vector<wire::SArmyRecord> decoded;
      if (wire::DecodeArmyLane(reader, mHaveArmies ? &mArmies : nullptr, decoded)) {
        mArmies = std::move(decoded);
        mHaveArmies = true;
      } else {
        ++mStats.armyFailures;
      }
    }
    // Grid lane: the view's intel grids, each a delta against the copy this client holds.
    if (!view.grids.empty()) {
      ++mStats.gridLanes;
      wire::BitReader reader(view.grids);
      if (!wire::DecodeGridLane(reader, mGrids)) {
        ++mStats.gridFailures;
      }
    }
    // Pose lane (plan WP8.1): the bones the rebuilder puts on the units' client poses.
    mPoses.clear();
    if (view.hasPoses) {
      ++mStats.poseLanes;
      mStats.poseBytes += view.poses.size();
      wire::BitReader reader(view.poses);
      if (!wire::DecodePoseLane(reader, mPoses)) {
        ++mStats.poseFailures;
        mPoses.clear();
      }
    }
    mRebuilder->SetPoseLane(view.hasPoses ? &mPoses : nullptr);
    wire::SViewFrame merged;
    const bool applied = mMerger.Decode(view.own, view.team, mCodec, merged)
                      && mRebuilder->ApplyFrame(std::move(merged), view.own.size() + view.team.size(), packet);
    mRebuilder->SetPoseLane(nullptr);
    if (!applied) {
      ++mStats.frameFailures;
      return false;
    }
    ++mStats.applied;
    return true;
  }
} // namespace faf::remote::client
