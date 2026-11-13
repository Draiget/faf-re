#include "remote/client/ServerViewClient.h"

#include <algorithm>
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
  bool ReadGameInfo(
    const std::span<const std::uint8_t> message,
    SServerGameInfo& out
  )
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

  bool ReadViewMessage(
    const std::span<const std::uint8_t> message,
    SViewMessage& out
  )
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
    // Plan WP8.1: a server that sends poses adds them as a sixth lane; plan WP9.1 step 3: the effect ops as a seventh;
    // plan WP5.14: the command records as an eighth. Any lane after those is a newer server's, skipped.
    out.poses = {};
    out.hasPoses = false;
    out.effects = {};
    out.commands = {};
    out.hasCommands = false;
    out.lanesSkipped = 0;
    for (std::size_t lane = 0; !reader.AtEnd(); ++lane) {
      const std::uint64_t size = reader.Varint();
      const std::uint8_t* const bytes = reader.Bytes(static_cast<std::size_t>(size));
      if (!reader.Ok()) {
        return false;
      }
      const std::span<const std::uint8_t> span(bytes, static_cast<std::size_t>(size));
      if (lane == 0u) {
        out.poses = span;
        out.hasPoses = true;
      } else if (lane == 1u) {
        out.effects = span;
      } else if (lane == 2u) {
        out.commands = span;
        out.hasCommands = true;
      } else {
        ++out.lanesSkipped;
      }
    }
    return true;
  }

  bool ReadTablesMessage(
    const std::span<const std::uint8_t> message,
    STablesMessage& out
  )
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

  CServerViewClient::CServerViewClient(
    moho::RRuleGameRules& rules,
    const SServerGameInfo& info
  )
    : mInfo(info)
    , mCodec(MakeViewCodec(info.mapSizeX, info.mapSizeZ))
  {
    // The client's own tables from its own rules, as the server builds its (WP7.2: both sides build them at load).
    const wire::SContentTables tables = BuildContentTables(rules);
    std::vector<const moho::REntityBlueprint*> blueprints = ResolveBlueprints(rules, tables);
    for (const moho::REntityBlueprint* const blueprint : blueprints) {
      mStats.blueprintsKnown += blueprint != nullptr ? 1u : 0u;
    }
    mCommands = std::make_unique<CCommandLaneApplier>(blueprints); // plan WP5.14: build orders name them
    mRebuilder = std::make_unique<CSyncRebuilder>(mCodec, std::move(blueprints), ResolveMeshes(rules, tables));
    mRebuilder->SetRules(&rules);
    mRebuilder->SetNoSim();
    mTables = std::make_unique<wire::CSessionTableReaders>();
    mRebuilder->SetSessionTables(mTables.get());
    mMerger.SetArmy(info.army);
    // Plan WP9.3: the effects lane, applied against this client's frames and rules.
    mEffectTarget = std::make_unique<SEffectTarget>([this](const std::int32_t id, const bool orRemoved) {
      return HoldsEntity(id, orRemoved);
    }, [&rules](const moho::EEffectOp op, const std::string& name) {
      return HasEffectBlueprint(rules, op, name);
    });
    mEffects = std::make_unique<CEffectLaneApplier>(*mEffectTarget);
    mEffects->SetHorizon(kCountedEffectBeats);
  }

  bool CServerViewClient::HoldsEntity(
    const std::int32_t id,
    const bool orRemoved
  ) const
  {
    if (id < 0) {
      return false;
    }
    const auto key = static_cast<std::uint32_t>(id);
    if (const wire::SViewFrame* const shown = mRebuilder->Baseline(); shown != nullptr) {
      const auto found = std::lower_bound(
        shown->entities.begin(),
        shown->entities.end(),
        key,
        [](const wire::SEntityRecord& record, const std::uint32_t at) {
        return record.id < at;
      }
      );
      if (found != shown->entities.end() && found->id == key) {
        return true;
      }
    }
    return orRemoved && std::binary_search(mPreviousIds.begin(), mPreviousIds.end(), key);
  }

  bool CServerViewClient::ApplyTables(
    const STablesMessage& tables
  )
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

  bool CServerViewClient::Apply(
    const SViewMessage& view,
    moho::SSyncData& packet
  )
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
    // Plan WP9.3: an emitter placed at an entity may name one this view removes; the ids shown before it answer that.
    mPreviousIds.clear();
    if (const wire::SViewFrame* const shown = mRebuilder->Baseline(); shown != nullptr && !view.effects.empty()) {
      mPreviousIds.reserve(shown->entities.size());
      for (const wire::SEntityRecord& record : shown->entities) {
        mPreviousIds.push_back(record.id);
      }
    }
    wire::SViewFrame merged;
    const bool applied = mMerger.Decode(view.own, view.team, mCodec, merged) &&
      mRebuilder->ApplyFrame(std::move(merged), view.own.size() + view.team.size(), packet);
    mRebuilder->SetPoseLane(nullptr);
    if (!applied) {
      ++mStats.frameFailures;
      return false;
    }
    ++mStats.applied;
    // The effects lane, after the frames whose entities it names. A view whose own frame came against nothing is
    // whole: the server takes this client to hold no effect then.
    const bool whole = wire::PeekFrameBaseline(view.own) == wire::kNoBaseline;
    if (mHosted) {
      // Plan WP9.3: the entities hosted effects follow, as this frame left them, before the lane's ops.
      mHosted->BeginBeat(view.beat, packet.mFocusArmy, mGrids);
    }
    if (!mEffects->Apply(view.effects, whole)) {
      ++mStats.effectFailures;
    }
    if (mHosted) {
      // One tick of every effect, as the sim's manager ticks once a beat; its particles go with this view's packet.
      mHosted->EndBeat(&packet);
    }
    // Plan WP5.14: the beat's command records into the packet's command lists. `DoBeat` makes the helpers from the
    // descriptors before the units' updates resolve their queues, as a lockstep sim's beat does; the applier drops (and
    // counts) any record of a command this client wasn't sent.
    mStats.commandBytes += view.commands.size();
    (void)mCommands->Apply(view.commands, packet);
    return true;
  }

  void CServerViewClient::HostEffects(
    moho::RRuleGameRules& rules,
    SEffectHostWorld world
  )
  {
    mRebuilder->KeepRemoved(true); // an impact placed at an entity this view removed reads its last state
    mHosted = std::make_unique<CClientEffects>(rules, *mRebuilder, [this](const std::int32_t id, const bool orRemoved) {
      return HoldsEntity(id, orRemoved);
    }, std::move(world));
    mEffects = std::make_unique<CEffectLaneApplier>(*mHosted); // effects end by themselves: no horizon
    mHosted->SetEndedHandler([this](const std::uint32_t id) {
      mEffects->Ended(id);
    });
  }
} // namespace faf::remote::client
