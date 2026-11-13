#include "remote/client/CommandLaneApplier.h"

#include <cstring>
#include <utility>

#include "moho/command/SSTICommandConstantData.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/command/SSTICommandVariableData.h"
#include "moho/sim/SOCellPos.h"
#include "moho/sim/SimDriver.h"

// Engine addition, server mode: see CommandLaneApplier.h.

namespace faf::remote::client
{
  namespace
  {
    void TargetToSim(
      const wire::SCommandTarget& target,
      moho::SSTITarget& out
    )
    {
      out.mType = static_cast<moho::EAiTargetType>(target.type);
      out.mEntityId = target.entity;
      out.mPos = Wm3::Vec3f(target.position[0], target.position[1], target.position[2]);
    }
  } // namespace

  void CommandDataToSim(
    const wire::SCommandData& data,
    moho::SSTICommandVariableData& out
  )
  {
    out.mEntIds.clear();
    for (const std::uint32_t unit : data.units) {
      out.mEntIds.push_back(static_cast<moho::EntId>(unit));
    }
    out.mCmdType = static_cast<moho::EUnitCommandType>(data.type);
    TargetToSim(data.target1, out.mTarget1);
    TargetToSim(data.target2, out.mTarget2);
    out.v14 = data.extra;
    out.mCells.clear();
    for (const wire::SCommandCell& cell : data.cells) {
      moho::SOCellPos pos{};
      pos.x = cell.x;
      pos.z = cell.z;
      out.mCells.push_back(pos);
    }
    out.mMaxCount = data.maxCount;
    out.mCount = data.count;
    out.v23 = data.flags;
  }

  void CommandDescriptorToSim(
    const wire::SCommandDescriptor& descriptor,
    const std::vector<const moho::REntityBlueprint*>& blueprints,
    moho::SSTICommandConstantData& out
  )
  {
    static_assert(sizeof(out.origin) == sizeof(float) * 4u, "the origin is four floats");
    out.cmd = static_cast<std::int32_t>(descriptor.id);
    out.mFormationScriptIndex = descriptor.formation;
    std::memcpy(&out.origin, descriptor.origin.data(), sizeof(out.origin));
    out.unk1 = descriptor.scale;
    out.blueprint = descriptor.blueprint != 0u && descriptor.blueprint - 1u < blueprints.size()
      ? const_cast<moho::REntityBlueprint*>(blueprints[descriptor.blueprint - 1u])
      : nullptr;
    out.unk2 = fa::string(descriptor.script.data(), descriptor.script.size());
  }

  CCommandLaneApplier::CCommandLaneApplier(
    std::vector<const moho::REntityBlueprint*> blueprints
  )
    : mBlueprints(std::move(blueprints))
  {}

  bool CCommandLaneApplier::Apply(
    const std::span<const std::uint8_t> lane,
    moho::SSyncData& packet
  )
  {
    if (!mReceiver.Apply(lane, mBeat)) {
      return false;
    }
    // The lists as `CCommandDB::PublishSyncData` leaves them; `DoBeat` applies them in its own order.
    for (const wire::SCommandDescriptor& descriptor : mBeat.descriptors) {
      moho::SSTICommandConstantData constant{};
      CommandDescriptorToSim(descriptor, mBlueprints, constant);
      mUnknownBlueprints += descriptor.blueprint != 0u && constant.blueprint == nullptr ? 1u : 0u;
      packet.mPublishedCommandDescriptors.push_back(constant);
    }
    for (const auto& [id, data] : mBeat.updates) {
      moho::SSyncPublishedCommandPacket published{};
      published.commandId = static_cast<moho::CmdId>(id);
      CommandDataToSim(data, published.variableData);
      packet.mPublishedCommandPackets.push_back(published);
    }
    for (const std::uint32_t id : mBeat.removals) {
      packet.mPendingCommandEventRemovals.push_back(static_cast<moho::CmdId>(id));
    }
    for (const std::uint32_t id : mBeat.releases) {
      packet.mPendingReleasedCommandIds.push_back(static_cast<moho::CmdId>(id));
    }
    return true;
  }
} // namespace faf::remote::client
