#include "remote/CommandRecords.h"

#include <algorithm>
#include <cstring>
#include <iterator>
#include <string_view>
#include <utility>

#include "moho/command/SSTICommandConstantData.h"
#include "moho/command/SSTICommandVariableData.h"
#include "moho/sim/SOCellPos.h"
#include "moho/sim/SimDriver.h"

// Engine addition, server mode: see CommandRecords.h.

namespace faf::remote
{
  namespace
  {
    [[nodiscard]] wire::SCommandTarget ToWire(
      const moho::SSTITarget& target
    )
    {
      wire::SCommandTarget out;
      out.type = static_cast<std::int32_t>(target.mType);
      out.entity = target.mEntityId;
      out.position = {target.mPos.x, target.mPos.y, target.mPos.z};
      return out;
    }
  } // namespace

  wire::SCommandData CommandDataFromSim(
    const moho::SSTICommandVariableData& data
  )
  {
    wire::SCommandData out;
    out.units.reserve(data.mEntIds.size());
    for (const moho::EntId unit : data.mEntIds) {
      out.units.push_back(static_cast<std::uint32_t>(unit));
    }
    out.type = static_cast<std::int32_t>(data.mCmdType);
    out.target1 = ToWire(data.mTarget1);
    out.target2 = ToWire(data.mTarget2);
    out.extra = data.v14;
    out.cells.reserve(data.mCells.size());
    for (const moho::SOCellPos& cell : data.mCells) {
      out.cells.push_back({cell.x, cell.z});
    }
    out.maxCount = data.mMaxCount;
    out.count = data.mCount;
    out.flags = data.v23;
    return out;
  }

  wire::SCommandDescriptor CommandDescriptorFromSim(
    const moho::SSTICommandConstantData& data,
    const CCommandBook::BlueprintRef& blueprint
  )
  {
    static_assert(sizeof(data.origin) == sizeof(float) * 4u, "the origin is four floats");
    wire::SCommandDescriptor out;
    out.id = static_cast<std::uint32_t>(data.cmd);
    out.formation = data.mFormationScriptIndex;
    std::memcpy(out.origin.data(), &data.origin, sizeof(out.origin));
    out.scale = data.unk1;
    out.blueprint = data.blueprint != nullptr && blueprint ? blueprint(data.blueprint) : 0u;
    const std::string_view script = data.unk2.view();
    out.script.assign(script.data(), script.size());
    return out;
  }

  void CCommandBook::TakeBeat(
    const moho::SSyncData& packet,
    const ArmyOf& armyOf,
    const BlueprintRef& blueprint
  )
  {
    ++mBeats;
    for (const std::uint32_t id : mReleased) {
      mCommands.erase(id);
    }
    mReleased.clear();
    mEvents.clear();

    for (const moho::SSTICommandConstantData& descriptor : packet.mPublishedCommandDescriptors) {
      SCommand& command = mCommands[static_cast<std::uint32_t>(descriptor.cmd)];
      command.descriptor = CommandDescriptorFromSim(descriptor, blueprint);
      command.shown = true;
      ++mDescriptors;
    }
    for (const moho::SSyncPublishedCommandPacket& published : packet.mPublishedCommandPackets) {
      const auto id = static_cast<std::uint32_t>(published.commandId);
      const auto found = mCommands.find(id);
      if (found == mCommands.end()) {
        ++mOrphans; // the sim publishes a packet only after the command's descriptor
        continue;
      }
      SCommand& command = found->second;
      command.data = CommandDataFromSim(published.variableData);
      command.armies.resize(command.data.units.size());
      for (std::size_t i = 0; i < command.data.units.size(); ++i) {
        command.armies[i] = armyOf ? armyOf(command.data.units[i]) : kNoArmy;
        mUnitsWithoutArmy += command.armies[i] == kNoArmy ? 1u : 0u;
      }
      command.shown = true;
      mEvents.push_back({EEvent::Update, id});
      ++mPackets;
    }
    for (const moho::CmdId removed : packet.mPendingCommandEventRemovals) {
      const auto id = static_cast<std::uint32_t>(removed);
      if (const auto found = mCommands.find(id); found != mCommands.end()) {
        found->second.shown = false;
      }
      mEvents.push_back({EEvent::Removal, id});
      ++mRemovals;
    }
    for (const moho::CmdId released : packet.mPendingReleasedCommandIds) {
      const auto id = static_cast<std::uint32_t>(released);
      mEvents.push_back({EEvent::Release, id});
      mReleased.push_back(id);
      ++mReleases;
    }

    mLiveIds.clear();
    mLiveIds.reserve(mCommands.size());
    for (const auto& [id, command] : mCommands) {
      mLiveIds.push_back(id);
    }
    std::sort(mLiveIds.begin(), mLiveIds.end());
    if (!mReleased.empty()) {
      std::vector<std::uint32_t> released = mReleased;
      std::sort(released.begin(), released.end());
      std::vector<std::uint32_t> live;
      live.reserve(mLiveIds.size());
      std::set_difference(mLiveIds.begin(), mLiveIds.end(), released.begin(), released.end(), std::back_inserter(live));
      mLiveIds.swap(live);
    }
  }

  void CCommandViewRoute::Cut(
    const CCommandBook::SCommand& command,
    const std::int32_t army,
    const bool everything,
    const STranslate& translate,
    wire::SCommandData& out
  )
  {
    out = command.data;
    // Units keep their sim ids in every view (remote/ViewIdMap.h), so only the list is cut.
    if (!everything) {
      std::size_t kept = 0;
      for (std::size_t i = 0; i < out.units.size(); ++i) {
        if (i < command.armies.size() && static_cast<std::int32_t>(command.armies[i]) == army) {
          out.units[kept++] = out.units[i];
        }
      }
      mCounts.unitsLeftOut += out.units.size() - kept;
      out.units.resize(kept);
    }
    if (out.units.empty()) {
      return;
    }
    for (wire::SCommandTarget* const target : {&out.target1, &out.target2}) {
      if (target->entity == wire::kNoCommandEntity) {
        continue;
      }
      const std::uint32_t viewId = translate.entity(target->entity);
      mCounts.targetsWithheld += viewId == wire::kNoCommandEntity ? 1u : 0u;
      mCounts.targetsRenumbered += viewId != wire::kNoCommandEntity && viewId != target->entity ? 1u : 0u;
      target->entity = viewId;
    }
  }

  void CCommandViewRoute::Write(
    const CCommandBook& book,
    const std::int32_t army,
    const bool everything,
    const bool whole,
    const STranslate& translate,
    wire::SCommandLane& lane
  )
  {
    lane.Clear();
    wire::SCommandData data;
    const auto describe = [&](SHeld& held, const CCommandBook::SCommand& command) {
      wire::SCommandDescriptor descriptor = command.descriptor;
      descriptor.id = held.viewId;
      lane.descriptors.push_back(std::move(descriptor));
      held.sent = wire::SCommandData{}; // a new helper starts from the defaults
      held.shown = true;
      ++mCounts.descriptors;
    };
    const auto update = [&](SHeld& held) {
      const std::uint32_t fields = wire::CommandFieldsChanged(held.sent, data);
      mCounts.emptyUpdates += fields == 0u ? 1u : 0u;
      ++mCounts.updates;
      held.sent = data;
      lane.updates.push_back({held.viewId, fields, std::move(data)});
      data = wire::SCommandData{};
    };

    if (whole) {
      // Its client holds nothing the server knows of: every shown command with one of its units, whole. Any other
      // helper it held goes (the lane is whole). Its own commands' releases still go, so its pool has their ids back.
      lane.whole = true;
      ++mCounts.wholes;
      std::unordered_map<std::uint32_t, SHeld> next;
      for (const std::uint32_t simId : book.LiveIds()) {
        const CCommandBook::SCommand* const command = book.Find(simId);
        if (command == nullptr || !command->shown) {
          continue;
        }
        Cut(*command, army, everything, translate, data);
        if (data.units.empty()) {
          continue;
        }
        SHeld& held = next[simId];
        held.viewId = translate.command(simId);
        describe(held, *command);
        update(held);
      }
      for (const CCommandBook::SEvent& event : book.Events()) {
        if (event.kind == CCommandBook::EEvent::Release && translate.isOwn(event.id)) {
          lane.releases.push_back(event.id);
          ++mCounts.ownReleases;
        }
      }
      mHeld.swap(next);
      return;
    }

    for (const CCommandBook::SEvent& event : book.Events()) {
      auto held = mHeld.find(event.id);
      switch (event.kind) {
      case CCommandBook::EEvent::Update: {
        const CCommandBook::SCommand* const command = book.Find(event.id);
        if (command == nullptr) {
          break;
        }
        Cut(*command, army, everything, translate, data);
        if (!data.units.empty()) {
          if (held == mHeld.end()) {
            held = mHeld.emplace(event.id, SHeld{}).first;
            held->second.viewId = translate.command(event.id);
          }
          if (!held->second.shown) {
            describe(held->second, *command);
          }
          update(held->second);
        } else if (held != mHeld.end() && held->second.shown) {
          // None of its units left in the record: the focused sim takes it off the client.
          lane.removals.push_back(held->second.viewId);
          held->second.shown = false;
          ++mCounts.removals;
        }
        break;
      }
      case CCommandBook::EEvent::Removal:
        if (held != mHeld.end() && held->second.shown) {
          lane.removals.push_back(held->second.viewId);
          held->second.shown = false;
          ++mCounts.removals;
        }
        break;
      case CCommandBook::EEvent::Release:
        if (held != mHeld.end()) {
          lane.releases.push_back(held->second.viewId);
          mHeld.erase(held);
          ++mCounts.releases;
        } else if (translate.isOwn(event.id)) {
          lane.releases.push_back(event.id); // its own id, which it keeps as it is
          ++mCounts.ownReleases;
        }
        break;
      }
    }
  }

  std::size_t CCommandViewRoute::Shown() const noexcept
  {
    std::size_t shown = 0;
    for (const auto& [id, held] : mHeld) {
      shown += held.shown ? 1u : 0u;
    }
    return shown;
  }
} // namespace faf::remote
