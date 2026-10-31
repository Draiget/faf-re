#include "remote/ViewIdMap.h"

#include <algorithm>

// Engine addition, server mode: see ViewIdMap.h.

namespace faf::remote
{
  namespace
  {
    constexpr std::uint32_t kFamilyProjectile = 1u;
    constexpr std::uint32_t kFamilyReconBlip = 3u;
    constexpr std::uint32_t kSerialMask = 0x000FFFFFu;
    constexpr std::uint32_t kCommandSerialMask = 0x00FFFFFFu;
    constexpr std::uint32_t kViewCommandTop = 0x80000000u; // the sim's own top byte; never a client's source

    [[nodiscard]] constexpr std::uint32_t Family(const std::uint32_t id) noexcept { return id >> 28u; }
    [[nodiscard]] constexpr std::uint32_t Source(const std::uint32_t id) noexcept { return (id >> 20u) & 0xFFu; }
  } // namespace

  bool CViewIdMap::MapsEntity(const std::uint32_t simId) const noexcept
  {
    const std::uint32_t family = Family(simId);
    if (family == kFamilyReconBlip) {
      return true;
    }
    return family == kFamilyProjectile && Source(simId) != static_cast<std::uint32_t>(mViewArmy);
  }

  std::uint32_t CViewIdMap::Entity(const std::uint32_t simId)
  {
    if (!MapsEntity(simId)) {
      return simId;
    }
    if (const auto found = mEntityToView.find(simId); found != mEntityToView.end()) {
      return found->second;
    }
    // Serials start at 1 in every family and source, in order of first appearance in this view.
    const std::uint32_t prefix = simId & ~kSerialMask;
    std::uint32_t& next = mNextSerial[prefix >> 20u];
    next = (next + 1u) & kSerialMask;
    if (next == 0u) {
      ++mOverflows;
      next = 1u;
    }
    const std::uint32_t viewId = prefix | next;
    mEntityToView.emplace(simId, viewId);
    mEntityToSim[viewId] = simId;
    ++mEntitiesMapped;
    return viewId;
  }

  std::uint32_t CViewIdMap::Command(const std::uint32_t simId, const OwnCommandTest& isOwnCommand)
  {
    if (isOwnCommand(simId)) {
      return simId;
    }
    if (const auto found = mCommandToView.find(simId); found != mCommandToView.end()) {
      return found->second;
    }
    mNextCommand = (mNextCommand + 1u) & kCommandSerialMask;
    if (mNextCommand == 0u) {
      ++mOverflows;
      mNextCommand = 1u;
    }
    const std::uint32_t viewId = kViewCommandTop | mNextCommand;
    mCommandToView.emplace(simId, viewId);
    mCommandToSim[viewId] = simId;
    ++mCommandsMapped;
    return viewId;
  }

  void CViewIdMap::Translate(wire::SViewFrame& frame, const OwnCommandTest& isOwnCommand)
  {
    for (wire::SEntityRecord& record : frame.entities) {
      record.id = Entity(record.id);
      if (record.appearance.attachParent != wire::SAppearance::kNoAttachParent) {
        record.appearance.attachParent = Entity(record.appearance.attachParent);
      }
      for (std::uint32_t& child : record.appearance.attachments) {
        child = Entity(child);
      }
      if (!record.isUnit) {
        continue;
      }
      // The detail is a value shared with the builder's world and earlier frames: it is copied
      // only when one of its ids is renumbered.
      const wire::SUnitDetail& shared = *record.unit.detail;
      const auto foreignCommand = [&isOwnCommand](const std::int32_t command) {
        return !isOwnCommand(static_cast<std::uint32_t>(command));
      };
      if (!MapsEntity(shared.creator) && !MapsEntity(shared.selectionInheritor) && !MapsEntity(shared.focusUnit)
          && !MapsEntity(shared.guardedUnit) && !MapsEntity(shared.targetBlip)
          && std::none_of(shared.commands.begin(), shared.commands.end(), foreignCommand)
          && std::none_of(shared.buildQueue.begin(), shared.buildQueue.end(), foreignCommand)) {
        continue;
      }
      wire::SUnitDetail detail = shared;
      detail.creator = Entity(detail.creator);
      detail.selectionInheritor = Entity(detail.selectionInheritor);
      detail.focusUnit = Entity(detail.focusUnit);
      detail.guardedUnit = Entity(detail.guardedUnit);
      detail.targetBlip = Entity(detail.targetBlip);
      for (std::int32_t& command : detail.commands) {
        command = static_cast<std::int32_t>(Command(static_cast<std::uint32_t>(command), isOwnCommand));
      }
      for (std::int32_t& command : detail.buildQueue) {
        command = static_cast<std::int32_t>(Command(static_cast<std::uint32_t>(command), isOwnCommand));
      }
      record.unit.detail.Assign(detail);
    }
    std::sort(frame.entities.begin(), frame.entities.end(), [](const wire::SEntityRecord& a, const wire::SEntityRecord& b) {
      return a.id < b.id;
    });
  }

  void CViewIdMap::RetireEntities(const std::span<const std::uint32_t> simIds)
  {
    for (const std::uint32_t simId : simIds) {
      if (const auto found = mEntityToView.find(simId); found != mEntityToView.end()) {
        mGrace.push_back({mBeat + kInboundGraceBeats, found->second, simId, false});
        mGraceEntities[simId] = found->second;
        mRetiredAt[simId] = mBeat;
        mEntityToView.erase(found);
      }
    }
  }

  void CViewIdMap::RetireCommands(const std::span<const std::uint32_t> simIds)
  {
    for (const std::uint32_t simId : simIds) {
      if (const auto found = mCommandToView.find(simId); found != mCommandToView.end()) {
        mGrace.push_back({mBeat + kInboundGraceBeats, found->second, simId, true});
        mGraceCommands[simId] = found->second;
        mCommandToView.erase(found);
      }
    }
  }

  void CViewIdMap::RetireCommandsUnless(const std::function<bool(std::uint32_t simId)>& alive)
  {
    for (auto it = mCommandToView.begin(); it != mCommandToView.end();) {
      if (alive(it->first)) {
        ++it;
        continue;
      }
      mGrace.push_back({mBeat + kInboundGraceBeats, it->second, it->first, true});
      mGraceCommands[it->first] = it->second;
      it = mCommandToView.erase(it);
    }
  }

  void CViewIdMap::AdvanceTo(const std::uint32_t beat)
  {
    mBeat = beat;
    while (!mGrace.empty() && mGrace.front().until <= beat) {
      const SGrace& retired = mGrace.front();
      (retired.command ? mCommandToSim : mEntityToSim).erase(retired.viewId);
      auto& held = retired.command ? mGraceCommands : mGraceEntities;
      if (const auto found = held.find(retired.simId); found != held.end() && found->second == retired.viewId) {
        held.erase(found);
      }
      mGrace.pop_front();
    }
  }

  bool CViewIdMap::EntityToSim(const std::uint32_t viewId, std::uint32_t& simId) const
  {
    if (!MapsEntity(viewId)) {
      simId = viewId; // never renumbered: the view sees the sim's id
      return true;
    }
    const auto found = mEntityToSim.find(viewId);
    if (found == mEntityToSim.end()) {
      return false;
    }
    simId = found->second;
    return true;
  }

  bool CViewIdMap::EntityToView(const std::uint32_t simId, std::uint32_t& viewId) const
  {
    if (!MapsEntity(simId)) {
      viewId = simId;
      return true;
    }
    const auto found = mEntityToView.find(simId);
    if (found == mEntityToView.end()) {
      return false;
    }
    viewId = found->second;
    return true;
  }

  bool CViewIdMap::CommandToView(
    const std::uint32_t simId, const OwnCommandTest& isOwnCommand, std::uint32_t& viewId
  ) const
  {
    if (isOwnCommand(simId)) {
      viewId = simId;
      return true;
    }
    const auto found = mCommandToView.find(simId);
    if (found == mCommandToView.end()) {
      return false;
    }
    viewId = found->second;
    return true;
  }

  bool CViewIdMap::EntityToHeldView(const std::uint32_t simId, std::uint32_t& viewId) const
  {
    if (EntityToView(simId, viewId)) {
      return true;
    }
    const auto found = mGraceEntities.find(simId);
    if (found == mGraceEntities.end()) {
      return false;
    }
    viewId = found->second;
    return true;
  }

  bool CViewIdMap::CommandToHeldView(
    const std::uint32_t simId, const OwnCommandTest& isOwnCommand, std::uint32_t& viewId
  ) const
  {
    if (CommandToView(simId, isOwnCommand, viewId)) {
      return true;
    }
    const auto found = mGraceCommands.find(simId);
    if (found == mGraceCommands.end()) {
      return false;
    }
    viewId = found->second;
    return true;
  }

  bool CViewIdMap::CommandToSim(const std::uint32_t viewId, std::uint32_t& simId) const
  {
    const auto found = mCommandToSim.find(viewId);
    if (found != mCommandToSim.end()) {
      simId = found->second;
      return true;
    }
    if ((viewId & 0xFF000000u) == kViewCommandTop) {
      return false; // a view id the view never got, or one retired
    }
    simId = viewId; // the client's own command
    return true;
  }
} // namespace faf::remote
