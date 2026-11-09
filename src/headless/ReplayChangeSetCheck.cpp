#include "headless/ReplayChangeSetCheck.h"

#include <algorithm>
#include <cstdio>

#include "moho/entity/Entity.h"
#include "moho/sim/SimDriver.h"
#include "remote/VisibilityOracle.h"

// Engine addition, server mode: see ReplayChangeSetCheck.h.

namespace faf::headless
{
  namespace
  {
    constexpr std::size_t kLoggedDifferences = 20;
    constexpr const char* kKindNames[] = {"units", "blips", "props", "projectiles", "other"};

    [[nodiscard]] std::size_t KindOf(moho::Entity& entity)
    {
      if (entity.IsUnit() != nullptr) {
        return 0;
      }
      if (entity.IsReconBlip() != nullptr) {
        return 1;
      }
      if (entity.IsProp() != nullptr) {
        return 2;
      }
      if (entity.IsProjectile() != nullptr) {
        return 3;
      }
      return 4;
    }
  } // namespace

  CReplayChangeSetCheck::~CReplayChangeSetCheck()
  {
    Uninstall();
  }

  void CReplayChangeSetCheck::Install()
  {
    moho::Sim::SetSyncObserver(this);
  }

  void CReplayChangeSetCheck::Uninstall()
  {
    moho::Sim::SetSyncObserver(nullptr);
  }

  void CReplayChangeSetCheck::OnBeatChanges(moho::Sim& sim, const moho::SSyncData& packet)
  {
    const std::lock_guard<std::mutex> guard(mLock);
    ++mBeats;

    mIds.clear();
    for (const remote::SChangedEntity& changed : Entities()) {
      mIds.push_back(static_cast<std::uint32_t>(changed.entity->id_));
    }
    mChanged += mIds.size();

    mPacketIds.clear();
    for (const moho::SCreateEntityParams& params : packet.mNewEntities) {
      mPacketIds.push_back(static_cast<std::uint32_t>(params.mEntityId));
    }
    for (const moho::SCreateUnitParams& params : packet.mNewUnits) {
      mPacketIds.push_back(static_cast<std::uint32_t>(params.mEntityId));
    }
    for (const moho::SEntityVariableUpdateEntry& update : packet.mEntityUpdates) {
      mPacketIds.push_back(static_cast<std::uint32_t>(update.mEntityId));
    }
    for (const moho::SUnitVariableUpdateEntry& update : packet.mUnitUpdates) {
      mPacketIds.push_back(static_cast<std::uint32_t>(update.mEntityId));
    }
    for (const moho::EntId id : packet.mDeleteIds) {
      mPacketIds.push_back(static_cast<std::uint32_t>(id));
    }
    for (const moho::EntId id : packet.mEraseIds) {
      mPacketIds.push_back(static_cast<std::uint32_t>(id));
    }
    std::sort(mPacketIds.begin(), mPacketIds.end());
    mPacketIds.erase(std::unique(mPacketIds.begin(), mPacketIds.end()), mPacketIds.end());
    mPacketRecords += mPacketIds.size();

    const auto note = [&](const char* const what, const std::uint32_t id) {
      if (mExamples.size() < kLoggedDifferences) {
        char line[160];
        std::snprintf(line, sizeof(line), "beat %u id 0x%08X: %s", sim.mCurBeat, id, what);
        mExamples.emplace_back(line);
      }
    };

    for (const std::uint32_t id : mPacketIds) {
      if (!std::binary_search(mIds.begin(), mIds.end(), id)) {
        ++mPacketNotInSet;
        note("in the packet, not in the change set", id);
      }
    }

    const std::int32_t focusArmy = sim.mSyncFilter.focusArmy;
    for (const remote::SChangedEntity& changed : Entities()) {
      moho::Entity* const entity = changed.entity;
      const auto id = static_cast<std::uint32_t>(entity->id_);
      if (std::binary_search(mPacketIds.begin(), mPacketIds.end(), id)) {
        continue;
      }
      if (remote::ResolveViewVisibility(sim, focusArmy, *entity).published) {
        ++mPublishedSilent;
        note("published at this focus, no packet record", id);
      } else {
        ++mUnpublishedByKind[KindOf(*entity)];
      }
    }
  }

  std::uint64_t CReplayChangeSetCheck::Failures() const noexcept
  {
    const std::lock_guard<std::mutex> guard(mLock);
    return mPacketNotInSet + mPublishedSilent;
  }

  std::string CReplayChangeSetCheck::Summary() const
  {
    const std::uint64_t failures = Failures();
    const std::lock_guard<std::mutex> guard(mLock);
    char text[320];
    std::snprintf(
      text, sizeof(text),
      "change-set check: %llu beats, %llu entities synced, %llu packet ids, %llu packet ids missing from the change "
      "set, %llu published entities with no packet record (%llu failures)",
      static_cast<unsigned long long>(mBeats), static_cast<unsigned long long>(mChanged),
      static_cast<unsigned long long>(mPacketRecords), static_cast<unsigned long long>(mPacketNotInSet),
      static_cast<unsigned long long>(mPublishedSilent), static_cast<unsigned long long>(failures)
    );
    std::string summary = text;
    summary += "\n  synced but not published at this focus:";
    for (std::size_t kind = 0; kind < kKindCount; ++kind) {
      std::snprintf(
        text, sizeof(text), " %s %llu", kKindNames[kind], static_cast<unsigned long long>(mUnpublishedByKind[kind])
      );
      summary += text;
    }
    for (const std::string& example : mExamples) {
      summary += "\n  " + example;
    }
    return summary;
  }
} // namespace faf::headless
