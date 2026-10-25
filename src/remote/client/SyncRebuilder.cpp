#include "remote/client/SyncRebuilder.h"

#include <algorithm>
#include <cmath>
#include <string>
#include <unordered_set>
#include <utility>

#include "moho/entity/REntityBlueprint.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SimDriver.h"
#include "moho/unit/core/Unit.h"
#include "remote/FrameBuilder.h"

// Engine addition, server mode: see SyncRebuilder.h.

namespace faf::remote::client
{
  namespace
  {
    void AppendBlueprints(
      const moho::RRuleGameRulesBlueprintMap& map, const wire::COrdinalTable& table,
      std::vector<const moho::REntityBlueprint*>& out
    )
    {
      for (const auto& [id, blueprint] : map) {
        if (blueprint == nullptr) {
          continue;
        }
        const std::uint32_t ordinal = table.Ordinal(id.c_str());
        if (ordinal < out.size()) {
          out[ordinal] = static_cast<const moho::REntityBlueprint*>(blueprint);
        }
      }
    }

    [[nodiscard]] bool SameTransform(const moho::VTransform& a, const moho::VTransform& b) noexcept
    {
      return a.pos_.x == b.pos_.x && a.pos_.y == b.pos_.y && a.pos_.z == b.pos_.z && a.orient_.w == b.orient_.w
        && a.orient_.x == b.orient_.x && a.orient_.y == b.orient_.y && a.orient_.z == b.orient_.z;
    }

    template <class Entry>
    [[nodiscard]] std::unordered_map<std::uint32_t, const Entry*> IndexById(const msvc8::vector<Entry>& entries)
    {
      std::unordered_map<std::uint32_t, const Entry*> index;
      index.reserve(entries.size());
      for (const Entry& entry : entries) {
        index[static_cast<std::uint32_t>(entry.mEntityId)] = &entry;
      }
      return index;
    }

    [[nodiscard]] std::unordered_set<std::uint32_t> IdSet(const msvc8::vector<moho::EntId>& ids)
    {
      std::unordered_set<std::uint32_t> set;
      for (const moho::EntId id : ids) {
        set.insert(static_cast<std::uint32_t>(id));
      }
      return set;
    }

    [[nodiscard]] bool IsOrphaned(const wire::SEntityRecord& record) noexcept
    {
      return (record.flags & kEntityFlagOrphaned) != 0u;
    }
  } // namespace

  std::vector<const moho::REntityBlueprint*> ResolveBlueprints(
    moho::RRuleGameRules& rules, const wire::SContentTables& tables
  )
  {
    std::vector<const moho::REntityBlueprint*> blueprints(tables.blueprints.Size(), nullptr);
    AppendBlueprints(rules.GetUnitBlueprints(), tables.blueprints, blueprints);
    AppendBlueprints(rules.GetPropBlueprints(), tables.blueprints, blueprints);
    AppendBlueprints(rules.GetProjectileBlueprints(), tables.blueprints, blueprints);
    return blueprints;
  }

  CSyncRebuilder::CSyncRebuilder(
    const wire::SFrameCodec& codec, std::vector<const moho::REntityBlueprint*> blueprints
  )
    : mCodec(codec)
    , mBlueprints(std::move(blueprints))
  {}

  moho::VTransform CSyncRebuilder::ShownTransform(const wire::SEntityRecord& record, const std::uint32_t beat) const
  {
    const wire::QuantizedPosition position =
      mCodec.deadReckoning ? wire::PredictPosition(record, beat, mCodec) : record.position;
    const std::array<float, 4> q =
      record.yawOnly ? wire::YawToQuaternion(record.orientation) : wire::UnpackQuaternion(record.orientation);
    moho::VTransform transform{};
    transform.orient_ = Wm3::Quatf(q[3], q[0], q[1], q[2]);
    transform.pos_ = Wm3::Vec3f(
      mCodec.position.x.Decode(position[0]), mCodec.position.y.Decode(position[1]),
      mCodec.position.z.Decode(position[2])
    );
    return transform;
  }

  bool CSyncRebuilder::Apply(const std::span<const std::uint8_t> frameBytes, moho::SSyncData& packet)
  {
    // The frame, against the one decoded last (the only baseline this client keeps).
    const std::uint32_t baselineId = wire::PeekFrameBaseline(frameBytes);
    const wire::SViewFrame* baseline = nullptr;
    if (baselineId != wire::kNoBaseline) {
      if (!mHasShown || mShown.frameId != baselineId) {
        ++mStats.decodeFailures;
        return false;
      }
      baseline = &mShown;
    }
    wire::BitReader reader(frameBytes);
    wire::SViewFrame frame;
    if (!wire::DecodeFrame(reader, baseline, mCodec, frame)) {
      ++mStats.decodeFailures;
      return false;
    }
    ++mStats.frames;
    mStats.frameBytes += frameBytes.size();

    const wire::SFrameDelta delta = wire::ComputeFrameDelta(mHasShown ? &mShown : nullptr, frame);
    const std::uint32_t beat = frame.beat;

    // What the handed packet says, for what the wire does not carry and for the checks.
    const auto packetEntities = IndexById(packet.mNewEntities);
    const auto packetUnits = IndexById(packet.mNewUnits);
    const auto packetEntityUpdates = IndexById(packet.mEntityUpdates);
    const auto packetErased = IdSet(packet.mEraseIds);
    const auto packetDeleted = IdSet(packet.mDeleteIds);

    msvc8::vector<moho::SCreateEntityParams> newEntities;
    msvc8::vector<moho::SCreateUnitParams> newUnits;
    msvc8::vector<moho::EntId> eraseIds;
    msvc8::vector<moho::EntId> deleteIds;
    std::unordered_set<std::uint32_t> createdNow;
    std::unordered_set<std::uint32_t> erasedNow; // still updated this beat: `DoBeat` erases after updates

    const auto create = [&](const wire::SEntityRecord& record) {
      const moho::REntityBlueprint* const blueprint =
        record.blueprint < mBlueprints.size() ? mBlueprints[record.blueprint] : nullptr;
      if (blueprint == nullptr) {
        ++mStats.noBlueprint;
      }
      if (record.isUnit) {
        moho::SCreateUnitParams params{};
        params.mEntityId = record.id;
        params.mBlueprint = blueprint;
        params.mTickCreated = static_cast<std::uint32_t>(packet.mCurTick);
        if (const auto it = packetUnits.find(record.id); it != packetUnits.end()) {
          params.mTickCreated = it->second->mTickCreated;
          params.mConstDat = it->second->mConstDat;
          mStats.blueprintMismatches += it->second->mBlueprint != blueprint ? 1u : 0u;
        } else {
          ++mStats.createdNotInPacket;
          ++mStats.unitConstantsMissing;
        }
        newUnits.push_back(params);
      } else {
        moho::SCreateEntityParams params{};
        params.mEntityId = record.id;
        params.mBlueprint = blueprint;
        params.mTickCreated = static_cast<std::uint32_t>(packet.mCurTick);
        if (const auto it = packetEntities.find(record.id); it != packetEntities.end()) {
          params.mTickCreated = it->second->mTickCreated;
          mStats.blueprintMismatches += it->second->mBlueprint != blueprint ? 1u : 0u;
        } else {
          ++mStats.createdNotInPacket;
        }
        newEntities.push_back(params);
      }
      ++mStats.created;
      createdNow.insert(record.id);
      SHeldEntity& held = mHeld[record.id];
      held = SHeldEntity{};
      held.live = true;
    };

    // Removals: a live entity goes (delete); an orphaned record leaving the frame has no
    // entity in the id map any more.
    for (const std::uint32_t id : delta.removed) {
      const auto it = mHeld.find(id);
      if (it != mHeld.end() && it->second.live) {
        deleteIds.push_back(static_cast<moho::EntId>(id));
        ++mStats.deleted;
        mStats.deleteMismatches += packetDeleted.count(id) == 0u ? 1u : 0u;
      }
      mHeld.erase(id);
    }
    for (const wire::SEntityRecord& record : delta.created) {
      if (IsOrphaned(record)) {
        mHeld[record.id] = SHeldEntity{}; // erased before this client saw it
      } else {
        create(record);
      }
    }
    for (const wire::SFrameDelta::SChange& change : delta.changed) {
      const auto it = mHeld.find(change.record.id);
      const bool live = it != mHeld.end() && it->second.live;
      if (IsOrphaned(change.record)) {
        if (live) {
          eraseIds.push_back(static_cast<moho::EntId>(change.record.id));
          it->second.live = false;
          erasedNow.insert(change.record.id);
          ++mStats.erased;
          mStats.eraseMismatches += packetErased.count(change.record.id) == 0u ? 1u : 0u;
        }
      } else if (!live) {
        create(change.record); // an id reused after an erase
      }
    }
    for (const std::uint32_t id : packetErased) {
      mStats.eraseMismatches += std::find(eraseIds.begin(), eraseIds.end(), static_cast<moho::EntId>(id)) == eraseIds.end()
        ? 1u
        : 0u;
    }
    for (const std::uint32_t id : packetDeleted) {
      const bool transient = packetEntities.count(id) != 0u || packetUnits.count(id) != 0u;
      if (!transient && std::find(deleteIds.begin(), deleteIds.end(), static_cast<moho::EntId>(id)) == deleteIds.end()) {
        ++mStats.deleteMismatches;
      }
    }
    for (const auto& [id, params] : packetEntities) {
      mStats.packetCreatedNotRebuilt += createdNow.count(id) == 0u ? 1u : 0u;
    }
    for (const auto& [id, params] : packetUnits) {
      mStats.packetCreatedNotRebuilt += createdNow.count(id) == 0u ? 1u : 0u;
    }

    // Entity updates: every live entity whose frame record changed, that the packet updates
    // (data the frame has no field for), or whose last transform has not caught up with its
    // current one (the UI interpolates between them).
    std::unordered_set<std::uint32_t> changedNow;
    for (const wire::SFrameDelta::SChange& change : delta.changed) {
      changedNow.insert(change.record.id);
    }
    const auto updatable = [&](const std::uint32_t id) {
      const auto it = mHeld.find(id);
      return it != mHeld.end() && (it->second.live || erasedNow.count(id) != 0u);
    };
    msvc8::vector<moho::SEntityVariableUpdateEntry> entityUpdates;
    for (const wire::SEntityRecord& record : frame.entities) {
      if (!updatable(record.id)) {
        continue;
      }
      const auto heldIt = mHeld.find(record.id);
      SHeldEntity& held = heldIt->second;
      const bool created = createdNow.count(record.id) != 0u;
      const auto packetIt = packetEntityUpdates.find(record.id);
      const bool fromPacket = packetIt != packetEntityUpdates.end();
      const bool moving = mCodec.deadReckoning && record.velocity != std::array<std::int32_t, 3>{};
      const bool settling = !created && !SameTransform(held.data.mCurTransform, held.data.mLastTransform);
      if (!created && !fromPacket && !moving && !settling && changedNow.count(record.id) == 0u) {
        continue;
      }

      moho::SEntityVariableUpdateEntry entry{};
      entry.mEntityId = static_cast<moho::EntId>(record.id);
      entry.mVariableData = fromPacket ? packetIt->second->mVariableData : held.data;
      if (fromPacket) {
        entry.mReserved04 = packetIt->second->mReserved04;
        ++mStats.entityDataBorrowed;
      } else {
        // A one-beat request the sim clears once it has synced it; the copy kept here must
        // not repeat it.
        entry.mVariableData.mRequestRefreshUI = 0u;
      }
      moho::SSTIEntityVariableData& data = entry.mVariableData;
      const moho::VTransform shown = ShownTransform(record, beat);
      data.mLastTransform = created ? shown : held.data.mCurTransform;
      data.mCurTransform = shown;
      data.mHealth = record.health;
      data.mMaxHealth = record.maxHealth;
      data.mFractionComplete = record.fractionComplete;
      UnpackEntityFlags(record.flags, data);
      if (fromPacket) {
        const Wm3::Vec3f& actual = packetIt->second->mVariableData.mCurTransform.pos_;
        mStats.maxPositionError = std::max(
          {mStats.maxPositionError, std::fabs(static_cast<double>(actual.x - shown.pos_.x)),
           std::fabs(static_cast<double>(actual.y - shown.pos_.y)),
           std::fabs(static_cast<double>(actual.z - shown.pos_.z))}
        );
      } else if (settling && changedNow.count(record.id) == 0u && !moving) {
        ++mStats.settleUpdates;
      }
      held.data = data;
      entityUpdates.push_back(std::move(entry));
      ++mStats.entityUpdates;
    }
    for (const auto& [id, entry] : packetEntityUpdates) {
      mStats.packetUpdatesDropped += updatable(id) ? 0u : 1u;
    }

    // Unit updates: the packet's, for units the client holds, with the frame's unit block.
    msvc8::vector<moho::SUnitVariableUpdateEntry> unitUpdates;
    std::unordered_set<std::uint32_t> unitUpdated;
    std::unordered_map<std::uint32_t, const wire::SEntityRecord*> records;
    records.reserve(frame.entities.size());
    for (const wire::SEntityRecord& record : frame.entities) {
      records[record.id] = &record;
    }
    for (moho::SUnitVariableUpdateEntry& update : packet.mUnitUpdates) {
      const auto id = static_cast<std::uint32_t>(update.mEntityId);
      const auto recordIt = records.find(id);
      if (!updatable(id) || recordIt == records.end() || !recordIt->second->isUnit) {
        ++mStats.packetUpdatesDropped;
        continue;
      }
      UnpackUnitFields(recordIt->second->unit, update.mVariableData);
      unitUpdated.insert(id);
      unitUpdates.push_back(std::move(update));
    }
    for (const wire::SFrameDelta::SChange& change : delta.changed) {
      if ((change.fields & wire::kUnitFields) != 0u && unitUpdated.count(change.record.id) == 0u) {
        ++mStats.unitChangesWithoutUpdate;
      }
    }

    packet.mNewEntities.swap(newEntities);
    packet.mNewUnits.swap(newUnits);
    packet.mEntityUpdates.swap(entityUpdates);
    packet.mUnitUpdates.swap(unitUpdates);
    packet.mEraseIds.swap(eraseIds);
    packet.mDeleteIds.swap(deleteIds);

    mShown = std::move(frame);
    mHasShown = true;
    return true;
  }
} // namespace faf::remote::client
