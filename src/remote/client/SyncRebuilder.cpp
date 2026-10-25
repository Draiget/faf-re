#include "remote/client/SyncRebuilder.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <string>
#include <unordered_set>
#include <utility>

#include "gpg/core/utils/Logging.h"
#include "moho/audio/CSndParams.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
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

  std::vector<moho::RMeshBlueprint*> ResolveMeshes(moho::RRuleGameRules& rules, const wire::SContentTables& tables)
  {
    std::vector<moho::RMeshBlueprint*> meshes(tables.meshes.Size(), nullptr);
    for (const auto& [id, blueprint] : rules.GetMeshBlueprints()) {
      if (blueprint == nullptr) {
        continue;
      }
      const std::uint32_t ordinal = tables.meshes.Ordinal(id.c_str());
      if (ordinal < meshes.size()) {
        meshes[ordinal] = static_cast<moho::RMeshBlueprint*>(blueprint);
      }
    }
    return meshes;
  }

  CSyncRebuilder::CSyncRebuilder(
    const wire::SFrameCodec& codec, std::vector<const moho::REntityBlueprint*> blueprints,
    std::vector<moho::RMeshBlueprint*> meshes
  )
    : mCodec(codec)
    , mBlueprints(std::move(blueprints))
    , mMeshes(std::move(meshes))
    , mMeshResources(mMeshes.size())
  {}

  void CSyncRebuilder::ApplyUnitStats(const std::vector<wire::SUnitStat>& stats, moho::Stats<moho::StatItem>& tree)
  {
    for (const wire::SUnitStat& stat : stats) {
      const std::string* const path = mSession != nullptr ? mSession->Names().Find(stat.name) : nullptr;
      if (path == nullptr) {
        ++mStats.unknownTableIds;
        continue;
      }
      moho::StatItem* const item = tree.GetItem(path->c_str(), true);
      if (item == nullptr) {
        continue;
      }
      item->mType = static_cast<moho::EStatType>(stat.type);
      item->mUseRealtimeSlot = stat.realtime ? 1 : 0;
      if (stat.type == wire::SUnitStat::kString) {
        const std::string* const text = mSession->Names().Find(stat.text);
        if (text == nullptr) {
          ++mStats.unknownTableIds;
          continue;
        }
        item->mValue = msvc8::string(text->c_str());
      } else if (stat.realtime) {
        item->mRealtimeValueBits = static_cast<std::int32_t>(stat.bits);
      } else {
        item->mPrimaryValueBits = static_cast<std::int32_t>(stat.bits);
      }
      ++mStats.statsApplied;
    }
  }

  moho::CSndParams* CSyncRebuilder::ResolveSound(const std::uint32_t id)
  {
    if (id == wire::COrdinalTable::kNone || mSession == nullptr) {
      return nullptr;
    }
    if (id < mSounds.size() && mSounds[id] != nullptr) {
      return mSounds[id];
    }
    const wire::SSoundEntry* const entry = mSession->Sounds().Find(id);
    if (entry == nullptr) {
      ++mStats.unknownTableIds;
      return nullptr;
    }
    if (mSounds.size() <= id) {
      mSounds.resize(id + 1u, nullptr);
    }
    // The process's interned params for these names, as `Sound{...}` makes them.
    mSounds[id] = moho::SND_FindOrCreateParams(
      msvc8::string(entry->bank.c_str()), msvc8::string(entry->cue.c_str()), msvc8::string(entry->lodCutoff.c_str()),
      msvc8::string(entry->rpcLoop.c_str())
    );
    return mSounds[id];
  }

  boost::shared_ptr<moho::CD3DBatchTexture> CSyncRebuilder::ResolveUnderlay(const std::uint32_t id)
  {
    if (id == wire::COrdinalTable::kNone || mSession == nullptr) {
      return {};
    }
    if (id < mUnderlays.size() && mUnderlays[id].resolved) {
      return mUnderlays[id].texture;
    }
    const std::string* const path = mSession->Names().Find(id);
    if (path == nullptr) {
      ++mStats.unknownTableIds;
      return {};
    }
    if (mUnderlays.size() <= id) {
      mUnderlays.resize(id + 1u);
    }
    // As `Entity::SetStrategicUnderlay`: the file texture, no border; kept for the session.
    mUnderlays[id].texture = moho::CD3DBatchTexture::FromFile(path->c_str(), 0u);
    mUnderlays[id].resolved = true;
    return mUnderlays[id].texture;
  }

  void CSyncRebuilder::ResolveMesh(const std::uint32_t ordinal, moho::SSTIEntityVariableData& data)
  {
    // As `Entity::SetMesh`: the blueprint and its LOD-resolved mesh, looked up once per mesh.
    if (ordinal >= mMeshes.size() || mMeshes[ordinal] == nullptr) {
      data.mMeshBlueprint = nullptr;
      data.mScmResource.reset();
      return;
    }
    SMeshResource& cached = mMeshResources[ordinal];
    if (!cached.resolved) {
      cached.resource = mMeshes[ordinal]->GetMesh();
      cached.resolved = true;
    }
    data.mMeshBlueprint = mMeshes[ordinal];
    data.mScmResource = cached.resource;
  }

  moho::VTransform CSyncRebuilder::ShownTransform(const wire::SEntityRecord& record, const std::uint32_t beat) const
  {
    const wire::QuantizedPosition position =
      mCodec.deadReckoning ? wire::PredictPosition(record, beat, mCodec) : record.position;
    const std::array<float, 4> q =
      record.yawOnly ? wire::YawToQuaternion(record.orientation) : wire::UnpackQuaternion(record.orientation);
    moho::VTransform transform{};
    transform.orient_ = Wm3::Quatf(q[3], q[0], q[1], q[2]);
    transform.pos_ = record.farPosition
                       ? Wm3::Vec3f(record.farValue[0], record.farValue[1], record.farValue[2])
                       : Wm3::Vec3f(
                           mCodec.position.x.Decode(position[0]), mCodec.position.y.Decode(position[1]),
                           mCodec.position.z.Decode(position[2])
                         );
    return transform;
  }

  bool CSyncRebuilder::Apply(const std::span<const std::uint8_t> frameBytes, moho::SSyncData& packet)
  {
    using Clock = std::chrono::steady_clock;
    const Clock::time_point start = Clock::now();
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

    const Clock::time_point decoded = Clock::now();
    const wire::SFrameDelta delta = wire::ComputeFrameDelta(mHasShown ? &mShown : nullptr, frame);
    const Clock::time_point compared = Clock::now();
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
      SHeldEntity& held = mHeld[record.id];
      held = SHeldEntity{};
      held.live = true;
      if (record.isUnit) {
        // The unit's constants from the frame and a stats tree of the client's own, filled from
        // the frame's stats (below).
        held.stats.reset(new moho::Stats<moho::StatItem>());
        moho::SCreateUnitParams params{};
        params.mEntityId = record.id;
        params.mBlueprint = blueprint;
        params.mTickCreated = static_cast<std::uint32_t>(packet.mCurTick);
        params.mConstDat.mBuildStateTag = record.unit.buildStateTag;
        params.mConstDat.mFake = record.unit.fake;
        params.mConstDat.mStatsRoot = held.stats;
        if (const auto it = packetUnits.find(record.id); it != packetUnits.end()) {
          mStats.blueprintMismatches += it->second->mBlueprint != blueprint ? 1u : 0u;
          mStats.unitConstantsMissing += it->second->mConstDat.mBuildStateTag != record.unit.buildStateTag
                                           || it->second->mConstDat.mFake != record.unit.fake
                                         ? 1u
                                         : 0u;
          mStats.tickMismatches += it->second->mTickCreated != params.mTickCreated ? 1u : 0u;
        } else {
          ++mStats.createdNotInPacket;
        }
        newUnits.push_back(params);
      } else {
        moho::SCreateEntityParams params{};
        params.mEntityId = record.id;
        params.mBlueprint = blueprint;
        params.mTickCreated = static_cast<std::uint32_t>(packet.mCurTick);
        if (const auto it = packetEntities.find(record.id); it != packetEntities.end()) {
          mStats.blueprintMismatches += it->second->mBlueprint != blueprint ? 1u : 0u;
          mStats.tickMismatches += it->second->mTickCreated != params.mTickCreated ? 1u : 0u;
        } else {
          ++mStats.createdNotInPacket;
        }
        newEntities.push_back(params);
      }
      ++mStats.created;
      createdNow.insert(record.id);
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
    const auto updatable = [&](const std::uint32_t id) {
      const auto it = mHeld.find(id);
      return it != mHeld.end() && (it->second.live || erasedNow.count(id) != 0u);
    };
    msvc8::vector<moho::SEntityVariableUpdateEntry> entityUpdates;
    entityUpdates.reserve(packet.mEntityUpdates.size() + delta.changed.size() + delta.created.size());
    // `frame.entities` and the delta's changes are both in id order: one cursor walks the changes.
    auto changeCursor = delta.changed.begin();
    for (const wire::SEntityRecord& record : frame.entities) {
      while (changeCursor != delta.changed.end() && changeCursor->record.id < record.id) {
        ++changeCursor;
      }
      const bool changed = changeCursor != delta.changed.end() && changeCursor->record.id == record.id;
      const auto heldIt = mHeld.find(record.id);
      if (heldIt == mHeld.end() || (!heldIt->second.live && erasedNow.count(record.id) == 0u)) {
        continue;
      }
      SHeldEntity& held = heldIt->second;
      const bool created = createdNow.count(record.id) != 0u;
      const auto packetIt = packetEntityUpdates.find(record.id);
      const bool fromPacket = packetIt != packetEntityUpdates.end();
      const bool moving = mCodec.deadReckoning && record.velocity != std::array<std::int32_t, 3>{};
      const bool settling = !created && !SameTransform(held.data.mCurTransform, held.data.mLastTransform);
      if (!created && !fromPacket && !moving && !settling && !changed) {
        continue;
      }

      moho::SEntityVariableUpdateEntry entry{};
      entry.mEntityId = static_cast<moho::EntId>(record.id);
      // The client's own copy with the frame's fields over it; mesh, sounds and the underlay
      // texture resolved from the frame's ids.
      entry.mVariableData = held.data;
      moho::SSTIEntityVariableData& data = entry.mVariableData;
      if (fromPacket) {
        entry.mReserved04 = packetIt->second->mReserved04;
        ++mStats.entityDataBorrowed;
      }
      UnpackAppearance(record.appearance, data);
      ResolveMesh(record.appearance.mesh, data);
      data.mAmbientSound = ResolveSound(record.appearance.ambientSound);
      data.mRumbleSound = ResolveSound(record.appearance.rumbleSound);
      data.mUnderlayTexture = ResolveUnderlay(record.appearance.underlay);
      const moho::VTransform shown = ShownTransform(record, beat);
      data.mLastTransform = created ? shown : held.data.mCurTransform;
      data.mCurTransform = shown;
      data.mHealth = record.health;
      data.mMaxHealth = record.maxHealth;
      data.mFractionComplete = record.fractionComplete;
      UnpackEntityFlags(record.flags, data);
      if (fromPacket) {
        const moho::SSTIEntityVariableData& sim = packetIt->second->mVariableData;
        mStats.meshMismatches += data.mMeshBlueprint != sim.mMeshBlueprint ? 1u : 0u;
        mStats.meshResourceMismatches += data.mScmResource.get() != sim.mScmResource.get() ? 1u : 0u;
        mStats.soundMismatches += (data.mAmbientSound != sim.mAmbientSound ? 1u : 0u)
                                + (data.mRumbleSound != sim.mRumbleSound ? 1u : 0u);
        mStats.underlayMismatches += data.mUnderlayTexture.get() != sim.mUnderlayTexture.get() ? 1u : 0u;
        const Wm3::Vec3f& actual = sim.mCurTransform.pos_;
        const double error = std::max(
          {std::fabs(static_cast<double>(actual.x - shown.pos_.x)), std::fabs(static_cast<double>(actual.y - shown.pos_.y)),
           std::fabs(static_cast<double>(actual.z - shown.pos_.z))}
        );
        mStats.maxPositionError = std::max(mStats.maxPositionError, error);
        if (!mCodec.deadReckoning && error > 1.0) {
          // Outside the quantiser's range (clamped): the first few are logged to size the range.
          if (++mStats.positionsOutOfRange <= 10u) {
            const moho::REntityBlueprint* const blueprint =
              record.blueprint < mBlueprints.size() ? mBlueprints[record.blueprint] : nullptr;
            gpg::Logf(
              "loopback: entity 0x%08x (%s) at (%.1f, %.1f, %.1f) is outside the position quantiser", record.id,
              blueprint != nullptr ? blueprint->mBlueprintId.c_str() : "no blueprint", actual.x, actual.y, actual.z
            );
          }
        }
      } else if (settling && !changed && !moving) {
        ++mStats.settleUpdates;
      }
      held.data = data;
      entityUpdates.push_back(std::move(entry));
      ++mStats.entityUpdates;
    }
    for (const auto& [id, entry] : packetEntityUpdates) {
      mStats.packetUpdatesDropped += updatable(id) ? 0u : 1u;
    }

    // Unit updates: the packet's, for units the client holds, with the frame's unit block. The
    // records are in id order, so a binary search finds each one; the packet's list is kept in
    // place unless an update has to go (copying a unit update is not cheap).
    const auto findRecord = [&frame](const std::uint32_t id) -> const wire::SEntityRecord* {
      const auto it = std::lower_bound(
        frame.entities.begin(), frame.entities.end(), id,
        [](const wire::SEntityRecord& record, const std::uint32_t key) { return record.id < key; }
      );
      return it != frame.entities.end() && it->id == id ? &*it : nullptr;
    };
    std::unordered_set<std::uint32_t> unitUpdated;
    std::vector<bool> keepUnitUpdate(packet.mUnitUpdates.size(), false);
    bool dropAny = false;
    for (std::size_t i = 0; i < packet.mUnitUpdates.size(); ++i) {
      moho::SUnitVariableUpdateEntry& update = packet.mUnitUpdates[i];
      const auto id = static_cast<std::uint32_t>(update.mEntityId);
      const wire::SEntityRecord* const record = findRecord(id);
      if (!updatable(id) || record == nullptr || !record->isUnit) {
        ++mStats.packetUpdatesDropped;
        dropAny = true;
        continue;
      }
      UnpackUnitFields(record->unit, update.mVariableData);
      unitUpdated.insert(id);
      keepUnitUpdate[i] = true;
    }
    if (dropAny) {
      msvc8::vector<moho::SUnitVariableUpdateEntry> kept;
      for (std::size_t i = 0; i < packet.mUnitUpdates.size(); ++i) {
        if (keepUnitUpdate[i]) {
          kept.push_back(packet.mUnitUpdates[i]);
        }
      }
      packet.mUnitUpdates.swap(kept);
    }
    for (const wire::SFrameDelta::SChange& change : delta.changed) {
      if ((change.fields & wire::kUnitFields) != 0u && unitUpdated.count(change.record.id) == 0u) {
        ++mStats.unitChangesWithoutUpdate;
      }
    }

    // Unit stats: the client's tree of each unit created now or whose stats changed.
    {
      auto changeIt = delta.changed.begin();
      for (const wire::SEntityRecord& record : frame.entities) {
        while (changeIt != delta.changed.end() && changeIt->record.id < record.id) {
          ++changeIt;
        }
        const bool statsChanged = changeIt != delta.changed.end() && changeIt->record.id == record.id
                               && (changeIt->fields & wire::kFieldUnitStats) != 0u;
        if (!record.isUnit || (!statsChanged && createdNow.count(record.id) == 0u)) {
          continue;
        }
        const auto heldIt = mHeld.find(record.id);
        if (heldIt != mHeld.end() && heldIt->second.stats) {
          ApplyUnitStats(record.unit.stats, *heldIt->second.stats);
        }
      }
    }

    packet.mNewEntities.swap(newEntities);
    packet.mNewUnits.swap(newUnits);
    packet.mEntityUpdates.swap(entityUpdates);
    packet.mEraseIds.swap(eraseIds);
    packet.mDeleteIds.swap(deleteIds);

    mShown = std::move(frame);
    const Clock::time_point rebuilt = Clock::now();
    mStats.decodeSeconds += std::chrono::duration<double>(decoded - start).count();
    mStats.deltaSeconds += std::chrono::duration<double>(compared - decoded).count();
    mStats.rebuildSeconds += std::chrono::duration<double>(rebuilt - compared).count();
    mHasShown = true;
    return true;
  }
} // namespace faf::remote::client
