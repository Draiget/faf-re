#include "remote/FrameBuilder.h"

#include <array>

#include "moho/entity/REntityBlueprint.h"
#include "moho/sim/SimDriver.h"
#include "moho/unit/core/Unit.h"

// Engine addition, server mode: see FrameBuilder.h. Reads the packet only.

namespace faf::remote
{
  namespace
  {
    void ApplyVariableData(
      wire::SEntityRecord& record, const moho::SSTIEntityVariableData& data, const wire::SFrameCodec& codec
    )
    {
      const auto& pos = data.mCurTransform.pos_;
      const auto& orient = data.mCurTransform.orient_;
      record.position = {codec.position.x.Encode(pos.x), codec.position.y.Encode(pos.y), codec.position.z.Encode(pos.z)};
      const std::array<float, 4> quaternion{orient.x, orient.y, orient.z, orient.w};
      record.yawOnly = wire::IsYawOnly(quaternion);
      record.orientation = record.yawOnly ? wire::QuantizeYaw(quaternion) : wire::PackQuaternion(quaternion);
      record.health = data.mHealth;
      record.maxHealth = data.mMaxHealth;
      record.fractionComplete = data.mFractionComplete;
      record.flags = static_cast<std::uint16_t>(PackEntityFlags(data) | (record.flags & kEntityFlagOrphaned));
    }

    [[nodiscard]] std::uint16_t SiloCount(const std::int32_t count) noexcept
    {
      return static_cast<std::uint16_t>(count < 0 ? 0 : (count > 0xFFFF ? 0xFFFF : count));
    }

    void ApplyUnitData(wire::SUnitFields& unit, const moho::SSTIUnitVariableData& data)
    {
      unit.fuelRatio = data.mFuelRatio;
      unit.shieldRatio = data.mShieldRatio;
      unit.workProgress = data.mWorkProgress;
      unit.unitStates = data.mUnitStates;
      unit.scriptBits = data.mScriptbits;
      unit.siloCounts = {
        SiloCount(data.mTacticalSiloBuildCount), SiloCount(data.mNukeSiloBuildCount),
        SiloCount(data.mTacticalSiloStorageCount), SiloCount(data.mNukeSiloStorageCount)
      };
      unit.unitFlags = static_cast<std::uint8_t>(
        (data.mIsPaused ? 1u : 0u) | (data.mAutoMode ? 2u : 0u) | (data.mAutoSurfaceMode ? 4u : 0u)
        | (data.mIsBusy ? 8u : 0u) | (data.mRepeatQueue ? 16u : 0u) | (data.mIsValidTarget ? 32u : 0u)
        | (data.mOverchargePaused ? 64u : 0u)
      );
    }
  } // namespace

  std::uint16_t PackEntityFlags(const moho::SSTIEntityVariableData& data) noexcept
  {
    std::uint32_t flags = 0;
    flags |= data.mIsBeingBuilt != 0u ? 1u : 0u;
    flags |= data.mIsDead != 0u ? 2u : 0u;
    flags |= (static_cast<std::uint32_t>(data.mVisibilityMode) & 7u) << 2;
    flags |= (static_cast<std::uint32_t>(data.mLayerMask) & 0x7Fu) << 5;
    return static_cast<std::uint16_t>(flags);
  }

  void UnpackEntityFlags(const std::uint16_t flags, moho::SSTIEntityVariableData& data) noexcept
  {
    data.mIsBeingBuilt = (flags & 1u) != 0u ? 1u : 0u;
    data.mIsDead = (flags & 2u) != 0u ? 1u : 0u;
    data.mVisibilityMode = static_cast<moho::EUserEntityVisibilityMode>((flags >> 2) & 7u);
    data.mLayerMask = static_cast<moho::ELayer>((flags >> 5) & 0x7Fu);
  }

  void UnpackUnitFields(const wire::SUnitFields& unit, moho::SSTIUnitVariableData& data) noexcept
  {
    data.mFuelRatio = unit.fuelRatio;
    data.mShieldRatio = unit.shieldRatio;
    data.mWorkProgress = unit.workProgress;
    data.mUnitStates = unit.unitStates;
    data.mScriptbits = unit.scriptBits;
    data.mTacticalSiloBuildCount = unit.siloCounts[0];
    data.mNukeSiloBuildCount = unit.siloCounts[1];
    data.mTacticalSiloStorageCount = unit.siloCounts[2];
    data.mNukeSiloStorageCount = unit.siloCounts[3];
    data.mIsPaused = (unit.unitFlags & 1u) != 0u;
    data.mAutoMode = (unit.unitFlags & 2u) != 0u;
    data.mAutoSurfaceMode = (unit.unitFlags & 4u) != 0u;
    data.mIsBusy = (unit.unitFlags & 8u) != 0u;
    data.mRepeatQueue = (unit.unitFlags & 16u) != 0u;
    data.mIsValidTarget = (unit.unitFlags & 32u) != 0u;
    data.mOverchargePaused = (unit.unitFlags & 64u) != 0u;
  }

  CViewFrameBuilder::CViewFrameBuilder(
    const wire::SContentTables& tables, const wire::SFrameCodec& codec, const std::uint32_t orphanBeats
  )
    : mTables(tables)
    , mCodec(codec)
    , mOrphanBeats(orphanBeats)
  {}

  void CViewFrameBuilder::Apply(const moho::SSyncData& packet)
  {
    // Orphaned records whose window has passed leave the frame (as a delete would; the
    // client has orphaned their entities already).
    const auto beat = static_cast<std::uint32_t>(packet.mCurBeat);
    for (auto it = mOrphanedAt.begin(); it != mOrphanedAt.end();) {
      if (beat - it->second >= mOrphanBeats) {
        mWorld.erase(it->first);
        it = mOrphanedAt.erase(it);
      } else {
        ++it;
      }
    }

    // `CWldSession::DoBeat`'s order: creations, updates, erases, deletes.
    const auto create = [&](const moho::SCreateEntityParams& params) -> wire::SEntityRecord& {
      wire::SEntityRecord record{};
      record.id = params.mEntityId;
      if (params.mBlueprint != nullptr) {
        record.blueprint = mTables.blueprints.Ordinal(params.mBlueprint->mBlueprintId.c_str());
        if (record.blueprint == wire::COrdinalTable::kNone) {
          ++mUnknownBlueprints;
        }
      }
      mOrphanedAt.erase(record.id); // an id the sim reuses is a new entity
      return mWorld[record.id] = record;
    };
    for (const moho::SCreateEntityParams& params : packet.mNewEntities) {
      (void)create(params);
    }
    for (const moho::SCreateUnitParams& params : packet.mNewUnits) {
      create(params).isUnit = true;
    }
    for (const moho::SEntityVariableUpdateEntry& update : packet.mEntityUpdates) {
      const auto it = mWorld.find(static_cast<std::uint32_t>(update.mEntityId));
      if (it != mWorld.end()) {
        ApplyVariableData(it->second, update.mVariableData, mCodec);
      }
    }
    for (const moho::SUnitVariableUpdateEntry& update : packet.mUnitUpdates) {
      const auto it = mWorld.find(static_cast<std::uint32_t>(update.mEntityId));
      if (it != mWorld.end() && it->second.isUnit) {
        ApplyUnitData(it->second.unit, update.mVariableData);
      }
    }
    for (const moho::EntId id : packet.mEraseIds) {
      const auto it = mWorld.find(static_cast<std::uint32_t>(id));
      if (it != mWorld.end()) {
        it->second.flags |= kEntityFlagOrphaned;
        mOrphanedAt.emplace(it->first, beat);
      }
    }
    for (const moho::EntId id : packet.mDeleteIds) {
      mWorld.erase(static_cast<std::uint32_t>(id));
      mOrphanedAt.erase(static_cast<std::uint32_t>(id));
    }
  }

  wire::SViewFrame CViewFrameBuilder::Build(const std::uint32_t beat)
  {
    wire::SViewFrame frame{};
    frame.frameId = mNextFrameId++;
    frame.beat = beat;
    frame.entities.reserve(mWorld.size());
    for (const auto& [id, record] : mWorld) {
      frame.entities.push_back(record);
    }
    return frame;
  }

  void CDeadReckoner::Apply(wire::SViewFrame& frame, const wire::SFrameCodec& codec)
  {
    std::map<std::uint32_t, SSent> next;
    for (wire::SEntityRecord& record : frame.entities) {
      const wire::QuantizedPosition actual = record.position;
      if (const auto found = mSent.find(record.id); found == mSent.end()) {
        record.anchorBeat = frame.beat; // anchored where it is created, at rest
      } else {
        wire::SEntityRecord anchored = found->second.record;
        if (wire::ApplyDeadReckoning(anchored, actual, found->second.actual, frame.beat, mTolerance, codec)) {
          ++mReanchors;
        }
        record.position = anchored.position;
        record.velocity = anchored.velocity;
        record.anchorBeat = anchored.anchorBeat;
      }
      next.emplace(record.id, SSent{record, actual});
    }
    mSent = std::move(next);
  }
} // namespace faf::remote
