#include "remote/FrameBuilder.h"

#include <algorithm>
#include <array>
#include <cmath>

#include "moho/audio/CSndParams.h"
#include "moho/audio/CSndVar.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/misc/StatItem.h"
#include "moho/unit/core/UnitAttributes.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/misc/Stats.h"
#include "moho/resource/CSimResources.h"
#include "moho/sim/STIMap.h"
#include "moho/render/textures/CD3DFileBatchTexture.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/sim/SimDriver.h"
#include "moho/unit/core/Unit.h"

// Engine addition, server mode: see FrameBuilder.h. Reads the packet only.

namespace faf::remote
{
  namespace
  {
    /** A sound's session-table id: its names, as `Sound{...}` / `RPCSound{...}` were given them. */
    [[nodiscard]] std::uint32_t SoundId(const moho::CSndParams* const params, wire::CSessionTableWriters* const session)
    {
      if (params == nullptr || session == nullptr) {
        return wire::COrdinalTable::kNone;
      }
      wire::SSoundEntry entry;
      entry.bank = params->mBank.c_str();
      entry.cue = params->mCue.c_str();
      entry.lodCutoff = params->mLodCutoff != nullptr ? params->mLodCutoff->mName.c_str() : "";
      entry.rpcLoop = params->mRpcLoopVariable != nullptr ? params->mRpcLoopVariable->mName.c_str() : "";
      return session->Sound(entry);
    }

    void ApplyAppearance(
      wire::SAppearance& look, const moho::SSTIEntityVariableData& data, const wire::SContentTables& tables,
      wire::CSessionTableWriters* const session, std::uint64_t& unknownUnderlays
    )
    {
      look.mesh = data.mMeshBlueprint != nullptr ? tables.meshes.Ordinal(data.mMeshBlueprint->mBlueprintId.c_str())
                                                 : wire::COrdinalTable::kNone;
      look.scale = {data.mScale.x, data.mScale.y, data.mScale.z};
      look.attachParent = data.mAttachmentParentRef;
      look.attachments.clear();
      for (const moho::SSTIEntityAttachInfo& attached : data.mAuxValueVector) {
        if (look.attachments.size() < wire::SAppearance::kMaxAttachments) {
          look.attachments.push_back(static_cast<std::uint32_t>(attached.mAttachedEntityId));
        }
      }
      look.visualFlags = PackVisualFlags(data);
      look.impact = data.mCurImpactValue;
      look.scroll = {data.mScrollBeatStart.x, data.mScrollBeatStart.y, data.mScrollBeatEnd.x, data.mScrollBeatEnd.y};
      const moho::SSTIIntelAttributes& intel = data.mIntelAttributes;
      look.intel = {intel.vision, intel.waterVision, intel.radar, intel.sonar,
                    intel.omni, intel.radarStealth, intel.sonarStealth, intel.cloak};
      look.ambientSound = SoundId(data.mAmbientSound, session);
      look.rumbleSound = SoundId(data.mRumbleSound, session);
      // The underlay is a file texture (`Entity::SetStrategicUnderlay` loads it by path, no border).
      look.underlay = wire::COrdinalTable::kNone;
      if (data.mUnderlayTexture) {
        const auto* const file = dynamic_cast<const moho::CD3DFileBatchTexture*>(data.mUnderlayTexture.get());
        if (file != nullptr && file->mBorder == 0u && session != nullptr) {
          look.underlay = session->Name(file->GetFilename().c_str());
        } else {
          ++unknownUnderlays;
        }
      }
    }

    void ApplyVariableData(
      wire::SEntityRecord& record, const moho::SSTIEntityVariableData& data, const wire::SFrameCodec& codec,
      const wire::SContentTables& tables, wire::CSessionTableWriters* const session, std::uint64_t& unknownUnderlays
    )
    {
      ApplyAppearance(record.appearance, data, tables, session, unknownUnderlays);
      const auto& pos = data.mCurTransform.pos_;
      const auto& orient = data.mCurTransform.orient_;
      record.position = {codec.position.x.Encode(pos.x), codec.position.y.Encode(pos.y), codec.position.z.Encode(pos.z)};
      // Outside the quantiser's range (or not a number): exact floats instead.
      const auto off = [](const wire::SAxisQuantizer& axis, const std::uint32_t q, const float value) {
        return !(std::fabs(axis.Decode(q) - value) <= axis.step);
      };
      record.farPosition = off(codec.position.x, record.position[0], pos.x) || off(codec.position.y, record.position[1], pos.y)
                        || off(codec.position.z, record.position[2], pos.z);
      if (record.farPosition) {
        record.farValue = {pos.x, pos.y, pos.z};
        record.position = {};
        record.velocity = {};
        record.anchorBeat = 0;
      } else {
        record.farValue = {};
      }
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

    void ReadCategories(wire::SCategoryBits& bits, const moho::EntityCategorySet& set)
    {
      bits.firstWord = set.mBits.mFirstWordIndex;
      bits.words.assign(set.mBits.mWords.begin(), set.mBits.mWords.end());
      if (bits.words.size() > wire::SCategoryBits::kMaxWords) {
        bits.words.resize(wire::SCategoryBits::kMaxWords);
      }
    }

    [[nodiscard]] std::uint32_t NameId(const msvc8::string& name, wire::CSessionTableWriters* const session)
    {
      return session != nullptr ? session->Name(name.c_str()) : wire::COrdinalTable::kNone;
    }

    void ApplyUnitDetail(
      wire::SUnitDetail& detail, const moho::SSTIUnitVariableData& data, const std::int32_t reconFlags,
      const wire::SContentTables& tables, wire::CSessionTableWriters* const session
    )
    {
      detail.creator = static_cast<std::uint32_t>(data.mCreator);
      detail.creationTick = data.mCreationTick;
      detail.stunTicks = data.mStunTicks;
      detail.jobType = data.mJobType;
      detail.fireState = data.mFireState;
      detail.siloMaxStorage = {data.mTacticalSiloMaxStorageCount, data.mNukeSiloMaxStorageCount};
      detail.selectionInheritor = static_cast<std::uint32_t>(data.mSelectionInheritorId);
      detail.customName = NameId(data.mCustomName, session);
      detail.focusUnit = static_cast<std::uint32_t>(data.mFocusUnit);
      detail.guardedUnit = static_cast<std::uint32_t>(data.mGuardedUnit);
      detail.targetBlip = static_cast<std::uint32_t>(data.mTargetBlip);
      detail.didRefresh = data.mDidRefresh ? 1u : 0u;
      detail.reconFlags = reconFlags;
      detail.economy = {data.mProduced.ENERGY,       data.mProduced.MASS,       data.mResourcesSpent.ENERGY,
                        data.mResourcesSpent.MASS,   data.mMaintainenceCost.ENERGY, data.mMaintainenceCost.MASS};
      detail.commands.assign(data.mCommands.begin(), data.mCommands.end());
      detail.buildQueue.assign(data.mBuildQueue.begin(), data.mBuildQueue.end());
      if (detail.commands.size() > wire::SUnitDetail::kMaxQueue) {
        detail.commands.resize(wire::SUnitDetail::kMaxQueue);
      }
      if (detail.buildQueue.size() > wire::SUnitDetail::kMaxQueue) {
        detail.buildQueue.resize(wire::SUnitDetail::kMaxQueue);
      }
      detail.weapons.clear();
      for (const moho::UnitWeaponInfo& info : data.mWeaponInfo) {
        if (detail.weapons.size() == wire::SUnitDetail::kMaxWeapons) {
          break;
        }
        wire::SUnitWeapon weapon;
        ReadCategories(weapon.targets, info.mCat1);
        ReadCategories(weapon.secondary, info.mCat2);
        weapon.layer = static_cast<std::uint32_t>(info.mLayer);
        weapon.minRadius = info.mMinRadius;
        weapon.maxRadius = info.mMaxRadius;
        weapon.effectiveRadius = info.mEffectiveRadius;
        weapon.minRangeVisual = NameId(info.mUIMinRangeVisualId, session);
        weapon.maxRangeVisual = NameId(info.mUIMaxRangeVisualId, session);
        detail.weapons.push_back(std::move(weapon));
      }
      const moho::UnitAttributes& source = data.mAttributes;
      wire::SUnitAttributes& attributes = detail.attributes;
      attributes.blueprint = source.blueprint != nullptr ? tables.blueprints.Ordinal(source.blueprint->mBlueprintId.c_str())
                                                         : wire::COrdinalTable::kNone;
      attributes.reserved04 = source.unknown_0004;
      ReadCategories(attributes.restriction, source.restrictionCategory);
      attributes.scalars = {source.spawnElevationOffset, source.moveSpeedMult, source.accelerationMult, source.turnMult,
                            source.breakOffTriggerMult, source.breakOffDistanceMult, source.consumptionPerSecondEnergy,
                            source.consumptionPerSecondMass, source.productionPerSecondEnergy,
                            source.productionPerSecondMass, source.buildRate, source.regenRate};
      attributes.commandCaps = source.commandCapsMask;
      attributes.toggleCaps = source.toggleCapsMask;
      attributes.flags = {static_cast<std::uint8_t>(source.mReclaimable ? 1u : 0u),
                          static_cast<std::uint8_t>(source.mCapturable ? 1u : 0u), source.unknown_006A,
                          source.unknown_006B};
      attributes.reserved6C = source.unknown_006C;
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

  std::uint8_t PackVisualFlags(const moho::SSTIEntityVariableData& data) noexcept
  {
    return static_cast<std::uint8_t>(
      (data.mVisibilityHidden != 0u ? 1u : 0u) | (data.mUsingAltFootprint != 0u ? 2u : 0u)
      | (data.mUsingAltFootprintSecondary != 0u ? 4u : 0u) | (data.mDestroyedByKill != 0u ? 8u : 0u)
      | (data.mRequestRefreshUI != 0u ? 16u : 0u)
    );
  }

  void UnpackAppearance(const wire::SAppearance& look, moho::SSTIEntityVariableData& data)
  {
    data.mScale = Wm3::Vec3f(look.scale[0], look.scale[1], look.scale[2]);
    data.mAttachmentParentRef = look.attachParent;
    data.mAuxValueVector.clear();
    for (const std::uint32_t id : look.attachments) {
      moho::SSTIEntityAttachInfo attached{};
      attached.mAttachedEntityId = static_cast<std::int32_t>(id);
      data.mAuxValueVector.push_back(attached);
    }
    data.mVisibilityHidden = (look.visualFlags & 1u) != 0u ? 1u : 0u;
    data.mUsingAltFootprint = (look.visualFlags & 2u) != 0u ? 1u : 0u;
    data.mUsingAltFootprintSecondary = (look.visualFlags & 4u) != 0u ? 1u : 0u;
    data.mDestroyedByKill = (look.visualFlags & 8u) != 0u ? 1u : 0u;
    data.mRequestRefreshUI = (look.visualFlags & 16u) != 0u ? 1u : 0u;
    data.mCurImpactValue = look.impact;
    data.mScrollBeatStart = Wm3::Vector2f(look.scroll[0], look.scroll[1]);
    data.mScrollBeatEnd = Wm3::Vector2f(look.scroll[2], look.scroll[3]);
    moho::SSTIIntelAttributes& intel = data.mIntelAttributes;
    intel.vision = look.intel[0];
    intel.waterVision = look.intel[1];
    intel.radar = look.intel[2];
    intel.sonar = look.intel[3];
    intel.omni = look.intel[4];
    intel.radarStealth = look.intel[5];
    intel.sonarStealth = look.intel[6];
    intel.cloak = look.intel[7];
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

  void ReadUnitStats(
    moho::Stats<moho::StatItem>& stats, wire::CSessionTableWriters& session, std::vector<wire::SUnitStat>& out
  )
  {
    out.clear();
    moho::STAT_VisitItems(stats, [&](const msvc8::string& path, moho::StatItem& item) {
      wire::SUnitStat stat{};
      stat.name = session.Name(path.c_str());
      stat.type = static_cast<std::uint8_t>(static_cast<std::uint32_t>(item.mType) & 3u);
      stat.realtime = item.mUseRealtimeSlot == 1;
      if (stat.type == wire::SUnitStat::kString) {
        msvc8::string value;
        (void)item.GetString(stat.realtime, &value);
        stat.text = session.Name(value.c_str());
      } else {
        stat.bits = static_cast<std::uint32_t>(stat.realtime ? item.mRealtimeValueBits : item.mPrimaryValueBits);
      }
      if (out.size() < wire::SUnitFields::kMaxStats) {
        out.push_back(stat);
      }
    });
    std::sort(out.begin(), out.end(), [](const wire::SUnitStat& a, const wire::SUnitStat& b) { return a.name < b.name; });
  }

  void CViewFrameBuilder::Apply(const moho::SSyncData& packet)
  {
    // Resource deposits the sim added since the last beat go on the session record (the sim
    // only ever appends them).
    if (mSession != nullptr && packet.mSimResources.px != nullptr) {
      moho::CSimResources& resources = *packet.mSimResources.px;
      boost::mutex::scoped_lock lock(resources.lock_);
      for (std::size_t i = mSession->DepositCount(); i < resources.deposits_.size(); ++i) {
        const moho::ResourceDeposit& source = resources.deposits_[i];
        const wire::SDeposit deposit{
          static_cast<std::uint8_t>(source.depositType), source.footprintRect.x0, source.footprintRect.z0,
          source.footprintRect.x1, source.footprintRect.z1
        };
        if (!mSession->Deposit(deposit)) {
          ++mDepositOverflows;
          break;
        }
      }
    }
    // Terrain edits: each changed rectangle with the heights the sim's field now holds there.
    if (mSession != nullptr) {
      const moho::CHeightField* const field = packet.mTerrainUpdate.px;
      for (const gpg::Rect2i& rect : packet.mPlayableRectUpdates) {
        wire::STerrainEdit edit{};
        edit.dirty = {rect.x0, rect.z0, rect.x1, rect.z1};
        edit.cells = {0, 0, -1, -1};
        if (field != nullptr) {
          const wire::SCellRect clipped{
            std::max(rect.x0, 0), std::max(rect.z0, 0), std::min(rect.x1, field->width - 1),
            std::min(rect.z1, field->height - 1)
          };
          if (clipped.x0 <= clipped.x1 && clipped.z0 <= clipped.z1) {
            edit.cells = clipped;
            edit.heights.reserve(
              static_cast<std::size_t>(clipped.x1 - clipped.x0 + 1) * static_cast<std::size_t>(clipped.z1 - clipped.z0 + 1)
            );
            for (std::int32_t z = clipped.z0; z <= clipped.z1; ++z) {
              const std::uint16_t* const row = field->data + static_cast<std::ptrdiff_t>(z) * field->width;
              edit.heights.insert(edit.heights.end(), row + clipped.x0, row + clipped.x1 + 1);
            }
          }
        }
        if (!mSession->TerrainEdit(std::move(edit))) {
          ++mTerrainEditOverflows;
        }
      }
    }

    // Orphaned records whose window has passed leave the frame (as a delete would; the
    // client has orphaned their entities already).
    const auto beat = static_cast<std::uint32_t>(packet.mCurBeat);
    for (auto it = mOrphanedAt.begin(); it != mOrphanedAt.end();) {
      if (beat - it->second >= mOrphanBeats) {
        mWorld.erase(it->first);
        mUnitStats.erase(it->first);
        it = mOrphanedAt.erase(it);
      } else {
        ++it;
      }
    }

    // `CWldSession::DoBeat`'s order: creations, updates, erases, deletes.
    const auto create = [&](const moho::SCreateEntityParams& params) -> wire::SEntityRecord& {
      wire::SEntityRecord record{};
      record.id = params.mEntityId;
      record.tickCreated = params.mTickCreated;
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
      wire::SEntityRecord& record = create(params);
      record.isUnit = true;
      record.unit.buildStateTag = params.mConstDat.mBuildStateTag;
      record.unit.fake = params.mConstDat.mFake;
      if (params.mConstDat.mStatsRoot) {
        mUnitStats[record.id] = params.mConstDat.mStatsRoot;
      } else {
        mUnitStats.erase(record.id);
      }
    }
    for (const moho::SEntityVariableUpdateEntry& update : packet.mEntityUpdates) {
      const auto it = mWorld.find(static_cast<std::uint32_t>(update.mEntityId));
      if (it != mWorld.end()) {
        ApplyVariableData(it->second, update.mVariableData, mCodec, mTables, mSession, mUnknownUnderlays);
      }
    }
    for (const moho::SUnitVariableUpdateEntry& update : packet.mUnitUpdates) {
      const auto it = mWorld.find(static_cast<std::uint32_t>(update.mEntityId));
      if (it != mWorld.end() && it->second.isUnit) {
        ApplyUnitData(it->second.unit, update.mVariableData);
        // Built aside and kept shared with the frames before unless it changed.
        ApplyUnitDetail(mDetailScratch, update.mVariableData, update.mReconFlags, mTables, mSession);
        it->second.unit.detail.Assign(mDetailScratch);
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
      mUnitStats.erase(static_cast<std::uint32_t>(id));
      mOrphanedAt.erase(static_cast<std::uint32_t>(id));
    }
  }

  wire::SViewFrame CViewFrameBuilder::Build(const std::uint32_t beat)
  {
    wire::SViewFrame frame{};
    frame.frameId = mNextFrameId++;
    frame.beat = beat;
    // Unit stats are live in the sim (the lockstep UI reads them from the sim's own tree), so
    // every unit's tree is read again for each frame.
    if (mSession != nullptr) {
      for (const auto& [id, stats] : mUnitStats) {
        if (const auto it = mWorld.find(id); it != mWorld.end()) {
          ReadUnitStats(*stats, *mSession, mStatsScratch);
          it->second.unit.stats.Assign(mStatsScratch);
        }
      }
    }
    frame.entities.reserve(mWorld.size());
    for (const auto& [id, record] : mWorld) {
      frame.entities.push_back(record);
    }
    return frame;
  }

  void CDeadReckoner::Apply(wire::SViewFrame& frame, const wire::SFrameCodec& codec)
  {
    // Both are in id order: records the frame no longer has (or has far away) are dropped.
    auto sent = mSent.begin();
    for (wire::SEntityRecord& record : frame.entities) {
      while (sent != mSent.end() && sent->first < record.id) {
        sent = mSent.erase(sent);
      }
      const bool held = sent != mSent.end() && sent->first == record.id;
      if (record.farPosition) {
        // Exact floats, never reckoned; the view re-anchors when it comes back in range.
        if (held) {
          sent = mSent.erase(sent);
        }
        continue;
      }
      const wire::QuantizedPosition actual = record.position;
      if (!held) {
        // Anchored where it is created, at rest.
        record.velocity = {};
        record.verticalAcceleration = 0;
        record.anchorBeat = frame.beat;
        SSent fresh{};
        fresh.anchor.position = actual;
        fresh.anchor.anchorBeat = frame.beat;
        fresh.history[0] = actual;
        fresh.historyCount = 1;
        fresh.lastBeat = frame.beat;
        if (codec.orientationReckoning) {
          record.yawRate = 0;
          record.orientationBeat = record.yawOnly ? frame.beat : 0u;
          fresh.anchor.orientation = record.orientation;
          fresh.anchor.yawOnly = record.yawOnly;
          fresh.anchor.orientationBeat = record.orientationBeat;
          if (record.yawOnly) {
            fresh.yawHistory[0] = record.orientation;
            fresh.yawCount = 1;
          }
        }
        sent = std::next(mSent.emplace_hint(sent, record.id, fresh));
        continue;
      }
      SSent& entry = sent->second;
      if (frame.beat != entry.lastBeat + 1u) {
        entry.historyCount = 0; // positions and yaws on consecutive beats only
        entry.yawCount = 0;
      }
      if (entry.historyCount == entry.history.size()) {
        std::move(entry.history.begin() + 1, entry.history.end(), entry.history.begin());
        --entry.historyCount;
      }
      entry.history[entry.historyCount++] = actual;
      entry.lastBeat = frame.beat;
      if (wire::ApplyDeadReckoning(
            entry.anchor, std::span<const wire::QuantizedPosition>(entry.history.data(), entry.historyCount),
            frame.beat, mScheme, codec
          )) {
        ++mReanchors;
      }
      record.position = entry.anchor.position;
      record.velocity = entry.anchor.velocity;
      record.verticalAcceleration = entry.anchor.verticalAcceleration;
      record.anchorBeat = entry.anchor.anchorBeat;
      if (codec.orientationReckoning) {
        if (!record.yawOnly) {
          entry.yawCount = 0;
        } else {
          if (entry.yawCount == entry.yawHistory.size()) {
            std::move(entry.yawHistory.begin() + 1, entry.yawHistory.end(), entry.yawHistory.begin());
            --entry.yawCount;
          }
          entry.yawHistory[entry.yawCount++] = record.orientation;
        }
        if (wire::ApplyOrientationReckoning(
              entry.anchor, record, std::span<const std::uint32_t>(entry.yawHistory.data(), entry.yawCount),
              frame.beat, mScheme, codec
            )) {
          ++mOrientationReanchors;
        }
        record.orientation = entry.anchor.orientation;
        record.yawOnly = entry.anchor.yawOnly;
        record.yawRate = entry.anchor.yawRate;
        record.orientationBeat = entry.anchor.orientationBeat;
      }
      ++sent;
    }
    mSent.erase(sent, mSent.end());
  }
} // namespace faf::remote
