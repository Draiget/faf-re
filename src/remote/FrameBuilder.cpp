#include "remote/FrameBuilder.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>

#include "moho/audio/CSndParams.h"
#include "moho/audio/CSndVar.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityId.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/sim/ReconBlip.h"
#include "moho/misc/StatItem.h"
#include "moho/unit/core/UnitAttributes.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/misc/Stats.h"
#include "moho/resource/CSimResources.h"
#include "moho/sim/STIMap.h"
#include "remote/UnderlayPaths.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/SimWorkerPool.h"
#include "remote/BeatChangeSet.h"
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
      wire::SAppearance& look, const std::uint32_t entityId, const moho::SSTIEntityVariableData& data,
      const wire::SContentTables& tables, wire::CSessionTableWriters* const session, const CUnderlayPathReader& underlays,
      std::uint64_t& unknownUnderlays
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
      // The underlay by the path `Entity::SetStrategicUnderlay` recorded: a server without a
      // client has no texture to read it from.
      look.underlay = wire::COrdinalTable::kNone;
      if (const std::string* const path = underlays.Find(entityId); path != nullptr && session != nullptr) {
        look.underlay = session->Name(path->c_str());
      } else if (data.mUnderlayTexture) {
        ++unknownUnderlays; // a texture whose path was not recorded
      }
    }

    constexpr std::int32_t kUnitReconFlags = 28; // `Unit::SyncInterface`, 0x006AC4DC..0x006AC500

    /**
     * What `SSTIEntityVariableData::operator=` copies, less what the builder does not read: the
     * mesh resource and the attached entities (`WriteEntityBlockForView` writes those). Sim
     * objects are shared by every view on every worker, so their reference counts stay untouched,
     * except for an underlay, which hardly any entity has.
     */
    void CopyEntityBlockReadByBuilder(moho::SSTIEntityVariableData& to, const moho::SSTIEntityVariableData& from)
    {
      to.mMeshBlueprint = from.mMeshBlueprint;
      to.mScale = from.mScale;
      to.mHealth = from.mHealth;
      to.mMaxHealth = from.mMaxHealth;
      to.mIsBeingBuilt = from.mIsBeingBuilt;
      to.mIsDead = from.mIsDead;
      to.mCurTransform = from.mCurTransform;
      to.mLastTransform = from.mLastTransform;
      to.mCurImpactValue = from.mCurImpactValue;
      to.mFractionComplete = from.mFractionComplete;
      to.mScrollBeatStart = from.mScrollBeatStart;
      to.mScrollBeatEnd = from.mScrollBeatEnd;
      to.mAmbientSound = from.mAmbientSound;
      to.mRumbleSound = from.mRumbleSound;
      to.mLayerMask = from.mLayerMask;
      to.mUsingAltFootprint = from.mUsingAltFootprint;
      to.mUsingAltFootprintSecondary = from.mUsingAltFootprintSecondary;
      if (from.mUnderlayTexture || to.mUnderlayTexture) {
        to.mUnderlayTexture = from.mUnderlayTexture;
      }
      to.mIntelAttributes = from.mIntelAttributes;
    }

    void ApplyVariableData(
      wire::SEntityRecord& record, const moho::SSTIEntityVariableData& data, const wire::SFrameCodec& codec,
      const wire::SContentTables& tables, wire::CSessionTableWriters* const session, const CUnderlayPathReader& underlays,
      std::uint64_t& unknownUnderlays
    )
    {
      ApplyAppearance(record.appearance, record.id, data, tables, session, underlays, unknownUnderlays);
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

    /** 0x005BF168..0x005BF1C4: the entity block from the view's recon record. */
    void WriteReconBlock(
      moho::SSTIEntityVariableData& block, const moho::SPerArmyReconInfo& recon, const std::uint32_t vision, const bool hasVision
    )
    {
      if (hasVision) {
        block.mIntelAttributes.SetIntelRadius(moho::ENTATTR_Vision, static_cast<int>(vision));
      }
      block.mMeshBlueprint = recon.mStiMesh;
      block.mHealth = recon.mHealth;
      block.mMaxHealth = recon.mMaxHealth;
      block.mFractionComplete = recon.mFractionComplete;
      block.mIsDead = recon.mMaybeDead;
    }

    /** What `ApplyVariableData` and `ApplyUnitData` write, from a record they wrote (`wire::HashBlipUpdate` covers the same). */
    void CopyBlipRecord(wire::SEntityRecord& record, const wire::SEntityRecord& from)
    {
      record.appearance = from.appearance;
      record.position = from.position;
      record.farPosition = from.farPosition;
      record.farValue = from.farValue;
      if (from.farPosition) {
        record.velocity = {};
        record.anchorBeat = 0;
      }
      record.yawOnly = from.yawOnly;
      record.orientation = from.orientation;
      record.health = from.health;
      record.maxHealth = from.maxHealth;
      record.fractionComplete = from.fractionComplete;
      record.flags = static_cast<std::uint16_t>(from.flags | (record.flags & kEntityFlagOrphaned));
      if (record.isUnit) {
        wire::SUnitFields& unit = record.unit;
        const wire::SUnitFields& fields = from.unit;
        unit.fuelRatio = fields.fuelRatio;
        unit.shieldRatio = fields.shieldRatio;
        unit.workProgress = fields.workProgress;
        unit.unitStates = fields.unitStates;
        unit.scriptBits = fields.scriptBits;
        unit.siloCounts = fields.siloCounts;
        unit.unitFlags = fields.unitFlags;
      }
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

  void CViewFrameBuilder::DropStats(const std::uint32_t id)
  {
    if (const auto found = mUnitStats.find(id); found != mUnitStats.end()) {
      mDroppedStats.push_back(std::move(found->second));
      mUnitStats.erase(found);
    }
  }

  void CViewFrameBuilder::ReleaseDropped()
  {
    mDroppedStats.clear();
  }

  CSharedEntityRecords::CSharedEntityRecords(const wire::SContentTables& tables, const wire::SFrameCodec& codec)
    : mTables(tables)
    , mCodec(codec)
  {}

  CSharedEntityRecords::~CSharedEntityRecords() = default;

  bool CSharedEntityRecords::Shareable(const moho::Entity& entity) noexcept
  {
    const moho::SSTIEntityVariableData& data = entity.mVarDat;
    return data.mAmbientSound == nullptr && data.mRumbleSound == nullptr && !data.mUnderlayTexture;
  }

  void CSharedEntityRecords::BeginBeat(const std::size_t changedCount)
  {
    mFree.insert(mFree.end(), mReplaced.begin(), mReplaced.end());
    mReplaced.clear();
    if (changedCount > mUpdateCapacity) {
      mUpdates = std::make_unique<SSharedUpdate[]>(changedCount * 2u);
      mUpdateCapacity = changedCount * 2u;
    } else {
      for (std::size_t i = 0; i < mUpdateCount; ++i) {
        mUpdates[i].modes.store(0u, std::memory_order_relaxed);
      }
    }
    mUpdateCount = changedCount;
  }

  void CSharedEntityRecords::Build(const std::vector<SChangedEntity>& changed, const bool parallel)
  {
    // Which records go where is decided here; filling them touches only each entity's own.
    for (std::size_t i = 0; i < changed.size(); ++i) {
      SSharedUpdate& update = mUpdates[i];
      const auto modes = update.modes.load(std::memory_order_relaxed);
      const moho::Entity& entity = *changed[i].entity;
      const auto id = static_cast<std::uint32_t>(entity.id_);
      SEntry* entry = mEntries.Find(id);
      if (entry != nullptr) {
        for (std::uint32_t& record : entry->records) {
          if (record != kNoRecord) {
            mReplaced.push_back(record);
            record = kNoRecord;
          }
        }
      }
      if (modes == 0u) {
        if (entry != nullptr) {
          mEntries.Erase(id);
        }
        continue;
      }
      if (entry == nullptr) {
        entry = &mEntries.Insert(id, SEntry{});
      }
      const auto tickCreated = static_cast<std::uint32_t>(entity.mTickCreated);
      if (entry->entity != &entity || entry->tickCreated != tickCreated) {
        entry->entity = &entity;
        entry->tickCreated = tickCreated;
        entry->blueprint = entity.BluePrint != nullptr ? mTables.blueprints.Ordinal(entity.BluePrint->mBlueprintId.c_str())
                                                       : wire::COrdinalTable::kNone;
      }
      for (std::size_t mode = 0; mode < SSharedUpdate::kModes; ++mode) {
        if ((modes & (1u << mode)) == 0u) {
          continue;
        }
        std::uint32_t index;
        if (!mFree.empty()) {
          index = mFree.back();
          mFree.pop_back();
        } else {
          index = static_cast<std::uint32_t>(mRecords.size());
          mRecords.grow_to(mRecords.size() + 1u);
        }
        entry->records[mode] = index;
        wire::SEntityRecord& record = mRecords[index];
        update.records[mode] = &record;
        record.id = id;
        record.tickCreated = entry->tickCreated;
        record.blueprint = entry->blueprint;
      }
    }

    const auto fill = [&](const std::size_t begin, const std::size_t end) {
      moho::SSTIEntityVariableData block;
      std::uint64_t unknownUnderlays = 0; // none: `Shareable`
      for (std::size_t i = begin; i < end; ++i) {
        const auto modes = mUpdates[i].modes.load(std::memory_order_relaxed);
        if (modes == 0u) {
          continue;
        }
        moho::Entity& entity = *changed[i].entity;
        CopyEntityBlockReadByBuilder(block, entity.mVarDat);
        for (std::size_t mode = 0; mode < SSharedUpdate::kModes; ++mode) {
          if ((modes & (1u << mode)) != 0u) {
            WriteEntityBlockForView(
              block, entity, static_cast<moho::EUserEntityVisibilityMode>(1 << mode), changed[i].requestRefreshUI
            );
            ApplyVariableData(
              *mUpdates[i].records[mode], block, mCodec, mTables, nullptr, mNoUnderlays, unknownUnderlays
            );
          }
        }
      }
    };
    if (parallel) {
      moho::CSimWorkerPool::Get().ParallelFor(changed.size(), 256u, fill);
    } else {
      fill(0u, changed.size());
    }
  }

  void CSharedEntityRecords::ReserveBlipRecords(const std::size_t count)
  {
    if (count > mBlipRecords.size()) {
      mBlipRecords.grow_to(count);
    }
  }

  void CSharedEntityRecords::FillBlipRecord(
    SBlipRecord& out, moho::SSTIEntityVariableData& block, moho::ReconBlip& blip, const bool requestRefreshUI, const std::size_t army,
    const moho::EUserEntityVisibilityMode mode, const std::uint32_t vision, const bool hasVision
  ) const
  {
    moho::Entity& entity = blip;
    CopyEntityBlockReadByBuilder(block, entity.mVarDat);
    WriteEntityBlockForView(block, entity, mode, requestRefreshUI);
    const moho::SPerArmyReconInfo& recon = blip.mReconDat[army];
    WriteReconBlock(block, recon, vision, hasVision);
    out.record.id = static_cast<std::uint32_t>(entity.id_);
    std::uint64_t unknownUnderlays = 0; // none: `Shareable`
    ApplyVariableData(out.record, block, mCodec, mTables, nullptr, mNoUnderlays, unknownUnderlays);
    ApplyUnitData(out.record.unit, blip.mUnitVarDat);
    ApplyUnitDetail(out.detail, blip.mUnitVarDat, static_cast<std::int32_t>(recon.mReconFlags), mTables, nullptr);
    if (const moho::Unit* const creator = blip.mCreator.GetObjectPtr(); creator != nullptr) {
      out.detail.stunTicks = creator->mUnitVarDat.mStunTicks != 0 ? 1 : 0;
    }
    out.hash = wire::HashBlipUpdate(out.record, out.detail);
  }

  void CViewFrameBuilder::ClearBefore() noexcept
  {
    for (const std::uint32_t slot : mBeforeSlots) {
      mBeforeRecords[slot] = nullptr;
    }
    mBeforeSlots.clear();
    mBefore.clear();
  }

  void CViewFrameBuilder::SaveBefore(const std::uint32_t slot)
  {
    if (slot < mWatched.size() && mWatched[slot] != 0u && mBeforeRecords[slot] == nullptr) {
      const wire::SEntityRecord* record = mWorldSlots[slot];
      if (mLocalSlots[slot] != kNoLocal) {
        record = &mBefore.push_back(*record);
      }
      mBeforeRecords[slot] = record;
      mBeforeSlots.push_back(slot);
    }
  }

  wire::SEntityRecord& CViewFrameBuilder::LocalRecord(const std::uint32_t slot)
  {
    if (mLocalSlots[slot] != kNoLocal) {
      return mLocalRecords[mLocalSlots[slot]];
    }
    std::uint32_t index;
    if (!mFreeLocal.empty()) {
      index = mFreeLocal.back();
      mFreeLocal.pop_back();
    } else {
      index = static_cast<std::uint32_t>(mLocalRecords.size());
      mLocalRecords.grow_to(mLocalRecords.size() + 1u);
    }
    mLocalSlots[slot] = index;
    wire::SEntityRecord& record = mLocalRecords[index];
    if (mWorldSlots[slot] != nullptr) {
      record = *mWorldSlots[slot];
    }
    mWorldSlots[slot] = &record;
    return record;
  }

  void CViewFrameBuilder::ReleaseLocal(const std::uint32_t slot)
  {
    const std::uint32_t index = mLocalSlots[slot];
    if (index != kNoLocal) {
      mLocalRecords[index] = wire::SEntityRecord{}; // lets go of what the record shares
      mFreeLocal.push_back(index);
      mLocalSlots[slot] = kNoLocal;
    }
  }

  std::uint32_t CViewFrameBuilder::NewSlot(const std::uint32_t id, const std::vector<SWorldEntry>::const_iterator found)
  {
    std::uint32_t slot;
    if (!mFreeSlots.empty()) {
      slot = mFreeSlots.back();
      mFreeSlots.pop_back();
    } else {
      slot = static_cast<std::uint32_t>(mWorldSlots.size());
      (void)mWorldSlots.push_back(nullptr);
      mLocalSlots.push_back(kNoLocal);
    }
    mWorldIndex.insert(found, SWorldEntry{id, slot});
    if (mTrackChanges) {
      mNewRecordIds.push_back(id);
    }
    return slot;
  }

  wire::SEntityRecord* CViewFrameBuilder::FindRecord(const std::uint32_t id)
  {
    const auto found = LowerBound(id);
    if (found == mWorldIndex.end() || found->id != id) {
      return nullptr;
    }
    SaveBefore(found->slot);
    return &LocalRecord(found->slot);
  }

  wire::SEntityRecord& CViewFrameBuilder::PutRecord(const wire::SEntityRecord& record)
  {
    if (mTrackChanges) {
      mTouchedIds.push_back(record.id);
    }
    const auto found = LowerBound(record.id);
    std::uint32_t slot;
    if (found != mWorldIndex.end() && found->id == record.id) {
      slot = found->slot;
      SaveBefore(slot);
    } else {
      slot = NewSlot(record.id, found);
    }
    wire::SEntityRecord& local = LocalRecord(slot);
    local = record;
    return local;
  }

  void CViewFrameBuilder::ApplySharedUpdate(const SDirectUpdate& update, std::size_t& cursor)
  {
    const auto id = static_cast<std::uint32_t>(update.target->entity->id_);
    const wire::SEntityRecord* const record = update.target->shared->records[SSharedUpdate::ModeIndex(update.Mode())];
    cursor = SeekWorld(cursor, id);
    const auto found = mWorldIndex.cbegin() + static_cast<std::ptrdiff_t>(cursor);
    const bool exists = found != mWorldIndex.end() && found->id == id;
    std::uint32_t slot;
    if (update.created) {
      mOrphanedAt.erase(id); // an id the sim reuses is a new entity
      if (record->blueprint == wire::COrdinalTable::kNone && update.target->entity->BluePrint != nullptr) {
        ++mUnknownBlueprints;
      }
      if (exists) {
        slot = found->slot;
        SaveBefore(slot);
      } else {
        slot = NewSlot(id, found);
      }
    } else {
      if (!exists) {
        return;
      }
      slot = found->slot;
      SaveBefore(slot);
    }
    ReleaseLocal(slot);
    mWorldSlots[slot] = record;
    if (mTrackChanges) {
      mTouchedIds.push_back(id);
    }
  }

  void CViewFrameBuilder::EraseRecord(const std::uint32_t id)
  {
    const auto found = LowerBound(id);
    if (found == mWorldIndex.end() || found->id != id) {
      return;
    }
    if (mTrackChanges) {
      mErasedRecords.push_back({id, found->slot});
    }
    UnwatchRecord(found->slot);
    ReleaseLocal(found->slot);
    mWorldSlots[found->slot] = nullptr;
    mFreeSlots.push_back(found->slot);
    mWorldIndex.erase(found);
  }

  void WriteEntityBlockForView(
    moho::SSTIEntityVariableData& data, moho::Entity& entity, const moho::EUserEntityVisibilityMode mode,
    const bool requestRefreshUI
  )
  {
    constexpr std::uint32_t kInvalidEntityId = moho::ToRaw(moho::EEntityIdSentinel::Invalid);

    // The attach parent and children as the function writes them before its copy.
    moho::Entity* const parent = entity.mAttachInfo.GetAttachTargetEntity();
    data.mAttachmentParentRef = parent != nullptr ? parent->id_ : kInvalidEntityId;
    data.mAuxValueVector.resize(
      entity.mAttachedEntities.size(), moho::SSTIEntityAttachInfo{std::bit_cast<std::int32_t>(kInvalidEntityId)}
    );
    for (std::size_t i = 0; i < entity.mAttachedEntities.size(); ++i) {
      moho::Entity* const child = entity.mAttachedEntities[i];
      data.mAuxValueVector[i].mAttachedEntityId = std::bit_cast<std::int32_t>(child != nullptr ? child->id_ : kInvalidEntityId);
    }

    // What `UpdateVisibility` would have left for this focus: published, and its mode.
    data.mVisibilityMode = mode;
    data.mVisibilityHidden = 1u;
    // `Entity::Sync` clears it after the copy (0x0067A10B); the walk's value.
    data.mRequestRefreshUI = requestRefreshUI ? 1u : 0u;
  }

  void CViewFrameBuilder::Apply(const moho::SSyncData& packet, const std::span<const SDirectUpdate> direct)
  {
    mUnderlays.Refresh();

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
      if (field != nullptr && !mSentTerrain) {
        // The heights as the client starts with them (SyncRebuilder.cpp: the first beat's).
        mSentTerrain.reset(new moho::CHeightField(field->width - 1, field->height - 1));
        std::copy_n(field->data, static_cast<std::size_t>(field->width) * static_cast<std::size_t>(field->height), mSentTerrain->data);
      }
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
              std::copy(row + clipped.x0, row + clipped.x1 + 1,
                        mSentTerrain->data + static_cast<std::ptrdiff_t>(z) * mSentTerrain->width + clipped.x0);
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
        EraseRecord(it->first);
        DropStats(it->first);
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
      return PutRecord(record);
    };
    for (const moho::SCreateEntityParams& params : packet.mNewEntities) {
      (void)create(params);
    }
    for (const moho::SCreateUnitParams& params : packet.mNewUnits) {
      wire::SEntityRecord& record = create(params);
      record.isUnit = true;
      record.unit.buildStateTag = params.mConstDat.mBuildStateTag;
      record.unit.fake = params.mConstDat.mFake;
      DropStats(record.id);
      if (params.mConstDat.mStatsRoot) {
        mUnitStats[record.id] = params.mConstDat.mStatsRoot;
      }
    }
    for (const moho::SEntityVariableUpdateEntry& update : packet.mEntityUpdates) {
      if (wire::SEntityRecord* const record = FindRecord(static_cast<std::uint32_t>(update.mEntityId)); record != nullptr) {
        ApplyVariableData(*record, update.mVariableData, mCodec, mTables, mSession, mUnderlays, mUnknownUnderlays);
        if (mTrackChanges) {
          mTouchedIds.push_back(record->id);
        }
      }
    }
    for (const moho::SUnitVariableUpdateEntry& update : packet.mUnitUpdates) {
      wire::SEntityRecord* const record = FindRecord(static_cast<std::uint32_t>(update.mEntityId));
      if (record != nullptr && record->isUnit) {
        ApplyUnitData(record->unit, update.mVariableData);
        // Built aside and kept shared with the frames before unless it changed.
        ApplyUnitDetail(mDetailScratch, update.mVariableData, update.mReconFlags, mTables, mSession);
        (void)record->unit.detail.Assign(mDetailScratch);
        if (mTrackChanges) {
          mTouchedIds.push_back(record->id);
        }
      }
    }
    std::size_t cursor = 0;
    for (const SDirectUpdate& update : direct) {
      const SDirectUpdate::STarget& target = *update.target;
      if (target.shared != nullptr) {
        ApplySharedUpdate(update, cursor);
        continue;
      }
      moho::Entity& entity = *target.entity;
      const auto id = static_cast<std::uint32_t>(entity.id_);
      cursor = SeekWorld(cursor, id);
      if (cursor == mWorldIndex.size() || mWorldIndex[cursor].id != id) {
        continue;
      }
      const std::uint32_t slot = mWorldIndex[cursor].slot;
      const SBlipRecord* const blipRecord = mSession == nullptr ? update.blipRecord : nullptr;
      SaveBefore(slot);
      wire::SEntityRecord* const record = &LocalRecord(slot);
      if (blipRecord != nullptr) {
        CopyBlipRecord(*record, blipRecord->record);
        if (record->isUnit) {
          (void)record->unit.detail.Assign(blipRecord->detail);
        }
        if (mTrackChanges) {
          mTouchedIds.push_back(record->id);
        }
        continue;
      }
      CopyEntityBlockReadByBuilder(mBlockScratch, entity.mVarDat);
      WriteEntityBlockForView(mBlockScratch, entity, update.Mode(), target.requestRefreshUI);
      const moho::SSTIUnitVariableData* unitData = nullptr;
      std::int32_t reconFlags = kUnitReconFlags;
      const moho::Unit* creator = nullptr;
      if (target.unit != nullptr) {
        unitData = &target.unit->VarDat();
      } else if (target.blip != nullptr) {
        const moho::SPerArmyReconInfo& recon = target.blip->mReconDat[update.army];
        creator = target.blip->mCreator.GetObjectPtr();
        unitData = &target.blip->mUnitVarDat;
        reconFlags = static_cast<std::int32_t>(recon.mReconFlags);
        WriteReconBlock(mBlockScratch, recon, update.vision, update.hasVision);
      }
      ApplyVariableData(*record, mBlockScratch, mCodec, mTables, mSession, mUnderlays, mUnknownUnderlays);
      if (unitData != nullptr && record->isUnit) {
        ApplyUnitData(record->unit, *unitData);
        ApplyUnitDetail(mDetailScratch, *unitData, reconFlags, mTables, mSession);
        if (creator != nullptr) {
          mDetailScratch.stunTicks = creator->mUnitVarDat.mStunTicks != 0 ? 1 : 0;
        }
        (void)record->unit.detail.Assign(mDetailScratch);
      }
      if (mTrackChanges) {
        mTouchedIds.push_back(record->id);
      }
    }
    for (const moho::EntId id : packet.mEraseIds) {
      if (wire::SEntityRecord* const record = FindRecord(static_cast<std::uint32_t>(id)); record != nullptr) {
        record->flags |= kEntityFlagOrphaned;
        mOrphanedAt.emplace(record->id, beat);
        if (mTrackChanges) {
          mTouchedIds.push_back(record->id);
        }
      }
    }
    for (const moho::EntId id : packet.mDeleteIds) {
      EraseRecord(static_cast<std::uint32_t>(id));
      DropStats(static_cast<std::uint32_t>(id));
      mOrphanedAt.erase(static_cast<std::uint32_t>(id));
    }
  }

  wire::SViewFrame CViewFrameBuilder::StartFrame(const std::uint32_t beat)
  {
    wire::SViewFrame frame{};
    frame.frameId = mNextFrameId++;
    frame.beat = beat;
    // Unit stats are live in the sim (the lockstep UI reads them from the sim's own tree), so
    // every unit's tree is read again for each frame.
    if (mSession != nullptr) {
      for (const auto& [id, stats] : mUnitStats) {
        if (wire::SEntityRecord* const record = FindRecord(id); record != nullptr) {
          ReadUnitStats(*stats, *mSession, mStatsScratch);
          if (record->unit.stats.Assign(mStatsScratch) && mTrackChanges) {
            mTouchedIds.push_back(id);
          }
        }
      }
    }
    return frame;
  }

  float CHeightFieldGround::HeightAt(const float x, const float z) const noexcept
  {
    return mField != nullptr ? mField->GetElevation(x, z) : 0.0f;
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
      const wire::QuantizedPosition predicted = wire::PredictPosition(entry.anchor, frame.beat, codec);
      const std::uint32_t anchoredAt = entry.anchor.anchorBeat;
      if (wire::ApplyDeadReckoning(
            entry.anchor, std::span<const wire::QuantizedPosition>(entry.history.data(), entry.historyCount),
            frame.beat, mScheme, codec
          )) {
        ++mReanchors;
        mGroundAnchors += entry.anchor.followsGround ? 1u : 0u;
        const auto off = [&](const int axis) {
          const std::int64_t error = static_cast<std::int64_t>(actual[axis]) - static_cast<std::int64_t>(predicted[axis]);
          return error > mScheme.tolerance || -error > mScheme.tolerance;
        };
        const bool horizontal = off(0) || off(2);
        const bool vertical = off(1);
        mCauses.horizontalOnly += horizontal && !vertical ? 1u : 0u;
        mCauses.verticalOnly += vertical && !horizontal ? 1u : 0u;
        mCauses.both += horizontal && vertical ? 1u : 0u;
        mCauses.units += record.isUnit ? 1u : 0u;
        mCauses.stopped += entry.historyCount >= 2u && entry.history[entry.historyCount - 2u] == actual ? 1u : 0u;
        const std::uint32_t age = frame.beat - anchoredAt;
        ++mCauses.afterBeats[age <= 1u ? 0 : (age <= 3u ? 1 : (age <= 9u ? 2 : 3))];
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
