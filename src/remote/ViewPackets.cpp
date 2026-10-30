#include "remote/ViewPackets.h"

#include <bit>

#include "moho/entity/Entity.h"
#include "moho/entity/EntityId.h"
#include "moho/entity/Prop.h"
#include "moho/sim/ReconBlip.h"
#include "moho/sim/SimDriver.h"
#include "moho/unit/core/Unit.h"
#include "remote/VisibilityOracle.h"

// Engine addition, server mode: see ViewPackets.h. Each step names the function it replays.

namespace faf::remote
{
  namespace
  {
    constexpr std::int32_t kUnitReconFlags = 28; // `Unit::SyncInterface`, 0x006AC4DC..0x006AC500

    /** The block `Entity::SyncInterface` (0x0067A290) copies, for one view. */
    [[nodiscard]] moho::SSTIEntityVariableData EntityBlockForView(
      moho::Entity& entity, const SViewVisibility& visibility, const bool requestRefreshUI
    )
    {
      constexpr std::uint32_t kInvalidEntityId = moho::ToRaw(moho::EEntityIdSentinel::Invalid);

      moho::SSTIEntityVariableData data = entity.mVarDat;

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
      data.mVisibilityMode = visibility.mode;
      data.mVisibilityHidden = 1u;
      // `Entity::Sync` clears it after the copy (0x0067A10B); the walk's value.
      data.mRequestRefreshUI = requestRefreshUI ? 1u : 0u;
      return data;
    }
  } // namespace

  CViewPackets::CViewPackets() = default;
  CViewPackets::~CViewPackets() = default;

  void CViewPackets::OnBeatChanges(moho::Sim& sim, const moho::SSyncData& packet)
  {
    (void)packet;
    const std::size_t armyCount = sim.mArmiesList.size();
    while (mPackets.size() < armyCount) {
      mPackets.push_back(std::make_unique<moho::SSyncData>());
      mViews.emplace_back();
    }

    for (std::size_t army = 0; army < armyCount; ++army) {
      moho::SSyncData& out = *mPackets[army];
      out.mNewEntities.clear();
      out.mNewUnits.clear();
      out.mEntityUpdates.clear();
      out.mUnitUpdates.clear();
      out.mDeleteIds.clear();
      out.mEraseIds.clear();
      out.mCurBeat = static_cast<std::int32_t>(sim.mCurBeat);
      out.mCurTick = static_cast<std::int32_t>(sim.mCurTick);
      out.mFocusArmy = static_cast<std::int32_t>(army);
      for (const SChangedEntity& changed : Entities()) {
        SyncForView(sim, static_cast<std::int32_t>(army), changed, out, mViews[army]);
      }
    }
    OnViewPackets(sim);
  }

  void CViewPackets::SyncForView(
    moho::Sim& sim, const std::int32_t army, const SChangedEntity& changed, moho::SSyncData& out,
    std::unordered_map<std::uint32_t, SViewEntity>& view
  )
  {
    moho::Entity& entity = *changed.entity;
    const auto id = static_cast<std::uint32_t>(entity.id_);
    const SViewVisibility visibility = ResolveViewVisibility(sim, army, entity);
    moho::Prop* const prop = entity.IsProp();
    moho::Unit* const unit = prop == nullptr ? entity.IsUnit() : nullptr;
    moho::ReconBlip* const blip = prop == nullptr && unit == nullptr ? entity.IsReconBlip() : nullptr;

    if (!visibility.published) {
      // `Entity::Sync` 0x0067A0EA..0x0067A102 / `Prop::Sync` 0x006FA2B8..0x006FA2F1.
      const auto found = view.find(id);
      if (found != view.end() && found->second.created) {
        if (prop != nullptr && prop->mReclaimTerminated) {
          out.mEraseIds.push_back(entity.id_);
        } else {
          out.mDeleteIds.push_back(entity.id_);
        }
        found->second.created = false;
      }
      if (entity.mOnDestroyDispatched != 0u && found != view.end()) {
        view.erase(found); // a later entity with this id is a new one
      }
      return;
    }

    SViewEntity& state = view[id];
    if (!state.created) {
      if (unit != nullptr || blip != nullptr) {
        // `Unit::CreateInterface` 0x006AC2C0 / `ReconBlip::CreateInterface` 0x005BEE90.
        moho::SCreateUnitParams params{};
        params.mEntityId = entity.id_;
        params.mBlueprint = entity.BluePrint;
        params.mTickCreated = static_cast<std::uint32_t>(entity.mTickCreated);
        if (unit != nullptr) {
          params.mConstDat.mBuildStateTag = unit->mConstDat.mBuildStateTag;
          params.mConstDat.mStatsRoot = unit->mConstDat.mStatsRoot;
          params.mConstDat.mFake = unit->mConstDat.mFake;
        } else {
          params.mConstDat.mBuildStateTag = blip->mUnitConstDat.mBuildStateTag;
          params.mConstDat.mStatsRoot = blip->mUnitConstDat.mStatsRoot;
          params.mConstDat.mFake = blip->mUnitConstDat.mFake;
        }
        out.mNewUnits.push_back(params);
      } else {
        // `Entity::CreateInterface` 0x0067A220.
        moho::SCreateEntityParams params{};
        params.mEntityId = entity.id_;
        params.mBlueprint = entity.BluePrint;
        params.mTickCreated = static_cast<std::uint32_t>(entity.mTickCreated);
        out.mNewEntities.push_back(params);
      }
      state.created = true;
    }

    moho::SSTIEntityVariableData block = EntityBlockForView(entity, visibility, changed.requestRefreshUI);

    if (unit != nullptr) {
      moho::SUnitVariableUpdateEntry& update = out.mUnitUpdates.emplace_back();
      update.mEntityId = entity.id_;
      update.mVariableData = unit->VarDat();
      update.mReconFlags = kUnitReconFlags;
    } else if (blip != nullptr) {
      const moho::SPerArmyReconInfo& recon = blip->mReconDat[static_cast<std::size_t>(army)];
      moho::Unit* const creator = blip->mCreator.GetObjectPtr();
      if (creator != nullptr) {
        // 0x005BF00A..0x005BF027: the creator's vision range, written into the blip itself.
        state.vision = static_cast<moho::Entity*>(creator)->mVarDat.mIntelAttributes.GetRange(moho::ENTATTR_Vision);
        state.hasVision = true;
      }
      if (state.hasVision) {
        block.mIntelAttributes.SetIntelRadius(moho::ENTATTR_Vision, static_cast<int>(state.vision));
      }

      moho::SUnitVariableUpdateEntry& update = out.mUnitUpdates.emplace_back();
      update.mEntityId = entity.id_;
      update.mVariableData = blip->mUnitVarDat;
      update.mVariableData.mSharedPose = recon.mPose;
      update.mVariableData.mPriorSharedPose = recon.mPriorPose;
      if (creator != nullptr) {
        update.mVariableData.mStunTicks = creator->mUnitVarDat.mStunTicks != 0 ? 1 : 0;
      }
      update.mReconFlags = static_cast<std::int32_t>(recon.mReconFlags);

      // 0x005BF168..0x005BF1C4: the entity block from the recon record.
      block.mMeshBlueprint = recon.mStiMesh;
      block.mScmResource = recon.mMesh;
      block.mHealth = recon.mHealth;
      block.mMaxHealth = recon.mMaxHealth;
      block.mFractionComplete = recon.mFractionComplete;
      block.mIsDead = recon.mMaybeDead;
    }

    moho::SEntityVariableUpdateEntry& update = out.mEntityUpdates.emplace_back();
    update.mEntityId = entity.id_;
    update.mVariableData = std::move(block);
  }
} // namespace faf::remote
