// Part of Unit.cpp, included there: consumption, production and weak references.

/**
 * Address: 0x006AAE20 (FUN_006AAE20, Moho::Unit::GetConsumptionRequest)
 *
 * What it does:
 * Returns the requested per-tick consumption pair from `mConsumptionData`.
 */
SEconValue Unit::GetConsumptionRequest() const
{
  SEconValue request{};
  request.energy = mConsumptionData->mRequested.energy;
  request.mass = mConsumptionData->mRequested.mass;
  return request;
}

/**
 * Address: 0x006AAE40 (FUN_006AAE40, Moho::Unit::UpdateResourceProduction)
 *
 * What it does:
 * Stores one economy-rate pair in the shared runtime production lane.
 */
void Unit::UpdateResourceProduction(const SEconValue& resourceProduction)
{
  mUnitVarDat.mMaintainenceCost.ENERGY = resourceProduction.energy;
  mUnitVarDat.mMaintainenceCost.MASS = resourceProduction.mass;
}

/**
 * Address: 0x006ABC70 (FUN_006ABC70, ?ResetEconValues@Unit@Moho@@QAEXXZ)
 *
 * What it does:
 * Clears the unit's produced and resources-spent economy totals.
 */
Unit* Unit::ResetEconValues()
{
  SSTIUnitVariableData& varDat = VarDat();
  varDat.mResourcesSpent.ENERGY = 0.0f;
  varDat.mResourcesSpent.MASS = 0.0f;
  varDat.mProduced.ENERGY = 0.0f;
  varDat.mProduced.MASS = 0.0f;
  return this;
}

/**
 * Address: 0x006AA900 (FUN_006AA900, ?SetConsumptionActive@Unit@Moho@@QAEX_N@Z)
 *
 * What it does:
 * Rebuilds unit upkeep request lanes for active/inactive economy
 * consumption and dispatches matching Lua script callbacks.
 */
void Unit::SetConsumptionActive(const bool isActive)
{
  const bool oldConsumptionIsActive = ConsumptionActive;
  ConsumptionActive = isActive;

  SEconValue newConsumption{};
  newConsumption.energy = mUnitVarDat.mAttributes.consumptionPerSecondEnergy * 0.1f;
  newConsumption.mass = mUnitVarDat.mAttributes.consumptionPerSecondMass * 0.1f;

  if (mConsumptionData == nullptr) {
    auto* const request = new CEconRequest{};
    request->mRequested = newConsumption;
    request->mGranted.energy = 0.0f;
    request->mGranted.mass = 0.0f;

    if (ArmyRef != nullptr) {
      if (CSimArmyEconomyInfo* const economyInfo = ArmyRef->GetEconomy(); economyInfo != nullptr) {
        request->mNode.ListLinkBefore(&economyInfo->registrationNode);
      }
    }

    if (mConsumptionData != nullptr) {
      mConsumptionData->mNode.ListUnlink();
      delete mConsumptionData;
    }
    mConsumptionData = request;
  }

  if (!ConsumptionActive) {
    // 0x006AA9DF..0x006AAA23: the unspent grant goes back into the army's
    // production pool (`GetEconomy() + 8` = mResources), so it is banked as
    // income on the next economy tick -- not straight into mStored.
    if (mConsumptionData != nullptr && ArmyRef != nullptr) {
      if (CSimArmyEconomyInfo* const economyInfo = ArmyRef->GetEconomy(); economyInfo != nullptr) {
        economyInfo->mResources.ENERGY += mConsumptionData->mGranted.energy;
        economyInfo->mResources.MASS += mConsumptionData->mGranted.mass;
      }
    }

    newConsumption.energy = 0.0f;
    newConsumption.mass = 0.0f;
  }

  if (mConsumptionData != nullptr) {
    mConsumptionData->mRequested = newConsumption;
  }

  mUnitVarDat.mMaintainenceCost.ENERGY = newConsumption.energy;
  mUnitVarDat.mMaintainenceCost.MASS = newConsumption.mass;

  if (ConsumptionActive != oldConsumptionIsActive) {
    if (ConsumptionActive) {
      CallbackStr("OnConsumptionActive");
    } else {
      CallbackStr("OnConsumptionInActive");
    }
  }
}

/**
 * Address: 0x006AAA90 (FUN_006AAA90, ?SetProductionActive@Unit@Moho@@QAEX_N@Z)
 *
 * What it does:
 * Writes one production-active flag lane and dispatches matching
 * `OnProductionActive` / `OnProductionInActive` script callbacks.
 */
void Unit::SetProductionActive(const bool isActive)
{
  ProductionActive = isActive;
  (void)RunScript(isActive ? kUnitOnProductionActiveScript : kUnitOnProductionInactiveScript);
}

/**
 * Address: 0x006A9370 (FUN_006A9370, ?RenderAIDebugInfo@Unit@Moho@@AAEXXZ)
 *
 * What it does:
 * Emits per-unit AI debug stat counters under `AIDebug_<UniqueName>`,
 * including platoon metadata, idle marker, and active unit-state markers.
 */
void Unit::RenderAIDebugInfo()
{
  if (!mDebugAIStates || ArmyRef == nullptr) {
    return;
  }

  ArmyRef->UpdateAIDebugPlatoonStats(this);

  CArmyStats* const armyStats = ArmyRef->GetArmyStats();
  if (armyStats == nullptr) {
    return;
  }

  const fa::string debugPrefix = fa::string("AIDebug_") + GetUniqueName();
  const fa::string unitStatePrefix = debugPrefix + "_UnitStates";

  const CUnitCommand* headCommand = nullptr;
  if (CommandQueue != nullptr && !CommandQueue->mCommandVec.empty()) {
    headCommand = CommandQueue->mCommandVec.begin()->GetObjectPtr();
  }

  if (headCommand == nullptr) {
    IncrementAIDebugStateStat(armyStats, unitStatePrefix + "_Idle");
  }

  for (
    std::int32_t stateValue = static_cast<std::int32_t>(UNITSTATE_Immobile);
    stateValue <= static_cast<std::int32_t>(UNITSTATE_SiloBuildingAmmo);
    ++stateValue
  ) {
    const EUnitState state = static_cast<EUnitState>(stateValue);
    if (!IsUnitState(state)) {
      continue;
    }

    const char* const stateLexical = UnitStateToDebugLexical(state);
    if (stateLexical == nullptr || stateLexical[0] == '\0') {
      continue;
    }

    IncrementAIDebugStateStat(armyStats, unitStatePrefix + "_" + stateLexical);
  }
}
namespace
{
  /**
   * Collapse one weak reference slot to the referenced entity's id, or to the
   * `0xF0000000` sentinel when the slot is empty or its target has died.
   *
   * `Unit::Sync` publishes four of these into the sync payload; the binary
   * inlines the same null-tag test and `id_` load at each one.
   */
  template <class TObject>
  [[nodiscard]] moho::EntId WeakRefEntityId(const moho::WeakPtr<TObject>& weak) noexcept
  {
    const TObject* const target = weak.GetObjectPtr();
    return target != nullptr ? target->id_ : kNoCreatorEntityId;
  }

  /**
   * A weapon's effective min/max radius: the live attribute when it has been
   * set, otherwise the blueprint default. The binary encodes "unset" as a
   * negative attribute value, and reaches the blueprint only on that path -
   * hence the member pointer rather than an eagerly-loaded fallback value.
   */
  [[nodiscard]] float ResolveWeaponRadius(
    const float attributeRadius,
    const moho::RUnitBlueprintWeapon* const blueprint,
    float moho::RUnitBlueprintWeapon::* const blueprintRadius
  ) noexcept
  {
    return attributeRadius < 0.0f ? blueprint->*blueprintRadius : attributeRadius;
  }
}



/**
 * Address: 0x006ABCC0 (FUN_006ABCC0, ?Sync@Unit@Moho@@UAEXPAUSSyncData@2@@Z)
 * Mangled: ?Sync@Unit@Moho@@UAEXPAUSSyncData@2@@Z
 * VFTable SLOT: 12 (over `Entity::Sync`)
 *
 * IDA signature:
 * void __thiscall Moho::Unit::Sync(Moho::Unit* this, Moho::SSyncData* syncData);
 *
 * What it does:
 * Refreshes the on-demand half of `VarDat()` and chains into `Entity::Sync`.
 *
 * Everything behind `NeedSyncGameData` is republished only when some gameplay
 * path has marked the unit dirty, and the flag is cleared on the way out:
 * the four weak references become entity ids, the six silo counters are
 * re-read (a unit with no silo controller reports zero rather than keeping a
 * stale count), and the weapon-info snapshot lane is regrown and refilled.
 *
 * The weapon pass is skipped entirely for a dead or destroy-queued unit -
 * its weapons are already being torn down - which leaves the last published
 * snapshot in place for the UI to keep drawing.
 *
 * Both shared animation poses are refreshed on every sync, dirty or not,
 * because they change every frame the unit animates.
 */
void Unit::Sync(SSyncData* const syncData)
{
  RefreshSyncBlock();
  Entity::Sync(syncData);
}

namespace moho
{
  /// Engine addition: RefreshSyncBlock assigns the two pose handles from the actor's fields instead of
  /// through a getter's copy. The copy only held a pose the actor still holds, so dropping it frees
  /// nothing earlier; an unchanged handle then costs no reference-count change at all. It still waits
  /// for the actor's queued pose update first, as the getter does.
  bool sim_UnitSyncHandleAssign = true;
  TConVar<bool> gTConVar_sim_UnitSyncHandleAssign(
    "sim_UnitSyncHandleAssign",
    "Unit sync refreshes assign pose handles from the animation actor's fields, without a getter's copy (same sim).",
    &sim_UnitSyncHandleAssign
  );
} // namespace moho

void Unit::RefreshSyncBlock(
  boost::shared_ptr<CAniPose>* const releasedPose, boost::shared_ptr<CAniPose>* const releasedPriorPose
)
{
  if (NeedSyncGameData) {
    SSTIUnitVariableData& varDat = VarDat();

    varDat.mCreator = WeakRefEntityId<Unit>(CreatorRef);
    varDat.mFocusUnit = WeakRefEntityId<Entity>(FocusEntityRef);
    varDat.mGuardedUnit = WeakRefEntityId<Unit>(GuardedUnitRef);
    varDat.mTargetBlip = WeakRefEntityId<Entity>(TargetBlipEntityRef);

    varDat.mTacticalSiloBuildCount = AiSiloBuild != nullptr ? AiSiloBuild->SiloGetBuildCount(SILOTYPE_Tactical) : 0;
    varDat.mNukeSiloBuildCount = AiSiloBuild != nullptr ? AiSiloBuild->SiloGetBuildCount(SILOTYPE_Nuke) : 0;
    varDat.mTacticalSiloStorageCount =
      AiSiloBuild != nullptr ? AiSiloBuild->SiloGetStorageCount(SILOTYPE_Tactical) : 0;
    varDat.mNukeSiloStorageCount = AiSiloBuild != nullptr ? AiSiloBuild->SiloGetStorageCount(SILOTYPE_Nuke) : 0;
    varDat.mTacticalSiloMaxStorageCount =
      AiSiloBuild != nullptr ? AiSiloBuild->SiloGetMaxStorageCount(SILOTYPE_Tactical) : 0;
    varDat.mNukeSiloMaxStorageCount = AiSiloBuild != nullptr ? AiSiloBuild->SiloGetMaxStorageCount(SILOTYPE_Nuke) : 0;

    if (!IsDead() && !DestroyQueued()) {
      const std::int32_t weaponCount = AiAttacker != nullptr ? AiAttacker->GetWeaponCount() : 0;

      gpg::fastvector_n<UnitWeaponInfo, 1>& weaponInfo = varDat.mWeaponInfo;
      if (static_cast<std::size_t>(weaponCount) > weaponInfo.size()) {
        weaponInfo.resize(static_cast<std::size_t>(weaponCount), UnitWeaponInfo{});
      }

      for (std::int32_t index = 0; index < weaponCount; ++index) {
        CAiAttackerImpl* const attacker = AiAttacker;
        if (attacker == nullptr) {
          continue;
        }

        const UnitWeapon* const weapon = attacker->GetWeapon(index);
        if (weapon == nullptr) {
          continue;
        }

        UnitWeaponInfo& snapshot = weaponInfo[static_cast<std::size_t>(index)];

        {
          EntityCategorySet category;
          snapshot.mCat1 = *weapon->GetCat1(&category);
        }
        {
          EntityCategorySet category;
          snapshot.mCat2 = *weapon->GetCat2(&category);
        }

        snapshot.mLayer = weapon->mFireTargetLayerCaps;

        const CWeaponAttributes& attributes = weapon->mAttributes;
        snapshot.mMinRadius =
          ResolveWeaponRadius(attributes.mMinRadius, attributes.mBlueprint, &RUnitBlueprintWeapon::MinRadius);
        snapshot.mMaxRadius =
          ResolveWeaponRadius(attributes.mMaxRadius, attributes.mBlueprint, &RUnitBlueprintWeapon::MaxRadius);

        if (weapon->mWeaponBlueprint != nullptr) {
          snapshot.mUIMinRangeVisualId = weapon->mWeaponBlueprint->UIMinRangeVisualId;
          snapshot.mUIMaxRangeVisualId = weapon->mWeaponBlueprint->UIMaxRangeVisualId;
        }

        // The blueprint's own effective radius wins when it is set; otherwise
        // the weapon falls back to whatever it resolved as its max range.
        if (weapon->mWeaponBlueprint != nullptr && weapon->mWeaponBlueprint->EffectiveRadius >= 0.0f) {
          snapshot.mEffectiveRadius = weapon->mWeaponBlueprint->EffectiveRadius;
        } else {
          snapshot.mEffectiveRadius =
            ResolveWeaponRadius(attributes.mMaxRadius, attributes.mBlueprint, &RUnitBlueprintWeapon::MaxRadius);
        }
      }
    }

    NeedSyncGameData = false;
  }

  if (!POSE_HoldClientHandles(*AniActor)) {
    if (VarDat().mSharedPose.get() != nullptr || VarDat().mPriorSharedPose.get() != nullptr) {
      boost::shared_ptr<CAniPose> none;
      boost::shared_ptr<CAniPose> nonePrior;
      if (releasedPose != nullptr) {
        releasedPose->swap(VarDat().mSharedPose);
      } else {
        VarDat().mSharedPose.swap(none);
      }
      if (releasedPriorPose != nullptr) {
        releasedPriorPose->swap(VarDat().mPriorSharedPose);
      } else {
        VarDat().mPriorSharedPose.swap(nonePrior);
      }
    }
    return;
  }
  if (sim_UnitSyncHandleAssign) {
    POSE_WaitFor(AniActor); // what GetPoseShared did first (sim_ParallelPose): this tick's queued update is done
  }
  if (releasedPose != nullptr) {
    releasedPose->swap(VarDat().mSharedPose);
  }
  if (sim_UnitSyncHandleAssign) {
    VarDat().mSharedPose = AniActor->mPose;
  } else {
    VarDat().mSharedPose = AniActor->GetPoseShared();
  }
  if (releasedPriorPose != nullptr) {
    releasedPriorPose->swap(VarDat().mPriorSharedPose);
  }
  if (sim_UnitSyncHandleAssign) {
    VarDat().mPriorSharedPose = AniActor->mPriorPose;
  } else {
    VarDat().mPriorSharedPose = AniActor->GetPriorPoseShared();
  }
}
