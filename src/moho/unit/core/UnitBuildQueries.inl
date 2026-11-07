// Part of Unit.cpp, included there: unit queries, targeting and build checks.

/**
 * Address: 0x006A4BC0 (FUN_006A4BC0)
 *
 * What it does:
 * Returns this unit pointer through the const RTTI/downcast lane.
 */
Unit const* Unit::IsUnit() const
{
  return this;
}

/**
 * Address: 0x006A4BB0 (FUN_006A4BB0)
 *
 * What it does:
 * Returns this unit pointer through the mutable RTTI/downcast lane.
 */
Unit* Unit::IsUnit()
{
  return this;
}

// Address: 0x006A48E0 (FUN_006A48E0, Unit::IsUserUnit() const)
UserUnit const* Unit::IsUserUnit() const
{
  return nullptr;
}

// Address: 0x006A48D0 (FUN_006A48D0, Unit::IsUserUnit())
UserUnit* Unit::IsUserUnit()
{
  return nullptr;
}

// 0x006A49A0
EntId Unit::GetEntityId() const
{
  return id_;
}

// 0x006A8B20
RUnitBlueprint const* Unit::GetBlueprint() const
{
  const REntityBlueprint* const blueprint = BluePrint;
  return blueprint ? blueprint->IsUnitBlueprint() : nullptr;
}

/**
 * Address: 0x006A7600 (FUN_006A7600)
 * Mangled: ?GetSkirtRect@Unit@Moho@@QBE?AV?$Rect2@M@gpg@@XZ
 *
 * What it does:
 * Projects this unit position to XZ and resolves world-space skirt bounds
 * through the owning unit blueprint.
 */
gpg::Rect2f Unit::GetSkirtRect() const
{
  const Wm3::Vec3f& unitPosition = GetPosition();
  const SCoordsVec2 unitPos2d{unitPosition.x, unitPosition.z};
  const RUnitBlueprint* const blueprint = GetBlueprint();
  return blueprint->GetSkirtRect(unitPos2d);
}

/**
 * Address: 0x006AAEC0 (FUN_006AAEC0, ?AddRecoilImpulse@Unit@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z)
 * Mangled: ?AddRecoilImpulse@Unit@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z
 *
 * What it does:
 * Forwards one recoil impulse into `UnitMotion` when present.
 */
void Unit::AddRecoilImpulse(const Wm3::Vec3f& impulse)
{
  CUnitMotion* const unitMotion = UnitMotion;
  if (unitMotion != nullptr) {
    unitMotion->AddRecoilImpulse(impulse);
  }
}

/**
 * Address: 0x006AAEE0 (FUN_006AAEE0, ?AddImpulse@Unit@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z)
 * Mangled: ?AddImpulse@Unit@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z
 *
 * What it does:
 * Forwards one world impulse to `UnitMotion` when present.
 */
void Unit::AddImpulse(const Wm3::Vec3f& impulse)
{
  CUnitMotion* const unitMotion = UnitMotion;
  if (unitMotion != nullptr) {
    unitMotion->AddImpulse(impulse, false);
  }
}

/**
 * Address: 0x006AAF00 (FUN_006AAF00, ?AddLocalImpulse@Unit@Moho@@QAEXABV?$Vector3@M@Wm3@@0@Z)
 * Mangled: ?AddLocalImpulse@Unit@Moho@@QAEXABV?$Vector3@M@Wm3@@0@Z
 *
 * What it does:
 * Routes local impulse handling by motion type: airborne units use body-local
 * impulse integration, non-air units feed unit-motion impulse blending.
 */
void Unit::AddLocalImpulse(const Wm3::Vec3f& localImpulse, const Wm3::Vec3f& localPoint)
{
  CUnitMotion* const unitMotion = UnitMotion;
  if (unitMotion == nullptr) {
    return;
  }

  const Unit* const motionOwner = unitMotion->mUnit;
  const RUnitBlueprint* const blueprint = motionOwner->GetBlueprint();
  if (blueprint->Physics.MotionType == RULEUMT_Air) {
    SPhysBody* const body = static_cast<Entity*>(unitMotion->mUnit)->GetPhysBody(false);
    body->AddLocalImpulse(localImpulse, localPoint);
    return;
  }

  unitMotion->AddImpulse(localImpulse, false);
}

/**
 * Address: 0x006AAF50 (FUN_006AAF50, ?PickTargetPoint@Unit@Moho@@QBE_NAAH@Z)
 *
 * What it does:
 * Picks a random index in `Blueprint->AI.TargetBones`; writes `-1` when
 * the list is empty. Returns true on all paths.
 */
bool Unit::PickTargetPoint(std::int32_t& outTargetPoint) const
{
  const RUnitBlueprint* const blueprint = GetBlueprint();
  const std::uint32_t targetBoneCount =
    (blueprint != nullptr) ? static_cast<std::uint32_t>(blueprint->AI.TargetBones.size()) : 0u;

  if (targetBoneCount == 0u || !SimulationRef || !SimulationRef->mRngState) {
    outTargetPoint = -1;
    return true;
  }

  const std::uint32_t randomValue = SimulationRef->mRngState->twister.NextUInt32();
  outTargetPoint = PickUniformIndexFromU32(randomValue, targetBoneCount);
  return true;
}

/**
 * Address: 0x006AAFB0 (FUN_006AAFB0, ?PickTargetPointAboveWater@Unit@Moho@@QBE_NAAH@Z)
 *
 * What it does:
 * Picks one target-bone index above current water elevation, or falls back
 * to unit centerline elevation when no target-bone lanes are present.
 */
bool Unit::PickTargetPointAboveWater(std::int32_t& outTargetPoint) const
{
  outTargetPoint = -1;

  const STIMap* const mapData = SimulationRef->mMapData;
  const float waterElevation = (mapData->mWaterEnabled != 0u) ? mapData->mWaterElevation : -10000.0f;

  const RUnitBlueprint* const blueprint = GetBlueprint();
  const fa::vector<fa::string>& targetBones = blueprint->AI.TargetBones;
  const std::int32_t targetBoneCount = static_cast<std::int32_t>(targetBones.size());
  if (targetBoneCount > 0) {
    fa::vector<std::int32_t> candidateIndices{};
    for (std::int32_t targetIndex = 0; targetIndex < targetBoneCount; ++targetIndex) {
      if (GetTargetPoint(targetIndex).y > waterElevation) {
        candidateIndices.push_back(targetIndex);
      }
    }

    if (!candidateIndices.empty()) {
      const std::uint32_t randomValue = SimulationRef->mRngState->twister.NextUInt32();
      const std::int32_t pick = PickUniformIndexFromU32(randomValue, static_cast<std::uint32_t>(candidateIndices.size()));
      outTargetPoint = candidateIndices[static_cast<std::size_t>(pick)];
      return true;
    }

    return false;
  }

  return GetPosition().y > waterElevation;
}

/**
 * Address: 0x006AB190 (FUN_006AB190, ?PickTargetPointBelowWater@Unit@Moho@@QBE_NAAH@Z)
 *
 * What it does:
 * Picks one target-bone index below current water elevation, or falls back
 * to unit centerline elevation when no target-bone lanes are present.
 */
bool Unit::PickTargetPointBelowWater(std::int32_t& outTargetPoint) const
{
  outTargetPoint = -1;

  const STIMap* const mapData = SimulationRef->mMapData;
  const float waterElevation = (mapData->mWaterEnabled != 0u) ? mapData->mWaterElevation : -10000.0f;

  const RUnitBlueprint* const blueprint = GetBlueprint();
  const fa::vector<fa::string>& targetBones = blueprint->AI.TargetBones;
  const std::int32_t targetBoneCount = static_cast<std::int32_t>(targetBones.size());
  if (targetBoneCount > 0) {
    fa::vector<std::int32_t> candidateIndices{};
    for (std::int32_t targetIndex = 0; targetIndex < targetBoneCount; ++targetIndex) {
      if (GetTargetPoint(targetIndex).y < waterElevation) {
        candidateIndices.push_back(targetIndex);
      }
    }

    if (!candidateIndices.empty()) {
      const std::uint32_t randomValue = SimulationRef->mRngState->twister.NextUInt32();
      const std::int32_t pick = PickUniformIndexFromU32(randomValue, static_cast<std::uint32_t>(candidateIndices.size()));
      outTargetPoint = candidateIndices[static_cast<std::size_t>(pick)];
      return true;
    }

    return false;
  }

  // 0x006AB31D: `comiss water, pos.y` / `ja` -- strictly below the surface.
  return GetPosition().y < waterElevation;
}

/**
 * Address: 0x006AB340 (FUN_006AB340, Moho::Unit::GetTargetPoint)
 *
 * What it does:
 * Resolves one target-bone index to world position, clamping index lanes to
 * blueprint target-bone bounds and falling back to root bone (`-1`) when the
 * request is negative.
 */
Wm3::Vec3f Unit::GetTargetPoint(std::int32_t targetPoint) const
{
  // FAF FA-Binary-Patches #145/#157 (Account for collision offset when picking
  // target point of unit with no target bones): a unit without target bones is
  // aimed at its collision-box centre -- the base `Entity::GetBoneWorldTransform`
  // root anchor, which adds the blueprint's CollisionOffsetX/Y/Z -- instead of
  // `Unit::GetBoneWorldTransform`'s SizeY/2 above the pending position. Only
  // this negative-index entry (0x006AB34D) changes.
  if (targetPoint < 0 && FAF_IsSimFixActive(EFafSimFix::TargetPointCollisionCentre)) {
    return Entity::GetBoneWorldTransform(-1).pos_;
  }

  const RUnitBlueprint* const blueprint = GetBlueprint();
  if (targetPoint >= 0 && blueprint != nullptr) {
    const fa::vector<fa::string>& targetBones = blueprint->AI.TargetBones;
    const std::int32_t maxIndex = static_cast<std::int32_t>(targetBones.size()) - 1;
    if (targetPoint >= maxIndex) {
      targetPoint = maxIndex;
    }

    if (targetPoint >= 0) {
      const int boneIndex = ResolveBoneIndex(targetBones[static_cast<std::size_t>(targetPoint)].c_str());
      return GetBoneWorldTransform(boneIndex).pos_;
    }
  }

  return GetBoneWorldTransform(-1).pos_;
}

/**
 * Address: 0x006AB9C0 (FUN_006AB9C0, ?SetMesh@Unit@Moho@@UAEXABVRResId@2@PAVRMeshBlueprint@2@_N@Z)
 *
 * IDA signature:
 * void __thiscall Moho::Unit::SetMesh(Moho::Unit *this, const Moho::RResId &meshResId,
 *   Moho::RMeshBlueprint *meshBlueprint, char rebuildAniActor);
 *
 * What it does:
 * Forwards to `Entity::SetMesh` with `allowExplicitPlaceholder=true`, then
 * (when `rebuildAniActor` is set) recreates the unit's `CAniPose` and
 * `CAniActor` runtime chain so the visible animation tracks the new mesh's
 * skeleton.
 */
void Unit::SetMesh(const RResId& meshResId, RMeshBlueprint* const meshBlueprint, const bool rebuildAniActor)
{
  Entity::SetMesh(meshResId, meshBlueprint, true);
  if (!rebuildAniActor) {
    return;
  }

  boost::shared_ptr<const CAniSkel> skeleton;
  if (RScmResource* const scmResource = mVarDat.mScmResource.get(); scmResource != nullptr) {
    skeleton = scmResource->GetSkeleton();
  }

  CAniPose* newPose = nullptr;
  if (void* const poseStorage = ::operator new(sizeof(CAniPose)); poseStorage != nullptr) {
    const float scale = GetUniformScale();
    newPose = ::new (poseStorage) CAniPose(skeleton, scale);
  }

  SSTIUnitVariableData& varDat = VarDat();
  varDat.mSharedPose.reset(newPose);
  varDat.mSharedPose->SetWorldTransform(GetTransformWm3());
  varDat.mPriorSharedPose = varDat.mSharedPose;

  CAniActor* const newActor = new CAniActor(varDat.mSharedPose, varDat.mPriorSharedPose);

  CAniActor* const oldActor = AniActor;
  AniActor = newActor;
  if (oldActor != nullptr) {
    oldActor->~CAniActor();
    ::operator delete(oldActor);
  }
}

/**
 * Address: 0x006ABB90 (FUN_006ABB90, ?SetPoses@Unit@Moho@@QAEXABV?$shared_ptr@VCAniPose@Moho@@@boost@@0@Z)
 *
 * What it does:
 * Copies prior/current shared animation poses into variable-data lanes and
 * mirrors them into `AniActor::{mPose,mPriorPose}`.
 */
void Unit::SetPoses(
  const boost::shared_ptr<CAniPose>& priorSharedPose,
  const boost::shared_ptr<CAniPose>& sharedPose
)
{
  SSTIUnitVariableData& varDat = VarDat();
  varDat.mSharedPose = sharedPose;
  varDat.mPriorSharedPose = priorSharedPose;

  AniActor->AssignPoses(sharedPose, priorSharedPose);
}

/**
 * Address: 0x006A9E50 (FUN_006A9E50, ?CanBuild@Unit@Moho@@QBE_NPBVRUnitBlueprint@2@@Z)
 *
 * What it does:
 * Tests whether `blueprint` is present in this unit's effective build
 * category set after army and per-unit build restrictions are applied.
 */
bool Unit::CanBuild(const RUnitBlueprint* const blueprint) const
{
  // CArmyImpl +0x198 on x86: the IArmy payload at +0x08, `mVarDat` at +0x80,
  // `mCategoryFilterSet` at +0x110.
  const EntityCategorySet& armyBuildCategories = ArmyRef->mVarDat.mCategoryFilterSet;
  const EntityCategorySet& unitBlueprintBuildCategories = GetBlueprint()->Economy.CategoryCache;
  const EntityCategorySet& unitBuildRestrictions = GetAttributes().restrictionCategory;

  const std::uint32_t categoryBitIndex = blueprint->mCategoryBitIndex;
  return armyBuildCategories.ContainsBit(categoryBitIndex) &&
    unitBlueprintBuildCategories.ContainsBit(categoryBitIndex) &&
    !unitBuildRestrictions.ContainsBit(categoryBitIndex);
}

/**
 * Address: 0x0062D780 (FUN_0062D780, Moho::Unit::CanStartBuilding)
 *
 * What it does:
 * Returns true when this unit's army economy can start a build tick from
 * stored resources or by satisfying required income gates.
 */
bool Unit::CanStartBuilding(const float energyCost, const float massCost) const
{
  constexpr float kBuildResourceEpsilon = 0.001f;

  if (ArmyRef == nullptr) {
    return false;
  }

  const CSimArmyEconomyInfo* const economyInfo = ArmyRef->GetEconomy();
  if (economyInfo == nullptr) {
    return false;
  }

  // The tests are written the way the binary's branches read (0x0062D7A5..0x0062D7DB), not simplified: its comiss
  // leaves a NaN passing each of them, and an army's income can be NaN (replay 26939667, where a factory waited a tick
  // too long on a NaN mass income).
  const SEconTotals& totals = economyInfo->economy;
  if (!(kBuildResourceEpsilon >= totals.mStored.ENERGY) && !(kBuildResourceEpsilon >= totals.mStored.MASS)) {
    return true;
  }

  const bool hasEnergyBudget = !(energyCost > 0.0f) || !(kBuildResourceEpsilon > totals.mIncome.ENERGY);
  const bool hasMassBudget = !(massCost > 0.0f) || !(kBuildResourceEpsilon > totals.mIncome.MASS);
  return hasEnergyBudget && hasMassBudget;
}

// 0x006A49D0
LuaPlus::LuaObject Unit::GetLuaObject()
{
  return mLuaObj;
}

/**
 * Address: 0x00603F10 (FUN_00603F10, Moho::Unit::DecrementCapturers)
 *
 * What it does:
 * Decrements the non-negative captor reference count at `CaptorCount`
 * (+0x690), clamped at zero. Returns the post-decrement count.
 */
std::int32_t Unit::DecrementCapturers()
{
  if (CaptorCount > 0) {
    --CaptorCount;
  }
  return CaptorCount;
}

/**
 * Address: 0x00603F30 (FUN_00603F30)
 *
 * What it does:
 * Returns the current non-negative captor reference count lane.
 */
std::int32_t Unit::GetCapturerCount() const noexcept
{
  return CaptorCount;
}

/**
 * Address: 0x005F24C0 (FUN_005F24C0)
 *
 * What it does:
 * Returns whether this unit belongs to the MELEE category lane.
 */
bool Unit::IsMeleeUnit() const noexcept
{
  return mIsMelee;
}

/**
 * Address: 0x005F5570 (FUN_005F5570)
 *
 * What it does:
 * Returns the current retaliation fire-state lane.
 */
std::int32_t Unit::GetFireStateValue() const noexcept
{
  return mUnitVarDat.mFireState;
}

/**
 * Address: 0x005F5560 (FUN_005F5560)
 *
 * What it does:
 * Stores one upgraded-unit entity id lane and returns that id.
 */
EntId Unit::SetUpgradedToEntityId(const EntId upgradedToEntityId) noexcept
{
  mUnitVarDat.mSelectionInheritorId = upgradedToEntityId;
  return upgradedToEntityId;
}

/**
 * Address: 0x005F5590 (FUN_005F5590)
 *
 * What it does:
 * Returns the current silo-build implementation lane pointer.
 */
CAiSiloBuildImpl* Unit::GetSiloBuildImpl() const noexcept
{
  return AiSiloBuild;
}

/**
 * Address: 0x006A75C0 (FUN_006A75C0, ?GetMaxFootprintSize@Unit@Moho@@QBEHXZ)
 *
 * What it does:
 * Returns the larger side length of this unit's footprint (`sizeX`/`sizeZ`).
 */
int Unit::GetMaxFootprintSize() const
{
  const SFootprint& footprint = GetFootprint();
  const int sizeX = static_cast<int>(footprint.mSizeX);
  const int sizeZ = static_cast<int>(footprint.mSizeZ);
  return (sizeX >= sizeZ) ? sizeX : sizeZ;
}

/**
 * Address: 0x006A7640 (FUN_006A7640, Moho::Unit::SetFocusEntity)
 * Mangled: ?SetFocusEntity@Unit@Moho@@QAEXPAVEntity@2@@Z
 *
 * What it does:
 * Rebinds the focus-entity weak reference at +0x4D0, runs the
 * `OnAssignedFocusEntity` Lua callback when the slot now holds a live
 * target (non-null, non-sentinel), then unconditionally marks the unit
 * dirty for sync replication.
 */
void Unit::SetFocusEntity(Entity* const focusEntity)
{
  FocusEntityRef.ResetFromObject(focusEntity);

  const WeakPtr<Entity>& focusLane = FocusEntityRef;
  if (focusLane.HasValue()) {
    RunScript(kUnitOnAssignedFocusEntityScript);
  }

  NeedSyncGameData = true;
}

/**
 * Address: 0x006A7680 (FUN_006A7680, ?SetTargetBlipEntity@Unit@Moho@@QAEXPAVEntity@2@@Z)
 *
 * What it does:
 * Rebinds target-blip weak-reference ownership and marks unit sync state
 * dirty for replication.
 */
void Unit::SetTargetBlipEntity(Entity* const blipEntity)
{
  TargetBlipEntityRef.Set(blipEntity);
  NeedSyncGameData = true;
}

// 0x006A49F0
bool Unit::IsDead() const
{
  return mVarDat.mIsDead != 0;
}

// 0x006A4A00
bool Unit::DestroyQueued() const
{
  return DestroyQueuedFlag != 0;
}

// 0x006A4A10
bool Unit::IsMobile() const
{
  return UnitMotion != nullptr;
}

// 0x006A4A20
bool Unit::IsBeingBuilt() const
{
  return mVarDat.mIsBeingBuilt != 0;
}

/**
 * Address: 0x006A4BD0 (FUN_006A4BD0, Moho::Unit::GetUniformScale)
 *
 * What it does:
 * Returns display uniform scale from the unit blueprint lane.
 */
float Unit::GetUniformScale() const
{
  return GetBlueprint()->Display.UniformScale;
}

/**
 * Address: 0x006A9C90 (FUN_006A9C90, Moho::Unit::GetVelocity)
 *
 * What it does:
 * Returns motion velocity when a unit-motion lane is active on non-air
 * layers; otherwise computes per-tick position delta scaled by
 * `mVelocityScale`.
 */
Wm3::Vec3f Unit::GetVelocity() const
{
  if (UnitMotion != nullptr && mVarDat.mLayerMask != LAYER_Air) {
    Wm3::Vec3f velocity{};
    (void)UnitMotion->GetVelocity(&velocity);
    return velocity;
  }

  Wm3::Vec3f velocity{};
  velocity.x = (mVarDat.mCurTransform.pos_.x - mVarDat.mLastTransform.pos_.x) * mVarDat.mCurImpactValue;
  velocity.y = (mVarDat.mCurTransform.pos_.y - mVarDat.mLastTransform.pos_.y) * mVarDat.mCurImpactValue;
  velocity.z = (mVarDat.mCurTransform.pos_.z - mVarDat.mLastTransform.pos_.z) * mVarDat.mCurImpactValue;
  return velocity;
}

/**
 * Address: 0x006A9350 (FUN_006A9350, Moho::Unit::AdjustHealth)
 *
 * What it does:
 * Forwards unit health adjustments to the shared `Entity` health mutation
 * path.
 */
void Unit::AdjustHealth(Entity* const instigator, const float delta)
{
  Entity::AdjustHealth(instigator, delta);
}

/**
 * Address: 0x006A9B50 (FUN_006A9B50, Moho::Unit::UpdateTerrainType)
 * Mangled: ?UpdateTerrainType@Unit@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z
 *
 * What it does:
 * Samples terrain type under this unit's footprint-centered cell, updates
 * `CurrentTerrainType`, and dispatches terrain-change script data when it
 * changes.
 */
void Unit::UpdateTerrainType(const Wm3::Vector3f& position)
{
  STIMap* const mapData = SimulationRef->mMapData;
  const SFootprint& footprint = GetFootprint();

  const auto sampleX = static_cast<std::int16_t>(
    static_cast<std::int32_t>(std::lrintf(position.x - (static_cast<float>(footprint.mSizeX) * 0.5f)))
  );
  const auto sampleZ = static_cast<std::int16_t>(
    static_cast<std::int32_t>(std::lrintf(position.z - (static_cast<float>(footprint.mSizeZ) * 0.5f)))
  );

  const std::uint8_t previousTerrainType = CurrentTerrainType;
  std::uint8_t nextTerrainType = 1u;

  const CHeightField* const heightField = mapData->mHeightField.get();
  if (static_cast<std::uint32_t>(sampleX) < static_cast<std::uint32_t>(heightField->width - 1)
      && static_cast<std::uint32_t>(sampleZ) < static_cast<std::uint32_t>(heightField->height - 1)) {
    const std::size_t index =
      static_cast<std::size_t>(sampleZ) * static_cast<std::size_t>(mapData->mTerrainType.width)
      + static_cast<std::size_t>(sampleX);
    nextTerrainType = mapData->mTerrainType.data[index];
  }

  CurrentTerrainType = nextTerrainType;
  if (nextTerrainType == previousTerrainType) {
    return;
  }

  LuaPlus::LuaObject previousTerrain = mapData->GetTerrainType(previousTerrainType);
  LuaPlus::LuaObject currentTerrain = mapData->GetTerrainType(CurrentTerrainType);
  RunScriptOnTerrainTypeChange(currentTerrain, previousTerrain);
}

/**
 * Address: 0x006A9A40 (FUN_006A9A40, Moho::Unit::HandleTerranEffects)
 *
 * What it does:
 * Reads terrain-type Lua data for this unit, applies periodic
 * `HealthEffectPerSecond` scaling against max health every 10 ticks, and
 * kills the unit when health reaches zero.
 */
void Unit::HandleTerranEffects()
{
  LuaPlus::LuaObject terrainType = SimulationRef->mMapData->GetTerrainType(CurrentTerrainType);
  if (!terrainType.IsTable()) {
    return;
  }

  if ((SimulationRef->mCurTick % 10u) != 0u) {
    return;
  }

  LuaPlus::LuaObject healthEffect = terrainType["HealthEffectPerSecond"];
  if (healthEffect.IsNil()) {
    return;
  }

  const float delta = healthEffect.GetNumber() * mVarDat.mMaxHealth;
  AdjustHealth(nullptr, delta);
  if (mVarDat.mHealth <= 0.0f) {
    Kill(nullptr, "", 0.0f);
  }
}
