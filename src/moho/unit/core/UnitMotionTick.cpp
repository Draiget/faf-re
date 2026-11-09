#include "moho/unit/core/UnitPrivate2.h"

namespace
{

  [[nodiscard]] bool ShouldTestPrepareMoveCellAgainstSkirt(
    const SOCellPos& candidateCell,
    const gpg::Rect2f& skirtRect
  ) noexcept
  {
    const float cellMinX = static_cast<float>(candidateCell.x);
    const float cellMinZ = static_cast<float>(candidateCell.z);
    const float cellMaxX = static_cast<float>(candidateCell.x + 1);
    const float cellMaxZ = static_cast<float>(candidateCell.z + 1);

    return skirtRect.x0 > cellMaxX || cellMinX > skirtRect.x1 || skirtRect.z0 > cellMaxZ || cellMinZ > skirtRect.z1 ||
      skirtRect.x1 <= skirtRect.x0 || skirtRect.z0 >= skirtRect.z1 || cellMaxX <= cellMinX || cellMinZ >= cellMaxZ;
  }

  [[nodiscard]] bool IsPrepareMoveCandidateValid(
    Unit& unit,
    const SFootprint& footprint,
    const ELayer moveLayer,
    const SOCellPos& cell,
    const Wm3::Vector3f& worldPos,
    const gpg::Rect2f& skirtRect,
    const bool useWholeMap
  )
  {
    Sim* const sim = unit.SimulationRef;
    if (sim == nullptr || sim->mMapData == nullptr || sim->mOGrid == nullptr) {
      return false;
    }

    if (!ShouldTestPrepareMoveCellAgainstSkirt(cell, skirtRect)) {
      return false;
    }

    const float border = static_cast<float>(FootprintMaxSide(footprint));
    if (!sim->mMapData->IsWithin(worldPos, border, useWholeMap)) {
      return false;
    }

    return IsMeleeCandidateCellNavigable(unit, nullptr, footprint, moveLayer, *sim->mOGrid, *sim->mMapData, cell);
  }
}


/**
 * Address: 0x006A9010 (FUN_006A9010, Moho::Unit::MotionTick)
 * Primary vtable slot 20 (`??_7Unit@Moho@@6BEntity@Moho@@@`, Entity subobject).
 *
 * What it does:
 * Per-tick motion driver. Logs the tick, advances the silo-build sidecar,
 * refreshes the guard formation and info cache, counts down the stun timer,
 * dispatches to the owned `CUnitMotion`'s own per-tick update, ticks every
 * pending economy event, refreshes animation manipulators from the pending
 * transform, recomputes whether this unit is currently attached to
 * something, then - while alive - either regenerates health (when not under
 * construction and the regen rate is positive) or applies build decay (when
 * still under construction, past the first tick after creation), then runs
 * the resource-management economy step. Finally, if this unit is not a POD
 * and its command queue is empty, issues an `AssistCommander` command to
 * itself; and if a builder sidecar is present, validates its factory queue.
 *
 * Entity::StandardInit registers the entity task in the simulation stage.
 * The task dispatcher reaches Entity::TaskTick (0x00679C40), whose final
 * virtual call dispatches here through the Entity subobject's slot 20.
 */
int Unit::MotionTick()
{
  SimulationRef->Logf("0x%08x's motion tick.\n", id_);

  {
    FAF_PROFILE_ZONE_NAMED("Unit::PreMotion");
    if (AiSiloBuild != nullptr) {
      AiSiloBuild->SiloTick();
    }

    UpdateGuardFormation();
    UpdateInfoCache();
  }

  if (mUnitVarDat.mStunTicks > 0) {
    --mUnitVarDat.mStunTicks;
  }

  int motionResult = static_cast<int>(TASKSTATUS_Wait);
  {
    FAF_PROFILE_ZONE_NAMED("Unit::Motion");
    if (UnitMotion != nullptr) {
      motionResult = static_cast<int>(UnitMotion->MotionTick());
    }
  }

  {
    FAF_PROFILE_ZONE_NAMED("Unit::EconomyEvents");
    for (CEconomyEvent* const economyEvent : mEconomyEventListHead) {
      economyEvent->ProcessTick();
    }
  }

  {
    FAF_PROFILE_ZONE_NAMED("Unit::Manipulators");
    POSE_UpdateManipulators(*this); // AniActor->UpdateManipulators(mPendingTransform), or queued (sim_ParallelPose)
  }

  mUnitVarDat.mIsBusy = mAttachInfo.HasAttachTarget();

  if (!mVarDat.mIsBeingBuilt) {
    if (mVarDat.mMaxHealth > mVarDat.mHealth && GetAttributes().regenRate > 0.0f) {
      AdjustHealth(this, GetAttributes().regenRate * 0.1f);
    }
  } else if (static_cast<std::int32_t>(SimulationRef->mCurTick - mCreationTick) > 1) {
    const RUnitBlueprintEconomy& economy = GetBlueprint()->Economy;
    float buildTime = std::max(economy.BuildCostEnergy, economy.BuildCostMass);
    buildTime = std::max(buildTime, economy.BuildTime);

    if (buildTime > 0.0f) {
      Materialize(-0.1f / buildTime);
      if (mVarDat.mHealth <= 0.0f) {
        RunScript("OnDecayed");
      }
    }
  }

  {
    FAF_PROFILE_ZONE_NAMED("Unit::ResourceManagement");
    HandleResourceManagement();
  }

  if (mIsNotPod && (CommandQueue == nullptr || CommandQueue->mCommandVec.empty())) {
    EntitySetTemplate<Unit> selectedUnits{};
    (void)selectedUnits.Add(this);
    SSTICommandIssueData commandData(EUnitCommandType::UNITCOMMAND_AssistCommander);
    (void)IssueCommandToSelectedUnits(SimulationRef, selectedUnits, commandData, false);
  }

  if (AiBuilder != nullptr) {
    AiBuilder->BuilderValidateFactoryCommandQueue();
  }

  return motionResult;
}

// 0x006A49B0
Wm3::Vec3f const& Unit::GetPosition() const
{
  return GetPositionWm3();
}

// 0x006A49C0
VTransform const& Unit::GetTransform() const
{
  return GetTransformWm3();
}

/**
 * Address: 0x0062CC40 (FUN_0062CC40, Moho::Unit::IsAtPosition)
 *
 * What it does:
 * Compares this unit's footprint-aligned grid anchor against one candidate
 * world position using the same half-footprint cell projection.
 */
bool Unit::IsAtPosition(const Wm3::Vec3f& position) const
{
  const SFootprint& unitFootprint = GetFootprint();
  const Wm3::Vec3f& currentPosition = GetPosition();

  const std::int16_t currentCellZ = static_cast<std::int16_t>(
    static_cast<int>(std::lrintf(currentPosition.z - static_cast<float>(unitFootprint.mSizeZ) * 0.5f))
  );
  const std::int16_t currentCellX = static_cast<std::int16_t>(
    static_cast<int>(std::lrintf(currentPosition.x - static_cast<float>(unitFootprint.mSizeX) * 0.5f))
  );

  const SFootprint& targetFootprint = GetFootprint();
  const std::int16_t targetCellZ = static_cast<std::int16_t>(
    static_cast<int>(std::lrintf(position.z - static_cast<float>(targetFootprint.mSizeZ) * 0.5f))
  );
  const std::int16_t targetCellX = static_cast<std::int16_t>(
    static_cast<int>(std::lrintf(position.x - static_cast<float>(targetFootprint.mSizeX) * 0.5f))
  );

  return currentCellX == targetCellX && currentCellZ == targetCellZ;
}

/**
 * Address: 0x006AA5C0 (FUN_006AA5C0, ?GetBoneWorldTransform@Unit@Moho@@UBE?AVVTransform@2@H@Z)
 *
 * What it does:
 * Resolves one unit bone world transform from pose composite lanes when the
 * bone index is valid, otherwise composes unit world transform with the
 * fallback local anchor (`+SizeY*0.5` for root `-1`).
 */
VTransform Unit::GetBoneWorldTransform(const int boneIndex) const
{
  if (boneIndex >= 0) {
    POSE_WaitFor(AniActor); // engine addition (sim_ParallelPose): this tick's pose first
  }
  if (AniActor != nullptr && AniActor->mPose.get() != nullptr && boneIndex >= 0) {
    const CAniPose* const pose = AniActor->mPose.get();
    const CAniPoseBone* const bonesBegin = pose->mBones.begin();
    const CAniPoseBone* const bonesEnd = pose->mBones.end();
    if (bonesBegin != nullptr && bonesEnd != nullptr && bonesEnd >= bonesBegin) {
      const std::size_t boneCount = static_cast<std::size_t>(bonesEnd - bonesBegin);
      if (static_cast<std::size_t>(boneIndex) < boneCount) {
        return bonesBegin[boneIndex].GetCompositeTransform();
      }
    }
  }

  VTransform localAnchor{};
  localAnchor.orient_.w = 1.0f;
  localAnchor.orient_.x = 0.0f;
  localAnchor.orient_.y = 0.0f;
  localAnchor.orient_.z = 0.0f;
  localAnchor.pos_.x = 0.0f;
  localAnchor.pos_.y = 0.0f;
  localAnchor.pos_.z = 0.0f;

  if (boneIndex == -1) {
    if (const RUnitBlueprint* const blueprint = GetBlueprint(); blueprint != nullptr) {
      localAnchor.pos_.y = blueprint->mSizeY * 0.5f;
    }
  }

  // 0x006AA692..0x006AA6ED: the anchor composes onto the pending transform
  // (Entity+0x150) -- where motion has already placed the unit this tick --
  // not the current one, which still holds last beat's position.
  return VTransform::Compose(mPendingTransform, localAnchor);
}

/**
 * Address: 0x006AA440 (FUN_006AA440, ?GetBoneLocalTransform@Unit@Moho@@UBE?AVVTransform@2@H@Z)
 *
 * What it does:
 * Resolves one unit bone local transform from animation pose composite lanes,
 * with `-1` fallback to blueprint center-height anchor.
 */
VTransform Unit::GetBoneLocalTransform(const int boneIndex) const
{
  VTransform localTransform{};
  localTransform.orient_.w = 1.0f;
  localTransform.orient_.x = 0.0f;
  localTransform.orient_.y = 0.0f;
  localTransform.orient_.z = 0.0f;
  localTransform.pos_.x = 0.0f;
  localTransform.pos_.y = 0.0f;
  localTransform.pos_.z = 0.0f;

  POSE_WaitFor(AniActor); // engine addition (sim_ParallelPose): this tick's pose first
  if (AniActor != nullptr && AniActor->mPose.get() != nullptr) {
    const CAniPose* const pose = AniActor->mPose.get();
    const CAniPoseBone* const bonesBegin = pose->mBones.begin();
    const CAniPoseBone* const bonesEnd = pose->mBones.end();
    if (bonesBegin != nullptr && bonesEnd != nullptr && bonesEnd >= bonesBegin) {
      const std::size_t boneCount = static_cast<std::size_t>(bonesEnd - bonesBegin);
      if (boneIndex >= 0 && static_cast<std::size_t>(boneIndex) < boneCount) {
        localTransform = bonesBegin[boneIndex].GetCompositeTransform();
        const VTransform poseInverse = pose->mLocalTransform.Inverse();
        localTransform = VTransform::Compose(localTransform, poseInverse);
        return localTransform;
      }
    }
  }

  if (boneIndex == -1) {
    localTransform.pos_.y = GetBlueprint()->mSizeY * 0.5f;
  }

  return localTransform;
}

/**
 * Address: 0x006A8D40 (FUN_006A8D40, Moho::Unit::IsSameFormationLayerWith)
 *
 * What it does:
 * Returns true when both units are not attacking and share the same non-null
 * formation-layer pointer.
 */
bool Unit::IsSameFormationLayerWith(const Unit* const other) const
{
  if (other == nullptr) {
    return false;
  }

  if (IsUnitState(UNITSTATE_Attacking) || other->IsUnitState(UNITSTATE_Attacking)) {
    return false;
  }

  return mInfoCache.mFormationLayer != nullptr && mInfoCache.mFormationLayer == other->mInfoCache.mFormationLayer;
}

/**
 * Address: 0x0062B780 (FUN_0062B780, Moho::Unit::PrepareMove)
 *
 * What it does:
 * Coerces one world-space move destination into the nearest valid move cell
 * for this unit, honoring occupancy/pathability and skirt exclusion.
 */
bool Unit::PrepareMove(
  const int moveFlags,
  Wm3::Vector3f* const inOutPos,
  gpg::Rect2f* const skirtRect,
  const bool useWholeMap
)
{
  if (inOutPos == nullptr || skirtRect == nullptr) {
    return false;
  }

  Sim* const sim = SimulationRef;
  if (sim == nullptr || sim->mMapData == nullptr || sim->mOGrid == nullptr) {
    return false;
  }

  SFootprint footprint = GetFootprint();
  const std::uint8_t footprintSearchSide = FootprintMaxSide(footprint);
  const int searchStep = (moveFlags > 0) ? moveFlags : static_cast<int>(footprintSearchSide) * 2;

  const ELayer moveLayer = mVarDat.mLayerMask;
  const RUnitBlueprint* const blueprint = GetBlueprint();
  if (blueprint != nullptr && blueprint->Air.CanFly) {
    const std::uint8_t adjustedCaps = static_cast<std::uint8_t>(
      (static_cast<std::uint8_t>(footprint.mOccupancyCaps) - static_cast<std::uint8_t>(EOccupancyCaps::OC_AIR)) |
      static_cast<std::uint8_t>(EOccupancyCaps::OC_LAND)
    );
    footprint.mOccupancyCaps = static_cast<EOccupancyCaps>(adjustedCaps);

    const std::uint8_t maxSide = FootprintMaxSide(footprint);
    footprint.mSizeX = maxSide;
    footprint.mSizeZ = maxSide;

    if (IsInCategory("CANLANDONWATER")) {
      const STIMap* const mapData = sim->mMapData;
      const CHeightField* const heightField = (mapData != nullptr && mapData->mHeightField) ? mapData->mHeightField.get() : nullptr;
      const float terrainElevation = (heightField != nullptr) ? heightField->GetElevation(inOutPos->x, inOutPos->z) : inOutPos->y;
      const float waterElevation =
        mapData != nullptr ? mapData->GetWaterElevationAt(inOutPos->x, inOutPos->z) : -10000.0f; // engine addition
      if (waterElevation > terrainElevation) {
        const std::uint8_t withWaterCaps = static_cast<std::uint8_t>(
          static_cast<std::uint8_t>(footprint.mOccupancyCaps) | static_cast<std::uint8_t>(EOccupancyCaps::OC_WATER)
        );
        footprint.mOccupancyCaps = static_cast<EOccupancyCaps>(withWaterCaps);
      }
    }
  }

  const float halfSizeX = static_cast<float>(footprint.mSizeX) * 0.5f;
  const float halfSizeZ = static_cast<float>(footprint.mSizeZ) * 0.5f;

  // 0x0062B941/0x0062B975: both origin coordinates go through x87 `fistp`
  // (round to nearest), not truncation. A destination at a whole world unit
  // with an odd footprint lands on .5 here, and truncating it started the ring
  // search one cell to the side (replay 26935800 beat 532: goal cell 95 vs 96).
  const int rawStartX = fa::RoundToInt(inOutPos->x - halfSizeX);
  const int rawStartZ = fa::RoundToInt(inOutPos->z - halfSizeZ);
  SOCellPos startCell{
    static_cast<std::int16_t>(rawStartX),
    static_cast<std::int16_t>(rawStartZ),
  };

  if (IsPrepareMoveCandidateValid(*this, footprint, moveLayer, startCell, *inOutPos, *skirtRect, useWholeMap)) {
    return true;
  }

  std::vector<Wm3::Vector3f> candidatePositions{};
  candidatePositions.reserve(16);

  int minRing = -1;
  int maxRing = 1;
  int checkedCellCount = 0;
  constexpr int kPrepareMoveMaxCheckedCells = 900;
  while (true) {
    candidatePositions.clear();

    for (int ringX = minRing; ringX <= maxRing; ++ringX) {
      const int ringStepZ = (ringX == minRing || ringX == maxRing) ? 1 : (2 * maxRing);
      const int rawX = static_cast<int>(startCell.x) + (ringX * searchStep);
      const std::int16_t cellX = static_cast<std::int16_t>(rawX);

      for (int ringZ = minRing; ringZ <= maxRing; ringZ += ringStepZ) {
        ++checkedCellCount;

        const int rawZ = static_cast<int>(startCell.z) + (ringZ * searchStep);
        const std::int16_t cellZ = static_cast<std::int16_t>(rawZ);
        const SOCellPos candidateCell{cellX, cellZ};

        const Wm3::Vector3f candidateWorldPos{
          static_cast<float>(cellX) + halfSizeX,
          0.0f,
          static_cast<float>(cellZ) + halfSizeZ,
        };

        if (!IsPrepareMoveCandidateValid(
              *this,
              footprint,
              moveLayer,
              candidateCell,
              candidateWorldPos,
              *skirtRect,
              useWholeMap
            ))
        {
          continue;
        }

        candidatePositions.push_back(candidateWorldPos);
      }
    }

    if (!candidatePositions.empty()) {
      break;
    }

    if (checkedCellCount >= kPrepareMoveMaxCheckedCells) {
      return false;
    }

    ++maxRing;
    --minRing;
  }

  const Wm3::Vector3f unitPosition = GetPosition();
  float bestDistanceSq = gpg::pInf;
  Wm3::Vector3f bestCandidatePos = *inOutPos;
  for (const Wm3::Vector3f& candidateWorldPos : candidatePositions) {
    const float dx = candidateWorldPos.x - unitPosition.x;
    const float dy = candidateWorldPos.y - unitPosition.y;
    const float dz = candidateWorldPos.z - unitPosition.z;
    const float distanceSq = (dx * dx) + (dy * dy) + (dz * dz);
    if (distanceSq < bestDistanceSq) {
      bestDistanceSq = distanceSq;
      bestCandidatePos = candidateWorldPos;
    }
  }

  inOutPos->x = bestCandidatePos.x;
  inOutPos->y = bestCandidatePos.y;
  inOutPos->z = bestCandidatePos.z;
  return true;
}
