// Part of Unit.cpp, included there: formations and occupied ground.

/**
 * Address: 0x006A8C20 (FUN_006A8C20, Moho::Unit::GetFormationVector)
 *
 * What it does:
 * Resolves one unit movement vector from formation runtime lanes, with
 * air-leader fallback to leader forward heading when applicable.
 */
Wm3::Vector3f Unit::GetFormationVector() const
{
  Wm3::Vector3f result{0.0f, 0.0f, 0.0f};

  if (IsUnitState(UNITSTATE_TransportLoading) || IsUnitState(UNITSTATE_Refueling) ||
      mInfoCache.mFormationLayer == nullptr) {
    return result;
  }

  if (mIsAir) {
    const Unit* const formationLead = mInfoCache.mFormationLeadRef.GetObjectPtr();
    if (formationLead != nullptr && !formationLead->mIsAir) {
      return ForwardXZ(*formationLead);
    }
  }

  const auto* const formationLayer = reinterpret_cast<const CAiFormationInstance*>(mInfoCache.mFormationLayer);
  if (formationLayer != nullptr && formationLayer->CommandIsForm()) {
    formationLayer->GetForwardVector(&result, const_cast<Unit*>(this));
  }

  return result;
}

/**
 * Address: 0x006A9720 (FUN_006A9720, Moho::Unit::GetFormation)
 *
 * What it does:
 * Resolves active formation ownership either from guarded-unit formation lane
 * or from the current command queue head command.
 */
IFormationInstance* Unit::GetFormation() const
{
  Unit* const guardedUnit = GuardedUnitRef.GetObjectPtr();
  if (guardedUnit != nullptr && !mIsEngineer) {
    if (IsUnitState(UNITSTATE_GuardBusy)) {
      return nullptr;
    }

    return guardedUnit->GuardFormation;
  }

  const CUnitCommandQueue* const commandQueue = CommandQueue;
  if (commandQueue != nullptr && !commandQueue->mCommandVec.empty()) {
    CUnitCommand* const currentCommand = commandQueue->mCommandVec.front().GetObjectPtr();
    if (currentCommand != nullptr) {
      CAiFormationInstance* const commandFormation = currentCommand->mFormationInstance;
      if (commandFormation != nullptr && commandFormation->Contains(const_cast<Unit*>(this), true)) {
        return commandFormation;
      }
    }
  }

  return nullptr;
}

/**
 * Address: 0x006A9810 (FUN_006A9810, Moho::Unit::UpdateInfoCache)
 *
 * What it does:
 * Refreshes cached formation-owner/speed lanes and recomputes movement top
 * speed for mobile units.
 */
void Unit::UpdateInfoCache()
{
  if (!IsMobile()) {
    return;
  }

  CAiFormationInstance* const formation = reinterpret_cast<CAiFormationInstance*>(GetFormation());
  SOffsetInfo* offsetInfo = nullptr;

  if (formation != nullptr && formation->CommandIsForm() && formation->Contains(this, false)) {
    // Virtual-call order as at 0x006A9860-0x006A98DF: GetOffsetInfo,
    // GetPriority, GetLeader, GetTargetPosition, GetDistFromLeader,
    // IsInFormation.
    offsetInfo = formation->GetOffsetInfo(this);
    mInfoCache.mFormationLayer = reinterpret_cast<CFormationInstance*>(formation);
    mInfoCache.mFormationPriorityOrder = formation->GetPriority(this, offsetInfo);

    Unit* const formationLead = formation->GetLeader(this, offsetInfo);
    mInfoCache.mFormationLeadRef.Set(formationLead);

    Wm3::Vec3f headingHint{};
    formation->GetTargetPosition(&headingHint, this, offsetInfo);
    mInfoCache.mFormationHeadingHint = headingHint;
    mInfoCache.mFormationDistanceMetric = formation->GetDistFromLeader(this, offsetInfo);
    // 0x006A98DB: `push 0` -- IsInFormation is asked about a null unit, not
    // `this`.
    mInfoCache.mHasFormationSpeedData = formation->IsInFormation(nullptr);
  } else {
    // 0x006A98E9-0x006A9951: layer = null, priority = 1, lead link cleared,
    // heading = own position, distance = 0, flag = false.
    mInfoCache.mFormationLayer = nullptr;
    mInfoCache.mFormationPriorityOrder = 1;
    mInfoCache.mFormationLeadRef.Set(nullptr);
    mInfoCache.mFormationHeadingHint = GetPosition();
    mInfoCache.mFormationDistanceMetric = 0.0f;
    mInfoCache.mHasFormationSpeedData = false;
  }

  const RUnitBlueprint* const blueprint = GetBlueprint();
  if (blueprint == nullptr) {
    mInfoCache.mFormationTopSpeed = 0.0f;
    return;
  }

  const float speedMult = GetAttributes().moveSpeedMult;
  float topSpeed = 0.0f;
  if (!blueprint->Air.CanFly) {
    topSpeed = blueprint->Physics.MaxSpeed * speedMult;
  } else {
    topSpeed = (blueprint->Air.MaxAirspeed * speedMult) / CalcTransportLoadFactor();
  }

  float speedScale = 1.0f;
  float clampedFormationSpeed = topSpeed;
  if (formation != nullptr && offsetInfo != nullptr) {
    const float formationSpeed = formation->CalcFormationSpeed(this, &speedScale, offsetInfo);
    if (formationSpeed > 0.0f) {
      clampedFormationSpeed = (formationSpeed > topSpeed) ? topSpeed : formationSpeed;
    }
  }

  const float scaledSpeed = speedScale * clampedFormationSpeed;
  // 0x006A9A24: `comiss scaled, top` / `ja` keeps `top`; unordered falls
  // through to the scaled value.
  if (!(scaledSpeed > topSpeed)) {
    topSpeed = scaledSpeed;
  }

  mInfoCache.mFormationTopSpeed = topSpeed;
}

/**
 * Address: 0x006A8D80 (FUN_006A8D80, ?IsHigherPriorityThan@Unit@Moho@@QBE_NPBV12@@Z)
 */
bool Unit::IsHigherPriorityThan(const Unit* const other) const
{
  if (!other) {
    return true;
  }

  if (IsUnitState(UNITSTATE_Immobile) || IsUnitState(UNITSTATE_Upgrading)) {
    return true;
  }
  if (other->IsUnitState(UNITSTATE_Immobile) || other->IsUnitState(UNITSTATE_Upgrading)) {
    return false;
  }

  if (mIsNaval) {
    if (!other->mIsNaval) {
      return true;
    }
  } else if (other->mIsNaval) {
    return false;
  }

  const bool thisIgnoreStructures = HasFootprintFlag(GetFootprint().mFlags, EFootprintFlags::FPFLAG_IgnoreStructures);
  const bool otherIgnoreStructures =
    HasFootprintFlag(other->GetFootprint().mFlags, EFootprintFlags::FPFLAG_IgnoreStructures);
  if (thisIgnoreStructures) {
    if (!otherIgnoreStructures) {
      return true;
    }
  } else if (otherIgnoreStructures) {
    return false;
  }

  if (const RUnitBlueprint* const blueprint = GetBlueprint()) {
    if (blueprint->Air.CanFly && mVarDat.mLayerMask != LAYER_Air) {
      return true;
    }
  }
  if (const RUnitBlueprint* const blueprint = other->GetBlueprint()) {
    if (blueprint->Air.CanFly && other->mVarDat.mLayerMask != LAYER_Air) {
      return false;
    }
  }

  if (IsUnitState(UNITSTATE_WaitingForTransport) && !other->IsUnitState(UNITSTATE_WaitingForTransport)) {
    return true;
  }

  if (GetGuardedUnit() == other) {
    return false;
  }
  if (other->GetGuardedUnit() == this) {
    return true;
  }

  bool inSharedFormation = false;
  if (mInfoCache.mFormationLayer && mInfoCache.mFormationLayer == other->mInfoCache.mFormationLayer) {
    inSharedFormation = true;

    const Unit* const formationLead = mInfoCache.mFormationLeadRef.GetObjectPtr();
    if (formationLead == this) {
      return true;
    }
    if (formationLead == other) {
      return false;
    }
  }

  if (IsUnitState(UNITSTATE_Moving) && !other->IsUnitState(UNITSTATE_Moving)) {
    return false;
  }
  if (!IsUnitState(UNITSTATE_Moving) && other->IsUnitState(UNITSTATE_Moving)) {
    return true;
  }

  if (inSharedFormation) {
    if (mInfoCache.mFormationPriorityOrder != other->mInfoCache.mFormationPriorityOrder) {
      return mInfoCache.mFormationPriorityOrder < other->mInfoCache.mFormationPriorityOrder;
    }
    return other->mInfoCache.mFormationDistanceMetric > mInfoCache.mFormationDistanceMetric;
  }

  const SFootprint& thisFootprint = GetFootprint();
  const SFootprint& otherFootprint = other->GetFootprint();
  const std::uint8_t thisFootprintSize = std::max(thisFootprint.mSizeX, thisFootprint.mSizeZ);
  const std::uint8_t otherFootprintSize = std::max(otherFootprint.mSizeX, otherFootprint.mSizeZ);
  if (thisFootprintSize > otherFootprintSize) {
    return true;
  }
  if (thisFootprintSize != otherFootprintSize) {
    return false;
  }

  if (const Unit* const moreInLine = UnitMoreInLineToOther(other, this)) {
    return moreInLine == this;
  }

  return static_cast<std::uint32_t>(GetEntityId()) < static_cast<std::uint32_t>(other->GetEntityId());
}

[[nodiscard]] bool PrepareMove(
  int moveFlags,
  Unit* unit,
  Wm3::Vector3f* inOutPos,
  gpg::Rect2f* outSkirtRect,
  bool useWholeMap
)
{
  // Alias of FUN_0062B780 canonical body in Unit::PrepareMove.
  if (unit == nullptr) {
    return false;
  }
  return unit->PrepareMove(moveFlags, inOutPos, outSkirtRect, useWholeMap);
}
namespace moho
{
  [[nodiscard]] bool PrepareMove(
    int moveFlags,
    Unit* unit,
    Wm3::Vector3f* inOutPos,
    gpg::Rect2f* outSkirtRect,
    bool useWholeMap
  )
  {
    return ::PrepareMove(moveFlags, unit, inOutPos, outSkirtRect, useWholeMap);
  }
}



/**
 * Address: 0x0062BEE0 (FUN_0062BEE0, Moho::Unit::HasMeleeSpaceAroundSmallTarget)
 *
 * What it does:
 * Scans perimeter candidate cells around `target` using this unit footprint,
 * filters by occupancy/pathability checks, and writes nearest valid melee
 * destination into `inOutCell`.
 */
bool Unit::HasMeleeSpaceAroundSmallTarget(Unit* const target, SOCellPos* const inOutCell)
{
  if (target == nullptr || inOutCell == nullptr) {
    return false;
  }

  Sim* const sim = SimulationRef;
  if (sim == nullptr || sim->mOGrid == nullptr || sim->mMapData == nullptr) {
    return false;
  }

  COGrid& ogrid = *sim->mOGrid;
  const STIMap& mapData = *sim->mMapData;

  const SFootprint& moverFootprint = GetFootprint();
  const SFootprint& targetFootprint = target->GetFootprint();
  const ELayer moveLayer = mVarDat.mLayerMask;
  const bool useWholeMap = (ArmyRef != nullptr) ? ArmyRef->UseWholeMap() : false;
  const float mapBorder = static_cast<float>(FootprintMaxSide(moverFootprint));

  const int minX = static_cast<int>(inOutCell->x) - static_cast<int>(moverFootprint.mSizeX);
  const int maxX = static_cast<int>(inOutCell->x) + static_cast<int>(targetFootprint.mSizeX);
  const int minZ = static_cast<int>(inOutCell->z) - static_cast<int>(moverFootprint.mSizeZ);
  const int maxZ = static_cast<int>(inOutCell->z) + static_cast<int>(targetFootprint.mSizeZ);
  if (minZ > maxZ) {
    return false;
  }

  const float moverHalfSizeX = static_cast<float>(moverFootprint.mSizeX) * 0.5f;
  const float moverHalfSizeZ = static_cast<float>(moverFootprint.mSizeZ) * 0.5f;

  bool found = false;
  float bestDistanceSq = gpg::pInf;
  SOCellPos bestCell = *inOutCell;

  for (int z = minZ; z <= maxZ; ++z) {
    int stepX = ((z == minZ) || (z == maxZ)) ? 1 : (maxX - minX);
    if (stepX <= 0) {
      stepX = 1;
    }

    for (int x = minX; x <= maxX; x += stepX) {
      const SOCellPos candidateCell{static_cast<std::int16_t>(x), static_cast<std::int16_t>(z)};
      const Wm3::Vec3f candidateWorldPos{
        static_cast<float>(x) + moverHalfSizeX,
        0.0f,
        static_cast<float>(z) + moverHalfSizeZ,
      };

      if (!mapData.IsWithin(candidateWorldPos, mapBorder, useWholeMap)) {
        continue;
      }

      if (!IsMeleeCandidateCellNavigable(*this, target, moverFootprint, moveLayer, ogrid, mapData, candidateCell)) {
        continue;
      }

      const Wm3::Vec3f unitPos = GetPosition();
      const float deltaX = candidateWorldPos.x - unitPos.x;
      const float deltaZ = candidateWorldPos.z - unitPos.z;
      const float distanceSq = (deltaX * deltaX) + (deltaZ * deltaZ);
      if (distanceSq < bestDistanceSq) {
        bestDistanceSq = distanceSq;
        bestCell = candidateCell;
        found = true;
      }
    }
  }

  if (!found) {
    return false;
  }

  *inOutCell = bestCell;
  return true;
}

/**
 * Address: 0x0062C340 (FUN_0062C340, Moho::Unit::HasMeleeSpaceAroundLargeTarget)
 *
 * What it does:
 * Scans a collision-bounds search window around `target`, applies shell
 * collision probes plus occupancy/pathability checks, and writes nearest
 * valid melee destination into `inOutCell`.
 */
bool Unit::HasMeleeSpaceAroundLargeTarget(Unit* const target, SOCellPos* const inOutCell, const int targetSize)
{
  if (target == nullptr || inOutCell == nullptr) {
    return false;
  }

  Sim* const sim = SimulationRef;
  if (sim == nullptr || sim->mOGrid == nullptr || sim->mMapData == nullptr) {
    return false;
  }

  CColPrimitiveBase* const targetCollisionShape = target->CollisionExtents;
  if (targetCollisionShape == nullptr) {
    return false;
  }

  COGrid& ogrid = *sim->mOGrid;
  const STIMap& mapData = *sim->mMapData;

  const SFootprint& moverFootprint = GetFootprint();
  const ELayer moveLayer = mVarDat.mLayerMask;
  const bool useWholeMap = (ArmyRef != nullptr) ? ArmyRef->UseWholeMap() : false;
  const float mapBorder = static_cast<float>(FootprintMaxSide(moverFootprint));

  const float innerHalfExtentX = static_cast<float>(targetSize + static_cast<int>(moverFootprint.mSizeX)) * 0.5f;
  const float innerHalfExtentZ = static_cast<float>(targetSize + static_cast<int>(moverFootprint.mSizeZ)) * 0.5f;
  const float outerHalfExtentX = innerHalfExtentX + 1.0f;
  const float outerHalfExtentZ = innerHalfExtentZ + 1.0f;

  constexpr float kMeleeProbeHalfHeight = 1000.0f;
  Wm3::Box3f outerProbe = BuildAxisAlignedCollisionProbe(
    Wm3::Vec3f::Zero(),
    Wm3::Vec3f(outerHalfExtentX, kMeleeProbeHalfHeight, outerHalfExtentZ)
  );
  Wm3::Box3f innerProbe = BuildAxisAlignedCollisionProbe(
    Wm3::Vec3f::Zero(),
    Wm3::Vec3f(innerHalfExtentX, kMeleeProbeHalfHeight, innerHalfExtentZ)
  );
  CollisionResult collisionResult{};

  // 0x0062C558..0x0062C5F0: the binary's inlined floor and ceil.
  const int minX = fa::FloorToIntX87(target->mAABox.Min.x) - static_cast<int>(moverFootprint.mSizeX);
  const int maxX = fa::CeilToIntX87(target->mAABox.Max.x) + 1;
  const int minZ = fa::FloorToIntX87(target->mAABox.Min.z) - static_cast<int>(moverFootprint.mSizeZ);
  const int maxZ = fa::CeilToIntX87(target->mAABox.Max.z) + 1;
  if (minZ > maxZ) {
    return false;
  }

  const float moverHalfSizeX = static_cast<float>(moverFootprint.mSizeX) * 0.5f;
  const float moverHalfSizeZ = static_cast<float>(moverFootprint.mSizeZ) * 0.5f;

  bool found = false;
  float bestDistanceSq = gpg::pInf;
  SOCellPos bestCell = *inOutCell;

  for (int z = minZ; z <= maxZ; ++z) {
    for (int x = minX; x <= maxX; ++x) {
      const SOCellPos candidateCell{static_cast<std::int16_t>(x), static_cast<std::int16_t>(z)};
      const Wm3::Vec3f candidateWorldPos{
        static_cast<float>(x) + moverHalfSizeX,
        0.0f,
        static_cast<float>(z) + moverHalfSizeZ,
      };

      if (!mapData.IsWithin(candidateWorldPos, mapBorder, useWholeMap)) {
        continue;
      }

      outerProbe.Center[0] = candidateWorldPos.x;
      outerProbe.Center[1] = candidateWorldPos.y;
      outerProbe.Center[2] = candidateWorldPos.z;
      if (!targetCollisionShape->CollideBox(&outerProbe, &collisionResult)) {
        continue;
      }

      innerProbe.Center[0] = candidateWorldPos.x;
      innerProbe.Center[1] = candidateWorldPos.y;
      innerProbe.Center[2] = candidateWorldPos.z;
      if (targetCollisionShape->CollideBox(&innerProbe, &collisionResult)) {
        continue;
      }

      if (!IsMeleeCandidateCellNavigable(*this, target, moverFootprint, moveLayer, ogrid, mapData, candidateCell)) {
        continue;
      }

      const Wm3::Vec3f unitPos = GetPosition();
      const float deltaX = candidateWorldPos.x - unitPos.x;
      const float deltaZ = candidateWorldPos.z - unitPos.z;
      const float distanceSq = (deltaX * deltaX) + (deltaZ * deltaZ);
      if (distanceSq < bestDistanceSq) {
        bestDistanceSq = distanceSq;
        bestCell = candidateCell;
        found = true;
      }
    }
  }

  if (!found) {
    return false;
  }

  *inOutCell = bestCell;
  return true;
}

/**
 * Address: 0x006A7770 (FUN_006A7770, ?ExecuteOccupyGround@Unit@Moho@@QAEXXZ)
 *
 * What it does:
 * Applies blueprint occupy-rect lanes (or footprint fallback rect) into
 * O-grid terrain/water occupancy masks and dirties path clusters.
 */
void Unit::ExecuteOccupyGround()
{
  const SFootprint& footprint = GetFootprint();
  const RUnitBlueprint* const blueprint = GetBlueprint();
  COGrid* const ogrid = SimulationRef ? SimulationRef->mOGrid : nullptr;
  if (ogrid == nullptr) {
    return;
  }
  const EOccupancyCaps occupancyCaps = footprint.mOccupancyCaps;


  const auto& occupyRects = blueprint->Physics.OccupyRects;
  if (occupyRects.empty()) {
    const Wm3::Vec3f& unitPos = GetPosition();
    const SOCellPos origin{
      static_cast<std::int16_t>(std::lrintf(unitPos.x - static_cast<float>(footprint.mSizeX) * 0.5f)),
      static_cast<std::int16_t>(std::lrintf(unitPos.z - static_cast<float>(footprint.mSizeZ) * 0.5f)),
    };
    ogrid->ExecuteOccupy(origin, footprint);
    return;
  }

  const Wm3::Vec3f& unitPos = GetPosition();
  for (const RUnitBlueprintOccupyRect& occupyRect : occupyRects) {
    gpg::Rect2i rect{};
    // 0x006A7819-0x006A78FC: min edges are `(center + pos) - half`, max edges
    // `(pos + half) + center` -- the add order differs between the two.
    rect.x0 = RoundOccupyRectEdge((occupyRect.CenterOffsetX + unitPos.x) - occupyRect.HalfSizeX);
    rect.x1 = RoundOccupyRectEdge((unitPos.x + occupyRect.HalfSizeX) + occupyRect.CenterOffsetX);
    rect.z0 = RoundOccupyRectEdge((unitPos.z + occupyRect.CenterOffsetZ) - occupyRect.HalfSizeZ);
    rect.z1 = RoundOccupyRectEdge((unitPos.z + occupyRect.HalfSizeZ) + occupyRect.CenterOffsetZ);
    ogrid->ExecuteOccupy(occupancyCaps, rect);
  }
}

/**
 * Address: 0x006A7AB0 (FUN_006A7AB0, Moho::Unit::ReleaseOccupyGround)
 *
 * What it does:
 * Clears the occupied-ground lane previously applied by `ExecuteOccupyGround`
 * and releases the matching footprint rectangle from the sim O-grid.
 */
void Unit::ReleaseOccupyGround()
{
  if (!FootprintDown) {
    return;
  }

  // 0x006A7AC9-0x006A7AF7: the blueprint's main footprint (`bp+0xD8`), not
  // `GetFootprint()` -- the alternate footprint is never consulted here.
  const SFootprint& footprint = GetBlueprint()->mFootprint;
  const Wm3::Vec3f& unitPos = GetPosition();
  const SOCellPos origin{
    static_cast<std::int16_t>(std::lrintf(unitPos.x - static_cast<float>(footprint.mSizeX) * 0.5f)),
    static_cast<std::int16_t>(std::lrintf(unitPos.z - static_cast<float>(footprint.mSizeZ) * 0.5f)),
  };

  if (SimulationRef != nullptr && SimulationRef->mOGrid != nullptr) {
    SimulationRef->mOGrid->ReleaseOccupy(origin, footprint);
  }

  FootprintDown = false;
}

/**
 * Address: 0x006AB6F0 (FUN_006AB6F0, ?ReserveOgridRect@Unit@Moho@@QAEXABV?$Rect2@H@gpg@@@Z)
 */
void Unit::ReserveOgridRect(const gpg::Rect2i& ogridRect)
{
  FreeOgridRect();

  ReservedOgridRectMinX = ogridRect.x0;
  ReservedOgridRectMinZ = ogridRect.z0;
  ReservedOgridRectMaxX = ogridRect.x1;
  ReservedOgridRectMaxZ = ogridRect.z1;

  FillReservedOgridRect(*this, true);
}

/**
 * Address: 0x006AB760 (FUN_006AB760, ?FreeOgridRect@Unit@Moho@@QAEXXZ)
 */
void Unit::FreeOgridRect()
{
  // 0x006AB7C9: `je` past both the vacate and the zeroing when the reserved
  // rect quantises to the zero collision rect -- the stored bounds are left
  // untouched in that case.
  const gpg::Rect2i reservedRect = GetReservedOgridRect(*this);
  if (IsCollisionRectEquivalentToZero(reservedRect)) {
    return;
  }

  FillReservedOgridRect(*this, false);

  ReservedOgridRectMinX = 0;
  ReservedOgridRectMinZ = 0;
  ReservedOgridRectMaxX = 0;
  ReservedOgridRectMaxZ = 0;
}

/**
 * Address: 0x006AB810 (FUN_006AB810, ?CanReserveOgridRect@Unit@Moho@@QAE_NABV?$Rect2@H@gpg@@@Z)
 */
bool Unit::CanReserveOgridRect(const gpg::Rect2i& ogridRect)
{
  const gpg::Rect2i reservedRect = GetReservedOgridRect(*this);
  const bool hadReservation = !IsCollisionRectEquivalentToZero(reservedRect);
  if (hadReservation) {
    FillReservedOgridRect(*this, false);
  }

  bool canReserve = true;
  if (SimulationRef && SimulationRef->mOGrid) {
    canReserve = !SimulationRef->mOGrid->IsRectOccupied(ogridRect);
  }

  if (hadReservation) {
    FillReservedOgridRect(*this, true);
  }

  return canReserve;
}

// 0x006A4990
UnitAttributes& Unit::GetAttributes()
{
  return mUnitVarDat.mAttributes;
}

// 0x006A4980
UnitAttributes const& Unit::GetAttributes() const
{
  return mUnitVarDat.mAttributes;
}

// 0x006A4B90
