// Part of Unit.cpp, included there: busy, navigator and guard state.

/**
 * Address: 0x006A7D10 (FUN_006A7D10, Moho::Unit::IsBusy)
 *
 * What it does:
 * Reports whether the unit currently has active navigation movement or
 * builder-side busy state.
 */
bool Unit::IsBusy() const
{
  const IAiNavigator* const navigator = AiNavigator;
  if (!navigator || !IsMobile() || navigator->GetStatus() == AINAVSTATUS_Idle) {
    const IAiBuilder* const builder = AiBuilder;
    if (builder == nullptr || !builder->BuilderIsBusy()) {
      return false;
    }
  }

  return true;
}

/**
 * Address: 0x005F0E80 (FUN_005F0E80, Moho::Unit::NeedsPickup)
 *
 * What it does:
 * Estimates whether assisting `task->mUnit` should switch to pickup by
 * comparing this unit's goal ETA against assisted-unit interception ETA.
 */
bool Unit::NeedsPickup(const CUnitAssistMoveTask* const task) const
{
  if (IsUnitState(UNITSTATE_ProblemGettingToGoal)) {
    return true;
  }

  const Unit* const assistedUnit = task ? task->mUnit : nullptr;
  if (assistedUnit == nullptr) {
    return false;
  }

  const RUnitBlueprint* const assistedBlueprint = assistedUnit->GetBlueprint();
  const float assistedMaxSpeed =
    (assistedBlueprint->Air.CanFly != 0u) ? assistedBlueprint->Air.MaxAirspeed : assistedBlueprint->Physics.MaxSpeed;
  if (assistedMaxSpeed < 0.001f) {
    return false;
  }

  const RUnitBlueprint* const selfBlueprint = GetBlueprint();
  const float selfMaxSpeed = (selfBlueprint->Air.CanFly != 0u) ? selfBlueprint->Air.MaxAirspeed : selfBlueprint->Physics.MaxSpeed;
  if (selfMaxSpeed < 0.001f) {
    return false;
  }

  const IAiNavigator* const navigator = AiNavigator;
  if (navigator == nullptr) {
    return false;
  }

  const Wm3::Vec3f& selfPosition = GetPosition();
  const Wm3::Vector3f goalPosition = navigator->GetGoalPos();
  const float goalDx = goalPosition.x - selfPosition.x;
  const float goalDz = goalPosition.z - selfPosition.z;
  const float goalDistance = std::sqrt((goalDz * goalDz) + (goalDx * goalDx));
  // 0x005F0F79-0x005F0F92: `1.0f / selfSpeed` is formed once and multiplied
  // in -- here and again in the near-pickup branch below (0x005F1018).
  const float selfInvSpeed = 1.0f / selfMaxSpeed;
  const float goalTime = selfInvSpeed * goalDistance;

  const Wm3::Vec3f& assistedPosition = assistedUnit->GetPosition();
  const float taskDx = assistedPosition.x - selfPosition.x;
  const float taskDz = assistedPosition.z - selfPosition.z;
  const float taskDistance = std::sqrt((taskDx * taskDx) + (taskDz * taskDz));

  // 0x005F0FE0-0x005F0FFF: x87 `fadd`/`fdiv`/`fadd 5.0` under the sim
  // thread's `_PC_24` control word, i.e. single-precision rounding per step.
  float pickupEta = ((taskDistance + goalDistance) / assistedMaxSpeed) + 5.0f;
  if (assistedUnit->mVarDat.mLayerMask == LAYER_Air || taskDistance > selfBlueprint->AI.GuardScanRadius) {
    pickupEta += 4.0f;
  } else {
    pickupEta = (selfInvSpeed * taskDistance) + pickupEta;
  }

  return goalTime > pickupEta;
}

/**
 * Address: 0x006A7D60 (FUN_006A7D60, ?IsIdleState@Unit@Moho@@QBE_NXZ)
 *
 * What it does:
 * Returns true when the command queue has no valid head command.
 */
bool Unit::IsIdleState() const
{
  const CUnitCommandQueue* const commandQueue = CommandQueue;
  if (commandQueue == nullptr || commandQueue->mCommandVec.empty()) {
    return true;
  }

  const CUnitCommand* const headCommand = commandQueue->mCommandVec.front().GetObjectPtr();
  return headCommand == nullptr;
}

/**
 * Address: 0x0062F030 (FUN_0062F030, Moho::Unit::FindPlatform)
 *
 * IDA signature:
 * Moho::Unit* __usercall FindPlatform@<eax>(Moho::Unit* this@<ecx>, int @<ebx>);
 *
 * What it does:
 * For an air unit needing refuel/repair (and not its own formation lead),
 * scans the owning army's AIRSTAGINGPLATFORM units for the first idle,
 * in-bounds transport within staging-platform scan radius that can receive
 * this unit. Returns that platform, or null.
 */
Unit* Unit::FindPlatform()
{
  // Guard: alive flying unit, fueled (or no motor), with the refuel-order cap.
  if (IsDead()) {
    return nullptr;
  }
  if (!GetBlueprint()->Air.CanFly) {
    return nullptr;
  }
  if (UnitMotion != nullptr && mUnitVarDat.mFuelRatio < 0.0f) {
    return nullptr;
  }
  if ((GetAttributes().commandCapsMask & 0x400000u) == 0u) {
    return nullptr;
  }

  // Skip if this unit is its own formation lead.
  if (IUnit* const formationLead = mInfoCache.mFormationLeadRef.GetObjectPtr();
      formationLead != nullptr && formationLead->IsUnit() == this) {
    return nullptr;
  }

  // Need refuel: threshold ratio exceeds current fuel ratio.
  const float fuelRatio = mUnitVarDat.mFuelRatio;
  bool needsService = false;
  if (CSimConVarBase* const needRefuelDef = &moho::gSimConVar_NeedRefuelThresholdRatio;
      needRefuelDef != nullptr) {
    if (CSimConVarInstanceBase* const needRefuel = SimulationRef->GetSimVar(needRefuelDef);
        needRefuel != nullptr) {
      needsService = *static_cast<const float*>(needRefuel->GetValueStorage()) > fuelRatio;
    }
  }
  // Need repair: threshold ratio exceeds the health fraction. 0x0062F10F
  // loads health (+0x98) and 0x0062F14A divides it by max health (+0x9C).
  if (!needsService) {
    const float health = mVarDat.mHealth;
    const float maxHealth = mVarDat.mMaxHealth;
    if (CSimConVarBase* const needRepairDef = &moho::gSimConVar_NeedRepairThresholdRatio;
        needRepairDef != nullptr) {
      if (CSimConVarInstanceBase* const needRepair = SimulationRef->GetSimVar(needRepairDef);
          needRepair != nullptr) {
        needsService = *static_cast<const float*>(needRepair->GetValueStorage()) > (health / maxHealth);
      }
    }
  }
  if (!needsService) {
    return nullptr;
  }

  RRuleGameRules* const rules = SimulationRef->mRules;
  const EntityCategorySet* const stagingPlatformCategory = rules->GetEntityCategory("AIRSTAGINGPLATFORM");
  const EntityCategorySet* const carrierCategory = rules->GetEntityCategory("CARRIER");

  EntitySetTemplate<Entity> stagingPlatforms;
  ArmyRef->GetUnits(&stagingPlatforms, const_cast<EntityCategorySet*>(stagingPlatformCategory));

  for (Entity* const platformEntity : stagingPlatforms) {
    if (platformEntity == nullptr) {
      continue;
    }
    Unit* const platform = static_cast<Unit*>(platformEntity);
    if (platform->IsDead() || platform->IsBeingBuilt() || platform->DestroyQueued()) {
      continue;
    }
    IAiTransport* const transport = platform->AiTransport;
    if (transport == nullptr) {
      continue;
    }

    const Wm3::Vec3f& platformPos = platform->GetPosition();
    const Wm3::Vec3f& selfPos = GetPosition();
    const float dz = selfPos.z - platformPos.z;
    const float dx = selfPos.x - platformPos.x;
    const float distance = std::sqrt(dz * dz + dx * dx);
    if (distance > platform->GetBlueprint()->AI.StagingPlatformScanRadius) {
      continue;
    }
    if (!platform->IsInBounds(ArmyRef->UseWholeMap(), 1.0f)) {
      continue;
    }
    if (!platform->IsIdleState()) {
      continue;
    }
    const ELayer platformLayer = platform->mVarDat.mLayerMask;
    if (platformLayer == LAYER_Seabed || platformLayer == LAYER_Sub) {
      continue;
    }

    if (EntityCategory::HasBlueprint(platform->GetBlueprint(), carrierCategory)) {
      if (transport->TransportHasAvailableStorage()) {
        return platform;
      }
    } else if (transport->TransportHasSpaceFor(GetBlueprint())) {
      return platform;
    }
  }

  return nullptr;
}

/**
 * Address: 0x006AC940 (FUN_006AC940, ?UpdateSpeedThroughStatus@Unit@Moho@@QAEXXZ)
 *
 * What it does:
 * Recomputes whether pathing should use speed-through-goal mode for this unit
 * from command queue state, formation leader weak-link ownership, and escort
 * movement heuristics.
 */
void Unit::UpdateSpeedThroughStatus()
{
  if (IsBeingBuilt() || IsDead() || DestroyQueued()) {
    return;
  }

  CUnitCommandQueue* const commandQueue = CommandQueue;
  IAiNavigator* const navigator = AiNavigator;
  if (commandQueue == nullptr || navigator == nullptr) {
    return;
  }

  CUnitCommand* const currentCommand = commandQueue->GetCurrentCommand();
  CUnitCommand* const nextCommand = commandQueue->GetNextCommand();

  if (IsUnitState(UNITSTATE_Refueling)) {
    navigator->SetSpeedThroughGoal(false);
    return;
  }

  bool enableSpeedThrough = false;
  if (IsUnitState(UNITSTATE_ForceSpeedThrough) || IsUnitState(UNITSTATE_CannotFindPlaceToLand)) {
    enableSpeedThrough = true;
  } else {
    bool isAirEscort = false;
    const RUnitBlueprint* const blueprint = GetBlueprint();
    if (blueprint->Air.CanFly && IsUnitState(UNITSTATE_Guarding) && !IsUnitState(UNITSTATE_Ferrying)) {
      if (!IsInCategory("EXPERIMENTAL")) {
        isAirEscort = true;
      }
    }

    if (isAirEscort) {
      enableSpeedThrough = true;
    } else if (
      currentCommand != nullptr
      && nextCommand != nullptr
      && nextCommand->GetCoordinatingOrdersSnapshot().empty()
    ) {
      if (IsSpeedThroughBusyCommandType(currentCommand->mVarDat.mCmdType)
          && IsSpeedThroughBusyCommandType(nextCommand->mVarDat.mCmdType) && !IsUnitState(UNITSTATE_AssistMoving)) {
        const Unit* const formationLead = mInfoCache.mFormationLeadRef.GetObjectPtr();
        if (formationLead == nullptr || formationLead == this) {
          enableSpeedThrough = true;
        }
      }
    }
  }

  navigator->SetSpeedThroughGoal(enableSpeedThrough);
}

/**
 * Address: 0x006AA310 (FUN_006AA310, ?Warp@Unit@Moho@@UAEXVVTransform@2@@Z)
 *
 * What it does:
 * Recomputes spawn elevation/layer for the incoming transform, warps through
 * motion component when present, then refreshes entity layer and terrain type.
 */
void Unit::Warp(const VTransform& transform)
{
  VTransform warpedTransform = transform;
  const ELayer startingLayer = GetStartingLayer(warpedTransform.pos_, LAYER_None);

  const Sim* const sim = SimulationRef;
  const STIMap* const mapData = sim ? sim->mMapData : nullptr;
  warpedTransform.pos_.y = IUnit::CalcSpawnElevation(mapData, startingLayer, warpedTransform, mUnitVarDat.mAttributes);

  if (UnitMotion != nullptr) {
    UnitMotion->Warp(warpedTransform);
    if (AiNavigator != nullptr) {
      AiNavigator->AbortMove();
    }
  } else {
    Entity::Warp(warpedTransform);
  }

  SetCurrentLayer(startingLayer);
  // 0x006AA428: `call Unit::UpdateTerrainType` (0x006A9B50) on the
  // elevation-adjusted warp position.
  UpdateTerrainType(warpedTransform.pos_);
}

// 0x006A7DC0
bool Unit::IsNavigatorIdle() const
{
  return !AiNavigator || AiNavigator->GetStatus() == 0;
}

// 0x006A4AF0
bool Unit::IsUnitState(const EUnitState state) const
{
  const std::uint32_t bit = static_cast<std::uint32_t>(state);
  if (bit >= 64u) {
    return false;
  }
  return (mUnitVarDat.mUnitStates & (1ull << bit)) != 0ull;
}

/**
 * Address: 0x0059A430 (FUN_0059A430, ?GetGuardedUnit@Unit@Moho@@QBEPAV12@XZ)
 */
Unit* Unit::GetGuardedUnit() const
{
  return GuardedUnitRef.GetObjectPtr();
}

/**
 * Address: 0x006AD060 (FUN_006AD060,
 *   ?GetBlipsInRange@Unit@Moho@@QAEAAV?$fastvector_n@V?$WeakPtr@VEntity@Moho@@@Moho@@$0BE@@gpg@@I@Z)
 *
 * IDA signature:
 * gpg::fastvector_n20_WeakPtr_Entity *__userpurge GetBlipsInRange@<eax>(
 *   Moho::Unit *this@<esi>, unsigned int interval);
 *
 * What it does:
 * Refreshes `mBlipsInRange` via `UpdateBlipsInRange()` when it is at least
 * `maxAgeTicks` ticks stale (current sim tick minus the last update tick, as an
 * unsigned compare), then returns a reference to the cached list.
 */
gpg::core::FastVectorN<WeakPtr<Entity>, 20>& Unit::GetBlipsInRange(const unsigned int maxAgeTicks)
{
  const unsigned int ticksSinceUpdate =
    SimulationRef->mCurTick - static_cast<unsigned int>(mBlipLastUpdateTick);
  if (ticksSinceUpdate >= maxAgeTicks) {
    UpdateBlipsInRange();
  }
  return mBlipsInRange;
}

/**
 * Address: 0x006ACC60 (FUN_006ACC60, ?UpdateBlipsInRange@Unit@Moho@@QAEXXZ)
 *
 * IDA signature:
 * void __stdcall Moho::Unit::UpdateBlipsInRange(Moho::Unit *this);
 *
 * What it does:
 * Rebuilds `mBlipsInRange` (see the field-by-field walk in the header). Computes
 * the effective scan radius (guard-scan blueprint radius when the head command is
 * a guard/patrol command, extended by the attacker's max weapon range), gathers
 * enemy units in that radius via `COGrid::EntitiesAroundPoint`, keeps those the
 * army can see as recon blips and (when set) within the army no-rush radius,
 * records a weak reference to each, and additionally records the jamming-shadow
 * blips of any candidate whose intel manager has active jamming. Finally stamps
 * `mBlipLastUpdateTick` with the current sim tick.
 */
void Unit::UpdateBlipsInRange()
{
  const RUnitBlueprint* const blueprint = GetBlueprint();
  CAiAttackerImpl* const attacker = AiAttacker;

  // Guard-scan radius: zero unless the head command passes FAF's patched gate.
  //
  // That gate (0x0128F2B6, jumped to from 0x006ACC95) loads the head of the
  // command queue's weak-pointer vector -- the pointer is the command's weak
  // link slot at `command+4` -- and tests `[slot+94h] & 30h`, i.e. the
  // command's `mCmdType` at `+0x98`.
  float scanRadius = 0.0f;
  CUnitCommand* const headCommand = CommandQueue->GetCurrentCommand();
  if (headCommand != nullptr && (static_cast<std::uint32_t>(headCommand->mVarDat.mCmdType) & 0x30u) != 0u) {
    scanRadius = blueprint->AI.GuardScanRadius;
  }

  // Extend the scan radius by the attacker's max weapon range.
  if (attacker != nullptr) {
    const float maxWeaponRange = attacker->GetMaxWeaponRange();
    if (maxWeaponRange > scanRadius) {
      scanRadius = maxWeaponRange;
    }
  }

  // No-rush centre = army start position + configured no-rush offset; used to
  // reject blips outside the no-rush radius while the no-rush timer is active.
  CArmyImpl* const army = ArmyRef;
  const float noRushOffsetX = army->mVarDat.mNoRushOffset.x;
  const float noRushOffsetY = army->mVarDat.mNoRushOffset.y;
  Wm3::Vector2f armyStartPosition{};
  army->GetArmyStartPos(armyStartPosition);
  const float noRushCenterX = armyStartPosition.x + noRushOffsetX;
  const float noRushCenterZ = armyStartPosition.y + noRushOffsetY;
  const float noRushRadius = army->mVarDat.mNoRushRadius;

  // Gather every unit within the scan radius of this unit's position.
  gpg::core::FastVectorN<CollisionResult, 10> unitsInRange{};
  COGrid* const grid = SimulationRef->mOGrid;
  EntitiesAroundPoint(unitsInRange, scanRadius, *grid, ENTITYTYPE_Unit, GetPosition());

  // Reset the blip list: unlink every currently-held weak reference from its
  // owner chain, release escaped heap storage, and rebind to inline storage.
  // Engine addition (sim_DeferBlipUnlinks): a heap block's unlinks wait for the
  // next tick and run in bulk; see `DeferredBlipUnlinks`.
  if (sim_DeferBlipUnlinks) {
    BlipListUnlinks().Adopt(mBlipsInRange, SimulationRef->mCurTick);
  } else {
    BlipListUnlinks().Flush();
    mBlipsInRange.ResetStorageToInline();
  }

  for (const CollisionResult& hit : unitsInRange) {
    Entity* const candidate = hit.sourceEntity;
    if (candidate == nullptr || candidate->mVarDat.mIsDead != 0u) {
      continue;
    }

    Unit* const candidateUnit = candidate->IsUnit();
    if (candidateUnit == nullptr || candidate->DestroyQueuedFlag != 0u) {
      continue;
    }

    CArmyImpl* const candidateArmy = candidate->ArmyRef;
    const std::uint32_t candidateArmyIndex =
      (candidateArmy != nullptr) ? static_cast<std::uint32_t>(candidateArmy->mConstDat.mArmyIndex) : 0xFFFFFFFFu;
    // IArmy::IsAlly (FUN_005BD630) is shadowed on CArmyImpl by the same-named
    // cached byte field (+0x128); its body is the allies bit-set membership
    // test, replicated here via the shared `Set::Contains` helper.
    if (army->mVarDat.mAllies.Contains(candidateArmyIndex)) {
      continue;
    }

    CAiReconDBImpl* const reconDb = army->GetReconDB();
    ReconBlip* const blip = (reconDb != nullptr) ? reconDb->ReconGetBlip(candidateUnit) : nullptr;
    if (blip == nullptr) {
      continue;
    }

    if (army->mVarDat.mNoRushTimer > 0) {
      const float deltaX = noRushCenterX - candidate->mVarDat.mCurTransform.pos_.x;
      const float deltaZ = noRushCenterZ - candidate->mVarDat.mCurTransform.pos_.z;
      const float distance = std::sqrt((deltaX * deltaX) + (deltaZ * deltaZ));
      if (distance > noRushRadius) {
        continue;
      }
    }

    // Record a weak reference to the visible enemy.
    mBlipsInRange.push_back(WeakPtr<Entity>(candidate));

    // When the candidate is actively jamming, also record its shadow blips.
    if (candidateUnit->mIntelManager->HasActiveJamming()) {
      EntitySetTemplate<Entity> jammingBlips = army->GetReconDB()->ReconGetJamingBlips(candidateUnit);
      for (Entity* const jammingEntity : jammingBlips) {
        mBlipsInRange.push_back(WeakPtr<Entity>(jammingEntity));
      }
    }
  }

  mBlipLastUpdateTick = static_cast<std::int32_t>(SimulationRef->mCurTick);
}

/**
 * Address: 0x006A76A0 (FUN_006A76A0, Moho::Unit::SetGuardedUnit)
 *
 * What it does:
 * Rebinds guarded-unit weak-link ownership, updates guarded-by slot lanes on
 * old/new guarded units, clears stale guard-formation lanes, and marks this
 * unit sync-dirty.
 */
void Unit::SetGuardedUnit(Unit* const guarded)
{
  Unit* const oldGuardedUnit = GuardedUnitRef.GetObjectPtr();
  if (oldGuardedUnit != nullptr) {
    (void)oldGuardedUnit->GuardedByList.Remove(this); // 0x005E8960
    ClearGuardFormation(oldGuardedUnit);
  }

  GuardedUnitRef.Set(guarded);

  Unit* const newGuardedUnit = GuardedUnitRef.GetObjectPtr();
  if (newGuardedUnit != nullptr) {
    (void)newGuardedUnit->GuardedByList.Add(this); // 0x0057DDD0
    ClearGuardFormation(newGuardedUnit);
  }

  NeedSyncGameData = true;
}

/**
 * Address: 0x006AA720 (FUN_006AA720, ?RemoveGuardedByUnit@Unit@Moho@@AAEXPAV12@@Z)
 * Mangled: ?RemoveGuardedByUnit@Unit@Moho@@AAEXPAV12@@Z
 *
 * What it does:
 * Inserts one guarding owner into this unit's guarded-by list when non-null,
 * then clears this unit's guard-formation lane.
 */
void Unit::RemoveGuardedByUnit(Unit* const guardedByUnit)
{
  if (guardedByUnit != nullptr) {
    (void)GuardedByList.Add(guardedByUnit); // 0x0057DDD0
  }

  ClearGuardFormation(this);
}

/**
 * Address: 0x00585B10 (FUN_00585B10, Moho::Unit::GetFocusEntity)
 */
Entity* Unit::GetFocusEntity() const
{
  return FocusEntityRef.GetObjectPtr();
}

/**
 * Address: 0x0062EE00 (FUN_0062EE00, Moho::Unit::GetStagingPlatform)
 */
Unit* Unit::GetStagingPlatform() const
{
  Unit* const transport = TransportedByRef.GetObjectPtr();
  if (transport == nullptr) {
    return nullptr;
  }

  if (transport->IsDead()) {
    return nullptr;
  }

  IAiTransport* const aiTransport = transport->AiTransport;
  if (aiTransport == nullptr || !aiTransport->TransportIsAirStagingPlatform()) {
    return nullptr;
  }

  return transport;
}

/**
 * Address: 0x005E3C30 (FUN_005E3C30, Moho::Unit::GetTransportedBy)
 */
Unit* Unit::GetTransportedBy() const
{
  return TransportedByRef.GetObjectPtr();
}

/**
 * Address: 0x005F0980 (FUN_005F0980, Moho::Unit::GetFerryUnit)
 *
 * IDA signature:
 * Moho::Unit *__usercall Moho::Unit::GetFerryUnit@<eax>(Moho::Unit *a1@<eax>);
 *
 * What it does:
 * Returns the unit currently bound to this unit's assigned-transport weak
 * lane (Unit +0x4C8). Identical accessor body to the binary's tiny FUN_005F0980
 * thunk: load the slot, return owner-decoded pointer or null on sentinel.
 */
Unit* Unit::GetFerryUnit() const
{
  return AssignedTransportRef.GetObjectPtr();
}

/**
 * Address: 0x0060DAD0 (FUN_0060DAD0, Moho::Unit::SetAssignedTransport)
 *
 * What it does:
 * Rebinds this unit's assigned-transport weak-reference lane.
 */
void Unit::SetAssignedTransport(Unit* const assignedTransport)
{
  AssignedTransportRef.Set(assignedTransport);
}

/**
 * Address: 0x006A8890 (FUN_006A8890, Moho::Unit::GetTransportFerryBeacon)
 *
 * What it does:
 * Returns ferry-beacon unit ownership from the current command-queue head
 * command when the weak unit lane resolves to a live unit.
 */
Unit* Unit::GetTransportFerryBeacon() const
{
  const CUnitCommandQueue* const commandQueue = CommandQueue;
  if (commandQueue == nullptr || commandQueue->mCommandVec.empty()) {
    return nullptr;
  }

  const CUnitCommand* const command = commandQueue->mCommandVec.front().GetObjectPtr();
  if (command == nullptr) {
    return nullptr;
  }

  return command->mUnit.GetObjectPtr();
}

/**
 * Address: 0x005F5540 (FUN_005F5540, Moho::Unit::GetCreator)
 *
 * What it does:
 * Resolves `CreatorRef` intrusive weak-link slot to a `Unit*`.
 */
Unit* Unit::GetCreator() const
{
  return CreatorRef.GetObjectPtr();
}

/**
 * Address: 0x0062D2B0 (FUN_0062D2B0, Moho::Unit::OverlapsWith)
 *
 * What it does:
 * Returns true when this unit skirt rectangle overlaps `other` using the
 * original 1.0f edge-contact tolerance checks.
 */
bool Unit::OverlapsWith(Unit* const other) const
{
  if (other == nullptr || IsDead() || other->IsDead()) {
    return false;
  }

  const gpg::Rect2f thisSkirt = GetSkirtRect();
  const gpg::Rect2f otherSkirt = other->GetSkirtRect();

  const float xEdgeDelta0 = std::fabs(thisSkirt.x0 - otherSkirt.x1);
  const float xEdgeDelta1 = std::fabs(thisSkirt.x1 - otherSkirt.x0);
  const bool xEdge0WithinTolerance = xEdgeDelta0 >= 0.0f && xEdgeDelta0 < 1.0f;
  const bool xEdge1WithinTolerance = xEdgeDelta1 >= 0.0f && xEdgeDelta1 < 1.0f;

  if (xEdge0WithinTolerance || xEdge1WithinTolerance) {
    return (thisSkirt.z0 >= otherSkirt.z0 && otherSkirt.z1 >= thisSkirt.z1) ||
      (otherSkirt.z0 >= thisSkirt.z0 && thisSkirt.z1 >= otherSkirt.z1);
  }

  const float yEdgeDelta0 = std::fabs(thisSkirt.z0 - otherSkirt.z1);
  const float yEdgeDelta1 = std::fabs(thisSkirt.z1 - otherSkirt.z0);
  const bool yEdge0WithinTolerance = yEdgeDelta0 >= 0.0f && yEdgeDelta0 < 1.0f;
  const bool yEdge1WithinTolerance = yEdgeDelta1 >= 0.0f && yEdgeDelta1 < 1.0f;

  if (!(yEdge0WithinTolerance || yEdge1WithinTolerance)) {
    return false;
  }

  return (thisSkirt.x0 >= otherSkirt.x0 && otherSkirt.x1 >= thisSkirt.x1) ||
    (otherSkirt.x0 >= thisSkirt.x0 && thisSkirt.x1 >= otherSkirt.x1);
}
