// Part of Unit.cpp, included there: death and cleanup.

/**
 * Address: 0x006A8090 (FUN_006A8090, ?Kill@Unit@Moho@@UAEXPAVEntity@2@VStrArg@gpg@@M@Z)
 *
 * What it does:
 * Applies unit death gating and teardown, notifies adjacency/transport and
 * script lanes, then updates army/platoon kill-value statistics.
 */
void Unit::Kill(Entity* const instigator, const gpg::StrArg reason, float excessDamageRatio)
{
  if (IsDead()) {
    return;
  }

  const bool scriptAllowsKill = RunScriptUnitBool("CheckCanBeKilled", this);
  if (!scriptAllowsKill && IsWithinPlayableRectOrNotCommander(*this)) {
    return;
  }

  // 0x006A81A2: `or dword ptr [esi+4A4h], 200h`. That is the HIGH state dword,
  // so bit 9 of it is state 32+9 = 41, UNITSTATE_NoCost -- what CArmyImpl's
  // unit-cap walk skips on, so a unit stops counting against the cap the moment
  // it starts dying. Read as a low-dword write it came out as state 9,
  // UNITSTATE_TransportUnloading, which every corpse then carried.
  mUnitVarDat.mUnitStates |= (1ull << static_cast<std::uint32_t>(UNITSTATE_NoCost));

  EntitySetTemplate<Unit> overlappingStructures{};
  if (!IsMobile()) {
    CollectAllOverlapping(&overlappingStructures, this);
    LookForStructureRebuilder();
  }

  if (Unit* const transportOwner = GetTransportedBy(); transportOwner != nullptr) {
    if (transportOwner->AiTransport != nullptr && mAttachInfo.GetAttachTargetEntity() != nullptr) {
      (void)transportOwner->AiTransport->TransportDetachUnit(this);
    }
    TransportedByRef.UnlinkFromOwnerChain();
    excessDamageRatio = 10.0f;
  }

  // 0x006A82BF..0x006A82D7: the half-built test compares 0.5 against the
  // entity build fraction (`this+0xD8`), not the unit's own work progress.
  if (IsBeingBuilt() && mVarDat.mFractionComplete < 0.5f) {
    excessDamageRatio = 10.0f;
  }

  (void)RunScript("SetDead");
  Entity::Kill(nullptr, "", 0.0f);
  mNeedsKillCleanup = true;

  if (!IsMobile() && !IsBeingBuilt()) {
    for (Entity* const entry : overlappingStructures.mVec) {
      Unit* const adjacent = static_cast<Unit*>(entry);
      if (adjacent == nullptr) {
        continue;
      }

      RunScriptUnit("OnNotAdjacentTo", adjacent);
      adjacent->RunScriptUnit("OnNotAdjacentTo", this);
      adjacent->ReserveOgridRect(GetReservedOgridRect(*adjacent));
    }
  }

  if (AiTransport != nullptr) {
    (void)AiTransport->TransportDetachAllUnits(true);
  }

  if (CommandQueue != nullptr) {
    CommandQueue->ClearCommandQueue();
  }

  RunScriptUnitOnKilled(instigator, reason, excessDamageRatio);

  const RUnitBlueprint* const blueprint = GetBlueprint();
  float massValue = (blueprint != nullptr) ? blueprint->Economy.BuildCostMass : 0.0f;
  float energyValue = (blueprint != nullptr) ? blueprint->Economy.BuildCostEnergy : 0.0f;
  if (IsBeingBuilt()) {
    massValue *= mVarDat.mFractionComplete;
    energyValue *= mVarDat.mFractionComplete;
  }

  if (ArmyRef != nullptr) {
    if (CArmyStats* const armyStats = ArmyRef->GetArmyStats(); armyStats != nullptr) {
      if (blueprint != nullptr) {
        IncrementArmyBlueprintFloatStat(armyStats, "Units_Killed", blueprint, 1.0f);
      }
      IncrementArmyIntStatByName(armyStats, "Units_Killed");
      (void)AddArmyStatFloatByName(armyStats, &massValue, "Units_MassValue_Lost");
      (void)AddArmyStatFloatByName(armyStats, &energyValue, "Units_EnergyValue_Lost");
    }

    ESquadClass squadClass = ESquadClass::Unassigned;
    if (CPlatoon* const platoon =
          ArmyRef->GetPlatoonFor(this, &squadClass);
        platoon != nullptr) {
      ++platoon->mLosses;
    }
  }

  CArmyImpl* const instigatorArmy = (instigator != nullptr) ? instigator->ArmyRef : nullptr;
  if (instigatorArmy == nullptr || ArmyRef == nullptr ||
      !ArmyRef->IsEnemy(static_cast<std::uint32_t>(instigatorArmy->mConstDat.mArmyIndex))) {
    return;
  }

  if (Unit* const instigatorUnit = instigator->IsUnit(); instigatorUnit != nullptr && instigatorUnit->ArmyRef != nullptr) {
    ESquadClass instigatorSquadClass = ESquadClass::Unassigned;
    if (CPlatoon* const instigatorPlatoon = instigatorUnit->ArmyRef->GetPlatoonFor(
          instigatorUnit,
          &instigatorSquadClass
        );
        instigatorPlatoon != nullptr) {
      ++instigatorPlatoon->mKills;
    }
  }

  CArmyStats* const enemyArmyStats = instigatorArmy->GetArmyStats();
  if (enemyArmyStats == nullptr) {
    return;
  }

  IncrementArmyIntStatByName(enemyArmyStats, "Enemies_Killed");
  if (blueprint != nullptr) {
    IncrementArmyBlueprintFloatStat(enemyArmyStats, "Enemies_Killed", blueprint, 1.0f);
  }
  (void)AddArmyStatFloatByName(enemyArmyStats, &massValue, "Enemies_MassValue_Destroyed");
  (void)AddArmyStatFloatByName(enemyArmyStats, &energyValue, "Enemies_EnergyValue_Destroyed");

  static const std::string kCommanderCategory = "COMMAND";
  if (Entity::IsInCategory(kCommanderCategory.c_str())) {
    const std::int32_t delta = 1;
    (void)enemyArmyStats->UpdateUnitStat("Enemies_Commanders_Destroyed", &delta);
  }
}

/**
 * Address: 0x006A88D0 (FUN_006A88D0, ?OnDestroy@Unit@Moho@@UAEXXZ)
 *
 * What it does:
 * Dispatches unit destruction-side adjacency/transport cleanup and then
 * forwards to the base entity destroy-dispatch path.
 */
void Unit::OnDestroy()
{
  if (AiAttacker != nullptr) {
    AiAttacker->WeaponsOnDestroy();
  }

  if (FootprintDown) {
    FreeOgridRect();
  }

  if (!IsDead()) {
    if (!IsMobile() && !IsBeingBuilt()) {
      EntitySetTemplate<Unit> adjacentUnits{};
      CollectAllOverlapping(&adjacentUnits, this);
      for (Entity* const entry : adjacentUnits.mVec) {
        Unit* const adjacent = static_cast<Unit*>(entry);
        RunScriptUnit("OnNotAdjacentTo", adjacent);
        adjacent->RunScriptUnit("OnNotAdjacentTo", this);
        adjacent->ReserveOgridRect(GetReservedOgridRect(*adjacent));
      }
    }

    RunScriptUnit("SetDead", this);
    mVarDat.mIsDead = 1u;

    if (Unit* const transportOwner = GetTransportedBy(); transportOwner != nullptr && !transportOwner->IsDead()) {
      (void)transportOwner->AiTransport->TransportDetachUnit(this);
      TransportedByRef.UnlinkFromOwnerChain();
    }

    if (AiTransport != nullptr) {
      EntitySetTemplate<Unit> detachedUnits = AiTransport->TransportDetachAllUnits(false);
      (void)detachedUnits;
    }
  }

  Entity::OnDestroy();
}

/**
 * Address: 0x006A8790 (FUN_006A8790)
 *
 * What it does:
 * Releases AI sidecars and command queue ownership during kill-cleanup, then
 * clears all corresponding unit pointers.
 */
void Unit::KillCleanup()
{
  mNeedsKillCleanup = false;

  if (AiAttacker) {
    AiAttacker->WeaponsOnDestroy();
  }

  auto* commandDispatch = AiCommandDispatch;
  AiCommandDispatch = nullptr;
  delete commandDispatch;

  if (CommandQueue) {
    CommandQueue->ClearCommandQueue();
  }

  auto* attacker = AiAttacker;
  AiAttacker = nullptr;
  delete attacker;

  auto* transport = AiTransport;
  AiTransport = nullptr;
  delete transport;

  auto* navigator = AiNavigator;
  AiNavigator = nullptr;
  delete navigator;

  auto* steering = AiSteering;
  AiSteering = nullptr;
  delete steering;

  auto* builder = AiBuilder;
  AiBuilder = nullptr;
  delete builder;

  auto* siloBuild = AiSiloBuild;
  AiSiloBuild = nullptr;
  delete siloBuild;

  CUnitCommandQueue* queue = CommandQueue;
  CommandQueue = nullptr;
  delete queue;
}

/**
 * Address: 0x006ACB20 (FUN_006ACB20)
 *
 * What it does:
 * Appends this unit's sync extra-data records into `out`: one `{bone, target
 * entity id}` pair per weapon for an attacker, or a single `{-1, beacon id}`
 * pair for a transport holding a teleport beacon.
 *
 * The weapon loop used to run through `CAiAttackerImpl::TryGetWeaponExtraData`
 * and `ReadExtraDataValue` over a `WeaponEmitterEntryView` / `WeaponExtraRefSubobject`
 * pair of reach-in structs. Reading 0x006ACB9A-0x006ACBDC says what those
 * anonymous offsets are:
 *
 *     mov  ecx, [esi+0D0h]   ; weapon->mTarget.targetEntity.ownerLinkSlot
 *     test ecx,ecx / je      ;   (mTarget is at +0xCC, the weak node at +0x04)
 *     add  ecx, -4           ; WeakPtr<Entity>::DecodeOwnerObject
 *     mov  edx, [esi+0A8h]   ; weapon->mBone
 *     mov  [eax], edx        ; pair.key
 *     je   no_entity
 *     mov  ecx, [ecx+68h]    ; Entity::id_
 *   ...
 *     mov  [esp+10h], 0F0000000h   ; no_entity: the missing-id sentinel
 *
 * so `extraKey` was the weapon's bone index, `extraRef` was the raw owner-link
 * slot of its target weak node, and `extraValue` at +0x64 off that slot was the
 * target entity's id (0x04 + 0x64 == 0x68). `GetObjectPtr()` also treats the
 * bare slot value 4 as an unbound sentinel, which the binary walks into; no
 * caller can produce it and the guard only turns a fault into the null path.
 */
void Unit::GetExtraData(SExtraUnitData* out) const
{
  if (!out) {
    return;
  }

  if (AiAttacker) {
    const int count = AiAttacker->GetWeaponCount();
    for (int i = 0; i < count; ++i) {
      const UnitWeapon* const weapon = AiAttacker->GetWeapon(i);

      SExtraUnitDataPair pair{};
      pair.key = weapon->mBone;
      const Entity* const targetEntity = weapon->mTarget.targetEntity.GetObjectPtr();
      pair.value = (targetEntity != nullptr) ? static_cast<std::int32_t>(targetEntity->id_)
                                             : static_cast<std::int32_t>(ToRaw(EEntityIdSentinel::Invalid));
      out->pairs.PushBack(pair);
    }
  } else if (AiTransport) {
    const Unit* teleportBeacon = AiTransport->TransportGetTeleportBeaconForSync();
    if (teleportBeacon) {
      SExtraUnitDataPair pair{};
      pair.key = -1;
      pair.value = teleportBeacon->id_;
      out->pairs.PushBack(pair);
    }
  }

  out->unitEntityId = id_;
}

/**
 * Address: 0x006A73F0 (FUN_006A73F0)
 *
 * What it does:
 * Applies pause/unpause when unit caps allow it, emits script callbacks on
 * state transitions, and marks sync game-data dirty.
 */
void Unit::SetPaused(const bool paused)
{
  const UnitAttributes& attributes = GetAttributes();
  const bool canToggle =
    (attributes.commandCapsMask & kCommandCapPause) != 0u || (attributes.toggleCapsMask & kToggleCapGeneric) != 0u;
  if (!canToggle) {
    return;
  }

  if (paused) {
    if (!mUnitVarDat.mIsPaused) {
      CallbackStr("OnPaused");
    }
  } else if (mUnitVarDat.mIsPaused) {
    CallbackStr("OnUnpaused");
  }

  mUnitVarDat.mIsPaused = paused;
  MarkNeedsSyncGameData();
}

/**
 * Address: 0x006A7450 (FUN_006A7450)
 *
 * What it does:
 * Sets repeat-queue mode, marks the dirty-sync lane, and emits
 * OnStartRepeatQueue/OnStopRepeatQueue callbacks.
 */
void Unit::SetRepeatQueue(const bool enabled)
{
  if (enabled) {
    if (!mUnitVarDat.mRepeatQueue) {
      CallbackStr("OnStartRepeatQueue");
    }
  } else if (mUnitVarDat.mRepeatQueue) {
    CallbackStr("OnStopRepeatQueue");
  }

  mUnitVarDat.mRepeatQueue = enabled;
  MarkNeedsSyncGameData();
}
