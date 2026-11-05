// Part of Unit.cpp, included there: lifetime stats and guard formations.

  void DecrementUnitArmyLifetimeStats(Unit& unit)
  {
    CArmyImpl* const army = unit.ArmyRef;
    if (army == nullptr) {
      return;
    }

    const RUnitBlueprint* const blueprint = unit.GetBlueprint();
    if (blueprint == nullptr) {
      return;
    }

    CArmyStats* const armyStats = army->GetArmyStats();
    if (armyStats == nullptr) {
      return;
    }

    if (unit.IsBeingBuilt()) {
      IncrementArmyBlueprintFloatStat(armyStats, "Units_BeingBuilt", blueprint, -1.0f);
      return;
    }

    if (blueprint->General.CapCost > 0.0f) {
      IncrementArmyBlueprintFloatStat(armyStats, "Units_Active", blueprint, -1.0f);
      const std::int32_t delta = -1;
      (void)armyStats->UpdateUnitStat("Units_Active", &delta);
    }
  }

  void DetachAndDestroyUnitTransport(Unit& unit)
  {
    if (unit.AiTransport == nullptr) {
      return;
    }

    EntitySetTemplate<Unit> detachedUnits = unit.AiTransport->TransportDetachAllUnits(true);
    (void)detachedUnits;
    DeleteAndNull(unit.AiTransport);
  }

  void ClearUnitOwnedSidecars(Unit& unit)
  {
    DeleteAndNull(unit.AiCommandDispatch);

    if (unit.CommandQueue != nullptr) {
      unit.CommandQueue->ClearCommandQueue();
    }

    DeleteAndNull(unit.AiAttacker);
    DetachAndDestroyUnitTransport(unit);
    DeleteAndNull(unit.AiNavigator);
    DeleteAndNull(unit.AiSteering);
    DeleteAndNull(unit.UnitMotion);
    DeleteAndNull(unit.AiBuilder);
    DeleteAndNull(unit.AiSiloBuild);
    DeleteAndNull(unit.CommandQueue);
    DeleteAndNull(unit.AniActor);
  }
  /**
   * Address: 0x007736A0 (FUN_007736A0, sub_7736A0)
   *
   * IDA signature:
   * float *__userpurge sub_7736A0(
   *     Moho::SEconValue *dest@<eax>, Moho::CEconRequest *request@<edx>, Moho::SEconValue *desired);
   *
   * What it does:
   * Clamps `desired` to what remains in `request.mGranted` (component-wise
   * min), writes the clamped amount into `dest`, then reduces
   * `request.mGranted` by that withdrawn amount (floored at zero).
   */
  SEconValue& WithdrawFromGrantedEconValue(SEconValue& dest, CEconRequest& request, const SEconValue& desired)
  {
    dest.energy = std::min(desired.energy, request.mGranted.energy);
    dest.mass = std::min(desired.mass, request.mGranted.mass);

    request.mGranted.energy = std::max(0.0f, request.mGranted.energy - dest.energy);
    request.mGranted.mass = std::max(0.0f, request.mGranted.mass - dest.mass);

    return dest;
  }
}



/**
 * Address: 0x006AD750 (FUN_006AD750, func_SetExtraStorage)
 *
 * IDA signature:
 * void callcnv_F3 func_SetExtraStorage(Moho::CEconStorage **a1@<eax>, Moho::CEconStorage *a2@<ecx>);
 */
void Unit::SetExtraStorage(CEconStorage* const newStorage)
{
  DestroyUnitExtraStorage(mExtraStorage);
  mExtraStorage = newStorage;
}

/**
 * Address: 0x006AAAC0 (FUN_006AAAC0, ?HandleResourceManagement@Unit@Moho@@AAEXXZ)
 *
 * What it does:
 * Per-tick economy step. Consumes this unit's request lane (throttling its
 * own production by the consumption fulfillment ratio when it is not a
 * natural producer), then - while alive, not under construction, and
 * production-active - maintains the extra max-storage lane the blueprint's
 * storage economy requires and contributes production output into the
 * owning army's economy and this unit's own beat accumulators. Otherwise
 * (not producing), tears down any owned extra-storage lane.
 */
void Unit::HandleResourceManagement()
{
  ResourceConsumed = 0.0f;
  float productionRate = 1.0f;

  if (!GetBlueprint()->Economy.NaturalProducer && mConsumptionData != nullptr) {
    productionRate = mConsumptionData->LimitingRate();
  }

  if (!IsDead() && ConsumptionActive && mConsumptionData != nullptr) {
    ResourceConsumed = mConsumptionData->LimitingRate();

    SEconValue desiredConsumption = mConsumptionData->mRequested;
    desiredConsumption.energy *= ResourceConsumed;
    desiredConsumption.mass *= ResourceConsumed;

    SEconValue withdrawn{};
    WithdrawFromGrantedEconValue(withdrawn, *mConsumptionData, desiredConsumption);

    mUnitVarDat.mResourcesSpent.ENERGY += withdrawn.energy;
    mUnitVarDat.mResourcesSpent.MASS += withdrawn.mass;
  }

  if (mVarDat.mIsBeingBuilt || IsDead() || !ProductionActive) {
    DestroyUnitExtraStorage(mExtraStorage);
    return;
  }

  const RUnitBlueprint* const blueprint = GetBlueprint();

  if (blueprint->Economy.StorageEnergy == 0.0f && blueprint->Economy.StorageMass == 0.0f) {
    DestroyUnitExtraStorage(mExtraStorage);
  } else {
    const SEconValue storageAmount{blueprint->Economy.StorageEnergy, blueprint->Economy.StorageMass};

    if (mExtraStorage != nullptr) {
      mExtraStorage->ChangeAmt(storageAmount);
    } else {
      CSimArmyEconomyInfo* const economyInfo = ArmyRef->GetEconomy();
      SetExtraStorage(new (std::nothrow) CEconStorage(storageAmount, reinterpret_cast<CEconomy*>(economyInfo)));
    }
  }

  SEconValue producedThisTick{
    mUnitVarDat.mAttributes.productionPerSecondEnergy * productionRate, mUnitVarDat.mAttributes.productionPerSecondMass * productionRate
  };
  producedThisTick.energy *= 0.1f;
  producedThisTick.mass *= 0.1f;

  CSimArmyEconomyInfo* const economyInfo = ArmyRef->GetEconomy();
  economyInfo->mResources.ENERGY += producedThisTick.energy;
  economyInfo->mResources.MASS += producedThisTick.mass;
  economyInfo->mPendingResources.ENERGY += producedThisTick.energy;
  economyInfo->mPendingResources.MASS += producedThisTick.mass;
  mUnitVarDat.mProduced.ENERGY += producedThisTick.energy;
  mUnitVarDat.mProduced.MASS += producedThisTick.mass;
}

/**
 * Address: 0x006AA7A0 (FUN_006AA7A0, ?UpdateGuardFormation@Unit@Moho@@AAEXXZ)
 *
 * What it does:
 * When this unit has no guard formation yet but has guarded units and a
 * blueprint-defined guard-formation script, builds a new
 * `CAiFormationInstance` centered on this unit (oriented along this unit's
 * own transform when mobile, or a zero orientation otherwise), disbands any
 * prior formation, and primes the new one.
 */
void Unit::UpdateGuardFormation()
{
  if (GuardFormation != nullptr || GuardedByList.Empty()) {
    return;
  }

  CAiFormationDBImpl* const formationDB = SimulationRef->mFormationDB;
  const char* const guardFormationScript = GetBlueprint()->AI.GuardFormationName.c_str();
  if (guardFormationScript == nullptr || *guardFormationScript == '\0') {
    return;
  }

  const Wm3::Vec3f& position = GetPosition();
  SCoordsVec2 formationCenter{};
  formationCenter.x = position.x;
  formationCenter.z = position.z;

  const Wm3::Quatf formationOrientation = IsMobile() ? GetTransform().orient_ : Zeroed<Wm3::Quaternionf>();

  CAiFormationInstance* const newFormation = formationDB->NewFormation(
    &GuardedByList,
    guardFormationScript,
    &formationCenter,
    formationOrientation.x,
    formationOrientation.y,
    formationOrientation.z,
    formationOrientation.w,
    15
  );

  IFormationInstance* const previousFormation = GuardFormation;
  GuardFormation = newFormation;
  delete previousFormation;

  newFormation->SetScale(1.0f);
}

/**
 * Address: 0x006A5050 (FUN_006A5050, ??0Unit@Moho@@AAE@PAVSim@1@@Z)
 * Mangled: ??0Unit@Moho@@AAE@PAVSim@1@@Z
 *
 * IDA signature:
 * Moho::Unit *__thiscall Moho::Unit::Unit(Moho::Unit *this, Moho::Sim *sim);
 *
 * What it does:
 * Deserialization-construct constructor (private; invoked only by
 * Unit::MemberConstruct). Constructs the IUnit/Entity/InstanceCounter<Unit>
 * bases on `sim`, default-constructs the const/variable stat-data
 * subobjects, and zero-initializes every runtime lane: AI sidecars, weak-ref
 * slots, the guarded-by list, the armor-multiplier map head, the economy-event
 * list, the info cache, the occupancy rect, and the recon/blip vectors.
 */
Unit::Unit(Sim* sim) : IUnit(), Entity(sim, ENTITYTYPE_Unit)
{
  UnitMotion = nullptr;
  CommandQueue = nullptr;
  CreatorRef = {};
  TransportedByRef = {};
  AssignedTransportRef = {};
  FocusEntityRef = {};
  TargetBlipEntityRef = {};
  GuardedUnitRef = {};
  GuardedPos.x = 0.0f;
  GuardedPos.y = 0.0f;
  GuardedPos.z = 0.0f;

  // `GuardedByList` constructs as a member: its list node self-linked, its
  // vector on the four inline slots that end at `GuardFormation`.

  GuardFormation = nullptr;
  mNeedsKillCleanup = false;
  mCreationTick = 0;
  mExtraStorage = nullptr;
  PriorityBoost = 1;
  mConsumptionData = nullptr;
  ConsumptionActive = false;
  ProductionActive = false;
  ResourceConsumed = 0.0f;
  AniActor = nullptr;
  AiAttacker = nullptr;
  AiCommandDispatch = nullptr;
  AiNavigator = nullptr;
  AiSteering = nullptr;
  AiBuilder = nullptr;
  AiSiloBuild = nullptr;
  AiTransport = nullptr;
  FootprintDown = false;
  TransportLoadFactor = -1.0f;

  // ArmorMultipliers (fa::map<fa::string,float>) self-constructs its
  // sentinel head via its own default constructor (member init) -- see
  // legacy/containers/RbTree.h's buy_head(), cited for this instantiation
  // (0x006B01C0) exactly where the binary's manual head-alloc-and-self-link
  // used to be modeled by hand here.

  // mEconomyEventListHead self-links via its TDatListItem ctor (member init).

  CurrentTerrainType = 0;
  mDebugAIStates = false;

  mInfoCache.mFormationLayer = nullptr;
  mInfoCache.mFormationLeadRef = {};
  mInfoCache.mFormationPriorityOrder = 0;
  mInfoCache.mHasFormationSpeedData = false;
  mInfoCache.mFormationTopSpeed = 0.0f;
  mInfoCache.mFormationDistanceMetric = 0.0f;
  mInfoCache.mFormationHeadingHint.x = 0.0f;
  mInfoCache.mFormationHeadingHint.y = 0.0f;
  mInfoCache.mFormationHeadingHint.z = 0.0f;

  ReservedOgridRectMinX = 0;
  ReservedOgridRectMinZ = 0;
  ReservedOgridRectMaxX = 0;
  ReservedOgridRectMaxZ = 0;

  // mBlipsInRange (FastVectorN<WeakPtr<Entity>,20>) and mReconBlips
  // (FastVectorN<ReconBlip*,2>) bind to their inline buffers as members.
  mBlipLastUpdateTick = 0;

  mIsNotPod = false;
  mIsEngineer = false;
  mIsNaval = false;
  mIsAir = false;
  mUsesGridBasedMotion = false;
  mIsMelee = false;
  CaptorCount = 0;
  NeedSyncGameData = true;
}
namespace
{
  /** Half the yaw spread a randomly-facing spawn gets, in radians (~30 degrees). */
  constexpr float kRandomSpawnYawLimit = 0.52359879f;

  /** `SSTIUnitVariableData::mCreator` when the unit was not built by anything. */
  constexpr moho::EntId kNoCreatorEntityId = static_cast<moho::EntId>(0xF0000000);

  /** `UnitStateMask` bit set while a unit is still under construction. */
  constexpr std::uint64_t kUnitStateBeingBuilt = 1ULL << 39;

  /**
   * Floor the two minima and ceil the two maxima of a skirt rectangle onto the
   * occupancy grid, which is what the binary's four `frndint`s plus sign
   * fixups come out to (Unit::Unit, 0x006A618F..0x006A6220).
   */
  [[nodiscard]] gpg::Rect2i SkirtRectToOgridRect(const gpg::Rect2f& skirt) noexcept
  {
    return gpg::Rect2i{
      fa::FloorToIntX87(skirt.x0),
      fa::FloorToIntX87(skirt.z0),
      fa::CeilToIntX87(skirt.x1),
      fa::CeilToIntX87(skirt.z1),
    };
  }
}



/**
 * Address: 0x006A53F0 (FUN_006A53F0, ??0Unit@Moho@@AAE@ABUSUnitConstructionParams@1@@Z)
 * Mangled: ??0Unit@Moho@@AAE@ABUSUnitConstructionParams@1@@Z
 *
 * IDA signature:
 * Moho::Unit *__stdcall Moho::Unit::Unit(Moho::Unit *unit,
 *     const Moho::SUnitConstructionParams *params);
 *
 * What it does:
 * The gameplay constructor - what `Sim::CreateUnit` calls, and the only way a
 * unit comes into existence outside a savegame load. Reserves an entity id out
 * of the owning army's id family, runs the blueprint-aware `Entity` base
 * constructor, seeds health and attributes from the blueprint, resolves the
 * spawn orientation and elevation, builds the intel manager, attaches every AI
 * sidecar the blueprint calls for (motion/navigator/steering, weapons, builder,
 * silo builder, transport, command queue, command dispatch), publishes the unit
 * into `ArmyPool`, and runs `OnCreate` plus either `OnStartBeingBuilt` or
 * `OnStopBeingBuilt`.
 */
Unit::Unit(const SUnitConstructionParams& params)
  : IUnit()
  , Entity(
      const_cast<REntityBlueprint*>(static_cast<const REntityBlueprint*>(params.mBlueprint)),
      params.mArmy->GetSim(),
      static_cast<EntId>(params.mArmy->GetSim()->mEntityDB->DoReserveId(
        static_cast<std::uint32_t>(params.mArmy->mConstDat.mArmyIndex) << 20
      )),
      ENTITYTYPE_Unit
    )
{
  Sim* const sim = SimulationRef;
  const RUnitBlueprint& blueprint = *params.mBlueprint;

  // --- runtime lanes: the same zeroing the deserialization ctor above does --
  UnitMotion = nullptr;
  CommandQueue = nullptr;
  CreatorRef = {};
  CreatorRef.Set(params.mLinkSourceUnit);
  TransportedByRef = {};
  AssignedTransportRef = {};
  FocusEntityRef = {};
  TargetBlipEntityRef = {};
  GuardedUnitRef = {};
  GuardedPos.x = 0.0f;
  GuardedPos.y = 0.0f;
  GuardedPos.z = 0.0f;

  GuardFormation = nullptr;
  mNeedsKillCleanup = false;
  mCreationTick = sim->mCurTick;
  mExtraStorage = nullptr;
  PriorityBoost = 1;
  mConsumptionData = nullptr;
  ConsumptionActive = false;
  ProductionActive = false;
  ResourceConsumed = 0.0f;
  AniActor = nullptr;
  AiAttacker = nullptr;
  AiCommandDispatch = nullptr;
  AiNavigator = nullptr;
  AiSteering = nullptr;
  AiBuilder = nullptr;
  AiSiloBuild = nullptr;
  AiTransport = nullptr;
  FootprintDown = false;
  TransportLoadFactor = -1.0f;

  // ArmorMultipliers (fa::map<fa::string,float>) self-constructs its
  // sentinel head via its own default constructor (member init); see the
  // sibling constructor above for the full citation.

  CurrentTerrainType = 0;
  mDebugAIStates = false;

  mInfoCache.mFormationLayer = nullptr;
  mInfoCache.mFormationLeadRef = {};
  mInfoCache.mFormationPriorityOrder = 0;
  mInfoCache.mHasFormationSpeedData = false;
  mInfoCache.mFormationTopSpeed = 0.0f;
  mInfoCache.mFormationDistanceMetric = 0.0f;
  mInfoCache.mFormationHeadingHint.x = 0.0f;
  mInfoCache.mFormationHeadingHint.y = 0.0f;
  mInfoCache.mFormationHeadingHint.z = 0.0f;

  ReservedOgridRectMinX = 0;
  ReservedOgridRectMinZ = 0;
  ReservedOgridRectMaxX = 0;
  ReservedOgridRectMaxZ = 0;

  mBlipLastUpdateTick = 0;

  mIsNotPod = false;
  mIsEngineer = false;
  mIsNaval = false;
  mIsAir = false;
  mUsesGridBasedMotion = false;
  mIsMelee = false;
  NeedSyncGameData = true;
  CaptorCount = 0;

  // 0x006A572F: `mov byte ptr [ebp+1C0h], 1` -- `ebp` is the Unit here (the two
  // neighbouring stores are `NeedSyncGameData` at Unit+0x68E and `CaptorCount`
  // at Unit+0x690, and the next one is `MaxHealth` at Unit+0x9C), so this is
  // `Entity::mQueueRelinkBlocked` at Entity+0x1B8.
  //
  // It pins the unit in `Sim::mCoordEntities` for life. `Entity::Sync`
  // (0x0067A114) unlinks the node it was reached through *unless* this flag is
  // set, and `Sim::Sync` publishes exactly the entities on that run -- so a
  // unit that is never unlinked is republished on every sync, whether or not
  // anything relinked it. That is what makes a value which changes with no
  // other side effect reach the client at all: `Unit::WorkProgress`
  // (Unit+0x2AC) is written by `CBuildTaskHelper::UpdateWorkProgress` and by
  // the `SetWorkProgress` Lua binding (0x006CCC85) as a bare `fstp`, with no
  // dirty mark and no relink anywhere. Without this line a stationary builder
  // published once and then froze: a factory's build bar never moved, and
  // neither did the intel-recharge bar Lua drives the same way. Props,
  // projectiles and blips keep the base default and stay change-driven.
  mQueueRelinkBlocked = 1u;

  // --- blueprint-derived health and attributes ---------------------------
  mVarDat.mMaxHealth = blueprint.Defense.MaxHealth;
  mVarDat.mHealth = params.mComplete != 0 ? blueprint.Defense.Health : 1.0f;
  mVarDat.mFractionComplete = static_cast<float>(params.mComplete);
  mVarDat.mIsBeingBuilt = 0;
  mVarDat.mIntelAttributes.Initialize(&blueprint);

  VarDat().mCreator = params.mLinkSourceUnit != nullptr ? params.mLinkSourceUnit->id_ : kNoCreatorEntityId;
  // Constructed in place over the unit's own attribute lane (unit+0x428).
  new (&mUnitVarDat.mAttributes) UnitAttributes(&blueprint, static_cast<const RRuleGameRulesImpl*>(sim->mRules));
  VarDat().mCreationTick = sim->mCurTick;

  SetAutoMode(blueprint.AI.InitialAutoMode != 0);
  RunScript("OnPreCreate");

  // --- intel manager -----------------------------------------------------
  // The slot was nulled by the Entity base a moment ago, so the binary's
  // release-the-previous-manager branch cannot be taken here.
  mIntelManager = new CIntel(&blueprint.Intel, sim, ArmyRef->GetReconDB());

  // --- spawn transform ---------------------------------------------------
  VTransform spawnTransform = params.mTransform;
  if (params.mUseLayerOverride == 0) {
    // No caller-supplied orientation. Mobile units whose blueprint asks for it
    // get a facing within +/-30 degrees of default so a batch of them does not
    // spawn perfectly aligned; everything else faces the default direction.
    if (blueprint.Display.SpawnRandomRotation != 0 && blueprint.IsMobile()) {
      const float yaw = sim->mRngState->FRand(-kRandomSpawnYawLimit, kRandomSpawnYawLimit);
      const Wm3::Vector3f yawAxis{0.0f, 1.0f, 0.0f};
      Wm3::Quatf spawnRotation{};
      (void)EulerRollToQuat(&yawAxis, &spawnRotation, yaw);
      spawnTransform.orient_ = spawnRotation;
    } else {
      spawnTransform.orient_.w = 1.0f;
      spawnTransform.orient_.x = 0.0f;
      spawnTransform.orient_.y = 0.0f;
      spawnTransform.orient_.z = 0.0f;
    }
  }

  // --- placeholder mesh --------------------------------------------------
  RMeshBlueprint* placeholderMesh = nullptr;
  const fa::string placeholderName = gpg::STR_ToLower(blueprint.Display.PlaceholderMeshName.c_str());
  if (!placeholderName.empty()) {
    const fa::string meshPath =
      gpg::STR_Printf("/units/%s/%s_mesh", placeholderName.c_str(), placeholderName.c_str());
    fa::string meshFileName{};
    (void)gpg::STR_CopyFilename(&meshFileName, &meshPath);

    RResId placeholderId{};
    placeholderId.name.assign_owned(meshFileName.view());
    placeholderMesh = sim->mRules->GetMeshBlueprint(placeholderId);
  }

  // A null pointee means nothing has claimed the mesh lane yet.
  if (!boost::HasSharedResource(mVarDat.mScmResource)) {
    SetMesh(blueprint.Display.MeshBlueprint, placeholderMesh, true);
  }

  // --- layer, terrain type and spawn elevation ---------------------------
  SetCurrentLayer(GetStartingLayer(spawnTransform.pos_, static_cast<ELayer>(params.mLayer)));
  UpdateTerrainType(spawnTransform.pos_);
  if (params.mFixElevation == 0) {
    spawnTransform.pos_.y =
      IUnit::CalcSpawnElevation(sim->mMapData, mVarDat.mLayerMask, spawnTransform, VarDat().mAttributes);
  }

  // Word-for-word copy (0x006A5BF9..0x006A5C23 stores the transform straight
  // into +0x150). Getting the quaternion one lane off rotates it and flips every
  // spawned unit upside-down on the user side (its skinned mesh draws as an
  // unlit black blob), which is what happened while +0x150 was spelled as a
  // `moho::Vector4f` naming (x,y,z,w) over the quaternion's (w,x,y,z) words.
  mPendingTransform = spawnTransform;
  // Twice, as the binary does: the first call publishes the spawn pose into the
  // current lane and the second copies it into the previous-frame lane, so the
  // unit does not interpolate in from wherever that lane happened to point.
  AdvanceCoords();
  AdvanceCoords();

  AniActor->GetPriorPoseShared()->SetWorldTransform(GetTransformWm3());
  AniActor->GetPoseShared()->SetWorldTransform(GetTransformWm3());
  VarDat().mPriorSharedPose = AniActor->GetPriorPoseShared();
  VarDat().mSharedPose = AniActor->GetPoseShared();

  // --- motion, navigator, steering ---------------------------------------
  // RULEUMT_None and RULEUMT_Special both leave the unit immobile; every value
  // between them gets a navigator, and only RULEUMT_Air gets the air one.
  const ERuleBPUnitMovementType motionType = blueprint.Physics.MotionType;
  if (motionType >= RULEUMT_Land && motionType <= RULEUMT_AmphibiousFloating) {
    UnitMotion = new CUnitMotion(this);
    AiNavigator =
      motionType == RULEUMT_Air ? AI_CreateAirNavigator(this) : AI_CreatePathingNavigator(this);
    AiSteering = AI_CreateSteering(this, UnitMotion, mVarDat.mLayerMask);
  } else {
    // Immobile units claim their footprint at spawn. Ferry beacons and in-place
    // upgrades are the exceptions: both sit on ground another unit already owns.
    if (!IsInCategory("FERRYBEACON") && !IsInCategory("UPGRADE")) {
      ExecuteOccupyGround();
      FootprintDown = true;
    }
  }

  // --- weapons -----------------------------------------------------------
  for (const RUnitBlueprintWeapon& weaponBlueprint : blueprint.Weapons.WeaponBlueprints) {
    if (weaponBlueprint.DummyWeapon != 0) {
      continue;
    }

    if (AiAttacker == nullptr) {
      AiAttacker = AI_CreateAttacker(this);
      mConstDat.mBuildStateTag = 1;
    }
    AiAttacker->CreateWeapon(const_cast<RUnitBlueprintWeapon*>(&weaponBlueprint));
  }

  // --- builder -----------------------------------------------------------
  if (!blueprint.Economy.BuildableCategories.empty() || IsInCategory("REBUILDER")) {
    AiBuilder = AI_CreateBuilder(this);

    if (IsInCategory("FACTORY")) {
      AiBuilder->BuilderSetIsFactory(true);
      if (UnitMotion == nullptr) {
        const Wm3::Vector3f& position = GetPosition();
        const SCoordsVec2 origin{position.x, position.z};
        ReserveOgridRect(SkirtRectToOgridRect(GetBlueprint()->GetSkirtRect(origin)));
      }
    }
  }

  // --- silo builder and transport ----------------------------------------
  if (IsInCategory("SILO")) {
    AiSiloBuild = static_cast<CAiSiloBuildImpl*>(AI_CreateSiloBuilder(this));
  }

  if ((VarDat().mAttributes.commandCapsMask & RULEUCC_Transport) != 0 || IsInCategory("PODSTAGINGPLATFORM")) {
    AiTransport = AI_CreateTransport(this);
  }

  // --- command plumbing --------------------------------------------------
  CommandQueue = new CUnitCommandQueue(this);
  AiCommandDispatch = static_cast<IAiCommandDispatchImpl*>(AI_CreateCommandDispatch(this));

  // --- publish into the army pool ----------------------------------------
  {
    EntitySetTemplate<Unit> spawnedSet{};
    (void)spawnedSet.Add(this);
    ArmyRef->AssignUnitsToPlatoon(&spawnedSet, "ArmyPool");
  }

  if (AiBuilder != nullptr && AiBuilder->BuilderIsFactory()) {
    AiBuilder->BuilderSetUpInitialRally();
  }

  InitializeArmor();
  RunScript("OnCreate");

  // --- being-built vs finished -------------------------------------------
  CArmyStats* const armyStats = ArmyRef->GetArmyStats();
  const char* const layerName = LayerToString(mVarDat.mLayerMask);
  // 0x006A6563..0x006A6584 / 0x006A67E5..0x006A6806: with no creator the
  // binary passes a nil LuaObject built on this unit's Lua state (0x00908970),
  // not the unit's own script object.
  const auto makeCreatorObject = [this](Unit* const creator) -> LuaPlus::LuaObject {
    if (creator != nullptr) {
      return creator->GetLuaObject();
    }
    LuaPlus::LuaObject nilObject;
    if (LuaPlus::LuaState* const scriptState = mLuaObj.GetActiveState(); scriptState != nullptr) {
      nilObject = LuaPlus::LuaObject(scriptState);
    }
    return nilObject;
  };

  if (params.mComplete == 0) {
    mUnitVarDat.mUnitStates |= kUnitStateBeingBuilt;
    mVarDat.mIsBeingBuilt = 1;
    if (armyStats != nullptr) {
      IncrementArmyBlueprintFloatStat(armyStats, "Units_BeingBuilt", &blueprint, 1.0f);
    }
    // 0x006A67B3..0x006A6830: creator read from `params.mLinkSourceUnit`
    // (+0x2C), fired through `RunScript_ObjStr` (0x006B07D0).
    RunScriptObjectString("OnStartBeingBuilt", makeCreatorObject(params.mLinkSourceUnit), layerName);
  } else {
    if (UnitMotion == nullptr) {
      EntitySetTemplate<Unit> overlapping{};
      (void)CollectAllOverlapping(&overlapping, this);
      for (Entity* const entry : overlapping.mVec) {
        Unit* const neighbour = static_cast<Unit*>(entry);
        if (neighbour == nullptr) {
          continue;
        }
        // 0x006A64A3..0x006A64C9: `RunScript_OnAdjacentTo` (0x006B0660) as
        // this->(neighbour, this), then neighbour->(this, this) -- both
        // arguments of the second call are this unit.
        RunScriptOnAdjacentTo(neighbour, this);
        neighbour->RunScriptOnAdjacentTo(this, this);
      }
    }

    // 0x006A6522..0x006A65AB: creator read from the `CreatorRef` weak link
    // (+0x4B8), fired through `RunScript_ObjStr` (0x006B07D0).
    RunScriptObjectString("OnStopBeingBuilt", makeCreatorObject(CreatorRef.GetObjectPtr()), layerName);

    if (blueprint.General.CapCost > 0.0f && armyStats != nullptr) {
      IncrementArmyBlueprintFloatStat(armyStats, "Units_Active", &blueprint, 1.0f);
      const std::int32_t delta = 1;
      (void)armyStats->UpdateUnitStat("Units_Active", &delta);
      IncrementArmyBlueprintFloatStat(armyStats, "Units_History", &blueprint, 1.0f);
      (void)armyStats->UpdateUnitStat("Units_History", &delta);
    }
  }

  if (ArmyRef != nullptr) {
    ArmyRef->AddUnitToCategorySet(this);
  }

  // --- cached category flags ---------------------------------------------
  mIsNotPod = IsInCategory("POD") || IsInCategory("STATIONASSISTPOD");
  mIsEngineer = IsInCategory("ENGINEER");
  mIsNaval = IsInCategory("NAVAL");
  mIsAir = IsInCategory("AIR");
  mIsMelee = IsInCategory("MELEE");
  mUsesGridBasedMotion = IsInCategory("GRIDBASEDMOTION");
}

/**
 * Address: 0x006AD3C0 (FUN_006AD3C0,
 * ?MemberConstruct@Unit@Moho@@CAXAAVReadArchive@gpg@@HABVRRef@4@AAVSerConstructResult@4@@Z)
 *
 * What it does:
 * Reflection construct-callback. Reads the owning `Sim*` from the archive,
 * allocates and constructs a fresh `Unit` on it, then publishes it to the
 * `SerConstructResult` as unowned.
 */
void Unit::MemberConstruct(
  gpg::ReadArchive& archive,
  const int,
  const gpg::RRef&,
  gpg::SerConstructResult& result
)
{
  Sim* sim = nullptr;
  const gpg::RRef owner{};
  archive.ReadPointer(&sim, &owner);
  result.SetUnowned(gpg::MakeRRef(new Unit(sim)), 0u);
}

/**
 * Address: 0x006A6BF0 (FUN_006A6BF0, ??1Unit@Moho@@UAE@XZ)
 *
 * What it does:
 * Releases unit-owned AI, command, guard, economy, occupancy, recon, and
 * weak-link runtime lanes before base/member teardown.
 */
Unit::~Unit()
{
  if (ArmyRef != nullptr) {
    (void)ArmyRef->ConsumeUnitFromCategorySet(this);
  }

  ClearUnitOwnedSidecars(*this);
  // ArmorMultipliers (fa::map<fa::string,float>) tears itself down via
  // its own destructor (member teardown, reverse declaration order) -- see
  // legacy/containers/RbTree.h's ~rb_tree()/destroy_subtree, matching the
  // binary's 0x006A5380 teardown shape this used to hand-model.
  ClearGuardFormation(this);
  DestroyUnitEconomyEvents(*this);
  ReleaseOccupyGround();
  DecrementUnitArmyLifetimeStats(*this);
  ClearGuardedByOwners(*this);

  if (ArmyRef != nullptr) {
    ArmyRef->RemoveFromPlatoon(this);
  }

  mReconBlips.ResetStorageToInline();
  ClearUnitWeakReferences(*this);
  DestroyUnitEconomyRequest(mConsumptionData);
  DestroyUnitExtraStorage(mExtraStorage);
  // After the members and `~Entity` (0x006A7369), the `IUnit` base's
  // `WeakObject` drops its weak references (0x006A736E).
}
