// Part of Sim.cpp, included there: unit creation and running Lua in the sim.

/**
 * Address: 0x007489E0 (FUN_007489E0)
 *
 * Moho::SUnitConstructionParams const &, bool
 *
 * IDA signature:
 * Moho::Unit *__userpurge Moho::Sim::CreateUnit@<eax>(Moho::SUnitConstructionParams *params@<esi>, char doCallback);
 *
 * What it does:
 * Applies army unit-cap checks and creates a Unit when caps allow.
 */
Unit* Sim::CreateUnit(const SUnitConstructionParams& params, const bool doCallback)
{
  if (!params.mArmy || !params.mBlueprint) {
    return nullptr;
  }

  if (!params.mArmy->IgnoreUnitCap()) {
    const float unitCap = params.mArmy->GetUnitCap();
    if (params.mArmy->GetArmyUnitCostTotal() + params.mBlueprint->General.CapCost > unitCap) {
      if (doCallback) {
        if (CAiBrain* const brain = params.mArmy->GetArmyBrain()) {
          brain->CallbackStr("OnUnitCapLimitReached");
        }
      }
      return nullptr;
    }
  }

  return new Unit(params);
}

Unit* Sim::CreateUnitForScript(const SUnitConstructionParams& params, const bool doCallback)
{
  return CreateUnit(params, doCallback);
}

/**
 * The inlined construction in `cfunc_CreateInitialArmyUnitL` (0x00709340); see
 * the declaration in Sim.h for the evidence that no unit-cap gate stands in
 * front of it.
 */
Unit* Sim::CreateInitialArmyUnit(const SUnitConstructionParams& params)
{
  if (!params.mArmy || !params.mBlueprint) {
    return nullptr;
  }

  return new (std::nothrow) Unit(params);
}

/**
 * Address: 0x007468E0 (FUN_007468E0, ?TransferUnit@Sim@Moho@@QAEPAVUnit@2@PAV32@PAVSimArmy@2@@Z)
 * Mangled: ?TransferUnit@Sim@Moho@@QAEPAVUnit@2@PAV32@PAVSimArmy@2@@Z
 *
 * IDA signature:
 * Moho::Unit *__thiscall Moho::Sim::TransferUnit(Moho::Sim *this, Moho::Unit *unit, Moho::CArmyImpl *newArmy);
 *
 * What it does:
 * Recursively transfers `unit` (plus its transport-carried cargo and attached
 * child units) to `newArmy`. Drains the transport storage, detaches child units
 * (splicing each child's `TransportedByRef` weak link out of its chain),
 * recursively transfers cargo and children, constructs a replacement Unit owned
 * by `newArmy`, migrates pose / health / custom name, re-populates transport
 * storage, re-attaches the transferred children, then destroys the original.
 * Returns the replacement Unit, or nullptr when the source is dead/destroy-queued
 * or the new army is over its unit cap.
 */
Unit* Sim::TransferUnit(Unit* const unit, CArmyImpl* const newArmy)
{
  if (!unit || unit->IsDead() || unit->DestroyQueued()) {
    return nullptr;
  }

  // Cargo transferred out of this unit's transport storage (parallel to
  // transferredCargo below), and the children transferred after detach.
  fa::vector<Unit*> transferredCargo;    // v57 (result of recursive transfer of stored units)
  fa::vector<Unit*> transferredChildren; // v56 (result of recursive transfer of attached units)
  fa::vector<Unit*> detachedChildren;    // v63 (mobile attached units, pre-detach)
  fa::vector<int> childParentBones;      // v65 (each child's mParentBoneIndex, captured pre-detach)
  fa::vector<int> childChildBones;       // v64 (each child's mChildBoneIndex, captured pre-detach)

  // --- Phase A: drain transport storage and recursively transfer the cargo ---
  if (IAiTransport* const transport = unit->AiTransport) {
    fa::vector<Unit*> storedCargo; // a2a

    EntitySetTemplate<Unit> storedUnits = transport->TransportGetStoredUnits();
    for (Unit* const storedUnit : storedUnits) {
      VTransform storedTransform{};
      storedTransform.orient_.w = 1.0f; // scratch out-transform (identity), receives the removed pose
      storedTransform.orient_.x = 0.0f;
      storedTransform.orient_.y = 0.0f;
      storedTransform.orient_.z = 0.0f;
      storedTransform.pos_.x = 0.0f;
      storedTransform.pos_.y = 0.0f;
      storedTransform.pos_.z = 0.0f;
      unit->AiTransport->TransportRemoveFromStorage(storedUnit, storedTransform);
      storedCargo.push_back(storedUnit);
    }

    for (Unit* const storedUnit : storedCargo) {
      Unit* const transferred = TransferUnit(storedUnit, newArmy);
      transferredCargo.push_back(transferred);
    }

    // 0x007469C0 jumps straight to the replacement unit (0x00746CC2) when
    // there is no transport, so the attached-child capture, detach and
    // transfer below run only for units that have one.
    // --- Phase B: capture mobile attached child units and their attach bones ---
    const fa::vector<Entity*>& attached = unit->GetAttachedEntities();
    for (Entity* const attachedEntity : attached) {
      if (!attachedEntity) {
        continue;
      }
      Unit* const child = attachedEntity->IsUnit();
      if (!child || !attachedEntity->IsMobile() || attachedEntity->mVarDat.mIsDead || attachedEntity->DestroyQueuedFlag) {
        continue;
      }
      detachedChildren.push_back(attachedEntity->IsUnit());
      childChildBones.push_back(attachedEntity->mAttachInfo.mChildBoneIndex);
      childParentBones.push_back(attachedEntity->mAttachInfo.mParentBoneIndex);
    }

    // --- Phase C: detach each captured child and unlink its transport weak-ref ---
    for (Unit* const child : detachedChildren) {
      child->DetachFrom(unit, true);
      child->TransportedByRef.UnlinkFromOwnerChain();
    }

    // --- Phase D: recursively transfer the detached children ---
    for (Unit* const child : detachedChildren) {
      Unit* const transferred = TransferUnit(child, newArmy);
      transferredChildren.push_back(transferred);
    }
  }

  // --- Phase F: construct the replacement unit under the new army ---
  const ELayer sourceLayer = unit->mVarDat.mLayerMask;
  const VTransform sourceTransform = unit->GetTransform();
  const RUnitBlueprint* const sourceBlueprint = unit->GetBlueprint();

  SUnitConstructionParams params(
    static_cast<std::int32_t>(sourceLayer),
    sourceTransform,
    newArmy,
    sourceBlueprint,
    nullptr,
    true
  );
  // The transfer path forces fixed-elevation on unconditionally (the layer==0 gate
  // that the shared ctor applies is not present in the shipped transfer code).
  params.mFixElevation = 1;

  Unit* const newUnit = CreateUnit(params, false);
  if (!newUnit) {
    // --- Phase H: creation failed (unit cap) — notify the army's brain script ---
    if (!newArmy->IgnoreUnitCap()) {
      if (CAiBrain* const brain = newArmy->GetArmyBrain()) {
        brain->RunScript("OnFailedUnitTransfer");
      }
    }
    return nullptr;
  }

  // --- Phase G: migrate pose, health, and custom name onto the replacement ---
  newUnit->SetPoses(unit->AniActor->GetPriorPoseShared(), unit->AniActor->GetPoseShared());

  if (unit->mVarDat.mHealth != newUnit->mVarDat.mHealth) {
    newUnit->SetHealth(unit->mVarDat.mHealth);
  }

  newUnit->SetCustomName(unit->GetCustomName());

  // --- Phase G (transport): re-populate storage and re-attach children ---
  if (newUnit->AiTransport) {
    for (Unit* const cargo : transferredCargo) {
      if (cargo) {
        newUnit->AiTransport->TransportAddToStorage(cargo);
      }
    }

    const std::size_t childCount = transferredChildren.size();
    for (std::size_t i = 0; i < childCount; ++i) {
      Unit* const child = transferredChildren[i];
      if (!child) {
        continue;
      }

      const int parentBoneIndex = childParentBones[i];
      const int childBoneIndex = childChildBones[i];

      // Re-attach the transferred child to the replacement unit. The attach payload
      // reuses the captured bone indices with an identity relative transform.
      SEntAttachInfo attachInfo(newUnit, childBoneIndex, parentBoneIndex, VTransform{});

      child->AttachTo(attachInfo);
      // Detach the temporary attach node from the replacement's weak chain; the
      // durable linkage now lives in the child's own mAttachInfo.
      attachInfo.mAttachTargetWeak.UnlinkFromOwnerChain();

      newUnit->AiTransport->TransportAssignSlot(child, parentBoneIndex);

      if (newUnit->AiTransport) {
        // Resolve the attach bone's name and fire the child's OnTransportAttach
        // script, matching the transport attach path.
        const boost::shared_ptr<const CAniSkel> skeleton = newUnit->AniActor->GetSkeleton();
        const CAniSkel* const skel = skeleton.get();
        const char* boneName = nullptr;
        if (skel) {
          const SAniSkelBone* const bones = skel->mBones.begin();
          const std::size_t boneCount = static_cast<std::size_t>(skel->mBones.end() - bones);
          if (bones && static_cast<std::size_t>(parentBoneIndex) < boneCount) {
            boneName = bones[static_cast<std::size_t>(parentBoneIndex)].mBoneName;
          }
        }
        if (boneName) {
          newUnit->RunScriptStringUnit("OnTransportAttach", boneName, child);
        }
      }
    }
  }

  // --- Phase G (finalize): clear source footprint occupancy for static units ---
  if (!newUnit->IsMobile()) {
    unit->FootprintDown = false;
  }

  unit->Destroy();
  return newUnit;
}

/**
 * Address: 0x00748AA0 (FUN_00748AA0)
 *
 * unsigned int, Moho::RResId const &, Moho::SCoordsVec2 const &, float
 *
 * What it does:
 * Cheat-gated unit creation entrypoint; resolves unit blueprint, builds construction params,
 * and forwards into Sim::CreateUnit(const SUnitConstructionParams&, bool).
 */
void Sim::CreateUnit(const uint32_t armyIndex, const RResId& blueprintId, const SCoordsVec2& pos, const float heading)
{
  if (!CheatsEnabled()) {
    return;
  }

  if (armyIndex >= mArmiesList.size()) {
    return;
  }

  CArmyImpl* const army = mArmiesList[armyIndex];
  if (!army || army->mVarDat.mIsOutOfGame) {
    return;
  }

  const RUnitBlueprint* const blueprint = ResolveUnitBlueprint(mRules, blueprintId);
  if (!blueprint) {
    Logf(
      "CreateUnit: unresolved blueprint '%s' requested by %s.\n",
      blueprintId.name.c_str(),
      GetCurrentCommandSourceName()
    );
    return;
  }

  SUnitConstructionParams params(
    0,
    BuildUnitSpawnTransform(pos, heading),
    army,
    blueprint,
    nullptr,
    true
  );
  // 0x00748BE7 clears only the elevation byte (+0x25). mUseLayerOverride stays 1
  // from the ctor, so the Unit ctor keeps the requested heading instead of
  // resetting it (or drawing a random yaw for SpawnRandomRotation blueprints).
  params.mFixElevation = 0;

  (void)CreateUnit(params, true);
}

/**
 * Address: 0x00748C00 (FUN_00748C00)
 *
 * What it does:
 * `ICommandSink` slot 7, a cheat command: creates prop `blueprint` at `loc`,
 * unrotated. Formerly split into a free `SpawnPropByBlueprint`, which added a
 * null/empty-blueprint early-out the binary does not have.
 */
void Sim::CreateProp(const char* const blueprint, const Wm3::Vec3f& loc)
{
  if (!CheatsEnabled()) {
    return;
  }

  // 0x00748C15..0x00748C5D: identity orientation, then the position.
  VTransform transform;
  transform.pos_ = loc;
  (void)PROP_Create(this, transform, blueprint);
}

/**
 * Address: 0x00748C80 (FUN_00748C80)
 *
 * What it does:
 * Looks up an entity by id, validates command-source ownership, then
 * destroys the entity through `Entity::Destroy()`.
 */
void Sim::DestroyEntity(const EntId entityId)
{
  Entity* entity = FindEntityById(mEntityDB, entityId);
  if (!entity || !OkayToMessWith(entity)) {
    return;
  }

  entity->Destroy();
}

/**
 * Address: 0x00748CD0 (FUN_00748CD0, ?WarpEntity@Sim@Moho@@UAEXVEntId@2@ABVVTransform@2@@Z)
 */
void Sim::WarpEntity(const EntId entityId, const VTransform& transform)
{
  if (!CheatsEnabled()) {
    return;
  }

  Entity* entity = FindEntityById(mEntityDB, entityId);
  if (!entity) {
    return;
  }

  ApplyWarpTransform(entity, transform);
}

/**
 * Address: 0x00748D50 (FUN_00748D50, ?ProcessInfoPair@Sim@Moho@@UAEXVEntId@2@VStrArg@gpg@@1@Z)
 *
 * What it does:
 * Applies one UI/info key-value command lane to a controllable live unit.
 */
void Sim::ProcessInfoPair(const EntId entityId, const gpg::StrArg key, const gpg::StrArg val)
{
  Entity* const entity = FindEntityById(mEntityDB, entityId);
  if (!entity || !OkayToMessWith(entity) || entity->mVarDat.mIsDead != 0u) {
    return;
  }

  if (gpg::STR_EqualsNoCase(key, "SetFireState")) {
    Unit* const unit = entity->IsUnit();
    if (!unit) {
      return;
    }

    EFireState fireState = static_cast<EFireState>(0);
    gpg::RRef fireStateRef{};
    fireStateRef = gpg::MakeRRef<moho::EFireState>(&fireState);
    (void)fireStateRef.SetLexical(val);
    if (static_cast<std::uint32_t>(fireState) <= 2u) {
      unit->SetFireState(static_cast<int>(fireState));
    }

    return;
  }

  if (gpg::STR_EqualsNoCase(key, "SetAutoMode")) {
    Unit* const unit = entity->IsUnit();
    bool value = false;
    if (unit && ParseBoolLiteral(val, value)) {
      unit->SetAutoMode(value);
    }

    return;
  }

  if (gpg::STR_EqualsNoCase(key, "SetAutoSurfaceMode")) {
    Unit* const unit = entity->IsUnit();
    bool value = false;
    if (unit && ParseBoolLiteral(val, value)) {
      unit->SetAutoSurfaceMode(value);
    }

    return;
  }

  if (gpg::STR_EqualsNoCase(key, "SetRepeatQueue")) {
    Unit* const unit = entity->IsUnit();
    bool value = false;
    if (unit && ParseBoolLiteral(val, value)) {
      unit->SetRepeatQueue(value);
    }

    return;
  }

  if (gpg::STR_EqualsNoCase(key, "SetPaused")) {
    Unit* const unit = entity->IsUnit();
    bool value = false;
    if (unit && ParseBoolLiteral(val, value)) {
      unit->SetPaused(value);
    }

    return;
  }

  if (gpg::STR_EqualsNoCase(key, "SiloBuildTactical")) {
    Unit* const unit = entity->IsUnit();
    if (unit && gpg::STR_EqualsNoCase(val, "add")) {
      QueueSiloBuildRequest(unit, 0);
    }

    return;
  }

  if (gpg::STR_EqualsNoCase(key, "SiloBuildNuke")) {
    Unit* const unit = entity->IsUnit();
    if (unit && gpg::STR_EqualsNoCase(val, "add")) {
      QueueSiloBuildRequest(unit, 1);
    }

    return;
  }

  if (gpg::STR_EqualsNoCase(key, "CustomName")) {
    Unit* const unit = entity->IsUnit();
    if (unit) {
      unit->SetCustomName(std::string(val ? val : ""));
    }

    return;
  }

  if (gpg::STR_EqualsNoCase(key, "ToggleScriptBit")) {
    Unit* const unit = entity->IsUnit();
    if (unit) {
      unit->ToggleScriptBit(std::atoi(val));
    }

    return;
  }

  if (gpg::STR_EqualsNoCase(key, "PlayNoStagingPlatformsVO")) {
    Unit* const unit = entity->IsUnit();
    if (!unit) {
      return;
    }

    (void)unit->ArmyRef->GetArmyBrain()->RunScript("OnPlayNoStagingPlatformsVO");
    return;
  }

  if (gpg::STR_EqualsNoCase(key, "PlayBusyStagingPlatformsVO")) {
    Unit* const unit = entity->IsUnit();
    if (!unit) {
      return;
    }

    (void)unit->ArmyRef->GetArmyBrain()->RunScript("OnPlayBusyStagingPlatformsVO");
    return;
  }
}

/**
 * Address: 0x00749A70 (FUN_00749A70)
 *
 * char const *, LuaPlus::LuaObject const &
 *
 * IDA signature:
 * void __thiscall Moho::Sim::ExecuteLuaInSim(
 *   Moho::Sim *this,
 *   char const *functionName,
 *   LuaPlus::LuaObject const &args);
 *
 * What it does:
 * Cheat-gated: calls the global Lua function `functionName` with `args` and
 * restores the stack top. A script error, including a name that is not a
 * function (the LuaFunction constructor raises that), is logged instead of
 * reaching the command decoder.
 */
void Sim::ExecuteLuaInSim(const char* const functionName, const LuaPlus::LuaObject& args)
{
  if (!CheatsEnabled()) {
    return;
  }

#if FAF_SERVER_MODE
  const SSyncRoutingCommand routingCommand(*this);
#endif
  try {
    lua_State* const state = mLuaState->m_state;
    const int savedTop = lua_gettop(state);
    const LuaPlus::LuaFunction<> function{mLuaState->GetGlobal(functionName)};
    function.Call_Object(args);
    lua_settop(state, savedTop);
  } catch (const std::exception& error) {
    gpg::Warnf("Error running global lua function '%s':\n%s", functionName, error.what());
  }
}

// Given moho:: linkage rather than internal: the shipped binary had this
// file-static beside its only caller, but our tree recovers that caller
// (ISSUE_FactoryCommand) into CWldSession.cpp, so an internal-linkage body
// here can never satisfy it - it was one of the /FORCE-swallowed LNK2019s.

/**
 * Address: 0x00749B60 (FUN_00749B60, ?LuaSimCallback@Sim@Moho@@UAEXPBDABVLuaObject@LuaPlus@@ABV?$BVSet@HUEntIdUniverse@Moho@@@2@@Z)
 *
 * What it does:
 * Imports `/lua/SimCallbacks.lua`, resolves `DoCallback`, builds an optional
 * selected-unit table, then executes `DoCallback(callbackName,args,units)`.
 */
void Sim::LuaSimCallback(
  const char* callbackName, const LuaPlus::LuaObject& args, const BVSet<EntId, EntIdUniverse>& entities
)
{
  LuaPlus::LuaObject selectedUnits(mLuaState);
  if (!entities.Empty()) {
    selectedUnits.AssignNewTable(mLuaState, 0, 0);

    // `end()` is re-evaluated every pass, as the binary's loop calls
    // 0x006E7A00 each time round.
    int luaIndex = 1;
    for (BVSet<EntId, EntIdUniverse>::const_iterator it = entities.begin(); it != entities.end(); ++it) {
      Entity* const entity = FindEntityById(mEntityDB, *it);
      if (!entity) {
        continue;
      }

      Unit* const unit = entity->IsUnit();
      if (!unit) {
        continue;
      }

      selectedUnits.SetObject(luaIndex, unit->GetLuaObject());
      ++luaIndex;
    }
  }

#if FAF_SERVER_MODE
  const SSyncRoutingCommand routingCommand(*this);
#endif
  // A script error is logged, not propagated: the binary's only handler here is
  // `catch (lua_RuntimeError&)` (FuncInfo 0x00EE1C84, funclet 0x00749D74).
  // Without it one bad UI callback (e.g. a wrong-arity Issue* call inside
  // SimCallbacks.lua) unwinds out of the sim thread and terminates the game.
  try {
    lua_State* const state = mLuaState->m_state;
    const int oldTop = lua_gettop(state);
    const LuaPlus::LuaObject simCallbacksModule = SCR_Import(mLuaState, "/lua/SimCallbacks.lua");
    const LuaPlus::LuaFunction<> doCallback(simCallbacksModule["DoCallback"]);
    doCallback(callbackName, args, selectedUnits);
    lua_settop(state, oldTop);
  } catch (const lua_RuntimeError& error) {
    gpg::Warnf("Error running sim lua callback function '%s':\n%s", callbackName, error.what());
  }
}

/**
 * Address: 0x0070A4C0 (FUN_0070A4C0, Moho::Sim::SetArmyColor)
 *
 * IDA signature:
 * int __cdecl Moho::Sim::SetArmyColor(
 *   Moho::Sim* sim,
 *   std::vector<std::string>* commandArgs,
 *   Wm3::Vector3<float>* worldPos,
 *   Moho::CArmyImpl* focusArmy,
 *   Moho::EntitySetTemplate<Unit>* selectedUnits);
 *
 * What it does:
 * Parses and applies the `SetArmyColor` sim-console command.
 */
int Sim::SetArmyColor(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  if (!sim || !commandArgs || commandArgs->size() < 5u) {
    if (sim) {
      sim->Printf(kSetArmyColorSyntaxText);
    }
    return 0;
  }

  const int armyIndex = std::atoi((*commandArgs)[1].c_str());
  const int red = std::atoi((*commandArgs)[2].c_str());
  const int green = std::atoi((*commandArgs)[3].c_str());
  const int blue = std::atoi((*commandArgs)[4].c_str());
  const std::uint32_t packedColor = PackOpaqueArmyColor(red, green, blue);

  if (armyIndex < 0 || static_cast<std::size_t>(armyIndex) >= sim->mArmiesList.size()) {
    sim->Printf(kSetArmyColorInvalidArmyText, armyIndex);
    return 0;
  }

  CArmyImpl* const army = sim->mArmiesList[static_cast<std::size_t>(armyIndex)];
  if (!army) {
    sim->Printf(kSetArmyColorInvalidArmyText, armyIndex);
    return 0;
  }

  army->mVarDat.mPlayerColorBgra = packedColor;
  army->mVarDat.mArmyColorBgra = packedColor;
  return 0;
}

/**
 * Address: 0x0064BD20 (FUN_0064BD20, Moho::Sim::DamageUnit)
 *
 * IDA signature:
 * void callcnv_33 Moho::Sim::DamageUnit(Moho::Sim *a1, std::vector_string *a4,
 *     Wm3::Vector3f *a3, Moho::CArmyImpl *_B0, std::vector_WeakObject_IUnit *a5);
 *
 * What it does:
 * `DamageUnit <amount>` console command - see the declaration. The binary
 * open-codes both weak-pointer operations as owner-chain walks: the instigator
 * detach at 0x0064BDE6..0x0064BDFD and the per-unit target rebind at
 * 0x0064BE60..0x0064BEA9. Both are exactly `WeakPtr<T>::Set`, so they are
 * expressed through it rather than re-spelled here.
 */
int Sim::DamageUnit(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;

  if (commandArgs == nullptr || commandArgs->size() < 2u) {
    sim->Printf(kDamageUnitUsageText);
    return 0;
  }

  CDamage damage(sim);
  damage.mMethod = CDamage_SINGLE_TARGET;
  damage.mAmount = static_cast<float>(std::atof(commandArgs->at(1).c_str()));

  // 0x0064BDE6: the instigator the CDamage constructor installed is unlinked
  // again, so debug damage is attributed to nobody.
  damage.mInstigator.Set(nullptr);

  // 0x0064BE01..0x0064BE36: the shared zero vector at 0x00F3D21C.
  damage.mVector = Wm3::Vec3f{0.0f, 0.0f, 0.0f};
  damage.mType = kDamageUnitDamageType;
  damage.mDamageFriendly = 1u;

  if (selectedUnits == nullptr) {
    return 0;
  }

  for (Entity* const entity : selectedUnits->mVec) {
    damage.mTarget.Set(entity);
    SIM_Damage(sim, damage);
  }

  return 0;
}

/**
 * Address: 0x00651B00 (FUN_00651B00, Moho::Sim::dbg)
 *
 * What it does:
 * Toggles one debug overlay by name, or prints available overlays and
 * prefix-match diagnostics when selection is omitted/ambiguous.
 */
int Sim::dbg(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  if (sim == nullptr) {
    return 0;
  }

  if (commandArgs == nullptr || commandArgs->empty()) {
    PrintAvailableDebugOverlayList(*sim);
    return 0;
  }

  if (commandArgs->size() > 2u) {
    sim->Printf(kDbgUsageText, commandArgs->front().c_str());
    return 0;
  }

  if (commandArgs->size() < 2u) {
    PrintAvailableDebugOverlayList(*sim);
    return 0;
  }

  const std::string& requestedOverlayName = commandArgs->at(1);

  gpg::RType* selectedType = TryFindExactDebugOverlayType(requestedOverlayName);
  if (selectedType == nullptr) {
    std::vector<const RDebugOverlayClass*> prefixMatches;
    CollectPrefixDebugOverlayTypes(requestedOverlayName, prefixMatches);

    if (prefixMatches.empty()) {
      sim->Printf(kDbgUnknownOverlayText, requestedOverlayName.c_str());
      PrintAvailableDebugOverlayList(*sim);
      return 0;
    }

    if (prefixMatches.size() > 1u) {
      sim->Printf(kDbgAmbiguousOverlayText, requestedOverlayName.c_str());
      sim->Printf(kDbgCouldBeAnyOfText);
      for (const RDebugOverlayClass* const overlayClass : prefixMatches) {
        if (overlayClass == nullptr) {
          continue;
        }
        sim->Printf("  %s - %s", overlayClass->GetName(), overlayClass->mOverlayDescription.c_str());
      }
      return 0;
    }

    selectedType = const_cast<RDebugOverlayClass*>(prefixMatches.front());
  }

  if (selectedType == nullptr) {
    return 0;
  }

  if (RDebugOverlay* const existingOverlay = FindDebugOverlayInstanceByType(*sim, *selectedType);
      existingOverlay != nullptr) {
    RemoveDebugOverlayInstance(*existingOverlay);
    return 0;
  }

  // 0x00651E52: no null test (`NewPtr` asserts its result); unlink, then
  // link before the head.
  sim->mDebugOverlays.push_back(CreateDebugOverlayInstance(*selectedType));

  return 0;
}

/**
 * Address: 0x006D17B0 (FUN_006D17B0, Moho::Sim::DebugSetConsumptionActive)
 *
 * What it does:
 * Enables upkeep consumption for each currently selected unit.
 */
int Sim::DebugSetConsumptionActive(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)sim;
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;

  ForEachSelectedUnit(selectedUnits, [](Unit& unit) {
    unit.SetConsumptionActive(true);
  });
  return 0;
}

/**
 * Address: 0x006D17F0 (FUN_006D17F0, Moho::Sim::DebugSetConsumptionInActive)
 *
 * What it does:
 * Disables upkeep consumption for each currently selected unit.
 */
int Sim::DebugSetConsumptionInActive(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)sim;
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;

  ForEachSelectedUnit(selectedUnits, [](Unit& unit) {
    unit.SetConsumptionActive(false);
  });
  return 0;
}

/**
 * Address: 0x006D1830 (FUN_006D1830, Moho::Sim::DebugSetProductionActive)
 *
 * What it does:
 * Marks selected units as production-active and dispatches
 * `OnProductionActive`.
 */
int Sim::DebugSetProductionActive(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)sim;
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;

  ForEachSelectedUnit(selectedUnits, [](Unit& unit) {
    unit.ProductionActive = true;
    unit.RunScript("OnProductionActive");
  });
  return 0;
}

/**
 * Address: 0x006D1880 (FUN_006D1880, Moho::Sim::DebugSetProductionInActive)
 *
 * What it does:
 * Marks selected units as production-inactive and dispatches
 * `OnProductionInActive`.
 */
int Sim::DebugSetProductionInActive(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)sim;
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;

  ForEachSelectedUnit(selectedUnits, [](Unit& unit) {
    unit.ProductionActive = false;
    unit.RunScript("OnProductionInActive");
  });
  return 0;
}

/**
 * Address: 0x006D18D0 (FUN_006D18D0, Moho::Sim::DebugAIStatesOn)
 *
 * What it does:
 * Enables per-unit AI debug-state display for currently selected units.
 */
int Sim::DebugAIStatesOn(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)sim;
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;

  ForEachSelectedUnit(selectedUnits, [](Unit& unit) {
    unit.mDebugAIStates = true;
  });
  return 0;
}

/**
 * Address: 0x006D1900 (FUN_006D1900, Moho::Sim::DebugAIStatesOff)
 *
 * What it does:
 * Disables per-unit AI debug-state display for currently selected units and
 * clears published AI debug stats.
 */
int Sim::DebugAIStatesOff(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)sim;
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;

  ForEachSelectedUnit(selectedUnits, [](Unit& unit) {
    unit.mDebugAIStates = false;
    unit.ShowAIDebugInfo(false);
  });
  return 0;
}

/**
 * Address: 0x0075ED00 (FUN_0075ED00, Moho::Sim::TrackStats)
 *
 * What it does:
 * Parses `TrackStats <true|false|reset>` and either toggles selected-unit
 * tracking for the focus army or clears `RealTimeStats` for all armies.
 */
int Sim::TrackStats(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)worldPos;

  if (sim == nullptr || commandArgs == nullptr || commandArgs->size() < 2) {
    const char* const commandName =
      (commandArgs != nullptr && !commandArgs->empty()) ? commandArgs->front().c_str() : "TrackStats";
    if (sim != nullptr) {
      sim->Printf("usage: %s <true|false|reset>", commandName);
    }
    return 0;
  }

  const std::string& mode = (*commandArgs)[1];
  if (mode != "reset") {
    const bool enableTracking = (mode == "true");
    ForEachSelectedUnit(selectedUnits, [focusArmy, enableTracking](Unit& unit) {
      if (unit.ArmyRef != focusArmy) {
        return;
      }

      // 0x0075EE21: the byte at unit+0x200, i.e. Entity+0x1F8.
      unit.RealtimeStatsEnabled = enableTracking ? 1u : 0u;
    });
    return 0;
  }

  for (CArmyImpl* const army : sim->mArmiesList) {
    if (army == nullptr) {
      continue;
    }

    CArmyStats* const armyStats = army->GetArmyStats();
    if (armyStats != nullptr) {
      armyStats->Delete("RealTimeStats");
    }
  }

  return 0;
}
namespace
{

  /**
   * Address: 0x0075FDB0 (FUN_0075FDB0)
   *
   * What it does:
   * Sorts one contiguous `DumpUnitsCountEntry` range by descending population
   * count using the binary lane's non-stable ordering contract.
   *
   * The binary's hand-rolled introsort variant recursively invokes the MSVC8
   * `_Adjust_heap` sift-down lane on this element type -- see
   * `Address: 0x00760590 (FUN_00760590` on the `DumpUnitsCountEntry`
   * instantiation cited in `legacy/algorithms/Sort.h`'s `adjust_heap`
   * template. `std::sort` in modern C++20 encapsulates the same heapify +
   * partition + insertion-sort machinery with identical worst-case order,
   * so the explicit heapify helper disappears at the intent-first source
   * level while preserving binary-equivalent ordering for finite inputs.
   */
  void SortDumpUnitsCountEntries(
    DumpUnitsCountEntry* const begin,
    DumpUnitsCountEntry* const end,
    const std::int32_t depthLimit,
    const std::int32_t userContext
  )
  {
    (void)depthLimit;
    (void)userContext;
    if (begin == nullptr || end == nullptr || begin >= end) {
      return;
    }

    std::sort(begin, end, [](const DumpUnitsCountEntry& lhs, const DumpUnitsCountEntry& rhs) {
      return lhs.count > rhs.count;
    });
  }
}



/**
 * Address: 0x0075EE50 (FUN_0075EE50, Moho::Sim::DumpUnits)
 *
 * What it does:
 * Aggregates live units by blueprint owner pointer, sorts by descending
 * population, and logs one `"<blueprintId> <count>"` line per entry.
 */
int Sim::DumpUnits(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  if (sim == nullptr || sim->mEntityDB == nullptr) {
    return 0;
  }

  // ABI: fa::vector so counts.push_back(...) names the MSVC8 STL grow lane
  // vector<DumpUnitsCountEntry>::_Insert_n (FUN_0075F810) on the capacity-full
  // path, matching the original binary; std::vector would inline its own grow.
  fa::vector<DumpUnitsCountEntry> counts;
  EntityDB* const entityDb = sim->mEntityDB;
  CEntityDbAllUnitsNode* node = entityDb->AllUnitsEnd(0u);
  CEntityDbAllUnitsNode* const end = entityDb->AllUnitsEnd();
  while (node != end) {
    Unit* const unit = EntityDB::UnitFromAllUnitsNode(node);
    node = EntityDB::NextAllUnitsNode(node);
    if (unit == nullptr) {
      continue;
    }

    const RUnitBlueprint* const blueprint = unit->GetBlueprint();
    auto found = std::find_if(counts.begin(), counts.end(), [blueprint](const DumpUnitsCountEntry& entry) {
      return entry.blueprint == blueprint;
    });
    if (found == counts.end()) {
      counts.push_back(DumpUnitsCountEntry{blueprint, 1});
    } else {
      ++found->count;
    }
  }

  if (!counts.empty()) {
    DumpUnitsCountEntry* const begin = counts.data();
    DumpUnitsCountEntry* const finish = begin + counts.size();
    const auto depthLimit = static_cast<std::int32_t>(counts.size());
    SortDumpUnitsCountEntries(begin, finish, depthLimit, 0);
  }

  for (const DumpUnitsCountEntry& entry : counts) {
    if (entry.blueprint == nullptr) {
      continue;
    }

    gpg::Logf("%s %i", entry.blueprint->mBlueprintId.c_str(), entry.count);
  }

  return 0;
}

/**
 * Address: 0x0075D7A0 (FUN_0075D7A0, Moho::Sim::DebugDumpArmyStats)
 *
 * IDA signature:
 * void __cdecl Moho::Sim::DebugDumpArmyStats(
 *     Moho::Sim *sim, std::vector_string *commandArgs, Wm3::Vector3f *worldPos,
 *     Moho::CArmyImpl *focusArmy, std::vector_WeakObject_IUnit *selectedUnits);
 *
 * What it does:
 * `DebugDumpArmyStats <armyIndex>` console callback. With fewer than two
 * tokens it prints the usage line; otherwise it parses the index, looks that
 * army up in `mArmiesList` (`[edx+910h]`/`[edx+914h]` at 0x0075D7F5 and
 * 0x0075D802) and, when the slot holds a live army, dumps its stat snapshot
 * through `CArmyStats::DumpStats` (0x0075D838).
 *
 * The binary indexes `mArmiesList` twice - once to load the army pointer at
 * 0x0075D814 and once for the `GetArmyStats` call at 0x0075D82E - so the
 * inlined bounds check appears twice, and the failing arm at 0x0075D840 is
 * the usual null-deref trap. Only the first index can actually fail, so the
 * recovered form keeps the single guard the source expressed.
 */
int Sim::DebugDumpArmyStats(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  if (commandArgs == nullptr || commandArgs->size() < 2u) {
    sim->Printf("usage: DebugDumpArmyStats armyIndex");
    return 0;
  }

  const auto armyIndex = static_cast<std::size_t>(std::atoi((*commandArgs)[1].c_str()));
  if (armyIndex >= sim->mArmiesList.size()) {
    return 0;
  }

  if (CArmyImpl* const army = sim->mArmiesList[armyIndex]; army != nullptr) {
    army->GetArmyStats()->DumpStats();
  }

  return 0;
}

/**
 * Address: 0x0064BB80 (FUN_0064BB80, Moho::Sim::SallyShears)
 *
 * What it does:
 * Toggles fog-of-war state across every army recon database.
 */
int Sim::SallyShears(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  if (sim == nullptr) {
    return 0;
  }

  for (CArmyImpl* const army : sim->mArmiesList) {
    if (army == nullptr) {
      continue;
    }

    CAiReconDBImpl* const reconDb = army->GetReconDB();
    if (reconDb == nullptr) {
      continue;
    }

    reconDb->ReconSetFogOfWar(!reconDb->ReconGetFogOfWar());
  }

  return 0;
}
namespace
{
  constexpr std::uint64_t kInt64SignBitMask = 0x8000000000000000ull;
  constexpr std::uint64_t kInt64MagnitudeMask = 0x7FFFFFFFFFFFFFFFull;
  // 0x0064BA94..0x0064BAA4: fild of the sign-bit-only qword, then fchs: +2^63.
  constexpr double kSignedInt64HighBitContribution = 9223372036854775808.0;
