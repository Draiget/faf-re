// Part of Sim.cpp, included there: shutdown and beam blueprint registration.

/**
 * Address: 0x007457F0 (FUN_007457F0, ?Shutdown@Sim@Moho@@QAEXXZ)
 *
 * What it does:
 * Destroys live units, drains the deferred deletion queue, shuts down the
 * sim sound manager, and latches `mDidProcess`.
 */
void Sim::Shutdown()
{
  // 0x007457F3..0x00745827 walks `mAllUnits` - the id-keyed tree every entity
  // registers itself in through `Entity::StandardInit` - and calls
  // `Entity::Destroy` on each node's value, with no type filter and no null
  // test:
  //
  //   0x007457F3  mov ecx, [esi+984h]   ; mEntityDB
  //   0x007457F9  mov eax, [ecx+4]      ; mAllUnits._Myhead  (the map is at +0)
  //   0x007457FC  mov eax, [eax]        ; _Myhead->_Left, i.e. begin()
  //   0x00745810  mov eax, [eax+10h]    ; node->second, the Entity*
  //   0x00745813  call 0x679AF0         ; Entity::Destroy
  //   0x0074581C  call 0x5C87A0         ; ++it
  //   0x00745825  cmp eax, edi / jne    ; until end()
  //
  // This used to walk `EntityDB::Entities()`, a hand-kept side table of
  // entity pointers that could outlive its entries; it was removed
  // 2026-09-22. `mAllUnits` cannot: `~Entity` -> `ReleaseId` erases the node.
  //
  // `Destroy()` only sets a flag, pushes to the deletion queue and relinks the
  // coord node - it never erases from `mAllUnits` - so walking the tree while
  // calling it is safe, which is why the binary does exactly that.
  //
  // Retire props and other entities too: the driver's final Sync publishes
  // their interface removals before world teardown releases the blueprints.
  if (mEntityDB != nullptr) {
    for (auto& entry : mEntityDB->mAllUnits) {
      // `DoReserveId` (0x00684480) inserts `{id, nullptr}` before
      // `StandardInit` fills the slot in, so a reserved-but-unbuilt id can
      // still be in the tree. The binary does not test for it; this does,
      // because it costs one compare and the alternative is a null `this`.
      Entity* const entity = entry.second;
      if (entity != nullptr) {
        entity->Destroy();
      }
    }
  }

  while (!mDeletionQueue.empty()) {
    void* const queuedObject = mDeletionQueue.front();
    mDeletionQueue.pop_front();
    RunQueuedDestroy(queuedObject);
  }

  if (mSoundManager != nullptr) {
    mSoundManager->Shutdown();
  }

  mDidProcess = true;
}

/**
 * Address: 0x0074B100 (FUN_0074B100, ?EndGame@Sim@Moho@@UAEXXZ)
 *
 * What it does:
 * Marks the sim as ended.
 */
void Sim::EndGame()
{
  mGameEnded = true;
}

/**
 * Address: 0x005859B0 (FUN_005859B0, Moho::Sim::ArmyCount)
 *
 * What it does:
 * Returns the number of army slots in the sim army list.
 */
int Sim::ArmyCount() const
{
  return static_cast<int>(mArmiesList.size());
}
namespace
{

  /**
   * Address: 0x00528DF0 (FUN_00528DF0)
   *
   * What it does:
   * Uses the active blueprint TLS lane and forwards one mesh-blueprint
   * registration callback into the canonical state registration routine.
   */
  [[maybe_unused]] int RegisterMeshBlueprintFromTlsLane(LuaPlus::LuaState* const state)
  {
    (void)&moho::BlueprintLoaderContext().mRules->mMeshBlueprints;
    (void)RegisterMeshBlueprintFromState(state);
    return 0;
  }

  /**
   * Address: 0x00528EB0 (FUN_00528EB0)
   *
   * What it does:
   * Uses the active blueprint TLS lane and forwards one trail-emitter
   * registration callback into the canonical state registration routine.
   */
  [[maybe_unused]] int RegisterTrailEmitterBlueprintFromTlsLane(LuaPlus::LuaState* const state)
  {
    (void)&moho::BlueprintLoaderContext().mRules->mTrailBlueprints;
    return RegisterTrailEmitterBlueprintFromState(state);
  }

  /**
   * Address: 0x00528F60 (FUN_00528F60)
   *
   * What it does:
   * Uses the active blueprint TLS lane and forwards one emitter-blueprint
   * registration callback into the canonical state registration routine.
   */
  [[maybe_unused]] int RegisterEmitterBlueprintFromTlsLane(LuaPlus::LuaState* const state)
  {
    (void)&moho::BlueprintLoaderContext().mRules->mEmitterBlueprints;
    return RegisterEmitterBlueprintFromState(state);
  }

  /**
   * Address: 0x00529010 (FUN_00529010)
   *
   * What it does:
   * Uses the active blueprint TLS lane and forwards one beam-blueprint
   * registration callback into the canonical state registration routine.
   */
  [[maybe_unused]] int RegisterBeamBlueprintFromTlsLane(LuaPlus::LuaState* const state)
  {
    (void)&moho::BlueprintLoaderContext().mRules->mBeamBlueprints;
    return RegisterBeamBlueprintFromState(state);
  }

  /**
   * Address: 0x005290C0 (FUN_005290C0)
   *
   * What it does:
   * Ticks one background-load progress update directly from the worker's
   * blueprint-loader context and returns the legacy success code.
   */
  [[maybe_unused]] int BlueprintLoaderUpdateProgressFromLoaderContext()
  {
    TickBlueprintLoaderProgressFromLoaderContext();
    return 0;
  }
}



/**
 * Address: 0x00BC8E50 (FUN_00BC8E50, register_RegisterUnitBlueprint_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_RegisterUnitBlueprint_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_RegisterUnitBlueprint_LuaFuncDef()
{
  return func_RegisterUnitBlueprint_LuaFuncDef();
}

/**
 * Address: 0x00BC8E60 (FUN_00BC8E60, register_RegisterPropBlueprint_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_RegisterPropBlueprint_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_RegisterPropBlueprint_LuaFuncDef()
{
  return func_RegisterPropBlueprint_LuaFuncDef();
}

/**
 * Address: 0x00BC8E70 (FUN_00BC8E70, register_RegisterProjectileBlueprint_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_RegisterProjectileBlueprint_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_RegisterProjectileBlueprint_LuaFuncDef()
{
  return func_RegisterProjectileBlueprint_LuaFuncDef();
}

/**
 * Address: 0x00BC8E80 (FUN_00BC8E80, register_RegisterMeshBlueprint_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_RegisterMeshBlueprint_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_RegisterMeshBlueprint_LuaFuncDef()
{
  return func_RegisterMeshBlueprint_LuaFuncDef();
}

/**
 * Address: 0x00BC8E90 (FUN_00BC8E90, register_RegisterTrailEmitterBlueprint_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_RegisterTrailEmitterBlueprint_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_RegisterTrailEmitterBlueprint_LuaFuncDef()
{
  return func_RegisterTrailEmitterBlueprint_LuaFuncDef();
}

/**
 * Address: 0x00BC8EA0 (FUN_00BC8EA0, register_RegisterEmitterBlueprint_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_RegisterEmitterBlueprint_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_RegisterEmitterBlueprint_LuaFuncDef()
{
  return func_RegisterEmitterBlueprint_LuaFuncDef();
}

/**
 * Address: 0x00BC8EB0 (FUN_00BC8EB0, j_func_RegisterBeamBlueprint_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_RegisterBeamBlueprint_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::j_func_RegisterBeamBlueprint_LuaFuncDef()
{
  return func_RegisterBeamBlueprint_LuaFuncDef();
}

/**
 * Address: 0x00BC8EC0 (FUN_00BC8EC0, j_func_BlueprintLoaderUpdateProgress_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_BlueprintLoaderUpdateProgress_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::j_func_BlueprintLoaderUpdateProgress_LuaFuncDef()
{
  return func_BlueprintLoaderUpdateProgress_LuaFuncDef();
}
