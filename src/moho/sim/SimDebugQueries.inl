// Part of Sim.cpp, included there: debug and stat helpers.

  [[nodiscard]] float ConvertSignedStorageLaneToFloat(const std::uint64_t lane) noexcept
  {
    double value = static_cast<double>(lane & kInt64MagnitudeMask);
    if ((lane & kInt64SignBitMask) != 0ull) {
      value += kSignedInt64HighBitContribution;
    }
    return static_cast<float>(value);
  }

  /**
   * Address: 0x0064BA60 (FUN_0064BA60)
   *
   * What it does:
   * Converts `SEconTotals::mMaxStorage` signed 64-bit ENERGY/MASS lanes into a
   * pair of float lanes using the original sign-bit split conversion path.
   */
  [[nodiscard]] SEconPair* BuildSignedMaxStorageFloatPair(
    SEconPair* const outPair,
    const SEconTotals& totals
  ) noexcept
  {
    outPair->ENERGY = ConvertSignedStorageLaneToFloat(totals.mMaxStorage.ENERGY);
    outPair->MASS = ConvertSignedStorageLaneToFloat(totals.mMaxStorage.MASS);
    return outPair;
  }
}



/**
 * Address: 0x0064BBE0 (FUN_0064BBE0, Moho::Sim::BlingBling)
 *
 * What it does:
 * Increases focus-army extra storage by 10000 energy/mass and credits current
 * resources by the updated max-storage lanes.
 */
int Sim::BlingBling(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)commandArgs;
  (void)worldPos;
  (void)selectedUnits;

  if (focusArmy == nullptr) {
    if (sim != nullptr) {
      sim->Printf("No focus army.");
    }
    return 0;
  }

  CSimArmyEconomyInfo* const economyInfo = focusArmy->GetEconomy();
  CEconStorage* const storage = GetArmyEconStorage(*focusArmy);
  if (economyInfo == nullptr || storage == nullptr) {
    return 0;
  }

  (void)storage->Chng(-1);
  storage->mAmt.energy += 10000.0f;
  storage->mAmt.mass += 10000.0f;
  (void)storage->Chng(1);

  // 0x0064BC79..0x0064BC96 adds into economy-info +0x08 (this tick's banked
  // resources), not the stored totals; the next economy tick moves it into storage.
  SEconPair grantedStorage{};
  (void)BuildSignedMaxStorageFloatPair(&grantedStorage, economyInfo->economy);
  economyInfo->mResources.ENERGY += grantedStorage.ENERGY;
  economyInfo->mResources.MASS += grantedStorage.MASS;

  return 0;
}

/**
 * Address: 0x0064BCA0 (FUN_0064BCA0, Moho::Sim::ZeroExtraStorage)
 *
 * What it does:
 * Zeroes focus-army extra-storage lanes after removing and reapplying storage
 * delta contribution.
 */
int Sim::ZeroExtraStorage(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)commandArgs;
  (void)worldPos;
  (void)selectedUnits;

  if (focusArmy == nullptr) {
    if (sim != nullptr) {
      sim->Printf("No focus army.");
    }
    return 0;
  }

  CEconStorage* const storage = GetArmyEconStorage(*focusArmy);
  if (storage == nullptr) {
    return 0;
  }

  (void)storage->Chng(-1);
  storage->mAmt.energy = 0.0f;
  storage->mAmt.mass = 0.0f;
  (void)storage->Chng(1);
  return 0;
}

/**
 * Address: 0x0064BF00 (FUN_0064BF00, Moho::Sim::AddImpulse)
 *
 * What it does:
 * Parses three impulse components, applies the impulse to each selected
 * unit's motion controller, and forces each selected unit into `LAYER_Air`.
 */
int Sim::AddImpulse(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;

  if (sim == nullptr || commandArgs == nullptr || commandArgs->size() < 4u) {
    if (sim != nullptr) {
      const int got = commandArgs != nullptr ? static_cast<int>(commandArgs->size()) : 0;
      sim->Printf("Insufficient args: got %i, expected %i", got, 4);
    }
    return 0;
  }

  const Wm3::Vector3f impulse{
    static_cast<float>(std::atof(commandArgs->at(1).c_str())),
    static_cast<float>(std::atof(commandArgs->at(2).c_str())),
    static_cast<float>(std::atof(commandArgs->at(3).c_str()))
  };

  ForEachSelectedUnit(selectedUnits, [&impulse](Unit& unit) {
    if (unit.UnitMotion != nullptr) {
      // 0x0064BFF3: `push 0; push &impulse; call CUnitMotion::AddImpulse`.
      unit.UnitMotion->AddImpulse(impulse, false);
    }
    unit.SetCurrentLayer(LAYER_Air);
  });

  return 0;
}

/**
 * Address: 0x005C37B0 (FUN_005C37B0, Moho::Sim::ReconFlush)
 *
 * What it does:
 * Flushes every army recon database currently attached to this sim.
 */
int Sim::ReconFlush(
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

  if (!sim) {
    return 0;
  }

  for (CArmyImpl* const army : sim->mArmiesList) {
    if (!army) {
      continue;
    }

    CAiReconDBImpl* const reconDb = army->GetReconDB();
    if (reconDb) {
      reconDb->Flush();
    }
  }

  return 0;
}

/**
 * Address: 0x00684D00 (FUN_00684D00, Moho::Sim::Purge)
 *
 * What it does:
 * Purges entities by category token and optional army filter.
 */
int Sim::Purge(
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

  if (!sim || !sim->mEntityDB || !commandArgs || commandArgs->size() < 2u) {
    return 0;
  }

  const std::string& categoryToken = commandArgs->at(1);
  const PurgeCategory category = ParsePurgeCategory(categoryToken);
  if (category == PurgeCategory::Unknown) {
    sim->Printf("Unknown type %s", categoryToken.c_str());
    return 0;
  }

  int armyFilter = -1;
  if (commandArgs->size() > 2u) {
    armyFilter = std::atoi(commandArgs->at(2).c_str());
  }

  std::vector<Entity*> targets;
  for (const auto& [entityId, entity] : sim->mEntityDB->mAllUnits) {
    if (!entity) {
      continue;
    }

    if (!EntityMatchesPurgeCategory(*entity, category)) {
      continue;
    }

    if (!EntityMatchesPurgeArmyFilter(*entity, armyFilter)) {
      continue;
    }

    if (!ShouldDestroyEntityForPurge(*entity)) {
      continue;
    }

    targets.push_back(entity);
  }

  for (Entity* const entity : targets) {
    if (entity) {
      entity->Destroy();
    }
  }

  return 0;
}

/**
 * Address: 0x006B6B40 (FUN_006B6B40, Moho::Sim::KillAll)
 *
 * What it does:
 * Kills every unit in the requested armies, or every army when no army
 * indexes are supplied.
 */
int Sim::KillAll(
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

  ForEachTargetArmyUnit(sim, commandArgs, [](Unit& unit) {
    unit.Kill(nullptr, "", 0.0f);
  });
  return 0;
}

/**
 * Address: 0x006B6DC0 (FUN_006B6DC0, Moho::Sim::DestroyAll)
 *
 * What it does:
 * Destroys every unit in the requested armies, or every army when no army
 * indexes are supplied.
 */
int Sim::DestroyAll(
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

  ForEachTargetArmyUnit(sim, commandArgs, [](Unit& unit) {
    static_cast<Entity&>(unit).Destroy();
  });
  return 0;
}

/**
 * Address: 0x006540A0 (FUN_006540A0)
 *
 * What it does:
 * Returns the effect-manager pointer lane stored on one `Sim` runtime object.
 */
[[nodiscard]] CEffectManagerImpl* ReadEffectManagerLane(const Sim* const sim)
{
  return sim->mEffectManager;
}

/**
 * Address: 0x0065E9D0 (FUN_0065E9D0, Moho::Sim::efx_NewEmitter)
 *
 * What it does:
 * Creates one emitter at the cursor world position when a blueprint name is
 * provided.
 */
int Sim::efx_NewEmitter(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)focusArmy;
  (void)selectedUnits;

  if (!sim || !worldPos || !Wm3::Vector3f::IsntNaN(worldPos) || !commandArgs) {
    return 0;
  }

  CEffectManagerImpl* const effectManager = ReadEffectManagerLane(sim);
  if (effectManager == nullptr) {
    return 0;
  }

  if (commandArgs->size() < 2u) {
    return 0;
  }

  const std::string& blueprintName = commandArgs->at(1);
  effectManager->CreateEmitter(*worldPos, blueprintName.c_str(), -1);
  return 0;
}

/**
 * Address: 0x0065EA50 (FUN_0065EA50, Moho::Sim::efx_AttachEmitter)
 *
 * What it does:
 * Uses command arg #1 as the target bone name and command args #2..N as
 * emitter blueprint tokens, then attaches each emitter token to each selected
 * unit when the primary emitter blueprint resolves in rules.
 */
int Sim::efx_AttachEmitter(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;

  if (!sim || !sim->mRules || !commandArgs || !selectedUnits) {
    return 0;
  }

  CEffectManagerImpl* const effectManager = ReadEffectManagerLane(sim);
  if (effectManager == nullptr) {
    return 0;
  }

  if (commandArgs->size() < 3u) {
    return 0;
  }

  const std::string& boneName = commandArgs->at(1);
  const std::string& primaryEmitterBlueprint = commandArgs->at(2);

  RResId emitterId{};
  gpg::STR_InitFilename(&emitterId.name, primaryEmitterBlueprint.c_str());
  if (sim->mRules->GetEmitterBlueprint(emitterId) == nullptr) {
    return 0;
  }

  ForEachSelectedUnit(selectedUnits, [&](Unit& unit) {
    Entity* const entity = static_cast<Entity*>(&unit);
    for (std::size_t index = 2u; index < commandArgs->size(); ++index) {
      const std::string& emitterBlueprint = commandArgs->at(index);
      const int boneIndex = entity->ResolveBoneIndex(boneName.c_str());
      effectManager->CreateAttachedEmitter(entity, boneIndex, emitterBlueprint.c_str(), -1);
    }
  });

  return 0;
}

/**
 * Address: 0x0066BD90 (FUN_0066BD90, func_AddLightParticle_SimConFunc)
 *
 * What it does:
 * Parses optional `lifetime`, `size`, and `texture` args, then creates a light
 * particle using `ramp_white_01` as the secondary texture.
 */
int Sim::AddLightParticle(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)focusArmy;
  (void)selectedUnits;

  if (!sim || !worldPos || !Wm3::Vector3f::IsntNaN(worldPos)) {
    return 0;
  }

  CEffectManagerImpl* const effectManager = ReadEffectManagerLane(sim);
  if (effectManager == nullptr) {
    return 0;
  }

  float lifetime = 2.0f;
  float size = 1.0f;
  fa::string texturePrimary{};

  if (commandArgs && commandArgs->size() > 1u) {
    for (std::size_t i = 1u; i < commandArgs->size(); ++i) {
      const std::string& key = commandArgs->at(i);
      const std::string* value = (i + 1u < commandArgs->size()) ? &commandArgs->at(i + 1u) : nullptr;
      if (!value) {
        continue;
      }

      if (key == "lifetime") {
        lifetime = static_cast<float>(std::atof(value->c_str()));
      } else if (key == "size") {
        size = static_cast<float>(std::atof(value->c_str()));
      } else if (key == "texture") {
        texturePrimary.assign_owned(value->c_str());
      }
    }
  }

  const fa::string textureSecondary("ramp_white_01");
  effectManager->CreateLightParticle(*worldPos, texturePrimary, textureSecondary, size, lifetime, -1);
  return 0;
}

/**
 * Address: 0x00734F50 (FUN_00734F50, Moho::Sim::Log)
 *
 * What it does:
 * Joins command args #1..N with spaces and logs the resulting text via
 * `gpg::Logf("%s", ...)`.
 */
int Sim::Log(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)sim;
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  std::string joined;
  if (commandArgs != nullptr && commandArgs->size() > 1u) {
    joined = commandArgs->at(1);
    for (std::size_t i = 2u; i < commandArgs->size(); ++i) {
      joined.push_back(' ');
      joined += commandArgs->at(i);
    }
  }

  gpg::Logf("%s", joined.c_str());
  return 0;
}

/**
 * Address: 0x00734FF0 (FUN_00734FF0, Moho::Sim::SimWarn)
 *
 * What it does:
 * Joins command args #1..N with spaces and warns using `gpg::Warnf("%s", ...)`.
 */
int Sim::SimWarn(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)sim;
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  std::string joined;
  if (commandArgs != nullptr && commandArgs->size() > 1u) {
    joined = commandArgs->at(1);
    for (std::size_t i = 2u; i < commandArgs->size(); ++i) {
      joined.push_back(' ');
      joined += commandArgs->at(i);
    }
  }

  gpg::Warnf("%s", joined.c_str());
  return 0;
}

/**
 * Address: 0x00735090 (FUN_00735090, Moho::Sim::SimError)
 *
 * What it does:
 * Joins command args #1..N with spaces and terminates with
 * `gpg::Die("%s", ...)`. Returns `int` because it's invoked as a Lua C
 * function (which require an `int` return slot for the result count); the
 * function is in practice noreturn via `gpg::Die`/`std::abort` but the
 * `[[noreturn]]` attribute can't be applied to non-void return types
 * (C4646), so it is omitted here.
 */
int Sim::SimError(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)sim;
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  std::string joined;
  if (commandArgs != nullptr && commandArgs->size() > 1u) {
    joined = commandArgs->at(1);
    for (std::size_t i = 2u; i < commandArgs->size(); ++i) {
      joined.push_back(' ');
      joined += commandArgs->at(i);
    }
  }

  gpg::Die("%s", joined.c_str());
  std::abort();
}

/**
 * Address: 0x00699D20 (FUN_00699D20, Moho::Sim::sim_Gravity)
 *
 * Moho::Sim *, std::vector<fa::string> *
 *
 * What it does:
 * Prints the current gravity value, or parses a new scalar and stores it as
 * the downward gravity acceleration on the active sim.
 */
int Sim::sim_Gravity(
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

  if (sim == nullptr || commandArgs == nullptr || commandArgs->empty()) {
    if (sim != nullptr) {
      sim->Printf("usage: %s [new-value]", "sim_Gravity");
      sim->Printf("    where new-value is in ogrids/(second^2)");
    }
    return 0;
  }

  if (sim->mPhysConstants == nullptr) {
    return 0;
  }

  Wm3::Vector3f& gravity = sim->mPhysConstants->mGravity;
  if (commandArgs->size() == 1u) {
    sim->Printf("Gravity is %.2f ogrids/(second^2) down.", -gravity.y);
    return 0;
  }

  if (commandArgs->size() == 2u) {
    float newGravity = 0.0f;
    const std::string& argument = commandArgs->at(1);
    if (::sscanf_s(argument.c_str(), "%f", &newGravity) == 1) {
      gravity.y = -newGravity;
      sim->Printf("Changing gravity to %.2f ogrids/(second^2) down.", newGravity);
    } else {
      sim->Printf("Invalid number: %s", argument.c_str());
    }
    return 0;
  }

  sim->Printf("usage: %s [new-value]", commandArgs->front().c_str());
  sim->Printf("    where new-value is in ogrids/(second^2)");
  return 0;
}

/**
 * Address: 0x00735110 (FUN_00735110, Moho::Sim::SimAssert)
 *
 * What it does:
 * No-op debug command callback lane.
 */
int Sim::SimAssert(
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
  (void)selectedUnits;
  return 0;
}

/**
 * Address: 0x00735120 (FUN_00735120, Moho::Sim::SimCrash)
 *
 * What it does:
 * Triggers an intentional null-write crash for debug fault testing.
 */
int Sim::SimCrash(
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
  (void)selectedUnits;

  *reinterpret_cast<volatile std::uint32_t*>(0) = 0u;
  return 0;
}

/**
 * Address: 0x0074B610 (FUN_0074B610, Moho::Sim::sim_DebugCrash)
 *
 * What it does:
 * Triggers an intentional null-write crash for debug fault testing.
 */
int Sim::sim_DebugCrash(
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
  (void)selectedUnits;

  *reinterpret_cast<volatile std::uint32_t*>(0) = 0u;
  return 0;
}

/**
 * Address: 0x00734BA0 (FUN_00734BA0, Moho::Sim::sim_TestFunc)
 *
 * What it does:
 * Debug console-command stub for the `sim_TestFunc` test entry: prints this
 * sim instance's own address and returns.
 */
int Sim::sim_TestFunc(
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

  sim->Printf("sim=%p", static_cast<const void*>(sim));
  return 0;
}

/**
 * Address: 0x0074B3F0 (FUN_0074B3F0, Moho::Sim::ScenarioMethod)
 *
 * What it does:
 * Looks up one scenario callback in `ScenarioInfo.Env` using command arg #1
 * and invokes it if present; warns when the callback is undefined.
 */
int Sim::ScenarioMethod(
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

  if (commandArgs == nullptr) {
    return 0;
  }

  const int argumentCount = static_cast<int>(commandArgs->size());
  if (argumentCount < 2 || sim == nullptr || sim->mLuaState == nullptr) {
    return argumentCount;
  }

  const std::string& methodName = commandArgs->at(1);
  LuaPlus::LuaObject globals = sim->mLuaState->GetGlobals();
  LuaPlus::LuaObject scenarioInfoObject = globals["ScenarioInfo"];
  LuaPlus::LuaObject scenarioEnvObject = scenarioInfoObject["Env"];
  LuaPlus::LuaObject scenarioMethodObject = scenarioEnvObject[methodName.c_str()];

  if (scenarioMethodObject) {
    LuaPlus::LuaFunction scenarioMethodFunction(scenarioMethodObject);
    scenarioMethodFunction.Call();
  } else {
    gpg::Warnf("ScenarioMethod '%s' not defined", methodName.c_str());
  }

  return 0;
}

/**
 * Address: 0x007595C0 (FUN_007595C0, Moho::Sim::SimLua)
 *
 * What it does:
 * Builds one Lua expression from sim-command args #1..N, exposes the first
 * selected unit as global `__selected_unit`, executes the expression, then
 * clears `__selected_unit`.
 */
int Sim::SimLua(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;

  if (sim == nullptr || commandArgs == nullptr || commandArgs->size() < 2u || sim->mLuaState == nullptr) {
    return 0;
  }

  auto clearSelectedUnitGlobal = [sim]() {
    lua_State* const rawState = sim->mLuaState != nullptr ? sim->mLuaState->GetCState() : nullptr;
    if (rawState == nullptr) {
      return;
    }

    lua_pushnil(rawState);
    lua_setglobal(rawState, "__selected_unit");
  };

  LuaPlus::LuaObject globals = sim->mLuaState->GetGlobals();
  Unit* selectedUnit = nullptr;
  if (selectedUnits != nullptr && selectedUnits->mVec.begin() != selectedUnits->mVec.end()) {
    selectedUnit = static_cast<Unit*>(*selectedUnits->mVec.begin());
  }

  if (selectedUnit != nullptr) {
    LuaPlus::LuaObject selectedUnitObject = selectedUnit->GetLuaObject();
    globals.SetObject("__selected_unit", selectedUnitObject);
  } else {
    clearSelectedUnitGlobal();
  }

  std::string commandText = commandArgs->at(1);
  for (std::size_t argIndex = 2u; argIndex < commandArgs->size(); ++argIndex) {
    commandText.push_back(' ');
    commandText += commandArgs->at(argIndex);
  }

  sim->Printf("%s", commandText.c_str());
  (void)SCR_LuaDoString(commandText.c_str(), sim->mLuaState);
  clearSelectedUnitGlobal();
  return 0;
}

/**
 * Address: 0x0075D5D0 (FUN_0075D5D0, Moho::Sim::DebugSetPlayableRect)
 *
 * IDA signature:
 * void __cdecl Moho::Sim::DebugSetPlayableRect(Moho::Sim *sim, std::vector_string *commandArgs);
 *
 * What it does:
 * `DebugSetPlayableRect x0 y0 x1 y1`. Parses the four bounds with `atoi` into
 * a `gpg::Rect2i` laid out `{x0, z0, x1, z1}` (0x0075D6A6..0x0075D6C2 stores
 * arg1 -> x0, arg2 -> z0, arg3 -> x1, arg4 -> z1), asks the sim's `STIMap` to
 * clamp and adopt it, and on success mirrors the change into Sim Lua by
 * running `SyncPlayableRect({ ... })`. The Lua mirror is built from the *raw
 * argument tokens*, not from the clamped rectangle - 0x0075D6EF re-reads the
 * argument vector and pushes the four strings in the order
 * `x0=arg1, x1=arg3, y0=arg2, y1=arg4`.
 */
int Sim::DebugSetPlayableRect(
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

  if (commandArgs == nullptr || commandArgs->size() < 5u) {
    sim->Printf(kDebugSetPlayableRectUsageText);
    return 0;
  }

  const gpg::Rect2i playableRect{
    std::atoi(commandArgs->at(1u).c_str()),
    std::atoi(commandArgs->at(2u).c_str()),
    std::atoi(commandArgs->at(3u).c_str()),
    std::atoi(commandArgs->at(4u).c_str())
  };

  if (!sim->mMapData->SetPlayableMapRect(playableRect)) {
    sim->Printf(kDebugSetPlayableRectInvalidText);
    return 0;
  }

  const fa::string syncCommand = gpg::STR_Printf(
    kDebugSetPlayableRectSyncFormat,
    commandArgs->at(1u).c_str(),
    commandArgs->at(3u).c_str(),
    commandArgs->at(2u).c_str(),
    commandArgs->at(4u).c_str()
  );
  (void)SCR_LuaDoString(syncCommand.c_str(), sim->mLuaState);
  return 0;
}

/**
 * Address: 0x0075D860 (FUN_0075D860, Moho::Sim::DebugMoveCamera)
 *
 * What it does:
 * Builds and executes `DebugMoveCamera(x0,y0,x1,y1)` in Sim Lua from command
 * args #1..#4.
 */
int Sim::DebugMoveCamera(
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

  if (commandArgs == nullptr || commandArgs->size() < 5u) {
    sim->Printf("usage: DebugMoveCamera x0 y0 x1 y1");
    return 0;
  }

  const fa::string commandText = gpg::STR_Printf(
    "DebugMoveCamera(%s,%s,%s,%s)",
    commandArgs->at(1).c_str(),
    commandArgs->at(2).c_str(),
    commandArgs->at(3).c_str(),
    commandArgs->at(4).c_str()
  );
  (void)SCR_LuaDoString(commandText.c_str(), sim->mLuaState);
  return 0;
}
